"""PR #205 — the Local Shield must never EXECUTE a tool because it crashed.

The bug this file exists to keep dead:

    except (AgentXSecurityBlock, AgentXCircuitBreakerTripped):
        raise
    except Exception as local_shield_error:
        print("... bypassed: %s" % local_shield_error)
        # <-- falls through, and the dangerous tool RUNS

Two instances already fired (`category`, then `reversible_transform`/#200) and BOTH were
fixed by guarding the FIELD, never the SWALLOW. Guarding fields one at a time is losing
whack-a-mole: every new whitelist field is a new way to throw. So the headline test here
is not "instance 3 is fixed" -- it is the FUZZ TRIPWIRE, which asserts the invariant:

    ✦ NO field in the loader whitelist, given ANY malformed value, can cause the
      dangerous tool to EXECUTE. ✦

Assertions are on a CALL SPY (did the tool function actually run?), never on printed
text. "Did it block?" and "what did it say?" are different questions, and only the first
one is a security property.
"""
import itertools
import json
import os

import pytest

from agentx_sdk import decorators
from agentx_sdk.decorators import (
    AgentXPolicyLoadError,
    AgentXSecurityBlock,
    AgentXCircuitBreakerTripped,
    agentx_protect,
    is_block,
    load_local_policy_keywords,
    start_secure_session,
    _BUILTIN_POLICY_KEYWORDS,
    _session_stats,
)

# A blatantly destructive payload. Every arm below feeds this in; the ONLY acceptable
# outcomes are "blocked" or "failed closed". "Executed" is the bug.
DANGEROUS = "DROP TABLE users;"

# Every field the loader copies out of an untrusted policies.json. A pulled cloud row or
# a hand-edited team-committed file is untrusted input, and this is the exact surface the
# two shipped instances came through.
WHITELIST_FIELDS = [
    "id",
    "name",
    "category",
    "blocked_intents",
    "socratic_prompt",
    "preferred_alternative",
    "reversible_transform",
    "is_active",       # decides whether the rule is ARMED AT ALL -- the most critical of all
]

# The malformed shapes a JSON file can actually carry where a string was expected.
#
# ⚠️ THE FALSY ONES ARE LOAD-BEARING. The first cut of this list was all TRUTHY
# ([["a","list"], {"a":"dict"}, 12345, True]) and it MISSED a live fail-open: the loader
# gated on `if p.get("is_active", True) and p.get("blocked_intents"):` BEFORE coercing, so a
# falsy-but-malformed value ({} / "" / 0 / false) short-circuited the gate, the row was
# silently DROPPED, and if it was the only row we fell back to the built-ins -- a silent
# rulebook swap that let the org's own rule go unenforced and the tool EXECUTE.
#
# A fuzz list that only tests truthy values cannot see a truthiness short-circuit. Found by
# a high-effort review, not by this test. Keep both polarities.
MALFORMED_VALUES = [
    ["a", "list"],
    {"a": "dict"},
    12345,
    True,
    {},            # falsy dict
    [],            # falsy list
    "",            # falsy string
    0,             # falsy int
    False,         # falsy bool
]


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    """Neutralize the two stores that SHADOW the built-in seeds, so these tests read the
    code under test and not a developer's local `.agentx/`. Without this, a real
    policies.json or overrides.json in the repo silently changes what is armed.

    ALSO resets the circuit-breaker strike state. Without it these tests pass alone and
    FAIL in the full suite: strikes accumulate per tool NAME across tests, so an earlier
    test's blocked retries pre-trip the breaker here and the call takes the breaker path
    instead of the one under test. (Same cross-test leak the blind eval hit.)"""
    monkeypatch.setenv("AGENTX_OVERRIDES", str(tmp_path / "no-overrides.json"))
    monkeypatch.delenv("AGENTX_POLICY_LOAD", raising=False)
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)
    # Every test starts with a shield that CAN read its rulebook; arms opt in.
    monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR", None)
    monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)
    monkeypatch.setattr(decorators, "_SHIELD_FAILOPEN_BANNER_SHOWN", False)
    monkeypatch.setattr(decorators, "LOCAL_POLICY_KEYWORDS", list(_BUILTIN_POLICY_KEYWORDS))
    # A FRESH TRACE, not just fresh strikes. The circuit breaker counts turns per TRACE, and
    # a test that never opens its own session inherits the previous test's trace -- already
    # full of turns -- so the breaker trips on the first call and the test takes the BREAKER
    # path instead of the one under test. That is why these passed alone and failed in the
    # full suite. reset_strike_state() alone is not enough; the session is the other half.
    decorators.reset_strike_state()
    start_secure_session()
    _session_stats["shield_failopens"] = 0
    yield
    decorators.reset_strike_state()


@pytest.fixture
def broken_project(tmp_path, monkeypatch):
    """A REAL project directory whose .agentx/policies.json is malformed, with the process
    cwd inside it.

    This drives the PRODUCTION path: the loader resolves `.agentx/policies.json` relative to
    the cwd, so the shield genuinely cannot read its rulebook. The first cut of these tests
    monkeypatched `_POLICY_LOAD_ERROR` instead -- which is the very sin the review caught on
    the MCP side, where a monkeypatched detector made a DEAD code path look tested. A test
    must take the path production takes, or it certifies a guarantee that does not exist."""
    project = tmp_path / "proj"
    (project / ".agentx").mkdir(parents=True)
    (project / ".agentx" / "policies.json").write_text(
        json.dumps([{
            "id": "POL-107", "name": "Mass Destructive Intent", "is_active": True,
            "blocked_intents": 12345,          # an ENFORCEMENT field, malformed -> fail closed
            "socratic_prompt": "Blocked.",
        }]), encoding="utf-8")
    monkeypatch.chdir(project)
    monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)
    monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR", None)
    return project


def _write_policies(tmp_path, policies):
    """Write a .agentx/policies.json the loader will find, and return its seed dir."""
    seed = tmp_path / ".agentx"
    seed.mkdir(exist_ok=True)
    (seed / "policies.json").write_text(json.dumps(policies), encoding="utf-8")
    return str(seed)


_SPY_SEQ = itertools.count()


def _spy_tool():
    """A protected tool that RECORDS whether its body actually ran.

    This is the whole point: we assert on `calls`, not on stdout. A test that greps the
    printed output cannot tell "blocked" from "crashed, printed a warning, and executed
    the DROP anyway" -- which is precisely how instances 1 and 2 shipped.

    The tool gets a UNIQUE NAME per call. The circuit breaker's strike counter is keyed by
    tool NAME and is process-global, so a shared name like `run_sql` (which half the suite
    uses) lets one test's blocked retries pre-trip the breaker inside another test: the call
    then takes the BREAKER path instead of the path under test, and the file passes alone
    while failing in the full suite."""
    calls = []

    def _tool(query, cot=""):
        calls.append(query)
        return "EXECUTED"

    # Rename BEFORE decorating: agentx_protect captures the display name at decoration time.
    _tool.__name__ = f"run_sql_spy_{next(_SPY_SEQ)}"
    return agentx_protect(agent_id="test_artifact_failclosed")(_tool), calls


# =====================================================================
# THE FUZZ TRIPWIRE — the invariant, not the instance
# =====================================================================

@pytest.mark.parametrize("field", WHITELIST_FIELDS)
@pytest.mark.parametrize("bad", MALFORMED_VALUES)
def test_no_whitelist_field_can_ever_disarm_the_shield(field, bad, tmp_path, monkeypatch):
    """✦ THE INVARIANT ✦  For EVERY field in the loader whitelist, and EVERY malformed
    value, a dangerous call must NOT execute.

    It may block (the policy still armed) or fail closed (the loader rejected the file).
    Both are correct. The one forbidden outcome is the tool body running.

    This generalizes the two shipped instances into the class. It is what a per-field
    isinstance guard could never give us: a NEW field added to that whitelist tomorrow is
    covered by this test the moment it is added to WHITELIST_FIELDS."""
    seed = _write_policies(tmp_path, [{
        "id": "POL-FUZZ",
        "name": "Fuzzed Policy",
        "is_active": True,
        "blocked_intents": ["drop table"],
        "socratic_prompt": "Blocked.",
        **{field: bad},
    }])

    # The loader either rejects the file (fail closed) or coerces it into something safe.
    try:
        loaded = load_local_policy_keywords(seed_dir=seed)
    except AgentXPolicyLoadError:
        # Fail-closed at load. Prove the CALL path refuses to run the tool -- through the
        # REAL cwd-resolved file, not a monkeypatched global.
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)
        monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR", None)
        run_sql, calls = _spy_tool()
        with pytest.raises(AgentXPolicyLoadError):
            run_sql(DANGEROUS)
        assert calls == [], (
            f"FAIL-OPEN: field={field!r} value={bad!r} -> the shield failed to load its "
            f"policies and the tool EXECUTED anyway. This is the #205 bug."
        )
        return

    # The file loaded. Then the armed policy must still catch the dangerous call, and the
    # tool must not run.
    monkeypatch.setattr(decorators, "LOCAL_POLICY_KEYWORDS", loaded)
    run_sql, calls = _spy_tool()
    try:
        result = run_sql(DANGEROUS)
    except (AgentXSecurityBlock, AgentXPolicyLoadError, AgentXCircuitBreakerTripped):
        result = None
    assert calls == [], (
        f"FAIL-OPEN: field={field!r} value={bad!r} -> the shield loaded but the dangerous "
        f"call EXECUTED. A malformed whitelist field disarmed the shield."
    )
    if result is not None:
        assert is_block(result), f"field={field!r} value={bad!r} produced neither a block nor a raise"


# =====================================================================
# PART A — narrow block: fail CLOSED on a policy-load failure
# =====================================================================

def test_a_malformed_COACHING_field_degrades_but_still_ENFORCES(tmp_path):
    """The line that matters most in this file.

    Instances 1 and 2 (`category`, then `reversible_transform`/#200) were malformed
    COACHING fields. They must NOT fail the call closed: `blocked_intents` is intact, so
    we can still answer the only question enforcement asks -- "does this call violate the
    policy?" -- and the answer is yes.

    Failing closed on a cosmetic field would take a customer's entire agent down because a
    coaching STRING was the wrong shape. That is an outage for a defect that costs us
    nothing to absorb. So: DROP the bad field, keep enforcing.

    The dangerous call still never runs. That is the invariant; failing closed was only
    ever the means."""
    seed = _write_policies(tmp_path, [{
        "id": "POL-107", "name": "Mass Destructive Intent", "is_active": True,
        "blocked_intents": ["drop table"], "socratic_prompt": "Blocked.",
        "reversible_transform": ["not", "a", "string"],
        "category": {"not": "a string"},
    }])

    loaded = load_local_policy_keywords(seed_dir=seed)     # must NOT raise

    pol = next(p for p in loaded if p["id"] == "POL-107")
    assert pol["blocked_intents"] == ["drop table"], "enforcement survives"

    # The malformed value is GONE. What replaces it is the C1 fallback: if this pulled row
    # shadows a built-in seed, the seed's own (good, tested) value is inherited, so a
    # corrupt cloud field degrades to the BUILT-IN coaching rather than to nothing. That is
    # the whole point of C1 doing double duty here.
    for field in ("reversible_transform", "category"):
        assert pol[field] != ["not", "a", "string"], f"{field}: malformed value survived"
        assert pol[field] is None or isinstance(pol[field], str), (
            f"{field}: must be dropped to None or inherited as a string, got {pol[field]!r}"
        )


def test_a_malformed_ENFORCEMENT_field_DOES_fail_closed(tmp_path):
    """The other side of the line. `blocked_intents` is what we SCAN. If it is a scalar,
    the scan raises ('int' object is not iterable) and we cannot tell whether this call is
    dangerous at all. THAT is when we do not get to certify the call as safe.

    Found by the fuzz tripwire, not by a customer."""
    seed = _write_policies(tmp_path, [{
        "id": "POL-107", "name": "Mass Destructive Intent", "is_active": True,
        "blocked_intents": 12345, "socratic_prompt": "Blocked.",
    }])
    with pytest.raises(AgentXPolicyLoadError) as err:
        load_local_policy_keywords(seed_dir=seed)
    assert err.value.field == "blocked_intents"
    assert err.value.source


def test_a_malformed_policy_ID_fails_closed(tmp_path):
    """Also found by the fuzz tripwire: an `id` that is a JSON array loaded fine and then
    threw DOWNSTREAM (it reaches dict keys and frozensets), so the shield fell open and the
    DROP executed. An unusable identity means an unauditable, unattributable rule."""
    seed = _write_policies(tmp_path, [{
        "id": ["a", "list"], "name": "X", "is_active": True,
        "blocked_intents": ["drop table"], "socratic_prompt": "Blocked.",
    }])
    with pytest.raises(AgentXPolicyLoadError) as err:
        load_local_policy_keywords(seed_dir=seed)
    assert err.value.field == "id"


def test_unparseable_json_fails_closed_not_silently_builtin(tmp_path):
    """The loader's OWN `except Exception: pass` used to swap in the built-ins while the
    developer believed their pulled org policies were armed. A corrupt rulebook is not a
    reason to quietly enforce a DIFFERENT rulebook."""
    seed = tmp_path / ".agentx"
    seed.mkdir()
    (seed / "policies.json").write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(AgentXPolicyLoadError):
        load_local_policy_keywords(seed_dir=str(seed))


def test_dangerous_call_does_not_run_when_policies_are_malformed(broken_project):
    """THE HEADLINE, driven through the REAL path (a real malformed file, a real cwd).

    Before #205 this printed "bypassed" and executed the DROP."""
    run_sql, calls = _spy_tool()

    with pytest.raises(AgentXPolicyLoadError):
        run_sql(DANGEROUS)

    assert calls == [], "the shield was blind and the tool ran anyway -- this is the bug"


def test_even_a_BENIGN_call_does_not_run_when_the_shield_is_blind(broken_project):
    """Fail-closed means CLOSED. If we cannot read the rulebook we cannot certify ANY call
    as safe, benign-looking or not -- we do not get to guess which ones matter."""
    run_sql, calls = _spy_tool()
    with pytest.raises(AgentXPolicyLoadError):
        run_sql("SELECT 1")
    assert calls == []


def test_fixing_the_file_UNBRICKS_the_agent_with_no_restart(broken_project):
    """The operator does exactly what our error message tells them, and it WORKS.

    The first cut latched the error at import and never re-read it, so an operator who fixed
    the field kept getting the identical error forever: the agent was bricked and the
    remediation we printed was a DEAD END. Now the file is tracked by (path, mtime, size),
    so the fix takes effect on the very next call."""
    run_sql, calls = _spy_tool()
    with pytest.raises(AgentXPolicyLoadError):
        run_sql("SELECT 1")

    # The operator fixes the field the message named.
    (broken_project / ".agentx" / "policies.json").write_text(
        json.dumps([{
            "id": "POL-107", "name": "Mass Destructive Intent", "is_active": True,
            "blocked_intents": ["drop table"], "socratic_prompt": "Blocked.",
        }]), encoding="utf-8")

    assert run_sql("SELECT 1") == "EXECUTED", "a fixed rulebook must un-brick the agent"
    assert calls == ["SELECT 1"]

    # ...and the repaired rulebook actually ENFORCES.
    calls.clear()
    try:
        result = run_sql(DANGEROUS)
        assert is_block(result)
    except AgentXSecurityBlock:
        pass
    assert calls == [], "the repaired rulebook must still block the dangerous call"


def test_deleting_the_file_also_unbricks_via_the_builtins(broken_project):
    """The other half of the printed remediation: "or remove the file to fall back to the
    built-in policies". It must actually work."""
    run_sql, calls = _spy_tool()
    with pytest.raises(AgentXPolicyLoadError):
        run_sql("SELECT 1")

    (broken_project / ".agentx" / "policies.json").unlink()

    assert run_sql("SELECT 1") == "EXECUTED"
    calls.clear()
    try:
        result = run_sql(DANGEROUS)          # built-ins are armed, so this still blocks
        assert is_block(result)
    except AgentXSecurityBlock:
        pass
    assert calls == [], "the built-in floor must arm once the bad file is gone"


def test_a_policies_file_CREATED_after_import_is_noticed(tmp_path, monkeypatch):
    """The inverse hole. A process that imported cleanly and then had a policies.json
    written under it (`agentx pull` mid-session) used to never notice, so freshly pulled org
    policies silently never enforced."""
    project = tmp_path / "proj"
    (project / ".agentx").mkdir(parents=True)
    monkeypatch.chdir(project)
    monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)
    monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR", None)

    run_sql, calls = _spy_tool()
    assert run_sql("SELECT 1") == "EXECUTED"          # healthy: no policy file at all

    # `agentx pull` lands a MALFORMED rulebook mid-session.
    (project / ".agentx" / "policies.json").write_text("{ not json", encoding="utf-8")

    calls.clear()
    with pytest.raises(AgentXPolicyLoadError):
        run_sql("SELECT 1")
    assert calls == [], "a file that appears after import must still be honored"


def test_policy_load_error_is_not_a_security_block(monkeypatch):
    """It must NOT subclass AgentXSecurityBlock and is_block() must be False.

    A block is a security VERDICT the agent is coached to recover from. This is an
    OPERATOR fault the agent cannot fix by picking a different tool. Conflating them
    feeds a nonsense challenge into the recovery loop and pollutes the recovery-rate
    denominator with an event that can never be 'recovered'."""
    err = AgentXPolicyLoadError("x", source="f.json", field="category")
    assert not isinstance(err, AgentXSecurityBlock)
    assert is_block(err) is False
    assert err.blocked is False


def test_policy_load_error_does_not_open_a_recovery_episode(broken_project):
    """Guards the denominator: a fail-closed must not register as a challenge episode."""
    before = _session_stats.get("challenge_episodes", 0)
    run_sql, _calls = _spy_tool()
    with pytest.raises(AgentXPolicyLoadError):
        run_sql(DANGEROUS)
    assert _session_stats.get("challenge_episodes", 0) == before


def test_error_message_names_the_file_the_field_and_the_fix(monkeypatch):
    """The developer must be able to ACT on it. Not a Socratic challenge: an operator
    error that names what to fix and how to opt out."""
    err = AgentXPolicyLoadError(
        "policy field 'category' must be a string, got list",
        source=".agentx/policies.json", field="category")
    msg = decorators._policy_load_error_message(err)
    assert ".agentx/policies.json" in msg
    assert "category" in msg
    assert "agentx policies --check" in msg
    assert "AGENTX_POLICY_LOAD=permissive" in msg
    assert "—" not in msg, "house style: no em dashes in user-facing copy"


# =====================================================================
# The escape hatch — what makes a strict default safe to ship
# =====================================================================

def test_permissive_runs_on_builtins_without_polluting_the_metric(broken_project, monkeypatch):
    """AGENTX_POLICY_LOAD=permissive falls back to the BUILT-IN floor, which still screens the
    call. A benign call RUNS -- but it was SCREENED, so it is NOT a fail-open and must NOT
    touch shield_failopens. Counting it here mislabeled a screened call as a bypass and
    polluted the founder's `WHERE shield_failopens > 0` hunt."""
    monkeypatch.setenv("AGENTX_POLICY_LOAD", "permissive")
    before = _session_stats.get("shield_failopens", 0)

    run_sql, calls = _spy_tool()
    run_sql("SELECT 1")          # benign: the built-in floor lets it through

    assert calls == ["SELECT 1"], "permissive runs the benign call on the built-in floor"
    assert _session_stats["shield_failopens"] - before == 0, "a screened call is NOT a fail-open"


def test_permissive_still_blocks_a_dangerous_call_via_the_builtins(broken_project, monkeypatch):
    """The built-in floor is armed under permissive, so DROP TABLE is still BLOCKED, the tool
    never runs, and a block is not a fail-open either -- the metric stays clean."""
    monkeypatch.setenv("AGENTX_POLICY_LOAD", "permissive")
    before = _session_stats.get("shield_failopens", 0)

    run_sql, calls = _spy_tool()
    try:
        result = run_sql(DANGEROUS)
        assert is_block(result)
    except AgentXSecurityBlock:
        pass
    assert calls == [], "the built-in floor still catches DROP TABLE under permissive"
    assert _session_stats["shield_failopens"] - before == 0, "a blocked call is not a fail-open"


def test_strict_is_the_default(monkeypatch):
    monkeypatch.delenv("AGENTX_POLICY_LOAD", raising=False)
    assert decorators._policy_load_posture() == "strict"


# =====================================================================
# PART B — the remaining fall-through is LOUD and COUNTED
# =====================================================================

def test_a_non_config_shield_bug_still_falls_open_but_is_counted(monkeypatch):
    """We deliberately did NOT hard-block on every shield exception: that turns a latent
    bug into an outage of the user's agent on the free tier, with no gateway behind it.
    So this still falls open -- but it is now counted, which is how instance 3 finds US.
    """
    def boom(*a, **k):
        raise RuntimeError("a bug that is not a policy-load failure")

    monkeypatch.setattr(decorators, "evaluate_call_keyless", boom)
    # DELTA, not absolute: the counter is a process-global the whole suite shares, so an
    # absolute assertion is order-dependent. The delta still pins the property exactly --
    # this call incremented it by exactly one.
    before = _session_stats.get("shield_failopens", 0)

    run_sql, calls = _spy_tool()
    run_sql("SELECT 1")

    assert calls == ["SELECT 1"], "a non-config shield bug still falls open (by design)"
    assert _session_stats["shield_failopens"] - before == 1, "...but it MUST be counted"


def test_failopen_banner_is_once_per_process_but_the_count_is_every_time(monkeypatch):
    """A hot loop must not spam the banner, but the COUNT must be true -- the pulse and
    the summary both read the count, not the banner."""
    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(decorators, "evaluate_call_keyless", boom)
    monkeypatch.setattr(decorators, "_SHIELD_FAILOPEN_BANNER_SHOWN", False)
    before = _session_stats.get("shield_failopens", 0)

    run_sql, calls = _spy_tool()
    run_sql("SELECT 1")
    run_sql("SELECT 2")
    run_sql("SELECT 3")

    assert len(calls) == 3
    assert _session_stats["shield_failopens"] - before == 3, "every fall-through counts"
    assert decorators._SHIELD_FAILOPEN_BANNER_SHOWN is True


def test_shield_failopens_is_pulsed_as_a_coarse_int_and_never_the_error_text():
    """The counter must reach the pulse (that is the whole point of counting it), and the
    exception text must NEVER leave the machine: a traceback can carry a file path, an
    argument, or a fragment of the user's data."""
    from agentx_sdk import pulse

    payload = pulse.build_payload(
        {**_session_stats, "shield_failopens": 7}, {"install_id": "x", "first_seen": "2026-01-01"})
    assert payload["session"]["shield_failopens"] == 7
    assert isinstance(payload["session"]["shield_failopens"], int)
    assert "shield_failopens" in pulse._ALLOWED_SESSION_KEYS

    flat = json.dumps(payload)
    for leaky in ("Traceback", "RuntimeError", "TypeError", ".agentx/policies.json"):
        assert leaky not in flat, f"the pulse must never carry {leaky!r}"


# =====================================================================
# C1 — a pull must never DEGRADE coaching
# =====================================================================

def _seed_with_safe_path():
    for seed in _BUILTIN_POLICY_KEYWORDS:
        if seed.get("preferred_alternative") and seed.get("id"):
            return seed
    pytest.skip("no built-in seed carries a preferred_alternative")


def test_pull_without_preferred_alternative_inherits_the_builtin_safe_path(tmp_path):
    """C1: a pulled policies.json WHOLLY REPLACES the built-in seeds, and cloud rows carry
    no `preferred_alternative`. So `agentx pull` silently DROPPED the "Safe alternative:"
    line, and a PAYING Control customer got WORSE coaching than a free keyless user -- a
    direct inversion of the tier ladder.

    After #205 the pulled row inherits the seed's safe path. It can still OVERRIDE it; it
    can no longer silently DELETE it."""
    seed = _seed_with_safe_path()
    seed_dir = _write_policies(tmp_path, [{
        "id": seed["id"],
        "name": seed["name"],
        "is_active": True,
        "blocked_intents": seed["blocked_intents"],
        "socratic_prompt": "A cloud-authored challenge.",
        # NO preferred_alternative -- exactly what the cloud sends today.
    }])

    loaded = load_local_policy_keywords(seed_dir=seed_dir)
    pulled = next(p for p in loaded if str(p["id"]) == str(seed["id"]))

    assert pulled["preferred_alternative"] == seed["preferred_alternative"], (
        "pulling org policies DROPPED the safe path -- a paying customer just got worse "
        "coaching than a free keyless user"
    )
    assert pulled["socratic_prompt"] == "A cloud-authored challenge.", "the pull still owns the challenge"


def test_pull_can_still_override_the_safe_path(tmp_path):
    """Inheritance must not become a cage: an org that DOES supply its own safe path wins."""
    seed = _seed_with_safe_path()
    seed_dir = _write_policies(tmp_path, [{
        "id": seed["id"], "name": seed["name"], "is_active": True,
        "blocked_intents": seed["blocked_intents"],
        "socratic_prompt": "Cloud challenge.",
        "preferred_alternative": "Use the org's approved archival job.",
    }])
    loaded = load_local_policy_keywords(seed_dir=seed_dir)
    pulled = next(p for p in loaded if str(p["id"]) == str(seed["id"]))
    assert pulled["preferred_alternative"] == "Use the org's approved archival job."


# =====================================================================
# Regressions from the high-effort review of this very PR
# =====================================================================

def test_a_non_list_top_level_fails_closed(tmp_path):
    """`{"policies": [...]}` -- the natural shape of a cloud API dump, or of a hand-merged
    file -- used to parse fine, yield ZERO policies, and fall through to the built-ins. A
    SILENT RULEBOOK SWAP: every org rule quietly unenforced while the boot banner still said
    the shield was up."""
    seed = tmp_path / ".agentx"
    seed.mkdir()
    (seed / "policies.json").write_text(
        json.dumps({"policies": [{"id": "POL-1", "blocked_intents": ["drop table"]}]}),
        encoding="utf-8")
    with pytest.raises(AgentXPolicyLoadError):
        load_local_policy_keywords(seed_dir=str(seed))


def test_a_falsy_malformed_enforcement_field_fails_closed(tmp_path):
    """The truthiness short-circuit. `if p.get("is_active", True) and p.get("blocked_intents")`
    ran BEFORE coercion, so a FALSY malformed value skipped validation entirely, the row was
    silently dropped, and (if it was the only row) we armed the built-ins instead -- the org's
    rule never fired and the tool EXECUTED.

    The original fuzz list was all-truthy and could not see this."""
    for falsy in ({}, "", 0, False):
        seed = tmp_path / f".agentx-{type(falsy).__name__}-{falsy!r}"
        seed.mkdir()
        (seed / "policies.json").write_text(
            json.dumps([{"id": "POL-ORG-1", "name": "Wire Transfer Guard",
                         "blocked_intents": falsy, "socratic_prompt": "no"}]),
            encoding="utf-8")
        with pytest.raises(AgentXPolicyLoadError):
            load_local_policy_keywords(seed_dir=str(seed))


def test_a_malformed_is_active_fails_closed(tmp_path):
    """`is_active` decides whether a rule is ARMED AT ALL. A malformed value used to read as
    'not active' and silently DISARM the rule."""
    seed = tmp_path / ".agentx"
    seed.mkdir()
    (seed / "policies.json").write_text(
        json.dumps([{"id": "POL-ORG-1", "name": "Wire Transfer Guard", "is_active": {},
                     "blocked_intents": ["transfer_funds"], "socratic_prompt": "no"}]),
        encoding="utf-8")
    with pytest.raises(AgentXPolicyLoadError) as err:
        load_local_policy_keywords(seed_dir=str(seed))
    assert err.value.field == "is_active"


def test_C1_does_NOT_inherit_across_a_NAME_collision(tmp_path):
    """C1 must inherit on IDENTITY (id), never on a name COINCIDENCE.

    A cloud row carrying a UUID id but reusing a seed's NAME for a differently-scoped rule
    would inherit that seed's `reversible_transform`. An EXFILTRATION block would then be
    coached to 'back up or snapshot the data first' -- the inherited coaching steering the
    agent TOWARD the harm the block existed to prevent. A safe path is class-specific."""
    seed_dir = tmp_path / ".agentx"
    seed_dir.mkdir()
    (seed_dir / "policies.json").write_text(json.dumps([{
        "id": "8f14e45f-ceea-467a-9575-000000000001",     # a cloud UUID: no seed has this id
        "name": "Mass Destructive Intent",                # ...but it REUSES a seed's name
        "is_active": True,
        "blocked_intents": ["select email"],              # ...for an EXFILTRATION rule
        "socratic_prompt": "Do not exfiltrate customer contact data.",
    }]), encoding="utf-8")

    loaded = load_local_policy_keywords(seed_dir=str(seed_dir))
    pol = loaded[0]

    assert pol["reversible_transform"] is None, (
        "inherited a destructive seed's reversible steer onto an exfiltration rule via a "
        "NAME collision -- the coaching would tell the agent to snapshot the data it was "
        "just blocked from touching"
    )
    assert pol["preferred_alternative"] is None, "safe paths are class-specific; do not guess"


def test_C1_inherits_the_seeds_CHALLENGE_too(tmp_path):
    """A malformed challenge on a pulled row used to degrade all the way to the generic
    'Policy Violation. Revise your action...' even though the shadowed seed's real,
    task-fitting text was right there. A GENERIC challenge measurably HURTS recovery
    (0/4 vs 3/3), so that is the exact coaching-degradation defect C1 exists to close."""
    seed = _seed_with_safe_path()
    seed_dir = _write_policies(tmp_path, [{
        "id": seed["id"], "name": seed["name"], "is_active": True,
        "blocked_intents": seed["blocked_intents"],
        "socratic_prompt": ["malformed"],                 # dropped by the coaching coercer
    }])
    loaded = load_local_policy_keywords(seed_dir=seed_dir)
    pol = next(p for p in loaded if str(p["id"]) == str(seed["id"]))

    assert pol["socratic_prompt"] == seed["socratic_prompt"], (
        "degraded to the generic challenge while holding the seed's good one"
    )
    assert "Policy Violation. Revise your action" not in pol["socratic_prompt"]


# =====================================================================
# Regressions from the SECOND review (fixes for the first review's fixes)
# =====================================================================

def test_deleting_a_malformed_file_before_the_first_call_unbricks(tmp_path, monkeypatch):
    """SENTINEL COLLISION. Import fails, so _POLICY_FILE_SIGNATURE stays 'unchecked'. If the
    operator deletes the file (via a separate CLI/edit) BEFORE this process makes its first
    protected call, the delete must still be detected.

    The first cut used None for BOTH 'unchecked' and 'no file exists', so deleting the file
    made `None == None` short-circuit to the STALE cached error and the agent stayed bricked
    forever -- with the exact remediation we print ('remove the file') as a dead end."""
    project = tmp_path / "proj"
    (project / ".agentx").mkdir(parents=True)
    f = project / ".agentx" / "policies.json"
    f.write_text("{ not json", encoding="utf-8")
    monkeypatch.chdir(project)

    # Simulate the import-time failure state: error latched, signature never set.
    monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR",
                        AgentXPolicyLoadError("boot", source=str(f)))
    monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)

    # Operator deletes the file BEFORE the first protected call in this process.
    f.unlink()

    run_sql, calls = _spy_tool()
    assert run_sql("SELECT 1") == "EXECUTED", "deleting the bad file must un-brick the agent"
    assert calls == ["SELECT 1"]


def test_C1_id_that_equals_a_seed_NAME_does_not_inherit(tmp_path):
    """The C1 index used to key by lowercased NAME too, so a pulled row whose `id` string
    equalled a seed's name inherited that seed's reversible_transform -- cross-class
    coaching that could steer an exfiltration block toward snapshotting the data. Id-only now.
    """
    seed = _seed_with_safe_path()
    seed_dir = _write_policies(tmp_path, [{
        "id": str(seed["name"]).strip().lower(),   # id string == a seed's lowercased NAME
        "name": "Some Org Rule",
        "is_active": True,
        "blocked_intents": ["select email"],
        "socratic_prompt": "Org challenge.",
    }])
    loaded = load_local_policy_keywords(seed_dir=seed_dir)
    pol = loaded[0]
    assert pol["reversible_transform"] is None, "inherited via a NAME collision -- must not"
    assert pol["preferred_alternative"] is None, "inherited via a NAME collision -- must not"


def test_a_malformed_child_does_not_silently_fall_through_to_the_parent(tmp_path, monkeypatch):
    """A malformed child .agentx/policies.json must FAIL CLOSED, not silently enforce a valid
    parent ../.agentx/policies.json -- that would be the silent rulebook swap this PR closes.
    Deliberate behavior change, pinned so a well-meant 'restore the fallback' can't reopen it.
    """
    parent = tmp_path / "repo"
    child = parent / "svc"
    (parent / ".agentx").mkdir(parents=True)
    (child / ".agentx").mkdir(parents=True)
    (parent / ".agentx" / "policies.json").write_text(
        json.dumps([{"id": "POL-PARENT", "blocked_intents": ["drop table"],
                     "socratic_prompt": "parent"}]), encoding="utf-8")
    (child / ".agentx" / "policies.json").write_text("{ broken", encoding="utf-8")
    monkeypatch.chdir(child)

    with pytest.raises(AgentXPolicyLoadError):
        load_local_policy_keywords(seed_dir=".agentx")


def test_permissive_counts_only_a_genuine_builtin_scan_crash_once(broken_project, monkeypatch):
    """The one fail-open in permissive: the BUILT-IN scan itself throwing, so the call truly
    ran unscreened. Counted exactly once -- not twice (the permissive branch no longer
    pre-counts, so there is a single count path)."""
    monkeypatch.setenv("AGENTX_POLICY_LOAD", "permissive")

    def boom(*a, **k):
        raise RuntimeError("scan also throws")
    monkeypatch.setattr(decorators, "evaluate_call_keyless", boom)

    before = _session_stats.get("shield_failopens", 0)
    run_sql, calls = _spy_tool()
    run_sql("SELECT 1")

    assert calls == ["SELECT 1"], "permissive + double fault still runs"
    assert _session_stats["shield_failopens"] - before == 1, "one call, one count -- not two"


def test_an_equal_size_fix_unbricks_even_if_the_signature_collides(broken_project):
    """A stat-based signature CANNOT guarantee it notices an equal-byte-length in-place edit
    (some filesystems leave (mtime_ns, inode, size) unchanged for a same-size rapid rewrite).
    So while FAILING CLOSED the accessor re-reads every call regardless of the signature --
    an operator's fix must un-brick even in the signature-collision case.

    This pins the behavior, not the tuple: it forces the worst case by leaving the cached
    signature pointing at the (now-fixed) file, and asserts the fix is still picked up."""
    f = broken_project / ".agentx" / "policies.json"

    run_sql, calls = _spy_tool()
    with pytest.raises(AgentXPolicyLoadError):
        run_sql("SELECT 1")                    # bricked; _POLICY_FILE_SIGNATURE now set

    # Fix the file, then FORCE the signature-collision worst case: pretend the stat tuple
    # did not change at all. A signature-cached accessor would stay bricked; ours re-reads.
    f.write_text(json.dumps([{"id": "POL-107", "name": "Mass Destructive Intent",
                              "is_active": True, "blocked_intents": ["drop table"],
                              "socratic_prompt": "Blocked."}]), encoding="utf-8")
    decorators._POLICY_FILE_SIGNATURE = decorators._policy_file_signature()  # collide on purpose

    assert run_sql("SELECT 1") == "EXECUTED", "a bricked agent must re-read despite a stale signature"
    assert calls == ["SELECT 1"]
