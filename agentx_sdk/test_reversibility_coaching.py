"""Reversibility-first coaching (recover-depth slice 2).

When a destructive / irreversible action is blocked keyless, the safe-path coaching LEADS
with a reversible-equivalent steer (soft-delete) so the agent can finish safely instead of
just being stopped. The steer is single-sourced in
``_REVERSIBLE_ALTERNATIVES`` (no per-seed drift), must render on BOTH keyless surfaces (the
``@agentx_protect`` decorator AND the agentx-mcp proxy), and must match what the
``agentx policies`` catalog advertises.

This file pins:
  * the library is wired for the destructive seeds and leaves exfiltration policies alone
    (no reversible equivalent for "don't exfiltrate");
  * no steer ships without a seed that can reach it (guards build-ahead-of-demand);
  * ``_effective_safe_path`` leads with the reversible steer but KEEPS the policy-specific
    alternative (e.g. the concrete "WHERE clause");
  * the ``agentx policies`` catalog advertises exactly what the block delivers (no
    catalog/delivery drift);
  * the steer reaches BOTH keyless block surfaces (the two share evaluate_call_keyless, so
    they must never coach differently).

Scope note: slice 2 is the COACHING jump only. The recovery credit stays strict same-tool
(the D1 honesty invariant guarded by test_recovery_continuity); crediting a cross-tool
coached alternative is a deferred, founder-reviewed follow-up.
"""
import io
import json

import pytest

from agentx_sdk import decorators as dec
from agentx_sdk.decorators import (
    _REVERSIBLE_ALTERNATIVES,
    _reversible_alternative,
    _effective_safe_path,
    _keyless_decision,
    _MASS_DESTRUCTIVE_POLICY,
    _SSRF_POLICY,
    builtin_policy_catalog,
)
from agentx_sdk import mcp_proxy as mp
from agentx_sdk import agentx_protect, is_block, reset_strike_state


# The distinctive phrase every reversible steer leads with (a surface-agnostic anchor).
_REVERSIBLE_LEAD = "reversible form you can undo"


@pytest.fixture(autouse=True)
def _force_builtins_and_keyless(monkeypatch):
    """Deterministic on any machine: pin the shipped builtins (a dev box may carry a pulled
    .agentx/policies.json that shadows them; the cold keyless install runs the builtins),
    run keyless (no key), and clear strike state so neither surface trips a circuit breaker
    from an unrelated test in the same process."""
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", list(dec._BUILTIN_POLICY_KEYWORDS))
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    reset_strike_state()


# --------------------------------------------------------------------------- #
# the library
# --------------------------------------------------------------------------- #
def test_wired_transforms_present_and_house_style():
    """The shipped library has the transforms its seeds reference, each a non-empty steer in
    house style (no em/en dash, the AI-tell scrubbed from user-facing copy)."""
    assert set(_REVERSIBLE_ALTERNATIVES) >= {"soft_delete"}
    for tid, steer in _REVERSIBLE_ALTERNATIVES.items():
        assert steer and steer.strip(), f"{tid}: empty steer"
        assert "—" not in steer and "–" not in steer, f"{tid}: dash in copy"
        assert _REVERSIBLE_LEAD in steer, f"{tid}: missing the reversible lead-in"


def test_no_transform_ships_without_a_seed():
    """No steer ships that no seed can reach (build-ahead-of-demand guard): every library
    key is referenced by at least one built-in seed's `reversible_transform`. Adding a
    transform for an action class the keyless floor does not yet seed fails here."""
    referenced = {p.get("reversible_transform") for p in dec._BUILTIN_POLICY_KEYWORDS}
    assert set(_REVERSIBLE_ALTERNATIVES) <= referenced, \
        "a reversible transform ships with no seed referencing it"


def test_reversible_alternative_only_for_tagged_policies():
    assert _reversible_alternative(_MASS_DESTRUCTIVE_POLICY) == _REVERSIBLE_ALTERNATIVES["soft_delete"]
    # An exfiltration policy has no reversible equivalent, so no steer.
    assert _reversible_alternative(_SSRF_POLICY) is None
    assert _reversible_alternative({"preferred_alternative": "x"}) is None
    # An unknown transform id (e.g. from a pulled policy) is dropped, not crashed.
    assert _reversible_alternative({"reversible_transform": "no_such_transform"}) is None


# --------------------------------------------------------------------------- #
# composition: lead with reversible, keep the specific alternative
# --------------------------------------------------------------------------- #
def test_effective_safe_path_leads_with_reversible_and_keeps_specifics():
    eff = _effective_safe_path(_MASS_DESTRUCTIVE_POLICY)
    assert eff.startswith(_REVERSIBLE_ALTERNATIVES["soft_delete"])
    assert "WHERE clause" in eff, "the policy-specific safe path must survive the lead-in"


def test_effective_safe_path_unchanged_without_a_transform():
    assert _effective_safe_path(_SSRF_POLICY) == _SSRF_POLICY["preferred_alternative"]


def test_effective_safe_path_handles_missing_base():
    assert _effective_safe_path({"reversible_transform": "soft_delete"}) == _REVERSIBLE_ALTERNATIVES["soft_delete"]
    assert _effective_safe_path({}) is None


# --------------------------------------------------------------------------- #
# the decision surfaces it (both keyless surfaces read this)
# --------------------------------------------------------------------------- #
def test_keyless_decision_surfaces_the_reversible_steer():
    decision = _keyless_decision(_MASS_DESTRUCTIVE_POLICY)
    assert _REVERSIBLE_LEAD in decision["preferred_alternative"]
    assert "WHERE clause" in decision["preferred_alternative"]


# --------------------------------------------------------------------------- #
# catalog == delivery (no drift between `agentx policies` and the block)
# --------------------------------------------------------------------------- #
def test_catalog_advertises_exactly_what_the_block_delivers():
    """The `agentx policies` discovery surface must show the SAME safe path the block
    delivers, reversible steer included, or `--edit` would seed from stale wording."""
    cat = {c["id"]: c for c in builtin_policy_catalog()}
    entry = cat[_MASS_DESTRUCTIVE_POLICY["id"]]
    assert entry["safe_path"] == _keyless_decision(_MASS_DESTRUCTIVE_POLICY)["preferred_alternative"]
    assert _REVERSIBLE_LEAD in entry["safe_path"]


# --------------------------------------------------------------------------- #
# cross-surface: the steer reaches BOTH keyless block paths
# --------------------------------------------------------------------------- #
def _drive_decorator_block(query):
    @agentx_protect(agent_id="reversibility_decorator")
    def run_sql(query, db_session=None):
        return {"status": "ok"}

    out = run_sql(query=query, db_session="<session>")
    assert is_block(out), "decorator shield must block the dangerous query"
    return str(out)          # the full model-facing payload, incl. the Safe alternative line


def _drive_mcp_block(query):
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "run_sql", "arguments": {"query": query}}}
    child, client = io.StringIO(), io.StringIO()
    mp._route_line(json.dumps(msg) + "\n", child, mp._ClientWriter(client),
                   {}, {}, 3, io.StringIO(), None)
    assert child.getvalue() == "", "mcp proxy must not forward the dangerous call"
    return json.loads(client.getvalue())["result"]["content"][0]["text"]


def test_reversible_steer_reaches_both_keyless_surfaces():
    """A DROP TABLE block delivers the reversibility-first steer on BOTH the decorator and
    the agentx-mcp proxy, and the concrete policy-specific path rides along on each."""
    dec_text = _drive_decorator_block("DROP TABLE users;")
    mcp_text = _drive_mcp_block("DROP TABLE users;")
    assert _REVERSIBLE_LEAD in dec_text, "decorator did not deliver the reversible steer"
    assert _REVERSIBLE_LEAD in mcp_text, "agentx-mcp did not deliver the reversible steer"
    assert "WHERE clause" in dec_text and "WHERE clause" in mcp_text


# --------------------------------------------------------------------------- #
# the REAL load path carries the transform (the tests above pin the raw seeds,
# so they would pass even if load_local_policy_keywords dropped the field)
# --------------------------------------------------------------------------- #
def test_loader_cold_install_keeps_builtin_reversible_transform(tmp_path, monkeypatch):
    """The cold keyless install (no pulled policies.json, the funnel target) arms the raw
    builtins, so the Mass Destructive seed must keep its reversible_transform through the
    loader for the steer to reach production, not only the pinned-seed tests above."""
    monkeypatch.chdir(tmp_path)              # no .agentx/policies.json here
    loaded = dec.load_local_policy_keywords()
    mdi = next(p for p in loaded if p["name"] == "Mass Destructive Intent")
    assert mdi.get("reversible_transform") == "soft_delete"


def test_loader_preserves_reversible_transform_for_pulled_policies(tmp_path, monkeypatch):
    """A pulled .agentx/policies.json that declares reversible_transform must carry it through
    the loader's field whitelist, or the 'a pulled policy opts in' steer silently vanishes for
    pulled/cloud policies (the exact drop code-review finding #2 caught)."""
    seed = tmp_path / ".agentx"
    seed.mkdir()
    (seed / "policies.json").write_text(json.dumps([{
        "id": "pulled-1", "name": "Pulled Destructive", "is_active": True,
        "blocked_intents": ["NUKE EVERYTHING"], "socratic_prompt": "No.",
        "preferred_alternative": "Do the scoped thing.",
        "reversible_transform": "soft_delete",
    }]), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    pulled = next(p for p in dec.load_local_policy_keywords() if p["id"] == "pulled-1")
    assert pulled.get("reversible_transform") == "soft_delete"
    assert dec._REVERSIBLE_ALTERNATIVES["soft_delete"] in dec._effective_safe_path(pulled)


@pytest.mark.parametrize("malformed", [["soft_delete"], {"id": "soft_delete"}, 7, True])
def test_malformed_reversible_transform_cannot_disarm_the_block(malformed):
    """FAIL-OPEN GUARD. A NON-string `reversible_transform` on a pulled/hand-edited policy made
    `_REVERSIBLE_ALTERNATIVES.get(<list>)` raise TypeError (unhashable). That escaped into the
    Local Shield's `except Exception`, which prints "bypassed" and FALLS THROUGH, so the
    keyless block never fired and the dangerous tool EXECUTED. Same bug class the sibling
    `category` field is already isinstance-guarded for. The steer is dropped; the BLOCK stands."""
    policy = {
        "id": "pulled-bad", "name": "Pulled Destructive", "is_active": True,
        "blocked_intents": ["DROP TABLE"], "socratic_prompt": "No.",
        "preferred_alternative": "Add a WHERE clause.",
        "reversible_transform": malformed,
    }
    # the lookup must not raise, and must not invent a steer from a malformed id
    assert _reversible_alternative(policy) is None
    # the policy-specific safe path survives; only the malformed steer is dropped
    assert "WHERE clause" in _effective_safe_path(policy)


def test_malformed_reversible_transform_still_blocks_end_to_end(tmp_path, monkeypatch):
    """The bypass, end to end on the keyless decorator surface: a pulled policy carrying a
    malformed reversible_transform must still BLOCK the tool call, not fail open and run it."""
    seed = tmp_path / ".agentx"
    seed.mkdir()
    (seed / "policies.json").write_text(json.dumps([{
        "id": "pulled-bad", "name": "Pulled Destructive", "is_active": True,
        "blocked_intents": ["DROP TABLE"], "socratic_prompt": "Blocked.",
        "reversible_transform": ["soft_delete"],   # malformed: a JSON array
    }]), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", dec.load_local_policy_keywords())

    executed = []

    @agentx_protect(agent_id="reversibility_malformed")
    def run_sql(query, db_session=None):
        executed.append(query)
        return {"status": "ok"}

    out = run_sql(query="DROP TABLE users;", db_session="<session>")
    assert is_block(out), "keyless shield failed OPEN on a malformed policy"
    assert executed == [], "the dangerous tool EXECUTED despite the policy"
