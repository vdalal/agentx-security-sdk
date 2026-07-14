"""PR #205 on the MCP surface — REACH, not just correctness.

Both surfaces run the keyless shield. A fix wired only into `decorators.py` reaches
decorator users and ZERO MCP users: that is exactly the gap #204 hit.

⚠️ THE FIRST CUT OF THIS FILE WAS A LIE, and a high-effort review caught it. It
monkeypatched `evaluate_call_keyless` to raise `AgentXPolicyLoadError` and asserted the
proxy failed closed. But `evaluate_call_keyless` only scans an already-loaded keyword list
and can NEVER raise that: the loader raises at IMPORT and `decorators` catches it into a
module global the proxy never read. So the proxy's fail-closed branch was DEAD CODE, a
malformed policies.json silently armed the built-ins for every MCP user, and these tests
were GREEN.

    A test that green-lights a path production cannot reach is worse than no test:
    it CERTIFIES the very gap it was written to close.

So every test here now drives the REAL path: a real malformed `.agentx/policies.json`
under a real cwd, read through `current_policy_load_error()` -- the same accessor the
decorator uses. No monkeypatched detector.

The three MCP-specific properties under test:
  1. FAIL CLOSED  — a malformed rulebook must NOT forward the call. Forwarding IS executing
     it: on the keyless MCP wedge nothing sits behind the proxy.
  2. NEVER CRASH  — agentx-mcp wraps SOMEONE ELSE'S server. An uncaught exception kills the
     proxy and takes the user's whole agent down.
  3. STDOUT STAYS CLEAN — stdout is the JSON-RPC stream. Every human-facing word to stderr.
"""
import io
import json

import pytest

from agentx_sdk import decorators
import agentx_sdk.mcp_proxy as mp


def _call(name="run_sql", args=None, req_id=1):
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": name, "arguments": args or {"query": "DROP TABLE users;"}}}


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(mp, "_MCP_BANNERS_SHOWN", set())
    monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR", None)
    monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)
    monkeypatch.delenv("AGENTX_POLICY_LOAD", raising=False)


@pytest.fixture
def broken_rulebook(tmp_path, monkeypatch):
    """A REAL malformed .agentx/policies.json under the process cwd. No monkeypatching of
    the detector: this is the path a real MCP user takes."""
    project = tmp_path / "proj"
    (project / ".agentx").mkdir(parents=True)
    (project / ".agentx" / "policies.json").write_text(
        json.dumps([{"id": "POL-ORG-1", "name": "Wire Transfer Guard", "is_active": True,
                     "blocked_intents": 12345, "socratic_prompt": "no"}]),
        encoding="utf-8")
    monkeypatch.chdir(project)
    monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)
    monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR", None)
    return project


def test_malformed_rulebook_does_not_forward_the_call(broken_rulebook):
    """✦ THE HEADLINE ✦ Driven through the real loader. "forward" here would mean the
    DROP TABLE reaches the wrapped server and RUNS."""
    stdout, stderr = io.StringIO(), io.StringIO()
    stats = {}

    verdict = mp._screen_message(_call(), stats, {}, 3, mp._ClientWriter(stdout), stderr)

    assert verdict == "block", "a blind shield MUST NOT forward the call to the server"
    # A strict fail-CLOSED is a BLOCK, not a fail-open: it must NOT touch shield_failopens.
    # That counter means "ran unscreened" on every surface, and counting safe blocks here
    # polluted the exact metric the founder uses to find real bypasses (finding #6).
    assert not stats.get("shield_failopens"), "a safe block must not inflate the fail-open metric"


def test_it_comes_back_as_a_clean_tool_error_not_a_crash(broken_rulebook):
    """agentx-mcp wraps someone else's server. A raise kills the proxy and takes the user's
    agent down. It must be a CallToolResult with isError: true, so the run SURVIVES."""
    stdout = io.StringIO()
    mp._screen_message(_call(), {}, {}, 3, mp._ClientWriter(stdout), io.StringIO())

    sent = stdout.getvalue().strip()
    assert sent, "the host must receive a response, not silence"
    msg = json.loads(sent.splitlines()[-1])
    assert msg["id"] == 1
    assert msg["result"]["isError"] is True, "must be a tool ERROR the host can survive"

    text = msg["result"]["content"][0]["text"]
    assert "NOT run" in text, "the model must be told the call did not execute"
    assert "policies.json" in text, "name the file to fix"
    assert "agentx policies --check" in text, "name the fix"
    assert "—" not in text, "house style: no em dashes in user-facing copy"


def test_permissive_runs_on_builtins_and_does_NOT_pollute_the_metric(broken_rulebook, monkeypatch):
    """Permissive + malformed file falls back to the BUILT-IN floor, which STILL screens the
    call. A benign call runs -- but it was SCREENED, so it is NOT a fail-open and must NOT
    touch shield_failopens (counting it mislabeled a screened call as a bypass)."""
    monkeypatch.setenv("AGENTX_POLICY_LOAD", "permissive")
    stats = {}
    verdict = mp._screen_message(
        _call(name="benign", args={"q": "SELECT 1"}), stats, {}, 3,
        mp._ClientWriter(io.StringIO()), io.StringIO())

    assert verdict == "forward", "permissive runs the benign call on the built-in floor"
    assert not stats.get("shield_failopens"), "a screened call is NOT a fail-open"


def test_permissive_still_BLOCKS_a_dangerous_call_via_the_builtins(broken_rulebook, monkeypatch):
    """The built-in floor is armed under permissive, so a DROP TABLE is still BLOCKED -- and a
    block is not a fail-open either, so the metric stays clean."""
    monkeypatch.setenv("AGENTX_POLICY_LOAD", "permissive")
    stats = {}
    verdict = mp._screen_message(
        _call(), stats, {}, 3, mp._ClientWriter(io.StringIO()), io.StringIO())

    assert verdict == "block", "the built-in floor still catches DROP TABLE under permissive"
    assert not stats.get("shield_failopens"), "a blocked call is not a fail-open"


def test_permissive_counts_ONLY_a_genuine_builtin_scan_crash(broken_rulebook, monkeypatch):
    """The one thing that IS a fail-open in permissive: the built-in scan itself throwing, so
    the call truly ran unscreened. That is counted, exactly once."""
    monkeypatch.setenv("AGENTX_POLICY_LOAD", "permissive")
    monkeypatch.setattr(mp, "evaluate_call_keyless",
                        lambda q: (_ for _ in ()).throw(RuntimeError("scan crash")))
    stats = {}
    verdict = mp._screen_message(
        _call(name="benign", args={"q": "SELECT 1"}), stats, {}, 3,
        mp._ClientWriter(io.StringIO()), io.StringIO())

    assert verdict == "forward"
    assert stats["shield_failopens"] == 1, "a genuine unscreened run IS counted, once"


def test_a_healthy_rulebook_does_not_fail_closed(tmp_path, monkeypatch):
    """The other direction: a VALID policies.json must not be mistaken for a broken one."""
    project = tmp_path / "ok"
    (project / ".agentx").mkdir(parents=True)
    (project / ".agentx" / "policies.json").write_text(
        json.dumps([{"id": "POL-107", "name": "Mass Destructive Intent", "is_active": True,
                     "blocked_intents": ["drop table"], "socratic_prompt": "Blocked."}]),
        encoding="utf-8")
    monkeypatch.chdir(project)
    monkeypatch.setattr(decorators, "_POLICY_FILE_SIGNATURE", decorators._UNCHECKED)
    monkeypatch.setattr(decorators, "_POLICY_LOAD_ERROR", None)

    stats = {}
    verdict = mp._screen_message(
        _call(name="benign", args={"q": "SELECT 1"}), stats, {}, 3,
        mp._ClientWriter(io.StringIO()), io.StringIO())

    assert verdict == "forward"
    assert not stats.get("shield_failopens"), "a healthy rulebook is not a shield failure"


# =====================================================================
# NEVER CRASH — the regression the review caught
# =====================================================================

@pytest.mark.parametrize("params", [["an", "array"], "a string", 12345, True])
def test_a_malformed_params_does_not_kill_the_proxy(params):
    """✦ THE REGRESSION ✦ JSON-RPC permits ARRAY params, and this proxy screens an UNTRUSTED
    client stream. The first cut bound `name` INSIDE the try, so `params.get` raised
    AttributeError BEFORE `name` existed, and the fail-open handler's own `str(name)` then
    raised UnboundLocalError -- which ESCAPED _screen_message, was caught by the pump loop,
    and TORE DOWN the user's entire MCP session.

    One malformed tools/call would have killed the user's agent. The exact outcome the code
    comments swear must never happen. If this test raises, we shipped it."""
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    stats = {}

    verdict = mp._screen_message(
        msg, stats, {}, 3, mp._ClientWriter(io.StringIO()), io.StringIO())

    assert verdict in ("block", "forward"), "must return a verdict, never propagate"


def test_an_id_less_call_is_still_not_forwarded(broken_rulebook):
    """A notification (no id) has nowhere to send an error response. It must still FAIL
    CLOSED -- dropping the call, never forwarding it."""
    stdout = io.StringIO()
    msg = _call()
    msg.pop("id")

    verdict = mp._screen_message(msg, {}, {}, 3, mp._ClientWriter(stdout), io.StringIO())

    assert verdict == "block", "an id-less call must still fail closed, not forward"
    assert stdout.getvalue().strip() == "", "no response is possible without an id"


def test_the_operator_message_never_touches_stdout(broken_rulebook):
    """stdout is the JSON-RPC stream. A stray banner byte there corrupts the protocol."""
    stdout, stderr = io.StringIO(), io.StringIO()
    mp._screen_message(_call(), {}, {}, 3, mp._ClientWriter(stdout), stderr)

    for line in stdout.getvalue().splitlines():
        if line.strip():
            json.loads(line)          # every stdout line MUST be valid JSON-RPC
    assert "Shield" in stderr.getvalue(), "the human-facing banner belongs on stderr"


# =====================================================================
# PART B — the remaining fall-through is loud and counted, on BOTH surfaces
# =====================================================================

def test_a_non_config_shield_bug_still_forwards_but_is_counted(monkeypatch):
    """We deliberately still fail OPEN on a non-config bug (a hard block would take down the
    user's agent on the free tier), but it is now COUNTED."""
    def boom(_q):
        raise RuntimeError("some other shield bug")

    monkeypatch.setattr(mp, "evaluate_call_keyless", boom)
    stats = {}

    verdict = mp._screen_message(
        _call(), stats, {}, 3, mp._ClientWriter(io.StringIO()), io.StringIO())

    assert verdict == "forward", "a non-config bug still falls open (by design)"
    assert stats["shield_failopens"] == 1, "...but it MUST be counted"


def test_failopens_are_counted_on_both_surfaces_not_just_the_decorator():
    """The REACH invariant, pinned: the same counter key on both surfaces."""
    from agentx_sdk.decorators import _session_stats
    assert "shield_failopens" in _session_stats, "decorator surface must carry the counter"

    stats = {}
    mp._record_mcp_shield_failopen(stats, "t", RuntimeError("x"), io.StringIO())
    assert stats["shield_failopens"] == 1, "MCP surface must carry the SAME counter"


def test_the_mcp_banner_is_once_per_process_but_the_count_is_every_time():
    stats, log = {}, io.StringIO()
    for _ in range(3):
        mp._record_mcp_shield_failopen(stats, "t", RuntimeError("x"), log)

    assert stats["shield_failopens"] == 3
    assert log.getvalue().count("AgentX Local Shield") == 1, "banner is once per process"


def test_both_surfaces_share_ONE_operator_message():
    """A near-verbatim COPY of the operator text used to live in mcp_proxy, in the one module
    whose docstring says its whole purpose is that the two paths "can never drift"."""
    assert not hasattr(mp, "_policy_load_error_text"), "the duplicate must be gone"
    assert mp._policy_load_error_message is decorators._policy_load_error_message
