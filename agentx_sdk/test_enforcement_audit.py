"""AGENTX_ENFORCEMENT = audit | enforce — the trust-before-enforce posture.

Audit runs the SAME detection but RECORDS what would have blocked and lets the original
call proceed (designs/shadow-audit-mode-spec.md). These pin the load-bearing promises:
  * audit PROCEEDS (returns the real tool result), enforce BLOCKS;
  * audit records a WOULD_BLOCK ledger row + a `would_blocks` count, and takes NONE of the
    CHALLENGED accounting (no intercept/critical count, no challenged-trace, no strike),
    so an audit install reads as EVALUATING, never "protected";
  * the per-tool `enforcement=` override beats the global env (both directions);
  * the circuit breaker and the fail-closed availability block are EXEMPT (audit is about
    policy false-positive risk, not letting a runaway loop or an unverifiable action run).
"""
import sqlite3

import pytest

import agentx_sdk.decorators as dec
from agentx_sdk.decorators import (
    agentx_protect, _session_stats, _strike_owner, _client,
    AgentXCircuitBreakerTripped, _resolve_enforcement, start_secure_session,
)


POLICY_VIOLATION = {
    "error": "AgentX Policy Violation",
    "policy_id": "POL-SEC-001",
    "policy_triggered": "Secrets and PII Exfiltration",
    "challenge": "Do not exfiltrate secrets.",
    "receipt_id": "rcpt-gw-1",
}
BREAKER = {
    "error": "AgentX Cognitive Loop Aborted",
    "receipt_id": "rcpt-brk",
    "challenge": "Maximum consecutive policy retry attempts reached.",
}
UNREACHABLE = {"status": "REASONING_ENGINE_UNREACHABLE", "reason": "connection_error"}


# Module-level tools (signatures fixed at decoration time, like the real API surface).
@agentx_protect(agent_id="audit_agent")
def gw_tool(sql_query: str):
    return f"EXECUTED: {sql_query}"


@agentx_protect(agent_id="audit_enforced", enforcement="enforce")
def enforced_tool(sql_query: str):
    return f"EXECUTED: {sql_query}"


@agentx_protect(agent_id="audit_override", enforcement="audit")
def per_tool_audit(sql_query: str):
    return f"EXECUTED: {sql_query}"


@pytest.fixture(autouse=True)
def log_capture(monkeypatch):
    """Capture log_intercept calls (assertable + no real .agentx.db write). Autouse so no
    decorator-driven test pollutes the repo ledger; requestable to read the captured rows."""
    rows = []
    monkeypatch.setattr(dec, "log_intercept", lambda *a, **k: rows.append(a))
    return rows


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    for key in ("would_blocks", "intercepts", "critical_blocks", "degraded_executions"):
        _session_stats[key] = 0
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    _session_stats["human_resolved_traces"].clear()
    _session_stats["consecutive_strikes"].clear()
    _session_stats["gateway_reached"] = False
    _session_stats["reasoning_enabled"] = None
    _session_stats["block_category"] = None
    _strike_owner.clear()
    dec._AUDIT_BANNER_SHOWN = False   # once-per-process banner: reset so order can't hide it
    # Shield bypassed by default so a test reaches the GATEWAY path unless it opts in;
    # posture cleared so each test sets its own.
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    monkeypatch.delenv("AGENTX_ENFORCEMENT", raising=False)
    monkeypatch.delenv("AGENTX_FAIL_MODE", raising=False)
    start_secure_session()
    yield


def _statuses(rows):
    # log_intercept(trace, agent, tool, policy_id, policy_name, status, ...)
    return [a[5] for a in rows if len(a) > 5]


# =============================================================================
# Resolver
# =============================================================================

def test_resolve_defaults_to_enforce(monkeypatch):
    monkeypatch.delenv("AGENTX_ENFORCEMENT", raising=False)
    assert _resolve_enforcement() == "enforce"


def test_resolve_reads_env_audit(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    assert _resolve_enforcement() == "audit"


def test_resolve_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "  AUDIT ")
    assert _resolve_enforcement() == "audit"


def test_resolve_per_tool_override_wins(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    assert _resolve_enforcement("enforce") == "enforce"
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "enforce")
    assert _resolve_enforcement("audit") == "audit"


def test_resolve_invalid_value_defaults_to_enforce(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "observe")  # not a real level
    assert _resolve_enforcement() == "enforce"


def test_resolve_empty_defaults_to_enforce(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "")
    assert _resolve_enforcement() == "enforce"


# =============================================================================
# Gateway policy path
# =============================================================================

def test_gateway_audit_proceeds_and_records(monkeypatch, log_capture):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: POLICY_VIOLATION)
    result = gw_tool(sql_query="SELECT ssn FROM users")
    assert result == "EXECUTED: SELECT ssn FROM users"   # proceeded, not blocked
    assert not dec.is_block(result)
    assert _session_stats["would_blocks"] == 1
    assert _session_stats["intercepts"] == 0             # NOT counted as a real block
    assert _session_stats["critical_blocks"] == 0
    assert _session_stats["challenged_traces"] == set()  # no recovery-denominator pollution
    assert "WOULD_BLOCK" in _statuses(log_capture)
    assert "CHALLENGED" not in _statuses(log_capture)


def test_gateway_enforce_still_blocks(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "enforce")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: POLICY_VIOLATION)
    result = gw_tool(sql_query="SELECT ssn FROM users")
    assert dec.is_block(result)
    assert _session_stats["would_blocks"] == 0
    assert _session_stats["intercepts"] == 1


def test_gateway_default_env_enforces(monkeypatch):
    monkeypatch.delenv("AGENTX_ENFORCEMENT", raising=False)
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: POLICY_VIOLATION)
    assert dec.is_block(gw_tool(sql_query="SELECT ssn FROM users"))
    assert _session_stats["would_blocks"] == 0


# =============================================================================
# Per-tool override (both directions)
# =============================================================================

def test_per_tool_enforce_overrides_global_audit(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: POLICY_VIOLATION)
    result = enforced_tool(sql_query="SELECT ssn FROM users")
    assert dec.is_block(result)                 # the surgical exception stays hard-blocked
    assert _session_stats["would_blocks"] == 0


def test_per_tool_audit_overrides_global_enforce(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "enforce")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: POLICY_VIOLATION)
    result = per_tool_audit(sql_query="SELECT ssn FROM users")
    assert result == "EXECUTED: SELECT ssn FROM users"
    assert _session_stats["would_blocks"] == 1


# =============================================================================
# Exemptions: circuit breaker + fail-closed still stop even in audit
# =============================================================================

def test_circuit_breaker_still_raises_in_audit(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: BREAKER)
    with pytest.raises(AgentXCircuitBreakerTripped):
        gw_tool(sql_query="SELECT 1")
    assert _session_stats["would_blocks"] == 0   # a breaker trip is not a would-block


def test_fail_closed_still_blocks_in_audit(monkeypatch):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: UNREACHABLE)
    result = gw_tool(sql_query="SELECT 1")
    assert dec.is_block(result)                  # availability block, audit does not relax it
    assert "failclosed-no-engine" in result
    assert _session_stats["would_blocks"] == 0


# =============================================================================
# Keyword-shield (keyless Layer-0) path
# =============================================================================

def _arm_shield(monkeypatch):
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)  # shield ON
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", [{
        "id": "POL-LS-BRK", "name": "Mass Destructive Intent",
        "blocked_intents": ["drop table"], "category": "DESTRUCTIVE_ACTION",
        "socratic_prompt": "Local prompt."}])


def test_keyword_shield_audit_proceeds_and_categorizes(monkeypatch, log_capture):
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    _arm_shield(monkeypatch)

    @agentx_protect(agent_id="audit_ks")
    def drop_tool(sql_query: str):
        return f"RAN: {sql_query}"

    start_secure_session()
    result = drop_tool(sql_query="DROP TABLE users;")
    assert result == "RAN: DROP TABLE users;"            # proceeded, no coaching block
    assert _session_stats["would_blocks"] == 1
    assert _session_stats["intercepts"] == 0
    assert _session_stats["block_category"] == "DESTRUCTIVE_ACTION"  # coarse pulse signal set
    # A strike still accrues in audit (below): it is what lets the keyless runaway breaker
    # trip, per spec — the ONLY local halt when there is no gateway. A single would-block
    # just proceeds; it does not block.
    assert _session_stats["consecutive_strikes"].get("drop_tool", 0) == 1
    assert "WOULD_BLOCK" in _statuses(log_capture)


def test_keyword_shield_audit_still_trips_breaker(monkeypatch, log_capture):
    """Spec: the circuit breaker is EXEMPT — a runaway loop must still halt even in audit.
    Keyless, the Layer-0 keyword breaker is the only local runaway protection, so a sustained
    same-tool would-block loop still trips the ceiling (each pre-ceiling call proceeds and
    records a would-block; the call past the ceiling raises)."""
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "3")
    _arm_shield(monkeypatch)

    @agentx_protect(agent_id="audit_ks2")
    def drop_tool2(sql_query: str):
        return "ran"

    start_secure_session()
    for _ in range(3):                                    # calls 1-3: below the ceiling
        assert drop_tool2(sql_query="DROP TABLE users;") == "ran"   # proceed + record
    assert _session_stats["would_blocks"] == 3
    assert _session_stats["consecutive_strikes"]["drop_tool2"] == 3
    with pytest.raises(AgentXCircuitBreakerTripped):     # call 4: runaway halts even in audit
        drop_tool2(sql_query="DROP TABLE users;")
    assert _session_stats["would_blocks"] == 3           # the tripped call is not a would-block


# =============================================================================
# Ledger separation — WOULD_BLOCK never inflates the recovery loop
# =============================================================================

def test_would_block_ledger_is_separate(tmp_path, monkeypatch):
    import agentx_sdk.db as db
    from agentx_sdk.db import (init_db, get_would_block_summary,
                               get_block_frequency, get_lifetime_stats)
    dbp = str(tmp_path / ".agentx_test.db")
    monkeypatch.setattr(db, "DB_PATH", dbp)
    init_db()
    conn = sqlite3.connect(dbp)
    conn.executemany(
        "INSERT INTO event_log (timestamp, trace_id, agent_id, tool_name, policy_id, "
        "policy_name, status, tokens_saved, time_saved_mins) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (1, "t1", "a", "tool", "POL-1", "Secrets and PII Exfiltration", "WOULD_BLOCK", 1500, 5),
            (2, "t2", "a", "tool", "POL-1", "Secrets and PII Exfiltration", "WOULD_BLOCK", 1500, 5),
            (3, "t3", "a", "tool", "POL-2", "Mass Destructive Intent", "CHALLENGED", 1500, 5),
        ],
    )
    conn.commit()
    conn.close()

    summary = get_would_block_summary(path=dbp)
    assert summary["total"] == 2
    assert summary["policies"][0]["policy_name"] == "Secrets and PII Exfiltration"
    assert summary["policies"][0]["would_blocks"] == 2

    # WOULD_BLOCK excluded from the recovery-loop counters (no rate/protected pollution).
    freq = get_block_frequency(path=dbp)
    assert all(row["policy_name"] != "Secrets and PII Exfiltration" for row in freq)
    stats = get_lifetime_stats()   # reads the monkeypatched DB_PATH
    assert stats["total_intercepts"] == 1   # only the single CHALLENGED episode


def test_would_block_summary_empty_on_no_db(tmp_path, monkeypatch):
    from agentx_sdk.db import get_would_block_summary
    missing = str(tmp_path / "nope.db")
    assert get_would_block_summary(path=missing) == {"total": 0, "policies": []}


# =============================================================================
# Pulse — an audit-only install is EVALUATING, not protected
# =============================================================================

def test_demo_next_steps_point_to_audit_onramp():
    """`agentx demo` proves the Shield on a demo attack; the next step it offers must be the
    risk-free audit on-ramp (run it on YOUR agent, blocking nothing), on BOTH the decorator
    and MCP-client branches."""
    from agentx_sdk.cli import _demo_next_steps
    decorator_branch = "\n".join(_demo_next_steps(None))
    assert "AGENTX_ENFORCEMENT=audit" in decorator_branch
    assert "agentx insights" in decorator_branch
    mcp_branch = "\n".join(_demo_next_steps(("Claude Desktop", "path/to/config.json")))
    assert "AGENTX_ENFORCEMENT=audit" in mcp_branch


def test_pulse_carries_would_blocks_but_not_protected():
    from agentx_sdk import pulse
    stats = {"total_calls": 3, "intercepts": 0, "critical_blocks": 0, "would_blocks": 2}
    payload = pulse.build_payload(stats, {"install_id": "x"})
    assert payload["session"]["would_blocks"] == 2
    assert payload["session"]["had_block"] is False   # NOT counted as a protected/block install
    assert payload["session"]["intercepts"] == 0
    assert "would_blocks" in pulse._ALLOWED_SESSION_KEYS


def test_audit_emits_loud_startup_banner_once(monkeypatch, caplog):
    """A non-blocking posture must announce itself loudly so a headless deploy is never
    silently unprotected — but only ONCE per process (not per call)."""
    import logging
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "audit")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    with caplog.at_level(logging.WARNING, logger="agentx"):
        gw_tool(sql_query="SELECT 1")
        assert sum("AUDIT mode" in r.getMessage() for r in caplog.records) == 1
        caplog.clear()
        gw_tool(sql_query="SELECT 2")   # once-per-process: no repeat banner
        assert not any("AUDIT mode" in r.getMessage() for r in caplog.records)


def test_enforce_emits_no_audit_banner(monkeypatch, caplog):
    import logging
    monkeypatch.setenv("AGENTX_ENFORCEMENT", "enforce")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    with caplog.at_level(logging.WARNING, logger="agentx"):
        gw_tool(sql_query="SELECT 1")
        assert not any("AUDIT mode" in r.getMessage() for r in caplog.records)


def test_client_forwards_enforcement_only_when_audit(monkeypatch):
    """The SDK forwards `enforcement` to /v1/evaluate ONLY for audit, so the gateway can skip
    persisting a CHALLENGED for an evaluating install. An enforcing/legacy caller's payload
    stays byte-identical (the gateway reads absent as enforce)."""
    import agentx_sdk.client as client_mod
    captured = {}

    class _Resp:
        status_code = 200
        headers = {}

        def json(self):
            return {"status": "ALLOWED"}

    monkeypatch.setattr(client_mod.requests, "post",
                        lambda url, json=None, headers=None, timeout=None: (captured.update(json or {}), _Resp())[1])
    monkeypatch.setenv("AGENTX_API_KEY", "k")
    c = client_mod.AgentXClient()

    c.evaluate_intent("a", "q", "cot", enforcement="enforce")
    assert "enforcement" not in captured          # enforce -> omitted (byte-identical payload)
    captured.clear()
    c.evaluate_intent("a", "q", "cot", enforcement="audit")
    assert captured.get("enforcement") == "audit"  # audit -> forwarded
