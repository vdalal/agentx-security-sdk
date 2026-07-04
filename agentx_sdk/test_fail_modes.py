import pytest

import agentx_sdk.decorators as dec_module
from agentx_sdk.decorators import agentx_protect, _session_stats, _strike_owner, _client, AgentXSecurityBlock, AgentXCircuitBreakerTripped


# Two module-level test tools: one untyped (returns str), one typed (returns dict)
@agentx_protect(agent_id="failmode_test_agent")
def mock_tool(sql_query: str):
    return f"EXECUTED: {sql_query}"


@agentx_protect(agent_id="failmode_typed_agent")
def mock_typed_tool(sql_query: str) -> dict:
    return {"status": "ok", "result": sql_query}


UNREACHABLE_CONNECTION = {"status": "REASONING_ENGINE_UNREACHABLE", "reason": "connection_error"}
UNREACHABLE_TIMEOUT    = {"status": "REASONING_ENGINE_UNREACHABLE", "reason": "timeout"}


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    """Clean session stats and bypass the local keyword shield before each test."""
    _session_stats["degraded_executions"] = 0
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    _session_stats["human_resolved_traces"].clear()
    _session_stats["consecutive_strikes"].clear()
    _session_stats["gateway_reached"] = False  # coarse pulse stage signal — reset so a reached-gateway test can't leak into the next
    _session_stats["reasoning_enabled"] = None  # companion pulse stage signal — reset alongside gateway_reached (SDK session-globals isolation)
    _session_stats["block_category"] = None  # companion pulse signal — reset with the other pulse-stage globals
    _strike_owner.clear()  # companion to consecutive_strikes — must reset together or the per-trace breaker reset leaks across tests
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    yield


# =============================================================================
# Fail-open (default)
# =============================================================================

def test_fail_open_executes_tool(monkeypatch):
    """Gateway unreachable + fail-open → tool runs and returns its real result."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "open")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    result = mock_tool(sql_query="SELECT * FROM users;")
    assert result == "EXECUTED: SELECT * FROM users;"


def test_fail_open_increments_degraded_count(monkeypatch):
    """Each fail-open execution increments the degraded_executions counter."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "open")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    mock_tool(sql_query="SELECT 1;")
    mock_tool(sql_query="SELECT 2;")
    assert _session_stats["degraded_executions"] == 2


def test_fail_open_resets_consecutive_strikes(monkeypatch):
    """Fail-open clears any pre-existing strike count (gateway came back, loop can continue)."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "open")
    _session_stats["consecutive_strikes"]["mock_tool"] = 2
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    mock_tool(sql_query="SELECT 1;")
    assert _session_stats["consecutive_strikes"]["mock_tool"] == 0


def test_fail_open_is_default_when_env_unset(monkeypatch):
    """AGENTX_FAIL_MODE not set → behaves as open; tool executes normally."""
    monkeypatch.delenv("AGENTX_FAIL_MODE", raising=False)
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    result = mock_tool(sql_query="SELECT 1;")
    assert result == "EXECUTED: SELECT 1;"
    assert _session_stats["degraded_executions"] == 1


def test_fail_open_on_timeout(monkeypatch):
    """Timeout (reason=timeout) is treated as fail-open the same as connection_error."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "open")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_TIMEOUT)
    result = mock_tool(sql_query="SELECT 1;")
    assert result == "EXECUTED: SELECT 1;"
    assert _session_stats["degraded_executions"] == 1


# =============================================================================
# Fail-closed
# =============================================================================

def test_fail_closed_blocks_execution(monkeypatch):
    """Gateway unreachable + fail-closed → tool body must never run."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)

    executed = []

    @agentx_protect(agent_id="failmode_test_agent")
    def sentinel(q: str):
        executed.append(q)
        return f"EXECUTED: {q}"

    sentinel(q="SELECT 1;")
    assert not executed


def test_fail_closed_returns_block_string(monkeypatch):
    """Fail-closed returns the security block marker string for untyped tools."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    result = mock_tool(sql_query="SELECT 1;")
    assert "🚨 [AgentX Security Block]" in result
    assert "failclosed-no-engine" in result


def test_fail_closed_accrues_strikes(monkeypatch):
    """Each fail-closed block increments consecutive_strikes so the circuit breaker can fire."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    mock_tool(sql_query="SELECT 1;")
    mock_tool(sql_query="SELECT 2;")
    assert _session_stats["consecutive_strikes"]["mock_tool"] == 2


def test_offline_fallback_breaker_trips_at_ceiling(monkeypatch):
    """Gateway unreachable + fail-closed: strikes accrue each blocked call (0→1→2→3) and the
    4th call trips the OFFLINE-ONLY breaker fallback. The SDK enforces the strike ceiling
    locally ONLY here — because the gateway (the decision authority) can't be reached. On a
    reachable call the gateway owns the verdict (Path B)."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "3")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)

    # Calls 1-3: fail-closed blocks accrue strikes 1, 2, 3 (below the ceiling — no trip).
    for i in range(3):
        mock_tool(sql_query=f"SELECT {i};")
    assert _session_stats["consecutive_strikes"]["mock_tool"] == 3

    # Call 4: strikes already at the ceiling → offline fallback trips before fail-closed handling.
    with pytest.raises(AgentXCircuitBreakerTripped) as exc_info:
        mock_tool(sql_query="SELECT 4;")
    assert "OFFLINE FALLBACK" in str(exc_info.value)


def test_fail_closed_does_not_seed_self_correction(monkeypatch):
    """Fail-closed is an availability event, not a policy challenge: it must NOT mark
    the trace recoverable. (Doing so previously seeded a correction with no matching
    intercept and drifted the recovery rate past 100%.)"""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    mock_tool(sql_query="SELECT 1;")
    assert _session_stats["challenged_traces"] == set()
    assert _session_stats["recovered_traces"] == set()


def test_fail_closed_typed_tool_raises_security_block(monkeypatch):
    """For -> dict typed tools, fail-closed raises AgentXSecurityBlock instead of returning a string."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    with pytest.raises(AgentXSecurityBlock) as exc_info:
        mock_typed_tool(sql_query="SELECT 1;")
    assert exc_info.value.receipt_id == "failclosed-no-engine"
    assert exc_info.value.policy_name is not None


def test_fail_closed_on_timeout(monkeypatch):
    """Timeout reason also triggers the fail-closed block (not just connection_error)."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_TIMEOUT)
    result = mock_tool(sql_query="SELECT 1;")
    assert "🚨 [AgentX Security Block]" in result
    assert _session_stats["consecutive_strikes"]["mock_tool"] == 1


def test_fail_closed_does_not_increment_degraded_count(monkeypatch):
    """degraded_executions only counts fail-open runs; fail-closed blocks must not touch it."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    mock_tool(sql_query="SELECT 1;")
    assert _session_stats["degraded_executions"] == 0


# =============================================================================
# Keyword-shield circuit breaker (a Layer-0 block loop the gateway never sees)
# =============================================================================

def _arm_keyword_shield(monkeypatch):
    """Turn the Layer-0 keyword shield ON with a single DROP-TABLE policy and a
    no-op incident sink, so a blocked tool exercises the shield path (the autouse
    fixture bypasses the shield by default)."""
    monkeypatch.setattr(dec_module, "LOCAL_POLICY_KEYWORDS", [{
        "id": "POL-LS-BRK", "name": "Mass Destructive Intent",
        "blocked_intents": ["drop table"],
        "socratic_prompt": "Local prompt.",
    }])
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)   # shield ON
    monkeypatch.setattr(dec_module._client, "register_incident", lambda **k: "rcpt-ls")


def test_keyword_shield_breaker_trips_at_ceiling(monkeypatch):
    """A keyword-shield block loop (never reaches the gateway) trips the breaker
    locally: blocks 1-3 accrue strikes, the 4th identical block halts. Regression
    for the token-drain gap found running examples/04 — a DROP TABLE apology loop
    short-circuits at the shield, so neither gateway Path B nor Path C ever saw it."""
    from agentx_sdk.decorators import start_secure_session
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "3")
    _arm_keyword_shield(monkeypatch)

    @agentx_protect(agent_id="ks_brk")
    def drop_tool(sql_query: str):
        return "ok"

    start_secure_session()
    for _ in range(3):
        result = drop_tool(sql_query="DROP TABLE users;")
        assert dec_module.is_block(result)
    assert _session_stats["consecutive_strikes"]["drop_tool"] == 3

    before = _session_stats["circuit_breakers_tripped"]
    with pytest.raises(AgentXCircuitBreakerTripped) as exc_info:
        drop_tool(sql_query="DROP TABLE users;")
    assert "Circuit Breaker" in str(exc_info.value)
    assert _session_stats["circuit_breakers_tripped"] == before + 1


def test_keyword_shield_single_block_does_not_trip(monkeypatch):
    """A single keyword-shield block must NOT trip the breaker — only a sustained loop."""
    _arm_keyword_shield(monkeypatch)

    @agentx_protect(agent_id="ks_one")
    def drop_tool2(sql_query: str):
        return "ok"

    result = drop_tool2(sql_query="DROP TABLE users;")   # must not raise
    assert dec_module.is_block(result)
    assert _session_stats["consecutive_strikes"]["drop_tool2"] == 1


def test_keyword_shield_strikes_reset_on_gateway_allow(monkeypatch):
    """A non-keyword call the gateway ALLOWS resets the keyword-shield strike count,
    so an agent that recovers to a safe action clears the loop counter (no false trip
    on the next block)."""
    from agentx_sdk.decorators import start_secure_session
    _arm_keyword_shield(monkeypatch)
    monkeypatch.setattr(dec_module._client, "evaluate_intent",
                        lambda **k: {"status": "ALLOWED"})

    @agentx_protect(agent_id="ks_reset")
    def maybe_tool(sql_query: str):
        return f"EXECUTED: {sql_query}"

    start_secure_session()
    maybe_tool(sql_query="DROP TABLE users;")            # shield block → strikes 1
    maybe_tool(sql_query="DROP TABLE users;")            # shield block → strikes 2
    assert _session_stats["consecutive_strikes"]["maybe_tool"] == 2
    maybe_tool(sql_query="SELECT count(*) FROM users;")  # safe → gateway ALLOW → reset
    assert _session_stats["consecutive_strikes"]["maybe_tool"] == 0


# =============================================================================
# Invalid fail-mode value
# =============================================================================

def test_invalid_fail_mode_defaults_to_open(monkeypatch):
    """Unrecognised value (e.g. 'close') falls back to open so a typo never silently disables safety."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "close")  # common typo
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    result = mock_tool(sql_query="SELECT 1;")
    assert result == "EXECUTED: SELECT 1;"
    assert _session_stats["degraded_executions"] == 1


# =============================================================================
# Cross-session strike isolation (the blind-eval "Circuit Breaker" false positive)
# =============================================================================

def test_strikes_reset_on_new_trace(monkeypatch):
    """A new agent session must NOT inherit the previous session's strike count.

    Regression for the blind-eval FP: one task's blocked execute_sql retries accrued
    strikes on the process-global, tool-name-keyed counter, and the NEXT task's first
    (benign) call on the same tool then tripped the breaker. Strikes are now scoped to
    the live trace — a different trace resets them to zero before the call is metered.
    """
    from agentx_sdk.decorators import start_secure_session
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "3")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)

    # Session A: three fail-closed blocks accrue strikes to the ceiling.
    start_secure_session()
    for i in range(3):
        mock_tool(sql_query=f"SELECT {i};")
    assert _session_stats["consecutive_strikes"]["mock_tool"] == 3

    # Session B: a brand-new trace. Before the fix, the leaked count (3 >= ceiling)
    # tripped the offline-fallback breaker on this first call. Now it starts clean:
    # no AgentXCircuitBreakerTripped, and the counter is 1 (this call), not 4.
    start_secure_session()
    result = mock_tool(sql_query="SELECT 1;")  # must NOT raise
    assert "🚨 [AgentX Security Block]" in result
    assert _session_stats["consecutive_strikes"]["mock_tool"] == 1


def test_same_trace_still_accrues_strikes(monkeypatch):
    """Isolation must not weaken the breaker WITHIN a session: repeated blocked calls on
    one trace still accumulate strikes (the per-trace reset only fires on a trace change)."""
    from agentx_sdk.decorators import start_secure_session
    monkeypatch.setenv("AGENTX_FAIL_MODE", "closed")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)

    start_secure_session()
    mock_tool(sql_query="SELECT 1;")
    mock_tool(sql_query="SELECT 2;")
    assert _session_stats["consecutive_strikes"]["mock_tool"] == 2


def test_reset_strike_state_clears_counters():
    """reset_strike_state() gives a harness a guaranteed clean slate between tasks."""
    from agentx_sdk.decorators import reset_strike_state, _strike_owner
    _session_stats["consecutive_strikes"]["some_tool"] = 5
    _strike_owner["some_tool"] = "trace-xyz"
    reset_strike_state()
    assert _session_stats["consecutive_strikes"] == {}
    assert _strike_owner == {}


def test_empty_fail_mode_defaults_to_open(monkeypatch):
    """Empty string for AGENTX_FAIL_MODE falls back to open."""
    monkeypatch.setenv("AGENTX_FAIL_MODE", "")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: UNREACHABLE_CONNECTION)
    result = mock_tool(sql_query="SELECT 1;")
    assert result == "EXECUTED: SELECT 1;"
