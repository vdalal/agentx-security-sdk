"""Tests for the developer-facing block-result contract (AgentXBlock / is_block).

A blocked tool call must come back as STRUCTURED data, not a prose blob the
developer has to parse:
  - untyped / `-> str` tool  -> returns an `AgentXBlock` (a str subclass + fields)
  - strictly-typed tool      -> raises `AgentXSecurityBlock` (same fields)
Detection is uniform via `is_block(...)`, and the legacy string behaviour is
preserved (the return is still a real `str`).
"""
import pytest

from agentx_sdk.decorators import agentx_protect, _client, _session_stats, _strike_owner
from agentx_sdk import is_block, AgentXBlock, AgentXSecurityBlock, AgentXCircuitBreakerTripped

# A gateway "policy violation" response (the main block path, Site 2 in the decorator).
VIOLATION = {
    "error": "AgentX Policy Violation",
    "policy_id": "POL-TEST-1",
    "policy_triggered": "Mass Destructive Intent",
    "challenge": "Use a scoped DELETE with a WHERE clause instead of dropping the table.",
    "receipt_id": "rcpt-test-123",
    "safe_path": "DELETE FROM users WHERE id = ?",
}
# A gateway circuit-breaker (loop-abort) response — a loop halt, NOT a policy block.
LOOP_ABORTED = {
    "error": "AgentX Cognitive Loop Aborted",
    "receipt_id": "rcpt-cb-1",
    "challenge": "Maximum consecutive policy retry attempts reached.",
}
ALLOWED = {"status": "ALLOWED"}


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    """Clean per-trace accounting and bypass the local keyword shield so the
    mocked gateway response is what drives each test."""
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    _session_stats["human_resolved_traces"].clear()
    for _k in ("open_challenges", "looped_traces"):
        _session_stats[_k].clear()
    _session_stats["challenge_episodes"] = 0
    _session_stats["self_corrections"] = 0
    _session_stats["consecutive_strikes"].clear()
    _session_stats["gateway_reached"] = False  # coarse pulse stage signal — reset so a reached-gateway test can't leak into the next
    _session_stats["reasoning_enabled"] = None  # companion pulse stage signal — reset alongside gateway_reached (SDK session-globals isolation)
    _session_stats["block_category"] = None  # companion pulse signal — reset with the other pulse-stage globals
    _strike_owner.clear()  # companion to consecutive_strikes — must reset together or the per-trace breaker reset leaks across tests
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    yield


@agentx_protect(agent_id="block_test_agent")
def untyped_tool(sql_query: str):
    return f"EXECUTED: {sql_query}"


@agentx_protect(agent_id="block_test_typed")
def typed_tool(sql_query: str) -> dict:
    return {"ok": True}


def test_untyped_block_returns_structured_agentx_block(monkeypatch):
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    result = untyped_tool(sql_query="DROP TABLE users;")

    assert is_block(result)
    assert isinstance(result, AgentXBlock)
    assert result.blocked is True
    assert result.policy == "Mass Destructive Intent"
    assert result.challenge.startswith("Use a scoped DELETE")
    assert result.receipt_id == "rcpt-test-123"
    assert result.safe_path == "DELETE FROM users WHERE id = ?"


def test_block_is_backward_compatible_string(monkeypatch):
    """Legacy integrations that treat the block as a string must keep working."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    result = untyped_tool(sql_query="DROP TABLE users;")

    assert isinstance(result, str)
    assert "🚨 [AgentX Security Block]" in result        # legacy substring check
    assert "rcpt-test-123" in result                      # receipt still in the prose


def test_typed_tool_raises_structured_security_block(monkeypatch):
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    with pytest.raises(AgentXSecurityBlock) as exc_info:
        typed_tool(sql_query="DROP TABLE users;")

    block = exc_info.value
    assert is_block(block)
    assert block.policy == "Mass Destructive Intent"
    assert block.policy_name == "Mass Destructive Intent"   # backward-compat alias
    assert block.challenge.startswith("Use a scoped DELETE")
    assert block.receipt_id == "rcpt-test-123"
    assert block.safe_path == "DELETE FROM users WHERE id = ?"


def test_allowed_call_is_not_a_block(monkeypatch):
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: ALLOWED)
    result = untyped_tool(sql_query="SELECT 1;")

    assert not is_block(result)
    assert result == "EXECUTED: SELECT 1;"


def test_is_block_false_on_plain_values():
    """`is_block` must not false-positive on ordinary tool return values."""
    assert not is_block("just a normal string")
    assert not is_block({"status": "ok"})
    assert not is_block(None)
    assert not is_block(42)


def test_circuit_breaker_is_not_a_policy_block(monkeypatch):
    """A loop-halt raises AgentXCircuitBreakerTripped and is deliberately NOT a
    policy block: is_block() returns False for it (2b contract). Callers catch the
    breaker separately to abort, distinct from reading .policy/.challenge."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: LOOP_ABORTED)
    with pytest.raises(AgentXCircuitBreakerTripped) as exc_info:
        untyped_tool(sql_query="DROP TABLE users;")
    assert not is_block(exc_info.value)
