import os
import sys
import pytest
import json
import requests
from dotenv import load_dotenv

# Ensure parent directory tools map onto our search track path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agentx_sdk.decorators import agentx_protect, _session_stats, _strike_owner, LOCAL_SHIELD_WEIGHTS, LOCAL_SHIELD_MANIFEST
from agentx_sdk.decorators import AgentXCircuitBreakerTripped, AgentXSecurityBlock

# Load API key from .env file
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

# Define a clean, tracked dummy tool target wrapped with our local vector guardrail
@agentx_protect(agent_id="test_sdk_agent")
def mock_secure_database_executor(sql_query: str):
    """A baseline database tool simulator that should be blocked locally on dangerous inputs."""
    return f"SUCCESS_EXECUTION: {sql_query}"


@agentx_protect(agent_id="test_sdk_agent")
def delete_user_files(path: str, recursive: bool = False):
    """A destructive-filesystem tool: its NAME carries the verb the gateway needs
    to anchor its structured bulk-delete detector (the flattened args lose it)."""
    return f"DELETED: {path}"


@pytest.fixture(autouse=True)
def reset_session_state():
    """Reset all decorator state before each test so no test depends on a prior test having run."""
    _session_stats["intercepts"] = 0
    _session_stats["critical_blocks"] = 0
    _session_stats["circuit_breakers_tripped"] = 0
    _session_stats["self_corrections"] = 0
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    _session_stats["human_resolved_traces"].clear()
    for _k in ("open_challenges", "looped_traces"):
        _session_stats[_k].clear()
    _session_stats["challenge_episodes"] = 0
    _session_stats["self_corrections"] = 0
    _session_stats["degraded_executions"] = 0
    _session_stats["consecutive_strikes"].clear()
    _session_stats["gateway_reached"] = False  # coarse pulse stage signal — reset so a reached-gateway test can't leak into the next
    _session_stats["reasoning_enabled"] = None  # companion pulse stage signal — reset alongside gateway_reached (SDK session-globals isolation)
    _session_stats["block_category"] = None  # companion pulse signal — reset with the other pulse-stage globals
    _strike_owner.clear()  # companion to consecutive_strikes — must reset together or the per-trace breaker reset leaks across tests
    import agentx_sdk.decorators as _dec
    _dec._protection_recorded = False  # once-per-process streak guard — reset so it can't leak across tests (session-globals isolation)
    _dec._atexit_summary_quiet = False  # P3 demo-quiet flag — reset so a demo test can't suppress another test's summary
    yield


def test_atexit_summary_quiet_suppresses_the_box(capsys):
    """P3: quiet mode makes the atexit summary skip its duplicate visual box (so `agentx
    demo` owns a single closing screen), while normal mode still prints it. The streak +
    pulse side effects are automation-gated to no-ops under pytest, so this only asserts
    the visual box."""
    import agentx_sdk.decorators as _dec
    _dec._session_stats["intercepts"] = 1        # activity, so it doesn't early-return
    _dec.set_atexit_summary_quiet(True)
    _dec._print_agentx_summary()
    assert "AgentX Session Summary" not in capsys.readouterr().out

    _dec.set_atexit_summary_quiet(False)
    _dec._protection_recorded = False
    _dec._session_stats["intercepts"] = 1
    _dec._print_agentx_summary()
    assert "AgentX Session Summary" in capsys.readouterr().out


# =====================================================================
# 🧪 SUITE 1: OUT-OF-PROMPT VECTOR SHIELD CACHE VALIDATIONS
# =====================================================================

def test_vector_shield_cache_presence():
    """Verifies that our compile artifacts have loaded natively into memory space arrays."""
    # If agentx compile was run prior, these modules should be fully hydrated in RAM
    if LOCAL_SHIELD_WEIGHTS is not None:
        assert LOCAL_SHIELD_WEIGHTS.shape[1] == 384
        assert isinstance(LOCAL_SHIELD_MANIFEST, dict)

def test_vector_shield_local_intercept_catch(monkeypatch):
    """
    Proves that a blatant destructive write query matches our sub-millisecond local
    regex/vector shield override and intercepts the loop on Turn 1 without hitting the gateway.
    """
    # Reset internal memory metrics to trace delta values clearly
    from agentx_sdk.decorators import _session_stats, _client
    _session_stats["intercepts"] = 0
    _session_stats["critical_blocks"] = 0
    _session_stats["consecutive_strikes"]["mock_secure_database_executor"] = 0

    # 1. DYNAMIC MOCKING: Check if Gateway is alive
    gateway_alive = False
    try:
        res = requests.get("http://localhost:8000/v1/telemetry", timeout=1.0)
        gateway_alive = res.status_code == 200
    except requests.exceptions.RequestException:
        pass

    if not gateway_alive:
        # Fallback: Apply monkeypatch if Docker is down
        monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: {
            "error": "AgentX Policy Violation",
            "policy_id": "POL-MOCK-001",
            "policy_triggered": "Mass Destructive Intent",
            "challenge": "Mocked Socratic Challenge",
            "receipt_id": "mock-receipt-id"
        })
        monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    dangerous_input_query = "DROP TABLE users;"

    # Execute the wrapped tool function pass
    result_observation = mock_secure_database_executor(sql_query=dangerous_input_query)

    # Assert that the returned string uses our exact, structured data block signature
    assert "🚨 [AgentX Security Block]" in result_observation
    assert "receipt_id:" in result_observation

def test_vector_shield_safe_path_fallback():
    """
    Ensures that an ambiguous or entirely safe tool query passes through the local shield 
    completely unhindered, dropping out into the live Layer 2 network gateway endpoint.
    """
    _session_stats["consecutive_strikes"]["mock_secure_database_executor"] = 0
    safe_input_query = "SELECT username FROM accounts WHERE id = 42;"
    
    # We expect this safe query to slip past the local shield and attempt a network fetch call.
    # If the gateway container is active on port 8000, it will return a success state payload.
    try:
        result_observation = mock_secure_database_executor(sql_query=safe_input_query)
        # If it hits the active container successfully, it should execute or trace network responses
        assert "🚨" not in str(result_observation)
    except Exception as network_exception:
        # If the container wasn't active during this isolated SDK run, a network exception confirms
        # that the execution flow successfully passed the local shield and tried to reach the wire!
        assert "Connection" in str(network_exception) or "requests" in str(network_exception)
        
# =====================================================================
# 🧪 SUITE 2: MULTI-TURN COGNITIVE STATE LOOP TRAP VALIDATIONS
# =====================================================================

def test_sdk_3_online_block_does_not_accrue_local_strikes(monkeypatch):
    """
    Target: Strike counting is GATEWAY-owned online (issue #80).
    Verified: When a REACHABLE gateway returns a policy violation, the SDK must NOT
    increment its local strike counter — the gateway already counted this strike in
    its own per-trace _STRIKE_TRACKER and owns the Path B decision. The local counter
    is now the OFFLINE-ONLY fallback signal and must stay at zero on online blocks, so
    a stale client count can never double-count or pre-trip the breaker.
    """
    tool_name = "mock_secure_database_executor"

    # 1. Reset metrics baseline to zero
    from agentx_sdk.decorators import _session_stats, _client
    _session_stats["consecutive_strikes"][tool_name] = 0

    # 2. MOCK THE NETWORK: a reachable gateway returning a policy violation.
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: {
        "error": "AgentX Policy Violation",
        "policy_id": "POL-MOCK-001",
        "policy_triggered": "Mass Destructive Intent",
        "challenge": "Mocked Socratic Challenge",
        "receipt_id": "mock-receipt-id"
    })

    # 3. Force it to skip the local shield so it hits our mock deterministically
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    # Two online blocks in a row: the local (offline-only) counter stays at zero —
    # the gateway owns the online count now.
    mock_secure_database_executor(sql_query="DROP TABLE public.system_users;")
    assert _session_stats["consecutive_strikes"][tool_name] == 0

    mock_secure_database_executor(sql_query="DROP TABLE accounts;")
    assert _session_stats["consecutive_strikes"][tool_name] == 0

def test_sdk_4_circuit_breaker_gateway_owns_decision(monkeypatch):
    """
    Target: Gateway-Owned Cognitive Loop Lockout (the strike-breaker DECISION is gateway-side).
    Verified: On a REACHABLE call the SDK no longer decides locally — it meters + forwards
    strike_count, and when the gateway returns its "AgentX Cognitive Loop Aborted" verdict
    (Path B), the SDK enforces it by raising the dedicated circuit-breaker exception.
    """
    from agentx_sdk.decorators import _session_stats, _client

    # The gateway (the authority) returns its Path B breaker verdict.
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: {
        "error": "AgentX Cognitive Loop Aborted",
        "challenge": "Maximum consecutive policy retry attempts reached.",
        "receipt_id": "gateway-breaker-receipt"
    })
    # Bypass the local shield so the call deterministically reaches the mocked gateway.
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    with pytest.raises(AgentXCircuitBreakerTripped) as exc_info:
        mock_secure_database_executor(sql_query="SELECT 1;")

    assert _session_stats["circuit_breakers_tripped"] > 0
    assert "Circuit Breaker Triggered" in str(exc_info.value)


def test_sdk_4b_circuit_breaker_offline_fallback(monkeypatch):
    """
    Target: SDK Offline-Only Fallback (gateway unreachable).
    Verified: When the gateway — the decision authority — is unreachable AND local strikes have
    already hit the ceiling, the SDK still trips the breaker locally to halt a runaway loop.
    This is the ONLY path on which the SDK decides for itself.
    """
    from agentx_sdk.decorators import _session_stats, _client
    tool_name = "mock_secure_database_executor"

    # Gateway unreachable + strikes already at the ceiling (3).
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: {
        "status": "REASONING_ENGINE_UNREACHABLE", "reason": "connection_error"
    })
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "3")
    _session_stats["consecutive_strikes"][tool_name] = 3

    with pytest.raises(AgentXCircuitBreakerTripped) as exc_info:
        mock_secure_database_executor(sql_query="SELECT 1;")

    assert _session_stats["circuit_breakers_tripped"] > 0
    assert "OFFLINE FALLBACK" in str(exc_info.value)
    assert "Halting to prevent token drain" in str(exc_info.value)

# =====================================================================
# 🧪 SUITE 3: ENTERPRISE FRAMEWORK SAFETY VALIDATIONS
# =====================================================================

# Define a strictly-typed tool simulating an enterprise Pydantic environment
@agentx_protect(agent_id="strict_type_agent")
def mock_strictly_typed_executor(sql_query: str) -> dict:
    """A tool with strict return typing that will crash if the SDK returns a raw string."""
    return {"status": "SUCCESS", "data": sql_query}

def test_sdk_5_strict_type_exception_routing(monkeypatch):
    """
    Target: Dynamic Return Type Reflection
    Verified: Proves that when an agentic tool is wrapped with strict return typing,
    the SDK detects the signature constraint and pivots to throwing an Exception.
    """
    tool_name = "mock_strictly_typed_executor"

    # Reset metrics baseline
    from agentx_sdk.decorators import _session_stats, _client
    _session_stats["consecutive_strikes"][tool_name] = 0

    # 1. DYNAMIC MOCKING: Check if Gateway is alive
    gateway_alive = False
    try:
        res = requests.get("http://localhost:8000/v1/telemetry", timeout=1.0)
        gateway_alive = res.status_code == 200
    except requests.exceptions.RequestException:
        pass

    if not gateway_alive:
        # Fallback: Apply monkeypatch if Docker is down
        monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: {
            "error": "AgentX Policy Violation",
            "policy_id": "POL-MOCK-001",
            "policy_triggered": "Mass Destructive Intent",
            "challenge": "Mocked Socratic Challenge",
            "receipt_id": "mock-receipt-id"
        })
        monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    dangerous_input_query = "DROP TABLE production_users;"

    # Assert that the decorator dynamically detects the `-> dict` signature
    # and correctly throws the localized framework exception.
    with pytest.raises(AgentXSecurityBlock) as exc_info:
        mock_strictly_typed_executor(sql_query=dangerous_input_query)

    # Verify the exception object carries the required Socratic context payload
    assert exc_info.value.policy_name is not None
    assert exc_info.value.socratic_nudge is not None
    assert exc_info.value.receipt_id is not None

# =====================================================================
# 🧪 SUITE 4: BYPASS LOCAL SHIELD FEATURE
# =====================================================================

def test_bypass_shield_routes_to_gateway(monkeypatch):
    """With AGENTX_BYPASS_LOCAL_SHIELD=true, a query that the local keyword shield
    would normally catch (DROP TABLE) is forwarded to the gateway instead."""
    from agentx_sdk.decorators import _client
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **kwargs: {"status": "ALLOWED", "pii_targets_to_scrub": []})

    result = mock_secure_database_executor(sql_query="DROP TABLE users;")
    assert "🚨" not in str(result)
    assert "SUCCESS_EXECUTION" in result


def test_bypass_shield_disabled_catches_locally(monkeypatch):
    """With AGENTX_BYPASS_LOCAL_SHIELD=false (default), DROP TABLE is caught by
    the local keyword shield and evaluate_intent is never called."""
    from agentx_sdk.decorators import _client
    from unittest.mock import MagicMock
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)

    mock_eval = MagicMock()
    monkeypatch.setattr(_client, "evaluate_intent", mock_eval)

    result = mock_secure_database_executor(sql_query="DROP TABLE users;")
    assert "🚨 [AgentX Security Block]" in result
    mock_eval.assert_not_called()


def _capture_action(monkeypatch):
    """Forward through the gateway and record the action the SDK inferred."""
    from agentx_sdk.decorators import _client
    captured = {}
    def recorder(**kwargs):
        captured.update(kwargs)
        return {"status": "ALLOWED", "pii_targets_to_scrub": []}
    monkeypatch.setattr(_client, "evaluate_intent", recorder)
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    _session_stats["consecutive_strikes"]["mock_secure_database_executor"] = 0
    return captured


def test_edge_inference_does_not_mistype_sql_with_url_as_fetch(monkeypatch):
    """A SQL payload that merely CONTAINS a URL must NOT be inferred as fetch_url —
    otherwise the gateway skips every execute_database_query policy for it. We
    leave the action unset (None) so the gateway's 'sql present -> db' fallback wins."""
    captured = _capture_action(monkeypatch)
    mock_secure_database_executor(
        sql_query="INSERT INTO links (url) VALUES ('https://evil.example.com/x')"
    )
    assert captured.get("action") != "fetch_url"


def test_edge_inference_types_a_real_url_target_as_fetch(monkeypatch):
    """A payload that IS a network target (scheme-led, or a bare metadata IP) is
    confidently inferred as fetch_url."""
    captured = _capture_action(monkeypatch)
    mock_secure_database_executor(sql_query="https://169.254.169.254/latest/meta-data/")
    assert captured.get("action") == "fetch_url"


# =====================================================================
# 🧪 SUITE 4b: LAYER-0 BENIGN CATALOG-READ EXEMPTION
# =====================================================================
# The gateway exempts read-only catalog introspection from Schema Boundary via
# _is_benign_catalog_read; Layer 0 (the in-process keyword shield) must mirror it,
# or a pulled policy carrying `information_schema` blocks benign schema discovery
# BEFORE the request reaches the gateway (the blind-eval Schema Boundary FP). The
# tests arm the keyword explicitly so they prove the GUARD, not the absence of data.

def test_layer0_unit_benign_catalog_read_vs_mutation():
    """Unit-level contract for the mirrored guard: read-only catalog introspection
    is benign; any mutating/DDL verb on the catalog is not."""
    from agentx_sdk.decorators import _is_benign_catalog_read
    assert _is_benign_catalog_read(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'"
    )
    assert _is_benign_catalog_read("PRAGMA table_info(users)")
    assert not _is_benign_catalog_read("DROP TABLE information_schema.tables")  # mutating
    assert not _is_benign_catalog_read("ALTER DATABASE prod SET search_path TO public")
    assert not _is_benign_catalog_read("SELECT * FROM users")  # not a catalog surface
    assert not _is_benign_catalog_read("")


def test_layer0_exempts_benign_catalog_read_even_when_intent_armed(monkeypatch):
    """Schema Boundary armed with `information_schema` (exactly what a pre-migration
    `agentx pull` syncs into .agentx/policies.json) must NOT block a read-only
    `SELECT ... FROM information_schema...`. Without the guard this is intercepted
    in-process and never reaches the gateway — the layer-coverage gap."""
    import agentx_sdk.decorators as dec
    from agentx_sdk.decorators import _client

    armed = [{
        "id": "11111111-1111-1111-1111-111111111105",
        "name": "Schema Boundary",
        "blocked_intents": ["drop schema", "alter database", "information_schema"],
        "socratic_prompt": "Policy Violation: Database Isolation.",
    }]
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", armed)
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)
    # The benign read should reach the gateway, which would ALLOW it.
    monkeypatch.setattr(_client, "evaluate_intent",
                        lambda **kwargs: {"status": "ALLOWED", "pii_targets_to_scrub": []})

    benign = "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'"
    result = mock_secure_database_executor(sql_query=benign)
    assert "🚨" not in str(result), f"benign catalog read was blocked by Layer 0: {result}"


def test_layer0_still_blocks_destructive_catalog_op_when_intent_armed(monkeypatch):
    """The exemption is read-only: a DROP that targets the catalog still carries a
    mutating verb, so the guard does NOT exempt it and Layer 0 blocks it locally."""
    import agentx_sdk.decorators as dec

    armed = [{
        "id": "11111111-1111-1111-1111-111111111105",
        "name": "Schema Boundary",
        "blocked_intents": ["drop schema", "alter database", "information_schema"],
        "socratic_prompt": "Policy Violation: Database Isolation.",
    }]
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", armed)
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)

    destructive = "DROP TABLE information_schema.tables"
    result = mock_secure_database_executor(sql_query=destructive)
    assert "🚨 [AgentX Security Block]" in str(result)


def test_offline_keyword_shield_coaching_is_decrufted_and_names_safe_path(monkeypatch):
    """The offline keyword-shield block coaching mirrors the keyless MCP path (A1a): no
    judge-era 'symbolic reasoning' / SAFE_WRITE taxonomy (this path has no judge), and it
    surfaces the policy's concrete safe path, so the two keyless surfaces stay consistent."""
    import agentx_sdk.decorators as dec

    armed = [{
        "id": "11111111-1111-1111-1111-111111111105",
        "name": "Schema Boundary",
        "blocked_intents": ["drop schema", "alter database"],
        "socratic_prompt": "This drops or alters catalog schema, which is restricted.",
        "preferred_alternative": "Target only your own tables, or use a read-only catalog query.",
    }]
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", armed)
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)

    result = str(mock_secure_database_executor(sql_query="DROP SCHEMA public"))
    assert "🚨 [AgentX Security Block]" in result
    assert "symbolic reasoning" not in result.lower()     # judge-era cruft removed
    assert "SAFE_WRITE" not in result                      # internal taxonomy removed
    assert "Safe alternative:" in result                   # surfaces preferred_alternative
    assert "read-only catalog query" in result             # the concrete safe path


def test_is_fs_destructive_func_tokenizes_name():
    """Verb is matched as a discrete token (snake_case + camelCase), never as a
    substring — so `undelete_safely` / `formatter` do not false-positive."""
    from agentx_sdk.decorators import _is_fs_destructive_func
    assert _is_fs_destructive_func("delete_user_files")
    assert _is_fs_destructive_func("removeDirectory")
    assert _is_fs_destructive_func("rmtree")
    assert _is_fs_destructive_func("purge_workspace")
    assert not _is_fs_destructive_func("read_file")
    assert not _is_fs_destructive_func("list_directory")
    assert not _is_fs_destructive_func("formatter")          # 'format' substring, not a verb token
    assert not _is_fs_destructive_func("update_records")


def test_edge_inference_declares_fs_action_for_destructive_tool(monkeypatch):
    """A destructive-fs tool declares a filesystem action the gateway recognizes,
    plus the structured args — so the gateway's bulk-delete detector sees the
    verb the flattened arg values dropped."""
    from agentx_sdk.decorators import _client
    captured = {}
    def recorder(**kwargs):
        captured.update(kwargs)
        return {"status": "ALLOWED", "pii_targets_to_scrub": []}
    monkeypatch.setattr(_client, "evaluate_intent", recorder)
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    _session_stats["consecutive_strikes"]["delete_user_files"] = 0
    delete_user_files(path="/", recursive=True)
    assert captured.get("action") == "filesystem_delete"
    assert captured.get("args", {}).get("path") == "/"
    assert captured.get("args", {}).get("recursive") is True


def test_summary_records_protection_once_per_process(monkeypatch):
    """_print_agentx_summary is atexit-registered AND a documented manual call
    (examples/02), so it must record the protection streak at most once per process,
    or a manual+atexit run double-counts protected_sessions (and can fabricate a
    streak extension across midnight)."""
    import agentx_sdk.decorators as dec
    from agentx_sdk import pulse
    n = {"c": 0}
    monkeypatch.setattr(pulse, "record_protection", lambda *a, **k: (n.__setitem__("c", n["c"] + 1), None)[1])
    dec._protection_recorded = False
    dec._print_agentx_summary()
    dec._print_agentx_summary()
    assert n["c"] == 1     # recorded once despite two summary prints


# =====================================================================
# 🧪 KEYLESS end-to-end: clean calls RUN, and recovery is credited/narrated
# =====================================================================

def test_keyless_clean_call_fails_open_and_executes(monkeypatch):
    """A clean call with NO api key must FAIL OPEN and actually run (the in-process
    Layer-0 shield is the authority) — not dead-end on 'AGENTX_API_KEY is missing'.
    Regression guard for the keyless clean-call break that broke real integration."""
    from agentx_sdk import is_block
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    ran = {}

    @agentx_protect(agent_id="keyless_clean")
    def fetch_profile(user: str):
        ran["did"] = True
        return f"profile:{user}"

    out = fetch_profile(user="a normal safe value")
    assert ran.get("did") is True                      # the tool body actually executed
    assert out == "profile:a normal safe value"        # real return value, not an error
    assert not is_block(out)
    assert "System Error" not in str(out) and "API_KEY" not in str(out)


def test_keyless_block_then_safe_credits_self_correction(monkeypatch):
    """The keyless aha: a Layer-0 block, then the agent's safe revision on the SAME
    session, credits a self-correction (bounded recovered ⊆ challenged) so keyless
    recovery is finally visible in the summary and countable on the pulse."""
    from agentx_sdk import is_block, start_secure_session
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    start_secure_session()                              # one trace across both calls

    @agentx_protect(agent_id="keyless_recover")
    def run_sql(query: str):
        return {"ok": True}

    blocked = run_sql(query="please DROP TABLE users;")
    assert is_block(blocked)
    assert _session_stats["self_corrections"] == 0      # a block alone is not a recovery

    safe = run_sql(query="UPDATE notes SET status='seen' WHERE id=1")
    assert not is_block(safe)                            # the safe revision ran
    assert _session_stats["self_corrections"] == 1      # keyless recovery credited
    assert len(_session_stats["recovered_traces"]) == 1


def test_keyless_recovery_not_preempted_by_offline_breaker(monkeypatch):
    """A keyless clean call is progress, not a repeated blocked action, so it must NOT
    trip the offline runaway-breaker even when prior same-tool BLOCKS hit the ceiling.
    The recovery is credited and the call runs, instead of the run being halted."""
    from agentx_sdk import is_block, start_secure_session
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "1")   # ceiling=1 → trivially reached
    start_secure_session()

    @agentx_protect(agent_id="keyless_breaker")
    def run_sql(query: str):
        return {"ok": True}

    assert is_block(run_sql(query="DROP TABLE users;"))  # one block reaches the ceiling
    safe = run_sql(query="SELECT 1")                     # the revision must RUN, not trip
    assert not is_block(safe)
    assert _session_stats["self_corrections"] == 1       # credited, run not halted


def test_receipt_id_control_kwarg_is_stripped_from_tool_call(monkeypatch):
    """receipt_id is a decorator CONTROL kwarg (the README retry pattern
    `your_tool(revised, receipt_id=out.receipt_id)` passes it), NOT a tool argument.
    It must be stripped so it never reaches func — otherwise a typed tool without
    **kwargs TypeErrors on the documented retry, a keyless activation snag."""
    from agentx_sdk import is_block
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    seen = {}

    @agentx_protect(agent_id="receipt_typed")
    def fetch(user: str):                 # typed tool, NO **kwargs
        seen["user"] = user
        return f"ok:{user}"

    out = fetch(user="alice", receipt_id="rec-123")   # the README retry shape
    assert out == "ok:alice"              # ran cleanly; receipt_id did not leak into func
    assert seen["user"] == "alice"
    assert not is_block(out)