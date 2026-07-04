import pytest
from unittest.mock import patch, MagicMock
import requests as requests_lib

from agentx_sdk.client import AgentXClient


def make_response(status_code, json_body=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_body or {}
    return mock


@pytest.fixture
def client():
    return AgentXClient(gateway_url="http://test-gateway:8000")


@pytest.fixture(autouse=True)
def set_api_key(monkeypatch):
    monkeypatch.setenv("AGENTX_API_KEY", "agentx_sk_test_key")


# =============================================================================
# evaluate_intent — happy path
# =============================================================================

def test_evaluate_intent_returns_gateway_json(client):
    gateway_body = {"status": "ALLOWED", "pii_targets_to_scrub": []}
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, gateway_body)) as mock_post:
        result = client.evaluate_intent(agent_id="a", query="SELECT 1", chain_of_thought="safe")
    assert result == gateway_body


def test_evaluate_intent_posts_to_correct_url(client):
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, {})) as mock_post:
        client.evaluate_intent(agent_id="a", query="q", chain_of_thought="cot")
    mock_post.assert_called_once()
    url = mock_post.call_args[0][0]
    assert url == "http://test-gateway:8000/v1/evaluate"


def test_evaluate_intent_sends_auth_header(client):
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, {})) as mock_post:
        client.evaluate_intent(agent_id="a", query="q", chain_of_thought="cot")
    headers = mock_post.call_args[1]["headers"]
    assert headers["Authorization"] == "Bearer agentx_sk_test_key"


def test_evaluate_intent_payload_fields(client):
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, {})) as mock_post:
        client.evaluate_intent(
            agent_id="my_agent",
            query="SELECT 1",
            chain_of_thought="just a read",
            receipt_id="rec-001",
            trace_id="trace-001",
        )
    payload = mock_post.call_args[1]["json"]
    assert payload["agent_id"] == "my_agent"
    assert payload["query"] == "SELECT 1"
    assert payload["cot"] == "just a read"
    assert payload["receipt_id"] == "rec-001"
    assert payload["trace_id"] == "trace-001"


def test_evaluate_intent_does_not_forward_strike_count(client):
    """Issue #80: the gateway owns the strike count + the Path B decision per
    trace_id, so the SDK must NOT ride a strike_count field in the payload (a stale
    client-side count must never be able to influence the gateway's verdict)."""
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, {})) as mock_post:
        client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c")
    payload = mock_post.call_args[1]["json"]
    assert "strike_count" not in payload


def test_evaluate_intent_strike_count_is_deprecated_and_ignored(client):
    """A caller still passing strike_count gets a loud DeprecationWarning (not a
    silent no-op), and the value is still never placed in the payload (issue #80)."""
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, {})) as mock_post:
        with pytest.warns(DeprecationWarning, match="strike_count"):
            client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c", strike_count=5)
    assert "strike_count" not in mock_post.call_args[1]["json"]


# =============================================================================
# evaluate_intent — action/args contract
# =============================================================================

def test_evaluate_intent_attaches_declared_action_and_args(client):
    """When the caller declares an action + structured args, both ride the payload."""
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, {})) as mock_post:
        client.evaluate_intent(
            agent_id="a", query="https://169.254.169.254/", chain_of_thought="c",
            action="fetch_url", args={"url": "https://169.254.169.254/"},
        )
    payload = mock_post.call_args[1]["json"]
    assert payload["action"] == "fetch_url"
    assert payload["args"] == {"url": "https://169.254.169.254/"}
    # The flattened text fallback is still present so the floor is never starved.
    assert payload["query"] == "https://169.254.169.254/"


def test_evaluate_intent_omits_action_args_for_legacy_callers(client):
    """A caller that declares neither action nor args sends the unchanged legacy shape."""
    with patch("agentx_sdk.client.requests.post", return_value=make_response(200, {})) as mock_post:
        client.evaluate_intent(agent_id="a", query="SELECT 1", chain_of_thought="c")
    payload = mock_post.call_args[1]["json"]
    assert "action" not in payload
    assert "args" not in payload


# =============================================================================
# evaluate_intent — error paths
# =============================================================================

def test_evaluate_intent_missing_api_key_is_keyless_not_error(client, monkeypatch):
    # Keyless (no key) is a SUPPORTED mode, not a hard error: evaluate_intent signals
    # UNREACHABLE with reason 'no_api_key' so the decorator fails OPEN (the Layer-0
    # shield is the authority) and a clean call runs, instead of dead-ending on a
    # "System Error". Regression guard for the keyless clean-call break.
    monkeypatch.delenv("AGENTX_API_KEY")
    result = client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c")
    assert result["status"] == "REASONING_ENGINE_UNREACHABLE"
    assert result["reason"] == "no_api_key"


def test_evaluate_intent_401_returns_error(client):
    with patch("agentx_sdk.client.requests.post", return_value=make_response(401)):
        result = client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c")
    assert result["status"] == "ERROR"
    assert result["message"] == "Invalid AgentX API Key."


def test_evaluate_intent_non_401_error_returns_json(client):
    """Non-401 non-200 responses (e.g. 500) pass the body through unchanged."""
    body = {"detail": "Internal Server Error"}
    with patch("agentx_sdk.client.requests.post", return_value=make_response(500, body)):
        result = client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c")
    assert result == body


def test_evaluate_intent_connection_error(client):
    with patch("agentx_sdk.client.requests.post", side_effect=requests_lib.exceptions.ConnectionError):
        result = client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c")
    assert result["status"] == "REASONING_ENGINE_UNREACHABLE"
    assert result["reason"] == "connection_error"


def test_evaluate_intent_timeout(client):
    with patch("agentx_sdk.client.requests.post", side_effect=requests_lib.exceptions.Timeout):
        result = client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c")
    assert result["status"] == "REASONING_ENGINE_UNREACHABLE"
    assert result["reason"] == "timeout"


def test_evaluate_intent_unexpected_exception(client):
    with patch("agentx_sdk.client.requests.post", side_effect=ValueError("boom")):
        result = client.evaluate_intent(agent_id="a", query="q", chain_of_thought="c")
    assert result["status"] == "ERROR"
    assert "boom" in result["message"]


# =============================================================================
# register_incident — happy path
# =============================================================================

# register_incident is FIRE-AND-FORGET (issue #3): it returns the client-pinned
# receipt UUID immediately and dispatches the POST on a daemon thread. Tests that
# assert on the POST call drain_pending_parks() (inside the patch context, so the
# mock is still installed when the thread fires) before inspecting call_args.

def test_register_incident_returns_pinned_uuid_immediately(client):
    """A key is set → return the client-pinned UUID, which is also what gets POSTed."""
    with patch("agentx_sdk.client.requests.post",
               return_value=make_response(200, {})) as mock_post:
        result = client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=2.0)
    sent_receipt = mock_post.call_args[1]["json"]["receipt_id"]
    assert result == sent_receipt
    assert result is not None


def test_register_incident_does_not_block_on_slow_control_plane(client):
    """The headline guarantee (issue #3): a slow/down control plane must NOT delay
    the response path. register_incident returns long before a 10s POST would."""
    import time as _time
    import threading as _threading

    # The POST blocks until the test releases it — so we measure register_incident's
    # return latency, then let the background thread finish and drain it inside the
    # patch context (no stray daemon thread or real network call leaks past the test).
    release = _threading.Event()

    def slow_post(*args, **kwargs):
        release.wait(timeout=5)
        return make_response(200, {})

    with patch("agentx_sdk.client.requests.post", side_effect=slow_post):
        start = _time.monotonic()
        result = client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        elapsed = _time.monotonic() - start
        # Returned essentially instantly while the (mocked) POST is still blocked.
        assert elapsed < 1.0, f"register_incident blocked for {elapsed:.2f}s on a slow park"
        assert result is not None
        release.set()
        client.drain_pending_parks(timeout=2.0)


def test_register_incident_pins_uuid_in_payload(client):
    """The UUID is generated client-side and included in the POST body."""
    with patch("agentx_sdk.client.requests.post",
               return_value=make_response(200, {})) as mock_post:
        client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=2.0)
    payload = mock_post.call_args[1]["json"]
    assert "receipt_id" in payload
    import uuid
    uuid.UUID(payload["receipt_id"])  # raises ValueError if malformed


def test_register_incident_posts_to_correct_url(client):
    with patch("agentx_sdk.client.requests.post",
               return_value=make_response(200, {})) as mock_post:
        client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=2.0)
    url = mock_post.call_args[0][0]
    assert url == "http://test-gateway:8000/v1/incident"


def test_register_incident_drain_joins_background_post(client):
    """drain_pending_parks() blocks until the dispatched POST has actually run, so a
    short script's session-end hook lands the park instead of dropping it."""
    with patch("agentx_sdk.client.requests.post",
               return_value=make_response(200, {})) as mock_post:
        client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=2.0)
        assert mock_post.called


# =============================================================================
# register_incident — offline + error paths
# =============================================================================

def test_register_incident_missing_api_key_returns_none_and_posts_nothing(client, monkeypatch):
    """No key → offline: return None and dispatch no background POST at all."""
    monkeypatch.delenv("AGENTX_API_KEY")
    with patch("agentx_sdk.client.requests.post") as mock_post:
        result = client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=1.0)
    assert result is None
    mock_post.assert_not_called()


@pytest.mark.parametrize("failure", [
    make_response(401),
    make_response(500),
    requests_lib.exceptions.Timeout(),
    requests_lib.exceptions.ConnectionError(),
    RuntimeError("oops"),
])
def test_register_incident_swallows_background_failures(client, failure):
    """A park failure (rejection, timeout, unreachable, bug) is best-effort: it is
    swallowed on the background thread and never raises into the caller, which still
    gets its pinned UUID. The block already stood — only the later COMPLIED match is
    at stake."""
    if isinstance(failure, Exception):
        post_patch = patch("agentx_sdk.client.requests.post", side_effect=failure)
    else:
        post_patch = patch("agentx_sdk.client.requests.post", return_value=failure)
    with post_patch:
        result = client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=2.0)
    assert result is not None  # caller always gets the pinned receipt


def test_register_incident_warns_async_on_rejected_park(client, capsys):
    """A rejected park (non-200) is surfaced as an async warning off the block path —
    not silently swallowed — so a misconfigured key still produces a signal."""
    with patch("agentx_sdk.client.requests.post", return_value=make_response(500)):
        client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=2.0)  # join so the warning has printed
    out = capsys.readouterr().out
    assert "park rejected" in out.lower() and "500" in out


def test_register_incident_warns_async_on_failed_park(client, capsys):
    """A transport failure (unreachable / timeout) is surfaced as an async warning."""
    with patch("agentx_sdk.client.requests.post",
               side_effect=requests_lib.exceptions.ConnectionError):
        client.register_incident(
            agent_id="a", query="q", chain_of_thought="c",
            policy_id="P1", policy_name="Policy", challenge_issued="Why?",
        )
        client.drain_pending_parks(timeout=2.0)
    out = capsys.readouterr().out
    assert "park failed" in out.lower()
