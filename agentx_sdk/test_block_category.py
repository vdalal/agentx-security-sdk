"""block_category pulse field: the coarse, closed-vocab failure class of a block.

It answers "what KIND of action got blocked" (DESTRUCTIVE_ACTION / NETWORK_TRAVERSAL
/ SECRETS_LEAK / PII_EXFILTRATION) for the keyless majority, never the tool name or
payload. SDK-derived from the matched Layer-0 policy, so it works with no gateway and
no key. Off-vocab is dropped (fail-safe).
"""
import pytest

from agentx_sdk import pulse
from agentx_sdk import decorators as dec
from agentx_sdk import agentx_protect, is_block


@pytest.fixture(autouse=True)
def reset_block_category(monkeypatch):
    # Reset the globals this module mutates so it can't leak into other suites
    # (the SDK session-globals isolation discipline).
    for k in ("total_calls", "intercepts", "critical_blocks"):
        dec._session_stats[k] = 0
    dec._session_stats["block_category"] = None
    dec._session_stats["challenged_traces"].clear()
    dec._session_stats["consecutive_strikes"].clear()
    dec._strike_owner.clear()
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)          # Layer-0 shield ACTIVE
    monkeypatch.setenv("AGENTX_GATEWAY_URL", "http://localhost:59999")        # dead-port: no real network
    # Pin to the fresh-install built-ins (what a pip-only keyless user runs), so the
    # test isn't at the mercy of a stray dev .agentx/policies.json.
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", list(dec._BUILTIN_POLICY_KEYWORDS))
    yield
    dec._session_stats["block_category"] = None


def test_builtin_policies_carry_valid_categories():
    # Every built-in keyless policy maps to a category in the closed vocab.
    for p in dec._BUILTIN_POLICY_KEYWORDS:
        assert p["category"] in dec._BLOCK_CATEGORY_VOCAB, p["name"]


def test_note_block_category_drops_off_vocab():
    dec._note_block_category("NOT_A_CATEGORY")
    assert dec._session_stats["block_category"] is None       # off-vocab dropped
    dec._note_block_category("DESTRUCTIVE_ACTION")
    assert dec._session_stats["block_category"] == "DESTRUCTIVE_ACTION"


def test_payload_reflects_block_category():
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    payload = pulse.build_payload({"block_category": "NETWORK_TRAVERSAL"}, state)
    assert payload["block_category"] == "NETWORK_TRAVERSAL"


def test_payload_block_category_none_when_absent():
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    assert pulse.build_payload({}, state)["block_category"] is None


def test_keyless_shield_block_sets_destructive_category():
    # End-to-end: a keyless DROP TABLE block (Layer-0 shield) tags the session.
    @agentx_protect(agent_id="test_artifact_block_category")
    def run_sql(query):
        return "EXECUTED"

    result = run_sql(query="Please clean up: DROP TABLE users;")
    assert is_block(result)
    assert dec._session_stats["block_category"] == "DESTRUCTIVE_ACTION"
