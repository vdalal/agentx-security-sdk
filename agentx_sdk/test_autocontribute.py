"""Tests for Lock-1 session-end auto-contribution (AgentXClient.auto_contribute).

Gates: EXPLICIT opt-in (AGENTX_CONTRIBUTE true) + networked (linked/cloud) + a key.
Default-off is unchanged (a silent no-op). Daily-debounced. All network is mocked —
no real gateway/plane is touched.
"""
import time
from unittest.mock import MagicMock, patch

import pytest

from agentx_sdk import client as client_mod
from agentx_sdk import pulse


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(pulse, "_PULSE_FILE", tmp_path / "pulse.json")
    monkeypatch.setattr(pulse, "_env_overlay", {})   # don't let a real ./.env bleed in
    for k in ("AGENTX_CONTRIBUTE", "AGENTX_MODE", "CONTROL_PLANE_URL",
              "AGENTX_API_KEY", "AGENTX_ALLOW_PAYLOAD_SYNC", "AGENTX_TELEMETRY"):
        monkeypatch.delenv(k, raising=False)
    yield


def _client():
    return client_mod.AgentXClient(gateway_url="http://gw:8000")


def test_noop_when_not_opted_in(monkeypatch):
    # Networked + keyed, but contribution NOT opted in -> default-off, no network.
    monkeypatch.setenv("AGENTX_MODE", "cloud")
    monkeypatch.setenv("AGENTX_API_KEY", "k")
    with patch.object(client_mod, "requests") as rq:
        _client().auto_contribute()
        rq.get.assert_not_called()
        rq.post.assert_not_called()


def test_noop_when_local(monkeypatch):
    # Opted in + keyed, but `local` has no plane -> no network.
    monkeypatch.setenv("AGENTX_CONTRIBUTE", "true")
    monkeypatch.setenv("AGENTX_API_KEY", "k")
    monkeypatch.setenv("AGENTX_MODE", "local")
    with patch.object(client_mod, "requests") as rq:
        _client().auto_contribute()
        rq.get.assert_not_called()


def test_pushes_when_opted_in_and_networked(monkeypatch):
    monkeypatch.setenv("AGENTX_CONTRIBUTE", "true")
    monkeypatch.setenv("AGENTX_API_KEY", "k")
    monkeypatch.setenv("AGENTX_MODE", "cloud")
    with patch.object(client_mod, "requests") as rq:
        rq.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"contributions": [{"policy_id": "p", "failure_mode": "DESTRUCTIVE_ACTION"}]},
        )
        rq.post.return_value = MagicMock(status_code=202)
        _client().auto_contribute()
        rq.get.assert_called_once()
        rq.post.assert_called_once()
    state = pulse._load_state()
    assert state.get("contributed") is True            # funnel contribute leg stamped
    assert state.get("last_auto_contribute")           # debounce stamped


def test_daily_debounce_blocks_second_run(monkeypatch):
    monkeypatch.setenv("AGENTX_CONTRIBUTE", "true")
    monkeypatch.setenv("AGENTX_API_KEY", "k")
    monkeypatch.setenv("AGENTX_MODE", "cloud")
    pulse._save_state({"last_auto_contribute": time.time()})   # already ran today
    with patch.object(client_mod, "requests") as rq:
        _client().auto_contribute()
        rq.get.assert_not_called()


def test_noop_without_key(monkeypatch):
    monkeypatch.setenv("AGENTX_CONTRIBUTE", "true")
    monkeypatch.setenv("AGENTX_MODE", "cloud")
    with patch.object(client_mod, "requests") as rq:
        _client().auto_contribute()
        rq.get.assert_not_called()


def test_skips_when_gateway_not_reached(monkeypatch):
    """#5: no gateway reached this session -> skip the atexit round-trip entirely."""
    monkeypatch.setenv("AGENTX_CONTRIBUTE", "true")
    monkeypatch.setenv("AGENTX_API_KEY", "k")
    monkeypatch.setenv("AGENTX_MODE", "cloud")
    with patch.object(client_mod, "requests") as rq:
        _client().auto_contribute(gateway_reached=False)
        rq.get.assert_not_called()


def test_passes_since_and_advances_cursor(monkeypatch):
    """#1: incremental — the stored cursor rides as ?since= and advances on success,
    so the same incidents are never re-sent."""
    monkeypatch.setenv("AGENTX_CONTRIBUTE", "true")
    monkeypatch.setenv("AGENTX_API_KEY", "k")
    monkeypatch.setenv("AGENTX_MODE", "cloud")
    pulse._save_state({"last_contributed_cursor": "C1"})   # prior high-water mark
    with patch.object(client_mod, "requests") as rq:
        rq.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"contributions": [{"policy_id": "p", "failure_mode": "X"}], "cursor": "C2"},
        )
        rq.post.return_value = MagicMock(status_code=202)
        _client().auto_contribute()
        _, kwargs = rq.get.call_args
        assert kwargs.get("params") == {"since": "C1"}
    assert pulse._load_state().get("last_contributed_cursor") == "C2"
