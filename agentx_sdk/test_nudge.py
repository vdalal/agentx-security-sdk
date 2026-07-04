"""The self-serve end-of-block nudge: the rung-0 -> Recover CTA at the activation moment.

Shown only on a keyless block (a block but no gateway reached), never for an install
that has EVER reached a gateway (so a Recover user whose gateway was merely down isn't
nagged), at most ~weekly (no per-session nag), never in automation/CI. Static print,
sends and tracks nothing.
"""
import time

import pytest

from agentx_sdk import pulse


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(pulse, "_PULSE_FILE", tmp_path / "pulse.json")
    # Treat the test run as a real (non-automation) session so the emitter actually runs.
    monkeypatch.setattr(pulse, "is_automation_context", lambda: False)
    yield


KEYLESS_BLOCK = {"critical_blocks": 1, "gateway_reached": False}


# --- the pure decision ---------------------------------------------------
def test_shows_on_fresh_keyless_block():
    assert pulse._should_emit_nudge(KEYLESS_BLOCK, {}, time.time()) is True


def test_suppressed_when_install_ever_reached_gateway():
    # A Recover user whose gateway was merely DOWN this session: not nagged (#2).
    assert pulse._should_emit_nudge(KEYLESS_BLOCK, {"ever_gateway": True}, time.time()) is False


def test_suppressed_when_gateway_reached_this_session():
    assert pulse._should_emit_nudge({"critical_blocks": 1, "gateway_reached": True}, {}, time.time()) is False


def test_suppressed_without_a_block():
    assert pulse._should_emit_nudge({"critical_blocks": 0, "gateway_reached": False}, {}, time.time()) is False


def test_debounced_within_interval():
    now = time.time()
    assert pulse._should_emit_nudge(KEYLESS_BLOCK, {"last_nudge_ts": now - 60}, now) is False        # a minute ago
    assert pulse._should_emit_nudge(KEYLESS_BLOCK, {"last_nudge_ts": now - 8 * 86400}, now) is True   # 8 days ago


# --- the emitter (print + persistence) -----------------------------------
def test_emit_prints_and_debounces(capsys):
    pulse.maybe_emit_nudge(dict(KEYLESS_BLOCK))
    out = capsys.readouterr().out
    assert "request-access" in out and "Recover" in out
    assert pulse._load_state().get("last_nudge_ts")          # debounce persisted
    pulse.maybe_emit_nudge(dict(KEYLESS_BLOCK))               # same-day second run
    assert "request-access" not in capsys.readouterr().out   # not nagged again


def test_emit_records_ever_gateway_sticky(capsys):
    pulse.maybe_emit_nudge({"critical_blocks": 1, "gateway_reached": True})
    assert pulse._load_state().get("ever_gateway") is True
    assert "request-access" not in capsys.readouterr().out


def test_emit_noop_in_automation(monkeypatch, capsys):
    monkeypatch.setattr(pulse, "is_automation_context", lambda: True)
    pulse.maybe_emit_nudge(dict(KEYLESS_BLOCK))
    assert capsys.readouterr().out == ""
    assert pulse._load_state() == {}                          # no pulse.json write in CI/tests
