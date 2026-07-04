"""
Tests for the anonymous usage pulse (pulse.py).

The load-bearing guarantees here are PRIVACY guarantees: a frozen whitelist of
fields, an explicit one-line opt-out that always wins, a transparency notice shown
before the first send, and fire-and-forget resilience. If any of these regress,
the SDK starts leaking — so these assert the negative space (what must NOT be sent)
as hard as the positive. Telemetry is ON by default (notify + opt-out): a clean
slate sends, AGENTX_TELEMETRY=off and a prior declined prompt silence it.
"""
import json
import os
from unittest.mock import patch

import pytest

from agentx_sdk import pulse


@pytest.fixture(autouse=True)
def isolated_pulse_state(tmp_path, monkeypatch):
    """Redirect the on-disk identity/debounce file into a tmp dir and clear the
    telemetry env var, so each test starts from a clean, network-free slate. A clean
    slate is default-ON (notify + opt-out); tests that need OFF set the env or a
    stored prior-no explicitly."""
    monkeypatch.setattr(pulse, "_PULSE_FILE", tmp_path / "pulse.json")
    monkeypatch.delenv("AGENTX_TELEMETRY", raising=False)
    monkeypatch.delenv("CONTROL_PLANE_URL", raising=False)
    # Pin the funnel-stage inputs off so _mode() resolves to a deterministic
    # "local" unless a test sets them explicitly (a stray shell AGENTX_MODE from
    # the test-run env must not bleed into mode assertions).
    monkeypatch.delenv("AGENTX_MODE", raising=False)
    monkeypatch.delenv("AGENTX_ALLOW_PAYLOAD_SYNC", raising=False)
    monkeypatch.delenv("AGENTX_ENV", raising=False)   # so a stray shell dev-env flag can't skew tests
    # Pin the .env overlay to empty so a real ./.env can't bleed into tests; the
    # .env-fallback test overrides this explicitly.
    monkeypatch.setattr(pulse, "_env_overlay", {})
    yield


def _active_session(**overrides):
    stats = {
        "total_calls": 2,
        "intercepts": 1,
        "critical_blocks": 1,
        "human_escalations": 0,
        "self_corrections": 1,
        # Decoy fields that carry real content/identity — these must NEVER leak:
        "challenged_traces": {"trace-abc"},
        "recovered_traces": {"trace-abc"},
        "consecutive_strikes": {"dispatch_crm_update": 2},
        "reported_cost_usd": 12.50,
    }
    stats.update(overrides)
    return stats


# --- consent gating -------------------------------------------------------

def test_enabled_by_default():
    # A clean slate (no env, no stored decision) is ON — the notify + opt-out policy.
    assert pulse.telemetry_enabled() is True


@pytest.mark.parametrize("val", ["development", "dev", "test", "Development", " DEV "])
def test_dev_env_flag_marks_automation_context(monkeypatch, val):
    # AGENTX_ENV=development|dev|test flags an internal/dev run so it's excluded from
    # the funnel (same class as CI/pytest), so the operator can stop polluting it.
    monkeypatch.setenv("AGENTX_ENV", val)
    assert pulse._is_dev_env() is True
    assert pulse.is_automation_context() is True


@pytest.mark.parametrize("val", ["production", "prod", "staging", ""])
def test_non_dev_env_is_not_flagged(monkeypatch, val):
    monkeypatch.setenv("AGENTX_ENV", val)
    assert pulse._is_dev_env() is False


def test_dev_env_flag_suppresses_protection(monkeypatch):
    # A dev-env run must not count toward the streak or write pulse.json (the whole
    # point: the operator's own machine can't inflate the funnel).
    monkeypatch.setenv("AGENTX_ENV", "development")
    assert pulse.record_protection(_active_session()) is None
    assert not pulse._PULSE_FILE.exists()


@pytest.mark.parametrize("val", ["on", "true", "1", "yes", "ON", "True"])
def test_enabled_for_truthy_values(monkeypatch, val):
    monkeypatch.setenv("AGENTX_TELEMETRY", val)
    assert pulse.telemetry_enabled() is True


@pytest.mark.parametrize("val", ["", "off", "false", "0", "no"])
def test_disabled_for_falsey_values(monkeypatch, val):
    monkeypatch.setenv("AGENTX_TELEMETRY", val)
    assert pulse.telemetry_enabled() is False


def test_explicit_off_sends_nothing(monkeypatch):
    monkeypatch.setenv("AGENTX_TELEMETRY", "off")
    with patch.object(pulse, "_post") as post:
        result = pulse.maybe_send(_active_session(), block=True)
    assert result is None
    post.assert_not_called()
    # And nothing is written to disk when opted out.
    assert not (pulse._PULSE_FILE).exists()


def test_prior_declined_prompt_still_honored(monkeypatch):
    # Back-compat: a developer who answered "no" to the legacy first-run prompt
    # (consent_prompted=True, telemetry_consent=False) is NOT flipped on by the new
    # default-on policy.
    pulse._save_state({"consent_prompted": True, "telemetry_consent": False})
    assert pulse.telemetry_enabled() is False


# --- the privacy whitelist (the critical one) -----------------------------

def test_payload_only_contains_allowed_keys():
    state = {"install_id": "fixed-id", "first_seen": "2026-06-01"}
    payload = pulse.build_payload(_active_session(), state)

    assert set(payload.keys()) <= pulse._ALLOWED_KEYS
    assert set(payload["session"].keys()) <= pulse._ALLOWED_SESSION_KEYS


def test_payload_emits_exactly_the_allowlist():
    """build_payload must emit EXACTLY the declared allowlist — not a subset.

    This locks the side that actually sends: adding a field to build_payload
    without declaring it (would fail the subset test above) AND declaring a key
    in the allowlist that build_payload stopped emitting are both caught here.
    The route (ui/app/api/pulse/route.ts) is the defense-in-depth mirror of this
    contract — KEEP IT IN SYNC when these sets change."""
    state = {"install_id": "fixed-id", "first_seen": "2026-06-01"}
    payload = pulse.build_payload(_active_session(), state)

    assert set(payload.keys()) == pulse._ALLOWED_KEYS
    assert set(payload["session"].keys()) == pulse._ALLOWED_SESSION_KEYS


def test_payload_never_leaks_content_or_identity():
    """No decoy content/identity field may appear anywhere in the serialized pulse."""
    state = {"install_id": "fixed-id", "first_seen": "2026-06-01"}
    payload = pulse.build_payload(_active_session(), state)
    blob = json.dumps(payload)

    for forbidden in ("trace-abc", "consecutive_strikes", "dispatch_crm_update",
                      "challenged_traces", "recovered_traces", "12.5", "reported_cost"):
        assert forbidden not in blob


def test_payload_counts_are_faithful():
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    payload = pulse.build_payload(_active_session(intercepts=3, critical_blocks=2), state)
    s = payload["session"]
    assert s["tools_monitored"] == 2
    assert s["intercepts"] == 3
    assert s["critical_blocks"] == 2
    assert s["had_block"] is True


# --- funnel-stage signals (mode + gateway_present) ------------------------

def test_payload_carries_funnel_stage_fields():
    """build_payload emits the coarse stage signals at the top level."""
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    payload = pulse.build_payload(_active_session(), state)
    assert "mode" in payload
    assert "gateway_present" in payload
    assert "reasoning_enabled" in payload


def test_gateway_present_reflects_session_signal():
    """gateway_present mirrors the session's gateway_reached flag (SDK-only vs +gateway)."""
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    assert pulse.build_payload(_active_session(), state)["gateway_present"] is False
    assert pulse.build_payload(_active_session(gateway_reached=True), state)["gateway_present"] is True


def test_reasoning_enabled_reflects_session_signal():
    """reasoning_enabled is the tri-state Recover signal (keyless Shield vs Recover):
    None when no gateway ever advertised it (old gateway / SDK-only) so deploy order
    can't mislabel a Recover user keyless; True/False when the gateway reported it."""
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    assert pulse.build_payload(_active_session(), state)["reasoning_enabled"] is None
    assert pulse.build_payload(_active_session(reasoning_enabled=True), state)["reasoning_enabled"] is True
    assert pulse.build_payload(_active_session(reasoning_enabled=False), state)["reasoning_enabled"] is False


def test_integration_defaults_to_decorator_and_reflects_mcp():
    """integration splits the funnel by surface: the in-process decorator path never
    sets it (defaults to 'decorator'); the agentx-mcp proxy sets 'mcp'. Off-vocab is
    normalized to 'decorator' (fail-safe — never free text)."""
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    assert pulse.build_payload(_active_session(), state)["integration"] == "decorator"
    assert pulse.build_payload(_active_session(integration="mcp"), state)["integration"] == "mcp"
    assert pulse.build_payload(_active_session(integration="bogus"), state)["integration"] == "decorator"


def test_contributed_reflects_state():
    """contributed is read from PERSISTENT state (set by `agentx push`, a different
    process), not session_stats — so the pulse can see the contribute funnel leg.
    Default False; True once the state flag is set."""
    base = {"install_id": "x", "first_seen": "2026-06-01"}
    assert pulse.build_payload(_active_session(), base)["contributed"] is False
    assert pulse.build_payload(_active_session(), {**base, "contributed": True})["contributed"] is True


def test_mark_contributed_sets_sticky_flag():
    """mark_contributed() persists contributed=True and mints the anon identity, so
    the next pulse reports the contribute leg joined by install_id."""
    pulse.mark_contributed()
    state = pulse._load_state()
    assert state["contributed"] is True
    assert state.get("install_id")   # identity minted so the flag joins the funnel


def test_mode_defaults_to_local():
    """No mode signals set => local (the cold, plane-less install)."""
    assert pulse._mode() == "local"


@pytest.mark.parametrize("val,expected", [
    ("local", "local"), ("linked", "linked"), ("cloud", "cloud"),
    ("CLOUD", "cloud"), (" Linked ", "linked"),
])
def test_explicit_mode_wins(monkeypatch, val, expected):
    monkeypatch.setenv("AGENTX_MODE", val)
    assert pulse._mode() == expected


def test_mode_inferred_linked_from_control_plane(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_URL", "https://agentx-core.com")
    assert pulse._mode() == "linked"


def test_mode_inferred_cloud_from_legacy_sync(monkeypatch):
    monkeypatch.setenv("AGENTX_ALLOW_PAYLOAD_SYNC", "true")
    assert pulse._mode() == "cloud"


def test_mode_is_a_closed_enum_value():
    """Whatever _mode returns is always one of the three coarse stages — never
    free-form text that could leak into the column."""
    state = {"install_id": "x", "first_seen": "2026-06-01"}
    assert pulse.build_payload(_active_session(), state)["mode"] in ("local", "linked", "cloud")


# --- identity stability ---------------------------------------------------

def test_install_id_is_stable_across_sends(monkeypatch):
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    with patch.object(pulse, "_post"):
        first = pulse.maybe_send(_active_session(), block=True)
    state = pulse._load_state()
    # Wind the debounce clock back so a second send is allowed.
    state["last_pulse"] = 0
    pulse._save_state(state)
    with patch.object(pulse, "_post"):
        second = pulse.maybe_send(_active_session(), block=True)
    assert first["install_id"] == second["install_id"]


# --- debounce -------------------------------------------------------------

def test_debounce_blocks_second_pulse_same_day(monkeypatch):
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    with patch.object(pulse, "_post") as post:
        assert pulse.maybe_send(_active_session(), block=True) is not None
        assert pulse.maybe_send(_active_session(), block=True) is None
    assert post.call_count == 1


def test_idle_session_still_heartbeats(monkeypatch):
    # No activity is NOT a reason to stay silent: an idle run (SDK imported, nothing
    # wrapped) still pulses so "this install ran today" is visible. The counts ride
    # along as zeros; the funnel separates "ran" from "activated" on tools_monitored.
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    idle = {"total_calls": 0, "intercepts": 0, "human_escalations": 0}
    with patch.object(pulse, "_post") as post:
        payload = pulse.maybe_send(idle, block=True)
    assert payload is not None
    post.assert_called_once()
    assert payload["session"]["tools_monitored"] == 0
    assert payload["session"]["had_block"] is False


# --- first-block-ever flag ------------------------------------------------

def test_first_block_ever_fires_once(monkeypatch):
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    with patch.object(pulse, "_post"):
        first = pulse.maybe_send(_active_session(), block=True)
    assert first["session"]["first_block_ever"] is True

    state = pulse._load_state()
    state["last_pulse"] = 0  # allow another send
    pulse._save_state(state)
    with patch.object(pulse, "_post"):
        second = pulse.maybe_send(_active_session(), block=True)
    assert second["session"]["first_block_ever"] is False


# --- resilience -----------------------------------------------------------

def test_send_swallows_network_errors(monkeypatch):
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    with patch("agentx_sdk.pulse.urllib.request.urlopen", side_effect=OSError("boom")):
        # block=True joins the worker thread; must not raise despite the error.
        result = pulse.maybe_send(_active_session(), block=True)
    assert result is not None  # dispatch happened; the failure was absorbed


def test_endpoint_default_when_no_plane():
    # A plane-less local install -> the public default.
    assert pulse._endpoint() == pulse._DEFAULT_ENDPOINT


def test_default_endpoint_is_canonical_www_not_redirecting_apex():
    # The apex agentx-core.com 307-redirects to www, and urllib refuses to follow a
    # 307 for a POST (it raises HTTPError) -> a default pointed at the bare apex
    # silently drops every plane-less cold-install pulse. Pin the canonical www host
    # so it can't regress to the apex.
    assert pulse._DEFAULT_ENDPOINT == "https://www.agentx-core.com/api/pulse"
    assert "://agentx-core.com" not in pulse._DEFAULT_ENDPOINT


# --- default-on policy + transparency notice ------------------------------

def test_default_on_install_is_default_on(monkeypatch):
    # A clean slate gets the one-time notice; an explicit env or a prior prompt
    # answer does not (it already knows).
    assert pulse._is_default_on() is True
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    assert pulse._is_default_on() is False
    monkeypatch.delenv("AGENTX_TELEMETRY")
    pulse._save_state({"consent_prompted": True, "telemetry_consent": True})
    assert pulse._is_default_on() is False


def test_show_notice_marks_shown_and_mints_identity():
    pulse._show_notice()
    state = pulse._load_state()
    assert state["notice_shown"] is True
    assert "install_id" in state            # identity minted alongside the disclosure


def test_show_notice_carries_demo_and_feedback_pointer(capsys):
    # The first-run notice doubles as the activation/qualitative-feedback touchpoint:
    # it points a fresh install at the instant demo and a channel to report breakage.
    pulse._show_notice()
    out = capsys.readouterr().out
    assert "agentx demo" in out
    assert "discord.gg/PmWRTtaSx2" in out
    assert "AGENTX_TELEMETRY=off" in out     # opt-out stays visible too


def test_explicit_opt_in_skips_notice(monkeypatch):
    # An AGENTX_TELEMETRY=on install already knows — on_session_end sends without
    # ever printing the default-on notice.
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    with patch.object(pulse, "_show_notice", side_effect=AssertionError("no notice")), \
         patch.object(pulse, "_post") as post:
        pulse.on_session_end(_active_session())
    post.assert_called_once()


def test_note_first_block_keeps_activation_honest_for_later_opt_in(monkeypatch):
    # Block happens while undecided/opted-out -> recorded, so a later opt-in send
    # reports first_block_ever=False (the real first block predates opt-in).
    pulse._note_first_block(_active_session())
    assert pulse._load_state().get("first_block_recorded") is True
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    with patch.object(pulse, "_post"):
        sent = pulse.maybe_send(_active_session(), block=True)
    assert sent["session"]["first_block_ever"] is False


# --- on_session_end orchestration -----------------------------------------

def test_on_session_end_sends_when_opted_in(monkeypatch):
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    with patch.object(pulse, "_post") as post:
        pulse.on_session_end(_active_session())
    post.assert_called_once()


def test_on_session_end_default_on_shows_notice_then_sends(monkeypatch):
    # A clean slate: the one-time transparency notice is shown, then the pulse is
    # sent, and the notice is marked so it never repeats.
    with patch.object(pulse, "_post") as post:
        pulse.on_session_end(_active_session())
    post.assert_called_once()
    assert pulse._load_state()["notice_shown"] is True


def test_on_session_end_first_run_no_activity_notices_and_sends(monkeypatch):
    # THE activation-visibility case: a first run that wrapped nothing must still
    # show the notice AND heartbeat, so a downloaded-and-ran install is no longer
    # invisible. (Previously the activity gate dropped both.)
    idle = {"total_calls": 0, "intercepts": 0, "human_escalations": 0}
    with patch.object(pulse, "_show_notice", wraps=pulse._show_notice) as notice, \
         patch.object(pulse, "_post") as post:
        pulse.on_session_end(idle)
    notice.assert_called_once()
    post.assert_called_once()
    assert pulse._load_state()["notice_shown"] is True


def test_on_session_end_notice_shown_once(monkeypatch):
    # The notice prints on the first activated session only; a same-day second
    # session is debounced (no send) and prints nothing new.
    with patch.object(pulse, "_show_notice", wraps=pulse._show_notice) as notice, \
         patch.object(pulse, "_post"):
        pulse.on_session_end(_active_session())
        pulse.on_session_end(_active_session())
    notice.assert_called_once()


def test_on_session_end_sends_non_interactive_by_default(monkeypatch):
    # Default-on is NOT gated on a TTY — a genuine non-interactive production run
    # (not CI/pytest, which on_session_end's caller excludes) still pulses.
    with patch.object(pulse, "_post") as post:
        pulse.on_session_end(_active_session())
    post.assert_called_once()


def test_on_session_end_respects_a_prior_no(monkeypatch):
    # A developer who declined the legacy prompt is never flipped on, and never
    # re-disclosed to.
    pulse._save_state({"consent_prompted": True, "telemetry_consent": False})
    with patch.object(pulse, "_show_notice", side_effect=AssertionError("no notice")), \
         patch.object(pulse, "_post") as post:
        pulse.on_session_end(_active_session())
    post.assert_not_called()


def test_on_session_end_first_block_default_on_reports_first_block_ever_true(monkeypatch):
    # The activation moment: a cold default-on install blocks for the first time.
    # _note_first_block must NOT have pre-flipped the flag, so the sent pulse
    # carries first_block_ever=True.
    captured = {}
    monkeypatch.setattr(pulse, "_post", lambda endpoint, payload: captured.update(payload))
    pulse.on_session_end(_active_session())              # _active_session has a block
    assert captured["session"]["first_block_ever"] is True


def test_is_automation_context_true_under_pytest():
    # We are running under pytest right now, so this must report automation.
    assert pulse.is_automation_context() is True


def test_is_ci_env_detection(monkeypatch):
    for v in pulse._CI_ENV_VARS:
        monkeypatch.delenv(v, raising=False)
    assert pulse._is_ci() is False
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert pulse._is_ci() is True


def test_on_session_end_opted_out_still_records_first_block(monkeypatch):
    # Not-sending paths (here: explicit opt-out) must still record the first block
    # so a LATER opt-in isn't misattributed.
    monkeypatch.setenv("AGENTX_TELEMETRY", "off")
    with patch.object(pulse, "_post") as post:
        pulse.on_session_end(_active_session())
    post.assert_not_called()
    assert pulse._load_state().get("first_block_recorded") is True


# --- endpoint idempotency + single-source consent -------------------------

@pytest.mark.parametrize("plane", ["https://my.plane/api/pulse", "https://my.plane/api/pulse/"])
def test_endpoint_idempotent_when_plane_already_has_route(monkeypatch, plane):
    monkeypatch.setenv("CONTROL_PLANE_URL", plane)
    assert pulse._endpoint() == "https://my.plane/api/pulse"   # not doubled


def test_show_notice_does_not_write_dotenv(tmp_path, monkeypatch):
    # The disclosure/identity state lives in ~/.agentx/pulse.json only — never
    # ./.env — so the opt-out surface (env) stays the developer's alone to set.
    monkeypatch.chdir(tmp_path)
    pulse._show_notice()
    assert not (tmp_path / ".env").exists()


def test_explicit_env_overrides_default_and_stored(monkeypatch):
    # Default-on with no env -> True; an explicit env off always wins, even over a
    # stored prior yes.
    pulse._save_state({"consent_prompted": True, "telemetry_consent": True})
    assert pulse.telemetry_enabled() is True            # stored yes, no env
    monkeypatch.setenv("AGENTX_TELEMETRY", "off")
    assert pulse.telemetry_enabled() is False           # explicit env always wins


def test_first_block_ever_bypasses_debounce(monkeypatch):
    # A non-block heartbeat sends first and consumes the daily debounce window...
    monkeypatch.setenv("AGENTX_TELEMETRY", "on")
    no_block = {"total_calls": 4, "intercepts": 0, "critical_blocks": 0}
    with patch.object(pulse, "_post"):
        first = pulse.maybe_send(no_block, block=True)
    assert first["session"]["first_block_ever"] is False
    # ...then the install's FIRST block fires the same day. Even though we're inside
    # the debounce window, the 'aha' must still be transmitted (not swallowed) -> it
    # force-sends with first_block_ever=True, and only now is the flag recorded.
    with patch.object(pulse, "_post") as post:
        aha = pulse.maybe_send(_active_session(), block=True)
    post.assert_called_once()
    assert aha is not None and aha["session"]["first_block_ever"] is True
    assert pulse._load_state().get("first_block_recorded") is True
    # A LATER (non-first) block is just a normal pulse: still debounced this same day,
    # and once it does send it does NOT misreport first_block_ever.
    with patch.object(pulse, "_post") as post:
        assert pulse.maybe_send(_active_session(), block=True) is None   # debounced
    post.assert_not_called()
    state = pulse._load_state(); state["last_pulse"] = 0; pulse._save_state(state)
    with patch.object(pulse, "_post"):
        later = pulse.maybe_send(_active_session(), block=True)
    assert later["session"]["first_block_ever"] is False


# --- endpoint derived from CONTROL_PLANE_URL ------------------------------

@pytest.mark.parametrize("plane,expected", [
    ("https://my.plane", "https://my.plane/api/pulse"),
    ("https://my.plane/", "https://my.plane/api/pulse"),       # trailing slash trimmed
    ("http://localhost:3000", "http://localhost:3000/api/pulse"),
])
def test_endpoint_derives_from_control_plane(monkeypatch, plane, expected):
    monkeypatch.setenv("CONTROL_PLANE_URL", plane)
    assert pulse._endpoint() == expected


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "ftp://evil/collect", "evil.example/x", "javascript:1"])
def test_endpoint_ignores_non_http_control_plane(monkeypatch, bad):
    # A stray/hostile CONTROL_PLANE_URL can't redirect the pulse — fall back to default.
    monkeypatch.setenv("CONTROL_PLANE_URL", bad)
    assert pulse._endpoint() == pulse._DEFAULT_ENDPOINT


# --- .env fallback ---------------------------------------------------------

def test_telemetry_flag_honored_from_dotenv_overlay(monkeypatch):
    # Not in process env, but present in the .env overlay (as .env.example tells
    # users to set it) — must still be honored.
    monkeypatch.setattr(pulse, "_env_overlay", {"AGENTX_TELEMETRY": "on"})
    assert pulse.telemetry_enabled() is True


# --- delivery at REAL interpreter shutdown (the atexit path) ---------------

def test_pulse_delivers_from_real_atexit_shutdown(tmp_path):
    """Regression: the pulse must actually leave at interpreter shutdown.

    on_session_end fires from an atexit handler, and Python 3.12+ refuses to start a
    new thread once shutdown has begun. maybe_send dispatched via a daemon thread and
    swallowed the resulting RuntimeError in its outer try/except, so on 3.12+ the
    default-on pulse silently never sent. Every other test in this file calls
    maybe_send/on_session_end *directly* (never through a genuine process exit), and
    CI is excluded from telemetry — so the suite stayed green while the real path was
    dead. This is the one test that exercises a true shutdown.

    It stands up a loopback receiver, runs the REAL SDK in a subprocess that blocks a
    DROP TABLE and then exits naturally (decorators' atexit -> on_session_end ->
    maybe_send during finalization), and asserts the pulse was delivered. Fails on the
    pre-fix code on Python 3.12+; passes on every supported version with the fix.
    """
    import json as _json
    import subprocess as _sp
    import sys as _sys
    import threading as _threading
    import time as _time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    received = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n)
            try:
                body = _json.loads(raw.decode("utf-8"))
            except Exception:
                body = None
            if isinstance(body, dict) and "install_id" in body and "session" in body:
                received.append(body)
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    _threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        home = tmp_path / "shutdown_home"
        home.mkdir()

        env = dict(os.environ)
        env["USERPROFILE"] = str(home)            # isolate ~/.agentx/pulse.json
        env["HOME"] = str(home)
        env["CONTROL_PLANE_URL"] = "http://127.0.0.1:%d" % port
        env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["AGENTX_TELEMETRY"] = "on"             # force ON; never inherit a repo .env opt-out
        # The child must NOT read as automation, or decorators skips the pulse entirely.
        env.pop("PYTEST_CURRENT_TEST", None)
        for _v in pulse._CI_ENV_VARS:
            env.pop(_v, None)

        # The production path verbatim: wrap a tool, block a DROP TABLE, exit naturally.
        child = (
            "import os\n"
            "from agentx_sdk import agentx_protect, start_secure_session, is_block\n"
            "start_secure_session()\n"
            "@agentx_protect(agent_id='pulse_atexit_regression')\n"
            "def run_sql(query, db_session=None):\n"
            "    return {'status': 'ok'}\n"
            "os.environ.pop('AGENTX_API_KEY', None)\n"
            "r = run_sql(query='Update notes; DROP TABLE users;', db_session='x')\n"
            "assert is_block(r), 'BLOCK_DID_NOT_FIRE'\n"
        )

        # Run from the isolated home (imports resolve via PYTHONPATH=repo_root), so the
        # child never reads the repo-root ./.env that load_env_file would otherwise pick up.
        proc = _sp.run([_sys.executable, "-c", child], env=env, cwd=str(home),
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=90)
        assert "BLOCK_DID_NOT_FIRE" not in (proc.stderr or ""), proc.stderr

        # The fixed send is synchronous at atexit, so the POST lands before the child
        # exits; poll only to absorb loopback scheduling jitter.
        deadline = _time.time() + 5.0
        while not received and _time.time() < deadline:
            _time.sleep(0.05)
    finally:
        srv.shutdown()
        srv.server_close()

    assert received, (
        "no pulse delivered from the real atexit/shutdown path — maybe_send is "
        "dropping the send during interpreter shutdown (the Python 3.12+ thread-start "
        "RuntimeError must fall back to a synchronous send)."
    )
    sent = received[-1]
    assert sent["session"]["had_block"] is True
    assert sent["session"]["first_block_ever"] is True   # the activation moment
    assert sent["sdk_version"]                            # version rode along


# --- record_protection: the LOCAL-ONLY protection streak (goal K) ----------
# The value-report bookkeeping both surfaces print at session end. The load-
# bearing guarantee is the same negative space as the rest of this file: the
# streak fields live in pulse.json but must NEVER ride the pulse.

@pytest.fixture()
def real_session(monkeypatch):
    """record_protection self-gates on automation (pytest IS automation), so these
    tests explicitly simulate a real developer session (the test_nudge pattern)."""
    monkeypatch.setattr(pulse, "is_automation_context", lambda: False)


def test_protection_first_session_starts_streak(real_session):
    from datetime import date
    day = date(2026, 7, 1)              # pinned so a midnight-crossing run can't flake
    got = pulse.record_protection(_active_session(), today=day)
    assert got == {"streak_days": 1, "protected_sessions": 1, "since": day.isoformat()}
    state = pulse._load_state()
    assert state["streak_days"] == 1
    assert state["last_protected_day"] == day.isoformat()
    assert state["install_id"]          # identity minted so the report has a since-date


def test_protection_same_day_counts_session_keeps_streak(real_session):
    pulse.record_protection(_active_session())
    got = pulse.record_protection(_active_session())
    assert got["streak_days"] == 1 and got["protected_sessions"] == 2


def test_protection_next_day_extends_streak(real_session):
    from datetime import date
    pulse.record_protection(_active_session(), today=date(2026, 7, 1))
    got = pulse.record_protection(_active_session(), today=date(2026, 7, 2))
    assert got["streak_days"] == 2 and got["protected_sessions"] == 2


def test_protection_gap_resets_streak(real_session):
    from datetime import date
    pulse.record_protection(_active_session(), today=date(2026, 7, 1))
    pulse.record_protection(_active_session(), today=date(2026, 7, 2))
    got = pulse.record_protection(_active_session(), today=date(2026, 7, 5))
    assert got["streak_days"] == 1      # a gap resets; sessions keep accumulating
    assert got["protected_sessions"] == 3


def test_protection_idle_session_writes_nothing(real_session):
    assert pulse.record_protection({"total_calls": 0}) is None
    assert not pulse._PULSE_FILE.exists()


def test_protection_noop_in_automation():
    # No real_session fixture: pytest itself IS the automation context, so the
    # streak must not count (or write pulse.json) from a test/CI run.
    assert pulse.record_protection(_active_session()) is None
    assert not pulse._PULSE_FILE.exists()


def test_protection_fields_never_reach_the_payload(real_session):
    """LOCAL-ONLY by construction: the streak's pulse.json fields must never ride
    the pulse. build_payload reads explicit keys, so state-side extras stay put."""
    pulse.record_protection(_active_session())
    state = pulse._load_state()
    assert state["protected_sessions"] == 1        # the fields ARE in local state
    flat = json.dumps(pulse.build_payload(_active_session(), state))
    for key in ("streak_days", "last_protected_day", "protected_sessions",
                "first_protected_day"):
        assert key not in flat


def test_protection_since_is_first_protected_day_not_install_date(real_session):
    """'since' must be the first PROTECTED day (0.4.6+), never the older install
    first_seen — otherwise the report overstates months of history that never happened."""
    from datetime import date
    pulse._save_state({"install_id": "x", "first_seen": "2026-01-01"})   # install predates
    got = pulse.record_protection(_active_session(), today=date(2026, 7, 1))
    assert got["since"] == "2026-07-01"
    later = pulse.record_protection(_active_session(), today=date(2026, 7, 2))
    assert later["since"] == "2026-07-01"           # sticky across sessions


def test_protection_corrupt_streak_does_not_brick(real_session):
    """A hand-edited/foreign non-numeric streak_days must self-heal, not raise inside
    the try and return None forever (never repairing the field)."""
    from datetime import date
    pulse._save_state({"install_id": "x", "first_seen": "2026-06-01",
                       "streak_days": "not-a-number", "last_protected_day": "2026-06-30"})
    got = pulse.record_protection(_active_session(), today=date(2026, 7, 1))
    assert got is not None and got["streak_days"] == 1   # reset, not bricked


def test_protection_datetime_today_is_normalized(real_session):
    """A datetime passed as `today` must be normalized to a date, or last_protected_day
    would carry a full timestamp that date.fromisoformat rejects next session."""
    from datetime import datetime
    pulse.record_protection(_active_session(), today=datetime(2026, 7, 1, 10, 30, 0))
    assert pulse._load_state()["last_protected_day"] == "2026-07-01"


def test_format_protection_line_is_canonical():
    assert pulse.format_protection_line(
        {"streak_days": 3, "protected_sessions": 7, "since": "2026-06-01"}
    ) == "3 day(s) | 7 protected session(s) since 2026-06-01"


def test_save_state_is_atomic_and_leaves_no_temp(real_session):
    """The atomic write (tmp + os.replace) leaves a complete pulse.json and no
    leftover temp file behind."""
    from datetime import date
    pulse.record_protection(_active_session(), today=date(2026, 7, 1))
    assert pulse._PULSE_FILE.exists()
    assert json.loads(pulse._PULSE_FILE.read_text(encoding="utf-8"))   # complete, parseable
    assert list(pulse._PULSE_FILE.parent.glob(".pulse-*.tmp")) == []   # no torn temp left
