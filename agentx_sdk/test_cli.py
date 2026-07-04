import json
import os
import pytest
from unittest.mock import patch, MagicMock, call
import requests as requests_lib

from agentx_sdk.cli import load_env_file, execute_status_inspection, execute_policy_pull


def make_response(status_code, json_body=None):
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_body or {}
    return m


TELEMETRY_BODY = {
    "intercepts": 5,
    "socratic_nudges_issued": 3,
    "human_escalations_required": 1,
    "successful_agent_pivots": 2,
    "agent_self_correction_rate_percent": 40.0,
}

POLICIES_BODY = {
    "neural_threshold": 0.30,
    "control_plane_url": "http://localhost:3000",
    "policies": [
        {"name": "Mass Destructive Intent", "target_action": "Execute Database Query", "is_active": True},
        {"name": "Network Sandbox (SSRF)", "target_action": "Fetch Network Resource", "is_active": False},
    ],
}


# =============================================================================
# load_env_file
# =============================================================================

def test_load_env_file_empty_when_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_env_file() == {}


def test_load_env_file_reads_key_value_pairs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("FOO=bar\nBAZ=qux\n")
    result = load_env_file()
    assert result["FOO"] == "bar"
    assert result["BAZ"] == "qux"


def test_load_env_file_strips_double_quotes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('KEY="my value"\n')
    assert load_env_file()["KEY"] == "my value"


def test_load_env_file_strips_single_quotes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("KEY='my value'\n")
    assert load_env_file()["KEY"] == "my value"


def test_load_env_file_skips_comments_and_blank_lines(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("# this is a comment\n\nKEY=value\n")
    result = load_env_file()
    assert list(result.keys()) == ["KEY"]


def test_load_env_file_splits_on_first_equals_only(tmp_path, monkeypatch):
    """Values containing = signs (e.g. URLs with query strings) must not be truncated."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("URL=http://host:8000/path?a=1&b=2\n")
    assert load_env_file()["URL"] == "http://host:8000/path?a=1&b=2"


def test_load_env_file_parent_fallback(tmp_path, monkeypatch):
    """When no local .env exists, falls back to ../.env."""
    child = tmp_path / "subdir"
    child.mkdir()
    (tmp_path / ".env").write_text("FROM_PARENT=yes\n")
    monkeypatch.chdir(child)
    assert load_env_file()["FROM_PARENT"] == "yes"


# =============================================================================
# execute_status_inspection
# =============================================================================

def test_execute_status_inspection_success_prints_telemetry(capsys):
    with patch("agentx_sdk.cli.requests.get") as mock_get:
        mock_get.side_effect = [
            make_response(200, TELEMETRY_BODY),
            make_response(200, POLICIES_BODY),
        ]
        execute_status_inspection("http://localhost:8000", "agentx_sk_test")
    out = capsys.readouterr().out
    assert "5" in out                          # intercepts count
    assert "40.0" in out                       # recovery rate
    assert "Mass Destructive Intent" in out    # policy name


def test_execute_status_inspection_shows_armed_and_disabled(capsys):
    with patch("agentx_sdk.cli.requests.get") as mock_get:
        mock_get.side_effect = [
            make_response(200, TELEMETRY_BODY),
            make_response(200, POLICIES_BODY),
        ]
        execute_status_inspection("http://localhost:8000", "agentx_sk_test")
    out = capsys.readouterr().out
    assert "ARMED" in out
    assert "DISABLED" in out


def test_execute_status_inspection_sends_auth_header():
    with patch("agentx_sdk.cli.requests.get") as mock_get:
        mock_get.side_effect = [
            make_response(200, TELEMETRY_BODY),
            make_response(200, POLICIES_BODY),
        ]
        execute_status_inspection("http://localhost:8000", "agentx_sk_mykey")
    for c in mock_get.call_args_list:
        assert c[1]["headers"]["Authorization"] == "Bearer agentx_sk_mykey"


def test_execute_status_inspection_local_no_gateway_exits_zero(capsys):
    """A keyless/local user has no gateway BY DESIGN, so an unreachable one is the normal
    free state, not a failure: render the local flight-recorder and exit 0 (not a red
    error). This is the P1 fix so the post-demo `agentx status` is an inviting second
    session, not a non-zero error."""
    with patch("agentx_sdk.cli.requests.get", side_effect=requests_lib.exceptions.ConnectionError):
        with pytest.raises(SystemExit) as exc_info:
            execute_status_inspection("http://localhost:8000", "agentx_sk_local_sandbox", "local")
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "AGENTX LOCAL STATUS" in out          # leads with the local view, no ❌ error
    assert "LOCAL FLIGHT RECORDER" in out


def test_execute_status_inspection_cloud_no_gateway_exits_one():
    """A linked/cloud user WAS expecting a gateway, so an unreachable one is a real fault:
    keep the non-zero exit."""
    with patch("agentx_sdk.cli.requests.get", side_effect=requests_lib.exceptions.ConnectionError):
        with pytest.raises(SystemExit) as exc_info:
            execute_status_inspection("http://localhost:8000", "agentx_sk_test", "cloud")
    assert exc_info.value.code == 1


def test_execute_status_inspection_exits_on_non_200():
    with patch("agentx_sdk.cli.requests.get") as mock_get:
        mock_get.side_effect = [
            make_response(401, {}),
            make_response(200, POLICIES_BODY),
        ]
        with pytest.raises(SystemExit) as exc_info:
            execute_status_inspection("http://localhost:8000", "agentx_sk_test")
    assert exc_info.value.code == 1


def test_execute_status_inspection_empty_policies_prints_warning(capsys):
    with patch("agentx_sdk.cli.requests.get") as mock_get:
        mock_get.side_effect = [
            make_response(200, TELEMETRY_BODY),
            make_response(200, {**POLICIES_BODY, "policies": []}),
        ]
        execute_status_inspection("http://localhost:8000", "agentx_sk_test")
    assert "No active policies" in capsys.readouterr().out


# =============================================================================
# execute_policy_pull
# =============================================================================

def test_execute_policy_pull_writes_policies_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    policies = [{"id": "P1", "name": "Test Policy"}]
    with patch("agentx_sdk.cli.requests.get",
               return_value=make_response(200, {"policies": policies})):
        execute_policy_pull("http://localhost:3000", "agentx_sk_test")
    written = json.loads((tmp_path / ".agentx" / "policies.json").read_text())
    assert written == policies


def test_execute_policy_pull_creates_agentx_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("agentx_sdk.cli.requests.get",
               return_value=make_response(200, {"policies": []})):
        execute_policy_pull("http://localhost:3000", "agentx_sk_test")
    assert (tmp_path / ".agentx").is_dir()


def test_execute_policy_pull_exits_on_401():
    with patch("agentx_sdk.cli.requests.get", return_value=make_response(401, {})):
        with pytest.raises(SystemExit) as exc_info:
            execute_policy_pull("http://localhost:3000", "agentx_sk_test")
    assert exc_info.value.code == 1


def test_execute_policy_pull_exits_on_non_200():
    with patch("agentx_sdk.cli.requests.get", return_value=make_response(500, {})):
        with pytest.raises(SystemExit) as exc_info:
            execute_policy_pull("http://localhost:3000", "agentx_sk_test")
    assert exc_info.value.code == 1


def test_execute_policy_pull_exits_on_network_error():
    with patch("agentx_sdk.cli.requests.get",
               side_effect=requests_lib.exceptions.ConnectionError):
        with pytest.raises(SystemExit) as exc_info:
            execute_policy_pull("http://localhost:3000", "agentx_sk_test")
    assert exc_info.value.code == 1


# =============================================================================
# execute_insights (render)
# =============================================================================
from agentx_sdk.cli import execute_insights


def _patch_insights(monkeypatch, harvest, active, rules=None, mcp=None):
    census = {"exists": True, "complied": 33, "with_resolution": 6, "path": "/tmp/incidents.db"}
    monkeypatch.setattr("agentx_sdk.cli.incident_db_census", lambda: census)
    monkeypatch.setattr("agentx_sdk.cli._collect_candidates",
                        lambda: (harvest, [], rules or [], mcp or []))
    monkeypatch.setattr("agentx_sdk.cli.load_overrides", lambda warn=False: {"overrides": active})

    def _enum(h):
        seq = 1
        for pid, bucket in h.items():
            for c in bucket.get("candidates", []):
                yield {"policy_id": pid, "suggestion": c["suggestion"], "seq": seq}
                seq += 1
    monkeypatch.setattr("agentx_sdk.cli.enumerate_candidates", _enum)


def test_insights_active_shown_once_and_alts_capped(capsys, monkeypatch):
    harvest = {"p1": {"policy_violated": "Mass Destructive Intent", "candidates": [
        {"suggestion": "Verify all SQL is read-only."},
        {"suggestion": "Forbid DROP and DELETE."},
        {"suggestion": "Only SELECT statements."},
        {"suggestion": "No destructive DDL."},
    ]}}
    active = {"p1": {"challenge": "Verify all SQL is read-only.", "policy_violated": "Mass Destructive Intent"}}
    _patch_insights(monkeypatch, harvest, active)
    execute_insights([])
    out = capsys.readouterr().out
    assert out.count("Verify all SQL is read-only.") == 1      # active is NOT double-printed
    assert "✅ Active (#1)" in out
    assert "Switch to:" in out
    assert "+1 more" in out                                    # 3 alts, only 2 shown
    assert "▶ adopt with:  agentx adopt <#>" in out            # the one CTA, up top
    assert "Not coaching this block yet" not in out            # this policy IS coaching


def test_insights_flags_policy_that_needs_a_pick(capsys, monkeypatch):
    harvest = {"p2": {"policy_violated": "Network Sandbox (SSRF)", "candidates": [
        {"suggestion": "Block cloud metadata IPs."},
    ]}}
    _patch_insights(monkeypatch, harvest, {})                  # nothing adopted yet
    execute_insights([])
    out = capsys.readouterr().out
    assert "Not coaching this block yet" in out
    assert "#1  Block cloud metadata IPs." in out


# =============================================================================
# agentx mcp-insights  (the keyless MCP recovery loop — sibling of insights)
# =============================================================================
from agentx_sdk.cli import execute_mcp_insights, execute_adopt


def _patch_mcp_insights(monkeypatch, mcp_flat, active=None, enabled=True, path="/x/mcp_harvest.jsonl"):
    # execute_mcp_insights uses _collect_candidates (global #N) + load_overrides, and lazy-imports
    # the empty-state helpers from mcp_proxy.
    monkeypatch.setattr("agentx_sdk.cli._collect_candidates",
                        lambda: ({}, [], [], mcp_flat))
    monkeypatch.setattr("agentx_sdk.cli.load_overrides", lambda warn=False: {"overrides": active or {}})
    monkeypatch.setattr("agentx_sdk.mcp_proxy._harvest_enabled", lambda: enabled)
    monkeypatch.setattr("agentx_sdk.mcp_proxy._harvest_path", lambda: path)


def test_mcp_insights_off_and_no_file_prompts_enable(capsys, monkeypatch, tmp_path):
    _patch_mcp_insights(monkeypatch, [], enabled=False, path=str(tmp_path / "nope.jsonl"))
    execute_mcp_insights()
    out = capsys.readouterr().out
    assert "Harvest is OFF" in out and "AGENTX_MCP_HARVEST=true" in out


def test_mcp_insights_renders_adoptable_paths(capsys, monkeypatch):
    mcp_flat = [
        {"seq": 4, "policy_id": "pol-1", "policy_violated": "Mass Destructive Intent",
         "suggestion": "Your agents recovered from 'Mass Destructive Intent' before by NARROWING the action.",
         "count": 3, "tool": "run_sql", "target_action": "READ", "scope": "scoped"},
    ]
    _patch_mcp_insights(monkeypatch, mcp_flat)
    execute_mcp_insights()
    out = capsys.readouterr().out
    assert "Mass Destructive Intent" in out
    assert "#4" in out                                   # global adopt sequence number
    assert "×3" in out                                   # recurrence
    assert "agentx adopt <#>" in out                     # the adopt CTA
    assert "SELECT" not in out and "DROP TABLE" not in out


def test_mcp_insights_marks_auto_coaching(capsys, monkeypatch):
    mcp_flat = [
        {"seq": 1, "policy_id": "pol-1", "policy_violated": "Mass Destructive Intent",
         "suggestion": "reframe text", "count": 5, "tool": "run_sql",
         "target_action": "READ", "scope": "scoped"},
    ]
    active = {"pol-1": {"challenge": "reframe text", "source": "mcp_auto"}}
    _patch_mcp_insights(monkeypatch, mcp_flat, active=active)
    execute_mcp_insights()
    assert "auto-coaching" in capsys.readouterr().out    # shows what auto-coach already applied


def test_adopt_mcp_candidate_writes_override(capsys, monkeypatch):
    # A #N that lands on an MCP recovery candidate adopts it as a reframe via adopt_override,
    # keyed to the policy, confirmed (non-interactive auto-confirms).
    mcp_flat = [
        {"seq": 3, "policy_id": "pol-9", "policy_violated": "Secrets and PII",
         "suggestion": "Narrow the read: add an id/filter/limit, then retry.",
         "safe_path": None, "resolution_type": "mcp_recovery", "count": 4,
         "tool": "read_file", "target_action": "READ", "scope": "scoped"},
    ]
    monkeypatch.setattr("agentx_sdk.cli._collect_candidates", lambda: ({}, [], [], mcp_flat))
    monkeypatch.setattr("agentx_sdk.cli.load_overrides", lambda warn=False: {"overrides": {}})
    captured = {}
    def _fake_adopt(pid, **kw):
        captured["pid"] = pid; captured.update(kw)
        return {"challenge": kw["challenge"], "safe_path": kw.get("safe_path")}
    monkeypatch.setattr("agentx_sdk.cli.adopt_override", _fake_adopt)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)     # non-interactive -> auto-confirm
    execute_adopt(["3"])
    assert captured["pid"] == "pol-9"
    assert captured["source"] == "mcp_harvest"
    assert captured["resolution_type"] == "mcp_recovery"
    assert captured["policy_violated"] == "Secrets and PII"


# =============================================================================
# agentx demo  (the zero-config instant-aha)
# =============================================================================

def test_execute_demo_blocks_offline(capsys, monkeypatch):
    # The demo must block the DROP TABLE through the in-process floor with NO key
    # and NO gateway — the dangerous EXECUTING line must never print — and surface
    # the next-step pointers (own-agent snippet, upgrade, dashboard, Discord).
    monkeypatch.setenv("AGENTX_MODE", "local")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    # Force the decorator branch so this test is deterministic regardless of whether the
    # machine running it happens to have an MCP client config. Reset the quiet flag after.
    monkeypatch.setattr("agentx_sdk.cli._detect_mcp_client", lambda: None)
    monkeypatch.setattr("agentx_sdk.decorators._atexit_summary_quiet", False)
    from agentx_sdk.cli import execute_demo
    execute_demo()
    out = capsys.readouterr().out
    assert "BLOCKED before execution" in out
    assert "[DB] EXECUTING" not in out          # the destructive call never ran
    assert "@agentx_protect" in out             # next-step: protect your own agent
    assert "discord.gg/PmWRTtaSx2" in out        # feedback channel


def test_execute_demo_routes_to_mcp_wrap_when_client_detected(capsys, monkeypatch):
    """P2: when an MCP client config is present, the demo's next step leads with the
    one-line agentx-mcp wrap (real traffic, no gateway) and frames the streak as growing,
    instead of the heavier decorator snippet."""
    monkeypatch.setenv("AGENTX_MODE", "local")
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    monkeypatch.setattr("agentx_sdk.cli._detect_mcp_client", lambda: ("Cursor", "~/.cursor/mcp.json"))
    monkeypatch.setattr("agentx_sdk.decorators._atexit_summary_quiet", False)
    from agentx_sdk.cli import execute_demo
    execute_demo()
    out = capsys.readouterr().out
    assert "BLOCKED before execution" in out
    assert "agentx-mcp" in out                   # the one-line wrap is the lead next step
    assert "Cursor" in out                        # named to the detected client
    assert "protection streak grows" in out       # the return hook
    assert "def your_tool" not in out             # decorator snippet is NOT the lead here


def test_detect_mcp_client_finds_config_and_returns_none_when_absent(tmp_path, monkeypatch):
    """The detector reports a client when a known config exists and None otherwise, cheaply
    and without raising."""
    from agentx_sdk.cli import _detect_mcp_client
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))          # isolate ~ probes
    monkeypatch.setenv("USERPROFILE", str(tmp_path))   # Windows ~
    monkeypatch.delenv("APPDATA", raising=False)
    assert _detect_mcp_client() is None
    cur = tmp_path / ".cursor"
    cur.mkdir()
    (cur / "mcp.json").write_text("{}")
    name, hint = _detect_mcp_client()
    assert name == "Cursor"


# =============================================================================
# agentx share  (shareable block card)
# =============================================================================

from agentx_sdk.cli import (_render_block_card, _share_draft, _block_attack_phrase,
                            _cell_width, execute_share)

_BLOCK = {
    "timestamp": 1750000000.0,
    "agent_id": "demo_cli",
    "tool_name": "run_sql",
    # Real built-in destructive-floor policy id, so the category->phrase map
    # resolves exactly as it does for a `agentx demo` block.
    "policy_id": "11111111-1111-1111-1111-111111111101",
    "policy_name": "Mass Destructive Intent",
    "status": "CHALLENGED",
    "tokens_saved": 1500,
    "time_saved_mins": 5,
}


def test_render_card_is_bordered_and_aligned():
    card = _render_block_card(_BLOCK)
    lines = card.splitlines()
    assert lines[0].startswith("┌") and lines[0].endswith("┐")
    assert lines[-1].startswith("└") and lines[-1].endswith("┘")
    # Every interior line is the SAME display width between the borders.
    widths = {_cell_width(ln[1:-1]) for ln in lines[1:-1]}
    assert len(widths) == 1


def test_render_card_shows_policy_tool_verdict():
    card = _render_block_card(_BLOCK)
    assert "Mass Destructive Intent" in card
    assert "run_sql()" in card
    assert "BLOCKED before it ran" in card


def test_render_card_never_leaks_a_payload():
    # The card is built from abstract fields only — a tool name yes, a query never.
    card = _render_block_card(_BLOCK)
    assert "DROP TABLE" not in card.upper()


def test_render_card_optional_note_is_shown():
    card = _render_block_card(_BLOCK, note="DROP TABLE users;")
    assert "DROP TABLE users;" in card
    assert "attempt:" in card


def test_render_card_long_value_stays_inside_border():
    # A long --note (or a long pulled policy name) must not blow out the right
    # border — the card is meant to be screenshot-clean.
    long_note = "DROP TABLE users; DELETE FROM customers WHERE 1=1; -- the whole pasted thing"
    card = _render_block_card(_BLOCK, note=long_note)
    lines = card.splitlines()
    widths = {_cell_width(ln[1:-1]) for ln in lines[1:-1]}
    assert len(widths) == 1                       # every interior line same width
    assert "…" in card                             # the overflow was clipped
    assert not any(_cell_width(ln) > _cell_width(lines[0]) for ln in lines)


def test_render_card_recovered_verdict():
    card = _render_block_card({**_BLOCK, "status": "RECOVERED"})
    assert "self-corrected" in card


def test_share_draft_matches_category_and_claim():
    draft = _share_draft(_BLOCK)
    assert "destructive database write" in draft
    assert "blocked it before it executed" in draft.lower()


def test_share_draft_recovered_claim():
    draft = _share_draft({**_BLOCK, "status": "RECOVERED"})
    assert "coached the agent" in draft.lower()


def test_block_attack_phrase_falls_back_to_policy_name():
    phrase = _block_attack_phrase({"policy_id": "UNKNOWN", "policy_name": "Weird Policy"})
    assert "Weird Policy" in phrase


def test_help_shows_decorate_next_step(capsys):
    # The most-common external install runs `agentx demo` and stops; `help` must
    # show how to wrap their OWN tool and handle a block, or they never take the
    # next step. Lock the guidance so it can't silently drop.
    from agentx_sdk.cli import _print_cli_usage
    _print_cli_usage()
    out = capsys.readouterr().out
    assert "@agentx_protect" in out
    assert "is_block" in out
    assert "out.challenge" in out          # the coach-and-retry next step
    assert "receipt_id" in out


def test_unknown_command_exits_nonzero(capsys, monkeypatch):
    # A typo'd command must fail loudly (exit 2), not silently succeed with exit 0, so
    # a script / CI catches it. Drives the real main() dispatch.
    monkeypatch.setenv("AGENTX_MODE", "local")
    monkeypatch.setattr("sys.argv", ["agentx", "frobnicate"])
    from agentx_sdk.cli import main
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert "Unknown command" in capsys.readouterr().out


def test_execute_share_no_block_routes_to_demo(capsys):
    with patch("agentx_sdk.db.get_recent_blocks", return_value=[]):
        execute_share([])
    out = capsys.readouterr().out
    assert "agentx demo" in out
    assert "nothing to share" in out.lower()


def test_execute_share_renders_card_and_draft(capsys):
    with patch("agentx_sdk.db.get_recent_blocks", return_value=[_BLOCK]):
        execute_share([])
    out = capsys.readouterr().out
    assert "Mass Destructive Intent" in out
    assert "utm_source=cli_share" in out
    assert "show-your-agent-app" in out
    assert "intent/tweet" in out


def test_execute_share_passes_note_through(capsys):
    with patch("agentx_sdk.db.get_recent_blocks", return_value=[_BLOCK]):
        execute_share(["--note", "DROP TABLE users;"])
    out = capsys.readouterr().out
    assert "DROP TABLE users;" in out


def test_execute_share_rejects_unknown_flag(capsys):
    with patch("agentx_sdk.db.get_recent_blocks", return_value=[_BLOCK]):
        with pytest.raises(SystemExit):
            execute_share(["--bogus"])
