"""Offline staleness notice: the only channel that reaches a PINNED install.

pip has no concept of "minimum version of myself", so an already-installed old SDK
never moves on its own. The build therefore nags itself once it is old enough. These
tests guard the two things that make that promise real:

  1. GATING   — it fires only when genuinely stale, never in CI, never on a bad constant.
  2. REACH    — it actually appears on BOTH session-end surfaces. A notice wired only
                into the decorator's atexit summary would reach ZERO agentx-mcp users,
                because `agentx-mcp` suppresses that summary and prints its own report.
                That is the exact failure the #201 post-mortem named: the tests asserted
                the mechanism, never that it reached the path the user is actually on.

Plus a cross-surface tripwire: both surfaces must render the SAME phrase from the SAME
shared helper, so the wording cannot drift (see pulse.format_protection_line for the
same discipline).
"""
import io
import sys
from datetime import date, timedelta

import pytest

import agentx_sdk
from agentx_sdk import decorators, mcp_proxy, pulse


# --------------------------------------------------------------------------
# 1. GATING
# --------------------------------------------------------------------------

def test_build_age_days_counts_days_since_release():
    assert pulse.build_age_days(released="2026-01-01", today=date(2026, 4, 1)) == 90


def test_build_age_days_is_none_on_an_unparseable_constant():
    """A bad constant must produce NO notice, never a guessed age. (``released=None`` is
    NOT junk: it is the documented sentinel for 'read the real __released__'.)"""
    for junk in ("", "yesterday", "2026-13-99", "07/11/2026", []):
        assert pulse.build_age_days(released=junk, today=date(2026, 7, 11)) is None


def test_build_age_days_clamps_a_future_release_to_zero():
    """A skewed clock must not produce a negative age (which would read as fresh anyway,
    but a negative day count in the phrase would be a visible bug)."""
    assert pulse.build_age_days(released="2026-12-01", today=date(2026, 7, 11)) == 0


def test_notice_is_silent_for_a_fresh_build(monkeypatch):
    monkeypatch.setattr(pulse, "is_automation_context", lambda: False)
    fresh = date.fromisoformat(agentx_sdk.__released__)
    assert pulse.staleness_notice(today=fresh) is None


def test_notice_is_silent_one_day_before_the_threshold(monkeypatch):
    monkeypatch.setattr(pulse, "is_automation_context", lambda: False)
    cut = date(2026, 1, 1)
    assert pulse.staleness_notice(
        released=cut.isoformat(),
        today=cut + timedelta(days=pulse._STALE_AFTER_DAYS - 1),
    ) is None


def test_notice_fires_at_the_threshold_and_names_the_age_and_version(monkeypatch):
    monkeypatch.setattr(pulse, "is_automation_context", lambda: False)
    cut = date(2026, 1, 1)
    line = pulse.staleness_notice(
        released=cut.isoformat(),
        today=cut + timedelta(days=pulse._STALE_AFTER_DAYS),
    )
    assert line is not None
    assert str(pulse._STALE_AFTER_DAYS) in line
    assert agentx_sdk.__version__ in line
    assert "security" in line


def test_notice_self_gates_in_automation():
    """Runs under pytest, so is_automation_context() is True and NOTHING is patched:
    a stale build must still stay quiet inside someone's test matrix / CI."""
    assert pulse.is_automation_context() is True
    assert pulse.staleness_notice(released="2020-01-01") is None


def test_notice_makes_no_network_call(monkeypatch):
    """It is an OFFLINE notice by design. If anyone ever 'improves' it into a PyPI
    lookup, this goes red: a security SDK must not grow a new outbound destination
    (and it must keep working airgapped, and for a developer who opted out of the pulse)."""
    def _boom(*a, **kw):
        raise AssertionError("staleness_notice must not make a network call")

    monkeypatch.setattr(pulse.urllib.request, "urlopen", _boom)
    monkeypatch.setattr(pulse, "is_automation_context", lambda: False)
    assert pulse.staleness_notice(released="2020-01-01") is not None


# --------------------------------------------------------------------------
# 2. REACH — it must appear on BOTH session-end surfaces
# --------------------------------------------------------------------------

_FAKE = "this build is 214 days old (9.9.9) and newer releases may carry security fixes"


@pytest.fixture
def stale(monkeypatch):
    """Force a stale verdict WITHOUT un-gating automation. Un-gating it globally would
    let record_protection / on_session_end fire real pulse I/O from a test run."""
    monkeypatch.setattr(pulse, "staleness_notice", lambda *a, **kw: _FAKE)
    return _FAKE


def test_mcp_report_emits_the_notice_on_stderr(stale, capsys):
    """agentx-mcp is the surface a notice is most likely to MISS: it suppresses the
    decorator's atexit summary, so it needs its own emit."""
    log = io.StringIO()
    mcp_proxy._protection_report({"total_calls": 1}, log)

    written = log.getvalue()
    assert _FAKE in written
    assert pulse.UPGRADE_COMMAND in written


def test_mcp_notice_never_touches_stdout(stale, capsys):
    """MCP speaks JSON-RPC over stdout. A human banner there corrupts the stream and
    breaks the user's agent, so the notice MUST go to the log stream (stderr)."""
    log = io.StringIO()
    mcp_proxy._protection_report({"total_calls": 1}, log)

    assert capsys.readouterr().out == ""


def test_mcp_report_stays_silent_when_it_screened_nothing(stale):
    """An idle proxy prints no report at all, so it must not print a nag either."""
    log = io.StringIO()
    mcp_proxy._protection_report({"total_calls": 0}, log)
    assert log.getvalue() == ""


def test_cli_emits_the_notice(stale, capsys, monkeypatch):
    """Third surface. A CLI-only user never makes a protected tool call, so the
    decorator summary never runs: without this emit they would NEVER be nagged, which
    is perverse, since the CLI is interactive and the remedy is a shell command."""
    from agentx_sdk import cli

    monkeypatch.setattr(sys, "argv", ["agentx", "status"])
    monkeypatch.setattr(cli, "execute_status_inspection", lambda *a, **kw: None)

    cli.main()

    out = capsys.readouterr().out
    assert _FAKE in out
    assert pulse.UPGRADE_COMMAND in out


def test_quiet_path_stays_silent_so_mcp_stdout_is_never_polluted(stale, capsys, monkeypatch):
    """The atexit-quiet branch is shared by `agentx demo` AND the MCP proxy (both call
    suppress_atexit_summary). Emitting the notice there would print a human banner to
    STDOUT inside an MCP session, corrupting the JSON-RPC stream and breaking the user's
    agent, and would double-print for MCP (which already emits on stderr). The demo is
    covered by the CLI emit instead. Red if anyone ever 'helpfully' adds it here.
    """
    monkeypatch.setattr(decorators, "_atexit_summary_quiet", True, raising=False)
    monkeypatch.setattr(decorators, "_protection_recorded", True, raising=False)
    monkeypatch.setitem(decorators._session_stats, "total_calls", 1)

    decorators._print_agentx_summary()

    assert _FAKE not in capsys.readouterr().out


def test_decorator_summary_emits_the_notice(stale, capsys, monkeypatch):
    monkeypatch.setattr(decorators, "_protection_recorded", True, raising=False)
    monkeypatch.setitem(decorators._session_stats, "total_calls", 1)

    decorators._print_agentx_summary()

    out = capsys.readouterr().out
    assert _FAKE in out
    assert pulse.UPGRADE_COMMAND in out


# --------------------------------------------------------------------------
# 3. TRIPWIRES
# --------------------------------------------------------------------------

def test_released_constant_is_a_real_date_and_not_in_the_future():
    """__released__ is hand-maintained alongside __version__ (BACKLOG C12). If it is
    garbage, build_age_days returns None and the notice silently NEVER fires — the
    failure mode is invisible, so pin it here."""
    released = date.fromisoformat(agentx_sdk.__released__)
    assert released <= date.today(), "__released__ is in the future"


def test_both_surfaces_render_the_identical_phrase(monkeypatch, capsys):
    """Cross-surface invariant: the decorator summary and the agentx-mcp report must
    show the SAME wording, from the SAME shared helper. Red the moment either surface
    hardcodes its own copy of the phrase or the upgrade command.

    NOTE the phrase is injected rather than un-gating is_automation_context: that gate
    also guards the real pulse send at decorators.py:867, so faking it here would make
    the test suite transmit live telemetry and pollute the activation funnel.
    """
    phrase = pulse.format_staleness_line(214, agentx_sdk.__version__)
    monkeypatch.setattr(pulse, "staleness_notice", lambda *a, **kw: phrase)
    monkeypatch.setattr(decorators, "_protection_recorded", True, raising=False)
    monkeypatch.setitem(decorators._session_stats, "total_calls", 1)

    log = io.StringIO()
    mcp_proxy._protection_report({"total_calls": 1}, log)
    decorators._print_agentx_summary()
    decorator_out = capsys.readouterr().out

    for surface in (log.getvalue(), decorator_out):
        assert phrase in surface
        assert pulse.UPGRADE_COMMAND in surface
