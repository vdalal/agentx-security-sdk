import os
import sqlite3
import time
import pytest

import agentx_sdk.db as db_module
from agentx_sdk.db import (init_db, log_intercept, get_lifetime_stats,
                           log_self_correction, get_recent_blocks, get_block_frequency, _connect)


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect all db operations to a temp file so tests never touch .agentx.db."""
    db_path = str(tmp_path / ".agentx_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    yield db_path


def _columns(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(event_log)")
    cols = [row[1] for row in cursor.fetchall()]
    conn.close()
    return cols


# =============================================================================
# init_db
# =============================================================================

def test_init_db_creates_v21_schema(isolated_db):
    init_db()
    cols = set(_columns(isolated_db))
    expected = {"id", "timestamp", "trace_id", "agent_id", "tool_name",
                "policy_id", "policy_name", "status", "tokens_saved", "time_saved_mins"}
    assert expected.issubset(cols)


def test_init_db_is_idempotent(isolated_db):
    init_db()
    init_db()
    conn = sqlite3.connect(isolated_db)
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    conn.close()
    assert len([t for t in tables if t[0] == "event_log"]) == 1


def test_init_db_legacy_wipe_upgrades_schema(isolated_db):
    # Simulate a legacy DB: table exists but missing policy_id and trace_id
    conn = sqlite3.connect(isolated_db)
    conn.execute("CREATE TABLE event_log (id INTEGER PRIMARY KEY, tool_name TEXT, status TEXT)")
    conn.execute("INSERT INTO event_log (tool_name, status) VALUES ('old_tool', 'CHALLENGED')")
    conn.commit()
    conn.close()

    init_db()

    cols = _columns(isolated_db)
    assert "trace_id" in cols
    assert "policy_id" in cols

    # Old data should be gone after the wipe
    conn = sqlite3.connect(isolated_db)
    count = conn.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
    conn.close()
    assert count == 0


def test_init_db_partial_legacy_triggers_wipe(isolated_db):
    # Table has trace_id but is missing policy_id — still legacy
    conn = sqlite3.connect(isolated_db)
    conn.execute("CREATE TABLE event_log (id INTEGER PRIMARY KEY, trace_id TEXT, status TEXT)")
    conn.commit()
    conn.close()

    init_db()

    cols = _columns(isolated_db)
    assert "policy_id" in cols


# =============================================================================
# Concurrency hardening (F3): busy timeout + best-effort writer
# =============================================================================

def test_connect_sets_busy_timeout(isolated_db):
    """Connections carry a busy timeout so concurrent in-process writers wait for
    the file lock instead of raising 'database is locked' immediately."""
    conn = _connect()
    busy = conn.execute("PRAGMA busy_timeout").fetchone()[0]
    conn.close()
    assert busy == db_module._BUSY_TIMEOUT_MS
    assert busy > 0


def test_log_intercept_swallows_db_errors(isolated_db, monkeypatch):
    """A transient SQLite failure on the online-block path must NOT propagate and
    break the protected tool call — log_intercept is best-effort."""
    init_db()

    def _boom(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db_module, "_connect", _boom)
    # Must not raise even though the connection fails.
    log_intercept("t", "a", "tool", "P1", "Policy", "CHALLENGED")


def test_connection_context_manager_closes_on_success(isolated_db):
    """`with _connection() as conn:` closes the handle on normal exit."""
    init_db()
    with db_module._connection() as conn:
        conn.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")  # operating on a closed connection raises


def test_connection_context_manager_closes_on_exception(isolated_db):
    """The connection is closed even when the body raises — the centralized fix
    for the leak found across log_intercept / log_self_correction / get_lifetime_stats."""
    init_db()
    captured = {}
    with pytest.raises(ValueError):
        with db_module._connection() as conn:
            captured["conn"] = conn
            raise ValueError("boom")
    with pytest.raises(sqlite3.ProgrammingError):
        captured["conn"].execute("SELECT 1")  # closed despite the exception


# =============================================================================
# log_intercept
# =============================================================================

def test_log_intercept_stores_all_fields(isolated_db):
    init_db()
    log_intercept(
        trace_id="trace-001",
        agent_id="test-agent",
        tool_name="run_query",
        policy_id="POL-001",
        policy_name="Mass Destructive Intent",
        status="CHALLENGED",
        tokens=1500,
        time_saved=5,
    )
    conn = sqlite3.connect(isolated_db)
    row = conn.execute(
        "SELECT trace_id, agent_id, tool_name, policy_id, policy_name, status, tokens_saved, time_saved_mins "
        "FROM event_log"
    ).fetchone()
    conn.close()
    assert row == ("trace-001", "test-agent", "run_query", "POL-001",
                   "Mass Destructive Intent", "CHALLENGED", 1500, 5)


def test_log_intercept_default_tokens_and_time(isolated_db):
    init_db()
    log_intercept("t", "a", "tool", "P1", "Policy", "CHALLENGED")
    conn = sqlite3.connect(isolated_db)
    row = conn.execute("SELECT tokens_saved, time_saved_mins FROM event_log").fetchone()
    conn.close()
    assert row == (1500, 5)


def test_log_intercept_sets_timestamp(isolated_db):
    init_db()
    before = time.time()
    log_intercept("t", "a", "tool", "P1", "Policy", "CHALLENGED")
    after = time.time()
    conn = sqlite3.connect(isolated_db)
    ts = conn.execute("SELECT timestamp FROM event_log").fetchone()[0]
    conn.close()
    assert before <= ts <= after


# =============================================================================
# get_lifetime_stats
# =============================================================================

def test_get_lifetime_stats_returns_none_when_no_db(isolated_db):
    # DB file was never created
    assert get_lifetime_stats() is None


def test_get_lifetime_stats_zeros_on_empty_db(isolated_db):
    init_db()
    result = get_lifetime_stats()
    assert result["total_intercepts"] == 0
    assert result["total_critical"] == 0
    assert result["total_tokens"] == 0
    assert result["total_time"] == 0
    assert result["total_self_corrections"] == 0
    assert result["top_offender"] == "None"


def test_get_lifetime_stats_counts_challenge_episodes(isolated_db):
    # A challenge episode = CHALLENGED (still open) OR RECOVERED (self-corrected).
    # Recovered rows MUST stay counted so the recovery rate can't exceed 100%.
    # ALLOWED rows never participate.
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Policy A", "CHALLENGED")
    log_intercept("t2", "a", "tool", "P1", "Policy A", "CHALLENGED")
    log_intercept("t3", "a", "tool", "P2", "Policy B", "ALLOWED")
    log_intercept("t4", "a", "tool", "P3", "Policy C", "RECOVERED")
    result = get_lifetime_stats()
    assert result["total_intercepts"] == 3  # 2 CHALLENGED + 1 RECOVERED, ALLOWED excluded


def test_get_lifetime_stats_critical_policy_filter(isolated_db):
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Mass Destructive Intent", "CHALLENGED")
    log_intercept("t2", "a", "tool", "P2", "Database Isolation", "CHALLENGED")
    log_intercept("t3", "a", "tool", "P3", "Customer Privacy Shield", "CHALLENGED")
    result = get_lifetime_stats()
    # Only "Mass Destructive Intent" and "Database Isolation" count as critical
    assert result["total_critical"] == 2


def test_get_lifetime_stats_token_and_time_sums(isolated_db):
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Policy A", "CHALLENGED", tokens=1000, time_saved=3)
    log_intercept("t2", "a", "tool", "P1", "Policy A", "CHALLENGED", tokens=2500, time_saved=7)
    log_intercept("t3", "a", "tool", "P2", "Policy B", "ALLOWED", tokens=9999, time_saved=99)
    result = get_lifetime_stats()
    # Only challenge episodes (CHALLENGED/RECOVERED) contribute; ALLOWED is excluded
    assert result["total_tokens"] == 3500
    assert result["total_time"] == 10


def test_get_lifetime_stats_top_offender_by_frequency(isolated_db):
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Mass Destructive Intent", "CHALLENGED")
    log_intercept("t2", "a", "tool", "P1", "Mass Destructive Intent", "CHALLENGED")
    log_intercept("t3", "a", "tool", "P2", "Customer Privacy Shield", "CHALLENGED")
    result = get_lifetime_stats()
    assert result["top_offender"] == "Mass Destructive Intent"


def test_get_lifetime_stats_recovery_count(isolated_db):
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Policy A", "RECOVERED")
    log_intercept("t2", "a", "tool", "P1", "Policy A", "RECOVERED")
    log_intercept("t3", "a", "tool", "P1", "Policy A", "CHALLENGED")
    result = get_lifetime_stats()
    assert result["total_self_corrections"] == 2


# =============================================================================
# log_self_correction
# =============================================================================

def test_log_self_correction_safe_when_no_db(isolated_db):
    log_self_correction("trace-001", "agent", "tool")  # must not raise


def test_log_self_correction_updates_challenged_to_recovered(isolated_db):
    init_db()
    log_intercept("trace-001", "agent", "run_query", "P1", "Policy A", "CHALLENGED")
    log_self_correction("trace-001", "agent", "run_query")
    conn = sqlite3.connect(isolated_db)
    row = conn.execute("SELECT status FROM event_log WHERE trace_id='trace-001'").fetchone()
    conn.close()
    assert row[0] == "RECOVERED"


def test_log_self_correction_only_touches_matching_rows(isolated_db):
    init_db()
    log_intercept("trace-001", "agent", "tool_a", "P1", "Policy A", "CHALLENGED")
    log_intercept("trace-002", "agent", "tool_b", "P2", "Policy B", "CHALLENGED")
    log_self_correction("trace-001", "agent", "tool_a")
    conn = sqlite3.connect(isolated_db)
    rows = {
        r[0]: r[1]
        for r in conn.execute("SELECT trace_id, status FROM event_log").fetchall()
    }
    conn.close()
    assert rows["trace-001"] == "RECOVERED"
    assert rows["trace-002"] == "CHALLENGED"  # unrelated row untouched


def test_log_self_correction_does_not_re_update_already_recovered(isolated_db):
    init_db()
    log_intercept("trace-001", "agent", "tool", "P1", "Policy A", "RECOVERED")
    # UPDATE WHERE status='CHALLENGED' should match nothing
    log_self_correction("trace-001", "agent", "tool")
    conn = sqlite3.connect(isolated_db)
    rows = conn.execute("SELECT status FROM event_log WHERE trace_id='trace-001'").fetchall()
    conn.close()
    # The original RECOVERED row plus the INSERT fallback row
    statuses = [r[0] for r in rows]
    assert all(s == "RECOVERED" for s in statuses)


def test_log_self_correction_insert_fallback_when_no_matching_row(isolated_db):
    """When no CHALLENGED row exists for the trace, a RECOVERED row is inserted as audit trail."""
    init_db()
    log_self_correction("ghost-trace", "agent", "orphaned_tool")
    conn = sqlite3.connect(isolated_db)
    row = conn.execute(
        "SELECT status, tool_name FROM event_log WHERE trace_id='ghost-trace'"
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "RECOVERED"
    assert row[1] == "orphaned_tool"


# =============================================================================
# Metrics drift — recovered rows stay in the denominator (no >100% rate)
# =============================================================================

def test_metrics_no_drift_recovered_rows_stay_in_denominator(isolated_db):
    """
    The INSERT fallback in log_self_correction can create RECOVERED rows without
    a prior CHALLENGED row. Because RECOVERED counts as a challenge episode,
    total_self_corrections can never exceed total_intercepts, so the recovery
    rate stays bounded at <=100% (the per-session fix).
    """
    init_db()
    # No prior CHALLENGED rows — two orphaned self-corrections via the INSERT fallback
    log_self_correction("ghost-1", "agent", "tool")
    log_self_correction("ghost-2", "agent", "tool")
    result = get_lifetime_stats()
    # Both RECOVERED rows count as episodes AND as self-corrections → 2/2 = 100%
    assert result["total_intercepts"] == 2
    assert result["total_self_corrections"] == 2
    assert result["total_self_corrections"] <= result["total_intercepts"]  # no drift


def test_log_self_correction_and_stats_reflect_correct_counts(isolated_db):
    """After a proper intercept→correction cycle, counts remain internally consistent."""
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Policy A", "CHALLENGED")
    log_intercept("t2", "a", "tool", "P1", "Policy A", "CHALLENGED")
    log_self_correction("t1", "a", "tool")  # flips t1 CHALLENGED → RECOVERED

    result = get_lifetime_stats()
    # t1 is now RECOVERED, t2 still CHALLENGED — both are challenge episodes, so
    # total_intercepts counts 2 and the one recovery yields a bounded 1/2 rate.
    assert result["total_intercepts"] == 2
    assert result["total_self_corrections"] == 1


# =============================================================================
# get_recent_blocks  (powers `agentx share`)
# =============================================================================

def test_get_recent_blocks_empty_when_no_db(isolated_db):
    # No init_db / no file on disk -> [] (caller routes to `agentx demo`).
    assert get_recent_blocks() == []


def test_get_recent_blocks_returns_newest_first_with_fields(isolated_db):
    init_db()
    log_intercept("t1", "agent_a", "run_sql", "POL-1", "Mass Destructive Intent", "CHALLENGED")
    log_intercept("t2", "agent_b", "fetch_url", "POL-2", "Network Sandbox (SSRF)", "CHALLENGED")
    rows = get_recent_blocks(5)
    assert len(rows) == 2
    # Newest first (t2 logged last).
    assert rows[0]["tool_name"] == "fetch_url"
    assert rows[0]["policy_name"] == "Network Sandbox (SSRF)"
    assert rows[0]["status"] == "CHALLENGED"
    # Carries the abstract fields the card needs, never a raw payload.
    assert set(rows[0]).issuperset(
        {"timestamp", "agent_id", "tool_name", "policy_id", "policy_name",
         "status", "tokens_saved", "time_saved_mins"})


def test_get_recent_blocks_limit_one_by_default(isolated_db):
    init_db()
    log_intercept("t1", "a", "tool_one", "POL-1", "P1", "CHALLENGED")
    log_intercept("t2", "a", "tool_two", "POL-2", "P2", "CHALLENGED")
    rows = get_recent_blocks()
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "tool_two"


def test_get_recent_blocks_includes_recovered_excludes_allowed(isolated_db):
    init_db()
    log_intercept("t1", "a", "run_sql", "POL-1", "Mass Destructive Intent", "CHALLENGED")
    log_self_correction("t1", "a", "run_sql")  # flips t1 -> RECOVERED
    # An ALLOWED row must never surface as a "catch".
    with _connect() as conn:
        conn.execute(
            "INSERT INTO event_log (timestamp, trace_id, agent_id, tool_name, "
            "policy_id, policy_name, status) VALUES (?,?,?,?,?,?,?)",
            (time.time(), "t9", "a", "safe_tool", "POL-X", "Benign", "ALLOWED"))
        conn.commit()
    rows = get_recent_blocks(10)
    assert {r["status"] for r in rows} == {"RECOVERED"}
    assert all(r["tool_name"] != "safe_tool" for r in rows)


# =============================================================================
# get_block_frequency  (real-usage harvest + frequency-ranked playground order)
# =============================================================================

def test_get_block_frequency_empty_when_no_db(isolated_db):
    # No file on disk -> [] (reader routes the dev to run an agent / `agentx demo`).
    assert get_block_frequency() == []


def test_get_block_frequency_ranks_by_blocks_desc(isolated_db):
    init_db()
    log_intercept("t1", "a", "run_sql", "P1", "Mass Destructive Intent", "CHALLENGED")
    log_intercept("t2", "a", "run_sql", "P1", "Mass Destructive Intent", "CHALLENGED")
    log_intercept("t3", "a", "fetch", "P2", "Network Sandbox (SSRF)", "CHALLENGED")
    rows = get_block_frequency()
    assert rows[0]["policy_name"] == "Mass Destructive Intent"
    assert rows[0]["blocks"] == 2
    assert rows[1]["policy_name"] == "Network Sandbox (SSRF)"
    assert rows[1]["blocks"] == 1


def test_get_block_frequency_counts_recoveries_and_rate(isolated_db):
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Policy A", "CHALLENGED")
    log_intercept("t2", "a", "tool", "P1", "Policy A", "CHALLENGED")
    log_self_correction("t1", "a", "tool")  # t1 CHALLENGED -> RECOVERED
    rows = get_block_frequency()
    assert len(rows) == 1
    assert rows[0]["blocks"] == 2       # both challenge episodes stay in the denominator
    assert rows[0]["recoveries"] == 1
    assert rows[0]["recovery_rate"] == 0.5


def test_get_block_frequency_excludes_allowed_rows(isolated_db):
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Policy A", "CHALLENGED")
    log_intercept("t2", "a", "safe", "P2", "Benign", "ALLOWED")
    rows = get_block_frequency()
    assert len(rows) == 1
    assert rows[0]["policy_name"] == "Policy A"


def test_get_block_frequency_excludes_named_agents(isolated_db):
    init_db()
    log_intercept("t1", "real_agent", "tool", "P1", "Policy A", "CHALLENGED")
    log_intercept("t2", "demo_cli", "tool", "P1", "Policy A", "CHALLENGED")
    log_intercept("t3", "demo_cli", "tool", "P1", "Policy A", "CHALLENGED")
    rows = get_block_frequency(exclude_agents=["demo_cli"])
    assert len(rows) == 1
    assert rows[0]["blocks"] == 1  # only the real_agent row survives the exclusion


def test_get_block_frequency_aggregates_mcp_and_decorator(isolated_db):
    # Both the decorator and the MCP proxy write the SAME event_log (distinct agent_ids).
    init_db()
    log_intercept("t1", "mcp_proxy", "tool_x", "P1", "Policy A", "CHALLENGED")
    log_intercept("t2", "my_agent", "tool_y", "P1", "Policy A", "CHALLENGED")
    rows = get_block_frequency()
    assert len(rows) == 1
    assert rows[0]["blocks"] == 2  # aggregated across both paths


def test_get_block_frequency_groups_by_policy_name_across_ids(isolated_db):
    # The ledger can carry the SAME policy_name under different policy_ids (distinct
    # code paths, or the recovery-insert token). Frequency must group by the human
    # policy NAME, not fragment by id — the report and the playground order key on
    # the name, so a split would double-list a policy and undercount it.
    init_db()
    log_intercept("t1", "a", "tool", "POL-A", "Mass Destructive Intent", "CHALLENGED")
    log_intercept("t2", "a", "tool", "POL-B", "Mass Destructive Intent", "CHALLENGED")
    rows = get_block_frequency()
    assert len(rows) == 1
    assert rows[0]["policy_name"] == "Mass Destructive Intent"
    assert rows[0]["blocks"] == 2


def test_get_block_frequency_reads_explicit_path(isolated_db):
    # The path= override reads a specific ledger file (used by scripts/ledger_insights.py --path).
    init_db()
    log_intercept("t1", "a", "tool", "P1", "Policy A", "CHALLENGED")
    rows = get_block_frequency(path=isolated_db)
    assert len(rows) == 1 and rows[0]["blocks"] == 1
