import sqlite3
import time
import os

# Hidden file in the directory where the developer runs their agent
DB_PATH = ".agentx.db"

import sqlite3
import time
import os
from contextlib import contextmanager

DB_PATH = ".agentx.db"

# Concurrency: agents sharing one process each open their own short-lived
# connection (no shared cursor), but concurrent WRITERS still serialize at the
# SQLite file lock. Without a busy timeout the second writer raises
# "database is locked" immediately; `timeout`/`busy_timeout` makes SQLite wait
# for the lock instead. Telemetry must never break a tool call, so the writers
# (log_intercept / log_self_correction) are ALSO wrapped best-effort below.
_BUSY_TIMEOUT_MS = 5000

# The AUDIT-posture ledger status. Written by BOTH keyless surfaces (the decorator's
# _audit_and_proceed and the agentx-mcp proxy) and read by get_would_block_summary, so
# the one literal that couples those three sites lives here instead of drifting as a bare
# string. Distinct from the CHALLENGED / RECOVERED episode statuses on purpose: the block
# and recovery readers filter those, so a WOULD_BLOCK row never inflates the recovery rate.
WOULD_BLOCK_STATUS = "WOULD_BLOCK"


def _connect(path=None):
    """Open a connection with a busy timeout so concurrent in-process writers
    wait for the file lock rather than raising 'database is locked'. `path`
    defaults to the module DB_PATH; pass one to read a specific ledger file."""
    conn = sqlite3.connect(path or DB_PATH, timeout=_BUSY_TIMEOUT_MS / 1000.0)
    try:
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    except sqlite3.Error:
        pass
    return conn


@contextmanager
def _connection(path=None):
    """Connection context manager that ALWAYS closes — even if the body raises —
    so no call site can leak the handle/lock under the contention this guard is
    meant to ease. Use as ``with _connection() as conn:``. Opening (with the busy
    timeout) is delegated to _connect; a failure to open propagates with nothing
    to close. This is the single home for connection cleanup — callers never
    hand-roll close()/finally, so the leak can't reappear one function at a time."""
    conn = _connect(path)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db():
    """Initializes the V2.1 SQLite database and performs an Alpha Wipe if legacy schema is detected."""
    legacy_detected = False
    
    # 1. Detect Legacy Schema
    if os.path.exists(DB_PATH):
        try:
            with _connection() as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(event_log)")
                columns = [col[1] for col in cursor.fetchall()]

                # If the table exists but doesn't have our new columns, it's legacy.
                if len(columns) > 0 and ('policy_id' not in columns or 'trace_id' not in columns):
                    legacy_detected = True
        except sqlite3.Error:
            pass

    # 2. The Safe Alpha Wipe
    if legacy_detected:
        print("\n🔄 [AgentX SDK] Legacy telemetry detected. Performing Alpha Wipe for schema upgrade...")
        try:
            os.remove(DB_PATH)
            print("✅ [AgentX SDK] Clean slate! Schema synced with trace_id and agent_id requirements.")
        except PermissionError:
            print("⚠️ [AgentX SDK] Windows file lock prevented DB wipe. Please delete '.agentx.db' manually.")

    # 3. Create the New V2.1 Schema (added trace_id and agent_id)
    with _connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                trace_id TEXT,      -- FIXED: Added in V2.1
                agent_id TEXT,      -- FIXED: Added in V2.1
                tool_name TEXT,
                policy_id TEXT,     -- NEW: Strict Alphanumeric ID (e.g., POL-SEC-001)
                policy_name TEXT,   -- Kept strictly for the CLI UI display
                status TEXT,
                tokens_saved INTEGER,
                time_saved_mins INTEGER
            )
        ''')
        conn.commit()

# Update your log_intercept function signature to accept the new ID!
# FIXED: Signature updated to accept trace_id and agent_id
def log_intercept(trace_id, agent_id, tool_name, policy_id, policy_name, status, tokens=1500, time_saved=5):
    # Best-effort: this runs on the online-block path OUTSIDE the wrapper's other
    # guards, so a transient SQLite lock (concurrent in-process writers) must not
    # propagate and break the tool call. The block itself already stood regardless.
    # _connection() guarantees the handle is closed even when the write raises.
    try:
        with _connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO event_log (timestamp, trace_id, agent_id, tool_name, policy_id, policy_name, status, tokens_saved, time_saved_mins)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (time.time(), trace_id, agent_id, tool_name, policy_id, policy_name, status, tokens, time_saved))
            conn.commit()
    except Exception:
        pass

def get_lifetime_stats():
    """Calculates cumulative stats and identifies the Top Offender using V2 Schema."""
    if not os.path.exists(DB_PATH):
        return None

    with _connection() as conn:
        cursor = conn.cursor()

        # A "challenge episode" is any row that was ever a challenge — still-open
        # (CHALLENGED) or self-corrected (RECOVERED, flipped in place by
        # log_self_correction). Recovered episodes MUST stay in the denominator,
        # otherwise total_self_corrections / total_intercepts can exceed 100%. This
        # mirrors the dashboard's per-session model (recovered is a subset of
        # challenged). ALLOWED/other rows never participate.
        CHALLENGE_EPISODE = "status IN ('CHALLENGED', 'RECOVERED')"

        # 1. Total challenge episodes (still-open + recovered)
        cursor.execute(f"SELECT COUNT(*) FROM event_log WHERE {CHALLENGE_EPISODE}")
        total_intercepts = cursor.fetchone()[0] or 0

        # 2. Critical Blocks (Updated to use policy_name)
        cursor.execute(f"SELECT COUNT(*) FROM event_log WHERE {CHALLENGE_EPISODE} AND policy_name IN ('Mass Destructive Intent', 'Database Isolation')")
        total_critical = cursor.fetchone()[0] or 0

        # 3. Total Self-Corrections (recovered episodes — the recovery numerator)
        cursor.execute("SELECT COUNT(*) FROM event_log WHERE status = 'RECOVERED'")
        total_recoveries = cursor.fetchone()[0] or 0

        # 4. Sum of Tokens and Time across all challenge episodes
        cursor.execute(f"SELECT SUM(tokens_saved), SUM(time_saved_mins) FROM event_log WHERE {CHALLENGE_EPISODE}")
        row = cursor.fetchone()
        total_tokens = row[0] or 0
        total_time = row[1] or 0

        # 5. Top Offender (Select policy_name, Group by policy_id)
        cursor.execute(f'''
            SELECT policy_name, COUNT(*) as c
            FROM event_log
            WHERE {CHALLENGE_EPISODE}
            GROUP BY policy_id
            ORDER BY c DESC LIMIT 1
        ''')
        top_offender_row = cursor.fetchone()
        top_offender = top_offender_row[0] if top_offender_row else None

    return {
        "total_intercepts": total_intercepts,
        "total_critical": total_critical,
        "total_tokens": int(total_tokens),
        "total_time": int(total_time),
        "top_offender": top_offender_row[0] if top_offender_row else "None",
        "total_self_corrections": total_recoveries # <--- ADDED THIS
    }
    
def get_recent_blocks(limit=1):
    """Return the most recent block episodes from the local ledger, newest first.

    Powers `agentx share`: the shareable block card is built ONLY from these
    abstract, privacy-safe fields (policy class, the dev's own tool name, the
    verdict, when, and the saved tokens/time) — never a raw query or payload,
    because the ledger never stores one. A still-open block reads CHALLENGED; one
    the agent recovered from reads RECOVERED. ALLOWED/other rows are excluded so
    `share` only ever surfaces an actual catch. Returns [] when there's no DB or
    no block yet (the caller routes the dev to `agentx demo`)."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        with _connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT timestamp, trace_id, agent_id, tool_name, policy_id,
                       policy_name, status, tokens_saved, time_saved_mins
                FROM event_log
                WHERE status IN ('CHALLENGED', 'RECOVERED')
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
            cols = [c[0] for c in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except Exception:
        return []


def log_self_correction(trace_id, agent_id, tool_name):
    """
    Surgically updates the status of the active challenged intercept to RECOVERED.
    Ensures get_lifetime_stats() compiles clean cumulative recovery rates without network overhead.
    """
    if not os.path.exists(DB_PATH):
        return
    # Best-effort: a transient SQLite error must not propagate; _connection()
    # guarantees the handle is closed even when the write raises.
    try:
        with _connection() as conn:
            cursor = conn.cursor()

            # 🛡️ ARCHITECTURAL CORRECTION:
            # Update the status of the row that was blocked on Turn 1 of this specific trace.
            # This prevents orphaned rows and keeps cumulative metrics mathematically accurate.
            cursor.execute('''
                UPDATE event_log
                SET status = 'RECOVERED'
                WHERE id = (
                    SELECT id FROM event_log
                    WHERE trace_id = ? AND tool_name = ? AND status = 'CHALLENGED'
                    ORDER BY id DESC LIMIT 1
                )
            ''', (trace_id, tool_name))

            # Flip exactly ONE row -- the most-recent open CHALLENGED row for this
            # (trace, tool) -- so one recovery EPISODE flips one ledger row. An unbounded
            # UPDATE flipped EVERY matching CHALLENGED row, inflating cumulative recoveries
            # when the same tool was blocked several times on one trace (code review).
            # (Removed 2026-07) The old "backstop" INSERT that wrote a fresh RECOVERED row
            # when no CHALLENGED row matched is gone too: it fabricated an ORPHAN recovery
            # on a cross-tool safe call, inflating the numerator. The in-memory (trace, tool)
            # credit gate (_credit_recovery) is authoritative and same-tool-scoped, so this
            # UPDATE flips the one real row for this episode or nothing. Under-recording a
            # rare row whose CHALLENGED write was lost beats fabricating one.
            conn.commit()
    except Exception:
        pass


def _grouped_policy_rows(path, status_clause, exclude_agents, extra_select=""):
    """Shared 'GROUP BY policy, count rows' aggregation over the ledger for a given status
    filter, so the ledger readers (get_block_frequency / get_would_block_summary) don't each
    hand-roll the exclude-agent clause + connection scaffold (the drift the two-copy version
    risked: a future 'also drop test-artifact agents' change would have to edit both). The
    caller shapes its own dict from the rows and maps a None return to its own empty value.

    status_clause: a trusted WHERE fragment on `status` (built from module constants, never
    user input). extra_select: an optional extra aggregate column appended to the SELECT
    (e.g. the recoveries SUM). Returns rows (policy_name, policy_id, COUNT(*)[, *extra])
    ordered count-DESC then policy_name-ASC, or None on missing-db / error."""
    p = path or DB_PATH
    if not os.path.exists(p):
        return None
    excluded = [a for a in (exclude_agents or []) if a]
    clause = status_clause
    params = []
    if excluded:
        clause += " AND agent_id NOT IN (%s)" % ",".join("?" for _ in excluded)
        params.extend(excluded)
    sel_extra = (", " + extra_select) if extra_select else ""
    try:
        with _connection(p) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT policy_name,
                       MAX(policy_id) AS policy_id,
                       COUNT(*) AS n{sel_extra}
                FROM event_log
                WHERE {clause}
                GROUP BY policy_name
                ORDER BY n DESC, policy_name ASC
                """,
                params,
            )
            return cursor.fetchall()
    except Exception:
        return None


def get_block_frequency(path=None, exclude_agents=None):
    """Rank the local flight-recorder ledger BY POLICY: how often each policy fired
    and how often the agent recovered from it. Aggregates BOTH the decorator and the
    MCP-proxy paths (they write the same event_log with distinct agent_ids). This is
    the local, privacy-safe harvest that grows the moat/insights view
    (scripts/ledger_insights.py) and the frequency-ranked playground order.

    A "block" is a challenge episode (still-open CHALLENGED or self-corrected
    RECOVERED); a "recovery" is a RECOVERED row; recovery_rate = recoveries / blocks.
    Privacy-safe by construction: the ledger stores only the policy class, the dev's
    own tool name, and the verdict — never a raw query or payload.

    path: read a specific ledger file (default: the module DB_PATH in the CWD).
    exclude_agents: iterable of agent_id values to drop (e.g. synthetic 'demo_cli' or
    test agents) so a representative order is not skewed by demo/test traffic.

    Returns a list of {policy_id, policy_name, blocks, recoveries, recovery_rate}
    dicts, most-frequent first; [] when there is no DB, an error, or no blocks.
    """
    rows = _grouped_policy_rows(
        path, "status IN ('CHALLENGED', 'RECOVERED')", exclude_agents,
        extra_select="SUM(CASE WHEN status = 'RECOVERED' THEN 1 ELSE 0 END)")
    if rows is None:
        return []
    out = []
    for policy_name, policy_id, blocks, recoveries in rows:
        blocks = blocks or 0
        recoveries = recoveries or 0
        out.append({
            "policy_id": policy_id,
            "policy_name": policy_name,
            "blocks": blocks,
            "recoveries": recoveries,
            "recovery_rate": round(recoveries / blocks, 3) if blocks else 0.0,
        })
    return out


def get_would_block_summary(path=None, exclude_agents=None):
    """Aggregate the AUDIT-posture ledger: how many times each policy WOULD have blocked
    while running under AGENTX_ENFORCEMENT=audit (status WOULD_BLOCK), most-frequent first.

    This is the report that earns the enforce decision: a developer runs AgentX
    non-blocking in staging for a week, then `agentx insights` shows exactly what audit
    would have caught, per policy, with zero risk taken. Kept STRICTLY separate from
    get_block_frequency / get_lifetime_stats (which count only real CHALLENGED /
    RECOVERED episodes) so an audited catch never inflates the recovery rate or the
    'agents protected' metric — an audit install is evaluating, not yet protected.

    Privacy-safe by construction (same as the block ledger): only the policy class, the
    dev's own tool name, and the verdict are stored, never a raw query or payload.

    path: read a specific ledger file (default: the module DB_PATH in the CWD).
    exclude_agents: iterable of agent_id values to drop.

    Returns {"total": int, "policies": [{policy_id, policy_name, would_blocks}, ...]};
    total is 0 (policies []) when there is no DB, an error, or no audited catch yet.
    """
    rows = _grouped_policy_rows(path, f"status = '{WOULD_BLOCK_STATUS}'", exclude_agents)
    if rows is None:
        return {"total": 0, "policies": []}
    policies = [
        {"policy_id": pid, "policy_name": pname, "would_blocks": wb or 0}
        for pname, pid, wb in rows
    ]
    return {"total": sum(row["would_blocks"] for row in policies), "policies": policies}