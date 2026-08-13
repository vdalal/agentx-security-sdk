import re
import sqlite3
import time
import os
from contextlib import contextmanager

# Hidden file in the directory where the developer runs their agent.
#
# RELATIVE on purpose: it resolves against the process cwd, which is what you want for the
# @agentx_protect decorator, where the process runs in the developer's project. It is the WRONG
# default for MCP, where the host launches the proxy from an arbitrary directory, so the proxy
# overrides this global at startup (see mcp_proxy._mcp_ledger_path). The default is deliberately
# left alone so no existing decorator user's ledger moves.
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

# The AUDIT-posture INVENTORY status (P-92): one row per call that PASSED, written only in
# audit mode by the same two keyless surfaces. Every other status in this ledger records a
# call we had an opinion about; this is the one that records a call we did not.
#
# 🔴 IT IS ALSO THE EVICTION KEY, WHICH IS WHY IT IS A CONSTANT AND NOT A BARE STRING.
# prune_ledger drops these BEFORE anything else (see the SIZE rule), because the inventory is
# high-volume routine traffic and the blocks are the record this product exists to keep. The
# rule is stated as "ALLOWED is evictable-first, everything else is protected" rather than as
# a list of protected statuses, so a hit status added later is protected by DEFAULT rather
# than by somebody remembering to add it here.
INVENTORY_STATUS = "ALLOWED"

# The agent ids OUR OWN scripted code writes under. They live here rather than in cli.py
# because the readers that must tell our traffic from the developer's are in this module.
#
# 🔴 A TUPLE, NOT A CONSTANT, BECAUSE THERE ARE TWO WRITERS AND THERE WAS ONLY EVER ONE RULE.
# `agentx demo` was the only thing that wrote rows we had to disown, so every reader compared
# against a single id. Then `examples/12_audit_what_your_agent_did.py` shipped, writing four
# ALLOWED rows of its own, and `agentx audit` reported them as what the DEVELOPER's agent did
# -- correct on the run itself (the example's own footer says so) and false by the next
# session, when that footer is long gone and only the ledger remains.
DEMO_AGENT_ID = "demo_cli"                      # `agentx demo` and `agentx demo --audit`
EXAMPLE_AGENT_ID = "agentx_example_agent"       # the shipped examples/ scripts
OUR_AGENT_IDS = (DEMO_AGENT_ID, EXAMPLE_AGENT_ID)


def _our_agents_clause(negate=False):
    """`agent_id IN (?,?)` / `NOT IN`, with its parameters, so every reader asks ONE question.

    🔴 THE NULL HALF IS NOT PEDANTRY, IT IS THIS FILE'S MOST-REPEATED BUG. `agent_id NOT IN
    (...)` evaluates to NULL for a row whose agent_id is NULL, and NULL is not true, so those
    rows silently vanish from the "not ours" side -- the same defect as `!= 'ALLOWED'` versus
    `IS NOT 'ALLOWED'`, which this module has already been fixed for twice. Legacy rows with
    no agent_id exist (the P-57 migration path contemplates them), so the null case is
    spelled out rather than inherited from SQLite's three-valued logic.
    """
    marks = ",".join("?" for _ in OUR_AGENT_IDS)
    if negate:
        return "(agent_id IS NULL OR agent_id NOT IN (%s))" % marks, list(OUR_AGENT_IDS)
    return "agent_id IN (%s)" % marks, list(OUR_AGENT_IDS)


def is_our_agent(agent_id):
    """Is this traffic OURS -- a scripted demo or a shipped example -- not the developer's?

    🔴 ONE PREDICATE, BECAUSE THE LAST TWO TIMES THIS WAS ANSWERED IT WAS ANSWERED PER SITE
    AND ONE SITE WAS MISSED. `agentx demo` writes a catch; `agentx demo --audit` writes four
    routine calls. The audit SCREEN learned to label both. The funnel COUNTERS did not, so a
    curious reader running the demo we advertise on three of our own screens pulsed
    `audit_calls=4, audit_tools=4, would_blocks=1` -- identical to an install that wrapped
    its own tools and ran them under audit, which is the exact population `audit_calls` was
    added to find. Measured, not reasoned: the payload was printed.

    ⚠️ THE RULE IS ABOUT THE RUNG, NOT ABOUT ALL TELEMETRY. `agentx demo` deliberately marks
    an install ACTIVATED -- that is why the demo emits a pulse at all, so a download that ran
    it is not invisible -- and this predicate must never be used to undo that. It gates the
    counters that answer "did someone run THEIR OWN agent under audit", and nothing else.

    ⚠️ EXACT MATCH, NEVER A PREFIX. A rule like "starts with agentx_" would be shorter and
    would disown the rows of any developer who names their own agent `agentx_billing` -- and
    telling someone their own agent's calls were ours is the one failure this whole split
    exists to prevent. A closed set cannot do that.
    """
    return bool(agent_id) and agent_id in OUR_AGENT_IDS


# Kept as the old name so nothing that imported it breaks mid-change; the meaning is now
# "ours", which is why the definition moved. Remove once no caller uses it.
is_demo_agent = is_our_agent


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


# The event_log schema, in ONE place. Both the CREATE below and the add-missing-column
# upgrade in _reconcile_columns are generated from this list, so a column added here
# migrates itself onto every ledger that already exists. That coupling is the point: the
# wipe this replaced (P-57) fired precisely BECAUSE adding a column was a separate act
# from teaching old ledgers about it.
_EVENT_LOG_COLUMNS = [
    ("id",              "INTEGER PRIMARY KEY AUTOINCREMENT"),
    ("timestamp",       "REAL"),
    ("trace_id",        "TEXT"),
    ("agent_id",        "TEXT"),
    ("tool_name",       "TEXT"),
    ("policy_id",       "TEXT"),   # Strict alphanumeric id (e.g. POL-SEC-001)
    ("policy_name",     "TEXT"),   # Kept strictly for the CLI UI display
    ("status",          "TEXT"),
    ("tokens_saved",    "INTEGER"),
    ("time_saved_mins", "INTEGER"),
    # --- P-92 INVENTORY: the SHAPE of a call, never its values ------------------------
    # These three are what let audit answer "what does your agent actually do?" without
    # putting the user's own customer data on their disk. See _call_shape() for the rule
    # each one obeys; the short version is that every value here is DERIVED and drawn from
    # a bounded set, so none of them can carry a name, an address, a secret or a figure.
    ("arg_names",       "TEXT"),
    ("amount",          "REAL NOT NULL DEFAULT 0"),
    ("target_class",    "TEXT"),
]

_CREATE_EVENT_LOG_SQL = "CREATE TABLE IF NOT EXISTS event_log (\n    %s\n)" % ",\n    ".join(
    "%s %s" % (name, ddl) for name, ddl in _EVENT_LOG_COLUMNS)


# --- RETENTION (P-97) -------------------------------------------------------------------
#
# Until 2026-08-11 NOTHING pruned this file. No retention, no row cap, no vacuum. That was
# survivable only because the ledger records the RARE event: every writer is a hit, and
# `reached_first_block` is 0 across six installs, so in practice we wrote almost nothing.
#
# 🔴 P-92 changes the write rate from "the rare block" to "every call", which is the entire
# point of that proposal and therefore the entire problem. The ceiling has to exist BEFORE
# the writer that needs it, or we ship unbounded growth onto the user's own disk.
#
# The policy, ratified by the founder 2026-08-11: 30 days OR 10,000 rows, whichever binds
# first, and the drop is REPORTED rather than silent. The loud part is not manners: P-57
# deleted an entire ledger quietly and the lesson taken from it was that deletion must
# always be visible to the person whose data it was.
_RETENTION_DAYS = 30
_RETENTION_MAX_ROWS = 10000

# Amortization. Pruning on every write would put a DELETE and a COUNT on a path that runs
# inside the developer's tool call; pruning only at import would let one long-running
# process grow without bound between restarts. Every Nth write is the compromise.
_PRUNE_EVERY_WRITES = 200
_writes_since_prune = 0

# 🔴 THE `ok` FLAG HAD NO READER, WHICH MADE THE WHOLE CEILING UNFALSIFIABLE. prune_ledger has
# always reported whether it could run, and nothing looked. So if the DELETE itself failed --
# a read-only file, a lock nobody clears, a full disk -- the ledger grew without limit and no
# surface said a word. That is the exact failure this feature exists to prevent, surviving
# inside the feature, which is what the code comment already claimed it had fixed.
#
# Counted IN MEMORY and per-process on purpose. The obvious place is the ledger_retention
# table, and it is the wrong place: the failure being counted is "we cannot write to this
# file", so the record of it would be the next thing to fail.
#
# Why a RUN of failures rather than one: a single miss is usually another process holding the
# lock for a moment, which resolves itself and is not worth a warning. A persistent cause
# fails every time. And the threshold naturally fires where it matters -- unbounded growth
# only hurts a ledger with volume, volume means many prune attempts, so a long-running agent
# reaches the threshold while a short script never does and does not need to.
#
# 🔴 ...BUT A RUN INSIDE ONE PROCESS IS NOT REACHABLE FOR MOST USERS, WHICH IS WHY THE
# SECOND CONDITION BELOW EXISTS. A prune is attempted once at init_db and then once per 200
# ledger writes, and this counter is per-process and starts at zero every run. A short
# script -- the common shape -- therefore makes ONE attempt and can never exceed a streak of
# 1, no matter how many times it runs or how large the file gets. The persistent causes
# named above (a read-only file, a permission problem) are exactly the ones that recur
# ACROSS processes rather than within one, so on a run-length alone they would stay silent
# forever. `_ledger_over_ceiling_at_failure` is the second opinion: when a prune fails we
# READ (reads still work on a read-only file) and ask whether the ledger is over the ceiling
# right now. If it is, the harm is already real and one failure is enough to say so; if it
# is not, nothing is wrong yet and the run-of-3 keeps a transient lock quiet.
_PRUNE_FAILURES_BEFORE_WARNING = 3
_consecutive_prune_failures = 0
# Where the ledger WAS when the trim failed. Captured at failure time because the warning
# prints from atexit, by which point the working directory may have moved.
_failed_ledger_path = None
_ledger_over_ceiling_at_failure = False

# What we dropped, so a reader can say so. ONE row, id pinned to 1 -- this is a counter,
# not a log, and a log of deletions would itself need a retention policy.
_CREATE_RETENTION_SQL = """CREATE TABLE IF NOT EXISTS ledger_retention (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    rows_dropped      INTEGER NOT NULL DEFAULT 0,
    blocks_dropped    INTEGER NOT NULL DEFAULT 0,
    last_prune_ts     REAL,
    oldest_dropped_ts REAL
)"""

# 🔴 `rows_dropped` STOPPED ANSWERING THE QUESTION EVERY READER ASKS OF IT. Three screens ask
# retention one thing -- "did we delete a CATCH" -- because that is the only deletion worth
# apologising for, and until P-92 a dropped row and a dropped catch were the same event. The
# inventory writer broke that: routine traffic is now evicted FIRST and by design, so on a
# ledger that has never held a single block `rows_dropped` climbs and `agentx status`,
# `agentx share` and `agentx insights` all say "no blocks REMAIN" plus a dropped count -- one
# word, and it reads as *we deleted your catches*. Reproduced end to end on 20 clean calls.
#
# The counter that decides a sentence has to be the counter that sentence is ABOUT. Same rule
# as get_ledger_census's `interceptions`, one table over, and this is the third round in a
# row a screen has read the wrong number here -- so it is fixed as a counter rather than as
# another branch at the call site.
_RETENTION_COLUMNS = [("blocks_dropped", "INTEGER NOT NULL DEFAULT 0")]


def _ensure_retention_columns(conn):
    """Add any ledger_retention column an older ledger is missing. Idempotent; never raises.

    The event_log migration path (_plan_migration) deliberately does not cover this table --
    it is a counter, not the user's history -- so it gets its own three lines here rather
    than a second general mechanism.
    """
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(ledger_retention)")}
        for name, ddl in _RETENTION_COLUMNS:
            if name in have:
                continue
            conn.execute("ALTER TABLE ledger_retention ADD COLUMN %s %s" % (name, ddl))
            if name == "blocks_dropped":
                # BACKFILLED FROM rows_dropped, and that is provable rather than a guess:
                # ALLOWED rows do not exist before P-92, so every row any earlier prune
                # dropped WAS an interception. Without this, every ledger in the field that
                # has already been trimmed would silently downgrade from "trimmed" to
                # "empty" -- losing a disclosure P-57 exists to guarantee, in the migration
                # that was supposed to sharpen it.
                conn.execute("UPDATE ledger_retention SET blocks_dropped = rows_dropped")
    except Exception:
        # A ledger we cannot ALTER still prunes; it just cannot tell the two counts apart,
        # and get_retention_status falls back to rows_dropped for exactly that ledger.
        pass


def _is_addable(ddl):
    """Whether SQLite will accept this column in an ALTER TABLE ADD COLUMN.

    It refuses a PRIMARY KEY or UNIQUE column, and NOT NULL *without* a default. NOT NULL
    WITH a default is accepted. The first version of this rule treated any NOT NULL as
    unaddable, which would have silently skipped a future ("amount", "REAL NOT NULL
    DEFAULT 0") on every ledger already in the field while fresh installs got it — a
    divergence with no symptom until a reader hit the missing column (code review, #318).
    """
    upper = ddl.upper()
    if "PRIMARY KEY" in upper or "UNIQUE" in upper:
        return False
    return "NOT NULL" not in upper or "DEFAULT" in upper


def _inspect_event_log(conn):
    """READ ONLY. Return the set of columns event_log has (empty when it does not exist).

    🔴 Kept strictly separate from the ALTER in _upgrade_existing_ledger, because ONLY a
    READ failure may trigger a quarantine. A WRITE failure — another process holding the
    lock, a read-only file, a full disk — says nothing about whether the ledger is
    readable, and setting an intact ledger aside on one is the exact harm this module
    exists to prevent. The first version of this fix wrapped both in one try (#318).
    """
    return {row[1] for row in conn.execute("PRAGMA table_info(event_log)")}


def _plan_migration(have):
    """Pure. Split what the current schema needs into (addable, foreign, unaddable).

    🔴 `foreign` and `unaddable` are DELIBERATELY different, and collapsing them is a bug
    this already had once (#318 round 2). Only `foreign` may quarantine.

    foreign   — the table has no PRIMARY KEY, so it is not an old ledger of ours, it is a
                different table that happens to be called event_log. Migrating it produces
                something worse than either a wipe or a refusal: `get_recent_blocks`
                (ORDER BY id) and `log_self_correction` (its subquery selects id) both fail
                and both swallow their own exception, so `agentx share` reports no blocks
                while blocks exist and recoveries stop recording, silently and permanently.
                Set it aside.
    unaddable — a column SQLite cannot ALTER in (today: NOT NULL with no default) that is
                NOT the key. The table is still ours and still works. SKIP the column and
                say so loudly. Quarantining here would turn one careless DDL string in
                _EVENT_LOG_COLUMNS into history displacement for every user in the field,
                which is far worse than shipping without the column — and worse than the
                pre-P-57 behaviour, which merely skipped it.

    Mirrors backend/incident_store.py::_reconcile_columns, which fixed the same class for
    the gateway's incident store in 2026-07 and likewise returns what it could NOT add so
    the caller can report it. The SDK ships standalone and cannot import from backend/, so
    this is a deliberate second copy of the PATTERN, not of any value.
    """
    addable, foreign, unaddable = [], [], []
    for name, ddl in _EVENT_LOG_COLUMNS:
        if name in have:
            continue
        if "PRIMARY KEY" in ddl.upper():
            foreign.append(name)
        elif _is_addable(ddl):
            addable.append((name, ddl))
        else:
            unaddable.append(name)
    return addable, foreign, unaddable


def _quarantine_ledger():
    """Move a ledger we cannot read ASIDE, never delete it, and return the backup path.

    Returns None when the move itself failed (typically a Windows file lock), in which case
    the user's file is left exactly as it was. Deleting is not an option in either branch:
    the file is the user's own history, and a schema we cannot handle is our problem, not a
    reason to destroy their record of it.

    ⚠️ Every name this produces ENDS IN `.bak`, including the numbered ones. The obvious
    scheme (`.bak-2`) does not match the near-universal `*.bak` gitignore line, so a
    quarantine would show up as an untracked file in the developer's own repo. Caught by
    running this against the real repo ledger rather than only against tmp_path.
    """
    target = DB_PATH + ".bak"
    n = 1
    while os.path.exists(target):
        n += 1
        target = "%s.%d.bak" % (DB_PATH, n)
    try:
        os.rename(DB_PATH, target)
    except OSError:
        return None
    return target


def _report_quarantine(why):
    """Set an unusable ledger aside and say so ONCE. Returns True when it is safe to build a
    fresh ledger in its place, False when the old file is still sitting there.

    One condition, one message. The first version printed "left it untouched" here and then
    a second "could not open the local ledger" from the CREATE that followed, which read as
    two separate problems (code review, #318).
    """
    backup = _quarantine_ledger()
    if backup:
        print("⚠️ [AgentX SDK] The local ledger %s, so it was saved as %s and a new one "
              "started. Nothing was deleted." % (why, backup))
        return True
    print("⚠️ [AgentX SDK] The local ledger %s, and it could not be moved aside (it may be "
          "open in another program). It is UNCHANGED, and this session will not be "
          "recorded." % why)
    return False


def _upgrade_existing_ledger():
    """Bring an existing ledger to the current schema, or set it aside if it is not one.
    Returns True when the caller should go on to CREATE, False when it must not.

    🔴 Every branch prints what it ACTUALLY did. The first version of this fix printed
    "Your history is intact" from the success path and "Could not read the local ledger"
    from a catch that also covered the WRITE — so a locked or read-only file produced a
    false diagnosis *and* moved an intact ledger aside, which is the very harm P-57 is
    about. Read and write are separated below for that reason; keep them separated.
    """
    try:
        with _connection() as conn:
            have = _inspect_event_log(conn)
    except sqlite3.Error:
        return _report_quarantine("could not be read (it is not a readable SQLite database)")

    if not have:
        return True                                   # no event_log yet; CREATE makes it

    addable, foreign, unaddable = _plan_migration(have)
    if foreign:
        return _report_quarantine(
            "has no %s column, so it is not one of ours" % ", ".join(foreign))
    if unaddable:
        # Loud, but NOT a reason to touch their data. See _plan_migration: this is a bad
        # DDL string on our side, and the ledger keeps working without the column.
        print("🔴 [AgentX SDK] Cannot add %s to an existing ledger, so this install will "
              "run without it. Your history is untouched. Please report this: "
              "https://bit.ly/agentfirewall" % ", ".join(unaddable))
    if not addable:
        return True                                   # already current

    try:
        with _connection() as conn:
            # Re-read inside the WRITE connection. Between the inspect above and here,
            # another process starting in the same directory can have run the same
            # migration; without this, the loser gets a duplicate-column error and reports
            # a failed upgrade on a ledger that is in fact perfectly fine.
            fresh = _inspect_event_log(conn)
            for name, ddl in [(n, d) for n, d in addable if n not in fresh]:
                # name/ddl come from the module constant, never from a caller or a payload,
                # so this interpolation carries no injection surface (ALTER takes no params).
                conn.execute("ALTER TABLE event_log ADD COLUMN %s %s" % (name, ddl))
            conn.commit()
    except sqlite3.Error as exc:
        # A WRITE failure is NOT evidence the ledger is bad. Leave it exactly as it is.
        print("⚠️ [AgentX SDK] Could not upgrade the local ledger (%s). It is UNCHANGED and "
              "your history is safe; this session may not be recorded. Try again once "
              "nothing else is using it." % exc)
        return False
    print("🔄 [AgentX SDK] Ledger upgraded to the current schema. Your history is intact.")
    return True


def init_db():
    """Create the local ledger, or upgrade an existing one IN PLACE. Never destroys it.

    This file is the user's own record of what AgentX did: every block, every recovery, and
    everything `agentx insights`, `agentx share` and `agentx review` read back. A schema
    change is OUR event, so it must not cost them that. Two rules hold the guarantee:

      1. Missing columns are ADDED, generated from _EVENT_LOG_COLUMNS, so the next column
         we ship migrates itself rather than orphaning every ledger in the field.
      2. A ledger we cannot read, or that is not one of ours, is RENAMED aside, never
         removed — and only a READ failure is allowed to reach that branch.

    🔴 Until 2026-08 this called os.remove(DB_PATH) on any legacy schema and printed
    "Clean slate!" (P-57). The trigger was entirely ours: it fired the first time a user ran
    a build that had added a column.

    ⚠️ This must NEVER raise. decorators.py imports this module and calls init_db() at
    import time (decorators.py:765), so an exception here breaks `import agentx_sdk`
    outright. That is the opposite of the sibling in backend/incident_store.py, which is
    documented as write-path-only and allowed to raise.
    """
    if os.path.exists(DB_PATH) and not _upgrade_existing_ledger():
        return

    try:
        with _connection() as conn:
            conn.execute(_CREATE_EVENT_LOG_SQL)
            conn.execute(_CREATE_RETENTION_SQL)
            conn.commit()
    except sqlite3.Error as exc:
        # Never raise (see the docstring). The ledger writers are already best-effort, so
        # the session runs unrecorded rather than the SDK failing to import.
        print("⚠️ [AgentX SDK] Could not open the local ledger (%s). Protection is unaffected; "
              "this session will not be recorded." % exc)
        return

    # Trim on the way in, so a ledger that grew under an older build (or under a process
    # that exited before its next amortized prune) comes back inside the ceiling without
    # waiting for 200 more writes. Best-effort by construction: prune_ledger swallows its
    # own errors, and init_db must never raise (see the docstring).
    prune_ledger()


def _ledger_exceeds_ceiling(path=None, cutoff=None, cap=None, margin=None):
    """Best-effort READ: is this ledger over the ceiling right now?

    Runs in prune_ledger's FAILURE path, which is precisely where writing is broken -- so
    this touches nothing but SELECTs and returns False on any error. A read-only file, or a
    writer holding the lock, still answers a read, and that is what makes this a usable
    second opinion on whether a failed trim has done any harm yet.

    ⚠️ THE AGE CHECK CARRIES A MARGIN, THE SIZE CHECK DOES NOT, AND THE ASYMMETRY IS THE
    POINT. Prunes are amortized over _PRUNE_EVERY_WRITES writes, so a perfectly healthy
    ledger is ALWAYS carrying rows that have aged past the cutoff since the last successful
    pass -- with a bare `> 0` there, one transient lock (the single failure this feature
    deliberately keeps quiet) was enough to tell a developer whose file is fine that it
    "will keep growing". Row COUNT is different: being over the cap is the harm itself, it
    is what the caller asked us to hold, and a caller who passes an explicit max_rows means
    that number.
    """
    slack = _PRUNE_EVERY_WRITES if margin is None else margin
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            if cap is not None:
                cursor.execute("SELECT COUNT(*) FROM event_log")
                if (cursor.fetchone()[0] or 0) > cap:
                    return True
            if cutoff is not None:
                cursor.execute(
                    "SELECT COUNT(*) FROM event_log "
                    "WHERE timestamp IS NOT NULL AND timestamp < ?", (cutoff,))
                return (cursor.fetchone()[0] or 0) > slack
    except Exception:
        return False
    return False


# --- P-92 CALL SHAPE ---------------------------------------------------------------------
#
# 🔴 THE ONE RULE: SHAPE, NEVER VALUES. Everything written by _call_shape is DERIVED from the
# call and drawn from a BOUNDED set. Both words are load-bearing and neither is decoration:
#
#   derived -- computed from the argument, never copied out of it.
#   bounded -- drawn from a finite set fixed in this file, never from caller-supplied text.
#
# ⚠️ THOSE TWO WORDS DESCRIBE `amount` AND `target_class`, NOT `arg_names`, and an earlier
# version of this comment claimed "nothing here can return caller-supplied text" over code
# that plainly does. An argument NAME is the caller's own text (and on the MCP path a REMOTE
# SERVER's text), capped in length and count but not drawn from any fixed set. That is the
# ratified design -- "argument names are safe" -- so the point is not to change it but to
# stop the comment promising a stronger guarantee than the function delivers. The line that
# holds without qualification is the one below: no argument VALUE is recorded.
#
# A raw argument value is neither, which is why none is recorded. This is not fussiness: a
# tool call's arguments are exactly where PII lives, the pulse posture we advertise is
# "counts only, never code/data", and P-92 multiplies the write rate by orders of magnitude.
# "Record what the agent touched" is one careless step from writing a user's customers onto
# their own disk, in a file we then keep for 30 days.
#
# ⚠️ THERE IS DELIBERATELY NO CARVE-OUT HERE, including for numbers. An exact figure is a
# value (a transfer amount is real data about a real transaction), so magnitude is recorded
# as the bucket floor instead -- see _magnitude_bucket. Ratified: "shape, never values, for
# the default path ... derived bounded features that carry magnitude."

# Closed vocabulary. A target class is only ever one of these; anything unrecognised becomes
# _CLASS_OTHER rather than free text, so a pulled policy or a creatively-named tool can never
# widen what lands in the column. Same closed-vocab guard the block categories already use.
_CLASS_OTHER = "other"
_TARGET_CLASSES = ("filesystem", "http", "db", "shell", "cloud", _CLASS_OTHER)

# What the SURFACE column prints. The stored value stays long and explicit (it is data, and
# `filesystem` survives a rename of this table); the screen gets the short form a reader takes
# in at a glance. Founder call: the surface is what means something to a user -- a policy name
# is ours, "DB" and "FS" are theirs.
_SURFACE_LABELS = {
    "db": "DB",
    "filesystem": "FS",
    "http": "HTTP",
    "shell": "SHELL",
    "cloud": "CLOUD",
    _CLASS_OTHER: "-",
}

# Substring -> class. Matched against the TOOL NAME and the ARGUMENT NAMES only, never
# against argument values, so nothing a user's data says can influence the result. First
# match wins in THIS order, so the result never depends on dict ordering.
#
# ⚠️ DELIBERATELY UNDER-INCLUSIVE, and it should stay that way. An earlier draft had bare
# "get", "post", "run" and "read" in here, which classified `get_customer` as http and
# `run_report` as shell. This ends up on a screen the user reads as a statement about their
# own agent, so a confident wrong class is worse than `other`: `other` says we do not know,
# which is true and costs nothing. Only add a needle that cannot plausibly mean something
# else -- and if a class is genuinely ambiguous, it belongs in `other`.
#
# 🔴 SECOND NARROWING, AND THE RULE ABOVE IS WHAT IT ENFORCES. Token-anchoring removed the
# anagram class (`send_feedback` -> DB) but left ordinary English words in the table, and each
# one still labelled real tools wrongly -- verified by running the classifier:
#     search(query=...)                -> DB
#     book_table(table_id=...)         -> DB
#     list_customers(cursor=...)       -> DB
#     approve_request(request_id=...)  -> HTTP
#     reserve_seat(cluster=...)        -> CLOUD
#     fill_bucket(bucket=...)          -> CLOUD
# None of those touch the surface named. `query`, `table`, `cursor`, `request`, `bucket`,
# `cluster` and `command` are words a domain tool uses for its own reasons, so by this file's
# own rule they belong in `other`. Dropping them costs almost nothing: `run_sql` still matches
# `sql`, `write_file` still matches `file`, and a tool we cannot place honestly says so.
_CLASS_HINTS = (
    (("sql", "db", "database", "postgres", "mysql", "mongo", "sqlite"), "db"),
    (("aws", "gcp", "azure", "cloud", "terraform", "s3"), "cloud"),
    (("http", "https", "url", "webhook"), "http"),
    (("shell", "exec", "cmd", "bash", "subprocess"), "shell"),
    (("file", "path", "dir", "directory", "unlink", "chmod"), "filesystem"),
)

# 🔴 WHICH ARGUMENT IS MONEY: THE DEVELOPER TELLS US. THIS IS P-83'S RULE, NOT A NEW ONE.
#
# An argument is an amount when it is NAMED `amount` (or `<prefix>_amount`) AND the same call
# carries a `currency` key holding a real value. The currency field is the developer's own
# declaration, written for their reasons and not for us, so there is nothing for us to guess.
#
# WHY IT IS SPELLED THIS WAY: it is what `backend/gateway.py::_labelled_transfer_pair` already
# does, shipped in #317 as the fixed half of P-83. Its own row states the principle -- "the
# argument NAME carries the meaning and no verb is needed". Both halves of the product now
# answer "which number is money" the same way instead of guessing separately.
#
# 🔴 WHAT THIS REPLACED, AND WHY THE REPLACEMENT IS THE POINT. The first fix for P-103 matched
# a LIST of money words (amount, price, cost, fee, subtotal, charge, payment, refund, balance)
# with no second signal. One weak signal cannot settle an ambiguous name, so it needed a
# growing list of exceptions to stay correct, and four review rounds each found another
# category: ids carrying money words (`payment_id`), units (`amount_cents`, a $2,500 charge
# shown as >=100,000), range bounds (`min_amount` on a read-only search), tax qualifiers
# (`amount_no_tax`). That is an open-ended question, and the list was the symptom of asking it.
# Requiring the currency field closes it: none of those carry one.
#
# ⚠️ KNOWN LIMIT, DELIBERATE, NOT A BUG TO REDISCOVER. This reads TOP-LEVEL arguments only.
# The gateway walks nested objects to depth 4 because `{"payment": {"amount": 250, "currency":
# "usd"}}` is the shape payment integrations pass, so a nested payload records nothing here.
# Founder call 2026-08-12: not porting the walk yet. Flat `amount=..., currency=...` kwargs are
# the normal shape for a decorated Python function, which is this path; nesting mostly arrives
# on the MCP path. Filed against [[#p-83]]; when the walk is adopted it extends THIS rule
# rather than replacing a different one.
_AMOUNT_KEY = "amount"
_CURRENCY_KEY = "currency"

# A range bound is not an amount moved. PORTED from the gateway rather than re-derived, with
# its measurement: `search_transactions(min_amount=100000, currency="usd")` is a READ, and it
# was interrupting a human. `from`/`to` are deliberately NOT here -- the gateway removed them
# in review round 4 because they are ordinary transfer leg names, and excluding them made
# `transfer(to_amount=450000, currency="usd")` extract 0.0 and the money floor go silent on
# its core case.
#
# ⚠️ THIS IS THE ONE ENUMERATION THAT SURVIVES, and saying otherwise would repeat the mistake
# the currency rule was adopted to end. The prefix must match EXACTLY, so
# `search_transactions(minimum_amount=100000, currency="usd")` records a magnitude for a
# read-only search. The gateway has the identical gap, so this is a faithful port rather than
# a divergence -- and it is left faithful on purpose: widening it here alone would give the
# two paths different answers, which is the thing that produced P-103 in the first place.
# If it is widened, widen it there and port again.
_RANGE_BOUND_PREFIXES = ("min", "max", "lower", "upper")


def _normalise_key(key):
    """Lowercase, with separators unified. The same normalisation the gateway applies, so
    `Payment-Amount` and `payment.amount` cannot mean different things on the two paths."""
    return str(key).strip().lower().replace("-", "_").replace(".", "_")


def _is_amount_key(name):
    """True when a NORMALISED key names an amount. Shared so the writer, the display and the
    manual check cannot answer this question three slightly different ways."""
    return name == _AMOUNT_KEY or name.endswith("_" + _AMOUNT_KEY)


def _is_currency_key(name):
    """True when a NORMALISED key names a currency."""
    return name == _CURRENCY_KEY or name.endswith("_" + _CURRENCY_KEY)


def _amount_prefix(name):
    """`total_amount` -> `total`, `amount` -> ``. For the range-bound check."""
    return name[:-len(_AMOUNT_KEY)].rstrip("_")


def _is_real_currency_value(value):
    """A currency key must CARRY a currency, not merely exist.

    Ported with its reason: `str(None)` is `"None"`, which is truthy, so a first cut on the
    gateway counted `{"amount": 99120033, "currency": None}` as money and put an identifier in
    front of a human. A generated tool schema that always emits `currency`, null when the call
    is not a payment, is the NORMAL shape -- not an edge case. Booleans are refused for the
    same reason: `currency=False` is not a currency.
    """
    if value is None or isinstance(value, bool):
        return False
    return bool(str(value).strip())


# Bounds on the argument-name list. A tool with 400 parameters, or one generated parameter
# name a megabyte long, must not be able to turn one ledger row into the thing the retention
# ceiling exists to prevent.
_MAX_ARG_NAMES = 24
_MAX_ARG_NAMES_CHARS = 512


def _magnitude_bucket(value):
    """The bucket FLOOR for a numeric magnitude, as a power of ten. Pure.

    5 -> 1.0, 42 -> 10.0, 1500 -> 1000.0, 0 -> 0.0, -30 -> 10.0 (sign is not magnitude).

    🔴 THE BUCKET IS THE POINT, NOT A ROUNDING CONVENIENCE. The exact figure is a value and
    fails the rule above; the bucket is derived and lands in a set with about twenty members,
    so it carries the magnitude ("your agent moved money twice above $1,000") while being
    unable to carry the transaction. Anything non-numeric returns 0.0 -- a string is never
    coerced, because parsing one is how a value sneaks into a numeric column.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    try:
        size = abs(float(value))
    except Exception:
        return 0.0
    # NaN/inf carry no magnitude and would poison MAX() for every reader of this column.
    if not (size == size) or size in (float("inf"),) or size < 1:
        return 0.0
    bucket = 1.0
    while bucket * 10 <= size:
        bucket *= 10
        # A float can reach 1e308; stop long before the loop becomes the interesting part.
        if bucket >= 1e15:
            break
    return bucket


def _name_tokens(raw):
    """Split identifier-ish text into whole lowercase tokens. Pure.

    🔴 ONE COPY, BECAUSE THE RULE WAS LEARNED EXPENSIVELY. `_classify_target` originally tested
    `needle in haystack` and read tool names like an anagram -- `send_feedback` classified as DB
    because "fee(db)ack" contains "db". The fix was to compare whole TOKENS, and it is the whole
    correctness of every name-matching rule in this file. A second matcher written from scratch
    (P-103's amount hints) would have had to re-learn it, and `discount_id` matching "count" is
    the same bug wearing a different hat. So both callers come through here.

    camelCase is a boundary too: MCP servers and JS tools are routinely `sendHttpRequest`, which
    is ONE token under a punctuation-only split. Split before lowercasing, because the case IS
    the boundary.
    """
    raw = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(raw or ""))
    return {t for t in re.split(r"[^a-z0-9]+", raw.lower()) if t}


def _classify_target(tool_name, names):
    """The bounded target class for a call. Pure, and reads NAMES ONLY (never values).

    First hint wins, in the fixed order above, so the result does not depend on dict
    ordering. Unrecognised is _CLASS_OTHER, never the caller's text.

    🔴 MATCHES WHOLE TOKENS, NOT SUBSTRINGS, AND THAT IS THE ENTIRE CORRECTNESS OF IT.
    The first version tested `needle in haystack`, which read the developer's tool names
    like an anagram: `send_feedback` classified as DB because "fee(db)ack" contains "db",
    `sandbox_run` likewise, `rapid_dispatch` and `capitalize_note` as HTTP because both
    contain "api", and `portable_export` as DB via "por(table)". Every one of those puts a
    confident wrong label on a screen the developer reads to learn what their own code does.

    Narrowing the NEEDLE LIST (which the comment above did) cannot fix that: the bug is in
    the matching RULE, and a shorter list of needles still matches inside longer words. So
    the haystack is split into tokens on any non-alphanumeric boundary and compared for
    equality. `run_sql` -> {run, sql} still matches "sql"; `send_feedback` -> {send,
    feedback} matches nothing and correctly answers `other`.
    """
    tokens = _name_tokens(" ".join([str(tool_name or "")] + [str(n) for n in (names or [])]))
    for needles, klass in _CLASS_HINTS:
        if tokens.intersection(needles):
            return klass
    return _CLASS_OTHER


def _call_shape(tool_name, arguments):
    """Derive (arg_names, amount, target_class) for one call. Pure, and never raises.

    `arguments` is the developer's own kwargs dict. ONLY ITS KEYS ARE READ, plus the numeric
    magnitude of its values via _magnitude_bucket -- which returns a bucket, not the number.

    No argument VALUE is ever returned. The argument NAMES are caller-supplied text (and on
    the MCP path a remote server's text), capped in count and length but not drawn from a
    fixed set -- that is the ratified design, and this docstring used to overstate it.
    """
    try:
        # 🔴 THE COMMA IS THE RECORD SEPARATOR, so a key containing one would split into two
        # argument names that the tool never had. Not hypothetical on the MCP path: those
        # keys come from a remote server's JSON, not from a Python signature. Stripped rather
        # than escaped -- this is a display list, not a payload, and an escape scheme is more
        # machinery than a name with a comma in it deserves.
        names = sorted(str(k).replace(",", " ") for k in (arguments or {}).keys())
    except Exception:
        names = []

    # Budget the LIST, then join. Slicing the joined string instead cut mid-name and left a
    # partial token ("customer_i") that the reader re-splits on "," and presents as a real
    # argument the developer never wrote.
    # `continue`, not `break`: names arrive SORTED, so one oversized name discarded every
    # remaining argument for that call rather than just itself -- and the reader loses the
    # whole ARGUMENTS column for that tool, which is the column they kept reading for. Skip
    # the one that does not fit and keep taking the ones that do. Still bounded twice over
    # (_MAX_ARG_NAMES on the loop, _MAX_ARG_NAMES_CHARS on the budget).
    kept, used = [], 0
    for name in names[:_MAX_ARG_NAMES]:
        cost = len(name) + (1 if kept else 0)
        if used + cost > _MAX_ARG_NAMES_CHARS:
            continue
        kept.append(name)
        used += cost
    joined = ",".join(kept)

    # 🔴 THE LABELLED ARGUMENT, NEVER THE LARGEST ONE (P-103, and P-65 before it). An id, an
    # order number, a timestamp or a row limit can no longer become "the amount" by being the
    # biggest integer in the payload, because nothing is measured unless the developer named a
    # currency. See the rule above for why this is P-83's test rather than one of our own.
    #
    # max() among the qualifying arguments, not first-wins: two amount keys are two readings of
    # one call and the larger consequence is the one worth showing. Same reasoning the gateway
    # records at extract_transfer_amount_with_currency, where taking the first non-zero let a
    # small labelled amount silence a large one.
    #
    # ⚠️ ONE DELIBERATE SIMPLIFICATION FROM THE GATEWAY, NAMED SO IT READS AS A CHOICE. The
    # gateway pairs each amount to the currency sharing its PREFIX, because it must show an
    # approver a figure AND its unit, and `{"fee_amount": 5, "fee_currency": "usd",
    # "total_amount": 450000, "total_currency": "jpy"}` once rendered as "450,000 USD". This
    # column stores no currency and displays none: it only needs to know the developer said
    # this call moves money. So presence anywhere in the call is enough here, and mispairing
    # has no consequence it could cause.
    # 🔴 ITERATE THE ARGUMENTS. DO NOT BUILD A NORMALISED DICT. The first cut of this block did
    # (`names = {_normalise_key(k): v for k, v in args.items()}`) and bought two defects with
    # one shortcut:
    #
    #   1. it SHADOWED `names`, the raw sorted key list this function passes to
    #      _classify_target on its last line. Normalising lowercases, which destroys the
    #      camelCase boundary `_name_tokens` was extracted IN THIS PR to preserve -- so
    #      `filePath` classified as `other` rather than `filesystem`, and the SURFACE column
    #      silently emptied for exactly the MCP payloads that arrive camelCased.
    #   2. a dict COLLAPSES colliding keys, last one wins. `{"Amount": 450000, "amount": 5}`
    #      recorded 5, dropping a $450k transfer below the display threshold entirely, and it
    #      made the answer depend on insertion order.
    #
    # The gateway has neither, because it iterates `action_args.items()` and takes a max. So
    # the shortcut was also a divergence from the rule this file claims to have ported.
    amount = 0.0
    try:
        args = arguments or {}
        has_currency = any(
            _is_currency_key(_normalise_key(k)) and _is_real_currency_value(v)
            for k, v in args.items())
        if has_currency:
            for key, value in args.items():
                norm = _normalise_key(key)
                if not _is_amount_key(norm) or _amount_prefix(norm) in _RANGE_BOUND_PREFIXES:
                    continue
                bucket = _magnitude_bucket(value)
                if bucket > amount:
                    amount = bucket
    except Exception:
        amount = 0.0

    return joined, amount, _classify_target(tool_name, names)


def _older(a, b):
    """The earlier of two possibly-None timestamps. Pure.

    The SIZE rule deletes in two passes (inventory first, then everything else), and each
    reports the oldest row it destroyed. The reader wants the oldest across BOTH, so the
    second pass must fold into the first rather than assign over it: pass 1 spends the OLDEST
    inventory rows, so its timestamp is usually the earlier one, and overwriting it would tell
    the user their surviving window starts later than it does -- a false statement about their
    own data, generated by the code that destroyed it. That is the same failure the CASE in
    the bookkeeping UPDATE below already guards from the other direction.
    """
    candidates = [t for t in (a, b) if t is not None]
    return min(candidates) if candidates else None


def prune_ledger(path=None, now=None, max_age_days=None, max_rows=None):
    """Enforce the retention ceiling on event_log. Returns a dict, never raises.

    Two rules, applied in order, both bounded by ONE deletion pass so a caller cannot
    observe a half-pruned ledger:

      1. AGE  -- rows older than `max_age_days`. Applies to every row alike.
      2. SIZE -- once age is applied, the oldest rows beyond `max_rows`, spending the P-92
         INVENTORY rows (`INVENTORY_STATUS`) first and touching anything else only if the
         protected rows alone still break the cap. Age does NOT get this split: a 30-day-old
         block has aged out on its own terms, and sparing it there would quietly turn the
         retention promise we disclose into something else.

    Ordering by `id`, not `timestamp`, for the size rule. `id` is the autoincrement and is
    monotonic; `timestamp` is wall-clock and can tie or move backwards across a DST shift or
    an NTP correction, which would make "the oldest 500 rows" ambiguous and let a size prune
    delete a different set on each run.

    ⚠️ A NULL timestamp survives the AGE rule on purpose. Legacy rows migrated by P-57's
    replacement carry NULLs, `NULL < cutoff` is never true in SQLite, and a row we cannot
    date is a row we cannot honestly call expired. The SIZE rule still reaches them, so they
    cannot accumulate without limit -- they just are not deleted on a guess.
    """
    global _writes_since_prune, _consecutive_prune_failures
    global _ledger_over_ceiling_at_failure, _failed_ledger_path

    days = _RETENTION_DAYS if max_age_days is None else max_age_days
    cap = _RETENTION_MAX_ROWS if max_rows is None else max_rows
    stamp = time.time() if now is None else now
    cutoff = stamp - (days * 86400)

    # `ok` distinguishes "there was nothing to drop" from "this pass could not run". Both
    # used to return dropped=0, so a ceiling that had silently stopped applying was
    # indistinguishable from a ledger comfortably inside it -- which is the failure this
    # whole feature exists to prevent, hiding inside the feature.
    result = {"dropped": 0, "oldest_dropped_ts": None, "ok": True}

    # 🔴 `ok` COVERS TWO DIFFERENT FAILURES AND ONLY ONE OF THEM MEANS "NOT BEING TRIMMED".
    # The inner except below sets ok=False when the DISCLOSURE write fails after the
    # deletions are already committed -- the trim WORKED, we just could not write down that
    # it did. Counting that as a trim failure makes the session summary tell the developer
    # their file "will keep growing" while it is in fact shrinking on every prune, which is a
    # false statement about their own data. This flag separates the two.
    deletions_committed = False

    try:
        if not os.path.exists(path or DB_PATH):
            return result

        with _connection(path) as conn:
            cursor = conn.cursor()

            # 🔴 SELF-HEAL, BECAUSE init_db CAN LEGITIMATELY NEVER HAVE CREATED THIS TABLE.
            # init_db returns early when _upgrade_existing_ledger() fails, and that is a
            # WRITE failure (a concurrent lock, a read-only file). log_intercept keeps
            # writing rows regardless, so without this line the ledger grows forever on
            # exactly the machines where the migration was contended. Measured before the
            # fix: 5 rows aged 100 days, prune reported dropped=0, all 5 survived.
            conn.execute(_CREATE_RETENTION_SQL)
            _ensure_retention_columns(conn)

            # Counted alongside `dropped` on every path below, because "we deleted a row" and
            # "we deleted one of your catches" are different disclosures and only the second
            # one is what three screens are actually asking about. See _RETENTION_COLUMNS.
            blocks = 0

            # Capture the oldest timestamp we are about to destroy BEFORE destroying it --
            # afterwards it is unrecoverable, and it is the one fact that lets a reader say
            # what the surviving window actually covers.
            cursor.execute(
                "SELECT MIN(timestamp) FROM event_log WHERE timestamp IS NOT NULL AND timestamp < ?",
                (cutoff,))
            oldest_by_age = cursor.fetchone()[0]

            # Counted BEFORE the DELETE, for the same reason the timestamp is: afterwards the
            # rows are gone and the question is unanswerable.
            cursor.execute(
                "SELECT COUNT(*) FROM event_log "
                "WHERE timestamp IS NOT NULL AND timestamp < ? AND status IS NOT ?",
                (cutoff, INVENTORY_STATUS))
            blocks += cursor.fetchone()[0] or 0

            cursor.execute("DELETE FROM event_log WHERE timestamp IS NOT NULL AND timestamp < ?",
                           (cutoff,))
            dropped = cursor.rowcount or 0

            # SIZE. Keep the newest `cap` rows by id; everything below that id goes.
            #
            # 🔴 TWO PASSES, BECAUSE ONE CAP HOLDS TWO KINDS OF ROW (P-92). Until the inventory
            # writer existed every row here was a block, so "keep the newest `cap`" could not
            # lose anything that mattered. Once audit records a row per CALL, routine traffic
            # and block records compete for the same 10,000, and a chatty agent would silently
            # evict its own block history -- the record the product's entire value story rests
            # on -- without a single line of this function looking wrong. It would also move
            # the "On record" recovery rate for reasons that have nothing to do with recovery,
            # since unrecovered blocks sit in that denominator alone.
            #
            # So the inventory is spent FIRST and the rest is spared until the spared rows
            # alone break the cap. On a ledger with no ALLOWED rows -- every ledger in the
            # field today -- pass 1 deletes nothing and pass 2 is the original code, byte for
            # byte, which is the compatibility guarantee test_ledger_retention.py pins.
            cursor.execute("SELECT COUNT(*) FROM event_log")
            remaining = cursor.fetchone()[0] or 0
            oldest_by_size = None
            if cap is not None and remaining > cap and cap > 0:
                # PASS 1 -- spend the inventory, oldest first, but only as much of it as the
                # overage actually requires. Deleting every ALLOWED row whenever the ledger is
                # one row over would throw away the whole inventory to make room for one block.
                excess = remaining - cap
                inventory_pick = (
                    "SELECT id FROM event_log WHERE status = ? ORDER BY id LIMIT ?")
                cursor.execute(
                    "SELECT MIN(timestamp) FROM event_log "
                    "WHERE timestamp IS NOT NULL AND id IN (%s)" % inventory_pick,
                    (INVENTORY_STATUS, excess))
                oldest_by_size = cursor.fetchone()[0]
                cursor.execute(
                    "DELETE FROM event_log WHERE id IN (%s)" % inventory_pick,
                    (INVENTORY_STATUS, excess))
                dropped += cursor.rowcount or 0

                # Re-count rather than subtract: pass 1 can delete FEWER rows than `excess`
                # when there is not enough inventory to cover it, and assuming otherwise would
                # skip pass 2 on exactly the ledger that still needs it.
                cursor.execute("SELECT COUNT(*) FROM event_log")
                remaining = cursor.fetchone()[0] or 0

            if cap is not None and remaining > cap:
                if cap <= 0:
                    # SQLite clamps a negative OFFSET to 0, so `LIMIT 1 OFFSET cap-1` with
                    # cap=0 returned the NEWEST row as the floor and spared it: max_rows=0
                    # kept one row. Latent while the constant is 10000, and an off-by-one
                    # waiting for the first caller that passes a computed cap.
                    cursor.execute(
                        "SELECT MIN(timestamp) FROM event_log WHERE timestamp IS NOT NULL")
                    oldest_by_size = _older(oldest_by_size, cursor.fetchone()[0])
                    cursor.execute("SELECT COUNT(*) FROM event_log WHERE status IS NOT ?",
                                   (INVENTORY_STATUS,))
                    blocks += cursor.fetchone()[0] or 0
                    cursor.execute("DELETE FROM event_log")
                    dropped += cursor.rowcount or 0
                else:
                    cursor.execute(
                        "SELECT id FROM event_log ORDER BY id DESC LIMIT 1 OFFSET ?", (cap - 1,))
                    row = cursor.fetchone()
                    if row:
                        floor_id = row[0]
                        cursor.execute(
                            "SELECT MIN(timestamp) FROM event_log WHERE id < ? AND timestamp IS NOT NULL",
                            (floor_id,))
                        oldest_by_size = _older(oldest_by_size, cursor.fetchone()[0])
                        # Pass 1 above deletes ONLY inventory rows, so it contributes nothing
                        # here by construction. This pass is the one that can reach a catch.
                        cursor.execute(
                            "SELECT COUNT(*) FROM event_log WHERE id < ? AND status IS NOT ?",
                            (floor_id, INVENTORY_STATUS))
                        blocks += cursor.fetchone()[0] or 0
                        cursor.execute("DELETE FROM event_log WHERE id < ?", (floor_id,))
                        dropped += cursor.rowcount or 0

            # 🔴 COMMIT THE DELETIONS BEFORE ANY BOOKKEEPING. They are the work; the counter
            # only DESCRIBES the work. In the first draft both lived in one transaction, so a
            # failure writing the counter rolled the deletions back with it -- the ledger
            # kept growing because we could not write down that it had shrunk.
            conn.commit()
            deletions_committed = True
            result["dropped"] = dropped

            if dropped:
                candidates = [t for t in (oldest_by_age, oldest_by_size) if t is not None]
                oldest = min(candidates) if candidates else None
                try:
                    conn.execute("INSERT OR IGNORE INTO ledger_retention (id) VALUES (1)")
                    # 🔴 TWO SPELLINGS, BECAUSE THE FALLBACK _ensure_retention_columns
                    # PROMISES HAS TO EXIST SOMEWHERE. That function swallows a failed ALTER
                    # and its comment says such a ledger "still prunes; it just cannot tell
                    # the two counts apart" -- which was not true of this statement: naming
                    # blocks_dropped unconditionally made the WHOLE bookkeeping UPDATE fail on
                    # that ledger, so rows_dropped, last_prune_ts and oldest_dropped_ts were
                    # lost too. Measured: 5 CHALLENGED rows deleted, get_retention_status()
                    # None, ledger_empty_reason() "empty" -- i.e. "nothing has been blocked in
                    # this ledger yet" printed over five catches we had just destroyed, the
                    # exact P-57 false-empty this counter exists to prevent. It also drove
                    # ok=False on every prune, which is what raises the P-97 "retention is
                    # failing" warning about a prune that deleted everything it meant to.
                    _SET_BLOCKS = "blocks_dropped    = blocks_dropped + ?,\n                               "
                    _BOOKKEEPING = """
                        UPDATE ledger_retention
                           SET rows_dropped      = rows_dropped + ?,
                               %slast_prune_ts     = ?,
                               oldest_dropped_ts = CASE
                                   WHEN ? IS NULL THEN oldest_dropped_ts
                                   ELSE MIN(COALESCE(oldest_dropped_ts, ?), ?)
                               END
                         WHERE id = 1
                    """
                    try:
                        conn.execute(_BOOKKEEPING % _SET_BLOCKS,
                                     (dropped, blocks, stamp, oldest, oldest, oldest))
                    except Exception:
                        # The split is lost for this ledger; the DISCLOSURE is not.
                        # get_retention_status already reads rows_dropped as the block count
                        # on a table with no blocks_dropped column, which is exact for it:
                        # such a ledger predates the inventory writer.
                        conn.execute(_BOOKKEEPING % "",
                                     (dropped, stamp, oldest, oldest, oldest))
                    # 🔴 The CASE is load-bearing. When every dropped row carried a NULL
                    # timestamp (legacy rows reached by the SIZE rule) `oldest` is None, and
                    # the first draft substituted the CURRENT time -- recording "the oldest
                    # thing we deleted was from just now", a false statement about the user's
                    # own data generated by the code that destroyed it.
                    conn.commit()
                    result["oldest_dropped_ts"] = oldest
                except Exception:
                    # The rows are already gone and committed. Losing the disclosure is bad
                    # (P-57 says deletion must be visible) but undoing the trim is worse, and
                    # `ok` carries the failure rather than swallowing it.
                    result["ok"] = False
    except Exception:
        # Retention is housekeeping. It must never break a tool call, and a ledger we could
        # not trim is strictly better than an exception on the write path.
        result["ok"] = False
    finally:
        # 🔴 RESET ON EVERY OUTCOME, not just the successful one. This used to be the last
        # statement after the `try`, so both the exception path and the missing-file path
        # skipped it. Once the counter sat at the threshold and prunes kept failing, EVERY
        # subsequent write ran a full prune attempt -- measured at 7 attempts for 9 writes on
        # a threshold of 3. The amortization collapsed onto the tool-call path precisely
        # under the DB contention that makes prunes fail in the first place.
        #
        # ⚠️ ...BUT ONLY FOR THE LEDGER THE COUNTER IS ABOUT. The counter is incremented by
        # log_intercept, which always writes the DEFAULT ledger, so a `path=` prune of some
        # OTHER file resetting it credited ledger A's housekeeping to ledger B and pushed the
        # real ledger's next prune out by up to another full interval. Measured: counter at
        # 2, prune_ledger(path=<unrelated file>), counter 0.
        if path is None:
            _writes_since_prune = 0
            # Scoped to the default ledger for the same reason: a failed prune of some other
            # file says nothing about whether THIS one is being trimmed.
            #
            # `deletions_committed` and not just `ok`: a pass that deleted rows and then
            # failed to record the deletion DID trim the ledger. See the flag's comment.
            if result["ok"] or deletions_committed:
                _consecutive_prune_failures = 0
                _ledger_over_ceiling_at_failure = False
                _failed_ledger_path = None
            else:
                _consecutive_prune_failures += 1
                # Asked once per failure and sticky until a success clears it: if the ledger
                # was over the ceiling when a trim failed, the harm is real now and does not
                # become less real because the next failed attempt could not be read.
                if not _ledger_over_ceiling_at_failure:
                    _ledger_over_ceiling_at_failure = _ledger_exceeds_ceiling(path, cutoff, cap)
                # 🔴 RESOLVE THE PATH NOW, NOT WHEN THE WARNING PRINTS. DB_PATH is relative, and
                # the warning prints from atexit -- so a script that chdir()s after opening the
                # ledger made the summary name an absolute path to a file that does not exist,
                # sending the developer to fix permissions on the wrong thing. The only
                # actionable content in the warning is that path; resolving it late made it a
                # wrong answer instead of a missing one.
                # `path` is None in this branch by construction (see the `if path is None`
                # above), so this is always the default ledger.
                _failed_ledger_path = os.path.abspath(DB_PATH)

    return result


def failed_ledger_path():
    """The ledger path as it resolved WHEN the trim failed, or None.

    The warning's only actionable content is this path, and DB_PATH is relative. Resolving
    it at print time (atexit) after a chdir named a file that does not exist.
    """
    return _failed_ledger_path


def ledger_needs_trimming(path=None, margin=None):
    """Is this ledger past its ceiling RIGHT NOW, by more than one prune interval?

    🔴 A COUNTER IS USELESS ON THE STATUS SCREEN, AND CHECKING FIRST IS WHY THIS EXISTS.
    `agentx status` is a one-shot process that never attempts a prune, so
    `retention_failure_streak()` is always 0 there. Rendering the streak on that screen would
    have been a warning that cannot fire -- the same inert guard this feature already shipped
    once. Measured before writing it: rendering the screen leaves the streak at 0.

    So this asks the ledger instead of asking our bookkeeping. Read-only, because the failure
    it detects is "we cannot write", and a screen that reports on a problem must not need the
    thing that is broken.

    The margin keeps it honest about NORMAL operation: the amortized prune runs every
    _PRUNE_EVERY_WRITES writes, so a healthy ledger sits slightly over its cap between prunes
    and that is not a fault. Past the ceiling by more than one whole interval means nothing is
    trimming it.
    """
    slack = _PRUNE_EVERY_WRITES if margin is None else margin
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM event_log")
            if (cursor.fetchone()[0] or 0) > _RETENTION_MAX_ROWS + slack:
                return True
            cursor.execute(
                "SELECT COUNT(*) FROM event_log "
                "WHERE timestamp IS NOT NULL AND timestamp < ?",
                (time.time() - _RETENTION_DAYS * 86400,))
            return (cursor.fetchone()[0] or 0) > slack
    except Exception:
        # An unreadable ledger is a different problem with its own sentence
        # (ledger_empty_reason). Claiming a size fault we could not measure would be a guess.
        return False


def retention_failure_streak():
    """How many times in a row the ceiling has failed to apply to the default ledger."""
    return _consecutive_prune_failures


def retention_is_failing():
    """Has the ceiling stopped applying often enough that the developer should be told?

    🔴 THIS IS THE READER THE `ok` FLAG NEVER HAD. Without it, "we could not trim your ledger"
    and "there was nothing to trim" were the same silence, so a ledger growing without limit
    looked exactly like one comfortably inside the ceiling.

    TWO ways in, because a run of failures alone is unreachable in a short-lived process (see
    _PRUNE_FAILURES_BEFORE_WARNING): a run of failures, OR a single failure on a ledger that
    a read confirms is ALREADY over the ceiling. The second is the one that fires for the
    persistent causes -- a read-only file, a permission problem -- which recur across runs
    rather than within one.
    """
    if _consecutive_prune_failures >= _PRUNE_FAILURES_BEFORE_WARNING:
        return True
    return _consecutive_prune_failures >= 1 and _ledger_over_ceiling_at_failure


# Fewest observations before a RATE is worth printing instead of the two counts it came
# from. Not tuned, and it does not need to be: below roughly ten, one event moves the
# percentage ten points or more, so the number reports our sample size rather than the
# agent's behaviour. "100.0% recovery" from three rows is the case that prompted this.
_RATE_MIN_SAMPLE = 10


def format_ratio(numerator, denominator):
    """Render a ratio as a percentage, or decline to when the sample cannot support one.

    🔴 ONE ENTRY POINT, DELIBERATELY. The sample floor shipped on the status screen alone
    while the session summary went on printing `{:.1f}%` over a handful of rows, so a
    first-time user still saw "100.0%" after `agentx demo` -- the exact defect the floor was
    added to remove, on the surface a decorator user sees every single run. A rule that has
    to be remembered at each render site gets applied at some of them.

    No decimal above the floor either: at ten rows one event moves the rate ten points, so a
    tenth of a percent was never real.

    ⚠️ THE COUNTS ARE ALWAYS PRESENT. The first version returned the percentage ALONE above
    the floor, and the status line went from "14  (58% recovery)" to "58% recovered" -- the
    fix for an over-precise number quietly deleted the exact numbers underneath it. Caught by
    looking at the rendered screen, not by a test, because every assertion still passed.
    """
    total = denominator or 0
    hits = numerator or 0
    # 🔴 A ZERO DENOMINATOR MUST NOT ERASE A NON-ZERO NUMERATOR. This returned the literal
    # "0 of 0" for ANY input whose denominator was 0, discarding `hits` -- so the gateway
    # screen rendered "0 of 0 recovered" over three real recoveries. It is reachable, not
    # theoretical: gateway.py bumps `successful_agent_pivots` on any allow carrying a
    # receipt_id (a deterministic-floor block issues one and never bumps
    # `socratic_nudges_issued`), and the gateway itself documents a cross-restart case where
    # pivots outrun nudges -- which is why /v1/telemetry CLAMPS its own rate to 100. The CLI
    # renders the two raw counters instead, so both skews arrive here. Report what we hold.
    if hits > total:
        # No percentage: a ratio above 1 is a counter skew, not a recovery rate, and
        # `%.0f%%` would print "120%" or (below the sample floor) hide it entirely.
        return "%d of %d" % (hits, total)
    if total <= 0:
        return "0 of 0"
    if total < _RATE_MIN_SAMPLE:
        return "%d of %d" % (hits, total)

    # 🔴 ROUNDING MUST NOT MANUFACTURE A 0% OR A 100%. `%.0f` on 999/1000 printed "100%" --
    # a claim of perfect recovery over a run that had a failure in it -- and on 1/1000 it
    # printed "0%", reporting no recovery over a run that had one. Those are the two values
    # a reader treats as absolute rather than approximate, so they are the two that have to
    # be earned exactly. Everything between them rounds normally.
    pct = hits / total * 100
    if hits and pct < 1:
        rendered = "<1%"
    elif hits < total and pct > 99:
        rendered = ">99%"
    else:
        rendered = "%.0f%%" % pct
    return "%d of %d (%s)" % (hits, total, rendered)


def get_ledger_census(path=None):
    """ONE answer to "what does this ledger actually hold", for every screen that speaks
    about it. Returns counts only; never None.

    🔴 THE DEFECT THIS EXISTS TO PREVENT. The status screen chose between "here are your
    blocks" and "nothing is here" from `get_lifetime_stats`, which counts only CHALLENGED
    and RECOVERED. Under AGENTX_ENFORCEMENT=audit the ledger fills with WOULD_BLOCK rows
    that query cannot see, so a ledger holding four audited rows printed "no blocks remain
    in this ledger" while the retention line beside it reported rows_kept: 4. Reproduced
    end to end.

    The general rule, and the reason this is a function rather than a fix at that one site:
    the query that DECIDES whether to print a claim must be the same one the claim is ABOUT.
    Two queries over one table will disagree eventually, and the screen states the
    disagreement as fact.
    """
    census = {"total_rows": 0, "block_episodes": 0, "would_blocks": 0, "recoveries": 0,
              # 🔴 `interceptions` IS NOT `total_rows`, AND SINCE P-92 THAT MATTERS. Every row
              # here used to be a call we had an opinion about, so the two were the same
              # number and "does this ledger hold anything" answered "does it hold a block".
              # The audit inventory writes a row per call that PASSED, so total_rows now moves
              # on routine traffic. Any screen asking "is there a catch to talk about" must
              # read THIS one -- see ledger_empty_reason, where the difference printed a false
              # sentence about the user's own deleted blocks.
              "interceptions": 0,
              # 🔴 OUR OWN DEMO'S ROWS, COUNTED IN THE SAME PASS. `agentx demo --audit` writes
              # four ALLOWED rows and one WOULD_BLOCK into the reader's real ledger, and
              # `agentx status` reads this census to say what "your agent" did. The audit
              # screen learned to footnote them (get_call_inventory) and this reader did not,
              # so the same traffic was labelled ours on one screen and theirs on another.
              # Counted here rather than by a second query for the reason stated above: the
              # query that decides a sentence has to be the one the sentence is about.
              "would_blocks_from_demo": 0, "inventory_from_demo": 0}
    if not os.path.exists(path or DB_PATH):
        return census
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            # Bound HERE, in the function that uses them. The first cut of this change read
            # these from a sibling reader's locals -- a NameError on every `agentx status`
            # with a ledger on disk. Second time in one day; grep for the enclosing scope,
            # do not assume a name is in it.
            _ours_sql, _ours_params = _our_agents_clause()
            cursor.execute("""
                SELECT COUNT(*),
                       SUM(CASE WHEN status IN ('CHALLENGED', 'RECOVERED') THEN 1 ELSE 0 END),
                       SUM(CASE WHEN status = ? THEN 1 ELSE 0 END),
                       SUM(CASE WHEN status = 'RECOVERED' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN status IS NOT ? THEN 1 ELSE 0 END),
                       SUM(CASE WHEN status = ? AND {ours} THEN 1 ELSE 0 END),
                       SUM(CASE WHEN status IS ? AND {ours} THEN 1 ELSE 0 END)
                  FROM event_log
            """.format(ours=_ours_sql), (WOULD_BLOCK_STATUS, INVENTORY_STATUS,
                  WOULD_BLOCK_STATUS, *_ours_params,
                  INVENTORY_STATUS, *_ours_params))
            (total, episodes, would, recovered, intercepted,
             would_demo, inv_demo) = cursor.fetchone()
            census["total_rows"] = total or 0
            census["block_episodes"] = episodes or 0
            census["would_blocks"] = would or 0
            census["recoveries"] = recovered or 0
            census["interceptions"] = intercepted or 0
            census["would_blocks_from_demo"] = would_demo or 0
            census["inventory_from_demo"] = inv_demo or 0
    except Exception:
        # An unreadable ledger reports zeros, exactly like an empty one. Callers that must
        # tell those apart already use ledger_is_unreadable(); this function's contract is
        # counts, and inventing a third state here would give them two ways to ask.
        return census
    return census


def get_call_inventory(path=None, limit=25):
    """P-92: what the agent DID, aggregated per tool. Never raises; returns a dict.

    Reads the INVENTORY rows only. The blocks are `agentx insights`' subject and are counted
    here purely so the report can say how many of this tool's calls we objected to -- the two
    commands answer different questions and neither should quietly become the other.

    🔴 `window_start` IS NOT DECORATION. Retention drops rows, so a bare "412 calls" invites
    the reader to treat it as their agent's whole history when it is a 30-day / 10,000-row
    window. `covers_all` says whether anything was ever dropped, so the caller can state the
    honest sentence instead of guessing. P-97 ratified that a drop is reported, not silent.
    """
    # 🔴 `flagged_total` IS LOAD-BEARING ON THE EMPTY SCREEN, not a nicety. An agent whose
    # every call tripped a policy has an EMPTY INVENTORY and a non-empty ledger, and the
    # first version of this reader reported that as "No calls recorded yet" -- to a developer
    # who had just watched a catch scroll past. Found by the founder running it against
    # examples/01_self_healing_agent.py, which makes exactly one call, and it is a catch.
    # Without this count the caller cannot tell "nothing ran" from "everything that ran was
    # flagged", and those need opposite sentences.
    empty = {"tools": [], "total_calls": 0, "window_start": None, "covers_all": True,
             "distinct_tools": 0, "readable": True, "flagged_total": 0,
             "would_block_total": 0, "unclassified_total": 0, "flagged_from_demo": 0,
             "inventory_from_demo": 0, "viewable_total": 0}
    if not os.path.exists(path or DB_PATH):
        return empty
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT tool_name,
                       COUNT(*),
                       MAX(amount),
                       MIN(timestamp),
                       MAX(timestamp)
                  FROM event_log
                 WHERE status IS ?
              GROUP BY tool_name
              ORDER BY COUNT(*) DESC, tool_name ASC
            """, (INVENTORY_STATUS,))
            rows = cursor.fetchall()

            tools = []
            for name, calls, amount, first_ts, last_ts in rows[:limit]:
                # Argument names and classes are collected per tool rather than per row: the
                # question the report answers is "what does this tool take", and one row is
                # only one call's worth of that. A tool called with different optional
                # arguments would otherwise look like several different tools.
                # `tool_name IS ?`, not `= ?`, for the same reason as the status comparisons
                # below and throughout this function: SQLite's `=` against NULL yields NULL,
                # never true, so a row whose tool_name was never written matches nothing --
                # including its OWN group, which `GROUP BY tool_name` happily produced. The
                # rule was applied to one column and not the other in the same WHERE clause.
                cursor.execute(
                    "SELECT DISTINCT arg_names, target_class FROM event_log "
                    "WHERE status IS ? AND tool_name IS ?", (INVENTORY_STATUS, name))
                names, classes = set(), set()
                for arg_names, target_class in cursor.fetchall():
                    names.update(n for n in (arg_names or "").split(",") if n)
                    if target_class:
                        classes.add(target_class)
                # `IS NOT`, not `!=`. In SQLite `NULL != 'ALLOWED'` evaluates to NULL, which
                # is not true, so a legacy row with no status (the P-57 migration path
                # explicitly contemplates them) counted as NEITHER inventory nor flagged and
                # vanished from every sentence on the screen.
                # 🔴 AND NOT OUR OWN DEMO'S CATCH. `flagged_total` / `flagged_from_demo` were
                # split so the screen-level sentence could footnote our traffic; this per-tool
                # count never got the same split, and `agentx demo` writes its scripted
                # DROP TABLE under the tool name **run_sql** -- one of the most common names a
                # real user will have. Reproduced: three of the developer's own clean run_sql
                # calls rendered as "run_sql 3 ... plus 1 call flagged", where the flag was
                # ours. A footnote at the bottom of the screen does not undo an annotation on
                # THEIR row; that line is the one a reader takes as "my run_sql tripped a
                # policy". Excluded here and still disclosed in the screen-level count below.
                _not_ours_sql, _not_ours_params = _our_agents_clause(negate=True)
                cursor.execute(
                    "SELECT COUNT(*) FROM event_log "
                    "WHERE tool_name IS ? AND status IS NOT ? AND " + _not_ours_sql,
                    (name, INVENTORY_STATUS, *_not_ours_params))
                flagged = cursor.fetchone()[0] or 0
                tools.append({
                    "tool": name, "calls": calls, "max_amount": amount or 0.0,
                    "arg_names": sorted(names), "classes": sorted(classes),
                    "first_ts": first_ts, "last_ts": last_ts, "flagged": flagged,
                })

            cursor.execute(
                "SELECT COUNT(*), MIN(timestamp) FROM event_log WHERE status IS ?",
                (INVENTORY_STATUS,))
            total, window_start = cursor.fetchone()

            # 🔴 GUARDED SEPARATELY, BECAUSE A MISSING TABLE IS NOT AN UNREADABLE LEDGER.
            # ledger_retention is created by init_db, so reading ANOTHER process's ledger
            # (get_call_inventory(path=...)) can raise "no such table" on a file that reads
            # perfectly. Inside the outer try that turned the whole screen into "your ledger
            # could not be read" -- a false statement about their data, produced by a missing
            # counter table nobody was asking about.
            # 🔴 AND THE COUNT IT READS IS THE INVENTORY'S OWN. `covers_all` drives one
            # sentence -- "this ledger has been trimmed, so the counts below describe what was
            # KEPT, not everything your agent has ever done" -- printed directly above the
            # CALL counts. Read from `rows_dropped` it fired on any deletion at all, so an
            # enforce-only user whose BLOCKS were trimmed, who then switched to audit, got
            # that warning over an inventory that was completely intact.
            #
            # This is the last instance of the template the rest of this change already
            # fixed: the counter that decides a sentence has to be the counter that sentence
            # is about. The number is exact rather than a proxy -- both counters are
            # incremented over the same delete sets, so their difference IS the count of
            # inventory rows deleted.
            # ONE except, because both failures mean the same thing here: a ledger with no
            # ledger_retention table, and one whose table predates `blocks_dropped`, BOTH
            # predate the inventory writer -- so no inventory row can ever have been dropped
            # out of either. None is exact for them, not a fallback guess. (Written as two
            # nested handlers first; the outer one was unreachable, which is a branch nobody
            # can test and everybody later has to reason about.)
            try:
                cursor.execute(
                    "SELECT rows_dropped - blocks_dropped FROM ledger_retention WHERE id = 1")
                dropped_row = cursor.fetchone()
            except Exception:
                dropped_row = None

            # 🔴 COUNTED OVER THE WHOLE LEDGER, AND EVERY CALLER MUST USE THIS RATHER THAN
            # SUMMING THE `tools` LIST. That sum is the defect this whole reader keeps
            # producing: `tools` holds only tools with INVENTORY rows, so a tool flagged on
            # every call is absent from it and contributes zero, and the screen announces
            # "nothing tripped a policy" over a ledger full of catches. The list is also
            # truncated to `limit`, so tools past the cut silently stop counting too.
            #
            # The rule, stated once: a sentence about the ledger is computed FROM the ledger,
            # never from the subset the screen happens to be showing.
            cursor.execute("SELECT COUNT(*) FROM event_log WHERE status IS NOT ?",
                           (INVENTORY_STATUS,))
            flagged_total = cursor.fetchone()[0] or 0

            # 🔴 OUR OWN DEMO IS NOT "WHAT YOUR AGENT DID". `agentx demo` writes a catch under
            # agent_id 'demo_cli', and the demo footer sends the reader straight here -- so on
            # the very first run of the ladder this screen reported OUR scripted call under a
            # header naming THEIR agent. `get_block_frequency` already takes exclude_agents
            # for exactly this; the counts below carry the split instead of hiding it, the
            # same way `agentx insights` footnotes its demo rows rather than dropping them.
            _ours_sql, _ours_params = _our_agents_clause()
            cursor.execute(
                "SELECT COUNT(*) FROM event_log WHERE status IS NOT ? AND " + _ours_sql,
                (INVENTORY_STATUS, *_ours_params))
            flagged_from_demo = cursor.fetchone()[0] or 0

            # 🔴 THE SAME SPLIT, ON THE OTHER STATUS, AND IT WAS MISSING. The comment above
            # only ever contemplated our demo's CATCH, because at the time that was the only
            # row `agentx demo` could write: it pins enforce, and enforce writes no inventory.
            # `agentx demo --audit` writes four ALLOWED rows under the same agent id, and
            # without this they are listed, tool by tool, under a header reading WHAT YOUR
            # AGENT DID. Same defect as the flagged count, one status over.
            #
            # ⚠️ COUNTED, NOT EXCLUDED, and that is the opposite call to the per-tool `flagged`
            # number above. There the demo row ANNOTATED a tool the developer also owns
            # (`run_sql`), so it had to come out. Here the rows ARE the table: a reader who
            # ran `agentx demo --audit` to see a populated screen and got an empty one would
            # have been shown nothing at all. So they stay, and the screen says whose they are.
            cursor.execute(
                "SELECT COUNT(*) FROM event_log WHERE status IS ? AND " + _ours_sql,
                (INVENTORY_STATUS, *_ours_params))
            inventory_from_demo = cursor.fetchone()[0] or 0

            # Split out because the two need DIFFERENT WORDS. A WOULD_BLOCK is a call audit
            # recorded and let RUN; a CHALLENGED/RECOVERED row is a call that was genuinely
            # stopped in enforce mode. On a mixed ledger -- enforce yesterday, audit today --
            # one sentence saying "would have been stopped" is false about half the rows.
            cursor.execute("SELECT COUNT(*) FROM event_log WHERE status IS ?",
                           (WOULD_BLOCK_STATUS,))
            would_block_total = cursor.fetchone()[0] or 0

            # Rows with NO status at all (legacy, pre-P-57 migration). They are counted in
            # flagged_total because a row we cannot classify is still a row -- but every
            # `agentx insights` reader filters on CHALLENGED / RECOVERED / WOULD_BLOCK, so
            # sending someone there to "see them" shows nothing. The caller needs to know how
            # many of the flagged are actually VIEWABLE before it offers that command.
            cursor.execute("SELECT COUNT(*) FROM event_log WHERE status IS NULL")
            unclassified_total = cursor.fetchone()[0] or 0

            # What `agentx insights` can actually SHOW. Deriving this as "flagged minus NULL"
            # assumed every non-NULL status is renderable there, and that reader filters on
            # exactly these three -- so any other legacy string would still have sent the
            # developer to a screen with nothing on it.
            cursor.execute(
                "SELECT COUNT(*) FROM event_log WHERE status IN (?, ?, ?)",
                ("CHALLENGED", "RECOVERED", WOULD_BLOCK_STATUS))
            viewable_total = cursor.fetchone()[0] or 0

            return {
                "tools": tools,
                "total_calls": total or 0,
                "distinct_tools": len(rows),
                "window_start": window_start,
                "covers_all": not (dropped_row and dropped_row[0]),
                "readable": True,
                "flagged_total": flagged_total,
                "would_block_total": would_block_total,
                "unclassified_total": unclassified_total,
                "viewable_total": viewable_total,
                "flagged_from_demo": flagged_from_demo,
                "inventory_from_demo": inventory_from_demo,
            }
    except Exception:
        # 🔴 A READ FAILURE IS NOT AN EMPTY LEDGER, and conflating them is the exact defect
        # #326 had to fix on the screen next door: a locked or corrupt file told the
        # developer nothing had ever happened. The caller renders these two differently.
        out = dict(empty)
        out["readable"] = False
        return out


def get_retention_status(path=None):
    """What retention has removed, for the readouts. Returns None when nothing was dropped.

    🔴 The reason this exists at all: P-57 deleted a whole ledger silently and the rule
    taken from it was that deletion is never invisible to the person whose data it was.
    A counter nobody reads is the same silence with extra steps, so `agentx insights` and
    the session summary both read this.
    """
    if not os.path.exists(path or DB_PATH):
        return None
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT rows_dropped, last_prune_ts, oldest_dropped_ts, "
                               "blocks_dropped FROM ledger_retention WHERE id = 1")
                row = cursor.fetchone()
            except Exception:
                # A ledger this build has never pruned still has the pre-P-92 table. Every
                # row it dropped was a catch (ALLOWED rows did not exist then), so
                # rows_dropped IS the block count for it -- the same equivalence
                # _ensure_retention_columns backfills on the next prune.
                cursor.execute("SELECT rows_dropped, last_prune_ts, oldest_dropped_ts, "
                               "rows_dropped FROM ledger_retention WHERE id = 1")
                row = cursor.fetchone()
            if not row or not row[0]:
                return None
            cursor.execute("SELECT COUNT(*), MIN(timestamp) FROM event_log")
            kept, oldest_kept = cursor.fetchone()
            return {
                "rows_dropped": row[0],
                # What the three "did you delete my catches" screens must read. See
                # _RETENTION_COLUMNS: rows_dropped now moves on routine traffic by design.
                "blocks_dropped": row[3] or 0,
                "last_prune_ts": row[1],
                "oldest_dropped_ts": row[2],
                "rows_kept": kept or 0,
                "oldest_kept_ts": oldest_kept,
                # 🔴 NAMED "current_" BECAUSE THEY ARE NOT THE LIMITS THOSE ROWS DIED UNDER.
                # `rows_dropped` is cumulative over every prune this file has ever seen; these
                # two are read live from the module constants. A caller that renders them as
                # "N dropped under the 30d / 10,000 limit" states a REASON that may never have
                # applied -- measured: a prune with max_rows=2 reports 10000. Harmless while
                # the constants are frozen, a false statement the day they are tuned, so the
                # key name is the guard rather than a comment at each call site.
                "current_max_age_days": _RETENTION_DAYS,
                "current_max_rows": _RETENTION_MAX_ROWS,
            }
    except Exception:
        # A missing ledger_retention table (a ledger created before this shipped and not yet
        # reopened) is indistinguishable from "nothing dropped", and both mean the same
        # thing to a reader: there is no deletion to disclose.
        return None

# Update your log_intercept function signature to accept the new ID!
# FIXED: Signature updated to accept trace_id and agent_id
def count_call_for_pulse(tool_name, stats, stats_lock=None):
    """Move the P-92 funnel counters for one recorded call. Best-effort; never raises.

    `stats_lock` is the caller's own lock, taken ONLY around the mutation. The decorator
    shares one process-global stats dict across threads (a swarm, or an async tool whose
    decision core runs in an executor), where a bare `+= 1` can be lost; the MCP proxy owns
    its dict on one loop and passes nothing. The lock deliberately does not span the ledger
    write in record_call -- that lock is documented as never held across I/O, and widening it
    to cover a SQLite write would put file contention on the developer's tool-call path.

    🔴 IT LIVES HERE, BESIDE THE WRITER, BECAUSE THE DECORATOR AND THE MCP PROXY BOTH WRITE
    AND ONLY ONE OF THEM WAS COUNTING. The proxy recorded inventory rows and left
    `audit_calls` at 0, and `mcp_proxy.main` emits its own pulse -- so every MCP install
    would have reported "never ran audit" while writing a full inventory, and the funnel row
    added to measure this rung would have read 0 for that entire population. A zero there
    says "nobody climbed the rung", which is the exact conclusion the instrumentation exists
    to test.

    `stats` is the caller's own session dict, the same pattern `_note_block_category` uses so
    the two keyless surfaces share one implementation instead of each keeping a copy. The
    tool NAMES are held locally only to size the set; only the COUNT ever leaves.
    """
    try:
        if stats_lock is not None:
            with stats_lock:
                _bump_audit_counters(tool_name, stats)
        else:
            _bump_audit_counters(tool_name, stats)
    except Exception:
        pass


# 🔴 THE SET IS BOUNDED, BECAUSE ON ONE OF THE TWO SURFACES ITS CONTENTS ARE NOT OURS. The
# decorator's tool names come from decorated functions, so the set can only grow to the size
# of the developer's own codebase. The MCP proxy's come from `params["name"]` on an UNTRUSTED
# client stream, in a process that stays up for the whole session -- so a client that varies
# the tool name (a generated dispatcher, a fuzzer, a buggy loop) grows this set without limit
# on the developer's machine, holding strings we only ever needed to COUNT. Above the cap the
# count stops rising, which is the right failure: `audit_tools` exists to separate "one tool
# in a loop" from "a real agent", and both answers are already given long before 1,000.
_MAX_AUDIT_TOOL_NAMES = 1000


def _bump_audit_counters(tool_name, stats):
    stats["audit_calls"] = stats.get("audit_calls", 0) + 1
    names = stats.setdefault("audit_tool_names", set())
    if len(names) < _MAX_AUDIT_TOOL_NAMES:
        names.add(tool_name)
    stats["audit_tools"] = len(names)


def record_call(trace_id, agent_id, tool_name, arguments=None, stats=None, stats_lock=None):
    """P-92: record ONE call that passed, in audit posture. Best-effort, never raises.

    The inventory writer. Deliberately a thin wrapper over log_intercept rather than its own
    INSERT, so it inherits the retention ceiling that hangs off that function instead of
    having to remember it -- a rule repeated at each call site lands on some of them.

    Callers pass the developer's raw kwargs; _call_shape reduces them to names, a magnitude
    bucket and a bounded class BEFORE anything reaches SQL, so no call site can hand a value
    to the ledger even by accident. That ordering is the guarantee, and
    test_audit_inventory_records_no_values.py is what stops a future edit from inverting it.
    """
    names, amount, target_class = _call_shape(tool_name, arguments)
    # Counted BEFORE the write, and outside its failure mode. log_intercept swallows its own
    # errors, so an unwritable ledger is invisible from here -- and that install is exactly
    # the one we most want on the funnel, not the one we quietly drop off it.
    #
    # ⚠️ THE TRADEOFF, NAMED SO THE NEXT READER SEES IT WAS CHOSEN. A review flagged the
    # other reading: on a locked or read-only ledger this pulses audit_calls > 0 with zero
    # rows written, so `ran_audit` counts a climb that produced nothing readable. Both
    # framings are defensible and this one is deliberate -- `ran_audit` answers "did anyone
    # run their agent under audit", which is TRUE whether or not our own write then failed,
    # and gating it on the write would make OUR ledger bug look like THEIR non-adoption. That
    # is the "a zero must earn its meaning" trap pointing the other way. The write failure is
    # not lost either: P-97's retention/ceiling warning surfaces an unwritable ledger on its
    # own surface. Closing the gap properly needs log_intercept to report whether the insert
    # committed, which is a change to a hot path with many callers and does not belong here.
    #
    # Counted HERE rather than at the call sites, so a third surface cannot record a call and
    # forget to count it, which is precisely what the MCP path did.
    # 🔴 THE ROW IS WRITTEN, THE COUNTER IS NOT, AND THE ASYMMETRY IS THE POINT. The screen
    # needs these rows -- `agentx demo --audit` exists so the reader sees a populated table --
    # and it labels them (`inventory_from_demo`). The pulse cannot label anything: it carries
    # coarse ints with no room for provenance, so on that surface the only honest options are
    # "count ours as theirs" or "do not count ours". See is_demo_agent.
    if stats is not None and not is_demo_agent(agent_id):
        count_call_for_pulse(tool_name, stats, stats_lock)
    log_intercept(trace_id, agent_id, tool_name, None, None, INVENTORY_STATUS,
                  arg_names=names, amount=amount, target_class=target_class)


def log_intercept(trace_id, agent_id, tool_name, policy_id, policy_name, status, tokens=None, time_saved=None,
                  arg_names=None, amount=0.0, target_class=None):
    # 🔴 THE DEFAULTS USED TO BE 1500 TOKENS AND 5 MINUTES, AND NO CALL SITE HAS EVER
    # PASSED A VALUE. Every row therefore carried the same invented pair, and the readers
    # summed them into "Tokens Saved: ~3000" on the session summary and "saved ~1500
    # tokens" on the shareable block card. That is a constant times a row count presented
    # as a measurement. Nothing on this path can observe what a blocked call would have
    # spent, so the honest value is NULL: we do not know. The columns stay (they are in
    # the migration surface, and a future gateway-side measurement has somewhere to land),
    # the fabricated numbers do not.
    # Best-effort: this runs on the online-block path OUTSIDE the wrapper's other
    # guards, so a transient SQLite lock (concurrent in-process writers) must not
    # propagate and break the tool call. The block itself already stood regardless.
    # _connection() guarantees the handle is closed even when the write raises.
    #
    # 🔴 THE CATCH IS WRITTEN EVEN WHEN THE P-92 COLUMNS ARE NOT THERE. Naming
    # arg_names/amount/target_class unconditionally made this INSERT fail with "no such
    # column" on any ledger the migration had not reached -- and because this whole function
    # is best-effort, that failure is SILENT and takes EVERY row with it, blocks included.
    # Measured: a pre-P-92 event_log plus one `log_intercept(... 'CHALLENGED')` left 0 rows
    # where the old code left 1. `_upgrade_existing_ledger` reaches that state on any WRITE
    # failure (it returns False and says "this session may not be recorded"), and its
    # `unaddable` branch promises in as many words that "the ledger keeps working without the
    # column" -- a promise this statement had quietly cancelled.
    #
    # So the retry is the LEGACY column set. The shape is lost for that row; the CATCH is
    # not, and the catch is the record this product exists to keep. An inventory row retried
    # this way still lands as an ALLOWED row with a NULL shape, which every reader already
    # handles (get_call_inventory's arg_names/target_class are read with `or ""`).
    _COLUMNS = ("timestamp, trace_id, agent_id, tool_name, policy_id, policy_name, status, "
                "tokens_saved, time_saved_mins")
    _values = (time.time(), trace_id, agent_id, tool_name, policy_id, policy_name, status,
               tokens, time_saved)
    try:
        with _connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO event_log (%s, arg_names, amount, target_class) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" % _COLUMNS,
                    _values + (arg_names, amount if amount is not None else 0.0, target_class))
            except sqlite3.OperationalError:
                cursor.execute(
                    "INSERT INTO event_log (%s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)" % _COLUMNS,
                    _values)
            conn.commit()
    except Exception:
        pass

    # 🔴 ONE ENTRY POINT FOR RETENTION, DELIBERATELY. Every ledger writer in the SDK goes
    # through this function, so hanging the amortized prune here means a future writer --
    # P-92's every-call inventory above all, which is the reason the ceiling exists --
    # inherits it instead of having to remember it. A rule that must be repeated at each
    # call site reliably lands on some of them.
    #
    # The counter is deliberately unlocked: two threads racing it can skip or repeat a
    # prune, and both are harmless (prune_ledger is bounded, idempotent and swallows its own
    # errors). A lock on the write path would cost more than the miss.
    global _writes_since_prune
    _writes_since_prune += 1
    if _writes_since_prune >= _PRUNE_EVERY_WRITES:
        prune_ledger()

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

        # 🔴 REMOVED: total_critical, total_tokens, total_time.
        #
        # `total_critical` counted a hardcoded TWO policy names while the session counter
        # it printed beside incremented on EVERY block, so the summary rendered
        # "Critical Blocks: 2 | Cumulative: 1" about the same two blocks. Three sites had
        # three different ideas of "critical" (unconditional keyless, a four-name gateway
        # list, this two-name query) and no severity data exists anywhere to arbitrate
        # between them. A word we cannot key on data is not a metric; the honest fix is to
        # stop printing it rather than to pick a list and maintain it. `Intercepts` already
        # answers "how many blocks", from one definition.
        #
        # `total_tokens` / `total_time` summed the invented per-row constants documented
        # on log_intercept above.

        # 2. Total Self-Corrections (recovered episodes — the recovery numerator)
        cursor.execute("SELECT COUNT(*) FROM event_log WHERE status = 'RECOVERED'")
        total_recoveries = cursor.fetchone()[0] or 0

        # 3. Top Offender (Select policy_name, Group by policy_id)
        #
        # policy_name IS NOT NULL because a MIGRATED legacy row has no policy identity, and
        # since P-57 those rows survive into the readers for the first time — the wipe used
        # to delete them. Without the filter the NULL group can win the count, and
        # `top_offender_row[0]` is then the object None rather than the "None" string the
        # fallback below intends, which cli.py:68 prints verbatim as "Top offender: None".
        # Such rows still COUNT as challenge episodes above; they just cannot be named.
        cursor.execute(f'''
            SELECT policy_name, COUNT(*) as c
            FROM event_log
            WHERE {CHALLENGE_EPISODE} AND policy_name IS NOT NULL
            GROUP BY policy_id
            ORDER BY c DESC LIMIT 1
        ''')
        top_offender_row = cursor.fetchone()

    return {
        "total_intercepts": total_intercepts,
        "top_offender": top_offender_row[0] if top_offender_row else "None",
        "total_self_corrections": total_recoveries
    }
    
def get_recent_blocks(limit=1):
    """Return the most recent block episodes from the local ledger, newest first.

    Powers `agentx share`: the shareable block card is built ONLY from these
    abstract, privacy-safe fields (policy class, the dev's own tool name, the
    verdict, and when) — never a raw query or payload, because the ledger never
    stores one. The tokens/time columns still come back and the card no longer
    renders them: nothing measures those, so they are written NULL. A still-open block reads CHALLENGED; one
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


# A policy fired by a hundred tools would otherwise put a hundred names on one line of an
# interactive screen. Bounded HERE, at the reader, so every caller inherits the cap instead
# of each one remembering it -- and the count beside the list stays the true one, because it
# comes from COUNT(*) over the rows, never from the length of this list.
_MAX_TOOLS_PER_POLICY = 6


def _tool_list(concat):
    """`GROUP_CONCAT` output -> a sorted, bounded list of tool names. Pure; never raises.

    Returns (names, hidden_count) so a caller can say "and 3 more" rather than silently
    showing a subset -- the truncation this project keeps having to make visible.
    """
    names = sorted({n.strip() for n in (concat or "").split(",") if n and n.strip()})
    if len(names) <= _MAX_TOOLS_PER_POLICY:
        return names, 0
    return names[:_MAX_TOOLS_PER_POLICY], len(names) - _MAX_TOOLS_PER_POLICY


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


def ledger_is_unreadable(path=None):
    """True when the ledger file EXISTS but cannot be read.

    🔴 THE READERS SWALLOW THEIR OWN ERRORS, so a caller cannot tell "nothing was blocked"
    from "we could not tell". `_grouped_policy_rows` ends in `except Exception: return
    None` and `get_block_frequency` maps that to `[]`, which is the same value a genuinely
    empty ledger produces. A screen that says "the floor has not stopped anything here" on
    a locked or corrupt store is the P-76 wrong answer arriving by a different route --
    stating a fact about the WORLD when all we hold is a fact about a READ.

    A missing file is NOT an error: nothing has been recorded, which is the honest empty
    state. Returns False on anything it cannot establish, so this can never be the reason
    a screen fails to render.

    ⚠️ AND NEITHER IS A FILE WITH NO event_log TABLE. `sqlite3.connect` CREATES a 0-byte
    file just by opening it, so the ledger exists from the first connection attempt and the
    schema arrives separately -- and init_db is documented as able to fail between the two
    (a read-only directory, a full disk, the contended migration prune_ledger self-heals
    against). Treating that as "unreadable" told the user their ledger may be CORRUPT and
    that "the blocks it holds are not recoverable", about an empty file holding nothing.
    A schema we have not created yet is an empty ledger, not a damaged one.

    🔴 THE PROBE HAS TO BE AS DEMANDING AS THE READS IT SPEAKS FOR. It was `SELECT 1 FROM
    event_log LIMIT 1`, which needs no column at all, while every screen selects NAMED
    columns -- `get_recent_blocks` asks for tokens_saved/time_saved_mins, `get_block_frequency`
    for policy_id/policy_name. None of the read-only screens (`agentx status`, `share`,
    `insights`) ever calls init_db, so a ledger written by an older SDK, or one whose
    migration failed, keeps a stale event_log: the trivial probe passed, the real query
    raised, the reader swallowed it and `agentx share` printed "No block on record in this
    ledger" over a CHALLENGED row and sent the developer to `agentx demo`. Measured, not
    theorised. The probe is generated from _EVENT_LOG_COLUMNS -- the same list the CREATE and
    the migration come from -- so it fails exactly when a reader would."""
    p = path or DB_PATH
    if not os.path.exists(p):
        return False
    try:
        with _connection(p) as conn:
            has_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_log'"
            ).fetchone()
            if not has_table:
                return False          # opened fine; simply not initialised yet
            conn.execute(
                "SELECT %s FROM event_log LIMIT 1"
                % ", ".join(name for name, _ in _EVENT_LOG_COLUMNS)
            ).fetchone()
        return False
    except Exception:
        return True


def ledger_empty_reason(path=None):
    """WHY is a screen about to print "nothing here"? ONE answer, for every empty state.

    🔴 THE CLASS THIS CLOSES. `ledger_is_unreadable` shipped, and exactly one of the four
    screens that read this ledger consulted it -- `agentx insights`. `agentx status` and
    `agentx share` each state an empty ledger as a fact about the agents, so a store that is
    on disk and will not open printed "no blocks recorded in this ledger yet" and routed the
    developer to `agentx demo`. That is the P-76 wrong answer, and it is the one this ledger
    must never give. Retention added a SECOND qualifier ("we deleted the evidence") and it
    landed on three of the four in the same way.

    A rule that has to be remembered at each empty state gets applied at some of them, so
    the decision lives here and the screens choose wording from the answer:

      "unreadable" -- the file is there and will not open. We know nothing; say so.
      "trimmed"    -- it opened and holds no catch, but OUR retention deleted rows out of it.
      "empty"      -- it opened, holds no catch, and we removed nothing. The only case in
                      which "nothing has been blocked yet" is a true sentence.
      "not_empty"  -- it opened and HAS catches. There is no emptiness to explain.

    🔴 "HOLDS NO CATCH", NOT "HOLDS NO ROWS", AND P-92 IS WHY. Every caller asks this from
    inside a branch that is about to say something about BLOCKS, and the audit inventory now
    writes a row per call that PASSED. Reading `total_rows` here meant one ordinary call under
    audit flipped the answer to "not_empty" -- so a developer whose real block had just been
    deleted by our own retention was told "no blocks recorded in this ledger yet", the exact
    false-empty "yet" claim this function exists to prevent, generated by the code that
    destroyed the evidence. Reproduced: one CHALLENGED row aged past the cutoff plus three
    audit calls, and `agentx status` printed "yet".

    🔴 WHY "not_empty" EXISTS, AND IT IS A TRAP I BUILT. The first version answered "trimmed"
    whenever retention had EVER dropped a row, without checking the ledger was empty now --
    while this docstring defined that value as "it opened AND IS EMPTY". It happened to be
    harmless because all three callers ask from inside an empty branch. But the tripwire in
    sdk_tests/test_ledger_emptiness_tripwire.py actively pushes every FUTURE ledger screen to
    call this function, so the first one that asks outside an empty branch would have printed
    "no blocks remain in this ledger" over a ledger holding hundreds of live blocks.

    A guard that is only correct because of where its callers happen to stand is not a guard;
    it is a coincidence with a good docstring. It answers the question it is asked now.
    """
    if ledger_is_unreadable(path):
        return "unreadable"
    if get_ledger_census(path)["interceptions"] > 0:
        return "not_empty"
    # 🔴 `blocks_dropped`, NOT "did retention run". Same defect as the census line above it,
    # one round later and one table over: P-92 made routine traffic the FIRST thing retention
    # evicts, so `rows_dropped` moves on ledgers that have never held a block -- and all three
    # callers then said "no blocks REMAIN in this ledger" plus a dropped count to a developer
    # whose catches were never touched, because there were none. "remain" versus "yet" is the
    # entire distinction this function exists to draw.
    retention = get_retention_status(path)
    if retention and retention.get("blocks_dropped"):
        return "trimmed"
    return "empty"


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
    # 🔴 THE TOOL TRAVELS WITH THE POLICY, in the query that already groups them. Every
    # flagged row stores BOTH `tool_name` and `policy_name`, and until now no screen printed
    # them together: `agentx insights` named the policy, `agentx audit` annotated the tool,
    # and "which of my tools tripped which control" -- the first question a security reviewer
    # asks -- could not be answered from either. Founder-caught reading his own output.
    #
    # GROUP_CONCAT skips NULL, so a legacy row with no tool_name drops out of the list rather
    # than rendering as an empty name; the COUNT above still includes it, which is the honest
    # split (we know it fired, we do not know what ran).
    rows = _grouped_policy_rows(
        path, "status IN ('CHALLENGED', 'RECOVERED')", exclude_agents,
        extra_select="SUM(CASE WHEN status = 'RECOVERED' THEN 1 ELSE 0 END), "
                     "GROUP_CONCAT(DISTINCT tool_name)")
    if rows is None:
        return []
    out = []
    for policy_name, policy_id, blocks, recoveries, tools in rows:
        blocks = blocks or 0
        recoveries = recoveries or 0
        out.append({
            "policy_id": policy_id,
            "policy_name": policy_name,
            "blocks": blocks,
            "recoveries": recoveries,
            "recovery_rate": round(recoveries / blocks, 3) if blocks else 0.0,
            "tools": _tool_list(tools),
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
    rows = _grouped_policy_rows(path, f"status = '{WOULD_BLOCK_STATUS}'", exclude_agents,
                                extra_select="GROUP_CONCAT(DISTINCT tool_name)")
    if rows is None:
        return {"total": 0, "policies": []}
    policies = [
        {"policy_id": pid, "policy_name": pname, "would_blocks": wb or 0,
         "tools": _tool_list(tools)}
        for pname, pid, wb, tools in rows
    ]
    return {"total": sum(row["would_blocks"] for row in policies), "policies": policies}