import atexit
import json
import re
import sqlite3
import threading
import time
import os
import sys
from contextlib import contextmanager

# Hidden file in the directory where the developer runs their agent.
#
# RELATIVE on purpose: it resolves against the process cwd, which is what you want for the
# @agentx_protect decorator, where the process runs in the developer's project. It is the WRONG
# default for MCP, where the host launches the proxy from an arbitrary directory, so the proxy
# overrides this global at startup (see mcp_proxy._mcp_ledger_path). The default is deliberately
# left alone so no existing decorator user's ledger moves.
#
# 🔴 `AGENTX_LEDGER_PATH` MOVES IT. The TypeScript door has `AGENTX_TS_LEDGER_PATH` and the MCP
# door has `AGENTX_MCP_LEDGER_PATH`; this one was added last, because until then the only way to
# move the decorator's ledger was to reach in and assign this global -- which is exactly what
# `mcp_proxy` does, and what every caller outside this package would have had to copy.
#
# It matters for a run whose cwd is not the project: CI, a container, a scheduled job. Without
# it those write `.agentx.db` into whatever directory the runner happened to start in, and the
# next run starts from an empty ledger with nothing saying so.
#
# ⚠️ READ AT IMPORT, NOT PER CALL, WHICH IS A REAL DIFFERENCE FROM THE OTHER TWO DOORS.
# `mcp_proxy._ledger_path()` and the TS `ledgerPath()` both resolve their variable when called,
# so setting it late still works there. Here the variable is consulted once, because this is a
# module global that callers read directly (`path or DB_PATH`) and that the proxy REASSIGNS at
# startup -- turning it into a function would change 41 call sites and break that override. So:
# set it before the process starts. Setting it afterwards does nothing, and a test that wants a
# different path should assign `db.DB_PATH` the way the root conftest already does.
DB_PATH = os.environ.get("AGENTX_LEDGER_PATH") or ".agentx.db"

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

# The INVENTORY status (P-92): one row per call that PASSED, written by the same two keyless
# surfaces. Every other status in this ledger records a call we had an opinion about; this is
# the one that records a call we did not.
#
# ⚠️ IT SAID "written only in audit mode", WHICH P-112's ENFORCE HALF INVERTED. This is the
# module-level definition of the status the whole feature turns on, so a reader who trusts it
# re-derives the old rule and concludes the default posture writes nothing. Both postures
# write these now; audit posture means blocking is off, and nothing more.
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
#
# 🔴 AND THE OTHER NAMES THE SHIPPED EXAMPLES ACTUALLY WRITE UNDER (no count here on
# purpose: a maintained number beside the list it counts goes stale before the list does).
# The comment above
# said this tuple covered "the shipped examples/ scripts" and it covered exactly ONE of them
# (12_audit_what_your_agent_did.py, the file it was added for). Every other example predates
# the constant and names its own agent, so `examples/00_quickstart_pip.py` -- the one file we
# tell a brand-new developer to run -- was disowned by nothing.
#
# Harmless while this tuple only fed `agentx audit` labelling; not harmless from 0.4.29, when
# `own_agent_block` started asking "was somebody caught in code THEY wrote". A quickstart run
# answered yes, which manufactures the exact evidence that field exists to look for, on the
# first command a stranger runs. Both halves of the rule now have to hold, so the polarity is
# pinned in sdk_tests/test_our_agent_ids.py: every id an example runs under is here, and no
# id here is one an example does not use.
#
# ⚠️ STILL A CLOSED SET OF EXACT NAMES, never a `demo_` prefix -- see is_our_agent below. A
# developer who calls their own agent `demo_billing` must keep their rows.
_EXAMPLE_AGENT_IDS = (
    "demo_quickstart_agent",      # 00_quickstart_pip.py
    "demo_db_agent",              # 01_self_healing_agent.py
    "demo_support_agent",         # 03_outbound_dlp_scrubbing.py
    "demo_stubborn_agent",        # 04_circuit_breaker_demo.py
    "demo_dlp_agent",             # 05_zero_knowledge_dlp.py
    "demo_soc_agent",             # 06_hitl_escalation.py
    "demo_react_sim_agent",       # 07_pure_react_agent_simulation.py
    "demo_frictionless_agent",    # 08_frictionless_agent_protection.py
)
# NOT here on purpose: 02 / 09 / 10 / 11 drive the gateway client directly and never wrap a
# tool, so their agent ids cannot reach the local ledger or the session counters this set
# gates. Claiming a name we do not need is not free -- it disowns any developer who picks it.
OUR_AGENT_IDS = (DEMO_AGENT_ID, EXAMPLE_AGENT_ID) + _EXAMPLE_AGENT_IDS


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


# --- THE HOT WRITE PATH (P-112 enforce half) ------------------------------------------
#
# 🔴 WHY THIS EXISTS AND WHY IT IS NOT `_connection`. Once the DEFAULT posture records, this
# writer runs inside every protected tool call instead of only on the rare block. `_connection`
# opens a fresh handle per call, and that is far too slow to sit on that path. MEASURED on
# Windows 11 / py3.12, warmup 100 then 1000 iterations, against a 178 us protected call:
#
#     connect + insert + commit + close, per call (what _connection does)   6620 us
#     persistent handle, NO WAL                                             3456 us
#     persistent handle + WAL                                                535 us
#     persistent handle + WAL + synchronous=NORMAL                            66 us
#
# ⚠️ TWO THINGS THAT MEASUREMENT OVERTURNED, recorded because the old numbers are still quoted.
# (1) "~95% of the cost is opening the connection" is FALSE here -- the connection is under
# half. The fsyncs together cost more: journal ~2921 us, commit ~469 us, the INSERT itself 66 us.
# (2) A persistent handle ALONE is not enough. Without WAL, journal_mode=DELETE writes and
# fsyncs a rollback journal per commit, so plain persistence still costs +1937% on the baseline.
# WAL is REQUIRED, not an optimisation to reach for later.
#
# 🔴 AND THE INSERT IS NOT WHAT THIS PATH COSTS ONCE THE LEDGER IS FULL. THE PRUNE IS.
# `_writes_since_prune` fires `prune_ledger()` inline every 200 writes. Before this change the
# default posture wrote ~nothing, so that effectively never ran from a protected call. It now
# runs on a ledger this same change drives every install to the 10,000-row cap, where the
# prune has real rows to delete and `event_log` carries no indexes. Measured by stubbing
# `prune_ledger` and interleaving, on a ledger seeded to 9,000 rows:
#
#     record_call with the prune stubbed out                                  25.7 us
#     record_call as it ships (prune amortized over 200 writes)              123.3 us
#     -> the prune is ~98 us per call, about 79% of what recording costs
#
# ⚠️ SO QUOTE 123 us FOR THE STEADY STATE, NOT 97. The 97 us figure this branch reported was
# measured on a FRESH ledger, where the prune's scans find nothing to delete and are cheap. It
# is the right number for a new install and the wrong one for the state this change creates.
# Against a 178-328 us protected call that is roughly +38% to +69%, not the +30% to +55% first
# reported. An earlier note here read "prune +66.6 us per call, 6% of recording", which cannot
# be both and was not re-derived; these numbers were.
#
# NOT CHANGED HERE, because the two cheap fixes both alter something ratified: raising the
# 200-write cadence lets the ledger overshoot P-97's cap between prunes, and indexing
# `event_log` is a schema migration. Founder decision, with the numbers above rather than
# without them.
#
# `_connection` is deliberately left exactly as it was: 20 read/admin call sites depend on its
# always-closes contract and two tests pin it (test_db.py::test_connection_context_manager_*).
# This is a second, narrower door for the one path that needs speed.
#
# ⚠️ synchronous=NORMAL IS A DURABILITY CHOICE, SAID OUT LOUD RATHER THAN SLIPPED IN. In WAL
# mode it CANNOT corrupt the database; it risks losing only the most recent commits on an OS
# crash or power cut. WAL frames survive process death, so this is strictly LESS lossy than the
# buffer-and-flush design considered and rejected, which loses everything on a kill -9.
_write_conn = None
_write_conn_path = None

# 🔴 WHETHER THE SPEED TRADE ACTUALLY GOT TAKEN, RECORDED RATHER THAN ASSUMED. The paragraph
# above argues `synchronous=NORMAL` is safe because "in WAL mode it CANNOT corrupt the
# database". That argument is CONDITIONAL on WAL, and the first cut never checked: `PRAGMA
# journal_mode=X` RETURNS the resulting mode instead of raising when the filesystem refuses
# the change (measured: it answers ('wal',) / ('delete',)), so the `except sqlite3.Error`
# fallback below can never see the case it was written for. On a mount without shared memory
# -- an SMB/NFS home directory, which is exactly the "some network mounts" that fallback
# names -- the ledger would have stayed on a rollback journal AND been dropped to NORMAL,
# which SQLite documents as corruption-capable after a power cut. A guard that cannot fire is
# this repo's most repeated defect; this one is answered by reading the result.
#
# It is also what `log_intercept` restores TO. Only a handle that was lowered needs raising
# for a block row, and only a handle that was lowered may be put back to NORMAL afterwards.
_write_conn_fast = False

# 🔴 A NEW LOCK, AND IT MAY NOT BE decorators._stats_lock. That lock is documented as never held
# across I/O (see record_call below), and widening it to span a SQLite write would put file
# contention on the developer's tool-call path. This one guards only this handle.
_write_lock = threading.RLock()


def _write_connection():
    """The persistent ledger handle, opened lazily and keyed on the resolved path.

    🔴 KEYED ON THE PATH, NOT A BARE "already open" FLAG. `DB_PATH` genuinely moves inside one
    process: `mcp_proxy._point_stores_at_mcp_home()` reassigns it and `main()` never restores it
    (correctly -- the proxy owns its process), `_reader_globals` moves and restores it, and the
    root conftest restores it after every test. A handle cached on nothing keeps writing to
    whichever ledger it opened first, and `log_intercept` swallows the error, so the rows are
    lost in silence. `decorators._LEDGER_MIGRATION_CHECKED` had exactly this bug and was fixed
    exactly this way; pinned by test_db.py::test_a_write_follows_db_path_when_it_moves_mid_process.

    🔴 ...AND THE KEY IS THE ABSOLUTE PATH, WHICH THE FIRST VERSION OF THIS FUNCTION GOT WRONG
    WHILE ITS DOCSTRING CLAIMED OTHERWISE. `DB_PATH` defaults to the RELATIVE ".agentx.db".
    `_connection()` re-resolves that against the current directory on every call; a cached
    handle resolves it exactly ONCE. So a process that changed directory after its first write
    -- an agent moving into a per-task workspace, which is ordinary -- kept writing into the
    ledger it opened first, while `agentx audit` run from the new directory read an empty one.

    Measured before the fix: write in A, chdir to B, write again, and BOTH rows are in
    A/.agentx.db with B's ledger empty. At the previous commit the second row correctly
    followed the directory. That is a regression this change introduced, and it was NOT
    confined to the new inventory rows: `log_intercept` is also the writer for CHALLENGED
    block rows, so an agent's catches went to the wrong file. The outer `except Exception:
    pass` hides nothing here, which is what makes it nasty -- the writes SUCCEED, into the
    wrong ledger.

    The pinned guard could not have caught it: that test moves the VARIABLE to an absolute
    path, and the root conftest pins `DB_PATH` absolute for the whole session, so the relative
    case is structurally invisible to the suite. See
    test_db.py::test_a_write_follows_the_working_directory_when_the_path_is_relative.

    🔴 check_same_thread=False PLUS THE LOCK, not `threading.local()`. Three thread families
    reach this writer: the caller's own thread, up to 16 `agentx-protect` pool threads (so every
    async-decorated tool records off the event loop), and the MCP relay pump. Thread-local would
    mean ~18 handles with no closer between them, and under WAL the sidecars outlive a handle
    that is never closed. One handle has one lifecycle and one closer; the lock costs far less
    than the write it guards. Pinned by
    test_db.py::test_every_thread_that_writes_a_row_gets_that_row_on_disk.

    ⚠️ LAZY, NEVER AT IMPORT. `import agentx_sdk` must leave no file behind (P-133), and
    test_import_writes_nothing.py drives that in a subprocess. Opening here means the first
    WRITE creates the ledger, which is the same moment it was created before.

    Callers hold `_write_lock`.
    """
    global _write_conn, _write_conn_path, _write_conn_fast
    # abspath, not realpath: it normalises "./x.db" and "x.db" to one key and costs a getcwd,
    # where realpath would stat every component of the path on a per-call route. Symlinked
    # ledgers reaching this by two different names is not a case anything here creates.
    #
    # Measured, because this runs on every recorded call: `abspath` itself is 0.46 us, and an
    # interleaved A/B of the whole write (7 rounds, min taken) put the fix 4 us FASTER than
    # the broken version -- i.e. the difference is under this harness's noise floor. It costs
    # nothing worth stating.
    path = os.path.abspath(DB_PATH)
    if _write_conn is not None and _write_conn_path == path:
        return _write_conn
    _close_write_connection()
    conn = sqlite3.connect(path, timeout=_BUSY_TIMEOUT_MS / 1000.0, check_same_thread=False)
    _write_conn_fast = False
    try:
        conn.execute("PRAGMA busy_timeout=%d" % _BUSY_TIMEOUT_MS)
        # 🔴 READ THE ANSWER, DO NOT ASSUME IT. This pragma reports the mode the database
        # ENDED UP IN and does not raise when the change is refused, so the `except` below is
        # not the WAL fallback it looks like. `synchronous=NORMAL` is only safe under WAL, so
        # it is only taken when WAL is what we actually got. See _write_conn_fast above.
        _mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        if _mode and str(_mode[0]).strip().lower() == "wal":
            conn.execute("PRAGMA synchronous=NORMAL")
            _write_conn_fast = True
    except sqlite3.Error:
        # A ledger on a filesystem that refuses WAL (some network mounts) still has to work.
        # It will be slow, and slow is the correct trade against not recording at all.
        pass
    # The writer stands up the table it writes, same rule as log_intercept's own CREATE and for
    # the same reason: init_db() no longer runs at import, so this may be first to touch the
    # file. Done ONCE per handle here rather than per call, which is most of what the per-call
    # CREATE was costing.
    # ⚠️ AND IF THAT CREATE RAISES, THE CONNECTION IS CLOSED RATHER THAN ABANDONED. It is not
    # cached until the line below, so an exception here used to drop the only reference to an
    # OPEN sqlite handle -- on a read-only ledger or a full disk that is one leaked handle per
    # protected tool call, with `log_intercept`'s outer swallow hiding every one. The per-call
    # COST of that failure is unchanged from before this branch (the old code opened a
    # connection per call too, so a broken ledger always re-paid the open); the leak is the
    # part that is new, and this is the whole of it.
    try:
        conn.execute(_CREATE_EVENT_LOG_SQL)
        conn.commit()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise
    _write_conn, _write_conn_path = conn, path
    return conn


def _close_write_connection():
    """Close and forget the persistent handle. Safe to call when there is none.

    🔴 REGISTERED AT IMPORT (below), NOT LAZILY ON FIRST WRITE, AND THE ORDER IS THE REASON.
    atexit runs LIFO. `decorators` imports this module, so registering here at import time puts
    this closer FIRST on the stack and therefore LAST to run -- after
    `decorators._print_agentx_summary`, which READS the ledger and WRITES through
    `advance_watermark`. Registered on first write instead, it would land after that handler and
    run BEFORE it, closing the ledger out from under the session-end readout. Everything on that
    path is best-effort, so the symptom would be the summary silently going quiet.

    Also the answer to `_quarantine_ledger`: on Windows `os.rename` fails while a handle is open,
    which flips that path into "this session will not be recorded". Callers that move the ledger
    aside close this first.
    """
    # 🔴 UNDER THE LOCK, BECAUSE TWO OF THE FOUR CALLERS DO NOT HOLD IT. `log_intercept`'s
    # recovery path and `_write_connection` both call this with `_write_lock` held (it is an
    # RLock, so re-entering is free); `_quarantine_ledger` and the atexit hook did not. With
    # one handle shared across the caller's thread, up to 16 protect-pool threads and the MCP
    # relay pump, an unlocked close can land between another thread's `execute` and its
    # `commit` -- and that row disappears into the outer swallow.
    #
    # ⚠️ BOUNDED, NOT BLOCKING FOREVER. This also runs from atexit, where a writer wedged on a
    # locked ledger must not turn process exit into a hang.
    #
    # 🔴 AND IF THE LOCK CANNOT BE TAKEN, IT DOES NOT CLOSE. The first cut closed anyway, on
    # the reasoning that this "is exactly the behaviour this had before, so the timeout can
    # only ever leave us where we already were". That argument is wrong in the way that
    # matters: closing a shared handle without the lock is precisely the mid-execute/commit
    # race this function took the lock to prevent, so the guard had a hole in the shape of its
    # own bug. Both callers that can reach the timeout are SAFER not closing -- at exit the OS
    # releases the handle, and `_quarantine_ledger` sees the False and takes its documented
    # "could not move it, your file is untouched" branch instead of renaming a file another
    # thread is mid-write on.
    #
    # Returns whether the handle is now closed, so a caller that needs it CLOSED (rather than
    # merely asked to close) can tell.
    global _write_conn, _write_conn_path, _write_conn_fast
    if not _write_lock.acquire(timeout=_BUSY_TIMEOUT_MS / 1000.0):
        return False
    try:
        # `_write_conn_fast` is a property of the HANDLE, so it is forgotten with the handle.
        # Left standing it would describe a connection that no longer exists, and the next one
        # may open on a different filesystem (DB_PATH moves) with a different answer.
        conn, _write_conn, _write_conn_path = _write_conn, None, None
        _write_conn_fast = False
        if conn is None:
            return True
        try:
            conn.close()
        except Exception:
            # ⚠️ NOT RESTORED, AND NOT A LEAK EITHER. A review called this a silent leak;
            # measured, it is not: dropping the only reference lets CPython finalise the
            # connection, which closes it (verified by renaming the file straight afterwards on
            # Windows, where an open handle would refuse). Deliberately not put back, because
            # the caller that reaches here most is `log_intercept`'s recovery path, whose whole
            # purpose is to stop a bad handle being handed to every later write.
            return False
        return True
    finally:
        _write_lock.release()


atexit.register(_close_write_connection)


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
    # --- WHAT WE SAID, so a recovery can be attributed to the words that caused it --------
    #
    # 🔴 THIS COLUMN IS A DIFFERENT KIND FROM THE THREE ABOVE, AND THE DISTINCTION IS THE
    # PRIVACY BOUNDARY. Those are DERIVED FROM the caller's payload and are bounded so they
    # cannot carry a value. This one is not derived from the payload: it is the coaching text
    # WE emitted. Do not read this as a relaxation of the rule above; a column holding
    # anything the CALLER supplied still belongs under that rule.
    #
    # ⚠️ AND THE BOUND IS NARROWER THAN IT FIRST LOOKS, SO IT IS STATED PROPERLY RATHER THAN
    # COMFORTABLY. An earlier version of this comment said the text is always "our own
    # string, already on the user's disk in the shipped seeds or in their own
    # .agentx/overrides.json". That is true of the KEYLESS path and false of the gateway one:
    # there the challenge can be composed by the judge per call, so it is neither shipped nor
    # on disk beforehand, and nothing stops a judge from quoting the payload it was shown
    # back into its own sentence.
    #
    # This still stays inside the rule, because what lands here is what we HANDED THE AGENT:
    # if it echoes the caller's data, the caller has already read it. But that is a different
    # and weaker guarantee than "our own string", and the difference matters the moment
    # anything considers sending this field anywhere. The contribution channel does not carry
    # it today. Any change to that is a privacy decision, not a plumbing one.
    #
    # WHY IT EXISTS. The ledger already records that a block happened (`policy_name`) and
    # whether the agent came back (`status`). What it could not say is WHICH WORDING was in
    # front of the agent, so attribution stopped at the policy. Change a policy's coaching
    # and nothing distinguishes before from after; write your own with `agentx customize`
    # and nothing tells you whether it worked. That is the free tier "never improving" in
    # one missing field, and it is the door most users arrive through.
    #
    # NULL on any row that was not a block, which is most of them: only a blocked call has
    # coaching. Bounded by the same 30-day / 10,000-row retention as everything else here.
    ("challenge_issued", "TEXT"),
    # --- COUNTED QUANTITY, a bucket floor and NOT a value ---------------------------------
    #
    # 🔴 APPENDED AT THE END ON PURPOSE, not slotted in beside `amount` where it reads better.
    # A fresh ledger gets its columns from _CREATE_EVENT_LOG_SQL in THIS order, while an
    # existing one gets them from ALTER TABLE ADD COLUMN, which can only append. Inserting
    # mid-list would give a new install and an upgraded install different column ORDERS for
    # the same schema, and anything reading positionally would then be correct on one and
    # wrong on the other, with nothing on either to say so.
    #
    # Same privacy rule as `amount`: `_magnitude_bucket` stores the power-of-ten FLOOR, so
    # 4,200 lands as 1000.0. The number itself never reaches the ledger. See `_is_count_key`
    # for which argument names qualify and why there is no corroborating field.
    ("quantity",        "REAL NOT NULL DEFAULT 0"),
    # --- WHICH POSTURE THIS CALL RAN UNDER ------------------------------------------------
    #
    # 🔴 THE QUESTION NOBODY COULD ANSWER: "which of my tools ran unprotected?" A per-tool
    # `enforcement="audit"` argument turns off blocking for that WHOLE tool, permanently, in
    # the developer's own source. It fails OPEN and it is invisible: it lives in code, not in
    # any store we can read, so no screen could ever list it.
    #
    # Recording the posture the call actually resolved to answers it from DATA instead. It
    # catches both shapes at once -- a whole run in audit, and one tool pinned to audit inside
    # an otherwise-enforcing run -- because both arrive here having already resolved.
    #
    # Bounded to 'audit' / 'enforce', so it carries no caller text. Appended at the END for
    # the same reason `quantity` was: a fresh ledger takes its column order from CREATE and an
    # existing one from ALTER TABLE ADD COLUMN, which can only append.
    ("posture",         "TEXT"),
]

_CREATE_EVENT_LOG_SQL = "CREATE TABLE IF NOT EXISTS event_log (\n    %s\n)" % ",\n    ".join(
    "%s %s" % (name, ddl) for name, ddl in _EVENT_LOG_COLUMNS)


# --- RETENTION -------------------------------------------------------------------------
#
# Before this retention policy shipped, NOTHING pruned this file. No retention, no row cap,
# no vacuum. That was survivable only because the ledger records the RARE event: every
# writer is a hit, and `reached_first_block` is 0 across six installs, so in practice we
# wrote almost nothing.
#
# 🔴 Recording every passing call, not only blocks, changes the write rate from "the rare
# event" to "every call", which is the entire reason this ceiling has to exist BEFORE the
# writer that needs it, rather than after -- otherwise we ship unbounded growth onto the
# user's own disk.
#
# The policy: 30 days OR 10,000 rows, whichever binds first, and the drop is REPORTED
# rather than silent. The loud part is not manners: an earlier version of this ledger was
# deleted quietly on a schema upgrade, and the lesson taken from it was that deletion must
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

    Mirrors the gateway's incident-store column reconciler, which fixed the same class for
    the gateway's incident store in 2026-07 and likewise returns what it could NOT add so
    the caller can report it. The SDK ships standalone and cannot import the gateway, so
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


# 🔴 A SQLITE LEDGER IS A FAMILY OF FILES, AND THIS IS THE ONE PLACE THAT SAYS SO.
#
# Under WAL a committed row lives in `<name>-wal` until a checkpoint, and `<name>-shm` is the
# shared-memory index beside it. Anything that MEASURES, MOVES, COPIES or DELETES a ledger and
# looks only at the `.db` is working on a fraction of it.
#
# This is a rule this branch has now been bitten by five times, in five different files, each
# found separately:
#
#   - the conftest store tripwire went green on the leak it exists to catch, because it samples
#     (exists, size, mtime) of the `.db` and a committed row does not touch it
#   - four privacy assertions read the `.db` bytes and reported "no value on disk" over a value
#     that was in the `-wal`
#   - the founder-runnable pr328 check had the same blind spot
#   - `_quarantine_ledger` renamed the `.db` and left the sidecars, so the quarantined copy was
#     missing its newest rows AND the orphaned `-wal` sat next to a fresh ledger for SQLite to
#     try to recover into
#
# By the fifth instance the answer stops being another local fix. The suffixes were already
# written down in SIX places (this module, `conftest.py`, two test helpers, two scripts, and a
# demo utility) -- a rule restated at each site, which is this codebase's most repeated defect
# and gets obeyed at some of them. It lives here now and the others import it.
LEDGER_SIDECARS = ("-wal", "-shm")


def ledger_files(path=None):
    """Every path a ledger occupies on disk, main file first. Pure; never touches the disk.

    Returns names, not existing files: a caller measuring drift WANTS a missing `-wal` in its
    list, because one that APPEARS during a run is itself the change worth seeing. Callers that
    need only what exists filter on `os.path.exists` themselves.
    """
    base = path or DB_PATH
    return (base,) + tuple(base + suffix for suffix in LEDGER_SIDECARS)


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
    # 🔴 THE FREE-NAME CHECK COVERS THE WHOLE FAMILY, AND THE FIRST VERSION OF THIS CHECKED
    # ONLY THE `.db`. That is this branch's own one-file blindness, reintroduced INSIDE the
    # commit that fixed it -- left written down, because it says the class is not fixed by
    # knowing about it.
    #
    # Measured: leave a stale `.agentx.db.bak-wal` with no `.agentx.db.bak` beside it (what a
    # user deleting a backup and missing its sidecar produces), and the loop picks
    # `.agentx.db.bak` as free. The sidecar rename then hits an existing file and fails into
    # the swallowing `except OSError` -- so the quarantined database ends up paired with a
    # STALE write-ahead log from an older rescue, while the live one holding the user's newest
    # rows is orphaned beside the path a fresh ledger is about to be created at. Both halves of
    # the harm this hunk exists to prevent, caused by the hunk.
    def _family_free(base):
        return not any(os.path.exists(name) for name in ledger_files(base))

    target = DB_PATH + ".bak"
    n = 1
    while not _family_free(target):
        n += 1
        target = "%s.%d.bak" % (DB_PATH, n)
    # 🔴 DROP OUR OWN HANDLE FIRST, OR THIS FAILS ON WINDOWS FOR A REASON WE CAUSED. The
    # docstring above already names a file lock as the usual cause of the None branch; since
    # P-112's enforce half the writer holds a persistent handle on this exact file, so without
    # this line we would be that lock ourselves, and the caller would tell the user "this
    # session will not be recorded" about a rename only we were blocking. Under WAL there are
    # also -wal/-shm sidecars open, which closing releases.
    #
    # 🔴 THE CLOSE AND THE RENAME ARE ONE STEP, UNDER THE LOCK. Closing and then renaming as
    # two unlocked steps leaves a window in which another writer thread calls
    # `_write_connection()` and CREATES `.agentx.db` again at the exact path being moved
    # aside -- so the rename either fails, or succeeds and the "moved aside, nothing was
    # deleted" message describes a file that now has a fresh sibling holding the rows written
    # in between. `_write_lock` is an RLock and `_close_write_connection` takes it too, so
    # nesting here costs nothing.
    with _write_lock:
        if not _close_write_connection():
            # Could not be sure our own handle is shut. Renaming a file another thread may be
            # mid-write on is worse than declining: this is the documented None branch, and it
            # leaves the user's ledger exactly as it was.
            return None
        try:
            os.rename(DB_PATH, target)
        except OSError:
            return None
        # 🔴 THE SIDECARS GO WITH IT, AND UNTIL NOW THEY DID NOT. Renaming only the `.db` left
        # two problems behind, and the second is the worse one: the quarantined copy is missing
        # whatever sat in its `-wal` (its NEWEST rows -- and this function's whole promise is
        # that the user's bytes survive), and the orphaned `-wal` stays beside the path a fresh
        # ledger is about to be created at, where SQLite will try to recover it into a database
        # it never belonged to.
        #
        # Windows hid this: with any other connection open the rename fails outright and we
        # return None, which is the safe documented branch. On POSIX it succeeds, so the
        # damage lands only on the platforms most users are on.
        #
        # Renamed to `target + suffix` so the pair still MATCHES: SQLite looks for a WAL beside
        # the database by name, so `x.db.bak` needs `x.db.bak-wal` to be readable later.
        #
        # ⚠️ BEST-EFFORT, AFTER the main file, and the residual is stated rather than hidden.
        # The main rename is the guarded step and keeps its all-or-nothing contract. If a
        # sidecar move then fails we are left with an orphan, which is strictly better than
        # the alternative of moving sidecars first and failing on the main file -- and deleting
        # one is never an option, because it may hold rows.
        for _side in ledger_files()[1:]:
            if os.path.exists(_side):
                try:
                    os.rename(_side, target + _side[len(DB_PATH):])
                except OSError:
                    pass
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
        _notice("⚠️ [AgentX SDK] The local ledger %s, so it was saved as %s and a new one "
              "started. Nothing was deleted." % (why, backup))
        return True
    _notice("⚠️ [AgentX SDK] The local ledger %s, and it could not be moved aside (it may be "
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
        # A bug report goes to the bug channel, not to the gateway signup page the short
        # link resolved to. See links.GATEWAY_URL for the three jobs that link was doing.
        from .links import DISCORD_URL
        _notice("🔴 [AgentX SDK] Cannot add %s to an existing ledger, so this install will "
              "run without it. Your history is untouched. Please report this: %s"
              % (", ".join(unaddable), DISCORD_URL))
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
        _notice("⚠️ [AgentX SDK] Could not upgrade the local ledger (%s). It is UNCHANGED and "
              "your history is safe; this session may not be recorded. Try again once "
              "nothing else is using it." % exc)
        return False
    _notice("🔄 [AgentX SDK] Ledger upgraded to the current schema. Your history is intact.")
    return True


def ensure_ledger_current():
    """Bring an EXISTING ledger up to the current schema. NEVER creates one. Never raises.

    Returns True when the caller may go on to CREATE (either there was nothing to upgrade, or the
    upgrade succeeded), False when an existing ledger could not be migrated.

    🔴 THIS EXISTS SO MIGRATION AND CREATION STOP BEING THE SAME EVENT. They were welded
    together in init_db(), which decorators.py called at import, so the only way to keep an old
    ledger migrating itself was to create a file for everybody who imported the SDK. Splitting
    them lets the reader entry points -- cli.main(), mcp_proxy._reader_globals, and the first
    protected call in decorators._decide -- keep db.py's promise that "a column added here migrates
    itself onto every ledger that already exists" without any of them writing to disk first.

    ⚠️ The three callers above are what keep that promise. If you remove one, narrow the promise
    with it rather than leaving a sentence nobody enforces.
    """
    if not os.path.exists(DB_PATH):
        return True
    return _upgrade_existing_ledger()



def _notice(message):
    """An SDK diagnostic. STDERR, always.

    🔴 STDOUT BELONGS TO THE COMMAND. These fire from ledger setup and migration, which now runs
    from `cli.main()` before a command renders, so on stdout they print AHEAD of the document and
    `agentx audit --json` emits something no parser can read. Exactly the defect the brand banner
    had to learn, and the same one the incident-park warning was moved off stdout for.

    Never deleted for a machine caller, only moved: someone piping JSON still needs to be told
    their ledger could not be upgraded.
    """
    print(message, file=sys.stderr)


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

    ⚠️ This must NEVER raise, and the REASON changed rather than the rule. decorators.py
    no longer calls this at import time, but mcp_proxy.main() calls it at proxy startup where a
    raise kills the JSON-RPC session before it speaks, and examples/01 and examples/03 call it at
    MODULE scope, where a raise still breaks a shipped example on import. That is the opposite of
    the sibling in the gateway's incident store, which is documented as write-path-only and allowed
    to raise.

    ⚠️ THIS CREATES A FILE, so it is the wrong call for anything a reader triggers. To bring an
    existing ledger up to date without conjuring one, call ensure_ledger_current() -- which is what
    the CLI and the MCP reader path do, so typing `agentx status` in a directory no longer leaves a
    database behind in it.
    """
    if not ensure_ledger_current():
        return

    try:
        with _connection() as conn:
            conn.execute(_CREATE_EVENT_LOG_SQL)
            conn.execute(_CREATE_RETENTION_SQL)
            # Like ledger_retention, this is OURS rather than the user's history, so it is
            # created here and stays outside _plan_migration -- the quarantine path that
            # table walks is about event_log being someone else's table, and a bookkeeping
            # table that fails to appear costs a screen a line, never a record.
            conn.execute(_CREATE_NOVELTY_SQL)
            conn.execute(_CREATE_NOVELTY_SEEN_SQL)
            conn.commit()
    except sqlite3.Error as exc:
        # Never raise (see the docstring). The ledger writers are already best-effort, so
        # the session runs unrecorded rather than the SDK failing to import.
        _notice("⚠️ [AgentX SDK] Could not open the local ledger (%s). Protection is unaffected; "
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
# WHY IT IS SPELLED THIS WAY: it is what the gateway's own transfer-pair labeller already
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
# Not porting the walk yet. Flat `amount=..., currency=...` kwargs are the normal shape for
# a decorated Python function, which is this path; nesting mostly arrives on the MCP path.
# When the walk is adopted it should extend THIS rule rather than replace a different one.
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


# 🔴 A COUNTED QUANTITY IS NOT MONEY, AND IT GETS ITS OWN COLUMN. For an infrastructure or
# data agent the consequential number is a ROW COUNT, not a dollar figure. Measured over a
# synthetic day of 199 protected calls, not one carried a size: a 4,200-row delete and a
# 98,000-row export were stored identically to the 120 routine queries beside them.
#
# 🔴 THIS IS NOT "THE BIGGEST INTEGER", AND MUST NEVER BECOME IT. That heuristic is the defect
# the money rule was rewritten to remove -- a row limit, an order number or a timestamp became
# "the amount" by being the largest number in the payload. The rule here is the SAME SHAPE as
# the money one: the developer's own argument NAME decides, nothing is guessed.
#
# ⚠️ WHY THERE IS NO CORROBORATING FIELD, unlike money. `amount` needs `currency` beside it
# because "amount" alone is ambiguous across units and range bounds. A `count` has no unit to
# disagree about, so requiring a second field would only mean recording nothing. The cost is
# that `retry_count=3` also records a quantity -- true, and harmless: it is genuinely a count,
# and `_magnitude_bucket` floors it to 1.0, which sorts below everything that matters.
#
# ⚠️ `limit` IS DELIBERATELY NOT A QUANTITY. It bounds a READ; nothing is acted on. This is the
# same distinction `_RANGE_BOUND_PREFIXES` already draws for money, kept consistent on purpose:
# 120 `run_query(limit=100)` calls must not outrank one 4,200-row delete.
_COUNT_KEY = "count"


def _is_count_key(name):
    """True when a NORMALISED key names a counted quantity. Mirrors `_is_amount_key`, so the
    writer and any future display cannot answer this question two different ways."""
    return name == _COUNT_KEY or name.endswith("_" + _COUNT_KEY)


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


def _classify_text(text):
    """The same bounded class, derived from a tool's own advertised DESCRIPTION.

    🔴 WHY THIS EXISTS. Names alone leave most calls unclassified: over a synthetic day of 199
    protected calls, 134 came back `other`, and every consequential one was among them -- a
    4,200-row delete, a 98,000-row export, a production deploy, a credential rotation. Only
    `fetch_url` and `write_file` earned a class. A SURFACE column that resolves for the routine
    calls and shrugs at the dangerous ones is worse than empty: it reads as coverage.

    The sentence a server author wrote to tell the MODEL what a tool does is the obvious signal,
    and we already parse it on the way past for drift detection, then throw the text away.

    🔴 THE OUTPUT IS A CLOSED SET, AND THAT IS THE SAFETY PROPERTY, NOT A DETAIL. A tool
    description is ATTACKER-CONTROLLED text from a remote server -- the same input
    `_description_poisoned` exists to screen. Deriving one of six fixed labels from it can at
    worst mislabel a surface. Persisting or DISPLAYING the sentence itself would put attacker
    text on the developer's screen, which is a different and much larger decision.

    ⚠️ AND THE CLASS MUST STAY DISPLAY-ONLY WHILE THIS INPUT EXISTS. Nothing that ranks, blocks
    or decides may read it, because a server author would then be steering our behaviour by
    writing a sentence. Rankings use argument shape and recorded magnitude, which the caller
    supplies, not the server.
    """
    tokens = _name_tokens(str(text or ""))
    for needles, klass in _CLASS_HINTS:
        if tokens.intersection(needles):
            return klass
    return _CLASS_OTHER


def _call_shape(tool_name, arguments, description=None):
    """Derive (arg_names, amount, target_class, quantity) for one call. Pure, never raises.

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

    # Same MAX-not-first rule as the amount block above, and for the same reason: taking
    # the first non-zero would let a small labelled count silence a large one in the same call.
    quantity = 0.0
    try:
        for key, value in (arguments or {}).items():
            if not _is_count_key(_normalise_key(key)):
                continue
            bucket = _magnitude_bucket(value)
            if bucket > quantity:
                quantity = bucket
    except Exception:
        quantity = 0.0

    # The caller's own words decide first. The DESCRIPTION is only consulted when the name and
    # arguments leave us with nothing, so a server author's sentence can never override what the
    # developer actually called -- it can only fill a blank that would otherwise print as "-".
    target_class = _classify_target(tool_name, names)
    if target_class == _CLASS_OTHER and description:
        target_class = _classify_text(description)

    return joined, amount, target_class, quantity


def _union_arg_names_and_classes(rows):
    """Union argument NAMES (each row's own comma-joined string, re-split) and TARGET
    CLASSES across a set of DISTINCT (arg_names, target_class) rows.

    The aggregation both get_call_inventory (per tool, ALLOWED rows) and
    get_would_block_summary (per policy, WOULD_BLOCK rows) need — extracted so a future fix
    to the split/union rule (e.g. an edge case in the comma split, or a name containing
    whitespace) applies to both readers at once rather than one silently drifting from the
    other, which is exactly the "fixed at one call site, missed the sibling" shape this
    file's own writers have hit twice.

    Pure; never raises (`split(",")` on a falsy value degrades to "", which the generator
    below already handles). Returns (sorted_names, sorted_classes)."""
    names, classes = set(), set()
    for arg_names, target_class in rows:
        names.update(n for n in (arg_names or "").split(",") if n)
        if target_class:
            classes.add(target_class)
    return sorted(names), sorted(classes)


def _exclude_agents_fragment(excluded):
    """The `agent_id NOT IN (...)` WHERE fragment `_grouped_policy_rows` and
    `get_would_block_summary`'s per-policy shape query both need, extracted so the two
    places that filter the SAME agent_id list cannot drift on HOW they filter it (the exact
    risk `_grouped_policy_rows`'s own docstring names for its callers, now also true of the
    caller that hand-rolled this instead of reusing it).

    `excluded` is the already-filtered (truthy-only) list, matching every existing call
    site's own filtering step. Returns ("", []) when there is nothing to exclude, else
    (" AND agent_id NOT IN (?,?,...)", [the ids]) — the fragment is a leading-space suffix,
    append directly to an existing WHERE clause."""
    if not excluded:
        return "", []
    return " AND agent_id NOT IN (%s)" % ",".join("?" for _ in excluded), list(excluded)


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
    # 🔴 A LEDGER THAT DOES NOT EXIST IS NOT OVER ITS CEILING. _connection() opens via
    # sqlite3.connect, which CREATES the file, so without this guard `agentx status` on a machine
    # that has never recorded anything leaves a 0-byte .agentx.db behind -- the same defect as the
    # 32 KB one, in a size that is HARDER to notice rather than easier.
    if not os.path.exists(path or DB_PATH):
        return False
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
    # theoretical: the gateway bumps `successful_agent_pivots` on any allow carrying a
    # receipt_id (a deterministic-floor block issues one and never bumps
    # `socratic_nudges_issued`), and the gateway itself documents a cross-restart case where
    # pivots outrun their denominator. ⚠️ THIS USED TO SAY "which is why /v1/telemetry CLAMPS
    # its own rate to 100". It no longer does: the ceiling was removed precisely because it was
    # hiding a numerator larger than its denominator rather than protecting a reader, so a rate
    # above 100 is now VISIBLE there. This function is the CLI's answer to the same skew and it
    # has always been the honest one. The CLI renders the two raw counters, so both skews arrive
    # here. Report what we hold.
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
              "would_blocks_from_demo": 0, "inventory_from_demo": 0,
              # 🔴 AND OUR DEMO'S BLOCKS, WHICH THE TWO COUNTS ABOVE LEFT OUT. `agentx demo`
              # writes one CHALLENGED row and recovers from it, and `agentx status` printed
              # that as "Total intercepts: 1 / 1 of 1 recovered" under a header about what
              # the reader's agent did, one command after `insights` had said it was ours
              # (founder walk). Same pass, same rule.
              "block_episodes_from_demo": 0, "recoveries_from_demo": 0}
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
                       SUM(CASE WHEN status IS ? AND {ours} THEN 1 ELSE 0 END),
                       SUM(CASE WHEN status IN ('CHALLENGED', 'RECOVERED') AND {ours}
                                THEN 1 ELSE 0 END),
                       SUM(CASE WHEN status = 'RECOVERED' AND {ours} THEN 1 ELSE 0 END)
                  FROM event_log
            """.format(ours=_ours_sql), (WOULD_BLOCK_STATUS, INVENTORY_STATUS,
                  WOULD_BLOCK_STATUS, *_ours_params,
                  INVENTORY_STATUS, *_ours_params,
                  *_ours_params, *_ours_params))
            (total, episodes, would, recovered, intercepted,
             would_demo, inv_demo, episodes_demo, recovered_demo) = cursor.fetchone()
            census["total_rows"] = total or 0
            census["block_episodes"] = episodes or 0
            census["would_blocks"] = would or 0
            census["recoveries"] = recovered or 0
            census["interceptions"] = intercepted or 0
            census["would_blocks_from_demo"] = would_demo or 0
            census["inventory_from_demo"] = inv_demo or 0
            census["block_episodes_from_demo"] = episodes_demo or 0
            census["recoveries_from_demo"] = recovered_demo or 0
    except Exception:
        # An unreadable ledger reports zeros, exactly like an empty one. Callers that must
        # tell those apart already use ledger_is_unreadable(); this function's contract is
        # counts, and inventing a third state here would give them two ways to ask.
        return census
    return census


# ONE template, two column sets. Written as a format slot rather than two literal queries so
# the legacy retry cannot drift from the real one -- the failure mode being that a pre-migration
# ledger silently returns a DIFFERENT shape (different grouping, different order) than a current
# one, on a screen whose whole job is describing what the ledger holds.
# 🔴 THE DEMO SPLIT RIDES THE GROUPED PASS, IT DOES NOT ADD A QUESTION. This function's own
# docstring measures its cost in QUESTIONS PER TOOL and names the fix for the next person who
# needs a per-tool number: fold it into the group. A per-tool `SELECT COUNT(*) WHERE agent_id
# IN (...)` would have been a third question per tool, worsening the exact figure that
# docstring is watching. A conditional SUM in the pass already running costs nothing.
#
# The `?` marks in the ours-clause sit in the SELECT list, so they bind BEFORE the status
# parameter in the WHERE -- hence `_INVENTORY_PARAMS` rather than a bare tuple at each call.
_INVENTORY_SQL = """
    SELECT tool_name,
           COUNT(*),
           MAX(amount),
           MIN(timestamp),
           MAX(timestamp),
           %s,
           SUM(CASE WHEN {ours} THEN 1 ELSE 0 END)
      FROM event_log
     WHERE status IS ?
  GROUP BY tool_name
  ORDER BY COUNT(*) DESC, tool_name ASC
""".replace("{ours}", _our_agents_clause()[0])

_INVENTORY_PARAMS = tuple(_our_agents_clause()[1]) + (INVENTORY_STATUS,)


def get_unprotected_tools(path=None, exclude_agents=None):
    """Which tools RAN but were not defended, and how many times. Never raises.

    🔴 THE QUESTION THIS ANSWERS CANNOT BE ANSWERED ANY OTHER WAY. A per-tool
    `enforcement="audit"` argument turns blocking off for that whole tool, permanently, in the
    developer's own source. Nothing else can see it: it is code, not configuration, so no
    store lists it and no screen could enumerate it. Reading it back from rows the calls
    themselves wrote is the only route.

    Returns ``[(tool_name, calls), ...]`` busiest first. An empty list means every recorded
    call was defended, which is the good answer and the common one.

    ⚠️ IT IS SILENT ON A PRE-POSTURE LEDGER RATHER THAN WRONG. Rows written before the column
    existed carry NULL, and NULL is not 'audit', so they are simply absent. A caller must not
    read an empty list as "everything was protected" on a ledger that predates this -- see
    `posture_coverage` for the denominator that makes the difference visible.
    """
    excluded = [a for a in (exclude_agents or []) if a]
    frag, frag_params = _exclude_agents_fragment(excluded)
    try:
        with _connection(path or DB_PATH) as conn:
            return [(row[0], row[1]) for row in conn.execute(
                "SELECT tool_name, COUNT(*) FROM event_log "
                "WHERE posture = 'audit' AND tool_name IS NOT NULL AND tool_name != ''"
                + frag + " GROUP BY tool_name ORDER BY COUNT(*) DESC, tool_name ASC",
                tuple(frag_params))]
    except Exception:
        return []


def posture_coverage(path=None):
    """``{audit, enforce, unknown}`` row counts, so a reader can state its own denominator.

    `unknown` is rows written before the posture column existed. A screen that reports "0
    tools ran unprotected" while most of the ledger is `unknown` is answering a question it
    cannot see, which is the failure this exists to prevent.
    """
    out = {"audit": 0, "enforce": 0, "unknown": 0}
    try:
        with _connection(path or DB_PATH) as conn:
            for posture, n in conn.execute(
                    "SELECT posture, COUNT(*) FROM event_log GROUP BY posture"):
                key = posture if posture in ("audit", "enforce") else "unknown"
                out[key] += n
    except Exception:
        pass
    return out


def get_call_inventory(path=None, limit=25):
    """P-92: what the agent DID, aggregated per tool. Never raises; returns a dict.

    Reads the INVENTORY rows only. The blocks are `agentx insights`' subject and are counted
    here purely so the report can say how many of this tool's calls we objected to -- the two
    commands answer different questions and neither should quietly become the other.

    🔴 `window_start` IS NOT DECORATION. Retention drops rows, so a bare "412 calls" invites
    the reader to treat it as their agent's whole history when it is a 30-day / 10,000-row
    window. `covers_all` says whether anything was ever dropped, so the caller can state the
    honest sentence instead of guessing. P-97 ratified that a drop is reported, not silent.

    🔴 P-130 MEASURED (Windows 11, Python 3.12.1, sqlite 3.43.1, 10,000-row ledger at P-97's
    cap, timestamps spread across the 30-day window). This asks the ledger once for the tool
    list and then TWO MORE QUESTIONS PER TOOL, so the cost is driven by DISTINCT TOOL COUNT,
    not by row count:

                                    12 tools   500 tools   10,000 tools
        screen (limit=25)             22.7ms      32.5ms         55.4ms     <= 63 queries
        --json (uncapped, #350)       31.1ms     573.0ms      11,367.0ms    20,013 queries
        control: no inventory rows    12.6ms

    The SCREEN is bounded by its 25-tool page, so it cannot get worse than ~55ms whatever the
    ledger holds. `--json` is bounded only by the retention cap, and the row's derived ceiling
    of "~20,000 queries in one command" is now an observation rather than an estimate: 20,013.

    ⚠️ WHY THIS WAS MEASURED NOW, AND WHY IT IS STILL NOT FIXED. P-130's severity was LOW on
    the stated grounds that "no measurement of a real ledger exists" -- which held because
    enforce wrote no inventory rows, so this loop ran ~zero times for every default install.
    P-112's enforce half ended that: every default install has inventory rows now. The
    severity did not rise, but the REASON changed, and a reason nobody re-checks is how a
    stale LOW survives. It is now conditional on an agent calling thousands of DISTINCT tool
    names, which is a generated dispatcher or a fuzzer, not an agent. At the realistic 12-50
    tools this is tens of milliseconds on a command a human typed.

    THE TRIGGER TO FIX IT, so the next reader does not have to re-derive it: a real ledger
    with more than a few hundred distinct tool names, or `--json` becoming something a program
    calls in a loop rather than something a person runs. The fix is named in the row -- fold
    the two per-tool queries into one grouped pass over `event_log`. The ANTI-fix is named
    too: do NOT put the cap back on `--json`. A silently truncated document is a worse failure
    than a slow one, and that completeness contract is why #350 removed it.

    ⚠️ AND DO NOT RAISE THE ROW CAP FIRST. The 10,000 -> 20,000 raise goes AFTER this, because
    the cap is a query-time backstop rather than a disk one: doubling it makes this worst case
    ~4x in wall clock, not 2x. Fixing the loop first makes the raise free.
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
             "inventory_from_demo": 0, "viewable_total": 0, "would_block_from_demo": 0,
             "totals": dict(dict.fromkeys(_LEDGER_TOTAL_KEYS, 0), window_start=None)}
    if not os.path.exists(path or DB_PATH):
        return empty
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            # 🔴 THE LEGACY RETRY IS THE SAME ONE `log_intercept` KEEPS FOR ITS INSERT, AND
            # FOR THE SAME REASON. Naming a newer column unconditionally makes this whole
            # SELECT fail with "no such column" on any ledger the migration has not reached,
            # and because the caller treats a failed read as UNREADABLE, one added column
            # turned every pre-migration ledger into "we cannot read your ledger". A missing
            # column is a missing FIELD, never a missing ledger.
            _legacy = False
            try:
                cursor.execute(_INVENTORY_SQL % "MAX(quantity)", _INVENTORY_PARAMS)
            except sqlite3.OperationalError:
                _legacy = True
                cursor.execute(_INVENTORY_SQL % "0", _INVENTORY_PARAMS)
            rows = cursor.fetchall()

            tools = []
            for name, calls, amount, first_ts, last_ts, quantity, demo_calls in rows[:limit]:
                # Argument names and classes are collected per tool rather than per row: the
                # question the report answers is "what does this tool take", and one row is
                # only one call's worth of that. A tool called with different optional
                # arguments would otherwise look like several different tools.
                # `tool_name IS ?`, not `= ?`, for the same reason as the status comparisons
                # below and throughout this function: SQLite's `=` against NULL yields NULL,
                # never true, so a row whose tool_name was never written matches nothing --
                # including its OWN group, which `GROUP BY tool_name` happily produced. The
                # rule was applied to one column and not the other in the same WHERE clause.
                # 🔴 `agent_id` RIDES THE QUERY THAT WAS ALREADY BEING RUN. This function's
                # own docstring measures its cost in QUESTIONS PER TOOL, and `--json` is
                # already at a measured 20,013 queries on the pathological ledger, so a third
                # per-tool question to answer "whose agent was this" would worsen the exact
                # number that docstring is watching. This DISTINCT scan was already reading a
                # row per (arg_names, target_class); reading the agent alongside them costs
                # no extra query and no extra pass.
                cursor.execute(
                    "SELECT DISTINCT arg_names, target_class, agent_id FROM event_log "
                    "WHERE status IS ? AND tool_name IS ?", (INVENTORY_STATUS, name))
                distinct_rows = cursor.fetchall()
                # Sliced to pairs here rather than widening `_union_arg_names_and_classes`,
                # which get_would_block_summary also calls. Changing a shared signature to
                # serve one of its two callers is how the other one acquires a bug.
                names, classes = _union_arg_names_and_classes(
                    [(r[0], r[1]) for r in distinct_rows])
                # 🔴 OUR OWN DEMO AGENT IS NOT ONE OF THEIR AGENTS. `agentx demo` writes its
                # scripted rows under the tool name `run_sql`, and the flagged count below
                # was split for precisely this reason: our traffic annotating the developer's
                # own row is a claim about their code that is not true. Without the same rule
                # here, a single-agent developer who has run the demo sees TWO agents on the
                # screen and one of them is ours -- on the first run of the ladder, which is
                # the run this screen exists to make legible.
                agents = sorted({r[2] for r in distinct_rows
                                 if r[2] and r[2] not in OUR_AGENT_IDS})
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
                    # The counted-quantity twin of max_amount. Kept a SEPARATE key rather than
                    # folded into it: a row count and a sum of money are different kinds of
                    # thing, and merging them is how the biggest-integer defect got in.
                    "max_quantity": quantity or 0.0,
                    "arg_names": names, "classes": classes, "agents": agents,
                    "first_ts": first_ts, "last_ts": last_ts, "flagged": flagged,
                    # 🔴 THE PER-TOOL SPLIT, SO A ROW CAN BE RECONCILED WHERE IT IS READ. The
                    # screen-level note says "21 of those came from AgentX's own demo or examples",
                    # which is a total across every tool -- so a reader looking at `run_sql 26`
                    # beside "run_sql ran 21 of your 39 calls" two lines above has nothing on
                    # screen that gets them from 26 to 21. Found by the founder on his own
                    # ledger, where the demo TOTAL also happened to be 21, which made the
                    # screen-level note look like the explanation when it was a coincidence.
                    "from_demo": int(demo_calls or 0),
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
            # 🔴 THROUGH `_ledger_totals`, NOT ITS OWN QUERY. This reader shipped a parallel
            # set of ledger-wide counts that only the human grouped screen read, so the two
            # surfaces of one command each had their own definition of the same fact -- the
            # last place not routed through the single source, and where the next instance of
            # this class was going to come from.
            #
            # The VALUE is unchanged and deliberately so: this screen counts every
            # non-inventory row, INCLUDING the status-less legacy ones, because before P-92
            # the ledger held nothing but calls we had an opinion about (see
            # INVENTORY_STATUS). `_ledger_totals` splits that pair apart for the machine
            # document; here they are added back together. Same numbers, one definition,
            # and `test_the_two_surfaces_agree_about_one_ledger` holds the relationship.
            _shared = _ledger_totals(cursor)
            flagged_total = _shared["flagged"] + _shared["unclassified"]

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

            # 🔴 AND WHICH OF THOSE WERE OURS, because a caller is about to use this count as
            # EVIDENCE. `agentx demo --audit` writes its scripted DROP TABLE as a WOULD_BLOCK,
            # so on the first run of the ladder this number is 1 and that 1 is ours. A screen
            # that says "audit caught these and let them run -- turn on enforce" off the back
            # of it is selling protection using our own demo as the proof, and telling a
            # developer their agent did something it did not. Third status to need this split
            # (see flagged_from_demo and inventory_from_demo directly below); the rule is that
            # any count a SENTENCE about "your agent" rests on needs it.
            cursor.execute(
                "SELECT COUNT(*) FROM event_log WHERE status IS ? AND " + _ours_sql,
                (WOULD_BLOCK_STATUS, *_ours_params))
            would_block_from_demo = cursor.fetchone()[0] or 0

            # Rows with NO status at all (legacy, pre-P-57 migration). They are counted in
            # flagged_total because a row we cannot classify is still a row -- but every
            # `agentx insights` reader filters on CHALLENGED / RECOVERED / WOULD_BLOCK, so
            # sending someone there to "see them" shows nothing. The caller needs to know how
            # many of the flagged are actually VIEWABLE before it offers that command.
            # Same source as `flagged_total` above, for the same reason: this number and the
            # machine document's `unclassified` are the same fact and must not be able to
            # drift apart.
            unclassified_total = _shared["unclassified"]

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
                "would_block_from_demo": would_block_from_demo,
                "unclassified_total": unclassified_total,
                "viewable_total": viewable_total,
                "flagged_from_demo": flagged_from_demo,
                "inventory_from_demo": inventory_from_demo,
                # Handed over rather than discarded. It was computed here and thrown away,
                # so the JSON caller opened a SECOND connection and recomputed all of it --
                # extra queries, and a separate transaction, so a row written between the two
                # reads produced a payload whose totals disagreed with the list they label.
                "totals": _shared,
            }
    except Exception:
        # 🔴 A READ FAILURE IS NOT AN EMPTY LEDGER, and conflating them is the exact defect
        # #326 had to fix on the screen next door: a locked or corrupt file told the
        # developer nothing had ever happened. The caller renders these two differently.
        out = dict(empty)
        out["readable"] = False
        return out


# --- THE MCP TOOL ROSTER: what the wrapped server ADVERTISED, called or not ------------
#
# The denominator the call rows cannot supply. A tool the agent never called appears in no
# row, so without this the audit screen can say what the agent did and never what it could
# have done. On the MCP door the server hands the proxy its whole menu on every `tools/list`,
# with the developer writing no code, so the denominator arrives for free and used to be
# thrown away once drift detection had fingerprinted it.
#
# NAMES ONLY. The proxy also sees each tool's description and input schema; those are
# attacker-controlled text and are never persisted (see `_inspect_list_line`). A tool NAME is
# already what every `event_log` row stores for a called tool, so the roster adds no new kind
# of data to the user's disk, only names the ledger would hold anyway had the agent called them.
#
# ONE ROW PER SERVER, holding the NEWEST advertised list, mirroring the TypeScript ledger's
# roster row: the question the screen answers is "what could this agent have called", not
# "every tool this server has ever advertised". A tool the server stops advertising drops out
# on the next `tools/list`.
#
# Bookkeeping, not the user's history: created on write with IF NOT EXISTS, outside
# `_plan_migration`, like `ledger_novelty`. Its absence costs the screen a line, never a record.
_CREATE_MCP_ROSTER_SQL = """CREATE TABLE IF NOT EXISTS mcp_tool_roster (
    server_key TEXT PRIMARY KEY,
    tools      TEXT NOT NULL,
    total      INTEGER NOT NULL,
    ts         REAL NOT NULL
)"""

# The names kept per server. `total` carries the true count so the screen's denominator is
# never understated by the cap; only the LIST is bounded, and a server advertising more than
# this is a generated dispatcher, not an agent's toolbox.
_ROSTER_MAX_NAMES = 500
# A single advertised name longer than this is not a tool name. Skipped, not truncated: a
# truncated name would never match its own `event_log` rows, so it would always read as
# "never called".
_ROSTER_MAX_NAME_LEN = 200

# The policy name the proxy writes a drift/poison row under. Defined HERE because the roster
# reader must exclude those rows from "called": they carry the drifted tool's name and the
# proxy's agent id, but the agent did not call anything. The proxy imports it from here so
# the writer and the reader cannot spell it two ways.
MCP_DRIFT_POLICY_NAME = "MCP Tool Description Drift"

# The agent id the MCP proxy writes every row under. Only its rows count against the roster:
# the roster describes ITS server, and a Python-door tool that happens to share a name with
# an advertised one was not called through that server.
MCP_PROXY_AGENT_ID = "mcp_proxy"

# A name carrying a C0/C1 control byte is not a tool name; it is a write primitive on the
# audit screen. The server chooses these strings, and a tool only has to be ADVERTISED, never
# called, to have its name printed under "never called", so an ESC sequence or a carriage
# return in a name forges a roster line with no agent involvement at all. Same class and the
# same answer as decorators._DETAIL_CONTROL_RE for a remote server's response body: drop the
# whole class rather than enumerate escape sequences. Skipped, not cleaned: a cleaned name
# would never match its own ledger rows.
_ROSTER_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def record_mcp_roster(server_key, names, path=None, only_if_present=False):
    """Write the newest advertised tool list for one wrapped server. Best-effort, never raises.

    NEVER CREATES THE STORE. The proxy calls this on every menu it sees, but writes only for
    a server with a numerator: a call recorded this session, or a roster row an earlier
    session's call earned (`only_if_present`, below). That is the TypeScript rule: a
    denominator is only meaningful beside a numerator, and a process that lists the tools of
    a server nobody calls should leave no record behind. The guard is kept here as well, so
    no caller can create a ledger purely to note what a server advertised.

    `only_if_present`: write only if this server ALREADY has a roster row. That is the
    proxy's gate for a session that re-lists the menu and has not (yet) made a call: the
    numerator exists from an earlier session, so the newest menu may replace the stale one,
    while a server never called still gets no row.

    Returns True when a row was written, so a caller can tell "wrote it" from "nowhere to
    write it"; the proxy uses that to retry at the next opportunity rather than marking the
    roster flushed.
    """
    try:
        if not server_key or not isinstance(names, (list, tuple)):
            return False
        if not os.path.exists(path or DB_PATH):
            return False
        clean = []
        seen = set()
        for name in names:
            if not isinstance(name, str) or not name or len(name) > _ROSTER_MAX_NAME_LEN:
                continue
            if _ROSTER_CONTROL_RE.search(name):
                continue
            if name in seen:
                continue
            seen.add(name)
            clean.append(name)
        total = len(clean)
        clean = sorted(clean)[:_ROSTER_MAX_NAMES]
        with _connection(path) as conn:
            if only_if_present:
                # Asked BEFORE the CREATE, so a never-called server's no-call session leaves
                # the ledger byte-for-byte as it was: no row, and no empty table either.
                try:
                    row = conn.execute("SELECT 1 FROM mcp_tool_roster WHERE server_key = ?",
                                       (str(server_key),)).fetchone()
                except sqlite3.OperationalError:
                    row = None          # no table: no server has a row
                if row is None:
                    return False
            conn.execute(_CREATE_MCP_ROSTER_SQL)
            conn.execute(
                "INSERT OR REPLACE INTO mcp_tool_roster (server_key, tools, total, ts) "
                "VALUES (?, ?, ?, ?)",
                (str(server_key), json.dumps(clean), total, time.time()))
            conn.commit()
        return True
    except Exception:
        return False


def get_mcp_roster(path=None):
    """Every wrapped server's newest advertised list, against what the ledger says was called.
    Never raises; returns a dict.

    `servers` is empty on a ledger with no roster row, which is every ledger written before
    this shipped. An absent roster means we do not know the total, and a screen printing
    "0 never called" from that would be a claim, not a gap: the caller prints nothing.

    🔴 COUNTS THE INTERSECTION, NOT THE LEDGER. `called` is the roster's names that have a
    row, and `never_called` is the rest of the roster. A tool the ledger holds that the
    newest roster does not name (the server stopped advertising it; a different server) is
    not counted either way. Counting every distinct ledger tool against one server's roster
    is what produced the TypeScript door's self-contradicting "2 wrapped. 4 called. 0 never
    ran." before it was fixed there; same basis here from the start.

    "Called" is any row the proxy wrote for that tool, whatever we said about it: a call we
    stopped was still a call the agent made. The one exclusion is a drift/poison row, which
    names a tool the server CHANGED, not one the agent called.
    """
    empty = {"readable": True, "servers": []}
    if not os.path.exists(path or DB_PATH):
        return empty
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT server_key, tools, total, ts FROM mcp_tool_roster")
            except sqlite3.OperationalError as exc:
                # No table: a ledger from before this shipped. That is "no roster", not
                # "unreadable" -- the ledger itself opened fine. ONLY that case: the same
                # exception class carries "database is locked" after the busy wait, and
                # reading a locked file as "no roster" is the empty-versus-unreadable
                # conflation the audit screen refuses everywhere else. Anything but a
                # missing table falls through to the outer handler and reads as unreadable.
                if "no such table" in str(exc).lower():
                    return empty
                raise
            roster_rows = cursor.fetchall()
            if not roster_rows:
                return empty
            cursor.execute(
                "SELECT DISTINCT tool_name FROM event_log "
                "WHERE agent_id IS ? AND tool_name IS NOT NULL "
                "AND (policy_name IS NULL OR policy_name IS NOT ?)",
                (MCP_PROXY_AGENT_ID, MCP_DRIFT_POLICY_NAME))
            ran = {r[0] for r in cursor.fetchall()}
        servers = []
        for server_key, tools_json, total, ts in roster_rows:
            try:
                tools = [t for t in json.loads(tools_json or "[]") if isinstance(t, str)]
            except Exception:
                tools = []
            called = [t for t in tools if t in ran]
            never = [t for t in tools if t not in ran]
            servers.append({
                "server_key": server_key,
                "tools": tools,
                # The true advertised count. Equal to len(tools) unless the list was capped,
                # in which case the names past the cap are neither called nor never-called
                # here: they are simply not listed.
                "total": int(total or len(tools)),
                "called": called,
                "never_called": never,
                "ts": ts,
            })
        servers.sort(key=lambda s: s["ts"] or 0, reverse=True)
        return {"readable": True, "servers": servers}
    except Exception:
        out = dict(empty)
        out["readable"] = False
        return out


#: Every count a sentence about this ledger can rest on, and the ONLY place they are
#: computed. Both audit views and both output shapes read these, so they cannot disagree.
_LEDGER_TOTAL_KEYS = ("rows", "inventory", "flagged", "unclassified", "ours",
                      "distinct_tools", "window_start")


def _ledger_totals(cursor):
    """The ledger-wide counts, from one place. Assumes an open cursor; never raises alone.

    🔴 ONE ENTRY POINT, BECAUSE TWO HAND-BUILT COPIES DISAGREED. The grouped reader and the
    per-call reader each assembled their own set, and the JSON built from them reported
    `flagged: 3, ours: 0` for a ledger whose 3rd flagged row WAS ours -- two numbers over
    two different populations, printed side by side under one label, so a consumer
    subtracting one from the other counted our own demo's block as the developer's.

    🔴 FOUR POPULATIONS, NOT TWO, AND THE FOURTH IS WHY. A row's status is ALLOWED (we
    looked and had nothing to say), a real verdict (we had an opinion), or NULL -- a legacy
    row predating the status column. `flagged` counts VERDICTS ONLY; the legacy rows are
    counted apart as `unclassified`, because the per-call screen renders one as "unrecorded"
    and a total that called it flagged would contradict the row beside it.

    ⚠️ AND THAT IS A NARROWER NUMBER THAN THE GROUPED SCREEN'S, DELIBERATELY. Before P-92
    this ledger held ONLY calls we had an opinion about (see INVENTORY_STATUS above), so a
    status-less row genuinely IS one -- which is why `agentx audit` counts it under "tripped
    a policy" and then says separately that it comes from an older ledger. Neither number is
    wrong; they are different sets. The screen's is `flagged + unclassified`, and
    `test_the_two_surfaces_agree_about_one_ledger` is what stops that relationship drifting.

    `IS` / `IS NOT`, never `=` / `!=`: SQLite yields NULL for those against NULL, which is
    not true, so a status-less row silently vanishes from every count at once. This module
    has been fixed for that trap more than once.
    """
    # 🔴 NOT `COUNT(DISTINCT tool_name)`, FOR THE SAME NULL RULE THIS DOCSTRING STATES.
    # SQLite's COUNT(DISTINCT col) SKIPS NULLs, so a row whose tool_name was never written
    # counted in `rows` and in no tool at all: a one-row legacy ledger rendered as
    # "1 call across 0 tools" on the per-call screen -- which then printed that very row as
    # "(unnamed)" underneath. Measured. `SELECT DISTINCT` keeps the NULL group, which is
    # also what `get_call_inventory`'s `GROUP BY tool_name` does, so the two readers agree
    # on how many tools a ledger holds instead of differing by one on exactly the rows this
    # function exists to stop mis-counting.
    cursor.execute(
        "SELECT COUNT(*), "
        "(SELECT COUNT(*) FROM (SELECT DISTINCT tool_name FROM event_log)), "
        "MIN(timestamp) FROM event_log")
    rows, distinct_tools, window_start = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) FROM event_log WHERE status IS ?", (INVENTORY_STATUS,))
    inventory = cursor.fetchone()[0] or 0

    cursor.execute(
        "SELECT COUNT(*) FROM event_log WHERE status IS NOT ? AND status IS NOT NULL",
        (INVENTORY_STATUS,))
    flagged = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM event_log WHERE status IS NULL")
    unclassified = cursor.fetchone()[0] or 0

    ours_sql, ours_params = _our_agents_clause()
    cursor.execute("SELECT COUNT(*) FROM event_log WHERE " + ours_sql, tuple(ours_params))
    ours = cursor.fetchone()[0] or 0

    return {"rows": rows or 0, "inventory": inventory, "flagged": flagged,
            "unclassified": unclassified, "ours": ours,
            "distinct_tools": distinct_tools or 0, "window_start": window_start}


def get_ledger_totals(path=None):
    """`_ledger_totals` for a caller that has no cursor. Never raises.

    Returns the counts plus `readable`. A caller rendering these must branch on `readable`:
    zeroes from an unreadable ledger describe a file nobody managed to open, which is not
    the same statement as an idle agent.
    """
    empty = dict.fromkeys(_LEDGER_TOTAL_KEYS, 0)
    empty["window_start"] = None
    empty["readable"] = True
    if not os.path.exists(path or DB_PATH):
        return empty
    try:
        with _connection(path) as conn:
            out = _ledger_totals(conn.cursor())
            out["readable"] = True
            return out
    except Exception:
        out = dict(empty)
        out["readable"] = False
        return out


def is_rule_match(policy_id, status):
    """True for a row that RAN and was the shape of an adopted rule. ONE definition for every
    reader, so the audit screen, its --json and the summary cannot disagree about which rows
    are matches.

    Both halves are required. A gateway that enforces the same rule writes the SAME `rule-`
    id onto the CHALLENGED / WOULD_BLOCK row it produces, so the prefix alone would mark a
    call the gateway STOPPED as a match -- a review of this branch found the legend and
    the --json field doing exactly that. The status is what says the call ran."""
    return (status == INVENTORY_STATUS and bool(policy_id)
            and str(policy_id).startswith("rule-"))


def get_rule_match_summary(path=None):
    """Which adopted rules the recorded calls were the shape of, per tool. Never raises.

    ONE grouped query for the whole screen, regardless of tool count. `get_call_inventory`
    already asks two questions per tool and its docstring measures the cost of that at
    20,013 queries on the pathological ledger; a third per-tool question for this would move
    the exact number that docstring is watching. Grouping here keeps this at one.

    Reads ALLOWED rows only. A `rule-` id on a CHALLENGED or WOULD_BLOCK row would mean a
    rule that BLOCKED, which only a gateway can do and only a gateway writes; those rows
    belong to `agentx insights`, not to the inventory this summarises.

    Returns {"total": int, "by_tool": {tool: [(rule_name, count), ...] count-DESC},
             "by_rule": {rule_name: count}, "by_id": {rule_id: count}}.
    `by_rule` is by NAME, for sentences that name what the ledger recorded. `by_id` is for
    the YOUR RULES table, which walks the developer's file: a name is not a key there. Two
    `adopt --rule` on one action without `--name` share a name, and a rule renamed in the
    file keeps its history under the id; keyed by name, both rows showed one summed count
    and the renamed rule showed 0 (scoped review of this branch).
    """
    empty = {"total": 0, "by_tool": {}, "by_rule": {}, "by_id": {}}
    p = path or DB_PATH
    if not os.path.exists(p):
        return empty
    try:
        with _connection(p) as conn:
            rows = conn.execute(
                "SELECT tool_name, policy_id, policy_name, COUNT(*) FROM event_log "
                "WHERE status IS ? AND policy_id LIKE 'rule-%' "
                "GROUP BY tool_name, policy_id, policy_name "
                "ORDER BY COUNT(*) DESC, policy_name ASC",
                (INVENTORY_STATUS,)).fetchall()
    except Exception:
        return empty
    by_tool, by_rule, by_id, total = {}, {}, {}, 0
    for tool, rid, name, n in rows:
        n = int(n or 0)
        name = name or "(unnamed rule)"
        by_tool.setdefault(tool or "(unnamed)", []).append((name, n))
        by_rule[name] = by_rule.get(name, 0) + n
        by_id[rid] = by_id.get(rid, 0) + n
        total += n
    return {"total": total, "by_tool": by_tool, "by_rule": by_rule, "by_id": by_id}


def get_call_log(path=None, limit=50, offset=0):
    """P-92: what the agent did, ONE ROW PER CALL, newest first. Never raises.

    The per-call sibling of `get_call_inventory`, which groups by tool. Both read the same
    ledger; this one does not collapse it, because the ORDER is information a grouped view
    cannot carry. A table read one row at a time, five hundred times, is "read_row: 500
    calls" in the aggregate and is recognisable for what it is here. Nothing in this product
    DETECTS that shape (P-117 -- only a stateful system could), so an ordered list is
    currently the only place it can be seen at all.

    🔴 IT READS EVERY STATUS, NOT JUST THE INVENTORY, and that is the whole difference from
    its sibling. `get_call_inventory` reads INVENTORY_STATUS alone because it answers "what
    did we have no opinion about". This answers "what did the agent DO", and a timeline with
    the calls we objected to filtered out shows a tool called five times when it was called
    six. The per-row `status` is what keeps the two questions apart: dropping the rows loses
    the count, a column does not.

    `limit=None` returns every row in the window -- what `--all` and `--json` pass. "Every
    row" is bounded by construction: _RETENTION_MAX_ROWS is the ceiling on this table.

    Returns {readable, rows, shown, window_start, covers_all, totals}, where `totals`
    is the shared `_ledger_totals` block -- handed over whole rather than picked apart, so a
    caller cannot pair two counts drawn over different populations. `readable` False means
    the ledger is on disk and could NOT be read -- never that the agent did nothing. The two
    render differently; see the same contract on `get_call_inventory`.
    """
    # Every key the success path returns, so a caller never has to branch on which of the
    # three exits it got. The missing-file and unreadable exits differ ONLY in `readable`.
    empty = {"readable": True, "rows": [], "shown": 0, "covers_all": True,
             "totals": dict(dict.fromkeys(_LEDGER_TOTAL_KEYS, 0), window_start=None),
             "window_start": None}
    if not os.path.exists(path or DB_PATH):
        return empty
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            # Counted over the WHOLE ledger, never from the page below. Same rule this
            # module already states for the grouped reader: a sentence about the ledger is
            # computed FROM the ledger, never from the subset the screen happens to show.
            totals = _ledger_totals(cursor)
            window_start = totals["window_start"]

            # 🔴 `rows_dropped`, NOT `rows_dropped - blocks_dropped`. The grouped reader
            # subtracts because its sentence is about INVENTORY rows only. This view holds
            # EVERY status, so any eviction at all shortens the window it describes --
            # borrowing the sibling's expression would report a fully-trimmed ledger of
            # blocks as complete. The counter that decides a sentence has to be the counter
            # that sentence is about.
            #
            # Guarded separately from the read above for the sibling's reason:
            # `ledger_retention` is created by init_db, so pointing this at ANOTHER
            # process's ledger can raise "no such table" on a file that reads perfectly, and
            # a missing counter table is not an unreadable ledger.
            try:
                cursor.execute("SELECT rows_dropped FROM ledger_retention WHERE id = 1")
                dropped_row = cursor.fetchone()
            except Exception:
                dropped_row = None

            # `id` is the tie-break, and it is load-bearing rather than tidy: `timestamp` is
            # a REAL, so two calls inside one clock tick come back in whatever order SQLite
            # likes. That makes "newest first" wrong exactly when calls are FASTEST, which
            # is the burst this view exists to make visible.
            sql = ("SELECT timestamp, tool_name, status, arg_names, amount, target_class, "
                   "policy_name, trace_id, agent_id, policy_id FROM event_log "
                   "ORDER BY timestamp DESC, id DESC")
            # 🔴 OFFSET SURVIVES `limit=None`. The clause used to be appended only when a
            # limit was set, so `get_call_log(limit=None, offset=50)` silently returned the
            # whole list from row 1 -- the next paging caller gets 50 duplicated rows with
            # nothing red. SQLite has no OFFSET without LIMIT, and `LIMIT -1` is its
            # documented "no limit", so the two stay independent as the signature promises.
            sql += " LIMIT ? OFFSET ?"
            params = [-1 if limit is None else int(limit), int(offset)]
            cursor.execute(sql, params)

            rows = []
            for (ts, tool, status, arg_names, amount, target_class,
                 policy_name, trace_id, agent_id, policy_id) in cursor.fetchall():
                rows.append({
                    "ts": ts,
                    "tool": tool,
                    "status": status,
                    "arg_names": arg_names,
                    "amount": amount or 0.0,
                    "target_class": target_class,
                    "policy_name": policy_name,
                    # on an ALLOWED row a `rule-` id here means "this call was the
                    # shape of a rule the developer adopted". The prefix is the discriminator,
                    # so readers do not have to know which statuses can carry a rule.
                    "policy_id": policy_id,
                    "trace_id": trace_id,
                    "agent_id": agent_id,
                    # MARKED, never dropped -- the same call the grouped screen makes for
                    # the same rows. `agentx demo --audit` writes real rows under our own
                    # agent id, and a reader who ran it precisely to get a populated screen
                    # would otherwise be handed an empty one.
                    # 🔴 THROUGH `is_our_agent`, WHOSE OWN DOCSTRING SAYS "ONE PREDICATE,
                    # BECAUSE THE LAST TWO TIMES THIS WAS ANSWERED IT WAS ANSWERED PER SITE
                    # AND ONE SITE WAS MISSED". This was a third hand-written site, in the
                    # branch whose whole stated class is going around an entry point that
                    # already exists. Equivalent today; that is not the point.
                    "ours": is_our_agent(agent_id),
                })

            return {
                "readable": True,
                "rows": rows,
                # NO `total` here. It was `totals["rows"]` under a second name, and one fact
                # with two names is what this change spent its review budget removing.
                "shown": len(rows),
                # The ledger-wide counts, whole and unedited, from the one place that
                # computes them. Handing over the block rather than a hand-picked pair is
                # what stops a caller inventing a subtraction between two populations.
                "totals": totals,
                "window_start": window_start,
                "covers_all": not (dropped_row and dropped_row[0]),
            }
    except Exception:
        # 🔴 A READ FAILURE IS NOT AN EMPTY LEDGER, and the stakes are higher here than on
        # the sibling: this reader feeds `--json`, whose consumer is a program with no prose
        # to tell the two apart. The JSON renderer OMITS the list entirely rather than
        # emitting [], because [] means "your agent did nothing".
        out = dict(empty)
        out["readable"] = False
        return out


# --- P-112 NOVELTY: what is NEW about this ledger since the reader last saw it ---------
#
# 🔴 THE WATERMARK IS A STORED COPY OF THE AGGREGATE, NEVER A TIMESTAMP AND NEVER A ROW ID,
# AND THAT IS THE WHOLE DESIGN. P-112 was decided as "audit first, enforce later": today only
# audit posture writes inventory rows, and when enforce eventually records them it will do so
# as PER-TOOL AGGREGATES upserted on an interval rather than one row per call -- the write
# volume becomes O(distinct tools), which is what removes the per-call cost objection. A reader
# that diffed timestamps, or walked per-call rows, would have to be rewritten on the day that
# lands. A reader that diffs this aggregate against a stored copy of the SAME aggregate does
# not, because the shape it reads is the shape that will still be there. Only the posture gate
# moves. That constraint is the reason this is not the obvious "rows newer than X" query.
#
# It is also the only version that survives retention. `MAX(amount)` read from the ledger goes
# DOWN when the row holding the largest bucket is trimmed, so a later call at the old size
# would be announced as a new record. A stored watermark only ever moves up.
_CREATE_NOVELTY_SQL = """CREATE TABLE IF NOT EXISTS ledger_novelty (
    watermark     TEXT NOT NULL,
    tool_name     TEXT NOT NULL,
    arg_names     TEXT,
    classes       TEXT,
    max_amount    REAL NOT NULL DEFAULT 0,
    calls         INTEGER NOT NULL DEFAULT 0,
    arg_combos    TEXT,
    max_day_calls INTEGER NOT NULL DEFAULT 0,
    max_day       TEXT,
    max_burst     INTEGER NOT NULL DEFAULT 0,
    max_burst_at  TEXT,
    hours         TEXT,
    weekend       INTEGER NOT NULL DEFAULT 0,
    last_ts       REAL,
    PRIMARY KEY (watermark, tool_name)
)"""

# Columns added after the table first shipped on this branch. Same three-line treatment as
# ledger_retention, and outside _plan_migration for the same reason: this is OUR bookkeeping,
# not the user's history, so a column we cannot add costs a novelty line and never a record.
_NOVELTY_COLUMNS = [
    ("arg_combos",    "TEXT"),
    ("max_day_calls", "INTEGER NOT NULL DEFAULT 0"),
    ("max_day",       "TEXT"),
    ("max_burst",     "INTEGER NOT NULL DEFAULT 0"),
    ("max_burst_at",  "TEXT"),
    ("hours",         "TEXT"),
    ("weekend",       "INTEGER NOT NULL DEFAULT 0"),
    ("last_ts",       "REAL"),
]


def _dumps_set(values):
    """Serialise a set of strings so EVERY member survives, including the empty one.

    The sets on a novelty row are otherwise separator-joined, which is fine while an empty
    member is meaningless (there is no empty argument name). It is not fine for argument
    COMBINATIONS, where "the call took no arguments" is a real and interesting member. See
    the read side for the defect that produced.
    """
    try:
        return json.dumps(sorted(values))
    except Exception:
        return "[]"


def _loads_set(blob):
    """Inverse of `_dumps_set`. Never raises; an unreadable value reads as empty."""
    try:
        loaded = json.loads(blob or "[]")
        return [v for v in loaded if isinstance(v, str)]
    except Exception:
        return []


def _ensure_novelty_columns(conn):
    """Add any ledger_novelty column an older ledger is missing. Idempotent; never raises."""
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(ledger_novelty)")}
        if not have:
            return
        for name, ddl in _NOVELTY_COLUMNS:
            if name not in have:
                conn.execute("ALTER TABLE ledger_novelty ADD COLUMN %s %s" % (name, ddl))
    except Exception:
        # A ledger we cannot ALTER still reads: the missing columns come back as absent keys
        # and the signals that depend on them stay quiet. Degrading to fewer novelty lines is
        # the correct failure for a feature whose whole job is to be pleasant.
        pass

# WHETHER THE READER HAS EVER SEEN THIS SURFACE, which is NOT the same question as whether we
# have any rows stored for it, and conflating the two produced a false sentence on the first
# run of the ladder. A ledger holding only our own demo rows gives the table above nothing to
# write, so "have we stored anything" answered NO for someone who had already run the command.
# One row per watermark; it is a flag, not a log.
_CREATE_NOVELTY_SEEN_SQL = """CREATE TABLE IF NOT EXISTS ledger_novelty_seen (
    watermark TEXT PRIMARY KEY,
    ts        REAL,
    busiest   TEXT
)"""

_NOVELTY_SEEN_COLUMNS = [("busiest", "TEXT")]


def _record_changed(now_id, was_id):
    """🔴 THE ONE RULE EVERY RECURRING SIGNAL GOES THROUGH: a record is news when its HOLDER
    changes, never when its VALUE moves.

    Three signals here are records rather than firsts -- busiest day, biggest burst, busiest
    tool -- and each one learned this separately and incompletely. `busiest_day` and `burst`
    were fixed to store the identity of the record (the day, the minute) and compare THAT,
    because a still-open day keeps growing and re-announced itself every session. `busiest`
    was left comparing a derived quantity, and had a worse version of the same bug: the
    stored call count is a running MAX, so once retention trims the previous leader's rows
    the live ledger and the watermark disagree PERMANENTLY and nothing reconciles them.
    Reproduced: 100 calls to one tool, 10 to another, trim the first, and "now your busiest
    tool" printed on every session forever -- crowding out every real fact on a two-line
    teaser.

    A rule invented at one site and not carried to its siblings is the template this branch
    keeps repeating. This is the entry point so a fourth record cannot get it wrong.
    """
    return bool(now_id) and now_id != was_id


def _ensure_novelty_seen_columns(conn):
    """Add any ledger_novelty_seen column an older ledger is missing. Never raises."""
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(ledger_novelty_seen)")}
        if not have:
            return
        for name, ddl in _NOVELTY_SEEN_COLUMNS:
            if name not in have:
                conn.execute("ALTER TABLE ledger_novelty_seen ADD COLUMN %s %s" % (name, ddl))
    except Exception:
        pass

# TWO watermarks, because the two surfaces ask DIFFERENT QUESTIONS and one watermark would
# have them eat each other's answer. The session-end line asks "what did I not know before
# this run"; `agentx audit` asks "what has changed since I last looked at this screen". With a
# single watermark the atexit line would consume the novelty and the report -- the screen we
# are trying to send them to -- would render empty for the reader who just followed it.
WATERMARK_SESSION = "session"
WATERMARK_REPORT = "report"

# Prose names for the surface classes. `_SURFACE_LABELS` is the TABLE column ("DB", "FS") and
# is too terse to drop into a sentence; these go in "first call to your database". Kept as a
# separate map rather than title-casing the stored value, because `http` reads as "network" to
# a developer and as nothing at all spelled out. `_CLASS_OTHER` is deliberately ABSENT: it
# means we could not tell, and "first call to your other" is a claim about their code we have
# no basis for. The same under-inclusive rule `_TARGET_CLASSES` is written under.
_SURFACE_WORDS = {
    "db": "database",
    "filesystem": "filesystem",
    "http": "network",
    "shell": "shell",
    "cloud": "cloud",
}

# How dominant one tool has to be before "your busiest tool" is worth a line. A share, not a
# rank: on a ledger of twenty tools the top one is always SOME tool, and printing it would be
# a fact with no information in it.
_CONCENTRATION_SHARE = 0.4

# ...and a floor under the sample, because a share of three calls is not a shape. On the
# first run of the ladder a wrapped agent has made a handful of calls and "mostly one tool:
# run_sql ran 2 of your 3" is arithmetic dressed as an observation. Found by walking the
# ladder in one directory rather than by a test, which is where this screen's last four
# defects came from too.
_CONCENTRATION_MIN_CALLS = 10

# How many argument names one novelty line will name before it counts the rest. An agent with
# optional arguments can add a dozen in one session, and a line that lists them all stops
# being a signal and becomes the table again.
_MAX_NEW_ARGS_SHOWN = 3

# How many argument COMBINATIONS one tool's watermark will remember. Unlike every other field
# stored there, this one is not drawn from a closed set -- a tool with many optional keywords
# has combinatorially many. Past the cap the tool stops contributing the missing-argument
# signal, which is the honest end state: a tool that varied enough to hit this has no stable
# "always passes X" for anything to violate.
_MAX_ARG_COMBOS = 24

# How far a new hour has to be from every hour already seen before it counts as the agent
# running OUTSIDE its usual window. 1 means "next door is the same window": 10am then 11am is
# a working day, 10am then 3am is not.
_HOUR_SAME_WINDOW = 1


def _hour_distance(a, b):
    """Hours between two clock hours, the short way round. Never raises; 24 on bad input.

    Circular on purpose: 23:00 and 00:00 are one hour apart, and treating them as
    twenty-three would call every late-night run a departure from a midnight one.
    """
    try:
        gap = abs(int(a) - int(b))
    except Exception:
        return 24
    return min(gap, 24 - gap)


# A "burst record" below this is not a record, it is two calls that happened to share a
# minute. Any agent in a loop clears it immediately; an agent doing one thing at a time never
# will, which is the distinction the line exists to draw.
_BURST_WORTH_SHOWING = 5

# A tool needs more than a single call before "now your busiest tool" means
# anything. One call each is a tie, and a tie is decided by spelling.
_BUSIEST_MIN_CALLS = 2

# How long an absence has to be before coming back is worth remarking on. A weekend is not an
# absence, and a line that fired every Monday would be a nag rather than news.
_GAP_WORTH_SHOWING = 7 * 86400


def current_call_shape(path=None):
    """The per-tool aggregate the novelty reader diffs. THE DEVELOPER'S ROWS ONLY.

    Returns ``{tool_name: {"calls", "max_amount", "arg_names", "classes"}}``, empty on any
    failure. Never raises.

    MEASURED, because P-112 is a row where an unmeasured cost nearly became a veto. Cost is
    LINEAR IN ROWS and paid ONCE PER SESSION, at exit -- the whole session-end pass (this
    read plus the write that reuses it) across 12 tools:

        50 rows 5.6 ms | 200 5.3 | 1,000 7.7 | 5,000 20 | 10,000 (P-97's cap) 44

    On a ledger holding only blocks -- no inventory rows, which is every install that has not
    turned audit on -- the read is 0.64 ms. Nothing here runs per tool call.

    ⚠️ TWO EARLIER SETS OF NUMBERS IN THIS DOCSTRING WERE WRONG, AND BOTH WERE WRONG THE SAME
    WAY: measured on a ledger built in a tight loop, where every row shared a handful of
    timestamps and the GROUP BY collapsed to a few groups. Spread realistically the read is
    ~31 ms at the cap, not the 13.9 first recorded here. A companion figure for the write was
    inflated for the opposite reason -- it was timed WITHOUT passing `current`, so it silently
    re-did the read. **A benchmark's fixture is part of its claim.** Re-run these when the
    function grows a query, and build the fixture like the thing it stands for.

    ⚠️ ALL THREE CALL SITES PASS `current` THROUGH, and that is a requirement rather than an
    observation. Omitting it makes the pair cost three scans instead of one. The MCP door did
    omit it, which also made an earlier version of the sentence above ("the read that both
    real call sites hand it") untrue of one of them -- a claim about call sites that was
    checked against two of the three.

    ⚠️ AND THIS DOES NOT HAVE TO BE A FULL SCAN. Every signal here is a union, a running
    maximum or a count, so new rows could be folded into the stored bookmark without
    re-reading the old ones -- bounded by activity rather than by ledger size. Deliberately
    NOT done: it needs a read-up-to marker whose failure mode is news silently lost forever.

    🔴 THE CONDITION THIS NOTE SET HAS NOW HAPPENED, AND THE ANSWER IS STILL NO. It said the
    trade "becomes the right one when enforce starts recording and every ledger sits at the
    cap permanently, which is P-112's second half" -- and that half has landed. Re-measured on
    that world (10,000 rows spread across the window): 41.4 ms at 12 tools, 96.2 ms at a
    pathological 10,000. Still ONCE PER PROCESS, at exit, off the tool-call path entirely, so
    a tenth of a second at the far end of a session does not buy a marker that can lose news
    silently. A note that names a trigger has to be re-read on the day it fires, which is the
    only reason this one is being answered rather than left standing.

    ⚠️ SAY HOW OFTEN IT RUNS, NOT WHICH PATH IT IS ON. Every number above is ONCE PER
    SESSION, at exit. Nothing in this file runs PER TOOL CALL -- the per-call code costs
    0.062 ms and this reader adds nothing to it, in either posture. The two costs differ by
    how often they happen, so that is what the words have to carry: "hot path" and
    "protected call path" name neither, and the second one also reads as a claim about
    enforce posture, which it is not.

    🔴 DELIBERATELY NOT `get_call_inventory`, and the two differences are both load-bearing.
    That reader caps at `limit` tools, so a tool would be announced as seen-for-the-first-time
    on the day it climbs into the top 25 -- years after its first call. And it deliberately
    INCLUDES our own demo rows so the screen can footnote them, which is right for a table the
    reader can see the footnote under and wrong for a one-line claim: "your agent touched your
    filesystem for the first time" about `agentx demo --audit`'s four scripted calls is us
    telling a developer something false about their own code, on the first run of the ladder,
    with no table underneath to qualify it. That is the exact misattribution the per-tool
    `flagged` count was already fixed for once.

    ⚠️ ROWS WITH NO TOOL NAME ARE SKIPPED ENTIRELY rather than grouped under a placeholder.
    Every sentence this feeds names the tool, so an unnamed one has nothing to say, and the
    table below keys on the name -- SQLite permits NULL in a PRIMARY KEY column and treats
    two NULLs as distinct, so admitting them would quietly grow a duplicate row per session.
    """
    if not os.path.exists(path or DB_PATH):
        return {}
    shape = {}
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            not_ours_sql, not_ours_params = _our_agents_clause(negate=True)
            cursor.execute(
                "SELECT tool_name, COUNT(*), MAX(amount), MAX(timestamp) FROM event_log "
                "WHERE status IS ? AND tool_name IS NOT NULL AND " + not_ours_sql +
                " GROUP BY tool_name",
                (INVENTORY_STATUS, *not_ours_params))
            for name, calls, amount, last_ts in cursor.fetchall():
                shape[name] = {"calls": calls or 0, "max_amount": amount or 0.0,
                               "arg_names": set(), "classes": set(), "combos": set(),
                               "max_burst": 0, "max_burst_at": None, "hours": set(), "weekend": False,
                               "max_day_calls": 0, "max_day": None, "last_ts": last_ts or 0.0}
            # ONE pass for every tool's argument names and classes, rather than the
            # per-tool query `get_call_inventory` runs. This one is called from atexit in
            # the developer's own process, so the N+1 is a cost their session pays.
            cursor.execute(
                "SELECT DISTINCT tool_name, arg_names, target_class FROM event_log "
                "WHERE status IS ? AND tool_name IS NOT NULL AND " + not_ours_sql,
                (INVENTORY_STATUS, *not_ours_params))
            for name, arg_names, target_class in cursor.fetchall():
                entry = shape.get(name)
                if entry is None:
                    continue
                entry["arg_names"].update(n for n in (arg_names or "").split(",") if n)
                if target_class:
                    entry["classes"].add(target_class)
                # 🔴 THE COMBINATION, NOT JUST THE UNION, and the difference is a whole class
                # of signal. Unioning the names answers "what can this tool take"; the SET OF
                # COMBINATIONS answers "what did this call actually pass", which is the only
                # way an argument going MISSING is visible. A query that always carried a
                # `limit` and one day does not is the shape of an unbounded read, and under a
                # union it is indistinguishable from any other call.
                #
                # Stored as a sorted csv so two calls passing the same keywords in a different
                # order are one combination rather than two.
                entry["combos"].add(",".join(sorted(
                    n for n in (arg_names or "").split(",") if n)))

            # --- THE TIME-SHAPED HALF, IN ONE PASS -------------------------------------
            #
            # Everything above is SHAPE, and shape is finite: one tool has one surface, a
            # handful of argument names and one magnitude range, so a developer who wrapped a
            # single function runs out of news almost immediately. Measured on ten sessions of
            # one realistic tool: EIGHT were silent, including the one that dropped an
            # argument it had always passed and the one that ran 45 calls against a previous
            # best of 20. Time-shaped facts are what renew, because a RECORD can always be
            # broken where a FIRST cannot happen twice.
            #
            # Grouped to the MINUTE and folded up in Python rather than run as four queries:
            # per-minute counts give the burst record directly, summing them by day gives the
            # daily record, and the hour and weekday come along on the same rows.
            #
            # ⚠️ LOCALTIME, DELIBERATELY. These end up in sentences a human reads about their
            # own working day -- "busiest day yet", "first call between 03:00 and 04:00" --
            # and a UTC day boundary would put a developer's evening work on tomorrow's date.
            # The stored timestamps stay epoch; only this reader localises.
            # ⚠️ ONE strftime, NOT FIVE, AND IT IS WORTH 17 MILLISECONDS. The first version
            # asked for the day, hour, weekday and minute as four separate conversions plus a
            # fifth for the grouping key, and every one of them runs per ROW: on a ledger at
            # the P-97 ceiling that took this function from 5.4 ms to 23.5 ms. One combined
            # key sliced in Python gives the same four facts, because they are all prefixes or
            # suffixes of the same string. Measured before and after, not assumed.
            cursor.execute(
                "SELECT tool_name,"
                "       strftime('%Y-%m-%d %H:%M %w', timestamp, 'unixepoch', 'localtime'),"
                "       COUNT(*)"
                "  FROM event_log"
                " WHERE status IS ? AND tool_name IS NOT NULL AND timestamp IS NOT NULL"
                "   AND " + not_ours_sql +
                " GROUP BY tool_name, 2",
                (INVENTORY_STATUS, *not_ours_params))
            per_day = {}
            for name, stamp, count in cursor.fetchall():
                # "2026-06-01 09:00 1" -> day, hour, minute-key, weekday.
                if not stamp or len(stamp) < 18:
                    continue
                day, hour, minute, weekday = stamp[:10], stamp[11:13], stamp[:16], stamp[-1]
                entry = shape.get(name)
                if entry is None:
                    continue
                count = count or 0
                if count > entry["max_burst"]:
                    entry["max_burst"] = count
                    entry["max_burst_at"] = minute
                if hour:
                    entry["hours"].add(hour)
                if weekday in ("0", "6"):
                    entry["weekend"] = True
                if day:
                    key = (name, day)
                    per_day[key] = per_day.get(key, 0) + count
            for (name, day), count in per_day.items():
                entry = shape[name]
                if count > entry["max_day_calls"]:
                    entry["max_day_calls"] = count
                    entry["max_day"] = day
    except Exception:
        # A ledger we cannot read has nothing NEW to say about it, and the callers of this
        # print a line only when there is one. Silence is the correct failure here: the
        # screens that must tell "unreadable" apart from "empty" read get_call_inventory,
        # which carries `readable` for exactly that.
        return {}
    return shape


# 🔴 "NEVER WATERMARKED" AND "COULD NOT READ IT" ARE DIFFERENT ANSWERS, and one value for
# both is the template this branch has now fixed five times (the seen-flag split, the
# column-tolerant select, the empty combination, and three ours-vs-theirs counts). The
# last instance lived in `advance_watermark`: it took `_read_watermark(...) or {}`, so a
# transient read failure merged the new state against NOTHING and every running maximum,
# set and timestamp was rewritten DOWNWARD -- breaking the "a watermark only ever moves
# up" invariant its own docstring promises, and re-announcing a record the tool had
# already set. Cheap to split now that the missing-table case is answered by the PRAGMA
# below rather than by the exception handler.
_WATERMARK_UNREADABLE = object()


def _read_watermark(watermark, path=None):
    """The stored aggregate for `watermark`.

    THREE answers, and callers depend on telling them apart:
      dict                    -- what we had seen
      None                    -- never watermarked, so everything is new
      _WATERMARK_UNREADABLE   -- we could not read it, so we know NOTHING

    None and {} are different answers and the caller depends on it: None means this ledger
    has never been watermarked, so everything in it is new and the surfaces say "first look"
    rather than announcing a year of history as though it happened this afternoon.
    """
    if not os.path.exists(path or DB_PATH):
        return None
    try:
        with _connection(path) as conn:
            cursor = conn.cursor()
            _ensure_novelty_columns(conn)
            # 🔴 SELECT WHAT THE TABLE ACTUALLY HAS, NOT WHAT THIS VERSION EXPECTS. The
            # ALTER above is best-effort and its comment claimed a graceful degradation --
            # "the missing columns come back as absent keys and the signals that depend on
            # them stay quiet". That was false: naming all thirteen columns made the SELECT
            # RAISE on a ledger we could not ALTER, the handler returned None, and None is
            # the sentinel for NEVER WATERMARKED -- so the entire watermark was discarded and
            # every tool re-announced as a first call, every session, silently. The failure
            # was total where the comment promised partial. Now the promise is the code.
            have = {r[1] for r in conn.execute("PRAGMA table_info(ledger_novelty)")}
            wanted = ["tool_name", "arg_names", "classes", "max_amount", "calls",
                      "arg_combos", "max_day_calls", "max_day", "max_burst", "max_burst_at",
                      "hours", "weekend", "last_ts"]
            present = [c for c in wanted if c in have]
            if "tool_name" not in present:
                return None
            cursor.execute(
                "SELECT %s FROM ledger_novelty WHERE watermark IS ?" % ", ".join(present),
                (watermark,))
            rows = [dict(zip(present, r)) for r in cursor.fetchall()]
    except Exception:
        # NOT "no such table" any more -- the PRAGMA above answers that by returning None
        # cleanly, which is what lets this handler mean one thing: a lock, a corrupt file,
        # a permission error. We know nothing about what was stored, and saying "nothing
        # was" would let the caller overwrite it.
        return _WATERMARK_UNREADABLE
    if not rows:
        return None
    stored = {}
    for row in rows:
        name = row.get("tool_name")
        arg_names, classes = row.get("arg_names"), row.get("classes")
        max_amount, calls = row.get("max_amount"), row.get("calls")
        combos, max_day_calls = row.get("arg_combos"), row.get("max_day_calls")
        max_day, max_burst = row.get("max_day"), row.get("max_burst")
        max_burst_at, hours = row.get("max_burst_at"), row.get("hours")
        weekend, last_ts = row.get("weekend"), row.get("last_ts")
        stored[name] = {
            "calls": calls or 0,
            "max_amount": max_amount or 0.0,
            "arg_names": {n for n in (arg_names or "").split(",") if n},
            "classes": {c for c in (classes or "").split(",") if c},
            # 🔴 JSON, NOT A SEPARATOR, AND THE EMPTY MEMBER IS WHY. A call that takes NO
            # arguments is a real combination, and its member is the empty string. Every
            # other set on this row is separator-joined and filtered with `if c` on the way
            # back, which is correct for them -- there is no such thing as an empty argument
            # NAME or an empty surface -- and silently wrong here: the no-argument
            # combination was written, dropped on read, and therefore counted as brand new on
            # every single session. `dropped` then compared the intersection of everything
            # else against an empty set and announced "called without <every argument> for
            # the first time", forever, top-ranked, about a call the developer had made weeks
            # earlier. Reproduced end to end before fixing.
            #
            # A set whose members can legitimately be empty needs a serialisation that
            # round-trips exactly, not one that filters. `test_every_stored_set_round_trips`
            # pins this for all four sets so the next one added cannot repeat it.
            "combos": set(_loads_set(combos)),
            "max_day_calls": max_day_calls or 0,
            "max_day": max_day,
            "max_burst": max_burst or 0,
            "max_burst_at": max_burst_at,
            "hours": {h for h in (hours or "").split(",") if h},
            "weekend": bool(weekend),
            "last_ts": last_ts or 0.0,
        }
    return stored


def _watermark_busiest(watermark, path=None):
    """Which tool was busiest when this watermark was last advanced, or None.

    Stored, not derived. See `_record_changed` for why deriving it from the call counts is a
    permanent nag rather than a one-off wrong answer.
    """
    if not os.path.exists(path or DB_PATH):
        return None
    try:
        with _connection(path) as conn:
            _ensure_novelty_seen_columns(conn)
            row = conn.execute(
                "SELECT busiest FROM ledger_novelty_seen WHERE watermark IS ?",
                (watermark,)).fetchone()
    except Exception:
        return None
    return row[0] if row else None


def _watermark_seen(watermark, path=None):
    """Has this surface ever run for this ledger? Never raises; False on anything unreadable.

    Deliberately separate from `_read_watermark`. "We have no rows for you" and "you have
    never looked" are different facts, and answering the second with the first is what put
    FIRST LOOK on a screen the reader had already opened.
    """
    if not os.path.exists(path or DB_PATH):
        return False
    try:
        with _connection(path) as conn:
            row = conn.execute(
                "SELECT 1 FROM ledger_novelty_seen WHERE watermark IS ?",
                (watermark,)).fetchone()
    except Exception:
        # "no such table" is the ordinary state of every ledger written before this shipped.
        return False
    return bool(row)


def advance_watermark(watermark, path=None, current=None):
    """Store `current` as what this watermark has now seen. Best-effort; never raises.

    ⚠️ A WATERMARK ONLY EVER MOVES UP, and there are TWO separate reasons, which is worth
    stating because they are easy to conflate and only one of them is this merge.

      1. A tool whose rows are ALL trimmed is protected by the loop, not by the merge: this
         iterates `current`, so a tool that has vanished from the ledger is simply not
         written, and its stored row stays exactly as it was.
      2. A tool whose rows are PARTIALLY trimmed is what the merge is for, and nothing else
         covers it. Retention drops the OLDEST rows first, so a tool that once passed
         ≥10,000 and now has only a ≥1,000 row left reports a SMALLER max than we have
         already seen. Overwriting would lower the watermark, and the tool's next large call
         would be announced as a record it had already set -- a false claim manufactured by
         our own housekeeping, which is the class P-97 was decided under. Argument names
         behave the same way: the row carrying `cc` ages out, and `cc` becomes new again.

    ⚠️ An earlier version of this docstring gave reason 1 as the justification for the merge.
    It is a true statement about the behaviour and the wrong explanation of this code, and a
    fault injection is what caught it: removing the merge left the test green.

    🔴 THE SURFACE IS MARKED AS HAVING RUN EVEN WHEN THERE IS NOTHING TO STORE, and that is
    a correctness fix, not tidiness. `first_look` is a claim about whether the READER has
    ever seen this screen, and an early return on an empty aggregate computed it from
    whether WE had rows -- two different questions. On the first run of the ladder every row
    in the ledger is ours, so `agentx audit` stored nothing, and the NEXT run still believed
    nobody had ever looked and headed the block "FIRST LOOK AT THIS LEDGER" for a founder
    who had run the command two steps earlier. Found by walking the ladder in one directory.

    This screen already had the rule, four lines above where this hooks in:
    `mark_audit_report_run` is written BEFORE the screen renders and is "never gated on what
    the screen FOUND", because the question is whether a human took the step. Same question
    here, and the same answer.
    """
    if current is None:
        current = current_call_shape(path)
    stored = _read_watermark(watermark, path)
    # 🔴 A READ WE COULD NOT DO IS NOT AN EMPTY READ. `or {}` treated them the same, so a
    # transient failure merged the new state against nothing and rewrote every running
    # maximum, set and timestamp DOWNWARD -- the exact invariant the docstring above
    # promises, broken by the handler meant to be defensive. The mark still goes in (a human
    # did take the step, and that is a different fact), but the per-tool detail is left
    # exactly as it was rather than replaced by a lower version of itself.
    unreadable = stored is _WATERMARK_UNREADABLE
    stored = {} if unreadable or stored is None else stored
    # 🔴 A MISSING LEDGER IS NOT MARKED. _connection() opens via sqlite3.connect, which CREATES the
    # file, so without this guard a caller asking only to record that somebody LOOKED would conjure
    # a database to write that mark into.
    #
    # ⚠️ READ THIS BEFORE DELETING THE GUARD, because it looks like the defect the docstring above
    # warns against and it is not. That defect was a ledger WITH rows whose aggregate came back
    # empty (on the first ladder run every row is ours), which made the NEXT run head the block
    # "FIRST LOOK AT THIS LEDGER" for someone who had run the command two steps earlier. That path
    # is untouched: the file exists, so we fall through and mark it exactly as before.
    #
    # What is genuinely given up is narrower -- the no-file case -- and three things make it
    # acceptable rather than hidden:
    #   1. The funnel record survives. `pulse.mark_audit_report_run` writes the "a human ran
    #      agentx audit" flag to the pulse file, not to this ledger, so the conversion event the
    #      P-92 funnel is built on is still captured.
    #   2. Nothing is announced on the empty run either way. `read_novelty` returns its `empty`
    #      literal with first_look=False whenever `current_call_shape` is falsy, which a missing
    #      ledger always is.
    #   3. The header the flag drives says "first look at THIS LEDGER". If no ledger existed when
    #      they last looked, the next run is the first look at one, so the claim stays true.
    # ⚠️ DEFENSIVE, AND SAID PLAINLY BECAUSE A FAULT INJECTION PROVED IT. Removing this guard does
    # NOT redden the read-only-command test: no shipped path reaches here without a ledger today.
    # The two novelty-line callers are gated behind `if items:`, and items require rows; the one
    # caller that deliberately marks an EMPTY screen is not reached, because execute_audit returns
    # on its own empty branch first. Kept anyway, and pinned by its own direct test, because
    # `advance_watermark` creating a database purely to record that somebody looked is a landmine
    # for the next caller -- and the record-while-blocking work rewrites exactly these paths.
    if not os.path.exists(path or DB_PATH):
        return False
    try:
        with _connection(path) as conn:
            conn.execute(_CREATE_NOVELTY_SQL)
            conn.execute(_CREATE_NOVELTY_SEEN_SQL)
            # The mark goes in FIRST and unconditionally. Everything below is the per-tool
            # detail, which an empty ledger simply does not have.
            _ensure_novelty_seen_columns(conn)
            # The busiest tool's NAME rides with the mark, because it is a ledger-level fact
            # rather than a per-tool one, and because storing the identity is what stops the
            # record re-firing (see _record_changed). Falls back to what was already stored
            # when the current ledger has nothing to say, so a trim cannot erase it.
            conn.execute(
                "INSERT OR REPLACE INTO ledger_novelty_seen (watermark, ts, busiest) "
                "VALUES (?, ?, ?)",
                (watermark, time.time(),
                 _busiest(current) or _watermark_busiest(watermark, path)))
            _ensure_novelty_columns(conn)
            for name, entry in ({} if unreadable else (current or {})).items():
                was = stored.get(name) or {}
                names = sorted(set(entry["arg_names"]) | set(was.get("arg_names") or ()))
                classes = sorted(set(entry["classes"]) | set(was.get("classes") or ()))
                hours = sorted(set(entry["hours"]) | set(was.get("hours") or ()))
                # 🔴 CAPPED, BECAUSE THIS ONE CAN GROW WITHOUT BOUND. Every other field here
                # is drawn from a small closed set -- 24 hours, six surfaces, one number --
                # but a tool called with many optional keywords has combinatorially many
                # argument combinations, and each is a distinct member. Past the cap we STOP
                # ADDING rather than evicting: an eviction policy would make a combination
                # "new" again later and re-announce a missing argument that has been normal
                # for weeks. A tool this varied has no stable "always passes X" to violate,
                # so the signal is meaningless for it anyway, and going quiet is the honest
                # end state.
                #
                # 🔴 CAPPED PER ADDITION, NOT PER CALL. The first version tested the size and
                # then unioned the whole batch in, so one advance carrying 34 combinations
                # sailed past a cap of 24 and stored all of them -- a size check that only
                # decided WHETHER to grow, never BY HOW MUCH. Caught by the test that asserts
                # the bound rather than by reading the branch, which looks correct. Sorted so
                # which ones survive is deterministic rather than set-iteration order.
                combos = set(was.get("combos") or ())
                for combo in sorted(entry["combos"]):
                    if len(combos) >= _MAX_ARG_COMBOS:
                        break
                    combos.add(combo)
                # A record only ever moves up. `max_day` travels WITH its count so the
                # sentence can name the day the record was set; taking the larger of the two
                # counts and the date beside it keeps them from drifting apart.
                if (was.get("max_day_calls") or 0) >= entry["max_day_calls"]:
                    day_calls, day = was.get("max_day_calls") or 0, was.get("max_day")
                else:
                    day_calls, day = entry["max_day_calls"], entry["max_day"]
                # Same pairing for the burst record: the minute it was set travels with the
                # count, so the reader is told about one record-setting minute once rather
                # than watching a still-open minute climb.
                if (was.get("max_burst") or 0) >= entry["max_burst"]:
                    burst, burst_at = was.get("max_burst") or 0, was.get("max_burst_at")
                else:
                    burst, burst_at = entry["max_burst"], entry["max_burst_at"]
                # INSERT OR REPLACE rather than an UPSERT clause: the merge above is already
                # done in Python, so the two are equivalent here, and `ON CONFLICT ... DO
                # UPDATE` needs SQLite 3.24+. The SDK ships to whatever sqlite3 the user's
                # Python was built against, and a version floor nobody declared is a failure
                # that appears only on someone else's machine.
                conn.execute(
                    "INSERT OR REPLACE INTO ledger_novelty "
                    "(watermark, tool_name, arg_names, classes, max_amount, calls, "
                    " arg_combos, max_day_calls, max_day, max_burst, max_burst_at, hours,"
                    " weekend, last_ts)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (watermark, name, ",".join(names), ",".join(classes),
                     max(entry["max_amount"], was.get("max_amount") or 0.0),
                     max(entry["calls"], was.get("calls") or 0),
                     _dumps_set(combos), day_calls, day,
                     burst, burst_at,
                     ",".join(hours),
                     1 if (entry["weekend"] or was.get("weekend")) else 0,
                     max(entry["last_ts"], was.get("last_ts") or 0.0)))
            conn.commit()
    except Exception:
        # A watermark we could not store means the same novelty is offered again next time.
        # Repeating a true line is a far cheaper failure than suppressing one, so this is
        # silent rather than surfaced.
        return False
    return True


def _busiest(shape):
    """The NAME of the most-called tool, ties broken by name so it is stable.

    Returns a string, not a pair. The docstring said "(tool, calls)" while the body returned
    `[0][0]`; every caller happened to be right, so the next one written from the docstring
    would have been the first to unpack a string into two names.
    """
    if not shape:
        return None
    return sorted(shape.items(), key=lambda kv: (-kv[1]["calls"], kv[0]))[0][0]


def read_novelty(watermark, path=None, current=None):
    """What is new about this ledger since `watermark` was last advanced. Never raises.

    Returns ``{"items", "first_look", "busiest", "busiest_calls", "total_calls",
    "distinct_tools"}``. `items` are dicts of ``{"tool", "kind", "detail"}``; render them
    through `format_novelty_item` so both surfaces print the same words.

    🔴 THERE IS NO POSTURE CHECK IN HERE, AND ITS ABSENCE IS DELIBERATE. Under enforce the
    ledger holds no inventory rows, so this returns nothing and both surfaces stay quiet
    without being told why. On the day P-112's second half lands and enforce records too,
    this function lights up with no edit -- which is the "only the posture gate moves"
    requirement, expressed as code rather than as a note asking someone to remember.
    """
    empty = {"items": [], "first_look": False, "busiest": None, "busiest_calls": 0,
             "total_calls": 0, "distinct_tools": 0}
    if current is None:
        current = current_call_shape(path)
    if not current:
        # ⚠️ AND `first_look` STAYS FALSE HERE, WHICH IS DELIBERATE. An earlier version read
        # it above this line under a comment insisting it had to be computed BEFORE the empty
        # return -- and then returned the `empty` literal, discarding it. The comment
        # described an intention the code did not carry out, and the round-trip to the ledger
        # was paid on every empty read, including every `agentx status`.
        #
        # There is nothing to claim on this path: no items means no header, and no header
        # means nothing for the flag to qualify. The defect that comment was aimed at lives
        # in `advance_watermark`, which marks the surface as having run whether or not it
        # found anything -- that is what makes the NEXT read say "new since you last looked"
        # instead of "first look" for someone who has already been here.
        return empty
    first_look = not _watermark_seen(watermark, path)
    stored = _read_watermark(watermark, path)
    if stored is _WATERMARK_UNREADABLE:
        # We cannot say what is NEW without knowing what was OLD. Treating an unreadable
        # watermark as an empty one would announce the developer's whole history as though
        # it had just happened -- the loudest possible wrong answer, produced by a lock.
        return empty
    stored = stored or {}

    items = []
    for name in sorted(current):
        entry = current[name]
        was = stored.get(name)
        # Ordered by what a reader would want first if the list is trimmed: a surface we had
        # never seen this tool touch, then a bigger magnitude than it has ever carried, then
        # the tool itself, and argument names last -- they are the noisiest of the four,
        # since one optional keyword adds one.
        new_classes = sorted(
            c for c in entry["classes"]
            if c in _SURFACE_WORDS and c not in ((was or {}).get("classes") or ()))
        for target_class in new_classes:
            items.append({"tool": name, "kind": "surface", "detail": target_class})
        # The stored `amount` IS a bucket floor, never a measurement (see _call_shape), so
        # comparing the numbers compares the buckets. A raw comparison would announce a new
        # record for 1,001 against 1,000 -- two calls the screen renders identically.
        #
        # ⚠️ AND ONLY FOR A TOOL WE ALREADY KNEW (`was`), which is a deliberate silence.
        # "Largest amount yet" is a claim about a history, and a tool on its first appearance
        # does not have one -- the honest headline there is the tool itself. The magnitude is
        # not lost: the table under this block prints it per tool either way.
        #
        # ⚠️ THIS COLUMN IS EMPTY UNLESS THE CALL ALSO NAMED A CURRENCY (P-103's rule, in
        # _call_shape), so `{"amount": 1500}` alone never fires this. Verified rather than
        # assumed -- the first smoke run of this function showed no amount item at all and
        # the branch looked exercised.
        if was and entry["max_amount"] > (was.get("max_amount") or 0.0):
            items.append({"tool": name, "kind": "amount", "detail": entry["max_amount"]})
        # 🔴 ONLY WHEN THE SURFACE LINE DID NOT ALREADY SAY IT. A tool we have never seen
        # necessarily reaches every surface it reaches for the first time, so both branches
        # fire and the block printed the same tool twice: "run_sql — first call to your
        # database" directly above "run_sql — first time we have seen this tool". One fact,
        # two sentences, and the second is the weaker of them. The surface line wins because
        # it is the half a reader can act on -- "a new tool" is a fact about our records,
        # "it reached your database" is a fact about their agent.
        if was is None and not new_classes:
            items.append({"tool": name, "kind": "tool", "detail": None})
        new_args = sorted(set(entry["arg_names"]) - set((was or {}).get("arg_names") or ()))
        # Only for a tool we already knew. On a brand-new tool every argument is new, and
        # "first time we have seen this tool" followed by a list of the arguments it takes
        # is one fact printed twice.
        if was is not None and new_args:
            items.append({"tool": name, "kind": "argument", "detail": new_args})

        # --- THE TIME-SHAPED AND COMBINATION SIGNALS -------------------------------------
        # Added because the shape signals above are FINITE and a developer who wrapped one
        # function exhausts them in a session or two. Every one of these can fire again.
        if was is not None:
            # 🔴 AN ARGUMENT THAT WENT MISSING, which is the security-shaped one. Reported
            # only for something EVERY previous call carried, computed as the intersection of
            # the stored combinations -- so a keyword that has always been optional is not
            # news, and a `limit` that has never once been absent is.
            old_combos = set(was.get("combos") or ())
            fresh = set(entry["combos"]) - old_combos
            if old_combos and fresh and len(old_combos) < _MAX_ARG_COMBOS:
                always_had = set.intersection(
                    *[{n for n in c.split(",") if n} for c in old_combos])
                for combo in sorted(fresh):
                    dropped = sorted(always_had - {n for n in combo.split(",") if n})
                    if dropped:
                        items.append({"tool": name, "kind": "dropped", "detail": dropped})
                        break
            # A RECORD, not a first, which is why it can fire forever. The day travels with
            # the count so the sentence can say what it beat.
            #
            # 🔴 ONCE PER RECORD-SETTING DAY, NOT ONCE PER SESSION. A record for a day still in
            # progress keeps growing, so without the day comparison a developer who runs their
            # agent six times on a busy Tuesday is told "busiest day yet" six times, with a
            # bigger number each time -- and one of those sessions made two calls. Every one
            # of those sentences is true and the sequence is a nag. Found by simulating ten
            # sessions of one tool, where it read "session 5 (2 calls): busiest day yet: 38".
            # Comparing the DAY rather than the COUNT collapses them to one.
            if (entry["max_day_calls"] > (was.get("max_day_calls") or 0)
                    and _record_changed(entry["max_day"], was.get("max_day"))):
                items.append({"tool": name, "kind": "busiest_day",
                              "detail": (entry["max_day_calls"], was.get("max_day_calls") or 0)})
            # Same rule at minute resolution, keyed on the minute the record was set. A
            # runaway loop looks exactly like this, which is why it earns a line even on a
            # well-behaved agent -- it is the one that will not be well-behaved. Floored so an
            # ordinary two-calls-in-a-minute is not a "record".
            if (entry["max_burst"] > (was.get("max_burst") or 0)
                    and entry["max_burst"] >= _BURST_WORTH_SHOWING
                    and _record_changed(entry["max_burst_at"],
                                       was.get("max_burst_at"))):
                items.append({"tool": name, "kind": "burst", "detail": entry["max_burst"]})

    # --- FACTS ABOUT THE AGENT, NOT ABOUT A TOOL --------------------------------------
    #
    # 🔴 WHEN the agent ran is a property of the SESSION, and emitting it per tool was pure
    # repetition. Measured on five tools in one late-night weekend session: "first call
    # between 03:00 and 04:00" appeared THREE times and "first weekend call" THREE times --
    # six of the fifteen items, all saying two things. That alone overflowed a six-line
    # screen and pushed out a magnitude record and a new tool.
    #
    # The union across tools is the right question: the agent has run at this hour before, or
    # it has not. These carry no tool name because naming one would be arbitrary -- the
    # renderers print them unprefixed.
    if stored:
        hours_now = set().union(*[e["hours"] for e in current.values()]) if current else set()
        hours_before = set().union(*[set(e.get("hours") or ()) for e in stored.values()])
        # 🔴 AN HOUR NEXT TO ONE WE HAVE ALREADY SEEN IS THE SAME WORKING WINDOW, NOT A NEW
        # ONE. Founder run: day one at 10:53, day two at 11:00 -- seven minutes later in real
        # time -- and this printed "first call between 11:00 and 12:00", then outranked BOTH
        # "first call in 9 days" and "busiest day yet" off a two-line teaser. A developer who
        # works ordinary hours would collect eight or ten of these in their first week, each
        # trivially true and none of them news.
        #
        # The signal was built for the opposite case: an agent running at 3am when it has
        # only ever run at 10am. Distance is what separates those, so distance is the rule --
        # circular, because 23:00 and 00:00 are an hour apart, not twenty-three.
        far_hours = sorted(
            h for h in (hours_now - hours_before)
            if all(_hour_distance(h, seen) > _HOUR_SAME_WINDOW for seen in hours_before))
        if far_hours and hours_before:
            items.append({"tool": "", "kind": "hour", "detail": far_hours[0]})
        if (any(e["weekend"] for e in current.values())
                and not any(e.get("weekend") for e in stored.values())):
            items.append({"tool": "", "kind": "weekend", "detail": None})

        # 🔴 THE RETURN IS A SESSION FACT TOO, and it was in the per-tool loop. Five tools
        # idle for a month produced FIVE "first call in 29 days" lines -- the entire audit
        # block and both teaser slots, all saying one thing. Exactly what `hour` and
        # `weekend` were lifted out of that loop for, re-introduced two commits later by
        # adding a new signal inside it. Computed over the newest call in the whole ledger.
        gap = (max((e["last_ts"] for e in current.values()), default=0.0)
               - max((e.get("last_ts") or 0.0 for e in stored.values()), default=0.0))
        if any(e.get("last_ts") for e in stored.values()) and gap >= _GAP_WORTH_SHOWING:
            items.append({"tool": "", "kind": "gap", "detail": gap})

    # 🔴 IDENTITY, NOT THE COUNT. `stored` holds a running MAX per tool, so once retention
    # trims the previous leader's rows the derived answer disagrees with the live ledger
    # FOREVER and re-announces every session. Same rule as the day and burst records.
    busiest_now = _busiest(current)
    busiest_before = _watermark_busiest(watermark, path)
    if busiest_before and _record_changed(busiest_now, busiest_before):
        # ⚠️ AND IT HAS TO BE A REAL LEAD, NOT A TIE-BREAK. `_busiest` breaks ties by name so
        # its answer is stable, which means two tools on one call each swap the title purely
        # on alphabetical order -- and "now your busiest tool" fires over nothing. Found by
        # an existing trimmed-tool test going red on this change, not by review. Compared
        # against the previous holder's count IN THE CURRENT LEDGER, so a leader that was
        # trimmed away does not hand over the title on a technicality either.
        now_calls = current[busiest_now]["calls"]
        before_calls = (current.get(busiest_before) or {}).get("calls", 0)
        if now_calls > before_calls and now_calls >= _BUSIEST_MIN_CALLS:
            items.append({"tool": busiest_now, "kind": "busiest", "detail": None})

    # Ordered by what a reader would want first when the list is trimmed, and the two at the
    # top are the two that could mean something is wrong: an argument that went missing and a
    # surface this tool had never touched. Records next, because they are the ones that recur.
    # Argument names last -- one optional keyword adds one, so it is the noisiest.
    order = {"dropped": 0, "surface": 1, "amount": 2, "burst": 3, "busiest_day": 4,
             "hour": 5, "weekend": 6, "tool": 7, "busiest": 8, "gap": 9, "argument": 10}
    # Default 99, NOT 9: 9 is `gap`'s own rank, so a kind added later would have silently
    # interleaved with it rather than sorting last as the comment above promises.
    items.sort(key=lambda i: (order.get(i["kind"], 99), i["tool"]))
    total = sum(e["calls"] for e in current.values())
    return {"items": items, "first_look": first_look, "busiest": busiest_now,
            "busiest_calls": current[busiest_now]["calls"] if busiest_now else 0,
            "total_calls": total, "distinct_tools": len(current)}


def top_novelty(items, limit):
    """The `limit` most worth showing, AT MOST ONE PER TOOL. Shared, so surfaces can't drift.

    🔴 BREADTH BEFORE DEPTH, AND MEASURED RATHER THAN GUESSED. `read_novelty` ranks purely by
    KIND, so every item of the loudest kind sorts ahead of every item of the next -- and on
    five tools in one eventful session that put two "busiest day yet" lines above BOTH
    session-level facts, pushing "first call between 03:00 and 04:00" and "first weekend
    call" off a six-line screen. Two lines about the same kind of thing, at the cost of the
    two that were about something else.

    One per tool first, in rank order, then the remainder if there is room. A developer
    scanning two lines learns about two tools rather than twice about one.

    ⚠️ ITEMS BEYOND THE LIMIT ARE NOT KEPT FOR NEXT TIME. The watermark advances over
    everything that was COMPUTED, not everything that was SHOWN, so the overflow expires --
    which is why the callers print a count of it rather than dropping it silently. Queuing it
    would need a second store and would re-announce week-old news; the ranking exists so that
    what expires is the least of it. The two surfaces keep SEPARATE watermarks, so anything
    the session line has no room for is still waiting when `agentx audit` runs.
    """
    picked, seen = [], set()
    for item in items:
        tool = item.get("tool") or ""
        if tool and tool in seen:
            continue
        seen.add(tool)
        picked.append(item)
        if len(picked) >= limit:
            return picked
    for item in items:
        if item not in picked:
            picked.append(item)
            if len(picked) >= limit:
                break
    return picked


def format_novelty_item(item):
    """The words for one novelty item, in ONE place because TWO surfaces print them.

    The session-end line and `agentx audit` show the same facts, and the last time this
    project let two surfaces word the same thing separately they drifted -- which is why
    `format_protection_line` and `format_staleness_line` exist next door. Returns "" for
    anything unrecognised, so an item kind added later cannot print a bare dict.
    """
    kind = item.get("kind")
    if kind == "surface":
        word = _SURFACE_WORDS.get(item.get("detail"))
        return "first call to your %s" % word if word else ""
    if kind == "amount":
        # "amount", not "number": the column holds the magnitude of an argument the tool
        # itself NAMED as an amount. And "yet", because a bucket floor is a lower bound.
        amount = item.get("detail") or 0
        try:
            return "largest amount yet: ≥%s" % f"{int(amount):,}"
        except Exception:
            return ""
    if kind == "tool":
        return "first time we have seen this tool"
    if kind == "busiest":
        return "now your busiest tool"
    if kind == "dropped":
        names = list(item.get("detail") or ())
        if not names:
            return ""
        return "called without %s for the first time" % ", ".join(names[:_MAX_NEW_ARGS_SHOWN])
    if kind == "busiest_day":
        try:
            now, before = item.get("detail")
        except Exception:
            return ""
        # The previous record is stated beside the new one, because "45 calls" alone is a
        # number the reader has to have been keeping track of to find interesting.
        if before:
            return "busiest day yet: %d calls (previous best %d)" % (now, before)
        return "busiest day yet: %d calls" % now
    if kind == "burst":
        return "%d calls in one minute, the most yet" % (item.get("detail") or 0)
    if kind == "hour":
        hour = item.get("detail")
        try:
            # % 24 so the last hour of the day does not render "between 23:00 and 24:00",
            # which is not a time anybody writes.
            return "first call between %02d:00 and %02d:00" % (int(hour), (int(hour) + 1) % 24)
        except Exception:
            return ""
    if kind == "weekend":
        return "first weekend call"
    if kind == "gap":
        days = int((item.get("detail") or 0) // 86400)
        if days < 1:
            return ""
        return "first call in %d days" % days
    if kind == "argument":
        names = list(item.get("detail") or ())
        if not names:
            return ""
        shown = ", ".join(names[:_MAX_NEW_ARGS_SHOWN])
        extra = len(names) - _MAX_NEW_ARGS_SHOWN
        return "new argument%s: %s%s" % ("" if len(names) == 1 else "s", shown,
                                         " +%d more" % extra if extra > 0 else "")
    return ""


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
def count_call_for_pulse(tool_name, stats, stats_lock=None, in_audit=False):
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
                _bump_audit_counters(tool_name, stats, in_audit)
        else:
            _bump_audit_counters(tool_name, stats, in_audit)
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


def _bump_audit_counters(tool_name, stats, in_audit):
    """Two counters, and the split is what keeps our own funnel readable.

    🔴 `audit_calls` ANSWERS "DID SOMEONE RUN THEIR AGENT UNDER AUDIT POSTURE", AND IT HAS TO
    KEEP ANSWERING THAT. It rides the anonymous pulse, and `scripts/funnel.py` derives
    `ran_audit` from it (`d["ran_audit"] |= bool(r.get("audit_calls"))`). Before P-112's
    enforce half only audit posture recorded, so "a row was written" and "the developer chose
    audit" were the same event and one counter could serve both.

    They are no longer the same event. Bumping `audit_calls` on every recorded call would make
    EVERY install pulse `audit_calls > 0`, including installs that never touched audit -- so
    `ran_audit` would quietly stop meaning adoption and start meaning "ran a protected tool at
    all". Nothing would break, no test would fail, and the funnel would keep reporting a
    number that answers a different question than the one its name asks. That is the failure
    this project keeps calling "a zero (or a one) that has not earned its meaning".

    So: `recorded_*` counts what was written, in any posture. `audit_*` counts audit posture
    only and is unchanged.

    ⚠️ `recorded_*` IS DELIBERATELY SESSION-LOCAL AND NOT ON THE PULSE. Nothing has a question
    for it yet -- not the funnel, and not, as an earlier version of this line claimed, "the
    screens". It has no production reader at all: the one screen that might have used it
    explicitly declines to (see the quiet-session arm in decorators.py, which gates on the
    posture-free rule instead and says why). It is written because the split is what keeps
    `audit_*` honest, and a counter that exists is cheaper to explain than one invented later.

    Adding a pulse field means the receiver allowlist plus an idempotent `usage_pulses`
    migration the founder has to run against live Supabase, and that is not worth paying
    for a signal nobody has asked a question of.
    `pulse.py` builds its payload from an explicit allowlist, so these keys cannot leak into
    it by accident -- if a question does turn up later, adding them is a deliberate act.
    """
    stats["recorded_calls"] = stats.get("recorded_calls", 0) + 1
    recorded_names = stats.setdefault("recorded_tool_names", set())
    if len(recorded_names) < _MAX_AUDIT_TOOL_NAMES:
        recorded_names.add(tool_name)
    stats["recorded_tools"] = len(recorded_names)

    if not in_audit:
        return
    stats["audit_calls"] = stats.get("audit_calls", 0) + 1
    names = stats.setdefault("audit_tool_names", set())
    if len(names) < _MAX_AUDIT_TOOL_NAMES:
        names.add(tool_name)
    stats["audit_tools"] = len(names)


def record_call(trace_id, agent_id, tool_name, arguments=None, stats=None, stats_lock=None,
                in_audit=False, description=None, matched_rule=None):
    """P-92: record ONE call that passed, in ANY posture. Best-effort, never raises.

    `matched_rule`: the adopted rule this call is the shape of, as
    `rules.match_adopted_rule` returns it, or None. When present the row carries the rule's
    id and name in `policy_id` / `policy_name`, columns that are NULL on every other
    `ALLOWED` row. The STATUS STAYS `ALLOWED`, and that is the design rather than an
    omission: the call ran and nothing stopped it, so every reader that counts `ALLOWED`
    rows -- the audit totals, the harvester, retention, the funnel -- goes on counting it.
    What changes is that the row can now say which rule it hit. The `rule-` prefix on
    `policy_id` is what tells a reader "annotation on a call that ran" from "the policy
    that stopped it", the same prefix that already guards deletes in `rules.py`.

    The rule's id and name are OUR strings (minted and stored by `adopt_rule`), so nothing
    from the caller's payload reaches the row through this parameter.

    (Said "in audit posture" until P-112's enforce half. This is the writer that half turns
    on, so its own first line claiming otherwise is the worst place for that to go stale.)

    The inventory writer. Deliberately a thin wrapper over log_intercept rather than its own
    INSERT, so it inherits the retention ceiling that hangs off that function instead of
    having to remember it -- a rule repeated at each call site lands on some of them.

    Callers pass the developer's raw kwargs; _call_shape reduces them to names, a magnitude
    bucket and a bounded class BEFORE anything reaches SQL, so no call site can hand a value
    to the ledger even by accident. That ordering is the guarantee, and
    sdk_tests/test_audit_inventory.py is what stops a future edit from inverting it -- four
    tests under its "Shape, never values" heading, one per writer: this one called directly,
    the WOULD_BLOCK path, and the decorator under each posture.

    ⚠️ THE FILE NAMED HERE USED TO BE `test_audit_inventory_records_no_values.py`, WHICH HAS
    NEVER EXISTED. A citation to a file nobody can open is worse than none: it reads as
    evidence and cannot be followed, and the same wrong name was copied into BACKLOG.md as
    the guarantee's home. Both corrected together.
    """
    names, amount, target_class, quantity = _call_shape(tool_name, arguments, description)
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
        count_call_for_pulse(tool_name, stats, stats_lock, in_audit)
    # `in_audit` has already been resolved by the caller through _resolve_enforcement, so a
    # tool pinned to audit by its own decorator argument arrives here as True even when the
    # rest of the run is enforcing. That is the case this column exists to make visible.
    rule_id = rule_name = None
    if matched_rule:
        rule_id = matched_rule.get("id")
        rule_name = matched_rule.get("name") or rule_id
    log_intercept(trace_id, agent_id, tool_name, rule_id, rule_name, INVENTORY_STATUS,
                  arg_names=names, amount=amount, target_class=target_class,
                  quantity=quantity, posture=("audit" if in_audit else "enforce"))


def log_intercept(trace_id, agent_id, tool_name, policy_id, policy_name, status, tokens=None, time_saved=None,
                  arg_names=None, amount=0.0, target_class=None, challenge_issued=None,
                  quantity=0.0, posture=None):
    # 🔴 CONTRACT: `arg_names`/`amount`/`target_class`/`quantity` MUST ALREADY BE REDUCED, via
    # `_call_shape`, before they reach here — never pass a raw `arguments` dict, a raw
    # query string, or an unreduced value to these three parameters. This function does
    # not call `_call_shape` itself and does not validate its inputs; it trusts every
    # caller to have already stripped values down to names/a bucket/a class. Every current
    # caller does (record_call and every WOULD_BLOCK writer route through `_call_shape`
    # first) — a future call site that skips that step would write a raw value straight to
    # the ledger with nothing here to stop it.
    #
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
        # 🔴 THE PERSISTENT HANDLE, NOT `_connection()`. Once the default posture records, this
        # runs inside every protected tool call, where opening a connection per write costs
        # ~6620 us against a 178 us call. See _write_connection for the measurements and for why
        # WAL is required rather than optional. The lock spans execute+commit as one unit.
        #
        # 🔴 THE WRITER STILL CREATES THE TABLE IT WRITES -- it moved to _write_connection, which
        # runs it ONCE per handle instead of once per call. init_db() no longer runs at import,
        # so this may still be the first thing in the process to touch the ledger, and without
        # that CREATE the INSERT below fails into the best-effort `except` and takes EVERY row
        # with it, silently. Doing it per handle rather than per call is most of what the
        # per-call CREATE was costing.
        #
        # ⚠️ IT STILL DOES NOT MIGRATE, AND THAT IS STILL THE POINT. `IF NOT EXISTS` is a no-op
        # against an existing pre-P-92 event_log, which is correct: the retry below stays the
        # WHOLE guarantee that a catch still gets recorded on a ledger the migration has not
        # reached. Upgrading an existing ledger is ensure_ledger_current's job and it runs at the
        # entry points, never on this path.
        with _write_lock:
            try:
                conn = _write_connection()
                # 🔴 THE CATCH ROW COMMITS DURABLY; THE ROUTINE ROW DOES NOT. The handle runs
                # `synchronous=NORMAL`, and that choice was argued entirely from the inventory
                # hot path -- "it risks only the most recent commits on an OS crash or power
                # cut" is an acceptable trade for routine traffic we now write on every call.
                # It is NOT the same trade for a block. This function is the single writer for
                # CHALLENGED rows too, which this file elsewhere calls "the record this
                # product exists to keep", and before this branch those committed at SQLite's
                # default FULL. Quietly weakening them was a side effect of speeding up a
                # different row, and nothing on any screen would have shown it.
                #
                # Paid only where it is owed: blocks are rare by construction, so the extra
                # disk sync costs nothing in aggregate, while the routine rows that made the
                # persistent handle necessary keep NORMAL.
                #
                # 🔴 PUT BACK IN A `finally`, AND THE FIRST CUT'S ARGUMENT FOR NOT NEEDING ONE
                # COVERED HALF THE EXITS. It read "if anything below raises, the handle is
                # dropped in the `except`, so a connection can never be left sitting at FULL"
                # -- true of an `Exception`, false of a `BaseException`. This function runs
                # inside every protected tool call, so a Ctrl-C between the pragma and the
                # commit is ordinary, and it walks straight past that `except Exception`: the
                # handle stays CACHED and stays at FULL for the life of the process, so every
                # later routine row pays the fsync this handle exists to avoid. Measured: the
                # next inventory row committed at synchronous=2.
                #
                # 🔴 AND THE PRAGMA MOVED INSIDE THE `try`, BECAUSE OUTSIDE IT THE `finally`
                # DID NOT COVER THE STATEMENT IT EXISTS FOR. A Ctrl-C landing after this
                # execute returned but before the `try` was entered left the cached handle at
                # FULL with nothing to put it back -- the exact defect the paragraph above
                # describes, in a one-statement window, in the fix for it.
                #
                # ⚠️ `_write_conn_fast` GATES IT. A handle whose filesystem refused WAL was
                # never lowered to NORMAL (see _write_connection), so it is ALREADY at FULL:
                # raising it is a no-op and "restoring" it to NORMAL afterwards would hand
                # every later routine row the rollback-journal + NORMAL combination SQLite
                # documents as corruption-capable. The switch only ever undoes what we did.
                _durable = _write_conn_fast and status != INVENTORY_STATUS
                try:
                    if _durable:
                        conn.execute("PRAGMA synchronous=FULL")
                    cursor = conn.cursor()
                    try:
                        cursor.execute(
                            "INSERT INTO event_log (%s, arg_names, amount, target_class, "
                            "challenge_issued, quantity, posture) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" % _COLUMNS,
                            _values + (arg_names, amount if amount is not None else 0.0,
                                       target_class, challenge_issued,
                                       quantity if quantity is not None else 0.0,
                                       posture))
                    except sqlite3.OperationalError:
                        cursor.execute(
                            "INSERT INTO event_log (%s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                            % _COLUMNS, _values)
                    conn.commit()
                finally:
                    # 🔴 ROLL BACK BEFORE RESTORING, OR THE RESTORE CANNOT RUN AT ALL. SQLite
                    # refuses the pragma inside an open transaction -- verbatim, "Safety level
                    # may not be changed inside a transaction" -- and an interrupt between the
                    # INSERT and the commit leaves exactly that: the implicit BEGIN still open
                    # on a handle every later call reuses. So the two halves are one fix, and a
                    # `finally` holding only the pragma would still have measured stuck-at-FULL.
                    # Rolling back also stops the next write inheriting a stranded transaction,
                    # and under WAL the writer lock it holds against other processes.
                    #
                    # Swallowed on purpose: on the failure path the handle is about to be
                    # dropped anyway, and a cleanup that raises here would REPLACE the real
                    # error with a meaningless one.
                    #
                    # This runs on the hot path, so it was measured rather than assumed:
                    # `conn.in_transaction` is 0.031 us, and after a successful commit it is
                    # False so the rollback is never called. Against the 123 us this write
                    # costs on a full ledger that is 0.03%.
                    try:
                        if conn.in_transaction:
                            conn.rollback()
                        if _durable:
                            conn.execute("PRAGMA synchronous=NORMAL")
                    except Exception:
                        pass
            except Exception:
                # 🔴 A BAD HANDLE MUST NOT POISON EVERY LATER WRITE. With a fresh connection per
                # call a failure was self-limiting: the next call opened a new one. A cached
                # handle is not -- if the ledger was deleted, moved, or the disk went read-only,
                # the same broken handle would be handed to every write for the life of the
                # process, and the outer swallow would hide all of it. Dropping it here means the
                # next write reopens and can recover, which is the behaviour this path had before.
                _close_write_connection()
                raise
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
    frag, frag_params = _exclude_agents_fragment(excluded)
    clause = status_clause + frag
    params = list(frag_params)
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
    the local, privacy-safe harvest that grows the insights view
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


def get_coaching_effectiveness(path=None, exclude_agents=None):
    """Rank the ledger BY THE WORDING THE AGENT WAS SHOWN: how often each piece of coaching
    was delivered, and how often the agent came back from it.

    This is the reader for `challenge_issued`. Until it existed the column was written and
    never read, so the ledger could say a rule fired and whether the agent recovered, and
    never which words were in front of it. That makes "did my coaching work" unanswerable,
    which is the question `agentx adopt` exists to let a developer act on.

    Same definitions as get_block_frequency, deliberately reusing its status filter rather
    than restating it: a "block" is a challenge episode (CHALLENGED or the RECOVERED it is
    flipped to in place), a "recovery" is a RECOVERED row. Two screens disagreeing about what
    a recovery is would be worse than either screen alone.

    🔴 IT REPORTS ITS OWN DENOMINATOR, AND THAT IS NOT DECORATION. `challenge_issued` is new,
    so every block recorded before it is NULL, and a ledger with hundreds of real blocks
    renders as an EMPTY list here. Without `unattributed` beside it, a developer reads "no
    coaching recorded" as "the feature is broken" or, worse, as "my agents were never
    coached". The two are different facts and the caller is given both:

        attributed   -- blocks whose wording we captured, the honest n for any rate below
        unattributed -- blocks that predate the column, or came through a path that does
                        not record it. NOT evidence of anything except our own blindness.

    Grouped by (policy, wording) rather than wording alone: the same sentence can be reached
    through two policies, and merging them would attribute one policy's recoveries to
    another's coaching.

    path: read a specific ledger file (default: the module DB_PATH in the CWD).
    exclude_agents: iterable of agent_id values to drop (demo/test traffic).

    Returns {"wordings": [{policy_id, policy_name, coaching, blocks, recoveries,
    recovery_rate}, ...] most-delivered first, "attributed": int, "unattributed": int}.
    Zeroed and empty when there is no DB, an error, or no blocks.
    """
    empty = {"wordings": [], "attributed": 0, "unattributed": 0}
    p = path or DB_PATH
    if not os.path.exists(p):
        return empty
    excluded = [a for a in (exclude_agents or []) if a]
    frag, frag_params = _exclude_agents_fragment(excluded)
    # The SAME episode filter get_block_frequency uses. Written once here and passed to both
    # queries below so the grouped rows and the unattributed count cannot describe different
    # populations -- a mismatch would make `attributed + unattributed` fail to equal the
    # block count the rest of the screen prints, and nobody would know which was wrong.
    episode = "status IN ('CHALLENGED', 'RECOVERED')" + frag
    recorded = "challenge_issued IS NOT NULL AND TRIM(challenge_issued) != ''"
    try:
        with _connection(p) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT policy_name,
                       MAX(policy_id) AS policy_id,
                       challenge_issued,
                       COUNT(*) AS n,
                       SUM(CASE WHEN status = 'RECOVERED' THEN 1 ELSE 0 END) AS recoveries
                FROM event_log
                WHERE {episode} AND {recorded}
                GROUP BY policy_name, challenge_issued
                ORDER BY n DESC, policy_name ASC
                """,
                list(frag_params),
            )
            rows = cursor.fetchall()
            cursor.execute(
                f"""
                SELECT SUM(CASE WHEN {recorded} THEN 1 ELSE 0 END),
                       SUM(CASE WHEN {recorded} THEN 0 ELSE 1 END)
                FROM event_log
                WHERE {episode}
                """,
                list(frag_params),
            )
            attributed, unattributed = cursor.fetchone() or (0, 0)
    # Wider than sqlite3.Error, because the docstring promises an empty dict on "no DB, an
    # error, or no blocks" and a connection can fail in ways that are not sqlite3 errors: an
    # OS/path failure, a lock wrapper. The CLI happens to swallow those; the founder walk
    # calls this directly and would have died on one.
    #
    # ⚠️ BUT NOT BARE `Exception`, WHICH WAS THE FIRST FIX AND WAS TOO WIDE. A TypeError or
    # AttributeError from our own code inside this block would be rendered to the user as
    # "no coaching recorded" -- a silent, confident absence, which is the exact failure the
    # denominator paragraph above exists to prevent. A bug in our code must not come out
    # looking like a fact about the user's ledger.
    #
    # (An earlier version of this comment justified the narrowing by saying the try "also
    # covers the query construction". It does not: the fragments and clauses are built above
    # the try. The narrowing is still right, for the reason stated above; the reason given
    # was about code that is not in the block, which would mis-scope it for the next reader.)
    except (sqlite3.Error, OSError):
        return empty
    out = []
    for policy_name, policy_id, coaching, blocks, recoveries in rows:
        blocks = blocks or 0
        recoveries = recoveries or 0
        out.append({
            "policy_id": policy_id,
            "policy_name": policy_name,
            "coaching": coaching,
            "blocks": blocks,
            "recoveries": recoveries,
            "recovery_rate": round(recoveries / blocks, 3) if blocks else 0.0,
        })
    return {"wordings": out,
            "attributed": attributed or 0,
            "unattributed": unattributed or 0}


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
    dev's own tool name, the verdict, and (as of the shape fix below) the SAME shape data
    an ALLOWED row already carries — argument NAMES, a magnitude BUCKET, a target CLASS,
    never a raw query or payload — are stored.

    path: read a specific ledger file (default: the module DB_PATH in the CWD).
    exclude_agents: iterable of agent_id values to drop.

    Returns {"total": int, "policies": [{policy_id, policy_name, would_blocks, tools,
    arg_names, classes, max_amount}, ...]}; total is 0 (policies []) when there is no DB,
    an error, or no audited catch yet.
    """
    p = path or DB_PATH
    rows = _grouped_policy_rows(p, f"status = '{WOULD_BLOCK_STATUS}'", exclude_agents,
                                extra_select="GROUP_CONCAT(DISTINCT tool_name)")
    if rows is None:
        return {"total": 0, "policies": []}
    excluded = [a for a in (exclude_agents or []) if a]
    exclude_frag, exclude_params = _exclude_agents_fragment(excluded)
    policies = []
    # 🔴 A SEPARATE PER-POLICY QUERY, THE SAME SHAPE get_call_inventory ALREADY USES FOR
    # ARG_NAMES/TARGET_CLASS -- not a GROUP_CONCAT bolted onto the query above. arg_names is
    # itself a comma-joined string per ROW ("limit,query"); GROUP_CONCAT-ing that across rows
    # would nest one comma-separated list inside another with no way to tell "one call's two
    # arguments" from "two calls' one argument each" apart on the way back out. Reading
    # DISTINCT rows and union-splitting them in Python (like get_call_inventory does per
    # tool) sidesteps that ambiguity entirely, at the cost of one query per policy rather
    # than folding it into the single GROUP BY above -- the same N+1 the tool-level reader
    # already accepts, and for the same reason: a handful of distinct policies, not a
    # per-call cost.
    try:
        with _connection(p) as conn:
            cursor = conn.cursor()
            for pname, pid, wb, tools in rows:
                arg_names, classes, max_amount = [], [], 0.0
                # 🔴 CAUGHT PER POLICY, NOT AROUND THE WHOLE LOOP. A ledger written before
                # the P-92-B shape columns existed fails this SELECT identically on every
                # policy, and the fallback below covers that. But scoping the catch here
                # (rather than around the whole `with` block, as an earlier version did)
                # means a transient failure on ONE policy's shape query — a lock, say —
                # degrades only that policy instead of discarding shape data already read
                # for every policy before it. It also means there is exactly one place that
                # builds a policy's dict, not two: the try body and the except path used to
                # each build their own nearly-identical dict literal, and a field added to
                # one had no test forcing it into the other.
                try:
                    cursor.execute(
                        "SELECT DISTINCT arg_names, target_class, amount FROM event_log "
                        "WHERE status = ? AND policy_name IS ?" + exclude_frag,
                        [WOULD_BLOCK_STATUS, pname] + exclude_params)
                    shape_rows = cursor.fetchall()
                    arg_names, classes = _union_arg_names_and_classes(
                        (r[0], r[1]) for r in shape_rows)
                    max_amount = max((r[2] or 0.0 for r in shape_rows), default=0.0)
                except Exception:
                    pass
                policies.append({
                    "policy_id": pid, "policy_name": pname, "would_blocks": wb or 0,
                    "tools": _tool_list(tools),
                    "arg_names": arg_names, "classes": classes, "max_amount": max_amount,
                })
    except Exception:
        # The COUNT query (via _grouped_policy_rows) already opened this same file once
        # successfully, so reaching here means opening a SECOND connection to it failed --
        # rarer than the per-policy column-missing case above, which is now caught inline.
        # Degrade the whole report to shape-less rather than lose it outright.
        policies = [
            {"policy_id": pid, "policy_name": pname, "would_blocks": wb or 0,
             "tools": _tool_list(tools), "arg_names": [], "classes": [], "max_amount": 0.0}
            for pname, pid, wb, tools in rows
        ]
    return {"total": sum(row["would_blocks"] for row in policies), "policies": policies}