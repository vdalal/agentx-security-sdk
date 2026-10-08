"""A change journal that makes a local record tamper-EVIDENT.

Every write our code makes to a tracked table (the SDK ledger's `event_log`, the incident store's
`incidents`) appends one entry to `chain_journal` in the SAME transaction: which row, put or
delete, and a digest of the row as written. Each entry's `link` is the hash of the previous link
and the entry, so the journal is a chain. `verify` replays it and compares every row in the table
with the last thing the journal says was written to it.

What it catches: a row edited, added or deleted by anything that did not go through this code (a
`sqlite3` shell, a script, an agent running SQL against its own record), and a journal entry
edited or removed. What it does NOT catch: a writer that knows this scheme and recomputes every
link, since it runs as the same user. The chain's latest link (`head`) is printed so a person can
keep it; a later record whose entry at that position differs was rewritten.

Detection, not prevention: nothing here stops a write.

The digest ignores columns whose value is NULL, so adding a column (which leaves it NULL on old
rows) never reads as an edit. The AgentX gateway runs a copy of this module and writes the
same journal into the incident store; keep the two identical.
"""
import hashlib
import json
import time

JOURNAL_SQL = (
    "CREATE TABLE IF NOT EXISTS chain_journal ("
    "seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, tbl TEXT, row_key TEXT, op TEXT, "
    "digest TEXT, link TEXT)")
# One row: where the journal starts after compaction (`seq` 0 and an empty link until then),
# and a digest of the row state it starts from (`chain_base`).
ANCHOR_SQL = (
    "CREATE TABLE IF NOT EXISTS chain_anchor (id INTEGER PRIMARY KEY CHECK (id = 1), "
    "seq INTEGER, link TEXT, base TEXT, started REAL)")
BASE_SQL = "CREATE TABLE IF NOT EXISTS chain_base (tbl TEXT, row_key TEXT, digest TEXT)"
# Rows found changed outside the journal whose OUTSIDE entries were folded by compaction: the
# finding outlives the entry. Covered by the anchor's base hash.
FINDINGS_SQL = "CREATE TABLE IF NOT EXISTS chain_findings (tbl TEXT, row_key TEXT)"
# The last digest the journal holds for each live row: an INDEX for `guard`, never what `verify`
# trusts (verify replays the journal itself).
ROWS_SQL = ("CREATE TABLE IF NOT EXISTS chain_rows (tbl TEXT, row_key TEXT, digest TEXT, "
            "PRIMARY KEY (tbl, row_key))")

PUT, DELETE, ADOPT = "put", "del", "adopt"
# A row found changed outside the journal just before AgentX wrote it: recorded so a legitimate
# write afterwards cannot absorb the evidence.
OUTSIDE = "outside"

# Compaction keeps the journal bounded: once it holds this many entries, everything but the
# newest KEEP is folded into the anchor and a base snapshot of the row state at that point.
COMPACT_AT = 60000
KEEP = 20000


def _value(v):
    if isinstance(v, bytes):
        return {"hex": v.hex()}
    return v


def row_digest(row):
    """Digest of one row (a mapping of column to value). NULL columns are left out, so a column
    added later does not change the digest of rows written before it."""
    body = {k: _value(v) for k, v in row.items() if v is not None}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def next_link(prev, tbl, row_key, op, digest):
    text = "\n".join((prev or "", tbl, str(row_key), op, digest or ""))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _base_hash(rows, findings=()):
    text = "\n".join("%s\t%s\t%s" % r for r in sorted(rows))
    if findings:      # absent when empty, so a snapshot from before findings hashes the same
        text += "\nF\n" + "\n".join("%s\t%s" % f for f in sorted(findings))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ensure(conn, tables):
    """Create the journal tables. On a store that has rows but no journal yet, ADOPT them: one
    entry per existing row, so the record covers them from now on. Edits made before adoption
    cannot be seen. `tables` maps table name to its key column. Commits."""
    conn.execute(JOURNAL_SQL)
    conn.execute(ANCHOR_SQL)
    conn.execute(BASE_SQL)
    conn.execute(FINDINGS_SQL)
    fresh_index = not _has_table(conn, "chain_rows")
    conn.execute(ROWS_SQL)
    if conn.execute("SELECT 1 FROM chain_anchor WHERE id = 1").fetchone():
        if fresh_index:          # a journal from before the index: build it from the replay
            state = _replay(conn)[0]
            conn.executemany("INSERT OR REPLACE INTO chain_rows VALUES (?, ?, ?)",
                             [(t, k, d) for (t, k), d in state.items() if d is not None])
            conn.commit()
        return
    # OR IGNORE, and only the writer that created the anchor adopts: two processes starting on
    # one store at once must not adopt the same rows twice. The INSERT takes the write lock, so
    # the second waits for the first's commit and then inserts nothing.
    cur = conn.execute("INSERT OR IGNORE INTO chain_anchor (id, seq, link, base, started) "
                       "VALUES (1, 0, '', ?, ?)", (_base_hash([]), time.time()))
    if not cur.rowcount:
        conn.commit()
        return
    for tbl, key in sorted(tables.items()):
        if not _has_table(conn, tbl):
            continue
        keys = [r[0] for r in conn.execute("SELECT %s FROM %s ORDER BY rowid" % (key, tbl))]
        record(conn, tbl, key, keys, ADOPT)
    conn.commit()


def _has_table(conn, tbl):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (tbl,)).fetchone() is not None


def _journaled(conn):
    return _has_table(conn, "chain_journal")


def _rows(conn, tbl, key, keys):
    cur = conn.execute("SELECT * FROM %s WHERE %s IN (%s)"
                       % (tbl, key, ",".join("?" * len(keys))), list(keys))
    names = [d[0] for d in cur.description]
    return {r[names.index(key)]: dict(zip(names, r)) for r in cur.fetchall()}


def record(conn, tbl, key, keys, op=PUT):
    """Append one entry per key: PUT/ADOPT digest the row as it now stands, DELETE records its
    removal. Call AFTER the data write and BEFORE the commit, on the same connection, so the
    entry commits with the write and the write's lock orders the chain. A store with no journal
    (never initialised) is left alone. Never commits."""
    keys = [k for k in keys if k is not None]
    if not keys or not _journaled(conn):
        return
    _write_lock(conn)
    indexed = _has_table(conn, "chain_rows")
    rows = {}
    if op != DELETE:
        for i in range(0, len(keys), 500):
            rows.update(_rows(conn, tbl, key, keys[i:i + 500]))
    last = conn.execute("SELECT link FROM chain_journal ORDER BY seq DESC LIMIT 1").fetchone()
    prev = last[0] if last else (conn.execute(
        "SELECT link FROM chain_anchor WHERE id = 1").fetchone() or [""])[0]
    now = time.time()
    for k in keys:
        if op == DELETE:
            digest = ""
        elif k in rows:
            digest = row_digest(rows[k])
        else:
            continue      # the write did not leave a row (an UPDATE that matched nothing)
        prev = next_link(prev, tbl, k, op, digest)
        conn.execute("INSERT INTO chain_journal (at, tbl, row_key, op, digest, link) "
                     "VALUES (?, ?, ?, ?, ?, ?)", (now, tbl, str(k), op, digest, prev))
        if indexed:
            if op == DELETE:
                conn.execute("DELETE FROM chain_rows WHERE tbl = ? AND row_key = ?", (tbl, str(k)))
            else:
                conn.execute("INSERT OR REPLACE INTO chain_rows VALUES (?, ?, ?)",
                             (tbl, str(k), digest))


def _write_lock(conn):
    """Take the write lock now, before anything is read: another process committing between
    our reads and our write would otherwise pair an old row with a new digest (a false
    finding) or link two entries to one predecessor (a forked chain)."""
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


def guard(conn, tbl, key, keys):
    """Call BEFORE AgentX updates or deletes these rows: any row whose contents no longer match
    the last digest the journal holds for it was changed outside the journal, and gets an
    OUTSIDE entry now, so the legitimate write that follows cannot absorb the evidence. A row
    the journal never recorded is left alone here (`verify` reports it as added). Never commits."""
    keys = [k for k in keys if k is not None]
    if not keys or not _journaled(conn) or not _has_table(conn, "chain_rows"):
        return
    _write_lock(conn)     # read the row and its digest under the lock the write will hold
    rows = {}
    for i in range(0, len(keys), 500):
        rows.update(_rows(conn, tbl, key, keys[i:i + 500]))
    bad = []
    for k, row in rows.items():
        held = conn.execute("SELECT digest FROM chain_rows WHERE tbl = ? AND row_key = ?",
                            (tbl, str(k))).fetchone()
        if held and held[0] != row_digest(row):
            bad.append(k)
    if bad:
        record(conn, tbl, key, bad, OUTSIDE)


def delete(conn, tbl, key, where, params=()):
    """DELETE FROM `tbl` WHERE `where`, journaled: reads the keys first, deletes, records each.
    Returns the number of rows deleted. Never commits."""
    keys = [r[0] for r in conn.execute("SELECT %s FROM %s WHERE %s" % (key, tbl, where),
                                       tuple(params))]
    guard(conn, tbl, key, keys)
    cur = conn.execute("DELETE FROM %s WHERE %s" % (tbl, where), tuple(params))
    record(conn, tbl, key, keys, DELETE)
    return cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else len(keys)


def _replay(conn):
    """(state {(tbl, key): digest}, head (seq, link, at), first break or None, entries)."""
    anchor = conn.execute("SELECT seq, link, base FROM chain_anchor WHERE id = 1").fetchone()
    seq0, link, base = anchor if anchor else (0, "", _base_hash([]))
    base_rows = [tuple(r) for r in conn.execute("SELECT tbl, row_key, digest FROM chain_base")]
    findings = ([tuple(r) for r in conn.execute("SELECT tbl, row_key FROM chain_findings")]
                if _has_table(conn, "chain_findings") else [])
    state, broken, outside = {}, None, set(findings)
    if _base_hash(base_rows, findings) != base:
        broken = {"seq": seq0, "why": "the starting snapshot was changed"}
    for t, k, d in base_rows:
        state[(t, k)] = d
    head, n, expect = (seq0, link, None), 0, seq0 + 1
    for seq, at, tbl, key, op, digest, stored in conn.execute(
            "SELECT seq, at, tbl, row_key, op, digest, link FROM chain_journal ORDER BY seq"):
        n += 1
        if broken is None and seq != expect:
            broken = {"seq": expect, "why": "journal entries are missing"}
        expect = seq + 1
        link = next_link(link, tbl, key, op, digest)
        if broken is None and link != stored:
            broken = {"seq": seq, "why": "a journal entry was changed"}
        link = stored
        if op == DELETE:
            state[(tbl, key)] = None
        else:
            state[(tbl, key)] = digest
        if op == OUTSIDE:
            outside.add((tbl, key))
        head = (seq, stored, at)
    return state, head, broken, n, outside


def verify(conn, tables):
    """See `_verify_once`. A result that is not intact is checked once more before it is
    returned: on a store that is not in WAL mode the reads are separate, so a write committing
    between the journal read and the table read looks like an added row for one read only,
    while a real change reads the same twice."""
    first = _verify_once(conn, tables)
    if first.get("intact") is False:
        return _verify_once(conn, tables)
    return first


def _begin_snapshot(conn):
    """Open one read transaction when the store is in WAL mode, so every read in the check sees
    the same committed state. Returns True when it opened one (the caller ends it). Outside WAL
    a read transaction holds a shared lock that makes live writes fail until the check ends,
    so there the reads stay separate and `verify` re-reads instead."""
    if conn.in_transaction:
        return False
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()
        if not mode or str(mode[0]).strip().lower() != "wal":
            return False
        conn.execute("BEGIN")
        return True
    except Exception:
        return False


def _verify_once(conn, tables):
    snapshot = _begin_snapshot(conn)
    try:
        return _verify_reads(conn, tables)
    finally:
        if snapshot:
            try:
                conn.rollback()
            except Exception:
                pass


def _verify_reads(conn, tables):
    """What the record says about itself. Never raises; `{"journaled": False}` for a store with
    no journal. `tables` maps table name to key column.

    Returns journaled, intact, entries, head_seq, head_link, head_at, started, broken (where the
    chain itself breaks), and per kind the rows that disagree with it: `edited` (contents differ
    from the last write recorded), `added` (a row nothing recorded writing), `removed` (a row the
    record says exists is gone)."""
    try:
        if not _journaled(conn):
            return {"journaled": False}
        state, head, broken, n, outside = _replay(conn)
        started = (conn.execute("SELECT started FROM chain_anchor WHERE id = 1").fetchone()
                   or [None])[0]
        now = {}
        for tbl, key in sorted(tables.items()):
            if not _has_table(conn, tbl):
                continue
            cur = conn.execute("SELECT * FROM %s" % tbl)
            names = [d[0] for d in cur.description]
            for r in cur.fetchall():
                row = dict(zip(names, r))
                now[(tbl, str(row[key]))] = row_digest(row)
        # A write committed DURING the scan has its journal entry committed with it, so it is
        # in the journal now: apply those entries before judging, or AgentX's own write reads
        # as an added row (review 3; the boot check runs beside live traffic).
        for tbl, key, op, digest in conn.execute(
                "SELECT tbl, row_key, op, digest FROM chain_journal WHERE seq > ? ORDER BY seq",
                (head[0],)):
            state[(tbl, key)] = None if op == DELETE else digest
            if op == OUTSIDE:     # a finding written during the scan is still a finding
                outside.add((tbl, key))
        edited, added, seen = [], [], set(now)
        for tk, d in sorted(now.items()):
            want = state.get(tk, "<none>")
            if want == "<none>" or want is None:
                added.append(tk)
            elif want != d:
                edited.append(tk)
        removed = sorted(tk for tk, d in state.items()
                         if d is not None and tk[0] in tables and tk not in seen)
        outside = sorted(outside)
        return {"journaled": True,
                "intact": not (broken or edited or added or removed or outside),
                "outside": outside,
                "entries": n, "head_seq": head[0], "head_link": head[1], "head_at": head[2],
                "started": started, "broken": broken, "edited": edited, "added": added,
                "removed": removed}
    except Exception as err:
        return {"journaled": True, "intact": None, "error": "%s: %s" % (type(err).__name__, err)}


def link_at(conn, seq):
    """The link at journal position `seq`, or None when the journal no longer holds it."""
    try:
        r = conn.execute("SELECT link FROM chain_journal WHERE seq = ?", (int(seq),)).fetchone()
        return r[0] if r else None
    except Exception:
        return None


def compact(conn, at=COMPACT_AT, keep=KEEP):
    """Fold all but the newest `keep` entries into the anchor once the journal holds `at`.
    The base snapshot is the row state the FOLDED entries describe (never re-read from the
    table, so an edit made before compaction is still caught after it). Returns the number of
    entries folded. Never commits."""
    if not _journaled(conn):
        return 0
    n = conn.execute("SELECT COUNT(*) FROM chain_journal").fetchone()[0]
    if n < at:
        return 0
    cut = conn.execute("SELECT seq, link FROM chain_journal ORDER BY seq DESC LIMIT 1 OFFSET ?",
                       (keep,)).fetchone()
    if not cut:
        return 0
    cut_seq, cut_link = cut
    anchor = conn.execute("SELECT seq, link, base FROM chain_anchor WHERE id = 1").fetchone()
    state = {(t, k): d for t, k, d in conn.execute("SELECT tbl, row_key, digest FROM chain_base")}
    link = anchor[1] if anchor else ""
    old_findings = ([tuple(r) for r in conn.execute("SELECT tbl, row_key FROM chain_findings")]
                    if _has_table(conn, "chain_findings") else [])
    if anchor and _base_hash([tuple(r) for r in conn.execute(
            "SELECT tbl, row_key, digest FROM chain_base")], old_findings) != anchor[2]:
        return 0      # an edited snapshot is never re-hashed into a clean one (review 3)
    findings = (set(tuple(r) for r in conn.execute("SELECT tbl, row_key FROM chain_findings"))
                if _has_table(conn, "chain_findings") else set())
    for tbl, key, op, digest, stored in conn.execute(
            "SELECT tbl, row_key, op, digest, link FROM chain_journal WHERE seq <= ? "
            "ORDER BY seq", (cut_seq,)):
        if next_link(link, tbl, key, op, digest) != stored:
            return 0      # a broken chain is never folded away
        link = stored
        state[(tbl, key)] = None if op == DELETE else digest
        if op == OUTSIDE:     # the finding outlives the folded entry
            findings.add((tbl, key))
    base_rows = [(t, k, d) for (t, k), d in state.items() if d is not None]
    conn.execute("DELETE FROM chain_base")
    conn.executemany("INSERT INTO chain_base (tbl, row_key, digest) VALUES (?, ?, ?)", base_rows)
    conn.execute(FINDINGS_SQL)
    conn.execute("DELETE FROM chain_findings")
    conn.executemany("INSERT INTO chain_findings (tbl, row_key) VALUES (?, ?)",
                     sorted(findings))
    conn.execute("UPDATE chain_anchor SET seq = ?, link = ?, base = ? WHERE id = 1",
                 (cut_seq, cut_link, _base_hash(base_rows, findings)))
    cur = conn.execute("DELETE FROM chain_journal WHERE seq <= ?", (cut_seq,))
    return cur.rowcount or 0
