"""
agentx_sdk/overrides.py — Build #2: the org-reframe override store.

The product's proven lever is challenge QUALITY: holding the block fixed, a
task-fitting reframe drives the agent to recover, while a generic one can induce
give-up (the challenge-quality A/B — 0/4 gave up vs 3/3 recovered, by challenge
text alone). BUILD #1 hand-wrote good *generic* challenges into the gateway
floor. BUILD #2 makes them ORG-SPECIFIC and SELF-IMPROVING — without touching
the gateway:

  * HARVEST  — the gateway already extracts a ``resolution_path`` on every
               COMPLIED self-correction (judge-produced; persisted to the local
               incident store). ``harvest_candidates()`` projects
               the *reusable* ones into ranked per-policy safe-path candidates.
  * ADOPT    — the developer reviews candidates (``agentx insights``) and
               promotes one (``agentx adopt``) into ``.agentx/overrides.json``.
               The manual gate is the anti-poisoning control: agent-generated
               text never becomes a live security challenge without a human
               blessing it.
  * APPLY    — ``get_active_override()`` is read by the SDK at block time and the
               adopted org reframe is swapped in *before* the AgentXBlock is
               delivered to the agent. Zero gateway round-trip.

Everything here is tenant-private (the org brain). It must NEVER flow to the
shared cross-tenant corpus — ``prompt_patch_suggestion`` is free text and stays
out of the abstract contribution path by construction.

Pure standard library (json / os / sqlite3) so it is import-safe at SDK module
load — module-level imports stay stdlib-only (the 0.3.1 import-safety lesson).
"""
import difflib
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

# Stored under the same ``.agentx/`` mount the gateway shares for policies.json
# and incidents.db, so the override store is git-trackable and survives restarts.
DEFAULT_OVERRIDES_PATH = os.path.join(".agentx", "overrides.json")
_SCHEMA_VERSION = 1

# The gateway persists incidents.db into whatever host dir its compose file mounts
# onto /app/.agentx. Two real layouts exist, both run from the repo root:
#   * partner kit   — mounts ./.agentx            -> ./.agentx/incidents.db
#   * this dev repo — mounts ./agentx_sdk/.agentx -> ./agentx_sdk/.agentx/incidents.db
# Resolve against both so `agentx insights` finds the store either way; an explicit
# AGENTX_INCIDENT_DB always wins (and is what the tests use).
_INCIDENT_DB_CANDIDATES = (
    os.path.join(".agentx", "incidents.db"),
    os.path.join("agentx_sdk", ".agentx", "incidents.db"),
)
DEFAULT_INCIDENT_DB = _INCIDENT_DB_CANDIDATES[0]


def _find_project_root(start=None):
    """Anchor the ``.agentx/`` store to the project root so ``agentx insights`` /
    ``adopt`` and the runtime SDK-swap agree no matter which directory the dev runs
    from (e.g. ``examples/``).

    Prefers the ``.git`` REPO ROOT — it is unique and cwd-independent, and matches
    the "commit overrides.json to your repo" sharing model — so that NESTED
    ``.agentx/`` dirs (a repo can have several: root, agentx_sdk/, backend/, …)
    cannot split the store between adopt-time and run-time. Only when there is no
    ``.git`` ancestor (not a git checkout) does it fall back to the nearest
    ``.agentx/`` ancestor, then cwd. ``AGENTX_OVERRIDES`` / ``AGENTX_INCIDENT_DB``
    override entirely."""
    start_abs = os.path.abspath(start or os.getcwd())
    cur = start_abs
    agentx_root = None
    while True:
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur                          # repo root wins — one store per repo
        if agentx_root is None and os.path.isdir(os.path.join(cur, ".agentx")):
            agentx_root = cur                   # nearest .agentx, used only if no .git
        parent = os.path.dirname(cur)
        if parent == cur:                       # reached the filesystem root
            break
        cur = parent
    return agentx_root or start_abs


def _overrides_path(path=None):
    if path:
        return path
    env = os.environ.get("AGENTX_OVERRIDES")
    if env:
        return env
    return os.path.join(_find_project_root(), DEFAULT_OVERRIDES_PATH)


def _incident_db_path(path=None):
    """Resolve the incident store the gateway wrote. Explicit arg / env win; else
    the first candidate that exists under the project root; else the primary
    default under that root (so a caller can still report a not-found path).
    Project-root-anchored so it resolves the same from any subdirectory."""
    if path:
        return path
    env = os.environ.get("AGENTX_INCIDENT_DB")
    if env:
        return env
    root = _find_project_root()
    for candidate in _INCIDENT_DB_CANDIDATES:
        full = os.path.join(root, candidate)
        if os.path.exists(full):
            return full
    return os.path.join(root, DEFAULT_INCIDENT_DB)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------- store I/O

def load_overrides(path=None, warn=False):
    """Return the override store dict. A missing or malformed file yields an empty
    store and NEVER raises — a bad override must not break the block path.

    When ``warn`` is set (the CLI surfaces pass it) and the file EXISTS but is
    unparseable, emit a stderr warning so a hand-edit typo isn't silent: otherwise
    a single bad comma would quietly disable EVERY adopted override. The runtime
    hot path leaves ``warn`` False to stay quiet and safe (and avoid per-block
    spam)."""
    p = _overrides_path(path)
    try:
        with open(p, "r", encoding="utf-8") as f:
            raw = f.read()
        # An EMPTY / whitespace-only file is NOT corrupt — it's an unused store (freshly
        # created, a starter-kit placeholder, or nothing adopted yet). Treat it as empty and
        # never warn: warning on the normal empty state trains users to ignore a warning that
        # should only ever mean "your JSON is actually broken".
        if not raw.strip():
            return {"version": _SCHEMA_VERSION, "overrides": {}}
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("override store is not a JSON object")
        data.setdefault("version", _SCHEMA_VERSION)
        if not isinstance(data.get("overrides"), dict):
            data["overrides"] = {}
        return data
    except FileNotFoundError:
        return {"version": _SCHEMA_VERSION, "overrides": {}}
    except (OSError, ValueError, json.JSONDecodeError) as e:
        if warn:
            print(f"⚠️  [AgentX] Could not read your override store at {p}: {e}\n"
                  f"    Your adopted org reframes are NOT being applied until this "
                  f"is fixed (it's plain JSON — check for a trailing comma or an "
                  f"unclosed quote).", file=sys.stderr)
        return {"version": _SCHEMA_VERSION, "overrides": {}}


def save_overrides(data, path=None):
    """Persist the override store ATOMICALLY (temp file + os.replace) so a crash
    mid-write can't truncate the live store into corruption; creates ``.agentx/``
    if needed. Returns the path written."""
    p = _overrides_path(path)
    parent = os.path.dirname(p)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        # ensure_ascii=False so hand-editors see real text (em-dashes, accents),
        # not \uXXXX escapes — this file is meant to be read and edited by humans.
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, p)                  # atomic swap on the same filesystem
    return p


def _entry_to_override(entry):
    """Project a stored override entry to the runtime ``{challenge, safe_path}``
    shape, or ``None`` if it carries no usable challenge."""
    if not isinstance(entry, dict):
        return None
    challenge = entry.get("challenge")
    if not challenge:
        return None
    return {"challenge": challenge, "safe_path": entry.get("safe_path")}


def get_active_override(policy_id, policy_name=None, path=None):
    """The adopted org reframe for this policy as ``{challenge, safe_path}``, or
    ``None``.

    Lookup is by ``policy_id`` FIRST (exact, strongest). If that misses and a
    ``policy_name`` is supplied, fall back to matching the stored
    ``policy_violated`` NAME — because the SAME logical policy can surface under
    DIFFERENT ids across the SDK's two block paths (the Layer-0 keyword shield's
    seed UUID vs the gateway/judge id), so a reframe adopted under one id would
    otherwise vanish on the other path mid-loop (the cross-path flicker seen
    running examples/07). The store already records ``policy_violated``, so the
    name is the stable cross-path key. Name match is normalized (lowercased,
    whitespace-collapsed) and deterministic: most-recently-adopted wins, ties
    broken on id.

    Read by the SDK on the block path, so it is total best-effort: any error or
    absent/blank override returns ``None`` and the caller falls back to the
    gateway's generic challenge unchanged.
    """
    if not policy_id and not policy_name:
        return None
    try:
        store = load_overrides(path)["overrides"]
    except Exception:
        return None
    if policy_id:
        hit = _entry_to_override(store.get(policy_id))
        if hit:
            return hit                              # exact id wins
    if policy_name:
        target = _norm_for_dedup(policy_name)
        if target:
            matches = [
                (entry.get("adopted_at") or "", pid, entry)
                for pid, entry in store.items()
                if isinstance(entry, dict)
                and _norm_for_dedup(entry.get("policy_violated")) == target
            ]
            # Most-recently-adopted first, tie-break on id — fully deterministic.
            for _, _, entry in sorted(matches, reverse=True):
                hit = _entry_to_override(entry)
                if hit:
                    return hit
    return None


def adopt(policy_id, *, challenge, safe_path=None, resolution_type=None,
          policy_violated=None, source="harvest", path=None):
    """Promote a reframe to the ACTIVE override for ``policy_id`` — the human
    gate. Overwrites any prior active override for that policy. Returns the
    stored entry."""
    if not policy_id:
        raise ValueError("policy_id is required to adopt an override")
    if not challenge or not str(challenge).strip():
        raise ValueError("challenge text is required to adopt an override")
    data = load_overrides(path)
    entry = {
        "policy_violated": policy_violated,
        "challenge": str(challenge).strip(),
        "safe_path": safe_path,
        "resolution_type": resolution_type,
        "source": source,
        "adopted_at": _now_iso(),
    }
    data["overrides"][policy_id] = entry
    save_overrides(data, path)
    return entry


# ------------------------------------------------- customize (agentx policies)

def list_customizable_policies(path=None):
    """Project the built-in floor policies for the ``agentx policies`` surface: each
    with its stable id, name, category, the shipped default challenge + safe path,
    and — overlaid — any ACTIVE override the dev has adopted or customized, so the
    listing shows what actually ships on the next block (not just the default).

    Read-only. Lazy-imports the built-in catalog so ``overrides.py`` stays import-safe
    (no ``decorators`` dependency at module load — the 0.3.1 lesson). The overlay uses
    the SAME ``get_active_override`` the block path uses (id-first, name-fallback), so
    ``customized`` here is true iff a block would actually be reframed.

    Returns ``[{id, name, category, default_challenge, default_safe_path,
    active_challenge, active_safe_path, customized}]``.
    """
    from .decorators import builtin_policy_catalog
    out = []
    for p in builtin_policy_catalog():
        override = get_active_override(p["id"], policy_name=p["name"], path=path)
        out.append({
            "id": p["id"],
            "name": p["name"],
            "category": p.get("category"),
            "default_challenge": p.get("challenge"),
            "default_safe_path": p.get("safe_path"),
            "active_challenge": override.get("challenge") if override else None,
            "active_safe_path": override.get("safe_path") if override else None,
            "customized": override is not None,
        })
    return out


def resolve_policy_by_name(name):
    """Resolve a human-readable policy name (as shown by ``agentx policies``) to its
    built-in catalog entry for ``agentx customize`` — so the keyless dev types a name,
    never a UUID. Case-insensitive, whitespace-normalized EXACT match.

    Returns ``(entry, matches)`` where ``entry`` is the single matched catalog dict
    (or ``None``) and ``matches`` is the count. The built-ins have unique names so a
    real hit is always ``(entry, 1)``; ``(None, 0)`` is a typo and ``(None, n>1)`` is
    an ambiguity the caller warns on rather than guessing (per the deferred
    name-collision decision)."""
    from .decorators import builtin_policy_catalog
    target = _norm_for_dedup(name)
    if not target:
        return None, 0
    matches = [p for p in builtin_policy_catalog()
               if _norm_for_dedup(p["name"]) == target]
    if len(matches) == 1:
        return matches[0], 1
    return None, len(matches)


# --------------------------------------------------------- outcome / label channel
# The label channel records whether a block was RIGHT (verdict), whether the reframe HELD
# (safe_path), and whether HARM occurred — writing back to the SAME incidents.db the
# gateway populates. The SDK and gateway are separate packages that cannot import each
# other, so this MIRRORS the gateway's incident-store writer; a parity test keeps the
# vocab and column set in lockstep.
_VERDICT_VOCAB = frozenset({"TRUE_POSITIVE", "FALSE_POSITIVE", "ACCEPTED_RISK"})
_SAFE_PATH_VOCAB = frozenset({"HELD", "FAILED"})
_HARM_VOCAB = frozenset({"HARM", "NO_HARM"})
_VERDICT_SOURCE_VOCAB = frozenset({"human", "declared"})  # verdict provenance, tenant-private
_LABEL_COLUMNS = ("label_verdict", "label_safe_path", "label_harm", "outcome_at",
                  "label_verdict_source")


def _ensure_label_columns(conn):
    """Add the outcome-label columns if this incidents.db predates them. The gateway's
    init_db normally creates them, but the SDK may be the FIRST to touch the store for a
    label (``agentx override`` before the gateway next writes), so it self-heals the same
    four nullable-TEXT columns. ADD COLUMN of a nullable column is non-destructive."""
    have = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
    for name in _LABEL_COLUMNS:
        if name not in have:
            conn.execute("ALTER TABLE incidents ADD COLUMN %s TEXT" % name)


def record_outcome(receipt_id, *, verdict=None, safe_path=None, harm=None, source=None,
                   db_path=None):
    """Attach an outcome LABEL to a stored incident, writing the SAME incidents.db the
    gateway populates. A PROVIDED axis overwrites; a None axis is preserved (COALESCE), so
    a verdict write never clobbers a prior safe_path and the reconciliation can downgrade
    HELD->FAILED. ``source`` records verdict PROVENANCE ("human" = a person judged this
    block via override/review; "declared" = a standing policy rule auto-applied it) —
    stored only alongside a verdict, tenant-private, so a later clear/harvest can tell the
    two apart. Off-vocab RAISES (fail-safe). Returns True iff a row was updated; False when
    the store or the receipt is missing (so the CLI can report an honest no-op)."""
    if verdict is not None and verdict not in _VERDICT_VOCAB:
        raise ValueError("verdict %r not in %s" % (verdict, sorted(_VERDICT_VOCAB)))
    if safe_path is not None and safe_path not in _SAFE_PATH_VOCAB:
        raise ValueError("safe_path %r not in %s" % (safe_path, sorted(_SAFE_PATH_VOCAB)))
    if harm is not None and harm not in _HARM_VOCAB:
        raise ValueError("harm %r not in %s" % (harm, sorted(_HARM_VOCAB)))
    # source is the verdict's provenance and is stored ONLY with a verdict, so validate it
    # only then; a safe_path/harm write may carry an advisory tag (e.g. "reconcile") we drop.
    if verdict is not None and source is not None and source not in _VERDICT_SOURCE_VOCAB:
        raise ValueError("source %r not in %s" % (source, sorted(_VERDICT_SOURCE_VOCAB)))
    if verdict is None and safe_path is None and harm is None:
        return False
    # Provenance is meaningful only for a verdict; a safe_path/harm-only write leaves it alone.
    verdict_source = source if verdict is not None else None
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return False
    try:
        conn = sqlite3.connect(p)
        try:
            _ensure_label_columns(conn)
            cur = conn.execute(
                "UPDATE incidents SET label_verdict = COALESCE(?, label_verdict), "
                "label_safe_path = COALESCE(?, label_safe_path), "
                "label_harm = COALESCE(?, label_harm), "
                "label_verdict_source = COALESCE(?, label_verdict_source), "
                "outcome_at = ? WHERE receipt_id = ?",
                (verdict, safe_path, harm, verdict_source, _now_iso(), receipt_id),
            )
            conn.commit()
            changed = cur.rowcount
        finally:
            conn.close()
    except sqlite3.Error:
        # Locked / corrupt DB — report a no-op rather than crash the CLI.
        return False
    return changed > 0


def delete_incident(receipt_id, db_path=None):
    """Remove an incident row entirely — for rows that should never have been in the
    labelable corpus at all (a common one: the SDK's own test suite / examples run against
    the SAME local incidents.db `agentx review` reads, seeding it with synthetic
    ``test_sdk_agent`` / ``looping_agent_xyz``-style traces). Distinct from a verdict: a
    verdict is a correctable LABEL on real signal; a delete is "this was never real signal,"
    and unlike a verdict it cannot be undone by writing again. Returns True iff a row was
    removed; False when the store or the receipt is missing."""
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return False
    try:
        conn = sqlite3.connect(p)
        try:
            cur = conn.execute("DELETE FROM incidents WHERE receipt_id = ?", (receipt_id,))
            conn.commit()
            deleted = cur.rowcount
        finally:
            conn.close()
    except sqlite3.Error:
        return False
    return deleted > 0


def delete_incidents(receipt_ids, db_path=None):
    """Delete a specific set of incident rows by receipt_id — powers ``agentx review``'s
    'delete-all' on a batch. Deliberately scoped to EXACTLY the ids passed (never a broader
    re-scan like ``apply_declared_verdicts``): deletion is irreversible, so unlike batch
    labeling it must never remove more than what the human actually saw. Returns the count
    actually deleted."""
    return sum(1 for rid in receipt_ids if delete_incident(rid, db_path=db_path))


def list_recent_incidents(limit=50, db_path=None):
    """Recent incidents with their labels, newest first — powers ``agentx review``.
    ``SELECT *`` so it degrades cleanly on an OLDER store: absent label columns simply
    read as missing (callers ``.get`` them), with no DDL on this read path. Missing
    store / locked DB -> []."""
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return []
    try:
        conn = sqlite3.connect(p)
        try:
            cur = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (int(limit),))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    for r in rows:
        r["resolution_path"] = _parse_resolution_path(r.get("resolution_path"))
    return rows


def find_incidents_by_receipt_prefix(prefix, db_path=None):
    """All incidents whose receipt_id starts with ``prefix`` — powers ``agentx override``'s
    receipt lookup. Unlike ``list_recent_incidents``, this is NOT bounded to a recency
    window: a receipt the user is overriding may be older than the N most recent incidents,
    and reporting 'not found' for a receipt that genuinely exists would be misleading. Runs
    as a ``LIKE`` prefix match (SQLite can use the ``receipt_id`` primary-key index for it);
    ``%``/``_``/``\\`` in ``prefix`` are escaped so they match literally, not as wildcards.
    Missing store / locked DB -> []."""
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return []
    escaped = str(prefix).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    try:
        conn = sqlite3.connect(p)
        try:
            cur = conn.execute(
                "SELECT * FROM incidents WHERE receipt_id LIKE ? ESCAPE '\\' "
                "ORDER BY created_at DESC", (escaped + "%",))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    for r in rows:
        r["resolution_path"] = _parse_resolution_path(r.get("resolution_path"))
    return rows


# A block that has NOT recovered (mirrors the gateway; guarded by the parity tripwire).
_BLOCKING_STATUSES = frozenset({"CHALLENGED", "DENIED", "ESCALATED"})


def reconcile_safe_paths(db_path=None):
    """Fill label_safe_path from trace history (mirrors the gateway's reconciliation). A
    COMPLIED incident is HELD unless a LATER block on the same (trace_id, policy_id) shows
    the reframe did not hold -> FAILED. Lazy + idempotent (overwrites, so a reblock arriving
    later downgrades a prior HELD); run before ``agentx review`` reads safe-path status.
    Returns the count relabeled this pass."""
    rows = list_recent_incidents(limit=100000, db_path=db_path)
    blocks = {}
    for r in rows:
        if r.get("status") in _BLOCKING_STATUSES and r.get("trace_id") and r.get("policy_id"):
            blocks.setdefault((r["trace_id"], r["policy_id"]), []).append(r.get("created_at") or "")
    updated = 0
    for r in rows:
        if r.get("status") != "COMPLIED" or not r.get("trace_id") or not r.get("policy_id"):
            continue
        pivot = r.get("resolved_at") or r.get("created_at") or ""
        later = any(ts > pivot for ts in blocks.get((r["trace_id"], r["policy_id"]), []))
        desired = "FAILED" if later else "HELD"
        if r.get("label_safe_path") != desired:
            if record_outcome(r["receipt_id"], safe_path=desired, db_path=db_path):
                updated += 1
    return updated


# --------------------------------------------------------------- harvest

_HARVEST_QUERY = (
    "SELECT policy_id, policy_violated, resolution_path "
    "FROM incidents WHERE status = 'COMPLIED' AND resolution_path IS NOT NULL"
)


def _parse_resolution_path(raw):
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else None
    except (TypeError, ValueError):
        return None


# Two suggestions whose normalized texts are at least this similar collapse into
# one candidate (counts summed). Conservative on purpose — HIGH precision: only
# near-identical phrasings merge, never genuinely distinct guidance. The judge
# rewords the same safe-path many ways, fragmenting exact-match dedup into many
# count=1 entries; this restores the recurrence signal. LEXICAL (stdlib difflib),
# not embedding-semantic — the SDK stays thin/stdlib-only (the 0.3.1 lesson);
# true paraphrase clustering would need embeddings and is deferred.
_DEDUP_SIMILARITY_THRESHOLD = 0.85


def _norm_for_dedup(text):
    return " ".join(str(text or "").lower().split())


def cluster_near_duplicates(cands, *, text_key, merge_extra=None,
                            threshold=_DEDUP_SIMILARITY_THRESHOLD):
    """Greedily merge candidate dicts whose ``text_key`` values are near-duplicate
    (difflib ratio >= ``threshold``), summing ``count``. Seeds clusters from the
    highest-count candidate first so the kept representative is the most-recurred
    and ordering is deterministic. ``merge_extra(rep, other)`` folds any extra
    fields (e.g. union indicators); ``count`` is always summed. Returns the list
    of representatives (unsorted; callers apply their own final sort)."""
    reps = []          # representative candidate dicts
    rep_norms = []     # parallel normalized texts
    for cand in sorted(cands, key=lambda c: (-c.get("count", 1), str(c.get(text_key, "")))):
        norm = _norm_for_dedup(cand.get(text_key, ""))
        idx = next(
            (i for i, rn in enumerate(rep_norms)
             if difflib.SequenceMatcher(None, norm, rn).ratio() >= threshold),
            None,
        )
        if idx is not None:
            reps[idx]["count"] = reps[idx].get("count", 1) + cand.get("count", 1)
            if merge_extra:
                merge_extra(reps[idx], cand)
        else:
            reps.append(dict(cand))
            rep_norms.append(norm)
    return reps


def harvest_candidates(db_path=None, cluster=True):
    """Project the local incident store's *reusable* ``resolution_path`` rows into
    ranked per-policy safe-path candidates.

    ``cluster=False`` skips the near-duplicate merge (the O(k^2) difflib pass). It
    leaves the SET of policies that carry candidates unchanged — clustering only
    collapses phrasings WITHIN a policy, never empties one — so any caller that
    needs only the policy set or an item COUNT (e.g. ``count_reviewable``'s
    session-end nudge) gets the identical answer without paying the merge cost.
    The per-policy ``candidates`` list is then unclustered (dupes not summed), so
    a caller that renders the top candidate must keep the default (``cluster=True``).

    Returns ``{policy_id: {"policy_violated": str|None, "candidates":
    [{"suggestion": str, "resolution_type": str|None, "count": int}]}}`` with
    candidates sorted by ``count`` descending (identical suggestions collapse and
    accrue a count, so the org's most-repeated safe path ranks first).

    A missing DB or older schema yields ``{}`` — the keyless / fresh case the
    caller renders as an honest empty state, never an error. ``resolution_path``
    is judge-produced, so it is ``NULL`` in keyless mode and this returns ``{}``
    until the dev runs the Recover tier (a Gemini key).
    """
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return {}
    try:
        conn = sqlite3.connect(p)
        try:
            rows = conn.execute(_HARVEST_QUERY).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        # Older store without the resolution_path column, or a locked/corrupt
        # DB — degrade to "nothing harvested yet" rather than crash the CLI.
        return {}

    grouped = {}
    for policy_id, policy_violated, rp_raw in rows:
        rp = _parse_resolution_path(rp_raw)
        if not rp or not rp.get("reusable"):
            continue
        suggestion = (rp.get("prompt_patch_suggestion") or "").strip()
        if not suggestion:
            continue
        pid = policy_id or "POL-UNKNOWN"
        bucket = grouped.setdefault(pid, {"policy_violated": policy_violated,
                                          "_by_text": {}})
        if policy_violated and not bucket.get("policy_violated"):
            bucket["policy_violated"] = policy_violated
        cand = bucket["_by_text"].setdefault(suggestion, {
            "suggestion": suggestion,
            "resolution_type": rp.get("resolution_type"),
            "count": 0,
        })
        cand["count"] += 1

    out = {}
    for pid, bucket in grouped.items():
        # Collapse exact dupes (the _by_text dict) THEN near-duplicate phrasings
        # (reworded same-intent safe-paths) so recurrence actually accumulates.
        # Skipped for count-only callers (cluster=False): merging changes only the
        # per-policy ranking, never whether the policy has a candidate at all.
        vals = list(bucket["_by_text"].values())
        merged = cluster_near_duplicates(vals, text_key="suggestion") if cluster else vals
        # (-count, suggestion) gives a FULLY deterministic order — ties break on
        # text, not dict/row insertion order — so the global sequence numbers in
        # `agentx insights` stay stable between listing and `agentx adopt <#>`.
        candidates = sorted(merged, key=lambda c: (-c["count"], c["suggestion"]))
        out[pid] = {"policy_violated": bucket.get("policy_violated"),
                    "candidates": candidates}
    return out


def enumerate_candidates(harvest):
    """Flatten ``harvest_candidates()`` into a stable, GLOBALLY-numbered list so a
    developer can promote by a single sequence number (``agentx adopt 3``) instead
    of copying a policy UUID. Deterministic ordering (policies sorted by id, then
    the per-policy candidate order) means ``insights`` and ``adopt`` agree.

    Returns ``[{seq, policy_id, policy_violated, suggestion, resolution_type,
    count}]`` (seq starts at 1).
    """
    flat = []
    for pid in sorted(harvest.keys()):
        bucket = harvest[pid]
        for cand in bucket.get("candidates", []):
            flat.append({
                "policy_id": pid,
                "policy_violated": bucket.get("policy_violated"),
                "suggestion": cand["suggestion"],
                "resolution_type": cand.get("resolution_type"),
                "count": cand.get("count", 1),
            })
    for i, item in enumerate(flat, start=1):
        item["seq"] = i
    return flat


def incident_db_census(db_path=None):
    """Diagnostic for ``agentx insights``: where the incident store is and how much
    of it is harvestable. Never raises — lets the CLI explain an empty result
    (wrong path? no recoveries? no judge?) instead of silently showing nothing.

    Returns ``{path, exists, complied, with_resolution}``.
    """
    p = _incident_db_path(db_path)
    info = {"path": p, "exists": os.path.exists(p), "complied": 0,
            "with_resolution": 0}
    if not info["exists"]:
        return info
    try:
        conn = sqlite3.connect(p)
        try:
            info["complied"] = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'COMPLIED'"
            ).fetchone()[0]
            info["with_resolution"] = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'COMPLIED' "
                "AND resolution_path IS NOT NULL"
            ).fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return info


def reviewable_items(db_path=None, cluster=True):
    """Items awaiting a human decision, for ``agentx review`` — the batched label-channel
    capture. Two kinds, teach-wins first:
      - {"kind": "adopt", policy_id, policy_violated, suggestion, resolution_type, count}
        a reframe the agent recovered with, not yet adopted for its policy.
      - {"kind": "verdict", receipt_id, policy_id, policy_violated, status, label_safe_path}
        a block with no verdict yet (was it right?).
    Empty when nothing awaits — the honest empty state, never an error.

    ONE adopt item per policy — the top-recurrence cluster from ``harvest_candidates``
    (already sorted highest-count first), not every surviving near-duplicate phrasing.
    Only one override can ever be active per policy, so presenting several as independent
    yes/no decisions just means each adopted one silently overwrites the last (wasted
    decisions on an LLM-paraphrased corpus, which rarely produces byte-identical text).
    The rest stay browsable by number via ``agentx insights`` / ``agentx adopt <#>``."""
    items = []
    for pid, bucket in harvest_candidates(db_path, cluster=cluster).items():
        candidates = bucket.get("candidates") or []
        if not candidates:
            continue
        if get_active_override(pid, policy_name=bucket.get("policy_violated")):
            continue
        top = candidates[0]
        items.append({
            "kind": "adopt", "policy_id": pid,
            "policy_violated": bucket.get("policy_violated"),
            "suggestion": top.get("suggestion"),
            "resolution_type": top.get("resolution_type"),
            "count": top.get("count"),
        })
    for r in list_recent_incidents(limit=200, db_path=db_path):
        if r.get("status") in _BLOCKING_STATUSES and not r.get("label_verdict"):
            items.append({
                "kind": "verdict",
                "receipt_id": r.get("receipt_id"),
                "policy_id": r.get("policy_id"),
                "policy_violated": r.get("policy_violated"),
                "status": r.get("status"),
                "label_safe_path": r.get("label_safe_path"),
                "created_at": r.get("created_at"),
                "challenge_issued": r.get("challenge_issued"),
                "agent_cot": r.get("agent_cot"),
                "raw_payload": r.get("raw_payload"),
            })
    return items


def labeled_items(db_path=None):
    """Blocks that ALREADY carry a verdict — powers ``agentx review --labeled``, the
    re-review path. ``reviewable_items`` only ever shows what's still PENDING; once
    labeled, an item vanishes from the normal walkthrough with no way back to see or
    change that decision. Same "verdict" item shape as ``reviewable_items``, plus the
    current ``label_verdict`` so it can be shown before it's (maybe) overwritten."""
    items = []
    for r in list_recent_incidents(limit=200, db_path=db_path):
        if r.get("label_verdict"):
            items.append({
                "kind": "verdict",
                "receipt_id": r.get("receipt_id"),
                "policy_id": r.get("policy_id"),
                "policy_violated": r.get("policy_violated"),
                "status": r.get("status"),
                "label_safe_path": r.get("label_safe_path"),
                "label_verdict": r.get("label_verdict"),
                "created_at": r.get("created_at"),
                "challenge_issued": r.get("challenge_issued"),
                "agent_cot": r.get("agent_cot"),
                "raw_payload": r.get("raw_payload"),
            })
    return items


def count_reviewable(db_path=None):
    """How many items await review — drives the session-end nudge (runs at atexit for
    every protected session, so it must stay cheap). ``cluster=False`` skips the
    near-duplicate merge: the count is invariant under clustering (adopt items are
    one-per-policy; verdict items don't cluster at all), so this returns the SAME
    number ``reviewable_items()`` would, without the O(k^2) difflib pass. Defensive:
    0 on any error / absent store, so the nudge stays quiet on a plain or keyless run."""
    try:
        return len(reviewable_items(db_path, cluster=False))
    except Exception:
        return 0


def label_stats(db_path=None):
    """Aggregate counts across the label channel's three axes, over EVERY incident in the
    store (not just what's pending) — powers ``agentx review --stats``. Complements
    ``reviewable_items`` (what's left to decide) with a "where do we stand" view. An
    off-vocab or absent axis value is counted as its own bucket (``unlabeled`` /
    ``n/a`` / ``unknown``) rather than skipped, so the buckets always sum to ``total``.
    Missing store -> all-zero counts, never raises."""
    rows = list_recent_incidents(limit=100000, db_path=db_path)
    stats = {
        "total": len(rows),
        "verdict": {"TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "ACCEPTED_RISK": 0, "unlabeled": 0},
        "safe_path": {"HELD": 0, "FAILED": 0, "n/a": 0},
        "harm": {"HARM": 0, "NO_HARM": 0, "unknown": 0},
        "blocking_open": 0,   # awaiting a verdict right now (mirrors reviewable_items)
    }
    for r in rows:
        v = r.get("label_verdict")
        stats["verdict"][v if v in _VERDICT_VOCAB else "unlabeled"] += 1
        sp = r.get("label_safe_path")
        stats["safe_path"][sp if sp in _SAFE_PATH_VOCAB else "n/a"] += 1
        h = r.get("label_harm")
        stats["harm"][h if h in _HARM_VOCAB else "unknown"] += 1
        if r.get("status") in _BLOCKING_STATUSES and not v:
            stats["blocking_open"] += 1
    return stats


# ------------------------------------------------- org rules file (cold-start seed)
# `.agentx/rules.json` is a plain-language, human-authored front-end over the override
# store: an org writes its safe-path REFRAMES and pre-declared VERDICTs once, up front, so
# the org brain is seeded before any harvest data exists. Human-authored -> poisoning-safe
# (only auto-applying AGENT-generated text is forbidden). REFRAME-AND-LABEL ONLY: a rule
# may add a reframe or pre-declare a verdict; it may NOT loosen/suppress a floor block --
# that is a higher-bar, explicitly-audited action, never a config line.
DEFAULT_ORG_RULES_PATH = os.path.join(".agentx", "rules.json")
_ORG_RULES_KEYS = ("reframes", "verdicts")
# Keys that would LOOSEN the floor — rejected with a pointer to the higher-bar gate.
_ORG_RULES_LOOSENING_KEYS = ("suppress", "allow", "never_block", "unblock", "exceptions")


def _org_rules_path(path=None):
    if path:
        return path
    env = os.environ.get("AGENTX_RULES")
    if env:
        return env
    return os.path.join(_find_project_root(), DEFAULT_ORG_RULES_PATH)


def load_org_rules(rules_path=None):
    """Read + validate `.agentx/rules.json`. Returns ``(rules, errors)``: ``rules`` is the
    parsed dict (empty if the file is absent), ``errors`` a list of human-readable problems.
    Never raises. Enforces the REFRAME-AND-LABEL-ONLY guardrail — a loosening key is an
    ERROR that names the higher-bar path, never a silent no-op."""
    p = _org_rules_path(rules_path)
    if not os.path.exists(p):
        return {}, []
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return {}, [f"could not parse {p}: {e}"]
    if not isinstance(data, dict):
        return {}, [f"{p}: the top level must be an object with 'reframes' / 'verdicts'"]
    errors = []
    for k in data:
        if k in _ORG_RULES_LOOSENING_KEYS:
            errors.append(
                f"'{k}' would LOOSEN the floor (stop a block from firing). That is NOT a "
                "rules-file action: suppressing a floor block is an explicit, audited "
                "approval, never a config line. Remove it — keep only 'reframes' / 'verdicts'.")
        elif k not in _ORG_RULES_KEYS:
            errors.append(f"unknown key '{k}' (expected 'reframes' / 'verdicts')")
    for r in (data.get("reframes") or []):
        if not isinstance(r, dict) or not r.get("policy") or not (r.get("safe_path") or r.get("challenge")):
            errors.append(f"a reframe needs 'policy' and 'safe_path' (or 'challenge'): {r!r}")
    for v in (data.get("verdicts") or []):
        if not isinstance(v, dict) or not v.get("policy") or v.get("verdict") not in _VERDICT_VOCAB:
            errors.append(f"a verdict needs 'policy' and 'verdict' in {sorted(_VERDICT_VOCAB)}: {v!r}")
    return data, errors


def _resolve_policy_ref(ref):
    """A rules-file 'policy' field is a plain built-in NAME or a raw policy id. Return
    ``(policy_id, policy_name)`` — the id keys the override store; the name is None for a
    raw/custom id."""
    entry, n = resolve_policy_by_name(ref)
    if n == 1:
        return entry["id"], entry["name"]
    return ref, None


def get_declared_verdict(policy_id, policy_name=None, path=None):
    """The org-declared verdict for a policy (from the rules file -> overrides.json
    'verdicts'), id-first with a name fallback. None if none declared.

    The name fallback checks the RAW name as a dict key before resolving it through
    the built-in catalog. This matters because set_declared_verdict's caller (the
    keyless-MCP wedge) keys a verdict by ``pid or name`` when no canonical policy_id
    was captured -- so the store can hold a verdict under the literal name string.
    A caller on the OTHER path (SDK/gateway incidents.db) that DOES have a real
    policy_id would otherwise never find it: policy_id misses the direct check, and
    resolving the name to its built-in id doesn't recover a verdict stored under the
    name itself. Mirrors get_active_override's cross-path name fallback."""
    verdicts = load_overrides(path).get("verdicts") or {}
    if policy_id and policy_id in verdicts:
        return verdicts[policy_id]
    if policy_name:
        if policy_name in verdicts:
            return verdicts[policy_name]
        entry, n = resolve_policy_by_name(policy_name)
        if n == 1 and entry["id"] in verdicts:
            return verdicts[entry["id"]]
    return None


def set_declared_verdict(policy_id, verdict, policy_name=None, path=None):
    """Record an org verdict for a POLICY into overrides.json 'verdicts' — the SAME store the
    rules file writes and get_declared_verdict reads. This is how the keyless-MCP wedge gets
    verdicted: its harvest is value-free and has NO per-block receipt (privacy by design), so
    its finest labelable unit is the policy, not an individual block. Off-vocab RAISES; a plain
    name resolves to its built-in id so review and the rules file agree on the key. Applying it
    to matching incidents (apply_declared_verdicts) is what carries it to the corpus. Returns
    the resolved policy id."""
    if verdict not in _VERDICT_VOCAB:
        raise ValueError("verdict %r not in %s" % (verdict, sorted(_VERDICT_VOCAB)))
    pid = policy_id
    if not pid and policy_name:
        entry, n = resolve_policy_by_name(policy_name)
        if n == 1:
            pid = entry["id"]
    if not pid:
        raise ValueError("a policy id or resolvable name is required to set a verdict")
    data = load_overrides(path)
    data.setdefault("verdicts", {})[pid] = verdict
    save_overrides(data, path)
    return pid


def clear_declared_verdict(policy_id=None, policy_name=None, path=None):
    """Remove a policy's STANDING declared verdict from overrides.json 'verdicts' — the
    counterpart to set_declared_verdict. Deletes it under BOTH its id key AND its name key,
    because a verdict can be stored under either (the cross-path identity flicker: the
    keyless-MCP wedge keys by ``pid or name``, the incidents.db batch path by the resolved
    id). Future blocks on the policy then re-SURFACE in review instead of being auto-labeled;
    EXISTING labels are left untouched (we don't record whether a label came from the
    auto-sweep or a human, so blindly un-labeling would wipe real human calls too). Returns
    the verdict that was removed, or None if the policy carried no standing verdict."""
    data = load_overrides(path)
    verdicts = data.get("verdicts") or {}
    keys = set()
    if policy_id:
        keys.add(policy_id)
    if policy_name:
        keys.add(policy_name)
        entry, n = resolve_policy_by_name(policy_name)
        if n == 1:
            keys.add(entry["id"])
    removed = None
    for k in keys:
        if k in verdicts:
            removed = verdicts.pop(k)
    if removed is not None:
        data["verdicts"] = verdicts
        save_overrides(data, path)
    return removed


def unlabel_declared_verdicts(policy_id=None, policy_name=None, db_path=None):
    """Clear the VERDICT axis on blocks a standing rule auto-applied (label_verdict_source ==
    'declared') for this policy, so they RE-SURFACE for review — leaving human-set verdicts
    (source 'human') and the other axes (safe_path / harm) untouched. The safe complement to
    clear_declared_verdict: removing a rule can now also undo exactly what the rule stamped,
    because provenance distinguishes rule-applied labels from human calls. Identity is matched
    by normalized NAME or policy_id (the same cross-path union used elsewhere). Returns the
    count cleared (0 on a missing/unreadable store, never raises)."""
    target_id = policy_id
    target_name = _norm_for_dedup(policy_name) if policy_name else None
    if policy_name and not target_id:
        entry, n = resolve_policy_by_name(policy_name)
        if n == 1:
            target_id = entry["id"]
    ids = {i for i in (policy_id, target_id) if i}
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return 0
    try:
        conn = sqlite3.connect(p)
        try:
            _ensure_label_columns(conn)
            rows = conn.execute(
                "SELECT receipt_id, policy_id, policy_violated FROM incidents "
                "WHERE label_verdict_source = 'declared'"
            ).fetchall()
            targets = [r[0] for r in rows
                       if (r[1] and r[1] in ids)
                       or (target_name and _norm_for_dedup(r[2] or "") == target_name)]
            if not targets:
                return 0
            conn.executemany(
                "UPDATE incidents SET label_verdict = NULL, label_verdict_source = NULL, "
                "outcome_at = ? WHERE receipt_id = ?",
                [(_now_iso(), rid) for rid in targets],
            )
            conn.commit()
            return len(targets)
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def count_policy_verdict_evidence(policy_id=None, policy_name=None, verdict=None, db_path=None):
    """How many labeled blocks in the local store belong to this policy (and, if ``verdict``
    is given, carry THAT verdict). Identity is matched by normalized NAME or by policy_id —
    the same cross-path flicker union the grouping uses, so a policy's blocks are found under
    either. Powers the 'limited data' guard: setting a STANDING rule from fewer than a couple
    of agreeing blocks is a thin-evidence action that ``agentx override --policy`` gates
    behind --force. Returns the count (0 on a missing/unreadable store, never raises)."""
    target_id = policy_id
    target_name = _norm_for_dedup(policy_name) if policy_name else None
    if policy_name and not target_id:
        entry, n = resolve_policy_by_name(policy_name)
        if n == 1:
            target_id = entry["id"]
    ids = {i for i in (policy_id, target_id) if i}
    count = 0
    try:
        rows = list_recent_incidents(limit=100000, db_path=db_path)
    except Exception:
        return 0
    for r in rows:
        lv = r.get("label_verdict")
        if not lv or (verdict is not None and lv != verdict):
            continue
        rid = r.get("policy_id")
        rname = _norm_for_dedup(r.get("policy_violated") or "")
        if (rid and rid in ids) or (target_name and rname == target_name):
            count += 1
    return count


def count_policy_unlabeled_blocks(policy_id=None, policy_name=None, db_path=None):
    """How many of THIS policy's blocks are still unlabeled (a pending verdict) — the rows a
    freshly-set standing rule will cover. Lets ``override --policy`` report a count scoped to
    the named policy instead of ``apply_declared_verdicts()``'s STORE-WIDE total (which spans
    every policy carrying a declared verdict). Identity matched by normalized NAME or policy_id
    (the cross-path union). 0 on a missing/unreadable store, never raises."""
    target_id = policy_id
    target_name = _norm_for_dedup(policy_name) if policy_name else None
    if policy_name and not target_id:
        entry, n = resolve_policy_by_name(policy_name)
        if n == 1:
            target_id = entry["id"]
    ids = {i for i in (policy_id, target_id) if i}
    count = 0
    try:
        rows = list_recent_incidents(limit=100000, db_path=db_path)
    except Exception:
        return 0
    for r in rows:
        if r.get("label_verdict") or r.get("status") not in _BLOCKING_STATUSES:
            continue
        rid = r.get("policy_id")
        rname = _norm_for_dedup(r.get("policy_violated") or "")
        if (rid and rid in ids) or (target_name and rname == target_name):
            count += 1
    return count


def apply_declared_verdicts(path=None, db_path=None):
    """Label any unlabeled block whose policy carries an org-declared verdict (the pre-label
    from the rules file), so it never re-prompts in review. Does NOT touch the block itself
    -- pre-label != suppress. Returns the count labeled.

    Scans the WHOLE store (like reconcile_safe_paths / label_stats), not a recent window: a
    standing declared verdict is a policy-level rule that applies to EVERY matching block, and
    a smaller cap made `verdict --policy`'s labeled-count (which counts this policy's pending
    blocks across the whole store) overstate what was actually applied on a large store."""
    if not (load_overrides(path).get("verdicts") or {}):
        return 0
    labeled = 0
    for r in list_recent_incidents(limit=100000, db_path=db_path):
        if r.get("label_verdict") or r.get("status") not in _BLOCKING_STATUSES:
            continue
        v = get_declared_verdict(r.get("policy_id"), r.get("policy_violated"), path=path)
        if v and record_outcome(r.get("receipt_id"), verdict=v, source="declared", db_path=db_path):
            labeled += 1
    return labeled


def apply_org_rules(rules_path=None, path=None, db_path=None):
    """Ingest `.agentx/rules.json` into the override store — the cold-start seed. REFRAMES
    become active overrides (human-authored, so always allowed); VERDICTs are declared and
    applied to any matching CURRENT unlabeled blocks. Raises ValueError on validation
    errors. Returns ``{reframes_adopted, verdicts_declared, blocks_labeled}``."""
    rules, errors = load_org_rules(rules_path)
    if errors:
        raise ValueError("; ".join(errors))
    data = load_overrides(path)
    data.setdefault("verdicts", {})
    reframes = verdicts = 0
    for r in (rules.get("reframes") or []):
        pid, pname = _resolve_policy_ref(r["policy"])
        data["overrides"][pid] = {
            "policy_violated": pname,
            "challenge": (r.get("challenge") or r.get("safe_path") or "").strip(),
            "safe_path": r.get("safe_path"),
            "resolution_type": None,
            "source": "rules",
            "adopted_at": _now_iso(),
        }
        reframes += 1
    for v in (rules.get("verdicts") or []):
        pid, _ = _resolve_policy_ref(v["policy"])
        data["verdicts"][pid] = v["verdict"]
        verdicts += 1
    save_overrides(data, path)
    labeled = apply_declared_verdicts(path=path, db_path=db_path)
    return {"reframes_adopted": reframes, "verdicts_declared": verdicts, "blocks_labeled": labeled}
