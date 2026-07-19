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
            data = json.load(f)
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


def harvest_candidates(db_path=None):
    """Project the local incident store's *reusable* ``resolution_path`` rows into
    ranked per-policy safe-path candidates.

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
        merged = cluster_near_duplicates(list(bucket["_by_text"].values()),
                                         text_key="suggestion")
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
