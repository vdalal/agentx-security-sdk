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
            return {"version": _SCHEMA_VERSION, "overrides": {}, "scoped_overrides": []}
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("override store is not a JSON object")
        data.setdefault("version", _SCHEMA_VERSION)
        if not isinstance(data.get("overrides"), dict):
            data["overrides"] = {}
        # Scoped overrides live in their OWN container, never inside the `overrides` map. See
        # _SCOPE_DIMENSIONS for why that separation is the safety property and not just tidiness.
        if not isinstance(data.get("scoped_overrides"), list):
            data["scoped_overrides"] = []
        return data
    except FileNotFoundError:
        return {"version": _SCHEMA_VERSION, "overrides": {}, "scoped_overrides": []}
    except (OSError, ValueError, json.JSONDecodeError) as e:
        if warn:
            print(f"⚠️  [AgentX] Could not read your override store at {p}: {e}\n"
                  f"    Your adopted org reframes are NOT being applied until this "
                  f"is fixed (it's plain JSON — check for a trailing comma or an "
                  f"unclosed quote).", file=sys.stderr)
        return {"version": _SCHEMA_VERSION, "overrides": {}, "scoped_overrides": []}


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


# --------------------------------------------------------- context-scoped overrides
# A scoped override attaches a reframe to a SITUATION rather than to a whole policy.
# The match key is four optional dimensions:
#
#   agent_id       the name the developer gave their own agent   -- carries org specificity
#   tool           the tool / function name                      -- carries org specificity
#   target_action  DELETE / EXECUTE / SEND / WRITE / LIST / READ / OTHER  -- a coarse CLASS
#   scope          scoped | broad (does any argument KEY narrow the blast radius)  -- coarse
#
# Read the asymmetry before writing one: the last two describe a class of call ("a delete-shaped
# tool called with some narrowing argument"), not one job. "Our nightly cleanup is fine" needs
# agent_id and/or tool; target_action + scope alone will match a great deal more than the author
# expects. This is stated here rather than only in the docs because the coarse pair is the one
# that is easiest to write and the least likely to mean what it looks like it means.
#
# REDIRECT ONLY. These change the coaching text and the safe path, never the block/allow verdict.
# That is what makes them safe to adopt without a governance gate: a reframe cannot turn a block
# into an allow. It is NOT free of consequence, though — a scoped reframe still reaches the agent
# and still steers its next action, so coaching that fires in the wrong place is a real cost even
# though it is not a loosened floor.
#
# WHY A SEPARATE CONTAINER. Scoped entries live in `scoped_overrides`, never in the `overrides`
# map. The invariant "a scoped override must never silently widen to the bare policy" is then
# STRUCTURAL: the bare lookup reads a different container, so there is no code path that could
# read a scoped entry as an unscoped one, and no rule anyone has to remember. The alternative
# (one list per policy id, scoped and bare together) would make that widening a live bug the
# whole time it stayed unwritten.
_SCOPE_DIMENSIONS = ("agent_id", "tool", "target_action", "scope")


# The two dimensions that are CODE IDENTIFIERS, compared exactly (after trimming) rather than
# case-folded. `billing` and `Billing` are two different agents, so case-folding them would fire a
# rule on something its author did not write — the same widening this whole mechanism exists to
# prevent, arriving through a convenience. The other two are CLOSED VOCABULARIES with one true
# spelling each, so those ARE case-normalized: a hand-edited store never passes through
# ``normalize_scope``, and `"delete"` there plainly means DELETE.
_EXACT_DIMENSIONS = ("agent_id", "tool")


def _canon_dimension(dimension, value):
    """One dimension's value in its comparable form. Identifiers keep their case; closed vocabs
    are folded to the single spelling ``normalize_scope`` would have produced."""
    text = "" if value is None else str(value).strip()
    if dimension in _EXACT_DIMENSIONS:
        return text
    return text.upper() if dimension == "target_action" else text.lower()


def _scope_matches(when, signature):
    """True iff EVERY dimension the override NAMES equals the block's signature.

    Two refusals matter more than the match itself:
      * an override that names NO dimension returns False, never "matches everything". An empty
        or stripped ``when`` is a malformed scoped entry, and the only safe reading of it is
        that it fires nowhere. This is the second half of the never-widen invariant: the
        container keeps a scoped entry out of the bare lookup, and this keeps an EMPTIED scoped
        entry from becoming a de-facto bare one inside its own container.
      * a missing signature returns False, so any caller that cannot describe the block simply
        gets the bare override — the behaviour that shipped before scoping existed.

    See ``_canon_dimension`` for why the two identifier dimensions are compared case-SENSITIVELY
    while the two closed vocabularies are not."""
    if not isinstance(when, dict) or not isinstance(signature, dict):
        return False
    named = [d for d in _SCOPE_DIMENSIONS if when.get(d)]
    if not named:
        return False
    return all(_canon_dimension(d, when[d]) == _canon_dimension(d, signature.get(d))
               for d in named)


def _scope_specificity(when):
    """How many dimensions an override names — the sort key for most-specific-first. Ties break
    on the fixed ``_SCOPE_DIMENSIONS`` ORDER (an agent_id-named scope outranks a same-sized one
    named on target_action), then on adoption time, so the winner is fully deterministic and two
    runs of the same store can never disagree."""
    return (
        sum(1 for d in _SCOPE_DIMENSIONS if isinstance(when, dict) and when.get(d)),
        tuple(1 if isinstance(when, dict) and when.get(d) else 0 for d in _SCOPE_DIMENSIONS),
    )


def _policy_matches(entry, policy_id, policy_name):
    """Whether a scoped entry belongs to this policy — the SAME id-or-name union
    ``get_active_override`` uses on the bare map, because the same logical policy carries
    different ids across the two block paths (keyword-shield seed UUID vs gateway/judge id).

    The name arm guards on the NORMALIZED name, matching what the bare lookup does. Guarding on
    the raw one instead lets a whitespace-only policy name normalize to "" and match an entry
    whose ``policy_violated`` is null — which every scoped adopt produces when the caller does
    not pass a name. It is a narrow case and it widens, which is the direction that matters."""
    if policy_id and entry.get("policy_id") == policy_id:
        return True
    target = _norm_for_dedup(policy_name)
    if target and _norm_for_dedup(entry.get("policy_violated")) == target:
        return True
    return False


def _sort_key(entry):
    """Ordering key for one scoped entry: most dimensions first, then most recently adopted.

    ``adopted_at`` is forced to ``str``. The store is a documented HAND-EDITABLE file, so a
    number there is reachable, and two entries with the same specificity would then compare int
    against str and raise TypeError straight out onto the block path — breaking this module's
    standing contract that a bad override never breaks a protected call. It survived a first
    probe because entries of DIFFERENT specificity resolve on the tuple and never reach this
    field; it takes two identically-scoped entries to see it."""
    return (_scope_specificity(entry.get("when")), str(entry.get("adopted_at") or ""))


def get_scoped_override(policy_id, policy_name=None, signature=None, path=None, store=None):
    """The most specific scoped reframe matching this block, as ``{challenge, safe_path}``, or
    ``None``. Best-effort like every read on the block path: any error yields ``None`` and the
    caller falls back to the bare override.

    ``store`` lets a caller that has already loaded the store pass it in. Without it this reads
    the file a second time on every block, since ``get_active_override`` needs it too."""
    if signature is None:
        return None
    try:
        if store is None:
            store = load_overrides(path)
        entries = store.get("scoped_overrides") or []
        matches = [e for e in entries
                   if isinstance(e, dict)
                   and _policy_matches(e, policy_id, policy_name)
                   and _scope_matches(e.get("when"), signature)]
        # The sort is INSIDE the try with everything else: it reads store data, so it is as
        # exposed to a malformed file as the parse is.
        for entry in sorted(matches, key=_sort_key, reverse=True):
            hit = _entry_to_override(entry)
            if hit:
                return hit
    except Exception:
        return None
    return None


def list_scoped_overrides(policy_id=None, policy_name=None, path=None, store=None):
    """Every scoped override for a policy (or, with neither argument, the whole store), as
    ``[{when, challenge, safe_path, source, adopted_at}]``, most specific first.

    This exists because a scoped override is otherwise INVISIBLE to the person who wrote it:
    ``agentx policies`` asks ``get_active_override`` with no signature, so a policy carrying
    only scoped rules reads as "not customized", which is the same thing it reads as when the
    author's scope has a typo in it. A rule you cannot see is a rule you cannot debug.

    ``store`` lets a caller iterating every policy load the file once instead of once per policy
    (``agentx policies`` walks 20+ floors)."""
    try:
        if store is None:
            store = load_overrides(path)
        entries = store.get("scoped_overrides") or []
        out = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if (policy_id or policy_name) and not _policy_matches(entry, policy_id, policy_name):
                continue
            out.append({
                "policy_id": entry.get("policy_id"),
                "policy_violated": entry.get("policy_violated"),
                "when": entry.get("when") or {},
                "challenge": entry.get("challenge"),
                "safe_path": entry.get("safe_path"),
                "source": entry.get("source"),
                "adopted_at": entry.get("adopted_at"),
            })
        # Same str-forced key as _sort_key, for the same reason: a hand-edited numeric
        # `adopted_at` beside a string one would otherwise raise out of a plain listing.
        return sorted(out, key=lambda e: (_scope_specificity(e["when"]),
                                          str(e["adopted_at"] or "")), reverse=True)
    except Exception:
        return []


def describe_scope(when):
    """A scope rendered for a human: ``agent nightly_cleanup · tool purge_stale_rows``. Empty
    scope renders as an explicit warning rather than a blank, because a blank would read as
    'applies everywhere' — the opposite of what an empty scope actually does (match nothing)."""
    if not isinstance(when, dict) or not any(when.get(d) for d in _SCOPE_DIMENSIONS):
        return "⚠ no scope — matches nothing"
    labels = {"agent_id": "agent", "tool": "tool",
              "target_action": "action", "scope": "shape"}
    return " · ".join("%s %s" % (labels[d], when[d])
                      for d in _SCOPE_DIMENSIONS if when.get(d))


def has_human_coaching(policy_id, policy_name=None, path=None, store=None):
    """Does this policy already carry coaching a human chose — of ANY kind, bare or scoped?

    This is the question every GATE actually wants, and asking it as
    ``get_active_override(pid, name)`` gets it wrong in one specific and consequential way: that
    call reads only the bare map, so a policy a human deliberately NARROWED to one situation looks
    untouched. The gates then offer, or install, a POLICY-WIDE override on it — widening exactly
    the policy someone took the trouble to scope. Deliberate narrowing is a stronger statement of
    intent than no opinion at all, and it has to read that way.

    Every gate should call THIS, not the lookup. The lookup answers "what fires for this block",
    which is a different question and needs a signature to answer honestly.

    ``store`` matters more here than it looks: this asks TWO questions, so without it each call is
    two file reads, and the gates call it once PER POLICY in a loop. That is the same read
    amplification already fixed in ``list_customizable_policies``, and it came straight back one
    function along."""
    if store is None:
        try:
            store = load_overrides(path)
        except Exception:
            return False
    if get_active_override(policy_id, policy_name=policy_name, store=store):
        return True
    return bool(list_scoped_overrides(policy_id, policy_name=policy_name, store=store))


def get_active_override(policy_id, policy_name=None, path=None, signature=None, store=None):
    """The adopted org reframe for this policy as ``{challenge, safe_path}``, or
    ``None``.

    When a ``signature`` describes the block (see ``_SCOPE_DIMENSIONS``), the most specific
    matching SCOPED override wins; the bare policy-wide override is the fallback. A caller that
    passes no signature gets exactly the pre-scoping behaviour.

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
        # ONE read, shared by the scoped and bare lookups. Two reads would double the file I/O
        # on every block, and would let the two halves answer from different states of a file
        # the user is allowed to edit while their agent runs. ``store`` extends that to a caller
        # walking every policy, which would otherwise read the file once per policy.
        data = load_overrides(path) if store is None else store
    except Exception:
        return None
    scoped = get_scoped_override(policy_id, policy_name=policy_name,
                                 signature=signature, store=data)
    if scoped:
        return scoped
    try:
        store = data["overrides"]
        if policy_id:
            hit = _entry_to_override(store.get(policy_id))
            if hit:
                return hit                              # exact id wins
        if policy_name:
            target = _norm_for_dedup(policy_name)
            if target:
                matches = [
                    (str(entry.get("adopted_at") or ""), str(pid), entry)
                    for pid, entry in store.items()
                    if isinstance(entry, dict)
                    and _norm_for_dedup(entry.get("policy_violated")) == target
                ]
                # Most-recently-adopted first, tie-break on id — fully deterministic. Both key
                # parts are forced to str for the same reason the scoped sort is (see
                # _sort_key): this store is hand-editable, so a number in `adopted_at` is
                # reachable, and comparing int against str raises onto the block path. The
                # third element is a dict and is NOT part of the key — reaching it would raise
                # too, which is why the sort is keyed on the first two explicitly.
                for _, _, entry in sorted(matches, key=lambda m: (m[0], m[1]), reverse=True):
                    hit = _entry_to_override(entry)
                    if hit:
                        return hit
    except Exception:
        return None
    return None


def normalize_scope(when):
    """Validate + clean a human-written scope into the stored ``when`` shape, or raise
    ValueError naming what is wrong. Returns ``None`` for "no scope given" (an unscoped adopt).

    Validation exists because a scope that matches NOTHING fails silently — the block just gets
    the generic challenge, exactly as if the author had never written the rule. A typo in
    ``target_action`` is the likely case, so the closed vocabularies are checked against the
    ones DERIVED from the classifier itself, never a hand-copied list."""
    if not when:
        return None
    if not isinstance(when, dict):
        raise ValueError("a scope must be an object with any of %s" % (list(_SCOPE_DIMENSIONS),))
    from .decorators import TARGET_ACTIONS, SCOPES
    cleaned, unknown = {}, []
    for k, v in when.items():
        if k not in _SCOPE_DIMENSIONS:
            unknown.append(k)
            continue
        if v is None or not str(v).strip():
            continue
        cleaned[k] = str(v).strip()
    if unknown:
        raise ValueError("unknown scope field(s) %s — a scope names any of %s"
                         % (sorted(unknown), list(_SCOPE_DIMENSIONS)))
    ta = cleaned.get("target_action")
    if ta and ta.upper() not in TARGET_ACTIONS:
        raise ValueError("target_action %r is not one of %s" % (ta, sorted(TARGET_ACTIONS)))
    if ta:
        cleaned["target_action"] = ta.upper()
    sc = cleaned.get("scope")
    if sc and sc.lower() not in SCOPES:
        raise ValueError("scope %r is not one of %s" % (sc, sorted(SCOPES)))
    if sc:
        cleaned["scope"] = sc.lower()
    if not cleaned:
        raise ValueError(
            "this scope names no dimension, so it would match nothing. Name at least one of %s "
            "— agent_id or tool for a specific job, target_action or scope for a whole class."
            % (list(_SCOPE_DIMENSIONS),))
    return cleaned


def adopt(policy_id, *, challenge, safe_path=None, resolution_type=None,
          policy_violated=None, source="harvest", when=None, path=None):
    """Promote a reframe to the ACTIVE override for ``policy_id`` — the human
    gate. Returns the stored entry.

    Without ``when`` this is the policy-wide override it has always been, and it overwrites any
    prior policy-wide override for that policy. With ``when`` (see ``_SCOPE_DIMENSIONS``) it
    stores a CONTEXT-SCOPED override instead, into the separate ``scoped_overrides`` container,
    replacing only a prior entry for the SAME policy and the SAME scope — a store can hold as
    many scoped overrides per policy as there are distinct scopes."""
    if not policy_id:
        raise ValueError("policy_id is required to adopt an override")
    if not challenge or not str(challenge).strip():
        raise ValueError("challenge text is required to adopt an override")
    cleaned_when = normalize_scope(when)
    data = load_overrides(path)
    entry = {
        "policy_violated": policy_violated,
        "challenge": str(challenge).strip(),
        "safe_path": safe_path,
        "resolution_type": resolution_type,
        "source": source,
        "adopted_at": _now_iso(),
    }
    if cleaned_when is None:
        data["overrides"][policy_id] = entry
    else:
        entry = dict(entry, policy_id=policy_id, when=cleaned_when)
        # Replace the same (policy, scope) rather than appending, so re-adopting a scope the
        # author already wrote updates it instead of silently stacking a second entry that the
        # most-specific-first sort would then have to break a tie between.
        data["scoped_overrides"] = [
            e for e in (data.get("scoped_overrides") or [])
            if not (isinstance(e, dict) and e.get("policy_id") == policy_id
                    and e.get("when") == cleaned_when)
        ] + [entry]
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
    # Read the store ONCE for the whole listing. Both lookups below take it, so a 20+ floor
    # listing is one file read rather than two per policy.
    store = load_overrides(path)
    for p in builtin_policy_catalog():
        override = get_active_override(p["id"], policy_name=p["name"], store=store)
        # Scoped rules are reported SEPARATELY rather than folded into active_challenge: which
        # one applies depends on the call, so there is no single "active" answer to give here,
        # and picking one would misreport three of them as the policy's coaching.
        scoped = list_scoped_overrides(p["id"], policy_name=p["name"], store=store)
        out.append({
            "id": p["id"],
            "name": p["name"],
            "category": p.get("category"),
            "default_challenge": p.get("challenge"),
            "default_safe_path": p.get("safe_path"),
            "active_challenge": override.get("challenge") if override else None,
            "active_safe_path": override.get("safe_path") if override else None,
            "customized": override is not None,
            "scoped": scoped,
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
    _store = load_overrides()          # once for the whole loop, not twice per policy
    for pid, bucket in harvest_candidates(db_path, cluster=cluster).items():
        candidates = bucket.get("candidates") or []
        if not candidates:
            continue
        # Any human coaching counts, scoped included — see has_human_coaching. Offering "adopt
        # this" for a policy the human already narrowed leads them to install a policy-wide rule
        # over their own scoped one.
        if has_human_coaching(pid, policy_name=bucket.get("policy_violated"), store=_store):
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
#
# A reframe may carry an optional "when" that scopes it to a SITUATION rather than the whole
# policy -- this is the authoring surface for context-scoped overrides (_SCOPE_DIMENSIONS):
#
#   {"reframes": [{"policy": "Mass Destructive Intent",
#                  "when": {"agent_id": "nightly_cleanup", "tool": "purge_stale_rows"},
#                  "safe_path": "Our nightly cleanup runs with a date filter -- add
#                                `WHERE created_at < now() - interval '90 days'` and retry."}]}
#
# It stays REDIRECT-only even when scoped: the block still fires, the coaching changes.
DEFAULT_ORG_RULES_PATH = os.path.join(".agentx", "rules.json")
_ORG_RULES_KEYS = ("reframes", "verdicts")
# The fields each entry may carry. Enforced as an ALLOWLIST because the failure mode of a
# misspelled key here is not "the field is ignored" -- it is "the rule applies to the whole policy
# instead of the one situation you wrote".
_ORG_RULES_REFRAME_KEYS = frozenset(("policy", "when", "challenge", "safe_path", "note"))
_ORG_RULES_VERDICT_KEYS = frozenset(("policy", "verdict", "note"))
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
            continue
        # 🔴 An unknown key on the reframe ITSELF is an ERROR, not something to ignore, and this is
        # the highest-consequence check in the file. Misspell `when` as `whn` and the reframe simply
        # reads as unscoped -- so a rule the author wrote for ONE situation is adopted POLICY-WIDE.
        # That is maximal widening, arriving silently, in the one feature whose stated property is
        # that it never silently widens. `normalize_scope` already rejects unknown fields INSIDE a
        # scope; nothing was checking the level above it, which is where the damage is worse.
        unknown = sorted(set(r) - _ORG_RULES_REFRAME_KEYS)
        if unknown:
            errors.append(
                f"reframe for '{r.get('policy')}' has unknown field(s) {unknown} "
                f"(expected {sorted(_ORG_RULES_REFRAME_KEYS)}). If you meant to scope it, the "
                f"field is 'when' — a misspelling here would silently make the rule apply to the "
                f"WHOLE policy instead of the situation you wrote.")
        # An optional 'when' scopes the reframe to a SITUATION instead of the whole policy. It is
        # validated HERE, at authoring time, because a scope that matches nothing fails SILENTLY
        # at block time: the agent just gets the generic challenge, indistinguishable from never
        # having written the rule at all. A typo has to be an error the author sees.
        if "when" in r:
            # A `when` that is PRESENT but names nothing ({} / [] / "" / 0 / null) is an ERROR, not
            # an unscoped adopt. normalize_scope returns None for anything falsy, which made the
            # reframe land in the bare map — so an author who wrote a scope and left it empty got
            # the rule applied to the WHOLE policy. That is the same silent widening the key
            # allowlist above exists to stop, arriving one level down, and it contradicts the code
            # beside it: `{"tool": "  "}` already errors with "would match nothing". Writing the
            # key at all is a statement of intent to scope; honour it or refuse it, never widen it.
            if not r.get("when"):
                errors.append(
                    f"reframe for '{r.get('policy')}' has an EMPTY 'when' ({r.get('when')!r}). "
                    f"A scope that names nothing would silently apply the rule to the WHOLE "
                    f"policy. Name at least one of {list(_SCOPE_DIMENSIONS)}, or remove the "
                    f"'when' key entirely if you meant the rule to be policy-wide.")
            else:
                try:
                    normalize_scope(r["when"])
                except ValueError as e:
                    errors.append(f"reframe for '{r.get('policy')}': {e}")
    for v in (data.get("verdicts") or []):
        if not isinstance(v, dict) or not v.get("policy") or v.get("verdict") not in _VERDICT_VOCAB:
            errors.append(f"a verdict needs 'policy' and 'verdict' in {sorted(_VERDICT_VOCAB)}: {v!r}")
            continue
        # Same check on the verdict side. It is lower-consequence (a misspelled 'verdict' already
        # fails the vocab test above, so it cannot silently widen) but an unknown key still means
        # the author wrote something that does nothing, and silence teaches them it worked.
        unknown = sorted(set(v) - _ORG_RULES_VERDICT_KEYS)
        if unknown:
            errors.append(f"verdict for '{v.get('policy')}' has unknown field(s) {unknown} "
                          f"(expected {sorted(_ORG_RULES_VERDICT_KEYS)})")
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
    errors. Returns ``{reframes_adopted, scoped_reframes_adopted, verdicts_declared,
    blocks_labeled}``.

    A reframe carrying a ``when`` is CONTEXT-SCOPED (``_SCOPE_DIMENSIONS``) and lands in the
    separate ``scoped_overrides`` container; the two counts are reported separately because
    "3 reframes" hides whether any of them will actually fire where the author meant."""
    rules, errors = load_org_rules(rules_path)
    if errors:
        raise ValueError("; ".join(errors))
    data = load_overrides(path)
    data.setdefault("verdicts", {})
    data.setdefault("scoped_overrides", [])
    # `rules.json` is DECLARATIVE: what the file says is what is active. So every entry this file
    # previously produced is withdrawn FIRST, and only the current contents are written back.
    #
    # Matching the old entry by its exact (policy, scope) instead was wrong in both directions and
    # in the dangerous direction. EDIT a rule's scope and the old, BROADER entry stayed live
    # forever — so narrowing "this tool" to "this agent AND this tool" left the tool-wide rule
    # coaching every other agent, which is the precise opposite of what the author just asked for.
    # DELETE a reframe from the file and it kept firing with nothing on disk to explain why. The
    # count printed "1 scoped" on every run, so neither showed up as anything the author could see.
    #
    # Scoped AND bare are both swept, because both had it — the bare map has kept a policy-wide
    # reframe alive across an emptied `rules.json` since that path shipped, and fixing only the
    # container this review happened to look at would leave the same bug one line away.
    #
    # Guarded on ``source == "rules"``: an override adopted via `agentx adopt` or written by
    # `agentx customize` did NOT come from this file and must survive an apply untouched.
    data["overrides"] = {k: v for k, v in data["overrides"].items()
                         if not (isinstance(v, dict) and v.get("source") == "rules")}
    data["scoped_overrides"] = [e for e in (data.get("scoped_overrides") or [])
                                if not (isinstance(e, dict) and e.get("source") == "rules")]
    # VERDICTS TOO. The first cut of this sweep did the two override containers and stopped, in the
    # same change whose message claimed to be fixing the template rather than the instance — so the
    # bug it named as "one line away" was left exactly one line away. A declared verdict carries
    # MORE consequence than a reframe: it pre-labels blocks and skips them in `agentx review`, so a
    # verdict withdrawn from the file but still live means blocks are being silently auto-labeled
    # by a rule that no longer exists on disk.
    #
    # Unlike the override containers, verdicts carry no `source` (the store holds a bare
    # policy_id -> verdict map, written by both this path and `set_declared_verdict`). So the
    # sweep is keyed on WHAT THIS FILE DECLARED LAST TIME, tracked explicitly.
    #
    # 🔴 Tracked as key->VALUE, not just the key. Tracking keys alone destroyed a human decision:
    # the file declares a verdict for P1, the developer then overrides it by hand with
    # `agentx verdict --policy`, the verdict is later removed from the file, and the sweep threw
    # away the HUMAN's call because the key still matched. A withdrawal may only retract a value
    # this file actually put there and that nobody has changed since.
    _prev = data.get("_rules_verdicts")
    if isinstance(_prev, list):                 # older shape (keys only) — treat as unknown values
        _prev = {k: None for k in _prev}
    if isinstance(_prev, dict) and _prev:
        _verdicts = dict(data.get("verdicts") or {})
        for k, previously_written in _prev.items():
            # Only if it is still OURS: same key AND still the value we wrote. A None means the
            # old key-only shape, where we cannot prove ownership — leave those alone rather than
            # guess, because the failure direction of guessing wrong is deleting a human's call.
            if previously_written is not None and _verdicts.get(k) == previously_written:
                _verdicts.pop(k, None)
        data["verdicts"] = _verdicts
    data.pop("_rules_verdict_keys", None)       # retire the old key shape if a store carries it
    reframes = scoped = verdicts = 0
    for r in (rules.get("reframes") or []):
        pid, pname = _resolve_policy_ref(r["policy"])
        entry = {
            "policy_violated": pname,
            "challenge": (r.get("challenge") or r.get("safe_path") or "").strip(),
            "safe_path": r.get("safe_path"),
            "resolution_type": None,
            "source": "rules",
            "adopted_at": _now_iso(),
        }
        when = normalize_scope(r.get("when"))     # already validated by load_org_rules
        if when is None:
            data["overrides"][pid] = entry
            reframes += 1
        else:
            data["scoped_overrides"].append(dict(entry, policy_id=pid, when=when))
            scoped += 1
    _declared_now = {}
    for v in (rules.get("verdicts") or []):
        pid, _ = _resolve_policy_ref(v["policy"])
        data["verdicts"][pid] = v["verdict"]
        _declared_now[pid] = v["verdict"]
        verdicts += 1
    # Record what THIS file wrote, key AND value, so the next apply can withdraw exactly what it
    # put there and can tell a value someone has since changed by hand. Stored rather than
    # inferred because the verdicts map itself carries no provenance.
    data["_rules_verdicts"] = _declared_now
    save_overrides(data, path)
    labeled = apply_declared_verdicts(path=path, db_path=db_path)
    return {"reframes_adopted": reframes, "scoped_reframes_adopted": scoped,
            "verdicts_declared": verdicts, "blocks_labeled": labeled}
