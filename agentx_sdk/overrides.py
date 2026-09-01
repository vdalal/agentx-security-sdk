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
from datetime import datetime, timedelta, timezone

# Stored under the same ``.agentx/`` mount the gateway shares for policies.json
# and incidents.db, so the override store is git-trackable and survives restarts.
DEFAULT_OVERRIDES_PATH = os.path.join(".agentx", "overrides.json")
_SCHEMA_VERSION = 1

# ONE canonical store: <project root>/.agentx/incidents.db. BACKLOG P-76.
#
# 🔴 THIS USED TO BE A CANDIDATE LIST SEARCHED FOR "the first one that EXISTS", and
# that is the defect, not a convenience. It made whichever store happened to appear
# first authoritative, so the answer changed the moment a second one showed up -- and
# one had, because the gateway resolved its own home against the process working
# directory. Measured in this repo: the reader returned a 4-row `.agentx/incidents.db`
# while the gateway had written 43,479 rows to `agentx_sdk/.agentx/incidents.db`, and
# `agentx insights` reported "No blocks recorded yet" to a developer whose gateway was
# recording perfectly. A resolution rule that silently re-points is worse than one that
# is simply wrong, because nothing about the output says which file it read.
#
# The gateway now anchors to the same project root, so there
# is one answer on both sides. Any OTHER store found under the root is a STRAY -- it is
# reported (see incident_db_strays), never silently substituted. An explicit
# AGENTX_INCIDENT_DB still wins, and is what the tests use.
DEFAULT_INCIDENT_DB = os.path.join(".agentx", "incidents.db")

# Directories a stray scan must never descend into: they are large, and none of them
# is anywhere a gateway writes its data home.
_STRAY_SCAN_SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv",
                    ".next", "dist", "build", ".pytest_cache", ".mypy_cache"}
_STRAY_SCAN_MAX_DEPTH = 3


def _find_project_root(start=None):
    """Anchor the ``.agentx/`` store to the project root so ``agentx insights`` /
    ``adopt`` and the runtime SDK-swap agree no matter which directory the dev runs
    from (e.g. ``examples/``).

    Prefers the ``.git`` REPO ROOT — it is unique and cwd-independent, and matches
    the "commit overrides.json to your repo" sharing model — so that NESTED
    ``.agentx/`` dirs (a repo can have several: the root and any package or service dir)
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


def _anchored_root(start=None):
    """The directory to anchor `.agentx/` to. THE single guarded entry point.

    🔴 EVERY STORE RESOLVER MUST USE THIS, NOT `_find_project_root` DIRECTLY, and the reason
    is the defect that made this function necessary. BACKLOG P-76/P-78 anchored the stores to
    the project root; the home-directory guard was then added to the gateway and to the policy
    loader but NOT to `_incident_db_path` or `_policy_db_path`. That left **two** resolution
    rules in a change whose entire thesis is that there is one, and it recreated the split it
    closed: from a marker-free scratch directory the gateway wrote `<cwd>/.agentx/incidents.db`
    while `agentx insights` read `~/.agentx/incidents.db` and reported "No blocks recorded
    yet" -- the identical false statement P-76 exists to eliminate.

    Fixing that by adding the guard at each call site would have left the template in place:
    the next resolver would forget it too. So the guard lives HERE, once, and callers cannot
    opt out by forgetting.

    **Why the guard exists at all:** `_find_project_root` walks up until it finds `.git` or
    `.agentx`, and `~/.agentx` exists for anyone who has run keyless `agentx adopt`. So for a
    process outside a checkout the "project root" resolves to the user's HOME, which would put
    a machine-wide store in `~/.agentx/` shared across every unrelated project. Anchoring only
    means something inside an actual project; when the walk escapes to home or above there is
    no project, and the honest answer is the working directory -- which is also the behaviour
    that predates the anchoring, so nothing moves for that user.
    """
    start_abs = os.path.abspath(start or os.getcwd())
    found = _find_project_root(start_abs)
    return start_abs if _is_home_or_above(found) else found


def _overrides_path(path=None):
    if path:
        return path
    env = os.environ.get("AGENTX_OVERRIDES")
    if env:
        return env
    return os.path.join(_anchored_root(), DEFAULT_OVERRIDES_PATH)


def _incident_db_path(path=None):
    """Resolve the incident store the gateway wrote. Explicit arg / env win, else the
    ONE canonical store under the project root.

    Returns the canonical path whether or not it exists, so a caller can report a
    not-found path rather than guessing at a different file. Project-root-anchored, so
    it resolves the same from any subdirectory and matches what the gateway writes
    (shared with the gateway). Existence is deliberately NOT part of the rule -- see the
    comment on DEFAULT_INCIDENT_DB for what "first one that exists" cost."""
    if path:
        return path
    env = os.environ.get("AGENTX_INCIDENT_DB")
    if env:
        return env
    return os.path.join(_anchored_root(), DEFAULT_INCIDENT_DB)


def _is_home_or_above(path):
    """True when ``path`` is the user's home directory or an ancestor of it.

    Such a directory is not "a project": scanning it is unbounded and anything found in it
    belongs to someone else's work, not the caller's. Never raises -- an unresolvable home
    just means "cannot prove it is home", and the scan proceeds as before.
    """
    try:
        home = os.path.realpath(os.path.expanduser("~"))
        p = os.path.realpath(path)
    except OSError:
        return False
    if home == p:
        return True
    # ⚠️ A FILESYSTEM ROOT ALREADY ENDS IN A SEPARATOR, so the naive `p + os.sep` produces
    # "C:\\\\" or "//" and the prefix test never matches -- the one directory that is most
    # obviously "above home" was the one case the guard let through, and it is the worst
    # place to start a walk from. Normalise the separator before comparing.
    prefix = p if p.endswith(os.sep) else p + os.sep
    return home.startswith(prefix)


def incident_db_strays(root=None, canonical=None):
    """Other ``.agentx/incidents.db`` files under the project root, LARGEST first.

    A stray is a store some gateway really did write, in a home that is no longer
    canonical -- typically one started from a subdirectory before P-76, or a compose
    mount pointing somewhere else. They are REPORTED, never read: substituting one is
    how the reader silently disagreed with the writer in the first place.

    Never raises and never opens a database. Only file sizes are used, because opening
    SQLite to count rows is itself a write risk, and a diagnostic that can dirty what it
    measures is not a diagnostic. Bounded to a shallow walk so ``agentx insights`` does
    not pay for a full-repo scan.

    Returns ``[{path, bytes}, ...]``, empty when the layout is clean.
    """
    explicit_root = root is not None
    root = root or _anchored_root()

    # 🔴 REFUSE TO SCAN WHEN "THE PROJECT" IS ACTUALLY THE HOME DIRECTORY.
    # _find_project_root falls back to the nearest ancestor holding .agentx/, and
    # `~/.agentx` exists for anyone who has run keyless `agentx adopt`. So a developer
    # running from any directory outside a checkout resolves the root to $HOME, and this
    # walk then (a) costs seconds of disk I/O on the MOST COMMON path -- a fresh user's
    # first `agentx insights`, where the store does not exist -- and (b) reports unrelated
    # projects' stores under the heading "other incident stores exist in this project",
    # offering to read one. That is a false statement of exactly the kind this feature was
    # written to correct, so it must not be the price of correcting the other one.
    #
    # The precise condition is "the root is the home directory or ABOVE it" -- that is
    # what makes the walk huge and makes neighbouring directories other people's projects.
    # Deliberately NOT "there is no .git": a partner kit is a real, bounded project with no
    # checkout, and it should still get the hint.
    if not explicit_root and _is_home_or_above(root):
        return []

    canonical = os.path.abspath(canonical or os.path.join(root, DEFAULT_INCIDENT_DB))
    found = []
    root_depth = os.path.abspath(root).rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = os.path.abspath(dirpath).rstrip(os.sep).count(os.sep) - root_depth
        if depth >= _STRAY_SCAN_MAX_DEPTH:
            dirnames[:] = []
        else:
            # Prune in place so os.walk never descends; a filter after the fact would
            # still pay the cost of walking node_modules.
            dirnames[:] = [d for d in dirnames if d not in _STRAY_SCAN_SKIP]
        if os.path.basename(dirpath) != ".agentx" or "incidents.db" not in filenames:
            continue
        full = os.path.abspath(os.path.join(dirpath, "incidents.db"))
        # 🔴 normcase, LIKE EVERY OTHER PATH COMPARISON IN THIS CHANGE. A raw `==` makes any
        # case difference between the walked path and the canonical one look like a
        # mismatch, and on Windows that means the canonical store LISTS ITSELF AS A STRAY --
        # the readout telling the developer their own store is not being read, which is the
        # exact false statement P-76 exists to remove, reintroduced by the code that reports
        # it. Cheap to get wrong because it is right on a case-sensitive filesystem and on
        # any run where both strings happen to come from the same source.
        if os.path.normcase(full) == os.path.normcase(canonical):
            continue
        try:
            found.append({"path": full, "bytes": os.path.getsize(full)})
        except OSError:
            continue
    # Largest first, and the docstring says exactly that. It used to claim
    # "newest-largest", which the sort never implemented -- mtime is not read anywhere here.
    # That matters because `_print_strays` offers `strays[0]` as the store to point
    # AGENTX_INCIDENT_DB at, so an unearned claim of recency is load-bearing copy. Size is
    # the honest proxy: the store with the most data in it is the one a developer is looking
    # for, and it needs no extra stat call.
    found.sort(key=lambda s: s["bytes"], reverse=True)
    return found


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
            # `, rowid DESC` is the same rule as the run rollup below and as the store's own
            # readers: created_at is caller-supplied and NOT unique, so ordering on it alone
            # leaves ties to SQLite -- and under a LIMIT that means the newest of two blocks
            # written in the same instant can be the one dropped from `agentx review`.
            cur = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (int(limit),))
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
                "ORDER BY created_at DESC, rowid DESC", (escaped + "%",))
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


# --- recovery readout (BACKLOG P-59) -------------------------------------------------
# This lives on the SDK side ON PURPOSE. It is a READ over the local incident store, and the
# reader is `agentx insights`, which already opens that exact file (see incident_db_census).
# Putting it here is not a new coupling and not a new thing published -- it is the same
# coupling that already ships. The gateway WRITES this data; nothing in the gateway reads it.
#
# 🔴 SECOND COPY OF A CLOSED VOCABULARY. The gateway owns _DOMAIN_TAG_VOCAB and this is a
# duplicate of it, which drifts by construction -- a KEEP IN SYNC comment is not a guard. The
# guard is the cross-surface recovery-vocabulary tripwire, which fails when the two diverge.
# The vocabulary is what stops a drifting tag becoming a real-looking action class and
# inflating whichever group it lands in.
_DOMAIN_TAG_VOCAB = frozenset({
    "database", "network", "agent-loop", "output", "general",
    "cost", "cost / ops", "comms", "supply-chain", "filesystem",
})


# Below this many blocks a rate is NOT REPORTED. Three blocks and one recovery is not "33%",
# it is noise wearing a percentage, and a percentage is what gets quoted.
#
# 🔴 ONE CONSTANT, NOT TWO THAT HAPPEN TO AGREE. P-97 added db._RATE_MIN_SAMPLE for the
# status screen and the session summary, encoding this identical rule at the identical value
# in a second file. Two copies of a threshold do not disagree on the day they are written;
# they disagree the day someone tunes one of them, and then two screens report different
# floors for the same ratio and neither is wrong on its own. Aliased rather than re-declared,
# so editing the source constant is the only way to change either. (db imports only
# sqlite3/time/os, so this cannot cycle.)
#
# ⚠️ THE ALIAS BINDS ONCE, AT IMPORT. An earlier version of this comment said "there is
# nothing to keep in sync", which overstates it: monkeypatching db._RATE_MIN_SAMPLE at
# RUNTIME does not move this name, and `recovery_summary`'s default argument below binds it
# a second time at def-time. That only matters to a test that patches one and asserts on the
# other; for shipped code the value has exactly one source.
from .db import _RATE_MIN_SAMPLE as RECOVERY_MIN_SAMPLE  # noqa: E402

# 🔴 THE PER-COACHING FLOOR IS SEPARATE AND HIGHER, and criterion 11 asks for it by name for a
# reason the per-class floor does not face: the rewrite queue is ranked ASCENDING, so the groups
# with the fewest observations are exactly the ones that float to the top. "A coaching item with
# three uses and no recoveries would top the rewrite queue on pure noise."
#
# Where 20 comes from, stated so the next person can argue with it rather than guess: with 20
# settled blocks and zero continuations, the one-sided 95% bound on the true rate is about 14%,
# which is low enough to act on. At 10 the same observation only bounds it at about 26% -- a
# coaching item that works a quarter of the time is not a rewrite candidate, and at that floor we
# could not tell the two apart. It is a JUDGEMENT about how much evidence justifies rewriting a
# piece of text, not a derived constant, and it gates an ACTION rather than a display.
COACHING_MIN_SAMPLE = 20

# The outcome vocabulary, READ side. The gateway owns the write-side copy
# (incident_store._OUTCOME_NEXT_VOCAB) and enforces it on write; this side must still classify
# defensively, because a store can be written by a NEWER gateway than the SDK reading it. A
# value we do not recognise is counted as exactly that -- never bucketed by prefix match, which
# would quietly fold a future `recovered_but_slower` into `recovered` and move the headline
# rate. Guarded by the cross-surface recovery-vocabulary tripwire.
_RECOVERED_OUTCOMES = frozenset({"recovered", "recovered_continued", "recovered_stopped"})
# 🔴 A HUMAN APPROVAL IS NOT A RECOVERY and must never reach the recovery rate: our coaching did
# not produce it, a person did. Deliberately OUTSIDE _RECOVERED_OUTCOMES, and the rows carrying
# it are lifted out of the per-class table entirely and reported on their own line.
_ESCALATION_OUTCOMES = frozenset({"approved_and_proceeded"})
# Mirrors incident_store._HUMAN_APPROVAL_STATUSES; pinned by the parity test.
_HUMAN_APPROVAL_STATUSES = frozenset({"ESCALATED"})
_SETTLED_OUTCOMES = (frozenset({"reblocked", "no_further_activity"})
                     | _RECOVERED_OUTCOMES | _ESCALATION_OUTCOMES)

# 🔴 THE SCOREBOARD'S BUCKETS, NAMED RATHER THAN SPELLED INLINE. `coaching_scoreboard` is a near
# copy of `recovery_summary`'s counting loop, and the first cut hardcoded these four strings while
# the original classified through the constants above. That is the drift class
# `test_recovery_summary_vocab_parity.py` exists for, and the parity test could not see it: it
# pins _SETTLED_OUTCOMES against the gateway's vocabulary and never reaches this function. Add a
# seventh outcome to BOTH vocabularies and the parity test stays green, the per-class table counts
# it, and every block carrying it silently lands in `unrecognised` here -- dropping out of
# `observed`, which is the denominator that ranks the rewrite queue.
#
# Splitting the recovered family is a JUDGEMENT per value, not something derivable from the
# vocabulary, so completeness is asserted by a test instead:
# test_coaching_scoreboard.py::test_every_known_outcome_lands_in_a_named_bucket.
_CONTINUED_OUTCOME = "recovered_continued"      # took the advice AND carried on working
_STOPPED_OUTCOME = "recovered_stopped"          # took the advice and the run ended
_PROVISIONAL_OUTCOME = "recovered"              # not yet split by refine_recoveries
_RESIDUAL_OUTCOME = "no_further_activity"       # we saw nothing more; evidence of neither
_OBSERVED_FAILURE_OUTCOMES = frozenset({"reblocked"})

# Statuses the settling sweep may touch: exactly the ones that join the block -> retry chain in
# the gateway (park_incident's `_chainable`). 🔴 ESCALATED IS DELIBERATELY ABSENT and that
# exclusion is the fix for a real defect: an escalation waits on a HUMAN, not on a timer, so a
# 15-minute sweep settled "no further activity" onto a block whose approver was at lunch --
# and because the settle writes an outcome, the genuine recovery that arrived when they got
# back could no longer land (first-write-wins). A residual we invented outranked an observation
# we made. Escalations stay open until something real happens to them.
_SETTLEABLE_STATUSES = frozenset({"CHALLENGED", "DENIED"})

# How long a run must be quiet before an unresolved block settles.
# 🔴 A PARAMETER THAT CHANGES EVERY NUMBER IT HAS EVER PRODUCED. A shorter window settles more
# blocks as "nothing more happened"; a longer one leaves them open. Stamp it wherever these
# counts are shown and treat a change to it the way a rubric change is treated -- results
# computed under different windows are not comparable.
SETTLE_AFTER_SECONDS = 900  # 15 minutes


# How long a read-time pass waits for a writer before giving up. The gateway uses 250ms on the
# hot ALLOW path; this side is a human running `agentx insights`, so it can afford to wait.
_STORE_BUSY_WAIT_SECONDS = 2.0


def _connect_incident_store(path):
    """A connection that WAITS for a writer instead of failing instantly.

    🔴 THE SWEEPS RUN WHILE THE GATEWAY IS UP -- that is the normal case, not the edge one:
    `agentx insights` reads the same file the running gateway writes on every block and every
    allowed call. SQLite fails a write against a held lock in milliseconds. Every OTHER store
    function in this module already returns a neutral value on ``sqlite3.Error`` ("Missing store
    / locked DB -> []"); the three added for P-59 did not, so a locked store took `agentx
    insights` down with a traceback -- the readout killed by the writer it reads. Reproduced by
    holding a ``BEGIN IMMEDIATE`` on the store: ``OperationalError: database is locked`` out of
    both sweeps. Waiting is how most of those stop happening; the caller swallows the rest.
    """
    return sqlite3.connect(path, timeout=_STORE_BUSY_WAIT_SECONDS)


def _observation_window(conn):
    """(since, allowed_calls) — when we started watching BOTH sides, and how many calls we let
    through since. ``(None, 0)`` when we have never watched.

    A run gets an activity row from its first ALLOWED call and also from its first BLOCK, so
    this is the earliest moment this build could have seen either half. Everything downstream --
    the rate, the per-class counts, the sweeps -- is scoped to it.
    """
    try:
        row = conn.execute(
            "SELECT MIN(first_seen), SUM(allowed_calls) FROM run_activity").fetchone()
    except sqlite3.Error:
        return None, 0            # a store predating the table: no data, not zero
    since, allowed = (row or (None, None))
    if not since:
        return None, 0
    return since, (allowed or 0)


def settle_stale_blocks(older_than_seconds=SETTLE_AFTER_SECONDS, db_path=None, now=None):
    """Settle blocks that never saw a qualifying allow to ``no_further_activity``.

    Without this, every unresolved block sits at NULL forever and the buckets never add up:
    "still open" and "nothing more happened" are indistinguishable, so no readout can be built
    on them. Lazy and idempotent like ``reconcile_safe_paths``, and called from the same place
    for the same reason -- at READ time, immediately before the readout that consumes it.

    🔴 IT LIVES HERE, BESIDE ITS READER, BECAUSE IT SHIPPED WITH NO CALLER AT ALL. The first
    cut put both sweeps in the gateway's incident store, which the SDK cannot import
    and the gateway never called -- so nothing settled in any real deployment, `open` never
    drained, and "N blocks recorded, none settled yet" was the permanent state for every user
    whose agents never recovered. The readout printed that sentence as though it were news.

    🔴 THIS BUCKET IS A RESIDUAL, NOT A MEASUREMENT, and the readout must print it that way.
    "We saw nothing more" covers an agent that gave up, a run that finished the job another
    way, and a process that crashed. It is not a failure count, and calling it one would be
    the flattering reading. A zero must earn its meaning.

    🔴 SCOPED TO THE OBSERVATION WINDOW. A row older than the first activity we ever recorded
    was written by a build that could not observe what came next, so settling it would stamp
    "we saw nothing further" onto a period we were not watching -- 38,561 of them on the real
    dev store, permanently, in a column the readout then counts. Outside the window a block
    stays NULL, which already means the honest thing: we do not know.

    ⚠️ A ROW WE CANNOT DATE IS LEFT ALONE. ``created_at`` is normally our own ISO-8601 UTC
    stamp, but ``save_incident`` accepts a caller-supplied value, so an unparseable one is
    possible. Settling it would be claiming an observation we did not make.

    🔴 THE RUN MUST BE QUIET, NOT MERELY THE BLOCK OLD, and the two are different rows. The
    first cut compared only ``incidents.created_at`` against the cutoff, so a run that was
    blocked 20 minutes ago and is STILL MAKING ALLOWED CALLS RIGHT NOW had that block stamped
    "no further activity" -- a claim the store's own ``run_activity.last_seen`` contradicts, on
    the same read. And because settling writes an outcome, first-write-wins then stopped the
    genuine recovery from ever landing when the slow retry arrived. That is exactly the defect
    the ESCALATED exclusion above was written for, reproduced through a different door: a
    residual we invented outranking an observation we were about to make. The parameter is
    named for how long a run must be QUIET; now it is measured that way.

    Only rows whose ``outcome_next`` IS NULL are touched, so a resolved recovery is never
    overwritten by a later sweep. Returns the count settled this pass.

    Never raises: a locked or unreadable store returns 0, the same neutral answer every other
    store function in this module gives (see ``_connect_incident_store``).
    """
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return 0
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(seconds=older_than_seconds)
    try:
        conn = _connect_incident_store(p)
    except sqlite3.Error:
        return 0
    stale = []
    try:
        since, _ = _observation_window(conn)
        if not since:
            return 0            # never watched: nothing here is settleable
        try:
            rows = conn.execute(
                "SELECT receipt_id, created_at, trace_id FROM incidents "
                "WHERE outcome_next IS NULL AND created_at >= ? "
                "AND COALESCE(parked_status, status) IN (%s)"
                % ",".join("?" * len(_SETTLEABLE_STATUSES)),
                (since,) + tuple(sorted(_SETTLEABLE_STATUSES)),
            ).fetchall()
        except sqlite3.Error:
            return 0            # a store predating the column: nothing to settle, not an error
        for receipt_id, created_at, trace_id in rows:
            created = _parse_iso(created_at)
            if created is None:
                continue        # undateable -> leave open, see the docstring
            if created >= cutoff:
                continue        # the block itself is too fresh to have gone quiet
            # The run's own record. NULL last_seen (a run we only ever blocked) is silence, not
            # activity, so it settles. A last_seen INSIDE the window is the run demonstrably
            # still going: leave it open, because "we saw nothing more" would be false and
            # would permanently pre-empt the recovery that has not arrived YET.
            seen = _parse_iso(_last_seen(conn, trace_id)) if trace_id else None
            if seen is not None and seen >= cutoff:
                continue
            stale.append(receipt_id)
        if not stale:
            return 0
        stamp = _now_iso()
        # rowcount, NOT len(stale). The UPDATE carries `AND outcome_next IS NULL`, so a row that
        # recovered between the SELECT above and this write is deliberately skipped -- and that
        # race is real enough to have its own test. Reporting candidates SELECTED as though they
        # were rows SETTLED made the returned count wrong in exactly the case the guard exists
        # for: the one time the two numbers differ is the one time anyone would be looking.
        settled = conn.executemany(
            "UPDATE incidents SET outcome_next = 'no_further_activity', outcome_next_at = ? "
            "WHERE receipt_id = ? AND outcome_next IS NULL",
            [(stamp, r) for r in stale],
        ).rowcount
        conn.commit()
    except sqlite3.Error:
        # A locked store loses this pass, not the command. The sweep is idempotent and runs
        # again on the next read, so nothing is lost permanently.
        return 0
    finally:
        conn.close()
    return settled


def refine_recoveries(older_than_seconds=SETTLE_AFTER_SECONDS, db_path=None, now=None):
    """Turn the provisional ``recovered`` into ``recovered_continued`` / ``recovered_stopped``.

    The gateway records the FACT of a recovery the moment it happens; it cannot know yet whether
    the run went on to do anything. This pass answers that from run activity, and it is the ONLY
    defence against the improvement loop learning the wrong lesson: the easiest way to score well
    on "the next call was allowed" is to suggest something trivially safe that does not
    accomplish what the user wanted. A run that takes our suggestion and then stops is the tell.

    🔴 A RECENT RECOVERY MUST NOT BE CLASSIFIED. The recovering call records activity BEFORE the
    resolution is written, so immediately afterwards ``last_seen`` is always just BEHIND
    ``outcome_next_at`` -- classifying then would mark every fresh recovery "stopped", a
    systematic error pointing at the unflattering answer for a reason that is pure timing. Only
    recoveries older than the quiet window are refined.

    Lazy like ``settle_stale_blocks`` and called beside it. Idempotent: only rows still reading
    exactly ``recovered`` are touched, so a refined row is final. Returns (continued, stopped).

    Never raises: a locked or unreadable store returns (0, 0), the same neutral answer every
    other store function in this module gives (see ``_connect_incident_store``).
    """
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return 0, 0
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(seconds=older_than_seconds)
    try:
        conn = _connect_incident_store(p)
    except sqlite3.Error:
        return 0, 0
    moved = {"recovered_continued": 0, "recovered_stopped": 0}
    continued, stopped = [], []
    try:
        try:
            rows = conn.execute(
                "SELECT receipt_id, trace_id, outcome_next_at FROM incidents "
                "WHERE outcome_next = 'recovered'").fetchall()
        except sqlite3.Error:
            return 0, 0         # a store predating the column
        for receipt_id, trace_id, resolved_at in rows:
            resolved = _parse_iso(resolved_at)
            if resolved is None:
                continue        # undateable -> leave provisional, same rule as the settle sweep
            if resolved >= cutoff:
                continue        # too recent to judge; see the docstring
            seen = _parse_iso(_last_seen(conn, trace_id)) if trace_id else None
            if seen is None:
                # 🔴 NO ACTIVITY RECORD IS EVIDENCE LOSS, NOT EVIDENCE OF STOPPING, and this
                # branch used to stamp `recovered_stopped` on it. The justification given was
                # "a run that only ever got blocked has no activity row" -- and that state is
                # UNREACHABLE for a row being refined here: every row in this loop reads
                # `recovered`, which only the ALLOW path writes, and that path calls
                # record_run_activity FIRST. save_incident writes a row for a block too.
                #
                # So the reachable causes are a FAILED or locked activity write (already
                # counted as run_activity_write_failures) and a NULL trace_id. Both mean we
                # lost the record, and turning that into `recovered_stopped` feeds our own
                # recording failure into the improvement loop as "this advice was safe and
                # useless" -- which is the signal the rewrite queue is RANKED on. It would
                # demote working coaching on the strength of a dropped write.
                #
                # Left provisional. `recovered` still counts as a recovery in the readout; only
                # the continued/stopped split stays unknown, which is the honest state.
                continue
            # STRICT. Activity at the SAME instant as the recovery is the recovering call
            # itself, which is not the run carrying on -- counting it would inflate the one
            # number the improvement loop ranks on, on nothing but timer granularity.
            (continued if seen > resolved else stopped).append(receipt_id)
        # rowcount, NOT len(ids) -- the SAME rule the settle sweep beside this was fixed for.
        # 🔴 That fix landed on ONE member of the class and left its sibling: both sweeps
        # SELECT then UPDATE behind a guard, so both can have a row move underneath them,
        # and both reported candidates as though they were rows changed. Fixing the
        # instance left the template standing.
        for outcome, ids in (("recovered_continued", continued), ("recovered_stopped", stopped)):
            if ids:
                moved[outcome] = conn.executemany(
                    "UPDATE incidents SET outcome_next = ? "
                    "WHERE receipt_id = ? AND outcome_next = 'recovered'",
                    [(outcome, r) for r in ids],
                ).rowcount
        conn.commit()
    except sqlite3.Error:
        # A locked store loses this pass, not the command. Idempotent, so the next read
        # refines the same rows.
        return 0, 0
    finally:
        conn.close()
    return moved["recovered_continued"], moved["recovered_stopped"]


def _last_seen(conn, trace_id):
    try:
        row = conn.execute(
            "SELECT last_seen FROM run_activity WHERE trace_id = ?", (trace_id,)).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def _parse_iso(value):
    """A tz-aware datetime, or None for anything we cannot date. Never raises: an unparseable
    stamp must leave a row alone, not take down the command doing the reading."""
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def recovery_summary(path=None, min_sample=RECOVERY_MIN_SAMPLE):
    """Aggregate what happened after our blocks. The readout half of P-59.

    Grouped by ``domain_tag`` -- the row's validated, closed-vocab action dimension. 🔴 THE
    BLENDED FIGURE MUST NEVER BE SHOWN ALONE: "our advice on destructive writes works and our
    advice on network calls does not" is a work item; "62%" is a fact nobody can act on. Every
    group carries ``readable``; a caller that prints a rate for an unreadable group is the bug
    this flag exists to prevent.

    Also returns a RUN-level rollup, because the per-block view answers a different question
    than the one anyone asks. Blocked, blocked again, then through is two per-block rows and
    one honest sentence: the run finished. Keep both; do not collapse them.

    🔴 EVERY COUNT HERE IS SCOPED TO THE OBSERVATION WINDOW, and they all use the SAME one.
    The first cut windowed only ``block_rate`` and left the per-class counts running over all
    history. On the real dev store that is 38,561 blocks written by a build that could not
    record an outcome, so the headline would have read "38561 settled, 3 recovered (0%)" -- the
    exact asymmetry the rate's window exists to prevent, one function away from it. Blocks
    outside the window are reported separately as ``blocks_before_window``, never mixed in.

    🔴 ``block_rate`` IS THE FIGURE THAT MUST NEVER BE OMITTED. Criterion 14: a recovery rate is
    never displayed without it, because the two fastest ways to raise recovery are to block more
    loosely and to suggest something trivially safe, and only this shows the first. It is
    computed from ``run_activity``, the allowed-call record this change added. ``None`` means we
    cannot compute it, which is never zero.

    ``state`` distinguishes the silences a single ``None`` used to collapse:
      ``ok``            counts below are real
      ``not_upgraded``  this store predates the outcome columns; the gateway adds them on its
                        next write. ``blocks_all_time`` is still true and may be enormous, so
                        "no blocks recorded yet" would be a false statement about it.
      ``no_window``     upgraded, but nothing was recorded while we were watching both sides.

    ``open`` counts blocks still awaiting an outcome; it is not a bucket of anything that
    happened. Callers should run ``settle_stale_blocks`` / ``refine_recoveries`` first -- the
    CLI does.
    """
    p = _incident_db_path(path)
    if not os.path.exists(p):
        return None
    try:
        conn = _connect_incident_store(p)
    except sqlite3.Error:
        return None             # unopenable store: no data, never a zero
    try:
        try:
            # ASKED, not inferred from a failure. The first cut detected "this store predates
            # the outcome columns" by catching the error from selecting them -- but a legacy
            # store has no run_activity table either, so the window came back empty and the
            # query was skipped before it could fail. The detector could never fire on the one
            # store it was written for. A schema question deserves a schema query.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
            if not columns:
                return None             # no incidents table: not one of our stores
            all_time = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        except sqlite3.Error:
            # sqlite3.Error, not OperationalError: a corrupt file raises DatabaseError (the
            # PARENT), and the narrow catch crashed `agentx insights` outright.
            return None
        if not all_time:
            return None
        if "outcome_next" not in columns:
            # 🔴 "PREDATES THE COLUMNS" AND "NO BLOCKS" ARE DIFFERENT SILENCES. Both used to
            # return None, and the CLI printed "No blocks recorded yet" for both -- a sentence
            # that is FALSE about a store holding tens of thousands of blocks. The GATEWAY owns
            # the schema and adds missing columns when it writes; this side only reads.
            return {"state": "not_upgraded", "blocks_all_time": all_time,
                    "min_sample": min_sample}
        since, allowed = _observation_window(conn)
        try:
            # `rowid` is SELECTED because it is the tie-break that decides which block ENDED a
            # run when two share a created_at -- see the `max()` key below, which is the line
            # that actually decides it. The ORDER BY does NOT: `max()` returns the FIRST
            # maximal element, so an ordered scan without that key would pick the EARLIEST of
            # a tie, which is deterministic and wrong. It is here only so the scan this
            # function reads is reproducible (P-85).
            rows = conn.execute(
                "SELECT domain_tag, outcome_next, trace_id, created_at, "
                "COALESCE(parked_status, status), rowid FROM incidents "
                "WHERE created_at >= ? ORDER BY created_at, rowid",
                (since,)).fetchall() if since else []
            # 🔴 COUNTED, NOT INFERRED BY SUBTRACTION. `created_at >= ?` silently drops a row
            # whose stamp is NULL (a NULL comparison is NULL, never true), and deriving the
            # pre-window figure as all_time minus what survived then reported those rows as
            # "recorded before we started tracking" -- which is not something we know about a
            # row we cannot date at all. Same fabrication as the escalation subtraction, one
            # column over. Asking directly keeps undateable rows out of BOTH buckets.
            before_window = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE created_at < ?", (since,)
            ).fetchone()[0] if since else 0
        except sqlite3.Error:
            # Belt and braces, and NOT dead code: the schema check above answers "does this
            # store have the outcome columns", which is a different question from "can this
            # file be read". A corrupt page raises DatabaseError here and would otherwise take
            # down `agentx insights` -- the crash finding 3 was filed for, reintroduced by
            # replacing the catch with a check that does not cover the same case.
            return None
    finally:
        conn.close()

    def _blank():
        return {"blocks": 0, "recovered": 0, "reblocked": 0,
                "no_further_activity": 0, "open": 0, "unrecognised": 0}

    def _count(bucket, outcome):
        bucket["blocks"] += 1
        if outcome is None:
            bucket["open"] += 1
        elif outcome in _RECOVERED_OUTCOMES:
            bucket["recovered"] += 1
        elif outcome in ("reblocked", "no_further_activity"):
            bucket[outcome] += 1
        else:
            # 🔴 An outcome we do not recognise used to fall through every branch while still
            # incrementing `blocks`, so it inflated `settled` -- the rate's DENOMINATOR -- and
            # landed in no bucket anyone could see. Vocabulary is enforced on write, which is
            # exactly why a value arriving here means something drifted, and a silent dilution
            # of the headline rate is the worst possible way to learn that.
            bucket["unrecognised"] += 1

    by_class, overall, runs = {}, _blank(), {}
    # 🔴 HUMAN APPROVALS ARE LIFTED OUT BEFORE ANYTHING IS COUNTED. An escalation is a block a
    # PERSON released, so "the next call was allowed" says nothing about our coaching -- and the
    # spec is explicit that approvals get their own counter and are never folded into the
    # recovery rate. Measured before this: twelve blocks our coaching recovered NONE of, plus
    # one human approval, printed 8%, and every point of it was the human.
    #
    # TWO signals, because each covers the other's blind spot. The OUTCOME is authoritative once
    # written (first-write-wins, so it stays true), but it exists only after the approval is
    # acted on. The PARKED status covers the ones still WAITING on a person -- `status` itself
    # cannot, because the middleware overwrites it on recovery, which is the bug parked_status
    # was added for. Falls back to `status` only for rows written before that column existed.
    escalations = {"total": 0, "proceeded": 0, "open": 0, "closed_other": 0}
    for domain_tag, outcome, trace_id, created_at, parked, rowid in rows:
        if parked in _HUMAN_APPROVAL_STATUSES or outcome in _ESCALATION_OUTCOMES:
            # 🔴 KEYED ON WHAT IT WAS, WHATEVER THE OUTCOME SAYS. The first cut only
            # consulted `parked` when the outcome was still NULL, so an escalation that
            # already carried an outcome fell straight through into the recovery table --
            # and the shipped-but-inert version of the redirect wrote a plain `recovered`
            # onto exactly those rows. Every one of them predating that fix was counted as
            # our coaching working. Reproduced: twelve blocks recovered NONE of, plus one
            # legacy row, printed 8% again.
            escalations["total"] += 1
            if outcome is None:
                escalations["open"] += 1
            elif outcome in _ESCALATION_OUTCOMES or outcome in _RECOVERED_OUTCOMES:
                # `recovered` here is a LEGACY row: written before the redirect existed.
                escalations["proceeded"] += 1
            else:
                # Settled some other way -- a timer reached it before the sweep excluded
                # escalations. Neither proceeded nor waiting, and never a recovery.
                escalations["closed_other"] += 1
            continue
        # An unknown or absent domain is its OWN named group, never folded into a real one:
        # a silent merge would let a drifting tag inflate whichever class it landed in.
        key = domain_tag if domain_tag in _DOMAIN_TAG_VOCAB else "(unclassified)"
        _count(by_class.setdefault(key, _blank()), outcome)
        _count(overall, outcome)
        if trace_id:
            runs.setdefault(trace_id, []).append((created_at or "", rowid, outcome))

    for bucket in list(by_class.values()) + [overall]:
        # SETTLED blocks are the only denominator a rate may use. An open block has not happened
        # yet, and counting it as a non-recovery reports a pessimistic rate that improves on its
        # own as the sweep runs. An unrecognised one is not a settled outcome either -- we have
        # no idea what it is.
        bucket["settled"] = bucket["blocks"] - bucket["open"] - bucket["unrecognised"]
        bucket["readable"] = bucket["settled"] >= min_sample

    # Run level: of the runs that hit at least one block, how many ended on a recovery.
    #
    # 🔴 SORT ON (created_at, rowid) — NEVER on the timestamp alone, and NEVER on the whole
    # tuple (P-85). The two failure modes it is threading between:
    #
    #   whole tuple    falls through to comparing the OUTCOME when two incidents on a run
    #                  share a created_at, and an unresolved outcome is None. `None < str`
    #                  raises TypeError and kills `agentx insights`.
    #   timestamp only was the fix for that, and it made ties ARBITRARY: `max()` returns
    #                  whichever equal element it met first, so which block "ended" the run
    #                  depended on row order. Measured: the same two-block run reported
    #                  ended_on_a_recovery as 0 or 1 across identical runs, 4 failures in 5.
    #
    # `rowid` is monotonic, always present, never NULL, and needs no coercion, so it gives a
    # TOTAL order that cannot raise. created_at is caller-supplied via save_incident and
    # /v1/incident pins its own values, so same-second blocks on one trace are ordinary
    # traffic, not a test artifact.
    # 🔴 THE DENOMINATOR IS SETTLED RUNS, NOT RUNS. This gate counted every run that hit a
    # block, unlike every other denominator in this function, which uses `settled`. A run whose
    # last block is still OPEN has not finished or failed to finish -- it has not happened yet.
    # Counting it printed "15 runs hit a block - 0 finished after their last one", where the
    # zero was partly pure absence, and it would improve on its own as the sweep ran. Same rule
    # the per-class table follows: a zero must earn its meaning.
    finished = settled_runs = 0
    for events in runs.values():
        last = max(events, key=lambda e: (e[0], e[1]))[2]
        if last not in _SETTLED_OUTCOMES:
            continue            # still open, or an outcome this version cannot read
        settled_runs += 1
        if last in _RECOVERED_OUTCOMES:
            finished += 1
    # 🔴 AN ESCALATION IS A CALL WE STOPPED, so it belongs in the BLOCK rate even though it
    # is kept out of the RECOVERY table. Removing it from both sides of this ratio made the
    # rate read LOW -- measured 0.333 where the true share of stopped calls was 0.500 --
    # and "we interfere less than we do" is the flattering direction. The two questions are
    # different: "how often do we stop a call" counts every stop; "does our coaching work"
    # counts only the ones coaching could have acted on.
    stopped = overall["blocks"] + escalations["total"]
    observed = stopped + allowed
    return {
        "state": "ok" if since else "no_window",
        "by_class": by_class,
        "overall": overall,
        # Its OWN counter, per the spec, never folded into the recovery rate above.
        "escalations": escalations,
        "runs": {"with_a_block": len(runs), "settled": settled_runs,
                 "ended_on_a_recovery": finished,
                 "readable": settled_runs >= min_sample},
        # 🔴 NEVER SHOW THE RECOVERY RATE WITHOUT THIS BESIDE IT. The two fastest ways to raise
        # recovery are to block more loosely and to suggest something trivially safe; the first
        # is visible only here. None means we cannot compute it, which is NOT zero.
        #
        # ⚠️ KNOWN BIAS, and it points the safe way. An allowed call arriving without a trace id
        # is not recorded, so the denominator can undercount allows, which makes the rate read
        # HIGH. Erring toward "we block more than we do" does not flatter us.
        "block_rate": (stopped / observed) if since and observed >= min_sample else None,
        "block_rate_since": since,
        "allowed_calls": allowed,
        # Written before we were watching what came next. Reported, never mixed in: they cannot
        # have recovered, and folding them into the counts would drive the headline to zero.
        "blocks_all_time": all_time,
        # 🔴 MINUS THE ESCALATIONS TOO. They are lifted out before anything is counted, so
        # they never reach overall["blocks"] -- and subtracting only that reported every
        # in-window human approval to the user as an EARLIER, pre-tracking block. A store
        # holding escalations printed a fabricated "N earlier block(s)" line.
        "blocks_before_window": before_window,
        # Rows we cannot date at all. Neither in the window nor before it: claiming
        # either would be an observation we did not make.
        "blocks_undateable": all_time - overall["blocks"] - escalations["total"]
                             - before_window,
        "settle_window_seconds": SETTLE_AFTER_SECONDS,
        "min_sample": min_sample,
    }


def coaching_scoreboard(path=None, min_sample=COACHING_MIN_SAMPLE):
    """Score every piece of coaching we hand an agent. Criteria 11 and 12 of P-59.

    ``recovery_summary`` answers "does our advice work HERE" (by action class). This answers
    "does THIS PIECE OF TEXT work", which is the half that compounds: the low scorers become a
    rewrite queue, the rewrite ships as a new version, and the new version is measured against
    the old one. Detection is automatic; the rewrite is a person's job.

    Grouped by ``(policy_id, coaching_version)``. Identity is ``policy_id`` -- there is
    deliberately no second coaching id in the ledger -- and the version is stamped at PARK
    time, so a rewrite of OUR canonical coaching starts a fresh score with no flag for anyone to
    remember to set. That is the spec's "a score goes provisional when its coaching text changes
    version": the old text keeps its history, the new text has none yet and reads as such.

    🔴 THAT HOLDS FOR CANONICAL COACHING ONLY, AND AN EARLIER VERSION OF THIS DOCSTRING CLAIMED IT
    UNCONDITIONALLY. ``coaching_version`` is ``POLICY_BASELINE_VERSION``, a BUILD stamp bumped when
    ``CANONICAL_COACHING_BY_FAILURE_MODE`` / ``_GATEWAY_BLOCK_SAFE_PATHS`` change (the gateway, which
    says so in its own comment). A developer-customised policy and a judge-authored
    ``socratic_prompt`` carry the generation they were ISSUED under, not one we wrote -- so if a
    developer edits their own coaching text, the version does NOT move and the new text is scored
    in the SAME group as the text it replaced. Exactly the inheritance the rest of this paragraph
    says cannot happen, in exactly the org-adaptive case the loop exists for. Nothing here detects
    it; the honest statement is that the boundary is OUR release, not THEIR edit.

    🔴 THE SCORE IS ``recovered_continued`` ALONE (criterion 12). The obvious metric -- "the next
    call was allowed" -- rewards advice that is safe and useless, because the easiest way to earn
    it is to suggest something trivially permitted that does not do what the user wanted.
    ``recovered_stopped`` is the tell for exactly that, so it is reported BESIDE the score and
    never added into it. A rising stopped share on a group whose score looks fine is the shape to
    watch.

    🔴 A PROVISIONAL ``recovered`` IS NOT SETTLED HERE, and this is the denominator trap in this
    function. The gateway records the FACT of a recovery immediately; only ``refine_recoveries``
    can later say whether the run went on to do anything. Counting an unrefined row as settled
    puts it in the denominator and never in the numerator, so a run that is still going would
    read as "this advice does not work". They are counted as ``refining`` and excluded from both
    sides. Callers should run the sweeps first; the CLI does.

    🔴 HUMAN APPROVALS ARE LIFTED OUT BEFORE ANYTHING IS COUNTED, on the same rule and for the
    same reason as ``recovery_summary``: a person released that block, not our text, so scoring
    our coaching on it credits the wrong author.

    🔴 THE DENOMINATOR IS ``observed``, NOT ``settled``, and the difference is most of the store.
    A block that settles to ``no_further_activity`` tells us nothing about the advice -- see the
    comment on that line, which records what the first version of this printed against real
    data.

    Returns ``None`` for a store we cannot read, and a ``state`` of ``not_upgraded`` /
    ``no_window`` for the two silences that are not "nothing recovered" -- the distinction
    ``recovery_summary`` exists to keep, kept here too rather than collapsed back into a zero.
    """
    p = _incident_db_path(path)
    if not os.path.exists(p):
        return None
    try:
        conn = _connect_incident_store(p)
    except sqlite3.Error:
        return None
    try:
        try:
            # ASKED, not inferred from a failed SELECT -- same reason as recovery_summary: a
            # store predating the columns has no run_activity either, so the window comes back
            # empty and the query that would have raised is never reached.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
            if not columns:
                return None
            all_time = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        except sqlite3.Error:
            return None
        if not all_time:
            return None
        if "outcome_next" not in columns or "coaching_version" not in columns:
            return {"state": "not_upgraded", "blocks_all_time": all_time,
                    "groups": [], "rewrite_queue": [], "min_sample": min_sample}
        since, _allowed = _observation_window(conn)
        try:
            rows = conn.execute(
                "SELECT policy_id, coaching_version, outcome_next, "
                "COALESCE(parked_status, status) FROM incidents "
                "WHERE created_at >= ?", (since,)).fetchall() if since else []
        except sqlite3.Error:
            return None
    finally:
        conn.close()

    def _blank(policy_id, version):
        return {"policy_id": policy_id, "coaching_version": version, "blocks": 0,
                "continued": 0, "stopped": 0, "reblocked": 0, "no_further_activity": 0,
                "refining": 0, "open": 0, "unrecognised": 0}

    groups = {}
    for policy_id, version, outcome, parked in rows:
        if parked in _HUMAN_APPROVAL_STATUSES or outcome in _ESCALATION_OUTCOMES:
            continue
        # A row with no coaching identity is its OWN named group, never folded into a real one.
        # Folding it would let unattributed blocks drag down a real piece of text's score, and
        # the size of this group is itself the finding -- it is what P-66 caught for domain_tag.
        key = (policy_id or "(no policy id)", version or "(no version)")
        g = groups.get(key) or groups.setdefault(key, _blank(*key))
        g["blocks"] += 1
        if outcome is None:
            g["open"] += 1
        elif outcome == _CONTINUED_OUTCOME:
            g["continued"] += 1
        elif outcome == _STOPPED_OUTCOME:
            g["stopped"] += 1
        elif outcome == _PROVISIONAL_OUTCOME:
            g["refining"] += 1
        elif outcome in _OBSERVED_FAILURE_OUTCOMES:
            g["reblocked"] += 1
        elif outcome == _RESIDUAL_OUTCOME:
            g["no_further_activity"] += 1
        else:
            # Never bucketed by prefix match. A future `recovered_but_slower` folded into the
            # numerator by a startswith() would move a score that drives a rewrite decision.
            g["unrecognised"] += 1

    out = []
    for g in groups.values():
        g["settled"] = (g["blocks"] - g["open"] - g["refining"] - g["unrecognised"])
        # 🔴 THE RESIDUAL IS NOT IN THE DENOMINATOR, AND THIS WAS FOUND BY RUNNING THE READOUT,
        # not by reviewing it. `no_further_activity` means "we saw nothing more" -- an agent that
        # gave up, a run that finished the job another way, or a crashed process. It is the one
        # bucket the spec insists is a residual rather than a measurement, and on the dev store
        # it is 80% of every settled block. (The DEV store, not production: the suites write into
        # `agentx_sdk/.agentx/incidents.db`, so it is part traffic and part test output. It shows
        # the SHAPE honestly -- a run that never retries settles to the residual whatever wrote it
        # -- but no count from it is a reading about customers.)
        # With the residual in the denominator the entire board read
        # `0 kept going (0%)` and the rewrite queue was really ranking "whose runs went quiet
        # most". Three coaching items were ranked as 0% rewrite candidates on 32, 51 and 21
        # blocks of which we observed the outcome of exactly NONE.
        #
        # So the score is over the outcomes we actually OBSERVED. `reblocked` stays in: being
        # blocked again after our advice is a real observation, and a damning one. `went_quiet`
        # is reported per group rather than folded away, because a coaching item whose runs
        # mostly vanish is a finding too -- just not this one.
        g["observed"] = g["continued"] + g["stopped"] + g["reblocked"]
        g["went_quiet"] = g["no_further_activity"]
        # The floor is on OBSERVED, not on blocks. A group with a thousand blocks and four
        # observations is the same amount of evidence as a group with four blocks.
        g["readable"] = g["observed"] >= min_sample
        # 🔴 None, NOT 0.0, for a group below the floor. A zero here would be indistinguishable
        # from a coaching item that genuinely never worked, and this number's whole job is to
        # order a queue -- an unreadable group rendered as 0.0 would sort straight to the top of
        # it, which is the precise failure criterion 11 exists to prevent.
        g["score"] = (g["continued"] / g["observed"]) if g["readable"] else None
        out.append(g)

    out.sort(key=lambda g: (-g["blocks"], g["policy_id"]))
    # Ascending by score: worst advice first, because that is the work item. Ties broken by MORE
    # evidence first, so a group scraping past the floor never outranks a well-observed one at
    # the same score.
    queue = sorted((g for g in out if g["readable"]),
                   key=lambda g: (g["score"], -g["observed"]))
    return {
        "state": "ok" if since else "no_window",
        "groups": out,
        "rewrite_queue": queue,
        "min_sample": min_sample,
        "window_since": since,
        "settle_window_seconds": SETTLE_AFTER_SECONDS,
        "blocks_all_time": all_time,
    }


def incident_db_census(db_path=None):
    """Diagnostic for ``agentx insights``: where the incident store is and how much
    of it is harvestable. Never raises — lets the CLI explain an empty result
    (wrong path? no recoveries? no judge?) instead of silently showing nothing.

    Returns ``{path, exists, complied, with_resolution, strays}``.

    ``strays`` lists other incident stores under the project root (BACKLOG P-76). It is
    populated ONLY when this store has no recovery data to show -- missing, empty, or
    predating the outcome columns. Those are precisely the states that print a SILENCE,
    and a silence is where a stray is the likely explanation ("No blocks recorded yet"
    said to someone whose gateway was filling a different file).

    ⚠️ Gated on ``with_resolution``, NOT on ``complied``. The store that caused this bug
    holds 4 rows and predates the outcome columns, so it has complied rows and still
    prints a silence; gating on complied would have skipped the scan in the one case
    that motivated it. A store with resolutions is the only one that needs no hint.

    An explicit ``db_path`` or ``AGENTX_INCIDENT_DB`` means the caller has already chosen
    a store, so no scan runs and no hint is printed.
    """
    p = _incident_db_path(db_path)
    info = {"path": p, "exists": os.path.exists(p), "complied": 0,
            "with_resolution": 0, "strays": []}
    chosen = bool(db_path) or bool(os.environ.get("AGENTX_INCIDENT_DB"))
    if not info["exists"]:
        if not chosen:
            info["strays"] = incident_db_strays(canonical=p)
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
    if not chosen and not info["with_resolution"]:
        info["strays"] = incident_db_strays(canonical=p)
    return info


def reviewable_items_with_truncation(db_path=None, cluster=True):
    """``(items, page_of_more)`` — the public form. ``page_of_more`` comes from the READ
    that was actually truncated, never from comparing two totals.

    Anything that prints a "showing N of M" must take the flag from here. Deriving it as
    ``total > REVIEW_READ_CAP`` looks equivalent and is not: adopt items are not subject to
    the cap, so five adopt items plus 198 pending blocks crosses the threshold while
    nothing was truncated at all."""
    return _reviewable_with_truncation(db_path, cluster)


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
    items, _ = _reviewable_with_truncation(db_path, cluster)
    return items


# The recency window for the two review reads. It is DELIBERATE: reviewable_items feeds
# count_reviewable, which runs at atexit for every protected session and must stay cheap.
# What was NOT deliberate is printing a saturated count as if it were a total -- see P-80.
REVIEW_READ_CAP = 200


def _incidents_by_verdict_state(limit, labelled, db_path=None):
    """``(rows, more_exist)`` -- blocks WITH a verdict (``labelled=True``) or WITHOUT one
    (``labelled=False``), newest first, the LIMIT applied to the rows that QUALIFY rather
    than to recent incidents in general.

    ONE function, not two near-copies, because both review reads have the same bug and a
    rule with two entry points gets fixed at one of them. ``agentx review`` and
    ``agentx review --labeled`` are the two members.

    🔴 THIS IS THE FIX FOR P-80's SECOND FACE. ``list_recent_incidents(200)`` then filtering
    in Python spends the window on rows that need no review, so 250 recently-labelled
    incidents in front of 50 unlabelled ones yields ZERO and the nudge disappears for a user
    with a real backlog. Filtering in SQL spends the window on the rows we want.

    Degrades on an older store rather than raising: the ``label_verdict`` column may not
    exist (this read predates it), in which case nothing is labelled -- so every blocking
    row is pending and NOTHING is labelled. Missing store / locked DB / no ``status``
    column -> ``([], False)``, the honest empty state every caller already renders."""
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return [], False
    statuses = sorted(_BLOCKING_STATUSES)
    try:
        conn = sqlite3.connect(p)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
            if "label_verdict" not in cols:
                # A store predating the label channel. Nothing can carry a verdict, so the
                # labelled read is empty and the pending read still needs `status`.
                if labelled:
                    return [], False
                if "status" not in cols:
                    return [], False
            if labelled:
                # 🔴 NO STATUS CLAUSE, deliberately. The Python version this replaces
                # filtered on `label_verdict` ALONE, so adding `status IN (...)` here would
                # silently drop any labelled row whose status is not blocking. This change
                # is about WHICH ROWS THE WINDOW IS SPENT ON, not about which rows qualify;
                # changing both at once is how a fix ships a second behaviour nobody asked
                # for.
                where, params = "label_verdict IS NOT NULL AND label_verdict != ''", []
            else:
                if "status" not in cols:
                    return [], False
                where = "status IN (%s)" % ",".join("?" for _ in statuses)
                if "label_verdict" in cols:
                    where += " AND (label_verdict IS NULL OR label_verdict = '')"
                params = list(statuses)
            # Same tie-break as list_recent_incidents: created_at is caller-supplied and
            # NOT unique, so ordering on it alone lets SQLite drop the newer of two rows
            # written in the same instant.
            order = ("ORDER BY created_at DESC, rowid DESC" if "created_at" in cols
                     else "ORDER BY rowid DESC")
            cur = conn.execute(
                "SELECT * FROM incidents WHERE %s %s LIMIT ?" % (where, order),
                params + [int(limit) + 1])            # +1: see _reviewable_with_truncation
            names = [c[0] for c in cur.description]
            rows = [dict(zip(names, r)) for r in cur.fetchall()]
        finally:
            conn.close()
    except sqlite3.Error:
        return [], False
    more_exist = len(rows) > limit
    rows = rows[:limit]
    for r in rows:
        r["resolution_path"] = _parse_resolution_path(r.get("resolution_path"))
    return rows, more_exist


def count_incidents(db_path=None):
    """Total rows in the store. A ``COUNT(*)``.

    ⚠️ NO PRODUCTION CALLER RIGHT NOW, and the history is the reason it is worth keeping.
    It was added to gate ``agentx review``'s "this can take a minute" banner on the size of
    the walk, after the first gate (pending count alone) promised a wait that never came.
    That was wrong too: reading rows is cheap (~0.4s for 43,000) and the cost is the
    per-row WRITES, so gating on stored rows fired the banner on every run forever for
    anyone with a large store. The banner gates on the writes now. Kept because "how big is
    this store" is a real question the retention work (P-97) will need to ask, and because
    the docstring is the record of why it must not be used for timing."""
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return 0
    try:
        conn = sqlite3.connect(p)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] or 0)
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def count_awaiting_verdict(db_path=None):
    """The EXACT number of blocks with no verdict yet. A ``COUNT(*)``, so it is cheap
    enough for the atexit nudge and does not materialise a single row.

    🔴 WHY EXACT AND NOT "200+". Three surfaces print this number and they disagreed on a
    real store: ``agentx review --stats`` counted the whole store
    and said **17,711 blocks still awaiting a verdict**, while the session-end nudge and
    the walkthrough header both read a 200-row window and could not say anything but 200.
    A reader with all three in front of them cannot tell which is the size of their job.
    The cap on the WALKTHROUGH is real work-limiting and stays; the cap on the COUNT was
    never anything but an artifact of reusing the list-read to do arithmetic."""
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return 0
    statuses = sorted(_BLOCKING_STATUSES)
    try:
        conn = sqlite3.connect(p)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
            if "status" not in cols:
                return 0
            where = "status IN (%s)" % ",".join("?" for _ in statuses)
            if "label_verdict" in cols:
                where += " AND (label_verdict IS NULL OR label_verdict = '')"
            row = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE %s" % where, statuses).fetchone()
            return int(row[0] or 0)
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def _reviewable_with_truncation(db_path=None, cluster=True):
    """``(items, hit_the_cap)`` -- the review backlog plus whether the read window was
    exhausted.

    🔴 THE +1 IS THE WHOLE POINT. Reading exactly
    ``REVIEW_READ_CAP`` rows cannot distinguish "there are exactly 200" from "there are
    thousands and you saw 200", and the session-end nudge printed the second as the first:
    seed 250 reviewable blocks and it prints "200 item(s)"; seed 500 and it prints "200"
    again. An operator reads that as the size of the job. Asking for one row MORE than we
    keep costs a single row per session and makes the number honest -- either it is the
    count, or it visibly is not.

    🔴 AND THE WINDOW IS SPENT ON ROWS THAT QUALIFY, which is the second half of the same
    defect and the more damaging one. This used to take the 200 most recent INCIDENTS and
    filter them here, so rows that need no review still consumed the window: a store with
    250 recently-labelled incidents in front of 50 unlabelled ones returned ZERO, the
    nudge vanished for a user with a real backlog, and `agentx review` showed an empty
    list over the same window. Measured on a real store: 50 items awaiting review, nothing on
    screen. Filtering in SQL means the count and the walkthrough see the same items, and
    ``hit_the_cap`` now means "more than 200 things ACTUALLY await review" rather than
    "more than 200 incidents exist", which is what a reader takes "200+" to mean anyway.
    """
    items = _adopt_items(db_path, cluster)
    raw, hit_the_cap = _incidents_by_verdict_state(REVIEW_READ_CAP, labelled=False,
                                                   db_path=db_path)
    for r in raw:
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
    return items, hit_the_cap


def _adopt_items(db_path=None, cluster=True):
    """The recoveries worth offering, one per policy. Split out so ``review_backlog_size``
    can count them WITHOUT also running the pending-blocks query and materialising 200
    verdict dicts it drops on the next line -- that ran at ``atexit`` for every protected
    session and opened the store twice to answer one question."""
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
    return items


def review_backlog_size(db_path=None):
    """``(count, more_than_we_will_show)`` for every surface that PRINTS the backlog size.

    The count is EXACT: a ``COUNT(*)`` for the pending blocks plus the adopt items. The
    flag says the walkthrough will show fewer than the count, so a caller can render
    "showing the first 200" rather than pretending the two numbers are one.

    🔴 THE COUNT USED TO BE THE LENGTH OF A CAPPED LIST, which is how three surfaces ended
    up disagreeing about one number on a real store: ``--stats`` said 17,711 awaiting, the
    nudge said 200, the walkthrough header said 200. Only one of those was the size of the
    job. Counting and listing are different questions and the cap belongs to the second.

    🔴 ``more_than_we_will_show`` IS NOT A TRUNCATION FLAG and callers must not use it as
    one. The cap applies to the pending BLOCKS only, so five adopt items behind 198 pending
    blocks pushes the total past 200 while nothing was truncated. Anything rendering
    "showing N of M" takes its flag from ``reviewable_items_with_truncation``, which gets it
    from the read that was actually cut short."""
    try:
        adopt = len(_adopt_items(db_path, cluster=False))
        pending = count_awaiting_verdict(db_path)
        total = adopt + pending
        return total, pending > REVIEW_READ_CAP
    except Exception:
        return 0, False


def labeled_items(db_path=None):
    """Blocks that ALREADY carry a verdict — powers ``agentx review --labeled``, the
    re-review path. ``reviewable_items`` only ever shows what's still PENDING; once
    labeled, an item vanishes from the normal walkthrough with no way back to see or
    change that decision. Same "verdict" item shape as ``reviewable_items``, plus the
    current ``label_verdict`` so it can be shown before it's (maybe) overwritten."""
    return labeled_items_with_truncation(db_path)[0]


def labeled_items_with_truncation(db_path=None):
    """``(items, more_exist)`` — the other member of P-80's class, and it had the same bug.

    The Python-side filter spent the 200-row window on rows that had NO verdict, so an
    operator whose recent blocks are all pending saw an empty ``--labeled`` list over a
    store holding 25,601 labelled ones. Filtered in SQL now, from the same one entry point
    as the pending read."""
    items = []
    rows, more_exist = _incidents_by_verdict_state(REVIEW_READ_CAP, labelled=True,
                                                   db_path=db_path)
    for r in rows:
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
    return items, more_exist


def count_reviewable(db_path=None):
    """How many items await review — drives the session-end nudge (runs at atexit for
    every protected session, so it must stay cheap). ``cluster=False`` skips the
    near-duplicate merge: the count is invariant under clustering (adopt items are
    one-per-policy; verdict items don't cluster at all), so this returns the SAME
    number ``reviewable_items()`` would, without the O(k^2) difflib pass. Defensive:
    0 on any error / absent store, so the nudge stays quiet on a plain or keyless run.

    Returns the bare int. Anything that PRINTS this number must use review_backlog_size()
    instead, which also says whether the number saturated -- printing a capped count as a
    total is P-80."""
    return review_backlog_size(db_path)[0]


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
    return os.path.join(_anchored_root(), DEFAULT_ORG_RULES_PATH)


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
