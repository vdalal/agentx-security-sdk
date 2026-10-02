"""Minimal, stdlib-only `.env` reader.

Lives in its own module so import-light callers (notably pulse.py, which runs at
atexit and must not drag in requests/numpy — the 0.3.1 import-safety lesson) can
read the project `.env` without importing cli.py and its heavy dependency graph.
cli.py re-exports load_env_file from here for backward compatibility.
"""
import os


# 🔴 ONE SPELLING OF THE FALLBACK, SHARED BY THE READER AND BY ANYTHING THAT NAMES IT.
# `parent_env_dir` below has to tell a developer WHICH folder is being skipped, and the
# obvious ways to do that both go wrong: changing what `load_env_file` returns breaks a
# reader with three call sites in `cli.py` (which re-exports it for backward compatibility)
# plus its tests, and recomputing `os.path.join("..", ".env")` in the calling module puts a
# copy of this rule in a file that will not be edited the day the fallback moves. Keeping
# the constant here means the copy sits against the rule instead of across a module
# boundary; `test_parent_env_dir_agrees_with_the_reader` pins the two together.
_PARENT_ENV = os.path.join("..", ".env")


def load_env_file(include_parent=True):
    """Extract KEY=value bindings from ./.env, falling back to ../.env. Returns a
    dict (empty if no file). Best-effort; never raises.

    `include_parent=False` reads ./.env ONLY, and the default stays True because every
    existing caller is a CLI command a human typed in that tree. See `dotenv_overlay`
    for which settings are read which way, and why that is not one answer."""
    env_vars = {}
    target_path = ".env"

    # If .env is missing locally, check the parent directory.
    if not os.path.exists(target_path):
        if include_parent and os.path.exists(_PARENT_ENV):
            target_path = _PARENT_ENV
        else:
            return env_vars

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                env_vars[key.strip()] = val.strip().strip('"').strip("'")
    except Exception:
        pass
    return env_vars


# THE `.env` OVERLAY, READ ONCE PER PROCESS. `load_env_file()` above opens a file on
# every call, which is fine for a CLI command and wrong for anything on the per-call
# path -- `cli.py` says so itself where it caches the health probe ("a load_env_file()
# read each time stalls an interactive..."). A process reads its `.env` once, which is
# also what every dotenv library does.
#
# `None` means "not read yet" and `{}` means "read, nothing there", so a missing file is
# cached too rather than re-stat'ed forever. Tests neutralise them by setting BOTH to `{}`
# -- the same seam `pulse._env_overlay` has always offered, and the reason that one is left
# in place rather than folded in here.
#
# 🔴 TWO OVERLAYS, BECAUSE "HOW FAR UP THE TREE DO WE LOOK" IS NOT ONE ANSWER, AND THE
# FIRST CUT OF THIS GOT IT BACKWARDS IN A WAY THAT WOULD HAVE COST SOMEONE THEIR OPT-OUT.
# The obvious split is CLI (permissive) versus library (strict), and it is wrong. What
# decides is WHAT THE SETTING DOES:
#
#   A DESTINATION for our data (AGENTX_GATEWAY_URL: where the query, the chain of thought
#   and the Authorization header are sent) is read from ./.env ONLY. A library runs inside
#   somebody else's process, and a stale file one directory up must not be able to retarget
#   an agent's payload. Nothing could do that before this branch; the permissive lookup is
#   the CLI's, and a library does not inherit the trust of a command a human typed.
#
#   AN OPT-OUT (AGENTX_TELEMETRY) is read up the tree, unchanged. Failing to SEE a refusal
#   sends data somebody declined, so the failure directions are opposite: for a destination
#   the risk is reading too much, for an opt-out it is reading too little. Narrowing this
#   one to ./.env would have quietly re-enabled telemetry for anyone who wrote their opt-out
#   at a repo root and runs their agent in a subdirectory.
_overlay = None          # ./.env only -- destinations
_overlay_tree = None     # ./.env, then ../.env -- opt-outs, and the CLI's own reads


def dotenv_overlay(include_parent=False):
    """The project `.env` as a dict, read at most once per process. Never raises.

    `include_parent` picks which of the two caches above; read the note there before
    changing a caller from one to the other, because the two failure directions are
    opposite."""
    global _overlay, _overlay_tree
    if include_parent:
        if _overlay_tree is None:
            try:
                _overlay_tree = load_env_file(include_parent=True) or {}
            except Exception:
                _overlay_tree = {}
        return _overlay_tree
    if _overlay is None:
        try:
            _overlay = load_env_file(include_parent=False) or {}
        except Exception:
            _overlay = {}
    return _overlay


def parent_env_dir():
    """The directory whose `.env` the RUNTIME deliberately does not read, or None.

    For the notice in `client.py`, which has to name the folder a developer should go and
    look at. It names the FOLDER and never the file's contents: the value being skipped is
    a gateway address, which can carry credentials, and the same reasoning already stopped
    `only_a_parent_sets`'s caller printing the URL.

    The answer is unambiguous wherever it is not None, which is why this can be a plain
    lookup rather than plumbing through the reader. `load_env_file` reads `./.env` OR
    `../.env` and never both, so a parent file is consulted only when the working directory
    has no `.env` at all -- exactly the state tested here. Never raises.

    🔴 IT RE-STATS THE DISK WHILE `only_a_parent_sets` ANSWERS FROM A PROCESS-LIFETIME CACHE,
    AND ONLY ONE STATE MAKES THEM DISAGREE. `dotenv_overlay` caches both lookups on first
    use; this function looks at the current working directory every time. A process that
    CHANGES DIRECTORY after the caches are warm -- an agent tool that chdirs, a test that
    does -- can therefore have the caller decide "a parent sets it" from the OLD cwd while
    this resolves against the NEW one, and the notice would then name a folder whose `.env`
    was never read. It is a notice rather than a verdict, and a wrong folder is worse than a
    vague one, so the caller falls back to "A .env one directory up" when this returns None.
    Pinned by `test_parent_env_dir_agrees_with_the_reader`, which drives a cwd change after
    the caches are warm -- the only state in which the two can differ."""
    try:
        if os.path.exists(".env") or not os.path.exists(_PARENT_ENV):
            return None
        return os.path.abspath("..")
    except Exception:
        return None


def only_a_parent_sets(key):
    """True when this setting is named by a `.env` the RUNTIME deliberately does not read.

    The two lookups can only disagree in one shape, and it is worth stating exactly because
    the shape is narrower than it sounds: `load_env_file` reads `./.env` OR `../.env`, never
    both, so a parent file is consulted only when the working directory has no `.env` at all.
    An agent two directories below the file sees neither and agrees with the CLI on the
    default; an agent beside the file sees it and agrees. One directory down is the whole
    window, and this returns True exactly there.

    🔴 THE PROCESS ENVIRONMENT IS ASKED FIRST, AND LEAVING IT OUT MADE THIS FIRE ON A HEALTHY
    INSTALL. `resolve_env` reads `os.environ` before either file, so an exported value means
    nothing is being ignored and the two doors agree. Comparing the overlays alone did not
    know that: with the variable exported -- which is the remedy the caller's own notice
    recommends -- it still returned True, so the notice said "calls go to X" and then advised
    the export that was already in place. Advice that cannot be followed to completion is
    worse than silence, and the line also printed a URL that can carry credentials for an
    install with nothing wrong with it.

    It answers a question ABOUT configuration and decides nothing: the caller chooses whether
    that is worth saying. Never raises."""
    try:
        exported = os.environ.get(key)
        if exported is not None and exported.strip():
            return False
        return key not in dotenv_overlay() and key in dotenv_overlay(include_parent=True)
    except Exception:
        return False


def resolve_env(key, default=None, overlay=None):
    """Resolve an `AGENTX_*` setting the way the CLI does: the process environment first,
    then the project `.env`, then `default`.

    🔴 ONE RULE, IN ONE PLACE, BECAUSE THE TWO DOORS DISAGREEING IS THE DEFECT. `cli.py`
    resolved `os.environ.get(...) or env.get(..., default)` inline at TWO sites (a first
    draft of this sentence said three, counting a third `load_env_file()` call that resolves
    `AGENTX_API_KEY`, which is a different variable) and the SDK runtime read `os.environ`
    alone, so a developer who put `AGENTX_GATEWAY_URL` in
    `.env` -- which is where `.env.example` shows it -- got `agentx status` reporting
    healthy against their gateway while every `@agentx_protect` call went to localhost,
    with nothing saying the two had looked in different places. Both of those sites
    now call this. `pulse._env` had already found the same disagreement for
    `AGENTX_TELEMETRY`; this is that rule hoisted, not a third copy of it.

    `overlay` is WHICH `.env` the caller trusts, and it is the caller's to pass because it
    is the one thing that legitimately differs (see the note above the two caches). The
    CLI passes its own already-loaded dict, which also keeps `cli.load_env_file`
    monkeypatchable -- a test patches that name for isolation, and reaching past it here
    would have disarmed the patch while leaving it looking effective.

    ⚠️ BLANK IS UNSET, AND THIS IS THE ONE PLACE IT IS STRICTER THAN THE LINE IT REPLACES.
    The CLI's `or` treats `""` as absent and a whitespace-only value as PRESENT, which
    would make `AGENTX_GATEWAY_URL="   "` the address of a gateway. Both are treated as
    unset here. `AGENTX_GATEWAY_URL=` with no value is ordinary in docker-compose and CI,
    and an earlier cut of this used `is not None`, which made the empty case resolve to
    localhost in the SDK and to the `.env` value in the CLI, which is the same split again,
    inside the function whose whole job is to end it.

    The process environment is still read at every call, so setting a variable after import
    keeps working. Only the file is cached.
    """
    val = os.environ.get(key)
    if val is not None and val.strip():
        return val
    if overlay is None:
        overlay = dotenv_overlay()
    val = overlay.get(key)
    if val is not None and str(val).strip():
        return val
    return default
