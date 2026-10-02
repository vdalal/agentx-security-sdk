"""Build-time stamping of `agentx_sdk.__released__`. Imported by setup.py's cmdclass hooks.

Lives at the repo root rather than inside setup.py so it can be TESTED without executing
setup(), and so the publish check can share the same regex instead of writing a second one.
MUST stay listed in MANIFEST.in: setup.py imports it, so an sdist without it cannot build.

WHY THIS EXISTS. `__released__` drives the OFFLINE staleness notice -- the only mechanism that
reaches a pinned install, since pip cannot declare a minimum version of the leaf package. Its
correct value is the UPLOAD day, which the source tree cannot know, because the upload is a
manual step some days after the version is cut. So it used to be written by hand at cut time,
and that has failed twice in the same shape:

  * An earlier `__published__` constant of the same kind was retired because it required a hand
    edit at upload time and the edit was missed every single time. A marker that lags is worse
    than no marker.
  * `__released__` then repeated it: a release went out carrying a date eight days old, so every
    first-run user was told on day one that their brand-new install might be missing security
    fixes, and pointed at an upgrade that returned the same build.
  * A publish check was then added that REFUSED a release whose in-tree date lagged. That made
    the missed edit loud without removing it, and turned every upload into a deadline measured
    from the cut.

The build knows the build date. Stamp it there and neither the hand edit nor the deadline exists.

THE SOURCE TREE IS NEVER MODIFIED. The hooks rewrite the file setuptools has already COPIED into
build/lib (wheel) or the release tree (sdist). The in-tree value stays a real committed date,
which the staleness tests and the publish check both read. "In-tree value is the default,
overwritten at build" is the shape; "computed at import" is what it rules out, because then
nothing in-tree is readable at all.
"""
import datetime
import os
import re

RELEASED_RE = re.compile(r'^(__released__\s*=\s*)["\']([^"\']*)["\']', re.M)


def read_released(text):
    """The `__released__` value in `text`, or None. Shared with the publish gate so the two
    never drift into two regexes that disagree."""
    m = RELEASED_RE.search(text)
    return m.group(2) if m else None


def stamp_released(text, today=None):
    """`text` with `__released__` set to `today` (default: the build date).

    RAISES rather than returning text unchanged when the constant is missing or duplicated.
    A silent no-op here reproduces the exact defect this module removes, and it would be
    invisible: the build would succeed and ship a stale date. Failing the build is the only
    honest outcome, because the person who renamed the constant is the person who can fix it.
    """
    today = today or datetime.date.today().isoformat()
    new, n = RELEASED_RE.subn(r'\g<1>"%s"' % today, text, count=0)
    if n != 1:
        raise RuntimeError(
            "stamp_released: expected exactly 1 `__released__` assignment, found %d. "
            "The constant was renamed, removed or duplicated; fix this hook before "
            "publishing." % n)
    return new


def stamp_file(path, today=None):
    """Stamp a file IN PLACE. Callers pass a path inside the build tree, never the source."""
    if not os.path.exists(path):
        raise RuntimeError("stamp target missing: %s" % path)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    stamped = stamp_released(text, today)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(stamped)
    print("stamped __released__ = %s in %s" % (read_released(stamped), path))
