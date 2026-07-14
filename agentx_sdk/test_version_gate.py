"""BACKLOG C12 — the version line is an invariant, so it gets a GATE, not a wish.

Three things used to be able to drift silently, and each one has bitten:

  (b) SDK source could change and ship under a version ALREADY on PyPI, so a security
      fix reached nobody (a user who upgraded got the same wheel).
  (c) `__released__` could stay behind `__version__`, which silently mis-dates the
      OFFLINE staleness notice -- the ONLY mechanism that can reach a pinned install.
  (d) `agentx-mcp` carried TWO version strings (pyproject.toml + agentx_mcp/__init__.py)
      with nothing binding them, so the wheel's metadata and the package's own report of
      itself could disagree.

NOTE on the shape of (b). The obvious gate -- "any SDK source diff must move
`__version__`" -- was REJECTED: it forces a bump on every PR, which is exactly the
version churn we are avoiding ("a version number is a budget, not a counter"), and it
would have failed the very PR that added this file. The real rule is narrower and truer:

    ✦ You may not ship SDK source under a version that is ALREADY PUBLISHED. ✦

So `__published__` records what is live on PyPI, and the gap between it and `__version__`
is the unreleased content accumulating for the next publish. Many PRs bundle under ONE
unreleased version; we publish once, with content; and the FIRST source PR after a
publish is forced to open the next version. One bump per release, not per PR.
"""
import os
import re
import subprocess

import pytest

import agentx_sdk

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MCP_PYPROJECT = os.path.join(REPO, "agentx-mcp", "pyproject.toml")
MCP_INIT = os.path.join(REPO, "agentx-mcp", "agentx_mcp", "__init__.py")

# This test file ships in the SDK sdist (it is in SOURCES.txt), so it runs in the standalone
# package too -- where `agentx-mcp/` does NOT exist (the mcp launcher is a sibling in the
# monorepo, not part of the SDK). Guard the agentx-mcp bind/floor checks so they SKIP there
# instead of failing on a missing file, the same way test_docs_cli_consistency skips when the
# marketing `ui/` tree is absent. In the monorepo (agentx-mcp/ present) they run for real.
_HAS_MCP = os.path.isfile(MCP_PYPROJECT) and os.path.isfile(MCP_INIT)
_needs_mcp = pytest.mark.skipif(
    not _HAS_MCP, reason="agentx-mcp/ not present (SDK-only sdist/mirror); monorepo-only check")


def _tuple(v):
    """('0.4.19') -> (0, 4, 19), so 0.4.9 < 0.4.19 (a string compare gets this WRONG)."""
    return tuple(int(part) for part in re.findall(r"\d+", v))


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _git(*args):
    return subprocess.run(
        ["git", "-C", REPO, *args],
        capture_output=True, text=True, timeout=30,
    )


# ---------------------------------------------------------------- (b)

def test_version_is_ahead_of_what_is_published_on_pypi():
    """✦ THE GATE ✦ SDK source in this tree must never ship under an already-published
    version. If this goes red, you changed the SDK and did not open a new version: a user
    who upgrades gets a wheel that is byte-identical to the one they already have, and the
    fix reaches NOBODY."""
    assert _tuple(agentx_sdk.__version__) > _tuple(agentx_sdk.__published__), (
        f"__version__ ({agentx_sdk.__version__}) must be GREATER than __published__ "
        f"({agentx_sdk.__published__}), the version live on PyPI. Bump __version__ (and "
        f"__released__ with it). If you just published, update __published__ in the same "
        f"commit as the `twine upload`."
    )


def test_published_marker_is_a_real_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+", agentx_sdk.__published__), (
        "__published__ must be the exact version string live on PyPI"
    )


def test_setup_py_reads_the_same_version_the_package_reports():
    """setup.py's `version=_read_version()` and `agentx_sdk.__version__` must agree, or the
    wheel is stamped with a version the code does not think it is."""
    setup_src = _read(os.path.join(REPO, "setup.py"))
    assert "_read_version()" in setup_src, (
        "setup.py should DERIVE the version from agentx_sdk/__init__.py, never re-declare it"
    )


# ---------------------------------------------------------------- (c)

def test_released_moves_with_version():
    """`__released__` drives the OFFLINE staleness notice, which is the only thing that can
    reach a PINNED install (pip cannot declare a minimum version of the leaf package). A
    stale date means an old install does not know it is old."""
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", agentx_sdk.__released__)

    # Whenever the diff-vs-main touches __version__, it must touch __released__ too.
    diff = _git("diff", "origin/main...HEAD", "--", "agentx_sdk/__init__.py")
    if diff.returncode != 0 or not diff.stdout.strip():
        pytest.skip("no git diff available (detached/shallow/no origin) or __init__ untouched")

    changed = diff.stdout
    version_moved = bool(re.search(r"^\+__version__", changed, re.M))
    released_moved = bool(re.search(r"^\+__released__", changed, re.M))
    if version_moved:
        assert released_moved, (
            "__version__ moved but __released__ did not. They ship together: a version cut "
            "with a stale release date mis-dates the staleness notice for every install."
        )


# ---------------------------------------------------------------- (d)

@_needs_mcp
def test_agentx_mcp_two_version_strings_agree():
    """✦ THE BIND ✦ agentx-mcp declares its version TWICE. Nothing tied them together, so
    a bump to one could silently leave the other behind."""
    pyproject_v = re.search(r'^version\s*=\s*"([^"]+)"', _read(MCP_PYPROJECT), re.M)
    init_v = re.search(r'^__version__\s*=\s*"([^"]+)"', _read(MCP_INIT), re.M)

    assert pyproject_v, "agentx-mcp/pyproject.toml has no [project].version"
    assert init_v, "agentx-mcp/agentx_mcp/__init__.py has no __version__"
    assert pyproject_v.group(1) == init_v.group(1), (
        f"agentx-mcp version DRIFT: pyproject.toml says {pyproject_v.group(1)}, "
        f"agentx_mcp/__init__.py says {init_v.group(1)}. Keep them in sync."
    )


# ---------------------------------------------------------------- (a)

@_needs_mcp
def test_agentx_mcp_sdk_floor_reaches_the_current_shield():
    """✦ REACH ✦ agentx-mcp's dependency floor is the ONLY thing that carries a keyless
    enforcement fix to an MCP user. A floor that an already-installed VULNERABLE SDK
    satisfies is a floor that never upgrades anyone.

    So on every keyless enforcement fix, the floor must move to the version that CONTAINS
    the fix. Here: the fail-open shield is fixed in 0.4.19, so the floor must be >= 0.4.19.
    """
    floor = re.search(r'agentx-security-sdk>=([\d.]+)', _read(MCP_PYPROJECT))
    assert floor, "agentx-mcp must pin a MINIMUM agentx-security-sdk version"

    assert _tuple(floor.group(1)) >= _tuple("0.4.19"), (
        f"agentx-mcp's SDK floor is {floor.group(1)}, but the Local Shield fail-open fix "
        f"(#205) landed in 0.4.19. Below that floor the shield still swallows its own "
        f"exceptions and EXECUTES the blocked tool. Raise the floor or the fix reaches "
        f"zero MCP users."
    )

    # And the floor must never advertise a version that does not exist yet.
    assert _tuple(floor.group(1)) <= _tuple(agentx_sdk.__version__), (
        f"agentx-mcp floors on agentx-security-sdk>={floor.group(1)}, which is AHEAD of the "
        f"SDK in this tree ({agentx_sdk.__version__}). That install is unsatisfiable."
    )
