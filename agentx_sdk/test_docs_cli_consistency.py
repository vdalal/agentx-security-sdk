"""Cross-surface consistency tripwire: the marketing site's /docs CLI reference table
must not drift from `agentx help`.

The command list lives on TWO surfaces that legitimately cannot share a source across
the Python <-> TSX boundary: `_print_cli_usage()` in `agentx_sdk/cli.py` (what
`agentx help` prints) and the CLI reference table in `ui/app/docs/page.tsx` (whose own
comment says "Content mirrors the CLI help"). Adding a command to one and forgetting
the other is a silent drift no single diff looks wrong for. This pins the STRUCTURAL
invariant on the command-name SET (not the descriptions, which are worded differently
by design):

  1. Every command documented in /docs is a REAL `agentx` command (docs is a subset of
     help). Red if the docs table lists a stale / renamed / typo'd command.
  2. Every `agentx help` command is either documented in /docs OR in the known-omitted
     ledger below. Red the moment a NEW command is added to help but not to /docs, and
     also red when a ledgered command later gets documented or removed (forcing the
     ledger to shrink) so the ledger can never rot.

Import-light: imports only the CLI usage printer (no gateway / fastembed) and reads the
docs page as text. Skips cleanly when `ui/` is absent (the SDK is published standalone to
PyPI and mirrored to a repo without the marketing site).

Trigger: runs on LOCAL pytest, picked up by the `pr-overnight` invariant gate
(`pytest -k consistency`) since the filename carries "consistency" — NOT Vercel CI.
"""
import contextlib
import io
import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ledger: `agentx help` commands intentionally NOT in the /docs CLI table.
# One line per entry stating the real reason (not an approval). If a ledgered
# command later gets documented in /docs, assertion 2 goes RED and forces its
# removal from here — the ledger can only shrink, never silently rot.
# Grounded in runtime truth (help - docs) at authoring time, not from memory.
# ---------------------------------------------------------------------------
_HELP_ONLY_LEDGER = {
    "mcp-insights",  # power-user sibling of `insights` (the keyless MCP recovery loop);
                     # the docs quickstart leads with the mainstream loop, not this.
    "help",          # meta-command (prints the list itself); not a documented workflow step.
}

_DOCS_PAGE = Path(__file__).resolve().parents[1] / "ui" / "app" / "docs" / "page.tsx"


def _help_commands():
    """The command names `agentx help` prints. Each usage row is two spaces, the
    command, then two or more spaces before its description; prose/snippet lines start
    with a capital or a deeper indent and do not match."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        from agentx_sdk.cli import _print_cli_usage
        _print_cli_usage()
    return set(re.findall(r"(?m)^  ([a-z][a-z0-9-]+)\s{2,}\S", buf.getvalue()))


def _docs_commands(text):
    """The command names in the /docs CLI reference table. Scoped to the slice between
    the NAV `.map(([id, label])` and the CLI table `.map(([cmd, desc])` so it matches
    ONLY the `["cmd", "desc"]` rows of the CLI table, never the in-page nav array."""
    nav = text.index(".map(([id, label])")
    cli = text.index(".map(([cmd, desc])")
    return set(re.findall(r'\["([a-z][a-z0-9-]+)",', text[nav:cli]))


@pytest.mark.skipif(not _DOCS_PAGE.is_file(),
                    reason="marketing /docs page absent (standalone SDK / mirror checkout)")
def test_docs_cli_table_matches_agentx_help():
    help_cmds = _help_commands()
    docs_cmds = _docs_commands(_DOCS_PAGE.read_text(encoding="utf-8"))

    # Sanity: the extractors found something on each surface (guards a silent regex/format
    # break that would make the assertions below vacuously pass).
    assert help_cmds, "no commands parsed from `agentx help` (check _print_cli_usage format)"
    assert docs_cmds, "no commands parsed from the /docs CLI table (check page.tsx format)"

    # 1. Every documented command is a real `agentx` command.
    stale = docs_cmds - help_cmds
    assert not stale, (
        f"/docs documents command(s) that `agentx help` does not list: {sorted(stale)}. "
        "Remove them from ui/app/docs/page.tsx or (if renamed) fix the name.")

    # 2. Every help command is documented in /docs or in the known-omitted ledger, and
    #    the ledger holds no stale entries. Exact equality forces the ledger to shrink
    #    when a command gets documented or removed.
    help_only = help_cmds - docs_cmds
    assert help_only == _HELP_ONLY_LEDGER, (
        f"`agentx help` vs /docs drifted. help-only commands are {sorted(help_only)}, "
        f"ledger is {sorted(_HELP_ONLY_LEDGER)}.\n"
        f"  - newly undocumented (add to ui/app/docs/page.tsx, or to the ledger with a reason): "
        f"{sorted(help_only - _HELP_ONLY_LEDGER)}\n"
        f"  - stale ledger entries (now documented or removed -> delete from the ledger): "
        f"{sorted(_HELP_ONLY_LEDGER - help_only)}")
