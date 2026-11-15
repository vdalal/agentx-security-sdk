"""A wrapped tool whose code changed under a team rule that names it.

A team rule (or a money rule) names a tool and stays as written when the tool's code changes, so a
rule can quietly stop fitting what the tool now does. When `@agentx_protect` wraps a tool that a
rule in this project's team rules file names, its source is fingerprinted and compared with the
fingerprints kept from earlier runs. A fingerprint not seen before prints one line on stderr, once.
A tool no rule names is never fingerprinted or kept: every refactor changes a fingerprint, so only
a tool a rule depends on is worth a line.

The fingerprints are this machine's, so they are kept in the user's home folder (one file per
project, named by the rules file's path), never beside the rules file, which a team commits. The
TypeScript SDK keeps its own in the same folder and file.

Never raises and never blocks: this runs when a module is imported, and a wrapped tool must work
whether or not the file can be read or written.
"""

import hashlib
import inspect
import json
import os
import sys
import tempfile
import threading
import types

from . import team_rules

# The fingerprints remembered per tool name. More than one: two wrapped functions can share a name
# (a sync and an async `refund`), and each must not read as a change to the other.
KEEP_PER_NAME = 5
_LOCK = threading.Lock()
_RULES_CACHE = {"key": None, "named": {}}


def _const_text(c, depth):
    """A constant as text that is the same in every process: a nested code object by its contents
    (no memory address), a set in sorted order (Python prints a set of words in a different order
    in each process; code review), a tuple item by item."""
    if isinstance(c, types.CodeType):
        return _code_text(c, depth + 1)
    if isinstance(c, (frozenset, set)):
        return "{%s}" % ",".join(sorted(_const_text(x, depth + 1) for x in c))
    if isinstance(c, tuple):
        return "(%s)" % ",".join(_const_text(x, depth + 1) for x in c)
    return repr(c)


def _code_text(code, depth=0):
    """A code object as text with no memory address in it and no order that changes between
    processes: its bytecode, names and constants."""
    if depth > 20:
        return ""
    consts = [_const_text(c, depth) for c in code.co_consts]
    return repr((code.co_code.hex(), code.co_names, code.co_varnames, consts))


def fingerprint(func):
    """The tool's source as text, hashed; its compiled code when there is no source (a frozen
    app, a REPL), or None when neither can be read."""
    target = inspect.unwrap(func) if callable(func) else func
    try:
        text = inspect.getsource(target)
    except (OSError, TypeError):
        code = getattr(target, "__code__", None)
        if code is None:
            return None
        text = _code_text(code)
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _named_tools():
    """{tool name: [(rule id, why)]} for the active rules in this project's file, read once per
    version of the file. {} when there is no file or it cannot be read."""
    try:
        p = team_rules.team_rules_path()
        st = os.stat(p)
        key = (p, st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    if _RULES_CACHE["key"] == key:
        return _RULES_CACHE["named"]
    named = {}
    try:
        for r in team_rules.read_team_rules(p):
            if not r.get("active", True):
                continue
            for t in r.get("tools") or []:
                named.setdefault(str(t), []).append((r.get("id"), r.get("why")))
    except Exception:
        named = {}
    _RULES_CACHE.update(key=key, named=named)
    return named


def project_key(rules_path):
    """The rules file's absolute path as both SDKs write it: forward slashes, lower case on
    Windows, where case does not name a different file."""
    p = os.path.abspath(rules_path).replace("\\", "/")
    return p.lower() if os.name == "nt" else p


def store_path(rules_path=None):
    """`~/.agentx/tool-fingerprints/<project>.json`, the project named by its rules file, or the
    same file name in `AGENTX_TOOL_FINGERPRINTS_DIR` when it is set."""
    folder = os.environ.get("AGENTX_TOOL_FINGERPRINTS_DIR")
    if not folder:
        home = os.path.expanduser("~")
        if not os.path.isabs(home):
            home = tempfile.gettempdir()
        folder = os.path.join(home, ".agentx", "tool-fingerprints")
    digest = hashlib.sha256(project_key(rules_path or team_rules.team_rules_path())
                            .encode("utf-8")).hexdigest()[:16]
    return os.path.join(folder, digest + ".json")


def note_wrapped_tool(name, func):
    """Compare a just-wrapped tool with the fingerprints kept for its name when a team rule names
    it, keep the new one, and print one line when it was not seen before. Returns the line
    printed, or None."""
    try:
        rules = _named_tools().get(name)
        if not rules:
            return None
        now = fingerprint(func)
        if now is None:
            return None
        key = "py:" + name
        with _LOCK:
            path = store_path()
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    kept = json.load(fh)
                if not isinstance(kept, dict):
                    kept = {}
            except (OSError, ValueError):
                kept = {}
            seen = kept.get(key)
            seen = [s for s in seen if isinstance(s, str)] if isinstance(seen, list) else []
            # Already known: nothing to say and nothing to write (code review: two tools of one
            # name rewrote the file on every start only to reorder it).
            if now in seen:
                return None
            first = not seen
            kept[key] = ([now] + [s for s in seen if s != now])[:KEEP_PER_NAME]
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                # One temporary name per writer: a TypeScript or another Python process writing
                # the same file at the same moment never shares it (code review).
                tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(kept, fh, indent=2, sort_keys=True)
                os.replace(tmp, path)
            except OSError:
                return None
        if first:
            return None        # first time seen: nothing to compare with
        rid, why = rules[0]
        more = " and %d more" % (len(rules) - 1) if len(rules) > 1 else ""
        verb = "name" if len(rules) > 1 else "names"
        # A reason written as a sentence ends in a full stop; inside the brackets it would read
        # "(... check them.). Check".
        why = str(why or "").strip().rstrip(".")
        line = ("[AgentX] %s changed since this project last ran it, and team rule %s%s %s it "
                "(%s). Check the rule still fits what the tool does: agentx rule list"
                % (name, rid, more, verb, why))
        print(line, file=sys.stderr)
        return line
    except Exception:
        return None
