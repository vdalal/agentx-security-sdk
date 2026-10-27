"""
agentx_sdk/team_rules.py — rules a person writes from a correction: `.agentx/team-rules.json`.

A correction the developer keeps repeating to their coding agent ("don't run the suites without
asking me") becomes a rule the hook checks before the call, on every harness the hook is
installed in, instead of a note the agent is supposed to remember. The file is committable, so
a teammate who pulls gets the same rules.

    {"version": 1, "rules": [{
        "id": "team-3f2a9c1b7d04",
        "tools": ["shell"],                  # "shell" = every shell tool; else exact tool names
        "match": ["run_suites.py"],          # every phrase must appear in the call, any case
        "action": "ask",
        "where_ask_unsupported": "warn",     # a harness that cannot ask: "warn" or "stop"
        "why": "the suites run once, at the end, with my go-ahead",
        "said": "I have had to ask you multiple times to not run the suites",
        "owner": "Vasu Dalal",
        "added_at": "2026-10-24T...",
        "active": true}]}

WHY A FILE OF ITS OWN, NOT `rules.json`. The adopted rules there are matched by shape and only
RECORDED on keyless doors (their meaning half needs the gateway's model), and the gateway
refuses, out loud, any rule in that file carrying a field it does not know. A rule here is the
exact words a person typed, so its match IS the rule, and its one action is to ask that person.

WHAT A RULE DOES: it asks. It never blocks on a harness that can ask. A harness that cannot
ask (Codex runs a call whose hook answers "ask")
gets `where_ask_unsupported`: "warn" (the default) shows the rule and lets the call run;
"stop" refuses it with the rule's reason, for a team that chose that for this rule.

Pure standard library, like `rules.py`, so it is import-safe at SDK load.
"""
import hashlib
import json
import os
import subprocess
import uuid

from .overrides import _anchored_root, _now_iso

TEAM_RULES_FILE = os.path.join(".agentx", "team-rules.json")
# Not "rule-": that prefix is the adopted rules' (`rules.json`), and readers of the record count
# a `rule-` id on a row as an adopted rule's match.
ID_PREFIX = "team-"
_FILE_VERSION = 1
ACTIONS = ("ask",)
WHERE_ASK_UNSUPPORTED = ("warn", "stop")
SHELL = "shell"
# The shell tools each harness names. Claude Code: Bash, PowerShell. Codex: Bash.
SHELL_TOOLS = ("Bash", "PowerShell")


def team_rules_path(path=None, project=None):
    """Explicit arg, else `AGENTX_TEAM_RULES_FILE`, else `<project>/.agentx/team-rules.json`,
    where the project is the one named (the hook names the folder its harness gave it) or the
    one this process is in."""
    if path:
        return path
    return os.environ.get("AGENTX_TEAM_RULES_FILE") or os.path.join(
        project or _anchored_root(), TEAM_RULES_FILE)


def _check_rule(r, p):
    """A stored rule, validated. Raises ValueError naming the file and the rule."""
    if not isinstance(r, dict) or not str(r.get("id") or "").startswith(ID_PREFIX):
        raise ValueError("%s holds a rule without a '%s' id" % (p, ID_PREFIX))
    rid = r["id"]
    if not isinstance(r.get("why"), str) or not r["why"].strip():
        raise ValueError("%s: rule %s needs \"why\", the reason shown when it asks" % (p, rid))
    for key in ("said", "owner", "added_at"):
        if key in r and not isinstance(r[key], str):
            raise ValueError("%s: rule %s has a %s that is not text" % (p, rid, key))
    tools = r.get("tools")
    if not isinstance(tools, list) or not tools or not all(
            isinstance(t, str) and t.strip() for t in tools):
        raise ValueError("%s: rule %s needs \"tools\", a list of tool names or \"shell\"" % (p, rid))
    match = r.get("match")
    if not isinstance(match, list) or not match or not all(
            isinstance(m, str) and m.strip() for m in match):
        raise ValueError("%s: rule %s needs \"match\", a list of phrases" % (p, rid))
    if r.get("action", "ask") not in ACTIONS:
        raise ValueError("%s: rule %s has action %r; a team rule asks (\"ask\")"
                         % (p, rid, r.get("action")))
    if r.get("where_ask_unsupported", "warn") not in WHERE_ASK_UNSUPPORTED:
        raise ValueError("%s: rule %s has where_ask_unsupported %r; use \"warn\" or \"stop\""
                         % (p, rid, r.get("where_ask_unsupported")))
    if not isinstance(r.get("active", True), bool):
        raise ValueError("%s: rule %s has an active value that is not true or false" % (p, rid))
    return r


def read_team_rules(path=None):
    """Every rule in the file, active or not. [] when there is no file; raises on a file that
    exists and cannot be read, so a damaged file never reads as "no rules"."""
    p = team_rules_path(path)
    if not os.path.exists(p):
        return []
    try:
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        # The parser's own text names no file ("Expecting value: line 1 column 27").
        raise ValueError("%s is not valid JSON (%s)" % (p, err))
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise ValueError("%s is not a team rules file (expected {\"version\", \"rules\": [...]})" % p)
    return [_check_rule(dict(r) if isinstance(r, dict) else r, p) for r in doc["rules"]]


def team_rules_fingerprint(rules):
    """A short, stable fingerprint of a list of team rules, so this machine and a gateway can
    tell whether the rules a person pushed are the ones in this file. Order counts: the first
    matching rule is the one that asks.
    🔴 THE GATEWAY COMPUTES THE SAME VALUE (its own `team_rules_fingerprint`): canonical JSON of
    the rules, sorted keys, no spaces, sha256, first 16 hex characters."""
    raw = json.dumps(list(rules), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _write(p, rules):
    """Whole file via a temp file and rename, so a crash leaves the old file."""
    parent = os.path.dirname(p)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"version": _FILE_VERSION, "rules": rules}, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, p)


def _git_user():
    try:
        out = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True,
                             timeout=5)
        return out.stdout.strip() or None
    except Exception:
        return None


def add_team_rule(tools, match, why, *, said=None, owner=None, where_ask_unsupported="warn",
                  path=None):
    """Write one active rule and return it. Raises ValueError, with nothing written, on a rule
    that cannot be stored or a file that cannot be read."""
    p = team_rules_path(path)
    rules = read_team_rules(p)
    same = existing_team_rule(tools or [SHELL], match, rules)
    if same is not None:
        raise ValueError("this is already a team rule (%s, added by %s). See it: agentx rule "
                         "list" % (same["id"], same.get("owner") or "nobody named"))
    why = str(why or "").strip()
    if not why:
        raise ValueError("a team rule needs a reason (--why): it is what the agent and the "
                         "person asked are shown")
    rule = {"id": ID_PREFIX + uuid.uuid4().hex[:12],
            "tools": [str(t).strip() for t in (tools or [SHELL]) if str(t).strip()],
            "match": [str(m).strip() for m in (match or []) if str(m).strip()],
            "action": "ask",
            "where_ask_unsupported": where_ask_unsupported,
            "why": why}
    if said and str(said).strip():
        rule["said"] = str(said).strip()
    rule["owner"] = (str(owner).strip() if owner and str(owner).strip() else None) or _git_user()
    if not rule["owner"]:
        rule.pop("owner")
    rule["added_at"] = _now_iso()
    rule["active"] = True
    _check_rule(rule, p)
    _write(p, rules + [rule])
    return rule


def existing_team_rule(tools, match, rules):
    """The rule in `rules` that checks the same tools for the same phrases (any order, any
    case), or None. Its reason may differ; the match is what decides what gets asked."""
    def key(ts, ms):
        return (frozenset(str(t).strip() for t in ts if str(t).strip()),
                frozenset(str(m).strip().lower() for m in ms if str(m).strip()))
    wanted = key(tools, match or [])
    return next((r for r in rules if key(r["tools"], r["match"]) == wanted), None)


def remove_team_rule(rule_id, path=None):
    """Remove a rule by id. Returns the removed rule, or None when no rule has that id."""
    p = team_rules_path(path)
    rules = read_team_rules(p)
    keep = [r for r in rules if r["id"] != rule_id]
    if len(keep) == len(rules):
        return None
    _write(p, keep)
    return next(r for r in rules if r["id"] == rule_id)


def _tool_names(tool_name):
    """The names a rule may use for this tool: the harness's name, the bare MCP tool name for
    `mcp__<server>__<tool>`, and "shell" for a shell tool."""
    names = {tool_name}
    if tool_name in SHELL_TOOLS:
        names.add(SHELL)
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) == 3 and parts[2]:
            names.add(parts[2])
    return names


def match_team_rule(tool_name, call_text, path=None):
    """The first active rule this call matches, or None. `call_text` is what the call says (a
    shell command, or an MCP call's name and argument values). Never raises: an unreadable
    file matches nothing here, and `team_rules_state` is what reports it."""
    try:
        names = _tool_names(tool_name)
        text = str(call_text or "").lower()
        for r in read_team_rules(path):
            if not r.get("active", True):
                continue
            if not names & set(r["tools"]):
                continue
            if all(m.lower() in text for m in r["match"]):
                return r
    except Exception:
        return None
    return None


def team_rules_state(path=None):
    """"read", "no file", or "damaged" (the file exists and could not be read)."""
    p = team_rules_path(path)
    if not os.path.exists(p):
        return "no file"
    try:
        read_team_rules(p)
        return "read"
    except Exception:
        return "damaged"


# What each rule did, one line per match: {"rule", "at", "outcome", "harness"}. It is this
# machine's, not the team's, so it sits in the hook's session folder, which the install already
# asks git to ignore (session pruning removes folders only, so the file stays). The ledger cannot
# hold it, because a call the developer declines never runs and so never gets a row. "ran" is
# written after an asked call has run (by `agentx hook record-ran`).
USES_FILE_NAME = "team-rule-uses.jsonl"
_USES_MAX_BYTES = 256 * 1024
OUTCOMES = ("ask", "ran", "warn", "stop")


def uses_path(path=None, project=None):
    return os.path.join(os.path.dirname(team_rules_path(path, project=project)), "hook-sessions",
                        USES_FILE_NAME)


def log_team_rule_use(rule_id, outcome, harness, path=None):
    """Append one use. Past the size cap the older half is dropped. Never raises."""
    import time
    try:
        p = uses_path(path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.exists(p) and os.path.getsize(p) > _USES_MAX_BYTES:
            with open(p, encoding="utf-8") as fh:
                lines = fh.readlines()
            with open(p + ".tmp", "w", encoding="utf-8", newline="\n") as fh:
                fh.writelines(lines[len(lines) // 2:])
            os.replace(p + ".tmp", p)
        with open(p, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"rule": rule_id, "at": time.time(), "outcome": outcome,
                                 "harness": harness}) + "\n")
    except Exception:
        pass


def rule_use_counts(rule_id, path=None):
    """{outcome: count, "since": earliest time or None} for one rule from the uses file, or None
    when it cannot be read."""
    p = uses_path(path)
    counts = {o: 0 for o in OUTCOMES}
    counts["since"] = None
    if not os.path.exists(p):
        return counts
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                try:
                    use = json.loads(line)
                except ValueError:
                    continue
                if use.get("rule") == rule_id and use.get("outcome") in OUTCOMES:
                    counts[use["outcome"]] += 1
                    at = use.get("at")
                    if isinstance(at, (int, float)) and (counts["since"] is None
                                                         or at < counts["since"]):
                        counts["since"] = at
        return counts
    except Exception:
        return None


# The outcomes that are a rule matching a call. "ran" follows an "ask" for the same call, so
# counting it would count that call twice.
_MATCH_OUTCOMES = ("ask", "warn", "stop")
PULSE_WINDOW_SECONDS = 7 * 24 * 60 * 60
# The hook's own check on changes to the rules (hook.RULE_CHANGE_ID, held equal by a test) logs
# through the same file; it is ours, not one the developer wrote, so the report does not count it.
RULE_CHANGE_ID = "team-rule-changes"


def pulse_counts(project=None, now=None):
    """(active rules, matches in the last 7 days) for the usage pulse, each None when its file
    exists and cannot be read: a zero has to mean "none". Counts only; the rules, their phrases
    and the calls they matched stay on this machine. Read at send time, because the pulse goes
    at most once a day and a per-session count would lose every other session's matches."""
    import time
    path = team_rules_path(project=project)
    try:
        rules = sum(1 for r in read_team_rules(path) if r.get("active", True))
    except Exception:
        rules = None
    since = (time.time() if now is None else now) - PULSE_WINDOW_SECONDS
    p = uses_path(path)
    if not os.path.exists(p):
        return rules, 0
    try:
        matches = 0
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                try:
                    use = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(use, dict) or use.get("rule") == RULE_CHANGE_ID:
                    continue
                at = use.get("at")
                if (use.get("outcome") in _MATCH_OUTCOMES and isinstance(at, (int, float))
                        and at >= since):
                    matches += 1
        return rules, matches
    except Exception:
        return rules, None


_USAGE ="""usage: agentx rule add PHRASE [PHRASE ...] --why "REASON" [options]
       agentx rule list
       agentx rule remove RULE_ID [--yes]
       agentx rule push

Turn a correction you keep repeating into a team rule. Before a call that
contains every PHRASE, Claude Code asks you first. The rule is saved in
.agentx/team-rules.json: commit it, and teammates who use the AgentX hook
get it too. push sends the file to your gateway (AGENTX_API_KEY), which
then checks an SDK agent's matching call: it holds it for a person to
answer, or stops it where nobody can answer a hold.

  --why "REASON"   Required. What you keep telling the agent. Shown when
                   it asks.
  --tool NAME      Which calls it checks. shell (the default) is a
                   Bash or PowerShell command in Claude Code or Codex.
                   Otherwise a tool's exact name: an SDK agent's
                   function (run_shell) or an MCP tool. Repeat for more.
  --said "QUOTE"   Optional: your words when you corrected the agent.
  --stop-where-cannot-ask
                   In Codex, which cannot ask, stop the call instead of
                   warning.
  --yes            Write without asking you to confirm (for a script you
                   run yourself).

Example:
  agentx rule add "run_suites.py" --why "the suites run once, at the end, with my go-ahead"
"""


def _say(text):
    """One indented paragraph, wrapped at the screens' 75-column fence. A path or a command
    longer than the line is never split."""
    import textwrap
    for line in textwrap.wrap(text, 75, initial_indent="   ", subsequent_indent="   ",
                              break_long_words=False, break_on_hyphens=False):
        print(line)


def _confirm(lines, assume_yes):
    """A person's yes. With no terminal and no --yes, nothing is written: an agent shelling
    out must not be able to add or remove a rule on its own."""
    import sys
    print()
    for line in lines:
        # A line starting with two spaces is a command: printed whole, never wrapped.
        if line.startswith("  "):
            print("   " + line)
        else:
            _say(line)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        _say("Not written: a team rule needs a person, and there is no terminal here to "
             "ask. Run it yourself, or add --yes from a script you run.")
        return False
    try:
        yes = input("   Proceed? [y/N]: ").strip().lower() in ("y", "yes")
    except EOFError:
        # A Claude Code `!` command reads as a terminal and gives no input (walk).
        print()
        _say("No answer came, so nothing changed. A ! command in Claude Code cannot answer "
             "this; add --yes, or run it in a terminal.")
        return False
    except KeyboardInterrupt:
        yes = False
    if not yes:
        print("   Nothing changed.")
    return yes


def _times(n):
    return "once" if n == 1 else "%d times" % n


def _local_date(stamp):
    """The date a stored UTC time falls on in this machine's time zone, or the text as stored."""
    from datetime import datetime
    try:
        if isinstance(stamp, (int, float)):
            return datetime.fromtimestamp(stamp).date().isoformat()
        return datetime.fromisoformat(str(stamp)).astimezone().date().isoformat()
    except Exception:
        return str(stamp or "an unknown date")[:10]


def _describe(rule):
    tools = ", ".join("any shell command" if t == SHELL else "a call to the tool '%s'" % t
                      for t in rule["tools"])
    return "%s that contains \"%s\"" % (tools, "\", \"".join(rule["match"]))


def _sdk_tools_seen(limit=5):
    """The tool names this project's record (`agentx audit`'s ledger) holds from an SDK agent,
    most-called first: not the hook's (it records only `Bash`, `PowerShell` and `mcp__...`, so
    those names are left out) and not our own demo's or examples'. [] when there is no record or
    it cannot be read: this feeds a hint, never a refusal.

    WHY. A rule on `shell` checks the coding agents' shell tools by their names. An SDK agent's
    tools reach the gateway under the developer's own function names (`run_shell`), which no
    `shell` rule checks, and before this nothing said so."""
    try:
        from . import db
        rows = db.get_tool_call_counts()       # db's reader: it leaves out server events
    except Exception:
        return []
    counts = {}
    from .hook import HOOK_AGENT_IDS
    for agent, tool, n in rows:
        # agentx-mcp writes its servers' tool names here too, bare, under its own id: those
        # are MCP tools Claude Code asks about, not an SDK agent's (scoped review).
        if (db.is_our_agent(agent) or agent == db.MCP_PROXY_AGENT_ID or agent in HOOK_AGENT_IDS
                or not str(tool).strip() or tool in SHELL_TOOLS
                or str(tool).startswith("mcp__")):
            continue
        counts[tool] = counts.get(tool, 0) + n
    return [t for t, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))][:limit]


def _sdk_tools_hint(tools):
    """The lines saying a rule's tools leave out SDK tools this project has seen, or []."""
    missed = [t for t in _sdk_tools_seen() if t not in tools]
    if not missed or any(t != SHELL for t in tools):
        return []
    # Where a named tool IS checked, said with it: a gateway reading this project's file, or one
    # sent a copy with `agentx rule push`. The SDK alone reads no team rule (scoped review: "name
    # it" read as "and then it is checked").
    return ["This rule does not cover your SDK agent's %s %s (from this project's record): "
            "shell means a Bash or PowerShell command in Claude Code or Codex. To cover one, "
            "add --tool %s. A gateway you run from this project checks it, and the hosted "
            "gateway does once you send it with agentx rule push; the SDK on its own does not."
            % ("tool" if len(missed) == 1 else "tools", ", ".join(missed), missed[0])]


def _installed_here():
    """(Claude Code, Codex): whether AgentX's check is installed in this project for each."""
    from . import hook
    root = _anchored_root()
    found = []
    for path in (os.path.join(root, ".claude", "settings.local.json"),
                 os.path.join(root, ".codex", "hooks.json")):
        settings, err = hook._read_settings(path)
        found.append(bool(not err and settings
                          and hook._count_ours(settings.get("hooks") or {})))
    return tuple(found)


# The gateway release that takes `PUT /v1/rules`; an older one answers 404.
_RULES_ROUTE_SINCE = "2026.10.26.2"
# What the add and remove screens say when a gateway key is set: a gateway sent a copy checks
# that copy, not this file (`_team_rules_source_path`), so a change reaches it only by a push.
_PUSH_HINT = ("If you have sent team rules to your gateway, it checks that copy until you send "
              "them again: agentx rule push")


def _shell_only(rule):
    return all(t in (SHELL,) + SHELL_TOOLS for t in rule["tools"])


def _gateway_view(gateway_url, key):
    """GET /v1/rules: the gateway's answer as a dict, "old" for a gateway with no such route, the
    status code of any other refusal, "unreadable" for a 200 whose body is not the answer, or
    None when it did not answer at all. The last two print different lines: "did not answer"
    is false of a gateway that answered."""
    import requests
    from .cli import _remote_json
    try:
        res = requests.get("%s/v1/rules" % gateway_url,
                           headers={"Authorization": "Bearer %s" % key}, timeout=3.0)
    except Exception:
        return None
    if res.status_code == 404:
        return "old"
    if res.status_code != 200:
        return res.status_code
    try:
        view = _remote_json(res)
    except Exception:
        return "unreadable"
    return view if isinstance(view, dict) else "unreadable"


def _gateway_line(gateway_url, key, rules, key_name="AGENTX_API_KEY"):
    """The `list` screen's last line: whether the gateway checks these same rules. `key_name` is
    the setting the key came from, for the line a refused key gets."""
    view = _gateway_view(gateway_url, key)
    if view is None:
        # "did not answer", not "could not be read": a key in the project's .env with nothing
        # running at that address reads as a fault in the gateway otherwise.
        _say("Your gateway at %s did not answer, so it is unknown which team rules it checks."
             % gateway_url)
        return
    if view == "unreadable":
        _say("Your gateway at %s answered, but its reply could not be read, so it is unknown "
             "which team rules it checks." % gateway_url)
        return
    if view == "old":
        # Not "checks no team rules": a 2026.10.26.1 gateway beside a project reads its own file;
        # what it lacks is this question and the push (walk audit).
        _say("Your gateway at %s cannot say which team rules it checks, and does not take them "
             "from agentx rule push: it is older than %s." % (gateway_url, _RULES_ROUTE_SINCE))
        return
    if isinstance(view, int):
        # Said apart from "could not be read" (code review): a refused key has a fix.
        _say("Your gateway at %s answered %d, so it is unknown which team rules it checks%s."
             % (gateway_url, view, ": it did not accept your %s" % key_name
                if view in (401, 403) else ""))
        return
    if not view.get("readable", True):
        _say("Your gateway's copy cannot be read, so it holds no call for a team rule. %s"
             % (view.get("error") or ""))
        return
    # Active rules only: a switched-off rule holds nothing (code review). An older answer
    # without the count falls back to every rule.
    theirs = view.get("active", view.get("rules")) or 0
    ours = sum(1 for r in rules if r.get("active", True))
    same = view.get("fingerprint") == team_rules_fingerprint(rules)
    if theirs and not os.path.exists(team_rules_path()):
        # Nothing here to send, so `agentx rule push` is not the advice (code review). "Sent"
        # only for a pushed copy: a gateway beside a project reads its own file (scoped review).
        # The file looked for is named: AGENTX_TEAM_RULES_FILE can point away from this folder
        # (scoped review 2).
        if view.get("source") == "pushed":
            _say("Your gateway at %s checks %s, sent from another copy of this project. There is "
                 "no team rules file at %s to compare or send."
                 % (gateway_url, _count(theirs), team_rules_path()))
        else:
            _say("Your gateway at %s checks %s from a team rules file of its own. There is no "
                 "team rules file at %s to compare."
                 % (gateway_url, _count(theirs), team_rules_path()))
    elif not theirs:
        _say("Your gateway at %s checks no team rules.%s"
             % (gateway_url, " Send these: agentx rule push" if ours and not same else ""))
    elif same:
        _say("Your gateway at %s checks these same rules%s." % (
            gateway_url, " (this file)" if view.get("source") == "local file" else ""))
    else:
        _say("Your gateway at %s checks a different set (%s). To send this file in its place: "
             "agentx rule push" % (gateway_url, _count(theirs)))


def _count(n):
    return "1 rule" if n == 1 else "%d rules" % n


def _push(gateway_url, api_key, admin_key, admin_refusal):
    """`agentx rule push`: send this file to the gateway, which replaces its copy with it.

    Sends AGENTX_ADMIN_KEY when it is set, as `agentx allowlist push` does: a gateway with admin
    keys refuses rules pushed with the agent's key, since an empty push switches every rule off."""
    import requests
    from .cli import _remote_json
    from .decorators import _sanitize_detail
    shown = team_rules_path()        # the file read and sent, AGENTX_TEAM_RULES_FILE included
    if admin_refusal:
        print("Nothing was sent. %s" % admin_refusal)
        return 1
    key = admin_key or api_key
    if not key:
        _say("Nothing was sent: there is no AGENTX_API_KEY, so there is no gateway to send the "
             "rules to. Without one, Claude Code and Codex check this file on this machine.")
        return 1
    if not os.path.exists(team_rules_path()):
        _say("No %s yet, so there is nothing to send. Add a rule first: agentx rule add "
             "\"PHRASE\" --why \"REASON\"" % shown)
        return 1
    rules = read_team_rules()                         # a damaged file raises: nothing is sent
    try:
        res = requests.put("%s/v1/rules" % gateway_url, json={"version": _FILE_VERSION,
                                                               "rules": rules},
                           headers={"Authorization": "Bearer %s" % key}, timeout=5.0)
    except Exception as err:
        print("Could not reach your gateway at %s, so nothing was sent: %s" % (gateway_url, err))
        return 1
    if res.status_code == 404:
        # "a push of", not "team rules": a 2026.10.26.1 gateway beside a project checks its file.
        _say("Nothing was sent: your gateway at %s does not take a push of team rules (it is "
             "older than %s)." % (gateway_url, _RULES_ROUTE_SINCE))
        return 1
    if res.status_code != 200:
        try:
            detail = _remote_json(res).get("detail") or res.text
        except Exception:
            detail = res.text
        _say("Your gateway refused the rules (%d), so its copy is unchanged: %s"
             % (res.status_code, _sanitize_detail(str(detail), limit=300)))
        return 1
    try:
        got = _remote_json(res)
        if not isinstance(got, dict):
            raise ValueError("not an object")
    except Exception:
        # The gateway said yes, so the rules may well be stored: never "Nothing was sent" here
        # (code review: a proxy's empty 200 read as an unchanged copy).
        _say("Your gateway answered that it took the rules, but its answer could not be read, so "
             "it is not known which rules it now checks. To see: agentx rule list")
        return 1
    active = [r for r in rules if r.get("active", True)]
    off = len(rules) - len(active)
    # The count and the gateway first, the file after: a path wraps onto its own line (walk).
    if not active:
        _say("Sent %s to %s, from %s. None is switched on, so that gateway now checks none."
             % (_count(len(rules)), gateway_url, shown))
    else:
        _say("Sent %s to %s%s, from %s." % (
            _count(len(rules)), gateway_url,
            " (%d switched off)" % off if off else "", shown))
        on_match = got.get("on_match") or {}
        if on_match.get("held", True):
            _say("From now on that gateway holds an SDK agent's call that matches one, for a "
                 "person to answer with agentx holds.")
        else:
            _say("From now on that gateway stops an SDK agent's call that matches one. %s"
                 % (on_match.get("why") or ""))
        shell = sum(1 for r in active if _shell_only(r))
        if shell:
            # A coding agent's shell command never reaches a gateway yet (the hook decides on the
            # machine). An SDK tool named Bash or PowerShell does, so the line says what "shell"
            # means rather than that the rule reaches no gateway (code review).
            # Counted over the switched-on rules, and said so when some are off, since the line
            # above counts every rule sent (scoped review).
            if len(active) == 1:
                lead = "The one switched on checks" if off else "That rule checks"
            elif shell == len(active):
                lead = ("All %d switched on check" % shell) if off else "All of them check"
            else:
                lead = ("%d of the %d switched on check" % (shell, len(active))) if off \
                    else "%d of them check" % shell
            _say("%s shell commands, meaning a tool named Bash or PowerShell. Claude Code's and "
                 "Codex's do not go through a gateway, so for those AgentX asks on each machine "
                 "with its hook." % lead)
    local_fp = team_rules_fingerprint(rules)
    same = got.get("fingerprint") == local_fp
    _say("Fingerprint %s%s" % (got.get("fingerprint"), ", the same as this file." if same else
         ", but this file's is %s: run agentx rule list to compare." % local_fp))
    return 0 if same else 1


def main(args, gateway_url=None, api_key=None, admin_key=None, admin_refusal=None):
    """`agentx rule add | list | remove | push`. Returns an exit code. The gateway address and
    keys are the CLI's (`agentx` resolves them); without a key, nothing here calls a gateway."""
    args = list(args or [])
    if not args or args[0] in ("-h", "--help", "help"):
        print(_USAGE)
        return 0 if args else 1
    assume_yes = "--yes" in args
    args = [a for a in args if a != "--yes"]
    sub, args = args[0], args[1:]
    if sub not in ("add", "list", "remove", "push"):
        print(_USAGE)
        return 1
    read_key = api_key or admin_key                   # either key reads the gateway's copy
    key_name = "AGENTX_API_KEY" if api_key else "AGENTX_ADMIN_KEY"
    try:
        if sub == "push":
            if args:
                print(_USAGE)
                return 1
            return _push(gateway_url, api_key, admin_key, admin_refusal)
        if sub == "list":
            if args:
                print(_USAGE)
                return 1
            rules = read_team_rules()
            if not rules:
                print("No team rules yet. Add one: agentx rule add \"PHRASE\" --why \"REASON\"")
                if read_key and gateway_url:
                    _gateway_line(gateway_url, read_key, rules, key_name)
                return 0
            print("Team rules in %s:" % team_rules_path())
            for r in rules:
                uses = rule_use_counts(r["id"])
                # What the rule does leads; the id is what `remove` takes, so it sits beside
                # who added it rather than heading the entry (copy pass).
                print("\n  %s %s" % ("Asks before" if r.get("active", True)
                                     else "Switched off. It asked before", _describe(r)))
                # What happened comes right under what the rule checks; why and who follow.
                if uses is None:
                    print("    on this machine: could not read %s" % uses_path())
                elif uses["since"] is None:
                    print("    on this machine: not used yet")
                else:
                    # Where it could not ask is a place: Codex warns (or stops, when the rule
                    # says so), and Claude Code's auto mode stops.
                    asked = []
                    if uses["ask"]:
                        asked.append("asked you %s" % _times(uses["ask"])
                                     + (" (you let it run %s)" % _times(uses["ran"])
                                        if uses["ran"] else ""))
                    if uses["warn"]:
                        asked.append("warned %s in Codex" % _times(uses["warn"]))
                    if uses["stop"]:
                        asked.append("stopped the call %s without asking (Codex, or Claude "
                                     "Code in a mode that does not ask, such as auto)"
                                     % _times(uses["stop"]))
                    import textwrap
                    print("\n".join(textwrap.wrap(
                        "on this machine since %s: %s" % (_local_date(uses["since"]),
                                                          "; ".join(asked)),
                        75, initial_indent="    ", subsequent_indent="      ",
                        break_long_words=False, break_on_hyphens=False)))
                print("    why: %s" % r["why"])
                if r.get("said"):
                    print("    you said: \"%s\"" % r["said"])
                print("    added by %s on %s (id %s)" % (r.get("owner") or "nobody named",
                                                      _local_date(r.get("added_at")), r["id"]))
            if read_key and gateway_url:
                print()
                _gateway_line(gateway_url, read_key, rules, key_name)
            return 0
        if sub == "remove":
            if len(args) != 1:
                print(_USAGE)
                return 1
            rule_id = args[0]
            target = next((r for r in read_team_rules() if r["id"] == rule_id), None)
            if target is None:
                print("No team rule has the id %s. See them: agentx rule list" % rule_id)
                return 1
            if not _confirm(["About to remove %s: it asks before %s." % (target["id"],
                                                                        _describe(target)),
                             "Why: %s" % target["why"],
                             "Added by %s on %s" % (target.get("owner") or "nobody named",
                                                    _local_date(target.get("added_at")))],
                            assume_yes):
                return 1
            remove_team_rule(rule_id)
            _say("Removed %s. Claude Code stops asking about it from its next call; commit the "
                 "file so teammates stop too." % rule_id)
            if read_key:
                _say(_PUSH_HINT)
            return 0

        phrases, tools, why, said, stop = [], [], None, None, False
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--why", "--said", "--tool"):
                if i + 1 >= len(args):
                    print(_USAGE)
                    return 1
                value = args[i + 1]
                if a == "--why":
                    why = value
                elif a == "--said":
                    said = value
                else:
                    tools.append(value)
                i += 2
                continue
            if a == "--stop-where-cannot-ask":
                stop = True
            elif a.startswith("--"):
                print(_USAGE)
                return 1
            else:
                phrases.append(a)
            i += 1
        if not phrases or not why:
            # Say what is missing; the whole help hid it (copy pass).
            print("A team rule needs the words to look for and a reason, for example:")
            print("  agentx rule add \"run_suites.py\" --why \"the suites run once, at the end\"")
            return 1
        tools = list(dict.fromkeys(tools))          # `--tool shell` twice is one tool
        preview = {"tools": tools or [SHELL], "match": phrases}
        same = existing_team_rule(preview["tools"], phrases, read_team_rules())
        if same is not None:
            _say("This is already a team rule: it asks before %s (added by %s). See it: "
                 "agentx rule list" % (_describe(same), same.get("owner") or "nobody named"))
            return 1
        # Which door checks it. A rule naming only tools this project's record shows an SDK
        # agent calling is checked by a gateway, never by Claude Code or Codex (scoped review:
        # the screen sent an SDK reader to install the hook).
        shell_kind = (SHELL,) + SHELL_TOOLS        # the hook hands a command back for these
        all_shell = all(t in shell_kind for t in preview["tools"])
        named = [t for t in preview["tools"] if t not in shell_kind]
        sdk_only = bool(named) and len(named) == len(preview["tools"]) \
            and set(named) <= set(_sdk_tools_seen(limit=1000))
        # A named tool the record has not shown an SDK agent calling may be either kind; say both
        # doors rather than guess (scoped review: a fresh project's run_shell read as Claude's).
        either = [t for t in named if not t.startswith("mcp__")] if not sdk_only else []
        quoted = "\"%s\"" % "\", \"".join(phrases)
        # One real example of how wide the match is, not a description of matching (copy pass).
        # Built from EVERY phrase, since a rule needs all of them; the command is a line of its
        # own (two leading spaces), which `_confirm` never wraps.
        if all_shell:
            example = ["A command that only mentions %s asks too, for example:"
                       % ("it" if len(phrases) == 1 else "them"),
                       "  git commit -m \"notes on %s\"" % " ".join(phrases)]
        else:
            example = ["A call that only mentions %s in an argument %s too."
                       % (quoted, "is held" if sdk_only else "asks")]
        if sdk_only:
            lines = ["About to add a team rule. A gateway you run from this project will hold "
                     "%s, for you to answer with agentx holds." % _describe(preview)] + example + [
                     "Why: %s" % why,
                     "The hosted gateway checks it once you send it with agentx rule push; the "
                     "SDK on its own does not check team rules."]
        else:
            lines = ["About to add a team rule. Claude Code will ask you before %s."
                     % _describe(preview)] + example + ["Why: %s" % why]
            if either:
                # "checks", not "holds": where nobody can answer a hold, a gateway stops the call,
                # and the push screen says which (scoped review).
                lines.append("If %s is an SDK agent's function rather than an MCP tool, a gateway "
                             "you run from this project, or one you send the rules to with "
                             "agentx rule push, checks the call instead: it holds it for agentx "
                             "holds, or stops it where nobody can answer a hold."
                             % " or ".join("'%s'" % t for t in either))
            if all_shell:
                lines.append("In a mode that does not ask, such as auto, AgentX stops the call "
                             "and gives you the command to run yourself.")
            elif any(t in shell_kind for t in preview["tools"]):
                lines.append("In a mode that does not ask, such as auto, AgentX stops the call: "
                             "a shell command is given back for you to run yourself; for a "
                             "tool, leave that mode and ask again.")
            else:
                lines.append("In a mode that does not ask, such as auto, AgentX stops the call; "
                             "to let it run, leave that mode and ask again.")
            if stop:
                lines.append("In Codex, which cannot ask, the call is stopped.")
            else:
                lines.append("In Codex, which cannot ask, you see a warning and the call runs.")
        # Before the person's yes, so they can answer no and add the tool's name instead.
        lines += _sdk_tools_hint(preview["tools"])
        if not _confirm(lines, assume_yes):
            return 1
        rule = add_team_rule(tools or [SHELL], phrases, why, said=said,
                             where_ask_unsupported="stop" if stop else "warn")
        _say("Added %s, saved in %s. To remove it: agentx rule remove %s"
             % (rule["id"], team_rules_path(), rule["id"]))
        _say("Added by: %s" % (rule["owner"] + " (your git name)" if rule.get("owner")
                               else "nobody named (git has no user.name here)"))
        if sdk_only:
            _say("Commit the file, and a gateway run from a teammate's copy of the project "
                 "checks it too.")
            if read_key:
                _say(_PUSH_HINT)
            return 0
        _say("Commit the file, and teammates who use the AgentX hook get the same rule.")
        if read_key:
            _say(_PUSH_HINT)
        claude, codex = _installed_here()
        # In AgentX's own repository a plain install is refused, so the command says --internal.
        from .hook import install_command_here
        if claude:
            _say("Claude Code checks it in this project from its next call.")
        else:
            _say("Claude Code does not check it here yet. Run: %s"
                 % install_command_here(project=_anchored_root()))
        if not codex:
            _say("For Codex too: %s" % install_command_here("--codex", project=_anchored_root()))
        return 0
    except ValueError as err:
        print("%s: %s" % ("Could not read the team rules" if sub == "list" else
                          "Nothing was sent" if sub == "push" else "Nothing changed", err))
        if team_rules_state() == "damaged":
            print("   Fix the file by hand (a merge conflict leaves <<<<<<< lines in it), or put "
                  "back the copy git has: git restore %s" % team_rules_path())
        return 1


def reason_text(rule):
    """The sentence the person asked, and the agent, are shown. The harness frames it (Claude
    Code: "requires confirmation for this command"), so it says only which rule and why."""
    if rule.get("builtin"):
        # AgentX's own check (the hook's rule-change rule): nobody added it, and `found` says
        # what the command does, which its match words may not appear in.
        text = "AgentX: %s. This call %s." % (rule["why"].rstrip("."), rule["found"])
        return text + (" " + rule["note"] if rule.get("note") else "")
    who = (", added by %s" % rule["owner"]) if rule.get("owner") else ""
    return "AgentX team rule%s: %s. This call contains \"%s\"." % (
        who, rule["why"].rstrip("."), "\", \"".join(rule["match"]))
