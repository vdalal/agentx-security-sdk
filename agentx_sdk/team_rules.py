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
import re
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
# A rule may name an argument and the number it holds at, one number or one per environment,
# and for money a currency. 🔴 MIRROR of the gateway's `_check_team_rule_number`: the same rule
# is accepted or refused on both doors.
# `\Z`, not `$`: `$` also matches before a trailing newline, so "prod\n" passed.
ENV_RE = re.compile(r"^[a-z0-9_-]{1,32}\Z")
ARGUMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
CURRENCY_RE = re.compile(r"^[A-Za-z]{2,10}\Z")
UNITS = ("cents",)
NUMBER_KEYS = ("argument", "hold_at", "currency", "currency_field", "unit", "recipient")


LIMIT_MAX = 10 ** 15


def _limit_ok(n):
    """A `hold_at` number: an int or float above 0 and below 10**15, never a bool. The ceiling
    keeps the number a hold shows a number; no count or amount a rule guards comes near it."""
    return (isinstance(n, (int, float)) and not isinstance(n, bool)
            and n == n and 0 < n < LIMIT_MAX)


def _check_number(r, p, rid):
    """The number keys of a rule, checked. Raises ValueError naming the rule. A rule with none
    of them is a rule on phrases alone."""
    if not any(k in r for k in NUMBER_KEYS):
        return
    arg = r.get("argument")
    if not isinstance(arg, str) or not ARGUMENT_RE.match(arg) or len(arg) > 200:
        raise ValueError("%s: rule %s needs \"argument\", the name of the argument it reads "
                         "(a dotted path reaches inside an object)" % (p, rid))
    if "hold_at" not in r:
        raise ValueError("%s: rule %s names an argument and needs \"hold_at\", the number it "
                         "holds at" % (p, rid))
    hold_at = r["hold_at"]
    if isinstance(hold_at, dict):
        if not hold_at or not all(isinstance(k, str) and ENV_RE.match(k) and _limit_ok(v)
                                  for k, v in hold_at.items()):
            raise ValueError("%s: rule %s has a hold_at that is not a number per environment "
                             "(lower-case names, each a number above 0 and below "
                             "1,000,000,000,000,000)" % (p, rid))
    elif not _limit_ok(hold_at):
        raise ValueError("%s: rule %s has a hold_at that is not a number above 0 and below "
                         "1,000,000,000,000,000" % (p, rid))
    cur = r.get("currency")
    if "currency" in r and (not isinstance(cur, str) or not CURRENCY_RE.match(cur)):
        raise ValueError("%s: rule %s has a currency that is not a code such as USD" % (p, rid))
    for key in ("currency_field", "unit", "recipient"):
        if key in r and "currency" not in r:
            raise ValueError("%s: rule %s has %s, which needs \"currency\"" % (p, rid, key))
    # `recipient`: the argument naming who is paid, so payments to one recipient add up on the
    # gateway. Read only there.
    for key in ("currency_field", "recipient"):
        v = r.get(key)
        if key in r and (not isinstance(v, str) or not ARGUMENT_RE.match(v) or len(v) > 200):
            raise ValueError("%s: rule %s has a %s that is not an argument name" % (p, rid, key))
    if "unit" in r and r["unit"] not in UNITS:
        raise ValueError("%s: rule %s has unit %r; only \"cents\" is read" % (p, rid, r["unit"]))


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
    _check_number(r, p, rid)
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


# What the file is, said in the file: it is committed and read by every teammate, so a reader who
# has never heard of AgentX learns what made it and where to read about it. Readers look only at
# `rules`, so these lines change nothing for an older SDK. No SDK version: teammates on
# different versions would rewrite that line on every save.
_FILE_SCHEMA = "agentx.team-rules/1"
_FILE_ABOUT = ("Team rules for AgentX (https://agentx-core.com/docs): each asks a person before a "
               "matching agent call runs. Change them with agentx rule add or agentx rule remove; "
               "agentx rule push sends them to your gateway.")


def _write(p, rules):
    """Whole file via a temp file and rename, so a crash leaves the old file."""
    parent = os.path.dirname(p)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"about": _FILE_ABOUT, "schema": _FILE_SCHEMA, "version": _FILE_VERSION,
                   "rules": rules}, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, p)


def _git_user():
    try:
        out = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True,
                             timeout=5)
        return out.stdout.strip() or None
    except Exception:
        return None


def _added(r):
    """ "added by Dana", or "added" when the rule names nobody: never "added by nobody named".
    The website's Rules tab says it the same way."""
    return "added by %s" % r["owner"] if r.get("owner") else "added"


def add_team_rule(tools, match, why, *, said=None, owner=None, where_ask_unsupported="warn",
                  path=None, argument=None, hold_at=None, currency=None, currency_field=None,
                  unit=None, recipient=None):
    """Write one active rule and return it. Raises ValueError, with nothing written, on a rule
    that cannot be stored or a file that cannot be read. `argument` and `hold_at` make it a rule
    with a number: it holds a call whose argument is at or above the number."""
    p = team_rules_path(path)
    rules = read_team_rules(p)
    same = existing_team_rule(tools or [SHELL], match, rules, argument=argument)
    if same is not None:
        # A switched-off one says so: "already a team rule" alone reads as in force, and the
        # person is left wondering why the call still runs.
        if not same.get("active", True):
            raise ValueError("this team rule is already in the file, switched off (%s, %s). To "
                             "add it again, remove that one first: agentx rule remove %s"
                             % (same["id"], _added(same), same["id"]))
        raise ValueError("this is already a team rule (%s, %s). See it: agentx rule list"
                         % (same["id"], _added(same)))
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
    if argument is not None:
        rule["argument"] = argument
    if hold_at is not None:
        rule["hold_at"] = hold_at
    for key, value in (("currency", currency), ("currency_field", currency_field),
                       ("unit", unit), ("recipient", recipient)):
        if value is not None:
            rule[key] = value
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


def asks_before(tool, words=None):
    """What a team rule on one tool does, in the words `agentx review` shows before the key and
    stores as the rule's reason (what the person and the agent read when a call is held)."""
    said = "a person approves each call to '%s'" % tool
    if words:
        said += " that contains \"%s\"" % words
    return said + " before it runs"


def add_tool_rule(tool, words=None, gateway_url=None, key=None):
    """Add the team rule `agentx review` offers for one tool: every call to it, or only those
    that also contain `words`. The tool's name is the first phrase because the text a team rule
    is matched against, by the gateway and the hook alike, starts with the tool's name for any
    tool that is not a shell. Agrees the gateway's copy first, as `agentx rule add` does. Raises
    ValueError, with nothing written, as `add_team_rule` does."""
    _agree_before_a_change(gateway_url, key)
    words = str(words or "").strip()
    return add_team_rule([tool], [tool] + ([words] if words else []), asks_before(tool, words))


def existing_team_rule(tools, match, rules, argument=None):
    """The rule in `rules` that checks the same tools for the same phrases (any order, any
    case) and reads the same argument (None for a rule on phrases alone), or None. Its reason
    and its number may differ; the match is what decides what gets asked. Without the argument
    in the key, a number rule beside an every-call rule on one tool was refused as the same
    rule. Mirror of the website's `sameRule`."""
    def key(ts, ms, arg):
        return (frozenset(str(t).strip() for t in ts if str(t).strip()),
                frozenset(str(m).strip().lower() for m in ms if str(m).strip()),
                arg or None)
    wanted = key(tools, match or [], argument)
    return next((r for r in rules
                 if key(r["tools"], r["match"], r.get("argument")) == wanted), None)


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


def match_team_rule(tool_name, call_text, path=None, arguments=None, environment=None):
    """The first active rule this call matches, or None. `call_text` is what the call says (a
    shell command, or an MCP call's name and argument values). Never raises: an unreadable
    file matches nothing here, and `team_rules_state` is what reports it."""
    try:
        return match_rules(tool_name, call_text, read_team_rules(path), arguments=arguments,
                           environment=environment)
    except Exception:
        return None


# ---- a rule with a number ---------------------------------------------------------------------
# 🔴 MIRROR of the gateway's readers of the same name (`_team_rule_hold_at`,
# `_team_rule_number_read`, `_team_rule_money_read`, `_walk_team_rules`, `_team_rule_number_says`):
# the same call is held by the same rule, for the same reason, on both doors.

SIGNS = "$€£¥₹"
# Text is read only when it can mean ONE number; a separator followed by exactly three digits
# and nothing after ("450.000", "1,000") is a thousands mark in one country and a decimal point
# in another, so it is held, as an unreadable value is. ASCII digits only.
_PLAIN_RE = re.compile(r"^\d+(\.\d+)?\Z", re.ASCII)
_TWO_WAYS_RE = re.compile(r"^[1-9]\d{0,2}\.\d{3}\Z", re.ASCII)
_GROUPED_RE = re.compile(r"^[1-9]\d{0,2}(?:(?:,\d{3}){2,}(?:\.\d+)?|,\d{3}\.\d+)\Z", re.ASCII)
TOO_LARGE = "a number too large to show"


def environment_here():
    """`AGENTX_ENVIRONMENT` when it is a short lower-case name, else None."""
    raw = os.environ.get("AGENTX_ENVIRONMENT", "")
    return raw if raw and ENV_RE.match(raw) else None


def is_money(rule):
    return "argument" in rule and "currency" in rule


def hold_at_for(rule, environment):
    """(the number `rule` holds at in `environment`, the environment it is for). No environment,
    or one the map does not name: the lowest, with None."""
    hold_at = rule["hold_at"]
    if not isinstance(hold_at, dict):
        return hold_at, None
    if environment in hold_at:
        return hold_at[environment], environment
    return min(hold_at.values()), None


def _text_number(s):
    from .rules import _coerce_only_when_number
    if _PLAIN_RE.match(s) and not _TWO_WAYS_RE.match(s):
        return _coerce_only_when_number(s)
    if _GROUPED_RE.match(s):
        return _coerce_only_when_number(s.replace(",", ""))
    return None


def number_read(rule, arguments):
    """(number, None), or (None, why) when the value cannot be read: the call is then held."""
    from .rules import _ONLY_WHEN_ABSENT, _coerce_only_when_number, _only_when_value
    try:
        value = _only_when_value(arguments if isinstance(arguments, dict) else {},
                                 rule["argument"])
        if value is _ONLY_WHEN_ABSENT:
            return None, "it was not passed"
        if value is None:
            return None, "it was empty"
        if isinstance(value, (list, tuple)):
            if is_money(rule):
                return None, "it is a list, not one amount"
            return len(value), None
        if isinstance(value, str):
            s = value.strip()
            if s and s[0] in SIGNS:
                s = s[1:].strip()
            elif s and s[-1] in SIGNS:
                s = s[:-1].strip()
            if s[:1] in ("-", "+"):
                s = s[1:].strip()
            num = _text_number(s)
            if num is None:
                return None, ("it is not written as one plain number"
                              if re.match(r"^[\d.,]+\Z", s) else "it is not a number")
        else:
            num = _coerce_only_when_number(value)
        if num is None:
            return None, "it is not a number"
        try:
            num = abs(float(num))
        except OverflowError:
            num = 1e308
        if rule.get("unit") == "cents":
            num = num / 100
        return (int(num) if num < 1e15 and num.is_integer() else num), None
    except Exception:
        return None, "it could not be read"


def money_read(rule, arguments, environment):
    """What a money rule reads: the amount, why not, whether the reason is the currency, the
    currency, and the number it holds at. The call's currency is never echoed."""
    from .rules import _ONLY_WHEN_ABSENT, _only_when_value
    at, env = hold_at_for(rule, environment)
    value, why = number_read(rule, arguments)
    currency = rule["currency"].upper()
    currency_problem = False
    if why is None and rule.get("currency_field"):
        raw = _only_when_value(arguments if isinstance(arguments, dict) else {},
                               rule["currency_field"])
        code = raw.strip() if isinstance(raw, str) else ""
        if raw is _ONLY_WHEN_ABSENT or raw is None or (isinstance(raw, str) and not code):
            why, currency_problem = "%s was not passed" % rule["currency_field"], True
        elif not CURRENCY_RE.match(code):
            why, currency_problem = "%s was not a currency code" % rule["currency_field"], True
        elif code.upper() != currency:
            why, currency_problem = "it is not in %s, the currency this rule is in" % currency, True
    return {"value": value, "why": why, "at": at, "environment": env, "currency": currency,
            "currency_problem": currency_problem}


def match_rules(tool_name, call_text, rules, arguments=None, environment=None):
    """The first active rule in `rules` that holds this call, or None, in file order. The one
    matcher: the file's rules and the rules pulled from a gateway go through it alike, and the
    gateway's `_walk_team_rules` is its mirror. A rule on phrases holds when they match. A
    number rule holds when its argument is at or above its number for `environment`, or cannot
    be read; below, the next rule is tried. A number or money rule comes back as a copy carrying
    `_number` or `_money`, what was read, for the sentence the person is shown. Never raises."""
    try:
        names = _tool_names(tool_name)
        text = str(call_text or "").lower()
        # A phrase that is this call's full MCP name (`mcp__github__delete_repo`, as /app and
        # `agentx review` saved it before the bare name) is read as the bare name: the hook's text
        # starts with `delete_repo`, so the full name never matched and the rule was silently off.
        # The gateway's text has the full name, which contains the bare one, so it agrees.
        full, lead = str(tool_name).lower(), _leading_name(tool_name).lower()
        for r in rules:
            if not r.get("active", True):
                continue
            if not names & set(r["tools"]):
                continue
            if not all((lead if m.lower() == full else m.lower()) in text for m in r["match"]):
                continue
            if "argument" not in r:
                return r
            if is_money(r):
                read = money_read(r, arguments, environment)
                if read["why"] is not None or read["value"] >= read["at"]:
                    return dict(r, _money=read)
                continue
            at, env = hold_at_for(r, environment)
            value, why = number_read(r, arguments)
            if why is not None or value >= at:
                return dict(r, _number={"value": value, "why": why, "at": at, "environment": env})
    except Exception:
        return None
    return None


def _number_text(n):
    """A number as a person reads it. Never raises."""
    if isinstance(n, bool):
        return "a value that is not a number"
    try:
        n = float(n)
    except OverflowError:
        return TOO_LARGE
    except (TypeError, ValueError):
        return "a value that is not a number"
    if n != n:
        return "a value that is not a number"
    if n in (float("inf"), float("-inf")) or abs(n) >= 1e21:
        return TOO_LARGE
    return "{:,.2f}".format(n) if not n.is_integer() else "{:,.0f}".format(n)


def number_says(rule):
    """The number sentence of a number or money rule's match, or "". The same words as the
    gateway's held-call reason."""
    read = rule.get("_number") or rule.get("_money")
    if not read:
        return ""
    # "Its count is 50": a sentence opening on a bare argument name read as code.
    arg, money = "Its " + rule["argument"], "_money" in rule
    if read["why"] is not None:
        if money and read.get("currency_problem"):
            return "%s could not be compared: %s, so this call waits for a person." % (
                arg, read["why"])
        return "%s could not be read (%s), so this call waits for a person." % (arg, read["why"])
    unit = (" " + read["currency"]) if money else ""
    at, value = _number_text(read["at"]), _number_text(read["value"])
    is_value = "is too large to show" if value == TOO_LARGE else "is %s%s" % (value, unit)
    if read["environment"]:
        return "%s %s, at or above the %s%s set for %s." % (
            arg, is_value, at, unit, read["environment"])
    if isinstance(rule.get("hold_at"), dict):
        return ("%s %s, at or above %s%s, the lowest this rule sets: this call named no "
                "environment the rule lists." % (arg, is_value, at, unit))
    return "%s %s, at or above the %s%s set." % (arg, is_value, at, unit)


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
# How the uses file is decoded: a byte that is not UTF-8 (the file sits where the agent can write)
# spoils its own line, never the read of the whole file (see `_report_state`).
UNTRUSTED_TEXT = "replace"
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
            # Its own try: on Windows the replace fails while another hook process is reading
            # the file, and that must cost only the halving (tried again at the next use), never
            # the use being logged (review). A temp name per process, so two halvings never mix.
            tmp = "%s.%d.tmp" % (p, os.getpid())
            try:
                with open(p, encoding="utf-8", errors=UNTRUSTED_TEXT) as fh:
                    lines = fh.readlines()
                with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                    fh.writelines(lines[len(lines) // 2:])
                os.replace(tmp, p)
            except Exception:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                # A halving that keeps failing must not let the file grow without end (review):
                # past four times the cap, this use is the one dropped.
                if os.path.getsize(p) > 4 * _USES_MAX_BYTES:
                    return
        # `id`: what the gateway counts a reported use by, so a report sent twice counts once.
        with open(p, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"id": uuid.uuid4().hex, "rule": rule_id, "at": time.time(),
                                 "outcome": outcome, "harness": harness}) + "\n")
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
        with open(p, encoding="utf-8", errors=UNTRUSTED_TEXT) as fh:
            for line in fh:
                try:
                    use = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(use, dict):
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
        with open(p, encoding="utf-8", errors=UNTRUSTED_TEXT) as fh:
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


# ---- the team's rules, from the gateway ------------------------------------------------------
# With a key, the hook pulls the rules a person sent (`agentx rule push`) from `GET /v1/rules`,
# checks them on this machine beside this file's, and sends back only what they matched
# (`POST /v1/rules/uses`). Each call is still decided here; nothing about a call no rule matched
# leaves the machine. Both files sit in the hook's session folder, beside the uses file.
PULLED_FILE_NAME = "team-rules.pulled.json"
REPORTED_FILE_NAME = "team-rule-uses.reported.json"
# The gateway release whose `GET /v1/rules` hands out the rules (`list`); older ones count them.
RULES_PULL_SINCE = "2026.10.27.1"
_PULL_TIMEOUT = 1.5
# How long an answer is kept before the gateway is asked again, by what it was: a gateway that is
# down costs one timeout a minute, not one per call.
_PULL_TTL = {"ok": 300, "unreachable": 60, "error": 60, "unreadable": 60, "refused": 600,
             "old": 3600}
_REPORT_EVERY = 300
# Well under what the gateway takes at once (500 uses, 128 KB). The batch is also cut by its
# encoded size (`_REPORT_MAX_BYTES`), since a rule id has no length limit: a batch refused for its
# size would be sent again unchanged, and that machine would never report again (scoped review).
_REPORT_MAX = 200
_REPORT_MAX_BYTES = 96 * 1024
# The latest time the gateway stores (2100-01-01, its `_team_rule_use`); later ones it ignores.
_GATEWAY_AT_MAX = 4102444800


def _hook_file(name, path=None):
    return os.path.join(os.path.dirname(uses_path(path)), name)


def _gateway_id(url, key):
    """Which gateway and key a pulled copy came from, hashed: the key itself is never written.
    The address without a trailing "/", so `agentx rule list` and the hook name one gateway the
    same way."""
    return hashlib.sha256(("%s\n%s" % (str(url).rstrip("/"), key)).encode("utf-8")
                          ).hexdigest()[:16]


def _read_json(p):
    try:
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except Exception:
        return None


def _write_json(p, doc):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = "%s.%d.tmp" % (p, os.getpid())
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        # ASCII: a lone surrogate read from an agent-written file (`"\ud800"`) is a str UTF-8
        # cannot write, and a write that raises would never let the file be rewritten (review).
        json.dump(doc, fh, ensure_ascii=True)
    os.replace(tmp, p)


def read_pulled(url, key, path=None):
    """The cached answer from this gateway for this key, or None: none yet, or one from another
    gateway or key. Never raises."""
    doc = _read_json(_hook_file(PULLED_FILE_NAME, path))
    if not doc or doc.get("gateway") != _gateway_id(url, key):
        return None
    # The copy sits where the agent can write: a document of the wrong shape is no copy, so the
    # hook asks again rather than raising in the middle of a call (code review).
    if not (isinstance(doc.get("status"), str) and isinstance(doc.get("rules", []), list)
            and isinstance(doc.get("checked_at", 0), (int, float))
            and not isinstance(doc.get("checked_at", 0), bool)):
        return None
    return doc


def pulled_rules(doc):
    """The rules in a cached answer, each checked as this file's are; one that fails the check is
    dropped, since the cache sits where the agent can write. [] for no answer."""
    out = []
    for r in (doc or {}).get("rules") or []:
        try:
            out.append(_check_rule(dict(r), PULLED_FILE_NAME))
        except Exception:
            continue
    return out


def _http(method, url, key, body=None, timeout=_PULL_TIMEOUT):
    """(status, parsed JSON or None); status None when nothing answered. Standard library only:
    the hook runs once per call as a fresh process and must not wait on importing `requests`."""
    import urllib.error
    import urllib.request
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer %s" % key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            status, raw = res.status, res.read()
    except urllib.error.HTTPError as err:
        return err.code, None
    except Exception:
        return None, None
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, None


def refresh_pulled(url, key, path=None, now=None):
    """Ask the gateway for the team's rules once the cached answer is older than its keep time
    (`_PULL_TTL`), and cache what it said. Returns the cached answer. Never raises.

    What each answer leaves to check: "ok", the rules it sent. "refused" (401, 403), none, so a
    revoked key stops adding the team's rules. "old" (a gateway older than RULES_PULL_SINCE), none.
    "unreachable", "unreadable" (its own copy is damaged) or any other fault, the rules last
    pulled: a team rule only asks, so a laptop off the network keeps asking what it asked."""
    import time
    now = time.time() if now is None else now
    doc = read_pulled(url, key, path)
    if doc and 0 <= now - (doc.get("checked_at") or 0) < _PULL_TTL.get(doc.get("status"), 60):
        return doc
    last = doc or {}
    if doc:
        # Claimed before the request, so parallel calls of one session do not all ask at once
        # (code review); they keep the copy they have until this one answers.
        try:
            _write_json(_hook_file(PULLED_FILE_NAME, path), dict(doc, checked_at=now))
        except Exception:
            pass
    status, view = _http("GET", "%s/v1/rules" % url, key)
    # `source` carried with the rules kept from the last answer: a copy kept while the gateway
    # does not answer is still that answer, "none" included (scoped review).
    new = {"gateway": _gateway_id(url, key), "checked_at": now, "rules": last.get("rules") or [],
           "rules_at": last.get("rules_at"), "source": last.get("source")}
    if status == 200 and isinstance(view, dict) and isinstance(view.get("list"), list):
        # `source` kept: "none" is a gateway holding no copy at all, which is not a list someone
        # emptied (`gateway_list_known`).
        new.update(status="ok", rules=view["list"], rules_at=now, source=view.get("source"))
    elif status == 200 and isinstance(view, dict) and "list" in view:
        new.update(status="unreadable")
    elif status == 404 or (status == 200 and isinstance(view, dict)):
        new.update(status="old", rules=[], rules_at=None)
    elif status in (401, 403):
        new.update(status="refused", code=status, rules=[], rules_at=None)
    elif status is None:
        new.update(status="unreachable")
    else:
        new.update(status="error", code=status)
    try:
        _write_json(_hook_file(PULLED_FILE_NAME, path), new)
    except Exception:
        pass
    return new


# ---- whose change wins: the gateway's list, this file, and what they last agreed on ----------
# With a key, the gateway's list is the team's one copy. A person can change it from the
# website, so this file and the gateway
# can each have changed since they last matched. The "base" is the gateway's list as it stood
# the last time THIS file and the gateway were the same (a push that took, `agentx rule pull`,
# or the hook finding them equal), kept beside the pulled copy (git ignores the folder). The
# hook's 5-minute pull never moves it, since that pull does not touch the file. With it, each
# rule id has a three-way answer, and the gateway wins whenever it changed.
# KNOWN LIMIT (code review, left as is): the base is filed under the key that wrote it, `rule
# push`/`pull` use the agent key when the shell has one, else the admin key, and the hook only
# ever has the agent key. A shell holding only AGENTX_ADMIN_KEY writes a base the hook does not
# find; that machine then reads every gateway difference as "changed there". Asking still errs
# toward the gateway's copy, which a person set, and `agentx rule list` says which rules differ.
BASE_FILE_NAME = "team-rules.base.json"


def _canon(r):
    """A rule as compared: its stored fields, never the hook's own mark nor what a match read
    from the call (`_number`, `_money`), which a matched rule carries on its copy."""
    return json.dumps({k: v for k, v in r.items()
                       if k != FROM_GATEWAY and k not in ("_number", "_money")},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _same(a, b):
    return a is not None and b is not None and _canon(a) == _canon(b)


def read_base(url, key, path=None):
    """The list this file last agreed on with this gateway and key, or None: never agreed, or the
    copy is from another gateway, of the wrong shape, or unreadable. Never raises."""
    doc = _read_json(_hook_file(BASE_FILE_NAME, path))
    if not doc or doc.get("gateway") != _gateway_id(url, key) or not isinstance(doc.get("rules"), list):
        return None
    # It sits where the agent can write: a rule that fails the file's check is no base for it.
    return pulled_rules(doc)


def write_base(url, key, rules, path=None):
    """Record `rules` as what this file and the gateway agree on. Never raises: a base not
    written only makes the next push stricter."""
    import time
    try:
        clean = [{k: v for k, v in r.items() if k != FROM_GATEWAY} for r in rules]
        if read_base(url, key, path) == clean:
            return
        _write_json(_hook_file(BASE_FILE_NAME, path),
                    {"gateway": _gateway_id(url, key), "rules": clean, "at": time.time()})
    except Exception:
        pass


def three_way(local, gateway, base):
    """(the rules to check, what changed on the gateway that this file does not hold).

    `local` is this file's rules, `gateway` the gateway's list, `base` what they last agreed on
    (None: never). Per id: the same on both, or changed only here (or added here and not sent),
    the file's; changed or added on the gateway, the gateway's (marked FROM_GATEWAY); removed on
    the gateway, gone; removed here and unchanged there, gone. Changed on both: the gateway's.
    The second answer lists each gateway change a push would undo, as (id, "added" | "changed" |
    "removed", the rule): a rule the file holds exactly as the gateway does is never one."""
    base_by_id = {r["id"]: r for r in (base or [])}
    gw_by_id = {r["id"]: r for r in gateway}
    local_ids = {r["id"] for r in local}
    checked = []
    for r in local:
        g, b = gw_by_id.get(r["id"]), base_by_id.get(r["id"])
        if g is not None:
            if _same(r, g) or (not _same(r, b) and _same(g, b)):
                checked.append(r)
            else:
                checked.append(dict(g, **{FROM_GATEWAY: True}))
        elif b is None:
            checked.append(r)                  # added here, not sent yet
        # else: it was agreed and the gateway no longer has it: removed there
    for g in gateway:
        if g["id"] in local_ids:
            continue
        if _same(g, base_by_id.get(g["id"])):
            continue                           # removed here, not sent yet
        checked.append(dict(g, **{FROM_GATEWAY: True}))
    local_by_id = {r["id"]: r for r in local}
    there = []
    for g in gateway:
        mine, b = local_by_id.get(g["id"]), base_by_id.get(g["id"])
        if _same(mine, g) or _same(g, b):
            continue
        there.append((g["id"], "added" if b is None and mine is None else "changed", g))
    for rid, b in base_by_id.items():
        if rid not in gw_by_id and rid in local_by_id:
            there.append((rid, "removed", b))
    return checked, there


def gateway_list_known(doc):
    """Whether a pulled copy holds a list the gateway really sent: a pull that answered, or the
    copy kept from one while the gateway does not answer. A refused key or an older gateway
    holds none, and then the file's rules alone are checked, as before (never "every rule was
    removed on the gateway"). So does a gateway that holds NO copy (`source` "none": its stored
    copy lost, or never sent), which answers an empty list: a list a person emptied is a copy
    ("pushed") holding none (code review)."""
    return bool(doc) and doc.get("rules_at") is not None and doc.get("status") in (
        "ok", "unreachable", "error", "unreadable") and doc.get("source") != "none"


def _sendable(s):
    """None, or text UTF-8 can carry. A lone surrogate (`"\ud800"` in the file, plain ASCII on
    disk) passes every `isinstance(str)` and fails the gateway's store; sent, it would be refused
    with its whole batch every time (review)."""
    if s is None:
        return True
    if not isinstance(s, str):
        return False
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _report_state(doc, gateway):
    """The report's state rebuilt from its typed fields only: a field of any other type reads as
    empty, so nothing in the file can raise later. ONE RULE FOR BOTH OF THE HOOK'S REPORT FILES,
    stated once (five review rounds found one shape at a time): they sit where the agent can
    write, so every byte of them is untrusted, and the worst any content may cost is a resend,
    never the reports after it. The uses file is read with `UNTRUSTED_TEXT` for the same reason."""
    doc = doc if isinstance(doc, dict) and doc.get("gateway") == gateway else {}
    tried = doc.get("tried_at")
    sent = doc.get("sent")
    return {"gateway": gateway,
            "tried_at": tried if isinstance(tried, (int, float)) and not isinstance(tried, bool)
            and 0 <= tried < _GATEWAY_AT_MAX else 0,
            "sent": [s for s in sent if isinstance(s, str) and _sendable(s)]
            if isinstance(sent, list) else []}


def report_uses(url, key, doc, path=None, now=None, force=False):
    """Send the gateway this machine's uses of the rules it handed out (`doc`, the cached answer),
    those not sent yet (by id), at most `_REPORT_MAX` at once and at most once every
    `_REPORT_EVERY` seconds unless `force`. A rule only this file holds is never sent. Returns
    how many the gateway stored, or None when nothing was sent. Never raises."""
    import time
    now = time.time() if now is None else now
    try:
        known = {r["id"] for r in pulled_rules(doc)}
        # Only to a gateway that just answered: one that did not would cost the call a second
        # timeout (code review), and the uses wait in the file until it answers.
        if not known or (doc or {}).get("status") != "ok":
            return None
        state_path = _hook_file(REPORTED_FILE_NAME, path)
        state = _report_state(_read_json(state_path), _gateway_id(url, key))
        if not force and 0 <= now - state["tried_at"] < _REPORT_EVERY:
            return None
        # Claimed now, whatever is found: with nothing new to send, every call would otherwise
        # read the whole file again (code review); parallel calls must not send one batch twice.
        state["tried_at"] = now
        _write_json(state_path, state)
        # 🔴 WHAT WAS SENT IS KEPT BY THE USE'S ID, NEVER BY A TIME. A time from this machine's
        # clock only moves forward, so after a clock set ahead was corrected, every use logged in
        # the hours it had run ahead sat behind the mark and was never sent (scoped review). The
        # gateway counts a use once by its id, so a resend costs a request and never a count.
        sent = set(state["sent"])
        uses, present = [], set()
        p = uses_path(path)
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors=UNTRUSTED_TEXT) as fh:
                for line in fh:
                    # 🔴 EACH LINE IS ITS OWN TRY. The file sits where the agent can write, and a
                    # check that raised on one line (a list for a rule, an integer too large for
                    # a float) used to end the report, and every report after it (review).
                    try:
                        u = json.loads(line)
                        if not isinstance(u, dict) or not isinstance(u.get("id"), str):
                            continue
                        present.add(u["id"])
                        at, rule = u.get("at"), u.get("rule")
                        # The gateway's own range, which also leaves out NaN and Infinity.
                        if (isinstance(at, (int, float)) and not isinstance(at, bool)
                                and 0 < at < _GATEWAY_AT_MAX and u["id"] not in sent
                                and isinstance(rule, str) and rule in known
                                and u.get("outcome") in OUTCOMES
                                and _sendable(u["id"]) and _sendable(u.get("harness"))):
                            uses.append({k: u.get(k) for k in ("id", "rule", "outcome", "at",
                                                               "harness")})
                    except Exception:
                        pass
        # Ids the file no longer holds (it is halved past its size cap) are dropped, so the list
        # is never longer than the file.
        sent &= present
        uses.sort(key=lambda u: u["at"])
        batch, size, passed = [], 0, []
        for u in uses:
            n = len(json.dumps(u)) + 2
            if n > _REPORT_MAX_BYTES:
                passed.append(u["id"])       # one use the gateway could never take: not again
                continue
            if len(batch) >= _REPORT_MAX or size + n > _REPORT_MAX_BYTES:
                break
            batch.append(u)
            size += n
        state["sent"] = sorted(sent | set(passed))
        if not batch:
            _write_json(state_path, state)
            return None
        status, body = _http("POST", "%s/v1/rules/uses" % url, key, {"uses": batch})
        if status != 200:
            _write_json(state_path, state)
            return None
        state["sent"] = sorted(set(state["sent"]) | {u["id"] for u in batch})
        _write_json(state_path, state)
        return (body or {}).get("stored")
    except Exception:
        return None


_USAGE ="""usage: agentx rule add PHRASE [PHRASE ...] --why "REASON" [options]
       agentx rule list
       agentx rule remove RULE_ID [--yes]
       agentx rule push
       agentx rule pull [--yes]

Turn a correction you keep repeating into a team rule. Before a call that
contains every PHRASE, Claude Code asks you first. The rule is saved in
.agentx/team-rules.json: commit it, and teammates who use the AgentX hook
get it too. push sends the file to your gateway (AGENTX_API_KEY), which
then checks an SDK agent's matching call: it holds it for a person to
answer, or stops it where nobody can answer a hold. pull takes the changes
made on your gateway (on the website, or pushed from another copy) into
the file; push refuses to undo them until you do.

  --why "REASON"   Required. What you keep telling the agent. Shown when
                   it asks.
  --tool NAME      Which calls it checks. shell (the default) is a
                   Bash or PowerShell command in Claude Code or Codex.
                   Otherwise a tool's exact name: an SDK agent's
                   function (run_shell) or an MCP tool. Repeat for more.
  --argument NAME  Hold a call by a number in it instead of by words:
                   the argument to read, with --hold-at and one --tool.
  --hold-at N      The number it holds at, or one per environment
                   (AGENTX_ENVIRONMENT): --hold-at prod=25 --hold-at dev=500.
  --currency CODE  The number is money in this currency (USD). For this
                   tool it takes the place of the gateway's money limit,
                   unless a limit the gateway's operator set is lower.
  --currency-field NAME
                   The argument naming the call's currency; a call in
                   another currency, or none, is held.
  --unit cents     The call's amount is in cents (an amount of 2550 is
                   25.50). --hold-at stays in the currency.
  --recipient NAME
                   The argument naming who is paid (customer_id). The
                   hosted gateway adds up payments to one recipient
                   over 24 hours and holds the one that reaches the
                   number; a gateway you run sets the window with
                   AGENTX_MONEY_TOTAL_HOURS (0 is off). Without it,
                   the gateway looks for an argument such as to,
                   payee or customer, and adds up the tool's payments
                   together if none is found.
  --said "QUOTE"   Optional: your words when you corrected the agent.
  --stop-where-cannot-ask
                   In Codex, which cannot ask, stop the call instead of
                   warning.
  --yes            Write without asking you to confirm (for a script you
                   run yourself).

Examples:
  agentx rule add "run_suites.py" --why "the suites run once, at the end, with my go-ahead"
  agentx rule add --tool provision_instances --argument count --hold-at prod=25 --hold-at dev=500 --why "more than a handful of VMs needs a second look"
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


def _joined(items, word):
    """"a", "a or b", "a, b or c": a list as a reader writes it, with the word that says whether
    one item or all of them must hold."""
    items = list(items)
    return items[0] if len(items) == 1 else "%s %s %s" % (", ".join(items[:-1]), word, items[-1])


def _leading_name(tool):
    """The name every call's matched text starts with, on every door: an MCP tool's bare name
    (the hook builds `mcp__srv__refund`'s text from `refund`; the gateway from the full name,
    which contains it), else the tool's own name."""
    parts = str(tool).split("__", 2)
    if str(tool).startswith("mcp__") and len(parts) == 3 and parts[2]:
        return parts[2]
    return str(tool)


def shown_phrases(rule):
    """The phrases a person reads for a rule. For a rule on one tool that is not a shell, a
    phrase found in the name every call's text starts with (`_leading_name`, compared as the
    matcher compares: any case, nothing trimmed) is left out: every call contains it, so it holds
    nothing back, and 'contains "refund_customer"' would only repeat the call's name. So is the
    tool's own full MCP name, which `match_rules` reads as the bare name. A phrase the matcher
    would not find there (a stray space) stays, so "every call" is said only of a rule that does
    hold every call. `agentx review` writes the tool's name as a
    rule's first phrase; the file keeps it, so an older SDK or gateway reads the rule as before.
    The gateway's `_team_rule_shown_phrases` and the website's `shownPhrases` do the same."""
    tools, match = rule.get("tools") or [], list(rule.get("match") or [])
    if len(tools) == 1 and tools[0] not in (SHELL,) + SHELL_TOOLS:
        lead, full = _leading_name(tools[0]).lower(), str(tools[0]).lower()
        return [m for m in match if str(m).lower() not in lead and str(m).lower() != full]
    return match


def every_call(rule):
    """True for a rule that holds every call to one tool: every phrase it has is the tool's own
    name. Said as "every call to the tool X", never as a call that "contains" anything. Never a
    rule with a number, which holds only a call at or above it: counted as every call,
    `agentx review` stopped offering a rule for the calls below it (review)."""
    tools = rule.get("tools") or []
    return ("argument" not in rule and len(tools) == 1 and tools[0] not in (SHELL,) + SHELL_TOOLS
            and bool(rule.get("match")) and not shown_phrases(rule))



def _describe(rule):
    # Any one of the tools, and every phrase (`match_team_rule`): a comma said neither. The
    # website's `describeRule` and the gateway's `_evidence_team_rule_calls` word it the same.
    if "argument" in rule and "hold_at" in rule:
        # Not "every call": a rule with a number holds only a call at or above it. Every tool it
        # names (review: only the first was said; a rule from the file may name more).
        # The words before the number: after it, "…and 25 anywhere else and that contains" read
        # as if the words belonged to "anywhere else" alone (scoped review).
        shown = shown_phrases(rule)
        words = (" that contains %s and" % _joined(('"%s"' % m for m in shown), "and")
                 if shown else "")
        return "%s%s whose %s is at or above %s" % (
            _joined(("a call to the tool '%s'" % t for t in rule["tools"]), "or"), words,
            rule["argument"], _hold_at_words(rule["hold_at"], rule.get("currency")))
    if every_call(rule):
        return "every call to the tool '%s'" % rule["tools"][0]
    tools = _joined(("any shell command" if t == SHELL else "a call to the tool '%s'" % t
                     for t in rule["tools"]), "or")
    return "%s that contains %s" % (tools, _joined(('"%s"' % m for m in shown_phrases(rule)),
                                                   "and"))


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


def _mcp_tools_seen():
    """The bare tool names this project's record holds from agentx-mcp (its servers' tools,
    which Claude Code asks about). Empty when there is no record. Never raises."""
    try:
        from . import db
        return {tool for agent, tool, _n in db.get_tool_call_counts()
                if agent == db.MCP_PROXY_AGENT_ID and str(tool).strip()}
    except Exception:
        return set()


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


def _uses_said(uses, you=True):
    """What a rule did, as the list screen says it: "asked you 3 times (you let it run once);
    warned once in Codex". `you` False for the team's counts, which are not all this person's."""
    said = []
    if uses.get("ask"):
        said.append(("asked you %s" if you else "asked %s") % _times(uses["ask"])
                    + ((" (you let it run %s)" if you else " (let it run %s)") % _times(uses["ran"])
                       if uses.get("ran") else ""))
    if uses.get("warn"):
        said.append("warned %s in Codex" % _times(uses["warn"]))
    if uses.get("stop"):
        said.append("stopped the call %s without asking (Codex, or Claude Code in a mode that "
                    "does not ask, such as auto)" % _times(uses["stop"]))
    return "; ".join(said)


def _print_wrapped(text):
    import textwrap
    print("\n".join(textwrap.wrap(text, 75, initial_indent="    ", subsequent_indent="      ",
                                  break_long_words=False, break_on_hyphens=False)))


def _team_uses_line(view, rule_id):
    """The rule's line from what every machine's hook reported to the gateway, or None when the
    gateway has no report of it (or did not answer)."""
    uses = ((view or {}).get("uses") or {}).get(rule_id) if isinstance(view, dict) else None
    said = _uses_said(uses, you=False) if isinstance(uses, dict) else ""
    if not said:
        return None
    return ("across your team since %s, as each machine's hook reported it: %s"
            % (_local_date(uses.get("since")), said))


def _print_rule(r, view, local_uses=True):
    """One rule on the list screen: what it checks, what it did here and across the team, why,
    who added it."""
    print("\n  %s %s" % ("Asks before" if r.get("active", True)
                         else "Switched off. It asked before", _describe(r)))
    # What happened comes right under what the rule checks; why and who follow.
    if local_uses:
        uses = rule_use_counts(r["id"])
        if uses is None:
            print("    on this machine: could not read %s" % uses_path())
        elif uses["since"] is None:
            print("    on this machine: not used yet")
        else:
            # Where it could not ask is a place: Codex warns (or stops, when the rule says so),
            # and Claude Code's auto mode stops.
            _print_wrapped("on this machine since %s: %s"
                           % (_local_date(uses["since"]), _uses_said(uses)))
    team = _team_uses_line(view, r["id"])
    if team:
        _print_wrapped(team)
    print("    why: %s" % r["why"])
    if r.get("said"):
        print("    you said: \"%s\"" % r["said"])
    print("    %s on %s (id %s)" % (_added(r),
                                          _local_date(r.get("added_at")), r["id"]))


def _pulled_here(gateway_url, key):
    """What this machine's hook did with the gateway's rules, read from its own copy: a
    measurement, not a forecast. The hook finds its key where Claude Code or Codex runs, which
    can differ from this shell's, so a copy taken with another key reads as not taken. `key` is
    the agent key: the hook never uses the admin key, so a copy is never filed under it."""
    if not key:
        return ("Whether this machine's hook has taken them is not known here: this shell has no "
                "AGENTX_API_KEY, the key the hook uses.")
    doc = read_pulled(gateway_url, key)
    if not doc:
        return ("This machine's hook has not taken them yet with this key; it does at the next "
                "Claude Code or Codex call, when AGENTX_API_KEY is set where those run.")
    if doc.get("status") == "ok":
        return "This machine's hook took them from it on %s." % _local_date(doc.get("rules_at"))
    if pulled_rules(doc):
        # No answer or a fault: the hook keeps the rules it last took.
        return ("This machine's hook could not reach it the last time it asked, and checks the "
                "copy it took on %s." % _local_date(doc.get("rules_at")))
    # "or something in front of it": a proxy answers 401/403 too (cli._refused_with_key).
    why = {"refused": "the gateway, or something in front of it, refused the key",
           "old": "the gateway is too old to send them",
           "unreachable": "no answer", "unreadable": "the gateway could not read its copy"
           }.get(doc.get("status"), "the gateway answered with a fault")
    return ("This machine's hook could not take them the last time it asked (%s), so it does "
            "not check them now." % why)


def _gateway_only_rules(view, rules):
    """The rules the gateway hands out that this file does not hold (by id), each checked as the
    file's are; [] when it handed out none."""
    if not isinstance(view, dict) or not isinstance(view.get("list"), list):
        return []
    ids = {r["id"] for r in rules}
    out = []
    for r in view["list"]:
        try:
            r = _check_rule(dict(r), "the gateway's team rules")
        except Exception:
            continue
        if r["id"] not in ids:
            out.append(r)
    return out


_NOT_ASKED = object()


def _gateway_line(gateway_url, key, rules, key_name="AGENTX_API_KEY", view=_NOT_ASKED):
    """The `list` screen's last line: whether the gateway checks these same rules. `key_name` is
    the setting the key came from, for the line a refused key gets. `view` is the gateway's
    answer when the caller already asked for it; None is an answer too (it did not answer), so
    a gateway that is down is not waited on twice (code review)."""
    view = _gateway_view(gateway_url, key) if view is _NOT_ASKED else view
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
        from .cli import _refused_with_key
        _say("Your gateway at %s answered %d, so it is unknown which team rules it checks%s."
             % (gateway_url, view, _refused_with_key(view, key_name)))
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
    # The changes on the gateway this file does not hold, which a push refuses to undo.
    # Known only where the gateway sent its list (from 2026.10.27.1); an older one sends counts.
    # Asked once, for every branch below.
    gw = gateway_list(view)
    listed = gw is not None
    there = three_way(rules, gw, read_base(gateway_url, key))[1] if listed else []
    changes = "1 change" if len(there) == 1 else "%d changes" % len(there)
    them = "it" if len(there) == 1 else "them"
    if theirs and not os.path.exists(team_rules_path()):
        # Nothing here to send, so `agentx rule push` is not the advice (code review). "Sent"
        # only for a pushed copy: a gateway beside a project reads its own file (scoped review).
        # The file looked for is named: AGENTX_TEAM_RULES_FILE can point away from this folder
        # (scoped review 2).
        if view.get("source") == "pushed":
            _say("Your gateway at %s checks %s, sent from another copy of this project%s. There "
                 "is no team rules file at %s%s" % (
                     gateway_url, _count(theirs), " or made on the website" if listed else "",
                     team_rules_path(), ". To make one from them: agentx rule pull" if listed
                     else " to compare or send."))
        else:
            _say("Your gateway at %s checks %s from a team rules file of its own. There is no "
                 "team rules file at %s to compare."
                 % (gateway_url, _count(theirs), team_rules_path()))
    elif not theirs:
        # Rules it holds but has switched off are said: "checks no team rules" alone read as a
        # gateway that lost them. Known only beside the `active` count.
        off = view.get("rules") if "active" in view else 0
        off = off if isinstance(off, int) and off > 0 else 0
        _say("Your gateway at %s checks no team rules%s.%s"
             % (gateway_url, "" if not off else " right now: its 1 rule is switched off"
                if off == 1 else " right now: all %d of its rules are switched off" % off,
                "" if not ours or same else
                (" It has %s this file does not hold; to take %s into this file: agentx rule "
                 "pull" % (changes, them)) if there else " Send these: agentx rule push"))
    elif same:
        _say("Your gateway at %s checks these same rules%s." % (
            gateway_url, " (this file)" if view.get("source") == "local file" else ""))
    else:
        # A push refuses to undo a change made on the gateway, so the line says which
        # comes first, counted per rule: added, changed or removed there.
        if there:
            _say("Your gateway at %s checks a different set (%s), with %s this file does not "
                 "hold. To take %s into this file: agentx rule pull (agentx rule push refuses "
                 "until then, so as not to undo %s)."
                 % (gateway_url, _count(theirs), changes, them, them))
        elif listed:
            _say("Your gateway at %s checks a different set (%s): the difference is changes "
                 "made in this file. To send them: agentx rule push" % (gateway_url, _count(theirs)))
        else:
            _say("Your gateway at %s checks a different set (%s). To send this file in its "
                 "place: agentx rule push" % (gateway_url, _count(theirs)))


def _count(n):
    return "1 rule" if n == 1 else "%d rules" % n


def _push(gateway_url, api_key, admin_key, admin_refusal):
    """`agentx rule push`: send this file to the gateway, which replaces its copy with it.

    Sends AGENTX_ADMIN_KEY when it is set, as `agentx allowlist push` does: a gateway with admin
    keys refuses rules pushed with the agent's key, since an empty push switches every rule off."""
    import requests
    from .cli import _REFUSAL_DETAIL_MAX, _copy_after, _refuser, _remote_json, _unreached
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
    # The gateway's list first. A push replaces it whole, so a change made there (on the
    # website, or pushed from another copy) that this file does not hold would be undone: then
    # nothing is sent, and `rule pull` takes the change into the file.
    base_key = api_key or admin_key
    view = _gateway_view(gateway_url, key)
    if view is None or view == "unreadable":
        _say("Nothing was sent: your gateway at %s %s when asked for its team rules first, and a "
             "push replaces them whole, so it is not known what this one would undo. Try again "
             "shortly." % (gateway_url, "did not answer" if view is None else
                           "answered in a way that could not be read"))
        return 1
    gateway = gateway_list(view)
    if gateway is not None:
        _, there = three_way(rules, gateway, read_base(gateway_url, base_key))
        if there:
            _say("Nothing was sent: your gateway's team rules have %s this file does not hold, "
                 "and a push replaces them whole, so it would undo %s:"
                 % ("a change" if len(there) == 1 else "%d changes" % len(there),
                    "it" if len(there) == 1 else "them"))
            _print_changes(there)
            print()
            _say("To take %s into this file first: agentx rule pull. Then push again."
                 % ("it" if len(there) == 1 else "them"))
            return 1
    try:
        res = requests.put("%s/v1/rules" % gateway_url, json={"version": _FILE_VERSION,
                                                               "rules": rules},
                           headers={"Authorization": "Bearer %s" % key}, timeout=5.0)
    except Exception as err:
        print(_unreached(err, gateway_url, "sent", "rules", "agentx rule list"))
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
        _say("%s refused the rules (%d), %s: %s"
             % (_refuser(res.status_code), res.status_code,
                _copy_after(res.status_code, "agentx rule list"),
                _sanitize_detail(str(detail), limit=_REFUSAL_DETAIL_MAX)))
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
    # This machine's copy of the gateway's rules is now out of date: the hook asks again at its
    # next call instead of after the copy's keep time.
    try:
        os.remove(_hook_file(PULLED_FILE_NAME))
    except OSError:
        pass
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
    if same:
        write_base(gateway_url, base_key, rules)
    _say("Fingerprint %s%s" % (got.get("fingerprint"), ", the same as this file." if same else
         ", but this file's is %s: run agentx rule list to compare." % local_fp))
    return 0 if same else 1


def _agree_if_same(gateway_url, key, rules, view=_NOT_ASKED):
    """Record the base whenever this file and the gateway's list are the same. Without one, a
    rule removed here reads as "added there" and the push refuses (code review: a machine that
    pushed with an older AgentX, or whose file came from git). Never raises."""
    try:
        if not (gateway_url and key):
            return
        view = _gateway_view(gateway_url, key) if view is _NOT_ASKED else view
        gateway = gateway_list(view)
        if gateway is None:
            return
        if [_canon(r) for r in gateway] == [_canon(r) for r in rules]:
            write_base(gateway_url, key, gateway)
    except Exception:
        pass


def _agree_before_a_change(gateway_url, key):
    """Before `add` or `remove` writes the file, so the change is read as made here (code review,
    then scoped review: an outdated base read a removal as "added there"). In order, stopping at
    the first that settles it:
      1. the base is this file: nothing to do;
      2. this machine's hook took the gateway's list and it is this file (a teammate's change
         that arrived by git and is already on the gateway): that is the base now, no call;
      3. no base at all (this machine never agreed): ask the gateway once.
    Otherwise (this file has changes not sent yet) nothing is asked, so a run of local changes
    makes no network call. Left open: an outdated base whose change arrived by git before this
    machine's hook ever took the new list; `agentx rule list` agrees it on its next run."""
    if not (key and gateway_url):
        return
    try:
        rules = read_team_rules()
        mine = [_canon(r) for r in rules]
        base = read_base(gateway_url, key)
        if base is not None and [_canon(r) for r in base] == mine:
            return
        doc = read_pulled(gateway_url, key)
        if doc and doc.get("status") == "ok" and doc.get("source") != "none":
            pulled = pulled_rules(doc)
            if [_canon(r) for r in pulled] == mine:
                write_base(gateway_url, key, pulled)
                return
        if base is None:
            _agree_if_same(gateway_url, key, rules)
    except Exception:
        pass


def gateway_list(view):
    """The gateway's list from its answer to `GET /v1/rules`, each rule checked as this file's
    are, or None when the answer holds no list to compare with: no answer, an older gateway that
    sends counts, a copy it cannot read, or NO copy at all (`source` "none", its stored copy lost
    or never sent). THE ONE RULE every screen and command uses (scoped review): a gateway with no
    copy is never "every rule was removed there", or `pull` would delete the file's rules and
    `push`, the command that restores the copy, would refuse."""
    if not (isinstance(view, dict) and isinstance(view.get("list"), list)
            and view.get("readable", True) and view.get("source") != "none"):
        return None
    return _checked_list(view)


def _checked_list(view):
    """The gateway's list, each rule checked as this file's are; one that fails is left out."""
    out = []
    for r in view.get("list") or []:
        try:
            out.append(_check_rule(dict(r), "the gateway's team rules"))
        except Exception:
            continue
    return out


_CHANGE_WORDS = {"added": "added there", "changed": "changed there", "removed": "removed there"}


def _print_changes(there):
    """Each change made on the gateway, one rule a line: which, how, and what it does there."""
    for rid, how, r in there:
        if how == "removed":
            print("     %s, %s. It asked before %s." % (rid, _CHANGE_WORDS[how], _describe(r)))
        else:
            print("     %s, %s. %s %s." % (rid, _CHANGE_WORDS[how],
                                          "Asks before" if r.get("active", True)
                                          else "Switched off; it asked before", _describe(r)))


def _pull(gateway_url, api_key, admin_key, assume_yes):
    """`agentx rule pull`: take the gateway's changes into this file. Per rule, the gateway's copy
    where it changed since the two last matched, this file's where only the file changed (kept,
    to send with a push); then the two agree on the gateway's list (`write_base`)."""
    key = api_key or admin_key
    shown = team_rules_path()
    if not key or not gateway_url:
        _say("Nothing changed: there is no AGENTX_API_KEY, so there is no gateway to take team "
             "rules from.")
        return 1
    view = _gateway_view(gateway_url, key)
    if not isinstance(view, dict):
        if view is None:
            why = "did not answer"
        elif view == "old":
            why = "is older than %s, which hands out its team rules" % RULES_PULL_SINCE
        elif view == "unreadable":
            why = "answered in a way that could not be read"
        else:
            from .cli import _refused_with_key
            why = "answered %d%s" % (view, _refused_with_key(view, "AGENTX_API_KEY" if api_key
                                                            else "AGENTX_ADMIN_KEY"))
        _say("Nothing changed: your gateway at %s %s." % (gateway_url, why))
        return 1
    if not view.get("readable", True):
        _say("Nothing changed: your gateway cannot read its own copy of the team rules. %s"
             % (view.get("error") or ""))
        return 1
    if not isinstance(view.get("list"), list):
        _say("Nothing changed: your gateway at %s sends the count of its team rules only (it is "
             "older than %s)." % (gateway_url, RULES_PULL_SINCE))
        return 1
    if view.get("source") == "none":
        # No copy at all is not "every rule removed there" (scoped review): a pull would delete
        # this file's rules, and committing it would delete them for the team.
        _say("Nothing changed: your gateway at %s holds no team rules at all, which is not the "
             "same as a list someone emptied. To send it this file's: agentx rule push"
             % gateway_url)
        return 1
    gateway = gateway_list(view)
    rules = read_team_rules()                         # a damaged file raises: nothing changes
    merged, _ = three_way(rules, gateway, read_base(gateway_url, key))
    merged = [{k: v for k, v in r.items() if k != FROM_GATEWAY} for r in merged]
    if [_canon(r) for r in merged] == [_canon(r) for r in rules]:
        if [_canon(r) for r in rules] == [_canon(r) for r in gateway]:
            write_base(gateway_url, key, gateway)
            _say("%s already holds your gateway's team rules. Nothing changed." % shown)
        else:
            _say("Nothing to take: your gateway has no change this file does not hold. This file "
                 "has changes it does not have yet; to send them: agentx rule push")
        return 0
    before = {r["id"]: r for r in rules}
    after = {r["id"]: r for r in merged}
    on_gw = {r["id"]: r for r in gateway}
    took = [r for r in merged if r["id"] in on_gw and _same(r, on_gw[r["id"]])
            and not _same(r, before.get(r["id"]))]
    gone = [r for r in rules if r["id"] not in after]
    kept = [r for r in merged if r["id"] not in on_gw or not _same(r, on_gw[r["id"]])]
    # Removed from this file and not sent: the gateway still holds them, and a push removes them.
    unsent = kept + [g for g in gateway if g["id"] not in after]
    lines = ["About to update %s from your gateway at %s:" % (shown, gateway_url)]
    for r in took:
        lines.append("%s: %s. %s %s." % (
            r["id"], "added there" if r["id"] not in before else "changed there",
            "Asks before" if r.get("active", True) else "Switched off; it asked before",
            _describe(r)))
    for r in gone:
        lines.append("%s: removed there. It asked before %s." % (r["id"], _describe(r)))
    if unsent:
        lines.append("Kept from this file, not sent to your gateway yet: %s."
                     % ", ".join(r["id"] for r in unsent))
    if not _confirm(lines, assume_yes):
        return 1
    _write(shown, merged)
    write_base(gateway_url, key, gateway)
    _say("Updated %s. Commit it, so teammates get the same rules." % shown)
    if unsent:
        _say("This file has %s your gateway does not have yet. To send %s: agentx rule push"
             % ("a change" if len(unsent) == 1 else "%d changes" % len(unsent),
                "it" if len(unsent) == 1 else "them"))
    return 0


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
    if sub not in ("add", "list", "remove", "push", "pull"):
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
        if sub == "pull":
            if args:
                print(_USAGE)
                return 1
            return _pull(gateway_url, api_key, admin_key, assume_yes)
        if sub == "list":
            if args:
                print(_USAGE)
                return 1
            rules = read_team_rules()
            # Asked once, for the counts every machine reported and the rules only it holds.
            view = _gateway_view(gateway_url, read_key) if (read_key and gateway_url) else None
            gw = gateway_list(view)
            listed = gw is not None
            # What this machine's hook checks, per id (`three_way`): the screen shows the same,
            # never the file's copy of a rule the gateway changed (code review).
            there_by_id = {}
            if listed:
                _agree_if_same(gateway_url, read_key, rules, view)
                checked, there = three_way(rules, gw, read_base(gateway_url, read_key))
                there_by_id = {rid: (how, r) for rid, how, r in there}
                mine = {r["id"] for r in rules}
                theirs = [{k: v for k, v in r.items() if k != FROM_GATEWAY} for r in checked
                          if r.get(FROM_GATEWAY) and r["id"] not in mine]
            else:
                theirs = _gateway_only_rules(view, rules)
            if not rules and not theirs:
                print("No team rules yet. Add one: agentx rule add \"PHRASE\" --why \"REASON\"")
                if read_key and gateway_url:
                    _gateway_line(gateway_url, read_key, rules, key_name, view=view)
                return 0
            if rules:
                print("Team rules in %s:" % team_rules_path())
            else:
                print("No team rules in %s." % team_rules_path())
            # What the rule does leads; the id is what `remove` takes, so it sits beside who
            # added it rather than heading the entry (copy pass).
            for r in rules:
                _print_rule(r, view)
                if r["id"] in there_by_id:
                    how, g = there_by_id[r["id"]]
                    # What the hook checks is said only with the key the hook uses: with only
                    # the admin key here, this machine's base is not the hook's (scoped review).
                    if how == "removed":
                        now = "removed there" + (
                            ", so this machine's hook no longer checks it" if api_key else "")
                    else:
                        now = "changed there: %s %s%s" % (
                            "it asks before" if g.get("active", True)
                            else "switched off; it asked before", _describe(g),
                            "; this machine's hook checks that" if api_key else "")
                    _print_wrapped("on your gateway: %s. To take it into this file: agentx "
                                   "rule pull" % now)
            if theirs:
                print()
                _say("From your gateway at %s, not in this file. %s To bring them into this "
                     "file: agentx rule pull" % (gateway_url, _pulled_here(gateway_url, api_key)))
                # This machine's hook logs its uses of these in the same file as the file's.
                for r in theirs:
                    _print_rule(r, view)
            if read_key and gateway_url:
                print()
                _gateway_line(gateway_url, read_key, rules, key_name, view=view)
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
                             "A%s on %s" % (_added(target)[1:],
                                                    _local_date(target.get("added_at")))],
                            assume_yes):
                return 1
            # Agreed before the change, so the hook and the next push read this removal as made
            # here, not as a rule added on the gateway (code review).
            _agree_before_a_change(gateway_url, read_key)
            remove_team_rule(rule_id)
            _say("Removed %s. Claude Code stops asking about it from its next call; commit the "
                 "file so teammates stop too." % rule_id)
            if read_key:
                _say(_PUSH_HINT)
            return 0

        phrases, tools, why, said, stop = [], [], None, None, False
        argument, hold_ats, money = None, [], {}
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--why", "--said", "--tool", "--argument", "--hold-at", "--currency",
                     "--currency-field", "--unit", "--recipient"):
                if i + 1 >= len(args):
                    print(_USAGE)
                    return 1
                value = args[i + 1]
                if a == "--why":
                    why = value
                elif a == "--said":
                    said = value
                elif a == "--argument":
                    argument = value
                elif a == "--hold-at":
                    hold_ats.append(value)
                elif a in ("--currency", "--currency-field", "--unit", "--recipient"):
                    money[a[2:].replace("-", "_")] = value
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
        if argument is not None or hold_ats or money:
            return _add_number_rule(tools, phrases, argument, hold_ats, why, said, stop,
                                    assume_yes, gateway_url, read_key, money=money)
        if not phrases or not why:
            # Say what is missing; the whole help hid it (copy pass).
            print("A team rule needs the words to look for and a reason, for example:")
            print("  agentx rule add \"run_suites.py\" --why \"the suites run once, at the end\"")
            return 1
        tools = list(dict.fromkeys(tools))          # `--tool shell` twice is one tool
        preview = {"tools": tools or [SHELL], "match": phrases}
        same = existing_team_rule(preview["tools"], phrases, read_team_rules())
        if same is not None:
            _say("This is already a team rule: it asks before %s (%s). See it: "
                 "agentx rule list" % (_describe(same), _added(same)))
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
        # Every tool a plain name the record does not show as an MCP tool: the gateway leads.
        gateway_first = bool(either) and len(either) == len(preview["tools"]) \
            and not set(either) & _mcp_tools_seen()
        quoted = "\"%s\"" % "\", \"".join(phrases)
        # One real example of how wide the match is, not a description of matching (copy pass).
        # Built from EVERY phrase, since a rule needs all of them; the command is a line of its
        # own (two leading spaces), which `_confirm` never wraps.
        if all_shell:
            example = ["A command that only mentions %s asks too, for example:"
                       % ("it" if len(phrases) == 1 else "them"),
                       "  git commit -m \"notes on %s\"" % " ".join(phrases)]
        elif every_call(preview):
            # "every call to the tool X" already says how wide it is; the width warning below
            # would read as a second condition.
            example = []
        else:
            # The door the screen leads with says the verb (review: a gateway-first screen said
            # "asks", Claude Code's word).
            example = ["A call that only mentions %s in an argument %s too."
                       % (quoted, "is held" if sdk_only or gateway_first else "asks")]
        if sdk_only:
            lines = ["About to add a team rule. A gateway you run from this project will hold "
                     "%s, for you to answer with agentx holds." % _describe(preview)] + example + [
                     "Why: %s" % why,
                     "The hosted gateway checks it once you send it with agentx rule push; the "
                     "SDK on its own does not check team rules."]
        elif gateway_first:
            # Every tool is a plain name, which an SDK agent's function or an MCP tool may have:
            # the gateway first, Claude Code as the MCP case (a fresh project's rule on
            # delete_bucket read as Claude Code's).
            names_said = " or ".join("'%s'" % t for t in either)
            lines = ["About to add a team rule. A gateway holds %s, for you to answer with agentx "
                     "holds; where nobody can answer a hold, it stops the call." % _describe(preview)
                     ] + example + [
                     "Why: %s" % why,
                     "The hosted gateway checks it once you send it with agentx rule push; the "
                     "SDK on its own does not check team rules.",
                     "If %s is an MCP tool, Claude Code asks you instead, through the AgentX hook. "
                     "In a mode that does not ask, such as auto, AgentX stops the call; to let it "
                     "run, leave that mode and ask again." % names_said,
                     "In Codex, which cannot ask, the call is stopped." if stop else
                     "In Codex, which cannot ask, you see a warning and the call runs."]
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
        _agree_before_a_change(gateway_url, read_key)
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


def _parse_hold_at(values):
    """`--hold-at` values as a rule's `hold_at`: one plain number ("25"), or one per environment
    ("prod=25", "dev=500"). Raises ValueError with the line to write."""
    def number(text):
        t = str(text).strip()
        # Digits and at most one point: float() also took "1e5" and "1_000", and "25.0" was
        # stored and shown as 25.0 (review).
        if not re.fullmatch(r"\d+(\.\d+)?", t, re.ASCII):
            raise ValueError("--hold-at %s is not a number. Write a number, or one per "
                             "environment: --hold-at prod=25 --hold-at dev=500" % text)
        n = float(t)
        n = int(n) if n.is_integer() else n
        if not _limit_ok(n):
            raise ValueError("--hold-at %s: the number must be above 0 and below "
                             "1,000,000,000,000,000" % text)
        return n
    if not values:
        raise ValueError("a rule with --argument needs the number it holds at: --hold-at 25, or "
                         "one per environment: --hold-at prod=25 --hold-at dev=500")
    if len(values) == 1 and "=" not in values[0]:
        return number(values[0])
    out = {}
    for v in values:
        env, sep, n = str(v).partition("=")
        env = env.strip()
        if not sep or not ENV_RE.match(env):
            raise ValueError(("--hold-at %s: each names an environment in lower case, such as "
                              "--hold-at prod=25" if len(values) > 1 else
                              "--hold-at %s: name the environment in lower case, such as "
                              "--hold-at prod=25") % v)
        if env in out:
            raise ValueError("--hold-at names %s twice" % env)
        out[env] = number(n)
    return out


def _hold_at_words(hold_at, currency=None):
    """'25', '25 on prod and 500 on dev, and 25 anywhere else', or with a currency after EACH
    number, '500 USD on prod, and 500 USD anywhere else' (review: one currency at the end read as
    the last environment's). "Anywhere else": a call naming no environment the rule lists is held
    at the lowest, and "500 USD on prod" alone read as if dev were not limited."""
    unit = (" " + currency.upper()) if currency else ""
    # A whole number without ".0", as /app writes it: a file may hold 25.0 (scoped review).
    num = lambda n: "{:,}".format(int(n) if isinstance(n, float) and n.is_integer() else n)  # noqa: E731
    if not isinstance(hold_at, dict):
        return num(hold_at) + unit
    parts = ["{}{} on {}".format(num(n), unit, env) for env, n in hold_at.items()]
    said = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return "{}, and {}{} anywhere else".format(said, num(min(hold_at.values())), unit)


def _money_options(money):
    """`--currency`, `--currency-field` and `--unit` as a rule's keys, or a sentence saying what
    to write instead (a str)."""
    if not money:
        return {}
    cur = money.get("currency")
    if not cur or not CURRENCY_RE.match(cur):
        return ("--currency names the currency the number is in, such as --currency USD"
                if cur is None or not money.get("currency") else
                "--currency %s is not a currency code such as USD" % cur)
    out = {"currency": cur.upper()}
    if "currency_field" in money:
        if not ARGUMENT_RE.match(money["currency_field"]):
            return "--currency-field names the argument that says the call's currency"
        out["currency_field"] = money["currency_field"]
    if "unit" in money:
        if money["unit"] not in UNITS:
            return "--unit takes only cents: --unit cents reads 2550 as 25.50"
        out["unit"] = money["unit"]
    if "recipient" in money:
        if not ARGUMENT_RE.match(money["recipient"]):
            return "--recipient names the argument that says who is paid, such as customer_id"
        out["recipient"] = money["recipient"]
    return out


def _add_number_rule(tools, phrases, argument, hold_ats, why, said, stop, assume_yes,
                     gateway_url, read_key, money=None):
    """`agentx rule add --tool T --argument A --hold-at N`: a rule that holds a call whose
    argument is at or above a number, one number or one per environment; with `--currency`, a
    money rule, which also replaces the gateway's default money limit for the tool. Its screen
    leads with the gateway, which is what checks it (the general screen led with Claude Code)."""
    money = _money_options(money)
    if isinstance(money, str):
        print(money)
        return 1
    tools = list(dict.fromkeys(tools))
    named = [t for t in tools if t not in (SHELL,) + SHELL_TOOLS]
    if len(tools) != 1 or not named:
        print("A rule with --argument names the one tool whose argument it reads, for example:")
        print("  agentx rule add --tool provision_instances --argument count --hold-at 25 "
              "--why \"more than a handful of VMs needs a second look\"")
        return 1
    if not argument or not ARGUMENT_RE.match(argument):
        print("--argument names the argument the rule reads, such as count, or spec.replicas "
              "inside an object.")
        return 1
    hold_at = _parse_hold_at(hold_ats)
    if not why:
        print("A team rule needs a reason, for example:")
        print("  --why \"more than a handful of VMs needs a second look\"")
        return 1
    tool = tools[0]
    # The name the tool's calls start with: an MCP tool's bare name, which the hook reads (review:
    # the full mcp__ name was never found in the call's text, so the rule held nothing there).
    match = list(dict.fromkeys(phrases or [_leading_name(tool)]))
    same = existing_team_rule(tools, match, read_team_rules(), argument=argument)
    if same is not None:
        _say("This is already a team rule: it reads %s on %s (%s). See it: agentx rule list"
             % (argument, tool, _added(same)))
        return 1
    cur = money.get("currency")
    lines = ["About to add a team rule. A gateway holds a call to %s when its %s is at or above %s, "
             "for you to answer with agentx holds." % (tool, argument,
                                                       _hold_at_words(hold_at, cur))]
    if isinstance(hold_at, dict):
        # The lowest is said once, in "anywhere else" above (scoped review); this says only how a
        # deployment names where it runs.
        lines.append("A deployment names its environment with AGENTX_ENVIRONMENT.")
    if cur:
        lines.append("This number is money: for this tool it takes the place of the gateway's "
                     "own money limit, higher or lower, unless a limit the gateway's operator "
                     "set is lower.")
        if money.get("unit") == "cents":
            lines.append("%s is read in cents: 2550 is 25.50 %s." % (argument, cur))
        if money.get("currency_field"):
            lines.append("A call whose %s is missing or not %s is held."
                         % (money["currency_field"], cur))
        if money.get("recipient"):
            lines.append("The hosted gateway adds up payments to the same %s over 24 hours "
                         "and holds the one that reaches the number. A gateway you run sets "
                         "that window with AGENTX_MONEY_TOTAL_HOURS (0 is off); one that sends "
                         "its records to a control plane does not add them up."
                         % money["recipient"])
    lines += ["A call whose %s is missing or not a number is held too." % argument,
              "Why: %s" % why,
              "The hosted gateway checks it once you send it with agentx rule push; the SDK on "
              "its own does not check team rules."]
    sdk_only = tool in set(_sdk_tools_seen(limit=1000))
    if not sdk_only:
        # The hook reads a number rule on an MCP tool of this name too (review: the screen said
        # only a gateway checks it, then Claude Code asked).
        lines.append("If %s is an MCP tool, Claude Code asks you before such a call too, through "
                     "the AgentX hook. In Codex, which cannot ask, %s." % (
                         tool, "the call is stopped" if stop else
                         "you see a warning and the call runs"))
    if not _confirm(lines, assume_yes):
        return 1
    _agree_before_a_change(gateway_url, read_key)
    rule = add_team_rule(tools, match, why, said=said,
                         where_ask_unsupported="stop" if stop else "warn",
                         argument=argument, hold_at=hold_at, **money)
    _say("Added %s, saved in %s. To remove it: agentx rule remove %s"
         % (rule["id"], team_rules_path(), rule["id"]))
    _say("Commit the file, and teammates get the same rule.")
    if read_key:
        _say(_PUSH_HINT)
    return 0


def reason_text(rule, hosted=False):
    """The sentence the person asked, and the agent, are shown. The harness frames it (Claude
    Code: "requires confirmation for this command"); the hook adds what a mode that cannot ask
    does instead. Outcome first, then why, what matched, and where to change the rule: "from
    your gateway (agentx rule list shows it)" named a mechanism, not a place to act. `hosted`:
    the key is the website's (agentx_sk_h_), so the rule can be changed on agentx-core.com/app;
    a self-hosted gateway's cannot.

    ⚠️ "<why>" and `This call contains "<phrases>".` are the gateway's held-call reason too
    (its `_team_rule_says`); a test keeps the two alike."""
    if rule.get("builtin"):
        # AgentX's own check (the hook's rule-change rule): nobody added it, and `found` says
        # what the command does, which its match words may not appear in.
        text = "AgentX: %s. This call %s." % (rule["why"].rstrip("."), rule["found"])
        return text + (" " + rule["note"] if rule.get("note") else "")
    who = (" (added by %s)" % rule["owner"]) if rule.get("owner") else ""
    # "Asks first", whatever the mode does with it: the auto-mode stop and Codex's warning are
    # said after this sentence by the hook.
    text = "AgentX: your team asks first. Why: %s%s." % (rule["why"].rstrip("."), who)
    number = number_says(rule)
    if number:
        text += " " + number
    # The tool's own name is no phrase worth saying (`shown_phrases`): 'This call contains
    # "refund_customer"' would only repeat the call's name back.
    shown = shown_phrases(rule)
    if shown:
        text += " This call contains %s." % _joined(('"%s"' % m for m in shown), "and")
    if rule.get(FROM_GATEWAY):
        # Not in this project's file, or (the hook marks it so, with the website's key only) in
        # it exactly as the gateway holds it: the person asked is told where it is changed.
        text += (" Change or switch off this rule at agentx-core.com/app." if hosted else
                 " Your team keeps this rule on its gateway; agentx rule list shows it.")
    elif os.environ.get("AGENTX_TEAM_RULES_FILE"):
        # The file the hook read, not the default it was moved from (scoped review).
        text += " It is in %s." % os.environ["AGENTX_TEAM_RULES_FILE"]
    else:
        text += " It is in this project's .agentx/team-rules.json."
    return text


# Set by the hook on a copy of each rule it took from the gateway, never stored in a file.
FROM_GATEWAY = "from_gateway"
