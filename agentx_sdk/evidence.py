"""`agentx evidence`: the evidence file, written from THIS machine's record.

The same schema as the hosted gateway's file (`agentx.evidence/2`), marked `door: "local"`, with
each field's local meaning: the rules this machine checks calls against (each with a reviewer's
description), the rules switched off and what still runs, the calls the local record shows
stopped or held (a call stopped while watching is listed as having run), a fingerprint over the
local rules and the SDK version, and the record's latest chain link, which
`agentx audit --record --head` checks later. A field with no local source is named in
`not_on_this_door`, never filled in.

Its words come from `evidence_words.json`, the file the gateway and the website read too: words
travel between doors, rules do not.

Read-only: it never writes the ledger, the rules or the incident store.
"""
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

SCHEMA = "agentx.evidence/2"
STOPPED_LIMIT = 500
_WORDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_words.json")


def words():
    """The shared evidence words (verdicts, notes, descriptions per door)."""
    with open(_WORDS_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def _iso(ts):
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
    except Exception:
        return None


def _canonical(value):
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


# Words are listed as words, never paraphrased into how the scan matches them: which arguments
# it reads and which cases it lets through differ by rule, and two rounds of review found each
# paraphrase false somewhere (decorators.evaluate_call_keyless is the authority).
def _words(intents):
    """The words as the check reads them: a blank one matches nothing, so it is not listed."""
    return [str(w).strip() for w in (intents or []) if str(w).strip()]


def _quoted(words):
    # Quoted, so a word with a comma in it does not read as two (review).
    return ", ".join('"%s"' % w for w in words)


def _added_words(pid, held_row, dec):
    """Words a policies file added to a shipped rule or check, beyond the ones it ships with."""
    shipped = {str(w).lower().strip() for s in dec._BUILTIN_POLICY_KEYWORDS
               if str(s.get("id")) == pid for w in (s.get("blocked_intents") or [])}
    return [w for w in _words((held_row or {}).get("blocked_intents"))
            if w.lower() not in shipped]


def _added_sentence(pid, held_row, shown_name, noun, dec):
    """The words a policies file added under this id, as one sentence ("" when none). A stop on
    one of those words is recorded under the file row's name, so a name other than the row's is
    given too, for every name the record can carry to appear in this file."""
    added = _added_words(pid, held_row, dec)
    if not added:
        return ""
    named = (held_row or {}).get("name")
    return ("Your policies file adds words under this %s%s: %s."
            % (noun, ', named "%s"' % named if named and named != shown_name else "",
               _quoted(added)))


# A built-in's "is allowed" clause is true of the shipped check alone: words a policies file
# adds under it can stop such a call (the founder's wording; measured with DELETE FROM
# under Mass Destructive Intent stopping a WHERE-limited delete). "Is not stopped" makes the same
# claim. Which descriptions carry one is pinned by a sweep in test_local_evidence.py.
ALLOWED_CLAUSE = re.compile(r"\b(?:is|are) (?:allowed|not stopped)\b")
ALLOWED_CAVEAT = "Words your policies file adds can stop a call this description says is allowed."


def _with(description, sentence):
    if not sentence:
        return description
    if description and ALLOWED_CLAUSE.search(description):
        sentence = "%s %s" % (sentence, ALLOWED_CAVEAT)
    return ("%s %s" % (description or "", sentence)).strip()


# The kinds of rule the screens count by, as this file names them.
KIND_FILE = "word list (from your policies file)"
KIND_ADOPTED = "your rule (adopted)"
KIND_TEAM = "your team's rule (asks)"


def team_rule_entries():
    """(in force, switched off, fingerprint rows) for the team rules this machine's hook checks:
    the project's team rules file and the rules it took from your gateway, each id the copy the
    hook uses, read as the hook reads them (`hook._team_rules_here`, never asking the gateway).

    WHY. The file opened with "the rules this machine's AgentX checks agent calls against" and
    left every team rule out, while `agentx rule list` showed them.

    🔴 FACTS, NOT A VERDICT PER CALL (two review rounds). A first version decided, per rule,
    which harness checks it here, and every round found another case it guessed wrong: a hook
    installed in a settings file it did not read, an MCP tool's name taken for an SDK function,
    the wrong fix named for the wrong harness. So each description says what the rule matches and
    how the hook treats it, stated with its scope; where the hook was found is a fact of its own
    (`rule_sources`' "team_rules_hook"), never folded into a conclusion. Never raises: [] on a
    failed read, which `rule_sources` then names."""
    from . import hook, team_rules
    try:
        path = team_rules.team_rules_path()
        rules, _line = hook._team_rules_here(os.getcwd(), path, pull=False)
    except Exception:
        return [], [], []
    in_force, off = [], []
    for r in rules:
        rid = str(r["id"])
        name = "Team rule %s" % rid
        # Not "(agentx rule push)": a rule on the gateway can be made on the website too.
        source = ("taken from your gateway" if r.get(team_rules.FROM_GATEWAY)
                  else "in the project's team rules file")
        if not r.get("active", True):
            off.append({"id": rid, "name": name,
                        "why": "A team rule (%s), switched off, so nothing matches it." % source})
            continue
        # Where the hook runs is the notes' and `team_rules_hook`'s to say, not each rule's.
        clauses = [
            "Asks before %s: the AgentX hook checks a matching shell or MCP call before Claude "
            "Code or Codex runs it, whether AgentX is blocking or watching. The first matching "
            "team rule answers, and a call a built-in rule stops is stopped first."
            % team_rules._describe(r)]
        if any(t != "PowerShell" for t in r["tools"]):
            # Codex's hook never sees PowerShell (`hook.CODEX_HOOK_MATCHER`). Known limit: a rule
            # naming only "PowerShell" also matches an MCP tool by that bare name, which Codex
            # does see; left unsaid, as no such tool is known (review round 4).
            clauses.append("Codex cannot ask, so there it %s." % (
                "stops the call" if r.get("where_ask_unsupported") == "stop"
                else "warns and lets the call run"))
        clauses.append("Claude Code in a mode that does not ask, such as auto, stops the call.")
        bare = [t for t in r["tools"] if t not in (team_rules.SHELL, "Bash", "PowerShell")
                and not t.startswith("mcp__")]
        if bare:
            # What the hook sees of a bare name, never what the name is (review: an MCP server's
            # function also shows in the SDK's record under the same name).
            clauses.append("The hook sees %s only in an MCP call (mcp__<server>__<name>); a call "
                           "to an SDK agent's function, or to another Claude Code tool, by that "
                           "name is not one the hook sees."
                           % " or ".join("'%s'" % t for t in bare))
        # A gateway reads ONE copy (`_team_rules_source_path`): the pushed one whenever it has
        # one, never merged, and a shared box never the file (review; `team_rules._PUSH_HINT`).
        clauses.append("The SDK on its own checks no team rule. A gateway checks the copy it "
                       "reads: the project's team rules file when it runs beside this project "
                       "and was never sent rules, else the copy last sent with agentx rule push.")
        clauses.append("Why: %s (%s)." % (r["why"].rstrip("."), source))
        in_force.append({"id": rid, "name": name, "kind": KIND_TEAM, "applies_to": None,
                         "description": " ".join(clauses)})
    # ONE row, in order: the first matching rule answers, so swapping two rules changes what is
    # checked, and the fingerprint (computed over sorted rows) must move with it (review). In
    # force or off follows each rule's own `active`, which the row holds.
    rows = [["team_rules", [[{k: v for k, v in r.items() if k != team_rules.FROM_GATEWAY},
                             bool(r.get(team_rules.FROM_GATEWAY))] for r in rules]]] if rules else []
    return in_force, off, rows


# Where `agentx hook install` (and `--codex`) put the hook in a project, and where Claude Code
# also runs one from (hook.install reads the shared file too).
_HOOK_SETTINGS = (("Claude Code", os.path.join(".claude", "settings.local.json")),
                  ("Claude Code", os.path.join(".claude", "settings.json")),
                  ("Codex", os.path.join(".codex", "hooks.json")))


def team_rules_hook():
    """Which of the project's settings files hold the AgentX hook's check (its PreToolUse
    entry, the one that asks): "found in <files>", "not found in <files>", plus "could not read
    <file>" for one that would not parse (never counted as "not found": review). The project
    is the one the team rules file is read from (`_anchored_root`), not the working folder.
    Settings outside the project are not read, and the value says so. A fact for the reader,
    never a conclusion about a call (review). Never raises."""
    from . import hook
    from .overrides import _anchored_root
    try:
        root = _anchored_root()
        found, unread = [], []
        for _harness, rel in _HOOK_SETTINGS:
            shown = rel.replace(os.sep, "/")
            settings, err = hook._read_settings(os.path.join(root, rel))
            if err:
                unread.append(shown)
                continue
            pre = ((settings or {}).get("hooks") or {}).get("PreToolUse") or []
            if any(hook._is_ours(h) for entry in pre if isinstance(entry, dict)
                   and isinstance(entry.get("hooks"), list) for h in entry["hooks"]):
                found.append(shown)
        parts = []
        read_ok = [rel.replace(os.sep, "/") for _h, rel in _HOOK_SETTINGS
                   if rel.replace(os.sep, "/") not in unread]
        if found:
            parts.append("found in %s" % ", ".join(found))
        elif read_ok:
            parts.append("not found in %s" % ", ".join(read_ok))
        if unread:
            parts.append("could not read %s" % ", ".join(unread))
        return "%s (settings outside the project not read)" % "; ".join(parts)
    except Exception:
        return "could not read"


def team_rules_from_gateway():
    """Where the copy of your gateway's team rules the hook checks stands: "no key" (none found
    here, so the hook takes none), "not taken yet" (the hook takes it before its next check),
    "taken", or the copy's own status ("refused", "unreachable", "old", "unreadable", "error")
    with ", earlier copy kept" where the hook still checks the rules it took before. Read as the
    hook reads it; never asks the gateway. A list with no gateway rule must say why (review)."""
    from . import hook, team_rules
    try:
        gateway = hook._team_gateway()
        if not gateway:
            return "no key"
        doc = team_rules.read_pulled(gateway[0], gateway[1], path=team_rules.team_rules_path())
        if doc is None:
            return "not taken yet"
        status = doc.get("status")
        if status == "ok":
            return "taken"
        return "%s%s" % (status, ", earlier copy kept" if team_rules.pulled_rules(doc) else "")
    except Exception:
        return "could not read"


def builtin_checks():
    """The built-in checks listed beside the policies: not in `agentx policies`' catalog, so
    `agentx status` counts them from here, the list this file is built from."""
    from . import decorators as dec
    return (dec._INVISIBLE_UNICODE_POLICY, dec._REVERSE_SHELL_POLICY)


def moved_while_off():
    """The one built-in check that keeps stopping calls under ANOTHER rule's name while a policies
    file switches its own rule off: the named-column PII floor, Customer Privacy Shield to
    Secrets and PII Exfiltration. {"off_id", "off_line", "to_id", "to_name", "to_line"} while
    that rule is off here, else None. Every surface listing the rules says it (the screens, the
    evidence file, `agentx policies --json`), so none reads as if the read now runs: the rule
    that is off says where its read went, and the rule that stops it says it does."""
    from . import decorators as dec
    to = dec._pii_bulk_read_policy()
    off = dec._CUSTOMER_PRIVACY_POLICY
    if str(to["id"]) == str(off["id"]):
        return None
    return {"off_id": str(off["id"]),
            "off_line": "Bulk reads of customer data are still stopped, under %s." % to["name"],
            "to_id": str(to["id"]), "to_name": to["name"],
            "to_line": "With %s switched off, it also stops a bulk read of customer data, for "
                       "example SELECT email, phone FROM customers." % off["name"]}


def policies_file_rules(doc=None):
    """What `.agentx/policies.json` arms beyond the shipped rules and words, in this file's own
    sentences: [{"id", "name", "text"}], a rule of the file's own (`own: True`) or words added
    under a built-in rule or check (`own: False`).

    ONE SOURCE for every screen that says what is armed here (`agentx status`, `agentx
    policies` and its `--json`, `agentx audit`): three of them left a team's rule out while
    this file listed it (step-2 walk). `doc` is the `agentx policies --json` document when
    the caller is building it, so the two cannot recurse. None when the file could not be
    read: a malformed file arms none of its rules, and [] would say it added nothing (review)."""
    return armed_beyond_builtin(doc)["from_file"]


def rule_sources():
    """Every place this machine's rules come from, and whether it was read: "read", "no file",
    or why not ("damaged", "could not open", "earlier import file", "could not read"). The evidence
    file's `rule_sources`, and the one answer `agentx status` and `agentx audit` give: each
    screen used to decide "could not read" its own way, and one of them mistook an earlier
    import file for a damaged one."""
    from . import decorators as dec
    from . import rules as rules_mod
    sig = dec._policy_file_signature()
    path = sig[0] if sig else None
    try:
        err = dec.current_policy_load_error()
    except Exception as exc:
        err = exc
    if err is None:
        policies = "read" if path else "no file"
    elif not path:
        policies = "could not read"
    else:
        try:
            with open(path, encoding="utf-8") as fh:
                json.load(fh)
            policies = "damaged"          # it parses, so the load refused its shape
        except OSError:
            policies = "could not open"
        except Exception:
            policies = "damaged"
    from . import team_rules
    try:
        team = team_rules.team_rules_state()
    except Exception:
        team = "could not read"
    return {"policies_file": policies,
            "adopted_rules": rules_mod.adopted_rules_state(),
            "outbound_allowlist": rules_mod.allowlist_state(),
            # The project's team rules file. "damaged": its rules are not in
            # rules_in_force, and only those the hook took from your gateway are.
            "team_rules": team,
            # The second source of team rules, said apart so a list with none of the gateway's
            # rules says why (review).
            "team_rules_from_gateway": team_rules_from_gateway(),
            # Where the hook that checks team rules was found: a fact, not a verdict (review).
            "team_rules_hook": team_rules_hook()}


# The states that mean the source was read. An absent file holds nothing, and an earlier import
# file under the rules name was read and holds no rules (status says to rename it).
SOURCE_OK = ("read", "no file", "earlier import file")


def armed_beyond_builtin(doc=None):
    """Everything armed here beyond the built-in rules and checks, from the list this file is
    built from: {"from_file": policies_file_rules' list or None, "adopted": the count of armed
    adopted rules, "sources": `rule_sources()`, "allowlist": {agent: sites} or None,
    "allowlist_error": str or None, "off": [{"name", "why"}] for the built-in policies switched
    off in the policies file}.

    `agentx audit` called its built-in list "the whole list" over all of these, and `agentx
    status` left the allowlist out of its counts (review)."""
    in_force, off, _rows, load_error, allow_error, allowlist, from_file = _rules(
        words()["descriptions"]["local"], doc)
    return {"from_file": None if load_error else from_file,
            "adopted": sum(1 for r in in_force if r["kind"] == KIND_ADOPTED),
            "sources": rule_sources(),
            "allowlist": allowlist, "allowlist_error": allow_error,
            # Built-in policies switched off in the file, with this file's reason (which says
            # where a read the rule stopped is stopped now, `moved_while_off`): listed off here,
            # still counted among "built-in policies" on status (review 2).
            "off": [{"name": o["name"], "why": o["why"]} for o in off]}


def _rules(local_descriptions, doc=None):
    """(in_force, off, fingerprint_rows, load_error, allow_error, allowlist, from_file). Read
    through the same accessors the keyless check uses on every call, and the same export
    `agentx policies --json` prints."""
    from . import decorators as dec
    from . import rules as rules_mod

    if doc is None:
        from .cli import _policies_json_payload
        doc = _policies_json_payload()
    in_force, off, rows, from_file = [], [], [], []
    held = {str(p.get("id")): p for p in (dec.LOCAL_POLICY_KEYWORDS or [])}
    moved = moved_while_off()

    def entry(pid, name, category, kind, description):
        # `applies_to` has no local source (see `not_on_this_door`): present and null, so a
        # program reading both doors' files finds the same keys. No `category`: it is our
        # internal label, and the hosted file does not carry it (walk).
        return {"id": pid, "name": name, "kind": kind,
                "description": description, "applies_to": None}

    for p in doc["policies"]:
        pid = str(p["id"])
        if p["enforced"]:
            # The hosted file's words for the same two kinds: code plus trigger words, or code
            # alone. Decided by whether the rule HOLDS words: Filesystem Path Boundary has none
            # and read "and word list" (walk).
            words_held = bool((held.get(pid) or {}).get("blocked_intents"))
            added = _added_sentence(pid, held.get(pid), p["name"], "rule", dec)
            description = _with(local_descriptions.get(pid), added)
            if moved and pid == moved["to_id"]:
                description = ("%s %s" % (description or "", moved["to_line"])).strip()
            in_force.append(entry(p["id"], p["name"], p.get("category"),
                                  ("built-in check and word list" if words_held
                                   else "built-in check")
                                  + (", your coaching wording" if p["customized"] else ""),
                                  description))
            rows.append(["rule", pid, held.get(pid)])
            if added:
                from_file.append({"id": p["id"], "name": p["name"], "text": added, "own": False})
        elif p.get("built_in_checks_still_run"):
            off.append({"id": p["id"], "name": p["name"],
                        "why": "Its trigger words are switched off in your policies file. "
                               "Built-in checks that report under this rule's name still stop "
                               "calls."})
        else:
            why = "Switched off in your policies file."
            if moved and pid == moved["off_id"]:
                why = "%s %s" % (why, moved["off_line"])
            off.append({"id": p["id"], "name": p["name"], "why": why})
    for det in builtin_checks():
        # A policies-file row under a check's own id arms its words too (the loop below skips
        # it): named in the kind, the description and the fingerprint (review). The row keeps
        # the check's name, which its own stops are recorded under; a word stop is recorded
        # under the file row's name, which the description gives.
        words = held.get(str(det["id"]))
        added = _added_sentence(str(det["id"]), words, det["name"], "check", dec)
        in_force.append(entry(det["id"], det["name"], det.get("category"),
                              "built-in check and word list"
                              if (words or {}).get("blocked_intents") else "built-in check",
                              _with(local_descriptions.get(str(det["id"])), added)))
        rows.append(["detector", det["id"], det["name"], words])
        if added:
            from_file.append({"id": det["id"], "name": det["name"], "text": added, "own": False})
    # A word rule in the policies file that is not one of the built-ins the export lists is armed
    # (the check holds it), so it is listed, after the built-ins, in its own words (review). It
    # may be a team's own or one `agentx pull` brought down, so it is named by where it lives,
    # not by who wrote it.
    listed = {str(p["id"]) for p in doc["policies"]}
    for pid, p in sorted(held.items()):
        if pid in listed or pid in local_descriptions:
            continue
        words = _words(p.get("blocked_intents"))
        text = ("Stops calls matching these words from your policies file: %s." % _quoted(words)
                if words else "A rule in your policies file with no usable words: it stops "
                              "nothing.")
        in_force.append(entry(p.get("id"), p.get("name") or pid, None, KIND_FILE, text))
        rows.append(["file-rule", pid, p])
        from_file.append({"id": p.get("id"), "name": p.get("name") or pid, "text": text,
                          "own": True})
    for r in rules_mod._armed_adopted_rules():
        # The developer's own rule, in their own words.
        in_force.append(entry(r["id"], r.get("name") or r["id"], r.get("target_action"),
                              KIND_ADOPTED,
                              r.get("semantic_description") or r.get("name")))
        rows.append(["adopted", r["id"], r])
    allow_error = None
    try:
        allow = rules_mod.read_allowlist()
    except Exception as exc:
        # A damaged file fails CLOSED in the live check: every call to a site is stopped until
        # it is fixed. Dropping it here told a reviewer no allowlist was in force while every
        # outbound call was being refused, so it is a rule in force, and a field not read.
        allow, allow_error = None, "%s: %s" % (type(exc).__name__, exc)
        in_force.append(entry(dec._OUTBOUND_ALLOWLIST_POLICY["id"], "Outbound Allowlist",
                              "OUTBOUND_ALLOWLIST", "your allowlist",
                              "The allowlist file could not be read (%s), so every call to a "
                              "site is stopped until it is fixed (recorded only, while watching)."
                              % allow_error))
        rows.append(["allowlist_unreadable", allow_error])
    if allow:
        for agent, hosts in sorted(allow.items()):
            hosts = sorted(hosts)
            # The allowlist itself, not a count of it: what a reviewer asked for.
            in_force.append(entry(dec._OUTBOUND_ALLOWLIST_POLICY["id"],
                                  "Outbound Allowlist (%s)" % agent, "OUTBOUND_ALLOWLIST",
                                  "your allowlist",
                                  "Calls from %s may reach only these sites: %s."
                                  % (agent, ", ".join(hosts) if hosts else "none")))
            rows.append(["allowlist", agent, hosts])
    # The allowlist as data: {} with no file, None when it could not be read (named in
    # `could_not_read` then, like every other null field).
    allowlist = None if allow is None else {a: sorted(h) for a, h in sorted(allow.items())}
    return in_force, off, rows, doc["shield"]["load_error"], allow_error, allowlist, from_file


def _not_run_or_opinion_clause():
    """db's "had an opinion" clause widened by REFUSED: the population this file lists and
    counts as stopped or held. One helper, so the list and its count cannot disagree."""
    from . import db
    sql, params = db._had_an_opinion_clause()
    return ("(%s OR status IS ? OR status IS ?)" % sql,
            list(params) + [db.REFUSED_STATUS, db.HALTED_STATUS])


# Kept byte-identical to the gateway's own copy of this rule (a test asserts it). A host can carry
# a secret in a label (`ghp_<token>.paste.example`
# is how DNS-label exfiltration is written), and this file is built to be handed on, so a label of
# 20 or more characters mixing letters and digits is shown as [withheld]; the rest of the host
# still says where the call went. An IP address has no letters and is never masked.
_SECRETISH_LABEL_RE = re.compile(r"^(?=[a-z0-9_-]*[0-9])(?=[a-z0-9_-]*[a-z])[a-z0-9_-]{20,}$")


def evidence_host(host):
    """`host` as this file shows it: a secret-looking label replaced by [withheld]."""
    return ".".join("[withheld]" if _SECRETISH_LABEL_RE.match(label) else label
                    for label in str(host).split("."))


def _masked_sites(sites):
    """{agent: {host: calls}} with each host shown as evidence_host shows it; two hosts that show
    the same are counted together. None (could not read) stays None."""
    if not isinstance(sites, dict):
        return sites
    out = {}
    for agent, hosts in sites.items():
        merged = {}
        for host, calls in (hosts or {}).items():
            shown = evidence_host(host)
            merged[shown] = merged.get(shown, 0) + (calls or 0)
        out[agent] = merged
    return out


def _ledger(db_path, verdicts):
    """(stopped rows, sites_since, sites undated, readable). The sites' period is read over the
    rows `db.get_destinations` counts (a site named, an allowed status), never the whole ledger."""
    from . import db
    if not os.path.exists(db_path):
        return [], None, False, True
    try:
        conn = db.calls_view(sqlite3.connect(db.read_only_uri(db_path), uri=True))
    except sqlite3.Error:
        return None, None, False, False
    try:
        # db's own "had an opinion" clause, so a legacy row with no status counts here exactly
        # as it does in every count db makes (a `NOT IN` drops a NULL status).
        # PLUS the calls refused for want of a verdict: not an opinion, but a call this machine
        # did not run, which is what this list is for. Same widening in `_opinion_counts`.
        opinion_sql, opinion_params = _not_run_or_opinion_clause()
        # The site each call was addressed to, so a reviewer can see where a call that ran while
        # watching went. A record older than the `dest_hosts` column has none to give: its rows
        # say null (not read), never [] (read, no site).
        select = ("SELECT id, timestamp, agent_id, tool_name, policy_name, status, posture, %s "
                  "FROM event_log WHERE %s ORDER BY timestamp DESC, id DESC LIMIT ?")
        params = tuple(opinion_params) + (STOPPED_LIMIT,)
        # Newest column first, each older record falling back one step: a record with sites and
        # no recipient domains still lists its sites.
        sites_column = domains_column = False
        rows = None
        for cols, has_sites, has_domains in (("dest_hosts, dest_domains", True, True),
                                             ("dest_hosts, NULL", True, False),
                                             ("NULL, NULL", False, False)):
            try:
                rows = conn.execute(select % (cols, opinion_sql), params).fetchall()
                sites_column, domains_column = has_sites, has_domains
                break
            except sqlite3.OperationalError:
                continue
        if rows is None:
            raise sqlite3.OperationalError("event_log could not be read")
    except sqlite3.Error:
        conn.close()
        return None, None, False, False
    try:
        # The statuses that RAN, not "no opinion": a REFUSED call had no opinion and did not run.
        ran = tuple(db.RAN_WITHOUT_OPINION_STATUSES)
        sites_oldest, sites_undated = conn.execute(
            "SELECT MIN(timestamp), SUM(timestamp IS NULL) FROM event_log "
            "WHERE dest_hosts IS NOT NULL AND status IN (%s)" % ",".join("?" * len(ran)),
            ran).fetchone()
    except sqlite3.Error:
        # A ledger older than the `dest_hosts` column: no site was recorded, so none is counted.
        sites_oldest, sites_undated = None, 0
    finally:
        conn.close()
    from .hook import HOOK_AGENT_LABELS as _HOOK_LABELS
    # The hook's own agent ids are ours, not names a reviewer knows: said as what they are.
    stopped = [{"time": _iso(ts),
                "agent": _HOOK_LABELS.get(agent, agent),
                "tool": tool, "rule": rule,
                "verdict": verdicts.get(status, status), "status": status,
                "posture": {"audit": "watching", "enforce": "enforcing"}.get(posture, posture),
                # Masking can make two hosts read the same: listed once.
                "sites": (sorted({evidence_host(h) for h in (hosts or "").split(",") if h})
                          if sites_column else None),
                # The domains of the email addresses the call was addressed to, never the
                # address; null on a record older than the column. The gateway's file lists
                # them too, as the SDK sent them.
                "recipient_domains": (
                    sorted({evidence_host(d) for d in (domains or "").split(",") if d})
                    if domains_column else None),
                "ledger_id": rid, "receipt_id": None}
               for rid, ts, agent, tool, rule, status, posture, hosts, domains in rows]
    return stopped, _iso(sites_oldest) if sites_oldest is not None else None, \
        bool(sites_undated), True


def _opinion_counts(db_path):
    """(stopped, held, not run, halted, ran while watching) over the WHOLE record, or None when it
    cannot be read. The listed calls are the newest few hundred, so counting them said
    "0 stopped" over a record whose one stopped call was older than the list (review).

    HELD and REFUSED are their own counts, never "stopped": the file names them in their own
    words ("Held for a person, not approved"; "Not run: no verdict could be had"), and a
    refusal is not an objection, so a "stopped" count that took them in said otherwise in the
    one line printed beside the file (review)."""
    from . import db
    if not os.path.exists(db_path):
        return 0, 0, 0, 0, 0
    try:
        conn = db.calls_view(sqlite3.connect(db.read_only_uri(db_path), uri=True))
        try:
            sql, params = _not_run_or_opinion_clause()
            total, ran, held, refused, halted = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(status IS 'WOULD_BLOCK'), 0), "
                "COALESCE(SUM(status IS ?), 0), COALESCE(SUM(status IS ?), 0), "
                "COALESCE(SUM(status IS ?), 0) FROM event_log WHERE %s" % sql,
                (db.HELD_STATUS, db.REFUSED_STATUS, db.HALTED_STATUS) + tuple(params)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return total - ran - held - refused - halted, held, refused, halted, ran


def _record_head(db_path):
    from .cli import _record_status
    from . import db
    v = _record_status(db_path, db.CHAIN_TABLES)
    if not v:
        return None, None
    if not v.get("head_seq"):
        # No entry yet, so no head; the verdict still stands. A row inserted outside AgentX into
        # a ledger with no journal entry reads `intact: False`, and must not read as "no record".
        return None, v.get("intact")
    return "ledger:%s:%s" % (v["head_seq"], v.get("head_link") or ""), v.get("intact")


def build(db_path=None):
    from . import db
    from . import rules as rules_mod
    from .cli import _sdk_version
    db_path = db_path or db.DB_PATH
    w = words()
    notes = w["notes"]["local"]
    in_force, off, fp_rows, load_error, allow_error, allowlist, _ = _rules(
        w["descriptions"]["local"])
    # Team rules here, not in `_rules`: its lists also feed `agentx status`'s built-in counts,
    # where a team rule switched off is not a built-in policy.
    team_in, team_off, team_rows = team_rule_entries()
    in_force, fp_rows = in_force + team_in, fp_rows + team_rows
    version = _sdk_version()
    fingerprint = hashlib.sha256(_canonical([version, sorted(fp_rows, key=_canonical)])
                                 .encode("utf-8")).hexdigest()
    stopped, sites_since, sites_undated, readable = _ledger(db_path, w["verdicts"])
    sites = _masked_sites(db.get_destinations(db_path, statuses=db.RAN_WITHOUT_OPINION_STATUSES)) \
        if readable else None
    head, intact = _record_head(db_path)
    could_not_read = [name for name, value in (("stopped_or_held_calls", stopped),
                                               ("sites_recorded", sites),
                                               ("outbound_allowlist", allowlist))
                      if value is None]
    # The hosted file's rule, decided once: a shown row with no date makes the list's period
    # unknown, never a "since" the list does not fit.
    stopped_undated = bool(stopped) and not all(r["time"] for r in stopped)
    # db prunes with ONE row cap over every record (allowed calls spent first), not one cap per
    # list as the gateway does: both maximums are that cap, and `max_rows_shared` says so.
    records_kept = {
        "days": db._RETENTION_DAYS,
        "max_stopped_or_held_calls": db._RETENTION_MAX_ROWS,
        "max_allowed_calls": db._RETENTION_MAX_ROWS,
        "max_rows_shared": True,
        "stopped_or_held_since": stopped[-1]["time"] if stopped and not stopped_undated else None,
        "sites_since": None if sites_undated else sites_since,
        "period_unknown": ((["stopped_or_held_calls"] if stopped_undated else [])
                           + (["sites_recorded"] if sites_undated else [])),
    }
    # schema, produced_by and about first, in the hosted file's order: what a reader opening the
    # file sees first is what it is.
    return {
        "schema": SCHEMA,
        "produced_by": {"tool": "agentx evidence", "version": version,
                        "docs": "https://agentx-core.com/docs"},
        "about": notes["about"],
        "door": "local",
        "before_you_share": w["notes"]["before_you_share"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sdk_version": version,
        "rules_readable": load_error is None,
        "rules_load_error": load_error,
        "rules_in_force": in_force,
        "rules_in_force_note": notes["rules_in_force"],
        # What the SQL checks do not promise, said once.
        "sql_checks_note": notes["sql_checks"],
        # Adopted rules marked off too: listed nowhere, they made this file's count
        # differ from status's, which lists them marked off. Not in `armed_beyond_builtin`'s
        # "off", which status prints under the built-in policies. The reason names no file: on
        # an install not yet moved, the rule is a store row (`agentx evidence` never moves them),
        # and "in your rules file" was false there (review of 569723ce).
        "rules_off": off + [
            {"id": r["id"], "name": r.get("name") or r["id"],
             "why": "A rule you added, switched off, so nothing matches it."}
            for r in rules_mod.switched_off_adopted_rules()] + team_off,
        "rules_fingerprint": fingerprint,
        "rules_fingerprint_note": notes["rules_fingerprint"],
        "stopped_or_held_calls": stopped,
        "stopped_or_held_calls_limit": STOPPED_LIMIT,
        "stopped_or_held_calls_note": notes["stopped_or_held_calls"],
        "sites_recorded": sites,
        "sites_recorded_note": notes["sites_recorded"],
        # What MCP servers changed in their tools. Not calls, so in no list of calls above, and
        # still here: a reviewer asks whether a tool changed under the agent.
        "server_changes": [
            # `held_then`, the name `agentx audit --json` gives the same fact: the record says
            # what pinning did at the time, never whether the tool is held now.
            {"tool": e["tool"], "what": db.SERVER_EVENT_WORDS[e["kind"]], "at": _iso(e["at"]),
             "held_then": e["held"]}
            for e in db.get_server_events(db_path)],
        "server_changes_note": notes["server_changes"],
        "outbound_allowlist": allowlist,
        "outbound_allowlist_note": notes["outbound_allowlist"],
        "rule_sources": rule_sources(),
        "rule_sources_note": notes["rule_sources"],
        "could_not_read": could_not_read,
        "not_on_this_door": w["not_on_this_door"]["local"],
        "records_kept": records_kept,
        "records_kept_note": notes["records_kept"],
        "record_head": head,
        "record_intact": intact,
        "record_head_note": notes["record_head"],
        "who_can_change": notes["who_can_change"],
    }


_GATEWAY_USAGE = (
    "Usage:\n"
    "  agentx evidence            this machine's record, in a dated file\n"
    "  agentx evidence --gateway  the file your gateway builds, for a reviewer\n"
    "\n"
    "  Either one takes:\n"
    "    --out FILE               written to FILE\n"
    "    --json                   printed, for a program\n"
    "\n"
    "  agentx evidence --gateway --head <value>\n"
    "                             checks the record was not rewritten since a\n"
    "                             file was made")


def _escape_c1(text):
    # C1 control characters (U+0080-U+009F) are not escaped by json.dumps, and a server-chosen
    # tool name can carry one: written raw, `cat` of the file would run it as a terminal code.
    # They can only sit inside strings, where \u escapes are valid JSON.
    return re.sub(r"[\x80-\x9f]", lambda m: "\\u%04x" % ord(m.group()), text)


def _value_after(args, flag):
    """The value after `flag`; None when it is last, empty or followed by another flag. Empty is
    missing: `--head "$SAVED"` with nothing saved wrote the file and exited 0, which a script reads
    as "still matches" (review); the TypeScript command refuses it the same way."""
    i = args.index(flag)
    value = args[i + 1] if i + 1 < len(args) else None
    return None if not value or value.startswith("--") else value


def _from_gateway(args, gateway_url, api_key, admin_key=None, admin_refusal=None):
    """`agentx evidence --gateway`: the file the gateway builds, notes and all (GET
    /v1/evidence?file=1), written as it came. The TypeScript SDK's `evidence` command and the
    website's download fetch the same file. `--head <value>` checks a value saved from an earlier
    file against the record now and writes nothing: 0 when it still matches, 1 otherwise."""
    import requests
    from .decorators import _sanitize_detail
    as_json = "--json" in args
    say = (lambda s: print(s, file=sys.stderr)) if as_json else print
    modes = [f for f in ("--out", "--json", "--head") if f in args]
    out = _value_after(args, "--out") if "--out" in args else ""
    head = _value_after(args, "--head") if "--head" in args else ""
    takes_value = {"--out", "--head"}
    stray = [a for i, a in enumerate(args)
             if (a.startswith("-") and a not in takes_value | {"--json", "--gateway"})
             or (not a.startswith("-") and (i == 0 or args[i - 1] not in takes_value))]
    if len(modes) > 1 or out is None or head is None or stray:
        print(_GATEWAY_USAGE, file=sys.stderr)
        return 2
    # Reading the evidence takes either key; the admin key is never needed for it.
    key = api_key or admin_key
    # Marked as the TypeScript `evidence` and both SDKs' `holds` mark them: an error leads with ❌,
    # a missing key with ⚠️ (founder's walk: the two SDKs' error lines differed).
    if not key and admin_refusal:
        say("❌ Nothing was sent. %s" % admin_refusal)
        return 1
    if not key:
        say("⚠️  No AGENTX_API_KEY, so there is no gateway to ask: the evidence file is built from your "
            "gateway's record of calls. For this machine's record: agentx evidence")
        return 1
    params = {"file": "1", **({"head": head} if head else {})}
    try:
        res = requests.get("%s/v1/evidence" % gateway_url.rstrip("/"), params=params,
                           headers={"Authorization": "Bearer %s" % key}, timeout=30.0)
    except Exception:
        # Never the exception's text: it can name the address with a token in it.
        say("❌ Could not reach your gateway at %s." % _sanitize_detail(gateway_url, limit=200))
        return 1
    if res.status_code in (401, 403):
        say("❌ Your gateway did not accept this key (%d)." % res.status_code)
        return 1
    try:
        doc = res.json()
    except ValueError:
        doc = None
    if res.status_code != 200 or not isinstance(doc, dict):
        detail = doc.get("detail") if isinstance(doc, dict) else None
        say("❌ Your gateway could not produce the evidence (%d): %s"
            % (res.status_code, _sanitize_detail(str(detail or res.text))))
        return 1
    if doc.get("schema") != SCHEMA:
        # An older gateway answers with the data alone; writing that would hand a reviewer a
        # file with none of its notes.
        say("❌ Your gateway does not build the evidence file yet. Update it to its latest version.")
        return 1
    if head:
        said = doc.get("record_head_check_note") or "Your gateway did not say."
        say(_sanitize_detail(str(said), limit=300))
        check = doc.get("record_head_check")
        return 0 if isinstance(check, dict) and check.get("result") == "matches" else 1
    text = _escape_c1(json.dumps(doc, indent=2, ensure_ascii=False))
    if as_json:
        print(text)
        return 0
    out_path = out or "agentx-evidence-%s.json" % datetime.now().strftime("%Y-%m-%d")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except OSError as exc:
        # Exit 2, as the local `agentx evidence` exits on a write it could not make.
        say("❌ Could not write %s (%s)." % (out_path, exc.strerror or exc))
        return 2

    def _count(field):
        return len(doc[field]) if isinstance(doc.get(field), list) else None

    stopped, watched = _count("stopped_or_held_calls"), _count("ran_while_watching")
    calls = ("the stopped calls could not be read" if stopped is None else
             "%d stopped or held call%s listed" % (stopped, "" if stopped == 1 else "s"))
    if watched:
        calls += ", %d call%s that ran while watching" % (watched, "" if watched == 1 else "s")
    rules = _count("rules_in_force") or 0
    # "off", not "switched off": a gateway rule is also off when no limit is set for it, which
    # nobody switched (its `why` in the file says which). The TypeScript command prints the same.
    print("Wrote %s: %d rule%s in force, %d off, %s."
          % (out_path, rules, "" if rules == 1 else "s", _count("rules_off") or 0, calls))
    if doc.get("record_head"):
        print("Record's latest entry: %s" % _sanitize_detail(str(doc["record_head"]), limit=200))
        print("To check later that the record was not rewritten: agentx evidence --gateway "
              "--head <that value>")
    if doc.get("before_you_share"):
        # Cleaned like every other server string on this screen: the file's copy is JSON-escaped,
        # the terminal's is not (review).
        print(_sanitize_detail(str(doc["before_you_share"]), limit=400))
    return 0


def main(args=None, gateway_url=None, api_key="", admin_key=None, admin_refusal=None):
    """`agentx evidence` writes the file (`--out FILE`, else agentx-evidence-<day>.json here) and
    says what is in it; `--json` prints the document on stdout for a program instead. Only
    `--json` writes to stdout, because the CLI's banner moves to stderr on `--json` alone: a
    document printed without it reached a pipe with the banner above it and did not parse.

    `--gateway` writes the file your gateway builds instead (`_from_gateway`)."""
    args = list(args or [])
    if "--gateway" in args:
        from .envfile import DEFAULT_GATEWAY_URL     # the one spelling of the default
        return _from_gateway(args, gateway_url or DEFAULT_GATEWAY_URL, api_key,
                             admin_key, admin_refusal)
    if "--head" in args:
        # A check of the gateway's record, never a file written over a flag this path ignores.
        print("agentx evidence: --head checks your gateway's record, so add --gateway. For this "
              "machine's record: agentx audit --record --head <value>", file=sys.stderr)
        return 2
    # Before anything is built or written: this path read only the flags it knew, so `--help`, or a
    # typo of `--json`, wrote the file. To stderr and non-zero, as `--gateway` and TypeScript do, so
    # `--json` keeps stdout a document even when the command line is wrong.
    stray = [a for i, a in enumerate(args)
             if (a.startswith("-") and a not in ("--out", "--json"))
             or (not a.startswith("-") and (i == 0 or args[i - 1] != "--out"))]
    if stray:
        print(_GATEWAY_USAGE, file=sys.stderr)
        return 2
    doc = build()
    text = _escape_c1(json.dumps(doc, indent=2, ensure_ascii=False))
    if "--json" in args:
        print(text)
        return 0
    out_path = None
    if "--out" in args:
        i = args.index("--out")
        out_path = args[i + 1] if i + 1 < len(args) else None
        if not out_path:
            print("agentx evidence: --out needs a file name.", file=sys.stderr)
            return 2
    out_path = out_path or "agentx-evidence-%s.json" % datetime.now().strftime("%Y-%m-%d")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except OSError as exc:
        # A missing folder or a read-only one: one plain line, not a traceback.
        print("agentx evidence: could not write %s (%s)." % (out_path, exc.strerror or exc),
              file=sys.stderr)
        return 2
    from . import db
    counts = _opinion_counts(db.DB_PATH) if doc["stopped_or_held_calls"] is not None else None
    if counts is None:
        calls = "the stopped calls could not be read"
    else:
        # A call flagged while watching RAN: counting it as "stopped" overclaimed (walk: 13
        # "stopped or held", of which 10 ran). Each kind is counted under its own words, over
        # the whole record, not the listed few hundred.
        stopped, held, refused, halted, watched = counts
        # Held and not-run calls only when there are some, so the familiar line is unchanged
        # for every ledger without them.
        calls = "%d stopped" % stopped
        if held:
            calls += ", %d held for a person (not approved)" % held
        if refused:
            calls += ", %d not run (no verdict)" % refused
        if halted:
            calls += ", %d halted (a runaway loop)" % halted
        calls += ", %d flagged while watching (%s)" % (watched, "it ran" if watched == 1 else "they ran")
    print("Wrote %s: %d rules in force, %d switched off, %s."
          % (out_path, len(doc["rules_in_force"]), len(doc["rules_off"]), calls))
    # The one value the reader is told to keep and check later, so it is printed, not left at
    # the bottom of the file (walk: "Where is record_head?").
    if doc.get("record_head"):
        print("Record's latest entry: %s" % doc["record_head"])
        print("To check later that the record was not rewritten: agentx audit --record --head "
              "<that value>")
    print(doc["before_you_share"])
    return 0
