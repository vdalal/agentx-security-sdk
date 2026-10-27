"""The Claude Code door: a `PreToolUse` command hook that screens a coding agent's tool calls.

Claude Code starts this process once per screened tool call, writes the call to stdin as JSON,
and reads the answer from stdout. It is the same keyless check the decorator and `agentx-mcp`
use (`decorators.evaluate_call_keyless`), with the same project rules: the developer's
policies file, adopted rules, outbound allowlist and their own coaching.

    agentx hook                  answer one PreToolUse event (what Claude Code runs)
    agentx hook post-tool-use    after a watched call the rules would stop, tell the agent
    agentx hook session-end      close the session: send the usage pulse, drop the counters
    agentx hook install          add both hooks to this project's .claude/settings.local.json
    agentx hook install --enforce  the same, blocking in every session (--watch switches back)
    agentx hook uninstall        remove them again (the record is kept)

WHAT IT SCREENS: shell commands (the Bash and PowerShell tools) and MCP tool calls
(`mcp__<server>__<tool>`), and the hook is registered for those tools only. Other tools (Read,
Edit, Write, ...) never start it, so the record never claims a call it did not read.

POSTURE: the shared resolver, as a door with no gateway behind it, so watching is the default.
  * watching (the default, or AGENTX_POSTURE set to audit): no permission decision is given, so Claude
    Code's own flow decides; a call the rules would stop is recorded as WOULD_BLOCK, runs, and
    the developer is shown one line saying so (`systemMessage`). The agent is told only after
    the call has run (`post-tool-use`), so the note cannot change what it did.
  * enforcing (`agentx hook install --enforce`, saved in the hook command so it holds in every
    session; or AGENTX_POSTURE=enforce where `claude` starts, for that session): the call is
    denied with the rule's coaching as the reason, and recorded as CHALLENGED. A deny from a
    hook applies in every permission mode. A variable that is set wins over the saved setting.
  A value AgentX does not know resolves to enforce, as on every door, and on this door the
  warning is shown in the Claude Code window, where the developer can see it.

THE VERDICT COMES FIRST: it is decided and returned before any record-keeping, so a fault in
the bookkeeping can never turn a deny into an allow. A fault before the verdict fails OPEN
(exit 0, nothing printed) and is counted for the usage pulse as `shield_failopens`.

STATE: each call is judged on its own. Each screened call leaves one small file under
`.agentx/hook-sessions/<session>/`, written by that call alone, so calls Claude Code runs in
parallel never overwrite each other; `session-end` sums them into one pulse and removes them.
"""
import json
import os
import re
import sys
import time
import uuid

AGENT_ID = "claude_code_hook"
# The agent id each harness's calls are checked and recorded under, so the record (and an
# allowlist entry, which names the same id) can always say which harness made a call.
CODEX_AGENT_ID = "codex_hook"
_HARNESS_AGENT_IDS = {"claude": AGENT_ID, "codex": CODEX_AGENT_ID}
# The agent id calls made in AgentX's own repository are recorded under, and that repository's
# sessions send no usage pulse: our own use must never count as a user's.
OWN_REPO_AGENT_ID = "agentx_own_repo"
# Every agent id this door writes. A reader that means "the hook's rows" uses this, never one id.
HOOK_AGENT_IDS = (AGENT_ID, CODEX_AGENT_ID, OWN_REPO_AGENT_ID)
HOOK_AGENT_LABELS = {AGENT_ID: "Claude Code (through the AgentX hook)",
                     CODEX_AGENT_ID: "Codex (through the AgentX hook)",
                     OWN_REPO_AGENT_ID: "AgentX's own repository (through the AgentX hook)"}
SCREENED_SHELL_TOOLS = ("Bash", "PowerShell")
# The tools Claude Code starts this hook for. Anything else never pays for a process start.
HOOK_MATCHER = "Bash|PowerShell|mcp__.*"
# Claude Code gives every SessionEnd hook together 1.5 seconds unless a hook names its own
# timeout, and cancels what is still running. Starting Python and sending the pulse can take
# longer on a busy machine, so ours names one.
SESSION_END_TIMEOUT_SECONDS = 10
_HOOK_MODULE = "-m agentx_sdk.hook"


# ---- reading the event ---------------------------------------------------------------------
# Shared with the after-the-call note, which Claude Code runs as a plain file without this
# package (see `_hook_note`), so the two read events and find records the same way.
from . import _hook_note
from ._hook_note import (read_event as _read_event, project_dir as _project_dir,
                         session_dir as _session_dir, call_record_name as _call_record_name,
                         post_tool_use)


def _call_parts(tool_name, tool_input):
    """(query, arguments, name, name_leads) for a call this door screens, or None.

    A shell tool's command is its statement. An MCP call is read the way `agentx-mcp` reads it:
    the tool's own name in front, then its argument values, with the names kept so a prose
    argument is never read as a command."""
    if not isinstance(tool_input, dict):
        return None
    if tool_name in SCREENED_SHELL_TOOLS:
        command = tool_input.get("command")
        if not isinstance(command, str) or not command.strip():
            return None
        return command, {"command": command}, tool_name, False
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        name = parts[2] if len(parts) == 3 and parts[2] else tool_name
        from .mcp_proxy import _flatten_call
        return _flatten_call(name, tool_input), tool_input, name, True
    return None


# ---- posture -------------------------------------------------------------------------------

def _posture(installed=None):
    """The posture for this call. A variable set where `claude` started wins, as on every door;
    with none set, the posture `agentx hook install --enforce` wrote into the hook command
    (`installed`) applies, so blocking holds in every session without exporting anything."""
    from .decorators import _resolve_enforcement
    env_set = bool((os.environ.get("AGENTX_POSTURE") or "").strip())
    if not env_set and installed in ("audit", "enforce"):
        return installed
    return _resolve_enforcement(None, keyless_door=True)


def posture_command_lines(posture, indent="      "):
    """How to put Claude Code at a posture. The install line saves it in the hook command, so
    it holds in every session; a variable exported where `claude` starts only lasts that window,
    which is why blocking used to be lost on the next start."""
    flag = "--enforce" if posture == "enforce" else "--watch"
    return ["%s%s   # Claude Code, every session from now on"
            % (indent, install_command_here(flag))]


def _posture_warning():
    """The resolver's warning for a posture it does not know, in words for this window, or None.

    The resolver prints it to stderr, which Claude Code discards for a hook, so a developer who
    typed AGENTX_POSTURE=watch got enforce with nothing on screen. Same rule as the resolver:
    a value outside audit/enforce resolves to enforce."""
    value = (os.environ.get("AGENTX_POSTURE") or "").strip().lower()
    if value and value not in ("audit", "enforce"):
        return ("AgentX: posture '%s' is not a value AgentX knows, so it is blocking (enforce). "
                "To watch without blocking, set AGENTX_POSTURE=audit; to block, "
                "AGENTX_POSTURE=enforce." % value)
    return None


# ---- per-session counters, one file per call -------------------------------------------------

def _write_call_record(project, event, record):
    """One file for one call, written by that call alone (no read-modify-write to race). It
    carries the time it was written: the file names are hashes, so only `at` gives the order."""
    try:
        record = dict(record, at=time.time())
        folder = _session_dir(project, (event or {}).get("session_id"))
        os.makedirs(folder, exist_ok=True)
        name = _call_record_name((event or {}).get("tool_use_id") or uuid.uuid4().hex)
        tmp = os.path.join(folder, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        os.replace(tmp, os.path.join(folder, name))
    except Exception:
        pass


def _first_in_session(project, event, key):
    """True the first time `key` is claimed in this session, False after. Atomic across the
    parallel processes of one session: the claim is an exclusive file create."""
    try:
        folder = _session_dir(project, (event or {}).get("session_id"))
        os.makedirs(folder, exist_ok=True)
        fd = os.open(os.path.join(folder, "noted-" + key), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
        return True
    except FileExistsError:
        return False
    except Exception:
        return False


def _claim_once(project, event, lines):
    """The texts of `lines` ((key, text or None) pairs) this call is the first in the session
    to show."""
    return [text for key, text in lines if text and _first_in_session(project, event, key)]


def _read_session(folder, paths=None):
    """The call records in `folder`. The path of every call file looked at, read or not, is
    added to `paths` (files are written whole by rename, so an unreadable one stays unreadable)."""
    records = []
    try:
        names = os.listdir(folder)
    except OSError:
        return records
    for name in sorted(names):
        if not name.endswith(".json"):
            continue
        if paths is not None:
            paths.append(os.path.join(folder, name))
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                records.append(data)
        except Exception:
            continue
    return records


# ---- the decision --------------------------------------------------------------------------

def _deny(reason_text, alternative, policy_name, tool):
    reason = str(reason_text or "This call is stopped by an AgentX rule.")
    if alternative:
        reason = "%s Instead: %s" % (reason, alternative)
    if policy_name:
        reason = "AgentX stopped '%s' (%s). %s" % (tool, policy_name, reason)
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _watching_notice(decision, tool):
    """A line shown to the developer when watching lets a call through that the rules would
    stop (the agent is told after the call, by `post_tool_use`). It carries no permission
    decision, so Claude Code's own flow decides the call exactly as it would without the hook."""
    name = decision.get("policy_name") or "an AgentX rule"
    # Names the variable only when one is set: "(AGENTX_POSTURE=audit)" with nothing set read
    # as a setting the developer had made (walk).
    why = "the default"
    if (os.environ.get("AGENTX_POSTURE") or "").strip():
        why = "AGENTX_POSTURE=%s" % os.environ["AGENTX_POSTURE"].strip()
    enforce = install_command_here("--enforce")
    if why == "the default":
        how = ("To block calls like this in every session, run %s in this project." % enforce)
    else:
        # A variable set where `claude` started is what made this watch, and it wins over an
        # enforcing install, so the install command would change nothing (review).
        how = ("To block calls like this, start Claude Code without %s (%s keeps blocking on "
               "in every session)." % (why, enforce))
    return ("AgentX would have stopped this %s call (%s). Watching (%s), so AgentX lets it through; it is "
            "recorded for agentx audit. %s" % (tool, name, why, how))


# Claude Code permission modes in which a hook's "ask" does not reach the developer. Auto mode
# was walked on 2.1.302: the hook answered "ask" and the call ran with no prompt (its docs say
# the prompt is forced). bypassPermissions skips every prompt.
_MODES_THAT_DO_NOT_ASK = ("auto", "bypassPermissions")


_PLAIN_LINE = re.compile(r"^[A-Za-z0-9 ._\-/=:+]+$")


def _hand_back(command, tool, mode, needs_yes=False):
    """How the developer runs a call a team rule stopped. Claude Code's `!` runs one line in its
    own shell (bash), so it is offered for a one-line command: alone for Bash, beside a
    PowerShell window for PowerShell. `needs_yes`: the call
    is `agentx rule add|remove`, whose y/N question a `!` command cannot answer (walk: "Proceed?
    [y/N]: Nothing changed."), so `--yes` is added, or asked for where adding it is not safe."""
    if not command:
        return "To let it run, leave %s mode and ask again." % mode
    if "\n" in command:
        return "To run it yourself, run it in a terminal (it is more than one line):\n%s" % command
    if tool == "PowerShell":
        # `!` runs bash, so PowerShell syntax may not work there; a plain line often does
        # (`py run_suites.py`), and opening a window is the slowest way back, so it is offered
        # beside the window. A PLAIN line only: letters, digits, spaces and . _ - / = : + and
        # nothing else. A list of the characters the two shells read differently was always one
        # short (`$name`, a backtick, `.\x`, quotes, separators, then globs, commas, `~`), and a
        # line bash reads differently runs a different command from the one the person reads.
        # Not for `agentx rule` either: a `!` command cannot answer its y/N question.
        if needs_yes or not _PLAIN_LINE.match(command):
            return "To run it yourself, run it in a PowerShell window: %s" % command
        return ("To run it yourself, type it with ! as the very first character: !%s (Claude "
                "Code runs it in bash), or run it in a PowerShell window." % command)
    if needs_yes:
        # `--yes` goes on the end only of a line that IS one agentx command: on any other line
        # the last word may be git's (a commit message naming the words), a comment, or bash -c's.
        import re
        words = command.split()
        first = words[0].strip("\"'") if words else ""
        plain = (re.split(r"[\\/]", first)[-1].lower() in _CLI_NAMES
                 and len(words) > 1 and words[1].lower() == "rule"
                 and not any(c in command for c in ";&|<>`$(#")
                 and command.count("'") % 2 == 0 and command.count('"') % 2 == 0
                 and not command.rstrip().endswith("\\"))
        if plain:
            return ("To run it yourself, type it with ! as the very first character (with --yes: a ! "
                    "command cannot answer agentx's y/N question): !%s --yes" % command)
        return ("To run it yourself, type it with ! as the very first character; if it runs agentx "
                "rule add or remove, add --yes to that command (a ! command cannot answer agentx's "
                "y/N question): !%s" % command)
    return "To run it yourself, type it with ! as the very first character: !%s" % command


# A shell command that changes the team rules is put to the developer like a team rule's match,
# so the agent cannot add or remove one on its own (`--yes` skips only the terminal's prompt).
_RULE_CHANGE_RE = None
RULE_CHANGE_ID = "team-rule-changes"


_CLI_NAMES = {"agentx", "agentx.exe", "agentx.cmd", "agentx_sdk.cli"}
TEAM_RULES_SHOWN = ".agentx/team-rules.json"
_REDIRECT_WORD_ENDS = " \t\r\n;&|()<>\"'$`"


def _redirect_targets(lowered):
    """(what each `>` or `>>` writes to, whether one target could not be read). `2>&1` writes
    to none, and a `>` inside quotes is no redirect (`jq '. > 0'`, `grep '=>'`). A target
    holding a quote, `$` or a backtick (`> "$PWD"/.agentx/team-rules.json`, a quoted path with
    a space) is not read as a shell would; it is reported as unread, and an unread target
    counts as a write. One pass over the command, not a pattern: a regex over a run of `>`
    backtracked at every start, quadratic, past the hook's timeout, which fails open."""
    # Quotes bash does not read as quotes (a `#` comment's apostrophe, a heredoc body, `\'` in
    # `$'...'`) leave this count wrong; each leaves a quote open across a line break or at the
    # end, and either sends the command to the stricter reading below.
    out, unread = set(), False
    quote, i, n = None, 0, len(lowered)
    while i < n:
        c = lowered[i]
        if quote:
            if c == quote:
                quote = None
            elif c == "\n":
                # A quote across a line break is most likely a `#` comment's apostrophe
                # (`# don't ...`), which bash does not read as a quote (review).
                return _redirect_targets_every_gt(lowered)
            elif c == "\\" and quote == '"':
                i += 1
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c in "'\"":
            quote = c
            i += 1
            continue
        if c != ">":
            i += 1
            continue
        j = i + 1
        while j < n and lowered[j] in ">|":                 # `>>`, and `>|` (noclobber)
            j += 1
        while j < n and lowered[j] in " \t":
            j += 1
        k = j
        while k < n and lowered[k] not in _REDIRECT_WORD_ENDS:
            k += 1
        if k < n and lowered[k] in "\"'$`":
            unread = True
        elif k > j:
            out.add(lowered[j:k])
        i = j        # the target's own quotes, if any, are read by the loop from here
    if quote:
        return _redirect_targets_every_gt(lowered)          # a quote never closed
    return out, unread


def _redirect_targets_every_gt(lowered):
    """The stricter reading, for a command whose quotes the scan above cannot trust: every `>`
    is a redirect, a quote inside one included. It can only ask more, never less."""
    out, unread = set(), False
    for part in lowered.split(">")[1:]:
        word = part.lstrip().lstrip("|").lstrip()
        end = 0
        while end < len(word) and word[end] not in _REDIRECT_WORD_ENDS:
            end += 1
        if word[end:end + 1] in ("\"", "'", "$", "`"):
            unread = True
        elif end:
            out.add(word[:end])
    return out, unread


def _rule_change_rule(command):
    """The built-in team rule a command that changes the team rules matches, or None.

    THE RULE IS THE WORDS, NOT A SPELLING: the command holds the CLI (a word whose own name is
    `agentx`, `agentx.exe` or `agentx_sdk.cli`, so not a folder in a path), `rule`, and `add`
    or `remove`, in any order; or it names `team-rules.json` with some shell writes,
    such as rm, > and git checkout. Every spelling has those words (a wrapper, a subshell, a
    quoted path, flags anywhere), and the check is linear on any input. Two spelling patterns
    were tried first: one missed the wrappers, the next took minutes on a crafted command, past
    the hook's timeout, which fails open. What it costs: a command that only mentions the words
    (a commit message about it) is asked about too. What it cannot see: the agent's own file
    tools; other ways to write the file (`sed -i.bak`, `perl -pi`, a `py -c` or `node -e`
    one-liner, a .NET file call); a command aimed at the folder, not the file (`rm -rf .agentx`,
    `git checkout -- .`); a word deliberately broken with quotes; or the CLI under another name.
    Those are not chased verb by verb: the file is committed and reviewed like code."""
    import re
    global _RULE_CHANGE_RE
    if _RULE_CHANGE_RE is None:
        _RULE_CHANGE_RE = re.compile(r"[\s;&|()`'\"=<>,]+")
    if not command:
        return None
    lowered = command.lower()
    tokens = [t for t in _RULE_CHANGE_RE.split(lowered) if t]
    # A token's own name, so a folder in a path (".agentx/", "agentx-rules") is not the CLI.
    names = {re.split(r"[\\/]", t)[-1] for t in tokens}
    cli = bool(names & _CLI_NAMES)
    changes = cli and "rule" in names and bool(names & {"add", "remove"})
    # Some shell writes to the rules file, such as rm, > and git checkout. A `>` counts when the
    # file is what it writes to, or when where it writes cannot be read (a quote or `$` in it);
    # `cat .agentx/team-rules.json 2>&1` reads the file.
    targets, unread = _redirect_targets(lowered)
    redirected = {re.split(r"[\\/]", t)[-1] for t in targets}
    writes_file = "team-rules.json" in names and (
        "team-rules.json" in redirected or unread
        or bool(names & {"rm", "del", "erase", "remove-item", "mv", "move",
                                        "move-item", "cp", "copy", "copy-item", "tee",
                                        "checkout", "restore", "set-content", "out-file",
                                        "clear-content", "truncate"})
        or ("sed" in names and "-i" in names))
    if not (changes or writes_file):
        return None
    # `builtin` and `found`: the person asked did not write this rule, and the command may not
    # hold its `match` words (`rm .agentx/team-rules.json`), so the reason says what was found.
    return {"id": RULE_CHANGE_ID, "tools": ["shell"], "match": ["agentx rule"],
            "why": "changing a team rule needs your own go-ahead, not the agent's",
            "where_ask_unsupported": "stop", "action": "ask", "builtin": True,
            # What the check SAW, not what the call does: a commit message naming the command
            # is asked about too (review: "runs" and "changes" were false of those).
            "found": "names agentx rule add or remove" if changes else
                     "names %s with a command that can write it, such as rm, > or git checkout"
                     % TEAM_RULES_SHOWN,
            # Said to the developer and the agent: how a person makes the change, since a ! line
            # cannot answer the CLI's y/N (walk). An instruction, not a promise that a yes here
            # is harmless: an agent can give agentx a terminal (review). Absent once --yes is there.
            "note": "To make this change yourself, run it with --yes: a ! command cannot answer "
                    "agentx's y/N question." if (changes and "--yes" not in names) else None}


def _team_answer(rule, harness, answer, event=None, command=None, tool=None):
    """(answer, outcome) for a call a team rule matches. `answer` is what is already there (a
    watching line, or None); `outcome` is "ask", "warn" or "stop".

    Claude Code is asked to put the call to the developer, except in a mode that does not ask
    (`_MODES_THAT_DO_NOT_ASK`): there the call is stopped, the developer is shown why, and a
    shell command is given back as `!<command>`, which the developer can type and the agent
    cannot (Claude Code passes `!` commands to no hook). Codex cannot ask either: it runs a call
    whose hook answers "ask" and reports the hook as failed (learn.chatgpt.com/docs/hooks), so
    there the rule's `where_ask_unsupported` decides: "warn" shows the rule and the call runs,
    "stop" refuses it with the rule's reason."""
    from .team_rules import reason_text
    reason = reason_text(rule)
    if harness == "codex":
        if rule.get("where_ask_unsupported") == "stop":
            return dict(answer or {}, hookSpecificOutput={
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": reason + " Codex cannot ask, so this rule stops the "
                "call here; the developer can run it themselves."}), "stop"
        return _with_message(answer, [reason + " Codex cannot ask for approval, so the call "
                                      "runs, and it is recorded."]), "warn"
    mode = (event or {}).get("permission_mode")
    if mode in _MODES_THAT_DO_NOT_ASK:
        how = _hand_back(command, tool, mode, needs_yes=bool(rule.get("note")))
        stopped = dict(answer or {}, hookSpecificOutput={
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "%s Claude Code is in %s mode, which does not stop to "
            "ask, so AgentX stopped this call. Ask the developer. %s" % (reason, mode, how)})
        why = str(rule.get("why") or "").rstrip(".")
        what = ("AgentX stopped a call it asks you about" if rule.get("builtin") else
                "AgentX stopped a call your team rule asks you about")
        return _with_message(stopped, ["%s (%s): %s mode does not stop to ask. %s"
                                       % (what, why, mode, how)]), "stop"
    return dict(answer or {}, hookSpecificOutput={
        "hookEventName": "PreToolUse", "permissionDecision": "ask",
        "permissionDecisionReason": reason}), "ask"


def _with_message(answer, messages):
    messages = [m for m in messages if m]
    if not messages:
        return answer
    answer = dict(answer or {})
    if answer.get("systemMessage"):
        messages.append(answer["systemMessage"])
    answer["systemMessage"] = "\n".join(messages)
    return answer


def decide(event, posture=None, harness="claude"):
    """Screen one PreToolUse event. Returns the JSON to print, or None for no objection.

    `harness` is the agent that ran the hook ("claude" or "codex"), written into the command
    by `agentx hook install`; it decides only how a team rule's "ask" is carried out.

    The verdict is fixed before any bookkeeping; a fault in the bookkeeping is counted and the
    verdict still stands. Raises only before the verdict, which the caller turns into a
    fail-open."""
    tool_name = event.get("tool_name")
    parts = _call_parts(tool_name, event.get("tool_input"))
    if parts is None:
        return None
    query, arguments, name, name_leads = parts
    tool_key = str(tool_name)
    project = _project_dir(event)
    posture = posture or _posture()
    agent_id = _agent_id(project, harness)

    from . import decorators
    # Re-read the rules for THIS project: the accessor reloads when the policies file it points
    # at changes, and the process now works in the project folder.
    load_err = decorators.current_policy_load_error()
    strict = decorators._policy_load_posture() == "strict"
    # One-time lines, claimed only once the verdict is fixed: a call that fails open before
    # it must not use up a line nobody saw.
    once = [("posture", _posture_warning())]

    if load_err is not None and strict and posture != "audit":
        # The other doors refuse every call while the rules cannot be read; so does this one.
        # Counted as agentx-mcp counts it: a screened call, not a block (no rule caught it).
        # Like agentx-mcp, no ledger row: any stopped row reads as a rule's block in insights
        # and review, and this one would lower the recovery rate for a broken file.
        reason = decorators._policy_load_error_message(load_err, mcp=True)
        answer = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                         "permissionDecision": "deny",
                                         "permissionDecisionReason": reason}}
        _write_call_record(project, event, {"posture": posture, "tool": tool_key,
                                            "screened": 1, "config_fault": 1})
        return _with_message(answer, _claim_once(project, event, once))
    if load_err is not None:
        once.append(("policy-load", "AgentX: your policy file could not be read, so only the "
                     "built-in rules are applied and your own are NOT: %s" % load_err))

    # The call runs on the developer's own machine: its own server is not an SSRF target
    # (`decorators._LOOPBACK_RAILS`).
    own_machine = {"project": project}
    decision = decorators.evaluate_call_keyless(query, arguments=arguments, tool_name=name,
                                                name_leads=name_leads, agent_id=agent_id,
                                                own_machine=own_machine, own_tool_door=True)
    answer = None
    challenge = None
    if decision is not None:
        if posture == "audit":
            answer = {"systemMessage": _watching_notice(decision, tool_key)}
        else:
            ch, safe = decision.get("challenge_text"), decision.get("preferred_alternative")
            try:
                ch, safe = decorators._apply_org_override(
                    decision.get("policy_id"), ch, safe,
                    policy_name=decision.get("policy_name"),
                    signature=decorators._call_signature(agent_id, tool_key, arguments.keys()))
            except Exception:
                pass          # keep the shipped wording; never lose the deny over it
            answer = _deny(ch, safe, decision.get("policy_name"), tool_key)
            # The coaching as every door records it, without this door's "AgentX stopped
            # 'Bash' (...)" lead: with it, one coaching was listed once per tool (walk).
            challenge = decorators._delivered_coaching(ch, safe)

    # A team rule asks the developer. A stop from the built-in rules is the stronger answer, so
    # a team rule is looked up only when there is none; a watching line is kept beside it.
    team = outcome = None
    if not (answer or {}).get("hookSpecificOutput"):
        from . import team_rules
        rules_path = team_rules.team_rules_path(project=project)
        shell = tool_key in SCREENED_SHELL_TOOLS
        team = (_rule_change_rule(query) if shell else None) or \
            team_rules.match_team_rule(tool_key, query, path=rules_path)
        if team is None and team_rules.team_rules_state(rules_path) == "damaged":
            # A file that cannot be read (a merge conflict, a hand edit) must not switch every
            # team rule off in silence.
            once.append(("team-rules-damaged", "AgentX: %s could not be read, so no team rule "
                         "is checked until it is fixed (agentx rule list says why)."
                         % rules_path))
        if team is not None:
            command = query if shell else None
            stop_answer, stop_outcome = _team_answer(team, harness, None, event,
                                                     command=command, tool=tool_key)
            if stop_outcome == "stop":
                # A stop is the answer, so a watching line beside it ("lets it through") would
                # be false, and the call is recorded as the team rule's stop, not as watched.
                answer, outcome, decision = stop_answer, stop_outcome, None
            else:
                answer, outcome = _team_answer(team, harness, answer, event, command=command,
                                               tool=tool_key)
            team_rules.log_team_rule_use(team["id"], outcome, harness, path=rules_path)

    from . import pulse
    notice = pulse.take_notice_if_due("hook")
    answer = _with_message(answer, _claim_once(project, event, once) + [notice])

    # The counts follow from the verdict alone, so they are fixed here, before the ledger.
    record = {"posture": posture, "tool": tool_key, "screened": 1}
    if outcome == "stop":
        # Stopped by a team rule. Not a clean call, and not a block the pulse counts: those
        # counts mean a built-in rule caught harm.
        record["team_stop"] = 1
    elif decision is None:
        record["clean"] = 1
    else:
        record["category"] = decision.get("category")
        record["would_block" if posture == "audit" else "intercept"] = 1
        # Read back by `post-tool-use`, to tell the agent which rule its call matched. Local
        # only: the pulse sums named counts and never carries a record's other fields.
        record["rule"] = decision.get("policy_name")
    if team is not None:
        record["team_rule"] = team["id"]
        record["team_outcome"] = outcome
    if outcome == "ask" and decision is None:
        # The developer has not answered yet, and a call they decline never runs, so no row is
        # written now. Claude Code runs the after-the-call note only for a call that ran (or
        # failed, which still ran); the note starts `record-ran`, which writes the row then.
        # (A call a built-in rule is also WATCHING keeps its row here, as every watched call
        # does: that row says what the rules saw, before any answer.)
        record["team_asked"] = 1
        _write_call_record(project, event, record)
        return answer
    _keep(event, project, posture, tool_key, arguments, decision, challenge, record, team=team,
          agent_id=agent_id, team_stopped=outcome == "stop")
    return answer


def record_ran(stdin=None):
    """`agentx hook record-ran`: write the row for a call a team rule asked about, now that it
    has run. Started by the after-the-call note, never by Claude Code. Never raises."""
    stdin = stdin or sys.stdin
    try:
        event = _read_event(stdin)
        if not event:
            return 0
        parts = _call_parts(event.get("tool_name"), event.get("tool_input"))
        if parts is None:
            return 0
        _query, arguments, _name, _leads = parts
        project = _project_dir(event)
        # What the check decided is in the call record it wrote. Only a posture this door knows
        # and a rule id are taken from it; the record sits where the agent can write.
        path = os.path.join(_session_dir(project, event.get("session_id")),
                            _call_record_name(event.get("tool_use_id") or ""))
        with open(path, encoding="utf-8") as fh:
            record = json.load(fh)
        if not (isinstance(record, dict) and record.get("team_asked")):
            return 0
        posture = record.get("posture") if record.get("posture") in ("audit", "enforce") \
            else _posture()
        tool_key = str(event.get("tool_name"))
        # The passing row is the call's, like every other passing row; which team rule asked
        # about it goes in the rule's own log, so no reader takes it for an adopted rule.
        _record(event, project, posture, tool_key, arguments, None, None, {},
                agent_id=_agent_id(project, "claude"))
        from . import team_rules
        rule_id = record.get("team_rule")
        rules_path = team_rules.team_rules_path(project=project)
        if isinstance(rule_id, str) and any(r["id"] == rule_id
                                            for r in team_rules.read_team_rules(rules_path)):
            team_rules.log_team_rule_use(rule_id, "ran", "claude", path=rules_path)
    except Exception:
        pass
    return 0


def _agent_id(project, harness):
    """The agent id this call is checked and recorded under: the harness's own, or ours in
    AgentX's own repository, so a screen or a count can always tell our calls from a user's."""
    if _is_agentx_source_tree(project):
        return OWN_REPO_AGENT_ID
    return _HARNESS_AGENT_IDS.get(harness, AGENT_ID)


def _keep(event, project, posture, tool_key, arguments, decision, challenge, record, team=None,
          agent_id=AGENT_ID, team_stopped=False):
    """Write the ledger row, then this call's counter file. A ledger fault loses only the row:
    the verdict stands and is counted as given, never as a fail-open (the call was screened)."""
    try:
        _record(event, project, posture, tool_key, arguments, decision, challenge, record,
                team=team, agent_id=agent_id, team_stopped=team_stopped)
    except Exception:
        pass
    _write_call_record(project, event, record)


def _team_rule_row(rule):
    """A team rule as the ledger names a matched rule: its id and a name a screen can show."""
    why = str(rule.get("why") or "")
    # AgentX's own rule-change check is not a team rule anybody added (`reason_text` says so too).
    label = "AgentX: " if rule.get("builtin") else "Team rule: "
    return {"id": rule["id"], "name": label + (why if len(why) <= 80 else why[:77] + "...")}


def _record(event, project, posture, tool_key, arguments, decision, challenge, record, team=None,
            agent_id=AGENT_ID, team_stopped=False):
    """The ledger row. Adds `rule_match` to `record` when an adopted rule matched. A call a team
    rule matched carries the rule on its row: a passing row when the call ran (after an ask, the
    row is written by `record_ran` once it has), a stopped row when the rule stopped it."""
    from . import db, decorators
    if not os.environ.get("AGENTX_LEDGER_PATH"):
        db.DB_PATH = os.path.join(project, ".agentx.db")
    db.init_db()
    trace = "hook-%s-%s" % (str(event.get("session_id") or "session")[:36],
                            str(event.get("tool_use_id") or uuid.uuid4().hex[:12]))
    row_cap = decorators.row_cap_for_arguments(arguments)
    reversibility = decorators.reversibility_for_arguments(arguments)
    if decision is None and team is not None and team_stopped:
        names, amount, target_class, quantity = db._call_shape(tool_key, arguments)
        row = _team_rule_row(team)
        from .team_rules import reason_text
        db.log_intercept(trace, agent_id, tool_key, row["id"], row["name"], "CHALLENGED",
                         posture=posture, challenge_issued=reason_text(team), arg_names=names,
                         amount=amount, target_class=target_class, quantity=quantity,
                         dest_hosts=db._dest_hosts_value(tool_key, arguments), row_cap=row_cap,
                         reversibility=reversibility)
    elif decision is None:
        matched = uncompared = None
        try:
            from .rules import evaluate_adopted_rule
            rule, status = evaluate_adopted_rule(tool_key, arguments)
            if rule and status == "uncompared":
                uncompared = rule
            elif rule:
                matched = rule
                record["rule_match"] = 1
        except Exception:
            pass
        db.record_call(trace, agent_id, tool_key, arguments, in_audit=posture == "audit",
                       matched_rule=matched, uncompared_rule=uncompared, row_cap=row_cap,
                       reversibility=reversibility)
    else:
        # The call's shape (argument names, a magnitude bucket, a target class, the host),
        # never its values: the same reduction the passing row gets.
        names, amount, target_class, quantity = db._call_shape(tool_key, arguments)
        shape = dict(arg_names=names, amount=amount, target_class=target_class,
                     quantity=quantity, dest_hosts=db._dest_hosts_value(tool_key, arguments),
                     row_cap=row_cap, reversibility=reversibility)
        if posture == "audit":
            db.log_intercept(trace, agent_id, tool_key, decision.get("policy_id"),
                             decision.get("policy_name"), db.WOULD_BLOCK_STATUS,
                             posture="audit", **shape)
        else:
            db.log_intercept(trace, agent_id, tool_key, decision.get("policy_id"),
                             decision.get("policy_name"), "CHALLENGED", posture="enforce",
                             challenge_issued=challenge, **shape)


def pre_tool_use(stdin=None, stdout=None, installed=None, harness="claude"):
    """Read one event, print a decision or nothing. Always exits 0 (fail open). `installed` is
    the posture `agentx hook install --enforce` wrote into the command, if any; `harness` is the
    agent the command was installed for."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    event = None
    decided = False
    try:
        event = _read_event(stdin)
        if event is not None:
            # Work in the project Claude Code named, so its rules and records are the ones used.
            os.chdir(_project_dir(event))
            answer = decide(event, posture=_posture(installed), harness=harness)
            decided = True           # counted by decide(); a failed write below is not a 2nd count
            if answer is not None:
                stdout.write(json.dumps(answer))
                stdout.flush()
            # Once per session, after the answer is out: old sessions that never closed are
            # cleared here too, since a developer who always kills the window never reaches
            # session-end. Only after a screened call, which has already made the session's
            # folder: a call this door does not read leaves nothing in the project.
            project = _project_dir(event)
            folder = _session_dir(project, event.get("session_id"))
            if os.path.isdir(folder) and _first_in_session(project, event, "prune"):
                _prune_stale_sessions(project, keep=folder)
            return 0
    except Exception:
        if decided:
            return 0
    # Before the verdict, or no readable event: nothing is printed, the call goes ahead.
    _count_failopen(event if isinstance(event, dict) else None)
    return 0


def _count_failopen(event):
    """Count a call that went ahead unscreened. With a readable event, into its session. With
    none, only into a project Claude Code named (never the folder the process started in),
    under no session; session-end sums that folder too."""
    try:
        named = os.environ.get("CLAUDE_PROJECT_DIR")
        if event is None and not (named and os.path.isdir(named)):
            return
        _write_call_record(_project_dir(event), event, {"shield_failopens": 1})
    except Exception:
        pass


def session_end(stdin=None):
    """Send this session's usage pulse from its call files, then remove them. Never raises."""
    stdin = stdin or sys.stdin
    try:
        event = _read_event(stdin)
        if event is None:
            return 0
        project = _project_dir(event)
        folder = _session_dir(project, event.get("session_id"))
    except Exception:
        return 0
    try:
        if _is_agentx_source_tree(project):
            # Our own repository: the call files are dropped, never summed into a pulse.
            paths = []
            _read_session(folder, paths)
            _remove(folder, paths)
        else:
            _send_session_pulse(project, folder)
    except Exception:
        pass
    _prune_stale_sessions(project, keep=folder)
    return 0


def _send_session_pulse(project, folder):
    """Sum the session's call files into one usage pulse, then remove them."""
    _adopt_unattributed(project, folder)
    paths = []
    records = _read_session(folder, paths)
    # Oldest first, so the session's posture and block category are its latest call's.
    records.sort(key=lambda r: r.get("at") if isinstance(r.get("at"), (int, float)) else 0)
    if not records:
        _remove(folder, paths)
        return
    screened = [r for r in records if r.get("screened")]
    audit = [r for r in screened if r.get("posture") == "audit"]
    categories = [r.get("category") for r in records if r.get("category")]
    postures = [r.get("posture") for r in records if r.get("posture")]
    stats = {
        "integration": "hook",
        "posture": postures[-1] if postures else None,
        "total_calls": len(screened),
        "intercepts": sum(1 for r in records if r.get("intercept")),
        "critical_blocks": sum(1 for r in records if r.get("intercept")),
        "would_blocks": sum(1 for r in records if r.get("would_block")),
        "shield_failopens": sum(int(r.get("shield_failopens") or 0) for r in records),
        # The audit rung counts what was WATCHED: clean calls in audit posture, and the
        # distinct tools seen while watching. An enforcing session is not an audit run.
        "audit_calls": sum(1 for r in audit if r.get("clean")),
        "audit_tools": len({r.get("tool") for r in audit}),
        "rule_matches": sum(1 for r in records if r.get("rule_match")),
        "block_category": categories[-1] if categories else None,
        # A coding agent's call is always the developer's own agent, never our demo.
        "own_agent_block": any(r.get("intercept") for r in records),
    }
    from . import team_rules
    stats["team_rules"], stats["team_rule_matches_7d"] = team_rules.pulse_counts(project)
    from . import pulse
    pulse.on_session_end(stats)
    _remove(folder, paths)


def _adopt_unattributed(project, folder):
    """Move the fail-opens counted with no readable event (no session to name) into this
    session's folder. Every session in the project shares that folder; a rename succeeds for
    one process only, so each such count is summed by exactly one session."""
    shared = _session_dir(project, None)
    if shared == folder:
        return
    try:
        names = [n for n in os.listdir(shared) if n.endswith(".json")]
    except OSError:
        return
    for name in names:
        try:
            os.makedirs(folder, exist_ok=True)
            os.rename(os.path.join(shared, name), os.path.join(folder, name))
        except OSError:
            continue        # another session took it first
    _drop_leftovers(shared)
    try:
        os.rmdir(shared)    # only when empty
    except OSError:
        pass


def _remove(folder, paths):
    """Remove the call files this session read, and its one-time claims. A file written after
    the read (a late call, a fail-open moved in) stays, and so does the folder."""
    for path in paths:
        try:
            os.remove(path)
        except OSError:
            pass
    _drop_leftovers(folder, "noted-")
    try:
        os.rmdir(folder)
    except OSError:
        pass


_STALE_TMP_SECONDS = 30
# A session Claude Code never closed (a killed window, a crash) never runs session-end, so its
# folder would stay forever. A week untouched is far past any live session.
_STALE_SESSION_SECONDS = 7 * 24 * 3600


def _prune_stale_sessions(project, keep=None):
    """Remove session folders untouched for _STALE_SESSION_SECONDS, never `keep` (the calling
    session's own). A folder's time moves with every call file written into it, so a live
    session's folder is never old. Never raises: pruning is housekeeping, not the check."""
    import shutil
    try:
        root = os.path.join(project, _hook_note.SESSIONS_DIR)
        # Never the shared no-session folder either: it holds fail-open counts the next
        # session-end has not summed yet, however old they are.
        keep = {os.path.abspath(k) for k in (keep, _session_dir(project, None)) if k}
        cutoff = time.time() - _STALE_SESSION_SECONDS
        for name in os.listdir(root):
            path = os.path.join(root, name)
            try:
                if (os.path.abspath(path) in keep or os.path.islink(path)
                        or not os.path.isdir(path) or os.path.getmtime(path) > cutoff):
                    continue
                shutil.rmtree(path, ignore_errors=True)
            except OSError:
                continue
    except Exception:
        pass


def _drop_leftovers(folder, prefix=None):
    """Remove one-time claims (`prefix`) and the .tmp of a call killed mid-write, which would
    otherwise keep the folder forever. A .tmp newer than _STALE_TMP_SECONDS may be a write in
    flight and is left."""
    try:
        names = os.listdir(folder)
    except OSError:
        return
    for name in names:
        path = os.path.join(folder, name)
        try:
            if (prefix and name.startswith(prefix)) or (
                    name.endswith(".tmp")
                    and time.time() - os.path.getmtime(path) > _STALE_TMP_SECONDS):
                os.remove(path)
        except OSError:
            pass


# ---- install -------------------------------------------------------------------------------

_ISOLATION_FLAGS = ("-I", "-P")
_isolation_flag_found = []


def _isolation_flag():
    """The flag that keeps the project folder off the check's import path, or "" when this
    Python has none that still finds AgentX.

    🔴 `-m` puts the folder Claude Code starts the hook in (the project) first on the import
    path, so a `json.py` the agent writes there shadows the module the check imports, and the
    agent has switched the check off. `-I` stops that, but it also drops the user's own
    site-packages, where `pip install --user` puts AgentX, and there the check would never
    start at all. So it is measured, not assumed: `-I` when this Python still imports the hook
    with it, else `-P` (Python 3.11+, which drops only the folder). Asked once per process.

    A probe that could not RUN (a timeout, a spawn error) is not a flag that does not work: it
    is kept in `_isolation_probe_failed`, so install says to try again rather than to move to
    a virtual environment (review)."""
    if not _isolation_flag_found:
        import subprocess
        import tempfile
        found = ""
        for flag in _ISOLATION_FLAGS:
            if flag == "-P" and sys.version_info < (3, 11):
                continue
            try:
                ran = subprocess.run([sys.executable, flag, "-c", "import agentx_sdk.hook"],
                                     cwd=tempfile.gettempdir(), capture_output=True, timeout=30)
            except Exception as err:
                _isolation_probe_failed.append(type(err).__name__)
                continue
            if ran.returncode == 0:
                found = flag
                break
        _isolation_flag_found.append(found)
    return _isolation_flag_found[0]


_isolation_probe_failed = []


def _hook_command(*args):
    """The command Claude Code runs: this interpreter, so the hook finds this install."""
    exe = sys.executable.replace("\\", "/")
    return " ".join(['"%s"' % exe] + ([_isolation_flag()] if _isolation_flag() else [])
                    + [_HOOK_MODULE] + list(args))


def _is_isolated(command):
    """True when an AgentX hook command starts Python with a flag that keeps the project
    folder off its import path."""
    head = str(command or "").replace("\\", "/").split(_HOOK_MODULE)[0].split()
    return any(flag in head for flag in _ISOLATION_FLAGS)


def unisolated_check(project=None):
    """True when <project>'s installed AgentX check (PreToolUse) starts Python without the
    flag, so a file the agent writes in the project can switch it off. Reads the file only:
    no probe, because status runs it every time and the Python that would be asked is this
    one, not the one the command names (review). Never raises."""
    try:
        project = os.path.abspath(project or os.getcwd())
        settings, err = _read_settings(os.path.join(project, ".claude", "settings.local.json"))
        if err or not settings:
            return False
        return any(_is_ours(h) and _HOOK_MODULE in str(h.get("command") or "")
                   and not _is_isolated(h.get("command"))
                   for e in (settings.get("hooks") or {}).get("PreToolUse") or []
                   if isinstance(e, dict)
                   for h in (e.get("hooks") or []) if isinstance(h, dict))
    except Exception:
        return False


# The after-the-call note runs as a plain file, so the package (and its check) never loads.
# `-I` keeps the file's own folder off the import path, so a module beside it never shadows
# the standard library it imports.
_NOTE_FILE = "agentx_sdk/_hook_note.py"


def _note_command():
    from . import _hook_note
    exe = sys.executable.replace("\\", "/")
    return '"%s" -I "%s"' % (exe, os.path.abspath(_hook_note.__file__).replace("\\", "/"))


def _is_agentx_source_tree(project):
    """True in a checkout of AgentX's own source, where our sessions must never count as a
    user's. An installed SDK lives in site-packages, never in the project folder itself.

    The repository's own suite runner is required too: a clone of the public SDK repository, or
    a project that copies the agentx_sdk folder in, has hook.py but not that file, and its
    developer is a user, so their calls keep their own agent id and their sessions are counted."""
    return (os.path.isfile(os.path.join(project, "agentx_sdk", "hook.py"))
            and os.path.isfile(os.path.join(project, "scripts", "run_suites.py")))


def _is_ours(hook):
    command = str(hook.get("command") or "").replace("\\", "/") if isinstance(hook, dict) else ""
    return _HOOK_MODULE in command or _NOTE_FILE in command


# Every Claude Code event an AgentX entry is registered for.
_HOOK_EVENTS = ("PreToolUse", "PostToolUse", "SessionEnd")


def _drop_ours(hooks):
    """Remove every AgentX hook command from a settings `hooks` object (any interpreter path).
    Returns how many were removed."""
    removed = 0
    for event_name in _HOOK_EVENTS:
        entries = hooks.get(event_name)
        if not isinstance(entries, list):
            continue
        kept = []
        for entry in entries:
            inner = entry.get("hooks") if isinstance(entry, dict) else None
            if isinstance(inner, list) and any(_is_ours(h) for h in inner):
                rest = [h for h in inner if not _is_ours(h)]
                removed += len(inner) - len(rest)
                if rest:
                    kept.append(dict(entry, hooks=rest))
                continue
            kept.append(entry)
        if kept:
            hooks[event_name] = kept
        else:
            del hooks[event_name]
    return removed


def _count_ours(hooks):
    """How many AgentX hook commands a settings `hooks` object holds. Reads only."""
    return sum(1 for name in _HOOK_EVENTS
               for entry in (hooks.get(name) or [])
               if isinstance(entry, dict) and isinstance(entry.get("hooks"), list)
               for h in entry["hooks"] if _is_ours(h))


def _read_settings(path):
    """(settings dict, None) or (None, error text). A missing file is an empty object."""
    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, encoding="utf-8") as fh:
            settings = json.load(fh)
    except Exception as err:
        return None, "%s could not be read (%s)" % (path, err)
    if not isinstance(settings, dict):
        return None, "%s is not a JSON object" % path
    if not isinstance(settings.get("hooks", {}), dict):
        return None, "'hooks' in %s is not an object" % path
    for name in _HOOK_EVENTS:
        if not isinstance((settings.get("hooks") or {}).get(name, []), list):
            return None, "'hooks.%s' in %s is not a list" % (name, path)
    return settings, None


def _git_state(project, relative):
    """'ignored', 'not ignored' or 'committed' when `project` is in a git repository, else
    None (not a repository, or no git): only there could the file be committed. A committed
    file is reported as not ignored whatever .gitignore says, so it is asked about first."""
    import subprocess

    def git(*args):
        return subprocess.run(["git", "-C", project] + list(args), capture_output=True,
                              timeout=10).returncode
    try:
        if git("ls-files", "--error-unmatch", relative) == 0:
            return "committed"
        return {0: "ignored", 1: "not ignored"}.get(git("check-ignore", "-q", relative))
    except Exception:
        return None


# What every screened call writes into the project folder: the path git is asked about, and
# the .gitignore line that covers it (the database's -wal and -shm files sit beside it). Only
# the session folder is named, never `.agentx/` whole: the policies file the team shares
# lives there too.
_RECORD_PATHS = ((".agentx.db", ".agentx.db", ".agentx.db*"),
                 (".agentx/hook-sessions", ".agentx/hook-sessions/session/call.json",
                  ".agentx/hook-sessions/"))


def _record_state(project, tracked, probe):
    """git's view of one record path. `tracked` is asked about first, as a pathspec, so a
    committed file anywhere under the session folder counts; `probe` is a file inside it,
    because check-ignore on the bare folder name misses a `folder/` pattern."""
    state = _git_state(project, tracked)
    return state if state in (None, "committed") else _git_state(project, probe)


def _next_rule_note(project, codex=False):
    """The one next step, while the project has no active team rule: the command that turns a
    correction into one, with a real example rather than a placeholder (a placeholder gets
    pasted). Nothing once a rule exists, or when the rules file cannot be read. On Codex, which
    cannot ask, a rule warns and lets the call run unless it stops there, so the example carries
    --stop-where-cannot-ask: its reason says pushes wait."""
    from . import team_rules
    try:
        path = team_rules.team_rules_path(project=project)
        if any(r.get("active", True) for r in team_rules.read_team_rules(path)):
            return ""
    except Exception:
        return ""
    return ("Next, turn a correction you keep giving your agent into a team rule, for example:\n"
            "    agentx rule add \"git push\" --why \"pushes wait until I have read the diff\"%s\n"
            % (" --stop-where-cannot-ask" if codex else ""))


def _record_note(project):
    """What install says about the files the hook writes into `project`, and in a git
    repository where they are not ignored, the .gitignore lines to add. One line: the detail
    (the -wal/-shm files, what each folder keeps) is mechanics a first install does not need."""
    text = "Each checked call is recorded in this folder (.agentx.db, .agentx/hook-sessions/).\n"
    states = [(_record_state(project, tracked, probe), tracked, line)
              for tracked, probe, line in _RECORD_PATHS]
    missing = [line for state, _, line in states if state in ("not ignored", "committed")]
    if missing:
        text += ("git does not ignore them here. Add %s to .gitignore:\n%s"
                 % ("this line" if len(missing) == 1 else "these lines",
                    "".join("    %s\n" % line for line in missing)))
    # Only the paths git tracks: naming an untracked one makes `git rm` fail on its pathspec
    # and untrack nothing.
    committed = [tracked for state, tracked, _ in states if state == "committed"]
    if committed:
        text += ("The record is tracked by git here. To stop tracking it and keep your copy:\n"
                 "    git rm -r --cached %s\n" % " ".join(committed))
    return text


def _install_command(ours=False, *flags):
    """`agentx hook install` as the reader must type it: in AgentX's own repository every install
    is refused without --internal, so a command the screen gives there carries it."""
    return " ".join(["agentx hook install", *flags] + (["--internal"] if ours else []))


def install_command_here(*flags, project=None):
    """`_install_command` for the project a screen is about (default: the working folder, which
    the hook has already moved into): every screen that tells someone to run the install."""
    return _install_command(_is_agentx_source_tree(os.path.abspath(project or os.getcwd())),
                            *flags)


def _interpreter_note(ours=False):
    """The hook command names this Python by its path, so a moved or rebuilt environment breaks
    every call; Claude Code shows that as a non-blocking error and runs the call unchecked."""
    return ("The hook runs this Python: %s. If it moves, calls go unchecked until you run %s "
            "again (agentx status says when).\n" % (sys.executable, _install_command(ours)))


def missing_hook_paths(project=None):
    """(path, event) for each file an installed AgentX hook in
    <project>/.claude/settings.local.json runs that no longer exists (its Python, or the note
    file beside the package), with the Claude Code event whose command names it, so a screen
    can say which part stopped. Empty when it is not installed, or all are there. Reads only,
    never raises."""
    import re
    try:
        project = os.path.abspath(project or os.getcwd())
        settings, err = _read_settings(os.path.join(project, ".claude", "settings.local.json"))
        if err or not settings:
            return []
        missing = []
        for name in _HOOK_EVENTS:
            for entry in (settings.get("hooks") or {}).get(name) or []:
                inner = entry.get("hooks") if isinstance(entry, dict) else None
                for h in inner if isinstance(inner, list) else []:
                    if not _is_ours(h):
                        continue
                    for path in re.findall(r'"([^"]+)"', str(h.get("command") or "")):
                        if not os.path.exists(path) and (path, name) not in missing:
                            missing.append((path, name))
        return missing
    except Exception:
        return []


_BACKUP_SUFFIX = ".agentx-backup"


def _write_settings(path, settings):
    """Write `settings`, backing the file up beside itself first. An empty object removes the
    file instead: `{}` says nothing Claude Code needs, and uninstall left one behind in a
    project that had no settings before install (cold install), and is not backed up: all
    that was removed is AgentX's own. Returns the backup's path, or None when none was
    written."""
    if not settings:
        if os.path.exists(path):
            os.remove(path)
        return None
    backup = None
    if os.path.exists(path):
        backup = path + _BACKUP_SUFFIX
        with open(path, encoding="utf-8") as src, open(backup, "w", encoding="utf-8") as dst:
            dst.write(src.read())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)
        fh.write("\n")
    return backup


def _backup_note(project, backup):
    """Name the backup a write left, and in a git repository where it is not ignored, the
    .gitignore line for it: a copy of the file holding this machine's Python path, untracked,
    that no screen mentioned (cold install)."""
    if not backup:
        return ""
    relative = ".claude/settings.local.json" + _BACKUP_SUFFIX
    text = "The file as it was before is kept at %s.\n" % backup
    git = _git_state(project, relative)
    if git == "not ignored":
        text += ("git does not ignore it here, and it can hold this machine's Python path. "
                 "Add this line to .gitignore:\n    %s\n" % relative)
    elif git == "committed":
        text += ("It is tracked by git here. To stop tracking it and keep your copy:\n"
                 "    git rm --cached %s\nThen add this line to .gitignore:\n    %s\n"
                 % (relative, relative))
    return text


def _installed_enforcing(hooks):
    """True when the PreToolUse check AgentX installed carries `--posture enforce`."""
    return any(_is_ours(h) and "--posture enforce" in str(h.get("command") or "")
               for e in (hooks.get("PreToolUse") or []) if isinstance(e, dict)
               for h in (e.get("hooks") or []) if isinstance(h, dict))


def _wanted_hooks(posture=None):
    """`posture="enforce"` writes the setting into the check's command line, so it blocks in
    every session with nothing exported. Watching writes the plain command, which is what every
    earlier install wrote."""
    check = (_hook_command("pre-tool-use", "--posture", "enforce") if posture == "enforce"
             else _hook_command())
    return {
        "PreToolUse": {"matcher": HOOK_MATCHER,
                       "hooks": [{"type": "command", "command": check}]},
        "PostToolUse": {"matcher": HOOK_MATCHER,
                        "hooks": [{"type": "command", "command": _note_command()}]},
        "SessionEnd": {"hooks": [{"type": "command", "command": _hook_command("session-end"),
                                  "timeout": SESSION_END_TIMEOUT_SECONDS}]},
    }


def _source_tree_refusal(project, ours, out):
    """1 with a line said when this install must not go ahead, else None. AgentX's own
    repository installs only with `--internal`, which records its calls under their own agent id
    and sends no pulse; `--internal` anywhere else is refused, so no user's install is flagged as
    AgentX's own development."""
    if _is_agentx_source_tree(project) and not ours:
        out.write("Not installed: this is AgentX's own repository, and calls made here must "
                  "never be counted as a user's. To use it here anyway, as AgentX's own "
                  "development (its own agent id, no usage count): agentx hook install "
                  "--internal\n")
        return 1
    if ours and not _is_agentx_source_tree(project):
        out.write("Not installed: --internal is only for AgentX's own repository.\n")
        return 1
    return None


def install(project=None, out=None, posture=None, ours=False):
    """Add the PreToolUse, PostToolUse and SessionEnd hooks to
    <project>/.claude/settings.local.json.

    `posture="enforce"` (`agentx hook install --enforce`) installs the check so it blocks in
    every session; `posture="audit"` (`--watch`) switches it back; None keeps what is installed
    (watching on a first install). A variable set where `claude` starts still wins for that
    session.

    The local file is the developer's own: the hook command names this machine's Python, so it
    must not land in the team's committed settings.json, and install never writes that file
    (it is the team's). An earlier AgentX entry in the local file, from any interpreter, is
    replaced rather than duplicated; one in settings.json is reported for the developer to
    remove. Merges into what is there; an unreadable file is left untouched and reported; a
    changed file is backed up beside itself as <name>.agentx-backup. In a git repository where
    the local file is not ignored, says so and gives the line to add."""
    out = out or sys.stdout
    project = os.path.abspath(project or os.getcwd())
    refused = _source_tree_refusal(project, ours, out)
    if refused:
        return refused
    local_path = os.path.join(project, ".claude", "settings.local.json")
    shared_path = os.path.join(project, ".claude", "settings.json")
    local, err = _read_settings(local_path)
    if err:
        out.write("Not installed: %s. Fix it and run this again; nothing was changed.\n" % err)
        return 1
    shared, err = _read_settings(shared_path)
    if err:
        out.write("Not installed: %s. Fix it and run this again; nothing was changed.\n" % err)
        return 1

    hooks = local.get("hooks") or {}
    if posture is None and _installed_enforcing(hooks):
        # Plain `install` keeps an enforcing install enforcing: only `--watch` switches it
        # back. The shared-settings advice below says "run agentx hook install again", and that
        # used to drop the developer back to watching without a word (review).
        posture = "enforce"
    # 🔴 A probe that could not RUN is not a reason to rewrite. Without this a timeout on a
    # reinstall wrote the check back WITHOUT the flag the earlier install had (review round 2).
    # Kept only from a command that runs THIS Python: another interpreter's flag can be one
    # this one rejects (`-P` before 3.11 exits 2, which Claude Code reads as "deny" on every
    # call) or one it cannot start the check under (scoped review).
    kept_flag = None
    if not _isolation_flag() and _isolation_probe_failed:
        this_exe = '"%s"' % sys.executable.replace("\\", "/")
        # By prefix, never by token: a path with a space (C:/Users/John Smith/...) splits.
        kept_flag = next((flag for e in hooks.get("PreToolUse") or [] if isinstance(e, dict)
                          for h in (e.get("hooks") or []) if isinstance(h, dict) and _is_ours(h)
                          for cmd in [str(h.get("command") or "").replace("\\", "/")]
                          if cmd.startswith(this_exe + " ")
                          for flag in _ISOLATION_FLAGS
                          if flag in cmd[len(this_exe):].split(_HOOK_MODULE)[0].split()
                          and not (flag == "-P" and sys.version_info < (3, 11))),
                         None)
        if kept_flag:
            _isolation_flag_found[:] = [kept_flag]
    wanted = _wanted_hooks(posture)
    # Installed means exactly our entries, one per event: the current ones, and no stale copy
    # beside them (a stale copy screens every call twice).
    already = _count_ours(hooks) == len(wanted) and all(
        any(isinstance(e, dict) and e.get("matcher") == w.get("matcher")
            and e.get("hooks") == w["hooks"] for e in hooks.get(name, []))
        for name, w in wanted.items())
    # "AgentX's checks", not "the rules": the watched or blocked calls are the checks' (the
    # shipped rules, the developer's policies file, adopted rules and site allowlist), while a
    # team rule waits for the developer under either setting (decide(): a team rule is looked up
    # only when no check stopped the call). "Waits for your go-ahead", not "asks": in a mode that
    # does not ask (auto), the call is stopped and handed back instead. The team-rule sentence
    # goes LAST, so "those calls" and "them" still mean the checks' calls.
    # "Built-in" names which checks: a reader who came for team rules otherwise meets "AgentX's
    # checks" with nothing saying what they are.
    if posture == "enforce":
        mode_text = ("Blocking: a call AgentX's built-in checks would stop is denied, and Claude "
                     "is told why and what to do instead, in every session; agentx audit lists "
                     "them. To go back to watching: %s" % _install_command(ours, "--watch"))
        team_text = "A team rule waits for your go-ahead, unless a check also stops the call."
    else:
        mode_text = ("Watching: a call AgentX's built-in checks would stop still runs, shows you "
                     "a line saying so, and is recorded; agentx audit lists them. To block those "
                     "calls in every session: %s" % _install_command(ours, "--enforce"))
        team_text = "A team rule still waits for your go-ahead."
    if already:
        out.write("Already installed in %s. %s. %s\n" % (local_path, mode_text, team_text))
    else:
        _drop_ours(hooks)
        for name, w in wanted.items():
            hooks.setdefault(name, []).append(w)
        local["hooks"] = hooks
        backup = _write_settings(local_path, local)
        out.write("Installed in %s. Claude Code now asks AgentX before each shell command and "
                  "MCP call. %s. %s\n" % (local_path, mode_text, team_text))
        out.write(_backup_note(project, backup))
    shared_hooks = shared.get("hooks") or {}
    if _count_ours(shared_hooks):
        # Says what is doubled, by which entry is copied: the CHECK records every call twice; the
        # after-the-call NOTE only tells the agent twice; a session-end copy does neither (it
        # sends the usage count), so it gets no claim at all.
        def copied(event_name):
            return _count_ours({event_name: shared_hooks.get(event_name) or []})
        if copied("PreToolUse"):
            twice = ": each call is checked and recorded twice, and agentx audit counts it twice."
        elif copied("PostToolUse"):
            twice = ": the agent is told twice."
        else:
            twice = "."
        out.write("%s (the team's shared settings) also has an AgentX hook, so Claude Code runs "
                  "both%s Remove the entries that run 'agentx_sdk.hook' or "
                  "'agentx_sdk/_hook_note.py' from that file (AgentX does not edit it), then run "
                  "%s again to check.\n"
                  % (shared_path, twice, _install_command(ours)))
    git = _git_state(project, ".claude/settings.local.json")
    if git == "not ignored":
        out.write("git does not ignore .claude/settings.local.json here, so it could be "
                  "committed with this machine's Python path in it. Add this line to "
                  ".gitignore:\n    .claude/settings.local.json\n")
    elif git == "committed":
        out.write(".claude/settings.local.json is tracked by git here, so this machine's "
                  "Python path in it goes into the repository the next time the file is "
                  "committed. To stop tracking it and keep your copy:\n"
                  "    git rm --cached .claude/settings.local.json\n"
                  "Then add this line to .gitignore:\n    .claude/settings.local.json\n")
    out.write(_record_note(project))
    out.write(_interpreter_note(ours))
    if kept_flag:
        out.write("Could not check how to keep the project folder off the check's import path "
                  "(%s), so the %s the earlier install used is kept.\n"
                  % (_isolation_probe_failed[0], kept_flag))
    elif not _isolation_flag() and _isolation_probe_failed:
        out.write("Could not check how to keep the project folder off the check's import path "
                  "(%s), so a file the agent writes there could switch the check off. Run "
                  "%s again.\n" % (_isolation_probe_failed[0], _install_command(ours)))
    elif not _isolation_flag():
        out.write("This Python cannot start the check with the project folder off its import "
                  "path (AgentX is installed where -I does not look, and -P needs Python "
                  "3.11), so a file the agent writes there could switch the check off. To "
                  "close that, install AgentX in a virtual environment and run %s from it.\n"
                  % _install_command(ours))
    # Last, so the screen ends on the one thing to do next.
    out.write(_next_rule_note(project))
    return 0


CODEX_HOOK_MATCHER = "^(Bash|mcp__.*)$"


def _codex_hooks_path(project):
    return os.path.join(project, ".codex", "hooks.json")


def install_codex(project=None, out=None, posture=None, ours=False):
    """Add the AgentX check to <project>/.codex/hooks.json as a Codex PreToolUse hook, so Codex
    runs the same check, against the same rules, as Claude Code.

    What differs is only what Codex can do with an answer: it can stop a call, and it cannot
    ask (it runs a call whose hook answers "ask"), so a team rule follows its
    `where_ask_unsupported` there. Codex skips a new or changed project hook until it is
    trusted in `/hooks`, which install says. No after-the-call note and no session pulse on
    this harness yet."""
    out = out or sys.stdout
    project = os.path.abspath(project or os.getcwd())
    refused = _source_tree_refusal(project, ours, out)
    if refused:
        return refused
    path = _codex_hooks_path(project)
    doc, err = _read_settings(path)
    if err:
        out.write("Not installed: %s. Fix it and run this again; nothing was changed.\n" % err)
        return 1
    hooks = doc.get("hooks") or {}
    entries = hooks.get("PreToolUse")
    if not isinstance(entries, list):
        entries = []
    args = ["pre-tool-use"] + (["--posture", "enforce"] if posture == "enforce" else []) \
        + ["--harness", "codex"]
    wanted = {"matcher": CODEX_HOOK_MATCHER,
              "hooks": [{"type": "command", "command": _hook_command(*args), "timeout": 30,
                         "statusMessage": "AgentX check"}]}
    if any(e == wanted for e in entries) and _count_ours({"PreToolUse": entries}) == 1:
        out.write("Already installed in %s.\n" % path)
        return 0
    # Only AgentX's own commands come out; a user's hook in the same entry stays.
    rest = {"PreToolUse": list(entries)}
    _drop_ours(rest)
    hooks["PreToolUse"] = rest.get("PreToolUse", []) + [wanted]
    doc["hooks"] = hooks
    backup = _write_settings(path, doc)
    out.write("Installed in %s. Codex now asks AgentX before each shell command and MCP call, "
              "with the same rules as Claude Code. Codex runs a new project hook only after you "
              "trust it: open /hooks in Codex once and trust the AgentX check.\n" % path)
    # The flag a person types, not the file's field name (found on the team-rules clip).
    out.write("Codex cannot ask you about a call, so a team rule there warns and lets the call "
              "run, unless the rule was added with --stop-where-cannot-ask.\n")
    if backup:
        out.write("The file as it was before is kept at %s.\n" % backup)
    if _git_state(project, ".codex/hooks.json") in ("not ignored", "committed"):
        out.write("The hook names this machine's Python, so keep .codex/hooks.json out of git: "
                  "add this line to .gitignore:\n    .codex/hooks.json\n")
    out.write(_next_rule_note(project, codex=True))
    return 0


def uninstall_codex(project=None, out=None):
    """Remove AgentX's check from <project>/.codex/hooks.json, leaving everything else as it was
    (backed up beside itself first)."""
    out = out or sys.stdout
    project = os.path.abspath(project or os.getcwd())
    path = _codex_hooks_path(project)
    doc, err = _read_settings(path)
    if err:
        out.write("Not removed: %s. Fix it and run this again; nothing was changed.\n" % err)
        return 1
    hooks = doc.get("hooks") or {}
    if not _drop_ours(hooks):
        out.write("AgentX is not installed in %s; nothing was changed.\n" % path)
        return 0
    if hooks:
        doc["hooks"] = hooks
    else:
        doc.pop("hooks", None)
    backup = _write_settings(path, doc)
    out.write("Removed AgentX from %s. Codex no longer asks AgentX before tool calls in this "
              "project.\n" % path)
    if backup:
        out.write("The file as it was before is kept at %s.\n" % backup)
    return 0


def uninstall(project=None, out=None):
    """Remove AgentX's hooks from <project>/.claude/settings.local.json, leaving everything
    else in the file as it was (backed up beside itself first). The team's settings.json is
    never edited: an AgentX entry there is reported for the developer to remove. The record
    (`.agentx.db`, `.agentx/`) is kept: it is the developer's, and `agentx audit` still reads it."""
    out = out or sys.stdout
    project = os.path.abspath(project or os.getcwd())
    local_path = os.path.join(project, ".claude", "settings.local.json")
    shared_path = os.path.join(project, ".claude", "settings.json")
    local, err = _read_settings(local_path)
    if err:
        out.write("Not removed: %s. Fix it and run this again; nothing was changed.\n" % err)
        return 1
    hooks = local.get("hooks") or {}
    removed = _drop_ours(hooks)
    if removed:
        if hooks:
            local["hooks"] = hooks
        else:
            local.pop("hooks", None)
        backup = _write_settings(local_path, local)
        out.write("Removed AgentX from %s%s. Claude Code no longer asks AgentX before tool "
                  "calls in this project. Your record is kept: agentx audit still reads it.\n"
                  % (local_path, "" if local else ", which held nothing else, so it was deleted"))
        out.write(_backup_note(project, backup) if local else _older_backup_note(local_path))
    else:
        out.write("AgentX is not installed in %s; nothing was changed.\n" % local_path)
    shared, err = _read_settings(shared_path)
    if not err and _count_ours(shared.get("hooks") or {}):
        out.write("%s (the team's shared settings) also has an AgentX hook, which this does not "
                  "edit. Remove the entries that run 'agentx_sdk.hook' or "
                  "'agentx_sdk/_hook_note.py' from that file.\n" % shared_path)
    return 0


def _older_backup_note(local_path):
    """When uninstall deleted the settings file, a backup an earlier install wrote beside it
    can still hold AgentX's hooks and this machine's Python path (review: install, install
    again, uninstall left one, unnamed). Deleted when AgentX's entries are all it holds, else
    named."""
    backup = local_path + _BACKUP_SUFFIX
    if not os.path.exists(backup):
        return ""
    held, err = _read_settings(backup)
    if not err:
        hooks = held.get("hooks") or {}
        _drop_ours(hooks)
        if not hooks:
            held.pop("hooks", None)
        if not held:
            try:
                os.remove(backup)
                return ""
            except OSError:
                pass
    text = ("An older copy of the file is still at %s; delete it if you do not need it.\n"
            % backup)
    # The advice `_backup_note` gives, minus its first line: this copy can hold the Python path.
    project = os.path.dirname(os.path.dirname(local_path))
    return text + _backup_note(project, backup).split("\n", 1)[1]


def _is_terminal(stream):
    try:
        return stream.isatty()
    except Exception:
        return False


def _flag_value(args, flag):
    """The word after `flag` in `args`, or None."""
    try:
        return args[args.index(flag) + 1]
    except (ValueError, IndexError):
        return None


class _Wrapped:
    """A person's screen for install and uninstall: each line wrapped at the 75-column fence the
    other agentx screens use, so a terminal never breaks a word ("MC / P call", found on the
    team-rules clip). A line that starts with a space is a command or a path to copy and is
    printed whole; a long word inside a sentence (a path with no spaces) is never split."""

    def __init__(self, out, width=75):
        self.out, self.width, self.buf = out, width, ""

    def write(self, text):
        self.buf += text
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self._line(line)

    def _line(self, line):
        import re
        import textwrap
        if len(line) <= self.width or line[:1].isspace():
            self.out.write(line + "\n")
            return
        # An `agentx ...` command inside a sentence stays on one line, so it can be copied whole
        # ("agentx hook / install --enforce" was split at first).
        glued = re.sub(r"agentx(?: (?:--)?[a-z][a-z-]*)+",
                       lambda m: m.group(0).replace(" ", "\x00"), line)
        for part in textwrap.wrap(glued, self.width, break_long_words=False,
                                  break_on_hyphens=False):
            self.out.write(part.replace("\x00", " ") + "\n")

    def flush(self):
        if self.buf:
            self._line(self.buf)
            self.buf = ""
        try:
            self.out.flush()
        except Exception:
            pass


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    sub = argv[0] if argv else ""
    if sub in ("install", "uninstall"):
        out = _Wrapped(sys.stdout)
        try:
            return _install_main(sub, argv[1:], out)
        finally:
            out.flush()
    return _other_main(sub, argv)


def _install_main(sub, rest, out):
    """`agentx hook install | uninstall`, written to `out` (a person's wrapped screen)."""
    if sub == "install":
        flags = [a for a in rest if a.startswith("--")]
        dirs = [a for a in rest if not a.startswith("--")]
        unknown = [f for f in flags if f not in ("--enforce", "--watch", "--codex", "--internal")]
        if unknown or ("--enforce" in flags and "--watch" in flags) or len(dirs) > 1:
            sys.stderr.write(_USAGE)
            return 1
        posture = "enforce" if "--enforce" in flags else "audit" if "--watch" in flags else None
        if "--codex" in flags:
            return install_codex(dirs[0] if dirs else None, out=out, posture=posture,
                                 ours="--internal" in flags)
        return install(dirs[0] if dirs else None, out=out, posture=posture,
                       ours="--internal" in flags)
    codex = "--codex" in rest
    rest = [a for a in rest if a != "--codex"]
    if len(rest) > 1 or any(a.startswith("--") for a in rest):
        sys.stderr.write(_USAGE)
        return 1
    return (uninstall_codex if codex else uninstall)(rest[0] if rest else None, out=out)


def _other_main(sub, argv):
    if sub == "session-end":
        return session_end()
    if sub == "post-tool-use":
        return post_tool_use()
    if sub == "record-ran":
        return record_ran()
    if sub in ("-h", "--help", "help"):
        sys.stdout.write(_USAGE)
        return 0
    if sub == "" and _is_terminal(sys.stdin):
        # A person typed it. Claude Code always pipes the event, so waiting on a terminal for
        # JSON would look like a hang.
        sys.stdout.write("agentx hook is run by Claude Code before each tool call.\n"
                         "To add it to this project:  %s\n" % install_command_here())
        return 0
    if sub in ("", "pre-tool-use"):
        rest = argv[1:]
        installed = "enforce" if _flag_value(rest, "--posture") == "enforce" else None
        harness = "codex" if _flag_value(rest, "--harness") == "codex" else "claude"
        return pre_tool_use(installed=installed, harness=harness)
    sys.stderr.write(_USAGE)
    # 1, never 2: to Claude Code a PreToolUse exit of 2 means "block this call".
    return 1


_USAGE = (
    "usage: agentx hook install [DIR] [--enforce | --watch] [--codex]\n"
    "       agentx hook uninstall [DIR] [--codex]\n"
    "\n"
    "  install            Add AgentX to this project's Claude Code settings. It\n"
    "                     watches: a call AgentX's built-in checks would stop runs\n"
    "                     and is recorded.\n"
    "  install --enforce  The same, but such calls are blocked in every session.\n"
    "  install --watch    Switch an enforcing install back to watching.\n"
    "  install --codex    Add the same check to this project's Codex hooks.\n"
    "  uninstall [DIR]    Remove AgentX's hooks from this project's settings (your\n"
    "                     record is kept).\n"
    "\n"
    "Claude Code runs the other forms itself:\n"
    "  pre-tool-use, post-tool-use, session-end.\n"
)


if __name__ == "__main__":
    sys.exit(main())
