"""The Claude Code door's after-the-call note, and the helpers the hook shares with it.

Claude Code runs this FILE by its path after each screened call (not `-m agentx_sdk...`), so
the package, and with it the whole check, is never imported: it starts in about the time of a
bare interpreter, where the hook itself needs the check and takes about three times as long.
It may therefore import only the standard library. `hook.py` imports the helpers below, so the
two never disagree on where a call's record lives.

What it does: when watching let through a call the rules would stop, the line before the call
went to the developer only, so the agent never learned it, and it could tell the developer that
nothing had flagged a call AgentX had just flagged. Told after the call has run, the note
cannot change what the agent did; it only makes the agent's account true. It reads the record
the same call's check wrote (matched by `tool_use_id`) and judges nothing again. It always
exits 0 and prints nothing on any fault: a missed note is a gap in what the agent knows, never
a change to the call.
"""
import hashlib
import json
import os
import sys

SESSIONS_DIR = os.path.join(".agentx", "hook-sessions")


def read_event(stdin):
    """The event as a dict, or None.

    Read as BYTES and decoded as UTF-8 (a leading byte-order mark dropped). Claude Code writes
    UTF-8, while Python on Windows decodes stdin with the local code page: a command holding a
    Cyrillic letter failed to decode (a silent fail-open), and a hidden direction-override
    character arrived garbled, so the check for it never fired."""
    raw = getattr(stdin, "buffer", None)
    if raw is not None:
        text = raw.read().decode("utf-8-sig", errors="replace")
    else:
        text = stdin.read().lstrip(chr(0xFEFF))
    event = json.loads(text or "{}")
    return event if isinstance(event, dict) else None


def project_dir(event=None):
    """Where this project's rules and records live: Claude Code names it, else the event's cwd."""
    named = os.environ.get("CLAUDE_PROJECT_DIR")
    if named and os.path.isdir(named):
        return os.path.abspath(named)
    cwd = (event or {}).get("cwd")
    if isinstance(cwd, str) and os.path.isdir(cwd):
        return os.path.abspath(cwd)
    return os.path.abspath(os.getcwd())


def session_dir(project, session_id):
    key = hashlib.sha256(str(session_id or "no-session").encode("utf-8")).hexdigest()[:24]
    return os.path.join(project, SESSIONS_DIR, key)


def call_record_name(call_id):
    return hashlib.sha256(str(call_id).encode("utf-8")).hexdigest()[:24] + ".json"


def post_tool_use(stdin=None, stdout=None):
    """Print the note for the agent when the call's record says watching let it through."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        event = read_event(stdin)
        call_id = (event or {}).get("tool_use_id")
        if not call_id:
            return 0
        path = os.path.join(session_dir(project_dir(event), event.get("session_id")),
                            call_record_name(call_id))
        with open(path, encoding="utf-8") as fh:
            record = json.load(fh)
        if not (isinstance(record, dict) and record.get("would_block")):
            return 0
        note = ("AgentX: your %s call just now matched its rule '%s'. AgentX is watching, not "
                "blocking, so the call ran, and the developer was shown a line saying so."
                % (record.get("tool") or event.get("tool_name") or "last",
                   record.get("rule") or "an AgentX rule"))
        stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                        "additionalContext": note}}))
        stdout.flush()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(post_tool_use())
