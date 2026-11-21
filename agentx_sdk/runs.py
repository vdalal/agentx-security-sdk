"""What an agent was asked and what it said, kept on this machine for `agentx match`.

The ledger (`.agentx.db`) keeps the shape of each call: argument names, never their values. This
file, beside it, keeps what the ledger does not, and only when the developer asks for it:

- ``agentx_sdk.task(text, id=None)`` at the start of a task: the request. The protected calls
  that run after it, in the same thread or async task, belong to it.
- ``agentx_sdk.reply(text)`` at the end: what the agent told the person. It ends the task, so a
  later call is not filed under it. With no task running, a reply is not kept: it belongs to none.
- With a task running, each protected call that ran: its tool, its argument names, and what its
  ``verify=`` found.
- What the tool declared it changes, when it did (``@agentx_protect(effect="books")``).
- With ``AGENTX_KEEP_ARG_VALUES=1``: the argument values too, so `agentx match` can check a
  record against what the call asked. Off unless set. A value under a secret's
  name is kept as "[withheld]", by the same rule the SDK uses to keep secrets off the wire
  (`flow.py`).

Nothing here is sent anywhere: no telemetry reads this file. Without a task and without the
setting, nothing is written and the file is never created. The file holds what the agent was told
and did, so it is kept out of git like the ledger: `.agentx.db*` in .gitignore covers both.

One JSON object per line, in the order written. Each `task()` starts a run with its own id, so a
task id used twice is two runs. Past `_MAX_BYTES` the file is cut to its newest half, at the start
of a task, so no task is kept without its beginning.
"""
import asyncio
import dataclasses
import datetime as _dt
import decimal as _decimal
import enum as _enum
import json
import numbers
import os
import pathlib as _pathlib
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor
from contextvars import ContextVar
from datetime import datetime, timezone

KEEP_VALUES_ENV = "AGENTX_KEEP_ARG_VALUES"
# What a tool may declare it changes (@agentx_protect(effect=...)), for `agentx match`.
EFFECTS = ("books", "cancels")
_SUFFIX = ".runs.jsonl"
_MAX_BYTES = 10 * 1024 * 1024
# A value longer than this is cut, and says so: a file's contents passed to a tool would otherwise
# fill the record with one call.
_MAX_VALUE_CHARS = 1000
WITHHELD = "[withheld]"

# (task id, run id) of the task this context is running, or None.
_task_var = ContextVar("agentx_task", default=None)
# Calls made between tasks (values kept, no task running) are one run per gap. A gap belongs to the
# session's trace, so calls the agent hands to worker threads or copied contexts (asyncio.to_thread,
# a framework's executor) stay in it; with no trace, to this context. A gap ends at task(), reply(),
# or after _GAP_IDLE_SECONDS with no call, so a process that never calls either does not make one
# run of calls days apart.
_gaps = {}                                          # trace -> [run id, time of its last call]
_gap_var = ContextVar("agentx_gap", default=None)   # [run id, time of its last call], with no trace
_GAP_IDLE_SECONDS = 30 * 60
# Past this many open gaps, the idle ones are dropped: a service that starts a session per request
# and never calls task() or reply() would otherwise keep one entry per request for its whole life.
_GAPS_SWEEP_AT = 256
_next_sweep = _GAPS_SWEEP_AT
# The file's lock: held across a write and a cut, which can take a while on a full file.
_lock = threading.Lock()
# The gaps' own lock, taken on the caller's thread (an async tool's event loop): never the file's,
# so a long cut on the writer thread cannot stall the loop.
_gap_lock = threading.Lock()

# The one thread every line is written on (`write_soon`): its own, so a write never waits behind
# the SDK's gateway calls and approval waits, and one worker keeps lines in the order written. Made
# here, with no lock to take on the event loop; its thread starts with its first write.
_WRITER_PREFIX = "agentx-runs"
_writer = _ThreadPoolExecutor(max_workers=1, thread_name_prefix=_WRITER_PREFIX)


def writer():
    return _writer


def _after_fork_in_child():
    """A forked child (gunicorn --preload, a multiprocessing or celery worker) inherits the writer
    with its thread gone and maybe a lock held by that thread: a write handed to it would wait
    forever. The child starts its own."""
    global _writer, _lock, _gap_lock, _said_lock, _gaps
    _lock = threading.Lock()
    _gap_lock = threading.Lock()
    _said_lock = threading.Lock()
    _writer = _ThreadPoolExecutor(max_workers=1, thread_name_prefix=_WRITER_PREFIX)
    # The child is another process: its calls and any reply are not the parent's task's, which
    # would otherwise read as one run with two replies.
    _task_var.set(None)
    _gap_var.set(None)
    _gaps = {}


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def _on_a_running_loop():
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


def write_soon(fn, *args):
    """Run a write (`fn(*args)`) on the writer thread, so every line, from any thread, goes through
    one worker and lands in the order it was asked for: task, then calls, then reply, even when a
    call runs in a worker thread (asyncio.to_thread) while the task line is still queued.

    On an event loop it is handed over and not waited for: the loop never waits on the file's lock,
    a cut of a full file, or the once-per-process git check. Anywhere else the caller waits for it,
    so a synchronous agent finds its line written when the call returns, as before. Never raises."""
    try:
        if threading.current_thread().name.startswith(_WRITER_PREFIX):
            fn(*args)                       # already on the writer: waiting on it would never end
            return
        future = _writer.submit(fn, *args)
    except Exception:
        # The writer is shut down (the interpreter is exiting): write here, as before.
        try:
            fn(*args)
        except Exception:
            pass
        return
    if _on_a_running_loop():
        return
    try:
        future.result()
    except Exception:
        pass


def flush(timeout=5.0):
    """Wait, up to `timeout` seconds, until every line handed to the writer so far is in the file.
    In an async agent or a notebook the lines are written a moment after task(), the call or
    reply() returns; call this before reading the file from the same process, or before running
    `agentx match` straight after. It blocks the caller, so not inside a running agent's event
    loop. Never raises."""
    try:
        if threading.current_thread().name.startswith(_WRITER_PREFIX):
            return                          # on the writer, everything before this is written
        _writer.submit(lambda: None).result(timeout)
    except Exception:
        pass


def _gap_run():
    """The run id for a call made with no task running."""
    import time
    now = time.time()
    trace = _trace()
    with _gap_lock:
        gap = _gaps.get(trace) if trace else _gap_var.get()
        if gap is None or now - gap[1] > _GAP_IDLE_SECONDS:
            gap = [uuid.uuid4().hex[:12], now]
            if trace:
                global _next_sweep
                if len(_gaps) >= _next_sweep:
                    for key in [k for k, g in _gaps.items() if now - g[1] > _GAP_IDLE_SECONDS]:
                        del _gaps[key]
                    # When most gaps are still active, the next sweep waits until the dict has
                    # doubled: a scan per new trace would cost more with every request.
                    _next_sweep = max(_GAPS_SWEEP_AT, 2 * len(_gaps))
                _gaps[trace] = gap
            else:
                _gap_var.set(gap)
        gap[1] = now
        return gap[0]


def _end_gap():
    trace = _trace()
    with _gap_lock:
        if trace:
            _gaps.pop(trace, None)
    _gap_var.set(None)


def path():
    """The file beside the ledger, `<ledger>.runs.jsonl`, as a full path: a line asked for now and
    written a moment later on the writer thread goes to the file the ledger path named now, even if
    the agent changed folder in between."""
    from . import db
    target = db.DB_PATH + _SUFFIX
    try:
        return os.path.abspath(target)
    except Exception:                       # the working folder was deleted under the process
        return target


def keeping_values():
    return os.environ.get(KEEP_VALUES_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def current_task():
    """The id of the task this context is running, or None."""
    current = _task_var.get()
    return current[0] if current else None


def _now():
    return datetime.now(timezone.utc).isoformat()


def _trace():
    try:
        from .decorators import trace_id_var
        return trace_id_var.get() or None
    except Exception:
        return None


_said = set()
# Its own lock, never the file's: reply() asks it on the caller's thread (an event loop), and the
# file's lock can be held across a long cut on the writer.
_said_lock = threading.Lock()


def _first_time(what):
    """True the first time this process asks about `what`, once across threads."""
    with _said_lock:
        if what in _said:
            return False
        _said.add(what)
        return True


def _say(line):
    import sys
    try:
        print(line, file=sys.stderr)
    except Exception:
        pass


def _say_once(what, target):
    """The first time this process writes each kind of thing, say what is kept and where, on
    stderr: the developer turned it on, and should see it working and know what it holds."""
    if not _first_time(what):
        return
    if what == "values":
        line = ("[AgentX SDK] Keeping the arguments of each protected call, values included, in %s "
                "(%s is set). A value under a secret's name is kept as [withheld]. On this machine "
                "only; nothing is sent anywhere." % (target, KEEP_VALUES_ENV))
    else:
        line = ("[AgentX SDK] Keeping the task, the agent's reply and each call's argument names in "
                "%s, for 'agentx match'. On this machine only; nothing is sent anywhere." % target)
    state = _git_state(target)
    if state == "committed":
        line += (" git tracks that file here, so every change to it is committed. To stop: git rm "
                 "--cached %s, and add this line to .gitignore: .agentx.db*" % os.path.basename(target))
    elif state == "not ignored":
        line += (" git does not ignore that file here: add this line to .gitignore so it is not "
                 "committed: .agentx.db*")
    _say(line)


_git_answer = {}


def _git_state(target):
    """'committed', 'not ignored', or None (ignored, no git, no repository, or git cannot say), for
    `target`; worked out once per process and kept."""
    with _lock:
        if target in _git_answer:
            return _git_answer[target]
    import subprocess
    folder = os.path.dirname(os.path.abspath(target)) or "."
    # GIT_DIR and its kind, set by a git hook the agent may be running under, would point git at
    # another repository than the one the file sits in.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}

    def git(*args):
        return subprocess.run(["git", "-C", folder] + list(args), capture_output=True, timeout=5,
                              env=env).returncode
    try:
        # Tracked first: check-ignore calls a tracked file "not ignored" whatever .gitignore says.
        if git("ls-files", "--error-unmatch", os.path.abspath(target)) == 0:
            state = "committed"
        else:
            state = "not ignored" if git("check-ignore", "-q", os.path.abspath(target)) == 1 else None
    except Exception:
        state = None
    with _lock:
        _git_answer[target] = state
    return state


def _write(entry, target):
    """Append one line to `target` (`path()`, taken when the line was asked for). Never raises: a
    record problem is never the agent's problem.

    Everything a line holds, its file included, is worked out by the caller before the line is
    handed to the writer (`write_soon`): read later, on the writer thread, a value the agent changed
    in the meantime, or a working folder it moved to, would be recorded instead of what the call
    had."""
    try:
        line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
        try:
            line.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate (a file name decoded with surrogateescape) cannot be written as utf-8,
            # and written as a JSON escape it comes back as itself and breaks every reader that
            # prints it (`agentx match --out`). Kept as the plain text "\udcff" instead.
            line = json.dumps(_as_plain_text(entry), ensure_ascii=False, default=str) + "\n"
        _say_once("values" if "args" in entry else "task", target)
        with _lock:
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(line)
            if os.path.getsize(target) > _MAX_BYTES:
                _cut(target)
    except Exception:
        pass


def _as_plain_text(value):
    """`value` with every string, keys included, holding only characters utf-8 can write: a lone
    surrogate becomes its escape as plain text ("\\udcff")."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, dict):
        return {_as_plain_text(k): _as_plain_text(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_as_plain_text(v) for v in value]
    return value


def _parsed(line):
    try:
        entry = json.loads(line)
        return entry if isinstance(entry, dict) else {}
    except Exception:
        return {}


def _cut(target):
    """Keep the newest half of the lines, from the first task line in that half, so no task is
    kept without its start (a reply with its calls cut away reads as a claim with nothing behind
    it). Lines before that first task line that belong to no task (calls between tasks) need no
    start, and stay. With no task line in the newer half, the whole newer half is kept. Each line
    is read once."""
    with open(target, encoding="utf-8") as fh:
        lines = fh.readlines()
    kept = lines[len(lines) // 2:]
    start, head = 0, []
    for i, line in enumerate(kept):
        entry = _parsed(line)
        if entry.get("kind") == "task":
            start = i
            break
        head.append(line if entry and entry.get("task") in (None, "") else None)
    else:
        head = []                           # no task line: the whole newer half stays
    with open(target, "w", encoding="utf-8") as fh:
        fh.writelines([line for line in head if line is not None] + kept[start:])


def task(text, id=None):
    """Start a task: the request the agent is working on. Calls made after this, in this thread or
    async task, are recorded as part of it until `reply()` or the next `task()`. Returns the task's
    id (the one given, or a new one).

    Kept only in the local file beside the ledger; nothing is sent anywhere."""
    from .decorators import trace_id_var, start_secure_session
    task_id = str(id) if id not in (None, "") else uuid.uuid4().hex[:12]
    run_id = uuid.uuid4().hex[:12]
    _task_var.set((task_id, run_id))
    if not trace_id_var.get():
        start_secure_session()
    _end_gap()
    write_soon(_write, {"kind": "task", "time": _now(), "task": task_id, "run": run_id,
                        "trace": _trace(), "text": _text(text)}, path())
    return task_id


def reply(text):
    """Record what the agent told the person at the end of the task this context is running: the
    claim `agentx match` checks against the records. Ends the task. Call it in the same thread or
    async task as `task()`: with no task running here, nothing is kept (a reply that belongs to no
    task cannot be checked against one), and stderr says so once.

    Kept only in the local file beside the ledger; nothing is sent anywhere."""
    current = _task_var.get()
    if not current:
        if _first_time("no_task_reply"):
            _say("[AgentX SDK] agentx_sdk.reply() was called with no task running here, so the reply "
                 "was not kept. Call it in the same thread or async task as agentx_sdk.task().")
        return
    write_soon(_write, {"kind": "reply", "time": _now(), "task": current[0], "run": current[1],
                        "trace": _trace(), "text": _text(text)}, path())
    _task_var.set(None)
    _end_gap()


# A task's or a reply's text past this is cut, and says so: one huge task line would otherwise keep
# the file over its size and make every later write rewrite it.
_MAX_TEXT_CHARS = 4000


def _text(text):
    text = "" if text is None else str(text)
    if len(text) > _MAX_TEXT_CHARS:
        return text[:_MAX_TEXT_CHARS] + " [cut: %d characters in all]" % len(text)
    return text


# Name parts withheld here on top of the SDK's own secret rule: words the wire rule leaves to the
# value's shape, and personal numbers no tool needs kept. Over-withholding is the safe side: an id
# under one of these names (contact_key, session_id) is withheld too, and cannot be matched.
_FLOOR_WORDS = {"auth", "key", "session", "otp", "totp", "mfa", "jwt", "pin", "ssn", "cvv", "cvc",
                "cookie", "passcode"}
# Endings of a name that holds a card or a government number (`flow._PII_ENDINGS` without the phone
# and the birth date, which an appointment record is matched by).
_FLOOR_ENDINGS = ("card_number", "credit_card", "social_security", "social_security_number")
# A connection object or string: kept off the wire too (`decorators._rule_args_for_gateway`).
_FLOOR_NAMES = {"conn", "cursor", "db_session"}
# Words that make a number under a token name a count or a position, not a token.
_COUNT_WORDS = {"count", "counts", "limit", "max", "min", "budget", "total", "num", "per",
                "remaining", "left", "index", "offset"}
# With the plural only: the words a model's usage is counted in (`tokens_used`, `prompt_tokens`).
_USAGE_WORDS = {"used", "usage", "prompt", "completion", "input", "output", "cached", "cache",
                "reasoning", "audio", "image"}
# The tool that splits text into tokens: a name, not a token.
_TOKENIZER_NOUNS = {"tokenizer", "tokenizers", "tokeniser", "tokenisers"}
# Words that make a token a credential, whatever the number beside it says.
_CREDENTIAL_WORDS = {"refresh", "access", "auth", "api", "bearer", "id", "session", "csrf", "oauth",
                     "secret", "jwt", "reset", "invite", "verify", "verification", "push", "device"}


def _withheld(name, value):
    """A value under a secret's name: the SDK's own rule (`decorators._is_secret_default`, which
    keeps secrets off the wire), or a name on the floor above."""
    from .decorators import _is_secret_default
    from .flow import _name_words
    name = str(name)
    if _is_secret_default(name, value):
        return True
    try:
        words = _name_words(name)
        joined = "_".join(words)
        # A word with "token" in it, however the name is written (APIToken, authtoken, token2,
        # tokenstr, refreshToken1, tokenised_card), is a token: withheld. Only the tool that splits
        # text (tokenizer, tokeniser) is not. Withholding too much costs a match, never a false
        # finding: `agentx match` never compares a withheld value, nor takes its call for a repeat. The exception is a number that is a count: beside a count word (`token_count`,
        # `max_tokens`), or, for the plural, beside a model-usage word (`tokens_used`,
        # `prompt_tokens`), and never beside or glued to a credential word.
        token_words = [w for w in words if "token" in w and w not in _TOKENIZER_NOUNS]
        if token_words:
            number = isinstance(value, numbers.Number) and not isinstance(value, bool)
            credential = bool(_CREDENTIAL_WORDS.intersection(words)) or \
                any(w not in ("token", "tokens") for w in token_words)
            plural = "tokens" in token_words
            counted = number and not credential and (
                bool(_COUNT_WORDS.intersection(words))
                or (plural and bool(_USAGE_WORDS.intersection(words))))
            if not counted:
                return True
        return bool(_FLOOR_WORDS.intersection(words) or joined in _FLOOR_NAMES
                    or any(joined.endswith(e) for e in _FLOOR_ENDINGS))
    except Exception:
        return True


# Kept as their text: values that carry no fields to hide and that a record often holds (an amount,
# a date, an id).
_AS_TEXT_TYPES = (_decimal.Decimal, _dt.date, _dt.time, _dt.timedelta, uuid.UUID, _pathlib.PurePath)
# How many containers and objects one argument may open before the rest is withheld: an object graph
# that points back at itself (an ORM row and its relations) is otherwise walked without end, on the
# agent's own call.
_MAX_OBJECTS = 500


def _plain(value):
    """`value` in a form the secret rule can see into: an enum as its value, a namedtuple, a
    dataclass, an attrs or pydantic model, or an object with fields as a dict of its fields; a known
    value type as its text. Anything else, and anything that fails, is WITHHELD: never its str(),
    which for a model prints its password field."""
    if value is None or isinstance(value, (str, bytes, bool, numbers.Number, dict, list, set, frozenset)):
        return value
    if isinstance(value, tuple):
        asdict = getattr(value, "_asdict", None)            # a namedtuple keeps its field names
        if callable(asdict):
            try:
                return dict(asdict())
            except Exception:
                return WITHHELD
        return value
    try:
        if isinstance(value, _enum.Enum):
            return _plain(value.value)
        if isinstance(value, _AS_TEXT_TYPES):
            return str(value)
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return {f.name: getattr(value, f.name, None) for f in dataclasses.fields(value)}
        attrs_fields = getattr(type(value), "__attrs_attrs__", None)
        if attrs_fields is not None:
            return {a.name: getattr(value, a.name, None) for a in attrs_fields}
        if hasattr(type(value), "model_fields") and callable(getattr(value, "model_dump", None)):
            return dict(value.model_dump())                 # pydantic 2
        if hasattr(type(value), "__fields__") and callable(getattr(value, "dict", None)):
            return dict(value.dict())                       # pydantic 1
        fields = getattr(value, "__dict__", None)
        if isinstance(fields, dict):
            public = {k: v for k, v in fields.items() if not str(k).startswith("_")}
            if public:
                return public
        slots = [s for c in type(value).__mro__ for s in (getattr(c, "__slots__", ()) or ())
                 if isinstance(s, str) and not s.startswith("_")]
        if slots:
            return {s: getattr(value, s, None) for s in slots}
    except Exception:
        return WITHHELD
    return WITHHELD


def _new_walk():
    # "chars": a FLOOR on the JSON text kept so far: each piece counts no more than it takes once
    # written ("ab" counts 4, 12 counts 2, a container 2 for its brackets). Once the floor passes
    # `_MAX_VALUE_CHARS` the value is over the limit whatever comes next, so the walk stops there
    # ("stopped") instead of reading a huge argument whole on the agent's own call. "left_out" is
    # set only when something was then actually skipped or shortened: only that makes a value
    # "cut", so a value that fits is never called cut.
    return {"seen": set(), "left": _MAX_OBJECTS, "chars": 0, "stopped": False, "left_out": False}


def _written_len(value):
    """How long json.dumps writes this non-text scalar (an int-based enum writes its number, not
    its name); 1 when it cannot be written (an int too long to print), which keeps the floor."""
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:
        return 1


def _key_text(key):
    """The text JSON writes for a dict key (a str-based enum as its value, 1 as "1", True as
    "true"), or None for a key JSON cannot write."""
    if isinstance(key, str):
        return "" + key                     # the str itself, never an enum's own str()
    if isinstance(key, (int, float)) or key is None:
        try:
            return json.dumps(key)
        except Exception:
            return None
    return None


def _key_len(key):
    """How long a dict key's text is once written, without its quotes: a str key (a str-based enum
    too) as its own text, a number by JSON's own rule, anything else 0 (the floor)."""
    if isinstance(key, str):
        return len(key)
    if isinstance(key, (int, float)) or key is None:
        return _written_len(key)
    return 0


def _spent(walk, n):
    """Count `n` characters of the floor; True once it is over the limit."""
    walk["chars"] += n
    if walk["chars"] > _MAX_VALUE_CHARS:
        walk["stopped"] = True
    return walk["stopped"]


_WITHHELD_CHARS = len(WITHHELD) + 2                 # "[withheld]" with its quotes


def _withheld_here(walk):
    _spent(walk, _WITHHELD_CHARS)
    return WITHHELD


def _scalar(value, walk):
    """A plain value, counted; a string or bytes longer than the room left is cut to just past it
    (the value is over the limit then, and only the first `_MAX_VALUE_CHARS` are written)."""
    if isinstance(value, (str, bytes)):
        room = _MAX_VALUE_CHARS - walk["chars"]
        if len(value) > max(0, room) + 1:
            walk["stopped"] = walk["left_out"] = True
            return value[:max(0, room) + 1]
        _spent(walk, len(value) + 2)
        return value
    _spent(walk, _written_len(value))           # None, True, False and numbers, as written
    return value


def _without_secrets(value, depth=0, walk=None):
    """`value` with every secret inside it withheld, at any depth: a dict's secret-named entry, a
    (name, value) pair as httpx and requests take headers and params, an object's fields. A
    container or object met a second time, or past `_MAX_OBJECTS` in one argument, is withheld, so
    a graph that points back at itself ends. Once the value is surely over `_MAX_VALUE_CHARS` the
    walk stops and the rest is left out: it would be cut, and nothing left out is written."""
    walk = walk if walk is not None else _new_walk()
    if depth > 32:
        return _withheld_here(walk)
    if value is None or isinstance(value, (str, bytes, bool, numbers.Number)):
        return _scalar(value, walk)
    if id(value) in walk["seen"] or walk["left"] <= 0:
        return _withheld_here(walk)
    walk["seen"].add(id(value))
    walk["left"] -= 1
    value = _plain(value)
    if isinstance(value, dict):
        _spent(walk, 2)
        out, written_keys = {}, set()
        for k, v in value.items():
            key_text = _key_text(k)
            if key_text is None or key_text in written_keys:
                # A key JSON cannot write (a tuple, an object: printed, it could carry a secret), or
                # two keys that write as the same text (1 and "1": one would silently replace the
                # other): the argument cannot be read as it was, so it is withheld whole (`_kept`).
                walk["unreadable"] = True
                return out
            written_keys.add(key_text)
            if walk["stopped"] or _spent(walk, _key_len(k)):
                walk["left_out"] = True             # this entry, and any after it, are not written
                break
            out[k] = _withheld_here(walk) if _withheld(k, v) else _without_secrets(v, depth + 1, walk)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        _spent(walk, 2)
        out = []
        for v in value:
            if walk["stopped"]:
                walk["left_out"] = True
                break
            if isinstance(v, (list, tuple)) and len(v) == 2 and isinstance(v[0], str) and _withheld(v[0], v[1]):
                _spent(walk, len(v[0]) + 4)         # ["name", ] around it
                out.append([v[0], _withheld_here(walk)])
            else:
                out.append(_without_secrets(v, depth + 1, walk))
        return out
    if isinstance(value, str):                      # _plain's text for it, or "[withheld]"
        return _scalar(value, walk)
    return value


def _kept(name, value):
    if _withheld(name, value):
        return WITHHELD
    if value is None or isinstance(value, (bool, int, float)):
        try:
            text = json.dumps(value)
        except Exception:                           # an int too long to print would fail the line
            return WITHHELD
        if len(text) <= _MAX_VALUE_CHARS:
            return value
        # A number past the limit is cut like any long value (README: "cut at 1,000 characters").
        return text[:_MAX_VALUE_CHARS] + " [cut: %d characters in all]" % len(text)
    if isinstance(value, str):
        text = value                                # nothing inside to withhold; its length is known
    else:
        walk = _new_walk()
        value = _without_secrets(value, walk=walk)
        if walk.get("unreadable"):
            return WITHHELD
        text = None
        if isinstance(value, (dict, list)):
            try:
                text = json.dumps(value, ensure_ascii=False, default=str)
            except Exception:
                pass
            else:
                if not walk["left_out"] and len(text) <= _MAX_VALUE_CHARS:
                    return json.loads(text)
        if text is None:
            try:
                text = str(value)
            except Exception:                       # e.g. an int too long to print: not kept, and
                return WITHHELD                     # never the whole call's line lost with it
        if walk["left_out"]:
            # The walk left part of it out because the value is over the limit: marked cut, never a
            # container that silently lost an entry, however it was turned into text.
            return text[:_MAX_VALUE_CHARS] + " [cut: more than %d characters in all]" % len(text)
    if len(text) > _MAX_VALUE_CHARS:
        return text[:_MAX_VALUE_CHARS] + " [cut: %d characters in all]" % len(text)
    return text


def note_call(tool, arguments, read_back=None, raised=None):
    """A protected call that ran. Written when a task is running or values are kept; otherwise
    nothing, at the cost of one lookup. `arguments` maps names to values; values are written only
    with AGENTX_KEEP_ARG_VALUES. `read_back` is what `verify=` found: "confirmed",
    "not_confirmed", "could_not_check", or None when the tool has no `verify=`. `raised` is the
    name of the error the tool raised, if it did: its work may still have landed (a text sent,
    then a timeout reading the answer), so it is a call like any other, marked."""
    later = note_call_later(tool, arguments, read_back, raised)
    if later is not None:
        write_soon(later)


def started():
    """The time a protected tool starts, for its line, or None when nothing will be written. The
    line carries the start, not the time it is written: a read-back cancelled minutes after the work
    landed would otherwise stamp the call outside its record's window."""
    try:
        if _task_var.get() or keeping_values():
            return _now()
    except Exception:
        pass
    return None


def note_call_later(tool, arguments, read_back=None, raised=None, at=None, effect=None):
    """`note_call` in two halves: the line is built now, in the caller's context (the task, the run,
    the time, the argument values as the call had them, the file), and the returned function writes
    it, so it can run on the writer thread without waiting on the event loop. `at` is when the tool
    started (`started()`); now when not given. `effect` is what the tool declared it changes
    ("books", "cancels"). None when nothing is to be written. Never raises."""
    try:
        current = _task_var.get()
        keep = keeping_values()
        if not current and not keep:
            return None
        if current:
            task_id, run = current
        else:
            task_id, run = None, _gap_run()
        args = dict(arguments or {})
        entry = {"kind": "call", "time": at or _now(), "task": task_id, "run": run,
                 "trace": _trace(), "tool": tool, "arg_names": sorted(str(k) for k in args)}
        if effect in EFFECTS:
            entry["effect"] = effect
        if keep:
            # The values now: an agent that reuses one argument object and changes it for its next
            # call would otherwise have the changed value recorded for this one.
            entry["args"] = {str(k): _kept(k, v) for k, v in args.items()}
        if read_back is not None:
            entry["read_back"] = read_back
        if raised:
            entry["raised"] = str(raised)
        target = path()
    except Exception:
        return None

    def finish():
        _write(entry, target)
    return finish


def read(file_path=None):
    """Every entry in the file, oldest first; [] when there is none. A line that is not JSON is
    skipped, never fatal: the file is appended to by running agents. Lines this process handed to
    the writer are written first (`flush`)."""
    flush()
    target = file_path or path()
    out = []
    try:
        with open(target, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict):
                    out.append(entry)
    except (OSError, UnicodeDecodeError):
        return []
    return out
