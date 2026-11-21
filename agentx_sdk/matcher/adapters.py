"""Reading the three inputs, and the plug-in registry for readers and checks.

The generic reader takes CSV, JSON (a list, or an object holding one list) or JSON Lines. It finds
its columns by common names; a mapping file (`--map`) names them when the names differ. Other
readers and checks are plug-ins: a package registers them under the `agentx.adapters` or
`agentx.checks` entry-point group and `agentx match` finds them, with no change here.

An adapter is a callable `adapter(path, mapping) -> dict` returning any of the keys "tasks",
"runs", "records", each a list of core objects. A check is a callable `check(context) -> list`
of `core.Item`, where `context` has `tasks`, `runs`, `records`, `result` and `settings`.
"""
import csv
import io
import json
import os
import re

from . import core

ADAPTER_GROUP = "agentx.adapters"
CHECK_GROUP = "agentx.checks"

# Common column names, tried in order. A mapping file overrides any of them.
TASK_COLUMNS = {
    # a bare "id" last: in a file that also has a named id column, "id" is usually a row's own
    "id": ("task_id", "ticket_id", "ticket", "request_id", "id"),
    "time": ("time_utc", "time", "timestamp", "created_at", "created", "requested_at", "date"),
    "text": ("request", "text", "task", "body", "message", "description", "subject"),
}
LOG_COLUMNS = {
    "run_id": ("run_id", "session_id", "session", "trace_id", "id"),
    "task_id": ("task_id", "ticket_id", "ticket", "request_id"),
    "time": ("started_utc", "started_at", "start_time", "time", "timestamp", "started", "start"),
    "calls": ("tool_calls", "calls", "steps", "actions"),
    "tool": ("tool", "tool_name", "name", "function"),
    "args": ("args", "arguments", "input", "params", "parameters"),
    "reply": ("final_message", "final_reply", "reply", "output", "response", "answer"),
}
RECORD_COLUMNS = {
    "id": ("change_id", "event_id", "history_id", "id"),
    "time": ("time_local", "time_utc", "time", "timestamp", "changed_at", "updated_at", "date"),
    "entity_id": ("record_id", "object_id", "entity_id", "contact_id"),
    "entity_name": ("record_name", "object_name", "entity_name", "contact_name", "name"),
    "field": ("field", "property", "property_name", "attribute"),
    "old": ("old", "old_value", "previous", "previous_value", "before", "from"),
    "new": ("new", "new_value", "value", "after", "to"),
    "actor": ("changed_by", "updated_by", "actor", "user", "author", "source"),
}


class InputError(Exception):
    """A file the matcher cannot read, said in words a person can act on."""


def _key(name):
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def read_text(path):
    """A file's text, or an InputError a person can act on."""
    if not os.path.exists(path):
        raise InputError("%s: no such file" % path)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise InputError("%s could not be read: %s" % (path, e.strerror or e))
    return raw.decode("utf-8-sig", errors="replace")


def read_rows(path):
    """A list of dicts from a CSV, JSON or JSON Lines file."""
    text = read_text(path)
    stripped = text.lstrip()
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jsonl", ".ndjson") or (ext != ".json" and stripped.startswith("{") and "\n{" in stripped):
        rows = []
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except ValueError as e:
                    raise InputError("%s line %d is not JSON: %s" % (path, n, e))
        return rows
    if ext == ".json" or stripped.startswith(("[", "{")):
        try:
            data = json.loads(text)
        except ValueError as e:
            lines = _json_lines(text)          # JSON Lines saved under a .json name
            if lines is not None:
                return lines
            raise InputError("%s is not JSON: %s" % (path, e))
        if isinstance(data, dict):
            # One run (a log of one run holds its list of calls: tool_calls, steps, ...) or a wrapper
            # around the rows ({"id": "export-1", "tickets": [...]}, {"start": 0, "messages": [...]}).
            # Only a calls list says "one run"; no other key is guessed at.
            if any(_key(k) in LOG_COLUMNS["calls"] and isinstance(v, list) for k, v in data.items()):
                return [data]
            lists = [v for v in data.values() if isinstance(v, list) and any(isinstance(x, dict) for x in v)]
            if len(lists) != 1:
                raise InputError("%s: expected a list of rows, or an object holding one list of rows" % path)
            data = lists[0]
        if not isinstance(data, list):
            raise InputError("%s: expected a list of rows" % path)
        return [r for r in data if isinstance(r, dict)]
    return list(csv.DictReader(io.StringIO(text)))


def _json_lines(text):
    """Rows when every non-empty line is a JSON object, else None."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            return None
        if not isinstance(row, dict):
            return None
        rows.append(row)
    return rows or None


def _columns(rows, wanted, given, path, required):
    """Map each wanted name to a column of these rows: the mapping file's name first, then the
    common names."""
    present = {}
    for r in rows[:50]:
        for k in r:
            present.setdefault(_key(k), k)
    out = {}
    for name, options in wanted.items():
        if given and given.get(name):
            col = given[name]
            if _key(col) not in present and rows:
                raise InputError("%s: the mapping names column %r for %s, and the file has no such "
                                 "column (it has: %s)" % (path, col, name, ", ".join(sorted(present.values()))))
            out[name] = present.get(_key(col), col)
            continue
        for opt in options:
            if opt in present and present[opt] not in out.values():
                out[name] = present[opt]
                break
    if "time" in wanted and "time" not in out and not (given and given.get("time")):
        sniffed = _time_column(rows, [c for c in present.values() if c not in out.values()])
        if sniffed:
            out["time"] = sniffed
    missing = [n for n in required if n not in out]
    if missing and rows:
        raise InputError("%s: could not find the column for %s (it has: %s). Name it in a mapping "
                         "file with --map." % (path, " and ".join(missing), ", ".join(sorted(present.values()))))
    return out


def _time_column(rows, candidates):
    """The one column whose values read as date and time, when no column has a known time name.
    Two such columns is a guess this does not make."""
    hits = []
    sample = rows[:50]
    for col in candidates:
        vals = [r.get(col) for r in sample if r.get(col) not in (None, "")]
        if not vals or not all(isinstance(v, str) and ":" in v for v in vals):
            continue
        if all(core.parse_time(v) is not None for v in vals):
            hits.append(col)
    return hits[0] if len(hits) == 1 else None


def _get(row, cols, name):
    col = cols.get(name)
    return row.get(col) if col else None


def _tz(mapping):
    if not mapping or mapping.get("tz") in (None, ""):
        return None
    tz = core.parse_offset(mapping.get("tz"))
    if tz is None:
        raise InputError("time zone %r in the mapping: write it as UTC, +05:30 or -05:00" % mapping.get("tz"))
    return tz


def read_tasks(path, mapping=None):
    rows = read_rows(path)
    cols = _columns(rows, TASK_COLUMNS, mapping, path, ("id",))
    tz = _tz(mapping)
    out = []
    for r in rows:
        tid = _get(r, cols, "id")
        if tid in (None, ""):
            continue
        out.append(core.Task(str(tid), core.parse_time(_get(r, cols, "time"), tz if tz is not None else core.parse_offset("UTC")),
                             _get(r, cols, "text") or "", r))
    return out


def _args(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            v = json.loads(value)
            return v if isinstance(v, dict) else {}
        except ValueError:
            return {}
    return {}


def read_runs(path, mapping=None):
    """Runs from a log. Two shapes: one row per run holding a list of its calls, or one row per
    call carrying its run's id (calls of one run are grouped)."""
    rows = read_rows(path)
    cols = _columns(rows, LOG_COLUMNS, mapping, path, ())
    tz = _tz(mapping)
    utc = tz if tz is not None else core.parse_offset("UTC")
    calls_col = cols.get("calls")
    runs = []
    # Nested only when the column really holds lists: in a CSV every cell is text, and a column named
    # "actions" may hold a count or a word.
    if calls_col and any(_call_list(r.get(calls_col)) is not None for r in rows):
        for n, r in enumerate(rows):
            raw_calls = _call_list(r.get(calls_col)) or []
            calls = []
            for c in raw_calls or []:
                if not isinstance(c, dict):
                    continue
                ckeys = {_key(k): k for k in c}
                tool = next((c[ckeys[o]] for o in LOG_COLUMNS["tool"] if o in ckeys), None)
                args = next((c[ckeys[o]] for o in LOG_COLUMNS["args"] if o in ckeys), None)
                ctime = next((c[ckeys[o]] for o in ("time", "timestamp", "at") if o in ckeys), None)
                call = core.Call(tool, _args(args), core.parse_time(ctime, utc))
                call.clock_assumed = core.clock_assumed(ctime, tz is not None)
                calls.append(call)
            rid = _get(r, cols, "run_id")
            runs.append(core.Run(str(rid) if rid not in (None, "") else "run-%d" % (n + 1),
                                 _str_or_none(_get(r, cols, "task_id")),
                                 core.parse_time(_get(r, cols, "time"), utc), calls,
                                 _get(r, cols, "reply") or "", r))
            runs[-1].clock_assumed = core.clock_assumed(_get(r, cols, "time"), tz is not None)
        return runs
    if "tool" not in cols:
        raise InputError("%s: found neither a list of calls per run nor a tool column per row. Name "
                         "them in a mapping file with --map." % path)
    # A session that handles several tasks is several runs: rows of one run id that name different
    # task ids are split by task id.
    tasks_of = {}
    for n, r in enumerate(rows):
        rid = _get(r, cols, "run_id")
        tasks_of.setdefault(str(rid) if rid not in (None, "") else "run-%d" % (n + 1), set()).add(
            _str_or_none(_get(r, cols, "task_id")))
    grouped = {}
    order = []
    last_task = {}          # session -> the task of its latest row that named one
    for n, r in enumerate(rows):
        rid = _get(r, cols, "run_id")
        rid = str(rid) if rid not in (None, "") else "run-%d" % (n + 1)
        task = _str_or_none(_get(r, cols, "task_id"))
        if len(tasks_of[rid] - {None}) > 1:
            # A row with no task id (a final reply, a note) belongs to the task the session was on.
            task = _str_or_none(_get(r, cols, "task_id")) or last_task.get(rid)
            if task is None:
                task = next(_str_or_none(_get(x, cols, "task_id")) for x in rows[n:]
                            if (str(_get(x, cols, "run_id")) == rid and _str_or_none(_get(x, cols, "task_id"))))
            last_task[rid] = task
            rid = "%s/%s" % (rid, task)
        if rid not in grouped:
            grouped[rid] = {"task": task,
                            "time": core.parse_time(_get(r, cols, "time"), utc), "calls": [], "reply": "", "raw": r,
                            "clock_assumed": core.clock_assumed(_get(r, cols, "time"), tz is not None)}
            order.append(rid)
        g = grouped[rid]
        tool = _get(r, cols, "tool")
        if tool not in (None, ""):
            call = core.Call(tool, _args(_get(r, cols, "args")), core.parse_time(_get(r, cols, "time"), utc))
            call.clock_assumed = core.clock_assumed(_get(r, cols, "time"), tz is not None)
            g["calls"].append(call)
        reply = _get(r, cols, "reply")
        if reply:
            g["reply"] = reply
    runs = [core.Run(rid, grouped[rid]["task"], grouped[rid]["time"], grouped[rid]["calls"], grouped[rid]["reply"],
                     grouped[rid]["raw"]) for rid in order]
    for run, rid in zip(runs, order):
        run.clock_assumed = grouped[rid]["clock_assumed"]
    return runs


def _call_list(value):
    """A cell's list of calls: a list, or text holding a JSON list. Anything else is None."""
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value.strip().startswith("["):
        try:
            v = json.loads(value)
        except ValueError:
            return None
        return v if isinstance(v, list) else None
    return None


def _str_or_none(v):
    return None if v in (None, "") else str(v)


def read_records(path, mapping=None):
    rows = read_rows(path)
    cols = _columns(rows, RECORD_COLUMNS, mapping, path, ("entity_id", "new"))
    tz = _tz(mapping)
    out = []
    for n, r in enumerate(rows):
        rid = _get(r, cols, "id")
        out.append(core.Record(str(rid) if rid not in (None, "") else "row-%d" % (n + 2),
                               core.parse_time(_get(r, cols, "time"), tz),
                               _str_or_none(_get(r, cols, "entity_id")), _get(r, cols, "entity_name"),
                               _get(r, cols, "field"), _get(r, cols, "old"), _get(r, cols, "new"),
                               _str_or_none(_get(r, cols, "actor")), r))
    return out


def generic(path, mapping=None, kind="records"):
    """The built-in reader: any CSV or JSON file, by column names or a mapping."""
    reader = {"tasks": read_tasks, "runs": read_runs, "records": read_records}[kind]
    return {kind: reader(path, mapping)}


from . import calendar as _calendar  # noqa: E402  (after the readers it uses)
from . import twilio as _twilio  # noqa: E402

BUILT_IN_ADAPTERS = {"generic": generic, "ics": _calendar.ics_adapter, "twilio": _twilio.twilio_adapter}
# A check returns None when the records hold nothing it reads (no calendar events, say), and a
# list (perhaps empty) when it ran: the report says which checks ran.
BUILT_IN_CHECKS = {"double_booked": _calendar.double_booked, "booked_twice": _calendar.booked_twice,
                   "failed_delivery": _twilio.failed_delivery, "texted_twice": _twilio.texted_twice,
                   "outside_hours": _twilio.outside_hours}


def sniff(path):
    """The built-in reader a records file needs, by its name or its columns: "ics", "twilio" or
    "generic". Never raises: a file it cannot open is left to the reader to report."""
    if str(path).lower().endswith((".ics", ".ical", ".ifb")):
        return "ics"
    try:
        rows = read_rows(path)
    except Exception:
        return "generic"
    return "twilio" if rows and _twilio.looks_like_twilio(rows[0].keys()) else "generic"


def _entry_points(group):
    """Entry points of a group, on every Python this package supports."""
    try:
        from importlib import metadata
    except ImportError:          # pragma: no cover - Python 3.8 always has it
        return []
    try:
        eps = metadata.entry_points()
    except Exception:
        return []
    if hasattr(eps, "select"):
        return list(eps.select(group=group))
    return list(eps.get(group, []))          # Python 3.8 and 3.9: a dict of lists


def load_plugins(group, built_in):
    """Built-ins plus whatever installed packages register. A plug-in that fails to load is
    reported, never fatal, and never replaces a built-in of the same name."""
    found = dict(built_in)
    problems = []
    for ep in _entry_points(group):
        if ep.name in found:
            problems.append("%s: plug-in %r has the name of one already loaded; skipped" % (group, ep.name))
            continue
        try:
            found[ep.name] = ep.load()
        except Exception as e:
            problems.append("%s: plug-in %r did not load (%s)" % (group, ep.name, e))
    return found, problems
