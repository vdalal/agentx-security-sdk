"""The matcher's core: what the person asked, what the agent did and said, and what the records show.

Three inputs, each optional except the records:

* tasks:   what someone asked the agent to do (an id, a time, the words);
* runs:    what the agent did (its tool calls) and said (its last reply), one run per task;
* records: what the system of record shows changed (a change history, one row per change).

The core joins them and sorts what does not line up into five lists, plus a list of things it
could not decide. It never reads the task's words as instructions: without a model it cannot
know that "move Lea to Won" means stage = Won. It compares the record with the agent's CALL,
which is structured, and says so in the list's name.

Nothing here touches the network.
"""
import re
from datetime import datetime, timedelta, timezone

# The five lists, in the order the report prints them. The keys are the JSON names; the titles
# are what a person reads.
LIST_CLAIM_NO_RECORD = "claim_no_record"
LIST_DUPLICATE = "duplicate"
LIST_DIFFERS_FROM_CALL = "differs_from_call"
LIST_UNASKED_CHANGE = "unasked_change"
LIST_TASK_NO_RUN = "task_no_run"

LISTS = (
    (LIST_CLAIM_NO_RECORD, "Said it was done, but no record shows it"),
    (LIST_DUPLICATE, "Done twice"),
    (LIST_DIFFERS_FROM_CALL, "The record differs from what the agent's call asked for"),
    (LIST_UNASKED_CHANGE, "Changed by the agent's account, with no call in the log behind it"),
    (LIST_TASK_NO_RUN, "Asked, but the agent never ran it"),
)

# How far after a call its record may land, and how far before (clocks disagree a little).
DEFAULT_WINDOW_MINUTES = 30
_EARLY_SLACK = timedelta(minutes=5)

# Tools whose name says they only read. A run made only of these changed nothing.
_READ_VERBS = ("get", "list", "search", "read", "find", "fetch", "lookup", "look_up", "check",
               "query", "view", "show", "describe", "count")


class MatchStop(Exception):
    """The files can be read but the run would only mislead: said in words, and the run stops."""


class Task(object):
    def __init__(self, id, time=None, text="", raw=None):
        self.id, self.time, self.text, self.raw = id, time, text or "", raw or {}


class Call(object):
    def __init__(self, tool, args=None, time=None, run=None, index=0):
        self.tool, self.args, self.time, self.run, self.index = tool, dict(args or {}), time, run, index
        self.entity = None          # the record id this call is about, once found
        self.entity_by = None       # "id" or "name": how it was found
        self.entity_arg = None      # which argument named it
        self.time_from_run = False  # True when `time` is its run's start, the call having none
        # Argument names whose value the log did not keep whole ("[withheld]", cut short): left out
        # of `args`, so never compared, and shown to the reader as they were written.
        self.unknown_args = {}


class Run(object):
    def __init__(self, id, task_id=None, time=None, calls=None, reply="", raw=None, untasked=False):
        self.id, self.task_id, self.time, self.reply, self.raw = id, task_id, time, reply or "", raw or {}
        # True when the reader knows the run belongs to no task (the SDK's own calls made between
        # tasks): never linked to a task by time, and never one task's missing run.
        self.untasked = untasked
        self.calls = []
        for i, c in enumerate(calls or []):
            c.run, c.index = self, i
            if c.time is None and time is not None:
                c.time = time
                c.time_from_run = True
            self.calls.append(c)


class Record(object):
    """One row of what the system shows changed. `kind` is set by the READER that made it ("event" for a
    calendar event, "message" for a text), never read from the data: a change history whose field
    column says "message" is still a change history."""

    def __init__(self, id, time=None, entity_id=None, entity_name=None, field=None, old=None, new=None,
                 actor=None, raw=None, kind=None):
        self.id, self.time, self.entity_id, self.entity_name = id, time, entity_id, entity_name
        self.field, self.old, self.new, self.actor, self.raw = field, old, new, actor, raw or {}
        self.kind = kind
        self.utc = None             # the record's time on the calls' clock, once the offset is known


class Item(object):
    """One entry on a list: what it is about, the rows that show it, and why."""

    def __init__(self, list_key, reason, task=None, run=None, call=None, records=(), unsure=False):
        self.list_key, self.reason, self.task, self.run, self.call = list_key, reason, task, run, call
        self.records, self.unsure = list(records), unsure

    def to_dict(self):
        out = {"list": self.list_key, "reason": self.reason}
        if self.task is not None:
            out["task"] = {"id": self.task.id, "text": self.task.text}
        if self.run is not None:
            out["run"] = {"id": self.run.id, "reply": self.run.reply}
        if self.call is not None:
            out["call"] = {"tool": self.call.tool,
                           "args": _jsonable(dict(self.call.args, **self.call.unknown_args))}
            if getattr(self.call, "raised", None):
                out["call"]["raised"] = self.call.raised
        if self.records:
            out["records"] = [_record_dict(r) for r in self.records]
        return out


def _jsonable(v):
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def _record_dict(r):
    out = {"id": r.id, "time": r.time.isoformat() if r.time else None, "record": r.entity_id,
           "name": r.entity_name, "field": r.field, "old": r.old, "new": r.new, "by": r.actor}
    if r.kind == "event":
        x = r.raw
        out.update({"start": x["start"].isoformat() if hasattr(x.get("start"), "isoformat") else None,
                    "end": x["end"].isoformat() if hasattr(x.get("end"), "isoformat") else None,
                    "attendees": list(x.get("attendees") or []), "status": x.get("status"),
                    "summary": x.get("summary")})
    return out


# --- values ----------------------------------------------------------------------------------

_NUMBER = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
_TIME_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


def norm(value):
    """A value in a form two sources can be compared in.

    Numbers compare as numbers ("$4,000" == "4000" == 4000.0). One token with a digit in it is an
    id or a code ("C108", "AbC123", "cus_9x"): it must match exactly, letter case included.
    Anything else is words (a stage, a status, a name, "Pro 2"): letter case and repeated spaces
    are ignored, so "Won" and "won" are one value."""
    if value is None:
        return ("empty", "")
    if isinstance(value, bool):
        return ("word", str(value).lower())
    if isinstance(value, (int, float)):
        return ("num", float(value))
    s = str(value).strip()
    if not s:
        return ("empty", "")
    if _TIME_LIKE.match(s):
        # A date and time that states its zone is a moment: "2026-11-26T14:00:00-05:00" and
        # "2026-11-26T19:00:00Z" are one value. One without a zone stays text: its moment is unknown.
        t = parse_time(s)
        if t is not None and t.tzinfo is not None:
            return ("time", t.isoformat())
    bare = s.replace(",", "").replace("$", "").replace(" ", "")
    if _NUMBER.match(bare):
        return ("num", float(bare))
    if any(ch.isdigit() for ch in s) and len(s.split()) == 1:
        return ("exact", s)
    return ("word", " ".join(s.split()).casefold())


def same(a, b):
    return norm(a) == norm(b)


def _is_scalar(v):
    return v is None or isinstance(v, (str, int, float, bool))


# --- times -----------------------------------------------------------------------------------

_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M",
            "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%d %b %Y %H:%M:%S", "%a, %d %b %Y %H:%M:%S")


def parse_time(value, tz=None):
    """A datetime in UTC, or None. `tz` is the zone of a time written without one (a timedelta
    from UTC, or None for "not known yet": such a time is returned naive)."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.match(r"^\d{9,}(\.\d+)?$", value.strip())):
        return _from_epoch(float(value))
    s = str(value).strip()
    if not s:
        return None
    # A zone written at the end: Z, UTC, GMT, +0500, -05:00. Kept, and applied after parsing.
    stated = None
    m = re.search(r"(?:\s*(?:UTC|GMT|Z)|\s*([+-])(\d{2}):?(\d{2}))$", s, re.IGNORECASE)
    if m and re.search(r"\d", s[:m.start()] or ""):
        if m.group(1):
            sign = 1 if m.group(1) == "+" else -1
            stated = sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
        else:
            stated = timedelta(0)
        body = s[:m.start()].strip()
    else:
        body = s
    dt = None
    try:
        dt = datetime.fromisoformat(body)
    except ValueError:
        for fmt in _FORMATS:
            try:
                dt = datetime.strptime(body, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc)
    if stated is not None:
        return (dt - stated).replace(tzinfo=timezone.utc)
    if tz is None:
        return dt
    return (dt - tz).replace(tzinfo=timezone.utc)


def clock_assumed(raw, tz_given):
    """True when a log time was written without its zone and no zone was given for the log: the
    reader takes it as UTC, which is a guess. A check that needs the call's real moment (a calendar's
    CREATED) treats such a time as unsure."""
    if tz_given or raw in (None, ""):
        return False
    t = parse_time(raw)
    return t is not None and t.tzinfo is None


def _from_epoch(n):
    """Seconds, milliseconds or microseconds since 1970, told apart by size."""
    if n > 1e14:
        n /= 1e6
    elif n > 1e11:
        n /= 1e3
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def parse_offset(text):
    """ "UTC", "+05:30", "-05:00", "-5" -> timedelta; anything else -> None."""
    if text is None:
        return None
    s = str(text).strip().upper()
    if s in ("UTC", "GMT", "Z", "0", "+0", "-0"):
        return timedelta(0)
    m = re.match(r"^(?:UTC|GMT)?([+-])(\d{1,2})(?::?(\d{2}))?$", s)
    if not m:
        return None
    sign = 1 if m.group(1) == "+" else -1
    return sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))


def offset_label(delta):
    if delta is None:
        return "unknown"
    mins = int(delta.total_seconds() // 60)
    if mins == 0:
        return "UTC"
    sign = "+" if mins > 0 else "-"
    mins = abs(mins)
    return "UTC%s%02d:%02d" % (sign, mins // 60, mins % 60)


def _as_utc(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


# --- the match -------------------------------------------------------------------------------

class Settings(object):
    def __init__(self, agent_account=None, records_tz=None, window_minutes=DEFAULT_WINDOW_MINUTES,
                 read_tools=()):
        self.agent_account = agent_account
        self.records_tz = records_tz            # timedelta, or None to infer
        self.window = timedelta(minutes=window_minutes)
        self.read_tools = set(read_tools or ())


class Result(object):
    def __init__(self):
        self.items = []
        self.inferred = {}
        self.counts = {}
        self.not_checked = {}       # list key -> why it could not be made
        self.notes = []
        self.checks_ran = []        # (name, title) of each check that found something to read
        self.checks_failed = []     # (name, title, why) of each check that broke before it finished
        self.records_kind = None    # "calendar" when the records are a calendar file

    def on(self, key):
        return [i for i in self.items if i.list_key == key and not i.unsure]

    def unsure(self):
        return [i for i in self.items if i.unsure]


def name_words(tool):
    """A tool's name as lower-case words, however it is written: snake_case, camelCase, dotted, an
    MCP server prefix (mcp__google_calendar__delete_event), digits between words."""
    return [w.lower() for w in re.split(r"[_\W\d]+|(?<=[a-z])(?=[A-Z])", str(tool or "")) if w]


def is_read_tool(tool, read_tools=()):
    if tool in read_tools:
        return True
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", str(tool or "")).lower()
    head = re.split(r"[_\-.\s]", name, 1)[0]
    return head in _READ_VERBS


def _place_calls(calls, records):
    """Find the record each call is about: by an argument equal to a record id (exact), else by
    an argument equal to a record's name (letter case ignored). A name two records share is left
    unplaced."""
    ids = {}
    names = {}
    for r in records:
        if r.entity_id not in (None, ""):
            ids[str(r.entity_id)] = r.entity_id
            if r.entity_name:
                names.setdefault(norm(r.entity_name), set()).add(r.entity_id)
    for c in calls:
        hit = None
        # an argument whose name says id is tried first
        keys = sorted(c.args, key=lambda k: (0 if str(k).lower().endswith("id") else 1, str(k)))
        for k in keys:
            v = c.args[k]
            if _is_scalar(v) and v is not None and str(v) in ids:
                hit = (ids[str(v)], "id", k)
                break
        if hit is None:
            for k in keys:
                v = c.args[k]
                if isinstance(v, str) and norm(v)[0] == "word" and norm(v) in names:
                    found = names[norm(v)]
                    if len(found) == 1:
                        hit = (next(iter(found)), "name", k)
                        break
        if hit:
            c.entity, c.entity_by, c.entity_arg = hit


def _in_window(call, rec_utc, window):
    if call.time is None or rec_utc is None:
        return False
    t = _as_utc(call.time)
    return t - _EARLY_SLACK <= rec_utc <= t + window


def _value_args(call):
    return {k: v for k, v in call.args.items() if k != call.entity_arg and _is_scalar(v) and v not in (None, "")}


def _pairs(calls, records, window, shift):
    """(call, arg, record) where the record is on the call's record, inside the window under this
    clock shift, and its new value equals one of the call's arguments."""
    by_entity = {}
    for r in records:
        by_entity.setdefault(r.entity_id, []).append(r)
    out = []
    for c in calls:
        if c.entity is None:
            continue
        for r in by_entity.get(c.entity, ()):
            rt = _shifted(r, shift)
            if not _in_window(c, rt, window):
                continue
            for k, v in _value_args(c).items():
                if same(v, r.new):
                    out.append((c, k, r))
    return out


def _shifted(record, shift):
    if record.time is None:
        return None
    if record.time.tzinfo is not None:
        return record.time
    return (record.time - shift).replace(tzinfo=timezone.utc)


def _candidate_shifts():
    for half_hours in range(-24, 29):
        yield timedelta(minutes=30 * half_hours)


def infer_records_offset(calls, records, window):
    """The clock offset of the records' naive times that lines the most calls up with records.
    Ties go to the smaller offset. Returns (offset, pairs found at it)."""
    if not any(r.time is not None and r.time.tzinfo is None for r in records):
        return timedelta(0), None
    best, best_n = timedelta(0), -1
    for shift in sorted(_candidate_shifts(), key=lambda d: abs(d.total_seconds())):
        n = len({(id(c), id(r)) for c, _k, r in _pairs(calls, records, window, shift)})
        if n > best_n:
            best, best_n = shift, n
    return best, best_n


def infer_agent_account(pairs):
    votes = {}
    for _c, _k, r in pairs:
        if r.actor not in (None, ""):
            votes[r.actor] = votes.get(r.actor, 0) + 1
    if not votes:
        return None
    return sorted(votes.items(), key=lambda kv: (-kv[1], str(kv[0])))[0][0]


def learn_fields(pairs):
    """Which record field each (tool, argument) writes, by vote over the calls whose value
    turned up in a record."""
    votes = {}
    for c, k, r in pairs:
        key = (c.tool, k)
        votes.setdefault(key, {})
        votes[key][r.field] = votes[key].get(r.field, 0) + 1
    out = {}
    for key, fields in votes.items():
        out[key] = sorted(fields.items(), key=lambda kv: (-kv[1], str(kv[0])))[0][0]
    return out


def match(tasks, runs, records, settings=None):
    """Join the three inputs and sort what does not line up. `tasks` and `runs` may be None (not
    given); the lists that need them are then reported as not checked."""
    s = settings or Settings()
    res = Result()
    records = list(records or [])
    calls = [c for run in (runs or []) for c in run.calls]
    write_calls = [c for c in calls if not is_read_tool(c.tool, s.read_tools)]

    _place_calls(write_calls, records)

    # The records' clock.
    if s.records_tz is not None:
        shift = s.records_tz
        res.inferred["records_time_zone"] = {"value": offset_label(shift), "how": "given"}
    elif runs:
        shift, _n = infer_records_offset(write_calls, records, s.window)
        res.inferred["records_time_zone"] = {"value": offset_label(shift), "how": "inferred"}
    else:
        shift = timedelta(0)
        res.inferred["records_time_zone"] = {"value": "UTC", "how": "assumed"}
    for r in records:
        r.utc = _shifted(r, shift)

    pairs = _pairs(write_calls, records, s.window, shift)

    # The agent's account.
    account = s.agent_account
    if account is not None:
        res.inferred["agent_account"] = {"value": account, "how": "given"}
    else:
        account = infer_agent_account(pairs)
        res.inferred["agent_account"] = {"value": account, "how": "inferred" if account else "unknown"}
    has_actor = any(r.actor not in (None, "") for r in records)
    if account is not None and has_actor:
        # As text: a reader may hand over a number (a user id) and the account is always typed as text.
        mine = [r for r in records if str(r.actor) == str(account)]
        others = [r for r in records if str(r.actor) != str(account)]
    else:
        mine, others = records, []
    if account is not None and has_actor and not mine:
        # A typed account with no change of its own, while another account's changes line up with
        # the agent's calls, is most likely the wrong name (an email for a display name): stop and
        # say so. With no other account lining up, it is a quiet week, and that is said instead.
        other = infer_agent_account(pairs)
        if other is not None and str(other) != str(account):
            n = len({id(c) for c, _k, r in pairs if r.actor == other})
            raise MatchStop("the agent's account %r made no change in these records, but the changes of "
                            "%r line up with %d of the agent's calls. If that is the agent, run again with "
                            "--agent-account %s" % (account, other, n, other))
        res.notes.append("The agent's account (%s) made no change in these records." % account)
    res.counts["records"] = len(records)
    res.counts["events"] = sum(1 for r in records if r.kind == "event")
    res.counts["messages"] = sum(1 for r in records if r.kind == "message")
    res.counts["records_by_agent"] = len(mine)
    res.counts["records_by_others"] = len(others)
    other_actors = sorted({str(r.actor) for r in others if r.actor not in (None, "")})
    res.inferred["other_accounts"] = other_actors

    pairs = [(c, k, r) for c, k, r in pairs if r in set(mine)] if others else pairs
    fields = learn_fields(pairs)
    res.inferred["fields"] = ["%s.%s -> %s" % (t, a, f) for (t, a), f in sorted(fields.items(), key=str)]

    if tasks and runs:
        linked = link_runs_to_tasks(tasks, runs, records)
        if linked:
            res.inferred["runs_linked_to_tasks"] = linked
    task_by_id = {t.id: t for t in (tasks or [])}
    res.counts["tasks"] = len(tasks or [])
    res.counts["runs"] = len(runs or [])
    res.counts["calls"] = len(calls)

    if runs is None:
        for key in (LIST_CLAIM_NO_RECORD, LIST_DUPLICATE, LIST_DIFFERS_FROM_CALL, LIST_UNASKED_CHANGE):
            res.not_checked[key] = "needs the agent's log"
        if tasks is None:
            res.not_checked[LIST_TASK_NO_RUN] = "needs the tasks and the agent's log"
        else:
            res.not_checked[LIST_TASK_NO_RUN] = "needs the agent's log"
        return res

    claimed = set()

    def task_of(run):
        return task_by_id.get(run.task_id)

    def near(c):
        found = [r for r in mine if r.entity_id == c.entity and r not in claimed and _in_window(c, r.utc, s.window)]
        found.sort(key=lambda r: abs((r.utc - _as_utc(c.time)).total_seconds()))
        return found

    ordered = sorted(write_calls, key=lambda c: (_as_utc(c.time) or datetime.min.replace(tzinfo=timezone.utc), c.run.id, c.index))
    outcome, wanted_of = {}, {}
    for c in ordered:
        if c.entity is None:
            outcome[id(c)] = ("unplaced",)
            continue
        wanted_of[id(c)] = [(k, fields[(c.tool, k)]) for k in _value_args(c) if (c.tool, k) in fields]
        if not wanted_of[id(c)]:
            outcome[id(c)] = ("unknown_field", [])

    # ONE RULE for which record belongs to which call. Every (call, field, record) that could go
    # together is weighed at once, field by field: a record goes to the NEAREST call that asked for
    # its field, exact matches before differing ones, and a record within reach of a call this file
    # cannot judge never goes to a confident list as a difference. Matching call by call, in time
    # order, handed a later call's record to an earlier call; this cannot.
    judged = [c for c in ordered if id(c) not in outcome]
    unplaced = [c for c in ordered if outcome.get(id(c), ("",))[0] == "unplaced"]
    unknown = [c for c in ordered if outcome.get(id(c), ("",))[0] == "unknown_field"]

    def gap(c, r):
        return abs((r.utc - _as_utc(c.time)).total_seconds())

    def undecidable(r):
        """In reach of a call that names no record this file has, or of one whose field is unknown."""
        return any(_in_window(u, r.utc, s.window) for u in unplaced) or \
            any(u.entity == r.entity_id and _in_window(u, r.utc, s.window) for u in unknown)

    cands = []
    for n, c in enumerate(judged):
        for k, f in wanted_of[id(c)]:
            for r in mine:
                if r.entity_id == c.entity and r.field == f and _in_window(c, r.utc, s.window):
                    cands.append((0 if same(c.args[k], r.new) else 1, gap(c, r), n, str(r.id), c, k, f, r))
    cands.sort(key=lambda t: t[:4])
    hits = {id(c): {} for c in judged}      # {field: record}
    diffs = {id(c): {} for c in judged}     # {field: (record, argument)}
    slots = set()

    def assign(exact_pass):
        for exact, _g, _n, _rid, c, k, f, r in cands:
            if (exact == 0) != exact_pass or r in claimed or (id(c), f) in slots:
                continue
            if not exact_pass and undecidable(r):
                continue
            claimed.add(r)
            slots.add((id(c), f))
            if exact_pass:
                hits[id(c)][f] = r
            else:
                diffs[id(c)][f] = (r, k)

    assign(True)
    # A call whose field is unknown takes the records left near it onto the unsure list with it.
    by_unknown = set()
    for c in unknown:
        found = near(c)
        claimed.update(found)
        by_unknown.update(found)
        outcome[id(c)] = ("unknown_field", found)
    assign(False)
    for c in judged:
        if diffs[id(c)] or hits[id(c)]:
            outcome[id(c)] = ("differs",) if diffs[id(c)] else ("matched",)
            continue
        # The call's field changed nearby, but only in records the rule above holds back (a call
        # this file cannot judge was near them too). That is not "no record": the call goes to
        # unsure with those records, never to list 1 (a booking rescheduled, then a text sent).
        held = []
        for exact, _g, _n, _rid, c2, _k, _f, r in cands:
            if c2 is c and r not in held and ((r not in claimed and undecidable(r)) or r in by_unknown):
                held.append(r)
        if held:
            claimed.update(held)
            outcome[id(c)] = ("held_back", held)
        else:
            outcome[id(c)] = ("none",)

    # The same call more than once in one run: a retry when the records show it once, the work
    # done twice when they show it more than once. "The same call" also means close in time: within
    # the window of the call before it, in every run, a task's or not. A retry or a double
    # submit comes seconds or minutes later; the same reminder sent at 09:00 and at 15:00 is two
    # pieces of work, not one done twice. The calendar and text checks hold to the same idea (booked
    # twice within 30 minutes, texted twice within an hour). A call with no time cannot be placed in
    # time, so it joins the band of the nearest timed call beside it in the log.
    repeat_of = {}
    for run in runs:
        groups = {}
        for c in run.calls:
            if id(c) in outcome and outcome[id(c)][0] in ("matched", "none", "differs"):
                # A call with a value the log did not keep whole may have differed from every other
                # call in exactly that value, so it is never "the same call" as another.
                key = ((id(c),) if c.unknown_args else
                       (c.tool, tuple(sorted((str(k), repr(norm(v))) for k, v in c.args.items()))))
                groups.setdefault(key, []).append(c)

        def own_time(c):
            """The call's own time; None when it had none (one filled from its run's start does
            not place it among the run's calls)."""
            return None if c.time_from_run else c.time

        banded = []
        for alike in groups.values():
            # The timed calls in time order, whatever order the log wrote them in (merged workers
            # write out of order), each band measured from the call before it.
            timed = sorted((c for c in alike if own_time(c) is not None),
                           key=lambda c: (_as_utc(c.time), c.index))
            bands, band_of = [], {}
            # Where each call stands in time, for the order inside its band: a timed call by its
            # start, an untimed one just before or after the timed call it was placed beside.
            place = {}
            for c in timed:
                if not bands or _as_utc(c.time) - _as_utc(bands[-1][-1].time) > s.window:
                    bands.append([])
                bands[-1].append(c)
                band_of[id(c)] = bands[-1]
                place[id(c)] = (_as_utc(c.time), c.index, 0)
            for c in alike:
                if own_time(c) is not None:
                    continue
                # The nearest timed call in log order, the earlier one first on a tie.
                near = min(timed, key=lambda t: (abs(t.index - c.index), t.index > c.index), default=None)
                if near is None:
                    if not bands:
                        bands.append([])
                    bands[-1].append(c)
                else:
                    band_of[id(near)].append(c)
                    place[id(c)] = (_as_utc(near.time), near.index,
                                    -1 if c.index < near.index else 1, c.index)
            # The call that STARTED first leads its band, not the one written first: a line is
            # written when its tool finishes, so a slow call started first is written after a quick
            # one started later. With no timed call in the group, log order is all there is.
            in_order = (lambda c: place[id(c)]) if timed else (lambda c: c.index)
            for band in bands:
                band.sort(key=in_order)
            banded.extend(bands)
        for same_calls in banded:
            if len(same_calls) < 2:
                continue
            per_field, per_diff = {}, {}
            for c in same_calls:
                for f, r in hits.get(id(c), {}).items():
                    per_field.setdefault(f, []).append(r)
                for f, rk in diffs.get(id(c), {}).items():
                    per_diff.setdefault(f, rk)
            # ONE RULE for which call of a group is reported: one that did not raise, if any. A
            # try that raised and a try that went through are the same work asked twice; reported
            # through the raised one, a plain claim would read as softened by its error. The errors
            # of the others are kept, so the item still names them.
            first = next((c for c in same_calls if not getattr(c, "raised", None)), same_calls[0])
            first.others_raised = [c.raised for c in same_calls
                                   if c is not first and getattr(c, "raised", None)]
            for c in same_calls:
                if c is not first:
                    outcome[id(c)] = ("repeat",)
            if any(len(v) >= 2 for v in per_field.values()):
                repeat_of[id(first)] = (first, len(same_calls), [r for v in per_field.values() for r in v],
                                        max(len(v) for v in per_field.values()))
                outcome[id(first)] = ("repeated_twice",)
                continue
            hits[id(first)] = {f: v[0] for f, v in per_field.items()}
            diffs[id(first)] = {f: rk for f, rk in per_diff.items() if f not in per_field}
            outcome[id(first)] = ("differs",) if diffs[id(first)] else ("matched",) if per_field else ("none",)

    # A second record of what a call already did exactly is that call done twice, whatever its other
    # fields did; unless a call this file cannot judge was in reach of it: then it goes to unsure.
    dup_of = {}
    for r in mine:
        if r in claimed or undecidable(r):
            continue
        best = None
        for c in ordered:
            if outcome.get(id(c), ("",))[0] not in ("matched", "differs"):
                continue
            first = hits[id(c)].get(r.field)
            if first is not None and c.entity == r.entity_id and same(first.new, r.new) \
                    and _in_window(c, r.utc, s.window):
                gap = abs((r.utc - _as_utc(c.time)).total_seconds())
                if best is None or gap < best[0]:
                    best = (gap, c)
        if best is not None:
            claimed.add(r)
            dup_of.setdefault(id(best[1]), (best[1], []))[1].append(r)

    # The same work in two runs: two triggers fired for one webhook, and each run made the call once
    # and matched its own record, so no run alone shows it twice. The same call (tool, record and
    # arguments) from two or more runs, each within the window of the one before, each with its own
    # record: done twice when the requests are the same, unsure when they differ (two people may
    # have asked for the same change). A call with no time of its own takes its run's start here:
    # what is compared is when the runs happened.
    across = {}
    groups = {}
    for c in ordered:
        if outcome.get(id(c), ("",))[0] != "matched" or c.unknown_args or c.time is None:
            continue
        key = (c.tool, c.entity, tuple(sorted((str(k), repr(norm(v))) for k, v in c.args.items())))
        groups.setdefault(key, []).append(c)
    for alike in groups.values():
        alike.sort(key=lambda c: (_as_utc(c.time), c.index))
        bands = []
        for c in alike:
            if not bands or _as_utc(c.time) - _as_utc(bands[-1][-1].time) > s.window:
                bands.append([])
            bands[-1].append(c)
        for band in bands:
            seen_runs, per_run = set(), []
            for c in band:                          # one call per run: a run's own repeats are above
                if id(c.run) not in seen_runs:
                    seen_runs.add(id(c.run))
                    per_run.append(c)
            if len(per_run) < 2:
                continue
            asked = [" ".join((task_of(c.run).text if task_of(c.run) else "").split()).casefold()
                     for c in per_run]
            same_request = all(asked) and len(set(asked)) == 1 and not any(c.run.untasked for c in per_run)
            first = per_run[0]
            recs = [r for c in per_run for r in hits[id(c)].values()]
            for c in per_run:                       # a second record of one run's call, said once
                recs += dup_of.pop(id(c), (None, []))[1]
            across[id(first)] = (per_run, recs, same_request)
            for c in per_run[1:]:
                outcome[id(c)] = ("repeat",)
            outcome[id(first)] = ("repeated_across",)

    # The lists.
    for c in ordered:
        o = outcome[id(c)]
        run = c.run
        task = task_of(run)
        before = len(res.items)
        # Outside any task no request says the work should have happened once: twice may be meant
        # (a reminder, a sync), so a duplicate there is unsure, never "done twice" for certain.
        outside = "Outside any task, so nothing says it should have happened once. " if run.untasked else ""
        if o[0] == "repeated_twice":
            _first, n, recs, times = repeat_of[id(c)]
            res.items.append(Item(LIST_DUPLICATE, outside + "The run made the same call %d times, and the "
                                  "records show the change %d times." % (n, times), task, run, c, recs,
                                  unsure=run.untasked))
        elif o[0] == "repeated_across":
            per_run, recs, same_request = across[id(c)]
            # The change, counted per field (a call that writes two fields makes two rows a time).
            per_field = {}
            for r in recs:
                per_field[r.field] = per_field.get(r.field, 0) + 1
            times = max(per_field.values(), default=0)
            gap = int((_as_utc(per_run[-1].time) - _as_utc(per_run[0].time)).total_seconds() // 60)
            which = ", ".join(str(x.run.task_id or x.run.id) for x in per_run)
            if same_request:
                reason = ("%d runs made the same call for the same request, %d minute%s apart (%s), "
                          "and the records show the change %d times." % (len(per_run), gap,
                                                                          "" if gap == 1 else "s",
                                                                          which, times))
            else:
                reason = ("%d runs made the same call, %d minute%s apart (%s), and the records show the "
                          "change %d times. Their requests differ, so both may have been meant."
                          % (len(per_run), gap, "" if gap == 1 else "s", which, times))
            res.items.append(Item(LIST_DUPLICATE, reason, task, run, c, recs, unsure=not same_request))
        elif o[0] == "held_back":
            res.items.append(Item(LIST_DIFFERS_FROM_CALL, "A record of this call's field changed near the call, "
                                  "but another call near it names no record this file has (or writes a field "
                                  "not known), so which call made the change cannot be told.", task, run, c,
                                  o[1][:3], unsure=True))
        elif o[0] == "unplaced":
            if c.unknown_args:
                # Its id may be exactly the value the log did not keep.
                reason = ("The call's %s %s withheld or cut short in the run file, and no other "
                          "argument names a record, so it could not be checked."
                          % (", ".join(sorted(c.unknown_args)),
                             "was" if len(c.unknown_args) == 1 else "were"))
            else:
                reason = ("The call names no record in the records file (no id or name in its "
                          "arguments matches one), so it could not be checked.")
            res.items.append(Item(LIST_CLAIM_NO_RECORD, reason, task, run, c, unsure=True))
        elif o[0] == "unknown_field":
            near = o[1]
            if near:
                res.items.append(Item(LIST_DIFFERS_FROM_CALL, "Records changed on this record near the "
                                      "call, but no other call of this tool shows which field it "
                                      "writes.", task, run, c, near[:3], unsure=True))
            else:
                res.items.append(Item(LIST_CLAIM_NO_RECORD, "No record of this call, and no other call "
                                      "of this tool was ever found in the records, so it may not "
                                      "write anything.", task, run, c, unsure=True))
        elif o[0] == "none":
            # Only the agent's account's changes were searched: say so, or a person's change to the
            # same record in that half hour makes the sentence false.
            by = (" by the agent's account (%s)" % account) if others else ""
            missing = ("No change to %s%s shows up in the records within %d minutes of the call."
                       % (c.entity, by, int(s.window.total_seconds() // 60)))
            if run.untasked:
                # A call outside any task: nobody said it was done, and there is no reply to read.
                res.items.append(Item(LIST_CLAIM_NO_RECORD, "A call made outside any task. %s" % missing,
                                      task, run, c, unsure=True))
            elif getattr(c, "raised", None):
                res.items.append(Item(LIST_CLAIM_NO_RECORD, "%s It may have failed before doing "
                                      "anything; check what the agent told the person." % missing,
                                      task, run, c, unsure=True))
            else:
                res.items.append(Item(LIST_CLAIM_NO_RECORD, missing, task, run, c))
        elif o[0] == "differs":
            parts = ["the call asked for %s = %s; the record shows %s" % (f, _show(c.args[k]),
                                                                          _show(in_offset_of(r.new, c.args[k])))
                     for f, (r, k) in sorted(diffs[id(c)].items(), key=lambda kv: str(kv[0]))]
            reason = "; ".join(parts)
            res.items.append(Item(LIST_DIFFERS_FROM_CALL, reason[0].upper() + reason[1:] + ".", task, run, c,
                                  [r for _f, (r, _k) in sorted(diffs[id(c)].items(), key=lambda kv: str(kv[0]))]))
        if id(c) in dup_of:
            extra = dup_of[id(c)][1]
            by_field = {}
            for r in extra:
                by_field.setdefault(r.field, [hits[id(c)][r.field]]).append(r)
            told = ", ".join("%s %d times" % (f, len(rs)) for f, rs in sorted(by_field.items(), key=lambda kv: str(kv[0])))
            res.items.append(Item(LIST_DUPLICATE, outside + "One call, and the records show its change more "
                                  "than once (%s)." % told, task, run, c,
                                  [r for rs in by_field.values() for r in rs], unsure=run.untasked))
        raised = getattr(c, "raised", None)
        others = getattr(c, "others_raised", None)
        if raised or others:
            # The tool raised (this call, or another try of the same call in the run): whatever an
            # item says about it, the reader needs the error beside it.
            said = ("The tool raised %s." % raised) if raised else \
                ("Another try of this same call raised %s." % ", ".join(sorted({str(o) for o in others})))
            for item in res.items[before:]:
                item.reason = "%s %s" % (said, item.reason)

    # A run that changed nothing: its reply is what a person needs to read.
    for run in runs:
        # Calls between tasks have no reply to read.
        if run.untasked:
            continue
        if not any(not is_read_tool(c.tool, s.read_tools) for c in run.calls):
            res.items.append(Item(LIST_CLAIM_NO_RECORD, "The run made no call that changes anything. Read "
                                  "its reply: if it says the work is done, no call of this run did it.",
                                  task_of(run), run))

    # Records the agent's account made that no call explains.
    if account is not None and has_actor:
        unplaced = [c for c in ordered if outcome[id(c)][0] == "unplaced"]
        for r in mine:
            if r in claimed:
                continue
            maybe = [c for c in unplaced if _in_window(c, r.utc, s.window)]
            if maybe:
                res.items.append(Item(LIST_UNASKED_CHANGE, "No call in the log matches this change, but "
                                      "a call near it (%s) names no record this file has, and it may be "
                                      "that call's change." % maybe[0].tool, records=[r], unsure=True))
            else:
                res.items.append(Item(LIST_UNASKED_CHANGE, "No call in the log asked for this change.",
                                      records=[r]))
    else:
        res.not_checked[LIST_UNASKED_CHANGE] = ("the records do not say who made each change"
                                               if not has_actor else "the agent's account is not known")

    # Runs that point at no task, and tasks with no run.
    if tasks is not None:
        for run in runs:
            if run.task_id not in (None, "") and run.task_id not in task_by_id:
                res.items.append(Item(LIST_TASK_NO_RUN, "The run names task %s, which is not in the "
                                      "tasks file." % run.task_id, None, run, unsure=True))
        ran = {run.task_id for run in runs}
        # A run its reader knows belongs to no task (the SDK's calls between tasks) is no task's
        # missing run.
        unlinked = [run for run in runs if run.task_id in (None, "") and not run.untasked]
        for t in tasks:
            if t.id in ran:
                continue
            if unlinked:
                res.items.append(Item(LIST_TASK_NO_RUN, "No run is linked to this task, but %d run(s) "
                                      "could not be linked to any task, and this may be one of them."
                                      % len(unlinked), t, unsure=True))
            else:
                res.items.append(Item(LIST_TASK_NO_RUN, "No run in the log for this task.", t))
    else:
        res.not_checked[LIST_TASK_NO_RUN] = "needs the tasks file"

    for key, _title in LISTS:
        res.counts[key] = len(res.on(key))
    res.counts["unsure"] = len(res.unsure())
    return res


TASK_LINK_WINDOW = timedelta(hours=2)


def link_runs_to_tasks(tasks, runs, records):
    """For runs that carry no task id: the task asked shortly before the run started whose words
    name the run's record (its name or id). With one such task, the run is linked to it; with
    none, the nearest earlier task with no run of its own; otherwise the run stays unlinked.
    Returns how many runs were linked, by which route, or None when every run had an id."""
    loose = [r for r in runs if r.task_id in (None, "") and not r.untasked]
    if not loose:
        return None
    names = {}
    for rec in records:
        if rec.entity_id not in (None, "") and rec.entity_name:
            names[rec.entity_id] = rec.entity_name
    taken = {r.task_id for r in runs if r.task_id not in (None, "")}
    counts = {"by_time_and_name": 0, "by_time_only": 0, "not_linked": 0}
    for run in sorted(loose, key=lambda r: _as_utc(r.time) or datetime.min.replace(tzinfo=timezone.utc)):
        if run.time is None:
            counts["not_linked"] += 1
            continue
        start = _as_utc(run.time)
        before = [t for t in tasks if t.id not in taken and t.time is not None
                  and start - TASK_LINK_WINDOW <= _as_utc(t.time) <= start + _EARLY_SLACK]
        words = set()
        for c in run.calls:
            if c.entity is not None:
                words.add(str(c.entity))
                if c.entity in names:
                    words.add(str(names[c.entity]))
        # whole words only: "Ana" must not find "Anastasia", nor "C1" find "C10"
        named = [t for t in before if any(w and re.search(r"(?<!\w)%s(?!\w)" % re.escape(w.casefold()),
                                                         t.text.casefold()) for w in words)]
        pick, how = None, None
        if len(named) >= 1:
            named.sort(key=lambda t: start - _as_utc(t.time))
            pick, how = named[0], "by_time_and_name"
        elif before and not words:
            before.sort(key=lambda t: start - _as_utc(t.time))
            pick, how = before[0], "by_time_only"
        if pick is None:
            counts["not_linked"] += 1
            continue
        run.task_id = pick.id
        run.linked_by = how
        taken.add(pick.id)
        counts[how] += 1
    return counts


def in_offset_of(value, like):
    """`value`, a time with its zone, written in the UTC offset `like` is written in, so the two
    read side by side ("15:00-05:00" against "16:00-05:00", not against "21:00+00:00"). Anything
    else is returned as it was."""
    if not (isinstance(value, str) and isinstance(like, str)):
        return value
    if norm(value)[0] != "time" or norm(like)[0] != "time":
        return value
    try:
        theirs = datetime.fromisoformat(like.strip().replace("Z", "+00:00"))
        mine = parse_time(value)
    except ValueError:
        return value
    if theirs.tzinfo is None or mine is None:
        return value
    return mine.astimezone(theirs.tzinfo).isoformat()


def offset_of(like):
    """The fixed UTC offset a time is written in ("2026-11-25T11:00:00-05:00" -> -05:00), or None
    for anything that is not a time with its zone."""
    if not isinstance(like, str) or norm(like)[0] != "time":
        return None
    try:
        theirs = datetime.fromisoformat(like.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return theirs.tzinfo


def _show(v):
    return repr(v) if isinstance(v, str) else str(v)
