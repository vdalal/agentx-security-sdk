"""Calendars: an iCalendar (.ics) reader and two checks on the events, a slot booked twice and one
person booked twice.

Every calendar exports .ics (Google Calendar, Outlook, Apple Calendar; Cal.com and Calendly through
the calendar they write to). One export is one calendar: one person's, or one room's. The reader keeps
what the checks need: when, who, and whether the event holds the time. It reads each event once at its
own time: a repeating event is not expanded.
"""
import re
from datetime import date, datetime, timedelta, timezone

from . import core

FIELD = "event"
# Two bookings for one person count as booked twice when they were made this close together.
MADE_TOGETHER = timedelta(minutes=30)
# ...and start this close together (a follow-up a week later is a follow-up).
STARTS_TOGETHER = timedelta(hours=24)
# Google addresses that are calendars, never people, however the export marks them: a Workspace
# room or resource (whether Google's .ics writes CUTYPE=RESOURCE on it is not confirmed), and a
# shared calendar added as a guest (real invites write it CUTYPE=INDIVIDUAL). As a guest one is
# never a person booked and never whose calendar this is; as the organizer it can still be the owner.
GOOGLE_NOT_PEOPLE = ("@resource.calendar.google.com", "@group.calendar.google.com")

try:
    from zoneinfo import ZoneInfo
except ImportError:                 # Python 3.8: no zoneinfo; named zones are not converted
    ZoneInfo = None

# The names Outlook writes for the zones a US or UK business most often uses.
WINDOWS_ZONES = {
    "eastern standard time": "America/New_York", "central standard time": "America/Chicago",
    "mountain standard time": "America/Denver", "us mountain standard time": "America/Phoenix",
    "pacific standard time": "America/Los_Angeles", "alaskan standard time": "America/Anchorage",
    "hawaiian standard time": "Pacific/Honolulu", "atlantic standard time": "America/Halifax",
    "gmt standard time": "Europe/London", "w. europe standard time": "Europe/Berlin",
    "romance standard time": "Europe/Paris", "central europe standard time": "Europe/Budapest",
    "india standard time": "Asia/Kolkata", "aus eastern standard time": "Australia/Sydney",
    "utc": "UTC",
}


def _unfold(text):
    """iCalendar lines, joined where a line was folded (a continuation starts with a space or tab)."""
    out = []
    for line in re.split(r"\r\n|\n|\r", text):
        if line[:1] in (" ", "\t") and out:
            out[-1] += line[1:]
        elif line:
            out.append(line)
    return out


def _split(line):
    """NAME;PARAM=V;PARAM="V:2":VALUE -> (NAME, {PARAM: V}, VALUE). A colon inside quotes is not the split."""
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == ":" and not quoted:
            head, value = line[:i], line[i + 1:]
            break
    else:
        return line.upper(), {}, ""
    parts = re.findall(r'(?:[^;"]|"[^"]*")+', head)
    name = parts[0].upper() if parts else ""
    params = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        params[k.upper()] = v.strip('"')
    return name, params, value


_ESCAPES = {"n": "\n", "N": "\n", ",": ",", ";": ";", "\\": "\\"}


def _text(value):
    """One pass over the escapes, so an escaped backslash before an n stays a backslash and an n."""
    return re.sub(r"\\([nN,;\\])", lambda m: _ESCAPES[m.group(1)], value)


class _Zones(object):
    def __init__(self):
        self.unknown = set()

    def get(self, name):
        if not name:
            return None
        if ZoneInfo is not None:
            for candidate in (name, WINDOWS_ZONES.get(name.strip().lower())):
                if not candidate:
                    continue
                try:
                    return ZoneInfo(candidate)
                except Exception:
                    continue
        self.unknown.add(name)
        return None


def _readable_zone(name):
    """The calendar's zone when this Python can read it (times are then shown in it), else None (UTC)."""
    if not name or ZoneInfo is None:
        return None
    for candidate in (name, WINDOWS_ZONES.get(name.strip().lower())):
        if candidate:
            try:
                return ZoneInfo(candidate)
            except Exception:
                continue
    return None


def _when(value, params, zones, as_written=False):
    """(datetime or date, all_day). A UTC time is UTC; a named zone is converted when this Python can
    read it; a floating time, or one in a zone it cannot read, stays as written (naive), as does any
    time when `as_written`."""
    v = value.strip()
    if params.get("VALUE", "").upper() == "DATE" or re.match(r"^\d{8}$", v):
        try:
            return date(int(v[:4]), int(v[4:6]), int(v[6:8])), True
        except ValueError:
            return None, True
    m = re.match(r"^(\d{8})T(\d{4})(\d{2})?(Z)?$", v)
    if not m:
        return None, False
    try:
        dt = datetime.strptime(m.group(1) + m.group(2) + (m.group(3) or "00"), "%Y%m%d%H%M%S")
    except ValueError:
        return None, False
    if as_written:
        return dt, False
    if m.group(4):
        return dt.replace(tzinfo=timezone.utc), False
    tz = zones.get(params.get("TZID"))
    if tz is not None:
        return dt.replace(tzinfo=tz).astimezone(timezone.utc), False
    return dt, False


def _duration(value):
    m = re.match(r"^([+-])?P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$", value.strip())
    if not m:
        return None
    sign = -1 if m.group(1) == "-" else 1
    w, d, h, mi, s = (int(x or 0) for x in m.groups()[1:])
    return sign * timedelta(weeks=w, days=d, hours=h, minutes=mi, seconds=s)


def _email(value):
    v = value.strip()
    return v[7:].lower() if v.lower().startswith("mailto:") else v.lower()


def read_ics(path, mapping=None, notes=None, counts=None):
    """The events of a calendar file, as records the checks read (kind "event"). What the reader could
    not do (a zone it could not read, events with no creation time) is appended to `notes`; `counts`,
    when given, gets "unread": the events left out for a start time it cannot read."""
    from .adapters import InputError, read_text
    text = read_text(path)
    if "BEGIN:VCALENDAR" not in text.upper():
        raise InputError("%s is not a calendar file (no BEGIN:VCALENDAR)" % path)
    zones = _Zones()
    evs = []
    ev, depth = None, 0
    cal_zone = cal_name = None
    for line in _unfold(text):
        name, params, value = _split(line)
        if name == "BEGIN":
            if value.upper() == "VEVENT" and ev is None:
                ev, depth = {"attendees": [], "answers": {}, "EXDATE": []}, 0
            elif ev is not None:
                depth += 1          # an alarm inside an event: its lines are not the event's
            continue
        if name == "END":
            if ev is not None and depth:
                depth -= 1
            elif ev is not None and value.upper() == "VEVENT":
                evs.append(ev)
                ev = None
            continue
        if ev is None and name == "X-WR-TIMEZONE":
            cal_zone = value.strip()        # the calendar's own zone, for showing times as its owner reads them
        if ev is None and name == "X-WR-CALNAME":
            cal_name = _text(value).strip()
        if ev is None or depth:
            continue
        if name == "ATTENDEE":
            who = _email(value)
            ev["answers"][who] = params.get("PARTSTAT", "").upper()    # the owner's answer decides the slot
            # a room or a resource is not a person, nor whose calendar this is, whatever it answered
            # (an Exchange room declines when it is already booked); a person who declined is not in
            # the event
            if params.get("CUTYPE", "").upper() in ("RESOURCE", "ROOM") or who.endswith(GOOGLE_NOT_PEOPLE):
                ev.setdefault("rooms", set()).add(who)
                continue
            if params.get("PARTSTAT", "").upper() == "DECLINED":
                # Not booked into the slot, but the event was still made for them: a booking check
                # must see it (a booking the customer then declined is not "none was made").
                ev.setdefault("declined", []).append(who)
                continue
            ev["attendees"].append(who)
        elif name in ("DTSTART", "DTEND", "RECURRENCE-ID", "CREATED"):
            ev[name] = _when(value, params, zones)
            ev[name + ";RAW"] = (value, params)
        elif name == "EXDATE":
            ev["EXDATE"] += [_when(v, params, zones)[0] for v in value.split(",") if v.strip()]
        elif name == "ORGANIZER":
            ev[name] = _email(value)
        elif name in ("UID", "SUMMARY", "STATUS", "TRANSP", "RRULE", "DURATION", "LOCATION", "SEQUENCE"):
            ev[name] = _text(value)
    given = (mapping or {}).get("owner")
    if given:
        owner, owner_from, tied = _email(given), "set in the mapping file", []
    else:
        owner, owner_from, tied = _owner(evs, cal_name)
    records = []
    for ev in evs:
        rec = _event_record(ev, len(records) + 1, zones, owner)
        if rec is not None:
            records.append(rec)
    if counts is not None:
        counts["unread"] = len(evs) - len(records)
    _first_occurrence_gone(records)
    _mark_apart(records)
    shown_in = _readable_zone(cal_zone)
    for r in records:
        r.raw["shown_in"] = shown_in
    if notes is not None:
        for z in sorted(zones.unknown):
            n = sum(1 for r in records if z in r.raw["zones_unread"] and r.raw["apart"])
            if n:
                notes.append("%s the time zone \"%s\", which %s, so %s could not be compared with your other "
                             "events (only with any others in that zone)."
                             % (_n(n, "event") + (" uses" if n == 1 else " use"), z, _why_unread(z),
                                "it" if n == 1 else "they"))
        floating = sum(1 for r in records if r.raw["zone_key"] == "" and r.raw["apart"])
        if floating:
            notes.append("%s no time zone at all, so %s could not be compared with your other events."
                         % (_n(floating, "event") + (" has" if floating == 1 else " have"),
                            "it" if floating == 1 else "they"))
        if tied:
            lines = ["{\"owner\": \"%s\"}" % who for who in tied]
            notes.append("Whose calendar this is could not be worked out: %s are each on nearly every event. "
                         "Until it is set, the owner may be listed below as a person booked twice, and an "
                         "invitation they declined still counts as holding time. To set it, save the line for "
                         "the person whose calendar you exported (not an account that books for them) as "
                         "owner.json and run again with --map owner.json: %s." % (_and(tied), " or ".join(lines)))
        # Only when some event names a person: a calendar of solo events, an empty one, or one
        # exported as availability only names nobody, and then the address may well be right.
        names_people = any(ev.get("ORGANIZER") or set(ev["answers"]) - ev.get("rooms", set()) for ev in evs)
        on_an_event = any(owner == ev.get("ORGANIZER") or owner in ev["answers"] for ev in evs)
        if given and names_people and not on_an_event and owner != _email(cal_name or ""):
            notes.append("%s, the owner the mapping file names, is on none of these events: check the address."
                         % owner)
        declined = sum(1 for r in records if r.raw["owner_released"])
        # Said whenever the owner was set by hand (the reader confirms it took), or when it changed a
        # result; not for an owner the mapping names who is on no event (the note above says that).
        if (given and on_an_event) or declined:
            notes.append("This calendar is read as %s's (%s).%s"
                         % (owner, owner_from, " Not counted as holding time: %s they declined."
                            % _n(declined, "invitation") if declined else ""))
        if not records:
            # Said, never left to a "None." under each check: an export of the wrong calendar, or of
            # dates that leave everything out, reads exactly like a calendar with nothing wrong. A file
            # whose events have no start this reader can read is said as that, not as an empty export.
            if evs:
                notes.append("The calendar file has %s, but none has a start time this tool can read, so "
                             "none was checked." % _n(len(evs), "event"))
            else:
                notes.append("The calendar file has no events: check it is the calendar the agent books into, "
                             "exported for the dates you mean.")
        elif len(evs) > len(records):
            # Left out without a word, one of them could be the booking a call is said to have missed.
            n = len(evs) - len(records)
            notes.append("%d of the file's %d events %s a start time this tool cannot read, so %s not checked."
                         % (n, len(evs), "has" if n == 1 else "have", "it was" if n == 1 else "they were"))
        missing = sum(1 for r in records if r.raw["created"] is None and r.raw["attendees"])
        if missing:
            notes.append("%d event%s say%s nothing about when %s made, so \"one person booked twice\" could "
                         "not check %s." % (missing, "" if missing == 1 else "s", "s" if missing == 1 else "",
                                             "it was" if missing == 1 else "they were",
                                             "it" if missing == 1 else "them"))
    return records


def _n(count, word):
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def _and(parts):
    return parts[0] if len(parts) == 1 else "%s and %s" % (", ".join(parts[:-1]), parts[-1])


def _owner(evs, cal_name):
    """Whose calendar this is, and how that was worked out: the calendar's name when it is an address,
    else the address on the events that name an organizer (the owner made them or was invited), on at
    least two, on four in five of them, and on more than any other address. Returns (owner, how,
    tied): no owner when unclear, and then `tied` names the addresses that were equally likely (the
    report asks for the owner in a mapping file), or is empty when no address was likely at all."""
    if cal_name and re.match(r"^[^@\s]+@[^@\s]+$", _email(cal_name)):
        return _email(cal_name), "the calendar's name", []
    counts, organized = {}, 0
    for ev in evs:
        if not ev.get("ORGANIZER"):
            continue
        organized += 1
        for who in (set(ev["answers"]) - ev.get("rooms", set())) | {ev["ORGANIZER"]}:
            if who:
                counts[who] = counts.get(who, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if not ranked or ranked[0][1] < 2 or ranked[0][1] * 5 < organized * 4:
        return None, None, []
    # Never a guess between them: an agent's account booking the owner and an owner inviting an
    # assistant to everything look the same in the file. The report offers each as a line to paste.
    tied = [who for who, c in ranked if c == ranked[0][1]]
    if len(tied) > 1:
        return None, None, tied
    return ranked[0][0], "the address on nearly every event", []


def _why_unread(zone):
    """Why a zone stayed as written, in words the reader can act on."""
    if ZoneInfo is None:
        return "this Python cannot convert (Python 3.9 or later can)"
    if "/" in zone or zone.strip().lower() in WINDOWS_ZONES:
        return "this machine has no time zone data for (pip install tzdata)"
    return "agentx match does not know"


def _mark_apart(records):
    """An event whose times stayed as written is compared only with events written in the same zone:
    it is "apart" when that is not the calendar's main group (the converted events, or, when none
    converted, the largest group). The report counts these: they were not checked against the rest."""
    timed = [r for r in records if isinstance(r.raw["start"], datetime)]
    groups = {}
    for r in timed:
        groups[r.raw["zone_key"]] = groups.get(r.raw["zone_key"], 0) + 1
    main = None if None in groups or not groups else max(groups, key=lambda k: (groups[k], k))
    for r in records:
        r.raw["apart"] = isinstance(r.raw["start"], datetime) and r.raw["zone_key"] != main


def _first_occurrence_gone(records):
    """A repeating event whose first occurrence was deleted (EXDATE) or moved (an instance whose
    RECURRENCE-ID is that time) holds nothing at its own first time."""
    moved = {}
    for r in records:
        if r.raw["recurrence_id"] is not None:
            moved.setdefault(r.raw["uid"], []).append(r.raw["recurrence_id"])
    for r in records:
        x = r.raw
        if x["repeats"] and x["recurrence_id"] is None:
            x["first_gone"] = x["start"] in x["exdates"] or x["start"] in moved.get(x["uid"], [])


def _event_record(ev, n, zones, owner=None):
    start, all_day = ev.get("DTSTART", (None, False))
    if start is None:
        return None
    end = ev.get("DTEND", (None, False))[0]
    start_tz = ev["DTSTART;RAW"][1].get("TZID")
    end_tz = ev["DTEND;RAW"][1].get("TZID") if "DTEND;RAW" in ev else start_tz
    if isinstance(start, datetime) and isinstance(end, datetime) and (start.tzinfo is None) != (end.tzinfo is None):
        # one end converted and the other not: neither is comparable with the other, so keep both as written
        start = _when(*ev["DTSTART;RAW"], zones=zones, as_written=True)[0]
        end = _when(*ev["DTEND;RAW"], zones=zones, as_written=True)[0]
    if end is None and ev.get("DURATION"):
        d = _duration(ev["DURATION"])
        end = start + d if d is not None else None
    if end is None:
        end = start + (timedelta(days=1) if all_day else timedelta(0))
    naive = isinstance(start, datetime) and start.tzinfo is None
    # Times kept as written are compared only with times written in the same zone; a floating time
    # (no zone at all) is its own group.
    zone_key = None if not naive else (start_tz or "") if start_tz == end_tz else "%s|%s" % (start_tz, end_tz)
    zones_unread = {z for z in (start_tz, end_tz) if z and z in zones.unknown}
    uid = ev.get("UID") or "event-%d" % n
    rid = ev.get("RECURRENCE-ID", (None, False))[0]
    # CREATED only: DTSTAMP in an export is the export's own time, the same on every event, and would
    # make any two bookings look made together
    created = ev.get("CREATED", (None, False))[0]
    organizer = ev.get("ORGANIZER")
    # The export is the owner's time: the owner is never one of the people booked, and an invite the
    # owner declined does not take the owner's slot.
    people = [a for a in ev["attendees"] if a and a != organizer and a != owner]
    answer = ev["answers"].get(owner, "") if owner else ""
    # Only a decline frees the slot: Google counts an unanswered invitation as busy, Outlook shows it
    # as tentative, and an agent that invites the owner into a taken slot is the case to catch.
    released = "declined" if answer == "DECLINED" else None
    raw = {"uid": uid, "start": start, "end": end, "all_day": all_day, "summary": ev.get("SUMMARY", ""),
           "status": (ev.get("STATUS") or "CONFIRMED").upper(),
           "transparent": (ev.get("TRANSP") or "").upper() == "TRANSPARENT",
           "attendees": people, "organizer": organizer, "owner_released": released,
           "created": created if isinstance(created, datetime) else None,
           "declined": [a for a in ev.get("declined", []) if a and a != organizer and a != owner],
           # How many times the event was rescheduled (RFC 5545 SEQUENCE); None when not written.
           "sequence": int(ev["SEQUENCE"]) if str(ev.get("SEQUENCE", "")).strip().isdigit() else None,
           "owner": owner,
           "repeats": bool(ev.get("RRULE")), "moved_instance": rid is not None, "recurrence_id": rid,
           "exdates": [d for d in ev["EXDATE"] if d is not None], "first_gone": False,
           "zone_key": zone_key, "zones_unread": zones_unread}
    rec_id = uid if rid is None else "%s (moved instance)" % uid
    when = start if isinstance(start, datetime) else datetime(start.year, start.month, start.day)
    return core.Record(rec_id, when, uid, ev.get("SUMMARY", ""), FIELD, None, ev.get("SUMMARY", ""),
                       organizer, raw, kind=FIELD)


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def person_key(value):
    """The key a booking is found by: an email address, lower case; None for anything else."""
    if isinstance(value, str) and _EMAIL.match(value.strip()):
        return value.strip().lower()
    return None


_END_WORDS = {"end", "ends", "until", "finish", "finishes"}


def _is_end_name(name):
    return bool(_END_WORDS.intersection(core.name_words(name)))


def _unusable(x):
    """Why an event cannot be compared with a booking call's start, or None when it can."""
    start = x.get("start")
    if x.get("status") == "CANCELLED":
        return "cancelled"
    if x.get("transparent"):
        return "marked free"
    if not isinstance(start, datetime) or x.get("all_day"):
        return "all day"
    if x.get("zones_unread"):
        return "in a time zone this reader could not read"
    if start.tzinfo is None:
        return "a start with no time zone"
    if x.get("moved_instance"):
        return "a changed date of a repeating event"
    return None


def _role(call, book_tools, undo_tools):
    """'books', 'cancels', or None: what the mapping file's lists say the tool does, else what the
    tool declared (@agentx_protect(effect=...), kept in the run file). Never read from its name: a
    name is whatever someone typed."""
    if call.tool in undo_tools:
        return "cancels"
    if call.tool in book_tools:
        return "books"
    return getattr(call, "effect", None)


def _booking_of(call, organizers, owner):
    """(person, start) for a call that books: exactly one person among its arguments and exactly
    one date and time that is not an end; None for any other call. The owner is never the person;
    of several addresses, the one that never organized an event is (a guest, not the staff)."""
    people = []
    for v in call.args.values():
        key = person_key(v) if core._is_scalar(v) else None
        if key and key != owner and key not in people:
            people.append(key)
    if len(people) > 1:
        people = [p for p in people if p not in organizers]
    times = [v for k, v in call.args.items()
             if isinstance(v, str) and core._TIME_LIKE.match(v.strip()) and not _is_end_name(k)]
    if len(people) != 1 or len(times) != 1:
        return None
    return people[0], times[0]


def _shown_start(x, like):
    return core.in_offset_of(x["start"].isoformat(), like) if isinstance(x.get("start"), datetime) else str(x.get("start"))


def check_bookings(runs, events, window, task_of, read_tools=(), book_tools=(), undo_tools=(), stats=None,
                   unread=0):
    """The agent's booking calls against the calendar it books into, by three rules. Anything the
    files cannot settle is unsure, never a finding.

    A booking call names one person (an email) and one start. Its window is the 5 minutes before the
    call to `window` after it; for a retry (the same booking asked again, each try within `window` of
    the first), from 5 minutes before the first try to `window` after the last. "Made" is the event's
    CREATED.

    1. No booking: no live booking for that person at that start is on the calendar at all, no
       event of theirs was made in the window (a booking made last week is not this call's job: a
       reminder carries the same values), and no event at that start was made in the window
       without them as a guest (it may be theirs: a staff- or room-only invite, the customer only
       in the title).
    2. Wrong slot: no booking at that start, and exactly one live event of theirs made in the window,
       at another start, never rescheduled (SEQUENCE 0). Rescheduled, or several, is unsure.
    3. Booked twice: two or more live events of theirs at that start (or declined by them, otherwise
       live), made in the window.

    A booking call is a call of a tool declared as booking: @agentx_protect(effect="books") (kept
    in the run file), or a mapping file's "book_tools" for a log written by anything else. A tool
    declared as cancelling is never one. Every other call is named in a note, with the line to
    add; nothing is read from a tool's name.

    Unsure: a start that cannot be read as a moment (no zone, or a zone written as a name) near a
    booking of theirs; an event of theirs made in the window, or that day, that cannot be compared
    (cancelled, declined, all day, ...); an event of theirs that does not say when it was made; a log
    whose times do not say their zone (the window then rests on an unknown clock); a call that
    raised; a call outside any task; a missing booking whose start is outside the dates the file's
    events cover, or in a file with no events (an export of another calendar, or of a date range
    that leaves the day out, shows no booking either), with a written date that is not a real one,
    or in a file with `unread` events left out for a start time the reader cannot read. Returns
    (items, calls this did not check: {reason: {tool: n}}); `stats`, when given, gets "checked"
    (pieces of booking work judged) and "as_asked" (those the calendar shows as the call asked)."""
    covers = _covers(events, unread)
    owner = next((r.raw.get("owner") for r in events if r.raw.get("owner")), None)
    owner = owner.lower() if owner else None
    organizers = {(r.raw.get("organizer") or "").lower() for r in events}
    by_person = {}
    for r in events:
        for key in {person_key(w) for w in list(r.raw.get("attendees") or []) + list(r.raw.get("declined") or [])}:
            if key:
                by_person.setdefault(key, []).append(r)
    # Live events by the moment they start, for "an event at that time that does not list them".
    by_start = {}
    for r in events:
        if _unusable(r.raw) is None:
            by_start.setdefault(core._as_utc(r.raw["start"]), []).append(r)
    items, not_checked, twice_seen = [], {}, set()

    def skip(reason, tool):
        not_checked.setdefault(reason, {})
        not_checked[reason][tool] = not_checked[reason].get(tool, 0) + 1

    for run in runs or []:
        # The same booking asked again in one run (a retry) is one piece of work: tries within the
        # window of the one before are judged once, over the window from the first try to the last,
        # through a try that did not raise, with the others' errors said beside it.
        tries = {}
        for c in run.calls:
            role = _role(c, set(book_tools), set(undo_tools))
            if role is None and c.tool in read_tools:
                continue                    # declared a read in the mapping file: nothing to check
            if role == "cancels":
                skip("they cancel a booking", c.tool)
                continue
            if role is None:
                skip('nothing says they book: if one does, add effect="books" to its @agentx_protect '
                     '(or, for a log written by anything else, list it in a mapping file\'s "book_tools")',
                     c.tool)
                continue
            booking = _booking_of(c, organizers, owner)
            if booking is None:
                skip("each names no one person and one start time", c.tool)
                continue
            if c.time is None:
                skip("the log gives no time for them", c.tool)
                continue
            asked = core.parse_time(booking[1])
            moment = asked.isoformat() if asked is not None and asked.tzinfo is not None else booking[1]
            tries.setdefault((c.tool, booking[0], moment), []).append(c)
        for cs_all in tries.values():
            cs_all.sort(key=lambda x: (core._as_utc(x.time), x.index))
            bands = []
            for x in cs_all:
                # Each try within the window of the FIRST: a call repeated every few minutes for an
                # hour is not one retry, and its window never stretches past twice the window.
                if not bands or core._as_utc(x.time) - core._as_utc(bands[-1][0].time) > window:
                    bands.append([])
                bands[-1].append(x)
            for cs in bands:
                item = _one_booking(cs, by_person, organizers, owner, window, twice_seen, run, task_of, by_start,
                                    covers, stats)
                if item is not None:
                    items.append(item)
    return items, not_checked


def _covers(events, unread=0):
    """(the events' starts, the calendar's own zone or None, events left out unread) for the dates a
    missing booking is said in; None for a file with no events. Dated per call by _not_covered: a
    calendar that names no zone is dated in the offset the call wrote its time in, as the report
    shows its events."""
    starts = [r.raw.get("start") for r in events if hasattr(r.raw.get("start"), "year")]
    if not starts:
        return None
    return (starts, next((r.raw.get("shown_in") for r in events if r.raw.get("shown_in") is not None), None),
            unread)


_WRITTEN_DATE = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})")


def _one_booking(cs, by_person, organizers, owner, window, twice_seen, run, task_of, by_start=None, covers=None,
                 stats=None):
    """The item for one piece of booking work (one try, or a retry's tries), or None."""
    c = next((x for x in cs if not getattr(x, "raised", None)), cs[0])
    booking = _booking_of(c, organizers, owner)
    theirs = by_person.get(booking[0], [])
    if stats is not None:
        stats["checked"] = stats.get("checked", 0) + 1
    got = _judge(c, booking, theirs, window, twice_seen,
                 span=(core._as_utc(cs[0].time), core._as_utc(cs[-1].time)), tries=len(cs), by_start=by_start,
                 covers=covers)
    if got is None:
        return None
    if got == _AS_ASKED:
        if stats is not None:
            stats["as_asked"] = stats.get("as_asked", 0) + 1
        return None
    key, reason, recs, unsure = got
    # What the log itself says about the call settles less: a log time with no zone puts the window
    # on an unknown clock (it matters only when something of theirs is on the calendar for the window
    # to have caught); a call that raised may have done nothing; a call outside any task has no
    # request saying it should have happened once.
    assumed = any(getattr(x.run, "clock_assumed", False) if x.time_from_run else getattr(x, "clock_assumed", False)
                  for x in cs)
    if not unsure and assumed and theirs:
        unsure = True
        reason += (" The log's times do not say their time zone, so the %d minutes after the call may be off."
                   % _minutes(window))
    if run.untasked:
        unsure = True
        reason = "Outside any task, so nothing says it should have happened. " + reason
    raised = getattr(c, "raised", None)
    others = sorted({str(x.raised) for x in cs if x is not c and getattr(x, "raised", None)})
    also = (" Another try of this same call raised %s." % ", ".join(others)) if others else ""
    if raised:
        if key == core.LIST_CLAIM_NO_RECORD:
            unsure = True
        reason = "The tool raised %s.%s %s" % (raised, also, reason)
    elif others:
        reason = also.strip() + " " + reason
    return core.Item(key, reason, task_of(run), run, c, recs, unsure=unsure)


_AS_ASKED = "as asked"


def _not_covered(start, covers):
    """Why the file cannot show a missing booking at `start` (a file with no event it could read, or a
    start dated before its first event or after its last), or None when it can. Whole days, so 3pm on
    the last day an event starts is inside. A start whose zone is not known (none written, or one
    this reader cannot read: dated from its written date) may fall a day either side, so it must be
    a day inside the span. Also unsure: a written date that is not a real one (a 30th of February), and any
    file with events left out for a start time this reader cannot read (one may be this booking)."""
    if covers is None:
        return "the calendar file has no event this tool can read (see the note above)"
    starts, shown_in, unread = covers
    if unread:
        return ("%s in the file %s a start time this tool cannot read, and %s may be this booking (see the note "
                "above)" % (_n(unread, "event"), "has" if unread == 1 else "have", "it" if unread == 1 else "one"))
    zone = shown_in or core.offset_of(start)
    asked = core.parse_time(start)
    if asked is not None and asked.tzinfo is not None:
        day = (asked.astimezone(zone) if zone is not None else asked).date()
        slack = timedelta(0)
    else:
        m = _WRITTEN_DATE.match(str(start))
        if asked is not None:
            day = asked.date()
        elif m:
            try:
                day = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return "its date (%s) is not a real date, so the file cannot place it" % m.group(0).strip()
        else:
            return None
        slack = timedelta(days=1)

    def date_of(s):
        if isinstance(s, datetime):
            if s.tzinfo is not None:
                s = s.astimezone(zone) if zone is not None else core._as_utc(s)
            return s.date()
        return s

    days = sorted(date_of(s) for s in starts)
    first, last = days[0], days[-1]
    if first + slack <= day <= last - slack:
        return None
    span = ("from %s to %s" % (first, last)) if first != last else "on %s only" % first
    # Dated in the call's offset (the calendar names no zone), these dates can differ from the count
    # line's, which are in UTC: say which clock they are on.
    off = zone.utcoffset(None) if shown_in is None and zone is not None else None
    if off:
        m = int(off.total_seconds() // 60)
        span += " (at %s%02d:%02d, the call's offset)" % ("-" if m < 0 else "+", abs(m) // 60, abs(m) % 60)
    return "the file's events are %s, so it may not cover that date" % span


def _judge(c, booking, theirs, window, twice_seen, span=None, tries=1, by_start=None, covers=None):
    """One booking call by the three rules: (list, reason, records, unsure); _AS_ASKED for a call the
    calendar shows as asked; None for a booking already reported through another call. `span`: (first
    try, last try) of a retry, whose window runs from 5 minutes before the first to `window` after the
    last; `tries`: how many, for the sentence. `covers`: what _covers says of the file, for the
    missing-booking rule (None: the file has no events)."""
    person, start = booking
    first, last = span or (core._as_utc(c.time), core._as_utc(c.time))
    lo, hi = first - core._EARLY_SLACK, last + window
    minutes = _minutes(window)
    when = ("within %d minutes of the call" % minutes if tries == 1 else
            "between the first of its %d tries and %d minutes after the last" % (tries, minutes))

    def made_in_window(r):
        made = r.raw.get("created")
        return made is not None and lo <= core._as_utc(made) <= hi

    def booked(r):
        """A live event this person is booked into (not one they declined)."""
        return _unusable(r.raw) is None and person in (r.raw.get("attendees") or [])

    def why_not(r):
        if person not in (r.raw.get("attendees") or []):
            return "declined by them"
        return _unusable(r.raw)

    asked = core.parse_time(start)
    moment = asked is not None and asked.tzinfo is not None
    live = [r for r in theirs if booked(r)]
    at_start = [r for r in live if moment and core._as_utc(r.raw["start"]) == asked]
    made_now = [r for r in theirs if made_in_window(r)]
    # A copy they declined at the asked start, otherwise live, was still made: it counts toward
    # booked twice.
    declined_copies = [r for r in theirs if r not in at_start and person in (r.raw.get("declined") or [])
                       and _unusable(r.raw) is None and moment and core._as_utc(r.raw["start"]) == asked]
    if at_start:
        twin = [r for r in at_start + declined_copies if made_in_window(r)]
        ids = frozenset(r.id for r in twin)
        if len(twin) >= 2 and ids not in twice_seen:
            twice_seen.add(ids)
            return (core.LIST_DUPLICATE, "%d bookings for %s at that time were made %s."
                    % (len(twin), person, when), twin, False)
        return _AS_ASKED if len(twin) < 2 else None
    if not moment:
        if asked is None:
            if not theirs:
                # Nothing of theirs on the calendar at all: rule 1 needs no time, but a file with no
                # event read shows nothing of anyone's, and a start dated outside the file's events
                # (by its written date) may be on a day the export left out.
                gap = _not_covered(start, covers)
                if gap:
                    return (core.LIST_CLAIM_NO_RECORD, "No booking for %s is on the calendar, but %s."
                            % (person, gap), [], True)
                return (core.LIST_CLAIM_NO_RECORD, "No booking for %s is on the calendar, and none was made %s."
                        % (person, when), [], False)
            return (core.LIST_DIFFERS_FROM_CALL, "The call's start (%s) could not be read as a time, so it cannot be "
                    "compared with the calendar." % start, made_now[:3], True)
        same_day = [r for r in live if _near(r.raw["start"], asked)]
        if made_now or same_day:
            return (core.LIST_DIFFERS_FROM_CALL, "The call's start (%s) does not say its time zone, so it cannot be "
                    "compared with the booking for %s on the calendar." % (start, person),
                    (made_now or same_day)[:3], True)
    # An event of theirs that day that cannot be compared (no zone, a zone not read, cancelled,
    # declined, ...) may be this booking, made earlier or now.
    that_day = [r for r in theirs if why_not(r) is not None and _near(r.raw.get("start"), asked)]
    usable_now = [r for r in made_now if booked(r)]
    if usable_now:
        one = usable_now[0]
        if len(usable_now) == 1 and len(made_now) == 1 and not that_day and one.raw.get("sequence") == 0:
            return (core.LIST_DIFFERS_FROM_CALL, "The call asked for start = %r; the booking for %s made then starts "
                    "at %r." % (start, person, _shown_start(one.raw, start)), [one], False)
        if len(usable_now) > 1:
            why = "%d bookings for them were made then" % len(usable_now)
        elif len(made_now) > 1 or that_day:
            other = [r for r in made_now + that_day if why_not(r) is not None][0]
            why = "another event for them made then or that day is %s" % why_not(other)
        elif one.raw.get("sequence"):
            why = "it was rescheduled since it was made"
        else:
            why = "the calendar does not say whether it was rescheduled"
        return (core.LIST_DIFFERS_FROM_CALL, "The call asked for start = %r; the booking for %s made then starts "
                "elsewhere, but %s." % (start, person, why), (usable_now + that_day)[:3], True)
    if made_now:
        return (core.LIST_CLAIM_NO_RECORD, "An event for %s made then is %s, so whether this call's booking landed "
                "cannot be told." % (person, why_not(made_now[0])), made_now[:3], True)
    if that_day:
        return (core.LIST_CLAIM_NO_RECORD, "An event for %s that day is %s, and it may be this booking."
                % (person, why_not(that_day[0])), that_day[:3], True)
    undated = [r for r in theirs if r.raw.get("created") is None]
    if undated:
        return (core.LIST_CLAIM_NO_RECORD, "No booking for %s at that time is on the calendar, but %s has an event "
                "that does not say when it was made, and it may be this call's." % (person, person), undated[:3],
                True)
    # An event at exactly that time, made then, that does not list them (a booking system that
    # invites only the stylist or the room, or writes the customer only in the title) may be this
    # booking: "none was made" cannot be said.
    unlisted = [r for r in (by_start or {}).get(asked, []) if r not in theirs and made_in_window(r)] if moment else []
    if unlisted:
        return (core.LIST_CLAIM_NO_RECORD, "No booking that lists %s is on the calendar, but an event at that time "
                "was made then without them as a guest, and it may be this booking." % person, unlisted[:3], True)
    gap = _not_covered(start, covers)
    if gap:
        return (core.LIST_CLAIM_NO_RECORD, "No booking for %s at %s is on the calendar, but %s."
                % (person, start, gap), [], True)
    return (core.LIST_CLAIM_NO_RECORD, "No booking for %s at %s is on the calendar, and none was made %s."
            % (person, start, when), [], False)


def _minutes(window):
    return int(window.total_seconds() // 60)


def _near(start, asked):
    """True when an event's start may be the asked time: within a day of it, whatever the zones (a
    start with no zone, or a date, is read as if in UTC, so a day either side covers every zone)."""
    if start is None:
        return False
    if not isinstance(start, datetime):
        start = datetime(start.year, start.month, start.day)
    a = asked.replace(tzinfo=None) if asked.tzinfo is None else core._as_utc(asked).replace(tzinfo=None)
    s = start.replace(tzinfo=None) if start.tzinfo is None else core._as_utc(start).replace(tzinfo=None)
    return abs(s - a) <= timedelta(days=1)


def ics_adapter(path, mapping=None):
    notes, counts = [], {}
    records = read_ics(path, mapping, notes, counts)
    return {"records": records, "notes": notes, "unread_events": counts.get("unread", 0)}


# --- the checks -------------------------------------------------------------------------------

def _events(ctx):
    return [r for r in ctx.records if r.kind == FIELD]


def _live(r):
    """Booked on this calendar: not cancelled, not marked free, not an invite the owner declined, not
    the deleted or moved first time of a repeating event."""
    x = r.raw
    return x["status"] != "CANCELLED" and not x["transparent"] and not x["owner_released"] and not x["first_gone"]


def _holds_time(r):
    """An event that takes the slot: booked, timed (not all day), with an end after its start."""
    x = r.raw
    return (_live(r) and not x["all_day"] and isinstance(x["start"], datetime)
            and isinstance(x["end"], datetime) and x["end"] > x["start"])


def double_booked(ctx):
    """Two events that overlap on the calendar (both hold some of the same time). A repeating event and its moved
    instance are one event. Times kept as written (a zone this Python could not read, or none) are
    compared only with times written in the same zone."""
    events = _events(ctx)
    if not events:
        return None
    out = []
    groups = {}
    for r in events:
        if _holds_time(r):
            groups.setdefault(r.raw["zone_key"], []).append(r)
    for key in sorted(groups, key=lambda k: (k is not None, k or "")):
        held = sorted(groups[key], key=lambda r: r.raw["start"])
        for i, a in enumerate(held):
            for b in held[i + 1:]:
                if b.raw["start"] >= a.raw["end"]:
                    break               # sorted by start: nothing later can overlap a
                if b.raw["uid"] == a.raw["uid"]:
                    continue
                out.append(core.Item("double_booked", "These look like the same event entered twice."
                                     if _same_event(a, b) else "These two events overlap on the calendar.",
                                     records=[a, b]))
    return out


def _same_event(a, b):
    """The same title (both have one) and the same start and end: one event entered twice, which is
    what a booking agent that books one request twice leaves on the calendar."""
    ta, tb = (" ".join((r.raw["summary"] or "").split()).casefold() for r in (a, b))
    return bool(ta) and ta == tb and a.raw["start"] == b.raw["start"] and a.raw["end"] == b.raw["end"]


def _comparable(a, b):
    return (a.tzinfo is None) == (b.tzinfo is None)


def booked_twice(ctx):
    """One person in two booked events made within MADE_TOGETHER of each other and starting within
    STARTS_TOGETHER: the same request answered twice. An event with no creation time is not checked
    (the reader says how many); when no event with a person in it has one, nothing could be checked."""
    events = _events(ctx)
    live = [r for r in events if _live(r) and isinstance(r.raw["start"], datetime)]
    if not any(r.raw["created"] is not None and r.raw["attendees"] for r in live):
        return None
    by_person = {}
    for r in live:
        for who in r.raw["attendees"]:
            by_person.setdefault(who, []).append(r)
    # One finding per pair of events, naming everyone in both: a pair shared by 14 guests is one
    # booking made twice, not 14 findings (seen on a real calendar).
    pairs = {}
    for who, rs in sorted(by_person.items()):
        rs.sort(key=lambda r: str(r.raw["start"]))
        for i, a in enumerate(rs):
            for b in rs[i + 1:]:
                if a.raw["uid"] == b.raw["uid"]:
                    continue
                ca, cb = a.raw["created"], b.raw["created"]
                if ca is None or cb is None or not _comparable(ca, cb) or not _comparable(a.raw["start"], b.raw["start"]):
                    continue
                if abs(ca - cb) <= MADE_TOGETHER and abs(a.raw["start"] - b.raw["start"]) <= STARTS_TOGETHER:
                    key = frozenset((id(a), id(b)))
                    if key not in pairs:
                        pairs[key] = ([a, b], int(abs(ca - cb).total_seconds() // 60), [])
                    pairs[key][2].append(who)
    out = []
    for (a, b), gap, people in sorted(pairs.values(), key=lambda p: (str(p[0][0].raw["start"]),
                                                                      str(p[0][1].raw["start"]))):
        out.append(core.Item("booked_twice", "%s in both, and the two were made %d minute%s apart."
                             % (_who_is(people), gap, "" if gap == 1 else "s"), records=[a, b]))
    return out


def _who_is(people):
    """"a@x is", "a@x and b@x are", "a@x and 13 others are": the people a finding is about, in order."""
    if len(people) == 1:
        return "%s is" % people[0]
    if len(people) == 2:
        return "%s and %s are" % (people[0], people[1])
    return "%s and %d others are" % (people[0], len(people) - 1)


double_booked.title = "A slot booked twice"
booked_twice.title = "One person booked twice"
