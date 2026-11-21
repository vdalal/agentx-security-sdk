"""Text messages: a reader for Twilio's message-log export ("Export CSV" on the console's Messaging
logs) and three checks on what the agent sent: texts that did not arrive, one person texted the same
thing twice, and texts started outside permitted hours.

Directions in the export: `outbound-api` is a text an app (the agent) sent through Twilio's API;
`outbound-reply` is Twilio's automatic reply to an incoming text; `inbound` came from the person. An
agent that answers through the API also writes `outbound-api`, so an API text sent within
REPLY_WITHIN after the person's own text is read as a reply. SMS and WhatsApp numbers
(`whatsapp:+1...`) share one file; one number is one person on either channel.
"""
from datetime import timedelta

from . import core

FIELD = "message"
COLUMNS = {"sid", "from", "to", "body", "status", "sentdate", "direction"}
TWICE_WITHIN = timedelta(minutes=60)
REPLY_WITHIN = timedelta(minutes=5)
DEFAULT_HOURS = ("08:00", "21:00")
FAILED = ("failed", "undelivered")
# A copy that never reached the person is not a second text (a retry after it is the normal fix).
NOT_SENT = FAILED + ("canceled",)

# Twilio's own words for the errors a person most often meets; any other code is shown as its number.
ERRORS = {
    30003: "the phone was unreachable",
    30004: "the message was blocked",
    30005: "the number is unknown or no longer in service",
    30006: "a landline or a number that cannot take texts",
    30007: "the carrier filtered it",
    30008: "an unknown error",
    30032: "the toll-free number has not been verified",
    30034: "the number is not registered for US texting (A2P 10DLC)",
    63016: "WhatsApp: outside the 24-hour window, a template is needed",
}


def looks_like_twilio(keys):
    return COLUMNS <= {str(k).strip().lower() for k in keys}


EXPORT_HOW = ("agentx match reads Twilio's message log as the console exports it: open Monitor, then Logs, "
              "then Messaging, set the dates and press Export CSV.")


def wrong_twilio_file(path):
    """A Twilio file this reader does not read, as a sentence saying which and what to export instead:
    a page from Twilio's API (voice calls, or messages in JSON), or a voice-call log as CSV (calls have a
    duration and no message body). None for anything else, including any file it cannot open. Only
    chooses a message: a file it names is refused either way, in words instead of a column error."""
    import json
    import re
    from .adapters import read_text
    try:
        text = read_text(path).lstrip()
    except Exception:
        return None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return None
        if not (isinstance(data, dict) and any(k in data for k in ("page_size", "first_page_uri", "next_page_uri"))):
            return None
        if isinstance(data.get("calls"), list):
            return "%s is a page of Twilio's voice-call log, which agentx match does not read. %s" % (path, EXPORT_HOW)
        if isinstance(data.get("messages"), list):
            return "%s is a page of messages from Twilio's API, which agentx match does not read. %s" % (path, EXPORT_HOW)
        return None
    header = text.splitlines()[0] if text else ""
    cols = {re.sub(r"[\s_]", "", c.strip().strip('"')).lower() for c in header.split(",")}
    if {"from", "to", "status", "direction", "duration"} <= cols and "body" not in cols:
        return "%s looks like Twilio's voice-call log, which agentx match does not read. %s" % (path, EXPORT_HOW)
    return None


def _person(number):
    n = (number or "").strip()
    return n[len("whatsapp:"):] if n.lower().startswith("whatsapp:") else n


def _channel(row_from, row_to):
    return "WhatsApp" if "whatsapp:" in ((row_from or "") + (row_to or "")).lower() else "SMS"


def read_messages(path, mapping=None):
    from .adapters import read_rows, InputError
    rows = read_rows(path)
    if rows and not looks_like_twilio(rows[0].keys()):
        raise InputError("%s does not look like a Twilio message export (it needs the columns %s)"
                         % (path, ", ".join(sorted(COLUMNS))))
    out = []
    for n, row in enumerate(rows):
        r = {str(k).strip().lower(): v for k, v in row.items()}
        direction = (r.get("direction") or "").strip().strip('"').lower()
        inbound = direction == "inbound"
        person = _person(r.get("from") if inbound else r.get("to"))
        try:
            error = int(str(r.get("errorcode") or "0").strip() or 0)
        except ValueError:
            error = 0
        sent = core.parse_time(r.get("sentdate"))
        raw = {"sid": r.get("sid") or "row-%d" % (n + 2), "from": r.get("from"), "to": r.get("to"),
               "person": person, "channel": _channel(r.get("from"), r.get("to")),
               "body": r.get("body") or "", "status": (r.get("status") or "").strip().lower(),
               "error": error, "direction": direction, "sent": sent,
               "sent_as_written": _as_written(r.get("sentdate"))}
        out.append(core.Record(raw["sid"], sent, person, person, FIELD, None, raw["body"], r.get("from"), raw,
                               kind=FIELD))
    _mark_api_replies(out)
    return out


def _mark_api_replies(records):
    """An outbound-api text sent within REPLY_WITHIN after an incoming text from the same person is
    the agent answering it."""
    came_in = {}
    for r in records:
        if r.raw["direction"] == "inbound" and r.raw["sent"] is not None:
            came_in.setdefault(r.raw["person"], []).append(r.raw["sent"])
    for r in records:
        x = r.raw
        x["answers"] = False
        if x["direction"] != "outbound-api" or x["sent"] is None:
            continue
        try:
            x["answers"] = any(timedelta(0) <= x["sent"] - t <= REPLY_WITHIN for t in came_in.get(x["person"], ()))
        except TypeError:           # a time with a zone and one without: not comparable, not a reply
            pass


def _direction(x):
    """The direction a check reads: an API text that answers the person counts as a reply."""
    return "outbound-reply" if x.get("answers") else x["direction"]


def _as_written(value):
    """The time with the zone offset the export wrote (the console's own zone), or None."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value).strip())
    except (TypeError, ValueError):
        return None


def twilio_adapter(path, mapping=None):
    return {"records": read_messages(path, mapping)}


def _messages(ctx):
    return [r for r in ctx.records if r.kind == FIELD]


def _show_error(code):
    if not code:
        return ""
    words = ERRORS.get(code)
    return " (error %d%s)" % (code, ": " + words if words else "")


# --- the checks -------------------------------------------------------------------------------

def failed_delivery(ctx):
    """A text the business sent that Twilio marks failed or undelivered. A text still at "sent" has
    no receipt from the carrier, which is not a failure: those are counted, never listed."""
    msgs = _messages(ctx)
    if not msgs:
        return None
    out = []
    no_receipt = 0
    for r in msgs:
        x = r.raw
        if not x["direction"].startswith("outbound"):
            continue
        if x["status"] in FAILED:
            out.append(core.Item("failed_delivery", "Twilio marks it %s%s." % (x["status"], _show_error(x["error"])),
                                 records=[r]))
        elif x["status"] == "sent":
            no_receipt += 1
    if no_receipt:
        ctx.result.notes.append("%d text%s still read \"sent\": the carrier gave no delivery receipt, which "
                                "is not a failure." % (no_receipt, "" if no_receipt == 1 else "s"))
    return out


def _same_text(a, b):
    return " ".join(a.split()).casefold() == " ".join(b.split()).casefold()


def texted_twice(ctx):
    """The same text to one person twice. For texts the agent started: twice within an hour, whatever
    came in between. For replies: twice in answer to one incoming text, since a reply to each new
    message repeats on purpose. A copy that failed, was undelivered or was canceled never reached the
    person: it is neither a copy nor a link between two copies."""
    msgs = _messages(ctx)
    if not msgs:
        return None
    by_person = {}
    for r in msgs:
        by_person.setdefault(r.raw["person"], []).append(r)
    out = []
    for person, rs in sorted(by_person.items()):
        rs = [r for r in rs if r.raw["sent"] is not None
              and not (r.raw["direction"].startswith("outbound") and r.raw["status"] in NOT_SENT)]
        # An incoming text and its automatic reply often carry the same second, and the export lists
        # the reply first: at one time, the incoming text sorts first (a reply cannot precede it).
        rs.sort(key=lambda r: (r.raw["sent"], 0 if r.raw["direction"] == "inbound" else 1))
        used = set()
        for i, a in enumerate(rs):
            if id(a) in used or not a.raw["direction"].startswith("outbound"):
                continue
            group = [a]
            for b in rs[i + 1:]:
                # chained: each copy within the hour of the copy before it (0, 50 and 100 minutes is
                # one text sent three times, not two plus one missed)
                if b.raw["sent"] - group[-1].raw["sent"] > TWICE_WITHIN:
                    break
                if b.raw["direction"] == "inbound":
                    if _direction(a.raw) == "outbound-reply":
                        break           # a new incoming text: the next reply answers it
                    continue
                # two API texts are copies whichever of them answered the person (a reminder sent
                # again after the person wrote, a confirmation re-sent after the agent's answer);
                # two replies are copies only in answer to one incoming text (the break above)
                same_kind = (a.raw["direction"] == b.raw["direction"] == "outbound-api"
                             or _direction(a.raw) == _direction(b.raw) == "outbound-reply")
                if same_kind and _same_text(a.raw["body"], b.raw["body"]):
                    group.append(b)
            if len(group) > 1:
                used.update(id(g) for g in group)
                gap = int((group[-1].raw["sent"] - group[0].raw["sent"]).total_seconds())
                when = "%d seconds" % gap if gap < 120 else "%d minutes" % (gap // 60)
                out.append(core.Item("texted_twice", "%s got the same text %d times in %s."
                                     % (person, len(group), when), records=group))
    return out


def _hm(text):
    h, _, m = str(text).partition(":")
    return int(h) * 60 + int(m or 0)


def outside_hours(ctx):
    """A text the agent started (outbound-api, not answering the person) outside permitted hours, by
    default 08:00 to 21:00 in the time zone the export writes (named in a note), or as a mapping file sets ("hours":
    {"start", "end", "tz"}). Replies answer the person's own text and may go out at any hour."""
    msgs = _messages(ctx)
    if not msgs:
        return None
    hours = (getattr(ctx, "mapping", None) or {}).get("hours") or {}
    start, end = _hm(hours.get("start", DEFAULT_HOURS[0])), _hm(hours.get("end", DEFAULT_HOURS[1]))
    tz = core.parse_offset(hours.get("tz")) if hours.get("tz") is not None else None
    shown = (hours.get("start", DEFAULT_HOURS[0]), hours.get("end", DEFAULT_HOURS[1]))
    # Said once, so a reader whose business keeps other hours sees what was checked and how to change it.
    if tz is not None:
        where = "at %s" % _offset(tz)
    else:
        # name the zone the export writes (two offsets when the file spans a clock change)
        offs = sorted({_offset(o) for o in (getattr(r.raw.get("sent_as_written"), "utcoffset", lambda: None)()
                                            for r in msgs) if o is not None})
        where = ("at %s, the time zone the export writes" % " and ".join(offs) if offs
                 else "at the times as the export writes them")
    if hours:
        ctx.result.notes.append("Permitted hours: %s to %s %s, from your mapping file." % (shown[0], shown[1], where))
    else:
        ctx.result.notes.append("Permitted hours: %s to %s %s (the default). To set your own, save "
                                "{\"hours\": {\"start\": \"07:00\", \"end\": \"20:00\", \"tz\": \"-06:00\"}} "
                                "as hours.json and run again with --map hours.json." % (shown[0], shown[1], where))
    out = []
    for r in msgs:
        x = r.raw
        local = x.get("sent_as_written") or x["sent"]
        if _direction(x) != "outbound-api" or local is None:
            continue
        if tz is not None and local.tzinfo is not None:
            local = local.astimezone(core.timezone(tz))
        minute = local.hour * 60 + local.minute
        inside = start <= minute < end if start < end else (minute >= start or minute < end)
        if not inside:
            off = local.utcoffset()
            out.append(core.Item("outside_hours", "Sent at %s%s, outside %s to %s."
                                 % (local.strftime("%H:%M"), " (%s)" % _offset(off) if off is not None else "",
                                    shown[0], shown[1]), records=[r]))
    return out


def _offset(delta):
    """-05:00 for a UTC offset of minus five hours."""
    minutes = int(delta.total_seconds() // 60)
    sign = "-" if minutes < 0 else "+"
    return "%s%02d:%02d" % (sign, abs(minutes) // 60, abs(minutes) % 60)


failed_delivery.title = "Texts that did not arrive"
texted_twice.title = "One person texted the same thing twice"
outside_hours.title = "Texts started outside permitted hours"
