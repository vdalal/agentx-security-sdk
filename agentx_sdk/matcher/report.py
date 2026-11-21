"""The report: Markdown for a file, plain text for the screen, JSON for a program. Each says what was
assumed about the files, so a reader can tell a finding from a guess about their data."""
import json
import textwrap

from . import core

PACKAGE = "agentx-security-sdk"
SITE = "https://agentx-core.com"


def _version():
    try:
        from agentx_sdk import __version__
        return __version__
    except Exception:
        return "unknown"


def produced_by():
    """What made the report, for anyone the file reaches."""
    return {"tool": "agentx match", "package": PACKAGE, "version": _version(), "url": SITE}


def to_json(result, inputs, findings=(), plugin_problems=()):
    lists = {}
    for key, _title in core.LISTS:
        lists[key] = [i.to_dict() for i in result.on(key)]
    return {
        "produced_by": produced_by(),
        "inputs": inputs,
        # what the matching assumed, only when matching ran: the screen leaves it out on the same rule,
        # and a calendar-only run assumes nothing about records' time zones or the agent's account
        "inferred": {} if all(k in result.not_checked for k, _t in core.LISTS) else result.inferred,
        "counts": result.counts,
        "lists": lists,
        "not_checked": result.not_checked,
        "checks_ran": [name for name, _title in result.checks_ran],
        "checks_failed": [{"check": name, "error": why, "built_in": ours}
                          for name, _title, why, ours in result.checks_failed],
        "notes": list(result.notes),
        "unsure": [i.to_dict() for i in result.unsure()],
        "findings": [f.to_dict() for f in findings],
        "plugin_problems": list(plugin_problems),
    }


def _cell(v, limit=70):
    s = "" if v is None else str(v)
    s = " ".join(s.split()).replace("|", "/")
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _item_lines(item, bold):
    head = []
    if item.task is not None:
        head.append("task %s" % item.task.id)
    if item.run is not None:
        head.append("run %s" % item.run.id)
    if item.call is not None:
        # Every argument as the log wrote it, a withheld or cut one included ("[withheld]"), so a
        # call whose id was withheld does not read as one that named nothing.
        shown = dict(item.call.args, **getattr(item.call, "unknown_args", {}))
        args = ", ".join("%s=%s" % (k, _cell(v, 30)) for k, v in shown.items())
        head.append("%s(%s)" % (item.call.tool, args))
    events = bool(item.records) and all(r.kind in ("event", "message") for r in item.records)
    if not head and item.records and not events:
        r = item.records[0]
        head.append("%s, %s" % (r.entity_name or r.entity_id or "", r.field or ""))
    out = ["- %s: %s" % (bold(", ".join(head)), item.reason) if head else "- %s" % item.reason]
    if item.task is not None and item.task.text:
        out.append("  - Asked: \"%s\"" % _cell(item.task.text, 120))
    if item.run is not None and item.run.reply:
        out.append("  - The agent said: \"%s\"" % _cell(item.run.reply, 120))
    # An event in a calendar that names no zone is shown in the offset the call wrote its time in, so
    # the booking reads beside the call ("12:00 to 12:45 -05:00" under "12:00:00-05:00", not in UTC).
    offsets = {core.offset_of(v) for v in (item.call.args.values() if item.call is not None else ())} - {None}
    like = offsets.pop() if len(offsets) == 1 else None
    for r in item.records:
        if r.kind == "message":
            x = r.raw
            when = x["sent_as_written"] or x["sent"]
            out.append("  - %s, %s, to %s (%s), %s: \"%s\"" % (
                r.id, _stamp(when) if hasattr(when, "strftime") else "no time",
                x["person"], x["channel"], x["status"] or "no status", _cell(x["body"], 100)))
            continue
        if r.kind == "event":
            x = r.raw
            # a long guest list (16 on a real calendar) is cut to three: the finding names who matters
            guests = list(x.get("attendees") or [])
            who = (", ".join(guests[:3]) + (" and %d others" % (len(guests) - 3) if len(guests) > 3 else "")) \
                or "no attendee listed"
            # the event's UID stays in the JSON: no calendar shows it and no command takes it
            # an event with no title says so: its ID (19vl1s7...@google.com) reads like an address
            out.append("  - %s, %s, with %s" % (_cell(x.get("summary") or "(no title)", 50), _span(x, like), who))
            continue
        when = r.time.strftime("%Y-%m-%d %H:%M") if r.time else "no time"
        out.append("  - Record %s, %s: %s %s, %s -> %s, by %s" % (
            r.id, when, _cell(r.entity_name or r.entity_id), _cell(r.field), _cell(r.old, 30) or "(empty)",
            _cell(r.new, 30), r.actor or "unknown"))
    return out


def _stamp(when):
    """A time with its UTC offset written as -05:00, the one offset style on every screen."""
    off = when.utcoffset() if getattr(when, "tzinfo", None) is not None else None
    if off is None:
        return when.strftime("%Y-%m-%d %H:%M")
    m = int(off.total_seconds() // 60)
    return "%s %s%02d:%02d" % (when.strftime("%Y-%m-%d %H:%M"), "-" if m < 0 else "+", abs(m) // 60, abs(m) % 60)


def _n(count, word):
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def _span(x, like=None):
    """An event's start and end in the calendar's own zone (as its owner reads it: "16:00 to 16:30
    EST"); when the calendar names no zone this Python reads, in the offset `like` (the call's,
    "-05:00"), else in UTC; as written when the time had none."""
    s, e = x.get("start"), x.get("end")
    if not hasattr(s, "strftime"):
        return "no time"
    zone = ""
    if getattr(s, "tzinfo", None) is not None:
        shown_in = x.get("shown_in")
        if shown_in is not None:
            s = s.astimezone(shown_in)
            e = e.astimezone(shown_in) if getattr(e, "tzinfo", None) is not None else e
            zone = " " + (s.tzname() or "")
        elif like is not None:
            s = s.astimezone(like)
            e = e.astimezone(like) if getattr(e, "tzinfo", None) is not None else e
            zone = " " + _stamp(s).rsplit(" ", 1)[1]
        else:
            zone = " UTC"
    if hasattr(e, "strftime") and getattr(e, "date", None) and e.date() == s.date():
        return "%s to %s%s" % (s.strftime("%Y-%m-%d %H:%M"), e.strftime("%H:%M"), zone)
    if hasattr(e, "strftime"):
        return "%s to %s%s" % (s.strftime("%Y-%m-%d %H:%M"), e.strftime("%Y-%m-%d %H:%M"), zone)
    return s.strftime("%Y-%m-%d %H:%M") + zone


_HOW = {"given": "as given", "inferred": "worked out from the files", "assumed": "assumed",
        "unknown": "not known"}


def _on_its_own(result):
    """What a run that read only the records checked, in the reader's words ("calendar"), or None when
    the run matched tasks and a log (or checked nothing at all)."""
    if not all(k in result.not_checked for k, _t in core.LISTS):
        return None
    if getattr(result, "records_kind", None) == "calendar":
        return "calendar"           # an empty one too: its checks read it alone, and found nothing to read
    if not (result.checks_ran or result.checks_failed):
        return None
    c = result.counts
    if c.get("records") and c.get("events") == c["records"]:
        return "calendar"
    if c.get("records") and c.get("messages") == c["records"]:
        return "text messages"
    return "records"


def _title(result):
    what = _on_its_own(result)
    if what is None:
        return "What the agent did, checked against the records"
    return "Your %s, checked on %s own" % (what, "its" if what == "calendar" else "their")


def to_markdown(result, inputs, findings=(), plugin_problems=(), plain=False, demo=False):
    """`plain` drops the Markdown marks a terminal would print as they are."""
    def h(level, text):
        return text if plain else "%s %s" % ("#" * level, text)

    def bold(text):
        return text if plain else "**%s**" % text

    c = result.counts
    lines = [h(1, _title(result)), ""]
    if demo:
        lines.append("A practice week with 11 mistakes planted on purpose.")
    else:
        lines.append("Files read:")
        for k, v in inputs.items():
            if v:
                lines.append("  %-8s %s" % (k, v))
    lines.append("")
    seen = []
    if inputs.get("tasks") or inputs.get("sdk log") or demo:
        seen.append("%d tasks" % c.get("tasks", 0))
    if inputs.get("log") or inputs.get("sdk log") or demo:
        seen.append("%d runs with %d calls" % (c.get("runs", 0), c.get("calls", 0)))
    recs = _n(c.get("records", 0), "record")
    if getattr(result, "records_kind", None) == "calendar":
        recs = _n(c.get("events", 0), "calendar event")
    elif c.get("events"):
        recs = _n(c["events"], "calendar event") if c["events"] == c.get("records") else \
            "%s, %d of them calendar events" % (recs, c["events"])
    if c.get("messages"):
        recs = _n(c["messages"], "text message") if c["messages"] == c.get("records") else \
            "%s, %d of them text messages" % (recs, c["messages"])
    if c.get("first_date") and (c.get("events") or c.get("messages")):
        # the period the file covers: a calendar export can hold ten years
        recs += (", %s to %s" % (c["first_date"], c["last_date"]) if c["first_date"] != c["last_date"]
                 else ", on %s" % c["first_date"])
    if c.get("events_skipped"):
        recs += " (%d cancelled, marked free or all day, so not checked)" % c["events_skipped"]
    if c.get("records_by_others", 0):
        recs += " (%d by the agent's account, %d by others)" % (c.get("records_by_agent", 0), c.get("records_by_others", 0))
    seen.append(recs)
    lines.append(", ".join(seen) + ".")
    if "bookings_checked" in c:
        # A booking the calendar shows as asked is in no list: said here, so it reads as checked, not skipped.
        n = c["bookings_checked"]
        lines.append("%s checked against the calendar; %d %s on it as the call asked." % (
            _n(n, "booking call"), c.get("bookings_as_asked", 0), "is" if c.get("bookings_as_asked", 0) == 1 else "are"))
    lines.append("")
    total = sum(c.get(k, 0) for k, _t in core.LISTS) + len(findings)
    unsure_n = c.get("unsure", 0)
    if nothing_checked(result, findings) and _on_its_own(result) == "calendar":
        lines.append(bold("Nothing was checked: no event in the calendar file could be read (see the note below)."))
    elif nothing_checked(result, findings):
        lines.append(bold("Nothing was checked: every list needs the agent's log (--log), and no check "
                          "reads these records alone."))
    elif total or unsure_n or result.checks_failed or c.get("events_apart"):
        summary = "%d to look at" % total
        if unsure_n:
            summary += ", %d unsure" % unsure_n
        if result.checks_failed:
            # a check that broke found nothing because it did not finish: never a clean headline
            n = len(result.checks_failed)
            summary += ", %d check%s could not finish" % (n, "" if n == 1 else "s")
        if c.get("events_apart"):
            # nor is a run where some events were checked only among themselves (the note says why)
            n = c["events_apart"]
            summary += ", %s could not be compared with the rest (see the note)" % _n(n, "event")
        lines.append(bold(summary + "."))
    elif result.checks_ran and all(k in result.not_checked for k, _t in core.LISTS):
        lines.append(bold("Nothing to look at: the checks that ran found nothing."))
    else:
        lines.append(bold("Nothing to look at: every check that could run found the records agree."))
    lines.append("")

    lists_off = all(k in result.not_checked for k, _t in core.LISTS)
    inf = result.inferred
    if lists_off:
        # Nothing was matched, so nothing was assumed about the matching; say only what applies.
        _records_only(lines, result, findings, h, bold)
        return _close(lines, result, plugin_problems, plain, demo)
    assumed = []
    # A calendar check assumes neither (calendar._match_calendar drops them): each event states its
    # own zone, and no account is read.
    if "agent_account" in inf:
        acct = inf["agent_account"]
        if acct.get("value"):
            assumed.append("- The agent's account in the records: %s (%s)." % (
                acct["value"], _HOW.get(acct.get("how"), acct.get("how", ""))))
        else:
            assumed.append("- The agent's account in the records: not known.")
    if "records_time_zone" in inf:
        tz = inf["records_time_zone"]
        assumed.append("- The records' times are in %s (%s)." % (tz.get("value"), _HOW.get(tz.get("how"), tz.get("how", ""))))
    if inf.get("other_accounts"):
        assumed.append("- Changes by other accounts are not counted: %s." % ", ".join(inf["other_accounts"]))
    if inf.get("fields"):
        assumed.append("- Which call writes which field: %s." % "; ".join(inf["fields"]))
    linked = inf.get("runs_linked_to_tasks")
    if linked:
        assumed.append("- Runs with no task id, linked to a task by time and the record's name: %d; by time "
                       "only: %d; not linked: %d." % (linked["by_time_and_name"], linked["by_time_only"],
                                                      linked["not_linked"]))
    notes = ["- %s" % note for note in result.notes]
    if assumed:
        # the reader's notes sit with the assumptions, as before; the mapping line is said only when
        # something was assumed (a note says its own fix)
        lines.append(h(2, "What it assumed about the files"))
        lines.append("")
        lines.extend(assumed[:2] + notes + assumed[2:])
        lines.append("- If any of these is wrong, set it in a mapping file (--map) and run again.")
        lines.append("")
    elif notes:
        lines.append(h(2, "About the files"))
        lines.append("")
        lines.extend(notes)
        lines.append("")

    for n, (key, title) in enumerate(core.LISTS, 1):
        items = result.on(key)
        if key in result.not_checked:
            lines.append(h(2, "%d. %s: not checked, %s" % (n, title, result.not_checked[key])))
            lines.append("")
            continue
        lines.append(h(2, "%d. %s (%d)" % (n, title, len(items))))
        lines.append("")
        if not items:
            lines.append("None.")
        for item in items:
            lines.extend(_item_lines(item, bold))
        lines.append("")

    _checks(lines, result, findings, h, bold)

    unsure = result.unsure()
    if unsure:
        lines.append(h(2, "Unsure (%d)" % len(unsure)))
        lines.append("")
        for item in unsure:
            lines.extend(_item_lines(item, bold))
        lines.append("")
    return _close(lines, result, plugin_problems, plain, demo)


def _records_only(lines, result, findings, h, bold):
    # Said once: when no check ran, the summary line above already says the log is needed.
    what = _on_its_own(result)
    if what:
        lines.append("To also check %s against what the agent was asked to do and did, add the tasks "
                     "(--tasks) and the agent's log (--log)." % ("it" if what == "calendar" else "them"))
        lines.append("")
    for note in result.notes:
        lines.append("Note: %s" % note)
    if result.notes:
        lines.append("")
    _checks(lines, result, findings, h, bold)


def _checks(lines, result, findings, h, bold):
    """Each check that ran, under its own title, with what it found or "None."."""
    shown = set()
    for name, title in result.checks_ran:
        mine = [f for f in findings if f.list_key == name]
        shown.update(id(f) for f in mine)
        lines.append(h(2, "%s (%d)" % (title, len(mine))))
        lines.append("")
        if not mine:
            lines.append("None.")
        for f in mine:
            lines.extend(_item_lines(f, bold))
        lines.append("")
    rest = [f for f in findings if id(f) not in shown]
    if rest:
        lines.append(h(2, "Other checks (%d)" % len(rest)))
        lines.append("")
        for f in rest:
            lines.extend(_item_lines(f, bold))
        lines.append("")
    if result.checks_failed:
        lines.append(h(2, "Checks that could not finish (%d)" % len(result.checks_failed)))
        lines.append("")
        for _name, title, why, ours in result.checks_failed:
            if ours:
                from ..pulse import FEEDBACK_ISSUES_URL
                lines.append("- %s: this check stopped partway, so what it would have found is not known. This "
                             "is a fault in agentx match, not in your file; the other results stand. Please report "
                             "it: %s (it said: \"%s\")" % (title, FEEDBACK_ISSUES_URL, _cell(why, 120)))
            else:
                lines.append("- %s: this check stopped partway, so what it would have found is not known. It is "
                             "a plug-in, not part of agentx match; the other results stand. Its error: \"%s\""
                             % (title, _cell(why, 120)))
        lines.append("")


def _close(lines, result, plugin_problems, plain, demo):
    for p in plugin_problems:
        lines.append("Note: %s" % p)
    # How it was checked travels with the report: a teammate or a client who receives the file can
    # see what made it and run it on their own agent. The screen leaves out the version and the
    # install line (its reader already has it); the saved file carries both.
    if plain:
        lines.append("Checked with agentx match, part of the open-source AgentX SDK (agentx-core.com). "
                     "Nothing left this machine.")
        if demo:
            lines.append("")
            lines.append("To check your own agent:")
            lines.append("  agentx match --tasks FILE --log FILE --records FILE")
    else:
        lines.append("Checked with agentx match (%s %s), part of the open-source AgentX SDK: %s. Nothing "
                     "left the machine it ran on." % (PACKAGE, _version(), SITE))
        lines.append("")
        lines.append("To check your own agent: `pip install %s`, then `agentx match --demo`." % PACKAGE)
    if plain:
        lines = [w for line in lines for w in _wrap(line)]
    return "\n".join(lines) + "\n"


def nothing_checked(result, findings=()):
    """True when no list could be made and no check found anything to say: a report of nothing,
    which must not read, or exit, as a clean one."""
    return (all(k in result.not_checked for k, _t in core.LISTS) and not result.checks_ran and not findings
            and not result.checks_failed)


SCREEN_WIDTH = 75


def _wrap(line):
    """A screen line folded at 75 columns, continuation lines indented under the text they continue."""
    if len(line) <= SCREEN_WIDTH:
        return [line]
    stripped = line.lstrip()
    lead = line[:len(line) - len(stripped)]
    hang = lead + ("  " if stripped.startswith("- ") else "")
    return textwrap.wrap(line, SCREEN_WIDTH, subsequent_indent=hang, break_long_words=False,
                         break_on_hyphens=False) or [line]


def dumps(doc):
    return json.dumps(doc, indent=2, sort_keys=False)
