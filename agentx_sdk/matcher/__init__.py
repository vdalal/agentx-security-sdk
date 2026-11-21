"""`agentx match`: check what an agent was asked, did and said against what the records show.

Runs on this machine only. It makes no network calls and sends nothing anywhere.

    agentx match --tasks tasks.csv --log agent_log.jsonl --records history.csv
    agentx match --records history.csv          (the records alone: only the checks run)
    agentx match --from-sdk --records history.csv   (the tasks and log from this SDK's own record)
    agentx match --demo                         (a planted week, to see the report)
"""
import argparse
import json
import os
import re
import sys
import time

from . import adapters, core, report
from . import calendar as _calendar

DEMO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo")
DEMO_FILES = {"tasks": "tasks.csv", "log": "agent_log.jsonl", "records": "crm_history.csv"}


class Context(object):
    """What a check is given: the inputs as read, the match result, the settings, and the mapping
    file's contents (a check may read its own keys there, like "hours")."""

    def __init__(self, tasks, runs, records, result, settings, mapping=None):
        self.tasks, self.runs, self.records, self.result, self.settings = tasks, runs, records, result, settings
        self.mapping = mapping or {}


def load_mapping(path):
    if not path:
        return {}
    if not os.path.exists(path):
        raise adapters.InputError("%s: no such mapping file" % path)
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except ValueError as e:
        raise adapters.InputError("%s is not JSON: %s" % (path, e))
    except OSError as e:
        raise adapters.InputError("%s could not be read: %s" % (path, e.strerror or e))
    if not isinstance(data, dict):
        raise adapters.InputError("%s: the mapping must be a JSON object" % path)
    for part in ("tasks", "log", "records"):
        if part in data and not isinstance(data[part], dict):
            raise adapters.InputError('%s: "%s" must be an object naming columns, like {"time": "When"}' % (path, part))
        if part in data and "owner" in data[part]:
            raise adapters.InputError('%s: "owner" goes at the top of the mapping file, not inside "%s": '
                                      '{"owner": "dr@clinic.com"}' % (path, part))
    w = data.get("window_minutes")
    if w is not None and (isinstance(w, bool) or not isinstance(w, int) or w < 0):
        raise adapters.InputError('%s: "window_minutes" must be a whole number of minutes, like 30' % path)
    for key, like in (("read_tools", "get_contact"), ("book_tools", "book_appointment"),
                      ("undo_tools", "cancel_appointment")):
        if key in data and not (isinstance(data[key], list) and all(isinstance(t, str) for t in data[key])):
            raise adapters.InputError('%s: "%s" must be a list of tool names, like ["%s"]' % (path, key, like))
    if data.get("agent_account") is not None and not isinstance(data["agent_account"], (str, int)):
        raise adapters.InputError('%s: "agent_account" must be the account name as text' % path)
    if "owner" in data and not (isinstance(data["owner"], str)
                                and re.match(r"^(mailto:)?[^@\s]+@[^@\s]+$", data["owner"].strip(), re.I)):
        raise adapters.InputError('%s: "owner" must be the calendar owner\'s email address, like "dr@clinic.com"'
                                  % path)
    if "hours" in data:
        h = data["hours"]
        ok = isinstance(h, dict) and all(re.match(r"^([01]\d|2[0-3]):[0-5]\d$", str(h[k]))
                                        for k in ("start", "end") if k in h)
        if ok and h.get("tz") is not None:
            off = core.parse_offset(h["tz"])
            ok = off is not None and abs(off.total_seconds()) < 24 * 3600
        if not ok:
            raise adapters.InputError('%s: "hours" must look like {"start": "08:00", "end": "21:00", "tz": "-05:00"}'
                                      % path)
    return data


def _match_calendar(tasks, runs, events, settings, mapping=None, unread_events=0):
    """The agent's calls against the calendar it books into. The core joins the runs and the tasks
    (a run that made no call, a task with no run), and calendar.check_bookings checks each booking
    call against the events by its own three rules: a calendar is not a change history (its event
    ids are the calendar's, its times are slots, and it holds all of its history), so its calls are
    not matched the way a change history's are."""
    result = core.match(tasks, runs, [], settings)
    mapping = mapping or {}
    book_tools, undo_tools = set(mapping.get("book_tools") or ()), set(mapping.get("undo_tools") or ())
    reads = set(settings.read_tools or ())
    # The core found no record for any call (it was given none): its per-call items are not true of
    # a calendar, and the booking check below says what is. Its "the run made no call that changes
    # anything" read tool names; here it is said from what is declared, never from a name.
    no_change = "The run made no call that changes anything."
    result.items = [i for i in result.items if i.call is None and not i.reason.startswith(no_change)]
    for run in runs or []:
        if run.untasked:
            continue
        declared = [c for c in run.calls if getattr(c, "effect", None) or c.tool in book_tools or c.tool in undo_tools]
        unknown = [c for c in run.calls if c not in declared and c.tool not in reads]
        if declared:
            continue
        task = next((t for t in (tasks or []) if t.id == run.task_id), None)
        if not unknown:
            result.items.append(core.Item(core.LIST_CLAIM_NO_RECORD, no_change + " Read its reply: if it says the "
                                          "work is done, no call of this run did it.", task, run))
        else:
            result.items.append(core.Item(core.LIST_CLAIM_NO_RECORD, "The run made no call declared as a booking "
                                          "(its other calls are named below as not checked). Read its reply: if it "
                                          "says it booked, one of those may have, or none did.", task, run,
                                          unsure=True))
    task_by_id = {t.id: t for t in (tasks or [])}
    stats = {}
    found, skipped = _calendar.check_bookings(runs, events, settings.window,
                                              lambda run: task_by_id.get(run.task_id), settings.read_tools,
                                              mapping.get("book_tools") or (), mapping.get("undo_tools") or (),
                                              stats=stats, unread=unread_events)
    result.counts["bookings_checked"] = stats.get("checked", 0)
    result.counts["bookings_as_asked"] = stats.get("as_asked", 0)
    result.items = found + result.items
    for why, tools in sorted(skipped.items()):
        result.notes.append("Not checked against the calendar, since %s: %s."
                            % (why, ", ".join("%s (%d)" % (t, n) for t, n in sorted(tools.items()))))
    result.not_checked[core.LIST_UNASKED_CHANGE] = (
        "because a calendar event usually names the calendar's owner as its organizer, whoever made the "
        "booking: the agent's bookings look the same as a person's")
    # Nothing here was worked out from the calendar: the core was given no records, and the booking
    # check reads each event's own time zone and never an account.
    for key in ("fields", "agent_account", "records_time_zone"):
        result.inferred.pop(key, None)
    result.counts["records"] = len(events)
    result.counts["events"] = sum(1 for r in events if r.kind == "event")
    for key, _title in core.LISTS:
        result.counts[key] = len(result.on(key))
    result.counts["unsure"] = len(result.unsure())
    return result


def _account_in(records, account):
    """The agent's account as the records spell it. A given account that never appears would make
    every record someone else's and every call look undone, so it stops the run instead."""
    if account in (None, ""):
        return None
    account = str(account)
    actors = sorted({str(r.actor) for r in records if r.actor not in (None, "")})
    if not actors or account in actors:
        return account
    folded = [a for a in actors if a.casefold() == account.casefold()]
    if len(folded) == 1:
        return folded[0]
    # Only a near spelling stops the run. An account that made no change this week is a real answer
    # (a quiet week, or every write failed), and a scheduled run must not fail on it.
    near = [a for a in actors if _close(a, account)]
    if near:
        raise adapters.InputError("the agent's account %r is not in the records; did you mean %s? Run again "
                                  "with --agent-account %s" % (account, " or ".join(repr(a) for a in near), near[0]))
    return account


def _close(a, b):
    """Two account names that differ only in spaces, dashes, dots or underscores, or one inside the
    other: likely the same account typed two ways."""
    def squash(s):
        return "".join(ch for ch in s.casefold() if ch.isalnum())
    sa, sb = squash(a), squash(b)
    return bool(sa) and bool(sb) and (sa == sb or (min(len(sa), len(sb)) >= 4 and (sa in sb or sb in sa)))


def run(tasks_path=None, log_path=None, records_path=None, mapping=None, adapter="generic",
        agent_account=None, window_minutes=None, sdk_path=None):
    """Read the files, match, run the checks. Returns (result, findings, inputs, plugin problems).
    `sdk_path` is the SDK's run file, read for the tasks and the log in place of `tasks_path` and
    `log_path`."""
    mapping = mapping or {}
    adapter_table, problems = adapters.load_plugins(adapters.ADAPTER_GROUP, adapters.BUILT_IN_ADAPTERS)
    check_table, check_problems = adapters.load_plugins(adapters.CHECK_GROUP, adapters.BUILT_IN_CHECKS)
    problems += check_problems
    if adapter not in adapter_table:
        raise adapters.InputError("no reader named %r (installed: %s)" % (adapter, ", ".join(sorted(adapter_table))))
    if not records_path:
        raise adapters.InputError("--records is needed: the records are what everything is checked against")

    tasks = adapters.read_tasks(tasks_path, mapping.get("tasks")) if tasks_path else None
    runs = adapters.read_runs(log_path, mapping.get("log")) if log_path else None
    sdk_notes = []
    if sdk_path:
        from . import sdk_log
        tasks, runs, sdk_notes = sdk_log.read(sdk_path)
    if adapter == "generic":
        adapter = adapters.sniff(records_path)     # a calendar or a Twilio export needs no --adapter
        if adapter == "generic":
            from . import twilio as _twilio
            wrong = _twilio.wrong_twilio_file(records_path)    # Twilio's call log or API, said in words
            if wrong:
                raise adapters.InputError(wrong)
    reader_notes, unread_events = [], 0
    if adapter == "generic":
        records = adapters.read_records(records_path, mapping.get("records"))
    else:
        rec_map = mapping.get("records") or {}
        if adapter == "ics":
            # whose calendar it is comes only from the top-level "owner", which load_mapping checked
            rec_map = {k: v for k, v in rec_map.items() if k != "owner"}
            if mapping.get("owner"):
                rec_map["owner"] = mapping["owner"]
        got = adapter_table[adapter](records_path, rec_map)
        records = list(got.get("records", []))
        unread_events = got.get("unread_events") or 0     # calendar events left out: no readable start
        reader_notes = [str(n) for n in (got.get("notes") or []) if isinstance(n, str)]
        if tasks is None and got.get("tasks") is not None:
            tasks = list(got["tasks"])
        if runs is None and got.get("runs") is not None:
            runs = list(got["runs"])

    rec_map = mapping.get("records") or {}
    # A calendar checked against the agent's calls has its own booking check (_match_calendar).
    by_booking = adapter == "ics" and runs is not None
    settings = core.Settings(
        agent_account=_account_in(records, agent_account or mapping.get("agent_account")),
        records_tz=core.parse_offset(rec_map.get("tz")) if rec_map.get("tz") else None,
        window_minutes=window_minutes or mapping.get("window_minutes") or core.DEFAULT_WINDOW_MINUTES,
        read_tools=mapping.get("read_tools") or (),
    )
    try:
        result = (_match_calendar(tasks, runs, records, settings, mapping, unread_events) if by_booking
                  else core.match(tasks, runs, records, settings))
    except core.MatchStop as e:
        raise adapters.InputError(str(e))
    if adapter == "ics":
        result.records_kind = "calendar"            # said as "calendar events", an empty file too
    result.notes.extend(sdk_notes + reader_notes)   # what the readers had to say about the files, by name
    # Events the reader could not put on one clock with the rest: checked only among themselves, so
    # a run with any of them is not clean (the reader's note says which and why).
    result.counts["events_apart"] = sum(1 for r in records if r.kind == "event" and r.raw.get("apart"))
    # Events no check reads (cancelled, marked free, all day), and the dates the file covers: said
    # beside the count, so a clash that is not listed can be told from an event that was skipped.
    result.counts["events_skipped"] = sum(1 for r in records if r.kind == "event" and (
        r.raw.get("status") == "CANCELLED" or r.raw.get("transparent") or r.raw.get("all_day")))
    days = sorted(d for d in (_day(r) for r in records) if d is not None)
    if days:
        result.counts["first_date"], result.counts["last_date"] = days[0], days[-1]
    findings = []
    ctx = Context(tasks, runs, records, result, settings, mapping)
    for name in check_table:        # built-ins in the order declared, then plug-ins

        try:
            got = check_table[name](ctx)
            if got is not None:
                got = list(got)     # consumed here, so a check that breaks while yielding is reported
        except Exception as e:
            # a check that could not finish is said in the headline and counts like unsure: never clean
            # (ours: a built-in check, so the fault is agentx match's to fix; else the plug-in's)
            result.checks_failed.append((name, getattr(check_table[name], "title", name), str(e) or type(e).__name__,
                                         check_table[name] is adapters.BUILT_IN_CHECKS.get(name)))
            continue
        if got is None:
            continue        # nothing in these records for this check to read
        result.checks_ran.append((name, getattr(check_table[name], "title", name)))
        findings.extend(got)
    if by_booking:
        # One double booking can show three ways: the agent's two calls ("Done twice") and the
        # calendar's own two checks. Said, so the reader sees one problem, not three.
        twice = {r.id for i in result.items if i.list_key == core.LIST_DUPLICATE and not i.unsure
                 for r in i.records}
        for f in findings:
            if getattr(f, "records", None) and all(r.id in twice for r in f.records):
                f.reason += ' The same bookings are under "Done twice" above.'
    inputs = ({"sdk log": sdk_path, "records": records_path} if sdk_path
              else {"tasks": tasks_path, "log": log_path, "records": records_path})
    return result, findings, inputs, problems


def _day(r):
    """The date of a calendar event or a text as its reader would see it (an event in the calendar's
    own zone, a text as the export wrote it), as YYYY-MM-DD; None for any other record."""
    if r.kind == "event":
        when, shown_in = r.raw.get("start"), r.raw.get("shown_in")
        if hasattr(when, "tzinfo") and getattr(when, "tzinfo", None) is not None and shown_in is not None:
            when = when.astimezone(shown_in)
    elif r.kind == "message":
        when = r.raw.get("sent_as_written") or r.raw.get("sent")
    else:
        return None
    return when.strftime("%Y-%m-%d") if hasattr(when, "strftime") else None


def _parser():
    p = argparse.ArgumentParser(
        prog="agentx match",
        description="Check what an agent was asked, did and said against what the records show. "
                    "Runs on this machine; nothing is sent anywhere.")
    p.add_argument("--tasks", metavar="FILE", help="what the agent was asked: CSV or JSON, one row per task")
    p.add_argument("--log", metavar="FILE", help="what the agent did and said: JSON Lines, JSON or CSV")
    p.add_argument("--records", metavar="FILE", help="what the system shows changed: CSV or JSON, one row per change")
    p.add_argument("--map", dest="map_path", metavar="FILE",
                   help="a JSON file naming columns, time zones and the agent's account")
    p.add_argument("--adapter", default="generic", metavar="NAME", help="the reader for --records (default: generic)")
    p.add_argument("--agent-account", metavar="NAME", help="the account the agent's changes are recorded under")
    p.add_argument("--window", type=int, metavar="MINUTES",
                   help="how long after a call its record may appear, and how close the same call made "
                        "again must be to the one before to count as the same piece of work (default 30)")
    p.add_argument("--out", metavar="NAME", help="also write the report to NAME.md and NAME.json")
    p.add_argument("--json", action="store_true", help="print the report as JSON, for a program")
    p.add_argument("--demo", action="store_true", help="show the report on a practice week with 11 mistakes planted")
    p.add_argument("--from-sdk", dest="from_sdk", nargs="?", const="", metavar="FILE",
                   help="read the tasks and the log from this SDK's own record (agentx_sdk.task() and "
                        "reply(), with AGENTX_KEEP_ARG_VALUES=1) instead of --tasks and --log")
    return p


def _shown(path):
    """The run file as "Files read" names it: from the working folder when it sits in it (the
    usual case, `.agentx.db.runs.jsonl`), in full otherwise."""
    try:
        rel = os.path.relpath(path)
    except (ValueError, OSError):           # another drive on Windows; a deleted working folder
        return path
    return path if rel == os.pardir or rel.startswith(os.pardir + os.sep) else rel


def main(argv=None):
    """Returns the exit code: 0 when nothing was found, 1 when anything is listed or unsure, 2 on a
    usage or file problem (so a scheduled run can tell the three apart)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_args(argv)
    if args.window is not None and args.window < 0:
        print("agentx match: --window must be a whole number of minutes, like 30", file=sys.stderr)
        return 2
    if args.demo:
        if args.tasks or args.log or args.records:
            print("agentx match: --demo runs on its own files; leave out --tasks, --log and --records.", file=sys.stderr)
            return 2
        args.tasks, args.log, args.records = (os.path.join(DEMO_DIR, DEMO_FILES[k]) for k in ("tasks", "log", "records"))
    sdk_path = None
    if args.from_sdk is not None:
        if args.demo or args.tasks or args.log:
            print("agentx match: --from-sdk reads the tasks and the log from this SDK's record; leave out "
                  "--tasks, --log and --demo.", file=sys.stderr)
            return 2
        from .. import runs as runs_module
        sdk_path = args.from_sdk or _shown(runs_module.path())
    started = time.time()
    try:
        mapping = load_mapping(args.map_path)
        result, findings, inputs, problems = run(args.tasks, args.log, args.records, mapping, args.adapter,
                                                 args.agent_account, args.window, sdk_path=sdk_path)
    except adapters.InputError as e:
        print("agentx match: %s" % e, file=sys.stderr)
        return 2
    if args.demo:
        inputs = {"files": "the built-in practice week, with 11 mistakes planted on purpose"}
    elif args.map_path:
        inputs["map"] = args.map_path       # listed under "Files read", so the reader sees it was used
    doc = report.to_json(result, inputs, findings, problems)
    doc["seconds"] = round(time.time() - started, 3)
    md = report.to_markdown(result, inputs, findings, problems, demo=args.demo)
    screen = report.to_markdown(result, inputs, findings, problems, plain=True, demo=args.demo)
    if args.out:
        try:
            with open(args.out + ".md", "w", encoding="utf-8") as fh:
                fh.write(md)
            with open(args.out + ".json", "w", encoding="utf-8") as fh:
                fh.write(report.dumps(doc))
        except OSError as e:
            print("agentx match: could not write %s.md and %s.json: %s" % (args.out, args.out, e.strerror or e),
                  file=sys.stderr)
            return 2
    if args.json:
        print(report.dumps(doc))
    else:
        print(screen)
        if args.out:
            print("Saved:\n  %s.md\n  %s.json" % (args.out, args.out))
    # A run that checked nothing is a usage problem, not a clean run; unsure, a check that could not
    # finish, and events that could not be compared with the rest count as found.
    if report.nothing_checked(result, findings):
        return 2
    found = (sum(result.counts.get(k, 0) for k, _t in core.LISTS) + len(findings) + result.counts.get("unsure", 0)
             + len(result.checks_failed) + result.counts.get("events_apart", 0))
    return 1 if found else 0
