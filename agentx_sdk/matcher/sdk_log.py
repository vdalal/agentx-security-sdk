"""The SDK's own record as `agentx match`'s tasks and log: `agentx match --from-sdk --records FILE`.

Reads the run file beside the ledger (`agentx_sdk/runs.py`): each `agentx_sdk.task()` is a task,
the protected calls that ran under it are its run, and its `agentx_sdk.reply()` is what the agent
said. A call is matched to a record by its argument values, so the values must have been kept
(AGENTX_KEEP_ARG_VALUES=1 where the agent ran); a task with a call recorded without them is left
out and counted, never guessed at.
"""
from . import core
from .adapters import InputError
from ..runs import WITHHELD

KEEP_VALUES_HINT = ("Set AGENTX_KEEP_ARG_VALUES=1 where the agent runs, run it again, then run this "
                    "command again.")


def _known(value):
    """False for a value the run file did not keep whole: "[withheld]", or a value cut short ("...
    [cut: N characters in all]"). Compared with a record, either would read as the call asking for
    something else."""
    if value == WITHHELD:
        return False
    return not (isinstance(value, str) and value.endswith(" characters in all]") and " [cut: " in value)


def _raised_text(value):
    """What a call raised, as words, or None when it raised nothing. The SDK writes the error's
    name; a run file written another way may hold true, an object, or an empty value here."""
    if value is None or value is False:
        return None
    if value is True:
        return "an error"
    if isinstance(value, dict):
        for key in ("type", "name", "error", "message"):
            if isinstance(value.get(key), str) and value[key].strip():
                return value[key].strip()
        return "an error" if value else None
    if isinstance(value, (list, tuple)):
        return "an error" if value else None
    text = str(value).strip()
    return text or None


def read(file_path):
    """(tasks, runs, notes) from the run file at `file_path`. Raises InputError when there is
    nothing to check."""
    from .. import runs as runs_module
    import os
    if not os.path.exists(file_path):
        raise InputError("%s: no record of tasks here. The agent writes it when it calls "
                         "agentx_sdk.task() at the start of each task (and agentx_sdk.reply() at the end), "
                         "with AGENTX_KEEP_ARG_VALUES=1 set." % file_path)
    entries = runs_module.read(file_path)
    utc = core.parse_offset("UTC")
    tasks, order = {}, []
    groups = {}             # run id -> {"task", "time", "calls", "reply", "no_values"}
    read_backs = {"confirmed": 0, "not_confirmed": 0, "could_not_check": 0}

    def group(entry):
        task_id = entry.get("task")
        task_id = str(task_id) if task_id not in (None, "") else None
        # Each task() is its own run (its "run" id), so a task id used twice is two runs. A line
        # written before runs had ids falls back to its task id, and a call made with no task (values
        # kept, no task running) to its trace.
        if entry.get("run"):
            rid = "%s/%s" % (task_id, entry["run"]) if task_id else "run-%s" % entry["run"]
        elif task_id:
            rid = task_id
        else:
            rid = "trace-%s" % str(entry.get("trace") or "none")[:8]
        if rid not in groups:
            groups[rid] = {"rid": rid, "task": task_id, "time": core.parse_time(entry.get("time"), utc),
                           "calls": [], "reply": "", "no_values": 0, "started": False}
            order.append(rid)
        return groups[rid]

    for e in entries:
        kind = e.get("kind")
        if kind == "task" and e.get("task") not in (None, ""):
            tid = str(e["task"])
            if tid not in tasks:
                tasks[tid] = core.Task(tid, core.parse_time(e.get("time"), utc), e.get("text") or "", e)
            else:
                tasks[tid].text = e.get("text") or tasks[tid].text      # the latest words for one id
            g = group(e)
            g["started"] = True
            g["time"] = core.parse_time(e.get("time"), utc)
            g["clock_assumed"] = core.clock_assumed(e.get("time"), False)
        elif kind == "call" and e.get("tool"):
            g = group(e)
            if not isinstance(e.get("args"), dict):
                g["no_values"] += 1
                continue
            # A withheld or cut value is left out, so it is never compared: the call is matched by
            # what was kept, or, with nothing to match by, listed as unsure.
            kept = {k: v for k, v in e["args"].items() if _known(v)}
            g["unknown_values"] = g.get("unknown_values", 0) + len(e["args"]) - len(kept)
            call = core.Call(e["tool"], kept, core.parse_time(e.get("time"), utc))
            call.clock_assumed = core.clock_assumed(e.get("time"), False)   # the SDK writes UTC; a hand-made line may not
            call.unknown_args = {str(k): v for k, v in e["args"].items() if not _known(v)}
            call.read_back = e.get("read_back")
            call.raised = _raised_text(e.get("raised"))
            call.effect = e.get("effect") if e.get("effect") in runs_module.EFFECTS else None
            g["calls"].append(call)
        elif kind == "reply":
            g = group(e)
            g["reply"] = e.get("text") or ""

    runs, dropped_tasks, dropped_calls, headless = [], 0, 0, 0
    dropped_ids, kept_ids = set(), set()
    for rid in order:
        g = groups[rid]
        if g["no_values"]:
            # Half a run would read as a claim with no call behind it: leave the whole task out.
            dropped_tasks += 1
            dropped_calls += g["no_values"]
            if g["task"]:
                dropped_ids.add(g["task"])
            continue
        if g["task"] and not g["started"]:
            # Its task line is not in the file (written by an older SDK, or the file was cut): its
            # calls without its start would be checked against nothing it was asked.
            headless += 1
            continue
        if not g["calls"] and not g["reply"]:
            # task() and nothing after it: a task with no run (list 5), never an empty claim.
            continue
        if g["task"]:
            kept_ids.add(g["task"])
        # A run with no task id is the SDK's calls between tasks (each gap its own run): no task's
        # run, so never linked to one by time.
        runs.append(core.Run(rid, g["task"], g["time"], g["calls"], g["reply"], {"from": "sdk"},
                             untasked=not g["task"]))
        runs[-1].clock_assumed = g.get("clock_assumed", False)
    for tid in dropped_ids - kept_ids:
        tasks.pop(tid, None)

    if not runs and dropped_tasks:
        raise InputError("%s: the calls here were recorded without their argument values, so none can be "
                         "matched to a record. %s" % (file_path, KEEP_VALUES_HINT))
    if not runs and not tasks:
        raise InputError("%s: no task was recorded here yet. The agent writes one when it calls "
                         "agentx_sdk.task() at the start of each task." % file_path)
    for run in runs:
        for call in run.calls:
            if getattr(call, "read_back", None) in read_backs:
                read_backs[call.read_back] += 1
    notes = []
    if dropped_tasks:
        notes.append("%d %s left out: %d of %s calls %s recorded without argument values, and a call "
                     "without them cannot be matched to a record. %s"
                     % (dropped_tasks, "task was" if dropped_tasks == 1 else "tasks were", dropped_calls,
                        "its" if dropped_tasks == 1 else "their", "was" if dropped_calls == 1 else "were",
                        KEEP_VALUES_HINT))
    unknown = sum(groups[run.id].get("unknown_values", 0) for run in runs if run.id in groups)
    if unknown:
        notes.append("%d argument %s withheld or cut short in the run file, so %s not compared with "
                     "the records. A call with one is never taken for a repeat of another, and with "
                     "nothing else to name its record it is listed as unsure."
                     % (unknown, "value was" if unknown == 1 else "values were",
                        "it was" if unknown == 1 else "they were"))
    if headless:
        notes.append("%d %s left out: %s start (the task() line) is not in the file, so %s calls cannot "
                     "be checked against what was asked."
                     % (headless, "run was" if headless == 1 else "runs were",
                        "its" if headless == 1 else "their", "its" if headless == 1 else "their"))
    raised = sum(1 for run in runs for call in run.calls if getattr(call, "raised", None))
    if raised:
        notes.append("%d of these calls raised an error after the tool started, so %s work may or may "
                     "not have landed. An item about such a call, or about another try of the same "
                     "call, names the error. A call that raised, with no record and no try of it that "
                     "went through, is listed as unsure, not under \"Said it was done\"."
                     % (raised, "its" if raised == 1 else "their"))
    if any(read_backs.values()):
        parts = ["%d confirmed" % read_backs["confirmed"]]
        if read_backs["not_confirmed"]:
            parts.append("%d not confirmed" % read_backs["not_confirmed"])
        if read_backs["could_not_check"]:
            parts.append("%d where the read-back itself failed" % read_backs["could_not_check"])
        notes.append("verify= read back %d of these calls: %s." % (sum(read_backs.values()), ", ".join(parts)))
    task_list = [tasks[t] for t in sorted(tasks, key=lambda t: (tasks[t].time is None, tasks[t].time, t))] \
        if tasks else None
    return task_list, runs, notes
