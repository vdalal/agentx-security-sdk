"""`agentx-mcp --demo`: see a dangerous MCP tools/call get blocked and coached, keyless.

The MCP twin of `agentx demo`. It drives the SAME proxy (`run_proxy`) your MCP client
spawns when you set `"command": "agentx-mcp"` in mcp.json, feeding it two tool calls so
you can watch the shield work without a full MCP client:

  1. run_sql("DROP TABLE users")                      -> BLOCKED before it reaches the server
  2. run_sql("SELECT id FROM users WHERE id = 42")    -> ALLOWED, reaches the server

The block comes back to the calling model as a coaching error it can self-correct on. The
run survives, that is the whole point versus a hard 403.

WHY THIS LIVES IN THE PACKAGE and not in `examples/`: examples are not part of the pip
distribution, so a `uvx agentx-mcp` user has no checkout and cannot run a loose .py file.
A command is the only uvx-reachable form of this demo.

No API key, no gateway, no Node, no checkout. Everything here is the deterministic
keyless floor.
"""
import io
import json
import os
import shutil
import sys
import tempfile

from agentx_sdk.links import DISCORD_URL

# The downstream "server" the proxy wraps for this demo. Kept as SOURCE (not a shipped
# .py next to this module, and not a `-m` entry point) for one reason: the child must be
# importable-free. It is written to the demo's own temp dir and run as a plain script, so
# it needs nothing on sys.path and cannot accidentally pick up a different agentx_sdk than
# the parent is using. Its only imports are stdlib json + sys.
_STUB_SOURCE = '''\
"""A tiny stand-in for a "real" MCP server, used only by `agentx-mcp --demo`.

It speaks just enough of the MCP stdio protocol for the demo: read a JSON-RPC line, echo
back a success result. It is deliberately dumb, it runs whatever tool call reaches it.
That is the point: the AgentX proxy blocks the dangerous call BEFORE it gets here, so this
"server" only ever runs the safe one.
"""
import json
import sys


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        req_id = msg.get("id")
        if req_id is None:
            continue  # a notification (e.g. "initialized"); nothing to answer
        if msg.get("method") == "tools/call":
            name = (msg.get("params") or {}).get("name", "?")
            result = {
                "content": [{"type": "text", "text": "the real server ran '%s'" % name}],
                "isError": False,
            }
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
'''


def _tools_call(req_id, tool, arguments):
    return json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })


def _drive(run_proxy, stub_path, out, audit=False):
    """Run the two-call demo against a real run_proxy + stub.

    Returns True when the run did what its POSTURE promises: under enforce the dangerous
    call was blocked and the safe one allowed; under audit BOTH reached the server, because
    watch-only stops nothing.

    🔴 THE TWO POSTURES HAVE OPPOSITE PASS CONDITIONS, which is why this is branched rather
    than shared. Keeping the enforce assertion would fail the audit run for doing exactly
    what audit is FOR, and the obvious repair -- accept either outcome -- yields a check
    that passes whatever happens, which is worse than having no check at all.
    """
    requests = "\n".join([
        _tools_call(1, "run_sql", {"query": "DROP TABLE users"}),
        _tools_call(2, "run_sql", {"query": "SELECT id FROM users WHERE id = 42"}),
    ]) + "\n"

    client_out = io.StringIO()
    session_stats = {
        "integration": "mcp", "total_calls": 0, "intercepts": 0,
        "critical_blocks": 0, "self_corrections": 0,
        # The key every audit branch in the proxy reads. Set HERE rather than from
        # AGENTX_ENFORCEMENT, matching the Python door's rule that a scripted demonstration
        # whose contract is printed on screen cannot let the reader's shell decide it.
        "_enforcement": "audit" if audit else "enforce",
    }
    # log -> a throwaway buffer: the proxy's own [agentx-mcp] lines are stderr diagnostics,
    # not what the model sees. The model sees ONLY the JSON-RPC on client_out.
    run_proxy(
        [sys.executable, stub_path],
        client_in=io.StringIO(requests),
        client_out=client_out,
        session_stats=session_stats,
        log=io.StringIO(),
    )

    responses = {}
    for line in client_out.getvalue().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        if isinstance(msg, dict) and msg.get("id") is not None:
            responses[msg["id"]] = msg

    def _text(msg):
        try:
            return msg["result"]["content"][0]["text"]
        except Exception:
            return "(no text)"

    def _is_error(msg):
        try:
            return bool(msg["result"]["isError"])
        except Exception:
            return False

    print("=" * 68, file=out)
    if audit:
        print(" AgentX for MCP: watch-only. Every call recorded, none stopped.", file=out)
    else:
        print(" AgentX for MCP: a destructive call stopped before it ran", file=out)
    print("=" * 68, file=out)

    blocked = responses.get(1)
    print("\n1. run_sql(\"DROP TABLE users\")", file=out)
    if audit:
        # 🔴 THE SAME CALL REACHES THE SERVER, AND THIS SCREEN MUST NOT SOFTEN THAT. The
        # whole value of the rung is showing a reader what watch-only costs before they
        # choose it: the destructive call they just watched being stopped now runs.
        if blocked is not None and not _is_error(blocked):
            # "blocks nothing", never "stops nothing": the clause is single-sourced from
            # decorators.AUDIT_POSTURE_CLAUSE, and this door once said "stops" while the
            # Python door said "blocks" -- the exact cross-door drift a test now guards, and
            # which this line reintroduced on its first draft.
            print("   -> RECORDED, and it RAN. Watch-only blocks nothing.", file=out)
            print("      The server did it: %s" % _text(blocked), file=out)
        else:
            print("   -> UNEXPECTED: watch-only should not have stopped this. Got: %r"
                  % (blocked,), file=out)
    elif blocked is not None and _is_error(blocked):
        print("   -> STOPPED. It never reached the server. Your agent was told:\n", file=out)
        print("      " + _text(blocked).replace("\n", "\n      "), file=out)
    else:
        print("   -> UNEXPECTED: this should have been blocked. Got: %r" % (blocked,), file=out)

    allowed = responses.get(2)
    print("\n2. run_sql(\"SELECT id FROM users WHERE id = 42\")", file=out)
    if allowed is not None and not _is_error(allowed):
        if audit:
            # 🔴 THE HEADER PROMISES EVERY CALL, AND THIS IS THE OTHER ONE. Watch-only opens
            # with "Every call recorded, none stopped" and then labelled exactly ONE line
            # RECORDED, because this line is shared with the blocking screen where recording
            # is not what is being claimed. A reader checking the promise against the screen
            # came up one short. Found by a founder walk: both screens carry the word
            # somewhere, so no assertion was red.
            print("   -> ALLOWED, and recorded like the one above. It reached the server: %s"
                  % _text(allowed), file=out)
        else:
            print("   -> ALLOWED. It reached the server: %s" % _text(allowed), file=out)
    else:
        print("   -> UNEXPECTED: this safe call should have been allowed. Got: %r" % (allowed,),
              file=out)

    # Ends on the NEXT ACTION, not on caveats. The previous footer spent three lines on
    # scope and internal terms ("this driver", "Shield only, no judge, stdio only") and gave
    # the reader nothing to do, which is the same dead end the scan CTA had.
    print("\n" + "-" * 68, file=out)
    if audit:
        print(" Nothing was installed and no key was used. Both calls reached the", file=out)
        print(" server, including the destructive one. That is what watch-only is.", file=out)
        print("", file=out)
        # The way back to blocking, named on the screen that just showed it switched off.
        # A reader who came here to evaluate needs the return trip to be as cheap as the
        # trip out, or the safe posture is the one that takes more typing to reach.
        print(" To watch the same call be STOPPED:  uvx agentx-mcp --demo", file=out)
        print("", file=out)
        # 🔴 WHERE THE RECORD WENT, BECAUSE THE HEADER JUST PROMISED ONE. `run_demo` drives a
        # throwaway server from a temp directory it chdirs into (see `run_demo` below), so
        # nothing here reaches the reader's own ledger -- and the CTA further down names
        # `uvx agentx-mcp --audit`. Without this, the screen promises a record and then hands
        # over the command that shows an empty one: the dead end the Python door's
        # `demo --audit` rung exists to remove, arriving on this door. Only on this screen,
        # because only this screen makes the promise.
        print(" This run is not in your ledger: it drove a throwaway server from a",
              file=out)
        print(" temp directory, so `uvx agentx-mcp --audit` will not show it. The",
              file=out)
        print(" record you keep is the one from your own server, below.", file=out)
    else:
        print(" Nothing was installed and no key was used. This is the free local check:", file=out)
        print(" it stops the blatant destructive calls, not everything.", file=out)
        print("", file=out)
        # 🔴 THE MIDDLE RUNG, AS A COMMAND. This door's ladder ran: --demo (a command),
        # then EDIT mcp.json AND RESTART YOUR CLIENT (a change in the reader's own repo),
        # then --audit (a command). The config block below is still how you wrap a REAL
        # server and is not going anywhere; what it should not be is the only way to SEE
        # watch-only. The Python door made this same rung a command for the same reason.
        print(" To see watch-only without wiring anything up:  uvx agentx-mcp --demo --audit",
              file=out)
    print("", file=out)
    # Same promise change as the Python door's footer (cli.py), for the same reason: audit
    # now records EVERY call, so offering "what it WOULD stop" undersells it and lands a
    # well-behaved server's reader on an empty screen. The two doors move together on
    # purpose; a rung that means different things depending on how you wired us in is the
    # recurring defect here (copy true of one path, generalised to all).
    # The clause comes from decorators.AUDIT_POSTURE_CLAUSE: this door said "stops nothing"
    # while the Python door said "blocks nothing", which is the drift the comment above warns
    # about ("a rung that means different things depending on how you wired us in") appearing
    # in the sentence that DEFINES the rung.
    from .decorators import AUDIT_POSTURE_CLAUSE, MCP_POSTURE_ENV_LINE
    if audit:
        # "A wrapped server", not "Audit": audit is the value, the record and the command,
        # watching is what the server does. "Audit watches" made the value the actor.
        print(f" Now do it on your own server. A wrapped server {AUDIT_POSTURE_CLAUSE}.", file=out)
    else:
        # 🔴 NOT AN AUDIT PITCH ON THE SCREEN THAT JUST BLOCKED. This paragraph and the config
        # under it printed on BOTH screens, so a reader who watched a DROP TABLE be stopped --
        # and wanted exactly that -- was handed, as the very next thing, a description of the
        # posture that switches it off, followed by a config block whose first line sets it.
        # "The env line is optional" arrived AFTER the snippet, and the snippet is what gets
        # copied. Blocking is what this screen demonstrated, so blocking is what its config
        # shows; watch-only is named under it as the option it is.
        print(" Now do it on your own server. It blocks there the way it just did here.",
              file=out)
    # The one sentence P-151 exists for, placed BEFORE the config rather than after it: the
    # reader needs to know what setting this buys before they paste it, not once they have.
    # It says only what the line above does not -- the clause already covers "blocks nothing",
    # so repeating that here is the padding an earlier draft shipped.
    # ⚠️ "You get the record with blocking on too" was a garden path: it means "with blocking
    # on, you get it as well", and reads as "the record, with blocking, on top". Same fact,
    # said without the ambiguity, and without naming a posture the reader has not met yet.
    #
    # 🔴 AND THE SECOND SENTENCE IS AUDIT-SCREEN ONLY, BECAUSE THE FIRST FIX ORPHANED IT.
    # Moving audit's definition down to the switch instruction left "Audit only changes what
    # gets stopped" printing on the blocking screen ABOVE any mention of what audit IS: a
    # term used before it had a referent, introduced by the edit that was fixing a different
    # ordering problem three lines up. On the blocking screen the sentence before it already
    # carries the whole point, so it goes rather than moves.
    print(" You get the same record whether blocking is on or off.", file=out)
    if audit:
        print(" The posture only changes what gets stopped.", file=out)
    print("", file=out)
    print(" In mcp.json:", file=out)
    # `"command": "uvx"`, matching ui/utils/mcp.ts -- the config this project actually ships.
    # The bare `"command": "agentx-mcp"` form only starts if agentx-mcp is on PATH, which a
    # reader who just ran `uvx agentx-mcp --demo` does NOT have: uvx is ephemeral. Handing
    # them that config gives a server that fails to start, which is the same dead end this
    # pass set out to remove. (Caught in review of #287.)
    # 🔴 THIS SHIPPED AS SHELL SYNTAX INSIDE A JSON BLOCK: a bare
    # `AGENTX_ENFORCEMENT=audit` printed under "In mcp.json:". Pasted, it is a parse
    # error; dropped, the reader runs a posture they believe they set. The config this
    # project actually ships (ui/utils/mcp.ts MCP_CONFIG) carries no `env` key at all,
    # and the twin on this door (EntryFlow.tsx) already states the `env` form correctly
    # -- so the SENTENCE above was corrected on both doors while the ARTIFACT a reader
    # pastes kept the defect. Same class as P-151, one layer down: prose fixed, the
    # thing next to it left alone.
    # Scope travels in the same sentence as the promise, exactly as it does on the
    # EntryFlow twin: one agentx-mcp process wraps ONE server, each server gets its own
    # block, so `env` on one block leaves every other wrapped server blocking. Marked
    # optional because the unmarked line defaulted a reader to unprotected on their real
    # server, which is the harm this row exists to remove.
    #
    # ⚠️ ENV FIRST, AND THE COMMA LIVES ON THE ENV LINE. The first fix printed `"env"` under
    # a line ending in `]` with no separator, so a reader who pasted both got a JSON parse
    # error instead of a shell one -- the same harm, one syntax along. Putting the OPTIONAL
    # key first is what makes both readings valid: take both lines and the comma separates
    # two sibling keys; drop the optional line and what remains is still a complete block,
    # with no trailing comma left dangling in front of the closing brace.
    # 🔴 ONLY ON THE SCREEN THAT DEMONSTRATED IT. Printing this as the FIRST line of the
    # snippet to a reader who had just chosen blocking made the copy-paste default the one
    # setting that turns blocking off. The ENV-FIRST-WITH-THE-COMMA rule above is unchanged
    # and is why this still works both ways: present, the comma separates two sibling keys;
    # absent, what remains is a complete block with nothing dangling.
    # 🔴 WHICH SCREEN CARRIES THE ENV LINE SWAPPED WITH THE DEFAULT, AND THE RULE DID NOT.
    # The rule is unchanged: the config we hand over reproduces the demo the reader just
    # watched, and the OTHER posture is named below it as the option. What changed is which
    # posture a plain config gives you. It used to be blocking, so the watch-only screen led
    # with an env line and the blocking screen needed none. Now a plain config watches, so the
    # watch-only reader needs no line at all and the BLOCKING reader is the one who does.
    #
    # ⚠️ AND THE ONE VALUE WE EVER PRINT IS `enforce`. The old line turned protection OFF,
    # which is why the comment above worries about it becoming a copy-paste default. Nothing
    # we hand over can do that any more: there is no config on either screen that switches
    # blocking off, because switching it off is what happens when you paste nothing.
    #
    # Everything above about placement still holds and is why this still works both ways:
    # env-key-first with the comma on the env line means taking both lines gives two sibling
    # keys, and dropping the optional one leaves a complete block with nothing dangling.
    if not audit:
        print("       %s," % (MCP_POSTURE_ENV_LINE % "enforce"), file=out)
    # `"command": "uvx"`, matching ui/utils/mcp.ts -- the config this project actually ships.
    # The bare `"command": "agentx-mcp"` form only starts if agentx-mcp is on PATH, which a
    # reader who just ran `uvx agentx-mcp --demo` does NOT have: uvx is ephemeral. Handing
    # them that config gives a server that fails to start, which is the same dead end this
    # pass set out to remove. (Caught in review of #287.)
    print("       \"command\": \"uvx\",  \"args\": [\"agentx-mcp\", \"npx\", \"-y\", \"your-mcp-server\", \"...\"]", file=out)
    print("", file=out)
    if not audit:
        # "keep watching", not "keep blocking". Scope is unchanged -- one agentx-mcp process
        # wraps ONE server and `env` applies to its own block -- but what the untouched
        # servers DO is the opposite of what it was, and this sentence asserts it.
        print(" The env line is optional. Add it per server block; the servers", file=out)
        print(" you leave alone keep watching without blocking.", file=out)
    else:
        # The option, named AFTER the config that matches what they watched, in the clause
        # every other surface uses so the two doors cannot drift on what audit means.
        # ⚠️ DEFINITION FIRST, THEN THE INSTRUCTION THE COLON BELONGS TO. The first draft
        # ended the instruction with a full stop and put the definition last, so the code
        # block below was introduced by "Audit watches every call and blocks nothing:" --
        # the colon attached to the definition rather than to the thing being demonstrated.
        # The clause stays in ONE f-string so it cannot be half-edited out of single-sourcing.
        # 🔴 THE OFFER INVERTED. This read "To switch ONE server to watch-only, add this
        # line", which since watching became the default offers the reader a way to reach
        # where they already are. What a reader of THIS screen -- the one that just watched a
        # block -- cannot get by doing nothing is blocking, so that is what is on offer.
        print(f" A wrapped server {AUDIT_POSTURE_CLAUSE}, and that is what the config above does.",
              file=out)
        print(" To switch ONE server to blocking, add this line above its \"command\" line:",
              file=out)
        print("       %s," % (MCP_POSTURE_ENV_LINE % "enforce"), file=out)
        # "Add it", matching the watch-only screen's wording: the two screens say the same
        # thing about scope and should not differ in how they say it.
        print(" Add it per server block; the servers you leave alone keep watching.", file=out)
    # `uvx agentx-mcp --audit`, never `agentx audit`: under uvx the SDK's `agentx` script is
    # not on PATH, and it reads the cwd-relative ledger rather than the per-user MCP one.
    # Same reachability rule the --insights CTA already follows on this door.
    # 🔴 THIS LINE WAS P-151's HARM, ON THE ONE ON-RAMP THIS DOOR HAS. It read "Use your client
    # as usual, then see what it did", printed directly under `AGENTX_ENFORCEMENT=audit` -- so
    # the reader was told to run UNPROTECTED in order to see what their server did. The record
    # does not depend on the posture (the proxy's recording gate moved with the decorator's),
    # so the only thing setting audit buys here is that nothing gets stopped.
    #
    # ⚠️ A REVIEW CLEARED THIS FILE ONCE, AND THE CLEARANCE WAS CARRIED FORWARD UNCHECKED. It
    # looked at the posture SENTENCE above -- which single-sources AUDIT_POSTURE_CLAUSE and is
    # correct -- and not at the instruction wrapped around it. Both twins on this door
    # (EntryFlow.tsx, mcp_proxy.py --help) were fixed while this one kept the defect.
    print("", file=out)
    print(" Use your client as usual, then:", file=out)
    print("       uvx agentx-mcp --audit", file=out)
    print("", file=out)
    # Same closing line as `agentx demo` (cli.py), from the same single-sourced invite, so the
    # two demos hand off to the same two places instead of each inventing an ending.
    # "·", not ".", matching cli.py's footer. A lone full stop between two links reads as a
    # stray period rather than a separator, and this is the same footer the Python door prints
    # one spelling of -- the drift this branch keeps finding, on the two doors again.
    # ⚠️ THE "> " STAYS ASCII ON PURPOSE and is NOT the "▶" cli.py uses: U+25B6 is not
    # encodable in cp1252, and this screen is written to a stream an MCP client owns. "·" IS
    # cp1252-encodable (measured), so matching the separator carries no such risk.
    print(" > Docs: https://agentx-core.com/docs   ·   Bugs / ideas: %s" % DISCORD_URL, file=out)
    print("-" * 68, file=out)

    if audit:
        # BOTH reached the server. Asserting the DROP was blocked here would fail the run
        # for honouring the posture it was asked to demonstrate.
        return (blocked is not None and not _is_error(blocked)
                and allowed is not None and not _is_error(allowed))
    return (blocked is not None and _is_error(blocked)
            and allowed is not None and not _is_error(allowed))


def run_demo(out=None, audit=False):
    """Run the keyless MCP demo. Returns a process exit code (0 = the posture held).

    Never raises for a demo-level failure: a floor regression returns 1 so it fails loudly
    in CI instead of printing UNEXPECTED under a 0 exit code.
    """
    # stdout, not stderr: in --demo mode this process is NOT a proxy, so nothing is
    # speaking JSON-RPC on stdout and the human output belongs there (pipeable, and it
    # matches `agentx demo`). The proxy's own channels are explicitly redirected into
    # buffers in _drive, so they cannot interleave.
    out = out or sys.stdout

    # --- Show the SHIPPED keyless floor, not a dev-pulled policy ----------------------
    # The keyword shield prefers a pulled `.agentx/policies.json`, which WHOLLY REPLACES
    # the built-in seeds (verified: 6 seeds -> 1 rule). A checked-out dev repo can carry
    # one, so running here would demo that file instead of what a fresh install does.
    # Chdir into a clean temp dir first. This is sufficient even though the policy loader
    # first runs at import: `decorators.current_policy_load_error()` re-reads whenever the
    # policy file's (path, mtime_ns, inode, size) signature changes, and the proxy calls it
    # on every screened call, so the chdir is picked up before the first tools/call.
    # A fresh `pip install agentx-mcp` user has no such file, so this is a no-op for them.
    orig_cwd = os.getcwd()
    tmp = tempfile.mkdtemp(prefix="agentx-mcp-demo-")
    stub_path = os.path.join(tmp, "stub_mcp_server.py")
    with open(stub_path, "w", encoding="utf-8") as fh:
        fh.write(_STUB_SOURCE)

    os.chdir(tmp)
    # Restore these afterwards. For the one-shot CLI it makes no difference (the process exits),
    # but run_demo is also called IN-PROCESS by the tests, and a setdefault that is never undone
    # leaks "CI=1" and pinning=off into every test that runs after it, making results depend on
    # test order. Same leak class as the one that had these tests writing into the real ~/.agentx.
    _borrowed = ("CI", "AGENTX_MCP_TOOL_PINNING", "AGENTX_MCP_HARVEST_PATH",
                 "AGENTX_MCP_PINS_PATH", "AGENTX_MCP_LEDGER_PATH",
                 "AGENTX_MCP_OVERRIDES_PATH")
    previous_env = {k: os.environ.get(k) for k in _borrowed}
    os.environ.setdefault("CI", "1")                          # never emit a usage pulse from a demo
    os.environ.setdefault("AGENTX_MCP_TOOL_PINNING", "off")   # keep the relay a clean byte pump

    # Pin the demo's stores INTO its own temp dir. The MCP stores are now per-user and
    # cwd-independent, so without this the demo resolves to the real ~/.agentx and can write
    # into a user's actual corpus. It happens to stay clean today only because the two demo
    # calls do not form a recovery PAIR, which is luck, not a guarantee: anyone extending the
    # demo to show a recovery (a very natural thing to want, since recovering is the pitch)
    # would silently put fake safe-paths into that user's review queue. These are set
    # unconditionally, not via setdefault, because a demo must never write to a real store
    # even if the caller has pointed those vars somewhere.
    #
    # 🔴 FOUR STORES, NOT THREE, AND THE FOURTH IS THE ONE THE COMMENT ABOVE IS ABOUT.
    # The "fake safe-paths in a user's review queue" write is `_auto_coach` calling
    # `adopt_override(path=_mcp_overrides_path())` -- which reads AGENTX_MCP_OVERRIDES_PATH and
    # otherwise falls back to the real `~/.agentx/overrides.json`. Pinning the other three left
    # the demo's ledger, harvest and pins in the temp dir and the ADOPTED OVERRIDES in the
    # user's actual store, so the one file the comment named was the one still unpinned.
    # The list to keep in step is the RESOLVERS, not the variables already written down here.
    os.environ["AGENTX_MCP_HARVEST_PATH"] = os.path.join(tmp, "mcp_harvest.jsonl")
    os.environ["AGENTX_MCP_PINS_PATH"] = os.path.join(tmp, "mcp_tool_pins.json")
    os.environ["AGENTX_MCP_LEDGER_PATH"] = os.path.join(tmp, "mcp-ledger.db")
    os.environ["AGENTX_MCP_OVERRIDES_PATH"] = os.path.join(tmp, "overrides.json")
    try:
        from agentx_sdk.mcp_proxy import run_proxy            # lazy: AFTER the chdir above
        ok = _drive(run_proxy, stub_path, out, audit=audit)
    finally:
        # Leave the temp dir before removing it (Windows cannot delete the process cwd),
        # then clean up so repeated runs do not leak demo directories.
        os.chdir(orig_cwd)
        # ⚠️ DROP THE LEDGER HANDLE FIRST, AND THIS IS INSURANCE RATHER THAN A FIX. A review
        # flagged this as an active leak on the grounds that the proxy now records a passing
        # call in every posture; probed, and `run_demo` opens no write handle at all, so
        # nothing is holding the file today and the cleanup already works. But it works by
        # accident: the day this demo does write a row, the `.db` plus its `-wal`/`-shm`
        # sidecars are open, `rmtree` fails on Windows, `ignore_errors=True` swallows it, and
        # the directory survives with nobody the wiser. One line makes the cleanup true
        # whether or not that day arrives.
        # Imported here, not at module scope: this file is deliberately import-light so the
        # demo starts fast, and the rest of it reaches into the SDK lazily for the same reason.
        try:
            from agentx_sdk import db as _db
            _db._close_write_connection()
        except Exception:
            pass
        shutil.rmtree(tmp, ignore_errors=True)
        for key, was in previous_env.items():
            if was is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = was

    if not ok:
        # The failure names the posture's OWN expectation. A shared message would tell an
        # operator whose watch-only run failed that we "expected the DROP TABLE blocked",
        # which is the opposite of what this run was asked to do and sends them debugging
        # the wrong thing.
        if audit:
            print("\n[FAIL] expected BOTH calls to reach the server under watch-only; "
                  "see above.", file=out)
        else:
            print("\n[FAIL] expected the DROP TABLE blocked and the SELECT allowed; see above.",
                  file=out)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run_demo())
