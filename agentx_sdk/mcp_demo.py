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


def _drive(run_proxy, stub_path, out):
    """Run the two-call demo against a real run_proxy + stub. Returns True when the
    dangerous call was blocked AND the safe one was allowed."""
    requests = "\n".join([
        _tools_call(1, "run_sql", {"query": "DROP TABLE users"}),
        _tools_call(2, "run_sql", {"query": "SELECT id FROM users WHERE id = 42"}),
    ]) + "\n"

    client_out = io.StringIO()
    session_stats = {
        "integration": "mcp", "total_calls": 0, "intercepts": 0,
        "critical_blocks": 0, "self_corrections": 0, "_enforcement": "enforce",
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
    print(" AgentX for MCP: a destructive call stopped before it ran", file=out)
    print("=" * 68, file=out)

    blocked = responses.get(1)
    print("\n1. run_sql(\"DROP TABLE users\")", file=out)
    if blocked is not None and _is_error(blocked):
        print("   -> STOPPED. It never reached the server. Your agent was told:\n", file=out)
        print("      " + _text(blocked).replace("\n", "\n      "), file=out)
    else:
        print("   -> UNEXPECTED: this should have been blocked. Got: %r" % (blocked,), file=out)

    allowed = responses.get(2)
    print("\n2. run_sql(\"SELECT id FROM users WHERE id = 42\")", file=out)
    if allowed is not None and not _is_error(allowed):
        print("   -> ALLOWED. It reached the server: %s" % _text(allowed), file=out)
    else:
        print("   -> UNEXPECTED: this safe call should have been allowed. Got: %r" % (allowed,),
              file=out)

    # Ends on the NEXT ACTION, not on caveats. The previous footer spent three lines on
    # scope and internal terms ("this driver", "Shield only, no judge, stdio only") and gave
    # the reader nothing to do, which is the same dead end the scan CTA had.
    print("\n" + "-" * 68, file=out)
    print(" Nothing was installed and no key was used. This is the free local check:", file=out)
    print(" it stops the blatant destructive calls, not everything.", file=out)
    print("", file=out)
    # Same promise change as the Python door's footer (cli.py), for the same reason: audit
    # now records EVERY call, so offering "what it WOULD stop" undersells it and lands a
    # well-behaved server's reader on an empty screen. The two doors move together on
    # purpose; a rung that means different things depending on how you wired us in is the
    # recurring defect here (copy true of one path, generalised to all).
    print(" Now do it on your own server. Audit watches every call and stops nothing.", file=out)
    print(" In mcp.json:", file=out)
    # `"command": "uvx"`, matching ui/utils/mcp.ts -- the config this project actually ships.
    # The bare `"command": "agentx-mcp"` form only starts if agentx-mcp is on PATH, which a
    # reader who just ran `uvx agentx-mcp --demo` does NOT have: uvx is ephemeral. Handing
    # them that config gives a server that fails to start, which is the same dead end this
    # pass set out to remove. (Caught in review of #287.)
    print("       \"command\": \"uvx\",  \"args\": [\"agentx-mcp\", \"npx\", \"-y\", \"your-mcp-server\", \"...\"]", file=out)
    print("       AGENTX_ENFORCEMENT=audit", file=out)
    # `uvx agentx-mcp --audit`, never `agentx audit`: under uvx the SDK's `agentx` script is
    # not on PATH, and it reads the cwd-relative ledger rather than the per-user MCP one.
    # Same reachability rule the --insights CTA already follows on this door.
    print("   Use your client as usual, then see what it did:  uvx agentx-mcp --audit", file=out)
    print("", file=out)
    # Same closing line as `agentx demo` (cli.py), from the same single-sourced invite, so the
    # two demos hand off to the same two places instead of each inventing an ending.
    print(" > Docs: https://agentx-core.com/docs   .   Bugs / ideas: %s" % DISCORD_URL, file=out)
    print("-" * 68, file=out)

    return (blocked is not None and _is_error(blocked)
            and allowed is not None and not _is_error(allowed))


def run_demo(out=None):
    """Run the keyless MCP demo. Returns a process exit code (0 = the floor held).

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
                 "AGENTX_MCP_PINS_PATH", "AGENTX_MCP_LEDGER_PATH")
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
    os.environ["AGENTX_MCP_HARVEST_PATH"] = os.path.join(tmp, "mcp_harvest.jsonl")
    os.environ["AGENTX_MCP_PINS_PATH"] = os.path.join(tmp, "mcp_tool_pins.json")
    os.environ["AGENTX_MCP_LEDGER_PATH"] = os.path.join(tmp, "mcp-ledger.db")
    try:
        from agentx_sdk.mcp_proxy import run_proxy            # lazy: AFTER the chdir above
        ok = _drive(run_proxy, stub_path, out)
    finally:
        # Leave the temp dir before removing it (Windows cannot delete the process cwd),
        # then clean up so repeated runs do not leak demo directories.
        os.chdir(orig_cwd)
        shutil.rmtree(tmp, ignore_errors=True)
        for key, was in previous_env.items():
            if was is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = was

    if not ok:
        print("\n[FAIL] expected the DROP TABLE blocked and the SELECT allowed; see above.",
              file=out)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run_demo())
