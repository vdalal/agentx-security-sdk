# AgentX — 2-minute quickstart (the cold-start repro)
# =====================================================================
# This is the ONE file to send a developer who has never seen AgentX.
# Unlike the other examples in this folder, it imports the PUBLISHED
# package — no repo clone, no sys.path hack, no python-dotenv, no .env.
#
#   1. pip install agentx-security-sdk
#   2. python 00_quickstart_pip.py
#
# It runs with ZERO API key and ZERO gateway: the deterministic SHIELD
# floor blocks the dangerous call in-process, offline, via the built-in
# fallback policy seeds. Connecting the hosted gateway later upgrades you
# from "block" to "block + coach the agent back to a safe path" (the
# Recover tier). Request access at https://agentx-core.com.
# =====================================================================

from agentx_sdk import agentx_protect, start_secure_session, is_block

# Optional: names this run in the local flight-recorder + prints a summary.
start_secure_session()


# Wrap ANY existing tool function with one decorator. AgentX reads the
# call's string arguments by signature reflection — you write no schema,
# no extraction lambda, and structural args (db sessions, etc.) are ignored.
#
# 🔴 posture="enforce" IS PINNED HERE ON PURPOSE, and your own install is different.
# A fresh install WATCHES: it records what would have been blocked and lets the call
# run, so wrapping a tool cannot break an agent that already works. This file's whole
# subject is watching a block happen, so it asks for the blocking posture explicitly.
# Drop the argument and you get the watching default.
@agentx_protect(agent_id="demo_quickstart_agent", posture="enforce")
def run_sql(query: str, db_session=None):
    # If you ever see this line print, the shield FAILED to intercept.
    print(f"[DB] EXECUTING (would be irreversible): {query}")
    return {"status": "ok"}


def main():
    print("=" * 64)
    print("AgentX quickstart — watch a DROP TABLE get blocked, no key needed")
    print("=" * 64)

    # A classic prompt-injection: the agent was told to update a record,
    # but the attacker smuggled a destructive statement into the payload.
    poisoned = "Update notes for client 99401; DROP TABLE users;"

    print(f"\nAgent tool call:\n  run_sql(query={poisoned!r})\n")

    result = run_sql(query=poisoned, db_session="<live SqlAlchemy session>")

    if is_block(result):
        print("BLOCKED before execution (deterministic floor — no key, no LLM).")
        print(f"  policy:  {result.policy}")
        print(f"  receipt: {result.receipt_id}")
        print("\nThe DROP TABLE never reached your database.")
        print("=" * 64)
        return

    print(f"NOT BLOCKED, unexpected. Tool returned: {result}")
    print("=" * 64)
    # 🔴 NON-ZERO ON PURPOSE, AND IT IS WHAT MAKES THE SUITE MEAN SOMETHING.
    # test_published_example_surface.py already runs this file as a keyless stranger would
    # and asserts it exits 0. Until this line existed that assertion only meant "it did not
    # crash": when the posture default flipped to watching, this file printed
    # "NOT BLOCKED, unexpected" on every run, exited 0, and the suite stayed green. The
    # file announced its own failure and the harness read it as ordinary stdout.
    raise SystemExit(1)


if __name__ == "__main__":
    main()
