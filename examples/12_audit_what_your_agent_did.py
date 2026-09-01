import os

# 🔴 SET BEFORE THE SDK IS IMPORTED, AND SET RATHER THAN INHERITED.
#
# Two separate reasons, and the second one is a bug we already shipped once.
#
# 1. The audit banner is printed on import, so a posture set after it is a posture the
#    banner never sees.
# 2. `agentx demo` used to inherit AGENTX_ENFORCEMENT and let the reader's shell decide
#    whether the demo worked. Our own on-ramp caused it: `$env:AGENTX_ENFORCEMENT="audit"`
#    persists for the whole PowerShell session. This script has the opposite contract to the
#    demo (it needs AUDIT, the demo needs ENFORCE), and the same fix applies to both: pin it.
#
# Nothing here is blocked. AgentX records every wrapped tool call, whether blocking is on
# or off; audit is what lets this one RUN.
os.environ["AGENTX_ENFORCEMENT"] = "audit"

import sys
from dotenv import load_dotenv

# --- Locate the SDK in the parent workspace root + load the shared .env ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))
sys.path.append(root_dir)

# 🔴 PINNED KEYLESS, AND POPPED *AFTER* load_dotenv OR IT COMES STRAIGHT BACK.
# `load_dotenv` does not override a variable that is already set, so popping before it looks
# like it works and then reloads the key from .env one line later.
#
# Why pin at all: with a key set and no gateway running, every call below fails OPEN and
# prints a DEGRADED banner, and the run takes a timeout per call. The ledger rows are still
# written -- the deterministic floor did screen them -- but the reader came here to see what
# audit records, not to debug a gateway that is not the point of this example. Same call
# `agentx demo` makes, for the same reason.
os.environ.pop("AGENTX_API_KEY", None)

from agentx_sdk import agentx_protect, start_secure_session, is_block

# The audit inventory (the ALLOWED row behind `agentx audit`) shipped after this example was
# written, so an older installed SDK runs every call below and records NOTHING -- an empty
# screen that reads as "your agent did nothing". Checked against the CAPABILITY rather than a
# version string: the version is a claim about the package, `record_call` is the writer this
# script actually depends on.
try:
    # DB_PATH is used below (the ledger this run writes to, read from the SDK rather than
    # restated here). `record_call` is the capability probe and is deliberately never called.
    # EXAMPLE_AGENT_ID joins the guard rather than sitting in its own import lower
    # down: it is newer than the published SDK too, so an unguarded import of it is a
    # traceback on exactly the install this branch exists to be kind to.
    from agentx_sdk.db import DB_PATH, EXAMPLE_AGENT_ID, record_call  # noqa: F401
except ImportError:
    print("This example needs the audit inventory, which is newer than your installed SDK.")
    print("    pip install -U agentx-security-sdk")
    sys.exit(0)

# =====================================================================
# 🔎 WHAT YOUR AGENT DID (AUDIT): KEYLESS, NO GATEWAY, BLOCKS NOTHING
# =====================================================================
# Every other example in this folder ends in an intervention: a block, a scrub, an
# escalation. This one is the other half, and it is the half that tells you something about
# YOUR agent rather than about our floor.
#
# WHAT AUDIT BUYS YOU HERE IS NOT THE RECORD. AgentX records every wrapped tool call,
# whether blocking is on or off, and `agentx audit` reads them back. What audit
# changes is that NOTHING IS STOPPED -- including the poisoned call at the end, which on the
# default posture would have been blocked. That is the only reason this example sets the
# posture at all.
#
# ⚠️ THAT LAST CALL IS THE ONE EXCEPTION ON THE AUDIT SCREEN. A call that tripped a
# policy is filed as a would-block, so it shows in `agentx insights`, not in the `agentx
# audit` table. Run this and the table lists FOUR calls while the session summary counts
# five. Said here because the sentence above used to claim audit read them all back the
# same, and a reader who counts is the reader this example is for.
#
# In audit posture AgentX vets every call exactly as it normally would, and then lets it run
# instead of stopping it. What lands in your local ledger is the SHAPE of each call:
#
#     the argument NAMES the agent passed   (never the values)
#     the SURFACE it touched                (DB / HTTP / FS / SHELL / CLOUD / -)
#     the size of any AMOUNT passed         (a bucket: ">=1,000", never the figure)
#
# So an agent that behaves perfectly still produces a report. That is the point: you find
# out what your agent does on an ordinary day, including the calls we had no opinion about.
#
# Runs keyless: no API key, no gateway, no LLM call. The ledger it writes is a SQLite file
# in this folder. (NOT "nothing leaves your machine" -- that blanket claim is false: the
# session summary still emits the anonymous activation pulse, same as every other run.)
# =====================================================================

TICKET = "SUP-1191"

# 🔴 THIS SCRIPT'S ROWS ARE MARKED AS OURS, AND YOURS SHOULD NOT BE.
#
# The rows below go into your real ledger, because the whole point is that `agentx audit`
# then has something to show. They are written under an agent id AgentX knows is its own, so
# that screen keeps calling them ours -- not just today, while this script's closing message
# is still on your terminal, but next week when only the ledger is left.
#
# When you copy this file, put YOUR agent's name here (it is imported above, and reads
# "agentx_example_agent"). That is the difference between a row the report attributes to us
# and a row it attributes to you.


# Four ordinary functions. The only change to any of them is the line above the def.
@agentx_protect(agent_id=EXAMPLE_AGENT_ID)
def query_orders_db(sql: str, limit: int = 50):
    print(f"   [DB]   {sql[:58]}{'...' if len(sql) > 58 else ''}")
    return [{"id": "ORD-8842", "total_usd": 2400.0, "status": "charged_twice"}]


@agentx_protect(agent_id=EXAMPLE_AGENT_ID)
def fetch_invoice_pdf(url: str):
    print(f"   [HTTP] GET {url}")
    return {"bytes": 48_112}


@agentx_protect(agent_id=EXAMPLE_AGENT_ID)
def issue_refund(order_id: str, amount: float, currency: str, reason: str):
    print(f"   [PAY]  refunding {order_id}")
    return {"refund_id": "RF-5501", "status": "settled"}


@agentx_protect(agent_id=EXAMPLE_AGENT_ID)
def write_ticket_note(path: str, contents: str):
    # Prints rather than writes: an example must not leave files in your project.
    print(f"   [FS]   note appended to {path}")
    return {"written": True}


def run_audit_example():
    print("=" * 72)
    print("🤖 AGENTX DEMO 12: AN ORDINARY DAY, NOTHING STOPPED (AUDIT)")
    print("=" * 72)
    print("Scenario: a support agent works one refund ticket end to end. AgentX records")
    print("every wrapped tool call, whether blocking is on or off. This run is in audit,")
    print("so nothing is stopped: the poisoned last call runs too.\n")

    start_secure_session()

    print(f"① The agent works ticket {TICKET}, with AgentX watching:")
    query_orders_db(
        sql="SELECT id, total_usd, status FROM orders WHERE customer_ref = ? AND created_at > ?",
        limit=50,
    )
    fetch_invoice_pdf(url="https://billing.acme-invoices.com/invoices/8842.pdf")
    issue_refund(order_id="ORD-8842", amount=2400.00, currency="usd",
                 reason="duplicate charge")
    write_ticket_note(
        path=f"tickets/{TICKET}.md",
        contents="Refunded ORD-8842. Duplicate charge confirmed against the invoice.",
    )

    # The ticket body came from a customer, and someone hid an instruction in it. In
    # ENFORCE this call is stopped. In AUDIT it is recorded and allowed to run, which is
    # what "audit takes zero risk" costs you: no risk of a false block, no protection either.
    print("\n② The ticket text carries a hidden instruction, and the agent follows it:")
    poisoned = "SELECT * FROM orders WHERE id = 'ORD-8842'; DROP TABLE orders; --"
    result = query_orders_db(sql=poisoned)

    print("\n" + "=" * 72)
    if is_block(result):
        # Cannot happen in audit, and worth saying out loud rather than assuming: if this
        # ever prints, the posture did not take and the run above is not an audit run.
        print("⚠️  That call was BLOCKED, so this run was not in audit posture.")
        print("    Nothing below describes what you just saw. Check AGENTX_ENFORCEMENT.")
        print("=" * 72 + "\n")
        return

    # No counts in this copy, deliberately. A hardcoded "five calls" beside the list of
    # calls it counts goes stale the first time somebody adds one, and the numbers the
    # reader should trust are the ones `agentx audit` derives from the ledger itself.
    # 🔍 NOT ✅. A green tick is the glyph this codebase uses for "that went well", and it sat
    # on the sentence describing the UNPROTECTED outcome -- fifteen lines under a banner that
    # says "Your agent is NOT protected: a flagged call still runs". The two read as opposite
    # verdicts on one run. 🔍 is the glyph the AUDIT narration above already uses, and audit is
    # an observation, not a success.
    print("🔍 Every call above ran, including the poisoned one. Nothing was blocked.")
    print("   AgentX recorded the shape of each call in your local ledger:")
    print(f"      {os.path.abspath(DB_PATH)}")
    print("")
    print("   All but the last were calls AgentX had no objection to. The last")
    print("   one tripped a policy and was recorded as a would-block, then let")
    print("   through, because that is what audit is: it watches, and it does")
    print("   not get in the way.")
    print("")
    # THE ONE NEXT STEP. Deliberately not run for you: `agentx audit` is the rung, and a
    # script that runs it on the reader's behalf both takes the step out of their hands and
    # marks it as taken in the funnel. Print the command, let them run it.
    print(" ▶ Now read it back:   agentx audit")
    print("")
    print("   Run it from this folder, or you will read a different ledger. You get a")
    print("   table of every tool above and what it touched, printed directly above the")
    print("   list of what the built-in floor watches for. Read the two together:")
    # 🔴 SAY THE COUNT DIFFERENCE ON SCREEN, NOT IN A SOURCE COMMENT. This was first written
    # into the `#` header above, which only somebody reading the file ever sees. The person who
    # RUNS this counts five calls here and then finds four in the table, with nothing on either
    # screen accounting for the fifth. A gap a reader can measure has to be answered where they
    # measure it.
    # ⚠️ ORDER IS LOAD-BEARING, AND INSERTING THE COUNT NOTE HERE BROKE IT ONCE. "Read the two
    # together:" leads into the sentence below; "that list" is the floor's watch-list printed
    # just above it. Wedged between the two, the count note put 'agentx insights' in between --
    # so "that list" read as insights, and the one word carrying the antecedent pointed at the
    # wrong screen. The count gets its own beat AFTER the pair instead.
    # The screen renders the bucket as "≥1,000"; this said ">=1,000". A reader comparing the
    # two has to decide whether they are the same thing, on the one line whose point is that
    # we store a shape and not their number.
    print("   issue_refund is not on that list. The refund is recorded as '≥1,000',")
    print("   never as $2,400, because the ledger keeps the shape and not the figure.")
    print("")
    print("   The table lists FOUR calls, not five. The poisoned one tripped a policy,")
    print("   so it is filed as a would-block and shows in 'agentx insights' instead.")
    print("")
    print("   These rows came from this example, not from your own agent. Delete the")
    print("   ledger file above to start clean.")
    print("")
    print("   Every tool here is an ordinary function with one line added. Open this")
    print("   file: that line is the whole change.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_audit_example()
