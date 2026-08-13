import os
import sys
import uuid
from dotenv import load_dotenv

# --- Locate the SDK in the parent workspace root + load the shared .env ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))
sys.path.append(root_dir)

from agentx_sdk import AgentXClient

# =====================================================================
# 🟡 GATEWAY-REQUIRED DEMO (this is NOT the keyless Shield floor)
# =====================================================================
# The runaway-provisioning floor already escalates on the ABSOLUTE fleet size
# (e.g. "50 instances, at or above the ceiling of 25"). But a 202 that reads
# "approve 50 instances?" still gets rubber-stamped, because the human is deciding
# on IDENTITY (the agent is allowed to provision) and not on CONSEQUENCE (50 is an
# order of magnitude past anything THIS agent has ever run).
#
# The per-agent baseline (the Recover tier) closes that gap. The gateway keeps a
# per-agent high-water mark of the fleet sizes the agent actually runs, and when a
# request escalates it appends the one fact that changes the answer:
#   "About 17x the largest fleet this agent has run (prior peak: 3 instances)."
# It is keyed on the AGENT across sessions, deliberately unlike the per-session
# breakers, so it learns the agent's routine even when no two calls share a session.
#
# Requirements to see this work:
#   • The AgentX gateway running (default http://localhost:8000)
#   • AGENTX_API_KEY set in your environment / .env
#   • AGENTX_PROVISION_COUNT_CEILING below the runaway size (default 25) and the
#     baseline enabled, AGENTX_BASELINE_DELTA_MULT > 0 (default 3)
# =====================================================================

ROUTINE_FLEET = 3      # the agent's normal, in-policy deploy size (under the ceiling)
RUNAWAY_FLEET = 50     # the one request that blows past the ceiling AND the agent's history
ROUTINE_RUNS = 3       # a few routine deploys to establish the baseline


def run_per_agent_baseline_demo():
    print("=" * 72)
    print("🤖 AGENTX DEMO 11: CONSEQUENCE vs THE AGENT'S OWN HISTORY (PER-AGENT BASELINE)")
    print("=" * 72)
    print("Scenario: an infra agent routinely provisions a small fleet, then one call")
    print("asks for 50 instances. The size alone already escalates, but AgentX adds how")
    print("far past THIS agent's own normal it is, so the human approves on consequence,")
    print("not identity.\n")

    api_key = os.environ.get("AGENTX_API_KEY")
    if not api_key:
        print("⚠️  AGENTX_API_KEY is not set. The per-agent baseline is a gateway-side")
        print("    verdict (the Recover tier), so this demo needs a key plus a running")
        print("    gateway. It is not the keyless Shield. Set AGENTX_API_KEY and retry.")
        return

    client = AgentXClient()  # defaults to http://localhost:8000
    agent_id = "demo_provisioning_agent"  # one agent, learned across sessions

    # --- 1. Establish the agent's normal envelope with routine, in-policy deploys ---
    # Each routine deploy runs on its OWN trace_id (a separate session). The baseline
    # is keyed on the agent, not the session, so it still learns the routine across all
    # of them, and only ALLOWED actions are recorded (a held/denied spike never counts).
    print(f"① Routine deploys establish the agent's normal (~{ROUTINE_FLEET} instances):\n")
    for i in range(1, ROUTINE_RUNS + 1):
        res = client.evaluate_intent(
            agent_id=agent_id,
            query=f"aws ec2 run-instances --image-id ami-0abc --count {ROUTINE_FLEET}",
            chain_of_thought=f"Standing up the usual {ROUTINE_FLEET} workers (run {i}).",
            trace_id=str(uuid.uuid4()),
        )
        status = res.get("status") if isinstance(res, dict) else None
        if status == "REASONING_ENGINE_UNREACHABLE":
            print("\n⚠️  Gateway unreachable. Start the AgentX gateway on localhost:8000,")
            print("    then retry.")
            return
        print(f"   run {i}: --count {ROUTINE_FLEET}  ->  {status}  (recorded into the agent's baseline)")

    # --- 2. The runaway request escalates WITH the consequence-vs-history line ---
    print(f"\n② The runaway request, {RUNAWAY_FLEET} instances in a single call:\n")
    res = client.evaluate_intent(
        agent_id=agent_id,
        query=f"aws ec2 run-instances --image-id ami-0abc --count {RUNAWAY_FLEET}",
        chain_of_thought="Scaling out hard to crunch the backlog.",
        trace_id=str(uuid.uuid4()),
    )
    status = res.get("status") if isinstance(res, dict) else None

    if status == "ESCALATED":
        print("!" * 72)
        print("🛑 [AGENTX GATEWAY] RUNAWAY PROVISIONING: paused for a human.")
        print(f"   Policy:   {res.get('policy_triggered')}")
        print(f"   Receipt:  {res.get('receipt_id')}")
        print(f"   Why:      {res.get('challenge')}")
        print("!" * 72)
        print("\n🔑 The closing sentence of the challenge is the point: the approver sees")
        print("   this is far outside the agent's OWN history, not just a large number.")
        print("   No IAM grant or static ceiling carries that; it needs the agent's")
        print("   learned baseline.")
    elif status == "REASONING_ENGINE_UNREACHABLE":
        print("⚠️  Gateway unreachable. Start it on localhost:8000 and retry.")
    else:
        print(f"⚠️  Expected an ESCALATED verdict, got: {res}")
        print("   Confirm the gateway's AGENTX_PROVISION_COUNT_CEILING (default 25) is")
        print("   below the runaway size and AGENTX_BASELINE_DELTA_MULT (default 3) is on.")

    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_per_agent_baseline_demo()
