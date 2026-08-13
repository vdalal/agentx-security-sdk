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
# Unlike examples 01/08 (deterministic Layer-0 Shield blocks that run with
# no key and no gateway), the Budget Ceiling floor is a GATEWAY-side
# HITL-escalation verdict. The signal isn't in any single payload — it is the
# CUMULATIVE session spend, which the SDK meters and forwards on every call.
# The gateway compares that running total to your configured ceiling and, once
# it is crossed, returns a 202 ESCALATED to pause the agent for a human.
#
# Requirements to see this work:
#   • The AgentX gateway running (default http://localhost:8000)
#   • AGENTX_API_KEY set in your environment / .env
#
# Why this demo drives the gateway contract directly instead of @agentx_protect:
# the decorator's escalation path SUSPENDS and polls a live human SOC for up to
# 2 minutes (the right production behavior — see example 06). Here we want a
# fast, terminating proof of the cost METER itself, so we simulate a runaway
# agent reporting its escalating spend step by step and watch the exact moment
# the ceiling trips. In your real code you'd just wrap the tool with
# @agentx_protect and call `agentx.record_spend(tokens=resp.usage.total_tokens,
# cost_usd=...)` after each LLM completion — the SDK forwards the total for you.
# =====================================================================

# Default ceiling is $25 (AGENTX_SESSION_COST_CEILING_USD), read by the GATEWAY
# process at its startup — not by this client. We simulate an expensive agent
# whose per-step spend marches past it.
COST_PER_STEP_USD = 4.50


def run_budget_ceiling_demo():
    print("=" * 72)
    print("🤖 AGENTX DEMO 09: THE RUNAWAY-COST CIRCUIT BREAKER (BUDGET CEILING)")
    print("=" * 72)
    print("Scenario: An agent is stuck in an unproductive loop, burning real")
    print("dollars on LLM calls (cf. AFDB #17 AutoGPT $120/8hr, #23 AgentGPT).")
    print("No single call is unsafe — the CUMULATIVE burn is the danger signal.")
    print("AgentX meters the spend and halts the session for a human before it")
    print("drains your wallet.\n")

    api_key = os.environ.get("AGENTX_API_KEY")
    if not api_key:
        print("⚠️  AGENTX_API_KEY is not set. The budget ceiling is a gateway-side")
        print("    verdict, so this demo needs a key + a running gateway (it is not")
        print("    the keyless Shield). Set AGENTX_API_KEY in your .env and retry.")
        return

    client = AgentXClient()  # defaults to http://localhost:8000
    trace_id = str(uuid.uuid4())  # one logical agent session across all steps

    cumulative_cost = 0.0
    halted = False

    for step in range(1, 11):
        # Simulate one more expensive reasoning call and meter its real cost.
        cumulative_cost += COST_PER_STEP_USD

        print(f"🔄 --- Agent Step {step} ---")
        print(f"   LLM call cost this step: ${COST_PER_STEP_USD:.2f}  |  "
              f"Session total so far: ${cumulative_cost:.2f}")

        # Each step is a slightly DIFFERENT (but unproductive) revision. Sending a
        # genuinely distinct action each turn is what isolates the budget ceiling:
        # repeating the identical query/CoT on one trace would instead trip the
        # no-progress loop breaker (Token Exhaustion Trap) — a different, also-correct
        # floor. The cost signal is the cumulative burn, not any single action.
        eval_res = client.evaluate_intent(
            agent_id="demo_runaway_agent",
            query=f"Revise the travel itinerary — pass {step}: tweak day {step} ordering.",
            chain_of_thought=f"Pass {step}: still not satisfied; reordering once more.",
            trace_id=trace_id,
            session_cost_usd=cumulative_cost,  # the SDK forwards this for you in real use
        )

        status = eval_res.get("status") if isinstance(eval_res, dict) else None

        if status == "ESCALATED":
            print("\n" + "!" * 72)
            print("🛑 [AGENTX GATEWAY] BUDGET CEILING REACHED — session paused for a human.")
            print(f"   Policy:     {eval_res.get('policy_triggered')}")
            print(f"   Receipt:    {eval_res.get('receipt_id')}")
            print(f"   Spent:      ${cumulative_cost:.2f} (crossed the configured ceiling)")
            print(f"   Why:        {eval_res.get('challenge')}")
            print("!" * 72)
            print("\n🔒 The runaway loop was stopped before it could keep burning budget.")
            print("   In production the agent suspends here and a human SOC approves or")
            print("   denies before any further spend (see example 06 for that flow).")
            halted = True
            break
        elif status in ("ALLOWED", "success"):
            print("   ✅ Under ceiling — agent allowed to continue.\n")
        elif status == "REASONING_ENGINE_UNREACHABLE":
            print("\n⚠️  Gateway unreachable. Start the AgentX gateway (localhost:8000)")
            print("    to see the budget ceiling enforced, then retry.")
            return
        else:
            print(f"\n⚠️  Unexpected gateway response: {eval_res}")
            return

    if not halted:
        print("⚠️  Loop finished without tripping the ceiling. Either the gateway's")
        print("    AGENTX_SESSION_COST_CEILING_USD is set higher than this demo's")
        print("    simulated spend, or the floor is disabled (AGENTX_FLOOR=off).")

    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_budget_ceiling_demo()
