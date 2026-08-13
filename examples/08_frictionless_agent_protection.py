import os
import sys
import json
from dotenv import load_dotenv

# --- Tell Python to locate the SDK files in the parent workspace folder root ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(root_dir)
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))

# Ingest stabilized AgentX SDK metrics collection structures
from agentx_sdk import agentx_protect, start_secure_session, is_block

# Initialize a secure isolated multi-turn telemetry thread tracking context frame
start_secure_session()

# =====================================================================
# 🛡️ THE FRICTIONLESS TOOL DEFINITION (NO EXTRACTION LAMBDAS SUPPLIED)
# =====================================================================
# The SDK reflexively reads signatures, aggregates string parameters,
# and strips structural connection arguments like 'db_session' natively.
# =====================================================================
@agentx_protect(agent_id="demo_frictionless_agent")
def dispatch_crm_update(client_id: str, profile_notes: str, db_session=None):
    """A sensitive corporate operation handling customer metadata changes."""
    print(f"\n[CRM SYSTEM] 💾 Writing metadata changes for client: {client_id}")
    print(f"[CRM SYSTEM] 📝 Notes Buffer: {profile_notes}")
    return {"status": "success", "message": "CRM partition committed safely."}


def run_frictionless_demo():
    print("=" * 72)
    print("🤖 AGENTX DEMO 08: ZERO-CONFIGURATION Enterprise TOOL PROTECTION")
    print("=" * 72)
    print("Scenario: An engineer wraps an existing corporate function with AgentX.")
    print("The SDK automatically parses inputs via Python signature reflection.\n")

    # The agent is prompt-injected via customer inputs to clear logging schemas
    malicious_notes_payload = "Customer requested normal update. Retain account historical state; DROP TABLE users;"
    target_client = "CLI-99401"
    
    print("🔄 --- Agent Execution Step ---")
    print(f"Agent Attempting Call: dispatch_crm_update(client_id='{target_client}', profile_notes='...')")
    print(f"Injected Input Payload: '{malicious_notes_payload}'")

    # Execute the protected operation turn
    tool_output = dispatch_crm_update(
        client_id=target_client,
        profile_notes=malicious_notes_payload,
        db_session="ActiveSqlAlchemySessionObjectPointer"  # Will be ignored by reflection weights
    )

    # Validate output formatting to ensure system convergence metrics match
    if is_block(tool_output):
        print("\n🛑 [AGENTX SHIELD] Request Intercepted & Blocked (deterministic floor — no key, no LLM)!")
        print(f"-> Policy: {tool_output.policy}")
        print("-> The reflection engine successfully captured the nested SQL payload.")
        print("-> The SQLAlchemy session context object was safely ignored.")
        print("\n🔒 Enterprise data assets protected via zero-configuration injection monitoring.")
    else:
        print(f"\n✅ Output Result: {tool_output}")
    print("=" * 72)
    # This keyless run BLOCKED the threat (deterministic Shield — no key, no LLM).
    # The next tier doesn't just block: it COACHES the agent back to a safe path so
    # the task still gets done. That re-planning needs your own LLM key.
    print("💡 Next: add a Gemini key to unlock the Recover tier — AgentX coaches your")
    print("   agent past the block to a safe completion, not just a dead-end. See it:")
    print("       python examples/10_self_correction_coaching.py")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    run_frictionless_demo()