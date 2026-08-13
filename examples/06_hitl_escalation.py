import os
import sys
import time
from dotenv import load_dotenv

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))
sys.path.append(root_dir)

from agentx_sdk.decorators import agentx_protect, start_secure_session

start_secure_session()

@agentx_protect(
    agent_id="demo_soc_agent",
    extract_query_func=lambda query, **kwargs: query,
    extract_cot_func=lambda query, cot, **kwargs: cot
)
def execute_sensitive_action(query: str, cot: str):
    print(f"\n💽 [PRODUCTION DB] Executing: {query}")
    return {"status": "success", "data": "Action completed after human approval."}

def run_hitl_demo():
    print("="*70)
    print("🤖 AGENTX DEMO 06: HUMAN-IN-THE-LOOP (SOC SANDBOX)")
    print("="*70)
    print("Scenario: Agent attempts an ambiguous or highly sensitive action.")
    print("Reasoning Engine flags it, SDK pauses execution, and waits for a human analyst.\n")

    # We use a CoT that triggers the escalation rule we saw in your pytest
    risky_query = "escalate" 
    agent_cot = "I am unsure if I am allowed to do this. Triggering escalation."

    print(f"🔄 --- Agent Action ---")
    print(f"Agent Attempting: execute_sensitive_action('{risky_query}')")
    
    # This should freeze and poll!
    result = execute_sensitive_action(query=risky_query, cot=agent_cot)

    print("\n📦 [AGENT RECEIVED DATA]:")
    print(result)

if __name__ == "__main__":
    run_hitl_demo()