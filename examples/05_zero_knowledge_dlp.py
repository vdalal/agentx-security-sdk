import os
import sys
import json
from dotenv import load_dotenv

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))

sys.path.append(root_dir)
from agentx_sdk.decorators import agentx_protect, start_secure_session

my_trace_id = start_secure_session()

# -------------------------------------------------------------------
# THE DEVELOPER'S TOOL (Local Database)
# -------------------------------------------------------------------
@agentx_protect(
    agent_id="demo_dlp_agent",
    extract_query_func=lambda query, **kwargs: query,
    extract_cot_func=lambda query, cot, **kwargs: cot
)
def fetch_user_profile(query: str, cot: str):
    print(f"💽 [LOCAL DB] Executing query against production database...")
    # Simulating a real local database returning sensitive, nested PII
    return {
        "id": 8472,
        "name": "Sarah Connor",
        "email": "sarah.connor@sky.net",
        "phone": "+1 (555) 123-4567",
        "role": "admin",
        "metadata": {
            "backup_email": "s.connor99@gmail.com",
            "notes": "Do not share phone number."
        }
    }

def run_dlp_demo():
    print("="*70)
    print("🤖 AGENTX DEMO 05: ZERO-KNOWLEDGE DLP (EGRESS SCRUBBING)")
    print("="*70)
    print("Scenario: An agent executes a safe read query. The local DB returns")
    print("sensitive PII. AgentX scrubs it before the agent sees it.\\n")

    safe_query = "SELECT * FROM users WHERE id = 8472;"
    agent_cot = "I need to check the user's profile."

    print(f"🔄 --- Agent Action ---")
    print(f"Agent Attempting: fetch_user_profile('{safe_query}')")
    
    # We are going to temporarily mock the `_local_standalone_evaluate` 
    # response just for this specific demo function by injecting a kwarg, 
    # but normally this instruction comes from the SQLite Edge Cache.
    
    # Execute
    result = fetch_user_profile(query=safe_query, cot=agent_cot)

    print("\n📦 [AGENT RECEIVED DATA]:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    run_dlp_demo()