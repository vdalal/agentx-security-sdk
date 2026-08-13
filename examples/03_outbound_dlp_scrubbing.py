import os
import json
import sys
from dotenv import load_dotenv
from google import genai

# --- FIX: Tell Python to look in the parent directory for the SDK ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(root_dir)

# --- FIX: Load the .env file from the root directory ---
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))

# AgentX SDK Imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentx_sdk.decorators import agentx_protect, _print_agentx_summary
from agentx_sdk.db import init_db

# -------------------------------------------------------------------
# 1. SETUP
# -------------------------------------------------------------------
GATEWAY_URL = "http://localhost:8000"
AGENT_ID = "demo_support_agent"

init_db()

# -------------------------------------------------------------------
# 2. THE DEVELOPER'S TOOL
# -------------------------------------------------------------------
@agentx_protect(
    agent_id=AGENT_ID,
    extract_query_func=lambda query, **kwargs: query,
    extract_cot_func=lambda query, cot, **kwargs: cot
)
# No `receipt_id` parameter: the decorator strips it before calling your tool, so you
# never declare it. This example never even passed one — it was carried over from the
# retry example, where declaring it silently hid BACKLOG P-68.
def execute_database_query(query: str, cot: str):
    """
    Note: In a real app, this function would query the database.
    However, the AgentX Reasoning Engine intercepts this call and, for READ queries,
    it returns the mock data directly from the reasoning engine's PII scrubber.
    Therefore, the code inside this function won't actually execute for this demo.
    """
    print(f"\n[DATABASE] This line won't print because the Reasoning Engine handles the mock data.")
    return {"status": "success", "data": "Raw Data"}

# -------------------------------------------------------------------
# 3. THE DEMO SCENARIO: PII Scrubbing
# -------------------------------------------------------------------
# Update the main execution entry wrapper at the bottom of your script file
def run_dlp_scrubbing_demo():
    print("="*70)
    print("🛡️  AGENTX DEMO 03: OUTBOUND DATA LEAK PROTECTION (DLP)")
    print("="*70)
    print("Scenario: An agent executes a safe read query, but the database utility")
    print("returns sensitive production customer variables (Emails, Phones, Keys).")
    print("AgentX local egress filters intercept the return stream and sanitize it")
    print("before the data can leak into the agent model's context window.\n")
    
    safe_query = "SELECT * FROM users WHERE id = 1;"
    agent_cot = "I need to look up the customer profile trace log to verify active tier status."
    
    print(f"🔄 --- Agent Turn Action ---")
    print(f"Agent Thought (CoT): '{agent_cot}'")
    print(f"Agent Attempting: execute_database_query('{safe_query}')")
    
    # 🛡️ THE EGRESS INTERCEPT HAPPENS HERE
    tool_output = execute_database_query(
        query=safe_query,
        cot=agent_cot
    )
    
    print("\n✅ [AGENTX EGRESS SHIELD] Safe query executed; PII scrubbed from the return stream (deterministic, local).")
    print("📦 [SANITIZED DATA STREAM DELIVERED TO AGENT HISTORY]:")
    print("-" * 50)
    print(tool_output)
    print("-" * 50)

if __name__ == "__main__":
    run_dlp_scrubbing_demo()
