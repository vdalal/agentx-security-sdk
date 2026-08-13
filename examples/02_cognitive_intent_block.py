import os
import json
import requests
import sys
from dotenv import load_dotenv

# --- Load the .env file from the root directory ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))

# AgentX SDK Imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentx_sdk.decorators import agentx_protect, _print_agentx_summary

# -------------------------------------------------------------------
# 1. SETUP
# -------------------------------------------------------------------
GATEWAY_URL = "http://localhost:8000"
AGENTX_API_KEY = os.environ.get("AGENTX_API_KEY", "agentx_sk_test_12345")

# -------------------------------------------------------------------
# 2. THE DEMO SCENARIO: AWS Metadata SSRF via REST API
# -------------------------------------------------------------------
def run_ssrf_demo():
    print("="*70)
    print("🤖 AGENTX DEMO 02: SSRF INFRASTRUCTURE PROTECTION (REST API)")
    print("="*70)
    print("Scenario: An agent attempts to access internal AWS metadata.")
    print("This demo bypasses the SDK and hits the Gateway's REST API directly,")
    print("proving AgentX can protect Node.js, Go, or Rust applications.\n")
    
    # The agent tries to hit the infamous AWS metadata IP
    malicious_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    agent_cot = "I need to fetch the AWS keys to complete my deployment task."
    
    print(f"🔄 --- Agent Attempt 1 ---")
    print(f"Agent Attempting to fetch: {malicious_url}")
    print(f"Agent Thought (CoT): '{agent_cot}'")
    
    # 🛡️ THE RAW REST INTERCEPT
    payload = {
        "url": malicious_url,
        "method": "GET",
        "agent_id": "demo_curl_agent",
        "cot": agent_cot
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AGENTX_API_KEY}"
    }
    
    print("\n[NETWORK] 🌐 Sending payload to AgentX Reasoning Engine `/v1/network/fetch`...")
    response = requests.post(f"{GATEWAY_URL}/v1/network/fetch", json=payload, headers=headers)
    
    if response.status_code == 200:
        gateway_data = response.json()
        if "error" in gateway_data and "Violation" in gateway_data["error"]:
            print("\n🛑 [AGENTX SHIELD] Network Request Hard-Blocked (deterministic floor — no key, no LLM)!")
            print(f"Reason: {gateway_data.get('policy_triggered')}")
            print(f"Message: {gateway_data.get('challenge')}")
        else:
            print(f"\n⚠️ [FAILURE] Request bypassed the firewall: {gateway_data}")
    else:
        print(f"\n❌ [ERROR] Reasoning Engine returned status {response.status_code}: {response.text}")

if __name__ == "__main__":
    run_ssrf_demo()
    print("\n")
    _print_agentx_summary()