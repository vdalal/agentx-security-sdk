import os
import sys
from dotenv import load_dotenv

# --- Load the .env file from the root directory ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))

# AgentX SDK Imports
sys.path.append(root_dir)
from agentx_sdk import agentx_protect, start_secure_session, AgentXCircuitBreakerTripped, is_block

# Start session tracker
my_trace_id = start_secure_session()

# -------------------------------------------------------------------
# THE DEVELOPER'S TOOL
# -------------------------------------------------------------------
@agentx_protect(
    agent_id="demo_stubborn_agent",
    extract_query_func=lambda query, **kwargs: query,
    extract_cot_func=lambda query, cot, **kwargs: cot
)
def execute_database_query(query: str, cot: str):
    # This will only run if AgentX allows it
    return f"Successfully executed: {query}"

def run_circuit_breaker_demo():
    print("="*70)
    print("🤖 AGENTX DEMO 04: THE INFINITE LOOP CIRCUIT BREAKER")
    print("="*70)
    print("Scenario: An LLM gets confused and repeatedly tries to execute")
    print("a blocked action (an 'apology loop'). AgentX tracks the strikes")
    print("and safely kills the process before it drains your token wallet.\n")

    malicious_query = "DROP TABLE users;"
    
    # Start with our initial rogue reasoning structure
    current_cot = "I am clearing out space by dropping legacy tables."

    # -------------------------------------------------------------------
    # GRACEFUL ERROR HANDLING: This is what we teach the developer to write
    # -------------------------------------------------------------------
    try:
        # Simulate a stubborn model trying to execute a task across 5 iterations
        attempt = 1
        while attempt <= 5:
            print(f"\n🔄 --- Agent Step {attempt} ---")
            print(f"Agent Thought (CoT): '{current_cot}'")
            print(f"Agent Attempting: execute_database_query('{malicious_query}')")
            
            tool_output = execute_database_query(query=malicious_query, cot=current_cot)
            
            print(f"📥 [AGENT RECEIVED OBSERVATION]: {tool_output}")
            
            # Simulate a confused/stubborn agent monologue response:
            # The model reads the AgentX block text, apologizes, but fails to fix its code payload.
            if is_block(tool_output):
                print("\n🧠 [AGENT MONOLOGUE]: 'Oh, I got a security block. Let me apologize and try again.'")
                current_cot = (
                    f"I apologize for hitting a security boundary on attempt {attempt}. "
                    f"Let me re-submit the identical command to see if it clears: DROP TABLE users;"
                )
            
            attempt += 1
            
    except AgentXCircuitBreakerTripped as e:
        print("\n" + "!"*70)
        print("🚨 [APPLICATION LEVEL] CAUGHT CIRCUIT BREAKER EXCEPTION!")
        print(f"Details: {e}")
        print("Action: Safely aborting agent task thread and alerting human operator.")
        print("!"*70)

if __name__ == "__main__":
    run_circuit_breaker_demo()