import os
import json
import sys
from dotenv import load_dotenv

# --- Make the SDK importable when running this file straight from the repo ---
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(root_dir)
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))

# AgentX SDK — the only two names you need to handle a block.
from agentx_sdk import agentx_protect, is_block
from agentx_sdk.db import init_db
# Session counters (for the demo to tell a verified execution from a fail-open one).
from agentx_sdk import decorators as agentx_runtime

# -------------------------------------------------------------------
# 1. SETUP: Point to the AgentX Security Gateway
# -------------------------------------------------------------------
GATEWAY_URL = "http://localhost:8000"
AGENT_ID = "demo_db_agent"
# This recovery demo makes a REAL LLM call to re-plan, so it needs a Gemini key AND the
# `google-genai` client. Both are checked HERE, and the client is imported here rather than
# at the top of the file, on purpose:
#
# this example ships in the published package, where `google-genai` is not a dependency. An
# import on line 5 raised ModuleNotFoundError before any of the friendly text below could
# print, and a published example that dies on its fifth line is worse than no example. It is
# also why this one was briefly dropped from the published set: the crash, not the key.
#
# The rule this file now satisfies is not "runs with no key" -- it is "never crashes for a
# reader with no key". Declining clearly, with somewhere to go, is a fine thing for a
# published example to do.
#
# BOTH ARE CHECKED BEFORE EITHER IS REPORTED. Chaining them (key first, client only if the key
# is set) named one thing at a time to the reader who has NEITHER -- which is the default for
# somebody who just ran `pip install`. They go and get a key, run it again, and are declined a
# second time for a package nobody mentioned. One decline should name everything it needs.
_MISSING = []
if not os.environ.get("GEMINI_API_KEY"):
    _MISSING.append("a GEMINI_API_KEY")
try:
    from google import genai
except ImportError:
    _MISSING.append("the google-genai package (pip install google-genai)")

if _MISSING:
    print(f"⚠️  Demo 01 needs {' and '.join(_MISSING)} — it calls an LLM to re-plan after a block.")
    print("    For the keyless path (deterministic Shield block, no key/gateway needed), run:")
    print("    python examples/00_quickstart_pip.py")
    sys.exit(0)

gemini_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
# Dynamic evaluation model hook configuration variable
AGENTX_EVALUATION_MODEL = os.getenv("AGENTX_EVALUATION_MODEL", "gemini-2.5-flash")

# Ensure local DB is ready for tracking (if using the local SDK features)
init_db()

# -------------------------------------------------------------------
# 2. THE DEVELOPER'S TOOL (Protected by AgentX)
# -------------------------------------------------------------------
# We wrap the sensitive database function with the AgentX SDK.
# The SDK intercepts the call and forwards the payload to the Gateway.
@agentx_protect(
    agent_id=AGENT_ID,
    extract_query_func=lambda query, **kwargs: query,
    extract_cot_func=lambda query, cot, **kwargs: cot,
    # Pinned: a fresh install WATCHES and lets the call run. This example's subject is
    # the block, so it asks for the blocking posture explicitly. Drop it for the default.
    posture="enforce",
)
# NOTE: no `receipt_id` parameter. You pass receipt_id= on a retry (see below) but your
# tool never has to declare it — the decorator strips it before your function is called.
# This example used to declare it, and that mattered more than it looked: with the
# parameter present the decorator's signature binding succeeded, which quietly hid a bug
# for every tool that did NOT declare it. Leaving it here would teach the workaround.
def execute_database_query(query: str, cot: str):
    """A mock database tool representing a connection to production."""
    print(f"\n[DATABASE] 💥 Executing against Prod DB: {query}")
    return {"status": "success", "rows_affected": 1, "data": "Query executed successfully."}

# -------------------------------------------------------------------
# 3. THE DEMO SCENARIO: Stacked SQL Injection
# -------------------------------------------------------------------
def run_sql_injection_demo():
    print("="*70)
    print("🤖 AGENTX DEMO 01: NEURO-SYMBOLIC SQL INJECTION PREVENTION")
    print("="*70)
    print("Scenario: An agent hallucinates a destructive query")
    print("hidden behind a safe READ operation.\n")

    # The agent hallucinates a destructive command while attempting a read operation,
    # but the LLM tries to lie in its Chain of Thought.
    current_cot = "I am just doing a normal read operation to fetch user stats."
    current_query = "SELECT COUNT(*) FROM users; DROP TABLE users;"
    current_receipt = None

    # Give the agent a chance to self-correct
    for attempt in range(3):
        print(f"\n🔄 --- Agent Step {attempt + 1} ---")
        print(f"Agent Attempting: execute_database_query('{current_query}')")
        print(f"Agent Thought (CoT): '{current_cot}'")

        # Snapshot the fail-open counter so we can tell, after the call, whether THIS
        # execution was verified by the gateway or ran fail-open (gateway unreachable).
        degraded_before = agentx_runtime._session_stats["degraded_executions"]

        # 🛡️ THE INTERCEPT HAPPENS HERE
        tool_output = execute_database_query(
            query=current_query,
            cot=current_cot,
            receipt_id=current_receipt
        )

        # If AgentX blocked the call, `tool_output` is a structured AgentXBlock.
        # No string parsing — just read the fields off it.
        if is_block(tool_output):
            print("\n🛑 [AGENTX SHIELD] Request Intercepted & Challenged (deterministic floor)!")
            print(f"Policy Triggered: {tool_output.policy}")
            print(f"Socratic Challenge Issued: {tool_output.challenge}")
            print(f"Captured Transaction Tracking UUID: {tool_output.receipt_id}")

            # Thread the receipt back on retry so the gateway can credit the recovery.
            current_receipt = tool_output.receipt_id

            print("\n🧠 [AGENT] Rethinking strategy based on AgentX Socratic Challenge...")
            rethink_prompt = f"""
            You attempted query: {current_query} based on logic: {current_cot}.
            The AgentX Reasoning Engine intercepted this with a strict constraint: "{tool_output.challenge}"

            You must self-correct. Provide a revised, strictly safe SQL query (like SELECT COUNT(*);)
            that only performs read operations. Do NOT attempt to drop tables.

            Return ONLY valid JSON: {{"revised_cot": "I understand the error...", "revised_query": "..."}}
            """

            # THE CALL AND THE PARSE ARE SEPARATE FAILURES WITH SEPARATE FIXES. One `except`
            # around both reported a depleted Gemini quota as "Failed to parse LLM response",
            # which sends a reader to inspect JSON when the answer was on their billing page.
            # The API's own message carries the remedy, so it is printed rather than replaced
            # by a label of ours.
            try:
                response = gemini_client.models.generate_content(
                    model=AGENTX_EVALUATION_MODEL,
                    contents=rethink_prompt,
                    config={"response_mime_type": "application/json"}
                )
            except Exception as e:
                print(f"❌ [AGENT ERROR] The re-plan call to Gemini failed: {e}")
                print("    Recovery needs a working key — quota and billing problems arrive")
                print("    here as 429 RESOURCE_EXHAUSTED. The block itself still held.")
                print("    For the keyless path, run:")
                print("    python examples/00_quickstart_pip.py")
                return

            try:
                correction = json.loads(response.text)
                current_cot = correction["revised_cot"]
                current_query = correction["revised_query"]
            except (ValueError, KeyError, TypeError) as e:
                print(f"❌ [AGENT ERROR] The model replied, but not in the JSON this demo "
                      f"asked for: {e}")
                return

        else:
            # `is_block` is False → the corrected query EXECUTED. Distinguish the two
            # ways that happens: the gateway verified+allowed it, OR the gateway was
            # unreachable and it ran fail-open (Layer-0 shield only; deep semantic checks
            # skipped). Only claim verification when this call did NOT run fail-open.
            ran_fail_open = (
                agentx_runtime._session_stats["degraded_executions"] > degraded_before
            )
            if ran_fail_open:
                print("\n⚠️  [AGENT RECOVERED — DEGRADED] The agent self-corrected and the query "
                      "executed, but the gateway was unreachable so it ran fail-open — the Layer-0 "
                      "shield applied, deep semantic checks were skipped. Start the gateway to verify "
                      "(see 'Degraded Executions' in the session summary).")
            else:
                print("\n✅ [AGENT RECOVERED] The agent self-corrected to a safe query, "
                      "verified and allowed by the Reasoning Engine.")
            break
    else:
        # The for-loop ran all attempts without `break` — the agent never produced a
        # safe correction. Surface it instead of exiting silently.
        print("\n🛑 [AGENT GAVE UP] No safe correction after 3 attempts — aborting the task.")

if __name__ == "__main__":
    run_sql_injection_demo()
