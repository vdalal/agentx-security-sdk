# AgentX examples

Runnable scripts, each one a single behaviour you can watch happen.

Three numbered examples are published with the SDK. They come in the source archive, not the wheel a plain `pip install` fetches, so if you installed from PyPI you will not have this folder: clone the repo, or download the sdist. Two of them run with no API key, no gateway
and no LLM credentials. The third, `01_self_healing_agent.py`, shows recovery: it needs your
own Gemini key, and if you run it without one it says so and points you at `00`.

If you are reading this in a **clone of the repository** you will see more scripts than these
three. Those extra ones are not part of the published package, and several of them do need a
Gemini key and a running gateway. Do not trust their headers to tell you which: some open
straight into `from google import genai` with nothing above it. `requirements.txt` lists which
script needs what, script by script.

## Setup

```bash
pip install agentx-security-sdk
pip install -r requirements.txt     # python-dotenv, for the two that load a local .env
```

`00_quickstart_pip.py` needs neither of those beyond the SDK itself. It is the file to run
first if you have just installed and want to see a block in ten seconds.

## Start here

| | | Needs |
|---|---|---|
| `00_quickstart_pip.py` | A prompt-injected `DROP TABLE` is stopped in-process | nothing, not even `requirements.txt` |
| `12_audit_what_your_agent_did.py` | **Nothing is blocked**, not even the poisoned call at the end. A support agent works a refund ticket, AgentX records every wrapped tool call, whether blocking is on or off. `agentx audit` lists four of them; the poisoned one tripped a policy, so it shows in `agentx insights` | `requirements.txt` (it loads a `.env`) |
| `01_self_healing_agent.py` | **Recovery.** A blocked agent reads the challenge, re-plans, and completes the task instead of dying | `requirements.txt`, `pip install google-genai`, and your own `GEMINI_API_KEY` |

`12` is the odd one out and worth running second. The other two end in an intervention, so
they show you what AgentX does. `12` shows you what your *agent* does, which is the half you
cannot get from a detector.

## Protecting an MCP server instead

`mcp/` wraps any MCP server so every `tools/call` is screened before it runs, with no changes
to the server and no Python in your own stack. Start with `mcp/README.md`.

## What the published package does not include

`01` shows recovery, but it shows the half that runs in this MIT package: the block lands, the
agent reads the challenge, re-plans with your key and finishes the task. The judge that *writes*
a task-fitting challenge, and the coach-and-retry it drives, run in the hosted gateway. Run `01`
without the gateway and it says so itself, in the line it prints: recovered, but *degraded*.

The scripts that drive that gateway end-to-end are not published, because shipping them would
mean shipping code you can read and cannot run. They exist in the repository if you have it.
Request gateway access at [agentx-core.com](https://agentx-core.com).

## A note on the ledger

Several of these write to `.agentx.db` in the directory you run them from. That file is the
local flight recorder `agentx audit`, `agentx insights` and `agentx status` read. It is per
directory, so running an example from one folder and `agentx audit` from another reads two
different files, and deleting it starts a fresh one.
