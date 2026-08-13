# AgentX examples

Runnable scripts, each one a single behaviour you can watch happen.

## Setup

```bash
pip install agentx-security-sdk
pip install -r requirements.txt     # python-dotenv, and google-genai for the LLM demos
```

`00_quickstart_pip.py` needs neither of those beyond the SDK itself. It is the file to run
first if you have just installed and want to see a block in ten seconds.

## Start here

| | | Needs |
|---|---|---|
| `00_quickstart_pip.py` | A prompt-injected `DROP TABLE` is stopped in-process | nothing, not even `requirements.txt` |
| `08_frictionless_agent_protection.py` | The same, on a tool with no configuration at all | `requirements.txt` (it loads a `.env`) |
| `12_audit_what_your_agent_did.py` | **Nothing is blocked.** A support agent works a refund ticket and AgentX records what each call touched, then `agentx audit` reads it back | `requirements.txt` (it loads a `.env`) |

`12` is the odd one out and worth running second. Every other example here ends in an
intervention (a block, a scrub, an escalation), so they show you what AgentX does. `12` shows
you what your *agent* does, which is the half you cannot get from a detector.

## The rest

`01`, `02`, `03`, `07` and `10` drive a real LLM and need a `GEMINI_API_KEY` plus the gateway
running. `04`, `05`, `06`, `09` and `11` are deterministic; `09` and `11` are gateway-side
verdicts and need the gateway with an `AGENTX_API_KEY`.

Each script says at the top what it needs and what it is showing.

## A note on the ledger

Several of these write to `.agentx.db` in the directory you run them from. That file is the
local flight recorder `agentx audit`, `agentx insights` and `agentx status` read. It is per
directory, so running an example from one folder and `agentx audit` from another reads two
different files, and deleting it starts a fresh one.
