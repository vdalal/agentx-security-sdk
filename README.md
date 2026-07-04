# 🛡️ AgentX SDK: The Action Firewall for AI Agents

[![PyPI](https://img.shields.io/pypi/v/agentx-security-sdk.svg)](https://pypi.org/project/agentx-security-sdk/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

LLM agents are powerful and brittle. Given the wrong prompt they will drop a production table, read a secret, or POST your data to an attacker's URL. A traditional guardrail answers with a hard `403` that kills the run and burns the tokens you already spent.

AgentX is different, and it protects you with zero keys. The hero is a deterministic **Shield** that runs in-process: it hard-blocks the catastrophic call (`DROP TABLE`, SSRF, secret reads, destructive shell and cloud teardown) and escalates the consequential-but-legitimate ones (large transfers, external publishes, runaway spend, bulk deletes) for a human to approve. No API key, no signup, no LLM round-trip.

This repository is the MIT-licensed SDK: the keyless Shield, which you can read, audit, and run yourself with no AgentX account.

## Install

```bash
pip install agentx-security-sdk
```

## See it work in 10 seconds (no key, no gateway)

```bash
agentx demo
```

Runs a canned agent that attempts a `DROP TABLE` and lets you watch the in-process Shield block it offline. It is the fastest way to confirm the install before you wire it into your own agent.

Caught something you are proud of? Turn it into a shareable card:

```bash
agentx share
```

`agentx share` renders your most recent catch as a screenshot-able receipt. It is privacy-safe by construction: it uses the policy class and your own tool name only, never the query or the payload.

## Protect a tool

Add `@agentx_protect` over any high-risk tool. The SDK inspects the call at runtime, so there is no schema to write and no boilerplate:

```python
from agentx_sdk.decorators import agentx_protect

@agentx_protect(agent_id="crm_agent")
def dispatch_crm_update(client_id: str, profile_notes: str, db_session=None):
    print(f"Updating records for {client_id}")
```

Your code reacts to a block with `is_block()`. You never parse message text, you read structured fields:

```python
from agentx_sdk import agentx_protect, is_block

result = dispatch_crm_update(client_id="CLI-99401", profile_notes=untrusted)

if is_block(result):
    print(f"Blocked by policy: {result.policy}")
    llm.send(result.challenge)   # feed the safe-path challenge back so the agent self-corrects
else:
    use(result)                  # not blocked: the real return value
```

For strictly-typed tools (LangChain or Pydantic tools that validate a `-> dict` return), AgentX raises instead of returning, so the framework does not crash on a changed return type:

```python
from agentx_sdk import AgentXSecurityBlock

try:
    data = fetch_user(uid)       # -> dict
except AgentXSecurityBlock as block:
    llm.send(block.challenge)
```

A runaway-loop circuit-breaker trip is not a policy block. It raises `AgentXCircuitBreakerTripped`, and `is_block()` returns `False` for it, so you can catch it separately to abort the run.

## Protect an MCP server with zero code

Do not own the tool's Python, or running a non-Python agent? Wrap any MCP server with `agentx-mcp` and every `tools/call` is screened by the same keyless Shield before it runs. It is one line in your `mcp.json` (Claude Code, Cursor, or any MCP client):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentx-mcp",
      "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    }
  }
}
```

No Python in your stack? Run it on demand with [`uvx`](https://docs.astral.sh/uv/) so `mcp.json` stays one line:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "uvx",
      "args": ["agentx-mcp", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    }
  }
}
```

(`pipx run agentx-mcp <real server command>` works the same way.) A blocked call comes back to the agent as a coaching tool error it can self-correct on, so the run keeps going and the dangerous call never reaches the server.

## What is open, and what is hosted

This repo is the keyless **Shield**: deterministic, in-process blocking with in-band coaching, MIT-licensed, no account required. It is the whole story for stopping the catastrophic call before it executes.

The **Recover** tier turns a block into a completed task. When you connect the hosted gateway, the agent gets a task-fitting path back and finishes the run instead of crashing, with human-in-the-loop review on the consequential calls. Recover runs in the hosted gateway, not in this SDK. Request access at [agentx-core.com](https://agentx-core.com).

## Development

```bash
pip install -e .
pytest agentx_sdk/
```

## License

MIT. See [LICENSE](LICENSE).

Homepage: [agentx-core.com](https://agentx-core.com)
