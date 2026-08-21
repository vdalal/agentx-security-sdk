# MCP examples

Guarding an MCP-based agent with AgentX, keyless, with no code change.

The Python examples in the parent directory show the `@agentx_protect` decorator. These
show the other keyless door: `agentx-mcp`, a proxy that wraps a real MCP server and screens
every `tools/call` before it runs.

## 1. The config (`mcp.json`)

`agentx-mcp` is a **wrapping proxy**: it launches your real MCP server as a child process
and relays the protocol verbatim, blocking only the dangerous `tools/call`. You wire it by
editing the server entry you already have in your MCP client's config (Claude Desktop,
Cursor, Claude Code, Windsurf, VS Code) so `agentx-mcp` runs in front of your real command:

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

`mcp.json` in this folder is exactly that (the `agentx-mcp` form, which needs `agentx-mcp` on
your PATH). To install nothing, use the `uvx` variant instead:

```json
"filesystem": {
  "command": "uvx",
  "args": ["agentx-mcp", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
}
```

Restart your client so it re-spawns the server. Now the client launches the proxy, the
proxy launches the real server, and every tool call is screened. A blocked call returns to
your agent as a coaching error it self-corrects on. To install persistently instead of
`uvx`: `pip install agentx-mcp` (or `pipx install agentx-mcp`), then set `command` to
`agentx-mcp`.

## 2. See it block (`agentx-mcp --demo`)

The `mcp.json` above is the real config, but seeing a block usually means wiring a whole MCP
client. This demo skips that: it drives the exact same proxy your client would spawn, feeds
it one dangerous and one safe tool call, and prints what each one gets back. No API key, no
gateway, no Node, no checkout.

```bash
uvx agentx-mcp --demo
```

You will see the `DROP TABLE` call blocked with coaching (it never reaches the server) and
the scoped `SELECT` allowed through. The demo runs against a bundled stub server that is a
dumb stand-in for a real one, it runs whatever reaches it, which is exactly why the proxy
has to stop the dangerous call first.

Both the driver and the stub live in `agentx_sdk/mcp_demo.py`, inside the installed package.
`see_block_over_mcp.py` in this directory is now a one-line shim that calls the same code, so
the older path still works from a clone.

## What this door is, said honestly

- **Keyless Shield only.** The block is a deterministic hard-block from the offline floor.
  Your own model reads the coaching and self-corrects. This is not the gateway judge;
  gateway-backed Recover over MCP is on the roadmap.
- **stdio transport only.** This wraps a local MCP server your client launches by command.
  A remote MCP server reached over HTTP/SSE is not covered today.
- **Not every agent uses MCP.** If your tools live in your own code (a Vercel AI SDK or
  LangChain `tool()`), there is no MCP boundary to wrap. Use the in-process guard instead:
  the `@agentx_protect` decorator, shown in the examples one directory up.
