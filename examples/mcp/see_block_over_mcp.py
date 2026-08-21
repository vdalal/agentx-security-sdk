"""See a dangerous MCP tools/call get blocked and coached, keyless, in ten seconds.

This is a thin shim. The demo itself ships INSIDE the package as `agentx-mcp --demo`,
because a command is the form of it that reaches everyone: a `uvx agentx-mcp` user never
unpacks a source distribution and so could not run a loose .py file, whatever we ship.

The canonical way to run it, with no checkout at all:

    uvx agentx-mcp --demo

This file is kept so the path in older docs still works, and so a reader browsing the repo
lands somewhere that explains where the demo went. The driver and the stub server both live
in `agentx_sdk/mcp_demo.py`.
"""
import sys

from agentx_sdk.mcp_demo import run_demo

if __name__ == "__main__":
    sys.exit(run_demo())
