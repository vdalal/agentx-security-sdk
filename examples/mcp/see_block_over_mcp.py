"""See a dangerous MCP tools/call get blocked and coached, keyless, in ten seconds.

This is now a thin shim. The demo itself ships INSIDE the package as `agentx-mcp --demo`,
because `examples/` is not part of the pip distribution: a `uvx agentx-mcp` user has no
checkout and could never run a loose .py file here. A command is the only form of this
demo that reaches them.

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
