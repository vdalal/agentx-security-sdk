import os
import re
from setuptools import setup, find_packages


def _read_version():
    """Single source of truth: read __version__ from agentx_sdk/__init__.py (regex, no
    import, so the build never depends on the package importing cleanly). Prevents the
    drift that shipped `agentx-mcp --version` as a stale 0.4.2 while the wheel was 0.4.4:
    bump the version in ONE place (__init__.py) and setup.py + `--version` follow."""
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, "agentx_sdk", "__init__.py"), encoding="utf-8") as f:
        match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', f.read(), re.M)
    if not match:
        raise RuntimeError("Unable to find __version__ in agentx_sdk/__init__.py")
    return match.group(1)


# Safely read README.md if it exists, otherwise use a default string
long_description = "Runtime firewall for AI agents - blocks catastrophic tool calls and self-heals the run."
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()

setup(
    name="agentx-security-sdk",
    version=_read_version(),
    author="AgentX Core Team",
    author_email="founders@agentx-core.com",
    description="Runtime firewall for AI agents - blocks catastrophic tool calls and self-heals the run.",
    keywords="ai-agents, agent-security, llm-security, ai-firewall, prompt-injection, "
             "guardrails, llm-guardrails, agent-guardrails, tool-use, autonomous-agents, "
             "mcp, ai-safety, self-healing",
    license="MIT",
    # Ship ONLY the SDK's MIT license. Pinned explicitly so setuptools' default
    # glob does NOT pull the repo-root proprietary LICENSE into the SDK wheel.
    license_files=["agentx_sdk/LICENSE"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://agentx-core.com",
    project_urls={
        "Homepage": "https://agentx-core.com",
        "Get Started": "https://bit.ly/agentfirewall",
    },
    packages=find_packages(include=["agentx_sdk", "agentx_sdk.*"]),
    install_requires=[
        "requests>=2.25.0",
    ],
    # 💡 THE observabilty entrypoint mapping hook
    entry_points={
        'console_scripts': [
            'agentx=agentx_sdk.cli:main',
            # Zero-code MCP-server wedge: wrap a real MCP server's command in
            # `agentx-mcp` to screen every tools/call through the keyless shield.
            'agentx-mcp=agentx_sdk.mcp_proxy:main',
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
