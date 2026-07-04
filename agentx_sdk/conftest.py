"""Shared pytest fixtures for the SDK suite.

Override-store isolation: `get_active_override` reads the project's real
`.agentx/overrides.json`. Once it gained a NAME fallback (an adopted reframe
applies to any block carrying the same policy name, not just the exact policy
id), a developer who had run `agentx adopt` would silently flip block-challenge
assertions in tests that trigger that policy (e.g. the "Mass Destructive Intent"
blocks in test_block_result.py). Tests must be deterministic regardless of what
the dev adopted locally, so default every test to an isolated, empty store.

A test that needs a POPULATED store sets `AGENTX_OVERRIDES` itself (the
`store_path` / `cli_env` fixtures, or an in-body monkeypatch.setenv); that
explicit value wins over this autouse default.
"""
import pytest


@pytest.fixture(autouse=True)
def _isolate_override_store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTX_OVERRIDES", str(tmp_path / "overrides.json"))


@pytest.fixture(autouse=True)
def _isolate_tool_pins(tmp_path, monkeypatch):
    """MCP tool-description drift pins default to .agentx/mcp_tool_pins.json under
    the project root; isolate them per-test so a run_proxy-path test (or the e2e
    stub server) can never read/write a real pin file or order-flake."""
    monkeypatch.setenv("AGENTX_MCP_PINS_PATH", str(tmp_path / "mcp_tool_pins.json"))
