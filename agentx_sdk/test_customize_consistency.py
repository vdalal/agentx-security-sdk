"""Cross-surface consistency tripwire for `agentx customize`.

A CUSTOMIZED coaching (written once by `agentx customize`, keyless, keyed by the
built-in policy id + a policy-name fallback) must render IDENTICALLY on BOTH keyless
block surfaces: the ``@agentx_protect`` decorator AND the agentx-mcp proxy. Both
deliver a block through the SAME ``_apply_org_override``, so an override written once
has to reach both. This pins that invariant.

Green when both surfaces apply the same customized coaching; RED the moment either
surface stops applying it, or the two paths drift on the policy identity they key the
override by (an id/name mismatch on one surface) — the exact silent drift no single
diff looks wrong for. It is the reason `agentx customize` can claim, in its own output,
that it "applies keyless on BOTH the SDK decorator and agentx-mcp block paths."

Ledger of KNOWN, intentional divergences (so we assert on the challenge SUBSTRING, not
byte equality):
  * The MCP proxy wraps the challenge in a coaching envelope (it names the blocked tool
    and adds a "Safe alternative:" line); the decorator exposes the raw challenge on
    ``AgentXBlock.challenge``. Same challenge TEXT, different surrounding frame — by
    design. If that ever needs to change, update this ledger, not the assertion style.
"""
import io
import json

import pytest

from agentx_sdk import decorators as dec
from agentx_sdk import overrides as ov
from agentx_sdk import mcp_proxy as mp
from agentx_sdk import agentx_protect, is_block, reset_strike_state


# The built-in floor policy BOTH surfaces match on a DROP TABLE.
_POLICY_NAME = "Mass Destructive Intent"
_BUILTIN = next(p for p in dec._BUILTIN_POLICY_KEYWORDS if p["name"] == _POLICY_NAME)
_DEFAULT_CHALLENGE = _BUILTIN["socratic_prompt"]
_CUSTOM_CHALLENGE = "ACME house rule: never DROP; snapshot then soft-delete, ping #data-eng."


@pytest.fixture(autouse=True)
def _force_builtins_and_keyless(monkeypatch):
    """Deterministic on any machine: pin the shipped builtins (a dev box may carry a
    pulled .agentx/policies.json that shadows them; the cold/keyless install — the funnel
    target — runs the builtins), run keyless (no key), and clear strike state so neither
    surface trips a circuit breaker from an unrelated test in the same session."""
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", list(dec._BUILTIN_POLICY_KEYWORDS))
    monkeypatch.delenv("AGENTX_API_KEY", raising=False)
    reset_strike_state()


def _drive_decorator_block(query):
    """Run the @agentx_protect keyless Layer-0 shield on a dangerous query; return the
    delivered AgentXBlock.challenge (with any org override applied)."""
    @agentx_protect(agent_id="tripwire_decorator")
    def run_sql(query, db_session=None):
        return {"status": "ok"}

    out = run_sql(query=query, db_session="<session>")
    assert is_block(out), "decorator shield must block the dangerous query"
    return out.challenge


def _drive_mcp_block(query):
    """Route a dangerous tools/call through the agentx-mcp proxy core; return the coaching
    text delivered back to the client (with any org override applied)."""
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "run_sql", "arguments": {"query": query}}}
    child, client = io.StringIO(), io.StringIO()
    mp._route_line(json.dumps(msg) + "\n", child, mp._ClientWriter(client),
                   {}, {}, 3, io.StringIO(), None)
    assert child.getvalue() == "", "mcp proxy must not forward the dangerous call"
    return json.loads(client.getvalue())["result"]["content"][0]["text"]


def test_default_coaching_reaches_both_surfaces():
    """Baseline (no override): both surfaces deliver the SHIPPED default coaching. This
    guards the tripwire itself — a surface that silently stopped delivering coaching at
    all would fail here before we even test customization."""
    assert _DEFAULT_CHALLENGE in _drive_decorator_block("DROP TABLE users;")
    assert _DEFAULT_CHALLENGE in _drive_mcp_block("DROP TABLE users;")


def test_customized_coaching_renders_identically_on_decorator_and_mcp():
    """THE invariant: a coaching customized once (keyed by the built-in id, carrying the
    policy name) reaches BOTH the decorator and the agentx-mcp block paths, and the
    shipped default no longer shows on either — proving the override actually swapped in
    on each surface (not appended, and not applied to only one)."""
    # Written exactly as `agentx customize` writes it: keyed by the built-in id, carrying
    # the policy NAME so the name-fallback matches too.
    ov.adopt(_BUILTIN["id"], challenge=_CUSTOM_CHALLENGE,
             policy_violated=_POLICY_NAME, source="customize")

    dec_text = _drive_decorator_block("DROP TABLE users;")
    mcp_text = _drive_mcp_block("DROP TABLE users;")

    # Applied on BOTH surfaces...
    assert _CUSTOM_CHALLENGE in dec_text, "decorator did not apply the customized coaching"
    assert _CUSTOM_CHALLENGE in mcp_text, "agentx-mcp did not apply the customized coaching"
    # ...and the shipped default is gone from BOTH (a real swap, not an append).
    assert _DEFAULT_CHALLENGE not in dec_text
    assert _DEFAULT_CHALLENGE not in mcp_text
