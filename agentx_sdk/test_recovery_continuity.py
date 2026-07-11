"""Cross-surface tripwire for the continuity-scoped recovery credit.

A "recovery" is a SAFE call on the SAME tool that was blocked (a self-correction),
counted per BLOCK-RECOVER EPISODE. Two surfaces implement it: the @agentx_protect
decorator (trace + tool via `_credit_recovery`, since it has a per-call trace) and the
agentx-mcp proxy (tool only, since the keyless proxy has NO per-call trace). This file is
the guard that keeps the two aligned and green-on-truth / red-on-drift:

  * the decorator credits a same-tool forward-safe call, does NOT credit a cross-tool
    call (abandonment), a re-block re-opens the episode so a genuine SECOND recovery is
    credited, and a looped or human-resolved run is not counted as recovered;
  * the recovered / abandoned / looped breakdown is computed by the SAME helper the
    session summary prints (`_recovery_breakdown`), so a breakdown bug can't pass green,
    and the buckets partition the challenge episodes;
  * both surfaces agree on the shared contract for a single recovery AND a repeat
    (block -> recover -> block -> recover == 2 on each).

The one LEGITIMATE divergence (documented, not a bug): the MCP proxy is keyed by tool
name alone because it has no trace, so it cannot bound recovered by a specific run the
way the decorator does. Both still count the same episodes under the shared contract,
which is what this file pins.
"""
import io
import json

import pytest

from agentx_sdk import mcp_proxy as mp
from agentx_sdk.decorators import (
    _session_stats,
    _strike_owner,
    _mark_challenged,
    _credit_recovery,
    _trip_breaker_if_ceiling,
    _recovery_breakdown,
    AgentXCircuitBreakerTripped,
)


@pytest.fixture(autouse=True)
def _reset_recovery_state():
    """Clear every recovery process-global before each test (session-globals isolation)."""
    _session_stats["self_corrections"] = 0
    _session_stats["challenge_episodes"] = 0
    _session_stats["circuit_breakers_tripped"] = 0
    for k in ("challenged_traces", "recovered_traces", "human_resolved_traces",
              "open_challenges", "looped_traces"):
        _session_stats[k].clear()
    _session_stats["consecutive_strikes"].clear()
    _strike_owner.clear()


# --------------------------------------------------------------------------- #
# decorator surface (trace + tool)
# --------------------------------------------------------------------------- #
def test_block_alone_is_not_a_recovery():
    _mark_challenged("t", "run_sql")
    assert _session_stats["self_corrections"] == 0


def test_same_tool_forward_safe_is_credited():
    _mark_challenged("t", "run_sql")
    assert _credit_recovery("t", "run_sql") is True
    assert _session_stats["self_corrections"] == 1


def test_cross_tool_call_is_abandonment_not_recovery():
    """The D1 honesty fix: blocked on run_sql, then a safe call on a DIFFERENT tool
    means the agent abandoned the blocked action; it must NOT be credited."""
    _mark_challenged("t", "run_sql")
    assert _credit_recovery("t", "send_email") is False
    assert _session_stats["self_corrections"] == 0


def test_reblock_same_tool_is_recredited():
    """A re-block reopens the episode, so a genuine SECOND recovery on the same
    (trace, tool) is credited again (episode counting, not set dedup)."""
    _mark_challenged("t", "run_sql")
    assert _credit_recovery("t", "run_sql") is True
    _mark_challenged("t", "run_sql")                 # re-block reopens the pair
    assert _credit_recovery("t", "run_sql") is True
    assert _session_stats["self_corrections"] == 2


def test_closed_challenge_is_not_double_credited():
    _mark_challenged("t", "run_sql")
    assert _credit_recovery("t", "run_sql") is True
    assert _credit_recovery("t", "run_sql") is False   # already closed, no re-block
    assert _session_stats["self_corrections"] == 1


def test_human_resolved_trace_is_not_credited():
    _mark_challenged("t", "run_sql")
    _session_stats["human_resolved_traces"].add("t")
    assert _credit_recovery("t", "run_sql") is False
    assert _session_stats["self_corrections"] == 0


def test_breaker_trip_marks_the_trace_looped():
    _session_stats["consecutive_strikes"]["http_get"] = 3
    with pytest.raises(AgentXCircuitBreakerTripped):
        _trip_breaker_if_ceiling("http_get", 3, "loop halt", trace_id="t-loop")
    assert "t-loop" in _session_stats["looped_traces"]


def test_recovery_breakdown_partitions_episodes_via_the_real_helper():
    """Exercises the SAME _recovery_breakdown the session summary prints (not an inline
    copy), with one episode of each outcome, and confirms the four buckets (recovered /
    abandoned / looped / human-approved) partition the challenge episodes. Pins the fix
    that human-approved runs are excluded from 'abandoned'."""
    _mark_challenged("t-rec", "run_sql")
    _credit_recovery("t-rec", "run_sql")                       # recovered

    _mark_challenged("t-aband", "delete_files")               # abandoned (left open)

    _mark_challenged("t-loop", "http_get")                    # looped
    _session_stats["consecutive_strikes"]["http_get"] = 3
    with pytest.raises(AgentXCircuitBreakerTripped):
        _trip_breaker_if_ceiling("http_get", 3, "loop halt", trace_id="t-loop")

    _mark_challenged("t-human", "wire_transfer")              # human-approved (not abandoned)
    _session_stats["human_resolved_traces"].add("t-human")

    total, recovered, abandoned, looped = _recovery_breakdown()
    assert (total, recovered, abandoned, looped) == (4, 1, 1, 1)
    # the human-approved episode is excluded from abandoned; the four buckets sum to total
    assert total - recovered - abandoned - looped == 1


def test_reblock_of_an_open_pair_is_the_same_episode_not_a_new_one():
    """A RE-block of an already-open (trace, tool) is the agent retrying the SAME blocked
    action (the loop the breaker exists for), so it is the same episode. Bumping the counter
    unconditionally grew the denominator while `open_challenges` (a set) did not grow, so the
    buckets stopped partitioning and the rate DEFLATED. Caught live by pr-overnight: example
    04 printed "of 3 challenge(s): 0 recovered - 0 abandoned - 1 looped" (sum 1, not 3)."""
    for _ in range(3):
        _mark_challenged("t", "run_sql")                       # blocked 3x, same action

    assert _session_stats["challenge_episodes"] == 1, "a re-block must not open a new episode"

    total, recovered, abandoned, looped = _recovery_breakdown()
    assert (total, recovered, abandoned, looped) == (1, 0, 1, 0)
    assert recovered + abandoned + looped == total, "buckets must partition the episodes"


def test_repeat_block_then_recovery_is_a_full_recovery_not_a_third():
    """3 blocks of one action, then a same-tool self-correct = ONE episode, RECOVERED: the
    session rate is 100%, not 33.3%. The denominator counts episodes, not intercepts."""
    for _ in range(3):
        _mark_challenged("t", "run_sql")
    assert _credit_recovery("t", "run_sql") is True

    total, recovered, abandoned, looped = _recovery_breakdown()
    assert (total, recovered, abandoned, looped) == (1, 1, 0, 0)
    assert recovered / total == 1.0


# --------------------------------------------------------------------------- #
# MCP proxy surface (tool only, no trace)
# --------------------------------------------------------------------------- #
def _line(*, id=1, name="run_sql", arguments=None):
    return json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": id,
                       "params": {"name": name, "arguments": arguments or {}}}) + "\n"


def _mcp_recoveries(scenario):
    """Drive an ordered scenario of JSON-RPC lines through the proxy routing core and
    return its self_corrections count. Mirrors test_mcp_proxy._route."""
    stats, streaks = {}, {}
    for line in scenario:
        mp._route_line(line, io.StringIO(), mp._ClientWriter(io.StringIO()), stats,
                       streaks, 3, io.StringIO(), None)
    return stats.get("self_corrections", 0)


def test_mcp_block_alone_is_not_a_recovery():
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    assert _mcp_recoveries([danger]) == 0


def test_mcp_same_tool_block_then_allow_is_one_recovery():
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    safe = _line(name="run_sql", arguments={"query": "SELECT 1"})
    assert _mcp_recoveries([danger, safe]) == 1


def test_mcp_repeat_recovery_counts_two_episodes():
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    safe = _line(name="run_sql", arguments={"query": "SELECT 1"})
    assert _mcp_recoveries([danger, safe, danger, safe]) == 2


# --------------------------------------------------------------------------- #
# cross-surface: the two must agree on the shared contract, single AND repeat
# --------------------------------------------------------------------------- #
def _decorator_recoveries(episodes):
    """Run `episodes` block->recover cycles on the decorator surface and return the
    self_corrections episode count."""
    for i in range(episodes):
        _mark_challenged("t", "run_sql")
        _credit_recovery("t", "run_sql")
    return _session_stats["self_corrections"]


def test_both_surfaces_agree_block_alone_is_zero():
    _mark_challenged("t", "run_sql")
    dec_count = _session_stats["self_corrections"]
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    assert dec_count == _mcp_recoveries([danger]) == 0


def test_both_surfaces_agree_single_recovery_is_one():
    dec_count = _decorator_recoveries(1)
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    safe = _line(name="run_sql", arguments={"query": "SELECT 1"})
    assert dec_count == _mcp_recoveries([danger, safe]) == 1


def test_both_surfaces_agree_repeat_recovery_is_two():
    """Both surfaces count recovery EPISODES, so a repeat block->recover->block->recover
    is 2 on each (this is the case the old set-based decorator silently under-counted)."""
    dec_count = _decorator_recoveries(2)
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    safe = _line(name="run_sql", arguments={"query": "SELECT 1"})
    assert dec_count == _mcp_recoveries([danger, safe, danger, safe]) == 2
