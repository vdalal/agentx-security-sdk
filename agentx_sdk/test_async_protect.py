"""Async tool support for @agentx_protect (audit finding F1).

Wrapping an `async def` tool must return an async wrapper that (a) never executes
the tool when the action is blocked, (b) awaits and returns the tool's result when
allowed, (c) routes typed blocks as a raised AgentXSecurityBlock, and (d) works
under genuine concurrency (asyncio.gather) without serializing on the event loop.

These drive the async wrapper via asyncio.run() from sync test functions, so no
pytest-asyncio plugin is required.
"""
import asyncio
import inspect
import threading

import pytest

from agentx_sdk.decorators import (
    agentx_protect,
    is_block,
    AgentXSecurityBlock,
    AgentXCircuitBreakerTripped,
    _session_stats,
    _strike_owner,
    _client,
    _get_async_executor,
    _credit_recovery,
)
import functools


@pytest.fixture(autouse=True)
def reset_session_state():
    """Clear decorator process-globals before each test (mirrors the sync suite)."""
    _session_stats["intercepts"] = 0
    _session_stats["critical_blocks"] = 0
    _session_stats["circuit_breakers_tripped"] = 0
    _session_stats["self_corrections"] = 0
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    _session_stats["human_resolved_traces"].clear()
    _session_stats["degraded_executions"] = 0
    _session_stats["consecutive_strikes"].clear()
    _session_stats["gateway_reached"] = False
    _session_stats["reasoning_enabled"] = None
    _session_stats["block_category"] = None
    _strike_owner.clear()
    yield


def test_decorator_preserves_sync_vs_async_shape():
    """A sync tool stays a sync callable; an async tool becomes a coroutine fn."""
    @agentx_protect(agent_id="shape_test")
    def sync_tool(x: str):
        return x

    @agentx_protect(agent_id="shape_test")
    async def async_tool(x: str):
        return x

    assert not inspect.iscoroutinefunction(sync_tool)
    assert inspect.iscoroutinefunction(async_tool)


def test_async_allowed_call_executes_and_returns(monkeypatch):
    """An ALLOWED async tool runs and its awaited result is returned unchanged."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    ran = {}

    @agentx_protect(agent_id="async_allow")
    async def fetch(value: str):
        ran["did"] = True
        return f"ran:{value}"

    out = asyncio.run(fetch(value="hello"))
    assert out == "ran:hello"
    assert ran.get("did") is True


def test_async_block_does_not_execute_tool():
    """A keyword-shield block on an async tool returns a block and NEVER runs the body."""
    executed = {"did": False}

    @agentx_protect(agent_id="async_block")
    async def run_sql(query: str):
        executed["did"] = True
        return f"EXECUTED:{query}"

    out = asyncio.run(run_sql(query="please clean up: DROP TABLE users;"))
    assert is_block(out)
    assert executed["did"] is False
    assert "EXECUTED" not in str(out)


def test_async_typed_block_raises_security_block():
    """A strictly-typed (-> dict) async tool raises AgentXSecurityBlock when blocked,
    since returning a string would crash a framework that validates the return type."""
    @agentx_protect(agent_id="async_typed")
    async def fetch_rows(query: str) -> dict:
        return {"ok": True}

    with pytest.raises(AgentXSecurityBlock):
        asyncio.run(fetch_rows(query="DROP TABLE accounts;"))


def test_async_gather_runs_concurrently_with_correct_verdicts(monkeypatch):
    """asyncio.gather of protected async tools: each gets its own verdict, the
    blocked one does not execute, the allowed ones do."""
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    def fake_eval(**kwargs):
        if "DROP" in str(kwargs.get("query", "")):
            return {
                "error": "AgentX Policy Violation",
                "policy_id": "POL-MOCK",
                "policy_triggered": "Mass Destructive Intent",
                "challenge": "revise",
                "receipt_id": "r",
            }
        return {"status": "ALLOWED"}

    monkeypatch.setattr(_client, "evaluate_intent", fake_eval)

    executed = []

    @agentx_protect(agent_id="async_swarm")
    async def tool(query: str):
        executed.append(query)
        return f"ran:{query}"

    async def driver():
        return await asyncio.gather(
            tool(query="safe one"),
            tool(query="DROP TABLE x"),
            tool(query="safe two"),
        )

    results = asyncio.run(driver())
    assert results[0] == "ran:safe one"
    assert is_block(results[1])
    assert results[2] == "ran:safe two"
    # The blocked call's body never ran; both safe ones did.
    assert "DROP TABLE x" not in executed
    assert set(executed) == {"safe one", "safe two"}


def test_async_does_not_block_event_loop(monkeypatch):
    """The blocking decision core runs off the event loop, so a concurrent
    asyncio task keeps making progress while protected tools are evaluated."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    @agentx_protect(agent_id="async_loop")
    async def slow_tool(value: str):
        return f"ran:{value}"

    ticks = {"n": 0}

    async def ticker():
        # If the event loop were stalled by the protected call, this could not advance.
        for _ in range(5):
            await asyncio.sleep(0)
            ticks["n"] += 1

    async def driver():
        return await asyncio.gather(slow_tool(value="a"), ticker())

    results = asyncio.run(driver())
    assert results[0] == "ran:a"
    assert ticks["n"] == 5


def test_thread_safe_counter_increments_under_threadpool(monkeypatch):
    """A ThreadPoolExecutor-style swarm of agents in one process must not lose
    counter increments to the read-modify-write race (audit finding F2). With the
    lock, total_calls is exactly the number of protected calls made."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    _session_stats["total_calls"] = 0

    @agentx_protect(agent_id="thread_swarm")
    def tool(x: str):
        return x

    n_threads, per_thread = 16, 64

    def worker():
        for i in range(per_thread):
            tool(x=str(i))

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert _session_stats["total_calls"] == n_threads * per_thread


# =============================================================================
# Review #115 fixes: trace propagation (finding 1) + dedicated executor (finding 2)
# =============================================================================

def test_async_circuit_breaker_accrues_across_calls(monkeypatch):
    """An async tool repeating a keyword-blocked action accrues strikes across
    sequential awaits in ONE task and trips the breaker. Proves the per-call trace
    is STABLE (finding 1): without the fix, copy_context mints a fresh trace each
    call, the strike resets every time, and the breaker never trips."""
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "3")

    @agentx_protect(agent_id="async_breaker")
    async def run_sql(query: str):
        return f"EXECUTED:{query}"

    async def driver():
        # No explicit start_secure_session() — the common case the fix must handle.
        for _ in range(6):
            try:
                await run_sql(query="DROP TABLE users;")
            except AgentXCircuitBreakerTripped:
                return "tripped"
        return "never"

    assert asyncio.run(driver()) == "tripped"


def test_async_recovery_credited_across_calls(monkeypatch):
    """A gateway block then a safe call on the same async session credits recovery —
    the block and the corrected call must share one trace (finding 1). Without the
    fix the two calls get different traces and recovery is never credited."""
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    calls = {"n": 0}

    def fake_eval(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"error": "AgentX Policy Violation", "policy_id": "P",
                    "policy_triggered": "Mass Destructive Intent",
                    "challenge": "revise", "receipt_id": "r"}
        return {"status": "ALLOWED"}

    monkeypatch.setattr(_client, "evaluate_intent", fake_eval)
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    @agentx_protect(agent_id="async_recover")
    async def tool(query: str):
        return f"ran:{query}"

    async def driver():
        await tool(query="dangerous thing")   # gateway BLOCK -> trace challenged
        await tool(query="safe thing")         # ALLOW on the SAME trace -> recovery

    asyncio.run(driver())
    assert len(_session_stats["recovered_traces"]) == 1


def test_async_runs_on_dedicated_executor_not_default(monkeypatch):
    """The blocking decision core runs on AgentX's own bounded pool (thread name
    `agentx-protect-*`), never asyncio's default executor, so it can't starve the
    host app's run_in_executor/to_thread (finding 2)."""
    from concurrent.futures import ThreadPoolExecutor
    assert isinstance(_get_async_executor(), ThreadPoolExecutor)

    seen = {}

    def capture_eval(**kwargs):
        seen["thread"] = threading.current_thread().name
        return {"status": "ALLOWED"}

    monkeypatch.setattr(_client, "evaluate_intent", capture_eval)
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    @agentx_protect(agent_id="async_exec")
    async def tool(x: str):
        return x

    asyncio.run(tool(x="hi"))
    # The gateway eval runs INSIDE _decide, i.e. on the executor thread.
    assert seen["thread"].startswith("agentx-protect")


# =============================================================================
# Review #115 finding 4 (functools.partial async detection) + finding 6 (recovery race)
# =============================================================================

def test_async_detected_and_awaited_through_functools_partial(monkeypatch):
    """A functools.partial-bound coroutine tool is classified as async, awaited (not
    returned un-awaited), and doesn't crash on the partial's missing __name__
    (finding 4). inspect.iscoroutinefunction alone would misclassify it as sync."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    ran = {}

    async def _impl(prefix, value):
        ran["did"] = True
        return f"{prefix}:{value}"

    protected = agentx_protect(agent_id="async_partial")(functools.partial(_impl, "P"))
    assert inspect.iscoroutinefunction(protected)  # classified async, not sync
    out = asyncio.run(protected(value="x"))
    assert out == "P:x"
    assert ran.get("did") is True


def test_partial_wrapped_async_block_does_not_crash_on_name():
    """A blocked partial-wrapped async tool exercises the func_name paths
    (log_intercept / strike key) without crashing on the missing __name__."""
    async def _impl(tag, query):
        return f"EXECUTED:{query}"

    protected = agentx_protect(agent_id="async_partial_block")(functools.partial(_impl, "t"))
    out = asyncio.run(protected(query="please DROP TABLE users;"))
    assert is_block(out)
    assert "EXECUTED" not in str(out)


def test_credit_recovery_idempotent_and_respects_human_resolved():
    """_credit_recovery transitions a challenged trace exactly once; a second call
    returns False (no double-credit / double-log), and a human-resolved trace is
    never credited (finding 6)."""
    for k in ("challenged_traces", "recovered_traces", "human_resolved_traces"):
        _session_stats[k].clear()
    t = "trace-xyz"
    _session_stats["challenged_traces"].add(t)
    assert _credit_recovery(t) is True
    assert _credit_recovery(t) is False
    assert t in _session_stats["recovered_traces"]

    _session_stats["recovered_traces"].clear()
    _session_stats["human_resolved_traces"].add(t)
    assert _credit_recovery(t) is False


def test_recovery_beat_narrated_once_on_self_correction(monkeypatch, capsys):
    """The heal-narration beat (goal K): the moment a challenged trace's retry runs
    safe, ONE dev-console line says the run was saved — and it does not repeat on
    further ALLOWs (the credit is once per trace, so the beat is too)."""
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    calls = {"n": 0}

    def fake_eval(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"error": "AgentX Policy Violation", "policy_id": "P",
                    "policy_triggered": "Mass Destructive Intent",
                    "challenge": "revise", "receipt_id": "r"}
        return {"status": "ALLOWED"}

    monkeypatch.setattr(_client, "evaluate_intent", fake_eval)
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    @agentx_protect(agent_id="async_beat")
    async def tool(query: str):
        return f"ran:{query}"

    async def driver():
        await tool(query="dangerous thing")    # gateway BLOCK -> trace challenged
        capsys.readouterr()                     # drop the block narration
        await tool(query="safe thing")          # ALLOW, same trace -> the beat
        first = capsys.readouterr().out
        await tool(query="another safe thing")  # already credited -> no repeat
        second = capsys.readouterr().out
        return first, second

    first, second = asyncio.run(driver())
    assert "Recovered" in first                   # the beat fired on the recovery
    assert "tool" in first                        # names the tool whose safe call was approved
    assert "ran safely" not in first              # claims approval, not (premature) completion
    assert "Recovered" not in second              # already credited -> no repeat


def test_credit_recovery_single_winner_under_threads():
    """Under concurrent ALLOWs on ONE shared challenged trace, exactly one call
    wins the transition — so log_self_correction (the DB write) runs once, not N
    times (finding 6: the recovery double-log race)."""
    for k in ("challenged_traces", "recovered_traces", "human_resolved_traces"):
        _session_stats[k].clear()
    t = "trace-race"
    _session_stats["challenged_traces"].add(t)

    wins = []

    def worker():
        if _credit_recovery(t):
            wins.append(1)

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert len(wins) == 1


# =============================================================================
# Review #117 findings 1/2 (coroutine detection edges) + finding 3 (strike key)
# =============================================================================

def test_class_with_async_call_not_misclassified_as_async(monkeypatch):
    """A CLASS whose body defines `async def __call__` constructs its instance
    SYNCHRONOUSLY, so it must NOT be treated as async — otherwise the async wrapper
    does `await SomeClass(...)` and raises TypeError (#117 finding 1)."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    class Tool:
        async def __call__(self, value):
            return f"async-call:{value}"

    protected = agentx_protect(agent_id="cls")(Tool)
    assert not inspect.iscoroutinefunction(protected)  # sync wrapper, not async
    result = protected()  # constructs the instance, no await crash
    assert isinstance(result, Tool)


def test_async_callable_object_instance_detected_and_awaited(monkeypatch):
    """An INSTANCE whose __call__ is a coroutine function IS detected as async and
    awaited — the __call__ fallback (guarded to instances) still works (#117 finding 2)."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: {"status": "ALLOWED"})
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")

    class AsyncTool:
        async def __call__(self, value):
            return f"obj:{value}"

    protected = agentx_protect(agent_id="obj")(AsyncTool())  # decorate the INSTANCE
    assert inspect.iscoroutinefunction(protected)
    assert asyncio.run(protected(value="z")) == "obj:z"


def test_partials_of_same_fn_do_not_share_strike_breaker(monkeypatch):
    """Two separately-decorated partials of ONE underlying fn get independent strike
    state, so add_a's offline strikes don't trip add_b's breaker (#117 finding 3).
    Pre-fix both keyed on 'handler', so add_b inherited add_a's strikes and tripped."""
    monkeypatch.setenv("AGENTX_MAX_COGNITIVE_TURNS", "3")

    async def handler(tag, query):
        return f"{tag}:{query}"

    add_a = agentx_protect(agent_id="a")(functools.partial(handler, "a"))
    add_b = agentx_protect(agent_id="b")(functools.partial(handler, "b"))

    async def driver():
        for _ in range(3):  # accrue 3 strikes on add_a (keyword-blocked, no trip yet)
            assert is_block(await add_a(query="DROP TABLE x;"))
        # add_b starts fresh: its first blocked call is a normal block, NOT a trip.
        return await add_b(query="DROP TABLE y;")

    # If add_b shared add_a's key it would raise AgentXCircuitBreakerTripped here.
    assert is_block(asyncio.run(driver()))
