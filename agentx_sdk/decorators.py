import os
import sys
import json
import atexit
import time
import functools
import uuid
import requests
import re
import logging
import atexit
import asyncio
import inspect
import threading
import contextvars
from contextvars import ContextVar

from .client import AgentXClient
from .db import init_db, log_intercept, get_lifetime_stats, log_self_correction
from . import pulse
from .overrides import get_active_override


# =====================================================================
# 🖥️ CONSOLE ENCODING HARDENING
# =====================================================================
# Our intercept + session-summary output carries status glyphs (🛡️ 🛑 ⚡). On a
# host whose stream encoding is a legacy code page — the Windows default cp1252,
# or any piped / redirected / CI run — those glyphs cannot be encoded, so the
# FIRST protected call would raise UnicodeEncodeError and abort the block BEFORE
# it returned. Re-encode stdout/stderr as UTF-8 (errors="replace") at import so
# protection never depends on the terminal's code page. Fully guarded and
# best-effort: a missing, captured, or non-reconfigurable stream is left as-is.
# =====================================================================
def _ensure_utf8_console():
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is None or not hasattr(stream, "reconfigure"):
                continue
            if "utf" not in (getattr(stream, "encoding", "") or "").lower():
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            # Never let console hardening break import or a tool call.
            pass


_ensure_utf8_console()


# =====================================================================
# ⚠️ FAIL-OPEN WARNING CHANNEL
# =====================================================================
# Routed through logging (WARNING level) rather than print(): WARNING+ surfaces
# even when the host app never configures logging, integrates with their
# handlers, and is alertable by ops — whereas agent frameworks routinely swallow
# stdout. One loud banner per process, then a concise line per call, so we
# neither spam the logs nor silently hide a safety downgrade.
# =====================================================================
logger = logging.getLogger("agentx")
_FAILOPEN_BANNER_SHOWN = False
_FAILMODE_WARNED = False


def _emit_failopen_warning(reason, tool_name):
    """Warn that a tool ran without gateway-side semantic checks (fail-open)."""
    global _FAILOPEN_BANNER_SHOWN

    # Is the in-process deterministic floor still up? It is, unless the developer
    # explicitly disabled it — in which case this call truly had NO AgentX checks.
    shield_active = bool(LOCAL_POLICY_KEYWORDS) and \
        os.environ.get("AGENTX_BYPASS_LOCAL_SHIELD", "false").lower() != "true"

    if reason == "timeout":
        # Gateway is UP but didn't answer in time — it may have been mid-evaluation
        # and about to block. This is the riskier of the two failure modes.
        cause = ("Reasoning Engine did not respond in time — it is running but slow "
                 "and may have been mid-evaluation.")
    else:
        cause = "Reasoning Engine is unreachable (down or not routable)."

    if shield_active:
        floor = ("Offline keyword shield STILL ENFORCED for deterministic threats; "
                 "only neural / chain-of-thought semantic checks were bypassed.")
    else:
        floor = "Offline shield is DISABLED — this tool ran with NO AgentX checks."

    if not _FAILOPEN_BANNER_SHOWN:
        logger.warning(
            "\n"
            "════════════════════════════════════════════════════════════\n"
            " ⚠️  AgentX DEGRADED PROTECTION — failing OPEN\n"
            "────────────────────────────────────────────────────────────\n"
            f" {cause}\n"
            f" Tool '{tool_name}' was executed.\n"
            f" {floor}\n"
            " Start the engine:  docker-compose up -d\n"
            "════════════════════════════════════════════════════════════"
        )
        _FAILOPEN_BANNER_SHOWN = True
    else:
        mode = "timeout" if reason == "timeout" else "engine unreachable"
        tail = "offline shield active" if shield_active else "NO checks"
        logger.warning(
            f"[AgentX] DEGRADED: '{tool_name}' ran with gateway bypassed "
            f"({mode}; {tail})."
        )


def _emit_failclosed_warning(reason, tool_name):
    """Warn that a tool was BLOCKED (fail-closed) because the engine couldn't vet it.

    No banner/throttle needed — under AGENTX_FAIL_MODE=closed the block itself is
    the loud signal; this line just explains why the action was held.
    """
    cause = "did not respond in time" if reason == "timeout" else "is unreachable"
    logger.warning(
        f"[AgentX] FAIL-CLOSED: '{tool_name}' BLOCKED — Reasoning Engine {cause}; "
        f"action NOT executed (AGENTX_FAIL_MODE=closed). Set AGENTX_FAIL_MODE=open to allow."
    )


def _resolve_fail_mode():
    """Resolve AGENTX_FAIL_MODE to 'open' or 'closed', warning once on a bad value.

    A security toggle must never be silently disabled by a typo: any unrecognized
    value (e.g. 'close', 'true', '1') falls back to the documented default 'open'
    but is surfaced loudly, so an operator who intended fail-CLOSED finds out
    instead of unknowingly running fail-OPEN through an outage.
    """
    global _FAILMODE_WARNED
    raw = os.environ.get("AGENTX_FAIL_MODE", "open").strip().lower()
    if raw == "":
        raw = "open"
    if raw in ("open", "closed"):
        return raw
    if not _FAILMODE_WARNED:
        logger.warning(
            f"[AgentX] Unrecognized AGENTX_FAIL_MODE={raw!r}; expected 'open' or 'closed'. "
            f"Falling back to 'open' (fail-open) — fix the value to engage fail-closed."
        )
        _FAILMODE_WARNED = True
    return "open"

# =====================================================================
# 🎛️ SDK CLIENT-SIDE MODEL ENVIRONMENT DESERIALIZATION
# =====================================================================
# Synchronizes the client processing layout with the gateway proxy definitions,
# defaulting safely to 'gemini-2.5-flash' but tracking variable updates.
# =====================================================================
AGENTX_EVALUATION_MODEL = os.getenv("AGENTX_EVALUATION_MODEL", "gemini-2.5-flash")

_client = AgentXClient()

# Initialize the local SQLite DB on startup
init_db()

# --- 0. THE TRACE ID CONTEXT ---
trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")

def start_secure_session():
    """Call this at the top of your agent script to group logs into a single session."""
    session_id = str(uuid.uuid4())
    trace_id_var.set(session_id)
    return session_id

# --- NEW: CIRCUIT BREAKER EXCEPTION ---
class AgentXCircuitBreakerTripped(Exception):
    """Raised when an agent is caught in an infinite apology loop.

    This is a loop-HALT, not a policy block: the agent kept retrying a blocked
    action with no progress, so AgentX stopped the run to prevent token drain.
    It is delivered ONLY as a raised exception (never a return value) and is
    deliberately distinct from a policy block — `is_block()` returns False for it.
    Catch it on its own to abort the task / alert a human."""
    pass


# =====================================================================
# 🧱 THE BLOCK RESULT CONTRACT (developer-facing — read this)
# =====================================================================
# When a protected tool call is blocked, you get the block back as STRUCTURED
# DATA — you never parse a prose blob. It reaches you one of two ways depending
# on your tool's return type, but BOTH carry the same fields:
#
#   • untyped / `-> str` tool        → returns an `AgentXBlock` (a str subclass,
#       so print() and any legacy string checks keep working, with fields attached)
#   • strictly-typed tool (-> dict)  → raises `AgentXSecurityBlock`
#       (returning a string would crash a framework that validates the type)
#
# Detect a block uniformly with `is_block(result)` (return path) or by catching
# `AgentXSecurityBlock` (raise path). Both expose:
#     .blocked     True
#     .policy      policy name that fired      ("Mass Destructive Intent")
#     .challenge   the Socratic challenge — what to do instead; feed this to your LLM
#     .safe_path   the policy's preferred alternative, if it names one (else None)
#     .receipt_id  incident id — pass it back on retry to thread the recovery loop
#
# A circuit-breaker trip (the agent looping with no progress) is a SEPARATE event:
# it always RAISES `AgentXCircuitBreakerTripped`, is not a policy block, and
# `is_block()` returns False for it — catch that exception on its own.
# =====================================================================
class AgentXBlock(str):
    """The result of a blocked tool call, returned for untyped / `-> str` tools.

    It IS a real string (so `print(result)`, `isinstance(result, str)`, and any
    legacy `"AgentX Security Block" in result` check keep working unchanged) and
    it ALSO carries the block's structured fields, so you never parse the prose:

        result = run_sql(query, cot=thought)
        if agentx.is_block(result):
            llm.send(result.challenge)              # the safe path to retry on
            run_sql(revised, receipt_id=result.receipt_id)
    """
    blocked = True

    def __new__(cls, prose, *, policy=None, challenge=None, receipt_id=None,
                safe_path=None):
        obj = super().__new__(cls, prose)
        obj.policy = policy
        obj.challenge = challenge if challenge is not None else str(prose)
        obj.receipt_id = receipt_id
        obj.safe_path = safe_path
        return obj


class AgentXSecurityBlock(Exception):
    """Raised when a blocked tool is strictly typed (returning a string would crash
    a framework that validates the return type — LangChain / Pydantic tools).

    Carries the same structured fields as `AgentXBlock`. Catch it and feed
    `.challenge` back to your agent's LLM so it can self-correct:

        try:
            data = fetch_user(uid)            # -> dict
        except AgentXSecurityBlock as block:
            llm.send(block.challenge)
    """
    blocked = True

    def __init__(self, message, receipt_id=None, policy_name=None,
                 challenge=None, safe_path=None):
        super().__init__(message)
        self.receipt_id = receipt_id
        self.policy = policy_name            # canonical, mirrors AgentXBlock.policy
        self.policy_name = policy_name       # kept for backward compatibility
        self.challenge = challenge if challenge is not None else message
        self.safe_path = safe_path
        self.socratic_nudge = message        # kept for backward compatibility


def is_block(result) -> bool:
    """True if a protected tool call was blocked by a security POLICY.

    True for the value an untyped tool returns (`AgentXBlock`) and for a caught
    `AgentXSecurityBlock` (strictly-typed tools) — both carry `.policy` /
    `.challenge` / `.safe_path`. A circuit-breaker trip is NOT a policy block: it
    raises `AgentXCircuitBreakerTripped`, which you catch separately, and
    `is_block()` returns False for it. Use this instead of substring-matching the
    message — the message text is not a stable API."""
    return getattr(result, "blocked", False) is True

# --- 1. THE SESSION TRACKER & EXIT SUMMARY ---
_session_stats = {
    "start_time": time.time(),
    "total_calls": 0,
    "intercepts": 0,
    "critical_blocks": 0,
    "self_corrections": 0,
    # Per-trace recovery accounting (mirrors the dashboard's per-session model):
    # recovery rate = |recovered_traces| / |challenged_traces|, bounded <=100% by
    # construction since recovered is always a subset of challenged. Replaces the
    # old global `last_call_was_challenge` boolean, which could seed a correction
    # with no matching intercept (the fail-closed path) and drift the rate >100%.
    "challenged_traces": set(),        # traces that hit a policy challenge this session
    "recovered_traces": set(),         # challenged traces the agent self-corrected on
    "human_resolved_traces": set(),    # challenged traces resolved by a human (not autonomous)
    "consecutive_strikes": {},         # <-- Tracks repeated failures per tool function name
    "circuit_breakers_tripped": 0,     # <-- Stable initialization key preserved
    "human_escalations": 0,            # <-- SURGICAL REFACTOR: Local tracker variable added
    "degraded_executions": 0,          # <-- Tool calls that ran fail-open (gateway unreachable / timed out)
    "gateway_reached": False,          # <-- True once any real gateway verdict came back this session (NOT unreachable). Coarse funnel-stage signal for the anonymous pulse: distinguishes "SDK only" from "SDK + gateway". Never carries identity.
    "reasoning_enabled": None,         # <-- Tri-state Recover signal for the pulse: None = no gateway ever advertised it (old gateway / SDK-only), False = gateway reported keyless, True = judge seen active (sticky). Never identity.
    "block_category": None,            # <-- Coarse closed-vocab failure class of a block this session (DESTRUCTIVE_ACTION/etc), for the pulse. "What KIND of action got blocked", never the tool name/payload. None = no categorized block. See _BLOCK_CATEGORY_VOCAB.
    "overrides_applied": 0,            # <-- BUILD #2: blocks where an adopted org reframe replaced the gateway's generic challenge
    # Session budget meter (AFDB #17/#23). The gateway's budget-ceiling floor reads
    # the running total off the payload; we feed it from one of two sources:
    "auto_tokens_estimate": 0,         # coarse ~4-chars/token proxy over inspected payloads — zero-config, catches runaway-loop VOLUME
    "reported_tokens": 0,              # REAL LLM usage fed via record_spend(); authoritative — replaces the estimate when present
    "reported_cost_usd": 0.0           # REAL $ via record_spend(); drives the dollar ceiling (no built-in $ estimate — that needs a model rate)
}

# Per-tool ownership of the live strike run. Maps func_name -> the trace_id whose
# blocked-retry run currently owns that tool's `consecutive_strikes` counter.
#
# Scope after issue #80: the gateway now OWNS the online strike count + the Path B
# decision (per-trace _STRIKE_TRACKER), so `consecutive_strikes` is the SDK's LOCAL
# fallback for the block classes the gateway never sees — fail-closed blocks while
# the gateway is unreachable, AND Layer-0 keyword-shield blocks (which short-circuit
# before any gateway round-trip, online or offline). This map still matters: the counter is
# process-global and keyed by tool name alone, so without it one offline session's
# blocked retries would carry over and trip the offline breaker on the NEXT
# session's first (possibly benign) call on the same tool (the blind-eval "Circuit
# Breaker" false positive, fixed in PR #79). We reset a tool's strikes the moment a
# DIFFERENT trace_id calls it, so every new session starts every tool at zero. A
# tool whose owner is unset is adopted by the current trace WITHOUT a reset, so the
# very first call and pre-seeded test state behave exactly as before.
# Scope note: this isolates by trace CHANGE, not concurrent interleaving — two live
# traces alternating calls to one tool in a single process is out of scope (the
# gateway's per-trace no-progress-loop breaker, Path C, still covers a repeat loop).
_strike_owner = {}

# Guards the once-per-process protection-streak record in _print_agentx_summary
# (which is both atexit-registered and a documented manual call), so a manual +
# atexit run doesn't double-count the streak. Process-lifetime; no test flips it.
_protection_recorded = False

# Set by a curated caller (agentx demo) that prints its OWN single closing screen, so
# the atexit summary skips its duplicate visual box while STILL running the two
# funnel-critical side effects: record the streak and emit the anonymous activation
# pulse. This is why the demo can't just atexit.unregister the summary — that would make
# an install that ran the demo an invisible download again. Default off.
_atexit_summary_quiet = False


def set_atexit_summary_quiet(quiet=True):
    """Let a curated caller (e.g. `agentx demo`) own a single closing screen while the
    atexit summary keeps its side effects (streak + activation pulse) and drops only the
    redundant box. Process-lifetime toggle; the demo is a one-shot CLI process."""
    global _atexit_summary_quiet
    _atexit_summary_quiet = quiet

# Thread-safety for the shared session state (audit finding F2). The block
# DECISION never depends on these numbers, but `_session_stats` is one process-
# global dict and a read-modify-write `+= 1` is not atomic. Multiple agents in
# ONE process now touch it concurrently — a ThreadPoolExecutor swarm, OR async
# tools whose (blocking) decision core runs in an executor thread (see the async
# wrapper) — so EVERY mutation of the shared offline-strike state runs through the
# helpers below under one lock: the increments AND the resets / owner flips. A bare
# unlocked `consecutive_strikes[name] = 0` reset could otherwise interleave with a
# locked `+= 1` and be silently undone (a strike resurrected after a legitimate
# ALLOW — review #115 finding 3). RLock (not Lock) is deliberate: _trip_breaker and
# these helpers may be composed, so re-entrant acquisition must be safe. Held only
# for the cheap mutation, never across I/O, so no meaningful hot-path contention.
#
# Residual (documented, best-effort): the OFFLINE breaker's check-then-increment
# (`_trip_breaker_if_ceiling` reads the count, the caller then increments) still has
# a small TOCTOU window under a same-tool swarm with the gateway UNREACHABLE — the
# COUNT is now consistent (no lost updates), only the trip edge can be off by one.
# The gateway owns the online strike count per-trace (Path B), so this is degraded-
# mode only.
_stats_lock = threading.RLock()


def _incr(key, n=1):
    """Thread-safe increment of a scalar `_session_stats` counter."""
    with _stats_lock:
        _session_stats[key] += n


def _incr_strike(func_name, n=1):
    """Thread-safe increment of the per-tool offline strike counter."""
    with _stats_lock:
        _session_stats["consecutive_strikes"][func_name] += n


def _adopt_strike_trace(func_name, trace_id):
    """Scope the per-tool offline-strike counter to the live trace, atomically.
    Reset the count when a DIFFERENT trace takes over the tool (so a prior session's
    blocked-retry run can't trip the breaker on this one), adopt an unset owner
    WITHOUT a reset (first-call / pre-seeded behaviour), and ensure the key exists.
    Done under the lock so the reset can't race a concurrent `_incr_strike`."""
    with _stats_lock:
        prev = _strike_owner.get(func_name)
        if prev and prev != trace_id:
            _session_stats["consecutive_strikes"][func_name] = 0
        _strike_owner[func_name] = trace_id
        _session_stats["consecutive_strikes"].setdefault(func_name, 0)


def _reset_strike(func_name):
    """Reset a tool's offline-strike counter to 0 under the lock — on a gateway
    ALLOW or a fail-open execution (the trace made progress) — so the reset can't
    race a concurrent locked increment and be lost."""
    with _stats_lock:
        _session_stats["consecutive_strikes"][func_name] = 0


def _mark_trace(set_name, trace_id):
    """Add a trace_id to one of the recovery-accounting sets under the lock, so the
    success-path recovery check sees a consistent view (review #115 finding 6)."""
    with _stats_lock:
        _session_stats[set_name].add(trace_id)


def _credit_recovery(trace_id):
    """Atomically credit a self-correction for `trace_id` and return True iff THIS
    call is the one that transitioned it to recovered — so the caller logs the DB
    row exactly once, OUTSIDE the lock. A trace is credited only if it was
    challenged, not already recovered, and not human-resolved. Concurrent ALLOWs on
    one shared trace can't double-credit / double-log (review #115 finding 6)."""
    with _stats_lock:
        s = _session_stats
        if (trace_id in s["challenged_traces"]
                and trace_id not in s["recovered_traces"]
                and trace_id not in s["human_resolved_traces"]):
            s["recovered_traces"].add(trace_id)
            s["self_corrections"] = len(s["recovered_traces"])
            return True
        return False


def _returns_coroutine(fn):
    """True if calling `fn` yields a coroutine. `asyncio.iscoroutinefunction` unwraps
    functools.partial (which `inspect.iscoroutinefunction` does NOT — review #115
    finding 4), so a partial-bound async tool (functools.partial(my_async_tool, conn))
    is detected rather than misclassified sync (which would return an un-awaited
    coroutine — body never runs, PII scrub bypassed). Falls back to an async callable
    OBJECT — an INSTANCE whose __call__ is a coroutine function (also partial-unwrapped
    via asyncio) — but explicitly NOT a class or plain routine: a class with
    `async def __call__` constructs its instance SYNCHRONOUSLY, so treating it as async
    would `await SomeClass(...)` and raise TypeError (review #117 findings 1 + 2 + 5)."""
    if asyncio.iscoroutinefunction(fn):
        return True
    if inspect.isclass(fn) or inspect.isroutine(fn):
        return False
    call = getattr(fn, "__call__", None)
    return call is not None and asyncio.iscoroutinefunction(call)


def _func_display_name(fn):
    """A usable tool name even when `fn` is a functools.partial (which has no
    __name__) or a callable object: unwrap partials to the underlying function,
    else fall back to the type name. Used for the strike key, logs, and telemetry
    so a partial-wrapped async tool (review #115 finding 4) never crashes on
    `func.__name__`."""
    while isinstance(fn, functools.partial):
        fn = fn.func
    return getattr(fn, "__name__", None) or type(fn).__name__


# A DEDICATED, bounded thread pool for running the (blocking) decision core off the
# event loop in the async path (review #115 finding 2). Kept SEPARATE from asyncio's
# default executor so AgentX's blocking work — the gateway round-trip, and especially
# the up-to-120s HITL poll — can never starve the host app's own run_in_executor /
# asyncio.to_thread (DB drivers, file I/O). Sized by AGENTX_ASYNC_MAX_WORKERS
# (default 16); a swarm larger than the pool serializes AgentX decisions but never
# blocks the host app. Lazily created so a purely-sync install never spins threads.
_async_executor = None
_async_executor_lock = threading.Lock()


def _get_async_executor():
    global _async_executor
    if _async_executor is None:
        with _async_executor_lock:
            if _async_executor is None:
                from concurrent.futures import ThreadPoolExecutor
                workers = max(1, int(os.environ.get("AGENTX_ASYNC_MAX_WORKERS", "16")))
                _async_executor = ThreadPoolExecutor(
                    max_workers=workers, thread_name_prefix="agentx-protect"
                )
    return _async_executor


def reset_strike_state():
    """Clear all circuit-breaker strike counters and their per-tool trace ownership.

    Call this between independent agent sessions/tasks that share one process — e.g.
    an eval or batch harness looping over tasks — so one session's blocked-retry run
    can never trip the breaker on the next session's first call. The SDK already
    auto-resets a tool's strikes when the active trace_id changes (see the protect
    wrapper); this is the explicit, belt-and-suspenders reset for harness code that
    wants a guaranteed clean slate regardless of trace handling. Cumulative summary
    counters (intercepts, critical blocks, recoveries, …) are left intact."""
    _session_stats["consecutive_strikes"].clear()
    _strike_owner.clear()


def record_spend(tokens: int = 0, cost_usd: float = 0.0):
    """Report this session's REAL LLM spend so the gateway's budget-ceiling floor
    (AFDB #17 AutoGPT $120/8hr, #23 AgentGPT 50-step crash) sees true usage rather
    than the coarse built-in estimate. Call it with your LLM client's usage after
    each completion — e.g. `agentx.record_spend(tokens=resp.usage.total_tokens)`,
    optionally `cost_usd=...`. Authoritative: once you report real tokens they
    replace the auto-estimate, and reported dollars enable the dollar ceiling
    (there is no built-in $ estimate, since that requires a per-model rate). Safe
    to leave unused — the token proxy still catches runaway loops by volume."""
    with _stats_lock:
        if tokens:
            _session_stats["reported_tokens"] += int(tokens)
        if cost_usd:
            _session_stats["reported_cost_usd"] += float(cost_usd)

def _apply_org_override(policy_id, challenge_text, safe_path, policy_name=None):
    """BUILD #2 — swap an adopted org reframe into a block before delivery. The
    SINGLE home for the override logic, shared by BOTH block paths (the gateway
    "Policy Violation" path and the Layer-0 keyword shield) so they can't drift.
    Returns ``(challenge_text, safe_path)``.

    ``policy_name`` is threaded so the lookup can fall back to the policy NAME
    when the id misses — the same logical policy is keyed by different ids across
    the two paths (keyword-shield seed UUID vs gateway/judge id), and an override
    adopted under one would otherwise flicker out on the other.

    Total best-effort: no/blank override → inputs returned unchanged. Counts and
    announces a swap ONLY when it actually changes the delivered block, so the
    'Org Reframes Applied' proof metric never inflates on a no-op override whose
    text already equals the generic challenge."""
    override = get_active_override(policy_id, policy_name=policy_name)
    if not override:
        return challenge_text, safe_path
    new_challenge = override.get("challenge") or challenge_text
    new_safe = override.get("safe_path") or safe_path
    if new_challenge == challenge_text and new_safe == safe_path:
        return challenge_text, safe_path          # adopted override is a no-op — don't count it
    _incr("overrides_applied")
    print(f"🧭 [AgentX SDK] Applied your org's adopted safe-path for policy '{policy_id}'.")
    return new_challenge, new_safe


def _trip_breaker_if_ceiling(func_name, max_allowed_turns, raise_message, log_message=None):
    """Halt a runaway loop on a LOCAL block path the gateway never sees — the
    Layer-0 keyword shield and the REASONING_ENGINE_UNREACHABLE offline fallback.
    Both decide off the same per-tool ``consecutive_strikes`` counter; centralising
    the ceiling-check + trip-count + raise here keeps that decision from drifting
    between the two paths. Raises ``AgentXCircuitBreakerTripped`` (with the
    caller's message) once the strike count has reached the ceiling; a no-op below
    it. ``log_message``, if given, is printed only on the trip. Callers increment
    the strike count themselves after a non-trip."""
    # Read the count under the lock for a consistent value, then release BEFORE the
    # locked _incr below (no nested acquisition needed on the trip path).
    with _stats_lock:
        tripped = _session_stats["consecutive_strikes"][func_name] >= max_allowed_turns
    if tripped:
        _incr("circuit_breakers_tripped")
        if log_message:
            print(log_message)
        raise AgentXCircuitBreakerTripped(raise_message)


def _print_agentx_summary():
    """Fires automatically when the developer's script ends or crashes."""

    # Re-harden the console: this runs at atexit, by which point a host (pytest,
    # a framework, a redirection context) may have swapped sys.stdout back to a
    # legacy code page after our import-time pass. Cheap no-op once UTF-8.
    _ensure_utf8_console()

    # Drain any fire-and-forget incident parks (issue #3) so a short script doesn't
    # exit and silently drop them. Bounded inside drain_pending_parks so a wedged
    # control plane can never hang shutdown; a no-op when nothing is pending.
    try:
        _client.drain_pending_parks(timeout=2.0)
    except Exception:
        pass

    # Only print if we actually did something this session to avoid terminal spam
    if _session_stats["total_calls"] == 0 and _session_stats["intercepts"] == 0 and _session_stats["human_escalations"] == 0:
        return

    # Quiet mode: a curated caller (agentx demo) already printed its own single close.
    # Skip the duplicate box, but KEEP the funnel-critical side effects — record the
    # streak and emit the anonymous activation pulse — so the demo still counts as an
    # activated install and still extends the streak.
    global _protection_recorded
    if _atexit_summary_quiet:
        if not _protection_recorded:
            _protection_recorded = True
            pulse.record_protection(_session_stats)
        if not pulse.is_automation_context():
            pulse.on_session_end(_session_stats)
            _client.auto_contribute(gateway_reached=_session_stats["gateway_reached"])
        return

    duration = round(time.time() - _session_stats["start_time"], 2)
    session_tokens = _session_stats["intercepts"] * 1500
    session_time = _session_stats["intercepts"] * 5
    
    # Circuit breaker trips
    cb_trips = _session_stats.get("circuit_breakers_tripped", 0)
    
    # Calculate hypothetical savings (e.g., preventing 10 loop iterations)
    loop_tokens_saved = cb_trips * 15000 
    loop_time_saved = cb_trips * 50

    # Fetch historical data
    try:
        history = get_lifetime_stats()
        if not history:
            raise ValueError("No history")
    except Exception:
        # Fallback if the local DB is fresh or errors out
        history = {
            "total_intercepts": _session_stats["intercepts"],
            "total_critical": _session_stats["critical_blocks"],
            "total_tokens": session_tokens,
            "total_time": session_time,
            "top_offender": None
        }

    print("\n" + "═"*60)
    print(f" 🛡️  AgentX Session Summary (Trace: {trace_id_var.get() or 'N/A'})")
    print("═"*60)
    print(f" ⏱️  Uptime:                {duration} seconds")
    print(f" 🛠️  Tools Monitored:       {_session_stats['total_calls']}")
    print("─"*60)
    
    # The Action-Oriented UI
        
    # 1. Calculate Session Recovery Rate — per trace (session), bounded <=100%
    #    because recovered_traces is always a subset of challenged_traces. Snapshot
    #    both lengths under the lock so a concurrent _credit_recovery / _mark_trace
    #    can't tear the numerator/denominator if the summary prints mid-session
    #    (#117 finding 4 — the read side of finding 6's write locking).
    with _stats_lock:
        challenged_sessions = len(_session_stats["challenged_traces"])
        recovered_sessions = len(_session_stats["recovered_traces"])
    session_recovery_rate = (
        (recovered_sessions / challenged_sessions) * 100
        if challenged_sessions else 0.0
    )
        
    # 2. Calculate Cumulative Recovery Rate
    cumulative_recovery_rate = 0.0
    if history.get('total_intercepts', 0) > 0:
        cumulative_recovery_rate = (history.get('total_self_corrections', 0) / history['total_intercepts']) * 100

    # 3. Print the aligned matrix
    print(f" 🛑 Intercepts:            {_session_stats['intercepts']:<3} |  Cumulative: {history.get('total_intercepts', 0)}")
    print(f" 💥 Critical Blocks:       {_session_stats['critical_blocks']:<3} |  Cumulative: {history.get('total_critical', 0)}")
    
    # --- FIXED: Display the Human Override metrics cleanly inside the table block layout ---
    print(f" 🚨 Human Escalations:     {_session_stats['human_escalations']:<3} |  Cumulative: {_session_stats['human_escalations']}")

    # --- DEGRADED PROTECTION AUDIT: only surfaces when the gateway was down/slow,
    #     so a fully-protected run stays clean and this line stands out when it appears ---
    if _session_stats.get("degraded_executions", 0) > 0:
        print(f" ⚠️  Degraded Executions:   {_session_stats['degraded_executions']:<3} |  ran WITHOUT gateway semantic checks (fail-open)")
        print("     -> the gateway would have evaluated these — get it (free, runs locally): https://bit.ly/agentfirewall")
    
    # --- CIRCUIT BREAKER METRICS ---
    if cb_trips > 0:
        print(f" 🔌 Breakers Tripped:      {cb_trips:<3} |  Loop Savings: ~{loop_tokens_saved} tokens")
        # Add the loop savings to BOTH the session stats and the cumulative stats
        session_tokens += loop_tokens_saved
        session_time += loop_time_saved
        if 'total_tokens' in history:
            history['total_tokens'] += loop_tokens_saved
        if 'total_time' in history:
            history['total_time'] += loop_time_saved

    print(f" 🔄 Self-Corrections:      {_session_stats['self_corrections']:<3} |  Cumulative: {history.get('total_self_corrections', 0)}")
    print(f" 📈 Recovery Rate:         {session_recovery_rate:<3.1f}% |  Cumulative: {cumulative_recovery_rate:.1f}%")

    # --- PROTECTION STREAK: the retention half of the value report — a reason to
    #     keep the SDK wired after the first catch. LOCAL-ONLY bookkeeping in
    #     pulse.json (outside the pulse allowlist, never transmitted). None — and
    #     no line — for an idle session or an automation/CI run. Recorded at most
    #     ONCE per process: this summary is atexit-registered AND a documented manual
    #     call (examples/02), so an unguarded record would double-count the streak on
    #     a manual+atexit run. The shared formatter keeps the wording identical to the
    #     agentx-mcp report so the two surfaces can't drift.
    if not _protection_recorded:
        _protection_recorded = True
        protection = pulse.record_protection(_session_stats)
        if protection:
            print(f" 🔥 Protection Streak:     {pulse.format_protection_line(protection)}")

    # --- BUILD #2: ORG-REFRAME LOOP — only surfaces when relevant, so a plain run
    #     stays clean. The "applied" line is proof the org brain is compounding;
    #     the nudge points devs at this session's freshly-harvested safe paths. ---
    if _session_stats.get("overrides_applied", 0) > 0:
        print(f" 🧭 Org Reframes Applied:  {_session_stats['overrides_applied']:<3} |  your adopted safe-paths replaced the generic challenge")
    if len(_session_stats["recovered_traces"]) > 0:
        print("─"*60)
        print(" 💡 Your agents self-corrected this session — AgentX may have learned")
        print("    reusable safe-paths (and detection rules, if rule harvest is on).")
        print("    Review & adopt what it learned:  agentx insights")
    print(f" 💰 Tokens Saved:          ~{session_tokens:<3} |  Cumulative: ~{history.get('total_tokens', 0)}")
    print(f" ⏳ Time Saved:            ~{session_time} min |  Cumulative: ~{history.get('total_time', 0)} min")

    # The 5+ Block Threshold for the Health Report
    if history.get('total_intercepts', 0) >= 5 and history.get('top_offender'):
        print("═"*60)
        print(" 🩺 AGENT HEALTH INSIGHT")
        print("─"*60)
        print(f" ⚠️  Top Offender: '{history['top_offender']}'")
        print(" 💡 Tip: Consider refining your agent's system prompt to avoid this.")

    # --- SELF-SERVE NUDGE ---
    # At the activation moment (a keyless block), point the dev at Recover. The pulse
    # module owns the decision + bookkeeping: shown only for an install that has NEVER
    # reached a gateway (so a Recover user whose gateway was down isn't nagged), at most
    # ~weekly (no per-session nag), never in automation/CI. Static CTA, no telemetry.
    pulse.maybe_emit_nudge(_session_stats)

    # --- ANONYMOUS USAGE PULSE (ON by default, one-line opt-out) ---
    # All telemetry I/O lives in pulse.on_session_end: send by default (a one-time
    # transparency notice prints before the first send); AGENTX_TELEMETRY=off and a
    # prior declined prompt silence it. Counts only, never code/data. See pulse.py.
    # Never from automation: a developer's test suite or a CI pipeline is
    # mechanical repetition, not adoption — counting it would pollute the
    # activation/retention funnel (and it keeps our own suite from writing the
    # real ~/.agentx at exit). Excluded even when telemetry is on. Genuine production
    # (non-interactive but not automation) is NOT excluded.
    if not pulse.is_automation_context():
        pulse.on_session_end(_session_stats)
        # Lock-1: session-end auto-contribution for EXPLICITLY opted-in + networked
        # installs (default-off unchanged; daily-debounced; bounded; fire-and-forget).
        # Removes the "remember to run `agentx push`" friction for users who said yes.
        _client.auto_contribute(gateway_reached=_session_stats["gateway_reached"])

    print("═"*60 + "\n")

atexit.register(_print_agentx_summary)
# --------------------------

# --- NEW: STANDALONE EVALUATOR (Solves the Latency Trap) ---
def _local_standalone_evaluate(query: str, cot: str):
    """Evaluates intent locally using AST for speed, and Gemini for semantics."""
    
    # ⚡ FAST PATH: AST Parsing (~2ms latency)
    try:
        import sqlglot
        parsed = sqlglot.parse_one(query)
        # If it's just a SELECT, mathematically it cannot be a destructive write.
        if parsed.key == "select":
            return {"status": "ALLOWED"}
    except ImportError:
        print("⚠️ [AgentX] Warning: 'sqlglot' not installed. AST Fast-Path disabled.")
    except Exception:
        # Not SQL, or invalid SQL. Fall through to the LLM semantic check.
        pass

    # 🧠 SLOW PATH: Local Semantic Eval (~400ms latency)
    gemini_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_key:
        raise ValueError("AgentX Standalone Mode requires GEMINI_API_KEY to evaluate non-read intents.")
    
    from google import genai
    client = genai.Client(api_key=gemini_key)
    prompt = f"Does the intent '{cot}' to run '{query}' represent a DESTRUCTIVE_WRITE? Reply exactly with YES or NO."
    
    try:
        llm_res = client.models.generate_content(
            model=AGENTX_EVALUATION_MODEL,
            contents=prompt
            ).text
        if "YES" in llm_res.upper():
             return {
                "error": "AgentX Policy Violation",
                "policy_id": "POL-LOC-001",
                "policy_triggered": "Mass Destructive Intent",
                "challenge": "You are attempting a destructive action. Revise to a SAFE_WRITE or READ."
            }
        return {"status": "ALLOWED"}
    except Exception as e:
        return {"error": "Local Eval Failed", "message": str(e)}

# --- THE EGRESS SCRUBBER (Zero-Knowledge DLP) ---
def _scrub_pii(data, pii_targets):
    """
    Recursively traverses dicts, lists, and strings to redact PII locally.
    Guarantees raw data never leaves the developer's VPC.
    """
    if not pii_targets or not data:
        return data

    # Simple regex dictionary for MVP (We will replace this with Presidio locally later)
    regex_map = {
        "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        "PHONE": r'(\+\d{1,2}\s?)?1?\-?\.?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'
    }

    if isinstance(data, str):
        scrubbed_string = data
        for target in pii_targets:
            target_upper = target.upper()
            if target_upper in regex_map:
                scrubbed_string = re.sub(regex_map[target_upper], f"[REDACTED_{target_upper}]", scrubbed_string)
        return scrubbed_string

    elif isinstance(data, dict):
        return {k: _scrub_pii(v, pii_targets) for k, v in data.items()}
    
    elif isinstance(data, list):
        return [_scrub_pii(item, pii_targets) for item in data]
    
    return data

# =====================================================================
# 🧬 MODULE-LEVEL MEMORY PASS: LOCAL VECTOR SHIELD STREAMING LOOPS
# =====================================================================
# Layer 0 (Local Vector Shield): Coming in v0.3.0
# Will use pre-compiled fastembed vectors for <1ms offline evaluation.
# For alpha: all evaluation handled by the Reasoning Engine (Layer 1).
def load_local_vector_shield_cache(seed_dir=".agentx"):
    """
    Natively streams local .bin binary array weights back into cache frames 
    to empower O(1) out-of-prompt validation lookups directly in process RAM.
    """
    import os
    import json

    # Traverse directory escalation paths cleanly to safely capture workspace anchors
    weights_path = os.path.join(seed_dir, "intent_seeds.bin")
    manifest_path = os.path.join(seed_dir, "seeds_manifest.json")
    
    if not os.path.exists(weights_path) or not os.path.exists(manifest_path):
        # Escalate up to parent footprint layer block if executing out of examples folder
        weights_path = os.path.join("..", seed_dir, "intent_seeds.bin")
        manifest_path = os.path.join("..", seed_dir, "seeds_manifest.json")
        if not os.path.exists(weights_path) or not os.path.exists(manifest_path):
            return None, None
        
    try:
        # numpy is imported lazily here (not at module/function entry) so the
        # keyword Layer 0 stays truly dependency-free: a clean `pip install`
        # with no compiled seed files never touches numpy. If numpy is absent
        # but seeds somehow exist, the except below degrades to (None, None).
        import numpy as np

        # Reconstruct the float32 matrix arrays from the local binary frame format
        raw_flat_weights = np.fromfile(weights_path, dtype=np.float32)
        total_rows = len(raw_flat_weights) // 384
        weights_matrix = raw_flat_weights.reshape((total_rows, 384))
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            metadata_manifest = json.load(f)
            
        return weights_matrix, metadata_manifest
    except Exception:
        return None, None

# Load the compiled binary matrices into memory once on SDK initial initialization startup
# (Retained for backward-compat imports; Layer 0 now runs on the keyword rails below.)
LOCAL_SHIELD_WEIGHTS, LOCAL_SHIELD_MANIFEST = load_local_vector_shield_cache()

# =====================================================================
# 🪶 LIGHTWEIGHT LAYER 0: KEYWORD / INTENT PRE-FILTER
# =====================================================================
# Deterministic, dependency-free (no numpy / fastembed) offline pre-filter.
# It absorbs the obvious cases locally — saving a gateway round-trip and an
# LLM call — and is the graceful-degradation floor if the gateway is
# unreachable. Real semantic scoring stays server-side in the gateway, where
# the shared immunity ledger and the moat live.
# =====================================================================

# Built-in seeds so protection works out-of-the-box, offline, with zero setup.
# Mirrors the gateway's active LOCAL_FALLBACK_SEEDS so client + server agree
# on the obvious threats.
# `category` is the coarse, closed-vocab failure class (mirrors the gateway's
# failure_mode taxonomy / README hero classes). It is the ONLY thing the anonymous
# pulse learns about a keyless block — "what KIND of action got blocked", never the
# tool/function name or payload (see _BLOCK_CATEGORY_VOCAB + pulse.py). Off-vocab is
# dropped, so a pulled/cloud policy without a known category simply reports nothing.
_BUILTIN_POLICY_KEYWORDS = [
    # socratic_prompt = the agent-facing CHALLENGE; preferred_alternative = the concrete
    # SAFE PATH. Both are written for the caller's own model to self-correct on (the
    # keyless MCP proxy + the offline keyword shield), so they lead with the issue and a
    # usable next step, NOT internal taxonomy or judge-era "explain your reasoning" cruft.
    {
        "id": "11111111-1111-1111-1111-111111111101",
        "name": "Mass Destructive Intent",
        "category": "DESTRUCTIVE_ACTION",
        # DROP/TRUNCATE are always destructive (no scoped-safe form). A scoped
        # DELETE/UPDATE (with a WHERE) is legitimate, so those are NOT flat tokens:
        # the WHERE-aware _detect_destructive_sql floor catches only the no-WHERE
        # mass form, which is why "DELETE FROM" is deliberately absent here.
        "blocked_intents": ["DROP TABLE", "TRUNCATE TABLE", "DROP DATABASE"],
        "socratic_prompt": "This is a destructive, irreversible write that drops or mass-deletes data.",
        "preferred_alternative": "Scope the change to specific rows with a WHERE clause, take a backup or snapshot first, or use a reversible soft-delete instead of dropping the table.",
    },
    {
        "id": "11111111-1111-1111-1111-111111111103",
        "name": "Network Sandbox (SSRF)",
        "category": "NETWORK_TRAVERSAL",
        # The literal loopback/metadata hostnames stay as fast substring rails; the
        # ENCODED-IP class (decimal/hex/octal/IPv6 forms of ANY loopback/link-local/
        # private/reserved target) is generalized by the structural _detect_ssrf_encoded
        # pass below. That replaces the two hardcoded encodings of 169.254.169.254 that
        # used to sit here AND removes their bare-integer false positive (a numeric id
        # such as `WHERE id = 2852039166` is no longer mistaken for the metadata IP).
        "blocked_intents": ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata.google.internal", "100.100.100.200", "[::1]", "fd00:ec2::254", "::ffff:169.254.169.254"],
        "socratic_prompt": "This target is a loopback or cloud-metadata address, a common SSRF path to internal credentials.",
        "preferred_alternative": "Send the request to the intended external service hostname over HTTPS, not an internal IP, localhost, or 169.254.169.254.",
    },
    {
        "id": "11111111-1111-1111-1111-111111111104",
        "name": "Secrets and PII Exfiltration",
        "category": "SECRETS_LEAK",
        "blocked_intents": ["system_users", "pastebin", "SELECT email", "SELECT role", "SELECT password", "SELECT api_key", "SELECT apikey", "SELECT secret", "gist.github", "webhook.site", "transfer.sh", "requestbin", "hastebin", "0x0.st"],
        "socratic_prompt": "This call reads credentials or routes data to an external paste sink, which is an exfiltration path.",
        "preferred_alternative": "Read only the non-secret fields you actually need and keep the data inside the trusted system. Do not send it to an external paste endpoint.",
    },
    {
        "id": "11111111-1111-1111-1111-111111111102",
        "name": "Customer Privacy Shield",
        "category": "PII_EXFILTRATION",
        "blocked_intents": ["SELECT email", "SELECT phone", "SELECT address", "credit_card"],
        "socratic_prompt": "This query pulls raw customer PII (email, phone, address, or card data). Bulk access to unmasked PII is restricted.",
        "preferred_alternative": "Select only the non-PII fields you need, aggregate instead of returning raw rows, or use masked or hashed columns.",
    },
    {
        "id": "11111111-1111-1111-1111-111111111105",
        "name": "Filesystem Path Boundary",
        "category": "DESTRUCTIVE_ACTION",
        "blocked_intents": ["../../", "/etc/passwd", "/etc/shadow", "id_rsa", ".ssh/", ".aws/credentials"],
        "socratic_prompt": "This path escapes the working directory with ../ traversal, or reads a system credential file (SSH keys, cloud credentials, /etc/passwd or /etc/shadow).",
        "preferred_alternative": "Stay inside the project working directory with a relative path that has no '../', and do not read credential or key files.",
    },
    {
        "id": "11111111-1111-1111-1111-111111111106",
        "name": "Destructive Shell Command",
        "category": "DESTRUCTIVE_ACTION",
        "blocked_intents": ["rm -rf /", "rm -rf ~", "rm -rf --no-preserve-root", "rm -fr /", ":(){", "mkfs", "of=/dev/sd", "of=/dev/nvme", "| bash", "|bash"],
        "socratic_prompt": "This is an irreversible shell teardown: a recursive delete of a root or home path, a disk format or overwrite, a fork bomb, or piping a downloaded script straight into a shell.",
        "preferred_alternative": "Scope any delete to a specific relative subdirectory, never / or ~. Download a script to a file and review it before running, instead of piping it into bash.",
    },
]

# Closed vocab for the pulse block_category (fail-safe: an unknown value is dropped,
# never emitted). Mirrors the gateway failure_mode hero classes; KEEP IN SYNC with the
# server-side allowlist in ui/app/api/pulse/route.ts.
_BLOCK_CATEGORY_VOCAB = frozenset({
    "DESTRUCTIVE_ACTION", "PII_EXFILTRATION", "NETWORK_TRAVERSAL", "SECRETS_LEAK",
})

# Stable policy_id -> category for the built-in floor policies, so the category
# survives even when LOCAL_POLICY_KEYWORDS is loaded from a pulled .agentx/policies.json
# (which carries the canonical floor ids but may drop the category field).
_POLICY_ID_TO_CATEGORY = {p["id"]: p["category"] for p in _BUILTIN_POLICY_KEYWORDS}

def _note_block_category(category, stats=None):
    """Record the coarse category of a block for the anonymous pulse. Closed-vocab
    only (off-vocab dropped). Last-write-wins across a session — a coarse 'what kind
    of action this install blocks' signal, never identity or payload. Writes into the
    decorator's module-global ``_session_stats`` by default; the agentx-mcp proxy
    passes its OWN stats dict so it shares this exact vocab guard instead of
    reimplementing it (the two can't drift)."""
    target = _session_stats if stats is None else stats
    # isinstance guard: a malformed pulled policy can carry a NON-string category, and
    # `<list> in <frozenset>` raises TypeError (unhashable) — drop it rather than let it
    # wedge the block path (incl. the agentx-mcp proxy's client routing loop).
    if isinstance(category, str) and category in _BLOCK_CATEGORY_VOCAB:
        target["block_category"] = category

def load_local_policy_keywords(seed_dir=".agentx"):
    """
    Loads policy keyword/intent definitions for the lightweight Layer 0 pre-filter.

    Prefers the developer's pulled policies (.agentx/policies.json from
    `agentx pull`, which carry blocked_intents + socratic_prompt), escalating
    to the parent directory, then falling back to a built-in seed list so
    protection works offline with zero setup.
    """
    import os
    import json

    candidate_paths = [
        os.path.join(seed_dir, "policies.json"),
        os.path.join("..", seed_dir, "policies.json"),
    ]

    for path in candidate_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                policies = []
                for p in (loaded if isinstance(loaded, list) else []):
                    # Only arm active rules that actually carry blocked intents
                    if p.get("is_active", True) and p.get("blocked_intents"):
                        policies.append({
                            "id": p.get("id", "POL-LOCAL"),
                            "name": p.get("name", "Local Policy"),
                            "category": p.get("category"),  # preserve the coarse pulse class if the pull carries it
                            "blocked_intents": p.get("blocked_intents", []),
                            "socratic_prompt": p.get("socratic_prompt")
                                or "Policy Violation. Revise your action to comply with security policy.",
                            # Carry the concrete safe path through if the pull supplies one, so the
                            # keyless coaching (A1a) can surface it for pulled/cloud policies too.
                            "preferred_alternative": p.get("preferred_alternative"),
                        })
                if policies:
                    return policies
            except Exception:
                pass

    return list(_BUILTIN_POLICY_KEYWORDS)

# Load the lightweight keyword rails once on SDK init (cheap, no heavy deps).
LOCAL_POLICY_KEYWORDS = load_local_policy_keywords()


# Reading the database catalog (information_schema / pg_catalog / sqlite_master /
# PRAGMA table_info) is how agents and ORMs DISCOVER schema — a benign READ, not a
# schema modification. The Schema Boundary policy can carry `information_schema` as
# a blocked_intent (it does in the cloud row / a pre-migration `agentx pull`), and
# Layer 0 is a blunt substring scanner: without this guard it blocks a benign
# `SELECT … FROM information_schema.columns` IN-PROCESS, before the request ever
# reaches the gateway — which already exempts the same reads via its own
# `_is_benign_catalog_read`. That asymmetry was the blind-eval Schema Boundary FP's
# "layer-coverage gap": the fix lived gateway-side only. These two patterns mirror
# the gateway's regexes (backend/gateway.py) so client and server agree; keep them
# in sync. A mutating/DDL verb (DROP/ALTER on the catalog) disqualifies the read,
# so a destructive catalog op is still caught by the keyword scan below.
_CATALOG_INTROSPECTION_RE = re.compile(
    r"\binformation_schema\b|\bpg_catalog\b|\bsqlite_master\b|\bsqlite_schema\b"
    r"|\bpragma\s+(?:table_info|table_list|index_list|index_info|database_list|foreign_key_list)\b",
    re.IGNORECASE,
)
_MUTATING_SQL_VERB_RE = re.compile(
    r"\b(?:drop|delete|truncate|update|insert|alter|grant|revoke|create|replace|merge)\b",
    re.IGNORECASE,
)


def _is_benign_catalog_read(query) -> bool:
    """True for a read-only introspection of the DB catalog: references a catalog
    surface (information_schema / pg_catalog / sqlite_master / a read PRAGMA) AND
    contains no mutating/DDL verb. Mirrors gateway._is_benign_catalog_read so the
    Layer-0 keyword shield does not block benign schema discovery."""
    if not query:
        return False
    q = str(query)
    if not _CATALOG_INTROSPECTION_RE.search(q):
        return False
    return not _MUTATING_SQL_VERB_RE.search(q)


# --- keyless-floor hardening (audit findings, 2026-07) ----------------------
# The keyless floor is a blatant-catastrophic floor. These helpers stop a BLATANT
# form from slipping the flat substring scan on a cosmetic variation, and add the
# destructive classes a flat token cannot express. Deeper obfuscation (encoded IPs,
# base64, semantic paraphrase) is by design the gateway judge's job, not this floor.

# Normalize the scanned payload: lowercase, drop /* */ block comments, collapse
# whitespace runs. So "DROP  TABLE" / "DROP/**/TABLE" / "DROP\tTABLE" all reduce to
# "drop table". We deliberately do NOT strip -- line comments: "--" is also a shell
# flag (rm -rf --no-preserve-root) and stripping it would blind the shell floor.
# CoT is never passed to this function (see the callers), so normalizing the payload
# cannot resurrect the self-correction false-positive the raw-substring note warned of.
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_WS_RUN_RE = re.compile(r"\s+")


def _normalize_for_match(raw):
    s = str(raw).lower()
    s = _BLOCK_COMMENT_RE.sub(" ", s)
    return _WS_RUN_RE.sub(" ", s).strip()


# Structural destructive-SQL floor for the classes a flat token cannot express
# (runs on the normalized haystack, so it is whitespace/comment robust):
#   * DROP / TRUNCATE of ANY object (table, database, schema, index, view, role)
#   * a MASS write with NO WHERE: DELETE FROM <t> or UPDATE <t> SET ... with no WHERE
# Mirrors the gateway's destructive-DDL + no-WHERE detectors (backend/gateway.py).
# Keyless has NO AST, so this regex runs as a substring match over arbitrary payload text.
# That forces it to stay NARROWER than the gateway: it deliberately omits the prose-ambiguous
# objects `user` and `trigger` (ordinary English words -> false positives on non-SQL text like
# "drop user surveys"). Real `DROP USER` / `DROP TRIGGER` are still caught precisely by the
# gateway's AST path; keyless enumerates only the SQL-specific objects.
_DESTRUCTIVE_DDL_RE = re.compile(
    r"\bdrop\s+(?:table|database|schema|index|view|materialized\s+view|"
    r"role|sequence|tablespace)\b"
    r"|\btruncate\s+(?:table\s+)?\w")
_MASS_WRITE_RE = re.compile(
    r"\bdelete\s+from\s+[\w.]+|\bupdate\s+[\w.]+\s+set\b")


def _detect_destructive_sql(normalized):
    """True for a blatant destructive SQL statement in the normalized payload."""
    if _DESTRUCTIVE_DDL_RE.search(normalized):
        return True
    m = _MASS_WRITE_RE.search(normalized)
    # No-WHERE mass delete/update: fire ONLY when no WHERE follows the write verb.
    # If a WHERE appears anywhere after (even inside a subquery or a string literal)
    # we stay conservative and do NOT fire — that subtlety is the gateway judge's job,
    # and it keeps a legitimate scoped write (the common case) from false-blocking.
    return bool(m and "where" not in normalized[m.start():])


# ---- Structural SSRF: encoded / alternate-form private-IP targets ----
# The literal metadata/loopback hostnames are fast substring rails in the SSRF policy above.
# This pass generalizes the ENCODED-IP class those literals cannot enumerate: decimal / hex /
# IPv6 forms of ANY loopback, link-local, private, reserved, or unspecified address
# (http://2130706433/ == 127.0.0.1, http://0x7f000001/ == 127.0.0.1), mirroring the gateway's
# _coerce_ip decode. It is deliberately NARROWER than the gateway's detect_ssrf_target: it
# fires ONLY on a host inside an explicit scheme://URL (not a bare host, and not the gateway's
# `.internal`/`.localhost` suffix rule), so a bare numeric id in a payload
# (`WHERE id = 2852039166`) is never coerced -> no false positive. (Dotted-octal like
# 0177.0.0.1 is NOT decoded -- ipaddress rejects leading-zero octets; same limit as the gateway.)
_SSRF_URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://([^\s/'\"<>]+)", re.IGNORECASE)


def _coerce_ip_keyless(host):
    """Canonicalize a host token to an ipaddress, decoding the common SSRF-bypass
    encodings (decimal int, hex int, dotted, IPv6). Returns None for a genuine hostname.
    Kept in step with the gateway's _coerce_ip so client + server agree."""
    import ipaddress
    h = host.strip().strip("[]")
    if not h:
        return None
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    try:
        as_int = int(h, 16) if h.lower().startswith("0x") else int(h)
        return ipaddress.ip_address(as_int)
    except (ValueError, OverflowError):
        return None


def _detect_ssrf_encoded(raw):
    """True if a scheme://URL in the payload targets a loopback / link-local / private /
    reserved / unspecified address in ANY encoding. URL-context-only (never a bare token),
    so a numeric literal elsewhere in the payload cannot false-trip it. ``raw`` is the
    already-stringified payload from evaluate_call_keyless."""
    if "://" not in raw:            # cheap guard: skip the regex on the common no-URL case
        return False
    for m in _SSRF_URL_RE.finditer(raw):
        netloc = m.group(1).split("@")[-1]
        if netloc.startswith("["):            # bracketed IPv6: [::1]:port
            host = netloc[1:].split("]")[0]
        else:
            host = netloc.split(":")[0]
        ip = _coerce_ip_keyless(host)
        if ip is None:
            continue
        # Unwrap an IPv4-mapped IPv6 (::ffff:a.b.c.d) to its embedded IPv4: the whole
        # ::ffff:0:0/96 block is is_reserved, which would else over-block a PUBLIC mapped
        # host (::ffff:93.184.216.34). Matches the gateway's _host_is_blocked_target.
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        if (ip.is_loopback or ip.is_link_local or ip.is_private
                or ip.is_reserved or ip.is_unspecified):
            return True
    return False


def _is_catalog_token(token):
    """True for a DB-catalog introspection token (information_schema / pg_catalog /
    sqlite_master / a read PRAGMA). Used to NARROW the benign-catalog exemption so it
    applies to catalog tokens ONLY: a query that merely name-drops information_schema
    can no longer disable a PII/secret block (the audit's over-exemption bypass)."""
    return bool(_CATALOG_INTROSPECTION_RE.search(str(token)))


# The canonical "Mass Destructive Intent" builtin, used to attribute the structural
# SQL floor's block so its category/coaching stay stable regardless of pulled policies.
_MASS_DESTRUCTIVE_POLICY = next(
    (p for p in _BUILTIN_POLICY_KEYWORDS if p["name"] == "Mass Destructive Intent"),
    _BUILTIN_POLICY_KEYWORDS[0])

# The SSRF builtin, used to attribute the structural encoded-IP floor so its
# category/coaching stay stable regardless of pulled policies.
_SSRF_POLICY = next(
    (p for p in _BUILTIN_POLICY_KEYWORDS if p["name"] == "Network Sandbox (SSRF)"),
    _BUILTIN_POLICY_KEYWORDS[0])


def _keyless_decision(policy):
    """Build the normalized keyless decision dict from a matched policy."""
    policy_id = policy.get("id", "POL-LOCAL")
    return {
        "policy_id": policy_id,
        "policy_name": policy.get("name", "Local Security Policy"),
        "challenge_text": policy.get(
            "socratic_prompt",
            "Policy Violation. Revise your action to comply with security policy."),
        "category": policy.get("category") or _POLICY_ID_TO_CATEGORY.get(policy_id),
        "preferred_alternative": policy.get("preferred_alternative"),
    }


def evaluate_call_keyless(query, *, bypass_local_shield=False):
    """Keyless Layer-0 detection — the SINGLE home shared by the @agentx_protect
    decorator and the ``agentx-mcp`` stdio proxy so the two paths can never drift.

    Pure and side-effect-free. It normalizes the ACTION/PAYLOAD (never the
    chain-of-thought — the caller passes only the call), then applies, in order:
    the deterministic substring scan of the normalized payload against the active
    ``LOCAL_POLICY_KEYWORDS`` blocked-intent rails (which preserves the matched
    policy's coaching + any adopted override), then a structural destructive-SQL
    FALLBACK (DROP/TRUNCATE any object, no-WHERE mass UPDATE/DELETE) for the classes a
    flat token cannot express. Returns the FIRST match as a normalized decision dict,
    or ``None`` to allow. The benign
    read-only catalog exemption (information_schema / PRAGMA) applies to catalog
    tokens ONLY, so legitimate schema discovery still passes but a PII/secret read
    that merely name-drops a catalog surface does not slip through.

    It deliberately does NOT run the circuit breaker, the org-reframe swap
    (``_apply_org_override``), the incident park, or the pulse: the caller owns those.

    This is the blatant-catastrophic floor. It catches encoded-IP SSRF only inside an
    explicit URL (see _detect_ssrf_encoded); deeper obfuscation (base64, semantic
    paraphrase, or a bare/scheme-less encoded host) is by design left to the gateway judge.

    Returns ``None`` (allow) or
    ``{policy_id, policy_name, challenge_text, category, preferred_alternative}``
    where ``challenge_text`` is the RAW socratic prompt (pre-override)."""
    if not LOCAL_POLICY_KEYWORDS or bypass_local_shield:
        return None
    raw = str(query)
    benign_catalog = _is_benign_catalog_read(raw)
    haystack = _normalize_for_match(raw)

    # 1) Token scan FIRST — preserves the specific matched policy's identity (so an
    #    adopted org override + its concrete safe-path survive) and, via normalization,
    #    now catches whitespace/comment-split token variants ("DROP  TABLE").
    for policy in LOCAL_POLICY_KEYWORDS:
        for intent in policy.get("blocked_intents", []):
            token = str(intent).lower().strip()
            if not token or token not in haystack:
                continue
            # Benign-catalog exemption applies to catalog tokens ONLY now, so a
            # PII/secret read that name-drops information_schema still blocks.
            if benign_catalog and _is_catalog_token(token):
                continue
            return _keyless_decision(policy)

    # 1b) Structural SSRF: an encoded / alternate-form private-IP target inside a URL that
    #     no flat literal enumerates (decimal/hex loopback + metadata IPs). Runs on the RAW
    #     payload (URLs survive normalization) and is URL-context-scoped, so a bare numeric
    #     id never coerces.
    if _detect_ssrf_encoded(raw):
        return _keyless_decision(_SSRF_POLICY)

    # 2) Structural destructive-SQL FALLBACK for classes no flat token expresses
    #    (DROP of other objects, TRUNCATE, a no-WHERE mass UPDATE/DELETE). Reached only
    #    when no policy token matched, so it never overrides a specific policy's coaching.
    if not benign_catalog and _detect_destructive_sql(haystack):
        return _keyless_decision(_MASS_DESTRUCTIVE_POLICY)

    return None


def _coerce_arg_value(value):
    """Coerce ONE argument value into the text the keyless keyword shield scans, or
    None to skip it. The single home for value flattening, shared by the decorator's
    arg loop and the agentx-mcp proxy's _flatten_call so the two feeders can't drift:
    str as-is, bool/int/float stringified, dict/list as compact JSON."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):   # bool is an int subclass; str() is identical
        return str(value)
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value)
        except Exception:
            return str(value)
    return None


def _max_cognitive_turns():
    """Circuit-breaker ceiling (AGENTX_MAX_COGNITIVE_TURNS), shared by the decorator
    and the agentx-mcp proxy so the breaker trips at the same threshold on both. A
    missing/invalid value falls back to 3; clamped to >= 1."""
    try:
        return max(1, int(os.getenv("AGENTX_MAX_COGNITIVE_TURNS", "3")))
    except (TypeError, ValueError):
        return 3


def suppress_atexit_summary():
    """Unregister the SDK's atexit session-summary printer. The agentx-mcp proxy
    calls this (a maintained public contract, not a reach into a private symbol) so
    the box-drawing summary never lands on its JSON-RPC stdout and the proxy owns a
    single pulse. Best-effort and idempotent."""
    try:
        atexit.unregister(_print_agentx_summary)
    except Exception:
        pass

# A destructive-filesystem tool is named with a destroy verb (delete_files,
# remove_directory, rmtree, purge_workspace, deleteFiles). The decorator flattens
# arg VALUES into `query`, so the gateway never sees the verb — only `path="/"`
# and `recursive=True` survive, as bare values. Declaring a filesystem action
# from the function name gives the gateway's structured bulk-delete detector the
# verb it needs to anchor on. Matched on tokenized name parts (snake_case +
# camelCase) so it is precise, not a substring guess. The value declared must be
# one the gateway recognizes (see gateway._FS_DESTRUCTIVE_ACTIONS).
_FS_DESTRUCTIVE_VERBS = {
    "delete", "remove", "rmtree", "rmdir", "unlink", "purge", "wipe", "nuke",
}


def _name_tokens(name):
    """Lowercase word tokens from a tool / function name: splits camelCase, letter<->digit
    runs (s3upload -> s 3 upload), and every non-alphanumeric separator (snake_case, kebab,
    dotted db.query, slashed fs/read_file). The ONE tokenizer shared by the keyless fs
    destroy-verb check and the MCP harvest classifiers, so name-splitting can't drift between
    them (the verb VOCABULARIES stay purpose-specific; only the mechanical split is shared)."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[a-z])(?=[0-9])|(?<=[0-9])(?=[a-z])", " ", name or "")
    return re.findall(r"[a-z0-9]+", spaced.lower())


def _is_fs_destructive_func(func_name: str) -> bool:
    """True when a function name contains a filesystem-destruction verb as a
    discrete token (delete_files / removeDir / rmtree), not a substring."""
    if not func_name:
        return False
    return any(tok in _FS_DESTRUCTIVE_VERBS for tok in _name_tokens(func_name))


# Internal directive returned by the decision core (`_decide`) to the wrapper
# shell. It means "the action is cleared — run the wrapped tool now, then scrub
# the result if targets are given". Hoisting tool EXECUTION out of the decision
# core is what lets ONE core serve both wrappers without duplicating 500+ lines:
# the sync wrapper calls `_decide` inline; the async wrapper runs the (blocking)
# core in an executor thread so the event loop is never stalled, then `await`s the
# tool here. Any other return value from `_decide` is terminal (a block / breaker /
# denial / error) and is passed straight back to the caller.
class _ExecuteTool:
    __slots__ = ("scrub_targets",)

    def __init__(self, scrub_targets=None):
        self.scrub_targets = scrub_targets or []


# --- 3. THE MAIN SENSOR DECORATOR ---
def agentx_protect(agent_id: str, extract_query_func=None, extract_cot_func=None, action: str = None, budget_pool_id: str = None):
    def decorator(func):
        # Async tool functions (LangGraph / autogen / asyncio.gather swarms) get an
        # async wrapper; sync tools keep the original synchronous path unchanged.
        _is_async_tool = _returns_coroutine(func)
        # The signature is fixed at decoration time — compute it ONCE and close over
        # it instead of re-running inspect.signature() on every call (hot path; #115
        # cleanup). Best-effort: an uninspectable callable falls back to None and
        # consumers default to the untyped / AgentXBlock-safe behaviour.
        try:
            _func_sig = inspect.signature(func)
        except (ValueError, TypeError):
            _func_sig = None
        # Partial-safe tool name (a functools.partial has no __name__) — resolved once.
        _func_name = _func_display_name(func)
        # Strike/breaker key: per-decorated-tool identity. For a plain function/method
        # it IS the display name (preserves existing per-tool semantics + tests); for a
        # functools.partial or a callable OBJECT — two of which can share one display
        # name — disambiguate by object identity so one tool's offline strikes can't
        # trip another tool's breaker or pool its strike state (review #117 finding 3).
        if inspect.isfunction(func) or inspect.ismethod(func):
            _strike_key = _func_name
        else:
            _strike_key = f"{_func_name}#{id(func)}"

        # THE DECISION CORE — everything except executing the tool. Returns a
        # terminal value (block/breaker/denial/error; or raises) OR an _ExecuteTool
        # directive telling the wrapper shell to run the tool. `args`/`kwargs` are
        # the call's positional/keyword arguments (the body still unpacks them with
        # *args/**kwargs exactly as before).
        def _decide(args, kwargs):
            _incr("total_calls")
            func_name = _func_name # <-- partial-safe DISPLAY name (logs / telemetry)
            strike_key = _strike_key # <-- per-tool key for strike/breaker state (#117 finding 3)

            # =========================================================
            # 🔌 CIRCUIT BREAKER CEILING (read here; ENFORCED gateway-side)
            # =========================================================
            # The strike-breaker DECISION lives gateway-side (Path B in /v1/evaluate):
            # the SDK meters strikes + forwards `strike_count`, and the gateway returns
            # the "AgentX Cognitive Loop Aborted" verdict (handled below at the gateway
            # circuit-breaker branch) — so a trip is parked as a control-plane-visible
            # incident, centrally tunable, with no duplicated authority. We read the
            # ceiling here ONLY for the offline fallback in the
            # REASONING_ENGINE_UNREACHABLE branch (when the gateway — the authority —
            # can't be reached, the SDK still stops a runaway loop locally).
            max_allowed_turns = _max_cognitive_turns()

            # --- TRACE ID LOGIC ---
            current_trace_id = trace_id_var.get()
            if not current_trace_id:
                # Auto-start a secure telemetry session if uninitialized
                current_trace_id = start_secure_session()

            # --- STRIKE STATE: SESSION-SCOPED (fixes cross-session leakage) ---
            # Scope the per-tool strike counter to the live trace: a DIFFERENT trace
            # taking over the tool zeroes its strikes (a prior session's blocked-retry
            # run can't trip the breaker here); an unset owner is adopted without a
            # reset (first-call / pre-seeded behaviour). Done atomically under the lock
            # so the reset can't race a concurrent increment (#115 finding 3).
            _adopt_strike_trace(strike_key, current_trace_id)

            # =========================================================
            # THE RETURN ROUTER (Dynamic Type Reflection)
            # =========================================================
            def _deliver_challenge(challenge_string: str, target_receipt_id: str, target_policy_name: str,
                                   is_circuit_breaker: bool = False, challenge_text: str = None, safe_path: str = None):
                """Routes the block based on the developer's function signature to prevent type crashes.

                Untyped / `-> str` tools get an `AgentXBlock` (a str subclass carrying
                structured fields); strictly-typed tools get `AgentXSecurityBlock` raised.
                Both carry identical fields so the caller detects a block uniformly
                (`is_block(...)` / catch the exception) instead of parsing the prose."""
                return_annotation = (
                    _func_sig.return_annotation if _func_sig is not None
                    else inspect.Signature.empty
                )

                # If it's a circuit breaker trip, we ALWAYS raise to kill the loop safely.
                if is_circuit_breaker:
                    raise AgentXCircuitBreakerTripped(f"AgentX Circuit Breaker Triggered: {challenge_string}")

                # If the function is untyped or strictly expects a string, returning our
                # AgentXBlock is safe (it IS a str). Do NOT return it for dict/Pydantic
                # returns, or the framework will crash — raise the structured exception.
                safe_types = (inspect.Signature.empty, str, type(None))
                if return_annotation in safe_types:
                    return AgentXBlock(
                        challenge_string,
                        policy=target_policy_name,
                        challenge=challenge_text,
                        receipt_id=target_receipt_id,
                        safe_path=safe_path,
                    )

                # If strictly typed, raise to prevent framework validation crashes
                raise AgentXSecurityBlock(
                    message=challenge_string,
                    receipt_id=target_receipt_id,
                    policy_name=target_policy_name,
                    challenge=challenge_text,
                    safe_path=safe_path,
                )
            
            # =========================================================
            # 🛡️ ARCHITECTURAL REFLECTIVE INGESTION CORE
            # Uses Python signature reflection to map runtime parameters.
            # Extracts text-heavy string structures and filters helper pointer
            # context to eliminate vector noise and secure multi-turn retries.
            # =========================================================
            # structured_args holds the per-parameter named fields the gateway can
            # route on; it is best-effort and always accompanied by the flattened
            # `query` text below, so a wrong/empty action can never starve the
            # gateway's text-scanning floor. (See the action/args contract note in
            # client.evaluate_intent.)
            structured_args = {}
            try:
                if extract_query_func:
                    query = extract_query_func(*args, **kwargs)
                else:
                    if _func_sig is None:
                        raise ValueError("uninspectable signature")
                    bound_args = _func_sig.bind(*args, **kwargs)
                    bound_args.apply_defaults()

                    extracted_text_elements = []
                    for param_name, param_value in bound_args.arguments.items():
                        # Filter database/network context objects that poison hyper-space weights
                        if param_name in ("self", "cls", "conn", "cursor", "db_session", "client"):
                            continue
                        coerced = _coerce_arg_value(param_value)
                        if coerced is None:
                            continue
                        extracted_text_elements.append(coerced)
                        # structured_args feeds the gateway's structured detectors; keep its
                        # historical shape (scalars + dict, never lists) so gateway behavior is
                        # unchanged. A list now rides the keyword-scan `query` only (closing the
                        # prior gap where a list-valued arg was dropped from the scan entirely).
                        if not isinstance(param_value, list):
                            structured_args[param_name] = param_value

                    query = " ".join(extracted_text_elements) if extracted_text_elements else str(args)

                if not query or str(query).strip() in ("()", "", "None"):
                    query = f"Interception trace summary for tool function: {func_name}"
            except Exception as reflect_err:
                query = f"Signature inspection fallback for {func_name} | Trace: {str(reflect_err)}"

            # =========================================================
            # 🧭 EDGE ACTION INFERENCE (overridable by the explicit action= param)
            # =========================================================
            # Resolve the tool surface once, here at the SDK edge. When the
            # developer declares action= we trust it. Otherwise we infer — but
            # DELIBERATELY conservatively: only call fetch_url when the payload IS
            # a network target (matched ANCHORED at the start), never when a query
            # merely *contains* a URL/IP. A SQL `INSERT ... VALUES('https://x')`
            # that was mis-typed as fetch_url would make the gateway skip every
            # execute_database_query policy for it. When we are not confident we
            # leave action UNSET and let the gateway's fallback ("sql present ->
            # db") decide — which is correct for SQL-carrying-a-URL. This is a
            # suggestion, never a gate — the flattened query still ships regardless.
            resolved_action = action
            if resolved_action is None:
                try:
                    probe = str(query).strip().lower()
                    # Anchored: a scheme-led URL, or a bare IP[:port] target.
                    if re.match(r"(?:https?|ftp|file)://|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:[/?]|$)", probe):
                        resolved_action = "fetch_url"
                    # A destructive-filesystem tool (delete_files, rmtree, ...) —
                    # declare a filesystem action so the gateway can anchor its
                    # structured bulk-delete detector on the verb the flattened
                    # arg values lose. "filesystem_delete" is in the gateway's
                    # recognized set; the flattened query still ships regardless.
                    elif _is_fs_destructive_func(func_name):
                        resolved_action = "filesystem_delete"
                    # else: leave None -> gateway fallback classifies the surface.
                except Exception:
                    resolved_action = None

            try:
                chain_of_thought = extract_cot_func(*args, **kwargs) if extract_cot_func else None
                if not chain_of_thought or chain_of_thought in ("", "Implicit tool call"):
                    chain_of_thought = f"Autonomous validation thread tracking function route: '{func_name}'"
            except Exception:
                chain_of_thought = "Implicit tool call execution thread context trace."
                
            # POP (not get): receipt_id is a decorator CONTROL kwarg — the caller passes
            # it on a retry to correlate the incident, per the README pattern
            # `your_tool(revised, receipt_id=out.receipt_id)` — NOT a tool argument. Strip
            # it here so it never leaks into func(*args, **kwargs) below, which otherwise
            # TypeErrors on any typed tool that lacks **kwargs (a keyless activation snag:
            # the documented retry pattern broke real tools). The query/args reflection
            # already ran above, so this does not change what is sent to the gateway.
            receipt_id = kwargs.pop("receipt_id", None)

            # The local strike count is no longer forwarded to the gateway — the gateway
            # OWNS the online count + the Path B decision now (issue #80). The only
            # remaining consumer is the OFFLINE-ONLY fallback (the
            # REASONING_ENGINE_UNREACHABLE branch), which reads consecutive_strikes
            # directly. We surface it here purely for debug visibility — read inline so
            # no stale local is left around to be mistaken for live online state.
            print(f"\n🛡️ [AgentX SDK] Intercepting tool call to '{func_name}' and "
                  f"active_stats = {_session_stats['consecutive_strikes'].get(func_name, 0)}...")

            # =====================================================================
            # 🪶 LAYER 0: OUT-OF-PROMPT LOCAL KEYWORD / INTENT PRE-FILTER
            # Check if the developer explicitly configured a system bypass flag
            # ✅ BYPASS IS 'OFF' BY DEFAULT: Evaluates false unless explicitly toggled to true in env
            # =====================================================================
            bypass_local_shield = os.environ.get("AGENTX_BYPASS_LOCAL_SHIELD", "false").lower() == "true"

            # Benign catalog introspection (read-only information_schema / PRAGMA)
            # is exempt: a Schema Boundary policy carrying `information_schema` would
            # otherwise let this blunt substring scanner block legitimate schema
            # discovery — the blind-eval FP. The gateway already exempts these reads;
            # we mirror that here so the exemption is store-independent (a pulled
            # policy.json can still carry the stale keyword). A mutating catalog op is
            # NOT exempt and still falls through to the scan below.
            if not bypass_local_shield:
                try:
                    # Keyless Layer-0 detection now lives in evaluate_call_keyless()
                    # (the SINGLE home shared with the agentx-mcp proxy so the two
                    # paths can't drift). It applies the benign-catalog exemption +
                    # the substring scan and returns the matched policy as a
                    # normalized decision dict (or None). Side-effect-free: the
                    # breaker, org-override swap, incident park, and delivery below
                    # all stay here so a halted loop neither delivers nor counts a
                    # reframe.
                    matched_policy = evaluate_call_keyless(query)

                    if matched_policy:
                        policy_name = matched_policy["policy_name"]
                        challenge_text = matched_policy["challenge_text"]
                        policy_id = matched_policy["policy_id"]

                        # CIRCUIT BREAKER on the keyword-shield path. A keyword-matched
                        # payload short-circuits HERE and never reaches the gateway, so
                        # neither the gateway's per-trace Path B nor Path C can ever count
                        # or halt it — an agent re-submitting e.g. `DROP TABLE users;` in an
                        # apology loop would block forever with no breaker (the token-drain
                        # gap found running examples/04). The shield is itself a LOCAL
                        # decision (no gateway consulted, online OR offline), so the SDK must
                        # enforce the strike ceiling for THIS block class — mirroring the
                        # REASONING_ENGINE_UNREACHABLE offline fallback (check before the
                        # increment, so it trips on the call AFTER the ceiling is reached).
                        # Placed before the override swap so a halted loop neither delivers
                        # nor counts a reframe. Strikes are already trace-scoped above (see
                        # _strike_owner) and a later gateway ALLOW / fail-open zeroes them,
                        # so only a sustained same-tool block loop trips.
                        _trip_breaker_if_ceiling(
                            strike_key, max_allowed_turns,
                            f"AgentX Circuit Breaker Triggered: agent repeated a keyword-blocked "
                            f"action on '{func_name}' {max_allowed_turns} times. Halting to prevent "
                            f"token drain (Layer-0 shield — the gateway never sees this call).",
                            log_message="🛑 [LOCAL KEYWORD SHIELD] Circuit breaker threshold met. Killing loop natively.")
                        _incr_strike(strike_key)

                        # BUILD #2 — org-reframe swap on the Layer-0 local-shield path
                        # too (the offline path a keyworded block like DROP TABLE takes;
                        # the incident is logged under this same policy_id, so the adopted
                        # reframe is keyed identically). Centralised in _apply_org_override
                        # so this path and the gateway path can never drift apart.
                        challenge_text, ls_safe_path = _apply_org_override(
                            policy_id, challenge_text,
                            matched_policy.get("preferred_alternative"),
                            policy_name=policy_name)

                        _incr("intercepts")
                        _incr("critical_blocks")
                        _note_block_category(matched_policy.get("category") or _POLICY_ID_TO_CATEGORY.get(policy_id))
                        _mark_trace("challenged_traces", current_trace_id)

                        log_intercept(current_trace_id, agent_id, func_name, policy_id, policy_name, "CHALLENGED")

                        print(f"⚡ [LOCAL KEYWORD SHIELD] Fast-path intercept engaged on policy '{policy_name}' (offline, no LLM judge).")
                        print(f"🛑 [LOCAL BLOCK] Policy '{policy_name}' matched a blocked intent locally.")

                        # Persist the CHALLENGED incident so this block is recorded and a
                        # later self-correction can flip it to COMPLIED (moving the
                        # 'Agent Runs Protected' metric). This is a cheap park call — NO
                        # neural/symbolic/LLM work runs gateway-side, so Layer 0's cost win
                        # is preserved. If the gateway is unreachable we degrade gracefully
                        # to an offline synthetic id (block still delivered, just not logged).
                        registered_receipt = _client.register_incident(
                            agent_id=agent_id,
                            query=str(query),
                            chain_of_thought=chain_of_thought,
                            policy_id=policy_id,
                            policy_name=policy_name,
                            challenge_issued=challenge_text,
                            trace_id=current_trace_id
                        )
                        effective_receipt = registered_receipt or f"local-keyword-shield-{policy_id}"
                        if registered_receipt:
                            # The park is fire-and-forget (issue #3): the POST runs off
                            # this block path, so a slow/down control plane never delays
                            # the agent. The receipt is the client-pinned UUID the row
                            # is committed under, drained at session end. Best-effort —
                            # if the park fails, _post_incident warns asynchronously
                            # (the block itself already stood regardless).
                            print(f"🧾 [LOCAL KEYWORD SHIELD] Incident park dispatched (async, best-effort — off the block path). Receipt: {effective_receipt}")
                        else:
                            print(f"📝 [LOCAL KEYWORD SHIELD] Offline (no API key) — using local receipt: {effective_receipt}")

                        # ✅ SURGICAL FIX: Route via the delivery function. Coaching mirrors the
                        # keyless MCP path (A1a): lead with the challenge + the concrete safe path,
                        # with no judge-era "explain your symbolic reasoning" / SAFE_WRITE taxonomy
                        # (this OFFLINE keyword-shield path has no judge), so the two keyless surfaces
                        # emit consistent coaching. The ONLINE/judge path below keeps its own wording.
                        ls_safe_hint = f" Safe alternative: {ls_safe_path}" if ls_safe_path else ""
                        payload = (
                            f"🚨 [AgentX Security Block] | policy: '{policy_name}' | receipt_id: '{effective_receipt}' | "
                            f"Challenge/Constraint: {challenge_text}{ls_safe_hint} "
                            f"System Instruction: Your request has been blocked. Revise the action to a "
                            f"safe form and retry your tool execution turn immediately."
                        )
                        return _deliver_challenge(
                            payload, effective_receipt, policy_name,
                            challenge_text=challenge_text,
                            safe_path=ls_safe_path,
                        )
                # ✅ DO NOT swallow our own intentional routing exceptions
                except (AgentXSecurityBlock, AgentXCircuitBreakerTripped):
                    raise
                except Exception as local_shield_error:
                    print(f"⚠️ [Local Shield] Out-of-prompt keyword pre-filter pass bypassed: {str(local_shield_error)}")

            # =========================================================
            # LAYER 2: THE LIVE FASTAPI WEDGE CALL
            # ✅ UPGRADED FASTAPI EVALUATE INTERFACE PASS
            # We forward our local strike integer payload metadata out-of-band directly to the gateway
            # =========================================================
            # Budget meter (AFDB #17/#23): add a coarse ~4-chars/token estimate for
            # this call as a zero-config proxy for runaway-loop VOLUME, then forward
            # the session total. Real usage reported via record_spend() is
            # authoritative and replaces the estimate; reported $ drives the dollar
            # ceiling. The gateway owns the ceiling + the ESCALATE verdict.
            _incr("auto_tokens_estimate", max(
                1, (len(str(query)) + len(str(chain_of_thought))) // 4
            ))
            session_tokens_total = (
                _session_stats["reported_tokens"] or _session_stats["auto_tokens_estimate"]
            )
            session_cost_total = _session_stats["reported_cost_usd"]

            # Shared multi-agent budget pool (AFDB #43): the decorator arg wins, else
            # the env var, so an orchestrator can set ONE AGENTX_BUDGET_POOL_ID across
            # every swarm peer it spawns with zero code change. Unset => no pooling.
            resolved_pool_id = budget_pool_id or os.environ.get("AGENTX_BUDGET_POOL_ID") or None

            eval_res = _client.evaluate_intent(
                agent_id=agent_id,
                query=query,
                chain_of_thought=chain_of_thought,
                receipt_id=receipt_id,
                trace_id=current_trace_id,
                action=resolved_action,
                args=structured_args or None,
                session_tokens=session_tokens_total,
                session_cost_usd=session_cost_total,
                budget_pool_id=resolved_pool_id,
            )

            status = eval_res.get("status") if isinstance(eval_res, dict) else None

            # A real verdict came back (allow OR block) — the gateway was reached.
            # UNREACHABLE is the one status that means it was NOT. Recorded once per
            # session as the anonymous pulse's coarse "SDK + gateway" funnel signal.
            if isinstance(eval_res, dict) and status != "REASONING_ENGINE_UNREACHABLE":
                _session_stats["gateway_reached"] = True
                # The gateway advertises whether the judge (Recover tier) is active
                # (reasoning_enabled). Capture once-True for the session — mirrors
                # gateway_reached — so the pulse can split keyless Shield vs Recover.
                advertised = eval_res.get("reasoning_enabled")
                if advertised is True:
                    _session_stats["reasoning_enabled"] = True
                elif advertised is False and _session_stats.get("reasoning_enabled") is not True:
                    _session_stats["reasoning_enabled"] = False

            # 0. GATEWAY UNREACHABLE: apply the configured fail-mode (default: open).
            if isinstance(eval_res, dict) and eval_res.get("status") == "REASONING_ENGINE_UNREACHABLE":
                # OFFLINE-ONLY FALLBACK: the gateway (the decision authority) is
                # unreachable, so the SDK enforces the strike ceiling locally to stop a
                # runaway loop. When the gateway IS reachable it owns BOTH the count and
                # this verdict via Path B (per-trace _STRIKE_TRACKER, issue #80) and parks
                # a control-plane-visible incident — the SDK forwards nothing.
                # consecutive_strikes accrues on the LOCAL block classes the gateway never
                # sees — the fail-closed blocks below AND the Layer-0 keyword-shield blocks
                # above (each short-circuits before a gateway round-trip). Fail-open resets
                # strikes each call, so this trips only on accrued local blocks.
                #
                # By-design threshold note (issue #80 review): this offline counter does
                # NOT inherit the gateway's online count — it can't, the gateway is
                # unreachable. So a gateway that fails mid-loop starts this counter from
                # whatever the LOCAL state was (online blocks no longer pre-seed it, and
                # an online ALLOW zeroes it). A gateway that is CONSISTENTLY down accrues
                # max_allowed_turns fail-closed blocks and trips correctly; the only case
                # that won't trip is a gateway flapping with intervening online ALLOWs —
                # but an allowed call is the gateway vetting the action as safe, i.e. real
                # progress, not a runaway, so resetting there is the right call.
                reason = eval_res.get("reason")
                fail_mode = _resolve_fail_mode()

                # KEYLESS (no key) + fail-open (default): this call already PASSED the
                # in-process Layer-0 shield, so it is progress, not a repeated blocked
                # action. Handle it BEFORE the offline runaway-breaker so a keyless
                # recovery is never preempted by the strike ceiling (a clean call is not
                # a loop; repeated keyless BLOCKS still trip the Layer-0 breaker above).
                # Keyless is a supported mode, not a degraded outage: run the call, with
                # no "DEGRADED, start the engine" banner and no degraded tally. This is
                # the fix for keyless clean calls dead-ending on a missing-key System
                # Error. (Keyless + AGENTX_FAIL_MODE=closed still falls through to the
                # block below: the operator explicitly chose to block the unverifiable.)
                if reason == "no_api_key" and fail_mode != "closed":
                    _reset_strike(strike_key)
                    # Credit a keyless self-correction if this trace was blocked earlier
                    # and the revised call now clears the shield (bounded recovered ⊆
                    # challenged, the same gate as the gateway ALLOWED path) + narrate the
                    # heal beat, so the keyless "the run survived" moment is finally
                    # visible AND countable on the pulse (self_corrections).
                    if _credit_recovery(current_trace_id):
                        log_self_correction(current_trace_id, agent_id, func_name)
                        print(f"🔄 [AgentX SDK] Recovered: the agent revised its approach after the block and the safe '{func_name}' call cleared the keyless shield.")
                    return _ExecuteTool()

                _trip_breaker_if_ceiling(
                    strike_key, max_allowed_turns,
                    f"[OFFLINE FALLBACK] Agent failed to self-correct on '{func_name}' "
                    f"{max_allowed_turns} times and the AgentX gateway is unreachable. "
                    f"Halting to prevent token drain.")

                if fail_mode == "closed":
                    # FAIL CLOSED: do NOT execute — the engine could not vet this action.
                    # Retries accrue strikes so a wedged/down engine trips the circuit
                    # breaker instead of the agent looping blindly forever.
                    _emit_failclosed_warning(reason, func_name)
                    # Accrue a strike so a wedged engine still trips the breaker, but do
                    # NOT mark the trace recoverable: a fail-closed block is an
                    # availability event, not a policy challenge. Crediting a later
                    # success here as a "self-correction" is what drifted the rate >100%.
                    _incr_strike(strike_key)
                    block_msg = (
                        "🚨 [AgentX Security Block] | policy: 'Fail-Closed (Reasoning Engine Unavailable)' | "
                        "receipt_id: 'failclosed-no-engine' | "
                        "Challenge/Constraint: This action could not be verified because the AgentX Reasoning "
                        "Engine is unavailable and AGENTX_FAIL_MODE=closed. The action was NOT executed. Do not "
                        "retry blindly; wait for the engine to recover or escalate to a human operator."
                    )
                    return _deliver_challenge(
                        block_msg, "failclosed-no-engine", "Fail-Closed (Reasoning Engine Unavailable)",
                        challenge_text=(
                            "This action could not be verified because the AgentX Reasoning Engine is "
                            "unavailable and AGENTX_FAIL_MODE=closed. The action was NOT executed. Do not "
                            "retry blindly; wait for the engine to recover or escalate to a human operator."
                        ),
                    )

                # FAIL OPEN (default), gateway expected but unreachable: genuinely
                # degraded (the keyless no-key case already returned above).
                _emit_failopen_warning(reason, func_name)
                _incr("degraded_executions")
                _reset_strike(strike_key)
                return _ExecuteTool()

            # 1. Check for the Unified Gateway's Block Signal
            if isinstance(eval_res, dict) and eval_res.get("error") == "AgentX Policy Violation":
                _incr("intercepts")
                # NOTE: the local strike counter is NOT incremented here anymore. A
                # reachable gateway block means the gateway already counted this strike
                # in its own per-trace _STRIKE_TRACKER and owns the Path B decision
                # (issue #80). The local counter accrues only on the OFFLINE fail-closed
                # path, so an online block must not double-count into it.
                # +++ SENSOR: mark this trace as challenged so a later safe call on the
                # same trace is counted as a self-correction (per-trace, bounded) +++
                _mark_trace("challenged_traces", current_trace_id)
                
                actual_policy_id = eval_res.get("policy_id", "POL-UNKNOWN")
                policy_name = eval_res.get("policy_triggered", "Unknown Policy")
                challenge_text = eval_res.get("challenge", "Policy violation detected. Please revise your intent.")
                returned_receipt_id = eval_res.get("receipt_id", "no-receipt")

                # BUILD #2 — org-reframe swap: if this org adopted a task-fitting
                # reframe for this policy (via `agentx adopt`), deliver it in place of
                # the gateway's generic challenge — zero gateway round-trip. Same
                # _apply_org_override helper as the Layer-0 path so the two never drift.
                _gateway_safe_path = eval_res.get("safe_path") or eval_res.get("preferred_alternative")
                challenge_text, _gateway_safe_path = _apply_org_override(
                    actual_policy_id, challenge_text, _gateway_safe_path,
                    policy_name=policy_name)
                
                critical_policies = [
                    "Mass Destructive Intent", 
                    "Database Isolation", 
                    "Secrets and PII Exfiltration", 
                    "Out-of-Bounds Execution"
                ]
                
                if policy_name in critical_policies:
                    _incr("critical_blocks")

                log_intercept(current_trace_id, agent_id, func_name, actual_policy_id, policy_name, "CHALLENGED")

                print(f"🛑 [AgentX SDK] Policy '{policy_name}' violated. Routing challenge instruction string.")
                
                # ✅ SURGICAL FIX: Route via the delivery function
                payload = (
                    f"🚨 [AgentX Security Block] | policy: '{policy_name}' | receipt_id: '{returned_receipt_id}' | "
                    f"Challenge/Constraint: {challenge_text} "
                    f"System Instruction: Your request has been blocked. Analyze this security barrier, "
                    f"adjust your parameters payload to be safe, change your execution query path, "
                    f"and retry your tool execution turn immediately."
                )
                return _deliver_challenge(
                    payload, returned_receipt_id, policy_name,
                    challenge_text=challenge_text,
                    safe_path=_gateway_safe_path,
                )

            # 1.5. CIRCUIT BREAKER FROM GATEWAY
            elif isinstance(eval_res, dict) and eval_res.get("error") == "AgentX Cognitive Loop Aborted":
                _incr("circuit_breakers_tripped")
                returned_receipt_id = eval_res.get("receipt_id", "no-receipt")
                challenge_text = eval_res.get("challenge", "Maximum consecutive policy retry attempts reached.")
                
                print(f"🛑 [AgentX SDK] Circuit Breaker threshold met. Killing loop natively.")
                
                # Force an exception raise here to break the agent's retry while-loop
                return _deliver_challenge(challenge_text, returned_receipt_id, "Circuit Breaker", is_circuit_breaker=True)

            # 2. Check for the Escalation Handoff (The HITL Polling Loop)
            elif isinstance(eval_res, dict) and eval_res.get("status") == "ESCALATED":
                # Track human escalation counters state natively in the session stats for accurate summary reporting
                _incr("human_escalations")
                
                receipt_id = eval_res.get("receipt_id")
                print(f"\n🚨 [AgentX SDK] Task suspended. Request escalated to Human SOC.")
                print(f"⏳ [AgentX SDK] Polling for human decision (Receipt: {receipt_id})...")
                
                api_key = os.environ.get("AGENTX_API_KEY")
                headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
                
                max_poll_seconds = 120 # 2-minute max wait
                poll_interval = 3
                elapsed = 0
                
                # The Polling Loop
                while elapsed < max_poll_seconds:
                    time.sleep(poll_interval)
                    elapsed += poll_interval
    
                    try:
                        status_check = requests.get(
                            f"{_client.gateway_url}/v1/status/{receipt_id}",
                            headers=headers,
                            timeout=2.0
                        )
                        if status_check.status_code == 200:
                            current_status = status_check.json().get("status")
                            
                            if current_status == "APPROVED":
                                print(f"\n✅ [AgentX SDK] Human SOC APPROVED the override!")
                                # Human-assisted, not autonomous: mark the trace resolved so
                                # a later safe call on it is NOT miscounted as self-correction.
                                _mark_trace("human_resolved_traces", current_trace_id)
                                return _ExecuteTool()
                                
                            elif current_status == "DENIED":
                                print(f"\n❌ [AgentX SDK] Human SOC DENIED the override.")
                                return json.dumps({
                                    "error": "AgentX Human Override Denied",
                                    "instruction": "The SOC analyst explicitly denied this action. You must find an alternative path or fail the task."
                                })
                                
                        elif status_check.status_code == 401:
                            print(f"\n❌ [AgentX SDK] Auth Error: Gateway rejected polling request.")
                            return json.dumps({"error": "Unauthorized Polling"})
                            
                    except requests.exceptions.RequestException as e:
                        print(f"⚠️ Ignore transient network drops. Keep trying. Polling error: {e}")
                        
                if elapsed >= max_poll_seconds:
                    print("⚠️ [AgentX SDK] SOC Polling Timeout reached. Failing safe.")
                    return "AgentX Error: Timeout waiting for SOC approval. Aborting action."

            # 3. Check for the "Success" path
            elif isinstance(eval_res, dict) and eval_res.get("status") in ["success", "ALLOWED"]:
                print(f"✅ [AgentX SDK] Intent safe. Executing '{func_name}'.")

                _reset_strike(strike_key)

                # Self-correction = a safe call on a trace that was previously challenged,
                # was not human-resolved, and hasn't already been credited. Keeping
                # recovered_traces a subset of challenged_traces bounds the rate <=100%.
                # Atomic credit-and-claim: only the call that actually transitions the
                # trace to recovered logs the DB row, so concurrent ALLOWs on one
                # shared async session can't double-log (#115 finding 6).
                if _credit_recovery(current_trace_id):
                    log_self_correction(current_trace_id, agent_id, func_name)
                    # The heal-narration beat. The block is narrated loudly and the
                    # session summary counts corrections, but without this line the
                    # heal lands silently and the dev never learns the run was saved.
                    # Dev console only, never the tool's return value (the model's
                    # channel stays clean coaching). Prints at APPROVAL time: execution
                    # is hoisted to the wrapper shell and runs next, so the wording
                    # claims the revision + approval, NOT completion (the call could
                    # still fail when it runs).
                    print(f"🔄 [AgentX SDK] Recovered: the agent revised its approach after the block and the safe '{func_name}' call was approved.")

                # Cleared to run. Execution is hoisted to the wrapper shell (so the
                # async wrapper can `await` it); any PII scrub rides along as a
                # directive and is applied to the result there.
                pii_targets = eval_res.get("pii_targets_to_scrub", [])
                return _ExecuteTool(scrub_targets=pii_targets)

            # 4. Handle actual Gateway crashes
            else:
                error_detail = eval_res.get("message") if isinstance(eval_res, dict) else "Unknown Connection Error"
                return f"AgentX System Error: {error_detail}"

        def _apply_scrub(result, decision):
            """Apply any PII scrub to an already-computed tool result. The SINGLE
            home for the post-execution scrub, shared by the sync and async finishers
            so DLP behaviour can't drift between them (#115 cleanup)."""
            if decision.scrub_targets:
                print(f"🧹 [AgentX SDK] Local DLP Active. Scrubbing {decision.scrub_targets} from output...")
                return _scrub_pii(result, decision.scrub_targets)
            return result

        def _finish_sync(decision, args, kwargs):
            """Run the tool for a SYNC verdict and apply any scrub, or pass the
            terminal verdict straight back."""
            if isinstance(decision, _ExecuteTool):
                return _apply_scrub(func(*args, **kwargs), decision)
            return decision

        if _is_async_tool:
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                # Establish a stable trace_id in THIS (the caller's) context BEFORE
                # snapshotting it. Without this, copy_context() captures an empty trace
                # and _decide's auto-start sets it only in the discarded copy — minting
                # a NEW trace every call, which defeats the offline AND gateway strike/
                # loop breakers (they key on the per-call trace) and never credits
                # recovery (#115 finding 1). Setting it here makes the trace persist
                # across sequential awaits in this task AND be seen by the awaited tool
                # body below — restoring parity with the sync path (also #115 finding 5).
                if not trace_id_var.get():
                    start_secure_session()
                # Run the BLOCKING decision core (gateway call + up-to-120s HITL poll)
                # on a DEDICATED bounded pool, NOT asyncio's default executor, so it
                # can never starve the host app's own run_in_executor / to_thread
                # (#115 finding 2). copy_context() carries the trace into the worker.
                loop = asyncio.get_running_loop()
                ctx = contextvars.copy_context()
                decision = await loop.run_in_executor(
                    _get_async_executor(), lambda: ctx.run(_decide, args, kwargs)
                )
                if isinstance(decision, _ExecuteTool):
                    return _apply_scrub(await func(*args, **kwargs), decision)
                return decision
            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return _finish_sync(_decide(args, kwargs), args, kwargs)
        return wrapper
    return decorator