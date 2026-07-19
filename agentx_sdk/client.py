import os
import time
import uuid
import warnings
import threading
import requests

class AgentXClient:
    def __init__(self, gateway_url="http://localhost:8000"):
        self.gateway_url = gateway_url
        # Outstanding fire-and-forget incident-park threads (see register_incident).
        # The block string is delivered to the agent immediately; the POST runs on
        # these threads, OFF the response path. Tracked so the session-end hook can
        # drain them (bounded) — otherwise a short script could exit and drop the
        # park before it lands. Guarded by a lock: parks dispatch from the agent
        # thread while the drain reads from the atexit thread.
        self._pending_parks = []
        self._pending_lock = threading.Lock()

    def evaluate_intent(self, agent_id, query, chain_of_thought, receipt_id=None, trace_id=None,
                        action=None, args=None, session_tokens=0, session_cost_usd=0, budget_pool_id=None,
                        enforcement=None, strike_count=None):
        # `strike_count` is DEPRECATED and ignored (issue #80): the gateway owns the
        # strike count + the Path B decision per trace_id now, so a forwarded count
        # can no longer influence the verdict. The parameter is retained only so
        # existing direct callers don't break; it is never placed in the payload. A
        # caller that still passes one gets a loud (not silent) signal that it's a
        # no-op, so a stale integration isn't left thinking it still drives the breaker.
        if strike_count is not None:
            warnings.warn(
                "AgentXClient.evaluate_intent(strike_count=...) is deprecated and ignored: "
                "the gateway now owns the circuit-breaker strike count per trace_id (issue "
                "#80). Remove the argument; the breaker trips on real consecutive blocks "
                "on the same trace_id.",
                DeprecationWarning,
                stacklevel=2,
            )
        # ✅ Fetch it dynamically right when the network request is made
        api_key = os.environ.get("AGENTX_API_KEY")

        if not api_key:
            # Keyless (no key configured) is a SUPPORTED mode, not an error. Signal
            # UNREACHABLE with a distinct reason so the decorator runs its keyless
            # fail-open path: the in-process Layer-0 shield already blocks the
            # catastrophic calls, so a CLEAN call executes instead of dead-ending on a
            # hard "System Error" (which silently broke every keyless clean call and
            # made the SDK look broken on a developer's first real, non-blocked call).
            # A PRESENT-but-invalid key still errors (401 below); only "no key" is keyless.
            return {"status": "REASONING_ENGINE_UNREACHABLE", "reason": "no_api_key"}

        # =========================================================
        # 🧭 ACTION / ARGS CONTRACT (declared routing, text fallback)
        # =========================================================
        # `action` names the tool surface (execute_database_query, fetch_url, …)
        # and `args` carries its structured named fields. Both are best-effort:
        # the decorator builds them via auto-reflection, so a developer never
        # has to. `query` is ALWAYS sent as the flattened inspectable text — the
        # gateway's deterministic floor scans it, so even if `action` is wrong or
        # absent the detectors are never starved. Structured when confident,
        # text-fallback always present.
        # =========================================================
        # `strike_count` is intentionally NOT sent: the gateway owns the strike
        # count + the Path B circuit-breaker decision per trace_id (issue #80). The
        # SDK no longer meters strikes for the online decision — it keeps only an
        # offline-only fallback counter (see decorators.py) for when this gateway is
        # unreachable, which by definition never rides in a payload.
        payload = {
            "agent_id": agent_id,
            "query": query,
            "cot": chain_of_thought,
            "receipt_id": receipt_id,
            "trace_id": trace_id,
        }
        # Only attach when present so an un-upgraded caller's payload is unchanged.
        if action is not None:
            payload["action"] = action
        if args:
            payload["args"] = args
        # Cumulative session spend for the budget-ceiling floor.
        # Sent like strike_count — the gateway owns the ceiling + verdict. Omitted
        # when zero so an un-metered caller's payload is unchanged.
        if session_tokens:
            payload["session_tokens"] = int(session_tokens)
        if session_cost_usd:
            payload["session_cost_usd"] = float(session_cost_usd)
        # Shared multi-agent budget pool key. When peers in an A2A swarm
        # carry the SAME budget_pool_id, the gateway sums their cumulative spend
        # across the pool. Omitted when unset so a single-agent caller's payload —
        # and verdict path — is byte-identical to today (no pool aggregation runs).
        if budget_pool_id:
            payload["budget_pool_id"] = str(budget_pool_id)
        # Enforcement posture (AGENTX_ENFORCEMENT). Forwarded ONLY when audit, so the
        # gateway skips persisting a policy CHALLENGED for an evaluating (non-enforcing)
        # install — it still returns the verdict, so the SDK records its own local
        # WOULD_BLOCK. Omitted for enforce so an enforcing/legacy caller's payload — and
        # the gateway's persistence path — is byte-identical to today.
        if str(enforcement or "").strip().lower() == "audit":
            payload["enforcement"] = "audit"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.gateway_url}/v1/evaluate", 
                json=payload,
                headers=headers,
                timeout=30.0 # Bounds a real gateway hang while surviving cold starts
                             # (first Next.js route compile + cold Gemini can exceed 15s)
            )
            
            if response.status_code == 401:
                return {"status": "ERROR", "message": "Invalid AgentX API Key."}
                
            result = response.json()
            # Reasoning-tier capability (Recover vs keyless Shield) is advertised as a
            # header on EVERY /v1/evaluate response, so the SDK learns it on any verdict
            # (block/escalate/allow) — not just the body paths that used to mention it.
            # Inject it so the decorator's capture stays uniform; absent header => None.
            hdr = response.headers.get("X-AgentX-Reasoning")
            if hdr is not None and isinstance(result, dict):
                result["reasoning_enabled"] = (hdr == "1")
            return result

        except requests.exceptions.ConnectionError:
            # Gateway is unreachable (down / not routable). The in-process Layer 0
            # offline shield still guards deterministic keyword threats — only the
            # gateway's neural/CoT semantic checks are skipped. Signal fail-open.
            return {"status": "REASONING_ENGINE_UNREACHABLE", "reason": "connection_error"}
        except requests.exceptions.Timeout:
            # Gateway is UP but did not answer in time — it may have been mid-evaluation
            # and about to block. Riskier than a clean connection failure. Signal fail-open.
            return {"status": "REASONING_ENGINE_UNREACHABLE", "reason": "timeout"}
        except Exception as e:
            return {"status": "ERROR", "message": f"AgentX unexpected error: {e}"}

    def register_incident(self, agent_id, query, chain_of_thought, policy_id,
                          policy_name, challenge_issued, trace_id=None):
        """
        Park a CHALLENGED incident for an offline (Layer 0 keyword shield) block —
        FIRE-AND-FORGET, off the response path (issue #3).

        No neural/symbolic/LLM evaluation runs gateway-side — this is a cheap
        registration that preserves Layer 0's cost win while persisting the
        incident, so a later self-correction can be matched and flipped to COMPLIED.

        The receipt UUID is pinned client-side, so we know it *before* any network
        call. We return that pinned id IMMEDIATELY and dispatch the actual POST on a
        daemon thread. The block is therefore delivered to the agent with zero added
        latency, and a slow/down control plane can no longer delay the SDK-facing
        path or push its timeout into fail-open — which is exactly what a synchronous
        10s park used to do on the keyword-shield path. The gateway parks the row
        under this exact UUID, so even if the background reply is lost the later
        COMPLIED PATCH still matches.

        Returns the pinned receipt (a UUID) when a key is set, or None when there is
        no AGENTX_API_KEY (offline — nothing is parked; the caller uses a synthetic
        local id).
        """
        api_key = os.environ.get("AGENTX_API_KEY")
        if not api_key:
            return None

        # Pin our own UUID and send it in the payload so the gateway parks the row
        # under exactly this id. That way a lost/timed-out response can't orphan the
        # incident — we already know the receipt the COMPLIED PATCH must target.
        # (Mirrors the gateway-side receipt pinning in park_incident.)
        receipt_id = str(uuid.uuid4())
        payload = {
            "receipt_id": receipt_id,
            "agent_id": agent_id,
            "query": query,
            "cot": chain_of_thought,
            "policy_id": policy_id,
            "policy_name": policy_name,
            "challenge_issued": challenge_issued,
            "trace_id": trace_id
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        t = threading.Thread(
            target=self._post_incident, args=(payload, headers), daemon=True
        )
        with self._pending_lock:
            # Garbage-collect finished threads so a long-running agent's list can't
            # grow unbounded, then track this one for the session-end drain.
            self._pending_parks = [p for p in self._pending_parks if p.is_alive()]
            self._pending_parks.append(t)
            # Start INSIDE the lock: a concurrent register_incident's is_alive()
            # GC above would otherwise evict this not-yet-started thread before
            # start(), leaving it untracked and undrainable (park dropped at exit).
            t.start()
        return receipt_id

    def _post_incident(self, payload, headers):
        """Best-effort background park (issue #3). Never raises into the caller — the
        block already stood; persistence is a side effect. A lost park only means a
        later self-correction can't be matched to flip the row to COMPLIED. A failure
        is surfaced as an async warning (not silently swallowed) so a misconfigured
        key / down control plane still produces a signal — just off the block path."""
        receipt = payload.get("receipt_id")
        try:
            # (connect, read) split: a 1s connect ceiling fails a doomed park BELOW the
            # 2s session-end drain budget — so the failure is observed (and warned)
            # before the drain abandons the thread at exit, instead of a dead-heat that
            # kills the thread mid-connect. A slow-but-alive control plane still gets up
            # to 10s to commit the row once connected.
            resp = requests.post(
                f"{self.gateway_url}/v1/incident",
                json=payload,
                headers=headers,
                timeout=(1.0, 10.0)
            )
            if resp.status_code != 200:
                print(f"⚠️ [LOCAL KEYWORD SHIELD] Async incident park rejected "
                      f"({resp.status_code}) for receipt {receipt} — the block stood, "
                      f"but recovery for this trace won't be recorded.")
        except Exception as e:
            print(f"⚠️ [LOCAL KEYWORD SHIELD] Async incident park failed "
                  f"({type(e).__name__}) for receipt {receipt} — the block stood, "
                  f"but recovery for this trace won't be recorded.")

    def drain_pending_parks(self, timeout=3.0):
        """Join outstanding fire-and-forget park threads at session end so a short
        script doesn't exit and silently drop them. Bounded by ``timeout`` seconds
        in total so a wedged control plane can never hang interpreter shutdown."""
        with self._pending_lock:
            pending = [p for p in self._pending_parks if p.is_alive()]
        deadline = time.monotonic() + timeout
        for p in pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            p.join(timeout=remaining)

    def auto_contribute(self, gateway_reached=True):
        """Lock-1 — session-end auto-contribution. For EXPLICITLY opted-in, NETWORKED
        installs, push the abstract corpus projection so the dev doesn't have to
        remember `agentx push`. Default UNCHANGED: a silent no-op unless
        AGENTX_CONTRIBUTE is explicitly true. Networked-only (`local` has no plane).
        INCREMENTAL: passes the stored cursor as `since` so only NEW incidents are sent
        (never re-uploading the whole projection, which the de-identified corpus cannot
        dedup). DAILY-debounced to bound the atexit round-trip; skipped entirely when no
        gateway was reached this session. Fire-and-forget; never raises (must never
        delay or break interpreter shutdown).
        """
        try:
            from . import pulse  # stdlib-only/import-safe; holds env/mode/state helpers

            # 1. EXPLICIT opt-in only — never prompt at exit; default-off stays off.
            if not pulse._truthy(pulse._env("AGENTX_CONTRIBUTE")):
                return
            # 2. Skip when no gateway was reached this session — the GET would only
            #    time out (gateway down) or add a needless shutdown round-trip (idle
            #    session); the next active session contributes.
            if not gateway_reached:
                return
            # 3. Networked only — `local` has no control plane to send to.
            mode = pulse._mode()
            if mode not in ("linked", "cloud"):
                return
            api_key = os.environ.get("AGENTX_API_KEY")
            if not api_key:
                return
            plane = (pulse._env("CONTROL_PLANE_URL") or "").strip().rstrip("/")
            if not plane and mode == "cloud":
                plane = "https://www.agentx-core.com"   # canonical www host (apex 307s)
            if not plane:
                return
            # 4. Daily debounce, stamped BEFORE the network so we attempt at most once
            #    per day regardless of outcome (a failure just retries tomorrow).
            state = pulse._load_state()
            now = time.time()
            if now - (state.get("last_auto_contribute", 0) or 0) < pulse._DEBOUNCE_SECONDS:
                return
            state["last_auto_contribute"] = now
            pulse._save_state(state)

            # 5. INCREMENTAL pull: pass the stored cursor as `since` so only NEW signals
            #    are sent (the privacy boundary is enforced server-side — raw
            #    payloads/CoT/ids never arrive), then advance the cursor on success.
            since = state.get("last_contributed_cursor")
            headers = {"Authorization": f"Bearer {api_key}"}
            proj = requests.get(
                f"{self.gateway_url}/v1/contribution", headers=headers,
                params={"since": since} if since else None, timeout=2.0,
            )
            if proj.status_code != 200:
                return
            body = proj.json() or {}
            contributions = body.get("contributions", [])
            if not contributions:
                return
            post = requests.post(
                f"{plane}/api/edge/contribute",
                json={"contributions": contributions},
                headers=headers,
                timeout=3.0,
            )
            if post.status_code in (200, 201, 202):
                pulse.mark_contributed(cursor=body.get("cursor"))   # advance delta cursor + stamp the leg
        except Exception:
            pass