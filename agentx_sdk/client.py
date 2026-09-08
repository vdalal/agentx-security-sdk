import os
import sys
import time
import uuid
import warnings
import threading
import requests

# 🔴 HOW LONG WE WAIT FOR A VERDICT, AND WE NOW TELL THE GATEWAY (P-157).
#
# This was a bare `timeout=30.0` at the request while the gateway's judge deadline also
# defaulted to 30s and could be configured higher. Two equal clocks, ours starting EARLIER
# because it begins before the request is sent, so a verdict that took the full judge deadline
# could never reach us: we gave up first and failed open, and the gateway's answer — including
# a correct block on a destructive write — was discarded in transit.
#
# A NAMED CONSTANT, not a literal, because it is now read in two places (the request bound and
# the forwarded field) and those two drifting apart is the whole defect restated. The gateway
# caps its judge to this minus its own overhead; see `_effective_judge_timeout` there, and the
# cross-surface tripwire that pins the relationship.
#
# Kept at 30.0 deliberately: raising it would trade a correct verdict for a longer hang, and
# the gateway now fits inside whatever we say rather than us waiting out whatever it chose.
EVALUATE_TIMEOUT_S = 30.0


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
                        enforcement=None, strike_count=None, tool=None):
        # `tool` is APPENDED, after the deprecated `strike_count`, not slotted in beside
        # the fields it belongs with. `strike_count` is retained precisely so existing
        # direct callers do not break, and inserting ahead of it would hand a caller
        # that still passes it positionally a `tool` instead. Every in-repo caller uses
        # keywords; the ordering is for the external ones we cannot see.
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
        # 🧭 ACTION / ARGS / TOOL CONTRACT (declared routing, text fallback)
        # =========================================================
        # `action` names the tool surface (execute_database_query, fetch_url, …)
        # and `args` carries its structured named fields. Both are best-effort:
        # the decorator builds them via auto-reflection, so a developer never
        # has to. `query` is ALWAYS sent as the flattened inspectable text — the
        # gateway's deterministic floor scans it, so even if `action` is wrong or
        # absent the detectors are never starved. Structured when confident,
        # text-fallback always present.
        #
        # `tool` is the DECORATED FUNCTION'S OWN NAME, and it is a THIRD channel on
        # purpose (BACKLOG P-69). The flattening keeps argument VALUES only, so
        # `delete_all_customer_records(table="customers")` reaches the gateway as the
        # word "customers" and the verb is simply gone. The name is where that verb
        # lives, and it is the granularity an operator actually configures against —
        # a per-context limit is written `support_agent:issue_refund`, which is a TOOL,
        # not one of the coarse action surfaces above.
        #
        # 🔴 IT IS NOT FOLDED INTO `action`, and that separation is the point. `action`
        # ROUTES: the gateway skips a surface-scoped policy whose target does not match
        # it. Putting a tool name there routes a database tool off the database
        # surface, which is what the SDK's old name-derived `filesystem_delete` guess
        # actually did. Carried separately, a wrong `tool` costs a limit lookup that
        # misses, never a policy that is skipped.
        #
        # No new data category: `query` and `args` already carry the caller's real
        # argument VALUES, and a function name is the developer's own code identity.
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
        # Attached only when non-empty, for the same reason: a direct caller that
        # passes no tool sends the payload it sends today, and the gateway's
        # tool-keyed lookups simply do not fire.
        if tool:
            payload["tool"] = str(tool)
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
            # 🔴 CAPABILITY marker, and it exists because the gateway and the SDK deploy
            # INDEPENDENTLY. This SDK releases EVERY verdict in audit — escalations and
            # breaker halts included.
            # Older SDKs do not: they still suspend on an ESCALATED and poll
            # /v1/status/{receipt_id} for up to 120 seconds.
            #
            # So a gateway that stopped parking escalations in audit, talking to an SDK
            # that still polls, would leave that poll unresolvable — 120s of hang followed
            # by "Timeout waiting for SOC approval", in the one mode whose entire promise
            # is that we do not change how their code behaves. Strictly worse than before,
            # because the parked row at least let a human approve it.
            #
            # The gateway therefore keys the full skip on THIS FLAG, not on the posture
            # alone. Behaviour is then correct in both directions regardless of which
            # side deploys first, which is the only property worth having here — deploy
            # ORDERING is not something a released SDK can be made to respect.
            payload["audit_releases_all"] = True

        # How long we will still be listening. The gateway fits its judge inside this so a
        # verdict cannot be produced after we have stopped waiting (P-157). Sent on EVERY
        # request, not only when it differs from the default, because the gateway's fallback
        # for an absent field has to assume the oldest released SDK rather than this one.
        payload["client_timeout_s"] = EVALUATE_TIMEOUT_S

        # What THIS build can actually redact, so the gateway only asks for what we can do.
        #
        # 🔴 SENT ON EVERY REQUEST, AND IT IS A CAPABILITY RATHER THAN A VERSION. The gateway
        # deploys separately from this package and can be AHEAD of it: a newer gateway naming a
        # category this build has no pattern for used to be told to scrub it, and `_scrub_pii`
        # skips a category it does not recognise -- so the values came back unredacted with no
        # error, no log and nothing the caller could see. Silent non-redaction, reported as
        # protection.
        #
        # Read from the scrubber's own map rather than restated, so it cannot go stale: adding a
        # regex there is what widens this, which is the same single source
        # `SCRUBBABLE_CATEGORIES` already gives the parity tripwire.
        #
        # Absent, an older SDK gets the legacy EMAIL/PHONE pair from the gateway -- exactly what
        # it has always been able to do. Correct whichever side deploys first, same as
        # `audit_releases_all` above.
        try:
            from .decorators import SCRUBBABLE_CATEGORIES
            payload["scrubbable_categories"] = list(SCRUBBABLE_CATEGORIES)
        except Exception:
            # Never let a capability advert break an evaluation. Omitting it is the SAFE
            # direction: the gateway falls back to the legacy pair rather than over-asking.
            pass

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                f"{self.gateway_url}/v1/evaluate", 
                json=payload,
                headers=headers,
                timeout=EVALUATE_TIMEOUT_S  # Bounds a real gateway hang while surviving cold
                                            # starts (first Next.js route compile + cold Gemini
                                            # can exceed 15s). Forwarded above so the gateway
                                            # can fit its judge inside it — see P-157.
            )
            
            # AUTH IS NOT AVAILABILITY, and the availability contract must not swallow it.
            # 401 was always a hard error; review found the new non-verdict gate below had
            # quietly annexed the rest of the class. An SSO proxy in front of the gateway
            # answering 403 {"detail":"SSO session expired"}, or a 407 from a corporate
            # proxy, is JSON that carries no verdict — so it took the availability path, and
            # under the ratified fail-OPEN default the protected tool RAN. That is strictly
            # worse than before this branch existed, where the same response hard-errored and
            # the tool did not run. Reproduced by review: a money-transfer tool executed on a
            # 403 with only a WARNING.
            #
            # These belong to a human, not to a retry: nobody's session expires their way out
            # of it and no amount of waiting fixes a bad credential. Safe to hard-error
            # because the gateway itself NEVER returns 401/403/407 (verified against every
            # response path in the gateway), so one of these can only have come from
            # something standing in front of it.
            #
            # 429 deliberately NOT here: rate limiting IS a transient capacity condition, and
            # that is exactly what the availability contract is for.
            if response.status_code == 401:
                # Unchanged wording: this string predates the class and is what an existing
                # test and anyone's log-grep expects. Widening the CLASS must not silently
                # reword the member that was already right.
                return {"status": "ERROR", "message": "Invalid AgentX API Key."}
            if response.status_code in (403, 407):
                return {"status": "ERROR",
                        "message": f"AgentX gateway request was rejected "
                                   f"(HTTP {response.status_code}). That is an authorization "
                                   f"or proxy-authentication problem, not an outage: the "
                                   f"tool was NOT run, and retrying will not help.",
                        "detail": (response.text or "")[:300]}

            # A 5xx, or ANY non-JSON body (a proxy's HTML error page, a bare
            # "Internal Server Error"), means the gateway could not return a verdict.
            # That is the SAME situation as unreachable, so it takes the SAME contract
            # instead of a hard ERROR. Previously `.json()` raised straight into the
            # generic handler below, which returns status ERROR, and the decorator turns
            # ERROR into "AgentX System Error" and DOES NOT RUN THE TOOL. So one
            # malformed field — or an ordinary cold-start 502 — silently disabled a
            # protected tool AND skipped the AGENTX_FAIL_MODE decision entirely, so the
            # default (open: run the tool, count a degraded execution) never got to apply
            # and nothing recorded that we were running unprotected. NOTE: this is NOT an
            # audit-posture issue — audit
            # deliberately covers POLICY blocks, not availability (see
            # decorators._audit_and_proceed) — it is fail-mode routing.
            # `gateway_reached` and `detail` matter and were lost in the first cut of this
            # fix. Review found two consequences. (1) decorators.py treats
            # REASONING_ENGINE_UNREACHABLE as "the gateway was never reached", so a PAYING
            # install whose gateway answers but answers badly emitted a pulse
            # byte-identical to one that never configured a gateway at all — corrupting the
            # signal that tells those two states apart. (2) dropping
            # response.text discarded the only clue that the gateway is UP and crashing,
            # which is exactly how P-21 was found in the first place. Carry both: the
            # verdict is availability, the FACTS say the server answered.
            #
            # TWO PROOF LEVELS, because one flag was being asked two different questions and
            # gave the wrong answer to one of them whichever way it was set.
            #   gateway_answered   -- SOMETHING replied at that URL. The funnel's question
            #                         ("did this install reach a gateway at all") wants this,
            #                         and a cold-start 502 answers YES, which is the whole
            #                         point of P-21.
            #   gateway_identified -- what replied was demonstrably OURS, i.e. it carried
            #                         X-AgentX-Reasoning. The precision consumers want this:
            #                         the steered-fault counter, and any advice of the form
            #                         "go read the engine's logs".
            # Review proposed gating the 5xx branch on the header outright. PROBED FIRST, and
            # the premise does not hold: the gateway's middleware stamps the header AFTER
            # `await call_next(...)`, so an HTTPException(500) keeps it but an UNHANDLED
            # exception never reaches the stamp — and an unhandled exception is precisely the
            # P-21 shape (`.strip()` on a JSON number). Gating 5xx on the header would
            # therefore have re-broken the exact case this branch was written for. Splitting
            # the two levels gets the reviewer's real point (a 502 from an ALB with no
            # backend must not fill the steered-fault counter) without that cost.
            if response.status_code >= 500:
                out = {"status": "REASONING_ENGINE_UNREACHABLE",
                       "reason": f"gateway_{response.status_code}",
                       "gateway_answered": True,
                       "detail": (response.text or "")[:300]}
                if response.headers.get("X-AgentX-Reasoning") is not None:
                    out["gateway_identified"] = True
                return out
            try:
                result = response.json()
            except ValueError:      # requests' JSONDecodeError subclasses ValueError
                # `gateway_answered` here, but ONLY if what answered is plausibly OUR
                # gateway. A 2xx/4xx with an unparseable body is the shape a corporate proxy
                # login page, a stale service returning HTML, or a plain 404 page has, and
                # none of those is a gateway. Setting the flag unconditionally traded P-21's
                # false negative for a false POSITIVE on the same signal: a developer with a
                # wrong `gateway_url` would have reported the paid-tier funnel stage as
                # reached without ever reaching a gateway. /v1/evaluate advertises
                # X-AgentX-Reasoning on every response, so the header is the cheap proof that
                # something of ours is on the other end. The 5xx branch above needs no such
                # proof: it is the cold-start / crashing-engine case P-21 was filed for, and
                # is claimed as answered on the strength of the status alone.
                out = {"status": "REASONING_ENGINE_UNREACHABLE",
                       "reason": "non_json_response",
                       "detail": (response.text or "")[:300]}
                if response.headers.get("X-AgentX-Reasoning") is not None:
                    out["gateway_answered"] = True
                    out["gateway_identified"] = True
                return out
            # THE THIRD MEMBER OF THE CLASS, and gating on the body's ENCODING is what hid
            # it. P-21 is "the gateway could not return a verdict"; that has three shapes, not
            # two — a 5xx, a body that will not parse, and a body that parses fine and is not
            # a verdict. The third is the COMMONEST misconfiguration of the three: point
            # gateway_url at the right host and the wrong path and FastAPI answers a JSON 404,
            # which parsed cleanly, carried no `status`, and fell through to the decorator as
            # a dict with nothing it recognises — so the tool was replaced by "AgentX System
            # Error", no fail-mode decision ran, and nothing was counted. Exactly the P-21
            # symptom the 5xx fix was written for, reached by a different door. Any unrelated
            # JSON API at that URL does the same.
            #
            # Every real /v1/evaluate answer carries `status` (ALLOWED / ESCALATED / …) or the
            # `error` a policy block uses, so that is the gate: a VERDICT, not an encoding.
            # Stated as one rule on purpose rather than a third special case, because a fourth
            # spelling of "not a verdict" is otherwise just a matter of time.
            if not isinstance(result, dict) or not ("status" in result or "error" in result):
                out = {"status": "REASONING_ENGINE_UNREACHABLE",
                       "reason": "non_verdict_body",
                       "detail": (response.text or "")[:300]}
                if response.headers.get("X-AgentX-Reasoning") is not None:
                    out["gateway_answered"] = True
                    out["gateway_identified"] = True
                return out
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
        except requests.exceptions.RequestException as e:
            # CLASS CLOSE, not another instance. The two handlers above name
            # two transport failures; `requests` has many more that mean the SAME thing —
            # SSLError (a proxy doing cert interception), ProxyError, TooManyRedirects,
            # ChunkedEncodingError, ContentDecodingError, RetryError. Every one of them is
            # "we could not get a verdict", and every one of them used to fall into the
            # bare `except Exception` below and come back as a hard ERROR, which the
            # decorator renders IN PLACE OF THE TOOL'S RESULT while skipping the
            # AGENTX_FAIL_MODE decision entirely. P-21 was found as one member of this
            # class (a plain-text 500); fixing only that member would have left the
            # template. RequestException is the honest boundary: everything under it is
            # the transport failing, so it is availability.
            return {"status": "REASONING_ENGINE_UNREACHABLE",
                    "reason": f"transport_{type(e).__name__.lower()}"}
        except Exception as e:
            # Deliberately still a hard ERROR: anything that is NOT a transport failure is
            # a bug in our own code (a TypeError here, a bad payload we built), and that
            # should be loud rather than silently degraded into "gateway unavailable".
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
            # 🔴 STDERR, BECAUSE STDOUT BELONGS TO THE COMMAND. These fire from a background park
            # thread at an arbitrary moment, so on stdout they land in the MIDDLE of whatever the
            # command is printing -- and `agentx audit --json` then emits a document no parser can
            # read. Exactly the rule the brand banner had to learn: a caller who asked for machine
            # output gets only the document, and a notice is never deleted for them, it is moved.
            #
            # It is also not command output by any reading. It is a diagnostic about telemetry
            # that failed while the block itself stood, which is what the sentence says.
            #
            # ⚠️ HOW IT SURFACED, because the shape is worth keeping: a suite test went red only
            # when the developer's local gateway was STOPPED and only in full-suite order. A park
            # to a gateway that is not there times out on a machine that drops rather than refuses,
            # the warning printed mid-JSON, and the completeness contract broke. The suite had been
            # green partly because a gateway happened to be running.
            if resp.status_code != 200:
                print(f"⚠️ [LOCAL KEYWORD SHIELD] Async incident park rejected "
                      f"({resp.status_code}) for receipt {receipt} — the block stood, "
                      f"but recovery for this trace won't be recorded.", file=sys.stderr)
        except Exception as e:
            print(f"⚠️ [LOCAL KEYWORD SHIELD] Async incident park failed "
                  f"({type(e).__name__}) for receipt {receipt} — the block stood, "
                  f"but recovery for this trace won't be recorded.", file=sys.stderr)

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
            # A 2xx does NOT mean anything was stored — see the same guard in cli.py and
            # BACKLOG P-41. Two of the route's three 2xx shapes carry {accepted: 0}: an
            # airgapped plane (no shared corpus off-cloud) and a batch whose rows all fail
            # the server-side allowlist. This path matters MORE than the CLI one because it
            # is automatic: it fires during ordinary SDK operation with no user command, so
            # a false success stamps the contribute leg for someone who never asked to
            # contribute. It also ADVANCES THE DELTA CURSOR, which is the worse half — a
            # cursor advanced past signals that were never stored means the next genuine
            # push silently skips them. Both effects are gated on the real count.
            if post.status_code in (200, 201, 202):
                try:
                    accepted = (post.json() or {}).get("accepted")
                except ValueError:
                    accepted = None
                # THE TRADE, stated because it is a real cost and not free (review of this
                # change): when `accepted` is falsy we neither stamp nor advance, so the SAME
                # delta is re-pulled and re-pushed on the next run. That is deliberate — an
                # unconfirmed cursor advance is the silent-skip failure this whole change
                # exists to remove — and it is BOUNDED: `last_auto_contribute` is stamped
                # BEFORE the push, so the 24h debounce applies whatever the outcome, making
                # the worst case one retry per install per day, not a loop.
                # The one shape it costs: a plane that STORES rows but omits `accepted` would
                # be re-sent the same batch daily and could accumulate duplicates. Every
                # branch of our own route returns `accepted`, so that requires a forked plane,
                # and at-least-once against a plane that will not confirm beats at-most-once
                # that silently drops. Revisit only if a partner runs such a plane.
                if accepted:
                    pulse.mark_contributed(cursor=body.get("cursor"))   # advance delta cursor + stamp the leg
        except Exception:
            pass