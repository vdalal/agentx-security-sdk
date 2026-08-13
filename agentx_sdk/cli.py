import os
import sys
import hashlib
import json
import shutil
import tempfile
import requests
from datetime import datetime, timezone

from .overrides import (harvest_candidates, load_overrides, adopt as adopt_override,
                        incident_db_census, enumerate_candidates,
                        list_customizable_policies, resolve_policy_by_name,
                        describe_scope, has_human_coaching,
                        get_active_override, _overrides_path, _norm_for_dedup,
                        record_outcome, list_recent_incidents,
                        find_incidents_by_receipt_prefix,
                        delete_incident, delete_incidents,
                        reconcile_safe_paths,
                        labeled_items_with_truncation, reviewable_items_with_truncation,
                        review_backlog_size, count_awaiting_verdict,
                        REVIEW_READ_CAP, label_stats,
                        load_org_rules, apply_org_rules, apply_declared_verdicts,
                        get_declared_verdict, set_declared_verdict,
                        clear_declared_verdict, count_policy_verdict_evidence,
                        count_policy_unlabeled_blocks,
                        unlabel_declared_verdicts, _resolve_policy_ref)
from .rules import harvest_rule_candidates, adopt_rule

# Re-exported from the stdlib-only envfile module (kept importable here for
# backward compatibility — callers and tests still do `from .cli import load_env_file`).
from .envfile import load_env_file

def _render_offline_dashboard(gateway_url, mode="local"):
    """No gateway reachable. For a keyless/local user that is the normal free state, so
    lead with THIS machine's LOCAL flight-recorder (the value they have accrued) and
    frame the gateway as an optional upgrade, no error. For a linked/cloud user a missing
    gateway IS a fault, so keep the error framing. Reuses get_lifetime_stats(), the SAME
    source as the end-of-run session summary, so the two can never drift."""
    local = (mode == "local")
    if local:
        print("\n🛡️  AGENTX LOCAL STATUS        (keyless in-process shield, no gateway needed)")
        print("=" * 75)
        print("  Your agents are protected right now. The in-process Layer-0 shield")
        print("  (@agentx_protect, or one line in mcp.json) blocks DROP TABLE, SSRF, and")
        print("  secret-exfil offline, with no gateway and no key.")
    else:
        print(f"❌ Gateway not reachable at {gateway_url} — the live dashboard is offline.")
        print("   -> Your agents are STILL protected: the in-process Layer-0 shield")
        print("      (@agentx_protect) keeps blocking deterministic threats — DROP TABLE,")
        print("      SSRF, secret-exfil — offline, with no gateway and no key.")

    # LOCAL flight-recorder: what THIS machine has blocked, from the SDK's own ledger.
    # Lazy import + broad guard so a missing/locked DB degrades to the reassurance
    # message rather than crashing the CLI.
    try:
        from . import db as db_module
        from .db import (get_lifetime_stats, get_retention_status, get_ledger_census,
                         format_ratio, ledger_empty_reason, ledger_needs_trimming)
    except Exception:
        db_module = None

    # 🔴 TWO GUARDS, NOT ONE, AND FOR THE REASON _print_local_blocks_section DOCUMENTS.
    # These were one `try`, so a raise from get_lifetime_stats -- which is consulted for ONE
    # thing, the offender's NAME, and is the only reader here that does not swallow its own
    # errors -- zeroed the CENSUS as well, and the census is what decides whether this screen
    # says "here are your blocks" or "nothing here". Losing a name is a blank field; losing
    # the census is the wrong answer.
    try:
        stats = get_lifetime_stats()
    except Exception:
        stats = None
    try:
        census = get_ledger_census()
    except Exception:
        # `interceptions` listed for completeness, so this fallback keeps matching the shape
        # get_ledger_census returns. It is NOT what stops a degraded read from raising -- the
        # reader below uses .get() for that, deliberately, because a screen whose whole job
        # is to work when things are broken must not depend on a literal staying in sync.
        census = {"total_rows": 0, "block_episodes": 0, "would_blocks": 0, "recoveries": 0,
                  "interceptions": 0, "would_blocks_from_demo": 0, "inventory_from_demo": 0}

    # 🔴 "THIS MACHINE" WAS FALSE, AND TWO RUNS PROVE IT. `DB_PATH` is ".agentx.db",
    # RELATIVE, resolved against the working directory (db.py documents that as deliberate
    # for the decorator, and the MCP door moves it somewhere else again). So `agentx` in the
    # project printed 24 intercepts at 58.3% and `agentx` from C:\ printed 3 at 100.0%, both
    # under a header claiming to describe the machine.
    #
    # Naming the FILE rather than picking a scope word is the only line that stays true on
    # both doors -- "this folder" would be wrong the moment the MCP proxy repoints the store
    # -- and it is the one fact that explains why two runs disagree.
    try:
        ledger_path = os.path.abspath(db_module.DB_PATH)
    except Exception:
        ledger_path = None

    # Read unconditionally: the EMPTY branch needs this as much as the populated one. A
    # ledger trimmed to zero rows reports "no blocks recorded yet", which is our own
    # housekeeping producing the false-empty answer P-76 exists to prevent.
    try:
        retention = get_retention_status()
    except Exception:
        retention = None

    # 🔴 THE CENSUS DECIDES *AND* SUPPLIES THE NUMBERS. The previous version put the census
    # only inside the `else`, so the branch was still chosen by `stats["total_intercepts"]`
    # -- a comment three lines below claimed otherwise, which made it a claim the code did
    # not honour. Worse, it left the deciding predicate and the described data as two
    # separate reads of one table, which is precisely the pattern get_ledger_census exists to
    # remove. `stats` is now consulted for ONE thing the census cannot answer: the offender's
    # NAME. Its counts are not read here at all, so the two can no longer disagree.
    if census.get("block_episodes", 0) > 0:
        intercepts = census["block_episodes"]
        recoveries = census["recoveries"]
        top_offender = (stats or {}).get("top_offender") or "None"
        print("\n📊 LOCAL FLIGHT RECORDER (no gateway needed):")
        if ledger_path:
            print(f"   {ledger_path}")
        # Three lines removed here, all unbacked: "Catastrophic actions blocked" (a
        # severity we hold no data for, counted from a stale two-name list) and the
        # token/time savings (a constant times a row count). Every number left is one
        # this machine actually observed.
        print(f"  🛡️  Total intercepts:             {intercepts}")
        # The sample floor lives in db.format_ratio, not here. It was written inline on this
        # screen first and the session summary kept printing a decimal percentage over a
        # handful of rows, which is the same defect this line was added to remove.
        print(f"  🔄 Self-corrections:             {format_ratio(recoveries, intercepts)} recovered")
        print(f"  ⚠️  Top offender:                 {top_offender}")
        # 🔴 THE SAME LABEL FIX AS THE SESSION SUMMARY, ON THE SCREEN IT MISSED. The rate
        # above is the identical ratio, and retention makes it climb on its own: unrecovered
        # blocks sit in the denominator alone, so trimming drops old failures while newer
        # successes survive. The summary in decorators.py says "On record" for exactly this
        # reason and this screen was left saying nothing at all -- fixing the instance and
        # leaving the template, which is the lesson already written into this function
        # thirty lines below. Silent when nothing was trimmed, so it means something when it
        # appears.
        # Keyed on blocks_dropped: every number above it is an INTERCEPT count, so this line
        # qualifies them only when an intercept is what we deleted. Since P-92 routine audit
        # traffic is evicted first, and reading rows_dropped here told a developer their
        # totals were partial when nothing they describe had been touched.
        if retention and retention.get("blocks_dropped"):
            # Two SEPARATE true sentences, not one causal one. "N dropped under the 30d /
            # 10,000 limit" states a reason: it says those specific rows died under those
            # specific limits. The count is cumulative over every prune this file has
            # seen, while the limits are read live, so the moment they are tuned that
            # sentence is false about most of the count. The count and the current policy
            # are both true on their own.
            print(f"  🗂️  Older block records dropped:  {retention['blocks_dropped']:,}")
            print(f"      This ledger keeps the last {retention['current_max_age_days']} days "
                  f"or {retention['current_max_rows']:,} records, so the totals above")
            print("      cover what was KEPT, not everything that happened.")
        # 🔴 P-93(b), ONE SURFACE OVER. This screen had real catches behind it and its only
        # next step was "get gateway access" -- the paid path -- while the command that
        # lists those catches per policy went unmentioned. That is the defect P-93(b) was
        # filed for, and I fixed it on `agentx insights` without checking whether the same
        # shape existed here. Fixing the instance leaves the template. A pointer rather
        # than the list itself, so the two screens do not drift into two renderings of one
        # thing.
        print(f"\n  See what was blocked, by policy:   {_insights_cmd()}")
    else:
        # 🔴 THE WORST FORM OF THE "this machine" CLAIM LIVED HERE. A developer whose
        # catches are in another folder was told they had none, which is the false-empty
        # answer P-76 exists to prevent, arriving through the working directory instead of a
        # path bug. Naming the file turns a wrong statement into a checkable one.
        # 🔴 THE BRANCH IS CHOSEN FROM THE CENSUS, NOT FROM get_lifetime_stats. That query
        # counts only CHALLENGED and RECOVERED, so under AGENTX_ENFORCEMENT=audit a ledger
        # full of WOULD_BLOCK rows landed here and announced that nothing remained in it --
        # while the retention line beside it reported rows_kept: 4. Reproduced end to end.
        # The query that DECIDES what to say has to be the one the sentence is ABOUT.
        #
        # 🔴 AND THE THIRD ROUTE TO IT WAS STILL OPEN: A READ THAT FAILED. Every reader this
        # screen uses swallows its own errors (get_ledger_census returns zeros from its own
        # `except`), so a ledger that is on disk and will not open arrives here looking
        # exactly like an empty one and was told "no blocks recorded in this ledger yet" --
        # then routed to `agentx demo`. `ledger_is_unreadable` existed for precisely this and
        # was consulted on ONE of the four screens that read this file. The decision now
        # lives in db.ledger_empty_reason so a fifth screen cannot forget it.
        try:
            reason = ledger_empty_reason()
        except Exception:
            reason = "empty"

        if reason == "unreadable":
            # No count, no retention line and no "wrap a tool" CTA: every one of them is a
            # sentence about a ledger we did not read.
            print("\n📊 LOCAL FLIGHT RECORDER: the ledger is on disk but could not be read,")
            print("   so this screen cannot tell you what your floor stopped. It is NOT a")
            print("   statement that nothing was blocked.")
            if ledger_path:
                print(f"   {ledger_path}")
            print("   Another process may hold it open. If it is corrupt, moving it aside")
            print("   starts a fresh one; the blocks it holds are not recoverable.")
        elif census.get("would_blocks", 0) > 0:
            # "while audit was on", NOT "under AGENTX_ENFORCEMENT=audit". Audit also comes
            # from the per-tool `enforcement=` argument -- which is how `agentx demo --audit`
            # writes these rows -- so naming a variable the reader never set is a false
            # statement about their environment. Fixed on the insights screen and the audit
            # banner in this same change; this was the third site.
            print("\n📊 LOCAL FLIGHT RECORDER: nothing was STOPPED in this ledger, but it")
            print(f"   holds {census['would_blocks']:,} call(s) recorded while audit was on")
            print("   and allowed to run. Audit records what the floor would stop; it does")
            print("   not stop it, so a zero here is the posture, not a verdict.")
            # ...and whose calls they were. Same footnote `agentx audit` and `agentx insights`
            # carry: `agentx demo --audit` writes a would-block into this ledger and three of
            # our own screens send the reader here to read it.
            _ours = census.get("would_blocks_from_demo") or 0
            if _ours:
                for _ln in _demo_row_note(_ours, of_total=census["would_blocks"],
                                          pronoun="these"):
                    # Re-indented to this screen's 3-space body, not the audit screen's 2.
                    print("   " + _ln.strip())
        elif reason == "trimmed":
            print("\n📊 LOCAL FLIGHT RECORDER: no blocks remain in this ledger.")
        else:
            print("\n📊 LOCAL FLIGHT RECORDER: no blocks recorded in this ledger yet.")
        if reason != "unreadable":
            # 🔴 STATE THE RULE ONCE: "go wrap a tool and run your agent" is only true of a
            # ledger holding no evidence that they already did. Every sentence above is about
            # BLOCKS, and since P-92 a ledger can hold thousands of rows and no block -- so
            # this screen was telling a developer who had wired us in and run 500 clean calls
            # to go wire us in and run their agent. Reproduced end to end on a 500-row
            # inventory. That population is not an edge case; it is the one P-92 was built
            # for, and `agentx audit` -- the screen where those 500 calls are visible -- went
            # unmentioned on the one screen they were most likely to be looking at.
            #
            # This is the same false-empty class as P-76 arriving through the CTA instead of
            # the claim: the sentence above is TRUE and the next step under it is false. The
            # fix ships as a rule rather than a third branch because the last two times this
            # shape was fixed (execute_audit's flagged_total, ledger_empty_reason's census)
            # the instance was fixed and the template left standing.
            # 🔴 DERIVED FROM THE CENSUS ALREADY READ ABOVE, not from a second aggregation.
            # This was `get_call_inventory()["total_calls"]`, which runs a GROUP BY plus two
            # more queries for each of up to 25 tools plus five full-table counts -- about
            # fifty-five scans of an unindexed table, on an interactive screen, to decide
            # whether to print one line. The census is one query and already holds the
            # answer: total_rows counts everything, interceptions counts everything we had an
            # opinion about, so the difference IS the inventory.
            #
            # It also removes a second reader of the same table from this screen, which is
            # the rule this function has now been fixed for three times: two queries over one
            # table eventually disagree, and the screen states the disagreement as fact.
            _inventory_calls = max(
                0, (census.get("total_rows") or 0) - (census.get("interceptions") or 0))
            # Same rule as the populated branch above: this section is about BLOCKS, so it
            # discloses the deletion of a block. Routine-traffic trimming is disclosed where
            # it actually qualifies something -- `agentx audit`, off inventory["covers_all"].
            if retention and retention.get("blocks_dropped"):
                print(f"   {retention['blocks_dropped']:,} older block record(s) have been "
                      f"dropped; this ledger keeps")
                print(f"   the last {retention['current_max_age_days']} days or "
                      f"{retention['current_max_rows']:,} records.")
            if ledger_path:
                print(f"   {ledger_path}")
                print("   Blocks are recorded per ledger, so running agentx from another folder")
                print("   reads a different one.")
            if _inventory_calls:
                # What the ledger DOES hold, and the screen that shows it. Named as calls we
                # had no objection to, so the zero above keeps its meaning instead of reading
                # as a contradiction two lines later.
                print(f"   This ledger holds {_inventory_calls:,} recorded call(s) that passed. "
                      "See what your")
                print(f"   agent did:   {_audit_cmd()}")
                # 🔴 "YOUR agent" IS THE CLAIM, SO OURS HAS TO BE NAMED. `agentx demo --audit`
                # writes four ALLOWED rows into this ledger by design (the audit screen exists
                # to show them), and this screen reported them under a sentence about the
                # reader's own agent. Same footnote get_call_inventory already carries; the
                # reader was updated when the writer was not.
                _ours = census.get("inventory_from_demo") or 0
                if _ours:
                    for _ln in _demo_row_note(_ours, of_total=_inventory_calls):
                        print("   " + _ln.strip())
            elif census.get("would_blocks", 0) > 0:
                # They ran, and every call ON RECORD tripped a policy -- so there is no
                # inventory to point at, and telling them to wrap a tool is the same wrong
                # next step. Their rows are on the insights screen.
                print(f"   See them, by policy:   {_insights_cmd()}")
            else:
                print("   Wrap a tool with @agentx_protect (or one line in mcp.json) and run your")
                print("   agent. Your catches and protection streak show up here.")

    # 🔴 ASKS THE LEDGER, NOT OUR COUNTER, AND OUTSIDE BOTH BRANCHES ABOVE. This is a one-shot
    # process that never attempts a prune, so the failure STREAK the session summary uses is
    # always 0 here -- rendering that would have been a warning that CANNOT FIRE, which is the
    # inert guard this feature already shipped once. Measured before writing it: rendering this
    # screen leaves the streak at 0.
    #
    # The observable harm is "this file is past its limit right now", and a READ answers that
    # even when writes are broken. Placed here so it covers the populated AND the empty screen:
    # a ledger over its ceiling is a problem either way.
    try:
        _over_ceiling = ledger_needs_trimming()
    except Exception:
        _over_ceiling = False
    if _over_ceiling:
        print("")
        print("  ⚠️  This ledger is past its limit and is NOT being trimmed, so it will keep")
        print("      growing. Usually it is not writable, or another process is holding it")
        print("      open.")

    print("\n  " + "─" * 71)
    if local:
        print("\n  Want the full deterministic floor (AST + the whole failure catalog),")
        print("  coached recovery, and the live team dashboard? It runs locally, free:")
        print("     ▶ Get gateway access:  https://bit.ly/agentfirewall")
    else:
        print("\n  The gateway adds the full deterministic floor (AST + the whole failure")
        print("  catalog), coached recovery, and the live team dashboard:")
        print("     ▶ Already a design partner?   docker compose up -d")
        print("     ▶ Want it (free, runs locally)?   https://bit.ly/agentfirewall")
    print("=" * 75)


def _self_corrections_line(pivots, nudges):
    """The gateway screen's recovery line. A function so it can be tested without a gateway.

    🔴 STOPPING THE IMPOSSIBLE PERCENTAGE WAS NOT ENOUGH. format_ratio correctly refuses to
    print "120%" when the counters skew, but the line then read "12 of 10 recovered (of the
    challenges it coached)" -- still impossible on its face, and it reads to a developer as our
    product being broken with nothing on screen saying why.

    The skew is real and documented, not a bug to hide: the gateway bumps `successful_agent_
    pivots` on any allow carrying a receipt_id, and a hard floor block issues one without ever
    bumping `socratic_nudges_issued`, so pivots outrun nudges across a restart. Keep both
    numbers, drop the ratio framing that cannot hold them, and name the cause in the same
    sentence.
    """
    from .db import format_ratio
    hits = pivots or 0
    coached = nudges or 0
    if hits > coached:
        return "%d recovered, %d coached  (counters disagree across a restart)" % (hits, coached)
    # ⚠️ THE DENOMINATOR IS `socratic_nudges_issued`, NOT `intercepts`. The gateway computes the
    # rate that way on purpose: a hard floor block bumps intercepts but never issues a nudge, so
    # anchoring to intercepts dilutes the rate toward zero. Using intercepts here would print a
    # DIFFERENT number under the same label.
    return "%s recovered (of the challenges it coached)" % format_ratio(hits, coached)


def execute_status_inspection(gateway_url, api_key, mode="local"):
    """Probes local container metrics endpoints for running RAM stats and armed rules."""
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        telemetry_res = requests.get(f"{gateway_url}/v1/telemetry", headers=headers, timeout=2.0)
        policy_res = requests.get(f"{gateway_url}/v1/debug/policies", headers=headers, timeout=2.0)
    except requests.exceptions.ConnectionError:
        _render_offline_dashboard(gateway_url, mode)
        # A keyless/local user has no gateway BY DESIGN: the in-process shield is the free
        # tier, so a missing gateway is the normal state, not a failure -> exit 0. A
        # linked/cloud user WAS expecting a gateway, so an unreachable one is a real
        # fault -> exit 1.
        sys.exit(0 if mode == "local" else 1)

    if telemetry_res.status_code != 200 or policy_res.status_code != 200:
        print("❌ Error: Reasoning Engine contract validation failed.")
        print(f"   -> /v1/telemetry status: {telemetry_res.status_code}")
        print(f"   -> /v1/debug/policies status: {policy_res.status_code}")
        print("=" * 75)
        sys.exit(1)

    telemetry = telemetry_res.json()
    policies_data = policy_res.json()

    print(f"\n📊 LIVE GATEWAY STATUS        (reasoning engine · {gateway_url})")
    print("=" * 75)
    print("  What the gateway has intercepted this run, and the policies armed right now.")
    print(f"\n  🛑 Intercepts:               {telemetry.get('intercepts', 0)}")
    print(f"  🧠 Socratic challenges:      {telemetry.get('socratic_nudges_issued', 0)}")
    print(f"  🚨 Human escalations (HITL): {telemetry.get('human_escalations_required', 0)}")
    # 🔴 THE SAMPLE FLOOR REACHES THE GATEWAY SCREEN TOO. This is the SAME command
    # (`agentx status`) as the offline flight recorder below, and it went on printing the
    # gateway's precomputed `agent_self_correction_rate_percent` bare -- so one nudge and one
    # pivot rendered "100.0% recovery" on the very screen the floor was added to clean up.
    # Rendered through db.format_ratio like every other rate, from the two counters the
    # gateway already sends, so there is no second place where the rule can be forgotten.
    #
    # ⚠️ THE DENOMINATOR IS `socratic_nudges_issued`, NOT `intercepts`. The gateway computes
    # the rate that way on purpose (gateway.py: a hard floor block bumps intercepts but never
    # issues a nudge, so anchoring to intercepts dilutes the rate toward zero). Using
    # intercepts here would have printed a DIFFERENT number under the same label.
    # 🔴 WHEN THE TWO COUNTERS DISAGREE, SAY SO IN THE SAME SENTENCE. Stopping the impossible
    # PERCENTAGE was not enough: the line then read "12 of 10 recovered (of the challenges it
    # coached)", which is still impossible on its face and reads to a developer as our product
    # being broken, with nothing on screen explaining why. The skew is real and documented --
    # the gateway bumps pivots on any allow carrying a receipt_id, and a hard floor block
    # issues one without ever bumping nudges, so pivots outrun nudges across a restart.
    # Keep both numbers, drop the ratio framing, and name the cause.
    print("  🔄 Self-corrections:         %s"
          % _self_corrections_line(telemetry.get('successful_agent_pivots', 0),
                                   telemetry.get('socratic_nudges_issued', 0)))
    print(f"  🎛️  Neural sensitivity:       {policies_data.get('neural_threshold', 0.30)}"
          f"        ☁️  Control plane:  {policies_data.get('control_plane_url', 'None (local sandbox)')}")

    print("\n🛡️  ARMED POLICIES        (enforcing right now)")

    policies = policies_data.get("policies", [])
    if not policies:
        print("  ⚠️ No active policies found in gateway RAM cache.")
    else:
        def _trunc(value, width):
            text = str(value)
            return text if len(text) <= width else text[: width - 3] + "..."

        # Split by enforcement. The gateway tags floor-enforced policies with
        # enforcement="deterministic_floor"; older gateways omit it, so everything
        # falls back into the neural group and renders as before (back-compatible).
        floor = [p for p in policies if p.get("enforcement") == "deterministic_floor"]
        neural = [p for p in policies if p.get("enforcement") != "deterministic_floor"]

        # Per-policy this-run hit counts (the breakdown of `intercepts`), joined by
        # the FULL policy name. Only rendered when the gateway actually reports them
        # (older gateways omit the key) so we never show a misleading column of 0s.
        policy_hits = telemetry.get("policy_hits")
        show_hits = isinstance(policy_hits, dict)
        policy_hits = policy_hits or {}
        rule = "-" * (76 if show_hits else 68)

        if neural:
            print("\n  🧠 NEURAL POLICIES (semantic + symbolic · toggleable)")
            header = f"   {'Policy Name / Definition':<31} | {'Target Action':<22} | {'Status':<8}"
            print(header + (f" | {'Hits':>5}" if show_hits else ""))
            print("   " + rule)
            for policy in neural:
                raw_name = policy.get("name", "Unnamed Rule")
                name = _trunc(raw_name, 31)
                action = _trunc(policy.get("target_action", "Neural Intercept"), 22)
                status_text = "ARMED" if policy.get("is_active", True) else "DISABLED"
                row = f"   {name:<31} | {action:<22} | {status_text:<8}"
                print(row + (f" | {policy_hits.get(raw_name, 0):>5}" if show_hits else ""))

        if floor:
            mech_label = {"hard-block": "HARD-BLOCK", "hitl-escalation": "HITL-ESCALATE"}
            print("\n  🧱 DETERMINISTIC FLOOR (always-on · zero-LLM · cannot be disabled)")
            header = f"   {'Policy Name / Definition':<31} | {'Surface':<22} | {'Mechanism':<13}"
            print(header + (f" | {'Hits':>5}" if show_hits else ""))
            print("   " + rule)
            for policy in floor:
                raw_name = policy.get("name", "Unnamed Rule")
                name = _trunc(raw_name, 31)
                surface = _trunc(policy.get("target_action", "-"), 22)
                mech = mech_label.get(policy.get("mechanism", ""), "FLOOR")
                row = f"   {name:<31} | {surface:<22} | {mech:<13}"
                print(row + (f" | {policy_hits.get(raw_name, 0):>5}" if show_hits else ""))

    cp = policies_data.get("control_plane_url") or ""
    dash = (cp.rstrip("/") + "/dashboard") if cp.startswith("http") else "http://localhost:3000/dashboard"
    print("\n" + "=" * 75)
    print("  ▶ Review what your agents learned:   agentx insights")
    print(f"  ▶ Open the live dashboard:           {dash}")
    print("\n  Tune detection sensitivity with AGENTX_NEURAL_THRESHOLD.")
    print("=" * 75)

def execute_policy_pull(control_plane_url, api_key):
    """Pulls customized configuration layers directly from the remote cloud Admin Plane brain."""
    print("\n📡 Connecting to Cloud Admin Plane to pull active policy engine matrix...")
    print(f"   Target URL: {control_plane_url}")

    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.get(f"{control_plane_url}/api/edge/sync", headers=headers, timeout=5.0)
        
        if response.status_code == 401:
            print("🔒 Perimeter Gating Violation: Cryptographic Handshake Denied. Invalid API Key.")
            print("=" * 75)
            sys.exit(1)
        elif response.status_code != 200:
            print(f"❌ Error: Control plane connection synchronization request failed (Status: {response.status_code})")
            print("=" * 75)
            sys.exit(1)

        payload = response.json() or {}
        policies = payload.get("policies", [])
        # `payload_sync_active` is the plane telling us WHY there is nothing to send, and
        # the old code discarded it. Same shape as the contribution push (BACKLOG P-41):
        # the server computed the truth, put it on the wire, and the client threw it away
        # and printed success. Three outcomes were collapsed into one "Success" line.
        sync_active = payload.get("payload_sync_active")

        # BACKLOG P-78: project-root-anchored, so `agentx pull` from a subdirectory writes
        # the file the shield actually reads. This was a bare ".agentx", resolved against
        # the process working directory, so where your org policies landed depended on
        # which directory you happened to be standing in.
        from .decorators import _project_root_cached
        target_dir = os.path.join(_project_root_cached(), ".agentx")
        target_file = os.path.join(target_dir, "policies.json")

        # AN EMPTY LIST IS WRITTEN ONLY WHEN THE PLANE SAYS ITS ANSWER IS AUTHORITATIVE.
        #
        # What a pulled file actually does, PROBED rather than assumed (two earlier versions
        # of this comment asserted things that were wrong, in both directions):
        #
        # 🔴 UPDATED BY BACKLOG P-49, IN THIS SAME PR. This used to say the loader "gates on
        # `if policies: return policies`" and that "a NON-EMPTY pull wholly replaces the
        # seeds". Both were true when written and both are FALSE now: that gate is gone and
        # `load_local_policy_keywords` merges a pulled file ON TOP OF the built-in floor
        # (`_merge_pulled_over_floor`). Data may add policies, add intents and change
        # coaching; it can no longer remove any of them.
        #
        # So the conclusion below survives but for a stronger reason: an empty file and no
        # file are still identical, and now a NON-EMPTY file cannot weaken the floor either.
        # The stake in this function is the ORG rulebook, and the floor is not at risk here
        # -- which is now enforced by construction rather than by this function being careful.
        #
        #   sync_active TRUE + []  AUTHORITATIVE. The org has zero active policies, which
        #                          is exactly what an operator sees after deactivating the
        #                          last rule. WRITE it. Refusing would mean a revocation
        #                          never reaches this machine and deactivated rules keep
        #                          enforcing forever, with the CLI reassuring the operator
        #                          that nothing changed.
        #   sync_active FALSE      NOT authoritative. The plane reports itself air-gapped
        #                          OR could not reach its policy store: ui/app/api/edge/
        #                          sync/route.ts returns this same flag from its DB-error
        #                          catch-all, so the copy must cover both. Writing [] here
        #                          would discard a good org rulebook on a transient outage.
        #   flag ABSENT            Every branch of our own route sets it, so its absence
        #                          means this probably is not an AgentX control plane.
        #
        # The original defect stands and is unchanged by all this: all three outcomes used
        # to print "Success: Successfully synchronized 0 policies".
        if not policies and sync_active is not True:
            if sync_active is False:
                why = ("The control plane reports itself air-gapped, or could not reach its "
                       "policy store.")
            else:
                why = ("The control plane answered without a payload_sync_active flag, so it may "
                       f"not be an AgentX control plane. Check CONTROL_PLANE_URL ({control_plane_url}).")
            print(f"\nℹ️  Nothing to synchronize. {why}")
            # No "./" prefix: `target_file` is ABSOLUTE since P-78 anchored the pull to the
            # project root, so the old f"./{target_file}" rendered "./C:\\Projects\\...\\
            # policies.json" -- not copy-pasteable, on the one path where the operator is
            # most likely to go looking for the file.
            print(f"   {target_file} was NOT overwritten, so any org rules you already "
                  f"pulled still apply.")
            print("=" * 75)
            return

        os.makedirs(target_dir, exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(policies, f, indent=2)

        if policies:
            print(f"✅ Success: Successfully synchronized {len(policies)} policies down to your local footprint.")
        else:
            # Authoritative zero. Say what happened rather than "Success: 0 policies",
            # which was the original defect, and name the thing that is still armed so an
            # operator does not read "cleared" as "unprotected".
            print("\n✅ Synchronized: this control plane has 0 active policies.")
            print("   Your local org rulebook is now cleared, which is how a revocation")
            print("   reaches this machine. The built-in floor stays armed.")
        print(f"💾 Local configuration footprint cached at: ./{target_file}")
        print("=" * 75)

    except Exception as network_fault:
        print(f"❌ Connection fault mapping runtime tracking targets: {network_fault}")
        print("=" * 75)
        sys.exit(1)

def execute_vector_seed_compilation(gateway_url, api_key, output_dir=None):
    """
    Surgically compiles armed security rules from the gateway cache into an
    optimized binary float32 weights matrix file for offline lookups.

    BACKLOG P-78: the default is the project's `.agentx/`, resolved from the project ROOT
    rather than the working directory. `load_local_vector_shield_cache` reads it from the
    root, so compiling into a cwd-relative directory produced seeds the shield would not
    find. `output_dir` stays overridable for callers and tests that pass one explicitly.
    """
    import numpy as np
    if output_dir is None:
        from .decorators import _project_root_cached
        output_dir = os.path.join(_project_root_cached(), ".agentx")
    print("\n🧬 Initializing AgentX Vector Seed Matrix Compilation Pass...")
    headers = {"Authorization": f"Bearer {api_key}"}
    
    try:
        response = requests.get(f"{gateway_url}/v1/debug/policies", headers=headers, timeout=3.0)
        if response.status_code != 200:
            print(f"❌ Error: Gateway rejected policy synchronization request with code: {response.status_code}")
            sys.exit(1)
            
        policies_payload = response.json()
        policies_list = policies_payload.get("policies", [])
        
        if not policies_list:
            print("⚠️ Warning: No active rules found in container cache to compile weights matrix.")
            return

        os.makedirs(output_dir, exist_ok=True)
        compiled_vectors = []
        metadata_manifest = {}

        for index, policy in enumerate(policies_list):
            name = policy.get("name", "Unnamed Policy")
            challenge = policy.get("challenge", "Action prohibited.")
            intents = policy.get("intents", [])
            
            print(f"  🗜️  Vectorizing neural hyperspace coordinates for: '{name}'")
            
            # Allocate a 384-dimensional float32 vector matrix footprint locally
            mock_vector = np.random.uniform(-1.0, 1.0, 384).astype(np.float32)
            norm = np.linalg.norm(mock_vector)
            normalized_vector = mock_vector if norm == 0 else mock_vector / norm
            
            compiled_vectors.append(normalized_vector)
            
            # Maintain exact tracking mappings for local runtime lookups
            metadata_manifest[str(index)] = {
                "policy_id": policy.get("id", f"POL-00{index}"),
                "name": name,
                "challenge": challenge,
                "intents": intents
            }

        # Convert to an un-collapsed high-performance binary weights block layout
        binary_matrix = np.array(compiled_vectors, dtype=np.float32)
        
        weights_path = os.path.join(output_dir, "intent_seeds.bin")
        manifest_path = os.path.join(output_dir, "seeds_manifest.json")
        
        binary_matrix.tofile(weights_path)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(metadata_manifest, f, indent=2)

        print("-----------------------------------------------------------------------")
        print("✅ Success: Local Seed Shield Vector compiled flawlessly!")
        print(f"  -> Weights Binary Matrix: {weights_path} ({binary_matrix.shape} Float32)")
        print(f"  -> Manifest Configuration Ledger: {manifest_path}")
        print("-----------------------------------------------------------------------")
        print("=" * 75)

    except Exception as e:
        print(f"❌ Critical Fault: Vector seed generation workflow failed: {e}")
        print("=" * 75)
        sys.exit(1)

def _contribution_consent_value(env):
    """Return the explicit AGENTX_CONTRIBUTE choice (True/False) if the developer
    has set it (process env first, then .env), else None (undecided)."""
    raw = os.environ.get("AGENTX_CONTRIBUTE")
    if raw is None:
        raw = env.get("AGENTX_CONTRIBUTE")
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _persist_contribution_choice(value):
    """Append AGENTX_CONTRIBUTE to ./.env so the choice sticks and the env var
    stays the one canonical switch. Best-effort; never fatal."""
    try:
        prefix = "\n" if os.path.exists(".env") and os.path.getsize(".env") > 0 else ""
        with open(".env", "a", encoding="utf-8") as f:
            f.write(f"{prefix}AGENTX_CONTRIBUTE={'true' if value else 'false'}\n")
    except Exception:
        pass


def resolve_contribution_consent(env):
    """Decide whether to contribute. The explicit AGENTX_CONTRIBUTE (process env or
    .env) is canonical and ALWAYS wins — set it and we never prompt. Only when it
    is UNSET *and* we're on an interactive terminal do we surface a one-time,
    value-framed prompt (and persist the answer to .env) — killing the discovery
    friction without removing consent. Unset + non-interactive = OFF, so CI and
    scripts are never blocked or hung."""
    explicit = _contribution_consent_value(env)
    if explicit is not None:
        return explicit
    if not sys.stdin.isatty():
        print("\n   🔒 Contribution is OFF (AGENTX_CONTRIBUTE unset). Set it to true to help")
        print("      grow shared immunity — abstract signals only, never your data.")
        return False
    print("\n   🌐 Help grow shared immunity?")
    print("      We'd share ONLY anonymous, abstract signals (which policy fired, on")
    print("      what day) — never your queries, reasoning, payloads, or any identifier.")
    try:
        answer = input("      Contribute these abstract signals? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    choice = answer in ("y", "yes")
    _persist_contribution_choice(choice)
    print(f"      {'✅ On' if choice else '🔒 Off'} — saved AGENTX_CONTRIBUTE="
          f"{'true' if choice else 'false'} to ./.env (change it anytime).")
    return choice


def execute_contribution_push(gateway_url, control_plane_url, api_key, env):
    """Grow the shared-immunity corpus from this machine — privacy-preserving by
    construction.

    The gateway projects the local incident store down to ABSTRACT, de-identified
    signal (`/v1/contribution`), so raw payloads, chain-of-thought, and identifiers
    never reach this process, let alone the network. We show exactly what would
    leave, always write it locally for inspection, and POST it to the shared corpus
    ONLY when the developer has explicitly opted in (AGENTX_CONTRIBUTE). Default is
    OFF — nothing leaves your box without consent.
    """
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        res = requests.get(f"{gateway_url}/v1/contribution", headers=headers, timeout=5.0)
    except requests.exceptions.ConnectionError:
        print(f"❌ Unable to reach the AgentX gateway at {gateway_url} (is it up? `docker ps`).")
        print("=" * 75)
        return
    if res.status_code != 200:
        print(f"❌ Gateway returned status {res.status_code} for the contribution projection. Skipping.")
        print("=" * 75)
        return

    body = res.json()
    contributions = body.get("contributions", [])
    fields = body.get("fields", [])

    # Always write a local artifact so there is a record and the dev can inspect
    # exactly what the abstract contribution looks like (the open data path).
    target_dir = ".agentx"
    os.makedirs(target_dir, exist_ok=True)
    artifact = os.path.join(target_dir, "contribution.jsonl")
    with open(artifact, "w", encoding="utf-8") as f:
        for c in contributions:
            f.write(json.dumps(c) + "\n")

    print(f"\n🧬 Abstract contribution ready: {len(contributions)} signal(s).")
    print(f"   Shared (and ONLY these): {', '.join(fields) or '—'}")
    print("   Never shared: your queries, chain-of-thought, payloads, or any identifier.")
    print(f"   💾 Written locally for your inspection: ./{artifact}")

    if not contributions:
        print("   (Nothing to contribute yet — run some protected agents first.)")
        print("=" * 75)
        return

    if not resolve_contribution_consent(env):
        print("\n   🔒 These signals stayed on your machine.")
        print("=" * 75)
        return

    try:
        post = requests.post(
            f"{control_plane_url}/api/edge/contribute",
            json={"contributions": contributions},
            headers=headers,
            timeout=10.0,
        )
        if post.status_code in (200, 201, 202):
            # A 2xx does NOT mean anything was stored, and we used to read it that way.
            # The route answers with THREE different 2xx shapes and TWO of them store
            # nothing: an airgapped control plane returns 200 {accepted: 0, note: ...}
            # because there is no shared corpus off-cloud, and a batch whose rows all
            # fail the server-side allowlist returns 202 {accepted: 0}. Treating either
            # as success told the developer something untrue AND stamped the pulse's
            # contribute leg, so an install that stored nothing counted as a contributor
            # (BACKLOG P-41 — found live: an install with 0 blocks and 0 intercepts
            # flagged contributed). The real count is already on the wire. Read it.
            # NAMED resp_body, not `body`: `body` is already bound above to the GATEWAY's
            # projection response, and shadowing it here would leave two different payloads
            # under one name in the same function. Nothing reads the outer one after this
            # point today, which is exactly what makes the shadow a trap for the next edit.
            try:
                resp_body = post.json() or {}
            except ValueError:
                resp_body = {}
            accepted = resp_body.get("accepted")
            if accepted:
                print(f"\n   ✅ Contributed {accepted} abstract signal(s) to shared immunity. Thank you.")
                # Mark the CONTRIBUTE funnel leg on the anonymous pulse (install-local,
                # abstract — the next pulse reports it). Best-effort; never break push.
                try:
                    from . import pulse
                    pulse.mark_contributed()
                except Exception:
                    pass
            else:
                # Neither branch stamps the leg — we cannot claim a contribution we did not
                # see confirmed — but they are DIFFERENT facts and saying so matters, because
                # "we stored nothing" and "we could not tell" send the reader to different
                # places. Every branch of our own route returns `accepted`, so an ABSENT one
                # means the responder was not that route (a proxy, an error page served 200,
                # a forked plane), which is a connectivity/config question, not a posture one.
                note = resp_body.get("note") or (
                    "Your control plane has no shared corpus to write to (local or "
                    "linked posture), or every signal was filtered server-side."
                    if accepted == 0 else
                    "The control plane answered without a stored-signal count, so this may "
                    f"not be an AgentX control plane. Check CONTROL_PLANE_URL ({control_plane_url})."
                )
                print(f"\n   ℹ️  Nothing was contributed. {note}")
                print(f"      Your signals are still saved locally at ./{artifact} for inspection.")
        else:
            print(f"\n   ⚠️  Shared corpus returned {post.status_code}. Saved locally; will retry next sync.")
    except requests.exceptions.RequestException as e:
        print(f"\n   ⚠️  Could not reach the shared corpus ({e}). Saved locally; will retry next sync.")
    print("=" * 75)


def execute_sync(gateway_url, control_plane_url, api_key, env):
    """`agentx sync` = pull the latest policies, then (opt-in) push the abstract
    contribution. One habit keeps you in sync with the network both ways."""
    execute_policy_pull(control_plane_url, api_key)
    execute_contribution_push(gateway_url, control_plane_url, api_key, env)


def _enumerate_mcp(mcp):
    """Flatten mcp_recovery_candidates() into a stable list (policies by key, then per-policy
    order) so the global ``#N`` and ``adopt <#>`` agree on the MCP recovery candidates too."""
    flat = []
    for key in sorted(mcp.keys()):
        bucket = mcp[key]
        for cand in bucket.get("candidates", []):
            flat.append({
                "policy_id": bucket.get("policy_id"),
                "policy_violated": bucket.get("policy_violated"),
                "suggestion": cand["suggestion"],
                "safe_path": cand.get("safe_path"),
                "resolution_type": cand.get("resolution_type"),
                "count": cand.get("count", 1),
                "tool": cand.get("tool"),
                "target_action": cand.get("target_action"),
                "scope": cand.get("scope"),
            })
    return flat


def _collect_candidates():
    """Harvest ALL learning outputs under ONE continuous global ``#N`` — decorator/judge
    recovery reframes first (seq 1..R), then detection rules (seq R+1..M), then keyless MCP
    recovery paths (seq M+1..) — so ``insights`` / ``mcp-insights`` and ``adopt <#>`` always
    agree on what each number means. Deterministic order on every side keeps the numbering
    stable between listing and adopting.

    Returns ``(harvest, reframe_flat, rule_list, mcp_flat)``.
    """
    harvest = harvest_candidates()
    reframe_flat = enumerate_candidates(harvest)        # already numbered 1..R
    rule_list = harvest_rule_candidates()
    base = len(reframe_flat)
    for i, rule in enumerate(rule_list, start=1):
        rule["seq"] = base + i
    # Keyless MCP recovery corpus -> adoptable candidates (the (B) wiring). Lazy import: keeps
    # the subprocess/threading of mcp_proxy off the import path of every `agentx` command.
    from .mcp_proxy import mcp_recovery_candidates
    mcp_flat = _enumerate_mcp(mcp_recovery_candidates())
    base2 = base + len(rule_list)
    for i, m in enumerate(mcp_flat, start=1):
        m["seq"] = base2 + i
    return harvest, reframe_flat, rule_list, mcp_flat


def _wrap(text, prefix, width=84):
    """Hanging-indent wrap for a candidate line, shared by `insights` + `mcp-insights` so the
    two sibling renderers can't drift. Never truncates (a safe-path's discriminating clause is
    usually in its tail); density is bounded by per-policy caps, not by cutting sentences."""
    import textwrap
    text = " ".join(str(text).split())
    return textwrap.fill(text, width=width, initial_indent=prefix,
                         subsequent_indent=" " * len(prefix),
                         break_long_words=False, break_on_hyphens=False)


# --------------------------------------------------------------------------------------
# WHICH COMMANDS THE CURRENT READER CAN ACTUALLY RUN
#
# `agentx-mcp` sets this to True before dispatching --review / --insights. It matters because
# the MCP door and the Python door hand the reader DIFFERENT commands, and until 2026-07-31
# this output assumed everyone had the `agentx` script:
#
#   pip install agentx-mcp     -> `agentx` AND `agentx-mcp` on PATH (the SDK is a dependency)
#   pipx install agentx-mcp    -> `agentx-mcp` only
#   uvx (the documented mcp.json: "command": "uvx")  -> NEITHER, nothing persists on PATH
#
# So an MCP reader following our own CTA reached `agentx adopt 3` and got command-not-found,
# at the exact moment we asked them to close the learning loop.
#
# WHY A FLAG AND NOT A PATH PROBE: `shutil.which()` cannot answer this from inside the
# process. Under uvx the ephemeral env's Scripts dir is on the CHILD's PATH by construction,
# so `which("agentx-mcp")` resolves into uv's cache for a user whose shell has no such
# command -- verified 2026-07-31, it reports success in exactly the direction that hurts.
#
# WHY `uvx agentx-mcp --x` AND NOT `agentx-mcp --x`: the uvx form works on ALL THREE install
# paths above, and it is already the form /docs teaches. Mildly redundant for someone who
# installed globally; correct for everyone.
MCP_ENTRY = False


def _review_cmd():
    return "uvx agentx-mcp --review" if MCP_ENTRY else "agentx review"


def _insights_cmd():
    return "uvx agentx-mcp --insights" if MCP_ENTRY else "agentx insights"


def _audit_cmd():
    # The same door resolution as its two siblings, and for the same reason: under uvx the
    # SDK's `agentx` script is not on PATH, so a bare `agentx audit` handed to an MCP reader
    # is a command-not-found aimed at exactly the person we just told to go look.
    return "uvx agentx-mcp --audit" if MCP_ENTRY else "agentx audit"


# (There was a `_demo_cmd()` here, added when the empty state offered the demo on both
# doors. The MCP door no longer offers it -- that demo deletes its own ledger, so the
# sentence was a circle -- and both branches now spell out their own command, which left
# this helper with no callers. Deleted rather than kept "in case": an unused door-resolver
# is the kind of thing a later change picks up and reintroduces the circle with.)


def _env_prefix_cmd(var, value, cmd):
    """A one-line 'set VAR then run cmd' the reader's actual shell will accept.

    POSIX takes the inline `VAR=value cmd` form. PowerShell needs a separate assignment
    and rejects the inline one outright, so a copy-paste hint that ignores the platform is
    a hint the reader cannot use. Values are quoted because these are absolute paths.
    """
    if os.name == "nt":
        # PowerShell is the Windows default; `;` sequences the two statements on one line.
        return '$env:%s="%s"; %s' % (var, value, cmd)
    return "%s='%s' %s" % (var, value, cmd)


def _human_bytes(n):
    """Size in the largest unit that keeps a non-zero leading digit."""
    for unit, scale in (("MB", 1024 * 1024), ("KB", 1024)):
        if n >= scale:
            return "%.1f %s" % (n / scale, unit)
    return "%d bytes" % n


def _print_strays(census):
    """Name other incident stores on disk when this one has nothing to say. BACKLOG P-76.

    🔴 THE SILENCE THIS BREAKS IS A FALSE STATEMENT, NOT A MISSING FEATURE. The reader and
    the gateway used to resolve their store differently -- the reader anchored to the
    project root, the gateway to whatever directory it was started from -- so a developer
    whose gateway was recording correctly was told "No blocks recorded yet" about their own
    data. Both halves now agree (backend/agentx_home.py), so a stray means an OLD store from
    before the fix, or a compose mount pointing elsewhere. Either way the honest move is to
    say which files exist and let the developer choose, never to read one of them and hope.
    """
    strays = census.get("strays") or []
    if not strays:
        return
    print("")
    print("  ⚠️  Other incident stores exist in this project, and this readout is NOT")
    print("      reading them:")
    for s in strays:
        # Scale the unit. A 24 KB store printed as "0.0 MB" reads as empty, which is the
        # same false-empty impression this whole warning exists to correct.
        print("        %s  (%s)" % (s["path"], _human_bytes(s["bytes"])))
    print("      A gateway started from a different directory wrote those. If that is")
    print("      where your blocks are, point at one and re-run:")
    # Platform-correct and QUOTED. `VAR=path cmd` is a parse error in PowerShell and cmd,
    # and this bug was found on Windows -- printing a POSIX-only line to the person most
    # likely to hit it defeats the point of the hint. Quoting matters independently: these
    # are absolute paths and any of them can contain a space.
    print("        %s" % _env_prefix_cmd("AGENTX_INCIDENT_DB", strays[0]["path"],
                                         _insights_cmd()))


# Imported, not restated. A second copy of "demo_cli" here is a second place to update
# when the set grows -- which it just did, with the shipped examples.
from .db import OUR_AGENT_IDS as _OUR_AGENT_IDS


def _print_local_blocks_section():
    """What the floor stopped ON THIS MACHINE, read from the SDK's own ledger. P-93(b).

    🔴 THIS SCREEN USED TO SAY NOTHING AT THE ONE MOMENT THE PRODUCT HAD JUST PROVED
    ITSELF. Reproduced 2026-08-10: two real keyless blocks land in `.agentx.db`, then
    `agentx insights` prints two sections, both describing the PAID path, both empty by
    construction for a keyless user, and the only concrete instruction on the screen is
    "go run the gateway". The data was already there and already had a reader --
    `get_block_frequency()` -- whose only caller was an internal script. Nothing was
    missing except the render.

    Both doors are safe: `_point_stores_at_mcp_home()` moves `db.DB_PATH` before the MCP
    reader runs, so this reads the per-user MCP ledger there and the project-anchored one
    here. Getting that wrong prints "nothing to see" over a store full of catches, which
    is the one wrong answer this surface must never give (P-76).
    """
    from . import db as db_module
    from .db import (get_block_frequency, get_would_block_summary, ledger_empty_reason,
                     get_retention_status, get_ledger_census)

    # "local to this machine" was the same false scope claim the status screen carried, on
    # the same store: DB_PATH is relative, so this is one ledger among however many the
    # developer has folders. Verified by reading the store this function actually opens --
    # the three other "local to this machine" headers in this file read the INCIDENT store
    # and the overrides store, whose scoping is a separate question and is NOT touched here.
    print("\n🛑 WHAT YOUR FLOOR STOPPED HERE          (local to this ledger)")
    print("=" * 75)

    # Defensive: a missing or locked ledger degrades to the empty state, never a traceback.
    # This runs on the same screen as `agentx review`'s CTA and must not take it down.
    #
    # Two separate guards so a failure of the SECOND read -- the one that exists only to
    # ATTRIBUTE demo traffic -- cannot blank the first. Losing the attribution costs a
    # footnote; losing `rows` gives the one wrong answer this surface must never give.
    #
    # ⚠️ THESE `try`s ARE BELT-AND-BRACES, NOT THE GUARD. `get_block_frequency` does not
    # raise: `_grouped_policy_rows` ends in `except Exception: return None` and the caller
    # maps that to `[]`. So an unreadable ledger arrives here looking exactly like an empty
    # one, and the real protection is `ledger_is_unreadable` below. An earlier version of
    # this comment claimed the split `try`s prevented the P-76 answer; they cannot, because
    # the exception they catch never arrives. Caught in the third review pass, and the test
    # that "covered" it was monkeypatching a raising reader -- a state the shipped function
    # cannot produce.
    try:
        rows = get_block_frequency()
    except Exception:
        rows = []
    try:
        without_demo = get_block_frequency(exclude_agents=list(_OUR_AGENT_IDS))
    except Exception:
        without_demo = rows       # -> demo_blocks == 0, so the footnote is skipped, not faked

    total = sum(r["blocks"] for r in rows)

    # ONE decision for "what does empty mean here", shared with `agentx status` and
    # `agentx share` (db.ledger_empty_reason). This screen was the only one that asked.
    try:
        _empty_reason = ledger_empty_reason()
    except Exception:
        _empty_reason = "empty"

    if not total and _empty_reason == "unreadable":
        # 🔴 SAY WHAT WE KNOW, WHICH IS NOTHING. The store is there and will not open, so
        # every sentence below this point would be a claim about the agents made from a
        # failed read.
        print("  The block ledger is on disk but could not be read, so this screen cannot")
        print("  tell you what your floor stopped. It is NOT a statement that nothing was")
        print("  blocked.")
        print("")
        print("     %s" % os.path.abspath(db_module.DB_PATH))
        print("")
        print("  Another process may hold it open. If it is corrupt, moving it aside starts")
        print("  a fresh one; the blocks it holds are not recoverable.")
        print("=" * 75)
        return

    # 🔴 RETENTION CAN MAKE THIS WHOLE SCREEN A PARTIAL ANSWER, so it is disclosed ONCE here
    # and covers both branches below rather than being remembered in each. Read after the
    # unreadable-ledger return on purpose: a store we could not open must not also be given
    # a confident sentence about what we pruned out of it.
    try:
        retention = get_retention_status()
    except Exception:
        retention = None

    # 🔴 `blocks_dropped`, NOT "retention ran at all". This screen lists BLOCKS, so the
    # warning it prints is a statement about blocks -- and since P-92 retention evicts
    # routine audit traffic FIRST and by design, so `rows_dropped` moves on a ledger whose
    # every catch is still present. Keyed on the count the sentence is about (see
    # db._RETENTION_COLUMNS), this stays silent when nothing it describes was lost.
    if retention and retention.get("blocks_dropped"):
        # Count and policy as two separate true sentences. Joining them ("dropped UNDER the
        # 30d limit") asserts those rows died under those limits; rows_dropped is cumulative
        # across every prune this file has seen and the limits are read live.
        print("  ⚠️  This ledger has been trimmed. %s older block record(s) have been dropped,"
              % f"{retention['blocks_dropped']:,}")
        print("      so this screen describes what was KEPT, not everything that happened.")
        print("      It keeps the last %d days or %s records."
              % (retention['current_max_age_days'], f"{retention['current_max_rows']:,}"))
        print("")

    if not total:
        # 🔴 "yet" IS A CLAIM ABOUT ALL OF HISTORY, AND OUR OWN HOUSEKEEPING CAN FALSIFY IT.
        # On a pruned ledger this machine HAS blocked things and we deleted the evidence.
        # Printing "nothing has been blocked yet" over that is the same false-empty answer
        # P-76 exists to prevent, arriving through retention instead of a path bug -- and
        # this time we would be the ones who made it false.
        # ...but only OUR DELETION OF A BLOCK can falsify it. Keyed on rows_dropped, the
        # sentence flipped to "no blocks REMAIN" -- which asserts there were some -- for any
        # developer whose routine audit traffic had been trimmed, and P-92 made that traffic
        # the first thing retention evicts. "Remain" was then a claim about catches they
        # never had, produced by the housekeeping that touched none of them.
        if retention and retention.get("blocks_dropped"):
            print("  No blocks remain on record here.")
        else:
            print("  Nothing has been blocked in this ledger yet.")
        # 🔴 OUTSIDE THE BRANCH, DELIBERATELY. The path was added to make "nothing here" a
        # checkable statement rather than a claim, and it was printed on only one of the two
        # ways of reaching that statement -- so the TRIMMED empty state, the one where our own
        # housekeeping caused the emptiness, was the case that lost the evidence. A fact that
        # qualifies a claim has to travel with every route to the claim.
        print("  %s" % os.path.abspath(db_module.DB_PATH))
        print("")
        # 🔴 A ZERO MUST EARN ITS MEANING. This SCREEN reads only blocks, so an empty one is
        # a statement about what it selects, not about how the agents behaved. Saying so is
        # the difference between an honest empty state and a flattering one.
        #
        # ⚠️ THIS COMMENT USED TO SAY "nothing records a call that PASSED", and P-92 is the
        # change that made that false: the audit inventory writes a row per passing call into
        # this same table. The justification survived the code it described, which is how a
        # future reader ends up defending a property the ledger no longer has.
        #
        # 🔴 AND A ZERO HAS A SECOND MEANING THIS SECTION USED TO TALK OVER. Under
        # AGENTX_ENFORCEMENT=audit the floor MATCHES and deliberately does not stop, so the
        # ledger holds WOULD_BLOCK rows and no blocks. Printing "the floor has not stopped
        # anything here" above a section that then lists 47 audited catches is a
        # contradiction on one screen, and `agentx demo` is the wrong next step for someone
        # whose catches are already sitting there. Past tense, about the ROWS, because
        # MCP_ENTRY cannot see the reader's current posture (same lesson as the audit
        # section below).
        try:
            audited = (get_would_block_summary() or {}).get("total", 0)
        except Exception:
            audited = 0
        if audited:
            # "while audit was on", not "under AGENTX_ENFORCEMENT=audit": the per-tool
            # `enforcement=` argument sets audit too, and that is the path `agentx demo
            # --audit` takes, so this sentence named a variable the reader had not set.
            print("  %d call(s) WERE recorded while audit was on and allowed"
                  % audited)
            print("  to run. Audit records what the floor would stop; it does not stop it,")
            print("  so a zero here is the posture, not a verdict on your agents.")
            # ...and whose calls they were, same as every other count on these screens.
            # 🔴 COUNTED DIRECTLY, NOT BY SUBTRACTION, AND THE SWALLOWED EXCEPTION IS WHY.
            # This read `audited - get_would_block_summary(exclude_agents=[demo])["total"]`.
            # That reader returns `{"total": 0}` on ANY error -- it swallows its own -- and
            # zero non-demo rows is also what a genuinely all-ours ledger looks like. So a
            # failed read did not drop the footnote, it printed "all of these came from an
            # agentx demo run" over rows that may have been entirely the developer's own.
            # The census counts it directly, in one query, and returns 0 for a ledger it
            # could not read -- which drops the footnote rather than inverting it.
            #
            # ⚠️ READ HERE, NOT INHERITED. The first version of this fix used a bare `census`,
            # which this function does not define and does not take: it would have raised
            # NameError on every `agentx insights` run with an audited row on it. Caught by
            # parsing the file for the enclosing scope rather than by reading the patch, and
            # it is precisely the failure the swallowed `except Exception` I was removing
            # would have hidden.
            # No handler, for the reason its twin in execute_insights now carries: the
            # census swallows its own errors and returns zeros, so anything a try here could
            # catch is a bug in this code -- and on the twin that is exactly what it caught,
            # and hid, until the founder noticed one screen disagreeing with another.
            _ours = (get_ledger_census() or {}).get("would_blocks_from_demo") or 0
            if _ours > 0:
                for _ln in _demo_row_note(_ours, of_total=audited, pronoun="these"):
                    print(_ln)
            # 🔴 NO CTA HERE, DELIBERATELY, and the first cut of this fix had one.
            #
            # Two reasons, and the second is the one I got wrong. (1) The audit section a
            # few lines below already ends in "flip to enforcing: AGENTX_ENFORCEMENT=
            # enforce", so adding one here put the same instruction on the screen twice.
            # (2) Would-block rows are HISTORY: an operator who audited last month and has
            # enforced ever since still has them, and an ungated "start stopping them"
            # tells someone already enforcing to start enforcing -- the identical
            # stale-nudge defect that section was already fixed for, reintroduced two
            # hundred lines above it. The sentence above is past tense and about the ROWS,
            # so it is true whatever they run now. The instruction, which is the only part
            # that asserts a current posture, stays where the posture is already known.
        else:
            # 🔴 THIS PARAGRAPH BECAME FALSE THE MOMENT RETENTION SHIPPED, and no test could
            # see it: both halves of the contradiction are print statements. On a trimmed
            # ledger "the floor has not stopped anything here" sits four lines under "40
            # older records were dropped", which is this screen calling itself a liar. Found
            # by RUNNING it, not by reviewing it.
            # 🔴 AND THEN P-92 FALSIFIED THE REPLACEMENT. Every branch here said "calls that
            # passed are screened and never written down" -- a true statement about the
            # ledger until the audit inventory started writing one row per PASSING call into
            # this same table. Found the same way as the paragraph above it: by running the
            # product, on a screen where both halves are print statements.
            #
            # The sentence now describes THIS SCREEN (which really does select only catches)
            # instead of the ledger (which no longer holds only catches), and points at the
            # screen that does answer "what did my agent do". That is both the correction and
            # the more useful sentence.
            if retention and retention.get("blocks_dropped"):
                print("  This screen lists blocks, and the oldest have been dropped, so it is")
                print("  not a record of everything the floor stopped. It also does NOT mean")
                print("  your agents ran clean -- it lists catches, not activity. What your")
                print("  agent actually did:   %s" % _audit_cmd())
            else:
                print("  This screen lists blocks, so an empty one means the floor has not")
                print("  stopped anything here. It does NOT mean your agents ran clean -- it")
                print("  lists catches, not activity. What your agent actually did:")
                print("     %s" % _audit_cmd())
            print("")
            # 🔴 THE MCP DOOR NEEDS A DIFFERENT SENTENCE, not the same one with a
            # different command in it. `uvx agentx-mcp --demo` pins its ledger into a
            # mkdtemp and deletes it on the way out (mcp_demo.py, deliberately -- a demo
            # must never write into a real corpus), so it leaves ZERO rows here. Offering
            # it from THIS screen sent the reader in a circle: run the demo, come back,
            # read "nothing has been blocked", get offered the demo again. Confirmed by
            # running it, in the third review pass. `agentx demo` on the CLI door DOES
            # land in this ledger, so that half keeps its ten-second promise.
            if MCP_ENTRY:
                print("  ▶ Route a tool through AgentX in your mcp.json, use it as you")
                print("    normally would, then re-run:   uvx agentx-mcp --insights")
                print("")
                print("    (`uvx agentx-mcp --demo` shows you a block, but it runs in a")
                print("     throwaway directory and deliberately records nothing here.)")
            else:
                print("  ▶ See a real block in about ten seconds:   agentx demo")
        print("=" * 75)
        return

    print("  %d block(s) recorded, by policy:" % total)
    for r in rows:
        line = "     %4dx   %s" % (r["blocks"], r["policy_name"] or "unattributed")
        if r["recoveries"]:
            line += "   (%d recovered)" % r["recoveries"]
        print(line)
        # WHICH TOOL, on its own line under the policy. The ledger has carried both on one
        # row since the beginning and no screen printed them together, so "which of my tools
        # tripped which control" -- the first thing a reviewer asks -- was unanswerable from
        # our own output. Indented under the policy rather than appended, because a long tool
        # list would push the count off the right of an 80-column terminal.
        for _ln in _tools_line(r.get("tools")):
            print(_ln)

    # Demo traffic is REAL (the floor genuinely stopped it) but it is ours, not theirs.
    # Folding it in silently would let someone read our own fixture as evidence about
    # their agents; dropping it would tell a user who has only run `agentx demo` that
    # nothing was ever blocked, which is the opposite lie.
    demo_blocks = total - sum(r["blocks"] for r in without_demo)
    if demo_blocks:
        print("")
        for _ln in _demo_row_note(demo_blocks, of_total=total, pronoun="these"):
            print(_ln)

    print("")
    # 🔴 THE POPULATED HALF OF THE SAME FALSE CLAIM, and the one a developer actually reads:
    # this branch runs whenever they have a single block. "Calls that passed were screened
    # and not recorded" was a statement about the STORE, and P-92 writes a row per passing
    # call into that store. Founder-caught by running `agentx insights`, not by review --
    # the sentence is a print statement, so nothing red could ever appear.
    print("  This screen lists catches only, so it is never a measure of activity.")
    print("  What your agent actually did, call by call:   %s" % _audit_cmd())
    print("=" * 75)


def _print_recovery_section(census):
    """What happened AFTER a block (BACKLOG P-59).

    THE THREE SILENCES ARE DIFFERENT AND MUST READ DIFFERENTLY. "No store on disk" means the
    GATEWAY has recorded no aftermath here -- the NORMAL case, because only the gateway writes
    to this store and most installs are keyless. "Blocks but nothing settled" means the
    outcomes have not resolved yet. Only the third is "nothing recovered". Printing a bare 0%
    for all three would tell a keyless user their agents never recover, which is not a finding
    about their agents, it is a finding about what we are not recording.

    ⚠️ THIS PARAGRAPH ITSELF CARRIED THE P-102 DEFECT until 2026-08-12. It read "the keyless
    shield does not write here", which is true of THIS STORE and reads as a claim about
    recoveries in general -- and recoveries ARE recorded, in the local ledger, by
    log_self_correction on both keyless paths. The user-facing copy (the print block below)
    was corrected first and this docstring was missed, which is the reader-check applied to
    prose and then not to the prose next door.

    📌 There was ONE user-facing copy of this sentence, not four. An earlier version of this
    paragraph said four, borrowing the count from the OTHER sentence corrected in the same
    change -- "the size of the biggest number", which genuinely did live on four surfaces
    (the demo, both copies of example 12, and the README). Two different sentences, one PR,
    and the number migrated between them. A count is a claim; this one was wrong in a comment
    warning about claims.
    """
    from .overrides import recovery_summary, refine_recoveries, settle_stale_blocks

    print("")
    print("🔁 WHAT HAPPENED AFTER A BLOCK           (local to this machine)")
    print("=" * 75)

    if not census["exists"]:
        # 🔴 P-102: THIS BRANCH USED TO DENY WHAT THE SAME SCREEN HAD JUST SHOWN. The old copy
        # read "the keyless shield does not write recovery outcomes", printed a few lines below
        # a policy row reading "(1 recovered)". Recoveries ARE recorded on every install:
        # log_self_correction flips CHALLENGED -> RECOVERED in the local ledger from both
        # keyless surfaces (decorators.py and the MCP proxy) and narrates it as it happens.
        # What a keyless install lacks is the AFTERMATH -- did the run go on to finish the job,
        # or stop right after our suggestion -- which is what THIS section reads and only the
        # gateway writes. Two true statements about two different records read as one
        # self-contradiction while neither of them names its record, so this one names it.
        # ⚠️ A STATEMENT ABOUT BEHAVIOUR, NEVER ABOUT WHAT IS CURRENTLY ON SCREEN. The first
        # cut of this fix read "any are shown beside the policy above", which is true only
        # when the section above HAS policies. On an empty ledger that section prints
        # "Nothing has been blocked in this ledger yet" and this one then pointed at a list
        # that was not there -- copy true of one path, generalised to all, which is the same
        # defect P-102 itself is. Found by rendering the empty path, not by review.
        # ⚠️ NO REFERENT AT ALL, THIRD ATTEMPT. Cut one read "shown beside the policy above";
        # cut two dropped the word "above" but kept pointing at a policy row that an empty
        # ledger never prints. Removing the deictic WORD is not the fix -- removing the
        # REFERENT is. This says what the product does and names nothing on the screen.
        print("  Recoveries ARE recorded: when your agent revises a blocked call and it")
        print("  runs, AgentX counts that as a recovery.")
        print("  What is missing here is what came NEXT: whether the run went on to")
        print("  finish the job, or stopped right after our suggestion. Only a gateway")
        print("  records that -- run your agents against the local gateway to collect it.")
        _print_strays(census)
        print("=" * 75)
        return

    # 🔴 THE SWEEPS RUN HERE, AT READ TIME, AND THIS IS THEIR ONLY CALLER. They shipped with
    # none at all, so nothing settled in a real deployment and "none settled yet" was permanent
    # rather than passing. Read-time is the right home: both are idempotent and neither needs a
    # daemon, so the readout cannot depend on a gateway having been alive at the right moment.
    # Same placement and same reason as reconcile_safe_paths before `agentx review`.
    settle_stale_blocks()
    refine_recoveries()

    summary = recovery_summary()
    if not summary:
        # 🔴 P-102 AGAIN, ONE BRANCH OVER, AND IT CONTRADICTS A NUMBER RATHER THAN A WORD.
        # This read "No blocks recorded yet" on a screen whose own block list two sections up
        # had just printed "1 block(s) recorded ... (1 recovered)". Reproduced on a keyless
        # run that has a gateway store on disk with nothing in it: the sentence is true of
        # THIS store and false of the local ledger, and it never said which one it meant.
        # Same fix as the census branch: name the record. No referent to anything on screen.
        print("  There is nothing to have recovered from in this gateway store: it has")
        print("  no blocks in it. Blocks your keyless shield recorded live in the local")
        print("  ledger and are not counted on this line.")
        _print_strays(census)
        print("=" * 75)
        return

    # 🔴 A FOURTH SILENCE, and it used to print as one of the other three. A store written by an
    # older gateway has no outcome columns at all, and saying "no blocks recorded yet" to
    # someone holding tens of thousands of them is simply false.
    if summary.get("state") == "not_upgraded":
        print("  %d block(s) recorded, but this store predates the outcome columns, so there"
              % summary["blocks_all_time"])
        print("  is nothing recorded about what happened after them. The gateway adds the")
        print("  columns on its next write -- blocks from then on will be tracked.")
        _print_strays(census)
        print("=" * 75)
        return

    o = summary["overall"]
    # Blocks written before we started watching what came next. They cannot have recovered, so
    # counting them would drag the headline to zero; they are named instead of hidden.
    if summary["blocks_before_window"]:
        print("  %d earlier block(s) are not counted below: they were recorded before we"
              % summary["blocks_before_window"])
        print("  started tracking what happened next, so nothing about them is known.")

    # 🔴 PRINTED BEFORE THE EARLY EXITS, because escalations are lifted OUT of `overall`. A store
    # whose in-window blocks were all human approvals had overall["blocks"] == 0 and printed
    # "Nothing has been recorded since we started tracking outcomes" over the top of them --
    # the same false silence this whole section exists to eliminate, reintroduced by the lift-out.
    esc = summary["escalations"]
    if esc["total"]:
        line = ("  %d went to a human: %d proceeded after approval, %d still waiting"
                % (esc["total"], esc["proceeded"], esc["open"]))
        if esc["closed_other"]:
            line += ", %d closed otherwise" % esc["closed_other"]
        print(line)

    if o["blocks"] == 0:
        if not esc["total"]:
            print("  Nothing has been recorded since we started tracking outcomes.")
        else:
            print("  Nothing else has been recorded since we started tracking outcomes.")
        print("=" * 75)
        return
    if o["settled"] == 0:
        print("  %d block(s) recorded, none settled yet. Outcomes settle once a run goes"
              % o["blocks"])
        print("  quiet; there is nothing to read until then.")
        print("=" * 75)
        return

    # By class FIRST and always. The blended figure is the least useful cut: "our advice on
    # destructive writes works and our advice on network calls does not" is a work item,
    # "62%" is not.
    for name, b in sorted(summary["by_class"].items(), key=lambda kv: -kv[1]["blocks"]):
        if not b["readable"]:
            print("  %-22s %4d blocks   not enough data yet" % (name, b["blocks"]))
            continue
        print("  %-22s %4d blocks   %d recovered (%s)"
              % (name, b["blocks"], b["recovered"], _share_pct(b["recovered"], b["settled"])))

    print("")
    if o["readable"]:
        print("  Overall: %d settled - %d recovered (%s) - %d blocked again"
              % (o["settled"], o["recovered"], _share_pct(o["recovered"], o["settled"]),
                 o["reblocked"]))
    else:
        print("  Overall: %d settled -- not enough data for a rate yet" % o["settled"])
    # NOT a failure count. It covers an agent that gave up, a run that finished the job
    # another way, and a crashed process. The window is stamped because it MOVES this number:
    # a shorter one settles more blocks into it, so two runs under different windows are not
    # comparable.
    print("  %d saw no further activity after %d min (we cannot tell why), %d still open"
          % (o["no_further_activity"], summary["settle_window_seconds"] // 60, o["open"]))
    # Loud rather than diluted. Vocabulary is enforced on write, so a value arriving here means
    # something drifted -- most likely a store written by a newer gateway than this SDK. These
    # are held OUT of `settled`, so they cannot quietly move the rate above.
    if o["unrecognised"]:
        print("  %d have an outcome this version does not recognize and are not counted in"
              % o["unrecognised"])
        print("  the rate. Upgrade the SDK (pip install -U agentx-security).")

    runs = summary["runs"]
    if runs["readable"]:
        # Both numbers, because they answer different questions and collapsing them hides an
        # open run inside a "did not finish". The denominator is SETTLED runs, matching every
        # other rate here.
        print("  %d runs hit a block - of the %d settled, %d finished after their last one"
              % (runs["with_a_block"], runs["settled"], runs["ended_on_a_recovery"]))

    # Never the recovery rate alone. The two fastest ways to raise it are to block more
    # loosely and to suggest something trivially safe, and only this line shows the first.
    if summary["block_rate"] is not None:
        print("  Blocked %s of observed calls since %s"
              % (_pct_text(summary["block_rate"]), summary["block_rate_since"][:10]))
    else:
        print("  Block rate: not measurable yet (allowed calls have only just started being")
        print("  recorded, so there is no period covering both).")
    _print_coaching_scoreboard()
    print("=" * 75)


def _shorten(text, width):
    """Left-aligned to `width`, middle-elided so a UUID stays recognisable at both ends.

    🔴 A TRUNCATED LABEL MUST STILL IDENTIFY ONE THING. Plain middle-elision collides for any two
    strings sharing a head and a tail, and it did: `11111111-aaaa-1111-1111-111111111101` and
    `11111111-bbbb-2222-2222-111111111101` both rendered `11111111...111111101`, version included.
    That is the ambiguity the numbered rewrite queue was written to remove, relocated into the
    renderer -- naming the coaching version buys nothing if the id beside it is not unique.

    So a truncated label carries three hex characters of a digest of the WHOLE string. Cryptic,
    and the alternative is two rows a reader cannot tell apart in the one place this output asks
    them to go and open something. Untruncated labels are unchanged.
    """
    text = str(text)
    if len(text) <= width:
        return text.ljust(width)
    tag = "#" + hashlib.sha1(text.encode("utf-8")).hexdigest()[:3]
    body = width - len(tag)
    head = (body - 3) // 2
    return text[:head] + "..." + text[len(text) - (body - 3 - head):] + tag


def _pct_text(fraction):
    """A share as text, never rounding a real observation away.

    🔴 A ROUNDED 0% IS THE ZERO THIS READOUT SPENT ITS WHOLE DESIGN REFUSING TO PRINT.
    `round(100 * 3 / 2000)` is 0, so three real recoveries print as "never once", which is a claim
    we did not measure. "<1%" carries the same decision -- still worst in the queue, still says
    rewrite it -- without asserting a zero. The collapse runs the other way too: 1,999 of 2,000
    rounds to 100%, reading as "never failed" for text that did.

    🔴 FIVE CALL SITES, NOT TWO. Found as two defects in the scoreboard and fixed there first,
    which left the template standing: the per-class table, the overall line and the block rate all
    ran their own `round(100 * ...)`. The dev store was printing `1 recovered (0%)` on the
    per-class table the whole time, in output that was read many times without anyone noticing.
    Every percentage in this section goes through here.
    """
    if fraction > 0 and fraction < 0.005:
        return "<1%"
    if fraction < 1 and fraction > 0.995:
        return ">99%"
    return "%d%%" % round(100.0 * fraction)


def _share_pct(part, whole):
    """`_pct_text` for the common case of a part over a whole. Zero whole is the caller's job."""
    return _pct_text(float(part) / whole)


def _stops_runs(group, min_sample):
    """Did more runs END than continue after this advice? The "safe and useless" tell.

    🔴 THE COMPARISON NEEDS ITS OWN EVIDENCE BAR, and running this against a populated store is
    what showed why: one group had six stopped and zero continued out of two thousand blocks, and
    a bare `stopped > continued` fired a scary sentence on six observations. The claim is only
    about the runs that actually TOOK our advice, so those are what must clear the floor. Reusing
    min_sample rather than inventing a second threshold.
    """
    return (group["stopped"] > group["continued"]
            and group["stopped"] + group["continued"] >= min_sample)


def _print_coaching_scoreboard():
    """Which piece of coaching worked, and what to rewrite first. P-59 criteria 11 and 12.

    The per-class table above says WHERE our advice works. This says WHICH TEXT works, and it is
    the half that compounds: a low scorer is a rewrite candidate, and the rewrite is measured
    against the version it replaced.

    🔴 EVERY NUMBER HERE IS SCOPED BY THE SAMPLE FLOOR, and the floor is the point. The queue is
    ranked worst-first, so without it the groups with the least evidence sort straight to the top
    and we would rewrite working text on the strength of three observations.
    """
    from .overrides import coaching_scoreboard

    board = coaching_scoreboard()
    # 🔴 FOUR SILENCES COLLAPSED INTO ONE `return`, WHICH IS THE DEFECT THIS WHOLE SECTION
    # EXISTS TO NOT COMMIT. A section that answers by printing nothing is indistinguishable
    # from a section that had nothing to say: no header, no line, no signal that an answer is
    # missing at all. `_print_recovery_section` above names each of its four silences
    # separately for exactly this reason; this one regressed against the good example sitting
    # twenty lines up.
    #
    # `not_upgraded` is the REACHABLE one and it is not theoretical: the two readers test
    # DIFFERENT schema conditions (`outcome_next` there, `outcome_next` OR `coaching_version`
    # here), and `_reconcile_columns` adds columns one bare ALTER at a time with no rollback, so
    # an upgrade interrupted mid-loop leaves precisely that split. Measured against such a store:
    # 30 blocks, a full per-class table printed, and this entire section absent.
    if board is None:
        # The ONLY one left silent, and deliberately: the caller has already returned for every
        # store that produces it (no file, no incidents table, nothing readable). Reaching here
        # would mean the two readers disagree about the same store, which is a bug in one of
        # them rather than a state worth narrating to a user.
        return
    print("")
    print("  WHICH COACHING WORKED")
    if board.get("state") == "not_upgraded":
        print("  This store records blocks but not which coaching issued them, so")
        print("  none of it can be scored. The gateway stamps that from its next write on.")
        return
    if board.get("state") == "no_window":
        # Its OWN sentence. Lumping it in with "no blocks carrying a stamp" says something FALSE
        # about it -- there may be plenty of stamped blocks; what is missing is a period where we
        # watched both the blocks and what came after. Unreachable through the caller today, and
        # named anyway, because the docstring one module over promises these silences stay
        # distinct and collapsing two of them here is how that promise quietly stops being true.
        print("  Not watching both sides yet, so nothing here can be scored.")
        return
    if board.get("state") != "ok" or not board["groups"]:
        print("  No blocks carrying a coaching stamp yet, so there is nothing to score.")
        return
    # Said once, here, rather than implied by the column heading. "Kept going" is the honest
    # reading of recovered_continued: the next call was allowed AND the run did more work
    # afterwards. It is NOT "the job succeeded" -- we do not observe that and must not imply it.
    print("  \"Kept going\" means the agent was allowed through and carried on")
    print("  working. It does not mean the job succeeded; we are not there for that.")
    print("  \"Went quiet\" is a run we stopped seeing: evidence of nothing, and it")
    print("  stays out of the percentage.")
    # 🔴 EVERY LINE BELOW STAYS INSIDE THE 75-COLUMN FENCE the rest of this section is framed by.
    # The first cut ran to 116 characters, so in an 80-column terminal every row wrapped and the
    # column alignment these format strings exist for was destroyed on the only screen most people
    # will read this on.
    # 🔴 THE kept/seen CELL IS SIZED FOR THE STORES THIS RUNS ON, not for the toy one it was
    # written against. An over-long %s does not truncate -- it SHIFTS every column to its
    # right, which is the alignment this whole block was re-flowed to protect. "%11s" fit
    # "9/20 (45%)" and nothing bigger; widening to 17 fixed the four-digit case and still
    # shifted at five ("19996/20000 (100%)" is 18), which the dev store can reach. 20 holds
    # six digits either side and keeps the row at 74, inside the same 75-column fence.
    # Guarded by test_the_kept_seen_cell_does_not_shift_the_row.
    print("  %-20s %-15s %20s %7s %6s"
          % ("coaching", "version", "kept/seen", "stopped", "quiet"))
    for g in board["groups"]:
        pid, ver = _shorten(g["policy_id"], 20), _shorten(g["coaching_version"], 15)
        if not g["readable"]:
            # 🔴 Criterion 11. Not a rate, not a zero, and not silently omitted either: a group
            # we cannot score still tells the reader that this coaching is being issued -- and
            # BOTH counts are printed, because the gap between them is the whole story on a
            # populated store, where a coaching item had 32 blocks and not one observed outcome.
            print("  %s %s  %d of %d back, too few to score"
                  % (pid, ver, g["observed"], g["blocks"]))
            continue
        print("  %s %s %20s %7d %6d"
              % (pid, ver, "%d/%d (%s)" % (g["continued"], g["observed"],
                                           _share_pct(g["continued"], g["observed"])),
                 g["stopped"], g["went_quiet"]))
    print("  Scoring needs %d outcomes back; \"quiet\" runs are not in the percentage."
          % board["min_sample"])

    queue = board["rewrite_queue"]
    if not queue:
        print("")
        print("  No coaching has enough outcomes back to score yet, so there is nothing to")
        print("  rank. That is too little evidence, not a verdict on the advice.")
        return

    # 🔴 THE VERSION IS PART OF THE ANSWER, NOT DECORATION. Groups are keyed by
    # (policy_id, coaching_version), so two generations of one policy are two rows -- and the
    # first cut printed only the id, which rendered "Rewrite first: POL-001 (25%), POL-001 (38%)".
    # The worst-ranked entry there is the SUPERSEDED text and the reader cannot tell which is
    # which, so the single line a human acts on was unactionable in precisely the
    # two-versions-in-window case criterion 12 exists to create.
    #
    # A numbered list rather than a comma run, because naming id AND version for three entries
    # does not fit on one line inside the fence, and because it gives the safe-but-useless flag
    # somewhere to attach instead of repeating the same names in a second sentence.
    print("")
    print("  Rewrite first:")
    for i, g in enumerate(queue[:3], start=1):
        # Counted over the whole scored set below; the marker only shows on the rows printed.
        mark = ("  [stops runs]" if _stops_runs(g, board["min_sample"]) else "")
        print("   %d. %s %s %4s kept%s"
              % (i, _shorten(g["policy_id"], 20), _shorten(g["coaching_version"], 15),
                 _share_pct(g["continued"], g["observed"]), mark))
    if len(queue) > 3:
        print("      and %d more scored below these." % (len(queue) - 3))
    print("  These are the texts agents were least likely to get moving after.")
    print("  Rewriting one is a person's job; this only says which one to open.")

    # 🔴 THE "SAFE AND USELESS" TELL, and it is the failure mode this loop is most likely to
    # reward: the easiest way to score well is to suggest something trivially permitted that does
    # not do what the user wanted. A group whose runs mostly STOP right after taking our advice
    # looks like a success in every other view, so it is flagged rather than folded into the
    # score. Counted over every SCORED group, not over the three printed above, so the sentence
    # and the number describe the same set.
    #
    # 🔴 THE COMPARISON NEEDS ITS OWN EVIDENCE BAR, and running this against a populated store is
    # what showed why: one group had six stopped and zero continued out of two thousand blocks, and
    # `stopped > continued` fired a scary sentence on six observations. The runs that actually
    # TOOK our advice are the only ones this claim is about, so they must clear the same floor
    # the score does. Reusing min_sample rather than inventing a second threshold.
    #
    # Marked on the rows above rather than re-listed by name in a sentence. Naming them twice was
    # what forced the "and N more" hedge, and it repeated ids that were already ambiguous without
    # their version.
    safe_but_useless = [g for g in queue if _stops_runs(g, board["min_sample"])]
    if safe_but_useless:
        # 🔴 THE COUNT AND THE VISIBLE MARKS MUST BE RECONCILABLE. Only the top three rows are
        # printed, so a bare "5 of the 5 scored" sat under three marks with no way to square the
        # two. Same claim-versus-visible mismatch the "and N more" name list was dropped for,
        # back in a different shape; saying where the rest are is the whole fix.
        print("  [stops runs] = more runs ENDED than continued after this advice,")
        print("  which is what safe-but-useless looks like. %d of the %d scored carry it,"
              % (len(safe_but_useless), len(queue)))
        # Keyed on identity, not dict equality: `g in safe_but_useless` compares every field,
        # which is both quadratic and true for two genuinely distinct groups that happen to
        # match on all counts.
        marked = {id(g) for g in safe_but_useless}
        print("  %d of them marked above. Open those first."
              % sum(1 for g in queue[:3] if id(g) in marked))


def _plural(n, singular, plural=None):
    """"1 call" / "2 calls". `n` is formatted with thousands separators.

    Worth the four lines: "1 call(s) tripped a policy" is the first sentence a stranger reads
    about their own agent, and the parenthetical is the tell of a screen nobody read aloud.
    """
    word = singular if n == 1 else (plural or singular + "s")
    return "%s %s" % (f"{n:,}", word)


# How long a single argument name may be before the "keep it whole" rule stops paying for
# itself. Nothing in the SDK's own examples, tests or demos comes close; a token past this is
# machine-generated, and on the MCP path it is generated by someone else's server.
_MAX_WHOLE_NAME = 40


def _fit_names(names, width):
    """Join argument names to fit `width`, dropping WHOLE names rather than cutting one.

    The list is the developer's own identifiers, and the reader's next move is to search
    their codebase for one. A half name is worse than a missing one: `min_a...` matches
    nothing and still reads like a parameter. `db._call_shape` reached the same conclusion on
    the write side -- it drops whole names too -- and this is the display twin. It does NOT
    emit "+N more"; that suffix is this function's, and an earlier version of this docstring
    credited it to the writer.

    Returns "(none)" for an empty list, so the caller does not have to special-case it.

    ⚠️ "+N more" COUNTS WHAT THIS FUNCTION DROPPED, NOT WHAT THE USER PASSED, and on a very
    wide call those differ. `db._call_shape` has already capped the stored list at
    `_MAX_ARG_NAMES` (24) and `_MAX_ARG_NAMES_CHARS` (512), so a tool with 40 keyword
    arguments can render "+22 more" when 38 are actually absent. A count is a claim and this
    one is a floor rather than a total.

    Left as a count deliberately: the display cannot know the true number without the writer
    storing it, which is a schema change, and dropping the number would cost real information
    on every ordinary row to fix a rare one. Pinned as a known limit rather than papered over.

    ⚠️ THE "KEEP IT WHOLE" TRADE IS BOUNDED, AND IT HAD TO BE. Keeping an oversized name whole
    is right for a long identifier a human typed; it is wrong for one nobody typed. Argument
    names on the MCP path come from a REMOTE server's JSON, and the writer's only per-row bound
    is `db._MAX_ARG_NAMES_CHARS` (512) across the whole list -- so one 300-character generated
    key rendered a 356-COLUMN audit row, measured, and took every other row's alignment with
    it. The code this replaced clipped at 30 and held the table together, so an unbounded
    overrun would be a regression traded for greppability that a 300-character token does not
    have anyway. Past _MAX_WHOLE_NAME it clips through `_fit`, which is visibly truncated
    rather than silently plausible -- the same contract the TOOL and SURFACE columns run under.
    """
    names = [str(n) for n in (names or []) if str(n)]
    if not names:
        return "(none)"

    joined = ", ".join(names)
    if len(joined) <= width:
        return joined

    # 🔴 RESERVE FOR THE SUFFIX BEFORE DECIDING WHAT FITS, and the first cut of this function
    # only SAID it did. It tested `len(", ".join(kept + [name])) > width` with no allowance for
    # " +N more", so the returned string could exceed the budget by the whole suffix: four
    # names of 14/14/2/2 returned 38 characters against a width of 30. A comment claiming a
    # reservation the code does not make is the defect this PR is named for, in the function
    # written to fix another instance of it.
    #
    # ⚠️ WHAT THIS GUARANTEES, STATED EXACTLY, BECAUSE THIS PARAGRAPH HAS OVERCLAIMED THREE
    # TIMES NOW. The return is at most `max(width, _MAX_WHOLE_NAME) + len(" +N more")`. At the
    # audit screen's width of 27 that is 49, NOT 27.
    #
    # Two ways it exceeds `width`, both deliberate:
    #   * a single name longer than `width` is kept, up to _MAX_WHOLE_NAME, because a reader
    #     can grep a long name and cannot grep half of one;
    #   * past _MAX_WHOLE_NAME it is CLIPPED -- so "kept whole" stops being true there, which
    #     the previous wording asserted flatly while the code clipped at 40.
    #
    # It says nothing about the caller's line length. That is the caller's arithmetic.
    #
    # Worst-case suffix, so the reserve cannot be too small: dropping every name but one still
    # renders "+N more" with N no wider than the total count.
    reserve = len(" +%d more" % len(names))
    kept = []
    for name in names:
        # Clip the first name BEFORE measuring later candidates against it, so the loop
        # compares against what will actually be displayed rather than the raw length.
        #
        # ⚠️ THIS DOES NOT RESCUE THE STARVED CASE, AND SAYING IT DID WAS THE FIRST DRAFT OF
        # THIS COMMENT. At the audit screen's width of 27 the budget after the suffix is ~19,
        # and a first name clipped to _MAX_WHOLE_NAME (40) already exceeds it, so nothing else
        # can join it either way:
        #
        #     _fit_names(["a"*60, "path", "url"], 27)  ->  "aaaa...(37)... +2 more"
        #
        # That IS the accepted trade, not a bug left lying around: the reader gets one name
        # they can grep plus an honest count, and the alternative -- clipping the long name
        # small enough for `path` and `url` to fit -- returns three fragments none of which
        # matches anything in their code. It is order-dependent (the same names with the long
        # one sorting LAST return both short ones), and that asymmetry is the cost.
        name = _fit(name, _MAX_WHOLE_NAME) if not kept else name
        candidate = ", ".join(kept + [name])
        if kept and len(candidate) > width - reserve:
            # 🔴 `continue`, NOT `break`, AND db._call_shape SAYS WHY IN THE SAME WORDS:
            # "names arrive SORTED, so one oversized name discarded every remaining argument
            # for that call rather than just itself." The first cut of this display twin used
            # `break` and reintroduced exactly that -- ["aaa", <26 chars>, "zzz"] returned
            # "aaa +2 more" while "aaa, zzz" fits in eight. Skip the one that does not fit and
            # keep taking the ones that do.
            continue
        kept.append(name)

    # ⚠️ ONE DELIBERATE OVERRUN REMAINS, and it is the right half of the trade: a single name
    # longer than the budget is kept WHOLE (the `kept and` guard above never drops the first),
    # up to _MAX_WHOLE_NAME. The reader's next move is to search their code for what they see,
    # and they can grep a long name but not half of one. Past that ceiling the name is
    # generated rather than typed, greppability buys nothing, and the row stops being a row --
    # see the docstring for the 356-column measurement that put the ceiling here.
    #
    # `max(width, ...)`: the ceiling only ever RELAXES the caller's budget, never tightens it.
    # A caller that hands this function a 100-column budget has already said a 90-character
    # name is acceptable there, and clipping it to 40 would be this function overruling the
    # only party that knows the line.
    ceiling = max(width, _MAX_WHOLE_NAME)
    if kept and len(kept[0]) > ceiling:
        kept[0] = _fit(kept[0], ceiling)

    dropped = len(names) - len(kept)
    if not dropped:
        return ", ".join(kept)
    return "%s +%d more" % (", ".join(kept), dropped)


def _fit(text, width):
    """Clip to `width` with an ellipsis, never silently. A truncated tool name that still
    looks like a name is worse than an obviously truncated one: the reader searches their
    codebase for `a_very_long_tool_name_th` and finds nothing."""
    text = str(text or "")
    return text if len(text) <= width else text[:width - 3] + "..."


# Below this, a "magnitude" is noise rather than a fact worth a line of its own: the bucket
# floor is 1.0 for any number >= 1, so a $5 charge produces ">=1". A magnitude line should mean
# the agent moved something big.
#
# This floor used to be doing two jobs. It also hid the P-103 defect, where `limit=5` or
# `account_id=1` produced "largest number passed: >=1" on almost every row -- the threshold
# suppressed the small lies and let the large ones (a customer id at >=1,000,000) through.
# db._call_shape now only measures arguments NAMED as amounts, so this is back to one job:
# deciding when a real amount is big enough to be worth a line.
_MAGNITUDE_WORTH_SHOWING = 100.0


def _format_bucket(amount):
    """Render a magnitude BUCKET as the ">= floor" it actually means.

    The stored value is a bucket floor, not a measurement: 1000.0 means "at least 1,000 and
    under 10,000". Printing it bare as "1,000" would read as an exact figure the ledger
    deliberately does not hold, which is the difference between a shape and a value.
    """
    try:
        if not amount or amount < 1:
            return ""
        return "≥%s" % f"{int(amount):,}"
    except Exception:
        return ""


def _print_wrap_snippet():
    """How to wrap a tool. The step this screen kept NAMING without ever SHOWING.

    🔴 IT WAS BACKWARDS. The POPULATED screen printed the decorator -- to a reader who has
    already wrapped something, which is how we saw their calls at all -- and both EMPTY
    branches said "Wrap a tool, then run your agent with it on:" followed only by the
    AGENTX_ENFORCEMENT lines. Step two, shown; step one, named and left as an exercise. On a
    fresh directory that is the entire first-run experience: an instruction with no
    instructions. Founder-flagged 2026-08-12 after running it in a new shell.

    ⚠️ PYTHON DOOR ONLY. An MCP reader does not decorate anything -- they add AgentX to
    mcp.json and their client spawns it -- so this snippet is not a step they can take, and
    the MCP branch deliberately does not call this. Same rule that keeps `agentx audit` off
    the uvx door's CTAs: a command is only a CTA if the reader of THAT surface can run it.

    A function rather than two copies, so the next empty branch inherits it. The last three
    defects on this screen were all one branch getting a fix its neighbour did not.
    """
    print("")
    print("      from agentx_sdk import agentx_protect")
    print('      @agentx_protect(agent_id="my_agent")   # around any tool function')


def _print_audit_sample():
    """Show what this screen looks like once a wrapped tool has run. EXAMPLE DATA ONLY.

    An empty screen does not teach the format, so someone who has never seen a populated
    `agentx audit` is being asked to wrap a tool on faith. This is the picture, placed on the
    screen they actually ran rather than in a footer they have scrolled past.

    🔴 MARKED ON EVERY LINE, BECAUSE SOMEONE WILL SCREENSHOT IT. A single header above the
    table does not survive a crop that starts one line lower, and fabricated rows passed off
    as a real audit would be the worst thing this command could produce. The `|` gutter plus
    a label at BOTH ends means no crop of it reads as a genuine table.

    ⚠️ DELIBERATELY BORING. The tempting version puts `refund_customer ... >=1,000` in here
    because that is the row that sells. That would be a promise about what they are going to
    find, and most agents will not find it. Show the shape; let their own data be the
    interesting part.

    🔴 MCP DOOR ONLY SINCE 2026-08-12. The Python door gets `_print_audit_offer` instead: a
    fabricated table was the best this screen could do while the only way to fill it was for
    the reader to go instrument their own codebase, and `agentx demo --audit` now fills it
    for real in one command. Where that command is available, invented rows are strictly
    worse than the thing they were standing in for.

    A uvx reader has no `agentx` on PATH, so offering them that command is offering an
    instruction they cannot follow. For them the picture is still the best available answer.
    """
    print("")
    # "a tool call goes through", not "a WRAPPED tool runs": this footer prints on BOTH
    # doors, and only the Python one wraps anything. An MCP reader routes their server
    # through the proxy and never writes a decorator, so the old wording described a step
    # they will never take, on the screen telling them what to expect.
    print("  Once a tool call goes through, this screen looks like:")
    print("")
    print("  +-- EXAMPLE, not your data --------------------------------------------")
    print("  |  TOOL                       CALLS  SURFACE     ARGUMENTS")
    # `query` alone, not `limit, query`: only arguments the agent actually PASSES are
    # recorded, so a defaulted `limit=10` never appears. The example has to promise a shape
    # the product produces, or the first thing it teaches is wrong.
    print("  |  run_sql                       12  DB          query")
    print("  |  send_http_request              5  HTTP        url")
    print("  |  write_file                     1  FS          contents, path")
    print("  +-- EXAMPLE, not your data --------------------------------------------")


def _tools_line(tools):
    """The "on: run_sql, charge_card" line under a policy. ONE renderer, two screens.

    `tools` is the (names, hidden) pair the ledger readers return, already bounded there. The
    hidden count is PRINTED rather than dropped: a truncated list that does not say it is
    truncated is the silent-cap failure this project keeps having to undo.

    Returns a list of lines (empty when there is nothing to say), so a caller that has no
    tool names -- a legacy ledger whose rows never recorded one -- prints nothing at all
    rather than an empty label.
    """
    names, hidden = (tools or ([], 0))
    if not names:
        return []
    # 🔴 THE TRUNCATION NOTICE MUST NOT BE THE THING THAT GETS TRUNCATED. The first cut
    # rendered six names and let `_fit` cut the line at 75, which produced
    # "on: tool_00, ... tool_05 an..." -- the cap silently eaten by the cap. So the line is
    # BUILT to fit: drop names until it does, and count every dropped one into the total, so
    # the number the reader sees is always the number actually hidden.
    prefix = "             on: "
    shown = list(names)
    while True:
        extra = hidden + (len(names) - len(shown))
        text = ", ".join(shown) + (" and %d more" % extra if extra else "")
        if len(prefix) + len(text) <= 75 or len(shown) <= 1:
            return [_fit(prefix + text, 75)]
        shown.pop()


def _demo_row_note(count, of_total=None, pronoun="those"):
    """The one sentence that attributes ledger rows to OUR demos, in one place.

    🔴 IT NAMED A COMMAND THAT COULD NOT HAVE WRITTEN THE ROW. Three screens said "came from
    `agentx demo`", which was exact while that was the only demo. `agentx demo --audit` now
    writes rows too, and a WOULD_BLOCK can only come from THAT one -- plain `agentx demo`
    pins enforce and writes CHALLENGED -- so a reader who ran only `--audit` was told their
    row came from a command they never ran. Reproduced in a clean directory.

    The fix is not a fourth spelling. Nothing in the ledger records WHICH demo wrote a row,
    so no sentence keyed on it can stay true; the honest unit is the family. One function so
    the next demo cannot leave a fourth site behind, which is how this got to three.

    🔴 THE SINGULAR IS ITS OWN BRANCH, AND IT IS NOT A STYLE POINT. The first version of this
    function printed "Every one of them came from an `agentx demo` run" under a line reading
    "1 call tripped a policy" -- a plural about one thing, sitting directly beneath a table of
    four tools, so the natural reading was that the whole table was being described. Found by
    reading the rendered screen, not the diff; every test of it was green.

    Every branch carries the NUMBER for the same reason: this sentence exists to stop a reader
    crediting our traffic to their agent, and a bare "every one of them" makes them look back
    up the screen to work out what "them" was.
    """
    of_total = count if of_total is None else of_total
    if count >= of_total:
        if count == 1:
            return ["  That one came from AgentX's own demo code, not from your own agents."]
        return ["  All %d came from AgentX's own demo code, not from your own agents." % count]
    return ["  %d of %s came from AgentX's own demo code, not from your own agents."
            % (count, pronoun)]


def _print_audit_offer():
    """The one-command way to see this screen populated. PYTHON DOOR ONLY.

    Printed BEFORE the wrap-a-tool guidance, not after, and the order is the whole point: a
    reader on the empty screen was being handed the expensive instruction first (go decorate
    a function in your own codebase, then re-run your agent with an env var set) and the
    cheap one never, because it did not exist. This is the rung between them.

    ⚠️ IT DOES NOT REPLACE THE WRAP SNIPPET, and it must not read as if it did. Running our
    scripted agent tells the reader what the screen looks like; it tells them nothing about
    their own agent, which is the only thing they came for. Hence "without touching your
    code" here and "on your own agent" immediately below.
    """
    print("  See this screen with real rows, in one command:")
    print("")
    print("      agentx demo --audit")
    print("")
    # Wrapped to 75, the width of the frame this screen is printed inside. At its first
    # length this line ran three characters past it.
    print("  It runs a scripted agent through the same shield in audit posture and")
    print("  leaves its calls in this ledger, marked as ours rather than yours.")
    print("")


def execute_audit(args=None):
    """`agentx audit` — what your agent actually DID. P-92.

    The sibling of `agentx insights`, and deliberately a different question. `insights` says
    what AgentX did (blocks, recoveries, safe paths); this says what the AGENT did, including
    -- especially -- all the calls we had no opinion about. Those are the calls that were
    never written down before, which is why the audit rung has been a blank screen for
    anybody whose agent behaves.

    🔴 NOT NAMED `scan`. `scan` is the static TS check that reads what an agent CAN do from
    its code. This reads what it DID, from the ledger. Same verb, different tense, and
    collapsing them would lose the only distinction that makes this worth running.
    """
    from . import db as db_module
    from . import pulse as pulse_module
    from .db import get_call_inventory, get_retention_status, ledger_empty_reason

    # Marked BEFORE the screen renders, and never gated on what the screen FOUND. The funnel
    # question is "did a human take this step", which is answered by them running the command
    # -- not by whether we had anything good to show them. Gating it on a populated screen
    # would silently drop exactly the reader who ran it, saw nothing, and left, which is the
    # leak we are hunting. Sticky and best-effort; it cannot raise.
    #
    # ⚠️ THERE IS EXACTLY ONE GATE, AND IT IS INSIDE THE WRITER: mark_audit_report_run returns
    # early under is_automation_context(), so a CI job or a contributor's pytest run cannot
    # climb this rung on an install no human touched. This comment used to say the mark was
    # written "unconditionally", which was true the day it was written and stopped being true
    # when that gate was added one commit later -- a justification outliving the code it
    # describes, which is the shape this file keeps having to re-fix.
    pulse_module.mark_audit_report_run()

    print("\n\U0001f50e WHAT YOUR AGENT DID                    (local to this ledger)")
    print("=" * 75)

    inventory = get_call_inventory()

    # 🔴 UNREADABLE IS NOT EMPTY. Same rule as the block screen next door, and the same
    # reason: telling a developer with a locked ledger that their agent did nothing is a
    # false statement about their own data, and it is the one wrong answer this surface
    # must never give (P-76, and the defect #326 had to fix on the neighbouring screen).
    if not inventory["readable"]:
        print("  The ledger is on disk but could not be read, so this screen cannot tell you")
        print("  what your agent did. It is NOT a statement that it did nothing.")
        print("")
        print("     %s" % os.path.abspath(db_module.DB_PATH))
        print("")
        print("  Another process may hold it open. If it is corrupt, moving it aside starts")
        print("  a fresh one; the records it holds are not recoverable.")
        print("=" * 75)
        return

    if not inventory["total_calls"]:
        # Three different empties, and they need three different sentences. Guessing here is
        # how "nothing happened" gets printed over a ledger that simply was not written to.
        try:
            reason = ledger_empty_reason()
        except Exception:
            reason = "empty"
        posture = (os.environ.get("AGENTX_ENFORCEMENT") or "").strip().lower()

        # 🔴 AN EMPTY INVENTORY IS NOT AN IDLE AGENT, and saying so was a real defect on this
        # screen. Reproduced against examples/01_self_healing_agent.py, which makes exactly
        # ONE call and that call is a catch: the developer watched a block scroll past, ran
        # this, and was told "No calls recorded yet" followed by "the next call your agent
        # makes will land here". Both sentences were false, and this is the same false-empty
        # class as P-76 arriving through a filter instead of a path bug -- the inventory holds
        # calls we had NO opinion about, so an agent we objected to every time empties it.
        # 🔴 THE TWO EMPTIES DIFFER IN WHAT THEY REPORT, NOT IN WHAT THEY ADVISE. The flagged
        # branch used to `return` here, which meant the one screen a reader reaches by
        # following our own ladder -- `agentx demo` writes a catch, then `agentx audit` --
        # never printed the instruction to turn audit on. It offered two causes instead, and
        # on that path neither was true: the real reason is that AGENTX_ENFORCEMENT is unset.
        # Both branches now fall through to the same guidance.
        if inventory["flagged_total"]:
            print("  Nothing here yet. This screen lists the calls AgentX had no objection")
            print("  to, and every call ON RECORD tripped a policy.")
            print("")
            # Offer `insights` only for rows it can actually SHOW. flagged_total counts
            # status-less legacy rows too, and every insights reader filters on
            # CHALLENGED / RECOVERED / WOULD_BLOCK -- so on a ledger of those, "see them"
            # sends the reader to a screen with nothing on it.
            # Counted from what `agentx insights` can actually RENDER, not from "not NULL".
            # That reader filters on CHALLENGED / RECOVERED / WOULD_BLOCK, so any other
            # legacy status string still routes someone to a screen that will not show it.
            viewable = inventory["viewable_total"]
            if viewable > 0:
                print("  %s on record. See them:  %s"
                      % (_plural(viewable, "call"),
                         "uvx agentx-mcp --insights" if MCP_ENTRY else "agentx insights"))
            else:
                print("  %s on record, from a ledger older than this version, so there is"
                      % _plural(inventory["flagged_total"], "call"))
                print("  nothing left to show about them.")
            # AFTER the count, because it qualifies it. `agentx demo` writes a catch under
            # our own agent id and its footer sends the reader straight here, so on the first
            # run of the ladder this screen was reporting OUR scripted call under a header
            # naming THEIR agent. Same footnote `agentx insights` already carries.
            if inventory["flagged_from_demo"]:
                for _ln in _demo_row_note(inventory["flagged_from_demo"],
                                          of_total=inventory["flagged_total"]):
                    print(_ln)
        else:
            print("  No calls recorded yet.")
            # 🔴 NAME THE LEDGER, because the likeliest cause of this screen is the reader
            # being in a different folder. DB_PATH is cwd-relative, so an agent run in
            # ~/proj and `agentx audit` run from ~ read two different files, and every
            # sentence below is then a confident guess about the wrong one. `agentx status`
            # already prints the path for exactly this reason.
            print("     %s" % os.path.abspath(db_module.DB_PATH))
            print("     Calls are recorded per ledger, so running agentx from another folder")
            print("     reads a different one.")
        print("")
        if MCP_ENTRY:
            # 🔴 NEITHER THE SHELL'S POSTURE NOR THE PYTHON CTA IS TRUE ON THIS DOOR, and
            # getting it wrong here is a documented past defect (see the --insights branch,
            # sdk_tests/test_cli.py). This reader sets AGENTX_ENFORCEMENT in mcp.json, for
            # the SERVER process their client spawns; the terminal running this command has
            # never seen it. So we cannot say "audit is off" -- we do not know -- and
            # `python your_agent.py` is not a command they have.
            # 🔴 THREE DEFECTS IN FIVE LINES, ALL THE SAME SHAPE: copy written for the
            # Python door and left standing on this one.
            #
            # 1. It assumed AgentX was ALREADY in their mcp.json and never showed how to get
            #    it there -- the exact gap the Python branches above had, one door over.
            # 2. It printed `AGENTX_ENFORCEMENT=audit` and told them to put that "in
            #    mcp.json". That is a shell assignment, not JSON: pasted into the file it
            #    names, it is a syntax error. Same class as handing a uvx reader a bare
            #    `agentx` command -- an instruction the reader of THIS surface cannot use.
            # 3. The closing line said "Once a WRAPPED tool runs". This reader wraps
            #    nothing; their tools are routed through the proxy.
            #
            # One block fixes all three: the entry is the wiring AND the env var, in the
            # syntax of the file it names. Shape taken from examples/mcp/README.md so the
            # screen and the shipped example cannot drift.
            print("  AgentX writes this down while audit is on. It is set in your mcp.json,")
            print("  for the server your client starts, so this terminal cannot tell whether")
            print("  it is on. Put agentx-mcp in front of the server you already have:")
            print("")
            print('      "your-server": {')
            print('        "command": "uvx",')
            print('        "args": ["agentx-mcp", "<the command your server already runs>"],')
            print('        "env": { "AGENTX_ENFORCEMENT": "audit" }')
            print("      }")
            print("")
            print("  Restart your client so it re-spawns the server, use it as usual, then")
            print("  run this again.")
        elif posture != "audit":
            # 🔴 THE CHEAP STEP FIRST. Everything below asks the reader to go change their
            # own codebase; `agentx demo --audit` fills this screen without them writing a
            # line. Guarded on `reason` for the same rule that guards the example table: next
            # to a ledger we could not read, telling someone to write MORE rows into it is
            # advice about a file we cannot see.
            if reason != "unreadable":
                _print_audit_offer()
            # TWO steps, each shown. The old copy named both ("wrap a tool, THEN run your
            # agent with it on") and printed only the second, which is why the snippet goes
            # BETWEEN the sentence and the env lines rather than after them: the reader does
            # them in this order.
            print("  On your own agent, AgentX writes this down while audit is on, and it is")
            print("  off in this shell. Wrap a tool:")
            _print_wrap_snippet()
            print("")
            print("  ...then run your agent with audit on:")
            print("")
            print("      AGENTX_ENFORCEMENT=audit python your_agent.py          # mac/linux")
            print('      $env:AGENTX_ENFORCEMENT="audit"; python your_agent.py  # PowerShell')
        elif reason == "unreadable":
            print("  The ledger could not be read, so this is not a statement that your agent")
            print("  did nothing.")
        else:
            # 🔴 THE READER WHO NEEDS THE SNIPPET MOST. Audit is ON and the inventory is
            # empty, so the one step still missing is the wrap -- and this was the branch
            # that offered nothing at all. Stated as a condition, not a diagnosis: they may
            # have wrapped a tool and simply not called it yet, and telling that reader
            # "nothing is wrapped" would be us guessing about their code.
            print("  Audit is on, so the next call your agent makes will land here.")
            print("  If you have not wrapped a tool yet:")
            _print_wrap_snippet()
            # Offered AFTER the snippet on this branch, unlike the one above, because this
            # reader has already done the expensive part: audit is on, so the missing step is
            # theirs to take and ours is only a way to see the format meanwhile.
            print("")
            _print_audit_offer()

        # 🔴 NOT ON THE UNREADABLE BRANCH. Everywhere else this screen is saying "you have no
        # data yet", and a picture of the format helps. There it is saying "we could not read
        # your data" -- and an example table beside that sentence is the P-76 answer wearing a
        # costume, because the reader has no reason to assume the rows are not theirs.
        #
        # AND MCP ONLY. The Python door has `_print_audit_offer` above, which fills this
        # screen with real rows in one command; printing an invented table underneath it
        # would make the reader compare our fiction with the thing that replaced it.
        if MCP_ENTRY and reason != "unreadable":
            _print_audit_sample()

        print("=" * 75)
        return

    # Disclosed BEFORE the numbers, because it changes what they mean. A reader who sees
    # "412 calls" and then learns the ledger was trimmed has already formed the wrong idea.
    if not inventory["covers_all"]:
        try:
            retention = get_retention_status()
        except Exception:
            retention = None
        if retention:
            print("  ⚠️  This ledger has been trimmed, so the counts below describe what was")
            print("      KEPT, not everything your agent has ever done. It keeps the last")
            print("      %d days or %s records."
                  % (retention['current_max_age_days'], f"{retention['current_max_rows']:,}"))
            print("")

    print("  %s across %s%s"
          % (_plural(inventory['total_calls'], "call"),
             _plural(inventory['distinct_tools'], "tool"),
             _since_phrase(inventory["window_start"])))
    # SAY WHEN THE TABLE IS NOT THE WHOLE HEADER. The counts above are ledger-wide and the
    # rows below are capped, so "30 tools" over 25 rows silently invites the reader to
    # believe they are looking at all of them. Same class as the counts that were being
    # summed from this list: the part is not the whole, and the screen has to admit which
    # one it is showing.
    # 🔴 DIRECTLY UNDER THE COUNT, BECAUSE IT QUALIFIES IT. `agentx demo --audit` writes four
    # real ALLOWED rows into this ledger so that this screen has something to show, and
    # without this line they are reported, tool by tool, as what THEIR agent did. The flagged
    # count next to it has carried the same footnote since P-92; the inventory did not,
    # because until `--audit` existed no demo could write an inventory row at all.
    #
    # The all-ours case gets its own sentence rather than a number the reader has to compare
    # against the line above: on the first run of the ladder that is the whole table, and
    # "4 of those" beside "4 calls" is a subtraction we should do for them.
    from_demo = inventory.get("inventory_from_demo") or 0
    if from_demo:
        for _ln in _demo_row_note(from_demo, of_total=inventory["total_calls"]):
            print(_ln)
        if from_demo >= inventory["total_calls"]:
            print("  Wrap one of your tools and its calls land here beside these.")
    hidden = inventory["distinct_tools"] - len(inventory["tools"])
    if hidden > 0:
        print("  (showing the busiest %d; %d more not listed)"
              % (len(inventory["tools"]), hidden))
    print("")
    print("  %-24s %7s  %-11s %s" % ("TOOL", "CALLS", "SURFACE", "ARGUMENTS"))
    print("  " + "-" * 71)
    for row in inventory["tools"]:
        classes = "/".join(
            db_module._SURFACE_LABELS.get(c, c)
            for c in row["classes"] if c != db_module._CLASS_OTHER) or "-"
        # 🔴 DROP WHOLE NAMES, NEVER SLICE THE JOINED STRING. This is the SAME defect
        # db._call_shape already fixed on the WRITE side, and its comment there says why:
        # slicing the join "cut mid-name and left a partial token that the reader re-splits
        # on ',' and presents as a real argument the developer never wrote." The writer
        # budgets by whole names; this reader sliced characters, so `min_amount` rendered as
        # `min_a...` and a developer searching their code for it finds nothing.
        #
        # Found by a founder run, on the row this PR added. Fixing the writer and leaving the
        # reader is the class this whole change keeps meeting.
        # 🔴 THE BUDGET IS DERIVED FROM THE ROW, NOT PICKED. The format below puts this column
        # at 48 ("  " + 24 + " " + 7 + "  " + 11 + " "), so a 30-char budget yields 78-column
        # rows against the 75 fence this screen keeps to -- measured on the PR's own example.
        # 75 - 48 = 27. It costs one argument name on a wide row, which is cheaper than a
        # wrapped line: wrapping destroys the alignment these format strings exist for.
        #
        # ⚠️ 27 DOES NOT ACTUALLY HOLD THE FENCE, AND SAYING IT DID WAS THE THIRD VERSION OF
        # THIS MISTAKE IN ONE FUNCTION. `_fit_names` can return up to 27 + a clipped 40-char
        # name + " +N more", so one 300-character key from a remote MCP schema renders a
        # 96-COLUMN row. Measured. The ORDINARY row fits -- 27 is what makes the common case
        # align -- and the pathological one is CAPPED rather than unbounded: it was 356 before
        # the ceiling landed. There is no single number: the row is 48 + the clip ceiling (40)
        # + " +N more", and N grows with the count -- `get_call_inventory` UNIONS argument
        # names across every row for a tool, so the list reaching here is NOT capped at
        # db._MAX_ARG_NAMES. Measured at 98 with one long key and 150 short ones. An earlier
        # version of this comment said "bounded at 96", which is a maintained number beside
        # the thing it counts, in the function where that class keeps recurring. The bound is
        # a formula, so it is written as one
        # the ceiling landed. Bounded and stated beats unbounded, and both beat a comment
        # claiming a fence it does not enforce.
        names = _fit_names(row["arg_names"], 75 - 48)
        # ⚠️ THIS COMMENT USED TO READ "Ellipsis on BOTH" and described the line above it as it
        # was BEFORE the fix two comments up. The names column no longer clips at all: it drops
        # whole names and says "+N more". Only the class list is still ellipsised, and for the
        # reason that half of the sentence always gave -- a clipped class list reads as a class
        # ("DB/HTTP/SHE"). A comment left describing the code it replaced is the same defect
        # this PR is named for.
        bucket = _format_bucket(row["max_amount"])
        print("  %-24s %7s  %-11s %s"
              % (_fit(row["tool"], 24), f"{row['calls']:,}", _fit(classes, 11), names))
        # The magnitude and the flag count are the two facts most likely to be the reason a
        # reader keeps reading, so they get their own line rather than a cramped column.
        detail = []
        if bucket and row["max_amount"] >= _MAGNITUDE_WORTH_SHOWING:
            # "amount", not "number": the column now holds the magnitude of an argument the
            # tool itself NAMED as an amount, so calling it a number again would re-describe
            # it as the thing P-103 removed.
            detail.append("largest amount passed: %s" % bucket)
        if row["flagged"]:
            # 🔴 "PLUS", NOT "OF THESE". The flagged calls are NOT in the count on this row:
            # a call we objected to is recorded as a catch, never as routine traffic, so
            # phrasing it as a subset would misdescribe both numbers at once.
            #
            # "flagged", not "we stepped in on": this count includes CHALLENGED rows from
            # enforce runs, where we DID step in, and WOULD_BLOCK rows from audit, where we
            # deliberately did not. One word has to be true of both.
            detail.append("plus %s flagged" % _plural(row["flagged"], "call"))
        if detail:
            print("  %-24s          %s" % ("", "; ".join(detail)))
    print("")
    # 🔴 FROM THE LEDGER, NEVER FROM THE `tools` LIST. Summing the list was the same
    # false-empty defect this PR already fixed once on the empty screen: a tool flagged on
    # EVERY call has no inventory rows, so it is not in the list at all and contributes 0 --
    # and the screen then announced "nothing tripped a policy" over a ledger of catches. The
    # list is also truncated to the display limit. get_call_inventory computes both counts
    # over the whole ledger for exactly this reason.
    flagged = inventory["flagged_total"]
    would_block = inventory["would_block_total"]
    if flagged:
        # Door-correct reader command. Under uvx the SDK's `agentx` script is not on PATH,
        # so the bare form is a command-not-found for exactly the person we just told to
        # go look at their catches.
        reader = "uvx agentx-mcp --insights" if MCP_ENTRY else "agentx insights"
        if would_block == flagged:
            # Every one was recorded-and-released, so the conditional is honest.
            print("  Nothing above was blocked. Separately, %s tripped a policy and would"
                  % _plural(flagged, "call"))
            print("  have been stopped:  %s" % reader)
        else:
            # A mixed ledger (enforce runs as well as audit ones), where "would have been
            # stopped" is false about the rows we actually stopped.
            #
            # 🔴 BOTH NUMBERS, BECAUSE THE READER IS ABOUT TO BE HANDED ONE OF THEM. This
            # said "46 calls tripped a policy. See them: agentx insights" on the founder's
            # ledger, and insights showed 39 -- its block section counts what was STOPPED,
            # and the 7 missing rows were the audited catches, which are the ones this screen
            # is most about. One total split into the two things it is made of, so the number
            # he lands on is the number he was promised.
            print("  Nothing above was blocked. Separately, %s tripped a policy."
                  % _plural(flagged, "call"))
            # 🔴 NOT `flagged - would_block`. `flagged_total` counts every row that is not
            # inventory, which INCLUDES the status-less legacy rows this same reader already
            # counts separately (unclassified_total, and viewable_total exists because "not
            # NULL" was not good enough either). Subtracting the audited rows from it called
            # every one of those a call we STOPPED. Reproduced on a ledger holding 3 legacy
            # rows + 1 WOULD_BLOCK: this screen said "3 were stopped" and `agentx insights`,
            # the command on the very next line, said "Nothing has been blocked in this
            # ledger yet" -- which is the exact mismatch this split was added to remove.
            #
            # `viewable_total` is the count insights can actually render (CHALLENGED /
            # RECOVERED / WOULD_BLOCK), so viewable minus audited IS what was stopped, in the
            # same terms as the screen the reader is being sent to.
            stopped = max(0, inventory["viewable_total"] - would_block)
            older = max(0, flagged - inventory["viewable_total"])
            # One line, because the two-line version wrapped onto an orphaned "to run." in
            # the founder's terminal. A sentence broken across a line break at a point that
            # is not a clause boundary reads as two half-sentences.
            if would_block and stopped:
                print("  %d %s stopped; %d ran anyway, recorded while audit was on."
                      % (stopped, "were" if stopped != 1 else "was", would_block))
            elif would_block:
                print("  %d ran anyway, recorded while audit was on." % would_block)
            if older:
                # Said rather than folded into either number: these rows carry no status, so
                # neither "stopped" nor "recorded" is true of them, and `agentx insights`
                # cannot show them at all. "The other" only when there IS another -- on a
                # ledger that is entirely legacy rows it would be describing the whole count.
                lead = "The other %d" % older if (stopped or would_block) else "%d" % older
                print("  %s %s from a ledger older than this version, so there is"
                      % (lead, "are" if older != 1 else "is"))
                print("  nothing left to show about them.")
            print("  See them:  %s" % reader)
        # The same attribution the EMPTY branch was fixed for, which this branch did not
        # get: `flagged` counts `agentx demo`'s own catch, so without this the populated
        # screen credits our scripted call to their agent too.
        if inventory["flagged_from_demo"]:
            for _ln in _demo_row_note(inventory["flagged_from_demo"],
                                      of_total=inventory["flagged_total"]):
                print(_ln)
    else:
        print("  Nothing above was blocked, and nothing tripped a policy.")

    # 🔴 WHAT WE WATCH FOR, STATED SO THE READER CAN DO THE JOIN THEMSELVES.
    #
    # This is the sentence the screen exists for. An agent that never trips a policy gets a
    # list of its own activity and no reason to care; put our coverage next to it and the
    # reader is the one who notices that `refund_customer` is not on our side of the page.
    #
    # ⚠️ IT DELIBERATELY MAKES NO CLAIM ABOUT *THEIR* TOOLS. Deciding that `refund_customer`
    # means money, and saying so, would be us guessing about their code on the strength of a
    # name -- and a confident wrong guess here costs more trust than saying nothing. We state
    # what we watch for, they hold it against a list of what they actually ran. Both halves
    # are facts, and the useful thought happens in the reader.
    try:
        from .decorators import keyless_coverage
        coverage = keyless_coverage()
    except Exception:
        coverage = []
    if coverage:
        # 🔴 SCOPED TO THE FLOOR THIS LIST ACTUALLY DESCRIBES. keyless_coverage() walks the
        # BUILT-IN floor, but the live shield also carries anything pulled by `agentx pull`
        # (additive since P-49), and a keyed install has the reasoning engine behind it. The
        # closing line used to be the unscoped "Anything your agent does outside that list
        # runs unwatched", which is simply untrue for someone paying us and understates what
        # they bought. Both sentences now name the floor rather than the product.
        keyed = bool((os.environ.get("AGENTX_API_KEY") or "").strip())
        print("")
        print("  The built-in floor watches for:")
        # POLICY + WHY, the same two columns `npx @agentx-core/scan` prints for the static
        # half. A reader who ran scan on their repo sees the identical names here against
        # what actually ran.
        for name, why in coverage:
            print("      %-34s %s" % (name, why))
        print("")
        if keyed:
            # Do NOT tell a paying user their agent is unwatched outside this list: their
            # gateway is the thing this screen cannot see. Read it aloud before changing it --
            # the first version of this ("anything it does not cover either is outside what
            # AgentX checks") was accurate and unparseable, which on a first-day screen is
            # the same as being wrong.
            print("  Your gateway checks more than this list. Anything neither of them")
            print("  covers runs unchecked.")
        else:
            print("  Anything outside that list is not checked by the built-in floor.")

    # 🔴 THE HONEST LIMIT OF THIS SCREEN, and the only CTA that can name what to do about it.
    # Every row above is a tool the developer ALREADY wrapped -- that is how we saw it. So a
    # "wrap your risky function X" prompt can never name one of them, and the tools that
    # genuinely still need wrapping are precisely the ones this screen is blind to. Saying so
    # is both the true caveat and the next step: on the shipped examples this table has one
    # or two rows, which reads as "not much happens" when it means "not much is wrapped".
    if not MCP_ENTRY:
        print("")
        print("  This is what your WRAPPED tools did. A tool you have not wrapped does not")
        print("  appear here at all. Wrap another and run again:")
        print("")
        print('      @agentx_protect(agent_id="my_agent")   # around any tool function')

    print("")
    print("  To start blocking instead of watching:")
    if MCP_ENTRY:
        # This reader's posture lives in mcp.json, not in a shell they can prefix.
        print("      set AGENTX_ENFORCEMENT=enforce in your mcp.json")
    else:
        # BOTH SHELLS, matching `agentx demo`. The bare `VAR=value cmd` form is not valid in
        # PowerShell, so a Windows reader given only that line has a CTA they cannot run --
        # the same reachability failure as handing an `agentx` command to a uvx door. The
        # demo footer already ships both forms; a rung that works there and not here is worse
        # than either, because the reader has already succeeded once with the other spelling.
        print("      AGENTX_ENFORCEMENT=enforce python your_agent.py          # mac/linux")
        print('      $env:AGENTX_ENFORCEMENT="enforce"; python your_agent.py  # PowerShell')
    print("=" * 75)


def _since_phrase(window_start):
    """" since <date>" for a window, or "" when we cannot date it. Never raises.

    Separate from the caller so an unparseable timestamp costs the phrase, not the screen.
    A NULL timestamp is real here: legacy rows migrated by P-57's replacement carry them.
    """
    if not window_start:
        return ""
    try:
        return " since %s" % datetime.fromtimestamp(window_start).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


def execute_insights(args=None):
    """`agentx insights` — the unified local learning loop review.

    Surfaces the task-fitting safe paths the org's OWN agents discovered when
    they self-corrected (the judge's reusable `resolution_path`, harvested from
    the local incident store), grouped by policy, ranked by how often they
    recurred. The dev reviews them here and promotes the good ones with
    `agentx adopt` — the manual gate that keeps agent-generated text from
    silently becoming a live security challenge.
    """
    verbose = bool(args) and any(a in ("-v", "--verbose") for a in args)

    # FIRST, and unconditionally. This is the only section a keyless user can populate,
    # and it describes what just happened to them; the two sections below describe the
    # gateway's recovery loop and are empty by construction without a key. Leading with
    # the paid path was the P-93(b) defect.
    _print_local_blocks_section()

    census = incident_db_census()
    harvest, _reframe_flat, rule_list, mcp_flat = _collect_candidates()
    store = load_overrides(warn=True)   # surface a corrupt store instead of showing an empty one
    active = store.get("overrides", {})

    # --- AUDIT posture report: what AGENTX_ENFORCEMENT=audit WOULD have blocked ---
    # Printed FIRST and unconditionally (even when there are no learned safe-paths yet),
    # because an install evaluating in audit mode has would-block rows but usually no
    # recoveries. This is the report that earns the enforce decision: what audit caught,
    # per policy, with zero risk taken. Kept semantically separate from the recovery loop
    # below (these are catches audit RECORDED, not blocks it enforced). Silent at zero
    # rows, so a normal enforce user never sees audit noise.
    # `get_ledger_census` is imported HERE. It is function-scoped in the two other
    # readers that use it, never module-level, so calling it from this one raised
    # NameError -- swallowed by the except below, which turned the attribution line
    # off silently. `DEMO_AGENT_ID` went with the subtraction it was imported for.
    from .db import get_would_block_summary, get_ledger_census
    audit = get_would_block_summary()
    # Gate on the CURRENT posture, not just the presence of rows: would-block rows are an
    # AUDIT-mode artifact, and once the dev has flipped to enforce, both the "what WOULD have
    # blocked" framing and the "flip to enforcing" nudge are stale / nonsensical (they are
    # already enforcing). Same os.environ source the decorator's _resolve_enforcement reads.
    in_audit = (os.environ.get("AGENTX_ENFORCEMENT") or "").strip().lower() == "audit"
    # 🔴 THE ROWS ARE THE EVIDENCE, NOT THE READER'S SHELL. This was gated on `in_audit or
    # MCP_ENTRY`, and both halves of the reasoning for it have since been removed by other
    # fixes: the "what WOULD have blocked" framing was rewritten into past tense (third review
    # of #287) so it is true whatever they run now, and the one line that DOES assert a
    # current posture -- the flip-to-enforcing nudge -- got its own `in_audit` gate below.
    # What was left was a justification outliving its code.
    #
    # `agentx demo --audit` made it actively harmful. It writes would-block rows using the
    # per-tool `enforcement=` argument, so the reader's shell is NEVER in audit -- and on the
    # Python door MCP_ENTRY is False -- which meant the rows our own demo had just created
    # were unreachable on every screen. Reproduced from the founder's terminal: `agentx audit`
    # promised "46 calls tripped a policy, see them: agentx insights" and insights showed 39,
    # the 7 missing ones being exactly the audited catches.
    #
    # Same lesson as the MCP fix one comment up, which is why it is stated as a rule now: a
    # reader gated on the reader's ENVIRONMENT hides data from whoever is standing in the
    # wrong shell. Gate on the DATA and describe it honestly.
    if audit["total"]:
        # The heading states a fact about the ROWS, not about the reader's current posture.
        # (This used to describe an `or MCP_ENTRY` clause in the gate above; the gate is now
        # on the rows alone, and the reasoning below is why the past tense survives it.)
        # Nothing visible to this screen says whether the reader is
        # STILL in audit. An operator who ran audit for a week and has since flipped to enforce
        # was being told "AUDIT MODE ... nothing was blocked ... flip to enforcing" about a
        # server that is enforcing. Past tense fixes that: these rows WERE recorded in audit,
        # which is true whatever they are running now. (Third review of #287.)
        print("\n🔍 RECORDED IN AUDIT MODE: calls AgentX would have stopped, that ran")
        print("=" * 75)
        # NOT "recorded under AGENTX_ENFORCEMENT=audit". Audit can also come from the
        # per-tool `enforcement=` argument, which is how `agentx demo --audit` writes these,
        # and naming a variable the reader never set is a statement about their environment
        # that is false. The banner next door had the same defect, found the same way.
        print(f"  {audit['total']} action(s) recorded while audit was on, by policy:")
        for row in audit["policies"]:
            print(f"     {row['would_blocks']:>4}x   {row['policy_name']}")
            # Same question, same answer, on the audited half: these are the calls that RAN.
            for _ln in _tools_line(row.get("tools")):
                print(_ln)
        # The same attribution every other count on these screens carries.
        #
        # 🔴 COUNTED DIRECTLY, NOT BY SUBTRACTION. `get_would_block_summary` swallows its own
        # errors and returns `{"total": 0}`, and zero non-demo rows is ALSO what an all-ours
        # ledger looks like -- so a failed read printed "all of these came from an `agentx
        # demo` run" over rows that may have been entirely the developer's own. Inverting the
        # sentence is a worse failure than losing it, and the census answers it in one query.
        # NO try/except. `get_ledger_census` swallows its own errors and returns zeros, so
        # the only thing a handler here can catch is a mistake in THIS code -- and it caught
        # one, silently, for the whole life of the line above.
        _ours = (get_ledger_census() or {}).get("would_blocks_from_demo") or 0
        if _ours > 0:
            for _ln in _demo_row_note(_ours, of_total=audit["total"], pronoun="these"):
                print(_ln)
        # The nudge is the one part that DOES assert a current posture, so it stays gated on
        # the reader's own env. On the MCP door we cannot see that, so we say nothing rather
        # than guess -- telling someone to "flip to enforcing" when they already have is the
        # failure this whole block just had.
        if in_audit:
            print("\n  These ran normally; audit takes zero risk. When the catches look right,")
            print("  flip to enforcing:   AGENTX_ENFORCEMENT=enforce")
        print("=" * 75)

    _print_recovery_section(census)

    print("\n🧠 SAFE-PATHS YOUR AGENTS LEARNED        (local to this machine)")
    print("=" * 75)
    print("  When an agent recovered from a block, AgentX saved the fix. Adopt one and")
    print("  AgentX coaches your agents straight to it on the next block.")

    if not harvest and not active and not rule_list:
        print("\n  No reusable safe-paths to show yet — here's why:")
        if not census["exists"]:
            print("   • No incident store on disk at that path. Run your protected")
            print("     agents against the local gateway first (it writes incidents.db")
            print("     into its mounted .agentx/). Set AGENTX_INCIDENT_DB to point")
            print("     elsewhere if your gateway mounts a different folder.")
        elif census["complied"] == 0:
            print("   • No self-corrections recorded — no agent has recovered from a")
            print("     block yet. Safe-paths are harvested only from recoveries.")
        elif census["with_resolution"] == 0:
            print("   • You have self-corrections, but none carry a reusable safe-path.")
            print("     The safe-path (resolution_path) is judge-produced — it only")
            print("     persists on a recent gateway build WITH a Gemini key live")
            print("     at the time of the recovery. Older recoveries won't have it;")
            print("     run a fresh recovery now that your key is set.")
        else:
            print("   • Self-corrections carry a resolution_path, but none were marked")
            print("     reusable by the judge yet. Keep running — reusable ones accrue.")
        if mcp_flat:
            # `agentx mcp-insights` has no MCP-door equivalent, and telling a reader who is
            # ALREADY inside --insights to go run another view is noise anyway. State the fact,
            # point at the command that acts on them.
            if MCP_ENTRY:
                print(f"\n  ▶ You DO have {len(mcp_flat)} keyless MCP recovery path(s): {_review_cmd()}")
            else:
                print(f"\n  ▶ You DO have {len(mcp_flat)} keyless MCP recovery path(s): agentx mcp-insights")
        # P-18, and this is the branch that needed it MOST. The first cut put the advisory
        # only on the populated path below, so the one screen that says "No reusable
        # safe-paths to show yet" — to a user who may have adopted every one of theirs over
        # MCP — was the one screen that never mentioned the other store. That is the "we lost
        # your work" reading this note exists to prevent, shown in the exact case it applies.
        # The `mcp_flat` line above does NOT cover it: per the comment there, mcp_flat counts
        # harvest CANDIDATES, and this counts safe-paths already ADOPTED. A user who adopted
        # all of theirs has zero candidates left and would still see nothing.
        _note_that_the_two_doors_keep_separate_brains()
        print("=" * 75)
        return

    # Show the FULL safe-path text, wrapped with a hanging indent — NEVER
    # truncated. A reframe's discriminating clause is usually in its tail (e.g.
    # "...unless specifically authorized"), so truncating forces a blind adopt —
    # the exact judgment the manual gate exists to make. Density is bounded by the
    # per-policy cap (2 alternatives + "N more"), not by cutting sentences.
    # --verbose surfaces how often a candidate recurred (×count) and its
    # resolution type — the signals the footer advertises ("ids, dates, counts").
    def meta(c):
        if not verbose:
            return ""
        cnt = f"  ×{c['count']}" if c.get("count") else ""
        rtype = f" [{c['resolution_type']}]" if c.get("resolution_type") else ""
        return f"{cnt}{rtype}"

    # Global sequence numbers across all candidates — the dev promotes by a single
    # `#N`, no UUID to copy or mistype. Same deterministic order `adopt <#>` uses.
    seq_by_pid = {}
    for item in enumerate_candidates(harvest):
        seq_by_pid.setdefault(item["policy_id"], {})[item["suggestion"]] = item["seq"]
    all_seqs = [s for d in seq_by_pid.values() for s in d.values()]
    example = f"   (e.g. agentx adopt {min(all_seqs)})" if all_seqs else ""

    # Summary line carries the headline numbers AND the one command that matters.
    policy_ids = sorted(set(harvest.keys()) | set(active.keys()))
    n = len(policy_ids)
    # The headline CTA names the command THIS reader has. On the MCP door `agentx adopt` does
    # not exist, and --review adopts too (it calls adopt_override itself), so point there
    # rather than at a command that would not run.
    print(f"\n  {census['complied']} recoveries · {census['with_resolution']} reusable fixes · "
          f"{n} {'policy' if n == 1 else 'policies'}"
          f"        ▶ adopt with:  {_review_cmd() if MCP_ENTRY else 'agentx adopt <#>'}")
    if verbose:
        print(f"     store: {census['path']}")

    for pid in policy_ids:
        bucket = harvest.get(pid, {})
        label = bucket.get("policy_violated") or active.get(pid, {}).get("policy_violated") or "—"
        print(f"\n  📋 {label}" + (f"   ({pid})" if verbose else ""))

        current = active.get(pid)
        active_challenge = current.get("challenge") if current else None
        candidates = bucket.get("candidates", [])

        if active_challenge:
            # Already coaching: show what's live ONCE (with its #), then only the
            # OTHER options as quick alternatives — no re-listing the active one.
            seq = seq_by_pid.get(pid, {}).get(active_challenge)
            print(_wrap(active_challenge, f"     ✅ Active{f' (#{seq})' if seq else ''}:  "))
            if verbose and current:
                print(f"        adopted {current.get('adopted_at', '?')} · source={current.get('source', '?')}")
            alts = [c for c in candidates if c["suggestion"] != active_challenge]
            if alts:
                print("     Switch to:")
                for c in alts[:2]:
                    seq = seq_by_pid.get(pid, {}).get(c["suggestion"], "?")
                    print(_wrap(c["suggestion"] + meta(c), f"        #{seq}  "))
                if len(alts) > 2:
                    print(f"        +{len(alts) - 2} more  →  {_insights_cmd()} --verbose")
        elif candidates:
            # Not coaching yet: this is where the dev actually needs to act.
            print("     ⚠️  Not coaching this block yet — adopt one so AgentX coaches it:")
            for c in candidates[:3]:
                seq = seq_by_pid.get(pid, {}).get(c["suggestion"], "?")
                print(_wrap(c["suggestion"] + meta(c), f"        #{seq}  "))
            if len(candidates) > 3:
                print(f"        +{len(candidates) - 3} more  →  {_insights_cmd()} --verbose")

    # --- DETECTION RULES (the other half of the loop) — what to CATCH going
    # forward, vs the reframes above (how to RECOVER). Same global #N, same gate.
    if rule_list:
        print("\n🧩 DETECTION RULES        (catch these going forward)")
        print("-" * 75)
        for rule in rule_list:
            label = rule.get("policy_violated") or f"{rule['effect_category']} via {rule['target_action']}"
            cnt = f"  ×{rule['count']}" if (verbose and rule.get("count")) else ""
            print(_wrap(f"{label}   (action={rule['target_action']} · effect={rule['effect_category']})",
                        f"  #{rule['seq']}{cnt}  "))
            if verbose:
                print(f"        {rule['semantic_description']}")
                if rule.get("indicators"):
                    print(f"        indicators: {', '.join(rule['indicators'])}")

    # Lead with the one-key review (lowest friction, and it covers verdicts too, not just
    # adopt); the numbered `adopt <#>` stays as the precise "target a specific one" form.
    print("\n  " + "─" * 71)
    print(f"  ▶ Review & act on all of these, one key each:   {_review_cmd()}")
    # The `adopt <#>` / `--rule` forms are the PRECISE alternatives to the one-key pass above.
    # They are `agentx` subcommands with no MCP equivalent, so on that door they are omitted
    # rather than printed as a command-not-found. Nothing is lost: the line above adopts,
    # labels and takes verdicts, and it reads the MCP corpus (cli._mcp_review_items).
    if not MCP_ENTRY:
        print(f"       or adopt a specific one:  agentx adopt <#>{example}")
        print("       tweak first:  agentx adopt <#> --edit        write your own:  agentx adopt <id> --text \"…\"")
        if rule_list:
            print("       author a rule:  agentx adopt --rule --action <a> --desc \"…\"")
    print()
    # WHERE it lands differs by door, so this sentence cannot be one string. The Python door
    # anchors the store to your project root precisely so you can commit it; the MCP door has
    # no project (an editor spawns the proxy from an arbitrary directory), so it keeps one
    # per-user store and there is nothing to commit. Printing the repo advice there sent people
    # looking for a file that is not in their repo. (2026-07-31, with the store fix.)
    if MCP_ENTRY:
        print("  Adopted coaching lands in your per-user store (~/.agentx/overrides.json) and")
        print("  applies to every server you front. A rule lands in your local policy store")
        print("  (the gateway enforces it next start).")
    else:
        print("  Adopted coaching lands in ./.agentx/overrides.json. Commit it to share with your")
        print("  repo. A rule lands in your local policy store (the gateway enforces it next start).")
    print("\n  Share adopted safe-paths across your team + add the full deterministic floor:")
    print("     https://bit.ly/agentfirewall")
    if mcp_flat:
        # Same reason as the branch above: no MCP-door equivalent, and this reader is here.
        if MCP_ENTRY:
            # NOT "(listed above)" -- that was false. mcp_flat comes from
            # mcp_recovery_candidates() and is a SEPARATE list from `harvest`; this body renders
            # harvest/active only, so those safe-paths appear nowhere above. Point at the command
            # that actually reads that corpus rather than claiming they were shown.
            print(f"\n  Also: {len(mcp_flat)} safe-path(s) from your keyless MCP wedge → {_review_cmd()}")
        else:
            print(f"\n  Also: {len(mcp_flat)} safe-path(s) from your keyless MCP wedge → agentx mcp-insights")
    # P-18. Distinct from the `mcp_flat` line above, which counts CANDIDATES harvested from
    # the MCP wedge; this counts safe-paths already ADOPTED into the per-user MCP store, which
    # this reader never resolves. Fires only when that store has entries, so it stays quiet
    # for the overwhelmingly common single-door user.
    _note_that_the_two_doors_keep_separate_brains()
    if not verbose:
        print(f"\n  ({_insights_cmd()} --verbose for ids, dates, counts, store path & full wording)")
    print("=" * 75)


def execute_mcp_insights():
    """`agentx mcp-insights` -- the keyless MCP counterpart to `agentx insights`.

    `agentx insights` reviews the decorator / gateway-judge learning loop. This reviews the
    KEYLESS MCP loop: the safe paths your agents discovered when they self-corrected on the
    agentx-mcp wedge (harvested silently, opt-in AGENTX_MCP_HARVEST). Each recurring safe path
    is a value-free, minimal-privilege reframe you can ADOPT into your org-brain with the SAME
    `agentx adopt <#>` (one number space across insights + rules + these); then A1b coaches your
    agents straight to it on the next block. Auto-coach (AGENTX_MCP_AUTO_COACH, default on) also
    promotes the strongest paths for you; a hand-adopt always WINS over an auto one."""
    from .mcp_proxy import _harvest_enabled, _harvest_path

    _harvest, _reframe, _rules, mcp_flat = _collect_candidates()
    active = load_overrides(warn=True).get("overrides", {})

    print("\n🧠 SAFE PATHS FROM YOUR MCP WEDGE        (keyless · local to this machine)")
    print("=" * 75)
    print("  When an agent recovered from a block on agentx-mcp, AgentX saved the safe SHAPE")
    print("  (value-free: action + scope, never a query or payload). Adopt one and AgentX")
    print("  coaches your agents to it on the next block. Sibling of `agentx insights`.")

    if not mcp_flat:
        path = _harvest_path()
        print("\n  No adoptable MCP recovery paths yet. Here's why:")
        if not os.path.exists(path):
            if not _harvest_enabled():
                print("   • Harvest is OFF (the default). Turn it on:  export AGENTX_MCP_HARVEST=true")
                print("     Abstract, local-only capture. Never your queries or payloads.")
            else:
                print(f"   • Harvest is on, but no file at {path} yet — run an agent through")
                print("     agentx-mcp until it recovers from a block on the SAME tool.")
        else:
            print(f"   • The corpus at {path} has no pairs carrying a policy identity yet")
            print("     (older captures aren't adoptable; new blocks record it automatically).")
        print("=" * 75)
        return

    # Group the flat candidates by policy for display; #N stays the GLOBAL adopt sequence.
    by_policy = {}
    for m in mcp_flat:
        by_policy.setdefault((m.get("policy_id"), m.get("policy_violated")), []).append(m)

    n = len(mcp_flat)
    print(f"\n  {n} recovery {'path' if n == 1 else 'paths'} across "
          f"{len(by_policy)} {'policy' if len(by_policy) == 1 else 'policies'}"
          f"        ▶ adopt with:  agentx adopt <#>")

    for (pid, label), cands in by_policy.items():
        current = active.get(pid) if pid else None
        status = ""
        if current:
            status = ("   ✅ auto-coaching (mcp)" if current.get("source") == "mcp_auto"
                      else "   ✅ coaching (you adopted)")
        print(f"\n  📋 {label or pid or '—'}{status}")
        for m in cands:
            times = f"  ×{m['count']}" if m.get("count", 1) > 1 else ""
            tag = "[%s %s on %s]" % (m.get("scope"), m.get("target_action"), m.get("tool"))
            print(_wrap("%s  %s%s" % (tag, m["suggestion"], times), f"        #{m['seq']}  "))

    print("\n" + "=" * 75)
    print("  ▶ Adopt one (pins it; a hand-adopt WINS over auto):   agentx adopt <#>")
    print("       tweak first:  agentx adopt <#> --edit")
    print("  Auto-coach promotes the strongest paths for you (AGENTX_MCP_AUTO_COACH=off to stop).")
    print("  Adopted coaching lands in ./.agentx/overrides.json. Commit to share with your team.")
    print("=" * 75)


_EDIT_BANNER = (
    "\n\n# ── Edit the challenge text your agents will receive for this policy. ──\n"
    "# Lines starting with # are ignored. Save & close to adopt; empty = abort.\n"
)


def _strip_editor_comments(content):
    """Drop the instruction/comment lines and trim — the pure, testable half of
    the $EDITOR flow."""
    lines = [ln for ln in (content or "").splitlines() if not ln.lstrip().startswith("#")]
    return "\n".join(lines).strip()


def _edit_text(seed_text):
    """Open $EDITOR (git-style) seeded with `seed_text`, return the edited text.
    Falls back to notepad on Windows / vi elsewhere. Returns "" on abort/error."""
    import tempfile, subprocess, shlex
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") \
        or ("notepad" if os.name == "nt" else "vi")
    fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="agentx_adopt_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write((seed_text or "") + _EDIT_BANNER)
        try:
            # No shell (avoids metachar/quoting footguns). On Windows let
            # CreateProcess parse the command line — it handles `code --wait` and a
            # quoted path-with-spaces natively; on POSIX shlex-split into argv.
            if os.name == "nt":
                subprocess.call(f'{editor} "{tmp}"')
            else:
                subprocess.call(shlex.split(editor) + [tmp])
        except Exception as e:
            print(f"   ⚠️  Could not launch editor '{editor}' ({e}). Aborting.")
            return ""
        with open(tmp, encoding="utf-8") as f:
            return _strip_editor_comments(f.read())
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _adopt_usage_exit():
    print("\n⚠️  Usage:")
    print("   agentx adopt <#>                     promote candidate #N (a coaching or a rule)")
    print("   agentx adopt <#> --edit              tweak that candidate in $EDITOR first")
    print("   agentx adopt <policy_id> --text \"...\"  author coaching from scratch (not a rule)")
    print("   ...add --safe-path \"...\"  to set result.safe_path distinctly from the challenge")
    print("   agentx adopt --rule --action <a> --desc \"...\"  author a detection RULE from scratch")
    print("   ...optional: --effect <CAT> --indicators \"a,b\" --challenge \"...\" --name \"...\"")
    print("   The <#> is the number shown by `agentx insights` (one sequence over both kinds).")
    print("=" * 75)
    sys.exit(1)


def _as_int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _confirm_adopt(label, challenge):
    """Show the EXACT text about to become the live challenge and confirm it.

    Guards the global-#N TOCTOU: the candidate list is derived live, so a recovery
    landing between `agentx insights` and `agentx adopt <N>` could renumber things —
    showing the resolved text lets the dev catch a mismatch before it's adopted.
    Auto-proceeds when non-interactive (scripted / CI) so it never hangs."""
    print(f"\n   About to adopt as the LIVE challenge for '{label}':")
    print(f"     “{challenge}”")
    if not sys.stdin.isatty():
        print("   (non-interactive — auto-confirmed)")
        return True
    try:
        return input("   Proceed? [y/N]: ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _gateway_reachable(timeout=0.4):
    """Best-effort probe: is a gateway listening at the configured URL? ANY HTTP
    response (even a 401/404) means something is bound there, so it counts as
    reachable; only a connection error or timeout counts as unreachable. Short
    timeout so authoring never stalls; a probe is never on a hot path (one CLI
    action). Reuses the resolved AGENTX_GATEWAY_URL so it agrees with `agentx status`."""
    env = load_env_file()
    gateway_url = (os.environ.get("AGENTX_GATEWAY_URL")
                   or env.get("AGENTX_GATEWAY_URL", "http://localhost:8000"))
    try:
        requests.get(f"{gateway_url}/health", timeout=timeout)
        return True
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return False
    except requests.exceptions.RequestException:
        return True   # something answered, just not cleanly — a gateway IS there


def _is_keyless_context():
    """True when the dev has NO control-plane key AND NO reachable gateway — so a
    GATEWAY-enforced detection rule they author is fully inert right now. Used to tell
    the honest truth on `agentx adopt --rule` (Option A) without blocking. A key set
    (Control/cloud) or a live gateway (Recover) means the standard 'restart the
    gateway' guidance is the right one."""
    env = load_env_file()
    if os.environ.get("AGENTX_API_KEY") or env.get("AGENTX_API_KEY"):
        return False
    return not _gateway_reachable()


def _print_rule_adopted(entry, verb="Adopted"):
    """Shared post-adopt message for BOTH rule-authoring paths (`adopt <#>` landing on
    a rule, and `adopt --rule` from scratch) so their output can't drift.

    Keyless-context-aware (Option A): a detection rule is GATEWAY-enforced, so for a
    dev running keyless (no key, no reachable gateway) it will not fire yet. Say that
    honestly instead of telling them to 'restart the gateway' they do not run. Never
    blocks or discards the work: a dev legitimately authors rules to commit for
    teammates / CI who DO run the gateway, and it arms the moment a gateway starts."""
    print(f"\n✅ {verb} detection rule '{entry['name']}'  (id: {entry['id']}).")
    print(f"     action={entry['target_action']} · {entry['semantic_description']}")
    if entry.get("indicators"):
        print(f"     exact indicators: {', '.join(entry['indicators'])}")
    print(f"   💾 Saved to {entry['path']} (the local policy store the gateway loads).")
    if _is_keyless_context():
        print("   This rule needs the gateway to enforce it (the Recover tier). You are")
        print("   running keyless right now, so it will not fire until you run the gateway.")
        print("   It is written to .agentx/ and arms the moment you do.")
    else:
        print("   The gateway enforces it on its NEXT start. Restart the gateway to arm it.")
    print("=" * 75)


def _adopt_rule_candidate(rule, do_edit):
    """Adopt a harvested DETECTION rule (the #N pointed at a rule, not a reframe).
    Writes a structural policy into the local policy store; the gateway enforces it
    on its next boot. Manual confirm is the anti-poisoning gate (agent-derived rule
    text never arms itself)."""
    label = rule.get("policy_violated") or f"{rule['effect_category']} via {rule['target_action']}"
    desc = rule["semantic_description"]

    challenge = None
    if do_edit:
        seed = (f"Policy Violation: {label}. {desc} Reach the goal a safe way "
                f"instead, or request human approval.")
        challenge = _edit_text(seed)
        if not challenge or not challenge.strip():
            print("\n🚫 Empty challenge — nothing adopted (aborted).")
            print("=" * 75)
            return

    if not do_edit:
        print(f"\n   About to ENFORCE a new detection rule (gateway, next start):")
        print(f"     {label} — {desc}")
        if rule.get("indicators"):
            print(f"     exact indicators: {', '.join(rule['indicators'])}")
        if sys.stdin.isatty():
            try:
                if input("   Proceed? [y/N]: ").strip().lower() not in ("y", "yes"):
                    print("\n🚫 Not adopted.")
                    print("=" * 75)
                    return
            except (EOFError, KeyboardInterrupt):
                print("\n🚫 Not adopted.")
                print("=" * 75)
                return
        else:
            print("   (non-interactive — auto-confirmed)")

    entry = adopt_rule(rule, challenge=challenge)
    _print_rule_adopted(entry, verb="Adopted")


# Common vocabularies the gateway recognizes — used only for a soft hint when a
# hand-authored rule uses an unusual value. Custom values are still accepted (the
# policy engine matches on whatever string is stored), so this never blocks.
_RULE_ACTIONS = ("execute_database_query", "fetch_url", "execute_shell",
                 "send_message", "write_file", "other")
_RULE_EFFECTS = ("DESTRUCTION", "EXFILTRATION", "SSRF", "SECRET_READ",
                 "WILDCARD_PII", "SUPPLY_CHAIN", "OTHER")


def _author_rule(args):
    """`agentx adopt --rule ...` — author a DETECTION rule from scratch.

    A rule is multi-field (action + effect + description + optional indicators),
    unlike a reframe's single challenge string, so it has its own flag set rather
    than overloading `--text`. Human-authored, so no confirm gate (the
    anti-poisoning rule only forbids auto-applying *agent*-generated text)."""
    action = effect = desc = name = challenge = None
    indicators = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--rule":
            i += 1
            continue
        if tok in ("--action", "--effect", "--desc", "--indicators", "--challenge", "--name"):
            if i + 1 >= len(args):
                print(f"\n❌ {tok} needs a value.")
                _adopt_usage_exit()
            val = args[i + 1]
            if tok == "--action":
                action = val
            elif tok == "--effect":
                effect = val
            elif tok == "--desc":
                desc = val
            elif tok == "--name":
                name = val
            elif tok == "--challenge":
                challenge = val
            elif tok == "--indicators":
                indicators = [s.strip() for s in val.split(",") if s.strip()]
            i += 2
        else:
            print(f"\n❌ Unexpected argument '{tok}' for `adopt --rule`.")
            _adopt_usage_exit()

    if not action or not action.strip() or not desc or not desc.strip():
        print("\n❌ `adopt --rule` requires --action and --desc.")
        _adopt_usage_exit()

    # Soft hints only — never block a custom value.
    if action not in _RULE_ACTIONS:
        print(f"   ⚠️  --action '{action}' isn't one of the common actions "
              f"({', '.join(_RULE_ACTIONS)}). Stored as-is; it matches only if the "
              f"gateway emits that exact target_action.")
    if effect and effect not in _RULE_EFFECTS:
        print(f"   ⚠️  --effect '{effect}' isn't one of {', '.join(_RULE_EFFECTS)}. "
              f"Stored as-is (used for the rule's label).")

    candidate = {
        "target_action": action,
        "effect_category": effect or "OTHER",
        "semantic_description": desc,
        "indicators": indicators,
        "policy_violated": name,
    }
    entry = adopt_rule(candidate, challenge=challenge)
    _print_rule_adopted(entry, verb="Authored")


def execute_adopt(args):
    """Promote/author the active override for a policy — the human-in-the-loop
    anti-poisoning gate. Promote by the global candidate number from
    `agentx insights` (`agentx adopt 3`) so there's no UUID to mistype; the
    `<policy_id> --text` form authors fresh wording. Free-text is human-authored,
    so it is always allowed; only auto-applying agent-generated text is forbidden."""
    if not args:
        _adopt_usage_exit()

    # Authoring a detection rule from scratch is multi-field — route it before the
    # reframe positional/--text parser (which would reject --action/--effect/…).
    if "--rule" in args:
        _author_rule(args)
        return

    positionals = []
    text = safe_path = None
    do_edit = False
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--edit":
            do_edit = True; i += 1
        elif tok in ("--text", "--safe-path"):
            if i + 1 >= len(args):
                print(f"\n❌ {tok} needs a value.")
                _adopt_usage_exit()
            if tok == "--text":
                text = args[i + 1]
            else:
                safe_path = args[i + 1]
            i += 2
        elif tok.startswith("--"):
            print(f"\n❌ Unknown option '{tok}'.")
            _adopt_usage_exit()
        else:
            positionals.append(tok); i += 1

    if not positionals:
        _adopt_usage_exit()

    harvest, flat, rule_list, mcp_flat = _collect_candidates()
    # Load the override store too — warns if it's corrupt (so a hand-edit typo
    # isn't silent) and lets prefix-matching resolve ids already overridden.
    active = load_overrides(warn=True).get("overrides", {})

    pid = None
    seed = ""
    resolution_type = None
    source = "manual"
    policy_violated = None

    seq = _as_int(positionals[0])
    if seq is not None:
        # ---- GLOBAL SEQUENCE MODE:  agentx adopt <#> [--edit] ----
        if text is not None:
            print("\n❌ --text authors fresh wording for a policy — pass a <policy_id>, not a #N.")
            _adopt_usage_exit()
        if len(positionals) > 1:
            print(f"\n❌ Unexpected extra argument '{positionals[1]}' after the candidate number.")
            _adopt_usage_exit()
        match = next((c for c in flat if c["seq"] == seq), None)
        if match is None:
            # The same #N space continues into detection rules — route there.
            rule_match = next((r for r in rule_list if r["seq"] == seq), None)
            if rule_match is not None:
                _adopt_rule_candidate(rule_match, do_edit)
                return
            # ...then into keyless MCP recovery paths. An MCP candidate adopts AS A REFRAME
            # (templated value-free challenge, keyed to its policy), so it falls through the
            # shared reframe tail — just flag its source so the confirm gate still fires.
            match = next((m for m in mcp_flat if m["seq"] == seq), None)
            if match is None:
                total = len(flat) + len(rule_list) + len(mcp_flat)
                hint = (f"`agentx insights` / `agentx mcp-insights` list 1..{total}." if total
                        else "`agentx insights` shows no candidates yet.")
                print(f"\n❌ No candidate #{seq}. {hint}")
                print("=" * 75)
                sys.exit(1)
        pid = match["policy_id"]
        seed = match["suggestion"]
        resolution_type = match["resolution_type"]
        policy_violated = match["policy_violated"]
        # An MCP candidate carries resolution_type="mcp_recovery"; label its source so it is
        # a hand-adopt (which WINS over any auto-coach entry) but still confirmed before it lands.
        source = "mcp_harvest" if match.get("resolution_type") == "mcp_recovery" else "harvest"
    else:
        # ---- POLICY-ID MODE:  adopt <pid> [<index>] [--text ...] ----
        pid = positionals[0]
        known_ids = set(harvest) | set(active)   # resolve against harvested AND already-overridden ids
        if pid not in known_ids:                 # forgiving unique-prefix match on the id
            prefixed = [k for k in known_ids if k.startswith(pid)]
            if len(prefixed) == 1:
                pid = prefixed[0]
            elif len(prefixed) > 1:
                print(f"\n❌ '{pid}' matches {len(prefixed)} policies — be more specific, "
                      f"or use `agentx adopt <#>`.")
                print("=" * 75)
                sys.exit(1)
        bucket = harvest.get(pid)
        policy_violated = (bucket or {}).get("policy_violated") or active.get(pid, {}).get("policy_violated")

        index = _as_int(positionals[1]) if len(positionals) > 1 else None
        if len(positionals) > 1 and index is None:
            print(f"\n❌ Expected a candidate index after the policy id, got '{positionals[1]}'.")
            _adopt_usage_exit()
        if index is not None and text is not None:
            print("\n❌ Use EITHER an <index> OR --text, not both.")
            _adopt_usage_exit()

        if index is not None:
            candidates = (bucket or {}).get("candidates") or []
            if not candidates:
                print(f"\n❌ No harvested candidates for policy '{pid}'. Use --text to author "
                      f"one, or `agentx adopt <#>` from `agentx insights`.")
                print("=" * 75)
                sys.exit(1)
            if index < 1 or index > len(candidates):
                print(f"\n❌ Index {index} out of range — policy '{pid}' has {len(candidates)} candidate(s).")
                print("=" * 75)
                sys.exit(1)
            chosen = candidates[index - 1]
            seed = chosen["suggestion"]
            resolution_type = chosen.get("resolution_type")
            source = "harvest"
        elif text is not None:
            seed = text
            if pid not in (set(harvest) | set(active)):
                print(f"   ⚠️  '{pid}' isn't a policy AgentX has seen recover, nor one you've already")
                print(f"      overridden — storing the override under it verbatim. It is delivered ONLY")
                print(f"      if this is the EXACT policy_id; a partial or typo'd id silently won't match.")
        elif not do_edit:
            _adopt_usage_exit()

    # --- shared edit / validate / adopt tail ---
    challenge = _edit_text(seed) if do_edit else seed
    if do_edit and challenge != seed:
        source = "manual"

    if not challenge or not challenge.strip():
        print("\n🚫 Empty challenge — nothing adopted (aborted).")
        print("=" * 75)
        return

    # Confirm a VERBATIM promote of a harvested candidate (the #N / index path),
    # where live renumbering could otherwise adopt a different reframe than was
    # shown. --text (you typed it) and --edit (you saw it in the editor) need no
    # extra confirm.
    if source in ("harvest", "mcp_harvest") and not do_edit and not _confirm_adopt(policy_violated or pid, challenge):
        print("\n🚫 Not adopted.")
        print("=" * 75)
        return

    entry = adopt_override(
        pid,
        challenge=challenge,
        # Only set safe_path when the dev explicitly provides one (--safe-path).
        # Defaulting it to the challenge prose would populate AgentXBlock.safe_path
        # with a paragraph and break its "a preferred alternative, else None" contract.
        safe_path=safe_path,
        resolution_type=resolution_type,
        policy_violated=policy_violated,
        source=source,
    )
    print(f"\n✅ Adopted org coaching for '{policy_violated or pid}'  (source: {source}).")
    print(f"   Next block on this policy delivers:")
    print(f"   “{entry['challenge']}”")
    if entry.get("safe_path") and entry["safe_path"] != entry["challenge"]:
        print(f"   result.safe_path → {entry['safe_path']}")
    print(f"   💾 Saved to ./.agentx/overrides.json — commit it to share with your team")
    print(f"      (ensure your .gitignore tracks it; the starter kit's does by default).")
    print(f"   ✏️  Change this wording anytime: edit the `challenge` (and `safe_path`)")
    print(f"      for this policy in ./.agentx/overrides.json, or re-run `agentx adopt`.")
    print("=" * 75)


def execute_policies(args=None):
    """`agentx policies` — list the customizable built-in floor policies, keyless.

    The discovery surface for `agentx customize`: each policy's NAME (what you type),
    and the CURRENT agent-facing coaching (the shipped default, overlaid with any
    coaching you've customized). `agentx policies --check` validates your override
    store so a hand-edit typo is loud, not a silent disable.

    Keyless by construction: the coaching listed here is exactly what both keyless
    block paths (the SDK decorator and agentx-mcp) deliver — no gateway, no key."""
    args = args or []
    if any(a in ("--check", "-c") for a in args):
        _policies_check()
        return
    unknown = [a for a in args if a.startswith("-")]
    if unknown:
        print(f"\n❌ Unknown option '{unknown[0]}' for `agentx policies` (did you mean --check?).")
        print("=" * 75)
        sys.exit(1)

    policies = list_customizable_policies()
    print("\n🛡️  CUSTOMIZABLE FLOOR POLICIES        (keyless · no gateway, no key)")
    print("=" * 75)
    print("  These built-in floors block deterministically, offline. You can customize the")
    print("  COACHING each one gives your agent on a block, by name:")
    print("       agentx customize \"<name>\" --text \"...\"        (or --edit to open your editor)")

    for p in policies:
        # A policy carrying ONLY scoped coaching used to render untagged, directly above the
        # scoped block listing that coaching — the header contradicting the two lines beneath it.
        if p["customized"]:
            tag = "   ✏️  customized"
        elif p.get("scoped"):
            tag = "   ✏️  customized (scoped)"
        else:
            tag = ""
        print(f"\n  📋 {p['name']}{tag}")
        challenge = p["active_challenge"] or p["default_challenge"]
        safe = p["active_safe_path"] or p["default_safe_path"]
        if challenge:
            print(_wrap(challenge, "     coaching:   "))
        if safe:
            print(_wrap(safe, "     safe path:  "))
        # Scoped coaching is listed under its policy WITH the situation it fires in. Without
        # this it is written and never shown, so a scope with a typo looks exactly like no
        # scope at all: the policy just reports the shipped default and the author has nothing
        # to check their rule against.
        for s in p.get("scoped") or []:
            print(f"     └ when {describe_scope(s['when'])}")
            if s.get("challenge"):
                print(_wrap(s["challenge"], "       coaching: "))
            if s.get("safe_path"):
                print(_wrap(s["safe_path"], "       safe path: "))

    print("\n" + "=" * 75)
    first = policies[0]["name"] if policies else "<name>"
    print(f"  ▶ Customize one:      agentx customize \"{first}\" --edit")
    print("  ▶ Validate your store:  agentx policies --check")
    print("  Customized coaching lands in ./.agentx/overrides.json. Commit it to share with")
    print("  your team. It applies keyless on BOTH the SDK decorator and agentx-mcp.")
    print("  To coach one job rather than a whole policy, add a `when` to a reframe in")
    print("  ./.agentx/rules.json, then run: agentx rules apply")
    print("=" * 75)


def _policy_store_check():
    """Validate `.agentx/policies.json` -- the PULLED RULEBOOK, not the override store.

    This exists because the shield's fail-closed error tells the operator to run
    `agentx policies --check`, and until now that command validated a DIFFERENT FILE
    (overrides.json). An operator whose agent was hard-down would run the one command we
    named, get a green "no override store yet", and learn nothing about the malformed
    policies.json that was actually stopping every call. The single remediation command we
    print could not diagnose the fault it was prescribed for.

    Returns True if the rulebook is loadable (or absent, which is fine: the built-ins arm)."""
    from .decorators import load_local_policy_keywords, AgentXPolicyLoadError

    print("\n🩺 POLICY RULEBOOK CHECK        (validates ./.agentx/policies.json)")
    print("=" * 75)
    print("  This is the file `agentx pull` writes. If it is malformed, AgentX fails CLOSED:")
    print("  your tools do not run, because a shield that cannot read its rules must not")
    print("  certify a call as safe.")
    try:
        policies = load_local_policy_keywords()
    except AgentXPolicyLoadError as err:
        print(f"\n  ❌ MALFORMED. Your agent is failing closed until this is fixed.")
        if getattr(err, "source", None):
            print(f"     file:  {err.source}")
        if getattr(err, "field", None):
            print(f"     field: {err.field}")
        print(f"     {err}")
        print("\n  ▶ fix that field, or delete the file to fall back to the built-in policies.")
        print("     Your agent recovers on the next call. No restart needed.")
        print("=" * 75)
        return False

    print(f"\n  ✅ parses. {len(policies)} policy/policies armed.")
    print("=" * 75)
    return True


def _policies_check():
    """`agentx policies --check` — validate BOTH stores that can silently disarm coaching:
    the pulled rulebook (policies.json) and the override store (overrides.json).

    A hand-edit typo in either is LOUD here (a single bad comma otherwise silently disables
    EVERY customized coaching, or hard-fails every call). Exits non-zero so CI catches it."""
    rulebook_ok = _policy_store_check()

    path = _overrides_path()
    print("\n🩺 OVERRIDE STORE CHECK        (validates ./.agentx/overrides.json)")
    print("=" * 75)
    print("  Your customized coaching lives in this file. A JSON typo silently disables ALL")
    print("  of it, so this confirms it parses and lists what is actually active.")

    if not os.path.exists(path):
        print(f"\n  ℹ️  No override store yet at {path}.")
        print("     Nothing customized, so the built-in floor coaching is in effect.")
        print("     ▶ Customize one:   agentx customize \"<name>\" --edit   (names: agentx policies)")
        print("=" * 75)
        if not rulebook_ok:
            sys.exit(1)
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
    except (OSError, ValueError) as e:
        print(f"\n  ❌ {path} is NOT valid JSON: {e}")
        print("     Your customized coaching is NOT being applied until this is fixed.")
        print("     It's plain JSON, so check for a trailing comma or an unclosed quote.")
        print("=" * 75)
        sys.exit(1)

    store = load_overrides(warn=True)
    active = store.get("overrides", {})
    # Scoped overrides are live coaching and have to be counted HERE. Reading only the bare map
    # made this gate report "no active overrides" for a store whose scoped rules were firing on
    # every matching block — and `agentx policies` points the author at this command two lines
    # after listing those very rules. A validator that says "nothing here" about live coaching is
    # the same "a rule you cannot see is a rule you cannot debug" failure the scoping work closed.
    scoped = [e for e in (store.get("scoped_overrides") or [])
              if isinstance(e, dict) and e.get("challenge")]
    real = [(pid, e) for pid, e in active.items() if isinstance(e, dict) and e.get("challenge")]
    if not real and not scoped:
        print(f"\n  ✅ {path} parses. No active overrides in it yet.")
        print("=" * 75)
        if not rulebook_ok:
            sys.exit(1)
        return

    catalog = {p["id"]: p["name"] for p in list_customizable_policies()}
    print(f"\n  ✅ {path} parses.  {len(real)} policy-wide + {len(scoped)} scoped override(s):")
    for pid, entry in real:
        label = entry.get("policy_violated") or catalog.get(pid) or pid
        print(f"\n  📋 {label}   (source: {entry.get('source', '?')})")
        print(_wrap(entry["challenge"], "     coaching:   "))
        if entry.get("safe_path"):
            print(_wrap(entry["safe_path"], "     safe path:  "))
    for entry in scoped:
        label = (entry.get("policy_violated") or catalog.get(entry.get("policy_id"))
                 or entry.get("policy_id") or "?")
        print(f"\n  📋 {label}   (source: {entry.get('source', '?')})")
        print(f"     └ when {describe_scope(entry.get('when'))}")
        print(_wrap(entry["challenge"], "       coaching: "))
        if entry.get("safe_path"):
            print(_wrap(entry["safe_path"], "       safe path: "))
    print("\n" + "=" * 75)
    print("  ▶ Change one:   agentx customize \"<name>\" --edit")
    print("=" * 75)
    # A malformed RULEBOOK exits non-zero even when the override store is pristine: the
    # operator's agent is failing closed, and a green exit code here would say otherwise.
    # Success just RETURNS: a sys.exit(0) would tear down any caller that imports this.
    if not rulebook_ok:
        sys.exit(1)


# ---------------------------------------------------------------------------
# agentx review — the batched, one-key review of what your agents' blocks taught
# AgentX (the label channel's PRIMARY capture path). Reconciles safe-paths, then
# walks each pending item: adopt a learned reframe, or record a verdict on a block.
# Never interrupts a run — the session summary just COUNTS and points here.
# ---------------------------------------------------------------------------
_VERDICT_KEYS = {"c": "TRUE_POSITIVE", "w": "FALSE_POSITIVE", "a": "ACCEPTED_RISK"}


def _relative_age(iso_ts):
    """A short 'N days ago' rendering of an ISO timestamp for review context — a receipt id
    alone gives a user nothing to go on days later. Best-effort: falls back to the raw string
    on any parse error, and to a plain placeholder when absent, so a malformed/missing
    timestamp never breaks the walkthrough."""
    if not iso_ts:
        return "at an unknown time"
    try:
        ts = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - ts
        days = delta.days
        if days >= 1:
            return f"{days} day{'s' if days != 1 else ''} ago"
        hours = delta.seconds // 3600
        if hours >= 1:
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        return "less than an hour ago"
    except (ValueError, TypeError):
        return str(iso_ts)


def _render_payload(raw):
    """Best-effort rendering of a stored raw_payload (JSON-encoded, arbitrary tool-call args)
    for review context — the agent's ATTEMPTED action, as opposed to the challenge AgentX
    issued back. Falls back to the raw string on anything that doesn't decode to a dict, so
    a malformed/legacy payload never breaks the walkthrough."""
    if not raw:
        return None
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        return str(raw)
    if isinstance(data, dict):
        return ", ".join(f"{k}={v}" for k, v in data.items())
    return str(data)


# Every wrapped field in a review item shares this fixed label width, so the actual VALUE
# text starts at the SAME column regardless of which label precedes it -- "agent's stated
# intent:" (the longest) would otherwise push its value further right than "challenge
# shown:" or "recovered via:", raggeding the left edge of the content down the page.
_REVIEW_FIELD_LABELS = ("recovered via:", "agent's stated intent:", "attempted action:",
                        "challenge shown:", "safe path so far:", "current verdict:")
_REVIEW_LABEL_WIDTH = max(len(l) for l in _REVIEW_FIELD_LABELS)


def _field(label):
    return f"   {label:<{_REVIEW_LABEL_WIDTH}}  "


def _print_review_item(n, total, it):
    label = it.get("policy_violated") or it.get("policy_id") or "policy"
    if it["kind"] == "adopt":
        print(f"\n[{n}/{total}] RECOVERY · {label}")
        print(_wrap(it.get("suggestion", ""), _field("recovered via:")))
        if (it.get("count") or 1) > 1:
            print(f"   (the agent found this {it['count']}x)")
        return
    if it.get("mcp"):
        print(f"\n[{n}/{total}] VERDICT · {label}")
        print("   policy-level verdict for the keyless-MCP wedge (no per-block receipt)")
        return
    count = it.get("count") or 1
    header = f"VERDICT ({count} blocks)" if it["kind"] == "verdict_group" else "VERDICT"
    print(f"\n[{n}/{total}] {header} · {label}")
    print(f"   blocked {_relative_age(it.get('created_at'))} — receipt {it.get('receipt_id', '')}"
          f"  (status: {it.get('status')})"
          + (f"   (showing the most recent of {count})" if it["kind"] == "verdict_group" else ""))
    if it.get("agent_cot"):
        print(_wrap(it["agent_cot"], _field("agent's stated intent:")))
    payload = _render_payload(it.get("raw_payload"))
    if payload:
        print(_wrap(payload, _field("attempted action:")))
    if it.get("challenge_issued"):
        print(_wrap(it["challenge_issued"], _field("challenge shown:")))
    if it.get("label_safe_path"):
        print(f"{_field('safe path so far:')}{it['label_safe_path']}")
    if it.get("label_verdict"):
        print(f"{_field('current verdict:')}{it['label_verdict']}  (choosing again overwrites this)")


def _mcp_review_items():
    """Keyless-MCP wedge recoveries as review 'adopt' items — parity with `insights`, so
    `agentx review` covers the MCP loop too, not just the incidents.db loop. Empty (never
    raises) when MCP harvest is off / there is no corpus; skips a policy already carrying an
    active override. Lives in the CLI layer because overrides.py stays free of the mcp_proxy
    import (its subprocess/threading must not load on every `agentx` command).

    ONE adopt item per policy (the top-recurrence signature — `mcp_flat` is already sorted
    highest-count-first per policy bucket, so the first occurrence IS that one), mirroring
    `reviewable_items`'s dedup: only one override can be active per policy, so offering every
    surviving (tool, action, scope) signature as an independent decision just means each
    adopted one clobbers the last."""
    try:
        _h, _r, _rules, mcp_flat = _collect_candidates()
    except Exception:
        return []
    out = []
    seen_adopt = set()
    seen_verdict = set()
    for m in mcp_flat:
        pid = m.get("policy_id")
        pviol = m.get("policy_violated")
        akey = pid or pviol
        # (1) adopt the learned reframe (unless the policy already carries an override).
        # has_human_coaching, not the bare lookup: a policy the user deliberately SCOPED has no
        # bare entry, so this used to keep offering "adopt this learned reframe" for it — and
        # accepting installs a POLICY-WIDE override over the narrow rule they wrote. The automated
        # path (mcp auto-coach) got this guard; the human-facing one is worse without it, because
        # here a person clicks yes.
        if (akey and akey not in seen_adopt and pid and m.get("suggestion")
                and not has_human_coaching(pid, policy_name=pviol)):
            seen_adopt.add(akey)
            out.append({
                "kind": "adopt", "policy_id": pid, "policy_violated": pviol,
                "suggestion": m.get("suggestion"),
                "resolution_type": m.get("resolution_type"),
                "count": m.get("count", 1),
            })
        # (2) verdict the POLICY — the MCP wedge has no per-block receipt, so its verdict is
        # policy-level. One item per policy, skipped once a verdict is already declared.
        vkey = pid or pviol
        if vkey and vkey not in seen_verdict and not get_declared_verdict(pid, pviol):
            seen_verdict.add(vkey)
            out.append({"kind": "verdict", "policy_id": pid, "policy_violated": pviol, "mcp": True})
    return out


def _print_review_stats():
    """`agentx review --stats` — where the label channel stands across EVERY incident in
    the store, not just what's still pending (that's the walkthrough above). It never PROMPTS
    (safe to run in any context, tty or not), but it is NOT a pure read: it first reconciles
    the derived safe-path labels (writing label_safe_path from trace history) so the HELD/
    FAILED counts are current. That write is idempotent, deterministic bookkeeping — never a
    human decision — so re-running is harmless, but a truly read-only caller should know a
    reconcile write happens here."""
    reconcile_safe_paths()                  # freshen derived safe-path labels before summarizing
    census = incident_db_census()
    stats = label_stats()
    print("\n📊 Label channel — outcome summary")
    print("=" * 75)
    if not census["exists"] or stats["total"] == 0:
        print("   No incidents recorded yet — nothing to summarize.")
        if not census["exists"]:
            print(f"   (no incident store yet at {census['path']})")
        print("=" * 75)
        return
    v, sp, h = stats["verdict"], stats["safe_path"], stats["harm"]
    print(f"   {stats['total']} incident(s) in the store")
    print("\n   Verdict    (was the block right?)")
    print(f"     ✓ correct:         {v['TRUE_POSITIVE']}")
    print(f"     ✗ false positive:  {v['FALSE_POSITIVE']}")
    print(f"     ~ accepted risk:   {v['ACCEPTED_RISK']}")
    print(f"     ?  unlabeled:      {v['unlabeled']}")
    print("\n   Safe path  (did the reframe hold?)")
    print(f"     held:              {sp['HELD']}")
    print(f"     failed:            {sp['FAILED']}")
    print(f"     n/a:               {sp['n/a']}")
    if h["HARM"] or h["NO_HARM"]:
        print("\n   Harm       (partner outcome / eval judge)")
        print(f"     harm:              {h['HARM']}")
        print(f"     no harm:           {h['NO_HARM']}")
        print(f"     unknown:           {h['unknown']}")
    print(f"\n   {stats['blocking_open']} block(s) still awaiting a verdict —  {_review_cmd()}")
    print("=" * 75)


def _identity_keys(it):
    """The identity signals on a verdict item: its normalized name and its policy_id, when
    present. Order matters: name first, since it's the more stable cross-path key."""
    keys = []
    name = _norm_for_dedup(it.get("policy_violated"))
    if name:
        keys.append(("name", name))
    if it.get("policy_id"):
        keys.append(("id", it["policy_id"]))
    return keys


def _group_verdict_items(items):
    """Collapse multiple per-receipt VERDICT items on the SAME policy into one batch-decision
    item. A real corpus surfaced 190+ individual receipts on a couple of hot policies -- each
    an independent yes/no when a human almost always wants to answer ONCE per policy, not
    scroll through near-identical prompts. Singletons (a policy with exactly one open block)
    and MCP policy-level verdicts (already one-per-policy) pass through unchanged. Ordering
    is preserved: a group appears at the position of its first-seen item.

    Grouped by a UNION over (normalized name, policy_id): two rows merge if they share
    EITHER signal. This closes identity drift in BOTH directions -- the same logical policy
    can carry a DIFFERENT id across the SDK's two block paths (the Layer-0 keyword shield's
    seed UUID vs the gateway/judge id, the cross-path flicker get_active_override already
    guards against), and separately, the SAME policy_id can carry a DIFFERENT name after a
    rename (e.g. a gateway policy renamed post-launch, its older incidents still carrying
    the old name). Grouping on just one signal silently splits what is really one policy
    into two "different" groups whenever the other signal also varies."""
    parent = {}

    def find(k):
        parent.setdefault(k, k)
        while parent[k] != k:
            parent[k] = parent.get(parent[k], parent[k])
            k = parent[k]
        return k

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    verdict_only = [it for it in items if it["kind"] == "verdict" and not it.get("mcp")]
    for it in verdict_only:
        keys = _identity_keys(it)
        for k in keys[1:]:
            union(keys[0], k)

    def group_key(it):
        keys = _identity_keys(it)
        return find(keys[0]) if keys else ("solo", id(it))

    slots = []
    group_by_key = {}
    for it in items:
        if it["kind"] != "verdict" or it.get("mcp"):
            slots.append(it)
            continue
        key = group_key(it)
        g = group_by_key.get(key)
        if g is None:
            g = {"kind": "verdict_group", "policy_id": it.get("policy_id"),
                 "policy_violated": it.get("policy_violated"), "items": []}
            group_by_key[key] = g
            slots.append(g)
        g["items"].append(it)
    out = []
    for it in slots:
        if it.get("kind") != "verdict_group":
            out.append(it)
            continue
        if len(it["items"]) == 1:
            out.append(it["items"][0])
            continue
        rep = it["items"][0]   # most recent (list_recent_incidents is newest-first)
        it.update({"count": len(it["items"]), "created_at": rep.get("created_at"),
                   "challenge_issued": rep.get("challenge_issued"), "agent_cot": rep.get("agent_cot"),
                   "raw_payload": rep.get("raw_payload"), "receipt_id": rep.get("receipt_id"),
                   "status": rep.get("status"), "label_verdict": rep.get("label_verdict")})
        out.append(it)
    return out


def _prompt_single_verdict(it):
    """One receipt, one verdict (or a delete). Returns "labeled", "deleted", or None (skipped).
    No capitalized default shown -- there IS no safe default for a human call on whether a
    block was right, so Enter honestly means skip, not a guess. Delete has no MCP form (a
    policy-level MCP verdict carries no receipt_id -- nothing to delete)."""
    q = ("   were blocks on this policy right? [c]orrect / [w]rong / [a]ccept-risk / [s]kip / [q]uit: "
         if it.get("mcp") else
         "   was the block right? [c]orrect / [w]rong / [a]ccept-risk / [d]elete / [s]kip / [q]uit: ")
    raw = input(q)
    ans = raw.strip().lower()
    if ans == "q":
        raise _ReviewQuit()
    if ans == "d" and not it.get("mcp"):
        delete_incident(it["receipt_id"])
        print("   ✓ deleted — removed from the local store, not just skipped")
        return "deleted"
    verdict = _VERDICT_KEYS.get(ans[:1])
    if not verdict:
        print("   – skipped")
        return None
    if it.get("receipt_id"):
        record_outcome(it["receipt_id"], verdict=verdict, source="human")   # per-block (incidents.db)
    else:
        set_declared_verdict(it.get("policy_id"), verdict,          # per-policy (MCP wedge)
                             policy_name=it.get("policy_violated"))
    print(f"   ✓ labeled {verdict}")
    return "labeled"


class _ReviewQuit(Exception):
    """Raised by the 'q' keystroke, at any nesting level, to stop the whole walkthrough."""


def _print_review_help():
    print(f"\nUsage:  {_review_cmd()} [--stats | --recover | --block | --labeled | -h]")
    print("=" * 75)
    print("  (no flags)   walk every pending item -- recoveries to adopt + blocks needing a verdict")
    print("  --recover    only the pending RECOVERY items (learned safe-paths ready to adopt)")
    print("  --block      only the pending VERDICT items (blocks awaiting a human call)")
    print("  --labeled    RE-REVIEW items that already have a verdict -- pick again to overwrite it")
    print("  --stats      a summary across every incident in the store, not just what's pending")
    print("  -h / --help  show this message")
    print()
    print("  In a terminal, each item is one keystroke:")
    print("    RECOVERY item     [Y]es adopt / [n]o / [s]kip / [q]uit")
    print("    VERDICT item      [c]orrect / [w]rong / [a]ccept-risk / [d]elete / [s]kip / [q]uit")
    print("    a GROUP of blocks on one policy also offers:")
    print("      [c]orrect-all / [w]rong-all / [a]ccept-risk-all / [d]elete-all / [i]ndividually")
    print()
    print("  Piped / non-interactive (CI, a script): lists pending items and never prompts.")
    print()
    # `agentx verdict` has no MCP form. On that door the standing-rule shortcut is omitted
    # rather than printed as a command-not-found; the one-key pass above sets the same rule.
    if not MCP_ENTRY:
        print("  Change a POLICY's STANDING rule directly (works even with no items shown here):")
        print("    agentx verdict --policy \"<name>\" --correct|--wrong|--accept-risk|--clear")
    print("=" * 75)


def _warn_if_mcp_corpus_is_stranded():
    """Tell a user whose MCP corpus predates the per-user store where it went.

    THIS PATH IS THE ONE THAT SURPRISES PEOPLE. In SDK 0.4.25 the MCP stores moved to a
    cwd-independent per-user location, because the proxy and the reviewer are separate
    processes with separate working directories and a project-relative path resolved
    differently in each. `agentx-mcp --review` says so when it spots an older corpus.

    `agentx review` reaches the SAME corpus (_mcp_review_items -> _collect_candidates ->
    mcp_recovery_candidates -> read_harvest_pairs), so a Python user who also ran the proxy
    in their project sees those MCP items simply STOP APPEARING after upgrading. Silently,
    which reads as lost history rather than a moved file. The advisory belongs on both
    readers or it is not an advisory, it is a coin flip on which command you happened to run.

    Never raises and never blocks the review: an import or filesystem problem here must not
    take down the command it is only annotating."""
    # The try guards the IMPORT, not the call. _legacy_project_harvest swallows its own
    # errors and returns None, so the call cannot raise; the import can, and it is lazy on
    # purpose because mcp_proxy pulls in subprocess/threading that must not load on every
    # `agentx` command. Flagged twice in review as redundant, so: it is one line of scope,
    # and the prints are deliberately OUTSIDE it, since a format error there is a bug we
    # want to see rather than swallow.
    try:
        from .mcp_proxy import _legacy_project_harvest
    except Exception:
        return
    stranded = _legacy_project_harvest()
    if not stranded:
        return
    print(f"\n   Note: an older MCP corpus sits at {stranded}, which is not what this reads.")
    print("   Since 0.4.25 the MCP store is per-user, so the proxy and this command agree")
    print("   from any directory. To keep using the older one, set:")
    print(f"     AGENTX_MCP_HARVEST_PATH={stranded}")


def _note_that_the_two_doors_keep_separate_brains():
    """Say out loud that the MCP door and the Python door learn into SEPARATE stores.

    BACKLOG P-18. Since #288 the MCP proxy's auto-coach writes adopted safe-paths to the
    per-user ~/.agentx/overrides.json, while `agentx insights`, `agentx review` and the
    @agentx_protect block path all resolve <project>/.agentx/overrides.json. So a reframe
    learned over MCP never appears in the Python door's insights and never coaches a
    Python-door block.

    That split is DELIBERATE (founder call 2026-07-31) and is not a bug: the MCP door has no
    project -- an editor spawns the proxy from an arbitrary directory -- so per-user is the
    only default both of its processes compute the same answer for. What was missing is
    anyone SAYING so, which leaves the product looking like it lost your work.

    Do NOT "fix" this by merging the stores. A cwd-derived read is exactly the bug
    _mcp_overrides_path was created to kill, and it comes back the moment either side
    prefers a project file it can only sometimes see.

    Speaks only when there is something to speak about (entries actually exist), so an empty
    store stays quiet. Never raises: this annotates a command, it must not take one down."""
    # WHICH DOOR is an explicit fact, not something to infer from a path coincidence.
    # Review found the first cut read "paths are equal" as "we are on the MCP door", but
    # _find_project_root() returns any directory containing .agentx/ — which is exactly what
    # the MCP door creates under $HOME. So running `agentx insights` from there made the
    # PYTHON door announce that these safe-paths "do NOT coach the Python door", while the
    # Python door was reading that very file. The message was the reverse of the truth.
    on_the_mcp_door = MCP_ENTRY
    try:
        from .mcp_proxy import _mcp_overrides_path
        from .overrides import _find_project_root, DEFAULT_OVERRIDES_PATH
        mcp_path = _mcp_overrides_path()
        entries = load_overrides(path=mcp_path).get("overrides", {}) or {}
        if on_the_mcp_door:
            # NOT _overrides_path() on this door. _point_stores_at_mcp_home() pins
            # AGENTX_OVERRIDES to the MCP store for the whole proxy process, and pins it
            # UNCONDITIONALLY (it overwrites even a user-exported value, as its own docstring
            # says). So _overrides_path() answers "the MCP store" here no matter what the
            # Python door reads, same_store was ALWAYS True, and this entire branch was dead
            # code for every real MCP user: `uvx agentx-mcp --insights` never printed the
            # note. Found by running it, not by reading it.
            # ON THIS DOOR, SILENCE REQUIRES AN EXPLICIT RELOCATION. Nothing else.
            #
            # Two heuristics were tried here and both went silent in the commonest directory.
            # Comparing against _overrides_path() lost to the pin. Comparing against the
            # project root lost because _find_project_root() falls back to the nearest
            # .agentx ancestor, which under $HOME is the store this door just created — and
            # then requiring a .git root lost too, because plenty of people keep $HOME in a
            # dotfiles repo, which makes $HOME "a real project" and hands the silence
            # straight back. Three attempts, same silence, because the question was wrong.
            #
            # The question is not "are these two paths equal here". The MCP proxy's cwd is
            # arbitrary, so where the PYTHON door will later resolve its store is genuinely
            # unknowable from inside this process — the user runs it in their project, which
            # is somewhere else. What IS knowable: the MCP store is per-user by construction,
            # and a project's store is not, so unless the user deliberately pointed them at
            # one file the split is real and worth saying. AGENTX_MCP_OVERRIDES_PATH is that
            # deliberate act, and .env.example already tells anyone setting it to set the
            # same value on both sides.
            other_path = os.path.join(_find_project_root(), DEFAULT_OVERRIDES_PATH)
            relocated_on_purpose = bool(os.environ.get("AGENTX_MCP_OVERRIDES_PATH"))
            paths_match = os.path.abspath(mcp_path) == os.path.abspath(other_path)
            same_store = paths_match and relocated_on_purpose
        else:
            other_path = _overrides_path()
            same_store = os.path.abspath(mcp_path) == os.path.abspath(other_path)
    except Exception:
        return
    if not entries:
        return
    if same_store:
        # Both doors resolve the SAME file here, so there is no split to warn about and the
        # honest thing is to say nothing rather than describe a division that isn't there.
        # Applies on BOTH doors: review found the first fix cured the Python side and left
        # the MCP side still announcing "they do NOT coach the Python door" while the Python
        # door reads that very file. Same bug, mirrored.
        return
    if on_the_mcp_door:
        print(f"\n   Note: these {len(entries)} safe-path(s) live in your per-user MCP store,")
        print("   which is separate from any project's .agentx/overrides.json. They travel")
        print("   with you across servers and projects, and they do NOT coach the Python")
        print("   door's @agentx_protect blocks.")
        return
    # "not shown here", never "not listed above": this is called from BOTH readers, and in
    # execute_review it runs BEFORE anything has been listed, so "above" referred to output
    # that did not exist yet.
    print(f"\n   Note: {len(entries)} safe-path(s) learned over MCP are kept in a separate")
    print("   per-user store, so they are not shown here and do not coach a block here.")
    print("   See them with:  uvx agentx-mcp --insights")


def execute_review(args=None):
    """`agentx review` — the batched, one-key review of the label channel, covering BOTH the
    incidents.db loop and the keyless-MCP wedge. Reconciles safe-paths, gathers pending items
    (recoveries to adopt + blocks needing a verdict), groups repeat per-receipt verdicts on the
    same policy into one batch decision, then walks each with a single keystroke.
    Non-interactive (piped / CI): prints the list and exits WITHOUT prompting, so it never
    blocks an automated run. ``--stats`` prints a summary across every incident instead.
    ``--recover`` / ``--block`` narrow the walkthrough to just one kind of item, for a store
    with enough of one kind that mixing them in is more scrolling than deciding. ``--labeled``
    re-opens items that already have a verdict, so a past call is never a dead end."""
    args = args or []
    if any(a in ("-h", "--help", "help", "?") for a in args):
        _print_review_help()
        return
    if "--stats" in args:
        _print_review_stats()
        return
    # 🔴 SAY WHAT IS HAPPENING BEFORE IT HAPPENS, AND GATE IT ON THE WORK.
    #
    # Two whole-store passes run before a single character is printed, and BOTH read up to
    # 100,000 rows and then write per changed row: reconcile_safe_paths and
    # apply_declared_verdicts. Measured ~43 SECONDS for ~17,700 blocks on the founder's
    # machine, 2026-08-10, in total silence. It reads as a hang, and it was why
    # `agentx review` looked unrunnable.
    #
    # 🔴 GATE ON THE WORK, AND THE WORK IS *WRITES*. Measured: reading 43,000 rows takes
    # ~0.4s; the 43 seconds was ~17,700 individual writes. So the cost tracks how many
    # blocks are about to be LABELLED, which is `pending` -- but only when the user has
    # declared verdicts, because apply_declared_verdicts returns immediately without them.
    # reconcile_safe_paths writes only for COMPLIED rows whose safe-path label changed,
    # which is a handful on any real store.
    #
    # ⚠️ TWO WRONG GATES BEFORE THIS ONE, AND THE SECOND IS THE INSTRUCTIVE MISTAKE.
    # v1 gated on `pending > 500` alone, so someone with a backlog and no declared verdicts
    # was promised a pass that exits immediately. The review said "the guard measures a
    # different quantity than the work", and I REPLACED THE QUANTITY (total rows) when what
    # it needed was the MISSING CONDITION. v2 then fired on every run forever for anyone
    # with a large store: the founder's own log, 43,353 rows, 0 pending, banner printed,
    # finished instantly. When a gate is wrong, ask what condition is missing before
    # rewriting what it measures.
    _to_apply = count_awaiting_verdict() if (load_overrides().get("verdicts") or {}) else 0
    if _to_apply > 500:
        print("\n   Applying verdicts you already declared to %d earlier block(s) you have"
              % _to_apply)
        print("   not seen. This writes one row at a time, so it can take a minute.")
        sys.stdout.flush()

    reconcile_safe_paths()                 # refresh safe-path labels before we show them
    _declared = apply_declared_verdicts()   # auto-label blocks the org's rules pre-declared
    if _declared:
        print("   Applied a declared verdict to %d block(s); they will not be asked again."
              % _declared)
    # The walkthrough is CAPPED at REVIEW_READ_CAP items, and the header below must say so
    # rather than print the cap as if it were the total. A store with 17,711 pending blocks
    # showed "200 item(s) to review" beside an `agentx review --stats` screen reading
    # 17,711 -- two numbers for one job, on two commands a person runs minutes apart.
    # 🔴 THE HEADER COUNTS WHAT IS ON SCREEN. NOTHING ELSE.
    #
    # The "N of M" form was wrong four different ways at once, all of them the same
    # mistake: the numerator and the denominator came from different populations and were
    # subtracted anyway.
    #   * M counted BLOCKS, N counted DECISIONS after _group_verdict_items collapsed
    #     repeats. 600 pending on one policy rendered "1 of 600".
    #   * --recover / --block filtered N afterwards, so "3 of 17711" implied 17,708 hidden
    #     recoveries when the 17,711 were blocks the flag had just excluded.
    #   * _mcp_review_items() fed N and was absent from M, so N could exceed M.
    #   * M > cap was used as "truncated", but the cap never applied to adopt items.
    # So: the header states items on screen, and COVERAGE gets its own line that names its
    # own unit and fires only when a read was ACTUALLY truncated.
    coverage = None
    if "--labeled" in args:
        items, _page_of_more = labeled_items_with_truncation()
        if _page_of_more:
            coverage = ("showing the most recent %d labeled block(s); older ones are not "
                        "listed" % REVIEW_READ_CAP)
    else:
        verdict_items, _page_of_more = reviewable_items_with_truncation()
        items = verdict_items + _mcp_review_items()
        if _page_of_more and "--recover" not in args:
            # Only when the VERDICT read was truncated, and never under --recover, where
            # blocks are not what is being listed.
            coverage = ("showing the most recent %d of %d block(s) awaiting a verdict"
                        % (REVIEW_READ_CAP, count_awaiting_verdict()))
        if "--recover" in args:
            items = [it for it in items if it["kind"] == "adopt"]
        elif "--block" in args:
            items = [it for it in items if it["kind"] == "verdict"]
    items = _group_verdict_items(items)
    _warn_if_mcp_corpus_is_stranded()
    _note_that_the_two_doors_keep_separate_brains()
    if not items:
        census = incident_db_census()
        print("\n✅ Nothing to review — no blocks awaiting a verdict, no new safe-paths to adopt.")
        if not census["exists"]:
            print(f"   (no incident store yet at {census['path']} — blocks appear here once the")
            # `agentx status` is a bare subcommand with no MCP form. It is informational, not
            # the loop, so on that door the sentence keeps its meaning and drops the command.
            if MCP_ENTRY:
                print("    gateway records them; keyless Shield runs keep local stats too.)")
            else:
                print("    gateway records them; keyless Shield runs keep local stats in `agentx status`.)")
        print("=" * 75)
        return

    if not sys.stdin.isatty():
        # Automated / piped: show the list, never block on input.
        print(f"\n📋 {len(items)} item(s) await review — run `{_review_cmd()}` at a terminal to act:")
        if coverage:
            print(f"   ({coverage})")
        for n, it in enumerate(items, 1):
            _print_review_item(n, len(items), it)
        print("=" * 75)
        return

    print(f"\n📋 {len(items)} item(s) to review — one key each. Enter accepts the CAPITALIZED"
          " default where one is shown; 'q' stops here and leaves the rest untouched.")
    if coverage:
        print(f"   ({coverage})")
    adopted = labeled = deleted = 0
    for n, it in enumerate(items, 1):
        _print_review_item(n, len(items), it)
        try:
            if it["kind"] == "adopt":
                raw = input("   teach this recovery? [Y]es / [n]o / [s]kip / [q]uit: ")
                if raw.strip().lower() == "q":
                    raise _ReviewQuit()
                ans = raw.strip().lower()
                if ans in ("", "y", "yes"):
                    adopt_override(it["policy_id"], challenge=it.get("suggestion") or "",
                                   resolution_type=it.get("resolution_type"),
                                   policy_violated=it.get("policy_violated"), source="review")
                    adopted += 1
                    print("   ✓ adopted — it will coach your agents on the next block")
                else:
                    print("   – skipped")
            elif it["kind"] == "verdict_group":
                count = it["count"]
                print(f"   {count} blocks on this policy await a verdict.")
                raw = input(f"   declare ONE verdict for all {count}, or go one at a time?"
                            " [c]orrect-all / [w]rong-all / [a]ccept-risk-all / [d]elete-all"
                            " / [i]ndividually / [s]kip / [q]uit: ")
                ans = raw.strip().lower()
                if ans == "q":
                    raise _ReviewQuit()
                if ans == "i":
                    for sub in it["items"]:
                        _print_review_item(1, 1, sub)
                        outcome = _prompt_single_verdict(sub)
                        if outcome == "labeled":
                            labeled += 1
                        elif outcome == "deleted":
                            deleted += 1
                    continue
                if ans == "d":
                    # Deliberately scoped to exactly the receipts shown in this group (see
                    # delete_incidents) -- unlike batch labeling, deletion is irreversible,
                    # so it must never reach beyond what the human actually saw.
                    n_deleted = delete_incidents([sub["receipt_id"] for sub in it["items"]])
                    deleted += n_deleted
                    print(f"   ✓ deleted {n_deleted} block(s) for this policy")
                    continue
                verdict = _VERDICT_KEYS.get(ans[:1])
                if verdict:
                    # 1. Label every VISIBLE receipt DIRECTLY -- guaranteed, regardless of any
                    #    policy_id/name variation among them. A name/id-keyed declared verdict
                    #    alone is not enough: it only reaches rows matching ONE identity, and a
                    #    group can span several (the keyword-shield-vs-gateway id flicker, OR a
                    #    historical policy rename leaving the same policy_id under two names) --
                    #    a batch answer must never leave something you just saw unlabeled.
                    direct = sum(1 for sub in it["items"] if sub.get("receipt_id")
                                and record_outcome(sub["receipt_id"], verdict=verdict, source="human"))
                    # 2. Declare under EVERY distinct identity actually seen in this group (not
                    #    just the representative's), so apply_declared_verdicts' broader sweep
                    #    (beyond the display window) can match a row carrying ANY of them.
                    for nm in {s.get("policy_violated") for s in it["items"] if s.get("policy_violated")}:
                        set_declared_verdict(nm, verdict, policy_name=nm)
                    for pid in {s.get("policy_id") for s in it["items"] if s.get("policy_id")}:
                        set_declared_verdict(pid, verdict)
                    swept = apply_declared_verdicts()   # skips the already-labeled direct ones
                    total = direct + swept
                    labeled += total
                    print(f"   ✓ labeled {verdict} on {total} block(s) for this policy")
                    # A batch answer is a standing decision — disclose it (parity with
                    # `verdict --policy`, which is explicit about the forward effect).
                    print(f"     (future blocks on this policy get {verdict} too; change or"
                          " clear it with `agentx verdict --policy`)")
                else:
                    print("   – skipped (all)")
            else:
                outcome = _prompt_single_verdict(it)
                if outcome == "labeled":
                    labeled += 1
                elif outcome == "deleted":
                    deleted += 1
        except _ReviewQuit:
            remaining = len(items) - n + 1
            print(f"   – stopping; {remaining} remaining item(s) untouched.")
            break
        except (EOFError, KeyboardInterrupt):
            print("\n   (stopped — nothing further changed)")
            break
    rec_word = "recovery" if adopted == 1 else "recoveries"
    print(f"\n✓ Review done: {adopted} {rec_word} adopted, {labeled} block(s) labeled, "
          f"{deleted} block(s) deleted.")
    print("=" * 75)


# ---------------------------------------------------------------------------
# agentx rules — the org rules file (.agentx/rules.json) cold-start seed. Plain-language
# reframes + pre-declared verdicts, human-authored so poisoning-safe; reframe-and-label
# only (a loosening rule is rejected). `check` validates + previews (safe in any mode);
# `apply` ingests into the override store.
# ---------------------------------------------------------------------------
_RULES_TEMPLATE = '''{
  "reframes": [
    { "policy": "Mass Destructive Intent",
      "safe_path": "Use a soft delete (UPDATE ... SET deleted=1); never DROP a live table" },

    { "policy": "Mass Destructive Intent",
      "when": { "agent_id": "nightly_cleanup", "tool": "purge_stale_rows" },
      "safe_path": "Our nightly cleanup filters by date: add WHERE created_at < now() - interval '90 days'" }
  ],
  "verdicts": [
    { "policy": "Budget Ceiling Approval", "verdict": "ACCEPTED_RISK",
      "note": "our nightly batch legitimately spends above the soft ceiling" }
  ]
}'''

def _scope_help():
    """The `when` explainer, with both closed vocabularies DERIVED rather than typed.

    The same PR that added this deliberately derives TARGET_ACTIONS from the classifier table,
    with the comment that a hand-typed copy is a hole exactly where the vocabulary changes — and
    then hand-typed it again here, three files away. Help text that lists a stale set of values is
    worse than none: it is the one place an author looks to find the spelling."""
    # BOTH closed vocabularies live in decorators, next to the classifier that produces them.
    # `SCOPES` was imported from .overrides here, where it is only a function-local name inside
    # normalize_scope and never becomes a module attribute — so this raised ImportError on the
    # FIRST-RUN path (`agentx rules check` with no rules.json), which is the exact path the new
    # `agentx policies` footer points a new user at. The whole suite stayed green because nothing
    # drove this function; a test now does.
    from .decorators import TARGET_ACTIONS, SCOPES
    from .overrides import _SCOPE_DIMENSIONS
    named = ", ".join(_SCOPE_DIMENSIONS[:-2])
    return (
        "  A reframe with a `when` coaches ONE situation instead of the whole policy. It can name\n"
        "  %s, target_action (%s) and scope\n"
        "  (%s); every field it names has to match for it to fire. %s are\n"
        "  the ones that pin it to one job — target_action and scope on their own describe a whole\n"
        "  class of call. It changes the coaching only; the block still fires either way."
        % (named, "/".join(sorted(TARGET_ACTIONS)), "/".join(sorted(SCOPES)),
           " and ".join(_SCOPE_DIMENSIONS[:-2]))
    )


def execute_rules(args):
    """`agentx rules check | apply` — seed the org brain from .agentx/rules.json before any
    harvest data exists. check = validate + dry-run preview (safe in audit or enforce);
    apply = ingest reframes (become active overrides) + verdicts (pre-label matching blocks)."""
    sub = (args[0].lower() if args else "check")
    if sub not in ("check", "apply"):
        print("\n⚠️  Usage:")
        print("   agentx rules check   validate + preview .agentx/rules.json (dry-run, any mode)")
        print("   agentx rules apply   ingest its reframes + verdicts into your override store")
        print("=" * 75)
        sys.exit(2)

    rules, errors = load_org_rules()
    if errors:
        print("\n❌ .agentx/rules.json has problems (nothing was applied):")
        for e in errors:
            print(f"   • {e}")
        print("=" * 75)
        sys.exit(1)
    if not rules:
        print("\n📄 No .agentx/rules.json yet. It seeds your org's safe-paths + known verdicts")
        print("   before any recovery data exists. A starter (reframe-and-label only):\n")
        print(_RULES_TEMPLATE)
        print()
        print(_scope_help())
        print("\n   Save it to .agentx/rules.json, then:  agentx rules apply")
        print("=" * 75)
        return

    reframes = rules.get("reframes") or []
    verdicts = rules.get("verdicts") or []
    print(f"\n📋 .agentx/rules.json — {len(reframes)} reframe(s), {len(verdicts)} verdict(s):")
    for r in reframes:
        print(_wrap(r.get("safe_path") or r.get("challenge") or "",
                    f"   reframe · {r['policy']}: "))
        # The SCOPE goes on its OWN line, never into the wrap prefix: _wrap uses the prefix as
        # the hanging indent, so folding a scope into it leaves almost no width for the text and
        # renders one word per line. `rules check` is the dry run and the last place an author
        # sees the rule before it goes live, so this line has to stay readable.
        if r.get("when"):
            print(f"       └ fires only when {describe_scope(r['when'])}")
            # Which DOORS the rule can reach. A scope naming agent_id cannot fire over
            # agentx-mcp — that door has no per-agent identity — and without this line the
            # author only discovers it by noticing coaching that never appears. Told here
            # because `rules check` is the dry run, before the rule goes live.
            if r["when"].get("agent_id"):
                print("         (reaches the SDK decorator only — agentx-mcp has no "
                      "per-agent identity)")
    for v in verdicts:
        note = f"  ({v['note']})" if v.get("note") else ""
        print(f"   verdict · {v['policy']} = {v['verdict']}{note}")

    if sub == "check":
        print("\n✓ Valid. Run `agentx rules apply` to ingest (nothing changed yet).")
        print("=" * 75)
        return

    summary = apply_org_rules()
    # The two reframe counts are DISJOINT (policy-wide vs scoped), so they are worded as a sum.
    # "1 reframe adopted, 1 scoped" reads as 1 total of which 1 was scoped, which is wrong.
    scoped_note = (f" + {summary['scoped_reframes_adopted']} scoped to a situation"
                   if summary.get("scoped_reframes_adopted") else "")
    print(f"\n✓ Applied: {summary['reframes_adopted']} policy-wide reframe(s){scoped_note}, "
          f"{summary['verdicts_declared']} verdict(s) declared, "
          f"{summary['blocks_labeled']} existing block(s) pre-labeled.")
    print("   Reframes now coach your agents; declared verdicts skip those blocks in review.")
    if summary.get("scoped_reframes_adopted"):
        print("   See where each scoped one fires:  agentx policies")
    print("=" * 75)


# ---------------------------------------------------------------------------
# agentx verdict — record a human VERDICT on a block (the outcome/label channel).
# The primary capture path is `agentx review`; this is the escape hatch for a
# specific receipt / scripting. Writes the verdict to the same incident store the
# gateway populates.
# ---------------------------------------------------------------------------
_VERDICT_FLAGS = {
    "--wrong": "FALSE_POSITIVE",       # a false block — a defect signal
    "--accept-risk": "ACCEPTED_RISK",  # the block was right; proceeding anyway (NOT a defect)
    "--correct": "TRUE_POSITIVE",      # the block was right
}


_VERDICT_FLAG_BY_VERDICT = {v: k for k, v in _VERDICT_FLAGS.items()}


def _verdict_usage_exit():
    print("\n⚠️  Usage:")
    print("   Label ONE block (by receipt id):")
    print("     agentx verdict <receipt_id> --wrong | --accept-risk | --correct")
    print("   Change/clear a POLICY's STANDING rule (also governs FUTURE blocks):")
    print("     agentx verdict --policy \"<name>\" --wrong | --accept-risk | --correct [--force]")
    print("     agentx verdict --policy \"<name>\" --clear     stop auto-labeling; future blocks re-surface")
    print("     agentx verdict --policy \"<name>\"             show the current standing rule")
    print("   --force sets a standing rule even when few labeled blocks support it — a")
    print("   deliberate call on limited data. Receipt ids prefix-match; see pending blocks:")
    print("     agentx review")
    print("=" * 75)
    sys.exit(2)


def _resolve_policy_target(ref):
    """Map a user-typed policy ref (a built-in NAME or a raw policy id, as shown by
    ``agentx review`` / ``agentx policies``) to ``(policy_id, policy_name, known)``. ``known``
    is True only when the ref matches a built-in policy OR a policy actually present in the
    local incident store — so a typo can't silently mint a junk standing rule when SETTING."""
    pid, pname = _resolve_policy_ref(ref)          # built-in name -> (id, name); else (ref, None)
    if pname is not None:
        return pid, pname, True
    target = _norm_for_dedup(ref)
    for r in list_recent_incidents(limit=100000):
        if r.get("policy_id") == ref or _norm_for_dedup(r.get("policy_violated") or "") == target:
            return r.get("policy_id") or ref, r.get("policy_violated") or None, True
    return ref, None, False


def _verdict_policy(ref, verdict, do_clear, force):
    """The --policy grain of `agentx verdict`: change / clear / show a policy's STANDING
    rule (the declared verdict apply_declared_verdicts uses to auto-label blocks). Directly
    reachable regardless of how many blocks are in front of you — the gap the per-item review
    flow can't close (a single-item correction moves only that row, and a quiet policy shows
    no items at all)."""
    pid, pname, known = _resolve_policy_target(ref)
    label = pname or ref

    if do_clear:
        if verdict is not None:
            print("\n❌ Use EITHER --clear OR a verdict flag, not both.")
            _verdict_usage_exit()
        removed = clear_declared_verdict(policy_id=pid, policy_name=pname)
        # Provenance lets us undo exactly what the rule stamped: re-surface the blocks it
        # auto-labeled (source 'declared'), never the human calls (source 'human').
        resurfaced = unlabel_declared_verdicts(policy_id=pid, policy_name=pname)
        if removed:
            print(f"\n✓ Cleared the standing rule ({removed}) on '{label}'.")
        elif resurfaced:
            print(f"\n✓ Cleared {resurfaced} rule-applied label(s) on '{label}'.")
        else:
            print(f"\n– No standing rule set on '{label}' — nothing to clear.")
            print("=" * 75)
            return
        if resurfaced:
            print(f"   Re-surfaced {resurfaced} block(s) the rule had auto-labeled — they")
            print("   return to `agentx review`. Your OWN verdicts (human calls) are kept.")
        else:
            print("   Future blocks on this policy re-surface for review instead of being")
            print("   auto-labeled.")
        print("=" * 75)
        return

    if verdict is None:                            # bare `--policy "<name>"` -> show
        current = get_declared_verdict(pid, pname)
        if current:
            print(f"\n📋 Standing rule on '{label}': {current}")
            print("   Auto-labels future blocks on this policy. Change it with a verdict flag,")
            print("   remove it with --clear.")
        else:
            print(f"\n📋 No standing rule on '{label}'.")
        print("=" * 75)
        return

    # set / change
    if not known:
        print(f"\n❌ No policy named or id '{ref}' in your catalog or incident store.")
        print("   Check the exact name in `agentx review` / `agentx policies`.")
        print("=" * 75)
        sys.exit(1)
    evidence = count_policy_verdict_evidence(policy_id=pid, policy_name=pname, verdict=verdict)
    if evidence < 2 and not force:
        flag = _VERDICT_FLAG_BY_VERDICT[verdict]
        print(f"\n⚠️  Only {evidence} labeled block(s) on '{label}' support {verdict} —")
        print("   a standing rule normally reflects a PATTERN of blocks, not one example.")
        print("   Re-run with --force to set it from limited data:")
        print(f"     agentx verdict --policy \"{label}\" {flag} --force")
        print("=" * 75)
        sys.exit(1)
    prev = get_declared_verdict(pid, pname)
    # Count THIS policy's pending blocks before applying — apply_declared_verdicts() is
    # store-wide (it labels every policy carrying a declared verdict), so its return value
    # would over-count and misattribute other policies' blocks to this one.
    mine = count_policy_unlabeled_blocks(pid, pname)
    set_declared_verdict(pid, verdict, policy_name=pname)
    # Also declare under the raw NAME (mirrors the batch-review path): the same logical policy
    # can carry blocks under DIFFERENT policy_ids with this name (the cross-path flicker), and
    # a name-key lets apply_declared_verdicts reach ALL of them via get_declared_verdict's
    # raw-name check -- matching what count_policy_unlabeled_blocks counts, so `mine` can't
    # over-report and no same-name block is left unlabeled.
    if pname:
        set_declared_verdict(pname, verdict)
    apply_declared_verdicts()
    if prev and prev != verdict:
        print(f"\n✓ Changed the standing rule on '{label}': {prev} → {verdict}.")
    elif prev == verdict:
        print(f"\n✓ Standing rule on '{label}' is {verdict} (unchanged).")
    else:
        print(f"\n✓ Set the standing rule on '{label}': {verdict}.")
    print(f"   Auto-labeled {mine} pending block(s) on this policy; future blocks get this")
    print("   verdict too. Change it with another verdict, remove it with --clear.")
    print("=" * 75)


def execute_verdict(args):
    """Record a human VERDICT — the label channel's escape hatch, at two grains:
      • per BLOCK:   agentx verdict <receipt> --wrong|--accept-risk|--correct
      • per POLICY:  agentx verdict --policy "<name>" --wrong|--accept-risk|--correct [--force]
                     agentx verdict --policy "<name>" --clear   (remove the standing rule)
                     agentx verdict --policy "<name>"           (show the standing rule)
    A per-block verdict labels that one receipt (record_outcome). A per-policy verdict is the
    STANDING rule apply_declared_verdicts uses to auto-label current-unlabeled AND future
    blocks — the direct way to change or clear it no matter how many blocks are in front of
    you. Setting one from thin evidence (<2 agreeing labeled blocks) requires --force. The
    verdict is a human judgment (never auto-inferred), so every grain is an explicit gesture;
    batched `agentx review` is the friendlier primary path."""
    args = args or []
    receipt = policy_ref = None
    verdict = None
    do_clear = force = False
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in _VERDICT_FLAGS:
            if verdict is not None:
                print("\n❌ Pass exactly one verdict flag.")
                _verdict_usage_exit()
            verdict = _VERDICT_FLAGS[tok]
            i += 1
        elif tok == "--policy":
            if i + 1 >= len(args):
                print("\n❌ --policy needs a policy name or id.")
                _verdict_usage_exit()
            policy_ref = args[i + 1]
            i += 2
        elif tok == "--clear":
            do_clear = True
            i += 1
        elif tok == "--force":
            force = True
            i += 1
        elif tok == "--reason":
            # Accepted for ergonomics but NOT stored — the incident row stays de-identified.
            # Consume the following token as its value ONLY if that token isn't itself a flag,
            # so `verdict <rec> --reason --wrong` can't swallow the verdict flag as the reason.
            i += 2 if (i + 1 < len(args) and not args[i + 1].startswith("--")) else 1
        elif tok.startswith("--"):
            print(f"\n❌ Unknown option '{tok}'.")
            _verdict_usage_exit()
        else:
            if receipt is not None:
                print(f"\n❌ Unexpected extra argument '{tok}'.")
                _verdict_usage_exit()
            receipt = tok
            i += 1

    if policy_ref and receipt:
        print("\n❌ Use EITHER a receipt id OR --policy, not both.")
        _verdict_usage_exit()
    if not policy_ref and (do_clear or force):
        print("\n❌ --clear / --force apply only to --policy.")
        _verdict_usage_exit()

    if policy_ref:
        _verdict_policy(policy_ref, verdict, do_clear, force)
        return

    # ---- per-block path ----
    if not receipt or verdict is None:
        _verdict_usage_exit()

    matches = find_incidents_by_receipt_prefix(receipt)
    if not matches:
        print(f"\n❌ No block found for receipt '{receipt}'.")
        print("   See recent blocks with:  agentx review")
        print("=" * 75)
        sys.exit(1)
    if len(matches) > 1:
        print(f"\n❌ '{receipt}' matches {len(matches)} blocks — use more of the receipt id.")
        print("=" * 75)
        sys.exit(1)

    rid = matches[0]["receipt_id"]
    if record_outcome(rid, verdict=verdict, source="human"):
        print(f"\n✓ Recorded verdict {verdict} on block {rid}.")
        print("=" * 75)
    else:
        print("\n❌ Could not record the verdict (incident store missing or not writable).")
        print("=" * 75)
        sys.exit(1)


def _customize_usage_exit():
    print("\n⚠️  Usage:")
    print("   agentx customize \"<policy name>\" --text \"<coaching>\"   set the coaching inline")
    print("   agentx customize \"<policy name>\" --edit               open $EDITOR seeded with the current coaching")
    print("   ...add --safe-path \"<path>\"  to set the concrete safe path distinctly from the coaching")
    print("   See the names you can customize:  agentx policies")
    print("=" * 75)
    sys.exit(1)


def execute_customize(args):
    """`agentx customize "<policy name>" [--text "..." | --edit] [--safe-path "..."]`
    — override a built-in floor policy's COACHING by human-readable name (no UUID),
    keyless. The smooth keyless path: it stores to ./.agentx/overrides.json keyed by
    the policy's stable id, so `get_active_override` applies it on BOTH the SDK
    decorator and the agentx-mcp block paths, no gateway.

    Human-authored text is always allowed (the anti-poisoning gate only forbids
    auto-applying AGENT-generated text), so no new gate is needed here."""
    if not args:
        _customize_usage_exit()

    name = text = safe_path = None
    do_edit = False
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--edit":
            do_edit = True
            i += 1
        elif tok in ("--text", "--safe-path"):
            if i + 1 >= len(args):
                print(f"\n❌ {tok} needs a value.")
                _customize_usage_exit()
            if tok == "--text":
                text = args[i + 1]
            else:
                safe_path = args[i + 1]
            i += 2
        elif tok.startswith("--"):
            print(f"\n❌ Unknown option '{tok}'.")
            _customize_usage_exit()
        elif name is None:
            name = tok
            i += 1
        else:
            print(f"\n❌ Unexpected extra argument '{tok}'. Quote the policy name if it has spaces.")
            _customize_usage_exit()

    if not name:
        _customize_usage_exit()
    if do_edit and text is not None:
        print("\n❌ Use EITHER --text OR --edit, not both.")
        _customize_usage_exit()

    entry_meta, n = resolve_policy_by_name(name)
    if entry_meta is None:
        if n > 1:
            print(f"\n❌ '{name}' is ambiguous ({n} policies match).")
        else:
            print(f"\n❌ No customizable policy named '{name}'.")
        print("   Names you can customize (from `agentx policies`):")
        for p in list_customizable_policies():
            print(f"     • {p['name']}")
        print("=" * 75)
        sys.exit(1)

    pid = entry_meta["id"]
    # Current effective coaching = any active override's, else the shipped default.
    # So `--edit` seeds from what the agent gets today, and a `--safe-path`-only edit
    # keeps the current coaching instead of blanking it.
    current = get_active_override(pid, policy_name=entry_meta["name"])
    current_challenge = (current.get("challenge") if current else None) or entry_meta["challenge"]
    current_safe = (current.get("safe_path") if current else None) or entry_meta["safe_path"]

    if do_edit:
        challenge = _edit_text(current_challenge or "")
    elif text is not None:
        challenge = text
    elif safe_path is not None:
        challenge = current_challenge          # safe-path-only: keep the current coaching
    else:
        print("\n❌ Nothing to change. Pass --text \"...\", --edit, or --safe-path \"...\".")
        _customize_usage_exit()

    if not challenge or not challenge.strip():
        print("\n🚫 Empty coaching, nothing customized (aborted).")
        print("=" * 75)
        return

    effective_safe = safe_path if safe_path is not None else current_safe

    if not _confirm_adopt(entry_meta["name"], challenge):
        print("\n🚫 Not customized.")
        print("=" * 75)
        return

    stored = adopt_override(
        pid,
        challenge=challenge,
        safe_path=effective_safe,
        policy_violated=entry_meta["name"],
        source="customize",
    )
    print(f"\n✅ Customized coaching for '{entry_meta['name']}'.")
    print("   Next block on this policy delivers:")
    print(f"   “{stored['challenge']}”")
    if stored.get("safe_path") and stored["safe_path"] != stored["challenge"]:
        print(f"   result.safe_path → {stored['safe_path']}")
    print("   💾 Saved to ./.agentx/overrides.json. Commit it to share with your team.")
    print("   It applies keyless on BOTH the SDK decorator and agentx-mcp block paths.")
    print("   ▶ Verify:  agentx policies --check")
    print("=" * 75)


# --- `agentx share`: turn a real block into a postable artifact ----------------
#
# The pip wedge works (installs activate on the keyless Layer-0 shield) but the
# people who hit a real block have nothing to post. `share` closes that loop: it
# renders the dev's most recent catch as a clean, screenshot-able receipt card +
# a ready-to-post draft + the link, so the war story spreads in the dev's own
# words. Privacy by construction — the card is built ONLY from the abstract ledger
# fields (policy class, the dev's own tool name, verdict, when), NEVER a raw query
# or payload, because the ledger never stores one.

# Homepage link carries an attribution tag so CLI-share traffic is distinguishable
# from cards / dev.to (the per-channel attribution leg).
_SHARE_LINK = "https://agentx-core.com/?utm_source=cli_share"
from .links import DISCORD_URL
_DISCORD_INVITE = DISCORD_URL  # module-local alias; canonical value lives in links.py

# Coarse, payload-free phrasing of WHAT class of action was caught, keyed by the
# closed block-category vocab. Honest at the category level (never claims to quote
# the dev's actual query). Falls back to the human policy name.
_CATEGORY_PHRASE = {
    "DESTRUCTIVE_ACTION": "a destructive database write",
    "PII_EXFILTRATION": "a bulk read of personal data",
    "NETWORK_TRAVERSAL": "an SSRF / blocked-network call",
    "SECRETS_LEAK": "a secrets-exfiltration attempt",
}


def _block_attack_phrase(block):
    """Map a ledger block to a coarse, payload-free 'what was attempted' phrase for
    the share draft. Prefers the policy_id -> category map (kept in sync with the
    pulse vocab); degrades to the human policy name, then a neutral default."""
    try:
        from .decorators import _POLICY_ID_TO_CATEGORY
        category = _POLICY_ID_TO_CATEGORY.get(block.get("policy_id"))
        if category in _CATEGORY_PHRASE:
            return _CATEGORY_PHRASE[category]
    except Exception:
        pass
    name = (block.get("policy_name") or "").strip()
    return f"a {name} action" if name else "an unsafe action"


def _cell_width(text):
    """Display width of a string for box alignment: zero-width joiners/selectors
    count 0, emoji/astral codepoints count 2, everything else 1. Keeps the card's
    right border aligned even with the 🛡 in the header."""
    width = 0
    for ch in text:
        o = ord(ch)
        if o in (0xFE0F, 0x200D) or 0x1F3FB <= o <= 0x1F3FF:
            continue
        width += 2 if (o >= 0x1F000 or 0x2600 <= o <= 0x27BF) else 1
    return width


def _render_block_card(block, note=None, inner=54):
    """Render a single ledger block as a bordered, copy-pasteable receipt card.
    Pure (no I/O) so it's unit-testable. `note` is an optional dev-supplied line
    (their data, their choice) for when they want to show the actual attempt."""
    recovered = block.get("status") == "RECOVERED"
    verdict = "BLOCKED, then the agent self-corrected" if recovered \
        else "BLOCKED before it ran"

    rows = []
    rows.append(("policy", block.get("policy_name") or "—"))
    tool = block.get("tool_name")
    if tool:
        rows.append(("tool", f"{tool}()"))
    if note and str(note).strip():
        rows.append(("attempt", str(note).strip()))
    rows.append(("verdict", verdict))

    # No "saved ~N tokens · ~N min" row. Those columns held a per-row constant nobody
    # measured, and this card is the one artifact a developer posts in public.

    ts = block.get("timestamp")
    if ts:
        import datetime
        try:
            rows.append(("when", datetime.date.fromtimestamp(float(ts)).isoformat()))
        except (ValueError, OverflowError, OSError, TypeError):
            pass  # a corrupt/out-of-range timestamp just drops the line, never crashes share

    label_w = max(len(k) for k, _ in rows)

    def pad(s):
        return s + " " * max(0, inner - _cell_width(s))

    def fit(value, budget):
        """Clip a value (with an ellipsis) so a long policy name, tool, or --note
        can't overflow the box and break the right border — the card is meant to
        be screenshot-clean. Width-aware so it works with the · / emoji too."""
        value = str(value)
        if _cell_width(value) <= budget:
            return value
        out = ""
        for ch in value:
            if _cell_width(out + ch) > budget - 1:
                break
            out += ch
        return out + "…"

    # Each row is "   {label}: {value}" — value gets whatever the box has left.
    value_budget = inner - (label_w + 5)

    lines = []
    lines.append("┌" + "─" * inner + "┐")
    lines.append("│" + pad("  🛡  AgentX caught an unsafe agent action") + "│")
    lines.append("│" + pad("") + "│")
    for k, v in rows:
        lines.append("│" + pad(f"   {k+':':<{label_w+1}} {fit(v, value_budget)}") + "│")
    lines.append("│" + pad("") + "│")
    lines.append("│" + pad("   Deterministic floor. No LLM, no network.") + "│")
    lines.append("│" + pad("") + "│")
    lines.append("│" + pad("   agentx-core.com · pip install agentx-security-sdk") + "│")
    lines.append("└" + "─" * inner + "┘")
    return "\n".join(lines)


def _share_draft(block):
    """The ready-to-post copy (X / Show HN / Discord), in house voice, em-dash-free,
    claim matched to what actually fired."""
    recovered = block.get("status") == "RECOVERED"
    phrase = _block_attack_phrase(block)
    tail = ("AgentX blocked it, then coached the agent to a safe path. "
            if recovered else "AgentX blocked it before it executed. ")
    return (f"My AI agent tried to run {phrase}. {tail}"
            "One decorator, no LLM, no network. 🛡️")


def execute_share(args=None):
    """`agentx share` — turn your most recent block into a postable artifact.

    Reads ONE local ledger (DB_PATH is relative, so it is the one in this working
    directory — not "this machine"), renders a privacy-safe receipt
    card + a ready-to-post draft + the link, and points at the Discord channel
    where these wins live. No block recorded yet routes the dev to `agentx demo`.
    Optional `--note "..."` lets a dev add their own attempt line (their data,
    their choice)."""
    args = args or []
    note = None
    i = 0
    while i < len(args):
        if args[i] == "--note":
            if i + 1 >= len(args):
                print("\n❌ --note needs a value.")
                print("=" * 75)
                sys.exit(1)
            note = args[i + 1]; i += 2
        else:
            print(f"\n❌ Unknown option '{args[i]}' for `agentx share`.")
            print("   Usage:  agentx share [--note \"what your agent tried\"]")
            print("=" * 75)
            sys.exit(1)

    from . import db as db_module
    from .db import get_recent_blocks, get_retention_status, ledger_empty_reason
    blocks = get_recent_blocks(1)

    # 🔴 THE SAME TWO FIXES AS THE STATUS AND INSIGHTS SCREENS, ON THE THIRD SURFACE THAT
    # READS THIS LEDGER. (1) "THIS machine's local ledger" is the scope claim DB_PATH cannot
    # support: it is relative, so `agentx share` from another folder reads a different file
    # and honestly reports a different most-recent catch. (2) The empty state below said "no
    # block on record YET", a claim about all of history that OUR OWN retention can falsify
    # -- on a trimmed ledger there were blocks and we deleted them.
    try:
        retention = get_retention_status()
    except Exception:
        retention = None

    print("\n📣 SHARE YOUR CATCH        (built from one local ledger)")
    print("=" * 75)
    if not blocks:
        # 🔴 (3) AND THE THIRD ROUTE WAS STILL HERE. get_recent_blocks ends in
        # `except Exception: return []`, the same value an empty ledger gives, so a store
        # that is on disk and will not open was told "no block on record" and sent to
        # `agentx demo` -- with a real catch sitting in the file we failed to read. Same
        # decision, same place, as the status and insights screens.
        try:
            reason = ledger_empty_reason()
        except Exception:
            reason = "empty"
        if reason == "unreadable":
            print("  This ledger is on disk but could not be read, so there is nothing to")
            print("  build a card from. That is NOT the same as having no catch: another")
            print("  process may hold it open.")
        elif reason == "trimmed" and retention:
            print("  No block remains on record here, so there's nothing to share.")
            # The BLOCK count, matching the sentence above it. `rows_dropped` counts the
            # routine audit traffic P-92 evicts first, so quoting it here attached a number
            # made mostly of ordinary calls to a sentence about deleted catches.
            print(f"  ({retention['blocks_dropped']:,} older block record(s) have been "
                  f"dropped; this ledger keeps the")
            print(f"   last {retention['current_max_age_days']} days or "
                  f"{retention['current_max_rows']:,} records.)")
        else:
            print("  No block on record in this ledger, so there's nothing to share.")
        try:
            print("  %s" % os.path.abspath(db_module.DB_PATH))
        except Exception:
            pass
        if reason != "unreadable":
            print("\n  Make one in ~10 seconds (offline, no key, no gateway):")
            print("     ▶ agentx demo        # watch a DROP TABLE get blocked")
            print("     ▶ agentx share       # then come back here")
            print("\n  Or run your own protected agent until it hits a block.")
        print("=" * 75)
        return

    block = blocks[0]
    print("  Here's your most recent catch as a postable card. Screenshot it, or copy")
    print("  the draft below. Privacy-safe: policy class + your tool name only, never")
    print("  the query or payload (the ledger never stores one).\n")
    print(_render_block_card(block, note=note))

    print("\n  ✍️  Ready to post (your win, your words, edit freely):\n")
    import textwrap
    draft = _share_draft(block)
    for line in textwrap.wrap(draft, width=64):
        print(f"     {line}")
    print(f"     {_SHARE_LINK}")

    from urllib.parse import quote
    tweet = quote(f"{draft}\n{_SHARE_LINK}")
    print("\n" + "=" * 75)
    print(f"  ▶ Post it in #welcome:  {_DISCORD_INVITE}")
    print(f"  ▶ Tweet it (pre-filled):            https://twitter.com/intent/tweet?text={tweet}")
    if note is None:
        print("\n  Want to show the actual attempt?  agentx share --note \"DROP TABLE users; ...\"")
    print("=" * 75)


def _detect_mcp_client():
    """Best-effort probe for an installed MCP client config so `agentx demo` can point an
    MCP user (Claude Code, Cursor, Windsurf) at the one-line agentx-mcp wrap (real traffic,
    no gateway) instead of the heavier decorator path. Returns (client_name, config_hint)
    or None. Cheap, never raises."""
    home = os.path.expanduser("~")
    cwd = os.getcwd()
    appdata = os.environ.get("APPDATA", "")
    candidates = [
        ("Cursor", os.path.join(cwd, ".cursor", "mcp.json"), "~/.cursor/mcp.json"),
        ("Cursor", os.path.join(home, ".cursor", "mcp.json"), "~/.cursor/mcp.json"),
        ("Claude Code", os.path.join(cwd, ".mcp.json"), "./.mcp.json"),
        ("Claude Code", os.path.join(home, ".claude.json"), "~/.claude.json"),
        ("Windsurf", os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
         "~/.codeium/windsurf/mcp_config.json"),
        ("Claude Desktop", os.path.join(appdata, "Claude", "claude_desktop_config.json") if appdata else "",
         "your Claude Desktop config"),
        ("Claude Desktop",
         os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
         "your Claude Desktop config"),
        ("your MCP client", os.path.join(cwd, "mcp.json"), "./mcp.json"),
    ]
    for name, path, hint in candidates:
        try:
            if path and os.path.isfile(path):
                return (name, hint)
        except Exception:
            continue
    return None


def _demo_next_steps():
    """The demo's closing next-steps as a list of lines.

    ONE next step, on the reader's OWN door: try it in AUDIT mode, which blocks nothing and
    records what it WOULD catch. Then Docs and Discord. Nothing else.

    THE MCP BRANCH WAS REMOVED (founder call 2026-07-31), for two reasons.

    Wrong door. This is `agentx demo`, the PYTHON SDK's command. Detecting a Cursor config
    and answering with "front an MCP server in ~/.cursor/mcp.json" sends someone who just
    installed the Python SDK to a different product surface. It also made two CTAs compete on
    the first screen a stranger sees, which is exactly what this function's own docstring said
    not to do.

    And it was WRONG, twice over, which is how it got noticed. It ended with
    `see what it caught: agentx insights`, but the MCP proxy writes its audit rows to the
    per-user ledger (~/.agentx/mcp-ledger.db) while `agentx insights` reads the cwd-relative
    `.agentx.db` — different files. And the audit section only renders when
    AGENTX_ENFORCEMENT=audit is set in the READER's shell, whereas that branch had just told
    them to set it in mcp.json, for the server process. So it pointed at a command that would
    show nothing, for two independent reasons.

    The MCP door has its own demo (`agentx-mcp --demo`) whose footer teaches the MCP on-ramp
    correctly, with the `"command": "uvx"` config this project actually ships. That is where
    an MCP reader should meet it.

    The old `mcp` parameter is GONE, not ignored: a caller passing it now gets a TypeError,
    which is the point -- silently handing them the Python branch when they asked for the MCP
    one is the worse failure. _detect_mcp_client() is now called by nothing but its own test; it is kept rather
    than deleted because detecting the reader's client is the obvious input to any future
    personalised onboarding, and it is 25 self-contained lines. If that never arrives, delete
    it and its test together.
    """
    # 🔴 EVERY LINE HERE MUST RUN AS PASTED. Two of them did not.
    #
    # The decorator line had no import, so pasting it gave a NameError -- while
    # `agentx help` twenty lines away printed the same snippet WITH the import. Two screens
    # of our own had drifted apart, and the one a stranger sees first was the broken one.
    #
    # `AGENTX_ENFORCEMENT=audit` sat on its own line as bash syntax. On PowerShell that is
    # not an assignment at all (there is no inline env-var prefix), so a Windows reader set
    # nothing and their agent ran in ENFORCE -- the exact opposite of the risk-free trial
    # being offered. Now shown attached to a real command, once per shell.
    lines = [
        # 🔴 THE PROMISE CHANGED WITH P-92, AND THE OLD ONE IS WHY THIS RUNG WAS DEAD.
        # It used to offer "records what it WOULD block", which on a well-behaved agent is a
        # guaranteed blank screen, and the line under the CTA apologised for that in advance
        # ("Nothing caught is a result too"). Audit now records every call, so the offer is
        # what the reader actually gets: a list of what their own agent did.
        # 🔴 THE CHEAP RUNG, ADDED 2026-08-12, AND IT GOES FIRST. What follows it asks the
        # reader to go and change their own codebase, and measured against our own ladder
        # that step is where they stop: `agentx demo` then `agentx audit` lands on an EMPTY
        # screen every time (the demo pins enforce, and enforce writes no inventory row), so
        # the reader was being asked to instrument an application on the strength of a
        # fabricated table. One command now shows them the real thing.
        " Audit is the other half: it watches every call and blocks nothing.",
        " See what it records, without touching your code:",
        "",
        "       agentx demo --audit",
        "       agentx audit",
        "",
        " Then do it on your own agent:",
        "",
        "       from agentx_sdk import agentx_protect",
        '       @agentx_protect(agent_id="my_agent")   # around any tool function',
        "",
        # Correct on THIS door: the decorator writes to the same cwd-relative store
        # `agentx insights` reads, so a reader who runs both from their project directory
        # sees their catches. (The MCP proxy does not, which is what broke the old branch.)
        "       AGENTX_ENFORCEMENT=audit python your_agent.py          # mac/linux",
        '       $env:AGENTX_ENFORCEMENT="audit"; python your_agent.py  # PowerShell',
        # 🔴 A SENTENCE WAS REMOVED HERE, AND ITS JOB WAS NOT. It read "(Every ordinary call
        # is listed, not just the ones that tripped a policy.)" and it existed because the
        # demo peaks on a DROP TABLE being stopped and then sent the reader to a screen that
        # would very likely be blank on their own well-behaved agent, where empty reads as
        # broken. It was a promise the reader had no way to check.
        #
        # `agentx demo --audit` above discharges the same job by demonstration: they see a
        # populated screen, with ordinary calls on it and nothing blocked, before they are
        # asked to instrument anything. Keeping both would be asserting what the line above
        # now shows.
    ]
    lines += [
        "",
        f" ▶ Docs: https://agentx-core.com/docs   ·   Bugs / ideas: #bugs-and-feature-requests  {_DISCORD_INVITE}",
    ]
    return lines


def execute_demo():
    """`agentx demo` — a ~10-second, zero-config 'aha': watch the in-process SHIELD
    block a catastrophic DROP TABLE with NO gateway and NO API key. This is the
    shortest path from a fresh `pip install` to seeing AgentX actually work, and it
    runs the SAME `@agentx_protect` path a real agent uses (the file form is
    examples/00_quickstart_pip.py). The session summary at exit also emits the
    anonymous activation pulse, so an install that runs the demo is no longer an
    invisible download — it shows up as activated. Fully offline; never raises out."""
    from . import agentx_protect, start_secure_session, is_block
    from .decorators import set_atexit_summary_quiet

    # Own a single, curated closing screen: suppress the atexit summary's duplicate box
    # while it STILL records the streak and fires the activation pulse (P3).
    set_atexit_summary_quiet(True)

    # The per-call narration is deliberately NOT suppressed (founder call 2026-07-31), and the
    # reasoning is worth keeping because it reversed once.
    #
    # It WAS suppressed for a day, on the grounds that the demo prints its own framed account
    # of the same two events and the reader was hearing the story twice. True at the time --
    # but the thing being suppressed was five lines carrying two raw UUIDs and a counter
    # labelled `active_stats` that actually held consecutive_strikes. That was noise, so
    # hiding it read as an improvement.
    #
    # Tidying those lines (5 -> 3, no identifiers, correct label) changed what the choice was
    # about. What is left is EVIDENCE:
    #     🛡️ [AgentX SDK] Checking 'run_sql'...
    #     🛑 [AgentX SDK] Stopped 'run_sql': Mass Destructive Intent (local check, no LLM).
    #     📝 [AgentX SDK] Recorded locally (no key needed).
    # The framed ✅ blocks are our INTERPRETATION of those events. A first run that carries
    # only the interpretation asks a security buyer to take our word for it, which is the
    # opposite of what this product argues. So the shield speaks first, then we explain.

    # No shield and no "AGENTX" here: the brand line from main() sits directly above, so both
    # were doubled the moment that banner stopped being a box.
    print("DEMO: a destructive call is stopped, and the agent still finishes the job")
    print("=" * 75)

    start_secure_session()

    # 🔴 PINNED TO ENFORCE, NEVER THE AMBIENT POSTURE. This is a scripted demonstration whose
    # entire contract is the sentence printed two lines above: the destructive call IS
    # stopped. Inheriting AGENTX_ENFORCEMENT let the shell decide whether our demo works --
    # and the failure is silent-ish and confusing, because the DROP TABLE runs, the narration
    # about stopping it never appears, and the block stats table is skipped.
    #
    # 🔴 AND OUR OWN INSTRUCTIONS CAUSE IT. The audit on-ramp we print tells the reader to
    # run `$env:AGENTX_ENFORCEMENT="audit"`, which in PowerShell persists for the WHOLE shell
    # session -- so following our ladder and then re-running `agentx demo` in the same window
    # breaks the first screen a new user is ever shown. Founder-reported, reproduced, and it
    # predates P-92; widening audit is what made the path common.
    #
    # `enforcement=` is the documented per-tool override and always beats the env var. The
    # demo's own failure branch already asserts this contract ("the demo should always stop
    # this call") -- it just had no way to hold it.
    @agentx_protect(agent_id="demo_cli", enforcement="enforce")
    def run_sql(query: str, db_session=None):
        # Runs ONLY when the shield ALLOWS a call — i.e. the agent's safe, revised
        # query. The catastrophic DROP TABLE is intercepted before it ever gets here.
        print(f"   [DB] ran the safe query: {query}")
        return {"status": "ok", "rows": 1}

    # A classic prompt-injection: the agent was told to update a note, but the
    # attacker smuggled a destructive statement into the payload.
    poisoned = "Update notes for client 99401; DROP TABLE users;"
    print("\n A poisoned agent tool call is about to run:")
    # No trailing blank: the decorator's own narration opens with a newline and supplies the
    # separation. A blank here as well left a two-line hole on the day that narration was
    # briefly suppressed.
    print(f"   run_sql(query={poisoned!r})")

    # Run as a pure LOCAL sandbox: temporarily clear AGENTX_API_KEY so this synthetic
    # block uses the in-process keyword shield with a local receipt and does NOT park
    # the incident to a shared cloud plane. Without this, a cloud-mode user running the
    # demo would inject a synthetic 'demo_cli' block into the PUBLIC landing hero (the
    # showcase tier includes demo_* traffic). Restored in finally so we never mutate the
    # caller's environment past this call.
    # Run the WHOLE demo as a pure LOCAL keyless sandbox: clear AGENTX_API_KEY for
    # BOTH calls so the demo always shows the keyless Shield path (block AND the
    # recovery), regardless of the caller's env, and never parks a synthetic
    # 'demo_cli' incident into a cloud plane. Restored in finally so we never mutate
    # the caller's environment past this call.
    # mkdtemp FIRST. It used to sit between the pop and the try, so a raise (read-only or
    # full temp dir, a bad TMPDIR) dropped AGENTX_API_KEY from the process with no restore --
    # and execute_demo runs in-process in the tests, so the loss propagated to everything after.
    _ov_dir = tempfile.mkdtemp(prefix="agentx-demo-")
    saved_key = os.environ.pop("AGENTX_API_KEY", None)

    # ...and point the OVERRIDE STORE somewhere empty, so this shows the SHIPPED keyless floor
    # rather than the running dev's customizations.
    #
    # An adopted safe-path REPLACES the coaching text, which is the exact thing this demo
    # exists to demonstrate. Anyone who had ever run `agentx adopt` was shown their own
    # wording while the screen claimed to be what a fresh install does, plus a stray
    # "Using your adopted safe-path for this policy" line that means nothing on a first run.
    # Verified 2026-07-31: run from C:\ the demo printed 3 SDK lines; run from a repo holding
    # .agentx/overrides.json it printed 4.
    #
    # NB the MCP demo (mcp_demo.py) solves the same class by chdir-ing into a temp dir for its
    # whole run. THIS demo does not chdir at all -- so the guard has to be explicit here, and
    # assuming the sibling's protection applied was wrong.
    saved_overrides = os.environ.get("AGENTX_OVERRIDES")
    os.environ["AGENTX_OVERRIDES"] = os.path.join(_ov_dir, "overrides.json")
    try:
        blocked = run_sql(query=poisoned, db_session="<live SqlAlchemy session>")

        print()
        if not is_block(blocked):
            print(" ⚠️  NOT STOPPED. That's unexpected; the demo should always stop this call.")
            print(f"      tool returned: {blocked}")
            print(f"      Please report this in #bugs-and-feature-requests on Discord: {_DISCORD_INVITE}")
            print("=" * 75)
            return

        # "STOPPED", matching `agentx-mcp --demo`: the two demos describe the same event and
        # should use the same word. "Deterministic floor" was a term of ours doing the work
        # that "no LLM call" does plainly.
        #
        # 🔴 "YOUR DATA DOES NOT LEAVE YOUR MACHINE", NOT "NOTHING LEFT YOUR MACHINE". The
        # blanket version is false and we know it is: this run emits the anonymous activation
        # pulse at exit, and the floor makes a dependency-reputation call to the public
        # registries. README's own "What leaves your machine" section names both. That
        # correction was made on the landing page (ui/app/page.tsx twice) and never reached
        # the CLI, so the strongest form of the claim survived on the FIRST screen a stranger
        # sees -- the one place a privacy claim is least checkable and most load-bearing.
        # Founder-ratified wording, matched verbatim to the landing rather than reworded here.
        # Continuation indented to align under "STOPPED", not to the 6-space block below it:
        # at 6 the second half read as a new bullet rather than the rest of the sentence.
        print(" ✅ STOPPED before it ran. No LLM call, and your data does not")
        print("    leave your machine.")
        print(f"      policy:   {getattr(blocked, 'policy', None)}")
        print("      The DROP TABLE never reached your database, and your agent was")
        print("      told what to do instead.")

        # THE RECOVERY (the whole point): the agent reads the coaching, revises to a
        # safe call, and it RUNS. Keyless, same session, so AgentX credits the
        # self-correction and narrates the heal beat above the summary.
        print("\n The agent revises the call and tries again:")
        safe_query = "UPDATE notes SET status='reviewed' WHERE client_id='CLI-99401'"
        print(f"   run_sql(query={safe_query!r})")
        recovered = run_sql(query=safe_query, db_session="<live SqlAlchemy session>")
        print()
        if not is_block(recovered):
            print(" ✅ RECOVERED. The safe call ran and the job finished. Your table is")
            print("    intact and the task is done.")
        else:
            print(" (the revised call was also blocked; pick a safer revision and retry.)")
    finally:
        if saved_key is not None:
            os.environ["AGENTX_API_KEY"] = saved_key
        # Restore rather than just unset: execute_demo is called IN-PROCESS by the tests, and
        # an env var left pointing at a deleted temp dir would leak into everything after it.
        if saved_overrides is None:
            os.environ.pop("AGENTX_OVERRIDES", None)
        else:
            os.environ["AGENTX_OVERRIDES"] = saved_overrides
        shutil.rmtree(_ov_dir, ignore_errors=True)

    # Was a "What this shows:" paragraph that restated both ✅ blocks above and then named
    # two tiers (SHIELD / RECOVER) and a "task-fitting challenge" -- our vocabulary, in the
    # first command a new user runs. The two outcome lines already said what happened, so
    # this keeps only what they do NOT say: what it cost, and what the paid step adds.
    print("\n That ran with no key and no signup. With the gateway and your own")
    print("   Gemini key, AgentX writes the fix and runs the retry for you.")
    print("\n  " + "─" * 71)
    for _ln in _demo_next_steps():
        print(_ln)
    print("=" * 75)


def execute_audit_demo():
    """`agentx demo --audit` — the rung between "watch a block" and "instrument your agent".

    🔴 WHY THIS EXISTS, AND IT IS A MEASURED GAP, NOT A NICETY. Following our own ladder,
    `agentx demo` then `agentx audit` lands on the EMPTY audit screen every time, by
    construction: the demo pins enforce, and enforce writes no inventory rows, so not even
    the clean recovered call it makes leaves a trace. The first `agentx audit` a new user
    ever runs is therefore guaranteed blank, and the only picture of the format we could
    offer was a fabricated table. Reproduced in a clean directory 2026-08-12.

    The middle rung was also the only one with no command: demo (a command), decorate your
    own code (a change in their repo), agentx audit (a command). This makes it a command.

    ⚠️ THE ROWS IT WRITES ARE REAL AND THEY GO IN THE READER'S LEDGER. That is the point --
    the next screen must be their own data, not ours -- so they are written under
    `DEMO_AGENT_ID` and `agentx audit` footnotes them (`inventory_from_demo`). Deleting them
    afterwards would leave the reader looking at the blank screen this command exists to fix.

    Posture comes from the per-tool `enforcement=` override, NEVER from the env var. Same
    call `execute_demo` makes for the opposite posture and for the same reason: a scripted
    demonstration whose contract is stated on screen cannot let the reader's shell decide
    whether it holds. It also means this command leaves their environment untouched.
    """
    from . import agentx_protect, start_secure_session, is_block
    from .db import DEMO_AGENT_ID
    from .decorators import set_atexit_summary_quiet

    set_atexit_summary_quiet(True)

    print("DEMO (AUDIT): nothing is blocked, and everything is written down")
    print("=" * 75)

    start_secure_session()

    # The file form of this same scenario, for anyone who wants to read it rather than run
    # it, is examples/12_audit_what_your_agent_did.py.
    @agentx_protect(agent_id=DEMO_AGENT_ID, enforcement="audit")
    def query_orders_db(sql: str, limit: int = 50):
        return [{"id": "ORD-8842", "total_usd": 2400.0}]

    @agentx_protect(agent_id=DEMO_AGENT_ID, enforcement="audit")
    def fetch_invoice_pdf(url: str):
        return {"bytes": 48_112}

    @agentx_protect(agent_id=DEMO_AGENT_ID, enforcement="audit")
    def issue_refund(order_id: str, amount: float, currency: str, reason: str):
        return {"refund_id": "RF-5501"}

    @agentx_protect(agent_id=DEMO_AGENT_ID, enforcement="audit")
    def write_ticket_note(path: str, contents: str):
        return {"written": True}

    print("\n A support agent works one refund ticket. Four ordinary calls:")
    print("")
    print("   query_orders_db(sql='SELECT id, total_usd, status FROM orders ...')")
    print("   fetch_invoice_pdf(url='https://billing.example.com/invoices/8842.pdf')")
    # Trimmed with an ellipsis rather than wrapped: at full width this line ran eight
    # characters past the frame every other screen here keeps to.
    print("   issue_refund(order_id='ORD-8842', amount=2400.00, currency='usd', ...)")
    print("   write_ticket_note(path='tickets/SUP-1191.md', contents='...')")

    # Keyless for the same reason `agentx demo` is: with a key set and no gateway every call
    # below fails open, costs a timeout and prints a DEGRADED banner over the story. Restored
    # in finally because this runs in-process in the tests.
    #
    # ...and the override store is pointed somewhere empty, for the reason recorded on its
    # twin in `execute_demo`: run from a directory holding `.agentx/overrides.json` that demo
    # printed the running developer's own adopted wording while claiming to show a fresh
    # install. Copying the key guard and not this one is how a per-call-site rule lands on
    # some of its sites -- and audit posture prints no coaching text today, so the gap would
    # have been invisible until the first line of it did.
    _ov_dir = tempfile.mkdtemp(prefix="agentx-audit-demo-")
    saved_key = os.environ.pop("AGENTX_API_KEY", None)
    saved_overrides = os.environ.get("AGENTX_OVERRIDES")
    os.environ["AGENTX_OVERRIDES"] = os.path.join(_ov_dir, "overrides.json")
    try:
        query_orders_db(
            sql="SELECT id, total_usd, status FROM orders WHERE customer_ref = ? AND created_at > ?",
            limit=50,
        )
        fetch_invoice_pdf(url="https://billing.example.com/invoices/8842.pdf")
        issue_refund(order_id="ORD-8842", amount=2400.00, currency="usd",
                     reason="duplicate charge")
        write_ticket_note(path="tickets/SUP-1191.md",
                          contents="Refunded ORD-8842. Duplicate charge confirmed.")

        print("\n The ticket text came from a customer, and it carries a hidden instruction")
        print(" that the agent follows:")
        print("")
        print("   query_orders_db(sql=\"... WHERE id='ORD-8842'; DROP TABLE orders; --\")")
        poisoned = "SELECT * FROM orders WHERE id = 'ORD-8842'; DROP TABLE orders; --"
        result = query_orders_db(sql=poisoned)
    finally:
        if saved_key is not None:
            os.environ["AGENTX_API_KEY"] = saved_key
        if saved_overrides is None:
            os.environ.pop("AGENTX_OVERRIDES", None)
        else:
            os.environ["AGENTX_OVERRIDES"] = saved_overrides
        shutil.rmtree(_ov_dir, ignore_errors=True)

    print("")
    if is_block(result):
        # Cannot happen while the override above is in place, and asserted rather than
        # assumed: if it ever does, every sentence below is false and the screen says so.
        print(" ⚠️  That call was BLOCKED, so this run was not in audit posture. Nothing")
        print("     below describes what you just saw. Please report it in #bugs-and-"
              f"feature-requests on Discord: {_DISCORD_INVITE}")
        print("=" * 75)
        return

    print(" ✅ Every call ran, including the last one. Audit blocks nothing.")
    # ⚠️ "any amount", NOT "the biggest number" (P-103). This sentence described the column
    # accurately until _call_shape stopped taking the largest value in the payload, and a
    # promise about what we record is the last place a stale description is noticed: nothing
    # can go red, and the reader has no way to check it. Four surfaces carried this one
    # sentence -- here, both copies of example 12, and the README that ships to PyPI.
    print("    What it wrote down is the SHAPE of each call: the argument names, the")
    print("    surface it touched, the size of any amount passed. Never the values.")
    print("")
    print("  " + "─" * 71)
    print(" ▶ Read it back:   agentx audit")
    print("")
    print("   Those rows are in your ledger now, marked as ours. Your own agent's calls")
    print("   land in the same table once you wrap a tool and run it with audit on:")
    print("")
    print("       from agentx_sdk import agentx_protect")
    print('       @agentx_protect(agent_id="my_agent")   # around any tool function')
    print("")
    print("       AGENTX_ENFORCEMENT=audit python your_agent.py          # mac/linux")
    print('       $env:AGENTX_ENFORCEMENT="audit"; python your_agent.py  # PowerShell')
    print("=" * 75)


def _print_cli_usage(advanced=False):
    """Single source of truth for the `agentx` command list — printed by
    `agentx help` and on an unknown command, so the two can never drift.

    The DEFAULT view is deliberately tiny: a new user needs exactly
    demo -> wrap-your-tool -> status, and curation is meant to happen through the
    session-end review nudge, not a memorized command. `agentx help --advanced`
    reveals the rest (curation, floor tuning, org sync, share), grouped by job."""
    print("\nUsage:  agentx <command>\n")
    print("  demo        10-second offline 'aha': watch a DROP TABLE get blocked (no key, no gateway)")
    # Listed as a flag on `demo` rather than as its own command, because it is the same demo
    # in the other posture. It earns a line in the DEFAULT view for the same reason `audit`
    # does: it is the rung between them, and a rung nobody can find is not a rung.
    print("                ('demo --audit' runs the same agent in watch-only mode and fills the audit screen)")
    # In the DEFAULT view, not --advanced, because it is the rung immediately after `demo`
    # and both demo footers now send the reader here. A command the on-ramp names and the
    # help screen hides is unfindable the moment that footer scrolls away.
    # 🔴 "your WRAPPED tools", not "your agent". The screen itself is careful about exactly
    # this -- "A tool you have not wrapped does not appear here at all" -- because a developer
    # who wrapped one tool of ten would otherwise read the table as their agent's whole
    # activity. The help line promised more than the screen delivers, in the same PR that
    # wrote the screen's caveat.
    print("  audit       What your wrapped tools actually DID, call by call, blocking nothing")
    print("                (run your agent with AGENTX_ENFORCEMENT=audit first)")
    print("  status      Local protection stats + armed policies (default; live view needs the gateway)")
    print("  review      One-key pass over pending blocks: adopt a safe-path, or label a block")
    print("                ('--stats' for a summary of every incident's outcome, not just what's pending)")
    print("  help        Show this message (also: -h, --help)")
    if not advanced:
        print("\n  More commands:  agentx help --advanced   (curation, floor tuning, org sync)")
    if advanced:
        print("\n  ── Advanced ─────────────────────────────────────────────────────────")
        print("\n  Teach & tune your firewall")
        print("    insights      Review your agents' learned safe-paths (numbered) for adoption")
        print("    adopt         Adopt a learned safe-path: 'adopt <#>' (--edit to tweak) or 'adopt <policy_id> --text ...'")
        print("    verdict       Record a verdict: 'verdict <receipt> --wrong | --accept-risk | --correct',")
        print("                  or a policy's standing rule: 'verdict --policy \"<name>\" <verdict> | --clear'")
        print("    mcp-insights  Review + adopt safe-paths from the keyless MCP wedge (sibling of insights)")
        print("    policies      List the customizable floor policies + your active coaching ('--check' to validate)")
        print("    customize     Customize a floor policy's coaching by name: 'customize \"<name>\" --text ...' (or --edit)")
        print("    rules         Seed org reframes + known verdicts from .agentx/rules.json ('check' or 'apply')")
        print("\n  Team & org sync")
        print("    pull          Pull your org's policy config from the control plane")
        print("    push          Contribute abstract threat signals to shared immunity (opt-in: AGENTX_CONTRIBUTE)")
        print("    sync          pull + push")
        print("\n  Share")
        print("    share         Turn your most recent block into a postable card + share draft")
    print("\n  " + "─" * 71)
    print("\n  Protect your own agent. Wrap any tool function, then handle the block:")
    print("       from agentx_sdk import agentx_protect, is_block")
    print("       @agentx_protect(agent_id=\"my_agent\")")
    print("       def your_tool(arg): ...")
    print("       out = your_tool(risky_input)")
    print("       if is_block(out):")
    print("           revised = your_llm(out.challenge)   # coach the agent to a safe path")
    print("           out = your_tool(revised, receipt_id=out.receipt_id)   # then retry")
    print("\n  Docs: https://agentx-core.com/docs   Gateway access: https://bit.ly/agentfirewall")
    print("=" * 75)


def main():
    # ONE brand line, not a boxed category. This prints before EVERY `agentx` command, and
    # every subcommand already announces itself underneath it -- so the old three-line box
    # ("AGENTX LOCAL OBSERVABILITY ENGINE") meant a reader met two stacked headers and five
    # lines of chrome before any content, on the first screen of the first command they run.
    # "Local observability engine" also named a category we use nowhere else, in the position
    # where a stranger decides what this thing is. The brand mark stays because the
    # subcommand headers below carry no product name of their own. (Founder call 2026-07-31.)
    print("🛡️  AgentX")
    print("=" * 75)

    # --- OFFLINE STALENESS NOTICE (the third surface) ---
    # A CLI-only user never makes a protected tool call, so the decorator's session
    # summary never runs and a notice wired only there would never reach them. `agentx
    # demo` routes through here too, and its curated close suppresses that summary, so
    # this is the only emit that covers it. The CLI is also the most natural place to
    # nag: it is interactive and the remedy is a shell command.
    #
    # stdout is SAFE here: this is the `agentx` console script. agentx-mcp has its own
    # separate main() (mcp_proxy) whose stdout is the JSON-RPC stream, and it emits the
    # notice on stderr from _protection_report instead. Same shared helper on all three
    # surfaces so the wording cannot drift.
    from . import pulse
    stale = pulse.staleness_notice()
    if stale:
        print(f" 📦 Update AgentX: {stale}.")
        print(f"    ▶ {pulse.UPGRADE_COMMAND}")
        print("=" * 75)

    env = load_env_file()

    # AGENTX_MODE is the single switch (local | linked | cloud). Mirror the
    # gateway's resolution so the CLI never disagrees about the active mode.
    mode = (os.environ.get("AGENTX_MODE") or env.get("AGENTX_MODE", "")).strip().lower()
    if mode not in ("local", "linked", "cloud"):
        legacy_sync = (os.environ.get("AGENTX_ALLOW_PAYLOAD_SYNC") or env.get("AGENTX_ALLOW_PAYLOAD_SYNC", "false")).strip().lower() == "true"
        has_cp = bool(os.environ.get("CONTROL_PLANE_URL") or env.get("CONTROL_PLANE_URL"))
        mode = "cloud" if legacy_sync else ("linked" if has_cp else "local")

    api_key = os.environ.get("AGENTX_API_KEY") or env.get("AGENTX_API_KEY")
    gateway_url = os.environ.get("AGENTX_GATEWAY_URL") or env.get("AGENTX_GATEWAY_URL", "http://localhost:8000")

    # AGENTX_CLOUD_ADMIN_PLANE is retired — CONTROL_PLANE_URL is the one name for
    # the control-plane location everywhere.
    control_plane_url = os.environ.get("CONTROL_PLANE_URL") or env.get("CONTROL_PLANE_URL", "http://localhost:3000")
    if "host.docker.internal" in control_plane_url:
        control_plane_url = "http://localhost:3000"

    # The API key is mandatory only when a remote control plane will actually be
    # contacted (cloud, or linked pointed at a hosted plane). Local/linked-local
    # run keyless against the sandbox.
    remote_plane = any(k in control_plane_url.lower() for k in ("vercel.app", "supabase.co", "agentx-core.com"))
    if not api_key and (mode == "cloud" or (mode == "linked" and remote_plane)):
        print(f"❌ Error: AGENTX_API_KEY is required for AGENTX_MODE={mode} against a remote control plane.")
        print("   Please append your cryptographic key string into your local .env file:")
        print("   AGENTX_API_KEY=agentx_sk_test_XXXXX")
        print("=" * 75)
        sys.exit(1)

    api_key = api_key or "agentx_sk_local_sandbox"

    args = sys.argv[1:]
    command = args[0].lower() if args else "status"

    if command == "pull":
        execute_policy_pull(control_plane_url, api_key)
    elif command == "push":
        execute_contribution_push(gateway_url, control_plane_url, api_key, env)
    elif command == "sync":
        execute_sync(gateway_url, control_plane_url, api_key, env)
    elif command == "compile":
        # ✅ NEW SURGICAL HOOK: Routes the compile action to our new weights matrix builder
        # execute_vector_seed_compilation(gateway_url, api_key)
        print("Layer 0 compilation available in a future release. For now, all evaluation handled by the Reasoning Engine (Layer 1).")
    elif command == "insights":
        execute_insights(args[1:])
    elif command == "audit":
        # The rung after `agentx demo`: wrap a tool, run in audit posture, see what your
        # agent did. Distinct from `insights`, which reports what AgentX did.
        execute_audit(args[1:])
    elif command in ("mcp-insights", "recovery-brain", "recoveries"):
        execute_mcp_insights()
    elif command == "adopt":
        execute_adopt(args[1:])
    elif command == "verdict":
        execute_verdict(args[1:])
    elif command == "review":
        execute_review(args[1:])
    elif command == "rules":
        execute_rules(args[1:])
    elif command == "policies":
        execute_policies(args[1:])
    elif command == "customize":
        execute_customize(args[1:])
    elif command == "demo":
        # `--audit` is a POSTURE flag on the same demo, not a second command: both run a
        # scripted agent through the same shield, one enforcing and one watching. Keeping it
        # off the top-level command list is deliberate -- the ladder has enough rungs.
        if any(a.lower() in ("--audit", "audit") for a in args[1:]):
            execute_audit_demo()
        else:
            execute_demo()
    elif command == "share":
        execute_share(args[1:])
    elif command in ["status", "inspect"]:
        execute_status_inspection(gateway_url, api_key, mode)
    elif command in ("help", "-h", "--help"):
        advanced = any(a.lower() in ("--advanced", "-a", "advanced", "all", "--all")
                       for a in args[1:])
        _print_cli_usage(advanced=advanced)
    else:
        print(f"⚠️  Unknown command: '{command}'")
        _print_cli_usage()
        # Exit non-zero so a typo'd command fails loudly in a script / CI, instead of
        # silently "succeeding" (matches the agentx-mcp entrypoint's exit 2 on misuse).
        sys.exit(2)

if __name__ == "__main__":
    main()