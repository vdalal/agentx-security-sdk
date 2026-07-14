import os
import sys
import json
import requests

from .overrides import (harvest_candidates, load_overrides, adopt as adopt_override,
                        incident_db_census, enumerate_candidates,
                        list_customizable_policies, resolve_policy_by_name,
                        get_active_override, _overrides_path)
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
        from .db import get_lifetime_stats
        stats = get_lifetime_stats()
    except Exception:
        stats = None

    if stats and stats.get("total_intercepts", 0) > 0:
        intercepts = stats["total_intercepts"]
        recoveries = stats.get("total_self_corrections", 0)
        rate = (recoveries / intercepts * 100) if intercepts else 0.0
        print("\n📊 LOCAL FLIGHT RECORDER (this machine, no gateway needed):")
        print(f"  🛑 Catastrophic actions blocked: {stats['total_critical']}")
        print(f"  🛡️  Total intercepts:             {intercepts}")
        print(f"  🔄 Self-corrections:             {recoveries}  ({rate:.1f}% recovery)")
        print(f"  💰 Tokens saved:                 ~{stats['total_tokens']}")
        print(f"  ⏳ Time saved:                   ~{stats['total_time']} min")
        print(f"  ⚠️  Top offender:                 {stats['top_offender']}")
    else:
        print("\n📊 LOCAL FLIGHT RECORDER: no blocks recorded on this machine yet.")
        print("   Wrap a tool with @agentx_protect (or one line in mcp.json) and run your")
        print("   agent. Your catches and protection streak show up here.")

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
    print(f"  🔄 Self-corrections:         {telemetry.get('successful_agent_pivots', 0)}"
          f"   ({telemetry.get('agent_self_correction_rate_percent', 0.0)}% recovery)")
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

        policies = response.json().get("policies", [])
        
        target_dir = ".agentx"
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, "policies.json")

        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(policies, f, indent=2)

        print(f"✅ Success: Successfully synchronized {len(policies)} policies down to your local footprint.")
        print(f"💾 Local configuration footprint cached at: ./{target_file}")
        print("=" * 75)

    except Exception as network_fault:
        print(f"❌ Connection fault mapping runtime tracking targets: {network_fault}")
        print("=" * 75)
        sys.exit(1)

def execute_vector_seed_compilation(gateway_url, api_key, output_dir=".agentx"):
    """
    Surgically compiles armed security rules from the gateway cache into an 
    optimized binary float32 weights matrix file for offline lookups.
    """
    import numpy as np
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
            print(f"\n   ✅ Contributed {len(contributions)} abstract signal(s) to shared immunity. Thank you.")
            # Mark the CONTRIBUTE funnel leg on the anonymous pulse (install-local,
            # abstract — the next pulse reports it). Best-effort; never break push.
            try:
                from . import pulse
                pulse.mark_contributed()
            except Exception:
                pass
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
    from .db import get_would_block_summary
    audit = get_would_block_summary()
    if audit["total"]:
        print("\n🔍 AUDIT MODE: what AgentX WOULD have blocked        (nothing was blocked)")
        print("=" * 75)
        print(f"  {audit['total']} action(s) recorded under AGENTX_ENFORCEMENT=audit, by policy:")
        for row in audit["policies"]:
            print(f"     {row['would_blocks']:>4}x   {row['policy_name']}")
        print("\n  These ran normally; audit takes zero risk. When the catches look right,")
        print("  flip to enforcing:   AGENTX_ENFORCEMENT=enforce")
        print("=" * 75)

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
            print("     persists on a gateway built from PR #64+ WITH a Gemini key live")
            print("     at the time of the recovery. Older recoveries won't have it;")
            print("     run a fresh recovery now that your key is set.")
        else:
            print("   • Self-corrections carry a resolution_path, but none were marked")
            print("     reusable by the judge yet. Keep running — reusable ones accrue.")
        if mcp_flat:
            print(f"\n  ▶ You DO have {len(mcp_flat)} keyless MCP recovery path(s): agentx mcp-insights")
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
    print(f"\n  {census['complied']} recoveries · {census['with_resolution']} reusable fixes · "
          f"{n} {'policy' if n == 1 else 'policies'}"
          f"        ▶ adopt with:  agentx adopt <#>")
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
                    print(f"        +{len(alts) - 2} more  →  agentx insights --verbose")
        elif candidates:
            # Not coaching yet: this is where the dev actually needs to act.
            print("     ⚠️  Not coaching this block yet — adopt one so AgentX coaches it:")
            for c in candidates[:3]:
                seq = seq_by_pid.get(pid, {}).get(c["suggestion"], "?")
                print(_wrap(c["suggestion"] + meta(c), f"        #{seq}  "))
            if len(candidates) > 3:
                print(f"        +{len(candidates) - 3} more  →  agentx insights --verbose")

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

    # One primary CTA; advanced forms demoted to a single dim line.
    print("\n" + "=" * 75)
    print(f"  ▶ Adopt the one you trust:   agentx adopt <#>{example}")
    print("       tweak first:  agentx adopt <#> --edit        write your own:  agentx adopt <id> --text \"…\"")
    if rule_list:
        print("       author a rule:  agentx adopt --rule --action <a> --desc \"…\"")
    print()
    print("  Adopted coaching lands in ./.agentx/overrides.json. Commit it to share with your")
    print("  repo. A rule lands in your local policy store (the gateway enforces it next start).")
    print("\n  Share adopted safe-paths across your team + add the full deterministic floor:")
    print("     https://bit.ly/agentfirewall")
    if mcp_flat:
        print(f"\n  Also: {len(mcp_flat)} safe-path(s) from your keyless MCP wedge → agentx mcp-insights")
    if not verbose:
        print("\n  (agentx insights --verbose for ids, dates, counts, store path & full wording)")
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
        tag = "   ✏️  customized" if p["customized"] else ""
        print(f"\n  📋 {p['name']}{tag}")
        challenge = p["active_challenge"] or p["default_challenge"]
        safe = p["active_safe_path"] or p["default_safe_path"]
        if challenge:
            print(_wrap(challenge, "     coaching:   "))
        if safe:
            print(_wrap(safe, "     safe path:  "))

    print("\n" + "=" * 75)
    first = policies[0]["name"] if policies else "<name>"
    print(f"  ▶ Customize one:      agentx customize \"{first}\" --edit")
    print("  ▶ Validate your store:  agentx policies --check")
    print("  Customized coaching lands in ./.agentx/overrides.json. Commit it to share with")
    print("  your team. It applies keyless on BOTH the SDK decorator and agentx-mcp.")
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

    active = load_overrides(warn=True).get("overrides", {})
    if not active:
        print(f"\n  ✅ {path} parses. No active overrides in it yet.")
        print("=" * 75)
        if not rulebook_ok:
            sys.exit(1)
        return

    catalog = {p["id"]: p["name"] for p in list_customizable_policies()}
    real = [(pid, e) for pid, e in active.items() if isinstance(e, dict) and e.get("challenge")]
    print(f"\n  ✅ {path} parses.  {len(real)} active override(s):")
    for pid, entry in real:
        label = entry.get("policy_violated") or catalog.get(pid) or pid
        print(f"\n  📋 {label}   (source: {entry.get('source', '?')})")
        print(_wrap(entry["challenge"], "     coaching:   "))
        if entry.get("safe_path"):
            print(_wrap(entry["safe_path"], "     safe path:  "))
    print("\n" + "=" * 75)
    print("  ▶ Change one:   agentx customize \"<name>\" --edit")
    print("=" * 75)
    # A malformed RULEBOOK exits non-zero even when the override store is pristine: the
    # operator's agent is failing closed, and a green exit code here would say otherwise.
    # Success just RETURNS: a sys.exit(0) would tear down any caller that imports this.
    if not rulebook_ok:
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
# from cards / dev.to (the per-channel attribution leg of Task #3).
_SHARE_LINK = "https://agentx-core.com/?utm_source=cli_share"
_DISCORD_INVITE = "https://discord.gg/PmWRTtaSx2"

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

    tokens = block.get("tokens_saved") or 0
    mins = block.get("time_saved_mins") or 0
    if tokens or mins:
        rows.append(("saved", f"~{tokens} tokens · ~{mins} min"))

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

    Reads the LOCAL ledger (this machine only), renders a privacy-safe receipt
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

    from .db import get_recent_blocks
    blocks = get_recent_blocks(1)

    print("\n📣 SHARE YOUR CATCH        (built from THIS machine's local ledger)")
    print("=" * 75)
    if not blocks:
        print("  No block on record yet, so there's nothing to share.")
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
    print(f"  ▶ Post it in #show-your-agent-app:  {_DISCORD_INVITE}")
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


def _demo_next_steps(mcp):
    """The demo's closing next-steps as a list of lines. `mcp` is (client_name, config_hint)
    or None. Split out so the MCP-vs-decorator branch is unit-testable without running the
    whole demo.

    ONE primary next step (protect a real surface, framed so the protection streak GROWS —
    the return hook the post-demo funnel was missing) plus audit as the safe-first variant,
    then a single Discord support line. Deliberately NOT here: Recover is already taught in
    the 'What this shows' paragraph, so it is not repeated as a competing CTA; and
    `agentx share` is omitted because the demo's catch is SYNTHETIC (identical every run),
    not a unique war-story worth posting. The MCP branch says 'Have {name}?' rather than
    'You're running {name}' — the detector only found a client CONFIG on disk, which does
    not mean the dev ran the demo from that client (they may be evaluating the Python SDK)."""
    lines = []
    if mcp:
        name, cfg = mcp
        lines += [
            f" Have {name}? Protect a REAL MCP server the same way: one line, no code, no key.",
            f"   In {cfg}, front any server's command with agentx-mcp:",
            '       "command": "agentx-mcp",',
            '       "args": ["npx", "-y", "your-mcp-server", "..."]',
            f" 1 ▶ Then use {name} as usual. Every real tool call is screened, and your",
            "     protection streak grows each session:  agentx status",
            " 2 ▶ Not sure it's safe to enforce on a real server? Front it in audit first:",
            "       AGENTX_ENFORCEMENT=audit   (records what it WOULD block, blocks nothing)",
            "     Then see what it caught, risk-free:  agentx insights",
            " ▶ Prefer to wrap Python tools directly?  https://agentx-core.com/docs",
        ]
    else:
        lines += [
            " 1 ▶ Protect your own agent. Wrap any tool, then coach and retry on a block:",
            "       from agentx_sdk import agentx_protect, is_block",
            '       @agentx_protect(agent_id="my_agent")',
            "       def your_tool(arg): ...",
            "       out = your_tool(risky_input)",
            "       if is_block(out):",
            "           revised = your_llm(out.challenge)   # coach it to a safe path",
            "           out = your_tool(revised, receipt_id=out.receipt_id)   # then retry",
            " 2 ▶ Wrap a tool, run your agent, then watch your protection streak grow:  agentx status",
            " 3 ▶ Not sure it's safe to enforce on a real agent? Run it in audit first:",
            "       AGENTX_ENFORCEMENT=audit   (records what it WOULD block, blocks nothing)",
            "     Then see what it caught, risk-free:  agentx insights",
        ]
    lines += [
        f" ▶ A bug or feature request? #bugs / #feature-requests on Discord: {_DISCORD_INVITE}",
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

    print("🛡️  AGENTX DEMO:  a blocked agent that RECOVERS and finishes (no key, no gateway)")
    print("=" * 75)

    start_secure_session()

    @agentx_protect(agent_id="demo_cli")
    def run_sql(query: str, db_session=None):
        # Runs ONLY when the shield ALLOWS a call — i.e. the agent's safe, revised
        # query. The catastrophic DROP TABLE is intercepted before it ever gets here.
        print(f"   [DB] ran the safe query: {query}")
        return {"status": "ok", "rows": 1}

    # A classic prompt-injection: the agent was told to update a note, but the
    # attacker smuggled a destructive statement into the payload.
    poisoned = "Update notes for client 99401; DROP TABLE users;"
    print("\n A poisoned agent tool call is about to run:")
    print(f"   run_sql(query={poisoned!r})\n")

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
    saved_key = os.environ.pop("AGENTX_API_KEY", None)
    try:
        blocked = run_sql(query=poisoned, db_session="<live SqlAlchemy session>")

        print()
        if not is_block(blocked):
            print(" ⚠️  NOT BLOCKED. That's unexpected; the demo should always block.")
            print(f"      tool returned: {blocked}")
            print(f"      Please report this in #bugs on Discord: {_DISCORD_INVITE}")
            print("=" * 75)
            return

        print(" ✅ BLOCKED before execution. Deterministic floor: no LLM, no network.")
        print(f"      policy:   {getattr(blocked, 'policy', None)}")
        print("      The DROP TABLE never reached your database, and it came back as")
        print("      coaching your agent can act on, not a fatal 403.")

        # THE RECOVERY (the whole point): the agent reads the coaching, revises to a
        # safe call, and it RUNS. Keyless, same session, so AgentX credits the
        # self-correction and narrates the heal beat above the summary.
        print("\n Now the agent does what a 403 never allows: it revises and retries:")
        safe_query = "UPDATE notes SET status='reviewed' WHERE client_id='CLI-99401'"
        print(f"   run_sql(query={safe_query!r})")
        recovered = run_sql(query=safe_query, db_session="<live SqlAlchemy session>")
        print()
        if not is_block(recovered):
            print(" ✅ RECOVERED. The safe call cleared the shield and ran. The task")
            print("    CONTINUED instead of crashing: no 403, no wiped table, no dead run.")
        else:
            print(" (the revised call was also blocked; pick a safer revision and retry.)")
    finally:
        if saved_key is not None:
            os.environ["AGENTX_API_KEY"] = saved_key

    print("\n What this shows: AgentX blocked a catastrophic call offline AND coached your")
    print("   agent to a safe path, so the run SURVIVED. Zero keys, zero gateway.")
    print("   That's SHIELD (keyless). RECOVER (gateway + your own key) writes the")
    print("   task-fitting challenge for you and runs the retry automatically.")
    print("=" * 75)
    for _ln in _demo_next_steps(_detect_mcp_client()):
        print(_ln)
    print("=" * 75)


def _print_cli_usage():
    """Single source of truth for the `agentx` command list — printed by
    `agentx help` and on an unknown command, so the two can never drift."""
    print("\nUsage:  agentx <command>\n")
    print("  demo        10-second offline 'aha': watch a DROP TABLE get blocked (no key, no gateway)")
    print("  share       Turn your most recent block into a postable card + share draft")
    print("  status      Local protection stats + armed policies (default; live view needs the gateway)")
    print("  pull        Pull your org's policy config from the control plane")
    print("  push        Contribute abstract threat signals to shared immunity (opt-in: AGENTX_CONTRIBUTE)")
    print("  sync        pull + push")
    print("  insights    Review your agents' learned safe-paths (numbered) for adoption")
    print("  mcp-insights  Review + adopt safe-paths from the keyless MCP wedge (sibling of insights)")
    print("  adopt       Adopt a learned safe-path: 'adopt <#>' (--edit to tweak) or 'adopt <policy_id> --text ...'")
    print("  policies    List the customizable floor policies + your active coaching ('--check' to validate)")
    print("  customize   Customize a floor policy's coaching by name: 'customize \"<name>\" --text ...' (or --edit)")
    print("  help        Show this message (also: -h, --help)")
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
    print("=" * 75)
    print("🛡️  AGENTX LOCAL OBSERVABILITY ENGINE")
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
    elif command in ("mcp-insights", "recovery-brain", "recoveries"):
        execute_mcp_insights()
    elif command == "adopt":
        execute_adopt(args[1:])
    elif command == "policies":
        execute_policies(args[1:])
    elif command == "customize":
        execute_customize(args[1:])
    elif command == "demo":
        execute_demo()
    elif command == "share":
        execute_share(args[1:])
    elif command in ["status", "inspect"]:
        execute_status_inspection(gateway_url, api_key, mode)
    elif command in ("help", "-h", "--help"):
        _print_cli_usage()
    else:
        print(f"⚠️  Unknown command: '{command}'")
        _print_cli_usage()
        # Exit non-zero so a typo'd command fails loudly in a script / CI, instead of
        # silently "succeeding" (matches the agentx-mcp entrypoint's exit 2 on misuse).
        sys.exit(2)

if __name__ == "__main__":
    main()