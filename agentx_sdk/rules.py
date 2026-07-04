"""
agentx_sdk/rules.py — the DETECTION half of the unified learning loop.

Sibling of ``overrides.py`` (the RECOVERY half). The gateway extracts a structural
``rule_suggestion`` on every judge-caught incident — the detection analog of
``resolution_path`` (see designs/unified-learning-loop.md). This module closes the
loop on the CLI:

  * HARVEST — ``harvest_rule_candidates()`` projects the *reusable*
              ``rule_suggestion`` rows from the local incident store into ranked
              structural-rule candidates.
  * ADOPT   — ``adopt_rule()`` writes the chosen candidate as a structural policy
              into the local policy store (``.agentx/policies.db``). The gateway
              already loads + evaluates that store at boot (symbolic
              ``target_action`` + neural ``semantic_description``), and boot
              reconciliation never overwrites non-baseline rows — so the rule goes
              live on the gateway's next start with ZERO gateway change, the same
              elegance as the SDK-swap for reframes. The manual adopt step is the
              anti-poisoning gate: an agent-derived rule never arms itself.

A structural rule generalizes (it matches the behavior CLASS via target_action +
semantic_description); exact ``indicators`` are the optional IOC subtype. This is
why a *rule* replaces the brittle string *signature* of the old immunity layer.

Tenant-private (the org brain). Pure standard library so it is import-safe at SDK
module load (the 0.3.1 import-safety lesson).
"""
import json
import os
import sqlite3
import uuid

# Reuse the project-root anchor + incident-store resolver + timestamp so the CLI
# and the gateway agree on where the shared .agentx/ stores live, from any cwd.
from .overrides import (_find_project_root, _incident_db_path, _now_iso,
                        cluster_near_duplicates)

# The gateway's local policy store (backend/policy_store.py) lives next to
# incidents.db under the shared .agentx/ mount. Same two real layouts as the
# incident store; an explicit AGENTX_POLICY_DB always wins (what the tests use).
_POLICY_DB_CANDIDATES = (
    os.path.join(".agentx", "policies.db"),
    os.path.join("agentx_sdk", ".agentx", "policies.db"),
)
DEFAULT_POLICY_DB = _POLICY_DB_CANDIDATES[0]

# Mirrors backend/policy_store.py init_db exactly so a rule the CLI writes is read
# back verbatim by the gateway. Kept in sync by the parity test in test_rules.py.
_CREATE_POLICIES_SQL = """
    CREATE TABLE IF NOT EXISTS policies (
        id                   TEXT PRIMARY KEY,
        created_at           TEXT,
        name                 TEXT,
        semantic_description TEXT,
        target_action        TEXT,
        blocked_intents      TEXT,
        pii_targets          TEXT,
        socratic_prompt      TEXT,
        is_active            INTEGER
    )
"""

_RULE_HARVEST_QUERY = (
    "SELECT policy_violated, rule_suggestion "
    "FROM incidents WHERE rule_suggestion IS NOT NULL"
)


def _policy_db_path(path=None):
    """Resolve the gateway's local policy store. Explicit arg / ``AGENTX_POLICY_DB``
    win; else the first candidate that exists under the project root; else the
    primary default under that root. Project-root-anchored so the CLI writes the
    same DB the gateway reads, from any subdirectory."""
    if path:
        return path
    env = os.environ.get("AGENTX_POLICY_DB")
    if env:
        return env
    root = _find_project_root()
    for candidate in _POLICY_DB_CANDIDATES:
        full = os.path.join(root, candidate)
        if os.path.exists(full):
            return full
    return os.path.join(root, DEFAULT_POLICY_DB)


def _parse_json_obj(raw):
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else None
    except (TypeError, ValueError):
        return None


def harvest_rule_candidates(db_path=None):
    """Project the local incident store's *reusable* ``rule_suggestion`` rows into
    ranked, deduplicated structural-rule candidates.

    Returns a list of ``{target_action, effect_category, semantic_description,
    indicators, policy_violated, count}`` sorted most-recurred first (ties broken
    deterministically) so the global ``#N`` numbering in ``agentx insights`` stays
    stable between listing and ``agentx adopt <#>``. Identical suggestions collapse
    and accrue a count; indicators union across the collapsed rows.

    A missing DB or older schema (no ``rule_suggestion`` column) yields ``[]`` —
    the keyless / fresh case the caller renders as an honest empty state.
    ``rule_suggestion`` is judge-produced, so it is ``NULL`` keyless and this
    returns ``[]`` until the dev runs the Recover tier (a Gemini key).
    """
    p = _incident_db_path(db_path)
    if not os.path.exists(p):
        return []
    try:
        conn = sqlite3.connect(p)
        try:
            rows = conn.execute(_RULE_HARVEST_QUERY).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []

    by_key = {}
    for policy_violated, rs_raw in rows:
        rs = _parse_json_obj(rs_raw)
        if not rs or not rs.get("reusable"):
            continue
        desc = (rs.get("semantic_description") or "").strip()
        if not desc:
            continue
        action = (rs.get("target_action") or "other").strip()
        effect = (rs.get("effect_category") or "OTHER").strip()
        key = (action, effect, desc)
        cand = by_key.setdefault(key, {
            "target_action": action,
            "effect_category": effect,
            "semantic_description": desc,
            "indicators": [],
            "policy_violated": policy_violated,
            "count": 0,
        })
        cand["count"] += 1
        if policy_violated and not cand.get("policy_violated"):
            cand["policy_violated"] = policy_violated
        inds = rs.get("indicators")
        if isinstance(inds, list):
            for ind in inds:
                ind = (ind or "").strip() if isinstance(ind, str) else ""
                if ind and ind not in cand["indicators"]:
                    cand["indicators"].append(ind)

    # Collapse near-duplicate phrasings WITHIN the same (action, effect) — the
    # judge rewords one threat's description many ways; merge them so recurrence
    # accumulates instead of fragmenting into count=1 entries. Indicators union
    # across the merged rows.
    def _union_indicators(rep, other):
        for ind in other.get("indicators") or []:
            if ind and ind not in rep["indicators"]:
                rep["indicators"].append(ind)

    groups = {}
    for c in by_key.values():
        groups.setdefault((c["target_action"], c["effect_category"]), []).append(c)
    merged = []
    for group in groups.values():
        merged.extend(cluster_near_duplicates(
            group, text_key="semantic_description", merge_extra=_union_indicators))

    return sorted(
        merged,
        key=lambda c: (-c["count"], c["effect_category"], c["target_action"],
                       c["semantic_description"]),
    )


def adopt_rule(candidate, *, challenge=None, path=None):
    """Write a structural-rule candidate into the local policy store as an ACTIVE
    policy — the human gate. Returns the stored ``{id, name, ...}`` dict.

    The gateway evaluates it on its next boot (symbolic ``target_action`` + neural
    ``semantic_description``; ``indicators`` are the exact-match IOC subtype). A
    fresh ``rule-<uuid>`` id keeps it out of the way of baseline reconciliation.
    """
    if not candidate or not str(candidate.get("semantic_description") or "").strip():
        raise ValueError("a rule candidate with a semantic_description is required")

    p = _policy_db_path(path)
    parent = os.path.dirname(p)
    if parent:
        os.makedirs(parent, exist_ok=True)

    rule_id = "rule-" + uuid.uuid4().hex[:12]
    effect = candidate.get("effect_category") or "OTHER"
    action = candidate.get("target_action") or "action"
    name = candidate.get("policy_violated") or f"{effect} via {action}"
    desc = str(candidate["semantic_description"]).strip()
    indicators = [i for i in (candidate.get("indicators") or []) if i]
    socratic = challenge or (
        f"Policy Violation: {name}. This action matches a dangerous pattern your "
        f"own incidents taught AgentX ({desc}). Reach the goal a safe way instead, "
        f"or request human approval."
    )

    conn = sqlite3.connect(p)
    try:
        conn.execute(_CREATE_POLICIES_SQL)
        conn.execute(
            """
            INSERT OR REPLACE INTO policies (
                id, created_at, name, semantic_description, target_action,
                blocked_intents, pii_targets, socratic_prompt, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule_id, _now_iso(), name, desc, action,
                json.dumps(indicators), None, socratic, 1,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return {"id": rule_id, "name": name, "target_action": action,
            "effect_category": effect, "semantic_description": desc,
            "indicators": indicators, "socratic_prompt": socratic, "path": p}
