"""
agentx_sdk/rules.py — the DETECTION half of the unified learning loop.

Sibling of ``overrides.py`` (the RECOVERY half). The gateway extracts a structural
``rule_suggestion`` on every judge-caught incident — the detection analog of
``resolution_path``. This module closes the
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

              🔴 AND IT HAS TO HOLD OFF A TERMINAL TOO, WHICH TAKES AN EXPLICIT GATE.
              A confirm that auto-proceeds when stdin is not a tty makes the ABSENCE of
              a human the strongest approval it can get — `agentx adopt <#>` from a CI
              job, a git hook, or an agent shelling out would write an is_active=1 rule
              with nothing typed, while a person pressing Enter at the same prompt
              declines. So the no-tty path declines, and `--yes` is how a person
              delegates that approval to a script in advance.
              See sdk_tests/test_no_human_means_decline.

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
from .overrides import (_anchored_root, _incident_db_path, _now_iso,
                        cluster_near_duplicates)

# The gateway's local policy store lives next to incidents.db
# in the project's ONE .agentx/ home. BACKLOG P-76.
#
# 🔴 THIS WAS A CANDIDATE LIST SEARCHED FOR "the first that EXISTS", the same defect the
# incident store had and for the same reason. It is worse here than there, because this
# module WRITES: `agentx rules apply` creates the policy row the gateway is supposed to
# arm. On the pre-P-76 layout the root store does not exist and the nested one does, so
# the CLI wrote `agentx_sdk/.agentx/policies.db`, reported success, and the gateway --
# now root-anchored on the gateway side too -- read a different file. The rule never
# armed and nothing said so. A silent write to the wrong store is worse than a silent
# read from one.
#
# An explicit AGENTX_POLICY_DB always wins (what the tests use).
DEFAULT_POLICY_DB = os.path.join(".agentx", "policies.db")

# Mirrors the gateway's policy-store schema exactly so a rule the CLI writes is read
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
    """Resolve the gateway's local policy store. Explicit arg / ``AGENTX_POLICY_DB`` win,
    else the ONE canonical store under the project root.

    Existence is deliberately NOT part of the rule -- see the comment on
    DEFAULT_POLICY_DB. This resolves to the same file the gateway's policy store writes, from
    any subdirectory, which is the whole point: the CLI writes the policy the gateway
    arms."""
    if path:
        return path
    env = os.environ.get("AGENTX_POLICY_DB")
    if env:
        return env
    return os.path.join(_anchored_root(), DEFAULT_POLICY_DB)


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


def _seen_clause(count, total_calls, distinct_tools):
    """How thin the evidence is, for a candidate with no magnitude to speak for it.

    🔴 THE COMPARISON HAS TO EXIST BEFORE WE IMPLY ONE. "seen once, out of 129 calls" invites
    the reader to weigh this tool against the rest of the ledger, which is a real signal. In a
    ledger holding ONE tool there is nothing to weigh it against, and "out of 1 calls" would be
    a comparison dressed up out of nothing -- the same defect as the sentence that once called
    a tool "Infrequent" after 120 calls, one level up. So that case says what is actually true:
    it is the only tool we have seen.

    🔴 AND THE DENOMINATOR NAMES ITS POPULATION, BECAUSE A BLOCK COUNT SITS ABOVE IT. The
    caller's query is `WHERE status = INVENTORY_STATUS` ("ALLOWED"), so this total counts the
    developer's ALLOWED calls and excludes every block outright -- two disjoint sets. Rendered
    as a bare "out of 39 calls" on the insights screen, it sat a few lines under "43 blocks
    recorded", and the arithmetic a reader tries is impossible: more blocks than calls, on a
    narrower set of tools. Found on a real repo ledger; a fixture holding no blocks cannot
    show it at all, because there the two figures never meet.
    Neither number was wrong. Nothing said they answer different questions, which is the same
    defect as the run_query row that read 122 under a sentence saying 120.
    """
    times = "once" if count == 1 else "%d times" % count
    if distinct_tools <= 1:
        return "seen %s, and the only tool here" % times
    return "seen %s, out of %s allowed calls" % (times, f"{total_calls:,}")


def harvest_rule_candidates_from_calls(db_path=None, limit=5):
    """Propose rules from the calls that were ALLOWED, ranked by what they touched.

    The SECOND candidate source. ``harvest_rule_candidates`` reads the incident store and only
    rows where the judge left a suggestion, so it returns nothing without a key and nothing
    until something was already caught. This one reads the plain log of calls that HAPPENED,
    which needs no key, no model and no incident, and works on the first run.

    That is where the new information is: a call the floor allowed is one we have no rule for
    yet. The "this would just re-derive the eight built-ins" objection applies to blocks, not
    here.

    RANKING: recorded magnitude first, then rarity. Both are computed from what the CALLER
    passed, never from a name list -- an allowlist of "dangerous-sounding" verbs is the
    enumeration treadmill, and it needs a growing set of exceptions to stay correct.

    🔴 RARITY ALONE WAS NOT ENOUGH, AND MAGNITUDE ALONE IS NOT EITHER. Rarity degenerates at
    the volumes a real install has (across four tools everything is rare), and magnitude is
    silent for a tool that takes no count at all -- a production deploy, a credential
    rotation. Ordering by magnitude and breaking ties on rarity keeps both: on the reference
    day of 199 calls the top four are exactly the four worth a rule, ahead of 120 queries, 40
    fetches and 25 file writes.

    ⚠️ THE HONEST LIMIT. That day was generated by a file that also wrote the answer key, so
    the ordering is a shape test rather than proof. Only a real log settles it.

    Returns the SAME candidate shape ``harvest_rule_candidates`` returns, so ``adopt_rule``
    needs no change and the human gate is unchanged: an agent-derived rule never arms itself.
    Returns ``[]`` on a missing ledger, an older schema, or no traffic -- the empty state the
    caller renders honestly rather than padding.
    """
    from . import db as _db

    path = db_path or _db.DB_PATH
    if not os.path.exists(path):
        return []

    # 🔴 OUR OWN TRAFFIC IS NOT THEIR AGENT. `agentx demo --audit` writes a full inventory on
    # purpose, so without this the very first thing we would propose is a rule derived from
    # our own demo. Reuses the shared fragment rather than hand-rolling the filter, which is
    # the drift this helper was extracted to prevent.
    excluded = [a for a in _db.OUR_AGENT_IDS if a]
    frag, frag_params = _db._exclude_agents_fragment(excluded)

    # ONE grouped pass. The per-tool pattern this deliberately avoids was measured at 20,013
    # queries on a wide ledger; the fix named there is to fold into the group, not add to it.
    sql = (
        "SELECT tool_name, MAX(quantity), COUNT(*), "
        "GROUP_CONCAT(DISTINCT arg_names), GROUP_CONCAT(DISTINCT target_class) "
        "FROM event_log "
        "WHERE status = ? AND tool_name IS NOT NULL AND tool_name != ''" + frag +
        " GROUP BY tool_name "
        # 🔴 NO LIMIT IN THE QUERY. It used to take the top 5 and THEN drop the tools already
        # ruled on, so a developer who adopted rules for their five biggest tools got an empty
        # list forever while tools 6..N sat there as perfectly good candidates. Truncation
        # after filtering, never before.
        "ORDER BY MAX(quantity) DESC, COUNT(*) ASC, tool_name ASC")
    try:
        conn = sqlite3.connect(path)
        try:
            rows = conn.execute(
                sql, tuple([_db.INVENTORY_STATUS] + list(frag_params))).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        # A pre-quantity ledger has no such column. An older schema yields nothing rather
        # than raising, exactly as the incident-store harvester does.
        return []

    # 🔴 THE LEDGER'S OWN SHAPE, READ ONCE, SO EVERY LINE CAN CARRY ITS REASON. Computed over
    # ALL rows before the per-tool loop, and before the `existing` filter and the `limit` break,
    # so "out of 129 calls" is not "out of the calls we happened to still be proposing".
    #
    # ⚠️ IT IS THE DEVELOPER'S OWN CALLS, NOT THE LEDGER'S. The query above already excludes our
    # demo agents, so this total is the same population the audit screen's "ran 21 of YOUR 39
    # calls" line counts -- and deliberately NOT the "60 calls across 8 tools" header, which is
    # ledger-wide. An earlier version of this comment claimed it matched the header; it does
    # not, and on a ledger holding demo traffic the two differ by exactly our rows.
    total_calls = sum(int(c or 0) for _, _, c, _, _ in rows)
    distinct_tools = len(rows)

    existing = _existing_rule_actions(path=None)
    candidates = []
    for tool_name, quantity, count, arg_names, classes in rows:
        if not tool_name or tool_name in existing:
            continue
        names = sorted({n for n in (arg_names or "").split(",") if n})
        klass = sorted({c for c in (classes or "").split(",") if c and c != _db._CLASS_OTHER})
        effect = (klass[0].upper() if klass else "OTHER")
        # The description is built from the SHAPE only: a tool name, argument names, and a
        # bucket floor. No argument VALUE exists in the ledger to leak into it even by
        # accident, which is what makes this safe to show and safe to store as a policy.
        # 🔴 SAY ONLY WHAT THE ROW SUPPORTS. This read "Infrequent calls to 'X'" for anything
        # without a magnitude, so a tool called 120 times was described to the developer as
        # infrequent -- caught by rendering the real screen, not by any test. Rarity is a
        # RANKING signal, computed against the rest of the ledger; it is not a fact about one
        # tool that this sentence is entitled to assert. A magnitude IS.
        desc = "%s to '%s'" % (
            "Large calls" if quantity and quantity >= 1000 else "Calls", tool_name)
        if names:
            desc += " with arguments named %s" % ", ".join(names)
        # 🔴 EVERY LINE ENDS WITH A REASON IT IS ON THE SCREEN. A magnitude IS one, and the
        # lines that had it were never the problem. The lines WITHOUT one read as bare "you
        # called this function" -- on a first run with one benign call, the whole screen was a
        # suggestion with no stated basis, and a reader can neither act on that nor dismiss it.
        #
        # ⚠️ WHY NOT A MINIMUM OBSERVATION COUNT, which is the obvious alternative. The rare
        # call is usually the dangerous one -- a credential rotation, a single huge export --
        # and this harvester ranks rarity UP for exactly that reason. A frequency floor would
        # suppress the candidates the ordering exists to surface and keep the routine repeats.
        # It would also SUPPRESS SILENTLY: a dropped candidate is indistinguishable from having
        # nothing to propose, which is the omission-carrying-a-decision failure this codebase
        # keeps paying for. Nothing here arms without an explicit adopt, so a thin suggestion
        # costs a glance; a hidden one costs the feature on the only run most people give us.
        # So: show it, and say how thin it is.
        # 🔴 EVIDENCE IS NOT RULE TEXT, AND THE FIRST CUT PUT IT IN THE RULE. `adopt_rule`
        # writes `semantic_description` into the policy store verbatim -- it IS the rule the
        # gateway matches on. So appending "seen 6 times, out of 39 calls" made an observation
        # taken on one afternoon part of a policy that outlives it, and part of the text the
        # gateway semantically matches against. A year later it is simply false, and nothing
        # would ever have corrected it.
        #
        # The magnitude clause stays IN the description on purpose: "largest recorded size >=
        # 1000" is a threshold, which is a property of the rule. How often we happened to see
        # the tool is a property of the ledger.
        evidence = ""
        if quantity:
            desc += " (largest recorded size >= %d)" % int(quantity)
        else:
            evidence = _seen_clause(count, total_calls, distinct_tools)
        candidates.append({
            "target_action": tool_name,
            "effect_category": effect,
            "semantic_description": desc,
            # Why we are proposing it, carried beside the rule rather than inside it. Every
            # screen composes the two back into one line via `cli._rule_line`, so the reader
            # sees no difference; what changes is that the STORED policy no longer carries an
            # observation from the afternoon it was proposed.
            "evidence": evidence,
            "indicators": [],
            "policy_violated": None,
            "count": int(count or 0),
        })
        if len(candidates) >= int(limit):
            break
    return candidates


def _existing_rule_actions(path=None):
    """`target_action` values the developer ADOPTED, so we never propose a rule for something
    they have already ruled on. Never raises; an unreadable or absent store suppresses nothing.

    🔴 `WHERE id LIKE 'rule-%'`, AND THE FILTER IS THE WHOLE CORRECTNESS OF IT. The policy
    store also holds the SHIPPED BASELINE rows, so a plain `SELECT target_action FROM policies`
    returns every built-in rule on any install that has booted the gateway or run `agentx
    pull`. Two things then go wrong at once: this suppresses proposals for tools the developer
    never ruled on, and the status screen counting these tells them they adopted rules they
    never adopted. `adopt_rule` mints `rule-<uuid>` ids precisely so an adopted row is
    distinguishable from a shipped one; nothing else in the table carries that prefix.
    """
    try:
        p = _policy_db_path(path)
        if not os.path.exists(p):
            return set()
        conn = sqlite3.connect(p)
        try:
            return {row[0] for row in conn.execute(
                "SELECT target_action FROM policies WHERE id LIKE 'rule-%'") if row and row[0]}
        finally:
            conn.close()
    except sqlite3.Error:
        return set()


def adopted_rules(path=None):
    """The detection rules the developer ADOPTED, for the undo pass. Never raises.

    Same `rule-%` filter as `_existing_rule_actions`, and for the same reason: the policy store
    also holds the SHIPPED BASELINE, and nothing but an adopted row carries that prefix. Here
    the filter is not just correctness, it is the safety boundary -- this list is what a delete
    is offered against.
    """
    try:
        p = _policy_db_path(path)
        if not os.path.exists(p):
            return []
        conn = sqlite3.connect(p)
        try:
            rows = conn.execute(
                "SELECT id, target_action, semantic_description FROM policies "
                "WHERE id LIKE 'rule-%' ORDER BY target_action, id").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return [{"id": r[0], "target_action": r[1], "semantic_description": r[2]} for r in rows]


def remove_rule(rule_id, path=None):
    """Un-adopt ONE rule by id. Returns True if a row was actually deleted.

    🔴 THE PREFIX IS CHECKED TWICE, IN PYTHON AND IN THE SQL, AND THAT IS NOT BELT-AND-BRACES
    FOR ITS OWN SAKE. This is the only DELETE against the policy store that a keystroke can
    reach. The shipped baseline lives in the same table, so an id that slipped through would
    remove a policy we ship and the developer would have no idea which. A caller passing
    anything without the adopted-row prefix is a bug, so it raises rather than silently
    matching nothing.
    """
    if not rule_id or not str(rule_id).startswith("rule-"):
        raise ValueError("remove_rule only removes ADOPTED rules (id must start with 'rule-')")
    try:
        p = _policy_db_path(path)
        if not os.path.exists(p):
            return False
        conn = sqlite3.connect(p)
        try:
            cur = conn.execute(
                "DELETE FROM policies WHERE id IS ? AND id LIKE 'rule-%'", (rule_id,))
            conn.commit()
            return (cur.rowcount or 0) > 0
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def adopted_rule_count(path=None):
    """How many rules the developer adopted. A COUNT of rows, not of distinct actions.

    Separate from `_existing_rule_actions` on purpose: that one answers "which tools have
    already been ruled on", where collapsing duplicates is correct. A screen saying "2 rules
    you adopted" is counting ROWS, and two adopted rules on one action would render as "1"
    if it reused the set.
    """
    try:
        p = _policy_db_path(path)
        if not os.path.exists(p):
            return 0
        conn = sqlite3.connect(p)
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM policies WHERE id LIKE 'rule-%'").fetchone()[0] or 0
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


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
