"""
agentx_sdk/rules.py — the DETECTION half of the unified learning loop.

Sibling of ``overrides.py`` (the RECOVERY half). The gateway extracts a structural
``rule_suggestion`` on every judge-caught incident — the detection analog of
``resolution_path``. This module closes the
loop on the CLI:

  * HARVEST — ``harvest_rule_candidates()`` projects the *reusable*
              ``rule_suggestion`` rows from the local incident store into ranked
              structural-rule candidates.
  * ADOPT   — ``adopt_rule()`` writes the chosen candidate into the project's
              committable rules file (``.agentx/rules.json``, see the block above
              ``_rules_file_path``). The keyless SDK matches it on its symbolic half
              from the next call; a gateway that reads the file arms both halves
              (symbolic ``target_action`` + neural ``semantic_description``) on its
              next policy refresh, and at boot. The manual adopt step is the
              anti-poisoning gate: an
              agent-derived rule never arms itself.

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
import sys
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
            # The shape the sentence above was built from, kept as data so `rule_name` can
            # name the rule from the same facts instead of re-parsing the sentence.
            "arg_names": names,
            "count": int(count or 0),
        })
        if len(candidates) >= int(limit):
            break
    return candidates


# =====================================================================
# THE RULES FILE: `.agentx/rules.json`
# =====================================================================
# Adopted rules used to live as rows in `policies.db`, beside the shipped baseline, for one
# reason: the gateway already loaded that store at boot, so a rule written there armed with no
# gateway change. That convenience had a cost nobody chose on its merits. A rule is
# configuration the developer authored, and everything else they author is committable text
# (`overrides.json`, the verdicts file); rules were the one thing in a binary, so they could not
# be shared through the repo, reviewed in a pull request, or reach a CI machine at all. The
# founder's question on the walk was why user rules live in a database. They do not any more.
#
# The file is the SOURCE OF TRUTH, not an export. There is no second copy to drift.
#
# Shape (one object per rule, sorted by id, two-space indent, trailing newline, so an adopt
# that changes nothing is a no-op diff):
#
#   {"version": 1, "rules": [{"id": "rule-…", "name": …, "target_action": …, "indicators": [],
#                             "semantic_description": …, "coaching": …, "active": true,
#                             "adopted_at": "…"}]}
#
# `active` is a POSITIVE field. A rule the developer switched off is present with `active:
# false`; a rule absent from the file does not exist. Absence never carries a decision -- a
# switched-off rule and a truncated file must not be the same bytes.
#
# Ids keep the `rule-` prefix. The ledger row for a matched call carries the rule's id, and
# every reader of that row (`db.is_rule_match`, the audit screens, the dashboard) keys on the
# prefix, so a rule carried over from the database keeps its id and its history.
#
# NOT `.agentx/import.json`: that file is consumed once by `agentx import` (coaching and
# verdicts); this one is read on every call and at every gateway boot. Three concerns, three
# files, the way verdicts left `overrides.json` so sharing coaching does not share judgments.
#
# A file an agent can write is a file an agent can poison. The `adopt` prompt keeps its human
# `y`, and the repository's own review is the gate on the file -- which is also the point: a
# rule change shows up in a pull request like any other configuration change.
DEFAULT_RULES_FILE = os.path.join(".agentx", "rules.json")
_RULES_FILE_VERSION = 1


def _rules_file_path(path=None):
    """Where the adopted rules live. Explicit arg, else ``AGENTX_RULES_FILE``, else the sibling of
    an explicit ``AGENTX_POLICY_DB``, else ``<project>/.agentx/rules.json``.

    The sibling rule is what keeps every existing test's isolation intact: the suites pin
    ``AGENTX_POLICY_DB`` to a temp directory, and the rules file lands beside it rather than in
    the developer's real project. It is also the right answer for a human who moved the policy
    store deliberately: their rules go where their store went.
    """
    if path:
        # A caller handing this the DATABASE path is a bug from before the move, and writing
        # JSON into a file named policies.db is the quiet kind. Found by a test fixture that
        # did exactly that; refused here so the next one is loud.
        if str(path).lower().endswith(".db"):
            raise ValueError("%s is the policy store; the rules file is rules.json beside it"
                             % path)
        return path
    env = os.environ.get("AGENTX_RULES_FILE")
    if env:
        return env
    db_env = os.environ.get("AGENTX_POLICY_DB")
    if db_env:
        return os.path.join(os.path.dirname(os.path.abspath(db_env)), "rules.json")
    return os.path.join(_anchored_root(), DEFAULT_RULES_FILE)


def _read_rules_file(p):
    """The rules in the file, as stored. Raises on a file that exists and cannot be read as this
    file's shape; returns [] for a file that does not exist. The distinction is deliberate: an
    absent file means none adopted, a damaged file must never read as none adopted."""
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, dict) and not isinstance(doc.get("rules"), list) \
            and ({"reframes", "verdicts"} & set(doc)):
        # The org-brain seed under its old name. Every reader that lists rules would warn on
        # every command without saying what to do; this says it once, where the reader looks.
        raise ValueError("%s is an org import file from an earlier version (coaching/verdicts); "
                         "move it to .agentx/import.json, which `agentx import` reads, and this "
                         "name is free for your adopted rules" % p)
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise ValueError("%s is not a rules file (expected {\"version\", \"rules\": [...]})" % p)
    out = []
    for r in doc["rules"]:
        if not isinstance(r, dict) or not str(r.get("id") or "").startswith("rule-"):
            raise ValueError("%s holds a rule without a 'rule-' id" % p)
        out.append(r)
    return out


def _write_rules_file(p, rules):
    """Write the whole file, deterministically, via a temp file and rename so a crash mid-write
    leaves the old file rather than half of the new one."""
    parent = os.path.dirname(p)
    if parent:
        os.makedirs(parent, exist_ok=True)
    doc = {"version": _RULES_FILE_VERSION,
           "rules": sorted(rules, key=lambda r: str(r.get("id")))}
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, p)


def _policy_db_rule_rows(db_path=None):
    """The adopted rules still sitting as `rule-` rows in `policies.db`, in the FILE's shape,
    READ ONLY. `[]` when there is no store or no such rows; `None` when the store exists and
    could not be read, so a caller counting them never turns "could not look" into 0.

    Three readers, one query: the one-time move below, the pulse counter (which must count
    without writing), and the hot-path matcher on an install that has not moved yet (which
    must match without writing). The first cut had only the move, and both other readers
    reached for it -- so the anonymous pulse migrated the developer's configuration at
    process exit, and an upgraded agent whose rules were still in the store matched nothing
    until some command happened to run. Found by the scoped review of this branch.
    """
    # 🔴 "NO SUCH TABLE" AND "NO SUCH COLUMN" ARE 0, NOT None. A store with no `policies`
    # table (a 0-byte file, a bare connect) or with a table narrower than the one `adopt` wrote
    # into cannot hold an adopted rule, so there is nothing to move and nothing to count.
    # Reading those as "could not read" made the writer refuse forever ("run the command
    # again", against a store no command would ever change), which the founder's suite run
    # hit on a test fixture with a four-column table. Locked, or not a database at all, is
    # still None: those stores may well hold rules we cannot see right now.
    needed = ("id", "created_at", "name", "semantic_description", "target_action",
              "blocked_intents", "socratic_prompt", "is_active")
    try:
        dbp = _policy_db_path(db_path)
        if not os.path.exists(dbp):
            return []
        conn = sqlite3.connect(dbp)
        try:
            have = {r[1] for r in conn.execute("PRAGMA table_info(policies)").fetchall()}
            if not have or not set(needed) <= have:
                return []
            rows = conn.execute(
                "SELECT %s FROM policies WHERE id LIKE 'rule-%%' ORDER BY id"
                % ", ".join(needed)).fetchall()
        finally:
            conn.close()
    except Exception:
        return None
    out = []
    for rid, created, name, desc, action, intents, socratic, active in rows:
        try:
            indicators = [str(i) for i in (json.loads(intents) if intents else []) if i]
        except (TypeError, ValueError):
            indicators = []
        out.append({
            "id": rid, "name": name or rid, "target_action": action,
            "indicators": indicators, "semantic_description": desc or "",
            "coaching": socratic or "",
            "active": bool(active) if active is not None else True,
            "adopted_at": created or _now_iso(),
        })
    return out


def _carry_rules_from_policy_db(p, db_path=None):
    """ONE-TIME MOVE of adopted rows out of `policies.db` into the file. Returns how many moved,
    or None when there were rows to move and the move FAILED: a writer must tell those apart,
    because "nothing to move" licenses writing a fresh file and "the move failed" does not.

    Runs only when the file does not exist yet, so an install that has already moved is never
    touched again. A MOVE, not a copy: two stores holding one rule is the exact class of defect
    where a deliberate act and a stale copy become the same bytes. The rows are deleted from the
    database only after the file is on disk. Prints what it did, because a silent migration of
    the developer's own configuration is the kind of thing that costs an afternoon.

    🔴 A MOVE THAT HALF-HAPPENS IS UNDONE, NOT LEFT. If the delete fails after the file is
    written (a local gateway holding the store open, say), the file just written is removed
    again and the failure is said out loud: both stores are then exactly as they were, and the
    next command retries. The first cut swallowed that failure with the file in place, so the
    rows stayed in the store forever (the carry never runs once the file exists) and a
    local-mode gateway kept arming them from the store after `agentx review --undo` had
    removed them from the file. Found by the scoped review of this branch.

    Never raises. A store that exists and cannot be READ is a failed move too (None), not
    "nothing to move": the writer above would otherwise create the file over rows it never
    saw, and the rows would be stranded behind it (third instance of the class, found by the
    review of the second). No store at all, or no `rule-` rows, is 0.
    """
    try:
        dbp = _policy_db_path(db_path)
        carried = _policy_db_rule_rows(db_path)
        if carried is None:
            print("⚠️ could not read %s to move your adopted rules out of it; nothing changed, "
                  "the next command retries. If a local gateway is running, stop it first."
                  % dbp, file=sys.stderr)
            return None
        if not carried:
            return 0
        _write_rules_file(p, carried)
        try:
            conn = sqlite3.connect(dbp)
            try:
                conn.execute("DELETE FROM policies WHERE id LIKE 'rule-%'")
                conn.commit()
            finally:
                conn.close()
        except Exception as err:
            try:
                os.remove(p)
            except OSError:
                pass
            print("⚠️ could not move %d adopted rule%s out of %s (%s). Nothing changed; the "
                  "next command retries. If a local gateway is running, stop it first."
                  % (len(carried), "" if len(carried) == 1 else "s", dbp, err), file=sys.stderr)
            return None
        print("📦 moved %d adopted rule%s from %s to %s; commit that file to share them"
              % (len(carried), "" if len(carried) == 1 else "s", dbp, p))
        return len(carried)
    except Exception:
        return None


def _store_beside(rules_path, explicit):
    """The policy store a rules file stands in for: beside an EXPLICIT rules path, else the
    resolved default. One answer for the move, the writer and the hot-path fallback, so a
    caller naming a scratch file never reads (or, worse, moves rows out of) the machine's
    default store. Two of the three had it wrong in turn; the third copy is the rule."""
    if explicit:
        return os.path.join(os.path.dirname(os.path.abspath(rules_path)), "policies.db")
    return None      # `_policy_db_path(None)`: env or the project default


def _load_rules(path=None):
    """Every rule in the file, active or not, after the one-time carry. Never raises: a damaged
    file is reported once on stderr and read as [] for THIS call, so a screen still renders --
    but the count functions below say None for it rather than 0, because a zero from a file we
    could not read is a claim we cannot make."""
    p = _rules_file_path(path)
    if not os.path.exists(p):
        _carry_rules_from_policy_db(p, db_path=_store_beside(p, path))
    try:
        return _read_rules_file(p)
    except Exception as err:
        print("⚠️ could not read %s (%s); treating it as empty for this command" % (p, err),
              file=sys.stderr)
        return []


def _load_rules_for_writing(path=None):
    """`_load_rules` for a WRITER. A reader can treat a file it cannot parse as empty for one
    screen; a writer that did the same would then replace that file with its own, and the
    developer's file is gone. So this raises instead, naming the file.

    🔴 THE FILE NAME IS SHARED WITH AN EARLIER FEATURE. `.agentx/rules.json` was the org-brain
    seed file (reframes and verdicts) before it was renamed to `import.json`, and
    `overrides._org_rules_path` still reads a legacy one. A project that kept that file would
    have had it read as "damaged" here and overwritten by the first `adopt`. The reverse
    direction is guarded in `_org_rules_path`: it does not take a detection-rules document as
    a legacy import file.
    """
    p = _rules_file_path(path)
    if not os.path.exists(p):
        # 🔴 A FAILED MOVE IS NOT AN EMPTY FILE. The carry says None when rows were there and
        # could not be moved; reading the (absent) file as [] here would write a fresh file
        # holding only the new rule, and the old rows would be stranded in the store behind
        # it, forever, which is the half-done state the carry just refused to leave. Round two
        # of the scoped review found this inside round one's fix.
        if _carry_rules_from_policy_db(p, db_path=_store_beside(p, path)) is None:
            raise ValueError("not writing %s: your earlier rules are still in the policy store "
                             "and could not be moved into the file just now (see the line "
                             "above). Nothing changed; run the command again." % p)
    try:
        return _read_rules_file(p)
    except Exception as err:
        raise ValueError("not writing %s: it exists and is not an adopted-rules file. %s"
                         % (p, err))


def _existing_rule_actions(path=None):
    """`target_action` values the developer ADOPTED, so we never propose a rule for something
    they have already ruled on. Never raises; an unreadable or absent file suppresses nothing.
    Switched-off rules count: the developer ruled on that tool, whichever way the switch sits."""
    try:
        return {r.get("target_action") for r in _load_rules(path) if r.get("target_action")}
    except Exception:
        return set()


def adopted_rules(path=None):
    """The detection rules the developer ADOPTED, for the undo pass. Never raises.

    Only `rule-` ids ever enter the file (`_read_rules_file` refuses anything else), so this list
    is the safety boundary a delete is offered against, as it was when the rows sat beside the
    shipped baseline in the database."""
    try:
        return [{"id": r["id"], "name": r.get("name") or r["id"],
                 "target_action": r.get("target_action"),
                 "semantic_description": r.get("semantic_description"),
                 "active": bool(r.get("active", True))}
                for r in sorted(_load_rules(path),
                                key=lambda r: (str(r.get("target_action")), str(r["id"])))]
    except Exception:
        return []


def remove_rule(rule_id, path=None):
    """Un-adopt ONE rule by id. Returns True if a rule was actually removed.

    The prefix is still checked, and it still raises on a bad caller rather than silently
    matching nothing: this is the only keystroke-reachable delete of the developer's own
    configuration, and a caller handing it something that is not an adopted-rule id is a bug."""
    if not rule_id or not str(rule_id).startswith("rule-"):
        raise ValueError("remove_rule only removes ADOPTED rules (id must start with 'rule-')")
    try:
        p = _rules_file_path(path)
        rules = _load_rules(path)
        kept = [r for r in rules if r.get("id") != rule_id]
        if len(kept) == len(rules):
            return False
        _write_rules_file(p, kept)
        return True
    except Exception:
        return False


_MATCH_CACHE = {}   # path -> ((mtime_ns, size), rules)


def _armed_adopted_rules(path=None):
    """The ACTIVE adopted rules, loaded once per change to the file. Never raises.

    Called on the hot path (every recorded call), so it cannot parse JSON each time. The cache
    key is the file's (mtime, size): an adopt, an undo or a hand edit changes at least one of
    them, and an unchanged file is not reopened. `_rules_file_path()` still walks up from cwd to
    find the project root on every call -- known, not measured, left open.

    🔴 AN ABSENT FILE READS THE STORE, READ ONLY, AND NEVER MIGRATES. An install upgrading to
    the file still has its rules as rows in `policies.db` until some command lists them; the
    first cut matched nothing in that window, so the calls that were matched and recorded the
    day before the upgrade silently stopped being, with nothing saying why. The rows are read
    here the way the file is (cached on the store's own mtime and size), and the move itself
    still waits for a command: the hot path must not write the developer's configuration.

    `active` is honoured here for the same reason the gateway honours it at boot: a rule
    somebody switched off must not go on matching quietly in the SDK.
    """
    try:
        p = _rules_file_path(path)
        source, reader = p, _read_rules_file
        try:
            st = os.stat(p)
        except OSError:
            _MATCH_CACHE.pop(p, None)
            # The store BESIDE the rules file it stands in for, so an explicit `path` never
            # reads the machine's default store by accident (round two of the scoped review).
            source = _policy_db_path(_store_beside(p, path))
            reader = (lambda dbp: _policy_db_rule_rows(dbp) or [])
            try:
                st = os.stat(source)
            except OSError:
                _MATCH_CACHE.pop(source, None)
                return []
        key = (st.st_mtime_ns, st.st_size)
        cached = _MATCH_CACHE.get(source)
        if cached and cached[0] == key:
            return cached[1]
        rules = []
        for r in reader(source):
            if not r.get("active", True):
                continue
            rules.append({"id": r["id"], "name": r.get("name") or r["id"],
                          "target_action": r.get("target_action"),
                          "indicators": [str(i) for i in (r.get("indicators") or []) if i]})
        rules.sort(key=lambda r: (str(r["target_action"]), r["id"]))
        _MATCH_CACHE[source] = (key, rules)
        return rules
    except Exception:
        return []


def _call_text(arguments):
    """One lowercase string of the call's argument VALUES, for indicator matching.

    Built in memory and dropped; nothing derived from it is written anywhere. The ledger row
    that records the match carries only the rule's own id and name, which are our strings.
    """
    if not arguments:
        return ""
    # Leaf VALUES, joined raw. Not json.dumps: that escapes backslashes, quotes and every
    # non-ASCII character, so an indicator like a Windows path or a name with an accent could
    # never match -- a silent false negative on the one half this matcher claims to do
    # exactly. Keys are left out on purpose: an indicator equal to an argument NAME would
    # otherwise match every call to the tool.
    out = []
    stack = [arguments]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple, set, frozenset)):
            stack.extend(v)
        elif v is not None:
            try:
                out.append(str(v))
            except Exception:
                continue
    return "\n".join(out).lower()


def match_adopted_rule(tool_name, arguments=None, path=None):
    """The adopted rule this call hits on its SYMBOLIC half, or None.

    This is the keyless SDK's whole knowledge of a user rule, and it is deliberately narrow:

      * `target_action` must equal the tool name. That is the rule as the keyless proposer
        writes it ("Calls to 'refund_payment'"), so on those rules a tool-name match IS the
        rule, not an approximation of it.
      * every `indicator` the rule carries must appear in the call's argument text. Indicators
        are the exact-match IOC half a judge-derived rule ships with; a rule with none matches
        on the tool name alone.

    What it does NOT do: read `semantic_description`. The meaning half of a rule is an
    embedding compared by meaning, the SDK has no model and, keyless, no network to reach one,
    so that half stays on the gateway. A match here says "this call is the shape your rule
    names", never "this call is what your rule means" -- which is why the caller RECORDS it
    and never blocks on it.

    Never raises: a match is an annotation on a call that already ran.
    """
    if not tool_name:
        return None
    try:
        candidates = [r for r in _armed_adopted_rules(path) if r["target_action"] == tool_name]
        if not candidates:
            return None
        text = None
        for rule in candidates:
            if rule["indicators"]:
                if text is None:
                    text = _call_text(arguments)
                if not all(ind.lower() in text for ind in rule["indicators"]):
                    continue
            return rule
        return None
    except Exception:
        return None


def adopted_rule_count(path=None):
    """How many rules the developer adopted, active or not. A COUNT of entries, not of distinct
    actions: two adopted rules on one action are two rules on every screen that says "2 rules
    you adopted"."""
    try:
        return len(_load_rules(path))
    except Exception:
        return 0


def adopted_rule_count_or_none(path=None):
    """The count for the WIRE: None when the file exists and cannot be read, so a zero on the
    pulse always means "none adopted" and never "we could not look". `adopted_rule_count` above
    swallows that case as 0, which is right for a screen and wrong for a counter.

    🔴 READS, NEVER WRITES. The pulse calls this at process exit inside the developer's agent
    and inside the MCP proxy; the first cut ran the one-time move from here, so telemetry
    migrated the developer's configuration (and, per-user on the MCP door, whichever repo the
    host launched from). An install that has not moved yet is counted from its store, read
    only; the move waits for a command that lists rules.
    """
    try:
        p = _rules_file_path(path)
        if not os.path.exists(p):
            rows = _policy_db_rule_rows(_store_beside(p, path))
            return None if rows is None else len(rows)
        return len(_read_rules_file(p))
    except Exception:
        return None


def rule_name(candidate, override=None):
    """The name a rule is listed under, decided in ONE place.

    In order: the name the developer typed (``adopt N --name``, ``adopt --rule --name``); the
    policy name a judge-derived candidate already carries (``policy_violated``); otherwise the
    tool and the argument names the proposal was built from -- ``refund_payment with amount``,
    or just ``refund_payment`` when the call carries no named arguments.

    🔴 NOTHING INVENTED. This used to fall through to ``"<effect> via <tool>"``, which for every
    keyless-proposed rule is ``OTHER via <tool>``: a category the developer never chose, printed
    as if they had named it. It went unseen for as long as the screens led with the tool name;
    the YOUR RULES table leads with the name, so the founder read it and asked where it came
    from. Every word here now comes from the developer or from their own call.
    """
    typed = str(override or "").strip()
    if typed:
        return typed
    given = str(candidate.get("policy_violated") or "").strip()
    if given:
        return given
    action = str(candidate.get("target_action") or "action").strip()
    names = [str(n).strip() for n in (candidate.get("arg_names") or []) if str(n).strip()]
    if names:
        return "%s with %s" % (action, ", ".join(names))
    return action


def adopt_rule(candidate, *, challenge=None, name=None, path=None):
    """Write a structural-rule candidate into `.agentx/rules.json` as an ACTIVE rule — the human
    gate. Returns the stored ``{id, name, ...}`` dict.

    ``name`` is the developer's own name for the rule; see ``rule_name`` for what is used when
    there is none.

    The keyless SDK matches it on its shape from the next call; a gateway that reads the file
    arms both halves on its next policy refresh (symbolic ``target_action`` + neural
    ``semantic_description``; ``indicators`` are the exact-match IOC subtype).
    """
    if not candidate or not str(candidate.get("semantic_description") or "").strip():
        raise ValueError("a rule candidate with a semantic_description is required")

    p = _rules_file_path(path)
    rules = _load_rules_for_writing(path)   # raises rather than replace a file it cannot read

    rule_id = "rule-" + uuid.uuid4().hex[:12]
    effect = candidate.get("effect_category") or "OTHER"
    action = candidate.get("target_action") or "action"
    name = rule_name(candidate, override=name)
    desc = str(candidate["semantic_description"]).strip()
    indicators = [i for i in (candidate.get("indicators") or []) if i]
    # What the agent is told on a match. It used to say "a dangerous pattern your own
    # incidents taught AgentX", which was false for the common case: a rule adopted from the
    # audit screen comes from ALLOWED calls, no incident ever happened, and "dangerous" was our
    # word for a rule the developer named "Refunds need a ticket". A founder read it in his
    # rules.json. The person who adopted the rule is the authority; the text says so.
    socratic = challenge or (
        f"Policy Violation: {name}. This call matches a rule you adopted ({desc}). "
        f"Reach the goal a safe way instead, or request human approval."
    )
    stored = {"id": rule_id, "name": name, "target_action": action, "indicators": indicators,
              "semantic_description": desc, "coaching": socratic, "active": True,
              "adopted_at": _now_iso()}
    _write_rules_file(p, rules + [stored])

    return {"id": rule_id, "name": name, "target_action": action,
            "effect_category": effect, "semantic_description": desc,
            "indicators": indicators, "socratic_prompt": socratic, "path": p}
