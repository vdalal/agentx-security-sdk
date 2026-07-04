"""Unified learning loop — DETECTION rule harvest + adopt (agentx_sdk/rules.py).

Sibling of test_build2_overrides.py (the RECOVERY half). Self-contained temp
SQLite (no backend dependency), so these run with the rest of the SDK suite.

  * HARVEST — reusable `rule_suggestion` rows in the local incident store ->
    ranked, deduplicated structural-rule candidates.
  * ADOPT   — a candidate is written into the local policy store as an ACTIVE
    policy in the exact column shape the gateway reads.
"""
import json
import sqlite3

import pytest

from agentx_sdk import rules


def _make_incident_db(path, rows):
    """Minimal incidents table with the column harvest_rule_candidates reads.
    rows = list of (receipt_id, policy_violated, rule_suggestion_dict_or_None)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE incidents (receipt_id TEXT PRIMARY KEY, "
            "policy_violated TEXT, rule_suggestion TEXT)"
        )
        for rid, pv, rs in rows:
            conn.execute(
                "INSERT INTO incidents (receipt_id, policy_violated, rule_suggestion) "
                "VALUES (?, ?, ?)",
                (rid, pv, json.dumps(rs) if rs is not None else None),
            )
        conn.commit()
    finally:
        conn.close()


def _rule(action, effect, desc, indicators=None, reusable=True):
    return {"target_action": action, "effect_category": effect,
            "semantic_description": desc, "indicators": indicators or [],
            "reusable": reusable}


@pytest.fixture
def incident_db(tmp_path, monkeypatch):
    p = tmp_path / "incidents.db"
    monkeypatch.setenv("AGENTX_INCIDENT_DB", str(p))
    return str(p)


@pytest.fixture
def policy_db(tmp_path, monkeypatch):
    p = tmp_path / "policies.db"
    monkeypatch.setenv("AGENTX_POLICY_DB", str(p))
    return str(p)


# --------------------------------------------------------------- harvest

def test_harvest_empty_when_no_db(incident_db):
    # env points at a path that does not exist yet
    assert rules.harvest_rule_candidates() == []


def test_harvest_filters_non_reusable(incident_db):
    _make_incident_db(incident_db, [
        ("r1", "SSRF Guard", _rule("fetch_url", "SSRF", "metadata fetch", reusable=True)),
        ("r2", "SSRF Guard", _rule("fetch_url", "SSRF", "one-off thing", reusable=False)),
    ])
    descs = [c["semantic_description"] for c in rules.harvest_rule_candidates()]
    assert "metadata fetch" in descs
    assert "one-off thing" not in descs


def test_harvest_dedups_and_ranks_by_count(incident_db):
    _make_incident_db(incident_db, [
        ("r1", "P", _rule("fetch_url", "SSRF", "metadata fetch")),
        ("r2", "P", _rule("fetch_url", "SSRF", "metadata fetch")),
        ("r3", "P", _rule("execute_database_query", "DESTRUCTION", "drops a table")),
    ])
    out = rules.harvest_rule_candidates()
    assert len(out) == 2
    assert out[0]["semantic_description"] == "metadata fetch"  # most-recurred first
    assert out[0]["count"] == 2
    assert out[1]["count"] == 1


def test_harvest_unions_indicators(incident_db):
    _make_incident_db(incident_db, [
        ("r1", "P", _rule("fetch_url", "SSRF", "metadata fetch", ["169.254.169.254"])),
        ("r2", "P", _rule("fetch_url", "SSRF", "metadata fetch", ["metadata.google.internal"])),
    ])
    out = rules.harvest_rule_candidates()
    assert len(out) == 1
    assert set(out[0]["indicators"]) == {"169.254.169.254", "metadata.google.internal"}


def test_harvest_skips_blank_description(incident_db):
    _make_incident_db(incident_db, [("r1", "P", _rule("fetch_url", "SSRF", ""))])
    assert rules.harvest_rule_candidates() == []


def test_harvest_clusters_near_duplicate_descriptions(incident_db):
    _make_incident_db(incident_db, [
        ("r1", "SSRF Guard", _rule("fetch_url", "SSRF", "fetching the cloud metadata endpoint", ["169.254.169.254"])),
        ("r2", "SSRF Guard", _rule("fetch_url", "SSRF", "fetching the cloud-metadata endpoint", ["metadata.google.internal"])),
        ("r3", "DDL Guard", _rule("execute_database_query", "DESTRUCTION", "drops a whole table")),
    ])
    out = rules.harvest_rule_candidates()
    ssrf = [c for c in out if c["effect_category"] == "SSRF"]
    assert len(ssrf) == 1                       # reworded SSRF descriptions merged
    assert ssrf[0]["count"] == 2
    assert set(ssrf[0]["indicators"]) == {"169.254.169.254", "metadata.google.internal"}  # unioned
    assert any(c["effect_category"] == "DESTRUCTION" for c in out)  # distinct rule untouched


# --------------------------------------------------------------- adopt

def test_adopt_rule_writes_active_policy(policy_db):
    cand = _rule("execute_database_query", "DESTRUCTION", "drops a whole table", ["DROP TABLE"])
    cand["policy_violated"] = "Mass Destructive Intent"
    entry = rules.adopt_rule(cand)
    assert entry["id"].startswith("rule-")

    # read it back via the policy-store column shape the gateway reads
    conn = sqlite3.connect(policy_db)
    try:
        row = conn.execute(
            "SELECT name, semantic_description, target_action, blocked_intents, "
            "socratic_prompt, is_active FROM policies WHERE id = ?", (entry["id"],)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    name, desc, action, intents, socratic, is_active = row
    assert name == "Mass Destructive Intent"
    assert action == "execute_database_query"
    assert desc == "drops a whole table"
    assert json.loads(intents) == ["DROP TABLE"]
    assert is_active == 1
    assert socratic  # a non-empty challenge was synthesized


def test_adopt_rule_requires_description(policy_db):
    with pytest.raises(ValueError):
        rules.adopt_rule({"target_action": "x", "effect_category": "OTHER",
                          "semantic_description": "   "})


def test_adopt_rule_honors_custom_challenge(policy_db):
    entry = rules.adopt_rule(_rule("fetch_url", "SSRF", "metadata fetch"),
                             challenge="Do not fetch metadata; use the config service.")
    assert entry["socratic_prompt"] == "Do not fetch metadata; use the config service."


def test_adopt_rule_name_falls_back_without_policy_violated(policy_db):
    entry = rules.adopt_rule(_rule("fetch_url", "SSRF", "metadata fetch"))
    assert entry["name"] == "SSRF via fetch_url"


# --------------------------------------------------------------- CLI routing

def test_cli_adopt_routes_rule_number_to_policy_store(incident_db, policy_db, tmp_path, monkeypatch):
    """The unified global #N spans reframes then rules; `agentx adopt <#>` must
    route a rule number to the policy store (not the override store). With no
    reframe candidates, the single rule is #1."""
    overrides_path = tmp_path / "overrides.json"
    monkeypatch.setenv("AGENTX_OVERRIDES", str(overrides_path))
    _make_incident_db(incident_db, [
        ("r1", "SSRF Guard", _rule("fetch_url", "SSRF", "metadata fetch", ["169.254.169.254"])),
    ])
    from agentx_sdk import cli
    cli.execute_adopt(["1"])  # #1 is the rule -> adopt_rule path (non-tty auto-confirms)

    conn = sqlite3.connect(policy_db)
    try:
        rows = conn.execute("SELECT target_action, semantic_description FROM policies").fetchall()
    finally:
        conn.close()
    assert any(r[0] == "fetch_url" and r[1] == "metadata fetch" for r in rows)
    # ...and NOT into the override store (a rule must not be misrouted as a reframe).
    assert not overrides_path.exists() or json.loads(overrides_path.read_text()).get("overrides") == {}


# --------------------------------------------------------------- author from scratch (P2.1)

def _policy_rows(policy_db):
    import os
    if not os.path.exists(policy_db):
        return []
    conn = sqlite3.connect(policy_db)
    try:
        try:
            cur = conn.execute(
                "SELECT name, target_action, semantic_description, blocked_intents, "
                "socratic_prompt, is_active FROM policies"
            )
        except sqlite3.OperationalError:
            return []  # table never created (no rule was authored)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def test_cli_author_rule_writes_policy(policy_db):
    from agentx_sdk import cli
    cli.execute_adopt([
        "--rule", "--action", "fetch_url", "--effect", "SSRF",
        "--desc", "fetching a cloud metadata endpoint",
        "--indicators", "169.254.169.254, metadata.google.internal",
    ])
    rows = _policy_rows(policy_db)
    assert len(rows) == 1
    r = rows[0]
    assert r["target_action"] == "fetch_url"
    assert r["semantic_description"] == "fetching a cloud metadata endpoint"
    assert json.loads(r["blocked_intents"]) == ["169.254.169.254", "metadata.google.internal"]
    assert r["is_active"] == 1
    assert r["name"] == "SSRF via fetch_url"  # falls back when --name omitted


def test_cli_author_rule_honors_name_and_challenge(policy_db):
    from agentx_sdk import cli
    cli.execute_adopt([
        "--rule", "--action", "execute_database_query", "--desc", "mass row update",
        "--name", "Unscoped Mass Update", "--challenge", "Add a WHERE clause first.",
    ])
    r = _policy_rows(policy_db)[0]
    assert r["name"] == "Unscoped Mass Update"
    assert r["socratic_prompt"] == "Add a WHERE clause first."


def test_cli_author_rule_requires_action_and_desc(policy_db):
    from agentx_sdk import cli
    # missing --desc -> usage exit (sys.exit(1))
    with pytest.raises(SystemExit):
        cli.execute_adopt(["--rule", "--action", "fetch_url"])
    # missing --action -> usage exit
    with pytest.raises(SystemExit):
        cli.execute_adopt(["--rule", "--desc", "something"])
    # nothing written on either failed attempt
    assert _policy_rows(policy_db) == []
