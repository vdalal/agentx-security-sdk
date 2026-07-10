"""Build #2 — org-reframe harvest + override (challenge-quality compounding).

Three layers, all client-side (zero gateway change):
  * the override STORE  (.agentx/overrides.json) — load/save/adopt/get
  * the HARVEST projection — reusable `resolution_path` rows in the local
    incident store -> ranked per-policy safe-path candidates
  * the SDK-SWAP — at block time the adopted org reframe replaces the gateway's
    generic challenge, and an empty store leaves the block byte-identical.

The harvest test seeds a self-contained temp SQLite (no backend dependency), so
these run with the rest of the SDK suite.
"""
import json
import os
import sqlite3

import pytest

from agentx_sdk import overrides
from agentx_sdk.decorators import agentx_protect, _client, _session_stats, _strike_owner
from agentx_sdk import is_block, AgentXBlock


# --------------------------------------------------------------- fixtures

@pytest.fixture
def store_path(tmp_path, monkeypatch):
    """Point the override store at a temp file via the documented env knob."""
    p = tmp_path / "overrides.json"
    monkeypatch.setenv("AGENTX_OVERRIDES", str(p))
    return str(p)


def _make_incident_db(path, rows):
    """Create a minimal incidents table (the columns harvest reads) and insert
    rows. `rows` = list of (receipt_id, status, policy_id, policy_violated,
    resolution_path_dict_or_None)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE incidents (receipt_id TEXT PRIMARY KEY, status TEXT, "
            "policy_id TEXT, policy_violated TEXT, resolution_path TEXT)"
        )
        for rid, status, pid, pv, rp in rows:
            conn.execute(
                "INSERT INTO incidents VALUES (?,?,?,?,?)",
                (rid, status, pid, pv, json.dumps(rp) if rp is not None else None),
            )
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------- store I/O

def test_get_active_override_empty_store_is_none(store_path):
    assert overrides.get_active_override("POL-TEST-1") is None


def test_adopt_then_get_active_override(store_path):
    overrides.adopt(
        "POL-SECRET-1",
        challenge="Verify via the public cert endpoint; never read the signing key.",
        safe_path="GET /pki/verify",
        resolution_type="FOUND_SAFE_ALTERNATIVE",
        policy_violated="Secrets and PII Exfiltration",
    )
    got = overrides.get_active_override("POL-SECRET-1")
    assert got is not None
    assert got["challenge"].startswith("Verify via the public cert endpoint")
    assert got["safe_path"] == "GET /pki/verify"
    # persisted to the requested path, not the default
    assert os.path.exists(store_path)
    with open(store_path) as f:
        disk = json.load(f)
    assert disk["overrides"]["POL-SECRET-1"]["source"] == "harvest"


def test_name_fallback_when_id_misses(store_path):
    """Cross-path keying gap: a reframe adopted under one id is still found when
    the same logical policy is queried under a DIFFERENT id, matched by name."""
    overrides.adopt(
        "11111111-1111-1111-1111-111111111101",      # keyword-shield seed UUID
        challenge="ORG: only read operations are permitted.",
        safe_path="SELECT count(*) FROM users",
        policy_violated="Mass Destructive Intent",
    )
    # The gateway/judge path emits the SAME policy under a different id.
    got = overrides.get_active_override(
        "POL-GATEWAY-XYZ", policy_name="Mass Destructive Intent")
    assert got is not None
    assert got["challenge"] == "ORG: only read operations are permitted."
    assert got["safe_path"] == "SELECT count(*) FROM users"


def test_exact_id_takes_precedence_over_name(store_path):
    """When both an exact-id override and a name match exist, the exact id wins."""
    overrides.adopt("POL-A", challenge="by-id", policy_violated="Mass Destructive Intent")
    overrides.adopt("POL-B", challenge="by-name", policy_violated="Mass Destructive Intent")
    got = overrides.get_active_override("POL-A", policy_name="Mass Destructive Intent")
    assert got["challenge"] == "by-id"


def test_name_fallback_is_case_insensitive(store_path):
    overrides.adopt("POL-A", challenge="read-only", policy_violated="Mass Destructive Intent")
    got = overrides.get_active_override("MISS", policy_name="  mass   destructive intent ")
    assert got is not None and got["challenge"] == "read-only"


def test_name_fallback_no_match_returns_none(store_path):
    overrides.adopt("POL-A", challenge="x", policy_violated="Secrets and PII Exfiltration")
    assert overrides.get_active_override("MISS", policy_name="Mass Destructive Intent") is None


def test_name_fallback_picks_most_recently_adopted(store_path):
    """Two overrides share a policy name under different ids — the most recently
    adopted wins (deterministic)."""
    overrides.adopt("POL-OLD", challenge="old wording",
                    policy_violated="Mass Destructive Intent")
    overrides.adopt("POL-NEW", challenge="new wording",
                    policy_violated="Mass Destructive Intent")
    # bump POL-NEW's adopted_at so it is unambiguously newer regardless of clock res
    store = overrides.load_overrides()
    store["overrides"]["POL-NEW"]["adopted_at"] = "2999-01-01T00:00:00+00:00"
    overrides.save_overrides(store)
    got = overrides.get_active_override("MISS", policy_name="Mass Destructive Intent")
    assert got["challenge"] == "new wording"


def test_no_id_and_no_name_returns_none(store_path):
    overrides.adopt("POL-A", challenge="x", policy_violated="MDI")
    assert overrides.get_active_override(None, policy_name=None) is None


def test_malformed_store_is_safe(store_path):
    with open(store_path, "w") as f:
        f.write("{ this is not json")
    # never raises; degrades to empty
    assert overrides.load_overrides() == {"version": 1, "overrides": {}}
    assert overrides.get_active_override("POL-TEST-1") is None


def test_adopt_rejects_blank_challenge(store_path):
    with pytest.raises(ValueError):
        overrides.adopt("POL-X", challenge="   ")


# --------------------------------------------------------------- harvest

def test_harvest_projects_reusable_only(tmp_path, monkeypatch):
    db = str(tmp_path / "incidents.db")
    _make_incident_db(db, [
        ("r1", "COMPLIED", "POL-A", "Secrets", {
            "reusable": True, "resolution_type": "FOUND_SAFE_ALTERNATIVE",
            "prompt_patch_suggestion": "Use the public cert endpoint."}),
        ("r2", "COMPLIED", "POL-A", "Secrets", {
            "reusable": False, "resolution_type": "X",
            "prompt_patch_suggestion": "this one is NOT reusable"}),
        ("r3", "COMPLIED", "POL-A", "Secrets", None),          # no resolution_path
        ("r4", "CHALLENGED", "POL-A", "Secrets", {              # not COMPLIED
            "reusable": True, "prompt_patch_suggestion": "ignored — still open"}),
    ])
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)

    out = overrides.harvest_candidates()
    assert set(out.keys()) == {"POL-A"}
    cands = out["POL-A"]["candidates"]
    assert len(cands) == 1
    assert cands[0]["suggestion"] == "Use the public cert endpoint."
    assert cands[0]["resolution_type"] == "FOUND_SAFE_ALTERNATIVE"


def test_cluster_near_duplicates_merges_and_sums():
    # near-identical phrasings collapse (count summed); distinct stays separate
    merged = overrides.cluster_near_duplicates(
        [
            {"suggestion": "Use a soft delete on the customers table.", "count": 1},
            {"suggestion": "Use a soft-delete on the customers table.", "count": 1},
            {"suggestion": "Scope the query to the current user's own rows.", "count": 1},
        ],
        text_key="suggestion",
    )
    assert len(merged) == 2
    by_count = sorted(merged, key=lambda c: -c["count"])
    assert by_count[0]["count"] == 2          # the two near-dupes merged
    assert by_count[1]["count"] == 1          # the distinct one stands alone


def test_harvest_clusters_near_duplicate_phrasings(tmp_path, monkeypatch):
    db = str(tmp_path / "incidents.db")
    _make_incident_db(db, [
        ("r1", "COMPLIED", "POL-D", "Mass Destructive", {
            "reusable": True, "prompt_patch_suggestion": "Use a soft delete on the customers table."}),
        ("r2", "COMPLIED", "POL-D", "Mass Destructive", {
            "reusable": True, "prompt_patch_suggestion": "Use a soft-delete on the customers table."}),
        ("r3", "COMPLIED", "POL-D", "Mass Destructive", {
            "reusable": True, "prompt_patch_suggestion": "Scope the query to the current user's own rows only."}),
    ])
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)
    cands = overrides.harvest_candidates()["POL-D"]["candidates"]
    assert len(cands) == 2          # the reworded near-dupes collapsed
    assert cands[0]["count"] == 2   # merged pair ranks first by recurrence
    assert cands[1]["count"] == 1


def test_harvest_ranks_by_recurrence(tmp_path, monkeypatch):
    db = str(tmp_path / "incidents.db")
    _make_incident_db(db, [
        ("r1", "COMPLIED", "POL-B", "Mass Mutation", {
            "reusable": True, "prompt_patch_suggestion": "Scope with a tight WHERE."}),
        ("r2", "COMPLIED", "POL-B", "Mass Mutation", {
            "reusable": True, "prompt_patch_suggestion": "Scope with a tight WHERE."}),
        ("r3", "COMPLIED", "POL-B", "Mass Mutation", {
            "reusable": True, "prompt_patch_suggestion": "Archive instead of bulk delete."}),
    ])
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)

    cands = overrides.harvest_candidates()["POL-B"]["candidates"]
    assert [c["suggestion"] for c in cands][0] == "Scope with a tight WHERE."  # ×2 ranks first
    assert cands[0]["count"] == 2
    assert cands[1]["count"] == 1


def test_harvest_missing_db_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTX_INCIDENT_DB", str(tmp_path / "nope.db"))
    assert overrides.harvest_candidates() == {}


def test_incident_db_env_override_wins(tmp_path, monkeypatch):
    target = str(tmp_path / "custom.db")
    monkeypatch.setenv("AGENTX_INCIDENT_DB", target)
    assert overrides._incident_db_path() == target


def test_incident_db_resolves_first_existing_candidate(tmp_path, monkeypatch):
    # Dev-repo layout: root has a .agentx/ (the anchor) but the incidents.db lives
    # under agentx_sdk/.agentx/. Resolution must fall through to the second
    # candidate, not stop at the bare default.
    monkeypatch.delenv("AGENTX_INCIDENT_DB", raising=False)
    (tmp_path / ".git").mkdir()                          # repo root (the anchor)
    (tmp_path / ".agentx").mkdir()
    nested = tmp_path / "agentx_sdk" / ".agentx"
    nested.mkdir(parents=True)
    _make_incident_db(str(nested / "incidents.db"), [])
    monkeypatch.chdir(tmp_path)
    assert overrides._incident_db_path().replace("\\", "/").endswith(
        "agentx_sdk/.agentx/incidents.db")


def test_store_resolves_from_subdirectory(tmp_path, monkeypatch):
    """The cwd-independence fix: running from examples/ must resolve the SAME
    store as running from the project root — so insights/adopt and the runtime
    swap never split."""
    monkeypatch.delenv("AGENTX_OVERRIDES", raising=False)
    monkeypatch.delenv("AGENTX_INCIDENT_DB", raising=False)
    (tmp_path / ".git").mkdir()                          # repo root (the anchor)
    (tmp_path / ".agentx").mkdir()                       # the store home at root
    _make_incident_db(str(tmp_path / ".agentx" / "incidents.db"), [])
    sub = tmp_path / "examples"
    sub.mkdir()
    monkeypatch.chdir(sub)                               # run from the subdirectory
    assert os.path.realpath(overrides._overrides_path()) == \
        os.path.realpath(str(tmp_path / ".agentx" / "overrides.json"))
    assert os.path.realpath(overrides._incident_db_path()) == \
        os.path.realpath(str(tmp_path / ".agentx" / "incidents.db"))


def test_incident_db_census(tmp_path, monkeypatch):
    db = str(tmp_path / "incidents.db")
    _make_incident_db(db, [
        ("r1", "COMPLIED", "POL-A", "Secrets", {
            "reusable": True, "prompt_patch_suggestion": "do X"}),
        ("r2", "COMPLIED", "POL-A", "Secrets", None),
        ("r3", "DENIED", "POL-A", "Secrets", None),
    ])
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)
    census = overrides.incident_db_census()
    assert census["exists"] is True
    assert census["complied"] == 2
    assert census["with_resolution"] == 1


def test_incident_db_census_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTX_INCIDENT_DB", str(tmp_path / "nope.db"))
    census = overrides.incident_db_census()
    assert census["exists"] is False
    assert census["complied"] == 0


def test_harvest_old_schema_without_column_is_safe(tmp_path, monkeypatch):
    db = str(tmp_path / "incidents.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE incidents (receipt_id TEXT, status TEXT)")  # no resolution_path
    conn.commit()
    conn.close()
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)
    assert overrides.harvest_candidates() == {}


# --------------------------------------------------------------- SDK swap

VIOLATION = {
    "error": "AgentX Policy Violation",
    "policy_id": "POL-SWAP-1",
    "policy_triggered": "Secrets and PII Exfiltration",
    "challenge": "Generic: revise your action.",
    "receipt_id": "rcpt-swap-1",
    "safe_path": "generic-safe-path",
}


@pytest.fixture(autouse=True)
def reset_swap_state(monkeypatch):
    _session_stats["challenged_traces"].clear()
    _session_stats["recovered_traces"].clear()
    for _k in ("open_challenges", "looped_traces"):
        _session_stats[_k].clear()
    _session_stats["challenge_episodes"] = 0
    _session_stats["self_corrections"] = 0
    _session_stats["consecutive_strikes"].clear()
    _session_stats["gateway_reached"] = False  # coarse pulse stage signal — reset so a reached-gateway test can't leak into the next
    _session_stats["reasoning_enabled"] = None  # companion pulse stage signal — reset alongside gateway_reached (SDK session-globals isolation)
    _session_stats["block_category"] = None  # companion pulse signal — reset with the other pulse-stage globals
    _strike_owner.clear()  # companion to consecutive_strikes — must reset together or the per-trace breaker reset leaks across tests
    _session_stats["overrides_applied"] = 0
    monkeypatch.setenv("AGENTX_BYPASS_LOCAL_SHIELD", "true")
    yield


@agentx_protect(agent_id="swap_test_agent")
def swap_tool(sql_query: str):
    return f"EXECUTED: {sql_query}"


def test_sdk_no_override_is_byte_identical(store_path, monkeypatch):
    """An org with an empty override store gets exactly the gateway block."""
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    result = swap_tool(sql_query="SELECT signing_key FROM secrets;")

    assert is_block(result)
    assert result.challenge == "Generic: revise your action."
    assert result.safe_path == "generic-safe-path"
    assert _session_stats["overrides_applied"] == 0


def test_sdk_swap_applies_adopted_override(store_path, monkeypatch):
    """Once adopted, the org reframe replaces the gateway's generic challenge —
    in both the structured field AND the legacy prose — and is counted."""
    overrides.adopt(
        "POL-SWAP-1",
        challenge="Verify via /pki/verify using the public certificate.",
        safe_path="GET /pki/verify",
        policy_violated="Secrets and PII Exfiltration",
    )
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    result = swap_tool(sql_query="SELECT signing_key FROM secrets;")

    assert isinstance(result, AgentXBlock)
    assert result.challenge == "Verify via /pki/verify using the public certificate."
    assert result.safe_path == "GET /pki/verify"
    assert "Verify via /pki/verify" in str(result)          # folded into the prose too
    assert _session_stats["overrides_applied"] == 1


def test_sdk_swap_for_other_policy_does_not_fire(store_path, monkeypatch):
    """An override for a different policy must not touch this block."""
    overrides.adopt("POL-OTHER", challenge="unrelated reframe")
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    result = swap_tool(sql_query="SELECT signing_key FROM secrets;")

    assert result.challenge == "Generic: revise your action."
    assert _session_stats["overrides_applied"] == 0


def test_sdk_swap_applies_by_name_when_id_differs(store_path, monkeypatch):
    """End-to-end cross-path fix: a reframe adopted under one policy_id still
    fires when the gateway returns the SAME logical policy under a DIFFERENT id
    — matched on policy_violated name. Regression guard for the flicker seen
    running examples/07 (override present on the keyword-shield turn, gone on the
    judge-path turns for the same policy)."""
    overrides.adopt(
        "11111111-1111-1111-1111-111111111101",          # adopted under the shield UUID
        challenge="ORG: only read operations are permitted.",
        policy_violated="Secrets and PII Exfiltration",  # same NAME the gateway returns
    )
    # VIOLATION.policy_id is POL-SWAP-1 (a DIFFERENT id) but the same name.
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    result = swap_tool(sql_query="SELECT signing_key FROM secrets;")

    assert is_block(result)
    assert result.challenge == "ORG: only read operations are permitted."
    assert _session_stats["overrides_applied"] == 1


def test_local_shield_swap_applies_override(store_path, monkeypatch):
    """The Layer-0 keyword-shield path (offline, no gateway) must ALSO deliver an
    adopted reframe — it's the path a keyworded block like DROP TABLE actually
    takes (regression guard for the gap found running examples/01 live)."""
    import agentx_sdk.decorators as dec
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", [{
        "id": "POL-LS-1", "name": "Mass Destructive Intent",
        "blocked_intents": ["drop table"],
        "socratic_prompt": "Generic local prompt.",
    }])
    monkeypatch.delenv("AGENTX_BYPASS_LOCAL_SHIELD", raising=False)   # shield ON
    monkeypatch.setattr(dec._client, "register_incident", lambda **k: "rcpt-ls")
    overrides.adopt("POL-LS-1", challenge="ORG: read-only only.",
                    safe_path="SELECT count(*) FROM users")

    @dec.agentx_protect(agent_id="ls_test")
    def ls_tool(sql_query: str):
        return "ok"

    result = ls_tool(sql_query="DROP TABLE users;")
    assert dec.is_block(result)
    assert result.challenge == "ORG: read-only only."
    assert result.safe_path == "SELECT count(*) FROM users"
    assert dec._session_stats["overrides_applied"] >= 1


# --------------------------------------------------------------- CLI curation

@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """Override store at a temp path + an empty incident store, so `agentx adopt`
    free-text paths don't read the real repo DB."""
    monkeypatch.setenv("AGENTX_OVERRIDES", str(tmp_path / "overrides.json"))
    monkeypatch.setenv("AGENTX_INCIDENT_DB", str(tmp_path / "no.db"))  # harvest -> {}
    return tmp_path


def test_strip_editor_comments():
    from agentx_sdk.cli import _strip_editor_comments
    raw = "Keep this\n# a comment\n   # indented comment\nAnd this\n"
    assert _strip_editor_comments(raw) == "Keep this\nAnd this"


def test_adopt_text_authors_free_text(cli_env):
    from agentx_sdk.cli import execute_adopt
    execute_adopt(["POL-CUSTOM", "--text",
                   "Query the read replica at db-ro.internal, never prod."])
    got = overrides.get_active_override("POL-CUSTOM")
    assert got["challenge"].startswith("Query the read replica")
    assert got["safe_path"] is None                        # no --safe-path → None, not the prose
    assert overrides.load_overrides()["overrides"]["POL-CUSTOM"]["source"] == "manual"


def test_adopt_text_with_distinct_safe_path(cli_env):
    from agentx_sdk.cli import execute_adopt
    execute_adopt(["POL-X", "--text", "Keep it read-only.",
                   "--safe-path", "SELECT count(*) FROM orders"])
    got = overrides.get_active_override("POL-X")
    assert got["challenge"] == "Keep it read-only."
    assert got["safe_path"] == "SELECT count(*) FROM orders"


def test_adopt_edit_uses_editor_result(cli_env, monkeypatch):
    """--edit routes through $EDITOR; inject the editor so no UI launches."""
    import agentx_sdk.cli as cli
    monkeypatch.setattr(cli, "_edit_text", lambda seed: "EDITED: " + (seed or ""))
    cli.execute_adopt(["POL-X", "--text", "base", "--edit"])
    assert overrides.get_active_override("POL-X")["challenge"] == "EDITED: base"


def test_adopt_empty_text_aborts_without_writing(cli_env):
    from agentx_sdk.cli import execute_adopt
    execute_adopt(["POL-X", "--text", "   "])
    assert overrides.get_active_override("POL-X") is None


def test_adopt_index_and_text_conflict_exits(cli_env):
    from agentx_sdk.cli import execute_adopt
    with pytest.raises(SystemExit):
        execute_adopt(["POL-X", "1", "--text", "foo"])


def test_adopt_unknown_flag_exits(cli_env):
    from agentx_sdk.cli import execute_adopt
    with pytest.raises(SystemExit):
        execute_adopt(["POL-X", "--bogus"])


# ------------------------------------------------ global sequence numbering

def test_enumerate_candidates_is_global_and_stable():
    harvest = {
        "POL-B": {"policy_violated": "Secrets",
                  "candidates": [{"suggestion": "b1", "count": 1, "resolution_type": None}]},
        "POL-A": {"policy_violated": "MDI",
                  "candidates": [{"suggestion": "a2", "count": 1, "resolution_type": None},
                                 {"suggestion": "a1", "count": 3, "resolution_type": None}]},
    }
    flat = overrides.enumerate_candidates(harvest)
    # policies sorted by id (A before B); per-policy order preserved; seq is global
    assert [(c["seq"], c["policy_id"], c["suggestion"]) for c in flat] == [
        (1, "POL-A", "a2"), (2, "POL-A", "a1"), (3, "POL-B", "b1")]


def test_adopt_by_global_seq_needs_no_uuid(tmp_path, monkeypatch):
    from agentx_sdk.cli import execute_adopt
    db = str(tmp_path / "incidents.db")
    _make_incident_db(db, [
        ("r1", "COMPLIED", "POL-A", "Mass Destructive", {
            "reusable": True, "prompt_patch_suggestion": "A-safe-path"}),
        ("r2", "COMPLIED", "POL-B", "Secrets", {
            "reusable": True, "prompt_patch_suggestion": "B-safe-path"}),
    ])
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)
    monkeypatch.setenv("AGENTX_OVERRIDES", str(tmp_path / "ov.json"))
    execute_adopt(["2"])                       # #1 = POL-A, #2 = POL-B (sorted by id)
    assert overrides.get_active_override("POL-B")["challenge"] == "B-safe-path"
    assert overrides.get_active_override("POL-A") is None


def test_adopt_seq_out_of_range_exits(cli_env):
    from agentx_sdk.cli import execute_adopt
    with pytest.raises(SystemExit):
        execute_adopt(["99"])                  # harvest is empty -> no #99


def test_adopt_seq_with_text_is_rejected(cli_env):
    from agentx_sdk.cli import execute_adopt
    with pytest.raises(SystemExit):
        execute_adopt(["1", "--text", "fresh"])  # --text needs a policy id, not a #


def test_adopt_unique_prefix_resolves_the_full_id(tmp_path, monkeypatch):
    from agentx_sdk.cli import execute_adopt
    db = str(tmp_path / "incidents.db")
    _make_incident_db(db, [
        ("r1", "COMPLIED", "11111111-1111-1111-1111-111111111101", "MDI", {
            "reusable": True, "prompt_patch_suggestion": "scoped read only"}),
    ])
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)
    monkeypatch.setenv("AGENTX_OVERRIDES", str(tmp_path / "ov.json"))
    # A dashed UUID prefix is non-numeric, so it routes to prefix matching (a bare
    # all-digit token would be read as a sequence # instead — which is correct).
    execute_adopt(["11111111-1111", "1"])      # abbreviated id (unique prefix)
    got = overrides.get_active_override("11111111-1111-1111-1111-111111111101")
    assert got["challenge"] == "scoped read only"


# ------------------------------------------------ review fixes (PR #71 code-review)

def test_git_root_preferred_over_nested_agentx(tmp_path, monkeypatch):
    """Fix #1: a nested .agentx must NOT split the store — the .git repo root is the
    anchor, so adopt-from-root and run-from-subdir resolve the same overrides.json."""
    monkeypatch.delenv("AGENTX_OVERRIDES", raising=False)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".agentx").mkdir()
    sub = tmp_path / "agentx_sdk"
    (sub / ".agentx").mkdir(parents=True)          # a SECOND, nested .agentx
    monkeypatch.chdir(sub)                          # run from inside the nested one
    assert os.path.realpath(overrides._find_project_root()) == os.path.realpath(str(tmp_path))
    assert os.path.realpath(overrides._overrides_path()) == \
        os.path.realpath(str(tmp_path / ".agentx" / "overrides.json"))


def test_load_overrides_warns_on_malformed(store_path, capsys):
    """Fix #2: a corrupt store warns (when warn=True) instead of silently emptying."""
    with open(store_path, "w", encoding="utf-8") as f:
        f.write("{ broken json,,,")
    data = overrides.load_overrides(warn=True)
    assert data == {"version": 1, "overrides": {}}
    err = capsys.readouterr().err
    assert "AgentX" in err and "overrides.json" in err


def test_load_overrides_silent_when_absent(store_path, capsys):
    """Fix #2: an absent file is normal — never warn, even with warn=True."""
    data = overrides.load_overrides(warn=True)
    assert data == {"version": 1, "overrides": {}}
    assert capsys.readouterr().err == ""


def test_adopt_prefix_resolves_via_active_override(cli_env):
    """Fix #3: prefix matching also resolves ids that only have an ACTIVE override
    (no fresh candidates), so re-editing an existing override by prefix works."""
    from agentx_sdk.cli import execute_adopt
    full = "11111111-1111-1111-1111-111111111101"
    overrides.adopt(full, challenge="original")            # active override, no harvest
    execute_adopt(["11111111-1111", "--text", "updated wording"])
    assert overrides.get_active_override(full)["challenge"] == "updated wording"


def test_adopt_text_default_safe_path_is_none(cli_env):
    """Fix #4: without --safe-path, safe_path is None (not the challenge prose)."""
    from agentx_sdk.cli import execute_adopt
    execute_adopt(["POL-Z", "--text", "Keep it read-only."])
    assert overrides.get_active_override("POL-Z")["safe_path"] is None


def test_sdk_swap_noop_override_not_counted(store_path, monkeypatch):
    """Fix #10: an override whose text already equals the gateway challenge is a
    no-op — it must not bump the 'Org Reframes Applied' proof metric."""
    overrides.adopt("POL-SWAP-1", challenge=VIOLATION["challenge"])  # identical text, no safe_path
    monkeypatch.setattr(_client, "evaluate_intent", lambda **k: VIOLATION)
    result = swap_tool(sql_query="SELECT signing_key FROM secrets;")
    assert result.challenge == VIOLATION["challenge"]
    assert _session_stats["overrides_applied"] == 0


def test_confirm_adopt_auto_proceeds_non_interactive(capsys):
    """Fix #5: scripted/non-interactive adopt auto-confirms (never hangs)."""
    from agentx_sdk import cli
    assert cli._confirm_adopt("Policy X", "some challenge") is True
    assert "auto-confirmed" in capsys.readouterr().out


def test_adopt_respects_declined_confirm(tmp_path, monkeypatch):
    """Fix #5: a declined confirm aborts a verbatim harvested promote (#N path)."""
    import agentx_sdk.cli as cli
    db = str(tmp_path / "incidents.db")
    _make_incident_db(db, [
        ("r1", "COMPLIED", "POL-A", "MDI", {"reusable": True, "prompt_patch_suggestion": "A-one"}),
    ])
    monkeypatch.setenv("AGENTX_INCIDENT_DB", db)
    monkeypatch.setenv("AGENTX_OVERRIDES", str(tmp_path / "ov.json"))
    monkeypatch.setattr(cli, "_confirm_adopt", lambda label, ch: False)
    cli.execute_adopt(["1"])
    assert overrides.get_active_override("POL-A") is None


def test_edit_text_launches_without_shell(monkeypatch):
    """Fix #8: a multi-word $EDITOR is launched without a shell (no shell=True
    footgun), preserving its args, and the editor's output is read back."""
    import subprocess
    import agentx_sdk.cli as cli
    monkeypatch.setenv("EDITOR", "myeditor --wait")
    monkeypatch.delenv("VISUAL", raising=False)
    seen = {}

    def fake_call(cmd, *a, **k):
        seen["cmd"] = cmd
        seen["shell"] = k.get("shell", False)
        if isinstance(cmd, list):                     # POSIX: argv list
            path = cmd[-1]
        else:                                         # Windows: '... "tmp"' string
            import shlex as _s
            path = _s.split(cmd, posix=False)[-1].strip('"')
        with open(path, "w", encoding="utf-8") as f:
            f.write("edited!\n")
        return 0

    monkeypatch.setattr(subprocess, "call", fake_call)
    assert cli._edit_text("seed") == "edited!"
    assert seen["shell"] is False                     # the footgun is gone
    if isinstance(seen["cmd"], list):
        assert seen["cmd"][:2] == ["myeditor", "--wait"]
    else:
        assert seen["cmd"].startswith("myeditor --wait ")
