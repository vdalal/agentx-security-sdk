"""Tests for the agentx-mcp stdio proxy (agentx_sdk/mcp_proxy.py).

Two layers:
  * the routing core (`_route_line`) driven with injected in-memory streams — fast,
    deterministic, covers block / allow / passthrough / malformed / catalog-exempt /
    breaker;
  * one true end-to-end test that spawns a real stub MCP server as the child and
    proves a dangerous tools/call is answered with an isError result and NEVER
    reaches the server, while a benign one is forwarded.

Plus a parity test pinning evaluate_call_keyless — the single detector shared with
the @agentx_protect decorator — so the two paths can't drift.
"""
import io
import json
import os
import sys

import pytest

from agentx_sdk import mcp_proxy as mp
from agentx_sdk.decorators import evaluate_call_keyless


def _line(method="tools/call", *, id=1, name="run_sql", arguments=None, **extra):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        msg["id"] = id
    if method == "tools/call":
        msg["params"] = {"name": name, "arguments": arguments or {}}
    msg.update(extra)
    return json.dumps(msg) + "\n"


def _route(line, *, stats=None, streaks=None, max_turns=3, harvest=None):
    """Drive one line through the core with in-memory streams. Returns
    (forwarded_to_child, sent_to_client, stats)."""
    child, client = io.StringIO(), io.StringIO()
    stats = {} if stats is None else stats
    mp._route_line(line, child, mp._ClientWriter(client), stats,
                   {} if streaks is None else streaks, max_turns, io.StringIO(), harvest)
    return child.getvalue(), client.getvalue(), stats


# --------------------------------------------------------------------------- #
# routing core
# --------------------------------------------------------------------------- #
def test_dangerous_tools_call_is_blocked_and_not_forwarded():
    line = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    forwarded, client_out, stats = _route(line)

    assert forwarded == ""                     # the dangerous call never reached the server
    resp = json.loads(client_out)
    assert resp["id"] == 1
    assert resp["result"]["isError"] is True   # MCP CallToolResult error -> agent self-corrects
    assert resp["result"]["content"][0]["type"] == "text"
    assert "AgentX" in resp["result"]["content"][0]["text"]
    assert stats["critical_blocks"] == 1 and stats["intercepts"] == 1
    assert stats["block_category"] == "DESTRUCTIVE_ACTION"
    assert stats["total_calls"] == 1


def test_benign_tools_call_is_forwarded_verbatim():
    line = _line(id=2, name="read_file", arguments={"path": "/data/notes.txt"})
    forwarded, client_out, stats = _route(line)

    assert forwarded == line                    # byte-for-byte passthrough
    assert client_out == ""                      # nothing synthesized back to the client
    assert stats["total_calls"] == 1
    assert "critical_blocks" not in stats or stats["critical_blocks"] == 0


@pytest.mark.parametrize("line", [
    _line(method="initialize", id=0, name=None),
    _line(method="tools/list", id=5, name=None),
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n",  # no id
    "this is not json at all\n",
    "\n",
])
def test_non_toolcall_and_malformed_pass_through_untouched(line):
    forwarded, client_out, stats = _route(line)
    assert forwarded == line
    assert client_out == ""
    assert stats.get("total_calls", 0) == 0     # only tools/call counts as monitored


def test_idless_dangerous_tools_call_is_dropped_not_forwarded():
    """A tools/call shaped as a notification (no id) is still screened: a blocked one
    cannot be answered (no id), so it is dropped, never forwarded to the server."""
    line = _line(id=None, name="run_sql", arguments={"query": "DROP TABLE users;"})
    forwarded, client_out, stats = _route(line)
    assert forwarded == ""                       # the dangerous call never reached the server
    assert client_out == ""                       # no id to address, so no response is emitted
    assert stats["critical_blocks"] == 1


def test_batch_screens_each_member():
    """A JSON-RPC batch (array) is screened member by member: the dangerous member is
    blocked (isError back to the client) and only the benign member is forwarded."""
    benign = {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
              "params": {"name": "read_file", "arguments": {"path": "/data/ok.txt"}}}
    danger = {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
              "params": {"name": "run_sql", "arguments": {"query": "DROP TABLE users;"}}}
    forwarded, client_out, stats = _route(json.dumps([benign, danger]) + "\n")

    fwd = json.loads(forwarded)
    assert isinstance(fwd, list) and len(fwd) == 1
    assert fwd[0]["params"]["name"] == "read_file"     # only the benign member forwarded
    resp = json.loads(client_out)
    assert resp["id"] == 11 and resp["result"]["isError"] is True
    assert stats["total_calls"] == 2 and stats["critical_blocks"] == 1


# --------------------------------------------------------------------------- #
# local flight-recorder ledger (P2 change 3) — real MCP catches reach `agentx status`
# --------------------------------------------------------------------------- #
def test_ledger_records_block_and_recovery(monkeypatch, tmp_path):
    """A real MCP catch is written to the SAME SQLite flight-recorder `agentx status`
    reads (not only the streak): a block logs CHALLENGED, and a later clean call on the
    same tool flips it to RECOVERED."""
    import agentx_sdk.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / ".agentx_ledger.db"))
    db_module.init_db()

    stats = {"_ledger": True, "_trace_id": "mcp-test", "total_calls": 0}
    streaks = {}
    # A dangerous call is blocked -> logged CHALLENGED.
    _route(_line(name="run_sql", arguments={"query": "DROP TABLE users;"}),
           stats=stats, streaks=streaks)
    result = db_module.get_lifetime_stats()
    assert result["total_intercepts"] == 1
    assert result["total_self_corrections"] == 0

    # A later clean call on the SAME tool trips the recovery heuristic -> flip to RECOVERED.
    _route(_line(id=2, name="run_sql", arguments={"query": "SELECT 1"}),
           stats=stats, streaks=streaks)
    result = db_module.get_lifetime_stats()
    assert result["total_intercepts"] == 1          # still one episode, now RECOVERED
    assert result["total_self_corrections"] == 1


def test_ledger_recovery_flips_one_block_not_all(monkeypatch, tmp_path):
    """A tool blocked twice before a single clean call must count as ONE recovery, not two:
    the clean call flips only the latest open block. A session-wide trace would flip both
    and inflate the recovery rate `agentx status` shows."""
    import agentx_sdk.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / ".agentx_multi.db"))
    db_module.init_db()

    stats = {"_ledger": True, "_trace_id": "mcp-test", "total_calls": 0}
    streaks = {}
    for _ in range(2):  # same tool blocked twice
        _route(_line(name="run_sql", arguments={"query": "DROP TABLE users;"}),
               stats=stats, streaks=streaks)
    _route(_line(id=9, name="run_sql", arguments={"query": "SELECT 1"}),
           stats=stats, streaks=streaks)

    result = db_module.get_lifetime_stats()
    assert result["total_intercepts"] == 2          # both blocks recorded
    assert result["total_self_corrections"] == 1    # one clean call = one recovery, not two


def test_routing_core_never_touches_ledger_without_flag(monkeypatch, tmp_path):
    """The routing-core tests build a bare session_stats (no _ledger), so the proxy must
    not write to the ledger there — the gate keeps the core unit tests DB-free."""
    import agentx_sdk.db as db_module
    db_file = tmp_path / ".agentx_none.db"
    monkeypatch.setattr(db_module, "DB_PATH", str(db_file))
    _route(_line(name="run_sql", arguments={"query": "DROP TABLE users;"}))  # stats={} default
    assert not db_file.exists()


def test_block_category_off_vocab_is_not_emitted(monkeypatch):
    """A blocked policy whose category is not in the closed vocab must not put free
    text on the pulse (privacy guard mirroring the decorator)."""
    decision = {"policy_name": "X", "challenge_text": "no", "category": "internal-billing-rule"}
    writer = mp._ClientWriter(io.StringIO())
    stats = {}
    # Patch the detector to return an off-vocab category for this one call.
    monkeypatch.setattr(mp, "evaluate_call_keyless", lambda q: decision)
    mp._screen_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "t", "arguments": {}}},
                       stats, {}, 3, writer, io.StringIO())
    assert "block_category" not in stats           # off-vocab dropped, never emitted


def test_non_string_category_does_not_wedge_screening(monkeypatch):
    """A malformed pulled policy can carry a NON-string category; screening must drop it
    without raising (a TypeError in `<list> in <frozenset>` would wedge the whole client
    routing loop). Pre-existing base-path fragility surfaced by the #135 review."""
    decision = {"policy_name": "X", "challenge_text": "no", "category": ["weird", "list"],
                "policy_id": "P", "preferred_alternative": None}
    monkeypatch.setattr(mp, "evaluate_call_keyless", lambda q: decision)
    stats = {}
    mp._screen_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "t", "arguments": {}}},
                       stats, {}, 3, mp._ClientWriter(io.StringIO()), io.StringIO())
    assert "block_category" not in stats           # non-string category dropped, never emitted
    assert stats["critical_blocks"] == 1           # the block still stood; the loop did not wedge


def test_benign_catalog_read_is_exempt():
    line = _line(id=3, name="run_sql",
                 arguments={"query": "SELECT * FROM information_schema.columns"})
    forwarded, client_out, stats = _route(line)
    assert forwarded == line                     # schema discovery is a benign read
    assert client_out == ""


def test_circuit_breaker_trips_after_ceiling():
    line = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    stats, streaks = {}, {}
    # Mirror the decorator: max_turns blocks are ALLOWED, the NEXT one trips the breaker
    # (compare-before-increment), so the MCP and decorator paths halt at the same point.
    for _ in range(3):
        _, client, stats = _route(line, stats=stats, streaks=streaks, max_turns=3)
        assert "circuit breaker" not in json.loads(client)["result"]["content"][0]["text"].lower()
    _, client, stats = _route(line, stats=stats, streaks=streaks, max_turns=3)
    assert "circuit breaker" in json.loads(client)["result"]["content"][0]["text"].lower()


def test_allow_resets_block_streak():
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    benign = _line(name="run_sql", arguments={"query": "SELECT 1"})
    stats, streaks = {}, {}
    _route(danger, stats=stats, streaks=streaks)
    assert streaks.get("run_sql") == 1
    _route(benign, stats=stats, streaks=streaks)
    assert "run_sql" not in streaks             # a clean call zeroes the streak


# --------------------------------------------------------------------------- #
# A1a — coaching is call-fitting and names a safe path (not generic)
# --------------------------------------------------------------------------- #
def test_block_coaching_is_call_fitting_and_names_a_safe_path(monkeypatch):
    """The keyless coaching names the blocked TOOL and the policy's concrete safe
    alternative, so the caller's model gets a task-fitting hint to recover on (not a
    generic 'policy violation'), and the judge-era cruft is gone. Arm the shipped
    builtins explicitly: a dev machine may carry a pulled .agentx/policies.json that
    shadows them, but the cold/keyless install (the funnel target) runs the builtins."""
    from agentx_sdk import decorators as dec
    monkeypatch.setattr(dec, "LOCAL_POLICY_KEYWORDS", list(dec._BUILTIN_POLICY_KEYWORDS))
    line = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    _, client_out, _ = _route(line)
    text = json.loads(client_out)["result"]["content"][0]["text"]
    assert "run_sql" in text                       # call-fitting: names the blocked tool
    assert "Safe alternative:" in text             # surfaces preferred_alternative
    assert "WHERE clause" in text                  # the concrete safe path, not boilerplate
    assert "symbolic reasoning" not in text.lower()   # judge-era cruft removed


# --------------------------------------------------------------------------- #
# A2 — the proxy counts a keyless recover (same-tool block -> later allow)
# --------------------------------------------------------------------------- #
def test_same_tool_block_then_allow_counts_a_self_correction():
    """The proxy is the only place that sees BOTH halves of a recovery. A block on tool
    T followed by a clean call on T (the model's safe revision) increments
    self_corrections, making the keyless recover visible on the pulse. Conservative:
    only a clean SAME-tool block->allow counts."""
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    safe = _line(name="run_sql", arguments={"query": "SELECT 1"})
    stats, streaks = {}, {}
    _route(danger, stats=stats, streaks=streaks)
    assert stats.get("self_corrections", 0) == 0   # a block alone is not a recovery
    _route(safe, stats=stats, streaks=streaks)
    assert stats["self_corrections"] == 1          # same tool now runs safe -> recovered


def test_clean_call_without_prior_block_is_not_a_self_correction():
    """A clean call on a tool that was never blocked must NOT count as a recovery."""
    _, _, stats = _route(_line(name="read_file", arguments={"path": "/data/ok.txt"}))
    assert stats.get("self_corrections", 0) == 0   # no prior block -> no over-count


# --------------------------------------------------------------------------- #
# (B) harvest-IN — opt-in, abstract-only, local recovery-pair capture
# --------------------------------------------------------------------------- #
def test_harvest_is_opt_in_off_by_default(monkeypatch):
    monkeypatch.delenv("AGENTX_MCP_HARVEST", raising=False)
    assert mp._harvest_enabled() is False
    monkeypatch.setenv("AGENTX_MCP_HARVEST", "1")
    assert mp._harvest_enabled() is True


def test_harvest_records_abstract_recovery_pair():
    """A same-tool block->allow yields ONE recovery-pair candidate carrying the coarse category
    AND the recovered call's value-free structural signature — never a raw payload."""
    h = mp._Harvest()
    stats, streaks = {}, {}
    _route(_line(name="run_sql", arguments={"query": "DROP TABLE users;"}),
           stats=stats, streaks=streaks, harvest=h)
    assert h.pairs == []                                    # a block alone is not a pair
    _route(_line(name="run_sql", arguments={"query": "SELECT name FROM users", "limit": 100}),
           stats=stats, streaks=streaks, harvest=h)
    pair = h.pairs[0]
    assert pair["tool"] == "run_sql"
    assert pair["policy_category"] == "DESTRUCTIVE_ACTION"
    assert pair["target_action"] == "EXECUTE"     # off the tool name "run_sql"
    assert pair["scope"] == "scoped"              # off the "limit" arg KEY (never its value)
    assert pair["recovered"] is True
    # Policy identity captured for adoption (floor label + id, value-free, not user data).
    assert isinstance(pair.get("policy_name"), str) and pair["policy_name"]
    assert isinstance(pair.get("policy_id"), str) and pair["policy_id"]
    assert "DROP TABLE" not in json.dumps(h.pairs)         # privacy: no raw payload captured
    assert "SELECT" not in json.dumps(h.pairs)             # privacy: not even the safe query


def test_harvest_pair_carries_policy_identity_for_adoption():
    """note_block records the policy identity (name + id) so a later same-tool recovery forms a
    pair keyed to the exact policy the next block matches. Identity keys are floor labels, not
    user data; the signature stays value-free."""
    h = mp._Harvest()
    h.note_block("read_file", "SECRETS_LEAK", policy_name="Secrets and PII", policy_id="pol-9")
    h.note_recovery("read_file", {"id": 1})
    assert h.pairs == [{
        "tool": "read_file", "policy_category": "SECRETS_LEAK",
        "policy_name": "Secrets and PII", "policy_id": "pol-9",
        "target_action": "READ", "scope": "scoped", "recovered": True,
    }]


def test_harvest_drops_off_vocab_category():
    """A category outside the closed pulse vocab is never captured (privacy guard)."""
    h = mp._Harvest()
    h.note_block("t", "internal-billing-rule")             # off-vocab -> dropped
    h.note_recovery("t")
    assert h.pairs == []


def test_flush_harvest_writes_exact_abstract_pair_to_local_jsonl(tmp_path, monkeypatch):
    """Flush appends the EXACT abstract pair (no deanonymizing timestamp) to a LOCAL jsonl
    under the project root, best-effort."""
    monkeypatch.delenv("AGENTX_MCP_HARVEST_PATH", raising=False)
    monkeypatch.setattr("agentx_sdk.overrides._find_project_root", lambda *a, **k: str(tmp_path))
    h = mp._Harvest()
    pair = {"tool": "run_sql", "policy_category": "DESTRUCTIVE_ACTION",
            "target_action": "EXECUTE", "scope": "scoped", "recovered": True}
    h.pairs = [dict(pair)]
    mp._flush_harvest(h, io.StringIO())
    out = tmp_path / ".agentx" / "mcp_harvest.jsonl"
    assert out.exists()
    rec = json.loads(out.read_text(encoding="utf-8").strip())
    assert rec == pair


def test_flush_harvest_honors_explicit_path(tmp_path, monkeypatch):
    """An explicit AGENTX_MCP_HARVEST_PATH wins (the MCP-context control)."""
    target = tmp_path / "nested" / "harvest.jsonl"
    monkeypatch.setenv("AGENTX_MCP_HARVEST_PATH", str(target))
    h = mp._Harvest()
    h.pairs = [{"tool": "t", "policy_category": "SECRETS_LEAK", "recovered": True}]
    mp._flush_harvest(h, io.StringIO())
    assert target.exists()


def test_harvest_off_vocab_block_clears_stale_pending():
    """An off-vocab re-block clears a stale pending category, so a later recovery is not
    mis-attributed to the earlier category (or crashed by a non-string category)."""
    h = mp._Harvest()
    h.note_block("t", "DESTRUCTIVE_ACTION")        # in-vocab -> pending
    h.note_block("t", "internal-billing-rule")     # off-vocab -> CLEARS pending
    h.note_block("u", ["weird", "list"])           # non-string -> dropped, no crash
    h.note_recovery("t")
    assert h.pairs == []                            # no mis-attributed pair


def test_harvest_skips_idless_uncoached_block():
    """An id-less blocked call is dropped with no coaching, so a later clean call on that tool
    is NOT recorded as a coached recovery (no phantom pair)."""
    h = mp._Harvest()
    stats, streaks = {}, {}
    _route(_line(id=None, name="run_sql", arguments={"query": "DROP TABLE users;"}),
           stats=stats, streaks=streaks, harvest=h)   # id-less block: dropped, not harvested
    _route(_line(name="run_sql", arguments={"query": "SELECT 1"}),
           stats=stats, streaks=streaks, harvest=h)
    assert h.pairs == []                              # no phantom pair from an uncoached block


# --------------------------------------------------------------------------- #
# (B) READ side — make the local recovery corpus legible (inverse of _flush_harvest)
# --------------------------------------------------------------------------- #
def _write_pairs(path, pairs):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")


def test_read_harvest_pairs_missing_file_is_empty(tmp_path):
    assert mp.read_harvest_pairs(str(tmp_path / "nope.jsonl")) == []


def test_read_harvest_pairs_reads_exact_records(tmp_path):
    pairs = [
        {"tool": "run_sql", "policy_category": "DESTRUCTIVE_ACTION",
         "target_action": "READ", "scope": "scoped", "recovered": True},
        {"tool": "fetch_url", "policy_category": "NETWORK_TRAVERSAL",
         "target_action": "READ", "scope": "broad", "recovered": True},
    ]
    f = tmp_path / "mcp_harvest.jsonl"
    _write_pairs(f, pairs)
    assert mp.read_harvest_pairs(str(f)) == pairs


def test_read_harvest_pairs_skips_malformed_and_non_dict_lines(tmp_path):
    """A blank line, a non-JSON line, or a valid-but-non-dict line is skipped, so a
    hand-edit or a partial append can't sink the whole view."""
    f = tmp_path / "mcp_harvest.jsonl"
    good = {"tool": "t", "policy_category": "SECRETS_LEAK", "recovered": True}
    content = (
        json.dumps(good) + "\n"
        + "\n"                       # blank line
        + "not json at all\n"        # malformed
        + "[1, 2, 3]\n"              # valid JSON, not a dict
        + '"a string"\n'             # valid JSON, not a dict
    )
    f.write_text(content, encoding="utf-8")
    assert mp.read_harvest_pairs(str(f)) == [good]


def test_read_harvest_pairs_survives_invalid_utf8(tmp_path):
    """A stray non-UTF-8 byte (truncated multibyte write / concurrent append / hand-edit)
    must NOT raise out of the inspection path: errors='replace' keeps the good lines and
    the mangled one just fails json.loads and is skipped."""
    f = tmp_path / "mcp_harvest.jsonl"
    good = {"tool": "t", "policy_category": "SECRETS_LEAK", "recovered": True}
    # A valid record, then a line with a raw invalid UTF-8 byte (0xFF).
    f.write_bytes((json.dumps(good) + "\n").encode("utf-8") + b"\xff{bad}\n")
    assert mp.read_harvest_pairs(str(f)) == [good]      # never raises, good line survives


# --------------------------------------------------------------------------- #
# (B) WIRING — project the corpus into adoptable org-brain candidates
# --------------------------------------------------------------------------- #
def test_recovery_challenge_is_minimal_privilege_and_value_free():
    """The templated coaching points toward LESS capability (oracle guardrail) and carries no
    lateral alternative and no user data."""
    scoped = mp._recovery_challenge("Mass Destructive Intent", "DELETE", "scoped")
    assert "Mass Destructive Intent" in scoped
    assert "narrow" in scoped.lower() or "archive" in scoped.lower() or "scoped" in scoped.lower()
    broad = mp._recovery_challenge(None, "READ", "broad")
    assert "less capability" in broad.lower()


def test_mcp_recovery_candidates_empty_when_no_corpus(tmp_path):
    assert mp.mcp_recovery_candidates(str(tmp_path / "nope.jsonl")) == {}


def test_mcp_recovery_candidates_group_rank_and_template(tmp_path):
    """Pairs with a policy identity become per-policy candidates, ranked by recurrence, each
    carrying a templated minimal-privilege challenge keyed to the exact policy."""
    pairs = [
        {"tool": "run_sql", "policy_category": "DESTRUCTIVE_ACTION", "policy_id": "pol-1",
         "policy_name": "Mass Destructive Intent", "target_action": "READ", "scope": "scoped"},
        {"tool": "run_sql", "policy_category": "DESTRUCTIVE_ACTION", "policy_id": "pol-1",
         "policy_name": "Mass Destructive Intent", "target_action": "READ", "scope": "scoped"},
        {"tool": "drop_table", "policy_category": "DESTRUCTIVE_ACTION", "policy_id": "pol-1",
         "policy_name": "Mass Destructive Intent", "target_action": "DELETE", "scope": "broad"},
    ]
    f = tmp_path / "mcp_harvest.jsonl"
    _write_pairs(f, pairs)
    out = mp.mcp_recovery_candidates(str(f))
    assert set(out) == {"pol-1"}
    bucket = out["pol-1"]
    assert bucket["policy_id"] == "pol-1"
    assert bucket["policy_violated"] == "Mass Destructive Intent"
    cands = bucket["candidates"]
    assert cands[0]["count"] == 2 and cands[0]["target_action"] == "READ"   # recurrence ranks first
    assert cands[1]["count"] == 1 and cands[1]["target_action"] == "DELETE"
    assert all(c["resolution_type"] == "mcp_recovery" for c in cands)
    assert "Mass Destructive Intent" in cands[0]["suggestion"]


def test_mcp_recovery_candidates_skip_pairs_without_identity(tmp_path):
    """A pre-identity pair (no policy_id/policy_name) still counts in the corpus but is NOT
    adoptable — an override must key to a real policy."""
    f = tmp_path / "mcp_harvest.jsonl"
    _write_pairs(f, [{"tool": "t", "policy_category": "SECRETS_LEAK",
                      "target_action": "READ", "scope": "broad", "recovered": True}])
    assert mp.mcp_recovery_candidates(str(f)) == {}


def test_mcp_recovery_candidates_key_by_name_when_no_id(tmp_path):
    """policy_name alone still keys a candidate (A1b's cross-path fallback matches on it)."""
    f = tmp_path / "mcp_harvest.jsonl"
    _write_pairs(f, [{"tool": "read_file", "policy_category": "SECRETS_LEAK",
                      "policy_name": "Secrets and PII", "target_action": "READ", "scope": "scoped"}])
    out = mp.mcp_recovery_candidates(str(f))
    assert set(out) == {"Secrets and PII"}
    assert out["Secrets and PII"]["policy_id"] == "Secrets and PII"       # name stands in as key


def test_write_then_read_roundtrip_agrees_on_path(tmp_path, monkeypatch):
    """The read side resolves the SAME file the writer used (via _harvest_path), so a flushed
    session is immediately legible + projectable with no path drift."""
    target = tmp_path / "nested" / "mcp_harvest.jsonl"
    monkeypatch.setenv("AGENTX_MCP_HARVEST_PATH", str(target))
    h = mp._Harvest()
    h.pairs = [{"tool": "run_sql", "policy_category": "DESTRUCTIVE_ACTION", "policy_id": "pol-1",
                "policy_name": "Mass Destructive Intent", "target_action": "READ",
                "scope": "scoped", "recovered": True}]
    mp._flush_harvest(h, io.StringIO())
    assert mp.read_harvest_pairs() == h.pairs   # no explicit path -> resolves via _harvest_path
    out = mp.mcp_recovery_candidates()
    assert out["pol-1"]["candidates"][0]["target_action"] == "READ"


# --------------------------------------------------------------------------- #
# (B) auto-coach — promote the strongest paths (auto-with-human-override)
# --------------------------------------------------------------------------- #
def _mcp_pairs(n, policy_id="pol-1", name="Mass Destructive Intent",
               action="READ", scope="scoped", tool="run_sql"):
    return [{"tool": tool, "policy_category": "DESTRUCTIVE_ACTION", "policy_id": policy_id,
             "policy_name": name, "target_action": action, "scope": scope, "recovered": True}
            for _ in range(n)]


def _setup_auto(tmp_path, monkeypatch, pairs, overrides=None):
    """Point the corpus + overrides at tmp files and give a resolvable project root (.agentx)."""
    corpus = tmp_path / ".agentx" / "mcp_harvest.jsonl"
    _write_pairs(corpus, pairs)
    ov = tmp_path / ".agentx" / "overrides.json"
    if overrides is not None:
        ov.write_text(json.dumps({"version": 1, "overrides": overrides}), encoding="utf-8")
    monkeypatch.setenv("AGENTX_MCP_HARVEST_PATH", str(corpus))
    monkeypatch.setenv("AGENTX_OVERRIDES", str(ov))
    monkeypatch.setattr("agentx_sdk.overrides._find_project_root", lambda *a, **k: str(tmp_path))
    return ov


def _store(ov):
    return json.loads(ov.read_text(encoding="utf-8"))["overrides"] if ov.exists() else {}


def test_auto_coach_promotes_above_threshold(tmp_path, monkeypatch):
    ov = _setup_auto(tmp_path, monkeypatch, _mcp_pairs(3))
    monkeypatch.setenv("AGENTX_MCP_AUTO_COACH", "on")
    monkeypatch.setenv("AGENTX_MCP_AUTO_COACH_MIN", "3")
    mp.auto_coach(log=io.StringIO())
    store = _store(ov)
    assert store["pol-1"]["source"] == "mcp_auto"
    assert store["pol-1"]["policy_violated"] == "Mass Destructive Intent"
    assert "SELECT" not in json.dumps(store) and "DROP" not in json.dumps(store)   # value-free


def test_auto_coach_respects_recurrence_threshold(tmp_path, monkeypatch):
    ov = _setup_auto(tmp_path, monkeypatch, _mcp_pairs(2))       # 2 < default 3
    monkeypatch.delenv("AGENTX_MCP_AUTO_COACH_MIN", raising=False)
    monkeypatch.delenv("AGENTX_MCP_AUTO_COACH", raising=False)   # default on
    mp.auto_coach(log=io.StringIO())
    assert _store(ov) == {}                                       # one-off never auto-promotes


def test_auto_coach_never_overwrites_human_override(tmp_path, monkeypatch):
    human = {"pol-1": {"challenge": "MY hand-written reframe", "source": "manual",
                       "policy_violated": "Mass Destructive Intent"}}
    ov = _setup_auto(tmp_path, monkeypatch, _mcp_pairs(5), overrides=human)
    mp.auto_coach(log=io.StringIO())
    store = _store(ov)
    assert store["pol-1"]["challenge"] == "MY hand-written reframe"   # human wins, untouched
    assert store["pol-1"]["source"] == "manual"


def test_auto_coach_off_switch(tmp_path, monkeypatch):
    ov = _setup_auto(tmp_path, monkeypatch, _mcp_pairs(5))
    monkeypatch.setenv("AGENTX_MCP_AUTO_COACH", "off")
    mp.auto_coach(log=io.StringIO())
    assert _store(ov) == {}


def test_auto_coach_skips_without_project_root(tmp_path, monkeypatch):
    # No .git/.agentx at the resolved root -> never scatter an overrides.json from an odd cwd.
    corpus = tmp_path / "mcp_harvest.jsonl"
    _write_pairs(corpus, _mcp_pairs(5))
    bare = tmp_path / "bare"; bare.mkdir()
    monkeypatch.setenv("AGENTX_MCP_HARVEST_PATH", str(corpus))
    monkeypatch.setenv("AGENTX_OVERRIDES", str(bare / ".agentx" / "overrides.json"))
    monkeypatch.setattr("agentx_sdk.overrides._find_project_root", lambda *a, **k: str(bare))
    mp.auto_coach(log=io.StringIO())
    assert not (bare / ".agentx" / "overrides.json").exists()


# --------------------------------------------------------------------------- #
# (B) abstraction — the value-free structural signature of a recovered call Y
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("tool, expected", [
    ("delete_file", "DELETE"),       # most-destructive-first: delete wins
    ("drop_table", "DELETE"),
    ("run_command", "EXECUTE"),
    ("send_email", "SEND"),
    ("upload_object", "SEND"),
    ("export_users", "SEND"),        # exfil verb -> SEND (not OTHER)
    ("update_record", "WRITE"),
    ("create_doc", "WRITE"),
    ("list_files", "LIST"),
    ("search_index", "LIST"),
    ("read_file", "READ"),
    ("get_user", "READ"),
    ("download_report", "READ"),     # exfil-retrieval verb -> READ (not OTHER)
    ("dump_table", "READ"),
    ("s3upload", "SEND"),            # digit-glued name still tokenizes (s|3|upload)
    ("read2files", "READ"),          # letter<->digit boundary split
    ("readFile", "READ"),            # camelCase split
    ("db.query", "READ"),            # dotted name split
    ("frobnicate", "OTHER"),         # unknown verb -> OTHER, never a guess
    ("", "OTHER"),
])
def test_target_action_is_read_off_the_tool_name(tool, expected):
    assert mp._target_action(tool) == expected


@pytest.mark.parametrize("arguments, expected", [
    ({"path": "/etc/hosts"}, "scoped"),          # narrowing KEY present
    ({"user_id": 7}, "scoped"),                  # snake_case -> token "id"
    ({"accountId": 7}, "scoped"),                # camelCase -> token "id" (same as snake)
    ({"where": "x=1", "limit": 10}, "scoped"),
    ({"to": "ops@co"}, "scoped"),                # destination-scoping key
    ({"query": "SELECT *"}, "broad"),            # payload key is NOT scoping
    ({"body": "...", "content": "..."}, "broad"),
    ({"unlimited": True}, "broad"),              # NOT a false "limit" substring hit
    ({"pathology": "x"}, "broad"),               # NOT a false "path" substring hit
    ({}, "broad"),                               # no args -> broad
    (None, "broad"),                             # non-dict -> broad
    ("just a string", "broad"),
])
def test_scope_is_read_off_arg_KEY_tokens_only(arguments, expected):
    assert mp._scope(arguments) == expected


def test_abstract_call_never_captures_a_value():
    """The signature is derived from the tool name + arg KEYS only; a secret in an arg VALUE
    (or in a value-bearing key like query/body) never enters the record."""
    sig = mp._abstract_call("fetch_rows", {"query": "SELECT token FROM secrets", "limit": 1})
    assert sig == {"target_action": "READ", "scope": "scoped"}
    blob = json.dumps(sig)
    assert "token" not in blob and "secrets" not in blob and "SELECT" not in blob


def test_abstract_call_is_best_effort_never_raises(monkeypatch):
    """Capture must never raise into the proxy session (the 'harvest never affects the run'
    invariant): a broken classifier falls back to the safe default, not an exception."""
    monkeypatch.setattr(mp, "_target_action", lambda tool: (_ for _ in ()).throw(RuntimeError("boom")))
    assert mp._abstract_call("read_file", {"id": 1}) == {"target_action": "OTHER", "scope": "broad"}


# --------------------------------------------------------------------------- #
# A1b — the org's adopted reframe reaches the keyless MCP coaching
# --------------------------------------------------------------------------- #
def test_org_reframe_is_injected_into_keyless_coaching(monkeypatch):
    """When the org has adopted a reframe for the blocked policy, the keyless MCP coaching
    carries the adopted challenge + safe-path (via the SHARED _apply_org_override the
    decorator uses), so the org brain reaches the MCP wedge. Reads only the local
    overrides store (keyless, no gateway)."""
    from agentx_sdk import decorators as dec
    reframe = {"challenge": "Use the audited soft_delete procedure for this table.",
               "safe_path": "Call soft_delete(table, where=...) instead of DROP."}
    monkeypatch.setattr(dec, "get_active_override",
                        lambda policy_id, policy_name=None, **k: reframe)

    line = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    _, client_out, _ = _route(line)
    text = json.loads(client_out)["result"]["content"][0]["text"]
    assert "audited soft_delete procedure" in text          # adopted challenge swapped in
    assert "Safe alternative:" in text                      # adopted safe-path surfaced
    assert "soft_delete(table" in text


def test_no_org_override_leaves_base_coaching_unchanged(monkeypatch):
    """No adopted override -> the base builtin coaching is delivered unchanged, so the
    cold install (the funnel target, no overrides) is unaffected by A1b."""
    from agentx_sdk import decorators as dec
    monkeypatch.setattr(dec, "get_active_override", lambda *a, **k: None)

    line = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    _, client_out, _ = _route(line)
    text = json.loads(client_out)["result"]["content"][0]["text"]
    assert "AgentX blocked this call" in text               # base wrapper, no reframe
    assert "soft_delete" not in text


# --------------------------------------------------------------------------- #
# flatten
# --------------------------------------------------------------------------- #
def test_flatten_includes_name_and_arg_values():
    flat = mp._flatten_call("delete_files", {"path": "/", "recursive": True, "count": 5})
    assert "delete_files" in flat and "/" in flat and "True" in flat and "5" in flat


def test_flatten_serializes_nested_structures():
    flat = mp._flatten_call("call", {"body": {"sql": "DROP TABLE t"}, "tags": ["a", "b"]})
    assert "DROP TABLE t" in flat and "a" in flat


# --------------------------------------------------------------------------- #
# parity with the shared keyless detector
# --------------------------------------------------------------------------- #
def test_evaluate_call_keyless_contract():
    decision = evaluate_call_keyless("DROP TABLE users;")
    assert decision is not None
    assert set(decision) == {"policy_id", "policy_name", "challenge_text",
                             "category", "preferred_alternative"}
    assert decision["challenge_text"]
    assert evaluate_call_keyless("just a friendly hello") is None
    assert evaluate_call_keyless("DROP TABLE users;", bypass_local_shield=True) is None
    assert evaluate_call_keyless("SELECT * FROM information_schema.columns") is None


# --------------------------------------------------------------------------- #
# end-to-end through a real child process
# --------------------------------------------------------------------------- #
_STUB_SERVER = r'''
import sys, json
rec = sys.argv[1] if len(sys.argv) > 1 else None
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if msg.get("method") == "tools/call" and rec:
        with open(rec, "a", encoding="utf-8") as f:
            f.write(msg["params"]["name"] + "\n")
    if msg.get("id") is not None:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
            "result": {"content": [{"type": "text", "text": "ok"}], "isError": False}}) + "\n")
        sys.stdout.flush()
'''


def test_end_to_end_dangerous_call_never_reaches_server(tmp_path):
    stub = tmp_path / "stub_server.py"
    stub.write_text(_STUB_SERVER, encoding="utf-8")
    rec = tmp_path / "received.txt"

    benign = _line(id=1, name="read_file", arguments={"path": "/data/ok.txt"})
    danger = _line(id=2, name="run_sql", arguments={"query": "DROP TABLE users;"})
    client_in = io.StringIO(benign + danger)
    client_out = io.StringIO()
    stats = {"integration": "mcp"}

    rc = mp.run_proxy([sys.executable, str(stub), str(rec)],
                      client_in=client_in, client_out=client_out,
                      session_stats=stats, log=io.StringIO())
    assert rc == 0

    received = rec.read_text(encoding="utf-8").split() if rec.exists() else []
    assert "read_file" in received            # benign call was forwarded to the server
    assert "run_sql" not in received          # dangerous call never reached the server

    # The client got an isError result for the blocked call's id.
    blocks = [json.loads(l) for l in client_out.getvalue().splitlines() if l.strip()]
    blocked = [m for m in blocks if m.get("id") == 2 and m.get("result", {}).get("isError")]
    assert blocked, "expected an isError CallToolResult for the blocked call"
    assert stats["critical_blocks"] == 1


# --------------------------------------------------------------------------- #
# Goal K — the heal-narration beat + the session-end value report
# --------------------------------------------------------------------------- #
def test_recovery_beat_is_narrated_to_the_log():
    """The block->clean recovery must not land silently in a counter: the moment it
    is counted, one stderr line tells the dev the run was saved. Dev-facing only —
    nothing about the recovery may reach the JSON-RPC client channel."""
    danger = _line(name="run_sql", arguments={"query": "DROP TABLE users;"})
    safe = _line(name="run_sql", arguments={"query": "SELECT 1"})
    child, client, log = io.StringIO(), io.StringIO(), io.StringIO()
    stats, streaks = {}, {}
    writer = mp._ClientWriter(client)
    mp._route_line(danger, child, writer, stats, streaks, 3, log)
    assert "issued a clean call" not in log.getvalue()  # a block alone is not a recovery
    mp._route_line(safe, child, writer, stats, streaks, 3, log)
    out = log.getvalue()
    assert "recovered:" in out and "run_sql" in out and "issued a clean call" in out
    assert "Task continued" not in out               # observational, not a completion claim
    assert "issued a clean call" not in client.getvalue()  # never the model's channel


def test_protection_report_prints_session_and_streak(tmp_path, monkeypatch):
    from agentx_sdk import pulse
    monkeypatch.setattr(pulse, "_PULSE_FILE", tmp_path / "pulse.json")
    monkeypatch.setattr(pulse, "is_automation_context", lambda: False)
    log = io.StringIO()
    mp._protection_report({"total_calls": 5, "critical_blocks": 2,
                           "self_corrections": 1}, log)
    out = log.getvalue()
    assert "5 call(s) screened" in out and "2 blocked" in out
    assert "1 self-corrected" in out
    assert "protection streak: 1 day(s)" in out and "1 protected session(s)" in out


def test_protection_report_silent_when_idle():
    log = io.StringIO()
    mp._protection_report({"total_calls": 0}, log)
    assert log.getvalue() == ""


def test_protection_report_streak_self_gates_in_automation(tmp_path, monkeypatch):
    """Called from a test/CI context the report may print, but the streak half
    self-gates: no streak line, no pulse.json write."""
    from agentx_sdk import pulse
    monkeypatch.setattr(pulse, "_PULSE_FILE", tmp_path / "pulse.json")
    log = io.StringIO()
    mp._protection_report({"total_calls": 3, "critical_blocks": 1,
                           "self_corrections": 0}, log)
    out = log.getvalue()
    assert "shield report" in out
    assert "protection streak" not in out
    assert not (tmp_path / "pulse.json").exists()
