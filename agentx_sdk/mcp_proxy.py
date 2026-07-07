"""
agentx_sdk/mcp_proxy.py — the ``agentx-mcp`` zero-code MCP-server wedge.

A transparent stdio JSON-RPC proxy. It wraps a real MCP server as a child process
and relays the protocol verbatim in BOTH directions, intercepting only
``tools/call`` requests. Each tool call is flattened and run through the SAME
keyless Layer-0 shield the ``@agentx_protect`` decorator uses
(``decorators.evaluate_call_keyless`` — the single shared detector, fed by the
single shared ``decorators._coerce_arg_value`` flattener, so the two paths can
never drift). A blocked call is NOT forwarded to the real server; instead the
proxy answers the client with an MCP ``CallToolResult`` carrying ``isError: true``
and a coaching message, so the calling model reads the block and self-corrects.
The run survives — that is the whole point versus a hard 403.

Keyless by design: no gateway, no API key, no third-party dependency, stdlib only
(so it stays Python >= 3.8 and language-agnostic about the server it wraps).

Wire it in one line in ``mcp.json`` (wrap the real server command)::

    "command": "agentx-mcp",
    "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]

STDOUT IS THE SACRED JSON-RPC CHANNEL. This module writes ONLY protocol messages
there, through a single lock-guarded writer; every diagnostic goes to stderr.
``main()`` aliases ``sys.stdout`` to stderr so no stray ``print`` (ours or the
SDK's) can corrupt the stream.

Known v1 scope: stdio transport only (the dominant Claude Code / Cursor case); the
keyless shield only (gateway-backed Recover over MCP is a planned follow-up).

Known limitations (deliberate for v1):
  * Child-death teardown relies on the host. When the wrapped server dies the relay
    closes the client stream (stdout EOF); a well-behaved MCP host (Claude Code /
    Cursor) then closes the proxy's stdin and we exit. A host that ignores stdout EOF
    while idle could leave the proxy parked on its stdin read with a dead child.
  * Batch requests are screened SAFELY (no blocked call is ever forwarded), but the
    response framing for a partially-blocked batch is not strict-JSON-RPC-batch
    conformant. JSON-RPC batching was removed in MCP 2025-06-18, so this only touches a
    legacy batch client.
  * The single writer lock is held across the blocking stdout write, so a host that
    stalls reading the proxy's stdout applies backpressure to both the relay and the
    block responses. That is correct (a stalled host stalls the proxy) but head-of-line.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
import uuid

# Importing the decorator module gives us the shared keyless detector + value
# flattener + breaker ceiling + block-category recorder, so the proxy and the decorator
# can't drift. CRITICAL: that import also runs agentx_sdk import-time code (e.g.
# db.init_db's one-time legacy-schema migration notice) that may PRINT to stdout, which
# for THIS process is the sacred JSON-RPC channel, and the import runs before main() can
# alias stdout. Redirect stdout to stderr just for the duration of the import (a LOCAL
# save/restore, not a global alias, so importing this module under pytest leaves stdout
# untouched) so no import-time print can corrupt the stream.
_real_stdout = sys.stdout
sys.stdout = sys.stderr
try:
    from agentx_sdk.decorators import (
        _BLOCK_CATEGORY_VOCAB,
        _apply_org_override,
        _coerce_arg_value,
        _max_cognitive_turns,
        _name_tokens,
        _note_block_category,
        _resolve_enforcement,
        evaluate_call_keyless,
    )
    # Bound at module load, under the same stdout guard, so the atexit _protection_report
    # never does a shutdown-time `from agentx_sdk import pulse` (import machinery can be
    # torn down at interpreter exit).
    from agentx_sdk import pulse
    # The local flight-recorder ledger (the SAME SQLite store the decorator writes and
    # `agentx status` reads), so a real MCP catch shows up in `agentx status` — not just
    # the streak. Best-effort at the call sites; gated on session_stats["_ledger"] so the
    # routing-core unit tests (which build a bare session_stats) never touch the ledger.
    from agentx_sdk.db import init_db, log_intercept, log_self_correction, WOULD_BLOCK_STATUS
finally:
    sys.stdout = _real_stdout

_USAGE = (
    "usage: agentx-mcp <command> [args...]\n"
    "\n"
    "Wrap a real MCP server so every tools/call is screened by AgentX's keyless\n"
    "shield before it runs. A blocked call is returned to the agent as a coaching\n"
    "error it can self-correct on; the dangerous call never reaches the server.\n"
    "\n"
    "  example (mcp.json):\n"
    "    \"command\": \"agentx-mcp\",\n"
    "    \"args\": [\"npx\", \"-y\", \"@modelcontextprotocol/server-filesystem\", \"/data\"]\n"
)


def _flatten_call(name, arguments):
    """Flatten an MCP ``tools/call`` into the payload string the shared keyword shield
    scans. Reuses ``decorators._coerce_arg_value`` for the argument VALUES so the proxy
    and the decorator coerce identically (no drift). One intentional difference: we
    prepend the tool NAME, because the keyless MCP path has no separate ``action``
    channel (the decorator routes the function name to the gateway's structured
    ``action`` instead), so the name is the proxy's only place to catch a destructive
    verb that lives in the tool name itself."""
    parts = []
    if name:
        parts.append(str(name))
    values = arguments.values() if isinstance(arguments, dict) else (arguments,)
    for value in values:
        coerced = _coerce_arg_value(value)
        if coerced is not None:
            parts.append(coerced)
    return " ".join(parts)


def _coaching_text(decision, tripped, tool_name=None):
    """The agent-facing block message. Written for the CALLER'S own model to self-correct
    on (no judge ever reads this), so it leads with the issue and the safe next step and
    stays call-specific: it names the tool that was blocked and, when the policy carries
    one, the concrete safe alternative (challenge-quality lever: task-fitting > generic).
    No em dashes (house style); this text can end up in a shared block card."""
    challenge = decision.get("challenge_text") or "Revise the action to comply with security policy."
    if challenge and challenge.rstrip()[-1:] not in ".!?":
        challenge = challenge.rstrip() + "."   # pulled-policy text may lack end punctuation; avoid a run-on
    safe = decision.get("preferred_alternative")
    on_tool = " on '%s'" % tool_name if tool_name else ""
    safe_hint = " Safe alternative: %s" % safe if safe else ""
    if tripped:
        return (
            "AgentX circuit breaker: this call%s was blocked repeatedly and has been "
            "halted to stop a runaway loop. Do not retry the same action. %s%s "
            "If you cannot reach the goal safely, ask the human operator."
            % (on_tool, challenge, safe_hint)
        )
    return (
        "AgentX blocked this call%s before it ran. %s%s Revise to a safe form and try "
        "again, or ask the human operator if you cannot reach the goal safely."
        % (on_tool, challenge, safe_hint)
    )


def _block_response(req_id, text):
    """An MCP ``CallToolResult`` with ``isError: true``. The calling model sees the
    tool 'fail' with this coaching text and can self-correct — the run survives."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


def _harvest_enabled():
    """(B) recovery-pair harvest is OPT-IN: OFF unless AGENTX_MCP_HARVEST is truthy, so a
    default / cold install captures NOTHING."""
    return os.environ.get("AGENTX_MCP_HARVEST", "").strip().lower() in ("1", "true", "yes", "on")


def _call_ceiling():
    """Session tools/call ceiling — the keyless runaway-loop guard for the cost-explosion
    class over MCP (AFDB #17/#23/#55, which the gateway budget floor owns for the decorator
    but has no keyless signal here). The proxy cannot meter LLM tokens (it never sees usage),
    so it uses tool-call VOLUME as the proxy: once a session crosses the ceiling, every
    further tools/call is halted with coaching. It catches the payload-VARYING runaway loop
    that the per-tool circuit breaker (identical payloads only) evades — the same 'the signal
    is the cumulative total, not any single call' shape as the budget ceiling.

    DEFAULT 0 = DISABLED (opt-in). A legitimate long agent session can make many tool calls,
    so a default-on halt would risk breaking a real run — the MCP wedge's whole value — which
    is why it is off unless an operator arms it (AGENTX_MCP_CALL_CEILING, e.g. 500 for a
    generous runaway bound). Clamped >= 0; an unparseable value disables it."""
    try:
        return max(0, int(os.environ.get("AGENTX_MCP_CALL_CEILING", "0")))
    except (TypeError, ValueError):
        return 0


# The structural-signature vocab for a recovered call Y (designs/mcp-corpus-intake.md (B),
# open decision #2 ratified 2026-06-30). Keyless MCP has NO judge to label a call, so the
# signature is a LOCAL, coarse heuristic: target_action is read off the tool NAME (word tokens
# via the shared _name_tokens), scope off the ARG-KEY shape. NEITHER ever inspects an argument
# VALUE, so no raw payload can enter the record (moat-collection-day0: never raw query / CoT /
# args). NOTE: this is a SEPARATE keyless action vocab -- it does NOT match the gateway's
# rule-shape target_action values (execute_database_query / fetch_url / send_message / ...), so
# generalizing a harvested pair into a shared gateway rule needs a CROSSWALK, not a direct join
# (see the design doc). The vocab is CLOSED (the value is always one of these tokens).
_ACTION_KEYWORDS = (   # first match wins; ordered most-destructive-first (a "delete_and_log"
                       # tool classifies as DELETE, not WRITE/READ)
    ("DELETE",  ("delete", "drop", "remove", "destroy", "truncate", "purge", "wipe")),
    ("EXECUTE", ("exec", "run", "shell", "command", "spawn", "eval", "invoke")),
    ("SEND",    ("send", "post", "upload", "email", "publish", "notify", "transfer", "push", "export")),
    ("WRITE",   ("write", "update", "insert", "put", "create", "save", "edit", "modify", "patch", "append", "upsert", "set")),
    ("LIST",    ("list", "search", "find", "browse", "scan", "enumerate", "glob")),
    ("READ",    ("read", "get", "query", "select", "fetch", "load", "view", "show", "retrieve", "describe", "cat", "download", "dump")),
)

# Arg-key WORD TOKENS that NARROW the blast radius -> the recovered call looks "scoped". Matched
# as whole tokens from the SAME _name_tokens split as the tool name (so camelCase accountId and
# snake_case account_id both surface the "id" token), never as raw substrings (so "unlimited" /
# "pathology" are not false "limit" / "path" hits). A bare payload key (query/body/content/data)
# is deliberately absent: carrying a query is not the same as scoping it. We test only KEY tokens,
# never store the key, never read the value.
_NARROWING_TOKENS = frozenset((
    "id", "ids", "key", "keys", "where", "filter", "limit", "scope", "path",
    "name", "prefix", "since", "after", "before", "page", "cursor", "offset",
    "top", "first", "target", "recipient", "to", "dest", "destination", "channel",
))


def _target_action(tool):
    """Coarse action class read off the tool NAME only (never a value), by exact word token
    (shared _name_tokens). Closed vocab; OTHER when nothing matches."""
    toks = set(_name_tokens(tool))
    for action, keys in _ACTION_KEYWORDS:
        if toks.intersection(keys):
            return action
    return "OTHER"


def _scope(arguments):
    """Coarse blast-radius shape read off the ARG-KEY names only (never a value): 'scoped' if any
    key carries a narrowing/target WORD TOKEN, else 'broad'. Named 'scope' (NOT effect_*) so it
    does not collide with the gateway's effect_category threat taxonomy. It is the structural
    signal for WHY the recovered call was safe (it narrowed the action), beyond the bare category.
    Coarse + value-free: it sees a narrowing KEY is present, never that a value targets everything."""
    if not isinstance(arguments, dict) or not arguments:
        return "broad"
    for raw in arguments.keys():
        if _NARROWING_TOKENS.intersection(_name_tokens(str(raw))):
            return "scoped"
    return "broad"


def _abstract_call(tool, arguments):
    """The structural signature of a recovered call Y: ``{target_action, scope}``. Purely
    structural + closed-vocab; inspects ONLY the tool name and the arg-KEY names, NEVER an
    argument value (moat-collection-day0). A coarse local heuristic, not a judge verdict. Total
    best-effort: any unexpected input falls back to the safe default so harvest CAPTURE can never
    raise into the proxy session (upholding the _flush_harvest 'never affect the run' invariant,
    which the widened capture would otherwise weaken vs the old pure-append)."""
    try:
        return {"target_action": _target_action(tool), "scope": _scope(arguments)}
    except Exception:
        return {"target_action": "OTHER", "scope": "broad"}


class _Harvest:
    """Opt-in, tenant-private, LOCAL-ONLY capture of keyless recovery pairs
    (designs/mcp-corpus-intake.md (B) — the SAFE-DEFAULT skeleton).

    On a block it remembers ONLY {tool, policy_category}: policy_category is the closed pulse
    vocab (validated), and tool is the SERVER-DEFINED tool identifier (NOT a vetted enum, so it
    is kept LOCAL and never transmitted). It NEVER stores raw args / query / chain-of-thought.
    On a later clean call to the SAME tool it forms a recovery-pair candidate carrying the
    block's category AND the recovered call's structural signature (_abstract_call: closed-vocab
    target_action + scope, derived from the tool name and arg-KEY shape only, never a value),
    written at session end to a LOCAL tenant-private file that NEVER crosses the network.

    FOUNDER RATIFICATION: (1) the abstraction RICHNESS is ratified (design-doc open decision #2,
    2026-06-30) -- a coarse STRUCTURAL signature of the recovered call, never a raw payload;
    implemented locally here. STILL founder-gated: how to sanitize the server-defined tool name
    (raw / hashed / dropped) before any NETWORK sink (it stays raw in this local file -- the org's
    own data), and (2) there is NO network sink and no Discovery/adopt-queue integration
    (moat-collection-day0, founder-gated)."""

    def __init__(self):
        self._pending = {}     # tool -> {policy_category, policy_name, policy_id} (abstract only)
        self.pairs = []        # recovery-pair candidates: {tool, policy_category, policy_name?,
                               # policy_id?, <signature>, recovered}

    def note_block(self, tool, category, policy_name=None, policy_id=None):
        # Record the coarse category (closed pulse vocab) PLUS the policy identity that fired.
        # policy_name / policy_id are FLOOR identifiers (our own closed-set labels, e.g. "Mass
        # Destructive Intent" / a floor UUID), NOT user data -- so they stay value-free (privacy
        # test asserts no arg/query leak) while giving `agentx adopt` a key that A1b can match on
        # the NEXT block (exact policy_id, else the cross-path policy_name). An off-vocab OR
        # non-string category (a malformed pulled policy) is dropped AND clears any stale pending
        # entry, so a later recovery is never mis-attributed, and a non-string can't raise on `in`.
        if isinstance(category, str) and category in _BLOCK_CATEGORY_VOCAB:
            self._pending[tool] = {
                "policy_category": category,
                "policy_name": policy_name if isinstance(policy_name, str) and policy_name else None,
                "policy_id": policy_id if isinstance(policy_id, str) and policy_id else None,
            }
        else:
            self._pending.pop(tool, None)

    def note_recovery(self, tool, arguments=None):
        # The recovered call's structural signature (closed-vocab, value-free) makes the pair a
        # USEFUL reframe ("for category C on tool T, the safe path was a scoped READ"), not just
        # "something recovered". arguments may be None when the caller has no args to abstract.
        pend = self._pending.pop(tool, None)
        if pend:
            pair = {"tool": tool, "policy_category": pend["policy_category"]}
            # Only carry the identity keys when present, so a pair stays minimal (and older
            # readers that don't expect them are unaffected).
            if pend.get("policy_name"):
                pair["policy_name"] = pend["policy_name"]
            if pend.get("policy_id"):
                pair["policy_id"] = pend["policy_id"]
            pair.update(_abstract_call(tool, arguments))
            pair["recovered"] = True
            self.pairs.append(pair)


def _harvest_path():
    """Where the local recovery-pair file lives. An explicit AGENTX_MCP_HARVEST_PATH wins (the
    opt-in user controls it — RECOMMENDED for MCP hosts, which launch the proxy from an unrelated
    cwd, often $HOME or /); otherwise it sits in .agentx/ under the project root, beside the
    overrides store. NB: launched outside a project (no .git/.agentx) the root falls back to cwd,
    so the explicit path is preferred in the MCP execution context."""
    explicit = os.environ.get("AGENTX_MCP_HARVEST_PATH")
    if explicit:
        return explicit
    from agentx_sdk.overrides import _find_project_root
    return os.path.join(_find_project_root(), ".agentx", "mcp_harvest.jsonl")


def _flush_harvest(harvest, log):
    """Append the session's recovery-pair candidates to a LOCAL tenant-private JSONL (see
    _harvest_path). LOCAL ONLY — it never crosses the network. The record is exactly the abstract
    pair {tool, policy_category, target_action, scope, recovered} (NO wall-clock timestamp, which
    would be deanonymizing once a sink ships). Best-effort: any error is swallowed so harvest can
    never affect the proxy or the run."""
    if not harvest or not harvest.pairs:
        return
    try:
        path = _harvest_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            for pair in harvest.pairs:
                f.write(json.dumps(pair) + "\n")
        print("[agentx-mcp] harvested %d local recovery-pair candidate(s) -> %s"
              % (len(harvest.pairs), path), file=log)
    except Exception as err:
        print("[agentx-mcp] harvest flush skipped: %s" % err, file=log)


# --------------------------------------------------------------------------- #
# (B) READ side — make the local recovery corpus LEGIBLE.
#
# The write side (above) is deliberately fire-and-forget: it appends abstract pairs
# and never reads them back, so until now the corpus was write-only and INVISIBLE.
# These two functions are the inverse of that contract (they own the same JSONL
# schema) so the org can SEE the recovery brain it is accumulating -- the honest
# alternative to defending recover by secrecy (designs/mcp-corpus-intake.md (B)).
# READ-ONLY and LOCAL: no promotion into coaching, no network sink (both still
# founder-gated). Total best-effort, like the write side -- inspection must never
# raise.
# --------------------------------------------------------------------------- #
def read_harvest_pairs(path=None, log=None):
    """Read the local recovery-pair candidates written by ``_flush_harvest``.

    Returns a list of pair dicts (the exact abstract records on disk), or ``[]``
    when the file is absent / empty. Best-effort by construction: a blank or
    malformed line is skipped (a hand-edit or a partial append must not sink the
    whole view), and any I/O error degrades to ``[]`` rather than raising. Honors
    ``AGENTX_MCP_HARVEST_PATH`` then the project-root ``.agentx/`` default, via the
    same ``_harvest_path`` the writer uses so read and write can't disagree."""
    log = log or sys.stderr
    p = path or _harvest_path()
    if not os.path.exists(p):
        return []
    pairs = []
    try:
        # errors="replace" mirrors the child-stdout reader: a stray non-UTF-8 byte
        # (a truncated multibyte write, a concurrent append, a hand-edit) must not raise
        # in `for line in f`; the mangled line then fails json.loads and is skipped,
        # so one bad byte costs its own line, never the whole corpus view.
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (ValueError, TypeError):
                    continue                       # a malformed line is skipped, never fatal
                if isinstance(rec, dict):
                    pairs.append(rec)
    except Exception as err:
        # Broad backstop (matches _flush_harvest / _abstract_call): inspection must
        # NEVER raise. errors="replace" above already neutralizes decode errors, so this
        # mainly catches OSError (a mid-read I/O failure, a path that turned into a dir);
        # anything unexpected still degrades to [] rather than crashing the CLI.
        print("[agentx-mcp] could not read harvest file %s: %s" % (p, err), file=log)
        return []
    return pairs


# Minimal-privilege coaching templated from the value-free signature. Oracle guardrail
# (mcp-keyless-recover-strategy): point toward LESS capability -- scope it down, drop the
# destructive step -- NEVER name a lateral tool/action (that maps the covered set). Closed-vocab
# in, so NO agent free-text becomes a challenge (anti-poisoning): safe to surface for adoption.
_ACTION_NARROW_HINT = {
    "DELETE":  "read or archive instead of deleting, and never remove without a scoped target",
    "EXECUTE": "run the narrowest read-only step instead of a broad command",
    "SEND":    "scope the recipient and payload instead of a broad send or export",
    "WRITE":   "add a WHERE/filter and touch only the target row instead of an unscoped write",
    "LIST":    "filter or prefix the listing instead of enumerating everything",
    "READ":    "add an id/filter/limit instead of selecting everything",
    "OTHER":   "narrow the action to the minimum needed and drop any destructive step",
}


def _recovery_challenge(policy_name, target_action, scope):
    """A value-free, minimal-privilege reframe templated from a recovery signature -- the
    coaching an adopted MCP-recovery candidate delivers on the next block. Points toward LESS
    capability (the oracle-safe gradient), never a lateral alternative."""
    hint = _ACTION_NARROW_HINT.get(target_action, _ACTION_NARROW_HINT["OTHER"])
    label = policy_name or "this policy"
    if scope == "scoped":
        return ("Your agents recovered from '%s' before by NARROWING the action (a scoped %s). "
                "Do the same: %s, then retry." % (label, target_action, hint))
    return ("Your agents hit '%s' here before. Reach the goal with less capability: %s, then retry."
            % (label, hint))


def mcp_recovery_candidates(path=None, log=None):
    """Project the local MCP recovery corpus into per-policy ADOPT candidates for the org-brain
    loop (`agentx mcp-insights` / `agentx adopt`) -- the wiring that turns the silently-harvested
    pairs into better recover, instead of a corpus nothing consumes.

    Groups the harvested pairs by the policy identity captured at block time, ranks each policy's
    value-free signatures by recurrence, and templates a minimal-privilege challenge from each.
    ONLY pairs carrying a policy identity (policy_id or policy_name) are adoptable -- an override
    must key to the exact policy the next block matches, so older pre-identity pairs are skipped
    here (they still count in the corpus, just aren't adoptable). Never raises.

    Returns ``{key: {"policy_id", "policy_violated", "candidates": [{"suggestion", "safe_path",
    "count", "resolution_type", "tool", "target_action", "scope"}]}}`` -- the same candidate
    shape the reframe/rule harvests use, so it drops straight into the shared adopt flow. ``key``
    is the override key (policy_id when present, else policy_name)."""
    grouped = {}
    for pair in read_harvest_pairs(path, log):
        if not isinstance(pair, dict):
            continue
        pid = pair.get("policy_id") if isinstance(pair.get("policy_id"), str) else None
        name = pair.get("policy_name") if isinstance(pair.get("policy_name"), str) else None
        key = pid or name
        if not key:
            continue                                  # pre-identity pair: not adoptable
        action = str(pair.get("target_action") or "OTHER")
        scope = str(pair.get("scope") or "broad")
        tool = str(pair.get("tool") or "?")
        bucket = grouped.setdefault(key, {"policy_id": pid or name,
                                          "policy_violated": name, "_sigs": {}})
        if name and not bucket.get("policy_violated"):
            bucket["policy_violated"] = name
        sig = bucket["_sigs"].setdefault((action, scope, tool),
                                         {"tool": tool, "target_action": action,
                                          "scope": scope, "count": 0})
        sig["count"] += 1

    out = {}
    for key, bucket in grouped.items():
        sigs = sorted(bucket["_sigs"].values(),
                      key=lambda s: (-s["count"], s["tool"], s["target_action"], s["scope"]))
        out[key] = {
            "policy_id": bucket["policy_id"],
            "policy_violated": bucket.get("policy_violated"),
            "candidates": [{
                "suggestion": _recovery_challenge(bucket.get("policy_violated"),
                                                  s["target_action"], s["scope"]),
                "safe_path": None,
                "count": s["count"],
                "resolution_type": "mcp_recovery",
                "tool": s["tool"], "target_action": s["target_action"], "scope": s["scope"],
            } for s in sigs],
        }
    return out


def _auto_coach_enabled():
    """Auto-coach is default ON (the moat should compound silently). One explicit off wins:
    AGENTX_MCP_AUTO_COACH in {0,false,no,off}."""
    return os.environ.get("AGENTX_MCP_AUTO_COACH", "on").strip().lower() not in ("0", "false", "no", "off")


def _auto_coach_min():
    """Recurrence gate: a signature must recur this many times before it auto-promotes, so a
    one-off (or an over-attributed pair) never becomes live coaching. Default 3."""
    try:
        return max(1, int(os.environ.get("AGENTX_MCP_AUTO_COACH_MIN", "3")))
    except (TypeError, ValueError):
        return 3


def auto_coach(path=None, log=None):
    """Auto-promote the strongest local MCP recovery paths into the org-brain so recover
    compounds WITHOUT a manual step -- the "auto" half of auto-with-override (founder-ratified).

    SAFE BY CONSTRUCTION:
      * value-free, minimal-privilege reframe (never lateral) -> a wrong signal still coaches safe;
      * recurrence-gated (>= AGENTX_MCP_AUTO_COACH_MIN, default 3) -> one-offs never promote;
      * writes source='mcp_auto' ONLY when a real project root resolves (has .git/.agentx), so an
        MCP host launched from an odd cwd ($HOME, /) never scatters an overrides.json;
      * a HUMAN-authored override always WINS -- an existing non-'mcp_auto' entry is never touched
        (hand-adopt beats auto), and an unchanged auto entry is left alone (no churn);
      * AGENTX_MCP_AUTO_COACH=off disables it entirely.
    Best-effort: any error is swallowed so it can never affect the proxy or the run."""
    log = log or sys.stderr
    if not _auto_coach_enabled():
        return
    try:
        from agentx_sdk.overrides import _find_project_root, load_overrides, adopt as adopt_override
        root = _find_project_root()
        if not (os.path.isdir(os.path.join(root, ".git")) or os.path.isdir(os.path.join(root, ".agentx"))):
            return                                     # no real project root -> don't scatter files
        candidates = mcp_recovery_candidates(path, log)
        if not candidates:
            return
        active = load_overrides().get("overrides", {})
        threshold = _auto_coach_min()
        promoted = 0
        for key, bucket in candidates.items():
            cands = bucket.get("candidates") or []
            top = cands[0] if cands else None
            if not top or top.get("count", 0) < threshold:
                continue                               # recurrence gate
            existing = active.get(key)
            if existing and existing.get("source") != "mcp_auto":
                continue                               # human-authored wins; never overwrite it
            if existing and existing.get("challenge") == top["suggestion"]:
                continue                               # identical auto entry already live; no churn
            adopt_override(bucket["policy_id"], challenge=top["suggestion"],
                           safe_path=top.get("safe_path"), resolution_type="mcp_recovery",
                           policy_violated=bucket.get("policy_violated"), source="mcp_auto")
            promoted += 1
        if promoted:
            print("[agentx-mcp] auto-coach promoted %d recovery path(s) into the org-brain "
                  "(source=mcp_auto; `agentx mcp-insights` to review, AGENTX_MCP_AUTO_COACH=off "
                  "to stop)." % promoted, file=log)
    except Exception as err:
        print("[agentx-mcp] auto-coach skipped: %s" % err, file=log)


# --------------------------------------------------------------------------- #
# MCP tool-description DRIFT / bait-and-switch detection (detector A + B).
#
# A NEW inspection direction. The tools/call screen watches the agent's OUTBOUND
# actions; this watches the SERVER's advertised capabilities -- the tools/list
# RESULT (server->client) the relay otherwise byte-pumps untouched. It answers the
# NSA-cited WhatsApp MCP exploit: a server advertises a benign tool at install (the
# human approves it once), then silently rewrites the tool description/schema on a
# later use to steer the agent.
#   * Detector A (drift): trust-on-first-use fingerprint of each tool's
#     {name,description,inputSchema}; a later change of an already-pinned tool is
#     the rug-pull. Persistent (.agentx/mcp_tool_pins.json) so it survives the
#     install-now / weaponize-next-launch gap.
#   * Detector B (poison): on FIRST sight of a tool, run its description through the
#     SAME keyless shield so an install-time-poisoned description (hidden
#     instructions / invisible-unicode carrier) is caught before the agent reads it
#     (TOFU alone cannot -- there is no "before" to diff).
# Keyless, zero-LLM (a sha256 compare + the existing shield), SDK-only: no gateway
# floor, no failure_mode enum, no migration. Mode via AGENTX_MCP_TOOL_PINNING
# {warn (default) | block | off}. TOTAL best-effort: every function swallows its
# own errors so an inspection failure can NEVER raise into the relay byte-pump
# (the same never-raise contract as _Harvest).
# --------------------------------------------------------------------------- #
def _tool_pinning_mode():
    """AGENTX_MCP_TOOL_PINNING in {warn (default), block, off}. warn = advisory
    (stderr + local ledger, never breaks a run); block = additionally gate a
    tools/call to a drifted tool; off = inert, byte-identical to today. An unknown
    value falls back to warn (the safe, non-breaking default)."""
    mode = os.environ.get("AGENTX_MCP_TOOL_PINNING", "warn").strip().lower()
    return mode if mode in ("warn", "block", "off") else "warn"


def _pins_path():
    """Where the persistent tool-fingerprint manifest lives. An explicit
    AGENTX_MCP_PINS_PATH wins (RECOMMENDED for MCP hosts, which launch the proxy
    from an unrelated cwd -- often $HOME or / -- the same gotcha _harvest_path
    documents); otherwise .agentx/mcp_tool_pins.json under the project root, beside
    the overrides + harvest stores."""
    explicit = os.environ.get("AGENTX_MCP_PINS_PATH")
    if explicit:
        return explicit
    from agentx_sdk.overrides import _find_project_root
    return os.path.join(_find_project_root(), ".agentx", "mcp_tool_pins.json")


def _server_key(child_cmd):
    """A stable id for the wrapped server = a short sha256 of its argv. A server
    invoked with different args pins separately -- a different launch is arguably a
    different trust context (design section 5)."""
    try:
        argv = " ".join(str(a) for a in (child_cmd or ()))
    except Exception:
        argv = ""
    return hashlib.sha256(argv.encode("utf-8", "replace")).hexdigest()[:16]


def _tool_fingerprint(tool):
    """sha256 over the canonical {name, description, inputSchema} of one advertised
    tool. Spans description AND inputSchema because a widened schema (a suddenly
    accepted `path`/`command` param) is as much an attack surface as a reworded
    description (design section 3b)."""
    canon = json.dumps(
        {"name": tool.get("name"),
         "description": tool.get("description"),
         "inputSchema": tool.get("inputSchema")},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str,
    )
    return hashlib.sha256(canon.encode("utf-8", "replace")).hexdigest()


def _description_poisoned(tool):
    """Run the tool's advertised description through the SAME keyless shield the
    tools/call path uses; a truthy decision means the description itself carries a
    dangerous payload (injection / invisible-unicode carrier) -- install-time
    poison (B). Best-effort: never raises."""
    try:
        desc = tool.get("description")
        if not isinstance(desc, str) or not desc:
            return False
        return bool(evaluate_call_keyless(desc))
    except Exception:
        return False


class _ToolPins:
    """Persistent, tenant-private tool-fingerprint manifest + drift/poison detector.

    Mirrors _Harvest's best-effort, never-raise contract: every method swallows its
    own errors so an inspection failure can never wedge the relay. The manifest is a
    LOCAL file that NEVER crosses the network. Shape: {server_key: {tool: fp}}."""

    def __init__(self, path=None):
        self._path = path or _pins_path()
        self._manifest = self._load()

    def _load(self):
        try:
            if not os.path.exists(self._path):
                return {}
            with open(self._path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _persist(self):
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._manifest, f)
        except Exception:
            pass

    def inspect(self, server_key, tools):
        """Compare a fresh tools/list result against the pinned manifest. Returns a
        list of (kind, tool_name) with kind in {'drift','poison'}. Records new
        fingerprints (TOFU) and persists. A brand-new tool is recorded, not drift.
        Never raises."""
        events = []
        try:
            if not isinstance(tools, list):
                return events
            pinned = self._manifest.get(server_key)
            first_sight = not isinstance(pinned, dict)
            pinned = dict(pinned) if isinstance(pinned, dict) else {}
            changed = False
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                name = tool.get("name")
                if not isinstance(name, str) or not name:
                    continue
                fp = _tool_fingerprint(tool)
                if name not in pinned:
                    # First sight of this tool -> content-scan for install poison (B),
                    # then pin. TOFU: a benign first listing is recorded silently.
                    if _description_poisoned(tool):
                        events.append(("poison", name))
                elif pinned.get(name) != fp:
                    # An already-approved tool changed its definition -> drift (A).
                    events.append(("drift", name))
                if pinned.get(name) != fp:
                    pinned[name] = fp
                    changed = True
            if changed or first_sight:
                self._manifest[server_key] = pinned
                self._persist()
        except Exception:
            return events
        return events


def _drift_coaching(tool_name):
    """Agent-facing re-verify coaching for block mode (no em dashes; house style)."""
    return ("AgentX blocked '%s': this tool's definition (description or input schema) "
            "changed since it was approved, a possible bait-and-switch. Re-verify the "
            "tool with the human operator before using it." % tool_name)


def _report_pin_events(events, mode, drifted, session_stats, log):
    """Surface drift/poison events: a loud stderr warning (warn AND block), a local
    flight-recorder row so `agentx status` attributes it to 'MCP Tool Description
    Drift', and -- in block mode -- add the tool to the drifted set so a later
    tools/call to it is gated. Never raises."""
    for kind, name in events:
        try:
            if kind == "drift":
                print("[agentx-mcp] WARNING: tool '%s' changed its description/schema since you "
                      "approved it, possible rug-pull (MCP Tool Description Drift)." % name, file=log)
            else:
                print("[agentx-mcp] WARNING: tool '%s' advertises a description carrying a possible "
                      "injection/hidden-instruction payload (MCP Tool Description Drift)." % name,
                      file=log)
            if session_stats.get("_ledger"):
                try:
                    # A uuid trace, NOT the shared _ledger_seq counter: this runs on the
                    # relay thread while the tools/call block path increments _ledger_seq
                    # on the main thread, so a shared read-modify-write would race. Drift
                    # rows never recover, so a unique id suffices (no monotonic counter).
                    trace = "%s-drift-%s" % (session_stats.get("_trace_id") or "mcp-session",
                                             uuid.uuid4().hex[:8])
                    log_intercept(trace, "mcp_proxy", name, None,
                                  "MCP Tool Description Drift", "CHALLENGED")
                except Exception:
                    pass
            if mode == "block" and drifted is not None:
                drifted.add(name)
        except Exception:
            continue


def _inspect_list_line(line, pins, pending_list_ids, server_key, mode, drifted, session_stats, log):
    """Guarded, best-effort server->client inspection of a tools/list RESULT, called
    just before the verbatim relay. It only READS the line and NEVER raises, so any
    failure just means the line relays untouched exactly as today. The hot path
    stays a byte pump: we JSON-parse ONLY a line that looks like a list response
    (carries "tools" + "id") AND whose id we correlated to a tools/list request;
    the bulk tool-output traffic is never parsed."""
    try:
        s = line.strip()
        if not s or s[0] != "{" or '"tools"' not in s or '"id"' not in s:
            return
        msg = json.loads(s)
        if not isinstance(msg, dict):
            return
        mid = msg.get("id")
        if mid is None or mid not in pending_list_ids:
            return
        pending_list_ids.discard(mid)
        result = msg.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return
        events = pins.inspect(server_key, tools)
        if events:
            _report_pin_events(events, mode, drifted, session_stats, log)
    except Exception:
        return


class _ClientWriter:
    """Serializes every write to the client's stdout (the sacred JSON-RPC channel).

    Two producers write here — the main routing thread (synthetic block responses)
    and the server->client pump thread (relayed server lines) — so each write+flush
    holds one lock to stop torn/interleaved lines. A per-write guard keeps a single
    failed line (e.g. a transient encode error) from silently killing the whole relay.
    Also owns close, used to propagate the child's death to the client as stream EOF."""

    def __init__(self, stream):
        self._stream = stream
        self._lock = threading.Lock()
        self._closed = False

    def send(self, obj):
        self._write(json.dumps(obj) + "\n")

    def relay(self, line):
        self._write(line)

    def _write(self, text):
        with self._lock:
            if self._closed:
                return
            try:
                self._stream.write(text)
                self._stream.flush()
            except Exception as err:
                # One bad line must never silently kill the relay / wedge the session.
                print("[agentx-mcp] client write failed: %s" % err, file=sys.stderr)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._stream.close()
            except Exception:
                pass


def _forward(line, child_in):
    """Relay the client's line to the real server VERBATIM (never re-serialized, so
    framing/whitespace is byte-preserved)."""
    child_in.write(line)
    child_in.flush()


def _screen_message(msg, session_stats, streaks, max_turns, writer, log, harvest=None):
    """Screen ONE parsed JSON-RPC message. Returns ``"forward"`` (the caller relays it
    to the server) or ``"block"`` (a blocked tools/call, already handled — do NOT
    forward). Side effects on a block: emit the isError response (only if the call had
    an id) and bump the counters. Fail-open: any evaluation error returns ``"forward"``
    so the proxy can never wedge the protocol."""
    if not (isinstance(msg, dict) and msg.get("method") == "tools/call"):
        return "forward"

    session_stats["total_calls"] = session_stats.get("total_calls", 0) + 1

    # Keyless runaway-loop ceiling (AFDB #17/#23/#55 over MCP): once this session's tool-call
    # VOLUME crosses the operator ceiling, halt every further call with coaching — the runaway
    # is the volume, not any single call, so this catches the payload-varying cost loop the
    # per-tool breaker (identical payloads only) evades. Opt-in: absent/0 ceiling is a no-op, so
    # a cold install is byte-identical to today. Placed BEFORE the shield so a runaway is halted
    # whether or not this particular call is otherwise clean. Never raises.
    ceiling = session_stats.get("_call_ceiling", 0)
    if ceiling and session_stats["total_calls"] > ceiling:
        req_id = msg.get("id")
        text = ("AgentX halted this session: it has made %d tool calls, past the configured "
                "ceiling of %d, a likely runaway loop burning budget. Stop retrying the task and "
                "ask the human operator before continuing."
                % (session_stats["total_calls"], ceiling))
        if req_id is not None:
            writer.send(_block_response(req_id, text))
        else:
            print("[agentx-mcp] dropped id-less tools/call past the runaway ceiling", file=log)
        session_stats["intercepts"] = session_stats.get("intercepts", 0) + 1
        session_stats["critical_blocks"] = session_stats.get("critical_blocks", 0) + 1
        print("[agentx-mcp] blocked tools/call (runaway ceiling %d exceeded at %d calls)."
              % (ceiling, session_stats["total_calls"]), file=log)
        return "block"

    # block-mode drift gate: a tools/call to a tool whose advertised definition
    # drifted is stopped with re-verify coaching BEFORE the shield runs -- the
    # malice is in the changed definition, not necessarily this call. The drifted
    # set is populated by the relay thread (best-effort cross-thread read; a race
    # only delays the gate by one call, acceptable for an advisory check). No-op
    # unless block mode flagged this tool. Never raises.
    try:
        if session_stats.get("_pin_mode") == "block":
            drifted = session_stats.get("_drifted")
            gate_name = str((msg.get("params") or {}).get("name"))
            if drifted and gate_name in drifted:
                req_id = msg.get("id")
                if req_id is not None:
                    writer.send(_block_response(req_id, _drift_coaching(gate_name)))
                else:
                    print("[agentx-mcp] dropped id-less call to drifted tool '%s'" % gate_name, file=log)
                session_stats["intercepts"] = session_stats.get("intercepts", 0) + 1
                session_stats["critical_blocks"] = session_stats.get("critical_blocks", 0) + 1
                print("[agentx-mcp] blocked tools/call '%s' (MCP Tool Description Drift; re-verify required)."
                      % gate_name, file=log)
                return "block"
    except Exception:
        pass

    try:
        params = msg.get("params") or {}
        name = params.get("name")
        decision = evaluate_call_keyless(_flatten_call(name, params.get("arguments")))
    except Exception as err:
        print("[agentx-mcp] shield bypassed (fail-open): %s" % err, file=log)
        return "forward"

    tool_key = str(name)
    if not decision:
        # A clean call zeroes this tool's block streak. If that streak was non-zero, this
        # SAME tool was blocked earlier and now runs safe: a rough proxy for "the agent
        # recovered on the coaching", so count it on the pulse. This is a HEURISTIC keyed
        # by tool name (the keyless proxy has no per-call trace) so it can over-attribute
        # (a later unrelated clean call on a tool that was once blocked) and under-count
        # cross-tool recoveries; it is therefore NOT identical to the decorator's
        # trace-keyed _credit_recovery (which bounds recovered <= challenged). Counts-only
        # / advisory: harvest-IN (designs/mcp-corpus-intake.md (B))'s block->allow
        # correlation hook used purely to COUNT (capturing the revised-safe call is later).
        if streaks.pop(tool_key, None):
            session_stats["self_corrections"] = session_stats.get("self_corrections", 0) + 1
            # Flip EXACTLY the latest open ledger block for this tool to RECOVERED (see the
            # block-logging twin), so one clean call counts as one recovery. A session-wide
            # trace would flip every prior block of the tool and inflate the recovery rate
            # `agentx status` shows. Gated + best-effort: never touches the DB in the
            # routing-core tests, never raises into the clean-forward path.
            if session_stats.get("_ledger"):
                try:
                    block_trace = session_stats.get("_open_blocks", {}).pop(tool_key, None)
                    if block_trace:
                        log_self_correction(block_trace, "mcp_proxy", tool_key)
                except Exception:
                    pass
            # The heal-narration beat (MCP twin of the decorator's). Best-effort: the
            # clean-forward path had NO I/O before this, and a raise here (a broken or
            # closed stderr pipe) must never propagate — it would tear down the proxy and
            # drop this safe call, breaking the "never wedge the protocol" contract. The
            # wording is deliberately weaker than the decorator's trace-keyed claim: this
            # heuristic is tool-name-keyed (no per-call trace, so it can fire for an
            # unrelated later clean call, or one whose earlier block was an id-less drop
            # with no coaching), so it states what the shield OBSERVED and hedges the
            # cause — never asserting a completed task.
            try:
                print("[agentx-mcp] recovered: '%s' issued a clean call after an earlier block (likely a self-correction)."
                      % tool_key, file=log)
            except Exception:
                pass
            if harvest is not None:
                # (B): form the abstract recovery-pair, capturing the SAFE call's structural
                # signature (value-free) so the pair is a useful reframe, not just a counter.
                harvest.note_recovery(tool_key, params.get("arguments"))
        return "forward"

    # AUDIT posture: this call matched a policy, but AGENTX_ENFORCEMENT=audit — record the
    # WOULD_BLOCK and FORWARD the real call instead of answering with coaching, so the
    # wrapped server runs untouched. Takes NONE of the block accounting below (no intercept
    # / critical count, no CHALLENGED ledger row, no strike, no harvest) — the twin of the
    # decorator's _audit_and_proceed, sharing the same category vocab guard + ledger so the
    # two keyless surfaces can't drift. Placed before the breaker: a would-block that
    # actually runs is not a blocked-retry loop.
    if session_stats.get("_enforcement") == "audit":
        session_stats["would_blocks"] = session_stats.get("would_blocks", 0) + 1
        _note_block_category(decision.get("category"), session_stats)
        if session_stats.get("_ledger"):
            try:
                seq = session_stats.get("_ledger_seq", 0)
                session_stats["_ledger_seq"] = seq + 1
                wb_trace = "%s-%d" % (session_stats.get("_trace_id") or "mcp-session", seq)
                log_intercept(wb_trace, "mcp_proxy", tool_key,
                              decision.get("policy_id"), decision.get("policy_name"), WOULD_BLOCK_STATUS)
            except Exception:
                pass
        try:
            print("[agentx-mcp] AUDIT: would have blocked '%s' (%s); AGENTX_ENFORCEMENT=audit, "
                  "forwarded and recorded. Review: agentx insights"
                  % (tool_key, decision.get("policy_name")), file=log)
        except Exception:
            pass
        return "forward"

    # Blocked. Match the decorator's breaker edge: _trip_breaker_if_ceiling checks the
    # count BEFORE the increment, so it trips on the call AFTER the ceiling is reached
    # (max_turns blocks are allowed, the next one trips). Compare-then-increment here so
    # the MCP and decorator paths halt a runaway loop at the same point.
    tripped = streaks.get(tool_key, 0) >= max_turns
    streaks[tool_key] = streaks.get(tool_key, 0) + 1

    session_stats["intercepts"] = session_stats.get("intercepts", 0) + 1
    session_stats["critical_blocks"] = session_stats.get("critical_blocks", 0) + 1
    # Closed-vocab privacy guard (only a known category enum may ride the pulse, never
    # the free text a pulled policy could carry), shared with the decorator via the
    # parameterized recorder so the two can't drift.
    _note_block_category(decision.get("category"), session_stats)
    # Record the block in the local flight-recorder ledger (CHALLENGED) so a real MCP
    # catch fills `agentx status`. Each block gets a UNIQUE trace and remembers itself as
    # this tool's latest open block, so a later clean call recovers exactly ONE block
    # (matches the decorator's per-call keying, keeps the recovery rate honest). Gated +
    # best-effort (see the clean-call twin above).
    if session_stats.get("_ledger"):
        try:
            seq = session_stats.get("_ledger_seq", 0)
            session_stats["_ledger_seq"] = seq + 1
            block_trace = "%s-%d" % (session_stats.get("_trace_id") or "mcp-session", seq)
            session_stats.setdefault("_open_blocks", {})[tool_key] = block_trace
            log_intercept(block_trace, "mcp_proxy", tool_key,
                          decision.get("policy_id"), decision.get("policy_name"), "CHALLENGED")
        except Exception:
            pass

    req_id = msg.get("id")
    if req_id is not None:
        if harvest is not None:
            # (B): only a block that was actually COACHED (had an id to answer) is a harvest
            # candidate — an id-less blocked call is dropped with no coaching, so a later clean
            # call on it is not a coached recovery. Carry the policy identity (name + id, floor
            # labels, value-free) so an adopted/auto reframe keys to the exact policy the next
            # block matches (mcp_recovery_candidates -> agentx adopt / auto-coach).
            harvest.note_block(tool_key, decision.get("category"),
                               policy_name=decision.get("policy_name"),
                               policy_id=decision.get("policy_id"))
        # A1b: enrich the keyless coaching with the org's adopted reframe (challenge +
        # safe-path) via the SHARED _apply_org_override the decorator uses, so the org
        # brain reaches the MCP wedge too and the two keyless paths can't drift. Keyless:
        # it reads the local .agentx/overrides.json (no gateway). Total best-effort — it
        # returns the inputs unchanged when nothing is adopted, so the cold install (the
        # funnel target, no overrides) is completely unaffected.
        ch, safe = _apply_org_override(
            decision.get("policy_id"), decision.get("challenge_text"),
            decision.get("preferred_alternative"), policy_name=decision.get("policy_name"))
        coached = dict(decision, challenge_text=ch, preferred_alternative=safe)
        writer.send(_block_response(req_id, _coaching_text(coached, tripped, name)))
    else:
        # A tools/call shaped as a notification (no id) cannot be answered, but it must
        # NOT be forwarded either — drop it so the dangerous call never reaches the server.
        print("[agentx-mcp] dropped id-less blocked tools/call '%s'" % tool_key, file=log)
    print("[agentx-mcp] blocked tools/call '%s' (policy: %s)%s"
          % (tool_key, decision.get("policy_name"), " [breaker tripped]" if tripped else ""),
          file=log)
    return "block"


def _route_line(line, child_in, writer, session_stats, streaks, max_turns, log, harvest=None):
    """Handle ONE client->server line. Forwards it to the child UNLESS a tools/call in
    it is blocked by the keyless shield. Scalars are forwarded byte-for-byte; a batch
    (JSON array) is screened member by member and only the un-blocked members are
    forwarded (re-serialized). Fail-open: anything we can't parse is forwarded so the
    proxy can never wedge the protocol."""
    if not line.strip():
        _forward(line, child_in)
        return
    try:
        msg = json.loads(line)
    except Exception:
        _forward(line, child_in)             # not JSON we understand — pass through
        return

    # Capture tools/list request ids (client->server) so the relay can id-correlate
    # the server's response for drift inspection. Guarded; a no-op unless drift
    # detection is on (session_stats carries the pending-id set).
    try:
        pend = session_stats.get("_pending_list_ids")
        if pend is not None and isinstance(msg, dict) and msg.get("method") == "tools/list" \
                and msg.get("id") is not None:
            pend.add(msg.get("id"))
    except Exception:
        pass

    # JSON-RPC batch: removed in MCP 2025-06-18, but a legacy client may still send an
    # array. Screen each member and forward only the ones we did not block, so a
    # dangerous tools/call buried in a batch can't slip through unscreened.
    if isinstance(msg, list):
        keep = [item for item in msg
                if _screen_message(item, session_stats, streaks, max_turns, writer, log, harvest) == "forward"]
        if keep:
            child_in.write(json.dumps(keep) + "\n")
            child_in.flush()
        return

    if _screen_message(msg, session_stats, streaks, max_turns, writer, log, harvest) == "forward":
        _forward(line, child_in)             # scalar: forward the ORIGINAL line verbatim


def run_proxy(child_cmd, *, client_in, client_out, session_stats, log=None,
              popen=None, close_client_on_child_exit=False):
    """Spawn ``child_cmd``, relay the MCP protocol both ways, screen ``tools/call``.
    Returns the child's exit code. Streams + the spawn function are injectable so the
    routing core can be unit-tested without a subprocess.

    ``close_client_on_child_exit`` (set by ``main`` for the real process, off for
    tests): when the child dies, close the client stream so the host sees stdout EOF
    and tears the proxy down, instead of the client hanging on a response that will
    never come."""
    log = log or sys.stderr
    max_turns = _max_cognitive_turns()
    streaks = {}
    harvest = _Harvest() if _harvest_enabled() else None   # (B): opt-in, default OFF -> inert
    writer = _ClientWriter(client_out)

    # MCP tool-description drift detection (server->client tools/list inspection).
    # `off` keeps the relay a byte-identical pump (pins is None -> never inspected).
    # The block-gate + tools/list id capture on the client->server path read their
    # state from session_stats (already threaded through _route_line /
    # _screen_message), so there is no signature churn.
    pin_mode = _tool_pinning_mode()
    pins = _ToolPins() if pin_mode != "off" else None
    server_key = _server_key(child_cmd)
    pending_list_ids = set()
    drifted = set()
    if pins is not None:
        session_stats["_pin_mode"] = pin_mode
        session_stats["_drifted"] = drifted
        session_stats["_pending_list_ids"] = pending_list_ids

    # Resolve the keyless runaway-loop ceiling ONCE per session (opt-in; 0 = disabled, the
    # default, so the key is absent and _screen_message's guard is a no-op). Stashed on
    # session_stats like _pin_mode so no routing-core signature churns.
    ceiling = _call_ceiling()
    if ceiling:
        session_stats["_call_ceiling"] = ceiling

    def _default_popen(cmd):
        # errors="replace": a stray non-UTF-8 byte from the server must not raise in the
        # relay's `for line in child.stdout` and tear the whole session down.
        return subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )

    try:
        child = (popen or _default_popen)(list(child_cmd))
    except FileNotFoundError:
        print("[agentx-mcp] cannot start MCP server, command not found: %s"
              % (child_cmd[0] if child_cmd else "?"), file=log)
        return 127
    except Exception as err:
        print("[agentx-mcp] failed to start MCP server %r: %s" % (list(child_cmd), err), file=log)
        return 1

    # Byte-preserve newlines on the forward path: a text-mode child stdin (newline=None)
    # would translate '\n' -> os.linesep ('\r\n' on Windows), breaking _forward's verbatim
    # contract and handing a newline-strict server CRLF. Popen has no newline kwarg, so
    # reconfigure post-spawn. Best-effort.
    try:
        child.stdin.reconfigure(newline="")
    except Exception:
        pass

    def _relay():
        try:
            for line in child.stdout:
                if pins is not None:
                    _inspect_list_line(line, pins, pending_list_ids, server_key,
                                       pin_mode, drifted, session_stats, log)
                writer.relay(line)
        except Exception:
            pass
        finally:
            if close_client_on_child_exit:
                writer.close()       # child died -> EOF the client so it doesn't hang

    pump = threading.Thread(target=_relay, daemon=True)
    pump.start()

    try:
        for line in client_in:
            _route_line(line, child.stdin, writer, session_stats, streaks, max_turns, log, harvest)
    except Exception as err:
        print("[agentx-mcp] client stream error: %s" % err, file=log)
    finally:
        try:
            child.stdin.close()
        except Exception:
            pass
        if harvest is not None:
            _flush_harvest(harvest, log)   # (B): write the session's local, abstract recovery pairs
            auto_coach(log=log)            # (B): auto-promote the strongest paths into the org-brain

    try:
        rc = child.wait(timeout=10)
    except Exception:
        try:
            child.kill()
        except Exception:
            pass
        try:
            rc = child.wait(timeout=5)
        except Exception:
            rc = None
        if rc is None:           # couldn't determine the exit code: treat as failure.
            rc = 1               # (a clean rc==0 reaped during the grace window stays 0)
    pump.join(timeout=2)
    return rc if rc is not None else 0


def _protection_report(session_stats, log):
    """The proxy's session-end value report ("here's what I protected") — the MCP
    twin of the decorator's atexit summary. One compact stderr line of what the
    shield did this session, plus the local protection streak
    (pulse.record_protection — pulse.json bookkeeping outside the pulse allowlist,
    never transmitted). Silent for a session that wrapped no calls, and in
    automation/CI the streak half self-gates. Never raises."""
    try:
        calls = int(session_stats.get("total_calls", 0) or 0)
        if calls <= 0:
            return
        print("[agentx-mcp] shield report: %d call(s) screened, %d blocked, %d self-corrected after a block."
              % (calls,
                 int(session_stats.get("critical_blocks", 0) or 0),
                 int(session_stats.get("self_corrections", 0) or 0)), file=log)
        protection = pulse.record_protection(session_stats)
        if protection:
            print("[agentx-mcp] protection streak: %s." % pulse.format_protection_line(protection), file=log)
    except Exception:
        pass


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)

    if argv and argv[0] in ("-h", "--help"):
        sys.stderr.write(_USAGE)
        return 0
    if argv and argv[0] == "--version":
        try:
            from agentx_sdk import __version__
            sys.stderr.write("agentx-mcp %s\n" % __version__)
        except Exception:
            sys.stderr.write("agentx-mcp\n")
        return 0
    if argv and argv[0] == "--":          # explicit end-of-options separator
        argv = argv[1:]
    if not argv:
        sys.stderr.write(_USAGE)
        return 2

    # --- stdout hygiene -------------------------------------------------------
    # Capture the REAL client channel, then alias sys.stdout to stderr so no stray
    # print (ours or the SDK's) can ever land on the JSON-RPC stream.
    client_out = sys.stdout
    for stream, kwargs in ((client_out, {"encoding": "utf-8", "newline": "\n"}),
                           (sys.stdin, {"encoding": "utf-8"})):
        try:
            stream.reconfigure(**kwargs)
        except Exception:
            pass
    client_in = sys.stdin
    sys.stdout = sys.stderr

    # Drop the decorator's atexit session summary (a maintained public contract, not a
    # reach into a private symbol): it prints a box to stdout and sends a 'decorator'
    # pulse. This process is the MCP proxy — stdout stays pure JSON-RPC and it owns a
    # single, correctly-labeled 'mcp' pulse.
    import atexit
    from agentx_sdk import decorators, pulse
    decorators.suppress_atexit_summary()

    session_stats = {"integration": "mcp", "total_calls": 0,
                     "intercepts": 0, "critical_blocks": 0, "self_corrections": 0}
    # Enable the local flight-recorder ledger for THIS real run (the routing-core tests
    # build their own bare session_stats and stay ledger-free). One session-scoped trace
    # id keys the block -> recovery flip. init_db is idempotent (the decorators import
    # already ran it); repeat it here so a proxy started in a fresh CWD still has a table.
    session_stats["_trace_id"] = "mcp-" + uuid.uuid4().hex[:12]
    session_stats["_ledger"] = True
    # ENFORCEMENT LEVEL (posture) for the whole wrapped server — chokepoint parity with
    # the decorator: the SAME global AGENTX_ENFORCEMENT switch means "audit the whole
    # server" is one env line here too. In `audit` a caught tools/call is recorded
    # (WOULD_BLOCK) and FORWARDED to the real server instead of being answered with a
    # coaching error, so a team can run the shield non-blocking in staging first. Resolved
    # once at startup (a long-lived process; no per-tool override on the proxy path).
    session_stats["_enforcement"] = _resolve_enforcement(None)
    try:
        init_db()
    except Exception:
        pass

    def _session_end():
        # Mirror the decorator path (decorators.py): never emit a pulse (or print
        # the value report / count a streak) from CI / automation, or wrapping a
        # server in a test harness pollutes the funnel.
        if not pulse.is_automation_context():
            _protection_report(session_stats, sys.stderr)
            pulse.on_session_end(session_stats)
    atexit.register(_session_end)

    _posture = session_stats.get("_enforcement", "enforce")
    if _posture == "audit":
        # Loud, unmissable: audit records but does NOT block, so a wrapped-server operator
        # must see at startup that the tools are being watched, not defended (twin of the
        # decorator's _emit_audit_banner).
        print("[agentx-mcp] "
              "============================================================", file=sys.stderr)
        print("[agentx-mcp]  AGENTX AUDIT MODE (AGENTX_ENFORCEMENT=audit): tool calls are "
              "RECORDED but NOT blocked.", file=sys.stderr)
        print("[agentx-mcp]  The server is NOT protected. See catches: agentx insights  |  "
              "Block for real: set AGENTX_ENFORCEMENT=enforce", file=sys.stderr)
        print("[agentx-mcp] "
              "============================================================", file=sys.stderr)
    print("[agentx-mcp] AgentX shield active (%s), wrapping: %s"
          % ("AUDIT: record-only, nothing blocked" if _posture == "audit" else "enforcing",
             " ".join(argv)), file=sys.stderr)
    return run_proxy(argv, client_in=client_in, client_out=client_out,
                     session_stats=session_stats, close_client_on_child_exit=True)


if __name__ == "__main__":
    sys.exit(main())
