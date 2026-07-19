"""
Anonymous usage pulse — ON by default, one-line opt-out.

Sends a tiny, abstract daily heartbeat — SDK version, OS family, Python minor, and
session COUNTS — so we can see activation and retention that anonymous PyPI download
numbers structurally cannot show (downloads have no per-install join key, so they can
never tell you whether one developer came back and kept updating).

Default ON with a one-time transparency notice — the "notify + opt-out" posture used
by Next.js / Homebrew analytics. The first activated run prints exactly what is shared
(anonymous version/OS/counts, never code or data) and how to turn it off. Two explicit
decisions are always honored above the default: ``AGENTX_TELEMETRY=off`` (env/.env),
and a "no" a developer gave to the legacy first-run prompt (stored in pulse.json).

Hard rules (asserted by test_pulse.py):
  * Never sends payloads, queries, CoT, args, paths, hostnames, usernames, keys.
  * Only the fields in ``_ALLOWED_KEYS`` / ``_ALLOWED_SESSION_KEYS`` ever leave.
  * Fire-and-forget: never raises, never hangs the agent, fails open offline.
  * stdlib-only (the 0.3.1 import-safety lesson) — no ``requests`` at import.
  * One explicit off always wins: ``AGENTX_TELEMETRY=off`` (env/.env) silences
    everything, and a prior declined prompt is never overridden by the default.
  * Test and CI runs are excluded entirely — even when on — because they are
    mechanical automation, not developer adoption (see is_automation_context).

The receiver is the control plane's ``POST /api/pulse`` (ui/app/api/pulse/route.ts),
resolved from CONTROL_PLANE_URL by ``_endpoint`` — the gateway is not in the path.
"""
import json
import os
import platform
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

# Anonymous, machine-local identity + send bookkeeping. NOT derived from
# hostname / MAC / username / path — a random token that only says "this
# install came back", never "who".
_PULSE_FILE = Path.home() / ".agentx" / "pulse.json"

# A plane-less `local` install has no CONTROL_PLANE_URL, so the default target is
# the public plane's /api/pulse. linked/cloud installs derive the endpoint from
# their own CONTROL_PLANE_URL instead (see _endpoint) — no pulse-specific var.
# MUST be the CANONICAL www host: the bare apex (agentx-core.com) issues a 307 ->
# www, and urllib refuses to follow a 307 for a POST (it raises HTTPError), so a
# default pointed at the apex silently drops every plane-less cold-install pulse.
_DEFAULT_ENDPOINT = "https://www.agentx-core.com/api/pulse"

_DEBOUNCE_SECONDS = 24 * 60 * 60   # at most one pulse per install per day
_TIMEOUT = 1.0                     # seconds — best-effort; bounds the atexit wait

# The complete set of keys that may leave the machine — the privacy contract.
# test_payload_emits_exactly_the_allowlist asserts build_payload emits EXACTLY
# these (not a subset), so this list and what we send can't drift apart.
# KEEP IN SYNC WITH the defense-in-depth mirror in ui/app/api/pulse/route.ts
# (projectPulse + SESSION_ALLOWLIST). Note the route renames `ts`->`pulse_ts` and
# splits had_block/first_block_ever (booleans) out from the count keys.
_ALLOWED_KEYS = {"install_id", "sdk_version", "python", "os", "first_seen", "ts",
                 "mode", "gateway_present", "reasoning_enabled", "contributed",
                 "block_category", "integration", "session"}
_ALLOWED_SESSION_KEYS = {
    "tools_monitored", "intercepts", "critical_blocks",
    "human_escalations", "self_corrections", "would_blocks",
    "had_block", "first_block_ever", "shield_failopens",
}


_env_overlay = None


def _env(key):
    """Resolve an AGENTX_* var from the process env, falling back to the project
    `.env` (via the stdlib-only envfile.load_env_file). The SDK runtime does not
    auto-load `.env`, so without this a flag placed in `.env` — exactly where
    .env.example tells users to put AGENTX_TELEMETRY — would silently no-op unless
    the host app happened to call load_dotenv(). Cached after first read. Never
    raises (telemetry must never break a run)."""
    val = os.environ.get(key)
    if val is not None:
        return val
    global _env_overlay
    if _env_overlay is None:
        try:
            from .envfile import load_env_file   # stdlib-only — no requests at atexit
            _env_overlay = load_env_file() or {}
        except Exception:
            _env_overlay = {}
    return _env_overlay.get(key)


def _truthy(val):
    return str(val or "").strip().lower() in ("1", "true", "on", "yes")


def telemetry_enabled(state=None):
    """True unless the developer explicitly opted out. Default ON (notify + opt-out).

    Precedence, so the two explicit decisions always beat the default:
      * AGENTX_TELEMETRY (env/.env) — an explicit override the user sets themselves,
        which ALWAYS wins when present (``off`` silences everything; ``on`` is a
        team-wide commit of the default).
      * a recorded answer to the legacy first-run prompt (``consent_prompted`` in
        ~/.agentx/pulse.json) — honored so a developer who already said "no" is
        never flipped back on by the new default.
      * otherwise ON — the default-on policy this module now ships with.
    ``state`` may be passed to avoid re-reading pulse.json when the caller already
    loaded it."""
    explicit = _env("AGENTX_TELEMETRY")
    if explicit is not None:
        return _truthy(explicit)
    if state is None:
        state = _load_state()
    if state.get("consent_prompted"):
        return bool(state.get("telemetry_consent", False))
    return True


def _is_http(url):
    return bool(url) and url.lower().startswith(("https://", "http://"))


def _endpoint():
    """Resolve where the pulse goes — reusing the SDK's existing control-plane var
    rather than a pulse-specific one:
      1. {CONTROL_PLANE_URL}/api/pulse — follow the plane the SDK is already
         pointed at (linked/cloud), so a configured plane receives its own pulses
         instead of the public host. /api/pulse is the canonical receiver on every
         plane; the gateway is not in the pulse path.
      2. the public default — for the cold, plane-less `local` install the pulse
         exists to capture (it has no CONTROL_PLANE_URL by definition).
    Only http(s) is accepted; any other scheme (file://, ftp://, …) is ignored so a
    stray/hostile CONTROL_PLANE_URL can't redirect the install_id-bearing pulse to
    an arbitrary sink."""
    plane = (_env("CONTROL_PLANE_URL") or "").strip()
    if _is_http(plane):
        base = plane.rstrip("/")
        # Idempotent: if the value already points at the route, don't double the
        # path (a CONTROL_PLANE_URL ending in /api/pulse would otherwise become
        # …/api/pulse/api/pulse → silent 404, swallowed by _post).
        return base if base.endswith("/api/pulse") else base + "/api/pulse"
    return _DEFAULT_ENDPOINT


def _mode():
    """Resolve the coarse data-plane mode (local | linked | cloud) for the funnel.

    Mirrors the single canonical resolution used by the CLI (cli.py) and the
    gateway/UI (mode_config.py / mode.ts) so the four surfaces never disagree:
    explicit AGENTX_MODE wins; else legacy AGENTX_ALLOW_PAYLOAD_SYNC=true => cloud;
    else a CONTROL_PLANE_URL => linked; else local. This is a 3-value coarse fact
    (same privacy class as os/python) — it names the install's adoption STAGE, not
    the developer. Never raises."""
    try:
        mode = (_env("AGENTX_MODE") or "").strip().lower()
        if mode in ("local", "linked", "cloud"):
            return mode
        if _truthy(_env("AGENTX_ALLOW_PAYLOAD_SYNC")):
            return "cloud"
        return "linked" if (_env("CONTROL_PLANE_URL") or "").strip() else "local"
    except Exception:
        return "local"


def _sdk_version():
    """Best-effort version read; never raises."""
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version("agentx-security-sdk")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    try:
        from agentx_sdk import __version__
        return __version__
    except Exception:
        return "unknown"


def _load_state():
    try:
        with open(_PULSE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_state(state):
    try:
        parent = Path(_PULSE_FILE).parent
        parent.mkdir(parents=True, exist_ok=True)
        # Atomic write. A torn pulse.json — a crash mid-write, or two SDK processes
        # exiting at once — is read back as {} by _load_state, which then re-mints
        # install_id AND drops a recorded telemetry opt-out (consent_prompted), silently
        # flipping an opted-out install back to default-on. Writing to a unique temp file
        # in the same dir and os.replace-ing it (atomic on POSIX and Windows) means a
        # reader only ever sees a complete file. record_protection made this a
        # once-per-active-session writer, so the previously-rare torn window is worth
        # closing. (Concurrent writers still last-writer-wins a lost update — benign for a
        # cosmetic streak; the pulse's own debounced fields were already exposed to that.)
        fd, tmp = tempfile.mkstemp(dir=str(parent), prefix=".pulse-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f)
            os.replace(tmp, _PULSE_FILE)
        except Exception:
            try:
                os.unlink(tmp)
            except Exception:
                pass
            raise
    except Exception:
        pass


def _ensure_identity(state):
    """Mint a stable random install_id + first_seen date on first ever run."""
    if not state.get("install_id"):
        state["install_id"] = str(uuid.uuid4())
    if not state.get("first_seen"):
        state["first_seen"] = date.today().isoformat()
    return state


def mark_contributed(state=None, cursor=None):
    """Record that this install reached the CONTRIBUTE funnel stage — called by
    `agentx push`/`sync` after a contribution POST succeeds. STICKY: once True it
    stays True. Mints the anonymous identity so the flag joins the funnel by
    install_id, and writes ONLY pulse.json. ``cursor`` (the gateway's contribution
    high-water mark) is persisted as ``last_contributed_cursor`` so the next push
    pulls only NEW incidents (the contribution delta) instead of re-sending the whole
    projection. Never raises (telemetry must never break the contribution flow)."""
    try:
        if state is None:
            state = _load_state()
        _ensure_identity(state)
        state["contributed"] = True
        state["last_contributed"] = date.today().isoformat()
        if cursor:
            state["last_contributed_cursor"] = cursor
        _save_state(state)
    except Exception:
        pass


def _had_block(session_stats):
    return bool(session_stats.get("intercepts", 0) or session_stats.get("critical_blocks", 0))


# NOTE: there is deliberately no activity gate. Since the funnel needs the
# download→ran→activated denominator, the pulse fires once daily whenever the SDK
# ran at all (even a bare import that wrapped nothing); ``tools_monitored`` rides
# along in every payload so the funnel can still separate "ran" (any pulse) from
# "activated" (tools_monitored>0) downstream.


def _is_default_on(state=None):
    """True when telemetry is active purely by the default-on policy — the developer
    has neither set AGENTX_TELEMETRY (env/.env) nor answered the legacy prompt. Only
    these installs get the one-time transparency notice; an explicit opt-in (or a
    prior prompt answer) already knows. Never raises."""
    if _env("AGENTX_TELEMETRY") is not None:
        return False
    if state is None:
        state = _load_state()
    return not state.get("consent_prompted", False)


# Test runners and CI are mechanical, repetitive automation — NOT developer
# adoption — so they would pollute the activation/retention funnel. We exclude
# them from telemetry entirely, regardless of opt-in (the same mental model as
# never sending pytest data). A genuine production deployment is non-interactive
# but is NOT automation, so it is deliberately NOT excluded here — only test
# frameworks and CI environments are.
_CI_ENV_VARS = (
    "CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
    "CIRCLECI", "TRAVIS", "BUILDKITE", "TF_BUILD", "TEAMCITY_VERSION",
    "BITBUCKET_BUILD_NUMBER", "APPVEYOR", "DRONE", "CODEBUILD_BUILD_ID",
)


def _is_ci():
    return any(os.environ.get(v) for v in _CI_ENV_VARS)


def _is_dev_env():
    """True when the developer explicitly flags this as a dev/test environment via
    AGENTX_ENV (development|dev|test), so their OWN runs don't pollute the activation
    funnel. A first-class, documented funnel opt-out distinct from AGENTX_TELEMETRY=off
    (which is the privacy switch): AGENTX_ENV=development means "this run is not real
    adoption signal", the same class as CI/pytest. The operator and contributors set it
    on their own machines so an internal footprint can't inflate the funnel. Reads
    env + .env (via _env). Never raises."""
    return str(_env("AGENTX_ENV") or "").strip().lower() in ("development", "dev", "test")


def is_automation_context():
    """True when this run is a test/CI invocation OR an explicitly-flagged dev
    environment (AGENTX_ENV=development|dev|test) — i.e. NOT genuine developer/usage
    signal. Such runs are excluded from telemetry (and the protection streak / nudge)
    even when opted in, so an operator's or contributor's own machine can't inflate the
    activation funnel. Never raises."""
    try:
        return (
            "pytest" in sys.modules
            or bool(os.environ.get("PYTEST_CURRENT_TEST"))
            or _is_ci()
            or _is_dev_env()
        )
    except Exception:
        return False


def _note_first_block(session_stats, state=None):
    """Record that this install's first block has happened (when we're NOT sending),
    so a later opt-in reports first_block_ever=False instead of misattributing the
    activation moment to that post-opt-in session. Never raises."""
    try:
        if not _had_block(session_stats):
            return
        if state is None:
            state = _load_state()
        if not state.get("first_block_recorded"):
            state["first_block_recorded"] = True
            _save_state(state)
    except Exception:
        pass


def _show_notice(state=None):
    """Print the one-time transparency notice for a default-on install and mark it
    shown (``notice_shown`` in ~/.agentx/pulse.json) so it never repeats. This is the
    disclosure half of the notify + opt-out posture: the developer is told what is
    shared and how to turn it off BEFORE the first pulse leaves. Mints the anonymous
    identity. Writes ONLY pulse.json — never ./.env. Never raises."""
    try:
        if state is None:
            state = _load_state()
        print("\n" + "─" * 60)
        print(" AgentX shares ANONYMOUS usage by default — SDK version, OS, and")
        print(" block COUNTS only. Never your code, queries, or data.")
        print(" Opt out anytime:  AGENTX_TELEMETRY=off")
        print(" New here? Try:  agentx demo   ·   Questions/feedback: https://discord.gg/PmWRTtaSx2")
        print("─" * 60)
        state["notice_shown"] = True
        _ensure_identity(state)
        _save_state(state)
    except Exception:
        pass


_NUDGE_MIN_INTERVAL_S = 7 * 86400   # show the Recover CTA at most ~weekly per install


def _should_emit_nudge(session_stats, state, now):
    """Pure decision for the keyless-block -> Recover CTA. Show only when this session
    hit a block but never reached a gateway (rung-0 keyless), the install has NEVER
    reached a gateway (so a Recover user whose gateway was merely DOWN this session is
    not nagged), and we have not shown it within _NUDGE_MIN_INTERVAL_S (no per-session
    nag). Pure: no I/O, fully testable."""
    if not (session_stats.get("critical_blocks", 0) > 0 and not session_stats.get("gateway_reached")):
        return False
    if state.get("ever_gateway"):
        return False
    return (now - (state.get("last_nudge_ts") or 0)) >= _NUDGE_MIN_INTERVAL_S


def maybe_emit_nudge(session_stats):
    """Print the one-line Recover CTA at the activation moment (a keyless block). Owns
    its own pulse.json bookkeeping: a sticky ``ever_gateway`` (set the moment an install
    reaches a gateway, so future down-sessions don't re-nag) + a ``last_nudge_ts``
    debounce. Excluded from automation/CI. A static CTA — sends and tracks NOTHING,
    independent of telemetry consent. Never raises."""
    try:
        if is_automation_context():
            return
        state = _load_state()
        changed = False
        if session_stats.get("gateway_reached") and not state.get("ever_gateway"):
            state["ever_gateway"] = True
            changed = True
        now = time.time()
        if _should_emit_nudge(session_stats, state, now):
            print("─" * 60)
            print(" ▶ That was the keyless Shield: it blocked the call AND coached your")
            print("   agent to self-correct. Recover (gateway + key)")
            print("   adds the judge that catches what keywords miss, auto-runs the retry,")
            print("   and escalates the biggest calls to a human.")
            print("   Unlock Recover: agentx-core.com/#request-access")
            print("   Community: discord.gg/PmWRTtaSx2")
            state["last_nudge_ts"] = now
            changed = True
        if changed:
            _save_state(state)
    except Exception:
        pass


# --- LOCAL-ONLY protection streak (the session-end value report) -------------
# Bookkeeping for the "here's what I protected" report both integration surfaces
# print at session end (the decorator's atexit summary, agentx-mcp's exit
# report). LOCAL by construction: the fields live in ~/.agentx/pulse.json but
# are NOT in _ALLOWED_KEYS, and build_payload reads only its explicit keys, so
# they can never ride the pulse (test_pulse pins this).


def _as_int(value, default=0):
    """Coerce a possibly-corrupt persisted value to int, self-healing to ``default``
    on anything non-numeric. pulse.json is a user-editable file, so a hand-edited or
    foreign-written ``streak_days: "3 days"`` must not raise and permanently brick the
    streak (a bare int() inside record_protection's try would return None every session
    thereafter and never repair the field). Never raises."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def record_protection(session_stats, state=None, today=None):
    """Update the local protection streak for a session that actually monitored at
    least one call, and return what the session-end value report shows:
    ``{"streak_days", "protected_sessions", "since"}``.

    Streak semantics (calendar days, local clock): consecutive days with at least
    one protected session. A same-day session keeps the streak, the first session
    on the NEXT day extends it, a gap (or clock weirdness) resets it to 1.
    ``protected_sessions`` counts every qualifying session since install; ``since``
    is the first day protection was counted (0.4.6+), NOT the older install-identity
    date, so the report never overstates the protection window.

    Returns None (and writes nothing) for an idle session (nothing monitored), in
    automation/CI (a test harness run is not protection the developer experienced,
    and counting it would fake the streak, same rule as the pulse/nudge), or on any
    error. ``today`` is injectable for tests (a datetime is normalized to its date).
    Never raises.

    Known coarse edges (deliberate, both fail conservative): a long-lived process
    (an editor-integrated MCP proxy up for days) samples the date once, at exit, so a
    multi-day run counts as its exit day; and a fully fail-open/bypassed session with
    calls>0 still counts (the signal is "you ran AgentX", matching how tools_monitored
    defines activation elsewhere). Neither ever over-claims a streak."""
    try:
        if is_automation_context():
            return None
        if _as_int(session_stats.get("total_calls", 0)) <= 0:
            return None
        if state is None:
            state = _load_state()
        _ensure_identity(state)
        if isinstance(today, datetime):       # a datetime would poison last_protected_day
            today = today.date()               # (fromisoformat rejects it next session)
        today = today or date.today()
        today_iso = today.isoformat()
        last = state.get("last_protected_day")
        streak = _as_int(state.get("streak_days"))
        if last == today_iso:
            streak = max(streak, 1)      # same-day session: keep (never zero) the streak
        else:
            gap = None
            try:
                if last:
                    gap = (today - date.fromisoformat(str(last))).days
            except Exception:
                gap = None
            streak = streak + 1 if gap == 1 else 1
        # The day protection COUNTING began (0.4.6+), sticky. Distinct from first_seen
        # (the install-identity date, possibly months earlier) so "since" is honest.
        if not state.get("first_protected_day"):
            state["first_protected_day"] = today_iso
        state["streak_days"] = streak
        state["last_protected_day"] = today_iso
        state["protected_sessions"] = _as_int(state.get("protected_sessions")) + 1
        _save_state(state)
        return {
            "streak_days": streak,
            "protected_sessions": state["protected_sessions"],
            "since": state["first_protected_day"],
        }
    except Exception:
        return None


def format_protection_line(protection):
    """The canonical protection-streak phrase shown by BOTH session-end surfaces (the
    decorator summary and the agentx-mcp report), so the wording cannot drift across
    the two integration paths (the same anti-drift discipline as the shared detector /
    org-override helpers). Takes record_protection's return dict; each surface adds
    only its own prefix."""
    return ("%d day(s) | %d protected session(s) since %s"
            % (protection["streak_days"], protection["protected_sessions"],
               protection["since"]))


# --- OFFLINE STALENESS NOTICE ------------------------------------------------
# The SDK is the LEAF package: pip has no concept of "minimum version of myself",
# so nothing can pull an already-installed old copy forward. (The agentx-mcp
# floor only reaches installs that arrive THROUGH agentx-mcp.) A pinned install
# keeps running whatever shield it shipped with, missing every enforcement fix
# since, and we have no way to contact it — the pulse is anonymous. This is the
# only channel that reaches it: once a build is old enough, it nags ITSELF.
#
# Deliberately OFFLINE. No PyPI query, no new outbound destination, works
# airgapped, and it is independent of telemetry consent, so a developer who
# opted OUT of the pulse still hears about a security release. The price of
# being offline is that it cannot name the current version, only report that
# this build is old — which is the actionable half anyway.
#
# THRESHOLD is tuned to the RELEASE CADENCE, not to a round number of days. We ship
# roughly every 1-2 days in active development, so even a 7-day-old build is already
# several releases and possibly an enforcement fix behind. 7 days surfaces the
# `pip install --upgrade` nudge sooner: the whole value of this channel is reaching a
# pinned install BEFORE it misses a security fix, and at this cadence a week is already stale.
#
# The one hazard of an age-only signal is a release DROUGHT longer than the
# threshold: it can nag a developer who is already current -- no newer release
# exists, but the offline notice cannot know that (it only reports "this build is N
# days old", which stays literally true). At 7 days that window is tighter than at
# 15, an ACCEPTED tradeoff for the earlier nudge. REVISIT (raise it back up) if the
# cadence slows to a stable maintenance line and the notice becomes wallpaper.
#
# Self-clearing: upgrading resets the age to 0, so the only developers who keep
# seeing it are the ones who have not upgraded, which is exactly the audience.
_STALE_AFTER_DAYS = 7

UPGRADE_COMMAND = "pip install --upgrade agentx-security-sdk"


def build_age_days(released=None, today=None):
    """Days since this build was cut, from the ``__released__`` constant. None when the
    constant is missing or unparseable, so a bad constant produces NO notice rather than
    a guessed age. Both args injectable for tests. Never raises."""
    try:
        if released is None:
            import agentx_sdk
            released = agentx_sdk.__released__
        if isinstance(today, datetime):     # a datetime would poison the subtraction
            today = today.date()
        today = today or date.today()
        return max(0, (today - date.fromisoformat(str(released))).days)
    except Exception:
        return None


def format_staleness_line(age_days, version):
    """The canonical staleness phrase shown by BOTH session-end surfaces (the decorator
    summary and the agentx-mcp report), so the wording cannot drift across the two
    integration paths (the same anti-drift discipline as format_protection_line). Each
    surface adds only its own prefix, stream, and the shared UPGRADE_COMMAND."""
    return ("this build is %d days old (%s) and newer releases may carry security fixes"
            % (age_days, version))


def staleness_notice(released=None, today=None):
    """The one-line upgrade notice when this build is older than _STALE_AFTER_DAYS, else
    None. Excluded from automation/CI (a nag inside someone's test matrix is noise, the
    same rule as the streak and the nudge). Sends and tracks NOTHING. Never raises."""
    try:
        if is_automation_context():
            return None
        age = build_age_days(released=released, today=today)
        if age is None or age < _STALE_AFTER_DAYS:
            return None
        import agentx_sdk
        return format_staleness_line(age, agentx_sdk.__version__)
    except Exception:
        return None


def on_session_end(session_stats):
    """Single atexit entry point for all telemetry I/O — called by the SDK session
    summary. Owns its own output. Never raises.

    Fires on EVERY session the SDK ran (including a first run that wrapped nothing),
    not just sessions with a block — that "the SDK executed here" heartbeat is the
    download→ran→activated denominator we were otherwise blind to. The daily debounce
    in maybe_send caps it at one pulse per install per day.

      * on (default, or AGENTX_TELEMETRY=on) -> send the pulse; a default-on install
        prints the one-time transparency notice on its FIRST run, before the first
        pulse leaves, regardless of whether that run had any activity.
      * opted out (AGENTX_TELEMETRY=off, or a prior declined prompt) -> nothing, but
        record the install's first block so a later opt-in isn't misattributed.
    """
    try:
        # Load the consent/bookkeeping state ONCE and thread it through every
        # helper, so a session exit reads pulse.json a single time (the helpers
        # mutate + persist this shared dict) instead of re-opening it 3-5×.
        state = _load_state()
        if telemetry_enabled(state):
            # Disclosure-before-send: a default-on install is told what is shared
            # (and how to turn it off) once, on the first run — before the first
            # pulse leaves, whether or not that run had activity. An explicit
            # opt-in already knows, so it skips the notice.
            if _is_default_on(state) and not state.get("notice_shown", False):
                _show_notice(state)
            maybe_send(session_stats, block=True, state=state)
            return

        # Opted out: record the install's first block so a later opt-in isn't
        # misattributed (the real first block predates the opt-in).
        _note_first_block(session_stats, state)
    except Exception:
        pass


# Integration surface that emitted the pulse — a closed 2-value enum (same privacy
# class as mode / block_category): the @agentx_protect decorator (the in-process
# path, default) vs the agentx-mcp stdio proxy. Names HOW the install integrates,
# never identity. KEEP IN SYNC with the JS mirror in ui/app/api/pulse/route.ts.
_INTEGRATION_VOCAB = frozenset({"decorator", "mcp"})


def _integration(session_stats):
    """Coarse integration surface for the funnel split. Defaults to "decorator" —
    the decorator path never sets it; the agentx-mcp proxy sets
    ``session_stats["integration"] = "mcp"`` on the dict it hands to on_session_end.
    Off-vocab is normalized to "decorator" (fail-safe — never emit free text). So
    "decorator" means "in-process, non-proxy": accurate today because every in-process
    pulse flows through the decorator's atexit; a future non-decorator in-process caller
    would bucket here too."""
    v = session_stats.get("integration")
    return v if v in _INTEGRATION_VOCAB else "decorator"


def build_payload(session_stats, state, first_block_ever=None):
    """Assemble the abstract pulse. WHITELIST ONLY — reads counters, never content.

    ``session_stats`` is the SDK's live ``_session_stats`` dict; it also carries
    sets like ``challenged_traces`` and a ``consecutive_strikes`` map — none of
    which are read here. Only the integer counters cross the wire.

    ``first_block_ever`` may be passed by the caller (which decides it before
    flipping ``first_block_recorded``); when omitted it is derived from state.
    """
    had_block = _had_block(session_stats)
    if first_block_ever is None:
        first_block_ever = had_block and not state.get("first_block_recorded", False)
    return {
        "install_id": state.get("install_id"),
        "sdk_version": _sdk_version(),
        "python": "%d.%d" % (sys.version_info[0], sys.version_info[1]),
        "os": (platform.system() or "unknown").lower(),
        "first_seen": state.get("first_seen"),
        "ts": datetime.now(timezone.utc).isoformat(),
        # Coarse funnel-stage signals (no identity): which data-plane mode this
        # install runs in, and whether it actually reached a gateway this session
        # (SDK-only Layer-0 vs SDK + gateway). Together they make the
        # SDK -> +gateway -> cloud adoption funnel visible per install_id.
        "mode": _mode(),
        "gateway_present": bool(session_stats.get("gateway_reached", False)),
        # Reasoning tier (keyless Shield vs Recover): the gateway advertised the
        # judge as active on at least one verdict this session. A capability signal,
        # not identity — same privacy class as mode / gateway_present.
        "reasoning_enabled": session_stats.get("reasoning_enabled"),
        # Contribute funnel leg: has this install ever POSTed an abstract corpus
        # contribution (set by `agentx push`/`sync` into pulse.json — install-local,
        # abstract, not identity). Completes install -> activated -> gateway ->
        # Recover -> contribute. Read from persistent state, not session_stats,
        # because the contribution happens in the CLI, a different process.
        "contributed": bool(state.get("contributed", False)),
        # Coarse failure CLASS of a block this session (DESTRUCTIVE_ACTION / SSRF /
        # secrets / PII) — "what KIND of action got blocked", a closed-vocab enum in
        # the same privacy class as os / mode. NEVER the tool/function name, payload,
        # args, or CoT. None = no categorized block (e.g. a keyless install whose only
        # block was an off-vocab policy, or no block at all). Set SDK-side from the
        # matched policy so it works keyless. See decorators._BLOCK_CATEGORY_VOCAB.
        "block_category": session_stats.get("block_category"),
        # Integration surface (decorator | mcp) — lets the funnel split in-process
        # decorator adoption from the agentx-mcp proxy with a GROUP BY. Coarse
        # closed-vocab, no identity. A pre-integration-field SDK omits it, so the
        # receiver maps absent -> NULL = "pre-signal".
        "integration": _integration(session_stats),
        "session": {
            "tools_monitored": int(session_stats.get("total_calls", 0)),
            "intercepts": int(session_stats.get("intercepts", 0)),
            "critical_blocks": int(session_stats.get("critical_blocks", 0)),
            "human_escalations": int(session_stats.get("human_escalations", 0)),
            "self_corrections": int(session_stats.get("self_corrections", 0)),
            # AUDIT posture: catches that WOULD have blocked but were recorded-and-let-
            # through (AGENTX_ENFORCEMENT=audit). A DISTINCT coarse count from intercepts
            # so the funnel sees a new honest activation state: would_blocks>0 with
            # had_block False = an install EVALUATING (running audit), not yet enforcing.
            # Never identity/payload, same privacy class as the other counts.
            "would_blocks": int(session_stats.get("would_blocks", 0)),
            "had_block": had_block,
            "first_block_ever": first_block_ever,
            # SHIELD FAIL-OPENS: tool calls the Local Shield could not screen because it
            # THREW and fell through, so the call ran unscreened. A shield BUG, not a
            # policy decision, and on the keyless tier an enforcement BYPASS (nothing sits
            # behind the fall-through). Instances 1 and 2 of this class were found by luck
            # on an EOD pass; this counter is how instance 3 finds US.
            #
            # A COARSE INT AND NOTHING ELSE. The exception text is deliberately NOT sent:
            # a traceback can carry a file path, an argument, or a fragment of the user's
            # data, and this allowlist exists precisely to keep that off the wire.
            "shield_failopens": int(session_stats.get("shield_failopens", 0)),
        },
    }


def _post(endpoint, payload):
    """Fire the pulse. Swallows every error — telemetry must never break a run."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "agentx-sdk-pulse/%s" % payload.get("sdk_version", "?"),
            },
        )
        urllib.request.urlopen(req, timeout=_TIMEOUT).close()
    except Exception:
        pass


def maybe_send(session_stats, block=False, state=None):
    """Send one pulse if (and only if) telemetry is on and we are outside the 24h
    debounce window. There is intentionally NO activity gate: an idle run (the SDK
    imported and exited without a block) still heartbeats, because "this install ran
    today" is the activation/retention signal we need — the session counts (which may
    all be 0) ride along in the payload. Returns the dispatched payload (for tests)
    or ``None`` when nothing was sent. ``state`` may be passed to reuse a dict the
    caller already loaded. Never raises.
    """
    try:
        if state is None:
            state = _load_state()
        if not telemetry_enabled(state):
            return None

        _ensure_identity(state)
        now = time.time()

        first_block_ever = _had_block(session_stats) and not state.get("first_block_recorded", False)
        last = state.get("last_pulse", 0) or 0
        debounced = (now - last) < _DEBOUNCE_SECONDS

        # Honor the once-per-day debounce, with ONE exception: the install's first-ever
        # block (the activation 'aha') always sends, even within the window. Since the
        # activity gate was dropped, an idle heartbeat earlier the same day can consume
        # the window; without this exception the first block is debounced and
        # first_block_ever=True is recorded locally but NEVER transmitted, silently
        # under-counting the exact funnel stage this pulse exists to measure. A normal
        # (non-first) block stays debounced, so this adds at most one extra pulse per
        # install lifetime.
        if debounced and not first_block_ever:
            _save_state(state)  # persist identity even when we skip
            return None

        # Flip the once-ever flag only now that we are actually sending it, so a
        # debounced first-block session can't consume the flag without transmitting it.
        if first_block_ever:
            state["first_block_recorded"] = True

        payload = build_payload(session_stats, state, first_block_ever=first_block_ever)

        # Persist BEFORE dispatch so a crash mid-send can't double-count tomorrow.
        state["last_pulse"] = now
        _save_state(state)

        endpoint = _endpoint()
        try:
            t = threading.Thread(target=_post, args=(endpoint, payload), daemon=True)
            t.start()
            if block:
                # atexit: a daemon thread is killed at interpreter exit, so this brief,
                # bounded join is what actually lets the pulse deliver. Capped at
                # _TIMEOUT (1.0s) once per 24h — not the prior ~2.0s.
                t.join(timeout=_TIMEOUT)
        except RuntimeError:
            # Python 3.12+ refuses to start a NEW thread once interpreter shutdown has
            # begun — which is EXACTLY when on_session_end fires (atexit). Before this
            # guard the RuntimeError was swallowed by the outer except and the default-on
            # pulse silently never sent on 3.12+ (every unit test calls maybe_send
            # directly, never through a real exit, so the suite stayed green). _post is
            # itself bounded by urlopen(timeout=_TIMEOUT) and never raises, so fall back
            # to a direct synchronous send: behaviour-equivalent to the join we were
            # already blocking on, and safe to run during shutdown.
            _post(endpoint, payload)
        return payload
    except Exception:
        return None
