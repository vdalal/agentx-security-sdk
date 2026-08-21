__version__ = "0.4.30"
# ISO date this version was cut. Drives the OFFLINE staleness notice
# (pulse.staleness_notice): an old install nags ITSELF to upgrade with no network
# call, because pip cannot declare a minimum version of the leaf package and so
# nothing else can reach a pinned install. MUST move with __version__.
__released__ = "2026-08-19"

# The rule "never ship SDK source under a version that is ALREADY published" still
# stands; what is gone is the hand-maintained `__published__` constant that used to
# claim to enforce it. It required a manual edit at `twine upload` time, that edit was
# missed every single time, and a marker that lags is worse than no marker: the gate
# read GREEN while the invariant was broken. Verified twice -- 0.4.18 vs a live 0.4.19,
# then 0.4.20 vs a live 0.4.21 with nine SDK commits stacked on top of it.
#
# This test file ships INSIDE the sdist, so an in-tree gate cannot ask PyPI what is
# actually live without making a user's own `pytest` hit the network. That is why the
# stale hand-maintained constant was the only in-tree option, and why the honest move is
# to stop pretending it is a gate. The rule is now PROCEDURAL, checked at publish time:
#
# ▶ Before `twine upload`, confirm THIS version is not already live. Ask about the exact
#   version, never the top-level index: `/pypi/<pkg>/json` is CDN-cached and has reported a
#   stale `info.version` for long enough to wave through an upload of a version that already
#   existed. The per-version endpoint is not cached the same way.
#
#   🔴 THREE OUTCOMES, NOT TWO, AND CONFLATING THEM IS THE WHOLE POINT: free, taken, and
#   "could not ask". A first cut of this instruction said "a 404 means the number is free"
#   over a bare urlopen -- but urlopen raises on a 404 AND on a DNS failure, a proxy block or
#   a timeout, so any network hiccup read as permission to upload. Same fail-open direction as
#   the cached index it replaced: every failure looks like good news.
#
#     py scripts/check_pypi_version_free.py       # 0 = free, 1 = taken, 2 = could not ask
#
#   It reads __version__ from this file rather than restating it, so it cannot go stale the
#   way the retired __published__ marker did.

from .decorators import (
    agentx_protect,
    record_spend,
    start_secure_session,
    reset_strike_state,
    is_block,
    AgentXBlock,
    AgentXSecurityBlock,
    AgentXCircuitBreakerTripped,
    AgentXPolicyLoadError,
)
from .client import AgentXClient

__all__ = [
    "agentx_protect",
    "AgentXClient",
    "record_spend",
    "start_secure_session",
    "reset_strike_state",
    "is_block",
    "AgentXBlock",
    "AgentXSecurityBlock",
    "AgentXCircuitBreakerTripped",
    "AgentXPolicyLoadError",
]