__version__ = "0.4.22"
# ISO date this version was cut. Drives the OFFLINE staleness notice
# (pulse.staleness_notice): an old install nags ITSELF to upgrade with no network
# call, because pip cannot declare a minimum version of the leaf package and so
# nothing else can reach a pinned install. MUST move with __version__ (BACKLOG C12).
__released__ = "2026-07-21"

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
# ▶ Before `twine upload`, confirm the live version is BELOW __version__:
#     python -c "import json,urllib.request as u; print(json.load(
#       u.urlopen('https://pypi.org/pypi/agentx-security-sdk/json'))['info']['version'])"

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