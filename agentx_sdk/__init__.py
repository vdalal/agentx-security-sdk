__version__ = "0.4.19"
# ISO date this version was cut. Drives the OFFLINE staleness notice
# (pulse.staleness_notice): an old install nags ITSELF to upgrade with no network
# call, because pip cannot declare a minimum version of the leaf package and so
# nothing else can reach a pinned install. MUST move with __version__ (BACKLOG C12).
__released__ = "2026-07-14"

# The version currently LIVE on PyPI. This is what makes "never ship code under an
# already-published version" checkable OFFLINE (test_version_gate.py).
#
# It is NOT a duplicate of __version__ and the two are SUPPOSED to differ: the gap
# between them is the unreleased content accumulating for the next publish. That gap
# is the whole point -- a version number is a budget, not a counter, so many PRs bundle
# under ONE unreleased version and we publish once, with content.
#
# The rejected alternative was a gate asserting "any SDK source diff must move
# __version__", which forces a bump on EVERY PR: exactly the version churn we are
# avoiding, and it would have failed this PR.
#
# ▶ UPDATE THIS AT `twine upload` TIME, in the same commit as the publish.
__published__ = "0.4.18"

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