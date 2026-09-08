"""Canonical outward-facing links for the SDK — one source of truth.

A rotation (e.g. a dead Discord invite) is a one-line change HERE, not a hunt across
cli.py / pulse.py / tests. Guarded by sdk_tests/test_discord_invite_consistency.py,
which is green-on-truth and red-on-drift across every shipped surface (SDK + UI + blog).

Leaf module: no intra-package imports, so cli.py and pulse.py can both import it with
zero cycle risk. See skill rotate-discord-invite + memory owned-channels-assets.
"""

# The community Discord. An invite dies when its target channel is deleted, even if set
# to never-expire, so expect this to rotate. Update ONLY this line; the UI mirror lives
# in ui/utils/site.ts (markdown blog posts stay literal — the tripwire covers them).
DISCORD_URL = "https://discord.gg/TmQ3TURjwK"

# Where a reader GETS the gateway. Was a bit.ly short link at eight shipped sites (the
# literal is deliberately not repeated here: test_discord_invite_consistency.py bans it
# outright, and a ban with a comment-shaped carve-out is a ban with a hole). That one
# link was doing THREE jobs at once:
#
#   1. gateway access      -- five sites, the job it was actually for
#   2. BUG REPORTING       -- three sites said "Please report this" and pointed a defect
#                             report at a signup page, where there is nowhere to report
#                             anything. Those now go to DISCORD_URL, which is where the
#                             #bugs-and-feature-requests channel lives.
#   3. traffic attribution -- the same URL was also used outside the product, so a click
#                             from a CLI user and a click from anywhere else were
#                             indistinguishable. Separate constants keep the two apart.
#
# Same root shape either way: one thing serving two masters, correct for one of them and
# quietly wrong for the other.
#
# ⚠️ AND A SHORTENER IS THE WRONG DEFAULT ON THIS PRODUCT SPECIFICALLY. It hides its
# destination, printed by a security tool whose whole argument is "check it, do not trust
# us". The real URL is barely longer and it is checkable.
GATEWAY_URL = "https://agentx-core.com/gateway"
