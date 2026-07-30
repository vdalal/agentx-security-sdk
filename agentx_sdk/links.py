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
