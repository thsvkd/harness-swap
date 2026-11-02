"""Multi-account switcher for Claude Code."""

# This engine ships inside the harness-swap distribution as the Claude Code
# adapter's implementation; its version names the upstream claude-swap
# lineage it tracks (export envelopes record it as ``swapVersion``).
__version__ = "0.30.0b1"

from claude_swap.switcher import ClaudeAccountSwitcher

__all__ = ["ClaudeAccountSwitcher", "__version__"]
