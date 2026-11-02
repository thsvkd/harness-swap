"""Built-in harness adapters, registered by import path (loaded lazily).

Adding a harness to hswap itself is one line here plus the adapter module;
third-party adapters use the ``harness_swap.adapters`` entry-point group
instead (see docs/adapter-development.md).
"""

BUILTIN: dict[str, str] = {
    "claude": "harness_swap.adapters.claude:ClaudeAdapter",
    "codex": "harness_swap.adapters.codex:CodexAdapter",
    "grok": "harness_swap.adapters.grok:GrokAdapter",
    "opencode": "harness_swap.adapters.opencode:OpenCodeAdapter",
}
