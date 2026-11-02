"""Where hswap keeps its own data.

``HSWAP_HOME`` wins. Otherwise Linux/WSL follow the XDG data directory
(``$XDG_DATA_HOME/harness-swap``, default ``~/.local/share/harness-swap``) and
macOS/Windows use ``~/.harness-swap`` -- the same split the Claude engine uses
for its own store, which hswap leaves where it is (see docs/migration.md).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def hswap_home() -> Path:
    env = os.environ.get("HSWAP_HOME")
    if env:
        return Path(os.path.expanduser(env))
    if sys.platform.startswith("linux"):
        xdg = os.path.expanduser(os.environ.get("XDG_DATA_HOME", ""))
        if xdg and os.path.isabs(xdg):
            return Path(xdg) / "harness-swap"
        return Path.home() / ".local" / "share" / "harness-swap"
    return Path.home() / ".harness-swap"


def harness_home(harness_id: str) -> Path:
    """Per-harness subdirectory: its account registry and stored credentials."""
    return hswap_home() / harness_id


def env_dir(name: str, default: Path) -> Path:
    """A harness home taken from an environment variable, else ``default``."""
    value = os.environ.get(name)
    return Path(os.path.expanduser(value)) if value else default
