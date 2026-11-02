"""Claude engine view of :mod:`harness_swap.infrastructure.locking`.

Same lock, raising the engine's own :class:`~claude_swap.exceptions.LockError`
so every existing ``except ClaudeSwitchError`` keeps catching a timeout.
"""

from __future__ import annotations

from claude_swap.exceptions import LockError
from harness_swap.infrastructure.locking import FileLock as _FileLock


class FileLock(_FileLock):
    error_class = LockError


__all__ = ["FileLock"]
