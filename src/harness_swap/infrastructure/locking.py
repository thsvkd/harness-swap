"""Cross-process advisory file locking (``flock`` on POSIX, ``msvcrt`` on Windows).

Used for hswap's own stores and, best-effort, for a harness's own lock file
around a credential write (Codex ``auth.lock``, Grok ``auth.json.lock``), so
the file is opened without truncation: a harness may keep a pid in it.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import IO

# Platform-specific imports for file locking
if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

from harness_swap.core.errors import LockError


class FileLock:
    """Cross-process file lock using platform-specific APIs.

    ``error_class`` is what ``with`` raises on a timeout; a caller with its
    own error hierarchy (the Claude engine) subclasses and overrides it.
    """

    error_class: type[Exception] = LockError

    def __init__(self, lock_path: Path, timeout: float = 10.0):
        self.lock_path = lock_path
        self.timeout = timeout
        self._lock_file: IO | None = None
        self._locked = False

    def acquire(self, timeout: float | None = None) -> bool:
        """Acquire exclusive lock with timeout.

        Args:
            timeout: Maximum seconds to wait for lock. Defaults to the
                timeout given at construction.

        Returns:
            True if lock acquired, False if timeout.
        """
        if timeout is None:
            timeout = self.timeout
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        # Append mode, not "w": never truncate a lock file someone else owns.
        # The seek pins msvcrt's byte-range lock to offset 0 for everyone.
        self._lock_file = open(self.lock_path, "a+")
        self._lock_file.seek(0)

        start = time.monotonic()
        while True:
            try:
                if sys.platform == "win32":
                    # Windows: use msvcrt for file locking
                    msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    # POSIX: use fcntl for file locking
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._locked = True
                return True
            except (BlockingIOError, OSError):
                if time.monotonic() - start > timeout:
                    self._lock_file.close()
                    self._lock_file = None
                    return False
                time.sleep(0.1)

    def release(self) -> None:
        """Release the lock."""
        if self._lock_file and self._locked:
            if sys.platform == "win32":
                # Windows: unlock using msvcrt
                try:
                    msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass  # File may already be unlocked
            else:
                # POSIX: unlock using fcntl
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None
            self._locked = False

    def __enter__(self) -> FileLock:
        if not self.acquire():
            raise self.error_class("Failed to acquire lock - another instance may be running")
        return self

    def __exit__(self, *args) -> None:
        self.release()
