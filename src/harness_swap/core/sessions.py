"""Isolated sessions: run a harness as one account without touching the default login.

Many harnesses take their whole state directory from an environment variable
(``CODEX_HOME``, ``GROK_HOME``, ``CLAUDE_CONFIG_DIR``). An isolated session
points that variable at the account's own directory under hswap's store,
which already holds that account's credential snapshot. The harness then
reads -- and refreshes -- that copy in place, so no token is ever copied
back and forth while it runs.

What is *shared* with the default home is up to the adapter: typically user
configuration and instructions (``config.toml``, ``AGENTS.md``, rules,
skills) are linked in, while credentials and session history stay per
account. Links are made only for names that exist in the default home and
not yet in the profile, and existing files are never replaced.

Liveness: :func:`launch` takes an exclusive lock on ``<home>/.hswap-session.lock``
and hands the open descriptor to the harness process (POSIX ``exec``) or
holds it while waiting (Windows). The kernel releases it when that process
exits -- including on Ctrl+C or a crash -- so :func:`in_use` is exact
without pid files.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from harness_swap.core.errors import HswapError
from harness_swap.core.store import mkdir_private

LOCK_NAME = ".hswap-session.lock"

if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI only
    import msvcrt
else:
    import fcntl


def link_shared(profile: Path, default_home: Path, names: tuple[str, ...]) -> list[str]:
    """Symlink ``names`` from ``default_home`` into ``profile``. Returns names linked.

    POSIX only: on Windows creating symlinks needs elevated rights or
    developer mode, so the profile simply starts without shared files.
    """
    mkdir_private(profile)
    linked = []
    if sys.platform == "win32":
        return linked
    for name in names:
        src = default_home / name
        dst = profile / name
        if not src.exists() or dst.exists() or dst.is_symlink():
            continue
        os.symlink(src, dst)
        linked.append(name)
    return linked


def _try_lock(fd: int) -> bool:
    try:
        if sys.platform == "win32":
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def in_use(profile: Path) -> bool:
    """True while an isolated session launched by hswap runs on ``profile``."""
    path = profile / LOCK_NAME
    if not path.exists():
        return False
    fd = os.open(path, os.O_RDWR)
    try:
        if not _try_lock(fd):
            return True
        if sys.platform == "win32":
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def acquire(profile: Path) -> int:
    """Take the session lock; returns the descriptor that holds it."""
    mkdir_private(profile)
    fd = os.open(profile / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    if not _try_lock(fd):
        os.close(fd)
        raise HswapError(f"another hswap session is already running on {profile}")
    return fd


def launch(argv: list[str], env: dict[str, str], lock_fd: int) -> int:
    """Run ``argv`` with ``env`` while ``lock_fd`` stays locked.

    POSIX: the lock descriptor is made inheritable and the process is
    replaced with ``exec``, so the harness itself owns the lock (and the
    terminal, signals and exit status). Never returns.

    Windows: runs the harness as a child, keeps the lock until it exits,
    and returns its exit code. Ctrl+C reaches the child through the shared
    console; this process just keeps waiting for it.
    """
    if sys.platform != "win32":
        os.set_inheritable(lock_fd, True)
        os.execvpe(argv[0], argv, env)
    proc = subprocess.Popen(argv, env=env)  # pragma: no cover - Windows path
    while True:  # pragma: no cover - Windows path
        try:
            return proc.wait()
        except KeyboardInterrupt:
            continue
