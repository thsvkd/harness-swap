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

Liveness: hswap takes an exclusive lock on ``<home>/.hswap-session.lock``
(under the account store's lock, so it cannot race a switch), starts the
harness as its child and keeps the lock until the child exits. The
descriptor is not inheritable, so servers or shells the harness leaves
behind never keep a session "in use". The kernel drops the lock if hswap
itself dies, so :func:`in_use` needs no pid files. Trade-off: if hswap is
killed with SIGKILL while the harness keeps running, the session no longer
counts as in use.
"""

from __future__ import annotations

import os
import signal
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
    """Take the session lock; returns the descriptor that holds it.

    ``profile`` may also be the harness's default home (a session on the
    active login); an existing directory keeps its permissions.
    """
    if not profile.exists():
        mkdir_private(profile)
    fd = os.open(profile / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    if not _try_lock(fd):
        os.close(fd)
        raise HswapError(f"another hswap session is already running on {profile}")
    return fd


def launch(argv: list[str], env: dict[str, str], lock_fd: int | None = None) -> int:
    """Run ``argv`` with ``env`` in the foreground; return its exit status.

    The harness shares the terminal and process group, so Ctrl+C / Ctrl+Z
    reach it directly; this process ignores SIGINT/SIGQUIT while waiting and
    forwards SIGTERM/SIGHUP. ``lock_fd`` (the session lock) is released after
    the child exits. A child killed by signal N yields ``128 + N``, as a
    shell reports it.
    """
    try:
        proc = subprocess.Popen(argv, env=env)
    except OSError as exc:
        if lock_fd is not None:
            os.close(lock_fd)
        raise HswapError(f"could not start {argv[0]}: {exc}") from None
    forwarded = {}
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGQUIT):
            forwarded[sig] = signal.signal(sig, signal.SIG_IGN)
        for sig in (signal.SIGTERM, signal.SIGHUP):
            forwarded[sig] = signal.signal(sig, lambda signum, _frame: proc.send_signal(signum))
    try:
        while True:
            try:
                code = proc.wait()
                break
            except KeyboardInterrupt:  # Windows: the console delivers Ctrl+C to both
                continue
    finally:
        for sig, handler in forwarded.items():
            signal.signal(sig, handler)
        if lock_fd is not None:
            os.close(lock_fd)
    return 128 - code if code < 0 else code
