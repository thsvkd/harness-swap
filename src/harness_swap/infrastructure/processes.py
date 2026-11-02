"""Find running processes of a harness by executable name.

The answer feeds restart notices and decides whether ``hswap <id> refresh``
may touch the active login, so it errs towards "running": an unreadable
process table yields ``None`` ("unknown"), and a harness started through a
wrapper, an emulator or a versioned binary (``qemu-aarch64 -cpu max
~/.grok/downloads/grok-linux-aarch64``) is found by its command line.
"""

from __future__ import annotations

import os
import sys

from harness_swap.infrastructure import spawn


def _is_harness_path(token: str, names: set[str]) -> bool:
    """``token`` is an executable file ``name``, ``name-<suffix>`` or a link to one.

    Only absolute paths of existing executables count, so neither the bare word in
    ``hswap grok refresh`` nor a path quoted in some shell command line matches.
    """
    if not os.path.isabs(token):
        return False
    real = os.path.realpath(token)
    if not (os.path.isfile(real) and os.access(real, os.X_OK)):
        return False
    for path in (token, real):
        base = os.path.basename(path)
        if any(base == n or base.startswith(n + "-") for n in names):
            return True
    return False


def find(names: set[str]) -> list[int] | None:
    """PIDs running an executable named in ``names``; ``None`` if unknowable."""
    try:
        if sys.platform == "win32":
            out = spawn.run(
                ["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10
            ).stdout
            rows = [line.strip('"').split('","') for line in out.splitlines() if line]
            pids = {r[1] for r in rows if len(r) > 1 and r[0].removesuffix(".exe") in names}
        else:
            pids = set()
            out = spawn.run(
                ["ps", "-A", "-o", "pid=,comm="], capture_output=True, text=True, timeout=10
            ).stdout
            for line in out.splitlines():
                pid, _, comm = line.strip().partition(" ")
                if os.path.basename(comm.strip()) in names:
                    pids.add(pid)
            # ponytail: argv split on spaces, so a path containing one is missed; /proc cmdline if that matters.
            out = spawn.run(
                ["ps", "-A", "-ww", "-o", "pid=,args="], capture_output=True, text=True, timeout=10
            ).stdout
            for line in out.splitlines():
                pid, _, args = line.strip().partition(" ")
                if any(_is_harness_path(token, names) for token in args.split()):
                    pids.add(pid)
    except Exception:  # noqa: BLE001 - any failure means "unknown"
        return None
    me = os.getpid()
    return sorted(int(pid) for pid in pids if pid.isdigit() and int(pid) != me)
