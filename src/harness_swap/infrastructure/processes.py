"""Find running processes by executable name (for restart-required notices).

Best effort by design: the answer only decides whether to *tell* the user a
restart is needed, never whether to act, so an unreadable process table
yields ``None`` ("unknown") rather than an error.
"""

from __future__ import annotations

import os
import sys

from harness_swap.infrastructure import spawn


def find(names: set[str]) -> list[int] | None:
    """PIDs whose executable basename is in ``names``; ``None`` if unknowable."""
    try:
        if sys.platform == "win32":
            out = spawn.run(
                ["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10
            ).stdout
            rows = [line.strip('"').split('","') for line in out.splitlines() if line]
            pairs = [(r[1], r[0].removesuffix(".exe")) for r in rows if len(r) > 1]
        else:
            out = spawn.run(
                ["ps", "-A", "-o", "pid=,comm="], capture_output=True, text=True, timeout=10
            ).stdout
            pairs = []
            for line in out.splitlines():
                pid, _, comm = line.strip().partition(" ")
                pairs.append((pid, os.path.basename(comm.strip())))
    except Exception:  # noqa: BLE001 - any failure means "unknown"
        return None
    me = os.getpid()
    return [int(pid) for pid, name in pairs if name in names and pid.isdigit() and int(pid) != me]
