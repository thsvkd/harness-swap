"""Plain-text helpers shared by both dashboards and the Claude engine's CLI.

No Textual or Rich import here: the engine's plain CLI paths use
:func:`reset_clock_string` too, and must not pay for the TUI's imports.
"""

from __future__ import annotations

import time
from datetime import datetime


def format_duration(seconds: float) -> str:
    """Compact duration: "45s", "12m", "2h 13m", "3d 4h"."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h}h {m}m" if m else f"{h}h"
    d, h = divmod(s // 3600, 24)
    return f"{d}d {h}h" if h else f"{d}d"


def reset_clock_string(reset_utc: datetime, now_utc: datetime) -> str:
    """Absolute reset time in local time: "20:39" same-day, else "Jul 5 08:59"."""
    reset_local = reset_utc.astimezone()
    now_local = now_utc.astimezone()
    if reset_local.date() == now_local.date():
        return reset_local.strftime("%H:%M")
    day = str(reset_local.day)
    return reset_local.strftime(f"%b {day} %H:%M")


def clock_stamp() -> str:
    """HH:MM:SS local-time stamp for the event log."""
    return time.strftime("%H:%M:%S")
