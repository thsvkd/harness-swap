"""Human and JSON rendering for the hswap CLI.

JSON payloads carry ``schemaVersion`` (bumped only on a breaking change) and
are built only from core models, which hold no secret material. As a last
line of defence :func:`emit_json` refuses to print anything that looks like a
token or key.
"""

from __future__ import annotations

import json
import sys
import time

from harness_swap.core.models import Account, UsageSnapshot, UsageState
from harness_swap.infrastructure.secrets import looks_secret

SCHEMA_VERSION = 1


class SecretLeak(RuntimeError):
    pass


def emit_json(payload: dict) -> None:
    text = json.dumps({"schemaVersion": SCHEMA_VERSION, **payload}, indent=2)
    if looks_secret(text):
        raise SecretLeak("refusing to print output that looks like it contains a credential")
    print(text)


def error_json(exc: BaseException) -> dict:
    return {"error": {"type": type(exc).__name__, "message": str(exc)}}


def _ago(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d{(seconds % 86400) // 3600}h"


def usage_text(snap: UsageSnapshot | None, now: float | None = None) -> str:
    if snap is None:
        return ""
    now = time.time() if now is None else now
    parts = []
    for w in snap.windows:
        pct = "?" if w.used_percent is None else f"{w.used_percent:.0f}%"
        reset = f" (resets in {_ago(w.resets_at - now)})" if w.resets_at and w.resets_at > now else ""
        parts.append(f"{w.name} {pct}{reset}")
    text = ", ".join(parts)
    if snap.state is not UsageState.AVAILABLE:
        label = str(snap.state).replace("_", " ")
        if snap.detail:
            label += f": {snap.detail}"
        text = f"{label} [{text}]" if text else label
    age = snap.age_s(now)
    if age is not None and snap.windows:
        text += f" · measured {_ago(age)} ago"
    return text


def account_line(acc: Account, show_provider: bool = False) -> str:
    """One account row; ``show_provider`` for harnesses that front several providers."""
    mark = "*" if acc.active else (" " if acc.active is False else "?")
    slot = f"{acc.slot:>2}" if acc.slot is not None else " -"
    alias = f" ({acc.alias})" if acc.alias else ""
    provider = f" [{acc.provider}]" if show_provider and acc.provider else ""
    mode = f" {acc.auth_mode}" if acc.auth_mode in ("api_key",) else ""
    return f" {mark} {slot}  {acc.label}{alias}{provider}{mode}"


def err(message: str) -> None:
    print(message, file=sys.stderr)
