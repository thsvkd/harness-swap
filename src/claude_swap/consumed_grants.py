"""Refresh tokens this machine has already spent, by fingerprint.

Presenting a consumed refresh token can make the server revoke the whole token
family, which logs out every process. Only keepalive and keychain-required mode
record here; `oauth.try_refresh_oauth_credentials` refuses whatever is recorded.
The file holds fingerprints and slot numbers, never a token.
"""

from __future__ import annotations

import json
import logging

from claude_swap.exceptions import LockError
from claude_swap.locking import FileLock
from claude_swap.paths import get_backup_root
from claude_swap.settings import atomic_write_json

FILENAME = "consumed_grants.json"
# Oldest entries drop off: at one rotation per 7 hours, about 75 days.
MAX_ENTRIES = 256

_logger = logging.getLogger("claude-swap")


def _read(path) -> dict:
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return rows if isinstance(rows, dict) else {}


def slot_of(fingerprint: str | None) -> str | None:
    """The slot that spent this lineage (``"unmanaged"`` for no slot), or None."""
    return _read(get_backup_root() / "cache" / FILENAME).get(fingerprint)


def record(fingerprint: str, slot: str) -> None:
    """Never raises: the POST already happened and its successor still needs storing.

    shortcut: rows name the slot at spend time, so `move`/`swap` leaves them stale
    and a drift check can misattribute an old copy; store the account uuid if that
    ever matters.
    """
    path = get_backup_root() / "cache" / FILENAME
    try:
        with FileLock(path.with_suffix(".lock")):
            rows = _read(path)
            rows.pop(fingerprint, None)
            rows[fingerprint] = slot
            atomic_write_json(path, dict(list(rows.items())[-MAX_ENTRIES:]))
    except (OSError, LockError) as e:
        _logger.warning("could not record a consumed grant: %s", type(e).__name__)
