"""Refresh tokens this machine has spent or may have spent, by fingerprint.

Presenting a consumed refresh token can make the server revoke the whole token
family, which logs out every process. So where this ledger is in use a token is
reserved here, durably, before its POST, and the outcome settles the entry: a
success or a rejected grant marks it consumed, a request that provably changed
nothing clears it, and anything else leaves it reserved because the server may have
rotated it. `oauth.try_refresh_oauth_credentials` refuses whatever is listed.

Only keepalive and keychain-required mode start the file; once it exists every
engine POST uses it. It holds fingerprints and account identities, never a token.
A missing file is an empty ledger. A file that cannot be read fails closed, since
an empty answer would reopen consumption, and is never rewritten.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from claude_swap.exceptions import ClaudeSwitchError, LockError
from claude_swap.locking import FileLock
from claude_swap.settings import atomic_write_json

FILENAME = "consumed_grants.json"
# Oldest entries drop off: at one rotation per 7 hours, about 58 days.
MAX_ENTRIES = 200
RESERVED = "reserved"
CONSUMED = "consumed"


class LedgerUnreadable(ClaudeSwitchError):
    """The ledger cannot answer or cannot record: nothing may be POSTed."""


def _path() -> Path:
    # Here because paths reaches oauth, which imports this module.
    from claude_swap.paths import get_backup_root

    return get_backup_root() / "cache" / FILENAME


def _valid(row: object) -> bool:
    return (
        isinstance(row, dict)
        and row.get("state") in (RESERVED, CONSUMED)
        and isinstance(row.get("email"), str)
        and isinstance(row.get("organizationUuid"), str)
    )


def _read(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError):
        raise LedgerUnreadable(f"{FILENAME} cannot be read") from None
    try:
        rows = json.loads(text)
    except ValueError:
        raise LedgerUnreadable(f"{FILENAME} is corrupt") from None
    if not isinstance(rows, dict) or not all(_valid(row) for row in rows.values()):
        raise LedgerUnreadable(f"{FILENAME} is corrupt")
    return rows


def in_use() -> bool:
    return _path().exists()


def entry(fingerprint: str | None) -> dict | None:
    """This lineage's row. Raises :class:`LedgerUnreadable` rather than guess."""
    return _read(_path()).get(fingerprint)


def _rewrite(mutate) -> None:
    path = _path()
    try:
        with FileLock(path.with_suffix(".lock")):
            rows = _read(path)  # raises before anything is written over it
            mutate(rows)
            atomic_write_json(path, dict(list(rows.items())[-MAX_ENTRIES:]))
            # The rename is only durable once the directory is; a reservation
            # lost to a crash would let the POST it guarded happen again.
            if sys.platform != "win32":  # a directory cannot be opened there
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
    except (OSError, LockError):
        raise LedgerUnreadable(f"{FILENAME} cannot be written") from None


def record(fingerprint: str, identity: tuple[str, str], state: str) -> None:
    """Raises :class:`LedgerUnreadable`; a reservation that failed forbids the POST.

    The row names the account, not the slot: `move` and `swap` renumber slots.
    """

    def mutate(rows: dict) -> None:
        rows.pop(fingerprint, None)
        rows[fingerprint] = {
            "state": state,
            "email": identity[0],
            "organizationUuid": identity[1] or "",
        }

    _rewrite(mutate)


def release(fingerprint: str) -> None:
    """The request provably changed nothing. Raises :class:`LedgerUnreadable`."""
    _rewrite(lambda rows: rows.pop(fingerprint, None))
