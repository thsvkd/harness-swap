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
import time
from pathlib import Path

from claude_swap.exceptions import ClaudeSwitchError, LockError
from claude_swap.locking import FileLock
from claude_swap.settings import atomic_write_json

FILENAME = "consumed_grants.json"
# Longer than any refresh token lives (about 30 days), so a dropped row can no
# longer name a token the server would accept or count as reuse. A row is never
# dropped for space, and an unresolved reservation is never dropped at all.
CONSUMED_RETENTION_S = 400 * 24 * 3600
# About 30 accounts rotating every 7 hours for 400 days. Past it, POSTs stop.
MAX_BYTES = 8 * 1024 * 1024
RESERVED = "reserved"
CONSUMED = "consumed"
OBSERVED_POST = "observed-post"
NEW_LOGIN = "new-login"


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
        and isinstance(row.get("at"), (int, float))
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
            if mutate(rows) is False:
                return
            oldest = time.time() - CONSUMED_RETENTION_S
            rows = {
                fingerprint: row
                for fingerprint, row in rows.items()
                if row["state"] == RESERVED or row["at"] >= oldest
            }
            if len(json.dumps(rows, indent=2).encode()) > MAX_BYTES:
                raise LedgerUnreadable(f"{FILENAME} is too large")
            atomic_write_json(path, rows)
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


def _row(identity: tuple[str, str], state: str, successor: str | None = None) -> dict:
    # The account, not the slot: `move` and `swap` renumber slots.
    row = {
        "state": state,
        "email": identity[0],
        "organizationUuid": identity[1] or "",
        "at": time.time(),
    }
    if successor:
        row["successorFp"] = successor
    return row


def reserve(fingerprint: str, identity: tuple[str, str]) -> bool:
    """Claim this token for one POST. False when any row already names it.

    One step under the ledger's lock: two consumers cannot both see it absent.
    Raises :class:`LedgerUnreadable`, which forbids the POST too.
    """
    claimed = False

    def mutate(rows: dict) -> bool:
        nonlocal claimed
        if fingerprint in rows:
            return False
        rows[fingerprint] = _row(identity, RESERVED)
        claimed = True
        return True

    _rewrite(mutate)
    return claimed


def record(
    fingerprint: str, identity: tuple[str, str], state: str, successor: str | None = None
) -> None:
    """Settle a row. ``successor`` is the fingerprint this token was exchanged for,
    the evidence keepalive needs to tell a successor from a rival. Raises
    :class:`LedgerUnreadable`."""

    def mutate(rows: dict) -> None:
        rows.pop(fingerprint, None)
        rows[fingerprint] = _row(identity, state, successor)

    _rewrite(mutate)


def record_lineage(
    predecessor: str, successor: str | None, identity: tuple[str, str], because: str
) -> None:
    """Rule L, the one writer of "this token is spent, and that one came from it":
    our own POST of it (``OBSERVED_POST``), or a provably new login (``NEW_LOGIN``).
    Nothing else may record it: a slot sync or a cleanup that invents this record lets
    a spent token through the next refresh. Raises :class:`LedgerUnreadable`."""
    if because not in (OBSERVED_POST, NEW_LOGIN):
        raise ValueError(f"not a source of lineage: {because}")
    record(predecessor, identity, CONSUMED, successor)


def release(fingerprint: str) -> None:
    """The request provably changed nothing. Raises :class:`LedgerUnreadable`."""
    _rewrite(lambda rows: rows.pop(fingerprint, None))
