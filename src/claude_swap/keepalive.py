"""``cswap keepalive``: one owner for the active login's refresh.

Claude Code refreshes an access token inside the last 5 minutes of its life, and
on macOS a process that cannot reach the login keychain reads and writes the
plaintext file only. So the same login can live in two stores that each refresh
on their own; the refresh token rotates and the loser presents a consumed one.
Run from the GUI session every few minutes, this refreshes well before that
window and keeps both stores on one generation, so no Claude Code process ever
reaches it. On Linux/Windows there is one store and only the refresh applies.

The report is also the contract with whatever watches this machine: every run
writes ``<store root>/cache/keepalive.json``. It carries no token and no path.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext

from claude_swap import macos_keychain, oauth
from claude_swap.claude_locks import claude_credentials_lock
from claude_swap.credentials import (
    CLAUDE_CODE_KEYCHAIN_SERVICE,
    _active_profile_is_default,
    _credential_object,
)
from claude_swap.exceptions import (
    ClaudeSwitchError,
    KeychainUnavailableError,
    LockError,
)
from claude_swap.locking import FileLock
from claude_swap.models import Platform
from claude_swap.paths import get_credentials_path
from claude_swap.settings import atomic_write_json
from claude_swap.usage_store import PERMANENT_AUTH_ERRORS, FetchRecord

DEFAULT_AHEAD_S = 3600.0
REPORT_FILENAME = "keepalive.json"
# Same bound as `_fetch_active_usage`: the POST runs under locks a concurrent
# switch waits on for 10 s.
_POST_TIMEOUT_S = 6.0

_MESSAGES = {
    "keychain_unavailable": (
        "The login keychain is not reachable from this process; "
        "run keepalive from the logged-in GUI session."
    ),
    "relogin_required": (
        "The refresh token was rejected; log in again and re-add the account."
    ),
    "split_brain": (
        "The two stores hold different logins and the older one could not be "
        "preserved; nothing was synced."
    ),
    "refresh_failed": "The token refresh failed; the next run retries.",
    "no_credentials": "No active Claude login found.",
    "locked": "Credential locks stayed held; the next run retries.",
    "unmanaged": "The active login matches no managed account; add it to back it up.",
}
_UNSUPPORTED_STORE = (
    "CLAUDE_CONFIG_DIR or CLAUDE_SECURESTORAGE_CONFIG_DIR names a credential store "
    "keepalive does not manage; run it from a normal shell."
)

_logger = logging.getLogger("claude-swap")


class _Stop(Exception):
    """End the run with this report error."""

    def __init__(self, kind: str, message: str | None = None):
        super().__init__(kind)
        self.kind = kind
        self.message = message or _MESSAGES[kind]


def run_keepalive(
    switcher,
    *,
    ahead: float = DEFAULT_AHEAD_S,
    ensure_file: bool = False,
    dry_run: bool = False,
) -> dict:
    """One pass. Never raises for an operational failure: the report says it."""
    report = {
        "schemaVersion": 1,
        "checkedAt": time.time(),
        "ok": False,
        "action": "none",
        "note": None,
        "activeSlot": None,
        "accessExpiresAt": None,
        "loginExpiresAt": None,
        "error": None,
    }
    if dry_run:
        report["dryRun"] = True
    try:
        _keep(switcher, report, ahead, ensure_file, dry_run)
    except _Stop as stop:
        report["error"] = {"type": stop.kind, "message": stop.message}
    except KeychainUnavailableError:
        report["error"] = _error("keychain_unavailable")
    except LockError:
        report["error"] = _error("locked")
    except (
        ClaudeSwitchError,
        macos_keychain.KeychainError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as e:
        _logger.warning("keepalive failed: %s", type(e).__name__)  # the text may hold a path
        report["error"] = _error("refresh_failed")
    report["ok"] = report["error"] is None
    try:
        atomic_write_json(switcher.backup_dir / "cache" / REPORT_FILENAME, report)
    except OSError as e:
        _logger.warning("could not write %s: %s", REPORT_FILENAME, type(e).__name__)
    return report


def _error(kind: str) -> dict:
    return {"type": kind, "message": _MESSAGES[kind]}


def _keep(switcher, report, ahead, ensure_file, dry_run) -> None:
    store = switcher._store
    macos = switcher.platform == Platform.MACOS

    identity = switcher._get_current_account()
    data = switcher._get_sequence_data() or {}
    slot = switcher._find_account_slot(data, *identity) if identity else None
    report["activeSlot"] = int(slot) if slot else None

    # Switch and consume resolve the default store only; syncing another
    # profile's file against the default Keychain item would create a split.
    if os.environ.get("CLAUDE_SECURESTORAGE_CONFIG_DIR") or (
        macos and not _active_profile_is_default()
    ):
        raise _Stop("refresh_failed", _UNSUPPORTED_STORE)
    if macos:
        if macos_keychain.keychain_reachable(platform="darwin") is False:
            raise _Stop("keychain_unavailable")
        store.keychain_required = True  # whatever the setting says

    token_account = None
    final = None
    with nullcontext() if dry_run else _locks(switcher, slot):
        keychain, file_creds = _read_stores(store, macos)
        if not keychain and not file_creds:
            if store._read_managed_key():
                report["note"] = "api_key"  # nothing here to sync or refresh
                return _finish_unmanaged(report, slot)
            raise _Stop("no_credentials")

        backup = switcher._read_account_credentials_ex(slot, identity[0])[0] if slot else ""
        final = _sync(switcher, report, slot, keychain, file_creds, backup, ensure_file, dry_run)
        if _due(final, ahead):
            if dry_run:
                report["action"] = "refreshed"
            else:
                final, token_account = _refresh(
                    switcher, report, slot, identity, final, backup, ensure_file
                )

    if slot and not dry_run:
        _settle_slot(switcher, report, slot, identity, final, token_account)
    _finish_unmanaged(report, slot)


def _finish_unmanaged(report, slot) -> None:
    if not slot and report["error"] is None:
        report["error"] = _error("unmanaged")


@contextmanager
def _locks(switcher, slot) -> Iterator[None]:
    """Consume lock, then the engine's lock, then Claude Code's: the order
    `_fetch_active_usage` and the switch path use. Timeouts raise LockError."""
    consume = (
        FileLock(switcher.credentials_dir / f".consume-{slot}.lock")
        if slot
        else nullcontext()
    )
    with consume, FileLock(switcher.lock_file), claude_credentials_lock():
        yield


def _read_stores(store, macos: bool) -> tuple[str, str]:
    """The active login as each store holds it, ``""`` when absent."""
    keychain = ""
    if macos:
        value, failed = store._read_one_oauth_keychain(CLAUDE_CODE_KEYCHAIN_SERVICE)
        if failed:
            raise _Stop("keychain_unavailable")
        keychain = value or ""
    path = get_credentials_path()
    file_creds = path.read_text(encoding="utf-8") if path.exists() else ""
    return keychain, file_creds if file_creds.strip() else ""


def _oauth_payload(credentials: str) -> dict:
    data = _credential_object(credentials) or {}
    payload = data.get("claudeAiOauth")
    return payload if isinstance(payload, dict) else {}


def _rank(credentials: str) -> float:
    """``expiresAt`` for picking the newest copy. Claude Code wipes the token
    fields in place when a refresh is rejected, so a copy with no access token
    ranks last whatever date it still carries."""
    payload = _oauth_payload(credentials)
    expires_at = payload.get("expiresAt")
    if not payload.get("accessToken") or isinstance(expires_at, bool):
        return 0
    return expires_at if isinstance(expires_at, (int, float)) else 0


def _due(credentials: str, ahead: float) -> bool:
    payload = _oauth_payload(credentials)
    if not payload.get("accessToken"):
        return True  # nothing usable; the refresh attempt classifies it
    expires_at = payload.get("expiresAt")
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
        return False  # a setup-token carries no expiry and has no refresh token
    return time.time() * 1000 + ahead * 1000 >= expires_at


def _sync(switcher, report, slot, keychain, file_creds, backup, ensure_file, dry_run) -> str:
    """Bring both stores to the authoritative copy; returns what they now hold."""
    store = switcher._store
    macos = switcher.platform == Platform.MACOS
    # A tie goes to the Keychain: it is what Claude Code reads first.
    authoritative = keychain if _rank(keychain) >= _rank(file_creds) and keychain else file_creds
    # The slot holding a newer generation means a live store was stranded on the
    # consumed one (a write that failed after a refresh): `_fetch_active_usage`
    # restores in that case too, and POSTing the live bytes could only fail.
    if slot and _rank(backup) > _rank(authoritative) and _oauth_payload(backup).get("refreshToken"):
        authoritative = backup

    fingerprint = oauth.credential_fingerprint(authoritative)
    losers = {
        creds
        for creds in (keychain, file_creds)
        if creds and creds != authoritative
        and oauth.credential_fingerprint(creds) != fingerprint
    }
    if losers:
        report["note"] = "split_brain"
        if not dry_run:
            for loser in losers:
                try:
                    store._write_unclaimed_credential(
                        loser,
                        {
                            "reason": "keepalive-split-brain",
                            "configSlot": slot or "unmanaged",
                            "fingerprint": oauth.credential_fingerprint(loser),
                        },
                    )
                except (ClaudeSwitchError, OSError) as e:
                    raise _Stop("split_brain") from e

    # The engine's composition with the Keychain as the live store: it wins the
    # machine-shared fields (mcpOAuth, ...), the login comes from the winner.
    live = keychain or file_creds
    composed = (
        authoritative
        if authoritative == live
        else switcher._prepare_credentials_for_activation(authoritative, live)
    )

    write_keychain = macos and keychain != composed
    write_file = (bool(file_creds) or ensure_file) and file_creds != composed
    if not dry_run:
        if write_keychain:
            store._write_oauth_credentials(composed)  # also rewrites a present file
        if write_file and not (write_keychain and file_creds):
            store._write_active_credentials_file(composed)
    if write_keychain:
        report["action"] = "synced-keychain"
    elif write_file:
        report["action"] = "synced-file" if file_creds else "created-file"
    _report_expiry(report, composed)
    return composed


def _report_expiry(report, credentials: str) -> None:
    report["accessExpiresAt"] = oauth.expires_at_iso(
        _oauth_payload(credentials).get("expiresAt")
    )
    report["loginExpiresAt"] = oauth.expires_at_iso(
        _oauth_payload(credentials).get("refreshTokenExpiresAt")
    )


def _refresh(
    switcher, report, slot, identity, current, backup, ensure_file
) -> tuple[str, dict | None]:
    """POST once, under every lock, on bytes just re-read. Writes the successor
    to the Keychain, a present file and the slot."""
    store = switcher._store
    fingerprint = oauth.credential_fingerprint(current)
    # The gate consumes the SLOT's copy, so it only applies when that copy is this
    # lineage, and only with these exact bytes: it reads any other access token as
    # "the world moved on" and hands the older copy back without a POST.
    via_gate = bool(slot and backup and oauth.credential_fingerprint(backup) == fingerprint)
    if via_gate:
        if backup != current:
            switcher._write_account_credentials(slot, identity[0], current)
        outcome = switcher._consume_backup_grant_locked(
            slot, identity[0], current, global_lock_held=True
        )
    else:
        # Unmanaged, or a rotation the slot has not caught up with. Posting the
        # live store's own grant is what Claude Code itself would do.
        outcome = oauth.try_refresh_oauth_credentials(current, timeout_s=_POST_TIMEOUT_S)

    if not outcome.credentials:
        if outcome.error in PERMANENT_AUTH_ERRORS:
            if slot:
                switcher._usage_store.record(
                    {slot: FetchRecord(
                        error=outcome.error,
                        struck_fp=outcome.consumed_fp or fingerprint,
                    )},
                    {slot: tuple(identity)},
                )
            raise _Stop("relogin_required")
        raise _Stop("refresh_failed")

    final = switcher._prepare_credentials_for_activation(outcome.credentials, current)
    try:
        store._write_oauth_credentials(final)
        if ensure_file and not get_credentials_path().exists():
            store._write_active_credentials_file(final)
    except (ClaudeSwitchError, OSError):
        if not via_gate:  # the grant is spent and no other store holds its successor
            _stash_successor(store, outcome.credentials, fingerprint)
        raise
    report["action"] = "refreshed"
    _report_expiry(report, final)
    if outcome.error is not None:
        # The gate parked the successor rather than persisting it to the slot;
        # its next pass adopts it.
        raise _Stop("refresh_failed")
    return final, outcome.token_account


def _stash_successor(store, credentials: str, consumed_fp: str | None) -> None:
    try:
        store._write_unclaimed_credential(
            credentials,
            {
                "reason": "keepalive-live-write-failed",
                "consumedFp": consumed_fp,
                "fingerprint": oauth.credential_fingerprint(credentials),
            },
        )
    except (ClaudeSwitchError, OSError):
        _logger.error("keepalive: a refreshed credential could not be stored anywhere")


def _settle_slot(switcher, report, slot, identity, final, token_account) -> None:
    """The slot's records, with no lock held: the identity helpers may take it."""
    email, org_uuid = identity
    store = switcher._usage_store
    if report["action"] == "refreshed":
        store.clear_dead_token([slot], {slot: tuple(identity)})
    login_expires_at = report["loginExpiresAt"]
    if store.entries({slot: tuple(identity)})[slot].login_expires_at != login_expires_at:
        store.set_login_expiry(slot, tuple(identity), login_expires_at)

    # A lineage the slot does not hold yet, or a token answering as someone else.
    if token_account:
        match = switcher._resolved_matches_slot_identity(slot, token_account)
        if match is not None:
            key = switcher._lineage_key(slot, email, oauth.credential_fingerprint(final) or "")
            switcher._probe_verdicts[key] = match
    switcher._resync_rotated_backup(slot, email, org_uuid, final)
    key = switcher._lineage_key(slot, email, oauth.credential_fingerprint(final) or "")
    if switcher._probe_verdicts.get(key) is False:
        report["error"] = _error("unmanaged")
