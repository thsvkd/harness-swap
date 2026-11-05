"""``cswap keepalive``: one owner for the active login's refresh.

Claude Code refreshes an access token inside the last 5 minutes of its life, and
on macOS a process that cannot reach the login keychain reads and writes the
plaintext file only. So the same login can live in two stores that each refresh
on their own; the refresh token rotates and the loser presents a consumed one.
Run from the GUI session every few minutes, this refreshes well before that
window and keeps both stores on one generation, so no Claude Code process ever
reaches it. On Linux/Windows there is one store and only the refresh applies.

The invariant: once a POST consumed a grant, its successor lands where the next
run looks (the stores, the slot, or the stash), and no run POSTs a consumed token.

The report is also the contract with whatever watches this machine: every run
writes ``<store root>/cache/keepalive.json``. It carries no token and no path.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from typing import NamedTuple

from claude_swap import consumed_grants, macos_keychain, oauth
from claude_swap.claude_locks import claude_credentials_lock
from claude_swap.credentials import (
    CLAUDE_CODE_KEYCHAIN_SERVICE,
    _active_profile_is_default,
    _credential_object,
    credential_generation,
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
# The consume lock is named after the slot, so a switch landing while we wait for
# it means releasing everything and starting over.
_SLOT_ATTEMPTS = 3
_UNMANAGED = "unmanaged"  # the stash's and the ledger's name for "no slot"

_MESSAGES = {
    "keychain_unavailable": (
        "The login keychain is not reachable from this process; "
        "run keepalive from the logged-in GUI session."
    ),
    "relogin_required": (
        "The refresh token was rejected or already spent; log in again and "
        "re-add the account."
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
_FILE_NOT_UPDATED = "file store could not be updated"
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


class _Active(NamedTuple):
    """Who `.claude.json` says is logged in, read once."""

    switcher: object
    identity: tuple[str, str] | None
    slot: str | None
    accounts: dict


def run_keepalive(
    switcher,
    *,
    ahead: float = DEFAULT_AHEAD_S,
    ensure_file: bool = False,
    dry_run: bool = False,
) -> dict:
    """One pass. Never raises for a failure of the run: the report says it."""
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
    except Exception as e:  # noqa: BLE001 - a watcher must always get a report
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


def _read_active(switcher) -> _Active:
    identity = switcher._get_current_account()
    data = switcher._get_sequence_data() or {}
    slot = switcher._find_account_slot(data, *identity) if identity else None
    return _Active(switcher, identity, slot, data.get("accounts", {}))


def _keep(switcher, report, ahead, ensure_file, dry_run) -> None:
    store = switcher._store
    macos = switcher.platform == Platform.MACOS
    active = _read_active(switcher)
    report["activeSlot"] = int(active.slot) if active.slot else None

    # Switch and consume resolve the default store only; syncing another
    # profile's file against the default Keychain item would create a split.
    if os.environ.get("CLAUDE_SECURESTORAGE_CONFIG_DIR") or (
        macos and not _active_profile_is_default()
    ):
        raise _Stop("refresh_failed", _UNSUPPORTED_STORE)
    if macos:
        if macos_keychain.keychain_reachable(platform="darwin") is False:
            raise _Stop("keychain_unavailable")
        store.pin_keychain()
    store.records_consumed = True

    if dry_run:
        _pass(active, report, ahead, ensure_file, dry_run=True)
        _finish(report, active, None, None, dry_run=True)
        return
    for _ in range(_SLOT_ATTEMPTS):
        expected = _read_active(switcher).slot
        with _locks(switcher, expected):
            active = _read_active(switcher)
            report["activeSlot"] = int(active.slot) if active.slot else None
            if active.slot != expected:
                continue
            final, token_account = _pass(active, report, ahead, ensure_file, dry_run=False)
        _finish(report, active, final, token_account, dry_run=False)
        return
    raise _Stop("locked")


def _finish(report, active, final, token_account, dry_run) -> None:
    if active.slot and final and not dry_run:
        _settle_slot(active, report, final, token_account)
    if not active.slot and report["error"] is None:
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


def _pass(active, report, ahead, ensure_file, dry_run) -> tuple[str | None, dict | None]:
    switcher = active.switcher
    store = switcher._store
    keychain, file_creds = _read_stores(store, switcher.platform == Platform.MACOS)
    if not keychain and not file_creds:
        if store._read_managed_key():
            report["note"] = "api_key"  # nothing here to sync or refresh
            return None, None
        raise _Stop("no_credentials")

    backup, parked_entry = _adopted_backup(active, keychain, file_creds, dry_run)
    final = _sync(active, report, keychain, file_creds, backup, ensure_file, dry_run)
    if parked_entry and oauth.credential_fingerprint(final) == oauth.credential_fingerprint(backup):
        switcher._retire_stash_entry(parked_entry, _UNMANAGED)
    token_account = None
    if _due(final, ahead):
        if dry_run:
            report["action"] = "refreshed"
        else:
            final, token_account = _refresh(active, report, final, backup, ensure_file)
    return final, token_account


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


def _adopted_backup(active, keychain, file_creds, dry_run) -> tuple[str, str | None]:
    """The slot's copy, after adopting a successor parked for what the stores
    still hold: posting past it would present a spent token. A login with no slot
    has only the stash, whose copy plays the same part. Returns the entry to retire."""
    switcher = active.switcher
    email = active.identity[0] if active.identity else ""
    backup = ""
    if active.slot:
        backup = switcher._read_account_credentials_ex(active.slot, email)[0]
    if dry_run:
        return backup, None
    held = [creds for creds in (backup, keychain, file_creds) if creds]
    if active.slot:
        for creds in held:
            adopted = switcher._adopt_stashed_successor(active.slot, email, creds)
            if adopted:
                return adopted, None
        return backup, None
    spent = {oauth.credential_fingerprint(creds) for creds in held}
    for entry_id, row in switcher._store._read_stash_manifest().items():
        if (
            row.get("configSlot") == _UNMANAGED
            and str(row.get("reason", "")).startswith("keepalive-")
            and row.get("consumedFp") in spent
        ):
            parked, _ = switcher._store._read_unclaimed_credential(entry_id)
            if parked:
                return parked, entry_id
    return backup, None


def _oauth_payload(credentials: str) -> dict:
    data = _credential_object(credentials) or {}
    payload = data.get("claudeAiOauth")
    return payload if isinstance(payload, dict) else {}


def _expires_at(credentials: str) -> float | None:
    value = _oauth_payload(credentials).get("expiresAt")
    return None if isinstance(value, bool) or not isinstance(value, (int, float)) else value


def _is_expired(credentials: str) -> bool:
    expires_at = _expires_at(credentials)
    return expires_at is not None and expires_at <= time.time() * 1000


def _due(credentials: str, ahead: float) -> bool:
    if not _oauth_payload(credentials).get("accessToken"):
        return True  # nothing usable; the refresh attempt classifies it
    expires_at = _expires_at(credentials)
    if expires_at is None:
        return False  # a setup-token carries no expiry and has no refresh token
    return time.time() * 1000 + ahead * 1000 >= expires_at


def _belongs(active, credentials: str, backup: str, *, probe: bool) -> bool | None:
    """Is this copy the current identity's login? None when nothing can tell."""
    switcher = active.switcher
    fingerprint = oauth.credential_fingerprint(credentials)
    if active.slot and backup and fingerprint == oauth.credential_fingerprint(backup):
        return True
    spender = consumed_grants.slot_of(fingerprint)
    if spender is not None:
        return spender == (active.slot or _UNMANAGED)
    for num, account in active.accounts.items():
        if num != active.slot:
            other = switcher._read_account_credentials_ex(num, account.get("email", ""))[0]
            if other and oauth.credential_fingerprint(other) == fingerprint:
                return False
    token = _oauth_payload(credentials).get("accessToken")
    if not probe or not token or _is_expired(credentials):
        return None
    # Network under these locks, like the POST: bounded at 5 s, and only reached
    # when two stores drifted and nothing local can attribute a copy.
    resolved = oauth.fetch_oauth_profile(token)
    if not resolved:
        return None
    if active.slot:
        return switcher._resolved_matches_slot_identity(active.slot, resolved, backfill=False)
    if not active.identity:
        return None
    email, org_uuid = active.identity
    if resolved.get("email") != email:
        return False if resolved.get("email") else None
    org = resolved.get("organizationUuid")
    return None if org is None else (org or "") == org_uuid


def _sync(active, report, keychain, file_creds, backup, ensure_file, dry_run) -> str:
    """Bring both stores to the authoritative copy; returns what they now hold."""
    switcher = active.switcher
    store = switcher._store
    macos = switcher.platform == Platform.MACOS
    live = [creds for creds in (keychain, file_creds) if creds]
    drifted = len({oauth.credential_fingerprint(creds) for creds in live}) > 1
    verdicts: dict[str, bool | None] = {}

    def belongs(creds: str) -> bool | None:
        if creds not in verdicts:
            verdicts[creds] = _belongs(active, creds, backup, probe=drifted)
        return verdicts[creds]

    # Newest first, the Keychain winning a tie (`sorted` is stable and Claude Code
    # reads it first). The first that is not another account's: a switch this run
    # did not see must not be undone by a stale, longer-lived copy.
    ordered = sorted(live, key=credential_generation, reverse=True)
    authoritative = next((creds for creds in ordered if belongs(creds) is not False), None)
    # The slot holding a newer generation means a live store was stranded on the
    # consumed one (a write that failed after a refresh): `_fetch_active_usage`
    # restores in that case too, and POSTing the live bytes could only fail.
    if _oauth_payload(backup).get("refreshToken") and (
        credential_generation(backup) > credential_generation(authoritative)
        if authoritative
        # Every live copy is another account's. Overwriting a login takes a slot
        # copy that can still work: a duplicated lineage can look foreign too.
        else not _is_expired(backup)
        and consumed_grants.slot_of(oauth.credential_fingerprint(backup)) is None
    ):
        authoritative = backup
    if authoritative is None:
        raise _Stop("unmanaged")

    fingerprint = oauth.credential_fingerprint(authoritative)
    for loser in dict.fromkeys(live):
        if loser == authoritative or oauth.credential_fingerprint(loser) == fingerprint:
            continue
        verdict = belongs(loser)
        if verdict is True or _spent_or_empty(loser, authoritative, verdict):
            continue  # a stale generation of this login is not a split
        if verdict is False:
            report["note"] = "split_brain"
        if not dry_run:
            _stash_loser(active, loser)

    # The engine's composition with the Keychain as the live store: it wins the
    # machine-shared fields (mcpOAuth, ...), the login comes from the winner.
    current = keychain or file_creds
    composed = (
        authoritative
        if authoritative == current
        else switcher._prepare_credentials_for_activation(authoritative, current)
    )
    if not _oauth_payload(composed).get("refreshToken") and any(
        _oauth_payload(creds).get("refreshToken") for creds in live
    ):
        raise _Stop("split_brain")  # never trade a store's refresh token for none

    write_keychain = macos and keychain != composed
    file_wanted = bool(file_creds) or ensure_file
    write_file = file_wanted and file_creds != composed
    if not dry_run:
        if write_keychain:
            store._write_oauth_credentials(composed)  # also rewrites a present file
        if file_wanted and (write_keychain or write_file):
            _settle_file(store, report, composed)
    if write_keychain:
        report["action"] = "synced-keychain"
    elif write_file:
        report["action"] = "synced-file" if file_creds else "created-file"
    _report_expiry(report, composed)
    return composed


def _file_text(path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _settle_file(store, report, expected: str) -> None:
    """Processes that only see the file read it, so a write that silently missed
    it must not read as success. The Keychain and the slot hold the login, so this
    reports instead of raising and the next run's sync repairs the file."""
    path = get_credentials_path()
    for _ in range(2):
        if _file_text(path) == expected:
            return
        try:
            store._write_active_credentials_file(expected)
        except (ClaudeSwitchError, OSError) as e:
            _logger.warning("keepalive: file write failed: %s", type(e).__name__)
    if _file_text(path) != expected:
        report["error"] = {"type": "refresh_failed", "message": _FILE_NOT_UPDATED}


def _spent_or_empty(loser: str, winner: str, verdict: bool | None) -> bool:
    """Nothing worth keeping: wiped token fields, or an unattributed copy that is
    expired and older than the winner, so its refresh token is presumed consumed."""
    payload = _oauth_payload(loser)
    if not payload:
        return False  # unparseable: we cannot say what it held
    if not payload.get("accessToken") and not payload.get("refreshToken"):
        return True
    return (
        verdict is None
        and _is_expired(loser)
        and (_expires_at(loser) or 0) < (_expires_at(winner) or 0)
    )


def _stash_loser(active, loser: str) -> None:
    store = active.switcher._store
    fingerprint = oauth.credential_fingerprint(loser)
    try:
        if any(
            row.get("fingerprint") == fingerprint
            for row in store._list_unclaimed_credentials().values()
        ):
            return
        store._write_unclaimed_credential(
            loser,
            {
                "reason": "keepalive-split-brain",
                "configSlot": active.slot or _UNMANAGED,
                "fingerprint": fingerprint,
            },
        )
    except (ClaudeSwitchError, OSError) as e:
        raise _Stop("split_brain") from e


def _report_expiry(report, credentials: str) -> None:
    report["accessExpiresAt"] = oauth.expires_at_iso(_expires_at(credentials))
    report["loginExpiresAt"] = oauth.login_expires_at_iso(credentials)


def _refresh(active, report, current, backup, ensure_file) -> tuple[str, dict | None]:
    """POST once, under every lock, on bytes just re-read. Writes the successor
    to the Keychain, a present file and the slot."""
    switcher = active.switcher
    store = switcher._store
    slot = active.slot
    fingerprint = oauth.credential_fingerprint(current)
    # The gate consumes the SLOT's copy, so it only applies when that copy is this
    # lineage, and only with these exact bytes: it reads any other access token as
    # "the world moved on" and hands the older copy back without a POST.
    via_gate = bool(slot and backup and oauth.credential_fingerprint(backup) == fingerprint)
    if via_gate:
        email = active.identity[0]
        if backup != current:
            switcher._write_account_credentials(slot, email, current)
        outcome = switcher._consume_backup_grant_locked(
            slot, email, current, global_lock_held=True
        )
    else:
        # Unmanaged, or a rotation the slot has not caught up with. Posting the
        # live store's own grant is what Claude Code itself would do.
        outcome = switcher.post_refresh(
            slot or _UNMANAGED, current, timeout_s=_POST_TIMEOUT_S
        )

    if not outcome.credentials:
        if outcome.error == "consumed":
            raise _Stop("relogin_required")  # nothing parked and no POST can help
        if outcome.error in PERMANENT_AUTH_ERRORS:
            if slot:
                switcher._usage_store.record(
                    {slot: FetchRecord(
                        error=outcome.error,
                        struck_fp=outcome.consumed_fp or fingerprint,
                    )},
                    {slot: active.identity},
                )
            raise _Stop("relogin_required")
        raise _Stop("refresh_failed")

    final = switcher._prepare_credentials_for_activation(outcome.credentials, current)
    file_wanted = ensure_file or get_credentials_path().exists()
    try:
        store._write_oauth_credentials(final)
    except (ClaudeSwitchError, OSError):
        # The gate stored it in the slot or its own stash, unless both failed.
        if not via_gate or (outcome.error and not outcome.stashed):
            switcher.stash_consumed_successor(
                slot or _UNMANAGED, outcome.credentials, fingerprint,
                "keepalive-live-write-failed",
            )
        raise
    if file_wanted:
        _settle_file(store, report, final)
    report["action"] = "refreshed"
    _report_expiry(report, final)
    if outcome.error is not None:
        # The gate parked the successor rather than persisting it to the slot;
        # its next pass adopts it.
        raise _Stop("refresh_failed")
    return final, outcome.token_account


def _settle_slot(active, report, final, token_account) -> None:
    """The slot's records, with no lock held: the identity helpers may take it."""
    switcher = active.switcher
    slot = active.slot
    email, org_uuid = active.identity
    store = switcher._usage_store
    if report["action"] == "refreshed":
        store.clear_dead_token([slot], {slot: active.identity})
    login_expires_at = report["loginExpiresAt"]
    if store.entries({slot: active.identity})[slot].login_expires_at != login_expires_at:
        store.set_login_expiry(slot, active.identity, login_expires_at)

    # A lineage the slot does not hold yet, or a token answering as someone else.
    fingerprint = oauth.credential_fingerprint(final) or ""
    if token_account:
        match = switcher._resolved_matches_slot_identity(slot, token_account)
        if match is not None:
            switcher._probe_verdicts[switcher._lineage_key(slot, email, fingerprint)] = match
    switcher._resync_rotated_backup(slot, email, org_uuid, final)
    if switcher._probe_verdicts.get(switcher._lineage_key(slot, email, fingerprint)) is False:
        report["error"] = _error("unmanaged")
