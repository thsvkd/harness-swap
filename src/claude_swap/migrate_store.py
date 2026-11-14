"""``cswap migrate-store``: the explicit human step onto the file credential store.

The only code besides the guard that talks to Keychain credential items once the store
is ``file``, so it calls ``macos_keychain`` directly and not the routed store methods.
Repair runs through here too, with the setting already on.

Every Keychain credential item is copied inside the login keychain and read back before
the original goes, so no step discards what may be the only copy of a live successor.

This records no lineage (rule L) and stashes no copy as a rule-U rival. The person
choosing ``--keep`` is the tie-break and the kept credential is canonical, as with
``keepalive --adopt``. What it replaces is kept in the Keychain backups, where rule U
does not look: a stash entry would hold every later refresh at ``split_brain``, which
is the state a repair exists to end.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from claude_swap import consumed_grants, macos_keychain, oauth
from claude_swap.claude_locks import claude_credentials_lock
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE, SECURITY_SERVICE
from claude_swap.exceptions import (
    ClaudeSwitchError,
    ConfigConflictError,
    CopiesDisagreeError,
    LockError,
)
from claude_swap.fsutil import atomic_write_text
from claude_swap.keepalive import (
    _LEDGER_UNREADABLE,
    _belongs,
    _oauth_payload,
    _read_active,
    _read_slot,
    _refuse_spent,
    _Stop,
)
from claude_swap.locking import FileLock
from claude_swap.paths import get_credentials_path
from claude_swap.settings import require_keychain, set_setting

CREDENTIALS_BACKUP = "claude-code-credentials"
_NEEDS_KEYCHAIN = (
    "The login keychain is not readable from this process, so nothing was changed. Run this "
    "from the GUI session, or after security unlock-keychain in the same shell."
)
_STEP_FAILED = (
    "A Keychain or file step failed ({}). Items are deleted only after every backup "
    "verified, and credentials.store is set only at the end; see the report for what ran."
)
_STORES_DIFFER_WARNING = (
    "file and keychain hold different logins; the one you do not keep is backed up but may "
    "be the newer one — if the kept one is spent, Claude will need /login."
)
_RESTORE_UNPROVEN = (
    "The backup may be a spent predecessor of the current login, so it was not restored and "
    "nothing was changed. Use /login in the screen session instead."
)
_RESTORE_ITEM_EXISTS = (
    "A Claude Code login already exists in the Keychain, so nothing was restored or changed. "
    "Use hswap claude migrate-store --to file --keep keychain to adopt it instead."
)
_UNSUPPORTED_STORE = (
    "CLAUDE_CONFIG_DIR or CLAUDE_SECURESTORAGE_CONFIG_DIR names a credential store "
    "migrate-store does not manage; run it from a normal shell."
)


def _refresh_fingerprint(credentials: str) -> str | None:
    token = _oauth_payload(credentials).get("refreshToken")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:6] if token else None


def _same_login(left: str, right: str) -> bool:
    return bool(left and right) and (
        oauth.credential_fingerprint(left) == oauth.credential_fingerprint(right)
    )


def _back_up(base: str, value: str, report: dict) -> None:
    """Into the login keychain under a new name. `set_password` sends it on stdin and
    reads it back, and raises unless it landed. `-U` would overwrite, so names never repeat."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    account = f"{base}.backup-{stamp}"
    attempt = 0
    while macos_keychain.get_password(SECURITY_SERVICE, account) is not None:
        attempt += 1
        account = f"{base}.backup-{stamp}-{attempt}"
    macos_keychain.set_password(SECURITY_SERVICE, account, value)
    report["backups"].append(account)


@contextmanager
def _all_locks(switcher) -> Iterator[None]:
    """Every slot's consume lock, then the order keepalive uses. Without a setting that
    forces it, an inactive slot's refresh holds only its consume lock across the POST,
    and a successor landing mid-copy would leave `.enc` on the spent token."""
    accounts = (switcher._get_sequence_data() or {}).get("accounts", {})
    held: list[FileLock] = []
    try:
        for num in sorted(accounts):
            lock = FileLock(switcher.credentials_dir / f".consume-{num}.lock")
            lock.__enter__()
            held.append(lock)
        with FileLock(switcher.lock_file), claude_credentials_lock():
            yield
    finally:
        for lock in reversed(held):
            lock.__exit__(None, None, None)


def _preflight(switcher) -> None:
    if require_keychain(switcher.backup_dir):
        raise ConfigConflictError()
    if "CLAUDE_CONFIG_DIR" in os.environ or "CLAUDE_SECURESTORAGE_CONFIG_DIR" in os.environ:
        raise _Stop("unsupported_store", _UNSUPPORTED_STORE)
    if macos_keychain.keychain_reachable(platform="darwin") is not True:
        raise _Stop("keychain_unavailable", _NEEDS_KEYCHAIN)
    # File mode stops at these, so a migration past them would only end in a refusal.
    switcher.refuse_session_profiles(force=True)
    switcher.refuse_unreadable_stash_manifest(force=True)


def _report_failure(report: dict, work) -> dict:
    """Run ``work``; whatever stops it lands in the report, with no path or token in it."""
    try:
        work()
    except _Stop as stop:
        report["error"] = {"type": stop.kind, "message": stop.message}
    except LockError:
        report["error"] = {"type": "locked", "message": "Credential locks stayed held; try again."}
    except consumed_grants.LedgerUnreadable:
        report["error"] = {"type": "refresh_failed", "message": _LEDGER_UNREADABLE}
    except ClaudeSwitchError as e:
        report["error"] = {"type": getattr(e, "json_type", type(e).__name__), "message": str(e)}
    except (*macos_keychain.KEYCHAIN_ERRORS, ValueError) as e:
        report["error"] = {
            "type": "keychain_unavailable",
            "message": _STEP_FAILED.format(type(e).__name__),
        }
    except OSError as e:  # its text names a path
        report["error"] = {"type": "io_error", "message": _STEP_FAILED.format(type(e).__name__)}
    report["ok"] = report["error"] is None
    return report


def run_migrate_store(switcher, keep: str, *, dry_run: bool = False) -> dict:
    report = {
        "schemaVersion": 1,
        "ok": False,
        "kept": keep,
        "fileFingerprint": None,
        "keychainFingerprint": None,
        "backups": [],
        "slotsMigrated": [],
        "itemAbsent": False,
        "storesDiffer": False,
        "warning": None,
        "error": None,
    }
    if dry_run:
        report["dryRun"] = True

    def work() -> None:
        _preflight(switcher)
        with _all_locks(switcher):
            _migrate(switcher, report, keep, dry_run)

    return _report_failure(report, work)


def _keychain_items() -> dict[tuple[str, str], str]:
    """Every Claude Code credential item and its value. The unsuffixed item is also asked
    for by name, so a dump that failed to show it cannot leave it undeleted and unread."""
    default = (CLAUDE_CODE_KEYCHAIN_SERVICE, macos_keychain.keychain_account_name())
    items = {}
    for item in dict.fromkeys([default, *macos_keychain.credential_items()]):
        value = macos_keychain.get_password(*item)
        if value is not None:
            items[item] = value
        elif item != default:
            raise _Stop("keychain_unavailable", _NEEDS_KEYCHAIN)
    return items


def _slot_plan(switcher, active, kept: str) -> list[tuple[str, str, str, list[str]]]:
    """(slot, email, what its `.enc` gets, what that makes worth keeping) per slot to write."""
    store = switcher._store
    plan = []
    for num, account in active.accounts.items():
        email = account.get("email", "")
        enc = store._leftover_backup_enc(num, email)
        item = macos_keychain.get_password(SECURITY_SERVICE, store._backup_username(num, email))
        item = item or ""
        if num == active.slot:
            if not _same_login(enc, kept):
                replaced = [item] if item else []
                if enc and not _same_login(enc, item):
                    replaced.append(enc)
                plan.append((num, email, kept, replaced))
        elif item and not enc:
            plan.append((num, email, item, []))
        elif item and not _same_login(enc, item) and not store._file_store():
            # Nothing here says which is newer, and posting a spent token can revoke the login.
            # Once the store is file, the `.enc` is: file mode never updates the item.
            raise _Stop(
                "split_brain",
                f"Slot {num} holds different tokens in its .enc and its Keychain backup, so "
                "nothing was changed. Log in as that account with /login and run hswap claude "
                "add, or remove the slot, and run this again.",
            )
    return plan


def _migrate(switcher, report: dict, keep: str, dry_run: bool) -> None:
    path = get_credentials_path()
    try:
        file_creds = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        file_creds = ""
    items = _keychain_items()
    keychain_creds = items.get(
        (CLAUDE_CODE_KEYCHAIN_SERVICE, macos_keychain.keychain_account_name()), ""
    )
    report["fileFingerprint"] = _refresh_fingerprint(file_creds)
    report["keychainFingerprint"] = _refresh_fingerprint(keychain_creds)
    # Before any refusal below, since the choice of --keep is what this warns about.
    if (
        report["fileFingerprint"]
        and report["keychainFingerprint"]
        and not _same_login(file_creds, keychain_creds)
    ):
        report["storesDiffer"] = True
        report["warning"] = _STORES_DIFFER_WARNING
    kept = file_creds if keep == "file" else keychain_creds
    if not _oauth_payload(kept).get("refreshToken"):
        raise _Stop("no_credentials", f"The {keep} store holds no refresh token; nothing was changed.")
    _refuse_spent(kept)
    active = _read_active(switcher)
    if _belongs(active, kept, _read_slot(active), probe=True) is False:
        raise _Stop("unmanaged", f"The {keep} login is another account's; nothing was changed.")
    plan = _slot_plan(switcher, active, kept)

    if dry_run:
        report["slotsMigrated"] = [int(num) for num, *_ in plan]
        report["itemAbsent"] = not items
        report["plan"] = [
            *(["write the keychain login to the file"] if keep == "keychain" else []),
            *[f"write slot {num}'s .enc" for num, *_ in plan],
            *[f"back up and delete {service}" for service, _ in items],
            "set credentials.store=file",
        ]
        return

    # Files first: until the originals go, a failure leaves the Keychain as it was.
    if keep == "keychain" and file_creds != kept:
        if file_creds.strip() and not _same_login(file_creds, kept):
            _back_up(CREDENTIALS_BACKUP, file_creds, report)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, kept)
    store = switcher._store
    for num, email, value, replaced in plan:
        for copy in replaced:
            _back_up(f"slot-{num}-{email}", copy, report)
        store._write_backup_enc(num, email, value)
        if store._leftover_backup_enc(num, email) != value:
            raise _Stop("refresh_failed", f"Slot {num}'s .enc did not read back; nothing was deleted.")
        report["slotsMigrated"].append(int(num))

    for value in items.values():
        _back_up(CREDENTIALS_BACKUP, value, report)
    for service, account in items:
        macos_keychain.delete_password(service, account)
    report["itemAbsent"] = not macos_keychain.credential_item_present()
    if not report["itemAbsent"]:
        raise _Stop("keychain_item_present")
    set_setting(switcher.backup_dir, "credentials.store", "file")


def _restore_is_safe(switcher, active, value: str) -> bool:
    """Claude Code rotates the file without telling the ledger, so a backup that differs
    from it may be its spent predecessor. Only the same token, or no other copy, is safe."""
    try:
        file_creds = get_credentials_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        file_creds = ""
    if file_creds.strip():
        return _same_login(file_creds, value)
    if not active.identity:
        return False  # nothing names the account whose copies would have to agree
    email, org_uuid = active.identity
    enc = switcher._store._leftover_backup_enc(active.slot, email) if active.slot else ""
    try:
        stash = switcher._stash_fingerprints(email, org_uuid)
    except CopiesDisagreeError:
        return False
    return stash <= {oauth.credential_fingerprint(value)} and (not enc or _same_login(enc, value))


def run_restore_keychain(switcher, backup_account: str) -> dict:
    """The rollback: a backup goes back as the Claude Code item and stays where it is. Only
    with no item there: an unlocked Claude Code may have rotated into one, leaving the backup
    its spent predecessor. Backups stop at the migration, and Claude Code would POST it."""
    report = {
        "schemaVersion": 1,
        "ok": False,
        "restored": backup_account,
        "fingerprint": None,
        "error": None,
    }

    def work() -> None:
        if macos_keychain.keychain_reachable(platform="darwin") is not True:
            raise _Stop("keychain_unavailable", _NEEDS_KEYCHAIN)
        account = macos_keychain.keychain_account_name()
        with _all_locks(switcher):
            value = (
                macos_keychain.get_password(SECURITY_SERVICE, backup_account)
                if backup_account.startswith(f"{CREDENTIALS_BACKUP}.backup-")
                else None
            )
            if value is None:
                raise _Stop("backup_not_found", "No such backup in the login keychain.")
            report["fingerprint"] = _refresh_fingerprint(value)
            # The lookup by service alone also finds an item the dump's account did not name.
            if _keychain_items() or macos_keychain.credential_item_present():
                raise _Stop("relogin_required", _RESTORE_ITEM_EXISTS)
            _refuse_spent(value)
            active = _read_active(switcher)
            if _belongs(active, value, _read_slot(active), probe=True) is False:
                raise _Stop("unmanaged", "That backup is another account's; nothing was changed.")
            if not _restore_is_safe(switcher, active, value):
                raise _Stop("relogin_required", _RESTORE_UNPROVEN)
            macos_keychain.set_password(CLAUDE_CODE_KEYCHAIN_SERVICE, account, value)

    return _report_failure(report, work)
