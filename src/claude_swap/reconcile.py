"""``cswap reconcile``: put back in the file store a login Claude Code wrote to the Keychain.

On macOS Claude Code always writes the login keychain first, so a `/login`, a refresh or
an MCP secret in a session where the keychain is open recreates a ``Claude Code-credentials``
item, and the file is deleted when the item was new. In file mode that stops every write
(``keychain_item_present``) until something settles which copy is the login.

This is ``migrate-store`` with the ``--keep`` choice made from evidence instead of a person.
The item is compared with the file, or with the active slot's copy when Claude Code deleted
the file. The later login is: the later generation of one lineage, the one a recorded link
or the ledger says came after the other, or the store's when the item holds a login that
migrate-store or reconcile already settled (``seen_logins.json``), since a stale cache put
it back. A login nothing here has seen proves nothing: a stale writer can hold one too.
Anything else is ``reconcile_ambiguous``, nothing changes, and a person settles it with
``migrate-store --keep``. That includes the usual case, a GUI refresh: nothing records
that the item's token came from the file's.

The item's value can only be read from a login session, so with the keychain locked this
reports ``keychain_item_present_locked`` and touches nothing: it reads no value, only the
item's attributes and the keychain's lock state.
"""

from __future__ import annotations

from claude_swap import consumed_grants, macos_keychain, oauth
from claude_swap.credentials import (
    CLAUDE_CODE_KEYCHAIN_SERVICE,
    credential_generation,
    holds_no_login,
)
from claude_swap.exceptions import NotFileStoreError
from claude_swap.keepalive import _read_active, _read_slot, _Stop
from claude_swap.migrate_store import (
    _all_locks,
    _keychain_items,
    _migrate,
    _preflight,
    _report_failure,
    seen_logins,
)
from claude_swap.settings import atomic_write_json
from claude_swap.paths import get_credentials_path

AMBIGUOUS = "reconcile_ambiguous"
REPORT_FILENAME = "reconcile.json"
LOCKED = "keychain_item_present_locked"
# 3 is the service's "written, loads at next login".
EXIT_CODES = {AMBIGUOUS: 4, LOCKED: 5}

_AMBIGUOUS_MESSAGE = (
    "The Keychain item and the credentials file hold different logins and nothing records "
    "which is newer, so nothing was changed. Pick the store whose writer refreshed last with "
    "hswap claude migrate-store --to file --keep file|keychain, or /login over SSH and "
    "hswap claude add."
)
_LOCKED_MESSAGE = (
    "The login keychain holds a Claude Code credential item but is locked here, so its "
    "value cannot be kept and nothing was changed. Run hswap claude reconcile from a login "
    "session, or after security unlock-keychain in the same shell."
)


def _file_text() -> str:
    try:
        text = get_credentials_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    return text if text.strip() else ""


def _newer(switcher, active, item: str, rival: str) -> str | None:
    """``item``, ``rival`` or None: which login came later, on evidence only. Never
    "the one nothing has seen": a Claude Code with a stale cache can write a token
    hswap never saw, and it is the older one."""
    item_fp, rival_fp = oauth.credential_fingerprint(item), oauth.credential_fingerprint(rival)
    if item_fp == rival_fp:
        return "item" if credential_generation(item) >= credential_generation(rival) else "rival"

    def came_after(winner: str, loser: str) -> bool:
        if winner in switcher._recorded_successors(active.identity, active.slot, loser):
            return True
        return consumed_grants.entry(loser) is not None and consumed_grants.entry(winner) is None

    item_wins, rival_wins = came_after(item_fp, rival_fp), came_after(rival_fp, item_fp)
    if item_wins != rival_wins:
        return "item" if item_wins else "rival"
    # A login this command already settled, now back in the item while the store moved on:
    # a stale writer put it there.
    if not item_wins and item_fp in seen_logins(switcher):
        return "rival"
    return None


def choose_kept(switcher, keychain: str, file_creds: str) -> tuple[str, str]:
    """(``file``, ``keychain`` or ``slot``, the login), on evidence only. Raises
    _Stop(AMBIGUOUS)."""
    if holds_no_login(keychain) and not holds_no_login(file_creds):
        return "file", file_creds
    active = _read_active(switcher)
    if holds_no_login(file_creds):
        # Claude Code deleted the file, maybe from a stale cache: the slot's copy stands in.
        rival, name = _read_slot(active), "slot"
    else:
        rival, name = file_creds, "file"
    if holds_no_login(rival):
        return "keychain", keychain
    verdict = _newer(switcher, active, keychain, rival)
    if verdict == "item":
        return "keychain", keychain
    if verdict == "rival":
        return name, rival
    raise _Stop(AMBIGUOUS, _AMBIGUOUS_MESSAGE)


def run_reconcile(switcher, *, dry_run: bool = False) -> dict:
    report = {
        "schemaVersion": 1,
        "ok": False,
        "action": "none",
        "kept": None,
        "keychainItemPresent": False,
        "keychainLocked": None,
        "fileFingerprint": None,
        "keychainFingerprint": None,
        "backups": [],
        "slotsMigrated": [],
        "itemAbsent": False,
        "storesDiffer": False,
        "warning": None,
        "error": None,
        "backupsPruned": [],
    }
    if dry_run:
        report["dryRun"] = True

    def work() -> None:
        if not switcher._store._file_store():
            raise NotFileStoreError("reconcile")
        # Attributes only: answers on a locked keychain and reads no value.
        if not macos_keychain.credential_item_present():
            report["itemAbsent"] = True
            return
        report["keychainItemPresent"] = True
        report["keychainLocked"] = macos_keychain.keychain_reachable(platform="darwin") is not True
        if report["keychainLocked"]:
            raise _Stop(LOCKED, _LOCKED_MESSAGE)
        _preflight(switcher)
        with _all_locks(switcher):
            items = _keychain_items()
            keychain = items.get(
                (CLAUDE_CODE_KEYCHAIN_SERVICE, macos_keychain.keychain_account_name()), ""
            )
            keep, kept = choose_kept(switcher, keychain, _file_text())
            report["kept"] = keep
            _migrate(switcher, report, "file" if keep == "slot" else keep, dry_run, kept)
        report["action"] = "planned" if dry_run else "reconciled"

    _report_failure(report, work)
    if not dry_run:
        try:  # doctor reads it; no token in it
            atomic_write_json(switcher.backup_dir / "cache" / REPORT_FILENAME, report)
        except OSError:
            pass
    return report
