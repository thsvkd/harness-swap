"""``cswap reconcile``: put back in the file store a login Claude Code wrote to the Keychain.

On macOS Claude Code always writes the login keychain first, so a `/login`, a refresh or
an MCP secret in a session where the keychain is open recreates a ``Claude Code-credentials``
item, and the file is deleted when the item was new. In file mode that stops every write
(``keychain_item_present``) until something settles which copy is the login.

This is ``migrate-store`` with the ``--keep`` choice made from evidence instead of a person.
Of two copies, the later is: the later generation of one lineage, the one a recorded link
or the ledger says came after the other, or the only one nothing here has seen (written
after hswap last looked). The item is compared with the file, or with the active slot's
copy when Claude Code deleted the file: a GUI process with a stale cache can write an
older token. Anything else is ``reconcile_ambiguous`` and nothing changes. Expiry orders only copies of one lineage,
as everywhere else. The writes, the read-back backups and the deletes are migrate-store's.

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
)
from claude_swap.paths import get_credentials_path

AMBIGUOUS = "reconcile_ambiguous"
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


def _newer(switcher, active, first: str, second: str) -> str | None:
    """``first``, ``second`` or None: which of two logins came later, on evidence only."""
    first_fp, second_fp = oauth.credential_fingerprint(first), oauth.credential_fingerprint(second)
    if first_fp == second_fp:
        return "first" if credential_generation(first) >= credential_generation(second) else "second"

    def came_after(winner: str, loser: str) -> bool:
        if winner in switcher._recorded_successors(active.identity, active.slot, loser):
            return True
        return consumed_grants.entry(loser) is not None and consumed_grants.entry(winner) is None

    first_wins, second_wins = came_after(first_fp, second_fp), came_after(second_fp, first_fp)
    if first_wins != second_wins:
        return "first" if first_wins else "second"
    if first_wins:
        return None  # a cycle
    email = active.identity[0] if active.identity else ""
    unseen = [
        name
        for name, creds in (("first", first), ("second", second))
        if switcher.is_provably_new_login(creds, active.slot, email, stores_must_agree=False)
    ]
    return unseen[0] if len(unseen) == 1 else None


def choose_kept(switcher, keychain: str, file_creds: str) -> str:
    """``file`` or ``keychain``, on evidence only. Raises _Stop(AMBIGUOUS)."""
    if holds_no_login(keychain) and not holds_no_login(file_creds):
        return "file"
    active = _read_active(switcher)
    if holds_no_login(file_creds):
        # Claude Code deleted the file, maybe from a stale cache: the slot's copy stands in.
        slot = _read_slot(active)
        if holds_no_login(slot) or _newer(switcher, active, keychain, slot) == "first":
            return "keychain"
    else:
        verdict = _newer(switcher, active, keychain, file_creds)
        if verdict:
            return "keychain" if verdict == "first" else "file"
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
            keep = choose_kept(switcher, keychain, _file_text())
            report["kept"] = keep
            _migrate(switcher, report, keep, dry_run)
        report["action"] = "planned" if dry_run else "reconciled"

    return _report_failure(report, work)
