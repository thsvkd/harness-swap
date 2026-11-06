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

With the Keychain in play, copies are never ordered by expiry or write time: a
refresh can issue a shorter lifetime and a clock can step back. Claude Code writes a
refresh's successor into its own store and keepalive holds Claude Code's locks, so
stores agreeing on a token mean it is unspent unless the ledger says otherwise, and
stores that differ need a recorded link or a person to choose (`--adopt`).

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
    _credential_object,
    credential_generation,
    holds_no_login,
)
from claude_swap.exceptions import (
    ClaudeSwitchError,
    CopiesDisagreeError,
    KeychainUnavailableError,
    LockError,
    RequiredModeUnsupportedError,
    StoresDisagreeError,
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
# Clock skew and a server's grace: the login's own expiry is the proof, not this.
_STASH_LAPSED_MARGIN_S = 24 * 3600
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
_UNLINKED_STORES = (
    "The Keychain and the credentials file hold different logins and no record links "
    "them; nothing was changed. Run hswap claude keepalive --adopt file|keychain, "
    "naming the store whose writer refreshed last. If you cannot tell, log in again "
    "with /login and adopt the store that login wrote."
)
_ADOPT_NEEDS_KEYCHAIN = "--adopt needs the macOS Keychain and a real run; nothing was changed."
_LEDGER_UNREADABLE = "consumed-grant ledger unreadable"
_UNCERTAIN_REFRESH = (
    "The last refresh had an uncertain outcome, so its token will not be sent "
    "again; log in again and re-add the account."
)
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
    adopt: str | None = None,
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
        _keep(switcher, report, ahead, ensure_file, dry_run, adopt)
    except _Stop as stop:
        report["error"] = {"type": stop.kind, "message": stop.message}
    except RequiredModeUnsupportedError as e:
        report["error"] = {"type": "required_mode_unsupported", "message": str(e)}
    except CopiesDisagreeError as e:
        report["error"] = {"type": "split_brain", "message": str(e)}
    except StoresDisagreeError:
        report["error"] = {"type": "split_brain", "message": _UNLINKED_STORES}
    except KeychainUnavailableError:
        report["error"] = _error("keychain_unavailable")
    except consumed_grants.LedgerUnreadable:
        report["error"] = {"type": "refresh_failed", "message": _LEDGER_UNREADABLE}
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


def _keep(switcher, report, ahead, ensure_file, dry_run, adopt=None) -> None:
    store = switcher._store
    macos = switcher.platform == Platform.MACOS
    active = _read_active(switcher)
    report["activeSlot"] = int(active.slot) if active.slot else None

    # Keepalive reads the unsuffixed Keychain item. Claude Code hashes either
    # variable into its service name when it is set at all, even to the default
    # directory, so the two would be looking at different items.
    if "CLAUDE_CONFIG_DIR" in os.environ or "CLAUDE_SECURESTORAGE_CONFIG_DIR" in os.environ:
        raise _Stop("refresh_failed", _UNSUPPORTED_STORE)
    if macos:
        if macos_keychain.keychain_reachable(platform="darwin") is False:
            raise _Stop("keychain_unavailable")
        store.pin_keychain()
        switcher.refuse_session_profiles()
    store.records_consumed = True
    if adopt and (dry_run or not store._keychain_is_required()):
        raise _Stop("adopt_refused", _ADOPT_NEEDS_KEYCHAIN)

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
            if adopt:
                final, token_account = _adopt(active, report, adopt), None
            else:
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
    switcher._required_mode_gate(reconciling=True)
    store = switcher._store
    keychain, file_creds = _read_stores(store, switcher.platform == Platform.MACOS)
    if not dry_run:
        _prune_stash(active)
    if not keychain and not file_creds:
        if store._read_managed_key():
            report["note"] = "api_key"  # nothing here to sync or refresh
            return None, None
        raise _Stop("no_credentials")

    moved = False
    if switcher.platform == Platform.MACOS:
        final, backup, moved = _reconcile(
            active, report, keychain, file_creds, ahead, ensure_file, dry_run
        )
    else:
        backup = _read_slot(active)
        held = [creds for creds in (backup, file_creds) if creds]
        successor, parked_entries = _parked_successor(active, held, dry_run)
        backup = successor or backup
        final = _sync(active, report, file_creds, backup, ensure_file, dry_run)
        _retire_parked(active, parked_entries, backup)
    token_account = None
    if not moved and _due(final, ahead):
        _refuse_spent(final)
        if dry_run:
            report["action"] = "refreshed"
        else:
            final, token_account = _refresh(active, report, final, backup, ensure_file)
    return final, token_account


def _retire_parked(active, entries: list[str], parked: str) -> None:
    """The stash holds the only sure copy until a store provably does."""
    store = active.switcher._store
    if entries and not _store_holds(store, active.switcher.platform == Platform.MACOS, parked):
        raise _Stop("refresh_failed", _FILE_NOT_UPDATED)
    for entry_id in entries:
        active.switcher._retire_stash_entry(entry_id, _UNMANAGED)


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


def _prune_stash(active) -> None:
    """Stash entries are base64 on disk, so one goes once its own login has provably
    lapsed. An unknown lifetime stays until `unclaimed --purge`, as does anything a
    successor chain or a reservation still points at."""
    switcher = active.switcher
    store = switcher._store
    if store._read_stash_manifest_ex()[1] != "ok":
        return  # orphan files could be the only record: see _adopt_stashed_successor
    rows = store._list_unclaimed_credentials()
    pointed_at = {row.get("consumedFp") for row in rows.values()}
    for entry_id in rows:
        value, unreadable = store._read_unclaimed_credential(entry_id)
        if unreadable or not value:
            continue
        lapsed_at = oauth.refresh_expiry_ms(_oauth_payload(value).get("refreshTokenExpiresAt"))
        if lapsed_at is None or lapsed_at > (time.time() - _STASH_LAPSED_MARGIN_S) * 1000:
            continue
        fingerprint = oauth.credential_fingerprint(value)
        recorded = consumed_grants.entry(fingerprint)
        if fingerprint in pointed_at or (
            recorded is not None and recorded["state"] == consumed_grants.RESERVED
        ):
            continue
        switcher._retire_stash_entry(entry_id, active.slot or _UNMANAGED)


def _store_holds(store, macos: bool, parked: str) -> bool:
    """A store read back now holds this successor, or the same lineage no older."""
    keychain, file_creds = _read_stores(store, macos)
    durable = keychain if macos else file_creds
    return durable == parked or (
        oauth.credential_fingerprint(durable) == oauth.credential_fingerprint(parked)
        and credential_generation(durable) >= credential_generation(parked)
    )


def _refuse_spent(credentials: str) -> None:
    """Called after every adoption: nothing newer exists, and no POST can help."""
    recorded = consumed_grants.entry(oauth.credential_fingerprint(credentials))
    if recorded is not None:
        raise _Stop(
            "relogin_required",
            _UNCERTAIN_REFRESH if recorded["state"] == consumed_grants.RESERVED else None,
        )


def _slot_copy(switcher, slot: str, email: str) -> str:
    """A slot's stored login. Unreadable defers the run: this copy can be the newest
    generation, and "" would read as there being none."""
    value, unreadable = switcher._read_account_credentials_ex(slot, email)
    if unreadable:
        raise _Stop("keychain_unavailable")
    return value


def _read_slot(active) -> str:
    return _slot_copy(active.switcher, active.slot, active.identity[0]) if active.slot else ""


def _parked_successor(active, held: list[str], dry_run) -> tuple[str | None, list[str]]:
    """A successor parked for one of these copies, adopted: posting past it would
    present a spent token. A login with no slot has only the stash, whose copy plays
    the same part. Returns it and the entries to retire once a store holds it."""
    switcher = active.switcher
    if dry_run:
        return None, []
    if active.slot:
        email = active.identity[0]
        for creds in held:
            adopted = switcher._adopt_stashed_successor(active.slot, email, creds)
            if adopted:
                return adopted, []
        return None, []
    spent = {oauth.credential_fingerprint(creds) for creds in held}
    identity = active.identity or ("", "")

    def is_ours(row: dict) -> bool:
        return (row.get("email"), row.get("organizationUuid")) == identity and str(
            row.get("reason", "")
        ).startswith("keepalive-")

    manifest = switcher._store._read_stash_manifest()
    for entry_id, row in manifest.items():
        if is_ours(row) and row.get("consumedFp") in spent:
            parked, _ = switcher._store._read_unclaimed_credential(entry_id)
            if parked:
                chain, terminal = switcher.stash_chain_terminal(
                    manifest, is_ours, entry_id, parked, row.get("consumedFp")
                )
                return terminal, chain
    return None, []


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
    # `backup` is the slot's copy, or a stash entry recorded for this identity.
    if backup and fingerprint == oauth.credential_fingerprint(backup):
        return True
    recorded = consumed_grants.entry(fingerprint)
    if recorded is not None:
        if not active.identity:
            return None
        return (recorded["email"], recorded["organizationUuid"]) == active.identity
    for num, account in active.accounts.items():
        if num != active.slot:
            other = _slot_copy(switcher, num, account.get("email", ""))
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


def _linked_successor(active, keychain: str, file_creds: str) -> str:
    """Of two differing stores the gate let through, the recorded successor."""
    file_fp = oauth.credential_fingerprint(file_creds)
    successors = active.switcher._recorded_successors(
        active.identity, active.slot, oauth.credential_fingerprint(keychain)
    )
    return file_creds if file_fp in successors else keychain


def _reconcile(
    active, report, keychain, file_creds, ahead, ensure_file, dry_run
) -> tuple[str, str, bool]:
    """The required-mode decision table, on evidence only (see the module docstring).
    Returns what the stores now hold, the slot's copy, and whether a recorded
    successor moved the login, which ends the run without a POST.
    """
    switcher = active.switcher
    backup = _read_slot(active)
    holders = [creds for creds in (keychain, file_creds) if not holds_no_login(creds)]
    if not holders:
        raise _Stop("no_credentials")
    stores_differ = len({oauth.credential_fingerprint(creds) for creds in holders}) > 1
    login = _linked_successor(active, keychain, file_creds) if stores_differ else holders[0]
    # The stores agree on another account's token: config and stores disagree on who
    # is logged in, and nothing here can say which is right.
    if _belongs(active, login, backup, probe=False) is False:
        raise _Stop("unmanaged")

    fingerprint = oauth.credential_fingerprint(login)
    successors = switcher._recorded_successors(active.identity, active.slot, fingerprint)
    successor, parked_entries = _parked_successor(active, [login], dry_run)
    if not successor and backup and oauth.credential_fingerprint(backup) in successors:
        successor = backup
    if dry_run and not successor and successors & {
        row.get("fingerprint") for row in switcher._store._read_stash_manifest().values()
    }:
        report["action"] = "synced-keychain"  # the real run adopts it from the stash
        _report_expiry(report, login)
        return login, backup, True
    if successor:
        login = successor
        backup = successor if active.slot else backup
    _refuse_spent(login)
    # Before anything is written: a POST is coming, and rule U may forbid it.
    if not stores_differ and not successor and _due(login, ahead):
        switcher._require_unanimity(login, active.identity or ("", ""))

    if stores_differ and not dry_run:
        for stale in holders:
            if oauth.credential_fingerprint(stale) != oauth.credential_fingerprint(login):
                _stash_loser(active, stale, True)  # a recorded link is this account's
    final = _write_stores(active, report, keychain, file_creds, login, ensure_file, dry_run)
    _retire_parked(active, parked_entries, login)
    return final, backup, stores_differ or bool(successor)


def _adopt(active, report, choice: str) -> str:
    """A person's tie-break: the chosen store goes to the other store and the slot,
    every copy it replaces is kept first, and nothing is POSTed."""
    switcher = active.switcher
    keychain, file_creds = _read_stores(switcher._store, True)
    chosen = file_creds if choice == "file" else keychain
    if not _oauth_payload(chosen).get("refreshToken"):
        raise _Stop("adopt_refused", f"The {choice} store holds no usable login; nothing was changed.")
    backup = _read_slot(active)
    if _belongs(active, chosen, backup, probe=True) is False:
        raise _Stop("unmanaged")
    _refuse_spent(chosen)

    fingerprint = oauth.credential_fingerprint(chosen)
    identity = active.identity or ("", "")
    # Decided before anything below adds to what the stash knows.
    new_login = switcher.is_provably_new_login(
        chosen, active.slot, identity[0], stores_must_agree=False
    )
    for stale in (keychain, file_creds):
        if not holds_no_login(stale) and oauth.credential_fingerprint(stale) != fingerprint:
            # In this login's stores, so this login's unless proven another's: a copy with
            # no identity would be invisible to the check before the next refresh.
            _stash_loser(active, stale, _belongs(active, stale, backup, probe=True) is not False)
    # Kept before the writes below replace them. They stay rivals unless this login is new.
    held = switcher._stored_copies(active.slot, identity[0]) if active.slot else []
    for stale in held:
        if not holds_no_login(stale) and oauth.credential_fingerprint(stale) != fingerprint:
            _stash_loser(active, stale, True)
    if new_login:
        switcher.supersede_stashed_copies(identity, chosen)
    final = _write_stores(active, report, keychain, file_creds, chosen, True, False)
    if active.slot:
        switcher._write_account_credentials(active.slot, active.identity[0], final)
    report["action"] = "adopted"
    return final


def _sync(active, report, file_creds, backup, ensure_file, dry_run) -> str:
    """Where the file is the only live store, it and the slot compete."""
    live = [file_creds] if file_creds else []
    verdicts: dict[str, bool | None] = {}

    def belongs(creds: str) -> bool | None:
        if creds not in verdicts:
            verdicts[creds] = _belongs(active, creds, backup, probe=False)
        return verdicts[creds]

    # Another account's copy never wins: a switch this run did not see must not be
    # undone by a stale, longer-lived copy. The slot competes too, since it holding
    # a newer generation means a live store was stranded on the consumed one (a
    # write that failed after a refresh), which `_fetch_active_usage` restores as
    # well. With every live copy foreign, overwriting a login takes a slot copy
    # that can still work: a duplicated lineage can look foreign too.
    candidates = [creds for creds in live if belongs(creds) is not False]
    if _oauth_payload(backup).get("refreshToken") and (
        candidates or (not _is_expired(backup) and not _is_spent(backup))
    ):
        candidates.append(backup)
    if not candidates:
        raise _Stop("unmanaged")

    # A working copy beats a spent one, then the newest wins. `max` keeps the first
    # on a tie.
    def rank(creds: str) -> tuple:
        return (_is_working(creds), credential_generation(creds))

    authoritative = max(candidates, key=rank)
    generation = credential_generation(authoritative)
    # Only this account's: another account's spent token says nothing about this one.
    spent_newer = [
        creds for creds in live
        if belongs(creds) is True
        and _is_spent(creds)
        and credential_generation(creds) > generation
    ]
    if spent_newer and belongs(authoritative) is True and not dry_run:
        # An older copy of a chain whose newer link is spent was very likely spent
        # to make that link. Keep that knowledge past the overwrite below. Only with
        # the winner proven: an unknown login may be no part of that chain.
        consumed_grants.reserve(
            oauth.credential_fingerprint(authoritative), active.identity or ("", "")
        )

    fingerprint = oauth.credential_fingerprint(authoritative)
    for loser in dict.fromkeys(live):
        if loser == authoritative or oauth.credential_fingerprint(loser) == fingerprint:
            continue
        verdict = belongs(loser)
        same_account = verdict is True and belongs(authoritative) is True
        if loser not in spent_newer and (same_account or _is_wiped(loser)):
            continue  # a stale generation of this login is not a split
        if verdict is False:
            report["note"] = "split_brain"
        if not dry_run:
            _stash_loser(active, loser, verdict)

    return _write_stores(active, report, "", file_creds, authoritative, ensure_file, dry_run)


def _write_stores(active, report, keychain, file_creds, login, ensure_file, dry_run) -> str:
    """Bring both stores to this login; returns what they now hold."""
    switcher = active.switcher
    store = switcher._store
    macos = switcher.platform == Platform.MACOS
    # The engine's composition with the Keychain as the live store: it wins the
    # machine-shared fields (mcpOAuth, ...), the login comes from the winner.
    current = keychain or file_creds
    composed = (
        login
        if login == current
        else switcher._prepare_credentials_for_activation(login, current)
    )
    if not _oauth_payload(composed).get("refreshToken") and any(
        _oauth_payload(creds).get("refreshToken") for creds in (keychain, file_creds) if creds
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


def _is_spent(credentials: str) -> bool:
    return consumed_grants.entry(oauth.credential_fingerprint(credentials)) is not None


def _is_working(credentials: str) -> bool:
    payload = _oauth_payload(credentials)
    return bool(
        payload.get("accessToken")
        and payload.get("refreshToken")
        and not _is_expired(credentials)
        and not _is_spent(credentials)
    )


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


def _is_wiped(credentials: str) -> bool:
    """Claude Code emptied its token fields: nothing left to keep. An expired copy
    is not this: its refresh token may be another account's only live one."""
    payload = _oauth_payload(credentials)
    return bool(payload) and not payload.get("accessToken") and not payload.get("refreshToken")


def _loser_identity(active, loser: str, verdict: bool | None) -> tuple[str, str]:
    """Whose this copy is, as far as anything says; empty when nothing does."""
    if verdict is True:
        return active.identity or ("", "")
    fingerprint = oauth.credential_fingerprint(loser)
    recorded = consumed_grants.entry(fingerprint)
    if recorded is not None:
        return (recorded["email"], recorded["organizationUuid"])
    for num, account in active.accounts.items():
        email = account.get("email", "")
        other = active.switcher._read_account_credentials_ex(num, email)[0]
        if other and oauth.credential_fingerprint(other) == fingerprint:
            return (email, account.get("organizationUuid", "") or "")
    return ("", "")


def _stash_loser(active, loser: str, verdict: bool | None) -> None:
    try:
        active.switcher.stash_verified(
            loser,
            _loser_identity(active, loser, verdict),
            active.slot or _UNMANAGED,
            "keepalive-split-brain",
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
            active.identity or ("", ""), current, locks_held=True, timeout_s=_POST_TIMEOUT_S
        )

    if not outcome.credentials:
        if outcome.error in ("consumed", "relogin_required"):
            raise _Stop("relogin_required")  # nothing parked and no POST can help
        if outcome.error == "stores-disagree":
            raise _Stop("split_brain", _UNLINKED_STORES)
        if outcome.error == "ledger-unreadable":
            raise _Stop("refresh_failed", _LEDGER_UNREADABLE)
        if outcome.fate == oauth.GRANT_UNCERTAIN:
            raise _Stop("relogin_required", _UNCERTAIN_REFRESH)
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
                slot or _UNMANAGED, active.identity or ("", ""), outcome.credentials,
                fingerprint, "keepalive-live-write-failed",
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


def _let_the_slot_follow(active, final: str) -> None:
    """Required mode: the live stores are authoritative, so the slot follows them,
    whatever its expiry says, and the resync keeps its copy first. Only a token proven
    to be another account's leaves the slot alone. Decides the verdict the resync acts on.
    """
    switcher = active.switcher
    copy = _read_slot(active)
    fingerprint = oauth.credential_fingerprint(final) or ""
    if oauth.credential_fingerprint(copy) == fingerprint:
        return
    key = switcher._lineage_key(active.slot, active.identity[0], fingerprint)
    if switcher._probe_verdicts.get(key) is None:
        switcher._probe_verdicts[key] = _belongs(active, final, copy, probe=True) is not False


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
    if switcher.platform == Platform.MACOS:
        _let_the_slot_follow(active, final)
    switcher._resync_rotated_backup(slot, email, org_uuid, final)
    if switcher._probe_verdicts.get(switcher._lineage_key(slot, email, fingerprint)) is False:
        report["error"] = _error("unmanaged")
