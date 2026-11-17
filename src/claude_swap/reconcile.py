"""``cswap reconcile``: put back in the file store a login Claude Code wrote to the Keychain.

On macOS Claude Code always writes the login keychain first, so a `/login`, a refresh or
an MCP secret in a session where the keychain is open recreates a ``Claude Code-credentials``
item, and the file is deleted when the item was new. In file mode that stops every write
(``keychain_item_present``) until something settles which copy is the login.

This is ``migrate-store`` with the ``--keep`` choice made from evidence instead of a person.
The item is compared with the file, or with the active slot's copy when Claude Code deleted
the file. The later login is: the later generation of one lineage, the one a recorded link
or the ledger says came after the other, or, of two logins an earlier migrate-store or reconcile run
settled against each other (``seen_logins.json``), the one it kept: the other came back
from a stale cache. A login nothing here has seen proves nothing: a stale writer can hold one too.
Anything else is ``reconcile_ambiguous``, nothing changes, and a person settles it with
``migrate-store --keep``. That includes the usual case, a GUI refresh: nothing records
that the item's token came from the file's.

The item's value can only be read from a login session, so with the keychain locked this
reports ``keychain_item_present_locked`` and touches nothing: it reads no value, only the
item's attributes and the keychain's lock state.
"""

from __future__ import annotations

import hashlib
import logging

from claude_swap import consumed_grants, events, macos_keychain, oauth
from claude_swap.credentials import (
    CLAUDE_CODE_KEYCHAIN_SERVICE,
    credential_generation,
    holds_no_login,
)
from claude_swap.exceptions import NotFileStoreError
from claude_swap.keepalive import _expires_at, _read_active, _read_slot, _Stop
from claude_swap.migrate_store import (
    _all_locks,
    _keychain_items,
    _migrate,
    _preflight,
    _report_failure,
    _mark_suspect,
    _refresh_fingerprint,
    back_up_once,
    settled_logins,
)
from claude_swap.settings import atomic_write_json
from claude_swap.paths import get_credentials_path

_logger = logging.getLogger("claude-swap")
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


_HINT_RUNNING = (
    "Nothing records which login is newer. The keepalive service was running, so the server "
    "most likely revoked the access token early (401) and Claude Code refreshed it itself."
)
_HINT_STOPPED = (
    "Nothing records which login is newer. The keepalive service was not running, so Claude "
    "Code may have refreshed on its own: start it with hswap claude keepalive "
    "--install-service [--system]."
)
_HINT_FIX = (
    " Check which store was written last and keep it with hswap claude migrate-store --to "
    "file --keep file|keychain. For reference only, nothing decides by it: the Keychain "
    "item's access token expires at {item}, the {rival}'s at {other}."
)


def _ambiguity_hint(item: str, rival: str, rival_name: str) -> str:
    """Why nothing could tell, as far as this machine can see. A jarvis tick running
    keepalive instead of the service reads as "not running"."""
    from claude_swap import keepalive_service

    try:
        status = keepalive_service.status()
        running = bool(status.get("managed") and status.get("loaded"))
    except Exception:  # noqa: BLE001 - a hint must not fail the report
        running = False
    where = "credentials file" if rival_name == "file" else "active slot's .enc"
    return (_HINT_RUNNING if running else _HINT_STOPPED) + _HINT_FIX.format(
        item=oauth.expires_at_iso(_expires_at(item)) or "unknown",
        rival=where,
        other=oauth.expires_at_iso(_expires_at(rival)) or "unknown",
    )


class _Ambiguous(_Stop):
    """Which copies nothing could order, for the hold and the hint."""

    def __init__(self, item: str, rival: str, rival_name: str):
        super().__init__(AMBIGUOUS, _AMBIGUOUS_MESSAGE)
        self.item, self.rival, self.rival_name = item, rival, rival_name


def _roles(switcher, active) -> dict | None:
    """The recorded roles, carried to the successors the ledger or the stash links to a
    kept login (a keepalive refresh) and, overriding that, to a suspect one's."""
    recorded = settled_logins(switcher)
    if recorded is None:
        return None
    roles = dict(recorded)
    for wanted in ("kept", "suspect"):
        for fp, role in recorded.items():
            if role == wanted:
                for successor in switcher._recorded_successors(active.identity, active.slot, fp):
                    if wanted == "suspect" or successor not in recorded:
                        roles[successor] = wanted
    return roles


def _hold(switcher, report: dict, ambiguous: _Ambiguous) -> None:
    """Nothing may be decided, but the item may be the only copy of the newest login and a
    stale writer can overwrite it, and the login a run kept may now be spent: back the
    item up once, and stop trusting that kept login until a person settles it."""
    rival_fp = oauth.credential_fingerprint(ambiguous.rival)
    if rival_fp:
        _mark_suspect(switcher, rival_fp)
    try:
        back_up_once(ambiguous.item, report)
    except (*macos_keychain.KEYCHAIN_ERRORS, ValueError):
        pass  # reported as ambiguous either way; the item stays where it is


def _file_text() -> str:
    try:
        text = get_credentials_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    return text if text.strip() else ""


def _access_key(creds: str) -> str | None:
    token = (oauth.extract_oauth_data(creds) or {}).get("accessToken") if creds else None
    return hashlib.sha256(token.encode()).hexdigest() if token else None


def _ask_server(switcher) -> dict[str, bool]:
    """Before the locks, since no network runs under them: does each copy's access token
    still sign in as the active account? A refresh revokes the access tokens it replaced
    (seen on the real server), so one that does is held by its lineage's live refresh
    token. Keyed by the access token's hash; a copy that changes before the decision
    simply has no answer. Never raises."""
    answers: dict[str, bool] = {}
    try:
        active = _read_active(switcher)
        if not active.identity:
            return answers
        item = _keychain_items().get(
            (CLAUDE_CODE_KEYCHAIN_SERVICE, macos_keychain.keychain_account_name()), ""
        )
        for creds in (item, _file_text(), _read_slot(active)):
            key = _access_key(creds)
            if key is None or key in answers:
                continue
            profile = oauth.fetch_oauth_profile(oauth.extract_oauth_data(creds)["accessToken"])
            answers[key] = profile is not None and (
                (profile.get("email") or "").lower(), profile.get("organizationUuid") or ""
            ) == (active.identity[0].lower(), active.identity[1] or "")
    except Exception:  # noqa: BLE001 - no answer is the old behaviour, never a failure
        _logger.debug("Could not ask the server about the copies", exc_info=True)
    return answers


def _server_word(server: dict, item: str, rival: str) -> str | None:
    """Where no record decides: the copy whose access token still signs in is its
    lineage's live tip (a refresh revokes the access tokens it replaced), and a mark that
    it may be spent cannot outweigh that. Only when both copies are as they were probed
    (a refresh in between leaves one unasked) and neither is on the ledger, which would
    say its refresh token was or may have been sent. With both alive (two separate
    logins) the item, which Claude Code wrote last, stays."""
    item_live, rival_live = server.get(_access_key(item)), server.get(_access_key(rival))
    if item_live is None or rival_live is None:
        return None
    if any(consumed_grants.entry(oauth.credential_fingerprint(c)) for c in (item, rival)):
        return None
    if item_live:
        return "item"
    return "rival" if rival_live else None


def _newer(
    switcher, active, item: str, rival: str, side: str = "file", server: dict | None = None
) -> str | None:
    """``item``, ``rival`` or None: which login came later, on evidence only. Never
    "the one nothing has seen": a Claude Code with a stale cache can write a token
    hswap never saw, and it is the older one. Nothing either, with the role record
    unreadable or a suspect on either side: the one it would keep may be spent."""
    item_fp, rival_fp = oauth.credential_fingerprint(item), oauth.credential_fingerprint(rival)
    roles = _roles(switcher, active)
    _note_sides(item, rival, side, roles or {})
    if roles is None:
        return _ruled("roles_unreadable", None)
    suspect = "suspect" in (roles.get(item_fp), roles.get(rival_fp))
    if not suspect and item_fp == rival_fp:
        later = credential_generation(item) >= credential_generation(rival)
        return _ruled("same_lineage", "item" if later else "rival")

    def came_after(winner: str, loser: str) -> bool:
        if winner in switcher._recorded_successors(active.identity, active.slot, loser):
            return True
        return consumed_grants.entry(loser) is not None and consumed_grants.entry(winner) is None

    item_wins, rival_wins = came_after(item_fp, rival_fp), came_after(rival_fp, item_fp)
    if not suspect and item_wins != rival_wins:
        return _ruled("recorded_link", "item" if item_wins else "rival")
    verdict = _server_word(server or {}, item, rival)
    if verdict is not None:
        return _ruled("server_live", verdict)
    if suspect:
        return _ruled("suspect", None)
    # A run settled these two against each other before: the one it replaced came back
    # from a stale cache. Both roles must match; a copy only touched proves nothing.
    if not item_wins:
        pair = (roles.get(item_fp), roles.get(rival_fp))
        if pair == ("replaced", "kept"):
            return _ruled("settled_roles", "rival")
        if pair == ("kept", "replaced"):
            return _ruled("settled_roles", "item")
    return _ruled("none", None)


def _ruled(rule: str, verdict: str | None) -> str | None:
    events.note(rule=rule)
    return verdict


def _note_sides(item: str, rival: str, side: str, roles: dict) -> None:
    """For logs/events.jsonl: what was compared, as fingerprints and expiries only."""

    def describe(creds: str, name: str) -> dict:
        return {
            "side": name,
            "fp": _refresh_fingerprint(creds),
            "expiresAt": oauth.expires_at_iso(_expires_at(creds)),
            "role": roles.get(oauth.credential_fingerprint(creds)),
        }

    events.note(item=describe(item, "keychain"), rival=describe(rival, side))


def choose_kept(
    switcher, keychain: str, file_creds: str, server: dict | None = None
) -> tuple[str, str]:
    """(``file``, ``keychain`` or ``slot``, the login), on evidence only. Raises
    _Stop(AMBIGUOUS)."""
    if holds_no_login(keychain) and not holds_no_login(file_creds):
        events.note(rule="item_empty")
        return "file", file_creds
    active = _read_active(switcher)
    if holds_no_login(file_creds):
        # Claude Code deleted the file, maybe from a stale cache: the slot's copy stands in.
        rival, name = _read_slot(active), "slot"
    else:
        rival, name = file_creds, "file"
    if holds_no_login(rival):
        events.note(rule="no_rival")
        return "keychain", keychain
    verdict = _newer(switcher, active, keychain, rival, name, server)
    if verdict == "item":
        return "keychain", keychain
    if verdict == "rival":
        return name, rival
    raise _Ambiguous(keychain, rival, name)


def _log_event(report: dict) -> None:
    kind = report["error"]["type"] if report["error"] else None
    if kind:
        result = {AMBIGUOUS: "ambiguous", LOCKED: "locked"}.get(kind, "error")
    else:
        result = report["action"]
    events.note(
        kept=report["kept"], backups=len(report["backups"]), pruned=len(report["backupsPruned"]),
        deleted=report["action"] == "reconciled" and report["itemAbsent"],
        keychainItemPresent=report["keychainItemPresent"], keychainLocked=report["keychainLocked"],
        dryRun=report.get("dryRun", False),
    )
    events.details_default(rule="none" if kind == AMBIGUOUS else None)
    events.outcome(result)
    events.error(kind)


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
        "hint": None,
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
        server = _ask_server(switcher)
        with _all_locks(switcher):
            items = _keychain_items()
            keychain = items.get(
                (CLAUDE_CODE_KEYCHAIN_SERVICE, macos_keychain.keychain_account_name()), ""
            )
            file_creds = _file_text()
            try:
                keep, kept = choose_kept(switcher, keychain, file_creds, server)
            except _Ambiguous as ambiguous:
                report["hint"] = _ambiguity_hint(ambiguous.item, ambiguous.rival, ambiguous.rival_name)
                if not dry_run:
                    _hold(switcher, report, ambiguous)
                raise
            report["kept"] = keep
            store_keep = "file" if keep == "slot" else keep
            _migrate(
                switcher, report, store_keep, dry_run, kept, judged=(keychain, file_creds), settle=False
            )
        report["action"] = "planned" if dry_run else "reconciled"

    _report_failure(report, work)
    _log_event(report)
    if not dry_run:
        try:  # doctor reads it; no token in it
            atomic_write_json(switcher.backup_dir / "cache" / REPORT_FILENAME, report)
        except OSError:
            pass
    return report
