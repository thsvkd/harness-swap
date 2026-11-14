"""``cswap doctor``: can this machine keep its Claude logins with no one logged in?

Read only, and safe with no login session: the keychain is asked by attributes only
(``credential_item_present``) and for reachability, and launchd only through ``print``.
The JSON is a contract (docs/claude.md, "Running without a login session"): fields are
added, never renamed, and ``problems`` holds stable codes.
"""

from __future__ import annotations

import json
import os
import stat

from claude_swap import keepalive_service, macos_keychain, reconcile, reconcile_service
from claude_swap.credentials import SECURITY_SERVICE
from claude_swap.json_output import SCHEMA_VERSION
from claude_swap.keepalive import _store_label
from claude_swap.models import Platform
from claude_swap.paths import get_credentials_path

_SERVICE_FIELDS = ("installed", "managed", "loaded", "outdated", "lastExitCode")


def _service(status: dict, *extra: str) -> dict:
    return {key: status.get(key) for key in (*extra, *_SERVICE_FIELDS)}


def _backup_count() -> int | None:
    try:
        return sum(
            1
            for service, account in macos_keychain.generic_items()
            if service == SECURITY_SERVICE and ".backup-" in account
        )
    except (*macos_keychain.KEYCHAIN_ERRORS, ValueError):
        return None


def _last_reconcile(switcher) -> tuple[str | None, str | None]:
    """(error type, hint) of the last reconcile run."""
    try:
        last = json.loads((switcher.backup_dir / "cache" / reconcile.REPORT_FILENAME).read_text(encoding="utf-8"))
        hint = last.get("hint")
        return (last.get("error") or {}).get("type"), hint if isinstance(hint, str) else None
    except (OSError, ValueError, AttributeError):
        return None, None


def run_doctor(switcher) -> dict:
    """Raises OSError when the store cannot be read; the CLI turns it into an error envelope."""
    macos = switcher.platform == Platform.MACOS
    # Off macOS the file is the only store there is.
    store = _store_label(switcher._store) if macos else "file"
    file_store = store == "file"
    try:
        mode = stat.S_IMODE(get_credentials_path().stat().st_mode)
    except FileNotFoundError:
        mode = None
    accounts = (switcher._get_sequence_data() or {}).get("accounts", {})
    without_backup = sorted(
        int(num)
        for num, account in accounts.items()
        if not switcher._store._backup_enc_path(num, account.get("email", "")).exists()
    )
    try:
        sessions = sorted(e.name for e in (switcher.backup_dir / "sessions").iterdir() if e.is_dir())
    except FileNotFoundError:
        sessions = []

    last_error, last_hint = _last_reconcile(switcher)
    report = {
        "schemaVersion": SCHEMA_VERSION,
        "ok": False,
        "problems": [],
        "store": store,
        "keychainItemPresent": None,
        "keychainLocked": None,
        "fileExists": mode is not None,
        "fileMode": None if mode is None else f"{mode:04o}",
        "slotsWithoutBackup": without_backup,
        "sessionDirs": sessions,
        "reconcileService": None,
        "keepaliveService": None,
        "keychainBackups": None,
        "lastReconcileError": last_error,
        "lastReconcileHint": last_hint,
    }
    problems = report["problems"]
    if macos:
        report["keychainItemPresent"] = macos_keychain.credential_item_present()
        report["keychainLocked"] = macos_keychain.keychain_reachable(platform="darwin") is not True
        report["reconcileService"] = _service(reconcile_service.status())
        report["keepaliveService"] = _service(keepalive_service.status(), "domain", "ahead")
        report["keychainBackups"] = _backup_count()
        if not file_store:
            problems.append("not_file_store")
    if file_store:
        if macos and report["keychainItemPresent"]:
            problems.append("keychain_item_present")
            if report["lastReconcileError"] == reconcile.AMBIGUOUS:
                problems.append("reconcile_ambiguous")
        if mode is None:
            problems.append("file_missing")
        elif os.name == "posix" and mode & 0o077:
            problems.append("file_mode_insecure")
    if macos and file_store:
        if without_backup:
            problems.append("slot_without_backup")
        if sessions:
            problems.append("session_profiles")
        if "CLAUDE_CONFIG_DIR" in os.environ or "CLAUDE_SECURESTORAGE_CONFIG_DIR" in os.environ:
            problems.append("profile_env")
        if not report["reconcileService"]["managed"]:
            problems.append("reconcile_service_missing")
        # Either domain will do; a scheduler hswap cannot see (a jarvis tick) is not counted.
        keepalive = report["keepaliveService"]
        if not (keepalive["managed"] and keepalive["loaded"]):
            problems.append("keepalive_service_missing")
        ahead = keepalive["ahead"]
        if keepalive["managed"] and ahead is not None and ahead <= keepalive_service.MIN_AHEAD_S:
            problems.append("keepalive_ahead_too_short")
    report["ok"] = not problems
    return report


def summary(switcher) -> dict:
    """``{"ok", "problems"}``, or ``{"ok": None, "problems": None, "error"}`` when the
    check itself failed: a caller reporting its own success must not end in a traceback."""
    try:
        report = run_doctor(switcher)
    except Exception as e:  # noqa: BLE001
        return {"ok": None, "problems": None, "error": io_error(e)}
    return {"ok": report["ok"], "problems": report["problems"]}


def io_error(e: Exception) -> dict:
    """No text from the exception: it can name a path."""
    kind = "io_error" if isinstance(e, OSError) else getattr(e, "json_type", type(e).__name__)
    return {"type": kind, "message": f"doctor could not read the store ({type(e).__name__})."}
