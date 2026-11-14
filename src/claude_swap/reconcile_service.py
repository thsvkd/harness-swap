"""Run ``reconcile`` from a gui LaunchAgent whenever the login keychain changes.

A ``Claude Code-credentials`` item only appears where the keychain is open, which is a
login session, so the agent lives there: ``WatchPaths`` on the login keychain file wakes
it within seconds of a write (launchd's ThrottleInterval spaces a burst), ``RunAtLoad``
runs it at login, and an hourly interval is the backstop. Its own backup and delete wake
it once more, and that run finds no item. Ownership and idempotency are keepalive's
(``keepalive_service``), under the label ``dev.hswap.reconcile``.
"""

from __future__ import annotations

import plistlib
import sys
from pathlib import Path

from claude_swap import keepalive_service as ks
from claude_swap import launch_agent

LABEL = "dev.hswap.reconcile"
INTERVAL_S = 3600
_MARKER = ("HSWAP_SERVICE", "reconcile")


def build(program: list[str], home: Path | None = None) -> bytes:
    doc = plistlib.loads(
        launch_agent.build_plist(
            program,
            LABEL,
            home,
            argv=[*program, "reconcile"],
            interval=INTERVAL_S,
            extra_env=dict([_MARKER]),
        )
    )
    doc["WatchPaths"] = [str((home or Path.home()) / "Library" / "Keychains" / "login.keychain-db")]
    return plistlib.dumps(doc)


def _outdated(doc: dict | None, home: Path | None) -> bool | None:
    args = (doc or {}).get("ProgramArguments") or []
    if not ks._managed(doc, _MARKER) or args[-1:] != ["reconcile"] or len(args) < 2:
        return None
    return ks._job(doc, _MARKER) != ks._job(plistlib.loads(build(args[:-1], home)), _MARKER)


def status(home: Path | None = None, uid: int | None = None) -> dict:
    macos = sys.platform == "darwin"
    doc = ks._read(home, LABEL) if macos else None
    base = ks.job_status(LABEL, _MARKER, doc, launch_agent.plist_path(LABEL, home), home)
    if not macos:
        return base
    base["outdated"] = _outdated(doc, home)
    return ks.ask_launchd(base, LABEL, uid, home)


def _require_macos() -> None:
    if sys.platform != "darwin":
        raise ks.UnsupportedPlatformError("The reconcile service is macOS-only.")


def install(home: Path | None = None, uid: int | None = None, program: list[str] | None = None) -> dict:
    """``action``: installed/updated/unchanged/deferred. The caller checks the store is file."""
    _require_macos()
    plist = build(program or launch_agent.resolve_program(), home)
    return {"action": ks.install_job(LABEL, _MARKER, plist, home, uid), **status(home, uid)}


def uninstall(home: Path | None = None, uid: int | None = None) -> dict:
    _require_macos()
    return {"action": ks.uninstall_job(LABEL, _MARKER, home, uid), **status(home, uid)}
