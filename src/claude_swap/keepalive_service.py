"""Run ``keepalive`` every few minutes as a macOS LaunchAgent.

keepalive must run in the GUI session because it reads the login Keychain, so
cron (which works for ``auto`` elsewhere) is not enough on macOS.

The label is ``dev.hswap.keepalive`` on purpose: hand-made agents already use
it, and sharing the label makes a second, duplicate job impossible. A plist is
ours only when it carries ``HSWAP_SERVICE=keepalive`` in its environment;
anything else under that label is left alone, never overwritten or removed.

Linux is not covered: there is no Keychain, so a cron line does the same job.
"""

from __future__ import annotations

import plistlib
import sys
from pathlib import Path

from claude_swap import launch_agent
from claude_swap.exceptions import ClaudeSwitchError

LABEL = "dev.hswap.keepalive"
INTERVAL_S = 300
_MARKER = ("HSWAP_SERVICE", "keepalive")


class ForeignServiceError(ClaudeSwitchError):
    json_type = "ForeignService"


class UnsupportedPlatformError(ClaudeSwitchError):
    json_type = "UnsupportedPlatform"


def _argv(program: list[str], ahead: float, then_auto: bool) -> list[str]:
    ahead_arg = str(int(ahead)) if float(ahead).is_integer() else repr(float(ahead))
    if not then_auto:
        return [*program, "keepalive", "--ahead", ahead_arg]
    # auto only after a successful keepalive; "$0" "$@" is the program argv.
    script = f'"$0" "$@" keepalive --ahead {ahead_arg} && exec "$0" "$@" auto --once'
    return ["/bin/sh", "-c", script, *program]


def build(program: list[str], ahead: float, then_auto: bool, home: Path | None = None) -> bytes:
    return launch_agent.build_plist(
        program,
        LABEL,
        home,
        argv=_argv(program, ahead, then_auto),
        interval=INTERVAL_S,
        extra_env=dict([_MARKER]),
    )


def _read(home: Path | None) -> dict | None:
    try:
        return plistlib.loads(launch_agent.plist_path(LABEL, home).read_bytes())
    except FileNotFoundError:
        return None
    except Exception:
        return {}  # unreadable: treat as someone else's


def _managed(doc: dict | None) -> bool | None:
    if doc is None:
        return None
    env = doc.get("EnvironmentVariables") or {}
    return env.get(_MARKER[0]) == _MARKER[1]


def _settings(doc: dict | None) -> tuple[float | None, bool | None]:
    """(ahead, thenAuto) recovered from our own plist's argv."""
    if not _managed(doc):
        return None, None
    args = doc.get("ProgramArguments") or []
    then_auto = bool(args) and args[0] == "/bin/sh"
    words = (args[2].replace('"', "").split() if then_auto and len(args) > 2 else args)
    try:
        ahead = float(words[words.index("--ahead") + 1])
    except (ValueError, IndexError):
        ahead = None
    return ahead, then_auto


def status(home: Path | None = None, uid: int | None = None) -> dict:
    out_log, err_log = launch_agent.log_paths(LABEL, home)
    plist = launch_agent.plist_path(LABEL, home)
    doc = _read(home) if sys.platform == "darwin" else None
    base = {
        "label": LABEL,
        "platform": "launchd" if sys.platform == "darwin" else "unsupported",
        "installed": doc is not None,
        "managed": _managed(doc),
        "loaded": False,
        "domainAvailable": False,
        "state": None,
        "pid": None,
        "lastExitCode": None,
        "intervalSeconds": doc.get("StartInterval") if _managed(doc) else None,
        "ahead": None,
        "thenAuto": None,
        "plist": str(plist),
        "stderrLog": str(err_log),
    }
    if sys.platform != "darwin":
        return base
    base["ahead"], base["thenAuto"] = _settings(doc)
    base["domainAvailable"] = launch_agent.domain_available(uid)
    st = launch_agent.status(LABEL, uid, home)
    base.update(loaded=st["loaded"], state=st["state"], pid=st["pid"], lastExitCode=st["last_exit_code"])
    return base


def _require_macos() -> None:
    if sys.platform != "darwin":
        raise UnsupportedPlatformError(
            "The keepalive service is macOS-only; on Linux run "
            "`hswap claude keepalive` from cron instead."
        )


def _job(doc: dict) -> tuple:
    return (doc.get("ProgramArguments"), doc.get("StartInterval"), _managed(doc))


def _refuse_foreign(home: Path | None, uid: int | None) -> dict | None:
    """Our plist, None when there is none, or raise: never touch someone else's job."""
    doc = _read(home)
    path = launch_agent.plist_path(LABEL, home)
    if doc is not None and not _managed(doc):
        raise ForeignServiceError(
            f"{path} was not made by hswap; left untouched. Remove it yourself to let hswap manage keepalive."
        )
    if doc is None and launch_agent.is_loaded(LABEL, uid):
        # Loaded from a plist elsewhere (another file name under the same label).
        raise ForeignServiceError(f"launchd runs {LABEL} from a plist hswap did not write; left untouched.")
    return doc


def install(
    ahead: float,
    then_auto: bool,
    home: Path | None = None,
    uid: int | None = None,
    program: list[str] | None = None,
) -> dict:
    """Write and load the agent. ``action``: installed/updated/unchanged/deferred."""
    _require_macos()
    doc = _refuse_foreign(home, uid)
    plist = build(program or launch_agent.resolve_program(), ahead, then_auto, home)
    path = launch_agent.plist_path(LABEL, home)
    # Same job, whatever PATH or proxies the caller has: reloading could cut a run short.
    unchanged = doc is not None and _job(doc) == _job(plistlib.loads(plist))
    if not launch_agent.domain_available(uid):
        # No GUI session (SSH, a LaunchDaemon): launchd loads the file at next login.
        if not unchanged:
            path.parent.mkdir(parents=True, exist_ok=True)
            launch_agent.log_paths(LABEL, home)[1].parent.mkdir(parents=True, exist_ok=True)
            launch_agent.atomic_write_bytes(path, plist)
        return {"action": "deferred", **status(home, uid)}
    if unchanged and launch_agent.is_loaded(LABEL, uid):
        return {"action": "unchanged", **status(home, uid)}
    launch_agent.install(LABEL, home, uid=uid, plist=plist)
    return {"action": "updated" if doc is not None else "installed", **status(home, uid)}


def uninstall(home: Path | None = None, uid: int | None = None) -> dict:
    _require_macos()
    doc = _refuse_foreign(home, uid)
    if doc is None:
        return {"action": "absent", **status(home, uid)}
    launch_agent.uninstall(LABEL, home, uid)
    return {"action": "removed", **status(home, uid)}
