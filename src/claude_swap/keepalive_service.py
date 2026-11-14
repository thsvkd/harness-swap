"""Run ``keepalive`` every few minutes as a macOS LaunchAgent.

keepalive must run in the GUI session because it reads the login Keychain, so
cron (which works for ``auto`` elsewhere) is not enough on macOS.

The label is ``dev.hswap.keepalive`` on purpose: hand-made agents already use
it, and sharing the label makes a second, duplicate job impossible. A plist is
ours only when it carries ``HSWAP_SERVICE=keepalive`` in its environment;
anything else under that label is left alone, never overwritten or removed.

With the file store keepalive needs no keychain, so it can also run where no one is
logged in: ``--system`` installs a LaunchDaemon that runs it as the user. Only one of the
two exists at a time, since both would run every few minutes.

Linux is not covered: there is no Keychain, so a cron line does the same job.
"""

from __future__ import annotations

import getpass
import os
import plistlib
import sys
import tempfile
import urllib.parse
from pathlib import Path

from claude_swap import launch_agent
from claude_swap.exceptions import ClaudeSwitchError

LABEL = "dev.hswap.keepalive"
INTERVAL_S = 300
_MARKER = ("HSWAP_SERVICE", "keepalive")
SYSTEM_DIR = Path("/Library/LaunchDaemons")
SYSTEM = "system"


class ForeignServiceError(ClaudeSwitchError):
    json_type = "ForeignService"


class UnsupportedPlatformError(ClaudeSwitchError):
    json_type = "UnsupportedPlatform"


class ServiceConflictError(ClaudeSwitchError):
    json_type = "ServiceConflict"


def system_plist_path() -> Path:
    return SYSTEM_DIR / f"{LABEL}.plist"


def _argv(program: list[str], ahead: float, then_auto: bool) -> list[str]:
    ahead_arg = str(int(ahead)) if float(ahead).is_integer() else repr(float(ahead))
    if not then_auto:
        return [*program, "keepalive", "--ahead", ahead_arg]
    # auto only after a successful keepalive; "$0" "$@" is the program argv.
    script = f'"$0" "$@" keepalive --ahead {ahead_arg} && exec "$0" "$@" auto --once'
    return ["/bin/sh", "-c", script, *program]


def _watch_paths(home: Path | None) -> list[str]:
    """Wake on a write to either store, not only every INTERVAL_S.

    launchd does not pass the installing shell's CLAUDE_CONFIG_DIR to the job,
    so the job syncs ~/.claude; watch that. keepalive writes only a store that
    differs, so its own write wakes it once more and that run writes nothing;
    launchd's default ThrottleInterval (10s) spaces any burst.
    """
    h = home or Path.home()
    return [
        str(h / "Library" / "Keychains" / "login.keychain-db"),
        str(h / ".claude" / ".credentials.json"),
    ]


def build(
    program: list[str], ahead: float, then_auto: bool, home: Path | None = None, user: str | None = None
) -> bytes:
    """``user``: a LaunchDaemon's, which runs as that user with that user's home."""
    doc = plistlib.loads(
        launch_agent.build_plist(
            program,
            LABEL,
            home,
            argv=_argv(program, ahead, then_auto),
            interval=INTERVAL_S,
            extra_env=dict([_MARKER]),
        )
    )
    doc["WatchPaths"] = _watch_paths(home)
    if user:
        doc["UserName"] = user
        # Set outright, not left to launchd: the store is found through this home.
        doc["EnvironmentVariables"].update(HOME=str(home or Path.home()), USER=user)
    return plistlib.dumps(doc)


def _read_path(path: Path) -> dict | None:
    try:
        return plistlib.loads(path.read_bytes())
    except FileNotFoundError:
        return None
    except Exception:
        return {}  # unreadable: treat as someone else's


def _read(home: Path | None, label: str = LABEL) -> dict | None:
    return _read_path(launch_agent.plist_path(label, home))


def _managed(doc: dict | None, marker: tuple[str, str] = _MARKER) -> bool | None:
    if doc is None:
        return None
    env = doc.get("EnvironmentVariables") or {}
    return env.get(marker[0]) == marker[1]


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


def _outdated(doc: dict | None, home: Path | None) -> bool | None:
    """Our plist differs from what this hswap would write for its own program,
    ahead and thenAuto: a reinstall with those settings brings it up to date."""
    ahead, then_auto = _settings(doc)
    if ahead is None:
        return None
    args = doc.get("ProgramArguments") or []
    if then_auto:
        program = args[3:]
    else:
        program = args[: args.index("keepalive")] if "keepalive" in args else []
    if not program:
        return None
    built = build(program, ahead, then_auto, home, user=doc.get("UserName"))
    return _job(doc) != _job(plistlib.loads(built))


def job_status(label: str, marker: tuple[str, str], doc: dict | None, plist: Path, home: Path | None) -> dict:
    """The fields every hswap service reports, launchd's answers still unasked."""
    managed = _managed(doc, marker)
    return {
        "label": label,
        "platform": "launchd" if sys.platform == "darwin" else "unsupported",
        "installed": doc is not None,
        "managed": managed,
        "loaded": False,
        "domainAvailable": False,
        "state": None,
        "pid": None,
        "lastExitCode": None,
        "intervalSeconds": doc.get("StartInterval") if managed else None,
        "outdated": None,
        "plist": str(plist),
        "stderrLog": str(launch_agent.log_paths(label, home)[1]),
    }


def ask_launchd(base: dict, label: str, uid: int | None, home: Path | None, domain: str | None = None) -> dict:
    base["domainAvailable"] = True if domain else launch_agent.domain_available(uid)
    st = launch_agent.status(label, uid, home, domain)
    base.update(loaded=st["loaded"], state=st["state"], pid=st["pid"], lastExitCode=st["last_exit_code"])
    return base


def status(home: Path | None = None, uid: int | None = None) -> dict:
    """The installed job, the LaunchDaemon first; ``domain`` says which (None: neither)."""
    macos = sys.platform == "darwin"
    system = _read_path(system_plist_path()) if macos else None
    doc = system if system is not None else (_read(home) if macos else None)
    plist = system_plist_path() if system is not None else launch_agent.plist_path(LABEL, home)
    base = job_status(LABEL, _MARKER, doc, plist, home)
    base.update(domain=None, ahead=None, thenAuto=None)
    if not macos:
        return base
    if doc is not None:
        base["domain"] = SYSTEM if system is not None else "gui"
    base["ahead"], base["thenAuto"] = _settings(doc)
    base["outdated"] = _outdated(doc, home)
    return ask_launchd(base, LABEL, uid, home, SYSTEM if system is not None else None)


def _require_macos() -> None:
    if sys.platform != "darwin":
        raise UnsupportedPlatformError(
            "The keepalive service is macOS-only; on Linux run "
            "`hswap claude keepalive` from cron instead."
        )


def _job(doc: dict, marker: tuple[str, str] = _MARKER) -> tuple:
    return (
        doc.get("ProgramArguments"),
        doc.get("StartInterval"),
        doc.get("WatchPaths"),
        doc.get("UserName"),
        _managed(doc, marker),
    )


def refuse_foreign(
    home: Path | None, uid: int | None, label: str = LABEL, marker: tuple[str, str] = _MARKER
) -> dict | None:
    """Our plist, None when there is none, or raise: never touch someone else's job."""
    doc = _read(home, label)
    path = launch_agent.plist_path(label, home)
    if doc is not None and not _managed(doc, marker):
        raise ForeignServiceError(
            f"{path} was not made by hswap; left untouched. Remove it yourself to let hswap manage it."
        )
    if doc is None and launch_agent.is_loaded(label, uid):
        # Loaded from a plist elsewhere (another file name under the same label).
        raise ForeignServiceError(f"launchd runs {label} from a plist hswap did not write; left untouched.")
    return doc


def install_job(label: str, marker: tuple[str, str], plist: bytes, home: Path | None, uid: int | None) -> str:
    """Write and load a gui LaunchAgent: installed/updated/unchanged/deferred."""
    doc = refuse_foreign(home, uid, label, marker)
    path = launch_agent.plist_path(label, home)
    # Same job, whatever PATH or proxies the caller has: reloading could cut a run short.
    unchanged = doc is not None and _job(doc, marker) == _job(plistlib.loads(plist), marker)
    if not launch_agent.domain_available(uid):
        # No GUI session (SSH, a LaunchDaemon): launchd loads the file at next login.
        if not unchanged:
            path.parent.mkdir(parents=True, exist_ok=True)
            launch_agent.log_paths(label, home)[1].parent.mkdir(parents=True, exist_ok=True)
            launch_agent.atomic_write_bytes(path, plist)
        return "deferred"
    if unchanged and launch_agent.is_loaded(label, uid):
        return "unchanged"
    launch_agent.install(label, home, uid=uid, plist=plist)
    return "updated" if doc is not None else "installed"


def uninstall_job(label: str, marker: tuple[str, str], home: Path | None, uid: int | None) -> str:
    if refuse_foreign(home, uid, label, marker) is None:
        return "absent"
    launch_agent.uninstall(label, home, uid)
    return "removed"


def _sudo(*args: str) -> None:
    """Root's half of the LaunchDaemon. sudo asks for the password on the terminal."""
    result = launch_agent.subprocess.run(["sudo", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        what = " ".join(args[:2]) if args[0] == "launchctl" else args[0]
        raise ClaudeSwitchError(
            f"sudo {what} failed (exit {result.returncode})" + (f": {detail}" if detail else "")
        )


def _read_system() -> dict | None:
    doc = _read_path(system_plist_path())
    if doc is not None and not _managed(doc):
        raise ForeignServiceError(f"{system_plist_path()} was not made by hswap; left untouched.")
    return doc


def _refuse_proxy_secrets() -> None:
    """The daemon plist is world-readable, and build_plist forwards the proxy variables."""
    for key in launch_agent._FORWARDED_ENV_KEYS:
        if "proxy" in key.lower() and "@" in urllib.parse.urlsplit(os.environ.get(key, "")).netloc:
            raise ClaudeSwitchError(
                f"{key} holds a user name or password, and the LaunchDaemon's plist is readable "
                "by every local user; unset it for this install (or use a proxy without one)."
            )


def _put_system_plist(plist: bytes, path: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / path.name
        staged.write_bytes(plist)
        # launchd refuses a daemon plist root does not own or others can write; 644
        # lets the user read it back for --service-status.
        _sudo("install", "-o", "root", "-g", "wheel", "-m", "644", str(staged), str(path))


def _install_system(plist: bytes, home: Path | None, uid: int | None) -> dict:
    gui = refuse_foreign(home, uid)  # someone else's agent under this label would run alongside
    doc = _read_system()
    path = system_plist_path()
    target = f"{SYSTEM}/{LABEL}"
    unchanged = doc is not None and _job(doc) == _job(plistlib.loads(plist))
    loaded = launch_agent.is_loaded(LABEL, domain=SYSTEM)
    if doc is None and loaded:
        raise ForeignServiceError(f"launchd runs {target} from a plist hswap did not write; left untouched.")
    if not (unchanged and loaded):
        err_log = launch_agent.log_paths(LABEL, home)[1]
        err_log.parent.mkdir(parents=True, exist_ok=True)
        err_log.touch(exist_ok=True)  # the user's: launchd would create it as root
        previous = path.read_bytes() if doc is not None else None
        _put_system_plist(plist, path)
        if loaded:
            _sudo("launchctl", "bootout", target)
            launch_agent._wait_until_unloaded(LABEL, domain=SYSTEM)
        try:
            _sudo("launchctl", "bootstrap", SYSTEM, str(path))
        except ClaudeSwitchError:
            # Back to what was there: no plist launchd would load at the next boot unasked.
            try:
                if previous is None:
                    _sudo("rm", "-f", str(path))
                else:
                    _put_system_plist(previous, path)
                    if loaded:
                        _sudo("launchctl", "bootstrap", SYSTEM, str(path))
            except ClaudeSwitchError:
                pass
            raise
    if gui is not None:
        launch_agent.uninstall(LABEL, home, uid)
    if unchanged and loaded:
        action = "unchanged"
    else:
        action = "updated" if doc is not None else "installed"
    return {"action": action, **status(home, uid)}


def install(
    ahead: float,
    then_auto: bool,
    home: Path | None = None,
    uid: int | None = None,
    program: list[str] | None = None,
    system: bool = False,
    user: str | None = None,
) -> dict:
    """Write and load the job. ``action``: installed/updated/unchanged/deferred.
    ``system``: a LaunchDaemon run as ``user`` (default: this one), through sudo; it
    replaces the gui agent. The caller checks that the store is file."""
    _require_macos()
    program = program or launch_agent.resolve_program()
    if system:
        _refuse_proxy_secrets()
        return _install_system(build(program, ahead, then_auto, home, user=user or getpass.getuser()), home, uid)
    if _read_path(system_plist_path()) is not None:
        raise ServiceConflictError(
            f"keepalive runs from {system_plist_path()}; remove it with "
            "hswap claude keepalive --uninstall-service --system first, so only one job runs."
        )
    action = install_job(LABEL, _MARKER, build(program, ahead, then_auto, home), home, uid)
    return {"action": action, **status(home, uid)}


def uninstall(home: Path | None = None, uid: int | None = None, system: bool = False) -> dict:
    _require_macos()
    if not system:
        return {"action": uninstall_job(LABEL, _MARKER, home, uid), **status(home, uid)}
    if _read_system() is None:
        return {"action": "absent", **status(home, uid)}
    if launch_agent.is_loaded(LABEL, domain=SYSTEM):
        _sudo("launchctl", "bootout", f"{SYSTEM}/{LABEL}")
    _sudo("rm", "-f", str(system_plist_path()))
    return {"action": "removed", **status(home, uid)}
