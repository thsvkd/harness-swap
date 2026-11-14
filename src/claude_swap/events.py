"""What each command did and why, one JSON line per run in ``<store root>/logs/events.jsonl``.

``claude-swap.log`` says what failed; it cannot say who ran the command (a gui
LaunchAgent, the system LaunchDaemon, a jarvis tick, a person over SSH) or why a
decision went the way it did, and that difference is what headless problems turn on.
So ``cli.main`` opens a record (``begin``), commands add their reasons (``note``,
``outcome``, ``error``), and the record is written once at the end (``finish``), with
extra lines for decisions a long run makes (``step``).

Never a secret: tokens appear only as the 6-hex fingerprints reports already use, a
string that still looks like a token is replaced before writing, and the home
directory is written as ``~``. Never a failure: writing is best effort, and a run
whose log cannot be written ends exactly as it would have.
"""

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

EVENTS_FILENAME = "events.jsonl"
MAX_BYTES = 1024 * 1024
BACKUPS = 3
STDERR_MAX_BYTES = 1024 * 1024
# Commands that only read the log (writing would bury what they show).
_SILENT = {"log"}
# Credentials in any form Claude Code or a person hands over; a long opaque run as well.
_SECRET = re.compile(r"sk-ant-[A-Za-z0-9_\-]+|[A-Za-z0-9_\-]{40,}")
_FLAG_COMMANDS = {
    "--list": "list", "--status": "status", "--switch": "switch", "--switch-to": "switch",
    "--add-account": "add", "--remove-account": "remove", "--tui": "tui", "--purge": "purge",
    "--export": "export", "--import": "import",
}
_SESSIONS = {"aqua": "aqua", "background": "background", "system": "system"}
# The launchd jobs whose stderr file this run writes, by HSWAP_CALLER.
STDERR_LABELS = {
    "launchd-gui-keepalive": "dev.hswap.keepalive",
    "launchd-system-keepalive": "dev.hswap.keepalive",
    "launchd-gui-reconcile": "dev.hswap.reconcile",
}

_state: dict = {}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def caller() -> str:
    """HSWAP_CALLER (the launchd plists and jarvis set it), else a TTY's person or unknown."""
    named = os.environ.get("HSWAP_CALLER", "").strip()
    if named:
        return named[:64]
    try:
        return "tty" if sys.stdin.isatty() else "unknown"
    except (AttributeError, ValueError, OSError):
        return "unknown"


def session() -> str:
    """The launchd session this process runs in; ``n/a`` off macOS."""
    if sys.platform != "darwin":
        return "n/a"
    try:
        result = subprocess.run(
            ["launchctl", "managername"], capture_output=True, text=True, timeout=2, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    return _SESSIONS.get((result.stdout or "").strip().lower(), "unknown")


def command_name(argv: list[str]) -> str:
    if not argv:
        return "tui"
    first = argv[0]
    if not first.startswith("-"):
        return first
    return _FLAG_COMMANDS.get(first, first.lstrip("-") or "unknown")


@functools.cache
def _version() -> str:
    try:
        from importlib.metadata import version

        return version("harness-swap")
    except Exception:  # noqa: BLE001 - a source checkout
        from claude_swap import __version__

        return __version__


def begin(cmd: str) -> None:
    _state.clear()
    _state.update(cmd=cmd, started=time.monotonic(), details={}, caller=caller())


def context() -> dict:
    """For the claude-swap.log prefix; the session is asked once, on first use."""
    if not _state:
        return {"cmd": "-", "caller": caller(), "session": "-"}
    if "session" not in _state:
        _state["session"] = session()
    return {"cmd": _state["cmd"], "caller": _state["caller"], "session": _state["session"]}


def active() -> str | None:
    return _state.get("cmd")


def note(**details) -> None:
    if _state:
        _state["details"].update(details)


def details_default(**details) -> None:
    """Set these only where nothing set them yet (and drop None)."""
    if _state:
        for key, value in details.items():
            if value is not None:
                _state["details"].setdefault(key, value)


def outcome(value: str) -> None:
    if _state:
        _state["outcome"] = value


def error(kind: str | None) -> None:
    if _state and kind and not _state.get("error"):
        _state["error"] = kind


def active_slot(slot) -> None:
    if _state and slot is not None:
        _state["activeSlot"] = int(slot)


def _store_root() -> Path:
    from claude_swap import paths

    return paths.get_backup_root()


def path(root: Path | None = None) -> Path:
    return (root or _store_root()) / "logs" / EVENTS_FILENAME


def _store_label(root: Path) -> str:
    from claude_swap.models import Platform
    from claude_swap.settings import credentials_store, require_keychain

    if Platform.detect() != Platform.MACOS:
        return "file"
    try:
        if credentials_store(root) == "file":
            return "file"
        return "keychain" if require_keychain(root) else "auto"
    except Exception:  # noqa: BLE001 - a policy that cannot be read
        return "invalid"


def _sequence_active(root: Path):
    try:
        value = json.loads((root / "sequence.json").read_text(encoding="utf-8")).get("activeAccountNumber")
    except (OSError, ValueError, AttributeError):
        return None
    return int(value) if isinstance(value, int) else None


def _scrub(line: str) -> str:
    home = str(Path.home())
    for form in (json.dumps(home)[1:-1], home):
        if form and form != "/":
            line = line.replace(form, "~")
    return _SECRET.sub("[redacted]", line)


def _rotate(target: Path, keep: int) -> None:
    for n in range(keep - 1, 0, -1):
        older = target.with_name(f"{target.name}.{n}")
        if older.exists():
            os.replace(older, target.with_name(f"{target.name}.{n + 1}"))
    os.replace(target, target.with_name(f"{target.name}.1"))


def _append(target: Path, line: str) -> None:
    target.parent.mkdir(mode=0o700, exist_ok=True)
    try:
        if target.stat().st_size + len(line) > MAX_BYTES:
            _rotate(target, BACKUPS)
    except FileNotFoundError:
        pass
    fd = os.open(target, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def _write(record: dict) -> None:
    """Best effort, and only into a store that exists: a run must not create one."""
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return  # root's HOME may be the user's; leave no root-owned file there
        root = _store_root()
        if not root.is_dir():
            return
        _append(path(root), _scrub(json.dumps(record, default=str, separators=(",", ":"))) + "\n")
    except Exception:  # noqa: BLE001 - logging never changes a result
        pass


def _record(exit_code: int, outcome_value: str | None, details: dict, error_kind) -> dict:
    root = _store_root()
    started = _state.get("started", time.monotonic())
    return {
        "ts": iso(time.time()),
        "v": _version(),
        "cmd": _state.get("cmd", "unknown"),
        "caller": _state.get("caller") or caller(),
        "session": context()["session"],
        "store": _store_label(root),
        "activeSlot": _state.get("activeSlot", _sequence_active(root)),
        "outcome": outcome_value or ("ok" if exit_code == 0 else "error"),
        "exit": exit_code,
        "ms": int((time.monotonic() - started) * 1000),
        "error": error_kind,
        "details": details,
    }


def step(outcome_value: str, **details) -> None:
    """An extra line for one decision of a long run (an auto loop's switch)."""
    if not _state or _state["cmd"] in _SILENT:
        return
    try:
        _write(_record(0, outcome_value, details, None))
    except Exception:  # noqa: BLE001
        pass


def finish(exit_code) -> None:
    if not _state:
        return
    try:
        code = exit_code if isinstance(exit_code, int) else (0 if exit_code is None else 1)
        if _state["cmd"] not in _SILENT:
            _write(_record(code, _state.get("outcome"), _state["details"], _state.get("error")))
    except Exception:  # noqa: BLE001
        pass
    finally:
        _state.clear()


def read(root: Path | None = None) -> list[dict]:
    """Every event, oldest first, across the rotated files; unreadable lines skipped."""
    target = path(root)
    rows = []
    for candidate in [target.with_name(f"{target.name}.{n}") for n in range(BACKUPS, 0, -1)] + [target]:
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


_MAX_TICKS = 30


def _slots(value):
    """Account refs to slot numbers: the decision is about slots, and an email is not
    needed to read it."""
    if isinstance(value, dict):
        if "number" in value and "email" in value:
            return value["number"]
        return {key: _slots(item) for key, item in value.items() if key not in ("schemaVersion", "ts")}
    if isinstance(value, list):
        return [_slots(item) for item in value]
    return value


def auto_event(payload: dict) -> None:
    """One auto-switch event (poll, switch, no-switch, …) into the run's details; a switch
    also gets its own line, so a long loop leaves one per decision."""
    if not _state:
        return
    compact = _slots(payload)
    ticks = _state["details"].setdefault("ticks", [])
    ticks.append(compact)
    del ticks[:-_MAX_TICKS]
    if payload.get("event") == "switch":
        step("switched", switch=compact)


def summary(row: dict) -> dict:
    return {key: row.get(key) for key in ("ts", "cmd", "caller", "outcome", "exit")}


def parse_since(text: str) -> datetime:
    """``1h``, ``30m``, ``2d`` or an ISO time. Raises ValueError."""
    match = re.fullmatch(r"(\d+)([smhd])", text.strip())
    if match:
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[match.group(2)]
        return datetime.now(UTC) - timedelta(**{unit: int(match.group(1))})
    moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


class StampedStream:
    """stderr under launchd: launchd's StandardErrorPath has no times, so each line gets a
    UTC stamp at its start."""

    def __init__(self, stream):
        self._stream = stream
        self._at_line_start = True

    def write(self, text: str) -> int:
        out = []
        for piece in text.splitlines(keepends=True):
            if self._at_line_start:
                out.append(iso(time.time()) + " ")
            out.append(piece)
            self._at_line_start = piece.endswith("\n")
        self._stream.write("".join(out))
        return len(text)

    def __getattr__(self, name):
        return getattr(self._stream, name)


def turn_over_stderr_file(label: str) -> None:
    """At a launchd run's start: an oversized StandardErrorPath goes to ``.1``. This run
    keeps writing to it; launchd opens a fresh one for the next."""
    try:
        from claude_swap import launch_agent

        err = launch_agent.log_paths(label)[1]
        if err.stat().st_size > STDERR_MAX_BYTES:
            os.replace(err, err.with_name(err.name + ".1"))
    except Exception:  # noqa: BLE001
        pass
