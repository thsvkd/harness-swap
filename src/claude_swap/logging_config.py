"""Logging configuration for Claude Swap."""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _restrict(log_file: Path) -> None:
    """The log and its rotated copies are the owner's: credential paths log here."""
    for path in log_file.parent.glob(log_file.name + "*"):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # a race with rotation, or a file that is not ours to change


class _LazyDirRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that creates its parent dir on first emit.

    Keeps the backup root from being materialized just because the switcher
    was instantiated. Necessary so a no-op run (e.g. ``cswap --status`` with
    no managed accounts) doesn't lay down ``cache/`` or log files inside the
    XDG path, which would later trip the legacy → XDG migration collision
    check if a legacy directory appeared between runs.
    """

    def _open(self):  # type: ignore[override]
        path = Path(self.baseFilename)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600))
        _restrict(path)
        return super()._open()


class _RunContext(logging.Filter):
    """Who ran the command that logged this line (see claude_swap.events)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from claude_swap import events

            ctx = events.context()
        except Exception:  # noqa: BLE001 - a log line never fails on this
            ctx = {"cmd": "-", "caller": "-", "session": "-"}
        record.run_cmd, record.run_caller, record.run_session = ctx["cmd"], ctx["caller"], ctx["session"]
        return True


def setup_logging(log_dir: Path, debug: bool = False) -> logging.Logger:
    """Setup logging with file and optional console output.

    The log directory is *not* created eagerly; it materializes on the first
    log record actually written, via ``_LazyDirRotatingFileHandler``.

    Args:
        log_dir: Directory to store log files.
        debug: Enable debug logging to console.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("claude-swap")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Clear any existing handlers
    logger.handlers.clear()

    # File handler - opens lazily so the dir is only created when something
    # is actually logged.
    log_file = log_dir / "claude-swap.log"
    _restrict(log_file)  # a run that logs nothing still narrows an old 0644 log
    file_handler = _LazyDirRotatingFileHandler(
        log_file,
        maxBytes=1024 * 1024,  # 1MB
        backupCount=3,
        delay=True,
    )
    file_handler.setLevel(logging.DEBUG)
    # The run's context goes after the level, so "<time> - <LEVEL> - " still starts each
    # line and the message stays whole for anything that greps it.
    file_handler.addFilter(_RunContext())
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(levelname)s - "
            "[cmd=%(run_cmd)s caller=%(run_caller)s session=%(run_session)s] %(message)s"
        )
    )
    logger.addHandler(file_handler)

    # Console handler for debug mode
    if debug:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(console_handler)

    return logger
