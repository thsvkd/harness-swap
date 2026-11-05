"""Tests for claude_swap.logging_config."""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path

import pytest

from claude_swap.logging_config import setup_logging


def test_setup_does_not_create_dir(tmp_path: Path):
    """Calling setup_logging must not materialize the log directory.

    The log dir lives under the cswap backup root; pre-creating it laid down
    cache/log artifacts that later tripped the legacy → XDG migration
    collision check (see paths.migrate_legacy_backup_dir).
    """
    log_dir = tmp_path / "should-not-exist"
    logger = setup_logging(log_dir)
    try:
        assert not log_dir.exists()
        # File handler is registered but stays unopened until first emit.
        assert logger.handlers
    finally:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)


def test_dir_is_created_on_first_log(tmp_path: Path):
    log_dir = tmp_path / "lazy"
    logger = setup_logging(log_dir)
    try:
        assert not log_dir.exists()
        logger.warning("trigger")
        for handler in logger.handlers:
            handler.flush()
        assert log_dir.is_dir()
        assert (log_dir / "claude-swap.log").exists()
    finally:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)


def test_debug_adds_console_handler(tmp_path: Path):
    log_dir = tmp_path / "dbg"
    logger = setup_logging(log_dir, debug=True)
    try:
        assert logger.level == logging.DEBUG
        assert any(
            isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
            for h in logger.handlers
        )
    finally:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
class TestLogFileIsPrivate:
    def _mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def _close(self, logger):
        for handler in logger.handlers:
            handler.close()

    def test_a_new_log_is_0600_whatever_the_umask(self, tmp_path):
        previous = os.umask(0o022)
        try:
            logger = setup_logging(tmp_path)
            logger.info("x")
            self._close(logger)
        finally:
            os.umask(previous)
        assert self._mode(tmp_path / "claude-swap.log") == 0o600

    def test_an_existing_0644_log_and_its_rotated_copies_are_narrowed_at_setup(self, tmp_path):
        paths = [tmp_path / "claude-swap.log", tmp_path / "claude-swap.log.1"]
        for path in paths:
            path.write_text("old")
            path.chmod(0o644)
        self._close(setup_logging(tmp_path))  # logs nothing
        assert [self._mode(path) for path in paths] == [0o600, 0o600]

    def test_a_rotated_in_log_stays_0600(self, tmp_path):
        previous = os.umask(0o022)
        try:
            logger = setup_logging(tmp_path)
            logger.handlers[0].maxBytes = 50
            for _ in range(5):
                logger.info("x" * 40)
            self._close(logger)
        finally:
            os.umask(previous)
        rotated = sorted(tmp_path.glob("claude-swap.log*"))
        assert len(rotated) >= 2
        assert {self._mode(path) for path in rotated} == {0o600}

    def test_setup_does_not_create_the_directory(self, tmp_path):
        self._close(setup_logging(tmp_path / "missing"))
        assert not (tmp_path / "missing").exists()
