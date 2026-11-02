"""Ask a harness a question over newline-delimited JSON-RPC on stdin/stdout.

Some harnesses answer usage questions themselves (Codex's ``app-server``,
Grok's ACP agent). Asking them, instead of calling their backend, leaves token
refresh and storage to the harness; hswap only reads the answer.

The child gets no terminal (stdin is the pipe, stderr is discarded) and is
stopped when the session ends or the deadline passes. Error messages are
scrubbed of anything credential-shaped.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from harness_swap.infrastructure.secrets import looks_secret


class RpcError(Exception):
    """``harness`` is True when the harness sent this error (its text is the harness's
    output); False for hswap's own transport failures (start, exit, timeout)."""

    def __init__(self, message: str, code: int | None = None, *, harness: bool = False):
        self.code = code
        self.harness = harness
        super().__init__(message)


def _clean(text: object) -> str:
    text = " ".join(str(text).split())[:300]  # one line: a harness may quote a multi-line server body
    return "(message withheld: looks like it contains a credential)" if looks_secret(text) else text


class _Session:
    def __init__(self, proc: subprocess.Popen, deadline: float, version_tag: bool):
        self._proc = proc
        self._deadline = deadline
        self._tag = {"jsonrpc": "2.0"} if version_tag else {}
        self._next_id = 0
        self._lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self._proc.stdout:  # type: ignore[union-attr]
            self._lines.put(line)
        self._lines.put(None)

    def _send(self, message: dict) -> None:
        try:
            self._proc.stdin.write(json.dumps({**self._tag, **message}) + "\n")  # type: ignore[union-attr]
            self._proc.stdin.flush()  # type: ignore[union-attr]
        except OSError:
            raise RpcError("the harness closed its input") from None

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"method": method, **({"params": params} if params is not None else {})})

    def request(self, method: str, params: dict | None = None) -> Any:
        """Send one request and wait for its response (other messages are skipped)."""
        msg_id = self._next_id
        self._next_id += 1
        self._send({"id": msg_id, "method": method, **({"params": params} if params is not None else {})})
        while True:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise RpcError(f"no answer to {method} in time")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                raise RpcError(f"no answer to {method} in time") from None
            if line is None:
                raise RpcError(f"the harness exited before answering {method}")
            try:
                message = json.loads(line)
            except ValueError:
                continue  # log output on stdout
            if not isinstance(message, dict) or message.get("id") != msg_id or "method" in message:
                continue  # a notification, or the harness asking us something
            if "error" in message:
                err = message["error"] if isinstance(message["error"], dict) else {"message": message["error"]}
                detail = err.get("data") if isinstance(err.get("data"), str) else err.get("message")
                raise RpcError(_clean(detail or "error"), err.get("code"), harness=True)
            return message.get("result")


@contextmanager
def session(
    argv: list[str], env: dict[str, str], *, timeout: float, version_tag: bool = True
) -> Iterator[_Session]:
    """Start ``argv`` and talk to it until the block ends (``timeout`` in total)."""
    try:
        proc = subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            # Its own process group, so helpers it starts (MCP servers, ...) end with it.
            start_new_session=os.name == "posix",
        )
    except OSError as exc:
        raise RpcError(f"could not start {argv[0]}: {exc}") from None
    try:
        yield _Session(proc, time.monotonic() + timeout, version_tag)
    finally:
        _stop(proc)


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, sig)
        elif sig == signal.SIGTERM:
            proc.terminate()
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _stop(proc: subprocess.Popen) -> None:
    """Close stdin, give the harness a moment to exit, then end its whole group."""
    try:
        proc.stdin.close()  # type: ignore[union-attr]
    except OSError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        _signal_group(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
            proc.wait()
    _signal_group(proc, signal.SIGTERM)  # helpers the harness left behind
