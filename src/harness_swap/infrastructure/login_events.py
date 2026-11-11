"""``add --login --json``: drive a harness's own sign-in for a parent process.

The parent (a web gateway) reads JSON Lines on stdout and writes the pasted
code to hswap's stdin, which the harness inherits. The harness's own output is
parsed here and never forwarded: it is free text that can change, and the
parent should depend on these events only. Events:

  {"type": "login_url", "harness", "url", "awaitsCode": true}       (Claude)
  {"type": "device_code", "harness", "url", "userCode", "expiresInSeconds"}
  {"type": "added", "harness", "account", "refreshed", "keepalive"}  exit 0
  {"type": "error", "harness", "error": {"type", "message"}}        exit 1

``error.type`` is one of ERROR_TYPES; the parent allowlists them.
"""

from __future__ import annotations

import json
import queue
import re
import signal
import subprocess
import threading
import time
from collections.abc import Mapping
from typing import TextIO

#: No recognisable prompt by then: the harness changed its wording; give up rather than hang.
PROMPT_TIMEOUT_S = 60.0
#: drive()'s return code when that happened.
NO_PROMPT = 124

ERROR_TYPES = ("login_failed", "wrong_account", "unsupported", "not_installed", "keychain_unavailable", "error")

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_URL = re.compile(r"(https://\S+)\s")  # trailing whitespace: the URL is complete
_USER_CODE = re.compile(r"^[ \t]*([A-Z0-9]{4,}-[A-Z0-9]{4,})[ \t]*\r?\n", re.M)  # whole line only
_EXPIRES = re.compile(r"expires in (\d+) minute")


def emit(out: TextIO, harness: str, kind: str, **fields) -> None:
    out.write(json.dumps({"type": kind, "harness": harness, **fields}) + "\n")
    out.flush()


def error_type(exc: BaseException) -> str:
    names = {c.__name__ for c in type(exc).__mro__}
    for name, kind in (
        ("LoginFailed", "login_failed"),
        ("LoginFailedError", "login_failed"),
        ("WrongAccount", "wrong_account"),
        ("WrongAccountError", "wrong_account"),
        ("UnsupportedOperation", "unsupported"),
        ("HarnessNotInstalled", "not_installed"),
        ("ClaudeNotInstalledError", "not_installed"),
        ("KeychainUnavailableError", "keychain_unavailable"),
    ):
        if name in names:
            return kind
    return "error"


def emit_error(out: TextIO, harness: str, exc: BaseException) -> None:
    emit(out, harness, "error", error={"type": error_type(exc), "message": str(exc)})


def prompt_event(text: str, device: bool) -> dict | None:
    """The sign-in prompt in the harness's output so far, once it is complete."""
    clean = _ANSI.sub("", text)
    url = _URL.search(clean)
    if url is None:
        return None
    if not device:
        return {"url": url.group(1), "awaitsCode": True}
    code = _USER_CODE.search(clean, url.end())
    if code is None:
        return None
    expires = _EXPIRES.search(clean)
    return {
        "url": url.group(1),
        "userCode": code.group(1),
        "expiresInSeconds": int(expires.group(1)) * 60 if expires else None,
    }


def _terminate(signum, frame):
    raise SystemExit(128 + signum)


def drive(argv: list[str], env: Mapping[str, str] | None, harness: str, out: TextIO, *, device: bool) -> int:
    """Run the sign-in with stdin inherited, emit its prompt once, return its exit code.

    Returns NO_PROMPT when no prompt was recognised in PROMPT_TIMEOUT_S. Stops
    when the process exits, even if a child of it keeps the pipe open. A SIGTERM
    to hswap ends the harness too, and lets the caller's cleanup run.
    """
    previous = signal.signal(signal.SIGTERM, _terminate)
    proc = None
    try:
        proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        chunks: queue.Queue[bytes] = queue.Queue()

        def pump():
            for chunk in iter(lambda: proc.stdout.read1(4096), b""):
                chunks.put(chunk)

        threading.Thread(target=pump, daemon=True).start()
        raw, sent, deadline = b"", False, time.monotonic() + PROMPT_TIMEOUT_S
        while True:
            try:
                chunk = chunks.get(timeout=0.2)
            except queue.Empty:
                if proc.poll() is not None:
                    return proc.returncode
                if not sent and time.monotonic() > deadline:
                    return NO_PROMPT
                continue
            if sent:
                continue  # keep draining so the harness never blocks on a full pipe
            raw += chunk
            found = prompt_event(raw.decode("utf-8", "replace"), device)
            if found:
                emit(out, harness, "device_code" if device else "login_url", **found)
                sent = True
    finally:
        signal.signal(signal.SIGTERM, previous)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
