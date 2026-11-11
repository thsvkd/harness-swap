"""`add --login --json`: the sign-in prompt is parsed into JSON Lines events."""

from __future__ import annotations

import json
import os
import sys

import pytest

from harness_swap import cli
from harness_swap.core.models import Installation
from harness_swap.core.registry import Registry
from harness_swap.infrastructure import login_events
from tests.hswap_helpers import codex_auth, fake_executable

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="fake executables are POSIX scripts")

# Captured from codex-cli 0.167.0, grok and claude (2026-11-11), ANSI kept.
CODEX = (
    "Follow these steps to sign in with ChatGPT using device code authorization:\n\n"
    "1. Open this link in your browser and sign in to your account\n"
    "   \x1b[94mhttps://auth.openai.com/codex/device\x1b[0m\n\n"
    "2. Enter this one-time code \x1b[90m(expires in 15 minutes)\x1b[0m\n"
    "   \x1b[94mATJC-E73B4\x1b[0m\n\n"
)
GROK = (
    "To sign in, open this URL in your browser:\n\n"
    "  https://accounts.x.ai/oauth2/device?user_code=56G7-FFE5\n\n"
    "Confirm this code in your browser:\n\n  56G7-FFE5\n\nWaiting for authorization...\n"
)
CLAUDE_URL = "https://claude.com/cai/oauth/authorize?code=true&client_id=x&state=y"
CLAUDE = f"Opening browser to sign in\nIf the browser didn't open, visit: {CLAUDE_URL}\nPaste code here if prompted > "


def test_device_prompts_are_parsed():
    assert login_events.prompt_event(CODEX, device=True) == {
        "url": "https://auth.openai.com/codex/device", "userCode": "ATJC-E73B4", "expiresInSeconds": 900,
    }
    assert login_events.prompt_event(GROK, device=True) == {
        "url": "https://accounts.x.ai/oauth2/device?user_code=56G7-FFE5",
        "userCode": "56G7-FFE5",
        "expiresInSeconds": None,
    }


def test_incomplete_output_waits_for_more():
    assert login_events.prompt_event(CODEX.split("2. Enter")[0], device=True) is None
    assert login_events.prompt_event(CLAUDE[: CLAUDE.index("state=y") + 3], device=False) is None
    assert login_events.prompt_event(CLAUDE, device=False) == {"url": CLAUDE_URL, "awaitsCode": True}


def test_error_types_form_a_closed_vocabulary():
    from claude_swap.exceptions import KeychainUnavailableError, LoginFailedError, WrongAccountError
    from harness_swap.core.errors import LoginFailed, UnsupportedOperation, WrongAccount

    for exc, kind in (
        (LoginFailed("x"), "login_failed"),
        (LoginFailedError("x"), "login_failed"),
        (WrongAccount("x"), "wrong_account"),
        (WrongAccountError("x"), "wrong_account"),
        (UnsupportedOperation("account_add", "x"), "unsupported"),
        (KeychainUnavailableError("x"), "keychain_unavailable"),
        (RuntimeError("x"), "error"),
    ):
        assert login_events.error_type(exc) == kind
        assert kind in login_events.ERROR_TYPES


@pytest.fixture
def codex_cli(tmp_path, monkeypatch):
    for name, sub in (("CODEX_HOME", "codex"), ("HSWAP_HOME", "hswap")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(name, str(tmp_path / sub))
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [])
    monkeypatch.setattr("harness_swap.adapters.codex.CodexAdapter._has_no_daemon_flag", lambda self: True)

    def install(body):
        exe = fake_executable(tmp_path / "bin", "codex", body)
        monkeypatch.setattr(
            "harness_swap.adapters.base.probe_installation",
            lambda name, args=("--version",): Installation(True, str(exe), "codex-cli 0.167.0"),
        )

    reg = Registry({"codex": "harness_swap.adapters.codex:CodexAdapter"}, discover_plugins=False)
    return reg, tmp_path, install


def _events(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


@posix_only
def test_codex_device_login_emits_the_code_then_added(codex_cli, capsys):
    reg, tmp_path, install = codex_cli
    auth = codex_auth("new@x.com", "user-n", "acct-n")
    install(f"""
assert sys.argv[1:] == ["login", "--device-auth"], sys.argv
sys.stdout.write({CODEX!r}); sys.stdout.flush()
open(os.path.join(os.environ["CODEX_HOME"], "auth.json"), "w").write({json.dumps(auth)!r})
""")
    code = cli.run(["codex", "add", "--login", "--json"], reg)
    events = _events(capsys)
    assert code == 0
    assert [e["type"] for e in events] == ["device_code", "added"]
    assert events[0]["userCode"] == "ATJC-E73B4" and events[0]["harness"] == "codex"
    assert events[1]["account"]["label"] == "new@x.com" and events[1]["refreshed"] is False
    assert not (tmp_path / "codex" / "auth.json").exists()  # the current login is untouched


@posix_only
def test_a_failed_sign_in_is_an_error_event(codex_cli, capsys):
    reg, _tmp, install = codex_cli
    install(f"sys.stdout.write({CODEX!r}); sys.exit(1)")
    code = cli.run(["codex", "add", "--login", "--json"], reg)
    events = _events(capsys)
    assert code == 1
    assert events[-1]["type"] == "error" and events[-1]["error"]["type"] == "login_failed"


def test_json_add_needs_login(codex_cli, capsys):
    reg, _tmp, _install = codex_cli
    assert cli.run(["codex", "add", "--json"], reg) == 1


def test_a_code_cut_mid_line_is_not_emitted():
    cut = CODEX[: CODEX.index("ATJC-E73B4") + len("ATJC-E73B")]
    assert login_events.prompt_event(cut, device=True) is None


def _script(tmp_path, body):
    return [sys.executable, "-c", f"import sys, os, time, subprocess\n{body}"]


@posix_only
def test_drive_passes_stdin_through_and_returns_the_exit_code(tmp_path, monkeypatch):
    import io
    import subprocess as sp

    out = io.StringIO()
    body = (
        f"sys.stdout.write({CLAUDE!r}); sys.stdout.flush()\n"
        "code = sys.stdin.readline().strip()\n"
        "sys.exit(0 if code == 'PASTED' else 9)"
    )
    r, w = os.pipe()
    os.write(w, b"PASTED\n")
    os.close(w)
    real_popen = sp.Popen
    monkeypatch.setattr(sp, "Popen", lambda *a, **k: real_popen(*a, stdin=r, **k))
    assert login_events.drive(_script(tmp_path, body), None, "claude", out, device=False) == 0
    assert json.loads(out.getvalue())["url"] == CLAUDE_URL


@posix_only
def test_drive_gives_up_without_a_recognisable_prompt(tmp_path, monkeypatch):
    import io

    monkeypatch.setattr(login_events, "PROMPT_TIMEOUT_S", 0.5)
    out = io.StringIO()
    argv = _script(tmp_path, "print('reworded prompt'); sys.stdout.flush(); time.sleep(30)")
    assert login_events.drive(argv, None, "codex", out, device=True) == login_events.NO_PROMPT
    assert out.getvalue() == ""


@posix_only
def test_drive_returns_when_the_harness_exits_though_a_child_holds_the_pipe(tmp_path):
    import io
    import time as _time

    argv = _script(tmp_path, "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])\nsys.exit(3)")
    started = _time.monotonic()
    assert login_events.drive(argv, None, "codex", io.StringIO(), device=True) == 3
    assert _time.monotonic() - started < 10


def test_unknown_provider_is_an_error_event_not_an_envelope(codex_cli, capsys):
    reg, _tmp, _install = codex_cli
    assert cli.run(["codex", "add", "--login", "--json", "--provider", "nope"], reg) == 1
    events = _events(capsys)
    assert events == [{"type": "error", "harness": "codex", "error": {"type": "error", "message": events[0]["error"]["message"]}}]
