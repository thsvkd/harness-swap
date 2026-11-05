"""Unit tests for the macOS ``security``-CLI wrapper (claude_swap.macos_keychain).

These mock ``subprocess.run`` so they exercise the wrapper's argv/stdin shaping,
hex encoding, and return-code handling without ever invoking the real
``security`` binary. (The autouse ``block_real_keychain`` guard replaces the
module's functions for *other* tests; here we patch ``subprocess`` so the real
function bodies run against a fake process.)
"""

from __future__ import annotations

import json
import subprocess
import traceback
from unittest.mock import MagicMock, patch

import pytest

from claude_swap import macos_keychain
from claude_swap.logging_config import setup_logging

# Every test here drives the *real* wrapper bodies (mocking subprocess) or runs
# against a temp keychain on CI, so opt the whole module out of the in-memory
# Keychain guard that replaces these functions for other tests.
pytestmark = pytest.mark.no_keychain_fake


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["security"], returncode=returncode, stdout=stdout, stderr=stderr
    )


# ---------------------------------------------------------------------------
# get_password
# ---------------------------------------------------------------------------


def test_get_password_returns_value_on_rc0():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(0, stdout="the-secret\n")
        assert macos_keychain.get_password("svc", "acct") == "the-secret"
        args = run.call_args.args[0]
        assert args[:2] == ["/usr/bin/security", "find-generic-password"]
        assert "-a" in args and "acct" in args and "svc" in args


def test_get_password_returns_none_only_on_rc44():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(44)
        assert macos_keychain.get_password("svc", "acct") is None


def test_get_password_raises_on_other_nonzero():
    # e.g. locked / denied / unavailable — must NOT be masked as "not found".
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(51, stderr="boom")
        with pytest.raises(macos_keychain.KeychainError):
            macos_keychain.get_password("svc", "acct")


# ---------------------------------------------------------------------------
# item_exists
# ---------------------------------------------------------------------------


def test_item_exists_true_on_rc0_and_never_requests_secret():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(0)
        assert macos_keychain.item_exists("svc", "acct") is True
        args = run.call_args.args[0]
        # Attribute-only lookup: must never pass -w (decrypting could prompt).
        assert "-w" not in args


def test_item_exists_false_on_rc44_and_errors():
    for rc in (44, 51):
        with patch("claude_swap.macos_keychain.subprocess.run") as run:
            run.return_value = _completed(rc)
            assert macos_keychain.item_exists("svc", "acct") is False


# ---------------------------------------------------------------------------
# set_password — the secret only ever travels on security -i's stdin
# ---------------------------------------------------------------------------


def test_set_password_small_payload_uses_security_i_stdin():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(0)
        macos_keychain.set_password("svc", "acct", "short-secret")

        args = run.call_args.args[0]
        kwargs = run.call_args.kwargs
        assert args == ["/usr/bin/security", "-i"]  # stdin path
        # Secret is NOT in argv; it rides in on stdin as a hex `-X` value.
        assert "short-secret" not in args
        stdin = kwargs["input"]
        assert stdin.startswith("add-generic-password -U")
        assert "-X " + "short-secret".encode().hex() in stdin
        # -a/-s are quoted in the stdin command line.
        assert '-a "acct"' in stdin and '-s "svc"' in stdin


def _split_line(line):
    """`security -i`'s tokenizer (Security/SecurityTool/macOS/security.c, split_line):
    quotes delimit, and a backslash copies the next character literally."""
    args, current, quote, escaped, in_arg = [], [], None, False, False
    for ch in line.rstrip("\n"):
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped, in_arg = True, True
        elif quote:
            if ch == quote:
                quote = None
            else:
                current.append(ch)
        elif ch in "\"'":
            quote, in_arg = ch, True
        elif ch.isspace():
            if in_arg:
                args.append("".join(current))
                current, in_arg = [], False
        else:
            current.append(ch)
            in_arg = True
    if in_arg:
        args.append("".join(current))
    return args


def _stored_value(line):
    """What `add-generic-password` stores from this stdin line."""
    args = _split_line(line)
    assert args[:2] == ["add-generic-password", "-U"]
    assert "\n" not in line.rstrip("\n")
    if "-X" in args:
        return bytes.fromhex(args[args.index("-X") + 1]).decode()
    return args[args.index("-w") + 1]


def _credential(size):
    """A real credential's shape, exactly `size` bytes of JSON."""
    login = {
        "accessToken": "sk-ant-oat01-" + "A" * 400,
        "refreshToken": "sk-ant-ort01-" + "B" * 400,
        "expiresAt": 1793900000000,
        "scopes": ["user:inference", "user:profile"],
    }
    base = len(json.dumps({"claudeAiOauth": login, "pad": ""}))
    return json.dumps({"claudeAiOauth": login, "pad": "C" * (size - base)})


@pytest.mark.parametrize("size", [2048, 3500])
def test_real_credential_sizes_never_reach_argv_and_round_trip(size):
    secret = _credential(size)
    assert len(secret) == size
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(0)
        macos_keychain.set_password("Claude Code-credentials", "me", secret)
    assert run.call_count == 1
    argv = " ".join(run.call_args.args[0])
    assert run.call_args.args[0] == ["/usr/bin/security", "-i"]
    assert secret not in argv and secret.encode().hex() not in argv and "sk-ant" not in argv
    stdin = run.call_args.kwargs["input"]
    assert " -w " in stdin  # the hex form would overflow the line buffer
    assert len(stdin.encode()) <= macos_keychain.SECURITY_STDIN_LINE_LIMIT
    assert _stored_value(stdin) == secret


@pytest.mark.parametrize(
    "secret",
    ['a"b', 'a\\b', 'trailing\\', '\\"', 'it\'s', "with space", '-w', 'é"\\'],
)
def test_quotes_and_backslashes_survive_security_i_parsing(secret):
    padded = secret + "x" * 2100  # past the hex form's limit, so `-w`
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(0)
        macos_keychain.set_password("svc", "acct", padded)
    assert " -w " in run.call_args.kwargs["input"]
    assert _stored_value(run.call_args.kwargs["input"]) == padded


def test_hex_form_is_kept_when_it_fits():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(0)
        macos_keychain.set_password("svc", "acct", "x" * 1900)
    assert " -X " in run.call_args.kwargs["input"]


@pytest.mark.parametrize(
    "value",
    [
        "x" * macos_keychain.SECURITY_STDIN_LINE_LIMIT,  # too long either way
        '"' * 2100,  # short, but escaping doubles it
        "line\nbreak" + "x" * 2100,  # would end the command early
        "nul\0" + "x" * 2100,
    ],
    ids=["too-long", "too-long-escaped", "newline", "nul"],
)
def test_a_value_stdin_cannot_carry_is_refused_not_sent_to_argv(value):
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        with pytest.raises(macos_keychain.KeychainError) as err:
            macos_keychain.set_password("svc", "acct", value)
    run.assert_not_called()
    assert value not in str(err.value)


def test_set_password_raises_on_nonzero():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(45, stderr="nope")
        with pytest.raises(macos_keychain.KeychainError):
            macos_keychain.set_password("svc", "acct", "secret")


def test_set_get_roundtrip_hex_is_decodable():
    # The hex written on set must decode back to the original UTF-8 secret.
    secret = 'token-with "quotes" and \\ backslash and é'
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _completed(0)

    with patch("claude_swap.macos_keychain.subprocess.run", side_effect=fake_run):
        macos_keychain.set_password("svc", "acct", secret)
    stdin = captured["kwargs"]["input"]
    hex_token = stdin.split("-X ", 1)[1].strip()
    assert bytes.fromhex(hex_token).decode("utf-8") == secret


# ---------------------------------------------------------------------------
# delete_password
# ---------------------------------------------------------------------------


def test_delete_password_rc0_and_rc44_are_success():
    for rc in (0, 44):
        with patch("claude_swap.macos_keychain.subprocess.run") as run:
            run.return_value = _completed(rc)
            macos_keychain.delete_password("svc", "acct")  # no raise


def test_delete_password_raises_on_other_nonzero():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(51, stderr="locked")
        with pytest.raises(macos_keychain.KeychainError):
            macos_keychain.delete_password("svc", "acct")


# ---------------------------------------------------------------------------
# timeouts — a wedged Keychain must surface as KeychainError, never a hang
# ---------------------------------------------------------------------------


def test_calls_pass_timeout_to_subprocess():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(0, stdout="x\n")
        macos_keychain.get_password("svc", "acct")
        assert run.call_args.kwargs.get("timeout") == macos_keychain._TIMEOUT


@pytest.mark.parametrize("fn,args", [
    ("get_password", ("svc", "acct")),
    ("set_password", ("svc", "acct", "secret")),
    ("delete_password", ("svc", "acct")),
])
def test_timeout_becomes_keychain_error(fn, args):
    timeout = subprocess.TimeoutExpired(cmd="security", timeout=5)
    with patch("claude_swap.macos_keychain.subprocess.run", side_effect=timeout):
        with pytest.raises(macos_keychain.KeychainError):
            getattr(macos_keychain, fn)(*args)


@pytest.mark.parametrize("fn,args", [
    ("get_password", ("svc", "acct")),
    ("set_password", ("svc", "acct", "SECRET-TOKEN")),
    ("delete_password", ("svc", "acct")),
])
def test_timeout_carries_no_command_into_message_chain_or_log(fn, args, tmp_path):
    secret_hex = "SECRET-TOKEN".encode().hex()
    timeout = subprocess.TimeoutExpired(
        cmd=["security", "-w", "SECRET-TOKEN", "-X", secret_hex], timeout=5,
        output="SECRET-TOKEN",
    )
    logger = setup_logging(tmp_path)
    with patch("claude_swap.macos_keychain.subprocess.run", side_effect=timeout):
        with pytest.raises(macos_keychain.KeychainError) as err:
            getattr(macos_keychain, fn)(*args)
    exc = err.value
    assert exc.__cause__ is None and exc.__suppress_context__ is True
    try:
        raise exc
    except macos_keychain.KeychainError:
        logger.warning("Persisting failed", exc_info=True)
    for handler in logger.handlers:
        handler.close()
    rendered = "".join(traceback.format_exception(exc))
    log_text = (tmp_path / "claude-swap.log").read_text()
    for text in (str(exc), repr(exc), rendered, log_text):
        assert "SECRET-TOKEN" not in text and secret_hex not in text
    assert "KeychainError" in log_text


def test_failed_write_message_carries_no_stderr():
    with patch("claude_swap.macos_keychain.subprocess.run") as run:
        run.return_value = _completed(45, stderr="echoed SECRET-TOKEN")
        with pytest.raises(macos_keychain.KeychainError) as err:
            macos_keychain.set_password("svc", "acct", "SECRET-TOKEN")
    assert "SECRET-TOKEN" not in str(err.value)


def test_item_exists_stays_false_on_timeout_and_missing_binary():
    # item_exists must never raise (it feeds cleanup, not the capability cache).
    timeout = subprocess.TimeoutExpired(cmd="security", timeout=5)
    with patch("claude_swap.macos_keychain.subprocess.run", side_effect=timeout):
        assert macos_keychain.item_exists("svc", "acct") is False
    with patch("claude_swap.macos_keychain.subprocess.run", side_effect=FileNotFoundError):
        assert macos_keychain.item_exists("svc", "acct") is False


# ---------------------------------------------------------------------------
# keychain_account_name — mirror Claude Code's getUsername()
# ---------------------------------------------------------------------------


def test_keychain_account_name_prefers_user_env(monkeypatch):
    monkeypatch.setenv("USER", "alice")
    assert macos_keychain.keychain_account_name() == "alice"


def test_keychain_account_name_no_user_env_avoids_legacy_default(monkeypatch):
    # The old active-store default was the bare string "user", which mismatches
    # Claude Code's OS-username on headless hosts ($USER unset). The shared helper
    # must fall back to the OS username / "claude-code-user", never "user".
    monkeypatch.delenv("USER", raising=False)
    name = macos_keychain.keychain_account_name()
    assert name and name != "user"


# The real-Keychain round-trip test lives in test_macos_keychain_contract.py,
# next to the `tmp_keychain` fixture it depends on.
