"""Antigravity CLI adapter: file switching, honest capabilities, usage asked of a fake agy."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime

import pytest

from harness_swap.adapters.agy import TOKEN_FILE, AgyAdapter
from harness_swap.core import accounts as service
from harness_swap.core import sessions, settings
from harness_swap.core.errors import HswapError, UnsupportedOperation
from harness_swap.core.models import Capability, Installation, Support, UsageState
from tests.hswap_helpers import fake_executable, write_json

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake executables are POSIX scripts")


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def token_doc(email: str, expires_in: float = 3600, method: str = "consumer") -> dict:
    return {
        "token": {
            "access_token": f"synthetic-access-{email}",
            "token_type": "Bearer",
            "refresh_token": f"synthetic-refresh-{email}",
            "expiry": iso(time.time() + expires_in),
            "expires_in": 3599,
        },
        "auth_method": method,
        "id_token_email": email,
    }


# A fake agy: records its argv/env/stdin per call, answers /usage from
# <home>/fake-usage.json (home = --gemini_dir or ~/.gemini), keyed by the
# token's email; prints a secret-looking line on failure.
FAKE_AGY = r"""
from pathlib import Path
args = sys.argv[1:]
home = Path(os.environ["HOME"]) / ".gemini"
if args and args[0].startswith("--gemini_dir="):
    home = Path(args.pop(0).split("=", 1)[1])
log = Path(os.environ["AGY_FAKE_LOG"])
with log.open("a") as fh:
    fh.write(json.dumps({"home": str(home), "args": args, "tty": sys.stdin.isatty(),
                         "noupdate": os.environ.get("AGY_CLI_DISABLE_AUTO_UPDATE"),
                         "dbus": os.environ.get("DBUS_SESSION_BUS_ADDRESS")}) + "\n")
email = json.loads((home / "antigravity-cli" / "antigravity-oauth-token").read_text())["id_token_email"]
answers = json.loads((Path(os.environ["AGY_FAKE_LOG"]).parent / "answers.json").read_text())
answer = answers[email]
if answer == "crash":
    print("synthetic-access-LEAK")
    sys.exit(3)
if answer == "login-prompt":  # a login agy cannot refresh: it waits for a browser sign-in
    print("Authentication required. Please visit the URL to log in:", file=sys.stderr, flush=True)
    import time
    time.sleep(30)
print(json.dumps(answer))
"""


def usage_doc(*buckets, status="SUCCESS", response=""):
    return {"conversation_id": "", "status": status, "response": response,
            "command": {"name": "usage", "data": {"groups": list(buckets)}}}


def group(name, *buckets):
    return {"name": name, "buckets": list(buckets)}


def bucket(window, remaining=None, reset=None, disabled=False):
    b = {"id": window, "name": f"{window} limit", "window": window}
    if remaining is not None:
        b["remaining_fraction"] = remaining
    if reset is not None:
        b["reset_time"] = reset
    if disabled:
        b["disabled"] = True
    return b


@pytest.fixture
def agy(tmp_path, monkeypatch):
    user = tmp_path / "user"
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setattr("pathlib.Path.home", lambda: user)
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    monkeypatch.setenv("AGY_FAKE_LOG", str(tmp_path / "calls.jsonl"))
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [])
    exe = fake_executable(tmp_path / "bin", "agy", FAKE_AGY)
    adapter = AgyAdapter()
    adapter._installation = Installation(True, str(exe), "1.4.8")
    return adapter, user / ".gemini", tmp_path


def sign_in(home, email, **kw):
    return write_json(home / TOKEN_FILE, token_doc(email, **kw))


def calls(tmp_path):
    log = tmp_path / "calls.jsonl"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def two_accounts(adapter, home):
    sign_in(home, "B@x.com")
    adapter.add_account()
    sign_in(home, "a@x.com")
    adapter.add_account()
    by_label = {a.label: a for a in adapter.list_accounts()}
    return by_label["a@x.com"], by_label["B@x.com"]


def test_identity_switch_and_restart_note(agy, monkeypatch):
    adapter, home, _ = agy
    a, b = two_accounts(adapter, home)
    assert (a.identity, a.provider, a.auth_mode, a.active) == ("consumer/a@x.com", "google", "consumer", True)
    assert b.identity == "consumer/b@x.com" and not b.active
    assert service.switch(adapter, "a@x.com").notes == ("already the active account",)
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [object()])
    result = service.switch(adapter, "B@x.com")
    assert json.loads((home / TOKEN_FILE).read_text())["id_token_email"] == "B@x.com"
    assert result.restart_required and sum("restart" in n for n in result.notes) == 1
    with pytest.raises(UnsupportedOperation, match="no sign-in command"):
        adapter.add_account(login=True)


def test_capabilities_are_honest(agy, monkeypatch):
    adapter, home, _ = agy
    caps = adapter.capabilities()
    assert caps[Capability.ACCOUNT_SWITCH].support is Support.UNAVAILABLE  # no token file: keyring or not signed in
    sign_in(home, "a@x.com")
    caps = adapter.capabilities()
    assert caps[Capability.ACCOUNT_SWITCH].support is Support.SUPPORTED
    assert caps[Capability.PARALLEL_SESSIONS].support is Support.EXPERIMENTAL
    assert caps[Capability.CREDENTIAL_HOT_RELOAD].support is Support.UNSUPPORTED
    usage = caps[Capability.USAGE_MONITORING]
    assert usage.support is Support.UNAVAILABLE and "hswap config set usage.remote" in usage.reason
    assert caps[Capability.AUTOMATIC_ROTATION].support is Support.UNAVAILABLE
    settings.set_value("usage.remote", "agy")
    caps = adapter.capabilities()
    assert caps[Capability.USAGE_MONITORING].support is Support.EXPERIMENTAL
    auto = caps[Capability.AUTOMATIC_ROTATION]
    assert auto.support is Support.EXPERIMENTAL
    assert "Antigravity Additional Terms" in auto.reason and "suspended in 2026" in auto.reason
    with monkeypatch.context() as m:
        m.setattr(sys, "platform", "darwin")
        caps = adapter.capabilities()
    assert caps[Capability.ACCOUNT_SWITCH].support is Support.UNAVAILABLE and "keychain" in caps[Capability.ACCOUNT_SWITCH].reason
    assert caps[Capability.USAGE_MONITORING].support is Support.UNAVAILABLE


def test_usage_is_asked_of_agy_in_each_accounts_home(agy, monkeypatch):
    adapter, home, tmp = agy
    a, b = two_accounts(adapter, home)
    reset = "2026-11-03T03:00:00Z"
    write_json(tmp / "answers.json", {
        "a@x.com": usage_doc(
            group("Gemini Models", bucket("5h", 0.75, reset), bucket("weekly", 0.4000000059604645, reset)),
            group("Claude and GPT models", bucket("weekly", disabled=True)),
        ),
        "B@x.com": usage_doc(group("Gemini Models", bucket("5h", 0, reset))),
    })
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/synthetic/bus")
    assert adapter.read_usage(a).state is UsageState.UNSUPPORTED and calls(tmp) == []  # not opted in
    settings.set_value("usage.remote", "agy")

    snap = adapter.read_usage(a)
    assert snap.state is UsageState.AVAILABLE
    assert [(w.name, w.used_percent, w.window_seconds) for w in snap.windows] == [
        ("Gemini Models 5h", 25.0, 18000), ("Gemini Models weekly", 60.0, 604800)]
    assert snap.windows[0].resets_at == datetime(2026, 11, 3, 3, tzinfo=UTC).timestamp()

    snap = adapter.read_usage(b)
    assert snap.state is UsageState.RATE_LIMITED and snap.max_used_percent == 100.0

    active_call, other_call = calls(tmp)
    assert active_call["home"] == str(home)  # active: default home, no flag
    assert other_call["home"] == str(adapter.store.account_dir(b.slot))
    for c in (active_call, other_call):
        assert c["args"] == ["-p", "/usage", "--output-format", "json"]
        assert c["tty"] is False and c["noupdate"] == "1" and c["dbus"] is None  # file, not keyring

    write_json(tmp / "answers.json", {"B@x.com": usage_doc(group("Claude", bucket("weekly", disabled=True)))})
    assert adapter.read_usage(b).state is UsageState.UNSUPPORTED  # no quota pool: not an error


def test_usage_never_races_another_refresher(agy):
    adapter, home, tmp = agy
    a, b = two_accounts(adapter, home)
    settings.set_value("usage.remote", "agy")
    write_json(tmp / "answers.json", {"a@x.com": usage_doc(group("G", bucket("5h", 1.0)))})
    sign_in(home, "a@x.com", expires_in=300)  # active token about to expire
    snap = adapter.read_usage(a)
    assert snap.state is UsageState.STALE and "about to expire" in snap.detail
    doc = token_doc("a@x.com")
    del doc["token"]["expiry"]  # unreadable expiry: never guess
    write_json(home / TOKEN_FILE, doc)
    assert adapter.read_usage(a).state is UsageState.STALE
    fd = sessions.acquire(adapter.store.account_dir(b.slot))  # a running `hswap agy run` owns b
    try:
        snap = adapter.read_usage(b)
    finally:
        os.close(fd)
    assert snap.state is UsageState.STALE and "running session" in snap.detail
    assert calls(tmp) == []


def test_usage_failures_never_echo_output(agy):
    adapter, home, tmp = agy
    a, b = two_accounts(adapter, home)
    settings.set_value("usage.remote", "agy")
    write_json(tmp / "answers.json", {
        "a@x.com": "crash",
        "B@x.com": {"status": "ERROR", "response": "", "error": "/usage failed: 401 UNAUTHENTICATED"},
    })
    with pytest.raises(HswapError) as exc:
        adapter.read_usage(a)
    assert "LEAK" not in str(exc.value) and "status 3" in str(exc.value)
    assert adapter.read_usage(b).state is UsageState.AUTHENTICATION_REQUIRED


def test_keep_alive_asks_agy_without_opt_in_and_never_echoes(agy, monkeypatch):
    adapter, home, tmp = agy
    a, b = two_accounts(adapter, home)
    assert adapter.capabilities()[Capability.CREDENTIAL_REFRESH].support is Support.SUPPORTED
    assert "hswap agy refresh" in adapter.capabilities()[Capability.CREDENTIAL_REFRESH].reason
    write_json(tmp / "answers.json", {"a@x.com": usage_doc(group("G", bucket("5h", 1.0))),
                                      "B@x.com": usage_doc(group("G", bucket("5h", 1.0)))})
    sign_in(home, "a@x.com", expires_in=60)  # nearly expired active token: no 10-minute guard here
    assert adapter.keep_alive(a) == "login used (Google refresh tokens do not rotate)"
    assert adapter.keep_alive(b) == "login used (Google refresh tokens do not rotate)"
    c_active, c_other = calls(tmp)
    assert c_active["args"] == ["-p", "/usage", "--output-format", "json"] and not c_active["tty"]
    assert c_other["home"] != str(home) and c_other["dbus"] is None
    # a running agy owns the active login: leave it alone
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [1])
    assert "skipped" in adapter.keep_alive(a) and len(calls(tmp)) == 2
    assert adapter.keep_alive(b).startswith("login used")  # inactive account is not that process's
    # a running hswap session owns b
    fd = sessions.acquire(adapter.store.account_dir(b.slot))
    try:
        assert adapter.keep_alive(b) == "skipped: a running session keeps it fresh"
    finally:
        os.close(fd)


def test_keep_alive_auth_failure_and_missing_login(agy):
    adapter, home, tmp = agy
    a, b = two_accounts(adapter, home)
    write_json(tmp / "answers.json", {
        "a@x.com": {"status": "ERROR", "response": "", "error": "401 UNAUTHENTICATED synthetic-access-LEAK"},
        "B@x.com": "crash",
    })
    with pytest.raises(HswapError, match="sign in again") as exc:
        adapter.keep_alive(a)
    assert "LEAK" not in str(exc.value)
    with pytest.raises(HswapError) as exc:
        adapter.keep_alive(b)
    assert "LEAK" not in str(exc.value)
    (adapter.store.account_dir(b.slot) / TOKEN_FILE).unlink()
    n = len(calls(tmp))
    with pytest.raises(HswapError, match="no stored credentials"):
        adapter.keep_alive(b)
    assert len(calls(tmp)) == n  # agy never started: it would wait for an interactive sign-in


def test_a_login_agy_cannot_refresh_says_sign_in_again_at_once(agy):
    adapter, home, tmp = agy
    _a, b = two_accounts(adapter, home)
    settings.set_value("usage.remote", "agy")
    write_json(tmp / "answers.json", {"a@x.com": "login-prompt", "B@x.com": "login-prompt"})
    started = time.monotonic()
    with pytest.raises(HswapError, match="sign in again"):
        adapter.keep_alive(b)
    assert adapter.read_usage(b).state is UsageState.AUTHENTICATION_REQUIRED
    assert time.monotonic() - started < 15  # not agy's 60 s wait for a browser
