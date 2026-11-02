"""Codex adapter against synthetic CODEX_HOME trees and a fake `codex` binary."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC
from pathlib import Path

import pytest

from harness_swap.adapters.codex import CodexAdapter, snapshot_from_rate_limits
from harness_swap.core import accounts as service
from harness_swap.core import sessions
from harness_swap.core.errors import HswapError, UnsupportedOperation
from harness_swap.core.models import Capability, Installation, Support, UsageState
from harness_swap.core.usage import UsageService
from tests.hswap_helpers import codex_auth, fake_executable, write_json

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="fake executables are POSIX scripts")


@pytest.fixture
def codex(tmp_path, monkeypatch):
    home = tmp_path / "codex-home"
    home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(home))
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    adapter = CodexAdapter()
    adapter._installation = Installation(True, "/fake/codex", "codex-cli 0.166.0")
    adapter._no_daemon = True
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [])
    return adapter, home


def login(home: Path, email, user, account, refresh="1"):
    return write_json(home / "auth.json", codex_auth(email, user, account, refresh))


def test_identity_comes_from_the_id_token(codex):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    acc = adapter.add_account()
    assert (acc.label, acc.identity, acc.provider, acc.auth_mode) == ("a@x.com", "user-a/acct-a", "openai", "chatgpt")
    assert acc.details["plan"] == "plus"


def test_same_user_in_two_workspaces_is_two_accounts(codex):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "personal")
    adapter.add_account()
    login(home, "a@x.com", "user-a", "team")
    adapter.add_account()
    assert [a.slot for a in adapter.list_accounts()] == [1, 2]


def test_api_key_login_is_fingerprinted_never_shown(codex):
    adapter, home = codex
    write_json(home / "auth.json", {"auth_mode": "apikey", "OPENAI_API_KEY": "sk-synthetic-0123456789abcdef"})
    acc = adapter.add_account()
    assert acc.auth_mode == "api_key" and "sk-" not in acc.label and "sk-" not in acc.identity


def test_switch_round_trip_and_restart_notice(codex, monkeypatch):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account(alias="work")
    login(home, "b@x.com", "user-b", "acct-b", refresh="b1")
    adapter.add_account()
    login(home, "b@x.com", "user-b", "acct-b", refresh="b2")  # Codex rotated b's token
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [4242])
    result = service.switch(adapter, "work")
    assert result.current.label == "a@x.com" and result.previous.label == "b@x.com"
    assert result.restart_required and "restarted" in result.notes[0]
    assert json.loads((home / "auth.json").read_text())["tokens"]["account_id"] == "acct-a"
    stored_b = json.loads((adapter.store.account_dir(2) / "auth.json").read_text())
    assert stored_b["tokens"]["refresh_token"] == "synthetic-refresh-b2"
    assert [a.active for a in adapter.list_accounts()] == [True, False]


@pytest.mark.parametrize("mode", ["keyring", "auto", "ephemeral"])
def test_non_file_credential_stores_are_refused(codex, mode):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account()
    (home / "config.toml").write_text(f'cli_auth_credentials_store = "{mode}"\n')
    assert [a.active for a in adapter.list_accounts()] == [None]  # auth.json is not what Codex uses
    caps = adapter.capabilities()
    assert caps[Capability.ACCOUNT_SWITCH].support is Support.UNAVAILABLE
    assert mode in caps[Capability.ACCOUNT_SWITCH].reason
    with pytest.raises(UnsupportedOperation, match="file-backed"):
        service.switch(adapter, "1")


def test_missing_binary_still_lists(codex):
    adapter, _home = codex
    adapter._installation = Installation(False, detail="`codex` not found on PATH")
    caps = adapter.capabilities()
    assert caps[Capability.ACCOUNT_LIST].usable
    assert not caps[Capability.ACCOUNT_SWITCH].usable and "not installed" in caps[Capability.ACCOUNT_SWITCH].reason
    assert adapter.list_accounts() == []


def test_switch_refused_while_an_isolated_session_runs_that_account(codex):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account()
    login(home, "b@x.com", "user-b", "acct-b")
    adapter.add_account()
    fd = sessions.acquire(adapter.store.account_dir(1))
    try:
        with pytest.raises(HswapError, match="isolated"):
            service.switch(adapter, "1")
        with pytest.raises(HswapError, match="in use"):
            adapter.remove_account(adapter.list_accounts()[0])
    finally:
        import os

        os.close(fd)
    service.switch(adapter, "1")


def test_isolated_run_uses_the_account_home_and_no_daemon(codex, monkeypatch):
    adapter, home = codex
    (home / "config.toml").write_text("model = 'x'\n")
    (home / "AGENTS.md").write_text("be nice")
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account()
    login(home, "b@x.com", "user-b", "acct-b")
    adapter.add_account()
    seen = {}

    def fake_launch(argv, env, fd):
        seen.update(argv=argv, env=env, in_use=sessions.in_use(Path(env["CODEX_HOME"])))
        return 0

    monkeypatch.setattr("harness_swap.core.sessions.launch", fake_launch)
    assert service.launch(adapter, "1", ["resume", "--last"]) == 0
    profile = adapter.store.account_dir(1)
    assert seen["argv"] == ["/fake/codex", "--no-daemon", "resume", "--last"]
    assert seen["env"]["CODEX_HOME"] == str(profile) and seen["in_use"]
    if sys.platform != "win32":
        assert (profile / "config.toml").is_symlink() and (profile / "AGENTS.md").is_symlink()
    # the default home's login was not touched
    assert json.loads((home / "auth.json").read_text())["tokens"]["account_id"] == "acct-b"


def test_running_the_active_account_uses_the_default_home(codex, monkeypatch):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account()
    seen = {}
    monkeypatch.setattr(
        "harness_swap.core.sessions.launch", lambda argv, env, fd: seen.update(argv=argv, env=env, fd=fd) or 5
    )
    assert service.launch(adapter, "1", ["--help"]) == 5
    assert seen["argv"] == ["/fake/codex", "--no-daemon", "--help"] and seen["fd"] is not None
    assert seen["env"]["CODEX_HOME"] == str(home)  # inherited, not redirected to a profile
    assert not (adapter.store.account_dir(1) / ".hswap-session.lock").exists()
    os.close(seen["fd"])


def test_a_run_on_the_active_login_blocks_switch_and_remove(codex, monkeypatch):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account()
    login(home, "b@x.com", "user-b", "acct-b")
    adapter.add_account()  # b is active
    mode = (home.stat().st_mode & 0o777) if sys.platform != "win32" else None
    held = {}

    def fake_launch(argv, env, fd):
        held["fd"] = fd
        assert "already the active account" in service.switch(adapter, "2").notes  # a no-op is fine
        with pytest.raises(HswapError, match="session is using the current login"):
            service.switch(adapter, "1")
        active = next(a for a in adapter.list_accounts() if a.active)
        with pytest.raises(HswapError, match="in use"):
            adapter.remove_account(active)
        return 0

    monkeypatch.setattr("harness_swap.core.sessions.launch", fake_launch)
    assert service.launch(adapter, "2", []) == 0
    os.close(held["fd"])
    if mode is not None:
        assert home.stat().st_mode & 0o777 == mode  # the user's home keeps its permissions
    assert service.switch(adapter, "1").current.slot == 1


@posix_only
def test_add_login_with_a_taken_alias_fails_before_signing_in(codex, tmp_path):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account(alias="work")
    marker = tmp_path / "ran"
    exe = fake_executable(tmp_path / "bin", "codex", f"open({str(marker)!r}, 'w').write('x')")
    adapter._installation = Installation(True, str(exe), "codex-cli 0.166.0")
    with pytest.raises(HswapError, match="already used"):
        adapter.add_account(login=True, alias="work")
    assert not marker.exists()


@posix_only
def test_add_with_login_never_touches_the_current_login(codex, tmp_path, monkeypatch):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account()
    before = (home / "auth.json").read_bytes()
    new_auth = codex_auth("new@x.com", "user-n", "acct-n")
    exe = fake_executable(
        tmp_path / "bin",
        "codex",
        f"""
assert sys.argv[1:] == ["login"], sys.argv
open(os.path.join(os.environ["CODEX_HOME"], "auth.json"), "w").write({json.dumps(new_auth)!r})
""",
    )
    adapter._installation = Installation(True, str(exe), "codex-cli 0.166.0")
    acc = adapter.add_account(login=True, alias="new")
    assert (acc.label, acc.slot, acc.alias) == ("new@x.com", 2, "new")
    assert (home / "auth.json").read_bytes() == before
    assert not any(p.name.startswith("pending-login") for p in adapter.store.root.iterdir())


@posix_only
def test_failed_login_adds_nothing(codex, tmp_path):
    adapter, _home = codex
    exe = fake_executable(tmp_path / "bin", "codex", "sys.exit(3)")
    adapter._installation = Installation(True, str(exe), "codex-cli 0.166.0")
    with pytest.raises(HswapError, match="status 3"):
        adapter.add_account(login=True)
    assert adapter.list_accounts() == []


# -- usage from Codex's own session logs ---------------------------------------------------


def rollout(home: Path, name: str, user: str, account: str, limits: list[dict], ts=None):
    from datetime import datetime

    ts = ts or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    path = home / "sessions" / "2026" / "11" / "02" / f"rollout-{name}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [{"type": "session_meta", "payload": {"creator_user_id": user, "creator_account_id": account}}]
    lines += [{"timestamp": ts, "type": "event_msg", "payload": {"type": "token_count", "rate_limits": rl}} for rl in limits]
    path.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    return path


def limits(used, resets_at, reached=None):
    return {
        "primary": {"used_percent": used, "window_minutes": 300, "resets_at": resets_at},
        "secondary": {"used_percent": 10.0, "window_minutes": 10080, "resets_at": resets_at + 86400},
        "credits": {"has_credits": False, "unlimited": False, "balance": "0"},
        "plan_type": "plus",
        "rate_limit_reached_type": reached,
    }


def test_usage_is_attributed_by_user_and_workspace(codex, tmp_path):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    a = adapter.add_account()
    future = int(time.time()) + 3600
    rollout(home, "1", "user-a", "acct-a", [limits(20.0, future), limits(35.0, future)])
    rollout(home, "2", "user-b", "acct-a", [limits(90.0, future)])  # same workspace, other user
    snap = adapter.read_usage(a)
    assert snap.state is UsageState.AVAILABLE
    assert [(w.name, w.used_percent) for w in snap.windows] == [("5h", 35.0), ("7d", 10.0)]
    assert snap.plan == "plus" and snap.source == "codex-session-log"


def test_usage_from_an_isolated_session_home_counts(codex):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    a = adapter.add_account()
    rollout(adapter.store.account_dir(1), "x", "user-a", "acct-a", [limits(55.0, int(time.time()) + 999)])
    assert adapter.read_usage(a).windows[0].used_percent == 55.0


def test_usage_states(codex):
    now = time.time()
    assert snapshot_from_rate_limits(limits(10, now - 5), None, now).state is UsageState.STALE
    assert snapshot_from_rate_limits(limits(100, now + 60, "primary"), None, now).state is UsageState.RATE_LIMITED
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    a = adapter.add_account()
    assert adapter.read_usage(a).state is UsageState.UNKNOWN


def test_switch_by_strategy_uses_usage(codex, tmp_path):
    adapter, home = codex
    future = int(time.time()) + 3600
    for i, used in ((1, 80.0), (2, 15.0), (3, 50.0)):
        login(home, f"{i}@x.com", f"user-{i}", f"acct-{i}")
        adapter.add_account()
        rollout(home, str(i), f"user-{i}", f"acct-{i}", [limits(used, future)])
    login(home, "1@x.com", "user-1", "acct-1")  # account 1 is active
    result = service.switch_by_strategy(adapter, "best", UsageService(tmp_path / "cache"), threshold=95.0)
    assert result.current.slot == 2
    assert not any("without knowing" in n for n in result.notes)


def test_next_available_says_when_it_picks_blind(codex, tmp_path):
    adapter, home = codex
    for i in (1, 2):
        login(home, f"{i}@x.com", f"user-{i}", f"acct-{i}")
        adapter.add_account()
    result = service.switch_by_strategy(adapter, "next-available", UsageService(tmp_path / "cache"), threshold=95.0)
    assert result.current.slot == 1
    assert any("no current usage data for 1@x.com" in n for n in result.notes)
    again = service.switch(adapter, "1")
    assert again.previous is None and "already the active account" in again.notes


def test_no_network_is_used_for_usage(codex, monkeypatch):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    a = adapter.add_account()

    def no_network(*a, **k):
        raise AssertionError("usage must not touch the network")

    monkeypatch.setattr("urllib.request.urlopen", no_network)
    monkeypatch.setattr("socket.create_connection", no_network)
    adapter.read_usage(a)


def test_switch_round_trip_keeps_keys_hswap_does_not_use(codex):
    adapter, home = codex
    doc = codex_auth("a@x.com", "user-a", "acct-a")
    doc["tokens"]["login_owner_id"] = "synthetic-owner-a"
    doc["tokens"]["oauth_provenance"] = {"issuer": "https://auth.example", "client_id": "app_synthetic"}
    doc["future_key"] = {"x": 1}
    write_json(home / "auth.json", doc)
    adapter.add_account()
    login(home, "b@x.com", "user-b", "acct-b")
    adapter.add_account()
    service.switch(adapter, "1")
    assert json.loads((home / "auth.json").read_text()) == doc
    service.switch(adapter, "2")
    service.switch(adapter, "1")
    assert json.loads((home / "auth.json").read_text()) == doc


# -- live usage by asking Codex (usage.remote) ------------------------------------------------

FAKE_APP_SERVER = """
log = open(os.environ["FAKE_LOG"], "a")
log.write(json.dumps({"argv": sys.argv[1:], "home": os.environ.get("CODEX_HOME"), "tty": os.isatty(0)}) + "\\n")
reply = json.load(open(os.environ["FAKE_REPLY"]))
print("codex starting", flush=True)  # stray output is skipped
for line in sys.stdin:
    log.write(line)
    log.flush()
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        print(json.dumps({"id": msg["id"], "result": {"userAgent": "hswap/0.166.0"}}), flush=True)
    elif msg.get("method") == "account/rateLimits/read":
        if reply.get("hang"):  # never answers: hswap's deadline ends it
            continue
        if os.environ.get("FAKE_ROTATE"):  # Codex refreshes a due token in its home
            path = os.path.join(os.environ["CODEX_HOME"], "auth.json")
            doc = json.load(open(path))
            doc["tokens"]["refresh_token"] += "-rotated"
            doc["last_refresh"] = "2026-11-03T00:00:00Z"
            json.dump(doc, open(path, "w"))
        print(json.dumps({"method": "account/rateLimits/updated", "params": {}}), flush=True)
        print(json.dumps({"id": msg["id"], **reply}), flush=True)
"""


def app_server_reply(used=40, reached=None, account="acct-1", **extra):
    future = int(time.time()) + 3600
    return {
        "result": {
            "rateLimits": {
                "limitId": "codex",
                "primary": {"usedPercent": used, "windowDurationMins": 300, "resetsAt": future},
                "secondary": {"usedPercent": 12, "windowDurationMins": 10080, "resetsAt": future + 86400},
                "credits": {"hasCredits": True, "unlimited": False, "balance": "5.20"},
                "planType": "pro",
                "rateLimitReachedType": reached,
            },
            "accountId": account,
            **extra,
        }
    }


@pytest.fixture
def remote(codex, tmp_path, monkeypatch):
    """Two accounts (1 inactive, 2 active), usage.remote on, a fake `codex app-server`."""
    from harness_swap.core import settings

    adapter, home = codex
    settings.set_value("usage.remote", "codex")
    for i in (1, 2):
        login(home, f"{i}@x.com", f"user-{i}", f"acct-{i}")
        adapter.add_account()
    exe = fake_executable(tmp_path / "bin", "codex", FAKE_APP_SERVER)
    adapter._installation = Installation(True, str(exe), "codex-cli 0.166.0")
    log, reply = tmp_path / "rpc.log", tmp_path / "reply.json"
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_REPLY", str(reply))

    def ask(slot, answer=None):
        write_json(reply, answer or app_server_reply(account=f"acct-{slot}"))
        return adapter.read_usage(next(a for a in adapter.list_accounts() if a.slot == slot))

    def calls():
        return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []

    return adapter, home, ask, calls


def set_live_token(home: Path, **fields):
    doc = json.loads((home / "auth.json").read_text())
    if "exp" in fields:
        from tests.hswap_helpers import jwt

        doc["tokens"]["access_token"] = jwt({"sub": "user-2", "exp": fields.pop("exp")})
    doc.update(fields)
    write_json(home / "auth.json", doc)


@posix_only
def test_inactive_account_is_asked_in_its_own_home(remote):
    adapter, home, ask, calls = remote
    before = (home / "auth.json").read_bytes()
    snap = ask(1)
    assert snap.state is UsageState.AVAILABLE and snap.source == "codex-app-server"
    assert [(w.name, w.used_percent, w.window_seconds) for w in snap.windows] == [("5h", 40.0, 18000), ("7d", 12.0, 604800)]
    assert snap.windows[0].resets_at > time.time()  # epoch seconds, not ms
    assert snap.plan == "pro" and snap.balance == {"hasCredits": True, "unlimited": False, "balance": "5.20"}
    start, *messages = calls()
    assert start == {"argv": ["app-server", "--listen", "stdio://"], "home": str(adapter.store.account_dir(1)), "tty": False}
    assert [m.get("method") for m in messages] == ["initialize", "initialized", "account/rateLimits/read"]
    assert all("jsonrpc" not in m for m in messages)
    assert messages[0]["params"]["clientInfo"]["name"] == "hswap"
    assert messages[2]["params"] == {"excludeResetCreditDetails": True}
    assert (home / "auth.json").read_bytes() == before  # the live login is not touched
    assert adapter.usage_policy.min_interval_s >= 120


@posix_only
def test_active_account_is_asked_only_with_token_life_left(remote):
    _adapter, home, ask, calls = remote
    set_live_token(home, exp=int(time.time()) + 300)  # Codex would refresh now
    snap = ask(2)
    assert snap.state is UsageState.STALE and "single-use" in snap.detail and calls() == []
    set_live_token(home, exp=int(time.time()) + 480)  # past Codex's 5 min, inside hswap's 10 min
    assert ask(2).state is UsageState.STALE and calls() == []
    set_live_token(home, exp=int(time.time()) + 660)
    assert ask(2).state is UsageState.AVAILABLE
    assert calls()[0]["home"] == str(home)


@posix_only
def test_an_unreadable_live_login_stops_every_read(remote):
    """Any account might be the live one, held in memory by a running Codex that
    could refresh it at any moment; reading a stored copy could refresh it twice."""
    _adapter, home, ask, calls = remote
    (home / "auth.json").write_text("{not json")
    for slot in (1, 2):
        with pytest.raises(HswapError, match="not valid JSON"):
            ask(slot)
    assert calls() == [] and (home / "auth.json").read_text() == "{not json"


@posix_only
def test_nothing_is_started_without_the_opt_in(remote, tmp_path):
    from harness_swap.core import settings

    settings.set_value("usage.remote", "")
    assert remote[2](1).source == "codex-session-log"
    assert not (tmp_path / "rpc.log").exists()


@posix_only
def test_live_read_reports_limits_over_a_rolled_over_window(remote):
    _adapter, _home, ask, _calls = remote
    reply = app_server_reply(reached="rate_limit_reached", account="acct-1")
    reply["result"]["rateLimits"]["primary"]["resetsAt"] = int(time.time()) - 1
    assert ask(1, reply).state is UsageState.RATE_LIMITED
    reply = app_server_reply(account="acct-1")
    reply["result"]["rateLimits"]["spendControlReached"] = True
    snap = ask(1, reply)
    assert snap.state is UsageState.RATE_LIMITED and "spend control" in snap.detail


@posix_only
def test_active_account_without_exp_follows_last_refresh(remote):
    from datetime import datetime, timedelta

    _adapter, home, ask, calls = remote
    old = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    set_live_token(home, last_refresh=old)
    assert ask(2).state is UsageState.STALE and calls() == []
    almost = (datetime.now(UTC) - timedelta(days=8) + timedelta(minutes=5)).isoformat()
    set_live_token(home, last_refresh=almost)  # inside the 10-minute margin
    assert ask(2).state is UsageState.STALE and calls() == []
    set_live_token(home, last_refresh=datetime.now(UTC).isoformat())
    assert ask(2).state is UsageState.AVAILABLE


@posix_only
def test_an_account_a_session_is_running_is_not_asked(remote, tmp_path):
    adapter, _home, ask, calls = remote
    fd = sessions.acquire(adapter.store.account_dir(1))
    try:
        snap = ask(1)
    finally:
        os.close(fd)
    assert snap.state is UsageState.STALE and "running session" in snap.detail and calls() == []
    # the usage service keeps serving the previous measurement meanwhile
    svc = UsageService(tmp_path / "cache", clock=lambda: 0.0)
    acc = adapter.list_accounts()[0]
    write_json(tmp_path / "reply.json", app_server_reply(used=70, account="acct-1"))
    assert svc.get(adapter, acc).windows[0].used_percent == 70.0
    fd = sessions.acquire(adapter.store.account_dir(1))
    try:
        svc.clock = lambda: 10_000.0
        again = svc.get(adapter, acc)
    finally:
        os.close(fd)
    assert again.state is UsageState.STALE and again.windows[0].used_percent == 70.0


@posix_only
def test_remote_usage_states(remote):
    _adapter, _home, ask, _calls = remote
    assert ask(1, app_server_reply(used=100, account="acct-1")).state is UsageState.RATE_LIMITED
    limited = ask(1, app_server_reply(used=20, reached="rate_limit_reached", account="acct-1"))
    assert limited.state is UsageState.RATE_LIMITED and limited.detail == "rate_limit_reached"
    assert ask(1, app_server_reply(account="acct-1", ordinaryUsageAllowed=False)).state is UsageState.RATE_LIMITED
    auth = ask(1, {"error": {"code": -32600, "message": "codex account authentication required to read rate limits"}})
    assert auth.state is UsageState.AUTHENTICATION_REQUIRED
    body = 'body={\n  "error": {\n    "message": "Could not parse your authentication token"\n  }\n}'
    unauthorized = ask(1, {"error": {"code": -32603, "message": f"GET https://x.invalid/usage failed: 401 Unauthorized; {body}"}})
    assert unauthorized.state is UsageState.AUTHENTICATION_REQUIRED and "Could not" not in unauthorized.detail
    with pytest.raises(Exception, match=r"^failed: 500 body=\{ \"error\": 1 \}$") as exc:
        ask(1, {"error": {"code": -32603, "message": 'failed: 500 body={\n  "error": 1\n}'}})
    assert "\n" not in str(exc.value)
    with pytest.raises(HswapError, match="different account"):
        ask(1, app_server_reply(account="acct-2"))
    with pytest.raises(Exception, match="withheld"):
        ask(1, {"error": {"code": -1, "message": "refresh failed for sk-proj-SyntheticAbCdEf0123456789xyz"}})


def test_capabilities_follow_the_opt_ins(codex):
    from harness_swap.core import settings

    adapter, _home = codex
    caps = adapter.capabilities()
    assert caps[Capability.USAGE_MONITORING].support is Support.EXPERIMENTAL  # session logs
    assert "usage.remote" in caps[Capability.USAGE_MONITORING].reason
    assert caps[Capability.AUTOMATIC_ROTATION].support is Support.UNAVAILABLE
    assert "usage.remote" in caps[Capability.AUTOMATIC_ROTATION].reason
    settings.set_value("usage.remote", "codex")
    caps = adapter.capabilities()
    assert caps[Capability.USAGE_MONITORING].support is Support.EXPERIMENTAL
    rotation = caps[Capability.AUTOMATIC_ROTATION]
    assert rotation.support is Support.EXPERIMENTAL and "circumvent any rate limits" in rotation.reason
    assert "https://" in rotation.reason
    adapter._installation = Installation(False, detail="`codex` not found on PATH")
    assert adapter.capabilities()[Capability.AUTOMATIC_ROTATION].support is Support.UNAVAILABLE


# -- keep-alive (`hswap codex refresh`) ------------------------------------------------------


def keep(adapter, slot):
    return adapter.keep_alive(next(a for a in adapter.list_accounts() if a.slot == slot))


@posix_only
def test_keep_alive_lets_codex_refresh_in_the_account_home(remote, monkeypatch):
    from harness_swap.core import settings

    adapter, home, _ask, calls = remote
    settings.set_value("usage.remote", "")  # an explicit refresh needs no opt-in
    write_json(Path(os.environ["FAKE_REPLY"]), app_server_reply(account="acct-1"))
    live = (home / "auth.json").read_bytes()
    assert keep(adapter, 1) == "token still valid"
    monkeypatch.setenv("FAKE_ROTATE", "1")
    result = keep(adapter, 1)
    assert result == "token refreshed" and "synthetic" not in result
    stored = json.loads((adapter.store.account_dir(1) / "auth.json").read_text())
    assert stored["tokens"]["refresh_token"] == "synthetic-refresh-1-rotated"
    assert (home / "auth.json").read_bytes() == live
    assert [c["home"] for c in calls() if "argv" in c] == [str(adapter.store.account_dir(1))] * 2


@posix_only
def test_keep_alive_touches_the_active_login_only_while_no_codex_runs(remote, monkeypatch):
    adapter, home, _ask, calls = remote
    write_json(Path(os.environ["FAKE_REPLY"]), app_server_reply(account="acct-2"))
    for running in ([4242], None):
        monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names, r=running: r)
        assert keep(adapter, 2) == "skipped: Codex CLI is running and refreshes the active login itself"
    assert calls() == []
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [])
    set_live_token(home, exp=int(time.time()) + 60)  # no 10-minute guard: nothing else can refresh it
    monkeypatch.setenv("FAKE_ROTATE", "1")
    assert keep(adapter, 2) == "token refreshed"
    assert calls()[0]["home"] == str(home)


@posix_only
def test_keep_alive_skips_an_account_a_session_runs(remote):
    adapter, _home, _ask, calls = remote
    fd = sessions.acquire(adapter.store.account_dir(1))
    try:
        assert keep(adapter, 1) == "skipped: a running session keeps it fresh"
    finally:
        os.close(fd)
    assert calls() == []


@posix_only
def test_keep_alive_failures_never_echo_codex(remote):
    adapter, _home, _ask, _calls = remote
    reply = Path(os.environ["FAKE_REPLY"])
    write_json(reply, {"error": {"code": -32600, "message": "codex account authentication required to read rate limits"}})
    with pytest.raises(HswapError, match="^sign in again: "):
        keep(adapter, 1)
    write_json(reply, {"error": {"code": -32603, "message": "failed to fetch codex rate limits: GET x failed: 401 Unauthorized"}})
    with pytest.raises(HswapError, match="^sign in again: "):
        keep(adapter, 1)
    write_json(reply, {"error": {"code": -32603, "message": "failed to fetch codex rate limits: 503 body=SECRETBODY"}})
    with pytest.raises(HswapError) as exc:
        keep(adapter, 1)
    assert "SECRETBODY" not in str(exc.value) and "sign in" not in str(exc.value)
    assert "(error -32603)" in str(exc.value)
    write_json(reply, {"error": "plain SECRETBODY"})  # a harness error without a code is still Codex's text
    with pytest.raises(HswapError) as exc:
        keep(adapter, 1)
    assert "SECRETBODY" not in str(exc.value) and str(exc.value).startswith("Codex could not check this login;")


@posix_only
def test_keep_alive_timeout_is_not_called_harmless(remote, monkeypatch):
    adapter, _home, _ask, _calls = remote
    monkeypatch.setattr("harness_swap.adapters.codex._RPC_TIMEOUT_S", 1.0)
    write_json(Path(os.environ["FAKE_REPLY"]), {"hang": True})
    with pytest.raises(HswapError) as exc:
        keep(adapter, 1)
    message = str(exc.value)
    assert message.startswith("no answer to account/rateLimits/read in time")
    assert "may need to sign in again" in message and "nothing changed" not in message


def test_keep_alive_reports_a_missing_login(codex):
    adapter, home = codex
    login(home, "1@x.com", "user-1", "acct-1")
    adapter.add_account()
    login(home, "2@x.com", "user-2", "acct-2")
    adapter.add_account()
    (adapter.store.account_dir(1) / "auth.json").write_text("not json")
    with pytest.raises(HswapError, match="^sign in again: "):
        keep(adapter, 1)


def test_keep_alive_has_nothing_to_refresh_for_api_keys(codex):
    adapter, home = codex
    write_json(home / "auth.json", {"auth_mode": "apikey", "OPENAI_API_KEY": "sk-synthetic-0123456789abcdef"})
    adapter.add_account()
    assert keep(adapter, 1) == "API-key login: nothing to refresh"


def test_credential_refresh_capability(codex):
    adapter, home = codex
    status = adapter.capabilities()[Capability.CREDENTIAL_REFRESH]
    assert status.support is Support.SUPPORTED and "hswap codex refresh" in status.reason
    (home / "config.toml").write_text('cli_auth_credentials_store = "keyring"\n')
    assert adapter.capabilities()[Capability.CREDENTIAL_REFRESH].support is Support.UNAVAILABLE
    (home / "config.toml").unlink()
    adapter._installation = Installation(False, detail="`codex` not found on PATH")
    assert adapter.capabilities()[Capability.CREDENTIAL_REFRESH].support is Support.UNAVAILABLE
