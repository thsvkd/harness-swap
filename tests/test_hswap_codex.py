"""Codex adapter against synthetic CODEX_HOME trees and a fake `codex` binary."""

from __future__ import annotations

import json
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
    (home / "config.toml").write_text(f'cli_auth_credentials_store = "{mode}"\n')
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


def test_running_the_active_account_execs_plain_codex(codex, monkeypatch):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    adapter.add_account()
    class Exec(Exception):
        pass

    def fake_exec(exe, argv):
        raise Exec(argv)

    monkeypatch.setattr("os.execvp", fake_exec)
    with pytest.raises(Exec) as exc:
        service.launch(adapter, "1", ["--help"])
    assert exc.value.args[0] == ["/fake/codex", "--help"]


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


def test_no_network_is_used_for_usage(codex, monkeypatch):
    adapter, home = codex
    login(home, "a@x.com", "user-a", "acct-a")
    a = adapter.add_account()

    def no_network(*a, **k):
        raise AssertionError("usage must not touch the network")

    monkeypatch.setattr("urllib.request.urlopen", no_network)
    monkeypatch.setattr("socket.create_connection", no_network)
    adapter.read_usage(a)
