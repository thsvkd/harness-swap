"""Grok adapter: scope-level switching, hot reload, no usage, isolated login."""

from __future__ import annotations

import json
import sys

import pytest

from harness_swap.adapters.grok import GrokAdapter
from harness_swap.core import accounts as service
from harness_swap.core.models import Capability, Installation, Support, UsageState
from harness_swap.core.usage import UsageService
from tests.hswap_helpers import fake_executable, grok_entry, write_json

SCOPE = "https://auth.example::client-1"


@pytest.fixture
def grok(tmp_path, monkeypatch):
    home = tmp_path / "grok-home"
    home.mkdir()
    monkeypatch.setenv("GROK_HOME", str(home))
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    adapter = GrokAdapter()
    adapter._installation = Installation(True, "/fake/grok", "grok 1.0.70")
    return adapter, home


def sign_in(home, email, user, extra=None):
    doc = {SCOPE: grok_entry(email, user)}
    doc.update(extra or {})
    return write_json(home / "auth.json", doc)


def test_switch_replaces_only_the_account_scope(grok):
    adapter, home = grok
    api_scope = {"xai::api_key": {"key": "synthetic-xai-api-key", "auth_mode": "api_key"}}
    sign_in(home, "a@x.com", "user-a", api_scope)
    adapter.add_account(provider=None)
    sign_in(home, "b@x.com", "user-b", api_scope)
    adapter.add_account()
    accounts = {a.label: a for a in adapter.list_accounts()}
    assert set(accounts) >= {"a@x.com", "b@x.com"}
    result = service.switch(adapter, "a@x.com")
    doc = json.loads((home / "auth.json").read_text())
    assert doc[SCOPE]["user_id"] == "user-a"
    assert doc["xai::api_key"] == api_scope["xai::api_key"]
    assert not result.restart_required
    assert "next request" in result.notes[0]


def test_capabilities_are_honest(grok):
    adapter, _ = grok
    caps = adapter.capabilities()
    assert caps[Capability.USAGE_MONITORING].support is Support.UNSUPPORTED
    assert caps[Capability.AUTOMATIC_ROTATION].support is Support.UNSUPPORTED
    assert caps[Capability.CREDENTIAL_HOT_RELOAD].support is Support.SUPPORTED
    assert caps[Capability.PARALLEL_SESSIONS].support is Support.EXPERIMENTAL


def test_usage_is_unsupported_not_guessed(grok, tmp_path):
    adapter, home = grok
    sign_in(home, "a@x.com", "user-a")
    acc = adapter.add_account()
    snap = service.collect_usage(adapter, [acc], UsageService(tmp_path / "c"))[acc.key]
    assert snap.state is UsageState.UNSUPPORTED and snap.windows == ()


def test_strategy_switch_is_refused_without_usage(grok, tmp_path):
    adapter, home = grok
    sign_in(home, "a@x.com", "user-a")
    adapter.add_account()
    with pytest.raises(Exception, match="usage_monitoring"):
        service.switch_by_strategy(adapter, "best", UsageService(tmp_path / "c"), threshold=95)


def test_isolated_session_shares_config_but_not_history(grok, monkeypatch):
    adapter, home = grok
    (home / "config.toml").write_text("x = 1\n")
    (home / "sessions").mkdir()
    sign_in(home, "a@x.com", "user-a")
    adapter.add_account()
    sign_in(home, "b@x.com", "user-b")
    adapter.add_account()
    seen = {}
    monkeypatch.setattr("harness_swap.core.sessions.launch", lambda argv, env, fd: seen.update(argv=argv, env=env) or 0)
    service.launch(adapter, "1", [])
    profile = adapter.store.account_dir(1)
    assert seen["env"]["GROK_HOME"] == str(profile)
    assert seen["argv"] == ["/fake/grok"]
    if sys.platform != "win32":
        assert (profile / "config.toml").is_symlink()
    assert not (profile / "sessions").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="fake executables are POSIX scripts")
def test_add_with_login_runs_in_a_throwaway_home(grok, tmp_path):
    adapter, home = grok
    (home / "config.toml").write_text("[grok_com_config.oidc]\n")
    sign_in(home, "a@x.com", "user-a")
    before = (home / "auth.json").read_bytes()
    new = {SCOPE: grok_entry("new@x.com", "user-n")}
    exe = fake_executable(
        tmp_path / "bin",
        "grok",
        f"""
home = os.environ["GROK_HOME"]
assert os.path.exists(os.path.join(home, "config.toml")), "OIDC config must be visible to the login"
open(os.path.join(home, "auth.json"), "w").write({json.dumps(new)!r})
""",
    )
    adapter._installation = Installation(True, str(exe), "grok 1.0.70")
    acc = adapter.add_account(login=True)
    assert acc.label == "new@x.com"
    assert (home / "auth.json").read_bytes() == before
