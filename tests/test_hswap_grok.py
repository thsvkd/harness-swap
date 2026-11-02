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


def test_switch_leaves_the_target_as_the_only_credential_scope(grok):
    adapter, home = grok
    api_scope = {"xai::api_key": {"key": "synthetic-xai-api-key", "auth_mode": "api_key"}}
    sign_in(home, "a@x.com", "user-a", {**api_scope, "preferences": {"theme": "dark"}})
    adapter.add_account()  # stores both the session login and the API key
    sign_in(home, "b@x.com", "user-b", {"preferences": {"theme": "dark"}})
    adapter.add_account()
    labels = {a.label for a in adapter.list_accounts()}
    assert {"a@x.com", "b@x.com"} <= labels and any(lbl.startswith("API key") for lbl in labels)
    result = service.switch(adapter, "a@x.com")
    doc = json.loads((home / "auth.json").read_text())
    assert doc[SCOPE]["user_id"] == "user-a" and doc["preferences"] == {"theme": "dark"}
    assert not result.restart_required and "next request" in result.notes[0]
    # switching to the API key drops the session scope Grok would otherwise prefer
    key_account = next(a for a in adapter.list_accounts() if a.auth_mode == "api_key")
    result = service.switch(adapter, str(key_account.slot))
    doc = json.loads((home / "auth.json").read_text())
    assert SCOPE not in doc and doc["xai::api_key"]["key"] == "synthetic-xai-api-key"
    assert result.previous.label == "a@x.com"
    assert [a.label for a in adapter.list_accounts() if a.active] == [key_account.label]


def test_unmanaged_other_scope_blocks_the_switch(grok):
    adapter, home = grok
    sign_in(home, "a@x.com", "user-a")
    adapter.add_account()
    sign_in(home, "b@x.com", "user-b", {"https://other::c2": grok_entry("x@y.com", "user-x")})
    before = (home / "auth.json").read_bytes()
    with pytest.raises(Exception, match="x@y.com"):
        service.switch(adapter, "a@x.com")
    assert (home / "auth.json").read_bytes() == before


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
