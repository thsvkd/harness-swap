"""Grok adapter: scope-level switching, hot reload, usage asked of Grok, isolated login."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from harness_swap.adapters.grok import GrokAdapter, _epoch, snapshot_from_billing
from harness_swap.core import accounts as service
from harness_swap.core import sessions, settings
from harness_swap.core.errors import CredentialError, HswapError
from harness_swap.core.models import Capability, Installation, Support, UsageState
from harness_swap.core.usage import UsageService
from harness_swap.infrastructure import processes
from tests.hswap_helpers import fake_executable, grok_entry, jwt, write_json

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="fake executables are POSIX scripts")

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
    assert caps[Capability.USAGE_MONITORING].support is Support.UNAVAILABLE
    assert "usage.remote" in caps[Capability.USAGE_MONITORING].reason
    assert caps[Capability.AUTOMATIC_ROTATION].support is Support.UNAVAILABLE
    assert caps[Capability.CREDENTIAL_HOT_RELOAD].support is Support.SUPPORTED
    assert caps[Capability.PARALLEL_SESSIONS].support is Support.EXPERIMENTAL


def test_usage_is_not_read_without_the_opt_in(grok, tmp_path):
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


# -- live usage by asking Grok (usage.remote) --------------------------------------------------

FAKE_ACP_AGENT = """
log = open(os.environ["FAKE_LOG"], "a")
log.write(json.dumps({"argv": sys.argv[1:], "home": os.environ.get("GROK_HOME"), "tty": os.isatty(0)}) + "\\n")
reply = json.load(open(os.environ["FAKE_REPLY"]))
print("grok starting", flush=True)  # stray output is skipped
for line in sys.stdin:
    log.write(line)
    log.flush()
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": 1}}), flush=True)
    elif msg.get("method") == "_x.ai/billing":
        if reply.get("hang"):  # never answers: hswap's deadline ends it
            continue
        if reply.pop("delete", False):  # Grok drops a credential whose refresh failed for good
            path = os.path.join(os.environ["GROK_HOME"], "auth.json")
            json.dump({}, open(path, "w"))
        if reply.pop("rotate", False):  # Grok refreshed a due token and stored it in its home
            path = os.path.join(os.environ["GROK_HOME"], "auth.json")
            doc = json.load(open(path))
            for entry in doc.values():
                entry["key"], entry["refresh_token"] = "synthetic-new-access", "synthetic-new-refresh"
            json.dump(doc, open(path, "w"))
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], **reply}), flush=True)
"""


def billing_reply(percent=40.0, period="weekly"):
    start = int(time.time()) - 86400
    return {
        "result": {
            "config": {
                "creditUsagePercent": percent,
                "currentPeriod": {"type": period, "start": str(start), "end": str(start + 7 * 86400)},
                "prepaidBalance": {"val": 1250},
                "onDemandCap": {"val": 5000},
                "onDemandUsed": {"val": 320},
                "isUnifiedBillingUser": True,
            }
        }
    }


def entry(email, user, exp=None, tier=5):
    claims = {"sub": user, "tier": tier, **({"exp": exp} if exp is not None else {})}
    return grok_entry(email, user, key=jwt(claims))


@pytest.fixture
def agent(grok, tmp_path, monkeypatch):
    """Two accounts (1 inactive, 2 active) and a fake `grok agent stdio`; no usage opt-in."""
    adapter, home = grok
    for i in (1, 2):
        write_json(home / "auth.json", {SCOPE: entry(f"{i}@x.com", f"user-{i}", exp=int(time.time()) + 3600)})
        adapter.add_account()
    exe = fake_executable(tmp_path / "bin", "grok", FAKE_ACP_AGENT)
    adapter._installation = Installation(True, str(exe), "grok 1.0.70")
    log, reply = tmp_path / "rpc.log", tmp_path / "reply.json"
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_REPLY", str(reply))

    def ask(slot, answer=None):
        write_json(reply, answer or billing_reply())
        return adapter.read_usage(next(a for a in adapter.list_accounts() if a.slot == slot))

    def calls():
        return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []

    return adapter, home, ask, calls


@pytest.fixture
def remote(agent):
    """`agent` with usage.remote on."""
    settings.set_value("usage.remote", "grok")
    return agent


def set_live(home, **fields):
    write_json(home / "auth.json", {SCOPE: {**entry("2@x.com", "user-2", exp=fields.pop("exp", None)), **fields}})


@posix_only
def test_inactive_account_is_asked_in_its_own_home(remote):
    adapter, home, ask, calls = remote
    before = (home / "auth.json").read_bytes()
    snap = ask(1)
    assert snap.state is UsageState.AVAILABLE and snap.source == "grok-acp"
    (window,) = snap.windows
    assert (window.name, window.used_percent, window.window_seconds) == ("weekly", 40.0, 7 * 86400)
    assert time.time() < window.resets_at < time.time() + 7 * 86400
    assert snap.plan == "supergrok_heavy"
    assert snap.balance == {"currency": "USD", "prepaidBalance": 12.5, "onDemandCap": 50.0, "onDemandUsed": 3.2}
    start, *messages = calls()
    assert start == {"argv": ["agent", "--no-leader", "stdio"], "home": str(adapter.store.account_dir(1)), "tty": False}
    assert [m["method"] for m in messages] == ["initialize", "_x.ai/billing"]
    assert all(m["jsonrpc"] == "2.0" for m in messages)
    assert messages[0]["params"] == {"protocolVersion": 1, "clientCapabilities": {}}
    assert (home / "auth.json").read_bytes() == before  # the live login is not touched
    assert adapter.usage_policy.min_interval_s >= 120


@posix_only
def test_active_account_is_asked_only_with_token_life_left(remote):
    _adapter, home, ask, calls = remote
    set_live(home, exp=int(time.time()) + 300)  # Grok may refresh now
    snap = ask(2)
    assert snap.state is UsageState.STALE and "due for refresh" in snap.detail and calls() == []
    # the stored expires_at counts too: the earlier of the two decides
    set_live(home, exp=int(time.time()) + 3600, expires_at=str(int(time.time()) + 60))
    assert ask(2).state is UsageState.STALE and calls() == []
    set_live(home)  # no readable expiry at all
    snap = ask(2)
    assert snap.state is UsageState.STALE and "unreadable" in snap.detail and calls() == []
    set_live(home, exp=int(time.time()) + 3600)
    assert ask(2).state is UsageState.AVAILABLE
    assert calls()[0]["home"] == str(home)


@posix_only
def test_an_account_a_session_is_running_is_not_asked(remote):
    adapter, _home, ask, calls = remote
    fd = sessions.acquire(adapter.store.account_dir(1))
    try:
        snap = ask(1)
    finally:
        os.close(fd)
    assert snap.state is UsageState.STALE and "running session" in snap.detail and calls() == []
    fd = sessions.acquire(adapter.home)  # `hswap run` on the active account owns the default home
    try:
        snap = ask(2)
    finally:
        os.close(fd)
    assert snap.state is UsageState.STALE and "running session" in snap.detail and calls() == []


@posix_only
def test_stored_copy_is_not_used_while_the_live_file_is_unreadable(remote):
    _adapter, home, ask, calls = remote
    (home / "auth.json").write_text("{", encoding="utf-8")  # mid-write or hand-edited, slot 2 is live
    for slot in (1, 2):
        with pytest.raises(CredentialError, match="not valid JSON"):
            ask(slot)
    assert calls() == []


@posix_only
def test_remote_usage_states(remote):
    _adapter, _home, ask, _calls = remote
    limited = ask(1, billing_reply(percent=100, period="USAGE_PERIOD_TYPE_MONTHLY"))  # as Grok 1.0.70 sends it
    assert limited.state is UsageState.RATE_LIMITED and limited.windows[0].name == "monthly"
    auth = ask(1, {"error": {"code": -32000, "message": "Authentication required", "data": "Authentication required to fetch billing data"}})
    assert auth.state is UsageState.AUTHENTICATION_REQUIRED
    assert ask(1, {"result": {"config": {}}}).state is UsageState.UNKNOWN
    grok_com = {"error": {"code": -32000, "message": "Billing data requires auth with grok.com"}}
    assert ask(1, grok_com).state is UsageState.UNSUPPORTED
    with pytest.raises(Exception, match="withheld"):
        ask(1, {"error": {"code": -1, "message": "refresh failed for xai-SyntheticAbCdEf0123456789xyzSynthetic"}})


@posix_only
def test_api_key_logins_are_unsupported_without_asking_grok(remote):
    adapter, home, _ask, calls = remote
    write_json(home / "auth.json", {"xai::api_key": {"key": "synthetic-xai-api-key", "auth_mode": "api_key"}})
    key = adapter.add_account()
    snap = adapter.read_usage(key)
    assert snap.state is UsageState.UNSUPPORTED and calls() == []


def test_capabilities_follow_the_opt_in(grok):
    adapter, _home = grok
    settings.set_value("usage.remote", "grok")
    caps = adapter.capabilities()
    assert caps[Capability.USAGE_MONITORING].support is Support.EXPERIMENTAL
    rotation = caps[Capability.AUTOMATIC_ROTATION]
    assert rotation.support is Support.EXPERIMENTAL and "circumventing any rate limits" in rotation.reason
    assert "https://x.ai/legal/acceptable-use-policy" in rotation.reason
    adapter._installation = Installation(False, detail="`grok` not found on PATH")
    caps = adapter.capabilities()
    assert caps[Capability.AUTOMATIC_ROTATION].support is Support.UNAVAILABLE
    assert caps[Capability.USAGE_MONITORING].support is Support.UNAVAILABLE


def test_billing_parsing_edges():
    assert _epoch(1.7e12) == 1.7e9 and _epoch("1700000000") == 1.7e9
    assert _epoch("2026-11-30T00:00:00Z") == _epoch("2026-11-30T00:00:00") == 1795996800.0  # no zone: UTC
    assert _epoch("soon") is None
    top_level = {"creditUsagePercent": 10, "subscription_tier": "SuperGrok Heavy"}
    assert snapshot_from_billing(top_level, "free", 0.0).plan == "SuperGrok Heavy"
    nested = {"config": {"creditUsagePercent": 10, "subscriptionTier": "SuperGrok"}}
    assert snapshot_from_billing(nested, "free", 0.0).plan == "SuperGrok"
    assert snapshot_from_billing({"config": {"creditUsagePercent": 10}}, "free", 0.0).plan == "free"


# -- keep-alive (`hswap grok refresh`): Grok refreshes in the account's own home ---------------


def keep(adapter, reply, slot, answer=None):
    write_json(reply, answer or billing_reply())
    return adapter.keep_alive(next(a for a in adapter.list_accounts() if a.slot == slot))


@posix_only
def test_keep_alive_asks_grok_in_the_stored_home_without_the_opt_in(agent, tmp_path, monkeypatch):
    adapter, home, _ask, calls = agent
    monkeypatch.setattr(processes, "find", lambda names: [4242])  # a Grok runs: only the active login waits
    live, stored = (home / "auth.json").read_bytes(), adapter.store.account_dir(1) / "auth.json"
    reply = tmp_path / "reply.json"
    result = keep(adapter, reply, 1, {**billing_reply(), "rotate": True})
    assert result == "token refreshed" and "synthetic" not in result
    assert json.loads(stored.read_text())[SCOPE]["refresh_token"] == "synthetic-new-refresh"
    assert (home / "auth.json").read_bytes() == live
    assert calls()[0]["home"] == str(adapter.store.account_dir(1)) and not calls()[0]["tty"]
    assert keep(adapter, reply, 1) == "token still valid"
    assert keep(adapter, reply, 2).startswith("skipped: Grok Build is running")


@posix_only
@pytest.mark.parametrize("running", [[4242], None])
def test_active_login_waits_while_grok_runs_or_may_run(agent, tmp_path, monkeypatch, running):
    adapter, _home, _ask, calls = agent
    monkeypatch.setattr(processes, "find", lambda names: running)
    assert keep(adapter, tmp_path / "reply.json", 2) == "skipped: Grok Build is running and refreshes the active login itself"
    assert calls() == []


@posix_only
def test_active_login_is_touched_when_no_grok_runs_even_near_expiry(agent, tmp_path, monkeypatch):
    adapter, home, _ask, calls = agent
    monkeypatch.setattr(processes, "find", lambda names: [])
    set_live(home, exp=int(time.time()) + 60)  # read_usage would wait; nothing else can refresh it now
    assert keep(adapter, tmp_path / "reply.json", 2, {**billing_reply(), "rotate": True}) == "token refreshed"
    assert calls()[0]["home"] == str(home)
    assert json.loads((home / "auth.json").read_text())[SCOPE]["key"] == "synthetic-new-access"


@posix_only
def test_keep_alive_skips_an_account_a_session_runs(agent, tmp_path):
    adapter, _home, _ask, calls = agent
    fd = sessions.acquire(adapter.store.account_dir(1))
    try:
        assert keep(adapter, tmp_path / "reply.json", 1) == "skipped: a running session keeps it fresh"
    finally:
        os.close(fd)
    assert calls() == []


@posix_only
def test_keep_alive_failures_say_sign_in_again_without_grok_output(agent, tmp_path):
    adapter, _home, _ask, _calls = agent
    reply = tmp_path / "reply.json"
    auth = {"error": {"code": -32000, "message": "Authentication required", "data": "Authentication required"}}
    with pytest.raises(HswapError, match="^sign in again: "):
        keep(adapter, reply, 1, auth)
    with pytest.raises(HswapError) as err:
        keep(adapter, reply, 1, {"error": {"code": -32603, "message": "upstream said synthetic-detail"}})
    assert "synthetic-detail" not in str(err.value) and "-32603" in str(err.value)
    grok_com = {"error": {"code": -32000, "message": "Billing data requires auth with grok.com"}}
    assert keep(adapter, reply, 1, grok_com) == "token still valid"
    with pytest.raises(HswapError) as err:  # a harness error without a code is still Grok's text
        keep(adapter, reply, 1, {"error": "upstream said synthetic-detail"})
    assert str(err.value) == "Grok could not check this login"
    with pytest.raises(HswapError, match="^sign in again: Grok removed this login"):
        keep(adapter, reply, 1, {**billing_reply(), "delete": True})


@posix_only
def test_keep_alive_timeout_shows_hswaps_own_message(agent, tmp_path, monkeypatch):
    adapter, _home, _ask, _calls = agent
    monkeypatch.setattr("harness_swap.adapters.grok._RPC_TIMEOUT_S", 1.0)
    with pytest.raises(HswapError, match="^no answer to _x.ai/billing in time$"):
        keep(adapter, tmp_path / "reply.json", 1, {"hang": True})


@posix_only
def test_keep_alive_skips_an_account_that_just_became_live(agent, tmp_path, monkeypatch):
    from harness_swap.core.credentials import SnapshotCredentials

    adapter, _home, _ask, calls = agent
    first = next(a for a in adapter.list_accounts() if a.slot == 1)
    real, seen = SnapshotCredentials.live_identities, []

    def live_identities(self):  # account 1 becomes live right after usage_home chose its stored home
        seen.append(1)
        return real(self) if len(seen) == 1 else {SCOPE: first}

    monkeypatch.setattr(SnapshotCredentials, "live_identities", live_identities)
    write_json(tmp_path / "reply.json", billing_reply())
    assert adapter.keep_alive(first) == "skipped: this account just became the live login"
    assert calls() == []


@posix_only
def test_process_check_sees_a_grok_started_through_a_wrapper(tmp_path):
    """qemu or a launcher shows up under its own name; the native binary is on its command line."""
    native = fake_executable(tmp_path / "downloads", "grok-linux-aarch64", "")
    proc = subprocess.Popen(["/bin/sh", "-c", "sleep 30; :", str(native)])
    try:
        assert proc.pid in processes.find({"grok"})
    finally:
        proc.kill()
        proc.wait()


@posix_only
def test_keep_alive_api_key_has_nothing_to_refresh(agent):
    adapter, home, _ask, calls = agent
    write_json(home / "auth.json", {"xai::api_key": {"key": "synthetic-xai-api-key", "auth_mode": "api_key"}})
    assert adapter.keep_alive(adapter.add_account()) == "API-key login: nothing to refresh" and calls() == []


def test_credential_refresh_capability_needs_only_the_install(grok):
    adapter, _home = grok
    status = adapter.capabilities()[Capability.CREDENTIAL_REFRESH]
    assert status.support is Support.SUPPORTED and "hswap grok refresh" in status.reason
    adapter._installation = Installation(False, detail="`grok` not found on PATH")
    assert adapter.capabilities()[Capability.CREDENTIAL_REFRESH].support is Support.UNAVAILABLE
