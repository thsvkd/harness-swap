"""Opt-in automatic switching, cache-only usage reads, stored-token refresh and the HTTP helper."""

from __future__ import annotations

import json
import time

import pytest

from harness_swap import cli
from harness_swap.core import autorotate, sessions, settings
from harness_swap.core.errors import UnsupportedOperation
from harness_swap.core.models import Capability, experimental
from harness_swap.core.registry import Registry
from harness_swap.core.usage import UsageService
from tests.hswap_helpers import write_json
from tests.test_hswap_contract import installed, load_example, login


@pytest.fixture
def acme(tmp_path, monkeypatch):
    module = load_example()

    class AutoAcme(module.AcmeAdapter):
        def capabilities(self):
            caps = super().capabilities()
            caps[Capability.AUTOMATIC_ROTATION] = experimental("test")
            return caps

    home = tmp_path / "acme-home"
    home.mkdir()
    monkeypatch.setenv("ACME_HOME", str(home))
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [])
    adapter = installed(AutoAcme)()
    for user in ("ann", "bob", "cat"):
        login(home, user)
        adapter.add_account()
    login(home, "ann")
    adapter.switch_account(adapter.list_accounts()[0])
    return adapter, home, tmp_path


def quota(home, **used):
    now = time.time()
    write_json(home / "quota.json", {u: {"used": p, "resets_at": now + 600, "measured_at": now} for u, p in used.items()})


def run(adapter, tmp_path, clock=time.time, **kw):
    return autorotate.run_once(
        adapter, UsageService(tmp_path / "cache", clock), threshold=80.0, cooldown_s=600.0, clock=clock, **kw
    )


def active(adapter):
    return next(a.label for a in adapter.list_accounts() if a.active)


def test_auto_is_off_until_the_user_opts_in(acme):
    adapter, home, tmp = acme
    quota(home, ann=95, bob=10, cat=50)
    with pytest.raises(UnsupportedOperation, match="auto.enabled"):
        run(adapter, tmp)
    assert active(adapter) == "ann@acme.test"


def test_auto_switches_to_the_most_headroom_then_respects_the_cooldown(acme):
    adapter, home, tmp = acme
    settings.set_value("auto.enabled", "acme")
    quota(home, ann=50, bob=10, cat=30)
    (event,) = run(adapter, tmp)
    assert event["action"] == "stay" and "below 80%" in event["reason"]

    quota(home, ann=95, bob=10, cat=30)
    later = lambda: time.time() + 120
    (event,) = run(adapter, tmp, clock=later, dry_run=True)
    assert event["action"] == "would-switch" and active(adapter) == "ann@acme.test"
    (event,) = run(adapter, tmp, clock=later)
    assert event["action"] == "switch" and event["target"]["label"] == "bob@acme.test"
    assert active(adapter) == "bob@acme.test"

    quota(home, ann=95, bob=99, cat=30)
    (event,) = run(adapter, tmp, clock=lambda: time.time() + 300)
    assert event["action"] == "wait" and "cooldown" in event["reason"]
    (event,) = run(adapter, tmp, clock=lambda: time.time() + 800)  # past the cooldown, data still fresh
    assert event["action"] == "switch" and event["target"]["label"] == "cat@acme.test"


def test_auto_never_switches_on_missing_data_or_without_headroom(acme):
    adapter, home, tmp = acme
    settings.set_value("auto.enabled", "acme")
    (event,) = run(adapter, tmp)
    assert event["action"] == "stay" and "not switching without data" in event["reason"]
    quota(home, ann=95, bob=90, cat=85)
    (event,) = run(adapter, tmp, clock=lambda: time.time() + 120)
    assert event["action"] == "stay" and "no other account" in event["reason"]
    assert active(adapter) == "ann@acme.test"


def test_overlapping_auto_runs_do_nothing(acme):
    adapter, _home, tmp = acme
    settings.set_value("auto.enabled", "acme")
    from harness_swap.infrastructure.locking import FileLock

    lock = FileLock(tmp / "hswap" / "acme" / ".auto.lock", timeout=0)
    assert lock.acquire(timeout=0)
    try:
        assert run(adapter, tmp) == [{"action": "skip", "reason": "another `auto` run is in progress"}]
    finally:
        lock.release()


def test_cli_auto_once_json_and_cached_reads(acme, capsys):
    adapter, home, _tmp = acme
    reg = Registry(discover_plugins=False)
    reg.register("acme", lambda: adapter)
    assert cli.run(["acme", "auto", "--once"], reg) == 1
    assert "auto.enabled" in capsys.readouterr().err
    cli.run(["config", "set", "auto.enabled", "acme"], reg)
    assert "responsible" in capsys.readouterr().err  # the terms warning
    quota(home, ann=40, bob=10, cat=30)
    assert cli.run(["acme", "auto", "--once", "--json"], reg) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["events"][0]["action"] == "stay"

    calls = []
    real = adapter.read_usage
    adapter.read_usage = lambda acc: calls.append(acc) or real(acc)
    assert cli.run(["acme", "list", "--cached", "--json"], reg) == 0
    rows = json.loads(capsys.readouterr().out)["accounts"]
    assert calls == []  # nothing measured, nothing refreshed
    assert rows[0]["usage"]["windows"][0]["usedPercent"] == 40.0  # what `auto` measured
    assert rows[2]["usage"]["state"] in ("available", "unknown")


# -- which copy of a token a usage read may use ------------------------------------------


def test_usage_part_prefers_the_live_login_and_flags_owned_tokens(acme):
    adapter, _home, _tmp = acme
    creds = adapter.credentials
    part, elsewhere = creds.usage_part(1)
    assert part["account"]["id"] == "ann" and elsewhere  # active: the harness's to refresh
    part, elsewhere = creds.usage_part(2)
    assert part["account"]["id"] == "bob" and not elsewhere
    fd = sessions.acquire(adapter.store.account_dir(3))
    try:
        assert creds.usage_part(3)[1] is True
    finally:
        import os

        os.close(fd)


# -- settings --------------------------------------------------------------------------------


def test_harness_lists_are_validated(tmp_path, monkeypatch):
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path))
    assert settings.set_value("usage.remote", "Codex, cursor") == ["codex", "cursor"]
    assert settings.opted_in("usage.remote", "cursor") and not settings.opted_in("usage.remote", "grok")
    with pytest.raises(ValueError, match="not a harness id"):
        settings.set_value("auto.enabled", "codex;rm")
    with pytest.raises(ValueError, match="between 60 and 86400"):
        settings.set_value("auto.cooldown", "5")
