"""Core services: store, rotation, usage service, registry, capability dispatch."""

from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

import pytest

from harness_swap.core import accounts as service
from harness_swap.core.adapter import AccountSwitcher, UsagePolicy, require
from harness_swap.core.errors import (
    AccountNotFound,
    HarnessNotFound,
    HswapError,
    StoreVersionError,
    UnsupportedOperation,
)
from harness_swap.core.models import (
    Account,
    Capability,
    Installation,
    QuotaWindow,
    UsageSnapshot,
    UsageState,
    supported,
    unsupported,
)
from harness_swap.core.registry import Registry
from harness_swap.core.rotation import select_account
from harness_swap.core.store import SCHEMA_VERSION, AccountStore
from harness_swap.core.usage import UsageService


def acct(slot, label=None, provider="p", active=False, **kw):
    return Account("h", f"id{slot}", label or f"u{slot}@x", provider, slot, active=active, **kw)


def snap(used, state=UsageState.AVAILABLE, resets_at=None):
    return UsageSnapshot(state, (QuotaWindow("w", used, resets_at),), measured_at=0.0)


# -- store --------------------------------------------------------------------------


class TestAccountStore:
    def test_duplicate_identity_reuses_the_slot(self, tmp_path):
        store = AccountStore(tmp_path / "h")
        accounts = []
        a, created = store.upsert(accounts, identity="i1", label="a@x", provider="p", auth_mode=None, part_key="")
        b, created_again = store.upsert(accounts, identity="i1", label="a2@x", provider="p", auth_mode=None, part_key="")
        assert created and not created_again
        assert a is b and a.slot == 1 and a.label == "a2@x" and len(accounts) == 1

    def test_same_identity_other_provider_is_a_different_account(self, tmp_path):
        store = AccountStore(tmp_path / "h")
        accounts = []
        store.upsert(accounts, identity="i1", label="a", provider="p1", auth_mode=None, part_key="")
        store.upsert(accounts, identity="i1", label="a", provider="p2", auth_mode=None, part_key="")
        assert [a.slot for a in accounts] == [1, 2]

    def test_slots_fill_the_first_gap(self, tmp_path):
        store = AccountStore(tmp_path / "h")
        accounts = []
        for i in range(3):
            store.upsert(accounts, identity=f"i{i}", label="x", provider=None, auth_mode=None, part_key="")
        accounts.pop(1)
        new, _ = store.upsert(accounts, identity="n", label="x", provider=None, auth_mode=None, part_key="")
        assert new.slot == 2

    def test_alias_must_be_unique_and_valid(self, tmp_path):
        store = AccountStore(tmp_path / "h")
        accounts = []
        store.upsert(accounts, identity="a", label="a", provider=None, auth_mode=None, part_key="", alias="Work")
        assert accounts[0].alias == "work"
        with pytest.raises(ValueError, match="already used"):
            store.upsert(accounts, identity="b", label="b", provider=None, auth_mode=None, part_key="", alias="work")
        with pytest.raises(ValueError, match="numeric"):
            store.upsert(accounts, identity="c", label="c", provider=None, auth_mode=None, part_key="", alias="12")

    def test_newer_schema_is_refused_not_rewritten(self, tmp_path):
        store = AccountStore(tmp_path / "h")
        store.root.mkdir(parents=True)
        original = json.dumps({"schemaVersion": SCHEMA_VERSION + 1, "accounts": []})
        store.file.write_text(original)
        with pytest.raises(StoreVersionError):
            store.load()
        assert store.file.read_text() == original

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_metadata_and_secrets_are_private(self, tmp_path):
        store = AccountStore(tmp_path / "h")
        store.save([])
        store.write_secret(1, "auth.json", b"{}")
        assert store.file.stat().st_mode & 0o777 == 0o600
        assert store.account_dir(1).stat().st_mode & 0o777 == 0o700
        assert (store.account_dir(1) / "auth.json").stat().st_mode & 0o777 == 0o600

    def test_delete_keeps_session_history(self, tmp_path):
        store = AccountStore(tmp_path / "h")
        accounts = []
        store.upsert(accounts, identity="a", label="a", provider=None, auth_mode=None, part_key="")
        store.save(accounts)
        store.write_secret(1, "auth.json", b"{}")
        (store.account_dir(1) / "sessions").mkdir()
        store.delete(1, ("auth.json",))
        assert store.load() == []
        assert not (store.account_dir(1) / "auth.json").exists()
        assert (store.account_dir(1) / "sessions").is_dir()


# -- rotation -------------------------------------------------------------------------


class TestRotation:
    def test_best_picks_most_headroom_and_never_the_current(self):
        a, b, c = acct(1), acct(2), acct(3)
        usage = {a.key: snap(10), b.key: snap(50), c.key: snap(30)}
        assert select_account([a, b, c], usage, current=a, strategy="best") is c

    def test_best_ignores_unknown_stale_and_over_threshold(self):
        a, b, c, d = acct(1), acct(2), acct(3), acct(4)
        usage = {
            b.key: UsageSnapshot(UsageState.UNKNOWN),
            c.key: snap(5, UsageState.STALE),
            d.key: snap(96),
        }
        assert select_account([a, b, c, d], usage, current=a, strategy="best", threshold=95) is None

    def test_best_breaks_ties_on_earliest_reset(self):
        a, b, c = acct(1), acct(2), acct(3)
        usage = {b.key: snap(20, resets_at=500), c.key: snap(20, resets_at=100)}
        assert select_account([a, b, c], usage, current=a, strategy="best") is c

    def test_next_available_rotates_and_skips_known_exhausted_only(self):
        a, b, c, d = acct(1), acct(2), acct(3), acct(4)
        usage = {
            c.key: snap(100, UsageState.RATE_LIMITED),
            d.key: UsageSnapshot(UsageState.UNKNOWN),
        }
        assert select_account([a, b, c, d], usage, current=b, strategy="next-available") is d
        usage[d.key] = snap(99)
        assert select_account([a, b, c, d], usage, current=b, strategy="next-available") is a

    def test_scoped_to_provider(self):
        a, b = acct(1, provider="x"), acct(2, provider="y")
        assert select_account([a, b], {}, current=None, strategy="next-available", provider="y") is b

    def test_no_current_account(self):
        a, b = acct(1), acct(2)
        assert select_account([a, b], {}, current=None, strategy="next-available") is a

    def test_unknown_strategy(self):
        with pytest.raises(ValueError):
            select_account([], {}, current=None, strategy="random")


# -- usage service ------------------------------------------------------------------------


class CountingReader:
    usage_policy = UsagePolicy(min_interval_s=60, stale_after_s=100, max_backoff_s=1000)

    def __init__(self, result):
        self.result = result
        self.calls = 0

    def read_usage(self, account):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class TestUsageService:
    def test_min_interval_is_respected_across_instances(self, tmp_path):
        clock = [1000.0]
        reader = CountingReader(snap(10))
        a = acct(1)
        UsageService(tmp_path, lambda: clock[0]).get(reader, a)
        clock[0] += 30
        UsageService(tmp_path, lambda: clock[0]).get(reader, a)
        assert reader.calls == 1
        clock[0] += 31
        UsageService(tmp_path, lambda: clock[0]).get(reader, a)
        assert reader.calls == 2

    def test_errors_back_off_and_keep_last_good_numbers(self, tmp_path):
        clock = [1000.0]
        svc = UsageService(tmp_path, lambda: clock[0])
        a = acct(1)
        good = CountingReader(UsageSnapshot(UsageState.AVAILABLE, (QuotaWindow("w", 42.0),), measured_at=1000.0))
        svc.get(good, a)
        clock[0] += 61
        bad = CountingReader(RuntimeError("boom"))
        result = svc.get(bad, a)
        assert result.state is UsageState.ERROR and "boom" in result.detail
        assert result.windows[0].used_percent == 42.0
        clock[0] += 61  # inside the backoff (60 * 2**1 = 120s)
        svc.get(bad, a)
        assert bad.calls == 1
        clock[0] += 120
        svc.get(bad, a)
        assert bad.calls == 2

    def test_old_measurements_are_reported_stale(self, tmp_path):
        clock = [1000.0]
        reader = CountingReader(UsageSnapshot(UsageState.AVAILABLE, (), measured_at=800.0))
        assert UsageService(tmp_path, lambda: clock[0]).get(reader, acct(1)).state is UsageState.STALE

    def test_cache_holds_no_credentials(self, tmp_path):
        reader = CountingReader(snap(10))
        UsageService(tmp_path).get(reader, acct(1))
        text = (tmp_path / "usage-cache.json").read_text()
        assert "token" not in text.lower()


# -- capability dispatch & resolution ------------------------------------------------------


class Minimal:
    id = "mini"
    display_name = "Mini"
    providers = ("p",)

    def __init__(self, caps=None, accounts=()):
        self._caps = caps or {}
        self._accounts = list(accounts)

    def installation(self):
        return Installation(True, "/bin/mini", "1.0.0")

    def capabilities(self):
        return self._caps

    def list_accounts(self):
        return self._accounts


class TestDispatch:
    def test_unsupported_capability_explains_itself(self):
        adapter = Minimal({Capability.ACCOUNT_SWITCH: unsupported("needs the pro plan")})
        with pytest.raises(UnsupportedOperation, match="needs the pro plan"):
            require(adapter, Capability.ACCOUNT_SWITCH, AccountSwitcher)

    def test_missing_capability_counts_as_unsupported(self):
        with pytest.raises(UnsupportedOperation):
            require(Minimal(), Capability.ACCOUNT_SWITCH, AccountSwitcher)

    def test_capability_without_the_role_is_refused(self):
        adapter = Minimal({Capability.ACCOUNT_SWITCH: supported()})
        with pytest.raises(UnsupportedOperation, match="does not implement"):
            require(adapter, Capability.ACCOUNT_SWITCH, AccountSwitcher)

    def test_usage_for_harness_without_usage_is_unsupported_not_unlimited(self, tmp_path):
        a = acct(1)
        result = service.collect_usage(Minimal(accounts=[a]), [a], UsageService(tmp_path))
        assert result[a.key].state is UsageState.UNSUPPORTED
        assert result[a.key].max_used_percent is None

    def test_resolve_by_slot_alias_identity_label(self):
        a = acct(1, label="Me@Example.com")
        b = Account("h", "id2", "b@x", "p", 2, alias="work")
        assert service.resolve([a, b], "1") is a
        assert service.resolve([a, b], "WORK") is b
        assert service.resolve([a, b], "id2") is b
        assert service.resolve([a, b], "me@example.com") is a
        with pytest.raises(AccountNotFound):
            service.resolve([a, b], "nobody")

    def test_resolve_ambiguous_label_needs_provider(self):
        a = Account("h", "id1", "same@x", "openai", 1)
        b = Account("h", "id2", "same@x", "xai", 2)
        with pytest.raises(HswapError, match="ambiguous"):
            service.resolve([a, b], "same@x")
        assert service.resolve([a, b], "same@x", provider="xai") is b


# -- registry -------------------------------------------------------------------------------


class FakeEntryPoint(SimpleNamespace):
    pass


class TestRegistry:
    def test_builtins_are_lazy(self):
        reg = Registry({"mini": "tests.does_not_exist:Nope"}, discover_plugins=False)
        assert reg.ids() == ["mini"]  # listing never imports
        with pytest.raises(HarnessNotFound, match="failed to load"):
            reg.get("mini")

    def test_runtime_registration_and_contract_check(self):
        reg = Registry(discover_plugins=False)
        reg.register("mini", Minimal)
        assert reg.get("mini").id == "mini"
        reg.register("other", Minimal)  # reports id "mini" under "other"
        with pytest.raises(HarnessNotFound, match="contract"):
            reg.get("other")
        assert [a.id for a in reg.available()] == ["mini"]

    def test_plugins_are_listed_but_not_loaded_until_trusted(self, monkeypatch):
        loaded = []

        def fake_eps(group):
            assert group == "harness_swap.adapters"
            return [FakeEntryPoint(name="mini", value="tests.test_hswap_core:Minimal", dist=SimpleNamespace(name="mini-dist"))]

        monkeypatch.setattr("harness_swap.core.registry.entry_points", fake_eps)
        monkeypatch.setattr("harness_swap.core.registry._load_target", lambda t: loaded.append(t) or Minimal())
        reg = Registry({}, trusted_plugins=set())
        (entry,) = reg.entries()
        assert entry.origin == "plugin:mini-dist" and not entry.trusted
        assert reg.available() == [] and loaded == []
        with pytest.raises(HarnessNotFound, match="not trusted"):
            reg.get("mini")
        monkeypatch.setenv("HSWAP_TRUSTED_PLUGINS", "mini")
        reg = Registry({}, trusted_plugins=set())
        assert reg.get("mini").id == "mini" and loaded

    def test_plugin_cannot_shadow_a_builtin(self, monkeypatch):
        monkeypatch.setattr(
            "harness_swap.core.registry.entry_points",
            lambda group: [FakeEntryPoint(name="mini", value="evil:Adapter", dist=None)],
        )
        reg = Registry({"mini": "tests.test_hswap_core:Minimal"}, trusted_plugins={"mini"})
        assert reg.entries()[0].origin == "builtin"


def test_hswap_home_respects_env_and_xdg(monkeypatch, tmp_path):
    from harness_swap.core.paths import hswap_home

    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "x"))
    assert hswap_home() == tmp_path / "x"
    monkeypatch.delenv("HSWAP_HOME")
    if sys.platform.startswith("linux"):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        assert hswap_home() == tmp_path / "xdg" / "harness-swap"
        monkeypatch.setenv("XDG_DATA_HOME", "relative/ignored")
        assert hswap_home() == __import__("pathlib").Path.home() / ".local" / "share" / "harness-swap"
    assert os.environ.get("HSWAP_HOME") is None


def test_installation_probe_reports_a_failing_binary(tmp_path, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("fake executables are POSIX scripts")
    from harness_swap.adapters.base import probe_installation
    from tests.hswap_helpers import fake_executable, prepend_path

    fake_executable(tmp_path / "bin", "brokenharness", "print('boom: missing runtime'); sys.exit(127)")
    fake_executable(tmp_path / "bin", "okharness", "print('okharness 1.2.3')")
    prepend_path(monkeypatch, tmp_path / "bin")
    broken = probe_installation("brokenharness")
    assert broken.installed and broken.version is None and "boom" in broken.detail
    assert probe_installation("okharness").version == "okharness 1.2.3"
    assert not probe_installation("definitely-not-installed-xyz").installed


class TestUsageBackoffRegressions:
    def test_backoff_applies_without_any_good_reading(self, tmp_path):
        clock = [1000.0]
        svc = UsageService(tmp_path, lambda: clock[0])
        bad = CountingReader(RuntimeError("down"))
        first = svc.get(bad, acct(1))
        second = svc.get(bad, acct(1))
        assert bad.calls == 1 and first.state is second.state is UsageState.ERROR
        assert "down" in second.detail

    def test_backoff_never_serves_old_numbers_as_available(self, tmp_path):
        clock = [1000.0]
        svc = UsageService(tmp_path, lambda: clock[0])
        svc.get(CountingReader(UsageSnapshot(UsageState.AVAILABLE, (QuotaWindow("w", 5.0),), measured_at=1000.0)), acct(1))
        clock[0] += 61
        bad = CountingReader(RuntimeError("down"))
        svc.get(bad, acct(1))
        clock[0] += 1
        during = svc.get(bad, acct(1))
        assert bad.calls == 1 and during.state is UsageState.ERROR and during.windows[0].used_percent == 5.0

    def test_unreadable_cache_entries_are_ignored(self, tmp_path):
        (tmp_path / "usage-cache.json").write_text(json.dumps({acct(1).key: {"snapshot": {"state": "bogus"}}}))
        reader = CountingReader(snap(10))
        assert UsageService(tmp_path, lambda: 10.0).get(reader, acct(1)).state is UsageState.AVAILABLE
        (tmp_path / "usage-cache.json").write_text("[1, 2]")
        UsageService(tmp_path, lambda: 10.0).get(reader, acct(2))
        assert reader.calls == 2


def test_store_errors_are_hswap_errors(tmp_path):
    store = AccountStore(tmp_path / "h")
    store.root.mkdir(parents=True)
    store.file.write_text("{broken")
    with pytest.raises(HswapError, match="not valid JSON"):
        store.load()


def test_trust_hint_keeps_already_trusted_plugins(monkeypatch):
    eps = [FakeEntryPoint(name=n, value="x:Y", dist=None) for n in ("one", "two")]
    monkeypatch.setattr("harness_swap.core.registry.entry_points", lambda group: eps)
    reg = Registry({}, trusted_plugins={"one"})
    with pytest.raises(HarnessNotFound, match="plugins.trusted one,two"):
        reg.get("two")
