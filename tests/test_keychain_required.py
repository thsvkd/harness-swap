"""Keychain-required mode: the preflight, the refusals, the cached view and the
ban on the plaintext fallback. Default-off behaviour is pinned by the existing
fallback tests (tests/test_switcher.py, tests/test_credentials.py)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import cli, macos_keychain
from claude_swap.exceptions import ClaudeSwitchError, KeychainUnavailableError
from claude_swap.models import Platform
from claude_swap.settings import (
    SETTING_SPECS,
    load_credential_settings,
    require_keychain,
    set_setting,
)
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.usage_store import FetchRecord

from .keychain_helpers import ACTIVE_ITEM, creds, macos_store, snapshot

LOGIN = "/Users/me/Library/Keychains/login.keychain-db"


def _fake_security(**answers):
    """A runner: {"list-keychains": (rc, stdout)}. Anything else rc 0, empty."""

    def run(args):
        rc, out = answers.get(args[0], (0, ""))
        if isinstance(rc, Exception):
            raise rc
        return subprocess.CompletedProcess(args, rc, stdout=out, stderr="")

    return run


@pytest.mark.no_keychain_fake
class TestPreflight:
    @pytest.fixture(autouse=True)
    def _home(self, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: Path("/Users/me"))

    def _reachable(self, **answers):
        return macos_keychain.keychain_reachable(
            _fake_security(**answers), platform="darwin"
        )

    def test_login_keychain_listed_and_answering_is_reachable(self):
        assert self._reachable(**{
            "login-keychain": (0, f'    "{LOGIN}"\n'),
            "list-keychains": (0, f'    "{LOGIN}"\n    "/Library/Keychains/System.keychain"\n'),
        }) is True

    def test_search_list_without_the_login_keychain_is_unreachable(self):
        # The measured LaunchDaemon: only the system keychain is listed, and an
        # item lookup would say rc 44. show-keychain-info must not rescue it.
        assert self._reachable(**{
            "list-keychains": (0, '    "/Library/Keychains/System.keychain"\n'),
        }) is False

    def test_a_daemon_reporting_the_system_keychain_is_not_the_login_keychain(self):
        # `default-keychain` answering System.keychain would otherwise pass both.
        assert self._reachable(**{
            "login-keychain": (0, '    "/Library/Keychains/System.keychain"\n'),
            "default-keychain": (0, '    "/Library/Keychains/System.keychain"\n'),
            "list-keychains": (0, '    "/Library/Keychains/System.keychain"\n'),
        }) is False

    def test_show_keychain_info_rc36_is_unreachable(self):
        assert self._reachable(**{
            "list-keychains": (0, f'    "{LOGIN}"\n'),
            "show-keychain-info": (36, ""),
        }) is False

    def test_reported_path_is_the_one_checked(self):
        custom = "/Users/me/Library/Keychains/renamed.keychain-db"
        seen = []

        def run(args):
            seen.append(args)
            out = f'"{custom}"\n' if args[0] in ("login-keychain", "list-keychains") else ""
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

        assert macos_keychain.keychain_reachable(run, platform="darwin") is True
        assert ["show-keychain-info", custom] in seen

    @pytest.mark.parametrize(
        "failure", [subprocess.TimeoutExpired("security", 5), OSError("no binary")]
    )
    def test_a_security_that_cannot_run_is_unreachable(self, failure):
        assert self._reachable(**{"list-keychains": (failure, "")}) is False

    def test_not_applicable_off_macos(self):
        def never(args):
            raise AssertionError("security must not run")

        assert macos_keychain.keychain_reachable(never, platform="linux") is None


class TestSetting:
    def test_registered_and_off_by_default(self, tmp_path):
        assert SETTING_SPECS["credentials.requireKeychain"].default is False
        assert load_credential_settings(tmp_path).require_keychain is False
        assert require_keychain(tmp_path) is False

    def test_config_set_turns_it_on(self, tmp_path):
        assert set_setting(tmp_path, "credentials.requireKeychain", "true") is True
        assert require_keychain(tmp_path) is True

    @pytest.mark.parametrize(
        "stored, env, expected",
        [("true", "0", False), ("false", "1", True), ("true", "junk", True)],
    )
    def test_env_wins(self, tmp_path, monkeypatch, stored, env, expected):
        set_setting(tmp_path, "credentials.requireKeychain", stored)
        monkeypatch.setenv("HSWAP_REQUIRE_KEYCHAIN", env)
        assert require_keychain(tmp_path) is expected


def _main(argv, capsys):
    """Run the CLI with `Platform.detect` saying macOS; (exit code, stdout, stderr)."""
    code = 0
    with (
        patch("claude_swap.models.Platform.detect", return_value=Platform.MACOS),
        patch.object(sys, "argv", ["cswap", *argv]),
    ):
        try:
            cli.main()
        except SystemExit as exc:
            code = exc.code
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def unreachable(temp_home, block_real_keychain, monkeypatch):
    """Two slots, live slot 1, mode on, and the keychain out of reach."""
    s = macos_store(temp_home)
    block_real_keychain.data[ACTIVE_ITEM] = creds()
    (temp_home / ".claude" / ".credentials.json").write_text(creds())
    s._write_account_credentials("1", "a@example.com", creds())
    s._write_account_credentials("2", "b@example.com", creds("sk-b", "rt-b"))
    set_setting(s.backup_dir, "credentials.requireKeychain", "true")
    block_real_keychain.reachable = False
    monkeypatch.setattr(
        "claude_swap.oauth.urllib.request.urlopen",
        lambda *a, **kw: pytest.fail("no network while refused"),
    )
    return s


class TestRefusals:
    @pytest.mark.parametrize(
        "argv",
        [
            ["switch"],
            ["switch", "2"],
            ["switch", "2", "--force"],
            ["switch", "--strategy", "best"],
            ["add"],
            ["add-token", "sk-ant-oat01-TOKEN"],
            ["remove", "2"],
            ["move", "2", "5"],
            ["swap", "1", "2"],
            ["auto", "--once"],
            ["auto"],
            ["keepalive"],
            ["purge"],
            ["run", "2"],
        ],
        ids=" ".join,
    )
    def test_refuses_and_changes_nothing(
        self, unreachable, temp_home, block_real_keychain, capsys, argv
    ):
        before = snapshot(temp_home, block_real_keychain)
        code, _, err = _main(argv, capsys)
        assert code == 1
        assert "GUI session" in err
        assert snapshot(temp_home, block_real_keychain) == before

    def test_import_refuses_and_changes_nothing(
        self, unreachable, temp_home, tmp_path, block_real_keychain, capsys
    ):
        source = tmp_path / "backup.cswap"
        source.write_text("{}")
        before = snapshot(temp_home, block_real_keychain)
        code, _, err = _main(["import", str(source)], capsys)
        assert code == 1 and "GUI session" in err
        assert snapshot(temp_home, block_real_keychain) == before

    @pytest.mark.parametrize(
        "argv",
        [["switch", "2", "--json"], ["switch", "--json"], ["auto", "--once", "--json"]],
        ids=" ".join,
    )
    def test_json_error_envelope(self, unreachable, temp_home, block_real_keychain, capsys, argv):
        before = snapshot(temp_home, block_real_keychain)
        code, out, _ = _main(argv, capsys)
        assert code == 1
        assert json.loads(out)["error"]["type"] == "keychain_unavailable"
        assert snapshot(temp_home, block_real_keychain) == before

    def test_auto_loop_tick_refuses_when_the_keychain_goes_away(
        self, temp_home, block_real_keychain
    ):
        from claude_swap.autoswitch import AutoSwitchEngine, TickOutcome
        from claude_swap.settings import load_settings

        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        block_real_keychain.reachable = False
        events = []
        engine = AutoSwitchEngine(s, load_settings(s.backup_dir), events.append)
        before = snapshot(temp_home, block_real_keychain)
        assert engine.tick() is TickOutcome.ERROR
        assert "GUI session" in events[-1].message
        assert snapshot(temp_home, block_real_keychain) == before

    def test_consume_gate_posts_nothing(self, unreachable):
        outcome = unreachable.consume_backup_grant("2", "b@example.com", creds("sk-b", "rt-b"))
        assert outcome.credentials is None and outcome.error == "transient"

    def test_default_mode_and_reachable_keychain_do_not_refuse(
        self, temp_home, block_real_keychain
    ):
        s = macos_store(temp_home)
        block_real_keychain.reachable = False
        s.refuse_if_keychain_unavailable()  # mode off
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        block_real_keychain.reachable = True
        s.refuse_if_keychain_unavailable()  # mode on, reachable

    def test_mode_is_a_no_op_off_macos(self, temp_home, block_real_keychain):
        s = macos_store(temp_home)
        s.platform = Platform.LINUX
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        block_real_keychain.reachable = False
        s.refuse_if_keychain_unavailable()
        s._write_credentials(creds())
        assert (temp_home / ".claude" / ".credentials.json").exists()


class TestCachedView:
    def _seed_usage(self, s):
        usage = {"five_hour": {"pct": 25.0}, "seven_day": {"pct": 10.0}}
        identities = {"1": ("a@example.com", ""), "2": ("b@example.com", "")}
        s._usage_store.record(
            {"1": FetchRecord(usage=usage), "2": FetchRecord(usage=usage)}, identities
        )

    def test_list_json_is_cached_and_marked(
        self, unreachable, temp_home, block_real_keychain, capsys
    ):
        self._seed_usage(unreachable)
        before = snapshot(temp_home, block_real_keychain)
        with patch(
            "claude_swap.oauth.try_fetch_usage_for_account",
            side_effect=AssertionError("no fetch"),
        ):
            code, out, _ = _main(["list", "--json"], capsys)
        payload = json.loads(out)
        assert code == 0
        assert payload["keychainUnavailable"] is True
        assert payload["activeAccountNumber"] == 1
        assert [row["usageStatus"] for row in payload["accounts"]] == ["ok", "ok"]
        assert payload["accounts"][0]["usage"]["fiveHour"]["pct"] == 25.0
        assert snapshot(temp_home, block_real_keychain) == before

    def test_list_keeps_the_login_expiry_keepalive_recorded(self, unreachable, capsys):
        unreachable._usage_store.set_login_expiry(
            "1", ("a@example.com", ""), "2030-01-01T00:00:00Z"
        )
        _, out, _ = _main(["list", "--json"], capsys)
        assert json.loads(out)["accounts"][0]["loginExpiresAt"] == "2030-01-01T00:00:00Z"

    def test_human_list_says_why(self, unreachable, capsys):
        self._seed_usage(unreachable)
        set_setting(unreachable.backup_dir, "updates.check", "false")  # no PyPI lookup
        code, out, err = _main(["list"], capsys)
        assert code == 0
        assert "cached" in out + err

    def test_empty_store_json_still_says_why(self, temp_home, block_real_keychain, capsys):
        s = ClaudeAccountSwitcher()
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        block_real_keychain.reachable = False
        code, out, _ = _main(["list", "--json"], capsys)
        assert code == 0 and json.loads(out)["keychainUnavailable"] is True

    def test_dashboard_snapshot_fetches_nothing(self, unreachable, block_real_keychain):
        self._seed_usage(unreachable)
        with patch.object(
            unreachable, "_fetch_account_usage", side_effect=AssertionError("no fetch")
        ):
            snap = unreachable.accounts_snapshot()
        assert snap.active_number == "1"

    def test_status_does_not_fetch(self, unreachable, capsys):
        self._seed_usage(unreachable)
        with patch(
            "claude_swap.oauth.try_fetch_usage_for_account",
            side_effect=AssertionError("no fetch"),
        ):
            code, out, _ = _main(["status", "--json"], capsys)
        assert code == 0
        assert json.loads(out)["active"]["usage"]["fiveHour"]["pct"] == 25.0

    def test_mode_off_has_no_marker(self, temp_home, block_real_keychain, capsys):
        macos_store(temp_home)
        block_real_keychain.reachable = False
        with patch("claude_swap.oauth.try_fetch_usage_for_account"):
            _, out, _ = _main(["list", "--json"], capsys)
        assert "keychainUnavailable" not in json.loads(out)


def _failing_set(real, *failing_services):
    def set_password(service, account, password):
        if not failing_services or service in failing_services:
            raise macos_keychain.KeychainError("-25308")
        real(service, account, password)

    return set_password


class TestNoFallback:
    """The preflight passed, then the Keychain write fails anyway."""

    @pytest.fixture
    def store(self, temp_home):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        return s

    def _plaintext(self, s, home):
        return [
            *s.credentials_dir.glob("*.enc*"),
            *(home / ".claude").glob(".credentials.json"),
        ]

    def test_active_write_raises(self, store, temp_home, block_real_keychain, monkeypatch):
        monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
        with pytest.raises(KeychainUnavailableError):
            store._write_credentials(creds())
        assert not self._plaintext(store, temp_home)

    def test_backup_write_raises(self, store, temp_home, monkeypatch):
        monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
        with pytest.raises(KeychainUnavailableError):
            store._write_account_credentials("1", "a@example.com", creds())
        assert not self._plaintext(store, temp_home)

    def test_managed_key_write_raises(self, store, temp_home, monkeypatch):
        monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
        config_before = (temp_home / ".claude.json").read_text()
        with pytest.raises(KeychainUnavailableError):
            store._write_credentials("sk-ant-api03-KEY")
        assert (temp_home / ".claude.json").read_text() == config_before

    def test_sticky_file_mode_does_not_reach_a_file_either(self, store, temp_home):
        store._store._keychain_usable_cache = False  # an earlier read failed
        with pytest.raises(KeychainUnavailableError):
            store._write_credentials(creds())
        with pytest.raises(KeychainUnavailableError):
            store._write_account_credentials("1", "a@example.com", creds())
        assert not self._plaintext(store, temp_home)

    def test_failed_retention_does_not_route_the_write_to_a_file(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        block_real_keychain.data[("claude-swap", "account-1-a@example.com")] = creds("old", "old")
        monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
        with pytest.raises(KeychainUnavailableError):
            store._write_account_credentials("1", "a@example.com", creds())
        assert not self._plaintext(store, temp_home)

    def test_mid_switch_failure_writes_no_fallback_and_keeps_the_live_store(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        live = creds("sk-live", "rt-live")
        block_real_keychain.data[ACTIVE_ITEM] = live
        store._write_account_credentials("1", "a@example.com", live)
        store._write_account_credentials("2", "b@example.com", creds("sk-b", "rt-b"))
        config_before = (temp_home / ".claude.json").read_bytes()
        monkeypatch.setattr(
            macos_keychain,
            "set_password",
            _failing_set(block_real_keychain.set_password, ACTIVE_ITEM[0]),
        )
        with pytest.raises(ClaudeSwitchError) as err:
            store.switch_to("2", json_output=True)
        assert isinstance(err.value, KeychainUnavailableError)
        assert block_real_keychain.data[ACTIVE_ITEM] == live
        assert not self._plaintext(store, temp_home)
        assert (temp_home / ".claude.json").read_bytes() == config_before
        assert store._get_sequence_data()["activeAccountNumber"] == 1

    def test_failure_after_the_keychain_write_rolls_it_back(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        live = creds("sk-live", "rt-live")
        block_real_keychain.data[ACTIVE_ITEM] = live
        store._write_account_credentials("1", "a@example.com", live)
        store._write_account_credentials("2", "b@example.com", creds("sk-b", "rt-b"))
        real_write = store._write_json

        def failing_write(path, data):
            if path == store._get_claude_config_path():
                raise OSError("disk full")
            real_write(path, data)

        monkeypatch.setattr(store, "_write_json", failing_write)
        with pytest.raises(ClaudeSwitchError):
            store.switch_to("2", json_output=True)
        assert block_real_keychain.data[ACTIVE_ITEM] == live
        assert not self._plaintext(store, temp_home)

    def test_default_mode_still_falls_back(self, temp_home, monkeypatch):
        s = macos_store(temp_home)
        monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
        s._write_credentials(creds())
        s._write_account_credentials("1", "a@example.com", creds())
        assert len(self._plaintext(s, temp_home)) == 2
