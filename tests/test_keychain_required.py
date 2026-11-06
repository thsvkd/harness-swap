"""Keychain-required mode: the preflight, the refusals, the cached view and the
ban on the plaintext fallback. Default-off behaviour is pinned by the existing
fallback tests (tests/test_switcher.py, tests/test_credentials.py)."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from claude_swap import cli, consumed_grants, macos_keychain, oauth
from claude_swap.exceptions import ClaudeSwitchError, KeychainUnavailableError
from claude_swap.keepalive import run_keepalive
from claude_swap.models import Platform
from claude_swap.settings import (
    SETTING_SPECS,
    load_credential_settings,
    require_keychain,
    set_setting,
)
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.usage_store import FetchRecord

from .keychain_helpers import ACTIVE_ITEM, FakeSecurity, creds, macos_store, snapshot, written_last

LOGIN = "/Users/me/Library/Keychains/login.keychain-db"


@pytest.fixture(autouse=True)
def _macos_store_root():
    """`get_backup_root()` follows `Platform.detect()`, so on Linux a store made without
    this and a CLI run that says macOS would each see a different directory."""
    with patch("claude_swap.models.Platform.detect", return_value=Platform.MACOS):
        yield


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
            _fake_security(**answers), platform="darwin", unlocked=lambda path: True
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

        assert macos_keychain.keychain_reachable(
            run, platform="darwin", unlocked=lambda path: path == custom
        ) is True
        assert ["show-keychain-info", custom] in seen

    @pytest.mark.parametrize(
        "failure", [subprocess.TimeoutExpired("security", 5), OSError("no binary")]
    )
    def test_a_security_that_cannot_run_is_unreachable(self, failure):
        assert self._reachable(**{"list-keychains": (failure, "")}) is False

    @pytest.mark.parametrize("state", [False, None], ids=["locked", "unknown"])
    def test_a_locked_keychain_never_reaches_the_command_that_can_prompt(self, state):
        seen = []

        def run(args):
            seen.append(args[0])
            out = f'"{LOGIN}"\n' if args[0] == "list-keychains" else ""
            return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

        assert macos_keychain.keychain_reachable(
            run, platform="darwin", unlocked=lambda path: state
        ) is False
        assert "show-keychain-info" not in seen

    def _framework(self, monkeypatch, *, status=0, status_rc=0, open_rc=0):
        calls = []

        def set_interaction(allowed):
            calls.append(("interaction", allowed))

        def open_keychain(path, out):
            calls.append(("open", path))
            return open_rc

        def get_status(keychain, out):
            out._obj.value = status
            calls.append(("status",))
            return status_rc

        def libraries(path):
            return SimpleNamespace(
                SecKeychainSetUserInteractionAllowed=set_interaction,
                SecKeychainOpen=open_keychain,
                SecKeychainGetStatus=get_status,
                CFRelease=lambda keychain: calls.append(("release",)),
            )

        monkeypatch.setattr(macos_keychain.ctypes, "CDLL", libraries)
        return calls

    @pytest.mark.parametrize("status, expected", [(1, True), (0, False), (6, False), (7, True)])
    def test_lock_state_reads_the_unlock_bit_with_interaction_off(
        self, monkeypatch, status, expected
    ):
        calls = self._framework(monkeypatch, status=status)
        assert macos_keychain._login_keychain_unlocked(LOGIN) is expected
        assert calls[0] == ("interaction", False)  # before any keychain call
        assert ("open", LOGIN.encode()) in calls

    @pytest.mark.parametrize("failure", [{"open_rc": -25294}, {"status_rc": -25308}])
    def test_lock_state_failure_is_unknown(self, monkeypatch, failure):
        self._framework(monkeypatch, status=1, **failure)
        assert macos_keychain._login_keychain_unlocked(LOGIN) is None

    def test_lock_state_without_the_framework_is_unknown(self, monkeypatch):
        def missing(path):
            raise OSError("no such library")

        monkeypatch.setattr(macos_keychain.ctypes, "CDLL", missing)
        assert macos_keychain._login_keychain_unlocked(LOGIN) is None

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
        [
            ("true", "0", True),  # a process's env cannot reopen the fallback
            ("false", "1", True),
            ("false", "0", False),
            ("true", "junk", True),
            ("false", "junk", False),
        ],
    )
    def test_env_may_only_tighten(self, tmp_path, monkeypatch, stored, env, expected):
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
    (temp_home / ".claude" / ".credentials.json").write_text(creds(), encoding="utf-8")
    s._write_account_credentials("1", "a@example.com", creds())
    s._write_account_credentials("2", "b@example.com", creds("sk-b", "rt-b"))
    set_setting(s.backup_dir, "credentials.requireKeychain", "true")
    block_real_keychain.reachable = False
    monkeypatch.setattr(
        "claude_swap.oauth.urllib.request.urlopen",
        lambda *a, **kw: pytest.fail("no network while refused"),
    )
    # If a refusal ever regresses, these fail the test: a loop would hang the run, and
    # `run` would exec a real claude.
    monkeypatch.setattr(
        "claude_swap.autoswitch.AutoSwitchEngine.run_loop",
        lambda self: pytest.fail("auto started its loop while refused"),
    )
    monkeypatch.setattr("claude_swap.session.shutil.which", lambda name: None)
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
        source.write_text("{}", encoding="utf-8")
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
        config_before = (temp_home / ".claude.json").read_text(encoding="utf-8")
        with pytest.raises(KeychainUnavailableError):
            store._write_credentials("sk-ant-api03-KEY")
        assert (temp_home / ".claude.json").read_text(encoding="utf-8") == config_before

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


class TestNoReadPathWrites:
    def _strip_org(self, s):
        data = s._get_sequence_data()
        del data["accounts"]["1"]["organizationUuid"]
        s._write_json(s.sequence_file, data)

    def test_R8_status_and_list_do_not_migrate_sequence_json(
        self, temp_home, block_real_keychain, capsys
    ):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        self._strip_org(s)
        block_real_keychain.reachable = False
        before = snapshot(temp_home, block_real_keychain)
        s._build_status_payload()
        s.status()
        s.list_accounts(json_output=True)
        s.list_accounts()
        s.accounts_snapshot()
        assert snapshot(temp_home, block_real_keychain) == before

    def test_R8_status_cli_writes_nothing_with_a_pending_migration(
        self, temp_home, block_real_keychain, capsys
    ):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        self._strip_org(s)
        block_real_keychain.reachable = False
        before = snapshot(temp_home, block_real_keychain)
        code, _, _ = _main(["status", "--json"], capsys)
        assert code == 0
        assert snapshot(temp_home, block_real_keychain) == before

    def test_R8_construction_runs_no_migration_in_the_closed_view(
        self, temp_home, block_real_keychain
    ):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        block_real_keychain.reachable = False
        state = s.backup_dir / ".migrations.json"
        state.unlink()
        with patch("claude_swap.models.Platform.detect", return_value=Platform.MACOS):
            ClaudeAccountSwitcher()
        assert not state.exists()

    def test_R8_migration_still_runs_when_the_keychain_is_reachable(self, temp_home):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        self._strip_org(s)
        assert "organizationUuid" in s._get_sequence_data_migrated()["accounts"]["1"]


class _RotatingEndpoint:
    def __init__(self):
        self.posts = []

    def __call__(self, request, timeout=None):
        self.posts.append(json.loads(request.data)["refresh_token"])
        n = len(self.posts)
        return io.BytesIO(json.dumps({
            "access_token": f"AT-{n}", "refresh_token": f"RT-{n}", "expires_in": 28800,
        }).encode())


class TestEncDoesNotShadowR9:
    @pytest.fixture
    def store(self, temp_home):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        return s

    def _seed(self, s, *, enc_expires, keychain_expires):
        s._write_account_credentials(
            "2", "b@example.com", creds("AT-kc", "RT-kc", expires_in_s=keychain_expires)
        )
        s._store._write_backup_enc(
            "2", "b@example.com", creds("AT-enc", "RT-enc", expires_in_s=enc_expires)
        )
        return s._store._backup_enc_path("2", "b@example.com")

    def _access(self, s):
        return oauth.extract_oauth_data(s._read_account_credentials("2", "b@example.com"))[
            "accessToken"
        ]

    def test_R9_newer_keychain_wins_and_the_read_changes_nothing(self, store):
        enc = self._seed(store, enc_expires=100, keychain_expires=7200)
        before = enc.read_bytes()
        assert self._access(store) == "AT-kc"
        assert enc.read_bytes() == before

    def test_R9_the_next_write_of_the_slot_removes_the_stale_enc(self, store):
        enc = self._seed(store, enc_expires=100, keychain_expires=7200)
        store._write_account_credentials("2", "b@example.com", creds("AT-new", "RT-new"))
        assert not enc.exists()
        assert self._access(store) == "AT-new"

    def test_R9_newer_enc_still_wins(self, store):
        enc = self._seed(store, enc_expires=7200, keychain_expires=100)
        assert self._access(store) == "AT-enc"
        assert enc.exists()

    def test_R9_refresh_token_outranks_a_later_date(self, store):
        enc = store._store._backup_enc_path("2", "b@example.com")
        store._write_account_credentials("2", "b@example.com", creds("AT-kc", "RT-kc"))
        data = json.loads(creds("AT-enc", "x", expires_in_s=99999))
        del data["claudeAiOauth"]["refreshToken"]
        store._store._write_backup_enc("2", "b@example.com", json.dumps(data))
        assert self._access(store) == "AT-kc"
        assert enc.exists()

    def test_R9_read_writes_nothing_when_the_keychain_is_unreachable(
        self, store, block_real_keychain
    ):
        enc = self._seed(store, enc_expires=100, keychain_expires=7200)
        block_real_keychain.reachable = False
        store._read_account_credentials("2", "b@example.com")
        assert enc.exists()

    def _backup_item_denied(self, monkeypatch):
        real = macos_keychain.get_password

        def denied(service, account):
            if service == "claude-swap":
                raise macos_keychain.KeychainError("denied")
            return real(service, account)

        monkeypatch.setattr(macos_keychain, "get_password", denied)

    def test_item_read_failure_is_unreadable_not_the_enc(self, store, monkeypatch):
        """Preflight passed, then this one item timed out or was denied."""
        self._seed(store, enc_expires=100, keychain_expires=7200)
        self._backup_item_denied(monkeypatch)
        assert store._read_account_credentials_ex("2", "b@example.com") == ("", True)

    def test_item_read_failure_defers_the_consume_gate(self, store, monkeypatch):
        self._seed(store, enc_expires=100, keychain_expires=7200)
        endpoint = _RotatingEndpoint()
        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", endpoint)
        self._backup_item_denied(monkeypatch)
        stale = creds("AT-enc", "RT-enc", expires_in_s=100)
        outcome = store.consume_backup_grant("2", "b@example.com", stale)
        assert outcome.error == "transient" and outcome.credentials is None
        assert endpoint.posts == []

    @pytest.mark.parametrize("leftover_enc", [True, False], ids=["enc", "no-enc"])
    @pytest.mark.parametrize("own_slot", [True, False], ids=["own-slot", "other-slot"])
    def test_item_read_failure_defers_keepalive(
        self, temp_home, block_real_keychain, monkeypatch, leftover_enc, own_slot
    ):
        s = macos_store(temp_home)
        slot = ("1", "a@example.com") if own_slot else ("2", "b@example.com")
        if leftover_enc:
            s._store._write_backup_enc(*slot, creds("AT-enc", "RT-enc", expires_in_s=100))
        live = creds("AT-K", "RT-K", expires_in_s=600)
        block_real_keychain.data[ACTIVE_ITEM] = live
        endpoint = _RotatingEndpoint()
        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", endpoint)
        real = macos_keychain.get_password

        def denied(service, account):
            if (service, account) == ("claude-swap", f"account-{slot[0]}-{slot[1]}"):
                raise macos_keychain.KeychainError("denied")
            return real(service, account)

        monkeypatch.setattr(macos_keychain, "get_password", denied)
        report = run_keepalive(s)
        assert report["ok"] is False and report["error"]["type"] == "keychain_unavailable"
        assert endpoint.posts == []
        assert block_real_keychain.data[ACTIVE_ITEM] == live

    def test_R9_default_mode_keeps_enc_wins(self, temp_home):
        s = macos_store(temp_home)
        self._seed(s, enc_expires=100, keychain_expires=7200)
        assert self._access(s) == "AT-enc"


class TestRequiredModeFetchPathR10:
    @pytest.fixture
    def setup(self, temp_home, block_real_keychain, monkeypatch):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        expired = creds("AT-0", "RT-0", expires_in_s=-100)
        block_real_keychain.data[ACTIVE_ITEM] = expired
        s._write_account_credentials("1", "a@example.com", expired)
        endpoint = _RotatingEndpoint()
        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", endpoint)
        monkeypatch.setattr(
            "claude_swap.oauth.try_fetch_usage_for_account",
            lambda *a, **kw: oauth.UsageOutcome(None, error="timeout"),
        )
        return s, expired, endpoint

    def test_R10_successor_survives_a_keychain_that_fails_after_the_post(
        self, setup, block_real_keychain, monkeypatch
    ):
        s, expired, endpoint = setup
        real_set = block_real_keychain.set_password
        real_endpoint = endpoint

        def post_then_lock(request, timeout=None):
            response = real_endpoint(request, timeout)
            monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
            return response

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post_then_lock)
        s._fetch_active_usage("1", "a@example.com", expired, "")
        assert endpoint.posts == ["RT-0"]
        spent = oauth.credential_fingerprint(expired)
        assert consumed_grants.entry(spent)["state"] == consumed_grants.CONSUMED
        rows = s._store._list_unclaimed_credentials()
        assert [row["consumedFp"] for row in rows.values()] == [spent]
        assert [row["configSlot"] for row in rows.values()] == ["1"]
        assert not list(s.credentials_dir.glob(".creds-*.enc"))
        assert not (s.home / ".claude" / ".credentials.json").exists()

        # The next pass, on the same path, adopts it instead of posting again.
        monkeypatch.setattr(macos_keychain, "set_password", real_set)
        fresh = ClaudeAccountSwitcher()
        fresh.platform = Platform.MACOS
        fresh._fetch_active_usage("1", "a@example.com", expired, "")
        assert endpoint.posts == ["RT-0"]
        assert oauth.extract_access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"
        assert oauth.extract_access_token(fresh._read_account_credentials("1", "a@example.com")) == "AT-1"
        assert fresh._store._list_unclaimed_credentials() == {}

    def test_R10_keepalive_adopts_what_the_fetch_path_parked(
        self, setup, block_real_keychain, monkeypatch
    ):
        s, expired, endpoint = setup
        s.stash_consumed_successor(
            "1", ("a@example.com", ""), creds("AT-P", "RT-P"),
            oauth.credential_fingerprint(expired), "active-refresh-persist-failed",
        )
        consumed_grants.record(
            oauth.credential_fingerprint(expired), ("a@example.com", ""), consumed_grants.CONSUMED
        )
        report = run_keepalive(s)
        assert report["ok"] is True and report["action"] == "synced-keychain"
        assert endpoint.posts == []
        assert oauth.extract_access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-P"

    def test_R10_fetch_path_preflights_before_the_post(
        self, setup, block_real_keychain
    ):
        s, expired, endpoint = setup
        assert s.keychain_gate_closed() is False  # a cached answer: reachable
        block_real_keychain.reachable = False
        before = snapshot(s.home, block_real_keychain)
        s._fetch_active_usage("1", "a@example.com", expired, "")
        assert endpoint.posts == []
        assert snapshot(s.home, block_real_keychain) == before

    def test_R10_consume_gate_and_freshen_preflight_before_the_post(
        self, setup, block_real_keychain
    ):
        from claude_swap.autoswitch import AutoSwitchEngine
        from claude_swap.settings import load_settings

        s, _, endpoint = setup
        stale = creds("AT-b", "RT-b", expires_in_s=-100)
        s._write_account_credentials("2", "b@example.com", stale)
        assert s.keychain_gate_closed() is False
        block_real_keychain.reachable = False
        assert s.consume_backup_grant("2", "b@example.com", stale).error == "transient"
        # Still inside the cached answer's TTL: the POST itself re-asks.
        s._keychain_gate = (time.monotonic(), False)
        assert s._consume_backup_grant_locked("2", "b@example.com", stale).error == "transient"
        s._keychain_gate = (time.monotonic(), False)
        engine = AutoSwitchEngine(s, load_settings(s.backup_dir), lambda event: None)
        assert engine._freshen_target("2", "b@example.com") == "transient"
        assert endpoint.posts == []

    def test_R10_default_mode_records_no_ledger(self, temp_home, block_real_keychain, monkeypatch):
        s = macos_store(temp_home)
        expired = creds("AT-0", "RT-0", expires_in_s=-100)
        block_real_keychain.data[ACTIVE_ITEM] = expired
        s._write_account_credentials("1", "a@example.com", expired)
        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", _RotatingEndpoint())
        monkeypatch.setattr(
            "claude_swap.oauth.try_fetch_usage_for_account",
            lambda *a, **kw: oauth.UsageOutcome(None, error="timeout"),
        )
        s._fetch_active_usage("1", "a@example.com", expired, "")
        assert not (s.backup_dir / "cache" / consumed_grants.FILENAME).exists()


class TestEnvOverrideCannotLoosen:
    def test_zero_does_not_reopen_the_plaintext_fallback(self, temp_home, monkeypatch):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        monkeypatch.setenv("HSWAP_REQUIRE_KEYCHAIN", "0")
        monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
        with pytest.raises(KeychainUnavailableError):
            s._write_credentials(creds())
        assert not (temp_home / ".claude" / ".credentials.json").exists()


@pytest.mark.no_keychain_fake
class TestKeychainThatManglesWithRcZero:
    """The real wrapper over a fake `security` that exits 0 and stores something else."""

    @pytest.fixture
    def mangling(self, temp_home, monkeypatch):
        monkeypatch.setattr(macos_keychain, "keychain_reachable", lambda *a, **kw: True)
        fake = FakeSecurity()
        monkeypatch.setattr("claude_swap.macos_keychain.subprocess.run", fake)
        s = macos_store(temp_home)
        endpoint = _RotatingEndpoint()
        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", endpoint)
        return s, fake, endpoint

    def _credential(self, access, refresh, expires_in_s):
        # Real size, so these take the quoted `-w` path a real login takes.
        return creds(access + "A" * 1000, refresh + "B" * 1000, expires_in_s=expires_in_s)

    def test_active_write_fails_closed_and_no_plaintext_appears(self, mangling, temp_home):
        s, fake, _ = mangling
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        fake.mangle = lambda value: value.replace('"', "")
        with pytest.raises(KeychainUnavailableError):
            s._write_credentials(self._credential("AT", "RT", 7200))
        assert not (temp_home / ".claude" / ".credentials.json").exists()
        assert not list(s.credentials_dir.glob("*.enc"))

    def test_keepalive_direct_post_keeps_the_successor_in_the_stash(self, mangling, temp_home):
        s, fake, endpoint = mangling
        near = self._credential("AT-0", "RT-0", 600)
        fake.items[ACTIVE_ITEM] = near
        s._store._write_account_credentials("1", "a@example.com", self._credential("AT-old", "RT-old", -100))
        fake.mangle = lambda value: value.replace('"', "")
        report = run_keepalive(s)
        assert report["ok"] is False and report["error"]["type"] == "keychain_unavailable"
        assert len(endpoint.posts) == 1
        rows = s._store._list_unclaimed_credentials()
        kept = [s._store._read_unclaimed_credential(i)[0] for i in rows]
        assert [oauth.extract_access_token(value) for value in kept] == ["AT-1"]
        assert [row["consumedFp"] for row in rows.values()] == [oauth.credential_fingerprint(near)]
        assert consumed_grants.entry(oauth.credential_fingerprint(near))["state"] == "consumed"
        assert not (temp_home / ".claude" / ".credentials.json").exists()

    def test_consume_gate_keeps_the_successor_in_the_stash(self, mangling):
        s, fake, endpoint = mangling
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        stale = self._credential("AT-b", "RT-b", -100)
        s._store._write_account_credentials("2", "b@example.com", stale)
        fake.mangle = lambda value: value.replace('"', "")
        outcome = s.consume_backup_grant("2", "b@example.com", stale)
        assert outcome.error == "transient" and outcome.stashed is True
        rows = s._store._list_unclaimed_credentials()
        kept = [s._store._read_unclaimed_credential(i)[0] for i in rows]
        assert [oauth.extract_access_token(value) for value in kept] == ["AT-1"]
        assert len(endpoint.posts) == 1

    def test_default_mode_falls_back_to_the_file_as_for_any_failed_write(self, mangling, temp_home):
        s, fake, _ = mangling
        fake.mangle = lambda value: value.replace('"', "")
        value = self._credential("AT", "RT", 7200)
        s._write_credentials(value)
        assert (temp_home / ".claude" / ".credentials.json").read_text(encoding="utf-8") == value
        assert ACTIVE_ITEM not in fake.items  # the fallback clears what would shadow it

    def test_non_ascii_metadata_stays_readable_and_the_enc_is_not_lost_to_it(self, mangling):
        """The review's path: hex in the slot, the readable .enc reconciled away, and a
        successor the next run could not adopt."""
        s, *_ = mangling
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        value = json.dumps(
            {"claudeAiOauth": json.loads(self._credential("AT", "RT", 7200))["claudeAiOauth"],
             "mcpOAuth": {"server": "café"}},
            ensure_ascii=False,
        )
        s._store._write_backup_enc("1", "a@example.com", value)
        s._write_account_credentials("1", "a@example.com", value)
        stored = s._read_account_credentials("1", "a@example.com")
        assert oauth.extract_oauth_data(stored)["refreshToken"].startswith("RT")
        assert json.loads(stored)["mcpOAuth"] == {"server": "café"}

    def test_a_faithful_keychain_round_trips_a_real_sized_credential(self, mangling):
        s, fake, _ = mangling
        value = self._credential("AT", "RT", 7200)
        s._write_credentials(value)
        assert fake.items[ACTIVE_ITEM] == value


class TestSelftestCommand:
    def _run(self, capsys, *argv, platform=Platform.MACOS):
        code = 0
        with (
            patch("claude_swap.cli.Platform.detect", return_value=platform),
            patch.object(sys, "argv", ["cswap", "keychain-selftest", *argv]),
        ):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return (code, *capsys.readouterr())

    @pytest.fixture
    def security(self, monkeypatch):
        fake = FakeSecurity()
        monkeypatch.setattr(macos_keychain, "keychain_reachable", lambda *a, **kw: True)
        monkeypatch.setattr("claude_swap.macos_keychain.subprocess.run", fake)
        return fake

    @pytest.mark.no_keychain_fake
    def test_ok(self, security, capsys):
        code, out, _ = self._run(capsys, "--json")
        assert code == 0 and json.loads(out) == {"ok": True}
        assert security.items == {}

    @pytest.mark.no_keychain_fake
    def test_mangling_fails_and_never_prints_the_value(self, security, capsys):
        security.mangle = lambda value: value.replace("\\", "")
        code, out, err = self._run(capsys, "--json")
        report = json.loads(out)
        assert code == 1 and report["ok"] is False
        assert report["error"]["type"] == "selftest_failed"
        assert security.items == {}
        for text in (out, err):
            assert "AbC-_" not in text and "HOME" not in text

    @pytest.mark.no_keychain_fake
    def test_a_failed_delete_exits_one(self, security, capsys):
        security.delete_rc = 45
        code, out, _ = self._run(capsys, "--json")
        assert code == 1 and json.loads(out)["ok"] is False

    @pytest.mark.no_keychain_fake
    def test_human_output(self, security, capsys):
        code, out, _ = self._run(capsys)
        assert code == 0 and "ok" in out and "AbC-_" not in out
        security.mangle = lambda value: value[:-1]
        code, out, err = self._run(capsys)
        assert code == 1 and "Error:" in err and "AbC-_" not in out + err

    def test_refuses_when_the_keychain_is_out_of_reach(self, block_real_keychain, capsys):
        block_real_keychain.reachable = False
        code, out, _ = self._run(capsys, "--json")
        report = json.loads(out)
        assert code == 1 and report["ok"] is False
        assert report["error"]["type"] == "keychain_unavailable"
        assert block_real_keychain.data == {}

    @pytest.mark.parametrize("flags, expected", [((), "unsupported\n"), (("--json",), '{"unsupported": true}\n')])
    def test_unsupported_elsewhere_exits_zero(self, capsys, flags, expected):
        code, out, _ = self._run(capsys, *flags, platform=Platform.LINUX)
        assert code == 0 and out == expected


class _TokenAndUsage:
    """Fake network: counts refresh POSTs, and refuses usage reads as Claude's server
    refuses a revoked token, which is what sends the fetch path to refresh."""

    def __init__(self):
        self.posts = []

    def __call__(self, request, timeout=None):
        if request.data is None:
            raise urllib.error.HTTPError(request.full_url, 401, "no", {}, io.BytesIO(b"{}"))
        self.posts.append(json.loads(request.data)["refresh_token"])
        n = len(self.posts)
        return io.BytesIO(json.dumps({
            "access_token": f"AT-{n}", "refresh_token": f"RT-{n}", "expires_in": 28800,
        }).encode())


class TestRequiredModeReadsTheFileBeforeAnActivePost:
    IDENTITY = ("a@example.com", "")

    @pytest.fixture
    def endpoint(self, monkeypatch):
        fake = _TokenAndUsage()
        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", fake)
        return fake

    @pytest.fixture
    def store(self, temp_home, block_real_keychain, endpoint):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        set_setting(s.backup_dir, "updates.check", "false")
        return s

    def _a_in_keychain_and_slot(self, s, keychain, expires_in_s):
        a = creds("AT-A", "RT-A", expires_in_s=expires_in_s)
        keychain.data[ACTIVE_ITEM] = a
        s._write_account_credentials("1", "a@example.com", a)
        return a

    @pytest.mark.parametrize(
        "expires_in_s", [-60, 3600], ids=["expired", "unexpired-but-refused-by-the-server"]
    )
    def test_codex_scenario_auto_does_not_post_the_keychain_predecessor(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch, capsys, expires_in_s
    ):
        """Claude Code refreshed A -> B in the file. keepalive sees B, but its Keychain
        write fails, and then `auto --once` runs on Keychain A."""
        a = self._a_in_keychain_and_slot(store, block_real_keychain, expires_in_s)
        b = creds("AT-B", "RT-B", expires_in_s=28000)
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(b, encoding="utf-8")
        written_last(block_real_keychain, file_path, "file")
        ledger_before = consumed_grants.in_use()

        real_set = block_real_keychain.set_password
        monkeypatch.setattr(macos_keychain, "set_password", _failing_set(None))
        report = run_keepalive(store)
        assert report["ok"] is False and report["error"]["type"] == "keychain_unavailable"
        monkeypatch.setattr(macos_keychain, "set_password", real_set)

        _main(["auto", "--once", "--json"], capsys)

        assert endpoint.posts == []
        fingerprint = oauth.credential_fingerprint(a)
        assert not ledger_before and consumed_grants.entry(fingerprint) is None
        assert file_path.read_text(encoding="utf-8") == b
        assert block_real_keychain.data[ACTIVE_ITEM] == a

    def test_keepalive_then_reconciles_with_no_post_of_the_predecessor(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch, capsys
    ):
        self._a_in_keychain_and_slot(store, block_real_keychain, -60)
        b = creds("AT-B", "RT-B", expires_in_s=28000)
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(b, encoding="utf-8")
        written_last(block_real_keychain, file_path, "file")
        _main(["auto", "--once", "--json"], capsys)
        assert endpoint.posts == []
        report = run_keepalive(ClaudeAccountSwitcher())
        assert report["ok"] is True and report["action"] == "synced-keychain"
        assert block_real_keychain.data[ACTIVE_ITEM] == b
        assert endpoint.posts == []

    @pytest.mark.parametrize("via", ["auto", "keepalive"])
    def test_healthy_path_refreshes_exactly_once(
        self, store, temp_home, block_real_keychain, endpoint, capsys, via
    ):
        a = creds("AT-A", "RT-A", expires_in_s=-60 if via == "auto" else 600)
        block_real_keychain.data[ACTIVE_ITEM] = a
        store._write_account_credentials("1", "a@example.com", a)
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(a, encoding="utf-8")
        if via == "auto":
            _main(["auto", "--once", "--json"], capsys)
        else:
            assert run_keepalive(store)["action"] == "refreshed"
        assert endpoint.posts == ["RT-A"]
        for stored in (block_real_keychain.data[ACTIVE_ITEM], file_path.read_text(encoding="utf-8")):
            assert oauth.extract_access_token(stored) == "AT-1"

    def _post(self, s, credentials, *, identity=None, locks_held=True):
        return s.post_refresh(identity or self.IDENTITY, credentials, locks_held=locks_held)

    @pytest.mark.parametrize(
        "file_content",
        [
            creds("AT-F", "RT-F", expires_in_s=28000),
            creds("AT-F", "RT-F", expires_in_s=100),  # a later expiry here proves nothing
            "not json",
        ],
        ids=["file-newer", "file-older", "file-garbled"],
    )
    def test_a_differing_or_garbled_file_means_no_post(self, store, temp_home, endpoint, file_content):
        (temp_home / ".claude" / ".credentials.json").write_text(file_content, encoding="utf-8")
        outcome = self._post(store, creds("AT-K", "RT-K", expires_in_s=7200))
        assert outcome.credentials is None and outcome.error == "transient"
        assert endpoint.posts == []
        assert consumed_grants.entry(oauth.credential_fingerprint(creds("x", "RT-K"))) is None

    def test_an_unreadable_file_means_no_post(self, store, temp_home, endpoint, monkeypatch):
        path = temp_home / ".claude" / ".credentials.json"
        path.write_text(creds("AT-F", "RT-F"), encoding="utf-8")
        real = Path.read_text

        def denied(self, *a, **kw):
            if self == path:
                raise PermissionError("denied")
            return real(self, *a, **kw)

        monkeypatch.setattr(Path, "read_text", denied)
        assert self._post(store, creds("AT-K", "RT-K")).error == "transient"
        assert endpoint.posts == []

    def test_an_unknown_active_identity_means_no_post(self, store, temp_home, endpoint):
        (temp_home / ".claude.json").write_text("{}", encoding="utf-8")
        assert self._post(store, creds("AT-K", "RT-K")).error == "transient"
        assert endpoint.posts == []

    def test_the_active_login_needs_claude_codes_locks(self, store, endpoint):
        assert self._post(store, creds("AT-K", "RT-K"), locks_held=False).error == "transient"
        assert endpoint.posts == []

    def test_consume_gate_defers_the_active_login(self, store, block_real_keychain, endpoint):
        a = self._a_in_keychain_and_slot(store, block_real_keychain, -60)
        assert store.consume_backup_grant("1", "a@example.com", a).error == "transient"
        assert endpoint.posts == []

    @pytest.mark.parametrize(
        "file_content", [None, "   \n", "same"], ids=["no-file", "blank-file", "same-token"]
    )
    def test_nothing_in_the_file_to_contradict_it_posts(self, store, temp_home, endpoint, file_content):
        candidate = creds("AT-K", "RT-K", expires_in_s=7200)
        if file_content is not None:
            (temp_home / ".claude" / ".credentials.json").write_text(
                creds("AT-other", "RT-K", expires_in_s=100) if file_content == "same" else file_content,
                encoding="utf-8",
            )
        assert self._post(store, candidate).error is None
        assert endpoint.posts == ["RT-K"]

    def test_a_file_copy_spent_here_does_not_block_a_newer_token(self, store, temp_home, endpoint):
        spent = creds("AT-F", "RT-F", expires_in_s=100)
        (temp_home / ".claude" / ".credentials.json").write_text(spent, encoding="utf-8")
        consumed_grants.record(
            oauth.credential_fingerprint(spent), self.IDENTITY, consumed_grants.CONSUMED
        )
        assert self._post(store, creds("AT-K", "RT-K", expires_in_s=7200)).error is None
        assert endpoint.posts == ["RT-K"]

    def test_a_newer_file_copy_spent_here_still_blocks_an_older_token(self, store, temp_home, endpoint):
        spent = creds("AT-F", "RT-F", expires_in_s=28000)
        (temp_home / ".claude" / ".credentials.json").write_text(spent, encoding="utf-8")
        consumed_grants.record(
            oauth.credential_fingerprint(spent), self.IDENTITY, consumed_grants.CONSUMED
        )
        assert self._post(store, creds("AT-K", "RT-K", expires_in_s=7200)).error == "transient"
        assert endpoint.posts == []

    def test_another_accounts_refresh_ignores_the_file(self, store, temp_home, endpoint):
        (temp_home / ".claude" / ".credentials.json").write_text(
            creds("AT-F", "RT-F", expires_in_s=28000), encoding="utf-8"
        )
        stale = creds("AT-b", "RT-b", expires_in_s=-60)
        store._write_account_credentials("2", "b@example.com", stale)
        outcome = store.consume_backup_grant("2", "b@example.com", stale)
        assert outcome.error is None and endpoint.posts == ["RT-b"]

    def test_default_mode_is_unchanged(self, temp_home, block_real_keychain, endpoint):
        s = macos_store(temp_home)
        (temp_home / ".claude" / ".credentials.json").write_text(
            creds("AT-F", "RT-F", expires_in_s=28000), encoding="utf-8"
        )
        assert self._post(s, creds("AT-K", "RT-K"), locks_held=False).error is None
        assert endpoint.posts == ["RT-K"]
