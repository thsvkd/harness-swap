"""Keychain-required mode: the preflight, the refusals, the cached view and the
ban on the plaintext fallback. Default-off behaviour is pinned by the existing
fallback tests (tests/test_switcher.py, tests/test_credentials.py)."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import time
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from claude_swap import cli, consumed_grants, macos_keychain, oauth
from claude_swap import switcher as switcher_module
from claude_swap.autoswitch import AutoSwitchEngine, TickOutcome
from claude_swap.exceptions import (
    ClaudeCodeLockTimeout,
    ClaudeSwitchError,
    CopiesDisagreeError,
    CredentialReadError,
    KeychainUnavailableError,
    ReloginRequiredError,
    RequiredModeUnsupportedError,
    StoresDisagreeError,
    SwitchError,
)
from claude_swap.keepalive import run_keepalive
from claude_swap.session import SessionManager
from claude_swap.transfer import import_accounts
from claude_swap.models import Platform
from claude_swap.settings import (
    SETTING_SPECS,
    AutoSwitchSettings,
    load_credential_settings,
    require_keychain,
    set_setting,
)
from claude_swap.switcher import ClaudeAccountSwitcher
from claude_swap.usage_store import FetchRecord

from .keychain_helpers import ACTIVE_ITEM, FakeSecurity, creds, macos_store, snapshot

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
            ["remove", "2"],
            ["auto", "--once"],
            ["auto"],
            ["keepalive"],
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
        # Not the stash: rule P keeps a replaced copy there, and it is no fallback.
        return [
            *s.credentials_dir.glob(".creds-*.enc*"),
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

    def test_R9_a_later_enc_does_not_win_on_its_expiry(self, store):
        enc = self._seed(store, enc_expires=7200, keychain_expires=100)
        assert self._access(store) == "AT-kc"
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

        # The next pass, on the same path, adopts it into the slot instead of posting
        # again, and leaves the live stores to keepalive, which moves them with no POST.
        monkeypatch.setattr(macos_keychain, "set_password", real_set)
        fresh = ClaudeAccountSwitcher()
        fresh.platform = Platform.MACOS
        fresh._fetch_active_usage("1", "a@example.com", expired, "")
        assert endpoint.posts == ["RT-0"]
        assert block_real_keychain.data[ACTIVE_ITEM] == expired
        assert oauth.extract_access_token(fresh._read_account_credentials("1", "a@example.com")) == "AT-1"
        assert fresh._store._list_unclaimed_credentials() == {}

        assert run_keepalive(fresh)["ok"] is True
        assert endpoint.posts == ["RT-0"]
        assert oauth.extract_access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"

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
        # A login with no slot is the one case that goes straight to the helper.
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "stranger@example.com", "accountUuid": "uuid-9"},
        }), encoding="utf-8")
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
        """Claude Code refreshed A -> B in the file. keepalive refuses to pick a side,
        and then `auto --once` runs on Keychain A anyway."""
        a = self._a_in_keychain_and_slot(store, block_real_keychain, expires_in_s)
        b = creds("AT-B", "RT-B", expires_in_s=28000)
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(b, encoding="utf-8")
        ledger_before = consumed_grants.in_use()

        report = run_keepalive(store)
        assert report["ok"] is False and report["error"]["type"] == "split_brain"

        _main(["auto", "--once", "--json"], capsys)

        assert endpoint.posts == []
        fingerprint = oauth.credential_fingerprint(a)
        assert not ledger_before and consumed_grants.entry(fingerprint) is None
        assert file_path.read_text(encoding="utf-8") == b
        assert block_real_keychain.data[ACTIVE_ITEM] == a

    def test_a_person_then_reconciles_with_no_post_of_the_predecessor(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch, capsys
    ):
        self._a_in_keychain_and_slot(store, block_real_keychain, -60)
        b = creds("AT-B", "RT-B", expires_in_s=28000)
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(b, encoding="utf-8")
        _main(["auto", "--once", "--json"], capsys)
        assert endpoint.posts == []
        assert run_keepalive(ClaudeAccountSwitcher())["error"]["type"] == "split_brain"
        report = run_keepalive(ClaudeAccountSwitcher(), adopt="file")
        assert report["ok"] is True and report["action"] == "adopted"
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
        assert outcome.credentials is None and outcome.error == "stores-disagree"
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
        assert self._post(store, creds("AT-K", "RT-K")).error == "stores-disagree"
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

    def test_a_file_copy_recorded_as_its_predecessor_does_not_block_a_token(
        self, store, temp_home, endpoint
    ):
        spent = creds("AT-F", "RT-F", expires_in_s=100)
        token = creds("AT-K", "RT-K", expires_in_s=7200)
        (temp_home / ".claude" / ".credentials.json").write_text(spent, encoding="utf-8")
        consumed_grants.record(
            oauth.credential_fingerprint(spent), self.IDENTITY, consumed_grants.CONSUMED,
            successor=oauth.credential_fingerprint(token),
        )
        assert self._post(store, token).error is None
        assert endpoint.posts == ["RT-K"]

    def test_a_file_copy_spent_here_with_no_link_blocks_even_a_later_token(
        self, store, temp_home, endpoint
    ):
        spent = creds("AT-F", "RT-F", expires_in_s=100)
        (temp_home / ".claude" / ".credentials.json").write_text(spent, encoding="utf-8")
        consumed_grants.record(
            oauth.credential_fingerprint(spent), self.IDENTITY, consumed_grants.CONSUMED
        )
        assert self._post(store, creds("AT-K", "RT-K", expires_in_s=7200)).error == "stores-disagree"
        assert endpoint.posts == []

    def test_a_newer_file_copy_spent_here_still_blocks_an_older_token(self, store, temp_home, endpoint):
        spent = creds("AT-F", "RT-F", expires_in_s=28000)
        (temp_home / ".claude" / ".credentials.json").write_text(spent, encoding="utf-8")
        consumed_grants.record(
            oauth.credential_fingerprint(spent), self.IDENTITY, consumed_grants.CONSUMED
        )
        assert self._post(store, creds("AT-K", "RT-K", expires_in_s=7200)).error == "stores-disagree"
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


class TestOnlyKeepaliveReconcilesTheActiveStores:
    """Codex round 10's open item: `auto` restored a slot copy over agreeing stores."""

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

    COMMANDS = pytest.mark.parametrize(
        "command",
        [["auto", "--once", "--json"], ["list", "--json"]],
        ids=["auto", "list"],
    )

    def _stores_on_b_and_slot_on_a(self, s, home, keychain, *, b_expires=-60, with_file=True):
        a = creds("AT-A", "RT-A", expires_in_s=28000)
        b = creds("AT-B", "RT-B", expires_in_s=b_expires)
        s._write_account_credentials("1", "a@example.com", a)
        keychain.data[ACTIVE_ITEM] = b
        file_path = home / ".claude" / ".credentials.json"
        if with_file:
            file_path.write_text(b, encoding="utf-8")
        return a, b, file_path

    @COMMANDS
    @pytest.mark.parametrize("with_file", [True, False], ids=["file", "no-file"])
    @pytest.mark.parametrize("b_expires", [-60, 3600], ids=["expired", "refused-by-the-server"])
    def test_a_valid_slot_copy_is_not_restored_or_posted(
        self, store, temp_home, block_real_keychain, endpoint, capsys, command, with_file, b_expires
    ):
        a, b, file_path = self._stores_on_b_and_slot_on_a(
            store, temp_home, block_real_keychain, b_expires=b_expires, with_file=with_file
        )
        for _ in range(2):
            _main(command, capsys)
        assert endpoint.posts == []
        assert block_real_keychain.data[ACTIVE_ITEM] == b
        assert file_path.exists() is with_file
        if with_file:
            assert file_path.read_text(encoding="utf-8") == b
        assert store._read_account_credentials("1", "a@example.com") == a

    @COMMANDS
    def test_keepalive_afterwards_sends_nothing_until_someone_chooses(
        self, store, temp_home, block_real_keychain, endpoint, capsys, command
    ):
        a, _, file_path = self._stores_on_b_and_slot_on_a(store, temp_home, block_real_keychain)
        _main(command, capsys)
        report = run_keepalive(ClaudeAccountSwitcher())
        assert report["error"]["type"] == "split_brain"
        assert endpoint.posts == []

        assert run_keepalive(ClaudeAccountSwitcher(), adopt="file")["action"] == "adopted"
        assert run_keepalive(ClaudeAccountSwitcher())["action"] == "refreshed"
        assert endpoint.posts == ["RT-B"]
        for stored in (block_real_keychain.data[ACTIVE_ITEM], file_path.read_text(encoding="utf-8")):
            assert oauth.extract_access_token(stored) == "AT-1"
        slot = oauth.extract_access_token(store._read_account_credentials("1", "a@example.com"))
        assert slot == "AT-1"
        rows = store._store._list_unclaimed_credentials()
        assert [store._store._read_unclaimed_credential(i)[0] for i in rows] == [a]

    @COMMANDS
    @pytest.mark.parametrize("file_copy", [creds("AT-F", "RT-F", expires_in_s=28000), "not json"], ids=["other-token", "garbled"])
    def test_stores_that_disagree_get_no_write_and_no_post(
        self, store, temp_home, block_real_keychain, endpoint, capsys, command, file_copy
    ):
        a = creds("AT-A", "RT-A", expires_in_s=28000)
        k = creds("AT-K", "RT-K", expires_in_s=-60)
        store._write_account_credentials("1", "a@example.com", a)
        block_real_keychain.data[ACTIVE_ITEM] = k
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(file_copy, encoding="utf-8")
        _main(command, capsys)
        assert endpoint.posts == []
        assert block_real_keychain.data[ACTIVE_ITEM] == k
        assert file_path.read_text(encoding="utf-8") == file_copy
        assert store._read_account_credentials("1", "a@example.com") == a

    def test_a_cleared_keychain_is_not_refilled_from_the_slot(
        self, store, temp_home, block_real_keychain, endpoint, capsys
    ):
        a = creds("AT-A", "RT-A", expires_in_s=28000)
        store._write_account_credentials("1", "a@example.com", a)
        _main(["auto", "--once", "--json"], capsys)
        assert ACTIVE_ITEM not in block_real_keychain.data
        assert endpoint.posts == []

    @COMMANDS
    def test_a_stash_adoption_here_leaves_keepalive_the_evidence(
        self, store, temp_home, block_real_keychain, endpoint, capsys, command
    ):
        """The row is retired here and the stores still hold X, with no ledger row."""
        x = creds("AT-X", "RT-X", expires_in_s=-60)
        y = creds("AT-Y", "RT-Y", expires_in_s=28000)
        store._write_account_credentials("1", "a@example.com", x)
        store.stash_consumed_successor(
            "1", ("a@example.com", ""), y, oauth.credential_fingerprint(x), "keepalive-live-write-failed"
        )
        block_real_keychain.data[ACTIVE_ITEM] = x
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(x, encoding="utf-8")
        _main(command, capsys)
        assert block_real_keychain.data[ACTIVE_ITEM] == x  # keepalive's to move
        report = run_keepalive(ClaudeAccountSwitcher())
        assert report["ok"] is True
        assert endpoint.posts == []
        assert block_real_keychain.data[ACTIVE_ITEM] == y
        assert file_path.read_text(encoding="utf-8") == y

    def _verified_drift(self, s, home, keychain, file_copy):
        a = creds("AT-A", "RT-A", expires_in_s=28000)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        s._write_account_credentials("1", "a@example.com", a)
        keychain.data[ACTIVE_ITEM] = b
        (home / ".claude" / ".credentials.json").write_text(file_copy or b, encoding="utf-8")
        key = s._lineage_key("1", "a@example.com", oauth.credential_fingerprint(b))
        s._probe_verdicts[key] = True
        return a, b

    def test_a_resync_from_agreeing_stores_keeps_the_slot_copy_first(
        self, store, temp_home, block_real_keychain
    ):
        a, b = self._verified_drift(store, temp_home, block_real_keychain, None)
        store._resync_rotated_backup("1", "a@example.com", "", b)
        assert store._read_account_credentials("1", "a@example.com") == b
        rows = store._store._list_unclaimed_credentials()
        assert [store._store._read_unclaimed_credential(i)[0] for i in rows] == [a]
        row = next(iter(rows.values()))
        assert (row["email"], row["organizationUuid"]) == ("a@example.com", "")

    def test_a_stash_that_fails_stops_the_resync(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        a, b = self._verified_drift(store, temp_home, block_real_keychain, None)
        monkeypatch.setattr(
            store._store, "_write_unclaimed_credential",
            lambda *args: (_ for _ in ()).throw(OSError("disk full")),
        )
        store._resync_rotated_backup("1", "a@example.com", "", b)
        assert store._read_account_credentials("1", "a@example.com") == a

    def test_no_resync_while_the_stores_disagree(self, store, temp_home, block_real_keychain):
        a, b = self._verified_drift(
            store, temp_home, block_real_keychain, creds("AT-F", "RT-F", expires_in_s=7200)
        )
        store._resync_rotated_backup("1", "a@example.com", "", b)
        assert store._read_account_credentials("1", "a@example.com") == a
        assert store._store._list_unclaimed_credentials() == {}

    def test_a_rotation_seen_mid_pass_with_the_stores_apart_writes_no_slot(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        a, b = self._verified_drift(
            store, temp_home, block_real_keychain, creds("AT-F", "RT-F", expires_in_s=7200)
        )
        store._fetch_active_usage("1", "a@example.com", creds("AT-old", "RT-old", expires_in_s=-60), "")
        assert store._read_account_credentials("1", "a@example.com") == a
        assert block_real_keychain.data[ACTIVE_ITEM] == b

    def test_a_stash_row_is_not_adopted_while_the_stores_are_apart(
        self, store, temp_home, block_real_keychain, endpoint, capsys
    ):
        x = creds("AT-X", "RT-X", expires_in_s=-60)
        y = creds("AT-Y", "RT-Y", expires_in_s=28000)
        store._write_account_credentials("1", "a@example.com", x)
        store.stash_consumed_successor(
            "1", ("a@example.com", ""), y, oauth.credential_fingerprint(x), "keepalive-live-write-failed"
        )
        block_real_keychain.data[ACTIVE_ITEM] = x
        (temp_home / ".claude" / ".credentials.json").write_text(
            creds("AT-F", "RT-F", expires_in_s=7200), encoding="utf-8"
        )
        _main(["auto", "--once", "--json"], capsys)
        assert store._read_account_credentials("1", "a@example.com") == x
        assert len(store._store._list_unclaimed_credentials()) == 1
        assert endpoint.posts == []

    def test_a_rotation_seen_mid_pass_keeps_the_slot_copy_before_following(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        a, b = self._verified_drift(store, temp_home, block_real_keychain, None)
        store._fetch_active_usage("1", "a@example.com", creds("AT-old", "RT-old", expires_in_s=-60), "")
        assert store._read_account_credentials("1", "a@example.com") == b
        rows = store._store._list_unclaimed_credentials()
        assert [store._store._read_unclaimed_credential(i)[0] for i in rows] == [a]

    def test_default_mode_still_restores_the_slot_copy(
        self, temp_home, block_real_keychain, endpoint, capsys
    ):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "updates.check", "false")
        a, _, _ = self._stores_on_b_and_slot_on_a(s, temp_home, block_real_keychain)
        _main(["auto", "--once", "--json"], capsys)
        assert block_real_keychain.data[ACTIVE_ITEM] == a
        assert endpoint.posts == []


SLOT_2 = ("claude-swap", "account-2-b@example.com")  # to seed a slot with no rule P row
_GATED_ENTRY_POINTS = {
    "switch_to": lambda s: s.switch_to("2", json_output=True),
    "force": lambda s: s.switch_to("1", json_output=True, force=True),
    "add": lambda s: s.add_account(assume_yes=True),
    "remove-inactive": lambda s: s.remove_account("2", assume_yes=True),
    "persist": lambda s: s.persist_backup_credentials(
        "2", "b@example.com", creds("AT-N", "RT-N")
    ),
}


class TestRequiredModeGate:
    """Codex round 11: one gate, under the locks, for every write and POST."""

    A_ID = ("a@example.com", "")
    B_ID = ("b@example.com", "")

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

    def _engine(self, s, events):
        return AutoSwitchEngine(s, AutoSwitchSettings(), events.append)

    def _agreeing(self, s, home, keychain, a=None):
        a = a or creds("AT-A", "RT-A", expires_in_s=28000)
        keychain.data[ACTIVE_ITEM] = a
        s._write_account_credentials("1", "a@example.com", a)
        s._write_account_credentials("2", "b@example.com", creds("AT-2", "RT-2", expires_in_s=28000))
        file_path = home / ".claude" / ".credentials.json"
        file_path.write_text(a, encoding="utf-8")
        return a, file_path

    def _disagreeing(self, s, home, keychain):
        a, file_path = self._agreeing(s, home, keychain)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        file_path.write_text(b, encoding="utf-8")
        return a, b, file_path

    # Round 11, finding 1.

    def test_a_refresh_landing_before_the_locks_stops_the_auto_switch(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch, capsys
    ):
        """No check before the locks can see this one: Claude Code refreshes the file
        A -> B just as the switch reaches for them."""
        a, file_path = self._agreeing(store, temp_home, block_real_keychain)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        slot_2 = store._read_account_credentials("2", "b@example.com")
        real_lock = switcher_module.claude_credentials_lock

        def refreshed_first(*args, **kwargs):
            file_path.write_text(b, encoding="utf-8")
            return real_lock(*args, **kwargs)

        monkeypatch.setattr(switcher_module, "claude_credentials_lock", refreshed_first)
        events = []
        outcome = self._engine(store, events)._perform(
            "2", "b@example.com", "failover", (None, float("inf"))
        )
        monkeypatch.setattr(switcher_module, "claude_credentials_lock", real_lock)
        assert outcome == TickOutcome.NO_ACTION
        assert [event.reason for event in events] == ["stores-disagree"]
        assert file_path.read_text(encoding="utf-8") == b
        assert block_real_keychain.data[ACTIVE_ITEM] == a
        assert store._read_account_credentials("1", "a@example.com") == a
        assert store._read_account_credentials("2", "b@example.com") == slot_2
        assert store._get_sequence_data()["activeAccountNumber"] == 1

        # Nor does anything later send the predecessor.
        _main(["auto", "--once", "--json"], capsys)
        assert store.consume_backup_grant("1", "a@example.com", a).credentials is None
        assert run_keepalive(ClaudeAccountSwitcher(), ahead=40000)["error"]["type"] == "split_brain"
        assert endpoint.posts == []
        assert file_path.read_text(encoding="utf-8") == b

    def test_a_manual_switch_refuses_and_writes_nothing(
        self, store, temp_home, block_real_keychain, endpoint, capsys
    ):
        self._disagreeing(store, temp_home, block_real_keychain)
        before = snapshot(temp_home, block_real_keychain)
        code, out, _ = _main(["--switch-to", "2", "--json"], capsys)
        assert code == 1
        assert json.loads(out)["error"]["type"] == "stores_disagree"
        assert snapshot(temp_home, block_real_keychain) == before
        assert endpoint.posts == []

    # Round 11, finding 2.

    def _exited_session(self, s, copy):
        session_dir = s._session_dir("2", "b@example.com")
        session_dir.mkdir(parents=True, exist_ok=True)
        path = session_dir / ".credentials.json"
        path.write_text(copy, encoding="utf-8")
        return path

    @pytest.mark.parametrize("session_expires", [300, 600, 1200], ids=["earlier", "equal", "later"])
    def test_an_exited_sessions_successor_stops_the_slot_post_whatever_its_expiry(
        self, store, temp_home, block_real_keychain, endpoint, session_expires
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        a = creds("AT-OLD", "RT-OLD", expires_in_s=600)
        block_real_keychain.data[SLOT_2] = a
        b = creds("AT-S", "RT-S", expires_in_s=session_expires)
        path = self._exited_session(store, b)

        outcome = store.consume_backup_grant("2", "b@example.com", a)
        assert outcome.credentials is None and outcome.error == "relogin_required"
        assert self._engine(store, [])._freshen_target("2", "b@example.com") == "invalid_grant"
        assert endpoint.posts == []
        assert path.read_text(encoding="utf-8") == b
        assert store._read_account_credentials("2", "b@example.com") == a

    def test_a_session_on_the_same_token_lets_the_post_through(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        a = creds("AT-OLD", "RT-OLD", expires_in_s=600)
        block_real_keychain.data[SLOT_2] = a
        self._exited_session(store, creds("AT-other", "RT-OLD", expires_in_s=300))
        assert store.consume_backup_grant("2", "b@example.com", a).error is None
        assert endpoint.posts == ["RT-OLD"]

    def test_a_session_recorded_as_the_predecessor_lets_the_post_through(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        older = creds("AT-P", "RT-P", expires_in_s=9000)
        a = creds("AT-OLD", "RT-OLD", expires_in_s=600)
        block_real_keychain.data[SLOT_2] = a
        self._exited_session(store, older)
        consumed_grants.record(
            oauth.credential_fingerprint(older), self.B_ID, consumed_grants.CONSUMED,
            successor=oauth.credential_fingerprint(a),
        )
        assert store.consume_backup_grant("2", "b@example.com", a).error is None
        assert endpoint.posts == ["RT-OLD"]

    @pytest.mark.parametrize("state", ["consumed", "reserved"])
    def test_a_token_on_the_ledger_is_refused_before_the_post(
        self, store, temp_home, block_real_keychain, endpoint, state
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        a = creds("AT-OLD", "RT-OLD", expires_in_s=600)
        block_real_keychain.data[SLOT_2] = a
        consumed_grants.record(oauth.credential_fingerprint(a), self.B_ID, state)
        assert store.consume_backup_grant("2", "b@example.com", a).error == "relogin_required"
        assert endpoint.posts == []

    def test_a_stashed_rival_stops_the_slot_post_and_a_linked_one_does_not(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        a = creds("AT-OLD", "RT-OLD", expires_in_s=600)
        rival = creds("AT-R", "RT-R", expires_in_s=9000)
        block_real_keychain.data[SLOT_2] = a
        store._store._write_unclaimed_credential(rival, {
            "reason": "keepalive-split-brain", "configSlot": "2",
            "email": "b@example.com", "organizationUuid": "",
            "fingerprint": oauth.credential_fingerprint(rival),
        })
        assert store.consume_backup_grant("2", "b@example.com", a).error == "relogin_required"
        assert endpoint.posts == []
        consumed_grants.record(
            oauth.credential_fingerprint(rival), self.B_ID, consumed_grants.CONSUMED,
            successor=oauth.credential_fingerprint(a),
        )
        assert store.consume_backup_grant("2", "b@example.com", a).error is None
        assert endpoint.posts == ["RT-OLD"]

    def test_a_differing_leftover_enc_is_a_rival(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        a = creds("AT-OLD", "RT-OLD", expires_in_s=600)
        block_real_keychain.data[SLOT_2] = a
        store._store._write_backup_enc(
            "2", "b@example.com", creds("AT-E", "RT-E", expires_in_s=100)
        )
        assert store.consume_backup_grant("2", "b@example.com", a).error == "relogin_required"
        assert endpoint.posts == []

    def test_switching_to_a_slot_a_session_has_moved_past_is_refused(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch
    ):
        """Activating it would make the stores agree on a spent token."""
        self._agreeing(store, temp_home, block_real_keychain)
        path = self._exited_session(store, creds("AT-S", "RT-S", expires_in_s=7200))
        before = snapshot(temp_home, block_real_keychain)
        with pytest.raises(ReloginRequiredError):
            store.switch_to("2", json_output=True)
        assert snapshot(temp_home, block_real_keychain) == before
        assert path.exists()

    def test_no_expiry_decides_which_slot_copy_is_read(self, store):
        store._write_account_credentials("2", "b@example.com", creds("AT-K", "RT-K", expires_in_s=100))
        store._store._write_backup_enc("2", "b@example.com", creds("AT-E", "RT-E", expires_in_s=9000))
        read = oauth.extract_access_token(store._read_account_credentials("2", "b@example.com"))
        assert read == "AT-K"

    def test_two_recorded_successors_of_one_token_defer(self, store, temp_home, block_real_keychain):
        x = creds("AT-X", "RT-X")
        x_fp = oauth.credential_fingerprint(x)
        y = creds("AT-Y", "RT-Y")
        y_fp = oauth.credential_fingerprint(y)
        for value in (creds("AT-1", "RT-1"), creds("AT-2", "RT-2")):
            store.stash_consumed_successor("1", self.A_ID, value, y_fp, "keepalive-live-write-failed")
        manifest = store._store._read_stash_manifest()
        with pytest.raises(CredentialReadError):
            store.stash_chain_terminal(manifest, lambda row: True, "start", y, x_fp)

    # Every entry point, with the stores apart.

    @pytest.mark.parametrize("entry", sorted(_GATED_ENTRY_POINTS))
    def test_every_entry_point_refuses_and_writes_nothing(
        self, store, temp_home, block_real_keychain, endpoint, entry
    ):
        self._disagreeing(store, temp_home, block_real_keychain)
        before = snapshot(temp_home, block_real_keychain)
        with pytest.raises(StoresDisagreeError):
            _GATED_ENTRY_POINTS[entry](store)
        assert snapshot(temp_home, block_real_keychain) == before
        assert endpoint.posts == []

    @pytest.mark.parametrize("name", ["fetch", "resync", "gate", "gate-held"])
    def test_the_never_raising_paths_refuse_and_write_nothing(
        self, store, temp_home, block_real_keychain, endpoint, name
    ):
        a, _, _ = self._disagreeing(store, temp_home, block_real_keychain)
        before = snapshot(temp_home, block_real_keychain)
        if name == "fetch":
            store._fetch_active_usage("1", "a@example.com", creds("AT-old", "RT-old", expires_in_s=-60), "")
        elif name == "resync":
            key = store._lineage_key("1", "a@example.com", oauth.credential_fingerprint(a))
            store._probe_verdicts[key] = True
            store._resync_rotated_backup("1", "a@example.com", "", a)
        else:
            outcome = (
                store.consume_backup_grant("2", "b@example.com", a)
                if name == "gate"
                else store._consume_backup_grant_locked("2", "b@example.com", a, global_lock_held=True)
            )
            assert outcome.error == "stores-disagree"
        assert snapshot(temp_home, block_real_keychain) == before
        assert endpoint.posts == []

    def test_adopt_alone_passes_a_disagreement(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        _, b, _ = self._disagreeing(store, temp_home, block_real_keychain)
        report = run_keepalive(ClaudeAccountSwitcher(), adopt="file")
        assert report["ok"] is True and report["action"] == "adopted"
        assert block_real_keychain.data[ACTIVE_ITEM] == b

    def test_an_unreadable_file_counts_as_a_disagreement(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        _, file_path = self._agreeing(store, temp_home, block_real_keychain)
        real = Path.read_text

        def denied(self, *a, **kw):
            if self == file_path:
                raise PermissionError("denied")
            return real(self, *a, **kw)

        monkeypatch.setattr(Path, "read_text", denied)
        with pytest.raises(StoresDisagreeError):
            store._required_mode_gate()

    def test_the_gate_holds_the_locks_it_asks_for(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        held = []
        real_lock = switcher_module.claude_credentials_lock
        real_gate = ClaudeAccountSwitcher._required_mode_gate

        class Spy:
            def __enter__(self):
                held.append("claude")
                self.inner = real_lock()
                return self.inner.__enter__()

            def __exit__(self, *exc):
                held.remove("claude")
                return self.inner.__exit__(*exc)

        calls = []

        def gate(self, *a, **kw):
            calls.append("claude" in held)  # the callers' own handlers would swallow an assert
            return real_gate(self, *a, **kw)

        monkeypatch.setattr(switcher_module, "claude_credentials_lock", Spy)
        monkeypatch.setattr(ClaudeAccountSwitcher, "_required_mode_gate", gate)
        store.consume_backup_grant(
            "2", "b@example.com", store._read_account_credentials("2", "b@example.com")
        )
        store.add_account(assume_yes=True)
        assert calls and all(calls)

    def test_a_switch_to_an_empty_slot_is_still_refused_as_a_disagreement(
        self, store, temp_home, block_real_keychain
    ):
        self._disagreeing(store, temp_home, block_real_keychain)
        store._delete_account_credentials("2", "b@example.com")
        with pytest.raises(StoresDisagreeError):
            store.switch_to("2", json_output=True)

    def test_a_stash_row_is_not_adopted_by_the_consume_gate_with_the_stores_apart(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._disagreeing(store, temp_home, block_real_keychain)
        x = store._read_account_credentials("2", "b@example.com")
        y = creds("AT-Y", "RT-Y", expires_in_s=28000)
        store.stash_consumed_successor(
            "2", self.B_ID, y, oauth.credential_fingerprint(x), "keepalive-live-write-failed"
        )
        assert store.consume_backup_grant("2", "b@example.com", x).error == "stores-disagree"
        assert store._read_account_credentials("2", "b@example.com") == x
        assert len(store._store._list_unclaimed_credentials()) == 1

    def test_a_live_session_on_another_token_refuses_the_switch_whatever_its_expiry(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        self._agreeing(store, temp_home, block_real_keychain)
        self._exited_session(store, creds("AT-S", "RT-S", expires_in_s=60))
        monkeypatch.setattr(
            "claude_swap.session.scan_live_sessions",
            lambda path: ([SimpleNamespace(pid=4242)], 0),
        )
        with pytest.raises(SwitchError, match="rotated past"):
            store.switch_to("2", json_output=True)

    def test_adopt_clears_earlier_rivals_for_the_chosen_login(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._disagreeing(store, temp_home, block_real_keychain)
        rival = creds("AT-R", "RT-R", expires_in_s=9000)
        store._store._write_unclaimed_credential(rival, {
            "reason": "keepalive-split-brain", "configSlot": "1",
            "email": "a@example.com", "organizationUuid": "",
            "fingerprint": oauth.credential_fingerprint(rival),
        })
        assert run_keepalive(ClaudeAccountSwitcher(), adopt="file")["ok"] is True
        fresh = ClaudeAccountSwitcher()
        fresh.platform = Platform.MACOS
        fresh.switch_to("2", json_output=True)
        left = fresh._read_account_credentials("1", "a@example.com")
        assert oauth.extract_access_token(left) == "AT-B"
        assert fresh.consume_backup_grant("1", "a@example.com", left).error is None
        assert endpoint.posts == ["RT-B"]

    # Healthy paths.

    def test_a_healthy_auto_switch_works_and_each_due_token_goes_once(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        _, file_path = self._agreeing(store, temp_home, block_real_keychain)
        slot_2 = creds("AT-2", "RT-2", expires_in_s=7200)
        store._write_account_credentials("2", "b@example.com", slot_2)
        events = []
        outcome = self._engine(store, events)._perform(
            "2", "b@example.com", "failover", (None, float("inf"))
        )
        assert outcome == TickOutcome.SWITCHED
        assert oauth.extract_access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-2"
        assert oauth.extract_access_token(file_path.read_text(encoding="utf-8")) == "AT-2"
        assert endpoint.posts == []

        # The new active comes due, and the one left behind later comes due too.
        for _ in range(2):
            run_keepalive(ClaudeAccountSwitcher(), ahead=7300)
        assert endpoint.posts == ["RT-2"]
        left = store._read_account_credentials("1", "a@example.com")
        assert oauth.extract_access_token(left) == "AT-A"
        fresh = ClaudeAccountSwitcher()
        fresh.platform = Platform.MACOS
        assert fresh.consume_backup_grant("1", "a@example.com", left).error is None
        assert endpoint.posts == ["RT-2", "RT-A"]

    def test_a_login_rotated_while_active_stays_refreshable_after_the_switch(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        """The outgoing backup replaces the slot's older copy, and records it as the
        predecessor: otherwise the kept copy would read as a rival for good."""
        old = creds("AT-OLD", "RT-OLD", expires_in_s=7200)
        a, _ = self._agreeing(store, temp_home, block_real_keychain, a=creds("AT-A", "RT-A", expires_in_s=28000))
        block_real_keychain.data[("claude-swap", "account-1-a@example.com")] = old
        store.switch_to("2", json_output=True)
        assert store._read_account_credentials("1", "a@example.com") == a
        rows = store._store._list_unclaimed_credentials()
        assert [store._store._read_unclaimed_credential(i)[0] for i in rows] == [old]
        assert store.consume_backup_grant("1", "a@example.com", a).error is None
        assert endpoint.posts == ["RT-A"]

    def test_a_new_login_clears_every_earlier_rival(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        rival = creds("AT-R", "RT-R", expires_in_s=9000)
        store._store._write_unclaimed_credential(rival, {
            "reason": "keepalive-split-brain", "configSlot": "1",
            "email": "a@example.com", "organizationUuid": "",
            "fingerprint": oauth.credential_fingerprint(rival),
        })
        a, _ = self._agreeing(store, temp_home, block_real_keychain)
        store.add_account(assume_yes=True)
        store.switch_to("2", json_output=True)
        assert store.consume_backup_grant("1", "a@example.com", a).error is None
        assert endpoint.posts == ["RT-A"]

    def test_default_mode_takes_no_gate_and_no_extra_lock(
        self, temp_home, block_real_keychain, endpoint
    ):
        s = macos_store(temp_home)
        a = creds("AT-A", "RT-A", expires_in_s=28000)
        block_real_keychain.data[ACTIVE_ITEM] = a
        s._write_account_credentials("1", "a@example.com", a)
        s._write_account_credentials("2", "b@example.com", creds("AT-2", "RT-2", expires_in_s=7200))
        (temp_home / ".claude" / ".credentials.json").write_text(
            creds("AT-B", "RT-B"), encoding="utf-8"
        )
        s._required_mode_gate()  # returns at once with the stores apart
        s.switch_to("2", json_output=True)
        assert oauth.extract_access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-2"


class _RequiredModeStore:
    A_ID = ("a@example.com", "")

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

    def _seed(self, s, home, keychain):
        """Every kind of store holds something: stores, slots, stash, ledger, session."""
        a = creds("AT-A", "RT-A", expires_in_s=28000)
        keychain.data[ACTIVE_ITEM] = a
        s._write_account_credentials("1", "a@example.com", a)
        s._write_account_credentials("2", "b@example.com", creds("AT-2", "RT-2", expires_in_s=28000))
        file_path = home / ".claude" / ".credentials.json"
        file_path.write_text(a, encoding="utf-8")
        entry = s._store._write_unclaimed_credential(creds("AT-X", "RT-X"), {
            "reason": "test", "email": "z@example.com", "organizationUuid": "",
        })
        consumed_grants.record(
            oauth.credential_fingerprint(creds("x", "RT-L")), self.A_ID, consumed_grants.CONSUMED
        )
        session_dir = s._session_dir("2", "b@example.com")
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / ".credentials.json").write_text(creds("AT-2", "RT-2"), encoding="utf-8")
        return a, file_path, entry


# The UIs call the switcher directly, past the CLI's check.
_DIRECT_REFUSALS = {
    "add-token": lambda s, h: s.add_account_from_token("sk-ant-oat01-TOKEN", assume_yes=True),
    "remove-active": lambda s, h: s.remove_account("1", assume_yes=True),
    "swap": lambda s, h: s.swap_accounts("1", "2"),
    "move": lambda s, h: s.move_account("2", "5"),
    "purge": lambda s, h: s.purge(),
    "import": lambda s, h: import_accounts(s, str(h / "import.json")),
    "run": lambda s, h: SessionManager(s).run("2", []),
    "setup-session": lambda s, h: SessionManager(s).setup_session("2", False),
}


class TestRequiredModeRefusesTheRest(_RequiredModeStore):
    """Codex round 12: the commands the Mac mini does not use are refused, first thing."""

    COMMANDS = pytest.mark.parametrize(
        "argv",
        [
            ["run", "2"],
            ["add-token", "sk-ant-oat01-TOKEN"],
            ["import", "IMPORT_FILE"],
            ["move", "2", "5"],
            ["swap", "1", "2"],
            ["purge"],
            ["unclaimed", "--purge", "ENTRY"],
        ],
        ids=lambda argv: " ".join(argv[:2]) if argv[0] == "unclaimed" else argv[0],
    )

    def _argv(self, argv, home, entry):
        (home / "import.json").write_text("{}", encoding="utf-8")
        return [
            {"IMPORT_FILE": str(home / "import.json"), "ENTRY": entry}.get(arg, arg) for arg in argv
        ]

    def _assert_refused(self, code, err):
        assert code == 1
        for needle in ("required_mode_unsupported", "credentials.requireKeychain", "/login", "hswap claude add"):
            assert needle in err

    @COMMANDS
    def test_a_refused_command_changes_nothing_and_does_not_start_up(
        self, store, temp_home, block_real_keychain, endpoint, capsys, monkeypatch, argv
    ):
        _, _, entry = self._seed(store, temp_home, block_real_keychain)
        argv = self._argv(argv, temp_home, entry)
        monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("no prompt comes first"))
        monkeypatch.setattr(
            cli, "ClaudeAccountSwitcher", lambda **kw: pytest.fail("refused after starting up")
        )
        before = snapshot(temp_home, block_real_keychain)
        code, _, err = _main(argv, capsys)
        self._assert_refused(code, err)
        assert snapshot(temp_home, block_real_keychain) == before
        assert endpoint.posts == []

    @COMMANDS
    def test_the_environment_alone_also_refuses(
        self, temp_home, block_real_keychain, capsys, monkeypatch, argv
    ):
        s = macos_store(temp_home)
        _, _, entry = self._seed(s, temp_home, block_real_keychain)
        argv = self._argv(argv, temp_home, entry)
        monkeypatch.setenv("HSWAP_REQUIRE_KEYCHAIN", "1")
        before = snapshot(temp_home, block_real_keychain)
        code, _, err = _main(argv, capsys)
        self._assert_refused(code, err)
        assert snapshot(temp_home, block_real_keychain) == before

    def test_removing_the_active_account_is_refused(
        self, store, temp_home, block_real_keychain, capsys, monkeypatch
    ):
        self._seed(store, temp_home, block_real_keychain)
        monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("no prompt comes first"))
        before = snapshot(temp_home, block_real_keychain)
        code, _, err = _main(["remove", "1"], capsys)
        self._assert_refused(code, err)
        assert snapshot(temp_home, block_real_keychain) == before

    def test_the_active_account_counts_by_the_login_too(
        self, store, temp_home, block_real_keychain
    ):
        """The sequence file can lag the login, and either says it is active."""
        self._seed(store, temp_home, block_real_keychain)
        data = store._get_sequence_data()
        data["activeAccountNumber"] = 2
        store._write_json(store.sequence_file, data)
        before = snapshot(temp_home, block_real_keychain)
        with pytest.raises(RequiredModeUnsupportedError):
            store.remove_account("1", assume_yes=True)
        assert snapshot(temp_home, block_real_keychain) == before

    @pytest.mark.parametrize("name", sorted(_DIRECT_REFUSALS))
    def test_a_direct_call_is_refused_too(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch, name
    ):
        self._seed(store, temp_home, block_real_keychain)
        (temp_home / "import.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("no prompt comes first"))
        monkeypatch.setattr("claude_swap.session.shutil.which", lambda name: None)
        before = snapshot(temp_home, block_real_keychain)
        with pytest.raises(RequiredModeUnsupportedError) as caught:
            _DIRECT_REFUSALS[name](store, temp_home)
        assert caught.value.json_type == "required_mode_unsupported"
        assert snapshot(temp_home, block_real_keychain) == before
        assert endpoint.posts == []

    def test_a_pinned_keepalive_process_is_refused_too(
        self, temp_home, block_real_keychain, endpoint
    ):
        """keepalive pins required mode on a store with the setting off."""
        s = macos_store(temp_home)
        s._store.pin_keychain()
        with pytest.raises(RequiredModeUnsupportedError):
            s.swap_accounts("1", "2")

    # What stays allowed.

    @pytest.mark.parametrize(
        "argv", [["list", "--json"], ["status", "--json"], ["config", "list"], ["unclaimed"]],
        ids=" ".join,
    )
    def test_the_supported_views_still_run(
        self, store, temp_home, block_real_keychain, capsys, argv
    ):
        self._seed(store, temp_home, block_real_keychain)
        code, _, err = _main(argv, capsys)
        assert code == 0 and "required_mode_unsupported" not in err

    def test_removing_an_inactive_slot_still_works_and_keeps_the_login(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        a, _, _ = self._seed(store, temp_home, block_real_keychain)
        store.remove_account("2", assume_yes=True)
        assert store._read_account_credentials("2", "b@example.com") == ""
        assert block_real_keychain.data[ACTIVE_ITEM] == a

    def test_add_from_the_live_login_still_works(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        self._seed(store, temp_home, block_real_keychain)
        b = creds("AT-new", "RT-new", expires_in_s=28000)
        block_real_keychain.data[ACTIVE_ITEM] = b
        (temp_home / ".claude" / ".credentials.json").write_text(b, encoding="utf-8")
        monkeypatch.setattr("claude_swap.oauth.fetch_oauth_profile", lambda token: {
            "email": "a@example.com", "uuid": "uuid-1", "organizationUuid": "",
        })
        store.add_account(assume_yes=True)
        assert store._read_account_credentials("1", "a@example.com") == b

    # Default mode, Linux and Windows.

    def test_default_mode_runs_them(self, temp_home, block_real_keychain, capsys):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "updates.check", "false")
        s._write_account_credentials("1", "a@example.com", creds("AT-A", "RT-A"))
        s._write_account_credentials("2", "b@example.com", creds("AT-2", "RT-2"))
        code, _, err = _main(["swap", "1", "2"], capsys)
        assert code == 0 and "required_mode_unsupported" not in err

    def test_other_platforms_never_refuse(self, temp_home, monkeypatch):
        monkeypatch.setenv("HSWAP_REQUIRE_KEYCHAIN", "1")
        with patch("claude_swap.models.Platform.detect", return_value=Platform.LINUX):
            cli._refuse_in_required_mode("swap")


class TestConsumeHoldsTheLocksThroughThePost(_RequiredModeStore):
    """Codex round 12, finding 1."""

    def _inactive_due(self, s, home, keychain):
        a = creds("AT-K", "RT-K", expires_in_s=28000)
        keychain.data[ACTIVE_ITEM] = a
        s._write_account_credentials("1", "a@example.com", a)
        due = creds("AT-2", "RT-2", expires_in_s=60)
        s._write_account_credentials("2", "b@example.com", due)
        file_path = home / ".claude" / ".credentials.json"
        file_path.write_text(a, encoding="utf-8")
        return a, due, file_path

    def test_a_switch_reaching_for_the_locks_waits_out_the_post(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch
    ):
        """A switch starting at the moment of the POST cannot activate the candidate until
        the successor is in the slot, so it activates the successor, not the predecessor."""
        _, due, _ = self._inactive_due(store, temp_home, block_real_keychain)
        results = {}
        other = ClaudeAccountSwitcher()
        other.platform = Platform.MACOS

        def switch():
            results["switched"] = other.switch_to("2", json_output=True)

        thread = threading.Thread(target=switch)
        real_post = oauth.try_refresh_oauth_credentials

        def post_while_switching(*args, **kwargs):
            thread.start()
            thread.join(0.5)
            results["blocked_during_post"] = thread.is_alive()
            return real_post(*args, **kwargs)

        monkeypatch.setattr(oauth, "try_refresh_oauth_credentials", post_while_switching)
        outcome = store.consume_backup_grant("2", "b@example.com", due)
        thread.join(30)
        assert outcome.error is None
        assert results["blocked_during_post"] is True
        assert endpoint.posts == ["RT-2"]
        assert results["switched"]["switched"] is True
        stored = oauth.extract_oauth_data(block_real_keychain.data[ACTIVE_ITEM])
        assert stored["refreshToken"] != "RT-2"
        assert oauth.extract_oauth_data(
            store._read_account_credentials("2", "b@example.com")
        )["refreshToken"] != "RT-2"

    def test_codex_interleaving_a_switch_and_a_refresh_before_the_locks_post_nothing(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch
    ):
        """The helper saw another account active; a switch activates the candidate, and
        Claude refreshes it in the file, all before this consume holds the locks."""
        _, due, file_path = self._inactive_due(store, temp_home, block_real_keychain)
        successor = creds("AT-B", "RT-B", expires_in_s=7200)
        armed = [True]
        real_file_lock = switcher_module.FileLock

        class SwitchLandsBeforeTheGlobalLock(real_file_lock):
            def __enter__(self):
                if armed[0] and self.lock_path == store.lock_file:
                    armed[0] = False
                    monkeypatch.setattr(switcher_module, "FileLock", real_file_lock)
                    other = ClaudeAccountSwitcher()
                    other.platform = Platform.MACOS
                    other.switch_to("2", json_output=True)
                    file_path.write_text(successor, encoding="utf-8")
                return super().__enter__()

        monkeypatch.setattr(switcher_module, "FileLock", SwitchLandsBeforeTheGlobalLock)
        outcome = store.consume_backup_grant("2", "b@example.com", due)
        assert armed[0] is False
        assert outcome.credentials is None
        assert endpoint.posts == []
        assert file_path.read_text(encoding="utf-8") == successor

        # Nothing later sends it either: the stores disagree until someone decides.
        assert run_keepalive(ClaudeAccountSwitcher(), ahead=40000)["error"]["type"] == "split_brain"
        assert endpoint.posts == []

    def test_an_account_that_became_active_is_not_posted_even_with_the_stores_agreeing(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        """This path writes only the slot, so the stores would keep the spent token."""
        a = creds("AT-A", "RT-A", expires_in_s=60)
        block_real_keychain.data[ACTIVE_ITEM] = a
        store._write_account_credentials("1", "a@example.com", a)
        (temp_home / ".claude" / ".credentials.json").write_text(a, encoding="utf-8")
        assert store.consume_backup_grant("1", "a@example.com", a).credentials is None
        assert endpoint.posts == []

    def test_locks_it_cannot_take_defer_with_no_post(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch
    ):
        _, due, _ = self._inactive_due(store, temp_home, block_real_keychain)

        def held_elsewhere(*args, **kwargs):
            raise ClaudeCodeLockTimeout("held")

        monkeypatch.setattr(switcher_module, "claude_credentials_lock", held_elsewhere)
        outcome = store.consume_backup_grant("2", "b@example.com", due)
        assert outcome.error == "transient" and endpoint.posts == []

    def test_an_inactive_refresh_still_goes_once_and_persists(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        _, due, _ = self._inactive_due(store, temp_home, block_real_keychain)
        outcome = store.consume_backup_grant("2", "b@example.com", due)
        assert outcome.error is None and endpoint.posts == ["RT-2"]
        assert store.consume_backup_grant(
            "2", "b@example.com", store._read_account_credentials("2", "b@example.com")
        ).error is None
        assert endpoint.posts[0] == "RT-2" and "RT-2" not in endpoint.posts[1:]


class TestRulesUAndP(_RequiredModeStore):
    """Codex round 13. U: the active login goes only if every copy agrees or is proven
    older. P: a copy is kept and read back before it is replaced or deleted."""

    SLOT_1 = ("claude-swap", "account-1-a@example.com")

    def _active(self, s, home, keychain, *, expires=600, slot=None, enc=None, session=None):
        x = creds("AT-X", "RT-X", expires_in_s=expires)
        keychain.data[ACTIVE_ITEM] = x
        keychain.data[self.SLOT_1] = slot or x
        file_path = home / ".claude" / ".credentials.json"
        file_path.write_text(x, encoding="utf-8")
        if enc:
            s._store._write_backup_enc("1", "a@example.com", enc)
        session_path = None
        if session:
            session_dir = s._session_dir("1", "a@example.com")
            session_dir.mkdir(parents=True, exist_ok=True)
            session_path = session_dir / ".credentials.json"
            session_path.write_text(session, encoding="utf-8")
        return x, file_path, session_path

    def _stashed(self, s):
        rows = s._store._list_unclaimed_credentials()
        return {s._store._read_unclaimed_credential(i)[0]: row for i, row in rows.items()}

    def _enc(self, s):
        return s._store._backup_enc_path("1", "a@example.com")

    # Round 13, finding 1.

    def test_a_slot_differing_only_in_metadata_writes_nothing_before_rule_u(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        """The write this used to do before the gate deleted the session's B."""
        slot = creds("AT-other", "RT-X", expires_in_s=600)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        _, _, session_path = self._active(
            store, temp_home, block_real_keychain, slot=slot, session=b
        )
        before = snapshot(temp_home, block_real_keychain)
        report = run_keepalive(ClaudeAccountSwitcher())
        assert report["ok"] is False and report["error"]["type"] == "split_brain"
        assert endpoint.posts == []
        assert session_path.read_text(encoding="utf-8") == b
        assert snapshot(temp_home, block_real_keychain) == before

    def test_a_slot_on_another_token_cannot_take_the_direct_branch(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        slot = creds("AT-S", "RT-S", expires_in_s=9000)
        self._active(store, temp_home, block_real_keychain, slot=slot)
        before = snapshot(temp_home, block_real_keychain)
        report = run_keepalive(ClaudeAccountSwitcher())
        assert report["error"]["type"] == "split_brain"
        assert endpoint.posts == []
        assert snapshot(temp_home, block_real_keychain) == before

    def test_the_post_helper_itself_applies_rule_u(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        x, _, _ = self._active(store, temp_home, block_real_keychain, slot=creds("AT-S", "RT-S"))
        outcome = store.post_refresh(self.A_ID, x, locks_held=True)
        assert outcome.error == "stores-disagree" and endpoint.posts == []

    # Round 13, finding 2.

    def test_a_resync_keeps_the_leftover_enc_before_deleting_it(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        slot = creds("AT-S", "RT-S", expires_in_s=9000)
        enc = creds("AT-E", "RT-E", expires_in_s=9000)
        x, _, _ = self._active(
            store, temp_home, block_real_keychain, expires=7200, slot=slot, enc=enc
        )
        assert run_keepalive(ClaudeAccountSwitcher())["ok"] is True
        assert block_real_keychain.data[self.SLOT_1] == x
        assert not self._enc(store).exists()
        kept = self._stashed(store)
        assert slot in kept and enc in kept
        assert (kept[enc]["email"], kept[enc]["organizationUuid"]) == self.A_ID
        assert endpoint.posts == []

        # It may still be live, so the next due run stops rather than guess.
        report = run_keepalive(ClaudeAccountSwitcher(), ahead=7300)
        assert report["error"]["type"] == "split_brain"
        assert endpoint.posts == []

    @pytest.mark.parametrize("failure", ["write", "read-back"])
    def test_a_stash_that_fails_stops_the_replacement(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch, failure
    ):
        slot = creds("AT-S", "RT-S", expires_in_s=9000)
        enc = creds("AT-E", "RT-E", expires_in_s=9000)
        self._active(store, temp_home, block_real_keychain, expires=7200, slot=slot, enc=enc)
        enc_bytes = self._enc(store).read_bytes()
        if failure == "write":
            monkeypatch.setattr(
                store._store, "_write_unclaimed_credential",
                lambda *a: (_ for _ in ()).throw(OSError("disk full")),
            )
        else:
            real = store._store._write_unclaimed_credential
            monkeypatch.setattr(store._store, "_write_unclaimed_credential", real)
            monkeypatch.setattr(store._store, "_read_unclaimed_credential", lambda i: ("", False))
        key = store._lineage_key("1", "a@example.com", oauth.credential_fingerprint(
            block_real_keychain.data[ACTIVE_ITEM]
        ))
        store._probe_verdicts[key] = True
        store._resync_rotated_backup("1", "a@example.com", "", block_real_keychain.data[ACTIVE_ITEM])
        assert block_real_keychain.data[self.SLOT_1] == slot
        assert self._enc(store).read_bytes() == enc_bytes

    # A leftover .enc on the active account: what the Mac mini's slots hold.

    def test_a_differing_enc_blocks_the_post_and_stays(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        enc = creds("AT-E", "RT-E", expires_in_s=100)
        self._active(store, temp_home, block_real_keychain, enc=enc)
        before = snapshot(temp_home, block_real_keychain)
        report = run_keepalive(ClaudeAccountSwitcher())
        assert report["error"]["type"] == "split_brain"
        assert ".enc" in report["error"]["message"] and "--adopt" in report["error"]["message"]
        assert endpoint.posts == []
        assert snapshot(temp_home, block_real_keychain) == before

    def test_adopt_keeps_and_replaces_the_enc_and_the_next_due_run_posts_once(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        enc = creds("AT-E", "RT-E", expires_in_s=100)
        x, _, _ = self._active(store, temp_home, block_real_keychain, enc=enc)
        assert run_keepalive(ClaudeAccountSwitcher())["error"]["type"] == "split_brain"

        report = run_keepalive(ClaudeAccountSwitcher(), adopt="file")
        assert report["ok"] is True and report["action"] == "adopted"
        assert endpoint.posts == []
        assert not self._enc(store).exists()
        assert enc in self._stashed(store)

        for _ in range(3):
            assert run_keepalive(ClaudeAccountSwitcher())["ok"] is True
        assert endpoint.posts == ["RT-X"]
        assert block_real_keychain.data[ACTIVE_ITEM] != x

    def test_adopt_stops_if_a_copy_cannot_be_kept(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch
    ):
        enc = creds("AT-E", "RT-E", expires_in_s=100)
        self._active(store, temp_home, block_real_keychain, enc=enc)
        before = snapshot(temp_home, block_real_keychain)
        monkeypatch.setattr(
            store._store.__class__, "_write_unclaimed_credential",
            lambda *a: (_ for _ in ()).throw(OSError("disk full")),
        )
        report = run_keepalive(ClaudeAccountSwitcher(), adopt="file")
        assert report["ok"] is False and report["error"]["type"] == "split_brain"
        assert snapshot(temp_home, block_real_keychain) == before

    def test_a_new_login_clears_a_differing_enc_too(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        enc = creds("AT-E", "RT-E", expires_in_s=100)
        self._active(store, temp_home, block_real_keychain, enc=enc)
        store.add_account(assume_yes=True)
        assert enc in self._stashed(store)
        assert not self._enc(store).exists()
        assert run_keepalive(ClaudeAccountSwitcher())["action"] == "refreshed"
        assert endpoint.posts == ["RT-X"]

    def test_an_enc_on_the_same_token_is_no_rival_and_needs_no_stash(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        same = creds("AT-other", "RT-X", expires_in_s=100)
        self._active(store, temp_home, block_real_keychain, enc=same)
        assert run_keepalive(ClaudeAccountSwitcher())["action"] == "refreshed"
        assert endpoint.posts == ["RT-X"]
        assert self._stashed(store) == {}
        assert not self._enc(store).exists()

    def test_a_garbled_enc_holds_nothing_to_keep(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._active(store, temp_home, block_real_keychain)
        self._enc(store).write_text("!!!! not base64", encoding="utf-8")
        assert run_keepalive(ClaudeAccountSwitcher())["action"] == "refreshed"
        assert endpoint.posts == ["RT-X"]

    # Everything rule U lists.

    @pytest.mark.parametrize("copy", ["keychain-slot", "enc", "session", "stash"])
    def test_any_copy_recorded_as_older_lets_the_post_through(
        self, store, temp_home, block_real_keychain, endpoint, copy
    ):
        older = creds("AT-O", "RT-O", expires_in_s=9000)
        x, _, _ = self._active(
            store, temp_home, block_real_keychain,
            slot=older if copy == "keychain-slot" else None,
            enc=older if copy == "enc" else None,
            session=older if copy == "session" else None,
        )
        if copy == "stash":
            store._store._write_unclaimed_credential(older, {
                "reason": "test", "configSlot": "1", "email": "a@example.com",
                "organizationUuid": "", "fingerprint": oauth.credential_fingerprint(older),
            })
        before = snapshot(temp_home, block_real_keychain)
        assert run_keepalive(ClaudeAccountSwitcher())["error"]["type"] == "split_brain"
        assert snapshot(temp_home, block_real_keychain) == before
        assert endpoint.posts == []

        consumed_grants.record(
            oauth.credential_fingerprint(older), self.A_ID, consumed_grants.CONSUMED,
            successor=oauth.credential_fingerprint(x),
        )
        assert run_keepalive(ClaudeAccountSwitcher())["action"] == "refreshed"
        assert endpoint.posts == ["RT-X"]

    def test_another_accounts_stash_entry_is_not_a_copy_of_this_login(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._active(store, temp_home, block_real_keychain)
        other = creds("AT-Z", "RT-Z")
        store._store._write_unclaimed_credential(other, {
            "reason": "test", "configSlot": "2", "email": "b@example.com",
            "organizationUuid": "", "fingerprint": oauth.credential_fingerprint(other),
        })
        assert run_keepalive(ClaudeAccountSwitcher())["action"] == "refreshed"
        assert endpoint.posts == ["RT-X"]

    @pytest.mark.parametrize("copy", ["enc", "session", "stash-manifest", "stash-entry"])
    def test_a_copy_that_cannot_be_read_blocks_the_post(
        self, store, temp_home, block_real_keychain, endpoint, monkeypatch, copy
    ):
        x, _, _ = self._active(store, temp_home, block_real_keychain)
        if copy == "enc":
            monkeypatch.setattr(
                store._store.__class__, "_leftover_backup_enc",
                lambda *a: (_ for _ in ()).throw(PermissionError("denied")),
            )
        elif copy == "session":
            store._session_dir("1", "a@example.com").mkdir(parents=True, exist_ok=True)
            monkeypatch.setattr("claude_swap.session.read_session_credentials", lambda d: None)
            monkeypatch.setattr("claude_swap.session._may_have_credential_material", lambda d: True)
        elif copy == "stash-manifest":
            monkeypatch.setattr(
                store._store.__class__, "_read_stash_manifest_ex", lambda self: ({}, "unreadable")
            )
        else:
            store._store._write_unclaimed_credential(creds("AT-O", "RT-O"), {
                "reason": "test", "configSlot": "1", "email": "a@example.com",
                "organizationUuid": "",
            })
            monkeypatch.setattr(
                store._store.__class__, "_read_unclaimed_credential", lambda self, i: ("", True)
            )
        with pytest.raises(CopiesDisagreeError):
            store._require_unanimity(x, self.A_ID)

    # Rule P's own cases.

    def test_a_refresh_stashes_nothing_because_its_predecessor_is_recorded(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        self._active(store, temp_home, block_real_keychain)
        assert run_keepalive(ClaudeAccountSwitcher())["action"] == "refreshed"
        assert self._stashed(store) == {}

    def test_a_copy_already_in_the_stash_is_not_stashed_twice(self, store):
        copy = creds("AT-C", "RT-C")
        for _ in range(2):
            store._preserve_copy(copy, None, identity=self.A_ID)
        assert len(self._stashed(store)) == 1

    def test_an_unreadable_stash_row_is_not_counted_as_kept(self, store, monkeypatch):
        copy = creds("AT-C", "RT-C")
        store._preserve_copy(copy, None, identity=self.A_ID)
        real = store._store._read_unclaimed_credential
        calls = []

        def first_unreadable(entry_id):
            calls.append(entry_id)
            return ("", True) if len(calls) == 1 else real(entry_id)

        monkeypatch.setattr(store._store, "_read_unclaimed_credential", first_unreadable)
        store._preserve_copy(copy, None, identity=self.A_ID)
        assert len(store._store._list_unclaimed_credentials()) == 2

    def test_a_read_back_that_differs_raises(self, store, monkeypatch):
        monkeypatch.setattr(store._store, "_read_unclaimed_credential", lambda i: ("other", False))
        with pytest.raises(ClaudeSwitchError):
            store._preserve_copy(creds("AT-C", "RT-C"), None, identity=self.A_ID)

    def test_removing_an_inactive_slot_keeps_every_copy_it_held(
        self, store, temp_home, block_real_keychain
    ):
        self._active(store, temp_home, block_real_keychain, expires=7200)
        kc = creds("AT-2", "RT-2")
        enc = creds("AT-2e", "RT-2e")
        session = creds("AT-2s", "RT-2s")
        block_real_keychain.data[SLOT_2] = kc
        store._store._write_backup_enc("2", "b@example.com", enc)
        session_dir = store._session_dir("2", "b@example.com")
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / ".credentials.json").write_text(session, encoding="utf-8")
        store.remove_account("2", assume_yes=True)
        assert SLOT_2 not in block_real_keychain.data
        kept = self._stashed(store)
        assert all(value in kept for value in (kc, enc, session))

    def test_a_write_to_a_slot_keeps_its_exited_sessions_copy(
        self, store, temp_home, block_real_keychain
    ):
        b = creds("AT-B", "RT-B")
        self._active(store, temp_home, block_real_keychain, expires=7200, session=b)
        store._write_account_credentials("1", "a@example.com", creds("AT-N", "RT-N"))
        assert b in self._stashed(store)

    def test_a_stale_stash_row_no_longer_loses_a_newer_slot_copy(
        self, store, temp_home, block_real_keychain, endpoint
    ):
        """The known limit from round 6: the newer copy now lands in the stash."""
        newer = creds("AT-Z", "RT-Z", expires_in_s=9000)
        x, _, _ = self._active(store, temp_home, block_real_keychain, expires=7200, slot=newer)
        y = creds("AT-Y", "RT-Y", expires_in_s=9000)
        store.stash_consumed_successor(
            "1", self.A_ID, y, oauth.credential_fingerprint(x), "keepalive-live-write-failed"
        )
        run_keepalive(ClaudeAccountSwitcher())
        assert newer in self._stashed(store)

    def test_a_switch_stashes_nothing_because_the_slot_keeps_the_live_login(
        self, store, temp_home, block_real_keychain
    ):
        self._active(store, temp_home, block_real_keychain, expires=7200)
        block_real_keychain.data[SLOT_2] = creds("AT-2", "RT-2", expires_in_s=7200)
        store.switch_to("2", json_output=True)
        assert self._stashed(store) == {}

    def _store_copies(self, s, home, keychain):
        a = creds("AT-A", "RT-A")
        f = creds("AT-F", "RT-F")
        keychain.data[ACTIVE_ITEM] = a
        file_path = home / ".claude" / ".credentials.json"
        file_path.write_text(f, encoding="utf-8")
        return a, f, file_path

    def test_replacing_the_stores_keeps_what_they_held(
        self, store, temp_home, block_real_keychain
    ):
        a, f, file_path = self._store_copies(store, temp_home, block_real_keychain)
        new = creds("AT-N", "RT-N")
        store._store._write_oauth_credentials(new)
        kept = self._stashed(store)
        assert a in kept and f in kept
        assert (kept[a]["email"], kept[a]["organizationUuid"]) == self.A_ID
        assert block_real_keychain.data[ACTIVE_ITEM] == new
        assert file_path.read_text(encoding="utf-8") == new

    def test_a_stash_that_fails_leaves_the_keychain_alone(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        a, f, file_path = self._store_copies(store, temp_home, block_real_keychain)
        monkeypatch.setattr(
            store._store, "_write_unclaimed_credential",
            lambda *args: (_ for _ in ()).throw(OSError("disk full")),
        )
        with pytest.raises(OSError):
            store._store._write_oauth_credentials(creds("AT-N", "RT-N"))
        assert block_real_keychain.data[ACTIVE_ITEM] == a
        assert file_path.read_text(encoding="utf-8") == f

    def test_a_stash_that_fails_leaves_the_file_alone(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        _, f, file_path = self._store_copies(store, temp_home, block_real_keychain)
        monkeypatch.setattr(
            store._store, "_write_unclaimed_credential",
            lambda *args: (_ for _ in ()).throw(OSError("disk full")),
        )
        with pytest.raises(OSError):
            store._store._write_active_credentials_file(creds("AT-N", "RT-N"))
        assert file_path.read_text(encoding="utf-8") == f

    def test_clearing_the_stores_keeps_what_they_held(
        self, store, temp_home, block_real_keychain
    ):
        a, f, file_path = self._store_copies(store, temp_home, block_real_keychain)
        store._store._clear_oauth_credential()
        kept = self._stashed(store)
        assert a in kept and f in kept
        assert ACTIVE_ITEM not in block_real_keychain.data and not file_path.exists()

    def test_a_file_that_cannot_be_read_is_not_replaced(
        self, store, temp_home, block_real_keychain, monkeypatch
    ):
        _, _, file_path = self._store_copies(store, temp_home, block_real_keychain)
        real = Path.read_text

        def denied(self, *a, **kw):
            if self == file_path:
                raise PermissionError("denied")
            return real(self, *a, **kw)

        monkeypatch.setattr(Path, "read_text", denied)
        with pytest.raises(ClaudeSwitchError):
            store._store._write_active_credentials_file(creds("AT-N", "RT-N"))

    # Default mode.

    def test_linux_still_keeps_the_copy_the_slot_replaces(self, temp_home, block_real_keychain):
        """Keepalive's own stash is not part of rule P, which applies on macOS only."""
        with patch("claude_swap.models.Platform.detect", return_value=Platform.LINUX):
            s = ClaudeAccountSwitcher()
            s._setup_directories()
            s._init_sequence_file()
            s._store.records_consumed = True
            data = s._get_sequence_data()
            accounts = {
                "1": {"email": "a@example.com", "uuid": "uuid-1", "organizationUuid": "", "organizationName": ""},
                "2": {"email": "b@example.com", "uuid": "uuid-2", "organizationUuid": "", "organizationName": ""},
            }
            data.update(activeAccountNumber=1, sequence=[1, 2], accounts=accounts)
            s._write_json(s.sequence_file, data)
            (temp_home / ".claude.json").write_text(json.dumps({
                "oauthAccount": {"emailAddress": "a@example.com", "accountUuid": "uuid-1"},
            }), encoding="utf-8")
            good = creds("AT-G", "RT-G", expires_in_s=7200)
            foreign = creds("AT-O", "RT-O", expires_in_s=20000)
            s._write_account_credentials("1", "a@example.com", good)
            s._write_account_credentials("2", "b@example.com", foreign)
            file_path = temp_home / ".claude" / ".credentials.json"
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(foreign, encoding="utf-8")
            report = run_keepalive(s)
            assert report["note"] == "split_brain"
            rows = s._store._list_unclaimed_credentials()
            assert [s._store._read_unclaimed_credential(i)[0] for i in rows] == [foreign]
            assert file_path.read_text(encoding="utf-8") == good

    def test_default_mode_keeps_nothing_and_applies_no_rule(
        self, temp_home, block_real_keychain, endpoint
    ):
        s = macos_store(temp_home)
        x = creds("AT-X", "RT-X", expires_in_s=600)
        block_real_keychain.data[ACTIVE_ITEM] = x
        s._write_account_credentials("1", "a@example.com", creds("AT-S", "RT-S"))
        s._store._write_backup_enc("1", "a@example.com", creds("AT-E", "RT-E"))
        s._write_account_credentials("1", "a@example.com", x)
        s._preserve_copy(creds("AT-D", "RT-D"), None, identity=self.A_ID)
        assert s._store._list_unclaimed_credentials() == {}
        assert not s._store._backup_enc_path("1", "a@example.com").exists()
        assert s.post_refresh(self.A_ID, x).credentials is not None
