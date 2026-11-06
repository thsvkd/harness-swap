"""`credentials.store=file` and `migrate-store`: a temp HOME, a fake `security` at the
subprocess seam so the real wrapper code runs, and a fake token endpoint. Tokens are
synthetic."""

from __future__ import annotations

import base64
import io
import json
import os
import stat
import subprocess
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import cli, consumed_grants, macos_keychain, oauth
from claude_swap.autoswitch import AutoSwitchEngine, TickOutcome
from claude_swap.exceptions import ConfigConflictError, KeychainItemPresentError
from claude_swap.keepalive import run_keepalive
from claude_swap.migrate_store import run_migrate_store, run_restore_keychain
from claude_swap.models import Platform
from claude_swap.settings import (
    AutoSwitchSettings,
    credentials_store,
    load_credential_settings,
    set_setting,
    strict_mode,
)
from claude_swap.switcher import ClaudeAccountSwitcher

from .keychain_helpers import FakeSecurity, creds, macos_store

pytestmark = pytest.mark.no_keychain_fake

ACCOUNT = macos_keychain.keychain_account_name()
SERVICE = macos_keychain.CREDENTIAL_SERVICE
ACTIVE_ITEM = (SERVICE, ACCOUNT)
SLOT_1 = ("1", "a@example.com")
SLOT_2 = ("2", "b@example.com")
NEAR = 600  # inside keepalive's default --ahead


@pytest.fixture(autouse=True)
def _macos_store_root():
    with patch("claude_swap.models.Platform.detect", return_value=Platform.MACOS):
        yield


class Security(FakeSecurity):
    """Adds what the file store asks that the base fake does not: the metadata lookup
    with an explicit keychain path, `dump-keychain`, and a log of every invocation."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.calls: list[list[str]] = []
        self.check_failure = None  # an rc, or an exception to raise, for the guard's calls

    def _dump(self) -> str:
        records = []
        for service, account in self.items:
            records.append(
                f'keychain: "{macos_keychain.login_keychain_file()}"\nversion: 512\n'
                f'class: "genp"\nattributes:\n'
                f'    0x00000007 <blob>="{service}"\n'
                f'    "acct"<blob>="{account}"\n'
                f'    "cdat"<timedate>=0x32303236  "2026"\n'
                f'    "svce"<blob>="{service}"\n'
            )
        records.append(
            f'keychain: "{macos_keychain.login_keychain_file()}"\nclass: "inet"\nattributes:\n'
            '    "acct"<blob>="x"\n    "srvr"<blob>="example.com"\n'
        )
        return "".join(records)

    def __call__(self, args, **kwargs):
        if args[0] != "/usr/bin/security":
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")
        self.calls.append(list(args[1:]))
        guard_lookup = args[1] == "find-generic-password" and "-a" not in args
        if guard_lookup or args[1] == "dump-keychain":
            assert "-w" not in args and "-d" not in args
            assert args[-1] == macos_keychain.login_keychain_file()
            if isinstance(self.check_failure, Exception):
                raise self.check_failure
            if self.check_failure:
                return self._completed(args, self.check_failure)
            if args[1] == "dump-keychain":
                return self._completed(args, 0, self._dump())
            found = any(service == args[args.index("-s") + 1] for service, _ in self.items)
            return self._completed(args, 0 if found else 44)
        return super().__call__(args, **kwargs)

    def non_guard_calls(self) -> list[list[str]]:
        def is_guard(call):
            return call[0] == "dump-keychain" or (
                call[0] == "find-generic-password" and "-a" not in call
            )

        return [call for call in self.calls if not is_guard(call)]


class Endpoint:
    def __init__(self):
        self.posts = []
        self.failure = None

    def __call__(self, request, timeout=None):
        self.posts.append(json.loads(request.data))
        if self.failure:
            raise self.failure
        return io.BytesIO(json.dumps({
            "access_token": "AT-NEW",
            "refresh_token": "RT-NEW",
            "expires_in": 28800,
        }).encode())


class Env:
    def __init__(self, home, security, endpoint):
        self.home = home
        self.security = security
        self.endpoint = endpoint
        self.file = home / ".claude" / ".credentials.json"
        self.reachable = True
        self.store = macos_store(home)

    @property
    def root(self):
        return self.store.backup_dir

    def enc_path(self, slot):
        return self.root / "credentials" / f".creds-{slot[0]}-{slot[1]}.enc"

    def write_enc(self, slot, value):
        self.enc_path(slot).parent.mkdir(parents=True, exist_ok=True)
        self.enc_path(slot).write_text(base64.b64encode(value.encode()).decode())

    def read_enc(self, slot):
        path = self.enc_path(slot)
        return base64.b64decode(path.read_text()).decode() if path.exists() else None

    def write_file(self, value):
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(value)
        self.file.chmod(0o600)

    def file_mode_on(self):
        set_setting(self.root, "credentials.store", "file")
        self.security.calls.clear()

    def keepalive(self, **kwargs):
        return run_keepalive(ClaudeAccountSwitcher(), **kwargs)

    def snapshot(self):
        files = {
            str(path.relative_to(self.home)): path.read_bytes()
            for path in sorted(self.home.rglob("*"))
            if path.is_file()
            and not path.name.endswith((".log", ".lock", ".takeover"))
            and path.name != "keepalive.json"
        }
        return {"files": files, "items": dict(self.security.items)}

    def credential_files(self):
        return {
            name: value
            for name, value in self.snapshot()["files"].items()
            if name.endswith((".credentials.json", ".enc"))
        }

    def stored_setting(self):
        path = self.root / "settings.json"
        data = json.loads(path.read_text()) if path.exists() else {}
        return data.get("credentials", {}).get("store")


@pytest.fixture
def env(temp_home, monkeypatch):
    security = Security()
    endpoint = Endpoint()
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.setattr("claude_swap.macos_keychain.subprocess.run", security)
    monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", endpoint)
    made = Env(temp_home, security, endpoint)
    monkeypatch.setattr(
        macos_keychain, "keychain_reachable", lambda *args, **kwargs: made.reachable
    )
    return made


@pytest.fixture
def healthy(env):
    """File mode, slot 1 active and agreeing with the file, slot 2 in `.enc`."""
    login = creds("AT-1", "RT-1")
    env.write_file(login)
    env.write_enc(SLOT_1, login)
    env.write_enc(SLOT_2, creds("AT-2", "RT-2"))
    env.file_mode_on()
    env.login = login
    return env


def run_cli(argv, capsys):
    capsys.readouterr()
    with patch.object(sys, "argv", ["cswap", *argv]):
        try:
            cli.main()
            code = 0
        except SystemExit as e:
            code = e.code or 0
    out, err = capsys.readouterr()
    return code, out, err


def json_error_type(out):
    return json.loads(out)["error"]["type"]


class TestConfig:
    def test_default_is_auto_and_set_get_round_trip(self, temp_home):
        root = temp_home / "root"
        assert credentials_store(root) == "auto"
        assert set_setting(root, "credentials.store", "file") == "file"
        assert load_credential_settings(root).store == "file"
        assert strict_mode(root) is True
        assert set_setting(root, "credentials.store", "auto") == "auto"
        assert strict_mode(root) is False

    def test_cli_set_get_and_bad_value(self, env, capsys):
        assert run_cli(["config", "set", "credentials.store", "file"], capsys)[0] == 0
        code, out, _ = run_cli(["config", "get", "credentials.store"], capsys)
        assert (code, out.strip()) == (0, "file")
        assert run_cli(["config", "set", "credentials.store", "elsewhere"], capsys)[0] == 1

    def test_a_garbled_value_reads_as_auto(self, temp_home):
        root = temp_home / "root"
        root.mkdir()
        (root / "settings.json").write_text(json.dumps({"credentials": {"store": "fil"}}))
        assert credentials_store(root) == "auto"

    def test_require_keychain_still_loads_alongside(self, temp_home):
        root = temp_home / "root"
        set_setting(root, "credentials.requireKeychain", "true")
        assert load_credential_settings(root).require_keychain is True
        assert load_credential_settings(root).store == "auto"

    def test_env_forces_file_and_can_only_tighten(self, temp_home, monkeypatch):
        root = temp_home / "root"
        monkeypatch.setenv("HSWAP_CREDENTIALS_STORE", "auto")
        assert credentials_store(root) == "auto"
        monkeypatch.setenv("HSWAP_CREDENTIALS_STORE", "file")
        assert credentials_store(root) == "file"
        monkeypatch.setenv("HSWAP_CREDENTIALS_STORE", "auto")
        set_setting(root, "credentials.store", "file")
        assert credentials_store(root) == "file"
        monkeypatch.delenv("HSWAP_CREDENTIALS_STORE")
        assert credentials_store(root) == "file"

    def test_config_set_refuses_the_second_either_way(self, temp_home):
        root = temp_home / "root"
        set_setting(root, "credentials.requireKeychain", "true")
        with pytest.raises(ConfigConflictError):
            set_setting(root, "credentials.store", "file")
        assert load_credential_settings(root).store == "auto"
        set_setting(root, "credentials.requireKeychain", "false")
        set_setting(root, "credentials.store", "file")
        with pytest.raises(ConfigConflictError):
            set_setting(root, "credentials.requireKeychain", "true")
        assert load_credential_settings(root).require_keychain is False

    def test_config_set_counts_the_environment(self, temp_home, monkeypatch):
        root = temp_home / "root"
        monkeypatch.setenv("HSWAP_REQUIRE_KEYCHAIN", "1")
        with pytest.raises(ConfigConflictError):
            set_setting(root, "credentials.store", "file")
        monkeypatch.delenv("HSWAP_REQUIRE_KEYCHAIN")
        monkeypatch.setenv("HSWAP_CREDENTIALS_STORE", "file")
        with pytest.raises(ConfigConflictError):
            set_setting(root, "credentials.requireKeychain", "true")

    def test_turning_the_other_off_is_not_a_conflict(self, temp_home):
        root = temp_home / "root"
        set_setting(root, "credentials.store", "file")
        assert set_setting(root, "credentials.requireKeychain", "false") is False

    def test_cli_refusal_says_config_conflict(self, env, capsys):
        env.file_mode_on()
        code, _, err = run_cli(["config", "set", "credentials.requireKeychain", "true"], capsys)
        assert code == 1 and "config_conflict" in err


class TestConfigConflictAtRuntime:
    @pytest.fixture
    def conflict(self, env, monkeypatch):
        env.write_file(creds())
        env.file_mode_on()
        monkeypatch.setenv("HSWAP_REQUIRE_KEYCHAIN", "1")
        return env

    @pytest.mark.parametrize(
        "argv",
        [
            ["list", "--json"],
            ["status", "--json"],
            ["switch", "2", "--json"],
            ["auto", "--once", "--json"],
            ["keepalive", "--json"],
            ["keychain-selftest", "--json"],
            ["migrate-store", "--to", "file", "--keep", "file", "--json"],
            ["run", "2", "--json"],
        ],
        ids=lambda argv: argv[0],
    )
    def test_every_command_refuses_before_any_side_effect(self, conflict, capsys, argv):
        before = conflict.snapshot()
        code, out, _ = run_cli(argv, capsys)
        assert code == 1
        assert json_error_type(out) == "config_conflict"
        assert conflict.snapshot() == before
        assert conflict.security.calls == []
        assert conflict.endpoint.posts == []

    def test_human_output_names_it(self, conflict, capsys):
        code, _, err = run_cli(["list"], capsys)
        assert code == 1 and "config_conflict" in err

    def test_the_switcher_refuses_too(self, conflict):
        with pytest.raises(ConfigConflictError):
            ClaudeAccountSwitcher()

    def test_config_stays_usable_to_repair_it(self, env, capsys):
        env.file_mode_on()
        path = env.root / "settings.json"
        data = json.loads(path.read_text())
        data["credentials"]["requireKeychain"] = True
        path.write_text(json.dumps(data))
        assert run_cli(["config", "get", "credentials.store"], capsys)[0] == 0
        assert run_cli(["list", "--json"], capsys)[0] == 1
        assert run_cli(["config", "unset", "credentials.requireKeychain"], capsys)[0] == 0
        assert run_cli(["list", "--json"], capsys)[0] == 0

    def test_off_macos_neither_setting_means_anything(self, conflict, capsys):
        with (
            patch("claude_swap.models.Platform.detect", return_value=Platform.LINUX),
            patch("claude_swap.cli.paths.get_backup_root", return_value=conflict.root),
        ):
            assert run_cli(["config", "path"], capsys)[0] == 0
            assert ClaudeAccountSwitcher()._store._file_store() is False


class TestHealthy:
    def test_due_posts_once_and_updates_the_file(self, healthy):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        report = healthy.keepalive()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert len(healthy.endpoint.posts) == 1
        assert healthy.endpoint.posts[0]["refresh_token"] == "RT-1"
        assert oauth.extract_oauth_data(healthy.file.read_text())["refreshToken"] == "RT-NEW"
        assert oauth.extract_oauth_data(healthy.read_enc(SLOT_1))["refreshToken"] == "RT-NEW"
        assert stat.S_IMODE(healthy.file.stat().st_mode) == 0o600
        assert healthy.security.items == {}
        assert healthy.security.non_guard_calls() == []

    def test_second_run_after_a_refresh_posts_nothing(self, healthy):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        assert healthy.keepalive()["action"] == "refreshed"
        report = healthy.keepalive()
        assert report["ok"] is True and report["action"] == "none"
        assert len(healthy.endpoint.posts) == 1

    def test_not_due_posts_nothing(self, healthy):
        before = healthy.credential_files()
        report = healthy.keepalive()
        assert report["ok"] is True and report["action"] == "none"
        assert healthy.endpoint.posts == []
        assert healthy.credential_files() == before
        assert healthy.security.non_guard_calls() == []

    def test_report_names_the_store(self, healthy):
        report = healthy.keepalive()
        assert report["store"] == "file" and report["keychainItemPresent"] is False
        assert report["schemaVersion"] == 1
        on_disk = json.loads((healthy.root / "cache" / "keepalive.json").read_text())
        assert on_disk == report

    def test_no_file_is_no_credentials(self, healthy):
        healthy.file.unlink()
        report = healthy.keepalive()
        assert report["error"]["type"] == "no_credentials"
        assert healthy.endpoint.posts == []

    def test_dry_run_changes_nothing(self, healthy):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        before = healthy.snapshot()
        report = healthy.keepalive(dry_run=True)
        assert report["action"] == "refreshed" and report["dryRun"] is True
        assert healthy.endpoint.posts == [] and healthy.snapshot() == before

    def test_switch_moves_the_login_through_enc_only(self, healthy):
        s = ClaudeAccountSwitcher()
        s.switch_to("2", json_output=True)
        assert oauth.extract_oauth_data(healthy.file.read_text())["refreshToken"] == "RT-2"
        assert oauth.extract_oauth_data(healthy.read_enc(SLOT_1))["refreshToken"] == "RT-1"
        assert s._get_current_account()[0] == "b@example.com"
        assert healthy.security.items == {}
        assert healthy.security.non_guard_calls() == []

    def test_auto_switch_between_two_slots_uses_enc_only(self, healthy):
        s = ClaudeAccountSwitcher()
        events = []
        engine = AutoSwitchEngine(s, AutoSwitchSettings(), events.append)
        outcome = engine._perform("2", "b@example.com", "failover", (None, float("inf")))
        assert outcome == TickOutcome.SWITCHED
        assert oauth.extract_oauth_data(healthy.file.read_text())["refreshToken"] == "RT-2"
        assert oauth.extract_oauth_data(healthy.read_enc(SLOT_1))["refreshToken"] == "RT-1"
        assert healthy.endpoint.posts == []
        assert healthy.security.items == {}
        assert healthy.security.non_guard_calls() == []

    def test_every_main_command_calls_only_the_guard(self, healthy, capsys):
        for argv in (
            ["list", "--json"],
            ["status", "--json"],
            ["list", "--token-status"],
            ["config"],
            ["unclaimed"],
            ["keepalive", "--json"],
            ["auto", "--once", "--dry-run", "--json"],
            ["add"],
            ["switch", "2", "--json"],
            ["switch", "1", "--json"],
            ["remove", "2"],
        ):
            with patch("builtins.input", return_value="y"):
                code, out, err = run_cli(argv, capsys)
            # `auto --once` says "nothing to do" with 2.
            assert code in ((0, 2) if argv[0] == "auto" else (0,)), (argv, out, err)
        assert healthy.security.non_guard_calls() == []
        assert healthy.security.items == {}
        # Every invocation was one of the guard's two shapes, and they did run.
        assert {call[0] for call in healthy.security.calls} == {
            "find-generic-password", "dump-keychain",
        }

    def test_a_session_read_calls_no_keychain_either(self, healthy):
        from claude_swap.session import delete_macos_keychain_entry

        profile = healthy.root / "sessions" / "x"
        profile.mkdir(parents=True)
        delete_macos_keychain_entry(profile)
        assert healthy.security.calls == []

    def test_retained_generation_stays_in_a_file(self, healthy):
        s = ClaudeAccountSwitcher()
        s._write_account_credentials(*SLOT_2, creds("AT-2B", "RT-2B"))
        assert oauth.extract_oauth_data(s._store._read_previous_backup(*SLOT_2))[
            "refreshToken"
        ] == "RT-2"
        assert healthy.security.calls == []

    def test_a_write_failure_parks_the_successor(self, healthy):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        s = ClaudeAccountSwitcher()
        with patch.object(s._store, "_write_active_credentials_file", side_effect=OSError("disk")):
            report = run_keepalive(s)
        assert report["ok"] is False
        assert len(healthy.endpoint.posts) == 1
        # The successor is stored somewhere the next run looks, and nothing posts again.
        report = healthy.keepalive()
        assert len(healthy.endpoint.posts) == 1
        assert report["ok"] is True and report["action"] == "synced-file"
        assert oauth.extract_oauth_data(healthy.file.read_text())["refreshToken"] == "RT-NEW"


class TestGuard:
    @pytest.fixture
    def due(self, healthy):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.credentials_before = healthy.credential_files()
        return healthy

    def _assert_refused(self, env):
        report = env.keepalive()
        assert report["ok"] is False
        assert report["error"]["type"] == "keychain_item_present"
        assert report["keychainItemPresent"] is True
        assert str(env.home) not in report["error"]["message"]
        assert env.endpoint.posts == []
        assert env.credential_files() == env.credentials_before

    def test_the_default_item_refuses(self, due):
        due.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        self._assert_refused(due)
        assert due.security.items[ACTIVE_ITEM]  # nothing deleted it

    def test_a_prefix_item_refuses(self, due):
        due.security.items[(f"{SERVICE}-abcd1234", ACCOUNT)] = creds("AT-K", "RT-K")
        self._assert_refused(due)
        assert ["dump-keychain", macos_keychain.login_keychain_file()] in due.security.calls

    @pytest.mark.parametrize(
        "failure",
        [36, 1, subprocess.TimeoutExpired("security", 5), OSError("no binary")],
        ids=["rc36", "rc1", "timeout", "oserror"],
    )
    def test_a_failed_check_refuses(self, due, failure):
        due.security.check_failure = failure
        self._assert_refused(due)

    def test_a_failed_dump_refuses(self, due, monkeypatch):
        real = macos_keychain._run_metadata

        def dump_fails(args):
            if args[0] == "dump-keychain":
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="")
            return real(args)

        monkeypatch.setattr(macos_keychain, "_run_metadata", dump_fails)
        self._assert_refused(due)

    def test_claude_swap_items_are_ignored(self, due):
        due.security.items[("claude-swap", "claude-code-credentials.backup-20260101T000000Z")] = "x"
        due.security.items[("claude-swap", f"{SERVICE}-abcd1234")] = "x"
        due.security.items[("claude-swap", "account-1-a@example.com")] = "x"
        report = due.keepalive()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert len(due.endpoint.posts) == 1
        assert due.security.non_guard_calls() == []

    def test_a_lookalike_service_is_ignored(self, due):
        due.security.items[(f"{SERVICE}2", ACCOUNT)] = "x"
        assert due.keepalive()["ok"] is True

    def test_switch_and_auto_refuse_too(self, due, capsys):
        due.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        before = due.snapshot()
        code, out, _ = run_cli(["switch", "2", "--json"], capsys)
        assert code == 1 and json_error_type(out) == "keychain_item_present"
        code, out, _ = run_cli(["auto", "--once", "--json"], capsys)
        assert code == TickOutcome.ERROR.value
        assert "keychain_item_present" in out
        assert due.snapshot() == before
        assert due.endpoint.posts == []

    def test_the_gate_and_the_post_each_check_under_the_locks(self, healthy):
        s = ClaudeAccountSwitcher()
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        with pytest.raises(KeychainItemPresentError):
            s._required_mode_gate()
        outcome = s.post_refresh(("a@example.com", ""), creds(), locks_held=True)
        assert outcome.error == "keychain_item_present"
        assert healthy.endpoint.posts == []

    def test_an_inactive_slot_refresh_stops_too(self, healthy):
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        s = ClaudeAccountSwitcher()
        outcome = s.consume_backup_grant(*SLOT_2, creds("AT-2", "RT-2"))
        assert outcome.credentials is None and outcome.error == "keychain_item_present"
        assert healthy.endpoint.posts == []

    def test_the_lookup_never_names_a_secret_flag(self, healthy):
        assert macos_keychain.credential_item_present() is False
        assert macos_keychain.credential_items() == []
        for call in healthy.security.calls:
            assert "-w" not in call and "-d" not in call
            assert call[-1] == macos_keychain.login_keychain_file()


class TestReportAndRaces:
    def test_item_present_wins_over_whatever_else_stops_the_run(self, healthy):
        (healthy.root / "sessions" / "x").mkdir(parents=True)
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        report = healthy.keepalive()
        assert report["error"]["type"] == "keychain_item_present"
        assert report["keychainItemPresent"] is True

    def test_a_clean_guard_is_reported_when_another_stop_ends_the_run(self, healthy):
        (healthy.root / "sessions" / "x").mkdir(parents=True)
        report = healthy.keepalive()
        assert report["error"]["type"] == "required_mode_unsupported"
        assert report["keychainItemPresent"] is False

    def test_a_pinned_run_that_finds_the_store_changed_stops_before_the_post(self, env):
        due = creds("AT-1", "RT-1", expires_in_s=NEAR)
        env.write_file(due)
        env.security.items[ACTIVE_ITEM] = due
        s = ClaudeAccountSwitcher()

        def migrated_while_waiting(active):
            set_setting(env.root, "credentials.store", "file")
            del env.security.items[ACTIVE_ITEM]
            return active

        real = __import__("claude_swap.keepalive", fromlist=["_pass"])._pass
        with patch(
            "claude_swap.keepalive._pass",
            lambda active, *args, **kwargs: real(migrated_while_waiting(active), *args, **kwargs),
        ):
            report = run_keepalive(s)
        assert report["error"]["type"] == "locked"
        assert env.endpoint.posts == []

    def test_usage_passes_defer_without_a_traceback_when_an_item_is_present(self, healthy, caplog):
        expired = creds("AT-1", "RT-1", expires_in_s=-60)
        healthy.write_file(expired)
        healthy.write_enc(SLOT_1, expired)
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        s = ClaudeAccountSwitcher()
        s.list_accounts(json_output=True)
        assert healthy.endpoint.posts == []
        assert "failed unexpectedly" not in caplog.text


class TestDumpParsing:
    def _items(self, output, monkeypatch):
        monkeypatch.setattr(
            macos_keychain,
            "_run_metadata",
            lambda args: subprocess.CompletedProcess(args, 0, stdout=output, stderr=""),
        )
        return macos_keychain.credential_items()

    def test_a_hex_form_attribute_counts(self, monkeypatch):
        output = (
            'keychain: "/x"\nclass: "genp"\nattributes:\n'
            '    "acct"<blob>="me"\n'
            f'    "svce"<blob>=0x436C61756465  "{SERVICE}-abcd1234"\n'
        )
        assert self._items(output, monkeypatch) == [(f"{SERVICE}-abcd1234", "me")]

    def test_another_class_does_not_count(self, monkeypatch):
        output = f'keychain: "/x"\nclass: "inet"\nattributes:\n    "svce"<blob>="{SERVICE}"\n'
        assert self._items(output, monkeypatch) == []

    def test_an_empty_dump_is_no_items(self, monkeypatch):
        assert self._items("", monkeypatch) == []


class TestStrictProtections:
    def test_slot_enc_with_an_unlinked_token_is_split_brain(self, healthy):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-X", "RT-X"))
        report = healthy.keepalive()
        assert report["error"]["type"] == "split_brain"
        assert healthy.endpoint.posts == []

    def test_stash_rival_is_split_brain(self, healthy):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        rival = creds("AT-R", "RT-R")
        ClaudeAccountSwitcher()._store._write_unclaimed_credential(rival, {
            "reason": "keepalive-split-brain", "configSlot": "1",
            "email": "a@example.com", "organizationUuid": "",
            "fingerprint": oauth.credential_fingerprint(rival),
        })
        assert healthy.keepalive()["error"]["type"] == "split_brain"
        assert healthy.endpoint.posts == []

    def test_a_ledger_linked_predecessor_is_allowed(self, healthy):
        old = creds("AT-OLD", "RT-OLD")
        now = creds("AT-1", "RT-1", expires_in_s=NEAR)
        healthy.write_file(now)
        healthy.write_enc(SLOT_1, old)
        identity = ("a@example.com", "")
        ClaudeAccountSwitcher()
        consumed_grants.reserve(oauth.credential_fingerprint(old), identity)
        consumed_grants.record(
            oauth.credential_fingerprint(old),
            identity,
            consumed_grants.CONSUMED,
            successor=oauth.credential_fingerprint(now),
        )
        report = healthy.keepalive()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert [post["refresh_token"] for post in healthy.endpoint.posts] == ["RT-1"]

    def test_a_token_on_the_ledger_is_never_sent(self, healthy):
        spent = creds("AT-1", "RT-1", expires_in_s=NEAR)
        healthy.write_file(spent)
        healthy.write_enc(SLOT_1, spent)
        ClaudeAccountSwitcher()
        consumed_grants.reserve(oauth.credential_fingerprint(spent), ("a@example.com", ""))
        assert healthy.keepalive()["error"]["type"] == "relogin_required"
        assert healthy.endpoint.posts == []

    def test_an_uncertain_refresh_is_not_retried(self, healthy):
        due = creds("AT-1", "RT-1", expires_in_s=NEAR)
        healthy.write_file(due)
        healthy.write_enc(SLOT_1, due)
        healthy.endpoint.failure = urllib.error.HTTPError("u", 500, "boom", {}, io.BytesIO(b""))
        assert healthy.keepalive()["ok"] is False
        assert healthy.keepalive()["error"]["type"] == "relogin_required"
        assert len(healthy.endpoint.posts) == 1

    def test_manifest_corrupt_stops(self, healthy):
        manifest = healthy.root / "credentials" / ".unclaimed-manifest.json"
        manifest.write_text("{not json")
        report = healthy.keepalive()
        assert report["error"]["type"] == "stash_manifest_corrupt"
        assert manifest.read_text() == "{not json"

    def test_session_profiles_stop(self, healthy):
        (healthy.root / "sessions" / "x").mkdir(parents=True)
        report = healthy.keepalive()
        assert report["error"]["type"] == "required_mode_unsupported"
        assert "credentials.store=file" in report["error"]["message"]

    @pytest.mark.parametrize(
        "argv",
        [
            ["run", "2"],
            ["add-token", "sk-ant-oat01-x"],
            ["import", "x.cswap"],
            ["move", "2", "3"],
            ["swap", "1", "2"],
            ["purge"],
            ["unclaimed", "--purge", "x"],
            ["remove", "1"],
        ],
        ids=lambda argv: argv[0],
    )
    def test_unsupported_commands_refuse(self, healthy, capsys, argv):
        before = healthy.snapshot()
        code, out, err = run_cli(argv, capsys)
        assert code != 0
        assert "required_mode_unsupported" in out + err
        assert "file-store" in out + err
        assert healthy.snapshot() == before

    def test_remove_of_an_inactive_slot_is_supported_and_keeps_rule_p(self, healthy, capsys):
        with patch("builtins.input", return_value="y"):
            assert run_cli(["remove", "2"], capsys)[0] == 0
        assert healthy.read_enc(SLOT_2) is None
        s = ClaudeAccountSwitcher()._store
        kept = [s._read_unclaimed_credential(e)[0] for e in s._list_unclaimed_credentials()]
        assert any("RT-2" in value for value in kept)

    @pytest.mark.parametrize("flags", [{"adopt": "file"}, {"ensure_file": True}], ids=["adopt", "ensure"])
    def test_keepalive_adopt_and_ensure_file_refuse(self, healthy, flags):
        before = healthy.snapshot()
        report = healthy.keepalive(**flags)
        assert report["error"]["type"] == "required_mode_unsupported"
        assert healthy.snapshot() == before

    def test_keychain_selftest_refuses(self, healthy, capsys):
        code, out, _ = run_cli(["keychain-selftest", "--json"], capsys)
        assert code == 1 and json_error_type(out) == "required_mode_unsupported"
        assert healthy.security.calls == []

    def test_claude_code_refresh_locks_are_held_around_the_gate(self, healthy):
        s = ClaudeAccountSwitcher()
        with (
            patch("claude_swap.switcher.claude_credentials_lock") as lock,
            s._required_mode_section(),
        ):
            pass
        lock.assert_called_once()

    def test_replacing_the_file_keeps_the_old_copy_first(self, healthy):
        s = ClaudeAccountSwitcher()
        s.switch_to("2", json_output=True)
        # The file's RT-1 outlives the change in slot 1, so nothing was stashed for it.
        assert oauth.extract_oauth_data(healthy.read_enc(SLOT_1))["refreshToken"] == "RT-1"


class TestDefaultModesAreUnchanged:
    def test_default_mode_uses_the_keychain(self, env):
        s = ClaudeAccountSwitcher()
        s.platform = Platform.MACOS
        s._store._write_oauth_credentials(creds("AT-1", "RT-1"))
        assert ACTIVE_ITEM in env.security.items
        assert s._store._strict_mode() is False
        assert s._store._has_keychain() is True
        assert not env.file.exists()
        assert all(call[0] != "dump-keychain" for call in env.security.calls)

    def test_default_keepalive_report_says_auto(self, env):
        env.security.items[ACTIVE_ITEM] = creds("AT-1", "RT-1")
        report = env.keepalive()
        assert report["store"] == "auto" and report["keychainItemPresent"] is True
        assert all(call[0] != "dump-keychain" for call in env.security.calls)

    def test_required_mode_report_says_keychain_and_still_refuses(self, env):
        set_setting(env.root, "credentials.requireKeychain", "true")
        env.reachable = False
        report = env.keepalive()
        assert report["store"] == "keychain"
        assert report["error"]["type"] == "keychain_unavailable"

    def test_required_mode_messages_are_untouched(self, env, capsys):
        set_setting(env.root, "credentials.requireKeychain", "true")
        _, out, err = run_cli(["swap", "1", "2"], capsys)
        assert "keychain-required" in out + err
        assert "credentials.requireKeychain" in out + err

    def test_off_macos_file_store_is_inert(self, temp_home):
        set_setting(temp_home / "root", "credentials.store", "file")
        with patch("claude_swap.models.Platform.detect", return_value=Platform.LINUX):
            s = ClaudeAccountSwitcher()
            set_setting(s.backup_dir, "credentials.store", "file")
            assert s._store._file_store() is False
            assert s._store._strict_mode() is False


@pytest.fixture
def split(env):
    """The state found in the field: Keychain and file differ, slot 1 (active) and slot 2
    back up only in the Keychain, and the store is still `auto`."""
    env.file_login = creds("AT-F", "RT-F")
    env.keychain_login = creds("AT-K", "RT-K")
    env.slot_1_item = creds("AT-S1", "RT-S1")
    env.slot_2_item = creds("AT-S2", "RT-S2")
    env.write_file(env.file_login)
    env.security.items[ACTIVE_ITEM] = env.keychain_login
    env.security.items[("claude-swap", "account-1-a@example.com")] = env.slot_1_item
    env.security.items[("claude-swap", "account-2-b@example.com")] = env.slot_2_item
    env.security.calls.clear()
    return env


def backups(env, prefix="claude-code-credentials.backup-"):
    return {
        account: value
        for (service, account), value in env.security.items.items()
        if service == "claude-swap" and account.startswith(prefix)
    }


class TestMigrateStore:
    def _run(self, env, keep, **kwargs):
        return run_migrate_store(ClaudeAccountSwitcher(), keep, **kwargs)

    def test_keep_file(self, split):
        before = split.file.read_bytes()
        report = self._run(split, "file")
        assert report["ok"] is True and report["error"] is None
        assert report["kept"] == "file"
        assert split.file.read_bytes() == before
        assert ACTIVE_ITEM not in split.security.items
        assert report["itemAbsent"] is True
        assert split.stored_setting() == "file"
        assert list(backups(split).values()) == [split.keychain_login]
        assert set(backups(split)) <= set(report["backups"])

    def test_keep_keychain(self, split):
        report = self._run(split, "keychain")
        assert report["ok"] is True
        assert split.file.read_text() == split.keychain_login
        assert stat.S_IMODE(split.file.stat().st_mode) == 0o600
        assert ACTIVE_ITEM not in split.security.items
        assert split.stored_setting() == "file"
        # Both logins survive: the file it replaced may have been the live one.
        assert sorted(backups(split).values()) == sorted([split.file_login, split.keychain_login])

    def test_backup_account_names(self, split):
        report = self._run(split, "file")
        import re

        assert any(
            re.fullmatch(r"claude-code-credentials\.backup-\d{8}T\d{6}Z(-\d+)?", name)
            for name in report["backups"]
        )
        assert any(
            re.fullmatch(r"slot-1-a@example\.com\.backup-\d{8}T\d{6}Z(-\d+)?", name)
            for name in report["backups"]
        )

    def test_a_taken_name_is_never_overwritten(self, split, monkeypatch):
        import claude_swap.migrate_store as module

        class Frozen(module.datetime):
            @classmethod
            def now(cls, tz=None):
                return module.datetime(2026, 1, 1, tzinfo=tz)

        monkeypatch.setattr(module, "datetime", Frozen)
        taken = "claude-code-credentials.backup-20260101T000000Z"
        split.security.items[("claude-swap", taken)] = "earlier"
        report = self._run(split, "file")
        assert report["ok"] is True
        assert split.security.items[("claude-swap", taken)] == "earlier"
        assert f"{taken}-1" in report["backups"]

    def test_slots(self, split):
        report = self._run(split, "file")
        # Active slot from the kept credential, not its Keychain copy.
        assert split.read_enc(SLOT_1) == split.file_login
        assert split.read_enc(SLOT_2) == split.slot_2_item
        assert report["slotsMigrated"] == [1, 2]
        assert list(backups(split, "slot-1-a@example.com.backup-").values()) == [split.slot_1_item]
        # Slot items stay; file mode never reads them.
        assert split.security.items[("claude-swap", "account-1-a@example.com")] == split.slot_1_item
        assert split.security.items[("claude-swap", "account-2-b@example.com")] == split.slot_2_item
        mode = stat.S_IMODE(split.enc_path(SLOT_2).stat().st_mode)
        assert mode == 0o600

    def test_no_lineage_and_no_stash(self, split):
        self._run(split, "file")
        s = ClaudeAccountSwitcher()._store
        assert s._list_unclaimed_credentials() == {}
        for login in (split.file_login, split.keychain_login, split.slot_1_item, split.slot_2_item):
            assert consumed_grants.entry(oauth.credential_fingerprint(login)) is None

    def test_after_migrating_keepalive_refreshes_once(self, split):
        assert self._run(split, "file")["ok"] is True
        split.write_file(creds("AT-F", "RT-F", expires_in_s=NEAR))
        split.security.calls.clear()
        report = split.keepalive()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert [post["refresh_token"] for post in split.endpoint.posts] == ["RT-F"]
        assert report["store"] == "file" and report["keychainItemPresent"] is False
        assert split.security.non_guard_calls() == []

    def test_dry_run_writes_nothing(self, split):
        before = split.snapshot()
        report = self._run(split, "keychain", dry_run=True)
        assert report["ok"] is True and report["dryRun"] is True
        assert report["slotsMigrated"] == [1, 2]
        assert report["backups"] == []
        assert report["itemAbsent"] is False
        assert any("credentials.store=file" in step for step in report["plan"])
        assert split.snapshot() == before
        assert split.stored_setting() is None
        assert all(not call[0].startswith(("delete", "-i")) for call in split.security.calls)

    def test_backup_verify_failure_deletes_nothing(self, split):
        split.security.mangle = lambda value: value[:-1]
        report = self._run(split, "file")
        assert report["ok"] is False and report["error"]["type"] == "keychain_unavailable"
        assert split.security.deleted == []
        assert split.security.items[ACTIVE_ITEM] == split.keychain_login
        assert split.stored_setting() is None

    def test_backup_write_failure_deletes_nothing(self, split):
        split.security.write_rc = 1
        report = self._run(split, "file")
        assert report["ok"] is False
        assert split.security.deleted == []
        assert split.stored_setting() is None

    def test_one_failed_backup_of_two_deletes_neither(self, split):
        real = macos_keychain.set_password
        second = f"{SERVICE}-abcd1234"
        split.security.items[(second, ACCOUNT)] = creds("AT-P", "RT-P")
        written = []

        def fails_on_second(service, account, value):
            if account.startswith("claude-code-credentials.backup-"):
                written.append(account)
                if len(written) == 2:
                    raise macos_keychain.KeychainError("nope")
            real(service, account, value)

        with patch.object(macos_keychain, "set_password", fails_on_second):
            report = self._run(split, "file")
        assert report["ok"] is False
        assert split.security.deleted == []
        assert (second, ACCOUNT) in split.security.items and ACTIVE_ITEM in split.security.items

    def test_a_delete_failure_leaves_the_setting_off(self, split):
        split.security.delete_rc = 1
        report = self._run(split, "file")
        assert report["ok"] is False and split.stored_setting() is None
        assert report["itemAbsent"] is False

    def test_an_item_that_survives_leaves_the_setting_off(self, split, monkeypatch):
        monkeypatch.setattr(macos_keychain, "delete_password", lambda service, account: None)
        report = self._run(split, "file")
        assert report["ok"] is False
        assert report["error"]["type"] == "keychain_item_present"
        assert split.stored_setting() is None

    def test_keychain_unavailable_refuses_and_changes_nothing(self, split):
        split.reachable = False
        before = split.snapshot()
        report = self._run(split, "file")
        assert report["ok"] is False and report["error"]["type"] == "keychain_unavailable"
        assert split.snapshot() == before
        assert split.security.calls == []

    def test_a_reachability_of_none_refuses(self, split):
        split.reachable = None
        assert self._run(split, "file")["error"]["type"] == "keychain_unavailable"

    @pytest.mark.parametrize("keep", ["file", "keychain"])
    def test_keep_needs_a_refresh_token_there(self, split, keep):
        if keep == "file":
            split.file.unlink()
        else:
            del split.security.items[ACTIVE_ITEM]
        before = split.snapshot()
        report = self._run(split, keep)
        assert report["error"]["type"] == "no_credentials"
        assert split.snapshot() == before

    def test_keep_file_with_no_refresh_token_refuses(self, split):
        split.write_file(json.dumps({"claudeAiOauth": {"accessToken": "AT"}}))
        assert self._run(split, "file")["error"]["type"] == "no_credentials"
        assert ACTIVE_ITEM in split.security.items

    def test_a_spent_kept_token_refuses(self, split):
        ClaudeAccountSwitcher()
        consumed_grants.reserve(oauth.credential_fingerprint(split.file_login), ("a@example.com", ""))
        before = split.snapshot()
        assert self._run(split, "file")["error"]["type"] == "relogin_required"
        assert split.snapshot() == before

    def test_another_accounts_login_refuses(self, split):
        split.write_enc(SLOT_2, split.file_login)
        before = split.snapshot()
        assert self._run(split, "file")["error"]["type"] == "unmanaged"
        assert split.snapshot() == before

    def test_prefix_items_are_backed_up_and_deleted(self, split):
        second = (f"{SERVICE}-abcd1234", ACCOUNT)
        split.security.items[second] = creds("AT-P", "RT-P")
        report = self._run(split, "file")
        assert report["ok"] is True
        assert second not in split.security.items
        assert any("RT-P" in value for value in backups(split).values())

    def test_inactive_slot_with_a_differing_enc_refuses_first(self, split):
        split.write_enc(SLOT_2, creds("AT-OLD", "RT-OLD"))
        before = split.snapshot()
        report = self._run(split, "file")
        assert report["error"]["type"] == "split_brain"
        assert "Slot 2" in report["error"]["message"]
        assert split.snapshot() == before

    def test_inactive_slot_already_in_enc_is_left_alone(self, split):
        kept = creds("AT-S2-OTHER", "RT-S2")
        split.write_enc(SLOT_2, kept)
        report = self._run(split, "file")
        assert report["ok"] is True and report["slotsMigrated"] == [1]
        assert split.read_enc(SLOT_2) == kept

    def test_session_profiles_refuse(self, split):
        (split.root / "sessions" / "x").mkdir(parents=True)
        assert self._run(split, "file")["error"]["type"] == "required_mode_unsupported"
        assert ACTIVE_ITEM in split.security.items

    def test_corrupt_manifest_refuses(self, split):
        (split.root / "credentials").mkdir(exist_ok=True)
        (split.root / "credentials" / ".unclaimed-manifest.json").write_text("{nope")
        assert self._run(split, "file")["error"]["type"] == "stash_manifest_corrupt"
        assert ACTIVE_ITEM in split.security.items

    def test_require_keychain_refuses(self, split):
        set_setting(split.root, "credentials.requireKeychain", "true")
        report = self._run(split, "file")
        assert report["error"]["type"] == "config_conflict"
        assert ACTIVE_ITEM in split.security.items

    def test_a_profile_environment_refuses(self, split, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(split.home / ".claude"))
        assert self._run(split, "file")["error"]["type"] == "unsupported_store"
        assert ACTIVE_ITEM in split.security.items

    def test_repair_in_file_mode_ends_the_guard_refusal(self, split):
        assert self._run(split, "file")["ok"] is True
        # Claude Code ran where the keychain was unlocked: successor there, file gone.
        split.write_enc(SLOT_1, split.file_login)
        successor = creds("AT-K2", "RT-K2", expires_in_s=NEAR)
        split.security.items[ACTIVE_ITEM] = successor
        split.file.unlink()
        assert split.keepalive()["error"]["type"] == "keychain_item_present"

        report = self._run(split, "keychain")
        assert report["ok"] is True and report["itemAbsent"] is True
        assert split.file.read_text() == successor
        assert split.read_enc(SLOT_1) == successor
        # The `.enc` it replaced is kept where rule U does not look.
        assert any(
            value == split.file_login
            for value in backups(split, "slot-1-a@example.com.backup-").values()
        )
        split.security.calls.clear()
        report = split.keepalive()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert [post["refresh_token"] for post in split.endpoint.posts] == ["RT-K2"]
        assert split.security.non_guard_calls() == []

    def test_repair_after_a_slot_rotated_in_file_mode(self, split):
        assert self._run(split, "file")["ok"] is True
        # File mode updated slot 2's `.enc`, and its Keychain item stays behind.
        rotated = creds("AT-S2-NEW", "RT-S2-NEW")
        split.write_enc(SLOT_2, rotated)
        split.security.items[ACTIVE_ITEM] = creds("AT-K2", "RT-K2")
        split.file.unlink()
        report = self._run(split, "keychain")
        assert report["ok"] is True and report["slotsMigrated"] == [1]
        assert split.read_enc(SLOT_2) == rotated
        assert split.keepalive()["ok"] is True

    def test_rerun_is_a_no_op_with_no_new_backups(self, split):
        assert self._run(split, "file")["ok"] is True
        count = len(backups(split)) + len(backups(split, "slot-"))
        report = self._run(split, "file")
        assert report["ok"] is True and report["slotsMigrated"] == []
        assert len(backups(split)) + len(backups(split, "slot-")) == count

    def test_no_token_in_any_output_or_log(self, split, capsys):
        code, out, err = run_cli(["migrate-store", "--to", "file", "--keep", "keychain", "--json"], capsys)
        assert code == 0
        report = json.loads(out)
        assert report["ok"] is True
        restored = report["backups"][0]
        code, restore_out, restore_err = run_cli(
            ["migrate-store", "--restore-keychain", restored, "--json"], capsys
        )
        assert code == 0
        logs = "".join(
            path.read_text(errors="replace")
            for path in split.home.rglob("*.log")
        )
        text = out + err + restore_out + restore_err + logs
        for token in ("AT-F", "RT-F", "AT-K", "RT-K", "AT-S1", "RT-S1", "AT-S2", "RT-S2"):
            assert token not in text
        for call in split.security.calls:
            assert not any("RT-" in argument for argument in call)

    def test_fingerprints_are_six_hex_of_the_refresh_token(self, split):
        import hashlib

        report = self._run(split, "file")
        assert report["fileFingerprint"] == hashlib.sha256(b"RT-F").hexdigest()[:6]
        assert report["keychainFingerprint"] == hashlib.sha256(b"RT-K").hexdigest()[:6]

    def test_cli_dry_run_and_human_output(self, split, capsys):
        code, out, _ = run_cli(["migrate-store", "--to", "file", "--keep", "file", "--dry-run"], capsys)
        assert code == 0 and "credentials.store=file" in out
        assert split.stored_setting() is None

    def test_cli_needs_to_and_keep(self, env, capsys):
        assert run_cli(["migrate-store", "--keep", "file"], capsys)[0] == 2
        assert run_cli(["migrate-store", "--to", "file"], capsys)[0] == 2
        assert run_cli(["migrate-store", "--restore-keychain", "x", "--keep", "file"], capsys)[0] == 2

    def test_cli_is_macos_only(self, env, capsys):
        with patch("claude_swap.models.Platform.detect", return_value=Platform.LINUX):
            code, out, _ = run_cli(
                ["migrate-store", "--to", "file", "--keep", "file", "--json"], capsys
            )
        assert code == 1 and json_error_type(out) == "unsupported"


class TestRestoreKeychain:
    def test_round_trip(self, split):
        report = run_migrate_store(ClaudeAccountSwitcher(), "file")
        name = next(iter(backups(split)))
        restored = run_restore_keychain(ClaudeAccountSwitcher(), name)
        assert restored["ok"] is True and restored["restored"] == name
        assert split.security.items[ACTIVE_ITEM] == split.keychain_login
        assert split.security.items[("claude-swap", name)] == split.keychain_login  # kept
        assert report["keychainFingerprint"] == restored["fingerprint"]

    def test_the_item_is_written_through_stdin_only(self, split):
        run_migrate_store(ClaudeAccountSwitcher(), "file")
        split.security.calls.clear()
        run_restore_keychain(ClaudeAccountSwitcher(), next(iter(backups(split))))
        assert ["-i"] in split.security.calls
        assert not any("RT-K" in " ".join(call) for call in split.security.calls)

    def test_an_item_already_there_is_kept_first(self, split):
        run_migrate_store(ClaudeAccountSwitcher(), "file")
        name = next(iter(backups(split)))
        newer = creds("AT-N", "RT-N")
        split.security.items[ACTIVE_ITEM] = newer
        restored = run_restore_keychain(ClaudeAccountSwitcher(), name)
        assert restored["ok"] is True
        assert split.security.items[("claude-swap", restored["backups"][0])] == newer

    def test_a_restored_item_trips_the_guard_until_the_setting_is_off(self, split):
        run_migrate_store(ClaudeAccountSwitcher(), "file")
        run_restore_keychain(ClaudeAccountSwitcher(), next(iter(backups(split))))
        assert split.keepalive()["error"]["type"] == "keychain_item_present"

    def test_a_spent_backup_refuses(self, split):
        run_migrate_store(ClaudeAccountSwitcher(), "file")
        name = next(iter(backups(split)))
        consumed_grants.reserve(
            oauth.credential_fingerprint(split.keychain_login), ("a@example.com", "")
        )
        report = run_restore_keychain(ClaudeAccountSwitcher(), name)
        assert report["error"]["type"] == "relogin_required"
        assert ACTIVE_ITEM not in split.security.items

    def test_another_accounts_backup_refuses(self, split):
        run_migrate_store(ClaudeAccountSwitcher(), "file")
        name = next(iter(backups(split)))
        split.write_enc(SLOT_2, split.keychain_login)
        report = run_restore_keychain(ClaudeAccountSwitcher(), name)
        assert report["error"]["type"] == "unmanaged"
        assert ACTIVE_ITEM not in split.security.items

    @pytest.mark.parametrize(
        "name",
        [
            "claude-code-credentials.backup-none",
            "account-1-a@example.com",
            "slot-1-a@example.com.backup-20260101T000000Z",
        ],
    )
    def test_unknown_or_non_backup_name_refuses(self, split, name):
        split.security.items[("claude-swap", "slot-1-a@example.com.backup-20260101T000000Z")] = (
            split.slot_1_item
        )
        before = dict(split.security.items)
        report = run_restore_keychain(ClaudeAccountSwitcher(), name)
        assert report["error"]["type"] == "backup_not_found"
        assert split.security.items == before

    def test_keychain_unavailable_refuses(self, split):
        split.reachable = False
        report = run_restore_keychain(ClaudeAccountSwitcher(), "x.backup-y")
        assert report["error"]["type"] == "keychain_unavailable"
        assert split.security.items[ACTIVE_ITEM] == split.keychain_login

    def test_a_failed_read_back_reports_it(self, split):
        run_migrate_store(ClaudeAccountSwitcher(), "file")
        name = next(iter(backups(split)))
        split.security.mangle = lambda value: value[:-1]
        report = run_restore_keychain(ClaudeAccountSwitcher(), name)
        assert report["ok"] is False
        assert split.security.items[("claude-swap", name)] == split.keychain_login


def test_module_is_free_of_machine_specific_values():
    """Docs and code name no host, no account and no path beyond `~`."""
    source = (Path(__file__).parents[1] / "src" / "claude_swap" / "migrate_store.py").read_text()
    assert "/Users/" not in source and "@" not in source.replace("@contextmanager", "")
    assert os.sep + "home" + os.sep not in source
