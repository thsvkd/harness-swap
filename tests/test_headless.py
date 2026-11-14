"""File store with no login session: keepalive, switch, auto and list on a locked keychain,
`reconcile`, `doctor`, the reconcile LaunchAgent, the keepalive LaunchDaemon and
`migrate-store --with-reconcile`. Same harness as test_file_store: a temp HOME and a fake
`security` at the subprocess seam. Tokens are synthetic."""

from __future__ import annotations

import json
import os
import plistlib
import subprocess
from unittest.mock import patch

import pytest

from claude_swap import consumed_grants, keepalive_service as ks, launch_agent, oauth
from claude_swap import reconcile_service as rs
from claude_swap.doctor import run_doctor
from claude_swap.reconcile import run_reconcile
from claude_swap.switcher import ClaudeAccountSwitcher

from .keychain_helpers import creds
from .test_file_store import (  # noqa: F401 - fixtures
    ACCOUNT,
    ACTIVE_ITEM,
    NEAR,
    SERVICE,
    SLOT_1,
    SLOT_2,
    _macos_store_root,
    backups,
    env,
    healthy,
    json_error_type,
    run_cli,
    split,
)

pytestmark = pytest.mark.no_keychain_fake

PROGRAM = ["/Users/x/.local/bin/hswap", "claude"]
UID = 501
TOKENS = ("AT-1", "RT-1", "AT-K", "RT-K", "AT-N", "RT-N", "AT-2", "RT-2")


@pytest.fixture
def daemon(healthy):
    """File mode where no login session exists: a LaunchDaemon or SSH. The keychain is
    locked, so only the guard's attribute lookups answer; everything else is rc 36."""
    healthy.reachable = False
    healthy.security.locked = True
    return healthy


def _reconcile(**kwargs):
    return run_reconcile(ClaudeAccountSwitcher(), **kwargs)


def _no_token_in(env, text):
    logs = "".join(path.read_text(errors="replace") for path in env.home.rglob("*.log"))
    for token in TOKENS:
        assert token not in text + logs
    for call in env.security.calls:
        assert not any("RT-" in argument or "AT-" in argument for argument in call)


class TestNoLoginSession:
    def test_list_keepalive_switch_auto_run_to_the_end(self, daemon, capsys):
        due = creds("AT-1", "RT-1", expires_in_s=NEAR)
        daemon.write_file(due)
        daemon.write_enc(SLOT_1, due)

        code, out, _ = run_cli(["keepalive", "--json"], capsys)
        report = json.loads(out)
        assert code == 0 and report["ok"] is True and report["action"] == "refreshed"
        assert report["store"] == "file" and report["keychainItemPresent"] is False
        assert [post["refresh_token"] for post in daemon.endpoint.posts] == ["RT-1"]
        assert oauth.extract_oauth_data(daemon.read_enc(SLOT_1))["refreshToken"] == "RT-NEW"
        code, out, err = run_cli(["list", "--json"], capsys)
        assert code == 0, err

        code, out, err = run_cli(["switch", "2", "--json"], capsys)
        assert code == 0, err
        assert oauth.extract_oauth_data(daemon.file.read_text())["refreshToken"] == "RT-2"
        code, out, _ = run_cli(["auto", "--once", "--json"], capsys)
        assert code in (0, 2), out  # 2: nothing to do
        assert daemon.security.non_guard_calls() == []
        assert daemon.security.items == {}

    def test_an_item_stops_it_and_names_reconcile(self, daemon, capsys):
        daemon.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        before = daemon.snapshot()
        code, out, _ = run_cli(["keepalive", "--json"], capsys)
        error = json.loads(out)["error"]
        assert code == 1 and error["type"] == "keychain_item_present"
        assert "hswap claude reconcile" in error["message"]
        code, out, _ = run_cli(["switch", "2", "--json"], capsys)
        assert code == 1 and json_error_type(out) == "keychain_item_present"
        assert daemon.snapshot() == before
        assert daemon.endpoint.posts == []


class TestReconcile:
    def test_no_item_is_a_no_op_that_reads_nothing(self, healthy):
        before = healthy.snapshot()
        report = _reconcile()
        assert report["ok"] is True and report["action"] == "none"
        assert report["keychainItemPresent"] is False and report["itemAbsent"] is True
        assert healthy.snapshot() == before
        assert healthy.security.non_guard_calls() == []

    def test_claude_code_moved_the_login_to_the_keychain(self, healthy):
        # A Claude Code with the keychain open refreshed, wrote the item and deleted the file.
        successor = creds("AT-K", "RT-K", expires_in_s=NEAR)
        healthy.security.items[ACTIVE_ITEM] = successor
        healthy.file.unlink()
        assert healthy.keepalive()["error"]["type"] == "keychain_item_present"

        report = _reconcile()
        assert report["ok"] is True and report["action"] == "reconciled"
        assert report["kept"] == "keychain" and report["itemAbsent"] is True
        assert healthy.file.read_text() == successor
        assert healthy.read_enc(SLOT_1) == successor
        assert ACTIVE_ITEM not in healthy.security.items
        # What it replaced was kept first and read back.
        assert list(backups(healthy, "slot-1-a@example.com.backup-").values()) == [healthy.login]
        assert list(backups(healthy).values()) == [successor]

        healthy.security.calls.clear()
        report = healthy.keepalive()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert [post["refresh_token"] for post in healthy.endpoint.posts] == ["RT-K"]
        assert healthy.security.non_guard_calls() == []

    @pytest.mark.parametrize("keychain_later", [True, False])
    def test_one_login_in_both_keeps_the_later_generation(self, healthy, keychain_later):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=3600))
        other = creds("AT-1B", "RT-1", expires_in_s=7200 if keychain_later else 600)
        healthy.security.items[ACTIVE_ITEM] = other
        report = _reconcile()
        assert report["ok"] is True
        assert report["kept"] == ("keychain" if keychain_later else "file")
        assert ACTIVE_ITEM not in healthy.security.items
        if keychain_later:
            assert healthy.file.read_text() == other

    @pytest.mark.parametrize("successor_in", ["file", "keychain"])
    def test_a_recorded_link_decides(self, healthy, successor_in):
        older, newer = creds("AT-K", "RT-K"), creds("AT-N", "RT-N")
        identity = ("a@example.com", "")
        ClaudeAccountSwitcher()
        consumed_grants.record_lineage(
            oauth.credential_fingerprint(older), oauth.credential_fingerprint(newer),
            identity, consumed_grants.NEW_LOGIN,
        )
        healthy.write_file(newer if successor_in == "file" else older)
        healthy.security.items[ACTIVE_ITEM] = older if successor_in == "file" else newer
        healthy.write_enc(SLOT_1, older)
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == successor_in
        assert healthy.file.read_text() == newer
        assert healthy.read_enc(SLOT_1) == newer

    def test_a_spent_file_token_loses(self, healthy):
        ClaudeAccountSwitcher()
        consumed_grants.reserve(oauth.credential_fingerprint(healthy.login), ("a@example.com", ""))
        successor = creds("AT-K", "RT-K")
        healthy.security.items[ACTIVE_ITEM] = successor
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == "keychain"
        assert healthy.file.read_text() == successor

    def test_an_unseen_keychain_login_beats_the_file_hswap_holds(self, healthy):
        # The file's token is the slot's `.enc`; the item's was never seen: written later.
        successor = creds("AT-K", "RT-K")
        healthy.security.items[ACTIVE_ITEM] = successor
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == "keychain"
        assert healthy.file.read_text() == successor
        assert any(value == healthy.login for value in backups(healthy).values())

    def test_an_unseen_file_login_beats_a_keychain_copy_hswap_holds(self, healthy):
        fresh = creds("AT-N", "RT-N")
        healthy.write_file(fresh)  # /login over SSH
        healthy.security.items[ACTIVE_ITEM] = healthy.login
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == "file"
        assert healthy.file.read_text() == fresh
        assert healthy.read_enc(SLOT_1) == fresh

    def test_two_unseen_logins_are_ambiguous_and_change_nothing(self, healthy, capsys):
        healthy.write_file(creds("AT-N", "RT-N"))
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        before = healthy.snapshot()
        code, out, err = run_cli(["reconcile", "--json"], capsys)
        report = json.loads(out)
        assert code == 4
        assert report["ok"] is False and report["error"]["type"] == "reconcile_ambiguous"
        assert report["kept"] is None
        assert healthy.snapshot() == before
        assert healthy.security.deleted == [] and healthy.security.stdin == []
        _no_token_in(healthy, out + err)

    def test_a_locked_keychain_is_reported_and_left_alone(self, daemon, capsys):
        daemon.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        daemon.file.unlink()
        before = daemon.snapshot()
        code, out, err = run_cli(["reconcile", "--json"], capsys)
        report = json.loads(out)
        assert code == 5
        assert report["error"]["type"] == "keychain_item_present_locked"
        assert report["keychainItemPresent"] is True and report["keychainLocked"] is True
        assert daemon.snapshot() == before
        assert daemon.security.non_guard_calls() == []

    def test_dry_run_plans_and_writes_nothing(self, healthy):
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        healthy.file.unlink()
        before = healthy.snapshot()
        report = _reconcile(dry_run=True)
        assert report["ok"] is True and report["dryRun"] is True
        assert report["kept"] == "keychain" and report["action"] == "planned"
        assert any("back up and delete" in step for step in report["plan"])
        assert healthy.snapshot() == before

    def test_a_prefix_item_alone_is_cleared_and_the_file_kept(self, healthy):
        item = (f"{SERVICE}-abcd1234", ACCOUNT)
        healthy.security.items[item] = creds("AT-K", "RT-K")
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == "file"
        assert item not in healthy.security.items
        assert healthy.file.read_text() == healthy.login

    def test_outside_the_file_store_it_refuses(self, env, capsys):
        env.write_file(creds())
        env.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        before = env.snapshot()
        code, out, _ = run_cli(["reconcile", "--json"], capsys)
        assert code == 1 and json_error_type(out) == "not_file_store"
        assert env.snapshot() == before

    def test_no_token_in_output_logs_or_argv(self, healthy, capsys):
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        healthy.file.unlink()
        code, out, err = run_cli(["reconcile", "--json"], capsys)
        assert code == 0 and json.loads(out)["ok"] is True
        code, text_out, text_err = run_cli(["reconcile"], capsys)
        assert code == 0
        _no_token_in(healthy, out + err + text_out + text_err)


class TestDoctor:
    @pytest.fixture(autouse=True)
    def _darwin(self):
        with (
            patch.object(ks.sys, "platform", "darwin"),
            patch.object(rs.sys, "platform", "darwin"),
            patch.object(launch_agent.sys, "platform", "darwin"),
        ):
            yield

    def _ready(self, env):
        rs.install(program=PROGRAM)  # no GUI domain here: written, deferred

    def test_a_ready_mac(self, daemon, capsys):
        self._ready(daemon)
        code, out, _ = run_cli(["doctor", "--json"], capsys)
        report = json.loads(out)
        assert code == 0, report
        assert set(report) == {
            "schemaVersion", "ok", "problems", "store", "keychainItemPresent", "keychainLocked",
            "fileExists", "fileMode", "slotsWithoutBackup", "sessionDirs",
            "reconcileService", "keepaliveService",
        }
        assert report["schemaVersion"] == 1
        assert report["ok"] is True and report["problems"] == []
        assert report["store"] == "file" and report["keychainItemPresent"] is False
        assert report["keychainLocked"] is True and report["fileExists"] is True
        if os.name == "posix":
            assert report["fileMode"] == "0600"
        assert report["slotsWithoutBackup"] == [] and report["sessionDirs"] == []
        assert report["reconcileService"]["installed"] is True
        assert report["reconcileService"]["managed"] is True
        assert report["keepaliveService"]["installed"] is False
        assert daemon.security.non_guard_calls() == []

    def test_it_is_read_only(self, daemon):
        self._ready(daemon)
        daemon.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        (daemon.root / "sessions" / "x").mkdir(parents=True)
        before = daemon.snapshot()
        run_doctor(ClaudeAccountSwitcher())
        assert daemon.snapshot() == before
        assert daemon.security.non_guard_calls() == []

    def _problems(self, env):
        return run_doctor(ClaudeAccountSwitcher())["problems"]

    def test_not_file_store(self, env):
        env.write_file(creds())
        assert "not_file_store" in self._problems(env)

    def test_keychain_item_present(self, healthy):
        self._ready(healthy)
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        assert self._problems(healthy) == ["keychain_item_present"]

    def test_file_missing(self, healthy):
        self._ready(healthy)
        healthy.file.unlink()
        assert self._problems(healthy) == ["file_missing"]

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
    def test_file_mode_insecure(self, healthy):
        self._ready(healthy)
        healthy.file.chmod(0o644)
        report = run_doctor(ClaudeAccountSwitcher())
        assert report["problems"] == ["file_mode_insecure"] and report["fileMode"] == "0644"

    def test_slot_without_backup(self, healthy):
        self._ready(healthy)
        healthy.enc_path(SLOT_2).unlink()
        report = run_doctor(ClaudeAccountSwitcher())
        assert report["problems"] == ["slot_without_backup"] and report["slotsWithoutBackup"] == [2]

    def test_session_profiles(self, healthy):
        self._ready(healthy)
        (healthy.root / "sessions" / "2-b@example.com").mkdir(parents=True)
        report = run_doctor(ClaudeAccountSwitcher())
        assert report["problems"] == ["session_profiles"]
        assert report["sessionDirs"] == ["2-b@example.com"]

    def test_profile_env(self, healthy, monkeypatch):
        self._ready(healthy)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(healthy.home / ".claude"))
        assert self._problems(healthy) == ["profile_env"]

    def test_reconcile_service_missing(self, healthy, capsys):
        problems = self._problems(healthy)
        assert problems == ["reconcile_service_missing"]
        code, out, _ = run_cli(["doctor"], capsys)
        assert code == 2 and "reconcile_service_missing" in out


def _launchctl(calls, *, gui=False, loaded=False):
    """launchctl and sudo: ``gui`` says whether the user's GUI domain exists, ``loaded``
    whether a job answers ``print``."""

    def run(argv, **kwargs):
        calls.append(list(argv))
        if argv[0] == "launchctl" and argv[1] == "print":
            target = argv[2]
            if target.startswith("gui/"):
                ok = gui and (target.count("/") == 1 or loaded)  # a gui job needs the domain
            else:
                ok = loaded
            return subprocess.CompletedProcess(argv, 0 if ok else 113, "\tstate = waiting\n" if ok else "", "")
        if argv[:2] == ["sudo", "install"]:
            (ks.SYSTEM_DIR).mkdir(parents=True, exist_ok=True)
            ks.system_plist_path().write_bytes(open(argv[-2], "rb").read())
        if argv[:3] == ["sudo", "rm", "-f"]:
            ks.system_plist_path().unlink(missing_ok=True)
        return subprocess.CompletedProcess(argv, 0, "", "")

    return patch.object(launch_agent.subprocess, "run", side_effect=run)


@pytest.fixture
def macos_services(tmp_path, monkeypatch):
    monkeypatch.setattr(ks, "SYSTEM_DIR", tmp_path / "LaunchDaemons")
    with (
        patch.object(ks.sys, "platform", "darwin"),
        patch.object(rs.sys, "platform", "darwin"),
        patch.object(launch_agent.sys, "platform", "darwin"),
    ):
        yield tmp_path


class TestReconcileService:
    def test_plist_watches_the_login_keychain_and_runs_at_load(self, tmp_path):
        doc = plistlib.loads(rs.build(PROGRAM, tmp_path))
        assert doc["Label"] == "dev.hswap.reconcile"
        assert doc["ProgramArguments"] == [*PROGRAM, "reconcile"]
        assert doc["WatchPaths"] == [str(tmp_path / "Library/Keychains/login.keychain-db")]
        assert doc["RunAtLoad"] is True and "KeepAlive" not in doc
        assert doc["EnvironmentVariables"]["HSWAP_SERVICE"] == "reconcile"

    def test_install_without_a_gui_session_defers(self, macos_services):
        calls = []
        with _launchctl(calls):
            result = rs.install(macos_services, UID, PROGRAM)
        assert result["action"] == "deferred" and result["installed"] is True
        assert not any(call[1] == "bootstrap" for call in calls)

    def test_install_loads_and_uninstall_removes(self, macos_services):
        calls = []
        with _launchctl(calls, gui=True):
            assert rs.install(macos_services, UID, PROGRAM)["action"] == "installed"
        assert ["launchctl", "bootstrap", f"gui/{UID}", str(launch_agent.plist_path(rs.LABEL, macos_services))] in calls
        with _launchctl(calls, gui=True, loaded=True):
            st = rs.status(macos_services, UID)
            assert st["managed"] is True and st["outdated"] is False and st["loaded"] is True
            assert rs.install(macos_services, UID, PROGRAM)["action"] == "unchanged"
            assert rs.uninstall(macos_services, UID)["action"] == "removed"
        assert not launch_agent.plist_path(rs.LABEL, macos_services).exists()

    def test_a_foreign_plist_is_left_alone(self, macos_services):
        path = launch_agent.plist_path(rs.LABEL, macos_services)
        path.parent.mkdir(parents=True)
        path.write_bytes(plistlib.dumps({"Label": rs.LABEL, "ProgramArguments": ["x"]}))
        with _launchctl([]), pytest.raises(ks.ForeignServiceError):
            rs.install(macos_services, UID, PROGRAM)

    def test_cli_refuses_outside_the_file_store(self, env, capsys):
        code, out, _ = run_cli(["reconcile", "--install-service", "--json"], capsys)
        assert code == 1 and json_error_type(out) == "not_file_store"
        assert not launch_agent.plist_path(rs.LABEL).exists()

    def test_cli_deferred_is_exit_3(self, healthy, capsys):
        with patch.object(rs.sys, "platform", "darwin"), patch.object(launch_agent.sys, "platform", "darwin"):
            code, out, _ = run_cli(["reconcile", "--install-service", "--json"], capsys)
        assert code == 3 and json.loads(out)["action"] == "deferred"


class TestKeepaliveDaemon:
    def _install(self, home, calls, **kwargs):
        return ks.install(7200, False, home, UID, PROGRAM, system=True, user="kgolf", **kwargs)

    def test_plist_runs_as_the_user_with_their_home(self, tmp_path):
        doc = plistlib.loads(ks.build(PROGRAM, 7200, False, tmp_path, user="kgolf"))
        assert doc["UserName"] == "kgolf"
        assert doc["EnvironmentVariables"]["HOME"] == str(tmp_path)
        assert doc["EnvironmentVariables"]["USER"] == "kgolf"
        assert doc["Label"] == "dev.hswap.keepalive" and doc["RunAtLoad"] is True
        assert doc["StartInterval"] == 300 and "WatchPaths" in doc
        assert "UserName" not in plistlib.loads(ks.build(PROGRAM, 7200, False, tmp_path))

    def test_install_goes_through_sudo_into_the_system_domain(self, macos_services):
        calls = []
        with _launchctl(calls):
            result = self._install(macos_services, calls)
        assert result["action"] == "installed" and result["domain"] == "system"
        path = str(ks.system_plist_path())
        assert ks.system_plist_path().parts[-2:] == ("LaunchDaemons", "dev.hswap.keepalive.plist")
        install = next(call for call in calls if call[:2] == ["sudo", "install"])
        assert install[2:8] == ["-o", "root", "-g", "wheel", "-m", "644"] and install[-1] == path
        assert ["sudo", "launchctl", "bootstrap", "system", path] in calls
        assert plistlib.loads(ks.system_plist_path().read_bytes())["UserName"] == "kgolf"
        assert (macos_services / "Library/Logs/dev.hswap.keepalive.err").exists()

    def test_it_replaces_the_gui_agent_so_only_one_runs(self, macos_services):
        calls = []
        with _launchctl(calls):
            ks.install(7200, False, macos_services, UID, PROGRAM)  # deferred gui agent
        gui = launch_agent.plist_path(ks.LABEL, macos_services)
        assert gui.exists()
        with _launchctl(calls):
            self._install(macos_services, calls)
        assert not gui.exists()

    def test_the_gui_agent_refuses_while_the_daemon_is_there(self, macos_services):
        calls = []
        with _launchctl(calls):
            self._install(macos_services, calls)
            with pytest.raises(ks.ServiceConflictError):
                ks.install(7200, False, macos_services, UID, PROGRAM)
        assert not launch_agent.plist_path(ks.LABEL, macos_services).exists()

    def test_status_and_uninstall(self, macos_services):
        calls = []
        with _launchctl(calls):
            self._install(macos_services, calls)
        with _launchctl(calls, loaded=True):
            st = ks.status(macos_services, UID)
            assert st["domain"] == "system" and st["managed"] is True and st["outdated"] is False
            assert self._install(macos_services, calls)["action"] == "unchanged"
            assert ks.uninstall(macos_services, UID, system=True)["action"] == "removed"
        assert ["sudo", "launchctl", "bootout", "system/dev.hswap.keepalive"] in calls
        assert not ks.system_plist_path().exists()

    def test_a_foreign_daemon_is_left_alone(self, macos_services):
        ks.SYSTEM_DIR.mkdir(parents=True)
        ks.system_plist_path().write_bytes(plistlib.dumps({"Label": ks.LABEL, "ProgramArguments": ["x"]}))
        calls = []
        with _launchctl(calls), pytest.raises(ks.ForeignServiceError):
            self._install(macos_services, calls)
        assert not any(call[0] == "sudo" for call in calls)

    def test_cli_refuses_outside_the_file_store(self, env, capsys, macos_services):
        calls = []
        with _launchctl(calls):
            code, out, _ = run_cli(["keepalive", "--install-service", "--system", "--json"], capsys)
        assert code == 1 and json_error_type(out) == "not_file_store"
        assert not any(call[0] == "sudo" for call in calls)

    def test_cli_installs_in_the_file_store(self, healthy, capsys, macos_services):
        calls = []
        with _launchctl(calls):
            code, out, err = run_cli(["keepalive", "--install-service", "--system", "--json"], capsys)
        assert code == 0, err
        assert json.loads(out)["domain"] == "system"

    def test_system_needs_a_service_option(self, healthy, capsys):
        assert run_cli(["keepalive", "--system"], capsys)[0] == 2


class TestMigrateStoreWithReconcile:
    def test_default_installs_the_reconcile_service_and_reports_doctor(self, split, capsys):
        with (
            patch.object(ks.sys, "platform", "darwin"),
            patch.object(rs.sys, "platform", "darwin"),
            patch.object(launch_agent.sys, "platform", "darwin"),
        ):
            code, out, err = run_cli(["migrate-store", "--to", "file", "--keep", "file", "--json"], capsys)
        report = json.loads(out)
        assert code == 0, err
        assert report["ok"] is True
        assert report["reconcileService"]["action"] == "deferred"
        assert launch_agent.plist_path(rs.LABEL).exists()
        assert report["doctor"]["ok"] is True and report["doctor"]["problems"] == []

    def test_without_reconcile_installs_nothing(self, split, capsys):
        code, out, _ = run_cli(
            ["migrate-store", "--to", "file", "--keep", "file", "--without-reconcile", "--json"], capsys
        )
        report = json.loads(out)
        assert code == 0 and report["reconcileService"] is None
        assert not launch_agent.plist_path(rs.LABEL).exists()
        assert report["doctor"]["problems"] == ["reconcile_service_missing"]

    def test_dry_run_installs_nothing(self, split, capsys):
        code, out, _ = run_cli(["migrate-store", "--to", "file", "--keep", "file", "--dry-run", "--json"], capsys)
        assert code == 0 and json.loads(out)["reconcileService"] is None
        assert not launch_agent.plist_path(rs.LABEL).exists()
