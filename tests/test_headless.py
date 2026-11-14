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
from claude_swap.exceptions import ClaudeSwitchError
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


@pytest.fixture
def darwin():
    """sys.platform reads darwin everywhere (it is one object), so give Windows the
    uid calls the macOS paths make."""
    with (
        patch.object(ks.sys, "platform", "darwin"),
        patch.object(os, "getuid", lambda: UID, create=True),
        patch.object(os, "geteuid", lambda: UID, create=True),
    ):
        yield
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

    def test_claude_code_moved_the_login_to_the_keychain_is_ambiguous(self, healthy):
        # A Claude Code with the keychain open refreshed, wrote the item and deleted the
        # file. Nothing records that the item came from the slot's token: a stale cache
        # writes exactly the same shape, so a person decides.
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K", expires_in_s=NEAR)
        healthy.file.unlink()
        before = healthy.snapshot()
        report = _reconcile()
        assert report["error"]["type"] == "reconcile_ambiguous" and report["kept"] is None
        assert healthy.snapshot() == before
        assert healthy.security.deleted == [] and healthy.security.stdin == []

    @pytest.mark.parametrize("file_left", [False, True])
    def test_a_stale_rewrite_after_a_settled_refresh_does_not_win(self, healthy, capsys, file_left):
        # The review's scenario. RT-1 is the login; GUI Claude Code A refreshes it to RT-3,
        # writes the item and deletes the file.
        rt3 = creds("AT-3", "RT-3", expires_in_s=NEAR)
        healthy.security.items[ACTIVE_ITEM] = rt3
        healthy.file.unlink()
        assert _reconcile()["error"]["type"] == "reconcile_ambiguous"
        # A person settles it; RT-3 is now in the file and the `.enc`.
        code, out, err = run_cli(
            ["migrate-store", "--to", "file", "--keep", "keychain", "--no-reconcile", "--no-keepalive", "--json"], capsys
        )
        assert code == 0, out + err
        assert healthy.file.read_text() == rt3 and healthy.read_enc(SLOT_1) == rt3
        # Claude Code B, with a stale cache, writes RT-1 back (the item was new, so it
        # also deletes the file, unless something rewrote it since).
        healthy.security.items[ACTIVE_ITEM] = healthy.login
        if not file_left:
            healthy.file.unlink()
        report = _reconcile()
        assert report["ok"] is True, report
        assert report["kept"] == ("file" if file_left else "slot")
        assert healthy.file.read_text() == rt3 and healthy.read_enc(SLOT_1) == rt3
        assert ACTIVE_ITEM not in healthy.security.items
        assert healthy.login in backups(healthy).values()  # kept, then deleted
        healthy.security.calls.clear()
        report = healthy.keepalive()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert [post["refresh_token"] for post in healthy.endpoint.posts] == ["RT-3"]

    def _settle_rt3(self, healthy, capsys):
        """RT-1 refreshed to RT-3 in the GUI; a person keeps the Keychain's."""
        rt3 = creds("AT-3", "RT-3", expires_in_s=NEAR)
        healthy.security.items[ACTIVE_ITEM] = rt3
        healthy.file.unlink()
        code, out, err = run_cli(
            ["migrate-store", "--to", "file", "--keep", "keychain", "--no-reconcile", "--no-keepalive", "--json"], capsys
        )
        assert code == 0, out + err
        return rt3

    def test_a_stale_file_does_not_beat_the_kept_login_back_in_the_item(self, healthy, capsys):
        # The re-review's scenario: A (live RT-3) writes an MCP secret, recreating the item
        # and deleting the file; B over SSH with a stale cache writes RT-1 to the file.
        rt3 = self._settle_rt3(healthy, capsys)
        healthy.security.items[ACTIVE_ITEM] = creds("AT-3", "RT-3", expires_in_s=NEAR, mcpOAuth={"s": {}})
        healthy.write_file(healthy.login)
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == "keychain", report
        assert oauth.credential_fingerprint(healthy.file.read_text()) == oauth.credential_fingerprint(rt3)
        assert oauth.credential_fingerprint(healthy.read_enc(SLOT_1)) == oauth.credential_fingerprint(rt3)
        healthy.keepalive()
        assert [post["refresh_token"] for post in healthy.endpoint.posts] == ["RT-3"]

    def test_two_stale_copies_stay_ambiguous(self, healthy, capsys):
        # The file went back to the replaced RT-1 and the item holds a token nothing saw:
        # neither is the login a run kept.
        self._settle_rt3(healthy, capsys)
        healthy.write_file(healthy.login)
        healthy.security.items[ACTIVE_ITEM] = creds("AT-X", "RT-X")
        before = healthy.snapshot()
        assert _reconcile()["error"]["type"] == "reconcile_ambiguous"
        assert healthy.snapshot() == before

    def test_a_write_between_the_decision_and_the_move_stops_it(self, healthy, monkeypatch):
        from claude_swap import reconcile

        healthy.security.items[ACTIVE_ITEM] = creds("AT-1B", "RT-1", expires_in_s=9000)
        healthy.file.unlink()
        real = reconcile.choose_kept

        def then_an_mcp_login(*args):
            verdict = real(*args)
            healthy.security.items[ACTIVE_ITEM] = creds("AT-1C", "RT-1", expires_in_s=9500)
            return verdict

        monkeypatch.setattr(reconcile, "choose_kept", then_an_mcp_login)
        report = _reconcile()
        assert report["error"]["type"] == "keychain_item_changed"
        assert not healthy.file.exists() and healthy.read_enc(SLOT_1) == healthy.login

    def test_with_the_file_gone_a_linked_item_is_kept(self, healthy):
        successor = creds("AT-K", "RT-K")
        ClaudeAccountSwitcher()
        consumed_grants.record_lineage(
            oauth.credential_fingerprint(healthy.login), oauth.credential_fingerprint(successor),
            ("a@example.com", ""), consumed_grants.NEW_LOGIN,
        )
        healthy.security.items[ACTIVE_ITEM] = successor
        healthy.file.unlink()
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == "keychain"
        assert healthy.file.read_text() == successor
        assert healthy.read_enc(SLOT_1) == successor

    def test_with_the_file_gone_a_linked_slot_is_kept(self, healthy):
        older = creds("AT-K", "RT-K")
        ClaudeAccountSwitcher()
        consumed_grants.record_lineage(
            oauth.credential_fingerprint(older), oauth.credential_fingerprint(healthy.login),
            ("a@example.com", ""), consumed_grants.OBSERVED_POST,
        )
        healthy.security.items[ACTIVE_ITEM] = older
        healthy.file.unlink()
        report = _reconcile()
        assert report["ok"] is True and report["kept"] == "slot"
        assert healthy.file.read_text() == healthy.login
        assert ACTIVE_ITEM not in healthy.security.items

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

    @pytest.mark.parametrize("fresh_in", ["keychain", "file"])
    def test_a_login_only_one_side_has_seen_is_still_ambiguous(self, healthy, fresh_in):
        fresh = creds("AT-N", "RT-N")
        if fresh_in == "keychain":
            healthy.security.items[ACTIVE_ITEM] = fresh
        else:
            healthy.write_file(fresh)  # /login over SSH
            healthy.security.items[ACTIVE_ITEM] = healthy.login
        before = healthy.snapshot()
        assert _reconcile()["error"]["type"] == "reconcile_ambiguous"
        assert healthy.snapshot() == before

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
        healthy.security.items[ACTIVE_ITEM] = creds("AT-1B", "RT-1", expires_in_s=9000)
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
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-1", expires_in_s=9000)
        healthy.file.unlink()
        code, out, err = run_cli(["reconcile", "--json"], capsys)
        assert code == 0 and json.loads(out)["ok"] is True
        code, text_out, text_err = run_cli(["reconcile"], capsys)
        assert code == 0
        _no_token_in(healthy, out + err + text_out + text_err)


class TestReconcileFailures:
    """Every failure leaves the item where it is, so nothing is lost and the next run retries."""

    @pytest.fixture
    def moved(self, healthy):
        # One lineage, a later generation in the item: reconcile keeps the item.
        healthy.item = creds("AT-1B", "RT-1", expires_in_s=9000)
        healthy.security.items[ACTIVE_ITEM] = healthy.item
        healthy.file.unlink()
        return healthy

    def _assert_item_kept(self, env, report, kind):
        assert report["ok"] is False and report["error"]["type"] == kind, report
        assert env.security.items[ACTIVE_ITEM] == env.item
        assert env.read_enc(SLOT_2) is not None

    def test_a_backup_that_does_not_read_back(self, moved):
        moved.security.mangle = lambda value: value[:-1]
        self._assert_item_kept(moved, _reconcile(), "keychain_unavailable")
        assert moved.security.deleted == []

    def test_an_enc_that_does_not_read_back(self, moved, monkeypatch):
        moved.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=60))  # so the slot is rewritten
        store = ClaudeAccountSwitcher()._store
        monkeypatch.setattr(type(store), "_leftover_backup_enc", lambda self, num, email: "garbled")
        self._assert_item_kept(moved, _reconcile(), "refresh_failed")
        assert moved.security.deleted == []

    def test_a_failed_delete(self, moved):
        moved.security.delete_rc = 1
        self._assert_item_kept(moved, _reconcile(), "keychain_unavailable")

    def test_locks_that_stay_held(self, moved, monkeypatch):
        from claude_swap import migrate_store
        from claude_swap.exceptions import LockError

        def held(*args, **kwargs):
            raise LockError("held")

        monkeypatch.setattr(migrate_store, "claude_credentials_lock", held)
        before = moved.snapshot()
        report = _reconcile()
        assert report["error"]["type"] == "locked"
        assert moved.snapshot() == before

    def test_an_item_rewritten_before_its_delete_is_left_for_the_next_run(self, moved, monkeypatch):
        from claude_swap import macos_keychain

        real = macos_keychain.set_password
        newer = creds("AT-1C", "RT-1", expires_in_s=9500, mcpOAuth={"srv": {"accessToken": "x"}})

        def mcp_login_lands(service, account, value):
            real(service, account, value)
            if account.startswith("claude-code-credentials.backup-"):
                moved.security.items[ACTIVE_ITEM] = newer  # a write that takes no lock

        monkeypatch.setattr(macos_keychain, "set_password", mcp_login_lands)
        report = _reconcile()
        assert report["error"]["type"] == "keychain_item_changed"
        assert moved.security.items[ACTIVE_ITEM] == newer
        monkeypatch.setattr(macos_keychain, "set_password", real)
        report = _reconcile()
        assert report["ok"] is True
        assert moved.file.read_text() == newer


class TestBackupCap:
    def _old(self, healthy, n, value):
        healthy.security.items[("claude-swap", f"claude-code-credentials.backup-2026010{n}T000000Z")] = value

    def test_redundant_copies_past_five_go(self, healthy):
        from claude_swap import migrate_store

        kept = creds("AT-1B", "RT-1", expires_in_s=9000)
        for n in range(7):
            self._old(healthy, n, creds(f"AT-1-{n}", "RT-1"))  # the kept lineage: redundant
        healthy.security.items[("claude-swap", "slot-1-a@example.com.backup-20260101T000000Z")] = "s"
        healthy.security.items[ACTIVE_ITEM] = kept
        report = _reconcile()
        assert report["ok"] is True
        names = [a for (_, a) in healthy.security.items if a.startswith("claude-code-credentials.backup-")]
        assert len(names) == migrate_store.BACKUPS_KEPT == 5
        assert set(report["backups"]) <= set(names)  # this run's survive
        assert "claude-code-credentials.backup-20260100T000000Z" in report["backupsPruned"]
        assert ("claude-swap", "slot-1-a@example.com.backup-20260101T000000Z") in healthy.security.items

    def test_a_copy_that_may_be_the_only_live_token_stays(self, healthy):
        for n in range(7):
            self._old(healthy, n, creds(f"AT-L{n}", f"RT-L{n}"))  # other lineages, maybe live
        ClaudeAccountSwitcher()
        consumed_grants.reserve(oauth.credential_fingerprint(creds("x", "RT-L0")), ("a@example.com", ""))
        healthy.security.items[ACTIVE_ITEM] = creds("AT-1B", "RT-1", expires_in_s=9000)
        report = _reconcile()
        assert report["ok"] is True
        assert report["backupsPruned"] == ["claude-code-credentials.backup-20260100T000000Z"]  # spent
        for n in range(1, 7):
            assert ("claude-swap", f"claude-code-credentials.backup-2026010{n}T000000Z") in healthy.security.items


RUNNING = {
    "domain": "system", "installed": True, "managed": True, "loaded": True,
    "outdated": False, "lastExitCode": 0,
}
_REAL_KS_STATUS = ks.status


class TestDoctor:
    @pytest.fixture(autouse=True)
    def _darwin(self, darwin, monkeypatch):
        monkeypatch.setattr(ks, "status", lambda *a, **k: dict(RUNNING))  # keepalive runs
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
            "reconcileService", "keepaliveService", "keychainBackups", "lastReconcileError",
            "lastReconcileHint",
        }
        assert report["keychainBackups"] == 0 and report["lastReconcileError"] is None
        assert report["schemaVersion"] == 1
        assert report["ok"] is True and report["problems"] == []
        assert report["store"] == "file" and report["keychainItemPresent"] is False
        assert report["keychainLocked"] is True and report["fileExists"] is True
        if os.name == "posix":
            assert report["fileMode"] == "0600"
        assert report["slotsWithoutBackup"] == [] and report["sessionDirs"] == []
        assert report["reconcileService"]["installed"] is True
        assert report["reconcileService"]["managed"] is True
        assert report["keepaliveService"]["domain"] == "system"
        assert report["keepaliveService"]["loaded"] is True
        assert report["lastReconcileHint"] is None
        assert daemon.security.non_guard_calls() == []

    def test_keepalive_service_missing_with_no_job(self, healthy, monkeypatch):
        self._ready(healthy)
        monkeypatch.setattr(ks, "status", _REAL_KS_STATUS)
        assert self._problems(healthy) == ["keepalive_service_missing"]

    def test_keepalive_service_missing_while_the_agent_waits_for_a_login(self, healthy, monkeypatch):
        self._ready(healthy)
        monkeypatch.setattr(ks, "status", _REAL_KS_STATUS)
        assert ks.install(3600, False, program=PROGRAM)["action"] == "deferred"
        report = run_doctor(ClaudeAccountSwitcher())
        assert report["problems"] == ["keepalive_service_missing"]
        assert report["keepaliveService"]["installed"] is True
        assert report["keepaliveService"]["loaded"] is False

    @pytest.mark.parametrize("domain", ["gui", "system"])
    def test_either_loaded_job_is_enough(self, healthy, monkeypatch, domain):
        self._ready(healthy)
        monkeypatch.setattr(ks, "status", lambda *a, **k: {**RUNNING, "domain": domain})
        assert self._problems(healthy) == []

    def test_a_foreign_job_does_not_count(self, healthy, monkeypatch):
        self._ready(healthy)
        monkeypatch.setattr(ks, "status", lambda *a, **k: {**RUNNING, "managed": False})
        assert self._problems(healthy) == ["keepalive_service_missing"]

    def test_outside_the_file_store_keepalive_is_not_asked_for(self, env, monkeypatch):
        monkeypatch.setattr(ks, "status", _REAL_KS_STATUS)
        env.write_file(creds())
        assert self._problems(env) == ["not_file_store"]

    @pytest.mark.parametrize("running", [True, False])
    def test_an_ambiguous_reconcile_leaves_a_hint(self, healthy, monkeypatch, running):
        self._ready(healthy)
        if not running:
            monkeypatch.setattr(ks, "status", _REAL_KS_STATUS)
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        report = _reconcile()
        assert report["error"]["type"] == "reconcile_ambiguous"
        hint = report["hint"]
        assert "migrate-store --to file --keep keychain" in hint
        assert ("401" in hint) if running else ("was not running" in hint)
        doctor_report = run_doctor(ClaudeAccountSwitcher())
        assert doctor_report["lastReconcileHint"] == hint
        assert doctor_report["lastReconcileError"] == "reconcile_ambiguous"
        for token in TOKENS:
            assert token not in hint

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

    def test_reconcile_ambiguous(self, healthy):
        self._ready(healthy)
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        assert _reconcile()["error"]["type"] == "reconcile_ambiguous"
        report = run_doctor(ClaudeAccountSwitcher())
        assert report["problems"] == ["keychain_item_present", "reconcile_ambiguous"]
        assert report["lastReconcileError"] == "reconcile_ambiguous"

    def test_backups_are_counted(self, healthy):
        self._ready(healthy)
        healthy.security.items[("claude-swap", "claude-code-credentials.backup-20260101T000000Z")] = "x"
        healthy.security.items[("claude-swap", "account-1-a@example.com")] = "y"
        assert run_doctor(ClaudeAccountSwitcher())["keychainBackups"] == 1

    def test_an_unreadable_store_is_an_error_envelope(self, healthy, capsys, monkeypatch):
        from claude_swap import doctor

        def denied(*args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr(doctor, "get_credentials_path", denied)
        code, out, _ = run_cli(["doctor", "--json"], capsys)
        assert code == 1 and json_error_type(out) == "io_error"

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
def macos_services(tmp_path, monkeypatch, darwin):
    monkeypatch.setattr(ks, "SYSTEM_DIR", tmp_path / "LaunchDaemons")
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

    def test_cli_deferred_is_exit_3(self, healthy, capsys, darwin):
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

    def test_a_daemon_loaded_from_another_plist_is_left_alone(self, macos_services):
        calls = []
        with _launchctl(calls, loaded=True), pytest.raises(ks.ForeignServiceError):
            self._install(macos_services, calls)
        assert not any(call[0] == "sudo" for call in calls)

    def test_no_proxy_password_goes_into_the_daemon_plist(self, macos_services, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@proxy.example:3128")
        calls = []
        with _launchctl(calls), pytest.raises(ClaudeSwitchError, match="password"):
            self._install(macos_services, calls)
        assert not any(call[0] == "sudo" for call in calls)
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
        with _launchctl(calls):
            self._install(macos_services, calls)
        doc = plistlib.loads(ks.system_plist_path().read_bytes())
        assert doc["EnvironmentVariables"]["HTTPS_PROXY"] == "http://proxy.example:3128"

    @pytest.mark.parametrize("value", ["user:secret@proxy.example:3128", "http://user@proxy.example:3128"])
    def test_a_proxy_user_without_a_scheme_is_caught_too(self, macos_services, monkeypatch, value):
        monkeypatch.setenv("https_proxy", value)
        with _launchctl([]), pytest.raises(ClaudeSwitchError, match="password"):
            self._install(macos_services, [])

    def test_a_plist_holding_a_proxy_password_is_rewritten(self, macos_services, monkeypatch):
        with _launchctl([]):
            self._install(macos_services, [])
        doc = plistlib.loads(ks.system_plist_path().read_bytes())
        doc["EnvironmentVariables"]["HTTPS_PROXY"] = "http://u:p@proxy.example:1"  # a 0.3.0 install
        ks.system_plist_path().write_bytes(plistlib.dumps(doc))
        with _launchctl([], loaded=True):
            assert self._install(macos_services, [])["action"] == "updated"
        assert "HTTPS_PROXY" not in plistlib.loads(ks.system_plist_path().read_bytes())["EnvironmentVariables"]

    def test_a_failed_bootstrap_removes_the_new_plist(self, macos_services):
        calls = []

        def run(argv, **kwargs):
            if argv[:3] == ["sudo", "launchctl", "bootstrap"]:
                calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 5, "", "Bootstrap failed: 5")
            return real(argv, **kwargs)

        with _launchctl(calls) as fake:
            real = fake.side_effect
            fake.side_effect = run
            with pytest.raises(ClaudeSwitchError, match="bootstrap"):
                self._install(macos_services, calls)
        assert not ks.system_plist_path().exists()

    def test_a_failed_bootstrap_on_update_puts_the_old_plist_back(self, macos_services):
        with _launchctl([]):
            self._install(macos_services, [])
        before = ks.system_plist_path().read_bytes()

        def run(argv, **kwargs):
            if argv[:3] == ["sudo", "launchctl", "bootstrap"] and b"1234" in ks.system_plist_path().read_bytes():
                return subprocess.CompletedProcess(argv, 5, "", "Bootstrap failed: 5")
            return real(argv, **kwargs)

        with _launchctl([], loaded=True) as fake:
            real = fake.side_effect
            fake.side_effect = run
            with pytest.raises(ClaudeSwitchError, match="bootstrap"):
                ks.install(1234, False, macos_services, UID, PROGRAM, system=True, user="kgolf")
        assert ks.system_plist_path().read_bytes() == before

    def test_config_refuses_to_leave_the_file_store_under_the_daemon(self, healthy, capsys, macos_services):
        with _launchctl([]):
            self._install(macos_services, [])
        code, _, err = run_cli(["config", "unset", "credentials.store"], capsys)
        assert code == 1 and "keepalive --uninstall-service --system" in err
        assert healthy.stored_setting() == "file"
        code, _, _ = run_cli(["config", "set", "credentials.store", "auto"], capsys)
        assert code == 1 and healthy.stored_setting() == "file"

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
    def test_default_installs_both_services_and_reports_doctor(self, split, capsys, darwin):
        code, out, err = run_cli(["migrate-store", "--to", "file", "--keep", "file", "--json"], capsys)
        report = json.loads(out)
        assert code == 3, err  # migrated; the agents load at the next login
        assert report["ok"] is True
        assert report["reconcileService"]["action"] == "deferred"
        assert report["keepaliveService"]["action"] == "deferred"
        assert report["keepaliveService"]["domain"] == "gui"
        assert launch_agent.plist_path(rs.LABEL).exists()
        assert launch_agent.plist_path(ks.LABEL).exists()
        # Written but not loaded: no GUI session here.
        assert report["doctor"]["problems"] == ["keepalive_service_missing"]

    def test_an_existing_keepalive_job_is_left_as_it_is(self, split, capsys, darwin, monkeypatch):
        monkeypatch.setattr(ks, "status", lambda *a, **k: dict(RUNNING))
        code, out, _ = run_cli(["migrate-store", "--to", "file", "--keep", "file", "--json"], capsys)
        report = json.loads(out)
        assert report["keepaliveService"] == {"action": "present", "domain": "system", "loaded": True}
        assert not launch_agent.plist_path(ks.LABEL).exists()

    def test_no_keepalive_installs_no_keepalive(self, split, capsys, darwin):
        code, out, _ = run_cli(
            ["migrate-store", "--to", "file", "--keep", "file", "--no-keepalive", "--no-reconcile", "--json"],
            capsys,
        )
        report = json.loads(out)
        assert code == 0 and report["keepaliveService"] is None
        assert not launch_agent.plist_path(ks.LABEL).exists()
        assert report["doctor"]["problems"] == ["reconcile_service_missing", "keepalive_service_missing"]

    def test_text_output_points_at_the_daemon(self, split, capsys, darwin):
        code, out, _ = run_cli(["migrate-store", "--to", "file", "--keep", "file"], capsys)
        assert code == 3
        assert "keepalive --install-service --system" in out

    def test_without_reconcile_installs_nothing(self, split, capsys):
        code, out, _ = run_cli(
            ["migrate-store", "--to", "file", "--keep", "file", "--no-reconcile", "--no-keepalive", "--json"],
            capsys,
        )
        report = json.loads(out)
        assert code == 0 and report["reconcileService"] is None
        assert not launch_agent.plist_path(rs.LABEL).exists()
        assert "reconcile_service_missing" in report["doctor"]["problems"]

    def test_a_failing_doctor_does_not_hide_a_done_migration(self, split, capsys, monkeypatch):
        from claude_swap import doctor

        def broken(switcher):
            raise PermissionError("denied")

        monkeypatch.setattr(doctor, "run_doctor", broken)
        code, out, _ = run_cli(
            ["migrate-store", "--to", "file", "--keep", "file", "--no-reconcile", "--no-keepalive", "--json"], capsys
        )
        report = json.loads(out)
        assert code == 0 and report["ok"] is True
        assert report["doctor"]["ok"] is None and report["doctor"]["error"]["type"] == "io_error"

    def test_with_reconcile_is_gone(self, split, capsys):
        assert run_cli(["migrate-store", "--to", "file", "--keep", "file", "--with-reconcile"], capsys)[0] == 2

    def test_dry_run_installs_nothing(self, split, capsys):
        code, out, _ = run_cli(["migrate-store", "--to", "file", "--keep", "file", "--dry-run", "--json"], capsys)
        report = json.loads(out)
        assert code == 0 and report["reconcileService"] is None and report["keepaliveService"] is None
        assert not launch_agent.plist_path(rs.LABEL).exists()
        assert not launch_agent.plist_path(ks.LABEL).exists()


class TestKeepaliveBeatsClaudeCode:
    """Claude Code 2.1.325 refreshes only when the stored token is within 5 minutes of its
    expiry, after re-reading storage (`$O(e,n=Date.now()){...return n+300000>=e}`). A keepalive
    job that runs every INTERVAL_S and refreshes within DEFAULT_AHEAD_S keeps the file's
    token out of that window, so Claude Code finds it fresh and never refreshes itself."""

    def test_the_constants_leave_room(self):
        from claude_swap.keepalive import CLAUDE_CODE_REFRESH_WINDOW_S, DEFAULT_AHEAD_S

        assert CLAUDE_CODE_REFRESH_WINDOW_S == 300
        # A refresh lands at the first run with less than DEFAULT_AHEAD_S left, at worst
        # one interval past that line.
        assert DEFAULT_AHEAD_S - ks.INTERVAL_S > CLAUDE_CODE_REFRESH_WINDOW_S
        # Room for at least three failed runs (network, a held lock) before Claude Code's window.
        assert (DEFAULT_AHEAD_S - CLAUDE_CODE_REFRESH_WINDOW_S) // ks.INTERVAL_S >= 3

    def test_a_run_one_interval_late_still_refreshes_outside_the_window(self):
        from claude_swap.keepalive import CLAUDE_CODE_REFRESH_WINDOW_S, DEFAULT_AHEAD_S, _due

        assert not _due(creds(expires_in_s=DEFAULT_AHEAD_S + 60), DEFAULT_AHEAD_S)
        late = DEFAULT_AHEAD_S + 60 - ks.INTERVAL_S
        assert _due(creds(expires_in_s=late), DEFAULT_AHEAD_S)
        assert late > CLAUDE_CODE_REFRESH_WINDOW_S

    def test_the_installed_job_uses_these_constants(self, tmp_path):
        from claude_swap.keepalive import DEFAULT_AHEAD_S

        doc = plistlib.loads(ks.build(PROGRAM, DEFAULT_AHEAD_S, False, tmp_path))
        assert doc["StartInterval"] == ks.INTERVAL_S
        assert doc["ProgramArguments"][-2:] == ["--ahead", str(int(DEFAULT_AHEAD_S))]
