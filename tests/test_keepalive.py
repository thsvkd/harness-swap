"""`cswap keepalive`: one refresher, both stores on one generation, a report that
never carries a token. Every test runs on a temp HOME with the Keychain fake and a
fake token endpoint."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import threading
import time
import urllib.error
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from claude_swap import (
    claude_locks,
    cli,
    consumed_grants,
    keepalive,
    macos_keychain,
    oauth,
)
from claude_swap.keepalive import run_keepalive
from claude_swap.models import Platform
from claude_swap.settings import set_setting
from claude_swap.switcher import ClaudeAccountSwitcher

from .keychain_helpers import ACTIVE_ITEM, creds, macos_store, snapshot

SLOT = ("1", "a@example.com")
IDENTITY = {"1": ("a@example.com", "")}
NEAR = 600  # inside the default --ahead, outside Claude Code's 5 minutes
OWN_ACCOUNT = {"uuid": "uuid-1", "email": "a@example.com", "organizationUuid": ""}
OTHER_ACCOUNT = {"uuid": "uuid-9", "email": "z@example.com", "organizationUuid": ""}


class TokenEndpoint:
    """Fake OAuth token endpoint; counts POSTs."""

    def __init__(self):
        self.posts = []
        self.failure = None
        self.account = None

    def __call__(self, request, timeout=None):
        self.posts.append(json.loads(request.data))
        if self.failure:
            raise self.failure
        body = {
            "access_token": "sk-ant-oat01-ACCESS-NEW",
            "refresh_token": "sk-ant-ort01-REFRESH-NEW",
            "expires_in": 28800,
        }
        if self.account:
            body["account"] = self.account
        return io.BytesIO(json.dumps(body).encode())


@pytest.fixture
def endpoint(monkeypatch):
    fake = TokenEndpoint()
    monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", fake)
    return fake


@pytest.fixture
def env(temp_home, block_real_keychain, endpoint):
    class Env:
        home = temp_home
        keychain = block_real_keychain
        post = endpoint
        store = macos_store(temp_home)
        file = temp_home / ".claude" / ".credentials.json"

        def active(self, value):
            self.keychain.data[ACTIVE_ITEM] = value

        def keychain_value(self):
            return self.keychain.data.get(ACTIVE_ITEM)

        def backup(self):
            return self.store._read_account_credentials(*SLOT)

        def backup_in_keychain(self):
            return self.keychain.data[("claude-swap", f"account-{SLOT[0]}-{SLOT[1]}")]

        def report_on_disk(self):
            return json.loads((self.store.backup_dir / "cache" / "keepalive.json").read_text())

        def run(self, **kwargs):
            return run_keepalive(self.store, **kwargs)

    return Env()


def access_token(credentials):
    return oauth.extract_oauth_data(credentials)["accessToken"]


class TestSync:
    def test_nothing_to_do(self, env):
        same = creds()
        env.active(same)
        env.file.write_text(same)
        env.store._write_account_credentials(*SLOT, same)
        report = env.run()
        assert report["ok"] is True and report["error"] is None
        assert report["action"] == "none" and report["note"] is None
        assert report["activeSlot"] == 1
        assert report["accessExpiresAt"] and report["loginExpiresAt"]
        assert env.post.posts == []

    def test_same_lineage_keychain_newer_syncs_the_file(self, env):
        env.active(creds("sk-new", expires_in_s=7200))
        env.file.write_text(creds("sk-old", expires_in_s=3700))
        report = env.run()
        assert report["action"] == "synced-file"
        assert report["note"] is None
        assert env.file.read_text() == env.keychain_value()
        assert env.store._store._list_unclaimed_credentials() == {}

    def test_same_lineage_file_newer_syncs_the_keychain(self, env):
        newer = creds("sk-new", expires_in_s=7200)
        env.active(creds("sk-old", expires_in_s=3700))
        env.file.write_text(newer)
        report = env.run()
        assert report["action"] == "synced-keychain"
        assert access_token(env.keychain_value()) == "sk-new"
        assert access_token(env.file.read_text()) == "sk-new"

    def test_tie_goes_to_the_keychain(self, env):
        env.active(creds("sk-k", "rt", expires_in_s=7200))
        env.file.write_text(env.keychain_value().replace("sk-k", "sk-f"))
        env.run()
        assert access_token(env.file.read_text()) == "sk-k"

    def test_only_the_file_exists_writes_the_keychain(self, env):
        env.file.write_text(creds("sk-file"))
        report = env.run()
        assert report["action"] == "synced-keychain"
        assert env.keychain_value() == env.file.read_text()

    def test_different_account_stashes_the_loser_then_syncs(self, env, monkeypatch):
        winner = creds("sk-win", "rt-win", expires_in_s=7200)
        loser = creds("sk-lose", "rt-lose", expires_in_s=3700)
        env.active(loser)
        env.file.write_text(winner)
        monkeypatch.setattr(oauth, "fetch_oauth_profile", lambda token: (
            OTHER_ACCOUNT if token == "sk-lose" else OWN_ACCOUNT
        ))
        report = env.run()
        assert report["action"] == "synced-keychain"
        assert report["note"] == "split_brain"
        assert report["ok"] is True
        assert access_token(env.keychain_value()) == "sk-win"
        stash = env.store._store._list_unclaimed_credentials()
        assert len(stash) == 1
        entry = next(iter(stash))
        assert env.store._store._read_unclaimed_credential(entry)[0] == loser

    def test_different_account_file_loses_too(self, env, monkeypatch):
        env.active(creds("sk-win", "rt-win", expires_in_s=7200))
        loser = creds("sk-lose", "rt-lose", expires_in_s=3700)
        env.file.write_text(loser)
        monkeypatch.setattr(oauth, "fetch_oauth_profile", lambda token: (
            OTHER_ACCOUNT if token == "sk-lose" else OWN_ACCOUNT
        ))
        report = env.run()
        assert report["action"] == "synced-file" and report["note"] == "split_brain"
        assert env.file.read_text() == env.keychain_value()

    def test_a_failed_stash_syncs_nothing(self, env, monkeypatch):
        keychain_copy = creds("sk-lose", "rt-lose", expires_in_s=3700)
        file_copy = creds("sk-win", "rt-win", expires_in_s=7200)
        env.active(keychain_copy)
        env.file.write_text(file_copy)
        monkeypatch.setattr(
            env.store._store,
            "_write_unclaimed_credential",
            lambda *a: (_ for _ in ()).throw(OSError("disk full")),
        )
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "split_brain"
        assert env.keychain_value() == keychain_copy
        assert env.file.read_text() == file_copy

    def test_a_wiped_copy_never_wins(self, env):
        # Claude Code empties the token fields on invalid_grant, keeping the date.
        wiped = json.loads(creds("x", "y", expires_in_s=99999))
        wiped["claudeAiOauth"].update(accessToken="", refreshToken="")
        env.active(json.dumps(wiped))
        env.file.write_text(creds("sk-good", "rt-good"))
        report = env.run()
        assert report["action"] == "synced-keychain"
        assert access_token(env.keychain_value()) == "sk-good"

    def test_shared_fields_stay_with_the_live_store(self, env):
        env.active(creds("sk-old", expires_in_s=3700, mcpOAuth={"s": "live"}))
        env.file.write_text(
            creds("sk-new", expires_in_s=7200, mcpOAuth={"s": "stale"}, trustedDeviceToken="dev")
        )
        env.run()
        for stored in (env.keychain_value(), env.file.read_text()):
            data = json.loads(stored)
            assert data["claudeAiOauth"]["accessToken"] == "sk-new"
            assert data["mcpOAuth"] == {"s": "live"}
            assert data["trustedDeviceToken"] == "dev"  # account-bound: goes with the login

    def test_ensure_file_creates_it_at_0600(self, env):
        env.active(creds())
        report = env.run(ensure_file=True)
        assert report["action"] == "created-file"
        assert env.file.read_text() == env.keychain_value()
        if os.name == "posix":
            assert stat.S_IMODE(env.file.stat().st_mode) == 0o600

    def test_no_file_is_created_without_ensure_file(self, env):
        env.active(creds())
        assert env.run()["action"] == "none"
        assert not env.file.exists()


class TestRefresh:
    def test_near_expiry_posts_once_and_writes_everywhere(self, env):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.file.write_text(near)
        env.store._write_account_credentials(*SLOT, near)
        report = env.run()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert len(env.post.posts) == 1
        assert env.post.posts[0]["refresh_token"] == "sk-ant-ort01-REFRESH-1"
        for stored in (env.keychain_value(), env.file.read_text(), env.backup()):
            assert access_token(stored) == "sk-ant-oat01-ACCESS-NEW"
        assert report["accessExpiresAt"] > time.strftime("%Y-%m-%dT", time.gmtime())
        # A login's own expiry survives the rotation, and the store remembers it.
        assert report["loginExpiresAt"] == oauth.login_expires_at_iso(env.keychain_value())
        entry = env.store._usage_store.entries(IDENTITY)["1"]
        assert entry.login_expires_at == report["loginExpiresAt"]

    def test_fresh_token_is_left_alone(self, env):
        env.active(creds(expires_in_s=7200))
        assert env.run()["action"] == "none"
        assert env.post.posts == []

    def test_ahead_decides(self, env):
        env.active(creds(expires_in_s=7200))
        assert env.run(ahead=100)["action"] == "none"
        assert env.post.posts == []
        env.run(ahead=7300)
        assert len(env.post.posts) == 1

    def test_a_slot_a_few_generations_behind_is_not_posted(self, env):
        """The slot's copy carries another access token of the same lineage; the
        gate must not read that as "someone already refreshed" and hand it back."""
        env.active(creds("sk-live", expires_in_s=NEAR))
        env.store._write_account_credentials(*SLOT, creds("sk-older", expires_in_s=NEAR - 100))
        report = env.run()
        assert report["action"] == "refreshed" and len(env.post.posts) == 1
        assert access_token(env.keychain_value()) == "sk-ant-oat01-ACCESS-NEW"
        assert access_token(env.backup()) == "sk-ant-oat01-ACCESS-NEW"

    def test_slot_on_an_older_lineage_is_healed_by_the_token_endpoint_identity(self, env):
        env.active(creds("sk-live", "rt-live", expires_in_s=NEAR))
        env.store._write_account_credentials(*SLOT, creds("sk-old", "rt-old", expires_in_s=-100))
        env.post.account = {"uuid": "uuid-1", "email_address": "a@example.com"}
        report = env.run()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert env.post.posts[0]["refresh_token"] == "rt-live"
        assert access_token(env.backup()) == "sk-ant-oat01-ACCESS-NEW"

    def test_token_answering_as_another_account_is_reported_and_not_stored(self, env):
        slot_copy = creds("sk-old", "rt-old", expires_in_s=-100)
        env.active(creds("sk-live", "rt-live", expires_in_s=NEAR))
        env.store._write_account_credentials(*SLOT, slot_copy)
        env.post.account = {"uuid": "someone-else", "email_address": "z@example.com"}
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "unmanaged"
        assert access_token(env.keychain_value()) == "sk-ant-oat01-ACCESS-NEW"
        assert env.backup() == slot_copy

    def test_racing_writer_rotates_before_the_lock_no_post(self, env, monkeypatch):
        rotated = creds("sk-raced", "rt-raced", expires_in_s=28000)
        env.active(creds(expires_in_s=NEAR))
        real = keepalive.claude_credentials_lock

        @contextmanager
        def racing_lock():
            with real():
                env.active(rotated)  # Claude Code finished its refresh as we took the lock
                yield

        monkeypatch.setattr(keepalive, "claude_credentials_lock", racing_lock)
        report = env.run()
        assert env.post.posts == []
        assert report["ok"] is True and report["action"] == "none"
        assert env.keychain_value() == rotated

    def test_invalid_grant_is_relogin_required_and_wipes_nothing(self, env):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.file.write_text(near)
        env.store._write_account_credentials(*SLOT, near)
        env.post.failure = urllib.error.HTTPError(
            "u", 400, "bad", {}, io.BytesIO(b'{"error":"invalid_grant"}')
        )
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "relogin_required"
        assert len(env.post.posts) == 1
        assert env.keychain_value() == near
        assert env.file.read_text() == near
        assert env.backup() == near
        entry = env.store._usage_store.entries(IDENTITY)["1"]
        assert entry.auth_dead_strikes == 1

    def test_network_error_is_refresh_failed(self, env):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.store._write_account_credentials(*SLOT, near)
        env.post.failure = urllib.error.URLError("down")
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "refresh_failed"
        assert env.keychain_value() == near and env.backup() == near
        assert env.store._usage_store.entries(IDENTITY)["1"].auth_dead_strikes == 0

    def test_a_refresh_heals_an_earlier_dead_token_strike(self, env):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.store._write_account_credentials(*SLOT, near)
        from claude_swap.usage_store import FetchRecord

        env.store._usage_store.record(
            {"1": FetchRecord(error="invalid_grant", struck_fp="x")}, IDENTITY
        )
        env.run()
        assert env.store._usage_store.entries(IDENTITY)["1"].auth_dead_strikes == 0

    def test_keychain_write_failure_after_the_post_has_no_fallback_and_recovers(
        self, env, monkeypatch
    ):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.file.write_text(near)
        env.store._write_account_credentials(*SLOT, near)
        real_set = env.keychain.set_password

        def locked_active_item(service, account, password):
            if service == ACTIVE_ITEM[0]:
                raise macos_keychain.KeychainError("-25308")
            real_set(service, account, password)

        monkeypatch.setattr(macos_keychain, "set_password", locked_active_item)
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "keychain_unavailable"
        assert env.file.read_text() == near  # no plaintext fallback
        assert len(env.post.posts) == 1

        # The next run (a new process) must not POST the spent grant: the slot
        # holds its successor.
        monkeypatch.setattr(macos_keychain, "set_password", real_set)
        fresh = ClaudeAccountSwitcher()
        fresh.platform = Platform.MACOS
        report = run_keepalive(fresh)
        assert access_token(env.backup_in_keychain()) == "sk-ant-oat01-ACCESS-NEW"
        assert report["ok"] is True and report["action"] == "synced-keychain"
        assert len(env.post.posts) == 1
        assert access_token(env.keychain_value()) == "sk-ant-oat01-ACCESS-NEW"
        assert access_token(env.file.read_text()) == "sk-ant-oat01-ACCESS-NEW"

    def test_unmanaged_write_failure_stashes_the_spent_grants_successor(self, temp_home, block_real_keychain, endpoint, monkeypatch):
        s = macos_store(temp_home, active="stranger@example.com")
        block_real_keychain.data[ACTIVE_ITEM] = creds(expires_in_s=NEAR)
        monkeypatch.setattr(
            macos_keychain,
            "set_password",
            lambda *a: (_ for _ in ()).throw(macos_keychain.KeychainError("-25308")),
        )
        assert run_keepalive(s)["error"]["type"] == "keychain_unavailable"
        stash = s._store._list_unclaimed_credentials()
        assert len(stash) == 1
        kept, _ = s._store._read_unclaimed_credential(next(iter(stash)))
        assert access_token(kept) == "sk-ant-oat01-ACCESS-NEW"


class TestLocks:
    def test_claude_code_lock_held_waits_then_reports_locked(self, env, monkeypatch):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        os.mkdir(claude_locks.oauth_refresh_lock_dir())
        monkeypatch.setattr(claude_locks, "DEFAULT_TIMEOUT_S", 0.3)
        started = time.monotonic()
        report = env.run()
        assert time.monotonic() - started >= 0.3
        assert report["ok"] is False and report["error"]["type"] == "locked"
        assert env.post.posts == []
        assert env.keychain_value() == near

    def test_lock_released_in_time_goes_ahead(self, env):
        env.active(creds(expires_in_s=NEAR))
        lock_dir = claude_locks.oauth_refresh_lock_dir()
        os.mkdir(lock_dir)
        threading.Timer(0.2, os.rmdir, [lock_dir]).start()
        report = env.run()
        assert report["ok"] is True and report["action"] == "refreshed"

    def test_slot_consume_lock_is_held_during_the_post(self, env, monkeypatch):
        from claude_swap.locking import FileLock

        env.active(creds(expires_in_s=NEAR))
        env.store._write_account_credentials(*SLOT, env.keychain_value())
        seen = {}
        real = env.post.__class__.__call__

        def probing(self, request, timeout=None):
            lock = FileLock(env.store.credentials_dir / ".consume-1.lock")
            seen["consume"] = lock.acquire(timeout=0)
            if seen["consume"]:
                lock.release()
            seen["cc"] = claude_locks.oauth_refresh_lock_dir().exists()
            seen["timeout"] = timeout
            return real(self, request, timeout)

        monkeypatch.setattr(TokenEndpoint, "__call__", probing)
        env.run()
        assert seen == {"consume": False, "cc": True, "timeout": 6.0}

    def test_locks_are_released_afterwards(self, env):
        env.active(creds(expires_in_s=NEAR))
        env.run()
        assert not claude_locks.oauth_refresh_lock_dir().exists()
        assert not claude_locks.credentials_lock_dir().exists()


class TestPreflight:
    def test_unreachable_changes_nothing_even_with_the_setting_off(self, env):
        env.active(creds("sk-k", expires_in_s=NEAR))
        env.file.write_text(creds("sk-f", expires_in_s=NEAR - 10))
        env.keychain.reachable = False
        before = snapshot(env.home, env.keychain)
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "keychain_unavailable"
        assert report["activeSlot"] == 1
        assert env.post.posts == []
        assert snapshot(env.home, env.keychain) == before
        assert env.report_on_disk()["error"]["type"] == "keychain_unavailable"

    def test_a_failing_keychain_read_changes_nothing(self, env, monkeypatch):
        env.file.write_text(creds())
        monkeypatch.setattr(
            macos_keychain,
            "get_password",
            lambda *a: (_ for _ in ()).throw(macos_keychain.KeychainError("denied")),
        )
        monkeypatch.setattr("claude_swap.credentials._ACTIVE_READ_RETRY_DELAY", 0)
        report = env.run()
        assert report["error"]["type"] == "keychain_unavailable"
        assert env.keychain.data == {}


class TestOtherStates:
    def test_no_credentials(self, env):
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "no_credentials"

    def test_unmanaged_login_is_still_kept_fresh(self, temp_home, block_real_keychain, endpoint):
        s = macos_store(temp_home, active="stranger@example.com")
        file_path = temp_home / ".claude" / ".credentials.json"
        block_real_keychain.data[ACTIVE_ITEM] = creds("sk-k", expires_in_s=NEAR)
        file_path.write_text(creds("sk-f", expires_in_s=NEAR - 10))
        report = run_keepalive(s)
        assert report["ok"] is False and report["error"]["type"] == "unmanaged"
        assert report["activeSlot"] is None
        assert report["action"] == "refreshed"
        assert len(endpoint.posts) == 1
        for stored in (block_real_keychain.data[ACTIVE_ITEM], file_path.read_text()):
            assert access_token(stored) == "sk-ant-oat01-ACCESS-NEW"

    def test_api_key_login_has_nothing_to_do(self, env):
        env.keychain.data[("Claude Code", ACTIVE_ITEM[1])] = "sk-ant-api03-KEY"
        report = env.run()
        assert report["ok"] is True and report["action"] == "none"
        assert report["note"] == "api_key"

    def test_setup_token_without_expiry_is_not_refreshed(self, env):
        env.active(json.dumps({"claudeAiOauth": {"accessToken": "sk-ant-oat01-SETUP"}}))
        report = env.run()
        assert report["ok"] is True and report["action"] == "none"
        assert env.post.posts == []

    def test_custom_profile_is_refused_before_touching_anything(self, env, monkeypatch, tmp_path):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "other"))
        env.active(creds(expires_in_s=NEAR))
        report = env.run()
        assert report["error"]["type"] == "refresh_failed"
        assert env.post.posts == []

    def test_linux_refreshes_the_file_only(self, env):
        env.store.platform = Platform.LINUX
        near = creds(expires_in_s=NEAR)
        env.file.write_text(near)
        env.store._write_account_credentials(*SLOT, near)
        report = env.run()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert len(env.post.posts) == 1
        assert access_token(env.file.read_text()) == "sk-ant-oat01-ACCESS-NEW"
        assert access_token(env.backup()) == "sk-ant-oat01-ACCESS-NEW"
        assert env.keychain.data == {}

    def test_linux_needs_no_preflight(self, env):
        env.store.platform = Platform.LINUX
        env.keychain.reachable = False
        env.file.write_text(creds())
        assert env.run()["ok"] is True


class TestReport:
    def test_shape_and_mode(self, env):
        env.active(creds())
        report = env.run()
        path = env.store.backup_dir / "cache" / "keepalive.json"
        assert json.loads(path.read_text()) == report
        assert list(report) == [
            "schemaVersion", "checkedAt", "ok", "action", "note", "activeSlot",
            "accessExpiresAt", "loginExpiresAt", "error",
        ]
        assert report["schemaVersion"] == 1 and isinstance(report["checkedAt"], float)
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_replaced_atomically(self, env):
        env.active(creds())
        env.run()
        path = env.store.backup_dir / "cache" / "keepalive.json"
        inode = path.stat().st_ino
        env.run()
        assert path.stat().st_ino != inode  # a rename, never an in-place rewrite
        assert [p.name for p in path.parent.iterdir() if "keepalive" in p.name] == ["keepalive.json"]

    def test_written_on_failure_too(self, env):
        env.run()
        on_disk = env.report_on_disk()
        assert on_disk["ok"] is False and on_disk["error"]["type"] == "no_credentials"

    def test_dry_run_changes_nothing_and_says_so(self, env, monkeypatch):
        env.active(creds("sk-k", "rt-a", expires_in_s=NEAR))
        env.file.write_text(creds("sk-f", "rt-b", expires_in_s=NEAR - 10))
        monkeypatch.setattr(oauth, "fetch_oauth_profile", lambda token: (
            OTHER_ACCOUNT if token == "sk-f" else OWN_ACCOUNT
        ))
        before = snapshot(env.home, env.keychain)
        report = env.run(dry_run=True, ensure_file=True)
        assert report["dryRun"] is True
        assert report["action"] == "refreshed" and report["note"] == "split_brain"
        assert env.post.posts == []
        assert snapshot(env.home, env.keychain) == before
        assert env.report_on_disk()["dryRun"] is True

    def test_dry_run_takes_no_lock(self, env):
        env.active(creds())
        os.mkdir(claude_locks.oauth_refresh_lock_dir())
        assert env.run(dry_run=True)["ok"] is True

    def test_write_failure_does_not_turn_into_a_crash(self, env, monkeypatch):
        env.active(creds())
        monkeypatch.setattr(
            keepalive, "atomic_write_json",
            lambda *a: (_ for _ in ()).throw(OSError("read-only")),
        )
        assert env.run()["ok"] is True


class TestCli:
    def _main(self, argv, capsys):
        code = 0
        with (
            patch("claude_swap.models.Platform.detect", return_value=Platform.MACOS),
            patch.object(sys, "argv", ["cswap", "keepalive", *argv]),
        ):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return code, *capsys.readouterr()

    def test_json_matches_the_file_and_exit_zero(self, env, capsys):
        env.active(creds())
        code, out, _ = self._main(["--json"], capsys)
        assert code == 0
        assert json.loads(out) == env.report_on_disk()

    def test_failure_exits_one(self, env, capsys):
        code, out, _ = self._main(["--json"], capsys)
        assert code == 1 and json.loads(out)["error"]["type"] == "no_credentials"

    def test_human_output(self, env, capsys):
        env.active(creds())
        code, out, _ = self._main([], capsys)
        assert code == 0 and "Keepalive: none" in out
        env.keychain.reachable = False
        code, _, err = self._main([], capsys)
        assert code == 1 and "GUI session" in err

    def test_flags_reach_the_run(self, env, capsys):
        env.active(creds(expires_in_s=7200))
        code, out, _ = self._main(["--ahead", "7300", "--ensure-file", "--dry-run", "--json"], capsys)
        report = json.loads(out)
        assert code == 0 and report["dryRun"] is True and report["action"] == "refreshed"
        assert not env.file.exists()

    @pytest.mark.parametrize("bad", ["-1", "nan", "inf"])
    def test_bad_ahead_is_a_usage_error(self, env, capsys, bad):
        code, _, err = self._main([f"--ahead={bad}"], capsys)
        assert code == 2 and "--ahead" in err

    def test_no_token_or_home_path_anywhere(self, env, capsys):
        """Every outcome, stdout, stderr and the file."""
        refresh = "sk-ant-ort01-SECRETREFRESH"
        generation = iter(range(100))

        def reset():
            # A fresh grant each time: a spent one is refused before any POST.
            n = next(generation)
            secret = creds(f"sk-ant-oat01-SECRET{n}", f"{refresh}{n}", expires_in_s=NEAR)
            env.active(secret)
            env.file.write_text(secret)
            env.store._write_account_credentials(*SLOT, secret)

        def outcomes():
            reset()
            yield  # refreshed
            reset()
            env.file.write_text(creds("sk-ant-oat01-SECRETOTHER", "sk-ant-ort01-SECRETOTHERRT"))
            yield  # split brain
            reset()
            env.post.failure = urllib.error.URLError(f"token {refresh} refused")
            yield  # refresh_failed
            reset()
            env.post.failure = urllib.error.HTTPError(
                "u", 400, "bad", {}, io.BytesIO(b'{"error":"invalid_grant"}')
            )
            yield  # relogin_required
            reset()
            env.keychain.reachable = False
            yield  # keychain_unavailable

        seen = []
        for _ in outcomes():
            _, out, err = self._main(["--json", "--debug"], capsys)
            on_disk = (env.store.backup_dir / "cache" / "keepalive.json").read_text()
            seen.append(json.loads(out)["error"] and json.loads(out)["error"]["type"])
            for text in (out, err, on_disk):
                assert "SECRET" not in text
                assert "sk-ant" not in text
                assert str(env.home) not in text
        assert seen[-1] == "keychain_unavailable"
        assert "relogin_required" in seen and "refresh_failed" in seen

    def test_settings_mode_does_not_change_keepalive(self, env, capsys):
        set_setting(env.store.backup_dir, "credentials.requireKeychain", "true")
        env.active(creds())
        code, *_ = self._main(["--json"], capsys)
        assert code == 0


class RotatingEndpoint:
    """Rotates like the real one: a consumed refresh token gets invalid_grant."""

    def __init__(self):
        self.posts = []
        self.spent = set()

    def __call__(self, request, timeout=None):
        token = json.loads(request.data)["refresh_token"]
        self.posts.append(token)
        if token in self.spent:
            raise urllib.error.HTTPError(
                "u", 400, "bad", {}, io.BytesIO(b'{"error":"invalid_grant"}')
            )
        self.spent.add(token)
        n = len(self.spent)
        return io.BytesIO(json.dumps({
            "access_token": f"AT-{n}", "refresh_token": f"RT-{n}", "expires_in": 28800,
        }).encode())


@pytest.fixture
def rotating(monkeypatch):
    fake = RotatingEndpoint()
    monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", fake)
    monkeypatch.setattr("claude_swap.credentials._ACTIVE_READ_RETRY_DELAY", 0)
    return fake


def new_process():
    s = ClaudeAccountSwitcher()
    s.platform = Platform.MACOS
    return s


def strikes(s):
    return s._usage_store.entries(IDENTITY)["1"].auth_dead_strikes


def _active_item_write_fails(keychain):
    real = keychain.set_password

    def set_password(service, account, password):
        if service == ACTIVE_ITEM[0]:
            raise macos_keychain.KeychainError("-25308")
        real(service, account, password)

    return set_password


class TestConsumedGrantIsNeverPostedAgain:
    def test_R1_one_transient_read_failure_does_not_strand_the_successor(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        near = creds("AT-0", "RT-0", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = near
        s._write_account_credentials(*SLOT, near)
        real_get = macos_keychain.get_password
        failures = [macos_keychain.KeychainError("transient")]

        def flaky(service, account):
            if (service, account) == ACTIVE_ITEM and failures:
                raise failures.pop()
            return real_get(service, account)

        monkeypatch.setattr(macos_keychain, "get_password", flaky)
        report = run_keepalive(s)
        assert report["ok"] is True and report["action"] == "refreshed"
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"

        second = new_process()
        assert run_keepalive(second)["ok"] is True
        assert rotating.posts == ["RT-0"]
        assert strikes(second) == 0

    def test_R1_a_backoff_armed_before_the_run_is_cleared(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        near = creds("AT-0", "RT-0", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = near
        s._write_account_credentials(*SLOT, near)
        # A failure in this process before keepalive proved reachability.
        s._store._keychain_usable_cache = False
        s._store._keychain_disabled_until = time.monotonic() + 60
        report = run_keepalive(s)
        assert report["ok"] is True and report["action"] == "refreshed"
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"
        assert rotating.posts == ["RT-0"]

    def test_R1_routing_is_not_sticky_when_the_keychain_is_required(
        self, temp_home, block_real_keychain, monkeypatch
    ):
        s = macos_store(temp_home)
        s._store.keychain_required = True
        monkeypatch.setattr(
            macos_keychain, "get_password",
            lambda *a: (_ for _ in ()).throw(macos_keychain.KeychainError("transient")),
        )
        with pytest.raises(macos_keychain.KeychainError):
            s._store._kc_call(macos_keychain.get_password, "svc", "acct")
        assert s._store._use_keychain() is True
        assert s._store._keychain_disabled_until == 0.0

    def test_R2_direct_post_write_failure_is_adopted_not_reposted(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-0", "RT-0", expires_in_s=NEAR)
        # The slot is one rotation behind, so this POST bypasses the gate.
        s._write_account_credentials(*SLOT, creds("AT-old", "RT-old", expires_in_s=-100))
        real_set = block_real_keychain.set_password
        monkeypatch.setattr(
            macos_keychain, "set_password", _active_item_write_fails(block_real_keychain)
        )
        report = run_keepalive(s)
        assert report["error"]["type"] == "keychain_unavailable"
        assert rotating.posts == ["RT-0"]

        monkeypatch.setattr(macos_keychain, "set_password", real_set)
        second = new_process()
        report = run_keepalive(second)
        assert report["ok"] is True and report["action"] == "synced-keychain"
        assert rotating.posts == ["RT-0"]
        assert strikes(second) == 0
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"
        assert second._store._list_unclaimed_credentials() == {}
        assert access_token(second._read_account_credentials(*SLOT)) == "AT-1"

    def test_R2_unmanaged_successor_is_adopted_from_the_stash(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home, active="stranger@example.com")
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-0", "RT-0", expires_in_s=NEAR)
        real_set = block_real_keychain.set_password
        monkeypatch.setattr(
            macos_keychain, "set_password", _active_item_write_fails(block_real_keychain)
        )
        assert run_keepalive(s)["error"]["type"] == "keychain_unavailable"
        monkeypatch.setattr(macos_keychain, "set_password", real_set)
        second = new_process()
        report = run_keepalive(second)
        assert report["action"] == "synced-keychain"
        assert report["error"]["type"] == "unmanaged"
        assert rotating.posts == ["RT-0"]
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"
        assert second._store._list_unclaimed_credentials() == {}

    def test_spent_token_with_nothing_parked_is_relogin_without_a_post(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        spent = creds("AT-0", "RT-0", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = spent
        s._write_account_credentials(*SLOT, spent)
        assert run_keepalive(s)["action"] == "refreshed"
        # Something outside hswap put the spent generation back everywhere.
        block_real_keychain.data[ACTIVE_ITEM] = spent
        s._write_account_credentials(*SLOT, spent)
        report = run_keepalive(new_process())
        assert report["ok"] is False and report["error"]["type"] == "relogin_required"
        assert rotating.posts == ["RT-0"]

    def test_ledger_holds_fingerprints_only_at_0600(self, env):
        near = creds("AT-LEDGER", "RT-LEDGER", expires_in_s=NEAR)
        env.active(near)
        env.store._write_account_credentials(*SLOT, near)
        env.run()
        path = env.store.backup_dir / "cache" / consumed_grants.FILENAME
        text = path.read_text()
        assert oauth.credential_fingerprint(near) in text
        assert "RT-LEDGER" not in text and "sk-ant" not in text
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_ledger_stays_bounded(self, temp_home):
        for n in range(consumed_grants.MAX_ENTRIES + 5):
            consumed_grants.record(f"sha256:{n}", "1")
        assert consumed_grants.slot_of("sha256:0") is None
        assert consumed_grants.slot_of(f"sha256:{consumed_grants.MAX_ENTRIES + 4}") == "1"

    def test_a_server_that_does_not_rotate_spends_nothing(self, env, monkeypatch):
        near = creds("AT-0", "RT-same", expires_in_s=NEAR)
        env.active(near)
        env.store._write_account_credentials(*SLOT, near)

        def no_rotation(request, timeout=None):
            return io.BytesIO(json.dumps({"access_token": "AT-1", "expires_in": 28800}).encode())

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", no_rotation)
        assert env.run()["action"] == "refreshed"
        assert consumed_grants.slot_of(oauth.credential_fingerprint(near)) is None

    def test_the_post_chokepoint_refuses_every_path(self, temp_home, rotating):
        spent = creds("AT-0", "RT-0")
        consumed_grants.record(oauth.credential_fingerprint(spent), "1")
        assert oauth.try_refresh_oauth_credentials(spent).error == "consumed"
        assert rotating.posts == []

    def test_consume_gate_adopts_a_keepalive_stash_before_it_would_post(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        spent = creds("AT-0", "RT-0", expires_in_s=NEAR)
        s._write_account_credentials(*SLOT, spent)
        consumed_grants.record(oauth.credential_fingerprint(spent), "1")
        s.stash_consumed_successor(
            "1", creds("AT-1", "RT-1"), oauth.credential_fingerprint(spent),
            "keepalive-live-write-failed",
        )
        outcome = s.consume_backup_grant(*SLOT, spent)
        assert outcome.error is None and access_token(outcome.credentials) == "AT-1"
        assert rotating.posts == []


class TestSwitchWhileWaitingR3:
    def _racing_lock(self, monkeypatch, home, keychain, *, file_copy=None):
        """A switch 1 -> 2 finishes while keepalive waits on the locks."""
        real = keepalive.claude_credentials_lock
        b = creds("AT-B", "RT-B", expires_in_s=7200)

        @contextmanager
        def racing():
            with real():
                keychain.data[ACTIVE_ITEM] = b
                (home / ".claude.json").write_text(json.dumps({
                    "oauthAccount": {"emailAddress": "b@example.com", "accountUuid": "uuid-2"},
                }))
                yield

        monkeypatch.setattr(keepalive, "claude_credentials_lock", racing)
        return b

    def test_R3_account_switched_away_from_is_not_resurrected(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        a = creds("AT-A", "RT-A", expires_in_s=20000)
        block_real_keychain.data[ACTIVE_ITEM] = a
        s._write_account_credentials("1", "a@example.com", a)
        s._write_account_credentials("2", "b@example.com", creds("AT-B", "RT-B", expires_in_s=7200))
        b = self._racing_lock(monkeypatch, temp_home, block_real_keychain)
        report = run_keepalive(s)
        assert report["ok"] is True and report["activeSlot"] == 2
        assert block_real_keychain.data[ACTIVE_ITEM] == b
        assert rotating.posts == []

    def test_R3_consume_lock_follows_the_slot_after_a_switch(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-A", "RT-A")
        s._write_account_credentials("2", "b@example.com", creds("AT-B", "RT-B", expires_in_s=7200))
        self._racing_lock(monkeypatch, temp_home, block_real_keychain)
        taken = []
        real_file_lock = keepalive.FileLock

        def spying(path, *a, **kw):
            taken.append(path.name)
            return real_file_lock(path, *a, **kw)

        monkeypatch.setattr(keepalive, "FileLock", spying)
        run_keepalive(s)
        consumes = [name for name in taken if name.startswith(".consume-")]
        assert consumes == [".consume-1.lock", ".consume-2.lock"]

    def test_R3_a_stale_longer_lived_copy_of_the_old_account_loses(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home, active="b@example.com")
        a = creds("AT-A", "RT-A", expires_in_s=20000)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        s._write_account_credentials("1", "a@example.com", a)
        s._write_account_credentials("2", "b@example.com", b)
        block_real_keychain.data[ACTIVE_ITEM] = b
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(a)
        report = run_keepalive(s)
        assert report["activeSlot"] == 2 and report["action"] == "synced-file"
        assert report["note"] == "split_brain"
        assert block_real_keychain.data[ACTIVE_ITEM] == b
        assert file_path.read_text() == b

    def test_R3_only_the_old_accounts_copy_live_restores_the_slot(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home, active="b@example.com")
        a = creds("AT-A", "RT-A", expires_in_s=20000)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        s._write_account_credentials("1", "a@example.com", a)
        s._write_account_credentials("2", "b@example.com", b)
        block_real_keychain.data[ACTIVE_ITEM] = a
        report = run_keepalive(s)
        assert report["action"] == "synced-keychain"
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-B"

    @pytest.mark.parametrize("spent", [False, True], ids=["expired", "on-ledger"])
    def test_R3_a_slot_copy_that_cannot_work_never_overwrites_a_live_login(
        self, temp_home, block_real_keychain, rotating, spent
    ):
        s = macos_store(temp_home, active="b@example.com")
        a = creds("AT-A", "RT-A", expires_in_s=20000)
        b = creds("AT-B", "RT-B", expires_in_s=7200 if spent else -60)
        s._write_account_credentials("1", "a@example.com", a)
        s._write_account_credentials("2", "b@example.com", b)
        if spent:
            consumed_grants.record(oauth.credential_fingerprint(b), "2")
        block_real_keychain.data[ACTIVE_ITEM] = a
        report = run_keepalive(s)
        assert report["error"]["type"] == "unmanaged"
        assert block_real_keychain.data[ACTIVE_ITEM] == a
        assert rotating.posts == []

    def test_R3_nothing_matches_the_identity_changes_nothing(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home, active="b@example.com")
        a = creds("AT-A", "RT-A", expires_in_s=NEAR)
        s._write_account_credentials("1", "a@example.com", a)
        block_real_keychain.data[ACTIVE_ITEM] = a
        report = run_keepalive(s)
        assert report["ok"] is False and report["error"]["type"] == "unmanaged"
        assert block_real_keychain.data[ACTIVE_ITEM] == a
        assert rotating.posts == []

    def test_R3_slot_that_keeps_moving_reports_locked(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-A", "RT-A", expires_in_s=NEAR)
        real = keepalive._read_active
        calls = iter(range(100))

        def moving(switcher):
            active = real(switcher)
            return active._replace(slot=str(next(calls)))

        monkeypatch.setattr(keepalive, "_read_active", moving)
        report = run_keepalive(s)
        assert report["error"]["type"] == "locked"
        assert rotating.posts == []


class TestGenerationRankR4:
    def _access_only(self, expires_in_s):
        data = json.loads(creds("AT-F", "x", expires_in_s=expires_in_s))
        del data["claudeAiOauth"]["refreshToken"]
        return json.dumps(data)

    def test_R4_a_copy_with_a_refresh_token_beats_a_later_one_without(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        full = creds("AT-K", "RT-K", expires_in_s=7200)
        block_real_keychain.data[ACTIVE_ITEM] = full
        s._write_account_credentials(*SLOT, full)
        file_path = temp_home / ".claude" / ".credentials.json"
        file_path.write_text(self._access_only(9000))
        report = run_keepalive(s)
        assert report["action"] == "synced-file"
        assert block_real_keychain.data[ACTIVE_ITEM] == full
        assert file_path.read_text() == full

    def test_R4_file_with_a_refresh_token_replaces_an_access_only_keychain(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        block_real_keychain.data[ACTIVE_ITEM] = self._access_only(9000)
        (temp_home / ".claude" / ".credentials.json").write_text(creds("AT-F", "RT-F"))
        run_keepalive(s)
        stored = oauth.extract_oauth_data(block_real_keychain.data[ACTIVE_ITEM])
        assert stored["refreshToken"] == "RT-F"

    def test_R4_never_trades_a_refresh_token_for_none(
        self, temp_home, block_real_keychain, rotating
    ):
        # The refresh-token copy is another account's, so it cannot win, and the
        # access-only one must not overwrite it either.
        s = macos_store(temp_home, active="stranger@example.com")
        foreign = creds("AT-A", "RT-A", expires_in_s=7200)
        s._write_account_credentials("1", "a@example.com", foreign)
        block_real_keychain.data[ACTIVE_ITEM] = foreign
        file_copy = self._access_only(9000)
        (temp_home / ".claude" / ".credentials.json").write_text(file_copy)
        report = run_keepalive(s)
        assert report["ok"] is False and report["error"]["type"] == "split_brain"
        assert block_real_keychain.data[ACTIVE_ITEM] == foreign


class TestReportSurvivesR6:
    def test_R6_null_oauth_account_still_reports(self, env, capsys):
        env.active(creds())
        (env.home / ".claude.json").write_text(json.dumps({"oauthAccount": None}))
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "unmanaged"
        assert env.report_on_disk()["error"]["type"] == "unmanaged"

    def test_R6_null_oauth_account_does_not_crash_other_commands(self, env):
        (env.home / ".claude.json").write_text(json.dumps({"oauthAccount": None}))
        assert env.store._get_current_account() is None

    def test_R6_any_exception_is_a_report_with_the_type_name_only(
        self, env, monkeypatch, caplog
    ):
        env.active(creds())

        def boom():
            raise RuntimeError("sk-ant-ort01-SECRET in /Users/me/.claude")

        monkeypatch.setattr(env.store, "_get_current_account", boom)
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "refresh_failed"
        on_disk = (env.store.backup_dir / "cache" / "keepalive.json").read_text()
        assert "SECRET" not in on_disk and "/Users" not in on_disk
        assert "SECRET" not in caplog.text
        assert "RuntimeError" in caplog.text


class TestOrdinaryRotationR7:
    def _loser_needs_no_probe(self, monkeypatch):
        monkeypatch.setattr(
            oauth, "fetch_oauth_profile",
            lambda token: pytest.fail("no probe needed") if token == "AT-0" else OWN_ACCOUNT,
        )

    def _assert_plain_sync(self, env, report):
        assert report["action"] == "synced-file"
        assert report["note"] is None
        assert env.store._store._list_unclaimed_credentials() == {}
        assert env.file.read_text() == env.keychain_value()

    def test_R7_probe_says_same_account(self, env, monkeypatch):
        env.active(creds("AT-1", "RT-1", expires_in_s=7200))
        env.file.write_text(creds("AT-0", "RT-0", expires_in_s=7000))
        monkeypatch.setattr(oauth, "fetch_oauth_profile", lambda token: OWN_ACCOUNT)
        self._assert_plain_sync(env, env.run())

    def test_R7_loser_lineage_is_the_slot_backup(self, env, monkeypatch):
        older = creds("AT-0", "RT-0", expires_in_s=7000)
        env.active(creds("AT-1", "RT-1", expires_in_s=7200))
        env.file.write_text(older)
        env.store._write_account_credentials(*SLOT, older)
        self._loser_needs_no_probe(monkeypatch)
        self._assert_plain_sync(env, env.run())

    def test_R7_loser_lineage_is_on_the_consumed_ledger(self, env, monkeypatch):
        older = creds("AT-0", "RT-0", expires_in_s=7000)
        env.active(creds("AT-1", "RT-1", expires_in_s=7200))
        env.file.write_text(older)
        consumed_grants.record(oauth.credential_fingerprint(older), "1")
        self._loser_needs_no_probe(monkeypatch)
        self._assert_plain_sync(env, env.run())

    def test_R7_expired_and_older_is_presumed_consumed(self, env, monkeypatch):
        env.active(creds("AT-1", "RT-1", expires_in_s=7200))
        env.file.write_text(creds("AT-0", "RT-0", expires_in_s=-60))
        monkeypatch.setattr(
            oauth, "fetch_oauth_profile",
            lambda token: pytest.fail("an expired token proves nothing") if token == "AT-0" else None,
        )
        self._assert_plain_sync(env, env.run())

    def test_R7_rotations_do_not_grow_the_stash_over_runs(self, env, monkeypatch):
        monkeypatch.setattr(oauth, "fetch_oauth_profile", lambda token: OWN_ACCOUNT)
        for i in range(3):
            env.active(creds(f"AT{i + 1}", f"RT{i + 1}", expires_in_s=7200 + 100 * i))
            env.file.write_text(creds(f"AT{i}", f"RT{i}", expires_in_s=7000 + 100 * i))
            assert env.run()["note"] is None
        assert env.store._store._list_unclaimed_credentials() == {}

    def test_R7_unattributable_live_copy_is_kept_without_the_note(self, env):
        loser = creds("AT-0", "RT-0", expires_in_s=7000)  # the probe answers nothing
        env.active(creds("AT-1", "RT-1", expires_in_s=7200))
        env.file.write_text(loser)
        report = env.run()
        assert report["action"] == "synced-file" and report["note"] is None
        stash = env.store._store._list_unclaimed_credentials()
        assert len(stash) == 1
        assert env.store._store._read_unclaimed_credential(next(iter(stash)))[0] == loser

    def test_R7_the_same_bytes_are_stashed_once(self, env):
        loser = creds("AT-0", "RT-0", expires_in_s=7000)
        for _ in range(3):
            env.active(creds("AT-1", "RT-1", expires_in_s=7200))
            env.file.write_text(loser)
            env.run()
        assert len(env.store._store._list_unclaimed_credentials()) == 1

    def test_R7_unparseable_copy_is_not_discarded(self, env):
        env.active(creds("AT-1", "RT-1"))
        env.file.write_text("not json")
        env.run()
        assert len(env.store._store._list_unclaimed_credentials()) == 1


class TestEnsureFileAtomic:
    def test_created_by_rename_and_narrowed_to_0600(self, env):
        env.active(creds())
        env.file.write_text("old")
        env.file.chmod(0o644)
        inode = env.file.stat().st_ino
        env.run(ensure_file=True)
        assert env.file.stat().st_ino != inode
        assert env.file.read_text() == env.keychain_value()
        if os.name == "posix":
            assert stat.S_IMODE(env.file.stat().st_mode) == 0o600
        assert [p.name for p in env.file.parent.iterdir() if ".credentials" in p.name] == [
            ".credentials.json"
        ]
