"""`cswap keepalive`: one refresher, both stores on one generation, a report that
never carries a token. Every test runs on a temp HOME with the Keychain fake and a
fake token endpoint."""

from __future__ import annotations

import ast
import base64
import errno
import hashlib
import io
import json
import os
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.error
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

import claude_swap
from claude_swap import (
    claude_locks,
    cli,
    consumed_grants,
    keepalive,
    macos_keychain,
    oauth,
)
from claude_swap import switcher as switcher_module
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
        env.post.failure = urllib.error.URLError(ConnectionRefusedError())
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

    @pytest.mark.parametrize("variable", ["CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR"])
    @pytest.mark.parametrize("value", ["default", "other", "empty"])
    @pytest.mark.parametrize("platform", [Platform.MACOS, Platform.LINUX], ids=["macos", "linux"])
    def test_either_config_variable_set_to_anything_is_refused(
        self, env, monkeypatch, variable, value, platform
    ):
        """Claude Code hashes even the default directory into its item's name."""
        monkeypatch.setenv(
            variable,
            {"default": str(env.home / ".claude"), "other": str(env.home / "other"), "empty": ""}[value],
        )
        env.store.platform = platform
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.file.write_text(near)
        before = snapshot(env.home, env.keychain)
        report = env.run()
        assert report["ok"] is False and report["error"]["type"] == "refresh_failed"
        assert "CLAUDE_CONFIG_DIR" in report["error"]["message"]
        assert env.post.posts == []
        assert snapshot(env.home, env.keychain) == before

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
            env.post.failure = urllib.error.URLError(ConnectionRefusedError(f"token {refresh}"))
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

    def test_a_server_that_does_not_rotate_spends_nothing(self, env, monkeypatch):
        near = creds("AT-0", "RT-same", expires_in_s=NEAR)
        env.active(near)
        env.store._write_account_credentials(*SLOT, near)

        def no_rotation(request, timeout=None):
            return io.BytesIO(json.dumps({"access_token": "AT-1", "expires_in": 28800}).encode())

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", no_rotation)
        assert env.run()["action"] == "refreshed"
        assert consumed_grants.entry(oauth.credential_fingerprint(near)) is None

    def test_the_post_chokepoint_refuses_every_path(self, temp_home, rotating):
        spent = creds("AT-0", "RT-0")
        consumed_grants.record(oauth.credential_fingerprint(spent), IDENTITY["1"], consumed_grants.CONSUMED)
        assert oauth.try_refresh_oauth_credentials(spent).error == "consumed"
        assert rotating.posts == []

    def test_consume_gate_adopts_a_keepalive_stash_before_it_would_post(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        spent = creds("AT-0", "RT-0", expires_in_s=NEAR)
        s._write_account_credentials(*SLOT, spent)
        consumed_grants.record(oauth.credential_fingerprint(spent), IDENTITY["1"], consumed_grants.CONSUMED)
        s.stash_consumed_successor(
            "1", IDENTITY["1"], creds("AT-1", "RT-1"), oauth.credential_fingerprint(spent),
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
            consumed_grants.record(
                oauth.credential_fingerprint(b), ("b@example.com", ""), consumed_grants.CONSUMED
            )
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
        consumed_grants.record(oauth.credential_fingerprint(older), IDENTITY["1"], consumed_grants.CONSUMED)
        self._loser_needs_no_probe(monkeypatch)
        self._assert_plain_sync(env, env.run())

    def test_expired_token_proves_nothing_so_the_copy_is_stashed(self, env, monkeypatch):
        """Round 2, finding 3: its refresh token may be the only live one anywhere."""
        loser = creds("AT-0", "RT-0", expires_in_s=-60)
        env.active(creds("AT-1", "RT-1", expires_in_s=7200))
        env.file.write_text(loser)
        monkeypatch.setattr(
            oauth, "fetch_oauth_profile",
            lambda token: pytest.fail("an expired token cannot be probed") if token == "AT-0" else None,
        )
        report = env.run()
        assert report["action"] == "synced-file" and report["note"] is None
        rows = env.store._store._list_unclaimed_credentials()
        assert [env.store._store._read_unclaimed_credential(i)[0] for i in rows] == [loser]

    def test_another_accounts_expired_keychain_copy_is_not_destroyed(
        self, temp_home, block_real_keychain, rotating
    ):
        """Codex's reproduction: Keychain holds A expired with a good refresh token,
        the file and the slot hold B, and A is attributable to nobody."""
        s = macos_store(temp_home, active="b@example.com")
        a = creds("AT-A", "RT-A", expires_in_s=-60)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        s._write_account_credentials("2", "b@example.com", b)
        block_real_keychain.data[ACTIVE_ITEM] = a
        (temp_home / ".claude" / ".credentials.json").write_text(b)
        report = run_keepalive(s)
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-B"
        assert report["action"] == "synced-keychain"
        rows = s._store._list_unclaimed_credentials()
        assert [s._store._read_unclaimed_credential(i)[0] for i in rows] == [a]

    @pytest.mark.parametrize("state", ["consumed", "reserved"])
    def test_a_copy_on_the_ledger_needs_no_stash(self, env, state):
        loser = creds("AT-0", "RT-0", expires_in_s=-60)
        env.active(creds("AT-1", "RT-1", expires_in_s=7200))
        env.file.write_text(loser)
        consumed_grants.record(oauth.credential_fingerprint(loser), IDENTITY["1"], state)
        env.run()
        assert env.store._store._list_unclaimed_credentials() == {}

    def test_the_same_lineage_needs_no_stash(self, env):
        env.active(creds("AT-1", "RT-same", expires_in_s=7200))
        env.file.write_text(creds("AT-0", "RT-same", expires_in_s=-60))
        env.run()
        assert env.store._store._list_unclaimed_credentials() == {}

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


class TestFileStoreMustBeUpdated:
    def _failing_file_writes(self, env, monkeypatch, *, failures=99):
        real = env.store._store._write_active_credentials_file
        left = [failures]
        calls = []

        def write(credentials):
            calls.append(credentials)
            if left[0] > 0:
                left[0] -= 1
                raise OSError("read-only")
            real(credentials)

        monkeypatch.setattr(env.store._store, "_write_active_credentials_file", write)
        return calls

    def test_refresh_with_a_stuck_file_is_not_reported_as_success(self, env, monkeypatch):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.file.write_text(near)
        env.store._write_account_credentials(*SLOT, near)
        self._failing_file_writes(env, monkeypatch)
        report = env.run()
        assert report["ok"] is False
        assert report["error"] == {
            "type": "refresh_failed", "message": "file store could not be updated",
        }
        assert report["action"] == "refreshed"
        # The successor is safe, and the file still holds the spent token.
        assert access_token(env.keychain_value()) == "sk-ant-oat01-ACCESS-NEW"
        assert access_token(env.backup()) == "sk-ant-oat01-ACCESS-NEW"
        assert env.file.read_text() == near
        assert env.report_on_disk()["ok"] is False

    def test_next_run_repairs_the_file_without_a_post(self, env, monkeypatch):
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.file.write_text(near)
        env.store._write_account_credentials(*SLOT, near)
        with monkeypatch.context() as stuck:
            self._failing_file_writes(env, stuck)
            env.run()
        assert len(env.post.posts) == 1
        report = env.run()
        assert report["ok"] is True and report["action"] == "synced-file"
        assert len(env.post.posts) == 1
        assert env.file.read_text() == env.keychain_value()

    def test_one_failed_write_is_retried(self, env, monkeypatch):
        env.active(creds("sk-new", expires_in_s=7200))
        env.file.write_text(creds("sk-old", expires_in_s=3700))
        calls = self._failing_file_writes(env, monkeypatch, failures=1)
        report = env.run()
        assert report["ok"] is True and report["action"] == "synced-file"
        assert len(calls) == 2
        assert env.file.read_text() == env.keychain_value()

    def test_a_write_that_lands_wrong_is_caught_by_the_read_back(self, env, monkeypatch):
        env.active(creds("sk-new", expires_in_s=7200))
        env.file.write_text(creds("sk-old", expires_in_s=3700))
        monkeypatch.setattr(
            env.store._store, "_write_active_credentials_file", lambda credentials: None
        )
        report = env.run()
        assert report["ok"] is False
        assert report["error"]["message"] == "file store could not be updated"

    def test_a_stuck_file_does_not_block_the_refresh(self, env, monkeypatch):
        env.active(creds("sk-k", expires_in_s=NEAR))
        env.file.write_text(creds("sk-f", expires_in_s=NEAR - 10))
        env.store._write_account_credentials(*SLOT, env.keychain_value())
        self._failing_file_writes(env, monkeypatch)
        report = env.run()
        assert report["action"] == "refreshed" and len(env.post.posts) == 1
        assert report["error"]["message"] == "file store could not be updated"

    def test_ensure_file_that_cannot_be_created_is_reported(self, env, monkeypatch):
        env.active(creds())
        self._failing_file_writes(env, monkeypatch)
        report = env.run(ensure_file=True)
        assert report["ok"] is False
        assert report["error"]["message"] == "file store could not be updated"

    def test_no_file_wanted_is_never_checked(self, env, monkeypatch):
        env.active(creds(expires_in_s=NEAR))
        env.store._write_account_credentials(*SLOT, env.keychain_value())
        calls = self._failing_file_writes(env, monkeypatch)
        report = env.run()
        assert report["ok"] is True and report["action"] == "refreshed"
        assert calls == [] and not env.file.exists()

    def test_silently_swallowed_rewrite_is_the_case_this_guards(self, env, monkeypatch):
        """The Keychain write's own file rewrite swallows its failure."""
        near = creds(expires_in_s=NEAR)
        env.active(near)
        env.file.write_text(near)
        env.store._write_account_credentials(*SLOT, near)
        monkeypatch.setattr(
            env.store._store, "_refresh_stale_credentials_file", lambda credentials: None
        )
        report = env.run()
        assert report["ok"] is True  # the retry below it repaired the file
        assert env.file.read_text() == env.keychain_value()


def _timeout_after_rotating(endpoint):
    """The server rotates, then the response is lost."""

    def post(request, timeout=None):
        endpoint(request, timeout)
        raise TimeoutError("read timed out")

    return post


class TestUncertainOutcomeIsNeverRetried:
    @pytest.fixture
    def near(self, temp_home, block_real_keychain):
        s = macos_store(temp_home)
        value = creds("AT-0", "RT-0", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = value
        s._write_account_credentials(*SLOT, value)
        return value

    @pytest.mark.parametrize(
        "failure",
        [
            TimeoutError("read timed out"),
            ConnectionResetError("reset"),
            urllib.error.URLError(TimeoutError("timed out")),  # unsure: treated as sent
            urllib.error.URLError(ssl.SSLError("write failed")),
            urllib.error.HTTPError("u", 503, "bad", {}, io.BytesIO(b"oops")),
        ],
        ids=["timeout", "reset", "connect-timeout", "tls-after-handshake", "5xx"],
    )
    def test_one_post_across_many_runs(self, near, rotating, monkeypatch, failure, block_real_keychain):
        def post(request, timeout=None):
            rotating(request, timeout)
            raise failure

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post)
        reports = [run_keepalive(new_process()) for _ in range(4)]
        assert rotating.posts == ["RT-0"]
        for report in reports:
            assert report["error"]["type"] == "relogin_required"
            assert "uncertain" in report["error"]["message"]
        assert block_real_keychain.data[ACTIVE_ITEM] == near  # nothing wiped

    def test_unparsable_2xx_is_uncertain(self, near, rotating, monkeypatch):
        def post(request, timeout=None):
            rotating(request, timeout)
            return io.BytesIO(b"<html>cut off")

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post)
        for _ in range(3):
            assert run_keepalive(new_process())["error"]["type"] == "relogin_required"
        assert rotating.posts == ["RT-0"]

    def test_2xx_missing_fields_is_uncertain(self, near, rotating, monkeypatch):
        def post(request, timeout=None):
            rotating(request, timeout)
            return io.BytesIO(b'{"refresh_token": "RT-9"}')

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post)
        run_keepalive(new_process())
        run_keepalive(new_process())
        assert rotating.posts == ["RT-0"]

    @pytest.mark.parametrize(
        "failure",
        [
            urllib.error.URLError(socket.gaierror("no such host")),
            urllib.error.URLError(ConnectionRefusedError()),
            urllib.error.URLError(ssl.SSLCertVerificationError("bad cert")),
            urllib.error.URLError(ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] x")),
            urllib.error.URLError(OSError(errno.ENETUNREACH, "unreachable")),
        ],
        ids=["dns", "refused", "cert", "handshake", "no-route"],
    )
    def test_definite_pre_send_failure_clears_the_reservation(
        self, near, rotating, monkeypatch, failure, block_real_keychain
    ):
        def not_sent(request, timeout=None):
            raise failure

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", not_sent)
        report = run_keepalive(new_process())
        assert report["error"]["type"] == "refresh_failed"
        assert consumed_grants.entry(oauth.credential_fingerprint(near)) is None

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", rotating)
        report = run_keepalive(new_process())
        assert report["ok"] is True and rotating.posts == ["RT-0"]
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"

    def test_a_refused_request_clears_the_reservation(self, near, monkeypatch):
        def refused(request, timeout=None):
            raise urllib.error.HTTPError("u", 429, "slow down", {}, io.BytesIO(b"{}"))

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", refused)
        assert run_keepalive(new_process())["error"]["type"] == "refresh_failed"
        assert consumed_grants.entry(oauth.credential_fingerprint(near)) is None

    def test_a_rejected_grant_is_never_presented_again(self, near, rotating, monkeypatch):
        def rejected(request, timeout=None):
            rotating.posts.append(json.loads(request.data)["refresh_token"])
            raise urllib.error.HTTPError(
                "u", 400, "bad", {}, io.BytesIO(b'{"error":"invalid_grant"}')
            )

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", rejected)
        reports = [run_keepalive(new_process()) for _ in range(3)]
        assert [r["error"]["type"] for r in reports] == ["relogin_required"] * 3
        assert rotating.posts == ["RT-0"]
        assert consumed_grants.entry(oauth.credential_fingerprint(near))["state"] == "consumed"

    def test_a_clear_success_marks_it_consumed(self, near, rotating):
        run_keepalive(new_process())
        assert consumed_grants.entry(oauth.credential_fingerprint(near))["state"] == "consumed"

    def test_a_successor_elsewhere_is_adopted_instead_of_giving_up(
        self, near, rotating, block_real_keychain, temp_home
    ):
        consumed_grants.record(
            oauth.credential_fingerprint(near), IDENTITY["1"], consumed_grants.RESERVED
        )
        newer = creds("AT-9", "RT-9", expires_in_s=20000)
        (temp_home / ".claude" / ".credentials.json").write_text(newer)
        report = run_keepalive(new_process())
        assert report["ok"] is True and report["action"] == "synced-keychain"
        assert block_real_keychain.data[ACTIVE_ITEM] == newer
        assert rotating.posts == []

    def test_uncertain_outcome_is_recognised_by_every_other_path(
        self, near, rotating, monkeypatch
    ):
        monkeypatch.setattr(
            "claude_swap.oauth.urllib.request.urlopen", _timeout_after_rotating(rotating)
        )
        run_keepalive(new_process())
        s = new_process()
        s._fetch_active_usage("1", "a@example.com", near, "")
        assert s.consume_backup_grant(*SLOT, near).error == "consumed"
        assert rotating.posts == ["RT-0"]

    def test_reservation_is_durable_before_the_request_leaves(
        self, near, monkeypatch
    ):
        order = []
        real_fsync = os.fsync
        monkeypatch.setattr(os, "fsync", lambda fd: (order.append("fsync"), real_fsync(fd))[1])

        def post(request, timeout=None):
            order.append("post")
            assert consumed_grants.entry(oauth.credential_fingerprint(near))["state"] == "reserved"
            raise TimeoutError

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post)
        run_keepalive(new_process())
        # File and directory, both before the POST.
        assert order.count("fsync") >= 2 and order[order.index("post") - 1] == "fsync"

    def test_a_reservation_that_cannot_be_written_forbids_the_post(
        self, near, rotating, monkeypatch
    ):
        def full(*a, **kw):
            raise OSError("disk full")

        monkeypatch.setattr(consumed_grants, "atomic_write_json", full)
        report = run_keepalive(new_process())
        assert report["error"] == {
            "type": "refresh_failed", "message": "consumed-grant ledger unreadable",
        }
        assert rotating.posts == []

    def test_a_settle_that_fails_leaves_it_refused(self, near, rotating, monkeypatch):
        real = consumed_grants.release

        def post(request, timeout=None):
            raise urllib.error.URLError(ConnectionRefusedError())

        def broken(fingerprint):
            raise consumed_grants.LedgerUnreadable("disk full")

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post)
        monkeypatch.setattr(consumed_grants, "release", broken)
        run_keepalive(new_process())
        monkeypatch.setattr(consumed_grants, "release", real)
        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", rotating)
        assert run_keepalive(new_process())["error"]["type"] == "relogin_required"
        assert rotating.posts == []

    def test_default_mode_is_untouched_until_a_ledger_exists(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        """No keepalive, no required mode: a timeout retries as it always did."""
        s = macos_store(temp_home)
        expired = creds("AT-0", "RT-0", expires_in_s=-100)
        block_real_keychain.data[ACTIVE_ITEM] = expired
        s._write_account_credentials(*SLOT, expired)
        monkeypatch.setattr(
            "claude_swap.oauth.urllib.request.urlopen", _timeout_after_rotating(rotating)
        )
        s._fetch_active_usage("1", "a@example.com", expired, "")
        assert not (s.backup_dir / "cache" / consumed_grants.FILENAME).exists()

    def test_an_existing_ledger_binds_a_default_mode_post(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        expired = creds("AT-0", "RT-0", expires_in_s=-100)
        block_real_keychain.data[ACTIVE_ITEM] = expired
        s._write_account_credentials(*SLOT, expired)
        consumed_grants.record("sha256:other", IDENTITY["1"], consumed_grants.CONSUMED)
        monkeypatch.setattr(
            "claude_swap.oauth.urllib.request.urlopen", _timeout_after_rotating(rotating)
        )
        s._fetch_active_usage("1", "a@example.com", expired, "")
        s._fetch_active_usage("1", "a@example.com", expired, "")
        assert rotating.posts == ["RT-0"]


class TestLedgerFailsClosed:
    def _ledger(self, s):
        return s.backup_dir / "cache" / consumed_grants.FILENAME

    def _setup(self, home, keychain):
        s = macos_store(home)
        near = creds("AT-0", "RT-0", expires_in_s=NEAR)
        keychain.data[ACTIVE_ITEM] = near
        s._write_account_credentials(*SLOT, near)
        return s, near

    @pytest.mark.parametrize(
        "content",
        [
            b"{not json",
            b"",  # a torn or truncated write
            b'{"sha256:a": {"state": "consumed", "em',
            b"[]",
            b'{"sha256:a": "1"}',
            b'{"sha256:a": {"state": "maybe", "email": "", "organizationUuid": ""}}',
            b"\xff\xfe",
        ],
        ids=["garbage", "empty", "partial", "not-a-dict", "old-row", "bad-state", "not-utf8"],
    )
    def test_corrupt_ledger_means_no_post_and_no_rewrite(
        self, temp_home, block_real_keychain, rotating, content
    ):
        s, near = self._setup(temp_home, block_real_keychain)
        path = self._ledger(s)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        report = run_keepalive(new_process())
        assert report["ok"] is False
        assert report["error"] == {
            "type": "refresh_failed", "message": "consumed-grant ledger unreadable",
        }
        assert rotating.posts == []
        assert path.read_bytes() == content
        assert block_real_keychain.data[ACTIVE_ITEM] == near

    def test_unreadable_ledger_means_no_post_and_no_rewrite(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s, _ = self._setup(temp_home, block_real_keychain)
        path = self._ledger(s)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
        real = consumed_grants.Path.read_text

        def denied(self, *a, **kw):
            if self.name == consumed_grants.FILENAME:
                raise PermissionError("denied")
            return real(self, *a, **kw)

        monkeypatch.setattr(consumed_grants.Path, "read_text", denied)
        report = run_keepalive(new_process())
        assert report["error"]["message"] == "consumed-grant ledger unreadable"
        assert rotating.posts == []
        assert real(path) == "{}"

    def test_every_post_path_refuses_on_a_corrupt_ledger(
        self, temp_home, block_real_keychain, rotating
    ):
        s, near = self._setup(temp_home, block_real_keychain)
        path = self._ledger(s)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{not json")
        assert oauth.try_refresh_oauth_credentials(near).error == "ledger-unreadable"
        assert s.consume_backup_grant(*SLOT, near).error == "ledger-unreadable"
        assert s._fetch_active_usage("1", "a@example.com", near, "") is not None
        assert rotating.posts == []
        assert path.read_bytes() == b"{not json"

    def test_recording_never_overwrites_unreadable_history(self, temp_home, tmp_path):
        s = macos_store(temp_home)
        path = self._ledger(s)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{not json")
        with pytest.raises(consumed_grants.LedgerUnreadable):
            consumed_grants.record("sha256:a", IDENTITY["1"], consumed_grants.CONSUMED)
        with pytest.raises(consumed_grants.LedgerUnreadable):
            consumed_grants.release("sha256:a")
        assert path.read_bytes() == b"{not json"

    def test_a_missing_ledger_is_empty(self, temp_home):
        assert consumed_grants.entry("sha256:a") is None

    def test_written_atomically_and_private(self, temp_home, tmp_path):
        macos_store(temp_home)
        consumed_grants.record("sha256:a", IDENTITY["1"], consumed_grants.RESERVED)
        path = consumed_grants._path()
        inode = path.stat().st_ino
        consumed_grants.record("sha256:b", IDENTITY["1"], consumed_grants.RESERVED)
        assert path.stat().st_ino != inode
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert sorted(p.name for p in path.parent.iterdir() if "consumed_grants" in p.name) == [
            "consumed_grants.json", "consumed_grants.lock",
        ]


class TestStashIsRetiredOnlyOnProof:
    def test_failed_unmanaged_recovery_keeps_the_only_successor(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        """Linux and Windows: the file is the only store."""
        s = macos_store(temp_home, active="stranger@example.com")
        s.platform = Platform.LINUX
        file_path = temp_home / ".claude" / ".credentials.json"
        spent = creds("AT-0", "RT-0", expires_in_s=NEAR)
        file_path.write_text(spent)
        successor = creds("AT-1", "RT-1", expires_in_s=28800)
        s.stash_consumed_successor(
            "unmanaged", ("stranger@example.com", ""), successor,
            oauth.credential_fingerprint(spent), "keepalive-live-write-failed",
        )
        consumed_grants.record(
            oauth.credential_fingerprint(spent),
            ("stranger@example.com", ""),
            consumed_grants.CONSUMED,
        )
        real_write = s._store._write_active_credentials_file

        def stuck(credentials):
            raise OSError("read-only")

        monkeypatch.setattr(s._store, "_write_active_credentials_file", stuck)
        report = run_keepalive(s)
        assert report["ok"] is False and report["error"]["type"] == "refresh_failed"
        rows = s._store._list_unclaimed_credentials()
        assert len(rows) == 1
        assert s._store._read_unclaimed_credential(next(iter(rows)))[0] == successor
        assert rotating.posts == []

        monkeypatch.setattr(s._store, "_write_active_credentials_file", real_write)
        report = run_keepalive(s)
        assert file_path.read_text() == successor
        assert s._store._list_unclaimed_credentials() == {}
        assert rotating.posts == []

    def test_a_write_that_silently_missed_keeps_the_stash(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home, active="stranger@example.com")
        spent = creds("AT-0", "RT-0", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = spent
        s.stash_consumed_successor(
            "unmanaged", ("stranger@example.com", ""), creds("AT-1", "RT-1"),
            oauth.credential_fingerprint(spent), "keepalive-live-write-failed",
        )
        consumed_grants.record(
            oauth.credential_fingerprint(spent),
            ("stranger@example.com", ""),
            consumed_grants.CONSUMED,
        )
        monkeypatch.setattr(s._store, "_write_oauth_credentials", lambda credentials: None)
        assert run_keepalive(s)["ok"] is False
        assert len(s._store._list_unclaimed_credentials()) == 1
        assert rotating.posts == []

    def test_slot_adoption_keeps_the_stash_when_the_write_did_not_land(
        self, temp_home, block_real_keychain, monkeypatch
    ):
        s = macos_store(temp_home)
        spent = creds("AT-0", "RT-0")
        s._write_account_credentials(*SLOT, spent)
        s.stash_consumed_successor(
            "1", IDENTITY["1"], creds("AT-1", "RT-1"), oauth.credential_fingerprint(spent),
            "keepalive-live-write-failed",
        )
        monkeypatch.setattr(s, "_write_account_credentials", lambda *a: None)
        assert access_token(s._adopt_stashed_successor(*SLOT, spent)) == "AT-1"
        assert len(s._store._list_unclaimed_credentials()) == 1


class TestLedgerAttributionByAccount:
    def _a_spent_then_slots_renumbered(self, temp_home, keychain, renumber):
        """A's copy is on the ledger, the login moved to B, then slots change."""
        s = macos_store(temp_home, active="b@example.com")
        a = creds("AT-A", "RT-A", expires_in_s=20000)
        b = creds("AT-B", "RT-B", expires_in_s=7200)
        s._write_account_credentials("1", "a@example.com", creds("AT-A2", "RT-A2"))
        s._write_account_credentials(
            "2", "b@example.com", creds("AT-Bold", "RT-Bold", expires_in_s=3600)
        )
        consumed_grants.record(
            oauth.credential_fingerprint(a), ("a@example.com", ""), consumed_grants.CONSUMED
        )
        renumber(s)
        keychain.data[ACTIVE_ITEM] = b
        (temp_home / ".claude" / ".credentials.json").write_text(a)
        return s, a, b

    @pytest.mark.parametrize(
        "renumber",
        [
            lambda s: s.swap_accounts("1", "2"),
            lambda s: s.move_account("2", "7"),
        ],
        ids=["swap", "move"],
    )
    def test_stale_copy_of_the_old_account_never_overwrites_the_current_one(
        self, temp_home, block_real_keychain, rotating, renumber
    ):
        s, a, b = self._a_spent_then_slots_renumbered(temp_home, block_real_keychain, renumber)
        report = run_keepalive(new_process())
        assert block_real_keychain.data[ACTIVE_ITEM] == b
        assert (temp_home / ".claude" / ".credentials.json").read_text() == b
        assert report["note"] == "split_brain"
        rows = s._store._list_unclaimed_credentials()
        assert [s._store._read_unclaimed_credential(i)[0] for i in rows] == [a]
        assert rotating.posts == []

    def test_ledger_row_names_the_account_not_the_slot(self, env):
        near = creds("AT-0", "RT-0", expires_in_s=NEAR)
        env.active(near)
        env.store._write_account_credentials(*SLOT, near)
        env.run()
        row = consumed_grants.entry(oauth.credential_fingerprint(near))
        assert (row["email"], row["organizationUuid"]) == IDENTITY["1"]
        assert "slot" not in row

    def test_a_consumed_copy_is_not_authoritative_over_a_working_one(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        spent = creds("AT-spent", "RT-spent", expires_in_s=20000)
        working = creds("AT-good", "RT-good", expires_in_s=7200)
        s._write_account_credentials(*SLOT, working)
        consumed_grants.record(
            oauth.credential_fingerprint(spent), IDENTITY["1"], consumed_grants.CONSUMED
        )
        block_real_keychain.data[ACTIVE_ITEM] = spent
        report = run_keepalive(s)
        assert report["action"] == "synced-keychain"
        assert block_real_keychain.data[ACTIVE_ITEM] == working
        assert rotating.posts == []

    def test_the_spent_copy_is_kept_and_its_older_replacement_is_never_posted(
        self, temp_home, block_real_keychain, rotating
    ):
        """An older link of a spent chain was very likely spent to make it."""
        s = macos_store(temp_home)
        spent = creds("AT-spent", "RT-spent", expires_in_s=20000)
        older = creds("AT-old", "RT-old", expires_in_s=NEAR)
        consumed_grants.record(
            oauth.credential_fingerprint(spent), IDENTITY["1"], consumed_grants.CONSUMED
        )
        block_real_keychain.data[ACTIVE_ITEM] = spent
        (temp_home / ".claude" / ".credentials.json").write_text(older)
        for _ in range(3):
            report = run_keepalive(new_process())
            assert report["error"]["type"] == "relogin_required"
        assert rotating.posts == []
        rows = s._store._list_unclaimed_credentials()
        assert [s._store._read_unclaimed_credential(i)[0] for i in rows] == [spent]

    def test_expired_older_copy_does_not_replace_a_spent_one_with_a_live_token(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        spent = creds("AT-spent", "RT-spent", expires_in_s=7200)
        consumed_grants.record(
            oauth.credential_fingerprint(spent), IDENTITY["1"], consumed_grants.CONSUMED
        )
        block_real_keychain.data[ACTIVE_ITEM] = spent
        (temp_home / ".claude" / ".credentials.json").write_text(
            creds("AT-old", "RT-old", expires_in_s=-60)
        )
        report = run_keepalive(s)
        assert report["action"] == "synced-file"
        assert block_real_keychain.data[ACTIVE_ITEM] == spent


class TestEveryPostGoesThroughTheHelper:
    def _functions_calling(self, name):
        """(file, enclosing function) of every call to `name` under src/."""
        found = set()
        root = Path(claude_swap.__file__).parent.parent
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for parent in ast.walk(tree):
                if not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(parent):
                    if isinstance(node, ast.Call):
                        func = node.func
                        called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                        if called == name:
                            found.add((path.name, parent.name))
        return found

    def test_only_the_helper_calls_the_post(self):
        assert self._functions_calling("try_refresh_oauth_credentials") == {
            ("switcher.py", "post_refresh"),
            # Reached only with refresh_via=None; pinned unreachable below.
            ("oauth.py", "try_fetch_usage_for_account"),
            ("oauth.py", "refresh_oauth_credentials"),
        }

    def test_the_helpers_callers_are_the_known_sites(self):
        assert self._functions_calling("post_refresh") == {
            ("switcher.py", "_consume_backup_grant_locked"),
            ("switcher.py", "_fetch_active_usage"),
            ("keepalive.py", "_refresh"),
        }

    def test_the_unreserved_oauth_paths_have_no_production_caller(self):
        assert self._functions_calling("refresh_oauth_credentials") == set()
        assert self._functions_calling("fetch_usage_for_account") == set()
        root = Path(claude_swap.__file__).parent.parent
        for path in root.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and getattr(
                    node.func, "attr", getattr(node.func, "id", "")
                ) == "try_fetch_usage_for_account":
                    keywords = {kw.arg: kw.value for kw in node.keywords}
                    if path.name == "oauth.py":
                        continue  # fetch_usage_for_account, pinned above
                    assert "refresh_via" in keywords or (
                        getattr(keywords.get("is_active"), "value", None) is True
                    ), f"{path.name}:{node.lineno} could POST without the gate"

    def test_the_token_url_is_only_used_by_the_post(self):
        root = Path(claude_swap.__file__).parent.parent
        users = [
            path.name
            for path in root.rglob("*.py")
            if "OAUTH_TOKEN_URL" in path.read_text() or "oauth/token" in path.read_text()
        ]
        assert users == ["oauth.py"]
        tree = ast.parse((root / "claude_swap" / "oauth.py").read_text())
        owners = {
            fn.name
            for fn in ast.walk(tree)
            if isinstance(fn, ast.FunctionDef)
            and any(
                isinstance(node, ast.Name) and node.id == "OAUTH_TOKEN_URL"
                for node in ast.walk(fn)
            )
        }
        assert owners == {"_post_grant"}

    @pytest.fixture
    def required(self, temp_home, block_real_keychain, monkeypatch):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        expired = creds("AT-b", "RT-b", expires_in_s=-100)
        s._write_account_credentials("2", "b@example.com", expired)
        s._write_account_credentials(*SLOT, creds("AT-a", "RT-a", expires_in_s=-100))
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-a", "RT-a", expires_in_s=-100)
        seen = []

        def post(request, timeout=None):
            token = json.loads(request.data)["refresh_token"]
            fingerprint = "sha256:" + hashlib.sha256(token.encode()).hexdigest()
            seen.append(consumed_grants.entry(fingerprint))
            raise TimeoutError

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post)
        monkeypatch.setattr(
            "claude_swap.oauth.try_fetch_usage_for_account",
            lambda *a, **kw: oauth.UsageOutcome(None, error="timeout"),
        )
        return s, expired, seen

    def _assert_reserved(self, seen):
        assert len(seen) == 1 and seen[0]["state"] == "reserved"

    def test_consume_gate_reserves_first(self, required):
        s, expired, seen = required
        s.consume_backup_grant("2", "b@example.com", expired)
        self._assert_reserved(seen)

    def test_fetch_path_reserves_first(self, required, block_real_keychain):
        s, _, seen = required
        live = block_real_keychain.data[ACTIVE_ITEM]
        s._fetch_active_usage("1", "a@example.com", live, "")
        self._assert_reserved(seen)

    def test_freshen_reserves_first(self, required):
        from claude_swap.autoswitch import AutoSwitchEngine
        from claude_swap.settings import load_settings

        s, _, seen = required
        engine = AutoSwitchEngine(s, load_settings(s.backup_dir), lambda event: None)
        assert engine._freshen_target("2", "b@example.com") == "transient"
        self._assert_reserved(seen)

    def test_keepalive_direct_reserves_first(self, required, block_real_keychain):
        s, _, seen = required
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-live", "RT-live", expires_in_s=NEAR)
        run_keepalive(s)  # the slot is on another lineage, so this bypasses the gate
        self._assert_reserved(seen)

    def test_keepalive_gate_reserves_first(self, required, block_real_keychain):
        s, _, seen = required
        near = creds("AT-a", "RT-a", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = near
        s._write_account_credentials(*SLOT, near)
        run_keepalive(s)
        self._assert_reserved(seen)


class TestReservationIsOneStep:
    def _race(self, consumers, post):
        """Every consumer past a barrier at once, each with its own attempt."""
        barrier = threading.Barrier(consumers)
        outcomes = []

        def consume():
            barrier.wait()
            outcomes.append(post())

        threads = [threading.Thread(target=consume) for _ in range(consumers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return outcomes

    def test_racing_consumers_produce_exactly_one_post(self, temp_home, monkeypatch):
        macos_store(temp_home)
        grant = creds("AT-0", "RT-0")
        posts = []
        lock = threading.Lock()

        def slow(request, timeout=None):
            with lock:
                posts.append(json.loads(request.data)["refresh_token"])
            time.sleep(0.05)
            return io.BytesIO(json.dumps({
                "access_token": "AT-1", "refresh_token": "RT-1", "expires_in": 28800,
            }).encode())

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", slow)
        outcomes = self._race(8, lambda: oauth.try_refresh_oauth_credentials(
            grant, ledger_identity=IDENTITY["1"]
        ))
        assert posts == ["RT-0"]
        assert sorted(str(outcome.error) for outcome in outcomes) == ["None"] + ["consumed"] * 7

    def test_a_reservation_is_claimed_once(self, temp_home):
        macos_store(temp_home)
        results = self._race(16, lambda: consumed_grants.reserve("sha256:a", IDENTITY["1"]))
        assert sorted(results) == [False] * 15 + [True]

    @pytest.mark.parametrize("state", ["reserved", "consumed"])
    def test_an_existing_row_forbids_the_post_and_is_left_alone(
        self, temp_home, rotating, state
    ):
        macos_store(temp_home)
        grant = creds("AT-0", "RT-0")
        fingerprint = oauth.credential_fingerprint(grant)
        consumed_grants.record(fingerprint, ("other@example.com", "org"), state)
        before = consumed_grants.entry(fingerprint)
        outcome = oauth.try_refresh_oauth_credentials(grant, ledger_identity=IDENTITY["1"])
        assert outcome.error == "consumed" and rotating.posts == []
        assert consumed_grants.entry(fingerprint) == before

    def test_the_consumer_that_lost_does_not_clear_the_winners_reservation(
        self, temp_home, rotating
    ):
        macos_store(temp_home)
        grant = creds("AT-0", "RT-0")
        fingerprint = oauth.credential_fingerprint(grant)
        consumed_grants.reserve(fingerprint, IDENTITY["1"])
        oauth.try_refresh_oauth_credentials(grant, ledger_identity=IDENTITY["1"])
        assert consumed_grants.entry(fingerprint)["state"] == "reserved"


class TestLedgerRetention:
    DAY = 24 * 3600

    def _seed(self, rows):
        path = consumed_grants._path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rows))
        return path

    def _row(self, state, age_days):
        return {
            "state": state, "email": "a@example.com", "organizationUuid": "",
            "at": time.time() - age_days * self.DAY,
        }

    def test_many_rows_evict_nothing(self, temp_home):
        macos_store(temp_home)
        self._seed({f"sha256:{n}": self._row("consumed", 1) for n in range(5000)})
        consumed_grants.record("sha256:new", IDENTITY["1"], consumed_grants.CONSUMED)
        assert consumed_grants.entry("sha256:0") is not None
        assert consumed_grants.entry("sha256:new") is not None

    def test_a_reservation_is_never_evicted_however_old(self, temp_home):
        macos_store(temp_home)
        self._seed({"sha256:uncertain": self._row("reserved", 5000)})
        consumed_grants.record("sha256:new", IDENTITY["1"], consumed_grants.CONSUMED)
        assert consumed_grants.entry("sha256:uncertain")["state"] == "reserved"

    def test_consumed_rows_are_kept_400_days_and_then_age_out(self, temp_home):
        macos_store(temp_home)
        self._seed({
            "sha256:kept": self._row("consumed", 399),
            "sha256:gone": self._row("consumed", 401),
        })
        consumed_grants.record("sha256:new", IDENTITY["1"], consumed_grants.CONSUMED)
        assert consumed_grants.entry("sha256:kept") is not None
        assert consumed_grants.entry("sha256:gone") is None

    def test_past_the_size_bound_it_fails_closed_without_evicting(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        near = creds("AT-0", "RT-0", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = near
        s._write_account_credentials(*SLOT, near)
        path = self._seed({f"sha256:{n}": self._row("consumed", 1) for n in range(50)})
        before = path.read_bytes()
        monkeypatch.setattr(consumed_grants, "MAX_BYTES", len(before))
        report = run_keepalive(new_process())
        assert report["error"] == {
            "type": "refresh_failed", "message": "consumed-grant ledger unreadable",
        }
        assert rotating.posts == []
        assert path.read_bytes() == before

    def test_a_refused_reservation_does_not_rewrite_the_file(self, temp_home):
        macos_store(temp_home)
        consumed_grants.reserve("sha256:a", IDENTITY["1"])
        inode = consumed_grants._path().stat().st_ino
        assert consumed_grants.reserve("sha256:a", IDENTITY["1"]) is False
        assert consumed_grants._path().stat().st_ino == inode


class TestSuccessorFollowsTheAccount:
    def _b_near(self, temp_home):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        near = creds("AT-0", "RT-0", expires_in_s=-60)
        s._write_account_credentials("2", "b@example.com", near)
        return s, near

    def test_move_during_the_post_then_a_retry_on_the_new_slot_adopts(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s, near = self._b_near(temp_home)

        def post_while_moving(request, timeout=None):
            response = rotating(request, timeout)
            s.move_account("2", "7")
            return response

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", post_while_moving)
        s.consume_backup_grant("2", "b@example.com", near)
        rows = s._store._list_unclaimed_credentials()
        assert [row["configSlot"] for row in rows.values()] == ["2"]
        assert [row["email"] for row in rows.values()] == ["b@example.com"]

        monkeypatch.setattr("claude_swap.oauth.urllib.request.urlopen", rotating)
        outcome = s.consume_backup_grant("7", "b@example.com", near)
        assert outcome.error is None and access_token(outcome.credentials) == "AT-1"
        assert rotating.posts == ["RT-0"]
        assert access_token(s._read_account_credentials("7", "b@example.com")) == "AT-1"
        assert s._store._list_unclaimed_credentials() == {}

    def test_keepalive_adopts_on_the_new_slot_after_a_move(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-0", "RT-0", expires_in_s=NEAR)
        s._write_account_credentials(*SLOT, creds("AT-old", "RT-old", expires_in_s=-100))
        real_set = block_real_keychain.set_password
        monkeypatch.setattr(
            macos_keychain, "set_password", _active_item_write_fails(block_real_keychain)
        )
        assert run_keepalive(s)["error"]["type"] == "keychain_unavailable"
        assert rotating.posts == ["RT-0"]

        monkeypatch.setattr(macos_keychain, "set_password", real_set)
        s.move_account("1", "7")
        report = run_keepalive(new_process())
        assert report["ok"] is True and report["activeSlot"] == 7
        assert rotating.posts == ["RT-0"]
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"

    def test_a_row_for_another_account_on_the_same_number_is_not_adopted(
        self, temp_home, block_real_keychain
    ):
        """After a swap the number means someone else, and the bytes are not theirs."""
        s = macos_store(temp_home)
        spent = creds("AT-0", "RT-0")
        s._write_account_credentials("2", "b@example.com", spent)
        s.stash_consumed_successor(
            "2", ("a@example.com", ""), creds("AT-A", "RT-A"),
            oauth.credential_fingerprint(spent), "keepalive-live-write-failed",
        )
        assert s._adopt_stashed_successor("2", "b@example.com", spent) is None
        assert len(s._store._list_unclaimed_credentials()) == 1

    def test_a_login_that_became_managed_adopts_what_it_parked_unmanaged(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        spent = creds("AT-0", "RT-0", expires_in_s=NEAR)
        block_real_keychain.data[ACTIVE_ITEM] = spent
        s.stash_consumed_successor(
            "unmanaged", IDENTITY["1"], creds("AT-1", "RT-1"),
            oauth.credential_fingerprint(spent), "keepalive-live-write-failed",
        )
        assert run_keepalive(s)["action"] == "synced-keychain"
        assert rotating.posts == []
        assert access_token(block_real_keychain.data[ACTIVE_ITEM]) == "AT-1"

    def test_rows_from_before_the_identity_still_go_by_the_slot_number(
        self, temp_home, block_real_keychain
    ):
        s = macos_store(temp_home)
        spent = creds("AT-0", "RT-0")
        s._write_account_credentials(*SLOT, spent)
        s._store._write_unclaimed_credential(creds("AT-1", "RT-1"), {
            "reason": "consume-gate-persist-failed",
            "configSlot": "1",
            "consumedFp": oauth.credential_fingerprint(spent),
        })
        assert access_token(s._adopt_stashed_successor(*SLOT, spent)) == "AT-1"


class TestIdentityIsCapturedWithTheCredential:
    def test_move_after_the_lock_keeps_the_identity_and_the_retry_adopts(
        self, temp_home, block_real_keychain, rotating, monkeypatch
    ):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        data = s._get_sequence_data()
        data["accounts"]["2"]["organizationUuid"] = "org-b"
        s._write_json(s.sequence_file, data)
        near = creds("AT-0", "RT-0", expires_in_s=-60)
        s._write_account_credentials("2", "b@example.com", near)

        real_lock = switcher_module.FileLock
        armed = [True]

        class MovesAfterTheGatesFirstRelease(real_lock):
            def __exit__(self, *args):
                super().__exit__(*args)
                if armed[0] and self.lock_path == s.lock_file:
                    armed[0] = False
                    s.move_account("2", "7")

        monkeypatch.setattr(switcher_module, "FileLock", MovesAfterTheGatesFirstRelease)
        s.consume_backup_grant("2", "b@example.com", near)
        monkeypatch.setattr(switcher_module, "FileLock", real_lock)
        assert armed == [False] and rotating.posts == ["RT-0"]

        rows = s._store._list_unclaimed_credentials()
        assert [(row["email"], row["organizationUuid"]) for row in rows.values()] == [
            ("b@example.com", "org-b")
        ]
        row = consumed_grants.entry(oauth.credential_fingerprint(near))
        assert (row["email"], row["organizationUuid"]) == ("b@example.com", "org-b")

        outcome = s.consume_backup_grant("7", "b@example.com", near)
        assert outcome.error is None and access_token(outcome.credentials) == "AT-1"
        assert rotating.posts == ["RT-0"]
        assert s._store._list_unclaimed_credentials() == {}


class TestDryRunChangesNothing:
    def test_divergent_backup_copies_stay_byte_identical(
        self, temp_home, block_real_keychain, rotating
    ):
        s = macos_store(temp_home)
        set_setting(s.backup_dir, "credentials.requireKeychain", "true")
        # Slot 1's Keychain copy and its leftover .enc differ, and the older .enc is
        # the one a read used to delete. The live stores differ as well.
        s._write_account_credentials(*SLOT, creds("AT-kc", "RT-kc", expires_in_s=7200))
        s._store._write_backup_enc(*SLOT, creds("AT-enc", "RT-enc", expires_in_s=100))
        s._write_account_credentials("2", "b@example.com", creds("AT-b", "RT-b", expires_in_s=7200))
        s._store._write_backup_enc("2", "b@example.com", creds("AT-b0", "RT-b0", expires_in_s=100))
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-K", "RT-K", expires_in_s=NEAR)
        (temp_home / ".claude" / ".credentials.json").write_text(
            creds("AT-F", "RT-F", expires_in_s=NEAR - 10)
        )
        before = snapshot(temp_home, block_real_keychain)
        assert any(name.endswith(".enc") for name in before["files"])
        report = run_keepalive(new_process(), dry_run=True, ensure_file=True)
        assert report["dryRun"] is True
        assert snapshot(temp_home, block_real_keychain) == before
        assert rotating.posts == []


class TestStashIsPruned:
    OLD = 32 * 24 * 3600

    @pytest.fixture
    def store(self, temp_home, block_real_keychain, rotating):
        s = macos_store(temp_home)
        block_real_keychain.data[ACTIVE_ITEM] = creds("AT-live", "RT-live", expires_in_s=7200)
        s._write_account_credentials(*SLOT, block_real_keychain.data[ACTIVE_ITEM])
        return s

    def _stash(self, s, value, *, age_s=None, **context):
        entry_id = s._store._write_unclaimed_credential(value, {
            "reason": "keepalive-split-brain",
            "configSlot": "1",
            "email": "a@example.com",
            "organizationUuid": "",
            "fingerprint": oauth.credential_fingerprint(value),
            **context,
        })
        if age_s is not None:
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age_s))
            s._store._mutate_stash_manifest(
                lambda rows: rows[entry_id].update(createdAt=stamp)
            )
        return entry_id

    def _ids(self, s):
        return set(s._store._list_unclaimed_credentials())

    def _consumed(self, value, identity=IDENTITY["1"]):
        consumed_grants.record(
            oauth.credential_fingerprint(value), identity, consumed_grants.CONSUMED
        )

    def test_consumed_with_a_newer_unspent_login_in_a_store_goes(self, store):
        spent = creds("AT-0", "RT-0", expires_in_s=100)
        self._consumed(spent)
        self._stash(store, spent)
        run_keepalive(store)
        assert self._ids(store) == set()

    def test_consumed_with_its_successor_in_another_entry_goes(self, store):
        spent = creds("AT-0", "RT-0", expires_in_s=30000)  # nothing in a store is newer
        self._consumed(spent)
        gone = self._stash(store, spent)
        kept = self._stash(
            store, creds("AT-1", "RT-1", expires_in_s=30000),
            consumedFp=oauth.credential_fingerprint(spent),
        )
        run_keepalive(store)
        ids = self._ids(store)
        assert gone not in ids and kept in ids

    def test_consumed_with_no_successor_stays(self, store):
        spent = creds("AT-0", "RT-0", expires_in_s=30000)
        self._consumed(spent)
        entry = self._stash(store, spent)
        run_keepalive(store)
        assert entry in self._ids(store)

    def test_a_successor_that_is_itself_spent_does_not_count(self, store, block_real_keychain):
        live = block_real_keychain.data[ACTIVE_ITEM]
        self._consumed(live)
        spent = creds("AT-0", "RT-0", expires_in_s=100)
        self._consumed(spent)
        entry = self._stash(store, spent)
        run_keepalive(store)
        assert entry in self._ids(store)

    def test_consumed_for_another_account_looks_at_that_accounts_slot(self, store):
        b = ("b@example.com", "")
        spent = creds("AT-b0", "RT-b0", expires_in_s=100)
        self._consumed(spent, b)
        entry = self._stash(store, spent)
        run_keepalive(store)
        assert entry in self._ids(store)  # slot 2 holds nothing newer, whatever the live login is
        store._write_account_credentials("2", "b@example.com", creds("AT-b1", "RT-b1"))
        run_keepalive(new_process())
        assert entry not in self._ids(store)

    def test_older_than_31_days_by_its_timestamp_goes(self, store):
        entry = self._stash(store, creds("AT-0", "RT-0"), age_s=self.OLD)
        run_keepalive(store)
        assert entry not in self._ids(store)

    def test_younger_than_31_days_stays(self, store):
        entry = self._stash(store, creds("AT-0", "RT-0"), age_s=30 * 24 * 3600)
        run_keepalive(store)
        assert entry in self._ids(store)

    def test_no_timestamp_goes_by_the_file_mtime(self, store):
        old = store._store._stash_entry_path("orphan-old")
        new = store._store._stash_entry_path("orphan-new")
        encoded = base64.b64encode(creds("AT-o", "RT-o").encode())
        store.credentials_dir.mkdir(parents=True, exist_ok=True)
        for path in (old, new):
            path.write_bytes(encoded)
        os.utime(old, (time.time() - self.OLD, time.time() - self.OLD))
        run_keepalive(store)
        assert not old.exists() and new.exists()

    @pytest.mark.parametrize("age_s", [None, 400 * 24 * 3600], ids=["new", "old"])
    def test_a_reservation_is_never_deleted(self, store, age_s):
        value = creds("AT-0", "RT-0", expires_in_s=100)
        consumed_grants.reserve(oauth.credential_fingerprint(value), IDENTITY["1"])
        entry = self._stash(store, value, age_s=age_s)
        run_keepalive(store)
        assert entry in self._ids(store)

    def test_dry_run_deletes_nothing(self, store, temp_home, block_real_keychain):
        self._stash(store, creds("AT-0", "RT-0"), age_s=self.OLD)
        spent = creds("AT-1", "RT-1", expires_in_s=100)
        self._consumed(spent)
        self._stash(store, spent)
        before = snapshot(temp_home, block_real_keychain)
        report = run_keepalive(new_process(), dry_run=True)
        assert report["ok"] is True
        assert snapshot(temp_home, block_real_keychain) == before

    def test_an_unreadable_manifest_deletes_nothing(self, store, monkeypatch):
        entry = self._stash(store, creds("AT-0", "RT-0"), age_s=self.OLD)
        monkeypatch.setattr(store._store, "_read_stash_manifest_ex", lambda: ({}, "unreadable"))
        keepalive._prune_stash(keepalive._read_active(store), "", "")
        monkeypatch.undo()
        assert entry in self._ids(store)

    def test_an_unreadable_entry_stays(self, store, monkeypatch):
        entry = self._stash(store, creds("AT-0", "RT-0"), age_s=self.OLD)
        monkeypatch.setattr(store._store, "_read_unclaimed_credential", lambda i: ("", True))
        keepalive._prune_stash(keepalive._read_active(store), "", "")
        monkeypatch.undo()
        assert entry in self._ids(store)

    def test_pruning_runs_without_a_login_too(self, temp_home, block_real_keychain, rotating):
        s = macos_store(temp_home)
        entry = self._stash(s, creds("AT-0", "RT-0"), age_s=self.OLD)
        assert run_keepalive(s)["error"]["type"] == "no_credentials"
        assert entry not in self._ids(s)
