"""Snapshot credential activation: the guarantees every file-backed adapter relies on."""

from __future__ import annotations

import json
import sys
import threading

import pytest

from harness_swap.core.credentials import Identity, SnapshotCredentials
from harness_swap.core.errors import CredentialConflict, CredentialError, LockError
from harness_swap.core.store import AccountStore
from harness_swap.infrastructure.locking import FileLock


class ScopedFormat:
    """A two-level document like Grok's: ``{scope: {"user": .., "token": ..}}``."""

    secret_name = "auth.json"

    def parts(self, doc):
        return {k: v for k, v in doc.items() if isinstance(v, dict) and "token" in v}

    def identify(self, key, part):
        return Identity(part["user"], f"{part['user']}@x", "prov", "oauth") if part.get("user") else None

    def merge(self, doc, key, part):
        out = dict(doc or {})
        out[key] = part
        return out


def entry(user, token):
    return {"user": user, "token": token}


@pytest.fixture
def env(tmp_path):
    live = tmp_path / "home" / "auth.json"
    live.parent.mkdir()
    store = AccountStore(tmp_path / "store")
    creds = SnapshotCredentials(ScopedFormat(), store, live, live.parent / "auth.json.lock", lock_timeout=0.5)
    return live, store, creds


def write(path, doc):
    path.write_text(json.dumps(doc))


def read(path):
    return json.loads(path.read_text())


def add(creds, live, doc):
    write(live, doc)
    return creds.add_current()


def test_switch_round_trip_and_sync_back_of_rotated_tokens(env):
    live, store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    add(creds, live, {"s": entry("bob", "b-1")})
    # bob's harness rotates his token while he is active
    write(live, {"s": entry("bob", "b-2")})
    target, previous = creds.activate(1)
    assert (target.slot, previous.slot) == (1, 2)
    assert read(live)["s"] == entry("alice", "a-1")
    # bob's stored copy received the rotated token before being replaced
    assert read(store.account_dir(2) / "auth.json")["s"]["token"] == "b-2"
    creds.activate(2)
    assert read(live)["s"]["token"] == "b-2"


def test_other_scopes_are_carried_over_untouched(env):
    live, _store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    add(creds, live, {"s": entry("bob", "b-1")})
    write(live, {"s": entry("bob", "b-1"), "other": {"token": "keep-me"}, "settings": {"x": 1}})
    creds.activate(1)
    doc = read(live)
    assert doc["other"] == {"token": "keep-me"} and doc["settings"] == {"x": 1}
    assert doc["s"]["user"] == "alice"


def test_unmanaged_live_login_is_never_overwritten_silently(env):
    live, _store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    write(live, {"s": entry("mallory", "m-1")})
    before = live.read_bytes()
    with pytest.raises(CredentialConflict, match="mallory@x"):
        creds.activate(1)
    assert live.read_bytes() == before


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_force_stashes_the_unmanaged_login_privately(env):
    live, store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    write(live, {"s": entry("mallory", "m-1")})
    before = live.read_bytes()
    creds.activate(1, force=True)
    (stash,) = (store.root / "stash").iterdir()
    assert stash.read_bytes() == before
    assert stash.stat().st_mode & 0o777 == 0o600
    assert read(live)["s"]["user"] == "alice"


def test_failed_write_restores_the_original_file(env, monkeypatch):
    live, _store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    add(creds, live, {"s": entry("bob", "b-1")})
    before = live.read_bytes()
    calls = []
    real = creds._read_live

    def broken_read():  # the read-back after writing sees a different account
        calls.append(1)
        raw, doc = real()
        if len(calls) == 2:
            return raw, {"s": entry("bob", "b-1")}
        return raw, doc

    monkeypatch.setattr(creds, "_read_live", broken_read)
    with pytest.raises(CredentialError, match="did not read back"):
        creds.activate(1)
    assert live.read_bytes() == before


def test_interrupted_write_leaves_the_original_file(env, monkeypatch):
    live, _store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    add(creds, live, {"s": entry("bob", "b-1")})
    before = live.read_bytes()

    def refuse(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("harness_swap.infrastructure.fsutil.replace_with_retry", refuse)
    with pytest.raises(OSError):
        creds.activate(1)
    assert live.read_bytes() == before
    assert sorted(p.name for p in live.parent.iterdir() if not p.name.endswith(".lock")) == ["auth.json"]


def test_switch_into_a_missing_live_file(env):
    live, _store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    live.unlink()
    creds.activate(1)
    assert read(live)["s"]["user"] == "alice"


def test_tampered_snapshot_is_refused(env):
    live, store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    add(creds, live, {"s": entry("bob", "b-1")})
    write(store.account_dir(1) / "auth.json", {"s": entry("eve", "e-1")})
    before = live.read_bytes()
    with pytest.raises(CredentialError, match="different account"):
        creds.activate(1)
    assert live.read_bytes() == before


def test_harness_lock_held_blocks_the_switch(env):
    live, _store, creds = env
    add(creds, live, {"s": entry("alice", "a-1")})
    add(creds, live, {"s": entry("bob", "b-1")})
    before = live.read_bytes()
    holder = FileLock(live.parent / "auth.json.lock")
    assert holder.acquire()
    try:
        with pytest.raises(LockError, match="refreshing"):
            creds.activate(1)
    finally:
        holder.release()
    assert live.read_bytes() == before


def test_harness_lock_file_is_not_truncated(env):
    live, _store, creds = env
    lock = live.parent / "auth.json.lock"
    lock.write_text("12345")
    add(creds, live, {"s": entry("alice", "a-1")})
    add(creds, live, {"s": entry("bob", "b-1")})
    creds.activate(1)
    assert lock.read_text() == "12345"


def test_concurrent_switches_never_corrupt_anything(env):
    live, store, creds = env
    users = ["alice", "bob", "carol"]
    for u in users:
        add(creds, live, {"s": entry(u, f"{u}-1")})
    errors = []

    def worker(slot):
        try:
            for _ in range(15):
                creds.activate(slot)
        except LockError:
            pass
        except Exception as exc:  # noqa: BLE001 - anything else is a bug
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(s,)) for s in (1, 2, 3, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert read(live)["s"]["user"] in users
    for slot, user in enumerate(users, start=1):
        assert read(store.account_dir(slot) / "auth.json")["s"]["user"] == user


def test_errors_never_contain_secret_material(env):
    live, _store, creds = env
    add(creds, live, {"s": entry("alice", "SECRET-TOKEN-VALUE")})
    write(live, {"s": entry("mallory", "OTHER-SECRET")})
    with pytest.raises(CredentialConflict) as exc:
        creds.activate(1)
    assert "SECRET" not in str(exc.value)
    live.write_text("{not json SECRET-TOKEN")
    with pytest.raises(CredentialError) as exc:
        creds.activate(1)
    assert "SECRET" not in str(exc.value)


def test_add_with_nothing_signed_in(env):
    _live, _store, creds = env
    with pytest.raises(CredentialError, match="not signed in"):
        creds.add_current()
