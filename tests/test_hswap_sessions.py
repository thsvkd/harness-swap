"""Isolated-session plumbing: lock lifetime, exit status, slot reuse."""

from __future__ import annotations

import os
import sys

import pytest

from harness_swap.core import sessions
from harness_swap.core.store import AccountStore

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell semantics")


@posix_only
def test_background_children_of_the_harness_do_not_keep_the_session_in_use(tmp_path):
    profile = tmp_path / "p"
    fd = sessions.acquire(profile)
    code = sessions.launch(["sh", "-c", "sleep 30 >/dev/null 2>&1 & exit 0"], dict(os.environ), fd)
    assert code == 0
    assert not sessions.in_use(profile)


@posix_only
def test_exit_status_and_signals_are_reported_like_a_shell(tmp_path):
    assert sessions.launch(["sh", "-c", "exit 7"], dict(os.environ)) == 7
    assert sessions.launch(["sh", "-c", "kill -TERM $$"], dict(os.environ)) == 128 + 15


def test_lock_is_held_while_running_and_released_after(tmp_path):
    profile = tmp_path / "p"
    fd = sessions.acquire(profile)
    assert sessions.in_use(profile)
    with pytest.raises(Exception, match="already running"):
        sessions.acquire(profile)
    sessions.launch([sys.executable, "-c", "pass"], dict(os.environ), fd)
    assert not sessions.in_use(profile)


def test_removed_slot_with_history_is_not_reused(tmp_path):
    store = AccountStore(tmp_path / "s")
    accounts = []
    store.upsert(accounts, identity="a", label="a", provider=None, auth_mode=None, part_key="")
    store.save(accounts)
    store.write_secret(1, "auth.json", b"{}")
    (store.account_dir(1) / "history.jsonl").write_text("old conversations")
    store.delete(1, ("auth.json",))
    new, _ = store.upsert([], identity="b", label="b", provider=None, auth_mode=None, part_key="")
    assert new.slot == 2


def test_remove_is_refused_while_a_session_runs(tmp_path):
    store = AccountStore(tmp_path / "s")
    accounts = []
    store.upsert(accounts, identity="a", label="a", provider=None, auth_mode=None, part_key="")
    store.save(accounts)
    fd = sessions.acquire(store.account_dir(1))
    try:
        with pytest.raises(Exception, match="busy"):
            store.delete(1, (), refuse=lambda d: "busy" if sessions.in_use(d) else None)
    finally:
        os.close(fd)
    assert [a.slot for a in store.load()] == [1]


def test_a_missing_executable_is_a_clean_error_and_frees_the_lock(tmp_path):
    from harness_swap.core.errors import HswapError

    profile = tmp_path / "p"
    fd = sessions.acquire(profile)
    with pytest.raises(HswapError, match="could not start"):
        sessions.launch([str(tmp_path / "no-such-harness")], dict(os.environ), fd)
    assert not sessions.in_use(profile)
