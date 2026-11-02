"""Shared usage collection: caching, pacing, backoff and staleness.

Adapters only know how to take *one* measurement (:class:`UsageReader`).
This service decides *when* to take it, so every adapter gets the same
manners without reimplementing them:

* never more than once per ``UsagePolicy.min_interval_s`` per account, even
  across concurrent ``hswap`` processes (the cache is shared on disk and
  updated under a lock);
* after a failure, exponential backoff up to ``max_backoff_s``; meanwhile
  the result is an ``error`` snapshot that still carries the last good
  numbers (so it is never mistaken for fresh headroom);
* a measurement older than ``stale_after_s`` is reported ``stale``;
* an adapter exception becomes an ``error`` snapshot, never a crash.

The cache holds usage numbers and timestamps only -- no credentials.
"""

from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Callable
from pathlib import Path

from harness_swap.core.adapter import UsageReader
from harness_swap.core.models import Account, QuotaWindow, UsageSnapshot, UsageState
from harness_swap.core.store import mkdir_private
from harness_swap.infrastructure.fsutil import atomic_write_text
from harness_swap.infrastructure.locking import FileLock

_CACHE_NAME = "usage-cache.json"


def _to_cache(s: UsageSnapshot) -> dict:
    d = dataclasses.asdict(s)
    d["state"] = str(s.state)
    return d


def _from_cache(d: dict) -> UsageSnapshot:
    windows = tuple(QuotaWindow(**w) for w in d.get("windows", ()))
    return UsageSnapshot(**{**d, "state": UsageState(d["state"]), "windows": windows})


class UsageService:
    def __init__(self, cache_dir: Path, clock: Callable[[], float] = time.time):
        self.cache_dir = cache_dir
        self.clock = clock

    def _path(self) -> Path:
        return self.cache_dir / _CACHE_NAME

    def _load(self) -> dict:
        try:
            data = json.loads(self._path().read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    #: How long a claimed measurement may take before another process may retry it.
    CLAIM_S = 300.0

    def _lock(self) -> FileLock:
        mkdir_private(self.cache_dir)
        return FileLock(self.cache_dir / ".usage.lock", timeout=30.0)

    def _entry(self, cache: dict, key: str) -> tuple[dict, UsageSnapshot | None]:
        entry = cache.get(key)
        entry = entry if isinstance(entry, dict) else {}
        try:
            return entry, (_from_cache(entry["snapshot"]) if "snapshot" in entry else None)
        except (TypeError, ValueError, KeyError, AttributeError):
            return {}, None  # written by another hswap version: start over

    def get(self, reader: UsageReader, account: Account) -> UsageSnapshot:
        """The account's usage, measuring it when the policy allows.

        The cache lock is held only to decide and to record, never while the
        adapter measures (asking a harness can take a minute): the measurement
        is *claimed* in the cache first, so a concurrent process serves the last
        numbers instead of starting a second measurement.
        """
        policy = reader.usage_policy
        now = self.clock()
        with self._lock():
            cache = self._load()
            entry, last = self._entry(cache, account.key)
            failures = entry.get("failures", 0)
            if failures and now < entry.get("retry_at", 0.0):
                return self._failed(last, entry.get("error", "usage read failed"))
            if not failures and last is not None and now < entry.get("fetched_at", 0.0) + policy.min_interval_s:
                return self._aged(last, policy.stale_after_s, now)
            if now < entry.get("claimed_until", 0.0):
                if last is None:
                    return UsageSnapshot(UsageState.UNKNOWN, detail="being measured by another hswap process")
                return self._aged(last, policy.stale_after_s, now)
            cache[account.key] = {**entry, "claimed_until": now + self.CLAIM_S}
            atomic_write_text(self._path(), json.dumps(cache, indent=1))
        try:
            snap = reader.read_usage(account)
            keep_last = snap.state is UsageState.STALE and not snap.windows and last is not None
            error = None
        except Exception as exc:  # noqa: BLE001 - any adapter failure becomes an error snapshot
            snap, keep_last, error = None, False, f"{type(exc).__name__}: {exc}"
        with self._lock():
            cache = self._load()
            entry, last = self._entry(cache, account.key)
            entry.pop("claimed_until", None)
            if keep_last and last is not None:
                # The adapter cannot measure right now (e.g. the account is not
                # the active one): keep serving the last measurement.
                snap = dataclasses.replace(last, state=UsageState.STALE, detail=snap.detail)  # type: ignore[union-attr]
            elif error is not None:
                failures = entry.get("failures", 0) + 1
                delay = min(policy.min_interval_s * 2**failures, policy.max_backoff_s)
                entry = {**entry, "failures": failures, "retry_at": now + delay, "error": error}
                snap = self._failed(last, error)
            else:
                entry = {"snapshot": _to_cache(snap), "fetched_at": now, "failures": 0}  # type: ignore[arg-type]
            cache[account.key] = entry
            atomic_write_text(self._path(), json.dumps(cache, indent=1))
        return self._aged(snap, policy.stale_after_s, now)  # type: ignore[arg-type]

    def peek(self, reader: UsageReader, account: Account) -> UsageSnapshot:
        """The cached measurement only: no adapter call, no network, no token
        refresh. ``unknown`` when nothing was measured yet."""
        entry = self._load().get(account.key)
        try:
            last = _from_cache(entry["snapshot"]) if isinstance(entry, dict) and "snapshot" in entry else None
        except (TypeError, ValueError, KeyError, AttributeError):
            last = None
        if last is None:
            return UsageSnapshot(UsageState.UNKNOWN, detail="not measured yet (cached read)")
        if isinstance(entry, dict) and entry.get("failures"):
            return self._failed(last, entry.get("error", "usage read failed"))
        return self._aged(last, reader.usage_policy.stale_after_s, self.clock())

    @staticmethod
    def _failed(last: UsageSnapshot | None, detail: str) -> UsageSnapshot:
        """An ``error`` snapshot that still carries the last good numbers."""
        return UsageSnapshot(
            UsageState.ERROR,
            windows=last.windows if last else (),
            measured_at=last.measured_at if last else None,
            source=last.source if last else "",
            detail=detail,
        )

    @staticmethod
    def _aged(snap: UsageSnapshot, stale_after_s: float, now: float) -> UsageSnapshot:
        age = snap.age_s(now)
        if snap.state is UsageState.AVAILABLE and age is not None and age > stale_after_s:
            return dataclasses.replace(snap, state=UsageState.STALE)
        return snap
