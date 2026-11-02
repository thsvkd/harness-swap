"""Opt-in automatic switching for harnesses that report usage (``hswap <harness> auto``).

One pass (:func:`run_once`) per active account (one per provider for
multi-provider harnesses):

* stay while the active account has fresh ``available`` usage below the
  threshold, or while its usage is unknown -- never switch on missing data;
* when it is at/over the threshold or rate limited, switch to the account with
  the most headroom (:func:`rotation.select_account`, strategy ``best``);
* never more than once per ``auto.cooldown`` seconds per harness, so a
  provider's lagging usage numbers cannot make it flap.

The harness must be listed in the ``auto.enabled`` setting: switching to other
accounts to keep working past a limit can breach a provider's terms, so it is
the user's explicit choice per harness. Overlapping runs (cron plus a terminal)
are serialised: a second run that finds one in progress does nothing.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from harness_swap.core import settings
from harness_swap.core.accounts import collect_usage
from harness_swap.core.adapter import (
    AccountSwitcher,
    HarnessAdapter,
    UsageReader,
    require,
)
from harness_swap.core.errors import UnsupportedOperation
from harness_swap.core.models import Capability, UsageSnapshot, UsageState
from harness_swap.core.paths import harness_home
from harness_swap.core.rotation import select_account
from harness_swap.core.store import mkdir_private
from harness_swap.core.usage import UsageService
from harness_swap.infrastructure.fsutil import atomic_write_text
from harness_swap.infrastructure.locking import FileLock


def _used(snap: UsageSnapshot) -> str:
    used = snap.max_used_percent
    return f"{used:g}%" if used is not None else "?"


def run_once(
    adapter: HarnessAdapter,
    service: UsageService,
    *,
    threshold: float,
    cooldown_s: float,
    provider: str | None = None,
    dry_run: bool = False,
    clock: Callable[[], float] = time.time,
) -> list[dict]:
    """One decision per active account. Returns JSON-ready events."""
    if not settings.opted_in("auto.enabled", adapter.id):
        raise UnsupportedOperation(
            str(Capability.AUTOMATIC_ROTATION),
            f"off for {adapter.id}; turn it on with `hswap config set auto.enabled <ids>` "
            "(include the harnesses already listed) after reading the warning it prints",
        )
    switcher = require(adapter, Capability.AUTOMATIC_ROTATION, AccountSwitcher)
    require(adapter, Capability.USAGE_MONITORING, UsageReader)
    home = harness_home(adapter.id)
    mkdir_private(home)
    lock = FileLock(home / ".auto.lock", timeout=0)
    if not lock.acquire(timeout=0):
        return [{"action": "skip", "reason": "another `auto` run is in progress"}]
    try:
        return _decide(adapter, switcher, service, home, threshold, cooldown_s, provider, dry_run, clock)
    finally:
        lock.release()


def _decide(adapter, switcher, service, home, threshold, cooldown_s, provider, dry_run, clock) -> list[dict]:
    accounts = adapter.list_accounts()
    actives = [a for a in accounts if a.active and (provider is None or a.provider == provider)]
    if not actives:
        return [{"action": "stay", "reason": "no managed account is active"}]
    state_path = home / "auto-state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        state = {}
    events = []
    for current in actives:
        pool = [a for a in accounts if a.provider == current.provider]
        usage = collect_usage(adapter, pool, service)
        snap = usage[current.key]
        event = {"provider": current.provider, "current": current.to_json(), "usage": snap.to_json()}
        exhausted = snap.state is UsageState.RATE_LIMITED or (
            snap.state is UsageState.AVAILABLE and (snap.max_used_percent or 0) >= threshold
        )
        if not exhausted:
            reason = (
                f"{current.label} is at {_used(snap)}, below {threshold:g}%"
                if snap.state is UsageState.AVAILABLE
                else f"no current usage for {current.label} ({snap.state}); not switching without data"
            )
            events.append({**event, "action": "stay", "reason": reason})
            continue
        target = select_account(pool, usage, current=current, strategy="best", threshold=threshold)
        if target is None:
            events.append({**event, "action": "stay", "reason": "no other account has known headroom"})
            continue
        since = clock() - float(state.get("lastSwitchAt", 0))
        if since < cooldown_s:
            events.append(
                {**event, "action": "wait", "target": target.to_json(),
                 "reason": f"last automatic switch {since:.0f}s ago (cooldown {cooldown_s:g}s)"}
            )
            continue
        why = f"{current.label} is at {_used(snap)}" if snap.state is UsageState.AVAILABLE else f"{current.label} is rate limited"
        if dry_run:
            events.append({**event, "action": "would-switch", "target": target.to_json(), "reason": why})
            continue
        result = switcher.switch_account(target)
        state["lastSwitchAt"] = clock()
        atomic_write_text(state_path, json.dumps(state))
        events.append({**event, "action": "switch", "target": target.to_json(), "reason": why, "result": result.to_json()})
    return events
