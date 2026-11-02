"""Harness-agnostic account selection from normalised usage.

Pure functions over :class:`Account` / :class:`UsageSnapshot`: no IO, no
provider knowledge, no credential activation. The caller collects usage and
performs the switch; this module only answers "which account next?".

Selection is always scoped to one harness (and, when given, one provider).
Nothing here routes work across harnesses.

Rules:

* ``best`` needs evidence: only accounts with ``available`` usage below the
  threshold qualify, and the one with the most headroom wins (earliest reset
  breaks ties). Unknown or stale usage is never treated as headroom.
* ``next-available`` rotates in slot order after the current account and
  skips only accounts *known* to be unusable (rate limited, at/over the
  threshold, needing re-authentication).
* The current account is never selected.
"""

from __future__ import annotations

from harness_swap.core.models import Account, UsageSnapshot, UsageState

STRATEGIES = ("best", "next-available")

_BLOCKED = (UsageState.RATE_LIMITED, UsageState.AUTHENTICATION_REQUIRED)


def _known_exhausted(snap: UsageSnapshot | None, threshold: float) -> bool:
    if snap is None:
        return False
    if snap.state in _BLOCKED:
        return True
    used = snap.max_used_percent
    return snap.state is UsageState.AVAILABLE and used is not None and used >= threshold


def _soonest_reset(snap: UsageSnapshot) -> float:
    resets = [w.resets_at for w in snap.windows if w.resets_at is not None]
    return min(resets) if resets else float("inf")


def select_account(
    accounts: list[Account],
    usage: dict[str, UsageSnapshot],
    *,
    current: Account | None,
    strategy: str,
    threshold: float = 95.0,
    provider: str | None = None,
) -> Account | None:
    """Pick the next account, or ``None`` when no candidate qualifies.

    ``usage`` is keyed by :attr:`Account.key`.
    """
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy!r}; choose from {', '.join(STRATEGIES)}")
    pool = [
        a
        for a in accounts
        if (provider is None or a.provider == provider)
        and (current is None or a.key != current.key)
    ]
    if strategy == "best":
        scored = []
        for acc in pool:
            snap = usage.get(acc.key)
            if snap is None or snap.state is not UsageState.AVAILABLE:
                continue
            used = snap.max_used_percent
            if used is None or used >= threshold:
                continue
            scored.append((used, _soonest_reset(snap), acc.slot or 0, acc))
        return min(scored, key=lambda t: t[:3])[3] if scored else None

    ordered = sorted(pool, key=lambda a: a.slot or 0)
    start = (current.slot or 0) if current else 0
    after = [a for a in ordered if (a.slot or 0) > start] + [a for a in ordered if (a.slot or 0) <= start]
    for acc in after:
        if not _known_exhausted(usage.get(acc.key), threshold):
            return acc
    return None
