"""Provider-neutral domain models.

Nothing here knows about any particular harness. Adapters translate their
own data into these shapes; the CLI, the TUI and the rotation policy read
only these shapes.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import UTC
from enum import StrEnum

#: Alias validation: letters/digits/-/_/., non-empty, not purely digits (so an
#: alias can never collide with a slot number in _resolve_account_identifier),
#: and not leading with '-' (argparse would treat it as an option, making the
#: alias impossible to pass back into any command once set).
_ALIAS_RE = re.compile(r"^[a-z0-9_.-]+$")


def normalize_alias(name: str) -> str:
    """Lowercase and validate a proposed alias; raise ValueError if invalid.

    Shared by every adapter's alias commands and by the Claude engine
    (``cswap alias``, ``add --alias``, import validation), so every path
    enforces identical rules.
    """
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("alias cannot be empty")
    if normalized.isdigit():
        raise ValueError(f"alias '{name}' cannot be purely numeric (reserved for slot numbers)")
    if normalized.startswith("-"):
        raise ValueError(
            f"alias '{name}' cannot start with '-' (would be read as a command flag)"
        )
    if not _ALIAS_RE.match(normalized):
        raise ValueError(
            f"alias '{name}' may only contain letters, digits, '-', '_', and '.'"
        )
    return normalized


class Capability(StrEnum):
    """Operations an adapter may offer. Reported per install at runtime."""

    ACCOUNT_LIST = "account_list"
    ACCOUNT_ADD = "account_add"
    ACCOUNT_REMOVE = "account_remove"
    ACCOUNT_SWITCH = "account_switch"
    #: Switching is done by the harness's own account commands, not by hswap
    #: rewriting credential files.
    NATIVE_ACCOUNT_SWITCH = "native_account_switch"
    #: hswap itself refreshes stored tokens (rather than leaving it to the harness).
    CREDENTIAL_REFRESH = "credential_refresh"
    USAGE_MONITORING = "usage_monitoring"
    AUTOMATIC_ROTATION = "automatic_rotation"
    PARALLEL_SESSIONS = "parallel_sessions"
    SESSION_RESUME = "session_resume"
    #: Running harness processes pick up a switched credential without a restart.
    CREDENTIAL_HOT_RELOAD = "credential_hot_reload"


class Support(StrEnum):
    SUPPORTED = "supported"
    #: Works, but rests on behaviour the harness does not document as stable.
    EXPERIMENTAL = "experimental"
    #: The adapter could do it, but this install lacks a prerequisite
    #: (binary missing, keyring credential store, old version, ...).
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class CapabilityStatus:
    support: Support
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.support in (Support.SUPPORTED, Support.EXPERIMENTAL)


def supported(reason: str = "") -> CapabilityStatus:
    return CapabilityStatus(Support.SUPPORTED, reason)


def experimental(reason: str) -> CapabilityStatus:
    return CapabilityStatus(Support.EXPERIMENTAL, reason)


def unavailable(reason: str) -> CapabilityStatus:
    return CapabilityStatus(Support.UNAVAILABLE, reason)


def unsupported(reason: str) -> CapabilityStatus:
    return CapabilityStatus(Support.UNSUPPORTED, reason)


@dataclass(frozen=True)
class Installation:
    """What was found on this machine for one harness."""

    installed: bool
    executable: str | None = None
    version: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class Account:
    """One account as hswap sees it. Never carries secret material.

    ``identity`` is stable and unique within (harness, provider): an OAuth
    subject/account id, a credential id, or a fingerprint of an API key --
    never the email alone, which is not unique (one email can own a personal
    and a team workspace). ``label`` is what humans recognise (usually the
    email). ``slot`` is hswap's per-harness number; ``None`` when the
    harness manages the account and hswap has not numbered it.
    """

    harness: str
    identity: str
    label: str
    provider: str | None = None
    slot: int | None = None
    alias: str | None = None
    auth_mode: str | None = None
    #: True/False when known, None when the harness does not reveal it.
    active: bool | None = None
    details: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def key(self) -> str:
        """Namespaced id, unique across every harness and provider."""
        return f"{self.harness}:{self.provider or '-'}:{self.identity}"

    def to_json(self) -> dict:
        out = {
            "harness": self.harness,
            "provider": self.provider,
            "slot": self.slot,
            "identity": self.identity,
            "label": self.label,
            "alias": self.alias,
            "authMode": self.auth_mode,
            "active": self.active,
        }
        if self.details:
            out["details"] = dict(self.details)
        return out


class UsageState(StrEnum):
    AVAILABLE = "available"
    STALE = "stale"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    AUTHENTICATION_REQUIRED = "authentication_required"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


@dataclass(frozen=True)
class QuotaWindow:
    """One limit the provider enforces, e.g. a 5-hour or weekly window.

    ``remaining`` is set only when the provider reports it; it is never
    derived from a guess about the limit's size.
    """

    name: str
    used_percent: float | None
    resets_at: float | None = None
    window_seconds: int | None = None
    remaining: float | None = None

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "usedPercent": self.used_percent,
            "resetsAt": _iso(self.resets_at),
            "windowSeconds": self.window_seconds,
            "remaining": self.remaining,
        }


@dataclass(frozen=True)
class UsageSnapshot:
    state: UsageState
    windows: tuple[QuotaWindow, ...] = ()
    measured_at: float | None = None
    source: str = ""
    detail: str = ""
    plan: str | None = None
    #: Credits or monetary balance, as the provider reports it.
    balance: dict | None = None

    @property
    def max_used_percent(self) -> float | None:
        values = [w.used_percent for w in self.windows if w.used_percent is not None]
        return max(values) if values else None

    def age_s(self, now: float | None = None) -> float | None:
        if self.measured_at is None:
            return None
        return max(0.0, (time.time() if now is None else now) - self.measured_at)

    def to_json(self) -> dict:
        return {
            "state": str(self.state),
            "windows": [w.to_json() for w in self.windows],
            "measuredAt": _iso(self.measured_at),
            "source": self.source,
            "detail": self.detail,
            "plan": self.plan,
            "balance": self.balance,
        }


def unsupported_usage(reason: str) -> UsageSnapshot:
    return UsageSnapshot(UsageState.UNSUPPORTED, detail=reason)


@dataclass(frozen=True)
class SwitchResult:
    harness: str
    current: Account
    previous: Account | None = None
    #: Running harness processes keep the old account until restarted.
    restart_required: bool = False
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "harness": self.harness,
            "from": self.previous.to_json() if self.previous else None,
            "to": self.current.to_json(),
            "restartRequired": self.restart_required,
            "notes": list(self.notes),
        }


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    from datetime import datetime

    return (
        datetime.fromtimestamp(ts, tz=UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
