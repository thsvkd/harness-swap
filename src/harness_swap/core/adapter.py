"""Adapter contracts.

A harness adapter implements the small required :class:`HarnessAdapter`
protocol and, separately, whichever optional role protocols it can honour.
The core never asks "which harness is this?"; it asks "does this adapter
play that role, and does :meth:`HarnessAdapter.capabilities` say the role is
usable on this install?" -- see :func:`require`.

Roles are deliberately narrow (interface segregation): an adapter that can
list and switch accounts but has no usage data simply does not implement
:class:`UsageReader`, and reports ``usage_monitoring`` as unsupported with a
reason the user can read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeVar, runtime_checkable

from harness_swap.core.errors import UnsupportedOperation
from harness_swap.core.models import (
    Account,
    Capability,
    CapabilityStatus,
    Installation,
    SwitchResult,
    UsageSnapshot,
    unsupported,
)


@runtime_checkable
class HarnessAdapter(Protocol):
    """Required by every adapter: identity, discovery, capabilities, listing."""

    #: Stable lowercase id used on the command line (``hswap <id> ...``).
    id: str
    display_name: str
    #: Providers this harness can talk to; empty when it is provider-agnostic.
    providers: tuple[str, ...]

    def installation(self) -> Installation:
        """Detect the harness on this machine. Must not raise for a missing binary."""
        ...

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        """What works on *this* install, each with a reason when it does not.

        Capabilities missing from the mapping count as unsupported.
        """
        ...

    def list_accounts(self) -> list[Account]:
        """Accounts hswap knows for this harness, with ``active`` filled in when knowable."""
        ...


@runtime_checkable
class AccountAdder(Protocol):
    def add_account(
        self, *, alias: str | None = None, provider: str | None = None, login: bool = False,
        email: str | None = None,
    ) -> Account:
        """Register an account. ``login`` runs the harness's own sign-in first,
        isolated so the current login is never replaced or revoked. ``email``
        (with ``login``) refuses the sign-in unless it ended on that account."""
        ...


@runtime_checkable
class AccountRemover(Protocol):
    def remove_account(self, account: Account) -> None:
        ...


@runtime_checkable
class AccountSwitcher(Protocol):
    def switch_account(self, account: Account, *, force: bool = False) -> SwitchResult:
        """Make ``account`` the harness's default login for new processes.

        Must leave the previous login intact (and recoverable) on failure.
        """
        ...


@runtime_checkable
class AliasStore(Protocol):
    def set_alias(self, account: Account, alias: str | None) -> Account:
        ...


@runtime_checkable
class UsageReader(Protocol):
    #: How often the shared usage service may call :meth:`read_usage` for one
    #: account, and how old a measurement may get before it counts as stale.
    usage_policy: UsagePolicy

    def read_usage(self, account: Account) -> UsageSnapshot:
        """One measurement. May raise; the usage service turns errors into
        an ``error`` snapshot and backs off."""
        ...


@runtime_checkable
class KeepAlive(Protocol):
    """Keeps a stored login usable (capability ``credential_refresh``).

    The harness itself is asked something that needs the login, in the
    account's own home, so it refreshes the token there when it is due --
    hswap never refreshes tokens itself. Returns what happened, in a few words.
    """

    def keep_alive(self, account: Account) -> str: ...


@runtime_checkable
class CachedUsageView(Protocol):
    """For a harness whose engine keeps its own usage cache: accounts and their
    last measured usage without any network call or token refresh. Others get
    the same from hswap's usage cache (``UsageService.peek``)."""

    def cached_view(self) -> tuple[list[Account], dict[str, UsageSnapshot]]: ...


@runtime_checkable
class SessionLauncher(Protocol):
    def launch(self, account: Account, args: list[str]) -> int:
        """Run the harness as ``account`` without touching the default login.

        May replace the current process (POSIX ``exec``) and never return.
        """
        ...


@runtime_checkable
class NativeCommandLine(Protocol):
    """An adapter whose harness-specific CLI is richer than the generic verbs.

    ``hswap <id> ...`` hands its arguments to :meth:`run_cli` unchanged.
    """

    def run_cli(self, argv: list[str]) -> int:
        ...


@runtime_checkable
class Migrator(Protocol):
    """An adapter with legacy data hswap must not convert implicitly."""

    def migration_plan(self) -> list[str]:
        """Human-readable steps that :meth:`apply_migration` would take; [] if none."""
        ...

    def apply_migration(self) -> list[str]:
        """Back up, then migrate. Idempotent; returns what was done."""
        ...


@runtime_checkable
class Diagnosable(Protocol):
    def diagnose(self) -> list[tuple[str, str]]:
        """``[(level, message)]`` with level ``info``/``warn``/``error``."""
        ...


@dataclass(frozen=True)
class UsagePolicy:
    #: Never ask the adapter for the same account more often than this.
    min_interval_s: float = 60.0
    #: A measurement older than this is reported as ``stale``.
    stale_after_s: float = 900.0
    #: Exponential backoff ceiling after failed reads.
    max_backoff_s: float = 1800.0


R = TypeVar("R")


def require(
    adapter: HarnessAdapter, capability: Capability, role: type[R]
) -> R:
    """Return ``adapter`` typed as ``role`` if the capability is usable here.

    Raises :class:`UnsupportedOperation` carrying the adapter's own reason
    otherwise, so the user learns *why* (wrong credential store, harness too
    old, not offered by the provider, ...).
    """
    status = adapter.capabilities().get(
        capability, unsupported(f"{adapter.display_name} does not offer this")
    )
    if not status.usable:
        raise UnsupportedOperation(str(capability), status.reason or "not available", str(status.support))
    if not isinstance(adapter, role):
        raise UnsupportedOperation(
            str(capability),
            f"the {adapter.id} adapter reports it but does not implement {role.__name__}",
        )
    return adapter  # type: ignore[return-value]
