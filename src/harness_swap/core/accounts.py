"""Harness-agnostic account operations used by every front end (CLI, TUI).

Each function takes an adapter and goes through :func:`require`, so the same
code path serves every harness and every unsupported case explains itself.
"""

from __future__ import annotations

import dataclasses

from harness_swap.core.adapter import (
    AccountAdder,
    AccountRemover,
    AccountSwitcher,
    AliasStore,
    CachedUsageView,
    HarnessAdapter,
    SessionLauncher,
    UsageReader,
    require,
)
from harness_swap.core.errors import (
    AccountNotFound,
    HswapError,
    NoSwitchTarget,
    UnsupportedOperation,
)
from harness_swap.core.models import (
    Account,
    Capability,
    SwitchResult,
    UsageSnapshot,
    UsageState,
    unsupported_usage,
)
from harness_swap.core.rotation import select_account
from harness_swap.core.usage import UsageService


def _choice(acc: Account) -> str:
    slot = acc.slot if acc.slot is not None else acc.identity
    alias = f" ({acc.alias})" if acc.alias else ""
    provider = f" [{acc.provider}]" if acc.provider else ""
    return f"{slot}: {acc.label}{alias}{provider}"


def resolve(
    accounts: list[Account], identifier: str, provider: str | None = None
) -> Account:
    """Find one account by slot number, alias, identity or label (email)."""
    pool = [a for a in accounts if provider is None or a.provider == provider]
    ident = identifier.strip()
    if ident.isdigit():
        matches = [a for a in pool if a.slot == int(ident)]
    else:
        lowered = ident.lower()
        matches = (
            [a for a in pool if a.alias == lowered]
            or [a for a in pool if a.identity == ident]
            or [a for a in pool if a.label.lower() == lowered]
        )
    if not matches:
        scope = f" for provider {provider}" if provider else ""
        known = ", ".join(_choice(a) for a in pool) or "none"
        raise AccountNotFound(f"no account matches {identifier!r}{scope}; known: {known}")
    if len(matches) > 1:
        options = ", ".join(_choice(a) for a in matches)
        hint = " or --provider" if len({a.provider for a in matches}) > 1 else ""
        raise HswapError(f"{identifier!r} is ambiguous: {options}. Use the slot number{hint}")
    return matches[0]


def active_accounts(adapter: HarnessAdapter) -> list[Account]:
    return [a for a in adapter.list_accounts() if a.active]


def add(adapter: HarnessAdapter, **kwargs) -> Account:
    return require(adapter, Capability.ACCOUNT_ADD, AccountAdder).add_account(**kwargs)


def remove(adapter: HarnessAdapter, identifier: str, provider: str | None = None) -> Account:
    remover = require(adapter, Capability.ACCOUNT_REMOVE, AccountRemover)
    account = resolve(adapter.list_accounts(), identifier, provider)
    remover.remove_account(account)
    return account


def set_alias(
    adapter: HarnessAdapter, identifier: str, alias: str | None, provider: str | None = None
) -> Account:
    if not isinstance(adapter, AliasStore):
        raise UnsupportedOperation("alias", f"the {adapter.id} adapter does not store aliases")
    return adapter.set_alias(resolve(adapter.list_accounts(), identifier, provider), alias)


def switch(
    adapter: HarnessAdapter,
    identifier: str,
    *,
    provider: str | None = None,
    force: bool = False,
) -> SwitchResult:
    switcher = require(adapter, Capability.ACCOUNT_SWITCH, AccountSwitcher)
    account = resolve(adapter.list_accounts(), identifier, provider)
    return switcher.switch_account(account, force=force)


def collect_usage(
    adapter: HarnessAdapter, accounts: list[Account], service: UsageService, *, cached: bool = False
) -> dict[str, UsageSnapshot]:
    """Usage for each account; an ``unsupported`` snapshot when the harness
    offers none, so callers never have to special-case it. ``cached`` reads
    only what earlier runs measured: no network, no token refresh."""
    status = adapter.capabilities().get(Capability.USAGE_MONITORING)
    if status is None or not status.usable or not isinstance(adapter, UsageReader):
        reason = status.reason if status else f"{adapter.display_name} reports no usage"
        return {a.key: unsupported_usage(reason) for a in accounts}
    read = service.peek if cached else service.get
    return {a.key: read(adapter, a) for a in accounts}


def cached_view(adapter: HarnessAdapter, service: UsageService) -> tuple[list[Account], dict[str, UsageSnapshot]]:
    """Accounts and their last measured usage: no network call, no token refresh."""
    if isinstance(adapter, CachedUsageView):
        return adapter.cached_view()
    accounts = adapter.list_accounts()
    return accounts, collect_usage(adapter, accounts, service, cached=True)


def switch_by_strategy(
    adapter: HarnessAdapter,
    strategy: str,
    service: UsageService,
    *,
    threshold: float,
    provider: str | None = None,
    force: bool = False,
) -> SwitchResult:
    """Manual, user-initiated switch to the account the policy picks."""
    switcher = require(adapter, Capability.ACCOUNT_SWITCH, AccountSwitcher)
    require(adapter, Capability.USAGE_MONITORING, UsageReader)
    accounts = adapter.list_accounts()
    current = next((a for a in accounts if a.active and (provider is None or a.provider == provider)), None)
    usage = collect_usage(adapter, accounts, service)
    target = select_account(
        accounts, usage, current=current, strategy=strategy, threshold=threshold, provider=provider
    )
    if target is None:
        raise NoSwitchTarget(
            f"no other {adapter.display_name} account qualifies for '{strategy}' "
            f"(threshold {threshold:g}%); usage may be unknown or stale -- see `hswap {adapter.id} usage`"
        )
    result = switcher.switch_account(target, force=force)
    if usage.get(target.key) is None or usage[target.key].state is not UsageState.AVAILABLE:
        note = f"no current usage data for {target.label}; '{strategy}' picked it without knowing its headroom"
        result = dataclasses.replace(result, notes=(*result.notes, note))
    return result


def launch(adapter: HarnessAdapter, identifier: str, args: list[str], provider: str | None = None) -> int:
    launcher = require(adapter, Capability.PARALLEL_SESSIONS, SessionLauncher)
    account = resolve(adapter.list_accounts(), identifier, provider)
    return launcher.launch(account, args)
