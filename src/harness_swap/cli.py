"""``hswap``: one command line for every registered harness.

Top-level commands work across harnesses; ``hswap <harness> ...`` works on
one. Both are built from the registry and each adapter's capabilities, so a
new adapter shows up here with no change to this file. An adapter with a
richer native command line (:class:`NativeCommandLine`) receives
``hswap <harness> ...`` verbatim instead of the generic verbs.
"""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version

from harness_swap import output
from harness_swap.core import accounts as service
from harness_swap.core import settings
from harness_swap.core.adapter import (
    Diagnosable,
    HarnessAdapter,
    Migrator,
    NativeCommandLine,
)
from harness_swap.core.errors import HswapError
from harness_swap.core.models import Capability, Support
from harness_swap.core.paths import hswap_home
from harness_swap.core.registry import Registry, default_registry
from harness_swap.core.rotation import STRATEGIES
from harness_swap.core.store import AccountStore
from harness_swap.core.usage import UsageService

TOP_LEVEL = ("harnesses", "capabilities", "list", "ls", "status", "doctor", "migrate", "config", "tui", "help")


def _version() -> str:
    try:
        return version("harness-swap")
    except PackageNotFoundError:
        return "unknown"


def _usage_service() -> UsageService:
    return UsageService(hswap_home() / "cache")


def _shows_provider(adapter: HarnessAdapter) -> bool:
    return len(adapter.providers) != 1


# -- per-harness generic verbs ------------------------------------------------------


def _harness_parser(adapter: HarnessAdapter) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=f"hswap {adapter.id}", description=f"Manage {adapter.display_name} accounts.")
    sub = p.add_subparsers(dest="verb", metavar="<command>", required=True)

    def cmd(name, help_, *aliases):
        return sub.add_parser(name, help=help_, aliases=list(aliases))

    def provider(sp):
        sp.add_argument("--provider", help="limit to one provider (multi-provider harnesses)")

    sp = cmd("list", "list accounts with usage", "ls")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--no-usage", action="store_true", help="skip usage collection")
    sp = cmd("status", "show the active account")
    sp.add_argument("--json", action="store_true")
    sp = cmd("add", "add the current login (or sign in a new one with --login)")
    sp.add_argument("--alias")
    sp.add_argument("--login", action="store_true", help="run the harness's own sign-in without touching the current login")
    provider(sp)
    sp = cmd("remove", "forget a stored account", "rm")
    sp.add_argument("account", metavar="SLOT|ALIAS|EMAIL")
    sp.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    provider(sp)
    sp = cmd("switch", "make an account the default login")
    sp.add_argument("account", nargs="?", metavar="SLOT|ALIAS|EMAIL")
    sp.add_argument("--strategy", choices=STRATEGIES, help="pick the target from usage (manual, one-off)")
    sp.add_argument("--force", action="store_true", help="stash an unmanaged current login and switch anyway")
    sp.add_argument("--json", action="store_true")
    provider(sp)
    sp = cmd("run", "run the harness as an account in this terminal only (args after --)")
    sp.add_argument("account", metavar="SLOT|ALIAS|EMAIL")
    provider(sp)
    sp = cmd("usage", "show usage for one or all accounts")
    sp.add_argument("account", nargs="?", metavar="SLOT|ALIAS|EMAIL")
    sp.add_argument("--json", action="store_true")
    provider(sp)
    sp = cmd("alias", "set or clear an account alias")
    sp.add_argument("account", metavar="SLOT|ALIAS|EMAIL")
    sp.add_argument("name", nargs="?")
    sp.add_argument("--unset", action="store_true")
    provider(sp)
    sp = cmd("capabilities", "what this harness supports here")
    sp.add_argument("--json", action="store_true")
    return p


def _print_accounts(adapter: HarnessAdapter, accounts, usage=None) -> None:
    if not accounts:
        print(f"   (no accounts; `hswap {adapter.id} add`)")
    if usage and all(str(s.state) == "unsupported" for s in usage.values()):
        details = {s.detail for s in usage.values()}
        if len(details) == 1:
            print(f"   usage: unsupported ({details.pop()})")
            usage = None
    for acc in accounts:
        line = output.account_line(acc, _shows_provider(adapter))
        text = output.usage_text(usage.get(acc.key)) if usage else ""
        print(line + (f"\n        {text}" if text else ""))


def _confirm(question: str) -> bool:
    if not sys.stdin.isatty():
        raise HswapError("refusing to ask for confirmation without a terminal; pass --yes")
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def harness_command(adapter: HarnessAdapter, argv: list[str]) -> int:
    if isinstance(adapter, NativeCommandLine):
        return adapter.run_cli(argv)
    passthrough: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, passthrough = argv[:i], argv[i + 1 :]
    args = _harness_parser(adapter).parse_args(argv)
    verb = {"ls": "list", "rm": "remove"}.get(args.verb, args.verb)
    as_json = getattr(args, "json", False)

    if verb == "list":
        accounts = adapter.list_accounts()
        usage = None if args.no_usage else service.collect_usage(adapter, accounts, _usage_service())
        if as_json:
            output.emit_json(_harness_json(adapter, accounts, usage))
        else:
            print(f"{adapter.display_name}:")
            _print_accounts(adapter, accounts, usage)
    elif verb == "status":
        active = service.active_accounts(adapter)
        if as_json:
            output.emit_json({"harness": adapter.id, "active": [a.to_json() for a in active]})
        elif not active:
            print(f"{adapter.display_name}: no managed account is active")
        else:
            for acc in active:
                print(f"{adapter.display_name}:{output.account_line(acc, _shows_provider(adapter))}")
    elif verb == "add":
        acc = service.add(adapter, alias=args.alias, provider=args.provider, login=args.login)
        print(f"Added {acc.label} as {adapter.id} slot {acc.slot}")
    elif verb == "remove":
        acc = service.resolve(adapter.list_accounts(), args.account, args.provider)
        if not args.yes and not _confirm(f"Remove {acc.label} (slot {acc.slot}) from hswap?"):
            print("Cancelled.")
            return 1
        service.remove(adapter, str(acc.slot) if acc.slot is not None else acc.identity, args.provider)
        print(f"Removed {acc.label}")
    elif verb == "switch":
        if args.strategy and args.account:
            raise HswapError("give an account or --strategy, not both")
        if args.strategy:
            result = service.switch_by_strategy(
                adapter,
                args.strategy,
                _usage_service(),
                threshold=settings.load()["rotation.threshold"],
                provider=args.provider,
                force=args.force,
            )
        elif args.account:
            result = service.switch(adapter, args.account, provider=args.provider, force=args.force)
        else:
            raise HswapError("which account? give SLOT|ALIAS|EMAIL or --strategy")
        if as_json:
            output.emit_json(result.to_json())
        else:
            print(f"{adapter.display_name}: now using {result.current.label} (slot {result.current.slot})")
            for note in result.notes:
                print(f"  - {note}")
    elif verb == "run":
        return service.launch(adapter, args.account, passthrough, args.provider)
    elif verb == "usage":
        accounts = adapter.list_accounts()
        if args.account:
            accounts = [service.resolve(accounts, args.account, args.provider)]
        usage = service.collect_usage(adapter, accounts, _usage_service())
        if as_json:
            output.emit_json(_harness_json(adapter, accounts, usage))
        else:
            _print_accounts(adapter, accounts, usage)
    elif verb == "alias":
        if args.unset == bool(args.name):
            raise HswapError("give a NAME or --unset")
        acc = service.set_alias(adapter, args.account, None if args.unset else args.name, args.provider)
        print(f"slot {acc.slot}: alias {acc.alias or '(none)'}")
    elif verb == "capabilities":
        _print_capabilities([adapter], as_json)
    return 0


def _harness_json(adapter, accounts, usage) -> dict:
    rows = []
    for acc in accounts:
        row = acc.to_json()
        if usage is not None:
            row["usage"] = usage[acc.key].to_json()
        rows.append(row)
    return {"harness": adapter.id, "accounts": rows}


# -- top-level commands -------------------------------------------------------------------


def _targets(registry: Registry, harness: str | None) -> list[HarnessAdapter]:
    return [registry.get(harness)] if harness else registry.available()


def _print_capabilities(adapters, as_json: bool) -> None:
    if as_json:
        output.emit_json(
            {
                "harnesses": {
                    a.id: {
                        str(c): {"support": str(s.support), "reason": s.reason}
                        for c, s in a.capabilities().items()
                    }
                    for a in adapters
                }
            }
        )
        return
    for a in adapters:
        print(f"{a.display_name} ({a.id})")
        caps = a.capabilities()
        for cap in Capability:
            status = caps.get(cap)
            support = str(status.support) if status else "unsupported"
            reason = f"  {status.reason}" if status and status.reason else ""
            print(f"  {cap!s:<22} {support:<12}{reason}")


def cmd_harnesses(registry: Registry, as_json: bool) -> int:
    rows = []
    for entry in registry.entries():
        row = {"id": entry.id, "origin": entry.origin, "trusted": entry.trusted}
        if entry.trusted:
            try:
                adapter = registry.get(entry.id)
                inst = adapter.installation()
                row |= {"name": adapter.display_name, "installed": inst.installed, "version": inst.version}
            except HswapError as exc:
                row["error"] = str(exc)
        rows.append(row)
    if as_json:
        output.emit_json({"harnesses": rows})
        return 0
    for r in rows:
        if not r["trusted"]:
            state = f"untrusted plugin ({r['origin']}); `{registry.trust_command(r['id'])}`"
        elif "error" in r:
            state = f"error: {r['error']}"
        else:
            state = (r["version"] or "installed") if r["installed"] else "not installed"
        print(f"{r['id']:<10} {r.get('name', ''):<14} {state}")
    return 0


def cmd_list(registry: Registry, harness: str | None, as_json: bool, with_usage: bool) -> int:
    results, errors = [], {}
    for adapter in _targets(registry, harness):
        try:
            accounts = adapter.list_accounts()
            usage = service.collect_usage(adapter, accounts, _usage_service()) if with_usage else None
            results.append((adapter, accounts, usage))
        except HswapError as exc:
            errors[adapter.id] = str(exc)
    if as_json:
        output.emit_json(
            {
                "harnesses": [_harness_json(a, accts, u) for a, accts, u in results],
                "errors": errors,
            }
        )
        return 0 if results or not errors else 1
    for adapter, accounts, usage in results:
        print(f"{adapter.display_name} ({adapter.id}):")
        _print_accounts(adapter, accounts, usage)
    for harness_id, message in errors.items():
        output.err(f"{harness_id}: {message}")
    return 0 if results or not errors else 1


def cmd_status(registry: Registry, harness: str | None, as_json: bool) -> int:
    rows = []
    for adapter in _targets(registry, harness):
        inst = adapter.installation()
        row = {"harness": adapter.id, "installed": inst.installed, "version": inst.version}
        try:
            row["active"] = [a.to_json() for a in service.active_accounts(adapter)]
        except HswapError as exc:
            row["error"] = str(exc)
        rows.append(row)
    if as_json:
        output.emit_json({"harnesses": rows})
        return 0
    for row in rows:
        if "error" in row:
            text = f"error: {row['error']}"
        elif row["active"]:
            text = ", ".join(a["label"] + (f" [{a['provider']}]" if a["provider"] else "") for a in row["active"])
        else:
            text = "no managed account active" if row["installed"] else "not installed"
        print(f"{row['harness']:<10} {text}")
    return 0


def cmd_doctor(registry: Registry, as_json: bool) -> int:
    findings: list[tuple[str, str, str]] = []
    home = hswap_home()
    findings.append(("hswap", "info", f"data directory {home}"))
    for entry in registry.entries():
        if entry.error:
            findings.append((entry.id, "error", entry.error))
    for adapter in registry.available():
        inst = adapter.installation()
        if inst.installed and inst.version:
            findings.append((adapter.id, "info", f"{inst.executable} {inst.version}"))
        else:
            findings.append((adapter.id, "warn", inst.detail or f"{inst.executable}: version unknown"))
        try:
            for cap, status in adapter.capabilities().items():
                if status.support is Support.UNAVAILABLE:
                    findings.append((adapter.id, "warn", f"{cap}: {status.reason}"))
            if isinstance(adapter, Diagnosable):
                findings += [(adapter.id, level, msg) for level, msg in adapter.diagnose()]
        except HswapError as exc:
            findings.append((adapter.id, "error", str(exc)))
        try:
            AccountStore(home / adapter.id).load()
        except HswapError as exc:
            findings.append((adapter.id, "error", str(exc)))
    if as_json:
        output.emit_json({"findings": [{"harness": h, "level": lv, "message": m} for h, lv, m in findings]})
    else:
        for harness_id, level, message in findings:
            print(f"[{level:<5}] {harness_id:<9} {message}")
    return 1 if any(level == "error" for _, level, _ in findings) else 0


def cmd_migrate(registry: Registry, dry_run: bool) -> int:
    did_anything = False
    for adapter in registry.available():
        if not isinstance(adapter, Migrator):
            continue
        plan = adapter.migration_plan()
        if not plan:
            continue
        did_anything = True
        print(f"{adapter.display_name}:")
        for step in plan if dry_run else adapter.apply_migration():
            print(f"  {'would ' if dry_run else ''}{step}")
    if not did_anything:
        print("Nothing to migrate.")
    return 0


def cmd_config(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="hswap config")
    p.add_argument("action", nargs="?", default="list", choices=("list", "get", "set", "unset", "path"))
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    args = p.parse_args(argv)
    if args.action == "path":
        print(settings.settings_path())
    elif args.action == "list":
        for key, value in settings.load().items():
            print(f"{key} = {value}")
    elif args.action == "get":
        values = settings.load()
        if args.key not in values:
            raise HswapError(f"unknown setting {args.key!r}; known: {', '.join(values)}")
        print(values[args.key])
    elif args.action == "set":
        if args.key is None or args.value is None:
            raise HswapError("usage: hswap config set KEY VALUE")
        try:
            print(f"{args.key} = {settings.set_value(args.key, args.value)}")
        except (KeyError, ValueError) as exc:
            raise HswapError(str(exc).strip("'\"")) from None
    elif args.action == "unset":
        try:
            settings.unset(args.key)
        except KeyError as exc:
            raise HswapError(str(exc).strip("'\"")) from None
    return 0


HELP = """usage: hswap <command> [options]
       hswap <harness> <command> [options]

Switch between multiple accounts across AI coding harnesses.

Across harnesses:
  hswap harnesses              installed harnesses and adapters
  hswap list [HARNESS]         accounts and usage (--json, --no-usage)
  hswap status [HARNESS]       active account per harness (--json)
  hswap capabilities [HARNESS] what each harness supports on this machine
  hswap doctor                 check installs, stores and permissions
  hswap migrate [--dry-run]    review/apply legacy data migration
  hswap config [list|get|set|unset|path]
  hswap tui                    dashboard (also: bare hswap in a terminal)

Per harness ({harnesses}):
  hswap <harness> list | status | add [--login] | remove | switch | run | usage | alias | capabilities
  Harnesses with a richer command set of their own take it here instead
  (see `hswap <harness> help`).
"""


def run(argv: list[str], registry: Registry | None = None) -> int:
    registry = registry or default_registry()
    if not argv:
        if sys.stdin.isatty() and sys.stdout.isatty():
            argv = ["tui"]
        else:
            print(HELP.format(harnesses=", ".join(registry.ids())))
            return 0
    head, rest = argv[0], argv[1:]
    if head in ("--version", "-V", "version"):
        print(f"hswap {_version()}")
        return 0
    if head in ("help", "-h", "--help"):
        print(HELP.format(harnesses=", ".join(registry.ids())))
        return 0
    as_json = "--json" in rest
    try:
        if head not in TOP_LEVEL:
            return harness_command(registry.get(head), rest)
        p = argparse.ArgumentParser(prog=f"hswap {head}")
        if head in ("list", "ls", "status", "capabilities"):
            p.add_argument("harness", nargs="?")
        if head in ("list", "ls"):
            p.add_argument("--no-usage", action="store_true")
        if head == "migrate":
            p.add_argument("--dry-run", action="store_true")
        if head == "config":
            return cmd_config(rest)
        if head != "migrate" and head != "tui":
            p.add_argument("--json", action="store_true")
        args = p.parse_args(rest)
        if head == "harnesses":
            return cmd_harnesses(registry, args.json)
        if head in ("list", "ls"):
            return cmd_list(registry, args.harness, args.json, not args.no_usage)
        if head == "status":
            return cmd_status(registry, args.harness, args.json)
        if head == "capabilities":
            _print_capabilities(_targets(registry, args.harness), args.json)
            return 0
        if head == "doctor":
            return cmd_doctor(registry, args.json)
        if head == "migrate":
            return cmd_migrate(registry, args.dry_run)
        if head == "tui":
            from harness_swap.ui.tui import run as run_tui

            return run_tui(registry)
    except (HswapError, output.SecretLeak) as exc:
        if as_json and not isinstance(exc, output.SecretLeak):
            output.emit_json(output.error_json(exc))
        else:
            output.err(f"Error: {exc}")
        return 1
    except KeyboardInterrupt:
        output.err("\nCancelled.")
        return 130
    return 0


def main() -> None:
    sys.exit(run(sys.argv[1:]))
