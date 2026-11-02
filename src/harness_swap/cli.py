"""``hswap``: one command line for every registered harness.

Top-level commands work across harnesses; ``hswap <harness> ...`` works on
one. Both are built from the registry and each adapter's capabilities, so a
new adapter shows up here with no change to this file. An adapter with a
richer native command line (:class:`NativeCommandLine`) receives
``hswap <harness> ...`` verbatim instead of the generic verbs.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version

from harness_swap import output
from harness_swap.core import accounts as service
from harness_swap.core import autorotate, settings
from harness_swap.core.adapter import (
    Diagnosable,
    HarnessAdapter,
    KeepAlive,
    Migrator,
    NativeCommandLine,
    require,
)
from harness_swap.core.errors import CredentialConflict, HswapError
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


def _describe(exc: BaseException) -> str:
    """An error line for one harness; a plugin's own exception keeps its type name."""
    return str(exc) if isinstance(exc, HswapError) else f"{type(exc).__name__}: {exc}"


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
    sp.add_argument("--cached", action="store_true", help="last measured usage only: no network, no token refresh")
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
    sp.usage = f"hswap {adapter.id} run SLOT|ALIAS|EMAIL [--provider P] [-- HARNESS ARGS...]"
    sp.add_argument("account", metavar="SLOT|ALIAS|EMAIL")
    provider(sp)
    sp = cmd("usage", "show usage for one or all accounts")
    sp.add_argument("account", nargs="?", metavar="SLOT|ALIAS|EMAIL")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--cached", action="store_true", help="last measured usage only: no network, no token refresh")
    provider(sp)
    sp = cmd("refresh", "keep stored logins alive: let the harness refresh tokens that are due (for cron)")
    sp.add_argument("account", nargs="?", metavar="SLOT|ALIAS|EMAIL")
    sp.add_argument("--json", action="store_true")
    provider(sp)
    sp = cmd("auto", "switch automatically when the active account nears its limit (opt-in: auto.enabled)")
    sp.add_argument("--once", action="store_true", help="one decision, then exit (for cron)")
    sp.add_argument("--interval", type=float, default=300.0, help="seconds between checks (default 300)")
    sp.add_argument("--dry-run", action="store_true", help="say what would happen, switch nothing")
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
    parser = _harness_parser(adapter)
    args, extra = parser.parse_known_args(argv)
    verb = {"ls": "list", "rm": "remove"}.get(args.verb, args.verb)
    if extra and verb == "run":
        parser.error(f"harness arguments go after `--`: hswap {adapter.id} run {args.account} -- {' '.join(extra)}")
    if extra:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")
    as_json = getattr(args, "json", False)
    if getattr(args, "provider", None) and adapter.providers and args.provider not in adapter.providers:
        raise HswapError(f"{adapter.id} has no provider {args.provider!r}; known: {', '.join(adapter.providers)}")

    if verb == "list":
        if args.cached:
            accounts, usage = service.cached_view(adapter, _usage_service())
        else:
            accounts = adapter.list_accounts()
            usage = None if args.no_usage else service.collect_usage(adapter, accounts, _usage_service())
        if as_json:
            output.emit_json(_harness_json(adapter, accounts, usage))
        else:
            print(f"{adapter.display_name}:")
            _print_accounts(adapter, accounts, usage)
    elif verb == "status":
        accounts = adapter.list_accounts()
        active = [a for a in accounts if a.active]
        known = bool(active) or all(a.active is not None for a in accounts)
        if as_json:
            output.emit_json({"harness": adapter.id, "active": [a.to_json() for a in active], "activeKnown": known})
        elif not known:
            print(f"{adapter.display_name}: the active account could not be determined (see `hswap {adapter.id} list`)")
        elif not active:
            print(f"{adapter.display_name}: no managed account is active")
        else:
            for acc in active:
                print(f"{adapter.display_name}:{output.account_line(acc, _shows_provider(adapter))}")
    elif verb == "add":
        known = {a.key for a in adapter.list_accounts()}
        acc = service.add(adapter, alias=args.alias, provider=args.provider, login=args.login)
        added = [a for a in adapter.list_accounts() if a.key not in known] or [acc]
        for new in added:
            if new.key in known:
                alias = f", alias {new.alias}" if args.alias else ""
                print(f"{new.label} is already {adapter.id} slot {new.slot}; its stored login was refreshed{alias}")
            else:
                print(f"Added {new.label} as {adapter.id} slot {new.slot}")
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
            try:
                result = service.switch(adapter, args.account, provider=args.provider, force=args.force)
            except CredentialConflict as exc:
                raise CredentialConflict(f"{exc}. To keep it as an account: `hswap {adapter.id} add`") from None
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
        if args.cached:
            accounts, usage = service.cached_view(adapter, _usage_service())
        else:
            accounts, usage = adapter.list_accounts(), None
        if args.account:
            accounts = [service.resolve(accounts, args.account, args.provider)]
        usage = usage or service.collect_usage(adapter, accounts, _usage_service())
        if as_json:
            output.emit_json(_harness_json(adapter, accounts, usage))
        else:
            _print_accounts(adapter, accounts, usage)
    elif verb == "alias":
        if args.unset == bool(args.name):
            raise HswapError("give a NAME or --unset")
        acc = service.set_alias(adapter, args.account, None if args.unset else args.name, args.provider)
        print(f"slot {acc.slot}: alias {acc.alias or '(none)'}")
    elif verb == "auto":
        return _auto(adapter, args)
    elif verb == "refresh":
        return _refresh(adapter, args)
    elif verb == "capabilities":
        return _print_capabilities([adapter], as_json)
    return 0


def _auto(adapter: HarnessAdapter, args) -> int:
    values = settings.load()
    while True:
        events = autorotate.run_once(
            adapter,
            _usage_service(),
            threshold=values["rotation.threshold"],
            cooldown_s=values["auto.cooldown"],
            provider=args.provider,
            dry_run=args.dry_run,
        )
        if args.json:
            output.emit_json({"harness": adapter.id, "at": time.time(), "events": events})
        else:
            for e in events:
                target = f" -> {e['target']['label']}" if "target" in e else ""
                print(f"{time.strftime('%H:%M:%S')} {adapter.display_name}: {e['action']}{target} ({e['reason']})")
        sys.stdout.flush()
        if args.once:
            return 0
        time.sleep(max(args.interval, 30.0))


def _refresh(adapter: HarnessAdapter, args) -> int:
    keeper = require(adapter, Capability.CREDENTIAL_REFRESH, KeepAlive)
    accounts = [a for a in adapter.list_accounts() if args.provider in (None, a.provider)]
    if args.account:
        accounts = [service.resolve(accounts, args.account, args.provider)]
    rows, failed = [], False
    for acc in accounts:
        try:
            rows.append({"account": acc.to_json(), "ok": True, "result": keeper.keep_alive(acc)})
        except Exception as exc:  # noqa: BLE001 - one account must not stop the others
            failed = True
            rows.append({"account": acc.to_json(), "ok": False, "result": _describe(exc)})
    if args.json:
        output.emit_json({"harness": adapter.id, "accounts": rows})
    else:
        for row in rows:
            a = row["account"]
            print(f"{adapter.display_name} {a['slot']} {a['label']}: {row['result']}")
    return 1 if failed else 0


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


def _print_capabilities(adapters, as_json: bool, load_errors: dict[str, str] | None = None) -> int:
    table, errors = {}, dict(load_errors or {})
    for a in adapters:
        try:
            table[a.id] = a.capabilities()
        except Exception as exc:  # noqa: BLE001 - one harness must not hide the others
            errors[a.id] = _describe(exc)
    if as_json:
        output.emit_json(
            {
                "harnesses": {
                    harness_id: {
                        str(c): {"support": str(caps[c].support), "reason": caps[c].reason}
                        if c in caps
                        else {"support": "unsupported", "reason": ""}
                        for c in Capability
                    }
                    for harness_id, caps in table.items()
                },
                "errors": errors,
            }
        )
        return 1 if errors else 0
    for a in adapters:
        print(f"{a.display_name} ({a.id})")
        if a.id in errors:
            print(f"  error: {errors[a.id]}")
            continue
        caps = table[a.id]
        for cap in Capability:
            status = caps.get(cap)
            support = str(status.support) if status else "unsupported"
            reason = f"  {status.reason}" if status and status.reason else ""
            print(f"  {cap!s:<22} {support:<12}{reason}")
    for harness_id in errors.keys() - {a.id for a in adapters}:
        print(f"{harness_id}\n  error: {errors[harness_id]}")
    return 1 if errors else 0


def cmd_harnesses(registry: Registry, as_json: bool) -> int:
    rows = []
    for entry in registry.entries():
        row = {"id": entry.id, "origin": entry.origin, "trusted": entry.trusted}
        if entry.error and not entry.trusted:
            row["error"] = entry.error
        elif entry.trusted:
            try:
                adapter = registry.get(entry.id)
                inst = adapter.installation()
                row |= {"name": adapter.display_name, "installed": inst.installed, "version": inst.version}
            except Exception as exc:  # noqa: BLE001 - one harness must not hide the others
                row["error"] = _describe(exc)
        rows.append(row)
    notices = [{"subject": s, "message": m} for s, m in registry.notices()]
    failed = any("error" in r and r["trusted"] for r in rows)
    if as_json:
        output.emit_json({"harnesses": rows, "notices": notices})
        return 1 if failed else 0
    for r in rows:
        if "error" in r:
            state = f"error: {r['error']}"
        elif not r["trusted"]:
            state = f"untrusted plugin ({r['origin']}); `{registry.trust_command(r['id'])}`"
        else:
            state = (r["version"] or "installed") if r["installed"] else "not installed"
            if r["origin"] != "builtin":
                state += f" ({r['origin']})"
        print(f"{r['id']:<10} {r.get('name', ''):<14} {state}")
    for n in notices:
        output.err(f"note: {n['subject']}: {n['message']}")
    return 1 if failed else 0


def cmd_list(registry: Registry, harness: str | None, as_json: bool, with_usage: bool, cached: bool = False) -> int:
    results, errors = [], {}
    for adapter in _targets(registry, harness):
        try:
            if cached:
                accounts, usage = service.cached_view(adapter, _usage_service())
            else:
                accounts = adapter.list_accounts()
                usage = service.collect_usage(adapter, accounts, _usage_service()) if with_usage else None
            results.append((adapter, accounts, usage))
        except Exception as exc:  # noqa: BLE001 - one harness must not hide the others
            errors[adapter.id] = _describe(exc)
    if harness is None:
        errors |= _load_errors(registry)
    if as_json:
        output.emit_json(
            {
                "harnesses": [_harness_json(a, accts, u) for a, accts, u in results],
                "errors": errors,
            }
        )
        return 1 if errors else 0
    for adapter, accounts, usage in results:
        print(f"{adapter.display_name} ({adapter.id}):")
        _print_accounts(adapter, accounts, usage)
    for harness_id, message in errors.items():
        output.err(f"{harness_id}: {message}")
    return 1 if errors else 0


def _load_errors(registry: Registry) -> dict[str, str]:
    """Trusted adapters that failed to load (after :meth:`Registry.available`)."""
    return {e.id: e.error for e in registry.entries() if e.trusted and e.error}


def cmd_status(registry: Registry, harness: str | None, as_json: bool) -> int:
    rows = []
    for adapter in _targets(registry, harness):
        row = {"harness": adapter.id, "installed": None, "version": None}
        try:
            inst = adapter.installation()
            row |= {"installed": inst.installed, "version": inst.version}
            accounts = adapter.list_accounts()
            row["active"] = [a.to_json() for a in accounts if a.active]
            row["activeKnown"] = bool(row["active"]) or all(a.active is not None for a in accounts)
        except Exception as exc:  # noqa: BLE001 - one harness must not hide the others
            row["error"] = _describe(exc)
        rows.append(row)
    if harness is None:
        rows += [{"harness": h, "installed": None, "version": None, "error": m} for h, m in _load_errors(registry).items()]
    errors = {row["harness"]: row["error"] for row in rows if "error" in row}
    if as_json:
        output.emit_json({"harnesses": rows, "errors": errors})
        return 1 if errors else 0
    for row in rows:
        if "error" in row:
            text = f"error: {row['error']}"
        elif not row["activeKnown"]:
            text = "active account unknown"
        elif row["active"]:
            text = ", ".join(
                a["label"]
                + (f" ({a['alias']})" if a["alias"] else "")
                + (f" [{a['provider']}]" if a["provider"] else "")
                + (" (disabled)" if a.get("details", {}).get("disabled") else "")
                for a in row["active"]
            )
        else:
            text = "no managed account active" if row["installed"] else "not installed"
        print(f"{row['harness']:<10} {text}")
    return 1 if errors else 0


def cmd_doctor(registry: Registry, as_json: bool) -> int:
    findings: list[tuple[str, str, str]] = []
    home = hswap_home()
    findings.append(("hswap", "info", f"data directory {home}"))
    adapters = registry.available()  # attempts every load, so failures are recorded
    for entry in registry.entries():
        if entry.error:  # a trusted adapter that failed to load is an error; a conflict is not
            findings.append((entry.id, "error" if entry.trusted else "warn", entry.error))
    findings += [(subject, "warn", message) for subject, message in registry.notices()]
    findings += [("hswap", "warn", message) for message in settings.invalid()]
    for adapter in adapters:
        try:
            inst = adapter.installation()
            if inst.installed and inst.version:
                findings.append((adapter.id, "info", f"{inst.executable} {inst.version}"))
            else:
                findings.append((adapter.id, "warn", inst.detail or f"{inst.executable}: version unknown"))
            for cap, status in adapter.capabilities().items():
                if status.support is Support.UNAVAILABLE:
                    findings.append((adapter.id, "warn", f"{cap}: {status.reason}"))
            if isinstance(adapter, Diagnosable):
                findings += [(adapter.id, level, msg) for level, msg in adapter.diagnose()]
        except Exception as exc:  # noqa: BLE001 - doctor reports, it does not crash
            findings.append((adapter.id, "error", _describe(exc)))
        try:
            AccountStore(home / adapter.id).load()
        except HswapError as exc:
            findings.append((adapter.id, "error", str(exc)))
    findings = list(dict.fromkeys(findings))  # an adapter's diagnose() may repeat the store check
    if as_json:
        output.emit_json({"findings": [{"harness": h, "level": lv, "message": m} for h, lv, m in findings]})
    else:
        width = min(max(len(h) for h, _, _ in findings), 24)
        for harness_id, level, message in findings:
            print(f"[{level:<5}] {harness_id:<{width}} {message}")
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
        steps = plan if dry_run else adapter.apply_migration()
        print(f"{adapter.display_name}:")
        for step in steps:
            print(f"  {'would ' if dry_run else ''}{step}")
    if not did_anything:
        print("Nothing to migrate.")
    return 0


def _show(value: object) -> str:
    return ",".join(value) if isinstance(value, list) else str(value)


def _check_harness_ids(registry: Registry, key: str, value: object) -> None:
    """A harness-list setting names harnesses hswap knows (a typo would silently do nothing)."""
    if key not in settings.WARNINGS or not isinstance(value, list):
        return
    unknown = sorted(set(value) - {e.id for e in registry.entries()})
    if unknown:
        raise HswapError(f"{key}: unknown harness {', '.join(unknown)}; known: {', '.join(registry.ids())}")


def _opt_in_notes(registry: Registry, added: set[str]) -> None:
    """Each newly opted-in harness's own terms warning (what `hswap capabilities` shows)."""
    for harness_id in sorted(added):
        try:
            terms = getattr(registry.get(harness_id), "terms", None)
        except HswapError:
            continue
        if terms:
            output.err(f"note: {harness_id} terms: {terms}")


def cmd_config(argv: list[str], registry: Registry) -> int:
    p = argparse.ArgumentParser(prog="hswap config")
    p.add_argument("action", nargs="?", default="list", choices=("list", "get", "set", "unset", "path"))
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    args = p.parse_args(argv)
    if args.action == "path":
        print(settings.settings_path())
    elif args.action == "list":
        for key, value in settings.load().items():
            print(f"{key} = {_show(value)}")
    elif args.action == "get":
        if args.key is None:
            raise HswapError("usage: hswap config get KEY")
        values = settings.load()
        if args.key not in values:
            raise HswapError(f"unknown setting {args.key!r}; known: {', '.join(values)}")
        print(_show(values[args.key]))
    elif args.action == "set":
        if args.key is None or args.value is None:
            raise HswapError("usage: hswap config set KEY VALUE")
        try:
            before = settings.load().get(args.key)
            if args.key in settings.SPECS:
                _check_harness_ids(registry, args.key, settings.SPECS[args.key][1](args.value))
            value = settings.set_value(args.key, args.value)
            print(f"{args.key} = {_show(value)}")
            added = set(value) - set(before or []) if isinstance(value, list) else set()
            if added and args.key in settings.WARNINGS:
                output.err(f"note: {settings.WARNINGS[args.key]}")
                _opt_in_notes(registry, added)
        except KeyError as exc:
            raise HswapError(str(exc).strip("'\"")) from None
        except ValueError as exc:
            raise HswapError(f"{args.key}: {exc}") from None
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
  hswap list [HARNESS]         accounts and usage (--json, --no-usage, --cached)
  hswap status [HARNESS]       active account per harness (--json)
  hswap capabilities [HARNESS] what each harness supports on this machine
  hswap doctor                 check installs, stores and permissions
  hswap migrate [--dry-run]    review/apply legacy data migration
  hswap config [list|get|set|unset|path]
  hswap tui                    dashboard (also: bare hswap in a terminal)

Per harness ({harnesses}):
  hswap <harness> list | status | add [--login] | remove | switch | run | usage | refresh | auto | alias | capabilities
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
    if argv[0] == "--json" and len(argv) > 1:  # `hswap --json status` == `hswap status --json`
        argv = [*argv[1:], "--json"]
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
            p.add_argument("--cached", action="store_true")
        if head == "migrate":
            p.add_argument("--dry-run", action="store_true")
        if head == "config":
            return cmd_config(rest, registry)
        if head != "migrate" and head != "tui":
            p.add_argument("--json", action="store_true")
        args = p.parse_args(rest)
        if head == "harnesses":
            return cmd_harnesses(registry, args.json)
        if head in ("list", "ls"):
            return cmd_list(registry, args.harness, args.json, not args.no_usage, args.cached)
        if head == "status":
            return cmd_status(registry, args.harness, args.json)
        if head == "capabilities":
            adapters = _targets(registry, args.harness)
            return _print_capabilities(adapters, args.json, None if args.harness else _load_errors(registry))
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
    except Exception as exc:  # an adapter bug (often a plugin): one clean line, not a traceback
        if os.environ.get("HSWAP_DEBUG"):
            raise
        if as_json:
            output.emit_json(output.error_json(exc))
        else:
            output.err(f"Error: {_describe(exc)} (set HSWAP_DEBUG=1 for a traceback)")
        return 1
    except KeyboardInterrupt:
        output.err("\nCancelled.")
        return 130
    return 0


def main() -> None:
    try:
        code = run(sys.argv[1:])
        sys.stdout.flush()
    except BrokenPipeError:  # `hswap list | head`: the reader left; not an error
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        code = 0
    sys.exit(code)
