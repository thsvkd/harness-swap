"""Claude Code adapter: the claude-swap engine behind hswap's contracts.

The engine (``claude_swap``, unchanged apart from a small embedding hook, its
error base class and two leaf modules that moved to ``harness_swap``) is the
proven implementation of everything Claude-specific -- Keychain/file credential routing, Claude Code's own
locks, refresh-token lineage checks, MCP/plugin OAuth preservation, the
usage store, auto-rotation and session profiles. This adapter does not
reimplement any of it:

* ``hswap claude <anything>`` runs the engine's CLI unchanged
  (:meth:`run_cli`), so every cswap command, flag and JSON payload keeps
  working, with ``hswap claude`` as the program name.
* The generic roles (list, switch, usage, ...) used by ``hswap list``, the
  dashboard and other harness-agnostic front ends translate the engine's
  schema-v1 JSON into core models.

The engine keeps using the claude-swap data directory in place, so cswap and
hswap see the same accounts. If the engine's own one-time move of a legacy
``~/.claude-swap-backup`` would run, every Claude command except help stops
and asks for ``hswap migrate`` instead of moving it as a side effect.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from harness_swap.adapters.base import probe_installation
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.errors import HswapError, UnsupportedOperation
from harness_swap.core.models import (
    Account,
    Capability,
    CapabilityStatus,
    Installation,
    QuotaWindow,
    SwitchResult,
    UsageSnapshot,
    UsageState,
    experimental,
    supported,
    unavailable,
    unsupported,
)
from harness_swap.core.paths import hswap_home
from harness_swap.core.store import mkdir_private
from harness_swap.infrastructure import spawn

PROG = "hswap claude"

#: engine verbs dispatched before its flag table (see ``claude_swap.cli.main``)
_ENGINE_VERBS = ("switch", "run", "auto", "map", "unmap", "unclaimed", "alias", "threshold", "priority", "swap", "move")


@functools.cache
def _cswap_command() -> re.Pattern:
    from claude_swap.cli import _SUBCOMMAND_FLAGS

    verbs = "|".join(sorted({*_SUBCOMMAND_FLAGS, *_ENGINE_VERBS, "config"}, key=len, reverse=True))
    return re.compile(rf"(?<![\w./-])cswap(?= (?:-|(?:{verbs})\b))")


def respell(text: str) -> str:
    """The engine's hints say ``cswap <command>``; under hswap that is ``hswap claude <command>``.

    Only the command spelling changes: the product name ("cswap's OAuth
    client") and paths (``~/.cswap-auto.log``) are left alone.
    """
    return _cswap_command().sub(PROG, text) if "cswap" in text else text


class _Respelled:
    """Write-through text stream that applies :func:`respell`."""

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        return self._stream.write(respell(text))

    def __getattr__(self, name: str):
        return getattr(self._stream, name)

#: engine ``usageStatus`` -> (state, explanation)
_STATUS = {
    "ok": (UsageState.AVAILABLE, ""),
    "token_expired": (UsageState.UNKNOWN, "token expired; Claude Code refreshes it on next use"),
    "relogin_required": (UsageState.AUTHENTICATION_REQUIRED, "refresh token is dead; sign in again"),
    "no_credentials": (UsageState.AUTHENTICATION_REQUIRED, "no stored credentials"),
    "api_key": (UsageState.UNSUPPORTED, "API-key accounts have no plan quota"),
    "keychain_unavailable": (UsageState.ERROR, "macOS Keychain unavailable"),
    "foreign_credential": (UsageState.ERROR, "live credential belongs to another account"),
    "unavailable": (UsageState.ERROR, "usage request failed"),
}


def _epoch(text: str | None) -> float | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _windows(usage: dict) -> tuple[QuotaWindow, ...]:
    out = []
    for key, name, seconds in (("fiveHour", "5h", 5 * 3600), ("sevenDay", "7d", 7 * 86400)):
        w = usage.get(key)
        if isinstance(w, dict):
            out.append(QuotaWindow(name, w.get("pct"), _epoch(w.get("resetsAt")), seconds))
    for w in usage.get("scoped") or ():
        out.append(QuotaWindow(f"7d:{w.get('name')}", w.get("pct"), _epoch(w.get("resetsAt")), 7 * 86400))
    return tuple(out)


def usage_from_row(row: dict) -> UsageSnapshot:
    """Normalise one engine ``list --json`` row's usage fields."""
    status = row.get("usageStatus", "unavailable")
    state, detail = _STATUS.get(status, (UsageState.UNKNOWN, status))
    usage = row.get("usage")
    measured = _epoch(row.get("usageFetchedAt"))
    if usage is None and row.get("lastGoodUsage"):
        usage, measured = row["lastGoodUsage"], _epoch(row.get("lastGoodFetchedAt"))
        if state is UsageState.ERROR:
            state, detail = UsageState.STALE, f"showing last good data ({detail})"
    windows = _windows(usage or {})
    if state is UsageState.AVAILABLE and any((w.used_percent or 0) >= 100 for w in windows):
        state = UsageState.RATE_LIMITED
    spend = (usage or {}).get("spend")
    return UsageSnapshot(
        state=state,
        windows=windows,
        measured_at=measured,
        source="anthropic-oauth-usage",
        detail=respell(row.get("usageError") or detail),
        balance={k: spend.get(k) for k in ("used", "limit", "currency", "pct")} if spend else None,
    )


def legacy_move_pending() -> tuple[Path, Path] | None:
    """``(legacy, target)`` when the engine would move ~/.claude-swap-backup."""
    from claude_swap import paths as cpaths

    target = cpaths.get_backup_root()
    legacy = cpaths.get_legacy_backup_root()
    try:
        same = legacy.resolve() == target.resolve()
    except OSError:
        same = legacy == target
    return None if same or not legacy.exists() else (legacy, target)


def legacy_collision(legacy: Path, target: Path) -> bool:
    """Both locations hold claude-swap data: the engine refuses to merge them."""
    from claude_swap import paths as cpaths

    return (
        target.exists()
        and not cpaths.migration_flag_for(target).exists()
        and cpaths._target_has_meaningful_data(target)
    )


def _collision_message(legacy: Path, target: Path) -> str:
    return (
        f"both {legacy} and {target} hold claude-swap data; hswap will not merge them. "
        "Keep the one you use, move the other out of the way, then run the command again."
    )


def _release_line(text: str) -> tuple[int, int] | None:
    m = re.search(r"(\d+)\.(\d+)", text)
    return (int(m[1]), int(m[2])) if m else None


def _loose_modes(root: Path) -> list[Path]:
    """Store directories and secret files that group/other can access (POSIX)."""
    if os.name != "posix" or not root.is_dir():
        return []
    loose = [root] if root.stat().st_mode & 0o077 else []
    loose += [
        f
        for f in sorted(root.glob("*.json"))
        if f.is_file() and f.stat().st_mode & 0o077  # sequence/settings/mappings
    ]
    for sub in (root / "credentials", root / "configs"):
        if not sub.is_dir():
            continue
        if sub.stat().st_mode & 0o077:
            loose.append(sub)
        loose += [
            f
            for f in sorted(sub.iterdir())
            if f.is_file() and not f.name.endswith(".lock") and f.stat().st_mode & 0o077
        ]
    return loose


class ClaudeAdapter:
    id = "claude"
    display_name = "Claude Code"
    providers = ("anthropic",)
    #: The engine paces and caches its own usage requests; don't add a second layer.
    usage_policy = UsagePolicy(min_interval_s=0.0, stale_after_s=900.0, max_backoff_s=0.0)

    def __init__(self) -> None:
        self._installation: Installation | None = None
        self._engine = None
        self._rows: dict[str, dict] | None = None

    # -- engine ------------------------------------------------------------------

    def _switcher(self):
        if self._engine is None:
            pending = legacy_move_pending()
            if pending and legacy_collision(*pending):
                raise HswapError(_collision_message(*pending))
            if pending:
                raise HswapError(
                    f"claude-swap data still lives in {pending[0]}; the Claude engine would move it to "
                    f"{pending[1]}. Run `hswap migrate --dry-run` to review, then `hswap migrate`."
                )
            from claude_swap.switcher import ClaudeAccountSwitcher

            self._engine = ClaudeAccountSwitcher()
        return self._engine

    def run_cli(self, argv: list[str]) -> int:
        # Only help/version run before a pending legacy move: every other
        # engine path (including bare `hswap claude` and `config`) may start
        # the engine, which would move the store as a side effect.
        if legacy_move_pending() and argv not in (["help"], ["-h"], ["--help"], ["--version"]):
            self._switcher()  # raises the explanatory error
        from claude_swap import cli as engine_cli

        saved = sys.argv, engine_cli.EMBEDDED_PROG, sys.stdout, sys.stderr
        sys.argv = [PROG, *argv]
        engine_cli.EMBEDDED_PROG = PROG
        sys.stdout, sys.stderr = _Respelled(sys.stdout), _Respelled(sys.stderr)
        try:
            engine_cli.main()
            return 0
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        except EOFError:
            raise HswapError("this command asks for confirmation; run it in a terminal") from None
        finally:
            sys.argv, engine_cli.EMBEDDED_PROG, sys.stdout, sys.stderr = saved

    # -- discovery ----------------------------------------------------------------

    def installation(self) -> Installation:
        if self._installation is None:
            self._installation = probe_installation("claude")
        return self._installation

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        macos = sys.platform == "darwin"
        inst = self.installation()
        no_binary = None if inst.installed else unavailable(f"Claude Code is not installed ({inst.detail})")
        return {
            Capability.ACCOUNT_LIST: supported(),
            Capability.ACCOUNT_ADD: supported("adds the current Claude Code login (`add`, `add-token`)"),
            Capability.ACCOUNT_REMOVE: supported(),
            Capability.ACCOUNT_SWITCH: supported("keeps MCP/plugin OAuth state; takes Claude Code's own locks"),
            Capability.NATIVE_ACCOUNT_SWITCH: unsupported("Claude Code has one login per config directory"),
            Capability.CREDENTIAL_REFRESH: supported("refreshes stored tokens for usage reads, lineage-checked"),
            Capability.USAGE_MONITORING: supported("Anthropic OAuth usage: 5-hour, 7-day and per-model windows"),
            Capability.AUTOMATIC_ROTATION: supported("`hswap claude auto` (threshold, priority, cooldown)"),
            Capability.PARALLEL_SESSIONS: no_binary
            or experimental("`hswap claude run <account>`: per-account CLAUDE_CONFIG_DIR"),
            Capability.SESSION_RESUME: no_binary or supported("`hswap claude run <account> -- --resume`"),
            Capability.CREDENTIAL_HOT_RELOAD: (
                experimental("picked up after the macOS Keychain cache expires; restart to apply at once")
                if macos
                else supported("Claude Code re-reads its credentials file")
            ),
        }

    # -- generic roles -------------------------------------------------------------

    def _list_rows(self) -> dict[str, dict]:
        if self._rows is None:
            payload = self._switcher().list_accounts(json_output=True) or {}
            self._rows = {str(r["number"]): r for r in payload.get("accounts", [])}
        return self._rows

    def _account(self, row: dict) -> Account:
        org = row.get("organizationUuid") or ""
        return Account(
            harness=self.id,
            identity=f"{row['email']}/{org or 'personal'}",
            label=row["email"],
            provider="anthropic",
            slot=int(row["number"]),
            alias=row.get("alias"),
            auth_mode="api_key" if row.get("usageStatus") == "api_key" else "oauth",
            active=bool(row.get("active")),
            details={"organization": row.get("organizationName") or "personal"}
            | ({"disabled": True} if row.get("disabled") else {}),
        )

    def list_accounts(self) -> list[Account]:
        self._rows = None  # always a fresh engine pass for a listing
        return [self._account(r) for r in self._list_rows().values()]

    def read_usage(self, account: Account) -> UsageSnapshot:
        row = self._list_rows().get(str(account.slot))
        if row is None:
            return UsageSnapshot(UsageState.UNKNOWN, detail="account not found in the engine")
        return usage_from_row(row)

    def add_account(
        self, *, alias: str | None = None, provider: str | None = None, login: bool = False
    ) -> Account:
        if login:
            raise UnsupportedOperation(
                "account_add", "sign in with Claude Code (`claude /login`), then `hswap claude add`"
            )
        sw = self._switcher()
        sw.add_account(slot=None, alias=alias)
        self._rows = None
        current = sw.current_account_number()
        return next(a for a in self.list_accounts() if str(a.slot) == str(current))

    def remove_account(self, account: Account) -> None:
        self._switcher().remove_account(str(account.slot), assume_yes=True)
        self._rows = None

    def set_alias(self, account: Account, alias: str | None) -> Account:
        sw = self._switcher()
        if alias is None:
            sw.unset_alias(str(account.slot))
        else:
            sw.set_alias(str(account.slot), alias)
        self._rows = None
        return next(a for a in self.list_accounts() if a.slot == account.slot)

    def switch_account(self, account: Account, *, force: bool = False) -> SwitchResult:
        payload = self._switcher().switch_to(str(account.slot), json_output=True, force=force) or {}
        self._rows = None
        accounts = {a.slot: a for a in self.list_accounts()}
        prev_ref = payload.get("from") or {}
        previous = accounts.get(prev_ref.get("number")) if payload.get("switched") else None
        notes = list(payload.get("warnings") or [])
        if not payload.get("switched"):
            notes.insert(0, "already the active account")
        elif sys.platform == "darwin":
            notes.append("Claude Code picks this up when its Keychain cache expires; restart to apply now")
        return SwitchResult(
            harness=self.id,
            current=accounts.get(account.slot, account),
            previous=previous,
            restart_required=False,
            notes=tuple(notes),
        )

    def launch(self, account: Account, args: list[str]) -> int:
        return self.run_cli(["run", str(account.slot), "--", *args])

    # -- migration / diagnostics ----------------------------------------------------

    def migration_plan(self) -> list[str]:
        pending = legacy_move_pending()
        if not pending:
            return []
        legacy, target = pending
        if legacy_collision(legacy, target):
            return [f"refuse to move {legacy}: {_collision_message(legacy, target)}"]
        return [f"back up {legacy} to {hswap_home() / 'backups'}/claude-swap-<time>, then move it to {target}"]

    def apply_migration(self) -> list[str]:
        pending = legacy_move_pending()
        if not pending:
            return []
        legacy, target = pending
        if legacy_collision(legacy, target):
            raise HswapError(_collision_message(legacy, target))
        backup_root = hswap_home() / "backups"
        mkdir_private(backup_root)
        backup = backup_root / f"claude-swap-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copytree(legacy, backup, symlinks=True)
        from claude_swap.switcher import ClaudeAccountSwitcher

        self._engine = ClaudeAccountSwitcher()  # performs the engine's own move
        return [f"backed up {legacy} to {backup}", f"moved {legacy} -> {target}"]

    def diagnose(self) -> list[tuple[str, str]]:
        from claude_swap import __version__ as engine_version
        from claude_swap import paths as cpaths

        out = []
        upstream = shutil.which("cswap")
        if upstream:
            try:
                theirs = spawn.run([upstream, "--version"], capture_output=True, text=True, timeout=15).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                theirs = ""
            if theirs and _release_line(theirs) == _release_line(engine_version):
                out.append(("info", f"upstream {theirs} at {upstream} shares the Claude store (same release line)"))
            else:
                message = (
                    f"upstream {theirs or 'cswap (version unknown)'} at {upstream} shares the Claude store, "
                    f"but hswap's engine is {engine_version}; keep both on the same release line"
                )
                out.append(("warn", message))
        pending = legacy_move_pending()
        if pending and legacy_collision(*pending):
            out.append(("error", _collision_message(*pending)))
        elif pending:
            out.append(("warn", f"legacy claude-swap data at {pending[0]}: run `hswap migrate`"))
        root = pending[0] if pending else cpaths.get_backup_root()
        loose = _loose_modes(root)
        if loose:
            advice = "chmod 700 the directories and 600 the files"
            out.append(("warn", f"{len(loose)} path(s) in {root} are accessible to other users, e.g. {loose[0]}; {advice}"))
        return out
