"""``hswap tui`` (and bare ``hswap`` in a terminal): every harness in one dashboard.

The Claude engine's dashboard (``hswap claude tui``), generalised: the same
chrome, themes, keys, menus and modals, with the accounts grouped per
harness. Built only from the registry, core models and capabilities, so a new
adapter appears here without any change to this package.

- Dashboard: each harness's active account(s) as a full card with usage bars,
  the others as one-line minis; a nested menu below (Switch account…, Watch
  accounts, Auto-switch view, Add account…, Remove account…, Theme…, Quit).
- ``s`` switch screen (Enter switches, ``b`` best pick), ``w`` watch screen
  (``s`` arms selection), ``g`` auto-switch view (dry-run until ``l``),
  ``f`` refresh now, ``ctrl+t`` cycles the theme (``ui.theme``).

The engine's "Disable / enable account" and "setup-token / API key" entries
are features of the Claude engine alone; they stay in ``hswap claude tui``.
The dashboard never forces a switch over a login hswap does not manage.
"""

from __future__ import annotations

import contextlib
import io
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from types import SimpleNamespace
from typing import Any, ClassVar, NamedTuple

from textual.app import App
from textual.binding import Binding
from textual.reactive import reactive
from textual.worker import WorkerState

from harness_swap.core import accounts as service
from harness_swap.core import settings
from harness_swap.core.errors import (
    CredentialConflict,
    HswapError,
    NoSwitchTarget,
    UnsupportedOperation,
)
from harness_swap.core.models import Account, Capability, UsageSnapshot
from harness_swap.core.paths import hswap_home
from harness_swap.core.registry import Registry
from harness_swap.core.usage import UsageService
from harness_swap.ui.fmt import format_duration
from harness_swap.ui.modals import ConfirmModal, OutputModal
from harness_swap.ui.screens import AutoScreen, DashboardScreen, WatchScreen
from harness_swap.ui.theme import CSWAP_DARK, CSWAP_LIGHT, STYLESHEET


class Row(NamedTuple):
    """One dashboard row: an account, or (``account`` None) a harness with nothing to list."""

    adapter: Any  # a HarnessAdapter, or a stand-in for a plugin that failed to load
    account: Account | None
    usage: UsageSnapshot | None  # None while it is being measured
    note: str = ""  # why a harness lists no account ("not installed: ...", "error: ...")


def _describe(exc: Exception) -> str:
    return str(exc) if isinstance(exc, HswapError) else f"{type(exc).__name__}: {exc}"


LOADING = "loading…"  # the note of a harness whose accounts are still being read
NO_ACCOUNTS = "no accounts · Add account…"
NOOP_NOTE = "already the active account"  # what the adapters note when the target is live already


def collect(registry: Registry, progress: Callable[[list[Row]], None] | None = None) -> list[Row]:
    """Every harness's accounts and usage -- errors inline.

    The harnesses are read in parallel, so one slow harness does not hold back
    the others. ``progress`` receives every harness's rows so far, in registry
    order, each time one of them advances: a ``LOADING`` row until its
    accounts are listed, then its accounts before their (possibly slow) usage.
    """
    usage_service = UsageService(hswap_home() / "cache")
    adapters = list(registry.available())
    failed = [  # plugins that failed to load: shown, not hidden
        Row(SimpleNamespace(id=entry.id, display_name=entry.id), None, None, f"error: {entry.error}")
        for entry in registry.entries()
        if entry.trusted and entry.error
    ]
    parts = {adapter.id: [Row(adapter, None, None, LOADING)] for adapter in adapters}
    lock = threading.Lock()

    def rows() -> list[Row]:
        return [r for adapter in adapters for r in parts[adapter.id]] + failed

    def put(adapter, part: list[Row]) -> None:
        with lock:
            parts[adapter.id] = part
            if progress:
                progress(rows())

    def read(adapter) -> None:
        try:
            inst = adapter.installation()
            if not inst.installed:
                put(adapter, [Row(adapter, None, None, f"not installed: {inst.detail}")])
                return
            accounts = adapter.list_accounts()
            if accounts:
                put(adapter, [Row(adapter, acc, None) for acc in accounts])
            usage = service.collect_usage(adapter, accounts, usage_service)
        except Exception as exc:  # noqa: BLE001 - one harness must not take the dashboard down
            put(adapter, [Row(adapter, None, None, f"error: {_describe(exc)}")])
            return
        put(adapter, [Row(adapter, acc, usage.get(acc.key)) for acc in accounts] or [Row(adapter, None, None, NO_ACCOUNTS)])

    # ponytail: a pass ends with its slowest harness, so the next one (and a fast
    # harness's refresh) waits for it; per-harness poll loops if that ever matters.
    with ThreadPoolExecutor(max_workers=max(1, len(adapters))) as pool:
        list(pool.map(read, adapters))
    return rows()


def addable(rows: list[Row]) -> list:
    """Installed harnesses that can add their current login (asked off the UI thread)."""
    out = []
    for adapter in {r.adapter.id: r.adapter for r in rows}.values():
        try:
            status = adapter.capabilities().get(Capability.ACCOUNT_ADD)
            if status is not None and status.usable and adapter.installation().installed:
                out.append(adapter)
        except Exception:  # noqa: BLE001, S112 - a broken harness simply offers nothing here
            continue
    return out


def _add_current(adapter) -> tuple[Account, bool]:
    """Add the harness's current login; also says whether hswap already had it."""
    known = {a.key for a in adapter.list_accounts()}
    acc = service.add(adapter)
    return acc, acc.key in known


class HswapApp(App):
    """Owns the poll loop and every mutating action, so all screens drive the
    same code paths. Blocking work always runs in thread workers."""

    TITLE = "hswap"
    CSS_PATH = STYLESHEET
    # No command palette: actions live in the dashboard's nested menu.
    ENABLE_COMMAND_PALETTE = False
    BINDINGS: ClassVar = [Binding("ctrl+t", "toggle_theme", "Theme")]

    # ponytail: 10s, not the engine dashboard's 3s, because listing accounts can
    # spawn a harness process (OpenCode runs `opencode auth list`); per-harness
    # intervals if one harness ever needs to be faster than the slowest.
    POLL_INTERVAL_S = 10.0
    # The data's age shows only past this (a staleness alarm, not a ticker).
    SNAPSHOT_AGE_NOTE_S = 60.0

    rows: reactive[list[Row] | None] = reactive(None, always_update=True)
    refresh_status: reactive[str] = reactive("")

    def __init__(self, registry: Registry, *, detected: str | None = None) -> None:
        super().__init__()
        self.registry = registry
        self._detected = detected  # terminal background sensed before the driver started
        self.usage_service = UsageService(hswap_home() / "cache")
        values = settings.load()
        #: The switch line: the tick on every bar, and `b`'s cut-off.
        self.threshold: float = values["rotation.threshold"]
        self._theme_name: str = values["ui.theme"]
        self.addable: list | None = None  # known after the first full pass
        self.busy = False
        self._collecting = False
        self._again = False
        self._collect_started: float | None = None
        self._rows_at: float | None = None
        self._last_refresh_error = ""

    def on_mount(self) -> None:
        self.register_theme(CSWAP_DARK)
        self.register_theme(CSWAP_LIGHT)
        self.theme = f"cswap-{self._resolved_theme()}"
        self.push_screen(DashboardScreen())
        self.set_interval(self.POLL_INTERVAL_S, self._tick)
        self.set_interval(1.0, self._second)
        self._tick()

    # -- poll loop ------------------------------------------------------------------

    def _tick(self) -> None:
        if self._collecting:
            return
        self._collecting = True
        self._collect_started = time.time()
        self.run_worker(self._collect_blocking, thread=True, group="refresh", exit_on_error=False, name="collect")

    def request_refresh(self) -> None:
        if self._collecting:
            self._again = True  # the pass in flight may predate what just changed
        else:
            self._tick()

    def _collect_blocking(self) -> None:
        rows = collect(self.registry, partial(self.call_from_thread, self._apply_rows))
        self.call_from_thread(self._collect_done, rows, addable(rows))

    def _apply_rows(self, rows: list[Row]) -> None:
        """Show ``rows``; a harness still loading keeps its previous rows, and an
        account being re-measured keeps its previous numbers meanwhile."""
        old: dict[str, list[Row]] = {}
        for r in self.rows or ():
            old.setdefault(r.adapter.id, []).append(r)
        usage = {(r.adapter.id, r.account.key): r.usage for part in old.values() for r in part if r.account}
        shown: list[Row] = []
        for r in rows:
            if r.account is None and r.note == LOADING:
                shown += old.get(r.adapter.id, [r])
            elif r.account is not None and r.usage is None:
                shown.append(r._replace(usage=usage.get((r.adapter.id, r.account.key))))
            else:
                shown.append(r)
        self.rows = shown

    def _collect_done(self, rows: list[Row], can_add: list) -> None:
        self._apply_rows(rows)
        self.addable = can_add
        self._collecting = False
        self._collect_started = None
        self._rows_at = time.time()
        self._last_refresh_error = ""
        self._update_refresh_status()
        if self._again:
            self._again = False
            self._tick()

    def _second(self) -> None:
        self._update_refresh_status()
        # Countdowns change once a minute, and every pass re-renders anyway;
        # tick each second only while one counts down its last minute.
        now = time.time()
        if any(
            w.resets_at and -1 < w.resets_at - now < 61
            for r in self.rows or ()
            if r.usage is not None
            for w in r.usage.windows
        ):
            self.rows = self.rows

    def _update_refresh_status(self) -> None:
        parts: list[str] = []
        now = time.time()
        if self._rows_at is not None and now - self._rows_at >= self.SNAPSHOT_AGE_NOTE_S:
            parts.append(f"snapshot {format_duration(now - self._rows_at)} ago")
        if self._collect_started is not None and now - self._collect_started >= self.POLL_INTERVAL_S:
            parts.append(f"refreshing {format_duration(now - self._collect_started)}")
        self.refresh_status = " · ".join(parts)

    def on_worker_state_changed(self, event) -> None:
        if event.state is not WorkerState.ERROR:
            return
        if event.worker.group == "refresh":
            self._collecting = False
            self._collect_started = None
            self._update_refresh_status()
            msg = str(event.worker.error)
            if msg != self._last_refresh_error:
                self._last_refresh_error = msg
                self.notify(f"Refresh failed: {msg}", severity="warning", timeout=6)
        elif event.worker.group == "action":
            self.busy = False
            self.notify(f"Action failed: {event.worker.error}", severity="error")

    # -- mutating actions (single-flight, captured, off-thread) ---------------------------

    def _start_action(self, label: str, fn, done, refused=None) -> None:
        """Run ``fn`` in a worker. ``done(result, output)`` on success;
        ``refused(error)`` may claim a failure it explains itself."""
        if self.busy:
            self.notify("Another action is still running", severity="warning")
            return
        self.busy = True
        self.run_worker(
            partial(self._action_blocking, label, fn, done, refused),
            thread=True,
            group="action",
            exit_on_error=False,
            name=label,
        )

    def _action_blocking(self, label: str, fn, done, refused) -> None:
        buf = io.StringIO()
        result = error = None
        # An unexpected prompt fails (EOFError) instead of freezing the app.
        saved, sys.stdin = sys.stdin, io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                result = fn()
        except Exception as exc:  # noqa: BLE001 - shown to the user, never a crash
            error = exc
        finally:
            sys.stdin = saved
        self.call_from_thread(self._action_finished, label, done, refused, result, error, buf.getvalue())

    def _action_finished(self, label: str, done, refused, result, error, output: str) -> None:
        self.busy = False
        self.request_refresh()
        if error is None:
            done(result, output)
        elif refused is not None and refused(error):
            pass
        elif isinstance(error, UnsupportedOperation):
            self.notify(error.reason, title=label, severity="warning", timeout=8)
        else:
            self.push_screen(OutputModal(f"{label} — failed", f"{output}Error: {_describe(error)}"))

    # -- account operations ------------------------------------------------------------------

    def do_switch(self, row: Row) -> None:
        adapter, acc = row.adapter, row.account
        target = str(acc.slot) if acc.slot is not None else acc.identity
        self._start_action(
            f"Switch {adapter.display_name} to {acc.label}",
            partial(service.switch, adapter, target, provider=acc.provider),
            partial(self._switched, adapter),
            partial(self._switch_refused, adapter, target),
        )

    def switch_best(self, row: Row) -> None:
        """``b``: the policy's pick within the highlighted account's harness."""
        adapter = row.adapter
        self._start_action(
            f"Switch {adapter.display_name} (best)",
            partial(
                service.switch_by_strategy, adapter, "best", self.usage_service,
                threshold=self.threshold, provider=row.account.provider,
            ),
            partial(self._switched, adapter),
            partial(self._switch_refused, adapter, "--strategy best"),
        )

    def _switched(self, adapter, result, _output: str) -> None:
        if NOOP_NOTE in result.notes or (result.previous is not None and result.previous.key == result.current.key):
            notes = [n for n in result.notes if n != NOOP_NOTE]
            lines = [f"{result.current.label} is already the active {adapter.display_name} account", *notes]
            self.notify("\n".join(lines), title="No switch", severity="warning")
            return
        lines = [f"Switched {adapter.display_name} to {result.current.label}", *result.notes]
        self.notify("\n".join(lines), title="Switch", timeout=8)

    def _switch_refused(self, adapter, target: str, error: Exception) -> bool:
        """Outcomes that are not failures: a calm "No switch" toast, never a modal."""
        if isinstance(error, CredentialConflict):
            message = (
                f"The current {adapter.display_name} login is not one hswap manages, and the dashboard "
                f"never replaces it. Add it first (Add account…), or run "
                f"`hswap {adapter.id} switch {target} --force`."
            )
        elif isinstance(error, UnsupportedOperation):
            message = error.reason
        elif isinstance(error, NoSwitchTarget):
            message = str(error)
        else:
            return False
        self.notify(message, title="No switch", severity="warning", timeout=12)
        return True

    def confirm_add(self, adapter) -> None:
        self.push_screen(
            ConfirmModal(
                f"Back up the current {adapter.display_name} login as a managed account?\n\n"
                "If this account is already managed, its stored login is refreshed in place.",
                title="Add account",
                yes_label="Add",
            ),
            partial(self._on_add_confirm, adapter),
        )

    def _on_add_confirm(self, adapter, confirmed: bool | None) -> None:
        if confirmed:
            self._start_action("Add current login", partial(_add_current, adapter), partial(self._added, adapter))

    def _added(self, adapter, result: tuple[Account, bool], output: str) -> None:
        if output.strip():  # the harness had more to say: show it, as the engine's dashboard does
            self.push_screen(OutputModal("Add current login", output))
            return
        acc, existed = result
        where = f"{adapter.display_name} slot {acc.slot}"
        message = f"{acc.label} is already {where}; its stored login was refreshed" if existed else f"Added {acc.label} as {where}"
        self.notify(message, title="Add account")

    def confirm_remove(self, row: Row) -> None:
        adapter, acc = row.adapter, row.account
        slot = "-" if acc.slot is None else acc.slot
        self.push_screen(
            ConfirmModal(
                f"Remove {adapter.display_name} account {slot} ({acc.label})?\n\nhswap forgets its stored copy.",
                title="Remove account",
                yes_label="Remove",
            ),
            partial(self._on_remove_confirm, row),
        )

    def _on_remove_confirm(self, row: Row, confirmed: bool | None) -> None:
        if not confirmed:
            return
        adapter, acc = row.adapter, row.account
        target = str(acc.slot) if acc.slot is not None else acc.identity
        self._start_action(
            f"Remove account {target}",
            partial(service.remove, adapter, target, acc.provider),
            lambda removed, _output: self.notify(
                f"Removed {removed.label} from {adapter.display_name}", title="Remove account"
            ),
        )

    # -- navigation ------------------------------------------------------------------------

    def action_refresh_full(self) -> None:
        self.request_refresh()
        self.notify("Refreshing usage…", timeout=2)

    def action_open_auto(self) -> None:
        if not isinstance(self.screen, AutoScreen):
            self.push_screen(AutoScreen())

    def action_open_watch(self) -> None:
        if not isinstance(self.screen, WatchScreen):
            self.push_screen(WatchScreen())

    # -- theme ------------------------------------------------------------------------------

    def _resolved_theme(self) -> str:
        """Concrete 'dark'/'light' for the setting; auto -> detected -> dark."""
        if self._theme_name == "auto":
            return self._detected or "dark"
        return self._theme_name

    def apply_theme(self, name: str) -> None:
        """Switch the live theme and persist the setting (``ui.theme``)."""
        self._theme_name = name
        self.theme = f"cswap-{self._resolved_theme()}"
        try:
            settings.set_value("ui.theme", name)
        except Exception as exc:  # noqa: BLE001 - persistence is best-effort; never crash the UI
            self.notify(f"Could not save theme: {exc}", severity="warning")

    def action_toggle_theme(self) -> None:
        order = ("dark", "light", "auto")
        nxt = order[(order.index(self._theme_name) + 1) % len(order)]
        self.apply_theme(nxt)
        self.notify(f"Theme: {nxt}")


def run(registry: Registry) -> int:
    from harness_swap.ui.appearance import detect_terminal_background, drain_stdin

    # Sense the terminal background while stdin is still in cooked mode
    # (Textual's driver starts inside app.run()); a detection bug must never
    # stop the dashboard from starting.
    try:
        detected = detect_terminal_background()
    except Exception:  # noqa: BLE001
        detected = None
    app = HswapApp(registry, detected=detected)
    # Drop a late reply so it is not read as keystrokes once the app runs.
    with contextlib.suppress(Exception):
        drain_stdin()
    app.run()
    return app.return_code or 0
