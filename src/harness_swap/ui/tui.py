"""``hswap tui``: one overview of every registered harness.

Built only from the registry, core models and capabilities, so a new adapter
appears here without any change to this file. Rows show harness, provider,
account, whether it is active, and normalised usage (or why there is none).
Harness-specific dashboards stay with their adapters (e.g. ``hswap claude tui``).

Keys: ``r`` refresh, ``s`` switch to the highlighted account, ``q`` quit.
"""

from __future__ import annotations

from typing import ClassVar

from harness_swap import output
from harness_swap.core import accounts as service
from harness_swap.core.models import Account, Capability
from harness_swap.core.paths import hswap_home
from harness_swap.core.registry import Registry
from harness_swap.core.usage import UsageService


def collect(registry: Registry) -> list[tuple]:
    """``[(adapter, account|None, usage text, note)]`` -- one pass, errors inline."""
    usage_service = UsageService(hswap_home() / "cache")
    rows = []
    for adapter in registry.available():
        inst = adapter.installation()
        if not inst.installed:
            rows.append((adapter, None, "", f"not installed: {inst.detail}"))
            continue
        try:
            accounts = adapter.list_accounts()
            usage = service.collect_usage(adapter, accounts, usage_service)
            switch = adapter.capabilities().get(Capability.ACCOUNT_SWITCH)
        except Exception as exc:  # noqa: BLE001 - one harness must not take the dashboard down
            rows.append((adapter, None, "", f"error: {exc}"))
            continue
        if not accounts:
            rows.append((adapter, None, "", f"no accounts (hswap {adapter.id} add)"))
        for acc in accounts:
            note = "" if switch and switch.usable else "switching unavailable"
            rows.append((adapter, acc, output.usage_text(usage.get(acc.key)), note))
    return rows


def build_app(registry: Registry):
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.widgets import DataTable, Footer, Header, Static

    class HswapOverview(App):
        TITLE = "hswap"
        SUB_TITLE = "accounts across harnesses"
        BINDINGS: ClassVar = [
            Binding("r", "refresh", "Refresh"),
            Binding("s", "switch", "Switch to highlighted"),
            Binding("q", "quit", "Quit"),
        ]

        def compose(self) -> ComposeResult:
            yield Header()
            yield DataTable(cursor_type="row", zebra_stripes=True)
            yield Static("", id="status")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one(DataTable)
            table.add_columns("Harness", "Provider", "Slot", "Account", "Active", "Usage / note")
            self._rows: list[tuple] = []
            self._message = ""
            self.action_refresh()

        def _say(self, text: str) -> None:
            self._message = text
            self.query_one("#status", Static).update(text)

        def action_refresh(self) -> None:
            self.query_one("#status", Static).update("Refreshing...")
            self.run_worker(lambda: collect(registry), thread=True, exclusive=True, group="refresh")

        def on_worker_state_changed(self, event) -> None:
            if event.worker.group == "refresh" and event.worker.is_finished and event.worker.result is not None:
                self._fill(event.worker.result)
                self.query_one("#status", Static).update(self._message)

        def _fill(self, rows: list[tuple]) -> None:
            self._rows = rows
            table = self.query_one(DataTable)
            table.clear()
            for adapter, acc, usage, note in rows:
                if acc is None:
                    table.add_row(adapter.display_name, "", "", "", "", note)
                    continue
                active = {True: "yes", False: "", None: "?"}[acc.active]
                label = acc.label + (f" ({acc.alias})" if acc.alias else "")
                table.add_row(
                    adapter.display_name,
                    acc.provider or "",
                    "" if acc.slot is None else str(acc.slot),
                    label,
                    active,
                    note or usage,
                )

        def action_switch(self) -> None:
            table = self.query_one(DataTable)
            if not self._rows or table.cursor_row is None:
                return
            adapter, acc, _usage, _note = self._rows[table.cursor_row]
            if acc is None:
                return
            self.run_worker(lambda: self._switch(adapter, acc), thread=True, group="switch")

        def _switch(self, adapter, acc: Account) -> None:
            try:
                result = service.switch(adapter, str(acc.slot) if acc.slot is not None else acc.identity, provider=acc.provider)
                message = f"{adapter.display_name}: now {result.current.label}. " + " ".join(result.notes)
            except Exception as exc:  # noqa: BLE001 - shown in the status line, not a crash
                message = f"{adapter.display_name}: {exc}"
            self.call_from_thread(self._say, message)
            self.call_from_thread(self.action_refresh)

    return HswapOverview()


def run(registry: Registry) -> int:
    build_app(registry).run()
    return 0
