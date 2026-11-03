"""Screens of ``hswap tui``: dashboard, switch, watch and auto-switch views.

The same layout, keys and wording as the Claude engine's own dashboard, with
the accounts grouped per harness. Everything here renders core models only:
a :class:`~harness_swap.ui.tui.Row` carries the adapter, the ``Account`` and
its ``UsageSnapshot``; blocking work (switch, add, remove, automatic-switch
passes) runs in thread workers owned by the app or the auto screen.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from functools import partial
from itertools import groupby
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, ListItem, ListView, RichLog, Static

from harness_swap.core import autorotate, settings
from harness_swap.core.errors import HarnessNotFound, HswapError, UnsupportedOperation
from harness_swap.core.models import QuotaWindow, UsageSnapshot, UsageState
from harness_swap.ui.fmt import clock_stamp, format_duration, reset_clock_string
from harness_swap.ui.modals import ConfirmModal
from harness_swap.ui.theme import Palette
from harness_swap.ui.widgets import MenuItem, usage_bar

if TYPE_CHECKING:
    from harness_swap.ui.tui import HswapApp, Row

FLASH_S = 1.5  # how long a just-measured row stays highlighted
AGE_NOTE_S = 180.0  # a measurement older than this shows its age on the card (as the engine's dashboard)
_WARN = {UsageState.AUTHENTICATION_REQUIRED, UsageState.RATE_LIMITED, UsageState.ERROR}
_DIM = {UsageState.STALE, UsageState.ERROR}  # numbers that are not current

MenuEntries = list[tuple[str, str]]  # (label, action_id)
_BACK = ("← back", "back")


# -- rendering (pure: rows in, Rich text out) -----------------------------------------


def groups(rows: list[Row]) -> list[tuple[Any, str, list[Row]]]:
    """``(adapter, heading note, account rows)`` per harness, in registry order."""
    out = []
    for _id, items in groupby(rows, key=lambda r: r.adapter.id):
        items = list(items)
        note = next((r.note for r in items if r.account is None and r.note), "")
        out.append((items[0].adapter, note, [r for r in items if r.account is not None]))
    return out


def _state(snap: UsageSnapshot) -> str:
    return str(snap.state).replace("_", " ")


def _warning(snap: UsageSnapshot) -> str:
    return f"⚠ {_state(snap)}: {snap.detail}" if snap.detail else f"⚠ {_state(snap)}"


def _tag(row: Row) -> str:
    """Provider (harnesses fronting several) and plan: measured, else as stored at add."""
    parts = []
    if row.account.provider and len(row.adapter.providers) != 1:
        parts.append(row.account.provider)
    plan = (row.usage.plan if row.usage is not None else None) or row.account.details.get("plan")
    if isinstance(plan, str) and plan:
        parts.append(plan)
    return " · ".join(parts)


def _reset(window: QuotaWindow, now: float, room: int | None = None) -> str | None:
    """``resets 2h 13m``; with ``· 23:44`` appended when it fits in ``room``."""
    if not window.resets_at:
        return None
    remaining = window.resets_at - now
    if remaining <= 0:
        return "resets now"
    text = f"resets {format_duration(remaining)}"
    if room is None:
        return text
    clock = reset_clock_string(
        datetime.fromtimestamp(window.resets_at, tz=UTC), datetime.fromtimestamp(now, tz=UTC)
    )
    full = f"{text} · {clock}"
    return full if len(full) <= room else text


def _balance(balance: dict) -> str:
    def show(value: object) -> str:
        return f"{value:g}" if isinstance(value, int | float) and not isinstance(value, bool) else str(value)

    parts = [f"{k} {show(v)}" for k, v in balance.items() if k != "currency" and v is not None]
    currency = balance.get("currency")
    return "balance  " + " · ".join(parts) + (f" ({currency})" if currency else "")


def heading_text(adapter: Any, note: str, palette: Palette) -> Text:
    text = Text(adapter.display_name, style=f"bold {palette.foreground}")
    if note:
        text.append(f"  {note}", style=palette.muted)
    return text


def _header(row: Row, now: float, palette: Palette, *, card: bool) -> Text:
    acc = row.account
    text = Text() if card else Text(no_wrap=True, overflow="ellipsis")
    slot = "-" if acc.slot is None else str(acc.slot)
    text.append(f"{slot:>2}  ", style=f"bold {palette.foreground if card else palette.muted}")
    if acc.alias:
        text.append(acc.alias, style=f"bold {palette.accent}")
        text.append(f" ({acc.label})", style=palette.foreground)
    else:
        text.append(acc.label, style=palette.foreground)
    tag = _tag(row)
    if tag:
        text.append(f"  [{tag}]", style=palette.muted)
    gap = "   " if card else "  "
    if card and acc.active:
        text.append("   ● active", style=f"bold {palette.accent}")
    if acc.active is None:
        text.append(f"{gap}active unknown", style=palette.muted)
    if acc.details.get("disabled"):
        text.append(f"{gap}(disabled)", style=palette.muted)
    age = row.usage.age_s(now) if card and row.usage is not None else None
    # A harness re-reads only every min_interval_s; a reading that just waits
    # for its next turn is not news.
    policy = getattr(row.adapter, "usage_policy", None)
    if age is not None and age >= max(AGE_NOTE_S, getattr(policy, "min_interval_s", 0.0) + 60.0):
        text.append(f"   · {format_duration(age)} ago", style=palette.muted)
    return text


def _usage_lines(
    snap: UsageSnapshot | None, width: int, threshold: float | None, now: float, palette: Palette
) -> list[Text]:
    if snap is None:
        return [Text("measuring…", style=palette.muted)]
    lines = []
    if snap.state in _WARN:
        lines.append(Text(_warning(snap), style=palette.sev_warn))
    elif snap.state in (UsageState.UNSUPPORTED, UsageState.UNKNOWN):
        lines.append(Text(f"· {snap.detail or _state(snap)}", style=palette.muted))
    if snap.windows:
        label_width = max(len(w.name) for w in snap.windows)
        bar_width = max(12, min(30, width - 42 - label_width))
        # everything on a row except the suffix: indent, label, bar, " NNN%", gap
        room = width - (4 + label_width + 1 + bar_width + 5 + 2)
        for w in snap.windows:
            lines.append(
                usage_bar(
                    f"{w.name:<{label_width}}", w.used_percent, _reset(w, now, room), bar_width,
                    stale=snap.state in _DIM, threshold=threshold, palette=palette,
                )
            )
    elif snap.state in (UsageState.AVAILABLE, UsageState.STALE) and not snap.balance:
        lines.append(Text("usage unavailable", style=palette.muted))
    if snap.balance:
        lines.append(Text(_balance(snap.balance), style=palette.muted))
    return lines


def card_text(row: Row, width: int, *, threshold: float | None, now: float, palette: Palette) -> Text:
    """The full account card: header line plus one bar per quota window."""
    text = _header(row, now, palette, card=True)
    for line in _usage_lines(row.usage, width, threshold, now, palette):
        text.append("\n    ")
        text.append(line)
    return text


def mini_text(row: Row, now: float, palette: Palette) -> Text:
    """One line for an inactive account: ``2  b@x.com  [plus]   5h 92% · 7d 63%``.

    Percentages only, severity colored; a window at/over 100% brings its reset
    countdown along.
    """
    text = _header(row, now, palette, card=False)
    text.append("   ")
    snap = row.usage
    if snap is None:
        text.append("measuring…", style=palette.muted)
        return text
    if not snap.windows:
        if snap.state in _WARN:
            text.append(_warning(snap), style=palette.sev_warn)
        else:
            text.append(snap.detail or "usage unknown", style=palette.muted)
        return text
    for i, w in enumerate(snap.windows):
        if i:
            text.append(" · ", style=palette.track)
        text.append(f"{w.name} ", style=palette.muted)
        if w.used_percent is None:
            text.append("?", style=palette.muted)
            continue
        color = palette.severity(w.used_percent)
        text.append(f"{w.used_percent:.0f}%", style=f"{color} dim" if snap.state in _DIM else color)
        reset = _reset(w, now) if w.used_percent >= 100 else None
        if reset:
            text.append(f" ({reset})", style=palette.muted)
    if snap.state in _WARN:
        text.append(f"   ⚠ {_state(snap)}", style=palette.sev_warn)
    return text


def panel_text(
    rows: list[Row],
    width: int,
    *,
    threshold: float | None,
    now: float,
    palette: Palette,
    only: set[str] | None = None,
    show_minis: bool = True,
) -> Text:
    """Every harness: a heading, its active account(s) as full cards, the
    others as one-line minis (in place, in slot order). Harnesses with no
    account to show come last, one line each, to leave room for the rest."""
    text = Text()
    listed = [g for g in groups(rows) if only is None or g[0].id in only]
    for adapter, note, accounts in [g for g in listed if g[2]]:
        if text:
            text.append("\n\n")
        text.append(heading_text(adapter, note, palette))
        blocks = [
            card_text(r, width, threshold=threshold, now=now, palette=palette)
            if r.account.active
            else mini_text(r, now, palette)
            for r in accounts
            if r.account.active or show_minis
        ]
        if not blocks:
            blocks = [Text("no managed account is active", style=palette.muted)]
        previous_multiline = False
        for i, block in enumerate(blocks):
            multiline = "\n" in block.plain
            # breathe around the expanded active card
            text.append("\n\n" if i and (multiline or previous_multiline) else "\n")
            text.append(block)
            previous_multiline = multiline
    for i, (adapter, note, _accounts) in enumerate(g for g in listed if not g[2]):
        if text:
            text.append("\n" if i else "\n\n")
        text.append(heading_text(adapter, note, palette))
    if text:
        return text
    return Text("no harness is opted in" if only is not None else "no harnesses (see `hswap harnesses`)", style=palette.muted)


# -- widgets ------------------------------------------------------------------------------


class HarnessPanel(Static):
    """The always-visible monitor: every harness, active cards and minis.
    ``only``/``show_minis=False`` make it the auto screen's active-card strip."""

    def __init__(self, *, only: set[str] | None = None, show_minis: bool = True, id: str | None = None) -> None:
        super().__init__(id=id)
        self.only = only
        self._show_minis = show_minis

    def on_mount(self) -> None:
        self.watch(self.app, "rows", lambda _rows: self.refresh(layout=True))
        self.watch(self.app, "theme", lambda _t: self.refresh(layout=True))

    def render(self) -> Text:
        app: HswapApp = self.app  # type: ignore[assignment]
        palette = Palette.from_theme(app.current_theme)
        if app.rows is None:
            return Text("loading…", style=palette.muted)
        return panel_text(
            app.rows, (self.size.width or 80) - 2, threshold=app.threshold, now=time.time(),
            palette=palette, only=self.only, show_minis=self._show_minis,
        )


class AccountCard(Static):
    def __init__(self, row: Row) -> None:
        super().__init__()
        self.row = row

    def render(self) -> Text:
        app: HswapApp = self.app  # type: ignore[assignment]
        return card_text(
            self.row, self.size.width or 80, threshold=None, now=time.time(),
            palette=Palette.from_theme(app.current_theme),
        )


class AccountItem(ListItem):
    """ListView row wrapping an :class:`AccountCard`."""

    def __init__(self, row: Row) -> None:
        super().__init__(AccountCard(row))
        self.row = row

    @property
    def key(self) -> tuple[str, str]:
        return (self.row.adapter.id, self.row.account.key)

    def set_row(self, row: Row) -> None:
        self.row = row
        card = self.query_one(AccountCard)
        card.row = row
        card.refresh(layout=True)


class _Heading(Static):
    def __init__(self, adapter: Any, note: str) -> None:
        super().__init__()
        self.adapter, self.note = adapter, note

    def render(self) -> Text:
        return heading_text(self.adapter, self.note, Palette.from_theme(self.app.current_theme))


class HeadingItem(ListItem):
    """A harness's name above its accounts; disabled, so the cursor skips it."""

    def __init__(self, adapter: Any, note: str, *, above_accounts: bool) -> None:
        # Right above its cards; a harness with none keeps the gap to the next one.
        super().__init__(_Heading(adapter, note), disabled=True, classes="harness-heading" if above_accounts else "")

    def set_heading(self, adapter: Any, note: str) -> None:
        heading = self.query_one(_Heading)
        heading.adapter, heading.note = adapter, note
        heading.refresh(layout=True)


# -- dashboard ------------------------------------------------------------------------------


class PanelScroll(VerticalScroll, can_focus=False):
    """The panel's frame: scrolls (PgUp/PgDn, the wheel) once the harnesses
    outgrow it. Never focused, so the arrow keys always drive the menu."""

    def on_resize(self) -> None:
        self.screen.refresh_bindings()  # the footer offers PgDn only while it scrolls


class DashboardScreen(Screen):
    """Account overview on top, a nested action menu below (the arrow keys
    drive the menu). Anything account-targeted opens a context of its own."""

    BINDINGS: ClassVar = [
        Binding("s", "open_switch", "Switch accounts"),
        Binding("w", "app.open_watch", "Watch"),
        Binding("escape,left", "menu_back", "Back", show=False),
        Binding("q", "app.quit", "Quit"),
        # Power shortcuts; the menu is the discoverable path.
        Binding("g", "app.open_auto", "Auto view", show=False),
        Binding("f", "app.refresh_full", "Refresh usage", show=False),
        Binding("j", "cursor_down", show=False),
        Binding("k", "cursor_up", show=False),
        # priority: the menu (a scrollable ListView) binds these keys too
        Binding("pagedown", "panel_scroll(1)", "More accounts", priority=True),
        Binding("pageup", "panel_scroll(-1)", show=False, priority=True),
    ]

    app: HswapApp

    def __init__(self) -> None:
        super().__init__()
        # Stack of (title, entries); depth 1 = root menu.
        self._menu_stack: list[tuple[str, MenuEntries]] = []
        self._remove_rows: list[Row] = []

    def compose(self) -> ComposeResult:
        with PanelScroll(id="panel-scroll"):  # many harnesses: the panel scrolls, the menu stays
            yield HarnessPanel(id="accounts-panel")
        yield Static("", id="menu-title")
        yield ListView(id="menu")
        yield Footer()

    async def on_mount(self) -> None:
        self.query_one("#menu", ListView).focus()
        await self._push_menu("menu", self._root_entries())

    # -- menu plumbing --------------------------------------------------------

    def _root_entries(self) -> MenuEntries:
        # No "Refresh" entry: every view auto-refreshes; `f` stays as a hidden
        # escape hatch.
        return [
            ("Switch account…", "switch"),
            ("Watch accounts", "watch"),
            ("Auto-switch view", "auto"),
            ("Add account…", "add-menu"),
            ("Remove account…", "remove-menu"),
            ("Theme…", "theme-menu"),
            ("Quit", "quit"),
        ]

    def _add_entries(self) -> MenuEntries:
        if self.app.addable is None:
            return [("checking harnesses…", "back")]
        entries: MenuEntries = [
            (f"From current {adapter.display_name} login", f"add:{adapter.id}") for adapter in self.app.addable
        ]
        entries.append(_BACK)
        return entries

    def _remove_entries(self) -> MenuEntries:
        self._remove_rows = [r for r in self.app.rows or () if r.account is not None]
        width = max((len(r.adapter.display_name) for r in self._remove_rows), default=0)
        entries: MenuEntries = []
        for i, row in enumerate(self._remove_rows):
            acc = row.account
            name = f"{acc.alias} ({acc.label})" if acc.alias else acc.label
            tag = _tag(row)
            slot = "-" if acc.slot is None else acc.slot
            entries.append(
                (f"{row.adapter.display_name:<{width}}  {slot:>2}  {name}" + (f"  [{tag}]" if tag else ""), f"remove:{i}")
            )
        entries.append(_BACK)
        return entries

    def _theme_entries(self) -> MenuEntries:
        """dark / light / auto, with the active setting marked."""
        current = self.app._theme_name
        entries: MenuEntries = [
            (f"{'●' if name == current else ' '} {name}", f"theme:{name}") for name in ("dark", "light", "auto")
        ]
        entries.append(_BACK)
        return entries

    async def _push_menu(self, title: str, entries: MenuEntries) -> None:
        self._menu_stack.append((title, entries))
        await self._render_menu()

    async def _pop_menu(self) -> None:
        if len(self._menu_stack) > 1:
            self._menu_stack.pop()
            await self._render_menu()

    async def _render_menu(self) -> None:
        _title, entries = self._menu_stack[-1]
        self.query_one("#menu-title", Static).update(" › ".join(t for t, _ in self._menu_stack))
        menu = self.query_one("#menu", ListView)
        await menu.clear()
        await menu.extend(MenuItem(label, action_id, muted=(action_id == "back")) for label, action_id in entries)
        menu.index = 0
        self._fit_panel()

    def on_resize(self) -> None:
        self._fit_panel()

    def _fit_panel(self) -> None:
        """The whole menu stays on screen; the panel gets the rest and scrolls past it."""
        if self._menu_stack:
            # menu title (with its margin), menu top padding, footer
            room = self.size.height - len(self._menu_stack[-1][1]) - 4
            self.query_one(PanelScroll).styles.max_height = max(4, room)

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "panel_scroll":
            scroll = self.query(PanelScroll)
            return bool(scroll) and scroll.first().max_scroll_y > 0
        return True

    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, MenuItem):
            await self._dispatch(event.item.action_id)

    async def _dispatch(self, action_id: str) -> None:
        app = self.app
        kind, _, arg = action_id.partition(":")
        if action_id == "back":
            await self._pop_menu()
        elif action_id == "switch":
            self.action_open_switch()
        elif action_id == "watch":
            app.action_open_watch()
        elif action_id == "auto":
            app.action_open_auto()
        elif action_id == "quit":
            app.exit()
        elif action_id == "add-menu":
            await self._push_menu("add account", self._add_entries())
        elif kind == "add":
            adapter = next((a for a in app.addable or () if a.id == arg), None)
            if adapter is not None:
                app.confirm_add(adapter)
        elif action_id == "remove-menu":
            await self._push_menu("remove account", self._remove_entries())
        elif kind == "remove":
            app.confirm_remove(self._remove_rows[int(arg)])
        elif action_id == "theme-menu":
            await self._push_menu("theme", self._theme_entries())
        elif kind == "theme":
            app.apply_theme(arg)
            app.notify(f"Theme: {arg}")
            await self._pop_menu()

    # -- actions ----------------------------------------------------------------

    def action_open_switch(self) -> None:
        if not isinstance(self.app.screen, SwitchScreen):
            self.app.push_screen(SwitchScreen())

    async def action_menu_back(self) -> None:
        await self._pop_menu()

    def action_cursor_down(self) -> None:
        self.query_one("#menu", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#menu", ListView).action_cursor_up()

    def action_panel_scroll(self, direction: int) -> None:
        scroll = self.query_one(PanelScroll)
        (scroll.scroll_page_down if direction > 0 else scroll.scroll_page_up)(animate=False)


# -- switch / watch ------------------------------------------------------------------------


class AccountListScreen(Screen):
    """A live ListView of every account as a full card, under a non-selectable
    heading per harness. Subclasses decide what the cursor does."""

    app: HswapApp

    def __init__(self) -> None:
        super().__init__()
        self._keys: list[tuple[str, str | None]] = []  # (harness id, account key | None for a heading)
        self._rows: list[Row | None] = []  # aligned with _keys; None for a heading
        self._stamps: dict[tuple[str, str], float | None] = {}
        self._placed: tuple[str, str | None] | None = None  # where the cursor was put, not moved by the user

    def compose(self) -> ComposeResult:
        yield Static("", id="list-title")
        yield ListView(id="accounts")
        yield Footer()

    def on_mount(self) -> None:
        self.watch(self.app, "rows", self._on_rows)

    async def _on_rows(self, rows: list[Row] | None) -> None:
        if rows is None:
            return
        listview = self.query_one("#accounts", ListView)
        flat: list[tuple[tuple[str, str | None], Any, Row | None, str, bool]] = []
        for adapter, note, accounts in groups(rows):
            flat.append(((adapter.id, None), adapter, None, note, bool(accounts)))
            flat += [((adapter.id, r.account.key), adapter, r, "", False) for r in accounts]
        keys = [key for key, *_ in flat]
        if keys != self._keys:
            previous, previous_index = self._highlighted_key(listview), listview.index
            await listview.clear()
            await listview.extend(
                AccountItem(row) if row is not None else HeadingItem(adapter, note, above_accounts=tight)
                for _k, adapter, row, note, tight in flat
            )
            self._keys, self._rows = keys, [row for _k, _a, row, _n, _t in flat]
            listview.index = self._index_after_build(previous, previous_index)
        else:
            self._rows = [row for _k, _a, row, _n, _t in flat]
            for item, (_k, adapter, row, note, _t) in zip(listview.children, flat, strict=False):
                if isinstance(item, AccountItem) and row is not None:
                    item.set_row(row)
                elif isinstance(item, HeadingItem):
                    item.set_heading(adapter, note)
        self._flash_updated(rows, listview)

    def _highlighted_key(self, listview: ListView) -> tuple[str, str | None] | None:
        index = listview.index
        return self._keys[index] if index is not None and 0 <= index < len(self._keys) else None

    def _index_after_build(self, previous: tuple[str, str | None] | None, previous_index: int | None) -> int | None:
        """Where the cursor lands after the list is (re)built: on the active
        account until the user moves it (harnesses arrive one by one), then on
        the same account wherever it moved."""
        if previous is None or previous == self._placed:
            index = self._active_index()
            self._placed = self._keys[index] if index is not None else None
            return index
        if previous in self._keys:
            return self._keys.index(previous)
        return self._account_near(previous_index or 0)

    def _active_index(self) -> int | None:
        accounts = [i for i, row in enumerate(self._rows) if row is not None]
        return next((i for i in accounts if self._rows[i].account.active), accounts[0] if accounts else None)

    def _account_near(self, index: int) -> int | None:
        accounts = [i for i, row in enumerate(self._rows) if row is not None]
        return next((i for i in accounts if i >= index), accounts[-1] if accounts else None)

    def _flash_updated(self, rows: list[Row], listview: ListView) -> None:
        """Briefly highlight rows whose measurement just advanced."""
        stamps = {
            (r.adapter.id, r.account.key): r.usage.measured_at
            for r in rows
            if r.account is not None and r.usage is not None
        }
        if self._stamps:
            changed = {key for key, ts in stamps.items() if ts is not None and ts != self._stamps.get(key)}
            for item in listview.query(AccountItem):
                if item.key in changed and not item.has_class("flash"):
                    item.add_class("flash")
                    self.set_timer(FLASH_S, partial(item.remove_class, "flash"))
        self._stamps = stamps

    def _highlighted_row(self) -> Row | None:
        item = self.query_one("#accounts", ListView).highlighted_child
        return item.row if isinstance(item, AccountItem) else None

    def action_cursor_down(self) -> None:
        self.query_one("#accounts", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#accounts", ListView).action_cursor_up()


class SwitchScreen(AccountListScreen):
    """All accounts, full-size and alive: arrows pick, Enter switches."""

    BINDINGS: ClassVar = [
        # priority: outranks the focused ListView's own (hidden) enter binding
        # so "Switch" is visible in the footer; the action delegates right back
        # to the list cursor, so behavior is identical.
        Binding("enter", "select_highlighted", "Switch", priority=True),
        Binding("b", "best_pick", "Best in harness"),
        Binding("escape,q,s", "back", "Back"),
        Binding("j", "cursor_down", show=False),
        Binding("k", "cursor_up", show=False),
    ]

    def on_mount(self) -> None:
        self.query_one("#list-title", Static).update("switch to which account?")
        self.query_one("#accounts", ListView).focus()
        super().on_mount()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, AccountItem):
            self.app.do_switch(event.item.row)
            self.app.pop_screen()

    def action_select_highlighted(self) -> None:
        listview = self.query_one("#accounts", ListView)
        if listview.display:
            listview.action_select_cursor()

    def action_best_pick(self) -> None:
        row = self._highlighted_row()
        if row is not None:
            self.app.switch_best(row)

    def action_back(self) -> None:
        self.app.pop_screen()


class WatchScreen(AccountListScreen):
    """Live monitor of every account, full detail, hands-off by default.

    ``s`` arms selection (cursor appears on the active account); Enter then
    switches and stays here. Esc disarms selection first, then leaves.
    """

    # Nothing focused until `s` arms selection: the arrows scroll the list
    # instead of moving a hidden cursor.
    AUTO_FOCUS = ""

    _WATCH_TITLE = "watching all accounts"
    _SELECT_TITLE = "switch to which account? · enter confirm · esc cancel"

    BINDINGS: ClassVar = [
        Binding("s", "toggle_select", "Switch"),
        Binding("enter", "select_highlighted", "Confirm", priority=True),
        Binding("f", "app.refresh_full", "Refresh", show=False),
        Binding("escape,q", "back", "Back"),
        Binding("down,j", "nav_down", show=False),
        Binding("up,k", "nav_up", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._armed = False

    def on_mount(self) -> None:
        self.watch(self.app, "refresh_status", self._on_refresh_status)
        self.query_one("#list-title", Static).update(self._title_text())
        super().on_mount()

    def _title_text(self) -> str:
        if self._armed:
            return self._SELECT_TITLE
        status = self.app.refresh_status
        return f"{self._WATCH_TITLE} · {status}" if status else self._WATCH_TITLE

    def _on_refresh_status(self, _status: str) -> None:
        if not self._armed:
            self.query_one("#list-title", Static).update(self._title_text())

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        # hidden and inert until selection is armed
        return action != "select_highlighted" or self._armed

    def _index_after_build(self, previous: tuple[str, str | None] | None, previous_index: int | None) -> int | None:
        if not self._armed:
            return None  # monitor mode: no cursor at all
        return super()._index_after_build(previous, previous_index)

    def _set_selecting(self, on: bool) -> None:
        self._armed = on
        listview = self.query_one("#accounts", ListView)
        title = self.query_one("#list-title", Static)
        if on:
            listview.index = self._active_index()
            listview.focus()
            title.update(self._SELECT_TITLE)
        else:
            listview.index = None
            self.set_focus(None)
            title.update(self._title_text())
        self.refresh_bindings()

    def action_toggle_select(self) -> None:
        self._set_selecting(not self._armed)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if self._armed and isinstance(event.item, AccountItem):
            self.app.do_switch(event.item.row)
            self._set_selecting(False)  # stay here, keep watching

    def action_select_highlighted(self) -> None:
        if self._armed:
            self.query_one("#accounts", ListView).action_select_cursor()

    def action_back(self) -> None:
        if self._armed:
            self._set_selecting(False)
        else:
            self.app.pop_screen()

    def action_nav_down(self) -> None:
        listview = self.query_one("#accounts", ListView)
        if self._armed:
            listview.action_cursor_down()
        else:
            listview.scroll_down(animate=False)

    def action_nav_up(self) -> None:
        listview = self.query_one("#accounts", ListView)
        if self._armed:
            listview.action_cursor_up()
        else:
            listview.scroll_up(animate=False)


# -- automatic switching ----------------------------------------------------------------------

_EVENT_ROLES = {"switch": "accent", "would-switch": "foreground"}  # anything else is muted
_LIMITS = (50.0, 99.9)  # rotation.threshold's accepted range


class AutoScreen(Screen):
    """Automatic switching for the opted-in harnesses (``auto.enabled``), visualised.

    Runs one :func:`autorotate.run_once` pass per opted-in harness on open and
    every minute, and logs its decisions. Opens in **dry-run**: opening a view
    must never start switching accounts on its own; going live is an explicit,
    confirmed action. ``t`` then ←/→ adjusts the threshold for this session
    only (never written to the settings).
    """

    BINDINGS: ClassVar = [
        Binding("l", "toggle_live", "Go live / dry-run"),
        Binding("t", "adjust_threshold", "Threshold"),
        Binding("left", "threshold_step(-1)", "-1%"),
        Binding("right", "threshold_step(1)", "+1%"),
        Binding("enter", "adjust_done", "Done"),
        Binding("escape,q", "back", "Back"),
    ]

    PASS_INTERVAL_S = 60.0

    app: HswapApp

    def __init__(self) -> None:
        super().__init__()
        values = settings.load()
        self._enabled: list[str] = values["auto.enabled"]
        self._cooldown: float = values["auto.cooldown"]
        self._configured: float = values["rotation.threshold"]
        self._threshold = self._configured
        self._entry_threshold = self._configured
        self._adjusting = False
        self._live = False
        self._pass_running = False
        self._reported: set[str] = set()  # harnesses whose "cannot run" was logged already

    def compose(self) -> ComposeResult:
        yield HarnessPanel(only=set(self._enabled), show_minis=False, id="auto-active-panel")
        with Vertical(id="auto-top"):
            with Horizontal(id="auto-title-row"):
                yield Static(" DRY-RUN ", id="mode-badge", classes="dry")
                yield Static("", id="auto-summary")
            yield Static("", id="candidates")
        yield RichLog(id="event-log", highlight=False, markup=False, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        self.app.threshold = self._threshold  # bars and passes agree on the file value
        self._update_summary()
        self.watch(self.app, "rows", lambda _rows: self._update_opt_in())
        self.watch(self.app, "theme", lambda _t: (self._update_summary(), self._update_opt_in()))
        self._log("— DRY-RUN (watching only) —")
        if not self._enabled:
            self._log("— no harness is opted in to automatic switching —")
        self._run_pass()
        self.set_interval(self.PASS_INTERVAL_S, self._run_pass)

    def on_unmount(self) -> None:
        # A session threshold must not outlive this view: the bar ticks go
        # back to the file value.
        self.app.threshold = self._configured

    def _palette(self) -> Palette:
        return Palette.from_theme(self.app.current_theme)

    def _log(self, message: str, role: str = "muted") -> None:
        palette = self._palette()
        text = Text()
        text.append(f"{clock_stamp()}  ", style=palette.muted)
        text.append(message, style=getattr(palette, role))
        self.query_one("#event-log", RichLog).write(text)

    def action_back(self) -> None:
        if self._adjusting:
            self._end_adjust()
            return
        self.app.pop_screen()

    # -- passes ---------------------------------------------------------------

    def _run_pass(self) -> None:
        if self._pass_running or not self._enabled:
            return
        self._pass_running = True
        self.run_worker(
            partial(self._pass_blocking, self._live, self._threshold),
            thread=True,
            group="auto",
            exit_on_error=False,
            name="auto-pass",
        )

    def _pass_blocking(self, live: bool, threshold: float) -> None:
        results: list[tuple[str, str, list[dict] | Exception]] = []
        for harness_id in self._enabled:
            name = harness_id
            try:
                adapter = self.app.registry.get(harness_id)
                name = adapter.display_name
                events = autorotate.run_once(
                    adapter, self.app.usage_service, threshold=threshold, cooldown_s=self._cooldown, dry_run=not live
                )
                results.append((harness_id, name, events))
            except Exception as exc:  # noqa: BLE001 - logged; one harness must not stop the others
                results.append((harness_id, name, exc))
        self.app.from_thread(self._pass_done, results)

    def _pass_done(self, results: list[tuple[str, str, list[dict] | Exception]]) -> None:
        self._pass_running = False
        if not self.is_attached:
            return
        switched = False
        for harness_id, name, outcome in results:
            if isinstance(outcome, Exception):
                if isinstance(outcome, UnsupportedOperation | HarnessNotFound):
                    if harness_id in self._reported:
                        continue  # said once; it will not fix itself mid-session
                    self._reported.add(harness_id)
                detail = str(outcome) if isinstance(outcome, HswapError) else f"{type(outcome).__name__}: {outcome}"
                self._log(f"{name}: {detail}", "sev_warn")
                continue
            for event in outcome:
                target = f" -> {event['target']['label']}" if "target" in event else ""
                self._log(f"{name}: {event['action']}{target} ({event['reason']})", _EVENT_ROLES.get(event["action"], "muted"))
                switched = switched or event["action"] == "switch"
        if switched:
            self.app.request_refresh()

    # -- live / dry-run ---------------------------------------------------------

    def action_toggle_live(self) -> None:
        if self._live:
            self._set_live(False)
            return
        self.app.push_screen(
            ConfirmModal(
                "Go live? hswap will switch the active account of each opted-in "
                "harness automatically when it reaches the threshold.\n\n"
                "(Same behavior as running `hswap <harness> auto` in a terminal.)",
                title="Go live",
                yes_label="Go live",
            ),
            lambda confirmed: self._set_live(True) if confirmed else None,
        )

    def _set_live(self, live: bool) -> None:
        self._live = live
        badge = self.query_one("#mode-badge", Static)
        badge.update(" LIVE " if live else " DRY-RUN ")
        badge.set_classes("live" if live else "dry")
        self._log("— LIVE (will switch accounts) —" if live else "— DRY-RUN (watching only) —")
        self._run_pass()

    # -- threshold adjust mode ------------------------------------------------

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        # hidden and inert until adjust mode is armed
        return action not in ("threshold_step", "adjust_done") or self._adjusting

    def action_adjust_threshold(self) -> None:
        if self._adjusting:
            self._end_adjust()
            return
        self._adjusting = True
        self._entry_threshold = self._threshold
        self._update_summary()
        self.refresh_bindings()

    def action_adjust_done(self) -> None:
        if self._adjusting:
            self._end_adjust()

    def action_threshold_step(self, delta: float) -> None:
        if not self._adjusting:
            return
        value = min(_LIMITS[1], max(_LIMITS[0], self._threshold + delta))
        if value != self._threshold:
            self._threshold = value
            self.app.threshold = value
            self.query_one("#auto-active-panel", HarnessPanel).refresh(layout=True)
            self._update_summary()

    def _end_adjust(self) -> None:
        self._adjusting = False
        self._update_summary()
        self.refresh_bindings()
        if self._threshold == self._entry_threshold:
            return  # no net change: nothing to announce
        self._log(f"— threshold set to {self._threshold:g}% for this session —")
        self._run_pass()

    # -- summary ----------------------------------------------------------------

    def _update_summary(self) -> None:
        palette = self._palette()
        text = Text()
        text.append("auto-switch · ")
        text.append(f"threshold {self._threshold:g}%", style=palette.accent if self._adjusting else "")
        if self._threshold != self._configured:
            text.append(" (session)", style=palette.muted)
        text.append(f" · cooldown {format_duration(self._cooldown)}")
        if self._adjusting:
            text.append("   ← → adjust · enter done", style=palette.muted)
        self.query_one("#auto-summary", Static).update(text)

    def _update_opt_in(self) -> None:
        palette = self._palette()
        names = {r.adapter.id: r.adapter.display_name for r in self.app.rows or ()}
        off = [name for harness_id, name in names.items() if harness_id not in self._enabled]
        text = Text()
        text.append("opted in  ", style=palette.muted)
        text.append(", ".join(names.get(i, i) for i in self._enabled) or "none", style=palette.foreground)
        if off:
            text.append("\nnot opted in  ", style=palette.muted)
            text.append(", ".join(off), style=palette.foreground)
            text.append(
                "\nopt in with `hswap config set auto.enabled <ids>` (list the ones already on too)",
                style=palette.muted,
            )
        self.query_one("#candidates", Static).update(text)
