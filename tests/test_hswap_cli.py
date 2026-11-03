"""hswap CLI: dispatch, JSON contracts, confirmations, and no secrets in output."""

from __future__ import annotations

import json

import pytest

from harness_swap import cli, output
from harness_swap.core.models import Account, Installation, supported
from harness_swap.core.registry import Registry
from tests.hswap_helpers import codex_auth, grok_entry, write_json


class Native:
    """An adapter with its own full command line."""

    id = "nat"
    display_name = "Native"
    providers = ("p",)

    def __init__(self):
        self.calls = []

    def installation(self):
        return Installation(True, "/bin/nat", "9.9")

    def capabilities(self):
        return {}

    def list_accounts(self):
        return [Account("nat", "i1", "n@x", "p", 1, active=True)]

    def run_cli(self, argv):
        self.calls.append(argv)
        return 7


def run(registry, capsys, *argv):
    code = cli.run(list(argv), registry)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_quiet(registry, *argv):
    """`hswap` output without pytest's capture (for use inside a running app)."""
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        cli.run(list(argv), registry)
    return buf.getvalue()


@pytest.fixture
def native():
    adapter = Native()
    reg = Registry(discover_plugins=False)
    reg.register("nat", lambda: adapter)
    return reg, adapter


def test_native_command_line_receives_argv_verbatim(native, capsys):
    reg, adapter = native
    assert run(reg, capsys, "nat", "list", "--weird-flag", "--", "x")[0] == 7
    assert adapter.calls == [["list", "--weird-flag", "--", "x"]]


def test_unknown_harness_is_a_clean_error(native, capsys):
    reg, _ = native
    code, out, err = run(reg, capsys, "nope", "list")
    assert code == 1 and "unknown harness 'nope'" in err and "nat" in err
    code, out, err = run(reg, capsys, "status", "nope", "--json")
    assert code == 1 and json.loads(out)["error"]["type"] == "HarnessNotFound"


def test_help_and_version_without_a_terminal(native, capsys, monkeypatch):
    reg, _ = native
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code, out, _ = run(reg, capsys)
    assert code == 0 and "Per harness (nat)" in out
    assert run(reg, capsys, "--version")[1].startswith("hswap ")


def test_status_and_harnesses_json(native, capsys):
    reg, _ = native
    doc = json.loads(run(reg, capsys, "status", "--json")[1])
    assert doc["schemaVersion"] == 1
    assert doc["harnesses"] == [{"harness": "nat", "installed": True, "version": "9.9",
                                 "active": [Account("nat", "i1", "n@x", "p", 1, active=True).to_json()],
                                 "activeKnown": True}]
    assert doc["errors"] == {}
    doc = json.loads(run(reg, capsys, "harnesses", "--json")[1])
    assert doc["harnesses"][0]["id"] == "nat"


def test_capabilities_lists_every_capability_with_reasons(native, capsys):
    reg, adapter = native
    adapter.capabilities = lambda: {"account_list": supported("yes")}
    out = run(reg, capsys, "capabilities", "nat")[1]
    assert "account_list" in out and "automatic_rotation" in out and "unsupported" in out


def test_emit_json_refuses_credential_shaped_text(capsys):
    with pytest.raises(output.SecretLeak):
        output.emit_json({"x": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4eHh4eHgifQ.sig"})
    with pytest.raises(output.SecretLeak):
        output.emit_json({"x": "sk-proj-Ab3dEfGh1jKlMn0pQrStUvWxYz12"})
    # ordinary names that merely start like a key prefix are fine
    output.emit_json({
        "identity": "user-abcdefghijklmnopqrstuvwxyz/acct-0123456789",
        "labels": ["rt-notifications-team@corp.com", "sess-shared-account-1@x.io", "sk-personal-account"],
    })
    assert "rt-notifications-team" in capsys.readouterr().out


def test_alias_and_config_mistakes_are_clean_errors(native, capsys, tmp_path, monkeypatch):
    reg, _ = native
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "h"))
    code, _out, err = run(reg, capsys, "config", "get", "nope")
    assert code == 1 and "unknown setting" in err and "Traceback" not in err
    code, _out, err = run(reg, capsys, "config", "unset", "nope")
    assert code == 1 and "unknown setting" in err


# -- end to end through the real built-in adapters, on synthetic homes ---------------------------


@pytest.fixture
def homes(tmp_path, monkeypatch):
    for name, sub in (("CODEX_HOME", "codex"), ("GROK_HOME", "grok"), ("HSWAP_HOME", "hswap")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(name, str(tmp_path / sub))
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [])
    monkeypatch.setattr(
        "harness_swap.adapters.base.probe_installation",
        lambda exe, args=("--version",): Installation(True, f"/fake/{exe}", "1.0.0"),
    )
    monkeypatch.setattr("harness_swap.adapters.codex.CodexAdapter._has_no_daemon_flag", lambda self: True)
    reg = Registry({"codex": "harness_swap.adapters.codex:CodexAdapter",
                    "grok": "harness_swap.adapters.grok:GrokAdapter"}, discover_plugins=False)
    return reg, tmp_path


def test_no_credential_material_reaches_any_output(homes, capsys):
    reg, tmp = homes
    write_json(tmp / "codex" / "auth.json", codex_auth("a@x.com", "user-a", "acct-a", refresh="SECRETREFRESH"))
    write_json(tmp / "grok" / "auth.json", {"https://auth.example::c": grok_entry("g@x.com", "user-g", key="SECRETGROKKEY")})
    assert run(reg, capsys, "codex", "add")[0] == 0
    assert run(reg, capsys, "grok", "add")[0] == 0
    write_json(tmp / "codex" / "auth.json", codex_auth("b@x.com", "user-b", "acct-b", refresh="SECRETB"))
    run(reg, capsys, "codex", "add")
    texts = []
    for argv in (
        ["list", "--json"], ["list"], ["status", "--json"], ["doctor", "--json"], ["capabilities", "--json"],
        ["codex", "list", "--json"], ["codex", "usage", "--json"], ["codex", "switch", "1", "--json"],
        ["grok", "list"], ["codex", "status"],
    ):
        _code, out, err = run(reg, capsys, *argv)
        texts.append(out + err)
    blob = "\n".join(texts)
    for secret in ("SECRETREFRESH", "SECRETGROKKEY", "SECRETB", "eyJ"):
        assert secret not in blob
    assert "a@x.com" in blob and "g@x.com" in blob


def test_alias_collisions_are_clean_errors(homes, capsys):
    reg, tmp = homes
    for user in ("a", "b"):
        write_json(tmp / "codex" / "auth.json", codex_auth(f"{user}@x.com", f"user-{user}", f"acct-{user}"))
        run(reg, capsys, "codex", "add")
    assert run(reg, capsys, "codex", "alias", "1", "work")[0] == 0
    code, _, err = run(reg, capsys, "codex", "alias", "2", "work")
    assert code == 1 and "already used by slot 1" in err
    code, _, err = run(reg, capsys, "codex", "alias", "2", "123")
    assert code == 1 and "numeric" in err


def test_remove_needs_confirmation_or_yes(homes, capsys, monkeypatch):
    reg, tmp = homes
    write_json(tmp / "codex" / "auth.json", codex_auth("a@x.com", "user-a", "acct-a"))
    run(reg, capsys, "codex", "add")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code, _, err = run(reg, capsys, "codex", "remove", "1")
    assert code == 1 and "--yes" in err
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert run(reg, capsys, "codex", "remove", "1")[0] == 1
    assert run(reg, capsys, "codex", "remove", "1", "--yes")[0] == 0
    assert json.loads(run(reg, capsys, "codex", "list", "--json", "--no-usage")[1])["accounts"] == []
    # the live login is not touched by forgetting hswap's copy
    assert json.loads((tmp / "codex" / "auth.json").read_text())["tokens"]["account_id"] == "acct-a"


def test_failed_switch_keeps_the_original_login(homes, capsys):
    reg, tmp = homes
    write_json(tmp / "codex" / "auth.json", codex_auth("a@x.com", "user-a", "acct-a"))
    run(reg, capsys, "codex", "add")
    write_json(tmp / "codex" / "auth.json", codex_auth("stranger@x.com", "user-s", "acct-s"))
    before = (tmp / "codex" / "auth.json").read_bytes()
    code, _, err = run(reg, capsys, "codex", "switch", "1")
    assert code == 1 and "not stored by hswap" in err
    assert (tmp / "codex" / "auth.json").read_bytes() == before


def test_config_round_trip(homes, capsys):
    reg, _ = homes
    assert run(reg, capsys, "config", "set", "rotation.threshold", "80")[0] == 0
    assert run(reg, capsys, "config", "get", "rotation.threshold")[1].strip() == "80.0"
    code, _, err = run(reg, capsys, "config", "set", "rotation.threshold", "20")
    assert code == 1 and "between" in err
    code, _, err = run(reg, capsys, "config", "set", "nope", "1")
    assert code == 1 and "unknown setting" in err
    assert run(reg, capsys, "config", "unset", "rotation.threshold")[0] == 0
    assert run(reg, capsys, "config", "get", "rotation.threshold")[1].strip() == "95.0"


def test_harness_opt_ins_name_known_harnesses_and_their_terms(homes, capsys):
    reg, _ = homes
    code, _, err = run(reg, capsys, "config", "set", "usage.remote", "codex,bogus")
    assert code == 1 and "unknown harness bogus" in err
    assert run(reg, capsys, "config", "get", "usage.remote")[1].strip() == ""
    code, _, err = run(reg, capsys, "config", "set", "usage.remote", "codex")
    assert code == 0 and "never calls a provider API or refreshes a token" in err
    assert "note: codex terms: OpenAI" in err
    code, _, err = run(reg, capsys, "config", "set", "auto.enabled", "codex,grok")
    assert code == 0 and "note: codex terms:" in err and "note: grok terms: xAI" in err
    code, _, err = run(reg, capsys, "config", "set", "auto.enabled", "grok")
    assert code == 0 and "note" not in err  # nothing newly enabled


def test_an_unknown_provider_is_refused(homes, capsys):
    reg, _ = homes
    code, _, err = run(reg, capsys, "codex", "refresh", "--provider", "foo")
    assert code == 1 and "codex has no provider 'foo'; known: openai" in err


def test_migrate_with_nothing_to_do(homes, capsys):
    reg, _ = homes
    code, out, _ = run(reg, capsys, "migrate", "--dry-run")
    assert code == 0 and "Nothing to migrate" in out


def _codex_accounts(reg, tmp, *users):
    """Add one synthetic Codex login per user; the last one stays the live login."""
    for user in users:
        write_json(tmp / "codex" / "auth.json", codex_auth(f"{user}@x.com", f"user-{user}", f"acct-user-{user}"))
        cli.run(["codex", "add"], reg)


def _dashboard(reg):
    """The real `hswap tui` app, with its toasts recorded as ``(title, message)``."""
    from harness_swap.ui.tui import HswapApp

    app = HswapApp(reg)
    toasts = []
    app.notify = lambda message, title="", **_kw: toasts.append((title, message))
    return app, toasts


async def _settle(pilot):
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


def _menu_ids(app):
    from textual.widgets import ListView

    from harness_swap.ui.widgets import MenuItem

    return [item.action_id for item in app.screen.query_one("#menu", ListView).query(MenuItem)]


@pytest.mark.asyncio
async def test_dashboard_groups_accounts_by_harness_and_switches(homes):
    from textual.widgets import ListView

    from harness_swap.ui.screens import SwitchScreen

    reg, tmp = homes
    _codex_accounts(reg, tmp, "a", "b")
    app, toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        panel = app.screen.query_one("#accounts-panel").render().plain
        # a heading per harness; the active account as a full card, the other as a mini
        assert panel.index("Codex CLI") < panel.index("a@x.com") < panel.index("b@x.com") < panel.index("Grok Build")
        assert "b@x.com  [plus]   ● active" in panel and "a@x.com  [plus]   ● active" not in panel
        assert "Grok Build  no accounts · Add account…" in panel

        await pilot.press("s")
        await _settle(pilot)
        assert isinstance(app.screen, SwitchScreen)
        assert str(app.screen.query_one("#list-title").render()) == "switch to which account?"
        listview = app.screen.query_one("#accounts", ListView)
        assert listview.highlighted_child.row.account.label == "b@x.com"  # starts on the active account
        await pilot.press("up", "up")  # the harness heading above a@x.com is skipped
        assert listview.highlighted_child.row.account.label == "a@x.com"
        await pilot.press("enter")
        await _settle(pilot)
        assert not isinstance(app.screen, SwitchScreen)  # Enter switches and pops back
        assert ("Switch", "Switched Codex CLI to a@x.com") in [(t, m.splitlines()[0]) for t, m in toasts]
        assert "a@x.com  [plus]   ● active" in app.screen.query_one("#accounts-panel").render().plain
    assert json.loads((tmp / "codex" / "auth.json").read_text())["tokens"]["account_id"] == "acct-user-a"


@pytest.mark.asyncio
async def test_dashboard_never_forces_over_an_unmanaged_login(homes):
    reg, tmp = homes
    _codex_accounts(reg, tmp, "a")
    write_json(tmp / "codex" / "auth.json", codex_auth("stranger@x.com", "user-s", "acct-s"))
    before = (tmp / "codex" / "auth.json").read_bytes()
    app, toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press("s")
        await _settle(pilot)
        await pilot.press("enter")
        await _settle(pilot)
    assert any(t == "No switch" and "hswap codex switch 1 --force" in message for t, message in toasts)
    assert (tmp / "codex" / "auth.json").read_bytes() == before


@pytest.mark.asyncio
async def test_switch_outcomes_that_change_nothing_are_calm_toasts(homes):
    from harness_swap.ui.screens import SwitchScreen

    reg, tmp = homes
    _codex_accounts(reg, tmp, "a", "b")
    app, toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press("s")
        await _settle(pilot)
        await pilot.press("b")  # no usage measured: nothing qualifies, which is no failure
        await _settle(pilot)
        assert isinstance(app.screen, SwitchScreen)  # no error modal on top
        await pilot.press("enter")  # the cursor starts on the active account
        await _settle(pilot)
    assert [t for t, _m in toasts] == ["No switch", "No switch"]
    assert toasts[1][1] == "b@x.com is already the active Codex CLI account"


@pytest.mark.asyncio
async def test_dashboard_menu_nests_with_a_breadcrumb(homes):
    from textual.widgets import Static

    reg, tmp = homes
    _codex_accounts(reg, tmp, "a")
    app, _toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)

        def crumb():
            return str(app.screen.query_one("#menu-title", Static).render())

        assert crumb() == "menu"
        assert _menu_ids(app) == ["switch", "watch", "auto", "add-menu", "remove-menu", "theme-menu", "quit"]
        await pilot.press("tab")  # the panel never takes focus from the menu
        assert app.focused is app.screen.query_one("#menu")
        await pilot.press("down", "down", "down", "enter")
        await pilot.pause()
        assert crumb() == "menu › add account"
        assert _menu_ids(app) == ["add:codex", "add:grok", "back"]
        await pilot.press("escape")
        await pilot.pause()
        assert crumb() == "menu" and _menu_ids(app)[0] == "switch"


@pytest.mark.asyncio
async def test_dashboard_removes_through_the_menu_after_confirming(homes):
    from harness_swap.ui.modals import ConfirmModal

    reg, tmp = homes
    _codex_accounts(reg, tmp, "a", "b")
    app, toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press("down", "down", "down", "down", "enter")  # Remove account…
        await pilot.pause()
        assert _menu_ids(app) == ["remove:0", "remove:1", "back"]
        await pilot.press("enter")  # Codex 1 a@x.com
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        assert "Remove Codex CLI account 1 (a@x.com)?" in str(app.screen.query_one(".modal-body").render())
        await pilot.press("y")
        await _settle(pilot)
        assert ("Remove account", "Removed a@x.com from Codex CLI") in toasts
    remaining = json.loads(run_quiet(reg, "codex", "list", "--json", "--no-usage"))["accounts"]
    assert [a["label"] for a in remaining] == ["b@x.com"]


@pytest.mark.asyncio
async def test_watch_arms_selection_on_demand(homes):
    from textual.widgets import ListView

    from harness_swap.ui.screens import DashboardScreen, WatchScreen

    reg, tmp = homes
    _codex_accounts(reg, tmp, "a", "b")
    app, _toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press("w")
        await _settle(pilot)
        assert isinstance(app.screen, WatchScreen)
        listview = app.screen.query_one("#accounts", ListView)
        assert listview.index is None  # monitor mode: no cursor
        assert str(app.screen.query_one("#list-title").render()) == "watching all accounts"
        await pilot.press("down")  # scrolls; no hidden cursor moves
        assert listview.index is None
        await pilot.press("s")
        await pilot.pause()
        assert listview.highlighted_child.row.account.label == "b@x.com"  # armed on the active account
        assert str(app.screen.query_one("#list-title").render()).startswith("switch to which account?")
        await pilot.press("escape")  # disarms first
        await pilot.pause()
        assert isinstance(app.screen, WatchScreen) and listview.index is None
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)


@pytest.mark.asyncio
async def test_ctrl_t_cycles_and_persists_the_theme(homes):
    from harness_swap.core import settings

    reg, _tmp = homes
    app, _toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        assert settings.load()["ui.theme"] == "auto"
        await pilot.press("ctrl+t")
        assert app.theme == "cswap-dark" and settings.load()["ui.theme"] == "dark"
        await pilot.press("ctrl+t")
        assert app.theme == "cswap-light" and settings.load()["ui.theme"] == "light"


@pytest.mark.asyncio
async def test_auto_view_opens_dry_and_explains_a_harness_it_cannot_run_once(homes):
    from textual.widgets import RichLog

    from harness_swap.core import settings
    from harness_swap.ui.screens import AutoScreen

    reg, tmp = homes
    write_json(tmp / "grok" / "auth.json", {"https://auth.example::c": grok_entry("g@x.com", "user-g")})
    run_quiet(reg, "grok", "add")
    settings.set_value("auto.enabled", "grok")  # opted in, but grok has no live usage without usage.remote
    app, _toasts = _dashboard(reg)
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press("g")
        await _settle(pilot)
        assert isinstance(app.screen, AutoScreen)
        assert str(app.screen.query_one("#mode-badge").render()).strip() == "DRY-RUN"
        app.screen._run_pass()  # the minute timer, now
        await _settle(pilot)
        lines = [line.text for line in app.screen.query_one("#event-log", RichLog).lines]
        assert any("DRY-RUN (watching only)" in line for line in lines)
        assert sum("Grok Build: automatic_rotation" in line for line in lines) == 1


def test_dashboard_reads_harnesses_in_parallel_and_shows_each_as_it_arrives():
    import threading
    from types import SimpleNamespace

    from harness_swap.core.models import Capability, Installation, unsupported
    from harness_swap.ui.tui import LOADING, collect

    acc = Account("b", "i", "b@x", None, 1)
    b_listed = threading.Event()

    def slow_install():
        assert b_listed.wait(5), "the slow harness held back the one after it"
        return Installation(False, "a", None, "missing")

    slow = SimpleNamespace(id="a", installation=slow_install)
    fast = SimpleNamespace(
        id="b", display_name="B", providers=(), installation=lambda: Installation(True, "b", "1"),
        list_accounts=lambda: [acc], capabilities=lambda: {Capability.USAGE_MONITORING: unsupported("none")},
    )
    seen = []

    def progress(rows):
        seen.append([(r.adapter.id, r.account, r.usage, r.note) for r in rows])
        if any(r.account is not None for r in rows):
            b_listed.set()

    rows = collect(SimpleNamespace(available=lambda: [slow, fast], entries=list), progress)
    # every harness from the start, in registry order; b's account before its usage is read
    assert seen[0] == [("a", None, None, LOADING), ("b", acc, None, "")]
    assert [(r.adapter.id, r.note) for r in rows] == [("a", "not installed: missing"), ("b", "")]
    assert rows[1].usage is not None


def test_a_read_that_outlives_the_dashboard_never_waits_on_it(homes):
    """A worker handing rows to an app that has exited must not block: the
    thread would never finish and the process could not exit (a slow CI
    runner hung at exit this way)."""
    import asyncio
    import threading
    from types import SimpleNamespace

    from harness_swap.core.models import Installation
    from harness_swap.ui.tui import HswapApp

    release, finished = threading.Event(), threading.Event()

    def slow_list():
        release.wait(5)
        return [Account("x", "i", "x@x", None, 1, active=True)]

    def capabilities():  # asked once the read has handed over its rows
        finished.set()
        return {}

    adapter = SimpleNamespace(
        id="x", display_name="X", providers=(), installation=lambda: Installation(True, "x", "1"),
        list_accounts=slow_list, capabilities=capabilities,
    )
    app = HswapApp(SimpleNamespace(available=lambda: [adapter], entries=list))

    async def open_and_quit():
        async with app.run_test():
            pass

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(open_and_quit())
        release.set()  # the read ends now, with the app gone and no loop running
        assert finished.wait(5), "the worker is stuck waiting for the app"
    finally:
        loop.run_until_complete(asyncio.sleep(0.2))  # on failure: let a stuck worker go
        loop.close()


def test_switch_cursor_follows_the_active_account_until_the_user_moves_it():
    from types import SimpleNamespace as NS

    from harness_swap.ui.screens import SwitchScreen

    def row(key, active):
        return NS(account=NS(key=key, active=active))

    screen = SwitchScreen()
    screen._keys, screen._rows = [("a", None), ("b", None)], [None, None]  # every harness still loading
    assert screen._index_after_build(None, None) is None
    screen._keys = [("a", None), ("b", None), ("b", "bob"), ("b", "ann")]
    screen._rows = [None, None, row("bob", False), row("ann", True)]
    assert screen._index_after_build(None, None) == 3  # the active account, not the first one listed
    screen._keys = [("a", None), ("a", "x"), ("b", None), ("b", "bob"), ("b", "ann")]
    screen._rows = [None, row("x", False), None, row("bob", False), row("ann", True)]
    assert screen._index_after_build(("b", "ann"), 3) == 4  # a harness arriving above does not move it off
    assert screen._index_after_build(("b", "bob"), 3) == 3  # once the user picked bob, bob stays


class Crashy(Native):
    """A trusted plugin with a bug: every probe raises a non-hswap exception."""

    id = "crashy"

    def installation(self):
        raise RuntimeError("probing exploded")

    def capabilities(self):
        raise RuntimeError("probing exploded")

    def list_accounts(self):
        raise RuntimeError("probing exploded")

    run_cli = None  # use the generic verbs


@pytest.mark.parametrize("argv", [["harnesses"], ["list"], ["status"], ["capabilities"], ["doctor"]])
@pytest.mark.parametrize("as_json", [False, True])
def test_one_broken_adapter_does_not_take_down_cross_harness_commands(native, capsys, tmp_path, monkeypatch, argv, as_json):
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path))
    reg, _ = native
    reg.register("crashy", Crashy)
    code, out, err = run(reg, capsys, *argv, *(["--json"] if as_json else []))
    assert "Traceback" not in out + err
    assert "RuntimeError: probing exploded" in out + err
    if as_json:
        json.loads(out)
    assert "nat" in out or "Native" in out  # the healthy harness is still reported
    assert code == 1  # any harness that failed makes the command fail, with the rest still shown


def test_doctor_reports_a_plugin_that_fails_to_load(native, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path))
    reg, _ = native
    reg.register("boom", "tests.no_such_module:Adapter")
    code, out, _ = run(reg, capsys, "doctor")
    assert code == 1 and "[error] boom" in out and "failed to load: ModuleNotFoundError" in out
    code, out, _ = run(reg, capsys, "list", "--json")
    assert "boom" in json.loads(out)["errors"]


def test_trusting_a_plugin_prints_the_list_plainly(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path))
    reg = Registry(discover_plugins=False)
    code, out, _ = run(reg, capsys, "config", "set", "plugins.trusted", "zest@zest-hswap,b@b-pkg")
    assert code == 0 and out.strip() == "plugins.trusted = b@b-pkg,zest@zest-hswap"
    code, _, err = run(reg, capsys, "config", "set", "plugins.trusted", "zest")
    assert code == 1 and "<id>@<distribution>" in err


def test_add_reports_every_login_it_stored(homes, capsys):
    reg, tmp = homes
    write_json(tmp / "grok" / "auth.json", {
        "https://auth.example::c1": grok_entry("a@x.com", "user-a"),
        "xai::api_key": {"key": "synthetic-xai-api-key", "auth_mode": "api_key"},
    })
    code, out, _ = run(reg, capsys, "grok", "add")
    assert code == 0 and "Added a@x.com as grok slot 1" in out and "Added API key sha256:" in out
    code, out, _ = run(reg, capsys, "grok", "add")
    assert "already grok slot 1" in out


def test_status_says_when_the_active_account_is_unknown(native, capsys):
    reg, adapter = native
    adapter.list_accounts = lambda: [Account("nat", "i1", "n@x", "p", 1, active=None)]
    code, out, _ = run(reg, capsys, "status")
    assert code == 0 and "nat        active account unknown" in out
    doc = json.loads(run(reg, capsys, "status", "--json")[1])
    assert doc["harnesses"][0]["activeKnown"] is False
    adapter.list_accounts = lambda: [Account("nat", "i1", "n@x", "p", 1, alias="w", active=True, details={"disabled": True})]
    assert "n@x (w) [p] (disabled)" in run(reg, capsys, "status")[1]


def test_output_into_a_closed_pipe_is_not_an_error(monkeypatch):
    import io
    import os

    class ClosedPipe(io.StringIO):
        def write(self, text):
            raise BrokenPipeError

        def fileno(self):
            return os.open(os.devnull, os.O_WRONLY)

    monkeypatch.setattr("sys.stdout", ClosedPipe())
    monkeypatch.setattr("sys.argv", ["hswap", "--version"])
    monkeypatch.setattr(os, "dup2", lambda a, b: None)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_json_flag_may_come_first_and_config_errors_name_the_key(native, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path))
    reg, _ = native
    code, out, _ = run(reg, capsys, "--json", "status")
    assert code == 0 and json.loads(out)["harnesses"][0]["harness"] == "nat"
    code, _, err = run(reg, capsys, "config", "set", "rotation.threshold", "20")
    assert code == 1 and "rotation.threshold: must be between 50 and 99.9" in err
    code, _, err = run(reg, capsys, "config", "get")
    assert code == 1 and "usage: hswap config get KEY" in err


def test_a_broken_plugin_is_one_clean_error_line_everywhere(native, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path))
    monkeypatch.delenv("HSWAP_DEBUG", raising=False)
    reg, _ = native
    reg.register("crashy", Crashy)
    reg.register("boom", "tests.no_such_module:Adapter")
    for argv in (["crashy", "list"], ["crashy", "status"]):
        code, out, err = run(reg, capsys, *argv)
        assert code == 1 and "Traceback" not in err and "RuntimeError: probing exploded" in err
    code, out, _ = run(reg, capsys, "crashy", "list", "--json")
    assert code == 1 and json.loads(out)["error"]["type"] == "RuntimeError"
    code, out, _ = run(reg, capsys, "capabilities", "--json")
    assert code == 1 and "boom" in json.loads(out)["errors"]
    code, out, _ = run(reg, capsys, "capabilities")
    assert "boom\n  error: failed to load: ModuleNotFoundError" in out

    from harness_swap.ui.tui import collect

    assert any(adapter.id == "boom" and "failed to load" in note for adapter, _a, _u, note in collect(reg))


def test_ignored_plugins_and_old_trust_entries_are_explained(capsys, tmp_path, monkeypatch):
    from types import SimpleNamespace

    from harness_swap.core import settings

    monkeypatch.setenv("HSWAP_HOME", str(tmp_path))
    ep = SimpleNamespace(name="nat", value="x:Y", dist=SimpleNamespace(name="squatter"))
    monkeypatch.setattr("harness_swap.core.registry.entry_points", lambda group: [ep])
    settings.settings_path().write_text(json.dumps({"plugins.trusted": ["zest"]}))  # pre-<id>@<dist> format
    reg = Registry({"nat": "tests.test_hswap_cli:Native"}, trusted_plugins=set(settings.load()["plugins.trusted"]))
    code, out, err = run(reg, capsys, "harnesses")
    assert code == 0 and "note: nat: ignored: squatter declares built-in id 'nat'" in err
    code, out, _ = run(reg, capsys, "doctor")
    assert code == 0  # an ignored entry point is a warning, not a failure
    assert "[warn ] nat" in out and "plugins.trusted in" in out and "is not <id>@<distribution>" in out


def test_doctor_reports_a_corrupt_store_once(homes, capsys):
    reg, tmp = homes
    (tmp / "hswap" / "codex").mkdir()
    (tmp / "hswap" / "codex" / "accounts.json").write_text("{broken")
    code, out, _ = run(reg, capsys, "doctor")
    assert code == 1 and out.count("accounts.json is not valid JSON") == 1


def test_refresh_reports_each_account_and_fails_on_any_failure(native, capsys):
    from harness_swap.core.models import Capability

    class Keeper(Native):
        id = "keep"
        run_cli = None

        def capabilities(self):
            return {Capability.ACCOUNT_LIST: supported(), Capability.CREDENTIAL_REFRESH: supported()}

        def list_accounts(self):
            return [Account("keep", "i1", "a@x", "p", 1), Account("keep", "i2", "b@x", "p", 2)]

        def keep_alive(self, account):
            if account.slot == 2:
                raise RuntimeError("sign in again")
            return "token is fresh"

    reg, _ = native
    reg.register("keep", Keeper)
    code, out, _ = run(reg, capsys, "keep", "refresh")
    assert code == 1 and "1 a@x: token is fresh" in out and "2 b@x: RuntimeError: sign in again" in out
    code, out, _ = run(reg, capsys, "keep", "refresh", "1", "--json")
    assert code == 0 and json.loads(out)["accounts"][0]["result"] == "token is fresh"
    code, _, _ = run(reg, capsys, "nat", "list")  # Native has its own command line: untouched
    assert code == 7
