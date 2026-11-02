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
                                 "active": [Account("nat", "i1", "n@x", "p", 1, active=True).to_json()]}]
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
        output.emit_json({"x": "sk-proj-abcdefghijklmnopqrstuvwxyz"})
    output.emit_json({"identity": "user-abcdefghijklmnopqrstuvwxyz/acct-0123456789"})
    assert "user-abc" in capsys.readouterr().out


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


def test_migrate_with_nothing_to_do(homes, capsys):
    reg, _ = homes
    code, out, _ = run(reg, capsys, "migrate", "--dry-run")
    assert code == 0 and "Nothing to migrate" in out


@pytest.mark.asyncio
async def test_dashboard_renders_and_switches(homes):
    from textual.widgets import DataTable, Static

    from harness_swap.ui.tui import build_app

    reg, tmp = homes
    for email, user in (("a@x.com", "user-a"), ("b@x.com", "user-b")):
        write_json(tmp / "codex" / "auth.json", codex_auth(email, user, f"acct-{user}"))
        cli.run(["codex", "add"], reg)
    app = build_app(reg)
    async with app.run_test() as pilot:
        await app.workers.wait_for_complete()
        await pilot.pause()
        table = app.query_one(DataTable)
        labels = [str(table.get_row_at(i)[3]) for i in range(table.row_count)]
        assert "a@x.com" in labels and "b@x.com" in labels
        assert any("not installed" in str(table.get_row_at(i)[5]) or str(table.get_row_at(i)[0]) == "Grok Build"
                   for i in range(table.row_count))
        table.move_cursor(row=labels.index("a@x.com"))
        await pilot.press("s")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "now a@x.com" in str(app.query_one("#status", Static).render())
    assert json.loads((tmp / "codex" / "auth.json").read_text())["tokens"]["account_id"] == "acct-user-a"
