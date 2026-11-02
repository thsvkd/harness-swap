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
        assert any("not installed" in str(table.get_row_at(i)[4]) or str(table.get_row_at(i)[1]) == "Grok Build"
                   for i in range(table.row_count))
        last = table.row_count - 1  # in the last harness's rows, which arrive after a partial fill
        table.move_cursor(row=last)
        await pilot.press("r")  # a refresh keeps the highlighted row
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert table.cursor_row == last
        table.move_cursor(row=labels.index("a@x.com"))
        await pilot.press("s")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "now a@x.com" in str(app.query_one("#status", Static).render())
    assert json.loads((tmp / "codex" / "auth.json").read_text())["tokens"]["account_id"] == "acct-user-a"


def test_dashboard_shows_each_harness_as_soon_as_it_is_read():
    from types import SimpleNamespace

    from harness_swap.core.models import Installation
    from harness_swap.ui.tui import collect

    def missing(harness_id):
        return SimpleNamespace(id=harness_id, installation=lambda: Installation(False, harness_id, None, "missing"))

    seen = []
    rows = collect(SimpleNamespace(available=lambda: [missing("a"), missing("b")], entries=list), seen.append)
    assert [[r[0].id for r in partial] for partial in seen] == [["a"]]
    assert [r[0].id for r in rows] == ["a", "b"]


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
