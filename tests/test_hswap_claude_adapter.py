"""Claude adapter: engine embedding, schema-v1 normalisation, migration gate."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from harness_swap.adapters import claude as claude_adapter
from harness_swap.adapters.claude import ClaudeAdapter, usage_from_row
from harness_swap.core import accounts as service
from harness_swap.core.errors import HswapError
from harness_swap.core.models import UsageState

ROW = {
    "number": 2,
    "email": "a@x.com",
    "organizationName": "Org",
    "organizationUuid": "org-1",
    "active": True,
    "usageStatus": "ok",
    "usage": {
        "fiveHour": {"pct": 42.0, "resetsAt": "2099-01-01T00:00:00Z"},
        "sevenDay": {"pct": 10.0, "resetsAt": "2099-01-05T00:00:00Z"},
        "scoped": [{"name": "Opus", "pct": 70.0, "resetsAt": "2099-01-05T00:00:00Z"}],
        "spend": {"used": 5.0, "limit": 20.0, "pct": 25.0, "currency": "USD"},
    },
    "usageFetchedAt": "2026-11-02T00:00:00Z",
    "alias": "work",
}


class TestUsageNormalisation:
    def test_windows_and_balance(self):
        snap = usage_from_row(ROW)
        assert snap.state is UsageState.AVAILABLE
        assert [(w.name, w.used_percent) for w in snap.windows] == [("5h", 42.0), ("7d", 10.0), ("7d:Opus", 70.0)]
        assert snap.windows[0].window_seconds == 5 * 3600
        assert snap.balance == {"used": 5.0, "limit": 20.0, "currency": "USD", "pct": 25.0}
        assert snap.max_used_percent == 70.0

    @pytest.mark.parametrize(
        ("status", "state"),
        [
            ("token_expired", UsageState.UNKNOWN),
            ("relogin_required", UsageState.AUTHENTICATION_REQUIRED),
            ("no_credentials", UsageState.AUTHENTICATION_REQUIRED),
            ("api_key", UsageState.UNSUPPORTED),
            ("keychain_unavailable", UsageState.ERROR),
            ("foreign_credential", UsageState.ERROR),
            ("unavailable", UsageState.ERROR),
        ],
    )
    def test_statuses(self, status, state):
        snap = usage_from_row({"usageStatus": status, "usage": None})
        assert snap.state is state and snap.windows == ()

    def test_last_good_data_is_stale_not_current(self):
        row = {"usageStatus": "unavailable", "usage": None, "usageError": "http-429",
               "lastGoodUsage": {"fiveHour": {"pct": 12.0}}, "lastGoodFetchedAt": "2026-11-01T00:00:00Z"}
        snap = usage_from_row(row)
        assert snap.state is UsageState.STALE and snap.windows[0].used_percent == 12.0
        assert snap.detail == "http-429"

    def test_full_window_is_rate_limited(self):
        snap = usage_from_row({"usageStatus": "ok", "usage": {"fiveHour": {"pct": 100.0}}})
        assert snap.state is UsageState.RATE_LIMITED


class FakeEngine:
    def __init__(self):
        self.switched = []

    def list_accounts(self, json_output=False, fetch=None):
        self.fetch = fetch
        active = self.switched[-1] if self.switched else "2"
        rows = [
            dict(ROW, number=1, email="b@x.com", organizationUuid="", alias=None, active=active == "1"),
            dict(ROW, active=active == "2"),
        ]
        return {"schemaVersion": 1, "accounts": rows}

    def switch_to(self, identifier, json_output=False, force=False):
        self.switched.append(identifier)
        return {"switched": True, "from": {"number": 2, "email": "a@x.com"}, "to": {"number": 1}, "warnings": ["w1"]}


def test_generic_roles_map_the_engine_payloads():
    adapter = ClaudeAdapter()
    adapter._engine = FakeEngine()
    accounts = adapter.list_accounts()
    assert [(a.slot, a.label, a.identity, a.active) for a in accounts] == [
        (1, "b@x.com", "b@x.com/personal", False),
        (2, "a@x.com", "a@x.com/org-1", True),
    ]
    result = service.switch(adapter, "b@x.com")
    assert result.current.slot == 1 and result.previous.slot == 2
    assert "w1" in result.notes
    assert adapter.read_usage(accounts[1]).state is UsageState.AVAILABLE


def test_run_cli_embeds_the_engine_and_restores_state(monkeypatch):
    from claude_swap import cli as engine_cli

    seen = {}

    def fake_main():
        seen["argv"] = list(sys.argv)
        seen["prog"] = engine_cli._prog_name()
        raise SystemExit(3)

    monkeypatch.setattr(engine_cli, "main", fake_main)
    saved = list(sys.argv)
    assert ClaudeAdapter().run_cli(["list", "--json"]) == 3
    assert seen == {"argv": ["hswap claude", "list", "--json"], "prog": "hswap claude"}
    assert sys.argv == saved and engine_cli.EMBEDDED_PROG is None


def test_embedded_engine_refuses_the_upstream_self_upgrade(monkeypatch, capsys):
    import claude_swap.update_check as uc

    monkeypatch.setattr(uc, "run_self_upgrade", lambda: pytest.fail("must not upgrade upstream claude-swap"))
    assert ClaudeAdapter().run_cli(["upgrade"]) == 1
    assert "harness-swap" in capsys.readouterr().err


def test_embedded_help_names_hswap_claude(capsys):
    assert ClaudeAdapter().run_cli(["help"]) == 0
    out = capsys.readouterr().out
    assert "hswap claude list" in out
    assert "upgrade" not in out  # refused when embedded, so not advertised
    assert "rm=remove" in out


@pytest.mark.parametrize(
    ("engine_text", "shown"),
    [
        ("log in with Claude Code, then run: cswap add", "log in with Claude Code, then run: hswap claude add"),
        ("Run cswap --switch to rotate.", "Run hswap claude --switch to rotate."),
        ("`cswap unclaimed --purge` drops it", "`hswap claude unclaimed --purge` drops it"),
        ("cswap's OAuth client was rejected", "cswap's OAuth client was rejected"),
        ("another cswap surface holds the slot", "another cswap surface holds the slot"),
        ("cswap auto --once >> ~/.cswap-auto.log", "hswap claude auto --once >> ~/.cswap-auto.log"),
    ],
)
def test_engine_hints_name_the_hswap_command(engine_text, shown):
    assert claude_adapter.respell(engine_text) == shown


def test_engine_output_is_respelled_and_streams_restored(monkeypatch, capsys):
    from claude_swap import cli as engine_cli

    def fake_main():
        print("re-login needed; then run: cswap add")
        print("cswap list failed", file=sys.stderr)

    monkeypatch.setattr(engine_cli, "main", fake_main)
    out_before, err_before = sys.stdout, sys.stderr
    assert ClaudeAdapter().run_cli(["list"]) == 0
    captured = capsys.readouterr()
    assert "then run: hswap claude add" in captured.out
    assert "hswap claude list failed" in captured.err
    assert (sys.stdout, sys.stderr) == (out_before, err_before)


def test_a_confirmation_without_a_terminal_is_a_clean_error(monkeypatch):
    from claude_swap import cli as engine_cli

    def fake_main():
        input("Remove? ")

    monkeypatch.setattr(engine_cli, "main", fake_main)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    with pytest.raises(HswapError, match="run it in a terminal"):
        ClaudeAdapter().run_cli(["remove", "1"])


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_doctor_flags_a_credential_store_others_can_read(monkeypatch, tmp_path):
    from claude_swap import paths as cpaths

    root = tmp_path / "claude-swap"
    (root / "credentials").mkdir(parents=True)
    root.chmod(0o700)
    (root / "credentials").chmod(0o700)
    secret = root / "credentials" / ".creds-1-a@x.com.enc"
    secret.write_text("{}")
    secret.chmod(0o600)
    (root / "credentials" / ".consume-1.lock").write_text("")
    (root / "credentials" / ".consume-1.lock").chmod(0o664)  # lock files are not secret
    monkeypatch.setattr(cpaths, "get_backup_root", lambda: root)
    monkeypatch.setattr(claude_adapter.shutil, "which", lambda name: None)
    assert ClaudeAdapter().diagnose() == []
    (root / "claude-swap.log").write_text("")
    (root / "claude-swap.log").chmod(0o664)  # neither is the log
    assert ClaudeAdapter().diagnose() == []
    secret.chmod(0o644)
    (warning,) = ClaudeAdapter().diagnose()
    assert warning[0] == "warn" and str(secret) in warning[1]
    secret.chmod(0o600)
    (root / "sequence.json").write_text("{}")
    (root / "sequence.json").chmod(0o644)
    (warning,) = ClaudeAdapter().diagnose()
    assert "sequence.json" in warning[1]


def test_doctor_compares_the_upstream_cswap_release_line(monkeypatch):
    import subprocess

    from claude_swap import __version__

    monkeypatch.setattr(claude_adapter.shutil, "which", lambda name: "/opt/bin/cswap")
    monkeypatch.setattr(claude_adapter, "_loose_modes", lambda root: [])

    def fake_run(version):
        return lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=f"cswap {version}\n")

    monkeypatch.setattr(claude_adapter.spawn, "run", fake_run("0.1.0"))
    (finding,) = ClaudeAdapter().diagnose()
    assert finding[0] == "warn" and "0.1.0" in finding[1] and __version__ in finding[1]
    major_minor = ".".join(__version__.split(".")[:2])
    monkeypatch.setattr(claude_adapter.spawn, "run", fake_run(f"{major_minor}.9"))
    (finding,) = ClaudeAdapter().diagnose()
    assert finding[0] == "info"


def test_disabled_accounts_are_marked_everywhere():
    from harness_swap import output

    engine = FakeEngine()
    rows = engine.list_accounts()
    rows["accounts"][0]["disabled"] = True
    engine.list_accounts = lambda json_output=False: rows
    adapter = ClaudeAdapter()
    adapter._engine = engine
    first, second = adapter.list_accounts()
    assert first.to_json()["details"]["disabled"] is True and "disabled" not in second.details
    assert output.account_line(first).endswith("(disabled)")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the legacy move only exists on Linux/WSL")
def test_legacy_store_is_not_moved_as_a_side_effect(monkeypatch, tmp_path):
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    legacy = Path.home() / ".claude-swap-backup"
    legacy.mkdir()
    (legacy / "sequence.json").write_text('{"accounts": {}}')
    adapter = ClaudeAdapter()
    with pytest.raises(HswapError, match="hswap migrate"):
        adapter.list_accounts()
    assert legacy.exists()
    (plan,) = adapter.migration_plan()
    assert "backups" in plan and "move it to" in plan
    done = adapter.apply_migration()
    assert not legacy.exists()
    (backup,) = (tmp_path / "hswap" / "backups").iterdir()
    assert (backup / "sequence.json").read_text() == '{"accounts": {}}'
    assert any("moved" in step for step in done)
    assert claude_adapter.legacy_move_pending() is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the legacy move only exists on Linux/WSL")
@pytest.mark.parametrize("argv", [[], ["config"], ["config", "list"], ["tui"], ["list"]])
def test_no_engine_path_bypasses_the_migration_gate(monkeypatch, tmp_path, argv):
    from claude_swap import cli as engine_cli

    legacy = Path.home() / ".claude-swap-backup"
    legacy.mkdir()
    monkeypatch.setattr(engine_cli, "main", lambda: pytest.fail("engine must not start"))
    with pytest.raises(HswapError, match="hswap migrate"):
        ClaudeAdapter().run_cli(argv)
    assert legacy.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the legacy move only exists on Linux/WSL")
def test_both_stores_present_is_refused_before_any_backup(monkeypatch, tmp_path):
    from claude_swap import paths as cpaths

    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    legacy = Path.home() / ".claude-swap-backup"
    legacy.mkdir()
    (legacy / "sequence.json").write_text("{}")
    target = cpaths.get_backup_root()
    target.mkdir(parents=True)
    (target / "sequence.json").write_text("{}")
    adapter = ClaudeAdapter()
    (plan,) = adapter.migration_plan()
    assert plan.startswith("refuse to move") and "will not merge" in plan
    with pytest.raises(HswapError, match="will not merge"):
        adapter.apply_migration()
    with pytest.raises(HswapError, match="will not merge"):
        adapter.list_accounts()
    assert not (tmp_path / "hswap" / "backups").exists()
    assert (legacy / "sequence.json").exists() and (target / "sequence.json").exists()
    monkeypatch.setattr(claude_adapter.shutil, "which", lambda name: None)
    monkeypatch.setattr(claude_adapter, "_loose_modes", lambda root: [])
    assert [level for level, message in adapter.diagnose() if "will not merge" in message] == ["error"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the legacy move only exists on Linux/WSL")
def test_help_still_works_with_a_pending_migration(capsys):
    (Path.home() / ".claude-swap-backup").mkdir()
    assert ClaudeAdapter().run_cli(["help"]) == 0
    assert (Path.home() / ".claude-swap-backup").exists()


def test_an_embedded_menubar_service_runs_hswap_not_an_upstream_cswap(monkeypatch, tmp_path):
    from claude_swap import cli as engine_cli
    from claude_swap import launch_agent

    found = {"hswap": str(tmp_path / "bin" / "hswap"), "cswap": "/opt/upstream/cswap"}
    monkeypatch.setattr(launch_agent.shutil, "which", found.get)
    monkeypatch.setattr(engine_cli, "EMBEDDED_PROG", "hswap claude")
    assert launch_agent.resolve_program() == [found["hswap"], "claude"]
    monkeypatch.setattr(launch_agent.shutil, "which", lambda name: None)
    assert launch_agent.resolve_program() == [sys.executable, "-m", "claude_swap"]


def test_cached_view_lets_the_engine_fetch_nothing():
    from harness_swap.core import accounts as service_mod
    from harness_swap.core.usage import UsageService

    adapter = ClaudeAdapter()
    adapter._engine = FakeEngine()
    accounts, usage = service_mod.cached_view(adapter, UsageService(Path("/nonexistent")))
    assert adapter._engine.fetch == set()
    assert [a.slot for a in accounts] == [1, 2] and usage[accounts[1].key].state is UsageState.AVAILABLE
