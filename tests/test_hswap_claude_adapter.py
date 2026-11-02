"""Claude adapter: engine embedding, schema-v1 normalisation, migration gate."""

from __future__ import annotations

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

    def list_accounts(self, json_output=False):
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
    assert adapter.migration_plan() and "move claude-swap data" in adapter.migration_plan()[0]
    done = adapter.apply_migration()
    assert not legacy.exists()
    (backup,) = (tmp_path / "hswap" / "backups").iterdir()
    assert (backup / "sequence.json").read_text() == '{"accounts": {}}'
    assert any("moved" in step for step in done)
    assert claude_adapter.legacy_move_pending() is None
