"""Debug logging: one line per command in <store root>/logs/events.jsonl, the
claude-swap.log prefix, launchd stderr stamping, `log` and doctor `lastEvents`.
Same harness as test_file_store: a temp HOME and a fake `security`. Tokens are synthetic."""

from __future__ import annotations

import json
import logging
import os
import plistlib
import re
import stat
import sys
import time
from unittest.mock import patch

import pytest

from claude_swap import events
from claude_swap import keepalive_service as ks
from claude_swap import reconcile_service as rs
from claude_swap.logging_config import setup_logging

from .keychain_helpers import creds
from .test_file_store import (  # noqa: F401 - fixtures
    ACTIVE_ITEM,
    NEAR,
    SLOT_1,
    SLOT_2,
    _macos_store_root,
    env,
    healthy,
    run_cli,
    split,
)

pytestmark = pytest.mark.no_keychain_fake

PROGRAM = ["/Users/x/.local/bin/hswap", "claude"]
FIELDS = {"ts", "v", "cmd", "caller", "session", "store", "activeSlot", "outcome", "exit", "ms", "error", "details"}
ISO = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z")
# Real-sized synthetic tokens: what a leak would look like.
ACCESS = "sk-ant-oat01-" + "A1b2C3d4" * 12
REFRESH = "sk-ant-ort01-" + "Z9y8X7w6" * 12


def _lines(env):
    path = env.root / "logs" / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _last(env, cmd):
    found = [event for event in _lines(env) if event["cmd"] == cmd]
    assert found, (cmd, _lines(env))
    return found[-1]


@pytest.fixture(autouse=True)
def _no_caller(monkeypatch):
    monkeypatch.delenv("HSWAP_CALLER", raising=False)


class TestOneLinePerCommand:
    @pytest.mark.parametrize(
        "argv, cmd",
        [
            (["list", "--json"], "list"),
            (["status", "--json"], "status"),
            (["keepalive", "--json"], "keepalive"),
            (["auto", "--once", "--json"], "auto"),
            (["switch", "2", "--json"], "switch"),
            (["reconcile", "--json"], "reconcile"),
            (["doctor", "--json"], "doctor"),
        ],
        ids=lambda value: value if isinstance(value, str) else None,
    )
    def test_schema(self, healthy, capsys, argv, cmd):
        code, _, _ = run_cli(argv, capsys)
        event = _last(healthy, cmd)
        assert set(event) == FIELDS
        assert ISO.match(event["ts"]) and event["exit"] == code
        assert event["caller"] == "unknown"  # pytest: not a TTY, no HSWAP_CALLER
        assert event["session"] in ("aqua", "background", "system", "unknown", "n/a")
        assert event["store"] == "file" and isinstance(event["ms"], int)
        assert isinstance(event["details"], dict)

    def test_migrate_store(self, split, capsys):
        code, _, _ = run_cli(["migrate-store", "--to", "file", "--keep", "file", "--no-reconcile", "--no-keepalive", "--json"], capsys)
        event = _last(split, "migrate-store")
        assert event["exit"] == code == 0 and event["outcome"] == "ok"
        assert event["details"]["kept"] == "file" and event["details"]["slotsMigrated"] == [1, 2]

    def test_a_dry_run_migration_logs_counts_not_its_plan_sentences(self, split, capsys):
        run_cli(["migrate-store", "--to", "file", "--keep", "keychain", "--dry-run", "--json"], capsys)
        details = _last(split, "migrate-store")["details"]
        assert details["steps"] == [f"planned:{len(details['steps']) and details['planned']}"]
        assert "back up" not in json.dumps(details) and details["planned"] >= 3

    def test_reconcile_details_say_why(self, healthy, capsys):
        healthy.security.items[ACTIVE_ITEM] = creds("AT-1B", "RT-1", expires_in_s=9000)
        healthy.file.unlink()
        run_cli(["reconcile", "--json"], capsys)
        event = _last(healthy, "reconcile")
        assert event["outcome"] == "reconciled"
        details = event["details"]
        assert details["rule"] == "same_lineage" and details["kept"] == "keychain"
        assert set(details["item"]) >= {"fp", "expiresAt", "role"} and details["rival"]["side"] == "slot"
        assert details["item"]["fp"] == details["rival"]["fp"]
        assert details["deleted"] is True and details["backups"] >= 1

    def test_an_ambiguous_reconcile_is_ambiguous(self, healthy, capsys):
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        assert run_cli(["reconcile", "--json"], capsys)[0] == 4
        event = _last(healthy, "reconcile")
        assert event["outcome"] == "ambiguous" and event["error"] == "reconcile_ambiguous"
        assert event["details"]["rule"] == "none" and event["details"]["deleted"] is False

    def test_keepalive_details(self, healthy, capsys):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        run_cli(["keepalive", "--json"], capsys)
        event = _last(healthy, "keepalive")
        assert event["outcome"] == "refreshed" and event["activeSlot"] == 1
        details = event["details"]
        assert details["refreshed"] is True and details["reason"] == "due" and details["ahead"] == 3600.0
        assert ISO.match(details["accessExpiresAt"])

    def test_keepalive_blocked_by_the_guard(self, healthy, capsys):
        healthy.security.items[ACTIVE_ITEM] = creds("AT-K", "RT-K")
        run_cli(["keepalive", "--json"], capsys)
        event = _last(healthy, "keepalive")
        assert event["outcome"] == "error" and event["error"] == "keychain_item_present"
        assert event["details"]["reason"] == "blocked:keychain_item_present"

    def test_switch_details(self, healthy, capsys):
        run_cli(["switch", "2", "--json"], capsys)
        event = _last(healthy, "switch")
        assert event["outcome"] == "switched"
        assert event["details"]["switch"] == {"from": 1, "to": 2, "reason": "switched", "trigger": "person"}

    def test_auto_details_name_each_slot_and_the_decision(self, healthy, capsys):
        code, _, _ = run_cli(["auto", "--once", "--json"], capsys)
        event = _last(healthy, "auto")
        assert event["outcome"] == {0: "switched", 1: "error", 2: "none", 3: "blocked"}[code]
        kinds = [tick["event"] for tick in event["details"]["ticks"]]
        assert kinds and "poll" in kinds
        # account refs are slot numbers here, not emails
        assert "example.com" not in json.dumps(event)

    def test_doctor_details_are_its_problems(self, healthy, capsys):
        run_cli(["doctor", "--json"], capsys)
        event = _last(healthy, "doctor")
        assert set(event["details"]) == {"problems"}

    def test_log_writes_no_event_of_its_own(self, healthy, capsys):
        run_cli(["list", "--json"], capsys)
        before = len(_lines(healthy))
        assert run_cli(["log", "--json"], capsys)[0] == 0
        assert len(_lines(healthy)) == before

    def test_no_store_root_no_log(self, temp_home, capsys):
        with patch("claude_swap.models.Platform.detect", return_value=__import__("claude_swap.models", fromlist=["Platform"]).Platform.MACOS):
            run_cli(["--version"], capsys)
        assert not list(temp_home.rglob("events.jsonl"))


class TestNoSecrets:
    def test_real_sized_tokens_never_reach_an_event(self, healthy, capsys):
        login = creds(ACCESS, REFRESH, expires_in_s=NEAR)
        healthy.write_file(login)
        healthy.write_enc(SLOT_1, login)
        healthy.write_enc(SLOT_2, creds(ACCESS[:-3] + "two", REFRESH[:-3] + "two"))
        for argv in (["list", "--json"], ["keepalive", "--json"], ["switch", "2", "--json"], ["doctor", "--json"]):
            run_cli(argv, capsys)
        healthy.security.items[ACTIVE_ITEM] = creds(ACCESS[:-3] + "kc0", REFRESH[:-3] + "kc0")
        run_cli(["reconcile", "--json"], capsys)
        text = (healthy.root / "logs" / "events.jsonl").read_text()
        for secret in (ACCESS, REFRESH, ACCESS[:24], REFRESH[:24], "sk-ant-"):
            assert secret not in text
        assert str(healthy.home) not in text
        logs = "".join(p.read_text(errors="replace") for p in healthy.home.rglob("*.log"))
        assert REFRESH not in logs and ACCESS not in logs

    def test_a_token_that_slips_into_details_is_redacted(self, healthy):
        events.begin("keepalive")
        events.note(oops=REFRESH, path=str(healthy.home / ".claude"))
        events.finish(0)
        text = (healthy.root / "logs" / "events.jsonl").read_text()
        assert REFRESH not in text and "[redacted]" in text and "~/.claude" in text


class TestFile:
    def test_mode_and_rotation(self, healthy, monkeypatch):
        monkeypatch.setattr(events, "MAX_BYTES", 400)
        for _ in range(40):
            events.begin("status")
            events.note(pad="x" * 100)
            events.finish(0)
        logs = healthy.root / "logs"
        names = sorted(p.name for p in logs.iterdir() if p.name.startswith("events.jsonl"))
        assert names == ["events.jsonl", "events.jsonl.1", "events.jsonl.2", "events.jsonl.3"]
        if os.name == "posix":
            for path in logs.glob("events.jsonl*"):
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
        # read() returns them oldest first across the rotation
        stamps = [event["ts"] for event in events.read(healthy.root)]
        assert stamps == sorted(stamps)

    def test_a_log_that_cannot_be_written_changes_nothing(self, healthy, capsys):
        healthy.write_file(creds("AT-1", "RT-1", expires_in_s=NEAR))
        healthy.write_enc(SLOT_1, creds("AT-1", "RT-1", expires_in_s=NEAR))
        (healthy.root / "logs").write_text("not a directory")
        code, out, err = run_cli(["keepalive", "--json"], capsys)
        assert code == 0 and json.loads(out)["action"] == "refreshed"
        code, out, _ = run_cli(["reconcile", "--json"], capsys)
        assert code == 0

    def test_the_store_root_logs_dir_is_throwaway_for_migration(self, tmp_path):
        from claude_swap.paths import _target_has_meaningful_data

        (tmp_path / "logs").mkdir()
        (tmp_path / "logs" / "events.jsonl").write_text("{}\n")
        assert _target_has_meaningful_data(tmp_path) is False


class TestCallerAndSession:
    def test_caller(self, monkeypatch):
        monkeypatch.setenv("HSWAP_CALLER", "jarvis-gateway")
        assert events.caller() == "jarvis-gateway"
        monkeypatch.delenv("HSWAP_CALLER")
        with patch.object(sys.stdin, "isatty", return_value=True):
            assert events.caller() == "tty"
        with patch.object(sys.stdin, "isatty", return_value=False):
            assert events.caller() == "unknown"

    @pytest.mark.parametrize("platform", ["linux", "win32"])
    def test_session_off_macos_is_na(self, platform):
        with patch.object(events.sys, "platform", platform):
            assert events.session() == "n/a"

    @pytest.mark.parametrize("answer, expected", [("Aqua", "aqua"), ("Background", "background"), ("System", "system"), ("LoginWindow", "unknown")])
    def test_session_on_macos(self, answer, expected):
        import subprocess

        def run(argv, **kwargs):
            assert argv == ["launchctl", "managername"]
            return subprocess.CompletedProcess(argv, 0, answer + "\n", "")

        with patch.object(events.sys, "platform", "darwin"), patch.object(events.subprocess, "run", run):
            assert events.session() == expected


class TestLaunchd:
    def test_each_plist_names_its_caller(self, tmp_path):
        def caller(plist):
            return plistlib.loads(plist)["EnvironmentVariables"]["HSWAP_CALLER"]

        assert caller(ks.build(PROGRAM, 3600, False, tmp_path)) == "launchd-gui-keepalive"
        assert caller(ks.build(PROGRAM, 3600, False, tmp_path, user="kgolf")) == "launchd-system-keepalive"
        assert caller(rs.build(PROGRAM, tmp_path)) == "launchd-gui-reconcile"

    def test_a_plist_without_a_caller_is_outdated(self, tmp_path):
        doc = plistlib.loads(ks.build(PROGRAM, 3600, False, tmp_path))
        del doc["EnvironmentVariables"]["HSWAP_CALLER"]
        assert ks._job(doc) != ks._job(plistlib.loads(ks.build(PROGRAM, 3600, False, tmp_path)))
        doc = plistlib.loads(rs.build(PROGRAM, tmp_path))
        del doc["EnvironmentVariables"]["HSWAP_CALLER"]
        path = tmp_path / "Library" / "LaunchAgents" / f"{rs.LABEL}.plist"
        path.parent.mkdir(parents=True)
        path.write_bytes(plistlib.dumps(doc))
        with patch.object(rs.sys, "platform", "darwin"), patch.object(ks.launch_agent.sys, "platform", "darwin"):
            assert rs._outdated(doc, tmp_path) is True

    @pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
    def test_the_stderr_file_is_created_owner_only(self, tmp_path, monkeypatch):
        err = tmp_path / "Library" / "Logs" / "dev.hswap.keepalive.err"
        err.parent.mkdir(parents=True)
        err.write_text("old\n")
        err.chmod(0o644)
        with patch.object(ks.sys, "platform", "darwin"), patch.object(ks.launch_agent.sys, "platform", "darwin"), \
                patch.object(os, "getuid", lambda: 501, create=True):
            ks.install(3600, False, tmp_path, 501, PROGRAM)  # no GUI domain: deferred
        assert stat.S_IMODE(err.stat().st_mode) == 0o600
        assert err.read_text() == "old\n"

    def test_stderr_lines_carry_a_utc_stamp_under_launchd(self, healthy, capsys, monkeypatch):
        monkeypatch.setenv("HSWAP_CALLER", "launchd-gui-keepalive")
        healthy.file.unlink()
        code, _, err = run_cli(["keepalive"], capsys)
        assert code == 1
        lines = [line for line in err.splitlines() if line.strip()]
        assert lines and all(ISO.match(line) for line in lines)
        assert _last(healthy, "keepalive")["caller"] == "launchd-gui-keepalive"

    def test_no_stamp_for_a_person(self, healthy, capsys):
        healthy.file.unlink()
        _, _, err = run_cli(["keepalive"], capsys)
        assert err.startswith("Error")

    def test_an_oversized_stderr_file_turns_over_at_start(self, healthy, capsys, monkeypatch):
        err = healthy.home / "Library" / "Logs" / "dev.hswap.keepalive.err"
        err.parent.mkdir(parents=True, exist_ok=True)
        err.write_text("x" * 64)
        monkeypatch.setattr(events, "STDERR_MAX_BYTES", 32)
        monkeypatch.setenv("HSWAP_CALLER", "launchd-system-keepalive")
        run_cli(["status", "--json"], capsys)
        assert (err.parent / "dev.hswap.keepalive.err.1").read_text() == "x" * 64
        assert not err.exists() or err.stat().st_size == 0


class TestClaudeSwapLog:
    def test_lines_carry_cmd_caller_and_session(self, tmp_path):
        events.begin("keepalive")
        try:
            logger = setup_logging(tmp_path)
            logger.warning("Usage fetch failed for account 2: http-429, retry-after 60s")
            for handler in logger.handlers:
                handler.flush()
        finally:
            events.finish(0)
        line = (tmp_path / "claude-swap.log").read_text().strip()
        assert re.match(
            r"^\S+ \S+ - WARNING - \[cmd=keepalive caller=unknown session=\S+\] Usage fetch failed for account 2", line
        ), line


class TestLogCommand:
    def _seed(self, env):
        now = time.time()
        logs = env.root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        rows = [
            {"ts": events.iso(now - 7200), "cmd": "keepalive", "caller": "launchd-system-keepalive", "session": "system",
             "outcome": "refreshed", "exit": 0, "ms": 20, "error": None, "details": {}},
            {"ts": events.iso(now - 600), "cmd": "reconcile", "caller": "launchd-gui-reconcile", "session": "aqua",
             "outcome": "ambiguous", "exit": 4, "ms": 30, "error": "reconcile_ambiguous", "details": {}},
            {"ts": events.iso(now - 60), "cmd": "keepalive", "caller": "jarvis-gateway", "session": "background",
             "outcome": "none", "exit": 0, "ms": 10, "error": None, "details": {}},
        ]
        (logs / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        return rows

    def test_filters(self, healthy, capsys):
        rows = self._seed(healthy)
        code, out, _ = run_cli(["log", "--json", "--cmd", "keepalive"], capsys)
        assert code == 0 and [json.loads(line) for line in out.splitlines()] == [rows[0], rows[2]]
        _, out, _ = run_cli(["log", "--json", "--since", "1h"], capsys)
        assert [json.loads(line)["cmd"] for line in out.splitlines()] == ["reconcile", "keepalive"]
        _, out, _ = run_cli(["log", "--json", "--tail", "1"], capsys)
        assert [json.loads(line) for line in out.splitlines()] == [rows[2]]
        _, out, _ = run_cli(["log", "--json", "--since", rows[1]["ts"]], capsys)
        assert len(out.splitlines()) == 2

    def test_the_human_view_is_one_line_each(self, healthy, capsys):
        self._seed(healthy)
        code, out, _ = run_cli(["log"], capsys)
        lines = out.splitlines()
        assert code == 0 and len(lines) == 3
        assert "reconcile" in lines[1] and "launchd-gui-reconcile" in lines[1]
        assert "ambiguous" in lines[1] and "reconcile_ambiguous" in lines[1]

    def test_without_a_filter_it_shows_the_last_20(self, healthy, capsys):
        logs = healthy.root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        rows = [{"ts": events.iso(time.time() - 100 + n), "cmd": "status", "n": n} for n in range(25)]
        (logs / "events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        _, out, _ = run_cli(["log", "--json"], capsys)
        assert [json.loads(line)["n"] for line in out.splitlines()] == list(range(5, 25))
        _, out, _ = run_cli(["log", "--json", "--cmd", "status"], capsys)
        assert len(out.splitlines()) == 25

    def test_a_bad_since_is_a_usage_error(self, healthy, capsys):
        assert run_cli(["log", "--since", "yesterday"], capsys)[0] == 2

    def test_no_log_yet(self, healthy, capsys):
        code, out, _ = run_cli(["log", "--json"], capsys)
        assert code == 0 and out == ""


class TestDoctorLastEvents:
    def test_the_last_five(self, healthy, capsys):
        for _ in range(3):
            run_cli(["list", "--json"], capsys)
        for _ in range(3):
            run_cli(["status", "--json"], capsys)
        _, out, _ = run_cli(["doctor", "--json"], capsys)
        last = json.loads(out)["lastEvents"]
        assert len(last) == 5
        assert all(set(row) == {"ts", "cmd", "caller", "outcome", "exit"} for row in last)
        assert [row["cmd"] for row in last] == ["list", "list", "status", "status", "status"]

    def test_none_yet(self, healthy, capsys):
        _, out, _ = run_cli(["doctor", "--json"], capsys)
        assert json.loads(out)["lastEvents"] == []


# --- independent review of the logging (0.3.1) ---------------------------------------

LEAKY = (
    "for a@corp.example see /Users/kgolf/.claude/x: server said 'quota exceeded for org' "
    "via http://bob:hunter2@proxy.corp:3128"
)
LEAK_FRAGMENTS = ("a@corp.example", "/Users/kgolf", "quota exceeded", "hunter2", "proxy.corp", "bob:")


class TestNoFreeText:
    @pytest.mark.parametrize("raised, kind", [
        (lambda: __import__("claude_swap.exceptions", fromlist=["x"]).ClaudeSwitchError(LEAKY), "ClaudeSwitchError"),
        (lambda: RuntimeError(LEAKY), "RuntimeError"),
    ], ids=["handled", "unexpected"])
    def test_auto_errors_leave_only_their_type(self, healthy, capsys, monkeypatch, raised, kind):
        from claude_swap.autoswitch import AutoSwitchEngine

        def boom(self):
            raise raised()

        monkeypatch.setattr(AutoSwitchEngine, "_tick_inner", boom)
        run_cli(["auto", "--once", "--json"], capsys)
        text = (healthy.root / "logs" / "events.jsonl").read_text()
        for fragment in LEAK_FRAGMENTS:
            assert fragment not in text
        error = [tick for tick in _last(healthy, "auto")["details"]["ticks"] if tick["event"] == "error"]
        assert error == [{"event": "error", "transient": True, "errorType": kind}]

    def test_switch_warnings_and_no_switch_detail_stay_out(self, healthy):
        class Event:
            def __init__(self, payload):
                self.payload = payload

            def to_json(self):
                return self.payload

        events.begin("auto")
        events.auto_event(Event({
            "event": "switch", "trigger": "threshold", "dryRun": False,
            "from": {"number": 1, "email": "a@example.com"}, "to": {"number": 2, "email": "b@example.com"},
            "warnings": [LEAKY],
        }))
        events.auto_event(Event({"event": "no-switch", "reason": "cooldown", "detail": LEAKY}))
        events.auto_event(Event({"event": "config-warning", "message": LEAKY}))
        events.auto_event(Event({"event": "account-quarantined", "number": 2, "email": "b@example.com", "reason": "dead-token"}))
        events.finish(0)
        text = (healthy.root / "logs" / "events.jsonl").read_text()
        for fragment in (*LEAK_FRAGMENTS, "example.com"):
            assert fragment not in text
        ticks = _last(healthy, "auto")["details"]["ticks"]
        assert ticks == [
            {"event": "switch", "trigger": "threshold", "dryRun": False, "from": 1, "to": 2},
            {"event": "no-switch", "reason": "cooldown"},
            {"event": "config-warning"},
            {"event": "account-quarantined", "number": 2, "reason": "dead-token"},
        ]

    def test_an_email_that_slips_into_details_is_masked(self, healthy):
        events.begin("status")
        events.note(who="Me.Name+tag@corp.example.co")
        events.finish(0)
        text = (healthy.root / "logs" / "events.jsonl").read_text()
        assert "corp.example" not in text and "[email]" in text

    def test_a_caller_that_is_not_a_plain_name_is_custom(self, monkeypatch):
        monkeypatch.setenv("HSWAP_CALLER", "me@corp.example")
        assert events.caller() == "custom"
        monkeypatch.setenv("HSWAP_CALLER", "launchd-gui-keepalive")
        assert events.caller() == "launchd-gui-keepalive"


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
class TestStderrFileMode:
    def _err(self, env):
        err = env.home / "Library" / "Logs" / "dev.hswap.keepalive.err"
        err.parent.mkdir(parents=True, exist_ok=True)
        return err

    def test_after_turning_over_both_files_are_owner_only(self, healthy, capsys, monkeypatch):
        err = self._err(healthy)
        err.write_text("x" * 64)
        err.chmod(0o600)
        monkeypatch.setattr(events, "STDERR_MAX_BYTES", 32)
        monkeypatch.setenv("HSWAP_CALLER", "launchd-gui-keepalive")
        run_cli(["status", "--json"], capsys)
        assert stat.S_IMODE(err.stat().st_mode) == 0o600 and err.stat().st_size == 0
        assert stat.S_IMODE(err.with_name(err.name + ".1").stat().st_mode) == 0o600

    def test_each_launchd_run_narrows_a_wide_file(self, healthy, capsys, monkeypatch):
        err = self._err(healthy)
        err.write_text("old\n")
        err.chmod(0o644)
        monkeypatch.setenv("HSWAP_CALLER", "launchd-system-keepalive")
        run_cli(["status", "--json"], capsys)
        assert stat.S_IMODE(err.stat().st_mode) == 0o600 and err.read_text() == "old\n"


class TestQuietWhenNotWriting:
    def test_nothing_is_asked_when_nothing_will_be_written(self, temp_home, monkeypatch):
        asked = []
        monkeypatch.setattr(events, "_store_label", lambda root: asked.append("store") or "file")
        monkeypatch.setattr(events, "session", lambda: asked.append("session") or "aqua")
        events.begin("status")
        events.finish(0)  # no store root
        assert asked == []


class TestTailRead:
    def _write(self, path, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def test_the_last_n_come_from_the_end_and_spill_into_older_files(self, healthy, monkeypatch):
        logs = healthy.root / "logs"
        self._write(logs / "events.jsonl.1", [{"n": n} for n in range(0, 3)])
        self._write(logs / "events.jsonl", [{"n": n} for n in range(3, 3 + 5000)])
        from pathlib import Path

        def refuse(self, *args, **kwargs):
            raise AssertionError("whole-file read")

        monkeypatch.setattr(Path, "read_text", refuse)
        assert [row["n"] for row in events.read(healthy.root, last=2)] == [5001, 5002]
        monkeypatch.undo()
        self._write(logs / "events.jsonl", [{"n": n} for n in range(3, 6)])
        assert [row["n"] for row in events.read(healthy.root, last=5)] == [1, 2, 3, 4, 5]


class TestLowLevel:
    def test_the_real_path_of_home_is_shortened_too(self, tmp_path, monkeypatch):
        real = tmp_path / "Users" / "someone"
        real.mkdir(parents=True)
        link = tmp_path / "home-link"
        link.symlink_to(real)
        monkeypatch.setattr("pathlib.Path.home", lambda: link)
        line = events._scrub(json.dumps({"a": str(real / ".claude"), "b": str(link / "x")}))
        assert str(real) not in line and str(link) not in line and line.count("~/") == 2

    def test_a_carriage_return_is_not_a_new_line(self):
        import io

        out = io.StringIO()
        stream = events.StampedStream(out)
        stream.write("50%\r100%\ndone\n")
        lines = out.getvalue().rstrip("\n").split("\n")
        assert len(lines) == 2 and lines[0].endswith("50%\r100%") and ISO.match(lines[0]) and ISO.match(lines[1])

    def test_a_cut_off_line_does_not_swallow_the_next(self, healthy):
        logs = healthy.root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "events.jsonl").write_text('{"cmd": "list", "outcome": "o')  # the disk filled up
        events.begin("status")
        events.finish(0)
        assert [row["cmd"] for row in events.read(healthy.root)] == ["status"]

    def test_turning_over_waits_for_no_one(self, healthy, monkeypatch):
        from claude_swap.locking import FileLock

        monkeypatch.setattr(events, "MAX_BYTES", 300)
        monkeypatch.setattr(events, "TURN_OVER_LOCK_S", 0.05)
        logs = healthy.root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        with FileLock(logs / ".events.lock"):
            for _ in range(10):
                events.begin("status")
                events.note(pad="x" * 80)
                events.finish(0)
        # Another process held the turn-over: lines still land, nothing is lost.
        assert len(events.read(healthy.root)) == 10


# --- re-review (0.3.1, before release) -----------------------------------------------


class TestPollWindows:
    def test_a_real_poll_keeps_window_usage_and_both_lines(self, healthy):
        from claude_swap.autoswitch import PollEvent

        events.begin("auto")
        events.auto_event(PollEvent(
            active={"number": 1, "email": "a@example.com"},
            headroom={"1": 40.0, "2": 75.5},
            threshold=90.0,
            fetch_errors={"2": "http-429"},
            windows={"1": {"5h": 60.0, "7d": 93.0, "Fable": 100.0}, "2": {"5h": 24.5}},
            weekly_threshold=97.0,
        ))
        events.finish(0)
        tick = _last(healthy, "auto")["details"]["ticks"][0]
        assert tick == {
            "event": "poll", "active": 1, "headroomPct": {"1": 40.0, "2": 75.5}, "threshold": 90.0,
            "windowsPct": {"1": {"5h": 60.0, "7d": 93.0, "Fable": 100.0}, "2": {"5h": 24.5}},
            "fetchErrors": {"2": "http-429"}, "weeklyThreshold": 97.0,
        }


class TestTailSkipsBrokenLines:
    def test_n_good_rows_even_past_broken_lines(self, healthy):
        logs = healthy.root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        good = [json.dumps({"n": n}) for n in range(10)]
        broken = ["{not json"] * 3
        (logs / "events.jsonl").write_text("\n".join(good[:7] + broken + good[7:]) + "\n")
        assert [row["n"] for row in events.read(healthy.root, last=5)] == [5, 6, 7, 8, 9]

    def test_broken_lines_across_a_block_boundary(self, healthy, monkeypatch):
        logs = healthy.root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(events, "_TAIL_BLOCK", 64)
        lines = [json.dumps({"n": n, "pad": "x" * 20}) for n in range(6)] + ["{broken" + "y" * 200] * 4
        (logs / "events.jsonl").write_text("\n".join(lines) + "\n")
        assert [row["n"] for row in events.read(healthy.root, last=3)] == [3, 4, 5]
