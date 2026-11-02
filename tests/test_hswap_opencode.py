"""OpenCode adapter: version-aware strategy, native V2 commands, legacy auth.json."""

from __future__ import annotations

import json
import sqlite3
import sys

import pytest

from harness_swap.adapters.opencode import OpenCodeAdapter
from harness_swap.core import accounts as service
from harness_swap.core.errors import UnsupportedOperation
from harness_swap.core.models import Capability, Support
from tests.hswap_helpers import fake_executable, jwt, prepend_path, write_json

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake executables are POSIX scripts")

# A V2 emulator: state in $FAKE_OC_STATE (integrations JSON) and a real SQLite
# credential table in $FAKE_OC_DB, mirroring OpenCode 2.2.5's commands.
V2 = r"""
import sqlite3
state_path, db = os.environ["FAKE_OC_STATE"], os.environ["FAKE_OC_DB"]
state = json.load(open(state_path))
args = sys.argv[1:]
log = open(os.environ["FAKE_OC_LOG"], "a"); log.write(" ".join(args) + "\n"); log.close()
def save():
    json.dump(state, open(state_path, "w"))
if args == ["--version"]:
    print("opencode v2.2.5")
elif args == ["auth", "switch", "--help"]:
    print("USAGE\n  opencode auth switch [flags] [<target>] [<credential>]")
elif args == ["debug", "paths"]:
    print(f"data       /tmp/x\ndb         {db}")
elif args == ["api", "experimental.usage.limits"]:
    if sys.stdin.isatty():
        print("stdin is a terminal", file=sys.stderr); sys.exit(9)
    reply = json.load(open(os.environ["FAKE_OC_LIMITS"]))
    print(reply["out"])
    print(reply.get("err", ""), file=sys.stderr)
    sys.exit(reply.get("code", 0))
elif args[:2] == ["auth", "list"]:
    print(json.dumps([{"id": i, "name": i.title(), "connections": [
        {"type": "credential", "id": c["id"], "label": c["label"], "method": c["method"]} for c in creds]}
        for i, creds in state.items() if creds] + [{"id": "env", "name": "Env", "connections": [{"type": "environment"}]}]))
elif args[:2] == ["auth", "switch"]:
    integration, cred = args[2], args[3]
    if not any(c["id"] == cred for c in state.get(integration, [])):
        print("no such credential", file=sys.stderr); sys.exit(1)
    con = sqlite3.connect(db)
    con.execute("UPDATE credential SET active = (id = ?) WHERE integration_id = ?", (cred, integration))
    con.commit()
elif args[:2] == ["auth", "logout"]:
    state[args[2]] = [c for c in state[args[2]] if c["id"] != args[3]]
    save()
    con = sqlite3.connect(db); con.execute("DELETE FROM credential WHERE id = ?", (args[3],)); con.commit()
elif args[:2] == ["auth", "login"]:
    integration = args[2]
    new = {"id": "cred_new", "label": "new-login", "method": "oauth"}
    state.setdefault(integration, []).append(new)
    save()
    con = sqlite3.connect(db)
    con.execute("UPDATE credential SET active = 0 WHERE integration_id = ?", (integration,))
    con.execute("INSERT INTO credential VALUES (?, ?, ?, ?, 1)", ("cred_new", integration, "new-login", "SECRET-VALUE-NEW"))
    con.commit()
else:
    print("unexpected", args, file=sys.stderr); sys.exit(2)
"""


@pytest.fixture
def v2(tmp_path, monkeypatch):
    state = {
        "openai": [{"id": "cred_o1", "label": "me@work", "method": "oauth"}],
        "anthropic": [
            {"id": "cred_a1", "label": "first", "method": "oauth"},
            {"id": "cred_a2", "label": "second", "method": "oauth"},
        ],
    }
    write_json(tmp_path / "state.json", state)
    db = tmp_path / "opencode.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE credential (id text primary key, integration_id text, label text, value text, active integer)")
    con.executemany(
        "INSERT INTO credential VALUES (?, ?, ?, ?, ?)",
        [
            ("cred_o1", "openai", "me@work", "SECRET-VALUE-O1", None),
            ("cred_a1", "anthropic", "first", "SECRET-VALUE-A1", 1),
            ("cred_a2", "anthropic", "second", "SECRET-VALUE-A2", 0),
        ],
    )
    con.commit()
    con.close()
    monkeypatch.setenv("FAKE_OC_STATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("FAKE_OC_DB", str(db))
    monkeypatch.setenv("FAKE_OC_LOG", str(tmp_path / "calls.log"))
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    fake_executable(tmp_path / "bin", "opencode", V2)
    prepend_path(monkeypatch, tmp_path / "bin")
    return OpenCodeAdapter(), tmp_path


def test_native_mode_is_detected_by_probing_not_by_version(v2):
    adapter, _ = v2
    assert adapter.mode() == "native"
    caps = adapter.capabilities()
    assert caps[Capability.NATIVE_ACCOUNT_SWITCH].support is Support.SUPPORTED
    assert caps[Capability.PARALLEL_SESSIONS].support is Support.UNSUPPORTED
    usage = caps[Capability.USAGE_MONITORING]
    assert usage.support is Support.UNAVAILABLE and "hswap config set usage.remote" in usage.reason
    assert "quota interface" not in usage.reason
    assert caps[Capability.AUTOMATIC_ROTATION].support is Support.UNAVAILABLE


def test_listing_numbers_accounts_and_reads_active_flags(v2):
    adapter, _ = v2
    accounts = {a.identity: a for a in adapter.list_accounts()}
    assert set(accounts) == {"cred_o1", "cred_a1", "cred_a2"}  # environment connections are skipped
    assert accounts["cred_a1"].active is True and accounts["cred_a2"].active is False
    assert accounts["cred_o1"].active is True  # the only saved account of its integration
    assert accounts["cred_a2"].provider == "anthropic"
    slots = {a.identity: a.slot for a in adapter.list_accounts()}
    assert slots == {k: a.slot for k, a in accounts.items()}  # stable across listings


def test_switch_goes_through_opencode_and_leaves_other_providers(v2):
    adapter, tmp = v2
    result = service.switch(adapter, "second", provider="anthropic")
    assert result.current.identity == "cred_a2" and result.previous.identity == "cred_a1"
    assert "auth switch anthropic cred_a2" in (tmp / "calls.log").read_text()
    accounts = {a.identity: a.active for a in adapter.list_accounts()}
    assert accounts == {"cred_o1": True, "cred_a1": False, "cred_a2": True}


def test_database_is_only_read_and_secrets_never_selected(v2, monkeypatch):
    adapter, tmp = v2
    before = (tmp / "opencode.db").read_bytes()
    queries = []
    real_connect = sqlite3.connect

    def spy(*a, **k):
        con = real_connect(*a, **k)
        con.set_trace_callback(queries.append)
        return con

    monkeypatch.setattr("harness_swap.adapters.opencode.sqlite3.connect", spy)
    accounts = adapter.list_accounts()
    assert (tmp / "opencode.db").read_bytes() == before
    assert queries and all("value" not in q.lower() for q in queries)
    assert all("SECRET" not in json.dumps(a.to_json()) for a in accounts)


def test_add_runs_native_login_and_keeps_earlier_logins(v2, monkeypatch):
    adapter, _tmp = v2
    acc = adapter.add_account(provider="anthropic", alias="fresh")
    assert (acc.identity, acc.alias) == ("cred_new", "fresh")
    ids = {a.identity for a in adapter.list_accounts()}
    assert {"cred_a1", "cred_a2", "cred_new"} <= ids


def test_remove_uses_native_logout(v2):
    adapter, tmp = v2
    service.remove(adapter, "first", provider="anthropic")
    assert "auth logout anthropic cred_a1" in (tmp / "calls.log").read_text()
    assert "cred_a1" not in {a.identity for a in adapter.list_accounts()}


def test_unknown_active_state_when_database_is_unavailable(v2, monkeypatch):
    adapter, tmp = v2
    (tmp / "opencode.db").unlink()
    assert {a.active for a in adapter.list_accounts()} == {None}


# -- unsupported and legacy versions -----------------------------------------------------------------


def _fake_version(tmp_path, monkeypatch, version, has_switch=False):
    body = f"""
args = sys.argv[1:]
if args == ["--version"]:
    print("{version}")
elif args[:2] == ["auth", "switch"] and {has_switch!r}:
    print("opencode auth switch")
else:
    print("Usage: opencode <command>"); sys.exit(0)
"""
    fake_executable(tmp_path / "bin", "opencode", body)
    prepend_path(monkeypatch, tmp_path / "bin")
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))


def test_unrecognised_v2_build_is_refused_not_guessed(tmp_path, monkeypatch):
    _fake_version(tmp_path, monkeypatch, "2.0.1")
    adapter = OpenCodeAdapter()
    assert adapter.mode() is None
    caps = adapter.capabilities()
    assert caps[Capability.ACCOUNT_SWITCH].support is Support.UNAVAILABLE
    with pytest.raises(UnsupportedOperation, match="does not guess"):
        adapter.list_accounts()


def test_legacy_mode_swaps_one_provider_and_keeps_the_rest(tmp_path, monkeypatch):
    _fake_version(tmp_path, monkeypatch, "1.4.2")
    data = tmp_path / "xdg" / "opencode"
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    other = {"type": "api", "key": "synthetic-openrouter-key"}
    first = {"type": "oauth", "access": jwt({"sub": "user-1", "email": "one@x"}), "refresh": "r1", "expires": 1}
    second = {"type": "oauth", "access": jwt({"sub": "user-2", "email": "two@x"}), "refresh": "r2", "expires": 1}
    write_json(data / "auth.json", {"anthropic": first, "openrouter": other})
    adapter = OpenCodeAdapter()
    assert adapter.mode() == "legacy"
    added = adapter.add_account(provider="anthropic")
    assert added.label == "one@x"
    write_json(data / "auth.json", {"anthropic": second, "openrouter": other})
    adapter.add_account(provider="anthropic")
    service.switch(adapter, "one@x", provider="anthropic")
    doc = json.loads((data / "auth.json").read_text())
    assert doc["anthropic"]["access"] == first["access"]
    assert doc["openrouter"] == other
    assert adapter.capabilities()[Capability.ACCOUNT_SWITCH].support is Support.EXPERIMENTAL


def test_missing_binary(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    adapter = OpenCodeAdapter()
    assert not adapter.installation().installed
    assert not adapter.capabilities()[Capability.ACCOUNT_SWITCH].usable


def test_a_hanging_opencode_is_reported_not_fatal(v2, monkeypatch):
    adapter, _ = v2
    import subprocess

    def hang(*a, **k):
        raise subprocess.TimeoutExpired(a[0], 120)

    monkeypatch.setattr("harness_swap.adapters.opencode.spawn.run", hang)
    caps = adapter.capabilities()
    assert caps[Capability.ACCOUNT_SWITCH].support is Support.UNAVAILABLE
    assert "did not finish" in caps[Capability.ACCOUNT_SWITCH].reason


def test_odd_listing_shapes(v2, monkeypatch):
    import subprocess

    adapter, _ = v2
    adapter.mode()
    listing = {"out": '[{"id": "x", "connections": null}, "junk", {"id": "y", "connections": '
               '["junk", {"type": "credential", "id": "c1", "label": "l"}]}]'}

    def fake_run(*args, capture=True):
        out = listing["out"] if args[:2] == ("auth", "list") else ""
        return subprocess.CompletedProcess(args, 0, out, "")

    monkeypatch.setattr(adapter, "_run", fake_run)
    assert [a.identity for a in adapter.list_accounts()] == ["c1"]
    listing["out"] = '{"not": "a list"}'
    with pytest.raises(Exception, match="JSON list"):
        adapter.list_accounts()


def test_a_failed_command_is_reported_in_one_readable_line():
    import subprocess

    from harness_swap.adapters.opencode import _failure

    trace = (
        "Server process exited with code 1\n"
        "Error: Managed service port 49374 on 127.0.0.1 is already in use by another process.\n"
        "    at <anonymous> (/$bunfs/root/chunk.js:3:7550) {\n"
        "  [cause]: ServeError:\n"
        "      at P (/$bunfs/root/chunk.js:52:8551)\n}\n"
    )
    out = subprocess.CompletedProcess([], 1, stdout="", stderr=trace)
    assert _failure(out) == "Error: Managed service port 49374 on 127.0.0.1 is already in use by another process."
    assert _failure(subprocess.CompletedProcess([], 2, stdout="", stderr="")) == "exit status 2"


# -- Go plan usage by asking OpenCode (usage.remote) -------------------------------------------------

NOW_MS = 1_900_000_000_000


@pytest.fixture
def console(v2, monkeypatch):
    """Two OpenCode Console logins (cred_c1 inactive, cred_c2 active) and usage.remote on."""
    from harness_swap.core import settings

    adapter, tmp = v2
    state = json.loads((tmp / "state.json").read_text())
    state["opencode"] = [
        {"id": "cred_c1", "label": "team", "method": "oauth"},
        {"id": "cred_c2", "label": "personal", "method": "oauth"},
        {"id": "cred_k1", "label": "svc", "method": "key"},
    ]
    write_json(tmp / "state.json", state)
    con = sqlite3.connect(tmp / "opencode.db")
    con.executemany(
        "INSERT INTO credential VALUES (?, ?, ?, ?, ?)",
        [
            ("cred_c1", "opencode", "team", "SECRET-C1", 0),
            ("cred_c2", "opencode", "personal", "SECRET-C2", 1),
            ("cred_k1", "opencode", "svc", "SECRET-K1", 0),
        ],
    )
    con.commit()
    con.close()
    monkeypatch.setenv("FAKE_OC_LIMITS", str(tmp / "limits.json"))
    settings.set_value("usage.remote", "opencode")

    def reply(out, code=0, err=""):
        write_json(tmp / "limits.json", {"out": out if isinstance(out, str) else json.dumps(out), "code": code, "err": err})

    accounts = {a.identity: a for a in adapter.list_accounts()}
    return adapter, tmp, accounts, reply


def _meter(percent, limited=False, resets=NOW_MS):
    return {"percent": percent, "limited": limited, "resetsAt": resets}


def _calls(tmp):
    return (tmp / "calls.log").read_text().splitlines()


def test_go_meters_become_windows_for_the_active_console_account(console):
    adapter, tmp, accounts, reply = console
    reply({"location": {}, "data": {"workspace": {"id": "wrk_1"}, "go": {
        "rolling": _meter(12.5), "weekly": _meter(40), "monthly": _meter(55, resets=NOW_MS + 5000)}, "budgets": []}})
    snap = adapter.read_usage(accounts["cred_c2"])
    assert snap.state.value == "available" and snap.source == "opencode"
    by = {w.name: w for w in snap.windows}
    assert set(by) == {"5h", "weekly", "monthly"}
    assert (by["5h"].used_percent, by["5h"].resets_at, by["5h"].window_seconds) == (12.5, NOW_MS / 1000, 18000)
    assert by["weekly"].window_seconds == 604800 and by["monthly"].window_seconds is None
    assert by["monthly"].resets_at == (NOW_MS + 5000) / 1000
    assert snap.measured_at is not None
    assert "api experimental.usage.limits" in _calls(tmp)


def test_a_limited_or_full_meter_means_rate_limited(console):
    adapter, _tmp, accounts, reply = console
    reply({"data": {"go": {"rolling": _meter(100, True), "weekly": _meter(30), "monthly": _meter(20)}}})
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "rate_limited"
    reply({"data": {"go": {"rolling": _meter(30), "weekly": _meter(30, limited=True), "monthly": _meter(20)}}})
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "rate_limited"


def test_a_partial_go_answer_keeps_the_meters_it_has(console):
    adapter, _tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(7), "monthly": "junk", "rolling": {"percent": "x"}}}})
    snap = adapter.read_usage(accounts["cred_c2"])
    assert [w.name for w in snap.windows] == ["weekly"]
    reply({"data": {"go": {}}})
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "unknown"


def test_null_data_is_unknown_and_a_workspace_without_go_is_unsupported(console):
    adapter, _tmp, accounts, reply = console
    reply({"location": {}, "data": None})
    snap = adapter.read_usage(accounts["cred_c2"])
    assert snap.state.value == "unknown" and snap.detail and not snap.windows
    reply({"data": {"workspace": {"id": "wrk_1"}, "budgets": []}})
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "unsupported"


def test_a_rejected_token_needs_authentication(console):
    adapter, _tmp, accounts, reply = console
    msg = {"_tag": "ServiceUnavailableError", "message": "OpenCode Console budgets are unavailable: GET ... 401 ...",
           "service": "opencode"}
    reply(msg, code=1)
    snap = adapter.read_usage(accounts["cred_c2"])
    assert snap.state.value == "authentication_required" and "auth login" in snap.detail
    reply("", code=1, err="Error: request failed with status 401")
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "authentication_required"


def test_a_stack_trace_line_number_is_not_a_401(console):
    adapter, _tmp, accounts, reply = console
    reply("", code=1, err="Error: port in use\n    at start (/$bunfs/root/opencode:401:17)")
    with pytest.raises(Exception, match="exit status 1"):
        adapter.read_usage(accounts["cred_c2"])


def test_json_after_startup_chatter_is_still_parsed(console):
    adapter, _tmp, accounts, reply = console
    reply("service started\n" + json.dumps({"data": {"go": {"weekly": _meter(9)}}}))
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "available"


def _set_value(tmp, identity, value):
    con = sqlite3.connect(tmp / "opencode.db")
    con.execute("UPDATE credential SET value = ? WHERE id = ?", (json.dumps(value), identity))
    con.commit()
    con.close()


def test_a_login_about_to_refresh_is_not_asked(console):
    import time

    adapter, tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(9)}}})
    _set_value(tmp, "cred_c2", {"access": "SECRET", "expires": int(time.time() * 1000) + 60_000})
    snap = adapter.read_usage(accounts["cred_c2"])
    assert snap.state.value == "stale" and "about to refresh" in snap.detail
    assert "api experimental.usage.limits" not in _calls(tmp)
    _set_value(tmp, "cred_c2", {"access": "SECRET", "expires": int(time.time() * 1000) + 3_600_000})
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "available"


def test_a_switch_made_inside_opencode_during_the_read_discards_the_answer(console, monkeypatch):
    adapter, tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(9)}}})
    real = adapter._ask_limits

    def ask_then_switch():
        out = real()
        con = sqlite3.connect(tmp / "opencode.db")
        con.execute("UPDATE credential SET active = (id = 'cred_c1') WHERE integration_id = 'opencode'")
        con.commit()
        con.close()
        return out

    monkeypatch.setattr(adapter, "_ask_limits", ask_then_switch)
    snap = adapter.read_usage(accounts["cred_c2"])
    assert snap.state.value == "stale" and not snap.windows and "changed during the read" in snap.detail


def test_other_failures_raise_without_echoing_the_output(console):
    adapter, _tmp, accounts, reply = console
    reply({"_tag": "ServiceUnavailableError", "message": "boom sk-SECRET-TOKEN-123"}, code=1)
    with pytest.raises(Exception, match="ServiceUnavailableError") as exc:
        adapter.read_usage(accounts["cred_c2"])
    assert "SECRET" not in str(exc.value)
    reply("not json at all", code=0)
    with pytest.raises(Exception, match="exit status 0"):
        adapter.read_usage(accounts["cred_c2"])
    reply("", code=3)
    with pytest.raises(Exception, match="exit status 3"):
        adapter.read_usage(accounts["cred_c2"])


def test_inactive_other_integration_and_key_accounts_are_not_measured(console):
    adapter, tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(1)}}})
    snap = adapter.read_usage(accounts["cred_c1"])
    assert snap.state.value == "stale" and not snap.windows
    assert "only while it is the active OpenCode Console account" in snap.detail
    for ident in ("cred_a1", "cred_o1", "cred_k1"):
        snap = adapter.read_usage(accounts[ident])
        assert snap.state.value == "unsupported" and "Console logins" in snap.detail
    assert "api experimental.usage.limits" not in _calls(tmp)


def test_the_active_flag_is_read_fresh_so_a_switch_is_followed(console):
    adapter, _tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(9)}}})
    assert adapter.read_usage(accounts["cred_c1"]).state.value == "stale"
    service.switch(adapter, "team", provider="opencode")
    assert adapter.read_usage(accounts["cred_c1"]).state.value == "available"
    assert adapter.read_usage(accounts["cred_c2"]).state.value == "stale"  # stale Account object, fresh answer


def test_unreadable_database_means_no_measurement(console):
    adapter, tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(9)}}})
    (tmp / "opencode.db").unlink()
    snap = adapter.read_usage(accounts["cred_c2"])
    assert snap.state.value == "stale" and "cannot tell" in snap.detail


def test_a_read_waits_out_a_switch_in_progress(console, monkeypatch):
    from harness_swap.core.errors import LockError
    from harness_swap.infrastructure import locking

    adapter, _tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(9)}}})

    def busy(self):
        raise LockError("held")

    monkeypatch.setattr(locking.FileLock, "__enter__", busy)
    snap = adapter.read_usage(accounts["cred_c2"])
    assert snap.state.value == "stale" and "switch is in progress" in snap.detail


def test_a_hanging_usage_read_is_an_error_for_the_service(console, monkeypatch):
    import subprocess

    adapter, _tmp, accounts, _reply = console

    def hang(*a, **k):
        raise subprocess.TimeoutExpired(a[0], 60)

    monkeypatch.setattr("harness_swap.adapters.opencode.spawn.run", hang)
    with pytest.raises(Exception, match="did not finish"):
        adapter.read_usage(accounts["cred_c2"])


def test_the_usage_service_keeps_the_last_measurement_for_an_inactive_account(console, tmp_path):
    from harness_swap.core.usage import UsageService

    adapter, _tmp, accounts, reply = console
    reply({"data": {"go": {"weekly": _meter(33)}}})
    clock = {"t": 1000.0}
    svc = UsageService(tmp_path / "cache", clock=lambda: clock["t"])
    first = svc.get(adapter, accounts["cred_c2"])
    assert first.state.value == "available"
    service.switch(adapter, "team", provider="opencode")  # c2 is now inactive
    clock["t"] += adapter.usage_policy.min_interval_s + 1
    again = svc.get(adapter, accounts["cred_c2"])
    assert again.state.value == "stale" and again.windows == first.windows
    assert adapter.usage_policy.min_interval_s >= 120


def test_usage_and_rotation_capabilities(console):
    from harness_swap.core import settings

    adapter, _tmp, _accounts, _reply = console
    caps = adapter.capabilities()
    usage, rotation = caps[Capability.USAGE_MONITORING], caps[Capability.AUTOMATIC_ROTATION]
    assert usage.support is Support.EXPERIMENTAL and "experimental.usage.limits" in usage.reason
    assert rotation.support is Support.EXPERIMENTAL
    assert "circumvent usage limits" in rotation.reason and "https://opencode.ai/legal/terms-of-service" in rotation.reason
    assert "only while they are active" in rotation.reason
    settings.unset("usage.remote")
    caps = adapter.capabilities()
    assert caps[Capability.USAGE_MONITORING].support is Support.UNAVAILABLE
    assert "enable with `hswap config set usage.remote <ids>`" in caps[Capability.USAGE_MONITORING].reason
    assert caps[Capability.AUTOMATIC_ROTATION].support is Support.UNAVAILABLE
    assert adapter.read_usage(_accounts["cred_c2"]).state.value == "unsupported"


def test_legacy_and_missing_opencode_report_no_usage(tmp_path, monkeypatch):
    _fake_version(tmp_path, monkeypatch, "1.4.2")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    caps = OpenCodeAdapter().capabilities()
    assert caps[Capability.USAGE_MONITORING].support is Support.UNSUPPORTED
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert OpenCodeAdapter().capabilities()[Capability.USAGE_MONITORING].support is Support.UNAVAILABLE
