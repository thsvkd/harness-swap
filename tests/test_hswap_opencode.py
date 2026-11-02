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
    assert caps[Capability.USAGE_MONITORING].support is Support.UNSUPPORTED


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
