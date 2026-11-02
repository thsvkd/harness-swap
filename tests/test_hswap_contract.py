"""Architecture acceptance test: a new harness plugs in without touching the core.

The example adapter in ``examples/acme_adapter.py`` (a fictional harness) is
registered at runtime and through a simulated entry-point plugin, then driven
through the real CLI, the shared services and the dashboard's data layer.
Nothing under ``harness_swap.core`` / ``cli`` / ``ui`` is modified or
special-cased for it -- and a static check proves shared code names no harness.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import harness_swap
from harness_swap import cli
from harness_swap.core.models import Installation
from harness_swap.core.registry import Registry
from harness_swap.ui.tui import collect
from tests.hswap_helpers import write_json

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def load_example():
    spec = importlib.util.spec_from_file_location("acme_adapter", EXAMPLES / "acme_adapter.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["acme_adapter"] = module
    spec.loader.exec_module(module)
    return module


def installed(cls):
    def factory():
        adapter = cls()
        adapter._installation = Installation(True, "/fake/acme", "acme 1.0.0")
        return adapter

    return factory


@pytest.fixture
def acme(tmp_path, monkeypatch):
    module = load_example()
    home = tmp_path / "acme-home"
    home.mkdir()
    monkeypatch.setenv("ACME_HOME", str(home))
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    monkeypatch.setattr("harness_swap.infrastructure.processes.find", lambda names: [])
    registry = Registry({}, discover_plugins=False)
    registry.register("acme", installed(module.AcmeAdapter))
    return registry, home


def login(home, user):
    write_json(home / "credentials.json", {"account": {"id": user, "email": f"{user}@acme.test", "token": f"tok-{user}"}})


def hswap(registry, capsys, *argv):
    code = cli.run(list(argv), registry)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_full_lifecycle_through_the_cli(acme, capsys):
    registry, home = acme
    login(home, "ann")
    assert hswap(registry, capsys, "acme", "add", "--alias", "one")[0] == 0
    login(home, "bob")
    assert hswap(registry, capsys, "acme", "add")[0] == 0

    code, out, _ = hswap(registry, capsys, "acme", "list", "--json", "--no-usage")
    doc = json.loads(out)
    assert code == 0 and doc["schemaVersion"] == 1 and doc["harness"] == "acme"
    assert [(a["slot"], a["label"], a["active"]) for a in doc["accounts"]] == [
        (1, "ann@acme.test", False),
        (2, "bob@acme.test", True),
    ]
    assert "usage" not in doc["accounts"][0]

    code, out, _ = hswap(registry, capsys, "acme", "switch", "one", "--json")
    assert code == 0 and json.loads(out)["to"]["label"] == "ann@acme.test"
    assert json.loads((home / "credentials.json").read_text())["account"]["id"] == "ann"

    now = time.time()
    write_json(home / "quota.json", {
        "ann": {"used": 90, "resets_at": now + 600, "measured_at": now},
        "bob": {"used": 20, "resets_at": now + 600, "measured_at": now},
    })
    code, out, err = hswap(registry, capsys, "acme", "switch", "--strategy", "best")
    assert code == 0 and "bob@acme.test" in out, err
    code, out, _ = hswap(registry, capsys, "acme", "usage")
    assert "day 90%" in out and "day 20%" in out

    assert hswap(registry, capsys, "acme", "alias", "2", "two")[0] == 0
    assert hswap(registry, capsys, "acme", "remove", "two", "--yes")[0] == 0
    code, out, _ = hswap(registry, capsys, "acme", "list", "--json", "--no-usage")
    assert [a["label"] for a in json.loads(out)["accounts"]] == ["ann@acme.test"]


def test_cross_harness_commands_and_dashboard_see_it(acme, capsys):
    registry, home = acme
    login(home, "ann")
    hswap(registry, capsys, "acme", "add")
    _code, out, _ = hswap(registry, capsys, "harnesses", "--json")
    assert {"id": "acme", "origin": "runtime", "trusted": True, "name": "Acme Code",
            "installed": True, "version": "acme 1.0.0"} in json.loads(out)["harnesses"]
    _code, out, _ = hswap(registry, capsys, "capabilities", "acme", "--json")
    caps = json.loads(out)["harnesses"]["acme"]
    assert caps["account_switch"]["support"] == "supported"
    assert caps["automatic_rotation"]["support"] == "unsupported"
    _code, out, _ = hswap(registry, capsys, "status", "--json")
    assert json.loads(out)["harnesses"][0]["active"][0]["label"] == "ann@acme.test"
    _code, out, _ = hswap(registry, capsys, "list")
    assert "Acme Code (acme):" in out and "ann@acme.test" in out
    rows = collect(registry)
    assert [(adapter.id, acc.label) for adapter, acc, _u, _n in rows] == [("acme", "ann@acme.test")]
    assert hswap(registry, capsys, "doctor")[0] == 0


def test_entry_point_plugin_needs_explicit_trust(tmp_path, monkeypatch, capsys):
    load_example()
    monkeypatch.setenv("ACME_HOME", str(tmp_path / "acme"))
    monkeypatch.setenv("HSWAP_HOME", str(tmp_path / "hswap"))
    monkeypatch.syspath_prepend(str(EXAMPLES))
    ep = SimpleNamespace(name="acme", value="acme_adapter:AcmeAdapter", dist=SimpleNamespace(name="acme-hswap"))
    monkeypatch.setattr("harness_swap.core.registry.entry_points", lambda group: [ep])

    code, _, err = hswap(Registry({}), capsys, "acme", "list")
    assert code == 1 and "not trusted" in err
    code, out, _ = hswap(Registry({}), capsys, "harnesses")
    assert "untrusted plugin (plugin:acme-hswap)" in out

    assert "hswap config set plugins.trusted acme@acme-hswap" in out
    monkeypatch.setenv("HSWAP_TRUSTED_PLUGINS", "acme@acme-hswap")
    code, out, _ = hswap(Registry({}), capsys, "acme", "list", "--no-usage")
    assert code == 0 and "Acme Code:" in out


SHARED = ["core", "cli.py", "output.py", "ui"]
HARNESS_WORDS = ("claude", "codex", "grok", "opencode", "acme", "anthropic", "openai", "xai")


def _string_literals(tree: ast.AST):
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
                docstrings.add(id(body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node


def test_shared_code_names_no_harness():
    root = Path(harness_swap.__file__).parent
    files = []
    for item in SHARED:
        path = root / item
        files += sorted(path.rglob("*.py")) if path.is_dir() else [path]
    files.append(root / "adapters" / "base.py")
    offenders = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in _string_literals(tree):
            lowered = node.value.lower()
            for word in HARNESS_WORDS:
                if word in lowered:
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}: {node.value!r}")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", None) or ""
                names = [module] + [a.name for a in node.names]
                if any(n.startswith(("claude_swap", "harness_swap.adapters.")) and "base" not in n for n in names):
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}: imports {names}")
    assert offenders == [], "\n".join(offenders)


def test_snapshot_name_must_match_the_live_file(load_example_module=None):
    module = load_example()

    class Mismatched(module.AcmeAdapter):
        credential_file = "login.json"

    with pytest.raises(TypeError, match="must equal credential_file"):
        Mismatched()


def test_messages_a_plugin_user_sees(acme, capsys):
    registry, home = acme
    login(home, "ann")
    assert "Added ann@acme.test as acme slot 1" in hswap(registry, capsys, "acme", "add")[1]
    assert "already acme slot 1; its stored login was refreshed" in hswap(registry, capsys, "acme", "add")[1]
    with pytest.raises(SystemExit):
        hswap(registry, capsys, "acme", "run", "1", "whoami")
    assert "hswap acme run 1 -- whoami" in capsys.readouterr().err
    login(home, "zed")  # signed in outside hswap
    code, out, _ = hswap(registry, capsys, "acme", "switch", "1", "--force")
    (stash,) = (home.parent / "hswap" / "acme" / "stash").iterdir()
    assert code == 0 and f"saved to {stash}" in out
