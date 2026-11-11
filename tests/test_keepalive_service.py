"""keepalive LaunchAgent: ownership, idempotency, deferred load, status shape.

``subprocess.run`` is patched so the real launchctl is never driven.
"""

from __future__ import annotations

import plistlib
import subprocess
from unittest.mock import patch

import pytest

from claude_swap import keepalive_service as ks
from claude_swap import launch_agent

PROGRAM = ["/Users/x/.local/bin/hswap", "claude"]
UID = 501


@pytest.fixture(autouse=True)
def _on_macos():
    with patch.object(ks.sys, "platform", "darwin"), patch.object(launch_agent.sys, "platform", "darwin"):
        yield


def _launchctl(domain_ok=True, loaded=True, calls=None):
    def run(argv, **kwargs):
        if calls is not None:
            calls.append(argv)
        if argv[1] == "print":
            ok = domain_ok if argv[2].count("/") == 1 else loaded
            out = "\tstate = not running\n\tlast exit code = 0\n" if ok else ""
            return subprocess.CompletedProcess(argv, 0 if ok else 113, out, "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    return patch.object(launch_agent.subprocess, "run", side_effect=run)


def _install(tmp_path, **kw):
    return ks.install(ahead=7200, then_auto=kw.pop("then_auto", False), home=tmp_path, uid=UID, program=PROGRAM)


def test_plist_is_periodic_marked_and_runs_keepalive(tmp_path):
    doc = plistlib.loads(ks.build(PROGRAM, 7200, False, tmp_path))
    assert doc["Label"] == "dev.hswap.keepalive"
    assert doc["StartInterval"] == 300 and doc["RunAtLoad"] is True
    assert "KeepAlive" not in doc
    assert doc["ProgramArguments"] == [*PROGRAM, "keepalive", "--ahead", "7200"]
    assert doc["EnvironmentVariables"]["HSWAP_SERVICE"] == "keepalive"


def test_then_auto_runs_auto_only_after_keepalive_succeeds(tmp_path):
    args = plistlib.loads(ks.build(PROGRAM, 7200, True, tmp_path))["ProgramArguments"]
    assert args[:2] == ["/bin/sh", "-c"] and args[3:] == PROGRAM
    assert "keepalive --ahead 7200 &&" in args[2] and args[2].endswith("auto --once")
    # the shell really chains them: $0 "$@" expands to the program argv
    out = subprocess.run(
        ["/bin/sh", "-c", args[2].replace('"$0" "$@"', 'echo "$0" "$@"'), *PROGRAM],
        capture_output=True, text=True,
    ).stdout.split("\n")
    assert out[0] == "/Users/x/.local/bin/hswap claude keepalive --ahead 7200"


def test_install_writes_loads_and_status_reads_it_back(tmp_path):
    calls = []
    with _launchctl(loaded=False, calls=calls):
        result = _install(tmp_path, then_auto=True)
    assert result["action"] == "installed"
    assert any(c[1] == "bootstrap" for c in calls)
    assert result["managed"] is True and result["ahead"] == 7200 and result["thenAuto"] is True


def test_install_is_a_noop_when_unchanged_and_loaded(tmp_path):
    with _launchctl(loaded=False):
        _install(tmp_path)
    calls = []
    with _launchctl(loaded=True, calls=calls):
        result = _install(tmp_path)
    assert result["action"] == "unchanged"
    assert not any(c[1] in ("bootstrap", "bootout") for c in calls)


def test_install_refuses_a_foreign_plist_and_leaves_it(tmp_path):
    path = launch_agent.plist_path(ks.LABEL, tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(plistlib.dumps({"Label": ks.LABEL, "ProgramArguments": ["/bin/sh", "x.sh"]}))
    before = path.read_bytes()
    with _launchctl(), pytest.raises(ks.ForeignServiceError):
        _install(tmp_path)
    with _launchctl(), pytest.raises(ks.ForeignServiceError):
        ks.uninstall(tmp_path, UID)
    assert path.read_bytes() == before
    with _launchctl():
        st = ks.status(tmp_path, UID)
    assert st["installed"] is True and st["managed"] is False and st["ahead"] is None


def test_install_without_a_gui_session_writes_but_defers(tmp_path):
    calls = []
    with _launchctl(domain_ok=False, loaded=False, calls=calls):
        result = _install(tmp_path)
    assert result["action"] == "deferred" and result["loaded"] is False
    assert launch_agent.plist_path(ks.LABEL, tmp_path).exists()
    assert not any(c[1] == "bootstrap" for c in calls)


def test_uninstall_removes_ours_and_reports_absent_after(tmp_path):
    with _launchctl(loaded=False):
        _install(tmp_path)
    with _launchctl(loaded=True):
        assert ks.uninstall(tmp_path, UID)["action"] == "removed"
    with _launchctl(loaded=False):
        assert ks.uninstall(tmp_path, UID)["action"] == "absent"
    assert not launch_agent.plist_path(ks.LABEL, tmp_path).exists()


def test_off_macos_status_is_unsupported_and_install_refuses(tmp_path):
    with patch.object(ks.sys, "platform", "linux"):
        st = ks.status(tmp_path, UID)
        assert st["platform"] == "unsupported" and st["installed"] is False
        with pytest.raises(ks.UnsupportedPlatformError):
            _install(tmp_path)


def test_a_job_loaded_from_another_plist_under_our_label_is_never_touched(tmp_path):
    calls = []
    with _launchctl(loaded=True, calls=calls):
        with pytest.raises(ks.ForeignServiceError):
            _install(tmp_path)
        with pytest.raises(ks.ForeignServiceError):
            ks.uninstall(tmp_path, UID)
    assert not any(c[1] in ("bootstrap", "bootout") for c in calls)
    assert not launch_agent.plist_path(ks.LABEL, tmp_path).exists()


def test_a_different_caller_environment_does_not_reload_the_job(tmp_path, monkeypatch):
    with _launchctl(loaded=False):
        _install(tmp_path)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    calls = []
    with _launchctl(loaded=True, calls=calls):
        assert _install(tmp_path)["action"] == "unchanged"
    assert not any(c[1] in ("bootstrap", "bootout") for c in calls)


def test_other_options_rewrite_and_reload(tmp_path):
    with _launchctl(loaded=False):
        _install(tmp_path)
    calls = []
    with _launchctl(loaded=True, calls=calls):
        result = ks.install(ahead=1234567, then_auto=False, home=tmp_path, uid=UID, program=PROGRAM)
    assert result["action"] == "updated" and result["ahead"] == 1234567
    assert any(c[1] == "bootstrap" for c in calls)
