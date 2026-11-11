"""`add --login`: claude auth login, then add; --org is checked after the sign-in."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from claude_swap.exceptions import ConfigError, ValidationError
from claude_swap.switcher import ClaudeAccountSwitcher


def _switcher(cfg_identity=None):
    s = ClaudeAccountSwitcher()
    s._setup_directories()
    s._init_sequence_file()
    if cfg_identity:
        s._get_claude_config_path().write_text(json.dumps({"oauthAccount": cfg_identity}), encoding="utf-8")
    return s


def _login(s, new_identity, rc=0):
    def run(cmd):
        s._get_claude_config_path().write_text(json.dumps({"oauthAccount": new_identity}), encoding="utf-8")
        run.cmd = cmd
        return MagicMock(returncode=rc)
    return run


def test_login_passes_flags_then_adds(temp_home: Path, mock_claude_config: Path):
    s = _switcher()
    new = {"emailAddress": "a@x.com", "organizationUuid": "o1", "organizationName": "Acme"}
    run = _login(s, new)
    with patch("shutil.which", return_value="/bin/claude"), patch("subprocess.run", run), \
         patch.object(s, "_account_exists", return_value=True), patch.object(s, "add_account") as add:
        s.login_and_add_account(email="a@x.com", org="acme", sso=True, alias="w")
    assert run.cmd == ["/bin/claude", "auth", "login", "--email", "a@x.com", "--sso"]
    add.assert_called_once_with(slot=None, alias="w")


def test_org_mismatch_adds_nothing(temp_home: Path, mock_claude_config: Path):
    s = _switcher()
    run = _login(s, {"emailAddress": "a@x.com", "organizationUuid": "o1", "organizationName": "Acme"})
    with patch("shutil.which", return_value="/bin/claude"), patch("subprocess.run", run), \
         patch.object(s, "_account_exists", return_value=True), patch.object(s, "add_account") as add:
        with pytest.raises(ValidationError):
            s.login_and_add_account(org="Other")
    add.assert_not_called()


def test_unmanaged_current_login_is_added_before_signing_in(temp_home: Path, mock_claude_config: Path):
    s = _switcher({"emailAddress": "old@x.com", "organizationUuid": ""})
    order = []
    run = _login(s, {"emailAddress": "a@x.com"})
    with patch("shutil.which", return_value="/bin/claude"), \
         patch("subprocess.run", lambda cmd: (order.append("login"), run(cmd))[1]), \
         patch.object(s, "add_account", side_effect=lambda **kw: order.append("add")):
        s.login_and_add_account()
    assert order == ["add", "login", "add"]


def test_unmanaged_login_that_cannot_be_saved_is_never_replaced(temp_home: Path, mock_claude_config: Path):
    s = _switcher({"emailAddress": "old@x.com", "organizationUuid": ""})
    with patch("shutil.which", return_value="/bin/claude"), patch("subprocess.run") as run, \
         patch.object(s, "add_account", side_effect=ConfigError("cannot save")):
        with pytest.raises(ConfigError):
            s.login_and_add_account()
    run.assert_not_called()


def test_failed_login_adds_nothing(temp_home: Path, mock_claude_config: Path):
    s = _switcher()
    with patch("shutil.which", return_value="/bin/claude"), \
         patch("subprocess.run", _login(s, {"emailAddress": "a@x.com"}, rc=1)), \
         patch.object(s, "_account_exists", return_value=True), patch.object(s, "add_account") as add:
        with pytest.raises(ConfigError):
            s.login_and_add_account()
    add.assert_not_called()


class _StubSwitcher:
    """Just enough of ClaudeAccountSwitcher for cli._login_json."""

    def __init__(self, fail=None):
        self.rows = [{"email": "old@x.com", "organizationUuid": "", "active": True}]
        self.fail = fail

    def list_accounts(self, json_output, fetch):
        assert json_output and fetch == set()  # cache only, never a usage fetch
        return {"accounts": self.rows}

    def login_and_add_account(self, events, **kw):
        print("chatter that must not reach stdout")
        from harness_swap.infrastructure import login_events

        login_events.emit(events, "claude", "login_url", url="https://claude.com/x", awaitsCode=True)
        if self.fail:
            raise self.fail
        self.rows = [{**self.rows[0], "active": False}, {"email": "new@x.com", "organizationUuid": "", "active": True}]


def _run_login_json(capsys, switcher):
    import argparse
    import json

    from claude_swap import cli

    args = argparse.Namespace(email=None, org=None, sso=False, console=False, alias=None)
    with patch.object(cli.sys, "platform", "linux"):
        code = cli._login_json(switcher, args)
    out = capsys.readouterr()
    return code, [json.loads(line) for line in out.out.splitlines()], out.err


def test_login_json_stdout_is_only_events(capsys):
    code, events, err = _run_login_json(capsys, _StubSwitcher())
    assert code == 0
    assert [e["type"] for e in events] == ["login_url", "added"]
    assert events[1]["account"]["email"] == "new@x.com"
    assert events[1]["refreshed"] is False and events[1]["keepalive"] is None
    assert "chatter" in err


def test_login_json_failure_is_an_error_event(capsys):
    from claude_swap.exceptions import WrongAccountError

    code, events, _err = _run_login_json(capsys, _StubSwitcher(fail=WrongAccountError("no")))
    assert code == 1
    assert events[-1] == {"type": "error", "harness": "claude", "error": {"type": "wrong_account", "message": "no"}}
