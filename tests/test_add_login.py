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
