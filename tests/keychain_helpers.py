"""A macOS-shaped store on a temp HOME and the in-memory Keychain fake, for the
keychain-required and keepalive tests. Tokens are synthetic."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.macos_keychain import keychain_account_name
from claude_swap.models import Platform
from claude_swap.switcher import ClaudeAccountSwitcher

LOGIN_EXPIRES_MS = 1_900_000_000_000
ACTIVE_ITEM = (CLAUDE_CODE_KEYCHAIN_SERVICE, keychain_account_name())


def creds(
    access: str = "sk-ant-oat01-ACCESS-1",
    refresh: str = "sk-ant-ort01-REFRESH-1",
    expires_in_s: float = 7200,
    **siblings,
) -> str:
    return json.dumps({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": refresh,
            "expiresAt": int((time.time() + expires_in_s) * 1000),
            "refreshTokenExpiresAt": LOGIN_EXPIRES_MS,
        },
        **siblings,
    })


def macos_store(home: Path, *, active: str = "a@example.com") -> ClaudeAccountSwitcher:
    """Slots 1 (a@) and 2 (b@), with ``active`` as the live identity."""
    s = ClaudeAccountSwitcher()
    s.platform = Platform.MACOS
    s._setup_directories()
    s._init_sequence_file()
    accounts = {}
    for num, email in (("1", "a@example.com"), ("2", "b@example.com")):
        accounts[num] = {
            "email": email,
            "uuid": f"uuid-{num}",
            "organizationUuid": "",
            "organizationName": "",
        }
        s._write_account_config(
            num, email, json.dumps({"oauthAccount": {"emailAddress": email}})
        )
    data = s._get_sequence_data()
    data.update(activeAccountNumber=1, sequence=[1, 2], accounts=accounts)
    s._write_json(s.sequence_file, data)
    (home / ".claude.json").write_text(json.dumps({
        "oauthAccount": {"emailAddress": active, "accountUuid": "uuid-1"},
    }))
    # A real store has already recorded its one-time migrations; the first
    # switcher above ran before the directory existed, so settle them now.
    with patch("claude_swap.models.Platform.detect", return_value=Platform.MACOS):
        ClaudeAccountSwitcher()
    return s


def snapshot(home: Path, keychain) -> dict:
    """Every credential-bearing byte: the files under HOME and the Keychain fake."""
    files = {
        str(path.relative_to(home)): path.read_bytes()
        for path in sorted(home.rglob("*"))
        if path.is_file()
        and not path.name.endswith((".log", ".lock", ".takeover"))
        and path.name != "keepalive.json"
    }
    return {"files": files, "keychain": dict(keychain.data)}
