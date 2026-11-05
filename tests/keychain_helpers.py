"""A macOS-shaped store on a temp HOME and the in-memory Keychain fake, for the
keychain-required and keepalive tests. Tokens are synthetic."""

from __future__ import annotations

import json
import subprocess
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


def split_line(line):
    """`security -i`'s tokenizer (Security/SecurityTool/macOS/security.c, split_line):
    quotes delimit, and a backslash copies the next character literally."""
    args, current, quote, escaped, in_arg = [], [], None, False, False
    for ch in line.rstrip("\n"):
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped, in_arg = True, True
        elif quote:
            if ch == quote:
                quote = None
            else:
                current.append(ch)
        elif ch in "\"'":
            quote, in_arg = ch, True
        elif ch.isspace():
            if in_arg:
                args.append("".join(current))
                current, in_arg = [], False
        else:
            current.append(ch)
            in_arg = True
    if in_arg:
        args.append("".join(current))
    return args


def stored_value(line):
    """What `add-generic-password` stores from this stdin line."""
    args = split_line(line)
    assert args[:2] == ["add-generic-password", "-U"]
    assert "\n" not in line.rstrip("\n")
    if "-X" in args:
        return bytes.fromhex(args[args.index("-X") + 1]).decode()
    return args[args.index("-w") + 1]


class FakeSecurity:
    """`subprocess.run` for `/usr/bin/security`: parses `-i` lines the way the real
    tool does and keeps items in memory. ``mangle`` is what its quoting did to a value
    while still exiting 0."""

    def __init__(self, mangle=None, write_rc=0, delete_rc=0):
        self.items = {}
        self.stdin = []
        self.written = []
        self.deleted = []
        self.mangle = mangle or (lambda value: value)
        self.write_rc = write_rc
        self.delete_rc = delete_rc

    def _completed(self, args, rc, stdout=""):
        return subprocess.CompletedProcess(args, rc, stdout=stdout, stderr="")

    def __call__(self, args, **kwargs):
        if args[1:] == ["-i"]:
            line = kwargs["input"]
            self.stdin.append(line)
            parsed = split_line(line)
            key = (parsed[parsed.index("-s") + 1], parsed[parsed.index("-a") + 1])
            self.written.append(key)
            if self.write_rc:
                return self._completed(args, self.write_rc)
            value = self.mangle(stored_value(line))
            if value is not None:
                self.items[key] = value
            return self._completed(args, 0)
        key = (args[args.index("-s") + 1], args[args.index("-a") + 1])
        if args[1] == "find-generic-password":
            value = self.items.get(key)
            if value is None:
                return self._completed(args, 44)
            # keychain_find.c: hex for the whole value if any byte fails isprint.
            raw = value.encode()
            printable = all(0x20 <= byte <= 0x7e for byte in raw)
            return self._completed(args, 0, (value if printable else raw.hex()) + "\n")
        assert args[1] == "delete-generic-password", args
        self.deleted.append(key)
        if self.delete_rc:
            return self._completed(args, self.delete_rc)
        return self._completed(args, 0 if self.items.pop(key, None) is not None else 44)
