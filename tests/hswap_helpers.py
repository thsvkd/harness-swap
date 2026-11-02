"""Synthetic credentials and fake harness executables for hswap tests.

Every token here is made up; nothing reads or writes a real credential.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
from pathlib import Path


def b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def jwt(claims: dict) -> str:
    return f"{b64({'alg': 'none'})}.{b64(claims)}.c2ln"


def codex_auth(email: str, user: str, account: str, refresh: str = "rt-1", plan: str = "plus") -> dict:
    claims = {
        "email": email,
        "https://api.openai.com/auth": {
            "chatgpt_user_id": user,
            "chatgpt_account_id": account,
            "chatgpt_plan_type": plan,
        },
    }
    return {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": jwt(claims),
            "access_token": jwt({"sub": user, "n": refresh}),
            "refresh_token": f"synthetic-refresh-{refresh}",
            "account_id": account,
        },
        "last_refresh": "2026-11-01T00:00:00Z",
    }


def grok_entry(email: str, user: str, team: str = "team-1", key: str = "synthetic-grok-token") -> dict:
    return {
        "key": key,
        "auth_mode": "oidc",
        "user_id": user,
        "email": email,
        "team_id": team,
        "refresh_token": f"synthetic-refresh-{user}",
        "oidc_issuer": "https://auth.example",
        "oidc_client_id": "client-1",
    }


def write_json(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return path


def fake_executable(bin_dir: Path, name: str, body: str) -> Path:
    """A Python script named ``name`` on ``bin_dir`` (POSIX only)."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text(f"#!{sys.executable}\nimport json, os, sys\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def prepend_path(monkeypatch, bin_dir: Path) -> None:
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
