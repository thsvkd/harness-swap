"""Codex CLI adapter.

Verified against Codex CLI 0.166.0 and the openai/codex sources (see
docs/harness-compatibility.md for the evidence and its classification):

* Login lives in ``$CODEX_HOME/auth.json`` (default ``~/.codex``) when
  ``cli_auth_credentials_store`` is ``file`` -- the shipped default. The
  ``keyring``/``auto``/``ephemeral`` stores are not file-backed and are
  refused, not guessed at.
* A running Codex reads the file once; before refreshing it re-reads it and
  stops with an account-mismatch error if the account changed. So a switch
  needs a restart of running Codex processes, and Codex never writes the old
  account back over the new one.
* Codex rotates refresh tokens; the shared snapshot logic captures the live
  file back into the account before every switch.
* Isolated sessions use a per-account ``CODEX_HOME`` and ``--no-daemon``
  (when this Codex has it), because the shared background server runs on
  the default login.
* Usage is read *passively* from the ``rate_limits`` snapshots Codex writes
  to its own session logs (``sessions/**/rollout-*.jsonl``), attributed by
  the ``creator_user_id``/``creator_account_id`` in each log's header. No
  network request is made; the undocumented usage endpoint is not used.
"""

from __future__ import annotations

import json
import subprocess
import time
import tomllib
from pathlib import Path

from harness_swap.adapters.base import FileCredentialAdapter
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.credentials import Identity, fingerprint, jwt_claims
from harness_swap.core.models import (
    Account,
    Capability,
    CapabilityStatus,
    QuotaWindow,
    UsageSnapshot,
    UsageState,
    experimental,
    supported,
    unavailable,
    unsupported,
)
from harness_swap.infrastructure import spawn

_AUTH_CLAIMS = "https://api.openai.com/auth"
#: Newest session logs examined per home when looking for a usage snapshot.
_MAX_LOGS = 300


class CodexAuthFormat:
    """``auth.json`` is one account: the whole document is the part."""

    secret_name = "auth.json"

    def parts(self, doc: dict) -> dict[str, dict]:
        return {"": doc} if (doc.get("tokens") or doc.get("OPENAI_API_KEY")) else {}

    def identify(self, part_key: str, part: dict) -> Identity | None:
        tokens = part.get("tokens")
        if isinstance(tokens, dict) and isinstance(tokens.get("id_token"), str):
            claims = jwt_claims(tokens["id_token"])
            auth = claims.get(_AUTH_CLAIMS)
            auth = auth if isinstance(auth, dict) else {}
            account_id = tokens.get("account_id") or auth.get("chatgpt_account_id")
            user_id = auth.get("chatgpt_user_id") or auth.get("user_id")
            if not (account_id and user_id):
                return None
            return Identity(
                identity=f"{user_id}/{account_id}",
                label=claims.get("email") or str(account_id),
                provider="openai",
                auth_mode="chatgpt",
                meta={
                    "userId": user_id,
                    "accountId": account_id,
                    "plan": auth.get("chatgpt_plan_type"),
                },
            )
        key = part.get("OPENAI_API_KEY")
        if isinstance(key, str) and key:
            fp = fingerprint(key)
            return Identity(f"apikey/{fp}", f"API key {fp}", "openai", "api_key")
        return None

    def merge(self, doc: dict | None, part_key: str, part: dict) -> dict:
        return dict(part)


def _window_name(minutes: int | None) -> str:
    if not minutes:
        return "window"
    if minutes % 1440 == 0:
        return f"{minutes // 1440}d"
    if minutes % 60 == 0:
        return f"{minutes // 60}h"
    return f"{minutes}m"


def _iso_to_epoch(text: str | None) -> float | None:
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(text)).timestamp()
    except ValueError:
        return None


def snapshot_from_rate_limits(rate_limits: dict, measured_at: float | None, now: float) -> UsageSnapshot:
    """Normalise one Codex ``rate_limits`` record (as logged by Codex)."""
    windows = []
    for name in ("primary", "secondary"):
        w = rate_limits.get(name)
        if not isinstance(w, dict):
            continue
        minutes = w.get("window_minutes")
        windows.append(
            QuotaWindow(
                name=_window_name(minutes),
                used_percent=float(w["used_percent"]) if w.get("used_percent") is not None else None,
                resets_at=float(w["resets_at"]) if w.get("resets_at") else None,
                window_seconds=int(minutes) * 60 if minutes else None,
            )
        )
    reset_passed = any(w.resets_at is not None and w.resets_at <= now for w in windows)
    if reset_passed:
        state, detail = UsageState.STALE, "a window has reset since Codex last logged usage"
    elif rate_limits.get("rate_limit_reached_type"):
        state, detail = UsageState.RATE_LIMITED, str(rate_limits["rate_limit_reached_type"])
    else:
        state, detail = UsageState.AVAILABLE, ""
    credits = rate_limits.get("credits")
    return UsageSnapshot(
        state=state,
        windows=tuple(windows),
        measured_at=measured_at,
        source="codex-session-log",
        detail=detail,
        plan=rate_limits.get("plan_type"),
        balance=credits if isinstance(credits, dict) else None,
    )


def latest_rate_limits(home: Path, user_id: str, account_id: str) -> tuple[dict, float | None] | None:
    """The newest ``rate_limits`` record Codex logged in ``home`` for this account."""
    sessions = home / "sessions"
    if not sessions.is_dir():
        return None
    logs = sorted(sessions.glob("*/*/*/rollout-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    for log in logs[:_MAX_LOGS]:
        try:
            with log.open(encoding="utf-8") as fh:
                header = json.loads(fh.readline()).get("payload") or {}
                if (header.get("creator_user_id"), header.get("creator_account_id")) != (user_id, account_id):
                    continue
                found = None
                for line in fh:
                    if '"rate_limits"' not in line:
                        continue
                    event = json.loads(line)
                    limits = (event.get("payload") or {}).get("rate_limits")
                    if isinstance(limits, dict):
                        found = (limits, _iso_to_epoch(event.get("timestamp")))
        except (OSError, ValueError):
            continue
        if found:
            return found
    return None


class CodexAdapter(FileCredentialAdapter):
    id = "codex"
    display_name = "Codex CLI"
    providers = ("openai",)
    executable = "codex"
    home_env = "CODEX_HOME"
    default_home = ".codex"
    harness_lock_name = "auth.lock"
    shared_names = ("config.toml", "AGENTS.md", "rules", "prompts", "skills", "hooks", "hooks.json")
    hot_reload = False
    fmt = CodexAuthFormat()
    usage_policy = UsagePolicy(min_interval_s=30.0, stale_after_s=3600.0, max_backoff_s=600.0)

    def credential_store(self) -> str:
        """``cli_auth_credentials_store`` from config.toml; Codex's default is ``file``."""
        try:
            config = tomllib.loads((self.home / "config.toml").read_text(encoding="utf-8"))
        except (FileNotFoundError, tomllib.TOMLDecodeError, OSError):
            return "file"
        value = config.get("cli_auth_credentials_store", "file")
        return value if isinstance(value, str) else "file"

    def _has_no_daemon_flag(self) -> bool:
        if not hasattr(self, "_no_daemon"):
            inst = self.installation()
            self._no_daemon = False
            if inst.installed:
                try:
                    out = spawn.run([inst.executable, "--help"], capture_output=True, text=True, timeout=20)
                    self._no_daemon = "--no-daemon" in (out.stdout or "")
                except (OSError, subprocess.SubprocessError):
                    pass
        return self._no_daemon

    def session_args(self) -> list[str]:
        return ["--no-daemon"] if self._has_no_daemon_flag() else []

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        inst = self.installation()
        store = self.credential_store()
        if not inst.installed:
            blocked = unavailable(f"Codex CLI is not installed ({inst.detail})")
        elif store != "file":
            blocked = unavailable(
                f'cli_auth_credentials_store = "{store}" keeps the login outside auth.json; '
                'hswap manages file-backed logins only. Set it to "file" and sign in again.'
            )
        else:
            blocked = None
        if self._has_no_daemon_flag():
            sessions_status = supported("per-account CODEX_HOME, run with --no-daemon")
        else:
            sessions_status = experimental(
                "per-account CODEX_HOME; this Codex has no --no-daemon flag, so a shared "
                "background server (if any) could serve the default login instead"
            )
        return {
            Capability.ACCOUNT_LIST: supported(),
            Capability.ACCOUNT_ADD: blocked or supported("current login, or --login in an isolated CODEX_HOME"),
            Capability.ACCOUNT_REMOVE: supported("forgets hswap's copy; the live login is untouched"),
            Capability.ACCOUNT_SWITCH: blocked or supported("swaps $CODEX_HOME/auth.json; restart running Codex"),
            Capability.NATIVE_ACCOUNT_SWITCH: unsupported("Codex has one login per CODEX_HOME"),
            Capability.CREDENTIAL_REFRESH: unsupported(
                "Codex refreshes its own tokens; hswap captures rotated tokens before every switch"
            ),
            Capability.USAGE_MONITORING: experimental(
                "read passively from rate-limit snapshots in Codex's own session logs; "
                "updates only when that account runs Codex on this machine"
            ),
            Capability.AUTOMATIC_ROTATION: unsupported(
                "no documented quota API, and rotating accounts to get around rate limits "
                "may breach OpenAI's terms; use `switch` (optionally --strategy) manually"
            ),
            Capability.PARALLEL_SESSIONS: blocked or sessions_status,
            Capability.SESSION_RESUME: supported("`run <account> -- resume`; history is per account home"),
            Capability.CREDENTIAL_HOT_RELOAD: unsupported(
                "a running Codex reads auth.json once and stops at its next refresh if the account changed"
            ),
        }

    def read_usage(self, account: Account) -> UsageSnapshot:
        if account.auth_mode == "api_key":
            return UsageSnapshot(UsageState.UNSUPPORTED, detail="API-key logins have no plan windows")
        user_id, account_id = account.details.get("userId"), account.details.get("accountId")
        if not (user_id and account_id):
            return UsageSnapshot(UsageState.UNKNOWN, detail="account identity incomplete; re-add it")
        homes = [self.home]
        if account.slot is not None:
            homes.append(self.store.account_dir(account.slot))
        found = [r for h in homes if (r := latest_rate_limits(h, user_id, account_id))]
        if not found:
            return UsageSnapshot(
                UsageState.UNKNOWN,
                source="codex-session-log",
                detail="no Codex session on this machine has logged usage for this account yet",
            )
        limits, measured_at = max(found, key=lambda r: r[1] or 0.0)
        return snapshot_from_rate_limits(limits, measured_at, time.time())
