"""Codex CLI adapter.

Verified against Codex CLI 0.166.0 and the openai/codex sources (see
docs/harness-compatibility.md for the evidence and its classification):

* Login lives in ``$CODEX_HOME/auth.json`` (default ``~/.codex``) when
  ``cli_auth_credentials_store`` is ``file`` -- the shipped default. The
  ``keyring``/``auto``/``ephemeral`` stores are not file-backed and are
  refused, not guessed at. Keys hswap does not use (``tokens.login_owner_id``,
  ``tokens.oauth_provenance``, ...) are copied verbatim: Codex checks them
  before it persists a refreshed token.
* A running Codex reads the file once; before refreshing it re-reads it and
  stops with an account-mismatch error if the account changed. So a switch
  needs a restart of running Codex processes, and Codex never writes the old
  account back over the new one.
* Codex rotates refresh tokens (single use); the shared snapshot logic
  captures the live file back into the account before every switch.
* Isolated sessions use a per-account ``CODEX_HOME`` and ``--no-daemon``
  (when this Codex has it), because the shared background server runs on
  the default login.
* Usage, by default, is read *passively* from the ``rate_limits`` snapshots
  Codex writes to its own session logs (``sessions/**/rollout-*.jsonl``),
  attributed by the ``creator_user_id``/``creator_account_id`` in each log's
  header. No network request is made.
* With ``usage.remote`` including ``codex``, usage is read live by asking
  Codex itself -- the request its ``/status`` uses: ``codex app-server
  --listen stdio://`` and ``account/rateLimits/read`` -- with ``CODEX_HOME``
  set to the account's own home, so Codex refreshes and stores its tokens
  itself and hswap never calls OpenAI. The interface is Codex's app-server
  protocol, not a documented quota API, so it is reported experimental. The
  active login is asked only while its access token has more than 10
  minutes left: Codex refreshes 5 minutes before expiry, and a Codex the
  user started could refresh the same single-use refresh token at once.
  Limits: only the main ``codex`` limit is mapped; extra metered limits in
  ``rateLimitsByLimitId`` are not read. If a read is cut off at the timeout
  while Codex is mid-refresh, the rotated refresh token may be lost and that
  account must sign in again.
* ``hswap codex refresh`` keeps stored logins usable the same way: one
  ``account/rateLimits/read`` in the account's own home, so Codex refreshes
  a due token and stores the rotated one there. No opt-in needed (the user
  asked); the active login only while no Codex runs on this machine, since
  that Codex could redeem the same single-use refresh token.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.metadata
import json
import os
import subprocess
import time
import tomllib
from pathlib import Path

from harness_swap.adapters.base import FileCredentialAdapter
from harness_swap.core import settings
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.credentials import Identity, fingerprint, jwt_claims
from harness_swap.core.errors import HswapError
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
from harness_swap.infrastructure import jsonrpc, processes, spawn

_AUTH_CLAIMS = "https://api.openai.com/auth"
#: Newest session logs examined per home when looking for a usage snapshot.
_MAX_LOGS = 300
#: The active login is asked about only with more token life than this left.
_MIN_TOKEN_LIFE_S = 600.0
#: Without a readable ``exp``, Codex refreshes when ``last_refresh`` is older than this.
_REFRESH_INTERVAL_S = 8 * 86400.0
#: Start-up, a possible token refresh and the usage request, in total.
_RPC_TIMEOUT_S = 45.0
_PASSIVE_POLICY = UsagePolicy(min_interval_s=30.0, stale_after_s=3600.0, max_backoff_s=600.0)
#: Each live read starts a Codex process and makes a request: keep it rare.
_REMOTE_POLICY = UsagePolicy(min_interval_s=300.0, stale_after_s=1800.0, max_backoff_s=3600.0)
_ENABLE_REMOTE = "enable with `hswap config set usage.remote <ids>` (include the harnesses already listed)"
_TERMS = (
    'OpenAI\'s Terms of Use (2024-12-11 text) forbid using the services to "circumvent any rate limits '
    'or restrictions" (https://openai.com/policies/row-terms-of-use; current wording not verified); OpenAI has not said whether '
    "switching between your own accounts counts. You are responsible for complying"
)


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


def snapshot_from_rate_limits(
    rate_limits: dict, measured_at: float | None, now: float, *, live: bool = False
) -> UsageSnapshot:
    """Normalise one Codex ``rate_limits`` record (as logged by Codex, or ``live`` from Codex)."""
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
    reset_passed = not live and any(w.resets_at is not None and w.resets_at <= now for w in windows)
    if reset_passed:
        state, detail = UsageState.STALE, "a window has reset since Codex last logged usage"
    elif rate_limits.get("rate_limit_reached_type"):
        state, detail = UsageState.RATE_LIMITED, str(rate_limits["rate_limit_reached_type"])
    elif any(w.used_percent is not None and w.used_percent >= 100 for w in windows):
        state, detail = UsageState.RATE_LIMITED, "a window is used up"
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


def snapshot_from_app_server(result: object, now: float) -> UsageSnapshot:
    """Normalise Codex's ``account/rateLimits/read`` answer (camelCase; ``resetsAt``
    in epoch seconds, ``windowDurationMins`` in minutes)."""
    rl = result.get("rateLimits") if isinstance(result, dict) else None
    if not isinstance(rl, dict):
        raise HswapError("Codex answered without rate limits")

    def window(w: object) -> dict | None:
        if not isinstance(w, dict):
            return None
        return {"used_percent": w.get("usedPercent"), "window_minutes": w.get("windowDurationMins"),
                "resets_at": w.get("resetsAt")}

    snap = snapshot_from_rate_limits(
        {
            "primary": window(rl.get("primary")),
            "secondary": window(rl.get("secondary")),
            "credits": rl.get("credits"),
            "plan_type": rl.get("planType"),
            "rate_limit_reached_type": rl.get("rateLimitReachedType"),
        },
        now,
        now,
        live=True,
    )
    if snap.state is UsageState.AVAILABLE:
        if rl.get("spendControlReached") is True:
            snap = dataclasses.replace(snap, state=UsageState.RATE_LIMITED, detail="spend control reached")
        elif result.get("ordinaryUsageAllowed") is False:  # type: ignore[union-attr]
            snap = dataclasses.replace(snap, state=UsageState.RATE_LIMITED, detail="Codex reports usage is not allowed")
    return dataclasses.replace(snap, source="codex-app-server")


def refresh_due(auth_file: Path, now: float) -> str | None:
    """Why asking Codex now could make it refresh this login (``None``: it would not).

    Mirrors Codex's own rule: refresh 5 minutes before the access token's
    ``exp``, or, when that cannot be read, once ``last_refresh`` is 8 days old.
    """
    try:
        doc = json.loads(auth_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "the live auth.json is unreadable"
    doc = doc if isinstance(doc, dict) else {}
    tokens = doc.get("tokens") if isinstance(doc.get("tokens"), dict) else {}
    exp = jwt_claims(tokens.get("access_token")).get("exp")
    if isinstance(exp, int | float) and not isinstance(exp, bool):
        if exp - now > _MIN_TOKEN_LIFE_S:
            return None
    else:
        last = _iso_to_epoch(doc.get("last_refresh"))
        if last is not None and now - last < _REFRESH_INTERVAL_S - _MIN_TOKEN_LIFE_S:
            return None
    return (
        "the active login's token is due for refresh, which a Codex you started may do at the same time "
        "(refresh tokens are single-use); showing the last measurement until Codex has refreshed it"
    )


def _token_hash(auth_file: Path) -> str | None:
    """A digest of what a refresh changes, so the outcome is told without showing a token."""
    try:
        doc = json.loads(auth_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    doc = doc if isinstance(doc, dict) else {}
    tokens = doc.get("tokens") if isinstance(doc.get("tokens"), dict) else {}
    fields = [tokens.get("refresh_token"), tokens.get("access_token"), doc.get("last_refresh")]
    return hashlib.sha256(json.dumps(fields).encode()).hexdigest()


def _auth_failed(exc: jsonrpc.RpcError) -> bool:
    """Codex's "no login" answer, a refresh it gave up on, or a 401 from its backend."""
    text = str(exc).lower()
    return any(s in text for s in ("authentication required", "sign in again", "401 unauthorized"))


def _hswap_version() -> str:
    try:
        return importlib.metadata.version("harness-swap")
    except importlib.metadata.PackageNotFoundError:
        return "0"


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
    #: The provider's terms on switching accounts, shown when it is opted in to usage.remote/auto.enabled.
    terms = _TERMS

    @property
    def remote_usage(self) -> bool:
        return settings.opted_in("usage.remote", self.id)

    @property
    def usage_policy(self) -> UsagePolicy:  # type: ignore[override]
        return _REMOTE_POLICY if self.remote_usage else _PASSIVE_POLICY

    def list_accounts(self) -> list[Account]:
        accounts = super().list_accounts()
        if self.credential_store() != "file":  # Codex is not using auth.json, so it says nothing
            return [dataclasses.replace(a, active=None) for a in accounts]
        return accounts

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
        if not self.remote_usage:
            usage_status = experimental(
                "read passively from rate-limit snapshots in Codex's own session logs; updates only "
                f"when that account runs Codex on this machine. For live reads by Codex, {_ENABLE_REMOTE}"
            )
            rotation_status = unavailable(f"needs live usage; {_ENABLE_REMOTE}")
        else:
            usage_status = blocked or experimental(
                "asks Codex itself (`codex app-server`, the request /status uses) in each account's own "
                "home; not while a session runs that account, nor while the active login is due for "
                "a token refresh. Codex's app-server protocol, not a documented quota API"
            )
            rotation_status = blocked or experimental(f"switches on live usage. {_TERMS}")
        return {
            Capability.ACCOUNT_LIST: supported(),
            Capability.ACCOUNT_ADD: blocked or supported("current login, or --login in an isolated CODEX_HOME"),
            Capability.ACCOUNT_REMOVE: supported("forgets hswap's copy; the live login is untouched"),
            Capability.ACCOUNT_SWITCH: blocked or supported("swaps $CODEX_HOME/auth.json; restart running Codex"),
            Capability.NATIVE_ACCOUNT_SWITCH: unsupported("Codex has one login per CODEX_HOME"),
            Capability.CREDENTIAL_REFRESH: blocked or supported(
                f"`hswap {self.id} refresh` asks Codex (`codex app-server`, the request /status uses) in each "
                "account's own home, so Codex refreshes a due token and stores it there; skips an account a "
                "session runs, and the active login while Codex runs"
            ),
            Capability.USAGE_MONITORING: usage_status,
            Capability.AUTOMATIC_ROTATION: rotation_status,
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
        if self.remote_usage:
            return self._ask_codex(account, account_id)
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

    def _ask_codex(self, account: Account, account_id: str) -> UsageSnapshot:
        """One live read through ``codex app-server`` in the account's own home."""
        inst = self._require_installed()
        with self.usage_home(account) as (home, active):
            if home is None:
                return UsageSnapshot(UsageState.STALE, detail="in use by a running session; showing the last measurement")
            if active and (why := refresh_due(home / self.credential_file, time.time())):
                return UsageSnapshot(UsageState.STALE, detail=why)
            try:
                result = self._rate_limits(inst.executable, home)
            except jsonrpc.RpcError as exc:
                if not (exc.harness and _auth_failed(exc)):
                    raise
                return UsageSnapshot(
                    UsageState.AUTHENTICATION_REQUIRED,
                    source="codex-app-server",
                    detail="Codex has no usable login for this account; sign in again and re-add it",
                )
        answered_for = result.get("accountId") if isinstance(result, dict) else None
        if answered_for and answered_for != account_id:
            raise HswapError("Codex answered for a different account; not recording it")
        return snapshot_from_app_server(result, time.time())

    def _rate_limits(self, executable: str | None, home: Path) -> object:
        """``account/rateLimits/read`` from ``codex app-server`` run in ``home``."""
        env_add, home_args = self.home_overrides(home)
        argv = [str(executable), *home_args, "app-server", "--listen", "stdio://"]
        with jsonrpc.session(argv, {**os.environ, **env_add}, timeout=_RPC_TIMEOUT_S, version_tag=False) as rpc:
            rpc.request("initialize", {"clientInfo": {"name": "hswap", "version": _hswap_version()}})
            rpc.notify("initialized")
            return rpc.request("account/rateLimits/read", {"excludeResetCreditDetails": True})

    def keep_alive(self, account: Account) -> str:
        """Ask Codex something that needs the login, so it refreshes a due token in that home."""
        if account.auth_mode == "api_key":
            return "API-key login: nothing to refresh"
        inst = self._require_installed()
        with self.usage_home(account) as (home, active):
            if home is None:
                return "skipped: a running session keeps it fresh"
            if active and processes.find({self.executable}) != []:
                return f"skipped: {self.display_name} is running and refreshes the active login itself"
            auth = home / self.credential_file
            before, error = _token_hash(auth), None
            if before is None:
                raise HswapError("sign in again: this account's login is missing from its Codex home")
            try:
                self._rate_limits(inst.executable, home)
            except jsonrpc.RpcError as exc:
                error = exc
            changed = _token_hash(auth) != before
        if error is not None and error.harness and _auth_failed(error):
            raise HswapError("sign in again: Codex could not use or refresh this login") from None
        if changed:
            return "token refreshed"
        if error is not None and not error.harness:  # hswap's own text: timeout, exit, start failure
            raise HswapError(
                f"{error}; if Codex was refreshing the token, this account may need to sign in again"
            ) from None
        if error is not None:
            # Codex's own error text is not repeated: it may quote server responses.
            code = f" (error {error.code})" if error.code is not None else ""
            raise HswapError(f"Codex could not check this login{code}; nothing changed, try again later") from None
        return "token still valid"
