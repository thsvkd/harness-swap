"""Grok Build adapter.

Verified against Grok Build 1.0.70 and its bundled user guide
(``~/.grok/docs/user-guide/02-authentication.md``, ``05-configuration.md``):

* ``$GROK_HOME`` (default ``~/.grok``) relocates the whole Grok home,
  including ``auth.json``. ``GROK_AUTH_PATH`` is *not* used: the config
  reloader ignores it and would keep watching the default file.
* ``auth.json`` (0600, guarded by ``auth.json.lock``) maps a login *scope*
  (``<issuer>::<client id>``, or ``xai::api_key``) to its credential, and
  can hold several scopes. Which one Grok uses is Grok's decision (session
  tokens outrank API keys), so a switch leaves the target as the only
  credential scope: other scopes that hswap stores are synced back first and
  dropped; one it does not store makes the switch stop (``--force`` stashes
  the file first). Non-credential keys are kept.
* "Grok picks up changes to ``~/.grok/auth.json`` automatically ... without
  a restart" (documented hot reload), so a switch reaches running sessions.
* ``grok login`` *replaces* the cached session, so ``add --login`` runs it
  in a throwaway ``GROK_HOME`` and imports the result.
* Usage: Grok's TUI ``/usage`` shows credit usage from its CLI proxy. With
  ``usage.remote`` including ``grok``, hswap asks Grok itself for the same
  data -- ``grok agent --no-leader stdio`` (ACP JSON-RPC) and its
  ``_x.ai/billing`` extension -- with ``GROK_HOME`` set to the account's own
  home, so Grok refreshes and stores its tokens under its own
  ``auth.json.lock`` and hswap never calls xAI. The answer is one included-
  credit percentage for the current weekly or monthly period plus dollar
  balances, not Codex-style 5 h / 7 d windows. ``_x.ai/billing`` is an
  undocumented ACP extension, so this is reported experimental. API-key
  logins have no billing data. The active login is asked only while its
  access token has more than 10 minutes left: a Grok the user started may
  refresh the same refresh token, and Grok deletes the credential after a
  permanent refresh failure.
* Keep-alive (``hswap grok refresh``): the same ``_x.ai/billing`` question,
  without the opt-in, makes Grok refresh a due token in the account's own home
  under its own lock. The active login is touched only while no Grok runs on
  this machine (then nothing else can be refreshing it). The answer compares a
  hash of the scope's access and refresh tokens before and after.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from harness_swap.adapters.base import FileCredentialAdapter
from harness_swap.core import settings
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.credentials import Identity, fingerprint, jwt_claims
from harness_swap.core.errors import CredentialError, HswapError
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
from harness_swap.infrastructure import jsonrpc, processes

#: The active login is asked about only with more token life than this left.
_MIN_TOKEN_LIFE_S = 600.0
#: Grok runs under emulation on some machines; start-up alone can take tens of seconds.
_RPC_TIMEOUT_S = 120.0
#: Each read starts a Grok process and makes a request: keep it rare.
_POLICY = UsagePolicy(min_interval_s=300.0, stale_after_s=1800.0, max_backoff_s=3600.0)
#: ``tier`` claim of Grok's access token (grok-build source, ``jwt_tier_claim``).
_TIERS = ("free", "supergrok", "x_basic", "x_premium", "x_premium_plus", "supergrok_heavy", "supergrok_lite", "supergrok_plus")
_SOURCE = "grok-acp"
_ENABLE_REMOTE = "enable with `hswap config set usage.remote <ids>` (include the harnesses already listed)"
_TERMS = (
    'xAI\'s Acceptable Use Policy (effective 2026-08-14) forbids "circumventing any rate limits or restrictions" '
    'and "Accessing the Services through unauthorized automated or non-human means" '
    "(https://x.ai/legal/acceptable-use-policy); xAI has not said whether switching between your own accounts "
    "counts. You are responsible for complying"
)


def _epoch(value: object) -> float | None:
    """Seconds since the epoch from epoch seconds/milliseconds or an ISO 8601 string."""
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            try:
                dt = datetime.fromisoformat(value)
            except ValueError:
                return None
            return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()  # no zone: read as UTC
    if isinstance(value, int | float) and not isinstance(value, bool):
        return value / 1000 if value > 1e11 else float(value)
    return None


def _usd(cents: object) -> float | None:
    """A ``Cent`` (``{"val": cents}``, or a bare number) in dollars."""
    val = cents.get("val") if isinstance(cents, dict) else cents
    return val / 100 if isinstance(val, int | float) and not isinstance(val, bool) else None


def snapshot_from_billing(result: object, plan: str | None, now: float) -> UsageSnapshot:
    """Normalise Grok's ``_x.ai/billing`` answer (a ``BillingConfigResponse``)."""
    if not isinstance(result, dict):
        raise HswapError("Grok answered without billing data")
    cfg = result["config"] if isinstance(result.get("config"), dict) else result
    period = cfg.get("currentPeriod") if isinstance(cfg.get("currentPeriod"), dict) else {}
    start, end = _epoch(period.get("start")), _epoch(period.get("end"))
    balance = {
        name: usd for name in ("prepaidBalance", "onDemandCap", "onDemandUsed") if (usd := _usd(cfg.get(name))) is not None
    }
    # Filled by Grok from /v1/settings; where it sits and how it is spelled is unverified.
    tiers = (d.get(k) for d in (cfg, result) for k in ("subscriptionTier", "subscription_tier"))
    plan = next((t for t in tiers if isinstance(t, str) and t), plan)
    common = {"measured_at": now, "source": _SOURCE, "plan": plan, "balance": {"currency": "USD", **balance} if balance else None}
    percent = cfg.get("creditUsagePercent")
    if not isinstance(percent, int | float) or isinstance(percent, bool):
        return UsageSnapshot(UsageState.UNKNOWN, detail="Grok reported no included-credit usage", **common)
    window = QuotaWindow(
        name=str(period.get("type") or "period"),
        used_percent=float(percent),
        resets_at=end,
        window_seconds=int(end - start) if start is not None and end is not None and end > start else None,
    )
    if percent >= 100:
        return UsageSnapshot(UsageState.RATE_LIMITED, (window,), detail="included credits used up", **common)
    return UsageSnapshot(UsageState.AVAILABLE, (window,), **common)


class GrokAuthFormat:
    secret_name = "auth.json"
    exclusive = True

    def parts(self, doc: dict) -> dict[str, dict]:
        return {
            scope: entry
            for scope, entry in doc.items()
            if isinstance(entry, dict) and isinstance(entry.get("key"), str)
        }

    def identify(self, part_key: str, part: dict) -> Identity | None:
        if part.get("auth_mode") == "api_key" or part_key.endswith("::api_key"):
            fp = fingerprint(part["key"])
            return Identity(f"apikey/{fp}", f"API key {fp}", "xai", "api_key")
        user_id = part.get("user_id")
        if not user_id:
            return None
        team_id = part.get("team_id") or ""
        return Identity(
            identity=f"{user_id}/{team_id}",
            label=part.get("email") or str(user_id),
            provider="xai",
            auth_mode=part.get("auth_mode") or "oauth",
            meta={"issuer": part.get("oidc_issuer") or part_key.split("::")[0]},
        )

    def merge(self, doc: dict | None, part_key: str, part: dict) -> dict:
        merged = dict(doc or {})
        merged[part_key] = part
        return merged


class GrokAdapter(FileCredentialAdapter):
    id = "grok"
    display_name = "Grok Build"
    providers = ("xai",)
    executable = "grok"
    home_env = "GROK_HOME"
    default_home = ".grok"
    harness_lock_name = "auth.json.lock"
    # User-facing configuration and content; session history stays per account.
    shared_names = ("config.toml", "rules", "skills", "memory", "installed-plugins", "trusted_folders.toml")
    hot_reload = True
    fmt = GrokAuthFormat()
    #: The provider's terms on switching accounts, shown when it is opted in to usage.remote/auto.enabled.
    terms = _TERMS
    usage_policy = _POLICY

    @property
    def remote_usage(self) -> bool:
        return settings.opted_in("usage.remote", self.id)

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        inst = self.installation()
        blocked = None if inst.installed else unavailable(f"Grok Build is not installed ({inst.detail})")
        if self.remote_usage:
            usage_status = blocked or experimental(
                "asks Grok itself (`grok agent stdio`, the `_x.ai/billing` data /usage shows) in each account's "
                "own home; not while a session runs that account, nor while the active login's token is within "
                "10 minutes of expiry. An undocumented ACP extension; API-key logins have no billing data"
            )
            rotation_status = blocked or experimental(f"switches on live credit usage. {_TERMS}")
        else:
            usage_status = unavailable(f"Grok reports credit usage when asked (what /usage shows); {_ENABLE_REMOTE}")
            rotation_status = unavailable(f"needs live usage; {_ENABLE_REMOTE}")
        return {
            Capability.ACCOUNT_LIST: supported(),
            Capability.ACCOUNT_ADD: blocked or supported("current login, or --login in an isolated GROK_HOME"),
            Capability.ACCOUNT_REMOVE: supported("forgets hswap's copy; the live login is untouched"),
            Capability.ACCOUNT_SWITCH: blocked or supported("replaces one login scope in $GROK_HOME/auth.json"),
            Capability.NATIVE_ACCOUNT_SWITCH: unsupported("`grok login` replaces the single cached session"),
            Capability.CREDENTIAL_REFRESH: blocked
            or supported(
                "`hswap grok refresh` asks Grok (`grok agent stdio`, `_x.ai/billing`) in each account's own home, "
                "so Grok refreshes a due token there under its own lock; skips accounts a session runs, and the "
                "active login while Grok is running. API-key logins have nothing to refresh"
            ),
            Capability.USAGE_MONITORING: usage_status,
            Capability.AUTOMATIC_ROTATION: rotation_status,
            Capability.PARALLEL_SESSIONS: blocked
            or experimental(
                "per-account GROK_HOME with shared config, rules, skills, memory and plugins linked in; "
                "session history is per account"
            ),
            Capability.SESSION_RESUME: supported("`run <account> -- --continue`; history is per account home"),
            Capability.CREDENTIAL_HOT_RELOAD: supported("documented: Grok reloads auth.json on its next request"),
        }

    def read_usage(self, account: Account) -> UsageSnapshot:
        if account.auth_mode == "api_key":
            return UsageSnapshot(UsageState.UNSUPPORTED, detail="API-key logins have no Grok billing data")
        inst = self._require_installed()
        with self.usage_home(account) as (home, active):
            if home is None:
                return UsageSnapshot(UsageState.STALE, detail="in use by a running session; showing the last measurement")
            if not active and (why := self._maybe_live(account)):
                return UsageSnapshot(UsageState.STALE, detail=f"{why}; showing the last measurement")
            entry = self._entry(home / self.credential_file, account.identity)
            if active and (why := token_expiring(entry, time.time())):
                return UsageSnapshot(UsageState.STALE, detail=why)
            try:
                result = self._billing(str(inst.executable), home)
            except jsonrpc.RpcError as exc:
                text = str(exc).lower()
                if "requires auth with grok.com" in text:
                    return UsageSnapshot(UsageState.UNSUPPORTED, source=_SOURCE, detail="this login has no Grok billing data")
                if "authentication required" not in text:
                    raise
                return UsageSnapshot(
                    UsageState.AUTHENTICATION_REQUIRED,
                    source=_SOURCE,
                    detail="Grok has no usable login for this account; sign in again and re-add it",
                )
        tier = jwt_claims((entry or {}).get("key")).get("tier")
        plan = _TIERS[tier] if isinstance(tier, int) and 0 <= tier < len(_TIERS) else None
        return snapshot_from_billing(result, plan, time.time())

    def keep_alive(self, account: Account) -> str:
        if account.auth_mode == "api_key":
            return "API-key login: nothing to refresh"
        inst = self._require_installed()
        with self.usage_home(account) as (home, active):
            if home is None:
                return "skipped: a running session keeps it fresh"
            # Grok processes elsewhere hold the active refresh token in memory; only refresh
            # it when none runs (unknown counts as running).
            if active and processes.find({self.executable}) != []:
                return f"skipped: {self.display_name} is running and refreshes the active login itself"
            if not active and (why := self._maybe_live(account)):
                return f"skipped: {why}"
            auth_file = home / self.credential_file
            before = self._entry(auth_file, account.identity)
            if before is None:
                raise HswapError("sign in again: this account's login is missing from its Grok home")
            try:
                self._billing(str(inst.executable), home)
            except jsonrpc.RpcError as exc:
                text = str(exc).lower()
                if "authentication required" in text:
                    raise HswapError("sign in again: Grok has no usable login for this account") from None
                # Billing is refused for non-grok.com logins after authentication, so the token was still checked.
                if not exc.harness:  # hswap's own text: timeout, exit, start failure
                    raise HswapError(str(exc)) from None
                if "requires auth with grok.com" not in text:
                    # Grok's own error text is not repeated: it may quote server responses.
                    code = f" (error {exc.code})" if exc.code is not None else ""
                    raise HswapError(f"Grok could not check this login{code}") from None
            after = self._entry(auth_file, account.identity)
        if after is None:
            raise HswapError("sign in again: Grok removed this login after its token refresh failed")
        return "token refreshed" if _token_hash(after) != _token_hash(before) else "token still valid"

    def _billing(self, executable: str, home: Path) -> object:
        """Ask Grok (``_x.ai/billing`` over ACP) with ``home`` as its ``GROK_HOME``."""
        env_add, home_args = self.home_overrides(home)
        argv = [executable, *home_args, "agent", "--no-leader", "stdio"]
        with jsonrpc.session(argv, {**os.environ, **env_add}, timeout=_RPC_TIMEOUT_S, version_tag=True) as rpc:
            rpc.request("initialize", {"protocolVersion": 1, "clientCapabilities": {}})
            return rpc.request("_x.ai/billing", {})

    def _maybe_live(self, account: Account) -> str | None:
        """Why ``account``'s stored copy must not be used now (``None``: it is not live).

        A second look after usage_home chose the stored copy: if the account is
        live by now, that copy may hold a refresh token Grok has already rotated
        in the default home, and refreshing it could revoke the live login.
        """
        try:
            live = self.credentials.live_identities()
        except CredentialError:
            return "Grok's live auth.json cannot be read right now, so this account may be live"
        if any(ident.identity == account.identity for ident in live.values()):
            return "this account just became the live login"
        return None

    def _entry(self, auth_file: Path, identity: str) -> dict | None:
        """This account's scope entry in ``auth_file`` (``None`` if absent or unreadable)."""
        try:
            doc = json.loads(auth_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        for key, part in self.fmt.parts(doc if isinstance(doc, dict) else {}).items():
            ident = self.fmt.identify(key, part)
            if ident and ident.identity == identity:
                return part
        return None


def _token_hash(entry: dict) -> str:
    """A digest of the refresh-relevant fields, to tell whether Grok rotated them without showing them."""
    return hashlib.sha256(json.dumps([entry.get("key"), entry.get("refresh_token")]).encode()).hexdigest()


def token_expiring(entry: dict | None, now: float) -> str | None:
    """Why asking Grok now could make it refresh the active login (``None``: it would not).

    Uses the earlier of the stored ``expires_at`` and the access token's ``exp``.
    """
    candidates = [_epoch((entry or {}).get("expires_at")), _epoch(jwt_claims((entry or {}).get("key")).get("exp"))]
    known = [c for c in candidates if c is not None]
    if not known:
        return "the active login's token expiry is unreadable, so Grok might refresh it while a Grok you started does"
    if min(known) - now > _MIN_TOKEN_LIFE_S:
        return None
    return (
        "the active login's token is due for refresh, which a Grok you started may do at the same time; "
        "showing the last measurement until Grok has refreshed it"
    )
