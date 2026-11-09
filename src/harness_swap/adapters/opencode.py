"""OpenCode adapter: a multi-provider harness, handled per installed version.

**Native (V2) mode** -- chosen when ``opencode auth switch`` exists (verified
on 2.2.5). OpenCode keeps several saved accounts per integration in its own
SQLite database and switches between them itself, so hswap only drives the
documented commands:

* list:   ``opencode auth list --format json``
* switch: ``opencode auth switch <integration> <credential-id>``
* add:    ``opencode auth login [<integration>]`` (a new login becomes a new
  saved account; earlier ones are kept)
* remove: ``opencode auth logout <integration> <credential-id>``

The database is never written. 2.2.5's JSON listing does not say which saved
account is active, so hswap reads just ``credential.id/integration_id/active``
through a read-only SQLite connection (``mode=ro``; the secret ``value``
column is never selected). If that schema is absent the account is shown
with ``active: unknown`` -- nothing else depends on it.

**Legacy mode** -- OpenCode 1.x keeps ``{provider: credential}`` in
``$XDG_DATA_HOME/opencode/auth.json``. hswap snapshots each provider's entry
and swaps only that provider's entry, keeping every other provider's login.
Verified with synthetic files only (no 1.x binary was available).

Any other version gets an explicit "unsupported version" rather than a
strategy that may not fit it.

**Usage (native mode, opt-in: ``usage.remote`` includes ``opencode``)** -- OpenCode
Go plan limits are read by asking OpenCode itself, ``opencode api
experimental.usage.limits`` (what its ``/usage`` view calls). OpenCode talks to
the Console and refreshes its own token inside its one background service, so
hswap never sees a token or calls a provider endpoint. The answer is about the
*active* ``opencode`` (OpenCode Console) login only; every other account keeps
its last measurement. The read holds hswap's switch lock (excluding hswap's own
switches) and re-checks the active flag afterwards, so a switch made inside
OpenCode meanwhile discards the answer. Because OpenCode refreshes its rotating
token on use, an active login within 10 minutes of expiry is not asked (its
``expires`` is the only value read from the secret column; no token is).
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path

from harness_swap.adapters.base import (
    FileCredentialAdapter,
    parse_version,
    probe_installation,
)
from harness_swap.core import settings
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.credentials import Identity, fingerprint, jwt_claims
from harness_swap.core.errors import (
    HarnessNotInstalled,
    HswapError,
    LockError,
    UnsupportedOperation,
)
from harness_swap.core.models import (
    Account,
    Capability,
    CapabilityStatus,
    Installation,
    QuotaWindow,
    SwitchResult,
    UsageSnapshot,
    UsageState,
    experimental,
    supported,
    unavailable,
    unsupported,
)
from harness_swap.core.paths import harness_home
from harness_swap.core.store import AccountStore, mkdir_private
from harness_swap.infrastructure import spawn
from harness_swap.infrastructure.locking import FileLock

NATIVE, LEGACY = "native", "legacy"

#: The one integration whose login carries a Console workspace (and so Go limits).
CONSOLE = "opencode"
#: Console route timeout is 15 s; the rest is the service starting up.
_USAGE_TIMEOUT_S = 60
#: Each read may start OpenCode's background service: keep it rare.
_USAGE_POLICY = UsagePolicy(min_interval_s=300.0, stale_after_s=1800.0, max_backoff_s=3600.0)
_REFRESH_MARGIN_MS = 600_000
_ONLY_ACTIVE = "measured only while it is the active OpenCode Console account"
_ENABLE_REMOTE = "enable with `hswap config set usage.remote <ids>` (include the harnesses already listed)"
#: Go meter -> (window name, length in seconds; None where OpenCode does not say).
_GO_WINDOWS = {"rolling": ("5h", 18000), "weekly": ("weekly", 604800), "monthly": ("monthly", None)}
_TERMS = (
    'OpenCode\'s Terms of Service (effective 2026-08-15) forbid using the services in a manner that "creates, '
    "maintains, or uses multiple accounts to circumvent usage limits, access restrictions, billing "
    'obligations" (https://opencode.ai/legal/terms-of-service), which automatic switching between '
    "OpenCode Console accounts to escape Go limits matches directly. Inactive accounts are measured only "
    "while they are active, so automatic switching rarely has evidence to act on. You are responsible for complying"
)


def _failure(out: subprocess.CompletedProcess) -> str:
    """One readable line from a failed OpenCode command, which prints stack traces."""
    lines = [line.strip() for line in (out.stderr or out.stdout or "").splitlines()]
    lines = [line for line in lines if line and not line.startswith(("at ", "[cause]", "}"))]
    best = next((line for line in lines if line.lower().startswith("error")), lines[0] if lines else None)
    return (best or f"exit status {out.returncode}")[:300]


class LegacyAuthFormat:
    """OpenCode 1.x ``auth.json``: one part per provider id."""

    secret_name = "auth.json"
    _TYPES = ("oauth", "api", "wellknown")

    def parts(self, doc: dict) -> dict[str, dict]:
        return {
            provider: entry
            for provider, entry in doc.items()
            if isinstance(entry, dict) and entry.get("type") in self._TYPES
        }

    def identify(self, part_key: str, part: dict) -> Identity | None:
        if part.get("type") in ("api", "wellknown"):
            key = part.get("key") or part.get("token")
            if not isinstance(key, str) or not key:
                return None
            fp = fingerprint(key)
            return Identity(f"apikey/{fp}", f"{part_key} API key {fp}", part_key, "api_key")
        subject = part.get("accountId")
        claims = jwt_claims(part.get("access") or "")
        subject = subject or claims.get("sub")
        if not subject:
            return None  # an opaque token with no stable id cannot be told apart
        label = claims.get("email") or f"{part_key} account {str(subject)[:8]}"
        return Identity(f"oauth/{subject}", label, part_key, "oauth")

    def merge(self, doc: dict | None, part_key: str, part: dict) -> dict:
        merged = dict(doc or {})
        merged[part_key] = part
        return merged


class LegacyOpenCode(FileCredentialAdapter):
    id = "opencode"
    display_name = "OpenCode"
    executable = "opencode"
    home_env = "XDG_DATA_HOME"  # unused for sessions: legacy mode has none
    default_home = ".local/share/opencode"
    fmt = LegacyAuthFormat()

    @property
    def home(self) -> Path:
        xdg = os.environ.get("XDG_DATA_HOME")
        return Path(xdg) / "opencode" if xdg else Path.home() / self.default_home

    @property
    def store(self) -> AccountStore:
        # Kept apart from native mode's numbering, so an upgrade to 2.x
        # never mixes snapshot slots with saved-account slots.
        return AccountStore(harness_home(self.id) / "legacy")


class OpenCodeAdapter:
    id = "opencode"
    display_name = "OpenCode"
    providers: tuple[str, ...] = ()  # any provider OpenCode is configured for
    #: Seconds allowed for one OpenCode command (it may start its service).
    timeout = 120
    usage_policy = _USAGE_POLICY
    #: The provider's terms on switching accounts, shown when it is opted in to usage.remote/auto.enabled.
    terms = _TERMS

    def __init__(self) -> None:
        self._installation: Installation | None = None
        self._mode: str | None | bool = False  # False = not probed yet
        self._legacy = LegacyOpenCode()
        self._db_path: Path | None | bool = False
        self._mode_error = ""

    # -- discovery ------------------------------------------------------------

    def installation(self) -> Installation:
        if self._installation is None:
            self._installation = probe_installation("opencode")
        return self._installation

    def _run(self, *args: str, capture: bool = True) -> subprocess.CompletedProcess:
        inst = self.installation()
        if not inst.installed:
            raise HarnessNotInstalled(f"OpenCode: {inst.detail}")
        try:
            if not capture:  # interactive: inherit the terminal
                return subprocess.run([inst.executable, *args], check=False)
            return spawn.run(
                [inst.executable, *args], capture_output=True, text=True, timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            raise HswapError(f"`opencode {' '.join(args)}` did not finish within {self.timeout}s") from None
        except OSError as exc:
            raise HswapError(f"could not run opencode: {exc}") from None

    def mode(self) -> str | None:
        if self._mode is False:
            self._mode = None
            inst = self.installation()
            if inst.installed:
                try:
                    out = self._run("auth", "switch", "--help")
                except HswapError as exc:
                    self._mode_error = str(exc)
                    return None
                if out.returncode == 0 and "auth switch" in (out.stdout or ""):
                    self._mode = NATIVE
                else:
                    version = parse_version(inst.version)
                    if version is not None and version[0] < 2:
                        self._mode = LEGACY
        return self._mode  # type: ignore[return-value]

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        inst = self.installation()
        mode = self.mode()
        if not inst.installed:
            return {c: unavailable(f"OpenCode is not installed ({inst.detail})") for c in Capability}
        if mode is None:
            off = unavailable(
                self._mode_error
                or f"OpenCode {inst.version} has no `auth switch` and is not a 1.x release; "
                "hswap does not guess at its credential storage"
            )
            return {c: off for c in Capability}
        if mode == LEGACY:
            usage = unsupported("OpenCode 1.x has no usage interface (`opencode stats` is local token statistics)")
            rotation = unsupported("no quota data to rotate on")
        elif not settings.opted_in("usage.remote", self.id):
            usage = unavailable(_ENABLE_REMOTE)
            rotation = unavailable(f"needs live usage; {_ENABLE_REMOTE}")
        else:
            usage = experimental(
                "asks OpenCode itself (`opencode api experimental.usage.limits`, what its /usage view uses) for "
                "OpenCode Go 5h/weekly/monthly limits; only the active OpenCode Console login is measured, "
                "others keep their last measurement. OpenCode does not report usage for API-key logins. Not verified against "
                "a live Go account"
            )
            rotation = experimental(f"switches on live usage. {_TERMS}")
        common = {
            Capability.ACCOUNT_LIST: supported(),
            Capability.CREDENTIAL_REFRESH: unsupported("OpenCode refreshes its own logins"),
            Capability.USAGE_MONITORING: usage,
            Capability.AUTOMATIC_ROTATION: rotation,
            Capability.PARALLEL_SESSIONS: unsupported(
                "the active account is global to OpenCode; per-session account selection is not documented"
            ),
            Capability.SESSION_RESUME: unsupported("no isolated sessions to resume"),
            Capability.CREDENTIAL_HOT_RELOAD: unsupported(
                "not documented whether open sessions pick up a switch; restart them to be sure"
            ),
        }
        if mode == NATIVE:
            return common | {
                Capability.ACCOUNT_ADD: supported("runs `opencode auth login`; earlier logins are kept"),
                Capability.ACCOUNT_REMOVE: supported("runs `opencode auth logout <integration> <id>`"),
                Capability.ACCOUNT_SWITCH: supported("runs `opencode auth switch <integration> <id>`"),
                Capability.NATIVE_ACCOUNT_SWITCH: supported("OpenCode keeps several saved accounts per integration"),
                Capability.CREDENTIAL_REFRESH: unsupported(
                    "OpenCode keeps inactive logins in its own database and refreshes an account only when it is "
                    "the active one; hswap does not write that database, so to keep an idle account usable switch "
                    "to it (`hswap opencode switch`) before its token lapses (OpenCode Console tokens last weeks)"
                ),
            }
        return common | {
            Capability.ACCOUNT_ADD: experimental("snapshots provider entries of the legacy auth.json"),
            Capability.ACCOUNT_REMOVE: experimental("forgets hswap's copy; the live login is untouched"),
            Capability.ACCOUNT_SWITCH: experimental("replaces one provider's entry in the legacy auth.json"),
            Capability.NATIVE_ACCOUNT_SWITCH: unsupported("OpenCode 1.x keeps one login per provider"),
        }

    def _require_mode(self) -> str:
        mode = self.mode()
        if mode is None:
            status = self.capabilities()[Capability.ACCOUNT_LIST]
            raise UnsupportedOperation(str(Capability.ACCOUNT_LIST), status.reason)
        return mode

    # -- native helpers --------------------------------------------------------

    @property
    def store(self) -> AccountStore:
        return AccountStore(harness_home(self.id))

    def _native_listing(self) -> list[dict]:
        out = self._run("auth", "list", "--format", "json")
        if out.returncode != 0:
            raise HswapError(f"`opencode auth list` failed: {_failure(out)}")
        try:
            data = json.loads(out.stdout)
        except ValueError:
            data = None
        if not isinstance(data, list):
            raise HswapError("`opencode auth list --format json` did not return a JSON list")
        return [item for item in data if isinstance(item, dict)]

    def _database(self) -> Path | None:
        if self._db_path is False:
            self._db_path = None
            try:
                out = self._run("debug", "paths")
            except HswapError:
                return None
            for line in (out.stdout or "").splitlines():
                name, _, value = line.strip().partition(" ")
                if name == "db" and value.strip():
                    self._db_path = Path(value.strip())
        return self._db_path  # type: ignore[return-value]

    def _active_flags(self) -> dict[str, bool] | None:
        """``{credential id: active}`` from a read-only look at OpenCode's DB."""
        db = self._database()
        if db is None or not db.exists():
            return None
        try:
            con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=2)
            try:
                rows = con.execute("SELECT id, integration_id, active FROM credential").fetchall()
            finally:
                con.close()
        except sqlite3.Error:
            return None
        by_integration: dict[str, list[tuple[str, int | None]]] = {}
        for cred_id, integration, active in rows:
            by_integration.setdefault(integration, []).append((cred_id, active))
        flags = {}
        for creds in by_integration.values():
            if any(a == 1 for _, a in creds):
                flags.update({c: a == 1 for c, a in creds})
            elif len(creds) == 1:
                flags[creds[0][0]] = True  # the only saved account is the one in use
        return flags

    def _expires_ms(self, identity: str) -> int | None:
        """Only the integer ``expires`` of a login (never a token); None when unreadable."""
        db = self._database()
        if db is None or not db.exists():
            return None
        try:
            con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=2)
            try:
                row = con.execute(
                    "SELECT json_extract(value, '$.expires') FROM credential WHERE id = ?", (identity,)
                ).fetchone()
            finally:
                con.close()
        except sqlite3.Error:
            return None
        value = row[0] if row else None
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def _native_accounts(self) -> list[Account]:
        listing = self._native_listing()
        active = self._active_flags()
        found = [
            (integration.get("id"), integration.get("name"), conn)
            for integration in listing
            for conn in (integration.get("connections") or [])
            if isinstance(conn, dict) and conn.get("type") == "credential" and conn.get("id")
        ]
        # hswap numbers saved accounts (and keeps aliases); OpenCode keeps the secrets.
        with self.store.lock():
            stored = self.store.load()
            live_ids = set()
            for integration, _name, conn in found:
                live_ids.add((conn["id"], integration))
                self.store.upsert(
                    stored,
                    identity=conn["id"],
                    label=conn.get("label") or conn["id"],
                    provider=integration,
                    auth_mode=conn.get("method"),
                    part_key=None,
                )
            stored = [s for s in stored if (s.identity, s.provider) in live_ids]
            self.store.save(stored)
        names = {integration: name for integration, name, _ in found}
        return [
            Account(
                harness=self.id,
                identity=s.identity,
                label=s.label,
                provider=s.provider,
                slot=s.slot,
                alias=s.alias,
                auth_mode=s.auth_mode,
                active=None if active is None else active.get(s.identity, False),
                details={"integration": names.get(s.provider) or s.provider},
            )
            for s in sorted(stored, key=lambda s: s.slot)
        ]

    # -- roles --------------------------------------------------------------------

    def list_accounts(self) -> list[Account]:
        if self._require_mode() == LEGACY:
            return self._legacy.list_accounts()
        return self._native_accounts()

    def add_account(
        self, *, alias: str | None = None, provider: str | None = None, login: bool = False,
        email: str | None = None,
    ) -> Account:
        if self._require_mode() == LEGACY:
            if login:
                raise UnsupportedOperation(
                    "account_add", "OpenCode 1.x has no isolated sign-in; run `opencode auth login`, then `add`"
                )
            return self._legacy.add_account(alias=alias, provider=provider)
        if email:
            raise UnsupportedOperation("account_add", "`opencode auth login` cannot be checked against --email")
        before = {a.key for a in self._native_accounts()}
        code = self._run("auth", "login", *([provider] if provider else []), capture=False).returncode
        if code != 0:
            raise HswapError(f"`opencode auth login` exited with status {code}; nothing added")
        new = [a for a in self._native_accounts() if a.key not in before]
        if not new:
            raise HswapError("no new saved account appeared after `opencode auth login`")
        account = new[-1]
        return self.set_alias(account, alias) if alias else account

    def remove_account(self, account: Account) -> None:
        if self._require_mode() == LEGACY:
            return self._legacy.remove_account(account)
        out = self._run("auth", "logout", account.provider or "", account.identity)
        if out.returncode != 0:
            raise HswapError(f"`opencode auth logout` failed: {_failure(out)}")

    def switch_account(self, account: Account, *, force: bool = False) -> SwitchResult:
        if self._require_mode() == LEGACY:
            return self._legacy.switch_account(account, force=force)
        # Serialises hswap's own switches (a separate file: the store lock is
        # taken inside, and flock is not reentrant). OpenCode's own concurrent
        # writers are outside hswap's control.
        mkdir_private(self.store.root)
        with FileLock(self.store.root / ".switch.lock", timeout=120):
            previous = next(
                (a for a in self._native_accounts() if a.provider == account.provider and a.active), None
            )
            out = self._run("auth", "switch", account.provider or "", account.identity)
            if out.returncode != 0:
                raise HswapError(f"`opencode auth switch` failed: {_failure(out)}")
            flags = self._active_flags()
            if flags is not None and not flags.get(account.identity):
                raise HswapError("OpenCode reported success but a different account is still active")
        return SwitchResult(
            harness=self.id,
            current=dataclasses.replace(account, active=True),
            previous=previous if previous and previous.key != account.key else None,
            restart_required=False,
            notes=(
                (
                    f"switched the active {account.provider} account in OpenCode's own store; "
                    "other integrations are unchanged"
                ),
            ),
        )

    # -- usage ------------------------------------------------------------------------

    def read_usage(self, account: Account) -> UsageSnapshot:
        if self.mode() != NATIVE:
            return UsageSnapshot(UsageState.UNSUPPORTED, detail="OpenCode 1.x has no usage interface")
        if not settings.opted_in("usage.remote", self.id):
            return UsageSnapshot(UsageState.UNSUPPORTED, detail=_ENABLE_REMOTE)
        if account.provider != CONSOLE or account.auth_mode == "key":
            return UsageSnapshot(
                UsageState.UNSUPPORTED, detail="OpenCode reports Go limits only for OpenCode Console logins"
            )
        self._database()  # resolved before the lock: it may spawn opencode
        # The route answers for whichever login is active, so a switch must not
        # slip in between the check and the answer.
        mkdir_private(self.store.root)
        try:
            with FileLock(self.store.root / ".switch.lock", timeout=30):
                flags = self._active_flags()
                if flags is None:
                    return UsageSnapshot(UsageState.STALE, detail="cannot tell which OpenCode account is active")
                if not flags.get(account.identity):
                    return UsageSnapshot(UsageState.STALE, detail=_ONLY_ACTIVE)
                expires = self._expires_ms(account.identity)
                if expires is not None and expires < time.time() * 1000 + _REFRESH_MARGIN_MS:
                    return UsageSnapshot(
                        UsageState.STALE,
                        detail="the OpenCode login is about to refresh; showing the last measurement",
                    )
                out = self._ask_limits()
                after = self._active_flags()
                if not after or not after.get(account.identity):
                    return UsageSnapshot(
                        UsageState.STALE,
                        detail="the active OpenCode account changed during the read; showing the last measurement",
                    )
        except LockError:
            return UsageSnapshot(UsageState.STALE, detail="an account switch is in progress; showing the last measurement")
        return self._limits_snapshot(out)

    def _ask_limits(self) -> subprocess.CompletedProcess:
        inst = self.installation()
        if not inst.installed:
            raise HarnessNotInstalled(f"OpenCode: {inst.detail}")
        try:
            return spawn.run(
                [str(inst.executable), "api", "experimental.usage.limits"],
                capture_output=True,
                text=True,
                timeout=_USAGE_TIMEOUT_S,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            raise HswapError(f"`opencode api experimental.usage.limits` did not finish within {_USAGE_TIMEOUT_S}s") from None
        except OSError as exc:
            raise HswapError(f"could not run opencode: {type(exc).__name__}") from None

    @staticmethod
    def _limits_snapshot(out: subprocess.CompletedProcess) -> UsageSnapshot:
        lines = f"{out.stdout or ''}\n{out.stderr or ''}".splitlines()
        text = "\n".join(line for line in lines if not line.strip().startswith("at "))
        doc = None
        # The whole of stdout, else its last JSON line (a service start-up may print before it).
        for candidate in (out.stdout, next((ln for ln in reversed((out.stdout or "").splitlines()) if ln.startswith("{")), None)):
            try:
                doc = json.loads(candidate)
                break
            except (TypeError, ValueError):
                continue
        failed = out.returncode != 0 or not isinstance(doc, dict) or "data" not in doc
        if failed:
            # A 401 from the Console (503 from the route) means the login was rejected.
            if re.search(r"(?<![:\d])401(?![:\d])|\bUnauthorized\b", text):
                return UsageSnapshot(
                    UsageState.AUTHENTICATION_REQUIRED,
                    source="opencode",
                    detail="OpenCode Console rejected this login; sign in again (`opencode auth login opencode`)",
                )
            tag = doc.get("_tag") if isinstance(doc, dict) else None
            why = tag if isinstance(tag, str) and tag.isalnum() else f"exit status {out.returncode}"
            raise HswapError(f"`opencode api experimental.usage.limits` failed ({why})")
        data = doc["data"]
        if data is None:
            return UsageSnapshot(
                UsageState.UNKNOWN,
                source="opencode",
                detail="OpenCode reports no usage limits for the active login (not signed in to a Console workspace)",
            )
        go = data.get("go") if isinstance(data, dict) else None
        if not isinstance(go, dict):
            return UsageSnapshot(
                UsageState.UNSUPPORTED, source="opencode", detail="this workspace has no OpenCode Go plan quota"
            )
        windows, limited = [], False
        for key, (name, length) in _GO_WINDOWS.items():
            meter = go.get(key)
            if not isinstance(meter, dict) or not isinstance(meter.get("percent"), int | float):
                continue
            percent = min(max(float(meter["percent"]), 0.0), 100.0)
            resets = meter.get("resetsAt")
            resets_s = resets / 1000.0 if isinstance(resets, int | float) and not isinstance(resets, bool) else None
            limited = limited or meter.get("limited") is True or percent >= 100
            windows.append(QuotaWindow(name, percent, resets_s, length))
        if not windows:
            return UsageSnapshot(UsageState.UNKNOWN, source="opencode", detail="OpenCode returned no Go meters")
        return UsageSnapshot(
            UsageState.RATE_LIMITED if limited else UsageState.AVAILABLE,
            windows=tuple(windows),
            measured_at=time.time(),
            source="opencode",
            detail="an OpenCode Go limit is reached" if limited else "",
        )

    def set_alias(self, account: Account, alias: str | None) -> Account:
        stored = self.store.set_alias(account.slot, alias)
        return dataclasses.replace(account, alias=stored.alias)
