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
"""

from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import subprocess
from pathlib import Path

from harness_swap.adapters.base import (
    FileCredentialAdapter,
    parse_version,
    probe_installation,
)
from harness_swap.core.credentials import Identity, fingerprint, jwt_claims
from harness_swap.core.errors import (
    HarnessNotInstalled,
    HswapError,
    UnsupportedOperation,
)
from harness_swap.core.models import (
    Account,
    Capability,
    CapabilityStatus,
    Installation,
    SwitchResult,
    experimental,
    supported,
    unavailable,
    unsupported,
)
from harness_swap.core.paths import harness_home
from harness_swap.core.store import AccountStore
from harness_swap.infrastructure import spawn

NATIVE, LEGACY = "native", "legacy"


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

    def __init__(self) -> None:
        self._installation: Installation | None = None
        self._mode: str | None | bool = False  # False = not probed yet
        self._legacy = LegacyOpenCode()
        self._db_path: Path | None | bool = False

    # -- discovery ------------------------------------------------------------

    def installation(self) -> Installation:
        if self._installation is None:
            self._installation = probe_installation("opencode")
        return self._installation

    def _run(self, *args: str, capture: bool = True) -> subprocess.CompletedProcess:
        inst = self.installation()
        if not inst.installed:
            raise HarnessNotInstalled(f"OpenCode: {inst.detail}")
        if not capture:  # interactive: inherit the terminal
            return subprocess.run([inst.executable, *args], check=False)
        return spawn.run(
            [inst.executable, *args], capture_output=True, text=True, timeout=self.timeout
        )

    def mode(self) -> str | None:
        if self._mode is False:
            self._mode = None
            inst = self.installation()
            if inst.installed:
                out = self._run("auth", "switch", "--help")
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
        no_usage = unsupported("OpenCode has no quota interface (`opencode stats` is local token statistics)")
        if not inst.installed:
            off = unavailable(f"OpenCode is not installed ({inst.detail})")
            return {c: off for c in Capability} | {Capability.USAGE_MONITORING: no_usage}
        if mode is None:
            off = unavailable(
                f"OpenCode {inst.version} has no `auth switch` and is not a 1.x release; "
                "hswap does not guess at its credential storage"
            )
            return {c: off for c in Capability} | {Capability.USAGE_MONITORING: no_usage}
        common = {
            Capability.ACCOUNT_LIST: supported(),
            Capability.CREDENTIAL_REFRESH: unsupported("OpenCode refreshes its own logins"),
            Capability.USAGE_MONITORING: no_usage,
            Capability.AUTOMATIC_ROTATION: unsupported("no quota data to rotate on"),
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
            raise HswapError(f"`opencode auth list` failed: {(out.stderr or '').strip()[:300]}")
        try:
            data = json.loads(out.stdout)
        except ValueError:
            raise HswapError("`opencode auth list --format json` did not return JSON") from None
        return data if isinstance(data, list) else []

    def _database(self) -> Path | None:
        if self._db_path is False:
            self._db_path = None
            out = self._run("debug", "paths")
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

    def _native_accounts(self) -> list[Account]:
        listing = self._native_listing()
        active = self._active_flags()
        found = [
            (integration.get("id"), integration.get("name"), conn)
            for integration in listing
            for conn in integration.get("connections", [])
            if conn.get("type") == "credential" and conn.get("id")
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
        self, *, alias: str | None = None, provider: str | None = None, login: bool = False
    ) -> Account:
        if self._require_mode() == LEGACY:
            if login:
                raise UnsupportedOperation(
                    "account_add", "OpenCode 1.x has no isolated sign-in; run `opencode auth login`, then `add`"
                )
            return self._legacy.add_account(alias=alias, provider=provider)
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
            raise HswapError(f"`opencode auth logout` failed: {(out.stderr or '').strip()[:300]}")

    def switch_account(self, account: Account, *, force: bool = False) -> SwitchResult:
        if self._require_mode() == LEGACY:
            return self._legacy.switch_account(account, force=force)
        previous = next(
            (a for a in self._native_accounts() if a.provider == account.provider and a.active), None
        )
        out = self._run("auth", "switch", account.provider or "", account.identity)
        if out.returncode != 0:
            raise HswapError(f"`opencode auth switch` failed: {(out.stderr or '').strip()[:300]}")
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

    def set_alias(self, account: Account, alias: str | None) -> Account:
        stored = self.store.set_alias(account.slot, alias)
        return dataclasses.replace(account, alias=stored.alias)
