"""Google Antigravity CLI (``agy``) adapter.

Researched against agy 1.4.8 on Linux (evidence and its classification:
docs/harness-compatibility.md):

* agy tries the OS keyring first and falls back to
  ``~/.gemini/antigravity-cli/antigravity-oauth-token`` (JSON: Go
  ``oauth2.Token`` under ``token`` plus ``auth_method`` and
  ``id_token_email``). The file is used on headless Linux (no D-Bus session
  bus / Secret Service); macOS and Windows keep the login in the system
  keychain, so file switching is reported unavailable there.
* The state directory moves only with the hidden flag ``--gemini_dir=<abs>``
  (no environment variable works); each such directory gets its own
  ``installation_id``.
* A running agy keeps the signed-in account in memory (no hot reload):
  switching affects new agy processes only.
* Usage is read by asking agy itself: ``agy -p /usage --output-format json``
  (no agent turn, no quota spent), in the account's own home, so agy -- not
  hswap -- refreshes that copy of the login. Opt-in via ``usage.remote``.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from harness_swap.adapters.base import FileCredentialAdapter
from harness_swap.core import settings
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.credentials import Identity
from harness_swap.core.errors import HswapError, UnsupportedOperation
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
from harness_swap.infrastructure import processes

TOKEN_FILE = "antigravity-cli/antigravity-oauth-token"
_WINDOW_S = {"5h": 5 * 3600, "weekly": 7 * 86400}
#: Ask agy about the active login only while its access token has this much life
#: left, so the call never refreshes it next to an agy the user started.
_MIN_TOKEN_LIFE_S = 600
_USAGE_TIMEOUT_S = 60
_OPT_IN = "enable with `hswap config set usage.remote <ids>`"
_NO_LOGIN = (
    "agy has no sign-in command that exits when done (sign-in starts from its interactive UI); "
    "run `hswap agy add` for the current login, sign in the next account in agy, then add again"
)
_TERMS = (
    "HIGHEST RISK OF ANY HARNESS. Google's Antigravity Additional Terms, section 6 "
    "(https://antigravity.google/terms), list \"Using third party software, tools, or services to access "
    "the Service\" as abuse and say \"Such actions may be grounds for suspension or termination of your "
    "Antigravity and/or Gemini CLI accounts.\" Accounts were reported suspended in 2026 for third-party use "
    "(https://discuss.ai.google.dev/t/antigravity-account-disabled-violation-of-terms-of-service-requesting-support/123014), "
    "and a forum reply not from Google staff says cycling several accounts to get past quota limits breaches "
    "the terms (https://discuss.ai.google.dev/t/one-person-several-paid-google-ai-pro-accounts-may-a-local-"
    "orchestrator-use-them-with-the-official-agy-cli/185460). "
    "hswap only launches the official agy, but Google has not said that is allowed; you risk every account involved."
)


class AgyTokenFormat:
    """The token file is one account: the whole document is the part."""

    secret_name = TOKEN_FILE

    def parts(self, doc: dict) -> dict[str, dict]:
        return {"": doc} if isinstance(doc.get("token"), dict) else {}

    def identify(self, part_key: str, part: dict) -> Identity | None:
        # The file carries only the email: no stable Google user id is available
        # offline (userinfo's `id` needs a network call), so the identity is the
        # sign-in method plus the lowercased email. Consumer and business logins
        # of one email are different quota pools, hence the method prefix.
        email = part.get("id_token_email")
        if not isinstance(email, str) or not email.strip():
            return None
        method = part.get("auth_method") if isinstance(part.get("auth_method"), str) else "oauth"
        return Identity(f"{method}/{email.strip().lower()}", email.strip(), "google", method)

    def merge(self, doc: dict | None, part_key: str, part: dict) -> dict:
        return dict(part)


def _epoch(text: object) -> float | None:
    try:
        return datetime.fromisoformat(str(text)).timestamp()
    except ValueError:
        return None


def snapshot_from_usage(doc: dict, now: float) -> UsageSnapshot:
    """Normalise ``agy -p /usage --output-format json`` output."""
    if doc.get("status") != "SUCCESS":
        said = f"{doc.get('error')} {doc.get('response')}"  # checked, never echoed
        if any(s in said for s in ("Authentication expired", "UNAUTHENTICATED", "authentication failed")):
            return UsageSnapshot(UsageState.AUTHENTICATION_REQUIRED, measured_at=now, source="agy /usage",
                                 detail="agy says the sign-in expired; run agy as this account and sign in again")
        raise HswapError("agy /usage did not succeed")
    data = (doc.get("command") or {}).get("data") or {}
    windows, groups = [], data.get("groups") or ()
    for group in groups:
        for bucket in group.get("buckets") or ():
            if bucket.get("disabled"):
                continue
            fraction = bucket.get("remaining_fraction")
            used = None
            if isinstance(fraction, (int, float)):
                used = round(min(100.0, max(0.0, (1 - fraction) * 100)), 1)
            window = str(bucket.get("window") or "")
            windows.append(QuotaWindow(
                name=f"{group.get('name') or '?'} {window or bucket.get('name') or ''}".strip(),
                used_percent=used,
                resets_at=_epoch(bucket.get("reset_time")),
                window_seconds=_WINDOW_S.get(window),
            ))
    if not windows and groups:  # every bucket disabled: this login has no quota pool
        return UsageSnapshot(UsageState.UNSUPPORTED, measured_at=now, source="agy /usage",
                             detail="this login has no enabled quota")
    if not windows:
        raise HswapError("agy /usage returned no quota windows")
    limited = any(w.used_percent is not None and w.used_percent >= 100 for w in windows)
    return UsageSnapshot(
        UsageState.RATE_LIMITED if limited else UsageState.AVAILABLE,
        windows=tuple(windows), measured_at=now, source="agy /usage",
    )


class AgyAdapter(FileCredentialAdapter):
    id = "agy"
    display_name = "Antigravity CLI"
    providers = ("google",)
    executable = "agy"
    home_flag = "--gemini_dir="
    default_home = ".gemini"
    credential_file = TOKEN_FILE
    # User configuration only; installation_id, history and the token stay per account.
    shared_names = ("config", "antigravity-cli/settings.json")
    hot_reload = False
    fmt = AgyTokenFormat()
    #: The provider's terms on switching accounts, shown when it is opted in to usage.remote/auto.enabled.
    terms = _TERMS
    # Each read starts a 200 MB agy binary that also signs in and phones home.
    usage_policy = UsagePolicy(min_interval_s=300.0, stale_after_s=1800.0, max_backoff_s=3600.0)

    def _file_blocker(self) -> CapabilityStatus | None:
        inst = self.installation()
        if not inst.installed:
            return unavailable(f"Antigravity CLI is not installed ({inst.detail})")
        if sys.platform in ("darwin", "win32"):
            return unavailable(
                "on macOS and Windows agy keeps its Google login in the system keychain, "
                "not in a file hswap can switch"
            )
        if not (self.home / self.credential_file).exists():
            return unavailable(
                f"no {self.home / self.credential_file}: agy keeps its login in the system keyring when a "
                "Secret Service is reachable and writes this file only as the fallback (no D-Bus session bus)"
            )
        return None

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        blocked = self._file_blocker()
        if blocked:
            usage = blocked
        elif not settings.opted_in("usage.remote", self.id):
            usage = unavailable(_OPT_IN)
        else:
            usage = experimental(
                "asks agy itself (`agy -p /usage --output-format json`) in each account's own home via its "
                "undocumented --gemini_dir flag; agy refreshes that login, hswap never does. It runs without "
                "DBUS_SESSION_BUS_ADDRESS so agy uses that home's token file, not a desktop keyring login "
                "(agy's documented headless fallback; untested on a host with a Secret Service)"
            )
        return {
            Capability.ACCOUNT_LIST: supported(),
            Capability.ACCOUNT_ADD: blocked or supported(f"current login only; --login: {_NO_LOGIN}"),
            Capability.ACCOUNT_REMOVE: supported("forgets hswap's copy; the live login is untouched"),
            Capability.ACCOUNT_SWITCH: blocked or supported(f"swaps ~/.gemini/{TOKEN_FILE}; restart running agy"),
            Capability.NATIVE_ACCOUNT_SWITCH: unsupported("agy keeps one Google login; /login replaces it"),
            Capability.CREDENTIAL_REFRESH: blocked or supported(
                "`hswap agy refresh` runs `agy -p /usage` in the account's own home (no agent turn, no quota "
                "spent), which makes agy use its refresh token; hswap never refreshes tokens itself"
            ),
            Capability.USAGE_MONITORING: usage,
            Capability.AUTOMATIC_ROTATION: experimental(_TERMS) if usage.usable
            else unavailable(f"needs usage monitoring ({usage.reason})"),
            Capability.PARALLEL_SESSIONS: blocked or experimental(
                "per-account home via agy's undocumented --gemini_dir flag (own installation_id); "
                "config/ and settings.json linked in, history per account"
            ),
            Capability.SESSION_RESUME: blocked or supported("`run <account> -- --continue`; history is per account home"),
            Capability.CREDENTIAL_HOT_RELOAD: unsupported(
                "a running agy keeps the signed-in account in memory until restarted"
            ),
        }

    def add_account(
        self, *, alias: str | None = None, provider: str | None = None, login: bool = False,
        email: str | None = None,
    ) -> Account:
        if login:
            raise UnsupportedOperation(str(Capability.ACCOUNT_ADD), _NO_LOGIN, "unavailable")
        return super().add_account(alias=alias, provider=provider)

    # --- usage ------------------------------------------------------------------

    def read_usage(self, account: Account) -> UsageSnapshot:
        if not settings.opted_in("usage.remote", self.id):
            return UsageSnapshot(UsageState.UNSUPPORTED, detail=_OPT_IN)
        with self.usage_home(account) as (home, active):
            if home is None:
                return UsageSnapshot(UsageState.STALE, detail="in use by a running session; showing the last measurement")
            token = home / self.credential_file
            if not token.exists():  # agy would block on an interactive sign-in
                return UsageSnapshot(UsageState.STALE, detail="no stored login to ask agy with")
            if active:
                left = self._token_life(token)
                if left is None or left <= _MIN_TOKEN_LIFE_S:
                    # An agy started outside hswap may share this home; let it refresh first.
                    return UsageSnapshot(
                        UsageState.STALE,
                        detail="the active login's access token is about to expire; waiting for agy to refresh it",
                    )
            return snapshot_from_usage(self._ask_usage(home, active), time.time())

    def keep_alive(self, account: Account) -> str:
        """Ask agy ``/usage`` so it uses the stored refresh token (needs no opt-in)."""
        with self.usage_home(account) as (home, active):
            if home is None:
                return "skipped: a running session keeps it fresh"
            if active and processes.find({self.executable}) != []:
                return f"skipped: {self.display_name} is running and refreshes the active login itself"
            if not (home / self.credential_file).exists():  # agy would block on an interactive sign-in
                raise HswapError("sign in again: this account's login is missing from its agy home")
            doc = self._ask_usage(home, active)
        # ponytail: agy refreshes in memory and rarely rewrites the file, so no before/after hash to compare.
        if doc.get("status") != "SUCCESS" and snapshot_from_usage(doc, 0).state is UsageState.AUTHENTICATION_REQUIRED:
            raise HswapError("sign in again: agy could not use or refresh this login")
        return "login used (Google refresh tokens do not rotate)"

    @staticmethod
    def _token_life(path: Path) -> float | None:
        try:
            expiry = _epoch(json.loads(path.read_text(encoding="utf-8"))["token"]["expiry"])
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return None if expiry is None else expiry - time.time()

    def _ask_usage(self, home: Path, active: bool) -> dict:
        inst = self._require_installed()
        home_args = [] if active else self.home_overrides(home)[1]  # default home: no flag
        try:
            proc = subprocess.Popen(
                [str(inst.executable), *home_args, "-p", "/usage", "--output-format", "json"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                # No session bus: agy then skips the keyring (one login per desktop, not scoped by
                # --gemini_dir) and uses this home's file, so the quota and any refresh stay with this account.
                env={**{k: v for k, v in os.environ.items() if k != "DBUS_SESSION_BUS_ADDRESS"},
                     "AGY_CLI_DISABLE_AUTO_UPDATE": "1"},
                start_new_session=os.name == "posix",  # no terminal; its helpers end with it
            )
        except OSError as exc:
            raise HswapError(f"could not start agy: {exc.strerror}") from None
        lines: queue.Queue = queue.Queue()
        for stream in (proc.stdout, proc.stderr):
            threading.Thread(target=_pump, args=(stream, stream is proc.stderr, lines), daemon=True).start()
        out, open_streams, deadline = [], 2, time.monotonic() + _USAGE_TIMEOUT_S
        try:
            while open_streams:
                try:
                    is_err, line = lines.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    raise HswapError(f"agy /usage did not answer within {_USAGE_TIMEOUT_S}s") from None
                if line is None:
                    open_streams -= 1
                elif is_err and _LOGIN_PROMPT in line:
                    # The login could not be used or refreshed: agy now waits for a browser sign-in.
                    return {"status": "ERROR", "error": "authentication failed or timed out"}
                elif not is_err:
                    out.append(line)
                    if isinstance(doc := _json("".join(out)), dict):  # agy may linger after answering
                        return doc
            returncode = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise HswapError(f"agy /usage did not answer within {_USAGE_TIMEOUT_S}s") from None
        finally:
            _stop(proc)
        # never echo agy's output: it may carry account data
        raise HswapError(f"agy /usage exited with status {returncode} without a JSON result")


#: What agy prints on stderr when it falls back to an interactive (browser) sign-in.
_LOGIN_PROMPT = "Authentication required"


def _pump(stream, is_err: bool, lines: queue.Queue) -> None:
    for line in stream:
        lines.put((is_err, line))
    lines.put((is_err, None))


def _json(text: str) -> object:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _stop(proc: subprocess.Popen) -> None:
    """End agy and anything it started (Google refresh tokens do not rotate, so nothing is lost)."""
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except OSError:
        pass
    proc.wait()
