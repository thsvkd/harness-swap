"""Building blocks shared by adapters. No harness names live here.

:class:`FileCredentialAdapter` implements every account role for a harness
whose login is a JSON file in a home directory that an environment variable
can relocate. A concrete adapter declares *data* -- executable, home
variable, credential format, what to share with isolated sessions, how it
reloads -- and overrides :meth:`capabilities` with what its install supports.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from harness_swap.core import sessions
from harness_swap.core.credentials import CredentialFormat, SnapshotCredentials
from harness_swap.core.errors import CredentialError, HarnessNotInstalled, HswapError
from harness_swap.core.models import Account, Installation, SwitchResult
from harness_swap.core.paths import env_dir, harness_home
from harness_swap.core.store import AccountStore, StoredAccount, mkdir_private
from harness_swap.infrastructure import processes, spawn

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    m = _VERSION_RE.search(text or "")
    return tuple(int(g) for g in m.groups()) if m else None  # type: ignore[return-value]


def probe_installation(executable: str, args: tuple[str, ...] = ("--version",)) -> Installation:
    path = shutil.which(executable)
    if path is None:
        return Installation(False, detail=f"`{executable}` not found on PATH")
    try:
        result = spawn.run([path, *args], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return Installation(True, path, None, f"version probe failed: {exc}")
    text = (result.stdout or result.stderr).strip().splitlines()
    first = text[0].strip() if text else ""
    if result.returncode != 0:
        return Installation(True, path, None, f"`{executable} {' '.join(args)}` failed: {first[:200]}")
    return Installation(True, path, first or None)


class FileCredentialAdapter:
    # --- declared by subclasses -------------------------------------------
    id: str
    display_name: str
    providers: tuple[str, ...] = ()
    executable: str
    #: Environment variable that moves the harness home; or, for a harness that
    #: takes it as a flag, ``home_flag`` (e.g. ``"--gemini_dir="``, value appended).
    home_env: str | None = None
    home_flag: str | None = None
    default_home: str  # relative to the user's home directory, e.g. ".codex"
    credential_file = "auth.json"
    harness_lock_name: str | None = None
    #: Default-home entries linked into an isolated session's home.
    shared_names: tuple[str, ...] = ()
    login_args: tuple[str, ...] = ("login",)
    #: Running processes pick up a switched credential file by themselves.
    hot_reload = False
    fmt: CredentialFormat

    def __init__(self) -> None:
        self._installation: Installation | None = None
        if self.fmt.secret_name != self.credential_file:
            # The account directory doubles as the harness home of an isolated
            # session, so the snapshot must carry the live file's name.
            raise TypeError(
                f"{type(self).__name__}: fmt.secret_name {self.fmt.secret_name!r} must equal "
                f"credential_file {self.credential_file!r}"
            )

    # --- locations ------------------------------------------------------------

    @property
    def home(self) -> Path:
        default = Path.home() / self.default_home
        return env_dir(self.home_env, default) if self.home_env else default

    def home_overrides(self, home: Path) -> tuple[dict[str, str], list[str]]:
        """Environment variables and leading arguments that point the harness at ``home``."""
        if self.home_flag:
            return {}, [f"{self.home_flag}{home}"]
        return {self.home_env: str(home)} if self.home_env else {}, []

    @property
    def store(self) -> AccountStore:
        return AccountStore(harness_home(self.id))

    @property
    def credentials(self) -> SnapshotCredentials:
        lock = self.home / self.harness_lock_name if self.harness_lock_name else None
        return SnapshotCredentials(self.fmt, self.store, self.home / self.credential_file, lock)

    # --- discovery --------------------------------------------------------------

    def installation(self) -> Installation:
        if self._installation is None:
            self._installation = probe_installation(self.executable)
        return self._installation

    def _require_installed(self) -> Installation:
        inst = self.installation()
        if not inst.installed:
            raise HarnessNotInstalled(f"{self.display_name}: {inst.detail}")
        return inst

    # --- listing ----------------------------------------------------------------

    def _to_account(self, acc: StoredAccount, active: bool | None) -> Account:
        return Account(
            harness=self.id,
            identity=acc.identity,
            label=acc.label,
            provider=acc.provider,
            slot=acc.slot,
            alias=acc.alias,
            auth_mode=acc.auth_mode,
            active=active,
            details=dict(acc.meta),
        )

    def list_accounts(self) -> list[Account]:
        creds = self.credentials
        try:
            live = creds.live_identities()
        except CredentialError:
            live = None  # unreadable live file: activity unknown, list still works
        return [
            self._to_account(s, None if live is None else creds.is_active(s, live))
            for s in self.store.load()
        ]

    def _stored(self, account: Account) -> StoredAccount:
        for acc in self.store.load():
            if acc.slot == account.slot:
                return acc
        raise HswapError(f"slot {account.slot} disappeared while hswap was running")

    # --- adding / removing -------------------------------------------------------

    def add_account(
        self, *, alias: str | None = None, provider: str | None = None, login: bool = False,
        email: str | None = None,
    ) -> Account:
        if login:
            if alias is not None:
                alias = self.store.check_new_alias(alias)  # fail before the user signs in
            results = self._login_isolated(alias=alias, provider=provider, email=email)
        else:
            results = self.credentials.add_current(alias=alias, provider=provider)
        slot = results[0][0].slot
        return next(a for a in self.list_accounts() if a.slot == slot)

    def _login_isolated(self, *, alias: str | None, provider: str | None, email: str | None = None):
        """Run the harness's own sign-in in a throwaway home, then import it.

        The default login is never replaced (so never revoked or logged out);
        user configuration is linked in so SSO/OIDC settings still apply.
        """
        inst = self._require_installed()
        for stale in self.store.root.glob("pending-login-*"):  # left by a killed sign-in
            if time.time() - stale.stat().st_mtime > 86400:
                shutil.rmtree(stale, ignore_errors=True)
        tmp = self.store.root / f"pending-login-{uuid.uuid4().hex}"
        try:
            sessions.link_shared(tmp, self.home, self.login_shared_names())
            env_add, home_args = self.home_overrides(tmp)
            code = subprocess.call([inst.executable, *home_args, *self.login_args], env={**os.environ, **env_add})
            if code != 0:
                raise HswapError(f"{self.executable} login exited with status {code}; nothing added")
            try:
                doc = json.loads((tmp / self.credential_file).read_text(encoding="utf-8"))
            except (FileNotFoundError, ValueError):
                raise CredentialError("sign-in finished but wrote no usable credentials") from None
            if email:  # the harness's own login cannot preselect an account, so check after
                got = [i.label for i in self.credentials._identities(doc).values()]
                if email.casefold() not in (g.casefold() for g in got):
                    raise HswapError(
                        f"Signed in as {', '.join(got) or 'an unknown account'}, not {email}; nothing added. "
                        "Pick the right account on the login page and retry."
                    )
            return self.credentials.import_document(doc, alias=alias, only_provider=provider)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def login_shared_names(self) -> tuple[str, ...]:
        return self.shared_names

    def remove_account(self, account: Account) -> None:
        def busy(directory):
            if sessions.in_use(directory) or (account.active and sessions.in_use(self.home)):
                return f"slot {account.slot} is in use by a running `hswap {self.id} run` session; exit it first"
            return None

        self.store.delete(account.slot, (self.credential_file,), refuse=busy)

    def set_alias(self, account: Account, alias: str | None) -> Account:
        return self._to_account(self.store.set_alias(account.slot, alias), account.active)

    # --- switching -------------------------------------------------------------------

    def switch_account(self, account: Account, *, force: bool = False) -> SwitchResult:
        creds = self.credentials
        target, previous = creds.activate(account.slot, force=force)
        notes = [f"the unmanaged login it replaced was saved to {creds.stashed}"] if creds.stashed else []
        restart = False
        if previous is not None and previous.slot == target.slot:
            notes.append("already the active account")
        elif self.hot_reload:
            notes.append(f"running {self.display_name} processes pick this up on their next request")
        else:
            running = processes.find({self.executable})
            restart = bool(running)
            if running:
                notes.append(
                    f"{len(running)} {self.display_name} process(es) are running; those using "
                    f"{self.home} keep the previous account until restarted"
                )
            elif running is None:
                notes.append(f"restart any running {self.display_name} to use the new account")
        return SwitchResult(
            harness=self.id,
            current=self._to_account(target, True),
            previous=self._to_account(previous, False) if previous and previous.slot != target.slot else None,
            restart_required=restart,
            notes=tuple(notes),
        )

    # --- diagnostics --------------------------------------------------------------

    def diagnose(self) -> list[tuple[str, str]]:
        out = []
        live = self.home / self.credential_file
        if live.exists() and os.name == "posix":
            mode = live.stat().st_mode & 0o777
            if mode & 0o077:
                out.append(("warn", f"{live} is readable by other users (mode {mode:o}); run chmod 600"))
        try:
            out.append(("info", f"{len(self.store.load())} stored account(s) in {self.store.root}"))
        except HswapError as exc:
            out.append(("error", str(exc)))
        except ValueError:
            out.append(("error", f"{self.store.file} is not valid JSON"))
        return out

    # --- isolated sessions -------------------------------------------------------

    def session_args(self) -> list[str]:
        """Extra harness arguments for an isolated session."""
        return []

    def launch(self, account: Account, args: list[str]) -> int:
        inst = self._require_installed()
        creds = self.credentials
        # Decide and take the session lock under the store lock, so a switch
        # (which checks the session lock under the same lock) cannot interleave.
        with self.store.lock():
            stored = self._stored(account)
            try:
                live = creds.live_identities()
            except CredentialError:
                live = {}
            if creds.is_active(stored, live):
                # Already the default login: the default home is the right one,
                # and a second copy of the token must not be created. The lock
                # on the default home stops a switch or remove underneath it.
                fd = sessions.acquire(self.home)
                argv, env = [inst.executable, *self.session_args(), *args], dict(os.environ)
            else:
                profile = self.store.account_dir(stored.slot)
                if not (profile / self.credential_file).exists():
                    raise CredentialError(f"slot {stored.slot} has no stored credentials to run with")
                mkdir_private(profile)
                sessions.link_shared(profile, self.home, self.shared_names)
                fd = sessions.acquire(profile)
                env_add, home_args = self.home_overrides(profile)
                argv = [inst.executable, *home_args, *self.session_args(), *args]
                env = {**os.environ, **env_add}
        return sessions.launch(argv, env, fd)

    # --- usage read by the harness itself ------------------------------------------

    @contextmanager
    def usage_home(self, account: Account) -> Iterator[tuple[Path | None, bool]]:
        """``(home, active)`` to ask the harness about ``account``'s usage, with
        that home's session lock held for the read.

        The active account is read in the default home; any other in its own
        account directory, so the harness refreshes that copy itself and
        nothing else holds the same refresh token. ``home`` is ``None`` when a
        running session already owns the account: a second process could
        refresh the same rotating token, so the caller must not start one.
        """
        creds = self.credentials
        with self.store.lock():
            stored = self._stored(account)
            # An unreadable live file raises: the account might be the live one,
            # and reading its stored copy could then refresh a token twice.
            live = creds.live_identities()
            active = creds.is_active(stored, live)
            home = self.home if active else self.store.account_dir(stored.slot)
            if not active and not (home / self.credential_file).exists():
                raise CredentialError(f"slot {stored.slot} has no stored credentials")
            fd = None
            if not sessions.in_use(home):
                if not active:
                    sessions.link_shared(home, self.home, self.shared_names)
                fd = sessions.acquire(home)
        try:
            yield (home if fd is not None else None), active
        finally:
            if fd is not None:
                os.close(fd)
