"""Snapshot-style credential management, shared by file-backed harnesses.

Many harnesses keep their login in one JSON file (Codex ``auth.json``, Grok
``auth.json``, legacy OpenCode ``auth.json``). Such a file holds one or more
*parts* -- the whole document, one OAuth scope, one provider -- and each part
belongs to one account. An adapter describes its file with a
:class:`CredentialFormat`; :class:`SnapshotCredentials` does the rest with
the same guarantees for every harness:

* **Sync-back first.** Harnesses rotate refresh tokens. Before anything is
  overwritten, every live part that belongs to a stored account is copied
  back into that account's snapshot, so the stored copy never goes stale.
* **No silent loss.** A live part that belongs to no stored account is not
  overwritten unless forced, and even then it is first stashed (0600) under
  ``<harness home>/stash/``.
* **Only the target part changes.** Other scopes/providers in the same file
  are carried over untouched.
* **Atomic, verified, reversible.** The new file is written by temp+rename
  at 0600, re-read and re-identified; on any mismatch or error the original
  bytes are put back (or the file removed if there was none).
* **Locked.** hswap's store lock, plus -- best effort -- the harness's own
  lock file, so a harness refresh and a switch cannot interleave.

Nothing in this module logs or returns secret material.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from harness_swap.core import sessions
from harness_swap.core.errors import (
    AccountNotFound,
    CredentialConflict,
    CredentialError,
    HswapError,
    LockError,
)
from harness_swap.core.store import AccountStore, StoredAccount, mkdir_private
from harness_swap.infrastructure.fsutil import atomic_write_bytes
from harness_swap.infrastructure.locking import FileLock


@dataclass(frozen=True)
class Identity:
    identity: str
    label: str
    provider: str | None
    auth_mode: str | None
    meta: dict = field(default_factory=dict, compare=False, hash=False)


class CredentialFormat(Protocol):
    """How one harness lays out its credential file. Pure functions, no IO."""

    #: Filename used for the per-account snapshot (and, in an isolated
    #: session, the harness home's own credential file).
    secret_name: str

    def parts(self, doc: dict) -> dict[str, dict]:
        """Split a live document into ``{part_key: part}``."""
        ...

    def identify(self, part_key: str, part: dict) -> Identity | None:
        """Who a part belongs to; ``None`` if it cannot be attributed."""
        ...

    def merge(self, doc: dict | None, part_key: str, part: dict) -> dict:
        """``doc`` with ``part_key`` set to ``part``, everything else kept."""
        ...

    # Optional: ``exclusive = True`` makes a switch drop every other credential
    # part (part keys must then be top-level keys of the document).


def fingerprint(secret: str) -> str:
    """A short, non-reversible tag for an API key (never the key itself)."""
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def jwt_claims(token: object) -> dict:
    """Decode a JWT payload for labelling only (no signature check: the token
    is read from the user's own credential file, not trusted for access)."""
    if not isinstance(token, str):
        return {}
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return claims if isinstance(claims, dict) else {}
    except (IndexError, ValueError, TypeError):
        return {}


def _load_doc(raw: bytes | None, where: Path) -> dict | None:
    if raw is None:
        return None
    try:
        doc = json.loads(raw)
    except ValueError:
        raise CredentialError(f"{where} is not valid JSON; refusing to touch it") from None
    if not isinstance(doc, dict):
        raise CredentialError(f"{where} is not a JSON object; refusing to touch it")
    return doc


def _dump(doc: dict) -> bytes:
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


class SnapshotCredentials:
    def __init__(
        self,
        fmt: CredentialFormat,
        store: AccountStore,
        live_path: Path,
        harness_lock: Path | None = None,
        lock_timeout: float = 10.0,
    ):
        self.fmt = fmt
        self.store = store
        self.live_path = live_path
        self.harness_lock = harness_lock
        self.lock_timeout = lock_timeout

    # -- reading -----------------------------------------------------------

    def _read_live(self) -> tuple[bytes | None, dict | None]:
        try:
            raw = self.live_path.read_bytes()
        except FileNotFoundError:
            return None, None
        return raw, _load_doc(raw, self.live_path)

    def live_identities(self) -> dict[str, Identity]:
        """``{part_key: identity}`` for every attributable live part."""
        _raw, doc = self._read_live()
        return self._identities(doc or {})

    def _identities(self, doc: dict) -> dict[str, Identity]:
        out = {}
        for key, part in self.fmt.parts(doc).items():
            ident = self.fmt.identify(key, part)
            if ident is not None:
                out[key] = ident
        return out

    def is_active(self, acc: StoredAccount, live: dict[str, Identity]) -> bool:
        ident = live.get(acc.part_key or "")
        return ident is not None and (ident.identity, ident.provider) == (acc.identity, acc.provider)

    def stored_part(self, acc: StoredAccount) -> dict:
        raw = self.store.read_secret(acc.slot, self.fmt.secret_name)
        where = self.store.account_dir(acc.slot) / self.fmt.secret_name
        doc = _load_doc(raw, where)
        part = self.fmt.parts(doc or {}).get(acc.part_key or "")
        if part is None:
            raise CredentialError(f"slot {acc.slot} has no stored credentials ({where})")
        ident = self.fmt.identify(acc.part_key or "", part)
        if ident is None or (ident.identity, ident.provider) != (acc.identity, acc.provider):
            raise CredentialError(
                f"slot {acc.slot}'s stored credentials belong to a different account; "
                "remove and re-add it"
            )
        return part

    # -- locking -------------------------------------------------------------

    @contextmanager
    def _locked(self):
        """hswap's store lock, then -- best effort -- the harness's own lock
        file, so a harness token refresh and a switch cannot interleave."""
        with self.store.lock(self.lock_timeout):
            if self.harness_lock is None or not self.harness_lock.parent.is_dir():
                yield
                return
            lock = FileLock(self.harness_lock, timeout=self.lock_timeout)
            if not lock.acquire():
                raise LockError(
                    f"{self.harness_lock} is held (the harness may be refreshing "
                    "its login); try again in a moment"
                )
            try:
                yield
            finally:
                lock.release()

    # -- sync-back -------------------------------------------------------------

    def _capture(self, accounts: list[StoredAccount], doc: dict) -> list[int]:
        """Copy live parts back into their stored accounts. Returns updated slots.

        A slot that an isolated session is running is skipped: that session
        refreshes the slot's snapshot in place, so it is newer than any copy
        the live file could hold.
        """
        updated = []
        for key, part in self.fmt.parts(doc).items():
            acc = self._owner(accounts, key, part)
            if acc is None or sessions.in_use(self.store.account_dir(acc.slot)):
                continue
            data = _dump(self.fmt.merge(None, key, part))
            if self.store.read_secret(acc.slot, self.fmt.secret_name) != data:
                self.store.write_secret(acc.slot, self.fmt.secret_name, data)
                updated.append(acc.slot)
        return updated

    def _owner(self, accounts: list[StoredAccount], key: str, part: dict) -> StoredAccount | None:
        """The stored account this live part belongs to (same identity *and* part key)."""
        ident = self.fmt.identify(key, part)
        if ident is None:
            return None
        acc = self.store.find(accounts, ident.identity, ident.provider)
        return acc if acc is not None and (acc.part_key or "") == key else None

    def sync_back(self) -> list[int]:
        """Public sync-back: refresh stored snapshots from the live file."""
        with self._locked():
            accounts = self.store.load()
            _raw, doc = self._read_live()
            return self._capture(accounts, doc or {})

    # -- adding ------------------------------------------------------------------

    def import_document(
        self,
        doc: dict,
        *,
        alias: str | None = None,
        only_provider: str | None = None,
    ) -> list[tuple[StoredAccount, bool]]:
        """Register every attributable part of ``doc`` (dedupes by identity)."""
        idents = self._identities(doc)
        if only_provider is not None:
            idents = {k: v for k, v in idents.items() if v.provider == only_provider}
        if not idents:
            raise CredentialError("no login found to add (sign in to the harness first)")
        if alias is not None and len(idents) > 1:
            raise CredentialError("--alias needs exactly one login; pass --provider to pick one")
        parts = self.fmt.parts(doc)
        results = []
        with self.store.lock(self.lock_timeout):
            accounts = self.store.load()
            for key, ident in idents.items():
                acc, created = self.store.upsert(
                    accounts,
                    identity=ident.identity,
                    label=ident.label,
                    provider=ident.provider,
                    auth_mode=ident.auth_mode,
                    part_key=key,
                    alias=alias,
                    meta=ident.meta,
                )
                self.store.write_secret(
                    acc.slot, self.fmt.secret_name, _dump(self.fmt.merge(None, key, parts[key]))
                )
                results.append((acc, created))
            self.store.save(accounts)
        return results

    def add_current(self, *, alias: str | None = None, provider: str | None = None):
        _raw, doc = self._read_live()
        if doc is None:
            raise CredentialError(f"not signed in: {self.live_path} does not exist")
        return self.import_document(doc, alias=alias, only_provider=provider)

    # -- switching -----------------------------------------------------------------

    def activate(self, slot: int, *, force: bool = False) -> tuple[StoredAccount, StoredAccount | None]:
        """Make stored ``slot`` the live login. Returns ``(target, previous)``.

        With an *exclusive* format (``fmt.exclusive``) the target becomes the
        only credential part of the file -- needed when the harness, not hswap,
        decides which of several parts it uses.
        """
        with self._locked():
            if sessions.in_use(self.store.account_dir(slot)):
                raise HswapError(
                    f"slot {slot} is running in an isolated session, which refreshes that login "
                    "on its own; activating it globally too would make two processes rotate one "
                    "refresh token. Exit that session first."
                )
            accounts = self.store.load()
            target = next((a for a in accounts if a.slot == slot), None)
            if target is None:
                raise AccountNotFound(f"no stored account in slot {slot}")
            raw, doc = self._read_live()
            doc = doc or {}
            self._capture(accounts, doc)
            key = target.part_key or ""
            part = self.stored_part(target)

            live_parts = self.fmt.parts(doc)
            exclusive = getattr(self.fmt, "exclusive", False)
            replaced = {k: p for k, p in live_parts.items() if k == key or exclusive}
            if key in replaced and len(replaced) == 1 and self._owner([target], key, replaced[key]):
                return target, target  # already active; nothing to write

            previous, unmanaged = None, []
            for k, p in replaced.items():
                ident = self.fmt.identify(k, p)
                if k == key and ident is not None and (ident.identity, ident.provider) == (target.identity, target.provider):
                    continue
                # The target signed in under another part key is not covered by
                # sync-back either, so it counts as unmanaged below.
                owner = self._owner(accounts, k, p)
                if owner is None:
                    unmanaged.append(ident.label if ident else "an unrecognised login")
                elif previous is None:
                    previous = owner
            if unmanaged:
                if not force:
                    raise CredentialConflict(
                        f"the current login ({', '.join(unmanaged)}) is not stored by hswap; switching "
                        "would lose it. Add it first, or pass --force to stash it and continue"
                    )
                self._stash(raw)

            base = {k: v for k, v in doc.items() if k == key or k not in replaced}
            self._write_live_verified(raw, self.fmt.merge(base, key, part), key, target)
            return target, previous

    def _stash(self, raw: bytes | None) -> Path | None:
        if raw is None:
            return None
        stash = self.store.root / "stash" / f"{self.live_path.name}.{time.time_ns()}"
        mkdir_private(stash.parent)
        atomic_write_bytes(stash, raw, mode=0o600, follow_symlinks=False)
        return stash

    def _write_live_verified(
        self, original: bytes | None, new_doc: dict, key: str, target: StoredAccount
    ) -> None:
        try:
            self.live_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(self.live_path, _dump(new_doc), mode=0o600)
            _raw, check = self._read_live()
            ident = self._identities(check or {}).get(key)
            if ident is None or (ident.identity, ident.provider) != (target.identity, target.provider):
                raise CredentialError("the written credentials did not read back as the target account")
        except BaseException:
            self._restore(original)
            raise

    def _restore(self, original: bytes | None) -> None:
        if original is None:
            self.live_path.unlink(missing_ok=True)
        else:
            atomic_write_bytes(self.live_path, original, mode=0o600)
