"""hswap's per-harness account registry.

Layout under ``<hswap home>/<harness>/``::

    accounts.json          metadata only: slots, identities, labels, aliases
    .lock                  serialises every read-modify-write of the above
    accounts/<slot>/       0700; secret material (e.g. auth.json, 0600) for
                           adapters that keep credential snapshots, and the
                           per-account harness home for isolated sessions

Metadata and secrets are separate on purpose: listing, aliasing and the
dashboard never open a secret file, and ``accounts.json`` can be shown,
diffed or attached to a bug report without leaking a token.

``accounts.json`` carries ``schemaVersion``. A file from a newer hswap is
refused rather than rewritten, so a downgrade cannot silently drop fields.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from harness_swap.core.errors import AccountNotFound, StoreVersionError
from harness_swap.core.models import normalize_alias
from harness_swap.infrastructure.fsutil import atomic_write_bytes, atomic_write_text
from harness_swap.infrastructure.locking import FileLock

SCHEMA_VERSION = 1


@dataclass
class StoredAccount:
    slot: int
    identity: str
    label: str
    provider: str | None = None
    auth_mode: str | None = None
    alias: str | None = None
    added: str = ""
    #: Which part of the harness's live credential document this account
    #: owns (whole file: ""; a scope or provider key otherwise). ``None`` for
    #: accounts the harness itself stores (no secret kept by hswap).
    part_key: str | None = None
    meta: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> StoredAccount:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(path, 0o700)


class AccountStore:
    def __init__(self, root: Path):
        self.root = root
        self.file = root / "accounts.json"

    # -- locking / raw IO ---------------------------------------------------

    def lock(self, timeout: float = 10.0) -> FileLock:
        mkdir_private(self.root)
        return FileLock(self.root / ".lock", timeout=timeout)

    def load(self) -> list[StoredAccount]:
        try:
            raw = self.file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        data = json.loads(raw)
        version = data.get("schemaVersion")
        if not isinstance(version, int) or version > SCHEMA_VERSION:
            raise StoreVersionError(
                f"{self.file} has schemaVersion {version!r}; this hswap understands "
                f"up to {SCHEMA_VERSION}. Upgrade hswap instead of editing the file."
            )
        return [StoredAccount.from_json(a) for a in data.get("accounts", [])]

    def save(self, accounts: list[StoredAccount]) -> None:
        mkdir_private(self.root)
        doc = {
            "schemaVersion": SCHEMA_VERSION,
            "accounts": [asdict(a) for a in sorted(accounts, key=lambda a: a.slot)],
        }
        atomic_write_text(self.file, json.dumps(doc, indent=2) + "\n")

    # -- secrets --------------------------------------------------------------

    def account_dir(self, slot: int) -> Path:
        return self.root / "accounts" / str(slot)

    def ensure_account_dir(self, slot: int) -> Path:
        mkdir_private(self.root / "accounts")
        path = self.account_dir(slot)
        mkdir_private(path)
        return path

    def read_secret(self, slot: int, name: str) -> bytes | None:
        try:
            return (self.account_dir(slot) / name).read_bytes()
        except FileNotFoundError:
            return None

    def write_secret(self, slot: int, name: str, data: bytes) -> None:
        atomic_write_bytes(self.ensure_account_dir(slot) / name, data, mode=0o600)

    # -- registry operations (call with the lock held) ------------------------

    @staticmethod
    def find(accounts: list[StoredAccount], identity: str, provider: str | None):
        for acc in accounts:
            if acc.identity == identity and acc.provider == provider:
                return acc
        return None

    @staticmethod
    def next_slot(accounts: list[StoredAccount]) -> int:
        used = {a.slot for a in accounts}
        slot = 1
        while slot in used:
            slot += 1
        return slot

    def upsert(
        self,
        accounts: list[StoredAccount],
        *,
        identity: str,
        label: str,
        provider: str | None,
        auth_mode: str | None,
        part_key: str | None,
        alias: str | None = None,
        meta: dict | None = None,
    ) -> tuple[StoredAccount, bool]:
        """Add or refresh an account in ``accounts`` (in place). Duplicate
        identities update the existing slot instead of taking a new one."""
        if alias is not None:
            alias = normalize_alias(alias)
            self._check_alias_free(accounts, alias, identity, provider)
        existing = self.find(accounts, identity, provider)
        if existing is not None:
            existing.label = label or existing.label
            existing.auth_mode = auth_mode
            existing.part_key = part_key
            existing.meta = meta or existing.meta
            if alias is not None:
                existing.alias = alias
            return existing, False
        acc = StoredAccount(
            slot=self.next_slot(accounts),
            identity=identity,
            label=label,
            provider=provider,
            auth_mode=auth_mode,
            alias=alias,
            added=_now(),
            part_key=part_key,
            meta=meta or {},
        )
        accounts.append(acc)
        return acc, True

    @staticmethod
    def _check_alias_free(accounts, alias, identity, provider) -> None:
        for acc in accounts:
            if acc.alias == alias and not (acc.identity == identity and acc.provider == provider):
                raise ValueError(f"alias '{alias}' is already used by slot {acc.slot}")

    def set_alias(self, slot: int, alias: str | None) -> StoredAccount:
        with self.lock():
            accounts = self.load()
            acc = next((a for a in accounts if a.slot == slot), None)
            if acc is None:
                raise AccountNotFound(f"no stored account in slot {slot}")
            if alias is not None:
                alias = normalize_alias(alias)
                self._check_alias_free(accounts, alias, acc.identity, acc.provider)
            acc.alias = alias
            self.save(accounts)
            return acc

    def delete(self, slot: int, secret_names: tuple[str, ...] = ()) -> None:
        """Forget ``slot`` and remove its ``secret_names`` files.

        The per-account harness home keeps any session history it holds:
        only credential files are removed, the rest is left for the user.
        """
        with self.lock():
            accounts = [a for a in self.load() if a.slot != slot]
            self.save(accounts)
        directory = self.account_dir(slot)
        if directory.is_dir():
            for name in secret_names:
                (directory / name).unlink(missing_ok=True)
            try:
                directory.rmdir()  # only when nothing else (history) lives there
            except OSError:
                pass
