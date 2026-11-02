"""Adapter discovery and registration.

Sources, in order:

1. **Built-ins** -- ``harness_swap.adapters.BUILTIN`` maps an id to a
   ``"module:Class"`` path. Imported lazily, so ``hswap codex list`` never
   loads the Claude engine.
2. **Runtime registrations** -- :meth:`Registry.register`, for embedding and
   tests.
3. **Entry-point plugins** -- the ``harness_swap.adapters`` entry-point group
   of any installed distribution. A plugin is *listed* as soon as it is
   installed but *loaded* (i.e. its code imported and run) only once the
   user trusts its id: ``hswap config set plugins.trusted <id>`` or
   ``HSWAP_TRUSTED_PLUGINS=<id>[,<id>...]``. Installing a package is not
   consent to run it with access to your credentials.

A loaded object must satisfy :class:`HarnessAdapter` and report the id it was
registered under; anything else is reported as a load error, not used.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import entry_points

from harness_swap.core.adapter import HarnessAdapter
from harness_swap.core.errors import HarnessNotFound

ENTRY_POINT_GROUP = "harness_swap.adapters"

Factory = Callable[[], HarnessAdapter]


@dataclass
class AdapterEntry:
    id: str
    origin: str  # "builtin" | "runtime" | "plugin:<distribution>"
    trusted: bool
    target: str | Factory
    error: str | None = None


def _load_target(target: str | Factory) -> HarnessAdapter:
    if callable(target):
        return target()
    module, _, attr = target.partition(":")
    obj = getattr(importlib.import_module(module), attr)
    return obj() if callable(obj) else obj


class Registry:
    def __init__(
        self,
        builtins: dict[str, str] | None = None,
        trusted_plugins: set[str] | None = None,
        discover_plugins: bool = True,
    ):
        self._entries: dict[str, AdapterEntry] = {}
        self._loaded: dict[str, HarnessAdapter] = {}
        self._trusted: set[str] = set()
        for adapter_id, target in (builtins or {}).items():
            self._entries[adapter_id] = AdapterEntry(adapter_id, "builtin", True, target)
        if discover_plugins:
            trusted = set(trusted_plugins or ())
            self._trusted = set(trusted)
            env = os.environ.get("HSWAP_TRUSTED_PLUGINS", "")
            trusted |= {i.strip().lower() for i in env.split(",") if i.strip()}
            self._discover(trusted)

    def _discover(self, trusted: set[str]) -> None:
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            adapter_id = ep.name.lower()
            if adapter_id in self._entries:
                continue  # a built-in (or earlier plugin) owns this id
            dist = ep.dist.name if ep.dist else "unknown"
            self._entries[adapter_id] = AdapterEntry(
                adapter_id, f"plugin:{dist}", adapter_id in trusted, ep.value
            )

    def register(self, adapter_id: str, target: str | Factory) -> None:
        self._entries[adapter_id] = AdapterEntry(adapter_id, "runtime", True, target)
        self._loaded.pop(adapter_id, None)

    def trust_command(self, adapter_id: str) -> str:
        """The config command that trusts ``adapter_id`` and keeps the others trusted."""
        return f"hswap config set plugins.trusted {','.join(sorted(self._trusted | {adapter_id}))}"

    def entries(self) -> list[AdapterEntry]:
        return sorted(self._entries.values(), key=lambda e: (e.origin != "builtin", e.id))

    def ids(self) -> list[str]:
        return [e.id for e in self.entries() if e.trusted]

    def get(self, adapter_id: str) -> HarnessAdapter:
        entry = self._entries.get(adapter_id)
        if entry is None:
            raise HarnessNotFound(
                f"unknown harness {adapter_id!r}; known: {', '.join(self.ids()) or 'none'}"
            )
        if not entry.trusted:
            raise HarnessNotFound(
                f"{adapter_id!r} comes from {entry.origin} and is not trusted; "
                f"run `{self.trust_command(adapter_id)}` to allow it"
            )
        if adapter_id not in self._loaded:
            try:
                adapter = _load_target(entry.target)
            except Exception as exc:
                entry.error = f"{type(exc).__name__}: {exc}"
                raise HarnessNotFound(f"{adapter_id!r} failed to load: {entry.error}") from exc
            if not isinstance(adapter, HarnessAdapter) or adapter.id != adapter_id:
                entry.error = "does not implement the HarnessAdapter contract under this id"
                raise HarnessNotFound(f"{adapter_id!r} {entry.error}")
            self._loaded[adapter_id] = adapter
        return self._loaded[adapter_id]

    def available(self) -> list[HarnessAdapter]:
        """Every trusted adapter that loads; load failures are recorded on the entry."""
        out = []
        for adapter_id in self.ids():
            try:
                out.append(self.get(adapter_id))
            except HarnessNotFound:
                continue
        return out


def default_registry() -> Registry:
    from harness_swap.adapters import BUILTIN
    from harness_swap.core import settings

    return Registry(BUILTIN, set(settings.load()["plugins.trusted"]))
