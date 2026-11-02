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
   user trusts that id **from that distribution**:
   ``hswap config set plugins.trusted <id>@<distribution>`` or
   ``HSWAP_TRUSTED_PLUGINS=<id>@<distribution>[,...]``. Installing a package
   is not consent to run it with access to your credentials, and trusting
   one package is not consent to run another that claims the same id.

Ids must be valid (:func:`check_id`): lowercase, path-safe and not one of
hswap's own command or directory names. A plugin entry point with an invalid
id, a built-in id, or an id that several installed packages declare is never
loaded; it is reported through :meth:`Registry.problems`. A loaded object must
satisfy :class:`HarnessAdapter` and report the id it was registered under;
anything else is recorded as a load error, not used.
"""

from __future__ import annotations

import importlib
import os
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import entry_points

from harness_swap.core.adapter import HarnessAdapter
from harness_swap.core.errors import HarnessNotFound

ENTRY_POINT_GROUP = "harness_swap.adapters"

#: An adapter id is also a command word (``hswap <id>``) and a directory
#: (``<hswap home>/<id>``), so hswap's own commands and data directories are taken.
RESERVED_IDS = frozenset(
    {
        "harnesses", "capabilities", "list", "ls", "status", "doctor", "migrate",
        "config", "tui", "help", "version", "cache", "backups",
    }
)
_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_DISTRIBUTION = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")

Factory = Callable[[], HarnessAdapter]


def check_id(adapter_id: str) -> str | None:
    """Why ``adapter_id`` cannot be used, or ``None`` when it can."""
    if not _ID.fullmatch(adapter_id):
        return "an id is 1-32 lowercase letters, digits, '-' or '_', starting with a letter"
    if adapter_id in RESERVED_IDS:
        return "the id is one of hswap's own command or directory names"
    return None


def distribution_key(name: str) -> str:
    """A distribution name normalised as pip does (``Zest_HSwap`` -> ``zest-hswap``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_trust(token: str) -> str:
    """Validate one ``<id>@<distribution>`` trust entry; returns it normalised."""
    adapter_id, at, dist = token.strip().lower().partition("@")
    dist = distribution_key(dist)
    if not at or check_id(adapter_id) or not _DISTRIBUTION.fullmatch(dist):
        raise ValueError(
            f"{token.strip()!r} is not <id>@<distribution> (e.g. zest@zest-hswap); "
            "`hswap harnesses` prints the exact command for an installed plugin"
        )
    return f"{adapter_id}@{dist}"


@dataclass
class AdapterEntry:
    id: str
    origin: str  # "builtin" | "runtime" | "plugin:<distribution>"
    trusted: bool
    target: str | Factory
    error: str | None = None
    distribution: str | None = None  # plugins: normalised distribution name

    @property
    def trust_token(self) -> str | None:
        return f"{self.id}@{self.distribution}" if self.distribution else None


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
        self._trusted: set[str] = set()  # from settings, for the trust hint
        self._notices: list[tuple[str, str]] = []
        for adapter_id, target in (builtins or {}).items():
            self._entries[adapter_id] = AdapterEntry(adapter_id, "builtin", True, target)
        if discover_plugins:
            self._trusted = set(trusted_plugins or ())
            trusted = set(self._trusted)
            for token in os.environ.get("HSWAP_TRUSTED_PLUGINS", "").split(","):
                if token.strip():
                    try:
                        trusted.add(parse_trust(token))
                    except ValueError as exc:
                        self._notices.append(("HSWAP_TRUSTED_PLUGINS", str(exc)))
            self._discover(trusted)

    def _discover(self, trusted: set[str]) -> None:
        claims: dict[str, dict[str, str]] = {}  # id -> {distribution: target}
        names: dict[str, str] = {}
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            name = ep.dist.name if ep.dist else "unknown"
            dist = distribution_key(name)
            names[dist] = name
            claims.setdefault(ep.name, {})[dist] = ep.value
        for adapter_id, by_dist in claims.items():
            packages = ", ".join(names[d] for d in sorted(by_dist))
            if adapter_id in self._entries:
                self._notices.append((adapter_id, f"ignored: {packages} declares built-in id {adapter_id!r}"))
                continue
            reason = check_id(adapter_id)
            if reason:
                self._notices.append((adapter_id, f"ignored plugin id {adapter_id!r} from {packages}: {reason}"))
                continue
            if len(by_dist) > 1:
                self._entries[adapter_id] = AdapterEntry(
                    adapter_id,
                    f"plugin:{packages}",
                    False,
                    "",
                    error=f"declared by several packages ({packages}); uninstall all but one",
                )
                continue
            ((dist, target),) = by_dist.items()
            entry = AdapterEntry(adapter_id, f"plugin:{names[dist]}", False, target, distribution=dist)
            entry.trusted = entry.trust_token in trusted
            self._entries[adapter_id] = entry
        installed = {f"{adapter_id}@{dist}" for adapter_id, by_dist in claims.items() for dist in by_dist}
        for token in sorted(trusted - installed):
            self._notices.append((token, "trusted, but no installed package provides it; remove it from plugins.trusted"))

    def register(self, adapter_id: str, target: str | Factory) -> None:
        reason = check_id(adapter_id)
        if reason:
            raise ValueError(f"cannot register {adapter_id!r}: {reason}")
        self._entries[adapter_id] = AdapterEntry(adapter_id, "runtime", True, target)
        self._loaded.pop(adapter_id, None)

    def trust_command(self, adapter_id: str) -> str:
        """The config command that trusts ``adapter_id`` and keeps the others trusted."""
        token = self._entries[adapter_id].trust_token
        tokens = sorted(self._trusted | ({token} if token else set()))
        return f"hswap config set plugins.trusted {shlex.quote(','.join(tokens))}"

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
        if entry.error and not entry.trusted:
            raise HarnessNotFound(f"{adapter_id!r} {entry.error}")
        if not entry.trusted:
            raise HarnessNotFound(
                f"{adapter_id!r} comes from {entry.origin} and is not trusted; "
                f"run `{self.trust_command(adapter_id)}` to allow it"
            )
        if adapter_id not in self._loaded:
            try:
                adapter = _load_target(entry.target)
            except (Exception, SystemExit) as exc:  # a plugin must not end hswap
                entry.error = f"failed to load: {type(exc).__name__}: {exc}"
                raise HarnessNotFound(f"{adapter_id!r} {entry.error}") from exc
            if not isinstance(adapter, HarnessAdapter):
                entry.error = "does not implement the HarnessAdapter contract"
                raise HarnessNotFound(f"{adapter_id!r} {entry.error}")
            if adapter.id != adapter_id:
                entry.error = f"reports id {adapter.id!r}, but is registered as {adapter_id!r}"
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

    def notices(self) -> list[tuple[str, str]]:
        """``(subject, message)`` for entry points and trust settings that were ignored."""
        return list(self._notices)

    def problems(self) -> list[tuple[str, str]]:
        """Load failures (call after :meth:`available`) followed by :meth:`notices`."""
        failed = [(e.id, e.error) for e in self.entries() if e.error]
        return failed + self._notices  # type: ignore[return-value]


def default_registry() -> Registry:
    from harness_swap.adapters import BUILTIN
    from harness_swap.core import settings

    return Registry(BUILTIN, set(settings.load()["plugins.trusted"]))
