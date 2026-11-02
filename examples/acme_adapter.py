"""Example hswap adapter for a fictional harness, "Acme Code".

Acme Code keeps its login in ``$ACME_HOME/credentials.json`` (default
``~/.acme``)::

    {"account": {"id": "u-123", "email": "me@example.com", "token": "..."}}

and, to make the example complete, writes the quota it last saw to
``$ACME_HOME/quota.json`` as ``{"<account id>": {"used": 42, "resets_at": <epoch>}}``.

Everything hswap does with it -- add, list, switch (with sync-back, conflict
refusal, rollback), aliases, isolated ``run`` sessions, usage with caching and
backoff, ``switch --strategy``, the dashboard -- comes from the core and
:class:`FileCredentialAdapter`. This file only *describes* Acme Code.

Use it as a plugin from your own package::

    # pyproject.toml
    [project.entry-points."harness_swap.adapters"]
    acme = "acme_adapter:AcmeAdapter"

then ``hswap config set plugins.trusted acme`` and ``hswap acme list``.
See docs/adapter-development.md for the walkthrough.
"""

from __future__ import annotations

import json

from harness_swap.adapters.base import FileCredentialAdapter
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.credentials import Identity
from harness_swap.core.models import (
    Account,
    Capability,
    CapabilityStatus,
    QuotaWindow,
    UsageSnapshot,
    UsageState,
    supported,
    unavailable,
    unsupported,
)


class AcmeCredentials:
    """How Acme lays out credentials.json: one account per file."""

    secret_name = "credentials.json"

    def parts(self, doc: dict) -> dict[str, dict]:
        return {"": doc} if isinstance(doc.get("account"), dict) else {}

    def identify(self, part_key: str, part: dict) -> Identity | None:
        account = part["account"]
        if not account.get("id"):
            return None
        return Identity(
            identity=account["id"],
            label=account.get("email") or account["id"],
            provider="acme",
            auth_mode="oauth",
        )

    def merge(self, doc: dict | None, part_key: str, part: dict) -> dict:
        return dict(part)


class AcmeAdapter(FileCredentialAdapter):
    id = "acme"
    display_name = "Acme Code"
    providers = ("acme",)
    executable = "acme"
    home_env = "ACME_HOME"
    default_home = ".acme"
    credential_file = "credentials.json"
    shared_names = ("settings.toml",)
    hot_reload = False
    fmt = AcmeCredentials()
    usage_policy = UsagePolicy(min_interval_s=60.0, stale_after_s=900.0)

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        inst = self.installation()
        need_binary = None if inst.installed else unavailable(f"Acme Code is not installed ({inst.detail})")
        return {
            Capability.ACCOUNT_LIST: supported(),
            Capability.ACCOUNT_ADD: need_binary or supported(),
            Capability.ACCOUNT_REMOVE: supported(),
            Capability.ACCOUNT_SWITCH: supported("swaps $ACME_HOME/credentials.json"),
            Capability.USAGE_MONITORING: supported("Acme's own quota.json"),
            Capability.PARALLEL_SESSIONS: need_binary or supported("per-account ACME_HOME"),
            Capability.AUTOMATIC_ROTATION: unsupported("example adapter: manual switching only"),
        }

    def read_usage(self, account: Account) -> UsageSnapshot:
        try:
            quota = json.loads((self.home / "quota.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return UsageSnapshot(UsageState.UNKNOWN, detail="Acme has not reported quota yet")
        entry = quota.get(account.identity)
        if entry is None:
            return UsageSnapshot(UsageState.UNKNOWN, detail="no quota recorded for this account")
        window = QuotaWindow("day", float(entry["used"]), entry.get("resets_at"), 86400)
        state = UsageState.RATE_LIMITED if window.used_percent >= 100 else UsageState.AVAILABLE
        return UsageSnapshot(state, (window,), measured_at=entry.get("measured_at"), source="acme-quota-file")
