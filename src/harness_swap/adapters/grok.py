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
* There is no quota interface: ``grok usage`` prints per-session token cost,
  and the documented monitoring is OpenTelemetry token metrics. Usage
  monitoring is therefore reported as unsupported, never estimated.
"""

from __future__ import annotations

from harness_swap.adapters.base import FileCredentialAdapter
from harness_swap.core.credentials import Identity, fingerprint
from harness_swap.core.models import (
    Capability,
    CapabilityStatus,
    experimental,
    supported,
    unavailable,
    unsupported,
)


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

    def capabilities(self) -> dict[Capability, CapabilityStatus]:
        inst = self.installation()
        blocked = None if inst.installed else unavailable(f"Grok Build is not installed ({inst.detail})")
        return {
            Capability.ACCOUNT_LIST: supported(),
            Capability.ACCOUNT_ADD: blocked or supported("current login, or --login in an isolated GROK_HOME"),
            Capability.ACCOUNT_REMOVE: supported("forgets hswap's copy; the live login is untouched"),
            Capability.ACCOUNT_SWITCH: blocked or supported("replaces one login scope in $GROK_HOME/auth.json"),
            Capability.NATIVE_ACCOUNT_SWITCH: unsupported("`grok login` replaces the single cached session"),
            Capability.CREDENTIAL_REFRESH: unsupported("Grok refreshes its own tokens; hswap captures them before a switch"),
            Capability.USAGE_MONITORING: unsupported(
                "Grok Build has no quota interface (`grok usage` is per-session token cost)"
            ),
            Capability.AUTOMATIC_ROTATION: unsupported("no quota data to rotate on"),
            Capability.PARALLEL_SESSIONS: blocked
            or experimental(
                "per-account GROK_HOME with shared config, rules, skills, memory and plugins linked in; "
                "session history is per account"
            ),
            Capability.SESSION_RESUME: supported("`run <account> -- --continue`; history is per account home"),
            Capability.CREDENTIAL_HOT_RELOAD: supported("documented: Grok reloads auth.json on its next request"),
        }
