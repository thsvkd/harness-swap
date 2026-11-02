# Writing a harness adapter

This guide adds a fifth harness to hswap, either inside hswap or as a separately
installed plugin package. The running example is
[`examples/acme_adapter.py`](../examples/acme_adapter.py), a complete adapter
for a fictional harness "Acme Code"; `tests/test_hswap_contract.py` drives it
through the real CLI, so everything below is known to work.

## 1. Learn the harness first

Before writing code, answer from the harness's documentation or source, and
record the answers with their classification (*verified*, *version-dependent*,
*experimental* or *unsupported*): in
[harness-compatibility.md](harness-compatibility.md) for an adapter inside
hswap, in your plugin's README for a plugin.

1. How is it installed, and how do you read its version?
2. Where does it keep the login, in what format, with what permissions and locks?
3. Can that location be moved with an environment variable (for isolated sessions)?
4. Does it already support several saved accounts natively?
5. Does a running process re-read the login, or keep it in memory?
6. Does it rotate refresh tokens (so stored copies go stale)?
7. Is there a documented, machine-readable quota/usage interface?
8. Do the provider's terms allow switching accounts automatically?

Do not guess. An unknown answer becomes an `unsupported`/`unavailable`
capability with the reason, not an implementation.

## 2. Pick a starting point

| Harness keeps its login in... | Start from |
|---|---|
| a JSON file in a home dir that an env var can move | `FileCredentialAdapter` (adapters/base.py): you write a `CredentialFormat` and declarations |
| its own store, with commands to list/switch accounts | a plain class implementing the roles by calling those commands (see adapters/opencode.py, native mode) |
| something else (OS keychain, a database you may not write) | report the capabilities as unavailable with the reason; implement listing only if you can read it safely |

Everything an adapter needs is importable from these modules:

```python
from harness_swap.adapters.base import FileCredentialAdapter
from harness_swap.core.adapter import UsagePolicy
from harness_swap.core.credentials import Identity, fingerprint, jwt_claims
from harness_swap.core.errors import (
    CredentialConflict, CredentialError, HarnessNotInstalled, HswapError, UnsupportedOperation,
)
from harness_swap.core.models import (
    Account, Capability, CapabilityStatus, QuotaWindow, UsageSnapshot, UsageState,
    experimental, supported, unavailable, unsupported,
)
```

## 3. Describe the credential file

A `CredentialFormat` is three pure functions (no IO) plus the snapshot file name:

```python
class AcmeCredentials:
    secret_name = "credentials.json"          # must equal the adapter's credential_file

    def parts(self, doc):                      # split the live file into parts
        return {"": doc} if isinstance(doc.get("account"), dict) else {}

    def identify(self, part_key, part):        # who owns a part? None = can't tell
        account = part["account"]
        if not account.get("id"):
            return None
        return Identity(identity=account["id"], label=account.get("email") or account["id"],
                        provider="acme", auth_mode="oauth")

    def merge(self, doc, part_key, part):      # put a part back into doc
        return dict(part)                      # "" = the whole file, so the part *is* the file
```

`Identity(identity, label, provider, auth_mode, meta={})`:

- `identity` must be stable and unique within the provider: a subject/user id
  (plus workspace/team when one user can have several), never just the email.
  For API keys use `fingerprint(key)`, never the key itself.
- `label` is what users see (an email, or `API key <fingerprint>`).
- `meta` holds only non-secret extras; they are shown in `--json`.
- `jwt_claims(token)` returns a JWT's payload claims as a dict (no signature
  check, no network), for logins that carry an id token.

Part keys:

- Use `""` when the whole file is one account. When a file holds several
  logins (OpenCode 1.x providers), make each one a part and have `merge`
  replace only that key and keep the rest of `doc` (which is `None` when there
  is no live file yet).
- If the *harness* chooses between several logins in one file (Grok scopes),
  set `exclusive = True` on the format: a switch then leaves the target as the
  only credential part, after saving the others back (part keys must be
  top-level keys).

## 4. Declare the adapter

```python
class AcmeAdapter(FileCredentialAdapter):
    id = "acme"                       # hswap acme ... (rules in section 8)
    display_name = "Acme Code"
    providers = ("acme",)             # () for a multi-provider harness
    executable = "acme"               # probed with --version
    home_env = "ACME_HOME"            # moves the whole harness home
    default_home = ".acme"            # relative to the user's home
    credential_file = "credentials.json"
    harness_lock_name = None          # the harness's own lock file, if it has one
    shared_names = ("settings.toml",) # linked into isolated sessions and --login homes
    login_args = ("login",)           # what `hswap acme add --login` runs
    hot_reload = False                # do running processes re-read the login?
    fmt = AcmeCredentials()
```

- `fmt.secret_name` must equal `credential_file`: the account's directory in
  hswap's store doubles as the harness home of an isolated session. hswap
  refuses to construct an adapter that breaks this.
- Override `session_args(self) -> list[str]` to add harness arguments to every
  isolated session (Codex adds `--no-daemon`), and
  `login_shared_names(self)` if `--login` needs a different set of linked
  files than sessions.

`FileCredentialAdapter` then provides, with the core's guarantees: `list_accounts`,
`add_account` (current login, or `--login` in a throwaway home so the current
login is never replaced), `remove_account`, `switch_account` (with sync-back,
conflict refusal, target-part (or exclusive) replacement, verification, rollback, restart
notice), `set_alias`, `launch` (isolated session) and `diagnose`.

## 5. Report capabilities honestly

Every `hswap <id>` verb is gated by one capability; a missing key counts as
`unsupported` and the verb is refused:

| Verb | Capability |
|---|---|
| `list`, `status` | `account_list` |
| `add` | `account_add` |
| `remove` | `account_remove` |
| `switch` | `account_switch` |
| `run` | `parallel_sessions` |
| `usage`, `switch --strategy` | `usage_monitoring` |

```python
def capabilities(self):
    inst = self.installation()
    need_binary = None if inst.installed else unavailable(f"Acme Code is not installed ({inst.detail})")
    return {
        Capability.ACCOUNT_LIST: supported(),
        Capability.ACCOUNT_ADD: supported("current login, or --login (needs the acme binary)"),
        Capability.ACCOUNT_REMOVE: supported(),
        Capability.ACCOUNT_SWITCH: supported("swaps $ACME_HOME/credentials.json"),
        Capability.USAGE_MONITORING: supported("Acme's own quota.json"),
        Capability.PARALLEL_SESSIONS: need_binary or supported("per-account ACME_HOME"),
        Capability.AUTOMATIC_ROTATION: unsupported("example adapter: manual switching only"),
    }
```

- Compute them from the install (version, config, binary present). Adding the
  current login needs no binary; `--login` checks for it by itself.
- `installation()` finds `executable` on `PATH` and runs it with `--version`. If
  the name is common (another program could own it), check that the version
  output is really your harness's before reporting it installed.
- Always give a reason the user can act on.
- Use `experimental(...)` when it works but relies on undocumented behaviour.
- Never return a fake success to satisfy an interface; `require()` will show
  the user your reason instead.

## 6. Usage (optional)

Implement `read_usage(account) -> UsageSnapshot` and set `usage_policy`.
Return one measurement; the `UsageService` handles pacing, caching across
processes, backoff and staleness. Map the provider's limits to `QuotaWindow`s
and its states to `UsageState` (`rate_limited`, `authentication_required`,
...). Raise on failure: it becomes an `error` snapshot that keeps the last good
numbers. Use only documented interfaces (or data the harness itself writes
locally); if there is none, do not implement the role and report
`usage_monitoring` as unsupported.

With usage available, `hswap acme switch --strategy best|next-available` works
automatically. Automatic background rotation is a separate decision: report
`automatic_rotation` as supported only if the provider's terms allow it.

## 7. Errors

Raise `harness_swap.core.errors` types: `UnsupportedOperation(capability,
reason)`, `HarnessNotInstalled`, `AccountNotFound`, `CredentialError`,
`CredentialConflict`, `LockError`, or plain `HswapError(message)`. The CLI turns
them into one clean line (or a JSON error envelope). Any other exception from
an adapter is shown the same way as `<Type>: <message>` (set `HSWAP_DEBUG=1` for
the traceback) and does not stop cross-harness commands, but it reads as a bug. Never put token material in a
message; name the account by label or slot.

## 8. Register it

**Ids** are 1-32 lowercase letters, digits, `-` or `_`, starting with a letter.
They may not be a built-in id (`claude`, `codex`, `grok`, `opencode`) or one of
hswap's own command or directory names: `harnesses capabilities list ls status
doctor migrate config tui help version cache backups`. The entry-point name and
the adapter's `id` must be the same string. Entry points that break these rules
are not loaded; `hswap harnesses` and `hswap doctor` say why.

Inside hswap: add one line to `harness_swap/adapters/__init__.py`:

```python
BUILTIN = {..., "acme": "harness_swap.adapters.acme:AcmeAdapter"}
```

As a separate package (no change to hswap at all):

```toml
# excerpt of your pyproject.toml
[project]
name = "acme-hswap"
dependencies = ["harness-swap"]

[project.entry-points."harness_swap.adapters"]
acme = "acme_adapter:AcmeAdapter"
```

(With hatchling, a module whose name differs from the project's needs
`[tool.hatch.build.targets.wheel] packages = ["acme_adapter.py"]` or similar.)

Install the plugin into hswap's own environment:

```bash
uv tool install harness-swap --with acme-hswap     # or: pipx inject harness-swap acme-hswap
uv tool install --reinstall ./harness-swap --with ./acme-hswap   # from local checkouts
```

`uv tool install harness-swap` run again *without* `--with` removes the plugin,
so repeat the `--with` on every reinstall or upgrade.

Installed plugins are listed by `hswap harnesses` but not imported until the
user trusts that id **from that distribution**. `hswap harnesses` prints the
exact command, which keeps the plugins already trusted:

```bash
hswap config set plugins.trusted acme@acme-hswap          # or HSWAP_TRUSTED_PLUGINS=acme@acme-hswap
```

If another package later declares the same id, it is not trusted, and an id
declared by two installed packages is not loaded at all until one is removed.

## 9. Test it

Copy the shape of `tests/test_hswap_contract.py` and the per-adapter tests:

- point the harness home at `tmp_path` with `monkeypatch.setenv(...)`, and
  `HSWAP_HOME` too (hswap's own suite also clears them and blocks writes to
  real stores, see [testing.md](testing.md));
- write synthetic credentials and never copy a real login. hswap's repository
  has small builders in `tests/hswap_helpers.py` (unsigned JWTs, fake
  executables); they are not part of the installed package, so copy what you
  need into your plugin's tests;
- instead of installing the harness, put a fake executable on `PATH` that
  answers `--version` (and `login`, to exercise `--login`);
- cover: add (twice = same slot), switch round trip, rotated-token sync-back,
  unmanaged login refused, other parts untouched, capability reasons for a
  missing binary, usage states, and that `--json` output contains no secret.

## 10. Checklist

- [ ] Facts recorded with their classification.
- [ ] Id follows the rules in section 8 and equals the entry-point name.
- [ ] Capabilities computed per install, every non-usable one with a reason,
      one for every verb you support.
- [ ] Identity stable and unique per provider; API keys fingerprinted.
- [ ] `fmt.secret_name == credential_file`.
- [ ] Rotated tokens survive a switch (sync-back covered by the core).
- [ ] Other logins in the same file untouched; nothing written outside the harness home.
- [ ] Restart/hot-reload behaviour reported in `SwitchResult.notes`.
- [ ] No secret in any output, error or log.
- [ ] Tests on synthetic data only.
