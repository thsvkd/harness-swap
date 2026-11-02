# Writing a harness adapter

This guide adds a fifth harness to hswap. The running example is
[`examples/acme_adapter.py`](../examples/acme_adapter.py), a complete adapter
for a fictional harness "Acme Code"; `tests/test_hswap_contract.py` drives it
through the real CLI, so everything below is known to work.

## 1. Learn the harness first

Before writing code, answer from the harness's documentation or source (and
record the answers in [harness-compatibility.md](harness-compatibility.md),
tagged *verified*, *version-dependent*, *experimental* or *unsupported*):

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
| a JSON file in a home dir that an env var can move | `FileCredentialAdapter` (adapters/base.py) — you write a `CredentialFormat` and declarations |
| its own store, with commands to list/switch accounts | a plain class implementing the roles by calling those commands (see adapters/opencode.py, native mode) |
| something else (OS keychain, a database you may not write) | report the capabilities as unavailable with the reason; implement listing only if you can read it safely |

## 3. Describe the credential file

A `CredentialFormat` is three pure functions (no IO):

```python
class AcmeCredentials:
    secret_name = "credentials.json"          # file name in the per-account dir

    def parts(self, doc):                      # split the live file into parts
        return {"": doc} if isinstance(doc.get("account"), dict) else {}

    def identify(self, part_key, part):        # who owns a part? None = can't tell
        account = part["account"]
        if not account.get("id"):
            return None
        return Identity(identity=account["id"], label=account.get("email") or account["id"],
                        provider="acme", auth_mode="oauth")

    def merge(self, doc, part_key, part):      # put a part back, keep the rest
        return dict(part)
```

- Use `""` as the part key when the whole file is one account. When a file holds
  several logins (Grok scopes, OpenCode 1.x providers), make each one a part and
  have `merge` replace only that key.
- `identity` must be stable and unique within the provider: a subject/user id
  (plus workspace/team when one user can have several), never just the email.
  For API keys use `fingerprint(key)` — never the key itself.
- Put only non-secret extras in `Identity.meta` (they are shown in `--json`).

## 4. Declare the adapter

```python
class AcmeAdapter(FileCredentialAdapter):
    id = "acme"                       # hswap acme ...
    display_name = "Acme Code"
    providers = ("acme",)             # () for a multi-provider harness
    executable = "acme"               # probed with --version
    home_env = "ACME_HOME"            # moves the whole harness home
    default_home = ".acme"
    credential_file = "credentials.json"
    harness_lock_name = None          # the harness's own lock file, if it has one
    shared_names = ("settings.toml",) # linked into isolated sessions
    hot_reload = False                # do running processes re-read the login?
    fmt = AcmeCredentials()
```

`FileCredentialAdapter` then provides, with the core's guarantees: `list_accounts`,
`add_account` (current login, or `--login` in a throwaway home so the current
login is never replaced), `remove_account`, `switch_account` (with sync-back,
conflict refusal, single-part replacement, verification, rollback, restart
notice), `set_alias`, `launch` (isolated session) and `diagnose`.

## 5. Report capabilities honestly

```python
def capabilities(self):
    inst = self.installation()
    need_binary = None if inst.installed else unavailable(f"Acme Code is not installed ({inst.detail})")
    return {
        Capability.ACCOUNT_LIST: supported(),
        Capability.ACCOUNT_ADD: need_binary or supported(),
        Capability.ACCOUNT_SWITCH: supported("swaps $ACME_HOME/credentials.json"),
        Capability.USAGE_MONITORING: supported("Acme's own quota.json"),
        Capability.PARALLEL_SESSIONS: need_binary or supported("per-account ACME_HOME"),
        Capability.AUTOMATIC_ROTATION: unsupported("example adapter: manual switching only"),
    }
```

- Compute them from the install (version, config, binary present).
- Missing keys count as `unsupported`. Always give a reason the user can act on.
- Use `experimental(...)` when it works but relies on undocumented behaviour.
- Never return a fake success to satisfy an interface; `require()` will show
  the user your reason instead.

## 6. Usage (optional)

Implement `read_usage(account) -> UsageSnapshot` and set `usage_policy`.
Return one measurement; the `UsageService` handles pacing, caching across
processes, backoff and staleness. Map the provider's limits to `QuotaWindow`s
and its states to `UsageState` (`rate_limited`, `authentication_required`,
...). Raise on failure — it becomes an `error` snapshot that keeps the last good
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
them into one clean line (or a JSON error envelope). Never put token material
in a message; name the account by label or slot.

## 8. Register it

Inside hswap: add one line to `harness_swap/adapters/__init__.py`:

```python
BUILTIN = {..., "acme": "harness_swap.adapters.acme:AcmeAdapter"}
```

As a separate package (no change to hswap at all):

```toml
# your pyproject.toml
[project.entry-points."harness_swap.adapters"]
acme = "acme_adapter:AcmeAdapter"
```

Installed plugins are listed by `hswap harnesses` but not imported until the
user trusts them: `hswap config set plugins.trusted acme` (or
`HSWAP_TRUSTED_PLUGINS=acme`). The setting is the complete list —
`hswap config set plugins.trusted acme,other` — and the hint hswap prints
already includes the ids you trust. A plugin cannot take over a built-in id, and an
object that does not satisfy the contract under its id is rejected. Avoid ids
that are hswap commands (`list`, `status`, `config`, ...).

## 9. Test it

Copy the shape of `tests/test_hswap_contract.py` and the per-adapter tests:

- point the harness home at `tmp_path` with `monkeypatch.setenv(...)`, and
  `HSWAP_HOME` too (the test suite also clears them and blocks writes to real
  stores, see [testing.md](testing.md));
- write synthetic credentials (`tests/hswap_helpers.py` has JWT builders); never
  copy a real login;
- set `adapter._installation = Installation(True, "/fake/acme", "1.0")`, or put a
  fake executable on `PATH` (`fake_executable`) to exercise login flows;
- cover: add (twice = same slot), switch round trip, rotated-token sync-back,
  unmanaged login refused, other parts untouched, capability reasons for a
  missing binary, usage states, and that `--json` output contains no secret.

## 10. Checklist

- [ ] Facts recorded in harness-compatibility.md with their classification.
- [ ] Capabilities computed per install, every non-usable one with a reason.
- [ ] Identity stable and unique per provider; API keys fingerprinted.
- [ ] Rotated tokens survive a switch (sync-back covered by the core).
- [ ] Other logins in the same file untouched; nothing written outside the harness home.
- [ ] Restart/hot-reload behaviour reported in `SwitchResult.notes`.
- [ ] No secret in any output, error or log.
- [ ] Tests on synthetic data only.
