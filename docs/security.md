# Security

hswap holds long-lived logins for several services. These are the rules it
follows, where they are enforced, and how they are tested.

## Secrets stay out of output

- Core models (`Account`, `UsageSnapshot`, `SwitchResult`) have no field for
  secret material. Adapters label accounts by email, slot, or a SHA-256
  fingerprint of an API key (`sha256:` + 16 hex digits); a key or token is
  never part of an identity.
- Errors name accounts, never tokens (`tests/test_hswap_credentials.py::
  test_errors_never_contain_secret_material`).
- `output.emit_json` refuses to print anything shaped like a JWT or a vendor
  key (`infrastructure/secrets.py`) — a guard against regressions, not a
  redaction layer.
- `tests/test_hswap_cli.py::test_no_credential_material_reaches_any_output`
  runs every top-level and per-harness command on synthetic logins and checks
  that no token reaches stdout or stderr.
- hswap logs nothing about credentials. The Claude engine keeps its own
  logging rules (unchanged).

## Credential files

- Stored snapshots: `<hswap home>/<harness>/accounts/<slot>/` is 0700, each
  secret file 0600, metadata (`accounts.json`) 0600 and secret-free.
- Every write is temp file + fsync + rename at 0600 (`infrastructure/fsutil`),
  so a reader sees the old or the new file, never a partial one. A symlinked
  credential file is written through, not replaced.
- Writes happen under hswap's per-harness lock and, best effort, the harness's
  own lock file (`auth.lock`, `auth.json.lock`), which hswap opens without
  truncating.

## Switching never loses a login

For every file-backed harness (`core/credentials.py`):

1. **Sync-back.** Live parts that belong to stored accounts are copied back
   before anything is overwritten, so a token the harness rotated since the
   last switch is kept.
2. **Unmanaged logins are refused.** If the login being replaced is not one
   hswap stores, the switch stops with a message. `--force` continues only
   after stashing the original file (0600) under `<harness>/stash/`.
3. **Only the target part changes.** Other OAuth scopes / providers in the
   same file are carried over byte-for-byte in content.
4. **Verified and reversible.** The new file is re-read and re-identified; on
   any mismatch or error the original bytes are restored (or the file removed
   if there was none). A tampered or mismatched stored snapshot is refused
   before anything is written.
5. **No double refreshers.** An account running in an isolated session cannot
   be activated globally (or removed) until that session exits.

`add --login` signs a new account in inside a throwaway harness home, so the
current login is never replaced or logged out (which could revoke its refresh
token).

Native multi-account harnesses (OpenCode 2.x) are switched only through their
own commands; hswap never writes their databases and reads OpenCode's only
through a read-only connection, selecting the non-secret
`id/integration_id/active` columns.

## Cross-harness isolation

Accounts are keyed by `(harness, provider, identity)`. A stored credential is
only ever written back into the harness and part it came from; two harnesses
that talk to the same provider never share a stored login.

## Plugins

Third-party adapters run with access to your credentials, so installing one is
not enough: its entry point is listed but not imported until you trust its id
(`hswap config set plugins.trusted <id>` or `HSWAP_TRUSTED_PLUGINS`). A plugin
cannot replace a built-in adapter id.

## Rate limits and provider terms

hswap shows usage and lets you switch accounts. It does not rotate accounts
automatically for harnesses whose providers offer no documented quota interface
(Codex, Grok, OpenCode). `hswap claude auto` is the claude-swap feature,
unchanged. Make sure your use of multiple accounts complies with each
provider's terms; hswap is not a tool for getting around rate limits or
protective controls.

## Known limits

- Snapshot files rely on file permissions, like the harnesses' own files do;
  use full-disk encryption on shared machines.
- The harness lock is advisory and best effort: a harness that writes its
  credentials without its lock can still race a switch; the read-back check
  then fails the switch and restores the original.
- Windows: permission bits are not applied; files inherit the user profile's ACLs.
