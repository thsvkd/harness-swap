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
  key with a mixed-case, digit-bearing body (`infrastructure/secrets.py`) — a
  guard against regressions, not a redaction layer; an all-lowercase key body
  would not be caught.
- `tests/test_hswap_cli.py::test_no_credential_material_reaches_any_output`
  runs every top-level and per-harness command on synthetic logins and checks
  that no token reaches stdout or stderr.
- hswap logs nothing about credentials. The Claude engine keeps its own
  logging rules (unchanged).
- One deliberate exception: `hswap claude export -` writes the exported
  accounts, tokens included, to stdout, and `hswap claude export <file>` to a
  0600 file (replacing an existing one). That is the claude-swap export
  format, plaintext by design (see [claude.md](claude.md)); treat its output
  like the credentials it contains.

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
   hswap stores (or the live file is empty or not valid JSON), the switch stops
   with a message. `--force` continues only after stashing the original file
   (0600) under `<harness>/stash/`, and prints where.
3. **Nothing unrelated changes.** Entries of other providers in the same file
   (OpenCode 1.x) and non-credential keys are carried over unchanged. Grok is
   the exception by design: Grok itself picks between several login scopes, so
   the target becomes the only one; every other scope is first saved back into
   its stored account, and one hswap does not store (including the target
   account signed in under a different scope) stops the switch unless `--force`
   stashes the file.
4. **Verified and reversible.** The new file is re-read and re-identified; on
   any mismatch or error the original bytes are restored (or the file removed
   if there was none). A tampered or mismatched stored snapshot is refused
   before anything is written.
5. **No double refreshers.** For file-backed harnesses (Codex, Grok), an
   account running in an isolated session cannot be activated globally (or
   removed) until that session exits; the check and the session start both
   happen under the store lock, and sync-back skips that account's snapshot,
   which the session keeps fresher. A `run` on the account that already is the
   default login uses the default home and locks it, so no switch or remove can
   change the login under it. Claude's `run` follows the claude-swap rules.

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

Third-party adapters run with access to your credentials, so an installed
plugin is listed but not imported until you trust it, and trust names the
package as well as the id: `hswap config set plugins.trusted <id>@<distribution>`
(or `HSWAP_TRUSTED_PLUGINS`). `hswap harnesses` prints that command, shell-safe.

- A package that declares an id you trusted for a *different* package is not
  trusted; trusted entries with no installed package are reported by
  `hswap doctor` and `hswap harnesses`.
- An id declared by two installed packages is loaded from neither.
- Ids are validated (lowercase, path-safe, not an hswap command or data
  directory); a plugin cannot replace a built-in id. Ignored entry points are
  reported, not silently dropped.
- A plugin that fails to load, raises, or exits is reported as an error for
  its own id; the other harnesses keep working.

This gate controls which adapters hswap *uses*. It is not a sandbox: any
package installed into hswap's environment can already run code when Python
starts (for example through a `.pth` file). Install only plugins you would
trust with your logins.

## Usage reads

hswap never refreshes a token or calls a provider's API itself (Claude's
claude-swap engine keeps its own behaviour). With `usage.remote` on, it starts the
*harness* and asks it (Codex `app-server`, Grok's ACP agent, OpenCode's `api`
command, `agy -p /usage`): the harness refreshes its own tokens and stores them
where it always does.

- An inactive account is asked in its own account directory
  (`FileCredentialAdapter.usage_home`) with that home's session lock held, so no
  other process holds the same rotating refresh token. If a running session owns
  the account it is not asked; the last measurement is shown as `stale`.
- The active account is asked in the default home only when its access token has
  more than 10 minutes left (Codex: JWT `exp`, else `last_refresh`; Grok: the
  earlier of `expires_at` and JWT `exp`; agy: `token.expiry`). If the expiry is
  unreadable it is not asked.
- If the live login file of a harness cannot be read, usage reads for every
  account of that harness return an error snapshot rather than reading a stored
  copy (which could be the account that is actually live).
- The child gets no shell and no terminal; error text from it is scrubbed and
  agy output is never echoed. `list --cached` and `usage --cached` start nothing.
- Limits: a Codex that refreshes after a 401 while hswap is asking cannot be
  detected, OpenCode's active flag and refresh happen inside its own service, and
  every live read is verified only against fake harnesses and real binaries
  without accounts (see [testing.md](testing.md)).

## Keep-alive (`hswap <id> refresh`)

`hswap codex|grok|agy refresh [ACCOUNT]` asks the harness the same usage question
to keep a stored login from lapsing. It needs no `usage.remote` opt-in (running it
is the request) and bypasses the usage cache.

- Each account is asked in its own home with that home's session lock held, as
  above; an account a running session owns is skipped (that session keeps it fresh).
- The active login is asked in the default home only when no process of that
  harness is found on this machine, matched by executable name or by an executable
  on its command line (a Grok started through a wrapper or `qemu` counts); an
  unreadable process table counts as running. The 10-minute guard does not apply,
  since nothing else can be refreshing the token.
- The result compares a SHA-256 of the refresh-relevant fields before and after
  (`token refreshed`, `token still valid`); tokens, file contents and harness output
  never appear in it. An authentication failure says `sign in again: ...` and exits 1.
- Several devices: each device's own `codex login` / `grok login` has its own
  refresh token, so refreshing this device's stored copy does not affect other
  devices. The only unsafe case is copying or syncing the same credential file
  between devices (two holders of one rotating refresh token); do not do that.
- Limits: the process check runs once, so a harness started by hand on the default
  home while hswap's harness runs (up to 45 s for Codex, 120 s for Grok) could
  redeem the same refresh token; Grok's `auth.json.lock` narrows this, Codex has no
  verified cross-process refresh lock. A Codex read cut off at its timeout while
  Codex is mid-refresh can lose the rotated token; hswap says so.

## Rate limits and provider terms

Automatic switching is opt-in per harness (`hswap config set auto.enabled <ids>`,
then `hswap <harness> auto`), needs live usage, is experimental everywhere, never
acts on missing or stale data and waits `auto.cooldown` between switches. It may
breach a provider's terms; you are responsible. What each says, and where
`hswap capabilities` quotes it:

- Google Antigravity: Additional Terms section 6 prohibits "Using third party
  software, tools, or services to access the Service" and says such actions "may
  be grounds for suspension or termination" of Antigravity and/or Gemini CLI
  accounts; suspensions were reported in 2026. Strongest warning.
- OpenAI (Codex): the Terms of Use (2024-12-11 text) forbid using the services
  to "circumvent any rate limits or restrictions"; whether switching between your
  own accounts counts is not stated.
- xAI (Grok): the Acceptable Use Policy prohibits "circumventing any rate limits
  or restrictions" and access through "unauthorized automated or non-human
  means"; nothing on several genuine accounts.
- OpenCode: the Terms of Service forbid using multiple accounts "to circumvent
  usage limits, access restrictions, billing obligations".
- Anthropic: `hswap claude auto` is the claude-swap feature, unchanged.

hswap is not a tool for getting around rate limits or protective controls.

## Known limits

- Snapshot files rely on file permissions, like the harnesses' own files do;
  use full-disk encryption on shared machines.
- The harness lock is advisory and best effort: a harness that writes its
  credentials without its lock can still race a switch; the read-back check
  then fails the switch and restores the original.
- Windows: permission bits are not applied; files inherit the user profile's ACLs.
- The session lock is held by hswap while it waits for the harness; if hswap is
  killed with SIGKILL the harness keeps running but the session no longer counts
  as in use.
- A Codex token refresh that is in flight during a switch can leave the outgoing
  account needing a fresh `codex login` (see harness-compatibility.md).
