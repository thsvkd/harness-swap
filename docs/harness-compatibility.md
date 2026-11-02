# Harness compatibility

What hswap does with each harness, and how each fact was established.
Tags used below: **verified** (documented, or confirmed against the installed
version), **version-dependent**, **experimental** (works, but rests on
undocumented behaviour), **unsupported**.

Checked on 2026-11-02 against Claude Code 2.1.316, Codex CLI 0.166.0,
Grok Build 1.0.70, OpenCode 2.2.5 and Antigravity (`agy`) 1.4.8 on Linux (aarch64), using `--help`
output, the harnesses' own documentation and sources, and the *structure*
(key names only) of local credential files. No credential was read into
hswap's tests or copied.

## Capability matrix

| Capability | Claude Code | Codex CLI | Grok Build | OpenCode 2.x | OpenCode 1.x | Antigravity |
|---|---|---|---|---|---|---|
| account_list | supported | supported | supported | supported | supported | supported |
| account_add | supported | supported¹ | supported | supported (native) | experimental | supported⁵ |
| account_remove | supported | supported | supported | supported (native) | experimental | supported |
| account_switch | supported | supported¹ | supported | supported (native) | experimental | supported⁵ |
| native_account_switch | unsupported | unsupported | unsupported | supported | unsupported | unsupported |
| credential_refresh (by hswap) | supported | supported⁷ | supported⁷ | unsupported | unsupported | supported⁷ |
| usage_monitoring | supported | experimental⁴ | experimental⁴ | experimental⁴ | unsupported | experimental⁴ |
| automatic_rotation | supported | experimental⁶ | experimental⁶ | experimental⁶ | unsupported | experimental⁶ |
| parallel_sessions | experimental | supported² | experimental | unsupported | unsupported | experimental⁵ |
| session_resume | supported | supported | supported | unsupported | unsupported | supported⁵ |
| credential_hot_reload | supported³ | unsupported | supported | unsupported | unsupported | unsupported |

¹ `unavailable` unless `cli_auth_credentials_store` is `file` (the default).
² `experimental` on a Codex without `--no-daemon`.
³ `experimental` on macOS (Keychain cache).
⁴ opt-in (`usage.remote`), otherwise `unavailable` with that hint (Codex keeps its
passive log reading, also experimental). Read by asking the harness; only ever
checked against fake harnesses and the real binaries without accounts.
⁵ `unavailable` unless the login is file-backed (see Antigravity below); `add --login` is unavailable.
⁶ opt-in (`auto.enabled`) and only when usage is usable; the reason quotes the provider's terms.
⁷ `hswap <id> refresh` (no opt-in) asks the harness in each account's own home, so
the harness refreshes a due token there; hswap never refreshes it. Skipped for an
account a session runs, and for the active login while that harness may be running
(see [security.md](security.md#keep-alive-hswap-id-refresh)). Codex and Grok report
`token refreshed` or `token still valid`; agy reports `login used` (its refresh token
does not rotate). `unavailable` when the harness is not installed or the login is not file-backed.
OpenCode 2.x: unsupported, because it keeps inactive logins in its own database and refreshes an account only while it is active; switch to an idle account before its token lapses. Claude: the engine refreshes tokens when it reads usage (`hswap claude list`, or `hswap claude auto --once` from cron). Keep-alive is verified against fake harnesses only.
Run `hswap capabilities` for your install.

## Claude Code

The claude-swap engine (unchanged apart from a small embedding hook); see
[claude.md](claude.md) and its tests (2900+).

- `CLAUDE_CONFIG_DIR` relocates the config home; credentials in
  `.credentials.json` (0600) on Linux/Windows, Keychain on macOS — verified
  (code.claude.com/docs/en/env-vars, /authentication).
- Isolated sessions (`run`) are marked experimental, as upstream marks them.

## Codex CLI

| Fact | Status | Evidence |
|---|---|---|
| `CODEX_HOME` (default `~/.codex`) holds `auth.json`, `config.toml`, sessions | verified | openai/codex `utils/home-dir`, learn.chatgpt.com/docs/auth |
| the installed binary honours `CODEX_HOME` and accepts hswap's synthetic `auth.json` shape | verified locally | `CODEX_HOME=<tmp> codex login status` → "Logged in using ChatGPT" (synthetic file), "Not logged in" (empty home), error (missing dir) |
| `cli_auth_credentials_store` = `file` \| `keyring` \| `auto` \| `ephemeral`, default `file` | verified | docs; `config/defaults.toml`; option present in 0.166.0 binary |
| `auth.json` fields `auth_mode`, `OPENAI_API_KEY`, `tokens{id_token, access_token, refresh_token, account_id}`, `last_refresh` | verified (source), version-dependent | `login/src/auth/storage.rs`; local file structure matches |
| identity: `id_token` claims `https://api.openai.com/auth.chatgpt_user_id` + `chatgpt_account_id`, email | verified locally | claims present; same user may belong to several workspaces |
| running Codex loads the login once; before refreshing it re-reads and stops on an account mismatch | verified (source) | `login/src/auth/manager.rs` |
| refresh tokens rotate and are written back (temp file + replace, `auth.lock`) | verified (source) | `manager.rs`, `storage.rs` |
| `auth.lock` is taken only around writes (free while Codex runs) | verified locally | non-blocking `flock` succeeded with Codex running |
| `codex --no-daemon`: "Run without the shared background server" | verified | `codex --help` 0.166.0 |
| session logs `sessions/YYYY/MM/DD/rollout-*.jsonl`: header `creator_user_id`, `creator_account_id`; `rate_limits{primary, secondary{used_percent, window_minutes, resets_at}, credits, plan_type, rate_limit_reached_type}` | experimental | observed in 0.166.0 logs; ids match the `id_token` claims; undocumented format |
| usage endpoint `/wham/usage`, `x-codex-*` headers | **not used** | undocumented; hswap never calls provider APIs |
| `codex app-server --listen stdio://`, JSON-RPC `initialize`, `initialized`, `account/rateLimits/read` returns `rateLimits{primary, secondary, planType, credits, rateLimitReachedType}` | experimental (shape from 0.166.0 source and generated schema; field stability inferred) | only the unauthenticated path was run on the real binary: error "authentication required", request id 0 accepted. A logged-in answer was never exercised; fakes only |
| `usedPercent`, `windowDurationMins`, `resetsAt` (epoch seconds) | inferred (source) | covered by a fake that speaks the protocol |

What hswap does: swaps `$CODEX_HOME/auth.json` (file store only), reports how
many Codex processes must be restarted, captures rotated tokens before every
switch, signs new accounts in with `CODEX_HOME=<throwaway>` so the current login
is never replaced, and runs isolated sessions with `CODEX_HOME=<account dir>
codex --no-daemon`. Usage is the last rate-limit snapshot Codex itself logged
for that account on this machine — it is as old as the last Codex run, and the
age is always shown.

With `usage.remote` including `codex`, hswap instead starts `codex app-server
--listen stdio://` (no shell, no terminal) and asks `account/rateLimits/read`, so
Codex does any token refresh itself. An inactive account is asked with
`CODEX_HOME=<its own account dir>`; the active one in the default home, and only
when the access token has more than 10 minutes left (without a readable `exp`:
`last_refresh` younger than 8 days minus 10 minutes), else the last measurement
is kept (`stale`). An account owned by a running session is not asked. A reply
for a different account id is refused. Minimum interval 300 s.

Automatic rotation (opt-in) is experimental: OpenAI's Terms of Use (2024-12-11
text, third-party mirror; the current page returned 403) forbid using the services
to "circumvent any rate limits or restrictions"
(https://openai.com/policies/row-terms-of-use). Whether switching between your
own accounts counts is unknown (inferred). Not done: keyring/auto/ephemeral stores,
killing running Codex processes.

Known limit: a live read starts Codex in the account's home, which creates
`installation_id` and sqlite files there. A Codex that gets a 401 and refreshes
while hswap asks the active account cannot be prevented; hswap cannot see
processes outside its own session locks. Server-side limits on the endpoint are unknown.

Known risk: if a running Codex is in the middle of refreshing its token when you
switch, the server may rotate the old account's refresh token after hswap has
captured it; Codex then refuses to write it back (account mismatch), and that
account needs `codex login` again. Whether Codex holds `auth.lock` across the
network refresh is not documented. Switch while Codex is idle where you can;
hswap reports running Codex processes after every switch.

## Grok Build

Bundled user guide (`~/.grok/docs/user-guide/`, 1.0.70) and xai-org/grok-build:

| Fact | Status | Evidence |
|---|---|---|
| `GROK_HOME` overrides the whole home (default `~/.grok`) | verified | 05-configuration.md, 14-headless-mode.md; `GROK_HOME=<tmp> grok du` reports and populates the temp home (1.0.70) |
| `auth.json` (0600) maps scopes (`<issuer>::<client id>`, `xai::api_key`) to credentials; several may coexist; `auth.json.lock` | verified (source + local structure) | `xai-grok-login/src/config.rs`, `model.rs` |
| "Grok picks up changes to `~/.grok/auth.json` automatically ... without a restart" | verified | 02-authentication.md "Hot Reload" |
| `grok login` replaces the cached session; `grok logout` clears it | verified | 02-authentication.md |
| precedence: per-model key > session token > `XAI_API_KEY` | verified | 02-authentication.md |
| `GROK_AUTH_PATH` moves the login file but the reloader ignores it | verified (source) | `storage.rs` vs `config/reloader.rs` — hswap does not use it |
| leader process caches credentials? | unknown | leader mode is off by default; not documented |
| quota API in the documented CLI | none | `grok usage` prints per-session token cost; docs describe OTEL token metrics only |
| `grok agent --no-leader stdio` speaks ACP; `initialize` then the extension `_x.ai/billing`, which is what `/usage` shows (credit usage percent, current period, prepaid and on-demand balances) | experimental (undocumented extension; protocol and the unauthenticated errors seen on the real 1.0.70 binary in a sandbox) | error "requires auth with grok.com" for API-key logins, "Authentication required" when signed out; a logged-in answer was never run, fakes only |
| result field names (`config`, `creditUsagePercent`, `currentPeriod{type,start,end}`, `subscriptionTier`), timestamp format | inferred (binary strings, public grok-build source older than 1.0.70) | parsed defensively: seconds, milliseconds or ISO 8601 |
| JWT `tier` claim names the plan | third-party (public grok-build source) | used only when `subscriptionTier` is absent |

What hswap does: makes the target the only credential scope in `auth.json`
(Grok, not hswap, chooses between several, and a session token outranks an
API key), after syncing the other stored scopes back; a scope hswap does not
store stops the switch unless `--force` stashes the file; non-credential keys
are kept; signs new accounts in with `GROK_HOME=<throwaway>` (config.toml linked so
OIDC settings apply); isolated sessions with `GROK_HOME=<account dir>`, linking
`config.toml`, `rules`, `skills`, `memory`, `installed-plugins` and
`trusted_folders.toml` (experimental: session history is per account, and
leader mode was not tested).

With `usage.remote` including `grok`, hswap runs `grok agent --no-leader stdio`
with `GROK_HOME=<account home>` (timeout 120 s, startup is slow under emulation)
and asks `_x.ai/billing`: one window from `creditUsagePercent`, balance in dollars,
plan from the answer or the JWT tier. Inactive accounts are asked in their own
account dir; the active login only with more than 10 minutes left on
`min(expires_at, JWT exp)`; accounts owned by a running session and API-key
logins are not asked. `>= 100%` is `rate_limited`, even though pay-as-you-go
credit might still serve requests. If Grok permanently fails to refresh a stored
inactive copy it deletes that credential and the account must be added again.
Automatic rotation (opt-in) is experimental: the xAI Acceptable Use Policy
(effective 2026-08-14, https://x.ai/legal/acceptable-use-policy) prohibits
"circumventing any rate limits or restrictions" and "Accessing the Services
through unauthorized automated or non-human means"; xAI has no clause on one
person holding several genuine accounts (inferred).

## OpenCode

| Fact | Status | Evidence |
|---|---|---|
| 2.x stores credentials in its SQLite DB (`opencode debug paths` → `db`); do not edit it | verified | dev.opencode.ai/v2/docs/cli/providers |
| several saved accounts per integration; `auth list --format json`, `auth switch <integration> <label-or-id>`, `auth login`, `auth logout` | verified | docs; `--help` 2.2.5 |
| `auth list --format json` → `[{id, name, connections:[{type, id, label, method}]}]`, no active flag in 2.2.5 | verified locally | 2.2.5 output |
| `credential(id, integration_id, active, ...)` table; `active` 1/0 per integration; a lone account has been seen both as 1 (fresh 2.2.5 store) and NULL | experimental | read-only inspection of 2.2.5; used only to display `active` (a lone NULL is shown as active) |
| every `opencode auth` command needs OpenCode's managed background service: it starts one (≈335 MB resident on aarch64) if none runs, and fails if its port (default 49374) is taken by another OpenCode home's service | verified locally | 2.2.5; `opencode service set port <port>` moves it |
| legacy `~/.local/share/opencode/auth.json` (`{provider: {type, ...}}`) | verified (1.x docs) | opencode.ai/docs/providers; imported once by 2.x, not written back |
| release that introduced `auth switch` | unknown | hswap probes `opencode auth switch --help` instead of trusting a version number |
| running sessions pick up a switch? | unknown | not documented |

What hswap does: native mode whenever `auth switch` exists; it numbers saved
accounts and keeps aliases in its own store, never reads secret columns, and
opens the DB read-only (`mode=ro`) only to show which account is active
(`active: unknown` if that fails). Because it calls `opencode auth list`, even a
read-only `hswap list`, `hswap status` or the dashboard starts OpenCode's
background service when it is not running. hswap's own concurrent switches are
serialised; switches made by OpenCode itself at the same moment are not. Legacy mode for 1.x snapshots and swaps one
provider entry at a time (experimental; verified with synthetic files only).
Any other version is refused with an explanation. No isolated sessions.

Usage (native mode, opt-in `usage.remote`, experimental): hswap runs `opencode api
experimental.usage.limits` (no `--standalone`, so OpenCode's background service
does any refresh) while holding its switch lock. Envelope `{location, data}`;
`data: null` is `unknown`, `data.go.{rolling, weekly, monthly}` become `5h`,
`weekly` and `monthly` windows (`limited` or 100% is `rate_limited`), no `go` is
`unsupported`. Only the `data: null` envelope was seen on the real 2.2.5 binary
(sandbox, empty home); the `go` meter shape and the 401/503 text come from binary
strings and the OpenAPI document (inferred) and were never run against a Go
account. Only the *active* account with the `opencode` provider is measured;
inactive accounts, API-key and `opencode-go` logins are not, so automatic switching
rarely has evidence. Plan tier and console budgets are not mapped. Auth failure is
recognised by matching `401`/`Unauthorized` in the output (inferred). 1.x has no
usage interface (`opencode stats` is local statistics). Automatic rotation
(opt-in, experimental) quotes the OpenCode Terms of Service (effective 2026-08-15,
https://opencode.ai/legal/terms-of-service): a user may not create, maintain or
use "multiple accounts to circumvent usage limits, access restrictions, billing obligations".

## Antigravity (`agy`)

Facts from agy 1.4.8 on Linux; `agy` has no sign-in command that exits when done.

| Fact | Status | Evidence |
|---|---|---|
| token file `~/.gemini/antigravity-cli/antigravity-oauth-token` (0600 JSON: `token{access_token, token_type, refresh_token, expiry, expires_in}`, `auth_method`, `id_token_email`); a hand-written file with these keys is accepted | verified | real file (key names only) and sandbox runs |
| agy tries the OS keyring first and falls back to the file; headless hosts bypass the keyring | verified (logs) / documented (changelog) | macOS/Windows keychain: hswap reports unavailable. On Linux, file existence stands in for "agy uses the file"; a Secret Service that appears later may win over a switched file (inferred) |
| `--gemini_dir=<absolute>` moves app data (`<dir>/antigravity-cli/`) and config (`<dir>/config/`); hidden, not in `--help` | verified on 1.4.8 only | sandbox; relative values rejected; env vars do not work |
| no hot reload: a running agy keeps the old account after the file is replaced | verified | 3 TUI runs, about 2 min each; hswap says so on every switch |
| one Google login only; `/login` replaces it | verified | symbols, no multi-account command |
| identity: only `id_token_email` is offline | verified | hswap uses `<auth_method>/<lowercased email>`; a changed email looks like a new account; older files with `id_token` are not recognised |
| access token about 1 h; agy refreshes at start when near expiry and rewrites the file; refresh token normally unchanged | verified | fake endpoint capture |
| `agy -p /usage --output-format json` prints quota groups and buckets without an agent turn or spending quota | documented (changelog) + verified | fake endpoint and a third-party sample; never a real paid account |
| with no token file it starts an interactive login and waits 60 s | verified | hswap never asks without a token file |
| with a token it cannot refresh it prints `Authentication required` on stderr and waits 60 s for a browser sign-in | verified (agy 1.4.8, synthetic expired token) | hswap stops agy at that line and reports `sign in again` |
| `AGY_CLI_DISABLE_AUTO_UPDATE` disables the updater | inferred | string in the binary; hswap sets it for usage calls |
| plan tier / credits are not in `/usage` | verified | `plan` and `balance` stay empty |
| installation id per app data dir, device signals sent at start | verified | each `--gemini_dir` gets its own; several accounts from one host are visible server-side (inferred) |

What hswap does: `add` stores the current login (add the next account by signing
in with agy, then add again), `switch` swaps the token file, isolated sessions use
`--gemini_dir=<account dir>` with `config` and `antigravity-cli/settings.json`
linked (experimental, hidden flag). Usage (opt-in, experimental): `agy
[--gemini_dir=...] -p /usage --output-format json`, 60 s timeout, windows named
`<group> <window>` (for example "Gemini Models 5h"), `used_percent = (1 -
remaining_fraction) * 100`, a bucket without `remaining_fraction` is unknown, not
guessed. Skipped as `stale` when a session owns the account, there is no token
file, or the active token has 10 minutes or less left (or its expiry is unreadable).
Authentication failures are recognised by "Authentication expired" and
`UNAUTHENTICATED`; the text for a revoked or ToS-blocked login is unverified, so
those become error snapshots with backoff.

Terms (documented, https://antigravity.google/terms, Additional Terms section 6):
using "third party software, tools, or services to access the Service" is
prohibited and "Such actions may be grounds for suspension or termination of
your Antigravity and/or Gemini CLI accounts." Whether running the official `agy`
from another tool falls under it is unanswered by Google staff (third-party
forum thread). Non-staff forum replies say cycling several accounts to bypass
quota breaks the terms, and account suspensions were reported in 2026
(https://discuss.ai.google.dev/t/antigravity-account-disabled-violation-of-terms-of-service-requesting-support/123014).
Automatic rotation for agy therefore carries the strongest warning of all harnesses.

Open: whether `--gemini_dir` scopes a keyring entry; the real payload for a paid
account; whether a long-running session ever re-reads the token file.

Not supported on purpose: Cursor (user decision) and Gemini CLI (retired).

## Cross-platform notes

- Isolated sessions link shared files with symlinks on POSIX only; on Windows
  a session starts without them.
- `run` starts the harness as a child process and waits for it on every
  platform, holding the session lock until it exits; exit status is passed through.
- Fake-executable tests (login flows, OpenCode emulator) are POSIX-only; the
  remaining hswap tests and the full engine suite are platform-neutral.
- Only Linux was exercised in this change; macOS/Windows behaviour of the new
  adapters is untested.
