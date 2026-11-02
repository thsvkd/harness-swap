# Harness compatibility

What hswap does with each harness, and how each fact was established.
Classification: **verified** (documented, or confirmed against the installed
version), **version-dependent**, **experimental** (works, but rests on
undocumented behaviour), **unsupported**.

Checked on 2026-11-02 against Claude Code 2.1.316, Codex CLI 0.166.0,
Grok Build 1.0.70 and OpenCode 2.2.5 on Linux (aarch64), using `--help`
output, the harnesses' own documentation and sources, and the *structure*
(key names only) of local credential files. No credential was read into
hswap's tests or copied.

## Capability matrix

| Capability | Claude Code | Codex CLI | Grok Build | OpenCode 2.x | OpenCode 1.x |
|---|---|---|---|---|---|
| account_list | supported | supported | supported | supported | supported |
| account_add | supported | supported¹ | supported | supported (native) | experimental |
| account_remove | supported | supported | supported | supported (native) | experimental |
| account_switch | supported | supported¹ | supported | supported (native) | experimental |
| native_account_switch | unsupported | unsupported | unsupported | supported | unsupported |
| credential_refresh (by hswap) | supported | unsupported | unsupported | unsupported | unsupported |
| usage_monitoring | supported | experimental | unsupported | unsupported | unsupported |
| automatic_rotation | supported | unsupported | unsupported | unsupported | unsupported |
| parallel_sessions | experimental | supported² | experimental | unsupported | unsupported |
| session_resume | supported | supported | supported | unsupported | unsupported |
| credential_hot_reload | supported³ | unsupported | supported | unsupported | unsupported |

¹ `unavailable` unless `cli_auth_credentials_store` is `file` (the default).
² `experimental` on a Codex without `--no-daemon`.
³ `experimental` on macOS (Keychain cache).
Run `hswap capabilities` for your install.

## Claude Code

Unchanged claude-swap engine; see [claude.md](claude.md) and its tests (2900+).

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
| usage endpoint `/wham/usage`, `x-codex-*` headers | **not used** | undocumented |

What hswap does: swaps `$CODEX_HOME/auth.json` (file store only), reports how
many Codex processes must be restarted, captures rotated tokens before every
switch, signs new accounts in with `CODEX_HOME=<throwaway>` so the current login
is never replaced, and runs isolated sessions with `CODEX_HOME=<account dir>
codex --no-daemon`. Usage is the last rate-limit snapshot Codex itself logged
for that account on this machine — it is as old as the last Codex run, and the
age is always shown.

Not done: automatic rotation (no documented quota API; rotating accounts to get
around rate limits may breach OpenAI's terms), keyring/auto/ephemeral stores,
killing running Codex processes.

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
| quota API | none | `grok usage` prints per-session token cost; docs describe OTEL token metrics only |

What hswap does: switches one scope inside `auth.json` and keeps every other
scope; signs new accounts in with `GROK_HOME=<throwaway>` (config.toml linked so
OIDC settings apply); isolated sessions with `GROK_HOME=<account dir>`, linking
`config.toml`, `rules`, `skills`, `memory`, `installed-plugins` and
`trusted_folders.toml` (experimental: session history is per account, and
leader mode was not tested). Usage monitoring is reported unsupported.

## OpenCode

| Fact | Status | Evidence |
|---|---|---|
| 2.x stores credentials in its SQLite DB (`opencode debug paths` → `db`); do not edit it | verified | dev.opencode.ai/v2/docs/cli/providers |
| several saved accounts per integration; `auth list --format json`, `auth switch <integration> <label-or-id>`, `auth login`, `auth logout` | verified | docs; `--help` 2.2.5 |
| `auth list --format json` → `[{id, name, connections:[{type, id, label, method}]}]`, no active flag in 2.2.5 | verified locally | 2.2.5 output |
| `credential(id, integration_id, active, ...)` table; `active` 1/0 per integration, NULL for a lone account | experimental | read-only inspection of 2.2.5; used only to display `active` |
| legacy `~/.local/share/opencode/auth.json` (`{provider: {type, ...}}`) | verified (1.x docs) | opencode.ai/docs/providers; imported once by 2.x, not written back |
| release that introduced `auth switch` | unknown | hswap probes `opencode auth switch --help` instead of trusting a version number |
| running sessions pick up a switch? | unknown | not documented |

What hswap does: native mode whenever `auth switch` exists; it numbers saved
accounts and keeps aliases in its own store, never reads secret columns, and
opens the DB read-only (`mode=ro`) only to show which account is active
(`active: unknown` if that fails). Legacy mode for 1.x snapshots and swaps one
provider entry at a time (experimental; verified with synthetic files only).
Any other version is refused with an explanation. No isolated sessions and no
usage (no quota interface; `opencode stats` is local statistics).

## Cross-platform notes

- Isolated sessions link shared files with symlinks on POSIX only; on Windows
  a session starts without them.
- On Windows `run` waits for the harness as a child process (no `exec`), holding
  the session lock until it exits.
- Fake-executable tests (login flows, OpenCode emulator) are POSIX-only; the
  remaining hswap tests and the full engine suite are platform-neutral.
- Only Linux was exercised in this change; macOS/Windows behaviour of the new
  adapters is untested.
