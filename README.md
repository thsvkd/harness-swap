# Harness Swap (`hswap`)

Switch between multiple accounts across AI coding harnesses, with automatic
rate-limit rotation, a unified usage dashboard, and parallel sessions.

`hswap` grew out of [claude-swap](https://github.com/realiti4/claude-swap). Its
Claude Code support *is* the claude-swap engine (unchanged apart from a small
embedding hook); Codex CLI, Grok Build, OpenCode and Antigravity are added through the same adapter contract any other
harness can implement.

| | Claude Code | Codex CLI | Grok Build | OpenCode | Antigravity (`agy`) |
|---|---|---|---|---|---|
| list / add / remove accounts | yes | yes | yes | yes (native) | yes⁵ |
| switch the default login | yes | yes¹ | yes | yes (native `auth switch`) | yes⁵ |
| running sessions pick up a switch | yes² | no, restart | yes | undocumented | no, restart |
| usage | 5h / 7d / per-model | experimental³ | experimental³ | experimental³ (Go plan) | experimental³ |
| automatic rotation | `hswap claude auto` | experimental⁴ | experimental⁴ | experimental⁴ | experimental⁴ |
| parallel isolated sessions | experimental | yes | experimental | no | experimental |

¹ file credential store only (`cli_auth_credentials_store = "file"`, Codex's default).
² on macOS once the Keychain cache expires.
³ opt-in: `hswap config set usage.remote <ids>`. hswap asks the harness itself
(Codex `app-server`, Grok's ACP agent, OpenCode `api experimental.usage.limits`,
`agy -p /usage`) and never calls a provider API or refreshes a token. Without the
opt-in Codex still shows the last snapshot it logged locally. Each harness's
answer for a real, active paid login was read once (2026-11-03, read-only) and
mapped correctly; inactive-account reads, keep-alive and automatic switching are
verified against fake harnesses only. OpenCode reports Go-plan limits only for OpenCode Console logins, not
API keys. Turning the opt-in on or off takes effect on the next read.
`list --cached` / `usage --cached` read the cache: no usage read, no token
refresh (hswap still runs each harness's version probe, and OpenCode's
`auth list`, to list accounts).
⁴ opt-in per harness: `hswap config set auto.enabled <ids>`, then
`hswap <harness> auto`. Needs live usage, and every provider's terms are
unclear or restrictive about switching accounts to get past limits (Google's
are the strictest); `hswap capabilities` and `config set` print the warning. Claude keeps
`hswap claude auto`, with its own threshold, JSON lines and exit codes
([docs/claude.md](docs/claude.md)).
⁵ file-backed login only (Linux; not the macOS/Windows keychain); `add --login`
is unavailable. Cursor and Gemini CLI are not supported. See
[docs/harness-compatibility.md](docs/harness-compatibility.md) for the evidence
and the reasons behind every cell. `hswap capabilities` prints the live answer
for *your* install.

## Install

```bash
uv tool install harness-swap   # or: pipx install harness-swap
hswap harnesses                # what is installed, which versions
```

From a clone: `uv tool install .`

Python 3.12+. hswap does not install a `cswap` command, so it never collides
with an installed upstream claude-swap; `hswap claude ...` takes every cswap
command (and `python -m claude_swap` still runs the engine directly).

## Quick start

```bash
hswap                       # dashboard (when run in a terminal)
hswap list                  # every harness, every account, usage where available
hswap status                # the active account per harness
```

### Dashboard

`hswap` (or `hswap tui`) is Claude's dashboard (`hswap claude tui`) for every
harness: per harness, the active account as a card with its usage bars (the
tick marks `rotation.threshold`) and the others on one line, with a menu below:
Switch account…, Watch accounts, Auto-switch view, Add account… (a harness's
current login), Remove account…, Theme…. Keys: `s` switch (`b` best pick
within the highlighted account's harness), `w` watch (`s` there to pick), `g`
auto-switch view (dry-run until `l`; `t` then ←/→ tries another threshold for
this session), `f` refresh now, PgDn/PgUp scroll the accounts when they do not
fit, `ctrl+t` theme (saved as `ui.theme`: dark, light or auto), `q` quit. It
re-reads every 10 s (all harnesses in parallel) and never forces a switch over a login hswap does not manage (that stays
`hswap <harness> switch ACCOUNT --force`). Disabling accounts and token logins
are Claude-only: use `hswap claude tui` for those.

### Claude Code

Exactly the claude-swap workflow, spelled `hswap claude`:

```bash
hswap claude add            # add the account Claude Code is logged into
hswap claude switch 2       # or an email / alias
hswap claude auto           # rotate before rate limits (threshold, priority, cooldown)
hswap claude run 2          # this terminal only, other sessions unaffected
hswap claude help           # everything else: tui, map, alias, threshold, export, ...
```

Full guide: [docs/claude.md](docs/claude.md). Existing claude-swap data is used
in place — nothing to import.

### Codex CLI

```bash
hswap codex add                       # store the current login
hswap codex add --login --alias work  # sign in another account in a throwaway CODEX_HOME;
                                      # the current login is never replaced or logged out
hswap codex switch work               # swaps $CODEX_HOME/auth.json; restart running Codex
hswap codex usage                     # last logged snapshot; live after `config set usage.remote codex`
hswap codex switch --strategy best    # one-off: the account with the most headroom
hswap codex run personal -- resume    # isolated per-account CODEX_HOME, this terminal only
```

`run` on the account that is already the default login runs in the default
`CODEX_HOME` (a second copy of the token would mean two refreshers); hswap still
holds a session lock there, so `switch` and `remove` wait until it exits.

### Grok Build

```bash
hswap grok add --login       # isolated GROK_HOME sign-in
hswap grok switch 1          # leaves that login as the only scope; Grok hot-reloads it
hswap grok run 2             # experimental isolated GROK_HOME session
```

`hswap codex|grok add --login --json` is for a program driving the sign-in
(a web gateway): it runs `login --device-auth` in the throwaway home and prints
JSON Lines only, `{"type":"device_code","url",…,"userCode","expiresInSeconds"}`,
then `{"type":"added","account",…}` (exit 0) or `{"type":"error","error":{"type",…}}`
(exit 1). The events and error types are in [docs/claude.md](docs/claude.md#sign-in-a-new-account-and-add-it-in-one-step).

### Antigravity (`agy`)

File-backed login only (`~/.gemini/antigravity-cli/antigravity-oauth-token`).

```bash
hswap agy add                # the current login; sign in the next account in agy, add again
hswap agy switch 2           # swaps the token file; restart running agy sessions
hswap agy run 2 -- --continue    # experimental: per-account --gemini_dir
```

### Usage and automatic switching (opt-in)

```bash
hswap config set usage.remote codex,grok,opencode,agy   # ask each harness for live usage
hswap list --cached                                      # no network, no token refresh
hswap config set auto.enabled codex                      # allow automatic switching
hswap codex auto [--once | --interval S] [--dry-run] [--json]
```

### Keep logins alive

```bash
hswap codex refresh [ACCOUNT] [--json]    # also: grok, agy
# crontab: keep stored logins fresh on a machine you rarely use
0 */6 * * * hswap codex refresh
```

`refresh` asks the harness (in each account's own home) so the harness refreshes
a due token itself; hswap never calls a provider. It needs no opt-in, skips an
account a running session owns and the active login while that harness runs (any
process whose command line names the harness executable counts, e.g. a sandbox
that binds it), and
prints `token refreshed` / `token still valid` (agy: `login used`), or
`sign in again: ...` with exit 1. OpenCode is unsupported: switch to an idle
account (`hswap opencode switch`) before its token lapses. Claude: the engine
refreshes tokens when it reads usage, so run `hswap claude list` or
`hswap claude auto --once` from cron. Verified against fake harnesses only, never
a live account. Why it is safe with several devices:
[docs/security.md](docs/security.md#keep-alive-hswap-id-refresh).

`auto` switches only on fresh usage at or over `rotation.threshold`, at most once
per `auto.cooldown` (default 600 s), and never on missing data. Read the terms
warning in `hswap capabilities` first.

### OpenCode

OpenCode 2.x keeps several saved accounts per provider itself; hswap drives its
`opencode auth` commands and never edits its database.

```bash
hswap opencode list
hswap opencode add --provider openai     # runs `opencode auth login openai`
hswap opencode switch 3                  # runs `opencode auth switch <provider> <id>`
hswap opencode switch work --provider anthropic
```

OpenCode 1.x (legacy `auth.json`) is handled by swapping one provider's entry at
a time (experimental, mock-verified).

## Commands

```
hswap harnesses | list [H] | status [H] | capabilities [H] | doctor | migrate [--dry-run]
hswap config [list|get|set|unset|path]  plugins.trusted, rotation.threshold, usage.remote, auto.enabled, auto.cooldown, ui.theme
hswap tui

hswap <harness> list [--json] [--no-usage] [--cached]
hswap <harness> status | usage [ACCOUNT] [--json] [--cached]
hswap <harness> auto [--once|--interval S] [--dry-run] [--json]   # opt-in
hswap <harness> add [--alias A] [--provider P] [--login [--json]]
hswap <harness> switch ACCOUNT [--provider P] [--force] [--json]
hswap <harness> switch --strategy best|next-available
hswap <harness> run ACCOUNT [-- harness args...]
hswap <harness> alias ACCOUNT NAME | --unset
hswap <harness> remove ACCOUNT [--yes]
```

These generic verbs apply to every harness except Claude Code, whose
`hswap claude ...` takes the full claude-swap command set instead (`hswap claude
help`); the cross-harness commands (`hswap list claude`, `hswap capabilities
claude`, ...) work for Claude too.

`ACCOUNT` is a slot number, an alias, or an email/label. Unsupported operations
fail with the reason (`hswap capabilities` lists them all). Every `--json`
payload carries `schemaVersion: 1`; Claude's own `--json` keeps claude-swap's
schema. Cross-harness commands (`list`, `status`, `capabilities`, `doctor`,
`harnesses`) still show every harness that works when one fails, report the
failure (`errors` in JSON), and exit 1.

- `remove` forgets the stored login. The account's isolated-session history
  stays in `<hswap home>/<harness>/accounts/<slot>/`; delete that directory to
  discard it.
- `switch --force` saves the login it replaces to
  `<hswap home>/<harness>/stash/<file>.<timestamp>` (0600) and prints the path.
  To get it back, copy it over the harness's login file (e.g.
  `$CODEX_HOME/auth.json`) and `hswap <harness> add` it.
- `rotation.threshold` (default 95%) is the cut-off for `switch --strategy` on
  the generic harnesses. Claude's auto-switch has its own settings
  (`hswap claude config`, default `autoswitch.threshold` 90%, per-account
  `hswap claude threshold`).

## How it stays safe

- Credentials never appear in output: core models carry no secrets, and hswap
  refuses to print JSON that looks like it contains a token. The one exception
  is the explicit, plaintext `hswap claude export -`.
- Before overwriting a login hswap copies the harness's freshly rotated tokens
  back into the stored account, refuses to overwrite a login it does not manage
  (`--force` stashes it first, 0600), leaves other providers' entries alone
  (Grok: the target becomes the only login scope, the others are saved first),
  writes atomically at 0600 under hswap's lock and the harness's own lock, re-reads
  the result and restores the original on any failure.
- For Codex and Grok, an account running in a `run` session cannot be
  activated globally (or removed) until that session exits — two processes
  would rotate one refresh token — and a `run` on the default login blocks
  switching away from it. Claude's `run` keeps the claude-swap rules
  (see docs/claude.md).
- Plugins (third-party adapters) load only after you trust that id from that
  package: `hswap config set plugins.trusted <id>@<distribution>` (the command
  `hswap harnesses` prints). See [docs/adapter-development.md](docs/adapter-development.md).

Details: [docs/security.md](docs/security.md).

## Documentation

- [Architecture](docs/architecture.md) — core, adapters, capability model
- [Writing an adapter](docs/adapter-development.md) — with a runnable example
- [Harness compatibility](docs/harness-compatibility.md) — what is verified, how
- [Security](docs/security.md) · [Migration from claude-swap](docs/migration.md) · [Testing](docs/testing.md)
- [Claude Code guide](docs/claude.md)

## License

MIT
