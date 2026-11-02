# Harness Swap (`hswap`)

Switch between multiple accounts across AI coding harnesses, with automatic
rate-limit rotation, a unified usage dashboard, and parallel sessions.

`hswap` grew out of [claude-swap](https://github.com/realiti4/claude-swap). Its
Claude Code support *is* the claude-swap engine (unchanged apart from a small
embedding hook); Codex CLI, Grok Build and OpenCode are added through the same adapter contract any other
harness can implement.

| | Claude Code | Codex CLI | Grok Build | OpenCode |
|---|---|---|---|---|
| list / add / remove accounts | yes | yes | yes | yes (native) |
| switch the default login | yes | yes¹ | yes | yes (native `auth switch`) |
| running sessions pick up a switch | yes² | no, restart | yes | undocumented |
| usage | 5h / 7d / per-model | experimental³ | no quota API | no quota API |
| automatic rotation | `hswap claude auto` | no⁴ | no | no |
| parallel isolated sessions | experimental | yes | experimental | no |

¹ file credential store only (`cli_auth_credentials_store = "file"`, Codex's default).
² on macOS once the Keychain cache expires. ³ read passively from Codex's own
session logs, no network calls. ⁴ manual `switch --strategy best` only — see
[docs/harness-compatibility.md](docs/harness-compatibility.md) for the evidence
and the reasons behind every cell. `hswap capabilities` prints the live answer
for *your* install.

## Install

hswap is not on PyPI yet. From a clone:

```bash
uv tool install .          # or: pipx install .
hswap harnesses            # what is installed, which versions
```

Python 3.12+. hswap does not install a `cswap` command, so it never collides
with an installed upstream claude-swap; `hswap claude ...` takes every cswap
command (and `python -m claude_swap` still runs the engine directly).

## Quick start

```bash
hswap                       # dashboard (when run in a terminal)
hswap list                  # every harness, every account, usage where available
hswap status                # the active account per harness
```

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
hswap codex usage                     # last rate-limit snapshot Codex logged per account
hswap codex switch --strategy best    # one-off: the account with the most headroom
hswap codex run personal -- resume    # isolated per-account CODEX_HOME, this terminal only
```

### Grok Build

```bash
hswap grok add --login       # isolated GROK_HOME sign-in
hswap grok switch 1          # replaces only that login scope; Grok hot-reloads it
hswap grok run 2             # experimental isolated GROK_HOME session
```

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
hswap config [list|get|set|unset|path]          plugins.trusted, rotation.threshold
hswap tui

hswap <harness> list [--json] [--no-usage]
hswap <harness> status | usage [ACCOUNT] [--json]
hswap <harness> add [--alias A] [--provider P] [--login]
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
schema.

## How it stays safe

- Credentials never appear in output: core models carry no secrets, and hswap
  refuses to print JSON that looks like it contains a token.
- Before overwriting a login hswap copies the harness's freshly rotated tokens
  back into the stored account, refuses to overwrite a login it does not manage
  (`--force` stashes it first, 0600), changes only the target scope/provider,
  writes atomically at 0600 under hswap's lock and the harness's own lock, re-reads
  the result and restores the original on any failure.
- For Codex and Grok, an account running in an isolated session cannot be
  activated globally (or removed) until that session exits — two processes
  would rotate one refresh token. Claude's `run` keeps the claude-swap rules
  (see docs/claude.md).

Details: [docs/security.md](docs/security.md).

## Documentation

- [Architecture](docs/architecture.md) — core, adapters, capability model
- [Writing an adapter](docs/adapter-development.md) — with a runnable example
- [Harness compatibility](docs/harness-compatibility.md) — what is verified, how
- [Security](docs/security.md) · [Migration from claude-swap](docs/migration.md) · [Testing](docs/testing.md)
- [Claude Code guide](docs/claude.md)

## License

MIT
