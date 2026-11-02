# Migrating from claude-swap

## Short version

Install hswap; your claude-swap accounts appear under `hswap claude` with the
same slots, aliases, thresholds, priorities and mappings. Nothing is copied or
converted.

```bash
uv tool install .            # from a clone of this repository
hswap migrate --dry-run      # shows anything that would change (usually nothing)
hswap claude list            # your existing accounts
```

## What happens to the data

hswap's Claude adapter *is* the claude-swap engine (release line 0.30). It reads
and writes the claude-swap store where it already is:

| Platform | Store |
|---|---|
| Linux/WSL | `$XDG_DATA_HOME/claude-swap` (default `~/.local/share/claude-swap`) |
| macOS/Windows | `~/.claude-swap-backup` (macOS backup credentials stay in the Keychain) |

There is therefore no import step, no duplicate copy of your credentials, and
no Keychain item is moved.

**One exception.** Very old claude-swap installs on Linux kept their data in
`~/.claude-swap-backup`; the engine moves it to the XDG location the first time
it starts. hswap does not let that happen as a side effect: every Claude command
except `hswap claude help`/`--version` (including bare `hswap claude`) stops
with an explanation instead, and

```bash
hswap migrate --dry-run   # would move ~/.claude-swap-backup -> ~/.local/share/claude-swap
hswap migrate             # backs it up to <hswap home>/backups/claude-swap-<time>, then moves it
```

The backup is a plain copy inside a 0700 directory; delete it once you are satisfied.
To roll back, move the backup back to `~/.claude-swap-backup` and remove the new
directory.

## Running hswap and cswap side by side

hswap does not install `cswap`, so an installed upstream claude-swap keeps its
command. Both work on the same store and serialise through its `.lock`
(`flock`), so they do not corrupt each other. Keep them on the same release
line: an older cswap may not understand data written by a newer engine and
vice versa. `hswap doctor` reports a `cswap` it finds on `PATH`.

`hswap claude upgrade` is refused (it would upgrade upstream claude-swap, not
hswap); upgrade hswap with the tool that installed it.

## hswap's own stores

Codex, Grok and OpenCode accounts live in `<hswap home>/<harness>/` (see
[architecture.md](architecture.md#data)). `accounts.json` carries
`schemaVersion: 1`. A file written by a newer hswap is refused with an error
rather than rewritten, so downgrading cannot silently drop data. Future schema
changes will be applied by `hswap migrate`, with the same dry-run and backup
behaviour.

Adding an account is idempotent: adding the same login again updates its slot
(duplicate detection by identity), it never creates a second slot.

## Removing hswap

`uv tool uninstall harness-swap`. Your harness logins are untouched. hswap's
own data is in `<hswap home>` (`hswap config path` prints a file inside it);
Claude data stays in the claude-swap store for cswap to use.
