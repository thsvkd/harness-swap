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

There is therefore no import step, and no Keychain item is moved. The engine
keeps one previous generation of each stored credential next to it
(`credentials/.creds-<n>-<email>.enc.prev`, 0600) once it rewrites the file, as
claude-swap 0.30 does; older cswap releases ignore those files.

**One exception.** Very old claude-swap installs on Linux kept their data in
`~/.claude-swap-backup`; the engine moves it to the XDG location the first time
it starts. hswap does not let that happen as a side effect: every Claude command
except `hswap claude help`/`--version` (including bare `hswap claude`) stops
with an explanation instead, and

```bash
hswap migrate --dry-run   # would back up ~/.claude-swap-backup, then move it to ~/.local/share/claude-swap
hswap migrate             # backs it up to <hswap home>/backups/claude-swap-<time>, then moves it
```

If both `~/.claude-swap-backup` and `~/.local/share/claude-swap` hold data,
hswap (like the engine) refuses to merge them: the dry run says so, and nothing
is copied. Keep the directory you use and move the other one aside.

The backup is a plain copy of your credentials inside a 0700 directory; delete
it once you are satisfied. To roll back, move the backup back to
`~/.claude-swap-backup` and remove the new directory. Anything changed since the
migration (accounts added, switches, settings) is lost by rolling back.

## Running hswap and cswap side by side

hswap does not install `cswap`, so an installed upstream claude-swap keeps its
command. Both work on the same store and serialise through its `.lock`
(`flock`), so they do not corrupt each other. Keep them on the same release
line: an older cswap may not understand data written by a newer engine and
vice versa. `hswap doctor` reports a `cswap` it finds on `PATH` with its
version, and warns when its release line differs from hswap's engine (in our
tests cswap 0.28 read 0.30 data without trouble, but that is not a promise).
It also warns when the claude-swap store's directories or credential files are
readable by other users.

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
