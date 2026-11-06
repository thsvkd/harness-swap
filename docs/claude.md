# Claude Code accounts (`hswap claude`)

> This is the guide of the claude-swap engine that powers hswap's Claude Code
> adapter, with every command spelled the hswap way: `hswap claude <command>`
> takes the same commands, flags and JSON output as upstream `cswap <command>`.
> hswap is installed and upgraded as described in the [README](../README.md);
> `hswap claude upgrade` refuses to run.


Multi-account switcher for Claude Code. Easily switch between multiple Claude accounts without logging out, or let it switch for you before you hit a rate limit. Track usage for every account in a live dashboard, and run accounts in parallel. Works with both the Claude Code CLI and the VS Code extension.

## Installation

Installed with hswap; see the [README](../README.md). The Claude engine needs no separate install.

## Usage

### Add your first account

Log into Claude Code with your first account, then:

```bash
hswap claude add
```

### Add more accounts

Log in with another account, then:

```bash
hswap claude add
```

Do not run `/logout` first: current Claude Code may revoke the refresh token stored for the account you are leaving.

### Switch accounts

Rotate to the next account:

```bash
hswap claude switch
```

Or switch to a specific account:

```bash
hswap claude switch 2
hswap claude switch user@example.com
hswap claude switch dev                # or by alias, once set with `hswap claude alias 2 dev`
```

Not sure which one? `hswap claude list` is the dashboard — every account's 5-hour and 7-day usage and reset times at a glance:

```bash
hswap claude list
```

Or let claude-swap auto-pick by remaining quota — `hswap claude switch --strategy best` (most quota left) or `--strategy next-available` (skip rate-limited accounts).

**Note:** You usually don't need to restart — on Linux/Windows the new account is picked up automatically, and on macOS after the Keychain cache expires. To apply it instantly, restart Claude Code or reopen the VS Code extension tab. See [Tips](#tips) for the per-platform details.

### Automatic switching

Let claude-swap watch your usage and switch for you. When the active account's 5-hour or 7-day window reaches the threshold (default 90%), it switches to the account with the most quota left — before you hit the limit, and safe to run while Claude Code is working:

```bash
hswap claude auto                     # foreground loop, polls every 60s
hswap claude auto --threshold 80      # switch earlier
hswap claude auto --weekly-threshold 97   # let the weekly window run higher before switching
hswap claude auto --model Fable       # also switch when the Fable weekly limit is hit
hswap claude auto --once              # single check-and-switch, for cron/scripts
hswap claude auto --dry-run           # log what it would do, never switch
hswap claude auto --strategy consume-first   # burn the soonest-resetting account first
hswap claude auto --strategy priority-consume-first   # your own tiers first, then soonest weekly reset
```

<details>
<summary>How it behaves & advanced usage</summary>

- Runs safely alongside Claude Code: switches take the same credential locks Claude Code uses, so a swap never collides with a token refresh.
- A cooldown (default 5 min) and a hysteresis margin stop it flip-flopping near the threshold: a proactive switch only lands on an account that's below the threshold *and* better than the current one by the margin — a candidate that clears the margin is always taken, but two accounts hovering at the line never ping-pong. When every account is already over its switch lines, it moves to the one with the most quota left before a limit (the lowest usage on its fullest window, whatever line that window carries) whatever the strategy, once that account has twice the current one's remaining quota or 3 points more than it, whichever is less. When every account is exhausted it keeps checking on a bounded slow cadence, waking sooner for an imminent reset.
- **Strategies** (`--strategy`, or `hswap claude config set autoswitch.strategy`): `best` (default) stays put until the active account nears its limit, then moves to the account with the most quota left. `consume-first` proactively keeps you on the account whose **weekly window resets soonest** — use-it-or-lose-it — switching to a sooner-resetting account (with room to spare) even below the threshold, so perishable weekly quota isn't wasted. `priority-consume-first` follows your own ranking first (see *Account priority tiers* below), then the soonest weekly reset within a tier.
- **A separate line for the weekly windows** (`--weekly-threshold 97`, or `hswap claude config set autoswitch.weeklyThreshold 97`): one threshold compared against the busiest window forces the same number on windows that want different ones — the 5-hour window recycles in hours (an overshoot costs one interrupted turn), while the weekly window is the budget (quota unspent before its reset is gone). With a weekly line, the 7-day window and any per-model window (`--model`) are judged against it and the threshold keeps governing the 5-hour window; every window is compared against its own line, so 7d 93% under a 97 line holds while 5h 95% under an 85 line switches, and the log names the window it measured (`7d 93% < 97%`). Points on different windows are not the same amount of work — the lines are comparable, the clocks are not.
- Usage polling is adaptive — a couple of accounts per check, busy alternates watched more closely, and exhausted ones checked about every ten minutes (or slower after 429s) — so API traffic stays flat no matter how many accounts you manage.
- It fails safe: if a usage check errors it keeps trusting the last-known numbers while retries back off, and an expired token on an idle machine makes it hold rather than fail over (Claude Code refreshes the token on your next message).
- An account whose refresh token has died is quarantined and reported until you either log in with it and re-run `hswap claude add --slot N`, or replace its stored credentials from a known-good export — a plain `hswap claude import backup.cswap` replaces dead-token slots on its own (`--force` is still required to replace other existing accounts; note a stale export can carry an already-superseded token). API-key accounts are never rotated onto unless you pass `--include-api-key-accounts`.
- To hold an account out of rotation yourself — a work account you don't want touched, one you're resting — run `hswap claude disable <num|email>`; `hswap claude enable <num|email>` puts it back. Disabled accounts are skipped by auto-switch, bare `hswap claude switch`, and the `best` / `next-available` strategies, but stay fully managed and remain a valid explicit `hswap claude switch <num|email>` target. They show a `(disabled)` marker in `hswap claude list`, in the [TUI](#interactive-dashboard-tui), and in the [menu bar](#menu-bar-macos) — both of which also let you toggle the state in place (TUI: menu → *Disable / enable account…*; menu bar: *Disable / enable account*).
- **Per-account threshold.** `hswap claude threshold <num|email> <pct>` gives one account its own switch-away line (50–99.9) in place of the global one: auto-switch leaves that account when *its* line is reached and prefers candidates still under *theirs*, with ranking and the hysteresis margin counting room under each account's own line rather than raw headroom. Like the global threshold it is a switch-away line, not a hard cap — with nothing under its line, or the active account at its limit, it still lands somewhere rather than stall (`priority-consume-first` is the exception: it holds, see below). With a weekly line set, the override applies to the 5-hour window only. Accounts without one keep the global threshold. `hswap claude threshold` alone lists the default and every override, `--unset` clears one, and the [TUI](#interactive-dashboard-tui) shows a `th 85%` badge.
- **Account priority tiers.** `hswap claude priority <num|email> <tier>` ranks an account for the `priority-consume-first` strategy: higher tiers are used first, accounts without one are tier 0 (valid tiers are 0–1000), and within a tier the account whose weekly window resets soonest goes first. It moves back to a higher tier as soon as that account is usable again (after the cooldown), and it never lands on an account at or over its switch lines — when nothing qualifies, even at the limit, it holds and keeps polling instead of relaxing them. Tiers alone change nothing; `best`, `consume-first`, and manual switching ignore them. It uses neither the hysteresis margin nor the exhausted slow cadence described above: equal tiers and reset times keep the active account, and a blocked state keeps polling at the normal interval. `hswap claude priority` lists every account's tier and `--unset` clears one.
- By default only the account-wide 5h/7d windows drive switching. If you work on one model and hit its **weekly per-model limit** first (e.g. Fable), add `--model Fable` (or `hswap claude config set autoswitch.model Fable`) to fold that model's window into the decision, so it switches off an account whose model quota is spent even while its 5h/7d windows still have room.
  - **Model names** are Anthropic's own per-model `display_name`s, matched case-insensitively. The exact strings for your accounts are the per-model rows in `hswap claude list` (e.g. a line reading `Fable: 100%`).

For cron/systemd timers, `--once` reports the outcome in its exit code (`0` switched, `1` error, `2` nothing to do, `3` blocked — no viable target), and `--json` emits one JSON event per line:

```bash
*/5 * * * * hswap claude auto --once --json >> ~/.cswap-auto.log 2>&1
```

Defaults like the threshold and cooldown are configurable with `hswap claude config set autoswitch.threshold 80` — flags override them (see [Configuration](#configuration)).

This is the Claude engine's own `auto`: unlike `hswap <codex|grok|opencode|agy> auto` (one `{harness, at, events}` JSON document per check, exit `0` unless it fails, the `rotation.threshold` from `hswap config`), it prints JSON lines, uses the exit codes above, and takes its threshold (default 90) from `hswap claude config`.

</details>

### Run multiple accounts at the same time (session mode)

Launch Claude Code as a specific account in the current terminal only — every other terminal and the VS Code extension stay on your default account, so two accounts can work in parallel.

```bash
hswap claude run 2                     # launch Claude Code as account 2, here only
hswap claude run user@example.com      # by email
hswap claude run 2 -- --resume         # everything after '--' is forwarded to claude
hswap claude run 2 --share-history     # share your chat history with this account too
hswap claude run 2 --require-session   # refuse rather than run plain claude if 2 is the default login
```

Sessions use your normal `~/.claude` setup (settings, CLAUDE.md, skills, MCP servers, etc.), but each account keeps its own chat history — pass `--share-history` if you want your accounts to continue the same conversations, or make it the default for every `hswap claude run` with `hswap claude config set run.shareHistory true` (`--no-share-history` still opts out per launch; on Windows the setting is ignored with a warning, while an explicit `--share-history` errors).

Running the account that is already your default login launches plain `claude` on that login instead of a session (a second copy of the active credential would go stale). Scripts that need the isolation guaranteed can pass `--require-session`, which refuses in that case instead.
  
A session refreshes its own copy of the account's token, so once it exits, the credential it rotated is captured back into the account's stored backup before a switch or usage check uses that backup. While a session is still running, `hswap claude switch` refuses to move the default login onto its account if the stored backup has already fallen behind (activating it could only fail); exit the session first, or pick another account. While a session runs, its account's usage is read with the session's own credential and never refreshed by hswap; a read the server refuses shows as token expired, and is not requested again, until the session renews the credential on its next call.

<details>
<summary>Sharing details — MCP servers & chat history</summary>

- With `--share-history`, a session started under one account shows up in `--resume` under the others, and nothing already saved is lost.
- User-scope MCP servers (`claude mcp add -s user`) are mirrored from your default profile on every launch — manage them there; changes made inside a session don't persist. Definitions are copied as-is (including inline `env`/`headers` values), but MCP OAuth logins are not — HTTP servers may ask you to authenticate once per profile via `/mcp`.
- `--no-share` turns sharing off and removes the mirrored MCP config (profiles that never mirrored are left alone).

</details>

<details>
<summary>Map accounts to directories — auto-pick per repo</summary>

Bind a directory to an account, and a bare `hswap claude run` there launches that account in session mode — e.g. work account in work repos, personal elsewhere:

```bash
hswap claude map 2 ~/work/client-app   # map a directory to account 2
hswap claude map user@example.com      # map the current directory
hswap claude map                       # list mappings
hswap claude unmap ~/work/client-app   # remove one (defaults to current directory)

cd ~/work/client-app/src
hswap claude run                       # → account 2, session mode
```

Subfolders inherit the nearest mapped ancestor. In an unmapped directory, `hswap claude run` just launches plain `claude` with your default login. Mappings are per-machine (not part of `hswap claude export`) and are cleaned up when their account is removed.

</details>

### Interactive dashboard (TUI)

Run `hswap claude` on its own (or `hswap claude tui`) for the full-screen dashboard: live usage for every account, switching, and the auto-switcher, all keyboard-driven. `hswap claude watch` opens it straight to the live monitor. Works on macOS, Linux, and Windows.

<img src="../assets/tui-watch.png" width="760" alt="hswap claude watch — live 5h/7d usage bars for every account, with reset times and the active account marked">

### Refresh expired tokens

If an account's token expires, log back into Claude Code with that account and re-run:

```bash
hswap claude add
```

This will update the stored credentials without creating a duplicate.

### Other commands

```bash
hswap claude run 2                     # Run an account in this terminal only (session mode)
hswap claude auto                      # Auto-switch when nearing rate limits (see above)
hswap claude keepalive                 # Sync the active login's stores and refresh it ahead of expiry
hswap claude keychain-selftest         # Check a credential-sized value survives a Keychain write (macOS)
hswap claude config                    # Show or edit settings (see Configuration below)
hswap claude list                      # Show all accounts with 5h/7d usage and reset times
hswap claude list --token-status       # Add source-labelled OAuth token diagnostics
hswap claude status                    # Show current account
hswap claude add --slot 3              # Add account to a specific slot (prompts before overwrite)
hswap claude add --alias dev           # Add account and give it a short alias
hswap claude remove 2                  # Remove an account
hswap claude disable 2                 # Hold an account out of auto-rotation (keeps its login)
hswap claude enable 2                  # Return a disabled account to rotation
hswap claude threshold 2 85            # Switch away from account 2 at 85%, not the global default
hswap claude threshold 2 --unset       # Return account 2 to the global default
hswap claude threshold                 # Show the global default and every per-account override
hswap claude priority 2 100            # Use account 2 before lower tiers (priority-consume-first strategy)
hswap claude priority 2 --unset        # Return account 2 to tier 0
hswap claude priority                  # Show every account's tier
hswap claude alias 2 dev               # Give an account a short alias (usable anywhere NUM|EMAIL is)
hswap claude alias 2 --unset           # Remove an account's alias
hswap claude alias                     # List all aliases
hswap claude move 2 1                  # Assign an account to a slot (relocates to an empty slot, swaps if taken)
hswap claude unclaimed                 # List stashed credential entries (slot + why they were stashed)
hswap claude unclaimed --purge ID      # Drop one (deletes its bytes; recover with /login + `hswap claude add`)
hswap claude tui                       # Interactive dashboard (also: bare `hswap claude`)
hswap claude watch                     # Dashboard, opened on the live watch page
hswap claude upgrade                   # Upgrade claude-swap to the latest version
hswap claude purge                     # Remove all claude-swap data
```

The original flag spellings (`hswap claude --switch`, `hswap claude --list`, ...) keep working.

## Tips

- **Do you need to restart after switching?** Usually not. On **Linux and Windows**, credentials are stored in a file and Claude Code re-reads them whenever that file changes, so the new account takes effect on your next message — no restart needed. On **macOS**, credentials live in the Keychain, which Claude Code caches for about 30 seconds; a running session picks up the switch once that cache expires. Restart Claude Code (or close and reopen the VS Code extension tab) only if you want the change to apply instantly.
- **Continuing sessions after switching:** You can keep using the same Claude Code session after switching — run `hswap claude switch` in any terminal and carry on. If you'd prefer a clean start, close and reopen Claude Code (or the VS Code extension tab) and use `--resume` to pick your previous session. Either way, the first message on the new account may use extra usage as its conversation cache rebuilds.

## How it works

- Backs up OAuth tokens and config when you add an account
- Swaps only the account-specific Claude login when you switch accounts;
  live account-independent OAuth state (such as MCP server logins) is
  preserved instead of being overwritten by a slot's older snapshot
- Account credentials stored securely using platform-appropriate methods
- Switches (manual and automatic) hold Claude Code's own credential locks while writing, so a swap never interleaves with a token refresh
- Auto-switch freshens a target's token before activating it, and quarantines accounts whose refresh token has died (recover by re-adding it with `hswap claude add --slot N`, or by replacing its stored credentials from a known-good export — a plain `hswap claude import backup.cswap` replaces dead-token slots automatically)
- Usage numbers refresh every few minutes — faster for an account being used or close to switching, slower for idle ones — keeping hswap comfortably inside Anthropic's rate limits however many dashboards you keep open on a machine. An age note like `· 6m ago` just means the next scheduled check hasn't come yet, not that something is stuck.

## Data locations

| Platform | Credentials | Config backups |
|----------|-------------|----------------|
| Windows | File-based (inside the backup directory, under `credentials/`) | `~/.claude-swap-backup/` |
| macOS | macOS Keychain | `~/.claude-swap-backup/` |
| Linux / WSL | File-based (inside the backup directory, under `credentials/`) | `${XDG_DATA_HOME:-~/.local/share}/claude-swap/` |

Session-mode profiles (`hswap claude run`) live under the backup directory in `sessions/`. Tool preferences (`settings.json`) and auto-switch state (`autoswitch_state.json` — cooldown and quarantined accounts; delete it to reset) live in the backup directory root.

On Linux/WSL, set `XDG_DATA_HOME` to override the default location.

## Menu bar (macOS)

<details>
<summary>Optional macOS menu bar app — usage at a glance, click to switch</summary>

Needs the `menubar` extra (macOS only):

```bash
uv tool install 'claude-swap[menubar]'   # or: pipx install 'claude-swap[menubar]'
hswap claude menubar
```

Shows every account's 5h / 7d / spend usage and switches with a click (specific / rotate / best / next-available), plus the TUI's add / disable-enable / remove / refresh actions. Enable *Settings → Auto-switch accounts* to run the same engine as [`hswap claude auto`](#automatic-switching) in the background; it shares the `autoswitch.*` settings, so the menu bar and CLI stay in sync. Off until you turn it on.

The icon is owned by a small wrapper bundle, `/Applications/claude-swap Menubar.app`, that `hswap claude menubar` builds (and refreshes after upgrades) on every start before hopping into it. That gives the process the bundle identifier `com.claude-swap.menubar`, which is what menu bar managers (Dimble, Ice, Bartender, SaneBar) key on to list, hide and order an icon; a bare Python process has none and is invisible to them. It has to be `/Applications`: macOS resolves a status item's owner from the app's location, and for an app anywhere else the item's identity is nil, so the first time a manager hides anything the icon goes down with it. If `/Applications` is not writable the bundle lands in the data directory and you get a one-line warning. Set `CLAUDE_SWAP_NO_BUNDLE=1` to run in the plain interpreter instead.

**Keep it running without a terminal.** `hswap claude menubar` runs in the foreground, so the status item dies with the terminal that started it and does not come back after a reboot. `--install-service` hands it to launchd instead — starts at login, restarts on crash:

```bash
hswap claude menubar --install-service     # start now, and at every login
hswap claude menubar --service-status      # installed? loaded? pid?
hswap claude menubar --uninstall-service   # stop it and remove the plist
```

The agent lives at `~/Library/LaunchAgents/com.cswap.menubar.plist` and logs to `~/Library/Logs/com.cswap.menubar.{log,err}`. It pins the `hswap` console script (as `hswap claude menubar`), whose path survives an upgrade — but the running process keeps the old build until it restarts, so after upgrading hswap either re-run `--install-service` or `launchctl kickstart -k gui/$(id -u)/com.cswap.menubar`.

</details>

## Advanced

### Configuration

Tool preferences live in `settings.json` in the backup root; `hswap claude config` reads and edits it with validation, so you never have to find the file or guess valid ranges.

<details>
<summary>Commands & usage</summary>

```bash
hswap claude config                              # list effective settings ("(default)" = not set)
hswap claude config get autoswitch.threshold
hswap claude config set autoswitch.threshold 80  # validated: rejects out-of-range values loudly
hswap claude config set autoswitch.weeklyThreshold 97  # own switch line for the 7-day/per-model windows
hswap claude config set autoswitch.model Fable   # per-model switching (see "auto"); Fable,Opus for several
hswap claude config set run.shareHistory true    # every hswap claude run shares chat history (see "run")
hswap claude config set updates.check false      # no daily PyPI lookup for the "newer version" hint
hswap claude config set credentials.requireKeychain true  # macOS: never fall back to plaintext (see "headless")
hswap claude config unset autoswitch.threshold   # back to the default
hswap claude config path                         # where settings.json lives
```

`hswap claude config --help` lists every key with its valid range and default. Hand-editing the file still works — `hswap claude config` is just a safer front door. `list` and `get` take `--json` for scripting.

</details>

### Backup and migration

Move account data between machines or back it up:

```bash
hswap claude export backup.cswap                    # All accounts to a file
hswap claude export backup.cswap --account 2        # One account
hswap claude export backup.cswap --full             # Include full ~/.claude.json and credential object (same-PC backup)
hswap claude import backup.cswap                    # Skips accounts that already exist
hswap claude import backup.cswap --force            # Overwrite existing
```

The export file is plaintext JSON and, by default, carries only each account's own login — machine-shared MCP/plugin OAuth tokens and the device token stay on the source machine (`--full` keeps everything, for same-PC backups). If you need encryption, pipe through your tool of choice (e.g. `hswap claude export - | gpg -c > backup.gpg`).

If an imported account is the one you're currently logged in as, activate the imported credentials with `hswap claude switch N --force` (a plain `switch` to the current account is a safe no-op and won't touch the import).

### Share usage readings between machines

Machines that hold the same accounts can end up spending one usage-endpoint budget: when they share a login (moved between them with `export`/`import`, so the same token is live on each), or when the account's usage requests are limited per account rather than per token. Their polling then adds up. `import-usage` lets one machine poll and hand its readings to the others:

```bash
hswap claude list --json | ssh laptop hswap claude import-usage - --hold 600
```

<details>
<summary>How it works — matching, holds & when a hold ends</summary>

The input is `hswap claude list --json` output. Each row with `usageStatus: "ok"` is matched to a local account by email and organization, and adopted when it is newer than the reading already stored. Its age comes from `usageAgeSeconds`, so the two machines' clocks never have to agree; a script that delays the hand-over should add the delay to that field. `--hold SECONDS` keeps every collector on the receiving machine (`list`, `status`, `auto`, the dashboard, the menu bar) from fetching those accounts for that long, and the held reading stays trusted for switch decisions meanwhile. A hold never runs past the reading's earliest window reset (per-model windows included), nor past an hour after the reading was taken. Renew it with each hand-over, or lift it early with `--hold 0`; when it lapses, the machine goes back to fetching for itself.

</details>

### JSON output for scripting

Add `--json` to `list`, `status`, or `switch` to emit a single machine-readable JSON object on stdout (human-readable notices go to stderr). Useful for scripting auto-swap and quota tracking.

```bash
hswap claude list --json                   # all accounts with usage/quota
hswap claude status --json                 # current active account
hswap claude switch --strategy best --json # switch, then report the result
hswap claude switch 2 --json
```

<details>
<summary>Example output & schema notes</summary>

```json
{
  "schemaVersion": 1,
  "activeAccountNumber": 2,
  "accounts": [
    { "number": 2, "email": "you@example.com", "active": true, "usageStatus": "ok",
      "usage": { "fiveHour": { "pct": 25.0, "resetsAt": "2026-06-22T23:29:59Z" },
                 "sevenDay": { "pct": 16.0, "resetsAt": "2026-06-26T17:59:59Z" } } }
  ]
}
```

Every payload carries a `schemaVersion` (currently `1`); on a handled error stdout is `{"schemaVersion":1,"error":{...}}` with a non-zero exit code. `--switch`/`--switch-to` report `{"switched": true|false, "from": …, "to": …, "reason": …}`.

Usage is served from a per-account cache: when the usage API is briefly unreachable, the last-known numbers are shown instead of nothing (the human view marks them with their age, e.g. `· 2m ago`). Rows with decision-trusted usage carry additive `usageFetchedAt`/`usageAgeSeconds` fields telling you how old the measurement is. Whenever `usage` is null but a last-known measurement exists — data too old to drive a decision (`usageStatus` stays `unavailable`), or a row in a non-`ok` state such as `token_expired` — additive `lastGoodUsage`/`lastGoodFetchedAt`/`lastGoodAgeSeconds` fields preserve the human display without making the account actionable. When `usage` is null and nothing else explains it (`usageStatus` is `unavailable`), an additive `usageError` names the last fetch failure by kind (e.g. `http-429`, `timeout`) and, while the cache is backing off from it, `usageRetryAt` gives the time of the next attempt. These fields apply to list rows and the managed active row from `status --json`. An account held out of rotation with `hswap claude disable` carries an additive `"disabled": true` on its row (absent otherwise). Per-account policy follows the same convention: a row carries `"threshold": 85.0` once one is set with `hswap claude threshold` — absent otherwise, so a fleet that never sets a policy emits rows identical to before.

A row carries an additive `loginExpiresAt` (ISO-8601 UTC) when the stored login records when its refresh token expires, which is the moment the slot will need a fresh `/login` and `hswap claude add --slot N`; a script can warn a few days ahead instead of discovering `relogin_required`. Absent when Claude Code recorded no such date for that login.

A top-level `keychainUnavailable: true` means keychain-required mode is on and this process cannot reach the login keychain, so the rows are the cached view: nothing was fetched or refreshed. See [Keeping a headless machine logged in](#keeping-a-headless-machine-logged-in-macos). Absent otherwise.

An account row also carries an additive `alias` field once one is set with `hswap claude alias` (e.g. `"alias": "dev"`); accounts without one simply omit the key.

Weekly windows (`sevenDay` and per-model `scoped` entries — never `fiveHour`) additively carry pace fields once the week is ~a day old: `expectedPct` (where usage would sit if spread evenly across the week) and `aheadOfPace` (`true` when meaningfully above that — the same signal the human views show as an `(ahead)`/`(ahead of pace)` marker). `projectedExhaustionAt`/`willLastToReset` extrapolate the current rate into an ETA to 100% and a yes/no "will it last to the reset"; they stay `--json`-only since a linear projection is too rough to present as fact in the UI.

</details>

`hswap claude auto --json` emits an event *stream* instead — one JSON object per line (`{"schemaVersion":1,"event":"switch","ts":…, …}` with kinds like `poll`, `switch`, `no-switch`, `account-quarantined`, `all-exhausted`, `error`). The contract is additive: new kinds and fields may appear, so scripts should ignore unknown ones.

### Add an account from a raw token or API key

If you only have a long-lived setup-token (e.g., produced by `claude setup-token`)
or a Console API key (`sk-ant-api03-...` workspace key, `sk-ant-usr-...` personal
key, or a service-account key) and you don't want to log in via the browser
flow first — useful on headless servers or when receiving a token from another
machine — register it directly. The token type is auto-detected:

```bash
hswap claude add-token sk-ant-oat01-...             # OAuth setup-token
hswap claude add-token sk-ant-api03-...             # API key (any Console key family)
hswap claude add-token sk-ant-oat01-... --slot 3
hswap claude add-token - --slot 3                   # read token from stdin
hswap claude add-token --email user@example.com     # optional label override
```

`--email` is optional; omitted values use `setup-token-{slot}@token.local`
(or `api-key-{slot}@token.local` for API keys). No Anthropic API calls are made.

**API-key accounts.** Any bare `sk-ant-...` value that is not an OAuth token
(`sk-ant-oat...`) registers a managed API-key account (the kind Claude Code uses
after `/login` with a key) rather than an OAuth setup-token. It switches like any
other account; since API keys have no subscription quota, they show no usage and the
usage-aware `switch` strategies never skip them as rate-limited. Create personal and
service-account keys scoped to a single workspace: a multi-workspace key needs an
`anthropic-workspace-id` header on every request, which Claude Code does not add for
a stored key.

## Keeping a headless machine logged in (macOS)

On macOS Claude Code keeps the active login in the login Keychain and falls back to `~/.claude/.credentials.json`. A process that cannot reach the login keychain (started by a LaunchDaemon, even with `UserName` set, or over SSH without an unlocked keychain) reads and writes only the file, and it cannot tell it is in that state: `security find-generic-password` answers rc 44, "not found", for an item that exists.

So one login ends up in two stores that each refresh on their own. The refresh token rotates on every refresh, and whichever side refreshes later presents a consumed token, which logs out every process on that side. hswap run from such a process makes it worse: its Keychain write fails, it falls back to the plaintext file and `.enc` backups, and it can neither remove the Keychain item nor see newer generations held there.

The cure is one refresher in a place that can see both stores, running early enough that no Claude Code process ever reaches its own refresh window (the last 5 minutes of the access token).

**1. Refuse to work from the wrong place.**

```bash
hswap claude config set credentials.requireKeychain true   # or HSWAP_REQUIRE_KEYCHAIN=1 to force it on
```

The environment variable can only tighten: `HSWAP_REQUIRE_KEYCHAIN=0` does not turn off a configured `true`, so a process cannot reopen the plaintext fallback by setting a variable.

With this on (macOS only; off by default), every command checks that the login keychain is in this process's search list, is unlocked, and answers `security show-keychain-info`. When it does not:

- commands that can write a credential (`switch`, `add`, `add-token`, `remove`, `import`, `move`, `swap`, `purge`, `run`, `auto`, `keepalive`) refuse before touching anything: exit 1, and under `--json` an error envelope with type `keychain_unavailable`;
- `list`, `status` and the dashboard show cached usage with no fetch, no refresh and no writes, and `list --json` adds `keychainUnavailable: true`.

A Keychain write that fails anyway never falls back to the plaintext file or an `.enc` backup; the command fails instead. Every refresh POST re-checks reachability first. A leftover `.enc` backup no longer outranks a newer Keychain copy, and the next Keychain write of that slot removes it; reading a backup changes nothing. If a backup's Keychain item cannot be read, the `.enc` is not used in its place: the refresh defers.

A locked login keychain in the GUI session counts as unreachable, and the check does not raise an unlock dialog. `security show-keychain-info` calls `SecKeychainCopySettings` with interaction allowed, and it returns `errSecInteractionNotAllowed` (rc 36) in a daemon, which means the call wants user interaction, so on a locked keychain in a GUI session it can prompt. hswap therefore reads the lock state first with `SecKeychainGetStatus` after `SecKeychainSetUserInteractionAllowed(false)`, in its own process, and runs `show-keychain-info` only once the keychain is known to be unlocked. If the lock state cannot be read, the keychain counts as unreachable. A keychain that locks after this check can still prompt on the next item read, for at most the 5 seconds `security` is given.

**Credential size.** hswap sends a credential to the Keychain only through `security -i`'s stdin, never on a command line where `ps` and audit logs would show it, and that stdin takes one line of at most 4096 bytes. A credential that does not fit cannot be written: in keychain-required mode and in `keepalive` the write fails, and with the mode off hswap falls back to the file as for any other Keychain failure. A credential carrying many MCP logins (`mcpOAuth`) can reach this limit.

**Read-back.** `security -i` exits 0 whatever its quoting did to a value, so every Keychain write is read back through the normal read and compared, and a mismatch counts as a failed write. `security` prints a value holding any non-printable byte as hex, which no reader can use, so credential JSON with non-ASCII text is stored with `\uXXXX` escapes (the same data to any JSON reader), and any other such value fails the write. Run `hswap claude keychain-selftest [--json]` once from the GUI session before relying on this setup. It writes a throwaway `hswap-selftest-<random>` item of a real credential's size containing quotes, backslashes and non-ASCII JSON through the same code path, compares it and always deletes it. It reports `{"ok":true}` and exit 0 only if the value matched and the item is gone, and it refuses with `keychain_unavailable` when the login keychain is out of reach. A failed read-back writes the previous value back once. If that fails too, the item keeps what `security` stored rather than being deleted, because a concurrent writer may have just stored a newer token, so treat a `keepalive` that starts reporting `keychain_unavailable` right after an upgrade as urgent. Elsewhere than macOS it prints `unsupported` and exits 0.

**2. Run one refresher from the GUI session.** Save as `~/Library/LaunchAgents/com.example.hswap-keepalive.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.hswap-keepalive</string>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/zsh</string>
    <string>-lc</string>
    <string>{ hswap claude keepalive --json --ensure-file; hswap claude auto --once --json; } >> ~/Library/Logs/hswap-keepalive.log 2>&amp;1</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>300</integer>
</dict>
</plist>
```

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.hswap-keepalive.plist
```

`--ensure-file` is for processes that only see the file: it keeps a copy there for them, 0600, on the same generation as the Keychain. Leave it out if nothing on the machine needs the file. The job needs a logged-in session with an unlocked login keychain; a machine booted to the login window has neither, and `keepalive` then reports `keychain_unavailable` until someone logs in.

**What `keepalive` does.** `hswap claude keepalive [--ahead SECONDS] [--ensure-file] [--dry-run] [--json]` takes Claude Code's credential locks and the slot's lock, reads who is logged in and both stores only then, and:

1. Brings the Keychain and the file to the newest copy of the current account: one with a refresh token beats one without, then the later `expiresAt` wins, and the Keychain wins a tie and keeps its machine-shared fields (`mcpOAuth`, ...). A copy that belongs to another account never wins, so a switch landing mid-run is not undone. A stale generation of the same account (Claude Code rotated one store) is a plain sync. A losing copy is skipped only when it and the winner are both positively this account's. Any other is stashed first (see `hswap claude unclaimed`, once per fingerprint) with whatever identity it can be attributed to, because an expired access token says nothing about its refresh token; `note` says `split_brain` only for another account.
2. If the access token expires within `--ahead` (default 3600 seconds), refreshes it once and writes the result to the Keychain, the file (when present or `--ensure-file`) and the slot's backup. A racing refresh is adopted, not repeated. A rejected refresh token reports `relogin_required` and wipes nothing.

A refresh token rotates and works once, and presenting a spent one can revoke the whole login. So a refresh whose result could not be written anywhere is parked in the stash, and the next run on any path adopts it instead of posting. A stash entry is removed only after a store is read back holding that login. Stash entries are base64 on disk, so each mutating `keepalive` run also deletes one whose own login has provably lapsed: its `refreshTokenExpiresAt` is a valid date that passed more than 24 hours ago. An entry with a missing, zero, negative or otherwise unusable date stays until `hswap claude unclaimed --purge`, and so does anything another entry's `consumedFp` or a reservation points at. Recovery follows `consumedFp` to the newest successor (16 links at most, and a cycle is refused), so a spent intermediate never reaches a store.

Keepalive and keychain-required mode keep a ledger of tokens in `cache/consumed_grants.json` (0600, fingerprints and the account's email and organization, no tokens), and once the file exists every refresh on the machine uses it. A token is claimed there, in one step under the file's lock and durably, before its POST, so two processes cannot both send it. Reservations are never dropped, consumed rows stay for 400 days, and past 8 MB the ledger fails closed rather than forget a token. A success or a rejected grant marks it consumed; a request that provably changed nothing clears it (DNS, connection refused, TLS handshake, or a 4xx refusal). Any other outcome (a timeout, a reset, a 5xx, an unparsable response) leaves it reserved, because the server may have rotated it. Nothing posts a listed token, so one uncertain outcome is never retried: `keepalive` adopts a newer copy if a store holds one, and otherwise reports `relogin_required`. Claude Code does not use this ledger, so if it refreshes that login itself the new token clears the condition. A ledger that cannot be read fails closed: no refresh runs anywhere, `keepalive` reports `refresh_failed` with "consumed-grant ledger unreadable", and the file is left as it is for you to inspect.

A copy on the ledger never wins over a working copy, and a copy recorded for another account never overwrites the current account's store. An older copy that replaces a spent one is itself treated as spent only when both are proven to be this account's, because it was then very likely spent to make that one; another account's spent token, or a winner of unknown identity, leaves the ledger alone.

After every write, `keepalive` reads the file back when it should hold the login, retries once, and otherwise reports `refresh_failed` with "file store could not be updated". The Keychain and the slot still hold the login in that case, and the next run repairs the file.

It refuses to run with `CLAUDE_CONFIG_DIR` or `CLAUDE_SECURESTORAGE_CONFIG_DIR` set to anything, even the default directory, because Claude Code then uses a differently named Keychain item; the LaunchAgent above sets neither. It always needs the login keychain on macOS, even with the setting off, and never falls back to the file. On Linux and Windows there is no Keychain: it refreshes the file only.

Every run, failures and `--dry-run` included, writes `cache/keepalive.json` in the store root (0600, no tokens, no paths), and `--json` prints the same object. The exit code is 0 when `ok`, 1 otherwise.

```json
{"schemaVersion": 1, "checkedAt": 1793900000.0, "ok": true,
 "action": "refreshed", "note": null, "activeSlot": 2,
 "accessExpiresAt": "2026-11-06T01:45:00Z", "loginExpiresAt": "2026-12-05T00:00:00Z",
 "error": null}
```

`action` is `none`, `synced-file`, `synced-keychain`, `created-file` or `refreshed`. `error` is null or `{"type", "message"}`, with `type` one of `keychain_unavailable`, `relogin_required`, `split_brain` (the older copy could not be preserved, so nothing was synced), `refresh_failed` (transient), `no_credentials`, `locked` or `unmanaged`, and `ok` is false whenever it is set. `unmanaged` means the login matches no managed slot: the stores were still synced and refreshed (see `action`), but nothing backs it up until you run `hswap claude add`. `--dry-run` adds `"dryRun": true` and reports what it would have done. `note` is `api_key` when the active login is a managed key, which has nothing to refresh.

## Uninstall

`hswap claude purge` removes all Claude data (it asks first). hswap itself is
uninstalled with `uv tool uninstall harness-swap` (see [migration.md](migration.md)).

## Requirements

- Python 3.12+
- Claude Code installed and logged in

## License

MIT
