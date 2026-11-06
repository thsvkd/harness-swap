# Testing

```bash
uv sync
uv run pytest                 # parallel (pytest-xdist), ~40–60 s on 4 cores
uv run pytest tests/test_hswap_*.py -n 0   # just the hswap layer, serially
```

## What is covered

| Area | File | Notes |
|---|---|---|
| Claude engine (regression) | `tests/test_*.py` (pre-existing, ~2900) | must stay green; changed only where a test pins the settings registry (`credentials.requireKeychain` is its 13th key) |
| `security` wrapper and log file | `test_macos_keychain.py`, `test_logging_config.py` | no secret, hex or `sk-ant` in argv at real credential sizes, `-w` round trip through a model of `security -i`'s tokenizer (quotes, backslashes), refusal of what stdin cannot carry, read-back after every write against a fake `security` that mangles with rc 0, the previous value restored once on a mismatch, non-ASCII JSON stored as ASCII and a hex read-back failing, `keychain-selftest`, no command or stderr in a timeout's message, chain or log, log and rotated copies at 0600 |
| Keychain-required mode | `test_keychain_required.py` | preflight over a fake `security` and lock-state reader (a locked keychain never reaches `show-keychain-info`), the env override only tightening, (search list without the login keychain, a daemon reporting `System.keychain`, rc 36, timeout, n/a off macOS), setting and env override, refusal with byte-identical stores for every credential-writing command, `keychain_unavailable` envelope, cached `list`/`status`/dashboard with no fetch, no plaintext or `.enc` fallback on any write path, mid-switch failure and rollback, no store write on any read path, a stale `.enc` not shadowing a newer Keychain copy and an unreadable item deferring instead of using the `.enc`, preflight before every POST, the credentials file read before a POST of the active login (a token spent in the file while the Keychain still holds it), the fetch path's successor surviving a failed write, and `auto`/`list` leaving the active stores to `keepalive`: no slot copy restored or posted, no write while the stores disagree, the slot copy kept before the slot follows them |
| `hswap claude keepalive` | `test_keepalive.py` | Keychain/file sync both ways, split-brain stash, shared fields, `--ensure-file`, refresh with one POST and the successor in every store, racing writer, `invalid_grant`, network error, identity from the token endpoint, a failed Keychain write after the POST and its recovery, Claude Code's lock held, unmanaged login, Linux, the report's shape and mode, no token or home path in any output, no consumed refresh token posted twice over two runs (fake endpoint that rotates and rejects reuse), a switch landing while waiting for the locks, the required-mode decision table (agreeing stores beat any slot copy, differing stores need a recorded link, `split_brain` otherwise, and no choice by expiry or write time), `--adopt`, the file read back after every write, stash pruning only on a valid, proven expiry, recovery following the `consumedFp` chain, reserve-before-POST with one POST across runs on every uncertain outcome (a fake endpoint that rotates and then times out), a ledger that fails closed and never evicts a reservation, racing consumers producing one POST, stash entries retired only on read-back, attribution and successor recovery surviving `move`/`swap`, and a static check that every POST goes through `post_refresh` |
| Core: store, rotation, usage service, registry, dispatch, resolution | `test_hswap_core.py` | |
| Credential activation guarantees | `test_hswap_credentials.py` | sync-back, conflict/stash, part isolation, exclusive formats, rollback on interrupted write and on failed verification, tampered snapshot, harness lock, lock file not truncated, concurrent switches (threads and processes), session-owned snapshot never overwritten, no secrets in errors |
| Isolated sessions | `test_hswap_sessions.py` | lock held while running and released after, not inherited by the harness's background children, exit status/signals, removed slot not reused, remove refused while running |
| Codex adapter | `test_hswap_codex.py` | identity, workspaces, API keys, switch + restart notice, credential-store modes, missing binary, isolated session (env, `--no-daemon`, links, lock), `--login` isolation, usage attribution and states, strategy switch, live usage over a fake `app-server` (own home, token-life guard, session-held account, account mismatch, scrubbing), round trip keeps unknown `auth.json` keys |
| Grok adapter | `test_hswap_grok.py` | exclusive scope switch (session ↔ API key), unmanaged scope refused, capability honesty, isolated session, `--login` isolation, no usage read without the opt-in, billing over a fake ACP agent (own home, expiry guard, session-held, states, API-key login, capabilities) |
| OpenCode adapter | `test_hswap_opencode.py` | V2 emulator over a real SQLite file: probe-based mode, listing + active flags, native switch/login/logout, DB never written and secret column never selected; unknown version refused; legacy provider swap; Go limits through a fake `api` command (windows, null data, auth, timeout, switch lock held, inactive accounts, stale carry-over) |
| Antigravity adapter | `test_hswap_agy.py` | fake `agy` speaking the `/usage` JSON: identity, switch + restart note, `add --login` refused, capabilities with and without the token file and on darwin, `--gemini_dir` argv/env/no tty, near-expiry and session-held skips, no output echoed, `UNAUTHENTICATED` |
| Keep-alive (`refresh`) | `test_hswap_codex.py`, `test_hswap_grok.py`, `test_hswap_agy.py`, `test_hswap_opencode.py` | fake harnesses: refreshed vs still valid, API-key login, session-held and running-harness skips, account that just became live, missing login, auth failures (`sign in again`), transport and harness errors never echo output, timeout; OpenCode refused as unsupported; process check sees a Grok started through a wrapper (real `ps`) |
| Automatic switching | `test_hswap_auto.py` | opt-in, threshold, cooldown, no switch on missing data, `--dry-run`, overlapping runs |
| Ask-a-harness transport | `test_hswap_jsonrpc.py` | JSON-RPC session over a fake child: deadline, shutdown, errors scrubbed |
| Claude adapter | `test_hswap_claude_adapter.py` | schema-v1 → core usage mapping, engine embedding (prog name, argv restore, upgrade refused), legacy-store migration gate (no engine path bypasses it) + backup |
| CLI and dashboard | `test_hswap_cli.py` | native passthrough, errors and JSON envelopes, confirmations, failed switch keeps login, config, **no credential in any output**, Textual pilot tests of the dashboard (grouped panel, menus, switch, never forcing, remove, watch, theme, auto view) |
| Extensibility acceptance | `test_hswap_contract.py` | the example adapter registered at runtime and as a trusted/untrusted entry-point plugin, driven through CLI, services and dashboard; snapshot-name rule; static check that shared code names no harness and imports no adapter |
| Plugin trust and isolation | `test_hswap_core.py`, `test_hswap_cli.py` | trust bound to the distribution, duplicate/invalid/reserved ids, a plugin that raises or exits, every cross-harness command (and `--json`) surviving a broken adapter |

## Isolation rules

- Every test runs with `$HOME`/`Path.home()` pointed at a temporary directory,
  and `HSWAP_HOME`, `CODEX_HOME`, `GROK_HOME`, `XDG_DATA_HOME`,
  `CLAUDE_CONFIG_DIR`, `HSWAP_REQUIRE_KEYCHAIN` and `HSWAP_TRUSTED_PLUGINS` cleared
  (`tests/conftest.py`, `_isolate_real_home`).
- `block_real_keychain` replaces the `security` wrapper, the keychain preflight
  included, with an in-memory fake (`reachable` sets the preflight's answer).
- A process-wide audit hook refuses writes to the developer's real stores:
  the claude-swap store and `~/.claude*`, plus hswap's data directory and the
  live credential files in `~/.codex`, `~/.grok` and
  `~/.local/share/opencode` (`_freeze_real_store_specs`).
- Credentials are synthetic (`tests/hswap_helpers.py` builds unsigned JWTs);
  harness binaries are faked with small Python scripts on `PATH` (POSIX only)
  or by setting `adapter._installation`.

## User acceptance runs

Before release, four agents used an installed hswap the way people would
(a newcomer on Codex and Grok, a claude-swap user migrating, a multi-terminal
OpenCode/Codex user scripting `--json`, and a plugin author following
[adapter-development.md](adapter-development.md) for a fifth harness), each in a
bubblewrap sandbox: a private `$HOME` and `/tmp`, a clean environment, the real
home hidden except the harness binaries (read-only), and synthetic logins only.
The real Claude Code, Codex, Grok, OpenCode and upstream cswap binaries were
exercised, never with a real account. The defects they found are fixed and
covered by the tests above, except these, which remain known limits:

- restart notices count every running process of the harness on the machine
  (hswap cannot tell which home each one uses);
- OpenCode: an account removed with `opencode auth logout` loses its hswap
  alias and slot; removing the active account does not say which one OpenCode
  activated instead; switches OpenCode makes itself are not serialised with
  hswap's;
- `add`, `remove` and `alias` have no `--json`;
- accounts with the same email in two workspaces look alike in `list`
  (use the slot number); `status` does not name a login hswap does not store;
  `add` names only the logins that were new when one file holds several;
- the dashboard re-reads every 10 s (Claude's own dashboard: 3 s), so a change
  made elsewhere can take that long to show; a slow harness (e.g. OpenCode
  starting its service) delays only its own rows;
- a usage reading of "unknown" is cached like any other for the adapter's
  minimum interval (30 s for Codex's passive log reading, 300 s for every live read);
- keep-alive's check-then-run race: a harness started by hand after hswap checked
  can redeem the same refresh token.

## What is mock-only

These pass against fakes and synthetic files, not against a live service:

- **keep-alive (`refresh`)**: fake harnesses only; whether a real Codex/Grok writes the rotated token as assumed, and agy's `/usage` as a login use, were not seen with a live account;
- **live usage reads for inactive accounts** (in an account's own home) and everything built on usage, including automatic switching: verified only against fake harnesses that speak the protocol, plus the real binaries in a sandbox with no account. The **active** login's answer from each real harness (Codex `account/rateLimits/read`, Grok `_x.ai/billing`, OpenCode `api experimental.usage.limits`, `agy -p /usage`) was read once with real paid accounts on 2026-11-03 (read-only, tokens with more than 10 minutes left, nothing written to hswap's store) and mapped correctly, which also showed Grok's period type is an enum name (`USAGE_PERIOD_TYPE_WEEKLY`, now normalised);
- Antigravity as a whole: the real `agy` 1.4.8 was run with a synthetic token and a dead or fake endpoint only;

- every switch/add/remove against real Codex, Grok and OpenCode logins (the
  tests use the real file formats; the binaries were checked separately with
  synthetic homes — see harness-compatibility.md);
- OpenCode 1.x legacy mode (no 1.x binary available);
- keychain-required mode and `keepalive`: the preflight was exercised only against `security` output measured on one Mac mini (2.1.318, a LaunchDaemon) and a fake lock-state reader (the real `SecKeychainGetStatus` call was only run on a nonexistent path), the `-w` write only against a model of `security -i`'s tokenizer (`hswap claude keychain-selftest` is the real check, run on the machine), and the refresh only against a fake token endpoint, so which real network failures land in "never sent" rests on urllib's and OpenSSL's exception shapes;
- macOS and Windows behaviour of the new adapters (only Linux was run).

The Claude engine's own suite includes its macOS/Windows paths, run on CI as
before.
