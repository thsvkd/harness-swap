# Testing

```bash
uv sync
uv run pytest                 # parallel (pytest-xdist), ~40–60 s on 4 cores
uv run pytest tests/test_hswap_*.py -n 0   # just the hswap layer, serially
```

## What is covered

| Area | File | Notes |
|---|---|---|
| Claude engine (regression) | `tests/test_*.py` (pre-existing, ~2900) | not modified; must stay green |
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
| CLI and dashboard | `test_hswap_cli.py` | native passthrough, errors and JSON envelopes, confirmations, failed switch keeps login, config, **no credential in any output**, Textual pilot test of the dashboard |
| Extensibility acceptance | `test_hswap_contract.py` | the example adapter registered at runtime and as a trusted/untrusted entry-point plugin, driven through CLI, services and dashboard; snapshot-name rule; static check that shared code names no harness and imports no adapter |
| Plugin trust and isolation | `test_hswap_core.py`, `test_hswap_cli.py` | trust bound to the distribution, duplicate/invalid/reserved ids, a plugin that raises or exits, every cross-harness command (and `--json`) surviving a broken adapter |

## Isolation rules

- Every test runs with `$HOME`/`Path.home()` pointed at a temporary directory,
  and `HSWAP_HOME`, `CODEX_HOME`, `GROK_HOME`, `XDG_DATA_HOME`,
  `CLAUDE_CONFIG_DIR` and `HSWAP_TRUSTED_PLUGINS` cleared (`tests/conftest.py`,
  `_isolate_real_home`).
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
- `add`, `remove` and `alias` have no `--json`; the dashboard refreshes on `r`
  only;
- accounts with the same email in two workspaces look alike in `list`
  (use the slot number); `status` does not name a login hswap does not store;
  `add` names only the logins that were new when one file holds several;
- the dashboard cuts long rows (Left/Right scrolls) and has no detail view;
  a slow harness (e.g. OpenCode starting its service) delays only its own rows;
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
- macOS and Windows behaviour of the new adapters (only Linux was run).

The Claude engine's own suite includes its macOS/Windows paths, run on CI as
before.
