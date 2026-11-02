# Testing

```bash
uv sync
uv run pytest                 # parallel (pytest-xdist), ~40 s on 4 cores
uv run pytest tests/test_hswap_*.py -n 0   # just the hswap layer, serially
```

## What is covered

| Area | File | Notes |
|---|---|---|
| Claude engine (regression) | `tests/test_*.py` (pre-existing, ~2900) | unchanged; must stay green |
| Core: store, rotation, usage service, registry, dispatch, resolution | `test_hswap_core.py` | |
| Credential activation guarantees | `test_hswap_credentials.py` | sync-back, conflict/stash, part isolation, rollback on interrupted write and on failed verification, tampered snapshot, harness lock, lock file not truncated, concurrent switches, no secrets in errors |
| Codex adapter | `test_hswap_codex.py` | identity, workspaces, API keys, switch + restart notice, credential-store modes, missing binary, isolated session (env, `--no-daemon`, links, lock), `--login` isolation, usage attribution and states, strategy switch, no network |
| Grok adapter | `test_hswap_grok.py` | scope-only switch, capability honesty, unsupported usage, isolated session, `--login` isolation |
| OpenCode adapter | `test_hswap_opencode.py` | V2 emulator over a real SQLite file: probe-based mode, listing + active flags, native switch/login/logout, DB never written and secret column never selected; unknown version refused; legacy provider swap |
| Claude adapter | `test_hswap_claude_adapter.py` | schema-v1 → core usage mapping, engine embedding (prog name, argv restore, upgrade refused), legacy-store migration gate + backup |
| CLI and dashboard | `test_hswap_cli.py` | native passthrough, errors and JSON envelopes, confirmations, failed switch keeps login, config, **no credential in any output**, Textual pilot test of the dashboard |
| Extensibility acceptance | `test_hswap_contract.py` | the example adapter registered at runtime and as a trusted/untrusted entry-point plugin, driven through CLI, services and dashboard; static check that shared code names no harness and imports no adapter |

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

## What is mock-only

These pass against fakes and synthetic files, not against a live service:

- every switch/add/remove against real Codex, Grok and OpenCode logins (the
  tests use the real file formats; the binaries were checked separately with
  synthetic homes — see harness-compatibility.md);
- OpenCode 1.x legacy mode (no 1.x binary available);
- macOS and Windows behaviour of the new adapters (only Linux was run).

The Claude engine's own suite includes its macOS/Windows paths, run on CI as
before.
