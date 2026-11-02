# Architecture

hswap is a harness-agnostic core plus one adapter per harness. The core owns
every rule that should behave the same for all harnesses (account identity,
slots and aliases, credential activation guarantees, usage pacing, account
selection, isolated sessions, output); an adapter only describes its harness.

## Layers and dependencies

```mermaid
flowchart TD
    subgraph Presentation
        CLI[cli.py<br/>hswap commands]
        TUI[ui/tui.py<br/>overview dashboard]
        OUT[output.py<br/>human + JSON v1]
    end
    subgraph "Application services (core)"
        ACC[accounts.py<br/>resolve, switch, strategy, launch]
        USG[usage.py<br/>UsageService: cache, pacing, backoff]
        ROT[rotation.py<br/>select_account]
        CRED[credentials.py<br/>SnapshotCredentials]
        SES[sessions.py<br/>isolated homes, session lock]
        REG[registry.py<br/>built-ins + trusted plugins]
    end
    subgraph "Domain (core)"
        MOD[models.py<br/>Account, UsageSnapshot, Capability]
        ADP[adapter.py<br/>role protocols, require()]
        STO[store.py<br/>AccountStore, schema v1]
        ERR[errors.py]
    end
    subgraph Adapters
        BASE[adapters/base.py<br/>FileCredentialAdapter]
        CL[claude.py]
        CX[codex.py]
        GK[grok.py]
        OC[opencode.py]
        PLUG[third-party plugins]
    end
    subgraph Infrastructure
        FS[fsutil: atomic 0600 writes]
        LK[locking: flock / msvcrt]
        SP[spawn, processes, secrets]
    end
    ENGINE[(claude_swap<br/>Claude engine)]

    CLI --> ACC & REG & OUT & USG
    TUI --> ACC & REG & OUT & USG
    ACC --> ADP & ROT & USG & MOD
    USG --> ADP & MOD & LK & FS
    CRED --> STO & LK & FS
    SES --> STO
    REG --> ADP
    STO --> FS & LK
    BASE --> CRED & SES & STO & SP
    CX & GK --> BASE
    OC --> BASE
    CL --> ENGINE
    ENGINE --> FS & LK & SP
    PLUG -. entry point .-> REG
    REG -. lazy import .-> CL & CX & GK & OC
```

Rules the code follows (and `tests/test_hswap_contract.py` checks):

- Nothing in `core/`, `cli.py`, `output.py`, `ui/` or `adapters/base.py`
  names a harness or provider, or imports an adapter or the Claude engine.
- Adapters depend on the core, never the other way round; the registry loads
  them by import path, lazily, so `hswap codex list` never imports the Claude
  engine.
- The Claude engine (`claude_swap`) is only imported by `adapters/claude.py`.
  Its generic leaf modules (`fsutil`, `locking`, `spawn`) now live in
  `harness_swap.infrastructure`; `claude_swap.fsutil` etc. are aliases of the
  same module objects. The engine's other changes are an embedding hook in
  `cli.py` (`EMBEDDED_PROG`), `ClaudeSwitchError` deriving from `HswapError`,
  and the alias validator moving to `core.models`; its 2900 existing tests
  pass unmodified.

## The adapter contract

Required (`HarnessAdapter`): `id`, `display_name`, `providers`,
`installation()`, `capabilities()`, `list_accounts()`.

Optional roles, each a separate `typing.Protocol` (`core/adapter.py`):

| Role | Method | Capability |
|---|---|---|
| `AccountAdder` | `add_account(alias, provider, login)` | `account_add` |
| `AccountRemover` | `remove_account(account)` | `account_remove` |
| `AccountSwitcher` | `switch_account(account, force)` | `account_switch` |
| `AliasStore` | `set_alias(account, alias)` | — |
| `UsageReader` | `read_usage(account)` + `usage_policy` | `usage_monitoring` |
| `SessionLauncher` | `launch(account, args)` | `parallel_sessions` |
| `NativeCommandLine` | `run_cli(argv)` | — (takes over `hswap <id> ...`) |
| `Migrator` | `migration_plan()`, `apply_migration()` | — (`hswap migrate`) |
| `Diagnosable` | `diagnose()` | — (`hswap doctor`) |

Front ends never call a role directly; they go through
`require(adapter, capability, Role)`, which raises `UnsupportedOperation`
carrying the adapter's own reason when the capability is not usable *on this
install* (binary missing, wrong credential store, version too old, provider
does not offer it). Capabilities are computed at runtime and have four levels:
`supported`, `experimental` (works, rests on undocumented behaviour),
`unavailable` (a prerequisite is missing here) and `unsupported`.

## Identity

An `Account` is identified by `(harness, provider, identity)` — `Account.key`
is `"<harness>:<provider>:<identity>"`. `identity` is a stable subject id
(OAuth user + workspace, OIDC user + team, a credential id, or a SHA-256
fingerprint of an API key), never an email alone. Slots are numbered per
harness. Credentials are never shared across harnesses, even for the same
provider.

## Credential activation (file-backed harnesses)

`core/credentials.py` implements switching once for every harness whose login
is a JSON file. The adapter supplies a `CredentialFormat` — how to split the
file into *parts* (whole file, one OAuth scope, one provider), who owns a part,
and how to put a part back. The core then guarantees, for every such harness:
sync-back of rotated tokens before any overwrite, refusal (or stash with
`--force`) of unmanaged logins, replacement of the target part only (or, for
an `exclusive` format such as Grok's, of every credential part, after saving
the others back), atomic 0600 writes,
read-back verification, rollback, and locking (hswap's lock plus the harness's
own lock file). See [security.md](security.md).

Harnesses that manage multiple accounts themselves (OpenCode 2.x) skip all of
this and implement the roles by calling their native commands.

## Usage and rotation

`UsageService` decides *when* an adapter's `read_usage` is called: at most once
per `UsagePolicy.min_interval_s` per account (shared on disk across processes,
under a lock), exponential backoff after failures while serving the last good
numbers as `error`/`stale`, and `stale` once older than `stale_after_s`.
`UsageSnapshot` carries any number of `QuotaWindow`s (name, used %, reset,
window length, remaining when reported), a state
(`available | stale | unknown | unsupported | authentication_required |
rate_limited | error`), plan and balance. An account with no usage data is
`unsupported`/`unknown`, never "unlimited".

`rotation.select_account` is pure: `best` requires fresh `available` evidence
below the threshold; `next-available` skips only accounts known to be exhausted.
It is scoped to one harness (and optionally one provider) and used for
user-initiated `switch --strategy`. Automatic background rotation remains the
Claude engine's `hswap claude auto`, which encodes Anthropic's quota model
(5-hour/7-day/per-model windows, priority tiers, hysteresis); no other harness
offers a documented quota API to rotate on.

## Sessions

`core/sessions.py`: an isolated session points the harness's home variable
(`CODEX_HOME`, `GROK_HOME`, ...) at the account's own directory in hswap's
store, which already holds that account's credentials, so the harness refreshes
them in place. User configuration named by the adapter is symlinked in; history
stays per account. hswap takes an exclusive lock on
`<home>/.hswap-session.lock` under the account store's lock (so a switch cannot
interleave), runs the harness as its child in the foreground, and releases the
lock when the child exits. The descriptor is not inheritable, so servers the
harness leaves behind do not keep the session "in use"; the kernel drops the
lock if hswap itself dies. Meanwhile that account cannot be activated globally,
and sync-back never overwrites its snapshot, which the session keeps fresher.

## Data

| What | Where |
|---|---|
| hswap stores | `$HSWAP_HOME`, else `$XDG_DATA_HOME/harness-swap` (Linux), `~/.harness-swap` (macOS/Windows) |
| per harness | `<home>/<harness>/accounts.json` (metadata, `schemaVersion` 1), `accounts/<slot>/` (0700, secrets 0600) |
| usage cache | `<home>/cache/usage-cache.json` (numbers only) |
| settings | `<home>/settings.json` |
| Claude | the claude-swap store, in place (`~/.local/share/claude-swap` or `~/.claude-swap-backup`) |
