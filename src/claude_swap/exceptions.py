"""Custom exceptions for Claude Switch."""

from harness_swap.core import errors as _core


class ClaudeSwitchError(_core.HswapError):
    """Base exception for Claude Switch errors."""

    pass


class CredentialError(ClaudeSwitchError):
    """Error related to credential operations."""

    pass


class CredentialReadError(CredentialError):
    """Failed to read credentials."""

    pass


class CredentialWriteError(CredentialError):
    """Failed to write credentials."""

    pass


class KeychainUnavailableError(CredentialError):
    """Keychain-required mode: the login keychain cannot be used from here."""

    json_type = "keychain_unavailable"  # the --json error envelope's ``type``


STORES_DISAGREE_MESSAGE = (
    "The Keychain and the credentials file hold different logins; nothing was changed. "
    "Run hswap claude keepalive --adopt file|keychain, naming the store whose writer "
    "refreshed last."
)
COPIES_DISAGREE_MESSAGE = (
    "A copy of this login (the slot's backup, a leftover .enc or the stash) holds a "
    "different token, or cannot be read, and no record shows it is older; nothing was "
    "sent. Log in again with /login and run hswap claude add."
)
RELOGIN_REQUIRED_MESSAGE = (
    "This login's token is already spent, or another copy of it holds a different token "
    "and no record shows which is newer; nothing was sent. Log in again with /login and "
    "run hswap claude add."
)


class StoresDisagreeError(CredentialError):
    """Keychain-required mode: the Keychain and the file hold different logins."""

    json_type = "stores_disagree"


class CopiesDisagreeError(StoresDisagreeError):
    """Keychain-required mode: a copy of the active login outside the stores differs."""


class ReloginRequiredError(CredentialError):
    """Keychain-required mode: nothing proves this token is the account's newest."""

    json_type = "relogin_required"


class RequiredModeUnsupportedError(ClaudeSwitchError):
    """Keychain-required mode supports a small set of commands, and this is not one."""

    json_type = "required_mode_unsupported"

    def __init__(self, command: str):
        super().__init__(
            f"required_mode_unsupported: {command} is not supported in keychain-required "
            "mode. Turn off credentials.requireKeychain temporarily to use it, or use "
            "/login and hswap claude add."
        )


class SessionProfilesExistError(RequiredModeUnsupportedError):
    """Keychain-required mode does not cover session profiles, so it stops at any."""

    def __init__(self, path: str):
        ClaudeSwitchError.__init__(
            self,
            "required_mode_unsupported: session profiles exist (from hswap claude run); "
            f"remove {path} or turn off credentials.requireKeychain.",
        )


class StashEntryInUseError(CredentialError):
    """Keychain-required mode: this stash entry may still be needed, so it stays."""

    json_type = "stash_entry_in_use"


class ConfigError(ClaudeSwitchError):
    """Error related to configuration operations."""

    pass


class SwitchError(ClaudeSwitchError):
    """Error during account switch operation."""

    pass


class SessionError(ClaudeSwitchError):
    """Error setting up or launching a session-mode profile."""

    pass


class LockError(ClaudeSwitchError, _core.LockError):
    """Error acquiring lock."""

    pass


class ClaudeCodeLockTimeout(LockError):
    """Timed out acquiring one of Claude Code's own advisory locks.

    Raised when ``~/.claude.lock`` / ``~/.claude.json.lock`` stays held past
    our bounded wait — usually Claude Code mid-token-refresh. Nothing has been
    mutated when this raises; the operation is safe to retry.
    """

    pass


class AccountNotFoundError(ClaudeSwitchError):
    """Account not found."""

    pass


class ValidationError(ClaudeSwitchError):
    """Validation error."""

    pass


class TransferError(ClaudeSwitchError):
    """Error during account export or import."""

    pass


class MigrationError(ClaudeSwitchError):
    """Error migrating the backup directory between layouts (e.g. legacy → XDG)."""

    pass


class MigrationIncomplete(ClaudeSwitchError):
    """A one-time data migration could not finish for every record.

    Raised by run-once migrations (see ``migrations.py``) when some entries
    failed or the source backend was inaccessible. The migration runner treats
    this as "not applied" so the migration is retried on the next run rather
    than being recorded as done with records left behind.
    """

    pass
