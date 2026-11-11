"""Error types shared by the core and every adapter.

Every error hswap raises on purpose derives from :class:`HswapError`, so the
CLI has one place to turn them into a clean message (or a JSON error
envelope) instead of a traceback. Messages must never contain secret
material; adapters pass identities (email, account id), never tokens.
"""

from __future__ import annotations


class HswapError(Exception):
    """Base class for every deliberate hswap failure."""


class LoginFailed(HswapError):
    """The harness's own sign-in did not finish with a usable login."""


class WrongAccount(HswapError):
    """The sign-in ended on another account than the one asked for."""


class LockError(HswapError):
    """A cross-process lock could not be acquired in time."""


class UnsupportedOperation(HswapError):
    """The harness (or this install of it) cannot do what was asked.

    Carries the capability name and a human explanation, so the caller can
    show *why* instead of a bare "not supported".
    """

    def __init__(self, capability: str, reason: str, support: str = "unsupported"):
        super().__init__(f"{capability} is {'unavailable here' if support == 'unavailable' else 'not supported'}: {reason}")
        self.capability = capability
        self.reason = reason


class HarnessNotFound(HswapError):
    """No adapter is registered under the requested harness id."""


class HarnessNotInstalled(HswapError):
    """The adapter exists but the harness binary/config is not present."""


class AccountNotFound(HswapError):
    """No stored account matches the given slot, alias or identity."""


class NoSwitchTarget(HswapError):
    """No other account qualifies for a strategy pick: nothing to switch to, not a failure."""


class CredentialError(HswapError):
    """Reading, validating or writing credential material failed."""


class CredentialConflict(CredentialError):
    """The live login is not one hswap manages, so overwriting it would lose it."""


class ValidationError(HswapError, ValueError):
    """User input (an alias, a setting) failed validation."""


class StoreVersionError(HswapError):
    """An hswap data file was written by a newer, incompatible hswap."""
