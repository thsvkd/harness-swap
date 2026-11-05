"""macOS Keychain access via the ``security`` CLI.

A small wrapper around the system ``security`` tool for storing generic
passwords, used instead of the third-party ``keyring`` library. Two reasons:

- The macOS hot path no longer needs the ``keyring`` dependency.
- Keychain items are created and read by the same stable ``security`` binary, so
  reads stay silent across upgrades. ``keyring`` (and any in-process
  Security.framework call) anchors the item's access to the *Python interpreter*,
  which ``uv tool upgrade`` rebuilds — at which point macOS can show the "wants to
  use your keychain" prompt. ``security`` never changes, so creator == reader and
  there is no prompt.

The read/write/delete shapes mirror Claude Code's own implementation
(``utils/secureStorage/macOsKeychainStorage.ts``):

- ``set_password`` pipes the command through ``security -i`` (stdin) so the secret
  never appears in process argv (``ps``, process audit logs). It hex-encodes the
  value (``-X``) when that fits ``security -i``'s 4096-byte stdin line buffer, sends
  it quoted (``-w``) when only that fits, and refuses otherwise. Unlike Claude
  Code's own writer it never falls back to argv: a real credential's hex is longer
  than the buffer, so the fallback would be the common case.
- ``get_password`` uses ``find-generic-password ... -w`` and treats exit code 44
  as "not found" (returns ``None``); any *other* non-zero exit raises so callers
  can tell a genuine miss apart from a locked/denied/unavailable Keychain.

Caveat: values must be printable text. ``find-generic-password -w`` prints the
stored data raw only when it is printable; data with non-printable bytes comes
back *hex-encoded*, so a write/read round-trip would not be identity. Fine for
this codebase (credentials are ASCII JSON), but don't reuse this wrapper for
arbitrary binary data. Claude Code's ``-w`` reads share the same constraint.

This module is import-safe on every platform (it only shells out at call time);
its functions are only meaningful on macOS.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from claude_swap import spawn

# ``security -i`` reads stdin with a 4096-byte fgets() buffer (BUFSIZ on darwin).
# A command line longer than this is truncated mid-argument: it fails to write
# while leaving any previous entry intact (Claude Code #30337). 64 bytes of
# headroom guards against line-terminator accounting differences.
SECURITY_STDIN_LINE_LIMIT = 4096 - 64

_NOT_FOUND_RC = 44  # errSecItemNotFound surfaced by find/delete-generic-password

# Bound every ``security`` spawn so a wedged Keychain (a locked login keychain
# prompting for an unlock that never comes on a headless/SSH host) can't hang the
# CLI. 5s, deliberately short: a credential op that has to fall back to the file
# may be followed by a best-effort cleanup spawn, so the per-op budget doubles in
# the worst case. A healthy Keychain answers in well under 100ms.
_TIMEOUT = 5.0

# Pin the absolute path to Apple's system binary rather than resolving via PATH:
# this is a credential tool, so an attacker-controlled ``security`` earlier on
# PATH must not be able to intercept secrets. ``/usr/bin/security`` is present on
# every macOS.
_SECURITY = "/usr/bin/security"
_SECURITY_FRAMEWORK = "/System/Library/Frameworks/Security.framework/Security"
_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_UNLOCK_STATE_STATUS = 1  # kSecUnlockStateStatus


class KeychainError(Exception):
    """A ``security`` invocation failed for a reason other than "not found"."""


# The exceptions a Keychain operation may raise that callers should treat as
# "Keychain unusable" (→ fall back to file storage) rather than a programming
# bug: a wrapper failure (KeychainError, incl. a converted timeout), a raw
# subprocess timeout, or a missing ``security`` binary (OSError). Catching this
# tuple — never bare ``Exception`` — keeps a real bug loud instead of silently
# routing to the file backend mid-invocation.
KEYCHAIN_ERRORS = (KeychainError, subprocess.TimeoutExpired, OSError)


def keychain_account_name() -> str:
    """Account name for the active-credential Keychain item, mirroring Claude
    Code's ``getUsername()`` (``utils/secureStorage/macOsKeychainHelpers.ts``).

    ``$USER`` first, then the OS username, then a stable final fallback. Matching
    this exactly matters on headless/launchd/cron hosts where ``$USER`` is unset:
    a divergent default (e.g. ``"user"``) would key a *different* Keychain item
    than Claude Code, so the two could not see each other's active credential.
    """
    user = os.environ.get("USER")
    if user:
        return user
    try:
        import pwd  # POSIX-only; the account-name call sites are macOS-only

        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return "claude-code-user"


def _quote(value: str) -> str:
    """Quote a value for a ``security -i`` stdin command line.

    ``security -i`` re-parses each line shell-style, so wrap the value in double
    quotes and backslash-escape any embedded ``"``/``\\`` (e.g. the active-
    credential service name contains a space).
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def get_password(service: str, account: str) -> str | None:
    """Return the stored password, or ``None`` if no such item exists (rc 44).

    Raises :class:`KeychainError` on any other non-zero exit (locked / denied /
    unavailable) or a timeout, so a genuine miss is not confused with a transient
    failure.
    """
    try:
        result = spawn.run(
            [_SECURITY, "find-generic-password", "-a", account, "-w", "-s", service],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise KeychainError(
            f"security find-generic-password timed out after {_TIMEOUT}s"
        ) from None
    if result.returncode == 0:
        # `-w` prints the value followed by one newline; strip exactly that so
        # values with meaningful leading/trailing whitespace survive intact.
        return result.stdout.removesuffix("\n")
    if result.returncode == _NOT_FOUND_RC:
        return None
    raise KeychainError(
        f"security find-generic-password failed (rc={result.returncode}): "
        f"{result.stderr.strip()}"
    )


def item_exists(service: str, account: str) -> bool:
    """Whether a generic-password item exists, without touching its secret.

    Attribute-only lookup (no ``-w``): nothing is decrypted, so this can never
    trigger a Keychain prompt, even for items owned by another app. Returns
    ``True`` only on rc 0; "not found" (rc 44), error exits, a timeout, and a
    missing binary all return ``False``. Deliberately **non-raising**: callers use
    it for cleanup verification, not access decisions, so it must never feed the
    capability cache (a timeout here means "couldn't tell", not "Keychain works").
    """
    try:
        result = spawn.run(
            [_SECURITY, "find-generic-password", "-a", account, "-s", service],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def set_password(service: str, account: str, password: str) -> None:
    """Create or update a generic-password item (``-U``).

    The secret only ever travels on ``security -i``'s stdin: as hex (``-X``) when
    that fits the line buffer, else quoted (``-w``), which a typical credential's
    JSON does. A value neither form can carry raises :class:`KeychainError`, as
    does a non-zero exit or a timeout. Messages carry no argv and no stderr.
    """
    prefix = f"add-generic-password -U -a {_quote(account)} -s {_quote(service)}"
    command = f"{prefix} -X {password.encode('utf-8').hex()}\n"
    if len(command.encode("utf-8")) > SECURITY_STDIN_LINE_LIMIT:
        # A line ends at a newline whatever the quoting, and argv ends at NUL.
        if "\n" in password or "\0" in password:
            raise KeychainError("value has a line break security -i cannot carry")
        command = f"{prefix} -w {_quote(password)}\n"
        if len(command.encode("utf-8")) > SECURITY_STDIN_LINE_LIMIT:
            raise KeychainError("value is too long for security -i's line buffer")
    try:
        result = spawn.run(
            [_SECURITY, "-i"],
            input=command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise KeychainError(
            f"security add-generic-password timed out after {_TIMEOUT}s"
        ) from None
    if result.returncode != 0:
        raise KeychainError(f"security add-generic-password failed (rc={result.returncode})")


def delete_password(service: str, account: str) -> None:
    """Delete a generic-password item. rc 44 (already absent) counts as success.

    Raises :class:`KeychainError` on any other non-zero exit or a timeout.
    """
    try:
        result = spawn.run(
            [_SECURITY, "delete-generic-password", "-a", account, "-s", service],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise KeychainError(
            f"security delete-generic-password timed out after {_TIMEOUT}s"
        ) from None
    if result.returncode in (0, _NOT_FOUND_RC):
        return
    raise KeychainError(
        f"security delete-generic-password failed (rc={result.returncode}): "
        f"{result.stderr.strip()}"
    )


def _run_security(args: list[str]) -> subprocess.CompletedProcess:
    return spawn.run(
        [_SECURITY, *args], capture_output=True, text=True, timeout=_TIMEOUT
    )


def _listed_paths(output: str) -> list[str]:
    """Paths from ``security`` listing output: one quoted path per line."""
    return [line.strip().strip('"') for line in output.splitlines() if line.strip()]


def _login_keychain_path(runner: Callable[[list[str]], subprocess.CompletedProcess]) -> str:
    """The login keychain's path, as ``security`` reports it.

    Only a path inside the user's own keychain directory counts: a daemon gets
    ``System.keychain`` here, which would pass both preflight conditions without
    saying anything about the login keychain.
    """
    keychains = Path.home() / "Library" / "Keychains"
    for args in (["login-keychain"], ["default-keychain", "-d", "user"]):
        try:
            result = runner(args)
        except KEYCHAIN_ERRORS:
            continue
        paths = _listed_paths(result.stdout) if result.returncode == 0 else []
        if paths and Path(os.path.realpath(paths[0])).parent == Path(os.path.realpath(keychains)):
            return paths[0]
    return str(keychains / "login.keychain-db")


def _login_keychain_unlocked(path: str) -> bool | None:
    """Locked or not, asked so that no dialog can appear; None when unknown.

    In-process because ``security`` has no such command, and it is safe here: a
    status read touches no item, so it anchors no item's access to this interpreter
    (the module docstring's reason to shell out). Nothing else in this process uses
    the framework's keychain API, so interaction stays off.
    """
    try:
        security = ctypes.CDLL(_SECURITY_FRAMEWORK)
        core_foundation = ctypes.CDLL(_CORE_FOUNDATION)
        security.SecKeychainSetUserInteractionAllowed(False)
        keychain = ctypes.c_void_p()
        status = ctypes.c_uint32()
        if security.SecKeychainOpen(os.fsencode(path), ctypes.byref(keychain)) != 0:
            return None
        try:
            if security.SecKeychainGetStatus(keychain, ctypes.byref(status)) != 0:
                return None
        finally:
            if keychain:
                core_foundation.CFRelease(keychain)
        return bool(status.value & _UNLOCK_STATE_STATUS)
    except (OSError, AttributeError):
        return None


def keychain_reachable(
    runner: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    *,
    platform: str = sys.platform,
    unlocked: Callable[[str], bool | None] = _login_keychain_unlocked,
) -> bool | None:
    """Can this process actually use the login keychain? ``None`` off macOS.

    A find-generic-password rc 44 proves nothing: a LaunchDaemon or an SSH session
    gets it for an item that exists, because the login keychain is not in its
    search list. So this asks the questions that do separate them: is the login
    keychain in this process's search list, is it unlocked, and does it answer
    ``show-keychain-info`` (rc 36 when no user session can unlock it)?

    ``show-keychain-info`` runs with interaction allowed, so on a locked keychain
    in a GUI session it can raise an unlock dialog. It only runs once the keychain
    is known to be unlocked; a lock state that cannot be read counts as unreachable.
    """
    if platform != "darwin":
        return None
    runner = runner or _run_security
    try:
        login = _login_keychain_path(runner)
        listed = runner(["list-keychains"])
        if listed.returncode != 0 or os.path.realpath(login) not in {
            os.path.realpath(path) for path in _listed_paths(listed.stdout)
        }:
            return False
        if unlocked(login) is not True:
            return False
        return runner(["show-keychain-info", login]).returncode == 0
    except KEYCHAIN_ERRORS:
        return False
