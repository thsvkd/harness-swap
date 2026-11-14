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
stored data raw only when every byte is printable; otherwise the whole value comes
back *hex-encoded*, and ``get_password`` returns that hex as it is. So
``set_password`` re-serializes credential JSON to ASCII when it has to, and refuses
anything else that would not read back. Claude Code's ``-w`` reads share the same
constraint.

This module is import-safe on every platform (it only shells out at call time);
its functions are only meaningful on macOS.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import secrets
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

# Claude Code's active OAuth item; a custom profile's carries a `-<hash>` suffix.
CREDENTIAL_SERVICE = "Claude Code-credentials"

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
# Every character `-w` quoting could get wrong, at a real credential's size: past
# what the hex form can carry, so `set_password` takes the path real logins take.
_SELFTEST_VALUE = json.dumps(
    {"a": "b\"c \\ 'd' $HOME %s é", "pad": "AbC-_.~09" * 240}, ensure_ascii=False
)


# One attribute line of `dump-keychain`: `"svce"<blob>="name"`, or with a hex form first.
_DUMP_ATTRIBUTE = re.compile(r'(?m)^\s*"(svce|acct)"<blob>=(?:0x[0-9A-Fa-f]+\s+)?"(.*)"\s*$')


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


def _readable_form(value: str) -> str:
    """A value `-w` prints as itself. A printable one stays byte for byte. A JSON
    object is re-serialized as ASCII, which any JSON reader decodes to the same data.
    Anything else stays as it is, and fails the read-back."""
    if all(0x20 <= byte <= 0x7e for byte in value.encode("utf-8")):
        return value
    try:
        data = json.loads(value)
    except ValueError:
        return value
    return json.dumps(data) if isinstance(data, dict) else value


def _value_argument(password: str, prefix: str) -> str:
    """The value as the command line carries it: hex when that fits the line buffer,
    else quoted. Raises :class:`KeychainError` when neither does."""
    argument = f"-X {password.encode('utf-8').hex()}"
    if len(f"{prefix} {argument}\n".encode()) <= SECURITY_STDIN_LINE_LIMIT:
        return argument
    # A line ends at a newline whatever the quoting, and argv ends at NUL.
    if "\n" in password or "\0" in password:
        raise KeychainError("value has a line break security -i cannot carry")
    argument = f"-w {_quote(password)}"
    if len(f"{prefix} {argument}\n".encode()) > SECURITY_STDIN_LINE_LIMIT:
        raise KeychainError("value is too long for security -i's line buffer")
    return argument


def set_password(service: str, account: str, password: str) -> None:
    """Create or update a generic-password item (``-U``).

    The secret only ever travels on ``security -i``'s stdin: as hex (``-X``) when
    that fits the line buffer, else quoted (``-w``), which a typical credential's
    JSON does. A value neither form can carry raises :class:`KeychainError`, as
    does a non-zero exit, a timeout, or an item that does not read back as what was
    sent: `security -i` exits 0 whatever its quoting did to the value. The check is
    the read every caller uses, so a value that comes back as hex fails it. Messages
    carry no argv, no stderr and no value.

    On that mismatch the previous value is written back once, so a bad write does
    not leave Claude Code reading a corrupt item. If that fails too the item is left
    as it is: deleting could destroy a newer token a concurrent writer just stored.
    """
    password = _readable_form(password)
    prefix = f"add-generic-password -U -a {_quote(account)} -s {_quote(service)}"
    command = f"{prefix} {_value_argument(password, prefix)}\n"
    try:
        previous = get_password(service, account)
    except KEYCHAIN_ERRORS:
        previous = None  # nothing to restore
    _send_write(command)
    if get_password(service, account) == password:
        return
    # All hex can be that printed form, and writing it back would store the wrong
    # bytes. Real values here are JSON or an sk-ant key.
    if previous and not re.fullmatch("[0-9a-f]+", previous):
        try:
            _send_write(f"{prefix} {_value_argument(previous, prefix)}\n")
        except KEYCHAIN_ERRORS:
            pass
    raise KeychainError("security add-generic-password stored a different value")


def _send_write(command: str) -> None:
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


def login_keychain_file() -> str:
    """Named outright: a daemon's search list lacks the login keychain, and there an
    unqualified lookup answers rc 44 for an item that exists."""
    return str(Path.home() / "Library" / "Keychains" / "login.keychain-db")


def _run_metadata(args: list[str]) -> subprocess.CompletedProcess:
    # Attributes can hold any bytes, and one odd account name must not read as a failure.
    return spawn.run(
        [_SECURITY, *args], capture_output=True, encoding="utf-8", errors="replace", timeout=_TIMEOUT
    )


def generic_items() -> list[tuple[str, str]]:
    """(service, account) of every generic password item in the login keychain.

    Attributes only, never `-d`, so this decrypts nothing and answers while the keychain
    is locked. Raises when `security` fails.
    """
    result = _run_metadata(["dump-keychain", login_keychain_file()])
    if result.returncode != 0:
        raise KeychainError(f"security dump-keychain failed (rc={result.returncode})")
    items = []
    for record in re.split(r"(?m)^keychain: ", result.stdout):
        if 'class: "genp"' in record:
            attributes = dict(_DUMP_ATTRIBUTE.findall(record))
            items.append((attributes.get("svce", ""), attributes.get("acct", "")))
    return items


def credential_items() -> list[tuple[str, str]]:
    """(service, account) of every Claude Code credential item in the login keychain.
    Matches on the service attribute: hswap's own `claude-swap` items may carry the
    name elsewhere."""
    return [
        (service, account)
        for service, account in generic_items()
        if service == CREDENTIAL_SERVICE or service.startswith(f"{CREDENTIAL_SERVICE}-")
    ]


def credential_item_present() -> bool:
    """Does the login keychain hold a Claude Code credential item? A check that fails
    answers True: the caller is deciding whether a refresh token may be spent."""
    try:
        found = _run_metadata(
            ["find-generic-password", "-s", CREDENTIAL_SERVICE, login_keychain_file()]
        )
        if found.returncode != _NOT_FOUND_RC:
            return True  # rc 0 is the item; anything else is a failed check
        return bool(credential_items())
    except (*KEYCHAIN_ERRORS, ValueError):
        return True


def selftest() -> bool:
    """Write, read back and delete a throwaway item through `set_password`, the path
    real credentials take. True only if the value matched and the item is gone."""
    service = f"hswap-selftest-{secrets.token_hex(8)}"
    account = keychain_account_name()
    matched = deleted = False
    try:
        set_password(service, account, _SELFTEST_VALUE)
        matched = True
    except KEYCHAIN_ERRORS:
        pass
    finally:
        try:
            delete_password(service, account)
            deleted = True
        except KEYCHAIN_ERRORS:
            pass
    return matched and deleted


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
