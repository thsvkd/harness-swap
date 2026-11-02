"""hswap's own settings (``<hswap home>/settings.json``).

Deliberately tiny. Harness-specific settings stay with the harness's adapter
(the Claude engine keeps its own ``settings.json``; ``hswap claude config``
manages it).
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from harness_swap.core.paths import hswap_home
from harness_swap.core.registry import check_id, parse_trust
from harness_swap.core.store import mkdir_private
from harness_swap.infrastructure.fsutil import atomic_write_text


def _plugin_ids(value: object) -> list[str]:
    items = value.split(",") if isinstance(value, str) else value
    if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
        raise ValueError("expected a comma-separated list of <id>@<distribution>")
    return sorted({parse_trust(i) for i in items if i.strip()})


def _harness_ids(value: object) -> list[str]:
    items = value.split(",") if isinstance(value, str) else value
    if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
        raise ValueError("expected a comma-separated list of harness ids")
    ids = sorted({i.strip().lower() for i in items if i.strip()})
    bad = [i for i in ids if check_id(i)]
    if bad:
        raise ValueError(f"not a harness id: {', '.join(bad)}")
    return ids


def _seconds(value: object) -> float:
    try:
        seconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError("expected a number of seconds") from None
    if math.isnan(seconds) or not 60 <= seconds <= 86400:
        raise ValueError("must be between 60 and 86400 seconds")
    return seconds


def _threshold(value: object) -> float:
    try:
        pct = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError("expected a number") from None
    if math.isnan(pct) or not 50.0 <= pct <= 99.9:
        raise ValueError("must be between 50 and 99.9")
    return pct


#: key -> (default, validator). Validators raise ValueError with a readable message.
SPECS = {
    "plugins.trusted": ([], _plugin_ids),
    "rotation.threshold": (95.0, _threshold),
    # Harnesses whose usage hswap may read from the endpoints the harness itself
    # calls (undocumented; may change), refreshing inactive accounts' tokens to do so.
    "usage.remote": ([], _harness_ids),
    # Harnesses `hswap <harness> auto` may switch automatically (opt-in: see the warning).
    "auto.enabled": ([], _harness_ids),
    "auto.cooldown": (600.0, _seconds),
}

#: Shown when a harness is added to one of these lists.
WARNINGS = {
    "usage.remote": (
        "hswap will call the usage endpoints these harnesses use themselves, with your own tokens. "
        "They are not public APIs: they may change or stop working without notice."
    ),
    "auto.enabled": (
        "Automatic switching uses your other accounts when one nears its limit. Several providers' terms "
        "restrict sharing accounts or using several to get around rate limits; check them. "
        "You are responsible for complying."
    ),
}


def opted_in(key: str, harness_id: str) -> bool:
    """Whether ``harness_id`` is in the list setting ``key`` (``usage.remote``, ``auto.enabled``)."""
    return harness_id in load()[key]


def settings_path() -> Path:
    return hswap_home() / "settings.json"


def load() -> dict:
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        data = {}
    out = {}
    for key, (default, validate) in SPECS.items():
        try:
            out[key] = validate(data[key]) if key in data else default
        except ValueError:
            out[key] = default  # a hand-edited bad value never blocks the CLI
    return out


def invalid() -> list[str]:
    """Stored values :func:`load` ignores (and falls back to the default for)."""
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except ValueError:
        return [f"{settings_path()} is not valid JSON; every setting uses its default"]
    out = []
    for key, (_default, validate) in SPECS.items():
        if key in data:
            try:
                validate(data[key])
            except ValueError as exc:
                out.append(f"{key} in {settings_path()} is ignored: {exc}")
    return out


def _write(data: dict) -> None:
    mkdir_private(settings_path().parent)
    atomic_write_text(settings_path(), json.dumps(data, indent=2) + "\n")


def set_value(key: str, raw: str) -> object:
    if key not in SPECS:
        raise KeyError(f"unknown setting {key!r}; known: {', '.join(SPECS)}")
    value = SPECS[key][1](raw)
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        data = {}
    data[key] = value
    _write(data)
    return value


def unset(key: str) -> None:
    if key not in SPECS:
        raise KeyError(f"unknown setting {key!r}; known: {', '.join(SPECS)}")
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return
    if data.pop(key, None) is not None:
        _write(data)
