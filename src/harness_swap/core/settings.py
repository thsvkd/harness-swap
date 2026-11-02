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
from harness_swap.core.store import mkdir_private
from harness_swap.infrastructure.fsutil import atomic_write_text


def _plugin_ids(value: object) -> list[str]:
    items = value.split(",") if isinstance(value, str) else value
    if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
        raise ValueError("expected a comma-separated list of adapter ids")
    return sorted({i.strip().lower() for i in items if i.strip()})


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
}


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
