"""Last-line detection of credential-shaped text in anything hswap prints.

Not a redaction layer: hswap never puts secrets into its output models in
the first place. This catches a regression before it reaches a terminal,
a log or a pasted bug report.
"""

from __future__ import annotations

import re

# JWTs, and the common vendor key/token prefixes followed by a long body.
_SECRET_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"\b(?:sk|sk-ant|sk-proj|xai|rt|sess|ghp|gho|github_pat)[-_][A-Za-z0-9_-]{16,}"
)


def looks_secret(text: str) -> bool:
    return bool(_SECRET_RE.search(text))
