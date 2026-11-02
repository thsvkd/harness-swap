"""Alias of :mod:`harness_swap.infrastructure.fsutil` (moved there in hswap).

The module object is shared, not copied, so ``claude_swap.fsutil.X`` and
``harness_swap.infrastructure.fsutil.X`` are the same attribute -- including
for monkeypatching.
"""

import sys

from harness_swap.infrastructure import fsutil as _fsutil

sys.modules[__name__] = _fsutil
