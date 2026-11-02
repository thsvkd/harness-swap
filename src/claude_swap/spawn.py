"""Alias of :mod:`harness_swap.infrastructure.spawn` (moved there in hswap).

The module object is shared, not copied, so patches through either name hit
the same attributes.
"""

import sys

from harness_swap.infrastructure import spawn as _spawn

sys.modules[__name__] = _spawn
