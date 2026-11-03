"""Alias of :mod:`harness_swap.ui.theme` (moved there so hswap's dashboard shares it).

The module object is shared, not copied, so ``claude_swap.tui.theme.X`` and
``harness_swap.ui.theme.X`` are the same attribute -- including for
monkeypatching.
"""

import sys

from harness_swap.ui import theme as _theme

sys.modules[__name__] = _theme
