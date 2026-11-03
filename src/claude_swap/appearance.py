"""Alias of :mod:`harness_swap.ui.appearance` (moved there so hswap's dashboard shares it).

The module object is shared, not copied, so ``claude_swap.appearance.X`` and
``harness_swap.ui.appearance.X`` are the same attribute -- including for
monkeypatching (``tests/conftest.py`` resets ``_cache`` through this name).
"""

import sys

from harness_swap.ui import appearance as _appearance

sys.modules[__name__] = _appearance
