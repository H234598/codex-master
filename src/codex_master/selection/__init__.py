"""Compatibility package for the existing deterministic selection core.

The legacy core remains the sole implementation.  This package boundary lets
the plan add typed submodules without duplicating or silently changing the
public ``codex_master.selection`` API.
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


_LEGACY_PATH = Path(__file__).resolve().parent.parent / "selection.py"
_SPEC = spec_from_file_location("codex_master._selection_legacy", _LEGACY_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("selection_core_unavailable")
_LEGACY = module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _LEGACY
_SPEC.loader.exec_module(_LEGACY)
for _name in dir(_LEGACY):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_LEGACY, _name)

__all__ = tuple(name for name in dir(_LEGACY) if not name.startswith("_"))
