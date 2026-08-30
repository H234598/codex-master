#!/usr/bin/python3
"""Installed entry point for the canonical Hive hourly probe."""

from __future__ import annotations

import os
from pathlib import Path
import sys


def _repository() -> Path:
    configured = os.environ.get("CODEX_MASTER_PROBE_REPOSITORY")
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_absolute():
            return candidate
    return Path(__file__).resolve().parents[2]


repository = _repository()
source = repository / "src"
if source.is_dir():
    sys.path.insert(0, str(source))

from codex_master.hive.hourly_probe import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
