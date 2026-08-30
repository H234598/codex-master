#!/usr/bin/python3
"""Installed entry point for the canonical Hive hourly probe."""

from __future__ import annotations

from pathlib import Path
import sys


install_root = Path(__file__).resolve().parents[1] / "lib" / "codex-master-hive-probe"
source = install_root / "src"
if not source.is_dir():
    raise SystemExit("installed_probe_source_missing")
sys.path.insert(0, str(source))

from codex_master.hive.hourly_probe import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
