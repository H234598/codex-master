from __future__ import annotations

import gzip
import os
from pathlib import Path
import stat
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "codex-master-manpage"
MANPAGE_NAME = "codex-master-mcp.1.gz"


def run_installer(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, os.fspath(INSTALLER), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_build_produces_deterministic_gzip_manpage(tmp_path: Path) -> None:
    result = run_installer("build", "--output-dir", os.fspath(tmp_path))
    assert result.returncode == 0, result.stderr

    artifact = tmp_path / MANPAGE_NAME
    first = artifact.read_bytes()
    rendered_source = gzip.decompress(first).decode("utf-8")
    assert rendered_source.startswith('.TH "CODEX-MASTER-MCP" "1"')
    assert b"\x00\x00\x00\x00" == first[4:8]

    result = run_installer("build", "--output-dir", os.fspath(tmp_path))
    assert result.returncode == 0, result.stderr
    assert artifact.read_bytes() == first


def test_install_and_verify_use_user_prefix_layout(tmp_path: Path) -> None:
    prefix = tmp_path / "prefix"
    result = run_installer("install", "--prefix", os.fspath(prefix))
    assert result.returncode == 0, result.stderr

    target = prefix / "share" / "man" / "man1" / MANPAGE_NAME
    assert target.is_file()
    assert not target.is_symlink()
    assert stat.S_IMODE(target.stat().st_mode) == 0o644

    result = run_installer("verify", "--prefix", os.fspath(prefix))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"verified: {target}"

    target.write_bytes(b"tampered")
    result = run_installer("verify", "--prefix", os.fspath(prefix))
    assert result.returncode != 0
    assert "installed manpage differs from source" in result.stderr


def test_install_refuses_symlinked_man1_directory(tmp_path: Path) -> None:
    prefix = tmp_path / "prefix"
    man_root = prefix / "share" / "man"
    outside = tmp_path / "outside"
    man_root.mkdir(parents=True)
    outside.mkdir()
    (man_root / "man1").symlink_to(outside, target_is_directory=True)

    result = run_installer("install", "--prefix", os.fspath(prefix))
    assert result.returncode != 0
    assert "symlink" in result.stderr.lower()
    assert not (outside / MANPAGE_NAME).exists()
