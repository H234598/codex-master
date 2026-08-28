from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_master import server


def test_install_resource_scope_gate_requires_root_and_is_idempotent(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    target = tmp_path / "libexec" / "codex-master-resource-scope-gate"
    target.parent.mkdir()

    with pytest.raises(server.AgentError, match="^resource_scope_gate_install_requires_root$"):
        server.install_resource_scope_gate(root=source_root, target=target)

    with patch.object(server.os, "geteuid", return_value=0):
        first = server.install_resource_scope_gate(root=source_root, target=target)
        second = server.install_resource_scope_gate(root=source_root, target=target)

    expected = (source_root / "bin" / "codex-master-resource-scope-gate").read_bytes()
    assert first == {"ok": True, "status": "installed", "raw_output": "not_returned"}
    assert second == {"ok": True, "status": "already_installed", "raw_output": "not_returned"}
    assert target.read_bytes() == expected
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_install_resource_scope_gate_refuses_existing_symlink(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    target = tmp_path / "libexec" / "codex-master-resource-scope-gate"
    target.parent.mkdir()
    target.symlink_to(tmp_path / "outside")

    with patch.object(server.os, "geteuid", return_value=0), pytest.raises(
        server.AgentError, match="^resource_scope_gate_target_untrusted$"
    ):
        server.install_resource_scope_gate(root=source_root, target=target)


def test_resource_scope_gate_install_cli_uses_explicit_installer(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(
        server,
        "install_resource_scope_gate",
        return_value={"ok": True, "status": "installed", "raw_output": "not_returned"},
    ) as install_gate:
        assert server.main_cli(["install-resource-scope-gate"]) == 0

    install_gate.assert_called_once_with()
    assert '"status": "installed"' in capsys.readouterr().out
