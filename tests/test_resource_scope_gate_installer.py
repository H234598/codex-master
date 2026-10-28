from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from the_hive import server


def _gate_bytes() -> bytes:
    source_root = Path(__file__).resolve().parents[1]
    return (source_root / "bin" / "the-hive-resource-scope-gate").read_bytes()


def test_install_resource_scope_gate_requires_root_and_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "libexec" / "the-hive-resource-scope-gate"
    target.parent.mkdir()

    with patch.object(server, "_resource_scope_gate_source_bytes", return_value=_gate_bytes()):
        with pytest.raises(server.AgentError, match="^resource_scope_gate_install_requires_root$"):
            server.install_resource_scope_gate(target=target)

        with patch.object(server.os, "geteuid", return_value=0):
            first = server.install_resource_scope_gate(target=target)
            second = server.install_resource_scope_gate(target=target)

    expected = _gate_bytes()
    assert first == {"ok": True, "status": "installed", "raw_output": "not_returned"}
    assert second == {"ok": True, "status": "already_installed", "raw_output": "not_returned"}
    assert target.read_bytes() == expected
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert target.stat().st_nlink == 1
    assert not list(target.parent.glob("*.stage"))


def test_install_resource_scope_gate_refuses_existing_symlink(tmp_path: Path) -> None:
    target = tmp_path / "libexec" / "the-hive-resource-scope-gate"
    target.parent.mkdir()
    target.symlink_to(tmp_path / "outside")

    with (
        patch.object(server, "_resource_scope_gate_source_bytes", return_value=_gate_bytes()),
        patch.object(server.os, "geteuid", return_value=0),
        pytest.raises(server.AgentError, match="^resource_scope_gate_target_untrusted$"),
    ):
        server.install_resource_scope_gate(target=target)


def test_install_resource_scope_gate_preserves_unknown_regular_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "libexec" / "the-hive-resource-scope-gate"
    target.parent.mkdir()
    foreign = b"foreign executable\n"
    target.write_bytes(foreign)
    target.chmod(0o755)

    with (
        patch.object(server, "_resource_scope_gate_source_bytes", return_value=_gate_bytes()),
        patch.object(server.os, "geteuid", return_value=0),
        pytest.raises(server.AgentError, match="^resource_scope_gate_target_untrusted$"),
    ):
        server.install_resource_scope_gate(target=target)

    assert target.read_bytes() == foreign
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_install_resource_scope_gate_preserves_matching_bytes_with_wrong_mode(
    tmp_path: Path,
) -> None:
    target = tmp_path / "libexec" / "the-hive-resource-scope-gate"
    target.parent.mkdir()
    expected = _gate_bytes()
    target.write_bytes(expected)
    target.chmod(0o700)

    with (
        patch.object(server, "_resource_scope_gate_source_bytes", return_value=expected),
        patch.object(server.os, "geteuid", return_value=0),
        pytest.raises(server.AgentError, match="^resource_scope_gate_target_untrusted$"),
    ):
        server.install_resource_scope_gate(target=target)

    assert target.read_bytes() == expected
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


def test_install_resource_scope_gate_does_not_replace_target_created_during_publish(
    tmp_path: Path,
) -> None:
    target = tmp_path / "libexec" / "the-hive-resource-scope-gate"
    target.parent.mkdir()
    foreign = b"racing foreign executable\n"
    original_rename = server._fleet_rename_noreplace_at

    def create_foreign_before_publish(
        parent_fd: int,
        source: str,
        destination: str,
        expected_source: os.stat_result,
        error_text: str,
        **kwargs: object,
    ) -> None:
        target.write_bytes(foreign)
        target.chmod(0o755)
        original_rename(
            parent_fd,
            source,
            destination,
            expected_source,
            error_text,
            **kwargs,
        )

    with (
        patch.object(server, "_resource_scope_gate_source_bytes", return_value=_gate_bytes()),
        patch.object(server.os, "geteuid", return_value=0),
        patch.object(
            server, "_fleet_rename_noreplace_at", side_effect=create_foreign_before_publish
        ),
        pytest.raises(
            server.AgentError, match="^resource_scope_gate_target_untrusted$"
        ),
    ):
        server.install_resource_scope_gate(target=target)

    assert target.read_bytes() == foreign
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_resource_scope_gate_install_cli_uses_explicit_installer(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(
        server,
        "install_resource_scope_gate",
        return_value={"ok": True, "status": "installed", "raw_output": "not_returned"},
    ) as install_gate:
        assert server.main_cli(["install-resource-scope-gate"]) == 0

    install_gate.assert_called_once_with()
    assert '"status": "installed"' in capsys.readouterr().out
