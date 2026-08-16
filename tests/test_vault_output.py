from datetime import UTC, datetime

import pytest

from codex_master.vault_output import write_hourly_report


def test_vault_writer_uses_bounded_report_path_and_is_idempotent(tmp_path):
    bucket = datetime(2026, 8, 16, 10, tzinfo=UTC)
    content = "---\ntype: goddess-executive-summary\n---\n"

    first = write_hourly_report(tmp_path, bucket, content)
    second = write_hourly_report(tmp_path, bucket, content)

    assert first == second
    assert first.relative_to(tmp_path).as_posix() == (
        "Reports/Masterjet/Göttinnenberichte/2026/08/16/10-00+00-00.md"
    )
    assert first.read_text(encoding="utf-8") == content


def test_vault_writer_rejects_symlinked_root(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "vault"
    root.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        write_hourly_report(root, datetime(2026, 8, 16, 10, tzinfo=UTC), "x")


def test_vault_writer_refuses_different_final_without_replace(tmp_path):
    bucket = datetime(2026, 8, 16, 10, tzinfo=UTC)
    write_hourly_report(tmp_path, bucket, "a")
    with pytest.raises(ValueError, match="replace"):
        write_hourly_report(tmp_path, bucket, "b")
    target = write_hourly_report(tmp_path, bucket, "b", replace=True)
    assert target.read_text(encoding="utf-8") == "b"
