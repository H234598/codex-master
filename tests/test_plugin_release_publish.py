from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "scripts" / "the-hive-plugin-release-publish"
INSTALLER = ROOT / "scripts" / "the-hive-hive-hourly-probe-install"
FILES = (
    ".codex-plugin/plugin.json",
    ".mcp.json",
    ".app.json",
    "hooks/hooks.json",
    "hooks/native_bee_event.py",
    "hooks/native_spawn_admission.py",
    "skills/the-hive-fleet/SKILL.md",
    "skills/the-hive-fleet/references/common-invariants.md",
    "skills/the-hive-fleet/references/diagnostics-retry-reporting.md",
    "skills/the-hive-fleet/references/queen-operations.md",
    "skills/the-hive-fleet/references/tl-worker-operations.md",
)


@pytest.fixture
def release(tmp_path: Path) -> tuple[Path, Path, str, str, str]:
    installer = runpy.run_path(str(INSTALLER))
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    (home / ".local" / "lib").mkdir(parents=True, mode=0o700)
    for path in (home / ".local", home / ".local" / "lib"):
        path.chmod(0o700)
    lock_parent = home / ".local" / "state" / "codex-master-mcp" / "hive"
    lock_parent.mkdir(parents=True, mode=0o700)
    for path in (
        lock_parent.parents[0],
        lock_parent.parents[1],
        lock_parent.parents[2],
    ):
        path.chmod(0o700)
    generation = "a" * 40
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT, stage=stage, generation=generation, commit=generation
    )
    manifest = (stage / ".the-hive-runtime-manifest.json").read_bytes()
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    bundle = stage / "TheHivePluginBundleV1"
    descriptor_digest = (
        "sha256:"
        + hashlib.sha256((bundle / "release-binding.json").read_bytes()).hexdigest()
    )
    plugin = home / "plugins" / "the-hive"
    plugin.mkdir(parents=True)
    for name in FILES:
        destination = plugin / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bundle / name, destination)
    marketplace = home / ".agents" / "plugins"
    marketplace.mkdir(parents=True)
    (marketplace / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "personal",
                "plugins": [
                    {
                        "name": "the-hive",
                        "source": {"source": "local", "path": "./plugins/the-hive"},
                    }
                ],
            }
        )
    )
    installer["_publish_runtime_generation"](
        stage=stage, release_root=home / ".local" / "lib" / "the-hive-runtime"
    )
    return home, plugin, generation, manifest_digest, descriptor_digest


def _run(release: tuple[Path, Path, str, str, str]) -> subprocess.CompletedProcess[str]:
    home, _plugin, generation, manifest_digest, descriptor_digest = release
    return subprocess.run(
        [
            sys.executable,
            str(OPERATOR),
            "--home",
            str(home),
            "--generation",
            generation,
            "--manifest-sha256",
            manifest_digest,
            "--descriptor-sha256",
            descriptor_digest,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_publishes_only_attested_descriptor_and_is_idempotent(
    release: tuple[Path, Path, str, str, str],
) -> None:
    home, plugin, generation, _manifest_digest, descriptor_digest = release
    original = {name: (plugin / name).read_bytes() for name in FILES}
    first = _run(release)
    assert first.returncode == 0, first.stdout
    first_result = json.loads(first.stdout)
    assert first_result["status"] == "published"
    assert first_result["descriptor_sha256"] == descriptor_digest
    assert len(first_result["receipt_sha256"]) == 64
    target = plugin / "release-binding.json"
    assert hashlib.sha256(target.read_bytes()).hexdigest() == descriptor_digest[7:]
    assert json.loads(target.read_text())["generation"] == generation
    assert all(
        (plugin / name).read_bytes() == value for name, value in original.items()
    )
    second = _run(release)
    assert second.returncode == 0
    second_result = json.loads(second.stdout)
    assert second_result["status"] == "already_published"
    assert len(second_result["receipt_sha256"]) == 64
    assert not list(plugin.glob(".release-binding.json.*"))


def test_publisher_persists_effect_receipt_after_descriptor_readback(
    release: tuple[Path, Path, str, str, str],
) -> None:
    home, plugin, generation, manifest_digest, descriptor_digest = release

    result = _run(release)

    assert result.returncode == 0, result.stdout
    state_root = home / ".local/state/codex-master-mcp/hive"
    receipt_path = state_root / "plugin-release-effect-receipt-v1.json"
    receipt = json.loads(receipt_path.read_bytes())
    target = plugin / "release-binding.json"
    target_stat = target.stat()
    assert receipt["schema_version"] == 1
    assert receipt["owner"] == "plugin_release_publisher"
    assert receipt["effect"] == "plugin_release_descriptor_verified_present"
    assert receipt["generation"] == generation
    assert receipt["manifest_digest"] == manifest_digest
    assert receipt["descriptor_sha256"] == descriptor_digest
    assert receipt["target"] == "plugins/the-hive/release-binding.json"
    assert receipt["target_identity"] == {
        "dev": target_stat.st_dev,
        "gid": target_stat.st_gid,
        "ino": target_stat.st_ino,
        "mode": 0o644,
        "nlink": 1,
        "size": target_stat.st_size,
        "uid": target_stat.st_uid,
    }
    assert receipt["issued_at_unix_ns"] > 0
    assert result.stdout
    assert hashlib.sha256(target.read_bytes()).hexdigest() == descriptor_digest[7:]


def test_publisher_rechecks_descriptor_after_crash_before_receipt(release):
    home, plugin, generation, manifest_digest, descriptor_digest = release
    namespace = runpy.run_path(str(OPERATOR), run_name="plugin_receipt_retry_test")
    publisher_globals = namespace["publish"].__globals__
    write_receipt = publisher_globals["_write_effect_receipt"]

    def crash_before_receipt(**_kwargs):
        raise namespace["PublishError"]("injected_receipt_crash")

    publisher_globals["_write_effect_receipt"] = crash_before_receipt
    with pytest.raises(namespace["PublishError"], match="injected_receipt_crash"):
        namespace["publish"](home, generation, manifest_digest, descriptor_digest)
    receipt_path = (
        home
        / ".local/state/codex-master-mcp/hive/plugin-release-effect-receipt-v1.json"
    )
    assert (plugin / "release-binding.json").is_file()
    assert not receipt_path.exists()

    publisher_globals["_write_effect_receipt"] = write_receipt
    result = namespace["publish"](home, generation, manifest_digest, descriptor_digest)

    assert result["status"] == "already_published"
    assert (
        json.loads(receipt_path.read_bytes())["descriptor_sha256"] == descriptor_digest
    )


def test_publisher_preserves_foreign_receipt_without_overwrite(release):
    home, plugin, generation, manifest_digest, descriptor_digest = release
    receipt_path = (
        home
        / ".local/state/codex-master-mcp/hive/plugin-release-effect-receipt-v1.json"
    )
    original = b"foreign receipt\n"
    receipt_path.write_bytes(original)
    receipt_path.chmod(0o600)
    namespace = runpy.run_path(str(OPERATOR), run_name="plugin_receipt_foreign_test")

    with pytest.raises(namespace["PublishError"]):
        namespace["publish"](home, generation, manifest_digest, descriptor_digest)

    assert receipt_path.read_bytes() == original
    assert not (plugin / "release-binding.json").exists()


def test_publisher_refreshes_stale_receipt_after_descriptor_readback(release):
    home, plugin, generation, manifest_digest, descriptor_digest = release
    first = _run(release)
    assert first.returncode == 0, first.stdout
    receipt_path = (
        home
        / ".local/state/codex-master-mcp/hive/plugin-release-effect-receipt-v1.json"
    )
    receipt = json.loads(receipt_path.read_bytes())
    receipt["issued_at_unix_ns"] = 1
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    )
    receipt_path.chmod(0o600)
    namespace = runpy.run_path(str(OPERATOR), run_name="plugin_receipt_refresh_test")

    result = namespace["publish"](home, generation, manifest_digest, descriptor_digest)

    refreshed = json.loads(receipt_path.read_bytes())
    assert result["status"] == "already_published"
    assert refreshed["issued_at_unix_ns"] > 1
    assert (plugin / "release-binding.json").is_file()


@pytest.mark.parametrize(
    "drift",
    [
        "descriptor",
        "runtime_descriptor_absent",
        "runtime_descriptor_drift",
        "hook",
        "marketplace",
        "pointer",
        "symlink",
    ],
)
def test_drift_holds_without_overwriting(
    release: tuple[Path, Path, str, str, str], drift: str
) -> None:
    home, plugin, *_ = release
    target = plugin / "release-binding.json"
    if drift == "descriptor":
        target.write_bytes(b"wrong\n")
    elif drift.startswith("runtime_descriptor_"):
        source = (
            home
            / ".local"
            / "lib"
            / "the-hive-runtime"
            / "generations"
            / ("a" * 40)
            / "TheHivePluginBundleV1"
            / "release-binding.json"
        )
        if drift.endswith("absent"):
            source.unlink()
        else:
            source.write_bytes(b"wrong\n")
    elif drift == "hook":
        (plugin / "hooks" / "native_bee_event.py").write_bytes(b"wrong\n")
    elif drift == "marketplace":
        (home / ".agents" / "plugins" / "marketplace.json").write_bytes(b"{}\n")
    elif drift == "pointer":
        pointer = (
            home
            / ".local"
            / "lib"
            / "the-hive-runtime"
            / ".the-hive-release-pointers.json"
        )
        pointer.write_bytes(b"{}\n")
    else:
        target.symlink_to(home / "outside")
    before = target.read_bytes() if target.is_file() else None
    result = _run(release)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "hold"
    assert (target.read_bytes() if target.is_file() else None) == before


def test_concurrent_target_creation_is_not_clobbered(
    release: tuple[Path, Path, str, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, plugin, generation, manifest_digest, descriptor_digest = release
    namespace = runpy.run_path(str(OPERATOR), run_name="plugin_publish_test")
    link = os.link

    def raced_link(source: str, destination: str, **kwargs: object) -> None:
        (plugin / destination).write_bytes(b"external\n")
        link(source, destination, **kwargs)

    monkeypatch.setattr(namespace["os"], "link", raced_link)
    with pytest.raises(namespace["PublishError"], match="plugin_descriptor_raced"):
        namespace["publish"](home, generation, manifest_digest, descriptor_digest)
    assert (plugin / "release-binding.json").read_bytes() == b"external\n"
    assert not list(plugin.glob(".release-binding.json.*"))


@pytest.mark.parametrize("race", ["source", "marketplace", "parent", "removed_target"])
def test_post_link_races_hold_and_remove_only_own_descriptor(
    release: tuple[Path, Path, str, str, str],
    monkeypatch: pytest.MonkeyPatch,
    race: str,
) -> None:
    home, plugin, generation, manifest_digest, descriptor_digest = release
    namespace = runpy.run_path(str(OPERATOR), run_name="plugin_publish_test")
    link = os.link

    def raced_link(source: str, destination: str, **kwargs: object) -> None:
        link(source, destination, **kwargs)
        if race == "source":
            (plugin / "hooks" / "native_bee_event.py").write_bytes(b"changed\n")
        elif race == "marketplace":
            (home / ".agents" / "plugins" / "marketplace.json").write_bytes(b"{}\n")
        elif race == "parent":
            (home / "plugins").rename(home / "plugins-moved")
            (home / "plugins").symlink_to(
                home / "plugins-moved", target_is_directory=True
            )
        else:
            (plugin / destination).unlink()

    monkeypatch.setattr(namespace["os"], "link", raced_link)
    with pytest.raises(Exception):
        namespace["publish"](home, generation, manifest_digest, descriptor_digest)
    if race == "parent":
        assert not (
            home / "plugins-moved" / "the-hive" / "release-binding.json"
        ).exists()
        (home / "plugins").unlink()
        (home / "plugins-moved").rename(home / "plugins")
    else:
        assert not (plugin / "release-binding.json").exists()
    assert not list(plugin.glob(".release-binding.json.*"))
