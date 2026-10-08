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
    assert json.loads(first.stdout) == {
        "status": "published",
        "descriptor_sha256": descriptor_digest,
    }
    target = plugin / "release-binding.json"
    assert hashlib.sha256(target.read_bytes()).hexdigest() == descriptor_digest[7:]
    assert json.loads(target.read_text())["generation"] == generation
    assert all(
        (plugin / name).read_bytes() == value for name, value in original.items()
    )
    assert _run(release).returncode == 0
    assert json.loads(_run(release).stdout)["status"] == "already_published"
    assert not list(plugin.glob(".release-binding.json.*"))


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
