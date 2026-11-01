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

from the_hive.hook_session_pin_store import HookSessionPinStoreV1
from the_hive.runtime_lifecycle import (
    _read_regular_at,
    _verify_plugin_release_effect_receipt,
)


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


def _run(
    release: tuple[Path, Path, str, str, str],
    *,
    previous_descriptor_sha256: str | None = None,
) -> subprocess.CompletedProcess[str]:
    home, _plugin, generation, manifest_digest, descriptor_digest = release
    extra: list[str] = []
    if previous_descriptor_sha256 is not None:
        extra = ["--expected-previous-descriptor-sha256", previous_descriptor_sha256]
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
            *extra,
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


@pytest.mark.parametrize(
    "race", ["source", "marketplace", "parent", "removed_target", "foreign_stage"]
)
def test_post_link_races_hold_and_remove_only_own_descriptor(
    release: tuple[Path, Path, str, str, str],
    monkeypatch: pytest.MonkeyPatch,
    race: str,
) -> None:
    home, plugin, generation, manifest_digest, descriptor_digest = release
    namespace = runpy.run_path(str(OPERATOR), run_name="plugin_publish_test")
    link = os.link
    foreign_bytes = b""

    def raced_link(source: str, destination: str, **kwargs: object) -> None:
        nonlocal foreign_bytes
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
        elif race == "foreign_stage":
            foreign_bytes = (plugin / source).read_bytes()
            (plugin / destination).unlink()
            replacement = home.parent / "foreign-stage-after-link"
            replacement.write_bytes(foreign_bytes)
            os.replace(replacement, plugin / source)
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
    stages = list(plugin.glob(".release-binding.json.*"))
    if race == "foreign_stage":
        assert len(stages) == 1
        assert stages[0].read_bytes() == foreign_bytes
    else:
        assert not stages


@pytest.fixture
def upgrade_release(release):
    assert _run(release).returncode == 0
    home, plugin, _, _, _ = release
    target = plugin / "release-binding.json"
    previous = target.read_bytes()
    previous_info = target.stat()
    HookSessionPinStoreV1.create_at(home / ".local/state/the-hive/hook-session-pins-v1")
    generation = "b" * 40
    stage = home.parent / "upgrade-stage"
    stage.mkdir(mode=0o700)
    installer = runpy.run_path(str(INSTALLER))
    installer["_build_runtime_image"](
        repository=ROOT, stage=stage, generation=generation, commit=generation
    )
    manifest_digest = (
        "sha256:"
        + hashlib.sha256(
            (stage / ".the-hive-runtime-manifest.json").read_bytes()
        ).hexdigest()
    )
    descriptor_digest = (
        "sha256:"
        + hashlib.sha256(
            (stage / "TheHivePluginBundleV1/release-binding.json").read_bytes()
        ).hexdigest()
    )
    installer["_publish_runtime_generation"](
        stage=stage, release_root=home / ".local/lib/the-hive-runtime"
    )
    return (
        (home, plugin, generation, manifest_digest, descriptor_digest),
        previous,
        previous_info,
    )


def _upgrade_call(namespace, upgrade_release):
    release, previous, _ = upgrade_release
    home, _, generation, manifest_digest, descriptor_digest = release
    return namespace["publish"](
        home,
        generation,
        manifest_digest,
        descriptor_digest,
        expected_previous_descriptor_sha256="sha256:"
        + hashlib.sha256(previous).hexdigest(),
    )


def test_upgrade_preserves_attested_predecessor_and_receipt(upgrade_release):
    release, previous, previous_info = upgrade_release
    home, plugin, generation, manifest_digest, descriptor_digest = release
    result = _run(
        release,
        previous_descriptor_sha256="sha256:" + hashlib.sha256(previous).hexdigest(),
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)["status"] == "published"
    archives = list(plugin.glob(".release-binding.json.previous-*"))
    assert len(archives) == 1
    assert archives[0].read_bytes() == previous
    assert archives[0].stat()[:7] == previous_info[:7]
    assert not list(plugin.glob(".release-binding.json.upgrade-*"))
    receipt = json.loads(
        (
            home
            / ".local/state/codex-master-mcp/hive/plugin-release-effect-receipt-v1.json"
        ).read_bytes()
    )
    assert receipt["generation"] == generation
    assert receipt["descriptor_sha256"] == descriptor_digest
    assert (
        len(
            _verify_plugin_release_effect_receipt(
                home=home, generation=generation, manifest_digest=manifest_digest
            )
        )
        == 64
    )
    namespace = runpy.run_path(str(OPERATOR))
    assert _upgrade_call(namespace, upgrade_release)["status"] == "already_published"
    archives[0].write_bytes(b"changed archive\n")
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)


@pytest.mark.parametrize(
    "invalid",
    ["missing_pin", "wrong_pin", "previous", "generation", "manifest", "payload"],
)
def test_upgrade_requires_explicit_attested_previous(upgrade_release, invalid):
    release, previous, _ = upgrade_release
    home, plugin, generation, manifest_digest, descriptor_digest = release
    target = plugin / "release-binding.json"
    if invalid == "previous":
        pointer = home / ".local/lib/the-hive-runtime/.the-hive-release-pointers.json"
        value = json.loads(pointer.read_bytes())
        value["previous"] = None
        pointer.write_text(json.dumps(value))
    elif invalid in {"generation", "manifest"}:
        value = json.loads(previous)
        key = "generation" if invalid == "generation" else "runtime_manifest_digest"
        value[key] = "c" * 40 if invalid == "generation" else "sha256:" + "0" * 64
        target.write_text(json.dumps(value))
    elif invalid == "payload":
        target.write_bytes(previous + b" ")
    before = target.read_bytes()
    namespace = runpy.run_path(str(OPERATOR))
    keyword = {}
    if invalid != "missing_pin":
        keyword["expected_previous_descriptor_sha256"] = (
            "sha256:" + "0" * 64
            if invalid == "wrong_pin"
            else "sha256:" + hashlib.sha256(before).hexdigest()
        )
    with pytest.raises(Exception):
        namespace["publish"](
            home, generation, manifest_digest, descriptor_digest, **keyword
        )
    assert target.read_bytes() == before
    assert not list(plugin.glob(".release-binding.json.*"))


@pytest.mark.parametrize("invalid", ["symlink", "hardlink", "mode"])
def test_upgrade_preserves_unsafe_previous(upgrade_release, invalid):
    release, previous, _ = upgrade_release
    home, plugin, _, _, _ = release
    target = plugin / "release-binding.json"
    outside = home.parent / "outside-descriptor"
    if invalid == "symlink":
        outside.write_bytes(previous)
        target.unlink()
        target.symlink_to(outside)
    elif invalid == "hardlink":
        os.link(target, outside)
    else:
        target.chmod(0o600)
    namespace = runpy.run_path(str(OPERATOR))
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)
    assert target.read_bytes() == previous
    assert not list(plugin.glob(".release-binding.json.*"))


@pytest.mark.parametrize("matching", [False, True])
def test_unresolved_upgrade_holds_before_matching(upgrade_release, matching):
    release, _, _ = upgrade_release
    home, plugin, generation, _, _ = release
    if matching:
        bundle = home / ".local/lib/the-hive-runtime/generations" / generation
        (plugin / "release-binding.json").write_bytes(
            (bundle / "TheHivePluginBundleV1/release-binding.json").read_bytes()
        )
    stage = plugin / ".release-binding.json.upgrade-unresolved"
    stage.write_bytes(b"preserve\n")
    namespace = runpy.run_path(str(OPERATOR))
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)
    assert stage.read_bytes() == b"preserve\n"


@pytest.mark.parametrize(
    "race",
    ["target", "target_bytes", "crash", "source", "marketplace", "parent", "fsync"],
)
def test_upgrade_exchange_races_preserve_displaced_objects(
    upgrade_release, monkeypatch, race
):
    release, previous, _ = upgrade_release
    home, plugin, _, _, _ = release
    namespace = runpy.run_path(str(OPERATOR))
    filesystem = namespace["LocalFleetHomeV2Filesystem"]
    exchange = filesystem.exchange_at
    fsync = os.fsync
    exchanged = False

    def raced_exchange(self, parent_fd, source, target):
        nonlocal exchanged
        if race == "target":
            replacement = home.parent / "foreign-target"
            replacement.write_bytes(b"foreign\n")
            os.replace(replacement, plugin / target)
        elif race == "target_bytes":
            (plugin / target).write_bytes(b"foreign\n")
        exchange(self, parent_fd, source, target)
        exchanged = True
        if race == "crash":
            raise namespace["PublishError"]("injected_after_exchange")
        if race == "source":
            (plugin / "hooks/native_bee_event.py").write_bytes(b"foreign source\n")
        elif race == "marketplace":
            (home / ".agents/plugins/marketplace.json").write_bytes(b"{}\n")
        elif race == "parent":
            (home / "plugins").rename(home / "plugins-moved")
            (home / "plugins").symlink_to(
                home / "plugins-moved", target_is_directory=True
            )

    def fail_after_exchange(fd):
        if race == "fsync" and exchanged:
            raise OSError("injected_parent_fsync")
        return fsync(fd)

    monkeypatch.setattr(filesystem, "exchange_at", raced_exchange)
    monkeypatch.setattr(os, "fsync", fail_after_exchange)
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)
    stages = list(plugin.glob(".release-binding.json.upgrade-*"))
    assert len(stages) == 1
    expected = b"foreign\n" if race in {"target", "target_bytes"} else previous
    assert stages[0].read_bytes() == expected
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)
    assert stages[0].read_bytes() == expected


def test_upgrade_missing_expected_previous_holds(upgrade_release):
    release, _, _ = upgrade_release
    _, plugin, _, _, _ = release
    target = plugin / "release-binding.json"
    target.unlink()
    namespace = runpy.run_path(str(OPERATOR))
    with pytest.raises(namespace["PublishError"], match="plugin_descriptor_conflict"):
        _upgrade_call(namespace, upgrade_release)
    assert not target.exists()
    assert not list(plugin.glob(".release-binding.json.*"))


@pytest.mark.parametrize("stage_change", ["own", "foreign", "copy"])
def test_pre_exchange_cleanup_preserves_foreign_stage(
    upgrade_release, monkeypatch, stage_change
):
    release, previous, _ = upgrade_release
    home, plugin, generation, _, _ = release
    namespace = runpy.run_path(str(OPERATOR))
    globals_ = namespace["publish"].__globals__
    source = plugin / "hooks/native_bee_event.py"
    source_before = source.read_bytes()
    new_descriptor = (
        home
        / ".local/lib/the-hive-runtime/generations"
        / generation
        / "TheHivePluginBundleV1/release-binding.json"
    ).read_bytes()
    foreign_bytes = new_descriptor if stage_change == "copy" else b"foreign stage\n"
    fsync = os.fsync
    injected = False
    cleanup_fds = []

    def replace_before_preflight(fd):
        nonlocal injected
        fsync(fd)
        stages = list(plugin.glob(".release-binding.json.upgrade-*"))
        if not injected and stages:
            info = os.fstat(fd)
            stage_info = stages[0].stat()
            if (info.st_dev, info.st_ino) == (stage_info.st_dev, stage_info.st_ino):
                injected = True
                if stage_change != "own":
                    foreign = home.parent / "foreign-stage"
                    foreign.write_bytes(foreign_bytes)
                    os.replace(foreign, stages[0])
                source.write_bytes(b"changed source\n")

    def read_cleanup(parent_fd, name, **kwargs):
        cleanup_fds.append(parent_fd)
        return _read_regular_at(parent_fd, name, **kwargs)

    monkeypatch.setattr(os, "fsync", replace_before_preflight)
    monkeypatch.setitem(globals_, "_read_regular_at", read_cleanup)
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)
    assert injected
    stages = list(plugin.glob(".release-binding.json.upgrade-*"))
    assert len(stages) == (0 if stage_change == "own" else 1)
    if stages:
        assert stages[0].read_bytes() == foreign_bytes
    assert (plugin / "release-binding.json").read_bytes() == previous
    assert len(cleanup_fds) == 1
    with pytest.raises(OSError):
        os.fstat(cleanup_fds[0])
    source.write_bytes(source_before)
    if stages:
        with pytest.raises(Exception):
            _upgrade_call(namespace, upgrade_release)
        assert stages[0].read_bytes() == foreign_bytes
    else:
        assert _upgrade_call(namespace, upgrade_release)["status"] == "published"


@pytest.mark.parametrize("race", ["replace", "same_bytes", "collision"])
def test_upgrade_archive_race_remains_closed_on_matching(
    upgrade_release, monkeypatch, race
):
    release, previous, _ = upgrade_release
    home, plugin, _, _, _ = release
    namespace = runpy.run_path(str(OPERATOR))
    filesystem = namespace["LocalFleetHomeV2Filesystem"]
    rename = filesystem.rename_noreplace_at

    def raced_archive(self, parent_fd, source, target):
        if race != "collision":
            replacement = home.parent / "foreign-archive"
            replacement.write_bytes(
                previous if race == "same_bytes" else b"foreign archive\n"
            )
            os.replace(replacement, plugin / source)
        else:
            (plugin / target).write_bytes(b"foreign archive\n")
        return rename(self, parent_fd, source, target)

    monkeypatch.setattr(filesystem, "rename_noreplace_at", raced_archive)
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)
    archives = list(plugin.glob(".release-binding.json.previous-*"))
    assert len(archives) == 1
    expected = previous if race == "same_bytes" else b"foreign archive\n"
    assert archives[0].read_bytes() == expected
    with pytest.raises(Exception):
        _upgrade_call(namespace, upgrade_release)
    assert archives[0].read_bytes() == expected


def test_upgrade_receipt_failure_retries_only_after_verified_archive(
    upgrade_release, monkeypatch
):
    release, previous, _ = upgrade_release
    _, plugin, _, _, descriptor_digest = release
    namespace = runpy.run_path(str(OPERATOR))
    globals_ = namespace["publish"].__globals__
    write_receipt = globals_["_write_effect_receipt"]

    def fail_receipt(**_kwargs):
        raise namespace["PublishError"]("injected_upgrade_receipt")

    monkeypatch.setitem(globals_, "_write_effect_receipt", fail_receipt)
    with pytest.raises(namespace["PublishError"], match="injected_upgrade_receipt"):
        _upgrade_call(namespace, upgrade_release)
    assert (
        "sha256:"
        + hashlib.sha256((plugin / "release-binding.json").read_bytes()).hexdigest()
        == descriptor_digest
    )
    archives = list(plugin.glob(".release-binding.json.previous-*"))
    assert len(archives) == 1 and archives[0].read_bytes() == previous
    monkeypatch.setitem(globals_, "_write_effect_receipt", write_receipt)
    assert _upgrade_call(namespace, upgrade_release)["status"] == "already_published"
