from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import pickle
import runpy
import weakref

import pytest


def _runtime_layout_module():
    try:
        return importlib.import_module("the_hive.runtime_layout")
    except ModuleNotFoundError:
        return None


def _write_file(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def materialize_runtime_image(
    tmp_path: Path, *, before_manifest: Callable[[Path], None] | None = None
) -> Path:
    root = tmp_path / "the-hive-runtime"
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    _write_file(root / "bin" / "the-hive-mcp", "#!/bin/sh\nexit 0\n", 0o755)
    _write_file(root / "bin" / "the-hive-mcp-stable", "#!/bin/sh\nexit 0\n", 0o755)
    _write_file(
        root / "bin" / "the-hive-plugin-hook-stable", "#!/bin/sh\nexit 0\n", 0o755
    )
    _write_file(
        root / "bin" / "the-hive-hive-hourly-probe",
        "#!/bin/sh\nexit 0\n",
        0o755,
    )
    _write_file(
        root / "bin" / "the-hive-resource-monitor", "#!/bin/sh\nexit 0\n", 0o755
    )
    _write_file(
        root / "systemd" / "user" / "the-hive-resource-monitor.service", "[Service]\n"
    )
    _write_file(root / "systemd" / "user" / "the-hive.slice", "[Slice]\n")
    _write_file(
        root / ".codex-plugin" / "plugin.json",
        json.dumps(
            {
                "name": "the-hive",
                "version": "0.10.5",
                "skills": "./skills/",
                "mcpServers": "./.mcp.json",
                "apps": "./.app.json",
                "hooks": "./hooks/hooks.json",
            }
        ),
    )
    _write_file(
        root / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "the-hive-mcp": {
                        "command": (
                            "/home/teladi/.local/lib/the-hive-runtime/the-hive-mcp"
                        ),
                        "args": [],
                        "startup_timeout_sec": 120,
                        "note": (
                            "Local data-sparse Codex Masterjet MCP server. "
                            "Controls the sleeping Agentinnen pool through tmux "
                            "and does not return raw terminal output by default."
                        ),
                    }
                }
            }
        ),
    )
    _write_file(
        root / ".app.json", json.dumps({"apps": {"the-hive": {"id": "connector"}}})
    )
    _write_file(root / "hooks" / "hooks.json", json.dumps({"hooks": {}}))
    _write_file(root / "hooks" / "native_bee_event.py", "# hook\n")
    _write_file(root / "hooks" / "native_spawn_admission.py", "# hook\n")
    _write_file(
        root / "skills" / "the-hive-fleet" / "SKILL.md",
        "---\nname: the-hive-fleet\n---\n",
    )
    _write_file(
        root / "codex-hive.json", json.dumps({"schema_version": 1, "mode": "shadow"})
    )
    _write_file(
        root / "codex-agent-classes.json",
        json.dumps({"schema_version": 1, "classes": []}),
    )
    _write_file(
        root / "src" / "the_hive" / "_runtime_spawn_helper.so", "test helper", 0o755
    )
    _write_file(root / "src" / "the_hive" / "hive" / "cli.py", "# image module\n")
    for relative in (
        "admission.py",
        "admission_runtime.py",
        "dynamic_pool.py",
        "hive/__init__.py",
        "hive/admission.py",
        "hive/dispatch.py",
        "hive/principals.py",
        "selection.py",
        "selection_service.py",
        "hook_abi_v1_core.py",
        "server.py",
        "hook_session_pin_store.py",
    ):
        _write_file(
            root / "src" / "the_hive" / relative,
            (
                Path(__file__).resolve().parents[1] / "src" / "the_hive" / relative
            ).read_text(encoding="utf-8"),
        )
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
    installer = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "the-hive-hive-hourly-probe-install"
        )
    )
    if before_manifest is not None:
        before_manifest(root)
    installer["_write_runtime_image_manifest"](root=root, commit="a" * 40)
    return root


def test_runtime_layout_is_immutable_and_derived_only_from_a_valid_image(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    layout = module.RuntimeLayout.from_runtime_root(root)

    assert layout.root == root
    assert layout.mcp_entrypoint == root / "bin" / "the-hive-mcp"
    assert layout.probe_entrypoint == root / "bin" / "the-hive-hive-hourly-probe"
    assert layout.metadata_root == root
    assert layout.spawn_helper == root / "src" / "the_hive" / "_runtime_spawn_helper.so"
    assert len(layout.spawn_helper_digest) == 64
    assert layout.manifest_digest.startswith("sha256:")
    with pytest.raises(FrozenInstanceError):
        layout.root = root.parent  # type: ignore[misc]


def test_runtime_layout_same_run_attestation_carries_one_manifest_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second manifest read or rebuilding the layout would break this proof."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest_path = root / ".the-hive-runtime-manifest.json"
    original_read = module._read_regular_bytes
    manifest_reads: list[bytes] = []

    def record_manifest_read(
        read_root: Path, relative_path: str, *, max_bytes: int
    ) -> bytes:
        raw = original_read(read_root, relative_path, max_bytes=max_bytes)
        if relative_path == ".the-hive-runtime-manifest.json":
            manifest_reads.append(raw)
        return raw

    monkeypatch.setattr(module, "_read_regular_bytes", record_manifest_read)
    attestation = module._attest_runtime_root(root)

    manifest = json.loads(manifest_path.read_bytes())
    assert len(manifest_reads) == 1
    assert attestation.manifest_bytes is manifest_reads[0]
    assert attestation.manifest_bytes == manifest_path.read_bytes()
    assert attestation.manifest_digest == (
        "sha256:" + hashlib.sha256(attestation.manifest_bytes).hexdigest()
    )
    assert attestation.layout.manifest_digest == attestation.manifest_digest
    assert attestation.commit == manifest["commit"]
    assert attestation.generation == manifest["generation"]
    assert attestation.target is root
    assert attestation.target == attestation.layout.root
    assert attestation.layout.root == root


def test_runtime_layout_public_factory_returns_the_same_run_attested_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Returning a reconstructed layout instead of the carrier's is a contract break."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    attest = module._attest_runtime_root
    attested: list[object] = []

    class DerivedRuntimeLayout(module.RuntimeLayout):
        pass

    def record_attestation(target: Path, **_kwargs: object) -> object:
        value = attest(target, **_kwargs)
        attested.append(value)
        return value

    monkeypatch.setattr(module, "_attest_runtime_root", record_attestation)

    layout = DerivedRuntimeLayout.from_runtime_root(root)

    assert len(attested) == 1
    carried = module._RuntimeLayoutAttestation.layout.__get__(
        attested[0], module._RuntimeLayoutAttestation
    )
    assert layout is carried
    assert type(layout) is DerivedRuntimeLayout


def test_runtime_layout_final_validator_uses_raw_bytes_not_a_mutable_manifest_map(
    tmp_path: Path,
) -> None:
    """Mutating a caller-held decoded map cannot replace final byte authority."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)
    manifest_bytes = (root / ".the-hive-runtime-manifest.json").read_bytes()
    caller_map = json.loads(manifest_bytes)
    caller_map["commit"] = "0" * 40

    module._final_runtime_layout_validation(
        manifest_bytes,
        target=Path(str(root)),
        mcp_entrypoint=Path(str(layout.mcp_entrypoint)),
        probe_entrypoint=Path(str(layout.probe_entrypoint)),
        metadata_root=Path(str(layout.metadata_root)),
        spawn_helper=Path(str(layout.spawn_helper)),
        path_bindings_match=True,
        spawn_helper_digest=layout.spawn_helper_digest,
        target_device=layout.root_device,
        target_inode=layout.root_inode,
        observed_target_device=layout.root_device,
        observed_target_inode=layout.root_inode,
        manifest_digest=layout.manifest_digest,
        commit=json.loads(manifest_bytes)["commit"],
        generation=json.loads(manifest_bytes)["generation"],
    )


def test_runtime_layout_manifest_bytes_parser_derives_local_facts(
    tmp_path: Path,
) -> None:
    """The final parser derives digest and metadata from raw bytes, not a map."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest_bytes = (root / ".the-hive-runtime-manifest.json").read_bytes()

    manifest, digest, metadata, spawn_digest = module._manifest_data_from_bytes(
        manifest_bytes
    )

    assert digest == "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    assert metadata["commit"] == manifest["commit"]
    assert metadata["generation"] == manifest["generation"]
    assert spawn_digest == manifest["files"]["src/the_hive/_runtime_spawn_helper.so"][
        "sha256"
    ]


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("manifest_digest", "sha256:" + "0" * 64),
        ("commit", "0" * 40),
        ("generation", "different-generation"),
        ("path_bindings_match", False),
    ),
)
def test_runtime_layout_final_validator_rejects_local_binding_drift(
    tmp_path: Path, field: str, replacement: object
) -> None:
    """Digest, commit, generation, and target-path facts remain byte-bound."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)
    manifest_bytes = (root / ".the-hive-runtime-manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    arguments: dict[str, object] = {
        "target": Path(str(root)),
        "mcp_entrypoint": Path(str(layout.mcp_entrypoint)),
        "probe_entrypoint": Path(str(layout.probe_entrypoint)),
        "metadata_root": Path(str(layout.metadata_root)),
        "spawn_helper": Path(str(layout.spawn_helper)),
        "path_bindings_match": True,
        "spawn_helper_digest": layout.spawn_helper_digest,
        "target_device": layout.root_device,
        "target_inode": layout.root_inode,
        "observed_target_device": layout.root_device,
        "observed_target_inode": layout.root_inode,
        "manifest_digest": layout.manifest_digest,
        "commit": manifest["commit"],
        "generation": manifest["generation"],
    }
    arguments[field] = replacement

    with pytest.raises(module.LayoutError, match="runtime_layout_invalid"):
        module._final_runtime_layout_validation(manifest_bytes, **arguments)


def test_runtime_layout_final_validator_does_not_run_a_path_hook(
    tmp_path: Path,
) -> None:
    """The pure final validator receives normalized paths and never stats them."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)
    manifest_bytes = (root / ".the-hive-runtime-manifest.json").read_bytes()

    class HookedPath(type(root)):
        def lstat(self) -> os.stat_result:
            raise AssertionError("post-final path hook")

        def __truediv__(self, other: object) -> Path:
            del other
            raise AssertionError("post-final path join")

    hooked = HookedPath(str(root))
    module._final_runtime_layout_validation(
        manifest_bytes,
        target=hooked,
        mcp_entrypoint=Path(str(layout.mcp_entrypoint)),
        probe_entrypoint=Path(str(layout.probe_entrypoint)),
        metadata_root=Path(str(layout.metadata_root)),
        spawn_helper=Path(str(layout.spawn_helper)),
        path_bindings_match=True,
        spawn_helper_digest=layout.spawn_helper_digest,
        target_device=layout.root_device,
        target_inode=layout.root_inode,
        observed_target_device=layout.root_device,
        observed_target_inode=layout.root_inode,
        manifest_digest=layout.manifest_digest,
        commit=json.loads(manifest_bytes)["commit"],
        generation=json.loads(manifest_bytes)["generation"],
    )


def test_runtime_layout_validates_an_attested_manifest_payload_directly(
    tmp_path: Path,
) -> None:
    """The payload validator must return release metadata from a valid image."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest, digest = module._validated_manifest(root)

    metadata = module._validate_attested_manifest_payload(root, manifest, digest)

    assert metadata["commit"] == manifest["commit"]
    assert metadata["generation"] == manifest["generation"]


def test_runtime_layout_validates_manifest_bytes_directly(tmp_path: Path) -> None:
    """The byte validator must preserve the one supplied manifest payload."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    raw = (root / ".the-hive-runtime-manifest.json").read_bytes()

    manifest, digest = module._validated_manifest_from_bytes(root, raw)

    assert digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert manifest["generation"] == json.loads(raw)["generation"]


def test_runtime_layout_reads_validated_manifest_bytes_directly(tmp_path: Path) -> None:
    """The manifest-byte reader returns the exact successfully checked bytes."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    manifest, digest, raw = module._validated_manifest_bytes(root)

    assert raw == (root / ".the-hive-runtime-manifest.json").read_bytes()
    assert digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert manifest["commit"] == "a" * 40


def test_runtime_layout_reads_base_slots_directly(tmp_path: Path) -> None:
    """Slot extraction must retain the factory layout's canonical values."""

    module = _runtime_layout_module()
    assert module is not None
    layout = module.RuntimeLayout.from_runtime_root(materialize_runtime_image(tmp_path))

    values = module._runtime_layout_slot_values(layout)

    assert values == (
        layout.root,
        layout.mcp_entrypoint,
        layout.probe_entrypoint,
        layout.metadata_root,
        layout.spawn_helper,
        layout.spawn_helper_digest,
        layout.root_device,
        layout.root_inode,
        layout.manifest_digest,
    )


def test_runtime_layout_normalizes_hookable_digest_subclasses_before_final(
    tmp_path: Path,
) -> None:
    """Digest subclasses must become local built-in strings before final checks."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    canonical = module.RuntimeLayout.from_runtime_root(root)

    class HookedDigest(str):
        hook_calls = 0

        def __str__(self) -> str:
            type(self).hook_calls += 1
            return super().__str__()

    layout = module.RuntimeLayout(
        root=canonical.root,
        mcp_entrypoint=canonical.mcp_entrypoint,
        probe_entrypoint=canonical.probe_entrypoint,
        metadata_root=canonical.metadata_root,
        spawn_helper=canonical.spawn_helper,
        spawn_helper_digest=HookedDigest(canonical.spawn_helper_digest),
        root_device=canonical.root_device,
        root_inode=canonical.root_inode,
        manifest_digest=HookedDigest(canonical.manifest_digest),
    )

    values = module._normalized_runtime_layout_values(layout)

    assert HookedDigest.hook_calls == 2
    assert type(values[5]) is str
    assert type(values[8]) is str
    manifest_bytes = (root / ".the-hive-runtime-manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    module._final_runtime_layout_validation(
        manifest_bytes,
        target=values[0],
        mcp_entrypoint=values[1],
        probe_entrypoint=values[2],
        metadata_root=values[3],
        spawn_helper=values[4],
        path_bindings_match=True,
        spawn_helper_digest=values[5],
        target_device=values[6],
        target_inode=values[7],
        observed_target_device=values[6],
        observed_target_inode=values[7],
        manifest_digest=values[8],
        commit=manifest["commit"],
        generation=manifest["generation"],
    )


def test_runtime_layout_final_validator_rejects_digest_subclasses(
    tmp_path: Path,
) -> None:
    """A hookable digest subclass is not an accepted final primitive value."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)
    manifest_bytes = (root / ".the-hive-runtime-manifest.json").read_bytes()

    class HookedDigest(str):
        def __eq__(self, other: object) -> bool:
            del other
            raise AssertionError("post-final digest equality hook")

    with pytest.raises(module.LayoutError, match="runtime_layout_invalid"):
        module._final_runtime_layout_validation(
            manifest_bytes,
            target=Path(str(root)),
            mcp_entrypoint=Path(str(layout.mcp_entrypoint)),
            probe_entrypoint=Path(str(layout.probe_entrypoint)),
            metadata_root=Path(str(layout.metadata_root)),
            spawn_helper=Path(str(layout.spawn_helper)),
            path_bindings_match=True,
            spawn_helper_digest=HookedDigest(layout.spawn_helper_digest),
            target_device=layout.root_device,
            target_inode=layout.root_inode,
            observed_target_device=layout.root_device,
            observed_target_inode=layout.root_inode,
            manifest_digest=HookedDigest(layout.manifest_digest),
            commit=json.loads(manifest_bytes)["commit"],
            generation=json.loads(manifest_bytes)["generation"],
        )


def test_runtime_layout_validates_local_manifest_bytes_without_a_second_read(
    tmp_path: Path,
) -> None:
    """The manifest-bytes path validates local bytes and returns final root facts."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)
    manifest_bytes = (root / ".the-hive-runtime-manifest.json").read_bytes()

    observed = module._validate_layout_values(
        layout.root,
        layout.mcp_entrypoint,
        layout.probe_entrypoint,
        layout.metadata_root,
        layout.spawn_helper,
        layout.spawn_helper_digest,
        layout.root_device,
        layout.root_inode,
        layout.manifest_digest,
        manifest_bytes=manifest_bytes,
    )

    assert observed == (layout.root_device, layout.root_inode)


def test_runtime_layout_subclass_preserves_public_factory_semantics(
    tmp_path: Path,
) -> None:
    """Rejecting a valid subclass would change public factory semantics."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    class DerivedRuntimeLayout(module.RuntimeLayout):
        def __post_init__(self) -> None:
            super().__post_init__()
            object.__setattr__(self, "public_factory_init", True)

    layout = DerivedRuntimeLayout.from_runtime_root(root)

    assert type(layout) is DerivedRuntimeLayout
    assert layout.public_factory_init is True
    assert layout.root == root


def test_runtime_layout_does_not_add_a_public_weakref_slot(tmp_path: Path) -> None:
    """A weakref slot would be a new public RuntimeLayout surface."""

    module = _runtime_layout_module()
    assert module is not None
    layout = module.RuntimeLayout.from_runtime_root(materialize_runtime_image(tmp_path))

    with pytest.raises(TypeError):
        weakref.ref(layout)


def test_runtime_layout_subclass_cannot_replace_the_local_manifest_authority(
    tmp_path: Path,
) -> None:
    """Subclass code must not turn ContextVar data into manifest authority."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    payload = root / "bin" / "the-hive-mcp"

    class ContextReplacingRuntimeLayout(module.RuntimeLayout):
        def __post_init__(self) -> None:
            super().__post_init__()
            payload.write_bytes(b"#!/bin/sh\nexit 1\n")
            payload.chmod(0o755)
            context_value = module._RUNTIME_LAYOUT_VALIDATION.get()
            if isinstance(context_value, dict):
                files = context_value["files"]
                assert isinstance(files, dict)
                entry = files["bin/the-hive-mcp"]
                assert isinstance(entry, dict)
                entry["size"] = len(payload.read_bytes())
                entry["sha256"] = hashlib.sha256(payload.read_bytes()).hexdigest()
            else:
                module._RUNTIME_LAYOUT_VALIDATION.set(b"replacement")

    with pytest.raises(module.LayoutError, match="runtime_layout_invalid"):
        ContextReplacingRuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rechecks_payload_swapped_after_first_layout_check(
    tmp_path: Path,
) -> None:
    """A payload swap after a successful subclass layout check must fail closed."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    payload = root / "src" / "the_hive" / "dynamic_pool.py"

    class PayloadSwappingRuntimeLayout(module.RuntimeLayout):
        def __post_init__(self) -> None:
            super().__post_init__()
            payload.write_bytes(b"swapped after the first layout check\n")
            payload.chmod(0o644)

    with pytest.raises(module.LayoutError, match="runtime_layout_invalid"):
        PayloadSwappingRuntimeLayout.from_runtime_root(root)


def test_runtime_layout_finishes_layout_hook_access_before_final_validation(
    tmp_path: Path,
) -> None:
    """Carrier construction must not make dynamic layout accesses after slots copy."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    payload = root / "bin" / "the-hive-mcp"

    class CarrierAccessSwappingRuntimeLayout(module.RuntimeLayout):
        def __getattribute__(self, name: str) -> object:
            caller = inspect.currentframe()
            caller = caller.f_back if caller is not None else None
            try:
                if (
                    name == "root"
                    and caller is not None
                    and isinstance(
                        caller.f_locals.get("self"),
                        module._RuntimeLayoutAttestation,
                    )
                ):
                    payload.write_bytes(b"#!/bin/sh\nexit 1\n")
                    payload.chmod(0o755)
            finally:
                del caller
            return super().__getattribute__(name)

    layout = CarrierAccessSwappingRuntimeLayout.from_runtime_root(root)

    assert layout.root == root
    assert payload.read_bytes() == b"#!/bin/sh\nexit 0\n"


def test_runtime_layout_same_run_attestation_preserves_manifest_size_bound(
    tmp_path: Path,
) -> None:
    """Holding bytes in RAM must not weaken the established metadata bound."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest = root / ".the-hive-runtime-manifest.json"
    manifest.write_bytes(b"x" * (module._MAX_METADATA_BYTES + 1))
    manifest.chmod(0o644)

    with pytest.raises(module.LayoutError, match="runtime_layout_invalid"):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_same_run_attestation_rechecks_swapped_payload_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A payload swap after the first manifest check must fail before output."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    payload = root / "src" / "the_hive" / "dynamic_pool.py"
    validate_layout_values = module._validate_layout_values

    def swap_then_validate(*args: object, **kwargs: object) -> None:
        payload.write_bytes(b"swapped after the first manifest check\n")
        payload.chmod(0o644)
        validate_layout_values(*args, **kwargs)

    monkeypatch.setattr(module, "_validate_layout_values", swap_then_validate)

    with pytest.raises(module.LayoutError, match="runtime_layout_invalid"):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_same_run_attestation_remains_frozen_ram_only_after_swap(
    tmp_path: Path,
) -> None:
    """A mutable carrier could be replaced after its target is attested."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    attestation = module._attest_runtime_root(root)
    layout = attestation.layout
    manifest_bytes = attestation.manifest_bytes
    manifest_path = root / ".the-hive-runtime-manifest.json"

    manifest_path.write_bytes(b"{}")

    assert attestation.layout is layout
    assert attestation.manifest_bytes is manifest_bytes
    assert attestation.manifest_bytes == manifest_bytes
    with pytest.raises(FrozenInstanceError):
        attestation.manifest_bytes = b"replacement"  # type: ignore[misc]
    with pytest.raises(TypeError):
        attestation.manifest_bytes[0] = 0  # type: ignore[index]
    with pytest.raises(TypeError):
        pickle.dumps(attestation)

@pytest.mark.parametrize("breakage", ("untrusted_root", "missing", "malformed"))
def test_runtime_layout_same_run_attestation_rejects_invalid_target(
    tmp_path: Path, breakage: str
) -> None:
    """An attestation must fail at its target rather than take a fallback path."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest_path = root / ".the-hive-runtime-manifest.json"
    if breakage == "untrusted_root":
        root.chmod(0o755)
    elif breakage == "missing":
        manifest_path.unlink()
    else:
        manifest_path.write_bytes(b"{")

    with pytest.raises(module.LayoutError, match="runtime_layout_invalid"):
        module._attest_runtime_root(root)


def test_runtime_layout_same_run_attestation_never_uses_release_or_module_fallbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any stage, pointer, or resolver fallback is outside direct target attestation."""

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    def unexpected_fallback(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unexpected release or module fallback")

    monkeypatch.setattr(
        module.RuntimeLayout, "from_current_release", unexpected_fallback
    )
    monkeypatch.setattr(
        module.RuntimeLayout, "from_previous_release", unexpected_fallback
    )
    monkeypatch.setattr(module.RuntimeLayout, "from_module_path", unexpected_fallback)
    monkeypatch.setattr(
        module.RuntimeLayout, "_from_release_pointer", unexpected_fallback
    )

    assert module._attest_runtime_root(root).layout.root == root


def test_runtime_layout_rejects_relative_and_nonprivate_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)

    monkeypatch.chdir(tmp_path)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(Path(root.name))
    root.chmod(0o755)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_an_image_reached_through_a_linked_parent(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path / "actual")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path / "actual", target_is_directory=True)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(linked_parent / root.name)


@pytest.mark.parametrize(
    "relative_path",
    (
        "bin/the-hive-mcp",
        "bin/the-hive-plugin-hook-stable",
        "bin/the-hive-hive-hourly-probe",
        ".codex-plugin/plugin.json",
        ".mcp.json",
        ".app.json",
        "hooks/hooks.json",
        "hooks/native_bee_event.py",
        "hooks/native_spawn_admission.py",
        "TheHivePluginBundleV1/release-binding.json",
        "root-install-plan.json",
        "skills/the-hive-fleet/SKILL.md",
        "codex-hive.json",
        "codex-agent-classes.json",
        "src/the_hive/_runtime_spawn_helper.so",
        ".the-hive-runtime-manifest.json",
    ),
)
def test_runtime_layout_rejects_missing_required_image_members(
    tmp_path: Path, relative_path: str
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    (root / relative_path).unlink()

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_linked_and_outside_entrypoints(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    entrypoint = root / "bin" / "the-hive-mcp"
    target = tmp_path / "outside-mcp"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    entrypoint.unlink()
    entrypoint.symlink_to(target)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)

    restored = materialize_runtime_image(tmp_path / "another")
    valid_layout = module.RuntimeLayout.from_runtime_root(restored)
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout(
            root=restored,
            mcp_entrypoint=target,
            probe_entrypoint=restored / "bin" / "the-hive-hive-hourly-probe",
            metadata_root=restored,
            spawn_helper=restored / "src" / "the_hive" / "_runtime_spawn_helper.so",
            spawn_helper_digest="0" * 64,
            root_device=valid_layout.root_device,
            root_inode=valid_layout.root_inode,
            manifest_digest=valid_layout.manifest_digest,
        )


def test_runtime_layout_rejects_a_helper_or_manifest_digest_deviation(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    helper = root / "src" / "the_hive" / "_runtime_spawn_helper.so"
    helper.write_bytes(b"swapped helper")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_witness_file_drift_after_valid_manifest(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)
    witness = root / "src" / "the_hive" / "dynamic_pool.py"
    witness.write_bytes(witness.read_bytes() + b"\n# drift after manifest\n")
    witness.chmod(0o644)

    with pytest.raises(module.LayoutError):
        module.validate_runtime_metadata(layout)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        (("successor_witness", "sha256"), "0" * 64),
        (("historical_lineage", "d73", "parent"), "0" * 40),
    ),
)
def test_runtime_layout_rejects_a_deviating_d89_successor_binding(
    tmp_path: Path, field: tuple[str, ...], replacement: str
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest_path = root / ".the-hive-runtime-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target = manifest
    for part in field[:-1]:
        target = target[part]
    target[field[-1]] = replacement
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_a_replaced_generation_or_manifest_digest(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout(
            root=layout.root,
            mcp_entrypoint=layout.mcp_entrypoint,
            probe_entrypoint=layout.probe_entrypoint,
            metadata_root=layout.metadata_root,
            spawn_helper=layout.spawn_helper,
            spawn_helper_digest=layout.spawn_helper_digest,
            root_device=layout.root_device,
            root_inode=layout.root_inode,
            manifest_digest="sha256:" + "0" * 64,
        )

    root.rename(tmp_path / "retired-generation")
    materialize_runtime_image(tmp_path)
    with pytest.raises(module.LayoutError):
        module.validate_runtime_metadata(layout)

    root = materialize_runtime_image(tmp_path / "manifest")
    manifest = root / ".the-hive-runtime-manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_a_release_binding_not_exactly_attested_by_manifest(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    descriptor = root / "TheHivePluginBundleV1" / "release-binding.json"
    binding = json.loads(descriptor.read_text(encoding="utf-8"))
    binding["hooks"]["native_bee_event"] = "sha256:" + "0" * 64
    descriptor.write_text(json.dumps(binding), encoding="utf-8")
    descriptor.chmod(0o644)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_a_root_install_plan_not_bound_to_abi_source_bytes(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    plan_path = root / "root-install-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["companion"]["sha256"] = "sha256:" + "0" * 64
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    plan_path.chmod(0o644)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def _dispatch_allowlist_inputs(
    tmp_path: Path,
) -> tuple[object, dict[str, object], str, bytes, bytes]:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    manifest, manifest_digest = module._validated_manifest(root)
    descriptor = (
        root / "TheHivePluginBundleV1" / "release-binding.json"
    ).read_bytes()
    root_install_plan = (root / "root-install-plan.json").read_bytes()
    return module, manifest, manifest_digest, descriptor, root_install_plan


def test_dispatch_allowlist_codec_is_canonical_and_has_the_exact_fieldset(
    tmp_path: Path,
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )

    encoded = module.dispatch_allowlist_bytes(manifest, manifest_digest)
    decoded = json.loads(encoded)

    assert encoded == (
        json.dumps(decoded, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    assert set(decoded) == {
        "schema",
        "plugin_id",
        "generation",
        "runtime_manifest_digest",
        "launcher_abi",
        "descriptor_sha256",
        "root_install_plan_sha256",
        "hooks",
    }
    assert decoded["schema"] == "D320DispatchAllowlistV1"
    assert decoded["plugin_id"] == "the-hive"
    assert decoded["runtime_manifest_digest"] == manifest_digest
    assert decoded["launcher_abi"] == (
        "/usr/local/libexec/the-hive/hook-abi/v1/launcher"
    )
    assert set(decoded["hooks"]) == {
        "native_bee_event",
        "native_spawn_admission",
    }
    module._validate_dispatch_allowlist(
        encoded, manifest, manifest_digest, descriptor, root_install_plan
    )


@pytest.mark.parametrize(
    "value",
    (
        "0" * 64,
        "sha256:" + "A" * 64,
        "sha256:" + "0" * 63,
        "sha512:" + "0" * 64,
    ),
)
def test_dispatch_allowlist_rejects_noncanonical_sha256_grammar(value: str) -> None:
    module = _runtime_layout_module()
    assert module is not None

    assert not module._is_sha256_digest(value)
    assert module._is_sha256_digest("sha256:" + "0" * 64)


@pytest.mark.parametrize("mutation", ("duplicate", "unknown", "missing"))
def test_dispatch_allowlist_rejects_duplicate_unknown_and_missing_fields(
    tmp_path: Path, mutation: str
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )
    encoded = module.dispatch_allowlist_bytes(manifest, manifest_digest)
    if mutation == "duplicate":
        candidate = (
            encoded.rstrip(b"\n")[:-1]
            + b',"schema":"D320DispatchAllowlistV1"}\n'
        )
    else:
        decoded = json.loads(encoded)
        if mutation == "unknown":
            decoded["unexpected"] = "value"
        else:
            del decoded["descriptor_sha256"]
        candidate = (
            json.dumps(
                decoded, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode("ascii")

    with pytest.raises(module.LayoutError):
        module._validate_dispatch_allowlist(
            candidate, manifest, manifest_digest, descriptor, root_install_plan
        )


def test_dispatch_allowlist_rejects_malformed_json_as_layout_error(
    tmp_path: Path,
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )

    with pytest.raises(module.LayoutError, match="^runtime_layout_invalid$"):
        module._validate_dispatch_allowlist(
            b'{"schema":',
            manifest,
            manifest_digest,
            descriptor,
            root_install_plan,
        )


def test_dispatch_allowlist_translates_json_recursion_error_to_layout_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )

    def raise_recursion_error(*args: object, **kwargs: object) -> object:
        raise RecursionError

    monkeypatch.setattr(module.json, "loads", raise_recursion_error)

    with pytest.raises(module.LayoutError, match="^runtime_layout_invalid$"):
        module._validate_dispatch_allowlist(
            b"{}", manifest, manifest_digest, descriptor, root_install_plan
        )


def test_dispatch_allowlist_rejects_deeply_nested_json_as_layout_error(
    tmp_path: Path,
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )
    candidate = b'{"schema":' + b"[" * 2048 + b"0" + b"]" * 2048 + b"}"
    assert len(candidate) <= module._MAX_METADATA_BYTES

    with pytest.raises(module.LayoutError, match="^runtime_layout_invalid$"):
        module._validate_dispatch_allowlist(
            candidate, manifest, manifest_digest, descriptor, root_install_plan
        )


@pytest.mark.parametrize(
    "field",
    ("runtime_manifest_digest", "descriptor_sha256", "root_install_plan_sha256"),
)
def test_dispatch_allowlist_rejects_invalid_top_level_digest_grammar(
    tmp_path: Path, field: str
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )
    decoded = json.loads(module.dispatch_allowlist_bytes(manifest, manifest_digest))
    decoded[field] = "sha256:" + "A" * 64
    candidate = (
        json.dumps(decoded, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")

    with pytest.raises(module.LayoutError):
        module._validate_dispatch_allowlist(
            candidate, manifest, manifest_digest, descriptor, root_install_plan
        )


@pytest.mark.parametrize(
    "mutation",
    ("plugin", "launcher", "hookset", "hook_digest"),
)
def test_dispatch_allowlist_rejects_constant_and_hookset_mismatches(
    tmp_path: Path, mutation: str
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )
    decoded = json.loads(module.dispatch_allowlist_bytes(manifest, manifest_digest))
    if mutation == "plugin":
        decoded["plugin_id"] = "the-hive@personal"
    elif mutation == "launcher":
        decoded["launcher_abi"] = "/tmp/launcher"
    elif mutation == "hookset":
        decoded["hooks"] = {"native_bee_event": decoded["hooks"]["native_bee_event"]}
    else:
        decoded["hooks"]["native_bee_event"] = "sha256:" + "0" * 64
    candidate = (
        json.dumps(decoded, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")

    with pytest.raises(module.LayoutError):
        module._validate_dispatch_allowlist(
            candidate, manifest, manifest_digest, descriptor, root_install_plan
        )


@pytest.mark.parametrize("mismatch", ("descriptor", "manifest", "plan", "hook"))
def test_dispatch_allowlist_rejects_descriptor_manifest_plan_and_hook_mismatches(
    tmp_path: Path, mismatch: str
) -> None:
    module, manifest, manifest_digest, descriptor, root_install_plan = (
        _dispatch_allowlist_inputs(tmp_path)
    )
    encoded = module.dispatch_allowlist_bytes(manifest, manifest_digest)
    if mismatch == "descriptor":
        descriptor = descriptor + b" "
    elif mismatch == "manifest":
        manifest_digest = "sha256:" + "0" * 64
    elif mismatch == "plan":
        root_install_plan = root_install_plan + b" "
    else:
        changed_descriptor = json.loads(descriptor)
        changed_descriptor["hooks"]["native_bee_event"] = "sha256:" + "0" * 64
        descriptor = (
            json.dumps(
                changed_descriptor,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")

    with pytest.raises(module.LayoutError):
        module._validate_dispatch_allowlist(
            encoded, manifest, manifest_digest, descriptor, root_install_plan
        )


def test_runtime_image_repository_root_is_not_public_or_registry_compatible(
    tmp_path: Path,
) -> None:
    from the_hive.hive.repositories import (
        RepositoryBinding,
        RepositoryError,
        RepositoryRegistry,
    )

    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    layout = module.RuntimeLayout.from_runtime_root(root)

    assert "RuntimeImageRepositoryRoot" not in module.__all__
    assert not hasattr(module, "RuntimeImageRepositoryRoot")
    with pytest.raises(ImportError):
        exec("from the_hive.runtime_layout import RuntimeImageRepositoryRoot", {})
    with pytest.raises(AttributeError):
        module.RuntimeImageRepositoryRoot(layout)  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        getattr(layout, "repository_root")
    with pytest.raises(RepositoryError, match="invalid_repository_root"):
        RepositoryBinding(
            "runtime-image",
            "https://github.com/example/runtime-image.git",
            layout,
            "main",
            RepositoryRegistry.config_digest(b"runtime-image-binding"),
        )


def test_runtime_layout_rejects_a_nonprivate_image_subdirectory(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    (root / "bin").chmod(0o755)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_escaping_metadata_references(tmp_path: Path) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    plugin = root / ".codex-plugin" / "plugin.json"
    plugin.write_text(
        json.dumps(
            {
                "name": "the-hive",
                "version": "0.10.5",
                "skills": "./skills/",
                "mcpServers": "../.mcp.json",
                "apps": "./.app.json",
                "hooks": "./hooks/hooks.json",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


@pytest.mark.parametrize("legacy_binding", ("plugin_name", "app_key", "skill_path"))
def test_runtime_layout_rejects_legacy_plugin_skill_metadata_bindings(
    tmp_path: Path, legacy_binding: str
) -> None:
    module = _runtime_layout_module()
    assert module is not None

    def add_legacy_binding(root: Path) -> None:
        if legacy_binding == "plugin_name":
            plugin_path = root / ".codex-plugin" / "plugin.json"
            plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
            plugin["name"] = "codex-master"
            plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
        elif legacy_binding == "app_key":
            app_path = root / ".app.json"
            app_path.write_text(
                json.dumps({"apps": {"codex-master": {"id": "connector"}}}),
                encoding="utf-8",
            )
        else:
            target = root / "skills" / "the-hive-fleet"
            target.rename(root / "skills" / "codex-master-fleet")

    if legacy_binding == "skill_path":
        root = materialize_runtime_image(tmp_path)
        (root / "skills" / "the-hive-fleet").rename(
            root / "skills" / "codex-master-fleet"
        )
        with pytest.raises(module.LayoutError):
            module.RuntimeLayout.from_runtime_root(root)
        return
    else:
        root = materialize_runtime_image(tmp_path, before_manifest=add_legacy_binding)
    manifest, digest = module._validated_manifest(root)
    assert manifest["schema_version"] == 2
    assert digest.startswith("sha256:")

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_rejects_legacy_python_mcp_manifest_commands(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "the-hive-mcp": {
                        "command": "python3",
                        "args": ["-c", "import sys; sys.path.insert(0, 'src')"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_requires_the_external_stable_mcp_launcher_shape(
    tmp_path: Path,
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    mcp_path = root / ".mcp.json"
    payload = json.loads(mcp_path.read_text(encoding="utf-8"))
    payload["mcpServers"]["the-hive-mcp"]["cwd"] = "/tmp/attacker"
    mcp_path.write_text(json.dumps(payload), encoding="utf-8")
    installer = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "the-hive-hive-hourly-probe-install"
        )
    )
    (root / ".the-hive-runtime-manifest.json").unlink()
    installer["_write_runtime_image_manifest"](root=root, commit="a" * 40)

    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_runtime_root(root)


def test_runtime_layout_derives_from_a_module_path_without_environment_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    root = materialize_runtime_image(tmp_path)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "untrusted-codex-home"))
    monkeypatch.setenv("CODEX_MASTER_RUNTIME_ROOT", str(tmp_path / "untrusted-runtime"))

    layout = module.RuntimeLayout.from_module_path(
        root / "src" / "the_hive" / "hive" / "cli.py"
    )

    assert layout.root == root
    with pytest.raises(module.LayoutError):
        module.RuntimeLayout.from_module_path(tmp_path / "not-an-image.py")


def test_runtime_state_layout_requires_the_exact_parameterless_state_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))

    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()

    assert layout.state_directory == state_directory
    assert layout.basename == "the-hive-ga-i2d-quiescence"


def test_runtime_state_layout_exposes_only_the_canonical_systemd_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))

    namespace: dict[str, object] = {}
    exec("from the_hive.runtime_layout import *", namespace)

    assert "RuntimeStateLayoutV1" not in namespace
    assert not hasattr(module.RuntimeStateLayoutV1, "from_environment")
    assert (
        module.RuntimeStateLayoutV1.from_systemd_state_directory().state_root
        == state_directory
    )


def test_runtime_state_layout_selects_one_exact_systemd_entry_and_is_not_constructible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    unrelated = tmp_path / "codex-master-admin"
    unrelated.mkdir(mode=0o700)
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", f"{unrelated}:{state_directory}")

    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()

    assert layout.state_root == state_directory
    assert layout.state_root_device == state_directory.stat().st_dev
    assert layout.state_root_inode == state_directory.stat().st_ino
    layout.validate()
    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1()
    with pytest.raises(TypeError):
        module.RuntimeStateLayoutV1(state_directory)  # type: ignore[call-arg]


def test_runtime_state_layout_rejects_an_unattested_object_new_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.delenv("STATE_DIRECTORY", raising=False)
    forged = object.__new__(module.RuntimeStateLayoutV1)
    object.__setattr__(forged, "state_root", state_directory)
    object.__setattr__(forged, "state_root_device", state_directory.stat().st_dev)
    object.__setattr__(forged, "state_root_inode", state_directory.stat().st_ino)

    with pytest.raises(module.LayoutError):
        forged.open_dirfd()


@pytest.mark.parametrize("representation", ("double_root", "trailing_slash"))
def test_runtime_state_layout_rejects_noncanonical_raw_systemd_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, representation: str
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    if representation == "double_root":
        raw_entry = "//" + str(state_directory).lstrip("/")
    else:
        raw_entry = f"{state_directory}/"
    monkeypatch.setenv("STATE_DIRECTORY", raw_entry)

    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1.from_systemd_state_directory()


def test_runtime_state_layout_rejects_relative_entries_and_missing_safe_dirfd_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", f"relative:{state_directory}")
    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1.from_systemd_state_directory()

    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))
    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()
    monkeypatch.delattr(os, "O_CLOEXEC", raising=False)
    with pytest.raises(module.LayoutError):
        layout.open_dirfd()


def test_runtime_state_layout_rejects_missing_o_nofollow_and_component_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "private-state" / "the-hive-ga-i2d-quiescence"
    state_directory.mkdir(mode=0o700, parents=True)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))
    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    with pytest.raises(module.LayoutError):
        layout.open_dirfd()

    monkeypatch.undo()
    target_parent = tmp_path / "actual-state"
    target_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-state"
    linked_parent.symlink_to(target_parent, target_is_directory=True)
    linked_state = linked_parent / "the-hive-ga-i2d-quiescence"
    (target_parent / "the-hive-ga-i2d-quiescence").mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(linked_state))
    with pytest.raises(module.LayoutError):
        module.RuntimeStateLayoutV1.from_systemd_state_directory()


def test_runtime_state_layout_rejects_a_final_dirfd_inode_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _runtime_layout_module()
    assert module is not None
    state_directory = tmp_path / "private-state" / "the-hive-ga-i2d-quiescence"
    replacement = tmp_path / "replacement-state"
    state_directory.mkdir(mode=0o700, parents=True)
    replacement.mkdir(mode=0o700)
    monkeypatch.setenv("STATE_DIRECTORY", str(state_directory))
    layout = module.RuntimeStateLayoutV1.from_systemd_state_directory()
    original_open = os.open

    def race_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == state_directory.name and "dir_fd" in kwargs:
            return original_open(replacement, flags)
        return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", race_open)
    with pytest.raises(module.LayoutError):
        layout.open_dirfd()
