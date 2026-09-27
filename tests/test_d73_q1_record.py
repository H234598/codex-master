"""Direct, synthetic Q1a checks for the private D339 record codec/decoder."""

from __future__ import annotations

import base64
from collections.abc import Callable
import copy
from dataclasses import replace
import fcntl
import hashlib
import json
import os
import struct
import threading

import pytest

from the_hive import _d73_q1_record as record


COMMIT = b"0123456789abcdef0123456789abcdef01234567"
GENERATION = b"g"
BUS_NAME = b"org.example.Policy"
SELINUX_CONTEXT = b"synthetic_u:synthetic_r:synthetic_t:s0"
POLKIT_ACTION = b"org.example.policy"
MANIFEST = (
    b'{"commit":"0123456789abcdef0123456789abcdef01234567",'
    b'"generation":"g","schema_version":2}\n'
)

# This is intentionally a static wire oracle, not a re-encoding in the test.
GOLDEN_SHA256 = "15a326627b0f1b63fb29ec785326a68299cd55e81cd116db26a10486d8159344"
GOLDEN_BYTES = base64.b64decode("VEhENzNRMQAAAQEsAAAGsDAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1NjcAAAPpAAAD6gAAAYAAAAAAAQIDBAUGBwgREhMUFRYXGAAAAHgAAACdAAAEbwAAAA8AAAABifB8KKi14e4esYiZrcuMCqCWRQj4URXDloB6Imm5h7vySnSM25a9gNwXi8mdoW37tZXcZ3rtGQXr+7bENErrgnLMuRpvA7H9V9ILJ17THXWFbJm9xethdNVXwfd9NPf3ooLUcmoWAPukVJsG/jcljO47QUPSEmwJeerjHrh6QJQCJGZonKlDH1nvHiIcSEh6G1NpfYzi59rAUa/GZhIjR7YN5nOmsB2jusHyQPoUh8QXao1zzkG1YgNWilN7VgcxdGhlLWhpdmUuZDczLmV4ZWN1dGlvbi1wb2xpY3kAAQAAAAAH0QABZwASb3JnLmV4YW1wbGUuUG9saWN5ACZzeW50aGV0aWNfdTpzeW50aGV0aWNfcjpzeW50aGV0aWNfdDpzMAASb3JnLmV4YW1wbGUucG9saWN5VEhENzNUMQAAAQAAAAAAnTAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1NjcAAQAA8kp0jNuWvYDcF4vJnaFt+7WV3Gd67RkF6/u2xDRK64KJ8HwoqLXh7h6xiJmty4wKoJZFCPhRFcOWgHoiabmHuwIkZmicqUMfWe8eIhxISHobU2l9jOLn2sBRr8ZmEiNHZ3siY29tbWl0IjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2NyIsImRpcmVjdG9yaWVzIjp7fSwiZmlsZXMiOnsieCI6eyJtb2RlIjozODQsIm5saW5rIjoxLCJzaGEyNTYiOiI1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1Iiwic2l6ZSI6MX19LCJnZW5lcmF0aW9uIjoiZyIsImhpc3RvcmljYWxfbGluZWFnZSI6eyJkNjkiOnsiY29tbWl0IjoiY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYyIsImR5bmFtaWNfcG9vbF9ibG9iIjoiZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZiIsInBhcmVudCI6ImVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWUiLCJ0cmVlIjoiZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZCJ9LCJkNzMiOnsiY29tbWl0IjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsInBhcmVudCI6IjMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMiLCJ0cmVlIjoiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMiJ9fSwicjJfYmFzZSI6eyJjb21taXQiOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwidHJlZSI6ImJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIifSwicmVsZWFzZSI6eyJiaW5kX3NvdXJjZXMiOltdLCJoNF91bml0cyI6W10sImhvb2tfYWJpIjoieCIsImhvb2tfYWJpX2NvbXBhbmlvbiI6IngiLCJob29rX2FiaV9jb3JlIjoieCIsImhvb2tfYWJpX3NvdXJjZSI6IngiLCJob29rX2VudHJ5cG9pbnRzIjpbXSwibW9uaXRvcl9lbnRyeXBvaW50IjoieCIsInBsdWdpbl9idW5kbGUiOiJ4IiwicHl0aG9uX3RyZWUiOiJ4Iiwicm9vdF9pbnN0YWxsX3BsYW4iOiJ4Iiwic3RhYmxlX2xhdW5jaGVycyI6W119LCJzY2hlbWFfdmVyc2lvbiI6Miwic3VjY2Vzc29yX3dpdG5lc3MiOnsicGF0aCI6InN5bnRoZXRpYy13aXRuZXNzIiwic2hhMjU2IjoiNDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NCJ9fQo=")  # noqa: E501


def _identity(*, size: int) -> record._DescriptorIdentity:
    return record._DescriptorIdentity(
        uid=1001,
        gid=1002,
        device=0x0102030405060708,
        inode=0x1112131415161718,
        size=size,
    )


def _encode(
    *,
    descriptor: record._DescriptorIdentity | None = None,
    generation: bytes = GENERATION,
    bus_name: bytes = BUS_NAME,
    selinux_context: bytes = SELINUX_CONTEXT,
    polkit_action: bytes = POLKIT_ACTION,
    manifest: bytes | None = None,
) -> bytes:
    if manifest is None:
        manifest = MANIFEST
    provisional = descriptor or _identity(size=0)
    first = record._encode_record(
        commit=COMMIT,
        descriptor=provisional,
        expected_uid=2001,
        generation=generation,
        bus_name=bus_name,
        selinux_context=selinux_context,
        polkit_action=polkit_action,
        manifest=manifest,
    )
    if descriptor is not None:
        return first
    return record._encode_record(
        commit=COMMIT,
        descriptor=_identity(size=len(first)),
        expected_uid=2001,
        generation=generation,
        bus_name=bus_name,
        selinux_context=selinux_context,
        polkit_action=polkit_action,
        manifest=manifest,
    )


def _rejects(raw: bytes, descriptor: record._DescriptorIdentity | None = None) -> None:
    with pytest.raises(record._Reject):
        record._decode_record_bytes(raw, descriptor or _identity(size=len(raw)))


def _put_u16(raw: bytes, offset: int, value: int) -> bytes:
    value_bytes = struct.pack(">H", value)
    return raw[:offset] + value_bytes + raw[offset + 2 :]


def _put_u32(raw: bytes, offset: int, value: int) -> bytes:
    value_bytes = struct.pack(">I", value)
    return raw[:offset] + value_bytes + raw[offset + 4 :]


def _put_u64(raw: bytes, offset: int, value: int) -> bytes:
    value_bytes = struct.pack(">Q", value)
    return raw[:offset] + value_bytes + raw[offset + 8 :]


def _replace_byte(raw: bytes, offset: int, value: int) -> bytes:
    return raw[:offset] + bytes((value,)) + raw[offset + 1 :]


def _leaf_offsets() -> dict[str, int]:
    generation_start = 300 + 39
    bus_length = generation_start + len(GENERATION)
    bus_start = bus_length + 2
    selinux_length = bus_start + len(BUS_NAME)
    selinux_start = selinux_length + 2
    action_length = selinux_start + len(SELINUX_CONTEXT)
    action_start = action_length + 2
    return {
        "generation_length": generation_start - 2,
        "generation": generation_start,
        "bus_length": bus_length,
        "bus": bus_start,
        "selinux_length": selinux_length,
        "selinux": selinux_start,
        "action_length": action_length,
        "action": action_start,
    }


def _tuple_start(raw: bytes) -> int:
    return 300 + struct.unpack(">I", raw[88:92])[0]


def _reference_digest(label: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(
        label + b"\0" + struct.pack(">I", len(payload)) + payload
    ).digest()


def _d341_manifest(
    *, generation: bytes = GENERATION, extra: dict[str, object] | None = None
) -> bytes:
    value: dict[str, object] = {
        "schema_version": 2,
        "commit": COMMIT.decode("ascii"),
        "generation": generation.decode("ascii"),
        "r2_base": {"commit": "a" * 40, "tree": "b" * 40},
        "historical_lineage": {
            "d69": {
                "commit": "c" * 40,
                "tree": "d" * 40,
                "parent": "e" * 40,
                "dynamic_pool_blob": "f" * 40,
            },
            "d73": {
                "commit": "1" * 40,
                "tree": "2" * 40,
                "parent": "3" * 40,
            },
        },
        "successor_witness": {"path": "synthetic-witness", "sha256": "4" * 64},
        "release": {
            "stable_launchers": [],
            "hook_abi_source": "x",
            "hook_abi": "x",
            "hook_abi_companion": "x",
            "hook_abi_core": "x",
            "hook_entrypoints": [],
            "plugin_bundle": "x",
            "root_install_plan": "x",
            "python_tree": "x",
            "monitor_entrypoint": "x",
            "h4_units": [],
            "bind_sources": [],
        },
        "directories": {},
        "files": {
            "x": {
                "mode": 0o600,
                "nlink": 1,
                "size": 1,
                "sha256": "5" * 64,
            }
        },
    }
    if extra is not None:
        value.update(extra)
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _canonical_manifest_with_padding(generation: bytes, length: int) -> bytes:
    value = json.loads(_d341_manifest(generation=generation))
    value["directories"] = {"x": {"mode": 0o700, "nlink": 1}}
    raw = (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    key_length = len(value["directories"])
    assert key_length == 1
    delta = length - len(raw)
    assert delta >= 0
    value["directories"] = {"x" * (1 + delta): {"mode": 0o700, "nlink": 1}}
    result = (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    assert len(result) == length
    return result


MANIFEST = _d341_manifest()


def _matrix_manifest_value() -> dict[str, object]:
    value = json.loads(_d341_manifest())
    assert type(value) is dict
    value["directories"] = {"directory": {"mode": 0o700, "nlink": 0}}
    return value


def _canonical_manifest(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _apply_manifest_matrix_case(
    value: dict[str, object],
    operation: str,
    path: tuple[str, ...],
    replacement: object,
) -> object:
    if operation == "replace_root":
        assert not path
        return replacement

    target: object = value
    for key in path[:-1]:
        assert type(target) is dict
        target = target[key]
    assert type(target) is dict
    if operation == "remove":
        del target[path[-1]]
    elif operation == "set":
        target[path[-1]] = replacement
    else:
        raise AssertionError(f"unknown manifest matrix operation: {operation}")
    return value


_MANIFEST_NEGATIVE_MATRIX = (
    # Every top-level key, the object shape, and every top-level value type.
    ("top-missing-schema_version", "remove", ("schema_version",), None),
    ("top-missing-commit", "remove", ("commit",), None),
    ("top-missing-generation", "remove", ("generation",), None),
    ("top-missing-r2_base", "remove", ("r2_base",), None),
    (
        "top-missing-historical_lineage",
        "remove",
        ("historical_lineage",),
        None,
    ),
    (
        "top-missing-successor_witness",
        "remove",
        ("successor_witness",),
        None,
    ),
    ("top-missing-release", "remove", ("release",), None),
    ("top-missing-directories", "remove", ("directories",), None),
    ("top-missing-files", "remove", ("files",), None),
    ("top-extra-key", "set", ("unexpected",), "synthetic"),
    ("top-container-list", "replace_root", (), []),
    ("top-wrong-schema_version-type", "set", ("schema_version",), "2"),
    ("top-wrong-commit-type", "set", ("commit",), 2),
    ("top-wrong-generation-type", "set", ("generation",), 2),
    ("top-wrong-r2_base-type", "set", ("r2_base",), []),
    (
        "top-wrong-historical_lineage-type",
        "set",
        ("historical_lineage",),
        [],
    ),
    (
        "top-wrong-successor_witness-type",
        "set",
        ("successor_witness",),
        [],
    ),
    ("top-wrong-release-type", "set", ("release",), []),
    ("top-wrong-directories-type", "set", ("directories",), []),
    ("top-wrong-files-type", "set", ("files",), []),
    # r2_base has exactly two lowercase 40-hex fields.
    ("r2_base-missing-commit", "remove", ("r2_base", "commit"), None),
    ("r2_base-missing-tree", "remove", ("r2_base", "tree"), None),
    ("r2_base-extra-key", "set", ("r2_base", "unexpected"), "x"),
    ("r2_base-wrong-commit-type", "set", ("r2_base", "commit"), 1),
    ("r2_base-wrong-tree-type", "set", ("r2_base", "tree"), 1),
    ("r2_base-invalid-commit-40hex", "set", ("r2_base", "commit"), "g" * 40),
    ("r2_base-invalid-tree-40hex", "set", ("r2_base", "tree"), "g" * 40),
    # historical_lineage owns only d69 and d73.
    (
        "historical_lineage-missing-d69",
        "remove",
        ("historical_lineage", "d69"),
        None,
    ),
    (
        "historical_lineage-missing-d73",
        "remove",
        ("historical_lineage", "d73"),
        None,
    ),
    (
        "historical_lineage-extra-key",
        "set",
        ("historical_lineage", "d74"),
        {},
    ),
    (
        "d69-missing-commit",
        "remove",
        ("historical_lineage", "d69", "commit"),
        None,
    ),
    (
        "d69-missing-tree",
        "remove",
        ("historical_lineage", "d69", "tree"),
        None,
    ),
    (
        "d69-missing-parent",
        "remove",
        ("historical_lineage", "d69", "parent"),
        None,
    ),
    (
        "d69-missing-dynamic_pool_blob",
        "remove",
        ("historical_lineage", "d69", "dynamic_pool_blob"),
        None,
    ),
    (
        "d69-extra-key",
        "set",
        ("historical_lineage", "d69", "unexpected"),
        "x",
    ),
    (
        "d69-wrong-commit-type",
        "set",
        ("historical_lineage", "d69", "commit"),
        1,
    ),
    (
        "d69-wrong-tree-type",
        "set",
        ("historical_lineage", "d69", "tree"),
        1,
    ),
    (
        "d69-wrong-parent-type",
        "set",
        ("historical_lineage", "d69", "parent"),
        1,
    ),
    (
        "d69-wrong-dynamic_pool_blob-type",
        "set",
        ("historical_lineage", "d69", "dynamic_pool_blob"),
        1,
    ),
    (
        "d69-invalid-commit-40hex",
        "set",
        ("historical_lineage", "d69", "commit"),
        "g" * 40,
    ),
    (
        "d69-invalid-tree-40hex",
        "set",
        ("historical_lineage", "d69", "tree"),
        "g" * 40,
    ),
    (
        "d69-invalid-parent-40hex",
        "set",
        ("historical_lineage", "d69", "parent"),
        "g" * 40,
    ),
    (
        "d69-invalid-dynamic_pool_blob-40hex",
        "set",
        ("historical_lineage", "d69", "dynamic_pool_blob"),
        "g" * 40,
    ),
    (
        "d73-missing-commit",
        "remove",
        ("historical_lineage", "d73", "commit"),
        None,
    ),
    (
        "d73-missing-tree",
        "remove",
        ("historical_lineage", "d73", "tree"),
        None,
    ),
    (
        "d73-missing-parent",
        "remove",
        ("historical_lineage", "d73", "parent"),
        None,
    ),
    (
        "d73-extra-key",
        "set",
        ("historical_lineage", "d73", "unexpected"),
        "x",
    ),
    (
        "d73-wrong-commit-type",
        "set",
        ("historical_lineage", "d73", "commit"),
        1,
    ),
    (
        "d73-wrong-tree-type",
        "set",
        ("historical_lineage", "d73", "tree"),
        1,
    ),
    (
        "d73-wrong-parent-type",
        "set",
        ("historical_lineage", "d73", "parent"),
        1,
    ),
    (
        "d73-invalid-commit-40hex",
        "set",
        ("historical_lineage", "d73", "commit"),
        "g" * 40,
    ),
    (
        "d73-invalid-tree-40hex",
        "set",
        ("historical_lineage", "d73", "tree"),
        "g" * 40,
    ),
    (
        "d73-invalid-parent-40hex",
        "set",
        ("historical_lineage", "d73", "parent"),
        "g" * 40,
    ),
    # successor_witness is an exact object with text path and 64-hex digest.
    (
        "successor_witness-missing-path",
        "remove",
        ("successor_witness", "path"),
        None,
    ),
    (
        "successor_witness-missing-sha256",
        "remove",
        ("successor_witness", "sha256"),
        None,
    ),
    (
        "successor_witness-extra-key",
        "set",
        ("successor_witness", "unexpected"),
        "x",
    ),
    (
        "successor_witness-wrong-path-type",
        "set",
        ("successor_witness", "path"),
        1,
    ),
    (
        "successor_witness-wrong-sha256-type",
        "set",
        ("successor_witness", "sha256"),
        1,
    ),
    (
        "successor_witness-empty-path",
        "set",
        ("successor_witness", "path"),
        "",
    ),
    (
        "successor_witness-nul-path",
        "set",
        ("successor_witness", "path"),
        "\0",
    ),
    (
        "successor_witness-invalid-sha256-64hex",
        "set",
        ("successor_witness", "sha256"),
        "g" * 64,
    ),
    # release: exact key set, four text arrays, and eight text scalars.
    (
        "release-missing-stable_launchers",
        "remove",
        ("release", "stable_launchers"),
        None,
    ),
    (
        "release-missing-hook_abi_source",
        "remove",
        ("release", "hook_abi_source"),
        None,
    ),
    ("release-missing-hook_abi", "remove", ("release", "hook_abi"), None),
    (
        "release-missing-hook_abi_companion",
        "remove",
        ("release", "hook_abi_companion"),
        None,
    ),
    (
        "release-missing-hook_abi_core",
        "remove",
        ("release", "hook_abi_core"),
        None,
    ),
    (
        "release-missing-hook_entrypoints",
        "remove",
        ("release", "hook_entrypoints"),
        None,
    ),
    (
        "release-missing-plugin_bundle",
        "remove",
        ("release", "plugin_bundle"),
        None,
    ),
    (
        "release-missing-root_install_plan",
        "remove",
        ("release", "root_install_plan"),
        None,
    ),
    (
        "release-missing-python_tree",
        "remove",
        ("release", "python_tree"),
        None,
    ),
    (
        "release-missing-monitor_entrypoint",
        "remove",
        ("release", "monitor_entrypoint"),
        None,
    ),
    (
        "release-missing-h4_units",
        "remove",
        ("release", "h4_units"),
        None,
    ),
    (
        "release-missing-bind_sources",
        "remove",
        ("release", "bind_sources"),
        None,
    ),
    ("release-extra-key", "set", ("release", "unexpected"), "x"),
    ("release-container-list", "set", ("release",), []),
    (
        "release-wrong-stable_launchers-type",
        "set",
        ("release", "stable_launchers"),
        "x",
    ),
    (
        "release-wrong-hook_abi_source-type",
        "set",
        ("release", "hook_abi_source"),
        [],
    ),
    (
        "release-wrong-hook_abi-type",
        "set",
        ("release", "hook_abi"),
        [],
    ),
    (
        "release-wrong-hook_abi_companion-type",
        "set",
        ("release", "hook_abi_companion"),
        [],
    ),
    (
        "release-wrong-hook_abi_core-type",
        "set",
        ("release", "hook_abi_core"),
        [],
    ),
    (
        "release-wrong-hook_entrypoints-type",
        "set",
        ("release", "hook_entrypoints"),
        "x",
    ),
    (
        "release-wrong-plugin_bundle-type",
        "set",
        ("release", "plugin_bundle"),
        [],
    ),
    (
        "release-wrong-root_install_plan-type",
        "set",
        ("release", "root_install_plan"),
        [],
    ),
    (
        "release-wrong-python_tree-type",
        "set",
        ("release", "python_tree"),
        [],
    ),
    (
        "release-wrong-monitor_entrypoint-type",
        "set",
        ("release", "monitor_entrypoint"),
        [],
    ),
    (
        "release-wrong-h4_units-type",
        "set",
        ("release", "h4_units"),
        "x",
    ),
    (
        "release-wrong-bind_sources-type",
        "set",
        ("release", "bind_sources"),
        "x",
    ),
    (
        "release-stable_launchers-empty-element",
        "set",
        ("release", "stable_launchers"),
        [""],
    ),
    (
        "release-stable_launchers-nul-element",
        "set",
        ("release", "stable_launchers"),
        ["\0"],
    ),
    (
        "release-stable_launchers-nonstring-element",
        "set",
        ("release", "stable_launchers"),
        [1],
    ),
    (
        "release-hook_entrypoints-empty-element",
        "set",
        ("release", "hook_entrypoints"),
        [""],
    ),
    (
        "release-hook_entrypoints-nul-element",
        "set",
        ("release", "hook_entrypoints"),
        ["\0"],
    ),
    (
        "release-hook_entrypoints-nonstring-element",
        "set",
        ("release", "hook_entrypoints"),
        [1],
    ),
    (
        "release-h4_units-empty-element",
        "set",
        ("release", "h4_units"),
        [""],
    ),
    (
        "release-h4_units-nul-element",
        "set",
        ("release", "h4_units"),
        ["\0"],
    ),
    (
        "release-h4_units-nonstring-element",
        "set",
        ("release", "h4_units"),
        [1],
    ),
    (
        "release-bind_sources-empty-element",
        "set",
        ("release", "bind_sources"),
        [""],
    ),
    (
        "release-bind_sources-nul-element",
        "set",
        ("release", "bind_sources"),
        ["\0"],
    ),
    (
        "release-bind_sources-nonstring-element",
        "set",
        ("release", "bind_sources"),
        [1],
    ),
    (
        "release-hook_abi_source-empty",
        "set",
        ("release", "hook_abi_source"),
        "",
    ),
    (
        "release-hook_abi_source-nul",
        "set",
        ("release", "hook_abi_source"),
        "\0",
    ),
    (
        "release-hook_abi_source-nonstring",
        "set",
        ("release", "hook_abi_source"),
        1,
    ),
    (
        "release-hook_abi-empty",
        "set",
        ("release", "hook_abi"),
        "",
    ),
    ("release-hook_abi-nul", "set", ("release", "hook_abi"), "\0"),
    (
        "release-hook_abi-nonstring",
        "set",
        ("release", "hook_abi"),
        1,
    ),
    (
        "release-hook_abi_companion-empty",
        "set",
        ("release", "hook_abi_companion"),
        "",
    ),
    (
        "release-hook_abi_companion-nul",
        "set",
        ("release", "hook_abi_companion"),
        "\0",
    ),
    (
        "release-hook_abi_companion-nonstring",
        "set",
        ("release", "hook_abi_companion"),
        1,
    ),
    (
        "release-hook_abi_core-empty",
        "set",
        ("release", "hook_abi_core"),
        "",
    ),
    (
        "release-hook_abi_core-nul",
        "set",
        ("release", "hook_abi_core"),
        "\0",
    ),
    (
        "release-hook_abi_core-nonstring",
        "set",
        ("release", "hook_abi_core"),
        1,
    ),
    (
        "release-plugin_bundle-empty",
        "set",
        ("release", "plugin_bundle"),
        "",
    ),
    (
        "release-plugin_bundle-nul",
        "set",
        ("release", "plugin_bundle"),
        "\0",
    ),
    (
        "release-plugin_bundle-nonstring",
        "set",
        ("release", "plugin_bundle"),
        1,
    ),
    (
        "release-root_install_plan-empty",
        "set",
        ("release", "root_install_plan"),
        "",
    ),
    (
        "release-root_install_plan-nul",
        "set",
        ("release", "root_install_plan"),
        "\0",
    ),
    (
        "release-root_install_plan-nonstring",
        "set",
        ("release", "root_install_plan"),
        1,
    ),
    (
        "release-python_tree-empty",
        "set",
        ("release", "python_tree"),
        "",
    ),
    (
        "release-python_tree-nul",
        "set",
        ("release", "python_tree"),
        "\0",
    ),
    (
        "release-python_tree-nonstring",
        "set",
        ("release", "python_tree"),
        1,
    ),
    (
        "release-monitor_entrypoint-empty",
        "set",
        ("release", "monitor_entrypoint"),
        "",
    ),
    (
        "release-monitor_entrypoint-nul",
        "set",
        ("release", "monitor_entrypoint"),
        "\0",
    ),
    (
        "release-monitor_entrypoint-nonstring",
        "set",
        ("release", "monitor_entrypoint"),
        1,
    ),
    # directories: dynamic key text plus exact entries and numeric bounds.
    ("directories-container-list", "set", ("directories",), []),
    (
        "directories-empty-key",
        "set",
        ("directories", ""),
        {"mode": 0o700, "nlink": 0},
    ),
    (
        "directories-nul-key",
        "set",
        ("directories", "\0"),
        {"mode": 0o700, "nlink": 0},
    ),
    (
        "directories-entry-missing-mode",
        "remove",
        ("directories", "directory", "mode"),
        None,
    ),
    (
        "directories-entry-missing-nlink",
        "remove",
        ("directories", "directory", "nlink"),
        None,
    ),
    (
        "directories-entry-extra-key",
        "set",
        ("directories", "directory", "unexpected"),
        1,
    ),
    (
        "directories-mode-bool",
        "set",
        ("directories", "directory", "mode"),
        True,
    ),
    (
        "directories-mode-noninteger",
        "set",
        ("directories", "directory", "mode"),
        1.5,
    ),
    (
        "directories-nlink-bool",
        "set",
        ("directories", "directory", "nlink"),
        True,
    ),
    (
        "directories-nlink-noninteger",
        "set",
        ("directories", "directory", "nlink"),
        1.5,
    ),
    (
        "directories-mode-lower-bound",
        "set",
        ("directories", "directory", "mode"),
        -1,
    ),
    (
        "directories-mode-upper-bound",
        "set",
        ("directories", "directory", "mode"),
        0o10000,
    ),
    (
        "directories-nlink-lower-bound",
        "set",
        ("directories", "directory", "nlink"),
        -1,
    ),
    (
        "directories-nlink-upper-bound",
        "set",
        ("directories", "directory", "nlink"),
        1 << 64,
    ),
    # files mirrors directories, with size and lowercase SHA-256 requirements.
    ("files-container-list", "set", ("files",), []),
    (
        "files-empty-key",
        "set",
        ("files", ""),
        {"mode": 0o600, "nlink": 1, "size": 1, "sha256": "5" * 64},
    ),
    (
        "files-nul-key",
        "set",
        ("files", "\0"),
        {"mode": 0o600, "nlink": 1, "size": 1, "sha256": "5" * 64},
    ),
    ("files-entry-missing-mode", "remove", ("files", "x", "mode"), None),
    ("files-entry-missing-nlink", "remove", ("files", "x", "nlink"), None),
    ("files-entry-missing-size", "remove", ("files", "x", "size"), None),
    (
        "files-entry-missing-sha256",
        "remove",
        ("files", "x", "sha256"),
        None,
    ),
    (
        "files-entry-extra-key",
        "set",
        ("files", "x", "unexpected"),
        1,
    ),
    ("files-mode-bool", "set", ("files", "x", "mode"), True),
    ("files-mode-noninteger", "set", ("files", "x", "mode"), 1.5),
    ("files-nlink-bool", "set", ("files", "x", "nlink"), True),
    ("files-nlink-noninteger", "set", ("files", "x", "nlink"), 1.5),
    ("files-size-bool", "set", ("files", "x", "size"), True),
    ("files-size-noninteger", "set", ("files", "x", "size"), 1.5),
    ("files-sha256-nonstring", "set", ("files", "x", "sha256"), 1),
    ("files-mode-lower-bound", "set", ("files", "x", "mode"), -1),
    ("files-mode-upper-bound", "set", ("files", "x", "mode"), 0o10000),
    ("files-nlink-lower-bound", "set", ("files", "x", "nlink"), -1),
    ("files-nlink-upper-bound", "set", ("files", "x", "nlink"), 1 << 64),
    ("files-size-lower-bound", "set", ("files", "x", "size"), 0),
    (
        "files-size-upper-bound",
        "set",
        ("files", "x", "size"),
        2 * 1024 * 1024 + 1,
    ),
    (
        "files-sha256-invalid-64hex",
        "set",
        ("files", "x", "sha256"),
        "g" * 64,
    ),
    (
        "files-sha256-uppercase-64hex",
        "set",
        ("files", "x", "sha256"),
        "A" * 64,
    ),
)


@pytest.mark.parametrize(
    ("case_id", "operation", "path", "replacement"),
    _MANIFEST_NEGATIVE_MATRIX,
    ids=[case[0] for case in _MANIFEST_NEGATIVE_MATRIX],
)
def test_d341_parse_manifest_rejects_complete_negative_schema_matrix(
    case_id: str,
    operation: str,
    path: tuple[str, ...],
    replacement: object,
) -> None:
    del case_id
    candidate = _apply_manifest_matrix_case(
        _matrix_manifest_value(), operation, path, replacement
    )
    with pytest.raises(record._Reject):
        record._parse_manifest(
            _canonical_manifest(candidate), commit=COMMIT, generation=GENERATION
        )


def test_d341_capability_rejects_subclass_dispatch_and_duplicate_issuance() -> None:
    class ForgedCapability(record.D73Q1Capability):
        __slots__ = ()

        def __hash__(self) -> int:
            return 0

        def __eq__(self, other: object) -> bool:
            return True

        def _take(self) -> int:
            return self._fd

    fd = _sealed_fd()
    try:
        forged = object.__new__(ForgedCapability)
        forged._fd = fd
        forged._consumed = False
        with pytest.raises(record._Reject):
            record._decode_capability(forged)
    finally:
        os.close(fd)

    first_fd = _sealed_fd()
    try:
        record._capability_from_fd(first_fd)
        with pytest.raises(record._Reject):
            record._capability_from_fd(first_fd)
    finally:
        os.close(first_fd)


def test_d341_new_helpers_are_direct_and_fail_closed() -> None:
    manifest = json.loads(_d341_manifest())
    assert record._exact_object({"key": 1}, {"key"}) == {"key": 1}
    assert record._hex_text("a" * 40, 40) == "a" * 40
    assert record._text("synthetic") == "synthetic"
    assert record._bounded_int(1, 0, 1) == 1
    record._validate_manifest_grammar(
        manifest, commit=COMMIT, generation=GENERATION
    )
    for function in (
        lambda: record._exact_object({}, {"key"}),
        lambda: record._hex_text("A" * 40, 40),
        lambda: record._text("\0"),
        lambda: record._bounded_int(True, 0, 1),
    ):
        with pytest.raises(record._Reject):
            function()

    fd = _sealed_fd()
    try:
        assert record._descriptor_key(fd) == (
            os.fstat(fd).st_dev,
            os.fstat(fd).st_ino,
        )
        capability = record._capability_from_fd(fd)
        record._register_capability(capability)
        assert record._take_capability(capability) == fd
    finally:
        os.close(fd)


def test_d341_capability_rejects_reused_fd_number_before_closing_it() -> None:
    original_fd = _sealed_fd()
    capability = record._capability_from_fd(original_fd)
    os.close(original_fd)
    replacement_fd = _sealed_fd()
    assert replacement_fd == original_fd
    with pytest.raises(record._Reject):
        record._decode_capability(capability)
    os.fstat(replacement_fd)
    os.close(replacement_fd)


def test_d341_tombstone_check_and_add_is_serialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BarrierSet:
        def __init__(self) -> None:
            self._values: set[tuple[int, int]] = set()
            self._barrier = threading.Barrier(2)

        def __contains__(self, value: object) -> bool:
            present = value in self._values
            try:
                self._barrier.wait(timeout=0.05)
            except threading.BrokenBarrierError:
                pass
            return present

        def add(self, value: tuple[int, int]) -> None:
            self._values.add(value)

    tombstones = BarrierSet()
    monkeypatch.setattr(record, "_ISSUED_DESCRIPTOR_IDENTITIES", tombstones)
    fd = _sealed_fd()
    barrier = threading.Barrier(2)
    results: list[object] = []

    def issue() -> None:
        barrier.wait(timeout=1)
        try:
            results.append(record._capability_from_fd(fd))
        except record._Reject:
            results.append(None)

    workers = [threading.Thread(target=issue) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=1)
        assert not worker.is_alive()
    capabilities = [item for item in results if item is not None]
    assert len(capabilities) == 1
    assert results.count(None) == 1
    record._decode_capability(capabilities[0])


def test_direct_integer_byte_and_offset_primitives_fail_closed() -> None:
    assert record._unsigned(0, 0) == 0
    assert record._unsigned(255, 8) == 255
    for value, bits in ((True, 8), (-1, 8), (256, 8), (0, -1)):
        with pytest.raises(record._Reject):
            record._unsigned(value, bits)

    assert record._bytes(b"x") == b"x"
    for value in ("x", bytearray(b"x"), memoryview(b"x")):
        with pytest.raises(record._Reject):
            record._bytes(value)

    assert record._u16(0x1234) == b"\x12\x34"
    assert record._u32(0x12345678) == b"\x12\x34\x56\x78"
    assert record._u64(0x0102030405060708) == b"\x01\x02\x03\x04\x05\x06\x07\x08"
    for encoder, value in (
        (record._u16, 1 << 16),
        (record._u32, 1 << 32),
        (record._u64, 1 << 64),
    ):
        with pytest.raises(record._Reject):
            encoder(value)

    raw = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert record._u16_at(raw, 1) == 0x0203
    assert record._u32_at(raw, 2) == 0x03040506
    assert record._u64_at(raw, 0) == 0x0102030405060708
    for reader in (record._u16_at, record._u32_at, record._u64_at):
        with pytest.raises(record._Reject):
            reader(raw, -1)
        with pytest.raises(record._Reject):
            reader(b"\0", 0)


def test_direct_value_manifest_and_digest_primitives_fail_closed() -> None:
    assert record._exact_ascii(b"!~", minimum=1, maximum=2) == b"!~"
    for value in (b"", b" ", b"\x7f"):
        with pytest.raises(record._Reject):
            record._exact_ascii(value, minimum=1, maximum=2)

    assert record._generation(b"generation-1") == b"generation-1"
    assert record._bus_name(b"org.synthetic.Policy") == b"org.synthetic.Policy"
    assert record._selinux_context(b"synthetic:context") == b"synthetic:context"
    assert record._polkit_action(b"org.synthetic.action") == b"org.synthetic.action"
    assert record._commit(COMMIT) == COMMIT
    for validator, value in (
        (record._generation, b"."),
        (record._bus_name, b":unique"),
        (record._selinux_context, b"\0"),
        (record._polkit_action, b"\0"),
        (record._commit, b"g" * 40),
    ):
        with pytest.raises(record._Reject):
            validator(value)

    identity = _identity(size=667)
    assert record._identity(identity) == identity
    with pytest.raises(record._Reject):
        record._identity(object())

    assert record._digest(b"label", b"payload") == hashlib.sha256(
        b"label\0\0\0\0\x07payload"
    ).digest()
    assert record._unique_json_object([("key", 1)]) == {"key": 1}
    with pytest.raises(record._Reject):
        record._unique_json_object([("key", 1), ("key", 2)])
    with pytest.raises(record._Reject):
        record._reject_json_constant("NaN")

    parsed = record._parse_manifest(MANIFEST, commit=COMMIT, generation=GENERATION)
    assert parsed["schema_version"] == 2
    with pytest.raises(record._Reject):
        record._parse_manifest(
            MANIFEST.replace(b'"schema_version":2', b'"schema_version":1'),
            commit=COMMIT,
            generation=GENERATION,
        )


def test_direct_leaf_tuple_header_and_sized_decoders_fail_closed() -> None:
    leaf = record._leaf(
        expected_uid=2001,
        generation=GENERATION,
        bus_name=BUS_NAME,
        selinux_context=SELINUX_CONTEXT,
        polkit_action=POLKIT_ACTION,
    )
    assert record._decode_leaf(leaf) == (
        2001,
        GENERATION,
        BUS_NAME,
        SELINUX_CONTEXT,
        POLKIT_ACTION,
    )
    with pytest.raises(record._Reject):
        record._decode_leaf(leaf[:-1])

    assert record._take_sized(b"\0\x01x", 0, 3) == (b"x", 3)
    with pytest.raises(record._Reject):
        record._take_sized(b"\0\x02x", 0, 3)

    prefix = record._header_prefix(
        total=667,
        commit=COMMIT,
        descriptor=_identity(size=667),
        leaf_length=len(leaf),
        tuple_length=157,
        manifest_length=len(MANIFEST),
    )
    assert len(prefix) == 108
    manifest_digest = bytes(range(32))
    leaf_digest = bytes(range(32, 64))
    binder = bytes(range(64, 96))
    tuple_bytes = record._tuple(
        commit=COMMIT,
        generation=GENERATION,
        manifest_digest=manifest_digest,
        leaf_digest=leaf_digest,
        binder=binder,
    )
    assert record._decode_tuple(
        tuple_bytes,
        commit=COMMIT,
        generation=GENERATION,
        manifest_digest=manifest_digest,
        leaf_digest=leaf_digest,
        binder=binder,
    ) is None
    with pytest.raises(record._Reject):
        record._decode_tuple(
            tuple_bytes[:-1],
            commit=COMMIT,
            generation=GENERATION,
            manifest_digest=manifest_digest,
            leaf_digest=leaf_digest,
            binder=binder,
        )

    encoded = record._encode_record(
        commit=COMMIT,
        descriptor=_identity(size=667),
        expected_uid=2001,
        generation=GENERATION,
        bus_name=BUS_NAME,
        selinux_context=SELINUX_CONTEXT,
        polkit_action=POLKIT_ACTION,
        manifest=MANIFEST,
    )
    assert encoded == GOLDEN_BYTES
    assert hashlib.sha256(encoded).hexdigest() == GOLDEN_SHA256


def test_golden_bytes_and_direct_codec_round_trip() -> None:
    raw = _encode()

    assert raw == GOLDEN_BYTES
    assert hashlib.sha256(raw).hexdigest() == GOLDEN_SHA256
    decoded = record._decode_record_bytes(
        GOLDEN_BYTES, _identity(size=len(GOLDEN_BYTES))
    )
    assert decoded.commit == COMMIT
    assert decoded.generation == GENERATION
    assert decoded.expected_uid == 2001
    assert decoded.bus_name == BUS_NAME
    assert decoded.selinux_context == SELINUX_CONTEXT
    assert decoded.polkit_action == POLKIT_ACTION
    assert decoded.manifest == MANIFEST


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("magic", lambda raw: _replace_byte(raw, 0, ord("X"))),
        ("version", lambda raw: _put_u16(raw, 8, 2)),
        ("header_length", lambda raw: _put_u16(raw, 10, 299)),
        ("total_too_small", lambda raw: _put_u32(raw, 12, 506)),
        ("total_too_large", lambda raw: _put_u32(raw, 12, 533192)),
        ("total_wrong", lambda raw: _put_u32(raw, 12, len(raw) - 1)),
        ("commit_alphabet", lambda raw: _replace_byte(raw, 16, ord("G"))),
        ("publisher_uid", lambda raw: _put_u32(raw, 56, 0)),
        ("publisher_gid", lambda raw: _put_u32(raw, 60, 0)),
        ("mode", lambda raw: _put_u32(raw, 64, 0o644)),
        ("link_count", lambda raw: _put_u32(raw, 68, 1)),
        ("device", lambda raw: _put_u64(raw, 72, 0)),
        ("inode", lambda raw: _put_u64(raw, 80, 0)),
        ("leaf_lower_bound", lambda raw: _put_u32(raw, 88, 48)),
        ("leaf_upper_bound", lambda raw: _put_u32(raw, 88, 8193)),
        ("tuple_lower_bound", lambda raw: _put_u32(raw, 92, 156)),
        ("tuple_upper_bound", lambda raw: _put_u32(raw, 92, 412)),
        ("manifest_lower_bound", lambda raw: _put_u32(raw, 96, 0)),
        ("manifest_upper_bound", lambda raw: _put_u32(raw, 96, 524289)),
        ("seals", lambda raw: _put_u32(raw, 100, 0)),
        ("fd_flags", lambda raw: _put_u32(raw, 104, 0)),
        ("trailing_bytes", lambda raw: raw + b"x"),
    ],
)
def test_decoder_rejects_every_fixed_header_field_and_trailing_bytes(
    name: str, mutate: object
) -> None:
    del name
    raw = _encode()
    _rejects(mutate(raw))  # type: ignore[operator]


def test_decoder_rejects_leaf_field_order_lengths_flags_and_text_rules() -> None:
    raw = _encode()
    offsets = _leaf_offsets()
    cases = (
        _replace_byte(raw, 300, ord("X")),
        _put_u16(raw, 300 + 29, 2),
        _put_u16(raw, 300 + 31, 1),
        _put_u32(raw, 300 + 33, 0),
        _put_u16(raw, offsets["generation_length"], 0),
        _replace_byte(raw, offsets["generation"], ord("/")),
        _replace_byte(raw, offsets["bus"], ord(":")),
        _replace_byte(raw, offsets["selinux"], 0),
        _replace_byte(raw, offsets["action"], 0),
        _put_u16(raw, offsets["action_length"], 0),
    )

    for malformed in cases:
        _rejects(malformed)


def test_codec_accepts_the_declared_minimum_and_maximum_field_bounds() -> None:
    minimum = _encode(
        generation=b"g",
        bus_name=b"b",
        selinux_context=b"s",
        polkit_action=b"p",
    )
    assert struct.unpack(">I", minimum[88:92])[0] == 49
    assert struct.unpack(">I", minimum[92:96])[0] == 157
    _rejects(minimum[:-1])

    generation = b"g" * 255
    manifest = _canonical_manifest_with_padding(
        generation, record._MAX_MANIFEST_LENGTH
    )
    maximum = _encode(
        generation=generation,
        bus_name=b"b" * 255,
        selinux_context=b"s" * 4096,
        polkit_action=b"p" * 255,
        manifest=manifest,
    )
    assert struct.unpack(">I", maximum[88:92])[0] == 4906
    assert struct.unpack(">I", maximum[92:96])[0] == 411
    assert struct.unpack(">I", maximum[96:100])[0] == 524288
    decoded = record._decode_record_bytes(
        maximum, _identity(size=len(maximum))
    )
    assert decoded.generation == generation
    assert decoded.manifest == manifest

    with pytest.raises(record._Reject):
        _encode(
            generation=generation,
            manifest=_canonical_manifest_with_padding(generation, 524289),
        )


def test_encoder_rejects_generation_bus_selinux_polkit_and_bounds() -> None:
    invalid_arguments = (
        {"generation": b"."},
        {"generation": b".."},
        {"generation": b"g/g"},
        {"generation": b"g\x00"},
        {"bus_name": b":synthetic.1"},
        {"bus_name": b"name\x00"},
        {"selinux_context": b"context\x00suffix"},
        {"polkit_action": b"action\x00suffix"},
        {"generation": b"g" * 256},
        {"bus_name": b"b" * 256},
        {"selinux_context": b"s" * 4097},
        {"polkit_action": b"p" * 256},
    )

    for overrides in invalid_arguments:
        with pytest.raises(record._Reject):
            _encode(**overrides)


def test_decoder_rejects_tuple_fields_order_reserve_and_generation_mismatch() -> None:
    raw = _encode()
    start = _tuple_start(raw)
    cases = (
        _replace_byte(raw, start, ord("X")),
        _put_u16(raw, start + 8, 2),
        _put_u16(raw, start + 10, 1),
        _put_u32(raw, start + 12, 156),
        _replace_byte(raw, start + 16, ord("a")),
        _put_u16(raw, start + 56, 2),
        _put_u16(raw, start + 58, 1),
        _replace_byte(raw, start + 156, ord("x")),
    )

    for malformed in cases:
        _rejects(malformed)


def test_manifest_is_ascii_duplicate_rejecting_schema_two_and_canonical() -> None:
    invalid_manifests = (
        MANIFEST[:-1],
        MANIFEST.replace(b'"schema_version":2', b'"schema_version":1'),
        MANIFEST.replace(b"{", b"{ ", 1),
        MANIFEST.replace(b"g", b"\\u0067", 1),
        b'{"commit":"0123456789abcdef0123456789abcdef01234567",'
        b'"generation":"g","schema_version":2,"schema_version":2}\n',
        b'{"commit":"0123456789abcdef0123456789abcdef01234567",'
        b'"generation":"g","schema_version":NaN}\n',
        b'\xff',
    )

    for manifest in invalid_manifests:
        with pytest.raises(record._Reject):
            _encode(manifest=manifest)


def test_decoder_rejects_all_six_digest_positions_and_tuple_binder_rule() -> None:
    raw = _encode()
    start = _tuple_start(raw)
    digest_offsets = (108, 140, 172, 204, 236, 268, start + 124)

    for offset in digest_offsets:
        _rejects(_replace_byte(raw, offset, raw[offset] ^ 1))


def test_digest_graph_uses_all_six_preimages_and_only_nulls_tuple_binder() -> None:
    raw = _encode()
    prefix = raw[:108]
    leaf_start = 300
    tuple_start = _tuple_start(raw)
    manifest_start = tuple_start + struct.unpack(">I", raw[92:96])[0]
    leaf = raw[leaf_start:tuple_start]
    tuple_bytes = raw[tuple_start:manifest_start]
    manifest = raw[manifest_start:]
    leaf_digest = _reference_digest(record._LEAF_LABEL, leaf)
    manifest_digest = _reference_digest(record._MANIFEST_LABEL, manifest)
    tuple_digest = _reference_digest(
        record._TUPLE_LABEL, tuple_bytes[:124] + bytes(32) + tuple_bytes[156:]
    )
    descriptor_digest = _reference_digest(record._DESCRIPTOR_LABEL, prefix)
    binder = _reference_digest(
        record._BINDER_LABEL,
        record._NAMESPACE
        + struct.pack(">H", 1)
        + COMMIT
        + leaf_digest
        + manifest_digest
        + tuple_digest
        + descriptor_digest,
    )
    generation_digest = _reference_digest(
        record._GENERATION_LABEL,
        prefix
        + leaf_digest
        + manifest_digest
        + tuple_digest
        + descriptor_digest
        + binder,
    )

    assert raw[108:140] == leaf_digest
    assert raw[140:172] == manifest_digest
    assert raw[172:204] == tuple_digest
    assert raw[204:236] == descriptor_digest
    assert raw[236:268] == binder == tuple_bytes[124:156]
    assert raw[268:300] == generation_digest
    assert _reference_digest(record._TUPLE_LABEL, tuple_bytes) != tuple_digest


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        assert written > 0
        offset += written


def _sealed_fd(
    *,
    mode: int = 0o600,
    seal: bool = True,
    cloexec: bool = True,
    raw_mutator: Callable[[bytes], bytes] | None = None,
) -> int:
    fd = os.memfd_create(
        "d73-q1-synthetic", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
    )
    os.fchmod(fd, mode)
    initial = os.fstat(fd)
    provisional = record._DescriptorIdentity(
        uid=initial.st_uid,
        gid=initial.st_gid,
        device=initial.st_dev,
        inode=initial.st_ino,
        size=0,
    )
    first = _encode(descriptor=provisional)
    identity = replace(provisional, size=len(first))
    raw = _encode(descriptor=identity)
    assert len(raw) == len(first)
    if raw_mutator is not None:
        raw = raw_mutator(raw)
    _write_all(fd, raw)
    if not cloexec:
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
    if seal:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, record._REQUIRED_SEALS)
    return fd


def test_direct_fd_state_validation_and_pread_exact_fail_closed() -> None:
    fd = _sealed_fd()
    try:
        state = record._fd_state(fd)
        assert state.identity() == record._DescriptorIdentity(
            uid=state.uid,
            gid=state.gid,
            device=state.device,
            inode=state.inode,
            size=state.size,
        )
        assert record._validate_fd_state(state) is state
        assert len(record._pread_exact(fd, state.size)) == state.size
        with pytest.raises(record._Reject):
            record._validate_fd_state(replace(state, mode=0o644))
    finally:
        os.close(fd)

    reader, writer = os.pipe()
    try:
        with pytest.raises(record._Reject):
            record._pread_exact(reader, 1)
    finally:
        os.close(reader)
        os.close(writer)


def test_capability_cannot_be_freely_constructed_and_positive_fd_is_one_shot() -> None:
    with pytest.raises(record._Reject):
        record.D73Q1Capability(123)  # type: ignore[call-arg]

    fd = _sealed_fd()
    capability = record._capability_from_fd(fd)
    decoded = record._decode_capability(capability)
    assert decoded.commit == COMMIT
    assert decoded.generation == GENERATION
    with pytest.raises(record._Reject):
        record._decode_capability(capability)
    with pytest.raises(OSError):
        os.fstat(fd)


def test_capability_take_is_direct_linear_and_registered() -> None:
    fd = os.memfd_create("d73-q1-take", os.MFD_CLOEXEC)
    capability = record._capability_from_fd(fd)
    assert record._take_capability(capability) == fd
    with pytest.raises(record._Reject):
        record._take_capability(capability)
    os.close(fd)


def test_capability_copy_forgery_and_reused_fd_number_are_rejected() -> None:
    fd = _sealed_fd()
    capability = record._capability_from_fd(fd)
    with pytest.raises(record._Reject):
        copy.copy(capability)
    with pytest.raises(record._Reject):
        copy.deepcopy(capability)

    forged = object.__new__(record.D73Q1Capability)
    forged._fd = fd
    forged._consumed = False
    with pytest.raises(record._Reject):
        record._decode_capability(forged)
    os.fstat(fd)

    record._decode_capability(capability)
    replacement_fd = _sealed_fd()
    assert replacement_fd == fd
    reused_forgery = object.__new__(record.D73Q1Capability)
    reused_forgery._fd = replacement_fd
    reused_forgery._consumed = False
    with pytest.raises(record._Reject):
        record._decode_capability(reused_forgery)
    os.fstat(replacement_fd)
    os.close(replacement_fd)


def test_decoder_closes_and_consumes_sealed_fd_on_digest_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fd = _sealed_fd(
        raw_mutator=lambda raw: _replace_byte(raw, 108, raw[108] ^ 1)
    )
    capability = record._capability_from_fd(fd)
    size = os.fstat(fd).st_size
    original_pread = record.os.pread
    reads: list[tuple[int, int, int]] = []

    def tracking_pread(descriptor: int, length: int, offset: int) -> bytes:
        payload = original_pread(descriptor, length, offset)
        reads.append((length, offset, len(payload)))
        return payload

    monkeypatch.setattr(record.os, "pread", tracking_pread)
    with pytest.raises(record._Reject):
        record._decode_capability(capability)
    assert reads == [(size, 0, size)]
    with pytest.raises(record._Reject):
        record._decode_capability(capability)
    with pytest.raises(OSError):
        os.fstat(fd)


def test_decoder_closes_fd_on_success_and_each_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    original_close = record.os.close

    def tracking_close(fd: int) -> None:
        closed.append(fd)
        original_close(fd)

    monkeypatch.setattr(record.os, "close", tracking_close)
    success_fd = _sealed_fd()
    record._decode_capability(record._capability_from_fd(success_fd))
    assert closed == [success_fd]

    original_pread = record.os.pread

    def short_read(fd: int, size: int, offset: int) -> bytes:
        return original_pread(fd, size, offset)[:-1]

    monkeypatch.setattr(record.os, "pread", short_read)
    failed_fd = _sealed_fd()
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(failed_fd))
    assert closed == [success_fd, failed_fd]
    with pytest.raises(OSError):
        os.fstat(failed_fd)


@pytest.mark.parametrize(
    "field",
    (
        "uid",
        "gid",
        "mode",
        "nlink",
        "size",
        "device",
        "inode",
        "seals",
        "fd_flags",
    ),
)
def test_decoder_rejects_each_descriptor_identity_field(
    field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fd = _sealed_fd()
    actual = record._fd_state(fd)
    replacement = {
        "uid": actual.uid + 1,
        "gid": actual.gid + 1,
        "mode": 0o644,
        "nlink": actual.nlink + 1,
        "size": actual.size - 1,
        "device": actual.device + 1,
        "inode": actual.inode + 1,
        "seals": actual.seals ^ 1,
        "fd_flags": actual.fd_flags | 2,
    }
    altered = replace(actual, **{field: replacement[field]})
    monkeypatch.setattr(record, "_fd_state", lambda _: altered)

    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(fd))
    with pytest.raises(OSError):
        os.fstat(fd)


def test_decoder_rejects_wrong_type_seals_and_cloexec() -> None:
    reader, writer = os.pipe()
    os.close(writer)
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(reader))
    with pytest.raises(OSError):
        os.fstat(reader)

    unsealed = _sealed_fd(seal=False)
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(unsealed))
    with pytest.raises(OSError):
        os.fstat(unsealed)

    no_cloexec = _sealed_fd(cloexec=False)
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(no_cloexec))
    with pytest.raises(OSError):
        os.fstat(no_cloexec)


def test_decoder_rejects_metadata_and_second_readback_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fd = _sealed_fd()
    original_state = record._fd_state
    state_calls = 0

    def drifting_state(descriptor: int) -> record._FDState:
        nonlocal state_calls
        state_calls += 1
        current = original_state(descriptor)
        if state_calls == 2:
            return replace(current, inode=current.inode + 1)
        return current

    monkeypatch.setattr(record, "_fd_state", drifting_state)
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(fd))
    with pytest.raises(OSError):
        os.fstat(fd)

    monkeypatch.undo()
    fd = _sealed_fd()
    original_pread = record.os.pread
    reads = 0

    def drifting_read(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal reads
        reads += 1
        payload = original_pread(descriptor, size, offset)
        if reads == 2:
            return payload[:-1] + bytes((payload[-1] ^ 1,))
        return payload

    monkeypatch.setattr(record.os, "pread", drifting_read)
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(fd))
    assert reads == 2
    with pytest.raises(OSError):
        os.fstat(fd)


def test_decoder_rejects_final_metadata_readback_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fd = _sealed_fd()
    original_state = record._fd_state
    state_calls = 0

    def drifting_state(descriptor: int) -> record._FDState:
        nonlocal state_calls
        state_calls += 1
        current = original_state(descriptor)
        if state_calls == 3:
            return replace(current, device=current.device + 1)
        return current

    monkeypatch.setattr(record, "_fd_state", drifting_state)
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(fd))
    assert state_calls == 3
    with pytest.raises(OSError):
        os.fstat(fd)


def test_cleanup_error_fails_closed_after_the_only_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fd = _sealed_fd()
    original_close = record.os.close
    closes = 0

    def close_then_report_error(descriptor: int) -> None:
        nonlocal closes
        closes += 1
        original_close(descriptor)
        raise OSError("synthetic close failure")

    monkeypatch.setattr(record.os, "close", close_then_report_error)
    with pytest.raises(record._Reject):
        record._decode_capability(record._capability_from_fd(fd))
    assert closes == 1
    with pytest.raises(OSError):
        os.fstat(fd)
