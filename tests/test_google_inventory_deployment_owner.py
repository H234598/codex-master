from __future__ import annotations

import fcntl
import io
import os
import socket
from collections.abc import Callable
from pathlib import Path

import pytest

import the_hive.google_inventory_deployment_owner as owner_module


class _ReadOnlyPort:
    def read(self, *args: object) -> object:
        return object()


class _Resolver:
    def __init__(self, result: object) -> None:
        self.result = result
        self.references: list[str] = []

    def resolve(self, reference: str) -> object:
        self.references.append(reference)
        return self.result


def _owner(
    *, resolver: object | None = None
) -> owner_module.GoogleInventoryDeploymentOwnerV1:
    return owner_module.GoogleInventoryDeploymentOwnerV1(
        plan_binding=_ReadOnlyPort(),
        principal_lease_scope=_ReadOnlyPort(),
        targetset=_ReadOnlyPort(),
        quiescence_resolver=resolver if resolver is not None else _Resolver(object()),
    )


def _assert_unavailable(call: Callable[[], object]) -> None:
    with pytest.raises(owner_module.DeploymentOwnerUnavailable) as captured:
        call()
    assert captured.value.code == "inventory.deployment_owner_unavailable"


def _regular_request_fd(path: Path, payload: bytes) -> int:
    path.write_bytes(payload)
    return os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)


def _sealed_memfd(payload: bytes) -> int:
    if not hasattr(os, "memfd_create"):
        pytest.skip("memfd_create is unavailable")
    required_flags = getattr(os, "MFD_ALLOW_SEALING", 0) | getattr(os, "MFD_CLOEXEC", 0)
    fd = os.memfd_create("ga-i2d-p1a-request", required_flags)
    os.write(fd, payload)
    seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    return fd


def _stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_rdev,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def test_owner_requires_all_explicit_read_only_p0_ports_and_resolver() -> None:
    port = _ReadOnlyPort()

    for field in (
        "plan_binding",
        "principal_lease_scope",
        "targetset",
        "quiescence_resolver",
    ):
        components: dict[str, object] = {
            "plan_binding": port,
            "principal_lease_scope": port,
            "targetset": port,
            "quiescence_resolver": _Resolver(object()),
        }
        components[field] = object()
        _assert_unavailable(
            lambda components=components: owner_module.GoogleInventoryDeploymentOwnerV1(
                **components  # type: ignore[arg-type]
            )
        )


def test_owner_binds_only_existing_resolver_read_operation() -> None:
    receipt = object()
    resolver = _Resolver(receipt)
    owner = _owner(resolver=resolver)

    assert owner.resolve_quiescence("receipt-v1-opaque") is receipt
    assert resolver.references == ["receipt-v1-opaque"]


@pytest.mark.parametrize(
    "resolver, reference",
    (
        (_Resolver(None), "receipt-v1-absent"),
        (_Resolver(object()), object()),
    ),
)
def test_owner_maps_absent_or_invalid_resolver_evidence_to_typed_unavailable(
    resolver: object, reference: object
) -> None:
    owner = _owner(resolver=resolver)

    _assert_unavailable(lambda: owner.resolve_quiescence(reference))


def test_owner_maps_resolver_exception_to_typed_unavailable() -> None:
    class RaisingResolver:
        def resolve(self, reference: str) -> object:
            del reference
            raise RuntimeError("must not escape")

    _assert_unavailable(
        lambda: _owner(resolver=RaisingResolver()).resolve_quiescence("r")
    )


def test_effect_is_constantly_typed_unavailable_without_action_or_effect_port() -> None:
    owner = _owner()

    assert owner.effect() == "unavailable"


def test_public_candidate_metadata_returns_the_exact_two_field_allowlist() -> None:
    metadata = owner_module.public_candidate_metadata(
        {
            "account_ref": "account-ref-1",
            "candidate_fingerprint": "sha256:" + "a" * 64,
            "email": "private@example.invalid",
            "subject": "private-subject",
            "path": "/private/client.json",
            "generation": "private-generation",
            "provider": "private-provider",
            "secret": "private-secret",
        }
    )

    assert metadata == {
        "account_ref": "account-ref-1",
        "candidate_fingerprint": "sha256:" + "a" * 64,
    }
    assert set(metadata) == {"account_ref", "candidate_fingerprint"}


def test_public_candidate_metadata_reads_only_allowlisted_object_attributes() -> None:
    class Candidate:
        account_ref = "account-ref-1"
        candidate_fingerprint = "sha256:" + "b" * 64
        client_id = "private-client-id"
        key_path = "/private/key.json"

    assert owner_module.public_candidate_metadata(Candidate()) == {
        "account_ref": "account-ref-1",
        "candidate_fingerprint": "sha256:" + "b" * 64,
    }


@pytest.mark.parametrize(
    "record",
    (
        {},
        {"account_ref": "account-ref-1"},
        {"candidate_fingerprint": "sha256:" + "c" * 64},
        {"account_ref": 7, "candidate_fingerprint": "sha256:" + "c" * 64},
        {"account_ref": "account-ref-1", "candidate_fingerprint": 7},
    ),
)
def test_public_candidate_metadata_fail_closes_without_two_string_allowlist_values(
    record: object,
) -> None:
    _assert_unavailable(lambda: owner_module.public_candidate_metadata(record))


def test_request_reader_duplicates_at_offset_zero_and_closes_only_its_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b'{"opaque":"request-bytes"}'
    original_fd = _regular_request_fd(tmp_path / "request.json", payload)
    duplicate_fds: list[int] = []
    original_dup = os.dup

    def tracking_dup(fd: int) -> int:
        duplicate = original_dup(fd)
        duplicate_fds.append(duplicate)
        return duplicate

    monkeypatch.setattr(owner_module.os, "dup", tracking_dup)
    try:
        os.lseek(original_fd, len(payload), os.SEEK_SET)
        before = os.fstat(original_fd)

        assert owner_module.read_request_bytes_from_fd(original_fd) == payload
        assert os.lseek(original_fd, 0, os.SEEK_CUR) == len(payload)
        assert _stable_metadata(os.fstat(original_fd)) == _stable_metadata(before)
        assert len(duplicate_fds) == 1
        with pytest.raises(OSError):
            os.fstat(duplicate_fds[0])
        os.fstat(original_fd)
    finally:
        os.close(original_fd)


def test_request_reader_accepts_a_fully_sealed_memfd() -> None:
    payload = b'{"opaque":"sealed-request"}'
    request_fd = _sealed_memfd(payload)
    try:
        os.lseek(request_fd, len(payload), os.SEEK_SET)
        assert owner_module.read_request_bytes_from_fd(request_fd) == payload
        assert os.lseek(request_fd, 0, os.SEEK_CUR) == len(payload)
        os.fstat(request_fd)
    finally:
        os.close(request_fd)


def test_request_reader_rejects_an_unsealed_memfd() -> None:
    if not hasattr(os, "memfd_create"):
        pytest.skip("memfd_create is unavailable")
    request_fd = os.memfd_create(
        "ga-i2d-p1a-unsealed", getattr(os, "MFD_ALLOW_SEALING", 0)
    )
    try:
        os.write(request_fd, b"{}")
        _assert_unavailable(lambda: owner_module.read_request_bytes_from_fd(request_fd))
    finally:
        os.close(request_fd)


def test_request_reader_rejects_a_partially_sealed_memfd() -> None:
    if not hasattr(os, "memfd_create"):
        pytest.skip("memfd_create is unavailable")
    request_fd = os.memfd_create(
        "ga-i2d-p1a-partial-seals", getattr(os, "MFD_ALLOW_SEALING", 0)
    )
    try:
        os.write(request_fd, b"{}")
        fcntl.fcntl(request_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE)
        _assert_unavailable(lambda: owner_module.read_request_bytes_from_fd(request_fd))
    finally:
        os.close(request_fd)


def test_request_reader_enforces_the_fixed_byte_bound(tmp_path: Path) -> None:
    exact = b"x" * owner_module._MAX_REQUEST_BYTES
    exact_fd = _regular_request_fd(tmp_path / "exact.json", exact)
    too_large_fd = _regular_request_fd(
        tmp_path / "too-large.json", exact + b"x"
    )
    try:
        assert owner_module.read_request_bytes_from_fd(exact_fd) == exact
        _assert_unavailable(
            lambda: owner_module.read_request_bytes_from_fd(too_large_fd)
        )
    finally:
        os.close(exact_fd)
        os.close(too_large_fd)


def test_request_reader_rejects_mutated_metadata_after_its_offset_zero_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_fd = _regular_request_fd(tmp_path / "mutable.json", b"request")
    original_pread = os.pread

    def mutate_after_read(fd: int, size: int, offset: int) -> bytes:
        result = original_pread(fd, size, offset)
        os.pwrite(request_fd, b"M", 0)
        return result

    monkeypatch.setattr(owner_module.os, "pread", mutate_after_read)
    try:
        _assert_unavailable(lambda: owner_module.read_request_bytes_from_fd(request_fd))
    finally:
        os.close(request_fd)


def test_request_reader_rejects_a_short_read_from_its_stable_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_fd = _regular_request_fd(tmp_path / "short-read.json", b"request")
    original_pread = os.pread

    def short_read(fd: int, size: int, offset: int) -> bytes:
        return original_pread(fd, size, offset)[:-1]

    monkeypatch.setattr(owner_module.os, "pread", short_read)
    try:
        _assert_unavailable(lambda: owner_module.read_request_bytes_from_fd(request_fd))
    finally:
        os.close(request_fd)


@pytest.mark.parametrize("bad_fd", (-1, True, "3", io.BytesIO(b"{}")))
def test_request_reader_rejects_non_exact_integer_descriptors(bad_fd: object) -> None:
    _assert_unavailable(lambda: owner_module.read_request_bytes_from_fd(bad_fd))


def test_request_reader_rejects_pipe_and_socket_descriptors() -> None:
    pipe_read, pipe_write = os.pipe()
    first_socket, second_socket = socket.socketpair()
    try:
        os.write(pipe_write, b"{}")
        _assert_unavailable(lambda: owner_module.read_request_bytes_from_fd(pipe_read))
        _assert_unavailable(
            lambda: owner_module.read_request_bytes_from_fd(first_socket.fileno())
        )
    finally:
        os.close(pipe_read)
        os.close(pipe_write)
        first_socket.close()
        second_socket.close()


def test_request_reader_closes_its_duplicate_when_rejecting_a_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe_read, pipe_write = os.pipe()
    duplicate_fds: list[int] = []
    original_dup = os.dup

    def tracking_dup(fd: int) -> int:
        duplicate = original_dup(fd)
        duplicate_fds.append(duplicate)
        return duplicate

    monkeypatch.setattr(owner_module.os, "dup", tracking_dup)
    try:
        _assert_unavailable(lambda: owner_module.read_request_bytes_from_fd(pipe_read))
        assert len(duplicate_fds) == 1
        with pytest.raises(OSError):
            os.fstat(duplicate_fds[0])
        os.fstat(pipe_read)
    finally:
        os.close(pipe_read)
        os.close(pipe_write)
