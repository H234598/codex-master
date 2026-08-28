from __future__ import annotations

import errno

import pytest

from codex_master.fleet_home_broker_identity import ObjectIdentity
from codex_master.fleet_home_broker_protocol import CANONICAL_AGENT_HOME
from codex_master.fleet_home_broker_linux import (
    O_CLOEXEC,
    REQUIRED_RESOLVE_FLAGS,
    IdmappedMountContract,
    LinuxBrokerCode,
    LinuxBrokerError,
    LinuxPlatformContract,
    OpenHow,
    PinnedFd,
    SystemdUnitEvidence,
    open_beneath_no_symlink,
    pin_peer_cgroup,
    rename_noreplace_and_fsync_parent,
    require_linux_platform,
    validate_idmapped_mount_contract,
)


SLOT_IDENTITY = ObjectIdentity(8, 101, 0o40700, 0, 0, 2)
CGROUP_IDENTITY = ObjectIdentity(8, 202, 0o40755, 0, 0, 2)
UNIT = SystemdUnitEvidence("codex-agent@bee_1.service", "a" * 32, CGROUP_IDENTITY, 4, "c10,c20")


class FakeOps:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.alive_results = [True, True]
        self.cgroup_name = "workload"
        self.cgroup_identity = CGROUP_IDENTITY
        self.open_result = PinnedFd(41, SLOT_IDENTITY)
        self.rename_error: BaseException | None = None

    def openat2(self, parent_fd: int, name: str, how: OpenHow) -> PinnedFd:
        self.calls.append(("openat2", parent_fd, name, how))
        if isinstance(self.open_result, BaseException):
            raise self.open_result
        return self.open_result

    def pidfd_open(self, pid: int) -> int:
        self.calls.append(("pidfd_open", pid))
        return 11

    def pidfd_alive(self, pidfd: int) -> bool:
        self.calls.append(("pidfd_alive", pidfd))
        return self.alive_results.pop(0)

    def open_proc_directory(self, pidfd: int) -> int:
        self.calls.append(("open_proc_directory", pidfd))
        return 12

    def read_cgroup_v2(self, proc_fd: int) -> str:
        self.calls.append(("read_cgroup_v2", proc_fd))
        return self.cgroup_name

    def open_cgroup_directory(self, proc_fd: int, name: str) -> int:
        self.calls.append(("open_cgroup_directory", proc_fd, name))
        return 13

    def stat_fd(self, fd: int) -> ObjectIdentity:
        self.calls.append(("stat_fd", fd))
        return self.cgroup_identity

    def fsync(self, fd: int) -> None:
        self.calls.append(("fsync", fd))

    def renameat2_noreplace(self, parent_fd: int, staging_name: str, final_name: str) -> None:
        self.calls.append(("renameat2_noreplace", parent_fd, staging_name, final_name))
        if self.rename_error is not None:
            raise self.rename_error

    def close(self, fd: int) -> None:
        self.calls.append(("close", fd))


def expect_code(code: LinuxBrokerCode, action) -> None:
    with pytest.raises(LinuxBrokerError) as raised:
        action()
    assert raised.value.code is code


def test_require_linux_platform_is_fail_closed_and_bool_exact() -> None:
    valid = LinuxPlatformContract(True, True, True, True)
    assert require_linux_platform(valid) is valid
    for value in (
        LinuxPlatformContract(False, True, True, True),
        LinuxPlatformContract(True, False, True, True),
        LinuxPlatformContract(True, True, False, True),
        LinuxPlatformContract(True, True, True, False),
        LinuxPlatformContract(1, True, True, True),
        object(),
    ):
        expect_code(LinuxBrokerCode.UNSUPPORTED_PLATFORM, lambda value=value: require_linux_platform(value))


def test_open_beneath_uses_one_openat2_with_all_guards_and_cloexec() -> None:
    ops = FakeOps()
    pinned = open_beneath_no_symlink(ops, 7, "slot", flags=0)
    assert pinned is ops.open_result
    assert ops.calls == [("openat2", 7, "slot", OpenHow(O_CLOEXEC, 0, REQUIRED_RESOLVE_FLAGS))]


@pytest.mark.parametrize("name", ("", ".", "..", "/slot", "../slot", "slot/child", "slot\x00"))
def test_open_beneath_rejects_unsafe_component_before_adapter_call(name: str) -> None:
    ops = FakeOps()
    expect_code(LinuxBrokerCode.UNSAFE_PATH, lambda: open_beneath_no_symlink(ops, 7, name, flags=0))
    assert ops.calls == []


@pytest.mark.parametrize(
    ("error", "code"),
    (
        (OSError(errno.EXDEV, "cross-device"), LinuxBrokerCode.CROSS_DEVICE),
        (OSError(errno.ELOOP, "symlink"), LinuxBrokerCode.UNSAFE_PATH),
        (NotImplementedError(), LinuxBrokerCode.UNSUPPORTED_PLATFORM),
        (OSError(errno.EIO, "io"), LinuxBrokerCode.IO_FAILURE),
    ),
)
def test_open_beneath_maps_openat2_failures_without_fallback(error: BaseException, code: LinuxBrokerCode) -> None:
    ops = FakeOps()
    ops.open_result = error
    expect_code(code, lambda: open_beneath_no_symlink(ops, 7, "slot", flags=0))
    assert [call[0] for call in ops.calls] == ["openat2"]


def test_open_beneath_rejects_an_unpinned_adapter_result() -> None:
    ops = FakeOps()
    ops.open_result = 41  # type: ignore[assignment]
    expect_code(LinuxBrokerCode.IO_FAILURE, lambda: open_beneath_no_symlink(ops, 7, "slot", flags=0))


def test_pin_peer_cgroup_requires_liveness_before_and_after_and_exact_inode() -> None:
    ops = FakeOps()
    evidence = pin_peer_cgroup(ops, 4242, UNIT)
    assert evidence.pid == 4242
    assert evidence.cgroup == CGROUP_IDENTITY
    assert evidence.invocation_id == UNIT.invocation_id
    assert [call[0] for call in ops.calls] == [
        "pidfd_open",
        "pidfd_alive",
        "open_proc_directory",
        "read_cgroup_v2",
        "open_cgroup_directory",
        "stat_fd",
        "pidfd_alive",
        "close",
        "close",
        "close",
    ]


def test_pin_peer_cgroup_rejects_stale_before_read_and_after_read() -> None:
    before = FakeOps()
    before.alive_results = [False]
    expect_code(LinuxBrokerCode.STALE_PEER, lambda: pin_peer_cgroup(before, 4242, UNIT))
    assert [call[0] for call in before.calls] == ["pidfd_open", "pidfd_alive", "close"]

    after = FakeOps()
    after.alive_results = [True, False]
    expect_code(LinuxBrokerCode.STALE_PEER, lambda: pin_peer_cgroup(after, 4242, UNIT))
    assert "read_cgroup_v2" in [call[0] for call in after.calls]
    assert [call[0] for call in after.calls][-4:] == ["pidfd_alive", "close", "close", "close"]


def test_pin_peer_cgroup_rejects_mismatched_or_unsafe_evidence() -> None:
    mismatch = FakeOps()
    mismatch.cgroup_identity = ObjectIdentity(8, 203, 0o40755, 0, 0, 2)
    expect_code(LinuxBrokerCode.IDENTITY_MISMATCH, lambda: pin_peer_cgroup(mismatch, 4242, UNIT))

    unsafe = FakeOps()
    unsafe.cgroup_name = "../escape"
    expect_code(LinuxBrokerCode.UNSAFE_PATH, lambda: pin_peer_cgroup(unsafe, 4242, UNIT))

    malformed = FakeOps()
    malformed.cgroup_identity = object()  # type: ignore[assignment]
    expect_code(LinuxBrokerCode.IDENTITY_MISMATCH, lambda: pin_peer_cgroup(malformed, 4242, UNIT))


def test_pin_peer_cgroup_closes_pinned_fds_when_an_adapter_read_fails() -> None:
    ops = FakeOps()
    ops.read_cgroup_v2 = lambda proc_fd: (_ for _ in ()).throw(OSError(errno.EIO, "read"))  # type: ignore[method-assign]
    expect_code(LinuxBrokerCode.IO_FAILURE, lambda: pin_peer_cgroup(ops, 4242, UNIT))
    assert [call[0] for call in ops.calls][-2:] == ["close", "close"]


def test_idmapped_mount_contract_is_immutable_data_validation_only() -> None:
    source = ObjectIdentity(8, 303, 0o40700, 0, 0, 2)
    valid = IdmappedMountContract(source, CANONICAL_AGENT_HOME, "c10,c20", True, True)
    assert validate_idmapped_mount_contract(valid) is valid
    for value, code in (
        (IdmappedMountContract(source, "/tmp/home", "c10,c20", True, True), LinuxBrokerCode.UNSAFE_PATH),
        (IdmappedMountContract(source, CANONICAL_AGENT_HOME, "c20,c10", True, True), LinuxBrokerCode.IDENTITY_MISMATCH),
        (IdmappedMountContract(source, CANONICAL_AGENT_HOME, "c10,c20", False, True), LinuxBrokerCode.IDENTITY_MISMATCH),
        (IdmappedMountContract(source, CANONICAL_AGENT_HOME, "c10,c20", True, False), LinuxBrokerCode.IDENTITY_MISMATCH),
        (IdmappedMountContract(source, CANONICAL_AGENT_HOME, "c10,c20", 1, True), LinuxBrokerCode.IDENTITY_MISMATCH),
    ):
        expect_code(code, lambda value=value: validate_idmapped_mount_contract(value))
    expect_code(LinuxBrokerCode.IDENTITY_MISMATCH, lambda: validate_idmapped_mount_contract(object()))
    expect_code(
        LinuxBrokerCode.IDENTITY_MISMATCH,
        lambda: validate_idmapped_mount_contract(
            IdmappedMountContract(object(), CANONICAL_AGENT_HOME, "c10,c20", True, True),  # type: ignore[arg-type]
        ),
    )


def test_rename_noreplace_calls_only_noreplace_then_exact_parent_fsync() -> None:
    ops = FakeOps()
    assert rename_noreplace_and_fsync_parent(ops, 7, "staging", "final") is None
    assert [call[0] for call in ops.calls] == ["renameat2_noreplace", "fsync"]
    assert ops.calls[1] == ("fsync", 7)


@pytest.mark.parametrize(
    ("error", "code"),
    (
        (FileExistsError(errno.EEXIST, "exists"), LinuxBrokerCode.ALREADY_EXISTS),
        (NotImplementedError(), LinuxBrokerCode.UNSUPPORTED_PLATFORM),
        (OSError(errno.ENOSYS, "missing"), LinuxBrokerCode.UNSUPPORTED_PLATFORM),
        (OSError(errno.EIO, "io"), LinuxBrokerCode.IO_FAILURE),
    ),
)
def test_rename_noreplace_has_no_fallback_on_any_failure(error: BaseException, code: LinuxBrokerCode) -> None:
    ops = FakeOps()
    ops.rename_error = error
    expect_code(code, lambda: rename_noreplace_and_fsync_parent(ops, 7, "staging", "final"))
    assert [call[0] for call in ops.calls] == ["renameat2_noreplace"]


def test_rename_noreplace_reports_parent_fsync_failure_after_single_publish() -> None:
    ops = FakeOps()
    ops.fsync = lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "fsync"))  # type: ignore[method-assign]
    expect_code(LinuxBrokerCode.IO_FAILURE, lambda: rename_noreplace_and_fsync_parent(ops, 7, "staging", "final"))
    assert [call[0] for call in ops.calls] == ["renameat2_noreplace"]


@pytest.mark.parametrize("name", ("", ".", "..", "../escape", "nested/name", "/absolute"))
def test_rename_rejects_unsafe_relative_names_before_adapter_call(name: str) -> None:
    ops = FakeOps()
    expect_code(LinuxBrokerCode.UNSAFE_PATH, lambda: rename_noreplace_and_fsync_parent(ops, 7, name, "final"))
    assert ops.calls == []
