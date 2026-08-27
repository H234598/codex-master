from __future__ import annotations

import copy
import dataclasses
from dataclasses import replace
import os
from pathlib import Path
import pickle
import subprocess
import sys
from threading import Thread
from typing import Callable
import xml.etree.ElementTree as ET

import dbus
from gi.repository import GLib
import pytest

from codex_master.fleet_home_broker_runtime import BrokerReleaseSpec
from codex_master.fleet_root_runtime_host import (
    FleetRootRuntimeHost,
    FleetRootRuntimeHostError,
    RootHostParticipant,
    RootHostParticipantBinding,
    RootRuntimeActivityOwnership,
)
from codex_master.fleet_root_system_bus import (
    BUS_INTERFACE,
    BUS_METHOD,
    BUS_NAME,
    BUS_PATH,
    HomeBrokerControlService,
    RootSystemBusError,
    RootSystemBusPeerAttestation,
    _LinuxPeerOperations,
    _ProcObservation,
    _UnitObservation,
    _attest_peer,
    _openat2,
    _parse_cgroup,
    _parse_stat,
)


GENERATION = 7
PEER_LABEL = b"system_u:system_r:codex_master_control_t:s0:c1,c2"
INVOCATION = bytes.fromhex("11" * 16)


def release_spec() -> BrokerReleaseSpec:
    return BrokerReleaseSpec(
        1,
        "0.11.0",
        "1" * 64,
        "2" * 64,
        "CHPB/2",
        "policy-v1",
        "provider-v1",
        "3" * 64,
        "4" * 64,
        "codex-master-home-broker.socket",
        "codex-master-home-broker.service",
        "org.codex_master.HomeBrokerControl",
        "/org/codex_master/HomeBrokerControl",
        "org.codex_master.HomeBrokerControl1",
        "codex_master_home_broker_t",
        "codex_master_control_t",
        "codex_master_home_broker_runtime_t",
    )


def reconciled_host(generation: int = GENERATION) -> FleetRootRuntimeHost:
    host = FleetRootRuntimeHost()
    host.reconcile(
        tuple(
            RootHostParticipantBinding(participant, generation)
            for participant in RootHostParticipant
        )
    )
    return host


def raw_credentials(
    *,
    pid: int = 1234,
    uid: int = 1000,
    groups: tuple[int, ...] = (1000, 1001),
    label: bytes = PEER_LABEL,
) -> dbus.Dictionary:
    return dbus.Dictionary(
        {
            "ProcessID": dbus.UInt32(pid),
            "UnixUserID": dbus.UInt32(uid),
            "UnixGroupIDs": dbus.Array(
                (dbus.UInt32(group) for group in groups), signature="u"
            ),
            "LinuxSecurityLabel": dbus.Array(
                (dbus.Byte(byte) for byte in label + b"\0"), signature="y"
            ),
        },
        signature="sv",
    )


class ScriptedOperations:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.open_fds: set[int] = set()
        self._next_fd = 10
        self.alive = [True] * 16
        self.proc = [
            _ProcObservation(444, 1000, "/user.slice/example.scope", PEER_LABEL),
            _ProcObservation(444, 1000, "/user.slice/example.scope", PEER_LABEL),
        ]
        self.stats = [(9, 10), (9, 10)]
        self.units = [
            _UnitObservation(
                "/org/freedesktop/systemd1/unit/example_2escope",
                "example.scope",
                INVOCATION,
                "/user.slice/example.scope",
            ),
            _UnitObservation(
                "/org/freedesktop/systemd1/unit/example_2escope",
                "example.scope",
                INVOCATION,
                "/user.slice/example.scope",
            ),
        ]
        self.enforcing = True
        self.self_label = PEER_LABEL

    def _fd(self, call: str) -> int:
        self.calls.append(call)
        fd = self._next_fd
        self._next_fd += 1
        self.open_fds.add(fd)
        return fd

    def pidfd_open(self, pid: int) -> int:
        assert type(pid) is int
        return self._fd("pidfd_open")

    def require_alive(self, pidfd: int) -> None:
        assert pidfd in self.open_fds
        self.calls.append("require_alive")
        if not self.alive.pop(0):
            raise RootSystemBusError("peer_exited")

    def open_proc_root(self) -> int:
        return self._fd("open_proc_root")

    def open_cgroup_root(self) -> int:
        return self._fd("open_cgroup_root")

    def open_proc_pid(self, proc_root: int, pid: int) -> int:
        assert proc_root in self.open_fds and type(pid) is int
        return self._fd("open_proc_pid")

    def read_proc(self, proc_fd: int) -> _ProcObservation:
        assert proc_fd in self.open_fds
        self.calls.append("read_proc")
        return self.proc.pop(0)

    def open_cgroup(self, cgroup_root: int, path: str) -> int:
        assert cgroup_root in self.open_fds and type(path) is str
        return self._fd("open_cgroup")

    def cgroup_identity(self, cgroup_fd: int) -> tuple[int, int]:
        assert cgroup_fd in self.open_fds
        self.calls.append("cgroup_identity")
        return self.stats.pop(0)

    def read_unit(self, pidfd: int) -> _UnitObservation:
        assert pidfd in self.open_fds
        self.calls.append("read_unit")
        return self.units.pop(0)

    def read_enforcing(self) -> bool:
        self.calls.append("read_enforcing")
        return self.enforcing

    def read_self_label(self, proc_root: int) -> bytes:
        assert proc_root in self.open_fds
        self.calls.append("read_self_label")
        return self.self_label

    def close(self, fd: int) -> None:
        assert fd in self.open_fds
        self.calls.append("close")
        self.open_fds.remove(fd)


class PrivateBus:
    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [
                "dbus-daemon",
                "--session",
                "--nofork",
                "--print-address=1",
                "--print-pid=1",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self.process.stdout is not None
        self.address = self.process.stdout.readline().strip()
        assert self.address
        assert self.process.stdout.readline().strip().isdigit()

    def close(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=5)
        assert self.process.returncode is not None


@pytest.fixture
def private_bus() -> PrivateBus:
    bus = PrivateBus()
    try:
        yield bus
    finally:
        bus.close()


def assert_code(code: str, operation: Callable[[], object]) -> None:
    with pytest.raises(RootSystemBusError) as caught:
        operation()
    assert caught.value.code == code
    assert caught.value.args == (code,)
    assert code not in repr(caught.value)


def test_private_bus_surface_name_and_empty_signature(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    operations = ScriptedOperations()
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        lambda _attestation, _ownership: None,
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    loop_thread = Thread(target=service.run)
    loop_thread.start()
    try:
        bus = dbus.bus.BusConnection(private_bus.address)
        xml = dbus.Interface(
            bus.get_object(BUS_NAME, BUS_PATH),
            "org.freedesktop.DBus.Introspectable",
        ).Introspect()
        root = ET.fromstring(str(xml))
        methods = root.findall(f".//interface[@name='{BUS_INTERFACE}']/method")
        assert [method.attrib["name"] for method in methods] == [BUS_METHOD]
        assert methods[0].findall("arg") == []

        assert_code(
            "name_unavailable",
            lambda: HomeBrokerControlService(
                reconciled_host(),
                GENERATION,
                release_spec(),
                lambda _attestation, _ownership: None,
                private_bus_address=private_bus.address,
                _operations=ScriptedOperations(),
                _credential_reader=lambda _sender: raw_credentials(),
            ),
        )
        bus.close()
    finally:
        service.close()
        service.close()
        loop_thread.join(5)
        assert not loop_thread.is_alive()


def test_real_private_sender_credentials_and_bad_payload_blocked(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    operations = ScriptedOperations()
    seen: list[RootSystemBusPeerAttestation] = []
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        lambda attestation, _ownership: seen.append(attestation),
        private_bus_address=private_bus.address,
        _operations=operations,
    )
    loop_thread = Thread(target=service.run)
    loop_thread.start()
    try:
        script = """
import dbus, os, sys
bus = dbus.bus.BusConnection(sys.argv[1])
obj = bus.get_object(sys.argv[2], sys.argv[3])
method = obj.get_dbus_method(sys.argv[4], sys.argv[5])
try:
    method()
except dbus.DBusException as exc:
    print(exc.get_dbus_name())
print('client-complete')
bus.close()
"""
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                private_bus.address,
                BUS_NAME,
                BUS_PATH,
                BUS_METHOD,
                BUS_INTERFACE,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "client-complete" in child.stdout
        assert operations.calls[0] == "pidfd_open"

        client = dbus.bus.BusConnection(private_bus.address)
        before = host.snapshot()
        operations_before = len(operations.calls)
        for payload in (
            "principal",
            "account",
            "profile",
            "binding",
            "agent",
            "generation",
            "path",
            "mcs",
            "release",
            "unit",
            "model",
            "operations",
        ):
            message = dbus.lowlevel.MethodCallMessage(
                destination=BUS_NAME,
                path=BUS_PATH,
                interface=BUS_INTERFACE,
                method=BUS_METHOD,
            )
            message.append(payload, signature="s")
            with pytest.raises(dbus.DBusException):
                client.send_message_with_reply_and_block(message)
        assert len(operations.calls) == operations_before
        assert host.snapshot() == before
        client.close()
    finally:
        service.close()
        loop_thread.join(5)
        assert not loop_thread.is_alive()


def test_attestation_binds_credentials_kernel_pid1_and_closes_all_fds() -> None:
    operations = ScriptedOperations()
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]
    evidence = _attest_peer(
        ":1.22",
        lambda _sender: reads.pop(0),
        operations,
        release_spec(),
    )
    assert evidence.pid == 1234
    assert evidence.uid == 1000
    assert evidence.effective_gid == 1000
    assert evidence.groups == (1000, 1001)
    assert evidence.start_time == 444
    assert evidence.cgroup_device == 9
    assert evidence.cgroup_inode == 10
    assert evidence.unit_name == "example.scope"
    assert evidence.invocation_id == "11" * 16
    assert evidence.selinux_context == PEER_LABEL
    assert evidence.mcs_pair == "c1,c2"
    assert operations.calls[0] == "pidfd_open"
    assert operations.calls.count("require_alive") == 13
    assert operations.open_fds == set()
    assert reads == []


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        ("exit", "peer_exited"),
        ("credential_pid", "credential_drift"),
        ("starttime", "pid_identity_drift"),
        ("proc_label", "security_label_drift"),
        ("cgroup_path", "cgroup_binding_drift"),
        ("cgroup_inode", "cgroup_binding_drift"),
        ("unit", "unit_binding_drift"),
        ("invocation", "unit_binding_drift"),
        ("control_group", "unit_binding_drift"),
        ("not_enforcing", "selinux_not_enforcing"),
        ("gateway", "selinux_gateway_invalid"),
        ("unconfined", "selinux_peer_invalid"),
        ("mcs", "selinux_peer_invalid"),
    ),
)
def test_attestation_drift_and_policy_fail_closed(mutation: str, code: str) -> None:
    operations = ScriptedOperations()
    reads = [raw_credentials(), raw_credentials(), raw_credentials()]
    if mutation == "exit":
        operations.alive[0] = False
    elif mutation == "credential_pid":
        reads[1] = raw_credentials(pid=1235)
    elif mutation == "starttime":
        operations.proc[1] = replace(operations.proc[1], start_time=445)
    elif mutation == "proc_label":
        operations.proc[1] = replace(
            operations.proc[1],
            security_label=b"system_u:system_r:other_t:s0:c1,c2",
        )
    elif mutation == "cgroup_path":
        operations.proc[1] = replace(
            operations.proc[1], cgroup_path="/user.slice/other.scope"
        )
    elif mutation == "cgroup_inode":
        operations.stats[1] = (9, 11)
    elif mutation == "unit":
        operations.units[1] = replace(operations.units[1], name="other.scope")
    elif mutation == "invocation":
        operations.units[1] = replace(
            operations.units[1], invocation_id=bytes.fromhex("22" * 16)
        )
    elif mutation == "control_group":
        operations.units[1] = replace(
            operations.units[1], control_group="/user.slice/other.scope"
        )
    elif mutation == "not_enforcing":
        operations.enforcing = False
    elif mutation == "gateway":
        operations.self_label = b"system_u:system_r:other_t:s0:c1,c2"
    elif mutation == "unconfined":
        label = b"unconfined_u:unconfined_r:unconfined_t:s0:c1,c2"
        reads = [raw_credentials(label=label)] * 3
        operations.proc = [
            replace(item, security_label=label) for item in operations.proc
        ]
    else:
        label = b"system_u:system_r:peer_t:s0:c2,c1"
        reads = [raw_credentials(label=label)] * 3
        operations.proc = [
            replace(item, security_label=label) for item in operations.proc
        ]

    assert_code(
        code,
        lambda: _attest_peer(
            ":1.22",
            lambda _sender: reads.pop(0),
            operations,
            release_spec(),
        ),
    )
    assert operations.open_fds == set()


@pytest.mark.parametrize(
    "credentials",
    (
        {},
        {"ProcessID": True},
        {"ProcessID": dbus.UInt32(0)},
        {
            "ProcessID": dbus.UInt32(1),
            "UnixUserID": dbus.UInt32(1),
            "UnixGroupIDs": dbus.Array([], signature="u"),
            "LinuxSecurityLabel": dbus.Array([], signature="y"),
        },
        raw_credentials(groups=(1000, 1000)),
    ),
)
def test_invalid_bus_credentials_block_before_pidfd(credentials: object) -> None:
    operations = ScriptedOperations()
    assert_code(
        "credentials_invalid",
        lambda: _attest_peer(
            ":1.22", lambda _sender: credentials, operations, release_spec()
        ),
    )
    assert operations.calls == []
    assert operations.open_fds == set()


def test_proc_stat_and_cgroup_parsers_are_unambiguous() -> None:
    fields = [b"S"] + [b"1"] * 18 + [b"444"]
    assert _parse_stat(b"123 (name with ) spaces) " + b" ".join(fields)) == 444
    assert _parse_cgroup(b"0::/user.slice/example.scope\n") == (
        "/user.slice/example.scope"
    )
    for malformed in (
        b"123 no-parentheses",
        b"123 (name) S 1",
    ):
        assert_code("proc_binding_invalid", lambda value=malformed: _parse_stat(value))
    for malformed in (
        b"",
        b"1:name:/legacy\n",
        b"0::/one\n0::/two\n",
        b"0::/../escape\n",
    ):
        assert_code(
            "cgroup_binding_invalid",
            lambda value=malformed: _parse_cgroup(value),
        )


def test_openat2_rejects_symlink_and_non_directory(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    (tmp_path / "link").symlink_to(directory, target_is_directory=True)
    (tmp_path / "file").write_bytes(b"x")
    root = os.open(tmp_path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        assert_code(
            "path_binding_invalid",
            lambda: _openat2(
                root,
                "link",
                os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
            ),
        )
        assert_code(
            "path_binding_invalid",
            lambda: _openat2(
                root,
                "file",
                os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
            ),
        )
    finally:
        os.close(root)


def test_host_coordination_failure_and_success_ownership(
    private_bus: PrivateBus,
) -> None:
    operations = ScriptedOperations()
    consumer_calls: list[
        tuple[RootSystemBusPeerAttestation, RootRuntimeActivityOwnership]
    ] = []

    service = HomeBrokerControlService(
        FleetRootRuntimeHost(),
        GENERATION,
        release_spec(),
        lambda attestation, ownership: consumer_calls.append((attestation, ownership)),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("host_unavailable", lambda: service._handle_start(":1.1"))
        assert operations.calls == []
        assert consumer_calls == []
    finally:
        service.close()

    host = reconciled_host()
    service = HomeBrokerControlService(
        host,
        GENERATION + 1,
        release_spec(),
        lambda attestation, ownership: consumer_calls.append((attestation, ownership)),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("host_unavailable", lambda: service._handle_start(":1.1"))
        assert operations.calls == []
    finally:
        service.close()

    host = reconciled_host()
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        lambda attestation, ownership: consumer_calls.append((attestation, ownership)),
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        service._handle_start(":1.1")
        attestation, ownership = consumer_calls[-1]
        assert type(attestation) is RootSystemBusPeerAttestation
        assert type(ownership) is RootRuntimeActivityOwnership
        assert host.snapshot().active_principals_or_agents == 1
        host.end_principal_or_agent(ownership)
        with pytest.raises(FleetRootRuntimeHostError):
            host.end_principal_or_agent(ownership)
    finally:
        service.close()


def test_admission_stop_preserves_snapshot_and_window(
    private_bus: PrivateBus,
) -> None:
    helpers = __import__("test_fleet_root_runtime_host", fromlist=["source_snapshot"])
    host = reconciled_host()
    admission = host.stop_admission()
    window = host.open_quiescence_window(admission, helpers.source_snapshot())
    before = host.snapshot()
    operations = ScriptedOperations()
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        lambda _attestation, _ownership: pytest.fail("consumer called"),
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        assert_code("admission_stopped", lambda: service._handle_start(":1.1"))
        assert host.snapshot() == before
        evidence = host.probe_quiescence(window)
        assert evidence.runtime_broker_epoch == before.runtime_broker_epoch
        assert operations.calls == []
    finally:
        service.close()


@pytest.mark.parametrize("failure", ("attestation", "consumer"))
def test_local_failure_ends_ownership_once(
    private_bus: PrivateBus, failure: str
) -> None:
    host = reconciled_host()
    before = host.snapshot()
    operations = ScriptedOperations()
    if failure == "attestation":
        operations.enforcing = False

    def consumer(_attestation: object, _ownership: object) -> None:
        if failure == "consumer":
            raise RuntimeError("private detail")

    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        consumer,
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        expected = (
            "selinux_not_enforcing" if failure == "attestation" else "consumer_failed"
        )
        assert_code(expected, lambda: service._handle_start(":1.1"))
        after = host.snapshot()
        assert after.active_principals_or_agents == 0
        assert after.active_leases_or_reservations == 0
        assert after.pending_registry_or_broker_transactions == 0
        assert after.pending_recoveries == 0
        assert after.runtime_broker_epoch == before.runtime_broker_epoch + 2
    finally:
        service.close()


def test_close_marks_system_bus_participant_lost_and_stale_calls_block(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    operations = ScriptedOperations()
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        lambda _attestation, _ownership: None,
        private_bus_address=private_bus.address,
        _operations=operations,
        _credential_reader=lambda _sender: raw_credentials(),
    )
    service.close()
    assert host.snapshot().reconciled is False
    assert_code("service_stale", lambda: service._handle_start(":1.1"))
    assert operations.calls == []


def test_external_name_loss_marks_participant_lost_and_close_cleans(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    GLib.MainLoop()
    before = len(os.listdir("/proc/self/fd"))
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        lambda _attestation, _ownership: None,
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    service._name_owner_changed(BUS_NAME, service._bus.get_unique_name(), "")
    assert host.snapshot().reconciled is False
    assert_code("service_stale", lambda: service._handle_start(":1.1"))
    service.close()
    assert len(os.listdir("/proc/self/fd")) == before


def test_successful_nonprincipal_activity_invalidates_existing_window() -> None:
    helpers = __import__("test_fleet_root_runtime_host", fromlist=["source_snapshot"])
    host = reconciled_host()
    admission = host.stop_admission()
    window = host.open_quiescence_window(admission, helpers.source_snapshot())
    ownership = host.begin_recovery()
    with pytest.raises(FleetRootRuntimeHostError) as caught:
        host.probe_quiescence(window)
    assert caught.value.code == "quiescence_epoch_drift"
    host.end_recovery(ownership)


def test_handoff_is_nontransferable_and_forge_never_reaches_consumer(
    private_bus: PrivateBus,
) -> None:
    host = reconciled_host()
    received: list[
        tuple[RootSystemBusPeerAttestation, RootRuntimeActivityOwnership]
    ] = []
    service = HomeBrokerControlService(
        host,
        GENERATION,
        release_spec(),
        lambda attestation, ownership: received.append((attestation, ownership)),
        private_bus_address=private_bus.address,
        _operations=ScriptedOperations(),
        _credential_reader=lambda _sender: raw_credentials(),
    )
    try:
        service._handle_start(":1.1")
        attestation, ownership = received.pop()
        assert repr(attestation) == "<RootSystemBusPeerAttestation redacted>"
        assert str(attestation) == repr(attestation)
        for operation in (
            lambda: RootSystemBusPeerAttestation(),
            lambda: copy.copy(attestation),
            lambda: copy.deepcopy(attestation),
            lambda: pickle.dumps(attestation),
            lambda: dataclasses.replace(attestation),
        ):
            with pytest.raises(TypeError):
                operation()

        forged = object.__new__(RootSystemBusPeerAttestation)
        for field in dataclasses.fields(attestation):
            object.__setattr__(forged, field.name, getattr(attestation, field.name))
        assert_code(
            "handoff_invalid",
            lambda: service._handoff(forged, ownership, object()),
        )
        assert received == []
        host.end_principal_or_agent(ownership)
    finally:
        service.close()


def test_real_pidfd_proc_cgroup_systemd_selinux_negative_has_no_fd_leak() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"],
        stdin=subprocess.PIPE,
    )
    try:
        groups = tuple(sorted(set(os.getgroups() + [os.getegid()])))
        label = Path(f"/proc/{child.pid}/attr/current").read_bytes().rstrip(b"\0\n")
        credentials = raw_credentials(
            pid=child.pid, uid=os.getuid(), groups=groups, label=label
        )
        system_bus = dbus.SystemBus(private=True)
        operations = _LinuxPeerOperations(system_bus)
        before = len(os.listdir("/proc/self/fd"))
        with pytest.raises(RootSystemBusError) as caught:
            _attest_peer(
                ":1.1",
                lambda _sender: credentials,
                operations,
                release_spec(),
            )
        assert caught.value.code in {
            "unit_binding_invalid",
            "selinux_gateway_invalid",
        }
        after = len(os.listdir("/proc/self/fd"))
        assert after == before
        system_bus.close()
    finally:
        assert child.stdin is not None
        child.stdin.write(b"x")
        child.stdin.close()
        child.wait(timeout=5)
