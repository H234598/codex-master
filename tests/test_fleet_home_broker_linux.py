import ast
import dataclasses
import inspect
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import codex_master.fleet_home_broker_linux as linux
from codex_master.fleet_home_broker_linux import (
    AgentStartPeerObservation,
    FdStat,
    LinuxBoundaryError,
    LinuxOperations,
    PeerSnapshot,
    PidfdIdentity,
    attest_peer_principal,
    open_pinned_child_directory,
    observe_agent_start_peer,
)
from codex_master.fleet_home_broker_protocol import (
    AgentStartEnvironmentProjection,
    AgentStartEnvelope,
    AgentStartExecutablePin,
    BindingExpectation,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    MAX_CHPB_DEVICE,
    MAX_CHPB_GENERATION,
    MAX_CHPB_INODE,
    DirectoryIdentity,
    PrincipalBinding,
    HomeAttestation,
    PolicyBinding,
    TransactionBinding,
    ChpbTransactionOperation,
)
from codex_master.fleet_control_release_v2 import (
    ControlReleaseSpecV2,
    ReleasePayloadDigestV2,
)
from codex_master.fleet_home_broker_identity import BrokerIdentity


CHILD_FD = 41
PID_FD = 73
PROC_FD = 83
CGROUP_FD = 97
PEER_PID = 1234
PID_START_TIME = 7
UNIT_NAME = "session-7.scope"
CONTROL_GROUP = f"/user.slice/user-1000.slice/{UNIT_NAME}"
EXPECTED_DIRECTORY = DirectoryIdentity(17, 29, 0o40700)
EXPECTED_STAT = FdStat(17, 29, 0o40700, 0, 0)
VALID_CGROUP_STAT = FdStat(17, 29, 0o40755, 1000, 1000)
EXPECTED_PID_IDENTITY = PidfdIdentity(PEER_PID, PID_START_TIME)
EXPECTED_SELINUX_CONTEXT = (
    "system_u:system_r:codex_master_agent_t:s0:c0,c1"
)


def principal(**changes):
    values = {
        "agent_id": "bee_1",
        "manifest_generation": 3,
        "unit_generation": 9,
        "cgroup_dev": 17,
        "cgroup_ino": 29,
        "invocation_id": "1" * 32,
        "mcs_pair": "c0,c1",
        "fencing_epoch": 4,
    }
    values.update(changes)
    return PrincipalBinding(**values)


def snapshot(**changes):
    values = {
        "pid": PEER_PID,
        "cgroup_dev": 17,
        "cgroup_ino": 29,
        "invocation_id": "1" * 32,
        "unit_generation": 9,
        "mcs_pair": "c0,c1",
    }
    values.update(changes)
    return PeerSnapshot(**values)


def agent_start_envelope():
    expected_principal = principal()
    expected_policy = PolicyBinding(7, "a" * 64)
    transaction_binding = TransactionBinding(
        ChpbTransactionOperation.PROVISION,
        "2" * 32,
        "3" * 32,
        expected_principal,
        expected_policy,
    )
    attestation = HomeAttestation(
        transaction_binding,
        "/run/codex-master-agent/home",
        DirectoryIdentity(0, 1, 0o40700),
        "a" * 64,
        expected_principal.mcs_pair,
    )
    release = ControlReleaseSpecV2(
        2,
        "0.10.5",
        (
            ReleasePayloadDigestV2("python_runtime", "1" * 64),
            ReleasePayloadDigestV2("root_helpers", "2" * 64),
            ReleasePayloadDigestV2("selinux_policy", "3" * 64),
            ReleasePayloadDigestV2("systemd_units", "4" * 64),
        ),
        CHPB_PROTOCOL,
        "org.codex_master.HomeBrokerControl2",
        "StartDynamicTeamlead",
        "codex-master-agent@.service",
        "/usr/libexec/codex-master-agent-launcher",
    )
    return AgentStartEnvelope(
        CHPB_PROTOCOL,
        ChpbMessageKind.AGENT_START_ENVELOPE,
        "5" * 32,
        release,
        "0.10.5",
        13,
        expected_principal,
        BindingExpectation("bee_1", 3, 9, 7, "a" * 64, 4),
        "codex-master-agent@c0\\x2cc1.service",
        BrokerIdentity(
            "bee_1",
            3,
            "c0,c1",
            "slot-1",
            7,
            "a" * 64,
            "b" * 64,
            4,
        ),
        AgentStartExecutablePin(
            "/usr/libexec/codex-master-agent-launcher", "b" * 64
        ),
        AgentStartEnvironmentProjection(
            (
                ("CODEX_HOME", "/run/codex-master-agent/home"),
                ("GEMINI_CLI_HOME", "/run/codex-master-agent/home"),
                ("HOME", "/run/codex-master-agent/home"),
            )
        ),
        attestation,
    )


class FakeOperations:
    def __init__(
        self,
        *,
        directory_stat=EXPECTED_STAT,
        cgroup_stat=VALID_CGROUP_STAT,
        operation_errors=None,
        proc_control_group=CONTROL_GROUP,
        pid1_unit_name=UNIT_NAME,
        pid1_control_group=CONTROL_GROUP,
        pid1_unit_generation=9,
        pid1_invocation_id="1" * 32,
        peer_mcs_pair="c0,c1",
        pid_identity=EXPECTED_PID_IDENTITY,
        reuse_at=None,
        reuse_pid=None,
        fresh_identity_per_reuse=False,
        pidfd_value=PID_FD,
        proc_fd_value=PROC_FD,
        cgroup_fd_value=CGROUP_FD,
    ):
        self.calls = []
        self.directory_stat = directory_stat
        self.cgroup_stat = cgroup_stat
        self.operation_errors = dict(operation_errors or {})
        self.proc_control_group = proc_control_group
        self.pid1_unit_name = pid1_unit_name
        self.pid1_control_group = pid1_control_group
        self.pid1_unit_generation = pid1_unit_generation
        self.pid1_invocation_id = pid1_invocation_id
        self.peer_mcs_pair = peer_mcs_pair
        self.pid_identity = pid_identity
        self.reuse_at = reuse_at
        self.reuse_pid = reuse_pid
        self.fresh_identity_per_reuse = fresh_identity_per_reuse
        self.pidfd_value = pidfd_value
        self.proc_fd_value = proc_fd_value
        self.cgroup_fd_value = cgroup_fd_value
        self.reuse_checks = 0
        self.observed_identities = []

    def _raise_if_configured(self, name):
        error = self.operation_errors.get(name)
        if error is not None:
            raise error

    def openat2(self, parent_fd, child_name, flags, resolve):
        self.calls.append(("openat2", parent_fd, child_name, flags, resolve))
        return CHILD_FD

    def fstat(self, fd):
        self.calls.append(("fstat", fd))
        self._raise_if_configured("fstat")
        return self.directory_stat if fd == CHILD_FD else self.cgroup_stat

    def close(self, fd):
        self.calls.append(("close", fd))

    def pidfd_open(self, pid, flags):
        self.calls.append(("pidfd_open", pid, flags))
        self._raise_if_configured("pidfd_open")
        return self.pidfd_value

    def pidfd_reuse_check(self, pidfd, pid, proc_fd, cgroup_fd, identity):
        self.calls.append(
            ("pidfd_reuse_check", pidfd, pid, proc_fd, cgroup_fd, identity)
        )
        self._raise_if_configured("pidfd_reuse_check")
        self.reuse_checks += 1
        if self.reuse_checks == self.reuse_at:
            observed = PidfdIdentity(
                self.reuse_pid if self.reuse_pid is not None else self.pid_identity.pid,
                self.pid_identity.start_time + 1,
            )
        elif self.fresh_identity_per_reuse:
            observed = PidfdIdentity(
                self.pid_identity.pid, self.pid_identity.start_time
            )
        else:
            observed = self.pid_identity
        self.observed_identities.append(observed)
        return observed

    def open_pinned_proc_pid(self, pidfd, pid, identity):
        self.calls.append(("open_pinned_proc_pid", pidfd, pid, identity))
        self._raise_if_configured("open_pinned_proc_pid")
        return self.proc_fd_value

    def open_proc_cgroup(self, pidfd, proc_fd, identity):
        self.calls.append(("open_proc_cgroup", pidfd, proc_fd, identity))
        self._raise_if_configured("open_proc_cgroup")
        return self.cgroup_fd_value

    def read_proc_control_group(
        self, pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
    ):
        self.calls.append(
            (
                "read_proc_control_group",
                pidfd,
                proc_fd,
                cgroup_fd,
                cgroup_dev,
                cgroup_ino,
            )
        )
        self._raise_if_configured("read_proc_control_group")
        return self.proc_control_group

    def read_pid1_unit_name(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            ("read_pid1_unit_name", pidfd, cgroup_fd, cgroup_dev, cgroup_ino)
        )
        self._raise_if_configured("read_pid1_unit_name")
        return self.pid1_unit_name

    def read_pid1_unit_generation(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            (
                "read_pid1_unit_generation",
                pidfd,
                cgroup_fd,
                cgroup_dev,
                cgroup_ino,
            )
        )
        self._raise_if_configured("read_pid1_unit_generation")
        return self.pid1_unit_generation

    def read_pid1_invocation_id(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            (
                "read_pid1_invocation_id",
                pidfd,
                cgroup_fd,
                cgroup_dev,
                cgroup_ino,
            )
        )
        self._raise_if_configured("read_pid1_invocation_id")
        return self.pid1_invocation_id

    def read_pid1_control_group(self, pidfd, cgroup_fd, cgroup_dev, cgroup_ino):
        self.calls.append(
            (
                "read_pid1_control_group",
                pidfd,
                cgroup_fd,
                cgroup_dev,
                cgroup_ino,
            )
        )
        self._raise_if_configured("read_pid1_control_group")
        return self.pid1_control_group

    def read_peer_mcs_pair(
        self, pidfd, proc_fd, cgroup_fd, cgroup_dev, cgroup_ino
    ):
        self.calls.append(
            (
                "read_peer_mcs_pair",
                pidfd,
                proc_fd,
                cgroup_fd,
                cgroup_dev,
                cgroup_ino,
            )
        )
        self._raise_if_configured("read_peer_mcs_pair")
        return self.peer_mcs_pair


def test_linux_value_types_are_frozen_and_slotted():
    for value in (EXPECTED_STAT, snapshot(), EXPECTED_PID_IDENTITY):
        klass = type(value)
        assert dataclasses.is_dataclass(value)
        assert klass.__dataclass_params__.frozen
        assert hasattr(klass, "__slots__")
        assert not hasattr(value, "__dict__")
        field = klass.__slots__[0]
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, None)


def test_open_pinned_child_directory_uses_exact_openat2_contract():
    operations = FakeOperations()

    assert open_pinned_child_directory(operations, 11, "child", EXPECTED_DIRECTORY) == CHILD_FD
    assert operations.calls == [
        (
            "openat2",
            11,
            "child",
            0o10000000 | 0o200000 | 0o400000 | 0o2000000,
            0x08 | 0x04 | 0x02,
        ),
        ("fstat", CHILD_FD),
    ]


@pytest.mark.parametrize(
    "expected",
    [
        DirectoryIdentity(True, 29, 0o40700),
        DirectoryIdentity(17, True, 0o40700),
        DirectoryIdentity(-1, 29, 0o40700),
        DirectoryIdentity(17, 0, 0o40700),
        DirectoryIdentity(MAX_CHPB_DEVICE + 1, 29, 0o40700),
        DirectoryIdentity(17, MAX_CHPB_INODE + 1, 0o40700),
        DirectoryIdentity(17, 29, 0o40701),
    ],
)
def test_invalid_expected_directory_identity_calls_no_operations(expected):
    operations = FakeOperations()

    with pytest.raises(LinuxBoundaryError):
        open_pinned_child_directory(operations, 11, "child", expected)

    assert operations.calls == []


@pytest.mark.parametrize(
    "observed",
    [
        FdStat(True, 29, 0o40700, 0, 0),
        FdStat(17, True, 0o40700, 0, 0),
        FdStat(-1, 29, 0o40700, 0, 0),
        FdStat(17, 0, 0o40700, 0, 0),
        FdStat(MAX_CHPB_DEVICE + 1, 29, 0o40700, 0, 0),
        FdStat(17, MAX_CHPB_INODE + 1, 0o40700, 0, 0),
        FdStat(17, 29, True, 0, 0),
        FdStat(17, 29, 0o40701, 0, 0),
        FdStat(17, 29, 0o40700, True, 0),
        FdStat(17, 29, 0o40700, 0, True),
        object(),
    ],
)
def test_invalid_observed_fd_stat_closes_child_fd(observed):
    operations = FakeOperations(directory_stat=observed)

    with pytest.raises(LinuxBoundaryError):
        open_pinned_child_directory(operations, 11, "child", EXPECTED_DIRECTORY)

    assert operations.calls[-1] == ("close", CHILD_FD)


@pytest.mark.parametrize("child_name", ["", ".", "..", "a/b", "a\\b", "a\x00b", "/absolute"])
def test_invalid_child_names_call_no_operations(child_name):
    operations = FakeOperations()

    with pytest.raises(LinuxBoundaryError):
        open_pinned_child_directory(operations, 11, child_name, EXPECTED_DIRECTORY)

    assert operations.calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dev", 18),
        ("ino", 30),
        ("mode", 0o40701),
        ("uid", 1),
        ("gid", 1),
    ],
)
def test_directory_identity_drift_closes_child_fd(field, value):
    operations = FakeOperations(
        directory_stat=dataclasses.replace(EXPECTED_STAT, **{field: value})
    )

    with pytest.raises(LinuxBoundaryError):
        open_pinned_child_directory(operations, 11, "child", EXPECTED_DIRECTORY)

    assert operations.calls[-1] == ("close", CHILD_FD)


def test_fstat_error_closes_child_fd():
    operations = FakeOperations(operation_errors={"fstat": OSError("fstat failed")})

    with pytest.raises(LinuxBoundaryError):
        open_pinned_child_directory(operations, 11, "child", EXPECTED_DIRECTORY)

    assert operations.calls[-1] == ("close", CHILD_FD)


@pytest.mark.parametrize("peer_pid", [-1, 0, True, "1234", None])
def test_invalid_peer_pid_calls_no_operations(peer_pid):
    operations = FakeOperations()

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, peer_pid, principal())

    assert operations.calls == []


def _reuse_check_call(proc_fd, cgroup_fd, identity):
    return ("pidfd_reuse_check", PID_FD, PEER_PID, proc_fd, cgroup_fd, identity)


def _bound_cgroup_call(name, *values):
    return (name, PID_FD, *values, 17, 29)


def test_attestation_uses_pidfd_identity_and_exact_bound_call_order():
    operations = FakeOperations()
    identity = EXPECTED_PID_IDENTITY

    assert attest_peer_principal(operations, PEER_PID, principal()) == snapshot()
    assert operations.calls == [
        ("pidfd_open", PEER_PID, 0),
        _reuse_check_call(None, None, None),
        ("open_pinned_proc_pid", PID_FD, PEER_PID, identity),
        _reuse_check_call(PROC_FD, None, identity),
        ("open_proc_cgroup", PID_FD, PROC_FD, identity),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        ("fstat", CGROUP_FD),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _bound_cgroup_call("read_proc_control_group", PROC_FD, CGROUP_FD),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _bound_cgroup_call("read_pid1_unit_name", CGROUP_FD),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _bound_cgroup_call("read_pid1_unit_generation", CGROUP_FD),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _bound_cgroup_call("read_pid1_invocation_id", CGROUP_FD),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _bound_cgroup_call("read_pid1_control_group", CGROUP_FD),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        _bound_cgroup_call("read_peer_mcs_pair", PROC_FD, CGROUP_FD),
        _reuse_check_call(PROC_FD, CGROUP_FD, identity),
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


def test_private_attestation_returns_only_final_validated_identity():
    operations = FakeOperations(fresh_identity_per_reuse=True)

    observed_snapshot, final_identity = linux._attest_peer_principal_with_identity(
        operations, PEER_PID, principal()
    )

    assert observed_snapshot == snapshot()
    assert operations.reuse_checks == 16
    assert final_identity is operations.observed_identities[-1]
    assert "_attest_peer_principal_with_identity" not in linux.__all__
    public_operations = FakeOperations()
    assert attest_peer_principal(public_operations, PEER_PID, principal()) == snapshot()
    assert public_operations.reuse_checks == 16


def test_private_root_owned_snapshot_exposes_only_final_attested_five_values():
    operations = FakeOperations(fresh_identity_per_reuse=True)

    observed, identity = linux._observe_peer_snapshot_with_identity(
        operations, PEER_PID
    )

    assert observed == snapshot()
    assert identity is operations.observed_identities[-1]
    assert operations.reuse_checks == 16
    assert "_observe_peer_snapshot_with_identity" not in linux.__all__
    assert observed.cgroup_dev == VALID_CGROUP_STAT.dev
    assert observed.cgroup_ino == VALID_CGROUP_STAT.ino
    assert observed.invocation_id == operations.pid1_invocation_id
    assert observed.unit_generation == operations.pid1_unit_generation
    assert observed.mcs_pair == operations.peer_mcs_pair


@pytest.mark.parametrize(
    "changes",
    [
        {"cgroup_stat": FdStat(17, 29, 0o100644, 1000, 1000)},
        {"pid1_unit_generation": True},
        {"pid1_invocation_id": "not-a-digest"},
        {"peer_mcs_pair": "c1,c0"},
        {"pid1_control_group": "/user.slice/user-1000.slice/wrong.scope"},
        {"reuse_at": 16},
    ],
)
def test_private_root_owned_snapshot_rejects_invalid_or_drifting_values(changes):
    operations = FakeOperations(**changes)

    with pytest.raises(LinuxBoundaryError):
        linux._observe_peer_snapshot_with_identity(operations, PEER_PID)

    assert [call for call in operations.calls if call[0] == "close"] == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


def test_root_owned_snapshot_source_keeps_linux_api_and_guard_contract():
    source = Path(linux.__file__).read_text()
    tree = ast.parse(source)
    observers = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_observe_peer_snapshot_with_identity"
    ]

    assert len(observers) == 1
    observer = observers[0]
    observer_guards = [
        node
        for node in ast.walk(observer)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_pidfd_guard"
    ]
    assert len(observer_guards) == 16

    private_attestation = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_attest_peer_principal_with_identity"
    )
    observer_calls = [
        node
        for node in ast.walk(private_attestation)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_observe_peer_snapshot_with_identity"
    ]
    assert len(observer_calls) == 1
    assert [argument.arg for argument in observer.args.args] == [
        "operations",
        "peer_pid",
    ]
    assert observer.args.posonlyargs == []
    assert observer.args.kwonlyargs == []
    assert observer.args.vararg is None
    assert observer.args.kwarg is None
    assert observer.args.defaults == []
    assert observer.args.kw_defaults == []

    validation_calls = [
        node
        for node in ast.walk(private_attestation)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_validate_principal"
    ]
    assert len(validation_calls) == 1
    assert validation_calls[0].lineno < observer_calls[0].lineno
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "operations"
        for node in ast.walk(private_attestation)
    )

    protocol = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "LinuxOperations"
    )
    assert [
        node.name for node in protocol.body if isinstance(node, ast.FunctionDef)
    ] == [
        "openat2",
        "fstat",
        "close",
        "pidfd_open",
        "pidfd_reuse_check",
        "open_pinned_proc_pid",
        "open_proc_cgroup",
        "read_proc_control_group",
        "read_pid1_unit_name",
        "read_pid1_unit_generation",
        "read_pid1_invocation_id",
        "read_pid1_control_group",
        "read_peer_mcs_pair",
    ]
    assert linux.__all__ == [
        "AgentStartPeerObservation",
        "FdStat",
        "LinuxBoundaryError",
        "LinuxOperations",
        "PeerSnapshot",
        "PidfdIdentity",
        "SAFE_DIRECTORY_MODE",
        "attest_peer_principal",
        "open_pinned_child_directory",
        "observe_agent_start_peer",
    ]


def test_same_pid_reuse_with_new_start_identity_closes_all_peer_fds():
    operations = FakeOperations(reuse_at=5)

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, PEER_PID, principal())

    assert operations.calls[-3:] == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"pid": PEER_PID + 1},
        {"cgroup_dev": 18},
        {"cgroup_ino": 30},
        {"invocation_id": "2" * 32},
        {"unit_generation": 10},
        {"mcs_pair": "c0,c2"},
    ],
)
def test_snapshot_drift_closes_all_peer_fds(changes):
    kwargs = {
        "pid1_unit_generation": changes.get("unit_generation", 9),
        "pid1_invocation_id": changes.get("invocation_id", "1" * 32),
        "peer_mcs_pair": changes.get("mcs_pair", "c0,c1"),
        "cgroup_stat": dataclasses.replace(
            VALID_CGROUP_STAT,
            dev=changes.get("cgroup_dev", 17),
            ino=changes.get("cgroup_ino", 29),
        ),
    }
    if "pid" in changes:
        kwargs.update({"reuse_at": 5, "reuse_pid": changes["pid"]})
    operations = FakeOperations(**kwargs)

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, PEER_PID, principal())

    assert operations.calls[-3:] == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


def test_invalid_principal_binding_contract_stops_before_linux_operations():
    operations = FakeOperations()

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, PEER_PID, principal(agent_id="not valid"))

    assert operations.calls == []
    assert tuple(inspect.signature(attest_peer_principal).parameters) == (
        "operations",
        "peer_pid",
        "expected_principal",
    )


def test_invalid_snapshot_field_closes_all_peer_fds():
    operations = FakeOperations(peer_mcs_pair=object())

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, PEER_PID, principal())

    assert operations.calls[-3:] == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("pid", 0),
        ("cgroup_dev", True),
        ("cgroup_dev", -1),
        ("cgroup_dev", MAX_CHPB_DEVICE + 1),
        ("cgroup_ino", True),
        ("cgroup_ino", 0),
        ("cgroup_ino", MAX_CHPB_INODE + 1),
        ("unit_generation", True),
        ("unit_generation", 0),
        ("unit_generation", MAX_CHPB_GENERATION + 1),
        ("invocation_id", object()),
        ("invocation_id", "not-a-digest"),
        ("mcs_pair", object()),
        ("mcs_pair", "c1,c0"),
    ],
)
def test_invalid_peer_fields_close_all_open_peer_fds(field, value):
    kwargs = {"peer_mcs_pair": value} if field == "mcs_pair" else {}
    kwargs.update(
        {"pid1_invocation_id": value} if field == "invocation_id" else {}
    )
    kwargs.update(
        {"pid1_unit_generation": value} if field == "unit_generation" else {}
    )
    if field == "pid":
        kwargs.update({"reuse_at": 5, "reuse_pid": value})
    if field in {"cgroup_dev", "cgroup_ino"}:
        kwargs["cgroup_stat"] = dataclasses.replace(
            VALID_CGROUP_STAT,
            **{"dev" if field == "cgroup_dev" else "ino": value},
        )
    operations = FakeOperations(**kwargs)

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, PEER_PID, principal())

    assert operations.calls[-3:] == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


@pytest.mark.parametrize(
    "cgroup_stat",
    [
        FdStat(True, 29, 0o40755, 1000, 1000),
        FdStat(17, True, 0o40755, 1000, 1000),
        FdStat(-1, 29, 0o40755, 1000, 1000),
        FdStat(17, 0, 0o40755, 1000, 1000),
        FdStat(18, 29, 0o40755, 1000, 1000),
        FdStat(17, 30, 0o40755, 1000, 1000),
        FdStat(17, 29, True, 1000, 1000),
        FdStat(17, 29, 0o100644, 1000, 1000),
        object(),
    ],
)
def test_invalid_cgroup_stat_closes_all_peer_fds(cgroup_stat):
    operations = FakeOperations(cgroup_stat=cgroup_stat)

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, PEER_PID, principal())

    assert operations.calls[-3:] == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


def test_valid_cgroup_v2_mode_and_nonroot_owner_are_accepted():
    operations = FakeOperations(cgroup_stat=FdStat(17, 29, 0o40755, 1000, 1000))

    assert attest_peer_principal(operations, PEER_PID, principal()) == snapshot()


def test_wrong_pid1_unit_cgroup_pair_is_rejected():
    operations = FakeOperations(pid1_unit_name="wrong.scope")

    with pytest.raises(LinuxBoundaryError):
        attest_peer_principal(operations, PEER_PID, principal())

    assert operations.calls[-3:] == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]


def test_linux_operations_has_no_aggregate_peer_snapshot_operation():
    assert not hasattr(LinuxOperations, "peer_snapshot")


def test_linux_module_import_scope_excludes_real_system_and_lifecycle_apis():
    source = (
        Path(__file__).resolve().parents[1]
        / "src/codex_master/fleet_home_broker_linux.py"
    ).read_text()
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".")[0])

    assert imported <= {"__future__", "dataclasses", "typing", "codex_master"}


def test_agent_start_peer_observation_binds_peer_credentials_and_unit_instance():
    unit_name = "codex-master-agent@c0\\x2cc1.service"
    control_group = f"/user.slice/user-1000.slice/{unit_name}"
    operations = FakeOperations(
        proc_control_group=control_group,
        pid1_unit_name=unit_name,
        pid1_control_group=control_group,
    )

    result = observe_agent_start_peer(
        operations,
        PEER_PID,
        1000,
        1001,
        agent_start_envelope(),
        EXPECTED_SELINUX_CONTEXT,
    )

    assert type(result) is AgentStartPeerObservation
    assert result.pid == PEER_PID
    assert result.uid == 1000
    assert result.gid == 1001
    assert result.start_time == PID_START_TIME
    assert result.cgroup_dev == 17
    assert result.cgroup_ino == 29
    assert result.unit_name == unit_name
    assert result.invocation_id == "1" * 32
    assert result.service_generation == 9
    assert result.mcs_pair == "c0,c1"
    assert result.selinux_context == EXPECTED_SELINUX_CONTEXT
    closes = [call for call in operations.calls if call[0] == "close"]
    assert closes == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]
    assert len(closes) == len({call[1] for call in closes})


@pytest.mark.parametrize(
    ("fd_changes", "expected_operation_names", "expected_closes"),
    (
        (
            {"proc_fd_value": PID_FD},
            ["pidfd_open", "pidfd_reuse_check", "open_pinned_proc_pid", "close"],
            [("close", PID_FD)],
        ),
        (
            {"cgroup_fd_value": PID_FD},
            [
                "pidfd_open",
                "pidfd_reuse_check",
                "open_pinned_proc_pid",
                "pidfd_reuse_check",
                "open_proc_cgroup",
                "close",
                "close",
            ],
            [("close", PROC_FD), ("close", PID_FD)],
        ),
        (
            {"cgroup_fd_value": PROC_FD},
            [
                "pidfd_open",
                "pidfd_reuse_check",
                "open_pinned_proc_pid",
                "pidfd_reuse_check",
                "open_proc_cgroup",
                "close",
                "close",
            ],
            [("close", PROC_FD), ("close", PID_FD)],
        ),
    ),
)
def test_agent_start_rejects_aliased_acquired_fds_before_next_boundary_use(
    fd_changes, expected_operation_names, expected_closes
):
    operations = FakeOperations(**fd_changes)

    with pytest.raises(LinuxBoundaryError):
        observe_agent_start_peer(
            operations,
            PEER_PID,
            1000,
            1001,
            agent_start_envelope(),
            EXPECTED_SELINUX_CONTEXT,
        )

    assert [call[0] for call in operations.calls] == expected_operation_names
    closes = [call for call in operations.calls if call[0] == "close"]
    assert closes == expected_closes
    assert len(closes) == len({call[1] for call in closes})


@pytest.mark.parametrize(
    ("fd_changes", "expected_operation_names", "expected_closes"),
    tuple(
        (
            {field: value},
            operation_names,
            closes,
        )
        for field, operation_names, closes in (
            ("pidfd_value", ["pidfd_open"], []),
            (
                "proc_fd_value",
                ["pidfd_open", "pidfd_reuse_check", "open_pinned_proc_pid", "close"],
                [("close", PID_FD)],
            ),
            (
                "cgroup_fd_value",
                [
                    "pidfd_open",
                    "pidfd_reuse_check",
                    "open_pinned_proc_pid",
                    "pidfd_reuse_check",
                    "open_proc_cgroup",
                    "close",
                    "close",
                ],
                [("close", PROC_FD), ("close", PID_FD)],
            ),
        )
        for value in (True, -1, "73")
    ),
)
def test_agent_start_rejects_invalid_acquired_fd_before_use_or_close(
    fd_changes, expected_operation_names, expected_closes
):
    operations = FakeOperations(**fd_changes)

    with pytest.raises(LinuxBoundaryError):
        observe_agent_start_peer(
            operations,
            PEER_PID,
            1000,
            1001,
            agent_start_envelope(),
            EXPECTED_SELINUX_CONTEXT,
        )

    assert [call[0] for call in operations.calls] == expected_operation_names
    assert [call for call in operations.calls if call[0] == "close"] == expected_closes


def test_agent_start_reader_failure_closes_three_unique_owned_fds_once_in_lifo_order():
    operations = FakeOperations(
        operation_errors={"read_proc_control_group": OSError("read failed")}
    )

    with pytest.raises(LinuxBoundaryError):
        observe_agent_start_peer(
            operations,
            PEER_PID,
            1000,
            1001,
            agent_start_envelope(),
            EXPECTED_SELINUX_CONTEXT,
        )

    closes = [call for call in operations.calls if call[0] == "close"]
    assert closes == [
        ("close", CGROUP_FD),
        ("close", PROC_FD),
        ("close", PID_FD),
    ]
    assert len(closes) == len({call[1] for call in closes})


@pytest.mark.parametrize(
    ("kwargs", "credentials"),
    (
        ({"pid1_unit_generation": 10}, (PEER_PID, 1000, 1001)),
        ({"pid1_invocation_id": "2" * 32}, (PEER_PID, 1000, 1001)),
        ({"peer_mcs_pair": "c0,c2"}, (PEER_PID, 1000, 1001)),
        ({"pid1_unit_name": "codex-master-agent@c0-c1.service"}, (PEER_PID, 1000, 1001)),
        ({}, (PEER_PID + 1, 1000, 1001)),
        ({}, (PEER_PID, True, 1001)),
        ({}, (PEER_PID, 1000, True)),
    ),
)
def test_agent_start_peer_observation_rejects_pid_uid_gid_and_unit_drift(
    kwargs, credentials
):
    operations = FakeOperations(**kwargs)
    with pytest.raises(LinuxBoundaryError):
        observe_agent_start_peer(
            operations,
            credentials[0],
            credentials[1],
            credentials[2],
            agent_start_envelope(),
            EXPECTED_SELINUX_CONTEXT,
        )
    if credentials[1] is True or credentials[2] is True:
        assert operations.calls == []
    elif credentials[0] != PEER_PID:
        assert operations.calls[-1] == ("close", PID_FD)
    else:
        assert operations.calls[-3:] == [
            ("close", CGROUP_FD),
            ("close", PROC_FD),
            ("close", PID_FD),
        ]


@pytest.mark.parametrize(
    "selinux_context",
    (
        "other_u:system_r:codex_master_agent_t:s0:c0,c1",
        "system_u:other_r:codex_master_agent_t:s0:c0,c1",
        "system_u:system_r:wrong_t:s0:c0,c1",
        "system_u:system_r:codex_master_agent_t:s0:c0,c2",
    ),
)
def test_direct_agent_start_observation_rejects_full_selinux_context_drift(
    selinux_context,
):
    operations = FakeOperations()

    with pytest.raises(LinuxBoundaryError):
        observe_agent_start_peer(
            operations,
            PEER_PID,
            1000,
            1001,
            agent_start_envelope(),
            selinux_context,
        )

    assert operations.calls == []


def test_agent_start_observation_keeps_v1_peer_snapshot_shape_untouched():
    assert tuple(field.name for field in dataclasses.fields(PeerSnapshot)) == (
        "pid",
        "cgroup_dev",
        "cgroup_ino",
        "invocation_id",
        "unit_generation",
        "mcs_pair",
    )
    assert tuple(field.name for field in dataclasses.fields(AgentStartPeerObservation)) == (
        "pid",
        "uid",
        "gid",
        "start_time",
        "cgroup_dev",
        "cgroup_ino",
        "unit_name",
        "invocation_id",
        "service_generation",
        "mcs_pair",
        "selinux_context",
    )
    observation = AgentStartPeerObservation(
        PEER_PID,
        1000,
        1001,
        PID_START_TIME,
        17,
        29,
        "codex-master-agent@c0\\x2cc1.service",
        "1" * 32,
        9,
        "c0,c1",
        EXPECTED_SELINUX_CONTEXT,
    )
    assert type(observation).__dataclass_params__.frozen
    assert hasattr(type(observation), "__slots__")
    assert not hasattr(observation, "__dict__")
