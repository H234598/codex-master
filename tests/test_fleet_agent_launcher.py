import ast
from dataclasses import fields, replace
import importlib
from pathlib import Path

import pytest

from codex_master.fleet_home_broker_client import AttestedHome
from codex_master.fleet_home_broker_identity import BrokerIdentity
from codex_master.fleet_home_broker_linux import FdStat
from codex_master.fleet_home_broker_protocol import (
    B2aRecoveryPhase,
    BindingExpectation,
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    CANONICAL_AGENT_HOME,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    DirectoryIdentity,
    HomeAttestation,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
)


launcher = importlib.import_module("codex_master.fleet_agent_launcher")

SCM_FD = 31
PARENT_FD = 41
PATH_FD = 51
REQUEST_ID = "a" * 32
TRANSACTION_ID = "b" * 32
STORE_UUID = "c" * 32
PROJECTION_DIGEST = "d" * 64
MANIFEST_DIGEST = "e" * 64
EXECUTABLE_FINGERPRINT = "f" * 64
PRINCIPAL = PrincipalBinding("agent_one", 7, 9, 17, 29, "1" * 32, "c1,c2", 11)
EXPECTED = BindingExpectation("agent_one", 7, 9, 13, PROJECTION_DIGEST, 11)
IDENTITY = BrokerIdentity(
    "agent_one",
    7,
    "c1,c2",
    "slot-snapshot",
    13,
    PROJECTION_DIGEST,
    EXECUTABLE_FINGERPRINT,
    11,
)
BINDING = TransactionBinding(
    ChpbTransactionOperation.PROVISION,
    TRANSACTION_ID,
    STORE_UUID,
    PRINCIPAL,
    PolicyBinding(13, PROJECTION_DIGEST),
)
DIRECTORY = DirectoryIdentity(17, 31, 0o40700)
OBSERVATION = BrokerObservation(
    BrokerObjectState.FINAL_COMPLETE,
    BrokerRegistryState.CURRENT,
    0,
)
TRANSACTION = TransactionStatus(
    BINDING,
    B2aRecoveryPhase.COMMITTED,
    BrokerCheckpoint.COMMITTED,
    OBSERVATION,
    1,
    BrokerResultCode.COMMITTED,
)
ATTESTATION = HomeAttestation(
    BINDING,
    CANONICAL_AGENT_HOME,
    DIRECTORY,
    MANIFEST_DIGEST,
    PRINCIPAL.mcs_pair,
)
REPLY = BrokerReply(
    CHPB_PROTOCOL,
    ChpbMessageKind.REPLY,
    REQUEST_ID,
    BrokerResultCode.OK,
    TRANSACTION,
    ATTESTATION,
)
HOME = AttestedHome(SCM_FD, REPLY, ATTESTATION)
EXECUTABLE = launcher.ExecutablePin("/usr/libexec/codex-agent", EXECUTABLE_FINGERPRINT)
ENVIRONMENT = {
    "CODEX_HOME": "/tmp/foreign-codex",
    "HOME": "/tmp/foreign-home",
    "GEMINI_CLI_HOME": "/tmp/foreign-gemini",
    "PATH": "/usr/bin",
    "KEEP": "value",
}
EXPECTED_ENVIRONMENT = tuple(
    sorted(
        {
            **ENVIRONMENT,
            "CODEX_HOME": CANONICAL_AGENT_HOME,
            "HOME": CANONICAL_AGENT_HOME,
            "GEMINI_CLI_HOME": CANONICAL_AGENT_HOME,
        }.items()
    )
)


class FakeOperations:
    def __init__(
        self,
        *,
        parent_fd=PARENT_FD,
        path_fd=PATH_FD,
        stats=None,
        observed_fingerprint=EXECUTABLE_FINGERPRINT,
        errors=None,
    ):
        self.parent_fd = parent_fd
        self.path_fd = path_fd
        self.stats = stats or {
            SCM_FD: FdStat(DIRECTORY.dev, DIRECTORY.ino, DIRECTORY.mode, 1000, 1000),
            PATH_FD: FdStat(DIRECTORY.dev, DIRECTORY.ino, DIRECTORY.mode, 1000, 1000),
        }
        self.observed_fingerprint = observed_fingerprint
        self.errors = errors or {}
        self.calls = []
        self.closed = []

    def _raise(self, operation):
        error = self.errors.get(operation)
        if error is not None:
            raise error

    def open_agent_parent(self):
        self.calls.append(("open_agent_parent",))
        self._raise("open_agent_parent")
        return self.parent_fd

    def openat2(self, parent_fd, child_name, flags, resolve):
        self.calls.append(("openat2", parent_fd, child_name, flags, resolve))
        self._raise("openat2")
        return self.path_fd

    def fstat(self, fd):
        self.calls.append(("fstat", fd))
        self._raise(f"fstat:{fd}")
        self._raise("fstat")
        return self.stats[fd]

    def close(self, fd):
        self.calls.append(("close", fd))
        self.closed.append(fd)
        self._raise(f"close:{fd}")
        self._raise("close")

    def executable_fingerprint(self, path):
        self.calls.append(("executable_fingerprint", path))
        self._raise("executable_fingerprint")
        return self.observed_fingerprint


def prepare(
    *,
    home=HOME,
    expected_principal=PRINCIPAL,
    expected=EXPECTED,
    identity=IDENTITY,
    executable=EXECUTABLE,
    environment=ENVIRONMENT,
    operations=None,
):
    operations = operations or FakeOperations()
    result = launcher.prepare_agent_launch(
        home,
        expected_principal,
        expected,
        identity,
        executable,
        environment,
        operations,
    )
    return result, operations


def assert_rejected(**kwargs):
    operations = kwargs.pop("operations", None) or FakeOperations()
    with pytest.raises(launcher.LauncherError):
        prepare(operations=operations, **kwargs)
    return operations


def home_from_reply(reply):
    return replace(HOME, reply=reply, attestation=reply.attestation)


def stats_for_home(home):
    directory = home.attestation.directory
    stat = FdStat(directory.dev, directory.ino, directory.mode, 1000, 1000)
    return {SCM_FD: stat, PATH_FD: stat}


def test_public_api_types_are_frozen_and_slotted():
    for type_ in (launcher.ExecutablePin, launcher.AgentLaunchPlan):
        assert getattr(type_, "__dataclass_params__").frozen
        assert getattr(type_, "__slots__")
    assert tuple(field.name for field in fields(launcher.ExecutablePin)) == (
        "path",
        "fingerprint",
    )
    assert tuple(field.name for field in fields(launcher.AgentLaunchPlan)) == (
        "executable",
        "environment",
        "home_fd",
    )


def test_public_error_and_operations_protocol_are_minimal():
    assert issubclass(launcher.LauncherError, ValueError)
    assert {
        "open_agent_parent",
        "openat2",
        "fstat",
        "close",
        "executable_fingerprint",
    } <= set(launcher.LauncherOperations.__dict__)


@pytest.mark.parametrize(
    ("argument", "value"),
    (
        ("home", object()),
        ("expected_principal", object()),
        ("expected", object()),
        ("identity", object()),
        ("executable", object()),
    ),
)
def test_invalid_input_types_reject_before_any_operation(argument, value):
    operations = FakeOperations()
    arguments = {argument: value}

    with pytest.raises(launcher.LauncherError):
        prepare(operations=operations, **arguments)

    if argument == "home":
        assert operations.calls == []
        assert operations.closed == []
    else:
        assert operations.calls == [("close", SCM_FD)]
        assert operations.closed == [SCM_FD]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("agent_id", "other_agent"),
        ("manifest_generation", 8),
        ("unit_generation", 10),
        ("policy_generation", 14),
        ("projection_digest", "0" * 64),
        ("fencing_epoch", 12),
    ),
)
def test_binding_expectation_drift_rejects_before_open(field, value):
    operations = FakeOperations()
    expected = replace(EXPECTED, **{field: value})

    assert_rejected(expected=expected, operations=operations)

    assert operations.calls == [("close", SCM_FD)]
    assert operations.closed == [SCM_FD]


@pytest.mark.parametrize(
    "expected_principal",
    (
        replace(PRINCIPAL, agent_id="other_agent"),
        replace(PRINCIPAL, manifest_generation=8),
        replace(PRINCIPAL, unit_generation=10),
        replace(PRINCIPAL, mcs_pair="c2,c3"),
        replace(PRINCIPAL, fencing_epoch=12),
    ),
)
def test_principal_or_identity_drift_rejects_before_open(expected_principal):
    operations = FakeOperations()

    assert_rejected(expected_principal=expected_principal, operations=operations)

    assert operations.calls == [("close", SCM_FD)]
    assert operations.closed == [SCM_FD]


@pytest.mark.parametrize(
    "identity",
    (
        replace(IDENTITY, agent_id="other_agent"),
        replace(IDENTITY, manifest_generation=8),
        replace(IDENTITY, mcs_pair="c2,c3"),
        replace(IDENTITY, policy_generation=14),
        replace(IDENTITY, projection_digest="0" * 64),
        replace(IDENTITY, fencing_epoch=12),
    ),
)
def test_broker_identity_drift_rejects_before_open(identity):
    operations = FakeOperations()

    assert_rejected(identity=identity, operations=operations)

    assert operations.calls == [("close", SCM_FD)]
    assert operations.closed == [SCM_FD]


def test_attestation_binding_and_path_drift_reject_before_open():
    drifted_binding = replace(
        BINDING, principal=replace(PRINCIPAL, agent_id="other_agent")
    )
    drifted_attestation = replace(
        ATTESTATION,
        binding=drifted_binding,
        canonical_path="/run/other-home",
    )
    home = replace(HOME, attestation=drifted_attestation)
    operations = FakeOperations()

    assert_rejected(home=home, operations=operations)

    assert operations.calls == [("close", SCM_FD)]
    assert operations.closed == [SCM_FD]


def test_reply_and_attestation_are_revalidated_before_fd_open():
    bad_directory = replace(DIRECTORY, mode=0o40701)
    bad_transaction = replace(TRANSACTION, terminal_result=None)
    bad_status = replace(TRANSACTION, population_total=0)
    cases = (
        home_from_reply(replace(REPLY, protocol="CHPB/1")),
        home_from_reply(replace(REPLY, transaction=bad_transaction)),
        home_from_reply(
            replace(REPLY, attestation=replace(ATTESTATION, directory=bad_directory))
        ),
        home_from_reply(
            replace(
                REPLY, attestation=replace(ATTESTATION, manifest_digest="not-a-digest")
            )
        ),
        home_from_reply(
            replace(REPLY, attestation=replace(ATTESTATION, mcs_pair="not-mcs"))
        ),
        home_from_reply(replace(REPLY, request_id="not-a-digest")),
        home_from_reply(replace(REPLY, transaction=bad_status)),
    )

    for home in cases:
        operations = FakeOperations(stats=stats_for_home(home))
        assert_rejected(home=home, operations=operations)
        assert operations.calls == [("close", SCM_FD)]
        assert operations.closed == [SCM_FD]


def test_openat2_uses_pinned_parent_and_exact_contract():
    operations = FakeOperations()

    _, operations = prepare(operations=operations)

    assert operations.calls[:2] == [
        ("open_agent_parent",),
        (
            "openat2",
            PARENT_FD,
            "home",
            0o10000000 | 0o200000 | 0o400000 | 0o2000000,
            0x08 | 0x04 | 0x02,
        ),
    ]


@pytest.mark.parametrize(
    ("fd", "field"),
    (
        (SCM_FD, "dev"),
        (SCM_FD, "ino"),
        (SCM_FD, "mode"),
        (PATH_FD, "dev"),
        (PATH_FD, "ino"),
        (PATH_FD, "mode"),
    ),
)
def test_scm_and_path_stats_must_match_attestation(fd, field):
    stats = {
        SCM_FD: FdStat(DIRECTORY.dev, DIRECTORY.ino, DIRECTORY.mode, 1000, 1000),
        PATH_FD: FdStat(DIRECTORY.dev, DIRECTORY.ino, DIRECTORY.mode, 1000, 1000),
    }
    original = stats[fd]
    stats[fd] = replace(original, **{field: getattr(original, field) + 1})
    operations = FakeOperations(stats=stats)

    assert_rejected(operations=operations)

    assert operations.closed == [SCM_FD, PATH_FD, PARENT_FD]


@pytest.mark.parametrize(
    "operation",
    ("openat2", "fstat", "executable_fingerprint"),
)
def test_every_failure_closes_scm_parent_and_unusable_path(operation):
    errors = {operation: OSError(operation)}
    operations = FakeOperations(errors=errors)

    assert_rejected(operations=operations)

    if operation == "openat2":
        assert operations.closed == [SCM_FD, PARENT_FD]
    else:
        assert operations.closed == [SCM_FD, PATH_FD, PARENT_FD]


def test_parent_open_failure_still_closes_consumed_scm_fd():
    operations = FakeOperations(errors={"open_agent_parent": OSError("parent")})

    assert_rejected(operations=operations)

    assert operations.closed == [SCM_FD]


@pytest.mark.parametrize("close_fd", (SCM_FD, PATH_FD, PARENT_FD))
def test_close_error_on_failure_still_attempts_every_known_fd(close_fd):
    operations = FakeOperations(
        errors={"executable_fingerprint": OSError("fingerprint")}
    )
    operations.errors[f"close:{close_fd}"] = OSError("close")

    assert_rejected(operations=operations)

    assert sorted(operations.closed) == sorted((SCM_FD, PATH_FD, PARENT_FD))


@pytest.mark.parametrize("close_fd", (SCM_FD, PARENT_FD))
def test_close_error_on_success_attempts_path_before_rejecting(close_fd):
    operations = FakeOperations()
    operations.errors[f"close:{close_fd}"] = OSError("close")

    with pytest.raises(launcher.LauncherError):
        prepare(operations=operations)

    assert sorted(operations.closed) == sorted((SCM_FD, PATH_FD, PARENT_FD))


@pytest.mark.parametrize(
    "path",
    (
        "relative/agent",
        "/usr/libexec/../agent",
        "/usr/./libexec/agent",
        "/usr//libexec/agent",
        "/usr/libexec/agent/",
        "/proc/self/fd/7",
        "/usr/libexec/agent\\name",
        "/usr/libexec/agent\x00name",
    ),
)
def test_executable_path_must_be_canonical_before_open(path):
    operations = FakeOperations()

    assert_rejected(
        executable=launcher.ExecutablePin(path, EXECUTABLE_FINGERPRINT),
        operations=operations,
    )

    assert operations.calls == [("close", SCM_FD)]
    assert operations.closed == [SCM_FD]


def test_executable_pin_must_match_identity_before_open():
    operations = FakeOperations()

    assert_rejected(
        executable=launcher.ExecutablePin("/usr/libexec/codex-agent", "0" * 64),
        operations=operations,
    )

    assert operations.calls == [("close", SCM_FD)]
    assert operations.closed == [SCM_FD]


def test_observed_executable_fingerprint_must_match_pin_and_identity():
    operations = FakeOperations(observed_fingerprint="0" * 64)

    assert_rejected(operations=operations)

    assert operations.closed == [SCM_FD, PATH_FD, PARENT_FD]


def test_environment_is_copied_and_only_three_home_values_are_replaced():
    environment = dict(ENVIRONMENT)

    result, operations = prepare(environment=environment)

    assert result.environment == EXPECTED_ENVIRONMENT
    assert type(result.environment) is tuple
    assert result.environment is not environment
    assert environment == ENVIRONMENT
    environment["KEEP"] = "mutated-after-return"
    assert result.environment == EXPECTED_ENVIRONMENT
    with pytest.raises(TypeError):
        result.environment[0] = ("MUTATED", "value")
    assert operations.closed == [SCM_FD, PARENT_FD]


def test_success_returns_plan_with_open_path_fd_only():
    result, operations = prepare()

    assert result == launcher.AgentLaunchPlan(
        EXECUTABLE,
        EXPECTED_ENVIRONMENT,
        PATH_FD,
    )
    assert type(result.environment) is tuple
    assert result.home_fd == PATH_FD
    assert operations.closed == [SCM_FD, PARENT_FD]


def test_launcher_source_has_no_forbidden_transport_process_or_start_surface():
    source_path = Path(launcher.__file__)
    source = source_path.read_text()
    tree = ast.parse(source)
    lowered = source.lower()
    for token in (
        "socket",
        "recvmsg",
        "sendmsg",
        "proc",
        "server",
        "subprocess",
        "os.environ",
    ):
        assert token not in lowered

    forbidden_modules = {"socket", "subprocess", "server", "os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                alias.name.split(".")[0] not in forbidden_modules
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            assert (
                node.module is None
                or node.module.split(".")[0] not in forbidden_modules
            )
