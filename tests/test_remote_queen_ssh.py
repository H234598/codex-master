import pytest

from codex_master.remote_queen_bootstrap import SshTargetV1
from codex_master.remote_queen_ssh import (
    MAX_SSH_CONNECT_TIMEOUT_SECONDS,
    MAX_SSH_OPERATION_TIMEOUT_SECONDS,
    MAX_SSH_STDERR_BYTES,
    MAX_SSH_STDOUT_BYTES,
    SSH_HOST_KEY_TYPES,
    ApprovedHostKeyV1,
    KnownHostKeyV1,
    PresentedHostKeyV1,
    RemoteQueenSshOperations,
    SshOperationLimitsV1,
    SshOperationResultV1,
    SshReadOnlyOperationV1,
    approve_known_host_key,
    validate_ssh_operation_result,
)
from codex_master.remote_queen_bootstrap import RemoteQueenBootstrapError


TARGET = SshTargetV1(user="queen", host="example.test")
FINGERPRINT = "SHA256:" + "A" * 43
OTHER_FINGERPRINT = "SHA256:" + "B" * 43
STDOUT = b'{"ok":true}'
STDERR = b"diagnostic secret"


def assert_domain_error(call, code):
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        call()
    assert exc_info.value.code == code
    assert str(exc_info.value) == code
    return exc_info.value


def make_result(**overrides):
    values = {
        "operation": SshReadOnlyOperationV1.HOST_FACTS,
        "returncode": 0,
        "stdout": STDOUT,
        "stderr": b"",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "host_key_fingerprint": FINGERPRINT,
    }
    values.update(overrides)
    return SshOperationResultV1(**values)


def make_approved():
    return ApprovedHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )


def test_limits_have_bounded_defaults_and_allowed_key_types():
    limits = SshOperationLimitsV1()

    assert limits.connect_timeout_seconds == 5
    assert limits.operation_timeout_seconds == 15
    assert limits.max_stdout_bytes == MAX_SSH_STDOUT_BYTES
    assert limits.max_stderr_bytes == MAX_SSH_STDERR_BYTES
    assert MAX_SSH_CONNECT_TIMEOUT_SECONDS == 10
    assert MAX_SSH_OPERATION_TIMEOUT_SECONDS == 30
    assert SSH_HOST_KEY_TYPES == frozenset(
        {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connect_timeout_seconds", True),
        ("connect_timeout_seconds", None),
        ("connect_timeout_seconds", 0),
        ("connect_timeout_seconds", -1),
        ("connect_timeout_seconds", MAX_SSH_CONNECT_TIMEOUT_SECONDS + 1),
        ("operation_timeout_seconds", False),
        ("operation_timeout_seconds", None),
        ("operation_timeout_seconds", 0),
        ("operation_timeout_seconds", -1),
        (
            "operation_timeout_seconds",
            MAX_SSH_OPERATION_TIMEOUT_SECONDS + 1,
        ),
        ("max_stdout_bytes", True),
        ("max_stdout_bytes", None),
        ("max_stdout_bytes", 0),
        ("max_stdout_bytes", -1),
        ("max_stdout_bytes", MAX_SSH_STDOUT_BYTES + 1),
        ("max_stderr_bytes", False),
        ("max_stderr_bytes", None),
        ("max_stderr_bytes", 0),
        ("max_stderr_bytes", -1),
        ("max_stderr_bytes", MAX_SSH_STDERR_BYTES + 1),
    ],
)
def test_limits_reject_bool_null_negative_and_oversized_values(field, value):
    values = {
        "connect_timeout_seconds": 5,
        "operation_timeout_seconds": 15,
        "max_stdout_bytes": MAX_SSH_STDOUT_BYTES,
        "max_stderr_bytes": MAX_SSH_STDERR_BYTES,
    }
    values[field] = value

    assert_domain_error(lambda: SshOperationLimitsV1(**values), "RQ_E_PLAN_INCONSISTENT")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: KnownHostKeyV1(
            host="",
            key_type="ssh-ed25519",
            sha256_fingerprint=FINGERPRINT,
        ),
        lambda: KnownHostKeyV1(
            host="example.test",
            key_type="ssh-dss",
            sha256_fingerprint=FINGERPRINT,
        ),
        lambda: KnownHostKeyV1(
            host="example.test",
            key_type="ssh-ed25519",
            sha256_fingerprint="SHA256:raw-key",
        ),
        lambda: KnownHostKeyV1(
            host="example.test",
            key_type="ssh-ed25519",
            sha256_fingerprint=FINGERPRINT,
            revoked=1,
        ),
        lambda: PresentedHostKeyV1(
            host="",
            key_type="ssh-ed25519",
            sha256_fingerprint=FINGERPRINT,
        ),
        lambda: PresentedHostKeyV1(
            host="example.test",
            key_type="ssh-dss",
            sha256_fingerprint=FINGERPRINT,
        ),
        lambda: PresentedHostKeyV1(
            host="example.test",
            key_type="ssh-ed25519",
            sha256_fingerprint="SHA256:raw-key",
        ),
        lambda: ApprovedHostKeyV1(
            host="",
            key_type="ssh-ed25519",
            sha256_fingerprint=FINGERPRINT,
        ),
        lambda: ApprovedHostKeyV1(
            host="example.test",
            key_type="ssh-dss",
            sha256_fingerprint=FINGERPRINT,
        ),
        lambda: ApprovedHostKeyV1(
            host="example.test",
            key_type="ssh-ed25519",
            sha256_fingerprint="SHA256:raw-key",
        ),
    ],
)
def test_host_key_values_reject_malformed_fields(factory):
    error = assert_domain_error(factory, "RQ_E_PLAN_INCONSISTENT")
    assert "raw-key" not in str(error)


def test_approve_known_host_key_requires_exact_nonrevoked_pin():
    known = KnownHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )
    presented = PresentedHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )

    approved = approve_known_host_key(
        target=TARGET,
        known_host_keys=(known,),
        presented_host_key=presented,
    )

    assert approved == ApprovedHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )


@pytest.mark.parametrize(
    "known_host_keys",
    [
        (),
        (
            KnownHostKeyV1(
                host=TARGET.host,
                key_type="ssh-ed25519",
                sha256_fingerprint=OTHER_FINGERPRINT,
            ),
        ),
        (
            KnownHostKeyV1(
                host="other.test",
                key_type="ssh-ed25519",
                sha256_fingerprint=FINGERPRINT,
            ),
        ),
        [
            KnownHostKeyV1(
                host=TARGET.host,
                key_type="ssh-ed25519",
                sha256_fingerprint=FINGERPRINT,
            )
        ],
    ],
)
def test_approve_known_host_key_rejects_missing_or_mismatched_pin(known_host_keys):
    presented = PresentedHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )

    assert_domain_error(
        lambda: approve_known_host_key(
            target=TARGET,
            known_host_keys=known_host_keys,
            presented_host_key=presented,
        ),
        "RQ_E_SSH_HOSTKEY"
        if isinstance(known_host_keys, tuple)
        else "RQ_E_PLAN_INCONSISTENT",
    )


def test_approve_known_host_key_rejects_presented_other_host():
    known = KnownHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )
    presented = PresentedHostKeyV1(
        host="other.test",
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )

    error = assert_domain_error(
        lambda: approve_known_host_key(
            target=TARGET,
            known_host_keys=(known,),
            presented_host_key=presented,
        ),
        "RQ_E_SSH_HOSTKEY",
    )
    assert "other.test" not in str(error)


def test_approve_known_host_key_revoked_exact_match_blocks_even_with_live_pin():
    live = KnownHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )
    revoked = KnownHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
        revoked=True,
    )
    presented = PresentedHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )

    assert_domain_error(
        lambda: approve_known_host_key(
            target=TARGET,
            known_host_keys=(live, revoked),
            presented_host_key=presented,
        ),
        "RQ_E_SSH_HOSTKEY",
    )


def test_approve_known_host_key_rejects_wrong_argument_types():
    presented = PresentedHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )
    known = KnownHostKeyV1(
        host=TARGET.host,
        key_type="ssh-ed25519",
        sha256_fingerprint=FINGERPRINT,
    )

    assert_domain_error(
        lambda: approve_known_host_key(
            target="example.test",
            known_host_keys=(known,),
            presented_host_key=presented,
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )
    assert_domain_error(
        lambda: approve_known_host_key(
            target=TARGET,
            known_host_keys=(known,),
            presented_host_key="not-a-key",
        ),
        "RQ_E_PLAN_INCONSISTENT",
    )


def test_validate_ssh_operation_result_returns_only_stdout_for_valid_result():
    result = make_result()

    assert (
        validate_ssh_operation_result(
            result,
            expected_operation=SshReadOnlyOperationV1.HOST_FACTS,
            approved_host_key=make_approved(),
            limits=SshOperationLimitsV1(),
        )
        == STDOUT
    )


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("operation", "other-operation", "RQ_E_PLAN_INCONSISTENT"),
        ("host_key_fingerprint", OTHER_FINGERPRINT, "RQ_E_SSH_HOSTKEY"),
        ("timed_out", True, "RQ_E_SSH_PREFLIGHT"),
        ("stdout_truncated", True, "RQ_E_SSH_PREFLIGHT"),
        ("stderr_truncated", True, "RQ_E_SSH_PREFLIGHT"),
        ("stdout", b"x" * (MAX_SSH_STDOUT_BYTES + 1), "RQ_E_SSH_PREFLIGHT"),
        ("stderr", b"x" * (MAX_SSH_STDERR_BYTES + 1), "RQ_E_SSH_PREFLIGHT"),
        ("stdout", "not-bytes", "RQ_E_PLAN_INCONSISTENT"),
        ("stderr", bytearray(), "RQ_E_PLAN_INCONSISTENT"),
        ("returncode", True, "RQ_E_PLAN_INCONSISTENT"),
        ("returncode", 7, "RQ_E_SSH_PREFLIGHT"),
    ],
)
def test_validate_ssh_operation_result_rejects_invalid_result(field, value, expected_code):
    result = make_result(**{field: value})

    error = assert_domain_error(
        lambda: validate_ssh_operation_result(
            result,
            expected_operation=SshReadOnlyOperationV1.HOST_FACTS,
            approved_host_key=make_approved(),
            limits=SshOperationLimitsV1(),
        ),
        expected_code,
    )
    assert "diagnostic secret" not in str(error)
    assert "example.test" not in str(error)


def test_validate_ssh_operation_result_rejects_timeout_flag_before_returning_output():
    result = make_result(timed_out=True)

    assert_domain_error(
        lambda: validate_ssh_operation_result(
            result,
            expected_operation=SshReadOnlyOperationV1.HOST_FACTS,
            approved_host_key=make_approved(),
            limits=SshOperationLimitsV1(),
        ),
        "RQ_E_SSH_PREFLIGHT",
    )


def test_operation_result_repr_is_fully_redacted():
    result = make_result(
        stdout=b"stdout-secret",
        stderr=b"stderr-secret",
        host_key_fingerprint="SHA256:" + "C" * 43,
    )

    assert repr(result) == "SshOperationResultV1(<redacted>)"
    assert "stdout-secret" not in repr(result)
    assert "stderr-secret" not in repr(result)
    assert "SHA256:" not in repr(result)


def test_protocol_is_publicly_available_without_runtime_adapter():
    assert RemoteQueenSshOperations.__name__ == "RemoteQueenSshOperations"
