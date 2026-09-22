from __future__ import annotations

import base64
import copy
from dataclasses import asdict
import pickle

import pytest

from the_hive.remote_queen_bootstrap import SshTargetV1
from the_hive import remote_queen_openssh_transport_contract as contract


def _api() -> dict[str, object]:
    """Require the D306 opaque-issuer boundary before exercising it.

    Break caught: removing the capability boundary must not silently turn the
    test into a check of the superseded D305 candidate API.
    """

    names = (
        "HostKeyCapabilityV1",
        "RemoteQueenHostKeyAuthorityV1",
        "RawKeyCredentialCapabilityV1",
        "OpenSshArgvPolicyV1",
        "_issue_host_key_capability_v1",
        "_issue_host_key_authority_v1",
        "_issue_raw_key_credential_v1",
        "_host_key_fingerprint_for_contract_test",
        "_host_key_record_digest_for_contract_test",
        "_credential_binding_digest_for_contract_test",
        "_argv_for_contract_test",
        "_certificate_sibling_policy_for_contract_test",
        "select_active_host_key_capability",
        "project_ssh_argv_policy",
        "host_facts_v1_operation",
    )
    missing = tuple(name for name in names if not hasattr(contract, name))
    assert not missing, f"D306 contract API missing: {missing!r}"
    return {name: getattr(contract, name) for name in names}


def _raw_blob() -> bytes:
    return b"d306-contract-test-public-key-blob"


def _record(
    *,
    host: str = "node.example.test",
    key_type: str = "ssh-ed25519",
    blob: bytes | None = None,
) -> bytes:
    encoded = base64.b64encode(_raw_blob() if blob is None else blob)
    return (
        host.encode("ascii") + b" " + key_type.encode("ascii") + b" " + encoded + b"\n"
    )


def _host_key(
    api: dict[str, object],
    *,
    record: bytes | None = None,
    enrollment_id: str = "enrollment-d306-1",
    generation: int = 7,
    authority_digest: str | None = None,
    provenance_digest: str | None = None,
    state: str = "active",
) -> object:
    issue = api["_issue_host_key_capability_v1"]
    assert callable(issue)
    return issue(
        known_hosts_record=_record() if record is None else record,
        enrollment_id=enrollment_id,
        authority_generation=generation,
        authority_digest=(
            contract.sha256_digest(b"host-authority-d306")
            if authority_digest is None
            else authority_digest
        ),
        enrollment_provenance_digest=(
            contract.sha256_digest(b"enrollment-provenance-d306")
            if provenance_digest is None
            else provenance_digest
        ),
        state=state,
    )


def _authority(api: dict[str, object], *capabilities: object) -> object:
    issue = api["_issue_host_key_authority_v1"]
    assert callable(issue)
    return issue(
        authority_generation=7,
        authority_digest=contract.sha256_digest(b"host-authority-d306"),
        capabilities=capabilities,
    )


def _credential(
    api: dict[str, object],
    *,
    host: str = "node.example.test",
    port: int = 22,
    user: str = "queen",
    host_generation: int = 7,
    host_digest: str | None = None,
    projection_id: str = "identity-projection-d306",
    projection_manifest_digest: str | None = None,
    state: str = "active",
    credential_kind: str = "openssh-identity-file-v1",
) -> object:
    issue = api["_issue_raw_key_credential_v1"]
    assert callable(issue)
    return issue(
        credential_id="credential-d306-1",
        credential_generation=5,
        credential_kind=credential_kind,
        effective_host=host,
        port=port,
        remote_user=user,
        host_authority_generation=host_generation,
        host_authority_digest=(
            contract.sha256_digest(b"host-authority-d306")
            if host_digest is None
            else host_digest
        ),
        projection_id=projection_id,
        projection_manifest_digest=(
            contract.sha256_digest(b"projection-manifest-d306")
            if projection_manifest_digest is None
            else projection_manifest_digest
        ),
        credential_provenance_digest=contract.sha256_digest(
            b"credential-provenance-d306"
        ),
        state=state,
    )


def _raises(code: str, thunk: object) -> None:
    assert callable(thunk)
    with pytest.raises(contract.RemoteQueenOpenSshContractError) as raised:
        thunk()
    assert raised.value.code == code


def test_authority_selects_exactly_one_active_dns_or_ipv4_port_22_enrollment() -> None:
    api = _api()
    select = api["select_active_host_key_capability"]
    assert callable(select)

    active = _host_key(api)
    historical_revoked = _host_key(
        api,
        record=_record(blob=b"historically-revoked-key"),
        enrollment_id="enrollment-d306-historical",
        state="revoked",
    )
    selected = select(
        _authority(api, historical_revoked, active),
        SshTargetV1(user="queen", host="node.example.test"),
    )
    assert selected is active

    ipv4 = _host_key(
        api,
        record=_record(host="192.0.2.44"),
        enrollment_id="enrollment-d306-ipv4",
    )
    assert (
        select(_authority(api, ipv4), SshTargetV1(user="queen", host="192.0.2.44"))
        is ipv4
    )

    _raises(
        "RQ_E_SSH_ENDPOINT_UNSUPPORTED",
        lambda: select(
            _authority(api, active),
            SshTargetV1(user="queen", host="[2001:db8::44]"),
        ),
    )
    _raises(
        "RQ_E_SSH_ENROLLMENT_MISSING",
        lambda: select(
            _authority(api, active),
            SshTargetV1(user="queen", host="other.example.test"),
        ),
    )
    _raises(
        "RQ_E_SSH_ENROLLMENT_AMBIGUOUS",
        lambda: select(
            _authority(
                api,
                active,
                _host_key(
                    api,
                    record=_record(blob=b"second-active-key"),
                    enrollment_id="enrollment-d306-second",
                ),
            ),
            SshTargetV1(user="queen", host="node.example.test"),
        ),
    )
    _raises(
        "RQ_E_SSH_KEY_REVOKED",
        lambda: select(
            _authority(api, historical_revoked),
            SshTargetV1(user="queen", host="node.example.test"),
        ),
    )


def test_authority_requires_verified_raw_blob_fingerprint_and_exact_digests() -> None:
    api = _api()
    capability = _host_key(api)
    fingerprint = api["_host_key_fingerprint_for_contract_test"]
    record_digest = api["_host_key_record_digest_for_contract_test"]
    assert callable(fingerprint)
    assert callable(record_digest)
    assert fingerprint(capability) == contract.ssh_sha256_fingerprint(_raw_blob())
    assert record_digest(capability) == contract.sha256_digest(_record())

    for invalid_record in (
        _record()[:-1],
        _record() + b"second.example.test ssh-ed25519 ZmFrZQ==\n",
        _record().replace(b" ", b"  ", 1),
        _record().replace(b"\n", b"\r\n"),
        _record().replace(b"\n", b"\x00\n"),
        _record(key_type="ssh-not-a-v1-key"),
        b"node.example.test ssh-ed25519 invalid-base64!\n",
    ):
        _raises(
            "RQ_E_SSH_AUTHORITY_INVALID",
            lambda invalid_record=invalid_record: _host_key(
                api, record=invalid_record, enrollment_id="invalid-record"
            ),
        )

    _raises(
        "RQ_E_SSH_AUTHORITY_INVALID",
        lambda: _authority(
            api,
            capability,
            _host_key(
                api,
                record=_record(blob=b"authority-digest-mismatch"),
                enrollment_id="other-authority",
                authority_digest=contract.sha256_digest(b"other-authority"),
            ),
        ),
    )
    _raises(
        "RQ_E_SSH_AUTHORITY_INVALID",
        lambda: _host_key(api, provenance_digest="sha256:" + "g" * 64),
    )


def test_host_facts_spec_has_fixed_ascii_command_and_digest_bound_stdin_bytes() -> None:
    api = _api()
    unavailable = api["host_facts_v1_operation"]
    assert callable(unavailable)

    _raises("RQ_E_SSH_OPERATION_UNAVAILABLE", unavailable)
    assert not hasattr(contract, "RemoteQueenOperationSpecV1")
    assert not hasattr(contract, "VerifiedAuthorityHostKeyV1")
    assert not hasattr(contract, "PresentedHostKeyV1")

    capability = _host_key(api)
    credential = _credential(api)
    binding_digest = api["_credential_binding_digest_for_contract_test"]
    assert callable(binding_digest)
    assert binding_digest(credential).startswith("sha256:")

    project = api["project_ssh_argv_policy"]
    assert callable(project)
    _raises(
        "RQ_E_SSH_CREDENTIAL_USER_MISMATCH",
        lambda: project(
            target=SshTargetV1(user="other", host="node.example.test"),
            host_key=capability,
            credential=credential,
            connect_timeout_seconds=5,
        ),
    )
    _raises(
        "RQ_E_SSH_CREDENTIAL_REVOKED",
        lambda: project(
            target=SshTargetV1(user="queen", host="node.example.test"),
            host_key=capability,
            credential=_credential(api, state="revoked"),
            connect_timeout_seconds=5,
        ),
    )
    _raises(
        "RQ_E_SSH_AUTH_UNAVAILABLE",
        lambda: project(
            target=SshTargetV1(user="queen", host="node.example.test"),
            host_key=capability,
            credential=_credential(api, host_generation=8),
            connect_timeout_seconds=5,
        ),
    )
    _raises(
        "RQ_E_SSH_AUTH_UNAVAILABLE",
        lambda: project(
            target=SshTargetV1(user="queen", host="node.example.test"),
            host_key=capability,
            credential=_credential(api, host="other.example.test"),
            connect_timeout_seconds=5,
        ),
    )
    _raises(
        "RQ_E_SSH_AUTH_UNAVAILABLE",
        lambda: project(
            target=SshTargetV1(user="queen", host="node.example.test"),
            host_key=capability,
            credential=_credential(
                api, host_digest=contract.sha256_digest(b"other-host-authority")
            ),
            connect_timeout_seconds=5,
        ),
    )
    _raises(
        "RQ_E_SSH_ENROLLMENT_MISSING",
        lambda: project(
            target=SshTargetV1(user="queen", host="node.example.test"),
            host_key=_host_key(
                api,
                record=_record(host="other.example.test"),
                enrollment_id="enrollment-d306-other-target",
            ),
            credential=credential,
            connect_timeout_seconds=5,
        ),
    )
    _raises(
        "RQ_E_SSH_KEY_REVOKED",
        lambda: project(
            target=SshTargetV1(user="queen", host="node.example.test"),
            host_key=_host_key(api, state="revoked"),
            credential=credential,
            connect_timeout_seconds=5,
        ),
    )
    _raises(
        "RQ_E_SSH_AUTHORITY_INVALID",
        lambda: _credential(api, credential_kind="fido-v1"),
    )
    _raises("RQ_E_SSH_ENDPOINT_UNSUPPORTED", lambda: _credential(api, port=2222))


def test_argv_template_disables_implicit_trust_agent_tty_and_forwarding() -> None:
    api = _api()
    project = api["project_ssh_argv_policy"]
    argv_for_test = api["_argv_for_contract_test"]
    certificate_policy = api["_certificate_sibling_policy_for_contract_test"]
    assert callable(project)
    assert callable(argv_for_test)
    assert callable(certificate_policy)

    policy = project(
        target=SshTargetV1(user="queen", host="node.example.test"),
        host_key=_host_key(api),
        credential=_credential(api),
        connect_timeout_seconds=5,
    )
    argv = argv_for_test(policy)
    assert argv[:5] == ("/usr/bin/ssh", "-F", "none", "-p", "22")
    assert "IdentityFile=__RQ_PRIVATE_IDENTITY_FILE__" in argv
    assert "UserKnownHostsFile=__RQ_PRIVATE_KNOWN_HOSTS__" in argv
    assert "GlobalKnownHostsFile=__RQ_PRIVATE_KNOWN_HOSTS__" in argv
    assert "RevokedHostKeys=__RQ_PRIVATE_REVOKED_HOST_KEYS__" in argv
    assert "CertificateFile=" not in "\n".join(argv)
    assert certificate_policy(policy) == "require-identity-cert-sibling-absent-at-exec"
    for required in (
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "PKCS11Provider=none",
        "KbdInteractiveAuthentication=no",
        "PasswordAuthentication=no",
        "HostbasedAuthentication=no",
        "GSSAPIAuthentication=no",
        "GSSAPIKeyExchange=no",
        "PubkeyAuthentication=yes",
        "PreferredAuthentications=publickey",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "ControlPath=none",
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no",
        "CheckHostIP=no",
        "CanonicalizeHostname=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ConnectTimeout=5",
        "ConnectionAttempts=1",
        "-T",
    ):
        assert required in argv
    for forbidden in (
        "accept-new",
        "-n",
        "-N",
        "-v",
        "-E",
        "ProxyUseFdpass",
        "SecurityKeyProvider=none",
        "node.example.test",
        "queen",
        "exec /bin/sh -s --",
    ):
        assert forbidden not in argv
    for timeout in (0, contract.MAX_SSH_CONNECT_TIMEOUT_SECONDS + 1):
        _raises(
            "RQ_E_SSH_AUTHORITY_INVALID",
            lambda timeout=timeout: project(
                target=SshTargetV1(user="queen", host="node.example.test"),
                host_key=_host_key(api),
                credential=_credential(api),
                connect_timeout_seconds=timeout,
            ),
        )


def test_contract_repr_and_failures_are_redacted() -> None:
    api = _api()
    host_key = _host_key(api)
    authority = _authority(api, host_key)
    credential = _credential(api)
    project = api["project_ssh_argv_policy"]
    assert callable(project)
    policy = project(
        target=SshTargetV1(user="queen", host="node.example.test"),
        host_key=host_key,
        credential=credential,
        connect_timeout_seconds=5,
    )
    protected = (
        "node.example.test",
        "queen",
        "identity-projection-d306",
        "d306-contract-test-public-key-blob",
        "__RQ_PRIVATE_IDENTITY_FILE__",
    )
    for value in (host_key, authority, credential, policy):
        assert str(value) == repr(value)
        assert "<redacted>" in repr(value)
        assert not any(item in repr(value) for item in protected)
        for attribute in (
            "record",
            "public_key_base64",
            "effective_host",
            "remote_user",
            "projection_id",
            "argv",
        ):
            assert not hasattr(value, attribute)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            _raises(
                "RQ_E_SSH_SERIALIZATION_FORBIDDEN",
                lambda operation=operation: operation(value),
            )
        for export in (vars, asdict, dict):
            with pytest.raises(TypeError):
                export(value)

    for value, private_slot, replacement in (
        (host_key, "_HostKeyCapabilityV1__state", "revoked"),
        (authority, "_RemoteQueenHostKeyAuthorityV1__authority_generation", 8),
        (credential, "_RawKeyCredentialCapabilityV1__host", "other.example.test"),
        (policy, "_OpenSshArgvPolicyV1__argv", ()),
    ):
        for attribute in ("public_after_issuance", private_slot):
            _raises(
                "RQ_E_SSH_CAPABILITY_IMMUTABLE",
                lambda value=value, attribute=attribute, replacement=replacement: (
                    setattr(value, attribute, replacement)
                ),
            )

    error = contract.RemoteQueenOpenSshContractError("RQ_E_SSH_AUTH_UNAVAILABLE")
    assert str(error) == "RQ_E_SSH_AUTH_UNAVAILABLE"
    assert repr(error) == "RemoteQueenOpenSshContractError(<redacted>)"
