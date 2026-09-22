"""Pure D306 capabilities and policies for the future OpenSSH transport.

This module deliberately has no authority materialization, process execution,
host-facts artifact, filesystem access, or verification receipt.  Its private
issuers are a package-component boundary for a later local authority reader
and for these focused tests; they are not a Python sandbox or proof that an
external authority has been checked.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re

from .remote_queen_bootstrap import SshTargetV1
from .remote_queen_ssh import MAX_SSH_CONNECT_TIMEOUT_SECONDS, SSH_HOST_KEY_TYPES


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z", re.ASCII)
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_SSH_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z")
_ACTIVE = "active"
_REVOKED = "revoked"
_RAW_KEY_CREDENTIAL_KIND = "openssh-identity-file-v1"
_CERTIFICATE_SIBLING_POLICY = "require-identity-cert-sibling-absent-at-exec"


class RemoteQueenOpenSshContractError(ValueError):
    """A fixed public error code that contains no protected contract value."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return "RemoteQueenOpenSshContractError(<redacted>)"


class HostKeyEnrollmentStateV1:
    """The two authority-attested enrollment states accepted by V1."""

    ACTIVE = _ACTIVE
    REVOKED = _REVOKED


def sha256_digest(value: bytes) -> str:
    """Return the exact SHA-256 digest spelling used by this pure contract."""

    if type(value) is not bytes:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def ssh_sha256_fingerprint(raw_blob: bytes) -> str:
    """Bind a raw blob to its OpenSSH SHA-256 fingerprint spelling.

    This is a structural digest binding only.  It does not parse or validate a
    complete SSH public-key wire format; the later authority validates the
    canonical record with the installed ``ssh-keygen`` before issuance.
    """

    if type(raw_blob) is not bytes or not raw_blob:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    encoded = base64.b64encode(hashlib.sha256(raw_blob).digest()).decode("ascii")
    return "SHA256:" + encoded.rstrip("=")


def _error(code: str) -> None:
    raise RemoteQueenOpenSshContractError(code)


def _require_digest(value: object, code: str = "RQ_E_SSH_AUTHORITY_INVALID") -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _error(code)
    return value


def _require_identifier(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or any(character.isspace() for character in value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return value


def _require_generation(value: object, code: str = "RQ_E_SSH_AUTHORITY_INVALID") -> int:
    if type(value) is not int or value <= 0:
        _error(code)
    return value


def _require_state(value: object, code: str = "RQ_E_SSH_AUTHORITY_INVALID") -> str:
    if value not in {_ACTIVE, _REVOKED}:
        _error(code)
    return value


def _is_dns_or_ipv4(host: str) -> bool:
    if (
        not 1 <= len(host) <= 253
        or not host.isascii()
        or any(character.isspace() for character in host)
    ):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in host):
        return False
    if any(token in host for token in (":", "[", "]", "@", "/", "\\")):
        return False
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        labels = host.split(".")
        if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
            return False
        if len(labels) == 4 and all(label.isdigit() for label in labels):
            return False
    return True


def _require_endpoint(host: object, port: object) -> str:
    if type(host) is not str or not _is_dns_or_ipv4(host) or type(port) is not int:
        _error("RQ_E_SSH_ENDPOINT_UNSUPPORTED")
    if port != 22:
        _error("RQ_E_SSH_ENDPOINT_UNSUPPORTED")
    return host


def _require_user(value: object) -> str:
    if type(value) is not str or _SSH_USER.fullmatch(value) is None:
        _error("RQ_E_SSH_CREDENTIAL_USER_MISMATCH")
    return value


def _decode_public_blob(value: bytes) -> tuple[str, bytes]:
    try:
        encoded = value.decode("ascii")
        raw_blob = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeDecodeError, ValueError):
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    if not raw_blob or base64.b64encode(raw_blob).decode("ascii") != encoded:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return encoded, raw_blob


def _parse_known_hosts_record(record: object) -> tuple[str, str, str, bytes, str, str]:
    if type(record) is not bytes or not record:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    if not record.endswith(b"\n") or record.count(b"\n") != 1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    body = record[:-1]
    if b"\r" in body or b"\x00" in body:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    fields = body.split(b" ")
    if len(fields) != 3 or any(not field for field in fields):
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    try:
        host = fields[0].decode("ascii")
        key_type = fields[1].decode("ascii")
    except UnicodeDecodeError:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    _require_endpoint(host, 22)
    if key_type not in SSH_HOST_KEY_TYPES:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    public_key_base64, raw_blob = _decode_public_blob(fields[2])
    return (
        host,
        key_type,
        public_key_base64,
        raw_blob,
        ssh_sha256_fingerprint(raw_blob),
        sha256_digest(record),
    )


class _OpaqueCapability:
    """A slotted component capability with explicit anti-export behavior."""

    __slots__ = ()

    def __setattr__(self, name: object, value: object) -> None:
        _error("RQ_E_SSH_CAPABILITY_IMMUTABLE")

    def __delattr__(self, name: object) -> None:
        _error("RQ_E_SSH_CAPABILITY_IMMUTABLE")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> object:
        _error("RQ_E_SSH_SERIALIZATION_FORBIDDEN")

    def __deepcopy__(self, memo: object) -> object:
        _error("RQ_E_SSH_SERIALIZATION_FORBIDDEN")

    def __reduce__(self) -> object:
        _error("RQ_E_SSH_SERIALIZATION_FORBIDDEN")

    def __reduce_ex__(self, protocol: object) -> object:
        _error("RQ_E_SSH_SERIALIZATION_FORBIDDEN")

    def __getstate__(self) -> object:
        _error("RQ_E_SSH_SERIALIZATION_FORBIDDEN")


class HostKeyCapabilityV1(_OpaqueCapability):
    """An opaque, immutable capability derived from one canonical record."""

    __slots__ = (
        "__authority_digest",
        "__authority_generation",
        "__enrollment_id",
        "__fingerprint",
        "__host",
        "__key_type",
        "__provenance_digest",
        "__public_key_base64",
        "__raw_blob",
        "__record",
        "__record_digest",
        "__state",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        _error("RQ_E_SSH_ISSUANCE_FORBIDDEN")

    @classmethod
    def _create(
        cls,
        *,
        authority_digest: str,
        authority_generation: int,
        enrollment_id: str,
        fingerprint: str,
        host: str,
        key_type: str,
        provenance_digest: str,
        public_key_base64: str,
        raw_blob: bytes,
        record: bytes,
        record_digest: str,
        state: str,
    ) -> HostKeyCapabilityV1:
        value = object.__new__(cls)
        object.__setattr__(
            value, "_HostKeyCapabilityV1__authority_digest", authority_digest
        )
        object.__setattr__(
            value, "_HostKeyCapabilityV1__authority_generation", authority_generation
        )
        object.__setattr__(value, "_HostKeyCapabilityV1__enrollment_id", enrollment_id)
        object.__setattr__(value, "_HostKeyCapabilityV1__fingerprint", fingerprint)
        object.__setattr__(value, "_HostKeyCapabilityV1__host", host)
        object.__setattr__(value, "_HostKeyCapabilityV1__key_type", key_type)
        object.__setattr__(
            value, "_HostKeyCapabilityV1__provenance_digest", provenance_digest
        )
        object.__setattr__(
            value, "_HostKeyCapabilityV1__public_key_base64", public_key_base64
        )
        object.__setattr__(value, "_HostKeyCapabilityV1__raw_blob", raw_blob)
        object.__setattr__(value, "_HostKeyCapabilityV1__record", record)
        object.__setattr__(value, "_HostKeyCapabilityV1__record_digest", record_digest)
        object.__setattr__(value, "_HostKeyCapabilityV1__state", state)
        return value


class RemoteQueenHostKeyAuthorityV1(_OpaqueCapability):
    """An opaque homogeneous collection of issuer-created host-key capabilities."""

    __slots__ = ("__authority_digest", "__authority_generation", "__capabilities")

    def __init__(self, *args: object, **kwargs: object) -> None:
        _error("RQ_E_SSH_ISSUANCE_FORBIDDEN")

    @classmethod
    def _create(
        cls,
        authority_generation: int,
        authority_digest: str,
        capabilities: tuple[HostKeyCapabilityV1, ...],
    ) -> RemoteQueenHostKeyAuthorityV1:
        value = object.__new__(cls)
        object.__setattr__(
            value,
            "_RemoteQueenHostKeyAuthorityV1__authority_generation",
            authority_generation,
        )
        object.__setattr__(
            value, "_RemoteQueenHostKeyAuthorityV1__authority_digest", authority_digest
        )
        object.__setattr__(
            value, "_RemoteQueenHostKeyAuthorityV1__capabilities", capabilities
        )
        return value


class RawKeyCredentialCapabilityV1(_OpaqueCapability):
    """An opaque raw-key-only credential projection binding without key bytes."""

    __slots__ = (
        "__binding_digest",
        "__credential_generation",
        "__credential_id",
        "__credential_provenance_digest",
        "__host",
        "__host_authority_digest",
        "__host_authority_generation",
        "__kind",
        "__port",
        "__projection_id",
        "__projection_manifest_digest",
        "__remote_user",
        "__state",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        _error("RQ_E_SSH_ISSUANCE_FORBIDDEN")

    @classmethod
    def _create(
        cls,
        *,
        binding_digest: str,
        credential_generation: int,
        credential_id: str,
        credential_provenance_digest: str,
        host: str,
        host_authority_digest: str,
        host_authority_generation: int,
        port: int,
        projection_id: str,
        projection_manifest_digest: str,
        remote_user: str,
        state: str,
    ) -> RawKeyCredentialCapabilityV1:
        value = object.__new__(cls)
        object.__setattr__(
            value, "_RawKeyCredentialCapabilityV1__binding_digest", binding_digest
        )
        object.__setattr__(
            value,
            "_RawKeyCredentialCapabilityV1__credential_generation",
            credential_generation,
        )
        object.__setattr__(
            value, "_RawKeyCredentialCapabilityV1__credential_id", credential_id
        )
        object.__setattr__(
            value,
            "_RawKeyCredentialCapabilityV1__credential_provenance_digest",
            credential_provenance_digest,
        )
        object.__setattr__(value, "_RawKeyCredentialCapabilityV1__host", host)
        object.__setattr__(
            value,
            "_RawKeyCredentialCapabilityV1__host_authority_digest",
            host_authority_digest,
        )
        object.__setattr__(
            value,
            "_RawKeyCredentialCapabilityV1__host_authority_generation",
            host_authority_generation,
        )
        object.__setattr__(
            value, "_RawKeyCredentialCapabilityV1__kind", _RAW_KEY_CREDENTIAL_KIND
        )
        object.__setattr__(value, "_RawKeyCredentialCapabilityV1__port", port)
        object.__setattr__(
            value, "_RawKeyCredentialCapabilityV1__projection_id", projection_id
        )
        object.__setattr__(
            value,
            "_RawKeyCredentialCapabilityV1__projection_manifest_digest",
            projection_manifest_digest,
        )
        object.__setattr__(
            value, "_RawKeyCredentialCapabilityV1__remote_user", remote_user
        )
        object.__setattr__(value, "_RawKeyCredentialCapabilityV1__state", state)
        return value


class OpenSshArgvPolicyV1(_OpaqueCapability):
    """A non-executable argv policy with private placeholders only."""

    __slots__ = ("__argv", "__certificate_sibling_policy")

    def __init__(self, *args: object, **kwargs: object) -> None:
        _error("RQ_E_SSH_ISSUANCE_FORBIDDEN")

    @classmethod
    def _create(cls, argv: tuple[str, ...]) -> OpenSshArgvPolicyV1:
        value = object.__new__(cls)
        object.__setattr__(value, "_OpenSshArgvPolicyV1__argv", argv)
        object.__setattr__(
            value,
            "_OpenSshArgvPolicyV1__certificate_sibling_policy",
            _CERTIFICATE_SIBLING_POLICY,
        )
        return value


def _issue_host_key_capability_v1(
    *,
    known_hosts_record: bytes,
    enrollment_id: str,
    authority_generation: int,
    authority_digest: str,
    enrollment_provenance_digest: str,
    state: str,
) -> HostKeyCapabilityV1:
    """Package-private issuer boundary; it performs no authority I/O."""

    _require_identifier(enrollment_id)
    _require_generation(authority_generation)
    _require_digest(authority_digest, "RQ_E_SSH_AUTHORITY_DIGEST")
    _require_digest(enrollment_provenance_digest)
    _require_state(state)
    host, key_type, public_key_base64, raw_blob, fingerprint, record_digest = (
        _parse_known_hosts_record(known_hosts_record)
    )
    return HostKeyCapabilityV1._create(
        authority_digest=authority_digest,
        authority_generation=authority_generation,
        enrollment_id=enrollment_id,
        fingerprint=fingerprint,
        host=host,
        key_type=key_type,
        provenance_digest=enrollment_provenance_digest,
        public_key_base64=public_key_base64,
        raw_blob=raw_blob,
        record=known_hosts_record,
        record_digest=record_digest,
        state=state,
    )


def _issue_host_key_authority_v1(
    *,
    authority_generation: int,
    authority_digest: str,
    capabilities: tuple[HostKeyCapabilityV1, ...],
) -> RemoteQueenHostKeyAuthorityV1:
    """Package-private homogeneous authority issuer for a future reader."""

    _require_generation(authority_generation)
    _require_digest(authority_digest, "RQ_E_SSH_AUTHORITY_DIGEST")
    if type(capabilities) is not tuple or not capabilities:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    if any(type(capability) is not HostKeyCapabilityV1 for capability in capabilities):
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    enrollment_ids = tuple(
        capability._HostKeyCapabilityV1__enrollment_id for capability in capabilities
    )
    if len(set(enrollment_ids)) != len(enrollment_ids):
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    if any(
        capability._HostKeyCapabilityV1__authority_generation != authority_generation
        or capability._HostKeyCapabilityV1__authority_digest != authority_digest
        for capability in capabilities
    ):
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return RemoteQueenHostKeyAuthorityV1._create(
        authority_generation, authority_digest, capabilities
    )


def _credential_binding_bytes(
    *,
    credential_id: str,
    credential_generation: int,
    host: str,
    host_authority_digest: str,
    host_authority_generation: int,
    port: int,
    projection_id: str,
    projection_manifest_digest: str,
    remote_user: str,
    credential_provenance_digest: str,
    state: str,
) -> bytes:
    values = (
        _RAW_KEY_CREDENTIAL_KIND,
        credential_id,
        str(credential_generation),
        host,
        str(port),
        remote_user,
        str(host_authority_generation),
        host_authority_digest,
        projection_id,
        projection_manifest_digest,
        credential_provenance_digest,
        state,
    )
    return ("\n".join(values) + "\n").encode("ascii")


def _issue_raw_key_credential_v1(
    *,
    credential_id: str,
    credential_generation: int,
    credential_kind: str,
    effective_host: str,
    port: int,
    remote_user: str,
    host_authority_generation: int,
    host_authority_digest: str,
    projection_id: str,
    projection_manifest_digest: str,
    credential_provenance_digest: str,
    state: str,
) -> RawKeyCredentialCapabilityV1:
    """Package-private raw-key-only credential issuer with no key or path."""

    _require_identifier(credential_id)
    _require_generation(credential_generation, "RQ_E_SSH_AUTH_UNAVAILABLE")
    if credential_kind != _RAW_KEY_CREDENTIAL_KIND:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    _require_endpoint(effective_host, port)
    _require_user(remote_user)
    _require_generation(host_authority_generation, "RQ_E_SSH_AUTH_UNAVAILABLE")
    _require_digest(host_authority_digest, "RQ_E_SSH_AUTHORITY_DIGEST")
    _require_identifier(projection_id)
    _require_digest(projection_manifest_digest, "RQ_E_SSH_AUTHORITY_DIGEST")
    _require_digest(credential_provenance_digest)
    _require_state(state, "RQ_E_SSH_CREDENTIAL_REVOKED")
    binding_digest = sha256_digest(
        _credential_binding_bytes(
            credential_id=credential_id,
            credential_generation=credential_generation,
            host=effective_host,
            host_authority_digest=host_authority_digest,
            host_authority_generation=host_authority_generation,
            port=port,
            projection_id=projection_id,
            projection_manifest_digest=projection_manifest_digest,
            remote_user=remote_user,
            credential_provenance_digest=credential_provenance_digest,
            state=state,
        )
    )
    return RawKeyCredentialCapabilityV1._create(
        binding_digest=binding_digest,
        credential_generation=credential_generation,
        credential_id=credential_id,
        credential_provenance_digest=credential_provenance_digest,
        host=effective_host,
        host_authority_digest=host_authority_digest,
        host_authority_generation=host_authority_generation,
        port=port,
        projection_id=projection_id,
        projection_manifest_digest=projection_manifest_digest,
        remote_user=remote_user,
        state=state,
    )


def select_active_host_key_capability(
    authority: RemoteQueenHostKeyAuthorityV1,
    target: SshTargetV1,
) -> HostKeyCapabilityV1:
    """Select one active V1 DNS/IPv4:22 record without normalizing it."""

    if type(authority) is not RemoteQueenHostKeyAuthorityV1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    if type(target) is not SshTargetV1:
        _error("RQ_E_SSH_ENDPOINT_UNSUPPORTED")
    _require_endpoint(target.host, 22)
    matching = tuple(
        capability
        for capability in authority._RemoteQueenHostKeyAuthorityV1__capabilities
        if capability._HostKeyCapabilityV1__host == target.host
    )
    active = tuple(
        capability
        for capability in matching
        if capability._HostKeyCapabilityV1__state == _ACTIVE
    )
    if len(active) == 1:
        return active[0]
    if len(active) > 1:
        _error("RQ_E_SSH_ENROLLMENT_AMBIGUOUS")
    if any(
        capability._HostKeyCapabilityV1__state == _REVOKED for capability in matching
    ):
        _error("RQ_E_SSH_KEY_REVOKED")
    _error("RQ_E_SSH_ENROLLMENT_MISSING")


def _require_policy_target(target: object) -> tuple[str, str]:
    if type(target) is not SshTargetV1:
        _error("RQ_E_SSH_ENDPOINT_UNSUPPORTED")
    host = _require_endpoint(target.host, 22)
    return host, _require_user(target.user)


def project_ssh_argv_policy(
    *,
    target: SshTargetV1,
    host_key: HostKeyCapabilityV1,
    credential: RawKeyCredentialCapabilityV1,
    connect_timeout_seconds: int,
) -> OpenSshArgvPolicyV1:
    """Project the D305 base policy without paths, destination, or command.

    A later materializer replaces only the private placeholders after checking
    its local authority files and the required absent ``-cert.pub`` sibling.
    This return value is intentionally not an executable invocation while the
    source-owned host-facts artifact remains unavailable.
    """

    host, user = _require_policy_target(target)
    if type(host_key) is not HostKeyCapabilityV1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    if host_key._HostKeyCapabilityV1__state != _ACTIVE:
        _error("RQ_E_SSH_KEY_REVOKED")
    if host_key._HostKeyCapabilityV1__host != host:
        _error("RQ_E_SSH_ENROLLMENT_MISSING")
    if type(credential) is not RawKeyCredentialCapabilityV1:
        _error("RQ_E_SSH_AUTH_UNAVAILABLE")
    if credential._RawKeyCredentialCapabilityV1__state == _REVOKED:
        _error("RQ_E_SSH_CREDENTIAL_REVOKED")
    if credential._RawKeyCredentialCapabilityV1__remote_user != user:
        _error("RQ_E_SSH_CREDENTIAL_USER_MISMATCH")
    if (
        credential._RawKeyCredentialCapabilityV1__host != host
        or credential._RawKeyCredentialCapabilityV1__port != 22
        or credential._RawKeyCredentialCapabilityV1__host_authority_generation
        != host_key._HostKeyCapabilityV1__authority_generation
        or credential._RawKeyCredentialCapabilityV1__host_authority_digest
        != host_key._HostKeyCapabilityV1__authority_digest
    ):
        _error("RQ_E_SSH_AUTH_UNAVAILABLE")
    if (
        type(connect_timeout_seconds) is not int
        or not 1 <= connect_timeout_seconds <= MAX_SSH_CONNECT_TIMEOUT_SECONDS
    ):
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    argv = (
        "/usr/bin/ssh",
        "-F",
        "none",
        "-p",
        "22",
        "-o",
        "BatchMode=yes",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "HostbasedAuthentication=no",
        "-o",
        "GSSAPIAuthentication=no",
        "-o",
        "GSSAPIKeyExchange=no",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "IdentityAgent=none",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityFile=__RQ_PRIVATE_IDENTITY_FILE__",
        "-o",
        "AddKeysToAgent=no",
        "-o",
        "PKCS11Provider=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ControlPath=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "CheckHostIP=no",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "UserKnownHostsFile=__RQ_PRIVATE_KNOWN_HOSTS__",
        "-o",
        "GlobalKnownHostsFile=__RQ_PRIVATE_KNOWN_HOSTS__",
        "-o",
        "RevokedHostKeys=__RQ_PRIVATE_REVOKED_HOST_KEYS__",
        "-o",
        f"ConnectTimeout={connect_timeout_seconds}",
        "-o",
        "ConnectionAttempts=1",
        "-T",
    )
    return OpenSshArgvPolicyV1._create(argv)


def host_facts_v1_operation(*args: object, **kwargs: object) -> None:
    """Fail closed until a separate source-owned facts artifact exists."""

    _error("RQ_E_SSH_OPERATION_UNAVAILABLE")


def _host_key_fingerprint_for_contract_test(value: object) -> str:
    if type(value) is not HostKeyCapabilityV1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return value._HostKeyCapabilityV1__fingerprint


def _host_key_record_digest_for_contract_test(value: object) -> str:
    if type(value) is not HostKeyCapabilityV1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return value._HostKeyCapabilityV1__record_digest


def _credential_binding_digest_for_contract_test(value: object) -> str:
    if type(value) is not RawKeyCredentialCapabilityV1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return value._RawKeyCredentialCapabilityV1__binding_digest


def _argv_for_contract_test(value: object) -> tuple[str, ...]:
    if type(value) is not OpenSshArgvPolicyV1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return value._OpenSshArgvPolicyV1__argv


def _certificate_sibling_policy_for_contract_test(value: object) -> str:
    if type(value) is not OpenSshArgvPolicyV1:
        _error("RQ_E_SSH_AUTHORITY_INVALID")
    return value._OpenSshArgvPolicyV1__certificate_sibling_policy
