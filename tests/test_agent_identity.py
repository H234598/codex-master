from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from codex_master.admin_hosts import AgentBindingV1, HostRegistry, HostRegistryError
from codex_master.agent_identity import AgentIdentityResolver


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def registry_at(tmp_path: Path) -> HostRegistry:
    return HostRegistry.for_test(tmp_path)


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


KEY_ONE = _key()
KEY_TWO = _key()


def _spki_digest(key: rsa.RSAPrivateKey) -> str:
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(spki).hexdigest()


SPKI_ONE = _spki_digest(KEY_ONE)
SPKI_TWO = _spki_digest(KEY_TWO)


def _cert_der(
    key: rsa.RSAPrivateKey,
    *,
    not_before: datetime = NOW - timedelta(minutes=5),
    not_after: datetime = NOW + timedelta(minutes=5),
) -> bytes:
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "worker-one")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


CERT_ONE_DER = _cert_der(KEY_ONE)
CERT_TWO_DER = _cert_der(KEY_TWO)
EXPIRED_CERT_DER = _cert_der(
    KEY_ONE,
    not_before=NOW - timedelta(hours=2),
    not_after=NOW - timedelta(hours=1),
)
FUTURE_CERT_DER = _cert_der(
    KEY_ONE,
    not_before=NOW + timedelta(hours=1),
    not_after=NOW + timedelta(hours=2),
)


def binding(
    host_ref: str,
    spki: str,
    *,
    lease_epoch: int = 1,
    enabled: bool = True,
) -> AgentBindingV1:
    return AgentBindingV1(
        host_ref=host_ref,
        client_spki_sha256=spki,
        lease_epoch=lease_epoch,
        enabled=enabled,
    )


def registration(
    ref: str = "worker-one",
    *,
    label: str = "Worker One",
    role: str = "execution",
) -> dict[str, object]:
    return {
        "ref": ref,
        "label": label,
        "role": role,
        "capabilities": ["resource.probe", "codex.execute"],
    }


def test_spki_digest_maps_to_exactly_one_enabled_host(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)
    registry.provision_agent_binding(
        registration(), binding("worker-one", SPKI_ONE), expected_generation=0
    )

    principal = AgentIdentityResolver(registry, now=lambda: NOW).resolve(CERT_ONE_DER)

    assert principal.host_ref == "worker-one"
    assert principal.registry_generation == 1
    assert principal.lease_epoch == 1


def test_same_spki_cannot_bind_second_host(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)
    registry.provision_agent_binding(
        registration(), binding("worker-one", SPKI_ONE), expected_generation=0
    )

    with pytest.raises(HostRegistryError, match="host.identity_mismatch"):
        registry.provision_agent_binding(
            registration("worker-two", label="Worker Two"),
            binding("worker-two", SPKI_ONE),
            expected_generation=1,
        )


def test_expired_or_not_yet_valid_certificate_is_rejected(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)
    registry.provision_agent_binding(
        registration(), binding("worker-one", SPKI_ONE), expected_generation=0
    )
    resolver = AgentIdentityResolver(registry, now=lambda: NOW)

    with pytest.raises(HostRegistryError, match="host.identity_invalid"):
        resolver.resolve(EXPIRED_CERT_DER)
    with pytest.raises(HostRegistryError, match="host.identity_invalid"):
        resolver.resolve(FUTURE_CERT_DER)


def test_disabled_binding_is_not_resolvable(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)
    registry.provision_agent_binding(
        registration(),
        binding("worker-one", SPKI_ONE, enabled=False),
        expected_generation=0,
    )

    with pytest.raises(HostRegistryError, match="host.identity_not_found"):
        AgentIdentityResolver(registry, now=lambda: NOW).resolve(CERT_ONE_DER)


def test_rotation_increments_generation_and_epoch_and_invalidates_old_spki(
    tmp_path: Path,
) -> None:
    registry = registry_at(tmp_path)
    registry.provision_agent_binding(
        registration(), binding("worker-one", SPKI_ONE), expected_generation=0
    )

    rotated = registry.provision_agent_binding(
        registration(), binding("worker-one", SPKI_TWO), expected_generation=1
    )

    assert rotated.generation == 2
    assert registry.agent_binding("worker-one").lease_epoch == 2
    assert registry.resolve_agent_spki(SPKI_TWO).lease_epoch == 2
    with pytest.raises(HostRegistryError, match="host.identity_not_found"):
        registry.resolve_agent_spki(SPKI_ONE)
    principal = AgentIdentityResolver(registry, now=lambda: NOW).resolve(CERT_TWO_DER)
    assert principal.host_ref == "worker-one"
    assert principal.registry_generation == 2
    assert principal.lease_epoch == 2


def test_malformed_certificate_or_binding_is_rejected(tmp_path: Path) -> None:
    registry = registry_at(tmp_path)
    registry.provision_agent_binding(
        registration(), binding("worker-one", SPKI_ONE), expected_generation=0
    )

    with pytest.raises(HostRegistryError, match="host.identity_invalid"):
        AgentIdentityResolver(registry, now=lambda: NOW).resolve(b"not-a-cert")
    with pytest.raises(HostRegistryError, match="host.identity_invalid"):
        registry.provision_agent_binding(
            registration("worker-two", label="Worker Two"),
            binding("worker-two", "sha256:nothex"),
            expected_generation=1,
        )
