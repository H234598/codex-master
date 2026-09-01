"""mTLS client-certificate identity resolution for statically bound host agents."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .admin_hosts import AgentPrincipalV1, HostRegistry, HostRegistryError


class AgentIdentityResolver:
    """Resolve a peer certificate to the single enabled registry principal."""

    def __init__(
        self,
        registry: HostRegistry,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._now = now or (lambda: datetime.now(UTC))

    def resolve(self, peer_certificate_der: bytes) -> AgentPrincipalV1:
        if type(peer_certificate_der) is not bytes:
            raise HostRegistryError("host.identity_invalid")
        try:
            certificate = x509.load_der_x509_certificate(peer_certificate_der)
            now = self._now()
            if now.tzinfo is None or now.utcoffset() is None:
                raise ValueError
            now = now.astimezone(UTC)
            if not (
                _not_valid_before(certificate) <= now <= _not_valid_after(certificate)
            ):
                raise ValueError
            spki = certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (TypeError, ValueError):
            raise HostRegistryError("host.identity_invalid") from None
        digest = "sha256:" + hashlib.sha256(spki).hexdigest()
        return self._registry.resolve_agent_spki(digest)


def _not_valid_before(certificate: x509.Certificate) -> datetime:
    value = getattr(certificate, "not_valid_before_utc", None)
    if value is None:
        value = certificate.not_valid_before.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _not_valid_after(certificate: x509.Certificate) -> datetime:
    value = getattr(certificate, "not_valid_after_utc", None)
    if value is None:
        value = certificate.not_valid_after.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = ["AgentIdentityResolver"]
