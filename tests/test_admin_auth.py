from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

from codex_master.admin_auth import (
    AdminAuthError,
    CloudflareAccessVerifier,
    MasterjetBearerVerifier,
    TotpStepUpVerifier,
)


NOW = 2_000_000_000
ISSUER = "https://team.cloudflareaccess.com"
AUDIENCE = "application-audience"
TOTP_SECRET = b"12345678901234567890"


def _b64(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def rsa_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "current-key",
                "use": "sig",
                "alg": "RS256",
                "n": _b64(numbers.n),
                "e": _b64(numbers.e),
            }
        ]
    }
    return private, jwks


def _token(private, **changes: object) -> str:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "sub": "user-one",
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 120,
    }
    claims.update(changes)
    return jwt.encode(
        claims, private, algorithm="RS256", headers={"kid": "current-key"}
    )


def _jwk(private, kid: str) -> dict[str, str]:
    numbers = private.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64(numbers.n),
        "e": _b64(numbers.e),
    }


def _key_token(private, kid: str) -> str:
    claims = {
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "sub": "user-one",
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 120,
    }
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid})


def _verifier(rsa_material) -> CloudflareAccessVerifier:
    _private, jwks = rsa_material
    return CloudflareAccessVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=jwks,
        principal_resolver=lambda subject, _claims: (
            (
                "fleet.read",
                "fleet.google.provision",
            )
            if subject == "user-one"
            else ()
        ),
        clock=lambda: NOW,
    )


def _private_file(tmp_path: Path, name: str, payload: bytes) -> int:
    path = tmp_path / name
    path.write_bytes(payload)
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def _totp(counter: int) -> str:
    digest = hmac.new(TOTP_SECRET, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def test_cloudflare_assertion_builds_principal_from_server_policy(rsa_material) -> None:
    private, _jwks = rsa_material
    principal = _verifier(rsa_material).verify(_token(private))

    assert principal.subject == "user-one"
    assert principal.scopes == ("fleet.read", "fleet.google.provision")
    assert principal.authentication == "cloudflare-access"
    assert principal.step_up is False


def test_cloudflare_jwks_can_be_loaded_and_rotated_from_private_fds(
    tmp_path, rsa_material
) -> None:
    private, jwks = rsa_material
    first_fd = _private_file(tmp_path, "jwks", json.dumps(jwks).encode("ascii"))
    second_fd = _private_file(
        tmp_path, "jwks-rotated", json.dumps(jwks).encode("ascii")
    )
    try:
        verifier = CloudflareAccessVerifier.from_fd(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_fd=first_fd,
            principal_resolver=lambda _subject, _claims: ("fleet.read",),
            clock=lambda: NOW,
        )
        verifier.replace_jwks_from_fd(second_fd)
    finally:
        os.close(first_fd)
        os.close(second_fd)

    assert verifier.verify(_token(private)).scopes == ("fleet.read",)


def test_cloudflare_official_certs_document_and_two_key_lkg_rotation() -> None:
    current = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    previous = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    document = {
        "keys": [_jwk(current, "current"), _jwk(previous, "previous")],
        "public_cert": "bounded metadata only",
        "public_certs": {"current": "bounded metadata only"},
    }
    verifier = CloudflareAccessVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=document,
        principal_resolver=lambda _subject, _claims: ("fleet.read",),
        clock=lambda: NOW,
    )

    assert verifier.verify(_key_token(current, "current")).subject == "user-one"
    assert verifier.verify(_key_token(previous, "previous")).subject == "user-one"
    unknown = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AdminAuthError, match="authority.identity_invalid"):
        verifier.verify(_key_token(unknown, "unknown"))
    with pytest.raises(AdminAuthError, match="authority.configuration_invalid"):
        verifier.replace_jwks({"keys": []})
    assert verifier.verify(_key_token(current, "current")).subject == "user-one"
    assert verifier.jwks_kids == ("current", "previous")
    assert verifier.refresh_jwks(lambda: {"keys": []}) is False
    assert verifier.jwks_kids == ("current", "previous")


def test_header_presence_without_valid_signature_is_denied(rsa_material) -> None:
    with pytest.raises(AdminAuthError, match="authority.identity_invalid"):
        _verifier(rsa_material).verify("eyJhbGciOiJub25lIn0.e30.")


def test_algorithm_confusion_and_unknown_key_are_denied(rsa_material) -> None:
    private, jwks = rsa_material
    verifier = _verifier(rsa_material)
    confused = jwt.encode(
        {
            "iss": ISSUER,
            "aud": [AUDIENCE],
            "sub": "user-one",
            "iat": NOW,
            "nbf": NOW,
            "exp": NOW + 30,
        },
        "shared-value-with-at-least-thirty-two-bytes",
        algorithm="HS256",
        headers={"kid": "current-key"},
    )
    unknown = jwt.encode(
        jwt.decode(_token(private), options={"verify_signature": False}),
        private,
        algorithm="RS256",
        headers={"kid": "retired-key"},
    )

    for token in (confused, unknown):
        with pytest.raises(AdminAuthError, match="authority.identity_invalid"):
            verifier.verify(token)
    assert jwks["keys"][0]["alg"] == "RS256"


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://other.cloudflareaccess.com"},
        {"aud": ["other-audience"]},
        {"exp": NOW - 1},
        {"nbf": NOW + 1},
        {"iat": NOW + 1},
        {"iat": NOW - 601},
        {"sub": ""},
    ],
)
def test_cloudflare_claim_boundaries_fail_closed(rsa_material, claims) -> None:
    private, _jwks = rsa_material
    with pytest.raises(AdminAuthError, match="authority.identity_invalid"):
        _verifier(rsa_material).verify(_token(private, **claims))


def test_cloudflare_policy_resolver_must_return_valid_explicit_scopes(
    rsa_material,
) -> None:
    private, jwks = rsa_material
    verifier = CloudflareAccessVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks=jwks,
        principal_resolver=lambda _subject, _claims: ("fleet.read", "bad scope"),
        clock=lambda: NOW,
    )

    with pytest.raises(AdminAuthError, match="authority.scope_invalid"):
        verifier.verify(_token(private))


def test_masterjet_bearer_is_loaded_from_private_fd_and_compared_exactly(
    tmp_path,
) -> None:
    fd = _private_file(tmp_path, "bearer", b"service-bearer\n")
    try:
        verifier = MasterjetBearerVerifier.from_fd(
            fd,
            subject="usage-service",
            scopes=("fleet.read", "fleet.secrets.ingress"),
        )
    finally:
        os.close(fd)

    assert verifier.verify("service-bearer").subject == "usage-service"
    with pytest.raises(AdminAuthError, match="authority.identity_invalid"):
        verifier.verify("service-bearer-extra")


def test_credential_fd_must_be_private_regular_and_bounded(tmp_path) -> None:
    path = tmp_path / "public"
    path.write_bytes(b"value")
    path.chmod(0o644)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(AdminAuthError, match="authority.credential_invalid"):
            MasterjetBearerVerifier.from_fd(fd, subject="svc", scopes=("fleet.read",))
    finally:
        os.close(fd)


def test_credential_fd_must_not_be_writable(tmp_path) -> None:
    path = tmp_path / "writable-fd"
    path.write_bytes(b"value")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with pytest.raises(AdminAuthError, match="authority.credential_invalid"):
            MasterjetBearerVerifier.from_fd(fd, subject="svc", scopes=("fleet.read",))
    finally:
        os.close(fd)


def test_totp_accepts_once_then_rejects_replay_and_cross_subject(tmp_path) -> None:
    encoded = base64.b32encode(TOTP_SECRET)
    fd = _private_file(tmp_path, "totp", encoded + b"\n")
    try:
        verifier = TotpStepUpVerifier.from_fd(fd, clock=lambda: NOW, skew_steps=0)
    finally:
        os.close(fd)
    code = _totp(NOW // 30)

    assert verifier.verify("user-one", code) == NOW // 30
    for subject in ("user-one", "user-two"):
        with pytest.raises(AdminAuthError, match="authority.step_up_replayed"):
            verifier.verify(subject, code)


def test_totp_counter_consumption_is_atomic_under_concurrency(tmp_path) -> None:
    fd = _private_file(tmp_path, "totp", base64.b32encode(TOTP_SECRET))
    try:
        verifier = TotpStepUpVerifier.from_fd(fd, clock=lambda: NOW, skew_steps=0)
    finally:
        os.close(fd)
    code = _totp(NOW // 30)

    def attempt() -> str:
        try:
            verifier.verify("user-one", code)
        except AdminAuthError as error:
            return error.code
        return "ok"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: attempt(), range(16)))

    assert results.count("ok") == 1
    assert results.count("authority.step_up_replayed") == 15


def test_totp_rejects_bad_code_without_consuming_counter(tmp_path) -> None:
    fd = _private_file(tmp_path, "totp", base64.b32encode(TOTP_SECRET))
    try:
        verifier = TotpStepUpVerifier.from_fd(fd, clock=lambda: NOW, skew_steps=0)
    finally:
        os.close(fd)

    with pytest.raises(AdminAuthError, match="authority.step_up_invalid"):
        verifier.verify("user-one", "000000")
    assert verifier.verify("user-one", _totp(NOW // 30)) == NOW // 30


def test_totp_replay_claim_survives_verifier_restart(tmp_path) -> None:
    fd = _private_file(tmp_path, "totp", base64.b32encode(TOTP_SECRET))
    state_path = tmp_path / "totp-replay.sqlite3"
    try:
        first = TotpStepUpVerifier.from_fd(
            fd, clock=lambda: NOW, skew_steps=0, replay_state_path=state_path
        )
        assert first.verify("user-one", _totp(NOW // 30)) == NOW // 30
        first.close()
        second = TotpStepUpVerifier.from_fd(
            fd, clock=lambda: NOW, skew_steps=0, replay_state_path=state_path
        )
    finally:
        os.close(fd)
    with pytest.raises(AdminAuthError, match="authority.step_up_replayed"):
        second.verify("user-two", _totp(NOW // 30))
    second.close()
