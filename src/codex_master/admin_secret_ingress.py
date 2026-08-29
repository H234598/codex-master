"""Durable, owner-authoritative secret-ingress sessions and capabilities."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path, PurePosixPath
import re
import secrets
import time
from typing import Final, cast

from .admin_service import (
    SecretIngressOwnerError,
    SecretIngressResolutionV1,
    SecretIngressSessionV1,
    SecretIngressUploadReceiptV1,
)
from .credential_vault import CredentialVault, CredentialVaultError
from .hive.state import HiveStateError, HiveStateStore


_STATE_FILE: Final[PurePosixPath] = PurePosixPath("secret-ingress.json")
_MAX_STATE_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_SESSIONS: Final[int] = 4096
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_KINDS = frozenset({"openai.auth-json", "google.oauth-client", "google-oauth-code"})
_OPERATIONS = {
    "openai.auth-json": "openai.auth.apply",
    "google.oauth-client": "google.oauth-client-import.apply",
    "google-oauth-code": "google.oauth.complete",
}


AdminSecretIngressError = SecretIngressOwnerError


@dataclass(frozen=True, slots=True, repr=False)
class SecretUploadClaimV1:
    session_id: str
    nonce: str
    _issuer: object

    def __repr__(self) -> str:
        return "SecretUploadClaimV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SecretResolveClaimV1:
    session_id: str
    nonce: str
    _issuer: object

    def __repr__(self) -> str:
        return "SecretResolveClaimV1(<redacted>)"


class AdminSecretIngressOwner:
    """Persist exact session state; store secret bytes only in encrypted vault."""

    def __init__(
        self,
        state_root: Path,
        *,
        vault: CredentialVault,
        plan_resolver: Callable[[str, str, str], object],
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = 120,
    ) -> None:
        if (
            not isinstance(vault, CredentialVault)
            or not callable(plan_resolver)
            or not callable(clock)
            or type(ttl_seconds) is not int
            or not 30 <= ttl_seconds <= 900
        ):
            raise AdminSecretIngressError("control.owner_unavailable")
        try:
            self._state = HiveStateStore(state_root)
        except HiveStateError:
            raise AdminSecretIngressError("control.owner_unavailable") from None
        self._vault = vault
        self._plan_resolver = plan_resolver
        self._clock = clock
        self._ttl = ttl_seconds
        self._issuer = object()

    def create_session(self, **values: object) -> SecretIngressSessionV1:
        principal = _token(values.get("principal"))
        account_ref = _token(values.get("account_ref"))
        kind = _token(values.get("credential_kind"))
        if kind not in _KINDS:
            raise AdminSecretIngressError("control.request_invalid")
        generation = _generation(values.get("expected_generation"))
        idempotency_key = _token(values.get("idempotency_key"))
        digest = _digest(values.get("plan_digest"))
        plan_id_value = values.get("plan_id")
        plan_id = _token(plan_id_value) if plan_id_value is not None else None
        now = _now(self._clock)
        session_id = _session_id(principal, account_ref, kind, idempotency_key)
        record = {
            "session_id": session_id,
            "principal": principal,
            "account_ref": account_ref,
            "credential_kind": kind,
            "operation": _OPERATIONS[kind],
            "plan_id": plan_id,
            "plan_digest": digest,
            "expected_generation": generation,
            "create_idempotency_key": idempotency_key,
            "upload_idempotency_key": None,
            "apply_idempotency_key": None,
            "receipt_generation": None,
            "expires_at": now + self._ttl,
            "claim_nonce": None,
            "state": "authorized",
        }
        with self._state.locked():
            document = self._read_locked()
            sessions = cast(dict[str, object], document["sessions"])
            existing = sessions.get(session_id)
            if existing is not None:
                if existing != record:
                    raise AdminSecretIngressError("control.request_invalid")
            else:
                if len(sessions) >= _MAX_SESSIONS:
                    raise AdminSecretIngressError("control.owner_unavailable")
                sessions[session_id] = record
                self._write_locked(document)
        return SecretIngressSessionV1(session_id, account_ref, "authorized")

    def reserve_upload(
        self,
        session_id: str,
        *,
        principal: str,
        expected_generation: int,
        idempotency_key: str,
    ) -> SecretUploadClaimV1:
        session_id = _token(session_id)
        principal = _token(principal)
        expected_generation = _generation(expected_generation)
        idempotency_key = _token(idempotency_key)
        nonce = secrets.token_hex(32)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, session_id)
            self._live(record)
            if (
                record["state"] != "authorized"
                or record["principal"] != principal
                or record["expected_generation"] != expected_generation
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            record["state"] = "uploading"
            record["claim_nonce"] = nonce
            record["upload_idempotency_key"] = idempotency_key
            self._write_locked(document)
        return SecretUploadClaimV1(session_id, nonce, self._issuer)

    def put_secret(
        self,
        session_id: str,
        secret: bytes | bytearray | memoryview,
        *,
        principal: str,
        upload_claim: object,
    ) -> SecretIngressUploadReceiptV1:
        claim = self._upload_claim(upload_claim, session_id)
        principal = _token(principal)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] != "uploading"
                or record["claim_nonce"] != claim.nonce
                or record["principal"] != principal
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            generation = cast(int, record["expected_generation"]) + 1
        raw = _secret_bytes(secret)
        try:
            self._vault.store_projection(claim.session_id, generation, raw)
        except CredentialVaultError:
            self._mark_unknown(claim)
            raise AdminSecretIngressError("control.owner_unavailable") from None
        return SecretIngressUploadReceiptV1(
            claim.session_id,
            cast(str, record["account_ref"]),
            "consumed",
            generation,
        )

    def commit_upload(
        self, claim: SecretUploadClaimV1, receipt: SecretIngressUploadReceiptV1
    ) -> None:
        claim = self._upload_claim(claim, receipt.session_id)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] != "uploading"
                or record["claim_nonce"] != claim.nonce
                or receipt.generation != cast(int, record["expected_generation"]) + 1
            ):
                raise AdminSecretIngressError("control.owner_unavailable")
            record["state"] = "uploaded"
            record["receipt_generation"] = receipt.generation
            record["claim_nonce"] = None
            self._write_locked(document)

    def rollback_upload(self, claim: SecretUploadClaimV1) -> None:
        claim = self._upload_claim(claim, claim.session_id)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if record["state"] == "uploading" and record["claim_nonce"] == claim.nonce:
                record["state"] = "authorized"
                record["claim_nonce"] = None
                record["upload_idempotency_key"] = None
                self._write_locked(document)

    def reserve_resolve(
        self, session_id: str, **values: object
    ) -> SecretResolveClaimV1:
        session_id = _token(session_id)
        expected = {
            "principal": _token(values.get("principal")),
            "operation": _token(values.get("operation")),
            "account_ref": _token(values.get("account_ref")),
            "credential_kind": _token(values.get("credential_kind")),
            "plan_id": _optional_token(values.get("plan_id")),
            "plan_digest": _digest(values.get("plan_digest")),
            "expected_generation": _generation(values.get("expected_generation")),
            "create_idempotency_key": _token(values.get("create_idempotency_key")),
            "upload_idempotency_key": _token(values.get("upload_idempotency_key")),
            "receipt_generation": _generation(values.get("receipt_generation")),
        }
        idempotency_key = _token(values.get("idempotency_key"))
        nonce = secrets.token_hex(32)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, session_id)
            self._live(record)
            if record["state"] != "uploaded" or any(
                record[key] != value for key, value in expected.items()
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            record["state"] = "resolving"
            record["claim_nonce"] = nonce
            record["apply_idempotency_key"] = idempotency_key
            self._write_locked(document)
        return SecretResolveClaimV1(session_id, nonce, self._issuer)

    def resolve(self, claim: object) -> SecretIngressResolutionV1:
        claim = self._resolve_claim(claim)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if record["state"] != "resolving" or record["claim_nonce"] != claim.nonce:
                raise AdminSecretIngressError("credential.upload_expired")
            generation = cast(int, record["receipt_generation"])
            plan_id = cast(str | None, record["plan_id"])
            kind = cast(str, record["credential_kind"])
            account_ref = cast(str, record["account_ref"])
        try:
            lease = self._vault.lease(
                claim.session_id, expected_generation=generation, ttl_seconds=30
            )
            upload = bytearray(self._vault.consume_lease(lease))
            plan = self._plan_resolver(kind, account_ref, plan_id or claim.session_id)
        except (CredentialVaultError, Exception):
            raise AdminSecretIngressError("control.owner_unavailable") from None
        return SecretIngressResolutionV1(claim.session_id, plan, upload, claim)

    def commit_resolve(self, resolution: SecretIngressResolutionV1) -> None:
        claim = self._resolution_claim(resolution)
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._record(document, claim.session_id)
                if (
                    record["state"] != "resolving"
                    or record["claim_nonce"] != claim.nonce
                ):
                    raise AdminSecretIngressError("control.owner_unavailable")
                record["state"] = "resolved"
                record["claim_nonce"] = None
                self._write_locked(document)
            self._vault.revoke_account(
                claim.session_id,
                expected_generation=cast(int, record["receipt_generation"]),
            )
        except CredentialVaultError:
            raise AdminSecretIngressError("control.owner_unavailable") from None
        finally:
            _wipe(resolution.upload)

    def rollback_resolve(self, resolution: SecretIngressResolutionV1) -> None:
        claim = self._resolution_claim(resolution)
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._record(document, claim.session_id)
                if (
                    record["state"] == "resolving"
                    and record["claim_nonce"] == claim.nonce
                ):
                    record["state"] = "uploaded"
                    record["claim_nonce"] = None
                    self._write_locked(document)
        finally:
            _wipe(resolution.upload)

    def _mark_unknown(self, claim: SecretUploadClaimV1) -> None:
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if record["state"] == "uploading" and record["claim_nonce"] == claim.nonce:
                record["state"] = "upload_unknown"
                self._write_locked(document)

    def _read_locked(self) -> dict[str, object]:
        try:
            value = self._state.read_json_locked(
                _STATE_FILE, max_bytes=_MAX_STATE_BYTES
            )
        except HiveStateError as error:
            if error.args == ("state_not_found",):
                return {"schema_version": 1, "sessions": {}}
            raise AdminSecretIngressError("control.owner_unavailable") from None
        if (
            set(value) != {"schema_version", "sessions"}
            or value.get("schema_version") != 1
            or type(value.get("sessions")) is not dict
            or len(cast(dict[object, object], value["sessions"])) > _MAX_SESSIONS
        ):
            raise AdminSecretIngressError("control.owner_unavailable")
        return {
            "schema_version": 1,
            "sessions": dict(cast(dict[str, object], value["sessions"])),
        }

    def _write_locked(self, value: Mapping[str, object]) -> None:
        try:
            self._state.replace_json_locked(_STATE_FILE, value)
        except HiveStateError:
            raise AdminSecretIngressError("control.owner_unavailable") from None

    def _record(
        self, document: Mapping[str, object], session_id: str
    ) -> dict[str, object]:
        raw = cast(dict[str, object], document["sessions"]).get(session_id)
        if type(raw) is not dict:
            raise AdminSecretIngressError("credential.upload_expired")
        return raw

    def _live(self, record: Mapping[str, object]) -> None:
        expires = record.get("expires_at")
        if not isinstance(expires, (int, float)) or isinstance(expires, bool):
            raise AdminSecretIngressError("credential.upload_expired")
        if _now(self._clock) >= float(expires):
            raise AdminSecretIngressError("credential.upload_expired")

    def _upload_claim(self, value: object, session_id: str) -> SecretUploadClaimV1:
        if (
            type(value) is not SecretUploadClaimV1
            or value._issuer is not self._issuer
            or value.session_id != session_id
        ):
            raise AdminSecretIngressError("credential.upload_expired")
        return value

    def _resolve_claim(self, value: object) -> SecretResolveClaimV1:
        if type(value) is not SecretResolveClaimV1 or value._issuer is not self._issuer:
            raise AdminSecretIngressError("credential.upload_expired")
        return value

    def _resolution_claim(self, value: object) -> SecretResolveClaimV1:
        if type(value) is not SecretIngressResolutionV1:
            raise AdminSecretIngressError("credential.upload_expired")
        return self._resolve_claim(value.claim)


def _session_id(principal: str, account: str, kind: str, key: str) -> str:
    payload = "\0".join((principal, account, kind, key)).encode("ascii")
    return "ingress-" + hashlib.sha256(payload).hexdigest()[:48]


def _token(value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AdminSecretIngressError("control.request_invalid")
    return value


def _optional_token(value: object) -> str | None:
    return None if value is None else _token(value)


def _digest(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AdminSecretIngressError("control.request_invalid")
    return value


def _generation(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise AdminSecretIngressError("control.request_invalid")
    return value


def _now(clock: Callable[[], float]) -> float:
    value = clock()
    if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
        raise AdminSecretIngressError("control.owner_unavailable")
    return float(value)


def _secret_bytes(value: object) -> bytes:
    if type(value) is bytes and value:
        return value
    if type(value) is bytearray and value:
        return bytes(value)
    if (
        type(value) is memoryview
        and value.nbytes
        and value.ndim == 1
        and value.contiguous
    ):
        return value.tobytes()
    raise AdminSecretIngressError("control.request_invalid")


def _wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)
    value.clear()
