"""Durable, owner-authoritative secret-ingress sessions and capabilities."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import secrets
import time
from typing import Final, cast

from .admin_service import (
    SecretIngressOwnerError,
    SecretIngressCapabilityV1,
    SecretIngressResolutionV1,
    SecretIngressSessionV1,
    SecretIngressUploadReceiptV1,
)
from .credential_vault import CredentialVault, CredentialVaultError
from .hive.state import HiveStateError, HiveStateStore


_STATE_FILE: Final[PurePosixPath] = PurePosixPath("secret-ingress.json")
_MAX_STATE_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_SESSIONS: Final[int] = 4096
_CAPACITY_STATES: Final[frozenset[str]] = frozenset(
    {
        "authorized",
        "upload_reserved",
        "upload_in_progress",
        "upload_unknown",
        "uploaded",
        "resolve_reserved",
    }
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_CLAIM = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
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
    claim_id: str
    expected_generation: int = -1
    idempotency_key: str = ""
    replay: bool = False

    def __repr__(self) -> str:
        return "SecretUploadClaimV1(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SecretResolveClaimV1:
    session_id: str
    claim_id: str
    reconcile_only: bool = False
    terminal_replay: bool = False

    def __repr__(self) -> str:
        return "SecretResolveClaimV1(<redacted>)"


class AdminSecretIngressOwner:
    """Persist exact session state; store secret bytes only in encrypted vault."""

    def __init__(
        self,
        state_root: Path,
        *,
        vault: CredentialVault,
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = 120,
    ) -> None:
        if (
            not isinstance(vault, CredentialVault)
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
        self._clock = clock
        self._ttl = ttl_seconds

    def create_session(self, **values: object) -> SecretIngressSessionV1:
        principal = _token(values.get("principal"))
        account_ref = _token(values.get("account_ref"))
        kind = _token(values.get("credential_kind"))
        if kind not in _KINDS:
            raise AdminSecretIngressError("control.request_invalid")
        generation = _generation(values.get("expected_generation"))
        idempotency_key = _token(values.get("idempotency_key"))
        digest = _digest(values.get("plan_digest"))
        transaction_value = values.get("transaction_id")
        transaction_id = (
            _token(transaction_value) if transaction_value is not None else None
        )
        now = _now(self._clock)
        session_id = _session_id(principal, account_ref, kind, idempotency_key)
        fingerprint = _request_fingerprint(
            principal,
            account_ref,
            kind,
            digest,
            generation,
            idempotency_key,
            transaction_id,
        )
        record: dict[str, object] = {
            "session_id": session_id,
            "principal": principal,
            "account_ref": account_ref,
            "credential_kind": kind,
            "operation": _OPERATIONS[kind],
            "transaction_id": transaction_id,
            "plan_digest": digest,
            "expected_generation": generation,
            "create_idempotency_key": idempotency_key,
            "upload_idempotency_key": None,
            "apply_idempotency_key": None,
            "receipt_generation": None,
            "expires_at": now + self._ttl,
            "claim_id": None,
            "request_fingerprint": fingerprint,
            "state": "authorized",
        }
        with self._state.locked():
            document = self._read_locked()
            sessions = cast(dict[str, object], document["sessions"])
            pruned = self._prune_locked(sessions, now)
            existing = sessions.get(session_id)
            if existing is not None:
                if (
                    type(existing) is not dict
                    or existing.get("request_fingerprint") != fingerprint
                ):
                    raise AdminSecretIngressError("control.request_invalid")
                record = cast(dict[str, object], existing)
            else:
                active_sessions = sum(
                    _consumes_capacity(value, now) for value in sessions.values()
                )
                if active_sessions >= _MAX_SESSIONS:
                    raise AdminSecretIngressError("control.owner_unavailable")
                sessions[session_id] = record
                self._write_locked(document)
            if pruned and existing is not None:
                self._write_locked(document)
        return SecretIngressSessionV1(
            session_id,
            account_ref,
            cast(str, record["state"]),
            digest,
            generation,
            cast(float, record["expires_at"]),
            generation,
        )

    def _prune_locked(self, sessions: dict[str, object], now: float) -> bool:
        removed = False
        for session_id, value in tuple(sessions.items()):
            if type(value) is not dict:
                continue
            state = value.get("state")
            expires_at = value.get("expires_at")
            expired = (
                type(expires_at) in {int, float} and cast(float, expires_at) <= now
            )
            if state in {"authorized", "upload_reserved"} and expired:
                sessions.pop(session_id)
                removed = True
                continue
            if not expired or state not in {
                "upload_in_progress",
                "upload_unknown",
                "uploaded",
                "resolve_reserved",
                "resolve_in_progress",
                "apply_unknown",
            }:
                continue
            generation = value.get("receipt_generation")
            if state in {"upload_in_progress", "upload_unknown"}:
                expected_generation = value.get("expected_generation")
                if type(expected_generation) is not int:
                    continue
                generation = expected_generation + 1
            if type(generation) is not int:
                continue
            try:
                metadata = self._vault.projection_metadata(session_id)
                if state in {"resolve_in_progress", "apply_unknown"}:
                    continue
                if metadata == ("active", generation):
                    self._vault.revoke_account(
                        session_id, expected_generation=generation
                    )
                    metadata = ("revoked", generation)
                if metadata in {None, ("revoked", generation)}:
                    sessions.pop(session_id)
                    removed = True
            except CredentialVaultError:
                continue
        return removed

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
        claim_id = secrets.token_hex(32)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, session_id)
            self._live(record)
            if (
                record["state"] in {"upload_reserved", "upload_in_progress"}
                and record["principal"] == principal
                and record["expected_generation"] == expected_generation
                and record["upload_idempotency_key"] == idempotency_key
                and type(record["claim_id"]) is str
            ):
                return SecretUploadClaimV1(
                    session_id,
                    record["claim_id"],
                    expected_generation,
                    idempotency_key,
                )
            if (
                record["state"] == "uploaded"
                and record["principal"] == principal
                and record["expected_generation"] == expected_generation
                and record["upload_idempotency_key"] == idempotency_key
                and type(record["receipt_generation"]) is int
            ):
                generation = record["receipt_generation"]
                if self._projection_metadata_or_error(session_id) != (
                    "active",
                    generation,
                ):
                    raise AdminSecretIngressError("control.owner_unavailable")
                replay_id = hashlib.sha256(
                    (session_id + "\0" + idempotency_key).encode("ascii")
                ).hexdigest()
                return SecretUploadClaimV1(
                    session_id,
                    replay_id,
                    expected_generation,
                    idempotency_key,
                    True,
                )
            if (
                record["state"] != "authorized"
                or record["principal"] != principal
                or record["expected_generation"] != expected_generation
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            record["state"] = "upload_reserved"
            record["claim_id"] = claim_id
            record["upload_idempotency_key"] = idempotency_key
            self._write_locked(document)
        return SecretUploadClaimV1(
            session_id, claim_id, expected_generation, idempotency_key
        )

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
            if claim.replay:
                generation = cast(int, record.get("receipt_generation"))
                if (
                    record["state"] != "uploaded"
                    or record["principal"] != principal
                    or record["expected_generation"] != claim.expected_generation
                    or record["upload_idempotency_key"] != claim.idempotency_key
                    or self._projection_metadata_or_error(claim.session_id)
                    != ("active", generation)
                ):
                    raise AdminSecretIngressError("credential.upload_expired")
                return SecretIngressUploadReceiptV1(
                    claim.session_id,
                    cast(str, record["account_ref"]),
                    "consumed",
                    generation,
                )
            if (
                record["state"] not in {"upload_reserved", "upload_in_progress"}
                or record["claim_id"] != claim.claim_id
                or record["principal"] != principal
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            generation = cast(int, record["expected_generation"]) + 1
            if record["state"] == "upload_reserved":
                record["state"] = "upload_in_progress"
                self._write_locked(document)
        raw = _secret_view(secret)
        try:
            try:
                existing = self._vault.projection_metadata(claim.session_id)
                if existing != ("active", generation):
                    self._vault.store_projection(claim.session_id, generation, raw)
            except Exception:
                existing = self._projection_metadata_or_unknown(claim)
                if existing != ("active", generation):
                    if existing is None:
                        self._restore_upload_reservation(claim)
                    else:
                        self._mark_unknown(claim)
                    raise AdminSecretIngressError("control.owner_unavailable") from None
        finally:
            raw.release()
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
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._record(document, claim.session_id)
                if claim.replay and self._upload_receipt_matches(
                    record, claim, receipt
                ):
                    return
                if (
                    record["state"] != "upload_in_progress"
                    or record["claim_id"] != claim.claim_id
                    or receipt.generation
                    != cast(int, record["expected_generation"]) + 1
                ):
                    raise AdminSecretIngressError("control.owner_unavailable")
                record["state"] = "uploaded"
                record["receipt_generation"] = receipt.generation
                record["claim_id"] = None
                self._write_locked(document)
        except AdminSecretIngressError:
            if self._stored_upload_receipt_matches(claim, receipt):
                return
            raise

    def continue_resolve(self, **values: object) -> SecretIngressCapabilityV1:
        """Reconstruct one exact authenticated continuation from durable evidence."""

        principal = _token(values.get("principal"))
        operation = _token(values.get("operation"))
        account_ref = _token(values.get("account_ref"))
        transaction_id = _optional_token(values.get("transaction_id"))
        expected_generation = _generation(values.get("expected_generation"))
        idempotency_key = _token(values.get("idempotency_key"))
        digest_value = values.get("plan_digest")
        requested_digest = None if digest_value is None else _digest(digest_value)
        now = _now(self._clock)
        with self._state.locked():
            document = self._read_locked()
            sessions = cast(dict[str, object], document["sessions"])
            candidates: list[dict[str, object]] = []
            for value in sessions.values():
                if type(value) is not dict:
                    continue
                state = value.get("state")
                stored_digest = value.get("plan_digest")
                if (
                    state
                    not in {
                        "uploaded",
                        "resolve_reserved",
                        "resolve_in_progress",
                        "apply_unknown",
                        "resolved",
                    }
                    or value.get("principal") != principal
                    or value.get("operation") != operation
                    or value.get("account_ref") != account_ref
                    or value.get("transaction_id") != transaction_id
                    or value.get("expected_generation") != expected_generation
                    or (
                        operation != "google.oauth.complete"
                        and stored_digest != requested_digest
                    )
                    or (
                        value.get("apply_idempotency_key") is not None
                        and value.get("apply_idempotency_key") != idempotency_key
                    )
                ):
                    continue
                expires_at = cast(float, value.get("expires_at"))
                if state == "uploaded" and expires_at <= now:
                    continue
                candidates.append(value)
            if len(candidates) != 1:
                raise AdminSecretIngressError("credential.upload_expired")
            record = candidates[0]
            generation = cast(int, record.get("receipt_generation"))
            metadata = self._projection_metadata_or_error(
                cast(str, record["session_id"])
            )
            state = cast(str, record["state"])
            reconcile_only = state in {
                "resolve_in_progress",
                "apply_unknown",
                "resolved",
            } or metadata == ("revoked", generation)
            if state != "resolved" and metadata not in {
                ("active", generation),
                ("revoked", generation),
            }:
                raise AdminSecretIngressError("control.owner_unavailable")
            return SecretIngressCapabilityV1(
                cast(str, record["session_id"]),
                principal,
                account_ref,
                operation,
                cast(str, record["credential_kind"]),
                transaction_id,
                cast(str, record["plan_digest"]),
                expected_generation,
                cast(str, record["create_idempotency_key"]),
                cast(str, record["upload_idempotency_key"]),
                idempotency_key,
                expected_generation,
                generation,
                cast(float, record["expires_at"]),
                reconcile_only,
            )

    def rollback_upload(self, claim: SecretUploadClaimV1) -> None:
        claim = self._upload_claim(claim, claim.session_id)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] == "upload_reserved"
                and record["claim_id"] == claim.claim_id
            ):
                record["state"] = "authorized"
                record["claim_id"] = None
                record["upload_idempotency_key"] = None
                self._write_locked(document)

    def reserve_resolve(
        self, session_id: str, **values: object
    ) -> SecretResolveClaimV1:
        session_id = _token(session_id)
        capability = values.get("capability")
        if type(capability) is SecretIngressCapabilityV1:
            values = {
                "principal": capability.subject,
                "operation": capability.operation,
                "account_ref": capability.account_ref,
                "credential_kind": capability.credential_kind,
                "transaction_id": capability.transaction_id,
                "plan_digest": capability.plan_digest,
                "expected_generation": capability.expected_generation,
                "create_idempotency_key": capability.create_idempotency_key,
                "upload_idempotency_key": capability.upload_idempotency_key,
                "idempotency_key": capability.apply_idempotency_key,
                "receipt_generation": capability.receipt_generation,
            }
        expected = {
            "principal": _token(values.get("principal")),
            "operation": _token(values.get("operation")),
            "account_ref": _token(values.get("account_ref")),
            "credential_kind": _token(values.get("credential_kind")),
            "transaction_id": _optional_token(values.get("transaction_id")),
            "plan_digest": _digest(values.get("plan_digest")),
            "expected_generation": _generation(values.get("expected_generation")),
            "create_idempotency_key": _token(values.get("create_idempotency_key")),
            "upload_idempotency_key": _token(values.get("upload_idempotency_key")),
            "receipt_generation": _generation(values.get("receipt_generation")),
        }
        idempotency_key = _token(values.get("idempotency_key"))
        claim_id = secrets.token_hex(32)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, session_id)
            reconciliation = (
                type(capability) is SecretIngressCapabilityV1
                and capability.reconcile_only
            )
            if record["state"] in {"resolve_in_progress", "apply_unknown"} and not (
                reconciliation
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            if record["state"] in {"uploaded", "resolve_reserved"}:
                self._live(record)
            if (
                record["state"]
                in {"resolve_reserved", "resolve_in_progress", "apply_unknown"}
                and record["apply_idempotency_key"] == idempotency_key
                and all(record[key] == value for key, value in expected.items())
                and type(record["claim_id"]) is str
            ):
                return SecretResolveClaimV1(
                    session_id,
                    record["claim_id"],
                    bool(
                        type(capability) is SecretIngressCapabilityV1
                        and capability.reconcile_only
                    ),
                )
            if (
                record["state"] == "resolved"
                and type(capability) is SecretIngressCapabilityV1
                and capability.reconcile_only
                and record["apply_idempotency_key"] == idempotency_key
                and all(record[key] == value for key, value in expected.items())
            ):
                return SecretResolveClaimV1(session_id, "0" * 64, True, True)
            if record["state"] != "uploaded" or any(
                record[key] != value for key, value in expected.items()
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            record["state"] = "resolve_reserved"
            record["claim_id"] = claim_id
            record["apply_idempotency_key"] = idempotency_key
            self._write_locked(document)
        return SecretResolveClaimV1(
            session_id,
            claim_id,
            bool(
                type(capability) is SecretIngressCapabilityV1
                and capability.reconcile_only
            ),
        )

    def resolve(self, claim: object) -> SecretIngressResolutionV1:
        claim = self._resolve_claim(claim)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if claim.terminal_replay:
                if record["state"] != "resolved":
                    raise AdminSecretIngressError("credential.upload_expired")
                return SecretIngressResolutionV1(
                    claim.session_id, bytearray(), claim, True
                )
            if (
                record["state"]
                not in {"resolve_reserved", "resolve_in_progress", "apply_unknown"}
                or record["claim_id"] != claim.claim_id
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            initial_state = record["state"]
            if not claim.reconcile_only and initial_state != "resolve_reserved":
                raise AdminSecretIngressError("credential.upload_expired")
            if initial_state in {"resolve_reserved", "apply_unknown"}:
                record["state"] = "resolve_in_progress"
                self._write_locked(document)
            generation = cast(int, record["receipt_generation"])
        if claim.reconcile_only:
            if self._projection_metadata_or_error(claim.session_id) not in {
                ("active", generation),
                ("revoked", generation),
            }:
                raise AdminSecretIngressError("control.owner_unavailable")
            return SecretIngressResolutionV1(claim.session_id, bytearray(), claim, True)
        try:
            lease = self._vault.lease(
                claim.session_id, expected_generation=generation, ttl_seconds=30
            )
            upload = bytearray(self._vault.consume_lease(lease))
        except CredentialVaultError:
            raise AdminSecretIngressError("control.owner_unavailable") from None
        return SecretIngressResolutionV1(claim.session_id, upload, claim, False)

    def read_oauth_client(
        self,
        session: object,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
    ) -> bytearray:
        if type(session) is not SecretIngressResolutionV1:
            raise AdminSecretIngressError("credential.upload_expired")
        claim = self._resolution_claim(session)
        self._assert_resolve_binding(
            claim,
            account_ref=account_ref,
            expected_generation=expected_generation,
            plan_digest=plan_digest,
        )
        return session.upload

    def acknowledge_oauth_client(
        self,
        session: object,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
        ack_operation_id: str,
    ) -> None:
        if (
            ack_operation_id != plan_digest
            or type(session) is not SecretIngressResolutionV1
        ):
            raise AdminSecretIngressError("credential.upload_expired")
        claim = self._resolution_claim(session)
        self._assert_resolve_binding(
            claim,
            account_ref=account_ref,
            expected_generation=expected_generation,
            plan_digest=plan_digest,
        )
        self.commit_resolve(session)

    def _assert_resolve_binding(
        self,
        claim: SecretResolveClaimV1,
        *,
        account_ref: str,
        expected_generation: int,
        plan_digest: str,
    ) -> None:
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] != "resolve_in_progress"
                or record["claim_id"] != claim.claim_id
                or record["account_ref"] != account_ref
                or record["expected_generation"] != expected_generation
                or record["plan_digest"] != plan_digest
            ):
                raise AdminSecretIngressError("credential.upload_expired")

    def commit_resolve(self, resolution: SecretIngressResolutionV1) -> None:
        claim = self._resolution_claim(resolution)
        try:
            if claim.terminal_replay:
                return
            with self._state.locked():
                document = self._read_locked()
                record = self._record(document, claim.session_id)
                if (
                    record["state"] != "resolve_in_progress"
                    or record["claim_id"] != claim.claim_id
                ):
                    raise AdminSecretIngressError("control.owner_unavailable")
                generation = cast(int, record["receipt_generation"])
            try:
                metadata = self._vault.projection_metadata(claim.session_id)
                if metadata == ("active", generation):
                    self._vault.revoke_account(
                        claim.session_id, expected_generation=generation
                    )
                elif metadata != ("revoked", generation):
                    raise CredentialVaultError("credential.generation_conflict")
            except CredentialVaultError:
                self._mark_resolve_unknown(claim)
                raise AdminSecretIngressError("control.owner_unavailable") from None
            self.reconcile_resolve(claim)
        finally:
            _wipe(resolution.upload)

    def reconcile_resolve(self, claim: object) -> None:
        claim = self._resolve_claim(claim)
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] not in {"resolve_in_progress", "apply_unknown"}
                or record["claim_id"] != claim.claim_id
            ):
                raise AdminSecretIngressError("credential.upload_expired")
            generation = cast(int, record["receipt_generation"])
            try:
                metadata = self._vault.projection_metadata(claim.session_id)
            except CredentialVaultError:
                raise AdminSecretIngressError("control.owner_unavailable") from None
            if metadata != ("revoked", generation):
                raise AdminSecretIngressError("control.owner_unavailable")
            record["state"] = "resolved"
            record["claim_id"] = None
            try:
                self._write_locked(document)
            except AdminSecretIngressError:
                stored = self._read_locked()
                stored_record = cast(dict[str, object], stored["sessions"]).get(
                    claim.session_id
                )
                if (
                    type(stored_record) is dict
                    and stored_record.get("state") == "resolved"
                ):
                    return
                raise

    def _mark_resolve_unknown(self, claim: SecretResolveClaimV1) -> None:
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] == "resolve_in_progress"
                and record["claim_id"] == claim.claim_id
            ):
                record["state"] = "apply_unknown"
                self._write_locked(document)

    def rollback_resolve(self, resolution: SecretIngressResolutionV1) -> None:
        claim = self._resolution_claim(resolution)
        try:
            with self._state.locked():
                document = self._read_locked()
                record = self._record(document, claim.session_id)
                if (
                    record["state"] in {"resolve_reserved", "resolve_in_progress"}
                    and record["claim_id"] == claim.claim_id
                ):
                    record["state"] = "uploaded"
                    record["claim_id"] = None
                    self._write_locked(document)
        finally:
            _wipe(resolution.upload)

    def mark_resolve_unknown(self, resolution: SecretIngressResolutionV1) -> None:
        claim = self._resolution_claim(resolution)
        try:
            self._mark_resolve_unknown(claim)
        finally:
            _wipe(resolution.upload)

    def _mark_unknown(self, claim: SecretUploadClaimV1) -> None:
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] == "upload_in_progress"
                and record["claim_id"] == claim.claim_id
            ):
                record["state"] = "upload_unknown"
                self._write_locked(document)

    def _restore_upload_reservation(self, claim: SecretUploadClaimV1) -> None:
        with self._state.locked():
            document = self._read_locked()
            record = self._record(document, claim.session_id)
            if (
                record["state"] == "upload_in_progress"
                and record["claim_id"] == claim.claim_id
            ):
                record["state"] = "upload_reserved"
                self._write_locked(document)

    def _projection_metadata_or_unknown(
        self, claim: SecretUploadClaimV1
    ) -> tuple[str, int] | None:
        try:
            return cast(
                tuple[str, int] | None,
                self._vault.projection_metadata(claim.session_id),
            )
        except CredentialVaultError:
            self._mark_unknown(claim)
            raise AdminSecretIngressError("control.owner_unavailable") from None

    def _projection_metadata_or_error(self, session_id: str) -> tuple[str, int] | None:
        try:
            return cast(
                tuple[str, int] | None,
                self._vault.projection_metadata(session_id),
            )
        except CredentialVaultError:
            raise AdminSecretIngressError("control.owner_unavailable") from None

    @staticmethod
    def _upload_receipt_matches(
        record: Mapping[str, object],
        claim: SecretUploadClaimV1,
        receipt: SecretIngressUploadReceiptV1,
    ) -> bool:
        return (
            record.get("state") == "uploaded"
            and record.get("session_id") == claim.session_id
            and record.get("expected_generation") == claim.expected_generation
            and record.get("upload_idempotency_key") == claim.idempotency_key
            and record.get("receipt_generation") == receipt.generation
            and record.get("account_ref") == receipt.account_ref
        )

    def _stored_upload_receipt_matches(
        self, claim: SecretUploadClaimV1, receipt: SecretIngressUploadReceiptV1
    ) -> bool:
        try:
            with self._state.locked():
                record = self._record(self._read_locked(), claim.session_id)
                return self._upload_receipt_matches(record, claim, receipt) and (
                    self._projection_metadata_or_error(claim.session_id)
                    == ("active", receipt.generation)
                )
        except AdminSecretIngressError:
            return False

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
        ):
            raise AdminSecretIngressError("control.owner_unavailable")
        return {
            "schema_version": 1,
            "sessions": dict(cast(dict[str, object], value["sessions"])),
        }

    def _write_locked(self, value: Mapping[str, object]) -> None:
        try:
            encoded = (
                json.dumps(
                    value,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            if len(encoded) > _MAX_STATE_BYTES:
                raise HiveStateError("state_oversize")
            self._state.replace_json_locked(_STATE_FILE, value, encoded=encoded)
        except (HiveStateError, TypeError, ValueError, RecursionError):
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
            or value.session_id != session_id
            or _CLAIM.fullmatch(value.claim_id) is None
            or type(value.expected_generation) is not int
            or not 0 <= value.expected_generation <= 2**63 - 1
            or _TOKEN.fullmatch(value.idempotency_key) is None
            or type(value.replay) is not bool
        ):
            raise AdminSecretIngressError("credential.upload_expired")
        return value

    def _resolve_claim(self, value: object) -> SecretResolveClaimV1:
        if (
            type(value) is not SecretResolveClaimV1
            or _CLAIM.fullmatch(value.claim_id) is None
            or type(value.reconcile_only) is not bool
            or type(value.terminal_replay) is not bool
        ):
            raise AdminSecretIngressError("credential.upload_expired")
        return value

    def _resolution_claim(self, value: object) -> SecretResolveClaimV1:
        if type(value) is not SecretIngressResolutionV1:
            raise AdminSecretIngressError("credential.upload_expired")
        return self._resolve_claim(value.claim)


def _session_id(principal: str, account: str, kind: str, key: str) -> str:
    payload = "\0".join((principal, account, kind, key)).encode("ascii")
    return "ingress-" + hashlib.sha256(payload).hexdigest()[:48]


def _request_fingerprint(
    principal: str,
    account: str,
    kind: str,
    digest: str,
    generation: int,
    key: str,
    transaction_id: str | None,
) -> str:
    payload = "\0".join(
        (
            principal,
            account,
            kind,
            digest,
            str(generation),
            key,
            transaction_id or "",
        )
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


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


def _consumes_capacity(value: object, now: float) -> bool:
    if type(value) is not dict:
        return False
    state = value.get("state")
    if state in _CAPACITY_STATES:
        return True
    expires_at = value.get("expires_at")
    return (
        state in {"resolve_in_progress", "apply_unknown"}
        and type(expires_at) in {int, float}
        and cast(float, expires_at) > now
    )


def _secret_view(value: object) -> memoryview:
    if type(value) in {bytes, bytearray} and value:
        return memoryview(cast(bytes | bytearray, value))
    if (
        type(value) is memoryview
        and value.nbytes
        and value.ndim == 1
        and value.contiguous
    ):
        return memoryview(value)
    raise AdminSecretIngressError("control.request_invalid")


def _wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)
    value.clear()
