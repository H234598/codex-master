"""Fail-closed production assembly for the Masterjet administration daemon."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Final, cast
import urllib.parse
import urllib.request

from .admin_auth import AdminAuthError, MasterjetBearerVerifier, TotpStepUpVerifier
from .admin_contracts import AdminPrincipalV1
from .admin_daemon import (
    AdminDaemon,
    CloudflareJwksFetcher,
    RefreshingCloudflareAccessVerifier,
)
from .admin_hosts import HostRegistry
from .admin_http import AdminHttpServer
from .admin_operations import AdminOperationStore
from .admin_secret_ingress import AdminSecretIngressOwner
from .admin_service import MasterjetControlService, OpenAIAccountSummaryV1
from .admin_socket import AdminSocketServer, UnixPeerCredentials
from .credential_vault import CredentialVault, CredentialVaultError
from .google_account_inventory import GoogleAccountInventoryError
from .google_account_inventory_manager import GoogleAccountInventoryManager
from .google_billing_service import (
    GoogleBillingBindResultV1,
    GoogleBillingBindingObservationV1,
    GoogleBillingService,
)
from .google_cloud_api import GoogleCloudApi, GoogleCloudApiError
from .google_cloud_provisioner import (
    FillToQuotaPlan,
    GoogleCloudProvisionerError,
    GoogleQuotaEvidenceV1,
    PlannedHiveProject,
    ProvisionPartialReceipt,
    ProvisionReceipt,
    build_fill_to_quota_plan,
    execute_fill_to_quota_plan,
)
from .google_inventory_store import GoogleInventoryStore
from .google_oauth_authorization import GoogleOAuthProfileIdV1
from .google_oauth_session import (
    GoogleOAuthCodeExchangeV1,
    GoogleOAuthControlService,
    GoogleOAuthSessionError,
    GoogleOAuthTokenWriteReceiptV1,
)
from .hive.state import HiveStateError, HiveStateStore
from .openai_credential_service import (
    OpenAIAccountIdentity,
    OpenAIAuthReceiptStore,
    OpenAICredentialService,
    OpenAIIdentitySource,
)


_CONFIG_MAX_BYTES: Final[int] = 64 * 1024
_QUOTA_MAX_BYTES: Final[int] = 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_HOST = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_TEAM_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"cloudflareaccess\.com\Z",
    re.ASCII,
)
_ACCOUNT_DOCUMENT = PurePosixPath("account-registry.json")
_TOKEN_RECEIPTS = PurePosixPath("google-token-receipts.json")
_PROVISIONER_DOCUMENT = PurePosixPath("google-provisioner-plans.json")
_INVENTORY_DOCUMENT = PurePosixPath("api-token.yaml")
_ACCOUNT_FIELDS = frozenset(
    {
        "schema_version",
        "http_host",
        "http_port",
        "origin_host",
        "authority_mode",
        "local_subject",
        "local_scopes",
        "remote_subject",
        "remote_scopes",
        "trusted_proxy_addresses",
    }
)
_CLOUDFLARE_FIELDS = frozenset({"cloudflare_team_domain", "cloudflare_audience"})


class AdminAssemblyError(RuntimeError):
    """Stable configuration/owner assembly failure without private detail."""

    def __init__(self) -> None:
        super().__init__("control.admin_configuration_invalid")


@dataclass(frozen=True, slots=True)
class AdminConfig:
    http_host: str
    http_port: int
    origin_host: str
    authority_mode: str
    local_subject: str
    local_scopes: tuple[str, ...]
    remote_subject: str
    remote_scopes: tuple[str, ...]
    trusted_proxy_addresses: tuple[str, ...]
    cloudflare_team_domain: str | None
    cloudflare_audience: str | None


class SystemdCredentialSet:
    """Own exact no-follow descriptors supplied through LoadCredential."""

    _NAMES = (
        "admin-config",
        "admin-bearer",
        "admin-totp",
        "admin-attestation",
        "admin-vault-key",
        "admin-quota-evidence",
    )

    def __init__(self, directory: Path) -> None:
        if not directory.is_absolute():
            raise AdminAssemblyError
        self._directory_fd: int | None = None
        self._fds: dict[str, int] = {}
        try:
            before = os.lstat(directory)
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid not in {0, os.geteuid()}
                or bool(stat.S_IMODE(before.st_mode) & 0o077)
            ):
                raise AdminAssemblyError
            directory_fd = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            opened = os.fstat(directory_fd)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(directory_fd)
                raise AdminAssemblyError
            self._directory_fd = directory_fd
            for name in self._NAMES:
                self._fds[name] = self._open(name)
        except BaseException:
            self.close()
            raise AdminAssemblyError from None

    def _open(self, name: str) -> int:
        directory_fd = self._directory_fd
        if directory_fd is None:
            raise AdminAssemblyError
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or before.st_nlink != 1
            or not 0 < before.st_size <= _QUOTA_MAX_BYTES
        ):
            raise AdminAssemblyError
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            os.close(descriptor)
            raise AdminAssemblyError
        os.set_inheritable(descriptor, False)
        return descriptor

    def fd(self, name: str) -> int:
        try:
            return self._fds[name]
        except KeyError:
            raise AdminAssemblyError from None

    def read(self, name: str, maximum: int) -> bytes:
        descriptor = self.fd(name)
        try:
            metadata = os.fstat(descriptor)
            if not 0 < metadata.st_size <= maximum:
                raise AdminAssemblyError
            value = os.pread(descriptor, metadata.st_size + 1, 0)
            current = os.fstat(descriptor)
            if len(value) != metadata.st_size or (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
            ) != (current.st_dev, current.st_ino, current.st_size):
                raise AdminAssemblyError
            return value
        except OSError:
            raise AdminAssemblyError from None

    def close(self) -> None:
        for descriptor in self._fds.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._fds.clear()
        if self._directory_fd is not None:
            try:
                os.close(self._directory_fd)
            except OSError:
                pass
            self._directory_fd = None


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _parse_json(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if type(value) is not dict:
            raise ValueError
        return cast(dict[str, object], value)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise AdminAssemblyError from None


def _configured_token(value: object) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AdminAssemblyError
    return value


def _configured_scopes(value: object) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= 64:
        raise AdminAssemblyError
    scopes = tuple(_configured_token(item) for item in value)
    if len(set(scopes)) != len(scopes):
        raise AdminAssemblyError
    return scopes


def parse_admin_config(raw: bytes) -> AdminConfig:
    value = _parse_json(raw)
    mode = value.get("authority_mode")
    expected = _ACCOUNT_FIELDS | (
        _CLOUDFLARE_FIELDS if mode in {"cloudflare", "require_both"} else frozenset()
    )
    if (
        set(value) != expected
        or value.get("schema_version") != 1
        or mode not in {"bearer", "cloudflare", "require_both"}
        or type(value.get("http_host")) is not str
        or value["http_host"] not in {"127.0.0.1", "::1"}
        or type(value.get("http_port")) is not int
        or not 1 <= cast(int, value["http_port"]) <= 65535
        or type(value.get("origin_host")) is not str
        or _HOST.fullmatch(cast(str, value["origin_host"])) is None
        or type(value.get("trusted_proxy_addresses")) is not list
        or not 1 <= len(cast(list[object], value["trusted_proxy_addresses"])) <= 16
    ):
        raise AdminAssemblyError
    trusted = tuple(
        cast(str, item) for item in cast(list[object], value["trusted_proxy_addresses"])
    )
    try:
        if any(
            type(item) is not str or not ipaddress.ip_address(item).is_loopback
            for item in trusted
        ):
            raise ValueError
    except ValueError:
        raise AdminAssemblyError from None
    team = cast(str | None, value.get("cloudflare_team_domain"))
    audience = cast(str | None, value.get("cloudflare_audience"))
    if mode in {"cloudflare", "require_both"} and (
        type(team) is not str
        or _TEAM_DOMAIN.fullmatch(team) is None
        or type(audience) is not str
        or not audience
        or len(audience.encode("utf-8")) > 1024
    ):
        raise AdminAssemblyError
    return AdminConfig(
        cast(str, value["http_host"]),
        cast(int, value["http_port"]),
        cast(str, value["origin_host"]),
        cast(str, mode),
        _configured_token(value.get("local_subject")),
        _configured_scopes(value.get("local_scopes")),
        _configured_token(value.get("remote_subject")),
        _configured_scopes(value.get("remote_scopes")),
        trusted,
        team,
        audience,
    )


def _empty_inventory(path: Path) -> None:
    store = HiveStateStore(path.parent)
    try:
        store.read_private_bytes(_INVENTORY_DOCUMENT, max_bytes=1024)
    except HiveStateError as error:
        if error.args != ("state_not_found",):
            raise
        store.replace_private_bytes(
            _INVENTORY_DOCUMENT,
            b"schema_version: 2\ngoogle_accounts: []\n",
        )


class DurableAccountRegistry:
    """CAS account registry, projected into the existing provider owners."""

    def __init__(
        self,
        state_root: Path,
        *,
        identities: OpenAIIdentitySource,
        google_store: GoogleInventoryStore,
        google_manager: GoogleAccountInventoryManager,
    ) -> None:
        self._state = HiveStateStore(state_root)
        self._identities = identities
        self._google_store = google_store
        self._google_manager = google_manager
        with self._state.locked():
            try:
                document = self._read_locked()
            except HiveStateError as error:
                if error.args != ("state_not_found",):
                    raise
                document = self._empty()
                self._state.replace_json_locked(_ACCOUNT_DOCUMENT, document)
        self._reconcile(document)

    @staticmethod
    def _empty() -> dict[str, object]:
        return {
            "schema_version": 1,
            "generations": {"openai": 1, "google": 1},
            "accounts": [],
            "receipts": [],
        }

    def _read_locked(self) -> dict[str, object]:
        value = dict(
            self._state.read_json_locked(_ACCOUNT_DOCUMENT, max_bytes=1024 * 1024)
        )
        if (
            set(value) != {"schema_version", "generations", "accounts", "receipts"}
            or value.get("schema_version") != 1
            or type(value.get("generations")) is not dict
            or cast(dict[str, object], value["generations"]).keys()
            != {"openai", "google"}
            or type(value.get("accounts")) is not list
            or type(value.get("receipts")) is not list
        ):
            raise HiveStateError("invalid_account_registry")
        return value

    def _reconcile(self, document: Mapping[str, object]) -> None:
        google_changed = False
        for raw in cast(list[object], document["accounts"]):
            if type(raw) is not dict:
                raise HiveStateError("invalid_account_registry")
            record = cast(dict[str, object], raw)
            if record.get("provider") == "openai":
                self._identities.set_identity(
                    cast(str, record["ref"]),
                    OpenAIAccountIdentity(
                        bool(record["enabled"]),
                        cast(str, record["ref"]),
                        cast(int, record["identity_generation"]),
                    ),
                )
            elif record.get("provider") == "google":
                google_changed = self._ensure_google(record) or google_changed
            else:
                raise HiveStateError("invalid_account_registry")
        if google_changed:
            self._google_manager.reload(
                expected_generation=self._google_manager.inventory_generation()
            )

    def _ensure_google(self, record: Mapping[str, object]) -> bool:
        _, current = self._google_store._read()
        accounts = cast(list[object], current.get("google_accounts"))
        if any(
            type(item) is dict and item.get("ref") == record["ref"] for item in accounts
        ):
            return False

        def add(document: dict[str, object]) -> None:
            target = cast(list[object], document["google_accounts"])
            target.append(
                {
                    "ref": record["ref"],
                    "login_email": record["ref"],
                    "recovery_email": None,
                    "label": record["label"],
                    "subject_id": None,
                    "billing_accounts": [],
                    "projects": [],
                    "auth": None,
                }
            )

        self._google_store.atomic_update(add)
        return True

    def current_generation(self, provider: str) -> int:
        provider = self._provider(provider)
        with self._state.locked():
            document = self._read_locked()
            return cast(int, cast(dict[str, object], document["generations"])[provider])

    def list_accounts(self) -> tuple[OpenAIAccountSummaryV1, ...]:
        with self._state.locked():
            document = self._read_locked()
            records = cast(list[object], document["accounts"])
            return tuple(
                OpenAIAccountSummaryV1(
                    cast(str, cast(dict[str, object], item)["ref"]),
                    cast(int, cast(dict[str, object], item)["identity_generation"]),
                )
                for item in records
                if type(item) is dict
                and item.get("provider") == "openai"
                and item.get("enabled") is True
            )

    def add_account(
        self,
        provider: str,
        account_ref: str,
        label: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        return self._mutate(
            "add",
            provider,
            account_ref,
            label,
            expected_generation,
            idempotency_key,
        )

    def disable_account(
        self,
        provider: str,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        return self._mutate(
            "disable",
            provider,
            account_ref,
            None,
            expected_generation,
            idempotency_key,
        )

    def _mutate(
        self,
        action: str,
        provider: str,
        account_ref: str,
        label: str | None,
        expected_generation: int,
        idempotency_key: str,
    ) -> Mapping[str, object]:
        provider = self._provider(provider)
        account_ref = _configured_token(account_ref)
        idempotency_key = _configured_token(idempotency_key)
        if action == "add" and (
            type(label) is not str or not label or len(label) > 256
        ):
            raise ValueError("control.request_invalid")
        fingerprint = sha256(
            json.dumps(
                [action, provider, account_ref, label, expected_generation],
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        with self._state.locked():
            document = self._read_locked()
            receipts = cast(list[object], document["receipts"])
            for raw in receipts:
                receipt = cast(dict[str, object], raw)
                if (
                    receipt["provider"] == provider
                    and receipt["key"] == idempotency_key
                ):
                    if receipt["fingerprint"] != fingerprint:
                        raise ValueError("control.idempotency_conflict")
                    return cast(dict[str, object], receipt["result"])
            generations = cast(dict[str, object], document["generations"])
            if generations[provider] != expected_generation:
                raise ValueError("credential.generation_conflict")
            accounts = cast(list[object], document["accounts"])
            existing = next(
                (
                    cast(dict[str, object], item)
                    for item in accounts
                    if type(item) is dict
                    and item.get("provider") == provider
                    and item.get("ref") == account_ref
                ),
                None,
            )
            if action == "add":
                if existing is not None:
                    raise ValueError("control.account_conflict")
                existing = {
                    "provider": provider,
                    "ref": account_ref,
                    "label": label,
                    "enabled": True,
                    "identity_generation": 1,
                }
                accounts.append(existing)
            else:
                if existing is None or existing.get("enabled") is not True:
                    raise ValueError("control.account_not_found")
                existing["enabled"] = False
                existing["identity_generation"] = (
                    cast(int, existing["identity_generation"]) + 1
                )
            generations[provider] = expected_generation + 1
            result = {
                "account": {
                    "ref": account_ref,
                    "generation": existing["identity_generation"],
                }
            }
            receipts.append(
                {
                    "provider": provider,
                    "key": idempotency_key,
                    "fingerprint": fingerprint,
                    "result": result,
                }
            )
            if len(receipts) > 4096:
                del receipts[: len(receipts) - 4096]
            self._state.replace_json_locked(_ACCOUNT_DOCUMENT, document)
        self._reconcile(document)
        return result

    @staticmethod
    def _provider(value: str) -> str:
        if value not in {"openai", "google"}:
            raise ValueError("control.request_invalid")
        return value


class CredentialQuotaCollector:
    def __init__(self, raw: bytes | Callable[[], bytes]) -> None:
        if type(raw) is bytes:
            self._source = lambda: raw
        elif callable(raw):
            self._source = raw
        else:
            raise AdminAssemblyError
        self._evidence()

    def _evidence(self) -> dict[str, GoogleQuotaEvidenceV1]:
        raw = self._source()
        if type(raw) is not bytes:
            raise AdminAssemblyError
        value = _parse_json(raw)
        if (
            set(value) != {"schema_version", "accounts"}
            or value.get("schema_version") != 1
            or type(value.get("accounts")) is not list
            or len(cast(list[object], value["accounts"])) > 4096
        ):
            raise AdminAssemblyError
        evidence: dict[str, GoogleQuotaEvidenceV1] = {}
        for item in cast(list[object], value["accounts"]):
            if type(item) is not dict or set(item) != {
                "account_ref",
                "remaining",
                "observed_at",
                "source",
                "inventory_generation",
                "inventory_fingerprint",
            }:
                raise AdminAssemblyError
            record = cast(dict[str, object], item)
            account_ref = _configured_token(record["account_ref"])
            if account_ref in evidence:
                raise AdminAssemblyError
            try:
                evidence[account_ref] = GoogleQuotaEvidenceV1(
                    cast(int, record["remaining"]),
                    cast(str, record["observed_at"]),
                    cast(str, record["source"]),
                    account_ref,
                    cast(int, record["inventory_generation"]),
                    cast(str, record["inventory_fingerprint"]),
                )
            except (TypeError, ValueError):
                raise AdminAssemblyError from None
        return evidence

    def collect(self, account_ref: str, *, expected_generation: int) -> object:
        evidence = self._evidence().get(account_ref)
        if evidence is None or evidence.inventory_generation != expected_generation:
            raise GoogleCloudProvisionerError("quota.evidence_invalid")
        return evidence


class DurableGoogleTokenWriter:
    """Bind OAuth refresh tokens to account/scope in an encrypted vault."""

    def __init__(
        self,
        state_root: Path,
        *,
        vault: CredentialVault,
        store: GoogleInventoryStore,
        manager: GoogleAccountInventoryManager,
    ) -> None:
        self._state = HiveStateStore(state_root)
        self._vault = vault
        self._store = store
        self._manager = manager
        with self._state.locked():
            try:
                self._read_locked()
            except HiveStateError as error:
                if error.args != ("state_not_found",):
                    raise
                self._state.replace_json_locked(
                    _TOKEN_RECEIPTS, {"schema_version": 1, "receipts": []}
                )

    def _read_locked(self) -> dict[str, object]:
        value = dict(
            self._state.read_json_locked(_TOKEN_RECEIPTS, max_bytes=1024 * 1024)
        )
        if (
            set(value) != {"schema_version", "receipts"}
            or value.get("schema_version") != 1
            or type(value.get("receipts")) is not list
        ):
            raise HiveStateError("invalid_google_token_receipts")
        return value

    @staticmethod
    def _receipt(value: Mapping[str, object]) -> GoogleOAuthTokenWriteReceiptV1:
        try:
            return GoogleOAuthTokenWriteReceiptV1(
                cast(str, value["operation_id"]),
                cast(str, value["account_ref"]),
                cast(str, value["subject_id"]),
                cast(str, value["oauth_client_fingerprint"]),
                GoogleOAuthProfileIdV1(cast(str, value["scope_profile"])),
                cast(str, value["scope_fingerprint"]),
            )
        except (KeyError, TypeError, ValueError):
            raise HiveStateError("invalid_google_token_receipts") from None

    def lookup_refresh_token_receipt(
        self,
        operation_id: str,
        *,
        account_ref: str,
        scope_profile: GoogleOAuthProfileIdV1,
        scope_fingerprint: str,
    ) -> GoogleOAuthTokenWriteReceiptV1 | None:
        with self._state.locked():
            document = self._read_locked()
            for raw in cast(list[object], document["receipts"]):
                if type(raw) is not dict:
                    raise HiveStateError("invalid_google_token_receipts")
                receipt = self._receipt(cast(dict[str, object], raw))
                if receipt.operation_id != operation_id:
                    continue
                if (
                    receipt.account_ref != account_ref
                    or receipt.scope_profile is not scope_profile
                    or receipt.scope_fingerprint != scope_fingerprint
                ):
                    raise GoogleOAuthSessionError("oauth.operation_conflict")
                return receipt
        return None

    def load_refresh_token(
        self,
        account_ref: str,
        *,
        subject_id: str,
        oauth_client_fingerprint: str,
    ) -> bytearray:
        try:
            account = self._manager._snapshot_for_internal_use().by_account_ref[
                account_ref
            ]
            if account.subject_id != subject_id:
                raise GoogleOAuthSessionError("oauth.subject_mismatch")
            with self._state.locked():
                document = self._read_locked()
                records = [
                    cast(dict[str, object], item)
                    for item in cast(list[object], document["receipts"])
                    if type(item) is dict and item.get("account_ref") == account_ref
                ]
                if not records:
                    raise GoogleOAuthSessionError("oauth.token_unavailable")
                current = records[-1]
                if (
                    current.get("subject_id") != subject_id
                    or current.get("oauth_client_fingerprint")
                    != oauth_client_fingerprint
                    or type(current.get("vault_generation")) is not int
                ):
                    raise GoogleOAuthSessionError("oauth.token_unavailable")
                generation = cast(int, current["vault_generation"])
            account_digest = sha256(account_ref.encode("ascii")).hexdigest()
            lease = self._vault.lease(
                f"google-refresh-{account_digest}",
                expected_generation=generation,
                ttl_seconds=30,
            )
            return bytearray(self._vault.consume_lease(lease))
        except GoogleOAuthSessionError:
            raise
        except (CredentialVaultError, HiveStateError, KeyError, TypeError, ValueError):
            raise GoogleOAuthSessionError("oauth.token_unavailable") from None

    def store_refresh_token(
        self,
        operation_id: str,
        *,
        account_ref: str,
        subject_id: str,
        oauth_client_fingerprint: str,
        scope_profile: GoogleOAuthProfileIdV1,
        scope_fingerprint: str,
        refresh_token: bytearray,
    ) -> GoogleOAuthTokenWriteReceiptV1:
        prior = self.lookup_refresh_token_receipt(
            operation_id,
            account_ref=account_ref,
            scope_profile=scope_profile,
            scope_fingerprint=scope_fingerprint,
        )
        if prior is not None:
            refresh_token[:] = b"\0" * len(refresh_token)
            return prior
        if scope_profile is not GoogleOAuthProfileIdV1.INVENTORY_READONLY:
            refresh_token[:] = b"\0" * len(refresh_token)
            raise GoogleOAuthSessionError("oauth.scope_mismatch")
        try:
            self._bind_subject(account_ref, subject_id)
        except GoogleOAuthSessionError:
            refresh_token[:] = b"\0" * len(refresh_token)
            raise
        except Exception:
            refresh_token[:] = b"\0" * len(refresh_token)
            raise GoogleOAuthSessionError("oauth.token_write_failed") from None
        account_digest = sha256(account_ref.encode("ascii")).hexdigest()
        vault_ref = f"google-refresh-{account_digest}"
        metadata = self._vault.projection_metadata(vault_ref)
        generation = 1 if metadata is None else metadata[1] + 1
        try:
            self._vault.store_projection(vault_ref, generation, refresh_token)
        finally:
            refresh_token[:] = b"\0" * len(refresh_token)
        receipt = GoogleOAuthTokenWriteReceiptV1(
            operation_id,
            account_ref,
            subject_id,
            oauth_client_fingerprint,
            scope_profile,
            scope_fingerprint,
        )
        with self._state.locked():
            document = self._read_locked()
            receipts = cast(list[object], document["receipts"])
            if len(receipts) >= 4096:
                del receipts[: len(receipts) - 4095]
            receipts.append(
                {
                    "operation_id": receipt.operation_id,
                    "account_ref": receipt.account_ref,
                    "subject_id": receipt.subject_id,
                    "oauth_client_fingerprint": receipt.oauth_client_fingerprint,
                    "scope_profile": receipt.scope_profile.value,
                    "scope_fingerprint": receipt.scope_fingerprint,
                    "vault_generation": generation,
                }
            )
            self._state.replace_json_locked(_TOKEN_RECEIPTS, document)
        return receipt

    def _bind_subject(self, account_ref: str, subject_id: str) -> None:
        snapshot = self._manager._snapshot_for_internal_use()
        try:
            account = snapshot.by_account_ref[account_ref]
        except KeyError:
            raise GoogleOAuthSessionError("oauth.account_mismatch") from None
        if account.subject_id == subject_id:
            return
        if account.subject_id is not None:
            raise GoogleOAuthSessionError("oauth.subject_mismatch")

        def bind(document: dict[str, object]) -> None:
            accounts = document.get("google_accounts")
            if type(accounts) is not list:
                raise GoogleOAuthSessionError("oauth.account_mismatch")
            matches = [
                cast(dict[str, object], item)
                for item in accounts
                if type(item) is dict and item.get("ref") == account_ref
            ]
            if len(matches) != 1 or any(
                type(item) is dict
                and item.get("ref") != account_ref
                and item.get("subject_id") == subject_id
                for item in accounts
            ):
                raise GoogleOAuthSessionError("oauth.subject_mismatch")
            current = matches[0].get("subject_id")
            if current is not None and current != subject_id:
                raise GoogleOAuthSessionError("oauth.subject_mismatch")
            matches[0]["subject_id"] = subject_id

        self._store.atomic_update(bind)
        self._manager.reload(expected_generation=snapshot.generation)
        rebound = self._manager._snapshot_for_internal_use().by_account_ref.get(account_ref)
        if rebound is None or rebound.subject_id != subject_id:
            raise GoogleOAuthSessionError("oauth.subject_mismatch")


class GoogleOAuthCodeExchange:
    """Fixed-endpoint installed-app code exchange with bounded responses."""

    def exchange(
        self,
        client: dict[str, object],
        *,
        code: str,
        redirect_uri: str,
        pkce_verifier: str,
    ) -> GoogleOAuthCodeExchangeV1:
        if client.get("token_uri") != "https://oauth2.googleapis.com/token":
            raise GoogleOAuthSessionError("oauth.exchange_failed")
        body = urllib.parse.urlencode(
            {
                "code": code,
                "client_id": client.get("client_id"),
                "client_secret": client.get("client_secret"),
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": pkce_verifier,
            }
        ).encode("ascii")
        request = urllib.request.Request(
            "https://oauth2.googleapis.com/token",
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200 or response.geturl() != request.full_url:
                    raise ValueError
                raw = response.read(64 * 1024 + 1)
            value = _parse_json(raw)
            access_token = value.get("access_token")
            refresh_token = value.get("refresh_token")
            if (
                type(access_token) is not str
                or not access_token
                or type(refresh_token) is not str
                or not refresh_token
                or len(refresh_token.encode("utf-8")) > 16 * 1024
            ):
                raise ValueError
            subject_id = GoogleCloudApi(access_token).subject_id()
            return GoogleOAuthCodeExchangeV1(
                subject_id, bytearray(refresh_token.encode("utf-8"))
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise GoogleOAuthSessionError("oauth.exchange_failed") from None


class GoogleAccessTokenAuthority:
    """Mint one account-bound access token from active vaulted OAuth material."""

    def __init__(self, oauth: object, tokens: object) -> None:
        self._oauth = oauth
        self._tokens = tokens

    def issue_access_token(
        self, account_ref: str, subject_id: str, *, expected_generation: int
    ) -> str:
        refresh_token = bytearray()
        try:
            client = self._oauth.active_oauth_client_material(
                account_ref, expected_generation=expected_generation
            )
            refresh_token = self._tokens.load_refresh_token(
                account_ref,
                subject_id=subject_id,
                oauth_client_fingerprint=client.client_fingerprint,
            )
            if (
                client.token_uri != "https://oauth2.googleapis.com/token"
                or type(refresh_token) is not bytearray
                or not refresh_token
            ):
                raise ValueError
            body = urllib.parse.urlencode(
                {
                    "client_id": client.client_id,
                    "client_secret": client.client_secret,
                    "refresh_token": refresh_token.decode("utf-8"),
                    "grant_type": "refresh_token",
                }
            ).encode("ascii")
            request = urllib.request.Request(
                client.token_uri,
                data=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200 or response.geturl() != client.token_uri:
                    raise ValueError
                raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError
            value = _parse_json(raw)
            access_token = value.get("access_token")
            if (
                type(access_token) is not str
                or not access_token
                or len(access_token.encode("utf-8")) > 16 * 1024
                or value.get("token_type") != "Bearer"
                or GoogleCloudApi(access_token).subject_id() != subject_id
            ):
                raise ValueError
            return access_token
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise GoogleCloudApiError("google.api_auth_failed") from None
        finally:
            refresh_token[:] = b"\0" * len(refresh_token)


class GoogleProvisioner:
    """Use canonical inventory plus the existing Cloud API effect adapter."""

    def __init__(
        self,
        state_root: Path,
        manager: GoogleAccountInventoryManager,
        store: GoogleInventoryStore,
        access_tokens: GoogleAccessTokenAuthority,
    ) -> None:
        self._state = HiveStateStore(state_root)
        self._manager = manager
        self._store = store
        self._access_tokens = access_tokens
        with self._state.locked():
            try:
                self._read_locked()
            except HiveStateError as error:
                if error.args != ("state_not_found",):
                    raise
                self._state.replace_json_locked(
                    _PROVISIONER_DOCUMENT,
                    {"schema_version": 1, "plans": [], "applies": []},
                )

    def _read_locked(self) -> dict[str, object]:
        document = dict(
            self._state.read_json_locked(
                _PROVISIONER_DOCUMENT, max_bytes=4 * 1024 * 1024
            )
        )
        if (
            set(document) != {"schema_version", "plans", "applies"}
            or document.get("schema_version") != 1
            or type(document.get("plans")) is not list
            or type(document.get("applies")) is not list
        ):
            raise HiveStateError("invalid_google_provisioner_plans")
        for item in cast(list[object], document["plans"]):
            if (
                type(item) is not dict
                or set(item) != {"idempotency_key", "plan"}
                or type(item.get("idempotency_key")) is not str
                or _TOKEN.fullmatch(cast(str, item["idempotency_key"])) is None
            ):
                raise HiveStateError("invalid_google_provisioner_plans")
            self._stored_plan(item.get("plan"))
        for item in cast(list[object], document["applies"]):
            if (
                type(item) is not dict
                or set(item) != {"idempotency_key", "plan_digest"}
                or type(item.get("idempotency_key")) is not str
                or _TOKEN.fullmatch(cast(str, item["idempotency_key"])) is None
                or type(item.get("plan_digest")) is not str
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}", cast(str, item["plan_digest"])
                )
                is None
            ):
                raise HiveStateError("invalid_google_provisioner_plans")
        return document

    @staticmethod
    def _plan_document(plan: FillToQuotaPlan) -> dict[str, object]:
        evidence = plan.quota_evidence
        return {
            "account_ref": plan.account_ref,
            "expected_subject_id": plan.expected_subject_id,
            "quota_remaining": plan.quota_remaining,
            "quota_evidence": {
                "remaining": evidence.remaining,
                "observed_at": evidence.observed_at,
                "source": evidence.source,
                "account_ref": evidence.account_ref,
                "inventory_generation": evidence.inventory_generation,
                "inventory_fingerprint": evidence.inventory_fingerprint,
            },
            "inventory_generation": plan.inventory_generation,
            "inventory_fingerprint": plan.inventory_fingerprint,
            "projects": [
                {
                    "ref": item.ref,
                    "project_name": item.project_name,
                    "project_id": item.project_id,
                    "expected_project_number": item.expected_project_number,
                    "key_display_name": item.key_display_name,
                }
                for item in plan.projects
            ],
            "fingerprint": plan.fingerprint,
        }

    @staticmethod
    def _stored_plan(value: object) -> FillToQuotaPlan:
        fields = {
            "account_ref",
            "expected_subject_id",
            "quota_remaining",
            "quota_evidence",
            "inventory_generation",
            "inventory_fingerprint",
            "projects",
            "fingerprint",
        }
        evidence_fields = {
            "remaining",
            "observed_at",
            "source",
            "account_ref",
            "inventory_generation",
            "inventory_fingerprint",
        }
        if type(value) is not dict or set(value) != fields:
            raise HiveStateError("invalid_google_provisioner_plans")
        evidence_value = value.get("quota_evidence")
        raw_projects = value.get("projects")
        if (
            type(evidence_value) is not dict
            or set(evidence_value) != evidence_fields
            or type(raw_projects) is not list
            or len(raw_projects) > 10_000
            or any(
                type(value.get(field)) is not str or not value.get(field)
                for field in ("account_ref", "expected_subject_id")
            )
            or type(value.get("quota_remaining")) is not int
            or type(value.get("inventory_generation")) is not int
            or type(value.get("inventory_fingerprint")) is not str
            or type(value.get("fingerprint")) is not str
            or type(evidence_value.get("remaining")) is not int
            or type(evidence_value.get("inventory_generation")) is not int
            or any(
                type(evidence_value.get(field)) is not str
                or not evidence_value.get(field)
                for field in (
                    "observed_at",
                    "source",
                    "account_ref",
                    "inventory_fingerprint",
                )
            )
        ):
            raise HiveStateError("invalid_google_provisioner_plans")
        project_fields = {
            "ref",
            "project_name",
            "project_id",
            "expected_project_number",
            "key_display_name",
        }
        for item in raw_projects:
            if (
                type(item) is not dict
                or set(item) != project_fields
                or any(
                    type(item.get(field)) is not str or not item.get(field)
                    for field in (
                        "ref",
                        "project_name",
                        "project_id",
                        "key_display_name",
                    )
                )
                or (
                    item.get("expected_project_number") is not None
                    and type(item.get("expected_project_number")) is not str
                )
            ):
                raise HiveStateError("invalid_google_provisioner_plans")
        try:
            record = cast(dict[str, object], value)
            evidence_record = cast(dict[str, object], evidence_value)
            projects = tuple(
                PlannedHiveProject(
                    cast(str, item["ref"]),
                    cast(str, item["project_name"]),
                    cast(str, item["project_id"]),
                    cast(str | None, item["expected_project_number"]),
                    cast(str, item["key_display_name"]),
                )
                for item in cast(list[dict[str, object]], raw_projects)
            )
            evidence = GoogleQuotaEvidenceV1(
                cast(int, evidence_record["remaining"]),
                cast(str, evidence_record["observed_at"]),
                cast(str, evidence_record["source"]),
                cast(str, evidence_record["account_ref"]),
                cast(int, evidence_record["inventory_generation"]),
                cast(str, evidence_record["inventory_fingerprint"]),
            )
            plan = FillToQuotaPlan(
                cast(str, record["account_ref"]),
                cast(str, record["expected_subject_id"]),
                cast(int, record["quota_remaining"]),
                evidence,
                cast(int, record["inventory_generation"]),
                cast(str, record["inventory_fingerprint"]),
                projects,
                cast(str, record["fingerprint"]),
            )
        except (KeyError, TypeError, ValueError):
            raise HiveStateError("invalid_google_provisioner_plans") from None
        serialized = GoogleProvisioner._plan_document(plan)
        fingerprint_payload = {
            key: serialized[key]
            for key in (
                "account_ref",
                "expected_subject_id",
                "quota_evidence",
                "projects",
            )
        }
        expected_fingerprint = "sha256:" + sha256(
            json.dumps(
                fingerprint_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        if (
            serialized != value
            or plan.quota_remaining != plan.quota_evidence.remaining
            or plan.inventory_generation
            != plan.quota_evidence.inventory_generation
            or plan.inventory_fingerprint
            != plan.quota_evidence.inventory_fingerprint
            or plan.fingerprint != expected_fingerprint
        ):
            raise HiveStateError("invalid_google_provisioner_plans")
        return plan

    @staticmethod
    def _idempotency_key(
        idempotency_key: str | None,
        *,
        account_ref: str,
        expected_generation: int,
        quota_evidence: object,
    ) -> str:
        if idempotency_key is None:
            encoded = repr(
                (account_ref, expected_generation, quota_evidence)
            ).encode("utf-8")
            return "automatic-" + sha256(encoded).hexdigest()
        if type(idempotency_key) is not str or _TOKEN.fullmatch(idempotency_key) is None:
            raise GoogleCloudProvisionerError("provisioner.confirmation_invalid")
        return idempotency_key

    def _api(
        self, account_ref: str, subject_id: str, expected_generation: int
    ) -> GoogleCloudApi:
        try:
            token = self._access_tokens.issue_access_token(
                account_ref,
                subject_id,
                expected_generation=expected_generation,
            )
        except GoogleCloudApiError:
            raise GoogleCloudProvisionerError("provisioner.credential_unavailable")
        return GoogleCloudApi(token)

    def plan(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str | None,
        quota_evidence: object,
    ) -> FillToQuotaPlan:
        operation_key = self._idempotency_key(
            idempotency_key,
            account_ref=account_ref,
            expected_generation=expected_generation,
            quota_evidence=quota_evidence,
        )
        with self._state.locked():
            document = self._read_locked()
            prior = [
                cast(dict[str, object], item)
                for item in cast(list[object], document["plans"])
                if type(item) is dict and item.get("idempotency_key") == operation_key
            ]
            if prior:
                if len(prior) != 1:
                    raise GoogleCloudProvisionerError(
                        "provisioner.confirmation_invalid"
                    )
                stored = self._stored_plan(prior[0].get("plan"))
                if (
                    stored.account_ref != account_ref
                    or stored.inventory_generation != expected_generation
                    or stored.quota_evidence != quota_evidence
                ):
                    raise GoogleCloudProvisionerError(
                        "provisioner.confirmation_invalid"
                    )
                return stored
        snapshot = self._manager._snapshot_for_internal_use()
        if snapshot.generation != expected_generation:
            raise GoogleCloudProvisionerError("provisioner.inventory_conflict")
        try:
            account = snapshot.by_account_ref[account_ref]
        except KeyError:
            raise GoogleCloudProvisionerError("provisioner.account_invalid") from None
        if account.subject_id is None:
            raise GoogleCloudProvisionerError("provisioner.subject_mismatch")
        api = self._api(account_ref, account.subject_id, snapshot.generation)
        visible = api.search_projects()
        names = {
            cast(str, item["displayName"])
            for item in visible
            if type(item.get("displayName")) is str
        }
        ids = {
            cast(str, item["projectId"])
            for item in visible
            if type(item.get("projectId")) is str
        }
        _, document = self._store._read()
        plan = build_fill_to_quota_plan(
            document,
            account_ref=account_ref,
            expected_subject_id=account.subject_id,
            quota_evidence=cast(GoogleQuotaEvidenceV1, quota_evidence),
            inventory_generation=snapshot.generation,
            inventory_fingerprint=snapshot.content_fingerprint,
            now=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            visible_project_names=names,
            reserved_project_ids=ids,
        )
        with self._state.locked():
            document = self._read_locked()
            plans = cast(list[object], document["plans"])
            prior = [
                cast(dict[str, object], item)
                for item in plans
                if type(item) is dict and item.get("idempotency_key") == operation_key
            ]
            if prior:
                stored = self._stored_plan(prior[0].get("plan"))
                if len(prior) != 1 or stored != plan:
                    raise GoogleCloudProvisionerError(
                        "provisioner.confirmation_invalid"
                    )
                return stored
            if len(plans) >= 4096:
                raise GoogleCloudProvisionerError("provisioner.confirmation_invalid")
            plans.append(
                {"idempotency_key": operation_key, "plan": self._plan_document(plan)}
            )
            self._state.replace_json_locked(_PROVISIONER_DOCUMENT, document)
        return plan

    def apply(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        plan_digest: str,
    ) -> ProvisionReceipt | ProvisionPartialReceipt:
        if type(idempotency_key) is not str or _TOKEN.fullmatch(idempotency_key) is None:
            raise GoogleCloudProvisionerError("provisioner.confirmation_invalid")
        with self._state.locked():
            document = self._read_locked()
            matches = []
            for item in cast(list[object], document["plans"]):
                if type(item) is not dict:
                    raise HiveStateError("invalid_google_provisioner_plans")
                raw_plan = item.get("plan")
                if type(raw_plan) is dict and raw_plan.get("fingerprint") == plan_digest:
                    matches.append(self._stored_plan(raw_plan))
            plan = matches[0] if len(matches) == 1 else None
            if (
                plan is None
                or plan.account_ref != account_ref
                or plan.inventory_generation != expected_generation
            ):
                raise GoogleCloudProvisionerError(
                    "provisioner.confirmation_invalid"
                )
            applies = cast(list[object], document["applies"])
            prior = [
                cast(dict[str, object], item)
                for item in applies
                if type(item) is dict and item.get("idempotency_key") == idempotency_key
            ]
            if prior and (
                len(prior) != 1 or prior[0].get("plan_digest") != plan_digest
            ):
                raise GoogleCloudProvisionerError("provisioner.confirmation_invalid")
            if not prior:
                if len(applies) >= 4096:
                    raise GoogleCloudProvisionerError(
                        "provisioner.confirmation_invalid"
                    )
                applies.append(
                    {"idempotency_key": idempotency_key, "plan_digest": plan_digest}
                )
                self._state.replace_json_locked(_PROVISIONER_DOCUMENT, document)
        api = self._api(
            account_ref, plan.expected_subject_id, expected_generation
        )
        try:
            receipt = execute_fill_to_quota_plan(
                plan,
                api=api,
                store=self._store,
                confirmed_fingerprint=plan_digest,
                now=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                current_inventory=lambda: (
                    self._manager._snapshot_for_internal_use().generation,
                    self._manager._snapshot_for_internal_use().content_fingerprint,
                ),
            )
            self._manager.reload(expected_generation=expected_generation)
            return receipt
        except GoogleCloudProvisionerError as error:
            if error.partial is not None:
                return error.partial
            raise


class GoogleBillingLease:
    def __init__(self, account_ref: str, subject_id: str, token: str) -> None:
        self.account_ref = account_ref
        self.subject_id = subject_id
        self._token = token

    def _request(
        self, method: str, project_id: str, body: object = None
    ) -> dict[str, object]:
        encoded = urllib.parse.quote(project_id, safe="")
        url = f"https://cloudbilling.googleapis.com/v1/projects/{encoded}/billingInfo"
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200 or response.geturl() != url:
                    raise ValueError
                raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError
            return _parse_json(raw)
        except Exception:
            raise GoogleCloudApiError("google.api_unavailable") from None

    @staticmethod
    def _binding(value: Mapping[str, object]) -> str | None:
        raw = value.get("billingAccountName")
        if raw is None:
            return None
        if type(raw) is not str or not raw.startswith("billingAccounts/"):
            raise GoogleCloudApiError("google.api_response_invalid")
        return raw.split("/", 1)[1]

    @staticmethod
    def _precondition(value: Mapping[str, object]) -> str:
        return (
            "sha256:"
            + sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        )

    def get_project_billing_binding(
        self, project_id: str
    ) -> GoogleBillingBindingObservationV1:
        value = self._request("GET", project_id)
        return GoogleBillingBindingObservationV1(
            self._binding(value), self._precondition(value)
        )

    def bind_project_if_unbound(
        self,
        project_id: str,
        billing_account_id: str,
        *,
        expected_precondition: str,
    ) -> GoogleBillingBindResultV1:
        current = self._request("GET", project_id)
        binding = self._binding(current)
        if self._precondition(current) != expected_precondition:
            return GoogleBillingBindResultV1("conflict", binding)
        if binding is not None:
            return GoogleBillingBindResultV1(
                "already_bound" if binding == billing_account_id else "conflict",
                binding,
            )
        result = self._request(
            "PUT",
            project_id,
            {"billingAccountName": "billingAccounts/" + billing_account_id},
        )
        return GoogleBillingBindResultV1("created", self._binding(result))


class GoogleBillingAuthority:
    def __init__(
        self,
        manager: GoogleAccountInventoryManager,
        access_tokens: GoogleAccessTokenAuthority,
    ) -> None:
        self._manager = manager
        self._access_tokens = access_tokens

    def lease_billing_effect(
        self, account_ref: str, subject_id: str
    ) -> GoogleBillingLease:
        try:
            snapshot = self._manager._snapshot_for_internal_use()
            account = snapshot.by_account_ref[account_ref]
            if account.subject_id != subject_id:
                raise KeyError
            token = self._access_tokens.issue_access_token(
                account_ref,
                subject_id,
                expected_generation=snapshot.generation,
            )
        except (GoogleAccountInventoryError, GoogleCloudApiError, KeyError, AttributeError):
            raise GoogleCloudApiError("google.api_auth_failed")
        return GoogleBillingLease(account_ref, subject_id, token)


class AdminRuntime:
    """Own the daemon, business owners, authorities, and credential FDs."""

    def __init__(
        self,
        daemon: AdminDaemon,
        service: MasterjetControlService,
        credentials: SystemdCredentialSet,
        *,
        openai_credentials: OpenAICredentialService,
        google_manager: GoogleAccountInventoryManager,
        bearer: MasterjetBearerVerifier | None,
        totp: TotpStepUpVerifier,
        access: RefreshingCloudflareAccessVerifier | None,
    ) -> None:
        self.daemon = daemon
        self.service = service
        self._credentials = credentials
        self._openai_credentials = openai_credentials
        self._google_manager = google_manager
        self._bearer = bearer
        self._totp = totp
        self._access = access
        self._closed = False

    def run(self) -> int:
        result = 1
        try:
            result = self.daemon.run()
        finally:
            if not self.close():
                result = 1
        return result

    def close(self) -> bool:
        if self._closed:
            return True
        self._closed = True
        clean = True
        for action in (
            self._openai_credentials.close,
            self._google_manager.close,
            self._close_access,
            self._close_authorities,
            self._credentials.close,
        ):
            try:
                action()
            except BaseException:
                clean = False
        return clean

    def _close_access(self) -> None:
        if self._access is not None:
            self._access.close(0.5)

    def _close_authorities(self) -> None:
        if self._bearer is not None:
            self._bearer.close()
        self._totp.close()


def _private_directory_from_environment(name: str) -> Path:
    raw = os.environ.get(name)
    if type(raw) is not str or not raw:
        raise AdminAssemblyError
    path = Path(raw)
    try:
        metadata = path.lstat()
    except OSError:
        raise AdminAssemblyError from None
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AdminAssemblyError
    return path


def _cloudflare_verifier(
    config: AdminConfig,
) -> RefreshingCloudflareAccessVerifier | None:
    if config.authority_mode == "bearer":
        return None
    team = config.cloudflare_team_domain
    audience = config.cloudflare_audience
    if team is None or audience is None:
        raise AdminAssemblyError
    fetcher = CloudflareJwksFetcher(team)
    initial = fetcher()

    def scopes(subject: str, _claims: Mapping[str, object]) -> tuple[str, ...]:
        if subject != config.remote_subject:
            raise AdminAuthError("authority.identity_invalid")
        return config.remote_scopes

    return RefreshingCloudflareAccessVerifier(
        issuer="https://" + team,
        audience=audience,
        initial_jwks=initial,
        loader=fetcher,
        principal_resolver=scopes,
    )


def _close_partial(actions: list[Callable[[], object]]) -> None:
    for action in reversed(actions):
        try:
            action()
        except BaseException:
            pass


def assemble_admin_runtime() -> AdminRuntime:
    """Build one installed owner graph from systemd-owned directories and FDs."""

    credential_directory = _private_directory_from_environment("CREDENTIALS_DIRECTORY")
    runtime_root = _private_directory_from_environment("RUNTIME_DIRECTORY")
    state_root = _private_directory_from_environment("STATE_DIRECTORY")
    credentials = SystemdCredentialSet(credential_directory)
    cleanup: list[Callable[[], object]] = [credentials.close]
    try:
        config = parse_admin_config(credentials.read("admin-config", _CONFIG_MAX_BYTES))
        inventory_path = state_root / _INVENTORY_DOCUMENT.name
        _empty_inventory(inventory_path)
        google_store = GoogleInventoryStore.from_systemd_state_directory()
        google_manager = GoogleAccountInventoryManager.from_systemd_state_directory()
        cleanup.append(google_manager.close)
        google_manager.reload()

        operation_store = AdminOperationStore(state_root)
        host_registry = HostRegistry(state_root)
        identities = OpenAIIdentitySource(state_root / "openai-identities")
        registry = DurableAccountRegistry(
            state_root / "account-registry",
            identities=identities,
            google_store=google_store,
            google_manager=google_manager,
        )

        ingress_vault = CredentialVault.from_key_fd(
            state_root / "secret-ingress-vault",
            key_fd=credentials.fd("admin-vault-key"),
        )
        ingress = AdminSecretIngressOwner(
            state_root / "secret-ingress", vault=ingress_vault
        )
        openai_vault = CredentialVault.from_key_fd(
            state_root / "openai-vault",
            key_fd=credentials.fd("admin-vault-key"),
        )
        openai_credentials = OpenAICredentialService(
            openai_vault,
            identities,
            OpenAIAuthReceiptStore(state_root / "openai-receipts"),
            ingress_authority=ingress,
        )
        cleanup.append(openai_credentials.close)

        google_client_vault = CredentialVault.from_key_fd(
            state_root / "google-client-vault",
            key_fd=credentials.fd("admin-vault-key"),
        )
        google_token_vault = CredentialVault.from_key_fd(
            state_root / "google-token-vault",
            key_fd=credentials.fd("admin-vault-key"),
        )
        token_writer = DurableGoogleTokenWriter(
            state_root / "google-token-receipts",
            vault=google_token_vault,
            store=google_store,
            manager=google_manager,
        )
        google_oauth = GoogleOAuthControlService(
            state_root / "google-oauth",
            manager=google_manager,
            client_vault=google_client_vault,
            token_writer=token_writer,
            secret_ingress=ingress,
            code_exchange=GoogleOAuthCodeExchange(),
        )
        quota = CredentialQuotaCollector(
            lambda: credentials.read("admin-quota-evidence", _QUOTA_MAX_BYTES)
        )
        access_tokens = GoogleAccessTokenAuthority(google_oauth, token_writer)
        provisioner = GoogleProvisioner(
            state_root / "google-provisioner",
            google_manager,
            google_store,
            access_tokens,
        )
        billing = GoogleBillingService(
            google_manager, GoogleBillingAuthority(google_manager, access_tokens)
        )

        service = MasterjetControlService(
            operation_store=operation_store,
            openai_accounts=registry,
            openai_credentials=openai_credentials,
            google_manager=google_manager,
            google_oauth=google_oauth,
            quota_collector=quota,
            google_provisioner=provisioner,
            google_billing=billing,
            host_registry=host_registry,
            secret_ingress=ingress,
            account_registry=registry,
        )

        bearer = (
            MasterjetBearerVerifier.from_fd(
                credentials.fd("admin-bearer"),
                subject=config.remote_subject,
                scopes=config.remote_scopes,
            )
            if config.authority_mode in {"bearer", "require_both"}
            else None
        )
        if bearer is not None:
            cleanup.append(bearer.close)
        totp = TotpStepUpVerifier.from_fd(
            credentials.fd("admin-totp"),
            replay_state_path=state_root / "totp-replay",
        )
        cleanup.append(totp.close)
        access = _cloudflare_verifier(config)
        if access is not None:
            cleanup.append(lambda: access.close(0.5))

        def authorize(peer: UnixPeerCredentials) -> AdminPrincipalV1:
            if peer.uid != os.geteuid():
                raise PermissionError
            return AdminPrincipalV1(
                config.local_subject,
                config.local_scopes,
                "unix-peer",
                True,
            )

        def socket_factory(candidate: MasterjetControlService) -> AdminSocketServer:
            return AdminSocketServer(
                runtime_root / "admin.sock",
                candidate,
                authorize,
                attestation_key_fd=credentials.fd("admin-attestation"),
            )

        def http_factory(candidate: MasterjetControlService) -> AdminHttpServer:
            return AdminHttpServer(
                (config.http_host, config.http_port),
                candidate,
                authority_mode=config.authority_mode,
                bearer_verifier=bearer,
                access_verifier=cast(Any, access),
                step_up_verifier=totp,
                origin_host=config.origin_host,
                trusted_proxy_addresses=config.trusted_proxy_addresses,
            )

        daemon = AdminDaemon(
            service,
            socket_factory=socket_factory,
            http_factory=http_factory,
            jwks_refresher=access,
        )
        cleanup.clear()
        return AdminRuntime(
            daemon,
            service,
            credentials,
            openai_credentials=openai_credentials,
            google_manager=google_manager,
            bearer=bearer,
            totp=totp,
            access=access,
        )
    except (KeyboardInterrupt, SystemExit):
        _close_partial(cleanup)
        raise
    except BaseException:
        _close_partial(cleanup)
        raise AdminAssemblyError from None
