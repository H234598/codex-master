"""Public desktop-client metadata bound to the private Inventory layout owner.

This is a new source-defined D160 schema. It is not a reader for downloaded
Google client documents or any historical deployment artifact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
import re

from . import google_inventory_token_vault as _layout_owner


_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_TOKEN_URI = "https://oauth2.googleapis.com/token"
_REDIRECT_KIND = "ipv4_loopback_ephemeral_callback"
_MAX_REGISTRY_BYTES = 32 * 1024
_MAX_GENERATION = 2**63 - 1
_ACCOUNT_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_CLIENT_ID = re.compile(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com\Z", re.ASCII)
_REGISTRY_NAME = "inventory-desktop-clients-v1.json"


class InventoryDesktopClientRegistryError(ValueError):
    """Closed, metadata-free registry failure."""


@dataclass(frozen=True, slots=True)
class _InventoryDesktopClientRecordV1:
    account_ref: str
    client_id: str
    client_type: str
    auth_uri: str
    token_uri: str
    redirect_kind: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class InventoryDesktopClientRegistryV1:
    registry_generation: int
    records: tuple[_InventoryDesktopClientRecordV1, ...]

    @property
    def fingerprint(self) -> str:
        return "sha256:" + sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def parse(cls, raw: bytes) -> InventoryDesktopClientRegistryV1:
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            value: dict[str, object] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError
                value[key] = item
            return value

        try:
            if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_REGISTRY_BYTES:
                raise ValueError
            document = json.loads(raw, object_pairs_hook=unique)
            if (
                type(document) is not dict
                or set(document)
                != {"format_version", "record_kind", "registry_generation", "records"}
                or type(document["format_version"]) is not int
                or document["format_version"] != 1
                or document["record_kind"] != "inventory_desktop_client_registry_v1"
                or type(document["registry_generation"]) is not int
                or not 1 <= document["registry_generation"] <= _MAX_GENERATION
                or type(document["records"]) is not list
            ):
                raise ValueError
            records: list[_InventoryDesktopClientRecordV1] = []
            accounts: list[str] = []
            clients: set[str] = set()
            for value in document["records"]:
                if (
                    type(value) is not dict
                    or set(value)
                    != {
                        "account_ref",
                        "client_id",
                        "client_type",
                        "auth_uri",
                        "token_uri",
                        "redirect_kind",
                        "fingerprint",
                    }
                    or any(type(item) is not str for item in value.values())
                    or _ACCOUNT_REF.fullmatch(value["account_ref"]) is None
                    or _CLIENT_ID.fullmatch(value["client_id"]) is None
                    or len(value["client_id"]) > 512
                    or value["client_type"] != "installed"
                    or value["auth_uri"] != _AUTH_URI
                    or value["token_uri"] != _TOKEN_URI
                    or value["redirect_kind"] != _REDIRECT_KIND
                ):
                    raise ValueError
                public = {
                    key: item for key, item in value.items() if key != "fingerprint"
                }
                fingerprint = (
                    "sha256:"
                    + sha256(
                        json.dumps(
                            public, sort_keys=True, separators=(",", ":")
                        ).encode("ascii")
                    ).hexdigest()
                )
                if value["fingerprint"] != fingerprint or value["client_id"] in clients:
                    raise ValueError
                accounts.append(value["account_ref"])
                clients.add(value["client_id"])
                records.append(_InventoryDesktopClientRecordV1(**value))
            if accounts != sorted(set(accounts)):
                raise ValueError
            return cls(document["registry_generation"], tuple(records))
        except (ValueError, TypeError, UnicodeError, KeyError, RecursionError):
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_invalid"
            ) from None

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "format_version": 1,
                "record_kind": "inventory_desktop_client_registry_v1",
                "registry_generation": self.registry_generation,
                "records": [asdict(record) for record in self.records],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def for_account(self, account_ref: str) -> _InventoryDesktopClientRecordV1:
        if type(account_ref) is str:
            for record in self.records:
                if record.account_ref == account_ref:
                    return record
        raise InventoryDesktopClientRegistryError(
            "oauth.inventory_registry_unavailable"
        )


class _InventoryDesktopClientRegistryStoreV1:
    """Sealed layout access; no production caller can supply a registry path."""

    __slots__ = ("_layout",)

    def __init__(self, layout: _layout_owner._TheHiveInventoryVaultLayout) -> None:
        if type(layout) is not _layout_owner._TheHiveInventoryVaultLayout:
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_invalid"
            )
        self._layout = layout

    def __repr__(self) -> str:
        return "_InventoryDesktopClientRegistryStoreV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private registry store is not serializable")

    def _read(self, directory):
        fd = None
        name = _layout_owner._PrivateName(_REGISTRY_NAME)
        try:
            if _layout_owner._revalidate_directory_capability(directory) is not None:
                raise ValueError
            try:
                fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory.fd,
                )
            except FileNotFoundError:
                return None, None
            code, identity = _layout_owner._validated_private_file_identity(fd)
            if code is not None or identity is None:
                raise ValueError
            if (
                _layout_owner._attest_private_fd_and_name(directory, name, fd, identity)
                is not None
            ):
                raise ValueError
            code, raw = _layout_owner._read_bounded(fd)
            if code is not None or raw is None:
                raise ValueError
            registry = InventoryDesktopClientRegistryV1.parse(raw)
            if (
                _layout_owner._attest_private_fd_and_name(directory, name, fd, identity)
                is not None
            ):
                raise ValueError
            return registry, identity
        finally:
            name.clear()
            _layout_owner._close_fd(fd)

    def load(self) -> InventoryDesktopClientRegistryV1 | None:
        directory = None
        try:
            directory = self._layout._open_inventory_oauth_directory()
            registry, _identity = self._read(directory)
            return registry
        except (
            ValueError,
            OSError,
            _layout_owner.GoogleInventoryReadonlyTokenVaultError,
        ):
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_unavailable"
            ) from None
        finally:
            _layout_owner._close_directory_capability(directory)

    def _replace(
        self, registry: InventoryDesktopClientRegistryV1, *, expected_generation: int
    ) -> None:
        """Atomic CAS primitive, private to the unconnected provisioning effect."""

        directory = None
        locked = None
        try:
            if (
                type(registry) is not InventoryDesktopClientRegistryV1
                or type(expected_generation) is not int
                or not 0 <= expected_generation < _MAX_GENERATION
            ):
                raise ValueError
            validated = InventoryDesktopClientRegistryV1.parse(
                registry.canonical_bytes()
            )
            if validated.registry_generation != expected_generation + 1:
                raise ValueError
            directory = self._layout._open_inventory_oauth_directory()
            code, locked = _layout_owner._acquire_locked_record(
                directory, "inventory-desktop-clients-v1"
            )
            if code is not None or locked is None:
                raise ValueError
            current, identity = self._read(directory)
            if (current.registry_generation if current else 0) != expected_generation:
                raise ValueError
            code = _layout_owner._write_record(
                directory,
                _layout_owner._PrivateName(_REGISTRY_NAME),
                _layout_owner._PrivateName(".inventory-desktop-clients-v1-"),
                _layout_owner._PrivateRecord(json.loads(validated.canonical_bytes())),
                identity,
            )
            if code is not None:
                raise ValueError
        except (
            ValueError,
            OSError,
            _layout_owner.GoogleInventoryReadonlyTokenVaultError,
        ):
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_unavailable"
            ) from None
        finally:
            _layout_owner._release_locked_record(locked)
            _layout_owner._close_directory_capability(directory)


_PROVISION_TEST_SEAL = object()


class _InventoryDesktopClientProvisionEffectV1:
    """Unwired Queen effect contract; production cannot mint its capability.

    A production Queen approval owner has not been defined. Only the explicit
    synthetic seam below creates this effect; possession of a caller string
    claiming to be Queen never grants access.
    """

    __slots__ = ("_store", "_registry", "_binding", "plan_digest", "_consumed")

    def __init__(
        self, seal, *, store, registry, plan_id, account_ref, expected_generation
    ):
        if (
            seal is not _PROVISION_TEST_SEAL
            or type(store) is not _InventoryDesktopClientRegistryStoreV1
            or type(registry) is not InventoryDesktopClientRegistryV1
            or type(plan_id) is not str
            or _ACCOUNT_REF.fullmatch(plan_id) is None
            or type(account_ref) is not str
            or _ACCOUNT_REF.fullmatch(account_ref) is None
            or type(expected_generation) is not int
            or not 0 <= expected_generation < _MAX_GENERATION
        ):
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_invalid"
            )
        registry = InventoryDesktopClientRegistryV1.parse(registry.canonical_bytes())
        registry.for_account(account_ref)
        current = store.load()
        previous_others = (
            tuple(
                record
                for record in current.records
                if record.account_ref != account_ref
            )
            if current
            else ()
        )
        if (
            (current.registry_generation if current else 0) != expected_generation
            or registry.registry_generation != expected_generation + 1
            or tuple(
                record
                for record in registry.records
                if record.account_ref != account_ref
            )
            != previous_others
        ):
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_invalid"
            )
        binding = (plan_id, account_ref, expected_generation)
        self._store = store
        self._registry = registry
        self._binding = binding
        self.plan_digest = (
            "sha256:"
            + sha256(
                b"inventory-desktop-client-provision-v1\0"
                + json.dumps(binding, separators=(",", ":")).encode("ascii")
                + b"\0"
                + registry.canonical_bytes()
            ).hexdigest()
        )
        self._consumed = False

    def __repr__(self) -> str:
        return "_InventoryDesktopClientProvisionEffectV1(<redacted>)"

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("private provisioning effect is not serializable")

    def _apply_preconfirmed_for_queen(
        self, *, plan_id, plan_digest, account_ref, expected_generation
    ) -> None:
        if self._consumed:
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_unavailable"
            )
        self._consumed = True
        if (
            type(plan_id) is not str
            or type(plan_digest) is not str
            or type(account_ref) is not str
            or type(expected_generation) is not int
            or (plan_id, account_ref, expected_generation) != self._binding
            or plan_digest != self.plan_digest
        ):
            raise InventoryDesktopClientRegistryError(
                "oauth.inventory_registry_invalid"
            )
        self._store._replace(self._registry, expected_generation=expected_generation)


def _for_test_inventory_desktop_client_provision_effect(
    *, store, registry, plan_id, account_ref, expected_generation
):
    """The sole minting seam; deliberately absent from production composition."""

    return _InventoryDesktopClientProvisionEffectV1(
        _PROVISION_TEST_SEAL,
        store=store,
        registry=registry,
        plan_id=plan_id,
        account_ref=account_ref,
        expected_generation=expected_generation,
    )
