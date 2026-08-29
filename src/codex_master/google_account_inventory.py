"""Strict, redacted ingestion for private Google account inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import threading
from types import MappingProxyType
from typing import Generic, Iterator, Mapping, TypeVar
import weakref

import yaml
from yaml.events import AliasEvent, ScalarEvent
from yaml.nodes import MappingNode, ScalarNode


DEFAULT_GOOGLE_ACCOUNT_INVENTORY_PATH = Path(
    "/home/teladi/.config/codex-master-mcp/api-token.yaml"
)
MAX_INVENTORY_BYTES = 1_048_576
MAX_BILLING_ACCOUNTS_PER_ACCOUNT = 4
MAX_PROJECT_SLOTS_PER_ACCOUNT = 256
MAX_YAML_DEPTH = 32
MAX_YAML_NODES = 4_096
MAX_YAML_SCALAR_BYTES = 32 * 1024
MAX_YAML_ALIASES = 0
MAX_HIVE_SLOT_DIGITS = 9

_ACCOUNT_FIELDS_V1 = frozenset(
    {
        "ref",
        "login_email",
        "recovery_email",
        "label",
        "subject_id",
        "billing_accounts",
        "projects",
    }
)
_ACCOUNT_FIELDS_V2 = _ACCOUNT_FIELDS_V1 | frozenset({"auth"})
_BILLING_FIELDS = frozenset({"ref", "billing_account_id", "label"})
_PROJECT_FIELDS_V1 = frozenset(
    {
        "ref",
        "billing_account_ref",
        "status",
        "project_id",
        "project_number",
        "key_id",
        "key_uid",
        "secret",
    }
)
_PROJECT_FIELDS_V2 = _PROJECT_FIELDS_V1 | frozenset(
    {"project_name", "purpose", "key_name"}
)
_PROJECT_PURPOSES = frozenset({"hive", "oauth_control", "external"})
_PROJECT_NAME = re.compile(r"[A-Za-z][A-Za-z' !-]{2,28}[A-Za-z]\Z")
_KEY_NAME = re.compile(r"[A-Za-z][A-Za-z' !-]{2,61}[A-Za-z]\Z")
_AUTH_FIELDS = frozenset(
    {"access_token", "refresh_token", "cookies", "client_fingerprint"}
)
_PROJECT_STATUSES = frozenset(
    {
        "active",
        "blocked",
        "delete_planned",
        "delete_requested",
        "restore_pending",
        "provisioning",
        "services_enabled",
        "deleted",
    }
)
_HIVE_REF = re.compile(r"the-hive-([0-9]+)\Z")


class GoogleAccountInventoryError(Exception):
    """Redacted inventory failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"GoogleAccountInventoryError({self.code!r})"


def systemd_google_account_inventory_path() -> Path:
    """Resolve the fixed inventory name inside systemd's private state directory."""

    raw = os.environ.get("STATE_DIRECTORY")
    if raw is None or not raw or ":" in raw:
        raise GoogleAccountInventoryError("credential.inventory_unavailable")
    root = Path(raw)
    try:
        metadata = os.lstat(root)
    except OSError:
        raise GoogleAccountInventoryError("credential.inventory_unavailable") from None
    if (
        not root.is_absolute()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise GoogleAccountInventoryError("credential.inventory_unavailable")
    return root / DEFAULT_GOOGLE_ACCOUNT_INVENTORY_PATH.name


_T = TypeVar("_T")


class _FrozenIndex(Mapping[str | int, _T], Generic[_T]):
    """Immutable index that remains safe through ``dataclasses.asdict``."""

    __slots__ = ("_items",)

    def __init__(self, values: Mapping[str | int, _T]) -> None:
        self._items = MappingProxyType(dict(values))

    def __getitem__(self, key: str | int) -> _T:
        return self._items[key]

    def __iter__(self) -> Iterator[str | int]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __deepcopy__(self, memo: dict[int, object]) -> dict[str | int, _T]:
        return dict(self._items)


@dataclass(frozen=True)
class GoogleBillingAccountV1:
    ref: str
    billing_account_id: str | None
    label: str | None


@dataclass(frozen=True)
class GoogleProjectV1:
    ref: str
    hive_slot: int
    billing_account_ref: str | None
    status: str
    project_id: str | None
    project_number: str | None
    key_id: str | None
    key_uid: str | None
    project_name: str | None
    purpose: str
    key_name: str | None


@dataclass(frozen=True)
class GoogleAccountV1:
    ref: str
    login_email: str
    recovery_email: str | None
    label: str | None
    subject_id: str | None
    billing_accounts: tuple[GoogleBillingAccountV1, ...]
    projects: tuple[GoogleProjectV1, ...]


@dataclass(frozen=True)
class GoogleAccountInventoryDocumentV1:
    """Private immutable parsed inventory; runtime state belongs to GA-I1."""

    schema_version: int
    accounts: tuple[GoogleAccountV1, ...]
    content_fingerprint: str
    by_ref: _FrozenIndex[GoogleAccountV1 | GoogleBillingAccountV1 | GoogleProjectV1] = (
        field(repr=False, compare=False, hash=False)
    )
    by_subject_id: _FrozenIndex[GoogleAccountV1] = field(
        repr=False, compare=False, hash=False
    )
    by_billing_account_id: _FrozenIndex[GoogleBillingAccountV1] = field(
        repr=False, compare=False, hash=False
    )
    by_project_id: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )
    by_key_id: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )
    by_key_uid: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )
    by_hive_slot: _FrozenIndex[GoogleProjectV1] = field(
        repr=False, compare=False, hash=False
    )

    def public_projection(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "schema_version": self.schema_version,
                "account_count": len(self.accounts),
                "billing_account_count": sum(
                    len(account.billing_accounts) for account in self.accounts
                ),
                "project_count": sum(
                    len(account.projects) for account in self.accounts
                ),
                "active_project_count": sum(
                    1
                    for account in self.accounts
                    for project in account.projects
                    if project.status == "active"
                ),
            }
        )

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("GoogleAccountInventoryDocumentV1 is not serializable")


class _GoogleAccountInventorySecretSource:
    """One-shot private source, deliberately absent from document fields."""

    __slots__ = ("_secrets",)

    def __init__(self, secrets: Mapping[str, str]) -> None:
        self._secrets = MappingProxyType(dict(secrets))

    def _secret_for_project(self, project_ref: str) -> str:
        try:
            return self._secrets[project_ref]
        except KeyError:
            _error("credential.inventory_secret_source_unavailable")

    def __repr__(self) -> str:
        return "_GoogleAccountInventorySecretSource()"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("private inventory secret source is not serializable")


_DOCUMENT_SECRET_SOURCES: dict[
    int,
    tuple[
        weakref.ReferenceType[GoogleAccountInventoryDocumentV1],
        _GoogleAccountInventorySecretSource,
    ],
] = {}
_DOCUMENT_SECRET_SOURCES_LOCK = threading.Lock()


def _bind_document_secret_source(
    document: GoogleAccountInventoryDocumentV1, secrets: Mapping[str, str]
) -> None:
    document_id = id(document)

    def discard(
        reference: weakref.ReferenceType[GoogleAccountInventoryDocumentV1],
    ) -> None:
        with _DOCUMENT_SECRET_SOURCES_LOCK:
            existing = _DOCUMENT_SECRET_SOURCES.get(document_id)
            if existing is not None and existing[0] is reference:
                _DOCUMENT_SECRET_SOURCES.pop(document_id, None)

    reference = weakref.ref(document, discard)
    with _DOCUMENT_SECRET_SOURCES_LOCK:
        _DOCUMENT_SECRET_SOURCES[document_id] = (
            reference,
            _GoogleAccountInventorySecretSource(secrets),
        )


def _consume_document_secret_source(
    document: GoogleAccountInventoryDocumentV1,
) -> _GoogleAccountInventorySecretSource:
    """GA-I1-only handoff; source is document-bound and consumable once."""

    with _DOCUMENT_SECRET_SOURCES_LOCK:
        existing = _DOCUMENT_SECRET_SOURCES.pop(id(document), None)
    if existing is None or existing[0]() is not document:
        _error("credential.inventory_secret_source_unavailable")
    return existing[1]


class GoogleAccountInventoryLoader:
    """Load only canonical private YAML. Test source injection stays private."""

    __slots__ = ("_path",)

    def __init__(self) -> None:
        self._path = DEFAULT_GOOGLE_ACCOUNT_INVENTORY_PATH

    @classmethod
    def from_systemd_state_directory(cls) -> GoogleAccountInventoryLoader:
        loader = cls.__new__(cls)
        loader._path = systemd_google_account_inventory_path()
        return loader

    @classmethod
    def _for_test_path(cls, path: Path) -> GoogleAccountInventoryLoader:
        loader = cls.__new__(cls)
        loader._path = path
        return loader

    def load(self) -> GoogleAccountInventoryDocumentV1:
        raw = _read_private_inventory_bytes(self._path)
        if b"\x00" in raw:
            _unavailable()
        try:
            parsed = _load_strict_yaml(raw.decode("utf-8"))
            return _build_document(parsed)
        except UnicodeError:
            _unavailable()
        except GoogleAccountInventoryError:
            raise
        except (yaml.YAMLError, RecursionError, ValueError, OverflowError, TypeError):
            _schema_invalid()


class _InventoryYamlBoundaryError(yaml.YAMLError):
    """Input boundary violation without parser details."""


@dataclass(frozen=True)
class _YamlIntegerLiteral:
    """Deferred YAML integer scalar; only schema_version may consume it."""

    value: str


class _StrictInventoryYamlLoader(yaml.SafeLoader):
    """SafeLoader with bounded structure and no YAML indirection features."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0
        self._aliases = 0

    def compose_node(self, parent: object, index: object) -> object:
        event = self.peek_event()
        if isinstance(event, AliasEvent):
            self._aliases += 1
            if self._aliases > MAX_YAML_ALIASES:
                raise _InventoryYamlBoundaryError("alias")
        if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
            raise _InventoryYamlBoundaryError("anchor")
        if (
            isinstance(event, ScalarEvent)
            and len(event.value.encode("utf-8")) > MAX_YAML_SCALAR_BYTES
        ):
            raise _InventoryYamlBoundaryError("scalar")
        self._depth += 1
        self._nodes += 1
        try:
            if self._depth > MAX_YAML_DEPTH or self._nodes > MAX_YAML_NODES:
                raise _InventoryYamlBoundaryError("structure")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(
        self, node: MappingNode, deep: bool = False
    ) -> dict[object, object]:
        result: dict[object, object] = {}
        for key_node, value_node in node.value:
            if (
                getattr(key_node, "value", None) == "<<"
                or getattr(key_node, "tag", None) == "tag:yaml.org,2002:merge"
            ):
                raise _InventoryYamlBoundaryError("merge")
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in result:
                    raise _InventoryYamlBoundaryError("duplicate")
                result[key] = self.construct_object(value_node, deep=deep)
            except TypeError:
                raise _InventoryYamlBoundaryError("mapping-key") from None
        return result

    def construct_yaml_int(self, node: ScalarNode) -> _YamlIntegerLiteral:
        if node.value not in {"1", "2"}:
            raise _InventoryYamlBoundaryError("integer")
        return _YamlIntegerLiteral(node.value)


_StrictInventoryYamlLoader.add_constructor(
    "tag:yaml.org,2002:int", _StrictInventoryYamlLoader.construct_yaml_int
)


def _load_strict_yaml(text: str) -> object:
    return yaml.load(text, Loader=_StrictInventoryYamlLoader)


def _error(code: str) -> None:
    raise GoogleAccountInventoryError(code) from None


def _unavailable() -> None:
    _error("credential.inventory_unavailable")


def _permissions() -> None:
    _error("credential.inventory_permissions")


def _schema_invalid() -> None:
    _error("credential.inventory_schema_invalid")


def _identity(
    item: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _safe_ancestor(item: os.stat_result) -> bool:
    mode = stat.S_IMODE(item.st_mode)
    if not stat.S_ISDIR(item.st_mode) or item.st_uid not in {0, os.geteuid()}:
        return False
    if item.st_uid == os.geteuid():
        return not bool(mode & 0o022)
    return not mode & 0o022 or bool(mode & stat.S_ISVTX)


def _safe_private_parent(item: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(item.st_mode)
        and item.st_uid == os.geteuid()
        and not bool(stat.S_IMODE(item.st_mode) & 0o022)
    )


def _safe_private_file(item: os.stat_result) -> bool:
    return _private_file_access(item) and item.st_size <= MAX_INVENTORY_BYTES


def _private_file_access(item: os.stat_result) -> bool:
    return (
        stat.S_ISREG(item.st_mode)
        and item.st_uid == os.geteuid()
        and stat.S_IMODE(item.st_mode) == 0o600
        and item.st_nlink == 1
    )


def _read_private_inventory_bytes(path: Path) -> bytes:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
    ):
        _unavailable()
    parts = path.parts
    if (
        len(parts) < 2
        or any(part in {"", ".", ".."} for part in parts[1:])
        or not hasattr(os, "O_NOFOLLOW")
    ):
        _unavailable()

    directories: list[int] = []
    links: list[
        tuple[int, str, int, tuple[int, int, int, int, int, int, int, int, int]]
    ] = []
    file_descriptor: int | None = None
    try:
        try:
            root_before = os.lstat(path.anchor)
            root_descriptor = os.open(
                path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
        except OSError:
            _unavailable()
        directories.append(root_descriptor)
        root_opened = os.fstat(root_descriptor)
        if _identity(root_before) != _identity(root_opened) or not _safe_ancestor(
            root_opened
        ):
            _permissions()

        parent_descriptor = root_descriptor
        parent_parts = parts[1:-1]
        for position, component in enumerate(parent_parts):
            try:
                before = os.stat(
                    component, dir_fd=parent_descriptor, follow_symlinks=False
                )
                if stat.S_ISLNK(before.st_mode):
                    _permissions()
                child_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_descriptor,
                )
            except OSError:
                _unavailable()
            opened = os.fstat(child_descriptor)
            is_private_parent = position == len(parent_parts) - 1
            safe = (
                _safe_private_parent(opened)
                if is_private_parent
                else _safe_ancestor(opened)
            )
            if _identity(before) != _identity(opened) or not safe:
                os.close(child_descriptor)
                _permissions()
            directories.append(child_descriptor)
            links.append(
                (parent_descriptor, component, child_descriptor, _identity(opened))
            )
            parent_descriptor = child_descriptor

        try:
            file_before = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
        except OSError:
            _unavailable()
        if not _private_file_access(file_before):
            _permissions()
        if file_before.st_size > MAX_INVENTORY_BYTES:
            _unavailable()
        try:
            file_descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
        except OSError:
            _unavailable()
        file_opened = os.fstat(file_descriptor)
        if _identity(file_before) != _identity(file_opened) or not _safe_private_file(
            file_opened
        ):
            _unavailable()

        chunks: list[bytes] = []
        total = 0
        while total <= MAX_INVENTORY_BYTES:
            chunk = os.read(
                file_descriptor, min(64 * 1024, MAX_INVENTORY_BYTES + 1 - total)
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_INVENTORY_BYTES:
            _unavailable()

        file_after = os.fstat(file_descriptor)
        try:
            file_current = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
        except OSError:
            _unavailable()
        if (
            _identity(file_after) != _identity(file_opened)
            or _identity(file_current) != _identity(file_opened)
            or not _safe_private_file(file_after)
        ):
            _unavailable()
        for parent_fd, component, child_fd, expected in links:
            try:
                current = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                _unavailable()
            if (
                _identity(current) != expected
                or _identity(os.fstat(child_fd)) != expected
            ):
                _unavailable()
        if _identity(os.fstat(root_descriptor)) != _identity(root_opened):
            _unavailable()
        return b"".join(chunks)
    except GoogleAccountInventoryError:
        raise
    except OSError:
        _unavailable()
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for descriptor in reversed(directories):
            os.close(descriptor)


def _mapping(
    value: object, allowed: frozenset[str], required: frozenset[str]
) -> dict[str, object]:
    if (
        type(value) is not dict
        or not required.issubset(value)
        or not set(value).issubset(allowed)
    ):
        _schema_invalid()
    return value


def _list(value: object, maximum: int) -> list[object]:
    if type(value) is not list or len(value) > maximum:
        _schema_invalid()
    return value


def _required_string(value: object) -> str:
    if type(value) is not str or not value:
        _schema_invalid()
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _required_string(value)


def _external_id(value: object) -> str | None:
    return None if value is None else _required_string(value)


def _project_name(value: object) -> str | None:
    if value is None:
        return None
    name = _required_string(value)
    if _PROJECT_NAME.fullmatch(name) is None:
        _schema_invalid()
    return name


def _key_name(value: object) -> str | None:
    if value is None:
        return None
    name = _required_string(value)
    if _KEY_NAME.fullmatch(name) is None:
        _schema_invalid()
    return name


def _validate_private_auth(value: object) -> None:
    if value is None:
        return
    data = _mapping(value, _AUTH_FIELDS, frozenset())
    for key in ("access_token", "refresh_token", "client_fingerprint"):
        token = data.get(key)
        if token is not None:
            _required_string(token)
    cookies = data.get("cookies")
    if cookies is None:
        return
    for cookie in _list(cookies, 512):
        if type(cookie) is not dict or len(cookie) > 24:
            _schema_invalid()
        for key, item in cookie.items():
            if type(key) is not str or not key or type(item) not in {
                str,
                int,
                float,
                bool,
                type(None),
            }:
                _schema_invalid()


def _hive_slot(ref: str) -> int:
    match = _HIVE_REF.fullmatch(ref)
    if match is None or len(match.group(1)) > MAX_HIVE_SLOT_DIGITS:
        _schema_invalid()
    slot = int(match.group(1))
    if slot < 1:
        _schema_invalid()
    return slot


def _build_document(document: object) -> GoogleAccountInventoryDocumentV1:
    top = _mapping(
        document,
        frozenset({"schema_version", "google_accounts"}),
        frozenset({"schema_version", "google_accounts"}),
    )
    schema_version = top["schema_version"]
    if type(schema_version) is not _YamlIntegerLiteral:
        _schema_invalid()
    version = int(schema_version.value)
    accounts: list[GoogleAccountV1] = []
    seen_refs: set[str] = set()
    seen_login_emails: set[str] = set()
    seen_subject_ids: set[str] = set()
    seen_billing_ids: set[str] = set()
    seen_project_ids: set[str] = set()
    seen_project_numbers: set[str] = set()
    seen_key_ids: set[str] = set()
    seen_key_uids: set[str] = set()
    seen_slots: set[int] = set()
    project_secrets: dict[str, str] = {}

    for raw_account in _list(top["google_accounts"], MAX_INVENTORY_BYTES):
        data = _mapping(
            raw_account,
            _ACCOUNT_FIELDS_V2 if version == 2 else _ACCOUNT_FIELDS_V1,
            frozenset({"ref", "login_email", "billing_accounts", "projects"}),
        )
        account_ref = _required_string(data["ref"])
        login_email = _required_string(data["login_email"])
        subject_id = _external_id(data.get("subject_id"))
        if account_ref in seen_refs:
            _error("credential.account_duplicate")
        if login_email.casefold() in seen_login_emails:
            _error("credential.login_duplicate")
        if subject_id is not None and subject_id in seen_subject_ids:
            _error("credential.subject_duplicate")
        seen_refs.add(account_ref)
        seen_login_emails.add(login_email.casefold())
        if subject_id is not None:
            seen_subject_ids.add(subject_id)
        if version == 2:
            _validate_private_auth(data.get("auth"))

        billings: list[GoogleBillingAccountV1] = []
        billing_refs: set[str] = set()
        for raw_billing in _list(
            data["billing_accounts"], MAX_BILLING_ACCOUNTS_PER_ACCOUNT
        ):
            billing_data = _mapping(
                raw_billing, _BILLING_FIELDS, frozenset({"ref", "billing_account_id"})
            )
            billing_ref = _required_string(billing_data["ref"])
            billing_id = _external_id(billing_data["billing_account_id"])
            if billing_ref in seen_refs or (
                billing_id is not None and billing_id in seen_billing_ids
            ):
                _error("credential.billing_duplicate")
            seen_refs.add(billing_ref)
            billing_refs.add(billing_ref)
            if billing_id is not None:
                seen_billing_ids.add(billing_id)
            billings.append(
                GoogleBillingAccountV1(
                    billing_ref, billing_id, _optional_string(billing_data.get("label"))
                )
            )

        projects: list[GoogleProjectV1] = []
        for raw_project in _list(data["projects"], MAX_PROJECT_SLOTS_PER_ACCOUNT):
            project_fields = (
                _PROJECT_FIELDS_V2 if version == 2 else _PROJECT_FIELDS_V1
            )
            project_data = _mapping(raw_project, project_fields, project_fields)
            project_ref = _required_string(project_data["ref"])
            hive_slot = _hive_slot(project_ref)
            billing_ref = _optional_string(project_data["billing_account_ref"])
            purpose = (
                _required_string(project_data["purpose"])
                if version == 2
                else "hive"
            )
            if purpose not in _PROJECT_PURPOSES:
                _schema_invalid()
            status = _required_string(project_data["status"])
            if status not in _PROJECT_STATUSES:
                _schema_invalid()
            secret = project_data["secret"]
            if status == "active" and purpose == "hive":
                secret_value = _required_string(secret)
            elif secret is not None:
                _schema_invalid()
            else:
                secret_value = None
            if billing_ref is not None and billing_ref not in billing_refs:
                _error("credential.billing_reference_foreign")
            project_id = _external_id(project_data["project_id"])
            project_number = _external_id(project_data["project_number"])
            key_id = _external_id(project_data["key_id"])
            key_uid = _external_id(project_data["key_uid"])
            project_name = (
                _project_name(project_data["project_name"])
                if version == 2
                else None
            )
            key_name = _key_name(project_data["key_name"]) if version == 2 else None
            if version == 2 and project_id is not None and project_name is None:
                _schema_invalid()
            if (
                project_ref in seen_refs
                or hive_slot in seen_slots
                or (project_id is not None and project_id in seen_project_ids)
                or (
                    project_number is not None
                    and project_number in seen_project_numbers
                )
            ):
                _error("credential.project_duplicate")
            if (key_id is not None and key_id in seen_key_ids) or (
                key_uid is not None and key_uid in seen_key_uids
            ):
                _error("credential.key_duplicate")
            seen_refs.add(project_ref)
            seen_slots.add(hive_slot)
            if project_id is not None:
                seen_project_ids.add(project_id)
            if project_number is not None:
                seen_project_numbers.add(project_number)
            if key_id is not None:
                seen_key_ids.add(key_id)
            if key_uid is not None:
                seen_key_uids.add(key_uid)
            if secret_value is not None:
                project_secrets[project_ref] = secret_value
            projects.append(
                GoogleProjectV1(
                    project_ref,
                    hive_slot,
                    billing_ref,
                    status,
                    project_id,
                    project_number,
                    key_id,
                    key_uid,
                    project_name,
                    purpose,
                    key_name,
                )
            )

        accounts.append(
            GoogleAccountV1(
                account_ref,
                login_email,
                _optional_string(data.get("recovery_email")),
                _optional_string(data.get("label")),
                subject_id,
                tuple(sorted(billings, key=lambda item: item.ref)),
                tuple(sorted(projects, key=lambda item: item.ref)),
            )
        )

    ordered = tuple(sorted(accounts, key=lambda item: item.ref))
    result = GoogleAccountInventoryDocumentV1(
        schema_version=version,
        accounts=ordered,
        content_fingerprint=_redacted_fingerprint(ordered),
        by_ref=_frozen_index(
            (item.ref, item)
            for account in ordered
            for item in (account, *account.billing_accounts, *account.projects)
        ),
        by_subject_id=_frozen_index(
            (account.subject_id, account)
            for account in ordered
            if account.subject_id is not None
        ),
        by_billing_account_id=_frozen_index(
            (billing.billing_account_id, billing)
            for account in ordered
            for billing in account.billing_accounts
            if billing.billing_account_id is not None
        ),
        by_project_id=_frozen_index(
            (project.project_id, project)
            for account in ordered
            for project in account.projects
            if project.project_id is not None
        ),
        by_key_id=_frozen_index(
            (project.key_id, project)
            for account in ordered
            for project in account.projects
            if project.key_id is not None
        ),
        by_key_uid=_frozen_index(
            (project.key_uid, project)
            for account in ordered
            for project in account.projects
            if project.key_uid is not None
        ),
        by_hive_slot=_frozen_index(
            (project.hive_slot, project)
            for account in ordered
            for project in account.projects
        ),
    )
    _bind_document_secret_source(result, project_secrets)
    return result


def _frozen_index(values: Iterator[tuple[str | int, _T]]) -> _FrozenIndex[_T]:
    return _FrozenIndex(dict(sorted(values, key=lambda item: str(item[0]))))


def _redacted_fingerprint(accounts: tuple[GoogleAccountV1, ...]) -> str:
    payload = [
        {
            "ref": account.ref,
            "login_email": account.login_email,
            "recovery_email": account.recovery_email,
            "label": account.label,
            "subject_id": account.subject_id,
            "billing_accounts": [
                {
                    "ref": billing.ref,
                    "billing_account_id": billing.billing_account_id,
                    "label": billing.label,
                }
                for billing in account.billing_accounts
            ],
            "projects": [
                {
                    "ref": project.ref,
                    "billing_account_ref": project.billing_account_ref,
                    "status": project.status,
                    "project_id": project.project_id,
                    "project_number": project.project_number,
                    "key_id": project.key_id,
                    "key_uid": project.key_uid,
                    "project_name": project.project_name,
                    "purpose": project.purpose,
                    "key_name": project.key_name,
                    "secret": None,
                }
                for project in account.projects
            ],
        }
        for account in accounts
    ]
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()
