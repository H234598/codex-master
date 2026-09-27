"""Synthetic D344 S1 contract tests for the private D73 ingress policy parser."""

from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
import json
import stat
from types import SimpleNamespace

import pytest

from the_hive import _d73_ingress_policy as ingress_policy


_SYNTHETIC_POLICY = {
    "account_name": "synthetic-control",
    "bus_name": "org.example.Control1",
    "expected_uid": 4242,
    "polkit_action": "org.example.d73.publish",
    "schema_version": 1,
    "selinux_context": "synthetic_u:synthetic_r:synthetic_t:s0",
}

# Hand-checked v1 oracle: these are synthetic test values, not host policy values.
_GOLDEN_BYTES = (
    b'{"account_name":"synthetic-control","bus_name":"org.example.Control1",'
    b'"expected_uid":4242,"polkit_action":"org.example.d73.publish",'
    b'"schema_version":1,"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n'
)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _with(**changes: object) -> bytes:
    value = dict(_SYNTHETIC_POLICY)
    value.update(changes)
    return _canonical(value)


def _without(field: str) -> bytes:
    value = dict(_SYNTHETIC_POLICY)
    del value[field]
    return _canonical(value)


def _error_code(raw: bytes) -> str:
    with pytest.raises(ingress_policy.D73IngressPolicyError) as caught:
        ingress_policy._decode_d73_ingress_policy_v1(raw)
    return caught.value.code


def test_decode_accepts_the_hand_checked_canonical_golden_bytes() -> None:
    policy = ingress_policy._decode_d73_ingress_policy_v1(_GOLDEN_BYTES)

    assert type(policy) is ingress_policy.D73IngressPolicyV1
    assert policy.account_name == "synthetic-control"
    assert policy.bus_name == "org.example.Control1"
    assert policy.expected_uid == 4242
    assert policy.polkit_action == "org.example.d73.publish"
    assert policy.schema_version == 1
    assert policy.selinux_context == "synthetic_u:synthetic_r:synthetic_t:s0"


def test_decode_returns_an_immutable_value() -> None:
    policy = ingress_policy._decode_d73_ingress_policy_v1(_GOLDEN_BYTES)

    with pytest.raises(FrozenInstanceError):
        policy.expected_uid = 7  # type: ignore[misc]


@pytest.mark.parametrize("expected_uid", (1, 4_294_967_295))
def test_decode_accepts_each_expected_uid_endpoint(expected_uid: int) -> None:
    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(expected_uid=expected_uid)
    )

    assert policy.expected_uid == expected_uid


def test_decode_accepts_a_255_byte_account_name() -> None:
    account_name = "a" * 255

    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(account_name=account_name)
    )

    assert policy.account_name == account_name


def test_decode_accepts_a_255_byte_bus_name() -> None:
    bus_name = "b" * 255

    policy = ingress_policy._decode_d73_ingress_policy_v1(_with(bus_name=bus_name))

    assert policy.bus_name == bus_name


def test_decode_accepts_a_255_byte_polkit_action() -> None:
    polkit_action = "p" * 255

    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(polkit_action=polkit_action)
    )

    assert policy.polkit_action == polkit_action


def test_decode_accepts_a_4096_byte_selinux_context() -> None:
    selinux_context = "s" * 4096

    policy = ingress_policy._decode_d73_ingress_policy_v1(
        _with(selinux_context=selinux_context)
    )

    assert policy.selinux_context == selinux_context


@pytest.mark.parametrize(
    ("name", "raw", "code"),
    (
        ("missing-final-lf", _GOLDEN_BYTES[:-1], "D73_POLICY_E_TERMINATOR"),
        ("second-final-lf", _GOLDEN_BYTES + b"\n", "D73_POLICY_E_TERMINATOR"),
        ("bom", b"\xef\xbb\xbf" + _GOLDEN_BYTES, "D73_POLICY_E_ASCII"),
        (
            "nul",
            _GOLDEN_BYTES.replace(b"control", b"con\x00trol"),
            "D73_POLICY_E_ASCII",
        ),
        ("crlf", _GOLDEN_BYTES[:-1] + b"\r\n", "D73_POLICY_E_ASCII"),
        ("whitespace", b" " + _GOLDEN_BYTES, "D73_POLICY_E_ASCII"),
    ),
)
def test_decode_rejects_non_v1_raw_byte_framing(
    name: str, raw: bytes, code: str
) -> None:
    del name
    assert _error_code(raw) == code


@pytest.mark.parametrize(
    ("name", "raw", "code"),
    (
        ("malformed-json", b'{"account_name":}\n', "D73_POLICY_E_JSON"),
        (
            "duplicate",
            b'{"account_name":"synthetic-control","account_name":"other",'
            b'"bus_name":"org.example.Control1","expected_uid":4242,'
            b'"polkit_action":"org.example.d73.publish","schema_version":1,'
            b'"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n',
            "D73_POLICY_E_DUPLICATE",
        ),
        ("second-json-value", _GOLDEN_BYTES[:-1] + b"{}\n", "D73_POLICY_E_TRAILING"),
        ("top-level-array", b"[]\n", "D73_POLICY_E_TOPLEVEL"),
    ),
)
def test_decode_rejects_invalid_json_shapes_before_field_values(
    name: str, raw: bytes, code: str
) -> None:
    del name
    assert _error_code(raw) == code


def test_decode_checks_unknown_fields_before_missing_fields() -> None:
    assert _error_code(_canonical({"unknown": "x"})) == "D73_POLICY_E_UNKNOWN_FIELD"


@pytest.mark.parametrize(
    "field",
    (
        "account_name",
        "bus_name",
        "expected_uid",
        "polkit_action",
        "schema_version",
        "selinux_context",
    ),
)
def test_decode_rejects_each_missing_field(field: str) -> None:
    assert _error_code(_without(field)) == "D73_POLICY_E_MISSING_FIELD"


@pytest.mark.parametrize(
    ("raw", "code"),
    (
        (_with(schema_version=2), "D73_POLICY_E_VERSION"),
        (_with(schema_version=True), "D73_POLICY_E_VERSION"),
        (_with(expected_uid=0), "D73_POLICY_E_UID"),
        (_with(expected_uid=4_294_967_296), "D73_POLICY_E_UID"),
        (_with(expected_uid=True), "D73_POLICY_E_UID"),
    ),
)
def test_decode_enforces_version_and_uid_integer_contracts(
    raw: bytes, code: str
) -> None:
    assert _error_code(raw) == code


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("account_name", 7, "D73_POLICY_E_ACCOUNT"),
        ("account_name", "", "D73_POLICY_E_ACCOUNT"),
        ("account_name", "x" * 256, "D73_POLICY_E_ACCOUNT"),
        ("account_name", "bad\nvalue", "D73_POLICY_E_ACCOUNT"),
        ("bus_name", 7, "D73_POLICY_E_BUS"),
        ("bus_name", "", "D73_POLICY_E_BUS"),
        ("bus_name", "x" * 256, "D73_POLICY_E_BUS"),
        ("bus_name", "bad\nvalue", "D73_POLICY_E_BUS"),
        ("polkit_action", 7, "D73_POLICY_E_POLKIT"),
        ("polkit_action", "", "D73_POLICY_E_POLKIT"),
        ("polkit_action", "x" * 256, "D73_POLICY_E_POLKIT"),
        ("polkit_action", "bad\nvalue", "D73_POLICY_E_POLKIT"),
        ("selinux_context", 7, "D73_POLICY_E_SELINUX"),
        ("selinux_context", "", "D73_POLICY_E_SELINUX"),
        ("selinux_context", "x" * 4097, "D73_POLICY_E_SELINUX"),
        ("selinux_context", "bad\nvalue", "D73_POLICY_E_SELINUX"),
    ),
)
def test_decode_enforces_each_string_field_type_and_bound(
    field: str, value: object, code: str
) -> None:
    assert _error_code(_with(**{field: value})) == code


@pytest.mark.parametrize(
    "raw",
    (
        b'{"account_name":"\\u0073ynthetic-control",'
        b'"bus_name":"org.example.Control1","expected_uid":4242,'
        b'"polkit_action":"org.example.d73.publish","schema_version":1,'
        b'"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n',
        b'{"schema_version":1,"account_name":"synthetic-control",'
        b'"bus_name":"org.example.Control1","expected_uid":4242,'
        b'"polkit_action":"org.example.d73.publish",'
        b'"selinux_context":"synthetic_u:synthetic_r:synthetic_t:s0"}\n',
    ),
)
def test_decode_rejects_bytes_that_parse_but_are_not_canonical(raw: bytes) -> None:
    assert _error_code(raw) == "D73_POLICY_E_CANONICAL"


_ROOT_FD = 101
_POLICY_DIRECTORY_FD = 102
_POLICY_FILE_FD = 103
_DIRECTORY_FLAGS = 0x01 | 0x02 | 0x04 | 0x08
_FILE_FLAGS = 0x01 | 0x04 | 0x08


def _synthetic_stat(
    mode: int,
    *,
    nlink: int = 1,
    uid: int = 0,
    gid: int = 0,
    dev: int = 17,
    ino: int = 23,
    size: int = len(_GOLDEN_BYTES),
) -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=mode,
        st_nlink=nlink,
        st_uid=uid,
        st_gid=gid,
        st_dev=dev,
        st_ino=ino,
        st_size=size,
    )


def _trusted_root() -> SimpleNamespace:
    return _synthetic_stat(stat.S_IFDIR | 0o755, nlink=3)


def _trusted_policy_directory() -> SimpleNamespace:
    return _synthetic_stat(stat.S_IFDIR | 0o755, nlink=2)


def _trusted_policy_file(*, size: int = len(_GOLDEN_BYTES)) -> SimpleNamespace:
    return _synthetic_stat(stat.S_IFREG | 0o644, size=size)


class _FakePolicyOs:
    O_RDONLY = 0x01
    O_DIRECTORY = 0x02
    O_CLOEXEC = 0x04
    O_NOFOLLOW = 0x08

    def __init__(
        self,
        *,
        stats: list[SimpleNamespace | BaseException] | None = None,
        pread_results: list[bytes | BaseException] | None = None,
        open_errors: dict[int, OSError] | None = None,
        close_errors: set[int] | None = None,
    ) -> None:
        policy_file = _trusted_policy_file()
        self._stats = list(
            stats
            or [
                _trusted_root(),
                _trusted_policy_directory(),
                policy_file,
                policy_file,
                policy_file,
            ]
        )
        self._pread_results = list(pread_results or [_GOLDEN_BYTES, _GOLDEN_BYTES])
        self._open_errors = open_errors or {}
        self._close_errors = close_errors or set()
        self._fds = (_ROOT_FD, _POLICY_DIRECTORY_FD, _POLICY_FILE_FD)
        self.open_calls: list[tuple[str, int, int | None]] = []
        self.fstat_calls: list[int] = []
        self.pread_calls: list[tuple[int, int, int]] = []
        self.close_calls: list[int] = []
        self.events: list[tuple[object, ...]] = []

    def open(self, path: str, flags: int, *, dir_fd: int | None = None) -> int:
        self.open_calls.append((path, flags, dir_fd))
        self.events.append(("open", path, flags, dir_fd))
        ordinal = len(self.open_calls)
        if ordinal in self._open_errors:
            raise self._open_errors[ordinal]
        return self._fds[ordinal - 1]

    def fstat(self, fd: int) -> SimpleNamespace:
        self.fstat_calls.append(fd)
        self.events.append(("fstat", fd))
        result = self._stats.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def pread(self, fd: int, size: int, offset: int) -> bytes:
        self.pread_calls.append((fd, size, offset))
        self.events.append(("pread", fd, size, offset))
        result = self._pread_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def close(self, fd: int) -> None:
        self.close_calls.append(fd)
        self.events.append(("close", fd))
        if fd in self._close_errors:
            raise OSError("synthetic close failure")


def _install_fake_os(monkeypatch: pytest.MonkeyPatch, fake_os: object) -> None:
    monkeypatch.setattr(ingress_policy, "os", fake_os, raising=False)


def _loader_error_code() -> str:
    with pytest.raises(ingress_policy.D73IngressPolicyError) as caught:
        ingress_policy._load_d73_ingress_policy_v1()
    return caught.value.code


def test_loader_uses_only_the_fixed_no_follow_descriptor_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_os = _FakePolicyOs()
    _install_fake_os(monkeypatch, fake_os)

    policy = ingress_policy._load_d73_ingress_policy_v1()

    assert policy == ingress_policy._decode_d73_ingress_policy_v1(_GOLDEN_BYTES)
    assert fake_os.events == [
        ("open", "/etc", _DIRECTORY_FLAGS, None),
        ("fstat", _ROOT_FD),
        ("open", "the-hive", _DIRECTORY_FLAGS, _ROOT_FD),
        ("fstat", _POLICY_DIRECTORY_FD),
        (
            "open",
            "d73-ingress-policy-v1.json",
            _FILE_FLAGS,
            _POLICY_DIRECTORY_FD,
        ),
        ("fstat", _POLICY_FILE_FD),
        ("pread", _POLICY_FILE_FD, len(_GOLDEN_BYTES), 0),
        ("fstat", _POLICY_FILE_FD),
        ("pread", _POLICY_FILE_FD, len(_GOLDEN_BYTES), 0),
        ("fstat", _POLICY_FILE_FD),
        ("close", _POLICY_FILE_FD),
        ("close", _POLICY_DIRECTORY_FD),
        ("close", _ROOT_FD),
    ]


def test_loader_forwards_only_the_first_attested_read_to_the_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_os = _FakePolicyOs()
    _install_fake_os(monkeypatch, fake_os)
    expected = object()
    received: list[bytes] = []

    def fake_decoder(raw: bytes) -> object:
        received.append(raw)
        return expected

    monkeypatch.setattr(ingress_policy, "_decode_d73_ingress_policy_v1", fake_decoder)

    assert ingress_policy._load_d73_ingress_policy_v1() is expected
    assert received == [_GOLDEN_BYTES]


def test_loader_rejects_an_platform_without_no_follow_before_opening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_open_calls: list[object] = []
    _install_fake_os(
        monkeypatch,
        SimpleNamespace(
            O_RDONLY=0x01,
            O_DIRECTORY=0x02,
            O_CLOEXEC=0x04,
            open=lambda *args, **kwargs: fake_open_calls.append((args, kwargs)),
        ),
    )

    assert _loader_error_code() == "D73_POLICY_E_NO_NOFOLLOW"
    assert fake_open_calls == []


@pytest.mark.parametrize(
    ("open_ordinal", "code", "expected_closed"),
    (
        (1, "D73_POLICY_E_OPEN_ROOT", []),
        (2, "D73_POLICY_E_OPEN_DIR", [_ROOT_FD]),
        (3, "D73_POLICY_E_OPEN_FILE", [_POLICY_DIRECTORY_FD, _ROOT_FD]),
    ),
)
def test_loader_rejects_each_no_follow_open_failure_and_closes_prior_fds(
    monkeypatch: pytest.MonkeyPatch,
    open_ordinal: int,
    code: str,
    expected_closed: list[int],
) -> None:
    fake_os = _FakePolicyOs(open_errors={open_ordinal: OSError("synthetic symlink")})
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == code
    assert fake_os.close_calls == expected_closed


@pytest.mark.parametrize(
    ("stats", "code", "expected_closed"),
    (
        ([OSError("root stat")], "D73_POLICY_E_DIR_STAT", [_ROOT_FD]),
        (
            [_trusted_root(), OSError("directory stat")],
            "D73_POLICY_E_DIR_STAT",
            [_POLICY_DIRECTORY_FD, _ROOT_FD],
        ),
    ),
)
def test_loader_rejects_each_directory_stat_failure(
    monkeypatch: pytest.MonkeyPatch,
    stats: list[SimpleNamespace | BaseException],
    code: str,
    expected_closed: list[int],
) -> None:
    fake_os = _FakePolicyOs(stats=stats)
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == code
    assert fake_os.close_calls == expected_closed


@pytest.mark.parametrize(
    "root_stat",
    (
        _synthetic_stat(stat.S_IFREG | 0o644),
        _synthetic_stat(stat.S_IFDIR | 0o755, uid=1),
        _synthetic_stat(stat.S_IFDIR | 0o775),
        _synthetic_stat(stat.S_IFDIR | 0o757),
    ),
)
def test_loader_rejects_each_untrusted_root_property(
    monkeypatch: pytest.MonkeyPatch, root_stat: SimpleNamespace
) -> None:
    fake_os = _FakePolicyOs(stats=[root_stat])
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_DIR_TRUST"
    assert fake_os.close_calls == [_ROOT_FD]


@pytest.mark.parametrize(
    "directory_stat",
    (
        _synthetic_stat(stat.S_IFREG | 0o755, nlink=2),
        _synthetic_stat(stat.S_IFLNK | 0o755, nlink=2),
        _synthetic_stat(stat.S_IFDIR | 0o755, nlink=2, uid=1),
        _synthetic_stat(stat.S_IFDIR | 0o755, nlink=2, gid=1),
        _synthetic_stat(stat.S_IFDIR | 0o700, nlink=2),
        _synthetic_stat(stat.S_IFDIR | 0o755, nlink=1),
    ),
)
def test_loader_rejects_each_untrusted_policy_directory_property(
    monkeypatch: pytest.MonkeyPatch, directory_stat: SimpleNamespace
) -> None:
    fake_os = _FakePolicyOs(stats=[_trusted_root(), directory_stat])
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_DIR_TRUST"
    assert fake_os.close_calls == [_POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize(
    "file_stat",
    (
        _synthetic_stat(stat.S_IFDIR | 0o644),
        _synthetic_stat(stat.S_IFLNK | 0o644),
    ),
)
def test_loader_rejects_each_non_regular_policy_file_type(
    monkeypatch: pytest.MonkeyPatch, file_stat: SimpleNamespace
) -> None:
    fake_os = _FakePolicyOs(
        stats=[_trusted_root(), _trusted_policy_directory(), file_stat]
    )
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_FILE_TYPE"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize(
    ("file_stat", "code"),
    (
        (_synthetic_stat(stat.S_IFREG | 0o644, uid=1), "D73_POLICY_E_FILE_OWNER"),
        (_synthetic_stat(stat.S_IFREG | 0o644, gid=1), "D73_POLICY_E_FILE_GROUP"),
        (_synthetic_stat(stat.S_IFREG | 0o600), "D73_POLICY_E_FILE_MODE"),
        (_synthetic_stat(stat.S_IFREG | 0o644, nlink=2), "D73_POLICY_E_FILE_NLINK"),
    ),
)
def test_loader_rejects_each_untrusted_policy_file_property(
    monkeypatch: pytest.MonkeyPatch, file_stat: SimpleNamespace, code: str
) -> None:
    fake_os = _FakePolicyOs(
        stats=[_trusted_root(), _trusted_policy_directory(), file_stat]
    )
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == code
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize("size", (0, 8193))
def test_loader_rejects_policy_file_size_outside_the_inclusive_range(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    fake_os = _FakePolicyOs(
        stats=[
            _trusted_root(),
            _trusted_policy_directory(),
            _trusted_policy_file(size=size),
        ]
    )
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_FILE_SIZE"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize("size", (1, 8192))
def test_loader_accepts_each_inclusive_policy_file_size_endpoint(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    raw = b"x" * size
    policy = object()
    fake_os = _FakePolicyOs(
        stats=[
            _trusted_root(),
            _trusted_policy_directory(),
            _trusted_policy_file(size=size),
            _trusted_policy_file(size=size),
            _trusted_policy_file(size=size),
        ],
        pread_results=[raw, raw],
    )
    _install_fake_os(monkeypatch, fake_os)
    monkeypatch.setattr(
        ingress_policy, "_decode_d73_ingress_policy_v1", lambda raw: policy
    )

    assert ingress_policy._load_d73_ingress_policy_v1() is policy
    assert fake_os.pread_calls == [
        (_POLICY_FILE_FD, size, 0),
        (_POLICY_FILE_FD, size, 0),
    ]


@pytest.mark.parametrize("fstat_ordinal", (3, 4, 5))
def test_loader_rejects_each_policy_file_stat_failure(
    monkeypatch: pytest.MonkeyPatch, fstat_ordinal: int
) -> None:
    stats: list[SimpleNamespace | BaseException] = [
        _trusted_root(),
        _trusted_policy_directory(),
        _trusted_policy_file(),
        _trusted_policy_file(),
        _trusted_policy_file(),
    ]
    stats[fstat_ordinal - 1] = OSError("file stat")
    fake_os = _FakePolicyOs(stats=stats)
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_FILE_STAT"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize(
    "pread_results",
    (
        [OSError("first read"), _GOLDEN_BYTES],
        [_GOLDEN_BYTES, OSError("second read")],
    ),
)
def test_loader_rejects_each_pread_os_error(
    monkeypatch: pytest.MonkeyPatch, pread_results: list[bytes | BaseException]
) -> None:
    fake_os = _FakePolicyOs(pread_results=pread_results)
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_READ"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize(
    "pread_results",
    (
        [_GOLDEN_BYTES[:-1], _GOLDEN_BYTES],
        [_GOLDEN_BYTES, _GOLDEN_BYTES[:-1]],
    ),
)
def test_loader_rejects_each_short_pread(
    monkeypatch: pytest.MonkeyPatch, pread_results: list[bytes | BaseException]
) -> None:
    fake_os = _FakePolicyOs(pread_results=pread_results)
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_SHORT_READ"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize(
    ("changed_snapshot", "changed_value"),
    (
        (1, {"dev": 18}),
        (2, {"ino": 24}),
    ),
)
def test_loader_rejects_each_post_read_descriptor_snapshot_drift(
    monkeypatch: pytest.MonkeyPatch,
    changed_snapshot: int,
    changed_value: dict[str, int],
) -> None:
    snapshots = [_trusted_policy_file(), _trusted_policy_file(), _trusted_policy_file()]
    snapshots[changed_snapshot] = _synthetic_stat(
        stat.S_IFREG | 0o644, **changed_value
    )
    fake_os = _FakePolicyOs(
        stats=[_trusted_root(), _trusted_policy_directory(), *snapshots]
    )
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_DESCRIPTOR_DRIFT"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


def test_loader_rejects_different_complete_readback_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    changed = _GOLDEN_BYTES.replace(b"4242", b"4243")
    fake_os = _FakePolicyOs(pread_results=[_GOLDEN_BYTES, changed])
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_READBACK_DRIFT"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


@pytest.mark.parametrize("failed_fd", (_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD))
def test_loader_reports_close_failure_after_closing_every_open_fd(
    monkeypatch: pytest.MonkeyPatch, failed_fd: int
) -> None:
    fake_os = _FakePolicyOs(close_errors={failed_fd})
    _install_fake_os(monkeypatch, fake_os)

    assert _loader_error_code() == "D73_POLICY_E_CLOSE"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


def test_loader_closes_each_open_fd_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_os = _FakePolicyOs(
        pread_results=[asyncio.CancelledError(), _GOLDEN_BYTES]
    )
    _install_fake_os(monkeypatch, fake_os)

    with pytest.raises(asyncio.CancelledError):
        ingress_policy._load_d73_ingress_policy_v1()
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]


def test_loader_closes_each_open_fd_when_the_existing_decoder_rejects_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_os = _FakePolicyOs()
    _install_fake_os(monkeypatch, fake_os)

    def reject_decoder(raw: bytes) -> object:
        del raw
        raise ingress_policy.D73IngressPolicyError("D73_POLICY_E_TEST_DECODER")

    monkeypatch.setattr(ingress_policy, "_decode_d73_ingress_policy_v1", reject_decoder)

    assert _loader_error_code() == "D73_POLICY_E_TEST_DECODER"
    assert fake_os.close_calls == [_POLICY_FILE_FD, _POLICY_DIRECTORY_FD, _ROOT_FD]
