"""Private, pure D344 S1 decoder for canonical D73 ingress-policy-v1 bytes."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import stat


_EXPECTED_FIELDS = frozenset(
    (
        "account_name",
        "bus_name",
        "expected_uid",
        "polkit_action",
        "schema_version",
        "selinux_context",
    )
)


class D73IngressPolicyError(ValueError):
    """Fail-closed D344 S1 policy rejection with a stable error code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class D73IngressPolicyV1:
    """The complete, immutable in-memory value of canonical policy-v1 bytes."""

    account_name: str
    bus_name: str
    expected_uid: int
    polkit_action: str
    schema_version: int
    selinux_context: str


def _decode_d73_ingress_policy_v1(raw: bytes) -> D73IngressPolicyV1:
    """Decode exactly one canonical D73 ingress-policy-v1 byte sequence."""
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise D73IngressPolicyError("D73_POLICY_E_TERMINATOR")

    body = raw[:-1]
    if any(byte < 0x21 or byte > 0x7E for byte in body):
        raise D73IngressPolicyError("D73_POLICY_E_ASCII")

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for key, value in pairs:
            if key in decoded:
                raise D73IngressPolicyError("D73_POLICY_E_DUPLICATE")
            decoded[key] = value
        return decoded

    try:
        parsed, end = json.JSONDecoder(object_pairs_hook=reject_duplicate).raw_decode(
            body.decode("ascii")
        )
    except D73IngressPolicyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise D73IngressPolicyError("D73_POLICY_E_JSON") from None

    if end != len(body):
        raise D73IngressPolicyError("D73_POLICY_E_TRAILING")
    if type(parsed) is not dict:
        raise D73IngressPolicyError("D73_POLICY_E_TOPLEVEL")

    keys = frozenset(parsed)
    if keys - _EXPECTED_FIELDS:
        raise D73IngressPolicyError("D73_POLICY_E_UNKNOWN_FIELD")
    if _EXPECTED_FIELDS - keys:
        raise D73IngressPolicyError("D73_POLICY_E_MISSING_FIELD")

    schema_version = parsed["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise D73IngressPolicyError("D73_POLICY_E_VERSION")

    account_name = parsed["account_name"]
    if (
        type(account_name) is not str
        or not 1 <= len(account_name) <= 255
        or any(not 0x21 <= ord(character) <= 0x7E for character in account_name)
    ):
        raise D73IngressPolicyError("D73_POLICY_E_ACCOUNT")

    expected_uid = parsed["expected_uid"]
    if type(expected_uid) is not int or not 1 <= expected_uid <= 4_294_967_295:
        raise D73IngressPolicyError("D73_POLICY_E_UID")

    bus_name = parsed["bus_name"]
    if (
        type(bus_name) is not str
        or not 1 <= len(bus_name) <= 255
        or any(not 0x21 <= ord(character) <= 0x7E for character in bus_name)
    ):
        raise D73IngressPolicyError("D73_POLICY_E_BUS")

    selinux_context = parsed["selinux_context"]
    if (
        type(selinux_context) is not str
        or not 1 <= len(selinux_context) <= 4096
        or any(not 0x21 <= ord(character) <= 0x7E for character in selinux_context)
    ):
        raise D73IngressPolicyError("D73_POLICY_E_SELINUX")

    polkit_action = parsed["polkit_action"]
    if (
        type(polkit_action) is not str
        or not 1 <= len(polkit_action) <= 255
        or any(not 0x21 <= ord(character) <= 0x7E for character in polkit_action)
    ):
        raise D73IngressPolicyError("D73_POLICY_E_POLKIT")

    policy = D73IngressPolicyV1(
        account_name=account_name,
        bus_name=bus_name,
        expected_uid=expected_uid,
        polkit_action=polkit_action,
        schema_version=schema_version,
        selinux_context=selinux_context,
    )
    canonical = (
        json.dumps(
            {
                "account_name": policy.account_name,
                "bus_name": policy.bus_name,
                "expected_uid": policy.expected_uid,
                "polkit_action": policy.polkit_action,
                "schema_version": policy.schema_version,
                "selinux_context": policy.selinux_context,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )
    if raw != canonical:
        raise D73IngressPolicyError("D73_POLICY_E_CANONICAL")
    return policy


def _load_d73_ingress_policy_v1() -> D73IngressPolicyV1:
    """Load one stable D73 policy-v1 value from its fixed trusted descriptor."""
    try:
        no_follow = os.O_NOFOLLOW
    except AttributeError:
        raise D73IngressPolicyError("D73_POLICY_E_NO_NOFOLLOW") from None

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | no_follow
    file_flags = os.O_RDONLY | os.O_CLOEXEC | no_follow
    root_fd: int | None = None
    policy_directory_fd: int | None = None
    policy_file_fd: int | None = None

    try:
        try:
            root_fd = os.open("/etc", directory_flags)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_OPEN_ROOT") from None

        try:
            root_stat = os.fstat(root_fd)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_DIR_STAT") from None
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != 0
            or root_stat.st_mode & 0o022
        ):
            raise D73IngressPolicyError("D73_POLICY_E_DIR_TRUST")

        try:
            policy_directory_fd = os.open(
                "the-hive", directory_flags, dir_fd=root_fd
            )
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_OPEN_DIR") from None

        try:
            policy_directory_stat = os.fstat(policy_directory_fd)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_DIR_STAT") from None
        if (
            not stat.S_ISDIR(policy_directory_stat.st_mode)
            or policy_directory_stat.st_uid != 0
            or policy_directory_stat.st_gid != 0
            or stat.S_IMODE(policy_directory_stat.st_mode) != 0o755
            or policy_directory_stat.st_nlink < 2
        ):
            raise D73IngressPolicyError("D73_POLICY_E_DIR_TRUST")

        try:
            policy_file_fd = os.open(
                "d73-ingress-policy-v1.json", file_flags, dir_fd=policy_directory_fd
            )
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_OPEN_FILE") from None

        try:
            policy_file_stat = os.fstat(policy_file_fd)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_STAT") from None
        if not stat.S_ISREG(policy_file_stat.st_mode):
            raise D73IngressPolicyError("D73_POLICY_E_FILE_TYPE")
        if policy_file_stat.st_uid != 0:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_OWNER")
        if policy_file_stat.st_gid != 0:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_GROUP")
        if stat.S_IMODE(policy_file_stat.st_mode) != 0o644:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_MODE")
        if policy_file_stat.st_nlink != 1:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_NLINK")
        if not 1 <= policy_file_stat.st_size <= 8192:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_SIZE")

        snapshot0 = (
            stat.S_IFMT(policy_file_stat.st_mode),
            stat.S_IMODE(policy_file_stat.st_mode),
            policy_file_stat.st_nlink,
            policy_file_stat.st_uid,
            policy_file_stat.st_gid,
            policy_file_stat.st_dev,
            policy_file_stat.st_ino,
            policy_file_stat.st_size,
        )
        try:
            first_read = os.pread(policy_file_fd, snapshot0[7], 0)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_READ") from None
        if len(first_read) != snapshot0[7]:
            raise D73IngressPolicyError("D73_POLICY_E_SHORT_READ")

        try:
            first_read_stat = os.fstat(policy_file_fd)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_STAT") from None
        snapshot1 = (
            stat.S_IFMT(first_read_stat.st_mode),
            stat.S_IMODE(first_read_stat.st_mode),
            first_read_stat.st_nlink,
            first_read_stat.st_uid,
            first_read_stat.st_gid,
            first_read_stat.st_dev,
            first_read_stat.st_ino,
            first_read_stat.st_size,
        )
        if snapshot1 != snapshot0:
            raise D73IngressPolicyError("D73_POLICY_E_DESCRIPTOR_DRIFT")

        try:
            second_read = os.pread(policy_file_fd, snapshot0[7], 0)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_READ") from None
        if len(second_read) != snapshot0[7]:
            raise D73IngressPolicyError("D73_POLICY_E_SHORT_READ")

        try:
            second_read_stat = os.fstat(policy_file_fd)
        except OSError:
            raise D73IngressPolicyError("D73_POLICY_E_FILE_STAT") from None
        snapshot2 = (
            stat.S_IFMT(second_read_stat.st_mode),
            stat.S_IMODE(second_read_stat.st_mode),
            second_read_stat.st_nlink,
            second_read_stat.st_uid,
            second_read_stat.st_gid,
            second_read_stat.st_dev,
            second_read_stat.st_ino,
            second_read_stat.st_size,
        )
        if snapshot2 != snapshot0:
            raise D73IngressPolicyError("D73_POLICY_E_DESCRIPTOR_DRIFT")
        if second_read != first_read:
            raise D73IngressPolicyError("D73_POLICY_E_READBACK_DRIFT")
        return _decode_d73_ingress_policy_v1(first_read)
    finally:
        close_failed = False
        for fd in (policy_file_fd, policy_directory_fd, root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    close_failed = True
        if close_failed:
            raise D73IngressPolicyError("D73_POLICY_E_CLOSE") from None
