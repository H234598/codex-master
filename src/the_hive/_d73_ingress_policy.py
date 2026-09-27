"""Private, pure D344 S1 decoder for canonical D73 ingress-policy-v1 bytes."""

from __future__ import annotations

from dataclasses import dataclass
import json


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
