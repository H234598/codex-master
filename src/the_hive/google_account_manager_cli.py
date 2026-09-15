"""Closed CLI adapter for the read-only Google inventory authority."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import sys
from typing import Final

from .google_inventory_readonly_control_service import (
    GoogleInventoryReadonlyControlService,
)


_REQUEST_INVALID: Final[str] = "inventory.readonly_control_request_invalid"
_UNAVAILABLE: Final[str] = "inventory.readonly_control_unavailable"
_SAFE_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "oauth.interactive_authorization_required",
        _REQUEST_INVALID,
        _UNAVAILABLE,
        "inventory.readonly_control_plan_invalid",
        "inventory.readonly_control_plan_expired",
        "inventory.readonly_control_plan_consumed",
        "inventory.readonly_control_plan_stale",
        "inventory.readonly_control_apply_failed",
        "inventory.readonly_control_reload_failed",
        "inventory.readonly_control_recovery_failed",
    }
)
_SCAN_RESULT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "status",
        "plan_reference",
        "account_count",
        "project_count",
        "billing_account_count",
        "service_count",
        "key_count",
        "changes",
    }
)
_SCAN_CHANGE_KINDS: Final[frozenset[str]] = frozenset({"canonical_account"})
_MAX_PLAN_REFERENCE_BYTES: Final[int] = 192


class _CliFailure(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ParseFailure(SystemExit):
    __slots__ = ()
    code: Final[str] = _REQUEST_INVALID

    def __init__(self) -> None:
        super().__init__(2)


class _ClosedArgumentParser(argparse.ArgumentParser):
    """Parser that never reflects invalid caller input to stderr."""

    def error(self, message: str) -> None:
        del message
        raise _ParseFailure()

    def parse_args(
        self,
        args: Sequence[str] | None = None,
        namespace: argparse.Namespace | None = None,
    ) -> argparse.Namespace:
        parsed = super().parse_args(args, namespace)
        if self.prog == "google-account-manager" and not _valid_arguments(parsed):
            self.error("")
        return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = _ClosedArgumentParser(prog="google-account-manager", add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory", add_help=False)
    inventory.add_argument("inventory_action", choices=("authorize", "scan"), nargs="?")
    inventory.add_argument("--plan", action="store_true")
    inventory.add_argument("--apply", dest="plan_reference")
    return parser


def _is_plan_reference(value: object) -> bool:
    if type(value) is not str or not value.startswith("plan-"):
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeError:
        return False
    return (
        len(encoded) <= _MAX_PLAN_REFERENCE_BYTES
        and len(encoded) > len("plan-")
        and all(character.isalnum() or character in "-_" for character in value)
    )


def _valid_arguments(arguments: argparse.Namespace) -> bool:
    if getattr(arguments, "command", None) != "inventory":
        return False
    action = getattr(arguments, "inventory_action", None)
    plan = getattr(arguments, "plan", None)
    reference = getattr(arguments, "plan_reference", None)
    return (
        (action == "authorize" and plan is False and reference is None)
        or (action == "scan" and plan is True and reference is None)
        or (action is None and plan is False and _is_plan_reference(reference))
    )


def _project_authorize(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or dict(value) != {"status": "authorized"}:
        raise _CliFailure(_UNAVAILABLE)
    return {"status": "authorized"}


def _project_apply(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or dict(value) != {"status": "applied"}:
        raise _CliFailure(_UNAVAILABLE)
    return {"status": "applied"}


def _project_subject_status(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"status"}:
        raise _CliFailure(_UNAVAILABLE)
    status = value.get("status")
    if status not in {"bound", "unavailable"}:
        raise _CliFailure(_UNAVAILABLE)
    assert type(status) is str
    return {"status": status}


def _project_scan(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _SCAN_RESULT_FIELDS:
        raise _CliFailure(_UNAVAILABLE)
    if value.get("status") != "planned" or not _is_plan_reference(
        value.get("plan_reference")
    ):
        raise _CliFailure(_UNAVAILABLE)
    result: dict[str, object] = {
        "status": "planned",
        "plan_reference": value["plan_reference"],
    }
    for field in (
        "account_count",
        "project_count",
        "billing_account_count",
        "service_count",
        "key_count",
    ):
        count = value.get(field)
        if type(count) is not int or count < 0:
            raise _CliFailure(_UNAVAILABLE)
        result[field] = count
    changes = value.get("changes")
    if (
        not isinstance(changes, Mapping)
        or set(changes) - _SCAN_CHANGE_KINDS
        or any(type(count) is not int or count < 0 for count in changes.values())
    ):
        raise _CliFailure(_UNAVAILABLE)
    result["changes"] = {kind: changes[kind] for kind in sorted(changes)}
    return result


def _dispatch_inventory_job(
    job: str, plan_reference: object = None
) -> dict[str, object]:
    """The only construction and dispatch boundary, including private status."""

    if (
        job not in {"authorize", "scan_plan", "apply", "subject_status"}
        or (job == "apply" and not _is_plan_reference(plan_reference))
        or (job != "apply" and plan_reference is not None)
    ):
        raise _CliFailure(_REQUEST_INVALID)
    service = GoogleInventoryReadonlyControlService()
    if job == "authorize":
        return _project_authorize(service.authorize())
    if job == "scan_plan":
        return _project_scan(service.scan_plan())
    if job == "apply":
        return _project_apply(service.apply(plan_reference))
    return _project_subject_status(service.subject_status())


def run(arguments: argparse.Namespace) -> int:
    """Forward one fixed grammar action to the sole control authority."""

    if not _valid_arguments(arguments):
        raise _CliFailure(_REQUEST_INVALID)
    action = getattr(arguments, "inventory_action", None)
    if action == "authorize":
        result = _dispatch_inventory_job("authorize")
    elif action == "scan" and getattr(arguments, "plan", None) is True:
        result = _dispatch_inventory_job("scan_plan")
    elif action is None:
        result = _dispatch_inventory_job("apply", arguments.plan_reference)
    else:
        raise _CliFailure(_REQUEST_INVALID)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _error_code(error: BaseException) -> str:
    code = getattr(error, "code", None)
    return code if type(code) is str and code in _SAFE_ERROR_CODES else _UNAVAILABLE


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except _ParseFailure as error:
        print(error.code, file=sys.stderr)
        return 1
    except Exception as error:
        print(_error_code(error), file=sys.stderr)
        return 1


def subject_id_main(argv: Sequence[str] | None = None) -> int:
    """Print only the subject-binding status from the same authority."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 0:
        print(_REQUEST_INVALID, file=sys.stderr)
        return 1
    try:
        result = _dispatch_inventory_job("subject_status")
    except Exception as error:
        print(_error_code(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
