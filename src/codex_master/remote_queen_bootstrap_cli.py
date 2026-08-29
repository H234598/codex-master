import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .remote_queen_bootstrap import (
    HostFactsV1,
    ManifestGenerationV1,
    ManagedObjectStateV1,
    QueenBindingV1,
    RemoteQueenBootstrapError,
    build_remote_queen_bootstrap_plan,
    parse_ssh_target,
    plan_as_dict,
)


class _TargetTolerantArgumentParser(argparse.ArgumentParser):
    def _parse_optional(self, arg_string):
        option_string = arg_string.split("=", 1)[0]
        if (
            arg_string.startswith("-")
            and option_string not in self._option_string_actions
        ):
            return None
        return super()._parse_optional(arg_string)


def build_parser(
    arguments: Sequence[str] | None = None,
) -> argparse.ArgumentParser:
    parser = _TargetTolerantArgumentParser(
        prog="python -m codex_master.remote_queen_bootstrap_cli"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_TargetTolerantArgumentParser,
    )
    plan_parser = subparsers.add_parser("plan", add_help=False)
    plan_parser.add_argument("ssh_target", metavar="SSH_TARGET")
    plan_parser.add_argument("--fixture", required=True, type=Path)
    return parser


def _fixture_inputs(fixture: Path):
    try:
        payload = json.loads(fixture.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT") from error
    if not isinstance(payload, dict) or set(payload) != {
        "host_facts",
        "desired_generation",
        "object_states",
        "queen_binding",
    }:
        raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")
    try:
        host_facts = HostFactsV1(**payload["host_facts"])
        desired_generation = ManifestGenerationV1(**payload["desired_generation"])
        object_states = tuple(
            ManagedObjectStateV1(**state) for state in payload["object_states"]
        )
        queen_binding = QueenBindingV1(**payload["queen_binding"])
    except (TypeError, ValueError, KeyError) as error:
        if isinstance(error, RemoteQueenBootstrapError):
            raise
        raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT") from error
    return host_facts, desired_generation, object_states, queen_binding


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_parser(arguments)
    try:
        parsed = parser.parse_args(arguments)
    except SystemExit as error:
        return int(error.code)

    try:
        ssh_target = parse_ssh_target(parsed.ssh_target)
        host_facts, desired_generation, object_states, queen_binding = _fixture_inputs(
            parsed.fixture
        )
        plan = build_remote_queen_bootstrap_plan(
            ssh_target=ssh_target,
            host_facts=host_facts,
            desired_generation=desired_generation,
            object_states=object_states,
            queen_binding=queen_binding,
        )
    except RemoteQueenBootstrapError as error:
        print(error.code, file=sys.stderr)
        return 2

    print(json.dumps(plan_as_dict(plan), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
