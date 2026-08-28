"""Data-only root permit contract for Dynamic-Teamlead A3 execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from codex_master.fleet_runners import DynamicTeamleadRunnerPlan


class _NonTransferablePermit:
    __slots__ = ()

    def __init__(self) -> None:
        raise TypeError("root_dynamic_teamlead_runner_permit_factory_required")

    def __copy__(self):
        raise TypeError("root_dynamic_teamlead_runner_permit_not_cloneable")

    def __deepcopy__(self, _memo):
        raise TypeError("root_dynamic_teamlead_runner_permit_not_cloneable")

    def __reduce_ex__(self, _protocol):
        raise TypeError("root_dynamic_teamlead_runner_permit_not_serializable")

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, init=False, repr=False)
class RootDynamicTeamleadRunnerPermit(_NonTransferablePermit):
    """Opaque root reference plus non-authoritative diagnostics."""

    opaque_reference: object
    principal_diagnostic: str
    identity_diagnostic: str
    snapshot_generation: int
    policy_generation: int
    release_diagnostic: str
    root_generation: int

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("root_dynamic_teamlead_runner_permit_not_subclassable")


class DynamicTeamleadRunnerOperations(Protocol):
    def execute(
        self,
        plan: DynamicTeamleadRunnerPlan,
        *,
        permit: RootDynamicTeamleadRunnerPermit,
    ) -> None: ...


__all__ = (
    "DynamicTeamleadRunnerOperations",
    "RootDynamicTeamleadRunnerPermit",
)
