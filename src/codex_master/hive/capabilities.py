"""Pure capability and active-binding eligibility decisions."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from codex_master.hive.types import validate_utc_datetime

if TYPE_CHECKING:
    from codex_master.hive.principals import Principal, PrincipalRegistry


ROOT_EXECUTIVE_CLASSES: frozenset[str] = frozenset({"gottbiene", "godbee", "goettin", "goddess"})
QUEEN_CLASSES: frozenset[str] = frozenset({"koenigin", "queen"})
GODDESS_REPORT_AUTO_CAPABILITY: str = "goddess.report.auto"


class CapabilityError(ValueError):
    """Raised when capability eligibility input is invalid."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def requires_goddess_auto_report(
    principal: Principal,
    *,
    capabilities: frozenset[str],
    registry: PrincipalRegistry,
    now: datetime,
) -> bool:
    from codex_master.hive.principals import Principal, PrincipalRegistry

    if type(principal) is not Principal:
        raise CapabilityError("invalid_principal")
    if type(registry) is not PrincipalRegistry:
        raise CapabilityError("invalid_principal_registry")
    if type(capabilities) is not frozenset or any(type(value) is not str for value in capabilities):
        raise CapabilityError("invalid_capability")
    if not isinstance(now, datetime):
        raise CapabilityError("invalid_capability_time")
    try:
        normalized_now = validate_utc_datetime(now)
    except Exception:
        raise CapabilityError("invalid_capability_time") from None

    if (
        principal.state != "active"
        or principal.class_id not in ROOT_EXECUTIVE_CLASSES
        or GODDESS_REPORT_AUTO_CAPABILITY not in capabilities
    ):
        return False
    try:
        authoritative_principal = registry.get(principal.principal_id)
    except Exception:
        return False
    if authoritative_principal != principal:
        return False
    try:
        result = registry.has_active_execution_binding(principal.principal_id, now=normalized_now)
    except Exception:
        raise CapabilityError("binding_check_unavailable") from None
    if type(result) is not bool:
        raise CapabilityError("invalid_binding_result")
    return result


__all__ = [
    "CapabilityError",
    "GODDESS_REPORT_AUTO_CAPABILITY",
    "QUEEN_CLASSES",
    "ROOT_EXECUTIVE_CLASSES",
    "requires_goddess_auto_report",
]
