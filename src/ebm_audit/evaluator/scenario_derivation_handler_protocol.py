"""Data-only protocol for substantive scenario derivation handlers."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ebm_audit.evaluator.scenario_evidence import (
        _AuthenticatedScenarioEvidenceContext,
    )
    from ebm_audit.evaluator.scenario_source_owner_manifest import (
        _ScenarioSourceOwnerRecord,
    )


type OwnerSlotKey = tuple[str, str, str]
type HandlerKey = tuple[
    Literal["COMMON_DERIVATION", "FAMILY_OUTPUT"],
    str | None,
    str,
    str | None,
    tuple[OwnerSlotKey, ...],
]

_STABLE_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]*(?:\.[A-Z0-9_]+)+$")


def _freeze_json_value(value: object, active_container_ids: set[int] | None = None) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("PASS value floats must be finite")
        return value
    if type(value) not in (list, tuple, dict):
        raise TypeError("PASS value must contain only JSON-like values")

    if active_container_ids is None:
        active_container_ids = set()
    container_id = id(value)
    if container_id in active_container_ids:
        raise ValueError("PASS value must not contain cycles")
    active_container_ids.add(container_id)
    try:
        if isinstance(value, (list, tuple)):
            return tuple(_freeze_json_value(item, active_container_ids) for item in value)
        assert isinstance(value, dict)
        if any(type(key) is not str for key in value):
            raise TypeError("PASS value object keys must be strings")
        return MappingProxyType(
            {key: _freeze_json_value(item, active_container_ids) for key, item in value.items()}
        )
    finally:
        active_container_ids.remove(container_id)


@dataclass(frozen=True, slots=True)
class HandlerRequest:
    """Data-only input whose possession grants no authentication or authority."""

    key: HandlerKey
    context: _AuthenticatedScenarioEvidenceContext
    owner_projections: tuple[tuple[_ScenarioSourceOwnerRecord, ...], ...]


@dataclass(frozen=True, slots=True)
class HandlerResult:
    """One derivation result with a closed PASS or FAIL payload shape."""

    key: HandlerKey
    state: Literal["PASS", "FAIL"]
    value: object | None
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.state) is not str or self.state not in ("PASS", "FAIL"):
            raise ValueError("state must be PASS or FAIL")
        if type(self.reason_codes) is not tuple:
            raise TypeError("reason_codes must be an immutable tuple")
        if any(
            type(code) is not str or _STABLE_REASON_CODE.fullmatch(code) is None
            for code in self.reason_codes
        ):
            raise ValueError("reason_codes must contain only stable reason codes")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("reason_codes must not contain duplicates")
        if self.state == "PASS":
            if self.value is None or self.reason_codes:
                raise ValueError("PASS requires a value and no reason codes")
            object.__setattr__(self, "value", _freeze_json_value(self.value))
            return
        if self.value is not None or not self.reason_codes:
            raise ValueError("FAIL requires no value and at least one reason code")


type Handler = Callable[[HandlerRequest], HandlerResult]

__all__ = [
    "Handler",
    "HandlerKey",
    "HandlerRequest",
    "HandlerResult",
    "OwnerSlotKey",
]
