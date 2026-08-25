"""Immutable public types for project-owned synthetic generation.

The objects in this module contain synthetic participant rows only.  They do
not accept or retain source-cohort identifiers or biomarker names.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Never, SupportsIndex, cast, final

import numpy as np
from numpy.typing import NDArray

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)

FloatMatrix = NDArray[np.float64]
BoolMatrix = NDArray[np.bool_]
ResolutionMode = Literal["DEVELOPMENT_VARIANT", "HELDOUT_RANGE", "TRANSFORMED_SOURCE"]
RootKind = Literal["CASE_SEED", "SHARED_DRAW_SEED", "OPERATION_SEED"]


@dataclass(frozen=True, slots=True)
class CaseCoordinate:
    """Evaluator-owned coordinates for exactly one synthetic case."""

    family_id: str
    variant_id: str
    replicate_index: int
    resolution_mode: ResolutionMode = "DEVELOPMENT_VARIANT"


@dataclass(frozen=True, slots=True)
class ComponentSeed:
    """One deterministic PCG64DXSM component stream identity."""

    component_path: str
    root_kind: RootKind
    full_digest: str
    seed_128: str
    shared: bool


@dataclass(frozen=True, slots=True)
class FieldResolution:
    """One typed row in the closed 71-field source ledger."""

    field_id: str
    value_type: str
    allowed_form: str
    source_kind: str
    source_reference: str
    draw_rule: str
    draw_consumed: bool
    draw_index: int | None
    sampled_integer: int | None
    resolution_source: dict[str, Any]
    resolved_destination_json_pointer: str | None
    resolved_value: Any

    def as_dict(self) -> dict[str, Any]:
        """Return the exact schema-facing row."""

        return {
            "field_id": self.field_id,
            "value_type": self.value_type,
            "allowed_form": self.allowed_form,
            "source_kind": self.source_kind,
            "source_reference": self.source_reference,
            "draw_rule": self.draw_rule,
            "draw_consumed": self.draw_consumed,
            "draw_index": self.draw_index,
            "sampled_integer": self.sampled_integer,
            "resolution_source": self.resolution_source,
            "resolved_destination_json_pointer": self.resolved_destination_json_pointer,
            "resolved_value": self.resolved_value,
        }


@dataclass(frozen=True, slots=True)
class FrozenMapping(Mapping[str, "FrozenJson"]):
    """Ordered immutable mapping used by terminal scientific records."""

    _items: tuple[tuple[str, FrozenJson], ...]

    def __post_init__(self) -> None:
        if not _is_frozen_mapping(self, seen=set()):
            raise ValueError("A terminal mapping is not deeply immutable JSON.")

    def __getitem__(self, key: str) -> FrozenJson:
        for item_key, value in self._items:
            if item_key == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"FrozenMapping({dict(self._items)!r})"


type FrozenJson = None | bool | int | float | str | tuple["FrozenJson", ...] | FrozenMapping


def _is_frozen_json(value: object, *, seen: set[int]) -> bool:
    if value is None or type(value) in {bool, int, float, str}:
        return not isinstance(value, float) or np.isfinite(value)
    identity = id(value)
    if identity in seen:
        return False
    if type(value) is tuple:
        seen.add(identity)
        try:
            return all(_is_frozen_json(item, seen=seen) for item in value)
        finally:
            seen.remove(identity)
    if type(value) is FrozenMapping:
        return _is_frozen_mapping(value, seen=seen)
    return False


def _is_frozen_mapping(value: FrozenMapping, *, seen: set[int]) -> bool:
    identity = id(value)
    if identity in seen or type(value._items) is not tuple:
        return False
    seen.add(identity)
    try:
        keys: list[str] = []
        for item in value._items:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or not _is_frozen_json(item[1], seen=seen)
            ):
                return False
            keys.append(item[0])
        return len(keys) == len(set(keys))
    finally:
        seen.remove(identity)


def freeze_json(value: object) -> FrozenJson:
    """Recursively detach and freeze one JSON-model value."""

    if value is None:
        return None
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is str:
        return value
    if type(value) is float:
        if np.isfinite(value):
            return value
        raise ValueError("A terminal field value is outside the immutable JSON model.")
    if type(value) is list:
        return tuple(freeze_json(item) for item in cast(list[object], value))
    if type(value) is tuple:
        return tuple(freeze_json(item) for item in cast(tuple[object, ...], value))
    if type(value) is dict and all(type(key) is str for key in value):
        return FrozenMapping(tuple((key, freeze_json(item)) for key, item in value.items()))
    raise ValueError("A terminal field value is outside the immutable JSON model.")


@final
@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class FrozenFieldResolution:
    """Deeply immutable terminal projection of one 71-field ledger row."""

    ordinal: int
    field_id: str
    value_type: str
    allowed_form: str
    source_kind: str
    source_reference: str
    draw_rule: str
    draw_consumed: bool
    draw_index: int | None
    sampled_integer: int | None
    resolution_source: FrozenMapping
    resolved_destination_json_pointer: str | None
    resolved_value: FrozenJson

    def __new__(cls, *_args: object, **_kwargs: object) -> FrozenFieldResolution:
        raise TypeError("Terminal field-resolution rows are factory-built only.")

    def __copy__(self) -> Never:
        raise TypeError("Terminal field-resolution rows cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Terminal field-resolution rows cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Terminal field-resolution rows cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Terminal field-resolution rows cannot be serialized.")


type _FrozenProjection = tuple[object, ...]


def _frozen_json_projection(value: FrozenJson) -> object:
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is float:
        return ("float", value)
    if type(value) is str:
        return ("string", value)
    if type(value) is tuple:
        return ("array", tuple(_frozen_json_projection(item) for item in value))
    if type(value) is FrozenMapping:
        return (
            "mapping",
            tuple((key, _frozen_json_projection(item)) for key, item in value._items),
        )
    raise ValueError("A terminal field value is outside the immutable JSON model.")


def _frozen_field_resolution_projection(row: FrozenFieldResolution) -> _FrozenProjection:
    return (
        row.ordinal,
        row.field_id,
        row.value_type,
        row.allowed_form,
        row.source_kind,
        row.source_reference,
        row.draw_rule,
        row.draw_consumed,
        row.draw_index,
        row.sampled_integer,
        _frozen_json_projection(row.resolution_source),
        row.resolved_destination_json_pointer,
        _frozen_json_projection(row.resolved_value),
    )


def _validate_frozen_field_resolution(row: FrozenFieldResolution) -> None:
    if (
        type(row) is not FrozenFieldResolution
        or type(row.ordinal) is not int
        or row.ordinal < 0
        or type(row.field_id) is not str
        or not row.field_id
        or type(row.value_type) is not str
        or not row.value_type
        or type(row.allowed_form) is not str
        or not row.allowed_form
        or type(row.source_kind) is not str
        or not row.source_kind
        or type(row.source_reference) is not str
        or not row.source_reference
        or type(row.draw_rule) is not str
        or not row.draw_rule
        or type(row.draw_consumed) is not bool
        or (
            row.draw_consumed
            and (type(row.draw_index) is not int or row.draw_index < 0)
        )
        or (
            not row.draw_consumed
            and (row.draw_index is not None or row.sampled_integer is not None)
        )
        or (
            row.sampled_integer is not None
            and type(row.sampled_integer) is not int
        )
        or type(row.resolution_source) is not FrozenMapping
        or not _is_frozen_mapping(row.resolution_source, seen=set())
        or (
            row.resolved_destination_json_pointer is not None
            and type(row.resolved_destination_json_pointer) is not str
        )
        or not _is_frozen_json(row.resolved_value, seen=set())
    ):
        raise ValueError("A terminal field-resolution row is invalid.")
    source_kind = row.resolution_source.get("kind")
    if (
        row.sampled_integer is not None
        and row.sampled_integer < 0
        and source_kind != "DECIMAL_TICK_RANGE"
    ):
        raise ValueError("A terminal field-resolution row is invalid.")


_FROZEN_FIELD_STATES: OneShotWeakRegistry[FrozenFieldResolution, _FrozenProjection]
_FROZEN_FIELD_STATES, _FROZEN_FIELD_STATE_ISSUER = create_one_shot_registry()


def _freeze_field_resolution(
    row: FieldResolution, *, ordinal: int
) -> FrozenFieldResolution:
    """Build and authenticate one exact terminal row projection."""

    if type(row) is not FieldResolution:
        raise ValueError("A terminal field-resolution source row is invalid.")
    resolution_source = freeze_json(row.resolution_source)
    if type(resolution_source) is not FrozenMapping:
        raise ValueError("A terminal resolution source must be an immutable mapping.")
    frozen = object.__new__(FrozenFieldResolution)
    values = {
        "ordinal": ordinal,
        "field_id": row.field_id,
        "value_type": row.value_type,
        "allowed_form": row.allowed_form,
        "source_kind": row.source_kind,
        "source_reference": row.source_reference,
        "draw_rule": row.draw_rule,
        "draw_consumed": row.draw_consumed,
        "draw_index": row.draw_index,
        "sampled_integer": row.sampled_integer,
        "resolution_source": resolution_source,
        "resolved_destination_json_pointer": row.resolved_destination_json_pointer,
        "resolved_value": freeze_json(row.resolved_value),
    }
    for name, value in values.items():
        object.__setattr__(frozen, name, value)
    _validate_frozen_field_resolution(frozen)
    projection = _frozen_field_resolution_projection(frozen)
    _FROZEN_FIELD_STATE_ISSUER.bind_once(frozen, projection)
    return frozen


def _require_authenticated_frozen_field_resolution(
    row: FrozenFieldResolution,
) -> _FrozenProjection:
    if type(row) is not FrozenFieldResolution:
        raise ValueError("A terminal field-resolution row is unauthenticated.")
    try:
        expected = _FROZEN_FIELD_STATES.read(row)
    except OneShotRegistryError:
        raise ValueError("A terminal field-resolution row is unauthenticated.") from None
    _validate_frozen_field_resolution(row)
    if _frozen_field_resolution_projection(row) != expected:
        raise ValueError("A terminal field-resolution row failed authentication.")
    return expected


@dataclass(frozen=True, slots=True)
class AuthenticatedSourceOwner:
    """A previously resolved ordinary case authenticated by its exact manifest."""

    resolved_case: ResolvedSyntheticCase


@dataclass(frozen=True, slots=True)
class ResolvedSyntheticCase:
    """Complete evaluator-derived input to the numerical generator."""

    coordinate: CaseCoordinate
    variant_index: int
    case_id: str
    case_seed: str
    shared_draw_seed: str | None
    operation_seed: str | None
    source_contract_sha256: str
    scenario_definitions_sha256: str
    field_resolutions: tuple[FieldResolution, ...]
    component_seeds: tuple[ComponentSeed, ...]
    component_seed_manifest: dict[str, Any]
    resolved_parameter_manifest: dict[str, Any]
    resolved_configuration: dict[str, Any]
    resolved_mechanism: dict[str, Any]
    resolution_bundle: dict[str, Any]

    def field_value(self, field_id: str) -> Any:
        """Return one reconstructed field, failing for an unknown field."""

        for row in self.field_resolutions:
            if row.field_id == field_id:
                return row.resolved_value
        raise KeyError(field_id)

    def component_seed(self, component_path: str) -> ComponentSeed:
        """Return one closed component record, failing for an unknown path."""

        for row in self.component_seeds:
            if row.component_path == component_path:
                return row
        raise KeyError(component_path)


_GENERATOR_REASON = re.compile(r"GENERATOR\.[A-Z0-9_]+\Z")


@dataclass(frozen=True, slots=True)
class HeldoutResolvedCase:
    """Public, seed-free projection of one privately resolved attempt case."""

    status: Literal["RESOLVED"]
    heldout_attempt_id: str
    coordinate: CaseCoordinate
    variant_index: int
    case_id: str
    source_contract_sha256: str
    scenario_definitions_sha256: str
    field_resolutions: tuple[FieldResolution, ...]
    parameter_draw_count: int
    resolved_configuration: dict[str, Any]
    resolved_mechanism: dict[str, Any]


@final
@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class RetainedGeneratorInvalid:
    """Seed-free terminal record for a claimed case that fails a dependency stage."""

    status: Literal["GENERATOR_INVALID"]
    heldout_attempt_id: str
    coordinate: CaseCoordinate
    variant_index: int
    case_id: str
    source_contract_sha256: str
    scenario_definitions_sha256: str
    field_resolutions: tuple[FrozenFieldResolution, ...]
    parameter_draw_count: int
    failed_dependency_stage_index: int
    failed_dependency_stage_id: str
    stable_reason: str
    terminal_branch: Literal["COMPILE_TIME_NON_SUCCESS"] = "COMPILE_TIME_NON_SUCCESS"
    worker_execution_allowed: Literal[False] = False
    fit_execution_allowed: Literal[False] = False
    retry_allowed: Literal[False] = False
    science_payload_allowed: Literal[False] = False
    planned_denominator_retained: Literal[True] = True
    rule_state: Literal["FAIL"] = "FAIL"

    def __new__(cls, *_args: object, **_kwargs: object) -> RetainedGeneratorInvalid:
        raise TypeError("Retained generator failure terminals are factory-built only.")

    def __copy__(self) -> Never:
        raise TypeError("Retained generator failure terminals cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Retained generator failure terminals cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Retained generator failure terminals cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Retained generator failure terminals cannot be serialized.")


_DEPENDENCY_STAGES = (
    "participants",
    "events",
    "group_counts",
    "mechanism",
    "event_arrays",
    "covariance_validity",
    "matched_comparator_overrides",
)


def _retained_terminal_projection(
    terminal: RetainedGeneratorInvalid,
    row_projections: tuple[_FrozenProjection, ...],
) -> _FrozenProjection:
    coordinate = terminal.coordinate
    return (
        terminal.status,
        terminal.heldout_attempt_id,
        (
            coordinate.family_id,
            coordinate.variant_id,
            coordinate.replicate_index,
            coordinate.resolution_mode,
        ),
        terminal.variant_index,
        terminal.case_id,
        terminal.source_contract_sha256,
        terminal.scenario_definitions_sha256,
        row_projections,
        terminal.parameter_draw_count,
        terminal.failed_dependency_stage_index,
        terminal.failed_dependency_stage_id,
        terminal.stable_reason,
        terminal.terminal_branch,
        terminal.worker_execution_allowed,
        terminal.fit_execution_allowed,
        terminal.retry_allowed,
        terminal.science_payload_allowed,
        terminal.planned_denominator_retained,
        terminal.rule_state,
    )


def _validate_retained_generator_invalid(
    terminal: RetainedGeneratorInvalid,
) -> tuple[_FrozenProjection, ...]:
    from .authority import FIELD_IDS

    rows = terminal.field_resolutions
    if (
        type(terminal) is not RetainedGeneratorInvalid
        or type(rows) is not tuple
        or len(rows) != 71
        or any(type(row) is not FrozenFieldResolution for row in rows)
    ):
        raise ValueError("A retained generator failure terminal projection is invalid.")
    try:
        row_projections = tuple(
            _require_authenticated_frozen_field_resolution(row) for row in rows
        )
    except ValueError:
        raise ValueError(
            "A retained generator failure terminal projection is invalid."
        ) from None
    drawn = tuple(row for row in rows if row.draw_consumed)
    no_draw = tuple(row for row in rows if not row.draw_consumed)
    if (
        terminal.status != "GENERATOR_INVALID"
        or type(terminal.coordinate) is not CaseCoordinate
        or type(terminal.coordinate.family_id) is not str
        or not terminal.coordinate.family_id
        or "\0" in terminal.coordinate.family_id
        or type(terminal.coordinate.variant_id) is not str
        or not terminal.coordinate.variant_id
        or "\0" in terminal.coordinate.variant_id
        or terminal.coordinate.resolution_mode not in {"HELDOUT_RANGE", "TRANSFORMED_SOURCE"}
        or type(terminal.heldout_attempt_id) is not str
        or not terminal.heldout_attempt_id
        or not terminal.heldout_attempt_id.isascii()
        or "\0" in terminal.heldout_attempt_id
        or type(terminal.variant_index) is not int
        or terminal.variant_index < 0
        or type(terminal.coordinate.replicate_index) is not int
        or terminal.coordinate.replicate_index < 0
        or terminal.case_id
        != (
            f"{terminal.coordinate.family_id}-v{terminal.variant_index}"
            f"-r{terminal.coordinate.replicate_index}"
        )
        or type(terminal.source_contract_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", terminal.source_contract_sha256) is None
        or type(terminal.scenario_definitions_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", terminal.scenario_definitions_sha256) is None
        or tuple(row.ordinal for row in rows) != tuple(range(71))
        or tuple(row.field_id for row in rows) != FIELD_IDS
        or rows[61].draw_consumed is not False
        or rows[61].draw_index is not None
        or rows[61].sampled_integer is not None
        or (
            terminal.coordinate.resolution_mode == "TRANSFORMED_SOURCE"
            and (
                rows[61].resolved_value != 59
                or dict(rows[61].resolution_source) != {"kind": "FIXED", "value": 59}
            )
        )
        or type(terminal.parameter_draw_count) is not int
        or terminal.parameter_draw_count != len(drawn)
        or tuple(row.draw_index for row in drawn) != tuple(range(len(drawn)))
        or any(row.draw_index is not None or row.sampled_integer is not None for row in no_draw)
        or type(terminal.failed_dependency_stage_index) is not int
        or not 0 <= terminal.failed_dependency_stage_index < len(_DEPENDENCY_STAGES)
        or type(terminal.failed_dependency_stage_id) is not str
        or _DEPENDENCY_STAGES[terminal.failed_dependency_stage_index]
        != terminal.failed_dependency_stage_id
        or type(terminal.stable_reason) is not str
        or _GENERATOR_REASON.fullmatch(terminal.stable_reason) is None
        or terminal.terminal_branch != "COMPILE_TIME_NON_SUCCESS"
        or terminal.worker_execution_allowed is not False
        or terminal.fit_execution_allowed is not False
        or terminal.retry_allowed is not False
        or terminal.science_payload_allowed is not False
        or terminal.planned_denominator_retained is not True
        or terminal.rule_state != "FAIL"
    ):
        raise ValueError("A retained generator failure terminal projection is invalid.")
    return row_projections


_RETAINED_TERMINAL_STATES: OneShotWeakRegistry[
    RetainedGeneratorInvalid, _FrozenProjection
]
_RETAINED_TERMINAL_STATES, _RETAINED_TERMINAL_STATE_ISSUER = create_one_shot_registry()


def _retain_generator_invalid(
    *,
    heldout_attempt_id: str,
    coordinate: CaseCoordinate,
    variant_index: int,
    case_id: str,
    source_contract_sha256: str,
    scenario_definitions_sha256: str,
    field_resolutions: tuple[FrozenFieldResolution, ...],
    parameter_draw_count: int,
    failed_dependency_stage_index: int,
    failed_dependency_stage_id: str,
    stable_reason: str,
) -> RetainedGeneratorInvalid:
    """Build and authenticate one exact terminal failure projection."""

    terminal = object.__new__(RetainedGeneratorInvalid)
    values = {
        "status": "GENERATOR_INVALID",
        "heldout_attempt_id": heldout_attempt_id,
        "coordinate": coordinate,
        "variant_index": variant_index,
        "case_id": case_id,
        "source_contract_sha256": source_contract_sha256,
        "scenario_definitions_sha256": scenario_definitions_sha256,
        "field_resolutions": field_resolutions,
        "parameter_draw_count": parameter_draw_count,
        "failed_dependency_stage_index": failed_dependency_stage_index,
        "failed_dependency_stage_id": failed_dependency_stage_id,
        "stable_reason": stable_reason,
        "terminal_branch": "COMPILE_TIME_NON_SUCCESS",
        "worker_execution_allowed": False,
        "fit_execution_allowed": False,
        "retry_allowed": False,
        "science_payload_allowed": False,
        "planned_denominator_retained": True,
        "rule_state": "FAIL",
    }
    for name, value in values.items():
        object.__setattr__(terminal, name, value)
    row_projections = _validate_retained_generator_invalid(terminal)
    projection = _retained_terminal_projection(terminal, row_projections)
    _RETAINED_TERMINAL_STATE_ISSUER.bind_once(terminal, projection)
    return terminal


def _require_authenticated_retained_generator_invalid(
    terminal: RetainedGeneratorInvalid,
) -> RetainedGeneratorInvalid:
    if type(terminal) is not RetainedGeneratorInvalid:
        raise ValueError("A retained generator failure terminal is unauthenticated.")
    try:
        expected = _RETAINED_TERMINAL_STATES.read(terminal)
    except OneShotRegistryError:
        raise ValueError("A retained generator failure terminal is unauthenticated.") from None
    rows = _validate_retained_generator_invalid(terminal)
    if _retained_terminal_projection(terminal, rows) != expected:
        raise ValueError("A retained generator failure terminal failed authentication.")
    return terminal


type HeldoutCaseResolution = HeldoutResolvedCase | RetainedGeneratorInvalid


@dataclass(frozen=True, slots=True)
class StageSnapshot:
    """Internal execution-owned output for one generation stage.

    This is deliberately not called a contract receipt.  The current schemas
    do not yet define a closed evaluator-owned replay receipt.
    """

    stage_index: int
    stage_id: str
    digest_domain: str
    output_sha256: str
    output: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SyntheticCaseArtifacts:
    """Generated data, truth, and execution outputs for one synthetic case."""

    resolved_case: ResolvedSyntheticCase
    scientific_data: dict[str, Any]
    truth: dict[str, Any]
    stage_snapshots: tuple[StageSnapshot, ...]
    clean_values: FloatMatrix
    perturbed_values: FloatMatrix
    missingness_mask: BoolMatrix


@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    """Internal typed replay result pending a closed schema-owned receipt."""

    status: Literal["MATCH", "MISMATCH", "GENERATOR_INVALID"]
    first_mismatch_stage: str | None
    compared_stage_count: int
    expected_stage_sha256: str | None
    candidate_stage_sha256: str | None
    data_match: bool
    truth_match: bool
    receipt_contract_state: Literal["UNSCHEMATIZED_INTERNAL_ONLY"] = "UNSCHEMATIZED_INTERNAL_ONLY"
