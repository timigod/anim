"""Replay-owned reconstruction from exact evaluator scenario bytes.

This module intentionally does not import the production resolver.  It provides
a separately executable reconstruction path for independent numerical replay.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import math
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Final, Literal, cast

import numpy as np

from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol.canonical import structured_sha256, structured_sha256_hex
from ebm_audit.schema.validation import SchemaValidationError, validate_instance

from .authority import (
    COMPONENT_PATHS,
    FIELD_IDS,
    ScenarioAuthority,
    load_scenario_authority,
    scenario_authority_source_reference,
)
from .models import (
    AuthenticatedSourceOwner,
    CaseCoordinate,
    ComponentSeed,
    FieldResolution,
    ResolvedSyntheticCase,
)
from .pure_no_signal import verify_pure_no_signal_semantics

_UINT64_HEX = re.compile(r"[0-9a-f]{16}\Z")
DEFAULT_EVENT_COUNT: Final = 8
MATCHED_COMPARATOR_GENERATION_STATE: Final = "UNAVAILABLE_PENDING_AUTHENTICATED_TRANSACTION_OWNER"
TRANSFORMED_NULL_GENERATION_STATE: Final = "UNAVAILABLE_PENDING_GENERATED_DATA_OWNER"
_INTEGER_TYPES = {
    "uint16",
    "uint32",
    "positive_uint16",
    "positive_uint32",
    "nonnegative_uint32",
}
_OPERATION_PATHS = {
    "label_permutation_null": ("label_permutation",),
    "within_group_feature_permutation_null": ("within_group_feature_permutation",),
}
_TRANSFORMED_OPERATION_FIELDS = {
    "source_events",
    "source_participants",
    "source_variant",
    "permutations_per_source",
    "truth_type",
}
_DIRECT_DESTINATIONS = {
    "participants": "/dimensions/participant_count",
    "events": "/dimensions/event_count",
    "amplitude": "/event_parameters/amplitude",
    "transition_width": "/event_parameters/transition_width",
    "covariate_event_effect": "/event_parameters/covariate_effect",
    "event_covariate_effect": "/event_parameters/covariate_effect",
    "group_event_effect": "/event_parameters/group_effect",
    "participant_random_effect_loading": "/event_parameters/participant_effect_loading",
    "measurement_noise_sd": "/measurement_noise/standard_deviations",
    "measurement_noise_sd_levels": "/scenario_parameters/measurement_noise_sd_levels",
    "reference_sampling_window": "/latent_sampling/reference_window",
    "at_risk_sampling_window": "/latent_sampling/at_risk_window",
    "boundary_rule_ids": "/scenario_parameters/boundary_rule_ids",
    "boundary_quantile_shifts": "/scenario_parameters/boundary_quantile_shifts",
    "base_quantile_cutoff": "/scenario_parameters/base_quantile_cutoff",
    "wrong_direction_event_ids": "/scenario_parameters/wrong_direction_event_ids",
}


def _fail(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _mapping(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise _fail(code, "A closed synthetic contract object is structurally invalid.")
    return value


def _list_of_mappings(value: object, code: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise _fail(code, "A closed synthetic contract registry is structurally invalid.")
    return cast(list[dict[str, Any]], value)


def _validate_schema(instance: object, *, definition: str | None = None) -> None:
    try:
        validate_instance(
            instance,
            "synthetic-resolved-configuration.schema.json",
            definition=definition,
        )
    except SchemaValidationError as exc:
        raise _fail(
            "GENERATOR.RESOLUTION_SCHEMA_INVALID",
            "A reconstructed synthetic owner failed its closed schema.",
        ) from exc


def _persisted_record(record: dict[str, Any], digest_field: str, domain: str) -> dict[str, Any]:
    preimage = copy.deepcopy(record)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage[digest_field] = None
    result = copy.deepcopy(preimage)
    result["digest_state"] = "PERSISTED"
    result[digest_field] = structured_sha256_hex(domain, preimage)
    return result


def _case_seed(authority: ScenarioAuthority, coordinate: CaseCoordinate) -> str:
    policy = _mapping(authority.data.get("seed_policy"), "GENERATOR.SEED_POLICY_INVALID")
    roots = policy.get("development_root_seeds")
    if (
        not isinstance(roots, list)
        or coordinate.replicate_index < 0
        or coordinate.replicate_index >= len(roots)
    ):
        raise _fail(
            "GENERATOR.REPLICATE_OUTSIDE_AUTHORITY",
            "The synthetic replicate has no declared development root.",
        )
    root = roots[coordinate.replicate_index]
    if not isinstance(root, str) or _UINT64_HEX.fullmatch(root) is None:
        raise _fail("GENERATOR.SEED_POLICY_INVALID", "A declared development root is invalid.")
    message = (
        "ebm-audit-development/v1\0"
        + coordinate.family_id
        + "\0"
        + coordinate.variant_id
        + "\0"
        + str(coordinate.replicate_index)
    ).encode()
    return hmac.new(bytes.fromhex(root), message, hashlib.sha256).digest()[:8].hex()


def _operation_seed(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    source_case_id: str,
) -> str:
    roots = _mapping(authority.data.get("seed_policy"), "GENERATOR.SEED_POLICY_INVALID").get(
        "development_root_seeds"
    )
    if not isinstance(roots, list) or not 0 <= coordinate.replicate_index < len(roots):
        raise _fail(
            "GENERATOR.REPLICATE_OUTSIDE_AUTHORITY",
            "The synthetic null operation has no declared development root.",
        )
    root = roots[coordinate.replicate_index]
    if not isinstance(root, str) or _UINT64_HEX.fullmatch(root) is None:
        raise _fail("GENERATOR.SEED_POLICY_INVALID", "A declared development root is invalid.")
    message = (
        "ebm-audit-development-null-operation/v1\0"
        + source_case_id
        + "\0"
        + coordinate.family_id
        + "\0"
        + str(coordinate.replicate_index)
    ).encode()
    return hmac.new(bytes.fromhex(root), message, hashlib.sha256).digest()[:8].hex()


def _component_record(root_seed: str, path: str, root_kind: str) -> ComponentSeed:
    if _UINT64_HEX.fullmatch(root_seed) is None:
        raise _fail("GENERATOR.COMPONENT_ROOT_INVALID", "A component root seed is invalid.")
    digest = hmac.new(
        bytes.fromhex(root_seed),
        b"ebm-audit-synthetic-component/v1\0" + path.encode(),
        hashlib.sha256,
    ).digest()
    return ComponentSeed(
        component_path=path,
        root_kind=cast(Literal["CASE_SEED", "SHARED_DRAW_SEED", "OPERATION_SEED"], root_kind),
        full_digest="sha256:" + digest.hex(),
        seed_128=digest[:16].hex(),
        shared=root_kind == "SHARED_DRAW_SEED",
    )


def _component_manifest(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    case_seed: str,
    source_case_id: str | None,
) -> tuple[tuple[ComponentSeed, ...], dict[str, Any], str | None]:
    operation_paths: tuple[str, ...]
    if coordinate.resolution_mode == "TRANSFORMED_SOURCE":
        if coordinate.family_id not in _OPERATION_PATHS or source_case_id is None:
            raise _fail(
                "GENERATOR.NULL_CONTEXT_INVALID",
                "The transformed synthetic case has no closed null-operation context.",
            )
        context: dict[str, Any] = {
            "kind": "DEVELOPMENT_NULL_OPERATION",
            "source_case_id": source_case_id,
            "null_family_id": coordinate.family_id,
            "null_replicate_index": coordinate.replicate_index,
        }
        operation_paths = _OPERATION_PATHS[coordinate.family_id]
        operation_seed = _operation_seed(authority, coordinate, source_case_id)
    else:
        if coordinate.family_id in _OPERATION_PATHS:
            raise _fail(
                "GENERATOR.NULL_CONTEXT_INVALID",
                "A null-transformation family requires an authenticated source case.",
            )
        context = {"kind": "ORDINARY_CASE"}
        operation_paths = ()
        operation_seed = None

    rows: list[ComponentSeed] = []
    for path in COMPONENT_PATHS:
        if path in operation_paths:
            if operation_seed is None:
                raise _fail(
                    "GENERATOR.COMPONENT_ROOT_INVALID",
                    "A declared null-operation component root is absent.",
                )
            rows.append(_component_record(operation_seed, path, "OPERATION_SEED"))
        else:
            rows.append(_component_record(case_seed, path, "CASE_SEED"))
    preimage = {
        "schema_version": "ebm-audit-component-seed-manifest/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "scenario_family_id": coordinate.family_id,
        "root_assignment_context": context,
        "case_seed": case_seed,
        "shared_draw_seed": None,
        "operation_seed": operation_seed,
        "shared_component_paths": [],
        "operation_component_paths": list(operation_paths),
        "ordered_component_paths": list(COMPONENT_PATHS),
        "components": [
            {
                "component_path": row.component_path,
                "root_kind": row.root_kind,
                "full_digest": row.full_digest,
                "seed_128": row.seed_128,
                "numpy_version": np.__version__,
                "bit_generator": "PCG64DXSM",
                "shared": row.shared,
            }
            for row in rows
        ],
        "component_seed_manifest_sha256": None,
    }
    manifest = _persisted_record(
        preimage,
        "component_seed_manifest_sha256",
        "ebm-audit/component-seed-manifest/1",
    )
    _validate_schema(manifest, definition="ComponentSeedManifest")
    return tuple(rows), manifest, operation_seed


def _exact_tick(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _fail("GENERATOR.DECIMAL_TICK_INVALID", "A decimal-tick endpoint is invalid.")
    if isinstance(value, float) and not math.isfinite(value):
        raise _fail("GENERATOR.DECIMAL_TICK_INVALID", "A decimal-tick endpoint is invalid.")
    try:
        scaled = Decimal(str(value)) * Decimal(1_000_000)
    except InvalidOperation as exc:
        raise _fail(
            "GENERATOR.DECIMAL_TICK_INVALID", "A decimal-tick endpoint is invalid."
        ) from exc
    if scaled != scaled.to_integral_value():
        raise _fail(
            "GENERATOR.DECIMAL_TICK_INVALID",
            "A decimal-tick endpoint is not on the declared grid.",
        )
    return int(scaled)


def sample_decimal_tick(
    minimum: float,
    maximum: float,
    *,
    seed_128: str,
) -> tuple[int, float]:
    """Sample one signed inclusive 1e-6 tick using the normative RNG."""

    if re.fullmatch(r"[0-9a-f]{32}", seed_128) is None:
        raise _fail("GENERATOR.COMPONENT_SEED_INVALID", "A component seed is invalid.")
    low = _exact_tick(minimum)
    high = _exact_tick(maximum)
    if low > high:
        raise _fail("GENERATOR.PARAMETER_RANGE_REVERSED", "A parameter range is reversed.")
    rng = np.random.Generator(np.random.PCG64DXSM(int(seed_128, 16)))
    sampled = int(rng.integers(low, high + 1))
    return sampled, float(np.float64(sampled) / np.float64(1_000_000))


def _family_and_variant(
    authority: ScenarioAuthority, coordinate: CaseCoordinate
) -> tuple[int, dict[str, Any], int, dict[str, Any]]:
    family_matches = [
        (index, row)
        for index, row in enumerate(authority.scenario_families)
        if row.get("id") == coordinate.family_id
    ]
    if len(family_matches) != 1:
        raise _fail(
            "GENERATOR.FAMILY_NOT_UNIQUE",
            "The requested synthetic family is absent or duplicated.",
        )
    family_index, family = family_matches[0]
    variants = _list_of_mappings(
        family.get("development_variants", []), "GENERATOR.VARIANT_REGISTRY_INVALID"
    )
    variant_matches = [
        (index, row) for index, row in enumerate(variants) if row.get("id") == coordinate.variant_id
    ]
    if len(variant_matches) != 1:
        raise _fail(
            "GENERATOR.VARIANT_NOT_UNIQUE",
            "The requested synthetic development variant is absent or duplicated.",
        )
    variant_index, variant = variant_matches[0]
    replicate_count = family.get("development_replicates")
    if (
        not isinstance(replicate_count, int)
        or isinstance(replicate_count, bool)
        or not 0 <= coordinate.replicate_index < replicate_count
    ):
        raise _fail(
            "GENERATOR.REPLICATE_OUTSIDE_FAMILY",
            "The requested replicate is outside the declared family denominator.",
        )
    return family_index, family, variant_index, variant


def _middle_pair(event_ids: list[str], *, correlated: bool = False) -> list[str]:
    if correlated and not 7 <= len(event_ids) <= 10:
        raise _fail(
            "GENERATOR.DUPLICATE_DIMENSION_INVALID",
            "The duplicate-event selector requires seven to ten events.",
        )
    if len(event_ids) < 2:
        raise _fail("GENERATOR.EVENT_DIMENSION_INVALID", "At least two events are required.")
    if correlated:
        left, right = select_middle_adjacent_pair(len(event_ids))
    else:
        left = (len(event_ids) - 1) // 2
        right = left + 1
    return [event_ids[left], event_ids[right]]


def select_middle_adjacent_pair(event_count: int = DEFAULT_EVENT_COUNT) -> tuple[int, int]:
    """Return the normative zero-based adjacent pair for seven to ten events."""

    if (
        isinstance(event_count, bool)
        or not isinstance(event_count, int)
        or not 7 <= event_count <= 10
    ):
        raise _fail(
            "GENERATOR.DUPLICATE_DIMENSION_INVALID",
            "The duplicate-event selector requires seven to ten events.",
        )
    left = (event_count - 1) // 2
    return left, left + 1


def _broadcast(value: object, count: int, field_id: str, *, positive: bool = False) -> list[float]:
    values = value if isinstance(value, list) else [value] * count
    if len(values) != count:
        raise _fail(
            "GENERATOR.EVENT_ARRAY_MISALIGNED",
            "A synthetic event parameter does not match the event count.",
        )
    result: list[float] = []
    for item in values:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise _fail(
                "GENERATOR.EVENT_PARAMETER_INVALID",
                "A synthetic event parameter is not numeric.",
            )
        converted = float(np.float64(item))
        if not math.isfinite(converted) or (positive and converted <= 0):
            raise _fail(
                "GENERATOR.EVENT_PARAMETER_INVALID",
                "A synthetic event parameter is outside its finite domain.",
            )
        result.append(converted)
    return result


def _derived_value(
    field_id: str,
    resolved: dict[str, Any],
    family_id: str,
) -> Any:
    event_count = resolved.get("events")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or not 2 <= event_count <= 12
    ):
        raise _fail(
            "GENERATOR.EVENT_DIMENSION_INVALID",
            "The resolved synthetic event count is invalid.",
        )
    event_ids = resolved.get("event_ids")
    if field_id == "event_ids":
        return [f"E{index + 1:02d}" for index in range(event_count)]
    if not isinstance(event_ids, list) or any(not isinstance(item, str) for item in event_ids):
        raise _fail("GENERATOR.EVENT_IDS_INVALID", "The resolved synthetic event IDs are invalid.")
    if field_id in {"pair_event_ids", "target_pair_event_ids"}:
        return _middle_pair(event_ids, correlated=family_id == "correlated_duplicate_events")
    if field_id == "pair_direction_rule":
        return (
            "target_equals_source"
            if resolved.get("pair_mode") == "exact_duplicate_post_noise"
            else "retain_common_directions"
        )
    if field_id == "equivalence_block_event_ids":
        if family_id == "correlated_duplicate_events":
            if resolved.get("pair_mode") == "exact_duplicate_post_noise":
                return _middle_pair(event_ids, correlated=True)
            return None
        size = resolved.get("equivalence_block_size")
        if not isinstance(size, int) or isinstance(size, bool) or not 2 <= size <= event_count:
            raise _fail(
                "GENERATOR.EQUIVALENCE_BLOCK_INVALID",
                "The equivalence-block selector has an invalid size.",
            )
        first = (event_count - size) // 2
        return event_ids[first : first + size]
    if field_id == "wrong_direction_event_ids":
        count = resolved.get("reversed_direction_events")
        if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= event_count:
            raise _fail(
                "GENERATOR.DIRECTION_SELECTOR_INVALID",
                "The direction-sabotage selector has an invalid count.",
            )
        first = (event_count - count) // 2
        return event_ids[first : first + count]
    if field_id == "event_directions":
        directions = ["higher" if index % 2 == 0 else "lower" for index in range(event_count)]
        if (
            family_id == "correlated_duplicate_events"
            and resolved.get("pair_mode") == "exact_duplicate_post_noise"
        ):
            source_id, target_id = _middle_pair(event_ids, correlated=True)
            directions[event_ids.index(target_id)] = directions[event_ids.index(source_id)]
        return directions
    if field_id == "event_centers":
        interval = resolved.get("event_center_range")
        if (
            not isinstance(interval, list)
            or len(interval) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, (int, float)) for value in interval
            )
        ):
            raise _fail(
                "GENERATOR.CENTER_RANGE_INVALID",
                "The synthetic event-center interval is invalid.",
            )
        low = np.float64(interval[0])
        high = np.float64(interval[1])
        step = np.float64(np.float64(high - low) / np.float64(event_count - 1))
        centers = [
            float(np.float64(low + np.float64(index) * step)) for index in range(event_count)
        ]
        if family_id in {"correlated_duplicate_events", "tightly_spaced_events"}:
            source_id, target_id = _middle_pair(
                event_ids, correlated=family_id == "correlated_duplicate_events"
            )
            source = event_ids.index(source_id)
            target = event_ids.index(target_id)
            if family_id == "correlated_duplicate_events":
                if resolved.get("pair_mode") == "exact_duplicate_post_noise":
                    centers[target] = centers[source]
                else:
                    gap = resolved.get("duplicate_center_gap")
                    if isinstance(gap, bool) or not isinstance(gap, (int, float)) or gap <= 0:
                        raise _fail(
                            "GENERATOR.DUPLICATE_GAP_INVALID",
                            "The correlated-event center gap is invalid.",
                        )
                    centers[target] = float(np.float64(centers[source]) + np.float64(gap))
            else:
                gap_value = resolved.get("adjacent_center_gap")
                if gap_value is None:
                    ratio = resolved.get("adjacent_center_gap_over_width")
                    width = resolved.get("transition_width")
                    if not isinstance(ratio, (int, float)) or not isinstance(width, (int, float)):
                        raise _fail(
                            "GENERATOR.TIGHT_GAP_INVALID",
                            "The tightly-spaced event gap is invalid.",
                        )
                    gap_value = np.float64(ratio) * np.float64(width)
                gap = np.float64(gap_value)
                width_scalar = np.float64(resolved.get("transition_width"))
                if not np.isfinite(gap) or gap <= 0 or gap > width_scalar:
                    raise _fail(
                        "GENERATOR.TIGHT_GAP_INVALID",
                        "The tightly-spaced event gap is outside the declared domain.",
                    )
                midpoint = np.float64(
                    np.float64(centers[source] + centers[target]) / np.float64(2.0)
                )
                centers[source] = float(np.float64(midpoint - np.float64(gap / 2.0)))
                centers[target] = float(np.float64(midpoint + np.float64(gap / 2.0)))
        elif family_id == "near_simultaneous_events":
            block_size = resolved.get("equivalence_block_size")
            if (
                not isinstance(block_size, int)
                or isinstance(block_size, bool)
                or not 2 <= block_size <= event_count
            ):
                raise _fail(
                    "GENERATOR.EQUIVALENCE_BLOCK_INVALID",
                    "The near-simultaneous block parameters are invalid.",
                )
            first = (event_count - block_size) // 2
            block = event_ids[first : first + block_size]
            ratio = resolved.get("center_gap_over_width")
            width = resolved.get("transition_width")
            if (
                not isinstance(block, list)
                or not isinstance(ratio, (int, float))
                or not isinstance(width, (int, float))
            ):
                raise _fail(
                    "GENERATOR.EQUIVALENCE_BLOCK_INVALID",
                    "The near-simultaneous block parameters are invalid.",
                )
            indexes = [event_ids.index(item) for item in block]
            midpoint = np.float64(
                np.add.reduce(np.asarray([centers[index] for index in indexes], dtype=np.float64))
                / np.float64(len(indexes))
            )
            gap = np.float64(np.float64(ratio) * np.float64(width))
            for offset, index in enumerate(indexes):
                relative = np.float64(offset) - np.float64((len(indexes) - 1) / 2.0)
                centers[index] = float(np.float64(midpoint + np.float64(relative * gap)))
        if not all(math.isfinite(value) for value in centers):
            raise _fail("GENERATOR.CENTERS_NONFINITE", "Synthetic event centers are non-finite.")
        return centers
    raise _fail(
        "GENERATOR.DERIVATION_UNIMPLEMENTED",
        "A registered synthetic field derivation is not implemented.",
    )


def _source_projection(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    family_index: int,
    family: dict[str, Any],
    variant_index: int,
    variant: dict[str, Any],
    source_owner: AuthenticatedSourceOwner | None,
) -> tuple[str, dict[str, Any] | None]:
    binding: dict[str, Any] | None = None
    if source_owner is not None:
        source = source_owner.resolved_case
        binding = {
            "source_scenario_family_id": source.coordinate.family_id,
            "source_variant_id": source.coordinate.variant_id,
            "source_replicate_index": source.coordinate.replicate_index,
            "source_resolution_mode": source.coordinate.resolution_mode,
            "resolved_parameter_manifest_sha256": source.resolved_parameter_manifest[
                "resolved_parameter_manifest_sha256"
            ],
            "field_values": {
                row.field_id: copy.deepcopy(row.resolved_value) for row in source.field_resolutions
            },
        }
    contract = _mapping(
        authority.data.get("generator_parameter_source_contract"),
        "GENERATOR.PARAMETER_SOURCE_CONTRACT_INVALID",
    )
    projection = {
        "schema_version": contract.get("schema_version"),
        "resolution_mode": coordinate.resolution_mode,
        "generator_field_registry": authority.data["generator_field_registry"],
        "common_defaults": authority.data["common_defaults"],
        "family_index": family_index,
        "family": family,
        "development_variant_index": variant_index,
        "development_variant": variant,
        "family_mechanism_closure": authority.data["family_mechanism_closure"],
        "generator_parameter_source_contract": contract,
        "heldout_family_override": None,
        "source_parameter_manifest_sha256": (
            binding["resolved_parameter_manifest_sha256"] if binding else None
        ),
        "transformed_source_binding": binding,
    }
    return structured_sha256_hex(
        "ebm-audit/generator-parameter-source-contract/1", projection
    ), binding


_NO_FAMILY_FIXED_VALUE = object()


def _development_family_fixed_value(
    field_id: str,
    definition: dict[str, Any],
    family: dict[str, Any],
) -> object:
    """Resolve only family values that the contract classifies as draw-free."""

    ranges = _mapping(family.get("allowed_ranges", {}), "GENERATOR.FAMILY_RANGE_INVALID")
    if field_id not in ranges:
        return _NO_FAMILY_FIXED_VALUE
    declared = ranges[field_id]
    allowed_form = definition.get("allowed_form")
    if allowed_form == "literal_endpoint_vector":
        return copy.deepcopy(declared)
    if allowed_form == "fixed":
        return copy.deepcopy(declared)
    if isinstance(declared, list) and len(declared) == 2 and declared[0] == declared[1]:
        return copy.deepcopy(declared[0])
    return _NO_FAMILY_FIXED_VALUE


def _resolve_fields(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    family_index: int,
    family: dict[str, Any],
    variant_index: int,
    variant: dict[str, Any],
    source_binding: dict[str, Any] | None,
) -> tuple[tuple[FieldResolution, ...], dict[str, Any]]:
    registry = authority.field_registry
    definitions = _mapping(registry.get("fields"), "GENERATOR.FIELD_REGISTRY_INVALID")
    common = _mapping(authority.data.get("common_defaults"), "GENERATOR.DEFAULTS_INVALID")
    source_contract = _mapping(
        authority.data.get("generator_parameter_source_contract"),
        "GENERATOR.PARAMETER_SOURCE_CONTRACT_INVALID",
    )
    mode_registry = _mapping(
        source_contract.get("family_mode_registry"), "GENERATOR.FAMILY_MODE_REGISTRY_INVALID"
    )
    derivations = _mapping(
        source_contract.get("derivation_registry"), "GENERATOR.DERIVATION_REGISTRY_INVALID"
    )
    family_id = coordinate.family_id
    derived_applicability = {
        "event_ids": True,
        "event_directions": True,
        "event_centers": True,
        "pair_event_ids": family_id == "correlated_duplicate_events",
        "target_pair_event_ids": family_id
        in {"correlated_duplicate_events", "tightly_spaced_events"},
        "pair_direction_rule": family_id == "correlated_duplicate_events",
        "equivalence_block_event_ids": family_id
        in {"correlated_duplicate_events", "near_simultaneous_events"},
        "wrong_direction_event_ids": family_id == "wrong_event_direction",
    }
    rows: list[FieldResolution] = []
    resolved: dict[str, Any] = {}
    for field_id in FIELD_IDS:
        definition = _mapping(definitions[field_id], "GENERATOR.FIELD_REGISTRY_INVALID")
        family_fixed_value = _development_family_fixed_value(field_id, definition, family)
        if coordinate.resolution_mode == "TRANSFORMED_SOURCE" and field_id not in (
            _TRANSFORMED_OPERATION_FIELDS
        ):
            if source_binding is None:
                raise _fail(
                    "GENERATOR.SOURCE_OWNER_REQUIRED",
                    "A transformed synthetic case lacks its authenticated source binding.",
                )
            source_kind = "TRANSFORMED_SOURCE_BINDING"
            source_reference = "authenticated-source-parameter-manifest#/field_draws/" + field_id
            value = copy.deepcopy(source_binding["field_values"][field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        elif coordinate.resolution_mode == "TRANSFORMED_SOURCE" and field_id in {
            "source_events",
            "source_participants",
        }:
            if source_binding is None:
                raise _fail(
                    "GENERATOR.SOURCE_OWNER_REQUIRED",
                    "A transformed synthetic case lacks its authenticated source binding.",
                )
            source_field = "events" if field_id == "source_events" else "participants"
            source_kind = "TRANSFORMED_SOURCE_BINDING"
            source_reference = (
                "authenticated-source-parameter-manifest#/field_draws/" + source_field
            )
            value = copy.deepcopy(source_binding["field_values"][source_field])
            resolution_source = {"kind": "FIXED", "value": value}
        elif derived_applicability.get(field_id, False):
            derivation = _mapping(derivations[field_id], "GENERATOR.DERIVATION_REGISTRY_INVALID")
            source_kind = "EVALUATOR_DERIVATION"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/generator_parameter_source_contract/derivation_registry/{field_id}",
            )
            resolution_source = {
                "kind": "DERIVED",
                "derivation_id": derivation["derivation_id"],
                "ordered_input_field_ids": copy.deepcopy(derivation["ordered_input_field_ids"]),
            }
            value = None
        elif field_id in mode_registry:
            family_modes = _mapping(
                mode_registry[field_id], "GENERATOR.FAMILY_MODE_REGISTRY_INVALID"
            )
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/generator_parameter_source_contract/family_mode_registry/{field_id}",
            )
            value = copy.deepcopy(family_modes.get(family_id, family_modes.get("default")))
            resolution_source = {"kind": "FIXED", "value": value}
        elif field_id in variant:
            source_kind = "DEVELOPMENT_VARIANT"
            source_reference = scenario_authority_source_reference(
                authority,
                (
                    f"/scenario_families/{family_index}/development_variants/"
                    f"{variant_index}/{field_id}"
                ),
            )
            value = copy.deepcopy(variant[field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        elif field_id == "truth_type":
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/scenario_families/{family_index}/truth_type",
            )
            value = copy.deepcopy(family["truth_type"])
            resolution_source = {"kind": "FIXED", "value": value}
        elif field_id in {"base_boundary_rule_id", "base_quantile_cutoff"} and field_id in family:
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/scenario_families/{family_index}/{field_id}",
            )
            value = copy.deepcopy(family[field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        elif family_fixed_value is not _NO_FAMILY_FIXED_VALUE:
            source_kind = "FAMILY_MECHANISM"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/scenario_families/{family_index}/allowed_ranges/{field_id}",
            )
            value = copy.deepcopy(family_fixed_value)
            resolution_source = {"kind": "FIXED", "value": value}
        elif field_id in common and not (
            field_id == "covariate_event_effect"
            and "event_covariate_effect"
            in _mapping(family.get("allowed_ranges", {}), "GENERATOR.FAMILY_RANGE_INVALID")
        ):
            source_kind = "COMMON_DEFAULT"
            source_reference = scenario_authority_source_reference(
                authority,
                f"/common_defaults/{field_id}",
            )
            value = copy.deepcopy(common[field_id])
            resolution_source = {"kind": "FIXED", "value": value}
        else:
            source_kind = "NOT_APPLICABLE"
            source_reference = scenario_authority_source_reference(
                authority,
                "/generator_parameter_source_contract/not_applicable_rule",
            )
            value = None
            resolution_source = {
                "kind": "NOT_APPLICABLE",
                "reason_id": f"{field_id}-not-applicable",
            }
        rows.append(
            FieldResolution(
                field_id=field_id,
                value_type=cast(str, definition["value_type"]),
                allowed_form=cast(str, definition["allowed_form"]),
                source_kind=source_kind,
                source_reference=source_reference,
                draw_rule=cast(str, definition["heldout_draw"]),
                draw_consumed=False,
                draw_index=None,
                sampled_integer=None,
                resolution_source=resolution_source,
                resolved_destination_json_pointer=None,
                resolved_value=value,
            )
        )
        resolved[field_id] = copy.deepcopy(value)

    replaced: list[FieldResolution] = []
    for row in rows:
        value = row.resolved_value
        if row.resolution_source["kind"] == "DERIVED":
            value = _derived_value(row.field_id, resolved, family_id)
            resolved[row.field_id] = copy.deepcopy(value)
        destination = _DIRECT_DESTINATIONS.get(row.field_id) if value is not None else None
        replaced.append(
            FieldResolution(
                field_id=row.field_id,
                value_type=row.value_type,
                allowed_form=row.allowed_form,
                source_kind=row.source_kind,
                source_reference=row.source_reference,
                draw_rule=row.draw_rule,
                draw_consumed=False,
                draw_index=None,
                sampled_integer=None,
                resolution_source=row.resolution_source,
                resolved_destination_json_pointer=destination,
                resolved_value=value,
            )
        )
    return tuple(replaced), resolved


def _resolve_pointer(value: object, pointer: str) -> Any:
    current = value
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise _fail(
                "GENERATOR.DEPENDENCY_POINTER_INVALID",
                "A dependency pointer does not resolve against the configuration.",
            )
    return current


def _dependency_records(
    authority: ScenarioAuthority, configuration: dict[str, Any]
) -> list[dict[str, Any]]:
    registry = _mapping(
        authority.data.get("dependency_stage_registry"),
        "GENERATOR.DEPENDENCY_REGISTRY_INVALID",
    )
    contracts = _list_of_mappings(
        registry.get("ordered_stages"), "GENERATOR.DEPENDENCY_REGISTRY_INVALID"
    )
    if len(contracts) != 7:
        raise _fail(
            "GENERATOR.DEPENDENCY_REGISTRY_DRIFT",
            "The closed dependency registry does not contain seven stages.",
        )
    result: list[dict[str, Any]] = []
    for index, contract in enumerate(contracts):
        pointers = contract.get("output_json_pointers")
        if not isinstance(pointers, list) or any(not isinstance(item, str) for item in pointers):
            raise _fail(
                "GENERATOR.DEPENDENCY_REGISTRY_INVALID",
                "A dependency output registry row is invalid.",
            )
        output_digest = structured_sha256(
            "ebm-audit/generator-dependency-output/1",
            {
                "stage": contract["stage"],
                "ordered_outputs": [
                    {
                        "json_pointer": pointer,
                        "value": copy.deepcopy(_resolve_pointer(configuration, pointer)),
                    }
                    for pointer in pointers
                ],
            },
        )
        result.append(
            {
                "stage": contract["stage"],
                "stage_index": index,
                "input_field_ids": copy.deepcopy(contract["input_field_ids"]),
                "output_json_pointers": copy.deepcopy(pointers),
                "status": contract["status"],
                "rng_draw_count": 0,
                "output_digest": output_digest,
            }
        )
    return result


def _configuration(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    values: dict[str, Any],
) -> dict[str, Any]:
    participant_count = values["participants"]
    event_count = values["events"]
    if (
        not isinstance(participant_count, int)
        or isinstance(participant_count, bool)
        or participant_count < 2
    ):
        raise _fail(
            "GENERATOR.PARTICIPANT_DIMENSION_INVALID",
            "The resolved synthetic participant count is invalid.",
        )
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or not 2 <= event_count <= 12
    ):
        raise _fail(
            "GENERATOR.EVENT_DIMENSION_INVALID",
            "The resolved synthetic event count is invalid.",
        )
    event_ids = values["event_ids"]
    directions = values["event_directions"]
    centers = _broadcast(values["event_centers"], event_count, "event_centers")
    baselines = _broadcast(values["baseline"], event_count, "baseline")
    amplitudes = _broadcast(values["amplitude"], event_count, "amplitude")
    if any(value < 0 for value in amplitudes):
        raise _fail("GENERATOR.AMPLITUDE_INVALID", "Synthetic amplitudes must be nonnegative.")
    widths = _broadcast(values["transition_width"], event_count, "transition_width", positive=True)
    covariate_source = (
        values["event_covariate_effect"]
        if values["event_covariate_effect"] is not None
        else values["covariate_event_effect"]
    )
    covariate_effects = _broadcast(covariate_source or 0.0, event_count, "covariate_effect")
    if coordinate.family_id == "covariate_confounding":
        magnitude = float(covariate_effects[0])
        covariate_effects = [
            magnitude if index % 2 == 0 else -magnitude for index in range(event_count)
        ]
    group_effects = _broadcast(values["group_event_effect"] or 0.0, event_count, "group_effect")
    loadings = _broadcast(
        values["participant_random_effect_loading"], event_count, "participant_effect_loading"
    )
    noise_sd = _broadcast(
        values["measurement_noise_sd"], event_count, "measurement_noise_sd", positive=True
    )
    correlation = values["equicorrelation"]
    if isinstance(correlation, bool) or not isinstance(correlation, (int, float)):
        raise _fail("GENERATOR.CORRELATION_INVALID", "Synthetic equicorrelation is invalid.")
    rho = float(np.float64(correlation))
    matrix = np.full((event_count, event_count), rho, dtype=np.float64)
    np.fill_diagonal(matrix, 1.0)
    pair_ids = values["pair_event_ids"] or values["target_pair_event_ids"] or []
    pair_mode = values["pair_mode"]
    if coordinate.family_id == "correlated_duplicate_events" and pair_mode == "correlated":
        expected = _middle_pair(cast(list[str], event_ids), correlated=True)
        if pair_ids != expected:
            raise _fail(
                "GENERATOR.DUPLICATE_SELECTOR_INVALID",
                "The resolved duplicate-event pair differs from the dimension-derived pair.",
            )
        pair_rho = values["duplicate_pair_correlation"]
        if isinstance(pair_rho, bool) or not isinstance(pair_rho, (int, float)):
            raise _fail(
                "GENERATOR.DUPLICATE_CORRELATION_INVALID",
                "The correlated-event pair correlation is invalid.",
            )
        left, right = (cast(list[str], event_ids).index(item) for item in expected)
        matrix[left, right] = matrix[right, left] = np.float64(pair_rho)
    if not np.array_equal(matrix, matrix.T):
        raise _fail("GENERATOR.COVARIANCE_INVALID", "The noise correlation matrix is asymmetric.")
    covariance = np.diag(noise_sd) @ matrix @ np.diag(noise_sd)
    try:
        np.linalg.cholesky(covariance)
    except np.linalg.LinAlgError as exc:
        raise _fail(
            "GENERATOR.COVARIANCE_NOT_POSITIVE_DEFINITE",
            "The synthetic noise covariance is not positive definite.",
        ) from exc

    reference_fraction = values["reference_fraction"]
    if isinstance(reference_fraction, bool) or not isinstance(reference_fraction, (int, float)):
        raise _fail(
            "GENERATOR.REFERENCE_FRACTION_INVALID",
            "The synthetic reference fraction is invalid.",
        )
    reference_fraction_float = float(np.float64(reference_fraction))
    reference_count = min(
        participant_count - 1,
        max(1, round(participant_count * reference_fraction_float)),
    )
    at_risk_count = participant_count - reference_count

    independent_window = values["latent_sampling_window"]
    if independent_window is not None:
        latent_sampling = {
            "mode": "GROUP_INDEPENDENT_WINDOW",
            "reference_window": None,
            "at_risk_window": None,
            "group_independent_window": copy.deepcopy(independent_window),
        }
    else:
        latent_sampling = {
            "mode": "GROUP_WINDOWS",
            "reference_window": copy.deepcopy(values["reference_sampling_window"]),
            "at_risk_window": copy.deepcopy(values["at_risk_sampling_window"]),
            "group_independent_window": None,
        }

    missing_family = values["missingness"]
    if missing_family == "MCAR":
        if values["event_missing_probabilities"] is not None:
            event_probabilities = _broadcast(
                values["event_missing_probabilities"], event_count, "event_missing_probabilities"
            )
        else:
            event_probabilities = _broadcast(
                values["event_missing_probability"], event_count, "event_missing_probability"
            )
    else:
        event_probabilities = [0.0] * event_count
    if any(not 0 <= value <= 1 for value in event_probabilities):
        raise _fail(
            "GENERATOR.MISSINGNESS_PROBABILITY_INVALID",
            "A synthetic missingness probability is outside zero to one.",
        )

    boundary_ids = copy.deepcopy(values["boundary_rule_ids"] or [])
    boundary_shifts = [float(item) for item in (values["boundary_quantile_shifts"] or [])]
    base_cutoff = values["base_quantile_cutoff"] if boundary_ids else None
    if len(boundary_ids) != len(boundary_shifts):
        raise _fail(
            "GENERATOR.BOUNDARY_RULES_INVALID",
            "Synthetic boundary rule IDs and shifts are misaligned.",
        )
    if base_cutoff is not None and (
        isinstance(base_cutoff, bool)
        or not isinstance(base_cutoff, (int, float))
        or not 0 < base_cutoff < 1
    ):
        raise _fail(
            "GENERATOR.BOUNDARY_RULES_INVALID",
            "The synthetic base boundary cutoff is invalid.",
        )

    analysis_directions = list(directions)
    wrong_ids = values["wrong_direction_event_ids"] or []
    for event_id in wrong_ids:
        index = cast(list[str], event_ids).index(event_id)
        analysis_directions[index] = "lower" if analysis_directions[index] == "higher" else "higher"

    preimage: dict[str, Any] = {
        "schema_version": "ebm-audit-resolved-generator-configuration/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "synthetic_marker": "SYNTHETIC",
        "scenario_family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "dimensions": {
            "participant_count": participant_count,
            "event_count": event_count,
        },
        "event_ids": copy.deepcopy(event_ids),
        "event_directions": copy.deepcopy(directions),
        "event_parameters": {
            "baseline": baselines,
            "amplitude": amplitudes,
            "transition_width": widths,
            "event_centers": centers,
            "covariate_effect": covariate_effects,
            "group_effect": group_effects,
            "participant_effect_loading": loadings,
        },
        "measurement_noise": {
            "family": values["measurement_noise_family"],
            "standard_deviations": noise_sd,
            "equicorrelation": rho,
            "correlation_matrix": matrix.tolist(),
            "student_t_df": values["student_t_df"],
            "centered_lognormal_sigma": values["centered_lognormal_sigma"],
            "centered_lognormal_weight": values["centered_lognormal_weight"],
        },
        "latent_sampling": latent_sampling,
        "group_generation": {
            "reference_fraction": reference_fraction_float,
            "reference_count": reference_count,
            "at_risk_count": at_risk_count,
            "boundary_rule_id": boundary_ids[0] if boundary_ids else None,
            "quantile_cutoff": float(base_cutoff) if base_cutoff is not None else None,
        },
        "covariates": {
            "mode": values["covariates"],
            "standardized_group_difference": (
                values["standardized_group_covariate_difference"]
                if values["covariates"] == "one_group_shifted_normal"
                else None
            ),
        },
        "participant_effect": {
            "standard_deviation": float(values["participant_random_effect_sd"]),
        },
        "missingness": {
            "family": missing_family,
            "event_probabilities": event_probabilities,
            "marginal_probability": (
                values["marginal_missing_probability"] if missing_family == "MAR" else None
            ),
            "covariate_log_odds_coefficient": (
                values["covariate_log_odds_coefficient"] if missing_family == "MAR" else None
            ),
            "group_log_odds_coefficient": (
                values["group_log_odds_coefficient"] if missing_family == "MAR" else None
            ),
        },
        "outliers": {
            "mode": values["outliers"],
            "injected_participant_count": int(values["injected_participants"] or 0),
            "affected_event_count": int(values["affected_events"] or 0),
            "offset_noise_sd": (
                float(values["offset_noise_sd"]) if values["outliers"] != "none" else None
            ),
        },
        "scenario_parameters": {
            "truth_type": values["truth_type"],
            "pair_mode": pair_mode,
            "pair_event_ids": copy.deepcopy(pair_ids),
            "equivalence_block_event_ids": copy.deepcopy(
                values["equivalence_block_event_ids"] or []
            ),
            "alternate_inversions": values["alternate_inversions"],
            "minority_fraction": values["minority_fraction"],
            "opposing_relation_fraction": values["opposing_relation_fraction"],
            "contamination_fraction": values["contamination_fraction"],
            "wrong_direction_event_ids": copy.deepcopy(wrong_ids),
            "measurement_noise_sd_levels": [
                float(item) for item in (values["measurement_noise_sd_levels"] or [])
            ],
            "boundary_rule_ids": boundary_ids,
            "boundary_quantile_shifts": boundary_shifts,
            "base_quantile_cutoff": float(base_cutoff) if base_cutoff is not None else None,
        },
        "analysis_configuration": {
            "reference_only_residualisation": False,
            "event_spec_directions": analysis_directions,
            "mcmc_profile_id": "characterization_2000",
        },
        "dependency_records": [],
        "resolved_generator_configuration_sha256": None,
    }
    preimage["dependency_records"] = _dependency_records(authority, preimage)
    configuration = _persisted_record(
        preimage,
        "resolved_generator_configuration_sha256",
        "ebm-audit/resolved-generator-configuration/1",
    )
    _validate_schema(configuration, definition="ResolvedGeneratorConfiguration")
    return configuration


def _lehmer_order(event_ids: list[str], inversions: int) -> list[str]:
    maximum = len(event_ids) * (len(event_ids) - 1) // 2
    if not 0 <= inversions <= maximum:
        raise _fail(
            "GENERATOR.ALTERNATE_ORDER_INVALID",
            "The requested alternate-order inversion count is invalid.",
        )
    remaining = list(event_ids)
    output: list[str] = []
    left = inversions
    while remaining:
        index = min(left, len(remaining) - 1)
        output.append(remaining.pop(index))
        left -= index
    return output


def _affected_tails(
    authority: ScenarioAuthority, configuration: dict[str, Any]
) -> tuple[list[str], list[str]]:
    if configuration["scenario_family_id"] != "incomplete_time_coverage":
        return [], []
    defaults = _mapping(authority.data["common_defaults"], "GENERATOR.DEFAULTS_INVALID")
    broad_low = min(
        defaults["reference_sampling_window"][0], defaults["at_risk_sampling_window"][0]
    )
    broad_high = max(
        defaults["reference_sampling_window"][1], defaults["at_risk_sampling_window"][1]
    )
    latent = configuration["latent_sampling"]
    restricted_low = min(latent["reference_window"][0], latent["at_risk_window"][0])
    restricted_high = max(latent["reference_window"][1], latent["at_risk_window"][1])
    event_parameters = configuration["event_parameters"]
    affected: list[str] = []
    sides: list[str] = []
    for event_id, center, width in zip(
        configuration["event_ids"],
        event_parameters["event_centers"],
        event_parameters["transition_width"],
        strict=True,
    ):
        broad_normal = broad_low <= center - 2.0 * width
        broad_abnormal = broad_high >= center + 2.0 * width
        restricted_normal = restricted_low <= center - 2.0 * width
        restricted_abnormal = restricted_high >= center + 2.0 * width
        missing_normal = broad_normal and not restricted_normal
        missing_abnormal = broad_abnormal and not restricted_abnormal
        if missing_normal or missing_abnormal:
            affected.append(event_id)
            sides.append(
                "BOTH"
                if missing_normal and missing_abnormal
                else "NORMAL"
                if missing_normal
                else "ABNORMAL"
            )
    return affected, sides


def _mechanism(
    authority: ScenarioAuthority,
    configuration: dict[str, Any],
) -> dict[str, Any]:
    family_id = configuration["scenario_family_id"]
    event_ids = cast(list[str], configuration["event_ids"])
    parameters = configuration["scenario_parameters"]
    pair_mode = parameters["pair_mode"]
    if family_id == "minority_alternate_sequence":
        mechanism_kind = "MINORITY_ALTERNATE_SEQUENCE"
        alternate = _lehmer_order(event_ids, int(parameters["alternate_inversions"]))
        subgroup_orders = [event_ids, alternate]
        identifiable = False
    elif family_id == "opposing_sequences_50_50":
        mechanism_kind = "OPPOSING_SEQUENCES_50_50"
        inversions = round(
            float(parameters["opposing_relation_fraction"])
            * (len(event_ids) * (len(event_ids) - 1) // 2)
        )
        subgroup_orders = [event_ids, _lehmer_order(event_ids, inversions)]
        identifiable = False
    elif family_id == "near_simultaneous_events":
        mechanism_kind = "EQUIVALENCE_BLOCKS"
        subgroup_orders = []
        identifiable = False
    elif family_id == "correlated_duplicate_events" and pair_mode == "exact_duplicate_post_noise":
        mechanism_kind = "EXACT_DUPLICATE_POST_NOISE"
        subgroup_orders = []
        identifiable = False
    elif family_id == "control_contamination":
        mechanism_kind = "LABEL_CONTAMINATION"
        subgroup_orders = []
        identifiable = True
    elif family_id in _OPERATION_PATHS:
        mechanism_kind = "REFITTED_NULL_TRANSFORMATION"
        subgroup_orders = []
        identifiable = False
    elif family_id == "pure_no_signal":
        mechanism_kind = "PURE_NO_SIGNAL"
        subgroup_orders = []
        identifiable = False
    else:
        mechanism_kind = "STRICT_TOTAL_ORDER"
        subgroup_orders = []
        identifiable = True
    affected, _ = _affected_tails(authority, configuration)
    dependency_records = configuration["dependency_records"]
    preimage = {
        "schema_version": "ebm-audit-resolved-generator-mechanism/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "scenario_family_id": family_id,
        "mechanism_kind": mechanism_kind,
        "strict_order_identifiable": identifiable,
        "base_order": event_ids if mechanism_kind != "PURE_NO_SIGNAL" else [],
        "subgroup_orders": subgroup_orders,
        "equivalence_blocks": (
            [parameters["equivalence_block_event_ids"]]
            if parameters["equivalence_block_event_ids"]
            else []
        ),
        "target_event_ids": parameters["pair_event_ids"],
        "affected_tail_event_ids": affected,
        "wrong_direction_event_ids": parameters["wrong_direction_event_ids"],
        "pre_root_stratum_id": None,
        "group_indicator_encoding": {"reference": 0, "at_risk": 1},
        "group_effect_application": (
            "gamma_i_times_binary_group_indicator_before_participant_and_noise"
        ),
        "group_effect_dependency_stage": "event_arrays",
        "group_effect_rng_draw_count": 0,
        "dependency_records_sha256": structured_sha256_hex(
            "ebm-audit/scenario-generator-dependencies/1", dependency_records
        ),
        "resolved_generator_mechanism_sha256": None,
    }
    mechanism = _persisted_record(
        preimage,
        "resolved_generator_mechanism_sha256",
        "ebm-audit/resolved-generator-mechanism/1",
    )
    _validate_schema(mechanism, definition="ResolvedGeneratorMechanism")
    return mechanism


def _validate_source_owner(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    family: dict[str, Any],
    variant: dict[str, Any],
    source_owner: AuthenticatedSourceOwner | None,
) -> None:
    if coordinate.resolution_mode == "DEVELOPMENT_VARIANT":
        if source_owner is not None:
            raise _fail(
                "GENERATOR.SOURCE_OWNER_UNDECLARED",
                "An ordinary synthetic case carries an undeclared source owner.",
            )
        return
    if source_owner is None or coordinate.family_id not in _OPERATION_PATHS:
        raise _fail(
            "GENERATOR.SOURCE_OWNER_REQUIRED",
            "A transformed synthetic case requires an authenticated source owner.",
        )
    source = source_owner.resolved_case
    # A source manifest is not authority merely because it is internally
    # self-consistent.  Reconstruct the complete ordinary source from the same
    # exact evaluator bytes before copying even one field from it.
    verify_exact_resolution(authority, source)
    expected_reference = f"{source.coordinate.family_id}/{source.coordinate.variant_id}"
    if (
        family.get("source_family") != source.coordinate.family_id
        or variant.get("source_variant") != expected_reference
        or source.coordinate.replicate_index != coordinate.replicate_index
        or source.coordinate.resolution_mode != "DEVELOPMENT_VARIANT"
        or tuple(row.field_id for row in source.field_resolutions) != FIELD_IDS
        or [row.as_dict() for row in source.field_resolutions]
        != source.resolved_parameter_manifest.get("field_draws")
        or source.resolution_bundle.get("resolved_parameter_manifest")
        != source.resolved_parameter_manifest
        or source.resolution_bundle.get("resolved_configuration") != source.resolved_configuration
    ):
        raise _fail(
            "GENERATOR.SOURCE_OWNER_MISMATCH",
            "The authenticated source owner differs from the null-operation plan.",
        )
    _validate_schema(source.resolved_parameter_manifest, definition="ResolvedParameterManifest")


def resolve_development_case(
    authority: ScenarioAuthority,
    coordinate: CaseCoordinate,
    *,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> ResolvedSyntheticCase:
    """Independently reconstruct one ordinary or source-bound-null plan."""

    if coordinate.resolution_mode not in {"DEVELOPMENT_VARIANT", "TRANSFORMED_SOURCE"}:
        if "MATCHED_COMPARATOR" in str(coordinate.resolution_mode):
            raise _fail(
                "GENERATOR.MATCHED_COMPARATOR_UNAVAILABLE",
                "Matched comparator generation requires its authenticated transaction owner.",
            )
        raise _fail(
            "GENERATOR.RESOLUTION_MODE_UNSUPPORTED",
            "The requested synthetic resolution mode is unsupported.",
        )
    strict_authority = load_scenario_authority(authority.exact_bytes)
    if authority != strict_authority:
        raise _fail(
            "GENERATOR.AUTHORITY_OBJECT_MISMATCH",
            "The scenario authority object differs from its exact source bytes.",
        )
    authority = strict_authority

    family_index, family, variant_index, variant = _family_and_variant(authority, coordinate)
    _validate_source_owner(authority, coordinate, family, variant, source_owner)
    case_seed = _case_seed(authority, coordinate)
    source_case_id = source_owner.resolved_case.case_id if source_owner is not None else None
    components, component_manifest, operation_seed = _component_manifest(
        authority, coordinate, case_seed, source_case_id
    )
    source_contract_sha256, source_binding = _source_projection(
        authority,
        coordinate,
        family_index,
        family,
        variant_index,
        variant,
        source_owner,
    )
    field_rows, values = _resolve_fields(
        authority,
        coordinate,
        family_index,
        family,
        variant_index,
        variant,
        source_binding,
    )
    if tuple(row.field_id for row in field_rows) != FIELD_IDS:
        raise _fail(
            "GENERATOR.FIELD_LEDGER_INVALID",
            "The reconstructed field ledger is incomplete or reordered.",
        )
    parameters_seed = next(row.seed_128 for row in components if row.component_path == "parameters")
    parameter_preimage = {
        "schema_version": "ebm-audit-resolved-parameter-manifest/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "scenario_family_id": coordinate.family_id,
        "variant_id": coordinate.variant_id,
        "replicate_index": coordinate.replicate_index,
        "resolution_mode": coordinate.resolution_mode,
        "source_contract_sha256": source_contract_sha256,
        "source_parameter_manifest_sha256": (
            source_binding["resolved_parameter_manifest_sha256"] if source_binding else None
        ),
        "ordered_field_ids": list(FIELD_IDS),
        "field_draws": [row.as_dict() for row in field_rows],
        "parameter_draw_count": 0,
        "parameters_component_seed": parameters_seed,
        "resolved_parameter_manifest_sha256": None,
    }
    parameter_manifest = _persisted_record(
        parameter_preimage,
        "resolved_parameter_manifest_sha256",
        "ebm-audit/resolved-parameter-manifest/1",
    )
    _validate_schema(parameter_manifest, definition="ResolvedParameterManifest")
    configuration = _configuration(authority, coordinate, values)
    verify_pure_no_signal_semantics(configuration)
    mechanism = _mechanism(authority, configuration)
    bundle = {
        "schema_version": "ebm-audit-synthetic-resolution-bundle/1.0",
        "resolved_configuration": configuration,
        "resolved_parameter_manifest": parameter_manifest,
        "resolved_generator_mechanism": mechanism,
        "component_seed_manifest": component_manifest,
    }
    _validate_schema(bundle)
    case_id = f"{coordinate.family_id}-v{variant_index}-r{coordinate.replicate_index}"
    return ResolvedSyntheticCase(
        coordinate=coordinate,
        variant_index=variant_index,
        case_id=case_id,
        case_seed=case_seed,
        shared_draw_seed=None,
        operation_seed=operation_seed,
        source_contract_sha256=source_contract_sha256,
        scenario_definitions_sha256=authority.definitions_sha256,
        field_resolutions=field_rows,
        component_seeds=components,
        component_seed_manifest=component_manifest,
        resolved_parameter_manifest=parameter_manifest,
        resolved_configuration=configuration,
        resolved_mechanism=mechanism,
        resolution_bundle=bundle,
    )


def verify_exact_resolution(
    authority: ScenarioAuthority,
    candidate: ResolvedSyntheticCase,
    *,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> None:
    """Reconstruct and byte-compare all schema-facing resolution owners."""

    expected = resolve_development_case(
        authority,
        candidate.coordinate,
        source_owner=source_owner,
    )
    if candidate != expected:
        raise _fail(
            "GENERATOR.RESOLUTION_REPLAY_MISMATCH",
            "The submitted synthetic resolution differs from evaluator reconstruction.",
        )
