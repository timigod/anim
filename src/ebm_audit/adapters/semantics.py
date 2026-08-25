"""Fail-closed semantic validation for successful worker results.

JSON Schema and exact file hashes prove shape declarations and byte ownership.
They do not prove that an array is a permutation, a probability distribution,
or the output that the request and advertised capabilities actually authorize.
This module owns those production invocation invariants; evaluator fixtures are
deliberately not imported by the runtime package.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

import numpy as np

from ebm_audit.errors import WorkerProtocolError
from ebm_audit.protocol import stage_semantics_digest, structured_sha256
from ebm_audit.schema import load_protocol_registry

_ABSOLUTE_TOLERANCE = 1e-12
_RELATIVE_TOLERANCE = 1e-10

_FIXED_COHORT_OUTPUTS = (
    "evaluation_stage_posterior",
    "evaluation_hard_stages",
    "evaluation_expected_stage",
)
_FIXED_COHORT_REASON = "STAGING.FIXED_COHORT_UNAVAILABLE"
_EXACT_FIXED_TARGET_OUTPUT = "exact_fixed_order_target"
_EXACT_FIXED_TARGET_REFERENCE_DIGEST_DOMAIN = "ebm-audit/exact-fixed-target-reference/1"
_EXACT_FIXED_TARGET_ARITHMETIC_ID = (
    "kde-ebm-0.0.3-uniform-order-posterior-binary64-uniform-stage-plus-1e-250/2"
)
_EXACT_FIXED_TARGET_MEMBERS = (
    (
        "position_probabilities_binding",
        ".exact-fixed-target-position-probabilities",
        "exact-fixed-order-target-event-position-probability/1",
    ),
    (
        "pairwise_precedence_binding",
        ".exact-fixed-target-pairwise-precedence",
        "exact-fixed-order-target-pairwise-precedence-probability/1",
    ),
)

_FIT_CANONICAL_ARRAYS = frozenset(
    {
        "central_order_permutation",
        "postburn_order_state_chain",
        "postburn_likelihood_trace",
        "order_state_chain",
        "likelihood_trace",
        "postburn_state_change_mask",
        "position_probabilities",
        "pairwise_precedence",
        "training_row_indexes",
        "training_stage_posterior",
        "training_map_stage",
        "training_map_tie_mask",
        "training_expected_stage",
        "evaluation_row_indexes",
        "evaluation_stage_posterior",
        "evaluation_map_stage",
        "evaluation_map_tie_mask",
        "evaluation_expected_stage",
    }
)
_FIT_STAGE_VALUE_ARRAYS = frozenset(
    {
        "training_stage_posterior",
        "training_map_stage",
        "training_map_tie_mask",
        "training_expected_stage",
        "evaluation_stage_posterior",
        "evaluation_map_stage",
        "evaluation_map_tie_mask",
        "evaluation_expected_stage",
    }
)
_STAGE_CANONICAL_ARRAYS = frozenset(
    {
        "stage_row_indexes",
        "stage_posterior",
        "stage_map_stage",
        "stage_map_tie_mask",
        "stage_expected_stage",
    }
)

_V2_WORKER_COMMANDS = ["describe", "validate", "fit", "self-test"]
_V2_REQUIRED_ALGORITHM_COMMANDS = ["validate", "fit"]


@dataclass(eq=False)
class _SemanticViolation(Exception):
    rule_id: str


def _require(condition: bool, rule_id: str) -> None:
    if not condition:
        raise _SemanticViolation(rule_id)


def _array(value: Any) -> np.ndarray[Any, Any]:
    return np.asarray(value)


def _dtype_shape(
    arrays: Mapping[str, Any],
    name: str,
    dtype: str,
    shape: tuple[int, ...],
) -> np.ndarray[Any, Any]:
    value = _array(arrays[name])
    _require(value.dtype.name == dtype, "ARRAY.DTYPE")
    _require(value.shape == shape, "ARRAY.SHAPE")
    if dtype == "float64":
        _require(bool(np.isfinite(value).all()), "ARRAY.NONFINITE")
    return value


def _close(left: Any, right: Any) -> bool:
    return bool(
        np.allclose(
            left,
            right,
            rtol=_RELATIVE_TOLERANCE,
            atol=_ABSOLUTE_TOLERANCE,
        )
    )


def _permutation_rows(value: np.ndarray[Any, Any], event_count: int) -> None:
    rows = value.reshape((-1, event_count))
    expected = np.arange(event_count, dtype=value.dtype)
    _require(
        all(bool(np.array_equal(np.sort(row), expected)) for row in rows),
        "ORDER.NOT_PERMUTATION",
    )


def _registry_rows(command: str) -> dict[str, Mapping[str, Any]]:
    return {
        str(row["output_id"]): row
        for row in load_protocol_registry()["requested_outputs"]
        if command in row["commands"]
    }


def _expected_component_applicability(
    command: str,
    requested_outputs: Sequence[str],
    capabilities: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], set[str]]:
    rows = _registry_rows(command)
    unavailable_fixed: set[str] = set()
    _require(len(requested_outputs) == len(set(requested_outputs)), "OUTPUT.DUPLICATE")
    for output_id in requested_outputs:
        row = rows.get(output_id)
        if row is None:
            raise _SemanticViolation("OUTPUT.NOT_REGISTERED_FOR_COMMAND")
        missing = [
            capability
            for capability in row["required_capabilities"]
            if capabilities.get(capability) is not True
        ]
        if not missing:
            continue
        component_scoped = (
            row.get("capability_absence_behavior") == "FIXED_COHORT_STAGE_COMPONENT_NOT_APPLICABLE"
            and missing == ["fixed_evaluation_cohort_staging"]
            and output_id in _FIXED_COHORT_OUTPUTS
        )
        _require(component_scoped, "CAPABILITY.REQUESTED_OUTPUT_UNAVAILABLE")
        unavailable_fixed.add(output_id)
    expected = [
        {
            "output_id": output_id,
            "status": "NOT_APPLICABLE_BY_CAPABILITY",
            "value": None,
            "reason_code": _FIXED_COHORT_REASON,
        }
        for output_id in _FIXED_COHORT_OUTPUTS
        if output_id in unavailable_fixed
    ]
    return expected, unavailable_fixed


def _expected_fit_arrays(
    requested_outputs: Sequence[str],
    unavailable_fixed: set[str],
) -> tuple[set[str], bool, bool]:
    rows = _registry_rows("fit")
    expected: set[str] = set()
    private_distributions_requested = False
    portable_artifact_requested = False
    for output_id in requested_outputs:
        if output_id in unavailable_fixed:
            continue
        if output_id == _EXACT_FIXED_TARGET_OUTPUT:
            continue
        for member_name in rows[output_id]["result_members"]:
            if member_name == "backend.<adapter_id>.<declared-name>":
                private_distributions_requested = True
            elif member_name == "backend_artifacts":
                portable_artifact_requested = True
            elif member_name not in {
                "actual_transition_count",
                "actual_transition_fraction",
            }:
                expected.add(str(member_name))
    return expected, private_distributions_requested, portable_artifact_requested


def _validate_exact_fixed_target_reference(
    result: Mapping[str, Any],
    arrays: Mapping[str, Any],
    event_ids: Sequence[str],
    participant_count: int,
    *,
    requested: bool,
) -> set[str]:
    catalog = result["array_catalog"]
    reference = result.get("exact_fixed_target_reference")
    target_semantics = {
        semantic_version
        for _binding_name, _member_suffix, semantic_version in _EXACT_FIXED_TARGET_MEMBERS
    }
    target_suffixes = {
        member_suffix
        for _binding_name, member_suffix, _semantic_version in _EXACT_FIXED_TARGET_MEMBERS
    }
    present_names = {
        str(name)
        for name, entry in catalog.items()
        if (
            str(entry["semantic_version"]) in target_semantics
            or any(str(name).endswith(suffix) for suffix in target_suffixes)
        )
    }
    if not requested:
        _require(reference is None, "EXACT_TARGET.UNREQUESTED_REFERENCE")
        _require(not present_names, "EXACT_TARGET.UNREQUESTED_ARRAY")
        return set()

    _require(isinstance(reference, Mapping), "EXACT_TARGET.REFERENCE_REQUIRED")
    reference = cast(Mapping[str, Any], reference)
    preimage = dict(reference)
    supplied_digest = preimage.pop("exact_fixed_target_reference_digest")
    _require(
        supplied_digest
        == structured_sha256(
            _EXACT_FIXED_TARGET_REFERENCE_DIGEST_DOMAIN,
            preimage,
        ),
        "EXACT_TARGET.REFERENCE_DIGEST",
    )
    event_count = len(event_ids)
    _require(
        reference["requested_output_id"] == _EXACT_FIXED_TARGET_OUTPUT
        and reference["target_arithmetic_id"] == _EXACT_FIXED_TARGET_ARITHMETIC_ID
        and reference["event_ids"] == list(event_ids)
        and reference["native_probability_matrix_shape"] == [participant_count, event_count, 2]
        and reference["native_probability_matrix_dtype"] == "float64"
        and reference["native_probability_matrix_order"] == "C"
        and reference["component_axis"] == ["non-event-density", "event-density"]
        and reference["order_count"] == math.factorial(event_count),
        "EXACT_TARGET.REFERENCE_OWNER",
    )
    even_mass = reference["even_permutation_mass"]
    _require(
        np.isfinite(even_mass) and 0.0 <= even_mass <= 1.0,
        "EXACT_TARGET.EVEN_MASS",
    )

    names: list[str] = []
    for binding_name, member_suffix, semantic_version in _EXACT_FIXED_TARGET_MEMBERS:
        binding = reference[binding_name]
        name = str(binding["member_name"])
        names.append(name)
        _require(
            name.startswith("backend.")
            and name.endswith(member_suffix)
            and name in arrays
            and name in catalog
            and catalog[name]["semantic_version"] == semantic_version
            and catalog[name]["array_digest"] == binding["array_digest"],
            "EXACT_TARGET.REFERENCE_ARRAY_BINDING",
        )
    _require(
        len(names) == len(set(names)) and set(names) == present_names,
        "EXACT_TARGET.ARRAY_SET",
    )

    position = _dtype_shape(
        arrays,
        names[0],
        "float64",
        (event_count, event_count),
    )
    pairwise = _dtype_shape(
        arrays,
        names[1],
        "float64",
        (event_count, event_count),
    )
    ones = np.ones(event_count, dtype=np.float64)
    _require(
        bool(np.all((position >= 0.0) & (position <= 1.0)))
        and _close(position.sum(axis=1), ones)
        and _close(position.sum(axis=0), ones),
        "EXACT_TARGET.POSITION",
    )
    _require(
        bool(np.all((pairwise >= 0.0) & (pairwise <= 1.0)))
        and _close(np.diag(pairwise), np.full(event_count, 0.5))
        and _close(pairwise + pairwise.T, np.ones((event_count, event_count))),
        "EXACT_TARGET.PAIRWISE",
    )

    matrix_digest = reference["native_probability_matrix_digest"]
    for name in names:
        origin = result["field_origins"][name]
        _require(
            origin["origin"] == "WORKER_DERIVED"
            and "exact_fixed_target_reference" in origin["source_fields"]
            and any(
                str(field).endswith(".native-probability-matrix")
                for field in origin["source_fields"]
            )
            and supplied_digest in origin["source_hashes"]
            and matrix_digest in origin["source_hashes"],
            "EXACT_TARGET.FIELD_ORIGIN_BINDING",
        )
    return set(names)


def _validate_stage_semantics_owner(
    dataset: Mapping[str, Any],
    algorithm: Mapping[str, Any],
) -> Mapping[str, Any]:
    definition = algorithm["stage_semantics_definition"]
    _require(isinstance(definition, Mapping), "STAGE.SEMANTICS_DEFINITION")
    observed_digest = stage_semantics_digest(definition)
    _require(
        algorithm["stage_semantics_digest"] == observed_digest
        and dataset["stage_semantics_digest"] == observed_digest,
        "STAGE.SEMANTICS_OWNER",
    )
    return cast(Mapping[str, Any], definition)


def _validate_row_indexes(
    arrays: Mapping[str, Any],
    request_arrays: Mapping[str, Any],
    name: str,
    count: int,
) -> None:
    output = _dtype_shape(arrays, name, "int64", (count,))
    request = _dtype_shape(request_arrays, name, "int64", (count,))
    expected = np.arange(count, dtype=np.int64)
    _require(bool(np.array_equal(request, expected)), "ROW_INDEX.REQUEST_NOT_CONTIGUOUS")
    _require(bool(np.array_equal(output, request)), "ROW_INDEX.RESPONSE_MISMATCH")


def _validate_stage_family(
    arrays: Mapping[str, Any],
    *,
    prefix: str,
    participant_count: int,
    event_count: int,
) -> None:
    posterior_name = f"{prefix}_stage_posterior"
    map_name = f"{prefix}_map_stage"
    tie_name = f"{prefix}_map_tie_mask"
    expected_name = f"{prefix}_expected_stage"
    posterior = None
    if posterior_name in arrays:
        posterior = _dtype_shape(
            arrays,
            posterior_name,
            "float64",
            (participant_count, event_count + 1),
        )
        _require(bool(np.all(posterior >= 0.0)), "STAGE.POSTERIOR_NEGATIVE")
        _require(bool(np.all(posterior <= 1.0)), "STAGE.POSTERIOR_ABOVE_ONE")
        _require(
            _close(posterior.sum(axis=1), np.ones(participant_count)),
            "STAGE.POSTERIOR_NOT_NORMALIZED",
        )

    map_stage = None
    tie_mask = None
    if map_name in arrays or tie_name in arrays:
        _require(map_name in arrays and tie_name in arrays, "STAGE.HARD_STAGE_INCOMPLETE")
        map_stage = _dtype_shape(arrays, map_name, "int32", (participant_count,))
        tie_mask = _dtype_shape(
            arrays,
            tie_name,
            "bool",
            (participant_count, event_count + 1),
        )
        _require(
            bool(np.all((map_stage >= 0) & (map_stage <= event_count))),
            "STAGE.MAP_OUT_OF_RANGE",
        )
        if participant_count:
            _require(bool(np.all(tie_mask.any(axis=1))), "STAGE.TIE_MASK_EMPTY")
            derived_map = np.argmax(tie_mask, axis=1).astype(np.int32)
            _require(bool(np.array_equal(map_stage, derived_map)), "STAGE.MAP_TIE_MISMATCH")

    if posterior is not None and tie_mask is not None and map_stage is not None:
        maxima = posterior.max(axis=1, keepdims=True)
        derived_ties = posterior == maxima
        _require(bool(np.array_equal(tie_mask, derived_ties)), "STAGE.TIE_POSTERIOR_MISMATCH")
        _require(
            bool(np.array_equal(map_stage, np.argmax(derived_ties, axis=1))),
            "STAGE.MAP_POSTERIOR_MISMATCH",
        )

    if expected_name in arrays:
        expected_stage = _dtype_shape(
            arrays,
            expected_name,
            "float64",
            (participant_count,),
        )
        _require(
            bool(np.all((expected_stage >= 0.0) & (expected_stage <= event_count))),
            "STAGE.EXPECTED_OUT_OF_RANGE",
        )
        if posterior is not None:
            stage_axis = np.arange(event_count + 1, dtype=np.float64)
            _require(
                _close(expected_stage, posterior @ stage_axis),
                "STAGE.EXPECTED_POSTERIOR_MISMATCH",
            )


def _validate_probability_matrices(
    arrays: Mapping[str, Any],
    event_count: int,
) -> None:
    if "position_probabilities" in arrays:
        position = _dtype_shape(
            arrays,
            "position_probabilities",
            "float64",
            (event_count, event_count),
        )
        _require(bool(np.all(position >= 0.0)), "POSITION.NEGATIVE")
        _require(bool(np.all(position <= 1.0)), "POSITION.ABOVE_ONE")
        ones = np.ones(event_count)
        _require(
            _close(position.sum(axis=1), ones) and _close(position.sum(axis=0), ones),
            "POSITION.NOT_DOUBLY_NORMALIZED",
        )

    if "pairwise_precedence" in arrays:
        pairwise = _dtype_shape(
            arrays,
            "pairwise_precedence",
            "float64",
            (event_count, event_count),
        )
        _require(
            bool(np.all((pairwise >= 0.0) & (pairwise <= 1.0))),
            "PAIRWISE.OUT_OF_RANGE",
        )
        _require(
            _close(np.diag(pairwise), np.full(event_count, 0.5)),
            "PAIRWISE.DIAGONAL",
        )
        _require(
            _close(pairwise + pairwise.T, np.ones((event_count, event_count))),
            "PAIRWISE.NOT_COMPLEMENTARY",
        )


def _derived_position(chain: np.ndarray[Any, Any], event_count: int) -> np.ndarray[Any, Any]:
    result = np.zeros((event_count, event_count), dtype=np.float64)
    positions = np.arange(event_count)
    for state in chain:
        result[state, positions] += 1.0
    return result / float(chain.shape[0])


def _derived_pairwise(chain: np.ndarray[Any, Any], event_count: int) -> np.ndarray[Any, Any]:
    result = np.zeros((event_count, event_count), dtype=np.float64)
    positions = np.empty(event_count, dtype=np.int64)
    event_axis = np.arange(event_count)
    for state in chain:
        positions[state] = event_axis
        result += positions[:, None] < positions[None, :]
    result /= float(chain.shape[0])
    np.fill_diagonal(result, 0.5)
    return result


def _validate_chain_arrays(
    result: Mapping[str, Any],
    arrays: Mapping[str, Any],
    event_ids: Sequence[str],
) -> None:
    event_count = len(event_ids)
    schedule_names = (
        "raw_iteration_count",
        "burn_in_count",
        "thinning_interval",
        "postburn_unthinned_state_count",
        "retained_state_count",
    )
    schedule = tuple(result[name] for name in schedule_names)
    complete_schedule = all(value is not None for value in schedule)
    _require(
        complete_schedule or all(value is None for value in schedule),
        "CHAIN.PARTIAL_SCHEDULE",
    )
    if complete_schedule:
        raw, burn, thin, postburn_count, retained_count = (int(value) for value in schedule)
        _require(raw >= 1 and 0 <= burn < raw and thin >= 1, "CHAIN.SCHEDULE_RANGE")
        _require(postburn_count == raw - burn, "CHAIN.POSTBURN_COUNT")
        expected_retained = ((raw - 1 - burn) // thin) + 1
        _require(retained_count == expected_retained, "CHAIN.RETAINED_COUNT")
    else:
        postburn_count = 0
        retained_count = 0
        thin = 1

    postburn_chain = None
    retained_chain = None
    if "postburn_order_state_chain" in arrays or "order_state_chain" in arrays:
        _require(
            "postburn_order_state_chain" in arrays and "order_state_chain" in arrays,
            "CHAIN.ORDER_SAMPLE_PAIR",
        )
        _require(complete_schedule, "CHAIN.ORDER_SAMPLE_WITHOUT_SCHEDULE")
        postburn_chain = _dtype_shape(
            arrays,
            "postburn_order_state_chain",
            "int32",
            (postburn_count, event_count),
        )
        retained_chain = _dtype_shape(
            arrays,
            "order_state_chain",
            "int32",
            (retained_count, event_count),
        )
        _permutation_rows(postburn_chain, event_count)
        _permutation_rows(retained_chain, event_count)
        _require(
            bool(np.array_equal(retained_chain, postburn_chain[::thin])),
            "CHAIN.THINNED_ORDER_MISMATCH",
        )

    if "postburn_likelihood_trace" in arrays or "likelihood_trace" in arrays:
        _require(
            "postburn_likelihood_trace" in arrays and "likelihood_trace" in arrays,
            "CHAIN.LIKELIHOOD_PAIR",
        )
        _require(complete_schedule, "CHAIN.LIKELIHOOD_WITHOUT_SCHEDULE")
        postburn_likelihood = _dtype_shape(
            arrays,
            "postburn_likelihood_trace",
            "float64",
            (postburn_count,),
        )
        retained_likelihood = _dtype_shape(
            arrays,
            "likelihood_trace",
            "float64",
            (retained_count,),
        )
        _require(
            result["likelihood_indexing"] == "post-proposal-state/1",
            "CHAIN.LIKELIHOOD_INDEXING",
        )
        _require(
            bool(np.array_equal(retained_likelihood, postburn_likelihood[::thin])),
            "CHAIN.THINNED_LIKELIHOOD_MISMATCH",
        )
    else:
        _require(result["likelihood_indexing"] is None, "CHAIN.UNREQUESTED_LIKELIHOOD_INDEX")

    if "postburn_state_change_mask" in arrays:
        _require(complete_schedule, "CHAIN.TRANSITION_WITHOUT_SCHEDULE")
        opportunity_count = max(postburn_count - 1, 0)
        mask = _dtype_shape(
            arrays,
            "postburn_state_change_mask",
            "bool",
            (opportunity_count,),
        )
        count = int(np.count_nonzero(mask))
        _require(result["actual_transition_count"] == count, "CHAIN.TRANSITION_COUNT")
        expected_fraction = None if opportunity_count == 0 else count / opportunity_count
        if expected_fraction is None:
            _require(result["actual_transition_fraction"] is None, "CHAIN.TRANSITION_FRACTION")
        else:
            _require(
                result["actual_transition_fraction"] is not None
                and _close(result["actual_transition_fraction"], expected_fraction),
                "CHAIN.TRANSITION_FRACTION",
            )
        if postburn_chain is not None:
            expected_mask = np.any(postburn_chain[1:] != postburn_chain[:-1], axis=1)
            _require(bool(np.array_equal(mask, expected_mask)), "CHAIN.TRANSITION_MASK")
    else:
        _require(
            result["actual_transition_count"] is None
            and result["actual_transition_fraction"] is None,
            "CHAIN.UNREQUESTED_TRANSITION_SCALAR",
        )

    if retained_chain is not None:
        if "position_probabilities" in arrays:
            _require(
                _close(
                    arrays["position_probabilities"],
                    _derived_position(retained_chain, event_count),
                ),
                "POSITION.CHAIN_DERIVATION",
            )
        if "pairwise_precedence" in arrays:
            _require(
                _close(
                    arrays["pairwise_precedence"],
                    _derived_pairwise(retained_chain, event_count),
                ),
                "PAIRWISE.CHAIN_DERIVATION",
            )
        if result["central_order_method"]["method_id"] == "retained-state-mode/1":
            counts = Counter(tuple(int(value) for value in row) for row in retained_chain)
            maximum = max(counts.values())
            candidates = [state for state, count in counts.items() if count == maximum]
            expected_order = min(
                candidates,
                key=lambda state: tuple(event_ids[index] for index in state),
            )
            _require(
                list(expected_order) == list(result["central_order_permutation"]),
                "ORDER.RETAINED_MODE_MISMATCH",
            )


def _validate_stage_model_reference(
    result: Mapping[str, Any],
    arrays: Mapping[str, Any],
    stage_semantics: Mapping[str, Any],
    event_ids: Sequence[str],
) -> set[str]:
    present_stage_members = _FIT_STAGE_VALUE_ARRAYS & set(arrays)
    reference = result["stage_model_reference"]
    if not present_stage_members:
        _require(reference is None, "STAGE.REFERENCE_WITHOUT_OUTPUT")
        return set()
    _require(isinstance(reference, Mapping), "STAGE.REFERENCE_REQUIRED")
    _require(stage_semantics["stage_model_availability"] == "AVAILABLE", "STAGE.UNAVAILABLE")
    preimage = dict(reference)
    supplied_digest = preimage.pop("stage_model_reference_digest")
    _require(
        supplied_digest == structured_sha256("ebm-audit/stage-model-reference/1", preimage),
        "STAGE.REFERENCE_DIGEST",
    )
    event_count = len(event_ids)
    _require(
        reference["event_ids"] == list(event_ids)
        and reference["stage_semantics_digest"] == result["stage_semantics_digest"]
        and reference["selection_method_id"] == stage_semantics["reference_selection_method_id"],
        "STAGE.REFERENCE_OWNER",
    )
    permutation = list(reference["reference_order_permutation"])
    _require(
        len(permutation) == event_count and sorted(permutation) == list(range(event_count)),
        "STAGE.REFERENCE_ORDER",
    )
    bindings = [
        reference["reference_order_binding"],
        *reference["fitted_distribution_bindings"],
        reference["final_stage_prior_binding"],
    ]
    names = [str(binding["member_name"]) for binding in bindings]
    _require(len(names) == len(set(names)), "STAGE.REFERENCE_BINDING_DUPLICATE")
    catalog = result["array_catalog"]
    for binding in bindings:
        name = str(binding["member_name"])
        _require(
            name in arrays and catalog[name]["array_digest"] == binding["array_digest"],
            "STAGE.REFERENCE_ARRAY_BINDING",
        )
    order_name = str(reference["reference_order_binding"]["member_name"])
    order = _dtype_shape(arrays, order_name, "int32", (event_count,))
    _require(bool(np.array_equal(order, permutation)), "STAGE.REFERENCE_ORDER_ARRAY")
    for binding in reference["fitted_distribution_bindings"]:
        fitted = _array(arrays[str(binding["member_name"])])
        _require(fitted.ndim >= 1 and fitted.shape[0] == event_count, "STAGE.FITTED_AXIS")
    prior_name = str(reference["final_stage_prior_binding"]["member_name"])
    prior = _dtype_shape(arrays, prior_name, "float64", (event_count + 1,))
    _require(bool(np.all(prior > 0.0)), "STAGE.FINAL_PRIOR_NOT_POSITIVE")
    _require(_close(prior.sum(), 1.0), "STAGE.FINAL_PRIOR_NOT_NORMALIZED")
    residual = reference["final_stage_prior_fixed_point_l1_residual"]
    _require(
        np.isfinite(residual)
        and residual >= 0.0
        and residual < stage_semantics["final_prior_residual_tolerance"],
        "STAGE.FINAL_PRIOR_NOT_CONVERGED",
    )

    required_source_fields = {"stage_model_reference", *names}
    required_source_hashes = {
        supplied_digest,
        *(str(binding["array_digest"]) for binding in bindings),
    }
    for member_name in present_stage_members:
        origin = result["field_origins"][member_name]
        if member_name.endswith("stage_posterior"):
            expected_method = stage_semantics["posterior_method_id"]
        elif member_name.endswith("expected_stage"):
            expected_method = stage_semantics["expected_stage_rule_id"]
        else:
            expected_method = stage_semantics["map_rule_id"]
        _require(
            origin["origin"] == "WORKER_DERIVED"
            and origin["method_id"] == expected_method
            and required_source_fields <= set(origin["source_fields"])
            and required_source_hashes <= set(origin["source_hashes"]),
            "STAGE.FIELD_ORIGIN_BINDING",
        )
    return set(names)


def _validate_manifest(
    result: Mapping[str, Any],
    dataset: Mapping[str, Any],
    arrays: Mapping[str, Any],
    request_arrays: Mapping[str, Any],
) -> None:
    manifest = result["participant_event_manifest"]
    participant_count = int(dataset["participant_count"])
    evaluation_count = int(dataset["evaluation_participant_count"])
    event_ids = list(dataset["event_ids"])
    _require(
        manifest["request_training_participants"] == participant_count
        and manifest["returned_training_participants"] == participant_count
        and manifest["request_evaluation_participants"] == evaluation_count
        and manifest["request_events"] == event_ids
        and manifest["returned_events"] == event_ids
        and manifest["worker_removed_participants"] == []
        and manifest["worker_removed_events"] == []
        and manifest["worker_modified_cells"] == [],
        "ACCOUNTING.MANIFEST",
    )
    request_catalog = dataset["array_catalog"]
    _require(
        manifest["training_row_indexes_digest"]
        == request_catalog["training_row_indexes"]["array_digest"],
        "ACCOUNTING.TRAINING_INDEX_DIGEST",
    )
    request_training_indexes = _dtype_shape(
        request_arrays,
        "training_row_indexes",
        "int64",
        (participant_count,),
    )
    _require(
        bool(np.array_equal(request_training_indexes, np.arange(participant_count))),
        "ROW_INDEX.REQUEST_NOT_CONTIGUOUS",
    )
    if "training_row_indexes" in arrays:
        _validate_row_indexes(
            arrays,
            request_arrays,
            "training_row_indexes",
            participant_count,
        )

    evaluation_outputs_present = any(
        name.startswith("evaluation_") and name != "evaluation_row_indexes" for name in arrays
    )
    expected_returned_evaluation = evaluation_count if evaluation_outputs_present else 0
    _require(
        manifest["returned_evaluation_participants"] == expected_returned_evaluation,
        "ACCOUNTING.EVALUATION_COUNT",
    )
    if evaluation_outputs_present:
        _require(evaluation_count > 0, "STAGE.EMPTY_EVALUATION_COHORT")
        _validate_row_indexes(
            arrays,
            request_arrays,
            "evaluation_row_indexes",
            evaluation_count,
        )
        _require(
            manifest["evaluation_row_indexes_digest"]
            == result["array_catalog"]["evaluation_row_indexes"]["array_digest"]
            == request_catalog["evaluation_row_indexes"]["array_digest"],
            "ACCOUNTING.EVALUATION_INDEX_DIGEST",
        )
    else:
        _require(
            manifest["evaluation_row_indexes_digest"] is None,
            "ACCOUNTING.UNUSED_EVALUATION_INDEX",
        )


def _validate_artifacts(
    result: Mapping[str, Any],
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    required: bool,
) -> None:
    artifacts = result["backend_artifacts"]
    _require(bool(artifacts) == required, "ARTIFACT.REQUEST_PRESENCE")
    identity = response["backend_identity"]
    request_payload = _scientific_input(request)
    for artifact in artifacts:
        _require(
            response["files"].get(artifact["relative_path"])
            == {
                "byte_length": artifact["byte_length"],
                "sha256": artifact["sha256"],
            }
            and artifact["creating_chain_execution_id"] == request_payload["chain_execution_id"]
            and artifact["creating_scientific_request_digest"]
            == request["scientific_request_digest"]
            and artifact["adapter_id"] == identity["adapter_id"]
            and artifact["algorithm_id"] == request_payload["algorithm_id"]
            and artifact["worker_executable_digest"] == identity["worker_executable_digest"]
            and artifact["worker_code_digest"] == identity["worker_code_digest"]
            and artifact["backend_source_digest"] == identity["backend_source_digest"]
            and artifact["environment_digest"] == identity["environment_digest"]
            and artifact["settings_digest"] == request_payload["settings_digest"]
            and artifact["event_ids"] == request_payload["dataset"]["event_ids"]
            and artifact["stage_semantics_digest"]
            == request_payload["dataset"]["stage_semantics_digest"],
            "ARTIFACT.OWNER_BINDING",
        )


def _validate_fit(
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    arrays: Mapping[str, Any],
    request_arrays: Mapping[str, Any],
    algorithm: Mapping[str, Any],
) -> None:
    request_payload = _scientific_input(request)
    dataset = request_payload["dataset"]
    result = response["payload"]["result"]
    capabilities = algorithm["capabilities"]
    requested_outputs = list(request_payload["requested_outputs"])
    _require("central_order" in requested_outputs, "OUTPUT.CENTRAL_ORDER_REQUIRED")
    expected_applicability, unavailable_fixed = _expected_component_applicability(
        "fit", requested_outputs, capabilities
    )
    _require(
        result["component_applicability"] == expected_applicability,
        "CAPABILITY.COMPONENT_APPLICABILITY",
    )
    expected_arrays, private_requested, portable_requested = _expected_fit_arrays(
        requested_outputs, unavailable_fixed
    )
    catalog = result["array_catalog"]
    present_canonical = _FIT_CANONICAL_ARRAYS & set(catalog)
    _require(present_canonical == expected_arrays, "OUTPUT.ARRAY_PRESENCE")

    event_ids = list(dataset["event_ids"])
    event_count = int(dataset["event_count"])
    participant_count = int(dataset["participant_count"])
    evaluation_count = int(dataset["evaluation_participant_count"])
    _require(
        event_count == len(event_ids)
        and result["event_ids"] == event_ids
        and result["preprocessing_manifest_digest"] == dataset["preprocessing_manifest_digest"]
        and result["stage_semantics_digest"] == dataset["stage_semantics_digest"],
        "EVENT.REQUEST_RESULT_MAPPING",
    )
    central = _dtype_shape(
        arrays,
        "central_order_permutation",
        "int32",
        (event_count,),
    )
    _permutation_rows(central, event_count)
    _require(
        central.tolist() == result["central_order_permutation"],
        "ORDER.JSON_ARRAY_MISMATCH",
    )

    stage_semantics = _validate_stage_semantics_owner(dataset, algorithm)
    reference_private_names = _validate_stage_model_reference(
        result,
        arrays,
        stage_semantics,
        event_ids,
    )
    exact_target_private_names = _validate_exact_fixed_target_reference(
        result,
        arrays,
        event_ids,
        participant_count,
        requested=_EXACT_FIXED_TARGET_OUTPUT in requested_outputs,
    )
    private_names = {name for name in arrays if name.startswith("backend.")}
    if private_requested:
        _require(bool(private_names), "OUTPUT.FITTED_DISTRIBUTION_MISSING")
    else:
        _require(
            private_names == reference_private_names | exact_target_private_names,
            "OUTPUT.UNREQUESTED_PRIVATE_ARRAY",
        )

    _validate_probability_matrices(arrays, event_count)
    _validate_chain_arrays(result, arrays, event_ids)
    _validate_stage_family(
        arrays,
        prefix="training",
        participant_count=participant_count,
        event_count=event_count,
    )
    _validate_stage_family(
        arrays,
        prefix="evaluation",
        participant_count=evaluation_count,
        event_count=event_count,
    )
    _validate_manifest(result, dataset, arrays, request_arrays)

    transition_requested = "accepted_transition_diagnostics" in requested_outputs
    expected_origin_names = set(catalog)
    if transition_requested:
        expected_origin_names.update({"actual_transition_count", "actual_transition_fraction"})
    _require(
        set(result["field_origins"]) == expected_origin_names,
        "OUTPUT.FIELD_ORIGIN_SET",
    )
    _require(
        all(
            origin["origin"] in {"BACKEND_NATIVE", "WORKER_DERIVED"}
            for origin in result["field_origins"].values()
        ),
        "OUTPUT.WORKER_ORIGIN",
    )
    _validate_artifacts(
        result,
        response,
        request,
        required=portable_requested,
    )


def _validate_validate(
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    algorithm: Mapping[str, Any],
) -> None:
    request_payload = _scientific_input(request)
    expected, _unavailable = _expected_component_applicability(
        "validate",
        list(request_payload["requested_outputs"]),
        algorithm["capabilities"],
    )
    payload = response["payload"]
    _require(
        payload["component_applicability"] == expected,
        "CAPABILITY.COMPONENT_APPLICABILITY",
    )
    expected_accounting = request_payload["data_accounting"]
    _require(
        payload["predicted_accounting"] == expected_accounting,
        "ACCOUNTING.PREDICTED_MISMATCH",
    )
    issues = payload["validation_issues"]
    has_blocking_issue = any(
        issue["severity"] in {"ERROR", "REQUIRES_CONFIRMATION"} for issue in issues
    )
    _require(
        payload["fit_permitted"] is (not has_blocking_issue),
        "VALIDATION.FIT_PERMISSION_MISMATCH",
    )
    _require(
        not any(issue["severity"] == "ERROR" for issue in issues),
        "VALIDATION.SUCCESS_WITH_ERROR",
    )
    _validate_stage_semantics_owner(request_payload["dataset"], algorithm)


def _validate_describe(response: Mapping[str, Any]) -> None:
    result = response["payload"]["result"]
    _require(
        result["supported_commands"] == _V2_WORKER_COMMANDS,
        "COMMAND.V2_WORKER_SURFACE",
    )
    for algorithm in result["supported_algorithms"]:
        commands = algorithm["supported_commands"]
        _require(commands == _V2_REQUIRED_ALGORITHM_COMMANDS, "COMMAND.V2_ALGORITHM_SURFACE")


def _validate_stage(
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    arrays: Mapping[str, Any],
    request_arrays: Mapping[str, Any],
    algorithm: Mapping[str, Any],
) -> None:
    request_payload = _scientific_input(request)
    dataset = request_payload["dataset"]
    result = response["payload"]["result"]
    requested_outputs = list(request_payload["requested_outputs"])
    _require(bool(requested_outputs), "OUTPUT.STAGE_OUTPUT_REQUIRED")
    expected_applicability, unavailable = _expected_component_applicability(
        "stage", requested_outputs, algorithm["capabilities"]
    )
    _require(not expected_applicability and not unavailable, "CAPABILITY.STAGE_UNAVAILABLE")
    rows = _registry_rows("stage")
    expected_arrays = {
        str(member)
        for output_id in requested_outputs
        for member in rows[output_id]["result_members"]
    }
    _require(
        (_STAGE_CANONICAL_ARRAYS & set(result["array_catalog"])) == expected_arrays,
        "OUTPUT.ARRAY_PRESENCE",
    )
    participant_count = int(dataset["participant_count"])
    event_ids = list(dataset["event_ids"])
    event_count = int(dataset["event_count"])
    stage_semantics = _validate_stage_semantics_owner(dataset, algorithm)
    _require(stage_semantics["stage_model_availability"] == "AVAILABLE", "STAGE.UNAVAILABLE")
    artifact = request_payload["fitted_artifact"]
    _require(
        result["fitted_artifact"] == artifact
        and artifact["stage_model_reference_digest"] is not None
        and result["stage_model_reference_digest"] == artifact["stage_model_reference_digest"]
        and result["event_ids"] == event_ids == artifact["event_ids"]
        and result["stage_semantics_digest"]
        == dataset["stage_semantics_digest"]
        == artifact["stage_semantics_digest"],
        "STAGE.ARTIFACT_REFERENCE_BINDING",
    )
    _validate_row_indexes(
        arrays,
        request_arrays,
        "stage_row_indexes",
        participant_count,
    )
    _validate_stage_family(
        arrays,
        prefix="stage",
        participant_count=participant_count,
        event_count=event_count,
    )
    _require(
        set(result["field_origins"]) == set(result["array_catalog"]),
        "OUTPUT.FIELD_ORIGIN_SET",
    )


def _scientific_input(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return the one projection owner plus command-specific scientific fields."""

    wire = request["payload"]
    projection = wire["execution_input_projection"]
    _require(isinstance(projection, Mapping), "REQUEST.EXECUTION_INPUT_PROJECTION")
    scientific = dict(projection)
    for field, value in wire.items():
        if field not in {"execution_input_projection", "execution_input_projection_digest"}:
            scientific[field] = value
    scientific["execution_input_projection_digest"] = wire["execution_input_projection_digest"]
    return scientific


def validate_success_response_semantics(
    *,
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    arrays: Mapping[str, Any],
    request_arrays: Mapping[str, Any],
    described_algorithm: Mapping[str, Any] | None,
) -> None:
    """Reject a schema-valid success whose scientific values are inconsistent."""

    if response.get("status") != "SUCCESS":
        return
    command = str(request["command"])
    if command not in {"describe", "validate", "fit", "stage"}:
        return
    try:
        if command == "describe":
            _validate_describe(response)
        elif described_algorithm is None:
            raise _SemanticViolation("ALGORITHM.DESCRIPTION_REQUIRED")
        elif command == "validate":
            algorithm = described_algorithm
            _validate_validate(response, request, algorithm)
        elif command == "fit":
            algorithm = described_algorithm
            _validate_fit(
                response,
                request,
                arrays,
                request_arrays,
                algorithm,
            )
        else:
            algorithm = described_algorithm
            _validate_stage(
                response,
                request,
                arrays,
                request_arrays,
                algorithm,
            )
    except _SemanticViolation as error:
        raise WorkerProtocolError(
            "PROTOCOL.RESPONSE_SEMANTICS",
            "A successful worker result violates the closed semantic contract.",
            details={"semantic_rule": error.rule_id},
        ) from None
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.RESPONSE_SEMANTICS",
            "A successful worker result could not satisfy the closed semantic contract.",
            details={"semantic_rule": "SEMANTICS.INVALID_STRUCTURE"},
        ) from None


__all__ = ["validate_success_response_semantics"]
