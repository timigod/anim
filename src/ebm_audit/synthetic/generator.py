"""Offline deterministic project-owned synthetic data generator."""

from __future__ import annotations

import copy
import hashlib
import hmac
import math
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import numpy as np
from numpy.typing import NDArray

from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.schema.validation import SchemaValidationError, validate_instance

from .authority import ScenarioAuthority
from .models import (
    AuthenticatedSourceOwner,
    ResolvedSyntheticCase,
    StageSnapshot,
    SyntheticCaseArtifacts,
)

_STAGES: tuple[tuple[str, str], ...] = (
    ("resolved_parameters", "ebm-audit/synthetic-generation-stage/resolved-parameters/1"),
    ("group_assignment", "ebm-audit/synthetic-generation-stage/group-assignment/1"),
    ("latent_coordinate", "ebm-audit/synthetic-generation-stage/latent-coordinate/1"),
    (
        "latent_source_contamination",
        "ebm-audit/synthetic-generation-stage/latent-source-contamination/1",
    ),
    ("transition_signal", "ebm-audit/synthetic-generation-stage/transition-signal/1"),
    ("covariate_effect", "ebm-audit/synthetic-generation-stage/covariate-effect/1"),
    ("group_effect", "ebm-audit/synthetic-generation-stage/group-effect/1"),
    ("participant_effect", "ebm-audit/synthetic-generation-stage/participant-effect/1"),
    (
        "base_measurement_noise",
        "ebm-audit/synthetic-generation-stage/base-measurement-noise/1",
    ),
    ("centered_skew", "ebm-audit/synthetic-generation-stage/centered-skew/1"),
    (
        "exact_duplicate_copy",
        "ebm-audit/synthetic-generation-stage/exact-duplicate-copy/1",
    ),
    (
        "observed_label_contamination",
        "ebm-audit/synthetic-generation-stage/observed-label-contamination/1",
    ),
    ("outliers", "ebm-audit/synthetic-generation-stage/outliers/1"),
    ("missingness", "ebm-audit/synthetic-generation-stage/missingness/1"),
)

_TRUTH_STAGE_SOURCES: tuple[tuple[str, ...], ...] = (
    (
        "/dimensions",
        "/event_truth",
        "/artifact_digests/resolved_generator_configuration_sha256",
        "/artifact_digests/resolved_parameter_manifest_sha256",
        "/artifact_digests/resolved_generator_mechanism_sha256",
    ),
    ("/group_truth/original_labels",),
    ("/participant_truth/latent_time",),
    (
        "/group_truth/contamination_mechanism",
        "/group_truth/contaminated_participant_indexes",
        "/participant_truth/latent_time",
    ),
    (
        "/event_truth/centers",
        "/event_truth/widths",
        "/event_truth/baselines",
        "/event_truth/amplitudes",
        "/event_truth/directions",
        "/participant_truth/latent_time",
    ),
    ("/covariate_truth", "/event_truth/covariate_effects"),
    ("/event_truth/group_effects", "/group_truth/original_labels"),
    (
        "/participant_truth/participant_random_effect",
        "/event_truth/participant_effect_loadings",
    ),
    (
        "/event_truth/noise_standard_deviations",
        "/event_truth/noise_correlation_matrix",
        "/seed_identity/component_seed_manifest_sha256",
    ),
    (
        "/event_truth/noise_standard_deviations",
        "/event_truth/noise_correlation_matrix",
        "/artifact_digests/resolved_generator_configuration_sha256",
    ),
    (
        "/mechanism_evidence/equivalence_block_event_ids",
        "/event_truth/centers",
        "/event_truth/directions",
    ),
    (
        "/group_truth/original_labels",
        "/group_truth/observed_labels",
        "/group_truth/contaminated_participant_indexes",
    ),
    ("/outlier_truth",),
    ("/missingness_truth", "/participant_truth/ordered_participants"),
)

_TRANSFORMED_SOURCE_FAMILIES = frozenset(
    {"label_permutation_null", "within_group_feature_permutation_null"}
)

FloatArray = NDArray[np.float64]
BoolArray = NDArray[np.bool_]


@dataclass(slots=True)
class _Execution:
    original_labels: list[str]
    observed_labels: list[str]
    group_indicator: NDArray[np.int64]
    latent_time: FloatArray
    participant_effect: FloatArray
    subgroup_labels: NDArray[np.int64]
    subgroup_orders: list[list[str]]
    covariate_ids: list[str]
    covariate_values: FloatArray
    transition: FloatArray
    covariate_contribution: FloatArray
    group_contribution: FloatArray
    participant_contribution: FloatArray
    normal_draws: FloatArray
    base_noise: FloatArray
    centered_skew: FloatArray
    values_without_group: FloatArray
    clean_values: FloatArray
    perturbed_values: FloatArray
    mask: BoolArray
    final_values: list[list[float | None]]
    contaminated_indexes: list[int]
    outlier_participants: list[int]
    outlier_cells: list[dict[str, int]]
    outlier_offsets: list[float]
    missing_event_probabilities: list[float]
    missing_marginal_probability: float | None
    missing_model_coefficients: list[float]
    stage_snapshots: tuple[StageSnapshot, ...]


def _invalid(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _contains_nonfinite(value: object) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, list):
        return any(_contains_nonfinite(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_nonfinite(item) for item in value.values())
    return False


def _record_digest_valid(record: dict[str, Any], field: str, domain: str) -> bool:
    preimage = copy.deepcopy(record)
    supplied = preimage.get(field)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage[field] = None
    return supplied == structured_sha256_hex(domain, preimage)


def _validate_case_plan(
    authority: ScenarioAuthority,
    case: ResolvedSyntheticCase,
    *,
    source_owner: AuthenticatedSourceOwner | None,
) -> None:
    # Schema validation and caller-recomputed hashes are not authority.  Always
    # reconstruct the complete plan from the exact evaluator bytes first.
    authority.verify_resolved_case(case, source_owner=source_owner)
    if _contains_nonfinite(case.resolution_bundle):
        raise _invalid(
            "GENERATOR.RESOLUTION_SCHEMA_INVALID",
            "The resolved synthetic generation plan failed its closed schema.",
        )
    try:
        validate_instance(case.resolution_bundle, "synthetic-resolved-configuration.schema.json")
    except SchemaValidationError as exc:
        raise _invalid(
            "GENERATOR.RESOLUTION_SCHEMA_INVALID",
            "The resolved synthetic generation plan failed its closed schema.",
        ) from exc
    if (
        case.resolution_bundle.get("resolved_configuration") != case.resolved_configuration
        or case.resolution_bundle.get("resolved_parameter_manifest")
        != case.resolved_parameter_manifest
        or case.resolution_bundle.get("resolved_generator_mechanism") != case.resolved_mechanism
        or case.resolution_bundle.get("component_seed_manifest") != case.component_seed_manifest
    ):
        raise _invalid(
            "GENERATOR.RESOLUTION_OWNER_MISMATCH",
            "The resolved synthetic owners are not bound to one bundle.",
        )
    digest_owners = (
        (
            case.resolved_configuration,
            "resolved_generator_configuration_sha256",
            "ebm-audit/resolved-generator-configuration/1",
        ),
        (
            case.resolved_parameter_manifest,
            "resolved_parameter_manifest_sha256",
            "ebm-audit/resolved-parameter-manifest/1",
        ),
        (
            case.resolved_mechanism,
            "resolved_generator_mechanism_sha256",
            "ebm-audit/resolved-generator-mechanism/1",
        ),
        (
            case.component_seed_manifest,
            "component_seed_manifest_sha256",
            "ebm-audit/component-seed-manifest/1",
        ),
    )
    if any(
        not _record_digest_valid(owner, field, domain) for owner, field, domain in digest_owners
    ):
        raise _invalid(
            "GENERATOR.RESOLUTION_DIGEST_MISMATCH",
            "A resolved synthetic owner differs from its canonical digest.",
        )
    if case.resolved_parameter_manifest.get("field_draws") != [
        row.as_dict() for row in case.field_resolutions
    ]:
        raise _invalid(
            "GENERATOR.FIELD_LEDGER_MISMATCH",
            "The resolved synthetic field ledger differs from its manifest.",
        )
    for record in case.component_seeds:
        roots = {
            "CASE_SEED": case.case_seed,
            "SHARED_DRAW_SEED": case.shared_draw_seed,
            "OPERATION_SEED": case.operation_seed,
        }
        root = roots[record.root_kind]
        if root is None:
            raise _invalid(
                "GENERATOR.COMPONENT_ROOT_INVALID",
                "A resolved synthetic component root is absent.",
            )
        digest = hmac.new(
            bytes.fromhex(root),
            b"ebm-audit-synthetic-component/v1\0" + record.component_path.encode(),
            hashlib.sha256,
        ).digest()
        if record.full_digest != "sha256:" + digest.hex() or record.seed_128 != digest[:16].hex():
            raise _invalid(
                "GENERATOR.COMPONENT_SEED_MISMATCH",
                "A resolved synthetic component seed differs from its declared root.",
            )
    configuration = case.resolved_configuration
    if case.coordinate.family_id == "correlated_duplicate_events":
        event_ids = configuration["event_ids"]
        if not 7 <= len(event_ids) <= 10:
            raise _invalid(
                "GENERATOR.DUPLICATE_DIMENSION_INVALID",
                "The duplicate-event selector requires seven to ten events.",
            )
        left = (len(event_ids) - 1) // 2
        expected = [event_ids[left], event_ids[left + 1]]
        scenario = configuration["scenario_parameters"]
        if scenario["pair_event_ids"] != expected:
            raise _invalid(
                "GENERATOR.DUPLICATE_SELECTOR_INVALID",
                "The duplicate-event pair differs from the dimension-derived selector.",
            )
        expected_block = expected if scenario["pair_mode"] == "exact_duplicate_post_noise" else []
        if scenario["equivalence_block_event_ids"] != expected_block:
            raise _invalid(
                "GENERATOR.DUPLICATE_SELECTOR_INVALID",
                "The duplicate-event equivalence block differs from its declared mode.",
            )


def _rng(case: ResolvedSyntheticCase, path: str) -> np.random.Generator:
    seed = case.component_seed(path).seed_128
    return np.random.Generator(np.random.PCG64DXSM(int(seed, 16)))


def _sigmoid(value: np.float64) -> np.float64:
    if value >= np.float64(0.0):
        return np.float64(np.float64(1.0) / np.float64(np.float64(1.0) + np.exp(-value)))
    exponential = np.exp(value)
    return np.float64(exponential / np.float64(np.float64(1.0) + exponential))


def _sigmoid_matrix(latent: FloatArray, centers: FloatArray, widths: FloatArray) -> FloatArray:
    result = np.empty((latent.shape[0], centers.shape[0]), dtype=np.float64, order="C")
    for participant in range(latent.shape[0]):
        for event in range(centers.shape[0]):
            q = np.float64(
                np.float64(np.float64(latent[participant]) - np.float64(centers[event]))
                / np.float64(widths[event])
            )
            result[participant, event] = _sigmoid(q)
    return result


def _left_add(*terms: FloatArray) -> FloatArray:
    if not terms:
        raise AssertionError("at least one term is required")
    result = np.array(terms[0], dtype=np.float64, order="C", copy=True)
    for term in terms[1:]:
        result = np.add(result, term, dtype=np.float64)
    if not np.all(np.isfinite(result)):
        raise _invalid(
            "GENERATOR.NONFINITE_INTERMEDIATE",
            "Synthetic generation produced a non-finite intermediate.",
        )
    return np.ascontiguousarray(result, dtype=np.float64)


def _snapshot(index: int, output: dict[str, Any]) -> StageSnapshot:
    stage_id, domain = _STAGES[index]
    return StageSnapshot(
        stage_index=index,
        stage_id=stage_id,
        digest_domain=domain,
        output_sha256=structured_sha256_hex(domain + "/execution-output", output),
        output=output,
    )


def _group_assignment(case: ResolvedSyntheticCase) -> tuple[list[str], NDArray[np.int64]]:
    configuration = case.resolved_configuration
    participant_count = configuration["dimensions"]["participant_count"]
    reference_count = configuration["group_generation"]["reference_count"]
    labels = np.concatenate(
        (
            np.zeros(reference_count, dtype=np.int64),
            np.ones(participant_count - reference_count, dtype=np.int64),
        )
    )
    _rng(case, "group_assignment").shuffle(labels)
    names = ["reference" if value == 0 else "at_risk" for value in labels.tolist()]
    return names, labels


def _latent_draws(case: ResolvedSyntheticCase, indicator: NDArray[np.int64]) -> FloatArray:
    configuration = case.resolved_configuration
    sampling = configuration["latent_sampling"]
    rng = _rng(case, "latent_time")
    result = np.empty(indicator.shape[0], dtype=np.float64)
    for index, group in enumerate(indicator.tolist()):
        if sampling["mode"] == "GROUP_INDEPENDENT_WINDOW":
            window = sampling["group_independent_window"]
        else:
            window = sampling["reference_window"] if group == 0 else sampling["at_risk_window"]
        if (
            not isinstance(window, list)
            or len(window) != 2
            or not math.isfinite(window[0])
            or not math.isfinite(window[1])
            or window[0] >= window[1]
        ):
            raise _invalid(
                "GENERATOR.LATENT_WINDOW_INVALID",
                "A declared latent sampling window is invalid.",
            )
        result[index] = np.float64(rng.uniform(np.float64(window[0]), np.float64(window[1])))
    return result


def _lehmer_order(event_ids: list[str], inversions: int) -> list[str]:
    remaining = list(event_ids)
    output: list[str] = []
    left = inversions
    maximum = len(event_ids) * (len(event_ids) - 1) // 2
    if not 0 <= left <= maximum:
        raise _invalid(
            "GENERATOR.ALTERNATE_ORDER_INVALID",
            "A synthetic alternate order has an invalid inversion count.",
        )
    while remaining:
        index = min(left, len(remaining) - 1)
        output.append(remaining.pop(index))
        left -= index
    return output


def _subgroups(
    case: ResolvedSyntheticCase,
) -> tuple[NDArray[np.int64], list[list[str]]]:
    configuration = case.resolved_configuration
    family = case.coordinate.family_id
    participant_count = configuration["dimensions"]["participant_count"]
    event_ids = cast(list[str], configuration["event_ids"])
    parameters = configuration["scenario_parameters"]
    if family == "minority_alternate_sequence":
        count = min(
            participant_count - 1,
            max(1, round(participant_count * float(parameters["minority_fraction"]))),
        )
        labels = np.concatenate(
            (
                np.zeros(participant_count - count, dtype=np.int64),
                np.ones(count, dtype=np.int64),
            )
        )
        _rng(case, "subgroup_assignment").shuffle(labels)
        return labels, [
            event_ids,
            _lehmer_order(event_ids, int(parameters["alternate_inversions"])),
        ]
    if family == "opposing_sequences_50_50":
        if participant_count % 2:
            raise _invalid(
                "GENERATOR.OPPOSING_PARTICIPANT_COUNT_INVALID",
                "The opposing-sequence participant count must be even.",
            )
        labels = np.concatenate(
            (
                np.zeros(participant_count // 2, dtype=np.int64),
                np.ones(participant_count // 2, dtype=np.int64),
            )
        )
        _rng(case, "subgroup_assignment").shuffle(labels)
        maximum = len(event_ids) * (len(event_ids) - 1) // 2
        inversions = round(float(parameters["opposing_relation_fraction"]) * maximum)
        return labels, [event_ids, _lehmer_order(event_ids, inversions)]
    return np.zeros(participant_count, dtype=np.int64), []


def _participant_centers(
    configuration: dict[str, Any],
    subgroup_labels: NDArray[np.int64],
    subgroup_orders: list[list[str]],
) -> FloatArray:
    participant_count = configuration["dimensions"]["participant_count"]
    event_ids = cast(list[str], configuration["event_ids"])
    base = np.asarray(configuration["event_parameters"]["event_centers"], dtype=np.float64)
    result = np.tile(base, (participant_count, 1))
    if not subgroup_orders:
        return result
    sorted_centers = np.sort(base)
    mappings: list[FloatArray] = []
    for order in subgroup_orders:
        mapped = np.empty(len(event_ids), dtype=np.float64)
        for position, event_id in enumerate(order):
            mapped[event_ids.index(event_id)] = sorted_centers[position]
        mappings.append(mapped)
    for participant, subgroup in enumerate(subgroup_labels.tolist()):
        result[participant] = mappings[subgroup]
    return result


def _transition(
    configuration: dict[str, Any],
    latent: FloatArray,
    participant_centers: FloatArray,
) -> FloatArray:
    parameters = configuration["event_parameters"]
    widths = np.asarray(parameters["transition_width"], dtype=np.float64)
    amplitudes = np.asarray(parameters["amplitude"], dtype=np.float64)
    directions = np.asarray(
        [1.0 if value == "higher" else -1.0 for value in configuration["event_directions"]],
        dtype=np.float64,
    )
    result = np.empty(participant_centers.shape, dtype=np.float64)
    for participant in range(participant_centers.shape[0]):
        probabilities = _sigmoid_matrix(
            latent[participant : participant + 1], participant_centers[participant], widths
        )[0]
        result[participant] = np.multiply(
            np.multiply(directions, amplitudes, dtype=np.float64),
            probabilities,
            dtype=np.float64,
        )
    return result


def _covariates(
    case: ResolvedSyntheticCase,
    indicator: NDArray[np.int64],
) -> tuple[list[str], FloatArray, FloatArray]:
    configuration = case.resolved_configuration
    mode = configuration["covariates"]["mode"]
    participant_count = configuration["dimensions"]["participant_count"]
    event_count = configuration["dimensions"]["event_count"]
    if mode == "none":
        return (
            [],
            np.empty((participant_count, 0), dtype=np.float64),
            np.zeros((participant_count, event_count), dtype=np.float64),
        )
    rng = _rng(case, "covariates")
    values = rng.standard_normal(participant_count, dtype=np.float64)
    if mode == "one_group_shifted_normal":
        difference = configuration["covariates"]["standardized_group_difference"]
        if not isinstance(difference, (int, float)) or isinstance(difference, bool):
            raise _invalid(
                "GENERATOR.COVARIATE_CONFIGURATION_INVALID",
                "The group-shifted covariate difference is invalid.",
            )
        shifts = np.where(indicator == 0, -float(difference) / 2.0, float(difference) / 2.0)
        values = np.add(values, shifts, dtype=np.float64)
    effects = np.asarray(configuration["event_parameters"]["covariate_effect"], dtype=np.float64)
    contribution = np.multiply(values[:, None], effects[None, :], dtype=np.float64)
    return ["z01"], values[:, None], contribution


def _measurement_noise(
    case: ResolvedSyntheticCase,
) -> tuple[FloatArray, FloatArray, FloatArray]:
    configuration = case.resolved_configuration
    participant_count = configuration["dimensions"]["participant_count"]
    event_count = configuration["dimensions"]["event_count"]
    noise = configuration["measurement_noise"]
    standard_deviations = np.asarray(noise["standard_deviations"], dtype=np.float64)
    correlation = np.asarray(noise["correlation_matrix"], dtype=np.float64)
    covariance = np.asarray(
        np.diag(standard_deviations) @ correlation @ np.diag(standard_deviations),
        dtype=np.float64,
    )
    try:
        lower = np.linalg.cholesky(covariance)
    except np.linalg.LinAlgError as exc:
        raise _invalid(
            "GENERATOR.COVARIANCE_NOT_POSITIVE_DEFINITE",
            "The synthetic covariance is not positive definite.",
        ) from exc
    normal = _rng(case, "measurement_normal").standard_normal(
        (participant_count, event_count), dtype=np.float64
    )
    base = np.empty_like(normal)
    for participant in range(participant_count):
        base[participant] = lower @ normal[participant]
    family = noise["family"]
    if family in {"multivariate_student_t", "student_t_plus_centered_lognormal"}:
        degrees = noise["student_t_df"]
        if not isinstance(degrees, (int, float)) or isinstance(degrees, bool) or degrees <= 2:
            raise _invalid(
                "GENERATOR.STUDENT_T_DF_INVALID",
                "The synthetic Student-t degrees of freedom must exceed two.",
            )
        scales = _rng(case, "measurement_scale").chisquare(float(degrees), participant_count)
        multipliers = np.sqrt(np.float64(float(degrees) - 2.0) / scales)
        base = np.multiply(base, multipliers[:, None], dtype=np.float64)
    skew = np.zeros_like(base)
    if family in {"normal_plus_centered_lognormal", "student_t_plus_centered_lognormal"}:
        sigma = noise["centered_lognormal_sigma"]
        weight = noise["centered_lognormal_weight"]
        if (
            not isinstance(sigma, (int, float))
            or isinstance(sigma, bool)
            or sigma < 0
            or not isinstance(weight, (int, float))
            or isinstance(weight, bool)
            or weight < 0
        ):
            raise _invalid(
                "GENERATOR.SKEW_PARAMETERS_INVALID",
                "The centered log-normal parameters are invalid.",
            )
        draws = _rng(case, "measurement_skew").standard_normal(
            (participant_count, event_count), dtype=np.float64
        )
        kappa = np.full(event_count, float(sigma), dtype=np.float64)
        omega = np.multiply(float(weight), standard_deviations, dtype=np.float64)
        exponent = np.subtract(
            np.multiply(draws, kappa[None, :], dtype=np.float64),
            np.square(kappa, dtype=np.float64)[None, :] / np.float64(2.0),
            dtype=np.float64,
        )
        skew = np.multiply(
            omega[None, :], np.subtract(np.exp(exponent), 1.0, dtype=np.float64), dtype=np.float64
        )
    if not np.all(np.isfinite(base)) or not np.all(np.isfinite(skew)):
        raise _invalid(
            "GENERATOR.NONFINITE_NOISE",
            "Synthetic measurement noise produced a non-finite value.",
        )
    return normal, base, skew


def _contaminate_labels(
    case: ResolvedSyntheticCase,
    original: list[str],
) -> tuple[list[str], list[int]]:
    fraction = case.resolved_configuration["scenario_parameters"]["contamination_fraction"]
    if case.coordinate.family_id != "control_contamination" or fraction is None:
        return list(original), []
    count = round(len(original) * float(fraction))
    count = min(len(original), max(0, count))
    selected = sorted(
        int(value)
        for value in _rng(case, "contamination").choice(len(original), size=count, replace=False)
    )
    observed = list(original)
    for index in selected:
        observed[index] = "at_risk" if observed[index] == "reference" else "reference"
    return observed, selected


def _outliers(
    case: ResolvedSyntheticCase,
    clean: FloatArray,
) -> tuple[FloatArray, list[int], list[dict[str, int]], list[float]]:
    configuration = case.resolved_configuration
    settings = configuration["outliers"]
    if settings["mode"] == "none":
        return np.array(clean, copy=True, order="C"), [], [], []
    participant_count, event_count = clean.shape
    participant_total = settings["injected_participant_count"]
    event_total = settings["affected_event_count"]
    if not 1 <= participant_total <= participant_count or not 1 <= event_total <= event_count:
        raise _invalid(
            "GENERATOR.OUTLIER_COUNTS_INVALID",
            "Synthetic outlier counts exceed the generated dimensions.",
        )
    rng = _rng(case, "outliers")
    participants = sorted(
        int(value) for value in rng.choice(participant_count, size=participant_total, replace=False)
    )
    events = sorted(
        int(value) for value in rng.choice(event_count, size=event_total, replace=False)
    )
    standard_deviations = np.asarray(
        configuration["measurement_noise"]["standard_deviations"], dtype=np.float64
    )
    scale = float(settings["offset_noise_sd"])
    output = np.array(clean, copy=True, order="C")
    cells: list[dict[str, int]] = []
    offsets: list[float] = []
    sequence = 0
    for participant in participants:
        for event in events:
            sign = 1.0 if sequence % 2 == 0 else -1.0
            offset = float(np.float64(sign * scale) * standard_deviations[event])
            output[participant, event] = np.float64(output[participant, event] + offset)
            cells.append({"participant_index": participant, "event_index": event})
            offsets.append(offset)
            sequence += 1
    return output, participants, cells, offsets


def _mar_intercept(target: float, linear: FloatArray) -> float:
    def mean_at(intercept: float) -> float:
        total = np.float64(0.0)
        for value in linear:
            total = np.float64(total + _sigmoid(np.float64(intercept + value)))
        return float(np.float64(total / np.float64(linear.shape[0])))

    low = -40.0
    high = 40.0
    if not mean_at(low) <= target <= mean_at(high):
        raise _invalid(
            "GENERATOR.MAR_TARGET_NOT_BRACKETED",
            "The declared MAR marginal probability is not bracketed.",
        )
    for _ in range(200):
        midpoint = float(np.float64(np.float64(low + high) / np.float64(2.0)))
        if mean_at(midpoint) < target:
            low = midpoint
        else:
            high = midpoint
    return float(np.float64(np.float64(low + high) / np.float64(2.0)))


def _missingness(
    case: ResolvedSyntheticCase,
    values: FloatArray,
    covariates: FloatArray,
    indicator: NDArray[np.int64],
) -> tuple[BoolArray, list[list[float | None]], list[float]]:
    settings = case.resolved_configuration["missingness"]
    participant_count, event_count = values.shape
    family = settings["family"]
    coefficients: list[float] = []
    if family == "none":
        probabilities = np.zeros((participant_count, event_count), dtype=np.float64)
    elif family == "MCAR":
        probabilities = np.tile(
            np.asarray(settings["event_probabilities"], dtype=np.float64),
            (participant_count, 1),
        )
    elif family == "MAR":
        if covariates.shape != (participant_count, 1):
            raise _invalid(
                "GENERATOR.MAR_COVARIATE_INVALID",
                "MAR generation requires one fully observed synthetic covariate.",
            )
        target = settings["marginal_probability"]
        covariate_coefficient = settings["covariate_log_odds_coefficient"]
        group_coefficient = settings["group_log_odds_coefficient"]
        if not all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            for value in (
                target,
                covariate_coefficient,
                group_coefficient,
            )
        ):
            raise _invalid(
                "GENERATOR.MAR_CONFIGURATION_INVALID",
                "The MAR coefficients are invalid.",
            )
        linear = np.add(
            np.multiply(covariates[:, 0], float(covariate_coefficient), dtype=np.float64),
            np.multiply(indicator, float(group_coefficient), dtype=np.float64),
            dtype=np.float64,
        )
        intercept = _mar_intercept(float(target), linear)
        coefficients = [intercept, float(covariate_coefficient), float(group_coefficient)]
        row_probabilities = np.asarray(
            [_sigmoid(np.float64(intercept + value)) for value in linear], dtype=np.float64
        )
        probabilities = np.tile(row_probabilities[:, None], (1, event_count))
    else:
        raise _invalid(
            "GENERATOR.MISSINGNESS_FAMILY_INVALID",
            "The synthetic missingness family is not implemented.",
        )
    draws = _rng(case, "missingness").random((participant_count, event_count))
    mask = np.less(draws, probabilities)
    scenario = case.resolved_configuration["scenario_parameters"]
    if scenario["pair_mode"] == "exact_duplicate_post_noise":
        source_id, target_id = scenario["pair_event_ids"]
        event_ids = case.resolved_configuration["event_ids"]
        source = event_ids.index(source_id)
        target_index = event_ids.index(target_id)
        np.copyto(mask[:, target_index], mask[:, source], casting="no")
    final: list[list[float | None]] = []
    for participant in range(participant_count):
        row: list[float | None] = []
        for event in range(event_count):
            row.append(None if mask[participant, event] else float(values[participant, event]))
        final.append(row)
    return np.ascontiguousarray(mask, dtype=np.bool_), final, coefficients


def _execute_ordinary(case: ResolvedSyntheticCase) -> _Execution:
    configuration = case.resolved_configuration
    participant_count = configuration["dimensions"]["participant_count"]
    original_labels, indicator = _group_assignment(case)
    snapshots: list[StageSnapshot] = [
        _snapshot(
            0,
            {
                "resolved_configuration_sha256": configuration[
                    "resolved_generator_configuration_sha256"
                ],
                "resolved_parameter_manifest_sha256": case.resolved_parameter_manifest[
                    "resolved_parameter_manifest_sha256"
                ],
                "resolved_mechanism_sha256": case.resolved_mechanism[
                    "resolved_generator_mechanism_sha256"
                ],
            },
        ),
        _snapshot(1, {"original_labels": original_labels}),
    ]
    latent = _latent_draws(case, indicator)
    snapshots.append(_snapshot(2, {"latent_time": latent.tolist()}))
    snapshots.append(_snapshot(3, {"contaminated_indexes": [], "latent_time": latent.tolist()}))
    subgroup_labels, subgroup_orders = _subgroups(case)
    centers = _participant_centers(configuration, subgroup_labels, subgroup_orders)
    transition = _transition(configuration, latent, centers)
    snapshots.append(_snapshot(4, {"transition_contribution": transition.tolist()}))
    covariate_ids, covariate_values, covariate_contribution = _covariates(case, indicator)
    snapshots.append(
        _snapshot(
            5,
            {
                "covariate_ids": covariate_ids,
                "covariate_values": covariate_values.tolist(),
                "covariate_contribution": covariate_contribution.tolist(),
            },
        )
    )
    group_effects = np.asarray(configuration["event_parameters"]["group_effect"], dtype=np.float64)
    group_contribution = np.multiply(indicator[:, None], group_effects[None, :], dtype=np.float64)
    snapshots.append(_snapshot(6, {"group_contribution": group_contribution.tolist()}))
    participant_effect = np.multiply(
        _rng(case, "participant_effect").standard_normal(participant_count, dtype=np.float64),
        configuration["participant_effect"]["standard_deviation"],
        dtype=np.float64,
    )
    loadings = np.asarray(
        configuration["event_parameters"]["participant_effect_loading"], dtype=np.float64
    )
    participant_contribution = np.multiply(
        participant_effect[:, None], loadings[None, :], dtype=np.float64
    )
    snapshots.append(
        _snapshot(
            7,
            {
                "participant_random_effect": participant_effect.tolist(),
                "participant_contribution": participant_contribution.tolist(),
            },
        )
    )
    normal, base_noise, skew = _measurement_noise(case)
    snapshots.append(
        _snapshot(
            8,
            {"measurement_normal_draws": normal.tolist(), "base_noise": base_noise.tolist()},
        )
    )
    baselines = np.asarray(configuration["event_parameters"]["baseline"], dtype=np.float64)
    baseline_transition = np.add(baselines[None, :], transition, dtype=np.float64)
    without_group = _left_add(
        baseline_transition,
        covariate_contribution,
        participant_contribution,
        base_noise,
        skew,
    )
    values = _left_add(
        baseline_transition,
        covariate_contribution,
        group_contribution,
        participant_contribution,
        base_noise,
        skew,
    )
    snapshots.append(
        _snapshot(
            9,
            {
                "centered_skew": skew.tolist(),
                "values_before_duplicate": values.tolist(),
            },
        )
    )
    scenario = configuration["scenario_parameters"]
    if scenario["pair_mode"] == "exact_duplicate_post_noise":
        source_id, target_id = scenario["pair_event_ids"]
        source = configuration["event_ids"].index(source_id)
        target = configuration["event_ids"].index(target_id)
        np.copyto(values[:, target], values[:, source], casting="no")
        np.copyto(without_group[:, target], without_group[:, source], casting="no")
    clean = np.ascontiguousarray(values, dtype=np.float64)
    snapshots.append(_snapshot(10, {"clean_values": clean.tolist()}))
    observed_labels, contaminated_indexes = _contaminate_labels(case, original_labels)
    snapshots.append(
        _snapshot(
            11,
            {
                "observed_labels": observed_labels,
                "contaminated_indexes": contaminated_indexes,
            },
        )
    )
    perturbed, outlier_participants, outlier_cells, outlier_offsets = _outliers(case, clean)
    snapshots.append(
        _snapshot(
            12,
            {
                "perturbed_values": perturbed.tolist(),
                "participant_indexes": outlier_participants,
                "cells": outlier_cells,
                "offsets": outlier_offsets,
            },
        )
    )
    mask, final_values, model_coefficients = _missingness(
        case, perturbed, covariate_values, indicator
    )
    snapshots.append(_snapshot(13, {"mask": mask.tolist(), "final_values": final_values}))
    if len(snapshots) != len(_STAGES):
        raise AssertionError("the closed stage sequence is incomplete")
    missing = configuration["missingness"]
    return _Execution(
        original_labels=original_labels,
        observed_labels=observed_labels,
        group_indicator=indicator,
        latent_time=latent,
        participant_effect=participant_effect,
        subgroup_labels=subgroup_labels,
        subgroup_orders=subgroup_orders,
        covariate_ids=covariate_ids,
        covariate_values=covariate_values,
        transition=transition,
        covariate_contribution=covariate_contribution,
        group_contribution=group_contribution,
        participant_contribution=participant_contribution,
        normal_draws=normal,
        base_noise=base_noise,
        centered_skew=skew,
        values_without_group=without_group,
        clean_values=clean,
        perturbed_values=perturbed,
        mask=mask,
        final_values=final_values,
        contaminated_indexes=contaminated_indexes,
        outlier_participants=outlier_participants,
        outlier_cells=outlier_cells,
        outlier_offsets=outlier_offsets,
        missing_event_probabilities=list(missing["event_probabilities"]),
        missing_marginal_probability=missing["marginal_probability"],
        missing_model_coefficients=model_coefficients,
        stage_snapshots=tuple(snapshots),
    )


def _execute_within_group_feature_permutation(
    case: ResolvedSyntheticCase,
    source_case: ResolvedSyntheticCase,
) -> _Execution:
    source = _execute_ordinary(source_case)
    clean = np.array(source.clean_values, dtype=np.float64, order="C", copy=True)
    perturbed = np.array(source.perturbed_values, dtype=np.float64, order="C", copy=True)
    mask = np.array(source.mask, dtype=np.bool_, order="C", copy=True)
    source_clean = np.array(source.clean_values, dtype=np.float64, order="C", copy=True)
    source_perturbed = np.array(
        source.perturbed_values,
        dtype=np.float64,
        order="C",
        copy=True,
    )
    source_mask = np.array(source.mask, dtype=np.bool_, order="C", copy=True)
    rng = _rng(case, "within_group_feature_permutation")
    labels = np.asarray(source.observed_labels, dtype=object)
    for label in sorted(set(source.observed_labels)):
        group_indexes = np.flatnonzero(labels == label)
        for event_index in range(perturbed.shape[1]):
            source_indexes = rng.permutation(group_indexes)
            clean[group_indexes, event_index] = source_clean[source_indexes, event_index]
            perturbed[group_indexes, event_index] = source_perturbed[
                source_indexes,
                event_index,
            ]
            mask[group_indexes, event_index] = source_mask[source_indexes, event_index]
    final_values = [
        [
            None if mask[row_index, event_index] else float(perturbed[row_index, event_index])
            for event_index in range(perturbed.shape[1])
        ]
        for row_index in range(perturbed.shape[0])
    ]
    snapshots = list(source.stage_snapshots)
    snapshots[0] = _snapshot(
        0,
        {
            "resolved_configuration_sha256": case.resolved_configuration[
                "resolved_generator_configuration_sha256"
            ],
            "resolved_parameter_manifest_sha256": case.resolved_parameter_manifest[
                "resolved_parameter_manifest_sha256"
            ],
            "resolved_mechanism_sha256": case.resolved_mechanism[
                "resolved_generator_mechanism_sha256"
            ],
        },
    )
    snapshots[10] = _snapshot(10, {"clean_values": clean.tolist()})
    snapshots[12] = _snapshot(
        12,
        {
            "perturbed_values": perturbed.tolist(),
            "participant_indexes": source.outlier_participants,
            "cells": source.outlier_cells,
            "offsets": source.outlier_offsets,
        },
    )
    snapshots[13] = _snapshot(
        13,
        {"mask": mask.tolist(), "final_values": final_values},
    )
    return replace(
        source,
        clean_values=np.ascontiguousarray(clean, dtype=np.float64),
        perturbed_values=np.ascontiguousarray(perturbed, dtype=np.float64),
        mask=np.ascontiguousarray(mask, dtype=np.bool_),
        final_values=final_values,
        stage_snapshots=tuple(snapshots),
    )


def _execute_label_permutation(
    case: ResolvedSyntheticCase,
    source_case: ResolvedSyntheticCase,
) -> _Execution:
    source = _execute_ordinary(source_case)
    observed_labels = [
        str(value)
        for value in _rng(case, "label_permutation").permutation(source.observed_labels)
    ]
    snapshots = list(source.stage_snapshots)
    snapshots[0] = _snapshot(
        0,
        {
            "resolved_configuration_sha256": case.resolved_configuration[
                "resolved_generator_configuration_sha256"
            ],
            "resolved_parameter_manifest_sha256": case.resolved_parameter_manifest[
                "resolved_parameter_manifest_sha256"
            ],
            "resolved_mechanism_sha256": case.resolved_mechanism[
                "resolved_generator_mechanism_sha256"
            ],
        },
    )
    snapshots[11] = _snapshot(
        11,
        {
            "observed_labels": observed_labels,
            "contaminated_indexes": source.contaminated_indexes,
        },
    )
    return replace(
        source,
        observed_labels=observed_labels,
        stage_snapshots=tuple(snapshots),
    )


def _array_sha256(array: NDArray[Any], dtype: str) -> str:
    contiguous = np.ascontiguousarray(array, dtype=np.dtype(dtype))
    return hashlib.sha256(contiguous.tobytes(order="C")).hexdigest()


def _generator_code_sha256() -> str:
    directory = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for name in (
        "authority.py",
        "models.py",
        "resolver.py",
        "generator.py",
        "pure_no_signal.py",
        "replay.py",
        "replay_resolution.py",
    ):
        path = directory / name
        if path.is_file():
            digest.update(name.encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _scientific_data(case: ResolvedSyntheticCase, execution: _Execution) -> dict[str, Any]:
    configuration = case.resolved_configuration
    participant_count = configuration["dimensions"]["participant_count"]
    preimage = {
        "schema_version": "ebm-audit-synthetic-scientific-data/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "synthetic_marker": "SYNTHETIC",
        "case_id": case.case_id,
        "dimensions": copy.deepcopy(configuration["dimensions"]),
        "participant_internal_indexes": list(range(participant_count)),
        "event_ids": copy.deepcopy(configuration["event_ids"]),
        "event_directions": copy.deepcopy(configuration["event_directions"]),
        "values": execution.final_values,
        "missingness_mask": execution.mask.tolist(),
        "analysis_group_labels": execution.observed_labels,
        "covariate_ids": execution.covariate_ids,
        "covariate_values": execution.covariate_values.tolist(),
        "generation_components": {
            "component_output_schema_version": "ebm-audit-generation-component-outputs/1.0",
            "participant_internal_indexes": list(range(participant_count)),
            "generation_group_labels": execution.original_labels,
            "participant_latent_time": execution.latent_time.tolist(),
            "participant_random_effect": execution.participant_effect.tolist(),
            "group_indicator": execution.group_indicator.tolist(),
            "transition_signal_contribution": execution.transition.tolist(),
            "covariate_contribution": execution.covariate_contribution.tolist(),
            "participant_effect_contribution": execution.participant_contribution.tolist(),
            "measurement_normal_draws": execution.normal_draws.tolist(),
            "measurement_noise_contribution": execution.base_noise.tolist(),
            "values_without_group_effect": execution.values_without_group.tolist(),
            "group_effect_contribution": execution.group_contribution.tolist(),
            "pre_missingness_values": execution.perturbed_values.tolist(),
        },
        "generated_scientific_data_sha256": None,
    }
    result = copy.deepcopy(preimage)
    result["digest_state"] = "PERSISTED"
    result["generated_scientific_data_sha256"] = structured_sha256_hex(
        "ebm-audit/generated-scientific-data/1", preimage
    )
    try:
        validate_instance(result, "synthetic-scientific-data.schema.json")
    except SchemaValidationError as exc:
        raise _invalid(
            "GENERATOR.SCIENTIFIC_DATA_SCHEMA_INVALID",
            "Generated synthetic data failed its closed schema.",
        ) from exc
    return result


def _order_truth(case: ResolvedSyntheticCase) -> dict[str, Any]:
    family = case.coordinate.family_id
    configuration = case.resolved_configuration
    event_ids = copy.deepcopy(configuration["event_ids"])
    equivalence = configuration["scenario_parameters"]["equivalence_block_event_ids"]
    if family in {"label_permutation_null", "within_group_feature_permutation_null"}:
        return {
            "truth_kind": "NONE",
            "strict_order_identifiable": False,
            "strict_order": [],
            "partial_order_blocks": [],
            "non_identifiability_reason": "REFITTED_NULL_TRANSFORMATION",
            "recoverable_signal": False,
        }
    if family == "pure_no_signal":
        return {
            "truth_kind": "NONE",
            "strict_order_identifiable": False,
            "strict_order": [],
            "partial_order_blocks": [],
            "non_identifiability_reason": "PURE_NO_SIGNAL",
            "recoverable_signal": False,
        }
    if family == "minority_alternate_sequence":
        return {
            "truth_kind": "MIXTURE_OF_STRICT_ORDERS",
            "strict_order_identifiable": False,
            "strict_order": [],
            "partial_order_blocks": [],
            "non_identifiability_reason": "MINORITY_ALTERNATE_SEQUENCE",
            "recoverable_signal": True,
        }
    if family == "opposing_sequences_50_50":
        return {
            "truth_kind": "MIXTURE_OF_STRICT_ORDERS",
            "strict_order_identifiable": False,
            "strict_order": [],
            "partial_order_blocks": [],
            "non_identifiability_reason": "OPPOSING_SEQUENCES",
            "recoverable_signal": True,
        }
    if equivalence:
        return {
            "truth_kind": "PARTIAL_ORDER",
            "strict_order_identifiable": False,
            "strict_order": [],
            "partial_order_blocks": [copy.deepcopy(equivalence)],
            "non_identifiability_reason": (
                "EXACT_DUPLICATE"
                if configuration["scenario_parameters"]["pair_mode"] == "exact_duplicate_post_noise"
                else "EQUIVALENCE_BLOCK"
            ),
            "recoverable_signal": True,
        }
    return {
        "truth_kind": "STRICT_TOTAL_ORDER",
        "strict_order_identifiable": True,
        "strict_order": event_ids,
        "partial_order_blocks": [],
        "non_identifiability_reason": None,
        "recoverable_signal": True,
    }


def _affected_tail_sides(case: ResolvedSyntheticCase) -> tuple[list[str], list[str]]:
    ids = case.resolved_mechanism["affected_tail_event_ids"]
    if not ids:
        return [], []
    configuration = case.resolved_configuration
    latent = configuration["latent_sampling"]
    restricted_low = min(latent["reference_window"][0], latent["at_risk_window"][0])
    restricted_high = max(latent["reference_window"][1], latent["at_risk_window"][1])
    # The contract's broad comparator uses [-1.5, 1.5] in current common defaults.
    broad_low = -1.5
    broad_high = 1.5
    sides: list[str] = []
    for event_id in ids:
        index = configuration["event_ids"].index(event_id)
        center = configuration["event_parameters"]["event_centers"][index]
        width = configuration["event_parameters"]["transition_width"][index]
        normal = broad_low <= center - 2.0 * width and restricted_low > center - 2.0 * width
        abnormal = broad_high >= center + 2.0 * width and restricted_high < center + 2.0 * width
        sides.append("BOTH" if normal and abnormal else "NORMAL" if normal else "ABNORMAL")
    return list(ids), sides


def _truth_stage_ledger(truth: dict[str, Any]) -> list[dict[str, Any]]:
    def pointer(value: object, path: str) -> Any:
        current = value
        for token in path[1:].split("/"):
            current = current[int(token)] if isinstance(current, list) else current[token]  # type: ignore[index]
        return current

    records: list[dict[str, Any]] = []
    previous: str | None = None
    for index, ((stage_id, domain), sources) in enumerate(
        zip(_STAGES, _TRUTH_STAGE_SOURCES, strict=True)
    ):
        source_digests = [
            structured_sha256_hex(
                "ebm-audit/synthetic-generation-stage-source/1",
                {
                    "owner_kind": "truth",
                    "json_pointer": source,
                    "value": copy.deepcopy(pointer(truth, source)),
                },
            )
            for source in sources
        ]
        record = {
            "stage_index": index,
            "stage_id": stage_id,
            "digest_domain": domain,
            "previous_stage_sha256": previous,
            "ordered_source_digests": source_digests,
            "stage_sha256": None,
        }
        record["stage_sha256"] = structured_sha256_hex(domain, record)
        records.append(record)
        previous = cast(str, record["stage_sha256"])
    return records


def _truth(
    case: ResolvedSyntheticCase,
    execution: _Execution,
    *,
    source_case: ResolvedSyntheticCase | None = None,
) -> dict[str, Any]:
    configuration = case.resolved_configuration
    participant_count = configuration["dimensions"]["participant_count"]
    event_count = configuration["dimensions"]["event_count"]
    order_truth = _order_truth(case)
    centers = configuration["event_parameters"]["event_centers"]
    stages: list[int | None]
    if order_truth["recoverable_signal"]:
        stages = [
            sum(1 for center in centers if execution.latent_time[index] >= center)
            for index in range(participant_count)
        ]
        stage_truth = {"state": "THRESHOLD_STAGE", "participant_stages": stages}
    else:
        stages = [None] * participant_count
        stage_truth = {"state": "NONE", "participant_stages": []}
    participant_rows = [
        {
            "participant_internal_index": index,
            "latent_time": float(execution.latent_time[index]),
            "participant_random_effect": float(execution.participant_effect[index]),
            "original_group_label": execution.original_labels[index],
            "observed_group_label": execution.observed_labels[index],
            "group_indicator": int(execution.group_indicator[index]),
            "group_effect_contribution": execution.group_contribution[index].tolist(),
            "values_without_group_effect": execution.values_without_group[index].tolist(),
            "pre_missingness_values": execution.perturbed_values[index].tolist(),
            "threshold_stage": stages[index],
        }
        for index in range(participant_count)
    ]
    if execution.subgroup_orders:
        subgroup_ids = [0, 1]
        subgroup_counts = [
            int(np.count_nonzero(execution.subgroup_labels == value)) for value in subgroup_ids
        ]
    else:
        subgroup_ids = [0]
        subgroup_counts = [participant_count]
    affected_ids, affected_sides = _affected_tail_sides(case)
    boundary_ids = configuration["scenario_parameters"]["boundary_rule_ids"]
    base_cutoff = configuration["scenario_parameters"]["base_quantile_cutoff"]
    shifts = configuration["scenario_parameters"]["boundary_quantile_shifts"]
    boundary_cutoffs = (
        [float(np.float64(base_cutoff) + np.float64(shift)) for shift in shifts]
        if boundary_ids
        else []
    )
    clean_digest = _array_sha256(execution.clean_values, "<f8")
    perturbed_digest = _array_sha256(execution.perturbed_values, "<f8")
    mask_digest = _array_sha256(execution.mask, "u1")
    family = case.coordinate.family_id
    preimage: dict[str, Any] = {
        "schema_version": "ebm-audit-synthetic-truth/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "synthetic_marker": "SYNTHETIC",
        "scenario_identity": {
            "family_id": family,
            "variant_id": case.coordinate.variant_id,
            "variant_index": case.variant_index,
            "case_id": case.case_id,
            "replicate_index": case.coordinate.replicate_index,
            "pre_root_stratum_id": case.resolved_mechanism["pre_root_stratum_id"],
            "planned_stratum_denominator": None,
        },
        "seed_identity": {
            "case_seed": case.case_seed,
            "source_case_seed": source_case.case_seed if source_case is not None else None,
            "comparator_case_seed": None,
            "shared_draw_seed": case.shared_draw_seed,
            "operation_seed": case.operation_seed,
            "component_seed_manifest_sha256": case.component_seed_manifest[
                "component_seed_manifest_sha256"
            ],
        },
        "dimensions": {"participant_count": participant_count, "event_count": event_count},
        "order_truth": order_truth,
        "stage_truth": stage_truth,
        "event_truth": {
            "event_ids": copy.deepcopy(configuration["event_ids"]),
            "centers": copy.deepcopy(centers),
            "widths": copy.deepcopy(configuration["event_parameters"]["transition_width"]),
            "baselines": copy.deepcopy(configuration["event_parameters"]["baseline"]),
            "amplitudes": copy.deepcopy(configuration["event_parameters"]["amplitude"]),
            "directions": copy.deepcopy(configuration["event_directions"]),
            "covariate_effects": copy.deepcopy(
                configuration["event_parameters"]["covariate_effect"]
            ),
            "group_effects": copy.deepcopy(configuration["event_parameters"]["group_effect"]),
            "participant_effect_loadings": copy.deepcopy(
                configuration["event_parameters"]["participant_effect_loading"]
            ),
            "noise_standard_deviations": copy.deepcopy(
                configuration["measurement_noise"]["standard_deviations"]
            ),
            "noise_correlation_matrix": copy.deepcopy(
                configuration["measurement_noise"]["correlation_matrix"]
            ),
        },
        "participant_truth": {
            "latent_time": execution.latent_time.tolist(),
            "participant_random_effect": execution.participant_effect.tolist(),
            "ordered_participants": participant_rows,
        },
        "group_truth": {
            "source_mechanism": configuration["latent_sampling"]["mode"],
            "original_labels": execution.original_labels,
            "observed_labels": execution.observed_labels,
            "contaminated_participant_indexes": execution.contaminated_indexes,
            "contamination_mechanism": (
                "BINARY_LABEL_FLIP" if execution.contaminated_indexes else "NONE"
            ),
            "contamination_fraction": float(
                configuration["scenario_parameters"]["contamination_fraction"] or 0.0
            ),
        },
        "subgroup_truth": {
            "subgroup_labels": execution.subgroup_labels.tolist(),
            "ordered_subgroup_ids": subgroup_ids,
            "subgroup_orders": execution.subgroup_orders,
            "subgroup_counts": subgroup_counts,
        },
        "covariate_truth": {
            "covariate_ids": execution.covariate_ids,
            "values": execution.covariate_values.tolist(),
            "distribution_id": (
                "NONE"
                if not execution.covariate_ids
                else "GROUP_SHIFTED_NORMAL"
                if configuration["covariates"]["mode"] == "one_group_shifted_normal"
                else "STANDARD_NORMAL"
            ),
            "parameters": (
                []
                if not execution.covariate_ids
                else [float(configuration["covariates"]["standardized_group_difference"] or 0.0)]
            ),
        },
        "outlier_truth": {
            "mode": configuration["outliers"]["mode"],
            "participant_indexes": execution.outlier_participants,
            "cells": execution.outlier_cells,
            "offsets": execution.outlier_offsets,
        },
        "missingness_truth": {
            "family": configuration["missingness"]["family"],
            "mask": execution.mask.tolist(),
            "event_probabilities": execution.missing_event_probabilities,
            "marginal_probability": execution.missing_marginal_probability,
            "model_coefficients": execution.missing_model_coefficients,
            "identity_permutation": None,
        },
        "mechanism_evidence": {
            "target_pair_event_ids": copy.deepcopy(
                configuration["scenario_parameters"]["pair_event_ids"]
            ),
            "equivalence_block_event_ids": copy.deepcopy(
                configuration["scenario_parameters"]["equivalence_block_event_ids"]
            ),
            "affected_tail_event_ids": affected_ids,
            "affected_tail_sides": affected_sides,
            "boundary_rule_ids": copy.deepcopy(boundary_ids),
            "boundary_quantile_cutoffs": boundary_cutoffs,
            "wrong_direction_event_ids": copy.deepcopy(
                configuration["scenario_parameters"]["wrong_direction_event_ids"]
            ),
            "ordered_comparator_operations_sha256": None,
        },
        "fpr_eligibility": {
            "eligibility_rule_id": "pure-no-signal-only/v1",
            "eligible": family == "pure_no_signal",
            "reason_code": (
                "PURE_NO_SIGNAL_INDEPENDENT_OPPORTUNITY"
                if family == "pure_no_signal"
                else "FAMILY_NOT_ELIGIBLE"
            ),
        },
        "generation_stage_hashes": [],
        "artifact_digests": {
            "generator_code_sha256": _generator_code_sha256(),
            "scenario_definitions_sha256": case.scenario_definitions_sha256,
            "resolved_generator_configuration_sha256": configuration[
                "resolved_generator_configuration_sha256"
            ],
            "resolved_parameter_manifest_sha256": case.resolved_parameter_manifest[
                "resolved_parameter_manifest_sha256"
            ],
            "resolved_generator_mechanism_sha256": case.resolved_mechanism[
                "resolved_generator_mechanism_sha256"
            ],
            "clean_array_sha256": clean_digest,
            "perturbed_array_sha256": perturbed_digest,
            "missingness_mask_sha256": mask_digest,
        },
        "truth_object_sha256": None,
    }
    preimage["generation_stage_hashes"] = _truth_stage_ledger(preimage)
    result = copy.deepcopy(preimage)
    result["digest_state"] = "PERSISTED"
    result["truth_object_sha256"] = structured_sha256_hex("ebm-audit/synthetic-truth/1", preimage)
    try:
        validate_instance(result, "synthetic-truth.schema.json")
    except SchemaValidationError as exc:
        raise _invalid(
            "GENERATOR.TRUTH_SCHEMA_INVALID",
            "Generated synthetic truth failed its closed schema.",
        ) from exc
    return result


def _immutable_float(array: FloatArray) -> FloatArray:
    copied = np.ascontiguousarray(array, dtype=np.float64)
    return np.frombuffer(copied.tobytes(order="C"), dtype=np.float64).reshape(copied.shape)


def _immutable_bool(array: BoolArray) -> BoolArray:
    copied = np.ascontiguousarray(array, dtype=np.bool_)
    return np.frombuffer(copied.tobytes(order="C"), dtype=np.bool_).reshape(copied.shape)


def _generate_already_authorized_case(
    case: ResolvedSyntheticCase,
    *,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> SyntheticCaseArtifacts:
    """Generate an exact case already owned by a sealed package transaction."""

    if case.coordinate.resolution_mode == "TRANSFORMED_SOURCE":
        if (
            case.coordinate.family_id not in _TRANSFORMED_SOURCE_FAMILIES
            or type(source_owner) is not AuthenticatedSourceOwner
        ):
            raise _invalid(
                "GENERATOR.TRANSFORMED_SOURCE_DATA_REQUIRED",
                "A transformed null requires its supported authenticated source owner.",
            )
        source_case = source_owner.resolved_case
        execution = (
            _execute_label_permutation(case, source_case)
            if case.coordinate.family_id == "label_permutation_null"
            else _execute_within_group_feature_permutation(case, source_case)
        )
    else:
        if source_owner is not None:
            raise _invalid(
                "GENERATOR.SOURCE_OWNER_UNEXPECTED",
                "An ordinary synthetic case cannot use a transformed source owner.",
            )
        source_case = None
        execution = _execute_ordinary(case)
    scientific_data = _scientific_data(case, execution)
    truth = _truth(case, execution, source_case=source_case)
    return SyntheticCaseArtifacts(
        resolved_case=case,
        scientific_data=scientific_data,
        truth=truth,
        stage_snapshots=execution.stage_snapshots,
        clean_values=_immutable_float(execution.clean_values),
        perturbed_values=_immutable_float(execution.perturbed_values),
        missingness_mask=_immutable_bool(execution.mask),
    )


def generate_synthetic_case(
    authority: ScenarioAuthority,
    case: ResolvedSyntheticCase,
    *,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> SyntheticCaseArtifacts:
    """Generate one unmistakably synthetic case entirely offline.

    Supported transformed nulls are regenerated from their exact authenticated
    source case. Other transformed-source families fail closed.
    """

    _validate_case_plan(authority, case, source_owner=source_owner)
    return _generate_already_authorized_case(case, source_owner=source_owner)
