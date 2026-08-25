"""Independent numerical replay for generated synthetic cases.

This module intentionally does not import the production generator.  It
re-derives component streams and recomputes the numerical stages from the
resolved evaluator-owned configuration.  Its result is internal typed evidence
until the project adds a closed replay-output/receipt schema.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, cast

import numpy as np
from numpy.typing import NDArray

from ebm_audit.protocol.canonical import structured_sha256_hex
from ebm_audit.protocol.errors import CanonicalizationError
from ebm_audit.schema.validation import collect_validation_errors

from .authority import COMPONENT_PATHS, ScenarioAuthority, load_scenario_authority
from .models import (
    AuthenticatedSourceOwner,
    ReplayReceipt,
    ResolvedSyntheticCase,
    StageSnapshot,
    SyntheticCaseArtifacts,
)
from .replay_resolution import resolve_development_case as _reconstruct_development_case

FloatArray = NDArray[np.float64]
IntArray = NDArray[np.int64]
BoolArray = NDArray[np.bool_]

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
_MATCHED_SHARED_PATHS = (
    "group_assignment",
    "latent_time",
    "covariates",
    "participant_effect",
    "measurement_normal",
    "measurement_scale",
    "measurement_skew",
    "contamination",
    "outliers",
    "missingness",
)


@dataclass(slots=True)
class _ReplayState:
    labels: list[str]
    observed_labels: list[str]
    indicator: IntArray
    latent: FloatArray
    participant_effect: FloatArray
    subgroup_labels: IntArray
    subgroup_orders: list[list[str]]
    covariate_ids: list[str]
    covariates: FloatArray
    transition: FloatArray
    covariate_term: FloatArray
    group_term: FloatArray
    participant_term: FloatArray
    normal_draws: FloatArray
    base_noise: FloatArray
    skew: FloatArray
    without_group: FloatArray
    clean: FloatArray
    perturbed: FloatArray
    mask: BoolArray
    values: list[list[float | None]]
    contaminated: list[int]
    outlier_participants: list[int]
    outlier_cells: list[dict[str, int]]
    outlier_offsets: list[float]
    model_coefficients: list[float]
    snapshots: tuple[StageSnapshot, ...]


def _seed(case: ResolvedSyntheticCase, path: str) -> str:
    record = case.component_seed(path)
    roots = {
        "CASE_SEED": case.case_seed,
        "SHARED_DRAW_SEED": case.shared_draw_seed,
        "OPERATION_SEED": case.operation_seed,
    }
    root = roots[record.root_kind]
    if root is None:
        raise ValueError("missing component root")
    expected = hmac.new(
        bytes.fromhex(root),
        b"ebm-audit-synthetic-component/v1\0" + path.encode(),
        hashlib.sha256,
    ).digest()
    if record.full_digest != "sha256:" + expected.hex() or record.seed_128 != expected[:16].hex():
        raise ValueError("component derivation mismatch")
    return expected[:16].hex()


def _rng(case: ResolvedSyntheticCase, path: str) -> np.random.Generator:
    return np.random.Generator(np.random.PCG64DXSM(int(_seed(case, path), 16)))


def _sigmoid(value: np.float64) -> np.float64:
    if value >= 0:
        return np.float64(1.0 / np.float64(1.0 + np.exp(-value)))
    exp_value = np.exp(value)
    return np.float64(exp_value / np.float64(1.0 + exp_value))


def _fold(terms: list[FloatArray]) -> FloatArray:
    result = np.array(terms[0], dtype=np.float64, order="C", copy=True)
    for term in terms[1:]:
        result = np.add(result, term, dtype=np.float64)
    if not np.all(np.isfinite(result)):
        raise ValueError("non-finite replay")
    return np.ascontiguousarray(result, dtype=np.float64)


def _snapshot(index: int, output: dict[str, Any]) -> StageSnapshot:
    stage_id, domain = _STAGES[index]
    return StageSnapshot(
        index,
        stage_id,
        domain,
        structured_sha256_hex(domain + "/execution-output", output),
        output,
    )


def _lehmer(events: list[str], inversions: int) -> list[str]:
    remaining = list(events)
    result: list[str] = []
    while remaining:
        index = min(inversions, len(remaining) - 1)
        result.append(remaining.pop(index))
        inversions -= index
    return result


def _group_and_latent(case: ResolvedSyntheticCase) -> tuple[list[str], IntArray, FloatArray]:
    config = case.resolved_configuration
    participant_count = config["dimensions"]["participant_count"]
    reference_count = config["group_generation"]["reference_count"]
    indicator = np.asarray(
        [0] * reference_count + [1] * (participant_count - reference_count), dtype=np.int64
    )
    _rng(case, "group_assignment").shuffle(indicator)
    labels = ["reference" if value == 0 else "at_risk" for value in indicator.tolist()]
    latent = np.empty(participant_count, dtype=np.float64)
    latent_rng = _rng(case, "latent_time")
    sampling = config["latent_sampling"]
    for index, group in enumerate(indicator.tolist()):
        window = (
            sampling["group_independent_window"]
            if sampling["mode"] == "GROUP_INDEPENDENT_WINDOW"
            else sampling["reference_window"]
            if group == 0
            else sampling["at_risk_window"]
        )
        if not isinstance(window, list) or len(window) != 2 or window[0] >= window[1]:
            raise ValueError("invalid latent window")
        latent[index] = np.float64(latent_rng.uniform(window[0], window[1]))
    return labels, indicator, latent


def _subgroups(case: ResolvedSyntheticCase) -> tuple[IntArray, list[list[str]]]:
    config = case.resolved_configuration
    family = case.coordinate.family_id
    participant_count = config["dimensions"]["participant_count"]
    events = cast(list[str], config["event_ids"])
    parameters = config["scenario_parameters"]
    if family == "minority_alternate_sequence":
        minority = min(
            participant_count - 1,
            max(1, round(participant_count * parameters["minority_fraction"])),
        )
        labels = np.asarray([0] * (participant_count - minority) + [1] * minority, dtype=np.int64)
        _rng(case, "subgroup_assignment").shuffle(labels)
        return labels, [events, _lehmer(events, parameters["alternate_inversions"])]
    if family == "opposing_sequences_50_50":
        if participant_count % 2:
            raise ValueError("opposing count is odd")
        labels = np.asarray(
            [0] * (participant_count // 2) + [1] * (participant_count // 2), dtype=np.int64
        )
        _rng(case, "subgroup_assignment").shuffle(labels)
        maximum = len(events) * (len(events) - 1) // 2
        inversions = round(parameters["opposing_relation_fraction"] * maximum)
        return labels, [events, _lehmer(events, inversions)]
    return np.zeros(participant_count, dtype=np.int64), []


def _transition(
    case: ResolvedSyntheticCase,
    latent: FloatArray,
    subgroup_labels: IntArray,
    subgroup_orders: list[list[str]],
) -> FloatArray:
    config = case.resolved_configuration
    events = cast(list[str], config["event_ids"])
    params = config["event_parameters"]
    base_centers = np.asarray(params["event_centers"], dtype=np.float64)
    centers = np.tile(base_centers, (latent.shape[0], 1))
    if subgroup_orders:
        ordered_centers = np.sort(base_centers)
        mappings: list[FloatArray] = []
        for order in subgroup_orders:
            mapping = np.empty(len(events), dtype=np.float64)
            for position, event_id in enumerate(order):
                mapping[events.index(event_id)] = ordered_centers[position]
            mappings.append(mapping)
        for participant, subgroup in enumerate(subgroup_labels.tolist()):
            centers[participant] = mappings[subgroup]
    widths = np.asarray(params["transition_width"], dtype=np.float64)
    amplitudes = np.asarray(params["amplitude"], dtype=np.float64)
    directions = np.asarray(
        [1.0 if direction == "higher" else -1.0 for direction in config["event_directions"]],
        dtype=np.float64,
    )
    result = np.empty_like(centers)
    for participant in range(latent.shape[0]):
        for event in range(len(events)):
            q = np.float64(
                np.float64(latent[participant] - centers[participant, event]) / widths[event]
            )
            result[participant, event] = np.float64(
                np.float64(directions[event] * amplitudes[event]) * _sigmoid(q)
            )
    return result


def _covariates(
    case: ResolvedSyntheticCase, indicator: IntArray
) -> tuple[list[str], FloatArray, FloatArray]:
    config = case.resolved_configuration
    participant_count = config["dimensions"]["participant_count"]
    event_count = config["dimensions"]["event_count"]
    mode = config["covariates"]["mode"]
    if mode == "none":
        return (
            [],
            np.empty((participant_count, 0), dtype=np.float64),
            np.zeros((participant_count, event_count), dtype=np.float64),
        )
    values = _rng(case, "covariates").standard_normal(participant_count, dtype=np.float64)
    if mode == "one_group_shifted_normal":
        difference = float(config["covariates"]["standardized_group_difference"])
        values = np.add(
            values,
            np.where(indicator == 0, -difference / 2.0, difference / 2.0),
            dtype=np.float64,
        )
    effects = np.asarray(config["event_parameters"]["covariate_effect"], dtype=np.float64)
    return (
        ["z01"],
        values[:, None],
        np.multiply(values[:, None], effects[None, :], dtype=np.float64),
    )


def _noise(case: ResolvedSyntheticCase) -> tuple[FloatArray, FloatArray, FloatArray]:
    config = case.resolved_configuration
    participant_count = config["dimensions"]["participant_count"]
    event_count = config["dimensions"]["event_count"]
    settings = config["measurement_noise"]
    sd = np.asarray(settings["standard_deviations"], dtype=np.float64)
    correlation = np.asarray(settings["correlation_matrix"], dtype=np.float64)
    lower = np.linalg.cholesky(np.diag(sd) @ correlation @ np.diag(sd))
    normal = _rng(case, "measurement_normal").standard_normal(
        (participant_count, event_count), dtype=np.float64
    )
    base = np.empty_like(normal)
    for participant in range(participant_count):
        base[participant] = lower @ normal[participant]
    family = settings["family"]
    if family in {"multivariate_student_t", "student_t_plus_centered_lognormal"}:
        degrees = float(settings["student_t_df"])
        scales = _rng(case, "measurement_scale").chisquare(degrees, participant_count)
        base = np.multiply(base, np.sqrt((degrees - 2.0) / scales)[:, None], dtype=np.float64)
    skew = np.zeros_like(base)
    if family in {"normal_plus_centered_lognormal", "student_t_plus_centered_lognormal"}:
        kappa = np.full(event_count, float(settings["centered_lognormal_sigma"]), dtype=np.float64)
        omega = np.multiply(float(settings["centered_lognormal_weight"]), sd, dtype=np.float64)
        draws = _rng(case, "measurement_skew").standard_normal(
            (participant_count, event_count), dtype=np.float64
        )
        exponent = np.subtract(
            np.multiply(draws, kappa[None, :], dtype=np.float64),
            np.square(kappa)[None, :] / 2.0,
            dtype=np.float64,
        )
        skew = np.multiply(omega[None, :], np.exp(exponent) - 1.0, dtype=np.float64)
    return normal, base, skew


def _labels(case: ResolvedSyntheticCase, labels: list[str]) -> tuple[list[str], list[int]]:
    fraction = case.resolved_configuration["scenario_parameters"]["contamination_fraction"]
    if case.coordinate.family_id != "control_contamination" or fraction is None:
        return list(labels), []
    count = round(len(labels) * fraction)
    indexes = sorted(
        int(item) for item in _rng(case, "contamination").choice(len(labels), count, replace=False)
    )
    observed = list(labels)
    for index in indexes:
        observed[index] = "at_risk" if observed[index] == "reference" else "reference"
    return observed, indexes


def _outliers(
    case: ResolvedSyntheticCase, clean: FloatArray
) -> tuple[FloatArray, list[int], list[dict[str, int]], list[float]]:
    settings = case.resolved_configuration["outliers"]
    if settings["mode"] == "none":
        return np.array(clean, copy=True, order="C"), [], [], []
    rng = _rng(case, "outliers")
    participants = sorted(
        int(item)
        for item in rng.choice(
            clean.shape[0], settings["injected_participant_count"], replace=False
        )
    )
    events = sorted(
        int(item)
        for item in rng.choice(clean.shape[1], settings["affected_event_count"], replace=False)
    )
    standard_deviations = np.asarray(
        case.resolved_configuration["measurement_noise"]["standard_deviations"],
        dtype=np.float64,
    )
    result = np.array(clean, copy=True, order="C")
    cells: list[dict[str, int]] = []
    offsets: list[float] = []
    sequence = 0
    for participant in participants:
        for event in events:
            sign = 1.0 if sequence % 2 == 0 else -1.0
            offset = float(
                np.float64(sign * settings["offset_noise_sd"]) * standard_deviations[event]
            )
            result[participant, event] = np.float64(result[participant, event] + offset)
            cells.append({"participant_index": participant, "event_index": event})
            offsets.append(offset)
            sequence += 1
    return result, participants, cells, offsets


def _mar_alpha(target: float, linear: FloatArray) -> float:
    def mean(alpha: float) -> float:
        accumulator = np.float64(0.0)
        for item in linear:
            accumulator = np.float64(accumulator + _sigmoid(np.float64(alpha + item)))
        return float(accumulator / np.float64(linear.shape[0]))

    low, high = -40.0, 40.0
    if not mean(low) <= target <= mean(high):
        raise ValueError("MAR target is unbracketed")
    for _ in range(200):
        midpoint = float(np.float64((low + high) / 2.0))
        if mean(midpoint) < target:
            low = midpoint
        else:
            high = midpoint
    return float(np.float64((low + high) / 2.0))


def _mask(
    case: ResolvedSyntheticCase,
    perturbed: FloatArray,
    covariates: FloatArray,
    indicator: IntArray,
) -> tuple[BoolArray, list[list[float | None]], list[float]]:
    settings = case.resolved_configuration["missingness"]
    family = settings["family"]
    if family == "none":
        probabilities = np.zeros_like(perturbed)
        coefficients: list[float] = []
    elif family == "MCAR":
        probabilities = np.tile(settings["event_probabilities"], (perturbed.shape[0], 1))
        coefficients = []
    elif family == "MAR":
        beta = float(settings["covariate_log_odds_coefficient"])
        eta = float(settings["group_log_odds_coefficient"])
        linear = np.add(covariates[:, 0] * beta, indicator * eta, dtype=np.float64)
        alpha = _mar_alpha(float(settings["marginal_probability"]), linear)
        coefficients = [alpha, beta, eta]
        row_probabilities = np.asarray(
            [_sigmoid(np.float64(alpha + item)) for item in linear], dtype=np.float64
        )
        probabilities = np.tile(row_probabilities[:, None], (1, perturbed.shape[1]))
    else:
        raise ValueError("unknown missingness family")
    mask = _rng(case, "missingness").random(perturbed.shape) < probabilities
    scenario = case.resolved_configuration["scenario_parameters"]
    if scenario["pair_mode"] == "exact_duplicate_post_noise":
        source_id, target_id = scenario["pair_event_ids"]
        event_ids = case.resolved_configuration["event_ids"]
        np.copyto(
            mask[:, event_ids.index(target_id)], mask[:, event_ids.index(source_id)], casting="no"
        )
    values = [
        [
            None if mask[participant, event] else float(perturbed[participant, event])
            for event in range(perturbed.shape[1])
        ]
        for participant in range(perturbed.shape[0])
    ]
    return np.ascontiguousarray(mask, dtype=np.bool_), values, coefficients


def _execute(case: ResolvedSyntheticCase) -> _ReplayState:
    config = case.resolved_configuration
    labels, indicator, latent = _group_and_latent(case)
    snapshots = [
        _snapshot(
            0,
            {
                "resolved_configuration_sha256": config["resolved_generator_configuration_sha256"],
                "resolved_parameter_manifest_sha256": case.resolved_parameter_manifest[
                    "resolved_parameter_manifest_sha256"
                ],
                "resolved_mechanism_sha256": case.resolved_mechanism[
                    "resolved_generator_mechanism_sha256"
                ],
            },
        ),
        _snapshot(1, {"original_labels": labels}),
        _snapshot(2, {"latent_time": latent.tolist()}),
        _snapshot(3, {"contaminated_indexes": [], "latent_time": latent.tolist()}),
    ]
    subgroup_labels, subgroup_orders = _subgroups(case)
    transition = _transition(case, latent, subgroup_labels, subgroup_orders)
    snapshots.append(_snapshot(4, {"transition_contribution": transition.tolist()}))
    covariate_ids, covariates, covariate_term = _covariates(case, indicator)
    snapshots.append(
        _snapshot(
            5,
            {
                "covariate_ids": covariate_ids,
                "covariate_values": covariates.tolist(),
                "covariate_contribution": covariate_term.tolist(),
            },
        )
    )
    group_effect = np.asarray(config["event_parameters"]["group_effect"], dtype=np.float64)
    group_term = np.multiply(indicator[:, None], group_effect[None, :], dtype=np.float64)
    snapshots.append(_snapshot(6, {"group_contribution": group_term.tolist()}))
    participant_effect = np.multiply(
        _rng(case, "participant_effect").standard_normal(
            config["dimensions"]["participant_count"], dtype=np.float64
        ),
        config["participant_effect"]["standard_deviation"],
        dtype=np.float64,
    )
    loadings = np.asarray(
        config["event_parameters"]["participant_effect_loading"], dtype=np.float64
    )
    participant_term = np.multiply(participant_effect[:, None], loadings[None, :], dtype=np.float64)
    snapshots.append(
        _snapshot(
            7,
            {
                "participant_random_effect": participant_effect.tolist(),
                "participant_contribution": participant_term.tolist(),
            },
        )
    )
    normal, base_noise, skew = _noise(case)
    snapshots.append(
        _snapshot(
            8,
            {"measurement_normal_draws": normal.tolist(), "base_noise": base_noise.tolist()},
        )
    )
    baseline = np.asarray(config["event_parameters"]["baseline"], dtype=np.float64)
    baseline_transition = np.add(baseline[None, :], transition, dtype=np.float64)
    without_group = _fold([baseline_transition, covariate_term, participant_term, base_noise, skew])
    values = _fold(
        [baseline_transition, covariate_term, group_term, participant_term, base_noise, skew]
    )
    snapshots.append(
        _snapshot(
            9,
            {"centered_skew": skew.tolist(), "values_before_duplicate": values.tolist()},
        )
    )
    scenario = config["scenario_parameters"]
    if scenario["pair_mode"] == "exact_duplicate_post_noise":
        source_id, target_id = scenario["pair_event_ids"]
        source = config["event_ids"].index(source_id)
        target = config["event_ids"].index(target_id)
        np.copyto(values[:, target], values[:, source], casting="no")
        np.copyto(without_group[:, target], without_group[:, source], casting="no")
    clean = np.ascontiguousarray(values, dtype=np.float64)
    snapshots.append(_snapshot(10, {"clean_values": clean.tolist()}))
    observed, contaminated = _labels(case, labels)
    snapshots.append(
        _snapshot(11, {"observed_labels": observed, "contaminated_indexes": contaminated})
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
    mask, final_values, coefficients = _mask(case, perturbed, covariates, indicator)
    snapshots.append(_snapshot(13, {"mask": mask.tolist(), "final_values": final_values}))
    return _ReplayState(
        labels,
        observed,
        indicator,
        latent,
        participant_effect,
        subgroup_labels,
        subgroup_orders,
        covariate_ids,
        covariates,
        transition,
        covariate_term,
        group_term,
        participant_term,
        normal,
        base_noise,
        skew,
        without_group,
        clean,
        perturbed,
        mask,
        final_values,
        contaminated,
        outlier_participants,
        outlier_cells,
        outlier_offsets,
        coefficients,
        tuple(snapshots),
    )


def _execute_within_group_feature_permutation(
    case: ResolvedSyntheticCase,
    source_case: ResolvedSyntheticCase,
) -> _ReplayState:
    source = _execute(source_case)
    clean = np.array(source.clean, dtype=np.float64, order="C", copy=True)
    perturbed = np.array(source.perturbed, dtype=np.float64, order="C", copy=True)
    mask = np.array(source.mask, dtype=np.bool_, order="C", copy=True)
    source_clean = np.array(source.clean, dtype=np.float64, order="C", copy=True)
    source_perturbed = np.array(source.perturbed, dtype=np.float64, order="C", copy=True)
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
    values = [
        [
            None if mask[row_index, event_index] else float(perturbed[row_index, event_index])
            for event_index in range(perturbed.shape[1])
        ]
        for row_index in range(perturbed.shape[0])
    ]
    snapshots = list(source.snapshots)
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
    snapshots[13] = _snapshot(13, {"mask": mask.tolist(), "final_values": values})
    return replace(
        source,
        clean=np.ascontiguousarray(clean, dtype=np.float64),
        perturbed=np.ascontiguousarray(perturbed, dtype=np.float64),
        mask=np.ascontiguousarray(mask, dtype=np.bool_),
        values=values,
        snapshots=tuple(snapshots),
    )


def _execute_label_permutation(
    case: ResolvedSyntheticCase,
    source_case: ResolvedSyntheticCase,
) -> _ReplayState:
    source = _execute(source_case)
    observed_labels = [
        str(value) for value in _rng(case, "label_permutation").permutation(source.observed_labels)
    ]
    snapshots = list(source.snapshots)
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
            "contaminated_indexes": source.contaminated,
        },
    )
    return replace(source, observed_labels=observed_labels, snapshots=tuple(snapshots))


def _digest_is_valid(owner: dict[str, Any], field: str, domain: str) -> bool:
    supplied = owner.get(field)
    preimage = copy.deepcopy(owner)
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage[field] = None
    return supplied == structured_sha256_hex(domain, preimage)


def _expected_data(case: ResolvedSyntheticCase, replay: _ReplayState) -> dict[str, Any]:
    config = case.resolved_configuration
    participant_count = config["dimensions"]["participant_count"]
    preimage = {
        "schema_version": "ebm-audit-synthetic-scientific-data/1.0",
        "digest_state": "DIGEST_PREIMAGE",
        "synthetic_marker": "SYNTHETIC",
        "case_id": case.case_id,
        "dimensions": copy.deepcopy(config["dimensions"]),
        "participant_internal_indexes": list(range(participant_count)),
        "event_ids": copy.deepcopy(config["event_ids"]),
        "event_directions": copy.deepcopy(config["event_directions"]),
        "values": replay.values,
        "missingness_mask": replay.mask.tolist(),
        "analysis_group_labels": replay.observed_labels,
        "covariate_ids": replay.covariate_ids,
        "covariate_values": replay.covariates.tolist(),
        "generation_components": {
            "component_output_schema_version": "ebm-audit-generation-component-outputs/1.0",
            "participant_internal_indexes": list(range(participant_count)),
            "generation_group_labels": replay.labels,
            "participant_latent_time": replay.latent.tolist(),
            "participant_random_effect": replay.participant_effect.tolist(),
            "group_indicator": replay.indicator.tolist(),
            "transition_signal_contribution": replay.transition.tolist(),
            "covariate_contribution": replay.covariate_term.tolist(),
            "participant_effect_contribution": replay.participant_term.tolist(),
            "measurement_normal_draws": replay.normal_draws.tolist(),
            "measurement_noise_contribution": replay.base_noise.tolist(),
            "values_without_group_effect": replay.without_group.tolist(),
            "group_effect_contribution": replay.group_term.tolist(),
            "pre_missingness_values": replay.perturbed.tolist(),
        },
        "generated_scientific_data_sha256": None,
    }
    expected = copy.deepcopy(preimage)
    expected["digest_state"] = "PERSISTED"
    expected["generated_scientific_data_sha256"] = structured_sha256_hex(
        "ebm-audit/generated-scientific-data/1", preimage
    )
    return expected


def _data_match(
    case: ResolvedSyntheticCase, candidate: dict[str, Any], replay: _ReplayState
) -> bool:
    return candidate == _expected_data(case, replay)


def _expected_order_truth(case: ResolvedSyntheticCase) -> dict[str, Any]:
    family = case.coordinate.family_id
    config = case.resolved_configuration
    event_ids = copy.deepcopy(config["event_ids"])
    equivalence = config["scenario_parameters"]["equivalence_block_event_ids"]
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
                if config["scenario_parameters"]["pair_mode"] == "exact_duplicate_post_noise"
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


def _affected_tail_sides(case: ResolvedSyntheticCase) -> tuple[list[str], list[str]]:
    ids = case.resolved_mechanism["affected_tail_event_ids"]
    if not ids:
        return [], []
    config = case.resolved_configuration
    latent = config["latent_sampling"]
    restricted_low = min(latent["reference_window"][0], latent["at_risk_window"][0])
    restricted_high = max(latent["reference_window"][1], latent["at_risk_window"][1])
    sides: list[str] = []
    for event_id in ids:
        index = config["event_ids"].index(event_id)
        center = config["event_parameters"]["event_centers"][index]
        width = config["event_parameters"]["transition_width"][index]
        normal = center - 2.0 * width >= -1.5 and restricted_low > center - 2.0 * width
        abnormal = center + 2.0 * width <= 1.5 and restricted_high < center + 2.0 * width
        sides.append("BOTH" if normal and abnormal else "NORMAL" if normal else "ABNORMAL")
    return list(ids), sides


def _pointer(value: object, path: str) -> Any:
    current = value
    for token in path[1:].split("/"):
        current = current[int(token)] if isinstance(current, list) else current[token]  # type: ignore[index]
    return current


def _truth_stage_ledger(truth: dict[str, Any]) -> list[dict[str, Any]]:
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
                    "value": copy.deepcopy(_pointer(truth, source)),
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


def _expected_truth(
    case: ResolvedSyntheticCase,
    replay: _ReplayState,
    *,
    source_case: ResolvedSyntheticCase | None = None,
) -> dict[str, Any]:
    config = case.resolved_configuration
    participant_count = config["dimensions"]["participant_count"]
    event_count = config["dimensions"]["event_count"]
    order_truth = _expected_order_truth(case)
    centers = config["event_parameters"]["event_centers"]
    stage_values: list[int | None]
    if order_truth["recoverable_signal"]:
        stage_values = [
            sum(1 for center in centers if replay.latent[index] >= center)
            for index in range(participant_count)
        ]
        stage_truth = {
            "state": "THRESHOLD_STAGE",
            "participant_stages": copy.deepcopy(stage_values),
        }
    else:
        stage_values = [None] * participant_count
        stage_truth = {"state": "NONE", "participant_stages": []}
    participant_rows = [
        {
            "participant_internal_index": index,
            "latent_time": float(replay.latent[index]),
            "participant_random_effect": float(replay.participant_effect[index]),
            "original_group_label": replay.labels[index],
            "observed_group_label": replay.observed_labels[index],
            "group_indicator": int(replay.indicator[index]),
            "group_effect_contribution": replay.group_term[index].tolist(),
            "values_without_group_effect": replay.without_group[index].tolist(),
            "pre_missingness_values": replay.perturbed[index].tolist(),
            "threshold_stage": stage_values[index],
        }
        for index in range(participant_count)
    ]
    if replay.subgroup_orders:
        subgroup_ids = [0, 1]
        subgroup_counts = [
            int(np.count_nonzero(replay.subgroup_labels == value)) for value in subgroup_ids
        ]
    else:
        subgroup_ids = [0]
        subgroup_counts = [participant_count]
    affected_ids, affected_sides = _affected_tail_sides(case)
    scenario = config["scenario_parameters"]
    boundary_ids = scenario["boundary_rule_ids"]
    base_cutoff = scenario["base_quantile_cutoff"]
    shifts = scenario["boundary_quantile_shifts"]
    boundary_cutoffs = (
        [float(np.float64(base_cutoff) + np.float64(shift)) for shift in shifts]
        if boundary_ids
        else []
    )
    family = case.coordinate.family_id
    missing = config["missingness"]
    truth: dict[str, Any] = {
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
            "event_ids": copy.deepcopy(config["event_ids"]),
            "centers": copy.deepcopy(centers),
            "widths": copy.deepcopy(config["event_parameters"]["transition_width"]),
            "baselines": copy.deepcopy(config["event_parameters"]["baseline"]),
            "amplitudes": copy.deepcopy(config["event_parameters"]["amplitude"]),
            "directions": copy.deepcopy(config["event_directions"]),
            "covariate_effects": copy.deepcopy(config["event_parameters"]["covariate_effect"]),
            "group_effects": copy.deepcopy(config["event_parameters"]["group_effect"]),
            "participant_effect_loadings": copy.deepcopy(
                config["event_parameters"]["participant_effect_loading"]
            ),
            "noise_standard_deviations": copy.deepcopy(
                config["measurement_noise"]["standard_deviations"]
            ),
            "noise_correlation_matrix": copy.deepcopy(
                config["measurement_noise"]["correlation_matrix"]
            ),
        },
        "participant_truth": {
            "latent_time": replay.latent.tolist(),
            "participant_random_effect": replay.participant_effect.tolist(),
            "ordered_participants": participant_rows,
        },
        "group_truth": {
            "source_mechanism": config["latent_sampling"]["mode"],
            "original_labels": replay.labels,
            "observed_labels": replay.observed_labels,
            "contaminated_participant_indexes": replay.contaminated,
            "contamination_mechanism": "BINARY_LABEL_FLIP" if replay.contaminated else "NONE",
            "contamination_fraction": float(scenario["contamination_fraction"] or 0.0),
        },
        "subgroup_truth": {
            "subgroup_labels": replay.subgroup_labels.tolist(),
            "ordered_subgroup_ids": subgroup_ids,
            "subgroup_orders": replay.subgroup_orders,
            "subgroup_counts": subgroup_counts,
        },
        "covariate_truth": {
            "covariate_ids": replay.covariate_ids,
            "values": replay.covariates.tolist(),
            "distribution_id": (
                "NONE"
                if not replay.covariate_ids
                else "GROUP_SHIFTED_NORMAL"
                if config["covariates"]["mode"] == "one_group_shifted_normal"
                else "STANDARD_NORMAL"
            ),
            "parameters": (
                []
                if not replay.covariate_ids
                else [float(config["covariates"]["standardized_group_difference"] or 0.0)]
            ),
        },
        "outlier_truth": {
            "mode": config["outliers"]["mode"],
            "participant_indexes": replay.outlier_participants,
            "cells": replay.outlier_cells,
            "offsets": replay.outlier_offsets,
        },
        "missingness_truth": {
            "family": missing["family"],
            "mask": replay.mask.tolist(),
            "event_probabilities": copy.deepcopy(missing["event_probabilities"]),
            "marginal_probability": missing["marginal_probability"],
            "model_coefficients": replay.model_coefficients,
            "identity_permutation": None,
        },
        "mechanism_evidence": {
            "target_pair_event_ids": copy.deepcopy(scenario["pair_event_ids"]),
            "equivalence_block_event_ids": copy.deepcopy(scenario["equivalence_block_event_ids"]),
            "affected_tail_event_ids": affected_ids,
            "affected_tail_sides": affected_sides,
            "boundary_rule_ids": copy.deepcopy(boundary_ids),
            "boundary_quantile_cutoffs": boundary_cutoffs,
            "wrong_direction_event_ids": copy.deepcopy(scenario["wrong_direction_event_ids"]),
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
            "resolved_generator_configuration_sha256": config[
                "resolved_generator_configuration_sha256"
            ],
            "resolved_parameter_manifest_sha256": case.resolved_parameter_manifest[
                "resolved_parameter_manifest_sha256"
            ],
            "resolved_generator_mechanism_sha256": case.resolved_mechanism[
                "resolved_generator_mechanism_sha256"
            ],
            "clean_array_sha256": _array_sha256(replay.clean, "<f8"),
            "perturbed_array_sha256": _array_sha256(replay.perturbed, "<f8"),
            "missingness_mask_sha256": _array_sha256(replay.mask, "u1"),
        },
        "truth_object_sha256": None,
    }
    truth["generation_stage_hashes"] = _truth_stage_ledger(truth)
    result = copy.deepcopy(truth)
    result["digest_state"] = "PERSISTED"
    result["truth_object_sha256"] = structured_sha256_hex("ebm-audit/synthetic-truth/1", truth)
    return result


def _truth_match(
    case: ResolvedSyntheticCase,
    truth: dict[str, Any],
    replay: _ReplayState,
    *,
    source_case: ResolvedSyntheticCase | None = None,
) -> bool:
    return truth == _expected_truth(case, replay, source_case=source_case)


def _authenticated_matched_case_is_valid(
    ordinary: ResolvedSyntheticCase,
    matched: ResolvedSyntheticCase,
) -> bool:
    if (
        ordinary.coordinate != matched.coordinate
        or ordinary.variant_index != matched.variant_index
        or ordinary.case_id != matched.case_id
        or ordinary.case_seed != matched.case_seed
        or ordinary.operation_seed != matched.operation_seed
        or ordinary.source_contract_sha256 != matched.source_contract_sha256
        or ordinary.scenario_definitions_sha256 != matched.scenario_definitions_sha256
        or ordinary.field_resolutions != matched.field_resolutions
        or ordinary.resolved_parameter_manifest != matched.resolved_parameter_manifest
        or ordinary.resolved_configuration != matched.resolved_configuration
        or ordinary.resolved_mechanism != matched.resolved_mechanism
        or matched.shared_draw_seed is None
    ):
        return False
    expected_bundle = copy.deepcopy(ordinary.resolution_bundle)
    expected_bundle["component_seed_manifest"] = matched.component_seed_manifest
    context = matched.component_seed_manifest.get("root_assignment_context")
    if (
        matched.resolution_bundle != expected_bundle
        or not isinstance(context, dict)
        or context
        != {
            "kind": "DEVELOPMENT_MATCHED_COMPARATOR",
            "comparator_id": "cmp_moderate_signal_vs_pure_no_signal",
            "source_variant_id": "moderate_57_public",
            "pair_index": matched.coordinate.replicate_index,
        }
        or matched.component_seed_manifest.get("shared_draw_seed") != matched.shared_draw_seed
        or matched.component_seed_manifest.get("shared_component_paths")
        != list(_MATCHED_SHARED_PATHS)
        or matched.component_seed_manifest.get("operation_component_paths") != []
    ):
        return False
    for path in COMPONENT_PATHS:
        actual = matched.component_seed(path)
        if path in _MATCHED_SHARED_PATHS:
            if actual.root_kind != "SHARED_DRAW_SEED" or actual.shared is not True:
                return False
        elif (
            actual != ordinary.component_seed(path)
            or actual.root_kind != "CASE_SEED"
            or actual.shared is not False
        ):
            return False
    return True


def _replay_already_authorized_case(
    case: ResolvedSyntheticCase,
    candidate: SyntheticCaseArtifacts,
    *,
    authority: ScenarioAuthority,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> ReplayReceipt:
    """Replay an exact case already owned by a sealed package transaction."""

    invalid = ReplayReceipt("GENERATOR_INVALID", None, 0, None, None, False, False)
    if (
        not isinstance(case, ResolvedSyntheticCase)
        or not isinstance(candidate, SyntheticCaseArtifacts)
        or not isinstance(authority, ScenarioAuthority)
    ):
        return invalid
    try:
        strict_authority = load_scenario_authority(authority.exact_bytes)
        if strict_authority != authority:
            return invalid
        if candidate.resolved_case != case:
            return invalid
        if case.coordinate.resolution_mode == "TRANSFORMED_SOURCE":
            if (
                case.coordinate.family_id not in _TRANSFORMED_SOURCE_FAMILIES
                or type(source_owner) is not AuthenticatedSourceOwner
            ):
                return invalid
            strict_authority.verify_resolved_case(case, source_owner=source_owner)
            source_case = source_owner.resolved_case
        else:
            if source_owner is not None:
                return invalid
            source_case = None
    except Exception:
        # Malformed nested values can define hostile equality behavior. This
        # public validation boundary is total and never exposes exception text.
        return invalid
    if (
        collect_validation_errors(
            case.resolution_bundle, "synthetic-resolved-configuration.schema.json"
        )
        or not _digest_is_valid(
            case.resolved_configuration,
            "resolved_generator_configuration_sha256",
            "ebm-audit/resolved-generator-configuration/1",
        )
        or not _digest_is_valid(
            case.resolved_parameter_manifest,
            "resolved_parameter_manifest_sha256",
            "ebm-audit/resolved-parameter-manifest/1",
        )
        or not _digest_is_valid(
            case.resolved_mechanism,
            "resolved_generator_mechanism_sha256",
            "ebm-audit/resolved-generator-mechanism/1",
        )
        or not _digest_is_valid(
            case.component_seed_manifest,
            "component_seed_manifest_sha256",
            "ebm-audit/component-seed-manifest/1",
        )
        or case.resolved_parameter_manifest.get("field_draws")
        != [row.as_dict() for row in case.field_resolutions]
    ):
        return ReplayReceipt("GENERATOR_INVALID", None, 0, None, None, False, False)
    if collect_validation_errors(
        candidate.scientific_data, "synthetic-scientific-data.schema.json"
    ) or collect_validation_errors(candidate.truth, "synthetic-truth.schema.json"):
        return ReplayReceipt("GENERATOR_INVALID", None, 0, None, None, False, False)
    try:
        if source_case is None:
            replay = _execute(case)
        elif case.coordinate.family_id == "label_permutation_null":
            replay = _execute_label_permutation(case, source_case)
        else:
            replay = _execute_within_group_feature_permutation(case, source_case)
    except (ArithmeticError, KeyError, TypeError, ValueError, np.linalg.LinAlgError):
        return ReplayReceipt("GENERATOR_INVALID", None, 0, None, None, False, False)
    candidate_stages = candidate.stage_snapshots
    compared = 0
    first_mismatch: str | None = None
    expected_digest: str | None = None
    actual_digest: str | None = None
    for index, expected in enumerate(replay.snapshots):
        if index >= len(candidate_stages):
            first_mismatch = expected.stage_id
            expected_digest = expected.output_sha256
            break
        actual = candidate_stages[index]
        if not isinstance(actual, StageSnapshot):
            return ReplayReceipt("GENERATOR_INVALID", None, compared, None, None, False, False)
        try:
            actual_recomputed = structured_sha256_hex(
                expected.digest_domain + "/execution-output", actual.output
            )
        except (CanonicalizationError, RecursionError):
            return ReplayReceipt("GENERATOR_INVALID", None, compared, None, None, False, False)
        if (
            actual.stage_index != expected.stage_index
            or actual.stage_id != expected.stage_id
            or actual.digest_domain != expected.digest_domain
            or actual.output_sha256 != actual_recomputed
            or actual.output != expected.output
            or actual_recomputed != expected.output_sha256
        ):
            first_mismatch = expected.stage_id
            expected_digest = expected.output_sha256
            actual_digest = actual_recomputed
            break
        compared += 1
    if first_mismatch is None and len(candidate_stages) != len(replay.snapshots):
        first_mismatch = "unexpected_extra_stage"
    array_match = (
        isinstance(candidate.clean_values, np.ndarray)
        and isinstance(candidate.perturbed_values, np.ndarray)
        and isinstance(candidate.missingness_mask, np.ndarray)
        and candidate.clean_values.dtype == np.dtype(np.float64)
        and candidate.perturbed_values.dtype == np.dtype(np.float64)
        and candidate.missingness_mask.dtype == np.dtype(np.bool_)
        and candidate.clean_values.flags.c_contiguous
        and candidate.perturbed_values.flags.c_contiguous
        and candidate.missingness_mask.flags.c_contiguous
        and np.array_equal(candidate.clean_values, replay.clean)
        and np.array_equal(candidate.perturbed_values, replay.perturbed)
        and np.array_equal(candidate.missingness_mask, replay.mask)
    )
    data_match = _data_match(case, candidate.scientific_data, replay) and array_match
    truth_match = _truth_match(
        case,
        candidate.truth,
        replay,
        source_case=source_case,
    )
    status: Literal["MATCH", "MISMATCH"] = (
        "MATCH" if first_mismatch is None and data_match and truth_match else "MISMATCH"
    )
    return ReplayReceipt(
        status,
        first_mismatch,
        compared,
        expected_digest,
        actual_digest,
        data_match,
        truth_match,
    )


def _replay_synthetic_case_impl(
    case: ResolvedSyntheticCase,
    candidate: SyntheticCaseArtifacts,
    *,
    authority: ScenarioAuthority,
    authenticated_ordinary_case: ResolvedSyntheticCase | None = None,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> ReplayReceipt:
    """Verify the public owner route, then call the shared replay core."""

    invalid = ReplayReceipt("GENERATOR_INVALID", None, 0, None, None, False, False)
    if (
        not isinstance(case, ResolvedSyntheticCase)
        or not isinstance(candidate, SyntheticCaseArtifacts)
        or not isinstance(authority, ScenarioAuthority)
    ):
        return invalid
    try:
        strict_authority = load_scenario_authority(authority.exact_bytes)
        if strict_authority != authority:
            return invalid
        expected_case = _reconstruct_development_case(
            strict_authority,
            case.coordinate,
            source_owner=source_owner,
        )
        if authenticated_ordinary_case is None:
            owner_valid = case == expected_case
        else:
            owner_valid = (
                authenticated_ordinary_case == expected_case
                and _authenticated_matched_case_is_valid(
                    authenticated_ordinary_case,
                    case,
                )
            )
        if not owner_valid:
            return invalid
    except Exception:
        return invalid
    return _replay_already_authorized_case(
        case,
        candidate,
        authority=strict_authority,
        source_owner=source_owner,
    )


def replay_synthetic_case(
    case: ResolvedSyntheticCase,
    candidate: SyntheticCaseArtifacts,
    *,
    authority: ScenarioAuthority,
    source_owner: AuthenticatedSourceOwner | None = None,
) -> ReplayReceipt:
    """Reconstruct and compare all owners, failing closed for malformed input."""

    try:
        return _replay_synthetic_case_impl(
            case,
            candidate,
            authority=authority,
            source_owner=source_owner,
        )
    except Exception:
        # This is the public untrusted-artifact boundary. Nested containers can
        # define hostile iteration, length, or equality behavior; no exception
        # text or participant-bearing value may escape.
        return ReplayReceipt("GENERATOR_INVALID", None, 0, None, None, False, False)


def _replay_authenticated_matched_case(
    ordinary_case: ResolvedSyntheticCase,
    matched_case: ResolvedSyntheticCase,
    candidate: SyntheticCaseArtifacts,
    *,
    authority: ScenarioAuthority,
) -> ReplayReceipt:
    """Replay one fixed matched member against its ordinary authority owner."""

    try:
        return _replay_synthetic_case_impl(
            matched_case,
            candidate,
            authority=authority,
            authenticated_ordinary_case=ordinary_case,
        )
    except Exception:
        return ReplayReceipt("GENERATOR_INVALID", None, 0, None, None, False, False)
