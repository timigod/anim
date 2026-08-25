"""Transparent SYNTHETIC-ONLY exact EBM for conformance checks."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, cast

import numpy as np
from numpy.typing import NDArray

from ebm_audit.oracle import ExactOracleInput
from ebm_audit.oracle.exact import _solve_exact_oracle_compact
from ebm_audit.protocol import (
    adapter_semantics_digest,
    stage_semantics_digest,
    structured_sha256,
    worker_fit_payload_digest,
)
from ebm_audit.schema import validate_instance
from ebm_audit.synthetic.conformance import (
    CONFORMANCE_ARRAY_NAMES,
    CONFORMANCE_GENERATION_SEED,
    CONFORMANCE_GENERATOR_ID,
    CONFORMANCE_GENERATOR_VERSION,
    CONFORMANCE_MAX_EVENT_COUNT,
    CONFORMANCE_MIN_EVENT_COUNT,
    CONFORMANCE_REPLICATE,
    CONFORMANCE_SCENARIO_ID,
    ConformanceGeneratedInput,
    build_conformance_provenance,
    conformance_complete_truth_record,
    conformance_generator_record,
    conformance_generator_record_sha256,
    generate_conformance_input,
)
from ebm_audit.synthetic.provenance import (
    PROJECT_SYNTHETIC_ARRAY_NAMES,
    PROJECT_SYNTHETIC_GENERATOR_ID,
    PROJECT_SYNTHETIC_GENERATOR_VERSION,
    project_candidate_array_catalog_sha256,
    project_candidate_dataset_sha256,
    project_candidate_derivation_selector,
    project_candidate_operation_intent_sha256,
    project_candidate_provenance_binding_sha256,
    project_synthetic_generator_code_sha256,
    project_synthetic_generator_record_sha256,
)
from ebm_audit.worker_sdk import (
    SyntheticProvenance,
    WorkerBackend,
    WorkerFailure,
    WorkerSuccess,
    array_catalog_entry,
    load_catalogued_npz_arrays,
)
from ebm_audit.workers.identity import WorkerIdentityMaterial
from ebm_audit.workers.structural import (
    ALGORITHM_ID as FIXTURE_ALGORITHM_ID,
)
from ebm_audit.workers.structural import (
    FIXTURE_STAGE_SEMANTICS_DIGEST,
    DeterministicFixtureBackend,
)

CONFORMANCE_ALGORITHM_ID = "conformance-exact-gaussian"
CONFORMANCE_MODEL_VERSION = "fixed-directional-gaussian/1.0"

_NORMAL_MEAN = -1.0
_ABNORMAL_MEAN = 1.0
_GAUSSIAN_SIGMA = 1.0
_EXACT_OUTPUTS = frozenset(
    {
        "central_order",
        "position_probabilities",
        "pairwise_precedence",
        "training_stage_posterior",
        "training_hard_stages",
        "training_expected_stage",
    }
)
_TRAINING_STAGE_OUTPUTS = frozenset(
    {
        "training_stage_posterior",
        "training_hard_stages",
        "training_expected_stage",
    }
)
_EVALUATION_STAGE_OUTPUTS = (
    "evaluation_stage_posterior",
    "evaluation_hard_stages",
    "evaluation_expected_stage",
)
_PRIVATE_ORDER = "backend.conformance-ebm.exact-order"
_PRIVATE_GAUSSIANS = "backend.conformance-ebm.fixed-gaussian-parameters"
_PRIVATE_STAGE_PRIOR = "backend.conformance-ebm.uniform-stage-prior"
_STAGE_SEMANTICS_DEFINITION = {
    "stage_semantics_schema_version": "ebm-audit-stage-semantics/1.0",
    "stage_model_availability": "AVAILABLE",
    "stage_axis_id": "strict-prefix-count-v1",
    "unavailable_reason_code": None,
    "reference_selection_method_id": "exact-canonical-best-order-v1",
    "fitted_distribution_method_id": "fixed-directional-gaussian-v1",
    "stage_prior_method_id": "uniform-stage-prior-v1",
    "stage_prior_max_iterations": 1,
    "final_prior_residual_method_id": "fixed-prior-zero-residual-v1",
    "final_prior_residual_tolerance": 1e-15,
    "final_prior_residual_comparison_rule_id": "strictly-less-than-v1",
    "final_prior_residual_failure_status": "BACKEND_ERROR",
    "final_prior_residual_failure_code": "STAGING.FINAL_PRIOR_NOT_CONVERGED",
    "posterior_method_id": "exact-canonical-order-stage-posterior-v1",
    "staging_rng_rule_id": "no-random-state-v1",
    "map_rule_id": "lowest-index-exact-posterior-maximum-v1",
    "expected_stage_rule_id": "posterior-mean-zero-to-n-v1",
    "fixed_evaluation_rule_id": "fixed-evaluation-unavailable-v1",
}
CONFORMANCE_STAGE_SEMANTICS_DIGEST = stage_semantics_digest(_STAGE_SEMANTICS_DEFINITION)


def conformance_exact_model_record() -> dict[str, object]:
    """Return the complete fixed likelihood and exact-inference definition."""

    return {
        "model_schema_version": "ebm-audit-conformance-exact-model/1.0",
        "model_version": CONFORMANCE_MODEL_VERSION,
        "likelihood_family": "univariate-gaussian-log-density/1",
        "normal_mean_for_higher_event": _NORMAL_MEAN,
        "abnormal_mean_for_higher_event": _ABNORMAL_MEAN,
        "sigma": _GAUSSIAN_SIGMA,
        "direction_rule": "lower-events-negate-both-higher-event-means/1",
        "stage_prior": "uniform-over-zero-through-event-count/1",
        "order_inference": "exact-enumeration-all-permutations/1",
        "minimum_events": CONFORMANCE_MIN_EVENT_COUNT,
        "maximum_events": CONFORMANCE_MAX_EVENT_COUNT,
    }


def conformance_exact_oracle_input(
    generated: ConformanceGeneratedInput,
    *,
    event_ids: tuple[str, ...],
) -> ExactOracleInput:
    """Map a generated fixture to the versioned fixed Gaussian oracle input."""

    values = np.asarray(generated.arrays["train_values"], dtype=np.float64)
    directions = cast(
        tuple[Literal["higher", "lower"], ...],
        tuple(generated.event_directions),
    )
    if values.shape[1] != len(event_ids) or len(directions) != len(event_ids):
        raise ValueError("The conformance event metadata does not align with the values.")
    normal_means = np.asarray(
        [_NORMAL_MEAN if direction == "higher" else -_NORMAL_MEAN for direction in directions],
        dtype=np.float64,
    )
    abnormal_means = np.asarray(
        [_ABNORMAL_MEAN if direction == "higher" else -_ABNORMAL_MEAN for direction in directions],
        dtype=np.float64,
    )
    log_normalizer = np.log(_GAUSSIAN_SIGMA * np.sqrt(2.0 * np.pi))
    log_p_not_abnormal = (
        -0.5 * np.square((values - normal_means[None, :]) / _GAUSSIAN_SIGMA) - log_normalizer
    )
    log_p_abnormal = (
        -0.5 * np.square((values - abnormal_means[None, :]) / _GAUSSIAN_SIGMA) - log_normalizer
    )
    stage_prior = np.full(
        len(event_ids) + 1,
        1.0 / float(len(event_ids) + 1),
        dtype=np.float64,
    )
    return ExactOracleInput(
        event_ids=event_ids,
        event_directions=directions,
        log_p_not_abnormal=np.asarray(log_p_not_abnormal, dtype=np.float64),
        log_p_abnormal=np.asarray(log_p_abnormal, dtype=np.float64),
        stage_prior=stage_prior,
    )


def _stage_summaries(
    stage_posterior: NDArray[np.float64],
) -> tuple[NDArray[Any], NDArray[Any], NDArray[Any]]:
    maxima = np.max(stage_posterior, axis=1, keepdims=True)
    ties = np.asarray(stage_posterior == maxima, dtype=np.bool_)
    hard = np.argmax(stage_posterior, axis=1).astype(np.int32)
    stages = np.arange(stage_posterior.shape[1], dtype=np.float64)
    expected = np.asarray(stage_posterior @ stages, dtype=np.float64)
    return hard, ties, expected


def conformance_exact_reference_record(
    *,
    participant_count: int,
    event_count: int,
    event_ids: tuple[str, ...],
) -> dict[str, object]:
    """Return post-admission model parameters and exact expected outputs."""

    known_truth = conformance_complete_truth_record(
        participant_count=participant_count,
        event_count=event_count,
        event_ids=event_ids,
    )
    generated = generate_conformance_input(
        participant_count=participant_count,
        event_count=event_count,
        event_ids=event_ids,
    )
    oracle_input = conformance_exact_oracle_input(generated, event_ids=event_ids)
    exact = _solve_exact_oracle_compact(oracle_input)
    hard, tie_mask, expected = _stage_summaries(exact.canonical_best_order_stage_posteriors)
    expected_outputs = {
        "log_p_not_abnormal": oracle_input.log_p_not_abnormal.tolist(),
        "log_p_abnormal": oracle_input.log_p_abnormal.tolist(),
        "stage_prior": oracle_input.stage_prior.tolist(),
        "canonical_best_order": list(exact.canonical_best_order),
        "best_order_count": exact.best_order_count,
        "position_probabilities": exact.position_probabilities.tolist(),
        "pairwise_precedence": exact.pairwise_precedence.tolist(),
        "training_stage_posterior": exact.canonical_best_order_stage_posteriors.tolist(),
        "training_map_stage": hard.tolist(),
        "training_map_tie_mask": tie_mask.tolist(),
        "training_expected_stage": expected.tolist(),
    }
    identity_material = {
        "complete_truth_record_id": known_truth["complete_truth_record_id"],
        "complete_truth_sha256": structured_sha256(
            "ebm-audit/conformance-complete-truth/3", known_truth
        ),
        "model": conformance_exact_model_record(),
        "expected_outputs": expected_outputs,
    }
    identity_digest = structured_sha256(
        "ebm-audit/conformance-exact-reference-identity/1",
        identity_material,
    )
    return {
        "record_schema_version": "ebm-audit-conformance-exact-reference/1.0",
        "exact_reference_record_id": (
            "conformance-reference-" + identity_digest.removeprefix("sha256:")[:42]
        ),
        **identity_material,
    }


def _synthetic_only_failure() -> WorkerFailure:
    return WorkerFailure(
        status="INVALID_INPUT",
        code="CONFORMANCE.SYNTHETIC_ONLY",
        safe_message="The conformance worker accepts only its regenerated synthetic input.",
        phase="synthetic-provenance-validation",
    )


class ExactConformanceBackend(DeterministicFixtureBackend):
    """Exact fixed-Gaussian EBM using the fixture backend only as a wire frame."""

    def __init__(self, identity: WorkerIdentityMaterial) -> None:
        super().__init__(identity)
        capabilities = dict(self._capabilities)
        capabilities.update(
            {
                "position_probabilities": True,
                "pairwise_precedence": True,
                "participant_stage_posterior": True,
                "hard_stages": True,
            }
        )
        constraints = dict(cast(Mapping[str, Any], capabilities["constraints"]))
        constraints["maximum_events"] = CONFORMANCE_MAX_EVENT_COUNT
        capabilities["constraints"] = constraints
        self._capabilities = capabilities
        self._capabilities_digest = structured_sha256("ebm-audit/capabilities/1", capabilities)
        self._settings_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:ebm-audit:worker-settings-schema:conformance-exact-gaussian:1",
            "title": "Fixed Gaussian exact conformance settings",
            "description": "No settings are accepted by this fixed synthetic model.",
            "type": "object",
            "additionalProperties": False,
            "properties": {},
            "required": [],
        }
        self._settings_schema_digest = structured_sha256(
            "ebm-audit/settings-schema/1", self._settings_schema
        )
        self._adapter_semantics = {
            **self._adapter_semantics,
            "algorithm_id": CONFORMANCE_ALGORITHM_ID,
            "semantic_version": CONFORMANCE_MODEL_VERSION,
            "capabilities_digest": self._capabilities_digest,
            "settings_schema_digest": self._settings_schema_digest,
            "stage_semantics_digest": CONFORMANCE_STAGE_SEMANTICS_DIGEST,
            "mcmc_projection": {
                "projection_schema_version": "ebm-audit-adapter-mcmc-projection/1.0",
                "availability": "UNAVAILABLE",
                "reason_code": "NON_CHAIN_ALGORITHM",
            },
        }
        self._adapter_semantics_digest = adapter_semantics_digest(self._adapter_semantics)
        self._allowed_requested_outputs = set(_EXACT_OUTPUTS)

    @property
    def describe_result(self) -> Mapping[str, Any]:
        result = dict(super().describe_result)
        algorithm = dict(result["supported_algorithms"][0])
        algorithm.update(
            {
                "algorithm_id": CONFORMANCE_ALGORITHM_ID,
                "capabilities": self._capabilities,
                "capabilities_digest": self._capabilities_digest,
                "settings_schema": self._settings_schema,
                "settings_schema_digest": self._settings_schema_digest,
                "stage_semantics_definition": _STAGE_SEMANTICS_DEFINITION,
                "stage_semantics_digest": CONFORMANCE_STAGE_SEMANTICS_DIGEST,
                "adapter_semantics": self._adapter_semantics,
                "adapter_semantics_digest": self._adapter_semantics_digest,
            }
        )
        result["supported_algorithms"] = [algorithm]
        result["worker_limitations"] = [
            "SYNTHETIC-ONLY: accepts only this worker's regenerated deterministic fixture.",
            "Uses one fixed directional Gaussian likelihood and a uniform stage prior.",
            "Enumerates every order exactly for two through nine events.",
            "Does not implement sampling, evaluation-cohort staging, or model artifacts.",
        ]
        return result

    def backend_identity(self, algorithm_id: str | None) -> Mapping[str, Any]:
        identity = dict(super().backend_identity(algorithm_id))
        identity["identity_evidence"] = [
            {
                "kind": "fixture-worker-code",
                "digest": self.identity.worker_code_digest,
                "note": "Deterministic SYNTHETIC-ONLY conformance code identity.",
            }
        ]
        return identity

    def capabilities_for(self, algorithm_id: str) -> Mapping[str, Any]:
        if algorithm_id != CONFORMANCE_ALGORITHM_ID:
            raise WorkerFailure(
                status="UNSUPPORTED_CAPABILITY",
                code="CAPABILITY.ALGORITHM_UNSUPPORTED",
                safe_message="The requested algorithm is not supported by this worker.",
                phase="request-validation",
            )
        return self._capabilities

    def capabilities_digest_for(self, algorithm_id: str) -> str:
        self.capabilities_for(algorithm_id)
        return self._capabilities_digest

    def _component_applicability(self, requested_outputs: list[str]) -> list[dict[str, Any]]:
        return [
            {
                "output_id": output_id,
                "status": "NOT_APPLICABLE_BY_CAPABILITY",
                "value": None,
                "reason_code": "STAGING.FIXED_COHORT_UNAVAILABLE",
            }
            for output_id in _EVALUATION_STAGE_OUTPUTS
            if output_id in requested_outputs
        ]

    def _framed_data(
        self,
        request: Mapping[str, Any],
        request_dir: Path,
    ) -> tuple[dict[str, Any], dict[str, NDArray[Any]]]:
        wire_payload = dict(request["payload"])
        projection = dict(wire_payload["execution_input_projection"])
        dataset = dict(projection["dataset"])
        requested_outputs = list(projection["requested_outputs"])
        if projection["algorithm_id"] != CONFORMANCE_ALGORITHM_ID:
            self.capabilities_for(str(projection["algorithm_id"]))
        if projection["settings"] != {}:
            raise WorkerFailure(
                status="INVALID_SPECIFICATION",
                code="SPEC.SETTINGS_UNSUPPORTED",
                safe_message="The exact conformance model accepts no settings.",
                phase="request-validation",
            )
        unsupported = [item for item in requested_outputs if item not in _EXACT_OUTPUTS]
        if unsupported:
            raise WorkerFailure(
                status="UNSUPPORTED_CAPABILITY",
                code="CAPABILITY.OUTPUT_UNSUPPORTED",
                safe_message="The conformance model cannot produce one or more requested outputs.",
                phase="capability-validation",
                counts={"unsupported_output_count": len(unsupported)},
            )
        if "central_order" not in requested_outputs:
            raise WorkerFailure(
                status="INVALID_SPECIFICATION",
                code="SPEC.CENTRAL_ORDER_REQUIRED",
                safe_message="The conformance fit requires the central-order output.",
                phase="request-validation",
            )
        if dataset["stage_semantics_digest"] != CONFORMANCE_STAGE_SEMANTICS_DIGEST:
            raise WorkerFailure(
                status="PROTOCOL_ERROR",
                code="PROTOCOL.STAGE_SEMANTICS_MISMATCH",
                safe_message="The dataset stage semantics do not match this algorithm.",
                phase="request-validation",
            )

        framed_request = dict(request)
        framed_wire_payload = dict(wire_payload)
        framed_projection = dict(projection)
        framed_dataset = dict(dataset)
        framed_projection["algorithm_id"] = FIXTURE_ALGORITHM_ID
        framed_projection["requested_outputs"] = ["central_order"]
        framed_dataset["stage_semantics_digest"] = FIXTURE_STAGE_SEMANTICS_DIGEST
        framed_projection["dataset"] = framed_dataset
        framed_wire_payload["execution_input_projection"] = framed_projection
        framed_request["payload"] = framed_wire_payload
        try:
            payload, arrays = super()._validate_request_data(framed_request, request_dir)
        except WorkerFailure as exc:
            if exc.code != "CAPABILITY.EVENT_LIMIT" or dataset["event_count"] != 9:
                raise
            arrays = load_catalogued_npz_arrays(
                request_dir / "values.npz",
                catalog=dataset["array_catalog"],
            )
            payload = dict(projection)
            payload["execution_input_projection_digest"] = wire_payload[
                "execution_input_projection_digest"
            ]
            for field in (
                "universe_id",
                "chain_execution_id",
                "attempt_id",
                "attempt_ordinal",
                "seed",
                "chain_id",
            ):
                if field in wire_payload:
                    payload[field] = wire_payload[field]
        payload["algorithm_id"] = CONFORMANCE_ALGORITHM_ID
        payload["requested_outputs"] = requested_outputs
        payload["requested_outputs_digest"] = projection["requested_outputs_digest"]
        payload["dataset"] = dataset
        return payload, dict(arrays)

    @staticmethod
    def _accounting(dataset: Mapping[str, Any]) -> dict[str, object]:
        return {
            "accounting_schema_version": "ebm-audit-data-accounting/2.0",
            "input_participants": int(dataset["participant_count"]),
            "output_participants": int(dataset["participant_count"]),
            "input_events": int(dataset["event_count"]),
            "output_events": int(dataset["event_count"]),
            "input_missing_cells": 0,
            "output_missing_cells": 0,
            "flagged_cells": 0,
            "masked_cells": 0,
            "transformed_cells": 0,
            "added_participant_instances": 0,
            "removed_participants": 0,
            "removed_events": 0,
            "operations": [],
        }

    def validate(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        payload, _ = self._framed_data(request, request_dir)
        dataset = payload["dataset"]
        return WorkerSuccess(
            payload={
                "algorithm_id": CONFORMANCE_ALGORITHM_ID,
                "settings_digest": payload["settings_digest"],
                "config_digest": payload["config_digest"],
                "requested_outputs_digest": payload["requested_outputs_digest"],
                "execution_input_projection_digest": payload["execution_input_projection_digest"],
                "validation_issues": [],
                "predicted_accounting": self._accounting(dataset),
                "component_applicability": self._component_applicability(
                    list(payload["requested_outputs"])
                ),
                "fit_permitted": True,
            }
        )

    def fit(
        self,
        request: Mapping[str, Any],
        request_dir: Path,
    ) -> WorkerSuccess:
        payload, input_arrays = self._framed_data(request, request_dir)
        dataset = payload["dataset"]
        event_ids = tuple(dataset["event_ids"])
        provenance = cast(Mapping[str, Any], dataset["synthetic_provenance"])
        generated = ConformanceGeneratedInput(
            event_directions=tuple(dataset["event_directions"]),
            group_codebook=dict(dataset["group_codebook"]),
            arrays=input_arrays,
            generated_input_sha256=str(provenance["generated_input_sha256"]),
        )
        oracle_input = conformance_exact_oracle_input(generated, event_ids=event_ids)
        exact = _solve_exact_oracle_compact(oracle_input)
        event_index = {event_id: index for index, event_id in enumerate(event_ids)}
        central = np.asarray(
            [event_index[event_id] for event_id in exact.canonical_best_order],
            dtype=np.int32,
        )
        requested_outputs = frozenset(payload["requested_outputs"])
        output_arrays: dict[str, NDArray[Any]] = {"central_order_permutation": central}
        if "position_probabilities" in requested_outputs:
            output_arrays["position_probabilities"] = exact.position_probabilities
        if "pairwise_precedence" in requested_outputs:
            output_arrays["pairwise_precedence"] = exact.pairwise_precedence

        stage_requested = bool(_TRAINING_STAGE_OUTPUTS.intersection(requested_outputs))
        stage_model_reference = None
        if stage_requested:
            stage_posterior = exact.canonical_best_order_stage_posteriors
            hard, tie_mask, expected = _stage_summaries(stage_posterior)
            output_arrays["training_row_indexes"] = np.asarray(
                input_arrays["training_row_indexes"], dtype=np.int64
            )
            if "training_stage_posterior" in requested_outputs:
                output_arrays["training_stage_posterior"] = stage_posterior
            if "training_hard_stages" in requested_outputs:
                output_arrays["training_map_stage"] = hard
                output_arrays["training_map_tie_mask"] = tie_mask
            if "training_expected_stage" in requested_outputs:
                output_arrays["training_expected_stage"] = expected
            direction_sign = np.asarray(
                [
                    1.0 if direction == "higher" else -1.0
                    for direction in generated.event_directions
                ],
                dtype=np.float64,
            )
            output_arrays[_PRIVATE_ORDER] = central.copy()
            output_arrays[_PRIVATE_GAUSSIANS] = np.column_stack(
                (
                    direction_sign * _NORMAL_MEAN,
                    direction_sign * _ABNORMAL_MEAN,
                    np.full(len(event_ids), _GAUSSIAN_SIGMA, dtype=np.float64),
                )
            )
            output_arrays[_PRIVATE_STAGE_PRIOR] = oracle_input.stage_prior

        semantic_versions = {
            "central_order_permutation": "event-index-at-position/1",
            "position_probabilities": "event-position-probability/1",
            "pairwise_precedence": "pairwise-event-precedence-probability/1",
            "training_row_indexes": "contiguous-internal-row-index/1",
            "training_stage_posterior": "training-stage-posterior/1",
            "training_map_stage": "training-map-stage/1",
            "training_map_tie_mask": "training-map-tie-mask/1",
            "training_expected_stage": "training-expected-stage/1",
            _PRIVATE_ORDER: "exact-canonical-best-event-index-at-position/1",
            _PRIVATE_GAUSSIANS: "fixed-directional-gaussian-mean-mean-sigma/1",
            _PRIVATE_STAGE_PRIOR: "uniform-stage-prior/1",
        }
        catalog = {
            name: array_catalog_entry(name, array, semantic_version=semantic_versions[name])
            for name, array in output_arrays.items()
        }
        model_digest = structured_sha256(
            "ebm-audit/conformance-exact-model/1", conformance_exact_model_record()
        )
        oracle_source_hashes = [dataset["scientific_data_digest"], model_digest]
        field_origins = {
            name: {
                "origin": "WORKER_DERIVED",
                "method_id": "exact-fixed-gaussian-enumeration-v1",
                "source_fields": ["train_values", "event_directions"],
                "source_hashes": oracle_source_hashes,
            }
            for name in output_arrays
        }
        if stage_requested:

            def binding(name: str) -> dict[str, str]:
                return {"member_name": name, "array_digest": str(catalog[name]["array_digest"])}

            reference_preimage = {
                "stage_model_reference_schema_version": "ebm-audit-stage-model-reference/1.0",
                "event_ids": list(event_ids),
                "selection_method_id": _STAGE_SEMANTICS_DEFINITION["reference_selection_method_id"],
                "reference_order_permutation": central.tolist(),
                "reference_order_binding": binding(_PRIVATE_ORDER),
                "fitted_distribution_bindings": [binding(_PRIVATE_GAUSSIANS)],
                "final_stage_prior_binding": binding(_PRIVATE_STAGE_PRIOR),
                "final_stage_prior_fixed_point_l1_residual": 0.0,
                "stage_semantics_digest": CONFORMANCE_STAGE_SEMANTICS_DIGEST,
            }
            stage_model_reference = {
                **reference_preimage,
                "stage_model_reference_digest": structured_sha256(
                    "ebm-audit/stage-model-reference/1", reference_preimage
                ),
            }
            reference_digest = stage_model_reference["stage_model_reference_digest"]
            reference_member_names = [_PRIVATE_ORDER, _PRIVATE_GAUSSIANS, _PRIVATE_STAGE_PRIOR]
            reference_source_fields = ["stage_model_reference", *reference_member_names]
            reference_source_hashes = [
                reference_digest,
                *(str(catalog[name]["array_digest"]) for name in reference_member_names),
            ]
            for name in output_arrays:
                if name == "training_row_indexes":
                    method_id = "request-row-index-copy-v1"
                    source_fields = ["training_row_indexes"]
                    source_hashes = [dataset["array_catalog"][name]["array_digest"]]
                elif name.endswith("stage_posterior"):
                    method_id = str(_STAGE_SEMANTICS_DEFINITION["posterior_method_id"])
                    source_fields = reference_source_fields
                    source_hashes = reference_source_hashes
                elif name.endswith("expected_stage"):
                    method_id = str(_STAGE_SEMANTICS_DEFINITION["expected_stage_rule_id"])
                    source_fields = reference_source_fields
                    source_hashes = reference_source_hashes
                elif name.endswith("map_stage") or name.endswith("map_tie_mask"):
                    method_id = str(_STAGE_SEMANTICS_DEFINITION["map_rule_id"])
                    source_fields = reference_source_fields
                    source_hashes = reference_source_hashes
                else:
                    continue
                field_origins[name] = {
                    "origin": "WORKER_DERIVED",
                    "method_id": method_id,
                    "source_fields": source_fields,
                    "source_hashes": source_hashes,
                }

        accounting = self._accounting(dataset)
        result: dict[str, Any] = {
            "payload_schema_version": "ebm-audit-worker-fit-payload/2.0",
            "universe_id": payload["universe_id"],
            "chain_execution_id": payload["chain_execution_id"],
            "attempt_id": payload["attempt_id"],
            "attempt_ordinal": payload["attempt_ordinal"],
            "algorithm_id": CONFORMANCE_ALGORITHM_ID,
            "settings_digest": payload["settings_digest"],
            "config_digest": payload["config_digest"],
            "requested_outputs_digest": payload["requested_outputs_digest"],
            "execution_input_projection_digest": payload["execution_input_projection_digest"],
            "seed": payload["seed"],
            "chain_id": payload["chain_id"],
            "event_ids": list(event_ids),
            "central_order_permutation": central.tolist(),
            "central_order_method": {
                "method_id": "backend-objective-maximum/1",
                "candidate_source": "backend_explored_order_set",
                "objective_id": "exact-marginal-order-log-likelihood-v1",
                "tie_break_rule": "lexicographically-smallest-event-id-sequence/1",
            },
            "raw_iteration_count": None,
            "burn_in_count": None,
            "thinning_interval": None,
            "postburn_unthinned_state_count": None,
            "retained_state_count": None,
            "likelihood_indexing": None,
            "actual_transition_count": None,
            "actual_transition_fraction": None,
            "array_catalog": catalog,
            "field_origins": field_origins,
            "participant_event_manifest": {
                "request_training_participants": int(dataset["participant_count"]),
                "returned_training_participants": int(dataset["participant_count"]),
                "training_row_indexes_digest": dataset["array_catalog"]["training_row_indexes"][
                    "array_digest"
                ],
                "request_evaluation_participants": int(
                    dataset["evaluation_participant_count"]
                ),
                "returned_evaluation_participants": 0,
                "evaluation_row_indexes_digest": None,
                "request_events": list(event_ids),
                "returned_events": list(event_ids),
                "worker_removed_participants": [],
                "worker_removed_events": [],
                "worker_modified_cells": [],
                "core_data_accounting_digest": structured_sha256(
                    "ebm-audit/worker-data-accounting/1", accounting
                ),
            },
            "preprocessing_manifest_digest": dataset["preprocessing_manifest_digest"],
            "stage_semantics_digest": CONFORMANCE_STAGE_SEMANTICS_DIGEST,
            "stage_model_reference": stage_model_reference,
            "component_applicability": self._component_applicability(
                list(payload["requested_outputs"])
            ),
            "input_digest": dataset["scientific_data_digest"],
            "core_code_digest": request["core_code_digest"],
            "worker_executable_digest": self.identity.worker_executable_digest,
            "worker_code_digest": self.identity.worker_code_digest,
            "backend_source_digest": self.identity.backend_source_digest,
            "environment_digest": self.identity.environment_digest,
            "capabilities_digest": self._capabilities_digest,
            "resource_summary": {
                "peak_resident_bytes": None,
                "cpu_seconds": None,
                "worker_process_count": 1,
                "effective_thread_limits": {
                    "blas": 1,
                    "openblas": 1,
                    "mkl": 1,
                    "omp": 1,
                    "numexpr": 1,
                    "veclib": 1,
                },
            },
            "backend_artifacts": [],
        }
        result["worker_fit_payload_digest"] = worker_fit_payload_digest(result)
        response_payload = {
            field: payload[field]
            for field in (
                "universe_id",
                "chain_execution_id",
                "attempt_id",
                "attempt_ordinal",
                "settings_digest",
                "config_digest",
                "requested_outputs_digest",
                "execution_input_projection_digest",
                "seed",
                "chain_id",
            )
        }
        response_payload["algorithm_id"] = CONFORMANCE_ALGORITHM_ID
        response_payload["result"] = result
        return WorkerSuccess(payload=response_payload, arrays=output_arrays)


class SyntheticOnlyConformanceBackend:
    """Fail-closed admission wrapper around the exact conformance backend."""

    def __init__(
        self,
        identity: WorkerIdentityMaterial | None = None,
        *,
        delegate: WorkerBackend | None = None,
    ) -> None:
        if delegate is None:
            if identity is None:
                raise ValueError("An identity is required for the default delegate.")
            delegate = ExactConformanceBackend(identity)
        self._delegate = delegate

    @property
    def describe_result(self) -> Mapping[str, Any]:
        result = dict(self._delegate.describe_result)
        result["worker_limitations"] = [
            "SYNTHETIC-ONLY: rejects every input not regenerated by this worker's tiny generator.",
            "Uses one fixed directional Gaussian likelihood and a uniform stage prior.",
            "Enumerates all event orders exactly for two through nine events.",
            "Does not implement sampling, evaluation-cohort staging, or model artifacts.",
        ]
        return result

    def backend_identity(self, algorithm_id: str | None) -> Mapping[str, Any]:
        return self._delegate.backend_identity(algorithm_id)

    def capabilities_for(self, algorithm_id: str) -> Mapping[str, Any]:
        return self._delegate.capabilities_for(algorithm_id)

    def capabilities_digest_for(self, algorithm_id: str) -> str:
        return self._delegate.capabilities_digest_for(algorithm_id)

    def describe(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        delegated = self._delegate.describe(request, request_dir)
        payload = dict(delegated.payload)
        payload["result"] = dict(self.describe_result)
        return WorkerSuccess(
            payload=payload,
            arrays=delegated.arrays,
            warnings=delegated.warnings,
        )

    def self_test(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        return self._delegate.self_test(request, request_dir)

    def validate(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        self._admit_synthetic_input(request, request_dir)
        return self._delegate.validate(request, request_dir)

    def fit(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        self._admit_synthetic_input(request, request_dir)
        delegated = self._delegate.fit(request, request_dir)
        payload = dict(delegated.payload)
        result_value = payload.get("result")
        if isinstance(result_value, Mapping):
            result = dict(result_value)
            dataset = request["payload"]["execution_input_projection"]["dataset"]
            result["synthetic_provenance"] = dict(dataset["synthetic_provenance"])
            result.pop("worker_fit_payload_digest", None)
            result["worker_fit_payload_digest"] = worker_fit_payload_digest(result)
            payload["result"] = result
        return WorkerSuccess(
            payload=payload,
            arrays=delegated.arrays,
            warnings=delegated.warnings,
        )

    def _admit_synthetic_input(
        self,
        request: Mapping[str, Any],
        request_dir: Path,
    ) -> None:
        """Select one of the two closed project-owned provenance contracts."""

        try:
            provenance = request["payload"]["execution_input_projection"]["dataset"][
                "synthetic_provenance"
            ]
        except Exception:
            raise _synthetic_only_failure() from None
        if (
            isinstance(provenance, Mapping)
            and provenance.get("generator_id") == PROJECT_SYNTHETIC_GENERATOR_ID
        ):
            self._admit_project_candidate_input(request, request_dir)
            return
        self._admit_regenerated_input(request, request_dir)

    def _admit_project_candidate_input(
        self,
        request: Mapping[str, Any],
        request_dir: Path,
    ) -> None:
        """Verify candidate hashes after the live core owner authenticated issue.

        The subprocess has no secret or signature.  It therefore verifies the
        deterministic record and exact received arrays, while the opaque live
        input owner remains the authenticity boundary for case and truth links.
        """

        try:
            projection = request["payload"]["execution_input_projection"]
            dataset = projection["dataset"]
            if not isinstance(dataset, Mapping):
                raise TypeError
            provenance = dataset.get("synthetic_provenance")
            if not isinstance(provenance, Mapping):
                raise TypeError
            validate_instance(
                dict(provenance),
                "worker-protocol.schema.json",
                definition="SyntheticProvenance",
            )
            project = provenance.get("project_candidate")
            if not isinstance(project, Mapping):
                raise TypeError
            candidate_binding = projection.get("candidate_provenance_binding")
            if not isinstance(candidate_binding, Mapping):
                raise TypeError
            validate_instance(
                dict(candidate_binding),
                "worker-protocol.schema.json",
                definition="CandidateProvenanceBinding",
            )
            if dict(candidate_binding) != {
                "binding_schema_version": "ebm-audit-candidate-provenance-binding/1.0",
                "candidate_id": project.get("candidate_id"),
                "analysis_specification_id": project.get("analysis_spec_id"),
                "operation_intent_digest": project.get(
                    "candidate_operation_intent_sha256"
                ),
                "selector": project.get("candidate_derivation_selector"),
                "operation_seed": project.get("candidate_operation_seed"),
            }:
                raise ValueError
            coordinate = project.get("case_coordinate")
            operation = project.get("candidate_operation_intent")
            if not isinstance(coordinate, Mapping) or not isinstance(operation, Mapping):
                raise TypeError
            if (
                provenance.get("classification") != "SYNTHETIC-ONLY"
                or provenance.get("generator_id") != PROJECT_SYNTHETIC_GENERATOR_ID
                or provenance.get("generator_version")
                != PROJECT_SYNTHETIC_GENERATOR_VERSION
                or provenance.get("generator_record_sha256")
                != project_synthetic_generator_record_sha256()
                or project.get("generator_code_sha256")
                != project_synthetic_generator_code_sha256()
                or project.get("authority_sha256")
                != project.get("scenario_definitions_sha256")
                or provenance.get("generated_input_sha256")
                != project.get("base_generated_scientific_data_sha256")
                or provenance.get("complete_truth_record_id") != project.get("case_id")
                or provenance.get("scenario_id") != coordinate.get("variant_id")
                or provenance.get("replicate") != coordinate.get("replicate_index")
                or provenance.get("seed") != project.get("case_seed")
                or provenance.get("source_kind")
                != "PROJECT_OWNED_DETERMINISTIC_GENERATOR"
                or provenance.get("participant_data_present") is not False
                or provenance.get("external_source_present") is not False
                or provenance.get("participant_count") != dataset.get("participant_count")
                or provenance.get("event_count") != dataset.get("event_count")
                or provenance.get("event_ids") != dataset.get("event_ids")
                or project.get("candidate_id") != project.get("analysis_spec_id")
                or project.get("candidate_derivation_kind") != operation.get("kind")
                or project.get("candidate_derivation_selector")
                != project_candidate_derivation_selector(operation)
                or project.get("candidate_operation_intent_sha256")
                != project_candidate_operation_intent_sha256(operation)
            ):
                raise ValueError
            kind = operation.get("kind")
            selector = project.get("candidate_derivation_selector")
            operation_seed = project.get("candidate_operation_seed")
            if kind == "ordinary":
                if selector != "ordinary" or operation_seed is not None:
                    raise ValueError
            elif kind in {"bootstrap", "subsample", "null"}:
                if not str(selector).startswith("replicate:") or type(operation_seed) is not str:
                    raise ValueError
            elif kind == "influence":
                if not str(selector).startswith("removal:") or operation_seed is not None:
                    raise ValueError
            else:
                raise ValueError
            resolution_mode = coordinate.get("resolution_mode")
            source_case_id = project.get("source_case_id")
            case_operation_seed = project.get("case_operation_seed")
            if resolution_mode == "TRANSFORMED_SOURCE":
                if type(source_case_id) is not str or type(case_operation_seed) is not str:
                    raise ValueError
            elif (
                resolution_mode != "DEVELOPMENT_VARIANT"
                or source_case_id is not None
                or case_operation_seed is not None
            ):
                raise ValueError
            expected_case_seed_identity = structured_sha256(
                "ebm-audit/project-synthetic-case-seed-identity/1",
                {
                    "case_seed": project["case_seed"],
                    "shared_draw_seed": project["shared_draw_seed"],
                    "case_operation_seed": project["case_operation_seed"],
                    "component_seed_manifest_sha256": project[
                        "component_seed_manifest_sha256"
                    ],
                },
            )
            if project.get("case_seed_identity_sha256") != expected_case_seed_identity:
                raise ValueError
            binding_preimage = dict(provenance)
            project_preimage = dict(project)
            observed_binding = project_preimage["provenance_binding_sha256"]
            project_preimage["provenance_binding_sha256"] = None
            binding_preimage["project_candidate"] = project_preimage
            if observed_binding != project_candidate_provenance_binding_sha256(
                binding_preimage
            ):
                raise ValueError
            base_dataset = dict(dataset)
            base_dataset.pop("synthetic_provenance")
            if project.get("candidate_dataset_sha256") != project_candidate_dataset_sha256(
                base_dataset
            ):
                raise ValueError
            catalog = dataset.get("array_catalog")
            if not isinstance(catalog, Mapping) or set(catalog) != PROJECT_SYNTHETIC_ARRAY_NAMES:
                raise ValueError
            if project.get(
                "candidate_array_catalog_sha256"
            ) != project_candidate_array_catalog_sha256(catalog):
                raise ValueError
            arrays = load_catalogued_npz_arrays(
                request_dir / "values.npz",
                catalog=catalog,
            )
            if set(arrays) != PROJECT_SYNTHETIC_ARRAY_NAMES:
                raise ValueError
            participant_count = dataset["participant_count"]
            evaluation_count = dataset["evaluation_participant_count"]
            event_count = dataset["event_count"]
            expected_shapes = {
                "train_values": (participant_count, event_count),
                "training_row_indexes": (participant_count,),
                "train_group_codes": (participant_count,),
                "evaluation_values": (evaluation_count, event_count),
                "evaluation_row_indexes": (evaluation_count,),
                "evaluation_group_codes": (evaluation_count,),
            }
            if any(arrays[name].shape != shape for name, shape in expected_shapes.items()):
                raise ValueError
            if not np.array_equal(
                arrays["training_row_indexes"], np.arange(participant_count, dtype=np.int64)
            ) or not np.array_equal(
                arrays["evaluation_row_indexes"], np.arange(evaluation_count, dtype=np.int64)
            ):
                raise ValueError
        except WorkerFailure:
            raise
        except Exception:
            raise _synthetic_only_failure() from None

    def _admit_regenerated_input(
        self,
        request: Mapping[str, Any],
        request_dir: Path,
    ) -> None:
        try:
            payload = request["payload"]
            projection = payload["execution_input_projection"]
            dataset = projection["dataset"]
            if not isinstance(dataset, Mapping):
                raise TypeError
            participant_count = dataset["participant_count"]
            event_count = dataset["event_count"]
            event_ids_value = dataset["event_ids"]
            if (
                not isinstance(participant_count, int)
                or isinstance(participant_count, bool)
                or not isinstance(event_count, int)
                or isinstance(event_count, bool)
                or not isinstance(event_ids_value, list)
                or not all(isinstance(event_id, str) for event_id in event_ids_value)
            ):
                raise TypeError
            event_ids = tuple(event_ids_value)
            generated = generate_conformance_input(
                participant_count=participant_count,
                event_count=event_count,
                event_ids=event_ids,
            )
            expected_provenance = build_conformance_provenance(
                participant_count=participant_count,
                event_count=event_count,
                event_ids=event_ids,
            )
            provenance = dataset.get("synthetic_provenance")
            if not isinstance(provenance, Mapping):
                raise TypeError
            observed_provenance = SyntheticProvenance.from_mapping(provenance).to_mapping()
            if observed_provenance != expected_provenance:
                raise ValueError
            if (
                observed_provenance["generated_input_sha256"] != generated.generated_input_sha256
                or dataset.get("event_directions") != list(generated.event_directions)
                or dataset.get("group_codebook") != generated.group_codebook
                or dataset.get("evaluation_participant_count") != 0
                or dataset.get("training_row_index_array") != "training_row_indexes"
                or dataset.get("evaluation_row_index_array") is not None
            ):
                raise ValueError
            catalog = dataset.get("array_catalog")
            if not isinstance(catalog, Mapping) or set(catalog) != CONFORMANCE_ARRAY_NAMES:
                raise ValueError
            observed_arrays = load_catalogued_npz_arrays(
                request_dir / "values.npz",
                catalog=catalog,
            )
            if set(observed_arrays) != CONFORMANCE_ARRAY_NAMES:
                raise ValueError
            for name, expected in generated.arrays.items():
                observed = observed_arrays[name]
                if (
                    observed.dtype != expected.dtype
                    or observed.shape != expected.shape
                ):
                    raise ValueError
            if sorted(observed_arrays["training_row_indexes"].tolist()) != list(
                range(participant_count)
            ):
                raise ValueError
            observed_rows = sorted(
                (
                    observed_arrays["train_values"][index].tobytes(),
                    int(observed_arrays["train_group_codes"][index]),
                )
                for index in range(participant_count)
            )
            expected_rows = sorted(
                (
                    generated.arrays["train_values"][index].tobytes(),
                    int(generated.arrays["train_group_codes"][index]),
                )
                for index in range(participant_count)
            )
            if observed_rows != expected_rows:
                raise ValueError
        except WorkerFailure:
            raise
        except Exception:
            raise _synthetic_only_failure() from None


__all__ = [
    "CONFORMANCE_ALGORITHM_ID",
    "CONFORMANCE_GENERATION_SEED",
    "CONFORMANCE_GENERATOR_ID",
    "CONFORMANCE_GENERATOR_VERSION",
    "CONFORMANCE_MODEL_VERSION",
    "CONFORMANCE_REPLICATE",
    "CONFORMANCE_SCENARIO_ID",
    "CONFORMANCE_STAGE_SEMANTICS_DIGEST",
    "ConformanceGeneratedInput",
    "ExactConformanceBackend",
    "SyntheticOnlyConformanceBackend",
    "build_conformance_provenance",
    "conformance_complete_truth_record",
    "conformance_exact_model_record",
    "conformance_exact_oracle_input",
    "conformance_exact_reference_record",
    "conformance_generator_record",
    "conformance_generator_record_sha256",
    "generate_conformance_input",
]
