"""Reusable deterministic structural worker used only for protocol tests.

This is deliberately not an EBM implementation. It returns a seed-controlled
permutation so the core can test transport, identity, and result invariants
without mistaking the fixture for evidence about disease order.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from ebm_audit.protocol import (
    adapter_semantics_digest,
    backend_identity_digest,
    canonical_json_bytes,
    expected_identity_pin,
    stage_semantics_digest,
    strict_json_loads,
    structured_sha256,
    worker_fit_payload_digest,
)
from ebm_audit.schema import load_protocol_registry, validate_instance
from ebm_audit.workers.arrays import (
    array_catalog_entry,
    canonical_array,
    load_catalogued_npz_arrays,
)
from ebm_audit.workers.identity import WorkerIdentityMaterial
from ebm_audit.workers.types import WorkerFailure, WorkerSuccess

ALGORITHM_ID = "fixture-strict-sequence"
_MAX_FIXTURE_EVENTS = 8
FIXTURE_STAGE_SEMANTICS_DEFINITION = {
    "stage_semantics_schema_version": "ebm-audit-stage-semantics/1.0",
    "stage_model_availability": "UNAVAILABLE",
    "stage_axis_id": "strict-prefix-count-v1",
    "unavailable_reason_code": "STAGING.MODEL_UNAVAILABLE",
}
FIXTURE_STAGE_SEMANTICS_DIGEST = stage_semantics_digest(FIXTURE_STAGE_SEMANTICS_DEFINITION)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_details() -> dict[str, object]:
    return {"counts": {}, "internal_indexes": [], "approved_event_ids": [], "digests": {}}


def _select_fixture_order(event_ids: list[str], seed: str) -> list[str]:
    best_score: str | None = None
    best_order: tuple[str, ...] | None = None
    for candidate in itertools.permutations(event_ids):
        score = structured_sha256(
            "ebm-audit/fixture-order-objective/1",
            {"seed": seed, "ordered_event_ids": list(candidate)},
        )
        if (
            best_score is None
            or score > best_score
            or (best_order is not None and score == best_score and candidate < best_order)
        ):
            best_score = score
            best_order = candidate
    if best_order is None:  # event_count >= 2 is guaranteed by the request schema
        raise RuntimeError("The structural fixture found no event permutation.")
    return list(best_order)


class DeterministicFixtureBackend:
    """A non-scientific backend that implements the four mandatory handlers."""

    def __init__(self, identity: WorkerIdentityMaterial) -> None:
        self.identity = identity
        registry = load_protocol_registry()
        self._requested_outputs = registry["requested_outputs"]
        self._self_test_checks = registry["self_test_checks"]
        self._requested_output_registry_digest = structured_sha256(
            "ebm-audit/requested-output-registry/1", self._requested_outputs
        )
        self._self_test_check_registry_digest = structured_sha256(
            "ebm-audit/self-test-check-registry/1", self._self_test_checks
        )
        self._capabilities = {
            "capabilities_schema_version": "ebm-audit-worker-capabilities/1.0",
            "strict_single_sequence": True,
            "grouped_or_simultaneous_events": False,
            "subtypes": False,
            "temporal_events": False,
            "missing_values": "REJECT",
            "per_feature_missingness": False,
            "order_samples": False,
            "position_probabilities": False,
            "pairwise_precedence": False,
            "likelihood_trace": False,
            "accepted_transition_diagnostics": False,
            "fitted_event_distributions": False,
            "participant_stage_posterior": False,
            "hard_stages": False,
            "fixed_evaluation_cohort_staging": False,
            "portable_fitted_model_artifact": False,
            "multiple_chains": False,
            "bootstrap": False,
            "cross_validation": False,
            "deterministic_seed": True,
            "offline_execution": True,
            "constraints": {
                "minimum_participants": 2,
                "maximum_participants": None,
                "minimum_events": 2,
                "maximum_events": _MAX_FIXTURE_EVENTS,
                "required_group_roles": [],
                "maximum_threads": 1,
                "maximum_raw_iterations": None,
            },
        }
        self._capabilities_digest = structured_sha256(
            "ebm-audit/capabilities/1", self._capabilities
        )
        self._settings_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:ebm-audit:worker-settings-schema:fixture-strict-sequence:1",
            "title": "Deterministic structural fixture settings",
            "description": "No settings are accepted; this fixture is not scientific inference.",
            "type": "object",
            "additionalProperties": False,
            "properties": {},
            "required": [],
        }
        self._settings_schema_digest = structured_sha256(
            "ebm-audit/settings-schema/1", self._settings_schema
        )
        self._adapter_semantics = {
            "adapter_semantics_schema_version": "ebm-audit-adapter-semantics/2.0",
            "adapter_id": self.identity.adapter_id,
            "algorithm_id": ALGORITHM_ID,
            "semantic_version": "fixture-strict-sequence/2.0",
            "supported_commands": ["validate", "fit"],
            "capabilities_digest": self._capabilities_digest,
            "settings_schema_digest": self._settings_schema_digest,
            "stage_semantics_digest": FIXTURE_STAGE_SEMANTICS_DIGEST,
            "requested_output_registry_digest": self._requested_output_registry_digest,
            "mcmc_projection": {
                "projection_schema_version": "ebm-audit-adapter-mcmc-projection/1.0",
                "availability": "UNAVAILABLE",
                "reason_code": "NON_CHAIN_ALGORITHM",
            },
        }
        self._adapter_semantics_digest = adapter_semantics_digest(self._adapter_semantics)
        self._allowed_requested_outputs = {
            "central_order",
            "evaluation_stage_posterior",
            "evaluation_hard_stages",
            "evaluation_expected_stage",
        }

    @property
    def describe_result(self) -> Mapping[str, Any]:
        return {
            "supported_commands": ["describe", "validate", "fit", "self-test"],
            "supported_algorithms": [
                {
                    "algorithm_id": ALGORITHM_ID,
                    "supported_commands": ["validate", "fit"],
                    "capabilities": self._capabilities,
                    "capabilities_digest": self._capabilities_digest,
                    "settings_schema": self._settings_schema,
                    "settings_schema_digest": self._settings_schema_digest,
                    "stage_semantics_definition": FIXTURE_STAGE_SEMANTICS_DEFINITION,
                    "stage_semantics_digest": FIXTURE_STAGE_SEMANTICS_DIGEST,
                    "adapter_semantics": self._adapter_semantics,
                    "adapter_semantics_digest": self._adapter_semantics_digest,
                    "settings_schema_validation_rules": [
                        {
                            "rule_id": "settings-schema-required-subset-of-properties/1",
                            "enforcement_phase": "describe-validation",
                            "failure_status": "PROTOCOL_ERROR",
                            "failure_code": "PROTOCOL.SETTINGS_SCHEMA_REQUIRED_PROPERTY_UNDECLARED",
                        }
                    ],
                }
            ],
            "worker_limitations": [
                "Non-scientific deterministic contract fixture only.",
                "It is never eligible for genuine backend acceptance or scientific interpretation.",
                "Its development environment identity is not a dependency or licence receipt.",
            ],
            "requested_output_registry_digest": self._requested_output_registry_digest,
            "self_test_check_registry_digest": self._self_test_check_registry_digest,
        }

    def backend_identity(self, algorithm_id: str | None) -> Mapping[str, Any]:
        return self.identity.for_algorithm(algorithm_id)

    def capabilities_for(self, algorithm_id: str) -> Mapping[str, Any]:
        if algorithm_id != ALGORITHM_ID:
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

    def describe(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        del request_dir
        expected = request["payload"]["expected_identity"]
        if expected is not None:
            observed = expected_identity_pin(
                self.backend_identity(None),
                algorithm_id=str(expected["selected_algorithm_id"]),
                algorithm_capabilities_digest=self.capabilities_digest_for(
                    str(expected["selected_algorithm_id"])
                ),
            )
            if observed != expected:
                raise WorkerFailure(
                    status="PROTOCOL_ERROR",
                    code="PROTOCOL.EXPECTED_IDENTITY_MISMATCH",
                    safe_message=("The worker identity does not match the configured expectation."),
                    phase="identity-validation",
                )
        return WorkerSuccess(payload={"result": dict(self.describe_result)})

    def _component_applicability(self, requested_outputs: list[str]) -> list[dict[str, Any]]:
        evaluation_outputs = (
            "evaluation_stage_posterior",
            "evaluation_hard_stages",
            "evaluation_expected_stage",
        )
        return [
            {
                "output_id": output_id,
                "status": "NOT_APPLICABLE_BY_CAPABILITY",
                "value": None,
                "reason_code": "STAGING.FIXED_COHORT_UNAVAILABLE",
            }
            for output_id in evaluation_outputs
            if output_id in requested_outputs
        ]

    def _validate_request_data(
        self, request: Mapping[str, Any], request_dir: Path
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        wire_payload = dict(request["payload"])
        payload = dict(wire_payload["execution_input_projection"])
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
        if payload["algorithm_id"] != ALGORITHM_ID:
            self.capabilities_for(str(payload["algorithm_id"]))
        if payload["settings"] != {}:
            raise WorkerFailure(
                status="INVALID_SPECIFICATION",
                code="SPEC.SETTINGS_UNSUPPORTED",
                safe_message="The deterministic fixture accepts an empty settings object only.",
                phase="request-validation",
            )

        requested_outputs = list(payload["requested_outputs"])
        unsupported = [
            item for item in requested_outputs if item not in self._allowed_requested_outputs
        ]
        if unsupported:
            raise WorkerFailure(
                status="UNSUPPORTED_CAPABILITY",
                code="CAPABILITY.OUTPUT_UNSUPPORTED",
                safe_message="The fixture cannot produce one or more requested outputs.",
                phase="capability-validation",
                counts={"unsupported_output_count": len(unsupported)},
            )
        if "central_order" not in requested_outputs:
            raise WorkerFailure(
                status="INVALID_SPECIFICATION",
                code="SPEC.CENTRAL_ORDER_REQUIRED",
                safe_message="The fixture fit requires the central-order output.",
                phase="request-validation",
            )

        dataset = dict(payload["dataset"])
        if dataset["stage_semantics_digest"] != FIXTURE_STAGE_SEMANTICS_DIGEST:
            raise WorkerFailure(
                status="PROTOCOL_ERROR",
                code="PROTOCOL.STAGE_SEMANTICS_MISMATCH",
                safe_message="The dataset stage semantics do not match this worker algorithm.",
                phase="request-validation",
            )
        catalog = dict(dataset["array_catalog"])
        try:
            arrays = load_catalogued_npz_arrays(
                request_dir / "values.npz",
                catalog=catalog,
            )
        except Exception:
            raise WorkerFailure(
                status="PROTOCOL_ERROR",
                code="PROTOCOL.ARRAY_CATALOG_MISMATCH",
                safe_message="A request array does not match its declared catalog entry.",
                phase="bundle-validation",
            ) from None

        try:
            values = arrays["train_values"]
            row_indexes = arrays["training_row_indexes"]
            group_codes = arrays["train_group_codes"]
        except KeyError:
            raise WorkerFailure(
                status="PROTOCOL_ERROR",
                code="PROTOCOL.REQUIRED_ARRAY_MISSING",
                safe_message="The request bundle is missing a mandatory array.",
                phase="bundle-validation",
            ) from None

        np = __import__("numpy")
        participant_count = int(dataset["participant_count"])
        event_count = int(dataset["event_count"])
        if event_count > _MAX_FIXTURE_EVENTS:
            raise WorkerFailure(
                status="UNSUPPORTED_CAPABILITY",
                code="CAPABILITY.EVENT_LIMIT",
                safe_message="The structural fixture event limit was exceeded.",
                phase="capability-validation",
                counts={"event_count": event_count},
            )
        if values.shape != (participant_count, event_count):
            raise WorkerFailure(
                status="INVALID_INPUT",
                code="DATA.EVENT_MATRIX_SHAPE",
                safe_message="The event matrix shape does not match the declared counts.",
                phase="data-validation",
                counts={"participant_count": participant_count, "event_count": event_count},
            )
        if list(row_indexes.tolist()) != list(range(participant_count)):
            raise WorkerFailure(
                status="PROTOCOL_ERROR",
                code="PROTOCOL.ROW_INDEX_ALIGNMENT",
                safe_message=(
                    "Training row indexes are not the required contiguous internal indexes."
                ),
                phase="data-validation",
            )
        if group_codes.shape != (participant_count,):
            raise WorkerFailure(
                status="INVALID_INPUT",
                code="DATA.GROUP_SHAPE",
                safe_message="Group-code shape does not match the participant count.",
                phase="data-validation",
            )
        declared_codes = {int(code) for code in dataset["group_codebook"]}
        if any(int(code) not in declared_codes for code in group_codes.tolist()):
            raise WorkerFailure(
                status="INVALID_INPUT",
                code="DATA.GROUP_CODE_UNDECLARED",
                safe_message="At least one group code is not declared in the group codebook.",
                phase="data-validation",
            )
        nonfinite_count = int(np.size(values) - np.isfinite(values).sum())
        if nonfinite_count:
            raise WorkerFailure(
                status="UNSUPPORTED_CAPABILITY",
                code="CAPABILITY.MISSING_VALUES",
                safe_message="The deterministic fixture requires a complete finite event matrix.",
                phase="data-validation",
                counts={"nonfinite_cell_count": nonfinite_count},
            )
        if (
            len(dataset["event_ids"]) != event_count
            or len(dataset["event_directions"]) != event_count
        ):
            raise WorkerFailure(
                status="INVALID_INPUT",
                code="DATA.EVENT_METADATA_COUNT",
                safe_message="Event metadata count does not match the event matrix.",
                phase="data-validation",
            )
        return payload, arrays

    def validate(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        payload, arrays = self._validate_request_data(request, request_dir)
        dataset = payload["dataset"]
        values = arrays["train_values"]
        accounting = {
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
        del values
        return WorkerSuccess(
            payload={
                "algorithm_id": ALGORITHM_ID,
                "settings_digest": payload["settings_digest"],
                "config_digest": payload["config_digest"],
                "requested_outputs_digest": payload["requested_outputs_digest"],
                "execution_input_projection_digest": payload["execution_input_projection_digest"],
                "validation_issues": [],
                "predicted_accounting": accounting,
                "component_applicability": self._component_applicability(
                    list(payload["requested_outputs"])
                ),
                "fit_permitted": True,
            }
        )

    def fit(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        payload, _arrays = self._validate_request_data(request, request_dir)
        dataset = payload["dataset"]
        event_ids = list(dataset["event_ids"])
        seed = str(payload["seed"])
        ordered_event_ids = _select_fixture_order(event_ids, seed)
        permutation = [event_ids.index(event_id) for event_id in ordered_event_ids]
        np = __import__("numpy")
        central_order = np.asarray(permutation, dtype=np.int32)
        catalog = {
            "central_order_permutation": array_catalog_entry(
                "central_order_permutation",
                central_order,
                semantic_version="event-index-at-position/1",
            )
        }
        training_index_digest = dataset["array_catalog"]["training_row_indexes"]["array_digest"]
        accounting_digest = structured_sha256(
            "ebm-audit/fixture-data-accounting/1",
            {
                "participants": dataset["participant_count"],
                "events": dataset["event_count"],
                "modifications": 0,
            },
        )
        resource_summary = {
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
        }
        result: dict[str, Any] = {
            "payload_schema_version": "ebm-audit-worker-fit-payload/2.0",
            "universe_id": payload["universe_id"],
            "chain_execution_id": payload["chain_execution_id"],
            "attempt_id": payload["attempt_id"],
            "attempt_ordinal": payload["attempt_ordinal"],
            "algorithm_id": ALGORITHM_ID,
            "settings_digest": payload["settings_digest"],
            "config_digest": payload["config_digest"],
            "requested_outputs_digest": payload["requested_outputs_digest"],
            "execution_input_projection_digest": payload["execution_input_projection_digest"],
            "seed": payload["seed"],
            "chain_id": payload["chain_id"],
            "event_ids": event_ids,
            "central_order_permutation": permutation,
            "central_order_method": {
                "method_id": "backend-objective-maximum/1",
                "candidate_source": "backend_explored_order_set",
                "objective_id": "fixture-seeded-order-digest-v1",
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
            "field_origins": {
                "central_order_permutation": {
                    "origin": "WORKER_DERIVED",
                    "method_id": "fixture-exhaustive-objective-selection-v1",
                    "source_fields": ["seed", "event_ids"],
                    "source_hashes": [
                        structured_sha256(
                            "ebm-audit/fixture-order-source/1",
                            {"seed": seed, "event_ids": event_ids},
                        )
                    ],
                }
            },
            "participant_event_manifest": {
                "request_training_participants": int(dataset["participant_count"]),
                "returned_training_participants": int(dataset["participant_count"]),
                "training_row_indexes_digest": training_index_digest,
                "request_evaluation_participants": int(dataset["evaluation_participant_count"]),
                "returned_evaluation_participants": 0,
                "evaluation_row_indexes_digest": None,
                "request_events": event_ids,
                "returned_events": event_ids,
                "worker_removed_participants": [],
                "worker_removed_events": [],
                "worker_modified_cells": [],
                "core_data_accounting_digest": accounting_digest,
            },
            "preprocessing_manifest_digest": dataset["preprocessing_manifest_digest"],
            "stage_semantics_digest": FIXTURE_STAGE_SEMANTICS_DIGEST,
            "stage_model_reference": None,
            "component_applicability": self._component_applicability(
                list(payload["requested_outputs"])
            ),
            "input_digest": dataset["scientific_data_digest"],
            "core_code_digest": request["core_code_digest"],
            "worker_executable_digest": self.identity.worker_executable_digest,
            "worker_code_digest": self.identity.worker_code_digest,
            "backend_source_digest": None,
            "environment_digest": self.identity.environment_digest,
            "capabilities_digest": self._capabilities_digest,
            "resource_summary": resource_summary,
            "backend_artifacts": [],
        }
        result["worker_fit_payload_digest"] = worker_fit_payload_digest(result)
        return WorkerSuccess(
            payload={
                "universe_id": payload["universe_id"],
                "chain_execution_id": payload["chain_execution_id"],
                "attempt_id": payload["attempt_id"],
                "attempt_ordinal": payload["attempt_ordinal"],
                "algorithm_id": ALGORITHM_ID,
                "settings_digest": payload["settings_digest"],
                "config_digest": payload["config_digest"],
                "requested_outputs_digest": payload["requested_outputs_digest"],
                "execution_input_projection_digest": payload["execution_input_projection_digest"],
                "seed": payload["seed"],
                "chain_id": payload["chain_id"],
                "result": result,
            },
            arrays={"central_order_permutation": central_order},
        )

    def self_test(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        del request_dir
        payload = request["payload"]
        requested_checks = list(payload["requested_checks"])
        registered = {row["check_id"] for row in self._self_test_checks}
        unknown = [check for check in requested_checks if check not in registered]
        if unknown:
            raise WorkerFailure(
                status="INVALID_SPECIFICATION",
                code="SPEC.SELF_TEST_CHECK_UNKNOWN",
                safe_message="The self-test request names an unknown check.",
                phase="request-validation",
                counts={"unknown_check_count": len(unknown)},
            )
        fixture_event_ids = ["synthetic_event_a", "synthetic_event_b"]
        fixture = {
            "fixture_schema_version": "ebm-audit-worker-self-test-fixture/1.0",
            "fixture_label": "synthetic-structure-only",
            "participant_count": 4,
            "event_ids": fixture_event_ids,
        }
        fixture_digest = structured_sha256("ebm-audit/worker-self-test-fixture/1", fixture)
        started = _utc_now()
        checks = []
        for check_id in requested_checks:
            outcome = "PASS"
            safe_message = "The deterministic structural fixture check passed."
            check_evidence: dict[str, str] = {"fixture": fixture_digest}
            try:
                if check_id == "schema-roundtrip":
                    descriptor = dict(self.describe_result)
                    validate_instance(
                        descriptor,
                        "worker-protocol.schema.json",
                        definition="DescribeResult",
                    )
                    if strict_json_loads(canonical_json_bytes(descriptor)) != descriptor:
                        raise ValueError
                    check_evidence["descriptor"] = structured_sha256(
                        "ebm-audit/fixture-descriptor/1",
                        descriptor,
                    )
                elif check_id == "identity-stability":
                    first_identity = self.backend_identity(None)
                    second_identity = self.backend_identity(None)
                    if first_identity != second_identity:
                        raise ValueError
                    check_evidence["identity"] = backend_identity_digest(first_identity)
                elif check_id == "seed-repeatability":
                    event_ids = list(fixture_event_ids)
                    seed = str(payload["seed"])
                    first_order = _select_fixture_order(event_ids, seed)
                    second_order = _select_fixture_order(event_ids, seed)
                    if first_order != second_order:
                        raise ValueError
                    check_evidence["order"] = structured_sha256(
                        "ebm-audit/fixture-self-test-order/1",
                        {"seed": seed, "event_ids": event_ids, "order": first_order},
                    )
                elif check_id == "array-invariants":
                    np = __import__("numpy")
                    permutation = canonical_array(np.asarray([1, 0], dtype=np.int32))
                    entry = array_catalog_entry(
                        "central_order_permutation",
                        permutation,
                        semantic_version="event-index-at-position/1",
                    )
                    if entry["dtype"] != "int32" or entry["shape"] != [2]:
                        raise ValueError
                    check_evidence["array"] = entry["array_digest"]
                elif check_id in {"offline-no-network", "side-effect-boundary"}:
                    outcome = "FAIL"
                    safe_message = (
                        "UNVERIFIED: this fixture has no operating-system containment proof."
                    )
                else:  # protected by the exact registry check above
                    raise ValueError
            except Exception:
                outcome = "FAIL"
                safe_message = "The deterministic structural fixture check failed."
            checks.append(
                {
                    "check_id": check_id,
                    "outcome": outcome,
                    "safe_message": safe_message,
                    "evidence_digests": check_evidence,
                    "evidence_counts": {"participant_count": 4, "event_count": 2},
                }
            )
        receipt = {
            "profile": "tiny-synthetic/1",
            "fixture_id": "synthetic-structure-only",
            "fixture_digest": fixture_digest,
            "worker_executable_digest": self.identity.worker_executable_digest,
            "worker_code_digest": self.identity.worker_code_digest,
            "backend_source_digest": None,
            "environment_digest": self.identity.environment_digest,
            "started_at_utc": started,
            "ended_at_utc": _utc_now(),
            "checks": checks,
        }
        return WorkerSuccess(payload={"seed": payload["seed"], "receipt": receipt})


class DeterministicMcmcFixtureBackend(DeterministicFixtureBackend):
    """Non-scientific deterministic chain fixture for core authority tests only."""

    def __init__(self, identity: WorkerIdentityMaterial) -> None:
        super().__init__(identity)
        capabilities = dict(self._capabilities)
        capabilities.update(
            {
                "order_samples": True,
                "position_probabilities": True,
                "pairwise_precedence": True,
                "likelihood_trace": True,
                "accepted_transition_diagnostics": True,
                "multiple_chains": True,
            }
        )
        constraints = dict(cast(Mapping[str, Any], capabilities["constraints"]))
        constraints["maximum_raw_iterations"] = 501
        capabilities["constraints"] = constraints
        self._capabilities = capabilities
        self._capabilities_digest = structured_sha256(
            "ebm-audit/capabilities/1", capabilities
        )
        semantics = dict(self._adapter_semantics)
        semantics.update(
            {
                "semantic_version": "fixture-deterministic-mcmc/1.0",
                "capabilities_digest": self._capabilities_digest,
                "mcmc_projection": {
                    "projection_schema_version": "ebm-audit-adapter-mcmc-projection/1.0",
                    "availability": "AVAILABLE",
                    "schedule_bindings": [
                        {
                            "plan_field": "raw_iteration_count",
                            "source_kind": "adapter-constant",
                            "backend_setting_id": None,
                            "constant_value": 501,
                        },
                        {
                            "plan_field": "burn_in_count",
                            "source_kind": "adapter-constant",
                            "backend_setting_id": None,
                            "constant_value": 1,
                        },
                        {
                            "plan_field": "thinning_interval",
                            "source_kind": "adapter-constant",
                            "backend_setting_id": None,
                            "constant_value": 1,
                        },
                    ],
                    "indexing_rule": "returned-post-proposal-row/1",
                    "proposal_method_id": "fixture-deterministic-adjacent-swap-v1",
                    "proposal_setting_bindings": [],
                    "initialization_rule": "fixture-seed-selected-order-v1",
                    "plan_owned_fields": ["chain_count", "seed_derivation_version"],
                },
            }
        )
        self._adapter_semantics = semantics
        self._adapter_semantics_digest = adapter_semantics_digest(semantics)
        self._allowed_requested_outputs.update(
            {
                "order_samples",
                "likelihood_trace",
                "accepted_transition_diagnostics",
                "position_probabilities",
                "pairwise_precedence",
            }
        )

    def _fixture_postburn_states(self, central: Any, alternate: Any) -> Any:
        np = __import__("numpy")
        postburn = np.tile(central, (500, 1))
        postburn[::5] = alternate
        return postburn

    def fit(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        base = super().fit(request, request_dir)
        payload = dict(base.payload)
        result = dict(cast(Mapping[str, Any], payload["result"]))
        np = __import__("numpy")
        central = np.asarray(result["central_order_permutation"], dtype=np.int32)
        alternate = central.copy()
        alternate[0], alternate[1] = central[1], central[0]
        postburn = self._fixture_postburn_states(central, alternate)
        retained = postburn.copy()
        changes = np.any(postburn[1:] != postburn[:-1], axis=1)
        likelihood = np.linspace(-250.0, -249.0, postburn.shape[0], dtype=np.float64)
        event_count = int(central.size)
        position = np.zeros((event_count, event_count), dtype=np.float64)
        precedence = np.zeros((event_count, event_count), dtype=np.float64)
        for state in retained:
            for position_index, event_index in enumerate(state.tolist()):
                position[event_index, position_index] += 1.0
            inverse = np.empty(event_count, dtype=np.int64)
            inverse[state] = np.arange(event_count, dtype=np.int64)
            precedence += inverse[:, None] < inverse[None, :]
        position /= float(retained.shape[0])
        precedence /= float(retained.shape[0])
        np.fill_diagonal(precedence, 0.5)
        requested_outputs = frozenset(
            cast(Mapping[str, Any], request["payload"]["execution_input_projection"])[
                "requested_outputs"
            ]
        )
        output_arrays = dict(base.arrays)
        if "order_samples" in requested_outputs:
            output_arrays.update(
                {
                    "postburn_order_state_chain": postburn,
                    "order_state_chain": retained,
                }
            )
        if "likelihood_trace" in requested_outputs:
            output_arrays.update(
                {
                    "postburn_likelihood_trace": likelihood,
                    "likelihood_trace": likelihood.copy(),
                }
            )
        if "accepted_transition_diagnostics" in requested_outputs:
            output_arrays["postburn_state_change_mask"] = changes
        if "position_probabilities" in requested_outputs:
            output_arrays["position_probabilities"] = position
        if "pairwise_precedence" in requested_outputs:
            output_arrays["pairwise_precedence"] = precedence
        semantic_versions = {
            "postburn_order_state_chain": (
                "postproposal-event-index-at-position-unthinned/1"
            ),
            "order_state_chain": "postproposal-event-index-at-position-retained/1",
            "postburn_likelihood_trace": (
                "postproposal-state-log-likelihood-unthinned/1"
            ),
            "likelihood_trace": "postproposal-state-log-likelihood-retained/1",
            "postburn_state_change_mask": "adjacent-postburn-state-change/1",
            "position_probabilities": "event-position-probability/1",
            "pairwise_precedence": "pairwise-event-precedence-probability/1",
        }
        catalog = dict(cast(Mapping[str, Any], result["array_catalog"]))
        for name, value in output_arrays.items():
            if name in semantic_versions:
                catalog[name] = array_catalog_entry(
                    name,
                    value,
                    semantic_version=semantic_versions[name],
                )
        trace_digest = array_catalog_entry(
            "postburn_order_state_chain",
            postburn,
            semantic_version=semantic_versions["postburn_order_state_chain"],
        )["array_digest"]
        likelihood_digest = array_catalog_entry(
            "postburn_likelihood_trace",
            likelihood,
            semantic_version=semantic_versions["postburn_likelihood_trace"],
        )["array_digest"]
        field_origins = dict(cast(Mapping[str, Any], result["field_origins"]))
        trace_source = {
            "origin": "WORKER_DERIVED",
            "method_id": "fixture-deterministic-order-trace-v1",
            "source_fields": ["seed", "event_ids"],
            "source_hashes": [trace_digest],
        }
        for name in ("postburn_order_state_chain", "order_state_chain"):
            if name in output_arrays:
                field_origins[name] = trace_source
        for name in ("postburn_likelihood_trace", "likelihood_trace"):
            if name in output_arrays:
                field_origins[name] = {
                    "origin": "WORKER_DERIVED",
                    "method_id": "fixture-deterministic-likelihood-trace-v1",
                    "source_fields": ["seed", "event_ids"],
                    "source_hashes": [likelihood_digest],
                }
        transition_origin = {
            "origin": "WORKER_DERIVED",
            "method_id": "adjacent-unthinned-postburn-state-change-v1",
            "source_fields": ["seed", "event_ids"],
            "source_hashes": [trace_digest],
        }
        if "accepted_transition_diagnostics" in requested_outputs:
            field_origins["postburn_state_change_mask"] = transition_origin
            field_origins["actual_transition_count"] = transition_origin
            field_origins["actual_transition_fraction"] = transition_origin
        for name, method in (
            ("position_probabilities", "retained-chain-position-probability-v1"),
            ("pairwise_precedence", "retained-chain-pairwise-precedence-v1"),
        ):
            if name not in output_arrays:
                continue
            field_origins[name] = {
                "origin": "WORKER_DERIVED",
                "method_id": method,
                "source_fields": ["seed", "event_ids"],
                "source_hashes": [trace_digest],
            }
        transition_count = (
            int(changes.sum())
            if "accepted_transition_diagnostics" in requested_outputs
            else None
        )
        transition_fraction = (
            float(changes.mean())
            if "accepted_transition_diagnostics" in requested_outputs
            else None
        )
        result.update(
            {
                "raw_iteration_count": 501,
                "burn_in_count": 1,
                "thinning_interval": 1,
                "postburn_unthinned_state_count": 500,
                "retained_state_count": 500,
                "likelihood_indexing": (
                    "post-proposal-state/1"
                    if "likelihood_trace" in requested_outputs
                    else None
                ),
                "actual_transition_count": transition_count,
                "actual_transition_fraction": transition_fraction,
                "array_catalog": catalog,
                "field_origins": field_origins,
                "capabilities_digest": self._capabilities_digest,
            }
        )
        result.pop("worker_fit_payload_digest", None)
        result["worker_fit_payload_digest"] = worker_fit_payload_digest(result)
        payload["result"] = result
        return WorkerSuccess(
            payload=payload,
            arrays=output_arrays,
            warnings=base.warnings,
        )
