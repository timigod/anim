"""Request-bound authoring context for researcher-owned Fit callbacks."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self, cast

from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.privacy.safe import normalize_worker_warning
from ebm_audit.protocol import (
    bind_request_digests,
    canonical_json_bytes,
    exact_file_sha256_path,
    strict_json_loads,
    structured_sha256,
    validate_request_execution_input_binding,
    worker_fit_payload_digest,
)
from ebm_audit.schema import validate_instance
from ebm_audit.workers.arrays import load_catalogued_npz_arrays
from ebm_audit.workers.types import WorkerFailure, WorkerSuccess

from .records import (
    ArrayReference,
    ArtifactReference,
    CapabilityDeclaration,
    SDKValidationError,
    StageReference,
    WarningRecord,
)

_RESOURCE_SUMMARY = {
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

_STANDARD_OUTPUT_SEMANTICS = {
    "postburn_order_state_chain": "postproposal-event-index-at-position-unthinned/1",
    "order_state_chain": "postproposal-event-index-at-position-retained/1",
    "postburn_likelihood_trace": "postproposal-state-log-likelihood-unthinned/1",
    "likelihood_trace": "postproposal-state-log-likelihood-retained/1",
    "postburn_state_change_mask": "adjacent-postburn-state-change/1",
    "position_probabilities": "event-position-probability/1",
    "pairwise_precedence": "pairwise-event-precedence-probability/1",
    "training_row_indexes": "contiguous-internal-row-index/1",
    "training_stage_posterior": "training-stage-posterior/1",
    "training_map_stage": "training-map-stage/1",
    "training_map_tie_mask": "training-map-tie-mask/1",
    "training_expected_stage": "training-expected-stage/1",
    "evaluation_row_indexes": "contiguous-internal-row-index/1",
    "evaluation_stage_posterior": "evaluation-stage-posterior/1",
    "evaluation_map_stage": "evaluation-map-stage/1",
    "evaluation_map_tie_mask": "evaluation-map-tie-mask/1",
    "evaluation_expected_stage": "evaluation-expected-stage/1",
}


@dataclass(frozen=True, slots=True)
class FitOutputs:
    """Closed standard Fit output values with protocol metadata owned by the SDK."""

    postburn_order_state_chain: Any | None = None
    order_state_chain: Any | None = None
    postburn_likelihood_trace: Any | None = None
    likelihood_trace: Any | None = None
    postburn_state_change_mask: Any | None = None
    position_probabilities: Any | None = None
    pairwise_precedence: Any | None = None
    training_row_indexes: Any | None = None
    training_stage_posterior: Any | None = None
    training_map_stage: Any | None = None
    training_map_tie_mask: Any | None = None
    training_expected_stage: Any | None = None
    evaluation_row_indexes: Any | None = None
    evaluation_stage_posterior: Any | None = None
    evaluation_map_stage: Any | None = None
    evaluation_map_tie_mask: Any | None = None
    evaluation_expected_stage: Any | None = None


_EMPTY_FIT_OUTPUTS = FitOutputs()


@dataclass(frozen=True, slots=True, init=False)
class FitContext:
    """One validated Fit request and its immutable execution projection.

    Construction copies the request through canonical JSON before exposing any
    fields. Later result authoring can therefore derive request-owned bindings
    without retaining a caller-mutable request mapping.
    """

    request_dir: Path
    _request_bytes: bytes = field(repr=False)
    _array_references: tuple[ArrayReference, ...] = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("FitContext must be created with FitContext.from_request().")

    @classmethod
    def from_request(cls, request: Mapping[str, Any], request_dir: Path) -> Self:
        """Validate and snapshot one exact protocol-v2 Fit request."""

        try:
            request_bytes = canonical_json_bytes(request)
            copied = strict_json_loads(request_bytes)
            validate_instance(copied, "worker-protocol.schema.json", definition="WorkerRequest")
            if not isinstance(copied, dict) or copied.get("command") != "fit":
                raise ValueError
            if bind_request_digests(copied) != copied:
                raise ValueError
            validate_request_execution_input_binding(copied)
            payload = copied.get("payload")
            if not isinstance(payload, dict):
                raise ValueError
            validate_instance(
                payload,
                "worker-protocol.schema.json",
                definition="FitRequestPayload",
            )
            projection = cast(dict[str, Any], payload["execution_input_projection"])
            dataset = cast(dict[str, Any], projection["dataset"])
            catalog = cast(dict[str, Any], dataset["array_catalog"])
            archive = Path(request_dir) / "values.npz"
            file_record = cast(dict[str, Any], copied["files"]).get("values.npz")
            if not isinstance(file_record, dict) or file_record != {
                "byte_length": archive.stat().st_size,
                "sha256": exact_file_sha256_path(archive),
            }:
                raise ValueError
            arrays = load_catalogued_npz_arrays(archive, catalog=catalog)
            _validate_input_arrays(dataset, arrays)
            if projection["data_accounting"] != _expected_data_accounting(dataset, arrays):
                raise ValueError
            array_references = tuple(
                ArrayReference(
                    member_name=name,
                    value=value,
                    semantic_version=cast(str, catalog[name]["semantic_version"]),
                )
                for name, value in sorted(arrays.items())
            )
        except Exception:
            raise SDKValidationError(
                phase="fit-request-validation",
                field="fit_request",
            ) from None
        instance = object.__new__(cls)
        object.__setattr__(instance, "request_dir", Path(request_dir))
        object.__setattr__(instance, "_request_bytes", request_bytes)
        object.__setattr__(instance, "_array_references", array_references)
        return instance

    @property
    def request(self) -> dict[str, Any]:
        """Return a fresh copy of the validated worker request."""

        return cast(dict[str, Any], strict_json_loads(self._request_bytes))

    @property
    def payload(self) -> dict[str, Any]:
        """Return a fresh copy of the Fit scientific request payload."""

        return cast(dict[str, Any], self.request["payload"])

    @property
    def execution_input_projection(self) -> dict[str, Any]:
        """Return a fresh copy of the request-owned execution projection."""

        return cast(dict[str, Any], self.payload["execution_input_projection"])

    @property
    def arrays(self) -> dict[str, Any]:
        """Return immutable copies of the validated request arrays."""

        copied: dict[str, Any] = {}
        for reference in self._array_references:
            value = reference.value.copy(order="C")
            value.flags.writeable = False
            copied[reference.member_name] = value
        return copied

    def fit_success(
        self,
        *,
        central_order: Any,
        central_order_method: Mapping[str, Any],
        field_origins: Mapping[str, Mapping[str, Any]],
        raw_iteration_count: int | None,
        burn_in_count: int | None,
        thinning_interval: int | None,
        postburn_unthinned_state_count: int | None,
        retained_state_count: int | None,
        likelihood_indexing: str | None,
        actual_transition_count: int | None,
        actual_transition_fraction: float | None,
        warnings: Iterable[WarningRecord | Mapping[str, Any]],
        outputs: FitOutputs = _EMPTY_FIT_OUTPUTS,
        stage_model_reference: StageReference | Mapping[str, Any] | None = None,
        backend_artifacts: Iterable[ArtifactReference | Mapping[str, Any]] = (),
        exact_fixed_target_reference: Mapping[str, Any] | None = None,
    ) -> WorkerSuccess | WorkerFailure:
        """Build one complete Fit result from explicit model-owned facts.

        Request identities, dataset accounting, capability absences, provenance,
        resource defaults, and array metadata are derived here. No scientific
        method, output array, field origin, or fitted artifact is invented.
        """

        try:
            if type(outputs) is not FitOutputs:
                raise ValueError
            central_reference = ArrayReference(
                member_name="central_order_permutation",
                value=central_order,
                semantic_version="event-index-at-position/1",
            )
            output_references = (central_reference, *_standard_output_references(outputs))
            output_arrays = {item.member_name: item.value for item in output_references}
            catalog = {
                item.member_name: item.catalog_entry()
                for item in sorted(output_references, key=lambda item: item.member_name)
            }
            permutation = central_reference.value.tolist()
            if not isinstance(permutation, list):
                raise ValueError

            payload = self.payload
            projection = self.execution_input_projection
            dataset = cast(dict[str, Any], projection["dataset"])
            identity = cast(dict[str, Any], projection["selected_backend_identity"])
            requested_outputs = cast(list[str], projection["requested_outputs"])
            applicability = CapabilityDeclaration.from_mapping(
                cast(dict[str, Any], projection["capabilities"])
            ).assess_requested_outputs(requested_outputs)

            result: dict[str, Any] = {
                "payload_schema_version": "ebm-audit-worker-fit-payload/2.0",
                "universe_id": payload["universe_id"],
                "chain_execution_id": payload["chain_execution_id"],
                "attempt_id": payload["attempt_id"],
                "attempt_ordinal": payload["attempt_ordinal"],
                "algorithm_id": projection["algorithm_id"],
                "settings_digest": projection["settings_digest"],
                "config_digest": projection["config_digest"],
                "requested_outputs_digest": projection["requested_outputs_digest"],
                "execution_input_projection_digest": payload["execution_input_projection_digest"],
                "seed": payload["seed"],
                "chain_id": payload["chain_id"],
                "event_ids": list(dataset["event_ids"]),
                "central_order_permutation": permutation,
                "central_order_method": dict(central_order_method),
                "raw_iteration_count": raw_iteration_count,
                "burn_in_count": burn_in_count,
                "thinning_interval": thinning_interval,
                "postburn_unthinned_state_count": postburn_unthinned_state_count,
                "retained_state_count": retained_state_count,
                "likelihood_indexing": likelihood_indexing,
                "actual_transition_count": actual_transition_count,
                "actual_transition_fraction": actual_transition_fraction,
                "array_catalog": catalog,
                "field_origins": {
                    name: dict(origin) for name, origin in sorted(field_origins.items())
                },
                "participant_event_manifest": _participant_event_manifest(
                    dataset,
                    projection,
                    catalog,
                ),
                "preprocessing_manifest_digest": dataset["preprocessing_manifest_digest"],
                "stage_semantics_digest": dataset["stage_semantics_digest"],
                "stage_model_reference": _optional_mapping(stage_model_reference),
                "component_applicability": [item.to_mapping() for item in applicability],
                "input_digest": dataset["scientific_data_digest"],
                "core_code_digest": projection["core_code_digest"],
                "worker_executable_digest": identity["worker_executable_digest"],
                "worker_code_digest": identity["worker_code_digest"],
                "backend_source_digest": identity["backend_source_digest"],
                "environment_digest": identity["environment_digest"],
                "capabilities_digest": projection["capabilities_digest"],
                "resource_summary": _RESOURCE_SUMMARY,
                "backend_artifacts": [
                    _required_mapping(artifact) for artifact in backend_artifacts
                ],
            }
            if exact_fixed_target_reference is not None:
                result["exact_fixed_target_reference"] = dict(exact_fixed_target_reference)
            synthetic_provenance = dataset.get("synthetic_provenance")
            if synthetic_provenance is not None:
                result["synthetic_provenance"] = synthetic_provenance
            result["worker_fit_payload_digest"] = worker_fit_payload_digest(result)

            fit_payload = {
                "universe_id": payload["universe_id"],
                "chain_execution_id": payload["chain_execution_id"],
                "attempt_id": payload["attempt_id"],
                "attempt_ordinal": payload["attempt_ordinal"],
                "algorithm_id": projection["algorithm_id"],
                "settings_digest": projection["settings_digest"],
                "config_digest": projection["config_digest"],
                "requested_outputs_digest": projection["requested_outputs_digest"],
                "execution_input_projection_digest": payload["execution_input_projection_digest"],
                "seed": payload["seed"],
                "chain_id": payload["chain_id"],
                "result": result,
            }
            admitted_warnings = [
                normalize_worker_warning(
                    warning.to_mapping() if isinstance(warning, WarningRecord) else dict(warning)
                )
                for warning in warnings
            ]
            assert_no_direct_identifier_fields(fit_payload)
            assert_no_direct_identifier_fields(admitted_warnings)

            from .records import FitSuccess

            return FitSuccess.from_mapping(fit_payload).as_worker_result(
                arrays=output_arrays,
                warnings=admitted_warnings,
            )
        except WorkerFailure as failure:
            return failure
        except Exception:
            return WorkerFailure(
                status="PROTOCOL_ERROR",
                code="FIT.RESULT_INVALID",
                safe_message="The Fit result does not match the canonical schema.",
                phase="fit-result-validation",
            )


def _expected_data_accounting(
    dataset: Mapping[str, Any],
    arrays: Mapping[str, Any],
) -> dict[str, Any]:
    np = __import__("numpy")
    missing = sum(
        int(value.size - np.isfinite(value).sum())
        for name in ("train_values", "evaluation_values")
        if (value := arrays.get(name)) is not None
    )
    participant_count = int(dataset["participant_count"])
    event_count = int(dataset["event_count"])
    return {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": participant_count,
        "output_participants": participant_count,
        "input_events": event_count,
        "output_events": event_count,
        "input_missing_cells": missing,
        "output_missing_cells": missing,
        "flagged_cells": 0,
        "masked_cells": 0,
        "transformed_cells": 0,
        "added_participant_instances": 0,
        "removed_participants": 0,
        "removed_events": 0,
        "operations": [],
    }


def _standard_output_references(outputs: FitOutputs) -> tuple[ArrayReference, ...]:
    return tuple(
        ArrayReference(
            member_name=member_name,
            value=value,
            semantic_version=semantic_version,
        )
        for member_name, semantic_version in _STANDARD_OUTPUT_SEMANTICS.items()
        if (value := getattr(outputs, member_name)) is not None
    )


def _validate_input_arrays(
    dataset: Mapping[str, Any],
    arrays: Mapping[str, Any],
) -> None:
    np = __import__("numpy")
    participant_count = int(dataset["participant_count"])
    evaluation_count = int(dataset["evaluation_participant_count"])
    event_count = int(dataset["event_count"])
    if (
        arrays["train_values"].shape != (participant_count, event_count)
        or arrays["training_row_indexes"].shape != (participant_count,)
        or arrays["train_group_codes"].shape != (participant_count,)
        or not np.array_equal(
            arrays["training_row_indexes"],
            np.arange(participant_count, dtype=np.int64),
        )
        or not np.isfinite(arrays["train_values"]).all()
    ):
        raise ValueError
    evaluation_names = {
        "evaluation_values",
        "evaluation_row_indexes",
        "evaluation_group_codes",
    }
    if evaluation_count:
        if not evaluation_names <= set(arrays):
            raise ValueError
        if (
            arrays["evaluation_values"].shape != (evaluation_count, event_count)
            or arrays["evaluation_row_indexes"].shape != (evaluation_count,)
            or arrays["evaluation_group_codes"].shape != (evaluation_count,)
            or not np.array_equal(
                arrays["evaluation_row_indexes"],
                np.arange(evaluation_count, dtype=np.int64),
            )
            or not np.isfinite(arrays["evaluation_values"]).all()
        ):
            raise ValueError
    elif evaluation_names & set(arrays):
        raise ValueError


def _participant_event_manifest(
    dataset: Mapping[str, Any],
    projection: Mapping[str, Any],
    output_catalog: Mapping[str, Any],
) -> dict[str, Any]:
    evaluation_outputs_present = any(
        name.startswith("evaluation_") and name != "evaluation_row_indexes"
        for name in output_catalog
    )
    request_catalog = cast(Mapping[str, Any], dataset["array_catalog"])
    evaluation_digest = None
    if evaluation_outputs_present:
        evaluation_digest = cast(Mapping[str, Any], output_catalog["evaluation_row_indexes"])[
            "array_digest"
        ]
    return {
        "request_training_participants": dataset["participant_count"],
        "returned_training_participants": dataset["participant_count"],
        "training_row_indexes_digest": cast(
            Mapping[str, Any], request_catalog["training_row_indexes"]
        )["array_digest"],
        "request_evaluation_participants": dataset["evaluation_participant_count"],
        "returned_evaluation_participants": (
            dataset["evaluation_participant_count"] if evaluation_outputs_present else 0
        ),
        "evaluation_row_indexes_digest": evaluation_digest,
        "request_events": list(cast(Iterable[str], dataset["event_ids"])),
        "returned_events": list(cast(Iterable[str], dataset["event_ids"])),
        "worker_removed_participants": [],
        "worker_removed_events": [],
        "worker_modified_cells": [],
        "core_data_accounting_digest": structured_sha256(
            "ebm-audit/data-accounting/1",
            projection["data_accounting"],
        ),
    }


def _optional_mapping(
    value: StageReference | Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    return value.to_mapping() if isinstance(value, StageReference) else dict(value)


def _required_mapping(
    value: ArtifactReference | Mapping[str, Any],
) -> dict[str, Any]:
    return value.to_mapping() if isinstance(value, ArtifactReference) else dict(value)
