"""Truthful, synthetic-only public contract checks for an external worker."""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np

from ebm_audit.errors import AuditError, PrivacyViolationError, WorkerProtocolError
from ebm_audit.protocol import (
    backend_identity_digest,
    canonical_json_bytes,
    exact_file_sha256,
    structured_sha256,
)
from ebm_audit.schema import SchemaValidationError, load_protocol_registry
from ebm_audit.synthetic.conformance import (
    build_conformance_provenance,
    generate_conformance_input,
)
from ebm_audit.workers.arrays import array_catalog_entry

from .config import WorkerCommand, WorkerConfig
from .invocation import (
    WorkerExecution,
    WorkerInvoker,
    _readback_authenticated_execution,
)
from .requests import fixture_dataset_descriptor, requested_outputs_digest, settings_digest

CaseStatus = Literal["PASS", "FAIL", "UNVERIFIED", "UNSUPPORTED"]

_SEED_A = "000000000000002a"
_SEED_B = "000000000000002b"
_MAX_SYNTHETIC_PARTICIPANTS = 1024
_MAX_SYNTHETIC_EVENTS = 64

_CORE_EVIDENCE_SUBJECT = "AUDITOR_CORE_BOUNDARY"
_WORKER_EVIDENCE_SUBJECT = "CONFIGURED_WORKER_SYNTHETIC_SURFACE"
_RAW_VALUE_CANARY = 0.125987654321
_PRIVATE_ID_CANARY = "contract_private_participant_canary_do_not_emit"
_CONFORMANCE_ALGORITHM_ID = "conformance-exact-gaussian"
_V2_WORKER_COMMANDS = ["describe", "validate", "fit", "self-test"]
_V2_REQUIRED_ALGORITHM_COMMANDS = ["validate", "fit"]
_REPEATABILITY_MEASUREMENT_FIELDS = frozenset(
    {"resource_summary", "backend_artifacts", "worker_fit_payload_digest"}
)
_INVARIANCE_FLOAT_ATOL = 1e-12

# A scientific array is projected only when the core knows what each axis
# means.  Adapter-private arrays are admitted below through the closed
# StageModelReference bindings, or through an exact adapter semantic version.
# An unknown applicable semantic is evidence that the invariant was not
# checked, never evidence that it passed.
_CANONICAL_ARRAY_SEMANTICS: Mapping[str, frozenset[str]] = {
    "central_order_permutation": frozenset({"event-index-at-position/1"}),
    "postburn_order_state_chain": frozenset({"postproposal-event-index-at-position-unthinned/1"}),
    "order_state_chain": frozenset({"postproposal-event-index-at-position-retained/1"}),
    "postburn_likelihood_trace": frozenset({"postproposal-state-log-likelihood-unthinned/1"}),
    "likelihood_trace": frozenset({"postproposal-state-log-likelihood-retained/1"}),
    "postburn_state_change_mask": frozenset({"adjacent-postburn-state-change/1"}),
    "position_probabilities": frozenset(
        {"event-position-probability/1", "position-probabilities/1"}
    ),
    "pairwise_precedence": frozenset(
        {"pairwise-event-precedence-probability/1", "pairwise-precedence/1"}
    ),
    "training_row_indexes": frozenset(
        {"contiguous-internal-row-index/1", "training-row-indexes/1"}
    ),
    "training_stage_posterior": frozenset({"training-stage-posterior/1"}),
    "training_map_stage": frozenset({"training-map-stage/1"}),
    "training_map_tie_mask": frozenset({"training-map-tie-mask/1"}),
    "training_expected_stage": frozenset({"training-expected-stage/1"}),
    "evaluation_row_indexes": frozenset({"contiguous-internal-row-index/1"}),
    "evaluation_stage_posterior": frozenset({"evaluation-stage-posterior/1"}),
    "evaluation_map_stage": frozenset({"evaluation-map-stage/1"}),
    "evaluation_map_tie_mask": frozenset({"evaluation-map-tie-mask/1"}),
    "evaluation_expected_stage": frozenset({"evaluation-expected-stage/1"}),
}
_EVENT_ORDER_ARRAYS = frozenset(
    {"central_order_permutation", "postburn_order_state_chain", "order_state_chain"}
)
_EVENT_FIRST_AXIS_ARRAYS = frozenset({"position_probabilities"})
_EVENT_BOTH_AXES_ARRAYS = frozenset({"pairwise_precedence"})
_TRAINING_ROW_ARRAYS = frozenset(
    {
        "training_row_indexes",
        "training_stage_posterior",
        "training_map_stage",
        "training_map_tie_mask",
        "training_expected_stage",
    }
)
_EVALUATION_ROW_ARRAYS = frozenset(
    {
        "evaluation_row_indexes",
        "evaluation_stage_posterior",
        "evaluation_map_stage",
        "evaluation_map_tie_mask",
        "evaluation_expected_stage",
    }
)
_PYSAEBM_PRIVATE_SEMANTICS: Mapping[str, str] = {
    "pysaebm-native-global-best-event-index-at-position/1": "event-order",
    "pysaebm-conjugate-priors-theta-mean-std/1": "event-first-axis",
    "pysaebm-conjugate-priors-phi-mean-std/1": "event-first-axis",
    "pysaebm-native-mh-disease-stage-prior/1": "unchanged",
    "pysaebm-plugin-pi-em-final-prior/1": "unchanged",
}
_STABLE_FIT_RESULT_FIELDS = (
    "payload_schema_version",
    "algorithm_id",
    "settings_digest",
    "requested_outputs_digest",
    "seed",
    "central_order_method",
    "raw_iteration_count",
    "burn_in_count",
    "thinning_interval",
    "postburn_unthinned_state_count",
    "retained_state_count",
    "likelihood_indexing",
    "actual_transition_count",
    "actual_transition_fraction",
    "preprocessing_manifest_digest",
    "stage_semantics_digest",
    "component_applicability",
    "capabilities_digest",
)


@dataclass(frozen=True)
class _SyntheticFixture:
    arrays: Mapping[str, Any]
    dataset: Mapping[str, Any]
    fixture_digest: str


@dataclass(frozen=True)
class _ScientificProjection:
    metadata: Mapping[str, Any]
    arrays: Mapping[str, np.ndarray[Any, Any]]


@dataclass(frozen=True)
class _PinnedContractHarnessInvoker:
    """Route every configured command through one call-scoped Describe owner."""

    invoker: WorkerInvoker
    description_capability: object

    def _invoke_contract_harness(
        self,
        *,
        command: str,
        payload_schema_version: str | None,
        payload: Mapping[str, Any],
        arrays: Mapping[str, Any] | None = None,
    ) -> WorkerExecution:
        return self.invoker._invoke_contract_harness(
            command=command,
            payload_schema_version=payload_schema_version,
            payload=payload,
            arrays=arrays,
            _authenticated_description_capability=self.description_capability,
        )


@dataclass(eq=False)
class _UnknownScientificSemantics(Exception):
    member_name: str
    semantic_version: str


def _case(
    case_id: str,
    status: CaseStatus,
    safe_message: str,
    *,
    implemented: bool = True,
    applicable: bool = True,
    required: bool = True,
    evidence_subject: str = _WORKER_EVIDENCE_SUBJECT,
    evidence: Mapping[str, int | str | bool] | None = None,
) -> dict[str, Any]:
    if not applicable and required:
        raise ValueError("A non-applicable contract case cannot be required.")
    return {
        "case_id": case_id,
        "implemented": implemented,
        "applicability": "APPLICABLE" if applicable else "NOT_APPLICABLE",
        "required": required,
        "status": status,
        "safe_message": safe_message,
        "evidence_subject": evidence_subject,
        "evidence": dict(evidence or {}),
    }


def _not_applicable(case_id: str, safe_message: str) -> dict[str, Any]:
    return _case(
        case_id,
        "UNSUPPORTED",
        safe_message,
        applicable=False,
        required=False,
    )


def _failure_case(case_id: str, error: Exception) -> dict[str, Any]:
    """Downgrade ordinary case failures, never a real privacy-boundary failure."""

    if isinstance(error, PrivacyViolationError):
        raise error
    code = error.code if isinstance(error, AuditError) else "UNEXPECTED.CASE_FAILURE"
    return _case(
        case_id,
        "FAIL",
        "The synthetic contract case did not complete successfully.",
        evidence={"error_code": code},
    )


def _find_algorithm(description: Mapping[str, Any], algorithm_id: str) -> Mapping[str, Any] | None:
    algorithms = description.get("supported_algorithms")
    if not isinstance(algorithms, list):
        return None
    matches = [
        algorithm
        for algorithm in algorithms
        if isinstance(algorithm, Mapping) and algorithm.get("algorithm_id") == algorithm_id
    ]
    return matches[0] if len(matches) == 1 else None


def _description_uses_v2_command_surface(description: Mapping[str, Any]) -> bool:
    algorithms = description.get("supported_algorithms")
    return (
        description.get("supported_commands") == _V2_WORKER_COMMANDS
        and isinstance(algorithms, list)
        and bool(algorithms)
        and all(
            isinstance(algorithm, Mapping)
            and algorithm.get("supported_commands") == _V2_REQUIRED_ALGORITHM_COMMANDS
            for algorithm in algorithms
        )
    )


def _bounded_count(
    minimum: object,
    maximum: object,
    *,
    normal: int,
    hard_limit: int,
) -> int | None:
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        return None
    if maximum is not None and (
        isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < minimum
    ):
        return None
    selected = max(normal, minimum)
    if isinstance(maximum, int):
        selected = min(selected, maximum)
    if selected < minimum or selected > hard_limit:
        return None
    return selected


def _synthetic_fixture(algorithm: Mapping[str, Any]) -> _SyntheticFixture | None:
    capabilities = algorithm.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return None
    constraints = capabilities.get("constraints")
    if not isinstance(constraints, Mapping):
        return None
    participant_count = _bounded_count(
        constraints.get("minimum_participants"),
        constraints.get("maximum_participants"),
        normal=4,
        hard_limit=_MAX_SYNTHETIC_PARTICIPANTS,
    )
    event_count = _bounded_count(
        constraints.get("minimum_events"),
        constraints.get("maximum_events"),
        normal=3,
        hard_limit=_MAX_SYNTHETIC_EVENTS,
    )
    if participant_count is None or participant_count < 2 or event_count is None:
        return None
    event_ids = [f"synthetic_event_{index:03d}" for index in range(event_count)]
    if algorithm.get("algorithm_id") == _CONFORMANCE_ALGORITHM_ID:
        generated = generate_conformance_input(
            participant_count=participant_count,
            event_count=event_count,
            event_ids=tuple(event_ids),
        )
        arrays = dict(generated.arrays)
        dataset = fixture_dataset_descriptor(
            arrays,
            event_ids=event_ids,
            event_directions=list(generated.event_directions),
            group_codebook=generated.group_codebook,
            stage_semantics_digest_value=str(algorithm["stage_semantics_digest"]),
        )
        dataset["synthetic_provenance"] = build_conformance_provenance(
            participant_count=participant_count,
            event_count=event_count,
            event_ids=tuple(event_ids),
        )
        fixture_digest = structured_sha256(
            "ebm-audit/public-contract-fixture/1",
            {
                "fixture_label": "project-owned-conformance-generator",
                "participant_count": participant_count,
                "event_count": event_count,
                "scientific_data_digest": dataset["scientific_data_digest"],
            },
        )
        return _SyntheticFixture(
            arrays=arrays,
            dataset=dataset,
            fixture_digest=fixture_digest,
        )
    row_grid = np.arange(participant_count, dtype=np.float64)[:, None]
    column_grid = np.arange(event_count, dtype=np.float64)[None, :]
    arrays: dict[str, Any] = {
        "train_values": np.asarray(((row_grid + column_grid) % 3.0) - 1.0, dtype=np.float64),
        "training_row_indexes": np.arange(participant_count, dtype=np.int64),
        "train_group_codes": np.asarray(
            np.arange(participant_count, dtype=np.int32) % 2,
            dtype=np.int32,
        ),
    }
    arrays["train_values"][0, 0] = _RAW_VALUE_CANARY
    dataset = fixture_dataset_descriptor(
        arrays,
        event_ids=event_ids,
        event_directions=["higher" if index % 2 == 0 else "lower" for index in range(event_count)],
        group_codebook={"0": "reference", "1": "at_risk"},
        stage_semantics_digest_value=str(algorithm["stage_semantics_digest"]),
    )
    fixture_digest = structured_sha256(
        "ebm-audit/public-contract-fixture/1",
        {
            "fixture_label": "project-owned-synthetic-structure-only",
            "participant_count": participant_count,
            "event_count": event_count,
            "scientific_data_digest": dataset["scientific_data_digest"],
        },
    )
    return _SyntheticFixture(arrays=arrays, dataset=dataset, fixture_digest=fixture_digest)


def _common_payload(
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    *,
    command: str,
    requested_outputs: list[str] | None = None,
) -> dict[str, Any]:
    outputs = ["central_order"] if requested_outputs is None else requested_outputs
    config_digest = structured_sha256(
        "ebm-audit/public-contract-config/1",
        {
            "algorithm_id": config.algorithm_id,
            "settings": config.settings,
            "fixture_digest": fixture.fixture_digest,
        },
    )
    return {
        "algorithm_id": config.algorithm_id,
        "settings": dict(config.settings),
        "settings_digest": settings_digest(config.settings),
        "config_digest": config_digest,
        "requested_outputs": outputs,
        "requested_outputs_digest": requested_outputs_digest(command, outputs),
        "dataset": dict(fixture.dataset),
    }


def _fit_payload(
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    *,
    seed: str,
) -> dict[str, Any]:
    common = _common_payload(config, fixture, command="fit")
    return {
        "universe_id": structured_sha256(
            "ebm-audit/public-contract-universe/1",
            {"fixture_digest": fixture.fixture_digest, "algorithm_id": config.algorithm_id},
        ),
        "chain_execution_id": structured_sha256(
            "ebm-audit/public-contract-chain/1",
            {"fixture_digest": fixture.fixture_digest, "seed": seed},
        ),
        "attempt_id": structured_sha256(
            "ebm-audit/public-contract-attempt/1",
            {"fixture_digest": fixture.fixture_digest, "seed": seed, "attempt": 0},
        ),
        "attempt_ordinal": 0,
        **common,
        "seed": seed,
        "chain_id": f"public-contract-{seed}",
    }


def _invoke_describe(invoker: WorkerInvoker, expected: Mapping[str, Any] | None) -> WorkerExecution:
    return invoker._invoke_contract_harness(
        command="describe",
        payload_schema_version=None,
        payload={"expected_identity": None if expected is None else dict(expected)},
    )


def _identity_case(
    _invoker: WorkerInvoker,
    config: WorkerConfig,
    describe_execution: WorkerExecution,
    algorithm: Mapping[str, Any],
) -> dict[str, Any]:
    expected = config.expected_identity
    if expected is None:
        return _case(
            "expected-immutable-identity",
            "UNVERIFIED",
            (
                "No immutable worker identity expectation was configured, so exact "
                "identity and drift checks did not run."
            ),
            evidence={"expected_non_null_field_count": 0},
        )
    if (
        describe_execution.response["status"] != "SUCCESS"
        or algorithm.get("algorithm_id") != expected.get("selected_algorithm_id")
    ):
        return _case(
            "expected-immutable-identity",
            "FAIL",
            "The worker identity does not match the configured expectation.",
        )
    return _case(
        "expected-immutable-identity",
        "PASS",
        "The configured immutable identity matches the selected worker algorithm.",
        evidence={"expected_non_null_field_count": len(expected)},
    )


def _self_test_case(invoker: WorkerInvoker, description: Mapping[str, Any]) -> dict[str, Any]:
    if "self-test" not in description.get("supported_commands", []):
        return _case(
            "worker-self-test",
            "UNSUPPORTED",
            "The required worker self-test command is not advertised.",
        )
    checks = [row["check_id"] for row in load_protocol_registry()["self_test_checks"]]
    try:
        execution = invoker._invoke_contract_harness(
            command="self-test",
            payload_schema_version=None,
            payload={
                "seed": _SEED_A,
                "profile": "tiny-synthetic/1",
                "requested_checks": checks,
            },
        )
    except Exception as error:
        return _failure_case("worker-self-test", error)
    response = execution.response
    if response["status"] == "UNSUPPORTED_CAPABILITY":
        return _case("worker-self-test", "UNSUPPORTED", "The self-test is unavailable.")
    if response["status"] != "SUCCESS":
        return _case("worker-self-test", "FAIL", "The worker self-test returned a failure.")
    rows = response["payload"]["receipt"]["checks"]
    failed = [row for row in rows if row["outcome"] != "PASS"]
    if not failed:
        return _case(
            "worker-self-test",
            "PASS",
            "Every requested worker-owned synthetic self-test passed.",
            evidence={"check_count": len(rows)},
        )
    containment_owned = {"offline-no-network", "side-effect-boundary"}
    unavailable = all(
        row["check_id"] in containment_owned and str(row["safe_message"]).startswith("UNVERIFIED:")
        for row in failed
    )
    containment_verified = (
        unavailable
        and execution.attempt_observability_verified
        and execution.containment_provider in {"macos-seatbelt", "linux-bubblewrap"}
        and execution.containment_launcher_sha256.startswith("sha256:")
    )
    if containment_verified:
        return _case(
            "worker-self-test",
            "PASS",
            (
                "Worker-owned checks passed or were covered for this cooperative synthetic "
                "invocation by the auditor OS containment and attempt guard. This does not "
                "claim hostile-code read isolation."
            ),
            evidence_subject="CONFIGURED_WORKER_PLUS_CORE_CONTAINMENT",
            evidence={
                "check_count": len(rows),
                "core_covered_check_count": len(failed),
                "containment_provider": execution.containment_provider,
                "containment_launcher_sha256": execution.containment_launcher_sha256,
                "attempt_guard_verified": execution.attempt_observability_verified,
            },
        )
    return _case(
        "worker-self-test",
        "UNVERIFIED" if unavailable else "FAIL",
        (
            "One or more worker-owned self-tests explicitly remain unverified."
            if unavailable
            else "One or more worker-owned synthetic self-tests failed."
        ),
        evidence={"check_count": len(rows), "non_pass_count": len(failed)},
    )


def _validate_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    try:
        execution = invoker._invoke_contract_harness(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=_common_payload(config, fixture, command="validate"),
            arrays=fixture.arrays,
        )
    except Exception as error:
        return _failure_case("finite-synthetic-validate", error)
    status = execution.response["status"]
    if status == "SUCCESS" and execution.response["payload"]["fit_permitted"] is True:
        return _case(
            "finite-synthetic-validate",
            "PASS",
            "The worker validated the complete finite synthetic fixture without fitting.",
        )
    if status == "UNSUPPORTED_CAPABILITY":
        return _case(
            "finite-synthetic-validate",
            "UNSUPPORTED",
            "The worker cannot validate this bounded synthetic fixture.",
        )
    return _case(
        "finite-synthetic-validate",
        "FAIL",
        "The finite synthetic validation did not permit fitting.",
    )


def _fit(
    invoker: WorkerInvoker,
    payload: Mapping[str, Any],
    fixture: _SyntheticFixture,
) -> WorkerExecution:
    return invoker._invoke_contract_harness(
        command="fit",
        payload_schema_version="ebm-audit-worker-fit-payload/2.0",
        payload=payload,
        arrays=fixture.arrays,
    )


def _repeatability_result_projection(result: Mapping[str, Any]) -> dict[str, Any]:
    """Return the deterministic canonical result, excluding measured/run-local evidence."""

    return {
        field: value
        for field, value in result.items()
        if field not in _REPEATABILITY_MEASUREMENT_FIELDS
    }


def _same_seed_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    payload = _fit_payload(config, fixture, seed=_SEED_A)
    try:
        first = _fit(invoker, payload, fixture)
        second = _fit(invoker, payload, fixture)
    except Exception as error:
        return _failure_case("fit-same-seed-repeatability", error)
    if first.response["status"] == second.response["status"] == "UNSUPPORTED_CAPABILITY":
        return _case(
            "fit-same-seed-repeatability",
            "UNSUPPORTED",
            "The worker cannot fit this bounded synthetic fixture.",
        )
    if first.response["status"] != "SUCCESS" or second.response["status"] != "SUCCESS":
        return _case(
            "fit-same-seed-repeatability",
            "FAIL",
            "A same-seed synthetic fit did not succeed.",
        )
    first_result = first.response["payload"]["result"]
    second_result = second.response["payload"]["result"]
    first_projection = _repeatability_result_projection(first_result)
    second_projection = _repeatability_result_projection(second_result)
    arrays_equal = set(first.arrays) == set(second.arrays) and all(
        bool(np.array_equal(first.arrays[name], second.arrays[name])) for name in first.arrays
    )
    warnings_equal = (
        first.response["warnings_record_count"] == second.response["warnings_record_count"]
        and first.response["warnings_file_digest"] == second.response["warnings_file_digest"]
    )
    if first_projection != second_projection or not arrays_equal or not warnings_equal:
        return _case(
            "fit-same-seed-repeatability",
            "FAIL",
            "The worker returned different results for the same seed and request.",
        )
    repeatability_digest = structured_sha256(
        "ebm-audit/contract-repeatability-result/1",
        {
            "result": first_projection,
            "array_catalog": first_result["array_catalog"],
            "warnings_record_count": first.response["warnings_record_count"],
            "warnings_file_digest": first.response["warnings_file_digest"],
        },
    )
    return _case(
        "fit-same-seed-repeatability",
        "PASS",
        "The same synthetic request and seed produced the same canonical result.",
        evidence={"repeatability_projection_digest": repeatability_digest},
    )


def _different_seed_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    first_payload = _fit_payload(config, fixture, seed=_SEED_A)
    second_payload = _fit_payload(config, fixture, seed=_SEED_B)
    try:
        first = _fit(invoker, first_payload, fixture)
        second = _fit(invoker, second_payload, fixture)
    except Exception as error:
        return _failure_case("fit-different-seed-no-cache", error)
    if first.response["status"] == second.response["status"] == "UNSUPPORTED_CAPABILITY":
        return _case(
            "fit-different-seed-no-cache",
            "UNSUPPORTED",
            "The worker cannot fit this bounded synthetic fixture.",
        )
    if first.response["status"] != "SUCCESS" or second.response["status"] != "SUCCESS":
        return _case(
            "fit-different-seed-no-cache",
            "FAIL",
            "A different-seed synthetic fit did not succeed.",
        )
    first_result = first.response["payload"]["result"]
    second_result = second.response["payload"]["result"]
    identities_are_bound = all(
        first_result[field] == first_payload[field]
        and second_result[field] == second_payload[field]
        and first_result[field] != second_result[field]
        for field in ("seed", "chain_execution_id", "attempt_id", "chain_id")
    )
    no_stale_digest = (
        first.response["scientific_request_digest"] != second.response["scientific_request_digest"]
        and first_result["worker_fit_payload_digest"] != second_result["worker_fit_payload_digest"]
    )
    if not identities_are_bound or not no_stale_digest:
        return _case(
            "fit-different-seed-no-cache",
            "FAIL",
            "The different-seed fit reused stale request or result identity.",
        )
    return _case(
        "fit-different-seed-no-cache",
        "PASS",
        "Different seeds produced separately bound requests and results.",
    )


def _unknown_algorithm_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    payload = _common_payload(config, fixture, command="validate")
    payload["algorithm_id"] = f"{config.algorithm_id}-contract-unknown"
    try:
        invoker._invoke_contract_harness(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=payload,
            arrays=fixture.arrays,
        )
    except WorkerProtocolError as error:
        if error.code == "PROTOCOL.DESCRIBE_COMMAND_OWNER":
            return _case(
                "unknown-algorithm-rejected",
                "PASS",
                "The core rejected an algorithm absent from the worker description.",
            )
        return _failure_case("unknown-algorithm-rejected", error)
    except Exception as error:
        return _failure_case("unknown-algorithm-rejected", error)
    return _case(
        "unknown-algorithm-rejected",
        "FAIL",
        "An algorithm absent from the worker description was not rejected.",
    )


def _invalid_setting_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    algorithm: Mapping[str, Any],
) -> dict[str, Any]:
    properties = algorithm["settings_schema"].get("properties", {})
    key = "__ebm_audit_contract_unknown_setting__"
    while key in properties:
        key += "_"
    payload = _common_payload(config, fixture, command="validate")
    invalid_settings = {**config.settings, key: True}
    payload["settings"] = invalid_settings
    payload["settings_digest"] = settings_digest(invalid_settings)
    try:
        invoker._invoke_contract_harness(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=payload,
            arrays=fixture.arrays,
        )
    except (SchemaValidationError, WorkerProtocolError) as error:
        if (
            isinstance(error, SchemaValidationError)
            or error.code == "PROTOCOL.DESCRIBE_COMMAND_OWNER"
        ):
            return _case(
                "unknown-setting-rejected",
                "PASS",
                "The core rejected a setting absent from the closed worker schema.",
            )
        return _failure_case("unknown-setting-rejected", error)
    except Exception as error:
        return _failure_case("unknown-setting-rejected", error)
    return _case(
        "unknown-setting-rejected",
        "FAIL",
        "A setting absent from the closed worker schema was not rejected.",
    )


def _unavailable_output_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    algorithm: Mapping[str, Any],
) -> dict[str, Any]:
    capabilities = algorithm["capabilities"]
    candidate = None
    for row in load_protocol_registry()["requested_outputs"]:
        if "validate" not in row["commands"]:
            continue
        required = row["required_capabilities"]
        if required and any(capabilities.get(name) is not True for name in required):
            candidate = row["output_id"]
            break
    if candidate is None:
        return _not_applicable(
            "unavailable-output-rejected",
            "The selected algorithm has no unavailable validate output to probe.",
        )
    payload = _common_payload(
        config,
        fixture,
        command="validate",
        requested_outputs=[candidate],
    )
    try:
        execution = invoker._invoke_contract_harness(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=payload,
            arrays=fixture.arrays,
        )
    except Exception as error:
        return _failure_case("unavailable-output-rejected", error)
    if execution.response["status"] == "UNSUPPORTED_CAPABILITY":
        return _case(
            "unavailable-output-rejected",
            "PASS",
            "The worker rejected an output absent from its declared capabilities.",
        )
    return _case(
        "unavailable-output-rejected",
        "FAIL",
        "The worker did not return the required unsupported-capability result.",
    )


def _applicable_fit_outputs(algorithm: Mapping[str, Any]) -> list[str]:
    capabilities = algorithm["capabilities"]
    commands = set(algorithm["supported_commands"])
    if "fit" not in commands or not isinstance(capabilities, Mapping):
        return []
    outputs = []
    for row in load_protocol_registry()["requested_outputs"]:
        if "fit" not in row["commands"]:
            continue
        required = row["required_capabilities"]
        if all(capabilities.get(name) is True for name in required):
            outputs.append(str(row["output_id"]))
    return outputs


def _fixture_with_evaluation(fixture: _SyntheticFixture) -> _SyntheticFixture | None:
    training_values = np.asarray(fixture.arrays["train_values"])
    training_groups = np.asarray(fixture.arrays["train_group_codes"])
    evaluation_count = min(2, int(training_values.shape[0]))
    if evaluation_count < 1:
        return None
    arrays = {name: np.array(value, copy=True) for name, value in fixture.arrays.items()}
    arrays.update(
        {
            "evaluation_values": np.array(
                training_values[-evaluation_count:],
                dtype=np.float64,
                copy=True,
            ),
            "evaluation_row_indexes": np.arange(evaluation_count, dtype=np.int64),
            "evaluation_group_codes": np.array(
                training_groups[-evaluation_count:],
                dtype=np.int32,
                copy=True,
            ),
        }
    )
    semantic_versions = {
        "train_values": "synthetic-event-matrix/1",
        "training_row_indexes": "contiguous-internal-row-index/1",
        "train_group_codes": "canonical-group-code/1",
        "evaluation_values": "synthetic-fixed-evaluation-event-matrix/1",
        "evaluation_row_indexes": "contiguous-internal-row-index/1",
        "evaluation_group_codes": "canonical-group-code/1",
    }
    catalog = {
        name: array_catalog_entry(name, array, semantic_version=semantic_versions[name])
        for name, array in arrays.items()
    }
    dataset = dict(fixture.dataset)
    dataset.update(
        {
            "evaluation_participant_count": evaluation_count,
            "evaluation_row_index_array": "evaluation_row_indexes",
            "array_catalog": catalog,
            "scientific_data_digest": structured_sha256(
                "ebm-audit/fixture-scientific-data/1",
                {
                    "label": "synthetic-structure-only",
                    "participant_count": dataset["participant_count"],
                    "event_ids": dataset["event_ids"],
                    "array_catalog": catalog,
                },
            ),
        }
    )
    digest = structured_sha256(
        "ebm-audit/public-contract-fixture/1",
        {
            "fixture_label": "project-owned-synthetic-structure-only",
            "participant_count": dataset["participant_count"],
            "event_count": dataset["event_count"],
            "scientific_data_digest": dataset["scientific_data_digest"],
        },
    )
    return _SyntheticFixture(arrays=arrays, dataset=dataset, fixture_digest=digest)


def _declared_fit_output_surface_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    algorithm: Mapping[str, Any],
) -> dict[str, Any]:
    outputs = _applicable_fit_outputs(algorithm)
    if "central_order" not in outputs:
        return _case(
            "declared-fit-output-surface",
            "FAIL",
            "The mandatory central-order fit output is not applicable by the registry.",
        )
    evaluation_outputs = [output for output in outputs if output.startswith("evaluation_")]
    selected_fixture = fixture
    if evaluation_outputs:
        evaluation_fixture = _fixture_with_evaluation(fixture)
        if evaluation_fixture is None:
            return _case(
                "declared-fit-output-surface",
                "UNVERIFIED",
                "The declared fixed-evaluation fit outputs could not be exercised.",
            )
        selected_fixture = evaluation_fixture
    try:
        pair = _successful_fit(
            invoker,
            config,
            selected_fixture,
            requested_outputs=outputs,
        )
    except Exception as error:
        return _failure_case("declared-fit-output-surface", error)
    if pair is None:
        return _case(
            "declared-fit-output-surface",
            "FAIL",
            "The worker did not return every fit output implied by its capability claims.",
        )
    return _case(
        "declared-fit-output-surface",
        "PASS",
        "Every registry-applicable declared fit output passed the closed core invariants.",
        evidence={
            "requested_fit_output_count": len(outputs),
            "fixed_evaluation_output_count": len(evaluation_outputs),
            "fixed_evaluation_participant_count": int(
                selected_fixture.dataset["evaluation_participant_count"]
            ),
        },
    )


def _adversary_command(mode: str) -> WorkerCommand:
    return WorkerCommand.from_tokens(
        [
            sys.executable,
            # Execute the worker file without importing the auditor-side
            # adapters package in the contained worker. Its eager configuration
            # imports are not part of the adversary's SDK dependency surface.
            str(Path(__file__).resolve().with_name("contract_adversary.py")),
            mode,
        ]
    )


def _core_rejection_subcase(
    mode: str,
    expected_code: str,
    *,
    timeout_seconds: float = 30.0,
) -> bool:
    try:
        WorkerInvoker(
            _adversary_command(mode),
            timeout_seconds=timeout_seconds,
        )._invoke_contract_harness(
            command="describe",
            payload_schema_version=None,
            payload={"expected_identity": None},
        )
    except (PrivacyViolationError, WorkerProtocolError) as error:
        return error.code == expected_code
    except Exception:
        return False
    return False


def _core_boundary_case(
    case_id: str,
    subcases: Sequence[tuple[str, str, float | None]],
) -> dict[str, Any]:
    passed = sum(
        _core_rejection_subcase(
            mode,
            expected_code,
            timeout_seconds=30.0 if timeout is None else timeout,
        )
        for mode, expected_code, timeout in subcases
    )
    return _case(
        case_id,
        "PASS" if passed == len(subcases) else "FAIL",
        (
            "The auditor core rejected every project-owned adversarial transport case."
            if passed == len(subcases)
            else "The auditor core did not reject every project-owned adversarial transport case."
        ),
        evidence_subject=_CORE_EVIDENCE_SUBJECT,
        evidence={"subcase_count": len(subcases), "passed_subcase_count": passed},
    )


def _core_boundary_cases() -> list[dict[str, Any]]:
    return [
        _core_boundary_case(
            "malformed-bundle-schema-and-version",
            (
                ("malformed-json", "PROTOCOL.RESPONSE_SCHEMA", None),
                ("wrong-version", "PROTOCOL.RESPONSE_SCHEMA", None),
            ),
        ),
        _core_boundary_case(
            "timeout-crash-and-partial-response",
            (
                ("timeout-after-response", "TIMEOUT.WORKER_DEADLINE", 1.0),
                ("nonzero-after-response", "BACKEND.WORKER_PROCESS_FAILED", None),
                ("partial-response", "BACKEND.WORKER_PROCESS_FAILED", None),
            ),
        ),
        _core_boundary_case(
            "unexpected-file-and-path-escape",
            (
                ("extra-work-file", "PROTOCOL.SIDE_EFFECT_INVENTORY", None),
                ("nested-response-marker", "PROTOCOL.RESPONSE_SCHEMA", None),
                (
                    "caught-outside-write-attempt",
                    "PRIVACY.OUTSIDE_WRITE_ATTEMPT",
                    None,
                ),
            ),
        ),
        _core_boundary_case(
            "explicit-network-attempt-case",
            (("caught-network-attempt", "PRIVACY.NETWORK_ATTEMPT", None),),
        ),
    ]


def _closed_file_binding_case() -> dict[str, Any]:
    return _core_boundary_case(
        "closed-file-set-and-metadata-binding",
        (
            ("mutate-request", "PRIVACY.OUTSIDE_WRITE_ATTEMPT", None),
            ("tamper-warnings", "PROTOCOL.RESPONSE_SCHEMA", None),
        ),
    )


def _has_exact_conformance_provenance(fixture: _SyntheticFixture) -> bool:
    provenance = fixture.dataset.get("synthetic_provenance")
    if not isinstance(provenance, Mapping):
        return False
    try:
        expected = build_conformance_provenance(
            participant_count=int(fixture.dataset["participant_count"]),
            event_count=int(fixture.dataset["event_count"]),
            event_ids=tuple(fixture.dataset["event_ids"]),
        )
    except (KeyError, TypeError, ValueError):
        return False
    return provenance == expected


def _fixture_with(
    fixture: _SyntheticFixture,
    arrays: Mapping[str, Any],
    *,
    event_ids: list[str] | None = None,
    event_directions: list[str] | None = None,
) -> _SyntheticFixture:
    resolved_ids = list(fixture.dataset["event_ids"]) if event_ids is None else list(event_ids)
    resolved_directions = (
        list(fixture.dataset["event_directions"])
        if event_directions is None
        else list(event_directions)
    )
    training_arrays = {
        name: arrays[name] for name in ("train_values", "training_row_indexes", "train_group_codes")
    }
    dataset = fixture_dataset_descriptor(
        training_arrays,
        event_ids=resolved_ids,
        event_directions=resolved_directions,
        group_codebook={"0": "reference", "1": "at_risk"},
        stage_semantics_digest_value=str(fixture.dataset["stage_semantics_digest"]),
    )
    if _has_exact_conformance_provenance(fixture):
        dataset["synthetic_provenance"] = build_conformance_provenance(
            participant_count=int(dataset["participant_count"]),
            event_count=int(dataset["event_count"]),
            event_ids=tuple(resolved_ids),
        )
    if "evaluation_values" in arrays:
        semantic_versions = {
            "train_values": "synthetic-event-matrix/1",
            "training_row_indexes": "contiguous-internal-row-index/1",
            "train_group_codes": "canonical-group-code/1",
            "evaluation_values": "synthetic-fixed-evaluation-event-matrix/1",
            "evaluation_row_indexes": "contiguous-internal-row-index/1",
            "evaluation_group_codes": "canonical-group-code/1",
        }
        catalog = {
            name: array_catalog_entry(name, array, semantic_version=semantic_versions[name])
            for name, array in arrays.items()
        }
        dataset.update(
            {
                "evaluation_participant_count": int(
                    np.asarray(arrays["evaluation_values"]).shape[0]
                ),
                "evaluation_row_index_array": "evaluation_row_indexes",
                "array_catalog": catalog,
                "scientific_data_digest": structured_sha256(
                    "ebm-audit/fixture-scientific-data/1",
                    {
                        "label": "synthetic-structure-only",
                        "participant_count": dataset["participant_count"],
                        "event_ids": resolved_ids,
                        "array_catalog": catalog,
                    },
                ),
            }
        )
    digest = structured_sha256(
        "ebm-audit/public-contract-fixture/1",
        {
            "fixture_label": "project-owned-synthetic-structure-only",
            "participant_count": dataset["participant_count"],
            "event_count": dataset["event_count"],
            "scientific_data_digest": dataset["scientific_data_digest"],
        },
    )
    return _SyntheticFixture(arrays=arrays, dataset=dataset, fixture_digest=digest)


def _successful_fit(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    *,
    seed: str = _SEED_A,
    requested_outputs: list[str] | None = None,
) -> tuple[WorkerExecution, Mapping[str, Any]] | None:
    payload = _fit_payload(config, fixture, seed=seed)
    if requested_outputs is not None:
        payload["requested_outputs"] = requested_outputs
        payload["requested_outputs_digest"] = requested_outputs_digest("fit", requested_outputs)
    execution = _fit(invoker, payload, fixture)
    if execution.response["status"] != "SUCCESS":
        return None
    return execution, payload


def _missingness_and_group_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    passed = 0
    group_arrays = {name: np.array(value, copy=True) for name, value in fixture.arrays.items()}
    group_arrays["train_group_codes"][0] = 2
    group_fixture = _fixture_with(fixture, group_arrays)
    try:
        group_execution = invoker._invoke_contract_harness(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=_common_payload(config, group_fixture, command="validate"),
            arrays=group_fixture.arrays,
        )
        group_passed = (
            group_execution.response["status"] == "INVALID_INPUT"
            and group_execution.response["error"]["code"]
            == (
                "CONFORMANCE.SYNTHETIC_ONLY"
                if _has_exact_conformance_provenance(fixture)
                else "DATA.GROUP_CODE_UNDECLARED"
            )
        )
    except PrivacyViolationError:
        raise
    except Exception:
        group_passed = False
    passed += int(group_passed)

    missing_arrays = {name: np.array(value, copy=True) for name, value in fixture.arrays.items()}
    missing_arrays["train_values"][0, 0] = np.nan
    missing_mode = capabilities.get("missing_values")
    try:
        missing_fixture = _fixture_with(fixture, missing_arrays)
        missing_execution = invoker._invoke_contract_harness(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=_common_payload(config, missing_fixture, command="validate"),
            arrays=missing_fixture.arrays,
        )
        # The current protocol has no missingness-mask transport and its canonical array
        # writer rejects non-finite values. A NATIVE claim is therefore
        # impossible to exercise truthfully in this protocol version.
        missing_passed = missing_mode == "REJECT" and missing_execution.response["status"] in {
            "INVALID_INPUT",
            "UNSUPPORTED_CAPABILITY",
        }
    except ValueError:
        # The canonical request-array writer itself refuses non-finite values.
        # This proves rejection before fit, but only satisfies a REJECT claim.
        missing_passed = missing_mode == "REJECT"
    except PrivacyViolationError:
        raise
    except Exception:
        missing_passed = False
    passed += int(missing_passed)
    return _case(
        "unsupported-missingness-and-invalid-group",
        "PASS" if passed == 2 else "FAIL",
        (
            "The configured request path enforced its declared missingness and group rules."
            if passed == 2
            else "The configured request path did not enforce every missingness and group rule."
        ),
        evidence_subject="CONFIGURED_WORKER_REQUEST_BOUNDARY",
        evidence={
            "subcase_count": 2,
            "passed_subcase_count": passed,
            "declared_missingness_mode": str(missing_mode),
        },
    )


def _fixture_for_fit_outputs(
    fixture: _SyntheticFixture,
    outputs: Sequence[str],
) -> _SyntheticFixture | None:
    if any(output.startswith("evaluation_") for output in outputs):
        return _fixture_with_evaluation(fixture)
    return fixture


def _permutation_map(values: Sequence[int], size: int, *, axis_name: str) -> np.ndarray[Any, Any]:
    mapping = np.asarray(values, dtype=np.int64)
    if mapping.shape != (size,) or not np.array_equal(np.sort(mapping), np.arange(size)):
        raise ValueError(f"{axis_name} is not a complete permutation")
    return mapping


def _project_first_axis(
    array: np.ndarray[Any, Any],
    current_to_base: np.ndarray[Any, Any],
) -> np.ndarray[Any, Any]:
    if array.ndim < 1 or array.shape[0] != len(current_to_base):
        raise ValueError("a scientific array has an invalid first-axis binding")
    projected = np.empty_like(array)
    projected[current_to_base] = array
    return projected


def _project_event_order(
    array: np.ndarray[Any, Any],
    event_to_base: np.ndarray[Any, Any],
) -> np.ndarray[Any, Any]:
    if array.dtype.kind not in {"i", "u"}:
        raise ValueError("an event-order array is not integral")
    if array.size and (int(np.min(array)) < 0 or int(np.max(array)) >= len(event_to_base)):
        raise ValueError("an event-order array contains an out-of-range event index")
    return np.asarray(event_to_base[array], dtype=array.dtype)


def _private_array_roles(result: Mapping[str, Any]) -> dict[str, str]:
    reference = result["stage_model_reference"]
    if reference is None:
        return {}
    roles = {
        str(reference["reference_order_binding"]["member_name"]): "event-order",
        str(reference["final_stage_prior_binding"]["member_name"]): "unchanged",
    }
    for binding in reference["fitted_distribution_bindings"]:
        roles[str(binding["member_name"])] = "event-first-axis"
    return roles


def _array_projection_rule(
    member_name: str,
    semantic_version: str,
    private_roles: Mapping[str, str],
) -> str:
    if member_name in _CANONICAL_ARRAY_SEMANTICS:
        if semantic_version not in _CANONICAL_ARRAY_SEMANTICS[member_name]:
            raise _UnknownScientificSemantics(member_name, semantic_version)
        if member_name in _EVENT_ORDER_ARRAYS:
            return "event-order"
        if member_name in _EVENT_FIRST_AXIS_ARRAYS:
            return "event-first-axis"
        if member_name in _EVENT_BOTH_AXES_ARRAYS:
            return "event-both-axes"
        if member_name in _TRAINING_ROW_ARRAYS:
            return "training-row-index" if member_name.endswith("row_indexes") else "training-row"
        if member_name in _EVALUATION_ROW_ARRAYS:
            return (
                "evaluation-row-index" if member_name.endswith("row_indexes") else "evaluation-row"
            )
        return "unchanged"
    if member_name in private_roles:
        return private_roles[member_name]
    private_rule = _PYSAEBM_PRIVATE_SEMANTICS.get(semantic_version)
    if private_rule is not None:
        return private_rule
    raise _UnknownScientificSemantics(member_name, semantic_version)


def _project_array(
    member_name: str,
    array: Any,
    *,
    rule: str,
    event_to_base: np.ndarray[Any, Any],
    training_row_to_base: np.ndarray[Any, Any],
    evaluation_row_to_base: np.ndarray[Any, Any],
) -> np.ndarray[Any, Any]:
    value = np.asarray(array)
    if rule == "event-order":
        return _project_event_order(value, event_to_base)
    if rule == "event-first-axis":
        return _project_first_axis(value, event_to_base)
    if rule == "event-both-axes":
        if value.ndim != 2 or value.shape != (len(event_to_base), len(event_to_base)):
            raise ValueError("an event-pair array has invalid axes")
        projected = np.empty_like(value)
        projected[np.ix_(event_to_base, event_to_base)] = value
        return projected
    if rule == "training-row-index":
        if value.dtype.kind not in {"i", "u"}:
            raise ValueError("a training row-index array is not integral")
        mapped = np.asarray(training_row_to_base[value], dtype=value.dtype)
        return _project_first_axis(mapped, training_row_to_base)
    if rule == "training-row":
        return _project_first_axis(value, training_row_to_base)
    if rule == "evaluation-row-index":
        if value.dtype.kind not in {"i", "u"}:
            raise ValueError("an evaluation row-index array is not integral")
        mapped = np.asarray(evaluation_row_to_base[value], dtype=value.dtype)
        return _project_first_axis(mapped, evaluation_row_to_base)
    if rule == "evaluation-row":
        return _project_first_axis(value, evaluation_row_to_base)
    if rule == "unchanged":
        return np.array(value, copy=True)
    raise ValueError(f"unknown scientific projection rule for {member_name}")


def _project_stage_model_reference(
    result: Mapping[str, Any],
    event_to_base: np.ndarray[Any, Any],
    base_event_ids: Sequence[str],
) -> Mapping[str, Any] | None:
    reference = result["stage_model_reference"]
    if reference is None:
        return None
    return {
        "stage_model_reference_schema_version": reference["stage_model_reference_schema_version"],
        "event_ids": list(base_event_ids),
        "selection_method_id": reference["selection_method_id"],
        "reference_order_permutation": _project_event_order(
            np.asarray(reference["reference_order_permutation"], dtype=np.int64),
            event_to_base,
        ).tolist(),
        "reference_order_member": reference["reference_order_binding"]["member_name"],
        "fitted_distribution_members": [
            binding["member_name"] for binding in reference["fitted_distribution_bindings"]
        ],
        "final_stage_prior_member": reference["final_stage_prior_binding"]["member_name"],
        "final_stage_prior_fixed_point_l1_residual": reference[
            "final_stage_prior_fixed_point_l1_residual"
        ],
        "stage_semantics_digest": reference["stage_semantics_digest"],
    }


def _project_manifest(
    manifest: Mapping[str, Any],
    base_event_ids: Sequence[str],
) -> Mapping[str, Any]:
    return {
        "request_training_participants": manifest["request_training_participants"],
        "returned_training_participants": manifest["returned_training_participants"],
        "request_evaluation_participants": manifest["request_evaluation_participants"],
        "returned_evaluation_participants": manifest["returned_evaluation_participants"],
        "request_events": list(base_event_ids),
        "returned_events": list(base_event_ids),
        "worker_removed_participants": manifest["worker_removed_participants"],
        "worker_removed_events": manifest["worker_removed_events"],
        "worker_modified_cells": manifest["worker_modified_cells"],
    }


def _project_field_origins(origins: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        name: {
            "origin": origin["origin"],
            "method_id": origin["method_id"],
            "source_fields": list(origin["source_fields"]),
        }
        for name, origin in sorted(origins.items())
    }


def _scientific_projection(
    execution: WorkerExecution,
    *,
    requested_outputs: Sequence[str],
    base_event_ids: Sequence[str],
    training_row_to_base: Sequence[int],
    evaluation_row_to_base: Sequence[int],
) -> _ScientificProjection:
    if "portable_fitted_model_artifact" in requested_outputs:
        raise _UnknownScientificSemantics("backend_artifacts", "portable-fitted-model-artifact/1")
    result = execution.response["payload"]["result"]
    current_event_ids = list(result["event_ids"])
    if set(current_event_ids) != set(base_event_ids):
        raise ValueError("the returned event label set changed")
    base_event_index = {event_id: index for index, event_id in enumerate(base_event_ids)}
    event_to_base = _permutation_map(
        [base_event_index[event_id] for event_id in current_event_ids],
        len(base_event_ids),
        axis_name="event-axis mapping",
    )
    training_mapping = _permutation_map(
        training_row_to_base,
        int(result["participant_event_manifest"]["returned_training_participants"]),
        axis_name="training-row mapping",
    )
    evaluation_mapping = _permutation_map(
        evaluation_row_to_base,
        int(result["participant_event_manifest"]["returned_evaluation_participants"]),
        axis_name="evaluation-row mapping",
    )
    private_roles = _private_array_roles(result)
    projected_arrays: dict[str, np.ndarray[Any, Any]] = {}
    catalog_projection: dict[str, Any] = {}
    for member_name, array in sorted(execution.arrays.items()):
        catalog = result["array_catalog"][member_name]
        semantic_version = str(catalog["semantic_version"])
        rule = _array_projection_rule(member_name, semantic_version, private_roles)
        projected = _project_array(
            member_name,
            array,
            rule=rule,
            event_to_base=event_to_base,
            training_row_to_base=training_mapping,
            evaluation_row_to_base=evaluation_mapping,
        )
        projected_arrays[member_name] = projected
        catalog_projection[member_name] = {
            "dtype": catalog["dtype"],
            "shape": list(projected.shape),
            "semantic_version": semantic_version,
        }

    metadata = {
        "requested_outputs": list(requested_outputs),
        "event_ids": list(base_event_ids),
        "central_order_permutation": _project_event_order(
            np.asarray(result["central_order_permutation"], dtype=np.int64),
            event_to_base,
        ).tolist(),
        "stable_result_fields": {field: result[field] for field in _STABLE_FIT_RESULT_FIELDS},
        "array_catalog": catalog_projection,
        "field_origins": _project_field_origins(result["field_origins"]),
        "participant_event_manifest": _project_manifest(
            result["participant_event_manifest"], base_event_ids
        ),
        "stage_model_reference": _project_stage_model_reference(
            result, event_to_base, base_event_ids
        ),
        "warnings_record_count": execution.response["warnings_record_count"],
        "warnings_file_digest": execution.response["warnings_file_digest"],
    }
    return _ScientificProjection(metadata=metadata, arrays=projected_arrays)


def _scientific_values_equal(left: Any, right: Any) -> bool:
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        return (
            isinstance(left, Mapping)
            and isinstance(right, Mapping)
            and set(left) == set(right)
            and all(_scientific_values_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, (list, tuple)) or isinstance(right, (list, tuple)):
        return (
            isinstance(left, (list, tuple))
            and isinstance(right, (list, tuple))
            and len(left) == len(right)
            and all(
                _scientific_values_equal(left_value, right_value)
                for left_value, right_value in zip(left, right, strict=True)
            )
        )
    if isinstance(left, (float, np.floating)) or isinstance(right, (float, np.floating)):
        return (
            isinstance(left, (float, np.floating))
            and isinstance(right, (float, np.floating))
            and bool(
                np.isclose(
                    float(left),
                    float(right),
                    rtol=0.0,
                    atol=_INVARIANCE_FLOAT_ATOL,
                )
            )
        )
    return type(left) is type(right) and left == right


def _scientific_arrays_equal(
    left: Mapping[str, np.ndarray[Any, Any]],
    right: Mapping[str, np.ndarray[Any, Any]],
) -> bool:
    if set(left) != set(right):
        return False
    for member_name in left:
        left_array = left[member_name]
        right_array = right[member_name]
        if left_array.dtype != right_array.dtype or left_array.shape != right_array.shape:
            return False
        if left_array.dtype.kind == "f":
            if not np.allclose(
                left_array,
                right_array,
                rtol=0.0,
                atol=_INVARIANCE_FLOAT_ATOL,
            ):
                return False
        elif not np.array_equal(left_array, right_array):
            return False
    return True


def _scientific_projection_digest(projection: _ScientificProjection) -> str:
    """Hash one complete fitted-result projection without retaining raw arrays."""

    array_rows = [
        {
            "member_name": member_name,
            "dtype": str(array.dtype),
            "shape": list(array.shape),
            "array_bytes_sha256": exact_file_sha256(array.tobytes(order="C")),
        }
        for member_name, array in sorted(projection.arrays.items())
    ]
    return structured_sha256(
        "ebm-audit/contract-fitted-result-projection/1",
        {
            "metadata": projection.metadata,
            "ordered_array_projections": array_rows,
        },
    )


def _authenticated_fit_evidence(
    execution: WorkerExecution,
) -> tuple[str, str] | None:
    """Read the exact request and execution identities for one genuine Fit."""

    if execution.authenticated_execution is None:
        return None
    try:
        readback = _readback_authenticated_execution(
            execution.authenticated_execution,
        )
    except TypeError:
        return None
    if readback.request.get("command") != "fit":
        return None
    return (
        readback.request_readback.evidence_digest,
        readback.execution_evidence_digest,
    )


def _compare_scientific_projections(
    base_execution: WorkerExecution,
    candidate_execution: WorkerExecution,
    *,
    requested_outputs: Sequence[str],
    base_event_ids: Sequence[str],
    base_training_count: int,
    candidate_training_row_to_base: Sequence[int],
    evaluation_count: int,
) -> tuple[CaseStatus, Mapping[str, int | str | bool]]:
    identity_training = list(range(base_training_count))
    identity_evaluation = list(range(evaluation_count))
    try:
        base = _scientific_projection(
            base_execution,
            requested_outputs=requested_outputs,
            base_event_ids=base_event_ids,
            training_row_to_base=identity_training,
            evaluation_row_to_base=identity_evaluation,
        )
        candidate = _scientific_projection(
            candidate_execution,
            requested_outputs=requested_outputs,
            base_event_ids=base_event_ids,
            training_row_to_base=candidate_training_row_to_base,
            evaluation_row_to_base=identity_evaluation,
        )
    except _UnknownScientificSemantics as error:
        return (
            "UNVERIFIED",
            {
                "reason_code": "CONTRACT.UNKNOWN_SCIENTIFIC_SEMANTICS",
                "member_name": error.member_name,
                "semantic_version": error.semantic_version,
                "requested_fit_output_count": len(requested_outputs),
            },
        )
    except (KeyError, TypeError, ValueError, IndexError):
        return (
            "FAIL",
            {
                "reason_code": "CONTRACT.INVALID_SCIENTIFIC_PROJECTION",
                "requested_fit_output_count": len(requested_outputs),
            },
        )
    metadata_equal = _scientific_values_equal(base.metadata, candidate.metadata)
    arrays_equal = _scientific_arrays_equal(base.arrays, candidate.arrays)
    base_identity = _authenticated_fit_evidence(base_execution)
    candidate_identity = _authenticated_fit_evidence(candidate_execution)
    current_event_ids = candidate_execution.response["payload"]["result"]["event_ids"]
    base_event_index = {event_id: index for index, event_id in enumerate(base_event_ids)}
    try:
        event_to_base = [base_event_index[event_id] for event_id in current_event_ids]
    except (KeyError, TypeError):
        event_to_base = []
    participant_to_base = list(candidate_training_row_to_base)
    participant_bijection = sorted(participant_to_base) == list(range(base_training_count))
    event_bijection = sorted(event_to_base) == list(range(len(base_event_ids)))
    bijection_verified = participant_bijection and event_bijection
    positional_join_rejected = (
        participant_to_base != list(range(base_training_count))
        or event_to_base != list(range(len(base_event_ids)))
    )
    baseline_projection_sha256 = _scientific_projection_digest(base)
    transformed_projection_sha256 = _scientific_projection_digest(candidate)
    authenticated_result_evidence = (
        base_identity is not None and candidate_identity is not None
    )
    return (
        "PASS" if metadata_equal and arrays_equal else "FAIL",
        {
            "requested_fit_output_count": len(requested_outputs),
            "compared_array_count": len(base.arrays),
            "stable_metadata_equal": metadata_equal,
            "scientific_arrays_equal": arrays_equal,
            "float_atol": str(_INVARIANCE_FLOAT_ATOL),
            "float_rtol": "0",
            "result_evidence_kind": "ACTUAL_FITTED_RESULT_PROJECTION",
            "authenticated_result_evidence": authenticated_result_evidence,
            "baseline_fitted_result_projection_sha256": baseline_projection_sha256,
            "transformed_fitted_result_projection_sha256": (
                transformed_projection_sha256
            ),
            "baseline_authenticated_request_evidence_sha256": (
                base_identity[0] if base_identity is not None else "sha256:" + "0" * 64
            ),
            "transformed_authenticated_request_evidence_sha256": (
                candidate_identity[0]
                if candidate_identity is not None
                else "sha256:" + "0" * 64
            ),
            "baseline_authenticated_execution_evidence_sha256": (
                base_identity[1] if base_identity is not None else "sha256:" + "0" * 64
            ),
            "transformed_authenticated_execution_evidence_sha256": (
                candidate_identity[1]
                if candidate_identity is not None
                else "sha256:" + "0" * 64
            ),
            "bijection_sha256": structured_sha256(
                "ebm-audit/contract-scientific-result-bijection/1",
                {
                    "participant_to_base": participant_to_base,
                    "event_to_base": event_to_base,
                },
            ),
            "bijection_size": len(participant_to_base) + len(event_to_base),
            "bijection_verified": bijection_verified,
            "positional_join_rejected": positional_join_rejected,
        },
    )


def _row_permutation_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    algorithm: Mapping[str, Any],
) -> dict[str, Any]:
    outputs = _applicable_fit_outputs(algorithm)
    selected_fixture = _fixture_for_fit_outputs(fixture, outputs)
    if selected_fixture is None:
        return _case(
            "row-permutation-and-index-roundtrip",
            "UNVERIFIED",
            "The complete applicable output surface could not be given an evaluation fixture.",
        )
    participant_count = int(selected_fixture.dataset["participant_count"])
    permutation = np.arange(participant_count - 1, -1, -1)
    arrays = {name: np.array(value, copy=True) for name, value in selected_fixture.arrays.items()}
    arrays["train_values"] = np.asarray(selected_fixture.arrays["train_values"])[permutation]
    arrays["training_row_indexes"] = np.arange(len(permutation), dtype=np.int64)
    arrays["train_group_codes"] = np.asarray(selected_fixture.arrays["train_group_codes"])[
        permutation
    ]
    permuted = _fixture_with(selected_fixture, arrays)
    try:
        base_pair = _successful_fit(invoker, config, selected_fixture, requested_outputs=outputs)
        permuted_pair = _successful_fit(invoker, config, permuted, requested_outputs=outputs)
    except Exception as error:
        return _failure_case("row-permutation-and-index-roundtrip", error)
    if base_pair is None or permuted_pair is None:
        return _case(
            "row-permutation-and-index-roundtrip",
            "FAIL",
            "A row-permutation synthetic fit did not succeed.",
        )
    base_result = base_pair[0].response["payload"]["result"]
    permuted_result = permuted_pair[0].response["payload"]["result"]
    roundtrip = (
        base_result["participant_event_manifest"]["training_row_indexes_digest"]
        == selected_fixture.dataset["array_catalog"]["training_row_indexes"]["array_digest"]
        and permuted_result["participant_event_manifest"]["training_row_indexes_digest"]
        == permuted.dataset["array_catalog"]["training_row_indexes"]["array_digest"]
    )
    status, evidence = _compare_scientific_projections(
        base_pair[0],
        permuted_pair[0],
        requested_outputs=outputs,
        base_event_ids=selected_fixture.dataset["event_ids"],
        base_training_count=participant_count,
        candidate_training_row_to_base=permutation.tolist(),
        evaluation_count=int(selected_fixture.dataset["evaluation_participant_count"]),
    )
    if status == "PASS" and not roundtrip:
        status = "FAIL"
    evidence = {**evidence, "exact_row_index_binding": roundtrip}
    return _case(
        "row-permutation-and-index-roundtrip",
        status,
        (
            "Row permutation preserved every applicable scientific output after "
            "exact inverse mapping."
            if status == "PASS"
            else "An applicable scientific output has unknown row semantics, so "
            "invariance is unverified."
            if status == "UNVERIFIED"
            else "Row permutation changed a scientific output or broke internal-index binding."
        ),
        evidence=evidence,
    )


def _feature_remapping_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    algorithm: Mapping[str, Any],
) -> dict[str, Any]:
    outputs = _applicable_fit_outputs(algorithm)
    selected_fixture = _fixture_for_fit_outputs(fixture, outputs)
    if selected_fixture is None:
        return _case(
            "feature-column-permutation-and-label-remap",
            "UNVERIFIED",
            "The complete applicable output surface could not be given an evaluation fixture.",
        )
    permutation = np.arange(int(selected_fixture.dataset["event_count"]) - 1, -1, -1)
    arrays = {name: np.array(value, copy=True) for name, value in selected_fixture.arrays.items()}
    arrays["train_values"] = np.asarray(selected_fixture.arrays["train_values"])[:, permutation]
    if "evaluation_values" in arrays:
        arrays["evaluation_values"] = np.asarray(selected_fixture.arrays["evaluation_values"])[
            :, permutation
        ]
    event_ids = [selected_fixture.dataset["event_ids"][index] for index in permutation]
    directions = [selected_fixture.dataset["event_directions"][index] for index in permutation]
    remapped = _fixture_with(
        selected_fixture,
        arrays,
        event_ids=event_ids,
        event_directions=directions,
    )
    try:
        base_pair = _successful_fit(invoker, config, selected_fixture, requested_outputs=outputs)
        remapped_pair = _successful_fit(invoker, config, remapped, requested_outputs=outputs)
    except Exception as error:
        return _failure_case("feature-column-permutation-and-label-remap", error)
    if base_pair is None or remapped_pair is None:
        return _case(
            "feature-column-permutation-and-label-remap",
            "FAIL",
            "A feature-remapping synthetic fit did not succeed.",
        )
    status, evidence = _compare_scientific_projections(
        base_pair[0],
        remapped_pair[0],
        requested_outputs=outputs,
        base_event_ids=selected_fixture.dataset["event_ids"],
        base_training_count=int(selected_fixture.dataset["participant_count"]),
        candidate_training_row_to_base=list(
            range(int(selected_fixture.dataset["participant_count"]))
        ),
        evaluation_count=int(selected_fixture.dataset["evaluation_participant_count"]),
    )
    return _case(
        "feature-column-permutation-and-label-remap",
        status,
        (
            "Column permutation preserved every applicable scientific output after "
            "exact event remapping."
            if status == "PASS"
            else "An applicable scientific output has unknown event semantics, so "
            "invariance is unverified."
            if status == "UNVERIFIED"
            else "Column permutation changed a scientific output after exact event remapping."
        ),
        evidence=evidence,
    )


def _complete_result_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    try:
        pair = _successful_fit(invoker, config, fixture)
    except Exception as error:
        return _failure_case("complete-result-invariant-matrix", error)
    if pair is None:
        return _case(
            "complete-result-invariant-matrix",
            "FAIL",
            "The result-invariant synthetic fit did not succeed.",
        )
    execution, _payload = pair
    result = execution.response["payload"]["result"]
    event_count = int(fixture.dataset["event_count"])
    permutation = list(result["central_order_permutation"])
    array = execution.arrays.get("central_order_permutation")
    valid = (
        result["event_ids"] == fixture.dataset["event_ids"]
        and sorted(permutation) == list(range(event_count))
        and array is not None
        and list(np.asarray(array).tolist()) == permutation
        and result["array_catalog"]["central_order_permutation"]
        == array_catalog_entry(
            "central_order_permutation",
            array,
            semantic_version="event-index-at-position/1",
        )
    )
    return _case(
        "complete-result-invariant-matrix",
        "PASS" if valid else "FAIL",
        (
            "Every returned central-order result invariant passed."
            if valid
            else "A returned central-order result invariant failed."
        ),
        evidence={"returned_array_count": len(execution.arrays)},
    )


def _accounting_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    try:
        validation = invoker._invoke_contract_harness(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=_common_payload(config, fixture, command="validate"),
            arrays=fixture.arrays,
        )
        pair = _successful_fit(invoker, config, fixture)
    except Exception as error:
        return _failure_case("participant-event-cell-accounting", error)
    if validation.response["status"] != "SUCCESS" or pair is None:
        return _case(
            "participant-event-cell-accounting",
            "FAIL",
            "The accounting synthetic commands did not succeed.",
        )
    predicted = validation.response["payload"]["predicted_accounting"]
    manifest = pair[0].response["payload"]["result"]["participant_event_manifest"]
    participants = int(fixture.dataset["participant_count"])
    events = int(fixture.dataset["event_count"])
    valid = (
        predicted["input_participants"] == predicted["output_participants"] == participants
        and predicted["input_events"] == predicted["output_events"] == events
        and predicted["removed_participants"] == 0
        and predicted["removed_events"] == 0
        and predicted["masked_cells"] == 0
        and predicted["transformed_cells"] == 0
        and manifest["request_training_participants"]
        == manifest["returned_training_participants"]
        == participants
        and manifest["request_events"] == manifest["returned_events"]
        and manifest["worker_removed_participants"] == []
        and manifest["worker_removed_events"] == []
        and manifest["worker_modified_cells"] == []
    )
    return _case(
        "participant-event-cell-accounting",
        "PASS" if valid else "FAIL",
        (
            "Participant, event, and cell accounting is one-to-one for the synthetic fixture."
            if valid
            else "Participant, event, or cell accounting is not one-to-one."
        ),
        evidence={"participant_count": participants, "event_count": events},
    )


def _fixture_raw_value_canary(fixture: _SyntheticFixture) -> float | None:
    try:
        values = np.asarray(fixture.arrays["train_values"])
        finite_values = values[np.isfinite(values)]
    except Exception:
        return None
    if int(np.count_nonzero(finite_values == _RAW_VALUE_CANARY)) > 0:
        return _RAW_VALUE_CANARY
    unique_values, counts = np.unique(finite_values, return_counts=True)
    unique_finite_values = unique_values[counts == 1]
    if unique_finite_values.size == 0:
        return None
    return float(unique_finite_values[0])


def _raw_value_canary_array_match_count(
    arrays: Mapping[str, Any],
    canary: float = _RAW_VALUE_CANARY,
) -> int:
    try:
        return sum(
            int(np.count_nonzero(np.asarray(array) == canary))
            for array in arrays.values()
        )
    except Exception:
        return -1


def _privacy_canary_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    raw_value_canary = _fixture_raw_value_canary(fixture)
    if raw_value_canary is None:
        return _case(
            "private-identifier-and-raw-value-canary-scan",
            "FAIL",
            "The synthetic fixture has no exact finite raw-value canary.",
        )
    input_canary_match_count = int(
        np.count_nonzero(
            np.asarray(fixture.arrays["train_values"]) == raw_value_canary
        )
    )
    identifier_rejected = False
    identifier_payload = _fit_payload(config, fixture, seed=_SEED_A)
    identifier_payload["participant_id"] = _PRIVATE_ID_CANARY
    try:
        _fit(invoker, identifier_payload, fixture)
    except PrivacyViolationError as error:
        if error.code != "PRIVACY.DIRECT_IDENTIFIER_FIELD":
            raise
        identifier_rejected = True
    except Exception:
        identifier_rejected = False
    try:
        pair = _successful_fit(invoker, config, fixture)
    except Exception as error:
        return _failure_case("private-identifier-and-raw-value-canary-scan", error)
    if pair is None:
        return _case(
            "private-identifier-and-raw-value-canary-scan",
            "FAIL",
            "The privacy-canary synthetic fit did not succeed.",
        )
    execution, _payload = pair
    retained = canonical_json_bytes(execution.response)
    array_canary_match_count = _raw_value_canary_array_match_count(
        execution.arrays,
        raw_value_canary,
    )
    canaries_absent = (
        input_canary_match_count > 0
        and str(raw_value_canary).encode("ascii") not in retained
        and array_canary_match_count == 0
        and not hasattr(execution.stdout, "content")
        and not hasattr(execution.stderr, "content")
    )
    passed = identifier_rejected and canaries_absent
    return _case(
        "private-identifier-and-raw-value-canary-scan",
        "PASS" if passed else "FAIL",
        (
            "The core rejected a synthetic direct identifier and the configured worker's "
            "retained response, every returned array, and diagnostics omitted the synthetic "
            "raw-value canary."
            if passed
            else "A synthetic privacy canary boundary did not hold."
        ),
        evidence_subject="CONFIGURED_WORKER_AND_AUDITOR_CORE_BOUNDARIES",
        evidence={
            "synthetic_canary_count": 2,
            "input_raw_value_canary_match_count": input_canary_match_count,
            "direct_identifier_rejected_before_worker": identifier_rejected,
            "returned_array_count_scanned": len(execution.arrays),
            "raw_value_array_match_count": array_canary_match_count,
            "retained_diagnostic_content": False,
        },
    )


def _full_range_seed_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
) -> dict[str, Any]:
    seeds = ("0000000000000000", "ffffffffffffffff")
    passed = 0
    for seed in seeds:
        try:
            pair = _successful_fit(invoker, config, fixture, seed=seed)
            passed += int(
                pair is not None
                and pair[0].response["payload"]["result"]["seed"] == seed
                and pair[1]["seed"] == seed
            )
        except PrivacyViolationError:
            raise
        except Exception:
            continue
    return _case(
        "full-range-canonical-seeds",
        "PASS" if passed == len(seeds) else "FAIL",
        (
            "Both canonical UInt64 boundary seeds were bound and completed."
            if passed == len(seeds)
            else "A canonical UInt64 boundary seed was not bound and completed."
        ),
        evidence={"subcase_count": len(seeds), "passed_subcase_count": passed},
    )


def _stage_reordering_case(
    algorithm: Mapping[str, Any],
) -> dict[str, Any]:
    commands = set(algorithm["supported_commands"])
    capabilities = algorithm["capabilities"]
    applicable = (
        "stage" in commands
        and capabilities.get("portable_fitted_model_artifact") is True
        and (
            capabilities.get("participant_stage_posterior") is True
            or capabilities.get("hard_stages") is True
        )
    )
    if not applicable:
        return _not_applicable(
            "reordered-stage-row-rejection",
            "The selected algorithm does not advertise the fitted-artifact staging surface.",
        )
    return _case(
        "reordered-stage-row-rejection",
        "UNVERIFIED",
        "The algorithm advertises staging, but this first harness has no portable model fixture.",
    )


def _sampler_indexing_case(
    invoker: WorkerInvoker,
    config: WorkerConfig,
    fixture: _SyntheticFixture,
    capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    output_by_capability = {
        "order_samples": "order_samples",
        "likelihood_trace": "likelihood_trace",
        "accepted_transition_diagnostics": "accepted_transition_diagnostics",
    }
    outputs = [
        output
        for capability, output in output_by_capability.items()
        if capabilities.get(capability) is True
    ]
    if not outputs:
        return _not_applicable(
            "sampler-off-by-one-and-convergence-finalisation",
            "The selected algorithm declares no canonical sampler-history capability.",
        )
    try:
        pair = _successful_fit(
            invoker,
            config,
            fixture,
            requested_outputs=["central_order", *outputs],
        )
    except Exception as error:
        return _failure_case("sampler-off-by-one-and-convergence-finalisation", error)
    if pair is None:
        return _case(
            "sampler-off-by-one-and-convergence-finalisation",
            "FAIL",
            "The sampler-indexing synthetic fit did not succeed.",
        )
    result = pair[0].response["payload"]["result"]
    counts = tuple(
        result[field]
        for field in (
            "raw_iteration_count",
            "burn_in_count",
            "thinning_interval",
            "postburn_unthinned_state_count",
            "retained_state_count",
        )
    )
    if any(value is None for value in counts):
        return _case(
            "sampler-off-by-one-and-convergence-finalisation",
            "FAIL",
            "A declared sampler-history result omitted its indexing counts.",
        )
    raw, burn, thin, postburn, retained = (int(value) for value in counts)
    expected_postburn = raw - burn
    expected_retained = ((raw - 1 - burn) // thin) + 1
    valid = (
        raw >= 1
        and 0 <= burn < raw
        and thin >= 1
        and postburn == expected_postburn
        and retained == expected_retained
    )
    return _case(
        "sampler-off-by-one-and-convergence-finalisation",
        "PASS" if valid else "FAIL",
        (
            "The returned sampler counts satisfy the canonical burn and thinning equations."
            if valid
            else "The returned sampler counts violate the canonical burn or thinning equations."
        ),
        evidence={"requested_sampler_output_count": len(outputs)},
    )


def _capability_applicability(algorithm: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if algorithm is None:
        return []
    capabilities = algorithm["capabilities"]
    rows = []
    for name in sorted(key for key, value in capabilities.items() if isinstance(value, bool)):
        rows.append(
            {
                "capability_id": name,
                "declared": capabilities[name],
                "disposition": ("APPLICABLE" if capabilities[name] else "NOT_APPLICABLE"),
            }
        )
    if "stage" not in algorithm["supported_commands"]:
        rows.append(
            {
                "capability_id": "stage-command",
                "declared": False,
                "disposition": "NOT_APPLICABLE",
            }
        )
    return rows


def _aggregate_status(cases: Sequence[Mapping[str, Any]]) -> CaseStatus:
    statuses = [row["status"] for row in cases if row["required"]]
    if "FAIL" in statuses:
        return "FAIL"
    if "UNVERIFIED" in statuses:
        return "UNVERIFIED"
    if "UNSUPPORTED" in statuses:
        return "UNSUPPORTED"
    return "PASS"


def _receipt(
    config: WorkerConfig,
    cases: list[dict[str, Any]],
    *,
    describe_execution: WorkerExecution | None = None,
    algorithm: Mapping[str, Any] | None = None,
    fixture: _SyntheticFixture | None = None,
) -> dict[str, Any]:
    identity: Mapping[str, Any] | None = None
    if describe_execution is not None:
        observed = describe_execution.response["backend_identity"]
        identity = {
            "backend_identity_digest": backend_identity_digest(observed),
            "adapter_id": observed["adapter_id"],
            "worker_executable_digest": observed["worker_executable_digest"],
            "worker_code_digest": observed["worker_code_digest"],
            "backend_source_digest": observed["backend_source_digest"],
            "environment_digest": observed["environment_digest"],
            "capabilities_digest": (
                None if algorithm is None else algorithm["capabilities_digest"]
            ),
        }
    return {
        "receipt_schema_version": "ebm-audit-public-contract-test/2.0",
        "aggregate_status": _aggregate_status(cases),
        "protocol_version": "ebm-audit-worker/v2",
        "algorithm_id": config.algorithm_id,
        "settings_digest": settings_digest(config.settings),
        "fixture_label": "project-owned-synthetic-structure-only",
        "fixture_digest": None if fixture is None else fixture.fixture_digest,
        "worker_identity": identity,
        "capability_applicability": _capability_applicability(algorithm),
        "cases": cases,
        "limitations": [
            "This receipt covers the configured algorithm's applicable synthetic surface.",
            "It is not scientific backend acceptance or evidence about participant data.",
            "UNVERIFIED and UNSUPPORTED cases are never counted as passes.",
            (
                "Core adversary cases prove auditor rejection boundaries, not "
                "configured-worker behavior."
            ),
            "Containment evidence does not establish hostile-code read isolation.",
        ],
    }


def run_contract_test(
    config: WorkerConfig,
    *,
    timeout_seconds: float = 30.0,
) -> Mapping[str, Any]:
    """Run the implemented public cases and retain every missing case honestly."""

    invoker = WorkerInvoker(
        config.worker,
        timeout_seconds=timeout_seconds,
        expected_identity=config.expected_identity,
    )
    cases: list[dict[str, Any]] = []
    describe_execution: WorkerExecution | None
    algorithm: Mapping[str, Any] | None
    description_capability: object | None = None
    try:
        describe_execution, description_capability = (
            invoker._open_contract_harness_description(config.expected_identity)
        )
        response = describe_execution.response
        if response["status"] != "SUCCESS":
            cases.append(_case("describe-schema-and-algorithm", "FAIL", "Worker describe failed."))
            describe_execution = None
            algorithm = None
            description: Mapping[str, Any] = {}
        else:
            description = response["payload"]["result"]
            command_surface_valid = _description_uses_v2_command_surface(description)
            algorithm = (
                _find_algorithm(description, config.algorithm_id) if command_surface_valid else None
            )
            cases.append(
                _case(
                    "describe-schema-and-algorithm",
                    "PASS" if algorithm is not None else "FAIL",
                    (
                        "The closed worker description contains the configured algorithm."
                        if algorithm is not None
                        else (
                            "The worker advertised a command outside the exact v2 surface."
                            if not command_surface_valid
                            else "The configured algorithm is absent from the worker description."
                        )
                    ),
                    evidence={
                        "supported_algorithm_count": len(description["supported_algorithms"])
                    },
                )
            )
    except Exception as error:
        cases.append(_failure_case("describe-schema-and-algorithm", error))
        describe_execution = None
        algorithm = None
        description = {}

    fixture = _synthetic_fixture(algorithm) if algorithm is not None else None
    identity_verified = False
    contract_invoker: WorkerInvoker | _PinnedContractHarnessInvoker = invoker
    if describe_execution is not None and algorithm is not None:
        identity_case = _identity_case(invoker, config, describe_execution, algorithm)
        cases.append(identity_case)
        identity_verified = (
            identity_case["status"] == "PASS" and description_capability is not None
        )
        if identity_verified:
            assert description_capability is not None
            contract_invoker = _PinnedContractHarnessInvoker(
                invoker=invoker,
                description_capability=description_capability,
            )
            cases.append(_self_test_case(contract_invoker, description))  # type: ignore[arg-type]
        else:
            cases.append(
                _case(
                    "worker-self-test",
                    "UNVERIFIED",
                    "Self-test did not run without a verified immutable identity pin.",
                )
            )
    else:
        cases.extend(
            [
                _case(
                    "expected-immutable-identity",
                    "UNVERIFIED",
                    "Identity expectation could not run without a valid description.",
                ),
                _case(
                    "worker-self-test",
                    "UNVERIFIED",
                    "Self-test could not run without a valid description.",
                ),
            ]
        )

    commands = set(algorithm.get("supported_commands", [])) if algorithm is not None else set()
    capabilities = algorithm.get("capabilities", {}) if algorithm is not None else {}
    fit_route_available = (
        identity_verified
        and config.expected_identity is not None
        and fixture is not None
        and {"validate", "fit"}.issubset(commands)
        and isinstance(capabilities, Mapping)
        and capabilities.get("strict_single_sequence") is True
        and capabilities.get("offline_execution") is True
        and capabilities.get("deterministic_seed") is True
    )
    if fit_route_available and fixture is not None and algorithm is not None:
        cases.extend(
            [
                _validate_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _same_seed_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _different_seed_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _unknown_algorithm_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _invalid_setting_case(contract_invoker, config, fixture, algorithm),  # type: ignore[arg-type]
                _unavailable_output_case(contract_invoker, config, fixture, algorithm),  # type: ignore[arg-type]
                _declared_fit_output_surface_case(
                    contract_invoker,  # type: ignore[arg-type]
                    config,
                    fixture,
                    algorithm,
                ),
                _missingness_and_group_case(
                    contract_invoker,  # type: ignore[arg-type]
                    config,
                    fixture,
                    capabilities,
                ),
                _row_permutation_case(contract_invoker, config, fixture, algorithm),  # type: ignore[arg-type]
                _feature_remapping_case(contract_invoker, config, fixture, algorithm),  # type: ignore[arg-type]
                _complete_result_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _accounting_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _privacy_canary_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _full_range_seed_case(contract_invoker, config, fixture),  # type: ignore[arg-type]
                _sampler_indexing_case(
                    contract_invoker,  # type: ignore[arg-type]
                    config,
                    fixture,
                    capabilities,
                ),
            ]
        )
    else:
        mandatory_route_claimed = (
            algorithm is not None
            and {"validate", "fit"}.issubset(commands)
            and isinstance(capabilities, Mapping)
            and capabilities.get("strict_single_sequence") is True
            and capabilities.get("offline_execution") is True
            and capabilities.get("deterministic_seed") is True
        )
        unavailable_status: CaseStatus = (
            "UNVERIFIED" if mandatory_route_claimed or algorithm is None else "UNSUPPORTED"
        )
        unavailable_message = (
            "The mandatory synthetic route did not run without a verified immutable "
            "worker identity pin."
            if algorithm is not None and not identity_verified
            else "The selected algorithm advertises the mandatory route, but the bounded "
            "synthetic fixture could not be constructed."
            if unavailable_status == "UNVERIFIED" and algorithm is not None
            else "The selected algorithm does not provide the mandatory synthetic route."
            if unavailable_status == "UNSUPPORTED"
            else "The mandatory synthetic route could not run without a valid description."
        )
        for case_id in (
            "finite-synthetic-validate",
            "fit-same-seed-repeatability",
            "fit-different-seed-no-cache",
            "unknown-algorithm-rejected",
            "unknown-setting-rejected",
            "unavailable-output-rejected",
            "declared-fit-output-surface",
            "unsupported-missingness-and-invalid-group",
            "row-permutation-and-index-roundtrip",
            "feature-column-permutation-and-label-remap",
            "complete-result-invariant-matrix",
            "participant-event-cell-accounting",
            "private-identifier-and-raw-value-canary-scan",
            "full-range-canonical-seeds",
        ):
            cases.append(
                _case(
                    case_id,
                    unavailable_status,
                    unavailable_message,
                )
            )
        sampler_capabilities = (
            "order_samples",
            "likelihood_trace",
            "accepted_transition_diagnostics",
        )
        if isinstance(capabilities, Mapping) and any(
            capabilities.get(name) is True for name in sampler_capabilities
        ):
            cases.append(
                _case(
                    "sampler-off-by-one-and-convergence-finalisation",
                    unavailable_status,
                    unavailable_message,
                )
            )
        else:
            cases.append(
                _not_applicable(
                    "sampler-off-by-one-and-convergence-finalisation",
                    "The selected algorithm declares no canonical sampler-history capability.",
                )
            )
    if algorithm is not None:
        cases.append(_stage_reordering_case(algorithm))
    else:
        cases.append(
            _not_applicable(
                "reordered-stage-row-rejection",
                "No configured algorithm description was available.",
            )
        )
    cases.extend(_core_boundary_cases())
    cases.append(_closed_file_binding_case())
    receipt = _receipt(
        config,
        cases,
        describe_execution=describe_execution,
        algorithm=algorithm,
        fixture=fixture,
    )
    if description_capability is not None:
        invoker._close_contract_harness_description(description_capability)
    return receipt


__all__ = ["CaseStatus", "run_contract_test"]
