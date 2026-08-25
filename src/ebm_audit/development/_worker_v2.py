from __future__ import annotations

import copy
import errno
import hashlib
import math
import os
import stat
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import numpy as np
from numpy.typing import NDArray

from ebm_audit.adapters import (
    AuthenticatedWorkerDescription,
    AuthenticatedWorkerExecutionEvidence,
    WorkerCommand,
    WorkerInvoker,
    describe_worker,
)
from ebm_audit.adapters.invocation import (
    _core_code_digest,
    _readback_authenticated_execution,
)
from ebm_audit.adapters.requests import (
    build_execution_input_projection,
    build_wire_scientific_payload,
)
from ebm_audit.metrics import ConvergenceChainInput, derive_convergence_record
from ebm_audit.metrics.kde_profile_transition_quality import (
    KdeProfileChainInput,
    calculate_kde_profile_transition_quality,
)
from ebm_audit.oracle.kde_target import solve_exact_kde_target
from ebm_audit.protocol import (
    canonical_json_bytes,
    domain_separated_bytes_sha256,
    exact_file_sha256_path,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.protocol.identities import (
    authenticated_execution_evidence_digest,
    authenticated_request_evidence_digest,
    execution_input_projection_digest,
    scientific_request_projection,
    worker_fit_payload_digest,
)
from ebm_audit.schema import validate_instance
from ebm_audit.workers.arrays import array_catalog_entry, write_deterministic_npz

GMM_MEMBER = "backend.kde-ebm.gmm-parameters"
TARGET_POSITION_MEMBER = "backend.kde-ebm.exact-fixed-target-position-probabilities"
TARGET_PAIRWISE_MEMBER = "backend.kde-ebm.exact-fixed-target-pairwise-precedence"
REFERENCE_DOMAIN = "ebm-audit/exact-fixed-target-reference/1"
MATRIX_DOMAIN = "ebm-audit/kde-ebm-native-probability-matrix/1"
SEMANTIC_FAILURE_CODE = "PROTOCOL.RESPONSE_SEMANTICS"
CALLBACK_FAILURE_CODE = "BACKEND.CALLBACK_FAILED"
PAYLOAD_FINALIZATION_FAILURE_CODE = "BACKEND.FIT_PAYLOAD_FINALIZATION_FAILED"
CALLBACK_EXCEPTION_CLASS_IDS = frozenset(
    {
        "BUILTINS_ASSERTION_ERROR",
        "BUILTINS_KEY_ERROR",
        "BUILTINS_MEMORY_ERROR",
        "BUILTINS_OS_ERROR",
        "BUILTINS_RUNTIME_ERROR",
        "BUILTINS_TYPE_ERROR",
        "BUILTINS_VALUE_ERROR",
        "UNLISTED_EXCEPTION",
    }
)
CALLBACK_SOURCE_IDS = frozenset(
    {
        "EBM_AUDIT_WORKERS_STRUCTURAL",
        "KDE_EBM_MODEL",
        "UNLISTED_CALLBACK_SOURCE",
    }
)
SEMANTIC_RULES = frozenset(
    {
        "ACCOUNTING.EVALUATION_COUNT",
        "ACCOUNTING.EVALUATION_INDEX_DIGEST",
        "ACCOUNTING.MANIFEST",
        "ACCOUNTING.PREDICTED_MISMATCH",
        "ACCOUNTING.TRAINING_INDEX_DIGEST",
        "ACCOUNTING.UNUSED_EVALUATION_INDEX",
        "ALGORITHM.DESCRIPTION_REQUIRED",
        "ARRAY.DTYPE",
        "ARRAY.NONFINITE",
        "ARRAY.SHAPE",
        "ARTIFACT.OWNER_BINDING",
        "ARTIFACT.REQUEST_PRESENCE",
        "CAPABILITY.COMPONENT_APPLICABILITY",
        "CAPABILITY.REQUESTED_OUTPUT_UNAVAILABLE",
        "CAPABILITY.STAGE_UNAVAILABLE",
        "CHAIN.LIKELIHOOD_INDEXING",
        "CHAIN.LIKELIHOOD_PAIR",
        "CHAIN.LIKELIHOOD_WITHOUT_SCHEDULE",
        "CHAIN.ORDER_SAMPLE_PAIR",
        "CHAIN.ORDER_SAMPLE_WITHOUT_SCHEDULE",
        "CHAIN.PARTIAL_SCHEDULE",
        "CHAIN.POSTBURN_COUNT",
        "CHAIN.RETAINED_COUNT",
        "CHAIN.SCHEDULE_RANGE",
        "CHAIN.THINNED_LIKELIHOOD_MISMATCH",
        "CHAIN.THINNED_ORDER_MISMATCH",
        "CHAIN.TRANSITION_COUNT",
        "CHAIN.TRANSITION_FRACTION",
        "CHAIN.TRANSITION_MASK",
        "CHAIN.TRANSITION_WITHOUT_SCHEDULE",
        "CHAIN.UNREQUESTED_LIKELIHOOD_INDEX",
        "CHAIN.UNREQUESTED_TRANSITION_SCALAR",
        "COMMAND.V2_ALGORITHM_SURFACE",
        "COMMAND.V2_WORKER_SURFACE",
        "EVENT.REQUEST_RESULT_MAPPING",
        "EXACT_TARGET.ARRAY_SET",
        "EXACT_TARGET.EVEN_MASS",
        "EXACT_TARGET.FIELD_ORIGIN_BINDING",
        "EXACT_TARGET.PAIRWISE",
        "EXACT_TARGET.POSITION",
        "EXACT_TARGET.REFERENCE_ARRAY_BINDING",
        "EXACT_TARGET.REFERENCE_DIGEST",
        "EXACT_TARGET.REFERENCE_OWNER",
        "EXACT_TARGET.REFERENCE_REQUIRED",
        "EXACT_TARGET.UNREQUESTED_ARRAY",
        "EXACT_TARGET.UNREQUESTED_REFERENCE",
        "ORDER.JSON_ARRAY_MISMATCH",
        "ORDER.NOT_PERMUTATION",
        "ORDER.RETAINED_MODE_MISMATCH",
        "OUTPUT.ARRAY_PRESENCE",
        "OUTPUT.CENTRAL_ORDER_REQUIRED",
        "OUTPUT.DUPLICATE",
        "OUTPUT.FIELD_ORIGIN_SET",
        "OUTPUT.FITTED_DISTRIBUTION_MISSING",
        "OUTPUT.NOT_REGISTERED_FOR_COMMAND",
        "OUTPUT.STAGE_OUTPUT_REQUIRED",
        "OUTPUT.UNREQUESTED_PRIVATE_ARRAY",
        "OUTPUT.WORKER_ORIGIN",
        "PAIRWISE.CHAIN_DERIVATION",
        "PAIRWISE.DIAGONAL",
        "PAIRWISE.NOT_COMPLEMENTARY",
        "PAIRWISE.OUT_OF_RANGE",
        "POSITION.ABOVE_ONE",
        "POSITION.CHAIN_DERIVATION",
        "POSITION.NEGATIVE",
        "POSITION.NOT_DOUBLY_NORMALIZED",
        "REQUEST.EXECUTION_INPUT_PROJECTION",
        "ROW_INDEX.REQUEST_NOT_CONTIGUOUS",
        "ROW_INDEX.RESPONSE_MISMATCH",
        "SEMANTICS.INVALID_STRUCTURE",
        "STAGE.ARTIFACT_REFERENCE_BINDING",
        "STAGE.EMPTY_EVALUATION_COHORT",
        "STAGE.EXPECTED_OUT_OF_RANGE",
        "STAGE.EXPECTED_POSTERIOR_MISMATCH",
        "STAGE.FIELD_ORIGIN_BINDING",
        "STAGE.FINAL_PRIOR_NOT_CONVERGED",
        "STAGE.FINAL_PRIOR_NOT_NORMALIZED",
        "STAGE.FINAL_PRIOR_NOT_POSITIVE",
        "STAGE.FITTED_AXIS",
        "STAGE.HARD_STAGE_INCOMPLETE",
        "STAGE.MAP_OUT_OF_RANGE",
        "STAGE.MAP_POSTERIOR_MISMATCH",
        "STAGE.MAP_TIE_MISMATCH",
        "STAGE.POSTERIOR_ABOVE_ONE",
        "STAGE.POSTERIOR_NEGATIVE",
        "STAGE.POSTERIOR_NOT_NORMALIZED",
        "STAGE.REFERENCE_ARRAY_BINDING",
        "STAGE.REFERENCE_BINDING_DUPLICATE",
        "STAGE.REFERENCE_DIGEST",
        "STAGE.REFERENCE_ORDER",
        "STAGE.REFERENCE_ORDER_ARRAY",
        "STAGE.REFERENCE_OWNER",
        "STAGE.REFERENCE_REQUIRED",
        "STAGE.REFERENCE_WITHOUT_OUTPUT",
        "STAGE.SEMANTICS_DEFINITION",
        "STAGE.SEMANTICS_OWNER",
        "STAGE.TIE_MASK_EMPTY",
        "STAGE.TIE_POSTERIOR_MISMATCH",
        "STAGE.UNAVAILABLE",
        "VALIDATION.FIT_PERMISSION_MISMATCH",
        "VALIDATION.SUCCESS_WITH_ERROR",
    }
)


class WorkerV2DevelopmentError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Authenticated synthetic Worker-v2 evidence is invalid.")


def _invalid(code: str) -> WorkerV2DevelopmentError:
    return WorkerV2DevelopmentError(code)


class WorkerV2NegativeResponseError(WorkerV2DevelopmentError):
    """An authenticated non-success response with a safe Worker failure code."""

    def __init__(
        self,
        code: str,
        callback_failure: Mapping[str, Any] | None = None,
        payload_finalization_failure: Mapping[str, Any] | None = None,
    ) -> None:
        self.callback_failure = (
            None if callback_failure is None else copy.deepcopy(dict(callback_failure))
        )
        self.payload_finalization_failure = (
            None
            if payload_finalization_failure is None
            else copy.deepcopy(dict(payload_finalization_failure))
        )
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ExpectedProjectionContext:
    """Immutable canonical-builder inputs owned outside the scientific request."""

    core_code_digest: str
    _selected_backend_identity: bytes
    _capabilities: bytes
    _stage_semantics_definition: bytes
    _adapter_semantics: bytes

    @staticmethod
    def _mapping(raw: bytes) -> Mapping[str, Any]:
        value = strict_json_loads(raw)
        if type(value) is not dict:
            raise TypeError("Expected projection context member is not a mapping.")
        return cast(dict[str, Any], value)

    @property
    def selected_backend_identity(self) -> Mapping[str, Any]:
        return self._mapping(self._selected_backend_identity)

    @property
    def capabilities(self) -> Mapping[str, Any]:
        return self._mapping(self._capabilities)

    @property
    def stage_semantics_definition(self) -> Mapping[str, Any]:
        return self._mapping(self._stage_semantics_definition)

    @property
    def adapter_semantics(self) -> Mapping[str, Any]:
        return self._mapping(self._adapter_semantics)


def expected_projection_context(
    *,
    core_code_digest: str,
    selected_backend_identity: Mapping[str, Any],
    capabilities: Mapping[str, Any],
    stage_semantics_definition: Mapping[str, Any],
    adapter_semantics: Mapping[str, Any],
) -> ExpectedProjectionContext:
    return ExpectedProjectionContext(
        core_code_digest=core_code_digest,
        _selected_backend_identity=canonical_json_bytes(selected_backend_identity),
        _capabilities=canonical_json_bytes(capabilities),
        _stage_semantics_definition=canonical_json_bytes(stage_semantics_definition),
        _adapter_semantics=canonical_json_bytes(adapter_semantics),
    )


def _description_projection_context(
    description: AuthenticatedWorkerDescription,
) -> ExpectedProjectionContext:
    algorithm_id = description.expected_identity["selected_algorithm_id"]
    algorithms = [
        algorithm
        for algorithm in description.supported_algorithms
        if algorithm.get("algorithm_id") == algorithm_id
    ]
    if len(algorithms) != 1:
        raise _invalid("WORKER_V2.IDENTITY")
    algorithm = algorithms[0]
    selected_backend_identity = dict(description.backend_identity)
    selected_backend_identity["algorithm_id"] = algorithm_id
    return expected_projection_context(
        core_code_digest=_core_code_digest(),
        selected_backend_identity=selected_backend_identity,
        capabilities=cast(Mapping[str, Any], algorithm["capabilities"]),
        stage_semantics_definition=cast(Mapping[str, Any], algorithm["stage_semantics_definition"]),
        adapter_semantics=cast(Mapping[str, Any], algorithm["adapter_semantics"]),
    )


def _request_file_projection(arrays: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not arrays:
        return {}
    with tempfile.TemporaryDirectory(prefix="ebm-audit-projection-") as temporary_name:
        path = Path(temporary_name) / "values.npz"
        write_deterministic_npz(path, arrays)
        return {
            "values.npz": {
                "byte_length": path.stat().st_size,
                "sha256": exact_file_sha256_path(path),
            }
        }


def safe_error_code(error: BaseException) -> str:
    code = getattr(error, "code", None)
    return (
        str(code)
        if isinstance(code, str)
        else "KDE_PROFILE.UNEXPECTED_" + type(error).__name__.upper()
    )


def safe_semantic_rule(error: BaseException) -> str | None:
    if safe_error_code(error) != SEMANTIC_FAILURE_CODE:
        return None
    details = getattr(error, "details", None)
    rule = details.get("semantic_rule") if isinstance(details, Mapping) else None
    return rule if type(rule) is str and rule in SEMANTIC_RULES else None


def terminal_failure(
    error: BaseException, phase: str, failed_serial_position: int | None
) -> dict[str, Any]:
    code = safe_error_code(error)
    result: dict[str, Any] = {
        "failure_code": code,
        "phase": phase,
        "failed_serial_position": failed_serial_position,
    }
    rule = safe_semantic_rule(error)
    if rule is not None:
        result["semantic_rule"] = rule
    callback_failure = getattr(error, "callback_failure", None)
    if code == CALLBACK_FAILURE_CODE and isinstance(callback_failure, Mapping):
        result["callback_failure"] = copy.deepcopy(dict(callback_failure))
    payload_finalization_failure = getattr(error, "payload_finalization_failure", None)
    if code == PAYLOAD_FINALIZATION_FAILURE_CODE and isinstance(
        payload_finalization_failure, Mapping
    ):
        result["payload_finalization_failure"] = copy.deepcopy(dict(payload_finalization_failure))
    return result


def strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = strict_json_loads(raw)
    except Exception:
        raise _invalid("WORKER_V2.JSON") from None
    if type(value) is not dict:
        raise _invalid("WORKER_V2.JSON")
    return cast(dict[str, Any], value)


def regular_file_bytes(root: Path, relative: str, expected: str | None = None) -> bytes:
    path = root / relative
    try:
        mode, raw = path.lstat().st_mode, path.read_bytes()
    except OSError:
        raise _invalid("WORKER_V2.RESOURCE") from None
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if not stat.S_ISREG(mode) or path.is_symlink() or (expected is not None and digest != expected):
        raise _invalid("WORKER_V2.RESOURCE")
    return raw


def project_warnings(
    registry: Mapping[str, list[str]],
    value: object,
) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise _invalid("WORKER_V2.WARNING_SHAPE")
    if len(value) > len(registry):
        raise _invalid("WORKER_V2.WARNING_SHAPE")
    result = []
    seen: set[object] = set()
    for warning in value:
        if not isinstance(warning, Mapping):
            raise _invalid("WORKER_V2.WARNING_SHAPE")
        details = warning.get("details")
        counts = details.get("counts") if isinstance(details, Mapping) else warning.get("counts")
        code = warning.get("code")
        if (
            warning.get("severity") != "WARNING"
            or code not in registry
            or code in seen
            or not isinstance(counts, Mapping)
            or set(counts) != set(registry[cast(str, code)])
            or any(type(item) is not int or item < 0 for item in counts.values())
        ):
            raise _invalid("WORKER_V2.WARNING_UNREGISTERED")
        seen.add(code)
        result.append({"code": code, "severity": "WARNING", "counts": dict(sorted(counts.items()))})
    return result


def authenticated_invoker(
    *,
    interpreter: Path,
    entrypoint: Path,
    timeout_seconds: float,
    algorithm_id: str,
    expected_identity: Mapping[str, Any],
    gate1_receipt_digest: str,
) -> tuple[WorkerInvoker, str, ExpectedProjectionContext]:
    command = WorkerCommand.from_tokens([str(interpreter), str(entrypoint)])
    receipt = describe_worker(
        command,
        timeout_seconds=timeout_seconds,
        selected_algorithm_id=algorithm_id,
    )
    pin = receipt.get("selected_expected_identity")
    base = pin.get("base_backend_identity") if isinstance(pin, Mapping) else None
    base_fields = (
        "adapter_id",
        "adapter_version",
        "backend_name",
        "backend_version",
        "backend_source_commit",
        "worker_executable_digest",
        "worker_code_digest",
        "backend_source_digest",
        "environment_digest",
    )
    selected_fields = (
        "capabilities_digest",
        "base_backend_identity_digest",
        "selected_backend_identity_digest",
    )
    evidence = base.get("identity_evidence") if isinstance(base, Mapping) else None
    if (
        not isinstance(pin, Mapping)
        or not isinstance(base, Mapping)
        or any(base.get(field) != expected_identity.get(field) for field in base_fields)
        or any(pin.get(field) != expected_identity.get(field) for field in selected_fields)
        or not isinstance(evidence, list)
        or not any(
            isinstance(row, Mapping)
            and row.get("kind") == "environment-receipt"
            and row.get("digest") == gate1_receipt_digest
            for row in evidence
        )
    ):
        raise _invalid("WORKER_V2.IDENTITY")
    invoker = WorkerInvoker(command, timeout_seconds=timeout_seconds, expected_identity=pin)
    description = invoker.describe_authenticated()
    return (
        invoker,
        description.response_metadata_digest,
        _description_projection_context(description),
    )


def _authenticated_response(
    execution: Any, command: str
) -> tuple[Mapping[str, Any], Mapping[str, Any] | None]:
    try:
        authenticated = execution.authenticated_execution
        if type(authenticated) is not AuthenticatedWorkerExecutionEvidence:
            raise ValueError
        readback = _readback_authenticated_execution(authenticated)
        request, response = readback.authenticated_request, readback.response
        if (
            execution.authenticated_request is not request
            or authenticated.authenticated_request is not request
            or request.command != command
            or authenticated.command != command
            or authenticated.status != response["status"]
        ):
            raise ValueError
    except Exception:
        raise _invalid("WORKER_V2.AUTHENTICATED_EVIDENCE") from None
    return response, readback.command_evidence


def _negative_command_failure(
    response: Mapping[str, Any],
    command_evidence: Mapping[str, Any] | None,
    command: str,
) -> None:
    error = None if command_evidence is None else command_evidence.get("error")
    if (
        not isinstance(command_evidence, Mapping)
        or command_evidence.get("command_evidence_schema_version")
        != "ebm-audit-negative-command-evidence/2.0"
        or command_evidence.get("command") != command
        or command_evidence.get("status") != response.get("status")
        or not isinstance(error, Mapping)
        or not isinstance(error.get("code"), str)
        or not error["code"]
    ):
        raise _invalid("WORKER_V2.AUTHENTICATED_EVIDENCE")
    code = str(error["code"])
    callback_failure = error.get("callback_failure")
    payload_finalization_failure = error.get("payload_finalization_failure")
    if code == CALLBACK_FAILURE_CODE:
        if (
            not isinstance(callback_failure, Mapping)
            or set(callback_failure)
            != {"exception_class_id", "callback_source_id", "callback_line"}
            or callback_failure.get("exception_class_id") not in CALLBACK_EXCEPTION_CLASS_IDS
            or callback_failure.get("callback_source_id") not in CALLBACK_SOURCE_IDS
            or type(callback_failure.get("callback_line")) is not int
            or not 0 <= callback_failure["callback_line"] <= 1_000_000
            or (
                callback_failure["callback_source_id"] == "UNLISTED_CALLBACK_SOURCE"
                and callback_failure["callback_line"] != 0
            )
            or (
                callback_failure["callback_source_id"] != "UNLISTED_CALLBACK_SOURCE"
                and callback_failure["callback_line"] == 0
            )
        ):
            raise _invalid("WORKER_V2.AUTHENTICATED_EVIDENCE")
    elif callback_failure is not None:
        raise _invalid("WORKER_V2.AUTHENTICATED_EVIDENCE")
    if code == PAYLOAD_FINALIZATION_FAILURE_CODE:
        try:
            validate_instance(
                payload_finalization_failure,
                "canonical-records.schema.json",
                definition="FitPayloadFinalizationFailure",
            )
        except Exception:
            raise _invalid("WORKER_V2.AUTHENTICATED_EVIDENCE") from None
    elif payload_finalization_failure is not None:
        raise _invalid("WORKER_V2.AUTHENTICATED_EVIDENCE")
    raise WorkerV2NegativeResponseError(
        code,
        callback_failure=(
            cast(Mapping[str, Any], callback_failure) if callback_failure is not None else None
        ),
        payload_finalization_failure=(
            cast(Mapping[str, Any], payload_finalization_failure)
            if payload_finalization_failure is not None
            else None
        ),
    )


def _execution_record(
    execution: Any,
    command: str,
    expected_payload: Mapping[str, Any],
    arrays: Mapping[str, Any],
    expected_context: ExpectedProjectionContext,
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    response, command_evidence = _authenticated_response(execution, command)
    try:
        request = execution.authenticated_request
        authenticated = execution.authenticated_execution
        projection = scientific_request_projection(request._request())
        if projection is None or request.scientific_request_digest is None:
            raise ValueError
        record = {
            "scientific_request_projection": projection,
            "scientific_request_digest": request.scientific_request_digest,
            "request_evidence_projection": dict(request.identity_projection),
            "request_evidence_digest": request.evidence_digest,
            "execution_evidence_projection": dict(authenticated.identity_projection),
            "execution_evidence_digest": authenticated.evidence_digest,
        }
        verify_execution_record(
            record,
            command=command,
            expected_payload=expected_payload,
            arrays=arrays,
            expected_context=expected_context,
            expected_status=str(response["status"]),
        )
    except Exception:
        raise _invalid("WORKER_V2.AUTHENTICATED_EVIDENCE") from None
    if response.get("status") != "SUCCESS":
        _negative_command_failure(response, command_evidence, command)
    return record, response


def authenticated_warning_records(execution: Any) -> list[dict[str, Any]]:
    try:
        readback = _readback_authenticated_execution(execution.authenticated_execution)
        raw = readback.response_file_bytes("warnings.jsonl")
        records = [strict_json_object(line) for line in raw.splitlines()]
        response, warning_file = readback.response, readback.response["files"]["warnings.jsonl"]
        if (
            response["warnings_record_count"] != len(records)
            or response["warnings_file_digest"] != warning_file["sha256"]
            or warning_file["byte_length"] != len(raw)
        ):
            raise ValueError
    except Exception:
        raise _invalid("WORKER_V2.WARNING_EVIDENCE") from None
    return records


def invoke_validated_fit(
    invoker: WorkerInvoker,
    *,
    common_payload: Mapping[str, Any],
    fit_payload: Mapping[str, Any],
    arrays: Mapping[str, Any],
    expected_context: ExpectedProjectionContext,
    fit_response_returned: list[bool] | None = None,
) -> tuple[Any, dict[str, Any]]:
    validation = invoker._invoke_contract_harness(
        command="validate",
        payload_schema_version="ebm-audit-worker-validation/2.0",
        payload=common_payload,
        arrays=arrays,
    )
    validation_evidence, validation_response = _execution_record(
        validation,
        "validate",
        common_payload,
        arrays,
        expected_context,
    )
    if validation_response.get("payload", {}).get("fit_permitted") is not True:
        raise _invalid("WORKER_V2.VALIDATION_FAILED")
    execution = invoker._invoke_contract_harness(
        command="fit",
        payload_schema_version="ebm-audit-worker-fit-payload/2.0",
        payload=fit_payload,
        arrays=arrays,
    )
    if fit_response_returned is not None:
        fit_response_returned[0] = True
    fit_evidence, fit_response = _execution_record(
        execution,
        "fit",
        fit_payload,
        arrays,
        expected_context,
    )
    records = {
        "validation_evidence": validation_evidence,
        "fit_evidence": fit_evidence,
    }
    validation_projection = records["validation_evidence"]["scientific_request_projection"]
    fit_projection = records["fit_evidence"]["scientific_request_projection"]
    if (
        validation_projection["payload"]["execution_input_projection_digest"]
        != fit_projection["payload"]["execution_input_projection_digest"]
    ):
        raise _invalid("WORKER_V2.VALIDATE_FIT_BINDING")
    result = fit_response["payload"]["result"]
    for field in (
        "universe_id",
        "chain_execution_id",
        "attempt_id",
        "attempt_ordinal",
        "seed",
        "settings_digest",
        "requested_outputs_digest",
    ):
        if result[field] != fit_payload[field]:
            raise _invalid("WORKER_V2.FIT_ECHO")
    preimage = {key: value for key, value in result.items() if key != "worker_fit_payload_digest"}
    if worker_fit_payload_digest(preimage) != result["worker_fit_payload_digest"]:
        raise _invalid("WORKER_V2.FIT_DIGEST")
    return execution, records


def verify_execution_record(
    value: object,
    *,
    command: str,
    expected_payload: Mapping[str, Any],
    arrays: Mapping[str, Any],
    expected_context: ExpectedProjectionContext,
    expected_status: str = "SUCCESS",
) -> str:
    names = {
        "scientific_request_projection",
        "scientific_request_digest",
        "request_evidence_projection",
        "request_evidence_digest",
        "execution_evidence_projection",
        "execution_evidence_digest",
    }
    if not isinstance(value, Mapping) or set(value) != names:
        raise _invalid("WORKER_V2.EVIDENCE_PROJECTION")
    scientific = value["scientific_request_projection"]
    request_projection = value["request_evidence_projection"]
    execution_projection = value["execution_evidence_projection"]
    if not all(
        isinstance(item, Mapping) for item in (scientific, request_projection, execution_projection)
    ):
        raise _invalid("WORKER_V2.EVIDENCE_PROJECTION")
    scientific = cast(Mapping[str, Any], scientific)
    request_projection = cast(Mapping[str, Any], request_projection)
    execution_projection = cast(Mapping[str, Any], execution_projection)
    scientific_digest = structured_sha256("ebm-audit/scientific-request/2", scientific)
    payload = scientific.get("payload")
    if (
        value["scientific_request_digest"] != scientific_digest
        or scientific.get("command") != command
        or not isinstance(payload, Mapping)
        or request_projection.get("command") != command
        or request_projection.get("scientific_request_digest") != scientific_digest
        or not isinstance(
            request_projection.get("authenticated_description_response_metadata_digest"), str
        )
        or value["request_evidence_digest"]
        != authenticated_request_evidence_digest(request_projection)
        or execution_projection.get("command") != command
        or execution_projection.get("status") != expected_status
        or execution_projection.get("authenticated_request_evidence_digest")
        != value["request_evidence_digest"]
        or execution_projection.get("authenticated_description_response_metadata_digest")
        != request_projection.get("authenticated_description_response_metadata_digest")
        or value["execution_evidence_digest"]
        != authenticated_execution_evidence_digest(execution_projection)
    ):
        raise _invalid("WORKER_V2.EVIDENCE_PROJECTION")
    input_projection = payload.get("execution_input_projection")
    input_digest = payload.get("execution_input_projection_digest")
    if (
        not isinstance(input_projection, Mapping)
        or input_digest != execution_input_projection_digest(input_projection)
        or request_projection.get("execution_input_projection_digest") != input_digest
    ):
        raise _invalid("WORKER_V2.INPUT_PROJECTION")
    try:
        expected_projection, expected_input_digest = build_execution_input_projection(
            expected_payload,
            arrays=arrays,
            files=_request_file_projection(arrays),
            core_code_digest=expected_context.core_code_digest,
            selected_backend_identity=expected_context.selected_backend_identity,
            capabilities=expected_context.capabilities,
            stage_semantics_definition=expected_context.stage_semantics_definition,
            adapter_semantics=expected_context.adapter_semantics,
        )
        expected_wire_payload = build_wire_scientific_payload(
            command,
            expected_payload,
            execution_input_projection=expected_projection,
            execution_input_projection_digest_value=expected_input_digest,
        )
    except Exception:
        raise _invalid("WORKER_V2.INPUT_BINDING") from None
    if dict(input_projection) != expected_projection or input_digest != expected_input_digest:
        raise _invalid("WORKER_V2.INPUT_BINDING")
    if dict(payload) != expected_wire_payload:
        raise _invalid("WORKER_V2.FIT_BINDING" if command == "fit" else "WORKER_V2.INPUT_BINDING")
    return str(input_digest)


def verify_worker_identity(
    value: object,
    *,
    expected: Mapping[str, Any],
    fields: Sequence[str],
) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {*fields, "authenticated_description_response_metadata_digest"}
        or any(value.get(field) != expected[field] for field in fields)
        or not isinstance(value.get("authenticated_description_response_metadata_digest"), str)
    ):
        raise _invalid("WORKER_V2.IDENTITY")
    return value


def _strict_scalar(value: object, dtype: str) -> bool | int | float:
    if dtype == "bool":
        if type(value) is not bool:
            raise _invalid("WORKER_V2.ARRAY_SCALAR")
        return value
    if dtype in {"int32", "int64"}:
        if type(value) is not int:
            raise _invalid("WORKER_V2.ARRAY_SCALAR")
        bounds = np.iinfo(np.dtype(dtype))
        if value < bounds.min or value > bounds.max:
            raise _invalid("WORKER_V2.ARRAY_SCALAR")
        return value
    if dtype != "float64" or isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _invalid("WORKER_V2.ARRAY_SCALAR")
    result = float(value)
    if not math.isfinite(result) or (type(value) is int and int(result) != value):
        raise _invalid("WORKER_V2.ARRAY_SCALAR")
    return result


def _strict_nested(value: object, shape: Sequence[int], dtype: str) -> object:
    if not shape:
        return _strict_scalar(value, dtype)
    if type(value) is not list or len(value) != shape[0]:
        raise _invalid("WORKER_V2.ARRAY_SHAPE")
    return [_strict_nested(item, shape[1:], dtype) for item in value]


def strict_retained_arrays(
    attempt: Mapping[str, Any],
    retained_names: Sequence[str],
) -> dict[str, NDArray[Any]]:
    catalog = attempt.get("array_catalog")
    values = attempt.get("participant_free_arrays")
    if not isinstance(catalog, Mapping) or not isinstance(values, Mapping):
        raise _invalid("WORKER_V2.ARRAY_RECORD")
    result: dict[str, NDArray[Any]] = {}
    for name in retained_names:
        entry = catalog.get(name)
        raw = values.get(name)
        if not isinstance(entry, Mapping):
            raise _invalid("WORKER_V2.ARRAY_RECORD")
        dtype, shape = entry.get("dtype"), entry.get("shape")
        if (
            dtype not in {"bool", "int32", "int64", "float64"}
            or type(shape) is not list
            or any(type(size) is not int or size < 0 for size in shape)
        ):
            raise _invalid("WORKER_V2.ARRAY_RECORD")
        array = np.asarray(_strict_nested(raw, shape, str(dtype)), dtype=str(dtype), order="C")
        if (
            array_catalog_entry(
                name,
                array,
                semantic_version=str(entry.get("semantic_version")),
            )
            != entry
        ):
            raise _invalid("WORKER_V2.ARRAY_DIGEST")
        result[name] = array
    return result


def verify_independent_target(
    *,
    values: NDArray[np.float64],
    groups: NDArray[np.integer[Any]],
    arrays: Mapping[str, NDArray[Any]],
    catalog: Mapping[str, Any],
    reference_value: object,
) -> tuple[str, str]:
    parameters = np.asarray(arrays[GMM_MEMBER], dtype=np.float64)
    if (
        parameters.shape != (9, 5)
        or not np.all(np.isfinite(parameters))
        or np.any(parameters[:, (1, 3)] <= 0.0)
        or np.any(parameters[:, 4] <= 0.0)
        or np.any(parameters[:, 4] >= 1.0)
    ):
        raise _invalid("WORKER_V2.GMM_PARAMETERS")
    if groups.shape != (values.shape[0],) or not np.all(np.isin(groups, (0, 1))):
        raise _invalid("WORKER_V2.GROUPS")
    row_order = np.asarray(
        sorted(
            range(values.shape[0]),
            key=lambda index: (int(groups[index]), values[index].tobytes(order="C")),
        ),
        dtype=np.int64,
    )
    ordered_values = values[row_order]
    matrix = np.empty((ordered_values.shape[0], 9, 2), dtype=np.float64, order="C")
    normalizer = math.sqrt(2.0 * math.pi)
    for event in range(9):
        for component, offset in enumerate((0, 2)):
            mean, scale = parameters[event, offset : offset + 2]
            standardized = (ordered_values[:, event] - mean) / scale
            matrix[:, event, component] = (np.exp(-(standardized**2) / 2.0) / normalizer) / scale
    matrix_digest = domain_separated_bytes_sha256(MATRIX_DOMAIN, matrix.tobytes(order="C"))
    if (
        not isinstance(reference_value, Mapping)
        or reference_value.get("native_probability_matrix_shape") != list(matrix.shape)
        or reference_value.get("native_probability_matrix_dtype") != "float64"
        or reference_value.get("native_probability_matrix_order") != "C"
        or reference_value.get("native_probability_matrix_digest") != matrix_digest
        or reference_value.get("event_ids") != [f"e{index:02d}" for index in range(1, 10)]
        or reference_value.get("component_axis") != ["non-event-density", "event-density"]
    ):
        raise _invalid("WORKER_V2.EXACT_TARGET")
    target = solve_exact_kde_target(
        matrix,
        event_ids=[f"e{index:02d}" for index in range(1, 10)],
    )
    reference = copy.deepcopy(dict(reference_value))
    digest = reference.pop("exact_fixed_target_reference_digest", None)
    bindings = {
        "position_probabilities_binding": TARGET_POSITION_MEMBER,
        "pairwise_precedence_binding": TARGET_PAIRWISE_MEMBER,
    }
    expected = {
        "exact_fixed_target_reference_schema_version": (
            "ebm-audit-exact-fixed-target-reference/1.0"
        ),
        "requested_output_id": "exact_fixed_order_target",
        "target_arithmetic_id": target.target_arithmetic_id,
        "native_probability_matrix_shape": list(matrix.shape),
        "native_probability_matrix_dtype": "float64",
        "native_probability_matrix_order": "C",
        "native_probability_matrix_digest": matrix_digest,
        "event_ids": list(target.event_ids),
        "component_axis": ["non-event-density", "event-density"],
        "order_count": target.order_count,
        **{
            field: {
                "member_name": name,
                "array_digest": cast(Mapping[str, Any], catalog[name])["array_digest"],
            }
            for field, name in bindings.items()
        },
        "even_permutation_mass": target.even_permutation_mass,
    }
    if (
        reference != expected
        or digest != structured_sha256(REFERENCE_DOMAIN, reference)
        or not np.array_equal(arrays[TARGET_POSITION_MEMBER], target.position_probabilities)
        or not np.array_equal(arrays[TARGET_PAIRWISE_MEMBER], target.pairwise_precedence)
    ):
        raise _invalid("WORKER_V2.EXACT_TARGET")
    return str(digest), str(cast(Mapping[str, Any], catalog[GMM_MEMBER])["array_digest"])


def clean_git_candidate(root: Path) -> dict[str, str]:
    def git(*arguments: str) -> bytes:
        try:
            return subprocess.run(
                ["git", *arguments],
                cwd=root,
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            raise _invalid("WORKER_V2.CANDIDATE_GIT") from None

    if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != root.resolve():
        raise _invalid("WORKER_V2.CANDIDATE_ROOT")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise _invalid("WORKER_V2.CANDIDATE_DIRTY")
    return {
        "identity_kind": "CLEAN_GIT_CANDIDATE",
        "commit": git("rev-parse", "HEAD^{commit}").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
    }


def transition_quality(captures: Sequence[Any]) -> dict[str, Any]:
    universes: dict[tuple[str, str, int, int], list[Any]] = {}
    for capture in captures:
        row = capture.attempt
        key = (
            str(row["family_id"]),
            str(row["variant_id"]),
            int(row["replicate_index"]),
            int(row["budget"]),
        )
        universes.setdefault(key, []).append(capture)
    if (
        len(captures) != 54
        or len(universes) != 18
        or any(len(group) != 3 for group in universes.values())
    ):
        raise _invalid("WORKER_V2.ATTEMPT_DENOMINATOR")
    assessments = {}
    event_ids = tuple(f"e{index:02d}" for index in range(1, 10))
    for key, group in universes.items():
        ordered = sorted(group, key=lambda item: int(item.attempt["chain_id"]))
        convergence = derive_convergence_record(
            [
                ConvergenceChainInput(
                    chain_execution_id=str(item.attempt["chain_execution_id"]),
                    event_ids=event_ids,
                    thinning_interval=10,
                    postburn_unthinned_state_count=item.unthinned.shape[0],
                    retained_state_count=item.retained.shape[0],
                    postburn_order_state_chain=item.unthinned,
                    position_probabilities=item.position,
                    pairwise_precedence=item.pairwise,
                    postburn_likelihood_trace=None,
                )
                for item in ordered
            ]
        )
        assessments[key] = str(convergence["assessment"])
    result = calculate_kde_profile_transition_quality(
        [
            KdeProfileChainInput(
                budget=int(item.attempt["budget"]),
                chain_slot=int(item.attempt["chain_slot"]),
                event_ids=event_ids,
                retained_order_states=item.retained,
                unthinned_postburn_order_states=item.unthinned,
                exact_position_probabilities=item.target_position,
                exact_pairwise_precedence=item.target_pairwise,
                exact_even_parity_probability=item.target_even,
                universe_convergence_assessment=assessments[
                    (
                        str(item.attempt["family_id"]),
                        str(item.attempt["variant_id"]),
                        int(item.attempt["replicate_index"]),
                        int(item.attempt["budget"]),
                    )
                ],
            )
            for item in captures
        ]
    )
    return cast(dict[str, Any], _json_ready(asdict(result)))


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_ready(item) for item in value]
    return value.item() if isinstance(value, np.generic) else value


def publish_receipt(
    output_directory: Path,
    evidence_name: str,
    raw: bytes,
) -> None:
    temporary = output_directory / ("." + evidence_name + ".tmp")
    final = output_directory / evidence_name
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise _invalid("WORKER_V2.EVIDENCE_SHORT_WRITE")
            view = view[count:]
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        readback = bytearray()
        while chunk := os.read(descriptor, 65536):
            readback.extend(chunk)
        if readback != raw:
            raise _invalid("WORKER_V2.EVIDENCE_READBACK")
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, final)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
        raise
