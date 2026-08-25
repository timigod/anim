"""Named, domain-separated identities from the normative protocol registry."""

from __future__ import annotations

import copy
import hashlib
import hmac
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Literal, NotRequired, TypedDict, cast

from ebm_audit.schema import (
    SchemaValidationError,
    load_protocol_registry,
    validate_instance,
)

from .canonical import canonical_json_bytes, structured_sha256
from .errors import CanonicalizationError, FramingError

type FitPayloadFinalizationStageId = Literal[
    "FIT_PAYLOAD_FINALIZATION_COPY",
    "FIT_PAYLOAD_FINALIZATION_SCHEMA_RESOURCE_OR_VALIDATOR",
    "FIT_PAYLOAD_FINALIZATION_SCHEMA_VIOLATION",
    "FIT_PAYLOAD_FINALIZATION_CANONICALIZATION",
    "FIT_PAYLOAD_FINALIZATION_DIGEST",
]


class FitPayloadFinalizationFailure(TypedDict):
    stage_id: FitPayloadFinalizationStageId
    schema_id: NotRequired[str]
    validator_keyword: NotRequired[str]
    safe_field_path: NotRequired[str]


class FitPayloadFinalizationError(Exception):
    """One closed, privacy-safe worker fit-payload finalization failure."""

    def __init__(self, failure: FitPayloadFinalizationFailure) -> None:
        self.failure: FitPayloadFinalizationFailure = failure.copy()
        super().__init__("Worker fit-payload finalization failed.")


_FIT_PAYLOAD_SCHEMA_NAME = "worker-protocol.schema.json"
_FIT_PAYLOAD_SCHEMA_DEFINITION = "WorkerFitPayloadDigestPreimage"
_FIT_PAYLOAD_SCHEMA_ID = f"{_FIT_PAYLOAD_SCHEMA_NAME}#/$defs/{_FIT_PAYLOAD_SCHEMA_DEFINITION}"
_SCHEMA_KEYWORD_TOKEN = re.compile(r"^(?:\$[A-Za-z]|[A-Za-z])[A-Za-z0-9_-]{0,63}$")
_SCHEMA_FIELD_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_INSTANCE_LOCATION_PARTS = re.compile(r"<field>|\[[0-9]+\]")


def _fit_payload_schema_violation_failure(
    caught: SchemaValidationError,
) -> FitPayloadFinalizationFailure | None:
    if (
        caught.schema_name != _FIT_PAYLOAD_SCHEMA_NAME
        or caught.definition != _FIT_PAYLOAD_SCHEMA_DEFINITION
        or not caught.violations
    ):
        return None
    candidates: list[tuple[tuple[int, str, str, str], FitPayloadFinalizationFailure]] = []
    for violation in caught.violations:
        keyword = violation.schema_keyword
        instance_location = violation.instance_location
        schema_location = violation.schema_location
        if (
            not isinstance(keyword, str)
            or _SCHEMA_KEYWORD_TOKEN.fullmatch(keyword) is None
            or not isinstance(instance_location, str)
            or not isinstance(schema_location, str)
            or not instance_location.startswith("$")
        ):
            return None

        parts = _INSTANCE_LOCATION_PARTS.findall(instance_location[1:])
        if "".join(parts) != instance_location[1:]:
            return None
        pointer_parts = schema_location.removeprefix("#/").split("/")
        schema_fields = [
            pointer_parts[index + 1].replace("~1", "/").replace("~0", "~")
            for index, part in enumerate(pointer_parts[:-1])
            if part == "properties"
        ]
        if len(schema_fields) != parts.count("<field>") or any(
            _SCHEMA_FIELD_TOKEN.fullmatch(field) is None for field in schema_fields
        ):
            return None

        fields = iter(schema_fields)
        safe_field_path = "$" + "".join(
            "[]" if part.startswith("[") else f".{next(fields)}" for part in parts
        )
        if len(safe_field_path) > 1000:
            return None
        candidates.append(
            (
                (-len(parts), instance_location, schema_location, keyword),
                {
                    "stage_id": "FIT_PAYLOAD_FINALIZATION_SCHEMA_VIOLATION",
                    "schema_id": _FIT_PAYLOAD_SCHEMA_ID,
                    "validator_keyword": keyword,
                    "safe_field_path": safe_field_path,
                },
            )
        )

    return min(candidates, key=lambda candidate: candidate[0])[1]


def deterministic_fit_request_id(attempt_id: str) -> str:
    """Derive the sole fit transport UUID from its authenticated attempt owner."""

    try:
        if (
            not isinstance(attempt_id, str)
            or not attempt_id.startswith("sha256:")
            or len(attempt_id) != 71
            or any(character not in "0123456789abcdef" for character in attempt_id[7:])
        ):
            raise ValueError
        bytes.fromhex(attempt_id.removeprefix("sha256:"))
        raw = bytearray(
            hashlib.sha256(b"ebm-audit/fit-request-id/1\0" + attempt_id.encode("ascii")).digest()[
                :16
            ]
        )
    except (UnicodeEncodeError, ValueError):
        raise FramingError(
            "Fit attempt identity is not a prefixed lowercase SHA-256 digest."
        ) from None
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def authenticated_request_evidence_digest(projection: Mapping[str, Any]) -> str:
    validate_instance(
        projection,
        "worker-protocol.schema.json",
        definition="AuthenticatedWorkerRequestEvidenceProjection",
    )
    return structured_sha256("ebm-audit/authenticated-worker-request-evidence/2", projection)


def authenticated_execution_evidence_digest(projection: Mapping[str, Any]) -> str:
    """Identify the closed privacy-safe projection of one complete worker response."""

    validate_instance(
        projection,
        "worker-protocol.schema.json",
        definition="AuthenticatedWorkerExecutionEvidenceProjection",
    )
    return structured_sha256("ebm-audit/authenticated-worker-execution-evidence/2", projection)


def core_observed_failure_digest(preimage: Mapping[str, Any]) -> str:
    validate_instance(
        preimage,
        "worker-protocol.schema.json",
        definition="CoreObservedFailureDigestPreimage",
    )
    return structured_sha256("ebm-audit/core-observed-failure/2", preimage)


def selected_algorithm_binding_digest(binding: Mapping[str, Any]) -> str:
    """Identify the sole exact ten-field Describe-owned algorithm binding."""

    validate_instance(
        binding,
        "analysis-universe.schema.json",
        definition="SelectedAlgorithmBinding",
    )
    return structured_sha256("ebm-audit/selected-algorithm-binding/2", binding)


def worker_command_evidence_digest(evidence: Mapping[str, Any]) -> str:
    """Identify one active validate/fit command-evidence projection."""

    validate_instance(
        evidence,
        "worker-protocol.schema.json",
        definition="CommandEvidenceProjection",
    )
    return structured_sha256("ebm-audit/worker-command-evidence/2", evidence)


def _closed_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(value))


def settings_digest(settings: Mapping[str, Any]) -> str:
    return structured_sha256("ebm-audit/settings/1", settings)


def settings_schema_digest(settings_schema: Mapping[str, Any]) -> str:
    return structured_sha256("ebm-audit/settings-schema/1", settings_schema)


def stage_semantics_digest(stage_semantics: Mapping[str, Any]) -> str:
    """Bind one complete, schema-valid algorithm staging definition."""

    validate_instance(
        stage_semantics,
        "canonical-records.schema.json",
        definition="StageSemanticsDefinition",
    )
    return structured_sha256("ebm-audit/stage-semantics/1", stage_semantics)


def capabilities_digest(capabilities: Mapping[str, Any]) -> str:
    validate_instance(
        capabilities,
        "worker-protocol.schema.json",
        definition="AdapterCapabilities",
    )
    return structured_sha256("ebm-audit/capabilities/1", capabilities)


def backend_identity_digest(identity: Mapping[str, Any]) -> str:
    validate_instance(
        identity,
        "canonical-records.schema.json",
        definition="BackendIdentity",
    )
    return structured_sha256("ebm-audit/backend-identity/1", identity)


def adapter_semantics_digest(semantics: Mapping[str, Any]) -> str:
    """Identify maintained adapter semantics without transport coupling."""

    validate_instance(
        semantics,
        "worker-protocol.schema.json",
        definition="AdapterSemantics",
    )
    projection = semantics["mcmc_projection"]
    if projection["availability"] == "AVAILABLE":
        proposal_bindings = projection["proposal_setting_bindings"]
        proposal_ids = [row["proposal_setting_id"] for row in proposal_bindings]
        backend_ids = [row["backend_setting_id"] for row in proposal_bindings]
        if len(proposal_ids) != len(set(proposal_ids)) or len(backend_ids) != len(set(backend_ids)):
            raise ValueError("MCMC proposal-setting bindings must be one-to-one.")
        canonical_rows = [canonical_json_bytes(row) for row in proposal_bindings]
        if canonical_rows != sorted(canonical_rows):
            raise ValueError("MCMC proposal-setting bindings must use canonical JCS order.")
    return structured_sha256("ebm-audit/adapter-semantics/2", semantics)


def expected_identity_pin(
    base_backend_identity: Mapping[str, Any],
    *,
    algorithm_id: str,
    algorithm_capabilities_digest: str,
) -> dict[str, Any]:
    """Build the complete reviewed pin for one selected algorithm.

    A describe response owns the worker-wide identity with ``algorithm_id=null``.
    Scientific commands own the same complete identity with the selected
    algorithm inserted.  Retaining both digests prevents an unchanged subset of
    component hashes from hiding drift in versions, source commit, backend name,
    or identity evidence.
    """

    base = _closed_copy(base_backend_identity)
    validate_instance(
        base,
        "canonical-records.schema.json",
        definition="BackendIdentity",
    )
    if base.get("algorithm_id") is not None:
        raise ValueError("A base backend identity must not select an algorithm.")
    selected = _closed_copy(base)
    selected["algorithm_id"] = algorithm_id
    pin = {
        "base_backend_identity": base,
        "base_backend_identity_digest": backend_identity_digest(base),
        "selected_algorithm_id": algorithm_id,
        "selected_backend_identity_digest": backend_identity_digest(selected),
        "capabilities_digest": algorithm_capabilities_digest,
    }
    validate_instance(
        pin,
        "worker-protocol.schema.json",
        definition="ExpectedIdentity",
    )
    return pin


def validate_expected_identity_pin(pin: Mapping[str, Any]) -> dict[str, Any]:
    """Return a closed copy only when every pin field matches its exact owner."""

    validate_instance(
        pin,
        "worker-protocol.schema.json",
        definition="ExpectedIdentity",
    )
    expected = expected_identity_pin(
        pin["base_backend_identity"],
        algorithm_id=str(pin["selected_algorithm_id"]),
        algorithm_capabilities_digest=str(pin["capabilities_digest"]),
    )
    if expected != dict(pin):
        raise ValueError("The expected worker identity pin is not self-consistent.")
    return _closed_copy(pin)


def expected_identity_pin_digest(pin: Mapping[str, Any]) -> str:
    """Validate and identify one complete expected worker identity pin."""

    validated = validate_expected_identity_pin(pin)
    return structured_sha256("ebm-audit/expected-identity-pin/1", validated)


def requested_output_registry_digest() -> str:
    rows = load_protocol_registry()["requested_outputs"]
    return structured_sha256("ebm-audit/requested-output-registry/1", rows)


def self_test_check_registry_digest() -> str:
    rows = load_protocol_registry()["self_test_checks"]
    return structured_sha256("ebm-audit/self-test-check-registry/1", rows)


def requested_outputs_digest(command: str, output_ids: Sequence[str]) -> str:
    registry = load_protocol_registry()
    rows = registry["requested_outputs"]
    if not isinstance(rows, list):
        raise FramingError("Requested-output registry has an invalid shape.")
    if len(set(output_ids)) != len(output_ids):
        raise FramingError("Requested outputs must not contain duplicates.")
    row_by_id = {row["output_id"]: row for row in rows}
    try:
        selected = [row_by_id[output_id] for output_id in output_ids]
    except (KeyError, TypeError) as exc:
        raise FramingError("Requested output is not registered.") from exc
    if any(command not in row["commands"] for row in selected):
        raise FramingError("Requested output is unavailable for this command.")
    order = {row["output_id"]: index for index, row in enumerate(rows)}
    ordered_ids = sorted(output_ids, key=order.__getitem__)
    preimage = {
        "registry_digest": requested_output_registry_digest(),
        "requested_outputs": ordered_ids,
    }
    return structured_sha256("ebm-audit/requested-outputs/2", preimage)


def scientific_requested_outputs_digest(output_ids: Sequence[str]) -> str:
    """Identify a selected output set without transport-command coupling."""

    registry = load_protocol_registry()
    rows = registry["requested_outputs"]
    if not isinstance(rows, list) or len(set(output_ids)) != len(output_ids):
        raise FramingError("Requested outputs have an invalid closed shape.")
    row_by_id = {row["output_id"]: row for row in rows}
    try:
        selected_ids = [row_by_id[output_id]["output_id"] for output_id in output_ids]
    except (KeyError, TypeError) as exc:
        raise FramingError("Requested output is not registered.") from exc
    order = {row["output_id"]: index for index, row in enumerate(rows)}
    preimage = {
        "registry_digest": requested_output_registry_digest(),
        "requested_outputs": sorted(selected_ids, key=order.__getitem__),
    }
    return structured_sha256("ebm-audit/requested-outputs/2", preimage)


def audit_case_configuration_digest(configuration: Mapping[str, Any]) -> str:
    """Validate and identify one explicit case-to-execution binding owner."""

    value = _closed_copy(configuration)
    validate_instance(
        value,
        "worker-protocol.schema.json",
        definition="AuditCaseConfigurationDigestPreimage",
    )
    specs = cast(Sequence[Mapping[str, Any]], value["ordered_analysis_specs"])
    spec_ids = [structured_sha256("ebm-audit/analysis-spec/3", spec) for spec in specs]
    if len(set(spec_ids)) != len(spec_ids) or spec_ids != sorted(
        spec_ids, key=lambda item: item.encode("utf-8")
    ):
        raise FramingError("Audit-case AnalysisSpecs must be unique and canonically ordered.")

    bindings = cast(Sequence[Mapping[str, Any]], value["operation_bindings"])
    matrix_ids = [cast(str, row["operation_matrix_id"]) for row in bindings]
    if len(set(matrix_ids)) != len(matrix_ids) or matrix_ids != sorted(
        matrix_ids, key=lambda item: item.encode("utf-8")
    ):
        raise FramingError("Audit-case operation bindings must be unique and ordered.")
    covered_ordinals: set[int] = set()
    for row in bindings:
        ordinal = cast(int, row["analysis_spec_ordinal"])
        if (
            row["case_id"] != value["case_id"]
            or ordinal < 0
            or ordinal >= len(spec_ids)
            or row["analysis_spec_id"] != spec_ids[ordinal]
        ):
            raise FramingError("An audit-case operation binding is detached.")
        covered_ordinals.add(ordinal)
    if covered_ordinals != set(range(len(spec_ids))):
        raise FramingError("Audit-case operation bindings do not cover every AnalysisSpec.")
    return structured_sha256("ebm-audit/audit-case-configuration/3", value)


def validate_execution_input_projection(projection: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one trusted-worker repeatability projection.

    The worker shell and backend callback share a process.  This contract binds
    repeatable scientific inputs; it is not a hostile-code isolation boundary.
    """

    value = _closed_copy(projection)
    validate_instance(
        value,
        "worker-protocol.schema.json",
        definition="ExecutionInputProjection",
    )
    if value["settings_digest"] != settings_digest(value["settings"]):
        raise FramingError("Execution-input settings do not match their digest.")
    if value["selected_backend_identity_digest"] != backend_identity_digest(
        value["selected_backend_identity"]
    ):
        raise FramingError("Execution-input backend identity does not match its digest.")
    if value["capabilities_digest"] != capabilities_digest(value["capabilities"]):
        raise FramingError("Execution-input capabilities do not match their digest.")
    if value["stage_semantics_digest"] != stage_semantics_digest(
        value["stage_semantics_definition"]
    ):
        raise FramingError("Execution-input stage semantics do not match their digest.")
    if value["adapter_semantics_digest"] != adapter_semantics_digest(value["adapter_semantics"]):
        raise FramingError("Execution-input adapter semantics do not match their digest.")
    if value["requested_outputs_digest"] != scientific_requested_outputs_digest(
        value["requested_outputs"]
    ):
        raise FramingError("Execution-input requested outputs do not match their digest.")
    dataset = cast(Mapping[str, Any], value["dataset"])
    identity = cast(Mapping[str, Any], value["selected_backend_identity"])
    if not (
        value["preprocessing_manifest_digest"] == dataset["preprocessing_manifest_digest"]
        and value["stage_semantics_digest"] == dataset["stage_semantics_digest"]
        and value["algorithm_id"] == identity["algorithm_id"]
        and value["algorithm_id"] == value["adapter_semantics"]["algorithm_id"]
        and identity["adapter_id"] == value["adapter_semantics"]["adapter_id"]
        and value["capabilities_digest"] == value["adapter_semantics"]["capabilities_digest"]
        and value["stage_semantics_digest"] == value["adapter_semantics"]["stage_semantics_digest"]
    ):
        raise FramingError("Execution-input repeated bindings are detached.")
    synthetic_provenance = dataset.get("synthetic_provenance")
    if synthetic_provenance is not None and (
        not isinstance(synthetic_provenance, Mapping)
        or synthetic_provenance["participant_count"] != dataset["participant_count"]
        or synthetic_provenance["event_count"] != dataset["event_count"]
        or synthetic_provenance["event_ids"] != dataset["event_ids"]
    ):
        raise FramingError("Synthetic provenance does not match its dataset owner.")
    if isinstance(dataset, Mapping) and "stage_row_index_array" in dataset:
        files = cast(Mapping[str, Any], value["input_files"])
        # The stage artifact is not an external path.  It must be one exact,
        # hashed file inside the retained request bundle.
        stage_files = [record for name, record in files.items() if name != "values.npz"]
        if len(stage_files) != 1:
            raise FramingError("Stage has no unique contained fitted artifact.")
    return value


def execution_input_projection_digest(projection: Mapping[str, Any]) -> str:
    value = validate_execution_input_projection(projection)
    return structured_sha256("ebm-audit/execution-input-projection/2", value)


def worker_validation_payload_digest(payload: Mapping[str, Any]) -> str:
    value = _closed_copy(payload)
    validate_instance(
        value,
        "worker-protocol.schema.json",
        definition="WorkerValidationPayloadDigestPreimage",
    )
    return structured_sha256("ebm-audit/worker-validation-payload/2", value)


def worker_fit_payload_digest(payload: Mapping[str, Any]) -> str:
    try:
        value = _closed_copy(payload)
    except Exception:
        raise FitPayloadFinalizationError({"stage_id": "FIT_PAYLOAD_FINALIZATION_COPY"}) from None

    try:
        validate_instance(
            value,
            _FIT_PAYLOAD_SCHEMA_NAME,
            definition=_FIT_PAYLOAD_SCHEMA_DEFINITION,
        )
    except SchemaValidationError as caught:
        try:
            failure = _fit_payload_schema_violation_failure(caught)
        except Exception:
            failure = None
        raise FitPayloadFinalizationError(
            failure or {"stage_id": "FIT_PAYLOAD_FINALIZATION_SCHEMA_RESOURCE_OR_VALIDATOR"}
        ) from None
    except Exception:
        raise FitPayloadFinalizationError(
            {"stage_id": "FIT_PAYLOAD_FINALIZATION_SCHEMA_RESOURCE_OR_VALIDATOR"}
        ) from None

    try:
        return structured_sha256("ebm-audit/worker-fit-payload/2", value)
    except CanonicalizationError:
        raise FitPayloadFinalizationError(
            {"stage_id": "FIT_PAYLOAD_FINALIZATION_CANONICALIZATION"}
        ) from None
    except Exception:
        raise FitPayloadFinalizationError({"stage_id": "FIT_PAYLOAD_FINALIZATION_DIGEST"}) from None


def actual_validate_worker_subject_digest(subject: Mapping[str, Any]) -> str:
    value = _closed_copy(subject)
    validate_instance(
        value,
        "worker-protocol.schema.json",
        definition="ActualValidateWorkerSubjectProjection",
    )
    return structured_sha256("ebm-audit/actual-validate-worker-subject/2", value)


def actual_fit_worker_subject_digest(subject: Mapping[str, Any]) -> str:
    value = _closed_copy(subject)
    validate_instance(
        value,
        "worker-protocol.schema.json",
        definition="ActualFitWorkerSubjectProjection",
    )
    return structured_sha256("ebm-audit/actual-fit-worker-subject/2", value)


def actual_stage_worker_subject_digest(subject: Mapping[str, Any]) -> str:
    value = _closed_copy(subject)
    validate_instance(
        value,
        "worker-protocol.schema.json",
        definition="ActualStageWorkerSubjectProjection",
    )
    return structured_sha256("ebm-audit/actual-stage-worker-subject/2", value)


def worker_stage_result_digest(result: Mapping[str, Any]) -> str:
    value = _closed_copy(result)
    validate_instance(
        value,
        "worker-protocol.schema.json",
        definition="StageResultDigestPreimage",
    )
    return structured_sha256("ebm-audit/worker-stage-result/2", value)


def scientific_request_projection(request: Mapping[str, Any]) -> dict[str, Any] | None:
    command = request.get("command")
    if command not in {"validate", "fit", "stage"}:
        return None
    projection = _closed_copy(request)
    for field in (
        "request_id",
        "request_metadata_digest",
        "scientific_request_digest",
        "created_at_utc",
    ):
        projection.pop(field, None)
    definition = {
        "validate": "ScientificValidateRequestProjection",
        "fit": "ScientificFitRequestProjection",
        "stage": "ScientificStageRequestProjection",
    }[str(command)]
    validate_instance(
        projection,
        "worker-protocol.schema.json",
        definition=definition,
    )
    return projection


def validate_request_execution_input_binding(request: Mapping[str, Any]) -> None:
    """Require the v2 wire projection to own every repeated envelope input."""

    if request.get("command") not in {"validate", "fit", "stage"}:
        return
    payload = request.get("payload")
    if not isinstance(payload, Mapping):
        raise FramingError("Scientific request payload is not an object.")
    if request.get("command") == "fit" and request.get("request_id") != (
        deterministic_fit_request_id(str(payload.get("attempt_id")))
    ):
        raise FramingError("Fit request UUID is detached from its attempt identity.")
    projection = payload.get("execution_input_projection")
    if not isinstance(projection, Mapping):
        raise FramingError("Scientific request has no execution-input projection.")
    expected = execution_input_projection_digest(projection)
    if payload.get("execution_input_projection_digest") != expected:
        raise FramingError("Execution-input projection digest does not match its owner.")
    if projection.get("core_code_digest") != request.get("core_code_digest"):
        raise FramingError("Execution-input core identity is detached from the envelope.")
    if projection.get("input_files") != request.get("files"):
        raise FramingError("Execution-input file descriptors are detached from the envelope.")
    outputs = projection.get("requested_outputs")
    if not isinstance(outputs, list):
        raise FramingError("Execution-input requested outputs are not an ordered array.")
    try:
        requested_outputs_digest(str(request["command"]), outputs)
    except Exception:
        raise FramingError(
            "Execution-input requested outputs are not eligible for the command."
        ) from None
    if request.get("command") == "stage":
        artifact = payload.get("fitted_artifact")
        files = projection.get("input_files")
        if not isinstance(artifact, Mapping) or not isinstance(files, Mapping):
            raise FramingError("Stage has no contained fitted-artifact binding.")
        record = files.get(artifact.get("relative_path"))
        if not isinstance(record, Mapping) or record != {
            "byte_length": artifact.get("byte_length"),
            "sha256": artifact.get("sha256"),
        }:
            raise FramingError("Stage fitted artifact is detached from its contained file.")


def scientific_request_digest(request: Mapping[str, Any]) -> str | None:
    projection = scientific_request_projection(request)
    if projection is None:
        return None
    return structured_sha256("ebm-audit/scientific-request/2", projection)


def retry_equivalence_projection(request: Mapping[str, Any]) -> dict[str, Any]:
    """Project one fit request for the sole identical process-failure retry.

    Attempt-specific request and cache identities remain distinct.  This
    projection starts from the complete fit scientific projection and removes
    exactly the two attempt coordinates; it is never a replacement request.
    """

    projection = scientific_request_projection(request)
    if projection is None or projection.get("command") != "fit":
        raise FramingError("Retry equivalence is defined only for a fit request.")
    payload = projection.get("payload")
    if not isinstance(payload, Mapping):
        raise FramingError("Fit retry equivalence has no closed payload owner.")
    retry_payload = _closed_copy(payload)
    try:
        del retry_payload["attempt_id"]
        del retry_payload["attempt_ordinal"]
    except KeyError:
        raise FramingError("Fit retry equivalence is missing its attempt coordinates.") from None
    retry_projection = _closed_copy(projection)
    retry_projection["payload"] = retry_payload
    validate_instance(
        retry_projection,
        "worker-protocol.schema.json",
        definition="RetryEquivalentFitRequestProjection",
    )
    return retry_projection


def retry_equivalence_digest(request: Mapping[str, Any]) -> str:
    """Identify the exact scientific fit request modulo attempt coordinates."""

    return structured_sha256(
        "ebm-audit/retry-equivalence/1",
        retry_equivalence_projection(request),
    )


_RESULT_NEGATIVE_STATUS_PRECEDENCE = (
    "PRIVACY_VIOLATION",
    "PROTOCOL_ERROR",
    "TIMEOUT",
    "BACKEND_ERROR",
    "INVALID_INPUT",
    "INVALID_SPECIFICATION",
    "UNSUPPORTED_CAPABILITY",
)
_RETRY_ELIGIBLE_PROCESS_FAILURE_CODES = frozenset(
    {"BACKEND.WORKER_START_FAILED", "BACKEND.WORKER_PROCESS_FAILED"}
)


def _result_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FramingError(f"Result finalization has no closed {label} owner.")
    return cast(Mapping[str, Any], value)


def _result_sequence(value: object, label: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise FramingError(f"Result finalization {label} is not an ordered array.")
    return [_result_mapping(item, f"{label} item") for item in value]


def _validate_core_failure_reference(evidence: Mapping[str, Any]) -> None:
    failure_value = evidence.get("core_observed_failure")
    if failure_value is None:
        if any(
            evidence.get(field) is not None
            for field in (
                "core_observed_failure_digest",
                "core_failure_class",
                "core_failure_code",
            )
        ):
            raise FramingError("Framed worker evidence contains detached core-failure fields.")
        return
    failure = _result_mapping(failure_value, "core-observed failure")
    if (
        core_observed_failure_digest(failure) != evidence.get("core_observed_failure_digest")
        or failure.get("failure_class") != evidence.get("core_failure_class")
        or failure.get("failure_code") != evidence.get("core_failure_code")
        or failure.get("authenticated_request_evidence_digest")
        != evidence.get("authenticated_request_evidence_digest")
    ):
        raise FramingError("Core-observed failure evidence is detached from its reference.")


def _validate_retry_attempt_group(
    attempts: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any]:
    if not 1 <= len(attempts) <= 2:
        raise FramingError("Each fit chain must retain one attempt and at most one retry.")
    if [attempt.get("attempt_ordinal") for attempt in attempts] != list(range(len(attempts))):
        raise FramingError("Fit attempt ordinals must be exactly [0] or [0, 1].")
    first = attempts[0]
    if len(attempts) == 1:
        return first

    retry = attempts[1]
    if (
        first.get("core_failure_class") != "PROCESS_FAILURE"
        or first.get("core_failure_code") not in _RETRY_ELIGIBLE_PROCESS_FAILURE_CODES
        or first.get("status") != "BACKEND_ERROR"
    ):
        raise FramingError("Ordinal-1 retry requires an ordinal-0 process start/crash failure.")
    if first.get("retry_equivalence_digest") != retry.get("retry_equivalence_digest"):
        raise FramingError("Retry attempts do not have the same retry-equivalence digest.")
    for field in (
        "attempt_id",
        "authenticated_request_evidence_digest",
        "request_metadata_digest",
        "scientific_request_digest",
    ):
        if first.get(field) == retry.get(field):
            raise FramingError(f"Retry attempts reuse attempt-specific {field}.")
    return retry


def _fit_terminal_evidence(
    evidence: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    if not evidence:
        return []
    groups: list[list[Mapping[str, Any]]] = []
    expected_position = 0
    for attempt in evidence:
        if attempt.get("command") != "fit":
            raise FramingError("Fit-attempt evidence contains another command.")
        _validate_core_failure_reference(attempt)
        position = attempt.get("chain_plan_position")
        chain_execution_id = attempt.get("chain_execution_id")
        if not isinstance(position, int) or isinstance(position, bool):
            raise FramingError("Fit-attempt evidence has no chain-plan position.")
        if position == expected_position:
            if not isinstance(chain_execution_id, str):
                raise FramingError("Fit-attempt evidence has no chain-execution identity.")
            groups.append([attempt])
            expected_position += 1
            continue
        if groups and position == expected_position - 1:
            group = groups[-1]
            if attempt.get("chain_execution_id") != group[0].get("chain_execution_id"):
                raise FramingError("One chain position names multiple chain executions.")
            group.append(attempt)
            continue
        raise FramingError("Fit-attempt chain positions must be a contiguous ordered prefix.")

    terminals: list[Mapping[str, Any]] = []
    seen_chain_ids: set[object] = set()
    seen_attempt_ids: set[object] = set()
    for group in groups:
        chain_execution_id = group[0].get("chain_execution_id")
        if chain_execution_id in seen_chain_ids:
            raise FramingError("A chain execution appears in more than one plan position.")
        seen_chain_ids.add(chain_execution_id)
        for attempt in group:
            attempt_id = attempt.get("attempt_id")
            if attempt_id in seen_attempt_ids:
                raise FramingError("A fit attempt identity is reused.")
            seen_attempt_ids.add(attempt_id)
        terminals.append(_validate_retry_attempt_group(group))
    return terminals


def _derived_negative_status(terminals: Sequence[Mapping[str, Any]]) -> str:
    statuses = {str(terminal.get("status")) for terminal in terminals}
    statuses.discard("SUCCESS")
    for status in _RESULT_NEGATIVE_STATUS_PRECEDENCE:
        if status in statuses:
            return status
    raise FramingError("Fit execution non-success has no terminal negative evidence.")


def _validate_result_error_category(body: Mapping[str, Any]) -> None:
    error = _result_mapping(body.get("error"), "error")
    if error.get("category") != body.get("status"):
        raise FramingError("Result error category does not match the final status.")


def _validate_prepared_result_owner(body: Mapping[str, Any]) -> None:
    identity = _result_mapping(body.get("backend_identity"), "backend identity")
    if backend_identity_digest(identity) != body.get("backend_identity_digest"):
        raise FramingError("Result backend identity does not match its complete owner.")
    for result_field, identity_field in (
        ("worker_executable_digest", "worker_executable_digest"),
        ("worker_code_digest", "worker_code_digest"),
        ("backend_source_digest", "backend_source_digest"),
        ("environment_digest", "environment_digest"),
    ):
        if body.get(result_field) != identity.get(identity_field):
            raise FramingError("Result backend component identity is detached.")

    cache_value = body.get("cache_lineage")
    if cache_value is None:
        return
    cache_lineage = _result_mapping(cache_value, "cache lineage")
    preimage = _closed_copy(cache_lineage)
    try:
        supplied = preimage.pop("cache_verification_digest")
    except KeyError:
        raise FramingError("Result cache lineage has no verification identity.") from None
    expected = structured_sha256("ebm-audit/cache-lineage-verification/1", preimage)
    if supplied != expected:
        raise FramingError("Result cache lineage does not match its complete owner.")
    chain_keys = cache_lineage.get("chain_cache_keys")
    if not isinstance(chain_keys, list) or len(chain_keys) != len(set(chain_keys)):
        raise FramingError("Result cache lineage repeats a chain cache identity.")


def _is_profile_unobserved_core_failure_reference(
    evidence: Mapping[str, Any],
) -> bool:
    return (
        evidence.get("evidence_reference_schema_version")
        == "ebm-audit-profile-fit-unobserved-core-failure-reference/1.0"
        and evidence.get("kind") == "PROFILE_UNOBSERVED_CORE_FAILURE"
    )


def _validate_profile_result_owner(
    body: Mapping[str, Any],
    fit_evidence: Sequence[Mapping[str, Any]],
) -> None:
    """Reprove the closed profile-only no-storage and no-retry branch."""

    if (
        body.get("execution_origin") != "PROFILE"
        or body.get("cache_lineage") is not None
        or len(fit_evidence) != 3
        or [attempt.get("chain_plan_position") for attempt in fit_evidence] != [0, 1, 2]
        or [attempt.get("attempt_ordinal") for attempt in fit_evidence] != [0, 0, 0]
    ):
        raise FramingError(
            "Profile result evidence must contain three exact attempt-zero fit terminals."
        )
    chain_execution_ids = [attempt.get("chain_execution_id") for attempt in fit_evidence]
    attempt_ids = [attempt.get("attempt_id") for attempt in fit_evidence]
    if (
        any(not isinstance(value, str) for value in chain_execution_ids)
        or any(not isinstance(value, str) for value in attempt_ids)
        or len(set(chain_execution_ids)) != 3
        or len(set(attempt_ids)) != 3
    ):
        raise FramingError("Profile result fit terminals repeat or omit an exact owner.")

    expected_profile_ids = (
        "characterization_2000",
        "characterization_5000",
        "characterization_10000",
    )
    candidate_ordinal = body.get("candidate_ordinal")
    universe_id = body.get("universe_id")
    for attempt in fit_evidence:
        if not _is_profile_unobserved_core_failure_reference(attempt):
            continue
        runtime_position = attempt.get("runtime_position")
        runtime_profile_position = attempt.get("runtime_profile_position")
        chain_plan_position = attempt.get("chain_plan_position")
        expected_chain_id = (
            f"chain-{chain_plan_position:04d}"
            if isinstance(chain_plan_position, int)
            and not isinstance(chain_plan_position, bool)
            and chain_plan_position in {0, 1, 2}
            else None
        )
        expected_attempt_id = structured_sha256(
            "ebm-audit/chain-attempt/3",
            {
                "chain_execution_id": attempt.get("chain_execution_id"),
                "attempt_ordinal": 0,
            },
        )
        if (
            not isinstance(candidate_ordinal, int)
            or isinstance(candidate_ordinal, bool)
            or candidate_ordinal not in {0, 1, 2}
            or attempt.get("candidate_ordinal") != candidate_ordinal
            or attempt.get("profile_id") != expected_profile_ids[candidate_ordinal]
            or attempt.get("universe_id") != universe_id
            or not isinstance(runtime_position, int)
            or isinstance(runtime_position, bool)
            or not isinstance(runtime_profile_position, int)
            or isinstance(runtime_profile_position, bool)
            or runtime_profile_position not in {0, 1, 2}
            or not isinstance(chain_plan_position, int)
            or isinstance(chain_plan_position, bool)
            or chain_plan_position not in {0, 1, 2}
            or runtime_position != (runtime_profile_position * 3) + chain_plan_position
            or attempt.get("chain_id") != expected_chain_id
            or attempt.get("attempt_id") != expected_attempt_id
            or attempt.get("failure_code") != "PROFILE_FIT.UNOBSERVED_CORE_FAILURE"
        ):
            raise FramingError(
                "Profile unobserved-core failure is detached from its exact fit slot."
            )

    observations = _result_sequence(
        body.get("profile_storage_observations"),
        "profile storage observations",
    )
    if (
        [observation.get("resource") for observation in observations] != ["CACHE", "CHECKPOINT"]
        or len({observation.get("execution_policy_digest") for observation in observations}) != 1
        or len({observation.get("guard_receipt_digest") for observation in observations}) != 1
    ):
        raise FramingError(
            "Profile storage evidence must contain exact CACHE then CHECKPOINT observations."
        )
    for observation in observations:
        preimage = _closed_copy(observation)
        try:
            supplied_digest = preimage.pop("observation_digest")
        except KeyError:
            raise FramingError("Profile storage observation has no identity.") from None
        if (
            observation.get("policy") != "NO_READ_NO_WRITE"
            or (observation.get("read_count"), observation.get("write_count")) != (0, 0)
            or observation.get("candidate_ordinal") != candidate_ordinal
            or observation.get("candidate_id") != body.get("candidate_id")
            or observation.get("analysis_spec_id") != body.get("analysis_spec_id")
            or observation.get("universe_id") != universe_id
            or observation.get("covered_chain_execution_ids") != chain_execution_ids
            or observation.get("covered_attempt_ids") != attempt_ids
            or supplied_digest
            != structured_sha256("ebm-audit/profile-storage-observation/1", preimage)
        ):
            raise FramingError(
                "Profile storage observation is detached from its candidate and fit terminals."
            )


def _validate_final_chain_payload(
    chain_result: Mapping[str, Any],
    *,
    body: Mapping[str, Any],
    terminal: Mapping[str, Any],
) -> None:
    preimage = _closed_copy(chain_result)
    try:
        supplied = preimage.pop("chain_payload_digest")
    except KeyError:
        raise FramingError("Scientific chain result has no payload identity.") from None
    expected = structured_sha256("ebm-audit/final-chain-payload/1", preimage)
    if supplied != expected:
        raise FramingError("Scientific chain payload does not match its complete owner.")

    event_ids = chain_result.get("event_ids")
    permutation = chain_result.get("central_order_permutation")
    central_event_ids = chain_result.get("central_order_event_ids")
    if not isinstance(event_ids, list) or not isinstance(permutation, list):
        raise FramingError("Scientific chain result has no ordered event owner.")
    try:
        expected_events = [event_ids[index] for index in permutation]
    except (IndexError, TypeError):
        raise FramingError("Scientific chain result has an invalid event permutation.") from None
    if sorted(permutation) != list(range(len(event_ids))) or central_event_ids != expected_events:
        raise FramingError("Scientific chain central order is detached from its event owner.")

    artifacts = chain_result.get("backend_artifacts")
    if not isinstance(artifacts, list):
        raise FramingError("Scientific chain result has no artifact inventory.")
    artifact_ids = [artifact.get("artifact_id") for artifact in artifacts]
    artifact_paths = [artifact.get("relative_path") for artifact in artifacts]
    if len(artifact_ids) != len(set(artifact_ids)) or len(artifact_paths) != len(
        set(artifact_paths)
    ):
        raise FramingError("Scientific chain result repeats an artifact owner.")
    identity = _result_mapping(body.get("backend_identity"), "backend identity")
    artifact_owner_fields = {
        "creating_scientific_request_digest": terminal.get("scientific_request_digest"),
        "adapter_id": identity.get("adapter_id"),
        "algorithm_id": identity.get("algorithm_id"),
        "worker_executable_digest": body.get("worker_executable_digest"),
        "worker_code_digest": body.get("worker_code_digest"),
        "backend_source_digest": body.get("backend_source_digest"),
        "environment_digest": body.get("environment_digest"),
        "settings_digest": body.get("settings_digest"),
    }
    for artifact in artifacts:
        if (
            artifact.get("creating_chain_execution_id") != chain_result.get("chain_execution_id")
            or artifact.get("event_ids") != event_ids
            or artifact.get("stage_semantics_digest") != chain_result.get("stage_semantics_digest")
            or any(
                artifact.get(field) != expected for field, expected in artifact_owner_fields.items()
            )
        ):
            raise FramingError("Scientific chain artifact is detached from its chain owner.")


def _validate_convergence_sampling_bindings(
    body: Mapping[str, Any],
    chain_results: Sequence[Mapping[str, Any]],
) -> None:
    convergence = _result_mapping(body.get("convergence"), "convergence record")
    rows = _result_sequence(
        convergence.get("sampling_accounting_by_chain"),
        "convergence sampling accounting",
    )
    sampling_chains: list[Mapping[str, Any]] = []
    for chain in chain_results:
        schedule = (
            chain.get("raw_iteration_count"),
            chain.get("burn_in_count"),
            chain.get("thinning_interval"),
            chain.get("postburn_unthinned_state_count"),
            chain.get("retained_state_count"),
        )
        if all(value is None for value in schedule):
            arrays = _result_mapping(chain.get("arrays"), "chain array catalog")
            if "postburn_order_state_chain" in arrays:
                raise FramingError("A non-sampling chain retained sampling evidence.")
            continue
        if any(value is None for value in schedule):
            raise FramingError("Scientific chain sampling accounting is incomplete.")
        sampling_chains.append(chain)

    if len(rows) != len(sampling_chains):
        raise FramingError(
            "Convergence sampling accounting does not cover the exact sampling chains."
        )
    for row, chain in zip(rows, sampling_chains, strict=True):
        arrays = _result_mapping(chain.get("arrays"), "chain array catalog")
        has_order_states = "postburn_order_state_chain" in arrays
        if row.get("chain_execution_id") != chain.get("chain_execution_id") or row.get(
            "thinning_interval"
        ) != chain.get("thinning_interval"):
            raise FramingError("Convergence sampling accounting is detached from its chain owner.")
        if has_order_states and row.get("order_state_status") == "MISSING":
            raise FramingError("Convergence omitted an owned order-state artifact.")
        if not has_order_states and row.get("order_state_status") != "MISSING":
            raise FramingError("Convergence claims an order-state artifact that is absent.")
        if row.get("order_state_status") == "VALID" and (
            row.get("postburn_unthinned_state_count") != chain.get("postburn_unthinned_state_count")
            or row.get("retained_state_count") != chain.get("retained_state_count")
        ):
            raise FramingError("Convergence sampling counts differ from the final chain payload.")


def _validate_chain_result_bindings(
    body: Mapping[str, Any], terminals: Sequence[Mapping[str, Any]]
) -> None:
    chain_results = _result_sequence(body.get("chain_results"), "chain results")
    if len(chain_results) != len(terminals) or not chain_results:
        raise FramingError(
            "Scientific finalization requires one chain result per terminal fit chain."
        )
    for position, (chain_result, terminal) in enumerate(zip(chain_results, terminals, strict=True)):
        _validate_final_chain_payload(chain_result, body=body, terminal=terminal)
        if (
            chain_result.get("chain_plan_position") != position
            or chain_result.get("chain_execution_id") != terminal.get("chain_execution_id")
            or chain_result.get("final_attempt_id") != terminal.get("attempt_id")
        ):
            raise FramingError("A scientific chain result is detached from its final attempt.")
        if chain_result.get("event_ids") != body.get("event_ids"):
            raise FramingError("A scientific chain result has a different event identity.")
    _validate_convergence_sampling_bindings(body, chain_results)
    reference = body.get("reference_chain")
    if reference is None:
        return
    reference_chain = _result_mapping(reference, "reference chain")
    first = chain_results[0]
    if any(
        reference_chain.get(field) != first.get(field)
        for field in (
            "chain_plan_position",
            "chain_execution_id",
            "final_attempt_id",
            "chain_payload_digest",
        )
    ):
        raise FramingError("Reference-chain selection is detached from plan position zero.")


def _validate_result_record_body_finalization(body: Mapping[str, Any]) -> None:
    kind = body.get("record_kind")
    if kind == "UNPREPARED":
        _validate_result_error_category(body)
        status = body.get("status")
        input_digest = body.get("input_digest")
        if status == "INVALID_SPECIFICATION" and input_digest is not None:
            raise FramingError("An invalid pre-canonical result must retain input_digest=null.")
        if status == "UNSUPPORTED_CAPABILITY" and not isinstance(input_digest, str):
            raise FramingError("A valid unsupported result requires canonical input_digest.")
        return

    validation = _result_mapping(body.get("validation_evidence"), "validation evidence")
    _validate_prepared_result_owner(body)
    if validation.get("command") != "validate":
        raise FramingError("Result validation evidence names another command.")
    _validate_core_failure_reference(validation)
    fit_evidence = _result_sequence(body.get("fit_attempt_evidence"), "fit-attempt evidence")
    profile_origin = body.get("execution_origin") == "PROFILE"
    if profile_origin:
        _validate_profile_result_owner(body, fit_evidence)
    terminals = _fit_terminal_evidence(fit_evidence)

    if kind == "EXECUTION_NON_SUCCESS":
        _validate_result_error_category(body)
        failed_command = body.get("failed_command")
        if failed_command == "validate":
            if validation.get("status") == "SUCCESS" or terminals:
                raise FramingError(
                    "Validate-terminal result must contain only exact negative validate evidence."
                )
            if body.get("status") != validation.get("status"):
                raise FramingError("Validate-terminal status does not match its evidence.")
            return
        if failed_command != "fit" or validation.get("status") != "SUCCESS":
            raise FramingError("Fit-terminal result has no successful validate boundary.")
        derived_status = _derived_negative_status(terminals)
        if body.get("status") != derived_status:
            raise FramingError("Fit-terminal status does not match terminal fit evidence.")
        selected_terminal = next(
            terminal for terminal in terminals if terminal.get("status") == derived_status
        )
        if (
            _is_profile_unobserved_core_failure_reference(selected_terminal)
            and _result_mapping(body.get("error"), "error").get("code")
            != "PROFILE_FIT.UNOBSERVED_CORE_FAILURE"
        ):
            raise FramingError("Profile unobserved-core failure lost its fixed result error code.")
        return

    if kind not in {"CONVERGENCE_NON_SUCCESS", "COMPLETED"}:
        raise FramingError("Result finalization has an unknown prepared branch.")
    if validation.get("status") != "SUCCESS" or not terminals:
        raise FramingError("Scientific finalization requires successful validate and fit evidence.")
    if any(terminal.get("status") != "SUCCESS" for terminal in terminals):
        raise FramingError("Convergence cannot finalize a chain with negative fit evidence.")
    _validate_chain_result_bindings(body, terminals)
    if kind == "CONVERGENCE_NON_SUCCESS":
        _validate_result_error_category(body)


def validate_result_record_finalization(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed ResultRecord/2 schema, identity, and evidence state machine."""

    from ebm_audit.metrics.convergence import (
        is_canonical_non_sampling_convergence_record,
    )

    value = _closed_copy(record)
    validate_instance(value, "canonical-records.schema.json", definition="ResultRecord")
    body = _result_mapping(value.get("body"), "body")
    if (
        body.get("status") == "SUCCESS"
        and isinstance(body.get("convergence"), Mapping)
        and body["convergence"].get("assessment") == "NOT_APPLICABLE"
        and not is_canonical_non_sampling_convergence_record(body["convergence"])
    ):
        raise FramingError(
            "A successful non-sampling result requires complete canonical convergence evidence."
        )
    _validate_result_record_body_finalization(body)
    preimage = {
        "result_schema_version": value["result_schema_version"],
        "body": value["body"],
    }
    expected = structured_sha256("ebm-audit/result-record/2", preimage)
    if value.get("result_id") != expected:
        raise FramingError("Result record identity does not match its complete final body.")
    cache_lineage = body.get("cache_lineage")
    if isinstance(cache_lineage, Mapping) and cache_lineage.get("source_result_id") == expected:
        raise FramingError("Result cache lineage cannot self-reference its new result.")
    return value


def request_metadata_digest(request: Mapping[str, Any]) -> str:
    preimage = _closed_copy(request)
    preimage.pop("request_metadata_digest", None)
    validate_instance(
        preimage,
        "worker-protocol.schema.json",
        definition="WorkerRequestMetadataDigestPreimage",
    )
    return structured_sha256("ebm-audit/worker-request-metadata/2", preimage)


def response_metadata_digest(response: Mapping[str, Any]) -> str:
    preimage = _closed_copy(response)
    preimage.pop("response_metadata_digest", None)
    validate_instance(
        preimage,
        "worker-protocol.schema.json",
        definition="WorkerResponseMetadataDigestPreimage",
    )
    return structured_sha256("ebm-audit/worker-response-metadata/2", preimage)


def _bind_or_verify(
    document: dict[str, Any],
    field: str,
    expected: str | None,
) -> None:
    supplied = document.get(field)
    if supplied is not None and not hmac.compare_digest(str(supplied), str(expected)):
        raise FramingError("Supplied protocol digest does not match its exact owner.")
    document[field] = expected


def bind_request_digests(request: Mapping[str, Any]) -> dict[str, Any]:
    """Bind or verify scientific then request-metadata identities in order."""

    bound = _closed_copy(request)
    validate_request_execution_input_binding(bound)
    _bind_or_verify(bound, "scientific_request_digest", scientific_request_digest(bound))
    _bind_or_verify(bound, "request_metadata_digest", request_metadata_digest(bound))
    validate_instance(bound, "worker-protocol.schema.json", definition="WorkerRequest")
    return bound


def bind_response_metadata_digest(response: Mapping[str, Any]) -> dict[str, Any]:
    """Bind or verify the one wire response metadata identity."""

    bound = _closed_copy(response)
    _bind_or_verify(bound, "response_metadata_digest", response_metadata_digest(bound))
    validate_instance(bound, "worker-protocol.schema.json", definition="WorkerResponse")
    return bound
