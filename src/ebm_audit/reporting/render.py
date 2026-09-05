"""Fail-closed reporting from exact in-process science-v2 evidence."""

from __future__ import annotations

import copy
import csv
import html
import io
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, NoReturn, SupportsIndex, cast
from weakref import WeakKeyDictionary

from ebm_audit.adapters.invocation import _readback_authenticated_execution
from ebm_audit.artifacts import PrivateArtifactStore
from ebm_audit.baseline.reproduction import (
    BASELINE_COMPARISON_IDS,
    VerifiedBaselineAssessment,
    VerifiedBaselineReproduction,
)
from ebm_audit.baseline.workflow import (
    BASELINE_ASSESSMENT_ARTIFACT_PATH,
    BASELINE_REPRODUCTION_ARTIFACT_PATH,
    derive_verified_baseline_outcome,
    verified_baseline_records,
)
from ebm_audit.errors import UnexpectedCoreError
from ebm_audit.evaluator.meaning_evidence_bundle import (
    AuthenticatedMeaningEvidenceExtension,
    issue_default_meaning_evidence_extension,
    read_authenticated_meaning_evidence_extension,
    validate_frozen_meaning_record,
    validate_meaning_extension_science_join,
)
from ebm_audit.evaluator.report_claim_projection import REPORT_CLAIM_DIRECTIVES
from ebm_audit.lifecycle import (
    classify_candidate_execution,
    project_candidate_execution_disposition,
)
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.results import SealedResultEvidenceSet
from ebm_audit.results.finalization import (
    _finalized_result_descriptive_chain_executions_from_state,
)
from ebm_audit.results.persistence import (
    _read_persisted_result,
    _read_persisted_result_and_finalized_state,
    _sealed_result_evidence_run,
)
from ebm_audit.schema import (
    SchemaValidationError,
    load_protocol_registry,
    validate_instance,
)
from ebm_audit.science import (
    CapturedScientificRun,
    SealedScientificEvidence,
    capture_scientific_run,
    project_scientific_evidence,
    seal_scientific_evidence,
)
from ebm_audit.science._influence_evidence import _validate_influence_semantics
from ebm_audit.science._null_evidence import _validate_null_semantics
from ebm_audit.science._origin_comparisons import (
    _validate_analyst_decision_semantics,
)
from ebm_audit.science._sampling_evidence import _validate_sampling_semantics
from ebm_audit.science.capture import (
    _read_captured_scientific_run,
    _read_private_stage_comparison_evidence,
    _read_sealed_scientific_evidence,
)

from ._report_model_artifact_binding import (
    AuthenticatedReportModelArtifactBinding,
    _issue_report_model_artifact_binding,
    _read_authenticated_report_model,
    _validated_binding_projection,
)
from .claims import (
    INFLUENCE_CAVEAT,
    MANDATORY_OPENING,
    NULL_SAFE_FALLBACK,
    REPORT_LANGUAGE_RULE_ID,
    assert_claims_allowed,
)
from .summary import decision_summary_html

if TYPE_CHECKING:
    from ebm_audit.synthetic.authority import ScenarioAuthority
    from ebm_audit.synthetic.development_null import (
        SealedDevelopmentNullScienceReceipt,
    )
    from ebm_audit.synthetic.models import ResolvedSyntheticCase

REPORT_V1_UNAVAILABLE_REASON = "PERSISTED_SCIENCE_V2_REHYDRATION_UNAVAILABLE"
REPORT_SCHEMA_VERSION = "ebm-audit-report/14.0"
CURRENT_REPORT_STATUS = "INCOMPLETE"

_AUDIT_CHECK_ORDER = (
    "baseline-reproduction",
    "within-fit-order-uncertainty",
    "independent-chain-stability",
    "sampling-stability",
    "analysis-choice-sensitivity",
    "pairwise-precedence",
    "participant-influence",
    "participant-stage-stability",
    "null-no-signal-comparison",
)
_REPORT_OUTPUT_ORDER = (
    "pairwise_precedence",
    "training_stage_posterior",
    "training_hard_stages",
    "training_expected_stage",
)
_TRAINING_STAGE_OUTPUTS = (
    ("posterior", "training_stage_posterior"),
    ("hard_stage", "training_hard_stages"),
    ("expected_stage", "training_expected_stage"),
)

_REPORT_PREDICATE_ORDER = (
    "KNOWN_POOR_ORDER_RECOVERY/v1",
    "KNOWN_POOR_STAGE_RECOVERY/v1",
    "KNOWN_POOR_RECOVERY/v1",
    "PRECISE_ORDER_OUTPUT/v1",
    "FORCED_PRECISION/v1",
    "INELIGIBLE_STRONG_LABEL/v1",
    "COVERAGE_LIMITATION_REPORTED/v1",
    "forced-precision-report-predicate/1",
    "coverage-limitation-report-predicate/1",
    "within-pair-precision-report-predicate/1",
    "bad-data-report-predicate/1",
    "correlated-within-pair-report/1",
    "partial-truth-scoring-report/1",
    "exact-duplicate-within-pair-report/1",
    "single-sequence-limitation-report/1",
    "precision-report-predicate/1",
    "block-scoring-report-predicate/1",
    "boundary-attribution-report/1",
    "threshold-selection-report/1",
    "direction-sensitivity-report/1",
    "direction-validity-report/1",
    "null-calibration-report/1",
    "fpr-denominator-report/1",
)

_REPORT_ARTIFACT_PATHS = (
    "evidence/scientific-evidence-projection.json",
    "report/report.json",
    "report/universes.csv",
    "report/meaning-evidence.csv",
    "report/provenance.csv",
    "report/report.html",
)
_DEVELOPMENT_NULL_SCIENCE_RECEIPT_PATH = "evidence/development-null-science-receipt.json"
_PRIVATE_STAGE_EVIDENCE_DIRECTORY = "private/science/participant-stage-comparisons"
_UNCERTAINTY_LAYER_ORDER = (
    "WITHIN_FIT",
    "CHAIN",
    "SAMPLING",
    "ANALYST_DECISION",
    "PARTICIPANT_INFLUENCE",
    "NULL",
)
_UNCERTAINTY_LAYER_COVERAGE_RULE_ID = "science-v2-uncertainty-layer-coverage/3"
_SECTION_TITLES = (
    ("scope", "What this audit can and cannot establish"),
    ("dataset-and-specification", "Dataset and specification summary"),
    ("data-accounting", "Data and preprocessing accounting"),
    ("baseline", "Baseline fit and diagnostics"),
    ("within-fit", "Within-fit order uncertainty"),
    ("chain", "Independent-chain and seed stability"),
    ("sampling", "Sampling and bootstrap stability"),
    ("analysis-choice", "Analysis-choice sensitivity"),
    ("pairwise-precedence", "Pairwise precedence"),
    ("participant-influence", "Participant influence"),
    ("participant-stage", "Participant-stage stability"),
    ("null", "Null and no-signal comparison"),
    ("terminal-universes", "Failed, invalid, and unsupported universes"),
    ("methods", "Methods and metric definitions"),
    ("provenance", "Provenance, backend, benchmark, and limitations"),
)
_LAYER_BY_SECTION = {
    "within-fit": "WITHIN_FIT",
    "chain": "CHAIN",
    "sampling": "SAMPLING",
    "analysis-choice": "ANALYST_DECISION",
    "pairwise-precedence": "ANALYST_DECISION",
    "participant-influence": "PARTICIPANT_INFLUENCE",
    "null": "NULL",
}
_FIXED_SECTION_STATUS = {
    "scope": ("AVAILABLE_WITH_LIMITS", ()),
    "dataset-and-specification": (
        "PARTIAL",
        ("REPORT.DATASET_DETAIL_AUTHORITY_PENDING",),
    ),
    "data-accounting": (
        "PARTIAL",
        ("REPORT.FIELD_ACCOUNTING_AUTHORITY_PENDING",),
    ),
    "terminal-universes": ("AVAILABLE", ()),
    "methods": ("PARTIAL", ("REPORT.METRIC_CATALOGUE_COMPLETION_PENDING",)),
    "provenance": (
        "PARTIAL",
        (
            "REPORT.BACKEND_PROVENANCE_PROJECTION_PENDING",
            "REPORT.BENCHMARK_AUTHORITY_PENDING",
        ),
    ),
}
_BASELINE_OUTCOME_ORDER = (
    "MATCH",
    "MISMATCH",
    "NOT_COMPARABLE",
    "NOT_SUPPLIED",
    "NOT_REQUIRED",
)
_BASELINE_LANGUAGE = {
    "BASELINE_REPRODUCED": (
        "The supplied canonical baseline was reproduced under the exact declared "
        "comparison contract. This permits validated baseline language for this run, "
        "but does not establish biological truth or a recoverable disease-order signal."
    ),
    "BASELINE_PARTIALLY_REPRODUCED": (
        "The supplied canonical baseline was only partially reproduced. Baseline "
        "language remains unavailable, and the results below describe only the connected "
        "model and configuration."
    ),
    "BASELINE_NOT_REPRODUCED": (
        "The supplied canonical baseline was not reproduced under the exact declared "
        "comparison contract. The results below must not be attributed to the supplied "
        "reference analysis."
    ),
    "BASELINE_REFERENCE_NOT_SUPPLIED": (
        "No canonical baseline reference was supplied. The results below describe only "
        "the connected model and configuration."
    ),
    "BASELINE_NOT_ASSESSABLE": (
        "The declared baseline candidate did not finish successfully, so baseline "
        "reproduction was not assessable. The results below retain that limitation."
    ),
}


class ReportUnavailableError(Exception):
    """Typed public refusal while persisted science-v2 rehydration is absent."""

    code = "REPORT.V1_DISABLED"
    reason = REPORT_V1_UNAVAILABLE_REASON
    safe_message = (
        "Standalone report generation is disabled until persisted exact "
        "science-v2 evidence can own every report conclusion."
    )

    def __init__(self) -> None:
        super().__init__(self.safe_message)


def render_report_from_run_dir(run_dir: Path, output_dir: Path) -> NoReturn:
    """Refuse cross-process reporting before inspecting either supplied path."""

    del run_dir, output_dir
    raise ReportUnavailableError()


def _report_contract_error() -> UnexpectedCoreError:
    return UnexpectedCoreError(
        "REPORT.OUTPUT_CONTRACT",
        "The local report did not satisfy its closed output contract.",
    )


def _require_mapping(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise _report_contract_error()
    return cast(dict[str, Any], value)


def _require_string(value: object) -> str:
    if type(value) is not str:
        raise _report_contract_error()
    return value


def _require_bare_sha256(value: object) -> str:
    digest = _require_string(value)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise _report_contract_error()
    return digest


def _require_prefixed_sha256(value: object) -> str:
    digest = _require_string(value)
    if not digest.startswith("sha256:"):
        raise _report_contract_error()
    _require_bare_sha256(digest.removeprefix("sha256:"))
    return digest


def _require_ordered_bare_sha256s(value: object) -> tuple[str, ...]:
    if type(value) is not list:
        raise _report_contract_error()
    digests = tuple(_require_bare_sha256(item) for item in cast(list[object], value))
    if len(set(digests)) != len(digests):
        raise _report_contract_error()
    return digests


def _baseline_report_projection(
    assessment_record: Mapping[str, Any],
    reproduction_record: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Reduce exact baseline records to a closed, identifier-free report view."""

    assessment_status = _require_string(assessment_record.get("status"))
    terminal = _require_mapping(assessment_record.get("baseline_terminal"))
    terminal_status = _require_string(terminal.get("final_status"))
    eligibility = assessment_record.get("validated_language_eligibility")
    reason_codes = assessment_record.get("reason_codes")
    if (
        assessment_status not in _BASELINE_LANGUAGE
        or type(eligibility) is not bool
        or type(reason_codes) is not list
        or any(type(reason) is not str for reason in reason_codes)
        or (assessment_status == "BASELINE_REPRODUCED") is not eligibility
    ):
        raise _report_contract_error()

    comparison_outcomes: list[dict[str, str]] = []
    reference_presence = "NOT_APPLICABLE"
    reproduction_status: str | None = None
    if reproduction_record is None:
        if terminal_status == "SUCCESS":
            raise _report_contract_error()
    else:
        if terminal_status != "SUCCESS":
            raise _report_contract_error()
        reproduction_status = _require_string(reproduction_record.get("status"))
        reference_presence = _require_string(reproduction_record.get("reference_presence"))
        comparisons = reproduction_record.get("ordered_comparisons")
        reproduction_reasons = reproduction_record.get("reason_codes")
        if (
            reproduction_status != assessment_status
            or reference_presence not in {"SUPPLIED", "NOT_SUPPLIED"}
            or reproduction_record.get("validated_language_eligibility") is not eligibility
            or reproduction_reasons != reason_codes
            or type(comparisons) is not list
            or len(comparisons) != 9
        ):
            raise _report_contract_error()
        for expected_id, value in zip(
            BASELINE_COMPARISON_IDS,
            comparisons,
            strict=True,
        ):
            comparison = _require_mapping(value)
            comparison_id = _require_string(comparison.get("comparison_id"))
            outcome = _require_string(comparison.get("outcome"))
            if comparison_id != expected_id or outcome not in _BASELINE_OUTCOME_ORDER:
                raise _report_contract_error()
            comparison_outcomes.append(
                {
                    "comparison_id": comparison_id,
                    "outcome": outcome,
                }
            )

    projection = {
        "assessment_status": assessment_status,
        "baseline_terminal_status": terminal_status,
        "reference_presence": reference_presence,
        "reproduction_status": reproduction_status,
        "validated_language_eligibility": eligibility,
        "reason_codes": list(cast(list[str], reason_codes)),
        "comparison_outcomes": comparison_outcomes,
    }
    assert_no_direct_identifier_fields(projection)
    return projection


def _verify_store_owns_evidence(
    store: PrivateArtifactStore,
    evidence: SealedResultEvidenceSet,
) -> None:
    if type(store) is not PrivateArtifactStore or type(evidence) is not SealedResultEvidenceSet:
        raise TypeError(
            "Incomplete reporting requires exact artifact-store and result-evidence authorities."
        )
    run = _sealed_result_evidence_run(evidence)
    if not run.persisted_results or any(
        _read_persisted_result(persisted).store is not store for persisted in run.persisted_results
    ):
        raise TypeError(
            "Incomplete reporting requires evidence persisted by the supplied artifact store."
        )


def _projection_synthetic_case_binding(
    projection: Mapping[str, Any],
) -> dict[str, str] | None:
    value = projection.get("synthetic_case_binding")
    if value is None:
        return None
    binding = _require_mapping(value)
    if set(binding) != {
        "case_id",
        "source_contract_sha256",
        "scenario_definitions_sha256",
    }:
        raise _report_contract_error()
    return {
        "case_id": _require_string(binding.get("case_id")),
        "source_contract_sha256": _require_string(binding.get("source_contract_sha256")),
        "scenario_definitions_sha256": _require_string(
            binding.get("scenario_definitions_sha256")
        ),
    }


def _report_synthetic_case_binding(
    projection: Mapping[str, Any],
) -> dict[str, str] | None:
    binding = _projection_synthetic_case_binding(projection)
    if binding is None:
        return None
    return {
        "case_id": binding["case_id"],
        "source_contract_sha256": f"sha256:{binding['source_contract_sha256']}",
        "scenario_definitions_sha256": f"sha256:{binding['scenario_definitions_sha256']}",
    }


def _project_candidate_binds_report_synthetic_case(
    provenance: Mapping[str, Any],
    binding: Mapping[str, str],
) -> bool:
    """Require one candidate-specific provenance record to bind the sealed case."""

    project_candidate = provenance.get("project_candidate")
    return (
        type(project_candidate) is dict
        and provenance.get("complete_truth_record_id") == binding.get("case_id")
        and project_candidate.get("case_id") == binding.get("case_id")
        and project_candidate.get("source_contract_sha256")
        == binding.get("source_contract_sha256")
        and project_candidate.get("scenario_definitions_sha256")
        == binding.get("scenario_definitions_sha256")
    )


def _classify_sealed_input_declaration(
    candidate_terminals: Sequence[Mapping[str, Any]],
    persisted_record_bytes: Sequence[bytes],
    projection: Mapping[str, Any],
) -> str:
    """Classify exact persisted provenance against its sealed science projection."""

    synthetic_case_binding = _report_synthetic_case_binding(projection)
    retained_provenance: bytes | None = None
    saw_present_provenance = False
    saw_missing_provenance = False
    all_successful = True
    if not persisted_record_bytes or len(persisted_record_bytes) != len(candidate_terminals):
        if synthetic_case_binding is not None:
            raise _report_contract_error()
        return "PRIVATE_LOCAL_INPUT"
    for terminal, canonical_bytes in zip(
        candidate_terminals,
        persisted_record_bytes,
        strict=True,
    ):
        record = strict_json_loads(canonical_bytes)
        if type(record) is not dict or type(record.get("body")) is not dict:
            raise _report_contract_error()
        body = cast(dict[str, Any], record["body"])
        terminal_successful = terminal.get("final_status") == "SUCCESS"
        body_successful = body.get("status") == "SUCCESS"
        if terminal_successful != body_successful:
            raise _report_contract_error()
        all_successful = all_successful and terminal_successful
        provenance = body.get("synthetic_provenance")
        if provenance is None:
            saw_missing_provenance = True
            continue
        saw_present_provenance = True
        if type(provenance) is not dict:
            raise _report_contract_error()
        try:
            validate_instance(
                provenance,
                "canonical-records.schema.json",
                definition="SyntheticProvenance",
            )
        except SchemaValidationError:
            raise _report_contract_error() from None
        if terminal_successful and provenance.get("event_ids") != body.get("event_ids"):
            raise _report_contract_error()
        provenance_bytes = canonical_json_bytes(provenance)
        if retained_provenance is None:
            retained_provenance = provenance_bytes
        elif synthetic_case_binding is None and provenance_bytes != retained_provenance:
            raise _report_contract_error()
        if synthetic_case_binding is not None and not (
            _project_candidate_binds_report_synthetic_case(
                provenance,
                synthetic_case_binding,
            )
        ):
            raise _report_contract_error()
    if saw_present_provenance and saw_missing_provenance:
        raise _report_contract_error()
    declaration = (
        "DECLARED_SYNTHETIC"
        if all_successful
        and (retained_provenance is not None or synthetic_case_binding is not None)
        else "PRIVATE_LOCAL_INPUT"
    )
    return declaration


def _sealed_input_declaration(
    evidence: SealedResultEvidenceSet,
    projection: Mapping[str, Any],
) -> str:
    """Classify only exact persisted provenance and its owned sealed science."""

    run = _sealed_result_evidence_run(evidence)
    return _classify_sealed_input_declaration(
        run.candidate_terminals,
        tuple(
            _read_persisted_result(persisted).canonical_bytes
            for persisted in run.persisted_results
        ),
        projection,
    )


def _validate_public_layer(
    projection: Mapping[str, Any],
    *,
    field: str,
    schema_name: str,
    definition: str,
    validator: Callable[[dict[str, object]], None],
    layer_field: str,
    expected_layer: str,
) -> dict[str, Any]:
    layer = _require_mapping(projection.get(field))
    try:
        validate_instance(layer, schema_name, definition=definition)
        validator(layer)
    except (SchemaValidationError, TypeError, ValueError, OverflowError):
        raise _report_contract_error() from None
    if (
        layer.get(layer_field) != expected_layer
        or layer.get("plan_digest") != projection.get("plan_digest")
        or layer.get("terminal_index_digest") != projection.get("terminal_index_digest")
    ):
        raise _report_contract_error()
    return layer


def _contribution_counts(
    attempts: object,
    *,
    allowed: frozenset[str],
) -> dict[str, int]:
    if type(attempts) is not list:
        raise _report_contract_error()
    counts = {state: 0 for state in allowed}
    for attempt_value in attempts:
        attempt = _require_mapping(attempt_value)
        state = attempt.get("contribution_state")
        if type(state) is not str or state not in allowed:
            raise _report_contract_error()
        counts[state] += 1
    return counts


def _component_implementation_status(
    component_coverage: object,
    *,
    pending_reason: str,
) -> tuple[str, str | None]:
    if type(component_coverage) is not list or not component_coverage:
        raise _report_contract_error()
    statuses: list[str] = []
    for value in component_coverage:
        component = _require_mapping(value)
        status = component.get("implementation_status")
        reason = component.get("reason_code")
        if (
            type(status) is not str
            or status not in {"IMPLEMENTED", "PENDING_IMPLEMENTATION"}
            or (status == "IMPLEMENTED" and reason is not None)
            or (status == "PENDING_IMPLEMENTATION" and (type(reason) is not str or not reason))
        ):
            raise _report_contract_error()
        statuses.append(status)
    if all(status == "IMPLEMENTED" for status in statuses):
        return "IMPLEMENTED", None
    return "PARTIALLY_IMPLEMENTED", pending_reason


def _layer_rows(projection: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    candidates = _candidate_rows(projection)
    sampling = _validate_public_layer(
        projection,
        field="sampling_evidence",
        schema_name="sampling-evidence.schema.json",
        definition="SamplingLayerEvidence",
        validator=_validate_sampling_semantics,
        layer_field="uncertainty_layer",
        expected_layer="SAMPLING",
    )
    analyst = _validate_public_layer(
        projection,
        field="analyst_decision_evidence",
        schema_name="analyst-decision-evidence.schema.json",
        definition="AnalystDecisionLayerEvidence",
        validator=_validate_analyst_decision_semantics,
        layer_field="layer",
        expected_layer="ANALYST_DECISION",
    )
    influence = _validate_public_layer(
        projection,
        field="participant_influence_evidence",
        schema_name="influence-evidence.schema.json",
        definition="InfluenceLayerEvidence",
        validator=_validate_influence_semantics,
        layer_field="uncertainty_layer",
        expected_layer="PARTICIPANT_INFLUENCE",
    )
    null = _validate_public_layer(
        projection,
        field="null_evidence",
        schema_name="null-evidence.schema.json",
        definition="NullLayerEvidence",
        validator=_validate_null_semantics,
        layer_field="uncertainty_layer",
        expected_layer="NULL",
    )

    coverage = _require_mapping(projection.get("uncertainty_layer_coverage"))
    rows = coverage.get("layers")
    if (
        set(coverage) != {"rule_id", "layers", "coverage_digest"}
        or coverage.get("rule_id") != _UNCERTAINTY_LAYER_COVERAGE_RULE_ID
        or type(rows) is not list
        or len(rows) != len(_UNCERTAINTY_LAYER_ORDER)
        or coverage.get("coverage_digest")
        != structured_sha256(
            "ebm-audit/uncertainty-layer-coverage/3",
            {
                "rule_id": _UNCERTAINTY_LAYER_COVERAGE_RULE_ID,
                "layers": rows,
            },
        )
    ):
        raise _report_contract_error()
    exact_rows = tuple(_require_mapping(value) for value in rows)
    if tuple(row.get("layer") for row in exact_rows) != _UNCERTAINTY_LAYER_ORDER:
        raise _report_contract_error()

    candidate_coverage: dict[str, list[dict[str, Any]]] = {}
    for layer, status_field, reason_field in (
        ("WITHIN_FIT", "within_fit_status", "within_fit_reason_code"),
        ("CHAIN", "chain_status", "chain_reason_code"),
    ):
        candidate_coverage[layer] = [
            {
                "candidate_ordinal": candidate["candidate_ordinal"],
                "status": candidate[status_field],
                "reason_code": candidate[reason_field],
            }
            for candidate in candidates
        ]
    influence_expected = {
        field: copy.deepcopy(influence[field])
        for field in (
            "layer_digest",
            "planned_origin_count",
            "attempt_count",
            "influence_record_count",
            "contribution_counts",
            "classification_status",
        )
    }
    null_expected = {
        field: copy.deepcopy(null[field])
        for field in (
            "layer_digest",
            "component_coverage",
            "attempt_count",
            "family_count",
            "terminal_status_counts",
            "calibration_state",
            "null_relative_label",
            "held_out_false_positive_rate_eligible",
            "strong_null_relative_language_eligible",
        )
    }
    sampling_status, sampling_reason = _component_implementation_status(
        sampling["component_coverage"],
        pending_reason="SCIENCE.SAMPLING_COMPONENTS_PENDING",
    )
    analyst_status, analyst_reason = _component_implementation_status(
        analyst["component_coverage"],
        pending_reason="SCIENCE.ANALYST_DECISION_COMPONENTS_PENDING",
    )
    if (
        analyst.get("implementation_status") != analyst_status
        or analyst.get("reason_code") != analyst_reason
    ):
        raise _report_contract_error()
    expected_coverage = {
        "WITHIN_FIT": (
            "IMPLEMENTED",
            None,
            candidate_coverage["WITHIN_FIT"],
        ),
        "CHAIN": ("IMPLEMENTED", None, candidate_coverage["CHAIN"]),
        "SAMPLING": (
            sampling_status,
            sampling_reason,
            {
                "layer_digest": sampling["layer_digest"],
                "component_coverage": copy.deepcopy(sampling["component_coverage"]),
            },
        ),
        "ANALYST_DECISION": (
            analyst_status,
            analyst_reason,
            {
                "layer_digest": analyst["layer_digest"],
                "component_coverage": copy.deepcopy(analyst["component_coverage"]),
            },
        ),
        "PARTICIPANT_INFLUENCE": (
            "IMPLEMENTED",
            None,
            influence_expected,
        ),
        "NULL": (
            "PARTIALLY_IMPLEMENTED",
            (
                "NULL_CALIBRATION_NOT_VALIDATED"
                if null["attempt_count"]
                else "SCIENCE.NULL_FAMILIES_NOT_PLANNED"
            ),
            null_expected,
        ),
    }
    for row in exact_rows:
        layer = _require_string(row.get("layer"))
        implementation, reason, evidence = expected_coverage[layer]
        if (
            set(row)
            != {
                "layer",
                "implementation_status",
                "evidence",
                "reason_code",
            }
            or row.get("implementation_status") != implementation
            or row.get("reason_code") != reason
            or row.get("evidence") != evidence
        ):
            raise _report_contract_error()

    sampling_counts = _contribution_counts(
        sampling["attempts"],
        allowed=frozenset(
            {
                "INTERPRETIVE",
                "DESCRIPTIVE_ONLY",
                "METRIC_NOT_ASSESSABLE",
                "FAILED",
            }
        ),
    )
    analyst_accounting = _require_mapping(analyst.get("accounting"))
    influence_counts = _require_mapping(influence.get("contribution_counts"))
    result: list[dict[str, Any]] = []
    for (
        layer,
        implementation,
        reason,
        assessable,
        unavailable,
        not_applicable,
        interpretive,
        descriptive,
        attempt_count,
        numeric_count,
        aggregate_count,
        layer_digest,
        components,
    ) in (
        (
            "WITHIN_FIT",
            "IMPLEMENTED",
            None,
            sum(row["within_fit_status"] == "ASSESSABLE" for row in candidates),
            sum(row["within_fit_status"] == "NOT_ASSESSABLE" for row in candidates),
            sum(row["within_fit_status"] == "NOT_APPLICABLE_BY_CAPABILITY" for row in candidates),
            0,
            0,
            len(candidates),
            len(candidates),
            0,
            None,
            [],
        ),
        (
            "CHAIN",
            "IMPLEMENTED",
            None,
            sum(row["chain_status"] == "ASSESSABLE" for row in candidates),
            sum(row["chain_status"] == "NOT_ASSESSABLE" for row in candidates),
            sum(row["chain_status"] == "NOT_APPLICABLE_BY_CAPABILITY" for row in candidates),
            0,
            0,
            len(candidates),
            len(candidates),
            0,
            None,
            [],
        ),
        (
            "SAMPLING",
            sampling_status,
            sampling_reason,
            sampling_counts["INTERPRETIVE"] + sampling_counts["DESCRIPTIVE_ONLY"],
            sampling_counts["METRIC_NOT_ASSESSABLE"] + sampling_counts["FAILED"],
            0,
            sampling_counts["INTERPRETIVE"],
            sampling_counts["DESCRIPTIVE_ONLY"],
            sampling["attempt_count"],
            sampling["unique_numeric_record_count"],
            sampling["family_count"],
            sampling["layer_digest"],
            sampling["component_coverage"],
        ),
        (
            "ANALYST_DECISION",
            analyst_status,
            analyst_reason,
            analyst_accounting["assessable_origin_count"],
            analyst_accounting["metric_not_assessable_origin_count"]
            + analyst_accounting["failed_origin_count"],
            analyst_accounting["reference_origin_count"]
            + analyst_accounting["not_applicable_origin_count"],
            analyst_accounting["interpretive_origin_count"],
            analyst_accounting["descriptive_only_origin_count"],
            analyst_accounting["planned_origin_count"],
            analyst_accounting["unique_applicable_numeric_pair_count"],
            len(cast(list[object], analyst["aggregates"])),
            analyst["layer_digest"],
            analyst["component_coverage"],
        ),
        (
            "PARTICIPANT_INFLUENCE",
            "IMPLEMENTED",
            None,
            influence_counts["INTERPRETIVE"] + influence_counts["DESCRIPTIVE_ONLY"],
            influence_counts["METRIC_NOT_ASSESSABLE"] + influence_counts["FAILED"],
            0,
            influence_counts["INTERPRETIVE"],
            influence_counts["DESCRIPTIVE_ONLY"],
            influence["attempt_count"],
            influence["influence_record_count"],
            0,
            influence["layer_digest"],
            [],
        ),
        (
            "NULL",
            "PARTIALLY_IMPLEMENTED",
            (
                "NULL_CALIBRATION_NOT_VALIDATED"
                if null["attempt_count"]
                else "SCIENCE.NULL_FAMILIES_NOT_PLANNED"
            ),
            0,
            null["attempt_count"],
            0,
            0,
            0,
            null["attempt_count"],
            0,
            null["family_count"],
            null["layer_digest"],
            null["component_coverage"],
        ),
    ):
        result.append(
            {
                "layer": layer,
                "implementation_status": implementation,
                "reason_code": reason,
                "layer_digest": layer_digest,
                "component_coverage": copy.deepcopy(components),
                "attempt_count": attempt_count,
                "numeric_record_count": numeric_count,
                "aggregate_count": aggregate_count,
                "assessable_record_count": assessable,
                "not_assessable_record_count": unavailable,
                "not_applicable_record_count": not_applicable,
                "interpretive_record_count": interpretive,
                "descriptive_record_count": descriptive,
            }
        )
    return tuple(result)


def _candidate_rows(projection: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    candidates = projection.get("candidate_records")
    if type(candidates) is not list or not candidates:
        raise _report_contract_error()
    rows: list[dict[str, Any]] = []
    for value in candidates:
        candidate = _require_mapping(value)
        within_fit = _require_mapping(candidate.get("within_fit"))
        chain = _require_mapping(candidate.get("chain"))
        ordinal = candidate.get("candidate_ordinal")
        universe_id = candidate.get("universe_id")
        if type(ordinal) is not int or type(ordinal) is bool:
            raise _report_contract_error()
        if universe_id is not None and type(universe_id) is not str:
            raise _report_contract_error()
        within_fit_status = _require_string(within_fit.get("status"))
        within_fit_reason = within_fit.get("reason_code")
        chain_status = _require_string(chain.get("status"))
        chain_reason = chain.get("reason_code")
        if (
            within_fit_status
            not in {
                "ASSESSABLE",
                "NOT_ASSESSABLE",
                "NOT_APPLICABLE_BY_CAPABILITY",
            }
            or chain_status
            not in {
                "ASSESSABLE",
                "NOT_ASSESSABLE",
                "NOT_APPLICABLE_BY_CAPABILITY",
            }
            or (within_fit_status == "ASSESSABLE") != (within_fit_reason is None)
            or (chain_status == "ASSESSABLE") != (chain_reason is None)
            or (within_fit_reason is not None and type(within_fit_reason) is not str)
            or (chain_reason is not None and type(chain_reason) is not str)
        ):
            raise _report_contract_error()
        rows.append(
            {
                "candidate_ordinal": ordinal,
                "candidate_id": _require_string(candidate.get("candidate_id")),
                "analysis_spec_id": _require_string(candidate.get("analysis_spec_id")),
                "universe_id": universe_id,
                "final_status": _require_string(candidate.get("final_status")),
                "eligibility": _require_string(candidate.get("eligibility")),
                "within_fit_status": within_fit_status,
                "within_fit_reason_code": within_fit_reason,
                "chain_status": chain_status,
                "chain_reason_code": chain_reason,
            }
        )
    if [row["candidate_ordinal"] for row in rows] != list(range(len(rows))):
        raise _report_contract_error()
    return tuple(rows)


def _null_evidence(projection: Mapping[str, Any]) -> dict[str, Any]:
    layer = _require_mapping(projection.get("null_evidence"))
    attempts = layer.get("attempts")
    aggregates = layer.get("aggregates")
    attempt_count = layer.get("attempt_count")
    family_count = layer.get("family_count")
    if (
        layer.get("uncertainty_layer") != "NULL"
        or layer.get("pooling_policy") != "NON_POOLABLE"
        or type(attempts) is not list
        or type(aggregates) is not list
        or type(attempt_count) is not int
        or attempt_count < 0
        or attempt_count != len(attempts)
        or type(family_count) is not int
        or family_count < 0
        or family_count != len(aggregates)
        or layer.get("calibration_state") != "UNCALIBRATED"
        or layer.get("null_relative_label") != "NULL_CALIBRATION_NOT_VALIDATED"
        or layer.get("held_out_false_positive_rate_eligible") is not False
        or layer.get("strong_null_relative_language_eligible") is not False
        or layer.get("classification_status") != "NO_FROZEN_NULL_CLASSIFICATION"
    ):
        raise _report_contract_error()
    for attempt_value in attempts:
        attempt = _require_mapping(attempt_value)
        if (
            type(attempt.get("source_analysis_spec_id")) is not str
            or type(attempt.get("source_variant_id")) is not str
            or type(attempt.get("derived_source_variant_id")) is not str
            or type(attempt.get("null_family_id")) is not str
            or type(attempt.get("null_method_id")) is not str
            or type(attempt.get("replicate_ordinal")) is not int
            or cast(int, attempt["replicate_ordinal"]) < 0
            or type(attempt.get("final_status")) is not str
            or type(attempt.get("source_final_status")) is not str
            or attempt.get("refit_preprocessing") is not True
            or attempt.get("calibration_eligible") is not False
            or attempt.get("held_out_false_positive_rate_eligible") is not False
            or attempt.get("strong_null_relative_language_eligible") is not False
        ):
            raise _report_contract_error()
    return dict(layer)


def _validate_participant_stage_projection_row(
    value: object,
) -> dict[str, Any]:
    row = _require_mapping(value)
    try:
        validate_instance(
            row,
            "report.schema.json",
            definition="ParticipantStageComparisonProjection",
        )
    except (SchemaValidationError, ValueError):
        raise _report_contract_error() from None
    if row.get("source_layer") not in {"ANALYST_DECISION", "SAMPLING"}:
        raise _report_contract_error()
    comparison = _require_mapping(row.get("participant_stage_comparison"))
    metric_status = comparison.get("metric_status")
    availability = comparison.get("availability")
    comparability = comparison.get("semantic_comparability")
    metrics = comparison.get("metrics")
    if type(metrics) is not list:
        raise _report_contract_error()
    metric_row_statuses = tuple(
        _require_string(_require_mapping(metric).get("status")) for metric in metrics
    )
    if metric_status == "ASSESSABLE":
        if (
            availability != "AVAILABLE"
            or comparability != "COMPARABLE"
            or any(status != "ASSESSABLE" for status in metric_row_statuses)
        ):
            raise _report_contract_error()
    elif metric_status == "NOT_APPLICABLE_BY_CAPABILITY":
        if availability != "NOT_APPLICABLE_BY_CAPABILITY" or any(
            status != "NOT_APPLICABLE_BY_CAPABILITY" for status in metric_row_statuses
        ):
            raise _report_contract_error()
    elif metric_status == "NOT_ASSESSABLE":
        if any(status != "NOT_ASSESSABLE" for status in metric_row_statuses):
            raise _report_contract_error()
    else:
        raise _report_contract_error()
    return row


def _participant_stage_comparisons(
    projection: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    analyst_decision = _require_mapping(projection.get("analyst_decision_evidence"))
    sampling = _require_mapping(projection.get("sampling_evidence"))
    try:
        validate_instance(
            analyst_decision,
            "analyst-decision-evidence.schema.json",
            definition="AnalystDecisionLayerEvidence",
        )
        validate_instance(
            sampling,
            "sampling-evidence.schema.json",
            definition="SamplingLayerEvidence",
        )
    except (SchemaValidationError, ValueError):
        raise _report_contract_error() from None
    if analyst_decision.get("layer") != "ANALYST_DECISION":
        raise _report_contract_error()
    if sampling.get("uncertainty_layer") != "SAMPLING":
        raise _report_contract_error()
    analyst_numeric_records = analyst_decision.get("numeric_records")
    sampling_numeric_records = sampling.get("numeric_records")
    if type(analyst_numeric_records) is not list or type(sampling_numeric_records) is not list:
        raise _report_contract_error()
    rows: list[dict[str, Any]] = []
    for value in analyst_numeric_records:
        record = _require_mapping(value)
        comparison = _require_mapping(record.get("participant_stage_comparison"))
        row = {
            "source_layer": "ANALYST_DECISION",
            "numeric_comparison_digest": record.get("numeric_comparison_digest"),
            "numeric_identity": copy.deepcopy(record.get("numeric_identity")),
            "eligibility": record.get("eligibility"),
            "subject_terminal_status": record.get("subject_terminal_status"),
            "comparator_terminal_status": record.get("comparator_terminal_status"),
            "participant_stage_comparison": copy.deepcopy(comparison),
        }
        rows.append(_validate_participant_stage_projection_row(row))
    for value in sampling_numeric_records:
        record = _require_mapping(value)
        comparison = _require_mapping(record.get("participant_stage_comparison"))
        row = {
            "source_layer": "SAMPLING",
            "numeric_comparison_digest": record.get("numeric_comparison_digest"),
            "numeric_identity": copy.deepcopy(record.get("numeric_identity")),
            "operation_descriptor": copy.deepcopy(record.get("operation_descriptor")),
            "eligibility": record.get("eligibility"),
            "subject_terminal_status": record.get("subject_terminal_status"),
            "source_terminal_status": record.get("source_terminal_status"),
            "participant_stage_comparison": copy.deepcopy(comparison),
        }
        rows.append(_validate_participant_stage_projection_row(row))
    rows.sort(
        key=lambda row: (
            _require_string(row.get("source_layer")).encode("utf-8"),
            _require_string(
                _require_mapping(row.get("numeric_identity")).get("subject_analysis_spec_id")
            ).encode("utf-8"),
            _require_string(
                _require_mapping(row.get("numeric_identity")).get(
                    "comparator_analysis_spec_id"
                    if row.get("source_layer") == "ANALYST_DECISION"
                    else "source_analysis_spec_id"
                )
            ).encode("utf-8"),
            _require_string(row.get("numeric_comparison_digest")).encode("utf-8"),
        )
    )
    assert_no_direct_identifier_fields(rows)
    return tuple(rows)


def _participant_stage_section_state(
    comparisons: Sequence[Mapping[str, Any]],
) -> tuple[str, tuple[str, ...]]:
    if not comparisons:
        return (
            "NOT_ASSESSABLE",
            ("REPORT.NO_DECLARED_PARTICIPANT_STAGE_COMPARISONS",),
        )
    rows = tuple(_validate_participant_stage_projection_row(row) for row in comparisons)
    assessable_rows = tuple(
        row
        for row in rows
        if _require_mapping(row["participant_stage_comparison"]).get("metric_status")
        == "ASSESSABLE"
    )
    interpretive_assessable_count = sum(
        row.get("eligibility") == "INTERPRETIVE" for row in assessable_rows
    )
    descriptive_assessable_count = sum(
        row.get("eligibility") == "DESCRIPTIVE_ONLY" for row in assessable_rows
    )
    descriptive_row_count = sum(row.get("eligibility") == "DESCRIPTIVE_ONLY" for row in rows)
    if len(assessable_rows) == len(rows) == interpretive_assessable_count:
        return "AVAILABLE", ()
    if len(assessable_rows) != (interpretive_assessable_count + descriptive_assessable_count):
        raise _report_contract_error()

    unavailable_rows = tuple(
        row
        for row in rows
        if _require_mapping(row["participant_stage_comparison"]).get("metric_status")
        != "ASSESSABLE"
    )
    capability_unavailable = any(
        (
            _require_mapping(row["participant_stage_comparison"]).get("metric_status")
            == "NOT_APPLICABLE_BY_CAPABILITY"
            and _require_mapping(row["participant_stage_comparison"]).get("availability")
            == "NOT_APPLICABLE_BY_CAPABILITY"
        )
        for row in unavailable_rows
    )
    semantically_non_equivalent = any(
        _require_mapping(row["participant_stage_comparison"]).get("semantic_comparability")
        == "SEMANTICALLY_NON_EQUIVALENT"
        for row in unavailable_rows
    )
    other_not_assessable = any(
        (
            _require_mapping(row["participant_stage_comparison"]).get("metric_status")
            != "NOT_APPLICABLE_BY_CAPABILITY"
            and _require_mapping(row["participant_stage_comparison"]).get("semantic_comparability")
            != "SEMANTICALLY_NON_EQUIVALENT"
        )
        for row in unavailable_rows
    )

    reasons: list[str] = []
    if descriptive_row_count:
        reasons.append("REPORT.PARTICIPANT_STAGE_DESCRIPTIVE_ONLY_PRESENT")
    if assessable_rows and unavailable_rows:
        reasons.append("REPORT.MIXED_PARTICIPANT_STAGE_ASSESSABILITY")
    if capability_unavailable:
        reasons.append("STAGING.FIXED_COHORT_UNAVAILABLE")
    if semantically_non_equivalent:
        reasons.append("COMPARISON.SEMANTICALLY_NON_EQUIVALENT")
    if other_not_assessable:
        reasons.append("REPORT.PARTICIPANT_STAGE_OTHER_NOT_ASSESSABLE")
    if assessable_rows:
        if not reasons:
            raise _report_contract_error()
        return "PARTIAL", tuple(reasons)
    if not reasons:
        raise _report_contract_error()
    return "NOT_ASSESSABLE", tuple(reasons)


def _applicability_row(
    check_id: str,
    *,
    state: str,
    reason_code: str,
    missing_capability: str | None = None,
) -> dict[str, str | None]:
    if (
        check_id not in _AUDIT_CHECK_ORDER
        or state not in {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE"}
        or not reason_code
        or (state == "UNAVAILABLE") is not (missing_capability is not None)
    ):
        raise _report_contract_error()
    return {
        "check_id": check_id,
        "applicability_state": state,
        "reason_code": reason_code,
        "missing_capability": missing_capability,
    }


def _sealed_requested_output_evidence(
    evidence: SealedResultEvidenceSet,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Derive report capability states from authenticated requests and sealed results."""

    registry = {
        str(row["output_id"]): row
        for row in load_protocol_registry()["requested_outputs"]
        if "fit" in row["commands"] and row["output_id"] in _REPORT_OUTPUT_ORDER
    }
    if tuple(output_id for output_id in _REPORT_OUTPUT_ORDER if output_id in registry) != (
        _REPORT_OUTPUT_ORDER
    ):
        raise _report_contract_error()
    counts = {
        output_id: {
            "capable": 0,
            "requested": 0,
            "available": 0,
            "not_applicable": 0,
        }
        for output_id in _REPORT_OUTPUT_ORDER
    }
    successful_chain_count = 0
    run = _sealed_result_evidence_run(evidence)
    for persisted_result in run.persisted_results:
        persisted_state, finalized_state = _read_persisted_result_and_finalized_state(
            persisted_result
        )
        if finalized_state.status != "SUCCESS":
            continue
        chain_executions = _finalized_result_descriptive_chain_executions_from_state(
            persisted_state.finalized_result,
            finalized_state,
        )
        if not chain_executions:
            raise _report_contract_error()
        for execution in chain_executions:
            readback = _readback_authenticated_execution(execution)
            request = _require_mapping(readback.request)
            response = _require_mapping(readback.response)
            payload = _require_mapping(request.get("payload"))
            projection = _require_mapping(payload.get("execution_input_projection"))
            requested_outputs = projection.get("requested_outputs")
            capabilities = projection.get("capabilities")
            response_payload = _require_mapping(response.get("payload"))
            result = _require_mapping(response_payload.get("result"))
            arrays = _require_mapping(result.get("array_catalog"))
            component_rows = result.get("component_applicability")
            if (
                request.get("command") != "fit"
                or response.get("status") != "SUCCESS"
                or type(requested_outputs) is not list
                or any(type(output_id) is not str for output_id in requested_outputs)
                or len(requested_outputs) != len(set(requested_outputs))
                or not isinstance(capabilities, Mapping)
                or type(component_rows) is not list
                or set(readback.response_arrays) != set(arrays)
            ):
                raise _report_contract_error()
            component_by_output = {
                _require_string(_require_mapping(row).get("output_id")): _require_mapping(row)
                for row in component_rows
            }
            if len(component_by_output) != len(component_rows):
                raise _report_contract_error()
            successful_chain_count += 1
            requested_set = set(cast(list[str], requested_outputs))
            for output_id in _REPORT_OUTPUT_ORDER:
                required_capabilities = registry[output_id].get("required_capabilities")
                if type(required_capabilities) is not list or any(
                    type(capability) is not str for capability in required_capabilities
                ):
                    raise _report_contract_error()
                if all(
                    capabilities.get(capability) is True
                    for capability in cast(list[str], required_capabilities)
                ):
                    counts[output_id]["capable"] += 1
                if output_id not in requested_set:
                    continue
                counts[output_id]["requested"] += 1
                component = component_by_output.get(output_id)
                if component is not None:
                    if (
                        component.get("status") != "NOT_APPLICABLE_BY_CAPABILITY"
                        or component.get("value") is not None
                        or type(component.get("reason_code")) is not str
                    ):
                        raise _report_contract_error()
                    counts[output_id]["not_applicable"] += 1
                    continue
                result_members = registry[output_id].get("result_members")
                if (
                    type(result_members) is not list
                    or any(type(member) is not str for member in result_members)
                    or not set(cast(list[str], result_members)).issubset(arrays)
                ):
                    raise _report_contract_error()
                counts[output_id]["available"] += 1

    states: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for output_id in _REPORT_OUTPUT_ORDER:
        output_counts = counts[output_id]
        if (
            successful_chain_count > 0
            and output_counts["requested"] == successful_chain_count
            and output_counts["available"] == successful_chain_count
        ):
            states[output_id] = "AVAILABLE"
            reasons[output_id] = "APPLICABILITY.SEALED_REQUESTED_OUTPUT"
        elif (
            successful_chain_count > 0
            and output_counts["requested"] == successful_chain_count
            and output_counts["not_applicable"] == successful_chain_count
        ):
            states[output_id] = "NOT_APPLICABLE"
            reasons[output_id] = "APPLICABILITY.SEALED_COMPONENT_NOT_APPLICABLE"
        else:
            states[output_id] = "UNAVAILABLE"
            reasons[output_id] = (
                "RESULT.SUCCESSFUL_EVIDENCE_UNAVAILABLE"
                if successful_chain_count == 0
                else (
                    "WORKER.CAPABILITY_UNAVAILABLE"
                    if output_counts["capable"] != successful_chain_count
                    else "REQUEST.OUTPUT_NOT_REQUESTED"
                )
            )
    capability_evidence = {
        "training_stage": {
            name: {
                "output_id": output_id,
                "status": states[output_id],
                "reason_code": reasons[output_id],
            }
            for name, output_id in _TRAINING_STAGE_OUTPUTS
        }
    }
    return capability_evidence, states


def _audit_check_applicability(
    *,
    layers: Sequence[Mapping[str, Any]],
    baseline: Mapping[str, Any],
    sealed_output_states: Mapping[str, str],
) -> tuple[dict[str, str | None], ...]:
    """Project existing scientific applicability into one closed report inventory."""

    by_layer = {_require_string(row.get("layer")): row for row in layers}
    rows: list[dict[str, str | None]] = []
    baseline_status = _require_string(baseline.get("assessment_status"))
    rows.append(
        _applicability_row(
            "baseline-reproduction",
            state=(
                "NOT_APPLICABLE" if baseline_status == "BASELINE_NOT_ASSESSABLE" else "AVAILABLE"
            ),
            reason_code=(
                "APPLICABILITY.BASELINE_CANDIDATE_NOT_SUCCESSFUL"
                if baseline_status == "BASELINE_NOT_ASSESSABLE"
                else "APPLICABILITY.SEALED_BASELINE_EVIDENCE"
            ),
        )
    )
    for check_id, layer_name in (
        ("within-fit-order-uncertainty", "WITHIN_FIT"),
        ("independent-chain-stability", "CHAIN"),
    ):
        layer = by_layer[layer_name]
        available = cast(int, layer["assessable_record_count"])
        unavailable = cast(int, layer["not_assessable_record_count"])
        not_applicable = cast(int, layer["not_applicable_record_count"])
        if available:
            state = "AVAILABLE"
            reason = "APPLICABILITY.SEALED_SCIENTIFIC_EVIDENCE"
            missing = None
        elif unavailable:
            state = "UNAVAILABLE"
            reason = "APPLICABILITY.REQUIRED_EVIDENCE_UNAVAILABLE"
            missing = (
                "position_probabilities" if layer_name == "WITHIN_FIT" else "independent_chains"
            )
        elif not_applicable:
            state = "NOT_APPLICABLE"
            reason = "APPLICABILITY.NOT_APPLICABLE_BY_CAPABILITY"
            missing = None
        else:
            raise _report_contract_error()
        rows.append(
            _applicability_row(
                check_id,
                state=state,
                reason_code=reason,
                missing_capability=missing,
            )
        )
    for check_id, layer_name, missing_capability in (
        ("sampling-stability", "SAMPLING", "sampling_replicates"),
        ("analysis-choice-sensitivity", "ANALYST_DECISION", "analysis_choice_universes"),
        ("participant-influence", "PARTICIPANT_INFLUENCE", "participant_influence_refits"),
        ("null-no-signal-comparison", "NULL", "null_replicates"),
    ):
        layer = by_layer[layer_name]
        attempt_count = cast(int, layer["attempt_count"])
        available = cast(int, layer["assessable_record_count"])
        if available:
            state = "AVAILABLE"
            reason = "APPLICABILITY.SEALED_SCIENTIFIC_EVIDENCE"
            missing = None
        elif attempt_count:
            state = "UNAVAILABLE"
            reason = "APPLICABILITY.REQUIRED_EVIDENCE_UNAVAILABLE"
            missing = missing_capability
        else:
            state = "NOT_APPLICABLE"
            reason = "APPLICABILITY.NOT_REQUESTED_BY_ANALYSIS_CONTRACT"
            missing = None
        rows.append(
            _applicability_row(
                check_id,
                state=state,
                reason_code=reason,
                missing_capability=missing,
            )
        )
    pairwise_state = sealed_output_states.get("pairwise_precedence")
    if pairwise_state not in {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE"}:
        raise _report_contract_error()
    rows.append(
        _applicability_row(
            "pairwise-precedence",
            state=pairwise_state,
            reason_code=(
                "APPLICABILITY.SEALED_REQUESTED_OUTPUT"
                if pairwise_state == "AVAILABLE"
                else (
                    "APPLICABILITY.SEALED_COMPONENT_NOT_APPLICABLE"
                    if pairwise_state == "NOT_APPLICABLE"
                    else "APPLICABILITY.REQUIRED_EVIDENCE_UNAVAILABLE"
                )
            ),
            missing_capability=("pairwise_precedence" if pairwise_state == "UNAVAILABLE" else None),
        )
    )
    training_stage_states = tuple(
        sealed_output_states.get(output_id) for _name, output_id in _TRAINING_STAGE_OUTPUTS
    )
    if any(
        state not in {"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE"}
        for state in training_stage_states
    ):
        raise _report_contract_error()
    stage_available = all(state == "AVAILABLE" for state in training_stage_states)
    rows.append(
        _applicability_row(
            "participant-stage-stability",
            state="AVAILABLE" if stage_available else "UNAVAILABLE",
            reason_code=(
                "APPLICABILITY.SEALED_REQUESTED_OUTPUT"
                if stage_available
                else "APPLICABILITY.REQUIRED_EVIDENCE_UNAVAILABLE"
            ),
            missing_capability=(None if stage_available else "participant_stage_outputs"),
        )
    )
    rows.sort(key=lambda row: _AUDIT_CHECK_ORDER.index(cast(str, row["check_id"])))
    if tuple(cast(str, row["check_id"]) for row in rows) != _AUDIT_CHECK_ORDER:
        raise _report_contract_error()
    return tuple(rows)


def _section_rows(
    layers: Sequence[Mapping[str, Any]],
    *,
    baseline: Mapping[str, Any] | None = None,
    participant_stage_comparisons: Sequence[Mapping[str, Any]] = (),
) -> tuple[dict[str, Any], ...]:
    by_layer = {str(row["layer"]): row for row in layers}
    sections: list[dict[str, Any]] = []
    for number, (section_id, title) in enumerate(_SECTION_TITLES, start=1):
        fixed = _FIXED_SECTION_STATUS.get(section_id)
        if fixed is not None:
            status, reason_codes = fixed
        elif section_id == "baseline":
            if baseline is None:
                status = "BLOCKED"
                reason_codes = ("REPORT.BASELINE_REPRODUCTION_AUTHORITY_PENDING",)
            else:
                baseline_status = _require_string(baseline.get("assessment_status"))
                eligibility = baseline.get("validated_language_eligibility")
                baseline_reasons = baseline.get("reason_codes")
                if (
                    baseline_status not in _BASELINE_LANGUAGE
                    or type(eligibility) is not bool
                    or type(baseline_reasons) is not list
                    or any(type(reason) is not str for reason in baseline_reasons)
                    or (baseline_status == "BASELINE_REPRODUCED") is not eligibility
                ):
                    raise _report_contract_error()
                if eligibility:
                    status = "AVAILABLE"
                    reason_codes = ()
                elif baseline_status == "BASELINE_PARTIALLY_REPRODUCED":
                    status = "PARTIAL"
                    reason_codes = tuple(cast(list[str], baseline_reasons))
                else:
                    status = "NOT_ASSESSABLE"
                    reason_codes = tuple(cast(list[str], baseline_reasons))
        elif section_id == "participant-stage":
            status, reason_codes = _participant_stage_section_state(participant_stage_comparisons)
        else:
            layer_name = _LAYER_BY_SECTION[section_id]
            try:
                layer = by_layer[layer_name]
            except KeyError:
                raise _report_contract_error() from None
            implementation = layer["implementation_status"]
            if implementation == "IMPLEMENTED":
                assessable_count = layer["assessable_record_count"]
                not_assessable_count = layer["not_assessable_record_count"]
                not_applicable_count = layer["not_applicable_record_count"]
                descriptive_count = layer["descriptive_record_count"]
                if layer_name in {"WITHIN_FIT", "CHAIN"}:
                    if assessable_count == 0:
                        status = "NOT_ASSESSABLE"
                        if not_applicable_count > 0 and not_assessable_count == 0:
                            reason_codes = ("REPORT.NO_CAPABILITY_APPLICABLE_CANDIDATE_EVIDENCE",)
                        elif not_applicable_count > 0:
                            reason_codes = (
                                "REPORT.NO_ASSESSABLE_CANDIDATE_EVIDENCE",
                                "REPORT.CANDIDATE_CAPABILITY_UNAVAILABLE",
                            )
                        else:
                            reason_codes = ("REPORT.NO_ASSESSABLE_CANDIDATE_EVIDENCE",)
                    elif not_assessable_count > 0 or not_applicable_count > 0:
                        status = "PARTIAL"
                        reason_codes = ("REPORT.MIXED_CANDIDATE_ASSESSABILITY",)
                    else:
                        status = "AVAILABLE"
                        reason_codes = ()
                elif layer_name == "SAMPLING":
                    attempt_count = layer["attempt_count"]
                    if attempt_count == 0:
                        status = "NOT_ASSESSABLE"
                        reason_codes = ("REPORT.NO_PLANNED_SAMPLING_EVIDENCE",)
                    elif assessable_count == 0:
                        status = "NOT_ASSESSABLE"
                        reason_codes = ("REPORT.NO_ASSESSABLE_SAMPLING_EVIDENCE",)
                    else:
                        reasons = []
                        if descriptive_count > 0:
                            reasons.append("REPORT.SAMPLING_DESCRIPTIVE_ONLY_PRESENT")
                        if not_assessable_count > 0:
                            reasons.append("REPORT.MIXED_SAMPLING_ASSESSABILITY")
                        if reasons:
                            status = "PARTIAL"
                            reason_codes = tuple(reasons)
                        else:
                            status = "AVAILABLE"
                            reason_codes = ()
                elif layer_name == "ANALYST_DECISION":
                    attempt_count = layer["attempt_count"]
                    applicable_count = assessable_count + not_assessable_count
                    if applicable_count == 0:
                        status = "NOT_ASSESSABLE"
                        reason_codes = (
                            (
                                "REPORT.NO_PLANNED_ANALYST_DECISION_EVIDENCE"
                                if attempt_count <= 1
                                else "REPORT.NO_APPLICABLE_ANALYST_DECISION_EVIDENCE"
                            ),
                        )
                    elif assessable_count == 0:
                        status = "NOT_ASSESSABLE"
                        reason_codes = ("REPORT.NO_ASSESSABLE_ANALYST_DECISION_EVIDENCE",)
                    else:
                        reasons = []
                        if descriptive_count > 0:
                            reasons.append("REPORT.ANALYST_DECISION_DESCRIPTIVE_ONLY_PRESENT")
                        if not_assessable_count > 0:
                            reasons.append("REPORT.MIXED_ANALYST_DECISION_ASSESSABILITY")
                        if reasons:
                            status = "PARTIAL"
                            reason_codes = tuple(reasons)
                        else:
                            status = "AVAILABLE"
                            reason_codes = ()
                elif layer_name == "PARTICIPANT_INFLUENCE":
                    if assessable_count == 0:
                        status = "NOT_ASSESSABLE"
                        if not_assessable_count == 0 and not_applicable_count == 0:
                            reason_codes = ("REPORT.NO_PLANNED_PARTICIPANT_INFLUENCE",)
                        else:
                            reason_codes = ("REPORT.NO_ASSESSABLE_PARTICIPANT_INFLUENCE_EVIDENCE",)
                    else:
                        reasons = []
                        if descriptive_count > 0:
                            reasons.append("REPORT.PARTICIPANT_INFLUENCE_DESCRIPTIVE_ONLY_PRESENT")
                        if not_assessable_count > 0 or not_applicable_count > 0:
                            reasons.append("REPORT.MIXED_PARTICIPANT_INFLUENCE_ASSESSABILITY")
                        if reasons:
                            status = "PARTIAL"
                            reason_codes = tuple(reasons)
                        else:
                            status = "AVAILABLE"
                            reason_codes = ()
                else:
                    raise _report_contract_error()
            elif implementation == "PARTIALLY_IMPLEMENTED":
                status = "PARTIAL"
                reason = layer["reason_code"]
                reason_codes = () if reason is None else (str(reason),)
            elif implementation == "PENDING_IMPLEMENTATION":
                status = "BLOCKED"
                reason = layer["reason_code"]
                reason_codes = () if reason is None else (str(reason),)
            else:
                raise _report_contract_error()
        sections.append(
            {
                "section_number": number,
                "section_id": section_id,
                "title": title,
                "status": status,
                "reason_codes": list(reason_codes),
            }
        )
    return tuple(sections)


def _report_extension_components(
    owner: AuthenticatedMeaningEvidenceExtension,
    *,
    scientific_evidence_digest: str | None = None,
    captured_scientific_run: CapturedScientificRun | None = None,
    sealed_scientific_evidence: SealedScientificEvidence | None = None,
) -> tuple[
    tuple[dict[str, Any], ...],
    str,
    tuple[dict[str, Any], ...],
    str,
    str,
    dict[str, Any],
    tuple[str, ...],
    tuple[str, ...],
    str,
]:
    if sealed_scientific_evidence is None:
        if captured_scientific_run is not None:
            raise _report_contract_error()
        extension = read_authenticated_meaning_evidence_extension(owner)
    else:
        if captured_scientific_run is None:
            raise _report_contract_error()
        extension = validate_meaning_extension_science_join(
            owner,
            captured_scientific_run,
            sealed_scientific_evidence,
        )
    claim_projection = _require_mapping(extension.get("report_claim_projection"))
    meaning_bundle = _require_mapping(extension.get("meaning_evidence_bundle"))
    claim_digest = _require_bare_sha256(extension.get("report_claim_projection_sha256"))
    meaning_digest = _require_bare_sha256(extension.get("meaning_evidence_bundle_sha256"))
    evidence_graph_digest = _require_bare_sha256(extension.get("evidence_graph_digest"))
    extension_science_digest = _require_bare_sha256(
        extension.get("scientific_evidence_digest")
    )
    evidence_graph_identity = _require_mapping(
        extension.get("evidence_graph_identity")
    )
    warning_digest_value = claim_projection.get("ordered_warning_record_sha256")
    terminal_digest_value = claim_projection.get(
        "ordered_public_terminal_result_sha256"
    )
    if (warning_digest_value is None) != (terminal_digest_value is None):
        raise _report_contract_error()
    if warning_digest_value is None:
        ordered_warning_record_sha256: tuple[str, ...] = ()
        ordered_public_terminal_result_sha256: tuple[str, ...] = ()
    else:
        ordered_warning_record_sha256 = _require_ordered_bare_sha256s(
            warning_digest_value
        )
        ordered_public_terminal_result_sha256 = _require_ordered_bare_sha256s(
            terminal_digest_value
        )
    if scientific_evidence_digest is not None:
        active_science_digest = _require_prefixed_sha256(scientific_evidence_digest)
        if extension_science_digest != active_science_digest.removeprefix("sha256:"):
            raise _report_contract_error()
    if (
        claim_projection.get("projection_sha256") != claim_digest
        or meaning_bundle.get("bundle_sha256") != meaning_digest
        or claim_projection.get("evidence_graph_digest") != evidence_graph_digest
        or meaning_bundle.get("evidence_graph_digest") != evidence_graph_digest
    ):
        raise _report_contract_error()
    claim_records = claim_projection.get("records")
    meaning_records = meaning_bundle.get("records")
    if type(claim_records) is not list or type(meaning_records) is not list:
        raise _report_contract_error()
    return (
        _validated_report_claim_records(claim_records),
        claim_digest,
        _validated_meaning_evidence_records(meaning_records),
        meaning_digest,
        evidence_graph_digest,
        copy.deepcopy(evidence_graph_identity),
        ordered_warning_record_sha256,
        ordered_public_terminal_result_sha256,
        extension_science_digest,
    )


def _report_model(
    projection: Mapping[str, Any],
    *,
    input_declaration: str,
    candidate_execution: Mapping[str, Any],
    baseline_assessment_record: Mapping[str, Any],
    baseline_reproduction_record: Mapping[str, Any] | None,
    private_participant_stage_evidence_count: int,
    capability_evidence: Mapping[str, Any],
    sealed_output_states: Mapping[str, str],
    report_claim_records: Sequence[Mapping[str, Any]],
    report_claim_projection_sha256: str,
    meaning_evidence_records: Sequence[Mapping[str, Any]],
    meaning_evidence_bundle_sha256: str,
    meaning_evidence_graph_digest: str,
    meaning_evidence_graph_identity: Mapping[str, Any],
    meaning_evidence_csv_sha256: str,
    ordered_warning_record_sha256: Sequence[str],
    ordered_public_terminal_result_sha256: Sequence[str],
    report_provenance_csv_sha256: str,
    development_null: Mapping[str, Any] | None = None,
    development_null_science_receipt_digest: str | None = None,
) -> dict[str, Any]:
    if (
        type(private_participant_stage_evidence_count) is not int
        or private_participant_stage_evidence_count < 0
    ):
        raise _report_contract_error()
    gate = _require_mapping(projection.get("science_completion_gate"))
    gate_status = _require_string(gate.get("status"))
    gate_reasons = gate.get("reason_codes")
    if (
        gate_status != "BLOCKED"
        or type(gate_reasons) is not list
        or not gate_reasons
        or any(type(code) is not str for code in gate_reasons)
    ):
        raise _report_contract_error()
    layers = list(_layer_rows(projection))
    null_evidence = _null_evidence(projection)
    report_claims = _validated_report_claim_records(report_claim_records)
    meaning_evidence = _validated_meaning_evidence_records(meaning_evidence_records)
    report_claim_projection_sha256 = _require_bare_sha256(
        report_claim_projection_sha256
    )
    meaning_evidence_bundle_sha256 = _require_bare_sha256(
        meaning_evidence_bundle_sha256
    )
    meaning_evidence_graph_digest = _require_bare_sha256(
        meaning_evidence_graph_digest
    )
    meaning_evidence_graph_identity = _require_mapping(
        copy.deepcopy(dict(meaning_evidence_graph_identity))
    )
    meaning_evidence_csv_sha256 = _require_prefixed_sha256(
        meaning_evidence_csv_sha256
    )
    ordered_warning_record_sha256 = _require_ordered_bare_sha256s(
        list(ordered_warning_record_sha256)
    )
    ordered_public_terminal_result_sha256 = _require_ordered_bare_sha256s(
        list(ordered_public_terminal_result_sha256)
    )
    report_provenance_csv_sha256 = _require_prefixed_sha256(
        report_provenance_csv_sha256
    )
    if (development_null is None) != (development_null_science_receipt_digest is None):
        raise _report_contract_error()
    if development_null is not None:
        null_rows = [row for row in layers if row["layer"] == "NULL"]
        if (
            len(null_rows) != 1
            or development_null.get("calibration_state") != "DEVELOPMENT_UNCALIBRATED"
            or development_null.get("null_relative_label") != "NULL_CALIBRATION_NOT_VALIDATED"
            or development_null.get("strong_null_relative_language_eligible") is not False
            or development_null.get("held_out_false_positive_rate_eligible") is not False
        ):
            raise _report_contract_error()
        null_rows[0]["implementation_status"] = "PARTIALLY_IMPLEMENTED"
        null_rows[0]["reason_code"] = "NULL_CALIBRATION_NOT_VALIDATED"
    candidates = _candidate_rows(projection)
    if candidate_execution.get("requested_candidate_count") != len(
        candidates
    ) or candidate_execution.get("terminal_record_count") != len(candidates):
        raise _report_contract_error()
    participant_stage_comparisons = _participant_stage_comparisons(projection)
    baseline = _baseline_report_projection(
        baseline_assessment_record,
        baseline_reproduction_record,
    )
    baseline_language = _BASELINE_LANGUAGE[_require_string(baseline["assessment_status"])]
    sampling_evidence = _require_mapping(projection.get("sampling_evidence"))
    analyst_decision_evidence = _require_mapping(projection.get("analyst_decision_evidence"))
    participant_influence = _require_mapping(projection.get("participant_influence_evidence"))
    science_synthetic_case_binding = _report_synthetic_case_binding(projection)
    if input_declaration == "DECLARED_SYNTHETIC":
        report_synthetic_case_binding = science_synthetic_case_binding
    elif input_declaration == "PRIVATE_LOCAL_INPUT":
        report_synthetic_case_binding = None
    else:
        raise _report_contract_error()
    gate_reason_projection = list(cast(list[str], gate_reasons))
    if (
        development_null is not None
        and "NULL_CALIBRATION_NOT_VALIDATED" not in gate_reason_projection
    ):
        gate_reason_projection.append("NULL_CALIBRATION_NOT_VALIDATED")
    model: dict[str, Any] = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "report_status": CURRENT_REPORT_STATUS,
        "input_declaration": input_declaration,
        "report_language_rule_id": REPORT_LANGUAGE_RULE_ID,
        "opening": MANDATORY_OPENING,
        "baseline_caveat": baseline_language,
        "null_caveat": NULL_SAFE_FALLBACK,
        "baseline": baseline,
        "candidate_execution": dict(candidate_execution),
        "science_completion_gate": {
            "status": gate_status,
            "reason_codes": gate_reason_projection,
        },
        "uncertainty_layers": list(layers),
        "capability_evidence": copy.deepcopy(dict(capability_evidence)),
        "audit_check_applicability": list(
            _audit_check_applicability(
                layers=layers,
                baseline=baseline,
                sealed_output_states=sealed_output_states,
            )
        ),
        "candidate_records": list(candidates),
        "meaning_evidence": list(meaning_evidence),
        "sampling_evidence": copy.deepcopy(sampling_evidence),
        "analyst_decision_evidence": copy.deepcopy(analyst_decision_evidence),
        "participant_stage_comparisons": list(participant_stage_comparisons),
        "participant_influence": copy.deepcopy(participant_influence),
        "null_evidence": copy.deepcopy(null_evidence),
        "report_predicates": list(report_claims),
        "required_claim_statements": list(_required_claim_statements(report_claims)),
        "sections": list(
            _section_rows(
                layers,
                baseline=baseline,
                participant_stage_comparisons=participant_stage_comparisons,
            )
        ),
        "provenance": {
            "plan_digest": _require_string(projection.get("plan_digest")),
            "terminal_index_digest": _require_string(projection.get("terminal_index_digest")),
            "scientific_evidence_digest": _require_string(
                projection.get("scientific_evidence_digest")
            ),
            "scientific_evidence_schema_version": _require_string(
                projection.get("scientific_evidence_schema_version")
            ),
            "scientific_evidence_rule_id": _require_string(projection.get("evidence_rule_id")),
            "report_claim_projection_sha256": report_claim_projection_sha256,
            "ordered_warning_record_sha256": list(ordered_warning_record_sha256),
            "ordered_public_terminal_result_sha256": list(
                ordered_public_terminal_result_sha256
            ),
            "meaning_evidence_bundle_sha256": meaning_evidence_bundle_sha256,
            "meaning_evidence_graph_digest": meaning_evidence_graph_digest,
            "meaning_evidence_graph_identity": meaning_evidence_graph_identity,
            "synthetic_case_binding": report_synthetic_case_binding,
        },
        "artifact_contract": {
            "scientific_evidence_projection_path": _REPORT_ARTIFACT_PATHS[0],
            "baseline_assessment_path": BASELINE_ASSESSMENT_ARTIFACT_PATH,
            "report_json_path": _REPORT_ARTIFACT_PATHS[1],
            "universes_csv_path": _REPORT_ARTIFACT_PATHS[2],
            "meaning_evidence_csv_path": _REPORT_ARTIFACT_PATHS[3],
            "meaning_evidence_csv_sha256": meaning_evidence_csv_sha256,
            "report_provenance_csv_path": _REPORT_ARTIFACT_PATHS[4],
            "report_provenance_csv_sha256": report_provenance_csv_sha256,
            "report_html_path": _REPORT_ARTIFACT_PATHS[5],
            "private_participant_stage_evidence_directory": (_PRIVATE_STAGE_EVIDENCE_DIRECTORY),
            "private_participant_stage_evidence_count": (private_participant_stage_evidence_count),
            "manifest_emitted": False,
            "standalone_rehydration_available": False,
        },
    }
    if development_null is not None:
        artifact_contract = cast(dict[str, Any], model["artifact_contract"])
        artifact_contract["development_null_science_receipt_path"] = (
            _DEVELOPMENT_NULL_SCIENCE_RECEIPT_PATH
        )
        model["development_null"] = dict(development_null)
        model["development_null_science_receipt_digest"] = development_null_science_receipt_digest
    if baseline_reproduction_record is not None:
        artifact_contract = cast(dict[str, Any], model["artifact_contract"])
        artifact_contract["baseline_reproduction_path"] = BASELINE_REPRODUCTION_ARTIFACT_PATH
    assert_no_direct_identifier_fields(model)
    try:
        validate_instance(model, "report.schema.json")
    except (SchemaValidationError, ValueError):
        raise _report_contract_error() from None
    return model


def _validated_report_claim_records(
    records: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Validate the exact pre-report claim projection without recomputing it."""

    if type(records) not in {list, tuple} or len(records) != len(_REPORT_PREDICATE_ORDER):
        raise _report_contract_error()
    projected: list[dict[str, Any]] = []
    for predicate_id, value in zip(_REPORT_PREDICATE_ORDER, records, strict=True):
        record = _require_mapping(value)
        if set(record) != {
            "predicate_id",
            "directive",
            "state",
            "value",
            "reason_codes",
            "failure_code",
            "input_record_ids",
            "source_record_digests",
            "operation_ids",
        } or record.get("predicate_id") != predicate_id:
            raise _report_contract_error()
        directive = record.get("directive")
        catalog = REPORT_CLAIM_DIRECTIVES.get(predicate_id)
        if not isinstance(catalog, Mapping) or directive != {
            field: catalog[field] for field in ("rule_id", "effect", "statement_id")
        }:
            raise _report_contract_error()
        state = record.get("state")
        result_value = record.get("value")
        reason_codes = record.get("reason_codes")
        failure_code = record.get("failure_code")
        input_record_ids = record.get("input_record_ids")
        source_record_digests = record.get("source_record_digests")
        operation_ids = record.get("operation_ids")
        if (
            state
            not in {
                "AVAILABLE",
                "UNAVAILABLE",
                "NOT_APPLICABLE",
                "INVALID",
                "FAILED",
            }
            or type(reason_codes) is not list
            or any(type(code) is not str or not code for code in reason_codes)
            or len(set(reason_codes)) != len(reason_codes)
            or type(input_record_ids) is not list
            or any(type(record_id) is not str or not record_id for record_id in input_record_ids)
            or len(set(input_record_ids)) != len(input_record_ids)
            or type(source_record_digests) is not list
            or any(
                type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                for digest in source_record_digests
            )
            or len(set(source_record_digests)) != len(source_record_digests)
            or type(operation_ids) is not list
            or any(
                type(operation_id) is not str or not operation_id
                for operation_id in operation_ids
            )
            or len(set(operation_ids)) != len(operation_ids)
        ):
            raise _report_contract_error()
        if state == "AVAILABLE":
            if (
                type(result_value) is not bool
                or reason_codes
                or failure_code is not None
                or not source_record_digests
            ):
                raise _report_contract_error()
        elif state in {"UNAVAILABLE", "NOT_APPLICABLE"}:
            if result_value is not None or not reason_codes or failure_code is not None:
                raise _report_contract_error()
        elif (
            result_value is not None
            or not reason_codes
            or type(failure_code) is not str
            or not failure_code
        ):
            raise _report_contract_error()
        projected.append(copy.deepcopy(dict(record)))
    assert_no_direct_identifier_fields(projected)
    return tuple(projected)


def _required_claim_statements(
    records: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    claims = _validated_report_claim_records(records)
    statements: list[str] = []
    for record in claims:
        if record["state"] != "AVAILABLE":
            continue
        directive = cast(Mapping[str, str], record["directive"])
        catalog = cast(Mapping[str, Any], REPORT_CLAIM_DIRECTIVES[record["predicate_id"]])
        effect = directive["effect"]
        if effect == "REQUIRE":
            statement = catalog.get("statement_text")
            if record["value"] is not True or type(statement) is not str or not statement:
                raise _report_contract_error()
            statements.append(statement)
        elif effect == "FORBID":
            forbidden_phrases = catalog.get("forbidden_phrases")
            if (
                record["value"] is not False
                or type(forbidden_phrases) is not tuple
                or not forbidden_phrases
            ):
                raise _report_contract_error()
        elif effect != "OBSERVE":
            raise _report_contract_error()
    return tuple(statements)


def _validate_claim_directive_output(
    model: Mapping[str, Any],
    report_html_bytes: bytes,
) -> None:
    claims_value = model.get("report_predicates")
    statements_value = model.get("required_claim_statements")
    if type(claims_value) is not list or type(statements_value) is not list:
        raise _report_contract_error()
    claims = _validated_report_claim_records(claims_value)
    expected_statements = _required_claim_statements(claims)
    if statements_value != list(expected_statements):
        raise _report_contract_error()
    html_text = report_html_bytes.decode("utf-8")
    for statement in expected_statements:
        if html.escape(statement) not in html_text:
            raise _report_contract_error()
    combined_text = canonical_json_bytes(dict(model)).decode("utf-8") + "\n" + html_text
    combined_casefold = combined_text.casefold()
    for record in claims:
        if record["state"] != "AVAILABLE":
            continue
        directive = cast(Mapping[str, str], record["directive"])
        if directive["effect"] != "FORBID":
            continue
        catalog = cast(Mapping[str, Any], REPORT_CLAIM_DIRECTIVES[record["predicate_id"]])
        forbidden_phrases = catalog.get("forbidden_phrases")
        if type(forbidden_phrases) is not tuple or any(
            type(phrase) is not str
            or not phrase
            or phrase.casefold() in combined_casefold
            for phrase in forbidden_phrases
        ):
            raise _report_contract_error()


def _csv_bytes(candidates: Sequence[Mapping[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(
        (
            "candidate_ordinal",
            "candidate_id",
            "analysis_spec_id",
            "universe_id",
            "final_status",
            "eligibility",
            "within_fit_status",
            "within_fit_reason_code",
            "chain_status",
            "chain_reason_code",
        )
    )
    for row in candidates:
        writer.writerow(
            (
                row["candidate_ordinal"],
                row["candidate_id"],
                row["analysis_spec_id"],
                row["universe_id"] or "",
                row["final_status"],
                row["eligibility"],
                row["within_fit_status"],
                row["within_fit_reason_code"] or "",
                row["chain_status"],
                row["chain_reason_code"] or "",
            )
        )
    return stream.getvalue().encode("utf-8")


def _validated_meaning_evidence_records(
    records: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Return the exact closed meaning inventory after runtime sequence checks."""

    if type(records) not in {list, tuple} or len(records) != 104:
        raise _report_contract_error()
    projected: list[dict[str, Any]] = []
    meaning_ids: list[str] = []
    for expected_ordinal, value in enumerate(records, start=1):
        record = _require_mapping(value)
        try:
            frozen_record = validate_frozen_meaning_record(record)
        except TypeError:
            raise _report_contract_error() from None
        if frozen_record != record:
            raise _report_contract_error()
        if set(record) != {
            "ordinal",
            "meaning_id",
            "operation_group_id",
            "state",
            "value",
            "reason_codes",
            "failure_code",
            "operation_ids",
            "output_schema_ref",
            "derivation_id",
            "source_record_digests",
        }:
            raise _report_contract_error()
        ordinal = record.get("ordinal")
        meaning_id = record.get("meaning_id")
        operation_group_id = record.get("operation_group_id")
        state = record.get("state")
        result_value = record.get("value")
        reason_codes = record.get("reason_codes")
        failure_code = record.get("failure_code")
        operation_ids = record.get("operation_ids")
        output_schema_ref = record.get("output_schema_ref")
        derivation_id = record.get("derivation_id")
        source_record_digests = record.get("source_record_digests")
        if (
            type(ordinal) is not int
            or type(ordinal) is bool
            or ordinal != expected_ordinal
            or type(meaning_id) is not str
            or len(meaning_id) < 3
            or type(operation_group_id) is not str
            or not operation_group_id
            or (output_schema_ref is not None and type(output_schema_ref) is not str)
            or type(derivation_id) is not str
            or not derivation_id
            or state
            not in {
                "AVAILABLE",
                "UNAVAILABLE",
                "NOT_APPLICABLE",
                "INVALID",
                "FAILED",
            }
            or type(reason_codes) is not list
            or any(type(code) is not str or not code for code in reason_codes)
            or len(set(reason_codes)) != len(reason_codes)
            or type(operation_ids) is not list
            or any(
                type(operation_id) is not str or not operation_id
                for operation_id in operation_ids
            )
            or len(set(operation_ids)) != len(operation_ids)
            or (state == "AVAILABLE" and not operation_ids)
            or (
                state == "NOT_APPLICABLE"
                and reason_codes == ["SCIENCE.SCENARIO_NOT_DECLARED"]
                and operation_ids
            )
            or type(source_record_digests) is not list
            or any(
                type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                for digest in source_record_digests
            )
            or len(set(source_record_digests)) != len(source_record_digests)
        ):
            raise _report_contract_error()
        if state == "AVAILABLE":
            if (
                result_value is None
                or reason_codes
                or failure_code is not None
                or not source_record_digests
            ):
                raise _report_contract_error()
        elif state in {"UNAVAILABLE", "NOT_APPLICABLE"}:
            if result_value is not None or not reason_codes or failure_code is not None:
                raise _report_contract_error()
        elif (
            result_value is not None
            or not reason_codes
            or type(failure_code) is not str
            or not failure_code
        ):
            raise _report_contract_error()
        projected_record = copy.deepcopy(dict(record))
        try:
            canonical_json_bytes(projected_record)
        except (TypeError, ValueError):
            raise _report_contract_error() from None
        projected.append(projected_record)
        meaning_ids.append(meaning_id)
    if len(set(meaning_ids)) != 104:
        raise _report_contract_error()
    assert_no_direct_identifier_fields(projected)
    return tuple(projected)


def _meaning_evidence_csv_bytes(
    records: Sequence[Mapping[str, Any]],
) -> bytes:
    validated = _validated_meaning_evidence_records(records)
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(
        (
            "ordinal",
            "meaning_id",
            "operation_group_id",
            "state",
            "value_json",
            "reason_codes",
            "failure_code",
            "operation_ids",
            "output_schema_ref",
            "derivation_id",
            "source_record_digests",
        )
    )
    for record in validated:
        writer.writerow(
            (
                record["ordinal"],
                record["meaning_id"],
                record["operation_group_id"],
                record["state"],
                (
                    canonical_json_bytes(record["value"]).decode("utf-8")
                    if record["value"] is not None
                    else ""
                ),
                "|".join(cast(Sequence[str], record["reason_codes"])),
                record["failure_code"] or "",
                "|".join(cast(Sequence[str], record["operation_ids"])),
                record["output_schema_ref"] or "",
                record["derivation_id"],
                "|".join(cast(Sequence[str], record["source_record_digests"])),
            )
        )
    return stream.getvalue().encode("utf-8")


def _report_provenance_csv_bytes(provenance: Mapping[str, Any]) -> bytes:
    warning_digests = _require_ordered_bare_sha256s(
        provenance.get("ordered_warning_record_sha256")
    )
    terminal_digests = _require_ordered_bare_sha256s(
        provenance.get("ordered_public_terminal_result_sha256")
    )
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("record_kind", "ordinal", "record_sha256"))
    for record_kind, digests in (
        ("WARNING_RECORD", warning_digests),
        ("PUBLIC_TERMINAL_RESULT", terminal_digests),
    ):
        for ordinal, digest in enumerate(digests):
            writer.writerow((record_kind, ordinal, digest))
    return stream.getvalue().encode("utf-8")


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    if not headers or any(len(row) != len(headers) for row in rows):
        raise _report_contract_error()
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return (
        '<div class="table-scroll">'
        f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _axis_vector_cell(value: object) -> str:
    if type(value) is not list:
        raise _report_contract_error()
    rows: list[tuple[str, str]] = []
    for item in value:
        choice = _require_mapping(item)
        rows.append(
            (
                _require_string(choice.get("axis_id")),
                _require_string(choice.get("choice_id")),
            )
        )
    if rows != sorted(
        rows,
        key=lambda row: (row[0].encode("utf-8"), row[1].encode("utf-8")),
    ) or len({axis_id for axis_id, _choice_id in rows}) != len(rows):
        raise _report_contract_error()
    return ", ".join(f"{axis_id}={choice_id}" for axis_id, choice_id in rows) or "none"


def _analyst_combination_table(
    analyst_aggregates: Sequence[object],
) -> str:
    rows: list[tuple[object, ...]] = []
    for aggregate_value in analyst_aggregates:
        aggregate = _require_mapping(aggregate_value)
        if aggregate.get("aggregate_kind") != "COMBINATION_FACTORIAL_VECTOR":
            continue
        vector = _axis_vector_cell(aggregate.get("axis_choices"))
        denominators = _require_mapping(aggregate.get("denominators"))
        members = aggregate.get("member_rows")
        if type(members) is not list or not members:
            raise _report_contract_error()
        for member_value in members:
            member = _require_mapping(member_value)
            member_identity = _require_mapping(member.get("member_identity"))
            numeric_identity = _require_mapping(member.get("numeric_identity"))
            if _axis_vector_cell(member.get("axis_choices")) != vector:
                raise _report_contract_error()
            rows.append(
                (
                    _require_string(aggregate.get("aggregate_digest")),
                    _require_string(aggregate.get("experiment_set_id")),
                    _require_string(aggregate.get("experiment_mode")),
                    vector,
                    _require_string(member.get("origin_id")),
                    _require_string(member_identity.get("analysis_declaration_id")),
                    member_identity.get("declaration_ordinal"),
                    _require_string(member.get("attempt_digest")),
                    _require_string(member.get("numeric_comparison_digest")),
                    _require_string(numeric_identity.get("subject_analysis_spec_id")),
                    _require_string(numeric_identity.get("comparator_analysis_spec_id")),
                    _require_string(member.get("contribution_state")),
                    denominators.get("planned_origin_count"),
                    denominators.get("interpretive_origin_count"),
                    denominators.get("descriptive_only_origin_count"),
                    denominators.get("metric_not_assessable_origin_count"),
                    denominators.get("failed_origin_count"),
                    denominators.get("terminal_unavailable_origin_count"),
                    _require_string(aggregate.get("attribution_semantics")),
                    _require_string(aggregate.get("interpretation_phrase")),
                    member.get("reason_code") or "none",
                )
            )
    return _table(
        (
            "Aggregate identity",
            "Experiment set",
            "Mode",
            "Full declared vector",
            "Origin identity",
            "Member declaration identity",
            "Member ordinal",
            "Attempt identity",
            "Numeric comparison identity",
            "Subject analysis",
            "Literal baseline analysis",
            "Contribution",
            "Planned denominator",
            "Interpretive denominator",
            "Descriptive-only denominator",
            "Not-assessable denominator",
            "Failed denominator",
            "Terminal-unavailable denominator",
            "Attribution semantics",
            "Safe interpretation",
            "Typed reason",
        ),
        tuple(rows),
    )


def _html_bytes(model: Mapping[str, Any], *, native_objective_html: str = "") -> bytes:
    input_declaration = _require_string(model.get("input_declaration"))
    input_label = (
        '<p class="input-declaration">INPUT CLASSIFICATION: SYNTHETIC-ONLY</p>'
        if input_declaration == "DECLARED_SYNTHETIC"
        else ""
    )
    execution = cast(Mapping[str, Any], model["candidate_execution"])
    gate = cast(Mapping[str, Any], model["science_completion_gate"])
    baseline = cast(Mapping[str, Any], model["baseline"])
    provenance = cast(Mapping[str, Any], model["provenance"])
    meaning_graph_identity = _require_mapping(
        provenance.get("meaning_evidence_graph_identity")
    )
    capability_evidence = _require_mapping(model.get("capability_evidence"))
    training_stage_evidence = _require_mapping(capability_evidence.get("training_stage"))
    audit_check_applicability = model.get("audit_check_applicability")
    if type(audit_check_applicability) is not list:
        raise _report_contract_error()
    candidates = cast(Sequence[Mapping[str, Any]], model["candidate_records"])
    sampling_evidence = cast(Mapping[str, Any], model["sampling_evidence"])
    analyst_decision_evidence = cast(
        Mapping[str, Any],
        model["analyst_decision_evidence"],
    )
    participant_stage_comparisons = cast(
        Sequence[Mapping[str, Any]],
        model["participant_stage_comparisons"],
    )
    influence = cast(Mapping[str, Any], model["participant_influence"])
    null_evidence = cast(Mapping[str, Any], model["null_evidence"])
    report_predicates = model.get("report_predicates")
    if type(report_predicates) is not list:
        raise _report_contract_error()
    required_claim_statements = model.get("required_claim_statements")
    if type(required_claim_statements) is not list or any(
        type(statement) is not str or not statement
        for statement in required_claim_statements
    ):
        raise _report_contract_error()
    required_claim_language = "".join(
        f'<p class="claim-directive">{html.escape(statement)}</p>'
        for statement in required_claim_statements
    )
    meaning_evidence_value = model.get("meaning_evidence")
    if type(meaning_evidence_value) is not list:
        raise _report_contract_error()
    meaning_evidence = _validated_meaning_evidence_records(meaning_evidence_value)
    report_predicate_table = _table(
        (
            "Predicate",
            "State",
            "Value",
            "Reasons",
            "Failure",
            "Input records",
            "Operations",
        ),
        tuple(
            (
                _require_string(_require_mapping(row).get("predicate_id")),
                _require_string(_require_mapping(row).get("state")),
                _require_mapping(row).get("value"),
                ", ".join(cast(Sequence[str], _require_mapping(row).get("reason_codes"))) or "none",
                _require_mapping(row).get("failure_code") or "none",
                ", ".join(cast(Sequence[str], _require_mapping(row).get("input_record_ids")))
                or "none",
                ", ".join(cast(Sequence[str], _require_mapping(row).get("operation_ids")))
                or "none",
            )
            for row in report_predicates
        ),
    )
    meaning_evidence_table = _table(
        (
            "Ordinal",
            "Meaning",
            "State",
            "Value",
            "Reasons",
            "Failure",
            "Derivation",
            "Operations",
        ),
        tuple(
            (
                row["ordinal"],
                row["meaning_id"],
                row["state"],
                (
                    canonical_json_bytes(row["value"]).decode("utf-8")
                    if row["value"] is not None
                    else "none"
                ),
                ", ".join(cast(Sequence[str], row["reason_codes"])) or "none",
                row["failure_code"] or "none",
                row["derivation_id"],
                ", ".join(cast(Sequence[str], row["operation_ids"])),
            )
            for row in meaning_evidence
        ),
    )
    sections = cast(Sequence[Mapping[str, Any]], model["sections"])
    section_by_id = {str(section["section_id"]): section for section in sections}
    development_null = cast(
        Mapping[str, Any] | None,
        model.get("development_null"),
    )
    baseline_language = _require_string(model.get("baseline_caveat"))
    baseline_outcomes = cast(
        Sequence[Mapping[str, Any]],
        baseline.get("comparison_outcomes"),
    )
    baseline_counts = {outcome: 0 for outcome in _BASELINE_OUTCOME_ORDER}
    for comparison in baseline_outcomes:
        outcome = _require_string(comparison.get("outcome"))
        if outcome not in baseline_counts:
            raise _report_contract_error()
        baseline_counts[outcome] += 1
    baseline_table = _table(
        ("Field", "Value"),
        (
            ("Assessment", _require_string(baseline.get("assessment_status"))),
            ("Baseline terminal", _require_string(baseline.get("baseline_terminal_status"))),
            ("Reference presence", _require_string(baseline.get("reference_presence"))),
            (
                "Reproduction",
                baseline.get("reproduction_status") or "not available",
            ),
            (
                "Validated language eligible",
                "yes" if baseline.get("validated_language_eligibility") else "no",
            ),
            *(
                (
                    f"Comparison outcome: {outcome}",
                    baseline_counts[outcome],
                )
                for outcome in _BASELINE_OUTCOME_ORDER
            ),
        ),
    )
    training_stage_capability_table = _table(
        ("Training-stage output", "State", "Reason"),
        tuple(
            (
                _require_string(
                    _require_mapping(training_stage_evidence.get(name)).get("output_id")
                ),
                _require_string(_require_mapping(training_stage_evidence.get(name)).get("status")),
                _require_string(
                    _require_mapping(training_stage_evidence.get(name)).get("reason_code")
                ),
            )
            for name, _output_id in _TRAINING_STAGE_OUTPUTS
        ),
    )
    audit_check_applicability_table = _table(
        ("Audit check", "State", "Reason", "Missing capability"),
        tuple(
            (
                _require_string(_require_mapping(row).get("check_id")),
                _require_string(_require_mapping(row).get("applicability_state")),
                _require_string(_require_mapping(row).get("reason_code")),
                _require_mapping(row).get("missing_capability") or "none",
            )
            for row in audit_check_applicability
        ),
    )

    def status(section_id: str) -> str:
        section = section_by_id[section_id]
        reasons = cast(Sequence[str], section["reason_codes"])
        suffix = "" if not reasons else " — " + ", ".join(reasons)
        return f'<p class="section-status">{html.escape(str(section["status"]) + suffix)}</p>'

    candidate_table = _table(
        (
            "Ordinal",
            "Terminal status",
            "Eligibility",
            "Within-fit",
            "Within-fit reason",
            "Chain",
            "Chain reason",
        ),
        tuple(
            (
                row["candidate_ordinal"],
                row["final_status"],
                row["eligibility"],
                row["within_fit_status"],
                row["within_fit_reason_code"] or "none",
                row["chain_status"],
                row["chain_reason_code"] or "none",
            )
            for row in candidates
        ),
    )

    def metric_cell(record: Mapping[str, Any], field: str) -> str:
        metric = _require_mapping(record.get(field))
        metric_status = _require_string(metric.get("status"))
        metric_value = metric.get("value")
        metric_reason = metric.get("reason_code")
        if metric_status == "ASSESSABLE":
            if metric_reason is not None or metric_value is None:
                raise _report_contract_error()
            if type(metric_value) is bool:
                return "yes" if metric_value else "no"
            if type(metric_value) not in {int, float}:
                raise _report_contract_error()
            return str(metric_value)
        if metric_value is not None or type(metric_reason) is not str:
            raise _report_contract_error()
        return f"{metric_status}: {metric_reason}"

    def comparison_metric_cells(
        record: Mapping[str, Any],
        *,
        include_maximum_rank_displacement: bool,
    ) -> tuple[str, ...]:
        bundle = _require_mapping(record.get("metric_bundle"))
        fields = ["kendall_distance", "footrule_distance"]
        if include_maximum_rank_displacement:
            fields.append("maximum_normalized_event_rank_displacement")
        fields.extend(("position_matrix_distance", "pairwise_matrix_distance"))
        flip_bundle = _require_mapping(bundle.get("pairwise_majority_flips"))
        return (
            *(metric_cell(bundle, field) for field in fields),
            metric_cell(flip_bundle, "flip_fraction"),
        )

    def nullable_cell(value: object) -> str:
        if value is None:
            return "not available"
        if type(value) is bool:
            return "yes" if value else "no"
        if type(value) not in {str, int, float}:
            raise _report_contract_error()
        return str(value)

    def nullable_event_order_cell(value: object) -> str:
        if value is None:
            return "not available"
        if type(value) is not list or any(type(item) is not str for item in value):
            raise _report_contract_error()
        return ", ".join(cast(list[str], value))

    def component_table(layer: Mapping[str, Any]) -> str:
        components = layer.get("component_coverage")
        if type(components) is not list or not components:
            raise _report_contract_error()
        return _table(
            ("Component", "Implementation", "Typed reason"),
            tuple(
                (
                    _require_string(_require_mapping(value).get("component")),
                    _require_string(_require_mapping(value).get("implementation_status")),
                    _require_mapping(value).get("reason_code") or "none",
                )
                for value in components
            ),
        )

    sampling_attempts = sampling_evidence.get("attempts")
    sampling_numeric_records = sampling_evidence.get("numeric_records")
    sampling_aggregates = sampling_evidence.get("aggregates")
    if (
        type(sampling_attempts) is not list
        or type(sampling_numeric_records) is not list
        or type(sampling_aggregates) is not list
    ):
        raise _report_contract_error()
    sampling_attempt_rows: list[tuple[object, ...]] = []
    for value in sampling_attempts:
        attempt = _require_mapping(value)
        descriptor = _require_mapping(attempt.get("operation_descriptor"))
        sampling_attempt_rows.append(
            (
                _require_string(attempt.get("attempt_digest")),
                _require_string(attempt.get("experiment_set_id")),
                _require_string(attempt.get("subject_analysis_spec_id")),
                _require_string(attempt.get("source_analysis_spec_id")),
                _require_string(attempt.get("numeric_comparison_digest")),
                _require_string(descriptor.get("experiment_mode")),
                _require_string(descriptor.get("sampling_method_id")),
                _require_string(descriptor.get("sampling_design")),
                (
                    descriptor.get("retained_fraction")
                    if descriptor.get("retained_fraction") is not None
                    else "not applicable"
                ),
                _require_string(descriptor.get("fixed_evaluation_cohort_policy")),
                descriptor.get("replicate_ordinal"),
                _require_string(attempt.get("subject_terminal_status")),
                _require_string(attempt.get("source_terminal_status")),
                _require_string(attempt.get("contribution_state")),
                attempt.get("reason_code") or "none",
            )
        )
    sampling_attempt_table = _table(
        (
            "Attempt digest",
            "Experiment set",
            "Sampling analysis",
            "Source analysis",
            "Numeric comparison digest",
            "Mode",
            "Method",
            "Design",
            "Retained fraction",
            "Fixed evaluation cohort",
            "Replicate",
            "Sampling-fit terminal status",
            "Source terminal status",
            "Contribution",
            "Typed reason",
        ),
        sampling_attempt_rows,
    )

    sampling_family_rows: list[tuple[object, ...]] = []
    sampling_metric_summary_rows: list[tuple[object, ...]] = []
    sampling_event_position_rows: list[tuple[object, ...]] = []
    sampling_endpoint_rows: list[tuple[object, ...]] = []
    sampling_relation_rows: list[tuple[object, ...]] = []
    sampling_pairwise_probability_rows: list[tuple[object, ...]] = []
    for value in sampling_aggregates:
        aggregate = _require_mapping(value)
        descriptor = _require_mapping(aggregate.get("operation_descriptor"))
        replicate_ordinals = aggregate.get("replicate_ordinals")
        metric_summaries = aggregate.get("metric_summaries")
        event_positions = aggregate.get("event_modal_position_frequencies")
        central_relations = aggregate.get("central_order_relation_frequencies")
        within_fit_relations = aggregate.get("within_fit_majority_relation_frequencies")
        probability_distributions = aggregate.get("within_fit_pairwise_probability_distributions")
        strata_group_spec_ids = descriptor.get("strata_group_spec_ids")
        if (
            type(replicate_ordinals) is not list
            or type(metric_summaries) is not list
            or type(event_positions) is not list
            or type(central_relations) is not list
            or type(within_fit_relations) is not list
            or type(probability_distributions) is not list
            or type(strata_group_spec_ids) is not list
        ):
            raise _report_contract_error()
        retained_fraction = (
            descriptor.get("retained_fraction")
            if descriptor.get("retained_fraction") is not None
            else "not applicable"
        )
        family_prefix = (
            _require_string(aggregate.get("aggregate_digest")),
            _require_string(aggregate.get("experiment_set_id")),
            _require_string(aggregate.get("source_analysis_spec_id")),
            _require_string(descriptor.get("experiment_mode")),
            retained_fraction,
        )
        sampling_family_rows.append(
            (
                *family_prefix,
                _require_string(descriptor.get("sampling_method_id")),
                _require_string(descriptor.get("sampling_design")),
                ", ".join(_require_string(group_spec_id) for group_spec_id in strata_group_spec_ids)
                or "none",
                _require_string(descriptor.get("fixed_evaluation_cohort_policy")),
                ", ".join(str(ordinal) for ordinal in replicate_ordinals),
                aggregate.get("planned_origin_count"),
                aggregate.get("interpretive_numeric_count"),
            )
        )
        for metric_value in metric_summaries:
            metric = _require_mapping(metric_value)
            sampling_metric_summary_rows.append(
                (
                    *family_prefix,
                    _require_string(metric.get("metric_id")),
                    _require_string(metric.get("status")),
                    metric.get("valid_count"),
                    metric.get("q10"),
                    metric.get("median"),
                    metric.get("q90"),
                    metric.get("maximum"),
                    metric.get("reason_code") or "none",
                )
            )
        for event_value in event_positions:
            event = _require_mapping(event_value)
            position_counts = event.get("position_counts")
            position_frequencies = event.get("position_frequencies")
            if type(position_counts) is not list or type(position_frequencies) is not list:
                raise _report_contract_error()
            sampling_event_position_rows.append(
                (
                    *family_prefix,
                    _require_string(event.get("event_id")),
                    event.get("contributing_count"),
                    ", ".join(str(count) for count in position_counts),
                    ", ".join(str(frequency) for frequency in position_frequencies),
                )
            )
        endpoint = _require_mapping(aggregate.get("endpoint_stability"))
        sampling_endpoint_rows.append(
            (
                *family_prefix,
                endpoint.get("k"),
                endpoint.get("contributing_count"),
                endpoint.get("first_event_stable_count"),
                endpoint.get("first_event_stable_frequency"),
                endpoint.get("last_event_stable_count"),
                endpoint.get("last_event_stable_frequency"),
                endpoint.get("reason_code") or "none",
            )
        )
        for relation_value in (*central_relations, *within_fit_relations):
            relation = _require_mapping(relation_value)
            sampling_relation_rows.append(
                (
                    *family_prefix,
                    _require_string(relation.get("relation_basis")),
                    _require_string(relation.get("event_a_id")),
                    _require_string(relation.get("event_b_id")),
                    relation.get("contributing_count"),
                    relation.get("a_before_b_count"),
                    relation.get("b_before_a_count"),
                    relation.get("tied_count"),
                    relation.get("a_before_b_frequency"),
                    relation.get("b_before_a_frequency"),
                    relation.get("tied_frequency"),
                )
            )
        for distribution_value in probability_distributions:
            distribution = _require_mapping(distribution_value)
            sampling_pairwise_probability_rows.append(
                (
                    *family_prefix,
                    _require_string(distribution.get("event_a_id")),
                    _require_string(distribution.get("event_b_id")),
                    distribution.get("contributing_count"),
                    distribution.get("q10"),
                    distribution.get("median"),
                    distribution.get("q90"),
                    distribution.get("minimum"),
                    distribution.get("maximum"),
                    distribution.get("mean"),
                )
            )

    family_key_headers = (
        "Aggregate digest",
        "Experiment set",
        "Source analysis",
        "Mode",
        "Retained fraction",
    )
    sampling_family_table = _table(
        (
            *family_key_headers,
            "Method",
            "Design",
            "Strata groups",
            "Fixed evaluation cohort",
            "Replicates",
            "Planned origins",
            "Interpretive numeric fits",
        ),
        sampling_family_rows,
    )
    sampling_metric_summary_table = _table(
        (
            *family_key_headers,
            "Metric",
            "Status",
            "Valid fits",
            "Q10",
            "Median",
            "Q90",
            "Maximum",
            "Typed reason",
        ),
        sampling_metric_summary_rows,
    )
    sampling_event_position_table = _table(
        (
            *family_key_headers,
            "Event",
            "Contributing fits",
            "Position counts",
            "Position frequencies",
        ),
        sampling_event_position_rows,
    )
    sampling_endpoint_table = _table(
        (
            *family_key_headers,
            "K",
            "Contributing fits",
            "First-event stable count",
            "First-event stable frequency",
            "Last-event stable count",
            "Last-event stable frequency",
            "Typed reason",
        ),
        sampling_endpoint_rows,
    )
    sampling_relation_table = _table(
        (
            *family_key_headers,
            "Relation basis",
            "Event A",
            "Event B",
            "Contributing fits",
            "A-before-B count",
            "B-before-A count",
            "Tied count",
            "A-before-B frequency",
            "B-before-A frequency",
            "Tied frequency",
        ),
        sampling_relation_rows,
    )
    sampling_pairwise_probability_table = _table(
        (
            *family_key_headers,
            "Event A",
            "Event B",
            "Contributing fits",
            "Q10",
            "Median",
            "Q90",
            "Minimum",
            "Maximum",
            "Mean",
        ),
        sampling_pairwise_probability_rows,
    )

    sampling_numeric_rows: list[tuple[object, ...]] = []
    for value in sampling_numeric_records:
        numeric = _require_mapping(value)
        identity = _require_mapping(numeric.get("numeric_identity"))
        descriptor = _require_mapping(numeric.get("operation_descriptor"))
        sampling_numeric_rows.append(
            (
                _require_string(numeric.get("numeric_comparison_digest")),
                _require_string(identity.get("subject_analysis_spec_id")),
                _require_string(identity.get("source_analysis_spec_id")),
                _require_string(descriptor.get("experiment_mode")),
                _require_string(descriptor.get("sampling_design")),
                (
                    descriptor.get("retained_fraction")
                    if descriptor.get("retained_fraction") is not None
                    else "not applicable"
                ),
                descriptor.get("replicate_ordinal"),
                _require_string(numeric.get("eligibility")),
                _require_string(numeric.get("numeric_status")),
                numeric.get("reason_code") or "none",
                *comparison_metric_cells(
                    numeric,
                    include_maximum_rank_displacement=True,
                ),
            )
        )
    sampling_numeric_table = _table(
        (
            "Numeric comparison digest",
            "Sampling analysis",
            "Source analysis",
            "Mode",
            "Design",
            "Retained fraction",
            "Replicate",
            "Eligibility",
            "Numeric status",
            "Typed reason",
            "Kendall distance",
            "Footrule distance",
            "Maximum rank displacement",
            "Position-matrix distance",
            "Pairwise-matrix distance",
            "Pairwise flip fraction",
        ),
        sampling_numeric_rows,
    )
    sampling_summary = (
        "<p><strong>No declared sampling comparison attempts were planned.</strong> "
        "The pending sampling components remain listed below.</p>"
        if not sampling_attempts
        else (
            "<p><strong>Declared sampling evidence is separated by operation "
            "family.</strong> "
            "Each attempt retains its source fit, terminal state, and contribution "
            "state. Bootstrap and subsampling are never pooled; participant-stage "
            "sampling remains separately typed below.</p>"
        )
    )
    sampling_accounting_table = _table(
        ("Typed count", "Value"),
        (
            ("Sampling attempts", sampling_evidence["attempt_count"]),
            (
                "Unique numeric comparisons",
                sampling_evidence["unique_numeric_record_count"],
            ),
            ("Aggregate families", sampling_evidence["family_count"]),
            ("Classification", sampling_evidence["classification_status"]),
        ),
    )

    analyst_attempts = analyst_decision_evidence.get("attempts")
    analyst_numeric_records = analyst_decision_evidence.get("numeric_records")
    analyst_aggregates = analyst_decision_evidence.get("aggregates")
    analyst_accounting = _require_mapping(analyst_decision_evidence.get("accounting"))
    if (
        type(analyst_attempts) is not list
        or type(analyst_numeric_records) is not list
        or type(analyst_aggregates) is not list
    ):
        raise _report_contract_error()

    analyst_attempt_table = _table(
        (
            "Origin identity",
            "Experiment set",
            "Mode",
            "Full declared vector",
            "Axis",
            "Choice",
            "Applicability",
            "Subject analysis",
            "Comparator analysis",
            "Numeric comparison identity",
            "Subject terminal status",
            "Comparator terminal status",
            "Contribution",
            "Attribution semantics",
            "Typed reason",
        ),
        tuple(
            (
                _require_string(_require_mapping(value).get("origin_id")),
                _require_string(_require_mapping(value).get("experiment_set_id")),
                _require_string(_require_mapping(value).get("experiment_mode")),
                _axis_vector_cell(_require_mapping(value).get("axis_choices")),
                _require_mapping(value).get("axis_id") or "none",
                _require_mapping(value).get("choice_id") or "none",
                _require_string(_require_mapping(value).get("applicability_state")),
                _require_string(_require_mapping(value).get("subject_analysis_spec_id")),
                _require_string(_require_mapping(value).get("comparator_analysis_spec_id")),
                _require_mapping(value).get("numeric_comparison_digest") or "not applicable",
                _require_string(_require_mapping(value).get("subject_terminal_status")),
                _require_string(_require_mapping(value).get("comparator_terminal_status")),
                _require_string(_require_mapping(value).get("contribution_state")),
                _require_string(_require_mapping(value).get("attribution_semantics")),
                _require_mapping(value).get("reason_code") or "none",
            )
            for value in analyst_attempts
        ),
    )
    analyst_numeric_table = _table(
        (
            "Numeric comparison digest",
            "Subject analysis",
            "Comparator analysis",
            "Eligibility",
            "Numeric status",
            "Typed reason",
            "Kendall distance",
            "Footrule distance",
            "Position-matrix distance",
            "Pairwise-matrix distance",
            "Pairwise flip fraction",
        ),
        tuple(
            (
                _require_string(_require_mapping(value).get("numeric_comparison_digest")),
                _require_string(
                    _require_mapping(_require_mapping(value).get("numeric_identity")).get(
                        "subject_analysis_spec_id"
                    )
                ),
                _require_string(
                    _require_mapping(_require_mapping(value).get("numeric_identity")).get(
                        "comparator_analysis_spec_id"
                    )
                ),
                _require_string(_require_mapping(value).get("eligibility")),
                _require_string(_require_mapping(value).get("numeric_status")),
                _require_mapping(value).get("reason_code") or "none",
                *comparison_metric_cells(
                    _require_mapping(value),
                    include_maximum_rank_displacement=False,
                ),
            )
            for value in analyst_numeric_records
        ),
    )
    analyst_rank_shift_rows: list[tuple[object, ...]] = []
    for value in analyst_numeric_records:
        record = _require_mapping(value)
        comparison_digest = _require_string(record.get("numeric_comparison_digest"))
        bundle = _require_mapping(record.get("metric_bundle"))
        rank_shifts = _require_mapping(bundle.get("event_rank_shifts"))
        rule_id = _require_string(rank_shifts.get("rule_id"))
        absolute_metric_id = _require_string(rank_shifts.get("absolute_rank_shift_metric_id"))
        normalized_metric_id = _require_string(rank_shifts.get("normalized_rank_shift_metric_id"))
        rank_shift_status = _require_string(rank_shifts.get("status"))
        rank_shift_reason = rank_shifts.get("reason_code")
        event_rows = rank_shifts.get("event_rows")
        if type(event_rows) is not list:
            raise _report_contract_error()
        if rank_shift_status == "ASSESSABLE":
            if rank_shift_reason is not None or not event_rows:
                raise _report_contract_error()
            for event_value in event_rows:
                event = _require_mapping(event_value)
                analyst_rank_shift_rows.append(
                    (
                        comparison_digest,
                        rule_id,
                        absolute_metric_id,
                        normalized_metric_id,
                        rank_shift_status,
                        _require_string(event.get("event_id")),
                        event.get("subject_rank"),
                        event.get("comparator_rank"),
                        event.get("absolute_rank_shift"),
                        event.get("normalized_rank_shift"),
                        "none",
                    )
                )
        elif rank_shift_status == "NOT_ASSESSABLE":
            if type(rank_shift_reason) is not str or event_rows:
                raise _report_contract_error()
            analyst_rank_shift_rows.append(
                (
                    comparison_digest,
                    rule_id,
                    absolute_metric_id,
                    normalized_metric_id,
                    rank_shift_status,
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    rank_shift_reason,
                )
            )
        else:
            raise _report_contract_error()
    analyst_rank_shift_table = _table(
        (
            "Numeric comparison digest",
            "Rank-shift rule",
            "Absolute metric",
            "Normalized metric",
            "Status",
            "Event",
            "Subject rank",
            "Comparator rank",
            "Absolute rank shift",
            "Normalized rank shift",
            "Typed reason",
        ),
        tuple(analyst_rank_shift_rows),
    )
    analyst_combination_table = _analyst_combination_table(analyst_aggregates)
    analyst_modes_by_numeric_digest: dict[str, set[str]] = {}
    for attempt_value in analyst_attempts:
        attempt = _require_mapping(attempt_value)
        numeric_digest = attempt.get("numeric_comparison_digest")
        if numeric_digest is None:
            continue
        analyst_modes_by_numeric_digest.setdefault(
            _require_string(numeric_digest),
            set(),
        ).add(_require_string(attempt.get("experiment_mode")))
    analyst_count_rows = (
        *(
            (label, analyst_accounting[field])
            for label, field in (
                ("Planned origins", "planned_origin_count"),
                ("Baseline reference origins", "reference_origin_count"),
                ("Applicable ordinary origins", "applicable_origin_count"),
                ("Other non-applicable origins", "not_applicable_origin_count"),
                ("Assessable origins", "assessable_origin_count"),
                ("Interpretive origins", "interpretive_origin_count"),
                ("Descriptive-only origins", "descriptive_only_origin_count"),
                (
                    "Metric-not-assessable origins",
                    "metric_not_assessable_origin_count",
                ),
                ("Failed origins", "failed_origin_count"),
                (
                    "Unique applicable numeric comparisons",
                    "unique_applicable_numeric_pair_count",
                ),
            )
        ),
        ("Aggregate families", len(analyst_aggregates)),
    )
    analyst_accounting_table = _table(
        ("Typed count", "Value"),
        analyst_count_rows,
    )

    influence_attempts = influence.get("attempts")
    if type(influence_attempts) is not list:
        raise _report_contract_error()
    influence_rows: list[tuple[object, ...]] = []
    for attempt_value in influence_attempts:
        attempt = _require_mapping(attempt_value)
        aliases = attempt.get("removed_aliases")
        reasons = attempt.get("reason_rows")
        record_value = attempt.get("influence_record")
        if (
            type(aliases) is not list
            or any(type(alias) is not str for alias in aliases)
            or type(reasons) is not list
        ):
            raise _report_contract_error()
        alias_label = ", ".join(cast(list[str], aliases))
        if not alias_label:
            named_group = attempt.get("named_group_spec_id")
            alias_label = (
                f"group:{named_group}" if type(named_group) is str else "no pseudonymous alias"
            )
        reason_text = ", ".join(
            (
                f"{_require_string(_require_mapping(reason).get('owner'))}:"
                f"{_require_string(_require_mapping(reason).get('reason_code'))}"
            )
            for reason in reasons
        )
        if record_value is None:
            influence_rows.append(
                (
                    alias_label,
                    attempt["contribution_state"],
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    "not available",
                    reason_text or "none",
                )
            )
            continue
        record = _require_mapping(record_value)
        component_states = _require_mapping(record.get("component_states"))
        high_components = sorted(
            (
                component_id
                for component_id, component_state in component_states.items()
                if component_state == "INFLUENCE_COMPONENT_HIGH"
            ),
            key=lambda value: value.encode("utf-8"),
        )
        influence_rows.append(
            (
                alias_label,
                attempt["contribution_state"],
                _require_string(record.get("participant_state")),
                ", ".join(high_components) or "none",
                metric_cell(record, "central_order_kendall_distance"),
                metric_cell(
                    record,
                    "maximum_normalized_event_rank_displacement",
                ),
                metric_cell(
                    record,
                    "strict_pairwise_majority_flip_fraction",
                ),
                metric_cell(record, "position_matrix_distance"),
                metric_cell(record, "pairwise_matrix_distance"),
                metric_cell(record, "convergence_degradation"),
                metric_cell(
                    record,
                    "fixed_cohort_stage_wasserstein_median",
                ),
                reason_text or "none",
            )
        )
    influence_rows.sort(key=lambda row: str(row[0]).encode("utf-8"))
    influence_table = _table(
        (
            "Removed alias or group",
            "Contribution",
            "Multi-component classification",
            "High components",
            "Kendall distance",
            "Maximum rank displacement",
            "Pairwise flip fraction",
            "Position-matrix distance",
            "Pairwise-matrix distance",
            "Convergence degraded",
            "Fixed-cohort stage movement",
            "Reasons",
        ),
        tuple(influence_rows),
    )
    participant_stage_rows: list[tuple[object, ...]] = []
    participant_stage_metric_rows: list[tuple[object, ...]] = []
    for row_value in participant_stage_comparisons:
        row = _validate_participant_stage_projection_row(row_value)
        identity = _require_mapping(row.get("numeric_identity"))
        comparison = _require_mapping(row.get("participant_stage_comparison"))
        comparison_digest = _require_string(row.get("numeric_comparison_digest"))
        source_layer = _require_string(row.get("source_layer"))
        if source_layer == "SAMPLING":
            operation_descriptor = _require_mapping(row.get("operation_descriptor"))
            operation_family = _require_string(operation_descriptor.get("experiment_mode"))
            operation_method = _require_string(operation_descriptor.get("sampling_method_id"))
            replicate_ordinal: object = operation_descriptor.get("replicate_ordinal")
            counterpart_analysis_spec_id = _require_string(identity.get("source_analysis_spec_id"))
            counterpart_terminal_status = _require_string(row.get("source_terminal_status"))
        else:
            modes = analyst_modes_by_numeric_digest.get(comparison_digest)
            if not modes:
                raise _report_contract_error()
            operation_family = "ordinary:" + ",".join(
                sorted(modes, key=lambda value: value.encode("utf-8"))
            )
            operation_method = "not applicable"
            replicate_ordinal = "not applicable"
            counterpart_analysis_spec_id = _require_string(
                identity.get("comparator_analysis_spec_id")
            )
            counterpart_terminal_status = _require_string(row.get("comparator_terminal_status"))
        quantiles = _require_mapping(comparison.get("normalized_stage_wasserstein_quantiles"))
        participant_stage_rows.append(
            (
                comparison_digest,
                source_layer,
                operation_family,
                operation_method,
                replicate_ordinal,
                _require_string(identity.get("subject_analysis_spec_id")),
                counterpart_analysis_spec_id,
                _require_string(row.get("subject_terminal_status")),
                counterpart_terminal_status,
                _require_string(row.get("eligibility")),
                _require_string(comparison.get("left_availability")),
                _require_string(comparison.get("right_availability")),
                _require_string(comparison.get("availability")),
                comparison.get("availability_reason_code") or "none",
                nullable_cell(comparison.get("left_stage_model_reference_digest")),
                nullable_event_order_cell(comparison.get("left_stage_reference_order_event_ids")),
                nullable_event_order_cell(comparison.get("left_headline_central_order_event_ids")),
                nullable_cell(comparison.get("left_stage_reference_order_matches_headline")),
                nullable_cell(comparison.get("right_stage_model_reference_digest")),
                nullable_event_order_cell(comparison.get("right_stage_reference_order_event_ids")),
                nullable_event_order_cell(comparison.get("right_headline_central_order_event_ids")),
                nullable_cell(comparison.get("right_stage_reference_order_matches_headline")),
                ", ".join(cast(Sequence[str], comparison.get("left_ordered_event_ids"))),
                ", ".join(cast(Sequence[str], comparison.get("right_ordered_event_ids"))),
                ", ".join(cast(Sequence[str], comparison.get("common_event_ids"))),
                comparison.get("common_event_count"),
                ", ".join(cast(Sequence[str], comparison.get("left_only_event_ids"))) or "none",
                ", ".join(cast(Sequence[str], comparison.get("right_only_event_ids"))) or "none",
                comparison.get("same_event_set"),
                comparison.get("same_ordered_event_ids"),
                comparison.get("same_event_direction_bindings"),
                comparison.get("same_stage_semantics"),
                _require_string(comparison.get("semantic_comparability")),
                comparison.get("semantic_comparability_reason_code") or "none",
                comparison.get("same_evaluation_cohort"),
                comparison.get("same_evaluation_row_indexes"),
                comparison.get("same_evaluation_unit_bindings"),
                comparison.get("evaluation_cohort_count"),
                comparison.get("evaluation_cohort_digest") or "none",
                _require_string(comparison.get("participant_selection_source")),
                comparison.get("cohort_denominator_count"),
                comparison.get("valid_participant_count"),
                comparison.get("missing_participant_count"),
                _require_string(comparison.get("quantile_rule_id")),
                nullable_cell(quantiles.get("q10")),
                nullable_cell(quantiles.get("q25")),
                nullable_cell(quantiles.get("q50")),
                nullable_cell(quantiles.get("q75")),
                nullable_cell(quantiles.get("q90")),
                nullable_cell(comparison.get("normalized_stage_wasserstein_iqr")),
                _require_string(comparison.get("private_evidence_digest")),
                _require_string(comparison.get("metric_status")),
                comparison.get("metric_reason_code") or "none",
            )
        )
        metrics = comparison.get("metrics")
        if type(metrics) is not list:
            raise _report_contract_error()
        for metric_value in metrics:
            metric = _require_mapping(metric_value)
            metric_status = _require_string(metric.get("status"))
            metric_reason = metric.get("reason_code")
            metric_value_exact = metric.get("value")
            if metric_status == "ASSESSABLE":
                if metric_reason is not None or type(metric_value_exact) not in {int, float}:
                    raise _report_contract_error()
                rendered_value: object = metric_value_exact
            else:
                if metric_value_exact is not None or type(metric_reason) is not str:
                    raise _report_contract_error()
                rendered_value = "not available"
            participant_stage_metric_rows.append(
                (
                    comparison_digest,
                    source_layer,
                    operation_family,
                    _require_string(metric.get("metric_id")),
                    metric_status,
                    rendered_value,
                    metric_reason or "none",
                )
            )
    participant_stage_table = _table(
        (
            "Numeric comparison digest",
            "Source layer",
            "Operation family",
            "Sampling method",
            "Replicate",
            "Subject analysis",
            "Comparator/source analysis",
            "Subject terminal status",
            "Comparator/source terminal status",
            "Eligibility",
            "Subject stage availability",
            "Comparator stage availability",
            "Combined stage availability",
            "Availability reason",
            "Subject stage-model reference digest",
            "Subject stage-reference order",
            "Subject headline central order",
            "Subject reference order matches headline",
            "Comparator stage-model reference digest",
            "Comparator stage-reference order",
            "Comparator headline central order",
            "Comparator reference order matches headline",
            "Subject ordered events",
            "Comparator ordered events",
            "Common events",
            "Common event count",
            "Subject-only events",
            "Comparator-only events",
            "Same event set",
            "Same ordered events",
            "Same event directions",
            "Same stage semantics",
            "Semantic comparability",
            "Semantic comparability reason",
            "Same evaluation cohort",
            "Same evaluation row alignment",
            "Same evaluation unit binding",
            "Evaluation cohort count",
            "Evaluation cohort digest",
            "Participant selection source",
            "Cohort denominator",
            "Valid participants",
            "Missing participants",
            "Quantile rule",
            "Normalized stage Wasserstein q10",
            "Normalized stage Wasserstein q25",
            "Normalized stage Wasserstein q50",
            "Normalized stage Wasserstein q75",
            "Normalized stage Wasserstein q90",
            "Normalized stage Wasserstein IQR",
            "Private evidence digest",
            "Metric status",
            "Metric reason",
        ),
        tuple(participant_stage_rows),
    )
    participant_stage_metrics_table = _table(
        (
            "Numeric comparison digest",
            "Source layer",
            "Operation family",
            "Metric",
            "Status",
            "Exact aggregate value",
            "Reason",
        ),
        tuple(participant_stage_metric_rows),
    )
    null_attempts = null_evidence.get("attempts")
    if type(null_attempts) is not list:
        raise _report_contract_error()
    null_rows: list[tuple[object, ...]] = []
    for attempt_value in null_attempts:
        attempt = _require_mapping(attempt_value)
        null_rows.append(
            (
                _require_string(attempt.get("source_analysis_spec_id")),
                _require_string(attempt.get("source_variant_id")),
                _require_string(attempt.get("derived_source_variant_id")),
                _require_string(attempt.get("null_family_id")),
                _require_string(attempt.get("null_method_id")),
                attempt["replicate_ordinal"],
                _require_string(attempt.get("final_status")),
                _require_string(attempt.get("source_final_status")),
                "UNCALIBRATED",
            )
        )
    null_table = _table(
        (
            "Ordinary source analysis",
            "Source variant",
            "Derived source variant",
            "Null family",
            "Refit method",
            "Replicate",
            "Null terminal status",
            "Source terminal status",
            "Calibration",
        ),
        tuple(null_rows),
    )
    if not null_rows:
        null_summary = (
            "<p><strong>No refitted null runs were planned for this audit.</strong> "
            "No null-family comparison is inferred from the empty roster.</p>"
        )
        null_table = ""
    else:
        null_summary = (
            "<p><strong>Refitted null runs are retained, but not calibrated.</strong>\n"
            "This report lists each transformed run and its ordinary source separately.\n"
            "It does not pool null families, calculate a p-value or false-positive rate, or\n"
            "claim that an observed order is stronger than no-signal behavior.</p>"
        )
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incomplete EBM Robustness Audit Report</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, sans-serif; }}
body {{ margin: 2rem auto; max-width: 76rem; padding: 0 1rem; line-height: 1.5;
        overflow-wrap: anywhere; }}
h1, h2 {{ color: #17324d; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #b8c2cc; padding: .45rem; text-align: left; }}
th {{ background: #eef3f7; }}
.gate {{ border-left: .35rem solid #b35300; padding: .75rem; background: #fff5e9; }}
.report-status {{ border: .2rem solid #9b2c2c; padding: .8rem; font-weight: 800; }}
.section-status {{ font-weight: 700; }}
code {{ overflow-wrap: anywhere; }}
.summary-scroll {{ overflow-x: auto; }}
.table-scroll {{ overflow-x: auto; max-width: 100%; }}
#native-objective-summary table {{ min-width: 40rem; }}
pre {{ overflow-x: auto; max-width: 100%; }}
#decision-summary {{ border: 1px solid #b8c2cc; padding: 1rem; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>EBM Robustness Audit Report</h1>
<p class="report-status">REPORT STATUS: INCOMPLETE</p>
{input_label}
<p>Science completion gate: <code>{html.escape(str(gate["status"]))}</code> —
{html.escape(", ".join(cast(Sequence[str], gate["reason_codes"])))}</p>
<h2>1. What this audit can and cannot establish</h2>
{status("scope")}
<p>{html.escape(MANDATORY_OPENING)}</p>
<p class="gate">{html.escape(baseline_language)}</p>
<p class="gate">{html.escape(NULL_SAFE_FALLBACK)}</p>
{decision_summary_html(model)}
{native_objective_html}
<h2>2. Dataset and specification summary</h2>
{status("dataset-and-specification")}
{
        _table(
            ("Field", "Value"),
            (
                ("Plan digest", provenance["plan_digest"]),
                ("Planned candidates", execution["requested_candidate_count"]),
                ("Scientific evidence schema", provenance["scientific_evidence_schema_version"]),
            ),
        )
    }
<h2>3. Data and preprocessing accounting</h2>
{status("data-accounting")}
<p>Field-level preprocessing accounting is not yet bound into this report.</p>
<h2>4. Baseline fit and diagnostics</h2>
{status("baseline")}
<p>{html.escape(baseline_language)}</p>
{baseline_table}
<h2>5. Within-fit order uncertainty</h2>
{status("within-fit")}
{candidate_table}
<h2>6. Independent-chain and seed stability</h2>
{status("chain")}
{candidate_table}
<h2>7. Sampling and bootstrap stability</h2>
{status("sampling")}
{sampling_summary}
{sampling_accounting_table}
<h3>Sampling component coverage</h3>
{component_table(sampling_evidence)}
<h3>Sampling operation families</h3>
{sampling_family_table}
<h3>Family metric summaries</h3>
{sampling_metric_summary_table}
<h3>Family event-position frequencies</h3>
{sampling_event_position_table}
<h3>Family endpoint stability</h3>
{sampling_endpoint_table}
<h3>Family pairwise relation frequencies</h3>
{sampling_relation_table}
<h3>Family pairwise-probability distributions</h3>
{sampling_pairwise_probability_table}
<h3>Sampling attempt roster</h3>
{sampling_attempt_table}
<h3>Sampling numeric comparison records</h3>
{sampling_numeric_table}
<h2>8. Analysis-choice sensitivity</h2>
{status("analysis-choice")}
<p>Each declared origin remains attached to its exact applicability and
contribution state. Baseline, non-applicable, failed, descriptive, and
interpretive origins remain distinct; no overall score or cross-layer
substitution is produced. Combination and full-factorial cells are compared
with the literal declared baseline and labelled
<code>DESCRIPTIVE_ASSOCIATION</code>: the declared vector is associated with
movement. No context contrast is inferred.</p>
{analyst_accounting_table}
<h3>Analyst-decision component coverage</h3>
{component_table(analyst_decision_evidence)}
<h3>Declared analysis-choice origin roster</h3>
{analyst_attempt_table}
<h3>Analysis-choice numeric comparison records</h3>
{analyst_numeric_table}
<h3>Analysis-choice per-event rank displacement</h3>
{analyst_rank_shift_table}
<h3>Declared-combination and full-factorial descriptive attribution</h3>
{analyst_combination_table}
<h2>9. Pairwise precedence</h2>
{status("pairwise-precedence")}
<p>The exact pairwise evidence, when available, is retained in the
live-evidence-derived scientific projection artifact. This report does not
pool uncertainty layers.</p>
<h2>10. Participant influence</h2>
{status("participant-influence")}
<p>{html.escape(INFLUENCE_CAVEAT)}</p>
<p>The component table is sorted by pseudonymous alias, not by a combined
score. A display ranking remains unavailable until component scaling and
development sensitivity are validated.</p>
{influence_table}
<h2>11. Participant-stage stability</h2>
{status("participant-stage")}
<p>Each declared sampling or analyst-decision comparison is shown independently
and attributed to its originating layer and operation family. Values are copied
from the sealed fixed-cohort participant-stage record without pooling,
recalculation, retained-subsample substitution, or an order-based fallback.</p>
{participant_stage_table}
{participant_stage_metrics_table}
<h2>12. Null and no-signal comparison</h2>
{status("null")}
{null_summary}
{null_table}
{
        ""
        if development_null is None
        else (
            "<p><strong>Development-only, uncalibrated.</strong> "
            "The persisted null-relative state is "
            f"<code>{html.escape(str(development_null['null_relative_label']))}</code>. "
            "It does not establish held-out false-positive control or authorize "
            "strong null-relative language.</p>"
        )
    }
<p>{html.escape(NULL_SAFE_FALLBACK)}</p>
<h2>13. Failed, invalid, and unsupported universes</h2>
{status("terminal-universes")}
{candidate_table}
<h2>14. Methods and metric definitions</h2>
{status("methods")}
<p>Candidate execution status comes from the exact lifecycle disposition.
Scientific layer statuses come from the sealed live scientific projection.
Section limitation statuses are fixed by this report contract. Reporting does
not refit a model or combine distinct uncertainty layers.</p>
<h3>Ordered meaning evidence</h3>
<p>Each row is copied from the authenticated meaning bundle. Unavailable,
not-applicable, invalid, and failed meanings remain visible.</p>
{meaning_evidence_table}
<h3>Versioned report predicates</h3>
{report_predicate_table}
<h3>Required claim limitations</h3>
{required_claim_language or '<p>No evidence-activated claim limitation is available.</p>'}
<h2>15. Provenance, backend, benchmark, and limitations</h2>
{status("provenance")}
<h3>Requested-output capability evidence</h3>
{training_stage_capability_table}
<h3>Audit-check applicability</h3>
{audit_check_applicability_table}
{
        _table(
            ("Field", "Value"),
            (
                ("Scientific evidence digest", provenance["scientific_evidence_digest"]),
                ("Claim projection digest", provenance["report_claim_projection_sha256"]),
                (
                    "Ordered warning record digests",
                    canonical_json_bytes(
                        provenance["ordered_warning_record_sha256"]
                    ).decode("utf-8"),
                ),
                (
                    "Ordered public terminal result digests",
                    canonical_json_bytes(
                        provenance["ordered_public_terminal_result_sha256"]
                    ).decode("utf-8"),
                ),
                ("Meaning evidence digest", provenance["meaning_evidence_bundle_sha256"]),
                ("Meaning evidence graph digest", provenance["meaning_evidence_graph_digest"]),
                (
                    "Meaning evidence graph identity",
                    canonical_json_bytes(meaning_graph_identity).decode("utf-8"),
                ),
                ("Terminal index digest", provenance["terminal_index_digest"]),
                ("Scientific evidence rule", provenance["scientific_evidence_rule_id"]),
                ("Candidate execution status", execution["state"]),
            ),
        )
    }
<p>This incomplete report states current verified technical properties only.
Backend-provenance projection, benchmark authority, the final run gate, and
standalone report rehydration remain unavailable.</p>
</body>
</html>
"""
    assert_claims_allowed(body)
    return body.encode("utf-8")


def _write_exact_artifacts(
    store: PrivateArtifactStore,
    artifacts: Mapping[str, bytes],
    artifact_paths: Sequence[str],
) -> tuple[dict[str, str], ...]:
    if set(artifacts) != set(artifact_paths) or len(artifacts) != len(artifact_paths):
        raise _report_contract_error()
    receipts: list[dict[str, str]] = []
    for path in artifact_paths:
        content = artifacts[path]
        store.write_bytes(path, content)
        readback = store.read_bytes(path, maximum_bytes=len(content))
        if readback != content:
            raise _report_contract_error()
        receipts.append({"path": path, "sha256": exact_file_sha256(readback)})
    return tuple(receipts)


def _report_artifact_paths(
    *,
    development_null: bool,
    baseline_reproduction: bool = False,
) -> tuple[str, ...]:
    return (
        _REPORT_ARTIFACT_PATHS[0],
        *((_DEVELOPMENT_NULL_SCIENCE_RECEIPT_PATH,) if development_null else ()),
        BASELINE_ASSESSMENT_ARTIFACT_PATH,
        *((BASELINE_REPRODUCTION_ARTIFACT_PATH,) if baseline_reproduction else ()),
        *_REPORT_ARTIFACT_PATHS[1:],
    )


def _science_artifact_payloads(
    projection: Mapping[str, Any],
    *,
    development_null_science_projection: Mapping[str, Any] | None,
) -> dict[str, bytes]:
    payloads = {
        _REPORT_ARTIFACT_PATHS[0]: canonical_json_bytes(projection),
    }
    if development_null_science_projection is not None:
        wrapped_science = _require_mapping(
            development_null_science_projection.get("scientific_evidence")
        )
        if canonical_json_bytes(wrapped_science) != payloads[_REPORT_ARTIFACT_PATHS[0]]:
            raise _report_contract_error()
        payloads[_DEVELOPMENT_NULL_SCIENCE_RECEIPT_PATH] = canonical_json_bytes(
            development_null_science_projection
        )
    return payloads


def _private_stage_artifact_payloads(
    records: Sequence[tuple[bytes, str]],
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for ordinal, (canonical_bytes, expected_digest) in enumerate(records):
        decoded = strict_json_loads(canonical_bytes)
        if (
            type(decoded) is not dict
            or canonical_json_bytes(decoded) != canonical_bytes
            or decoded.get("private_evidence_digest") != expected_digest
        ):
            raise _report_contract_error()
        payloads[f"{_PRIVATE_STAGE_EVIDENCE_DIRECTORY}/{ordinal:08d}.json"] = canonical_bytes
    return payloads


def _validate_private_stage_linkage(
    records: Sequence[tuple[bytes, str]],
    participant_stage_rows: Sequence[object],
) -> None:
    unmatched_private_digests = [digest for _private_bytes, digest in records]
    for row_value in participant_stage_rows:
        row = _require_mapping(row_value)
        comparison = _require_mapping(row.get("participant_stage_comparison"))
        public_digest = _require_string(comparison.get("private_evidence_digest"))
        try:
            unmatched_private_digests.remove(public_digest)
        except ValueError:
            raise _report_contract_error() from None
    if unmatched_private_digests:
        raise _report_contract_error()


@dataclass(frozen=True, slots=True)
class _LiveReportTransactionResult:
    receipt: Mapping[str, Any]
    report_model_artifact_binding: AuthenticatedReportModelArtifactBinding
    authenticated_owner: _AuthenticatedLiveReportTransaction


@dataclass(frozen=True, slots=True)
class _LiveReportTransactionState:
    receipt: Mapping[str, Any]
    receipt_bytes: bytes
    report_model_artifact_binding: AuthenticatedReportModelArtifactBinding
    meaning_evidence_extension: AuthenticatedMeaningEvidenceExtension
    captured_scientific_run: CapturedScientificRun
    sealed_scientific_evidence: SealedScientificEvidence


class _AuthenticatedLiveReportTransaction:
    __slots__ = ("__weakref__",)

    def __new__(cls) -> _AuthenticatedLiveReportTransaction:
        raise TypeError("Authenticated live report transactions are issued by the producer.")

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise AttributeError("Authenticated live report transactions are immutable.")

    def __copy__(self) -> _AuthenticatedLiveReportTransaction:
        raise TypeError("Authenticated live report transactions cannot be copied.")

    def __deepcopy__(self, _memo: object) -> _AuthenticatedLiveReportTransaction:
        raise TypeError("Authenticated live report transactions cannot be copied.")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Authenticated live report transactions cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Authenticated live report transactions cannot be serialized.")


def _build_live_report_transaction_boundary() -> tuple[
    Callable[
        [
            Mapping[str, Any],
            AuthenticatedReportModelArtifactBinding,
            AuthenticatedMeaningEvidenceExtension,
            CapturedScientificRun,
            SealedScientificEvidence,
        ],
        _AuthenticatedLiveReportTransaction,
    ],
    Callable[[object], _LiveReportTransactionState],
]:
    states: WeakKeyDictionary[
        _AuthenticatedLiveReportTransaction,
        _LiveReportTransactionState,
    ] = WeakKeyDictionary()
    lock = Lock()

    def issue(
        receipt: Mapping[str, Any],
        report_model_artifact_binding: AuthenticatedReportModelArtifactBinding,
        meaning_evidence_extension: AuthenticatedMeaningEvidenceExtension,
        captured_scientific_run: CapturedScientificRun,
        sealed_scientific_evidence: SealedScientificEvidence,
        /,
    ) -> _AuthenticatedLiveReportTransaction:
        captured_state = _read_captured_scientific_run(captured_scientific_run)
        sealed_state = _read_sealed_scientific_evidence(sealed_scientific_evidence)
        binding_projection = _validated_binding_projection(report_model_artifact_binding)
        report_model = _read_authenticated_report_model(report_model_artifact_binding)
        artifact_contract_value = report_model.get("artifact_contract")
        provenance_value = report_model.get("provenance")
        if type(artifact_contract_value) is not dict or type(provenance_value) is not dict:
            raise TypeError("The live report transaction provenance is detached.")
        artifact_contract = cast(dict[str, Any], artifact_contract_value)
        provenance = cast(dict[str, Any], provenance_value)
        (
            claim_records,
            claim_digest,
            meaning_records,
            meaning_digest,
            evidence_graph_digest,
            evidence_graph_identity,
            ordered_warning_record_sha256,
            ordered_public_terminal_result_sha256,
            _extension_science_digest,
        ) = _report_extension_components(
            meaning_evidence_extension,
            scientific_evidence_digest=cast(
                str,
                provenance.get("scientific_evidence_digest"),
            ),
            captured_scientific_run=captured_scientific_run,
            sealed_scientific_evidence=sealed_scientific_evidence,
        )
        artifacts = receipt.get("artifacts")
        if (
            sealed_state.capture is not captured_scientific_run
            or captured_state.plan_digest != receipt.get("plan_digest")
            or sealed_state.evidence_digest != receipt.get("scientific_evidence_digest")
            or type(artifacts) is not list
            or report_model.get("report_predicates") != list(claim_records)
            or report_model.get("meaning_evidence") != list(meaning_records)
            or provenance.get("report_claim_projection_sha256") != claim_digest
            or provenance.get("meaning_evidence_bundle_sha256") != meaning_digest
            or provenance.get("meaning_evidence_graph_digest") != evidence_graph_digest
            or provenance.get("meaning_evidence_graph_identity")
            != evidence_graph_identity
            or provenance.get("ordered_warning_record_sha256")
            != list(ordered_warning_record_sha256)
            or provenance.get("ordered_public_terminal_result_sha256")
            != list(ordered_public_terminal_result_sha256)
            or receipt.get("meaning_evidence_graph_digest")
            != evidence_graph_digest
            or receipt.get("meaning_evidence_graph_identity")
            != evidence_graph_identity
        ):
            raise TypeError("The live report transaction provenance is detached.")
        for path, field in (
            ("report/report.json", "report_artifact_sha256"),
            ("report/report.html", "report_html_artifact_sha256"),
        ):
            rows = [row for row in artifacts if type(row) is dict and row.get("path") == path]
            if len(rows) != 1 or rows[0].get("sha256") != binding_projection[field]:
                raise TypeError("The live report transaction provenance is detached.")
        meaning_rows = [
            row
            for row in artifacts
            if type(row) is dict and row.get("path") == "report/meaning-evidence.csv"
        ]
        if (
            len(meaning_rows) != 1
            or meaning_rows[0].get("sha256")
            != artifact_contract.get("meaning_evidence_csv_sha256")
        ):
            raise TypeError("The live report transaction provenance is detached.")
        provenance_rows = [
            row
            for row in artifacts
            if type(row) is dict and row.get("path") == "report/provenance.csv"
        ]
        if (
            len(provenance_rows) != 1
            or provenance_rows[0].get("sha256")
            != artifact_contract.get("report_provenance_csv_sha256")
        ):
            raise TypeError("The live report transaction provenance is detached.")
        owner = object.__new__(_AuthenticatedLiveReportTransaction)
        state = _LiveReportTransactionState(
            receipt=receipt,
            receipt_bytes=canonical_json_bytes(dict(receipt)),
            report_model_artifact_binding=report_model_artifact_binding,
            meaning_evidence_extension=meaning_evidence_extension,
            captured_scientific_run=captured_scientific_run,
            sealed_scientific_evidence=sealed_scientific_evidence,
        )
        with lock:
            states[owner] = state
        return owner

    def consume(owner: object, /) -> _LiveReportTransactionState:
        if type(owner) is not _AuthenticatedLiveReportTransaction:
            raise TypeError("A genuine live report transaction owner is required.")
        with lock:
            try:
                state = states.pop(owner)
            except (KeyError, TypeError):
                raise TypeError("The live report transaction owner is not live.") from None
        captured_state = _read_captured_scientific_run(state.captured_scientific_run)
        sealed_state = _read_sealed_scientific_evidence(state.sealed_scientific_evidence)
        report_model = _read_authenticated_report_model(
            state.report_model_artifact_binding
        )
        provenance_value = report_model.get("provenance")
        if type(provenance_value) is not dict:
            raise TypeError("The live report transaction provenance is detached.")
        (
            claim_records,
            claim_digest,
            meaning_records,
            meaning_digest,
            evidence_graph_digest,
            evidence_graph_identity,
            ordered_warning_record_sha256,
            ordered_public_terminal_result_sha256,
            _extension_science_digest,
        ) = _report_extension_components(
            state.meaning_evidence_extension,
            scientific_evidence_digest=cast(
                str,
                cast(dict[str, Any], provenance_value).get(
                    "scientific_evidence_digest"
                ),
            ),
            captured_scientific_run=state.captured_scientific_run,
            sealed_scientific_evidence=state.sealed_scientific_evidence,
        )
        if (
            canonical_json_bytes(dict(state.receipt)) != state.receipt_bytes
            or sealed_state.capture is not state.captured_scientific_run
            or captured_state.plan_digest != state.receipt.get("plan_digest")
            or sealed_state.evidence_digest != state.receipt.get("scientific_evidence_digest")
            or report_model.get("report_predicates") != list(claim_records)
            or report_model.get("meaning_evidence") != list(meaning_records)
            or provenance_value.get("report_claim_projection_sha256") != claim_digest
            or provenance_value.get("meaning_evidence_bundle_sha256") != meaning_digest
            or provenance_value.get("meaning_evidence_graph_digest")
            != evidence_graph_digest
            or provenance_value.get("meaning_evidence_graph_identity")
            != evidence_graph_identity
            or provenance_value.get("ordered_warning_record_sha256")
            != list(ordered_warning_record_sha256)
            or provenance_value.get("ordered_public_terminal_result_sha256")
            != list(ordered_public_terminal_result_sha256)
            or state.receipt.get("meaning_evidence_graph_digest")
            != evidence_graph_digest
            or state.receipt.get("meaning_evidence_graph_identity")
            != evidence_graph_identity
        ):
            raise TypeError("The live report transaction provenance is detached.")
        return state

    return issue, consume


(
    _issue_live_report_transaction,
    _consume_live_report_transaction,
) = _build_live_report_transaction_boundary()
del _build_live_report_transaction_boundary


def _write_report_from_live_evidence_transaction(
    store: PrivateArtifactStore,
    evidence: SealedResultEvidenceSet,
    /,
    *,
    input_declaration: str = "PRIVATE_LOCAL_INPUT",
    baseline_assessment: VerifiedBaselineAssessment | None = None,
    baseline_reproduction: VerifiedBaselineReproduction | None = None,
    development_null_science_receipt: (SealedDevelopmentNullScienceReceipt | None) = None,
    scenario_authority: ScenarioAuthority | None = None,
    resolved_synthetic_case: ResolvedSyntheticCase | None = None,
    authenticated_meaning_evidence_extension: (
        AuthenticatedMeaningEvidenceExtension | None
    ) = None,
    _sealed_scientific_evidence: SealedScientificEvidence | None = None,
) -> _LiveReportTransactionResult:
    """Write the current report from exact live result evidence."""

    _verify_store_owns_evidence(store, evidence)
    if input_declaration not in {"DECLARED_SYNTHETIC", "PRIVATE_LOCAL_INPUT"}:
        raise _report_contract_error()
    if (scenario_authority is None) != (resolved_synthetic_case is None):
        raise _report_contract_error()
    if development_null_science_receipt is not None and scenario_authority is not None:
        raise _report_contract_error()
    if baseline_assessment is None:
        if baseline_reproduction is not None:
            raise TypeError(
                "A baseline reproduction cannot be supplied without its exact assessment."
            )
        baseline_outcome = derive_verified_baseline_outcome(evidence, None)
        baseline_assessment = baseline_outcome.assessment
        baseline_reproduction = baseline_outcome.reproduction
    baseline_assessment_projection, baseline_reproduction_projection = verified_baseline_records(
        evidence,
        baseline_assessment,
        baseline_reproduction,
    )
    disposition = classify_candidate_execution(evidence)
    development_null: Mapping[str, Any] | None = None
    development_null_science_receipt_digest: str | None = None
    development_null_science_projection: Mapping[str, Any] | None = None
    if development_null_science_receipt is None:
        if _sealed_scientific_evidence is None:
            captured_scientific_run = capture_scientific_run(
                evidence,
                scenario_authority=scenario_authority,
                resolved_synthetic_case=resolved_synthetic_case,
            )
            sealed_scientific_evidence = seal_scientific_evidence(captured_scientific_run)
        else:
            sealed_scientific_evidence = _sealed_scientific_evidence
            sealed_state = _read_sealed_scientific_evidence(sealed_scientific_evidence)
            captured_scientific_run = sealed_state.capture
            captured_state = _read_captured_scientific_run(captured_scientific_run)
            if captured_state.sealed_result_evidence_set is not evidence:
                raise TypeError("The supplied sealed science belongs to different result evidence.")
        projection = project_scientific_evidence(sealed_scientific_evidence)
    else:
        from ebm_audit.synthetic.development_null import (
            _read_development_null_scientific_evidence,
            project_development_null_science_receipt,
        )

        sealed_scientific_evidence = _read_development_null_scientific_evidence(
            development_null_science_receipt,
            evidence=evidence,
        )
        if (
            _sealed_scientific_evidence is not None
            and _sealed_scientific_evidence is not sealed_scientific_evidence
        ):
            raise TypeError("The supplied sealed science disagrees with the development receipt.")
        sealed_state = _read_sealed_scientific_evidence(sealed_scientific_evidence)
        captured_scientific_run = sealed_state.capture
        development_null_science_projection = project_development_null_science_receipt(
            development_null_science_receipt,
            evidence=evidence,
        )
        projection = _require_mapping(
            development_null_science_projection.get("scientific_evidence")
        )
        development_null = _require_mapping(
            development_null_science_projection.get("development_null")
        )
        development_null_science_receipt_digest = _require_string(
            development_null_science_projection.get("receipt_digest")
        )
    sealed_input_declaration = _sealed_input_declaration(evidence, projection)
    scientific_evidence_digest = _require_prefixed_sha256(
        projection.get("scientific_evidence_digest")
    )
    if authenticated_meaning_evidence_extension is None and (
        scenario_authority is not None or resolved_synthetic_case is not None
    ):
        raise _report_contract_error()
    if authenticated_meaning_evidence_extension is None:
        authenticated_meaning_evidence_extension = issue_default_meaning_evidence_extension(
            evidence_graph_digest=scientific_evidence_digest.removeprefix("sha256:"),
            operation_plan_sha256=_require_string(projection.get("plan_digest")),
        )
    (
        report_claim_records,
        report_claim_projection_sha256,
        meaning_evidence_records,
        meaning_evidence_bundle_sha256,
        meaning_evidence_graph_digest,
        meaning_evidence_graph_identity,
        ordered_warning_record_sha256,
        ordered_public_terminal_result_sha256,
        _extension_science_digest,
    ) = _report_extension_components(
        authenticated_meaning_evidence_extension,
        scientific_evidence_digest=scientific_evidence_digest,
        captured_scientific_run=captured_scientific_run,
        sealed_scientific_evidence=sealed_scientific_evidence,
    )
    meaning_evidence_csv_bytes = _meaning_evidence_csv_bytes(meaning_evidence_records)
    meaning_evidence_csv_sha256 = exact_file_sha256(meaning_evidence_csv_bytes)
    report_provenance_csv_bytes = _report_provenance_csv_bytes(
        {
            "ordered_warning_record_sha256": list(ordered_warning_record_sha256),
            "ordered_public_terminal_result_sha256": list(
                ordered_public_terminal_result_sha256
            ),
        }
    )
    report_provenance_csv_sha256 = exact_file_sha256(report_provenance_csv_bytes)
    private_stage_records = _read_private_stage_comparison_evidence(sealed_scientific_evidence)
    private_stage_artifacts = _private_stage_artifact_payloads(private_stage_records)
    assert_no_direct_identifier_fields(projection)
    execution = project_candidate_execution_disposition(disposition)
    capability_evidence, sealed_output_states = _sealed_requested_output_evidence(evidence)
    if development_null is not None and (
        development_null["plan_digest"] != projection["plan_digest"]
        or development_null["terminal_index_digest"] != projection["terminal_index_digest"]
        or development_null["candidate_count"] != execution["requested_candidate_count"]
        or development_null["terminal_record_count"] != execution["terminal_record_count"]
        or development_null["success_count"] != execution["success_count"]
        or development_null["non_success_terminal_count"] != execution["non_success_terminal_count"]
    ):
        raise _report_contract_error()
    model = _report_model(
        projection,
        input_declaration=sealed_input_declaration,
        candidate_execution=execution,
        baseline_assessment_record=baseline_assessment_projection,
        baseline_reproduction_record=baseline_reproduction_projection,
        private_participant_stage_evidence_count=len(private_stage_records),
        capability_evidence=capability_evidence,
        sealed_output_states=sealed_output_states,
        report_claim_records=report_claim_records,
        report_claim_projection_sha256=report_claim_projection_sha256,
        meaning_evidence_records=meaning_evidence_records,
        meaning_evidence_bundle_sha256=meaning_evidence_bundle_sha256,
        meaning_evidence_graph_digest=meaning_evidence_graph_digest,
        meaning_evidence_graph_identity=meaning_evidence_graph_identity,
        meaning_evidence_csv_sha256=meaning_evidence_csv_sha256,
        ordered_warning_record_sha256=ordered_warning_record_sha256,
        ordered_public_terminal_result_sha256=(
            ordered_public_terminal_result_sha256
        ),
        report_provenance_csv_sha256=report_provenance_csv_sha256,
        development_null=development_null,
        development_null_science_receipt_digest=(development_null_science_receipt_digest),
    )
    _validate_private_stage_linkage(
        private_stage_records,
        cast(Sequence[object], model["participant_stage_comparisons"]),
    )
    report_bytes = canonical_json_bytes(model)
    parsed = strict_json_loads(report_bytes)
    if parsed != model:
        raise _report_contract_error()
    if _report_provenance_csv_bytes(
        _require_mapping(model.get("provenance"))
    ) != report_provenance_csv_bytes:
        raise _report_contract_error()
    from .objective_orders import (
        objective_choice_html,
        objective_choice_summary,
        objective_order_projection,
    )

    live_run = _sealed_result_evidence_run(evidence)
    native_orders = [
        objective_order_projection(
            strict_json_loads(_read_persisted_result(persisted).canonical_bytes),
            candidate,
            model["provenance"]["plan_digest"],
            scientific_candidate["event_semantics"],
        )
        for persisted, candidate, scientific_candidate in zip(
            live_run.persisted_results, model["candidate_records"],
            cast(Sequence[dict[str, Any]], projection["candidate_records"]), strict=True
        )
    ]
    native_objective_html = objective_choice_html(objective_choice_summary(model, native_orders))
    report_html_bytes = _html_bytes(model, native_objective_html=native_objective_html)
    _validate_claim_directive_output(model, report_html_bytes)
    report_model_artifact_binding = _issue_report_model_artifact_binding(
        model,
        report_bytes,
        report_html_bytes,
    )
    baseline_artifacts = {
        BASELINE_ASSESSMENT_ARTIFACT_PATH: canonical_json_bytes(baseline_assessment_projection),
    }
    if baseline_reproduction_projection is not None:
        baseline_artifacts[BASELINE_REPRODUCTION_ARTIFACT_PATH] = canonical_json_bytes(
            baseline_reproduction_projection
        )
    artifacts: dict[str, bytes] = {
        **_science_artifact_payloads(
            projection,
            development_null_science_projection=development_null_science_projection,
        ),
        **baseline_artifacts,
        _REPORT_ARTIFACT_PATHS[1]: report_bytes,
        _REPORT_ARTIFACT_PATHS[2]: _csv_bytes(
            cast(Sequence[Mapping[str, Any]], model["candidate_records"])
        ),
        _REPORT_ARTIFACT_PATHS[3]: meaning_evidence_csv_bytes,
        _REPORT_ARTIFACT_PATHS[4]: report_provenance_csv_bytes,
        _REPORT_ARTIFACT_PATHS[5]: report_html_bytes,
    }
    private_receipts = _write_exact_artifacts(
        store,
        private_stage_artifacts,
        tuple(private_stage_artifacts),
    )
    receipts = _write_exact_artifacts(
        store,
        artifacts,
        _report_artifact_paths(
            development_null=development_null_science_projection is not None,
            baseline_reproduction=baseline_reproduction_projection is not None,
        ),
    )
    gate = cast(Mapping[str, Any], model["science_completion_gate"])
    provenance = cast(Mapping[str, Any], model["provenance"])
    sampling = cast(Mapping[str, Any], model["sampling_evidence"])
    analyst = cast(Mapping[str, Any], model["analyst_decision_evidence"])
    analyst_accounting = cast(Mapping[str, Any], analyst["accounting"])
    influence = cast(Mapping[str, Any], model["participant_influence"])
    meaning_rows = cast(Sequence[Mapping[str, Any]], model["meaning_evidence"])
    meaning_state_counts = {
        state: sum(row["state"] == state for row in meaning_rows)
        for state in (
            "AVAILABLE",
            "UNAVAILABLE",
            "NOT_APPLICABLE",
            "INVALID",
            "FAILED",
        )
    }
    section_by_id = {
        cast(str, row["section_id"]): row
        for row in cast(Sequence[Mapping[str, Any]], model["sections"])
    }
    receipt: dict[str, Any] = {
        "report_receipt_schema_version": "ebm-audit-report-receipt/11.0",
        "report_status": CURRENT_REPORT_STATUS,
        "baseline_assessment_status": baseline_assessment_projection["status"],
        "baseline_validated_language_eligibility": baseline_assessment_projection[
            "validated_language_eligibility"
        ],
        "baseline_reproduction_emitted": baseline_reproduction_projection is not None,
        "science_completion_gate_status": gate["status"],
        "science_completion_reason_codes": list(cast(Sequence[str], gate["reason_codes"])),
        "plan_digest": provenance["plan_digest"],
        "terminal_index_digest": provenance["terminal_index_digest"],
        "scientific_evidence_digest": provenance["scientific_evidence_digest"],
        "report_claim_projection_sha256": provenance[
            "report_claim_projection_sha256"
        ],
        "meaning_evidence_bundle_sha256": provenance[
            "meaning_evidence_bundle_sha256"
        ],
        "meaning_evidence_graph_digest": provenance[
            "meaning_evidence_graph_digest"
        ],
        "meaning_evidence_graph_identity": copy.deepcopy(
            provenance["meaning_evidence_graph_identity"]
        ),
        "meaning_evidence_count": len(meaning_rows),
        "meaning_evidence_state_counts": meaning_state_counts,
        "meaning_evidence_csv_sha256": meaning_evidence_csv_sha256,
        "report_provenance_csv_sha256": report_provenance_csv_sha256,
        "sampling_attempt_count": sampling["attempt_count"],
        "sampling_numeric_record_count": sampling["unique_numeric_record_count"],
        "sampling_family_count": sampling["family_count"],
        "analyst_decision_attempt_count": analyst_accounting["planned_origin_count"],
        "analyst_decision_numeric_record_count": analyst_accounting[
            "unique_applicable_numeric_pair_count"
        ],
        "analyst_decision_aggregate_count": len(cast(Sequence[object], analyst["aggregates"])),
        "participant_influence_planned_origin_count": influence["planned_origin_count"],
        "participant_influence_attempt_count": influence["attempt_count"],
        "participant_influence_record_count": influence["influence_record_count"],
        "participant_influence_contribution_counts": dict(
            cast(Mapping[str, int], influence["contribution_counts"])
        ),
        "participant_influence_status": section_by_id["participant-influence"]["status"],
        "participant_stage_status": section_by_id["participant-stage"]["status"],
        "private_participant_stage_evidence_count": len(private_receipts),
        "candidate_execution": dict(execution),
        "artifact_count": len(receipts),
        "artifacts": list(receipts),
        "manifest_emitted": False,
    }
    if development_null is not None:
        receipt["development_null"] = dict(development_null)
        receipt["development_null_science_receipt_digest"] = development_null_science_receipt_digest
    authenticated_owner = _issue_live_report_transaction(
        receipt,
        report_model_artifact_binding,
        authenticated_meaning_evidence_extension,
        captured_scientific_run,
        sealed_scientific_evidence,
    )
    return _LiveReportTransactionResult(
        receipt=receipt,
        report_model_artifact_binding=report_model_artifact_binding,
        authenticated_owner=authenticated_owner,
    )


def write_report_from_live_evidence(
    store: PrivateArtifactStore,
    evidence: SealedResultEvidenceSet,
    /,
    *,
    input_declaration: str = "PRIVATE_LOCAL_INPUT",
    baseline_assessment: VerifiedBaselineAssessment | None = None,
    baseline_reproduction: VerifiedBaselineReproduction | None = None,
    development_null_science_receipt: (SealedDevelopmentNullScienceReceipt | None) = None,
    scenario_authority: ScenarioAuthority | None = None,
    resolved_synthetic_case: ResolvedSyntheticCase | None = None,
) -> Mapping[str, Any]:
    """Write the current report while preserving the established public receipt."""

    return _write_report_from_live_evidence_transaction(
        store,
        evidence,
        input_declaration=input_declaration,
        baseline_assessment=baseline_assessment,
        baseline_reproduction=baseline_reproduction,
        development_null_science_receipt=development_null_science_receipt,
        scenario_authority=scenario_authority,
        resolved_synthetic_case=resolved_synthetic_case,
    ).receipt


__all__ = [
    "CURRENT_REPORT_STATUS",
    "REPORT_SCHEMA_VERSION",
    "REPORT_V1_UNAVAILABLE_REASON",
    "ReportUnavailableError",
    "render_report_from_run_dir",
    "write_report_from_live_evidence",
]
