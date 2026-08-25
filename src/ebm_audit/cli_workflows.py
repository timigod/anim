"""Privacy-safe local CLI workflows.

Pre-execution commands deliberately stop before scientific worker ``validate``
or ``fit`` calls. The run workflow composes the same configuration, exact-file,
authenticated-Describe, dataset-preparation, Plan/3, production-execution, and
live-evidence reporting authorities instead of creating a CLI-specific path.
"""

from __future__ import annotations

import copy
import json
import os
import stat
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

import ebm_audit.reporting.render as render
from ebm_audit import __version__
from ebm_audit.adapters import (
    AuthenticatedWorkerDescription,
    WorkerCommand,
    WorkerConfig,
    WorkerInvoker,
    describe_worker,
)
from ebm_audit.artifacts import (
    PrivateArtifactStore,
    StagedOutputTransaction,
    ensure_private_directory,
    write_private_new,
)
from ebm_audit.artifacts.transaction import _issue_terminal_run_status_validator
from ebm_audit.baseline.workflow import (
    BASELINE_ASSESSMENT_ARTIFACT_PATH,
    BASELINE_REPRODUCTION_ARTIFACT_PATH,
    derive_verified_baseline_outcome,
)
from ebm_audit.config import (
    PlanEligibleAuditConfig,
    ResolvedAuditConfig,
    RunEligibleAuditConfig,
    VerifiedAuditConfigFiles,
    authorize_audit_config_plan,
    authorize_audit_config_run,
    authorize_plan_candidates,
    load_audit_config,
    parse_audit_config,
    verify_audit_config_files,
)
from ebm_audit.data import prepare_audit_dataset
from ebm_audit.errors import AuditError, ExitCode, InvalidInputError, UnexpectedCoreError
from ebm_audit.evaluator.meaning_evidence_bundle import (
    AuthenticatedMeaningEvidenceExtension,
    issue_default_meaning_evidence_extension,
    validate_meaning_extension_science_join,
)
from ebm_audit.evaluator.operation_matrix import _authenticate_existing_plan_operation_matrix
from ebm_audit.metrics import CONVERGENCE_RULE
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    requested_outputs_digest,
    settings_digest,
    settings_schema_digest,
    structured_sha256,
    validate_relative_posix_path,
)
from ebm_audit.reporting._report_model_artifact_binding import (
    AuthenticatedReportModelArtifactBinding,
    _validated_binding_projection,
)
from ebm_audit.results import (
    open_result_persistence_journal,
    persisted_candidate_terminals,
    seal_result_evidence_set,
)
from ebm_audit.runner import (
    execute_preparation_transaction,
    execute_preparation_transaction_no_retry,
)
from ebm_audit.schema import (
    RESOURCE_FILENAMES,
    SchemaValidationError,
    load_resource_json,
    load_schema,
    validate_instance,
)
from ebm_audit.science import (
    CapturedScientificRun,
    SealedScientificEvidence,
    capture_scientific_run,
    seal_scientific_evidence,
)
from ebm_audit.science.capture import (
    _read_captured_scientific_run,
    _read_sealed_scientific_evidence,
    _scientific_evidence_read_scope,
)
from ebm_audit.universe import (
    PlanningAuthority,
    PreparationTransaction,
    compile_analysis_plan,
    issue_planning_authority,
    issue_public_intent_manifest,
)
from ebm_audit.universe.preparation import (
    PreparedExecutionAuthorization,
    _capture_preparation_transaction_state_identity,
)

if TYPE_CHECKING:
    from ebm_audit.synthetic.audit_input import SealedPublicSyntheticAuditInput
    from ebm_audit.synthetic.development_null import (
        SealedDevelopmentNullScienceReceipt,
    )
    from ebm_audit.universe.preparation import _ConformanceDemoProvenance

_STARTER_NAMES = {
    "synthetic": "synthetic.audit.yaml",
    "idris-2025-public": "idris-2025-public.structural.audit.yaml",
}
_DOCTOR_PROBE_NAME = ".ebm-audit-doctor-write-probe"
_SCALAR_PLAN_COUNT_FIELDS = (
    "candidate_count",
    "origin_count",
    "additional_origin_count",
    "planned_candidate_count",
    "plan_ineligible_candidate_count",
    "seedless_chain_slot_count",
    "planned_fit_ceiling",
)


@dataclass(frozen=True, slots=True)
class _ExecutionAuditTransactionResult:
    """Authenticated execution evidence before any report work is allowed."""

    planning_authority: PlanningAuthority
    preparation_transaction: PreparationTransaction
    prepared_authorizations: tuple[PreparedExecutionAuthorization, ...]
    captured_scientific_run: CapturedScientificRun
    sealed_scientific_evidence: SealedScientificEvidence


@dataclass(frozen=True, slots=True)
class _OrdinaryAuditTransactionResult:
    public_result: tuple[Mapping[str, Any], ExitCode]
    planning_authority: PlanningAuthority
    preparation_transaction: PreparationTransaction
    captured_scientific_run: CapturedScientificRun
    sealed_scientific_evidence: SealedScientificEvidence
    meaning_evidence_extension: AuthenticatedMeaningEvidenceExtension
    report_model_artifact_binding: AuthenticatedReportModelArtifactBinding


type _ValidatedOrdinaryPlanCallback = Callable[
    [
        PlanningAuthority,
        PreparationTransaction,
        VerifiedAuditConfigFiles,
        tuple[PreparedExecutionAuthorization, ...],
    ],
    None,
]

type _ValidatedOrdinaryAuditCallback = Callable[
    [
        PlanningAuthority,
        PreparationTransaction,
        tuple[PreparedExecutionAuthorization, ...],
        CapturedScientificRun,
        SealedScientificEvidence,
    ],
    AuthenticatedMeaningEvidenceExtension,
]

type _ValidatedOrdinaryReportBindingCallback = Callable[
    [AuthenticatedReportModelArtifactBinding],
    None,
]


def _complete_ordinary_audit_transaction(
    owner: object,
    public_result: tuple[Mapping[str, Any], ExitCode],
    planning_authority: PlanningAuthority,
    preparation_transaction: PreparationTransaction,
    captured_scientific_run: CapturedScientificRun,
    sealed_scientific_evidence: SealedScientificEvidence,
    meaning_evidence_extension: AuthenticatedMeaningEvidenceExtension,
    /,
) -> _OrdinaryAuditTransactionResult:
    if type(planning_authority) is not PlanningAuthority:
        raise TypeError("A genuine planning authority is required.")
    try:
        planning_state = planning_authority._state()
    except TypeError:
        raise TypeError("A genuine planning authority is required.") from None
    preparation_state = _capture_preparation_transaction_state_identity(preparation_transaction)
    publication = planning_state.preparation_publication
    publication_token = planning_state.preparation_publication_token
    if (
        publication is None
        or publication_token is None
        or preparation_state.publication_token is not publication_token
        or publication.transaction is not preparation_transaction
    ):
        raise TypeError("The ordinary planning and preparation owner chain is detached.")
    state = render._consume_live_report_transaction(owner)
    if (
        state.captured_scientific_run is not captured_scientific_run
        or state.sealed_scientific_evidence is not sealed_scientific_evidence
        or type(meaning_evidence_extension) is not AuthenticatedMeaningEvidenceExtension
        or state.meaning_evidence_extension is not meaning_evidence_extension
    ):
        raise TypeError("The ordinary transaction evidence owner chain is detached.")
    binding = state.report_model_artifact_binding
    binding_projection = _validated_binding_projection(binding)
    captured_state = _read_captured_scientific_run(captured_scientific_run)
    sealed_state = _read_sealed_scientific_evidence(sealed_scientific_evidence)
    receipt = state.receipt
    artifacts = receipt.get("artifacts")
    if type(artifacts) is not list:
        raise UnexpectedCoreError(
            "REPORT.TRANSACTION_BINDING",
            "The ordinary report transaction failed exact artifact binding.",
        )
    for artifact_path, projection_field in (
        ("report/report.json", "report_artifact_sha256"),
        ("report/report.html", "report_html_artifact_sha256"),
    ):
        report_rows = [
            row for row in artifacts if type(row) is dict and row.get("path") == artifact_path
        ]
        if (
            len(report_rows) != 1
            or type(report_rows[0].get("sha256")) is not str
            or report_rows[0]["sha256"] != binding_projection[projection_field]
        ):
            raise UnexpectedCoreError(
                "REPORT.TRANSACTION_BINDING",
                "The ordinary report transaction failed exact artifact binding.",
            )
    if (
        captured_state.preparation_transaction is not preparation_transaction
        or sealed_state.capture is not captured_scientific_run
        or receipt.get("plan_digest") != captured_state.plan_digest
        or receipt.get("scientific_evidence_digest") != sealed_state.evidence_digest
    ):
        raise TypeError("The ordinary transaction evidence owner chain is detached.")
    return _OrdinaryAuditTransactionResult(
        public_result=public_result,
        planning_authority=planning_authority,
        preparation_transaction=preparation_transaction,
        captured_scientific_run=captured_scientific_run,
        sealed_scientific_evidence=sealed_scientific_evidence,
        meaning_evidence_extension=meaning_evidence_extension,
        report_model_artifact_binding=binding,
    )


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _starter_template_bytes(template_kind: str) -> bytes:
    starter_name = _STARTER_NAMES.get(template_kind)
    if starter_name is None:
        raise InvalidInputError(
            "SPEC.STARTER_TEMPLATE_UNKNOWN",
            "The requested AuditConfig/0.3 starter is unavailable.",
        )
    source_candidate = Path(__file__).resolve().parents[2] / "examples" / "config" / starter_name
    try:
        if source_candidate.is_file():
            return source_candidate.read_bytes()
    except OSError:
        pass
    try:
        packaged = resources.files("ebm_audit").joinpath("examples", "config", starter_name)
        return packaged.read_bytes()
    except (FileNotFoundError, OSError, TypeError):
        raise InvalidInputError(
            "SPEC.STARTER_TEMPLATE_UNAVAILABLE",
            "The packaged AuditConfig/0.3 starter is unavailable.",
        ) from None


def _relative_config_path(value: str) -> str:
    try:
        return validate_relative_posix_path(value)
    except Exception:
        raise InvalidInputError(
            "SPEC.STARTER_RELATIVE_PATH",
            "Starter paths must be non-empty config-relative POSIX paths.",
        ) from None


def initialize_config(
    *,
    destination: Path,
    input_path: str,
    worker_config_path: str,
    run_root: str,
    template_kind: str = "synthetic",
) -> Mapping[str, Any]:
    """Create one deterministic, non-overwriting AuditConfig/0.3 starter."""

    template = parse_audit_config(_starter_template_bytes(template_kind))
    initialized = copy.deepcopy(template)
    initialized["input"]["path"] = _relative_config_path(input_path)
    initialized["worker"]["config_path"] = _relative_config_path(worker_config_path)
    initialized["output"]["root"] = _relative_config_path(run_root)
    content = _json_bytes(initialized)
    # Re-parse the exact emitted bytes so the on-disk starter, not merely its
    # source template, is proven to remain on the active v0.3 contract.
    parsed = parse_audit_config(content)
    if parsed["config_schema_version"] != "ebm-audit-config/0.3":
        raise InvalidInputError(
            "SPEC.STARTER_SCHEMA_VERSION",
            "The starter is not an AuditConfig/0.3 document.",
        )
    write_private_new(destination, content)
    return {
        "command_result_schema_version": "ebm-audit-cli-init-result/1.0",
        "status": "CREATED",
        "config_schema_version": "ebm-audit-config/0.3",
        "config_byte_digest": exact_file_sha256(content),
        "private_file_mode": "0600",
        "overwrite": False,
    }


@contextmanager
def authorized_description(
    resolved: ResolvedAuditConfig,
    *,
    timeout_seconds: float,
) -> Iterator[
    tuple[
        RunEligibleAuditConfig,
        VerifiedAuditConfigFiles,
        WorkerConfig,
        AuthenticatedWorkerDescription,
    ]
]:
    """Open the exact genuine pre-execution authority chain and close it."""

    verified = verify_audit_config_files(resolved)
    try:
        authorized = authorize_audit_config_run(verified)
        worker_config, description = _describe_authorized_worker(
            authorized,
            timeout_seconds=timeout_seconds,
        )
        yield authorized, verified, worker_config, description
    finally:
        verified.close()


@contextmanager
def plan_eligible_description(
    resolved: ResolvedAuditConfig,
    *,
    timeout_seconds: float,
) -> Iterator[
    tuple[
        PlanEligibleAuditConfig,
        VerifiedAuditConfigFiles,
        WorkerConfig,
        AuthenticatedWorkerDescription,
    ]
]:
    """Authenticate Describe and issue exact authority for dry planning only."""

    verified = verify_audit_config_files(resolved)
    try:
        worker_config, description = _describe_verified_worker(
            verified,
            timeout_seconds=timeout_seconds,
        )
        authorized = authorize_audit_config_plan(verified, description)
        yield authorized, verified, worker_config, description
    finally:
        verified.close()


def _describe_verified_worker(
    verified: VerifiedAuditConfigFiles,
    *,
    timeout_seconds: float,
) -> tuple[WorkerConfig, AuthenticatedWorkerDescription]:
    """Consume one exact verified worker config and authenticate Describe."""

    worker_config = verified.consume_worker_config(
        lambda handle: WorkerConfig.from_yaml_bytes(handle.read())
    )
    description = WorkerInvoker(
        worker_config.worker,
        timeout_seconds=timeout_seconds,
        expected_identity=worker_config.expected_identity,
    ).describe_authenticated()
    return worker_config, description


def _describe_authorized_worker(
    authorized: RunEligibleAuditConfig,
    *,
    timeout_seconds: float,
) -> tuple[WorkerConfig, AuthenticatedWorkerDescription]:
    """Consume one exact verified worker config and authenticate Describe."""

    worker_config = authorized.consume_worker_config(
        lambda handle: WorkerConfig.from_yaml_bytes(handle.read())
    )
    description = WorkerInvoker(
        worker_config.worker,
        timeout_seconds=timeout_seconds,
        expected_identity=worker_config.expected_identity,
    ).describe_authenticated()
    return worker_config, description


def _input_declaration(
    authorized: PlanEligibleAuditConfig | RunEligibleAuditConfig,
) -> str:
    """Return one bounded label, never a caller's free text."""

    private = authorized.private_config
    template = cast(Mapping[str, Any], private["template"])
    input_config = cast(Mapping[str, Any], private["input"])
    variant = cast(Mapping[str, Any], input_config["variant"])
    if (
        template["kind"] == "synthetic"
        and template["contains_real_rows"] is False
        and variant["is_synthetic"] is True
    ):
        return "DECLARED_SYNTHETIC"
    return "PRIVATE_LOCAL_INPUT"


def _public_confirmation_issues(
    authorized: PlanEligibleAuditConfig,
) -> list[dict[str, object]]:
    """Project confirmation blockers to codes and declared public event IDs."""

    private = authorized.private_config
    events = cast(
        Sequence[Mapping[str, Any]],
        cast(Mapping[str, Any], private["column_roles"])["events"],
    )
    all_event_ids = sorted(
        (cast(str, row["event_id"]) for row in events), key=lambda value: value.encode("utf-8")
    )
    issue_event_ids = {
        "CONFIRMATION.TEMPLATE_LOCAL_MAPPING": all_event_ids,
        "CONFIRMATION.EVENT_DIRECTION": sorted(
            (
                cast(str, row["event_id"])
                for row in events
                if row["abnormal_direction"] == "REQUIRES_CONFIRMATION"
            ),
            key=lambda value: value.encode("utf-8"),
        ),
        "CONFIRMATION.EVENT_IDENTIFIER_RISK_REVIEW": sorted(
            (
                cast(str, row["event_id"])
                for row in events
                if row["identifier_risk_reviewed"] is not True
            ),
            key=lambda value: value.encode("utf-8"),
        ),
    }
    return [
        {
            "code": code,
            "event_ids": issue_event_ids.get(code, []),
        }
        for code in authorized.confirmation_issue_codes
    ]


def _public_plan_advisories(plan: Mapping[str, Any]) -> list[dict[str, object]]:
    """Project bounded convergence advisories without changing Plan/3."""

    required_count = CONVERGENCE_RULE.assessable_min_independent_chains
    advisories: list[dict[str, object]] = []
    for candidate in cast(Sequence[Mapping[str, Any]], plan["candidates"]):
        analysis_spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        mcmc = analysis_spec["mcmc"]
        if not isinstance(mcmc, Mapping):
            continue
        observed_count = cast(int, mcmc["chain_count"])
        if observed_count < required_count:
            advisories.append(
                {
                    "advisory_schema_version": "ebm-audit-plan-advisory/1.0",
                    "code": "PLAN.INSUFFICIENT_INDEPENDENT_CHAINS",
                    "candidate_ordinal": candidate["candidate_ordinal"],
                    "observed_count": observed_count,
                    "required_count": required_count,
                }
            )
    return advisories


def validate_preexecution(
    config_path: Path,
    *,
    timeout_seconds: float,
) -> Mapping[str, Any]:
    """Verify config, exact files, plan eligibility, and authenticated Describe."""

    resolved = load_audit_config(config_path)
    with plan_eligible_description(resolved, timeout_seconds=timeout_seconds) as (
        authorized,
        verified,
        _worker_config,
        _description,
    ):
        return {
            "command_result_schema_version": "ebm-audit-cli-validate-result/1.0",
            "status": "VALID",
            "offline": True,
            "input_declaration": _input_declaration(authorized),
            "scientific_worker_commands_run": 0,
            "checked_file_count": verified.verified_file_role_count,
            "confirmation_issue_count": len(verified.confirmation_issue_codes),
            "confirmation_issues": _public_confirmation_issues(authorized),
            "capability_mismatch_count": 0,
            "warning_count": 0,
            "resolved_config_digest": verified.resolved_public_digest,
            "verification_digest": verified.verification_id,
            "source_admission_digest": verified.source_admission_id,
            "worker_identity_digest": verified.worker_identity_digest,
            # Authenticated Describe evidence carries a fresh request/response
            # identity. It is verified above but intentionally omitted from
            # this repeatable summary; emitting it would make identical local
            # inputs produce different CLI bytes.
            "authenticated_describe_count": 1,
        }


def plan_preexecution(
    config_path: Path,
    *,
    profile_id: str,
    timeout_seconds: float,
) -> Mapping[str, Any]:
    """Compile Plan/3 through its authority-owned rebuild without execution."""

    resolved = load_audit_config(config_path)
    with plan_eligible_description(resolved, timeout_seconds=timeout_seconds) as (
        authorized,
        _verified,
        _worker_config,
        description,
    ):
        public_intent = issue_public_intent_manifest(authorized, (description,))
        prepared = prepare_audit_dataset(authorized)
        authority = issue_planning_authority(
            authorized,
            prepared,
            (description,),
            public_intent_manifest=public_intent,
            profile_id=profile_id,
        )
        plan = compile_analysis_plan(authority)
        counts = cast(Mapping[str, Any], plan["counts"])
        budget = cast(Mapping[str, Any], plan["budget_decision"])
        candidates = cast(Sequence[Mapping[str, Any]], plan["candidates"])
        planning_reason_codes = sorted(
            {
                cast(str, reason["reason_code"])
                for candidate in candidates
                for reason in cast(Sequence[Mapping[str, Any]], candidate["planning_reasons"])
            }
        )
        advisories = _public_plan_advisories(plan)
        summary = prepared.summary
        return {
            "command_result_schema_version": "ebm-audit-cli-plan-result/1.1",
            "status": "PLANNED",
            "offline": True,
            "input_declaration": _input_declaration(authorized),
            "scientific_worker_commands_run": 0,
            "confirmation_issue_count": len(authorized.confirmation_issue_codes),
            "confirmation_issues": _public_confirmation_issues(authorized),
            "plan_schema_version": plan["plan_schema_version"],
            "plan_digest": plan["plan_digest"],
            "public_intent_manifest_digest": public_intent.manifest_digest,
            "prepared_dataset_digest": prepared.prepared_dataset_id,
            "dataset_summary_digest": prepared.summary_digest,
            "dataset_counts": {
                "row_count": summary.row_count,
                "participant_count": summary.participant_count,
                "event_count": summary.event_count,
                "group_spec_count": summary.group_spec_count,
                "covariate_count": summary.covariate_count,
                "metadata_count": summary.metadata_count,
            },
            "plan_counts": {field: counts[field] for field in _SCALAR_PLAN_COUNT_FIELDS},
            "planning_reason_count": len(planning_reason_codes),
            "planning_reason_codes": planning_reason_codes,
            "advisory_count": len(advisories),
            "advisories": advisories,
            "budget_summary": {
                "decision": budget["decision"],
                "reason_count": len(cast(list[object], budget["reason_codes"])),
                "ordinary_candidate_limit": budget["ordinary_candidate_limit"],
                "fit_limit": budget["fit_limit"],
                "influence_removal_limit": budget["influence_removal_limit"],
                "max_parallel_workers": budget["max_parallel_workers"],
                "planned_ordinary_candidate_count": budget["planned_ordinary_candidate_count"],
                "planned_fit_ceiling": budget["planned_fit_ceiling"],
                "maximum_scoped_exact_influence_count": budget[
                    "maximum_scoped_exact_influence_count"
                ],
            },
        }


def _jsonl_bytes(rows: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(dict(row)) + b"\n" for row in rows)


def _terminal_ledgers(
    terminals: Sequence[Mapping[str, Any]],
    *,
    science_reason_codes: Sequence[str],
) -> tuple[bytes, bytes]:
    failures: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = [
        {
            "code": reason,
            "scope": "SCIENCE_COMPLETION_GATE",
        }
        for reason in science_reason_codes
    ]
    for terminal in terminals:
        status = cast(str, terminal["final_status"])
        if status == "SUCCESS":
            continue
        row = {
            "candidate_ordinal": cast(int, terminal["candidate_ordinal"]),
            "code": f"CANDIDATE.{status}",
            "final_status": status,
        }
        if status == "CONVERGENCE_WARN":
            warnings.append(row)
        else:
            failures.append(row)
    return _jsonl_bytes(failures), _jsonl_bytes(warnings)


def _run_completion_outcome(
    candidate_execution: Mapping[str, Any],
    *,
    report_status: object,
    science_completion_gate_status: object,
) -> tuple[str, ExitCode]:
    """Keep candidate execution and whole-audit completion as separate facts."""

    state = candidate_execution.get("state")
    raw_exit_code = candidate_execution.get("exit_code")
    try:
        candidate_exit_code = ExitCode(cast(int, raw_exit_code))
    except (TypeError, ValueError):
        raise UnexpectedCoreError(
            "RUN.CANDIDATE_EXECUTION_DISPOSITION",
            "The candidate-execution disposition is invalid.",
        ) from None

    if state == "COMPLETE" and candidate_exit_code is ExitCode.SUCCESS:
        if report_status == "INCOMPLETE" and science_completion_gate_status == "BLOCKED":
            return "PARTIAL", ExitCode.PARTIAL
    elif state == "PARTIAL" and candidate_exit_code is ExitCode.PARTIAL:
        return "PARTIAL", ExitCode.PARTIAL
    elif state == "PRIVACY_FAILED" and candidate_exit_code is ExitCode.PRIVACY_FAILED:
        return "PRIVACY_FAILED", ExitCode.PRIVACY_FAILED
    elif state == "FAILED" and candidate_exit_code in {
        ExitCode.INVALID_INPUT_OR_SPECIFICATION,
        ExitCode.WORKER_OR_CAPABILITY_UNAVAILABLE,
        ExitCode.BACKEND_OR_PROTOCOL_FAILURE,
    }:
        return "FAILED", candidate_exit_code

    raise UnexpectedCoreError(
        "RUN.COMPLETION_DISPOSITION",
        "The whole-audit completion disposition is invalid.",
    )


def _terminal_run_status_bytes(
    value: Mapping[str, Any],
    *,
    candidate_execution: Mapping[str, Any],
    staging_run_root_id: str,
    participant_stage_status: str,
    development_null_science_receipt: (SealedDevelopmentNullScienceReceipt | None) = None,
) -> bytes:
    """Validate one exact privacy-safe terminal status before publication."""

    assert_no_direct_identifier_fields(value)
    development_null: Mapping[str, Any] | None = None
    development_null_science_receipt_digest: str | None = None
    if development_null_science_receipt is not None:
        from ebm_audit.synthetic.development_null import (
            project_development_null_science_receipt,
        )

        development_null_science_projection = project_development_null_science_receipt(
            development_null_science_receipt
        )
        development_null = cast(
            Mapping[str, Any],
            development_null_science_projection["development_null"],
        )
        development_null_science_receipt_digest = cast(
            str,
            development_null_science_projection["receipt_digest"],
        )
    try:
        validate_instance(value, "run-status.schema.json")
        status_counts = cast(Mapping[str, int], value["terminal_status_counts"])
        requested = cast(int, value["requested_candidate_count"])
        terminal = cast(int, value["terminal_record_count"])
        success = cast(int, value["success_count"])
        non_success = cast(int, value["non_success_terminal_count"])
        privacy = cast(int, value["privacy_failure_count"])
        influence_planned = cast(
            int,
            value["participant_influence_planned_origin_count"],
        )
        influence_attempts = cast(
            int,
            value["participant_influence_attempt_count"],
        )
        influence_records = cast(
            int,
            value["participant_influence_record_count"],
        )
        private_stage_count = cast(
            int,
            value["private_participant_stage_evidence_count"],
        )
        influence_counts = cast(
            Mapping[str, int],
            value["participant_influence_contribution_counts"],
        )
        interpretive_influence_count = influence_counts["INTERPRETIVE"]
        descriptive_influence_count = influence_counts["DESCRIPTIVE_ONLY"]
        publication = cast(Mapping[str, Any], value["publication"])
        publication_inventory = cast(
            Sequence[Mapping[str, Any]],
            publication["inventory"],
        )
        report_artifacts = cast(
            Sequence[Mapping[str, str]],
            value["report_artifacts"],
        )
        publication_paths = [cast(str, row["path"]) for row in publication_inventory]
        required_publication_paths = {
            "config.resolved.yaml",
            "data-summary.json",
            "failures.jsonl",
            "warnings.jsonl",
            "state/candidate-terminal-index.json",
            "evidence/scientific-evidence-projection.json",
            BASELINE_ASSESSMENT_ARTIFACT_PATH,
            "report/report.json",
            "report/universes.csv",
            "report/meaning-evidence.csv",
            "report/provenance.csv",
            "report/report.html",
            *(f"results/candidate-{ordinal:08d}.json" for ordinal in range(requested)),
            *(f"state/candidate-terminals/{ordinal:08d}.json" for ordinal in range(requested)),
            *(
                f"private/science/participant-stage-comparisons/{ordinal:08d}.json"
                for ordinal in range(private_stage_count)
            ),
        }
        if development_null is not None:
            required_publication_paths.add("evidence/development-null-science-receipt.json")
        baseline_reproduction_emitted = any(
            artifact["path"] == BASELINE_REPRODUCTION_ARTIFACT_PATH for artifact in report_artifacts
        )
        if baseline_reproduction_emitted:
            required_publication_paths.add(BASELINE_REPRODUCTION_ARTIFACT_PATH)
        optional_publication_paths = {
            *(f"cache/results/candidate-{ordinal:08d}.json" for ordinal in range(requested)),
        }
        inventory_by_path = {cast(str, row["path"]): row for row in publication_inventory}
        status_development_null = cast(
            Mapping[str, Any] | None,
            value.get("development_null"),
        )
        status_development_null_science_receipt_digest = cast(
            str | None,
            value.get("development_null_science_receipt_digest"),
        )
        expected_report_paths = [
            "evidence/scientific-evidence-projection.json",
            *(
                ["evidence/development-null-science-receipt.json"]
                if development_null is not None
                else []
            ),
            BASELINE_ASSESSMENT_ARTIFACT_PATH,
            *([BASELINE_REPRODUCTION_ARTIFACT_PATH] if baseline_reproduction_emitted else []),
                "report/report.json",
                "report/universes.csv",
                "report/meaning-evidence.csv",
                "report/provenance.csv",
                "report/report.html",
        ]
        expected_influence_status = (
            "NOT_ASSESSABLE"
            if influence_records == 0
            else ("AVAILABLE" if interpretive_influence_count == influence_attempts else "PARTIAL")
        )
        if (
            value["candidate_execution_status"] != candidate_execution["state"]
            or value["candidate_execution_exit_code"] != candidate_execution["exit_code"]
            or value["candidate_execution_primary_failure_class"]
            != candidate_execution["primary_failure_class"]
            or requested != candidate_execution["requested_candidate_count"]
            or terminal != candidate_execution["terminal_record_count"]
            or success != candidate_execution["success_count"]
            or non_success != candidate_execution["non_success_terminal_count"]
            or privacy != candidate_execution["privacy_failure_count"]
            or dict(status_counts) != candidate_execution["terminal_status_counts"]
            or requested != terminal
            or terminal != success + non_success
            or sum(status_counts.values()) != non_success
            or privacy != status_counts["PRIVACY_VIOLATION"]
            or influence_planned != influence_attempts
            or influence_records > influence_attempts
            or set(influence_counts)
            != {
                "INTERPRETIVE",
                "DESCRIPTIVE_ONLY",
                "METRIC_NOT_ASSESSABLE",
                "FAILED",
            }
            or any(type(count) is not int or count < 0 for count in influence_counts.values())
            or sum(influence_counts.values()) != influence_attempts
            or influence_records != interpretive_influence_count + descriptive_influence_count
            or publication["staging_run_root_id"] != staging_run_root_id
            or publication_paths != sorted(publication_paths, key=lambda path: path.encode("utf-8"))
            or len(set(publication_paths)) != len(publication_paths)
            or not required_publication_paths.issubset(publication_paths)
            or not (set(publication_paths) - required_publication_paths).issubset(
                optional_publication_paths
            )
            or publication["inventory_digest"]
            != structured_sha256(
                "ebm-audit/run-publication-inventory/1",
                list(publication_inventory),
            )
            or any(
                inventory_by_path.get(artifact["path"], {}).get("sha256") != artifact["sha256"]
                for artifact in report_artifacts
            )
            or value["participant_influence_status"] != expected_influence_status
            or value["participant_stage_status"] != participant_stage_status
            or value["report_artifact_count"] != len(report_artifacts)
            or [artifact["path"] for artifact in report_artifacts] != expected_report_paths
            or (
                development_null is None
                and (
                    status_development_null is not None
                    or status_development_null_science_receipt_digest is not None
                )
            )
            or (
                development_null is not None
                and (
                    status_development_null != development_null
                    or status_development_null_science_receipt_digest
                    != development_null_science_receipt_digest
                    or development_null.get("plan_digest") != value["plan_digest"]
                    or development_null.get("terminal_index_digest")
                    != value["terminal_index_digest"]
                    or development_null.get("prepared_dataset_digest")
                    != value["prepared_dataset_digest"]
                    or development_null.get("candidate_count") != requested
                    or development_null.get("terminal_record_count") != terminal
                    or development_null.get("success_count") != success
                    or development_null.get("non_success_terminal_count") != non_success
                    or development_null.get("calibration_state") != "DEVELOPMENT_UNCALIBRATED"
                    or development_null.get("null_relative_label")
                    != "NULL_CALIBRATION_NOT_VALIDATED"
                    or development_null.get("strong_null_relative_language_eligible") is not False
                    or development_null.get("held_out_false_positive_rate_eligible") is not False
                    or "NULL_CALIBRATION_NOT_VALIDATED"
                    not in value["science_completion_reason_codes"]
                )
            )
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, SchemaValidationError):
        raise UnexpectedCoreError(
            "RUN.TERMINAL_STATUS_CONTRACT",
            "The terminal run status is inconsistent with exact execution evidence.",
        ) from None
    return canonical_json_bytes(dict(value))


def _publication_receipt(
    store: PrivateArtifactStore,
    *,
    requested_candidate_count: int,
    private_participant_stage_evidence_count: int,
    baseline_reproduction_emitted: bool,
) -> dict[str, Any]:
    """Bind every staged, non-authentication artifact before run-status publication."""

    if (
        type(store) is not PrivateArtifactStore
        or type(requested_candidate_count) is not int
        or requested_candidate_count < 1
        or type(private_participant_stage_evidence_count) is not int
        or private_participant_stage_evidence_count < 0
        or type(baseline_reproduction_emitted) is not bool
    ):
        raise UnexpectedCoreError(
            "RUN.PUBLICATION_INVENTORY",
            "The staged run publication inventory is invalid.",
        )
    paths = {
        "config.resolved.yaml",
        "data-summary.json",
        "failures.jsonl",
        "warnings.jsonl",
        "state/candidate-terminal-index.json",
        "evidence/scientific-evidence-projection.json",
        BASELINE_ASSESSMENT_ARTIFACT_PATH,
        "report/report.json",
        "report/universes.csv",
        "report/meaning-evidence.csv",
        "report/provenance.csv",
        "report/report.html",
    }
    if baseline_reproduction_emitted:
        paths.add(BASELINE_REPRODUCTION_ARTIFACT_PATH)
    optional_cache_paths: list[str] = []
    for ordinal in range(requested_candidate_count):
        paths.add(f"results/candidate-{ordinal:08d}.json")
        paths.add(f"state/candidate-terminals/{ordinal:08d}.json")
        optional_cache_paths.append(f"cache/results/candidate-{ordinal:08d}.json")
    for ordinal in range(private_participant_stage_evidence_count):
        paths.add(f"private/science/participant-stage-comparisons/{ordinal:08d}.json")
    inventory: list[dict[str, Any]] = []
    for path in sorted((*paths, *optional_cache_paths), key=lambda value: value.encode("utf-8")):
        try:
            content = store.read_bytes(path)
        except InvalidInputError as error:
            if path in optional_cache_paths and error.code == "SPEC.OUTPUT_MISSING":
                continue
            raise UnexpectedCoreError(
                "RUN.PUBLICATION_INVENTORY",
                "The staged run publication inventory is incomplete.",
            ) from None
        inventory.append(
            {
                "path": path,
                "sha256": exact_file_sha256(content),
                "byte_length": len(content),
            }
        )
    receipt = {
        "schema_version": "ebm-audit-run-publication/1.0",
        "state": "STAGED_READY_FOR_PUBLICATION",
        "staging_run_root_id": store.run_root_id,
        "final_precondition": "ABSENT",
        "scope": "NON_AUTHENTICATION_ARTIFACTS_EXCLUDING_RUN_STATUS",
        "inventory": inventory,
        "inventory_digest": structured_sha256(
            "ebm-audit/run-publication-inventory/1",
            inventory,
        ),
    }
    return receipt


@contextmanager
def _conformance_worker_path(capability_profile: str = "full") -> Iterator[Path]:
    """Expose the canonical conformance worker from an install or checkout."""

    profiles = {
        "full": ("conformance_ebm", "worker.py", "model.py"),
        "partial": (
            "conformance_ebm_partial",
            "partial_worker.py",
            "partial_model.py",
        ),
    }
    try:
        directory_name, worker_name, model_name = profiles[capability_profile]
    except KeyError:
        raise InvalidInputError(
            "DEMO.CONFORMANCE_CAPABILITY_PROFILE",
            "The conformance capability profile is invalid.",
        ) from None
    with ExitStack() as stack:
        packaged_root: Path | None = None
        with suppress(FileNotFoundError, OSError, TypeError):
            packaged_root = stack.enter_context(
                resources.as_file(resources.files("ebm_audit").joinpath("workers", directory_name))
            )
        if packaged_root is not None:
            packaged_worker = packaged_root / worker_name
            if packaged_worker.is_file() and (packaged_root / model_name).is_file():
                yield packaged_worker
                return

    source_root = Path(__file__).resolve().parents[2] / "workers" / directory_name
    source_worker = source_root / worker_name
    if source_worker.is_file() and (source_root / model_name).is_file():
        yield source_worker
        return
    raise InvalidInputError(
        "DEMO.CONFORMANCE_WORKER_UNAVAILABLE",
        "The built-in conformance worker is unavailable.",
    )


def _conformance_demo_config(
    root: Path,
    *,
    worker_path: Path,
    capability_profile: str = "full",
) -> tuple[Path, Mapping[str, Any]]:
    """Materialize the exact D08-generated input behind an ordinary audit config."""

    from ebm_audit.synthetic.conformance import (
        build_conformance_provenance,
        generate_conformance_input,
    )

    event_ids = ("synthetic-event-a", "synthetic-event-b")
    generated = generate_conformance_input(
        participant_count=4,
        event_count=len(event_ids),
        event_ids=event_ids,
    )
    provenance = build_conformance_provenance(
        participant_count=4,
        event_count=len(event_ids),
        event_ids=event_ids,
    )
    data_root = root / "data"
    worker_root = root / "worker"
    ensure_private_directory(data_root)
    ensure_private_directory(worker_root)
    input_rows = ["participant_code,group,event_01,event_02"]
    values = generated.arrays["train_values"]
    groups = generated.arrays["train_group_codes"]
    for index in range(4):
        group = "reference" if int(groups[index]) == 0 else "at-risk"
        input_rows.append(
            ",".join(
                (
                    f"conformance-participant-{index + 1:04d}",
                    group,
                    repr(float(values[index, 0])),
                    repr(float(values[index, 1])),
                )
            )
        )
    input_bytes = ("\n".join(input_rows) + "\n").encode("ascii")
    input_path = data_root / "conformance-input.csv"
    write_private_new(input_path, input_bytes)

    worker = WorkerCommand.from_tokens((sys.executable, str(worker_path)))
    receipt = describe_worker(worker)
    available_identities = cast(list[dict[str, Any]], receipt["available_expected_identities"])
    advertised_algorithms = cast(
        list[dict[str, Any]],
        cast(dict[str, Any], receipt["description"])["supported_algorithms"],
    )
    if len(available_identities) != 1 or len(advertised_algorithms) != 1:
        raise InvalidInputError(
            "DEMO.CONFORMANCE_WORKER_SURFACE",
            "The built-in conformance worker must advertise exactly one algorithm.",
        )
    algorithm_id = str(advertised_algorithms[0]["algorithm_id"])
    if available_identities[0]["algorithm_id"] != algorithm_id:
        raise InvalidInputError(
            "DEMO.CONFORMANCE_WORKER_SURFACE",
            "The built-in conformance worker identity is inconsistent.",
        )
    expected = cast(dict[str, Any], available_identities[0]["expected_identity"])
    description = WorkerInvoker(worker, expected_identity=expected).describe_authenticated()
    algorithm = cast(
        dict[str, Any],
        next(
            row for row in description.supported_algorithms if row["algorithm_id"] == algorithm_id
        ),
    )
    worker_config = {
        "worker": {"argv": list(worker.argv)},
        "algorithm_id": algorithm_id,
        "settings": {},
        "expected_identity": expected,
    }
    worker_bytes = _json_bytes(worker_config)
    worker_path_config = worker_root / "worker.json"
    write_private_new(worker_path_config, worker_bytes)

    config = copy.deepcopy(parse_audit_config(_starter_template_bytes("synthetic")))
    config.pop("development_scenario_authority", None)
    input_digest = exact_file_sha256(input_bytes)
    config["input"].update(
        {
            "path": f"{root.name}/data/conformance-input.csv",
            "expected_byte_digest": input_digest,
            "format": {
                **config["input"]["format"],
                "columns": [
                    {"source_column": "participant_code", "physical_type": "string"},
                    {"source_column": "group", "physical_type": "string"},
                    {"source_column": "event_01", "physical_type": "float64"},
                    {"source_column": "event_02", "physical_type": "float64"},
                ],
            },
            "variant": {
                **config["input"]["variant"],
                "variant_id": "conformance-strict-sequence",
                "label": "Project-owned deterministic conformance input",
                "source_digest": input_digest,
                "provenance_note": "Generated locally by the D08 conformance generator.",
                "created_by": "auditor-synthetic-generator",
                "synthetic_truth_digest": provenance["complete_truth_sha256"],
            },
        }
    )
    events = config["column_roles"]["events"]
    for index, event in enumerate(events):
        event.update(
            {
                "event_id": event_ids[index],
                "display_name": f"Synthetic event {index + 1}",
                "abnormal_direction": generated.event_directions[index],
            }
        )
    config["column_roles"]["covariates"] = []
    config["column_roles"]["metadata"] = []
    config["column_roles"]["ignored_columns"] = []
    config["worker"].update(
        {
            "config_path": f"{root.name}/worker/worker.json",
            "worker_config_digest": exact_file_sha256(worker_bytes),
            "worker_identity_digest": expected["selected_backend_identity_digest"],
        }
    )
    requested_outputs = [
        "central_order",
        "position_probabilities",
        "pairwise_precedence",
    ]
    if capability_profile in {"full", "partial"}:
        requested_outputs.extend(
            (
                "training_stage_posterior",
                "training_expected_stage",
            )
        )
    if capability_profile == "full":
        requested_outputs.insert(-1, "training_hard_stages")
    base_identity = expected["base_backend_identity"]
    backend = config["baseline_analysis"]["backend"]
    backend.update(
        {
            "adapter_id": base_identity["adapter_id"],
            "adapter_semantics_digest": algorithm["adapter_semantics_digest"],
            "expected_backend_name": base_identity["backend_name"],
            "expected_backend_source_digest": base_identity["backend_source_digest"],
            "algorithm_id": algorithm_id,
            "capabilities_digest": algorithm["capabilities_digest"],
            "settings_schema_digest": algorithm["settings_schema_digest"],
            "stage_semantics_digest": algorithm["stage_semantics_digest"],
            "settings": {},
            "settings_digest": settings_digest({}),
            "requested_outputs": requested_outputs,
            "requested_outputs_digest": requested_outputs_digest("fit", requested_outputs),
        }
    )
    config["baseline_analysis"]["dataset_variant_intent"].update(
        {
            "source_variant_id": "conformance-strict-sequence",
        }
    )
    config["baseline_analysis"]["event_set"] = [{"event_id": event_id} for event_id in event_ids]
    config["baseline_analysis"]["event_directions"] = dict(
        zip(event_ids, generated.event_directions, strict=True)
    )
    config["baseline_analysis"]["missingness_policy"]["event_ids"] = list(event_ids)
    projection = algorithm["adapter_semantics"]["mcmc_projection"]
    if projection["availability"] == "UNAVAILABLE":
        config["baseline_analysis"]["mcmc"] = None
    else:
        mcmc = config["baseline_analysis"]["mcmc"]
        for binding in projection["schedule_bindings"]:
            if binding["source_kind"] != "adapter-constant":
                raise InvalidInputError(
                    "DEMO.CONFORMANCE_SETTINGS",
                    "The built-in conformance worker has an unsupported settings contract.",
                )
            mcmc[binding["plan_field"]] = binding["constant_value"]
        proposal_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"urn:ebm-audit:worker-settings-schema:{projection['proposal_method_id']}:1",
            "type": "object",
            "additionalProperties": False,
            "properties": {},
            "required": [],
        }
        mcmc.update(
            {
                "chain_count": 1,
                "indexing_rule": projection["indexing_rule"],
                "initialization_rule": projection["initialization_rule"],
                "proposal_method_id": projection["proposal_method_id"],
                "proposal_settings": [],
                "proposal_settings_schema_digest": settings_schema_digest(proposal_schema),
            }
        )
    config["source_variants"] = [
        {
            **config["source_variants"][0],
            "source_variant_id": "conformance-strict-sequence",
        }
    ]
    config["experiments"]["sets"] = [
        experiment
        for experiment in config["experiments"]["sets"]
        if experiment["mode"] == "baseline"
    ]
    for profile in config["profiles"].values():
        profile.update(
            {
                "bootstrap_replicates": 0,
                "subsample_replicates": 0,
                "influence_max_removals": 0,
                "null_replicates_per_family": 0,
                "max_parallel_workers": 1,
            }
        )
    config["output"]["root"] = "ebm-audit-demo"
    config_path = root.parent / ".ebm-audit-conformance-demo.json"
    write_private_new(config_path, _json_bytes(config))
    return config_path, provenance


def run_conformance_demo(
    *,
    timeout_seconds: float,
    capability_profile: str = "full",
) -> tuple[Mapping[str, Any], ExitCode]:
    """Run D08's exact synthetic EBM through the ordinary local audit path."""

    from ebm_audit.universe.preparation import _conformance_demo_provenance

    destination = Path.cwd() / "ebm-audit-demo"
    support_root = Path.cwd() / ".ebm-audit-conformance-demo"
    config_path = Path.cwd() / ".ebm-audit-conformance-demo.json"
    if (
        destination.exists()
        or destination.is_symlink()
        or support_root.exists()
        or config_path.exists()
        or config_path.is_symlink()
    ):
        raise InvalidInputError(
            "SPEC.OUTPUT_ALREADY_EXISTS",
            "The output path already exists; this command does not overwrite artifacts.",
        )
    ensure_private_directory(support_root)
    try:
        with _conformance_worker_path(capability_profile) as worker_path:
            config_path, provenance = _conformance_demo_config(
                support_root,
                worker_path=worker_path,
                capability_profile=capability_profile,
            )
            result, exit_code = run_audit(
                config_path,
                profile_id="quick",
                timeout_seconds=timeout_seconds,
                _conformance_demo_provenance=_conformance_demo_provenance(provenance),
            )
        return result, exit_code
    finally:
        with suppress(OSError):
            config_path.unlink()
        for path in sorted(support_root.rglob("*"), reverse=True):
            with suppress(OSError):
                path.unlink() if path.is_file() else path.rmdir()
        with suppress(OSError):
            support_root.rmdir()


def _run_audit_transaction(
    config_path: Path,
    *,
    profile_id: str,
    timeout_seconds: float,
    _conformance_demo_provenance: _ConformanceDemoProvenance | None = None,
    _validated_plan_callback: _ValidatedOrdinaryPlanCallback | None = None,
    _validated_completion_callback: _ValidatedOrdinaryAuditCallback | None = None,
    _validated_report_binding_callback: (_ValidatedOrdinaryReportBindingCallback | None) = None,
    _execution_only: bool = False,
    _disable_process_failure_retry: bool = False,
    _public_synthetic_input_owner: SealedPublicSyntheticAuditInput | None = None,
) -> _OrdinaryAuditTransactionResult | _ExecutionAuditTransactionResult:
    """Execute one exact local candidate set, optionally stopping before reports."""

    with ExitStack() as stack:
        development_transaction = None
        development_science_receipt = None
        staged_output: StagedOutputTransaction | None = None
        if _public_synthetic_input_owner is not None:
            from ebm_audit.synthetic.audit_input import (
                _public_synthetic_input_read_scope,
                _read_public_synthetic_ordinary_transaction_owners,
            )

            stack.enter_context(
                _public_synthetic_input_read_scope(_public_synthetic_input_owner)
            )
            (
                source_config,
                public_staged_output,
                verified,
                authorized,
                prepared,
            ) = _read_public_synthetic_ordinary_transaction_owners(_public_synthetic_input_owner)
            if config_path.absolute() != source_config.private_paths.source_config:
                raise TypeError("The public synthetic input belongs to a different source config.")
            worker_config, description = _describe_authorized_worker(
                authorized,
                timeout_seconds=timeout_seconds,
            )
            store = public_staged_output.store
        else:
            resolved = load_audit_config(config_path)
            from ebm_audit.synthetic.development_null import is_development_null_run

        if _public_synthetic_input_owner is None and is_development_null_run(resolved):
            from ebm_audit.synthetic.development_null import (
                open_development_null_transaction,
            )

            ensure_private_directory(resolved.private_paths.output_root.parent)
            staged_output = stack.enter_context(
                StagedOutputTransaction.create(resolved.private_paths.output_root)
            )
            development_transaction = open_development_null_transaction(
                resolved,
                staged_output,
                profile_id=profile_id,
            )
            authorized = development_transaction.authorized_config
            verified = development_transaction.verified_config_files
            stack.callback(verified.close)
            worker_config, description = _describe_authorized_worker(
                authorized,
                timeout_seconds=timeout_seconds,
            )
            prepared = development_transaction.prepared_dataset
            store = staged_output.store
        elif _public_synthetic_input_owner is None:
            (
                authorized,
                verified,
                worker_config,
                description,
            ) = stack.enter_context(
                authorized_description(
                    resolved,
                    timeout_seconds=timeout_seconds,
                )
            )
            prepared = prepare_audit_dataset(authorized)
            store = authorized.open_output_store()
        public_intent = issue_public_intent_manifest(authorized, (description,))
        authority = issue_planning_authority(
            authorized,
            prepared,
            (description,),
            public_intent_manifest=public_intent,
            profile_id=profile_id,
        )
        plan = compile_analysis_plan(authority)
        if _conformance_demo_provenance is None:
            transaction = authority.prepare()
        else:
            from ebm_audit.universe.preparation import _prepare_analysis_plan

            transaction = _prepare_analysis_plan(
                authority,
                conformance_demo_provenance=_conformance_demo_provenance,
            )
        plan_authorization = authorize_plan_candidates(authority)
        authorizations = _authenticate_existing_plan_operation_matrix(authority, transaction)
        if _validated_plan_callback is not None:
            if not callable(_validated_plan_callback):
                raise TypeError("The ordinary plan callback must be callable.")
            _validated_plan_callback(authority, transaction, verified, authorizations)
        resolved_public_config = authorized.resolved_public_config
        dataset_summary_record = prepared.summary.record
        assert_no_direct_identifier_fields(resolved_public_config)
        assert_no_direct_identifier_fields(dataset_summary_record)
        store.write_bytes(
            "config.resolved.yaml",
            _json_bytes(resolved_public_config),
        )
        store.write_bytes(
            "data-summary.json",
            canonical_json_bytes(dataset_summary_record),
        )
        journal = open_result_persistence_journal(
            store,
            plan_authorization,
            transaction,
        )
        invoker = WorkerInvoker(
            worker_config.worker,
            timeout_seconds=timeout_seconds,
            expected_identity=worker_config.expected_identity,
        )
        if _disable_process_failure_retry:
            execute_preparation_transaction_no_retry(transaction, invoker, journal)
        else:
            execute_preparation_transaction(transaction, invoker, journal)
        terminals = persisted_candidate_terminals(journal)
        evidence = seal_result_evidence_set(journal)
        baseline_outcome = derive_verified_baseline_outcome(
            evidence,
            authorized.baseline_reference_bundle,
        )
        captured_scientific_run = capture_scientific_run(evidence)
        sealed_scientific_evidence = seal_scientific_evidence(captured_scientific_run)
        if not _execution_only:
            stack.enter_context(
                _scientific_evidence_read_scope(
                    captured_scientific_run,
                    sealed_scientific_evidence,
                )
            )
        if _execution_only:
            if (
                _validated_completion_callback is not None
                or _validated_report_binding_callback is not None
            ):
                raise TypeError(
                    "The execution-only transaction cannot accept meaning or report callbacks."
                )
            return _ExecutionAuditTransactionResult(
                planning_authority=authority,
                preparation_transaction=transaction,
                prepared_authorizations=authorizations,
                captured_scientific_run=captured_scientific_run,
                sealed_scientific_evidence=sealed_scientific_evidence,
            )
        if _validated_completion_callback is None:
            meaning_evidence_extension = issue_default_meaning_evidence_extension(
                evidence_graph_digest=_read_sealed_scientific_evidence(
                    sealed_scientific_evidence
                ).evidence_digest.removeprefix("sha256:"),
                operation_plan_sha256=_read_captured_scientific_run(
                    captured_scientific_run
                ).plan_digest,
            )
        else:
            if not callable(_validated_completion_callback):
                raise TypeError("The ordinary completion callback must be callable.")
            meaning_evidence_extension = _validated_completion_callback(
                authority,
                transaction,
                authorizations,
                captured_scientific_run,
                sealed_scientific_evidence,
            )
            if type(meaning_evidence_extension) is not AuthenticatedMeaningEvidenceExtension:
                raise TypeError(
                    "The ordinary completion callback returned an invalid evidence extension."
                )
        validate_meaning_extension_science_join(
            meaning_evidence_extension,
            captured_scientific_run,
            sealed_scientific_evidence,
        )
        if development_transaction is not None:
            from ebm_audit.synthetic.development_null import (
                bind_development_null_terminal_evidence,
                seal_development_null_science_receipt,
            )

            development_null_receipt = bind_development_null_terminal_evidence(
                development_transaction,
                evidence,
            )
            development_science_receipt = seal_development_null_science_receipt(
                evidence,
                sealed_scientific_evidence,
                development_null_receipt,
            )
        input_declaration = _input_declaration(authorized)
        report_transaction = render._write_report_from_live_evidence_transaction(
            store,
            evidence,
            input_declaration=input_declaration,
            baseline_assessment=baseline_outcome.assessment,
            baseline_reproduction=baseline_outcome.reproduction,
            development_null_science_receipt=development_science_receipt,
            _sealed_scientific_evidence=sealed_scientific_evidence,
            authenticated_meaning_evidence_extension=meaning_evidence_extension,
        )
        if _validated_report_binding_callback is not None:
            if not callable(_validated_report_binding_callback):
                raise TypeError("The ordinary report-binding callback must be callable.")
            report_binding_result = _validated_report_binding_callback(
                report_transaction.report_model_artifact_binding
            )
            if report_binding_result is not None:
                raise TypeError("The ordinary report-binding callback returned an invalid result.")
        authenticated_report_transaction = report_transaction.authenticated_owner
        report_receipt = report_transaction.receipt
        candidate_execution = cast(
            Mapping[str, Any],
            report_receipt["candidate_execution"],
        )
        science_reason_codes = cast(
            Sequence[str],
            report_receipt["science_completion_reason_codes"],
        )
        run_completion_status, process_exit_code = _run_completion_outcome(
            candidate_execution,
            report_status=report_receipt["report_status"],
            science_completion_gate_status=report_receipt["science_completion_gate_status"],
        )
        failures, warnings = _terminal_ledgers(
            terminals,
            science_reason_codes=science_reason_codes,
        )
        store.write_bytes("failures.jsonl", failures)
        store.write_bytes("warnings.jsonl", warnings)
        run_status: dict[str, Any] = {
            "run_status_schema_version": "ebm-audit-run-status/6.0",
            "command_result_schema_version": "ebm-audit-cli-run-result/6.0",
            "run_completion_status": run_completion_status,
            "process_exit_code": int(process_exit_code),
            "candidate_execution_status": candidate_execution["state"],
            "candidate_execution_exit_code": candidate_execution["exit_code"],
            "candidate_execution_primary_failure_class": candidate_execution[
                "primary_failure_class"
            ],
            "audit_report_status": report_receipt["report_status"],
            "science_completion_gate_status": report_receipt["science_completion_gate_status"],
            "science_completion_reason_codes": list(science_reason_codes),
            "offline": True,
            "input_declaration": input_declaration,
            "profile_id": profile_id,
            "plan_schema_version": plan["plan_schema_version"],
            "plan_digest": plan["plan_digest"],
            "prepared_dataset_digest": prepared.prepared_dataset_id,
            "dataset_summary_digest": prepared.summary_digest,
            "terminal_index_digest": report_receipt["terminal_index_digest"],
            "scientific_evidence_digest": report_receipt["scientific_evidence_digest"],
            "participant_influence_planned_origin_count": report_receipt[
                "participant_influence_planned_origin_count"
            ],
            "participant_influence_attempt_count": report_receipt[
                "participant_influence_attempt_count"
            ],
            "participant_influence_record_count": report_receipt[
                "participant_influence_record_count"
            ],
            "participant_influence_contribution_counts": dict(
                cast(
                    Mapping[str, int],
                    report_receipt["participant_influence_contribution_counts"],
                )
            ),
            "participant_influence_status": report_receipt["participant_influence_status"],
            "participant_stage_status": report_receipt["participant_stage_status"],
            "private_participant_stage_evidence_count": report_receipt[
                "private_participant_stage_evidence_count"
            ],
            "requested_candidate_count": candidate_execution["requested_candidate_count"],
            "terminal_record_count": candidate_execution["terminal_record_count"],
            "success_count": candidate_execution["success_count"],
            "non_success_terminal_count": candidate_execution["non_success_terminal_count"],
            "privacy_failure_count": candidate_execution["privacy_failure_count"],
            "terminal_status_counts": dict(
                cast(
                    Mapping[str, int],
                    candidate_execution["terminal_status_counts"],
                )
            ),
            "report_artifact_count": report_receipt["artifact_count"],
            "report_artifacts": list(
                cast(Sequence[Mapping[str, str]], report_receipt["artifacts"])
            ),
            "manifest_emitted": False,
            "standalone_report_rehydration_available": False,
        }
        if development_science_receipt is not None:
            from ebm_audit.synthetic.development_null import (
                project_development_null_science_receipt,
                remove_development_null_private_inputs,
            )

            development_science_projection = project_development_null_science_receipt(
                development_science_receipt,
                evidence=evidence,
            )
            development_null_projection = cast(
                Mapping[str, Any],
                development_science_projection["development_null"],
            )
            if (
                report_receipt.get("development_null") != development_null_projection
                or report_receipt.get("development_null_science_receipt_digest")
                != development_science_projection["receipt_digest"]
            ):
                raise UnexpectedCoreError(
                    "DEVELOPMENT.NULL_REPORT_BINDING",
                    "The development-null report detached from its sealed science owner.",
                )
            expected_science_bytes = canonical_json_bytes(
                cast(
                    Mapping[str, Any],
                    development_science_projection["scientific_evidence"],
                )
            )
            expected_development_receipt_bytes = canonical_json_bytes(
                development_science_projection
            )
            run_status["development_null"] = dict(development_null_projection)
            run_status["development_null_science_receipt_digest"] = development_science_projection[
                "receipt_digest"
            ]
            if development_transaction is None or staged_output is None:
                raise UnexpectedCoreError(
                    "DEVELOPMENT.NULL_PUBLICATION",
                    "The development-null publication transaction is unavailable.",
                )
            remove_development_null_private_inputs(development_transaction)
            run_status["publication"] = staged_output.publication_receipt()
        else:
            run_status["publication"] = _publication_receipt(
                store,
                requested_candidate_count=cast(
                    int,
                    candidate_execution["requested_candidate_count"],
                ),
                private_participant_stage_evidence_count=cast(
                    int,
                    report_receipt["private_participant_stage_evidence_count"],
                ),
                baseline_reproduction_emitted=cast(
                    bool,
                    report_receipt["baseline_reproduction_emitted"],
                ),
            )
        assert_no_direct_identifier_fields(run_status)
        status_bytes = _terminal_run_status_bytes(
            run_status,
            candidate_execution=candidate_execution,
            staging_run_root_id=store.run_root_id,
            participant_stage_status=cast(
                str,
                report_receipt["participant_stage_status"],
            ),
            development_null_science_receipt=development_science_receipt,
        )
        store.write_bytes("run-status.json", status_bytes)
        if staged_output is not None:
            published = staged_output.publish_terminal_receipt(
                validate_terminal_run_status=(_issue_terminal_run_status_validator(status_bytes))
            )
            snapshot = published.read_verified()
            if snapshot.run_status_bytes != status_bytes or development_science_receipt is None:
                raise UnexpectedCoreError(
                    "DEVELOPMENT.NULL_PUBLICATION_READBACK",
                    "The published development-null bundle failed exact readback.",
                )
            if (
                snapshot.read_bytes("evidence/scientific-evidence-projection.json")
                != expected_science_bytes
                or snapshot.read_bytes("evidence/development-null-science-receipt.json")
                != expected_development_receipt_bytes
            ):
                raise UnexpectedCoreError(
                    "DEVELOPMENT.NULL_PUBLICATION_READBACK",
                    "The published development-null science receipt failed exact readback.",
                )
        return _complete_ordinary_audit_transaction(
            authenticated_report_transaction,
            (run_status, process_exit_code),
            authority,
            transaction,
            captured_scientific_run,
            sealed_scientific_evidence,
            meaning_evidence_extension,
        )


def _run_audit_execution_transaction(
    config_path: Path,
    *,
    profile_id: str,
    timeout_seconds: float,
    _conformance_demo_provenance: _ConformanceDemoProvenance | None = None,
    _validated_plan_callback: _ValidatedOrdinaryPlanCallback | None = None,
    _disable_process_failure_retry: bool = False,
    _public_synthetic_input_owner: SealedPublicSyntheticAuditInput | None = None,
) -> _ExecutionAuditTransactionResult:
    """Run the authenticated lifecycle and stop before meaning/report assembly."""

    result = _run_audit_transaction(
        config_path,
        profile_id=profile_id,
        timeout_seconds=timeout_seconds,
        _conformance_demo_provenance=_conformance_demo_provenance,
        _validated_plan_callback=_validated_plan_callback,
        _execution_only=True,
        _disable_process_failure_retry=_disable_process_failure_retry,
        _public_synthetic_input_owner=_public_synthetic_input_owner,
    )
    if type(result) is not _ExecutionAuditTransactionResult:
        raise UnexpectedCoreError(
            "RUN.EXECUTION_TRANSACTION_RESULT",
            "The execution-only workflow returned a report transaction.",
        )
    return result


def run_audit(
    config_path: Path,
    *,
    profile_id: str,
    timeout_seconds: float,
    _conformance_demo_provenance: _ConformanceDemoProvenance | None = None,
) -> tuple[Mapping[str, Any], ExitCode]:
    """Execute one audit and preserve the established public result shape."""

    result = _run_audit_transaction(
        config_path,
        profile_id=profile_id,
        timeout_seconds=timeout_seconds,
        _conformance_demo_provenance=_conformance_demo_provenance,
    )
    if type(result) is not _OrdinaryAuditTransactionResult:
        raise UnexpectedCoreError(
            "RUN.ORDINARY_TRANSACTION_RESULT",
            "The ordinary workflow returned an execution-only transaction.",
        )
    return result.public_result


def _doctor_check(
    check_id: str,
    status: str,
    *,
    failure_code: str | None = None,
    count: int | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {"check_id": check_id, "status": status}
    if failure_code is not None:
        row["failure_code"] = failure_code
    if count is not None:
        row["checked_count"] = count
    return row


def _schema_doctor_check() -> dict[str, Any]:
    try:
        for name in RESOURCE_FILENAMES:
            load_resource_json(name)
            if name.endswith(".schema.json"):
                Draft202012Validator.check_schema(load_schema(name))
    except Exception:
        return _doctor_check(
            "package-and-normative-resources",
            "FAIL",
            failure_code="DOCTOR.NORMATIVE_RESOURCE_INVALID",
        )
    return _doctor_check(
        "package-and-normative-resources",
        "PASS",
        count=len(RESOURCE_FILENAMES),
    )


def _root_doctor_check(root: Path) -> dict[str, Any]:
    descriptor: int | None = None
    probe_created = False
    try:
        if not root.exists():
            raise OSError
        ensure_private_directory(root)
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(root.absolute(), flags)
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode) or stat.S_IMODE(observed.st_mode) != 0o700:
            raise OSError
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            create_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        probe = os.open(_DOCTOR_PROBE_NAME, create_flags, 0o600, dir_fd=descriptor)
        probe_created = True
        try:
            os.write(probe, b"offline-local-readiness-probe\n")
            os.fsync(probe)
        finally:
            os.close(probe)
        os.unlink(_DOCTOR_PROBE_NAME, dir_fd=descriptor)
        probe_created = False
    except (AuditError, OSError):
        return _doctor_check(
            "private-local-root",
            "FAIL",
            failure_code="DOCTOR.PRIVATE_ROOT_NOT_WRITABLE",
        )
    finally:
        if descriptor is not None:
            if probe_created:
                with suppress(OSError):
                    os.unlink(_DOCTOR_PROBE_NAME, dir_fd=descriptor)
            os.close(descriptor)
    return _doctor_check("private-local-root", "PASS")


def _configured_worker_doctor_check(
    config_path: Path,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    try:
        config = WorkerConfig.from_yaml(config_path)
        WorkerInvoker(
            config.worker,
            timeout_seconds=timeout_seconds,
            expected_identity=config.expected_identity,
        ).describe_authenticated()
    except AuditError as exc:
        return _doctor_check(
            "configured-worker-authenticated-describe",
            "FAIL",
            failure_code=exc.code,
        )
    except Exception:
        return _doctor_check(
            "configured-worker-authenticated-describe",
            "FAIL",
            failure_code="DOCTOR.WORKER_CHECK_FAILED",
        )
    return _doctor_check("configured-worker-authenticated-describe", "PASS")


def _pysaebm_root() -> Path:
    return Path(__file__).resolve().parents[2] / "workers" / "pysaebm"


def _pysaebm_doctor_check(*, timeout_seconds: float) -> dict[str, Any]:
    root = _pysaebm_root()
    python = root / ".venv" / "bin" / "python"
    worker = root / "worker.py"
    lock = root / "uv.lock"
    try:
        if not python.is_file() or not worker.is_file() or not lock.is_file():
            raise OSError
        command = WorkerCommand.from_tokens((str(python), str(worker)))
        describe_worker(command, timeout_seconds=timeout_seconds)
    except AuditError as exc:
        return _doctor_check(
            "pinned-pysaebm-worker",
            "FAIL",
            failure_code=exc.code,
        )
    except Exception:
        return _doctor_check(
            "pinned-pysaebm-worker",
            "FAIL",
            failure_code="DOCTOR.PYSAEBM_UNAVAILABLE",
        )
    return _doctor_check("pinned-pysaebm-worker", "PASS")


def doctor(
    *,
    root: Path | None,
    worker_config: Path | None,
    require_pysaebm: bool,
    timeout_seconds: float,
) -> tuple[Mapping[str, Any], ExitCode]:
    """Run deterministic local-only readiness checks without model fitting."""

    checks = [
        _doctor_check("python-runtime", "PASS" if sys.version_info >= (3, 12) else "FAIL"),
        _doctor_check("auditor-package", "PASS" if __version__ else "FAIL"),
        _doctor_check("offline-no-network-posture", "PASS"),
        _schema_doctor_check(),
    ]
    if root is not None:
        checks.append(_root_doctor_check(root))
    if worker_config is not None:
        checks.append(
            _configured_worker_doctor_check(
                worker_config,
                timeout_seconds=timeout_seconds,
            )
        )
    if require_pysaebm:
        checks.append(_pysaebm_doctor_check(timeout_seconds=timeout_seconds))

    failures = [row for row in checks if row["status"] != "PASS"]
    failure_codes = {str(row.get("failure_code", "")) for row in failures}
    if not failures:
        exit_code = ExitCode.SUCCESS
    elif any(code.startswith("PRIVACY.") for code in failure_codes):
        exit_code = ExitCode.PRIVACY_FAILED
    elif any(code.startswith("BACKEND.") or code.startswith("PROTOCOL.") for code in failure_codes):
        exit_code = ExitCode.BACKEND_OR_PROTOCOL_FAILURE
    elif any("WORKER" in code or "PYSAEBM" in code for code in failure_codes):
        exit_code = ExitCode.WORKER_OR_CAPABILITY_UNAVAILABLE
    elif any(code.startswith("SPEC.") or "ROOT" in code for code in failure_codes):
        exit_code = ExitCode.INVALID_INPUT_OR_SPECIFICATION
    else:
        exit_code = ExitCode.UNEXPECTED_CORE_ERROR
    return (
        {
            "command_result_schema_version": "ebm-audit-cli-doctor-result/1.0",
            "status": "READY" if not failures else "NOT_READY",
            "offline": True,
            "network_calls": 0,
            "scientific_worker_commands_run": 0,
            "check_count": len(checks),
            "failure_count": len(failures),
            "checks": checks,
        },
        exit_code,
    )


__all__ = [
    "authorized_description",
    "doctor",
    "initialize_config",
    "plan_preexecution",
    "validate_preexecution",
]
