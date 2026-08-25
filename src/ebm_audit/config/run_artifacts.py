"""Executable invariants for append-only run artifact snapshots."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from ebm_audit.baseline import (
    BaselineReproductionError,
    VerifiedBaselineAssessment,
    _verified_baseline_assessment_snapshot,
)
from ebm_audit.errors import InvalidInputError, PrivacyViolationError
from ebm_audit.lifecycle import (
    CandidateTerminalAuthorization,
    LifecycleInputError,
    PlanCandidateAuthorization,
    SealedCandidateExecutionDisposition,
    _candidate_execution_disposition_evidence,
    _candidate_execution_disposition_record,
    _candidate_terminal_rows,
    _plan_candidate_rows,
    _read_candidate_terminal_authorization,
    _read_plan_candidate_authorization,
    classify_candidate_execution,
    verify_lifecycle_registry,
)
from ebm_audit.privacy.safe import assert_no_direct_identifier_fields
from ebm_audit.protocol import exact_file_sha256
from ebm_audit.schema import (
    ResourceNotFoundError,
    SchemaValidationError,
    resource_bytes,
    validate_instance,
)

from .models import ConfigContractError

if TYPE_CHECKING:
    from ebm_audit.results.persistence import (
        SealedCandidateTerminalIndex,
        SealedResultEvidenceSet,
    )

RUN_STATES: tuple[str, ...] = (
    "RUN_CREATED",
    "INPUT_VALIDATED",
    "PLAN_SEALED",
    "EXECUTING",
    "ALL_UNIVERSES_TERMINAL",
    "BASELINE_SEALED",
    "EVIDENCE_SEALED",
    "REPORT_SEALED",
    "MANIFEST_SEALED",
)

_ARTIFACT_FIELDS: tuple[str, ...] = (
    "run_created_digest",
    "input_validation_digest",
    "plan_digest",
    "execution_start_digest",
    "candidate_terminal_index_digest",
    "baseline_digest",
    "evidence_digest",
    "report_digest",
    "manifest_digest",
)

_RUN_ARTIFACT_OWNER_SCHEMA_REF = "run-artifacts.schema.json#/$defs/RunArtifactState"
_RUN_ARTIFACT_RULE_FIELDS = frozenset(
    {
        "invariant_id",
        "owner_schema_ref",
        "enforcement_kind",
        "required",
        "requires_verified_baseline_assessment",
    }
)
_RUN_ARTIFACT_ENFORCEMENT_KINDS = frozenset({"schema", "runtime", "schema-plus-runtime"})
_EXPECTED_RUN_ARTIFACT_RULE_METADATA: tuple[tuple[str, str, bool], ...] = (
    ("run-state-history-is-exact-prefix/1", "runtime", False),
    ("run-state-artifact-availability/1", "runtime", False),
    ("candidate-terminal-prefix-and-complete-coverage/2", "runtime", False),
    (
        "candidate-execution-disposition-derived-from-exact-result-evidence/1",
        "runtime",
        False,
    ),
    (
        "manifest-requires-exact-run-gate-disposition/1",
        "runtime",
        True,
    ),
    ("cli-lifecycle-registry-exact-resource-digest/1", "runtime", False),
    ("manifest-is-last/1", "schema-plus-runtime", False),
    (
        "no-private-path-participant-or-raw-value-fields/1",
        "schema-plus-runtime",
        False,
    ),
)
_RUN_ARTIFACT_REJECTION_CODES = frozenset(
    {
        "RUN.ARTIFACT_DIGEST_MUTATED",
        "RUN.ARTIFACT_STATE_MISMATCH",
        "RUN.BASELINE_ASSESSMENT_IDENTITY",
        "RUN.BASELINE_VERIFICATION_REQUIRED",
        "RUN.CANDIDATE_EXECUTION_DISPOSITION_IDENTITY",
        "RUN.CANDIDATE_EXECUTION_DISPOSITION_REQUIRED",
        "RUN.HISTORY_MUTATED",
        "RUN.IMMUTABLE_IDENTITY_MUTATED",
        "RUN.INCOMPLETE_TERMINAL_COVERAGE",
        "RUN.INTERNAL_CONTRACT",
        "RUN.LIFECYCLE_REGISTRY_IDENTITY",
        "RUN.LIFECYCLE_REGISTRY_RESOURCE",
        "RUN.LIFECYCLE_RULE_CLOSURE",
        "RUN.LIFECYCLE_RULE_EXECUTION",
        "RUN.MANIFEST_NOT_LAST",
        "RUN.NON_ADJACENT_TRANSITION",
        "RUN.PLAN_AUTHORIZATION_REQUIRED",
        "RUN.PLAN_CANDIDATE_MISMATCH",
        "RUN.PLAN_IDENTITY_MISMATCH",
        "RUN.PRIVACY_FIELD",
        "RUN.RESULT_EVIDENCE_IDENTITY",
        "RUN.RESULT_EVIDENCE_REQUIRED",
        "RUN.RUN_GATE_DISPOSITION_REQUIRED",
        "RUN.SAME_STATE_MUTATION",
        "RUN.SCHEMA",
        "RUN.STATE_HISTORY_LENGTH",
        "RUN.STATE_HISTORY_PREFIX",
        "RUN.TERMINAL_BEFORE_EXECUTION",
        "RUN.TERMINAL_AUTHORIZATION_REQUIRED",
        "RUN.TERMINAL_INDEX_AUTHORIZATION_REQUIRED",
        "RUN.TERMINAL_INDEX_IDENTITY",
        "RUN.TERMINAL_LEDGER_MUTATED",
        "RUN.CANDIDATE_TERMINAL_IDENTITY",
        "RUN.UNKNOWN_STATE",
    }
)
_RUN_ARTIFACT_VALIDATION_SUCCESS = object()


@dataclass(frozen=True, slots=True)
class _RunArtifactRuleContext:
    snapshot: Mapping[str, Any]
    lifecycle_registry_bytes: bytes
    plan_candidate_authorization: PlanCandidateAuthorization | None
    candidate_terminal_authorization: CandidateTerminalAuthorization | None
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None
    sealed_result_evidence_set: SealedResultEvidenceSet | None
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition | None
    verified_baseline_assessment: VerifiedBaselineAssessment | None


@dataclass(frozen=True, slots=True)
class _SanitizedRunControlFlow:
    kind: str
    exit_code: int | None = None


def _fail(code: str) -> ConfigContractError:
    return ConfigContractError(code)


def _sanitize_run_boundary_exception(
    stopped: BaseException,
) -> str | _SanitizedRunControlFlow:
    if type(stopped) is KeyboardInterrupt:
        return _SanitizedRunControlFlow("keyboard_interrupt")
    if type(stopped) is SystemExit:
        stopped_code = stopped.code
        safe_exit_code = stopped_code if stopped_code is None or type(stopped_code) is int else 1
        return _SanitizedRunControlFlow("system_exit", safe_exit_code)
    if type(stopped) is GeneratorExit:
        return _SanitizedRunControlFlow("generator_exit")
    return "RUN.INTERNAL_CONTRACT"


def _closed_run_rejection_code(rejected: ConfigContractError) -> str:
    if type(rejected) is not ConfigContractError:
        return "RUN.INTERNAL_CONTRACT"
    try:
        code = rejected.code
    except BaseException:
        return "RUN.INTERNAL_CONTRACT"
    if type(code) is not str or code not in _RUN_ARTIFACT_REJECTION_CODES:
        return "RUN.INTERNAL_CONTRACT"
    return code


def _finish_run_validation_boundary(
    outcome: object,
) -> None:
    if outcome is _RUN_ARTIFACT_VALIDATION_SUCCESS:
        return
    if type(outcome) is _SanitizedRunControlFlow:
        if outcome.kind == "keyboard_interrupt":
            raise KeyboardInterrupt
        if outcome.kind == "system_exit":
            raise SystemExit(outcome.exit_code)
        raise GeneratorExit
    if type(outcome) is str and outcome in _RUN_ARTIFACT_REJECTION_CODES:
        raise _fail(outcome)
    raise _fail("RUN.INTERNAL_CONTRACT")


def _normalize_run_boundary_outcome(outcome: object) -> object:
    if outcome is _RUN_ARTIFACT_VALIDATION_SUCCESS:
        return _RUN_ARTIFACT_VALIDATION_SUCCESS
    if type(outcome) is str:
        return outcome if outcome in _RUN_ARTIFACT_REJECTION_CODES else "RUN.INTERNAL_CONTRACT"
    if type(outcome) is not _SanitizedRunControlFlow:
        return "RUN.INTERNAL_CONTRACT"
    try:
        kind = outcome.kind
        exit_code = outcome.exit_code
    except BaseException:
        return "RUN.INTERNAL_CONTRACT"
    if type(kind) is not str:
        return "RUN.INTERNAL_CONTRACT"
    if kind == "keyboard_interrupt" and exit_code is None:
        return _SanitizedRunControlFlow(kind)
    if kind == "generator_exit" and exit_code is None:
        return _SanitizedRunControlFlow(kind)
    if kind == "system_exit" and (exit_code is None or type(exit_code) is int):
        return _SanitizedRunControlFlow(kind, exit_code)
    return "RUN.INTERNAL_CONTRACT"


def _validate_history(snapshot: Mapping[str, Any]) -> int:
    current = cast(str, snapshot["current_state"])
    state_index: int | None = None
    with suppress(ValueError):
        state_index = RUN_STATES.index(current)
    if state_index is None:
        raise _fail("RUN.UNKNOWN_STATE")
    history = cast(Sequence[Mapping[str, Any]], snapshot["state_history"])
    if len(history) != state_index + 1:
        raise _fail("RUN.STATE_HISTORY_LENGTH")
    for ordinal, (row, state) in enumerate(zip(history, RUN_STATES, strict=False)):
        if row["ordinal"] != ordinal or row["state"] != state:
            raise _fail("RUN.STATE_HISTORY_PREFIX")
    return state_index


def _validate_artifact_availability(snapshot: Mapping[str, Any], state_index: int) -> None:
    artifacts = cast(Mapping[str, Any], snapshot["artifact_digests"])
    for index, field in enumerate(_ARTIFACT_FIELDS):
        if (artifacts[field] is not None) != (index <= state_index):
            raise _fail("RUN.ARTIFACT_STATE_MISMATCH")
    identity = cast(Mapping[str, Any], snapshot["identity"])
    if identity["plan_digest"] != artifacts["plan_digest"]:
        raise _fail("RUN.PLAN_IDENTITY_MISMATCH")


def _candidate_key(row: Mapping[str, Any]) -> tuple[object, object, object]:
    return (
        row.get("candidate_ordinal"),
        row.get("candidate_id"),
        row.get("analysis_spec_id"),
    )


def _validate_candidate_coverage(
    snapshot: Mapping[str, Any],
    state_index: int,
    plan_candidate_authorization: PlanCandidateAuthorization | None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None,
) -> None:
    planned = list(cast(Sequence[Mapping[str, Any]], snapshot["planned_candidates"]))
    terminals = cast(Sequence[Mapping[str, Any]], snapshot["candidate_terminals"])
    plan_index = RUN_STATES.index("PLAN_SEALED")
    if state_index < plan_index:
        if planned or terminals:
            raise _fail("RUN.PLAN_CANDIDATE_MISMATCH")
        return
    if type(plan_candidate_authorization) is not PlanCandidateAuthorization:
        raise _fail("RUN.PLAN_AUTHORIZATION_REQUIRED")
    try:
        authority_state = _read_plan_candidate_authorization(plan_candidate_authorization)
        authorized = list(_plan_candidate_rows(plan_candidate_authorization))
    except TypeError:
        raise _fail("RUN.PLAN_AUTHORIZATION_REQUIRED") from None
    identity = cast(Mapping[str, Any], snapshot["identity"])
    if (
        identity["plan_digest"] != authority_state.plan_digest
        or planned != authorized
        or any(
            _candidate_key(row) != (ordinal, row["candidate_id"], row["candidate_id"])
            for ordinal, row in enumerate(planned)
        )
    ):
        raise _fail("RUN.PLAN_CANDIDATE_MISMATCH")
    if len(terminals) > len(planned) or any(
        _candidate_key(terminal) != _candidate_key(planned[position])
        for position, terminal in enumerate(terminals)
    ):
        raise _fail("RUN.CANDIDATE_TERMINAL_IDENTITY")
    if state_index < RUN_STATES.index("EXECUTING") and terminals:
        raise _fail("RUN.TERMINAL_BEFORE_EXECUTION")
    authorized_terminals: list[dict[str, Any]] | None = None
    if terminals or state_index >= RUN_STATES.index("ALL_UNIVERSES_TERMINAL"):
        if type(candidate_terminal_authorization) is not CandidateTerminalAuthorization:
            raise _fail("RUN.TERMINAL_AUTHORIZATION_REQUIRED")
        try:
            terminal_state = _read_candidate_terminal_authorization(
                candidate_terminal_authorization
            )
            authorized_terminals = list(_candidate_terminal_rows(candidate_terminal_authorization))
        except TypeError:
            raise _fail("RUN.TERMINAL_AUTHORIZATION_REQUIRED") from None
        if terminal_state.plan_candidate_authorization is not plan_candidate_authorization:
            raise _fail("RUN.PLAN_CANDIDATE_MISMATCH")
        if list(terminals) != authorized_terminals[: len(terminals)]:
            raise _fail("RUN.CANDIDATE_TERMINAL_IDENTITY")
    if state_index >= RUN_STATES.index("ALL_UNIVERSES_TERMINAL") and (
        len(terminals) != len(planned) or list(terminals) != authorized_terminals
    ):
        raise _fail("RUN.INCOMPLETE_TERMINAL_COVERAGE")
    all_terminal_index = RUN_STATES.index("ALL_UNIVERSES_TERMINAL")
    if state_index < all_terminal_index:
        return
    from ebm_audit.results.persistence import (
        SealedCandidateTerminalIndex,
        _read_sealed_terminal_index,
    )

    if type(sealed_candidate_terminal_index) is not SealedCandidateTerminalIndex:
        raise _fail("RUN.TERMINAL_INDEX_AUTHORIZATION_REQUIRED")
    try:
        sealed_state = _read_sealed_terminal_index(sealed_candidate_terminal_index)
    except TypeError:
        raise _fail("RUN.TERMINAL_INDEX_AUTHORIZATION_REQUIRED") from None
    except InvalidInputError:
        raise _fail("RUN.TERMINAL_INDEX_IDENTITY") from None
    artifacts = cast(Mapping[str, Any], snapshot["artifact_digests"])
    if (
        sealed_state.plan_candidate_authorization is not plan_candidate_authorization
        or sealed_state.terminal_authorization is not candidate_terminal_authorization
        or sealed_state.artifact_digest != artifacts["candidate_terminal_index_digest"]
    ):
        raise _fail("RUN.TERMINAL_INDEX_IDENTITY")


def _validate_result_evidence_identity(
    snapshot: Mapping[str, Any],
    state_index: int,
    plan_candidate_authorization: PlanCandidateAuthorization | None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition | None,
) -> None:
    if state_index < RUN_STATES.index("EVIDENCE_SEALED"):
        return
    from ebm_audit.results.persistence import (
        SealedResultEvidenceSet,
        _sealed_result_evidence_run,
    )

    if type(sealed_result_evidence_set) is not SealedResultEvidenceSet:
        raise _fail("RUN.RESULT_EVIDENCE_REQUIRED")
    try:
        binding = _sealed_result_evidence_run(sealed_result_evidence_set)
    except (InvalidInputError, TypeError):
        raise _fail("RUN.RESULT_EVIDENCE_IDENTITY") from None
    artifacts = cast(Mapping[str, Any], snapshot["artifact_digests"])
    if (
        binding.plan_candidate_authorization is not plan_candidate_authorization
        or binding.terminal_authorization is not candidate_terminal_authorization
        or binding.sealed_terminal_index is not sealed_candidate_terminal_index
        or list(binding.candidate_terminals) != snapshot["candidate_terminals"]
        or binding.terminal_index_digest != artifacts["candidate_terminal_index_digest"]
    ):
        raise _fail("RUN.RESULT_EVIDENCE_IDENTITY")
    if (
        type(sealed_candidate_execution_disposition)
        is not SealedCandidateExecutionDisposition
    ):
        raise _fail("RUN.CANDIDATE_EXECUTION_DISPOSITION_REQUIRED")
    try:
        exact_evidence = _candidate_execution_disposition_evidence(
            sealed_candidate_execution_disposition
        )
        canonical_disposition = classify_candidate_execution(
            sealed_result_evidence_set
        )
    except LifecycleInputError:
        raise _fail("RUN.CANDIDATE_EXECUTION_DISPOSITION_IDENTITY") from None
    if (
        exact_evidence is not sealed_result_evidence_set
        or canonical_disposition is not sealed_candidate_execution_disposition
    ):
        raise _fail("RUN.CANDIDATE_EXECUTION_DISPOSITION_IDENTITY")


def _validate_baseline_evidence_identity(
    verified_baseline_assessment: VerifiedBaselineAssessment,
    sealed_result_evidence_set: SealedResultEvidenceSet,
) -> None:
    try:
        snapshot = _verified_baseline_assessment_snapshot(verified_baseline_assessment)
        from ebm_audit.results.persistence import _sealed_result_evidence_baseline

        baseline = _sealed_result_evidence_baseline(sealed_result_evidence_set)
    except (BaselineReproductionError, TypeError):
        raise _fail("RUN.BASELINE_VERIFICATION_REQUIRED") from None
    if (
        snapshot.sealed_result_evidence_set is not sealed_result_evidence_set
        or snapshot.plan_digest != baseline.plan_candidate_authorization.plan_digest
        or snapshot.baseline_candidate_ordinal != baseline.baseline_candidate["candidate_ordinal"]
        or snapshot.baseline_candidate_id != baseline.baseline_candidate["candidate_id"]
        or snapshot.baseline_result_id != baseline.baseline_terminal["result_id"]
        or snapshot.baseline_result_digest != baseline.baseline_terminal["result_digest"]
        or snapshot.candidate_terminal_index_digest != baseline.terminal_index_digest
        or snapshot.terminal_status != baseline.baseline_terminal["final_status"]
    ):
        raise _fail("RUN.BASELINE_ASSESSMENT_IDENTITY")


def _validate_candidate_execution_record(
    snapshot: Mapping[str, Any],
    sealed_result_evidence_set: SealedResultEvidenceSet,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition,
) -> None:
    try:
        exact_evidence = _candidate_execution_disposition_evidence(
            sealed_candidate_execution_disposition
        )
        exact_record = _candidate_execution_disposition_record(
            sealed_candidate_execution_disposition
        )
    except LifecycleInputError:
        raise _fail("RUN.CANDIDATE_EXECUTION_DISPOSITION_IDENTITY") from None
    if exact_evidence is not sealed_result_evidence_set:
        raise _fail("RUN.CANDIDATE_EXECUTION_DISPOSITION_IDENTITY")
    if snapshot["lifecycle_inputs"] != exact_record:
        raise _fail("RUN.CANDIDATE_EXECUTION_DISPOSITION_IDENTITY")


def _validate_manifest_is_last(snapshot: Mapping[str, Any]) -> None:
    is_manifest_sealed = snapshot["current_state"] == "MANIFEST_SEALED"
    artifacts = cast(Mapping[str, Any], snapshot["artifact_digests"])
    if is_manifest_sealed:
        invalid = (
            snapshot["lifecycle_inputs"] is None
            or snapshot["terminal_outcome"] is None
            or any(artifacts[field] is None for field in _ARTIFACT_FIELDS)
        )
    else:
        invalid = (
            snapshot["lifecycle_inputs"] is not None
            or snapshot["terminal_outcome"] is not None
            or artifacts["manifest_digest"] is not None
        )
    if invalid:
        raise _fail("RUN.MANIFEST_NOT_LAST")


def _rule_history(context: _RunArtifactRuleContext) -> str:
    _validate_history(context.snapshot)
    return "run-state-history-is-exact-prefix/1"


def _rule_artifact_availability(context: _RunArtifactRuleContext) -> str:
    state_index = _validate_history(context.snapshot)
    _validate_artifact_availability(context.snapshot, state_index)
    return "run-state-artifact-availability/1"


def _rule_candidate_coverage(context: _RunArtifactRuleContext) -> str:
    state_index = _validate_history(context.snapshot)
    _validate_candidate_coverage(
        context.snapshot,
        state_index,
        context.plan_candidate_authorization,
        context.candidate_terminal_authorization,
        context.sealed_candidate_terminal_index,
    )
    _validate_result_evidence_identity(
        context.snapshot,
        state_index,
        context.plan_candidate_authorization,
        context.candidate_terminal_authorization,
        context.sealed_candidate_terminal_index,
        context.sealed_result_evidence_set,
        context.sealed_candidate_execution_disposition,
    )
    return "candidate-terminal-prefix-and-complete-coverage/2"


def _rule_candidate_execution_disposition(context: _RunArtifactRuleContext) -> str:
    if context.snapshot["current_state"] == "MANIFEST_SEALED":
        evidence = context.sealed_result_evidence_set
        disposition = context.sealed_candidate_execution_disposition
        from ebm_audit.results.persistence import SealedResultEvidenceSet

        if type(evidence) is not SealedResultEvidenceSet:
            raise _fail("RUN.RESULT_EVIDENCE_REQUIRED")
        if type(disposition) is not SealedCandidateExecutionDisposition:
            raise _fail("RUN.CANDIDATE_EXECUTION_DISPOSITION_REQUIRED")
        _validate_candidate_execution_record(
            context.snapshot,
            evidence,
            disposition,
        )
    return "candidate-execution-disposition-derived-from-exact-result-evidence/1"


def _rule_manifest_run_gate(context: _RunArtifactRuleContext) -> str:
    if context.snapshot["current_state"] == "MANIFEST_SEALED":
        capability = context.verified_baseline_assessment
        evidence = context.sealed_result_evidence_set
        if type(capability) is not VerifiedBaselineAssessment:
            raise _fail("RUN.BASELINE_VERIFICATION_REQUIRED")
        from ebm_audit.results.persistence import SealedResultEvidenceSet

        if type(evidence) is not SealedResultEvidenceSet:
            raise _fail("RUN.RESULT_EVIDENCE_REQUIRED")
        _validate_baseline_evidence_identity(capability, evidence)
        raise _fail("RUN.RUN_GATE_DISPOSITION_REQUIRED")
    return "manifest-requires-exact-run-gate-disposition/1"


def _rule_registry_digest(context: _RunArtifactRuleContext) -> str:
    expected = exact_file_sha256(context.lifecycle_registry_bytes)
    if context.snapshot["cli_lifecycle_registry_digest"] != expected:
        raise _fail("RUN.LIFECYCLE_REGISTRY_IDENTITY")
    return "cli-lifecycle-registry-exact-resource-digest/1"


def _rule_manifest_is_last(context: _RunArtifactRuleContext) -> str:
    _validate_manifest_is_last(context.snapshot)
    return "manifest-is-last/1"


def _rule_no_private_fields(context: _RunArtifactRuleContext) -> str:
    try:
        assert_no_direct_identifier_fields(context.snapshot)
    except PrivacyViolationError:
        raise _fail("RUN.PRIVACY_FIELD") from None
    return "no-private-path-participant-or-raw-value-fields/1"


_RunArtifactRuleHandler = Callable[[_RunArtifactRuleContext], str]
_RUN_ARTIFACT_RULE_HANDLERS: tuple[
    tuple[str, _RunArtifactRuleHandler],
    ...,
] = (
    ("run-state-history-is-exact-prefix/1", _rule_history),
    ("run-state-artifact-availability/1", _rule_artifact_availability),
    ("candidate-terminal-prefix-and-complete-coverage/2", _rule_candidate_coverage),
    (
        "candidate-execution-disposition-derived-from-exact-result-evidence/1",
        _rule_candidate_execution_disposition,
    ),
    (
        "manifest-requires-exact-run-gate-disposition/1",
        _rule_manifest_run_gate,
    ),
    (
        "cli-lifecycle-registry-exact-resource-digest/1",
        _rule_registry_digest,
    ),
    ("manifest-is-last/1", _rule_manifest_is_last),
    (
        "no-private-path-participant-or-raw-value-fields/1",
        _rule_no_private_fields,
    ),
)


def _load_run_artifact_invariant_rows(
    lifecycle_registry_bytes: bytes,
) -> tuple[Mapping[str, Any], ...]:
    try:
        registry = json.loads(lifecycle_registry_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _fail("RUN.LIFECYCLE_RULE_CLOSURE") from None
    if not isinstance(registry, Mapping):
        raise _fail("RUN.LIFECYCLE_RULE_CLOSURE")
    raw_rows = registry.get("run_artifact_invariant_registry")
    if not isinstance(raw_rows, list) or any(not isinstance(row, Mapping) for row in raw_rows):
        raise _fail("RUN.LIFECYCLE_RULE_CLOSURE")
    return tuple(cast(Mapping[str, Any], row) for row in raw_rows)


def _validate_rule_closure(rows: Sequence[Mapping[str, Any]]) -> None:
    handlers = _RUN_ARTIFACT_RULE_HANDLERS
    handler_ids = tuple(invariant_id for invariant_id, _handler in handlers)
    registry_ids = tuple(row.get("invariant_id") for row in rows)
    expected_ids = tuple(row[0] for row in _EXPECTED_RUN_ARTIFACT_RULE_METADATA)
    if (
        handler_ids != expected_ids
        or registry_ids != handler_ids
        or len(set(handler_ids)) != len(handler_ids)
        or any(not callable(handler) for _invariant_id, handler in handlers)
    ):
        raise _fail("RUN.LIFECYCLE_RULE_CLOSURE")

    for row, (invariant_id, enforcement_kind, baseline_required) in zip(
        rows,
        _EXPECTED_RUN_ARTIFACT_RULE_METADATA,
        strict=True,
    ):
        if (
            set(row) != _RUN_ARTIFACT_RULE_FIELDS
            or row["invariant_id"] != invariant_id
            or row["owner_schema_ref"] != _RUN_ARTIFACT_OWNER_SCHEMA_REF
            or row["enforcement_kind"] not in _RUN_ARTIFACT_ENFORCEMENT_KINDS
            or row["enforcement_kind"] != enforcement_kind
            or row["required"] is not True
            or row["requires_verified_baseline_assessment"] is not baseline_required
        ):
            raise _fail("RUN.LIFECYCLE_RULE_CLOSURE")


def _dispatch_run_artifact_rules(
    snapshot: Mapping[str, Any],
    lifecycle_registry_bytes: bytes,
    plan_candidate_authorization: PlanCandidateAuthorization | None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition | None,
    verified_baseline_assessment: VerifiedBaselineAssessment | None,
) -> None:
    rows = _load_run_artifact_invariant_rows(lifecycle_registry_bytes)
    _validate_rule_closure(rows)
    context = _RunArtifactRuleContext(
        snapshot=snapshot,
        lifecycle_registry_bytes=lifecycle_registry_bytes,
        plan_candidate_authorization=plan_candidate_authorization,
        candidate_terminal_authorization=candidate_terminal_authorization,
        sealed_candidate_terminal_index=sealed_candidate_terminal_index,
        sealed_result_evidence_set=sealed_result_evidence_set,
        sealed_candidate_execution_disposition=sealed_candidate_execution_disposition,
        verified_baseline_assessment=verified_baseline_assessment,
    )
    execution_receipts: list[str] = []
    for row, (invariant_id, handler) in zip(
        rows,
        _RUN_ARTIFACT_RULE_HANDLERS,
        strict=True,
    ):
        if (
            row["requires_verified_baseline_assessment"] is True
            and snapshot["current_state"] == "MANIFEST_SEALED"
            and type(verified_baseline_assessment) is not VerifiedBaselineAssessment
        ):
            raise _fail("RUN.BASELINE_VERIFICATION_REQUIRED")
        try:
            receipt = handler(context)
        except ConfigContractError:
            raise
        except Exception:
            raise _fail("RUN.LIFECYCLE_RULE_EXECUTION") from None
        if receipt != invariant_id:
            raise _fail("RUN.LIFECYCLE_RULE_EXECUTION")
        execution_receipts.append(receipt)
    if tuple(execution_receipts) != tuple(row["invariant_id"] for row in rows):
        raise _fail("RUN.LIFECYCLE_RULE_EXECUTION")


def _validate_run_artifact_inner(
    snapshot: Mapping[str, Any],
    *,
    plan_candidate_authorization: PlanCandidateAuthorization | None = None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None = None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None = None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None = None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition
    | None = None,
    verified_baseline_assessment: VerifiedBaselineAssessment | None = None,
) -> None:
    """Validate one run snapshot against schema and executable invariants."""

    value = cast(dict[str, Any], dict(snapshot))
    schema_invalid = False
    try:
        validate_instance(value, "run-artifacts.schema.json", definition="RunArtifactState")
    except SchemaValidationError:
        schema_invalid = True
    if schema_invalid:
        raise _fail("RUN.SCHEMA")
    try:
        lifecycle_registry_bytes = resource_bytes("cli-lifecycle-registry.json")
        verify_lifecycle_registry(lifecycle_registry_bytes)
    except (LifecycleInputError, ResourceNotFoundError):
        raise _fail("RUN.LIFECYCLE_REGISTRY_RESOURCE") from None
    _dispatch_run_artifact_rules(
        value,
        lifecycle_registry_bytes,
        plan_candidate_authorization,
        candidate_terminal_authorization,
        sealed_candidate_terminal_index,
        sealed_result_evidence_set,
        sealed_candidate_execution_disposition,
        verified_baseline_assessment,
    )


def _try_validate_run_artifact(
    snapshot: Mapping[str, Any],
    plan_candidate_authorization: PlanCandidateAuthorization | None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition | None,
    verified_baseline_assessment: VerifiedBaselineAssessment | None,
) -> object:
    try:
        _validate_run_artifact_inner(
            snapshot,
            plan_candidate_authorization=plan_candidate_authorization,
            candidate_terminal_authorization=candidate_terminal_authorization,
            sealed_candidate_terminal_index=sealed_candidate_terminal_index,
            sealed_result_evidence_set=sealed_result_evidence_set,
            sealed_candidate_execution_disposition=sealed_candidate_execution_disposition,
            verified_baseline_assessment=verified_baseline_assessment,
        )
        return _RUN_ARTIFACT_VALIDATION_SUCCESS
    except ConfigContractError as rejected:
        return _closed_run_rejection_code(rejected)
    except BaseException as stopped:
        return _sanitize_run_boundary_exception(stopped)


def validate_run_artifact(
    snapshot: Mapping[str, Any],
    *,
    plan_candidate_authorization: PlanCandidateAuthorization | None = None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None = None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None = None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None = None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition
    | None = None,
    verified_baseline_assessment: VerifiedBaselineAssessment | None = None,
) -> None:
    """Validate a snapshot through a total privacy-safe public boundary."""

    try:
        outcome: object = _try_validate_run_artifact(
            snapshot,
            plan_candidate_authorization,
            candidate_terminal_authorization,
            sealed_candidate_terminal_index,
            sealed_result_evidence_set,
            sealed_candidate_execution_disposition,
            verified_baseline_assessment,
        )
    except BaseException as stopped:
        outcome = _sanitize_run_boundary_exception(stopped)
    finally:
        del snapshot
        del plan_candidate_authorization
        del candidate_terminal_authorization
        del sealed_candidate_terminal_index
        del sealed_result_evidence_set
        del sealed_candidate_execution_disposition
        del verified_baseline_assessment
    try:
        safe_outcome = _normalize_run_boundary_outcome(outcome)
    except BaseException as stopped:
        safe_outcome = _sanitize_run_boundary_exception(stopped)
    finally:
        del outcome
    _finish_run_validation_boundary(safe_outcome)


def _validate_append_only_transition_inner(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    plan_candidate_authorization: PlanCandidateAuthorization | None = None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None = None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None = None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None = None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition
    | None = None,
    verified_baseline_assessment: VerifiedBaselineAssessment | None = None,
) -> None:
    """Validate that one valid snapshot only appends accepted run evidence."""

    _validate_run_artifact_inner(
        previous,
        plan_candidate_authorization=plan_candidate_authorization,
        candidate_terminal_authorization=candidate_terminal_authorization,
        sealed_candidate_terminal_index=sealed_candidate_terminal_index,
        sealed_result_evidence_set=sealed_result_evidence_set,
        sealed_candidate_execution_disposition=sealed_candidate_execution_disposition,
        verified_baseline_assessment=verified_baseline_assessment,
    )
    _validate_run_artifact_inner(
        current,
        plan_candidate_authorization=plan_candidate_authorization,
        candidate_terminal_authorization=candidate_terminal_authorization,
        sealed_candidate_terminal_index=sealed_candidate_terminal_index,
        sealed_result_evidence_set=sealed_result_evidence_set,
        sealed_candidate_execution_disposition=sealed_candidate_execution_disposition,
        verified_baseline_assessment=verified_baseline_assessment,
    )
    previous_index = RUN_STATES.index(cast(str, previous["current_state"]))
    current_index = RUN_STATES.index(cast(str, current["current_state"]))
    if current_index not in {previous_index, previous_index + 1}:
        raise _fail("RUN.NON_ADJACENT_TRANSITION")
    if current_index == previous_index and current_index != RUN_STATES.index("EXECUTING"):
        if previous != current:
            raise _fail("RUN.SAME_STATE_MUTATION")
        return
    previous_history = list(cast(Sequence[Mapping[str, Any]], previous["state_history"]))
    current_history = list(cast(Sequence[Mapping[str, Any]], current["state_history"]))
    if current_history[: len(previous_history)] != previous_history:
        raise _fail("RUN.HISTORY_MUTATED")
    for field in (
        "run_artifact_schema_version",
        "run_id",
        "cli_lifecycle_registry_version",
        "cli_lifecycle_registry_digest",
        "identity",
        "planned_candidates",
    ):
        if previous[field] != current[field]:
            if field == "identity" and previous_index < 2 <= current_index:
                previous_identity = dict(cast(Mapping[str, Any], previous[field]))
                current_identity = dict(cast(Mapping[str, Any], current[field]))
                previous_identity["plan_digest"] = current_identity["plan_digest"]
                if previous_identity == current_identity:
                    continue
            if (
                field == "planned_candidates"
                and previous_index < 2 <= current_index
                and previous[field] == []
            ):
                continue
            raise _fail("RUN.IMMUTABLE_IDENTITY_MUTATED")
    previous_terminals = list(cast(Sequence[Mapping[str, Any]], previous["candidate_terminals"]))
    current_terminals = list(cast(Sequence[Mapping[str, Any]], current["candidate_terminals"]))
    if current_terminals[: len(previous_terminals)] != previous_terminals:
        raise _fail("RUN.TERMINAL_LEDGER_MUTATED")
    previous_artifacts = cast(Mapping[str, Any], previous["artifact_digests"])
    current_artifacts = cast(Mapping[str, Any], current["artifact_digests"])
    if any(
        previous_artifacts[field] is not None
        and previous_artifacts[field] != current_artifacts[field]
        for field in _ARTIFACT_FIELDS
    ):
        raise _fail("RUN.ARTIFACT_DIGEST_MUTATED")


def _try_validate_append_only_transition(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    plan_candidate_authorization: PlanCandidateAuthorization | None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition | None,
    verified_baseline_assessment: VerifiedBaselineAssessment | None,
) -> object:
    try:
        _validate_append_only_transition_inner(
            previous,
            current,
            plan_candidate_authorization=plan_candidate_authorization,
            candidate_terminal_authorization=candidate_terminal_authorization,
            sealed_candidate_terminal_index=sealed_candidate_terminal_index,
            sealed_result_evidence_set=sealed_result_evidence_set,
            sealed_candidate_execution_disposition=sealed_candidate_execution_disposition,
            verified_baseline_assessment=verified_baseline_assessment,
        )
        return _RUN_ARTIFACT_VALIDATION_SUCCESS
    except ConfigContractError as rejected:
        return _closed_run_rejection_code(rejected)
    except BaseException as stopped:
        return _sanitize_run_boundary_exception(stopped)


def validate_append_only_transition(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    plan_candidate_authorization: PlanCandidateAuthorization | None = None,
    candidate_terminal_authorization: CandidateTerminalAuthorization | None = None,
    sealed_candidate_terminal_index: SealedCandidateTerminalIndex | None = None,
    sealed_result_evidence_set: SealedResultEvidenceSet | None = None,
    sealed_candidate_execution_disposition: SealedCandidateExecutionDisposition
    | None = None,
    verified_baseline_assessment: VerifiedBaselineAssessment | None = None,
) -> None:
    """Validate an append-only transition without retaining rejected inputs."""

    try:
        outcome: object = _try_validate_append_only_transition(
            previous,
            current,
            plan_candidate_authorization,
            candidate_terminal_authorization,
            sealed_candidate_terminal_index,
            sealed_result_evidence_set,
            sealed_candidate_execution_disposition,
            verified_baseline_assessment,
        )
    except BaseException as stopped:
        outcome = _sanitize_run_boundary_exception(stopped)
    finally:
        del previous
        del current
        del plan_candidate_authorization
        del candidate_terminal_authorization
        del sealed_candidate_terminal_index
        del sealed_result_evidence_set
        del sealed_candidate_execution_disposition
        del verified_baseline_assessment
    try:
        safe_outcome = _normalize_run_boundary_outcome(outcome)
    except BaseException as stopped:
        safe_outcome = _sanitize_run_boundary_exception(stopped)
    finally:
        del outcome
    _finish_run_validation_boundary(safe_outcome)
