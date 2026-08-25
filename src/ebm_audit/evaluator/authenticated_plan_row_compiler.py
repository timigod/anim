"""Evaluator-private authenticated direct-operation-plan compiler."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from threading import Lock, RLock
from typing import Literal, Never, cast, final

from ebm_audit._capability_registry import OneShotWeakRegistry, create_one_shot_registry
from ebm_audit.adapters.invocation import normalize_worker_timeout_seconds
from ebm_audit.config.verification import (
    VerifiedAuditConfigFiles,
    _read_verified_source_config_binding,
)
from ebm_audit.evaluator.heldout_score import (
    DirectOperationPlanEntry,
    _direct_operation_plan_digest,
)
from ebm_audit.evaluator.operation_matrix import _authenticate_existing_plan_operation_matrix
from ebm_audit.evaluator.scenario_case_batch import (
    AuthenticatedScenarioCaseBatch,
    _read_authenticated_batch_context,
)
from ebm_audit.protocol import structured_sha256_hex
from ebm_audit.reporting._report_model_artifact_binding import (
    AuthenticatedReportModelArtifactBinding,
    _validated_binding_projection,
)
from ebm_audit.science import CapturedScientificRun, SealedScientificEvidence
from ebm_audit.science.capture import (
    _read_captured_scientific_run,
    _read_sealed_scientific_evidence,
)
from ebm_audit.universe.planning import PlanningAuthority
from ebm_audit.universe.preparation import (
    CandidateResultAuthorization,
    PreparationTransaction,
    PreparedExecutionAuthorization,
    UnpreparedResultAuthorization,
)

_COMPILE_RECEIPT_DOMAIN = "ebm-audit/authenticated-plan-row-compile-receipt/1"
_SCIENCE_BINDING_RECEIPT_DOMAIN = (
    "ebm-audit/authenticated-plan-row-science-binding-receipt/1"
)
_BINDING_RECEIPT_DOMAIN = "ebm-audit/authenticated-plan-row-binding-receipt/1"
_COMPILER_TRANSACTION_DOMAIN = "ebm-audit/heldout-compiler-transaction/1"
_PLANNING_AUTHORITY_IDENTITY_DOMAIN = "ebm-audit/planning-authority-binding/1"
_PREPARATION_TRANSACTION_IDENTITY_DOMAIN = "ebm-audit/preparation-transaction-binding/1"
_CAPTURED_SCIENTIFIC_RUN_IDENTITY_DOMAIN = "ebm-audit/captured-scientific-run-binding/1"


@dataclass(frozen=True, slots=True)
class AuthenticatedPlanRowCompileReceipt:
    schema_version: Literal["ebm-audit-authenticated-plan-row-compile-receipt/1.0"]
    heldout_attempt_id: str
    benchmark_subject_digest: str
    compiler_transaction_id: str
    source_config_digest: str
    profile_id: str
    timeout_seconds: float
    ordered_analysis_spec_ids: tuple[str, ...]
    authenticated_case_batch_sha256: str
    compiled_plan_sha256: str
    compile_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class AuthenticatedPlanRowBindingReceipt:
    schema_version: Literal["ebm-audit-authenticated-plan-row-binding-receipt/1.0"]
    compile_receipt_sha256: str
    planning_authority_identity_sha256: str
    preparation_transaction_identity_sha256: str
    captured_scientific_run_sha256: str
    sealed_scientific_evidence_sha256: str
    report_model_artifact_binding_sha256: str
    binding_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class AuthenticatedPlanRowScienceBindingReceipt:
    schema_version: Literal[
        "ebm-audit-authenticated-plan-row-science-binding-receipt/1.0"
    ]
    compile_receipt_sha256: str
    planning_authority_identity_sha256: str
    preparation_transaction_identity_sha256: str
    captured_scientific_run_sha256: str
    sealed_scientific_evidence_sha256: str
    science_binding_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class _IssueContextState:
    source_owner: object
    heldout_attempt_id: str
    benchmark_subject_digest: str
    revalidate: Callable[[object], tuple[str, str]]


@dataclass(slots=True)
class _CompiledPlanState:
    issue_context: AuthenticatedPlanCompilerIssueContext
    batch: AuthenticatedScenarioCaseBatch
    verified_files: VerifiedAuditConfigFiles
    source_config_bytes: bytes
    planning_authority: PlanningAuthority
    preparation_transaction: PreparationTransaction
    authorizations: tuple[PreparedExecutionAuthorization, ...]
    candidate_authorizations: tuple[CandidateResultAuthorization, ...]
    compile_mode: Literal["PREPARED", "UNPREPARED_PUBLIC_TRUTH"]
    rows: tuple[DirectOperationPlanEntry, ...]
    receipt: AuthenticatedPlanRowCompileReceipt
    science_binding_receipt: AuthenticatedPlanRowScienceBindingReceipt | None
    binding_receipt: AuthenticatedPlanRowBindingReceipt | None
    status: Literal["COMPILED", "SCIENCE_BOUND", "BOUND", "CONSUMED"]
    lock: RLock


@final
class AuthenticatedPlanCompilerIssueContext:
    """Opaque retained issue-open context accepted by the compiler."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Never:
        raise TypeError("Plan compiler issue contexts are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Plan compiler issue contexts cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Plan compiler issue contexts are immutable.")


@final
class AuthenticatedDirectOperationPlan:
    """Opaque one-shot owner of compiler-derived direct operation rows."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Never:
        raise TypeError("Authenticated direct operation plans are privately compiled.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Authenticated direct operation plans cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Authenticated direct operation plans are immutable.")


_ISSUE_CONTEXT_STATES: OneShotWeakRegistry[
    AuthenticatedPlanCompilerIssueContext, _IssueContextState
]
_ISSUE_CONTEXT_STATES, _ISSUE_CONTEXT_STATE_ISSUER = create_one_shot_registry()
_PLAN_STATES: OneShotWeakRegistry[AuthenticatedDirectOperationPlan, _CompiledPlanState]
_PLAN_STATES, _PLAN_STATE_ISSUER = create_one_shot_registry()
_ISSUER_CLAIM_LOCK = Lock()
_ISSUER_CLAIMED = False


def _claim_plan_compiler_issue_context_issuer(
    *,
    owner_types: tuple[type[object], ...],
    read_context: Callable[[object], tuple[str, str]],
) -> Callable[[object], AuthenticatedPlanCompilerIssueContext]:
    """Give the evaluator runner the sole issue-context boundary."""

    global _ISSUER_CLAIMED
    if (
        type(owner_types) is not tuple
        or not owner_types
        or any(type(owner_type) is not type for owner_type in owner_types)
        or not callable(read_context)
    ):
        raise TypeError("The plan compiler issuer claim is invalid.")
    with _ISSUER_CLAIM_LOCK:
        if _ISSUER_CLAIMED:
            raise TypeError("The plan compiler issuer was already claimed.")
        _ISSUER_CLAIMED = True

    def issue(source_owner: object) -> AuthenticatedPlanCompilerIssueContext:
        if type(source_owner) not in owner_types:
            raise TypeError("The plan compiler source owner is invalid.")
        heldout_attempt_id, benchmark_subject_digest = read_context(source_owner)
        if not all(
            type(value) is str and value
            for value in (heldout_attempt_id, benchmark_subject_digest)
        ):
            raise TypeError("The plan compiler issue context is invalid.")
        owner: AuthenticatedPlanCompilerIssueContext = object.__new__(
            AuthenticatedPlanCompilerIssueContext  # type: ignore[arg-type]
        )
        _ISSUE_CONTEXT_STATE_ISSUER.bind_once(
            owner,
            _IssueContextState(
                source_owner=source_owner,
                heldout_attempt_id=heldout_attempt_id,
                benchmark_subject_digest=benchmark_subject_digest,
                revalidate=read_context,
            ),
        )
        return owner

    return issue


def _read_issue_context(
    owner: AuthenticatedPlanCompilerIssueContext,
) -> _IssueContextState:
    if type(owner) is not AuthenticatedPlanCompilerIssueContext:
        raise TypeError("A genuine plan compiler issue context is required.")
    state = _ISSUE_CONTEXT_STATES.read(owner)
    observed = state.revalidate(state.source_owner)
    if observed != (state.heldout_attempt_id, state.benchmark_subject_digest):
        raise TypeError("The plan compiler issue context is detached.")
    return state


def _receipt_projection(
    receipt: (
        AuthenticatedPlanRowCompileReceipt
        | AuthenticatedPlanRowScienceBindingReceipt
        | AuthenticatedPlanRowBindingReceipt
    ),
    digest_field: str,
) -> dict[str, object]:
    projection = asdict(receipt)
    projection[digest_field] = None
    if "ordered_analysis_spec_ids" in projection:
        projection["ordered_analysis_spec_ids"] = list(
            projection["ordered_analysis_spec_ids"]
        )
    return projection


def _same_authorizations(
    supplied: tuple[PreparedExecutionAuthorization, ...],
    authenticated: tuple[PreparedExecutionAuthorization, ...],
) -> bool:
    return type(supplied) is tuple and len(supplied) == len(authenticated) and all(
        left is right for left, right in zip(supplied, authenticated, strict=True)
    )


def _same_candidate_authorizations(
    supplied: tuple[CandidateResultAuthorization, ...],
    authenticated: tuple[CandidateResultAuthorization, ...],
) -> bool:
    return type(supplied) is tuple and len(supplied) == len(authenticated) and all(
        left is right for left, right in zip(supplied, authenticated, strict=True)
    )


def _is_exact_unprepared_public_truth_candidate(
    authorizations: tuple[CandidateResultAuthorization, ...],
) -> bool:
    if len(authorizations) != 1:
        return False
    authorization = authorizations[0]
    return (
        type(authorization) is UnpreparedResultAuthorization
        and authorization.preparation_state == "PREPARATION_UNSUPPORTED"
        and authorization.terminal_status == "UNSUPPORTED_CAPABILITY"
        and authorization.preparation_reasons
        == (
            {
                "reason_code": "PREPARATION.COMPLETE_CASE_ROW_LOSS_UNSUPPORTED",
                "rule_id": "preparation.capability/1",
            },
        )
    )


def _compile_authenticated_plan_rows_impl(
    issue_context: AuthenticatedPlanCompilerIssueContext,
    batch: AuthenticatedScenarioCaseBatch,
    verified_files: VerifiedAuditConfigFiles,
    planning_authority: PlanningAuthority,
    preparation_transaction: PreparationTransaction,
    authorizations: tuple[PreparedExecutionAuthorization, ...],
    *,
    profile_id: str,
    timeout_seconds: float,
    allow_unprepared_public_truth: bool,
) -> AuthenticatedDirectOperationPlan:
    """Compile one exact plan after Plan/3 preparation and before first Fit."""

    issue_state = _read_issue_context(issue_context)
    if type(batch) is not AuthenticatedScenarioCaseBatch:
        raise TypeError("A genuine authenticated scenario case batch is required.")
    context = _read_authenticated_batch_context(batch)
    if context.benchmark_subject_digest != issue_state.benchmark_subject_digest:
        raise TypeError("The scenario batch is detached from the issue-open context.")
    source = _read_verified_source_config_binding(verified_files)
    profiles = source.resolved.private_config.get("profiles")
    if (
        type(profile_id) is not str
        or type(profiles) is not dict
        or profile_id not in profiles
        or type(planning_authority) is not PlanningAuthority
        or planning_authority.profile_id != profile_id
    ):
        raise TypeError("The compiler profile is not authenticated.")
    normalized_timeout = normalize_worker_timeout_seconds(timeout_seconds)
    authenticated = _authenticate_existing_plan_operation_matrix(
        planning_authority,
        preparation_transaction,
    )
    transaction_candidates = preparation_transaction.candidate_authorizations
    if not _same_authorizations(authorizations, authenticated):
        raise TypeError("The compiler preparation authorizations are invalid.")
    if allow_unprepared_public_truth:
        if authenticated or not _is_exact_unprepared_public_truth_candidate(
            transaction_candidates
        ):
            raise TypeError("The compiler unprepared truth authorization is invalid.")
        candidate_authorizations = transaction_candidates
        compile_mode: Literal[
            "PREPARED", "UNPREPARED_PUBLIC_TRUTH"
        ] = "UNPREPARED_PUBLIC_TRUTH"
    else:
        if not authenticated:
            raise TypeError("The compiler preparation authorizations are invalid.")
        candidate_authorizations = cast(
            tuple[CandidateResultAuthorization, ...],
            authenticated,
        )
        compile_mode = "PREPARED"
    analysis_spec_ids = tuple(
        owner.analysis_spec_id for owner in candidate_authorizations
    )
    if len(set(analysis_spec_ids)) != len(analysis_spec_ids):
        raise TypeError("Analysis specification identities must be unique.")
    rows = tuple(
        DirectOperationPlanEntry(
            operation_ordinal=ordinal,
            operation_kind="scenario",
            family_id=case.family_id,
            evidence_kind="public-synthetic-truth-validation/1",
        )
        for ordinal, case in enumerate(context.cases)
    )
    if not rows:
        raise TypeError("The authenticated case batch is empty.")
    compiled_plan_sha256 = _direct_operation_plan_digest(rows)
    compiler_transaction_id = structured_sha256_hex(
        _COMPILER_TRANSACTION_DOMAIN,
        {
            "heldout_attempt_id": issue_state.heldout_attempt_id,
            "benchmark_subject_digest": issue_state.benchmark_subject_digest,
            "source_config_digest": source.byte_digest,
            "profile_id": profile_id,
            "timeout_seconds": normalized_timeout,
            "ordered_analysis_spec_ids": list(analysis_spec_ids),
            "authenticated_case_batch_sha256": batch.digest,
            "compiled_plan_sha256": compiled_plan_sha256,
        },
    )
    projection: dict[str, object] = {
        "schema_version": "ebm-audit-authenticated-plan-row-compile-receipt/1.0",
        "heldout_attempt_id": issue_state.heldout_attempt_id,
        "benchmark_subject_digest": issue_state.benchmark_subject_digest,
        "compiler_transaction_id": compiler_transaction_id,
        "source_config_digest": source.byte_digest,
        "profile_id": profile_id,
        "timeout_seconds": normalized_timeout,
        "ordered_analysis_spec_ids": analysis_spec_ids,
        "authenticated_case_batch_sha256": batch.digest,
        "compiled_plan_sha256": compiled_plan_sha256,
        "compile_receipt_sha256": "",
    }
    hash_projection = dict(projection)
    hash_projection["ordered_analysis_spec_ids"] = list(analysis_spec_ids)
    hash_projection["compile_receipt_sha256"] = None
    projection["compile_receipt_sha256"] = structured_sha256_hex(
        _COMPILE_RECEIPT_DOMAIN,
        hash_projection,
    )
    receipt = AuthenticatedPlanRowCompileReceipt(**projection)  # type: ignore[arg-type]
    owner: AuthenticatedDirectOperationPlan = object.__new__(
        AuthenticatedDirectOperationPlan  # type: ignore[arg-type]
    )
    _PLAN_STATE_ISSUER.bind_once(
        owner,
        _CompiledPlanState(
            issue_context=issue_context,
            batch=batch,
            verified_files=verified_files,
            source_config_bytes=source.exact_bytes,
            planning_authority=planning_authority,
            preparation_transaction=preparation_transaction,
            authorizations=authenticated,
            candidate_authorizations=candidate_authorizations,
            compile_mode=compile_mode,
            rows=rows,
            receipt=receipt,
            science_binding_receipt=None,
            binding_receipt=None,
            status="COMPILED",
            lock=RLock(),
        ),
    )
    return owner


def _compile_authenticated_plan_rows(
    issue_context: AuthenticatedPlanCompilerIssueContext,
    batch: AuthenticatedScenarioCaseBatch,
    verified_files: VerifiedAuditConfigFiles,
    planning_authority: PlanningAuthority,
    preparation_transaction: PreparationTransaction,
    authorizations: tuple[PreparedExecutionAuthorization, ...],
    *,
    profile_id: str,
    timeout_seconds: float,
) -> AuthenticatedDirectOperationPlan:
    """Compile an exact ordinary plan that has at least one prepared candidate."""

    return _compile_authenticated_plan_rows_impl(
        issue_context,
        batch,
        verified_files,
        planning_authority,
        preparation_transaction,
        authorizations,
        profile_id=profile_id,
        timeout_seconds=timeout_seconds,
        allow_unprepared_public_truth=False,
    )


def _compile_authenticated_unprepared_truth_plan_rows(
    issue_context: AuthenticatedPlanCompilerIssueContext,
    batch: AuthenticatedScenarioCaseBatch,
    verified_files: VerifiedAuditConfigFiles,
    planning_authority: PlanningAuthority,
    preparation_transaction: PreparationTransaction,
    authorizations: tuple[PreparedExecutionAuthorization, ...],
    *,
    profile_id: str,
    timeout_seconds: float,
) -> AuthenticatedDirectOperationPlan:
    """Compile rows only for one exact complete-case typed-unavailable candidate."""

    return _compile_authenticated_plan_rows_impl(
        issue_context,
        batch,
        verified_files,
        planning_authority,
        preparation_transaction,
        authorizations,
        profile_id=profile_id,
        timeout_seconds=timeout_seconds,
        allow_unprepared_public_truth=True,
    )


def _validate_compiled_state(
    owner: AuthenticatedDirectOperationPlan,
) -> _CompiledPlanState:
    if type(owner) is not AuthenticatedDirectOperationPlan:
        raise TypeError("A genuine authenticated direct operation plan is required.")
    state = _PLAN_STATES.read(owner)
    issue_state = _read_issue_context(state.issue_context)
    context = _read_authenticated_batch_context(state.batch)
    source = _read_verified_source_config_binding(state.verified_files)
    authenticated = _authenticate_existing_plan_operation_matrix(
        state.planning_authority,
        state.preparation_transaction,
    )
    transaction_candidates = state.preparation_transaction.candidate_authorizations
    if state.compile_mode == "PREPARED":
        candidate_authorizations = cast(
            tuple[CandidateResultAuthorization, ...],
            authenticated,
        )
        compile_mode_valid = bool(authenticated)
    elif state.compile_mode == "UNPREPARED_PUBLIC_TRUTH":
        candidate_authorizations = transaction_candidates
        compile_mode_valid = not authenticated and (
            _is_exact_unprepared_public_truth_candidate(candidate_authorizations)
        )
    else:
        candidate_authorizations = ()
        compile_mode_valid = False
    analysis_spec_ids = tuple(item.analysis_spec_id for item in candidate_authorizations)
    expected_rows = tuple(
        DirectOperationPlanEntry(
            operation_ordinal=ordinal,
            operation_kind="scenario",
            family_id=case.family_id,
            evidence_kind="public-synthetic-truth-validation/1",
        )
        for ordinal, case in enumerate(context.cases)
    )
    receipt = state.receipt
    science_binding_receipt = state.science_binding_receipt
    binding_receipt = state.binding_receipt
    science_binding_receipt_valid = (
        type(science_binding_receipt) is AuthenticatedPlanRowScienceBindingReceipt
        and science_binding_receipt.compile_receipt_sha256
        == receipt.compile_receipt_sha256
        and science_binding_receipt.science_binding_receipt_sha256
        == structured_sha256_hex(
            _SCIENCE_BINDING_RECEIPT_DOMAIN,
            _receipt_projection(
                science_binding_receipt,
                "science_binding_receipt_sha256",
            ),
        )
    )
    if (
        not science_binding_receipt_valid
        or type(binding_receipt) is not AuthenticatedPlanRowBindingReceipt
    ):
        binding_receipt_valid = False
    else:
        science_binding = cast(
            AuthenticatedPlanRowScienceBindingReceipt,
            science_binding_receipt,
        )
        binding_receipt_valid = (
            binding_receipt.compile_receipt_sha256 == receipt.compile_receipt_sha256
            and binding_receipt.planning_authority_identity_sha256
            == science_binding.planning_authority_identity_sha256
            and binding_receipt.preparation_transaction_identity_sha256
            == science_binding.preparation_transaction_identity_sha256
            and binding_receipt.captured_scientific_run_sha256
            == science_binding.captured_scientific_run_sha256
            and binding_receipt.sealed_scientific_evidence_sha256
            == science_binding.sealed_scientific_evidence_sha256
            and binding_receipt.binding_receipt_sha256
            == structured_sha256_hex(
                _BINDING_RECEIPT_DOMAIN,
                _receipt_projection(binding_receipt, "binding_receipt_sha256"),
            )
        )
    lifecycle_valid = (
        (
            state.status == "COMPILED"
            and science_binding_receipt is None
            and binding_receipt is None
        )
        or (
            state.status == "SCIENCE_BOUND"
            and science_binding_receipt_valid
            and binding_receipt is None
        )
        or (state.status in {"BOUND", "CONSUMED"} and binding_receipt_valid)
    )
    expected_compiler_transaction_id = structured_sha256_hex(
        _COMPILER_TRANSACTION_DOMAIN,
        {
            "heldout_attempt_id": issue_state.heldout_attempt_id,
            "benchmark_subject_digest": issue_state.benchmark_subject_digest,
            "source_config_digest": source.byte_digest,
            "profile_id": receipt.profile_id,
            "timeout_seconds": receipt.timeout_seconds,
            "ordered_analysis_spec_ids": list(analysis_spec_ids),
            "authenticated_case_batch_sha256": state.batch.digest,
            "compiled_plan_sha256": _direct_operation_plan_digest(expected_rows),
        },
    )
    if (
        not lifecycle_valid
        or not compile_mode_valid
        or context.benchmark_subject_digest != issue_state.benchmark_subject_digest
        or source.exact_bytes != state.source_config_bytes
        or source.byte_digest != receipt.source_config_digest
        or not _same_authorizations(state.authorizations, authenticated)
        or not _same_candidate_authorizations(
            state.candidate_authorizations,
            candidate_authorizations,
        )
        or state.planning_authority.profile_id != receipt.profile_id
        or analysis_spec_ids != receipt.ordered_analysis_spec_ids
        or state.rows != expected_rows
        or receipt.heldout_attempt_id != issue_state.heldout_attempt_id
        or receipt.benchmark_subject_digest != issue_state.benchmark_subject_digest
        or receipt.compiler_transaction_id != expected_compiler_transaction_id
        or receipt.authenticated_case_batch_sha256 != state.batch.digest
        or receipt.source_config_digest
        != f"sha256:{hashlib.sha256(source.exact_bytes).hexdigest()}"
        or receipt.compiled_plan_sha256 != _direct_operation_plan_digest(state.rows)
        or receipt.compile_receipt_sha256
        != structured_sha256_hex(
            _COMPILE_RECEIPT_DOMAIN,
            _receipt_projection(receipt, "compile_receipt_sha256"),
        )
    ):
        raise TypeError("The authenticated direct operation plan is invalid.")
    return state


def _read_authenticated_plan_rows(
    owner: AuthenticatedDirectOperationPlan,
) -> tuple[DirectOperationPlanEntry, ...]:
    """Return rows only after the post-transaction binding exists."""

    state = _validate_compiled_state(owner)
    if state.status != "BOUND" or state.binding_receipt is None:
        raise TypeError("The authenticated direct operation plan is not bound.")
    return state.rows


def _read_science_bound_authenticated_plan_rows(
    owner: AuthenticatedDirectOperationPlan,
    receipt: AuthenticatedPlanRowScienceBindingReceipt,
) -> tuple[DirectOperationPlanEntry, ...]:
    """Read exact compiled rows only during the authenticated pre-report stage."""

    state = _validate_compiled_state(owner)
    if (
        state.status != "SCIENCE_BOUND"
        or type(receipt) is not AuthenticatedPlanRowScienceBindingReceipt
        or state.science_binding_receipt is not receipt
    ):
        raise TypeError("The authenticated plan-row science binding is detached.")
    return state.rows


def _read_authenticated_plan_row_binding(
    owner: AuthenticatedDirectOperationPlan,
    receipt: AuthenticatedPlanRowBindingReceipt,
) -> tuple[DirectOperationPlanEntry, ...]:
    """Revalidate one exact bound plan and its issued transaction receipt."""

    state = _validate_compiled_state(owner)
    if (
        state.status != "BOUND"
        or type(receipt) is not AuthenticatedPlanRowBindingReceipt
        or state.binding_receipt is not receipt
    ):
        raise TypeError("The authenticated plan-row binding is detached.")
    return state.rows


def _read_authenticated_unprepared_plan_row_binding(
    owner: AuthenticatedDirectOperationPlan,
    receipt: AuthenticatedPlanRowBindingReceipt,
) -> tuple[
    tuple[DirectOperationPlanEntry, ...],
    UnpreparedResultAuthorization,
]:
    """Revalidate one exact typed-unprepared plan, receipt, and result authority."""

    rows = _read_authenticated_plan_row_binding(owner, receipt)
    state = _PLAN_STATES.read(owner)
    if (
        state.compile_mode != "UNPREPARED_PUBLIC_TRUTH"
        or len(state.candidate_authorizations) != 1
        or type(state.candidate_authorizations[0]) is not UnpreparedResultAuthorization
    ):
        raise TypeError("The authenticated unprepared plan-row binding is invalid.")
    return rows, state.candidate_authorizations[0]


def _bind_authenticated_plan_rows_to_science(
    owner: AuthenticatedDirectOperationPlan,
    planning_authority: PlanningAuthority,
    preparation_transaction: PreparationTransaction,
    authorizations: tuple[PreparedExecutionAuthorization, ...],
    captured_scientific_run: CapturedScientificRun,
    sealed_scientific_evidence: SealedScientificEvidence,
) -> AuthenticatedPlanRowScienceBindingReceipt:
    """Bind unchanged compiled rows to authenticated science before reporting."""

    state = _validate_compiled_state(owner)
    if (
        planning_authority is not state.planning_authority
        or preparation_transaction is not state.preparation_transaction
        or not _same_authorizations(authorizations, state.authorizations)
    ):
        raise TypeError("The binding ordinary transaction owners are detached.")
    authenticated = _authenticate_existing_plan_operation_matrix(
        planning_authority,
        preparation_transaction,
    )
    if not _same_authorizations(authorizations, authenticated):
        raise TypeError("The binding preparation authorizations are invalid.")
    binding_authorizations: tuple[CandidateResultAuthorization, ...]
    if state.compile_mode == "PREPARED":
        binding_authorizations = cast(
            tuple[CandidateResultAuthorization, ...],
            authenticated,
        )
    else:
        binding_authorizations = preparation_transaction.candidate_authorizations
        if not _same_candidate_authorizations(
            binding_authorizations,
            state.candidate_authorizations,
        ):
            raise TypeError("The binding result authorizations are invalid.")
    analysis_spec_ids = tuple(item.analysis_spec_id for item in binding_authorizations)
    if analysis_spec_ids != state.receipt.ordered_analysis_spec_ids:
        raise TypeError("The binding analysis specification order is detached.")
    captured = _read_captured_scientific_run(captured_scientific_run)
    sealed = _read_sealed_scientific_evidence(sealed_scientific_evidence)
    if (
        captured.preparation_transaction is not preparation_transaction
        or captured.preparation_receipt_digest != preparation_transaction.receipt_digest
        or sealed.capture is not captured_scientific_run
    ):
        raise TypeError("The binding scientific owner chain is detached.")
    planning_identity = structured_sha256_hex(
        _PLANNING_AUTHORITY_IDENTITY_DOMAIN,
        {
            "planning_summary_id": planning_authority.planning_summary_id,
            "public_intent_manifest_digest": planning_authority.public_intent_manifest_digest,
            "plan_digest": captured.plan_digest,
        },
    )
    preparation_identity = structured_sha256_hex(
        _PREPARATION_TRANSACTION_IDENTITY_DOMAIN,
        {
            "plan_digest": captured.plan_digest,
            "preparation_receipt_digest": preparation_transaction.receipt_digest,
            "ordered_analysis_spec_ids": list(analysis_spec_ids),
        },
    )
    captured_identity = structured_sha256_hex(
        _CAPTURED_SCIENTIFIC_RUN_IDENTITY_DOMAIN,
        {
            "plan_digest": captured.plan_digest,
            "preparation_receipt_digest": captured.preparation_receipt_digest,
            "terminal_index_digest": captured.terminal_index_digest,
        },
    )
    projection: dict[str, object] = {
        "schema_version": (
            "ebm-audit-authenticated-plan-row-science-binding-receipt/1.0"
        ),
        "compile_receipt_sha256": state.receipt.compile_receipt_sha256,
        "planning_authority_identity_sha256": planning_identity,
        "preparation_transaction_identity_sha256": preparation_identity,
        "captured_scientific_run_sha256": captured_identity,
        "sealed_scientific_evidence_sha256": sealed.evidence_digest,
        "science_binding_receipt_sha256": "",
    }
    hash_projection = dict(projection)
    hash_projection["science_binding_receipt_sha256"] = None
    projection["science_binding_receipt_sha256"] = structured_sha256_hex(
        _SCIENCE_BINDING_RECEIPT_DOMAIN,
        hash_projection,
    )
    receipt = AuthenticatedPlanRowScienceBindingReceipt(
        schema_version=(
            "ebm-audit-authenticated-plan-row-science-binding-receipt/1.0"
        ),
        compile_receipt_sha256=cast(str, projection["compile_receipt_sha256"]),
        planning_authority_identity_sha256=cast(
            str,
            projection["planning_authority_identity_sha256"],
        ),
        preparation_transaction_identity_sha256=cast(
            str,
            projection["preparation_transaction_identity_sha256"],
        ),
        captured_scientific_run_sha256=cast(
            str,
            projection["captured_scientific_run_sha256"],
        ),
        sealed_scientific_evidence_sha256=cast(
            str,
            projection["sealed_scientific_evidence_sha256"],
        ),
        science_binding_receipt_sha256=cast(
            str,
            projection["science_binding_receipt_sha256"],
        ),
    )
    with state.lock:
        if (
            state.status != "COMPILED"
            or state.science_binding_receipt is not None
            or state.binding_receipt is not None
        ):
            raise TypeError(
                "The authenticated direct operation plan cannot bind again at the science stage."
            )
        state.science_binding_receipt = receipt
        state.status = "SCIENCE_BOUND"
    return receipt


def _finalize_authenticated_plan_row_report_binding(
    owner: AuthenticatedDirectOperationPlan,
    science_receipt: AuthenticatedPlanRowScienceBindingReceipt,
    report_binding: AuthenticatedReportModelArtifactBinding,
) -> AuthenticatedPlanRowBindingReceipt:
    """Attach one final authenticated report to an exact science-bound plan."""

    state = _validate_compiled_state(owner)
    if (
        state.status != "SCIENCE_BOUND"
        or type(science_receipt) is not AuthenticatedPlanRowScienceBindingReceipt
        or state.science_binding_receipt is not science_receipt
        or state.binding_receipt is not None
    ):
        raise TypeError("The authenticated plan-row science binding is detached.")
    report = _validated_binding_projection(report_binding)
    projection: dict[str, object] = {
        "schema_version": "ebm-audit-authenticated-plan-row-binding-receipt/1.0",
        "compile_receipt_sha256": state.receipt.compile_receipt_sha256,
        "planning_authority_identity_sha256": (
            science_receipt.planning_authority_identity_sha256
        ),
        "preparation_transaction_identity_sha256": (
            science_receipt.preparation_transaction_identity_sha256
        ),
        "captured_scientific_run_sha256": (
            science_receipt.captured_scientific_run_sha256
        ),
        "sealed_scientific_evidence_sha256": (
            science_receipt.sealed_scientific_evidence_sha256
        ),
        "report_model_artifact_binding_sha256": report["binding_sha256"],
        "binding_receipt_sha256": "",
    }
    hash_projection = dict(projection)
    hash_projection["binding_receipt_sha256"] = None
    projection["binding_receipt_sha256"] = structured_sha256_hex(
        _BINDING_RECEIPT_DOMAIN,
        hash_projection,
    )
    receipt = AuthenticatedPlanRowBindingReceipt(**projection)  # type: ignore[arg-type]
    with state.lock:
        if (
            state.status != "SCIENCE_BOUND"
            or state.science_binding_receipt is not science_receipt
            or state.binding_receipt is not None
        ):
            raise TypeError(
                "The authenticated direct operation plan cannot bind again at the report stage."
            )
        state.binding_receipt = receipt
        state.status = "BOUND"
    return receipt


def _bind_authenticated_plan_rows(
    owner: AuthenticatedDirectOperationPlan,
    planning_authority: PlanningAuthority,
    preparation_transaction: PreparationTransaction,
    authorizations: tuple[PreparedExecutionAuthorization, ...],
    captured_scientific_run: CapturedScientificRun,
    sealed_scientific_evidence: SealedScientificEvidence,
    report_binding: AuthenticatedReportModelArtifactBinding,
) -> AuthenticatedPlanRowBindingReceipt:
    """Compatibility wrapper for the former single-stage terminal binding."""

    _validated_binding_projection(report_binding)
    science_receipt = _bind_authenticated_plan_rows_to_science(
        owner,
        planning_authority,
        preparation_transaction,
        authorizations,
        captured_scientific_run,
        sealed_scientific_evidence,
    )
    return _finalize_authenticated_plan_row_report_binding(
        owner,
        science_receipt,
        report_binding,
    )


def _consume_authenticated_plan_rows(
    owner: AuthenticatedDirectOperationPlan,
) -> tuple[DirectOperationPlanEntry, ...]:
    """Consume one bound authenticated plan exactly once at terminal sealing."""

    state = _validate_compiled_state(owner)
    with state.lock:
        if state.status != "BOUND" or state.binding_receipt is None:
            raise TypeError("The authenticated direct operation plan is not bound.")
        rows = state.rows
        state.status = "CONSUMED"
    return rows


__all__: list[str] = []
