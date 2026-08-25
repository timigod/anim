"""Evaluator-owned direct scoring for one sealed synthetic conformance attempt.

The public scorer accepts one opaque sealed owner.  It never accepts paths,
roots, seeds, result vectors, mappings, counts, or caller-built receipt bytes.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Final, Literal, Never, SupportsIndex, cast, final

from ebm_audit.errors import InvalidInputError
from ebm_audit.evaluator.scenario_predicates import (
    ScenarioPredicateResult,
    _validated_result_projection,
)
from ebm_audit.protocol import CanonicalizationError, strict_json_loads
from ebm_audit.protocol.canonical import canonical_json_bytes, structured_sha256_hex

Outcome = Literal["PASS", "WARN", "FAIL"]
Applicability = Literal["APPLICABLE", "NOT_APPLICABLE", "UNAVAILABLE"]

_SEAL_DOMAIN: Final = "ebm-audit/direct-sealed-attempt-authentication/1"
_COMMITMENT_DOMAIN: Final = "ebm-audit/direct-preexecution-commitment-receipt/2"
_PLAN_DOMAIN: Final = "ebm-audit/direct-compiled-plan/1"
_INVENTORY_DOMAIN: Final = "ebm-audit/direct-terminal-evidence-inventory/1"
_SCORE_DOMAIN: Final = "ebm-audit/direct-conformance-score-receipt/1"
_VALIDATION_DOMAIN: Final = "ebm-audit/direct-conformance-validation-receipt/1"
_OWNER_TOKEN: Final = object()
_OUTCOME_RANK: Final = {"PASS": 0, "WARN": 1, "FAIL": 2}
_OUTCOMES: Final[tuple[Outcome, ...]] = ("PASS", "WARN", "FAIL")


class DirectScoreError(RuntimeError):
    """A stable fail-closed rejection without evidence disclosure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Direct sealed-attempt scoring failed: {code}.")


def _reject(code: str) -> Never:
    raise DirectScoreError(code)


def _digest(domain: str, value: object) -> str:
    return structured_sha256_hex(domain, value)


def _direct_operation_plan_digest(
    plan: tuple[DirectOperationPlanEntry, ...],
) -> str:
    """Return the canonical digest of one exact ordered direct operation plan."""

    if type(plan) is not tuple or any(type(row) is not DirectOperationPlanEntry for row in plan):
        _reject("COMPILED_PLAN_INVALID")
    return _digest(_PLAN_DOMAIN, [asdict(row) for row in plan])


@dataclass(frozen=True, slots=True)
class DirectPreexecutionCommitmentReceipt:
    schema_version: Literal["ebm-audit-direct-preexecution-commitment/2.0"]
    mode: Literal["local_offline"]
    subject_kind: Literal["SYNTHETIC_ONLY_CONFORMANCE_EBM"]
    candidate_sha256: str
    benchmark_contract_sha256: str
    scenario_definitions_sha256: str
    supersession_sha256: str
    direct_producer_source_set_sha256: str
    root_commitment_sha256: str
    commitment_receipt_sha256: str
    committed_at_utc: str


@dataclass(frozen=True, slots=True)
class DirectOperationPlanEntry:
    operation_ordinal: int
    operation_kind: str
    family_id: str
    evidence_kind: str


@final
class DirectTerminalEvidence:
    """Opaque terminal bound to one freshly validated scenario result owner."""

    _binding_bytes: bytes
    _evidence_kind: str
    _gate_applicability: Applicability
    _gate_outcome: Outcome
    _operation_kind: str
    _operation_ordinal: int
    _predicate_result: ScenarioPredicateResult
    _quantitative_outcome: Outcome
    _terminal_status: Literal["SUCCESS", "NON_ASSESSABLE", "FAILURE"]

    __slots__ = (
        "_binding_bytes",
        "_evidence_kind",
        "_gate_applicability",
        "_gate_outcome",
        "_operation_kind",
        "_operation_ordinal",
        "_predicate_result",
        "_quantitative_outcome",
        "_terminal_status",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> DirectTerminalEvidence:
        raise TypeError("Direct terminal evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Direct terminal evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Direct terminal evidence is immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Direct terminal evidence cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Direct terminal evidence cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Direct terminal evidence cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Direct terminal evidence cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Direct terminal evidence cannot be copied or serialized.")

    @property
    def operation_ordinal(self) -> int:
        return cast(int, _terminal_projection(self)["operation_ordinal"])

    @property
    def operation_kind(self) -> str:
        return cast(str, _terminal_projection(self)["operation_kind"])

    @property
    def family_id(self) -> str:
        return cast(str, _terminal_projection(self)["family_id"])

    @property
    def evidence_kind(self) -> str:
        return cast(str, _terminal_projection(self)["evidence_kind"])

    @property
    def predicate_id(self) -> str:
        return cast(str, _terminal_projection(self)["predicate_id"])

    @property
    def predicate_result_sha256(self) -> str:
        return cast(str, _terminal_projection(self)["predicate_result_sha256"])

    @property
    def family_outcome(self) -> Outcome:
        return cast(Outcome, _terminal_projection(self)["family_outcome"])

    @property
    def quantitative_outcome(self) -> Outcome:
        return cast(Outcome, _terminal_projection(self)["quantitative_outcome"])

    @property
    def gate_outcome(self) -> Outcome:
        return cast(Outcome, _terminal_projection(self)["gate_outcome"])

    @property
    def gate_applicability(self) -> Applicability:
        return cast(Applicability, _terminal_projection(self)["gate_applicability"])

    @property
    def terminal_status(self) -> Literal["SUCCESS", "NON_ASSESSABLE", "FAILURE"]:
        return cast(
            Literal["SUCCESS", "NON_ASSESSABLE", "FAILURE"],
            _terminal_projection(self)["terminal_status"],
        )


def _result_projection(result: ScenarioPredicateResult) -> dict[str, object]:
    try:
        return _validated_result_projection(result)
    except InvalidInputError:
        _reject("PREDICATE_RESULT_INVALID")


def _issue_direct_terminal_evidence(
    plan: DirectOperationPlanEntry,
    predicate_result: ScenarioPredicateResult,
    *,
    quantitative_outcome: Outcome,
    gate_outcome: Outcome,
    gate_applicability: Applicability,
    terminal_status: Literal["SUCCESS", "NON_ASSESSABLE", "FAILURE"],
) -> DirectTerminalEvidence:
    """Issue one terminal whose scenario fields come only from its result owner."""

    if type(plan) is not DirectOperationPlanEntry:
        _reject("TERMINAL_PLAN_INVALID")
    result = _result_projection(predicate_result)
    if result["family_id"] != plan.family_id:
        _reject("PREDICATE_RESULT_FAMILY_MISMATCH")
    if (
        quantitative_outcome not in _OUTCOMES
        or gate_outcome not in _OUTCOMES
        or gate_applicability not in {"APPLICABLE", "NOT_APPLICABLE", "UNAVAILABLE"}
        or terminal_status not in {"SUCCESS", "NON_ASSESSABLE", "FAILURE"}
    ):
        _reject("TERMINAL_OUTCOME_INVALID")
    binding = {
        "family_id": result["family_id"],
        "predicate_id": result["predicate_id"],
        "predicate_result_sha256": result["result_sha256"],
        "family_outcome": result["outcome"],
    }
    terminal = object.__new__(DirectTerminalEvidence)
    object.__setattr__(terminal, "_binding_bytes", canonical_json_bytes(binding))
    object.__setattr__(terminal, "_operation_ordinal", plan.operation_ordinal)
    object.__setattr__(terminal, "_operation_kind", plan.operation_kind)
    object.__setattr__(terminal, "_evidence_kind", plan.evidence_kind)
    object.__setattr__(terminal, "_predicate_result", predicate_result)
    object.__setattr__(terminal, "_quantitative_outcome", quantitative_outcome)
    object.__setattr__(terminal, "_gate_outcome", gate_outcome)
    object.__setattr__(terminal, "_gate_applicability", gate_applicability)
    object.__setattr__(terminal, "_terminal_status", terminal_status)
    _terminal_projection(terminal)
    return terminal


def _terminal_projection(terminal: DirectTerminalEvidence) -> dict[str, object]:
    if type(terminal) is not DirectTerminalEvidence:
        _reject("TERMINAL_OWNER_INVALID")
    try:
        binding_value = strict_json_loads(terminal._binding_bytes)
    except CanonicalizationError:
        _reject("TERMINAL_BINDING_INVALID")
    binding_keys = {
        "family_id",
        "predicate_id",
        "predicate_result_sha256",
        "family_outcome",
    }
    if type(binding_value) is not dict or set(binding_value) != binding_keys:
        _reject("TERMINAL_BINDING_INVALID")
    binding = cast(dict[str, object], binding_value)
    result = _result_projection(terminal._predicate_result)
    expected_binding = {
        "family_id": result["family_id"],
        "predicate_id": result["predicate_id"],
        "predicate_result_sha256": result["result_sha256"],
        "family_outcome": result["outcome"],
    }
    if binding != expected_binding or canonical_json_bytes(binding) != terminal._binding_bytes:
        _reject("TERMINAL_PREDICATE_RESULT_SUBSTITUTED")
    if (
        type(terminal._operation_ordinal) is not int
        or terminal._operation_ordinal < 0
        or type(terminal._operation_kind) is not str
        or not terminal._operation_kind
        or type(terminal._evidence_kind) is not str
        or not terminal._evidence_kind
        or terminal._quantitative_outcome not in _OUTCOMES
        or terminal._gate_outcome not in _OUTCOMES
        or terminal._gate_applicability not in {"APPLICABLE", "NOT_APPLICABLE", "UNAVAILABLE"}
        or terminal._terminal_status not in {"SUCCESS", "NON_ASSESSABLE", "FAILURE"}
    ):
        _reject("TERMINAL_PROJECTION_INVALID")
    return {
        "operation_ordinal": terminal._operation_ordinal,
        "operation_kind": terminal._operation_kind,
        "family_id": result["family_id"],
        "evidence_kind": terminal._evidence_kind,
        "predicate_id": result["predicate_id"],
        "predicate_result_sha256": result["result_sha256"],
        "family_outcome": result["outcome"],
        "quantitative_outcome": terminal._quantitative_outcome,
        "gate_outcome": terminal._gate_outcome,
        "gate_applicability": terminal._gate_applicability,
        "terminal_status": terminal._terminal_status,
    }


@dataclass(frozen=True, slots=True)
class SealedHeldoutAttemptReceipt:
    schema_version: Literal["ebm-audit-sealed-heldout-attempt-receipt/1.0"]
    subject_kind: Literal["SYNTHETIC_ONLY_CONFORMANCE_EBM"]
    commitment_receipt_sha256: str
    candidate_sha256: str
    supersession_sha256: str
    direct_producer_source_set_sha256: str
    compiled_plan_sha256: str
    terminal_evidence_inventory_sha256: str
    planned_operation_count: int
    terminal_evidence_count: int
    family_count: Literal[23]
    sealed_at_utc: str
    sealed_heldout_attempt_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class DirectConformanceScoreReceipt:
    schema_version: Literal["ebm-audit-direct-conformance-score-receipt/1.0"]
    subject_kind: Literal["SYNTHETIC_ONLY_CONFORMANCE_EBM"]
    commitment_receipt_sha256: str
    sealed_heldout_attempt_receipt_sha256: str
    candidate_sha256: str
    supersession_sha256: str
    direct_producer_source_set_sha256: str
    compiled_plan_sha256: str
    terminal_evidence_inventory_sha256: str
    ordered_family_outcomes_sha256: str
    quantitative_outcomes_sha256: str
    gate_outcomes_sha256: str
    aggregate_outcome: Outcome
    family_count: Literal[23]
    pass_count: int
    warn_count: int
    fail_count: int
    not_assessable_count: int
    applicable_gate_count: int
    non_applicable_gate_count: int
    unavailable_gate_count: int
    completed_at_utc: str
    score_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class DirectConformanceValidationReceipt:
    schema_version: Literal["ebm-audit-direct-conformance-validation-receipt/1.0"]
    subject_kind: Literal["SYNTHETIC_ONLY_CONFORMANCE_EBM"]
    score_receipt_sha256: str
    commitment_receipt_sha256: str
    sealed_heldout_attempt_receipt_sha256: str
    validation_status: Literal["VALIDATED"]
    research_backend_acceptance_eligible: Literal[False]
    completed_at_utc: str
    validation_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class DirectScoreResult:
    score_receipt: DirectConformanceScoreReceipt
    validation_receipt: DirectConformanceValidationReceipt


class SealedHeldoutAttempt:
    """Opaque owner; construction requires the evaluator-private module token."""

    __slots__ = (
        "_authenticator",
        "_commitment",
        "_expected_families",
        "_inventory",
        "_plan",
        "_receipt",
        "_scored",
        "_seal_tag",
    )

    def __init__(
        self,
        *,
        owner_token: object,
        authenticator: Callable[[bytes, str], bool],
        commitment: DirectPreexecutionCommitmentReceipt,
        expected_families: tuple[str, ...],
        plan: tuple[DirectOperationPlanEntry, ...],
        inventory: tuple[DirectTerminalEvidence, ...],
        receipt: SealedHeldoutAttemptReceipt,
        seal_tag: str,
    ) -> None:
        if owner_token is not _OWNER_TOKEN:
            _reject("SEALED_OWNER_FORGERY")
        self._authenticator = authenticator
        self._commitment = commitment
        self._expected_families = expected_families
        self._plan = plan
        self._inventory = inventory
        self._receipt = receipt
        self._seal_tag = seal_tag
        self._scored = False


def _without_hash(
    value: DirectPreexecutionCommitmentReceipt | SealedHeldoutAttemptReceipt,
    field: str,
) -> dict[str, object]:
    projection: dict[str, object] = asdict(value)
    projection[field] = None
    return projection


def _seal_payload(attempt: SealedHeldoutAttempt) -> dict[str, object]:
    return {
        "commitment": asdict(attempt._commitment),
        "expected_families": list(attempt._expected_families),
        "plan": [asdict(row) for row in attempt._plan],
        "inventory": [_terminal_projection(row) for row in attempt._inventory],
        "receipt": asdict(attempt._receipt),
    }


def _seal_attempt(
    *,
    owner_key: bytes,
    commitment: DirectPreexecutionCommitmentReceipt,
    expected_families: tuple[str, ...],
    plan: tuple[DirectOperationPlanEntry, ...],
    inventory: tuple[DirectTerminalEvidence, ...],
    sealed_at_utc: str,
) -> SealedHeldoutAttempt:
    """Evaluator-private sealing boundary used by the runner and synthetic tests."""

    if type(owner_key) is not bytes or len(owner_key) != 32:
        _reject("SEALED_OWNER_KEY_INVALID")
    if len(expected_families) != 23 or len(set(expected_families)) != 23:
        _reject("FAMILY_VECTOR_INVALID")
    compiled_plan_sha256 = _direct_operation_plan_digest(plan)
    inventory_sha256 = _digest(_INVENTORY_DOMAIN, [_terminal_projection(row) for row in inventory])
    receipt_projection: dict[str, object] = {
        "schema_version": "ebm-audit-sealed-heldout-attempt-receipt/1.0",
        "subject_kind": "SYNTHETIC_ONLY_CONFORMANCE_EBM",
        "commitment_receipt_sha256": commitment.commitment_receipt_sha256,
        "candidate_sha256": commitment.candidate_sha256,
        "supersession_sha256": commitment.supersession_sha256,
        "direct_producer_source_set_sha256": commitment.direct_producer_source_set_sha256,
        "compiled_plan_sha256": compiled_plan_sha256,
        "terminal_evidence_inventory_sha256": inventory_sha256,
        "planned_operation_count": len(plan),
        "terminal_evidence_count": len(inventory),
        "family_count": 23,
        "sealed_at_utc": sealed_at_utc,
        "sealed_heldout_attempt_receipt_sha256": None,
    }
    receipt_hash = _digest("ebm-audit/sealed-heldout-attempt-receipt/1", receipt_projection)
    receipt_projection["sealed_heldout_attempt_receipt_sha256"] = receipt_hash
    receipt = SealedHeldoutAttemptReceipt(**receipt_projection)  # type: ignore[arg-type]
    attempt = SealedHeldoutAttempt(
        owner_token=_OWNER_TOKEN,
        authenticator=lambda payload, observed_tag: hmac.compare_digest(
            hmac.new(
                owner_key,
                _SEAL_DOMAIN.encode("ascii") + b"\x00" + payload,
                hashlib.sha256,
            ).hexdigest(),
            observed_tag,
        ),
        commitment=commitment,
        expected_families=expected_families,
        plan=plan,
        inventory=inventory,
        receipt=receipt,
        seal_tag="",
    )
    tag = hmac.new(
        owner_key,
        _SEAL_DOMAIN.encode("ascii") + b"\x00" + canonical_json_bytes(_seal_payload(attempt)),
        hashlib.sha256,
    ).hexdigest()
    attempt._seal_tag = tag
    return attempt


def _authenticate(attempt: SealedHeldoutAttempt) -> None:
    if not attempt._authenticator(canonical_json_bytes(_seal_payload(attempt)), attempt._seal_tag):
        _reject("SEALED_ATTEMPT_AUTHENTICATION_FAILED")


def _aggregate(outcomes: list[Outcome]) -> Outcome:
    if not outcomes:
        _reject("OUTCOME_VECTOR_EMPTY")
    return max(outcomes, key=_OUTCOME_RANK.__getitem__)


def score_sealed_attempt(attempt: SealedHeldoutAttempt) -> DirectScoreResult:
    """Authenticate and score exactly one evaluator-owned sealed attempt.

    No public CLI or protocol payload exposes the private owner key or permits
    selection of score inputs.
    """

    if type(attempt) is not SealedHeldoutAttempt:
        _reject("SEALED_ATTEMPT_REQUIRED")
    if attempt._scored:
        _reject("ATTEMPT_ALREADY_SCORED")
    _authenticate(attempt)
    commitment = attempt._commitment
    receipt = attempt._receipt
    if commitment.subject_kind != "SYNTHETIC_ONLY_CONFORMANCE_EBM":
        _reject("CONFORMANCE_SUBJECT_INVALID")
    if (
        _digest(
            _COMMITMENT_DOMAIN,
            _without_hash(commitment, "commitment_receipt_sha256"),
        )
        != commitment.commitment_receipt_sha256
    ):
        _reject("COMMITMENT_RECEIPT_INVALID")
    if commitment.commitment_receipt_sha256 != receipt.commitment_receipt_sha256:
        _reject("COMMITMENT_BINDING_MISMATCH")
    if _direct_operation_plan_digest(attempt._plan) != receipt.compiled_plan_sha256:
        _reject("COMPILED_PLAN_MUTATED")
    if (
        _digest(
            _INVENTORY_DOMAIN,
            [_terminal_projection(row) for row in attempt._inventory],
        )
        != receipt.terminal_evidence_inventory_sha256
    ):
        _reject("TERMINAL_INVENTORY_MUTATED")
    if (
        _digest(
            "ebm-audit/sealed-heldout-attempt-receipt/1",
            _without_hash(receipt, "sealed_heldout_attempt_receipt_sha256"),
        )
        != receipt.sealed_heldout_attempt_receipt_sha256
    ):
        _reject("SEALED_RECEIPT_MUTATED")
    if len(attempt._plan) != len(attempt._inventory) or not attempt._plan:
        _reject("TERMINAL_INVENTORY_COUNT_MISMATCH")

    family_vectors: dict[str, list[Outcome]] = {family: [] for family in attempt._expected_families}
    quantitative: list[dict[str, object]] = []
    gates: list[dict[str, object]] = []
    not_assessable_count = 0
    for ordinal, (planned, observed) in enumerate(
        zip(attempt._plan, attempt._inventory, strict=True)
    ):
        if planned.operation_ordinal != ordinal or observed.operation_ordinal != ordinal:
            _reject("TERMINAL_EVIDENCE_ORDER_INVALID")
        if (
            planned.operation_kind,
            planned.family_id,
            planned.evidence_kind,
        ) != (
            observed.operation_kind,
            observed.family_id,
            observed.evidence_kind,
        ):
            _reject("TERMINAL_EVIDENCE_SUBSTITUTED")
        if planned.family_id not in family_vectors:
            _reject("TERMINAL_EVIDENCE_FAMILY_INVALID")
        if observed.gate_applicability != "APPLICABLE" and observed.gate_outcome != "FAIL":
            # Capability absence remains explicit and non-passing.
            _reject("NON_APPLICABLE_GATE_PASSED")
        if observed.gate_outcome == "WARN":
            _reject("HARD_GATE_WARN_FORBIDDEN")
        if observed.terminal_status == "NON_ASSESSABLE":
            not_assessable_count += 1
            if "FAIL" not in (
                observed.family_outcome,
                observed.quantitative_outcome,
                observed.gate_outcome,
            ):
                _reject("NON_ASSESSABLE_PASSED")
        operation_outcome = _aggregate(
            [observed.family_outcome, observed.quantitative_outcome, observed.gate_outcome]
        )
        family_vectors[planned.family_id].append(operation_outcome)
        quantitative.append(
            {"operation_ordinal": ordinal, "outcome": observed.quantitative_outcome}
        )
        gates.append(
            {
                "operation_ordinal": ordinal,
                "applicability": observed.gate_applicability,
                "outcome": observed.gate_outcome,
            }
        )

    ordered_family_outcomes: list[dict[str, object]] = []
    family_outcomes: list[Outcome] = []
    for family_id in attempt._expected_families:
        if not family_vectors[family_id]:
            _reject("PLANNED_FAMILY_EVIDENCE_MISSING")
        outcome = _aggregate(family_vectors[family_id])
        family_outcomes.append(outcome)
        ordered_family_outcomes.append({"family_id": family_id, "outcome": outcome})
    aggregate_outcome = _aggregate(family_outcomes)
    counts = {outcome: family_outcomes.count(outcome) for outcome in _OUTCOMES}
    applicable_gate_count = sum(row["applicability"] == "APPLICABLE" for row in gates)
    non_applicable_gate_count = sum(row["applicability"] == "NOT_APPLICABLE" for row in gates)
    unavailable_gate_count = sum(row["applicability"] == "UNAVAILABLE" for row in gates)
    score_projection: dict[str, object] = {
        "schema_version": "ebm-audit-direct-conformance-score-receipt/1.0",
        "subject_kind": "SYNTHETIC_ONLY_CONFORMANCE_EBM",
        "commitment_receipt_sha256": commitment.commitment_receipt_sha256,
        "sealed_heldout_attempt_receipt_sha256": receipt.sealed_heldout_attempt_receipt_sha256,
        "candidate_sha256": commitment.candidate_sha256,
        "supersession_sha256": commitment.supersession_sha256,
        "direct_producer_source_set_sha256": commitment.direct_producer_source_set_sha256,
        "compiled_plan_sha256": receipt.compiled_plan_sha256,
        "terminal_evidence_inventory_sha256": receipt.terminal_evidence_inventory_sha256,
        "ordered_family_outcomes_sha256": _digest(
            "ebm-audit/direct-ordered-family-outcomes/1", ordered_family_outcomes
        ),
        "quantitative_outcomes_sha256": _digest(
            "ebm-audit/direct-quantitative-outcomes/1", quantitative
        ),
        "gate_outcomes_sha256": _digest("ebm-audit/direct-gate-outcomes/1", gates),
        "aggregate_outcome": aggregate_outcome,
        "family_count": 23,
        "pass_count": counts["PASS"],
        "warn_count": counts["WARN"],
        "fail_count": counts["FAIL"],
        "not_assessable_count": not_assessable_count,
        "applicable_gate_count": applicable_gate_count,
        "non_applicable_gate_count": non_applicable_gate_count,
        "unavailable_gate_count": unavailable_gate_count,
        "completed_at_utc": receipt.sealed_at_utc,
        "score_receipt_sha256": None,
    }
    score_hash = _digest(_SCORE_DOMAIN, score_projection)
    score_projection["score_receipt_sha256"] = score_hash
    score_receipt = DirectConformanceScoreReceipt(**score_projection)  # type: ignore[arg-type]
    validation_projection: dict[str, object] = {
        "schema_version": "ebm-audit-direct-conformance-validation-receipt/1.0",
        "subject_kind": "SYNTHETIC_ONLY_CONFORMANCE_EBM",
        "score_receipt_sha256": score_hash,
        "commitment_receipt_sha256": commitment.commitment_receipt_sha256,
        "sealed_heldout_attempt_receipt_sha256": receipt.sealed_heldout_attempt_receipt_sha256,
        "validation_status": "VALIDATED",
        "research_backend_acceptance_eligible": False,
        "completed_at_utc": receipt.sealed_at_utc,
        "validation_receipt_sha256": None,
    }
    validation_hash = _digest(_VALIDATION_DOMAIN, validation_projection)
    validation_projection["validation_receipt_sha256"] = validation_hash
    validation_receipt = DirectConformanceValidationReceipt(
        schema_version="ebm-audit-direct-conformance-validation-receipt/1.0",
        subject_kind="SYNTHETIC_ONLY_CONFORMANCE_EBM",
        score_receipt_sha256=score_hash,
        commitment_receipt_sha256=commitment.commitment_receipt_sha256,
        sealed_heldout_attempt_receipt_sha256=(receipt.sealed_heldout_attempt_receipt_sha256),
        validation_status="VALIDATED",
        research_backend_acceptance_eligible=False,
        completed_at_utc=receipt.sealed_at_utc,
        validation_receipt_sha256=validation_hash,
    )
    attempt._scored = True
    return DirectScoreResult(score_receipt, validation_receipt)


def _clone_with_mutation_for_test(
    attempt: SealedHeldoutAttempt,
    *,
    field: str,
    value: object,
) -> SealedHeldoutAttempt:
    """Private adversarial fixture helper; deliberately preserves the old tag."""

    cloned = copy.copy(attempt)
    object.__setattr__(cloned, field, value)
    return cloned


__all__ = [
    "DirectConformanceScoreReceipt",
    "DirectConformanceValidationReceipt",
    "DirectOperationPlanEntry",
    "DirectPreexecutionCommitmentReceipt",
    "DirectScoreError",
    "DirectScoreResult",
    "DirectTerminalEvidence",
    "SealedHeldoutAttempt",
    "SealedHeldoutAttemptReceipt",
    "score_sealed_attempt",
]
