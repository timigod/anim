"""Fail-closed records for the proportional readiness boundary.

This module owns the small, pre-challenge part of the proportional contract.
It does not create a seed and it does not execute a Fit.  It only binds the
candidate, the frozen contract identities, the ordered 17-gate manifest, and
the evidence which may later be consumed by the final readiness receipt.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final, Literal, Never, cast

from ebm_audit.evaluator.independent_review_receipt import (
    IndependentReviewExpectation,
    validate_independent_review_receipt,
)
from ebm_audit.evaluator.meaning_evidence_bundle import _FROZEN_COVERAGE_ROWS
from ebm_audit.evaluator.proportional_challenge_receipt import (
    validate_proportional_challenge_attempt_receipt,
)
from ebm_audit.protocol.canonical import structured_sha256_hex

_MANIFEST_DIGEST_DOMAIN: Final = "ebm-audit/proportional-hard-gate-manifest/1"
_FREEZE_DIGEST_DOMAIN: Final = "ebm-audit/proportional-candidate-plan-freeze/1"
_READINESS_DIGEST_DOMAIN: Final = "ebm-audit/proportional-readiness-receipt/1"
_GATE_OWNER_BINDING_DOMAIN: Final = "ebm-audit/proportional-hard-gate-owner-binding/1"
_GATE_FACTS_DOMAIN: Final = "ebm-audit/proportional-hard-gate-observed-facts/1"
_SCHEMA_VERSION: Final = "ebm-audit-proportional-readiness-receipt/1.0"
_FREEZE_SCHEMA_VERSION: Final = "ebm-audit-proportional-candidate-plan-freeze/1.0"
_EVIDENCE_SCHEMA_VERSION: Final = "ebm-audit-proportional-hard-gate-evidence/1.0"
_FROZEN_MANIFEST_SHA256: Final = (
    "afac7470474815f4f5525d3dcc7782d17b881ba36589d28622bd1868778eb1b7"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")

EXPECTED_HARD_GATE_IDS: Final[tuple[str, ...]] = (
    "contract_candidate_plan_frozen",
    "researcher_workflow_and_handoff",
    "meaning_inventory_complete",
    "substantive_scientific_validation",
    "full_partial_capability_honesty",
    "baseline_truthfulness",
    "no_silent_data_change",
    "uncertainty_separation",
    "provenance",
    "privacy",
    "offline_operation",
    "determinism",
    "visible_warnings_and_failures",
    "cautious_language",
    "no_result_conditioned_tuning",
    "independent_review",
    "no_unauthorized_external_action",
)

_IDENTITY_FIELDS: Final[tuple[str, ...]] = (
    "candidate_git_commit",
    "candidate_tree_sha256",
    "contract_sha256",
    "meaning_inventory_sha256",
    "meaning_coverage_sha256",
    "scenario_derivation_registry_sha256",
    "proportional_readiness_schema_sha256",
    "conformance_ebm_identity_sha256",
    "challenge_plan_sha256",
    "expected_results_sha256",
    "hard_gate_manifest_sha256",
)
_FINAL_RECEIPT_FIELDS: Final = frozenset(
    {
        "schema_version",
        "attempt_id",
        "candidate_plan_freeze_receipt",
        "candidate_plan_freeze_receipt_sha256",
        *_IDENTITY_FIELDS,
        "proportional_challenge_attempt_receipt",
        "proportional_challenge_attempt_receipt_sha256",
        "proportional_operation_plan_sha256",
        "fresh_seed_commitment_sha256",
        "fit_count",
        "wall_clock_seconds",
        "ordered_meaning_results",
        "covered_meaning_ids",
        "unavailable_meaning_ids",
        "not_applicable_meaning_ids",
        "invalid_meaning_ids",
        "failed_meaning_ids",
        "hard_gate_manifest",
        "hard_gate_manifest_sha256",
        "hard_gate_evidence_bundle",
        "hard_gate_evidence_bundle_sha256",
        "hard_gate_expected_artifact_receipts",
        "hard_gate_owner_artifact_sha256",
        "hard_gates",
        "artifact_hashes",
        "report_surface_verification_receipt_sha256",
        "independent_review",
        "independent_review_receipt_sha256",
        "independent_review_expectation",
        "no_participant_data_used",
        "no_unauthorized_external_action",
        "readiness_state",
        "proportional_readiness_receipt_sha256",
    }
)
_FROZEN_PROPORTIONAL_CONTRACT_SHA256: Final = (
    "2cf53a6006b174d7b2ef574a293f1499cff450491ef0359088a6889b0c288119"
)
_EXPECTED_MEANING_IDS: Final = tuple(
    cast(str, row["meaning_id"]) for row in _FROZEN_COVERAGE_ROWS
)


class ProportionalReadinessError(ValueError):
    """A malformed, stale, substituted, or replayed readiness record."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _review_expectation_projection(
    expectation: IndependentReviewExpectation,
) -> dict[str, object]:
    if type(expectation) is not IndependentReviewExpectation:
        _reject("READINESS.REVIEW_EXPECTATION_INVALID")
    return {
        "candidate_git_object_format": expectation.candidate_git_object_format,
        "candidate_git_commit": expectation.candidate_git_commit,
        "candidate_git_tree": expectation.candidate_git_tree,
        "candidate_freeze_receipt_sha256": (
            expectation.candidate_freeze_receipt_sha256
        ),
        "challenge_attempt_receipt_sha256": (
            expectation.challenge_attempt_receipt_sha256
        ),
        "ordered_challenge_artifact_sha256": list(
            expectation.ordered_challenge_artifact_sha256
        ),
    }


def _review_expectation_from_projection(
    value: object,
) -> IndependentReviewExpectation:
    raw = _mapping(value, "READINESS.REVIEW_EXPECTATION_INVALID")
    expected_fields = {
        "candidate_git_object_format",
        "candidate_git_commit",
        "candidate_git_tree",
        "candidate_freeze_receipt_sha256",
        "challenge_attempt_receipt_sha256",
        "ordered_challenge_artifact_sha256",
    }
    artifacts = raw.get("ordered_challenge_artifact_sha256")
    if set(raw) != expected_fields or type(artifacts) is not list:
        _reject("READINESS.REVIEW_EXPECTATION_INVALID")
    try:
        return IndependentReviewExpectation(
            candidate_git_object_format=cast(
                Literal["sha1", "sha256"],
                raw["candidate_git_object_format"],
            ),
            candidate_git_commit=cast(str, raw["candidate_git_commit"]),
            candidate_git_tree=cast(str, raw["candidate_git_tree"]),
            candidate_freeze_receipt_sha256=cast(
                str,
                raw["candidate_freeze_receipt_sha256"],
            ),
            challenge_attempt_receipt_sha256=cast(
                str,
                raw["challenge_attempt_receipt_sha256"],
            ),
            ordered_challenge_artifact_sha256=tuple(cast(list[str], artifacts)),
        )
    except (KeyError, TypeError, ValueError):
        _reject("READINESS.REVIEW_EXPECTATION_INVALID")


def _reject(code: str) -> Never:
    raise ProportionalReadinessError(code)


def _sha(value: object, *, commit: bool = False) -> bool:
    return isinstance(value, str) and bool((
        _COMMIT if commit else _SHA256
    ).fullmatch(value))


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(code)
    return value


def hard_gate_manifest_projection(manifest: Mapping[str, object]) -> dict[str, object]:
    """Return the canonical projection used for the 17-row manifest digest."""

    raw = _mapping(manifest, "HARD_GATES.MANIFEST_NOT_OBJECT")
    schema_version = raw.get("manifest_schema_version")
    gates = raw.get("gates")
    bindings = raw.get("evidence_bindings")
    if (
        not isinstance(schema_version, str)
        or not isinstance(gates, Sequence)
        or isinstance(gates, (str, bytes))
        or not isinstance(bindings, Sequence)
        or isinstance(bindings, (str, bytes))
        or len(gates) != len(bindings)
        or len(gates) != 17
    ):
        _reject("HARD_GATES.MANIFEST_CARDINALITY")
    gate_ids: list[str] = []
    records: list[dict[str, object]] = []
    for ordinal, (gate, binding) in enumerate(zip(gates, bindings, strict=True), 1):
        gate_row = dict(_mapping(gate, "HARD_GATES.GATE_NOT_OBJECT"))
        binding_row = dict(_mapping(binding, "HARD_GATES.BINDING_NOT_OBJECT"))
        gate_id = gate_row.get("gate_id")
        if not isinstance(gate_id, str):
            _reject("HARD_GATES.GATE_ID_MISSING")
        gate_ids.append(gate_id)
        if binding_row.get("gate_id") != gate_id:
            _reject("HARD_GATES.BINDING_GATE_MISMATCH")
        if gate_row.get("accepted_state") != "PASS":
            _reject("HARD_GATES.ACCEPTED_STATE_NOT_PASS")
        records.append({"ordinal": ordinal, "gate": gate_row, "evidence_binding": binding_row})
    if tuple(gate_ids) != EXPECTED_HARD_GATE_IDS:
        _reject("HARD_GATES.ORDER_OR_IDENTITY_MISMATCH")
    if len(set(gate_ids)) != 17:
        _reject("HARD_GATES.DUPLICATE_GATE")
    owners = [
        dict(_mapping(row, "HARD_GATES.GATE_NOT_OBJECT")).get("evidence_owner")
        for row in gates
    ]
    failures = [
        dict(_mapping(row, "HARD_GATES.GATE_NOT_OBJECT")).get("failure_code")
        for row in gates
    ]
    fields = [
        dict(_mapping(row, "HARD_GATES.GATE_NOT_OBJECT")).get("receipt_field")
        for row in gates
    ]
    if len(set(owners)) != 17 or len(set(failures)) != 17 or len(set(fields)) != 17:
        _reject("HARD_GATES.DUPLICATE_OWNER_FAILURE_OR_FIELD")
    return {"schema_version": schema_version, "records": records}


def hard_gate_manifest_sha256(manifest: Mapping[str, object]) -> str:
    return structured_sha256_hex(_MANIFEST_DIGEST_DOMAIN, hard_gate_manifest_projection(manifest))


def validate_hard_gate_manifest(manifest: Mapping[str, object]) -> str:
    """Validate the closed manifest and return its digest."""

    raw = _mapping(manifest, "HARD_GATES.MANIFEST_NOT_OBJECT")
    digest = hard_gate_manifest_sha256(raw)
    declared = raw.get("projection_sha256")
    if declared != digest or digest != _FROZEN_MANIFEST_SHA256:
        _reject("HARD_GATES.MANIFEST_DIGEST_MISMATCH")
    if (
        raw.get("manifest_schema_version")
        != "ebm-audit-proportional-hard-gate-manifest/1.0"
        or raw.get("digest_domain") != _MANIFEST_DIGEST_DOMAIN
        or raw.get("ordered_count") != 17
    ):
        _reject("HARD_GATES.MANIFEST_DOMAIN_OR_COUNT")
    return digest


def issue_candidate_plan_freeze_receipt(
    identities: Mapping[str, object],
    *,
    hard_gate_manifest: Mapping[str, object],
    committed_at_utc: str,
) -> dict[str, object]:
    """Bind all pre-seed identities without creating a seed root."""

    source = _mapping(identities, "FREEZE.IDENTITY_NOT_OBJECT")
    if set(source) != set(_IDENTITY_FIELDS):
        _reject("FREEZE.IDENTITY_FIELDS_INVALID")
    manifest_sha = validate_hard_gate_manifest(hard_gate_manifest)
    values: dict[str, object] = {}
    for field in _IDENTITY_FIELDS:
        value = source.get(field)
        valid = _sha(value, commit=field == "candidate_git_commit")
        if not valid:
            _reject(f"FREEZE.IDENTITY_INVALID.{field.upper()}")
        values[field] = value
    if values["hard_gate_manifest_sha256"] != manifest_sha:
        _reject("FREEZE.MANIFEST_BINDING_MISMATCH")
    if values["contract_sha256"] != _FROZEN_PROPORTIONAL_CONTRACT_SHA256:
        _reject("FREEZE.CONTRACT_IDENTITY_MISMATCH")
    if not committed_at_utc:
        _reject("FREEZE.COMMITMENT_TIME_INVALID")
    receipt: dict[str, object] = {
        "schema_version": _FREEZE_SCHEMA_VERSION,
        **values,
        "hard_gate_manifest_sha256": manifest_sha,
        "seed_root_state": "NOT_CREATED",
        "fit_count": 0,
        "tuning_state": "FROZEN",
        "committed_at_utc": committed_at_utc,
        "candidate_plan_freeze_receipt_sha256": None,
    }
    receipt["candidate_plan_freeze_receipt_sha256"] = structured_sha256_hex(
        _FREEZE_DIGEST_DOMAIN,
        {
            key: value
            for key, value in receipt.items()
            if key != "candidate_plan_freeze_receipt_sha256"
        },
    )
    return receipt


def validate_candidate_plan_freeze_receipt(receipt: Mapping[str, object]) -> str:
    raw = _mapping(receipt, "FREEZE.RECEIPT_NOT_OBJECT")
    expected_fields = {
        "schema_version",
        *_IDENTITY_FIELDS,
        "seed_root_state",
        "fit_count",
        "tuning_state",
        "committed_at_utc",
        "candidate_plan_freeze_receipt_sha256",
    }
    if set(raw) != expected_fields:
        _reject("FREEZE.RECEIPT_FIELDS_INVALID")
    if raw.get("schema_version") != _FREEZE_SCHEMA_VERSION:
        _reject("FREEZE.SCHEMA_VERSION")
    for field in _IDENTITY_FIELDS:
        value = raw.get(field)
        if not _sha(value, commit=field == "candidate_git_commit"):
            _reject(f"FREEZE.IDENTITY_INVALID.{field.upper()}")
    if raw.get("contract_sha256") != _FROZEN_PROPORTIONAL_CONTRACT_SHA256:
        _reject("FREEZE.CONTRACT_IDENTITY_MISMATCH")
    if not isinstance(raw.get("committed_at_utc"), str) or not raw.get(
        "committed_at_utc"
    ):
        _reject("FREEZE.COMMITMENT_TIME_INVALID")
    if raw.get("seed_root_state") != "NOT_CREATED" or raw.get("fit_count") != 0:
        _reject("FREEZE.SEED_ALREADY_CREATED")
    if raw.get("tuning_state") != "FROZEN":
        _reject("FREEZE.TUNING_NOT_FROZEN")
    digest = raw.get("candidate_plan_freeze_receipt_sha256")
    expected = structured_sha256_hex(
        _FREEZE_DIGEST_DOMAIN,
        {key: value for key, value in raw.items() if key != "candidate_plan_freeze_receipt_sha256"},
    )
    if digest != expected or not _sha(digest):
        _reject("FREEZE.DIGEST_MISMATCH")
    return expected


def evaluate_hard_gate_evidence(
    manifest: Mapping[str, object],
    evidence: Sequence[Mapping[str, object]],
    *,
    candidate_plan_freeze_receipt_sha256: str,
) -> tuple[str, tuple[str, ...]]:
    """Return ``PASS`` only for one exact PASS record per manifest gate."""

    validate_hard_gate_manifest(manifest)
    if not _sha(candidate_plan_freeze_receipt_sha256) or len(evidence) != 17:
        return "BLOCKED", ("HARD_GATES.MISSING_OR_UNBOUND_EVIDENCE",)
    seen: set[str] = set()
    reasons: list[str] = []
    raw_gates = _mapping(manifest, "HARD_GATES.MANIFEST_NOT_OBJECT").get("gates")
    if not isinstance(raw_gates, list):
        return "BLOCKED", ("HARD_GATES.MANIFEST_CARDINALITY",)
    gates = list(raw_gates)
    for expected, row in zip(gates, evidence, strict=False):
        gate = _mapping(expected, "HARD_GATES.GATE_NOT_OBJECT")
        observed = _mapping(row, "HARD_GATES.EVIDENCE_NOT_OBJECT")
        allowed_keys = {
            "schema_version",
            "gate_id",
            "preserved_invariant_ids",
            "evidence_owner",
            "source_artifact_sha256",
            "observed_facts_sha256",
            "state",
            "failure_code",
        }
        if set(observed) - allowed_keys:
            reasons.append("HARD_GATES.EVIDENCE_ADDITIONAL_PROPERTY")
        gate_id = observed.get("gate_id")
        if not isinstance(gate_id, str) or gate_id in seen:
            reasons.append("HARD_GATES.DUPLICATE_OR_UNKNOWN_EVIDENCE")
            continue
        seen.add(gate_id)
        if gate_id != gate.get("gate_id"):
            reasons.append("HARD_GATES.REORDERED_OR_SUBSTITUTED_EVIDENCE")
            continue
        if observed.get("evidence_owner") != gate.get("evidence_owner"):
            reasons.append("HARD_GATES.OWNER_SUBSTITUTION")
        if observed.get("preserved_invariant_ids") != gate.get("preserved_invariant_ids"):
            reasons.append("HARD_GATES.INVARIANT_SUBSTITUTION")
        if observed.get("schema_version") != _EVIDENCE_SCHEMA_VERSION:
            reasons.append("HARD_GATES.EVIDENCE_SCHEMA_MISMATCH")
        if not _sha(observed.get("source_artifact_sha256")):
            reasons.append("HARD_GATES.SOURCE_ARTIFACT_UNBOUND")
        if not _sha(observed.get("observed_facts_sha256")):
            reasons.append("HARD_GATES.OBSERVED_FACTS_UNBOUND")
        if observed.get("state") != "PASS":
            reasons.append("HARD_GATES.EVIDENCE_NOT_PASS")
        expected_failure = None if observed.get("state") == "PASS" else gate.get("failure_code")
        if observed.get("failure_code") != expected_failure:
            reasons.append("HARD_GATES.CONTRADICTORY_FAILURE_CODE")
        if (
            gate_id == "contract_candidate_plan_frozen"
            and observed.get("source_artifact_sha256")
            != candidate_plan_freeze_receipt_sha256
        ):
            reasons.append("HARD_GATES.STALE_FREEZE_BINDING")
    if tuple(sorted(seen)) != tuple(sorted(EXPECTED_HARD_GATE_IDS)):
        reasons.append("HARD_GATES.MISSING_OR_UNKNOWN_GATE")
    return ("PASS", ()) if not reasons else ("BLOCKED", tuple(dict.fromkeys(reasons)))


def _required_owner_bindings(
    manifest: Mapping[str, object],
    owner_artifacts: Mapping[str, object],
    gate_id: str,
) -> tuple[str, str]:
    bindings = manifest.get("evidence_bindings")
    if not isinstance(bindings, Sequence) or isinstance(bindings, (str, bytes)):
        _reject("HARD_GATES.BINDINGS_INVALID")
    binding = next(
        (
            _mapping(row, "HARD_GATES.BINDING_NOT_OBJECT")
            for row in bindings
            if isinstance(row, Mapping) and row.get("gate_id") == gate_id
        ),
        None,
    )
    if binding is None:
        _reject("HARD_GATES.BINDING_MISSING")
    required = binding.get("required_evidence_owners")
    if not isinstance(required, list) or not required:
        _reject("HARD_GATES.BINDING_OWNERS_INVALID")
    ordered = []
    for owner in required:
        digest = owner_artifacts.get(owner) if isinstance(owner, str) else None
        if not isinstance(owner, str) or not _sha(digest):
            _reject("HARD_GATES.OWNER_ARTIFACT_MISSING")
        ordered.append({"evidence_owner": owner, "artifact_sha256": digest})
    source = structured_sha256_hex(
        _GATE_OWNER_BINDING_DOMAIN,
        {"gate_id": gate_id, "ordered_owner_artifacts": ordered},
    )
    facts = structured_sha256_hex(
        _GATE_FACTS_DOMAIN,
        {"gate_id": gate_id, "source_artifact_sha256": source, "state": "PASS"},
    )
    return source, facts


def _validate_final_gate_evidence(
    manifest: Mapping[str, object],
    evidence: Sequence[Mapping[str, object]],
    owner_artifacts: Mapping[str, object],
) -> None:
    raw_bindings = manifest.get("evidence_bindings")
    if not isinstance(raw_bindings, list):
        _reject("HARD_GATES.BINDINGS_INVALID")
    required_owner_names = {
        owner
        for row in raw_bindings
        if isinstance(row, Mapping)
        for owner in row.get("required_evidence_owners", [])
        if isinstance(owner, str)
    }
    if set(owner_artifacts) != required_owner_names:
        _reject("HARD_GATES.OWNER_ARTIFACT_SET_INVALID")
    if len(evidence) != 17:
        _reject("HARD_GATES.FINAL_EVIDENCE_COUNT")
    gates = manifest.get("gates")
    if not isinstance(gates, list):
        _reject("HARD_GATES.MANIFEST_CARDINALITY")
    for gate, observed in zip(gates, evidence, strict=True):
        gate_row = _mapping(gate, "HARD_GATES.GATE_NOT_OBJECT")
        evidence_row = _mapping(observed, "HARD_GATES.EVIDENCE_NOT_OBJECT")
        gate_id = gate_row.get("gate_id")
        if not isinstance(gate_id, str):
            _reject("HARD_GATES.GATE_ID_MISSING")
        source, facts = _required_owner_bindings(manifest, owner_artifacts, gate_id)
        expected = {
            "schema_version": _EVIDENCE_SCHEMA_VERSION,
            "gate_id": gate_id,
            "preserved_invariant_ids": gate_row.get("preserved_invariant_ids"),
            "evidence_owner": gate_row.get("evidence_owner"),
            "source_artifact_sha256": source,
            "observed_facts_sha256": facts,
            "state": "PASS",
            "failure_code": None,
        }
        if dict(evidence_row) != expected:
            _reject("HARD_GATES.FINAL_EVIDENCE_INVALID")


def validate_final_proportional_readiness_receipt(
    receipt: Mapping[str, object],
) -> str:
    """Rebuild every final binding before accepting READY."""

    raw = _mapping(receipt, "READINESS.RECEIPT_NOT_OBJECT")
    if set(raw) != _FINAL_RECEIPT_FIELDS:
        _reject("READINESS.RECEIPT_FIELDS")
    freeze = _mapping(
        raw.get("candidate_plan_freeze_receipt"),
        "READINESS.FREEZE_RECEIPT_MISSING",
    )
    if validate_candidate_plan_freeze_receipt(freeze) != raw.get(
        "candidate_plan_freeze_receipt_sha256"
    ):
        _reject("READINESS.FREEZE_BINDING_INVALID")
    if any(raw.get(field) != freeze.get(field) for field in _IDENTITY_FIELDS):
        _reject("READINESS.IDENTITY_SUBSTITUTION")
    manifest = _mapping(raw.get("hard_gate_manifest"), "READINESS.MANIFEST_MISSING")
    if validate_hard_gate_manifest(manifest) != raw.get("hard_gate_manifest_sha256"):
        _reject("READINESS.MANIFEST_BINDING_MISMATCH")
    challenge = _mapping(
        raw.get("proportional_challenge_attempt_receipt"),
        "READINESS.CHALLENGE_RECEIPT_INVALID",
    )
    challenge_sha = validate_proportional_challenge_attempt_receipt(challenge)
    if (
        raw.get("proportional_challenge_attempt_receipt_sha256") != challenge_sha
        or challenge.get("candidate_plan_freeze_receipt_sha256")
        != raw.get("candidate_plan_freeze_receipt_sha256")
        or challenge.get("attempt_id") != raw.get("attempt_id")
        or challenge.get("proportional_operation_plan_sha256")
        != raw.get("proportional_operation_plan_sha256")
        or challenge.get("fresh_seed_commitment_sha256")
        != raw.get("fresh_seed_commitment_sha256")
        or challenge.get("monotonic_elapsed_seconds")
        != raw.get("wall_clock_seconds")
        or challenge.get("challenge_artifact_hashes") != raw.get("artifact_hashes")
    ):
        _reject("READINESS.CHALLENGE_BINDING_INVALID")
    bundle = _mapping(
        raw.get("hard_gate_evidence_bundle"),
        "READINESS.HARD_GATE_BUNDLE_INVALID",
    )
    expected_artifact_receipts = _mapping(
        raw.get("hard_gate_expected_artifact_receipts"),
        "READINESS.HARD_GATE_EXPECTATIONS_INVALID",
    )
    review_expectation = _review_expectation_from_projection(
        raw.get("independent_review_expectation")
    )
    from ebm_audit.evaluator.proportional_hard_gate_bundle import (
        validate_hard_gate_evidence_bundle,
    )

    bundle_sha = validate_hard_gate_evidence_bundle(
        bundle,
        hard_gate_manifest=manifest,
        expected_artifact_receipts=cast(
            Mapping[str, Mapping[str, object]],
            expected_artifact_receipts,
        ),
        independent_review_expectation=review_expectation,
    )
    if (
        raw.get("hard_gate_evidence_bundle_sha256") != bundle_sha
        or bundle.get("candidate_plan_freeze_receipt_sha256")
        != raw.get("candidate_plan_freeze_receipt_sha256")
        or bundle.get("challenge_attempt_receipt_sha256") != challenge_sha
        or bundle.get("hard_gate_manifest_sha256")
        != raw.get("hard_gate_manifest_sha256")
    ):
        _reject("READINESS.HARD_GATE_BUNDLE_BINDING_INVALID")
    evidence = raw.get("hard_gates")
    owner_artifacts = raw.get("hard_gate_owner_artifact_sha256")
    if not isinstance(evidence, list) or not isinstance(owner_artifacts, Mapping):
        _reject("READINESS.GATE_BINDINGS_MISSING")
    _validate_final_gate_evidence(manifest, evidence, owner_artifacts)
    if (
        bundle.get("hard_gate_evidence") != evidence
        or bundle.get("hard_gate_owner_artifact_sha256") != owner_artifacts
    ):
        _reject("READINESS.HARD_GATE_BUNDLE_BINDING_INVALID")
    meanings = raw.get("ordered_meaning_results")
    artifacts = raw.get("artifact_hashes")
    review = raw.get("independent_review")
    try:
        validated_review = validate_independent_review_receipt(
            _mapping(review, "READINESS.REVIEW_INVALID"),
            expected=review_expectation,
        )
    except (TypeError, ValueError):
        _reject("READINESS.REVIEW_INVALID")
    wall_clock_seconds = raw.get("wall_clock_seconds")
    if (
        raw.get("readiness_state")
        != "READY FOR RESEARCHERS TO INTEGRATE AN EBM AND RUN THE AUDITOR LOCALLY"
        or raw.get("fit_count") != 104
        or not isinstance(wall_clock_seconds, (int, float))
        or isinstance(wall_clock_seconds, bool)
        or not 0 <= wall_clock_seconds <= 10_500
        or not _sha(raw.get("proportional_operation_plan_sha256"))
        or not _sha(raw.get("fresh_seed_commitment_sha256"))
        or not isinstance(meanings, list)
        or len(meanings) != 104
        or raw.get("covered_meaning_ids")
        != [row.get("meaning_id") for row in meanings if isinstance(row, Mapping)]
        or any(raw.get(field) for field in (
            "unavailable_meaning_ids",
            "not_applicable_meaning_ids",
            "invalid_meaning_ids",
            "failed_meaning_ids",
        ))
        or not isinstance(artifacts, Mapping)
        or set(artifacts)
        != {
            "report/report.json",
            "report/meaning-evidence.csv",
            "report/report.html",
        }
        or any(not _sha(value) for value in artifacts.values())
        or not _sha(raw.get("report_surface_verification_receipt_sha256"))
        or raw.get("independent_review_receipt_sha256")
        != validated_review.independent_review_receipt_sha256
        or bundle.get("independent_review_receipt") != review
        or bundle.get("independent_review_receipt_sha256")
        != validated_review.independent_review_receipt_sha256
        or bundle.get("independent_review_expectation")
        != _review_expectation_projection(review_expectation)
        or raw.get("no_participant_data_used") is not True
        or raw.get("no_unauthorized_external_action") is not True
    ):
        _reject("READINESS.READY_TERMINAL_FIELDS_INVALID")
    for ordinal, row in enumerate(meanings, 1):
        if (
            not isinstance(row, Mapping)
            or row.get("ordinal") != ordinal
            or not isinstance(row.get("meaning_id"), str)
            or row.get("state") != "AVAILABLE"
        ):
            _reject("READINESS.MEANING_RESULTS_INCOMPLETE")
    if tuple(row["meaning_id"] for row in meanings) != _EXPECTED_MEANING_IDS:
        _reject("READINESS.MEANING_RESULTS_INCOMPLETE")
    digest = raw.get("proportional_readiness_receipt_sha256")
    expected = structured_sha256_hex(
        _READINESS_DIGEST_DOMAIN,
        {
            key: value
            for key, value in raw.items()
            if key != "proportional_readiness_receipt_sha256"
        },
    )
    if digest != expected or not _sha(digest):
        _reject("READINESS.DIGEST_MISMATCH")
    return expected
