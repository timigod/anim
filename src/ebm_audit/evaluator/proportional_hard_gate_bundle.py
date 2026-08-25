"""Opaque source receipts and one exact proportional hard-gate bundle.

This module closes already-validated runner evidence.  It does not create seed
material, execute a Fit, run the challenge, or invent gate evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from threading import RLock
from typing import Final, Literal, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.evaluator.independent_review_receipt import (
    IndependentReviewExpectation,
    IndependentReviewReceipt,
    independent_review_receipt_mapping,
    validate_independent_review_receipt,
)
from ebm_audit.evaluator.proportional_gate_receipts import (
    validate_semantic_gate_receipt,
)
from ebm_audit.evaluator.proportional_readiness import (
    EXPECTED_HARD_GATE_IDS,
    _validate_final_gate_evidence,
    validate_candidate_plan_freeze_receipt,
    validate_hard_gate_manifest,
)
from ebm_audit.protocol import (
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256_hex,
)
from ebm_audit.protocol.errors import CanonicalizationError

_SOURCE_SCHEMA_VERSION: Final = "ebm-audit-proportional-hard-gate-source-receipt/1.0"
_BUNDLE_SCHEMA_VERSION: Final = "ebm-audit-proportional-hard-gate-evidence-bundle/1.0"
_EVIDENCE_SCHEMA_VERSION: Final = "ebm-audit-proportional-hard-gate-evidence/1.0"
_SOURCE_DIGEST_DOMAIN: Final = "ebm-audit/proportional-hard-gate-source-receipt/1"
_BUNDLE_DIGEST_DOMAIN: Final = "ebm-audit/proportional-hard-gate-evidence-bundle/1"
_OWNER_BINDING_DOMAIN: Final = "ebm-audit/proportional-hard-gate-owner-binding/1"
_OBSERVED_FACTS_DOMAIN: Final = "ebm-audit/proportional-hard-gate-observed-facts/1"
_FROZEN_MANIFEST_SHA256: Final = (
    "afac7470474815f4f5525d3dcc7782d17b881ba36589d28622bd1868778eb1b7"
)
_SOURCE_FIELDS: Final = frozenset(
    {
        "schema_version",
        "hard_gate_manifest_sha256",
        "gate_id",
        "evidence_owner",
        "candidate_plan_freeze_receipt_sha256",
        "challenge_attempt_receipt_sha256",
        "ordered_source_artifacts",
        "source_artifact_sha256",
        "observed_facts_sha256",
        "state",
        "failure_code",
        "hard_gate_source_receipt_sha256",
    }
)
_ARTIFACT_FIELDS: Final = frozenset(
    {"artifact_id", "artifact_sha256", "artifact_receipt"}
)
_AUTHENTICATED_ARTIFACT_FIELDS: Final = frozenset(
    {
        "schema_version",
        "artifact_id",
        "candidate_plan_freeze_receipt_sha256",
        "challenge_attempt_receipt_sha256",
        "owner_projection",
        "owner_projection_sha256",
        "state",
        "failure_code",
        "artifact_receipt_sha256",
    }
)
_AUTHENTICATED_ARTIFACT_SCHEMA_VERSIONS: Final[dict[str, str]] = {
    "FRESH_ENVIRONMENT_HANDOFF_RECEIPT": "ebm-audit-fresh-environment-handoff-receipt/1.0",
    "PROPORTIONAL_OPERATION_PLAN": "ebm-audit-proportional-operation-plan-receipt/1.0",
    "MEANING_EVIDENCE_BUNDLE": "ebm-audit-meaning-evidence-bundle-receipt/1.0",
    "REPORT_SURFACE_VERIFICATION_RECEIPT": "ebm-audit-report-surface-verification-receipt/1.0",
    "PUBLIC_TERMINAL_RESULT": "ebm-audit-public-terminal-result-receipt/1.0",
    "SCIENTIFIC_VALIDATION_RECEIPT": "ebm-audit-scientific-validation-receipt/1.0",
    "PUBLIC_BATCH_CASE_PLAN": "ebm-audit-public-batch-case-plan-receipt/1.0",
    "CANONICAL_SCIENTIFIC_PAYLOAD": "ebm-audit-canonical-scientific-payload-receipt/1.0",
    "PREPROCESSING_EXECUTION_RECORD": "ebm-audit-preprocessing-execution-record-receipt/1.0",
    "PREPARATION_ROW_INSTANCE_MANIFEST": "ebm-audit-preparation-row-instance-manifest-receipt/1.0",
    "EXECUTED_TRANSFORMATION_EVIDENCE": "ebm-audit-executed-transformation-evidence-receipt/1.0",
    "EVIDENCE_BUNDLE_RECEIPT": "ebm-audit-evidence-bundle-receipt/1.0",
    "PRIVACY_SCAN_RECEIPT": "ebm-audit-privacy-scan-receipt/1.0",
    "OFFLINE_CONTAINMENT_RECEIPT": "ebm-audit-offline-containment-receipt/1.0",
    "DETERMINISM_RECEIPT": "ebm-audit-determinism-receipt/1.0",
    "WARNING_RECORD": "ebm-audit-warning-record-receipt/1.0",
    "REPORT_CLAIM_PROJECTION": "ebm-audit-report-claim-projection-receipt/1.0",
    "NO_TUNING_RECEIPT": "ebm-audit-no-tuning-receipt/1.0",
    "EXTERNAL_ACTION_AUDIT_RECEIPT": "ebm-audit-external-action-audit-receipt/1.0",
}
_AUTHENTICATED_ARTIFACT_PROJECTION_DOMAINS: Final[dict[str, str]] = {
    artifact_id: f"ebm-audit/{artifact_id.lower().replace('_', '-')}-owner-projection/1"
    for artifact_id in _AUTHENTICATED_ARTIFACT_SCHEMA_VERSIONS
}
_AUTHENTICATED_ARTIFACT_RECEIPT_DOMAINS: Final[dict[str, str]] = {
    artifact_id: f"ebm-audit/{artifact_id.lower().replace('_', '-')}-receipt/1"
    for artifact_id in _AUTHENTICATED_ARTIFACT_SCHEMA_VERSIONS
}
_BUNDLE_FIELDS: Final = frozenset(
    {
        "schema_version",
        "hard_gate_manifest_sha256",
        "candidate_plan_freeze_receipt_sha256",
        "challenge_attempt_receipt_sha256",
        "ordered_source_receipts",
        "hard_gate_evidence",
        "hard_gate_owner_artifact_sha256",
        "independent_review_receipt",
        "independent_review_receipt_sha256",
        "independent_review_expectation",
        "hard_gate_evidence_bundle_sha256",
    }
)
_REVIEW_EXPECTATION_FIELDS: Final = frozenset(
    {
        "candidate_git_object_format",
        "candidate_git_commit",
        "candidate_git_tree",
        "candidate_freeze_receipt_sha256",
        "challenge_attempt_receipt_sha256",
        "ordered_challenge_artifact_sha256",
    }
)


class ProportionalHardGateBundleError(ValueError):
    """A malformed, stale, contradictory, substituted, or replayed gate owner."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> Never:
    raise ProportionalHardGateBundleError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        _reject(code)
    return cast(Mapping[str, object], value)


def _validated_authenticated_artifact_receipt(
    receipt: object,
    *,
    artifact_id: str,
    expected_receipt: Mapping[str, object],
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
) -> tuple[dict[str, object], str]:
    """Validate one exact durable owner projection in its own hash domain."""

    schema_version = _AUTHENTICATED_ARTIFACT_SCHEMA_VERSIONS.get(artifact_id)
    projection_domain = _AUTHENTICATED_ARTIFACT_PROJECTION_DOMAINS.get(artifact_id)
    receipt_domain = _AUTHENTICATED_ARTIFACT_RECEIPT_DOMAINS.get(artifact_id)
    raw = dict(_mapping(receipt, "HARD_GATE_SOURCE.ARTIFACT_RECEIPT"))
    expected = dict(
        _mapping(expected_receipt, "HARD_GATE_SOURCE.EXPECTED_ARTIFACT_RECEIPT")
    )
    projection = raw.get("owner_projection")
    if (
        schema_version is None
        or projection_domain is None
        or receipt_domain is None
        or set(raw) != _AUTHENTICATED_ARTIFACT_FIELDS
        or raw.get("schema_version") != schema_version
        or raw.get("artifact_id") != artifact_id
        or raw.get("candidate_plan_freeze_receipt_sha256")
        != candidate_plan_freeze_receipt_sha256
        or raw.get("challenge_attempt_receipt_sha256")
        != challenge_attempt_receipt_sha256
        or not isinstance(projection, Mapping)
        or not projection
        or raw.get("owner_projection_sha256")
        != structured_sha256_hex(projection_domain, projection)
        or raw.get("state") != "AUTHENTICATED"
        or raw.get("failure_code") is not None
        or raw.get("artifact_receipt_sha256")
        != structured_sha256_hex(
            receipt_domain,
            _without_digest(raw, "artifact_receipt_sha256"),
        )
        or raw != expected
    ):
        _reject("HARD_GATE_SOURCE.ARTIFACT_RECEIPT_INVALID")
    if artifact_id in {
        "FRESH_ENVIRONMENT_HANDOFF_RECEIPT",
        "SCIENTIFIC_VALIDATION_RECEIPT",
        "PRIVACY_SCAN_RECEIPT",
        "OFFLINE_CONTAINMENT_RECEIPT",
        "DETERMINISM_RECEIPT",
        "EXTERNAL_ACTION_AUDIT_RECEIPT",
    }:
        semantic = _mapping(
            projection,
            "HARD_GATE_SOURCE.SEMANTIC_RECEIPT",
        )
        handoff_sha256 = semantic.get("finalization_handoff_sha256")
        if not _is_sha256(handoff_sha256):
            _reject("HARD_GATE_SOURCE.SEMANTIC_RECEIPT_INVALID")
        try:
            validate_semantic_gate_receipt(
                semantic,
                artifact_id=artifact_id,
                candidate_plan_freeze_receipt_sha256=(
                    candidate_plan_freeze_receipt_sha256
                ),
                challenge_attempt_receipt_sha256=(
                    challenge_attempt_receipt_sha256
                ),
                finalization_handoff_sha256=cast(str, handoff_sha256),
            )
        except (TypeError, ValueError):
            _reject("HARD_GATE_SOURCE.SEMANTIC_RECEIPT_INVALID")
    return raw, cast(str, raw["artifact_receipt_sha256"])


def authenticated_hard_gate_artifact_receipt(
    *,
    artifact_id: str,
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    owner_projection: Mapping[str, object],
) -> dict[str, object]:
    """Close one already-authenticated runtime projection into durable bytes."""

    schema_version = _AUTHENTICATED_ARTIFACT_SCHEMA_VERSIONS.get(artifact_id)
    projection_domain = _AUTHENTICATED_ARTIFACT_PROJECTION_DOMAINS.get(artifact_id)
    receipt_domain = _AUTHENTICATED_ARTIFACT_RECEIPT_DOMAINS.get(artifact_id)
    if (
        schema_version is None
        or projection_domain is None
        or receipt_domain is None
        or not _is_sha256(candidate_plan_freeze_receipt_sha256)
        or not _is_sha256(challenge_attempt_receipt_sha256)
        or not isinstance(owner_projection, Mapping)
        or not owner_projection
    ):
        _reject("HARD_GATE_SOURCE.ARTIFACT_PROJECTION_INVALID")
    receipt: dict[str, object] = {
        "schema_version": schema_version,
        "artifact_id": artifact_id,
        "candidate_plan_freeze_receipt_sha256": (
            candidate_plan_freeze_receipt_sha256
        ),
        "challenge_attempt_receipt_sha256": challenge_attempt_receipt_sha256,
        "owner_projection": dict(owner_projection),
        "owner_projection_sha256": structured_sha256_hex(
            projection_domain,
            owner_projection,
        ),
        "state": "AUTHENTICATED",
        "failure_code": None,
        "artifact_receipt_sha256": None,
    }
    receipt["artifact_receipt_sha256"] = structured_sha256_hex(
        receipt_domain,
        _without_digest(receipt, "artifact_receipt_sha256"),
    )
    _validated_authenticated_artifact_receipt(
        receipt,
        artifact_id=artifact_id,
        expected_receipt=receipt,
        candidate_plan_freeze_receipt_sha256=(
            candidate_plan_freeze_receipt_sha256
        ),
        challenge_attempt_receipt_sha256=challenge_attempt_receipt_sha256,
    )
    return receipt


def _validated_artifact_receipt_dispatch(
    receipt: object,
    *,
    artifact_id: str,
    expected_receipt: Mapping[str, object],
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    independent_review_expectation: IndependentReviewExpectation,
) -> tuple[dict[str, object], str]:
    """Dispatch each required owner to its exact durable receipt validator."""

    raw = dict(_mapping(receipt, "HARD_GATE_SOURCE.ARTIFACT_RECEIPT"))
    expected = dict(
        _mapping(expected_receipt, "HARD_GATE_SOURCE.EXPECTED_ARTIFACT_RECEIPT")
    )
    if raw != expected:
        _reject("HARD_GATE_SOURCE.ARTIFACT_RECEIPT_SUBSTITUTION")
    if artifact_id == "CANDIDATE_PLAN_FREEZE_RECEIPT":
        try:
            digest = validate_candidate_plan_freeze_receipt(raw)
        except Exception:
            _reject("HARD_GATE_SOURCE.ARTIFACT_RECEIPT_INVALID")
        if digest != candidate_plan_freeze_receipt_sha256:
            _reject("HARD_GATE_SOURCE.ARTIFACT_RECEIPT_STALE")
        return raw, digest
    if artifact_id == "INDEPENDENT_REVIEW_RECEIPT":
        try:
            review = validate_independent_review_receipt(
                raw,
                expected=independent_review_expectation,
            )
        except Exception:
            _reject("HARD_GATE_SOURCE.ARTIFACT_RECEIPT_INVALID")
        if (
            review.candidate_freeze_receipt_sha256
            != candidate_plan_freeze_receipt_sha256
            or review.challenge_attempt_receipt_sha256
            != challenge_attempt_receipt_sha256
        ):
            _reject("HARD_GATE_SOURCE.ARTIFACT_RECEIPT_STALE")
        return raw, review.independent_review_receipt_sha256
    return _validated_authenticated_artifact_receipt(
        raw,
        artifact_id=artifact_id,
        expected_receipt=expected,
        candidate_plan_freeze_receipt_sha256=(
            candidate_plan_freeze_receipt_sha256
        ),
        challenge_attempt_receipt_sha256=challenge_attempt_receipt_sha256,
    )


def _manifest_rows(
    manifest: Mapping[str, object],
) -> tuple[str, tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    try:
        digest = validate_hard_gate_manifest(manifest)
    except Exception:
        _reject("HARD_GATE_BUNDLE.MANIFEST_INVALID")
    gates = manifest.get("gates")
    bindings = manifest.get("evidence_bindings")
    if type(gates) is not list or type(bindings) is not list or len(gates) != 17:
        _reject("HARD_GATE_BUNDLE.MANIFEST_INVALID")
    gate_rows = tuple(dict(_mapping(row, "HARD_GATE_BUNDLE.MANIFEST_INVALID")) for row in gates)
    binding_rows = tuple(
        dict(_mapping(row, "HARD_GATE_BUNDLE.MANIFEST_INVALID")) for row in bindings
    )
    if (
        digest != _FROZEN_MANIFEST_SHA256
        or tuple(row.get("gate_id") for row in gate_rows) != EXPECTED_HARD_GATE_IDS
        or tuple(row.get("gate_id") for row in binding_rows) != EXPECTED_HARD_GATE_IDS
    ):
        _reject("HARD_GATE_BUNDLE.MANIFEST_INVALID")
    return digest, gate_rows, binding_rows


def _gate_contract(
    manifest: Mapping[str, object], gate_id: object
) -> tuple[str, dict[str, object], tuple[str, ...]]:
    manifest_sha, gates, bindings = _manifest_rows(manifest)
    matching = [
        (gate, binding)
        for gate, binding in zip(gates, bindings, strict=True)
        if gate.get("gate_id") == gate_id
    ]
    if len(matching) != 1:
        _reject("HARD_GATE_SOURCE.GATE_ID")
    gate, binding = matching[0]
    required = binding.get("required_evidence_owners")
    if (
        type(required) is not list
        or not required
        or any(type(owner) is not str for owner in required)
        or len(set(cast(list[str], required))) != len(required)
    ):
        _reject("HARD_GATE_SOURCE.MANIFEST_BINDING")
    return manifest_sha, gate, tuple(cast(list[str], required))


def _validated_artifacts(
    value: object,
    *,
    required_artifact_ids: tuple[str, ...],
    expected_artifact_receipts: Mapping[str, Mapping[str, object]],
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    independent_review_expectation: IndependentReviewExpectation,
) -> list[dict[str, object]]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or len(value) != len(required_artifact_ids)
    ):
        _reject("HARD_GATE_SOURCE.ARTIFACT_COUNT")
    records: list[dict[str, object]] = []
    for artifact_id, item in zip(required_artifact_ids, value, strict=True):
        row = _mapping(item, "HARD_GATE_SOURCE.ARTIFACT_FIELDS")
        if set(row) != _ARTIFACT_FIELDS:
            _reject("HARD_GATE_SOURCE.ARTIFACT_FIELDS")
        if row.get("artifact_id") != artifact_id:
            _reject("HARD_GATE_SOURCE.ARTIFACT_ORDER")
        digest = row.get("artifact_sha256")
        if not _is_sha256(digest):
            _reject("HARD_GATE_SOURCE.ARTIFACT_DIGEST")
        expected_receipt = expected_artifact_receipts.get(artifact_id)
        if expected_receipt is None:
            _reject("HARD_GATE_SOURCE.EXPECTED_ARTIFACT_RECEIPT_MISSING")
        closed_receipt, expected_digest = _validated_artifact_receipt_dispatch(
            row.get("artifact_receipt"),
            artifact_id=artifact_id,
            expected_receipt=expected_receipt,
            candidate_plan_freeze_receipt_sha256=(
                candidate_plan_freeze_receipt_sha256
            ),
            challenge_attempt_receipt_sha256=challenge_attempt_receipt_sha256,
            independent_review_expectation=independent_review_expectation,
        )
        if digest != expected_digest:
            _reject("HARD_GATE_SOURCE.ARTIFACT_DIGEST_MISMATCH")
        records.append(
            {
                "artifact_id": artifact_id,
                "artifact_sha256": digest,
                "artifact_receipt": closed_receipt,
            }
        )
    return records


def _source_binding_sha256(gate_id: str, artifacts: Sequence[Mapping[str, object]]) -> str:
    return structured_sha256_hex(
        _OWNER_BINDING_DOMAIN,
        {
            "gate_id": gate_id,
            "ordered_owner_artifacts": [
                {
                    "evidence_owner": row["artifact_id"],
                    "artifact_sha256": row["artifact_sha256"],
                }
                for row in artifacts
            ],
        },
    )


def _observed_facts_sha256(gate_id: str, source_artifact_sha256: str) -> str:
    return structured_sha256_hex(
        _OBSERVED_FACTS_DOMAIN,
        {
            "gate_id": gate_id,
            "source_artifact_sha256": source_artifact_sha256,
            "state": "PASS",
        },
    )


def _without_digest(value: Mapping[str, object], field: str) -> dict[str, object]:
    return {key: item for key, item in value.items() if key != field}


def validate_hard_gate_source_receipt(
    receipt: Mapping[str, object],
    *,
    hard_gate_manifest: Mapping[str, object],
    expected_artifact_receipts: Mapping[str, Mapping[str, object]],
    independent_review_expectation: IndependentReviewExpectation,
) -> str:
    """Revalidate one durable source receipt against the frozen gate row."""

    raw = _mapping(receipt, "HARD_GATE_SOURCE.RECEIPT_OBJECT")
    if set(raw) != _SOURCE_FIELDS:
        _reject("HARD_GATE_SOURCE.RECEIPT_FIELDS")
    manifest_sha, gate, required = _gate_contract(hard_gate_manifest, raw.get("gate_id"))
    if (
        raw.get("schema_version") != _SOURCE_SCHEMA_VERSION
        or raw.get("hard_gate_manifest_sha256") != manifest_sha
        or raw.get("evidence_owner") != gate.get("evidence_owner")
    ):
        _reject("HARD_GATE_SOURCE.GATE_BINDING")
    if not _is_sha256(raw.get("candidate_plan_freeze_receipt_sha256")):
        _reject("HARD_GATE_SOURCE.FREEZE_DIGEST")
    if not _is_sha256(raw.get("challenge_attempt_receipt_sha256")):
        _reject("HARD_GATE_SOURCE.CHALLENGE_DIGEST")
    artifacts = _validated_artifacts(
        raw.get("ordered_source_artifacts"),
        required_artifact_ids=required,
        expected_artifact_receipts=expected_artifact_receipts,
        candidate_plan_freeze_receipt_sha256=cast(
            str,
            raw["candidate_plan_freeze_receipt_sha256"],
        ),
        challenge_attempt_receipt_sha256=cast(
            str,
            raw["challenge_attempt_receipt_sha256"],
        ),
        independent_review_expectation=independent_review_expectation,
    )
    gate_id = cast(str, raw["gate_id"])
    source_sha = _source_binding_sha256(gate_id, artifacts)
    if raw.get("source_artifact_sha256") != source_sha:
        _reject("HARD_GATE_SOURCE.SOURCE_DIGEST")
    if raw.get("observed_facts_sha256") != _observed_facts_sha256(gate_id, source_sha):
        _reject("HARD_GATE_SOURCE.OBSERVED_FACTS")
    if raw.get("state") != "PASS" or raw.get("failure_code") is not None:
        _reject("HARD_GATE_SOURCE.CONTRADICTORY_STATE")
    digest = raw.get("hard_gate_source_receipt_sha256")
    expected = structured_sha256_hex(
        _SOURCE_DIGEST_DOMAIN,
        _without_digest(raw, "hard_gate_source_receipt_sha256"),
    )
    if not _is_sha256(digest) or digest != expected:
        _reject("HARD_GATE_SOURCE.RECEIPT_DIGEST")
    return expected


@dataclass(slots=True)
class _SourceState:
    canonical_bytes: bytes
    receipt_sha256: str
    expected_artifact_receipts: dict[str, dict[str, object]]
    independent_review_expectation: IndependentReviewExpectation
    consumed: bool
    lock: RLock


class _OpaqueOwner:
    __slots__ = ()

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Hard-gate owners are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Hard-gate owners cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Hard-gate owners cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Hard-gate owners cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Hard-gate owners cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Hard-gate owners cannot be copied or serialized.")


@final
class HardGateSourceReceipt(_OpaqueOwner):
    """Opaque owner of one exact gate's concrete source artifacts."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> HardGateSourceReceipt:
        raise TypeError("Hard-gate source receipts are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Hard-gate source receipts cannot be subclassed.")

    @property
    def digest(self) -> str:
        return _validated_source_owner(self)[0].receipt_sha256


_SOURCE_STATES: OneShotWeakRegistry[HardGateSourceReceipt, _SourceState]
_SOURCE_STATES, _SOURCE_ISSUER = create_one_shot_registry()


def _validated_source_owner(
    owner: object,
) -> tuple[_SourceState, dict[str, object], dict[str, object]]:
    if type(owner) is not HardGateSourceReceipt:
        _reject("HARD_GATE_SOURCE.OPAQUE_OWNER_REQUIRED")
    try:
        state = _SOURCE_STATES.read(owner)
        projection = strict_json_loads(state.canonical_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("HARD_GATE_SOURCE.OPAQUE_OWNER_INVALID")
    if type(projection) is not dict:
        _reject("HARD_GATE_SOURCE.OPAQUE_OWNER_INVALID")
    raw = cast(dict[str, object], projection)
    manifest_sha = raw.get("hard_gate_manifest_sha256")
    if manifest_sha != _FROZEN_MANIFEST_SHA256:
        _reject("HARD_GATE_SOURCE.OPAQUE_OWNER_INVALID")
    if canonical_json_bytes(raw) != state.canonical_bytes:
        _reject("HARD_GATE_SOURCE.OPAQUE_OWNER_INVALID")
    return state, raw, {"hard_gate_manifest_sha256": manifest_sha}


def _issue_hard_gate_source_receipt(
    *,
    hard_gate_manifest: Mapping[str, object],
    gate_id: str,
    evidence_owner: str,
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    ordered_source_artifacts: Sequence[Mapping[str, object]],
    expected_artifact_receipts: Mapping[str, Mapping[str, object]],
    independent_review_expectation: IndependentReviewExpectation,
    observed_facts_sha256: str,
    state: str,
    failure_code: object,
) -> HardGateSourceReceipt:
    """Issue only on the already-authenticated runner evidence path."""

    manifest_sha, gate, required = _gate_contract(hard_gate_manifest, gate_id)
    if evidence_owner != gate.get("evidence_owner"):
        _reject("HARD_GATE_SOURCE.GATE_BINDING")
    if not _is_sha256(candidate_plan_freeze_receipt_sha256):
        _reject("HARD_GATE_SOURCE.FREEZE_DIGEST")
    if not _is_sha256(challenge_attempt_receipt_sha256):
        _reject("HARD_GATE_SOURCE.CHALLENGE_DIGEST")
    artifacts = _validated_artifacts(
        ordered_source_artifacts,
        required_artifact_ids=required,
        expected_artifact_receipts=expected_artifact_receipts,
        candidate_plan_freeze_receipt_sha256=(
            candidate_plan_freeze_receipt_sha256
        ),
        challenge_attempt_receipt_sha256=challenge_attempt_receipt_sha256,
        independent_review_expectation=independent_review_expectation,
    )
    source_sha = _source_binding_sha256(gate_id, artifacts)
    if observed_facts_sha256 != _observed_facts_sha256(gate_id, source_sha):
        _reject("HARD_GATE_SOURCE.OBSERVED_FACTS")
    if state != "PASS" or failure_code is not None:
        _reject("HARD_GATE_SOURCE.CONTRADICTORY_STATE")
    receipt: dict[str, object] = {
        "schema_version": _SOURCE_SCHEMA_VERSION,
        "hard_gate_manifest_sha256": manifest_sha,
        "gate_id": gate_id,
        "evidence_owner": evidence_owner,
        "candidate_plan_freeze_receipt_sha256": candidate_plan_freeze_receipt_sha256,
        "challenge_attempt_receipt_sha256": challenge_attempt_receipt_sha256,
        "ordered_source_artifacts": artifacts,
        "source_artifact_sha256": source_sha,
        "observed_facts_sha256": observed_facts_sha256,
        "state": "PASS",
        "failure_code": None,
        "hard_gate_source_receipt_sha256": None,
    }
    receipt["hard_gate_source_receipt_sha256"] = structured_sha256_hex(
        _SOURCE_DIGEST_DOMAIN,
        _without_digest(receipt, "hard_gate_source_receipt_sha256"),
    )
    digest = validate_hard_gate_source_receipt(
        receipt,
        hard_gate_manifest=hard_gate_manifest,
        expected_artifact_receipts=expected_artifact_receipts,
        independent_review_expectation=independent_review_expectation,
    )
    owner = object.__new__(HardGateSourceReceipt)
    _SOURCE_ISSUER.bind_once(
        owner,
        _SourceState(
            canonical_json_bytes(receipt),
            digest,
            {
                artifact_id: dict(expected_artifact_receipts[artifact_id])
                for artifact_id in required
            },
            independent_review_expectation,
            False,
            RLock(),
        ),
    )
    return owner


def hard_gate_source_receipt_projection(
    owner: HardGateSourceReceipt, *, hard_gate_manifest: Mapping[str, object]
) -> dict[str, object]:
    """Return a fresh durable source projection after full revalidation."""

    state, projection, _binding = _validated_source_owner(owner)
    validate_hard_gate_source_receipt(
        projection,
        hard_gate_manifest=hard_gate_manifest,
        expected_artifact_receipts=state.expected_artifact_receipts,
        independent_review_expectation=state.independent_review_expectation,
    )
    return projection


class HardGateSourceReceiptConsumer:
    """Consume one opaque source receipt exactly once across all consumers."""

    __slots__ = ()

    def consume(
        self,
        owner: HardGateSourceReceipt,
        *,
        hard_gate_manifest: Mapping[str, object],
    ) -> dict[str, object]:
        state, projection, _binding = _validated_source_owner(owner)
        validate_hard_gate_source_receipt(
            projection,
            hard_gate_manifest=hard_gate_manifest,
            expected_artifact_receipts=state.expected_artifact_receipts,
            independent_review_expectation=state.independent_review_expectation,
        )
        with state.lock:
            if state.consumed:
                _reject("HARD_GATE_SOURCE.REPLAY")
            state.consumed = True
        return projection


def _expectation_mapping(expected: IndependentReviewExpectation) -> dict[str, object]:
    return {
        "candidate_git_object_format": expected.candidate_git_object_format,
        "candidate_git_commit": expected.candidate_git_commit,
        "candidate_git_tree": expected.candidate_git_tree,
        "candidate_freeze_receipt_sha256": expected.candidate_freeze_receipt_sha256,
        "challenge_attempt_receipt_sha256": expected.challenge_attempt_receipt_sha256,
        "ordered_challenge_artifact_sha256": list(
            expected.ordered_challenge_artifact_sha256
        ),
    }


def _expectation_from_mapping(value: object) -> IndependentReviewExpectation:
    raw = _mapping(value, "HARD_GATE_BUNDLE.REVIEW_EXPECTATION")
    if set(raw) != _REVIEW_EXPECTATION_FIELDS:
        _reject("HARD_GATE_BUNDLE.REVIEW_EXPECTATION")
    artifacts = raw.get("ordered_challenge_artifact_sha256")
    if type(artifacts) is not list:
        _reject("HARD_GATE_BUNDLE.REVIEW_EXPECTATION")
    try:
        return IndependentReviewExpectation(
            candidate_git_object_format=cast(
                Literal["sha1", "sha256"], raw["candidate_git_object_format"]
            ),
            candidate_git_commit=cast(str, raw["candidate_git_commit"]),
            candidate_git_tree=cast(str, raw["candidate_git_tree"]),
            candidate_freeze_receipt_sha256=cast(
                str, raw["candidate_freeze_receipt_sha256"]
            ),
            challenge_attempt_receipt_sha256=cast(
                str, raw["challenge_attempt_receipt_sha256"]
            ),
            ordered_challenge_artifact_sha256=tuple(cast(list[str], artifacts)),
        )
    except (KeyError, TypeError, ValueError):
        _reject("HARD_GATE_BUNDLE.REVIEW_EXPECTATION")


def _validated_review(
    receipt_value: object,
    expectation_value: object,
    *,
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
) -> tuple[dict[str, object], dict[str, object], str]:
    receipt = _mapping(receipt_value, "HARD_GATE_BUNDLE.REVIEW_RECEIPT")
    expectation = _expectation_from_mapping(expectation_value)
    if (
        expectation.candidate_freeze_receipt_sha256
        != candidate_plan_freeze_receipt_sha256
        or expectation.challenge_attempt_receipt_sha256
        != challenge_attempt_receipt_sha256
    ):
        _reject("HARD_GATE_BUNDLE.REVIEW_BINDING")
    try:
        validated = validate_independent_review_receipt(receipt, expected=expectation)
    except Exception:
        _reject("HARD_GATE_BUNDLE.REVIEW_RECEIPT")
    projection = independent_review_receipt_mapping(validated)
    return (
        projection,
        _expectation_mapping(expectation),
        validated.independent_review_receipt_sha256,
    )


def _rebuild_bundle_components(
    source_receipts: object,
    *,
    hard_gate_manifest: Mapping[str, object],
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    expected_artifact_receipts: Mapping[str, Mapping[str, object]],
    independent_review_expectation: IndependentReviewExpectation,
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, str]]:
    manifest_sha, gates, _bindings = _manifest_rows(hard_gate_manifest)
    if (
        not isinstance(source_receipts, Sequence)
        or isinstance(source_receipts, (str, bytes, bytearray))
        or len(source_receipts) != 17
    ):
        _reject("HARD_GATE_BUNDLE.SOURCE_COUNT")
    projections: list[dict[str, object]] = []
    evidence: list[dict[str, object]] = []
    owner_artifacts: dict[str, str] = {}
    seen_receipts: set[str] = set()
    for gate, item in zip(gates, source_receipts, strict=True):
        projection = dict(_mapping(item, "HARD_GATE_BUNDLE.SOURCE_RECEIPT"))
        digest = validate_hard_gate_source_receipt(
            projection,
            hard_gate_manifest=hard_gate_manifest,
            expected_artifact_receipts=expected_artifact_receipts,
            independent_review_expectation=independent_review_expectation,
        )
        if digest in seen_receipts:
            _reject("HARD_GATE_BUNDLE.DUPLICATE_SOURCE")
        seen_receipts.add(digest)
        if (
            projection.get("hard_gate_manifest_sha256") != manifest_sha
            or projection.get("gate_id") != gate.get("gate_id")
            or projection.get("evidence_owner") != gate.get("evidence_owner")
        ):
            _reject("HARD_GATE_BUNDLE.SOURCE_ORDER")
        if (
            projection.get("candidate_plan_freeze_receipt_sha256")
            != candidate_plan_freeze_receipt_sha256
            or projection.get("challenge_attempt_receipt_sha256")
            != challenge_attempt_receipt_sha256
        ):
            _reject("HARD_GATE_BUNDLE.STALE_SOURCE")
        artifacts = projection.get("ordered_source_artifacts")
        if type(artifacts) is not list:
            _reject("HARD_GATE_BUNDLE.SOURCE_RECEIPT")
        for artifact in artifacts:
            row = _mapping(artifact, "HARD_GATE_BUNDLE.SOURCE_RECEIPT")
            artifact_id = cast(str, row["artifact_id"])
            artifact_sha = cast(str, row["artifact_sha256"])
            prior = owner_artifacts.get(artifact_id)
            if prior is not None and prior != artifact_sha:
                _reject("HARD_GATE_BUNDLE.CONTRADICTORY_ARTIFACT")
            owner_artifacts[artifact_id] = artifact_sha
        evidence.append(
            {
                "schema_version": _EVIDENCE_SCHEMA_VERSION,
                "gate_id": projection["gate_id"],
                "preserved_invariant_ids": gate["preserved_invariant_ids"],
                "evidence_owner": projection["evidence_owner"],
                "source_artifact_sha256": projection["source_artifact_sha256"],
                "observed_facts_sha256": projection["observed_facts_sha256"],
                "state": "PASS",
                "failure_code": None,
            }
        )
        projections.append(projection)
    try:
        _validate_final_gate_evidence(hard_gate_manifest, evidence, owner_artifacts)
    except Exception:
        _reject("HARD_GATE_BUNDLE.FINAL_EVIDENCE")
    return projections, evidence, owner_artifacts


def validate_hard_gate_evidence_bundle(
    bundle: Mapping[str, object],
    *,
    hard_gate_manifest: Mapping[str, object],
    expected_artifact_receipts: Mapping[str, Mapping[str, object]],
    independent_review_expectation: IndependentReviewExpectation,
) -> str:
    """Revalidate every retained source, review binding, and evidence row."""

    raw = _mapping(bundle, "HARD_GATE_BUNDLE.RECEIPT_OBJECT")
    if set(raw) != _BUNDLE_FIELDS:
        _reject("HARD_GATE_BUNDLE.RECEIPT_FIELDS")
    manifest_sha, _gates, _bindings = _manifest_rows(hard_gate_manifest)
    freeze_sha = raw.get("candidate_plan_freeze_receipt_sha256")
    challenge_sha = raw.get("challenge_attempt_receipt_sha256")
    if (
        raw.get("schema_version") != _BUNDLE_SCHEMA_VERSION
        or raw.get("hard_gate_manifest_sha256") != manifest_sha
        or not _is_sha256(freeze_sha)
        or not _is_sha256(challenge_sha)
    ):
        _reject("HARD_GATE_BUNDLE.IDENTITY")
    projections, evidence, owner_artifacts = _rebuild_bundle_components(
        raw.get("ordered_source_receipts"),
        hard_gate_manifest=hard_gate_manifest,
        candidate_plan_freeze_receipt_sha256=cast(str, freeze_sha),
        challenge_attempt_receipt_sha256=cast(str, challenge_sha),
        expected_artifact_receipts=expected_artifact_receipts,
        independent_review_expectation=independent_review_expectation,
    )
    review, expectation, review_sha = _validated_review(
        raw.get("independent_review_receipt"),
        raw.get("independent_review_expectation"),
        candidate_plan_freeze_receipt_sha256=cast(str, freeze_sha),
        challenge_attempt_receipt_sha256=cast(str, challenge_sha),
    )
    if expectation != _expectation_mapping(independent_review_expectation):
        _reject("HARD_GATE_BUNDLE.REVIEW_BINDING")
    review_artifact = owner_artifacts.get("INDEPENDENT_REVIEW_RECEIPT")
    if review_artifact != review_sha:
        _reject("HARD_GATE_BUNDLE.REVIEW_BINDING")
    if (
        raw.get("ordered_source_receipts") != projections
        or raw.get("hard_gate_evidence") != evidence
        or raw.get("hard_gate_owner_artifact_sha256") != owner_artifacts
        or raw.get("independent_review_receipt") != review
        or raw.get("independent_review_receipt_sha256") != review_sha
        or raw.get("independent_review_expectation") != expectation
    ):
        _reject("HARD_GATE_BUNDLE.PROJECTION_MISMATCH")
    digest = raw.get("hard_gate_evidence_bundle_sha256")
    expected = structured_sha256_hex(
        _BUNDLE_DIGEST_DOMAIN,
        _without_digest(raw, "hard_gate_evidence_bundle_sha256"),
    )
    if not _is_sha256(digest) or digest != expected:
        _reject("HARD_GATE_BUNDLE.RECEIPT_DIGEST")
    return expected


@dataclass(slots=True)
class _BundleState:
    canonical_bytes: bytes
    bundle_sha256: str
    manifest: dict[str, object]
    expected_artifact_receipts: dict[str, dict[str, object]]
    independent_review_expectation: IndependentReviewExpectation
    consumed: bool
    lock: RLock


@final
class HardGateEvidenceBundle(_OpaqueOwner):
    """Opaque owner of all 17 exact source receipts and evidence records."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> HardGateEvidenceBundle:
        raise TypeError("Hard-gate evidence bundles are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Hard-gate evidence bundles cannot be subclassed.")

    @property
    def digest(self) -> str:
        return _validated_bundle_owner(self)[0].bundle_sha256


_BUNDLE_STATES: OneShotWeakRegistry[HardGateEvidenceBundle, _BundleState]
_BUNDLE_STATES, _BUNDLE_ISSUER = create_one_shot_registry()


def _validated_bundle_owner(
    owner: object,
) -> tuple[_BundleState, dict[str, object]]:
    if type(owner) is not HardGateEvidenceBundle:
        _reject("HARD_GATE_BUNDLE.OPAQUE_OWNER_REQUIRED")
    try:
        state = _BUNDLE_STATES.read(owner)
        projection = strict_json_loads(state.canonical_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("HARD_GATE_BUNDLE.OPAQUE_OWNER_INVALID")
    if type(projection) is not dict:
        _reject("HARD_GATE_BUNDLE.OPAQUE_OWNER_INVALID")
    raw = cast(dict[str, object], projection)
    digest = validate_hard_gate_evidence_bundle(
        raw,
        hard_gate_manifest=state.manifest,
        expected_artifact_receipts=state.expected_artifact_receipts,
        independent_review_expectation=state.independent_review_expectation,
    )
    if digest != state.bundle_sha256 or canonical_json_bytes(raw) != state.canonical_bytes:
        _reject("HARD_GATE_BUNDLE.OPAQUE_OWNER_INVALID")
    return state, raw


def _issue_hard_gate_evidence_bundle(
    *,
    hard_gate_manifest: Mapping[str, object],
    candidate_plan_freeze_receipt_sha256: str,
    challenge_attempt_receipt_sha256: str,
    ordered_source_receipts: Sequence[HardGateSourceReceipt],
    independent_review_receipt: IndependentReviewReceipt,
    independent_review_expectation: IndependentReviewExpectation,
    expected_artifact_receipts: Mapping[str, Mapping[str, object]],
) -> HardGateEvidenceBundle:
    """Consume all 17 runner-authenticated source owners into one bundle."""

    manifest_sha, _gates, _bindings = _manifest_rows(hard_gate_manifest)
    if not _is_sha256(candidate_plan_freeze_receipt_sha256):
        _reject("HARD_GATE_BUNDLE.FREEZE_DIGEST")
    if not _is_sha256(challenge_attempt_receipt_sha256):
        _reject("HARD_GATE_BUNDLE.CHALLENGE_DIGEST")
    if len(ordered_source_receipts) != 17 or len(
        {id(row) for row in ordered_source_receipts}
    ) != 17:
        _reject("HARD_GATE_BUNDLE.SOURCE_COUNT")
    source_states: list[_SourceState] = []
    source_projections: list[dict[str, object]] = []
    for source_owner in ordered_source_receipts:
        state, projection, _binding = _validated_source_owner(source_owner)
        validate_hard_gate_source_receipt(
            projection,
            hard_gate_manifest=hard_gate_manifest,
            expected_artifact_receipts=expected_artifact_receipts,
            independent_review_expectation=independent_review_expectation,
        )
        source_states.append(state)
        source_projections.append(projection)
    projections, evidence, owner_artifacts = _rebuild_bundle_components(
        source_projections,
        hard_gate_manifest=hard_gate_manifest,
        candidate_plan_freeze_receipt_sha256=candidate_plan_freeze_receipt_sha256,
        challenge_attempt_receipt_sha256=challenge_attempt_receipt_sha256,
        expected_artifact_receipts=expected_artifact_receipts,
        independent_review_expectation=independent_review_expectation,
    )
    if type(independent_review_receipt) is not IndependentReviewReceipt or type(
        independent_review_expectation
    ) is not IndependentReviewExpectation:
        _reject("HARD_GATE_BUNDLE.REVIEW_RECEIPT")
    review, expectation, review_sha = _validated_review(
        independent_review_receipt_mapping(independent_review_receipt),
        _expectation_mapping(independent_review_expectation),
        candidate_plan_freeze_receipt_sha256=candidate_plan_freeze_receipt_sha256,
        challenge_attempt_receipt_sha256=challenge_attempt_receipt_sha256,
    )
    if owner_artifacts.get("INDEPENDENT_REVIEW_RECEIPT") != review_sha:
        _reject("HARD_GATE_BUNDLE.REVIEW_BINDING")
    receipt: dict[str, object] = {
        "schema_version": _BUNDLE_SCHEMA_VERSION,
        "hard_gate_manifest_sha256": manifest_sha,
        "candidate_plan_freeze_receipt_sha256": candidate_plan_freeze_receipt_sha256,
        "challenge_attempt_receipt_sha256": challenge_attempt_receipt_sha256,
        "ordered_source_receipts": projections,
        "hard_gate_evidence": evidence,
        "hard_gate_owner_artifact_sha256": owner_artifacts,
        "independent_review_receipt": review,
        "independent_review_receipt_sha256": review_sha,
        "independent_review_expectation": expectation,
        "hard_gate_evidence_bundle_sha256": None,
    }
    receipt["hard_gate_evidence_bundle_sha256"] = structured_sha256_hex(
        _BUNDLE_DIGEST_DOMAIN,
        _without_digest(receipt, "hard_gate_evidence_bundle_sha256"),
    )
    digest = validate_hard_gate_evidence_bundle(
        receipt,
        hard_gate_manifest=hard_gate_manifest,
        expected_artifact_receipts=expected_artifact_receipts,
        independent_review_expectation=independent_review_expectation,
    )
    ordered_states = sorted(source_states, key=id)
    for state in ordered_states:
        state.lock.acquire()
    try:
        if any(state.consumed for state in source_states):
            _reject("HARD_GATE_BUNDLE.SOURCE_REPLAY")
        bundle_owner = object.__new__(HardGateEvidenceBundle)
        _BUNDLE_ISSUER.bind_once(
            bundle_owner,
            _BundleState(
                canonical_bytes=canonical_json_bytes(receipt),
                bundle_sha256=digest,
                manifest=dict(hard_gate_manifest),
                expected_artifact_receipts={
                    artifact_id: dict(artifact_receipt)
                    for artifact_id, artifact_receipt in expected_artifact_receipts.items()
                },
                independent_review_expectation=independent_review_expectation,
                consumed=False,
                lock=RLock(),
            ),
        )
        for state in source_states:
            state.consumed = True
    finally:
        for state in reversed(ordered_states):
            state.lock.release()
    return bundle_owner


def hard_gate_evidence_bundle_projection(
    owner: HardGateEvidenceBundle,
) -> dict[str, object]:
    """Return a fresh durable bundle projection without consuming it."""

    _state, projection = _validated_bundle_owner(owner)
    return projection


def _hard_gate_evidence_bundle_validation_context(
    owner: HardGateEvidenceBundle,
) -> tuple[dict[str, dict[str, object]], IndependentReviewExpectation]:
    """Return the exact expectations retained by one opaque bundle owner."""

    state, _projection = _validated_bundle_owner(owner)
    return (
        {
            artifact_id: dict(receipt)
            for artifact_id, receipt in state.expected_artifact_receipts.items()
        },
        state.independent_review_expectation,
    )


class HardGateEvidenceBundleConsumer:
    """Consume one opaque 17-gate bundle exactly once across all consumers."""

    __slots__ = ()

    def consume(self, owner: HardGateEvidenceBundle) -> dict[str, object]:
        state, projection = _validated_bundle_owner(owner)
        with state.lock:
            if state.consumed:
                _reject("HARD_GATE_BUNDLE.REPLAY")
            state.consumed = True
        return projection


__all__ = [
    "HardGateEvidenceBundle",
    "HardGateEvidenceBundleConsumer",
    "HardGateSourceReceipt",
    "HardGateSourceReceiptConsumer",
    "ProportionalHardGateBundleError",
    "hard_gate_evidence_bundle_projection",
    "hard_gate_source_receipt_projection",
    "validate_hard_gate_evidence_bundle",
    "validate_hard_gate_source_receipt",
]
