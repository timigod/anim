"""Durable binding for one independent review of one exact challenge attempt.

The receipt records an independent attestation.  Its digest detects mutation,
but it does not authenticate either identity and does not create scientific
evidence.  The challenge artifacts and their meaning remain owned by the
artifacts named by the receipt.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Final, Literal, Never, cast

from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256_hex

_RECEIPT_DOMAIN: Final = "ebm-audit/independent-review-receipt/1"
_SCHEMA_VERSION: Final = "ebm-audit-independent-review-receipt/1.0"
_INDEPENDENCE_ATTESTATION: Final = "REVIEWER_IS_NOT_IMPLEMENTATION_OWNER"
_ACCEPTED_VERDICT: Final = "ACCEPTED"

type ReviewScope = Literal[
    "IMPLEMENTATION",
    "SCIENCE",
    "PRIVACY",
    "PROVENANCE",
    "HOSTILE_OUTPUTS",
    "INSTALL",
]
type GitObjectFormat = Literal["sha1", "sha256"]

REQUIRED_REVIEW_SCOPE: Final[tuple[ReviewScope, ...]] = (
    "IMPLEMENTATION",
    "SCIENCE",
    "PRIVACY",
    "PROVENANCE",
    "HOSTILE_OUTPUTS",
    "INSTALL",
)

_ALLOWED_FIELDS: Final = frozenset(
    {
        "schema_version",
        "candidate_git_object_format",
        "candidate_git_commit",
        "candidate_git_tree",
        "candidate_freeze_receipt_sha256",
        "challenge_attempt_receipt_sha256",
        "ordered_challenge_artifact_sha256",
        "reviewer_identity",
        "implementation_owner_identity",
        "independence_attestation",
        "verdict",
        "reviewed_scope",
        "unresolved_material_findings",
        "independent_review_receipt_sha256",
    }
)


class IndependentReviewReceiptValidationError(ValueError):
    """A classified rejection of an independent-review receipt."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Independent-review receipt validation failed.")


def _reject(code: str) -> Never:
    raise IndependentReviewReceiptValidationError(code)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_oid(value: object, object_format: object) -> bool:
    if type(value) is not str or object_format not in {"sha1", "sha256"}:
        return False
    expected_length = 40 if object_format == "sha1" else 64
    return len(value) == expected_length and all(
        character in "0123456789abcdef" for character in value
    )


def _is_identity(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 256
        and value == value.strip()
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _validate_binding_components(
    *,
    candidate_git_object_format: object,
    candidate_git_commit: object,
    candidate_git_tree: object,
    candidate_freeze_receipt_sha256: object,
    challenge_attempt_receipt_sha256: object,
    ordered_challenge_artifact_sha256: object,
) -> None:
    if candidate_git_object_format not in {"sha1", "sha256"}:
        _reject("INDEPENDENT_REVIEW.CANDIDATE_OBJECT_FORMAT")
    if not _is_git_oid(candidate_git_commit, candidate_git_object_format):
        _reject("INDEPENDENT_REVIEW.CANDIDATE_COMMIT")
    if not _is_git_oid(candidate_git_tree, candidate_git_object_format):
        _reject("INDEPENDENT_REVIEW.CANDIDATE_TREE")
    if not _is_sha256(candidate_freeze_receipt_sha256):
        _reject("INDEPENDENT_REVIEW.CANDIDATE_FREEZE_DIGEST")
    if not _is_sha256(challenge_attempt_receipt_sha256):
        _reject("INDEPENDENT_REVIEW.CHALLENGE_ATTEMPT_DIGEST")
    if (
        type(ordered_challenge_artifact_sha256) is not tuple
        or not ordered_challenge_artifact_sha256
        or any(not _is_sha256(value) for value in ordered_challenge_artifact_sha256)
    ):
        _reject("INDEPENDENT_REVIEW.CHALLENGE_ARTIFACTS")


@dataclass(frozen=True, slots=True)
class IndependentReviewExpectation:
    """Exact candidate and attempt identities expected by a receipt consumer."""

    candidate_git_object_format: GitObjectFormat
    candidate_git_commit: str
    candidate_git_tree: str
    candidate_freeze_receipt_sha256: str
    challenge_attempt_receipt_sha256: str
    ordered_challenge_artifact_sha256: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_binding_components(
            candidate_git_object_format=self.candidate_git_object_format,
            candidate_git_commit=self.candidate_git_commit,
            candidate_git_tree=self.candidate_git_tree,
            candidate_freeze_receipt_sha256=self.candidate_freeze_receipt_sha256,
            challenge_attempt_receipt_sha256=self.challenge_attempt_receipt_sha256,
            ordered_challenge_artifact_sha256=self.ordered_challenge_artifact_sha256,
        )


@dataclass(frozen=True, slots=True)
class IndependentReviewReceipt:
    """Validated immutable projection of one durable independent attestation."""

    schema_version: Literal["ebm-audit-independent-review-receipt/1.0"]
    candidate_git_object_format: GitObjectFormat
    candidate_git_commit: str
    candidate_git_tree: str
    candidate_freeze_receipt_sha256: str
    challenge_attempt_receipt_sha256: str
    ordered_challenge_artifact_sha256: tuple[str, ...]
    reviewer_identity: str
    implementation_owner_identity: str
    independence_attestation: Literal["REVIEWER_IS_NOT_IMPLEMENTATION_OWNER"]
    verdict: Literal["ACCEPTED"]
    reviewed_scope: tuple[ReviewScope, ...]
    unresolved_material_findings: tuple[object, ...]
    independent_review_receipt_sha256: str


def independent_review_receipt_mapping(
    receipt: IndependentReviewReceipt,
) -> dict[str, object]:
    """Return the exact JSON-model projection of a validated receipt."""

    if type(receipt) is not IndependentReviewReceipt:
        raise TypeError("A validated independent-review receipt is required.")
    return {
        "schema_version": receipt.schema_version,
        "candidate_git_object_format": receipt.candidate_git_object_format,
        "candidate_git_commit": receipt.candidate_git_commit,
        "candidate_git_tree": receipt.candidate_git_tree,
        "candidate_freeze_receipt_sha256": receipt.candidate_freeze_receipt_sha256,
        "challenge_attempt_receipt_sha256": receipt.challenge_attempt_receipt_sha256,
        "ordered_challenge_artifact_sha256": list(receipt.ordered_challenge_artifact_sha256),
        "reviewer_identity": receipt.reviewer_identity,
        "implementation_owner_identity": receipt.implementation_owner_identity,
        "independence_attestation": receipt.independence_attestation,
        "verdict": receipt.verdict,
        "reviewed_scope": list(receipt.reviewed_scope),
        "unresolved_material_findings": list(receipt.unresolved_material_findings),
        "independent_review_receipt_sha256": (receipt.independent_review_receipt_sha256),
    }


def independent_review_receipt_bytes(receipt: IndependentReviewReceipt) -> bytes:
    """Serialize a validated receipt as canonical JSON bytes."""

    return canonical_json_bytes(independent_review_receipt_mapping(receipt))


def _receipt_preimage(payload: Mapping[str, object]) -> dict[str, object]:
    preimage = dict(payload)
    preimage["independent_review_receipt_sha256"] = None
    return preimage


def _load_payload(
    source: Mapping[str, object] | bytes | bytearray | memoryview,
) -> dict[str, object]:
    if isinstance(source, (bytes, bytearray, memoryview)):
        loaded: object = strict_json_loads(source)
        if type(loaded) is not dict:
            _reject("INDEPENDENT_REVIEW.RECEIPT_OBJECT")
        payload = cast(dict[object, object], loaded)
        if any(type(key) is not str for key in payload):
            _reject("INDEPENDENT_REVIEW.RECEIPT_FIELDS")
        return cast(dict[str, object], payload)
    if not isinstance(source, Mapping):
        _reject("INDEPENDENT_REVIEW.RECEIPT_OBJECT")
    if any(type(key) is not str for key in source):
        _reject("INDEPENDENT_REVIEW.RECEIPT_FIELDS")
    return dict(source)


def _validate_expected_binding(
    receipt: IndependentReviewReceipt,
    expected: IndependentReviewExpectation,
) -> None:
    if type(expected) is not IndependentReviewExpectation:
        raise TypeError("An exact independent-review expectation is required.")
    if (
        receipt.candidate_git_object_format != expected.candidate_git_object_format
        or receipt.candidate_git_commit != expected.candidate_git_commit
        or receipt.candidate_git_tree != expected.candidate_git_tree
    ):
        _reject("INDEPENDENT_REVIEW.CANDIDATE_SUBSTITUTION")
    if receipt.candidate_freeze_receipt_sha256 != expected.candidate_freeze_receipt_sha256:
        _reject("INDEPENDENT_REVIEW.CANDIDATE_FREEZE_SUBSTITUTION")
    if receipt.challenge_attempt_receipt_sha256 != expected.challenge_attempt_receipt_sha256:
        _reject("INDEPENDENT_REVIEW.CHALLENGE_ATTEMPT_SUBSTITUTION")
    if receipt.ordered_challenge_artifact_sha256 != expected.ordered_challenge_artifact_sha256:
        _reject("INDEPENDENT_REVIEW.CHALLENGE_ARTIFACT_SUBSTITUTION")


def validate_independent_review_receipt(
    source: Mapping[str, object] | bytes | bytearray | memoryview,
    *,
    expected: IndependentReviewExpectation,
) -> IndependentReviewReceipt:
    """Validate exact fields, digest, independence, scope, and expected owners."""

    payload = _load_payload(source)
    if set(payload) != _ALLOWED_FIELDS:
        _reject("INDEPENDENT_REVIEW.RECEIPT_FIELDS")
    if payload["schema_version"] != _SCHEMA_VERSION:
        _reject("INDEPENDENT_REVIEW.SCHEMA_VERSION")

    artifact_values = payload["ordered_challenge_artifact_sha256"]
    if type(artifact_values) is not list:
        _reject("INDEPENDENT_REVIEW.CHALLENGE_ARTIFACTS")
    artifacts = tuple(artifact_values)
    _validate_binding_components(
        candidate_git_object_format=payload["candidate_git_object_format"],
        candidate_git_commit=payload["candidate_git_commit"],
        candidate_git_tree=payload["candidate_git_tree"],
        candidate_freeze_receipt_sha256=payload["candidate_freeze_receipt_sha256"],
        challenge_attempt_receipt_sha256=payload["challenge_attempt_receipt_sha256"],
        ordered_challenge_artifact_sha256=artifacts,
    )

    reviewer_identity = payload["reviewer_identity"]
    implementation_owner_identity = payload["implementation_owner_identity"]
    if not _is_identity(reviewer_identity) or not _is_identity(implementation_owner_identity):
        _reject("INDEPENDENT_REVIEW.IDENTITY")
    if reviewer_identity == implementation_owner_identity:
        _reject("INDEPENDENT_REVIEW.NOT_INDEPENDENT")
    if payload["independence_attestation"] != _INDEPENDENCE_ATTESTATION:
        _reject("INDEPENDENT_REVIEW.INDEPENDENCE_ATTESTATION")
    if payload["verdict"] != _ACCEPTED_VERDICT:
        _reject("INDEPENDENT_REVIEW.VERDICT")

    scope_values = payload["reviewed_scope"]
    if type(scope_values) is not list or tuple(scope_values) != REQUIRED_REVIEW_SCOPE:
        _reject("INDEPENDENT_REVIEW.REVIEW_SCOPE")
    findings = payload["unresolved_material_findings"]
    if type(findings) is not list or findings:
        _reject("INDEPENDENT_REVIEW.UNRESOLVED_MATERIAL_FINDINGS")

    receipt_digest = payload["independent_review_receipt_sha256"]
    if not _is_sha256(receipt_digest) or receipt_digest != structured_sha256_hex(
        _RECEIPT_DOMAIN,
        _receipt_preimage(payload),
    ):
        _reject("INDEPENDENT_REVIEW.RECEIPT_DIGEST")

    receipt = IndependentReviewReceipt(
        schema_version="ebm-audit-independent-review-receipt/1.0",
        candidate_git_object_format=cast(
            GitObjectFormat,
            payload["candidate_git_object_format"],
        ),
        candidate_git_commit=cast(str, payload["candidate_git_commit"]),
        candidate_git_tree=cast(str, payload["candidate_git_tree"]),
        candidate_freeze_receipt_sha256=cast(
            str,
            payload["candidate_freeze_receipt_sha256"],
        ),
        challenge_attempt_receipt_sha256=cast(
            str,
            payload["challenge_attempt_receipt_sha256"],
        ),
        ordered_challenge_artifact_sha256=cast(tuple[str, ...], artifacts),
        reviewer_identity=cast(str, reviewer_identity),
        implementation_owner_identity=cast(str, implementation_owner_identity),
        independence_attestation="REVIEWER_IS_NOT_IMPLEMENTATION_OWNER",
        verdict="ACCEPTED",
        reviewed_scope=REQUIRED_REVIEW_SCOPE,
        unresolved_material_findings=(),
        independent_review_receipt_sha256=receipt_digest,
    )
    _validate_expected_binding(receipt, expected)
    return receipt


def issue_independent_review_receipt(
    *,
    binding: IndependentReviewExpectation,
    reviewer_identity: str,
    implementation_owner_identity: str,
    independence_attestation: str,
    verdict: str,
    reviewed_scope: tuple[ReviewScope, ...],
    unresolved_material_findings: tuple[Mapping[str, object], ...],
) -> IndependentReviewReceipt:
    """Issue a self-digested receipt after every acceptance condition is explicit."""

    if type(binding) is not IndependentReviewExpectation:
        raise TypeError("An exact independent-review expectation is required.")
    payload: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "candidate_git_object_format": binding.candidate_git_object_format,
        "candidate_git_commit": binding.candidate_git_commit,
        "candidate_git_tree": binding.candidate_git_tree,
        "candidate_freeze_receipt_sha256": binding.candidate_freeze_receipt_sha256,
        "challenge_attempt_receipt_sha256": binding.challenge_attempt_receipt_sha256,
        "ordered_challenge_artifact_sha256": list(binding.ordered_challenge_artifact_sha256),
        "reviewer_identity": reviewer_identity,
        "implementation_owner_identity": implementation_owner_identity,
        "independence_attestation": independence_attestation,
        "verdict": verdict,
        "reviewed_scope": list(reviewed_scope),
        "unresolved_material_findings": [dict(finding) for finding in unresolved_material_findings],
        "independent_review_receipt_sha256": None,
    }
    payload["independent_review_receipt_sha256"] = structured_sha256_hex(
        _RECEIPT_DOMAIN,
        payload,
    )
    return validate_independent_review_receipt(payload, expected=binding)


class IndependentReviewReceiptConsumer:
    """Consume each valid receipt digest at most once in this consumer ledger."""

    __slots__ = ("_consumed_receipt_sha256", "_lock")

    def __init__(self) -> None:
        self._consumed_receipt_sha256: set[str] = set()
        self._lock = Lock()

    def consume(
        self,
        source: Mapping[str, object] | bytes | bytearray | memoryview,
        *,
        expected: IndependentReviewExpectation,
    ) -> IndependentReviewReceipt:
        """Validate and atomically consume one exact receipt; reject replay."""

        receipt = validate_independent_review_receipt(source, expected=expected)
        with self._lock:
            if receipt.independent_review_receipt_sha256 in self._consumed_receipt_sha256:
                _reject("INDEPENDENT_REVIEW.REPLAY")
            self._consumed_receipt_sha256.add(receipt.independent_review_receipt_sha256)
        return receipt


__all__ = [
    "REQUIRED_REVIEW_SCOPE",
    "IndependentReviewExpectation",
    "IndependentReviewReceipt",
    "IndependentReviewReceiptConsumer",
    "IndependentReviewReceiptValidationError",
    "independent_review_receipt_bytes",
    "independent_review_receipt_mapping",
    "issue_independent_review_receipt",
    "validate_independent_review_receipt",
]
