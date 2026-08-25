"""Durable receipt for one completed proportional challenge attempt.

The runner supplies already-validated post-execution facts.  This module does
not create seed material, invoke a backend, or execute a Fit.  It closes those
facts into canonical bytes, retains one opaque in-process owner, and supports
strict later validation of the durable projection.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from threading import RLock
from typing import Final, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol.canonical import (
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256_hex,
)
from ebm_audit.protocol.errors import CanonicalizationError

_RECEIPT_DOMAIN: Final = "ebm-audit/proportional-challenge-attempt-receipt/1"
_TERMINAL_VECTOR_DOMAIN: Final = (
    "ebm-audit/proportional-challenge-ordered-public-terminal-vector/1"
)
_INVOCATION_LEDGER_DOMAIN: Final = (
    "ebm-audit/proportional-challenge-fit-invocation-ledger/1"
)
_SCHEMA_VERSION: Final = "ebm-audit-proportional-challenge-attempt-receipt/1.1"
_EXPECTED_FIT_COUNT: Final = 104
_TERMINAL_TIMEOUT_SECONDS: Final = 10_500.0
_NO_TUNING_STATE: Final = "UNCHANGED_SINCE_CANDIDATE_FREEZE"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_RECEIPT_FIELDS: Final = frozenset(
    {
        "schema_version",
        "candidate_plan_freeze_receipt_sha256",
        "attempt_id",
        "proportional_operation_plan_sha256",
        "fresh_seed_commitment_sha256",
        "ordered_public_terminals",
        "ordered_public_terminal_result_vector_sha256",
        "ordered_fit_invocation_ledger",
        "fit_invocation_ledger_sha256",
        "fit_count",
        "monotonic_elapsed_seconds",
        "challenge_artifact_hashes",
        "no_result_conditioned_tuning_state",
        "proportional_challenge_attempt_receipt_sha256",
    }
)
_TERMINAL_FIELDS: Final = frozenset(
    {"operation_ordinal", "public_terminal_result_sha256", "backend_invoked"}
)
_INVOCATION_FIELDS: Final = frozenset(
    {
        "operation_ordinal",
        "operation_instance_id",
        "operation_plan_entry_sha256",
        "case_operation_join_key",
        "chain_plan_position",
        "chain_execution_id",
        "attempt_id",
        "attempt_ordinal",
        "authenticated_request_evidence_digest",
        "authenticated_execution_evidence_digest",
        "command_evidence_digest",
        "scientific_request_digest",
        "status",
        "finalized_result_record_sha256",
        "fitted_result_sha256",
    }
)
_JOIN_KEY_FIELDS: Final = frozenset(
    {
        "benchmark_subject_digest",
        "authenticated_batch_sha256",
        "case_id",
        "operation_instance_id",
    }
)


class ProportionalChallengeReceiptError(ValueError):
    """A malformed, substituted, mutated, or replayed challenge receipt."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> Never:
    raise ProportionalChallengeReceiptError(code)


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _is_attempt_id(value: object) -> bool:
    return type(value) is str and _ATTEMPT_ID.fullmatch(value) is not None


def _validated_elapsed(value: object) -> int | float:
    if (
        type(value) not in {int, float}
        or not math.isfinite(cast(float, value))
        or not 0 < cast(float, value) <= _TERMINAL_TIMEOUT_SECONDS
    ):
        _reject("CHALLENGE.ELAPSED_INVALID")
    return cast(int | float, value)


def _validated_artifact_hashes(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or not 1 <= len(value) <= 256:
        _reject("CHALLENGE.ARTIFACT_HASHES_INVALID")
    artifacts: dict[str, str] = {}
    for artifact_id, digest in value.items():
        if (
            type(artifact_id) is not str
            or _ARTIFACT_ID.fullmatch(artifact_id) is None
            or artifact_id.startswith("/")
            or any(part in {"", ".", ".."} for part in artifact_id.split("/"))
            or not _is_sha256(digest)
        ):
            _reject("CHALLENGE.ARTIFACT_HASHES_INVALID")
        artifacts[artifact_id] = cast(str, digest)
    return {artifact_id: artifacts[artifact_id] for artifact_id in sorted(artifacts)}


def _validated_terminals(value: object) -> tuple[list[dict[str, object]], list[str]]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or len(value) != _EXPECTED_FIT_COUNT
    ):
        _reject("CHALLENGE.TERMINAL_COUNT")
    terminals: list[dict[str, object]] = []
    digests: list[str] = []
    for ordinal, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != _TERMINAL_FIELDS:
            _reject("CHALLENGE.TERMINAL_FIELDS")
        if item.get("operation_ordinal") != ordinal or type(
            item.get("operation_ordinal")
        ) is not int:
            _reject("CHALLENGE.TERMINAL_ORDER")
        digest = item.get("public_terminal_result_sha256")
        if not _is_sha256(digest):
            _reject("CHALLENGE.TERMINAL_DIGEST")
        if item.get("backend_invoked") is not True:
            _reject("CHALLENGE.BACKEND_NOT_INVOKED")
        digest = cast(str, digest)
        digests.append(digest)
        terminals.append(
            {
                "operation_ordinal": ordinal,
                "public_terminal_result_sha256": digest,
                "backend_invoked": True,
            }
        )
    if len(set(digests)) != _EXPECTED_FIT_COUNT:
        _reject("CHALLENGE.TERMINAL_DUPLICATE")
    return terminals, digests


def _validated_invocation_ledger(value: object) -> list[dict[str, object]]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or len(value) != _EXPECTED_FIT_COUNT
    ):
        _reject("CHALLENGE.INVOCATION_COUNT")
    rows: list[dict[str, object]] = []
    operation_ids: set[str] = set()
    attempt_ids: set[str] = set()
    chain_execution_ids: set[str] = set()
    for ordinal, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != _INVOCATION_FIELDS:
            _reject("CHALLENGE.INVOCATION_FIELDS")
        operation_id = item.get("operation_instance_id")
        join_key = item.get("case_operation_join_key")
        chain_position = item.get("chain_plan_position")
        chain_execution_id = item.get("chain_execution_id")
        attempt_id = item.get("attempt_id")
        if (
            item.get("operation_ordinal") != ordinal
            or type(item.get("operation_ordinal")) is not int
        ):
            _reject("CHALLENGE.INVOCATION_ORDER")
        if type(operation_id) is not str or not operation_id or operation_id in operation_ids:
            _reject("CHALLENGE.INVOCATION_OPERATION_ID")
        if (
            not isinstance(join_key, Mapping)
            or set(join_key) != _JOIN_KEY_FIELDS
            or join_key.get("operation_instance_id") != operation_id
            or any(
                type(join_key.get(field)) is not str or not join_key.get(field)
                for field in _JOIN_KEY_FIELDS
            )
        ):
            _reject("CHALLENGE.INVOCATION_JOIN_KEY")
        if type(chain_position) is not int or chain_position != 0:
            _reject("CHALLENGE.INVOCATION_CHAIN_POSITION")
        if (
            not _is_attempt_id(chain_execution_id)
            or cast(str, chain_execution_id) in chain_execution_ids
            or not _is_attempt_id(attempt_id)
            or cast(str, attempt_id) in attempt_ids
        ):
            _reject("CHALLENGE.INVOCATION_ATTEMPT_ID")
        if item.get("attempt_ordinal") != 0 or type(item.get("attempt_ordinal")) is not int:
            _reject("CHALLENGE.INVOCATION_RETRY")
        for field in (
            "operation_plan_entry_sha256",
            "authenticated_request_evidence_digest",
            "authenticated_execution_evidence_digest",
            "command_evidence_digest",
            "scientific_request_digest",
            "finalized_result_record_sha256",
            "fitted_result_sha256",
        ):
            if not _is_sha256(item.get(field)):
                _reject(f"CHALLENGE.INVOCATION_DIGEST.{field.upper()}")
        fitted_result_digest = cast(str, item["fitted_result_sha256"])
        if item.get("status") not in {"SUCCESS", "CONVERGENCE_WARN"}:
            _reject("CHALLENGE.INVOCATION_STATUS")
        operation_ids.add(operation_id)
        chain_execution_ids.add(cast(str, chain_execution_id))
        attempt_ids.add(cast(str, attempt_id))
        rows.append(
            {
                "operation_ordinal": ordinal,
                "operation_instance_id": operation_id,
                "operation_plan_entry_sha256": item["operation_plan_entry_sha256"],
                "case_operation_join_key": dict(cast(Mapping[str, object], join_key)),
                "chain_plan_position": chain_position,
                "chain_execution_id": chain_execution_id,
                "attempt_id": attempt_id,
                "attempt_ordinal": 0,
                "authenticated_request_evidence_digest": item[
                    "authenticated_request_evidence_digest"
                ],
                "authenticated_execution_evidence_digest": item[
                    "authenticated_execution_evidence_digest"
                ],
                "command_evidence_digest": item["command_evidence_digest"],
                "scientific_request_digest": item["scientific_request_digest"],
                "status": item["status"],
                "finalized_result_record_sha256": item[
                    "finalized_result_record_sha256"
                ],
                "fitted_result_sha256": fitted_result_digest,
            }
        )
    return rows


def _receipt_preimage(receipt: Mapping[str, object]) -> dict[str, object]:
    return {
        field: receipt[field]
        for field in _RECEIPT_FIELDS
        if field != "proportional_challenge_attempt_receipt_sha256"
    }


def validate_proportional_challenge_attempt_receipt(
    receipt: Mapping[str, object],
) -> str:
    """Rebuild every strict field and return the canonical receipt digest."""

    if not isinstance(receipt, Mapping) or set(receipt) != _RECEIPT_FIELDS:
        _reject("CHALLENGE.RECEIPT_FIELDS")
    if receipt.get("schema_version") != _SCHEMA_VERSION:
        _reject("CHALLENGE.SCHEMA_VERSION")
    if not _is_attempt_id(receipt.get("attempt_id")):
        _reject("CHALLENGE.ATTEMPT_ID")
    for field in (
        "candidate_plan_freeze_receipt_sha256",
        "proportional_operation_plan_sha256",
        "fresh_seed_commitment_sha256",
    ):
        if not _is_sha256(receipt.get(field)):
            _reject(f"CHALLENGE.IDENTITY_INVALID.{field.upper()}")
    terminals, digests = _validated_terminals(receipt.get("ordered_public_terminals"))
    expected_vector_digest = structured_sha256_hex(_TERMINAL_VECTOR_DOMAIN, digests)
    if receipt.get("ordered_public_terminal_result_vector_sha256") != (
        expected_vector_digest
    ):
        _reject("CHALLENGE.TERMINAL_VECTOR_DIGEST")
    invocation_ledger = _validated_invocation_ledger(
        receipt.get("ordered_fit_invocation_ledger")
    )
    expected_ledger_digest = structured_sha256_hex(
        _INVOCATION_LEDGER_DOMAIN,
        invocation_ledger,
    )
    if receipt.get("fit_invocation_ledger_sha256") != expected_ledger_digest:
        _reject("CHALLENGE.INVOCATION_LEDGER_DIGEST")
    if receipt.get("fit_count") != len(invocation_ledger) or type(
        receipt.get("fit_count")
    ) is not int:
        _reject("CHALLENGE.FIT_COUNT")
    _validated_elapsed(receipt.get("monotonic_elapsed_seconds"))
    artifacts = _validated_artifact_hashes(receipt.get("challenge_artifact_hashes"))
    if receipt.get("challenge_artifact_hashes") != artifacts:
        _reject("CHALLENGE.ARTIFACT_HASHES_INVALID")
    if receipt.get("no_result_conditioned_tuning_state") != _NO_TUNING_STATE:
        _reject("CHALLENGE.RESULT_CONDITIONED_TUNING")
    digest = receipt.get("proportional_challenge_attempt_receipt_sha256")
    try:
        expected = structured_sha256_hex(_RECEIPT_DOMAIN, _receipt_preimage(receipt))
    except (CanonicalizationError, KeyError):
        _reject("CHALLENGE.CANONICALIZATION")
    if not _is_sha256(digest) or digest != expected:
        _reject("CHALLENGE.RECEIPT_DIGEST")
    if receipt.get("ordered_public_terminals") != terminals:
        _reject("CHALLENGE.TERMINAL_FIELDS")
    return expected


@dataclass(slots=True)
class _ReceiptState:
    canonical_bytes: bytes
    receipt_sha256: str
    consumed: bool
    lock: RLock


@final
class ProportionalChallengeAttemptReceipt:
    """Opaque owner of one exact, canonical post-execution receipt."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> ProportionalChallengeAttemptReceipt:
        raise TypeError("Proportional challenge receipts are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Proportional challenge receipts cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Proportional challenge receipts are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Proportional challenge receipts cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Proportional challenge receipts cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Proportional challenge receipts cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Proportional challenge receipts cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Proportional challenge receipts cannot be copied or serialized.")

    @property
    def digest(self) -> str:
        return _validated_owner_state(self).receipt_sha256


_STATES: OneShotWeakRegistry[ProportionalChallengeAttemptReceipt, _ReceiptState]
_STATES, _ISSUER = create_one_shot_registry()


def _validated_owner_state(owner: object) -> _ReceiptState:
    if type(owner) is not ProportionalChallengeAttemptReceipt:
        _reject("CHALLENGE.OPAQUE_OWNER_REQUIRED")
    try:
        state = _STATES.read(owner)
        projection = strict_json_loads(state.canonical_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        _reject("CHALLENGE.OPAQUE_OWNER_INVALID")
    if not isinstance(projection, dict):
        _reject("CHALLENGE.OPAQUE_OWNER_INVALID")
    digest = validate_proportional_challenge_attempt_receipt(projection)
    if digest != state.receipt_sha256 or canonical_json_bytes(projection) != (
        state.canonical_bytes
    ):
        _reject("CHALLENGE.OPAQUE_OWNER_INVALID")
    return state


def _validated_owner_projection(
    owner: object,
) -> tuple[_ReceiptState, dict[str, object]]:
    state = _validated_owner_state(owner)
    try:
        projection = strict_json_loads(state.canonical_bytes)
    except CanonicalizationError:
        _reject("CHALLENGE.OPAQUE_OWNER_INVALID")
    if not isinstance(projection, dict):
        _reject("CHALLENGE.OPAQUE_OWNER_INVALID")
    return state, cast(dict[str, object], projection)


def _issue_proportional_challenge_attempt_receipt(
    *,
    candidate_plan_freeze_receipt_sha256: str,
    attempt_id: str,
    proportional_operation_plan_sha256: str,
    fresh_seed_commitment_sha256: str,
    validated_public_terminals: Sequence[Mapping[str, object]],
    fit_count: int,
    invocation_ledger: Sequence[Mapping[str, object]],
    monotonic_elapsed_seconds: int | float,
    challenge_artifact_hashes: Mapping[str, object],
    no_result_conditioned_tuning_state: str,
) -> ProportionalChallengeAttemptReceipt:
    """Close facts supplied only by the already-authenticated runner path."""

    if not _is_attempt_id(attempt_id):
        _reject("CHALLENGE.ATTEMPT_ID")
    for field, value in (
        (
            "candidate_plan_freeze_receipt_sha256",
            candidate_plan_freeze_receipt_sha256,
        ),
        ("proportional_operation_plan_sha256", proportional_operation_plan_sha256),
        ("fresh_seed_commitment_sha256", fresh_seed_commitment_sha256),
    ):
        if not _is_sha256(value):
            _reject(f"CHALLENGE.IDENTITY_INVALID.{field.upper()}")
    ledger = _validated_invocation_ledger(invocation_ledger)
    if fit_count != len(ledger) or type(fit_count) is not int:
        _reject("CHALLENGE.FIT_COUNT")
    _validated_elapsed(monotonic_elapsed_seconds)
    if no_result_conditioned_tuning_state != _NO_TUNING_STATE:
        _reject("CHALLENGE.RESULT_CONDITIONED_TUNING")
    terminals, digests = _validated_terminals(validated_public_terminals)
    artifacts = _validated_artifact_hashes(challenge_artifact_hashes)
    receipt: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "candidate_plan_freeze_receipt_sha256": candidate_plan_freeze_receipt_sha256,
        "attempt_id": attempt_id,
        "proportional_operation_plan_sha256": proportional_operation_plan_sha256,
        "fresh_seed_commitment_sha256": fresh_seed_commitment_sha256,
        "ordered_public_terminals": terminals,
        "ordered_public_terminal_result_vector_sha256": structured_sha256_hex(
            _TERMINAL_VECTOR_DOMAIN,
            digests,
        ),
        "ordered_fit_invocation_ledger": ledger,
        "fit_invocation_ledger_sha256": structured_sha256_hex(
            _INVOCATION_LEDGER_DOMAIN,
            ledger,
        ),
        "fit_count": len(ledger),
        "monotonic_elapsed_seconds": monotonic_elapsed_seconds,
        "challenge_artifact_hashes": artifacts,
        "no_result_conditioned_tuning_state": no_result_conditioned_tuning_state,
        "proportional_challenge_attempt_receipt_sha256": None,
    }
    receipt["proportional_challenge_attempt_receipt_sha256"] = (
        structured_sha256_hex(_RECEIPT_DOMAIN, _receipt_preimage(receipt))
    )
    digest = validate_proportional_challenge_attempt_receipt(receipt)
    canonical = canonical_json_bytes(receipt)
    instance = object.__new__(ProportionalChallengeAttemptReceipt)
    _ISSUER.bind_once(
        instance,
        _ReceiptState(
            canonical_bytes=canonical,
            receipt_sha256=digest,
            consumed=False,
            lock=RLock(),
        ),
    )
    return instance


def proportional_challenge_attempt_receipt_projection(
    owner: ProportionalChallengeAttemptReceipt,
) -> dict[str, object]:
    """Return a fresh durable projection without consuming its opaque owner."""

    _state, projection = _validated_owner_projection(owner)
    return projection


class ProportionalChallengeAttemptReceiptConsumer:
    """Consume one opaque challenge receipt exactly once across all consumers."""

    __slots__ = ()

    def consume(
        self, owner: ProportionalChallengeAttemptReceipt
    ) -> dict[str, object]:
        state, projection = _validated_owner_projection(owner)
        with state.lock:
            if state.consumed:
                _reject("CHALLENGE.REPLAY")
            state.consumed = True
        return projection


__all__ = [
    "ProportionalChallengeAttemptReceipt",
    "ProportionalChallengeAttemptReceiptConsumer",
    "ProportionalChallengeReceiptError",
    "proportional_challenge_attempt_receipt_projection",
    "validate_proportional_challenge_attempt_receipt",
]
