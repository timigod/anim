"""Live, non-decisive closeout for one profile-characterization run.

This module deliberately does not issue
``ProfileCharacterizationEvidenceReceipt/3``.  It preserves the exact live
completion authority and exposes a privacy-safe deterministic projection that
can be inspected before the process exits.  Profile selection and benchmark
freeze remain unavailable until the complete metric, comparison, and
independently reviewed transition-decision graph exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Never, SupportsIndex, cast, final
from weakref import ReferenceType, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256, strict_json_loads
from ebm_audit.runner.profile_characterization_run import (
    ProfileCharacterizationRunCompletion,
    _read_profile_characterization_run_completion,
)
from ebm_audit.runner.profile_finalization import (
    _ProfileFinalizedResultGroupSnapshot,
    _snapshot_profile_finalized_result_group,
)
from ebm_audit.runner.profile_persistence import (
    _read_sealed_profile_result_group,
    _SealedProfileResultGroupSnapshot,
    _snapshot_sealed_profile_result_group,
)

from .profile_characterization import project_profile_characterization_plan

_SCHEMA_VERSION = "ebm-audit-profile-characterization-live-evidence/1.0"
_KIND = "PROFILE_CHARACTERIZATION_LIVE_EVIDENCE_PRECURSOR"
_AUTHORITY_SCOPE = "LIVE_OWNER_PRECURSOR_NOT_PROFILE_CHARACTERIZATION_EVIDENCE_RECEIPT_V3"
_DECISION_STATE = "PENDING_INDEPENDENT_TRANSITION_RULE_REVIEW"
_SELECTION_OUTCOME = "NO_SELECTION"
_COORDINATE_COUNT = 6
_RESULTS_PER_COORDINATE = 3
_RESULT_COUNT = _COORDINATE_COUNT * _RESULTS_PER_COORDINATE


@dataclass(frozen=True, slots=True, repr=False)
class _LiveEvidenceState:
    completion: ProfileCharacterizationRunCompletion
    projection_bytes: bytes


class _LiveEvidencePublication:
    __slots__ = ("lock", "owner_ref", "status")

    def __init__(self) -> None:
        self.lock = RLock()
        self.owner_ref: ReferenceType[ProfileCharacterizationLiveEvidence] | None = None
        self.status = "FRESH"


_EVIDENCE_STATES: OneShotWeakRegistry[object, _LiveEvidenceState]
_EVIDENCE_STATE_ISSUER: OneShotRegistryIssuer[object, _LiveEvidenceState]
(_EVIDENCE_STATES, _EVIDENCE_STATE_ISSUER) = create_one_shot_registry()

_PUBLICATIONS: OneShotWeakRegistry[object, _LiveEvidencePublication]
_PUBLICATION_ISSUER: OneShotRegistryIssuer[object, _LiveEvidencePublication]
(_PUBLICATIONS, _PUBLICATION_ISSUER) = create_one_shot_registry()
_PUBLICATIONS_LOCK = RLock()


@final
class ProfileCharacterizationLiveEvidence:
    """Opaque live owner of one non-decisive characterization closeout."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> ProfileCharacterizationLiveEvidence:
        raise TypeError("Profile-characterization live evidence is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Profile-characterization live evidence cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Profile-characterization live evidence is immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Profile-characterization live evidence cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Profile-characterization live evidence cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Profile-characterization live evidence cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Profile-characterization live evidence cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Profile-characterization live evidence cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_live_evidence(self)
        return "ProfileCharacterizationLiveEvidence(<non-decisive-live-closeout>)"


def _closed_result_rows(
    snapshot: _ProfileFinalizedResultGroupSnapshot,
    *,
    coordinate_ordinal: int,
    profile_execution_identity_sha256: str,
) -> list[dict[str, Any]]:
    if (
        type(snapshot) is not _ProfileFinalizedResultGroupSnapshot
        or snapshot.coordinate_ordinal != coordinate_ordinal
        or snapshot.profile_execution_identity_sha256 != profile_execution_identity_sha256
        or type(snapshot.ordered_analysis_spec_ids) is not tuple
        or len(snapshot.ordered_analysis_spec_ids) != _RESULTS_PER_COORDINATE
        or type(snapshot.results) is not tuple
        or len(snapshot.results) != _RESULTS_PER_COORDINATE
        or tuple(row.candidate_ordinal for row in snapshot.results) != (0, 1, 2)
    ):
        raise TypeError("Profile-characterization finalized result ownership changed.")

    rows: list[dict[str, Any]] = []
    for candidate_ordinal, (analysis_spec_id, result) in enumerate(
        zip(
            snapshot.ordered_analysis_spec_ids,
            snapshot.results,
            strict=True,
        )
    ):
        if (
            type(analysis_spec_id) is not str
            or not analysis_spec_id
            or type(result.result_id) is not str
            or not result.result_id
            or type(result.canonical_bytes) is not bytes
        ):
            raise TypeError("Profile-characterization finalized result storage changed.")
        try:
            record = strict_json_loads(result.canonical_bytes)
        except (TypeError, ValueError):
            raise TypeError(
                "Profile-characterization finalized result is not canonical JSON."
            ) from None
        if (
            type(record) is not dict
            or canonical_json_bytes(record) != result.canonical_bytes
            or record.get("result_id") != result.result_id
            or type(record.get("body")) is not dict
        ):
            raise TypeError("Profile-characterization finalized result storage changed.")
        body = cast(dict[str, Any], record["body"])
        convergence = body.get("convergence")
        convergence_assessment: str | None
        if convergence is None:
            convergence_assessment = None
        elif type(convergence) is dict and type(convergence.get("assessment")) is str:
            convergence_assessment = cast(str, convergence["assessment"])
        else:
            raise TypeError("Profile-characterization finalized convergence storage changed.")
        if (
            body.get("candidate_ordinal") != candidate_ordinal
            or body.get("analysis_spec_id") != analysis_spec_id
            or type(body.get("record_kind")) is not str
            or type(body.get("status")) is not str
        ):
            raise TypeError("Profile-characterization finalized result binding changed.")
        rows.append(
            {
                "coordinate_ordinal": coordinate_ordinal,
                "candidate_ordinal": candidate_ordinal,
                "analysis_spec_id": analysis_spec_id,
                "result_id": result.result_id,
                "result_byte_length": len(result.canonical_bytes),
                "result_sha256": exact_file_sha256(result.canonical_bytes),
                "record_kind": body["record_kind"],
                "status": body["status"],
                "convergence_assessment": convergence_assessment,
            }
        )
    return rows


def _coordinate_projection(
    *,
    coordinate_ordinal: int,
    receipt: _SealedProfileResultGroupSnapshot,
    finalized: _ProfileFinalizedResultGroupSnapshot,
    coordinate_bytes: bytes,
    profile_execution_identity_sha256: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if (
        type(receipt) is not _SealedProfileResultGroupSnapshot
        or receipt.coordinate_ordinal != coordinate_ordinal
        or receipt.profile_execution_identity_sha256 != profile_execution_identity_sha256
        or receipt.result_count != _RESULTS_PER_COORDINATE
    ):
        raise TypeError("Profile-characterization sealed coordinate ownership changed.")
    result_rows = _closed_result_rows(
        finalized,
        coordinate_ordinal=coordinate_ordinal,
        profile_execution_identity_sha256=profile_execution_identity_sha256,
    )
    return (
        {
            "coordinate_ordinal": coordinate_ordinal,
            "plan_coordinate_sha256": exact_file_sha256(coordinate_bytes),
            "result_group_manifest_relative_path": receipt.manifest_relative_path,
            "result_group_manifest_sha256": receipt.manifest_sha256,
            "result_count": receipt.result_count,
        },
        result_rows,
    )


def _projection_bytes_from_completion(
    completion: ProfileCharacterizationRunCompletion,
) -> bytes:
    state = _read_profile_characterization_run_completion(completion)
    authority = state.authority
    plan_projection = project_profile_characterization_plan(state.plan_owner)
    plan_receipt = plan_projection.get("plan_receipt")
    selection_policy = plan_receipt.get("selection_policy") if type(plan_receipt) is dict else None
    transition_policy = (
        selection_policy.get("transition_quality_policy")
        if type(selection_policy) is dict
        else None
    )
    if (
        len(state.coordinate_owners) != _COORDINATE_COUNT
        or len(authority.coordinate_bytes) != _COORDINATE_COUNT
        or type(plan_receipt) is not dict
        or plan_receipt.get("profile_characterization_plan_receipt_sha256")
        != authority.plan_receipt_sha256
        or type(transition_policy) is not dict
        or transition_policy.get("review_state") != _DECISION_STATE
        or transition_policy.get("pre_review_selection_outcome") != _SELECTION_OUTCOME
    ):
        raise TypeError("Profile-characterization completion authority changed.")

    coordinate_rows: list[dict[str, Any]] = []
    result_rows: list[dict[str, Any]] = []
    for coordinate_ordinal, (owners, coordinate_bytes) in enumerate(
        zip(
            state.coordinate_owners,
            authority.coordinate_bytes,
            strict=True,
        )
    ):
        sealed_state = _read_sealed_profile_result_group(owners.sealed_result_group)
        if (
            sealed_state.group is not owners.finalized_group
            or sealed_state.store is not state.aggregate_store
        ):
            raise TypeError(
                "Profile-characterization sealed result does not own the finalized group."
            )
        receipt = _snapshot_sealed_profile_result_group(owners.sealed_result_group)
        if receipt != owners.sealed_receipt:
            raise TypeError("Profile-characterization sealed coordinate receipt changed.")
        finalized = _snapshot_profile_finalized_result_group(sealed_state.group)
        if (
            tuple(row.result_id for row in finalized.results) != sealed_state.result_ids
            or tuple(exact_file_sha256(row.canonical_bytes) for row in finalized.results)
            != sealed_state.result_digests
            or tuple(len(row.canonical_bytes) for row in finalized.results)
            != sealed_state.result_byte_lengths
        ):
            raise TypeError(
                "Profile-characterization sealed manifest does not bind the finalized results."
            )
        coordinate, results = _coordinate_projection(
            coordinate_ordinal=coordinate_ordinal,
            receipt=receipt,
            finalized=finalized,
            coordinate_bytes=coordinate_bytes,
            profile_execution_identity_sha256=(authority.profile_execution_identity_sha256),
        )
        coordinate_rows.append(coordinate)
        result_rows.extend(results)

    if (
        len(coordinate_rows) != _COORDINATE_COUNT
        or len(result_rows) != _RESULT_COUNT
        or [(row["coordinate_ordinal"], row["candidate_ordinal"]) for row in result_rows]
        != [
            (coordinate_ordinal, candidate_ordinal)
            for coordinate_ordinal in range(_COORDINATE_COUNT)
            for candidate_ordinal in range(_RESULTS_PER_COORDINATE)
        ]
    ):
        raise TypeError("Profile-characterization live evidence is incomplete.")

    projection = {
        "profile_characterization_live_evidence_schema_version": _SCHEMA_VERSION,
        "evidence_kind": _KIND,
        "authority_scope": _AUTHORITY_SCOPE,
        "decision_state": _DECISION_STATE,
        "selection_outcome": _SELECTION_OUTCOME,
        "profile_characterization_plan_receipt_sha256": (authority.plan_receipt_sha256),
        "profile_execution_identity_sha256": (authority.profile_execution_identity_sha256),
        "backend_identity_digest": authority.backend_identity_digest,
        "resolved_source_config_digest": authority.resolved_source_config_digest,
        "source_config_bytes_sha256": authority.source_config_bytes_sha256,
        "scenario_authority_bytes_sha256": (authority.scenario_authority_bytes_sha256),
        "worker_config_bytes_sha256": authority.worker_config_bytes_sha256,
        "run_root_id": state.aggregate_store.run_root_id,
        "aggregate_manifest_relative_path": state.manifest_path,
        "aggregate_manifest_sha256": exact_file_sha256(state.manifest_bytes),
        "coordinate_count": _COORDINATE_COUNT,
        "result_count": _RESULT_COUNT,
        "ordered_coordinate_receipts": coordinate_rows,
        "ordered_result_summaries": result_rows,
    }
    assert_no_direct_identifier_fields(projection)
    content = canonical_json_bytes(projection)
    decoded = strict_json_loads(content)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != content:
        raise TypeError("Profile-characterization live evidence is not canonical JSON.")
    return content


def _read_live_evidence(value: object) -> _LiveEvidenceState:
    if type(value) is not ProfileCharacterizationLiveEvidence:
        raise TypeError("A genuine profile-characterization live evidence owner is required.")
    try:
        state = _EVIDENCE_STATES[value]
    except (KeyError, TypeError):
        raise TypeError(
            "A genuine profile-characterization live evidence owner is required."
        ) from None
    current_bytes = _projection_bytes_from_completion(state.completion)
    if current_bytes != state.projection_bytes:
        raise TypeError("Profile-characterization live evidence changed after issuance.")
    _EVIDENCE_STATES.require(value, state)
    return state


def _publication_for(
    completion: ProfileCharacterizationRunCompletion,
) -> _LiveEvidencePublication:
    with _PUBLICATIONS_LOCK:
        publication = _PUBLICATIONS.get(completion)
        if publication is None:
            publication = _LiveEvidencePublication()
            _PUBLICATION_ISSUER.bind_once(completion, publication)
        return publication


def issue_profile_characterization_live_evidence(
    completion: ProfileCharacterizationRunCompletion,
) -> ProfileCharacterizationLiveEvidence:
    """Issue one live, non-decisive closeout for an exact completed run."""

    if type(completion) is not ProfileCharacterizationRunCompletion:
        raise TypeError("A genuine profile-characterization completion is required.")
    publication = _publication_for(completion)
    with publication.lock:
        existing = None if publication.owner_ref is None else publication.owner_ref()
        if publication.status == "ISSUED":
            if existing is None:
                raise TypeError(
                    "Profile-characterization live evidence was consumed and cannot be reissued."
                )
            _read_live_evidence(existing)
            return existing
        if publication.status != "FRESH":
            raise TypeError("Profile-characterization live evidence issuance cannot retry.")
        publication.status = "ISSUING"
        try:
            projection_bytes = _projection_bytes_from_completion(completion)
            owner = object.__new__(ProfileCharacterizationLiveEvidence)
            state = _LiveEvidenceState(
                completion=completion,
                projection_bytes=projection_bytes,
            )
            _EVIDENCE_STATE_ISSUER.bind_once(owner, state)
            publication.owner_ref = ref(owner)
            publication.status = "ISSUED"
            _read_live_evidence(owner)
            return owner
        except BaseException:
            publication.owner_ref = None
            publication.status = "FAILED"
            raise


def project_profile_characterization_live_evidence(
    owner: ProfileCharacterizationLiveEvidence,
) -> dict[str, Any]:
    """Project deterministic privacy-safe metadata without replacing authority."""

    state = _read_live_evidence(owner)
    projection = strict_json_loads(state.projection_bytes)
    if type(projection) is not dict:
        raise TypeError("Profile-characterization live evidence storage is invalid.")
    return cast(dict[str, Any], projection)


__all__ = [
    "ProfileCharacterizationLiveEvidence",
    "issue_profile_characterization_live_evidence",
    "project_profile_characterization_live_evidence",
]
