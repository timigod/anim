"""Serial six-coordinate execution for one sealed profile-characterization plan.

This is deliberately an internal-library coordinator.  It owns the fixed
coordinate traversal and exposes no caller-selected subset, order, retry,
backend, budget, or seed surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock, RLock
from typing import Any, Never, SupportsIndex, cast, final
from weakref import ReferenceType, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import WorkerConfig
from ebm_audit.artifacts import PrivateArtifactStore, StagedOutputTransaction
from ebm_audit.config import ResolvedAuditConfig
from ebm_audit.evaluator import (
    SealedProfileCharacterizationPlan,
    project_profile_characterization_plan,
)
from ebm_audit.evaluator.profile_characterization import (
    _require_profile_characterization_plan_provenance_current,
)
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.profile_input_identity import ProfileGeneratedInputBinding
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.synthetic.audit_input import (
    _issue_profile_case_execution_authorization,
    _open_profile_generated_input,
    _read_exact_source_inputs,
    _validated_profile_plan_projection,
)
from ebm_audit.synthetic.models import CaseCoordinate
from ebm_audit.universe import prepare_profile_candidate_group

from .profile_execution import run_profile_fit_session
from .profile_finalization import finalize_profile_fit_session
from .profile_fit_slots import issue_profile_fit_slot_group
from .profile_persistence import (
    _SealedProfileResultGroupSnapshot,
    _snapshot_sealed_profile_result_group,
    seal_profile_result_group,
)
from .profile_validation import (
    ProfileValidationBarrier,
    run_profile_validation_session,
)

_COORDINATE_COUNT = 6
_RESULT_COUNT = 18
_FIT_COUNT = 54
_RESULTS_PER_COORDINATE = 3
_FITS_PER_COORDINATE = 9
_AGGREGATE_MANIFEST_PATH = "profile-characterization/profile-characterization-run-manifest.json"
_AGGREGATE_SCHEMA_VERSION = "ebm-audit-profile-characterization-run-manifest/1.0"
_AGGREGATE_SCHEMA_NAME = "profile-characterization-run.schema.json"

type _SixCoordinateReceipts = tuple[
    _SealedProfileResultGroupSnapshot,
    _SealedProfileResultGroupSnapshot,
    _SealedProfileResultGroupSnapshot,
    _SealedProfileResultGroupSnapshot,
    _SealedProfileResultGroupSnapshot,
    _SealedProfileResultGroupSnapshot,
]


@dataclass(frozen=True, slots=True, repr=False)
class _ProfileCharacterizationRunAuthority:
    plan_receipt_sha256: str
    profile_execution_identity_sha256: str
    backend_identity_digest: str
    resolved_source_config_digest: str
    source_config_bytes_sha256: str
    scenario_authority_bytes_sha256: str
    worker_config_bytes_sha256: str
    coordinates: tuple[
        CaseCoordinate,
        CaseCoordinate,
        CaseCoordinate,
        CaseCoordinate,
        CaseCoordinate,
        CaseCoordinate,
    ]
    coordinate_bytes: tuple[bytes, bytes, bytes, bytes, bytes, bytes]


@dataclass(frozen=True, slots=True, repr=False)
class _CoordinateOwners:
    authorization: object
    staging: StagedOutputTransaction
    input_binding: ProfileGeneratedInputBinding
    prepared_group: object
    validation_session: object
    validation_barrier: ProfileValidationBarrier
    fit_slot_group: object
    fit_session: object
    finalized_group: object
    sealed_result_group: object
    sealed_receipt: _SealedProfileResultGroupSnapshot


class _ProfileCharacterizationRunPublication:
    __slots__ = (
        "completion_ref",
        "lock",
        "source_config",
        "status",
        "token",
    )

    def __init__(self, source_config: ResolvedAuditConfig) -> None:
        self.completion_ref: ReferenceType[ProfileCharacterizationRunCompletion] | None = None
        self.lock = RLock()
        self.source_config = source_config
        self.status = "FRESH"
        self.token = object()


@dataclass(frozen=True, slots=True, repr=False)
class _ProfileCharacterizationRunCompletionState:
    publication: _ProfileCharacterizationRunPublication
    publication_token: object
    plan_owner: SealedProfileCharacterizationPlan
    source_config: ResolvedAuditConfig
    authority: _ProfileCharacterizationRunAuthority
    coordinate_owners: tuple[
        _CoordinateOwners,
        _CoordinateOwners,
        _CoordinateOwners,
        _CoordinateOwners,
        _CoordinateOwners,
        _CoordinateOwners,
    ]
    aggregate_store: PrivateArtifactStore
    manifest_path: str
    manifest_bytes: bytes


_RUN_PUBLICATIONS: OneShotWeakRegistry[object, _ProfileCharacterizationRunPublication]
_RUN_PUBLICATION_ISSUER: OneShotRegistryIssuer[object, _ProfileCharacterizationRunPublication]
(_RUN_PUBLICATIONS, _RUN_PUBLICATION_ISSUER) = create_one_shot_registry()
_RUN_PUBLICATIONS_LOCK = Lock()

_COMPLETION_STATES: OneShotWeakRegistry[object, _ProfileCharacterizationRunCompletionState]
_COMPLETION_STATE_ISSUER: OneShotRegistryIssuer[object, _ProfileCharacterizationRunCompletionState]
(_COMPLETION_STATES, _COMPLETION_STATE_ISSUER) = create_one_shot_registry()


@final
class ProfileCharacterizationRunCompletion:
    """Opaque live proof of one complete fixed six-coordinate run."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> ProfileCharacterizationRunCompletion:
        raise TypeError("Profile-characterization completions are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Profile-characterization completions cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Profile-characterization completions are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Profile-characterization completions cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Profile-characterization completions cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Profile-characterization completions cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Profile-characterization completions cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Profile-characterization completions cannot be copied or serialized.")

    def __repr__(self) -> str:
        _read_profile_characterization_run_completion(self)
        return "ProfileCharacterizationRunCompletion(<complete-six-coordinate-run>)"


def _raw_sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TypeError(f"The profile run has an invalid {label}.")
    return value


def _prefixed_sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise TypeError(f"The profile run has an invalid {label}.")
    return value


def _closed_coordinate(value: bytes) -> CaseCoordinate:
    try:
        coordinate = strict_json_loads(value)
    except (TypeError, ValueError):
        raise TypeError("A sealed profile coordinate is not canonical JSON.") from None
    if (
        type(coordinate) is not dict
        or canonical_json_bytes(coordinate) != value
        or set(coordinate) != {"family_id", "scenario_id", "replicate_index"}
        or type(coordinate.get("family_id")) is not str
        or type(coordinate.get("scenario_id")) is not str
        or type(coordinate.get("replicate_index")) is not int
        or cast(int, coordinate["replicate_index"]) < 0
    ):
        raise TypeError("A sealed profile coordinate is invalid.")
    return CaseCoordinate(
        family_id=cast(str, coordinate["family_id"]),
        variant_id=cast(str, coordinate["scenario_id"]),
        replicate_index=cast(int, coordinate["replicate_index"]),
    )


def _derive_run_authority(
    plan_owner: SealedProfileCharacterizationPlan,
    source_config: ResolvedAuditConfig,
) -> _ProfileCharacterizationRunAuthority:
    """Revalidate the plan and exact source bytes before any coordinate runs."""

    if type(plan_owner) is not SealedProfileCharacterizationPlan:
        raise TypeError("A genuine sealed profile-characterization plan is required.")
    if type(source_config) is not ResolvedAuditConfig:
        raise TypeError("A genuine resolved audit config is required.")

    _require_profile_characterization_plan_provenance_current(plan_owner)
    source_config_bytes, authority_bytes, worker_bytes = _read_exact_source_inputs(source_config)
    worker_config = WorkerConfig.from_yaml_bytes(worker_bytes)
    projection = _validated_profile_plan_projection(plan_owner, worker_config)
    detached = project_profile_characterization_plan(plan_owner)
    try:
        closed = strict_json_loads(canonical_json_bytes(detached))
    except (TypeError, ValueError):
        raise TypeError("The sealed profile plan projection is invalid.") from None
    if type(closed) is not dict or set(closed) != {
        "plan_receipt",
        "blocked_diagnostic",
        "execution_contract",
    }:
        raise TypeError("The sealed profile plan projection is incomplete.")
    execution_contract = closed.get("execution_contract")
    if type(execution_contract) is not dict:
        raise TypeError("The sealed profile plan has no execution contract.")
    backend_identity_digest = _prefixed_sha256(
        execution_contract.get("backend_identity_digest"),
        label="backend identity digest",
    )
    if (
        len(projection.coordinate_bytes) != _COORDINATE_COUNT
        or len(set(projection.coordinate_bytes)) != _COORDINATE_COUNT
    ):
        raise TypeError("The sealed profile plan must contain exactly six coordinates.")
    coordinates = tuple(_closed_coordinate(row) for row in projection.coordinate_bytes)
    return _ProfileCharacterizationRunAuthority(
        plan_receipt_sha256=_raw_sha256(
            projection.plan_receipt_sha256,
            label="plan receipt digest",
        ),
        profile_execution_identity_sha256=_raw_sha256(
            projection.profile_execution_identity_sha256,
            label="profile execution identity",
        ),
        backend_identity_digest=backend_identity_digest,
        resolved_source_config_digest=_prefixed_sha256(
            source_config.public_digest,
            label="resolved source-config digest",
        ),
        source_config_bytes_sha256=exact_file_sha256(source_config_bytes),
        scenario_authority_bytes_sha256=exact_file_sha256(authority_bytes),
        worker_config_bytes_sha256=exact_file_sha256(worker_bytes),
        coordinates=cast(
            tuple[
                CaseCoordinate,
                CaseCoordinate,
                CaseCoordinate,
                CaseCoordinate,
                CaseCoordinate,
                CaseCoordinate,
            ],
            coordinates,
        ),
        coordinate_bytes=cast(
            tuple[bytes, bytes, bytes, bytes, bytes, bytes],
            projection.coordinate_bytes,
        ),
    )


def _publication_for(
    plan_owner: SealedProfileCharacterizationPlan,
    source_config: ResolvedAuditConfig,
) -> _ProfileCharacterizationRunPublication:
    with _RUN_PUBLICATIONS_LOCK:
        publication = _RUN_PUBLICATIONS.get(plan_owner)
        if publication is None:
            publication = _ProfileCharacterizationRunPublication(source_config)
            _RUN_PUBLICATION_ISSUER.bind_once(plan_owner, publication)
        elif publication.source_config is not source_config:
            raise TypeError("The sealed profile plan is already bound to another source authority.")
        return publication


def _create_private_staging(
    source_config: ResolvedAuditConfig,
) -> StagedOutputTransaction:
    return StagedOutputTransaction.create(source_config.private_paths.output_root)


def _run_coordinate(
    *,
    plan_owner: SealedProfileCharacterizationPlan,
    source_config: ResolvedAuditConfig,
    coordinate: CaseCoordinate,
    coordinate_ordinal: int,
    staging: StagedOutputTransaction,
) -> _CoordinateOwners:
    """Run the existing one-use chain once for one internally selected coordinate."""

    authorization = _issue_profile_case_execution_authorization(
        plan_owner,
        source_config,
        coordinate,
    )
    input_binding = cast(
        ProfileGeneratedInputBinding,
        _open_profile_generated_input(authorization, staging),
    )
    prepared_group = prepare_profile_candidate_group(plan_owner, input_binding)
    validation_session = run_profile_validation_session(prepared_group)
    validation_barrier = validation_session.barrier
    if type(validation_barrier) is not ProfileValidationBarrier:
        raise TypeError("Profile validation did not issue the exact three-candidate barrier.")
    fit_slot_group = issue_profile_fit_slot_group(validation_barrier)
    _require_profile_characterization_plan_provenance_current(plan_owner)
    fit_session = run_profile_fit_session(fit_slot_group)
    finalized_group = finalize_profile_fit_session(fit_session)
    result_store = staging.store
    sealed_result_group = seal_profile_result_group(finalized_group, result_store)
    sealed_receipt = _snapshot_sealed_profile_result_group(sealed_result_group)
    if (
        type(sealed_receipt) is not _SealedProfileResultGroupSnapshot
        or sealed_receipt.run_root_id != result_store.run_root_id
        or sealed_receipt.coordinate_ordinal != coordinate_ordinal
        or sealed_receipt.profile_execution_identity_sha256
        != prepared_group.profile_execution_identity_sha256
        or sealed_receipt.result_count != _RESULTS_PER_COORDINATE
    ):
        raise TypeError("A sealed coordinate result receipt changed its exact owner.")
    return _CoordinateOwners(
        authorization=authorization,
        staging=staging,
        input_binding=input_binding,
        prepared_group=prepared_group,
        validation_session=validation_session,
        validation_barrier=validation_barrier,
        fit_slot_group=fit_slot_group,
        fit_session=fit_session,
        finalized_group=finalized_group,
        sealed_result_group=sealed_result_group,
        sealed_receipt=sealed_receipt,
    )


def _aggregate_manifest(
    authority: _ProfileCharacterizationRunAuthority,
    receipts: _SixCoordinateReceipts,
    store: PrivateArtifactStore,
) -> dict[str, Any]:
    if (
        len(receipts) != _COORDINATE_COUNT
        or tuple(row.coordinate_ordinal for row in receipts) != tuple(range(_COORDINATE_COUNT))
        or any(row.run_root_id != store.run_root_id for row in receipts)
        or any(
            row.profile_execution_identity_sha256 != authority.profile_execution_identity_sha256
            for row in receipts
        )
        or any(row.result_count != _RESULTS_PER_COORDINATE for row in receipts)
    ):
        raise TypeError("The aggregate profile manifest has incomplete coordinate receipts.")
    manifest = {
        "profile_characterization_run_manifest_schema_version": (_AGGREGATE_SCHEMA_VERSION),
        "manifest_kind": "PROFILE_CHARACTERIZATION_RUN",
        "completion_state": "COMPLETE",
        "run_root_id": store.run_root_id,
        "profile_characterization_plan_receipt_sha256": (authority.plan_receipt_sha256),
        "profile_execution_identity_sha256": (authority.profile_execution_identity_sha256),
        "backend_identity_digest": authority.backend_identity_digest,
        "resolved_source_config_digest": authority.resolved_source_config_digest,
        "source_config_bytes_sha256": authority.source_config_bytes_sha256,
        "scenario_authority_bytes_sha256": (authority.scenario_authority_bytes_sha256),
        "worker_config_bytes_sha256": authority.worker_config_bytes_sha256,
        "coordinate_count": _COORDINATE_COUNT,
        "result_count": _RESULT_COUNT,
        "fit_count": _FIT_COUNT,
        "ordered_coordinate_receipts": [
            {
                "coordinate_ordinal": ordinal,
                "plan_coordinate_sha256": exact_file_sha256(authority.coordinate_bytes[ordinal]),
                "run_root_id": receipt.run_root_id,
                "profile_execution_identity_sha256": (receipt.profile_execution_identity_sha256),
                "result_group_manifest_relative_path": (receipt.manifest_relative_path),
                "result_group_manifest_sha256": receipt.manifest_sha256,
                "result_count": _RESULTS_PER_COORDINATE,
                "fit_count": _FITS_PER_COORDINATE,
            }
            for ordinal, receipt in enumerate(receipts)
        ],
    }
    assert_no_direct_identifier_fields(manifest)
    _validate_aggregate_manifest(manifest)
    return manifest


def _validate_aggregate_manifest(manifest: dict[str, Any]) -> None:
    try:
        validate_instance(
            manifest,
            _AGGREGATE_SCHEMA_NAME,
            definition="ProfileCharacterizationRunManifest",
        )
    except SchemaValidationError:
        raise TypeError("The profile-characterization aggregate manifest is invalid.") from None


def _write_aggregate_manifest(
    store: PrivateArtifactStore,
    manifest: dict[str, Any],
) -> bytes:
    """Write the sole run-completion artifact after all coordinate manifests."""

    content = canonical_json_bytes(manifest)
    store.write_bytes(_AGGREGATE_MANIFEST_PATH, content)
    readback = store.read_bytes(
        _AGGREGATE_MANIFEST_PATH,
        maximum_bytes=len(content),
    )
    if readback != content:
        raise TypeError("The aggregate profile manifest failed exact readback.")
    return readback


def _read_profile_characterization_run_completion(
    value: object,
) -> _ProfileCharacterizationRunCompletionState:
    if type(value) is not ProfileCharacterizationRunCompletion:
        raise TypeError("A genuine profile-characterization completion is required.")
    try:
        state = _COMPLETION_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine profile-characterization completion is required.") from None
    with state.publication.lock:
        current = (
            None if state.publication.completion_ref is None else state.publication.completion_ref()
        )
        if (
            state.publication_token is not state.publication.token
            or state.publication.status != "COMPLETE"
            or current is not value
            or state.publication.source_config is not state.source_config
        ):
            raise TypeError("Profile-characterization completion authority changed.")
        authority = _derive_run_authority(state.plan_owner, state.source_config)
        receipts = cast(
            _SixCoordinateReceipts,
            tuple(
                _snapshot_sealed_profile_result_group(owner.sealed_result_group)
                for owner in state.coordinate_owners
            ),
        )
        manifest = _aggregate_manifest(authority, receipts, state.aggregate_store)
        expected_bytes = canonical_json_bytes(manifest)
        readback = state.aggregate_store.read_bytes(
            state.manifest_path,
            maximum_bytes=len(expected_bytes),
        )
        if (
            authority != state.authority
            or receipts != tuple(owner.sealed_receipt for owner in state.coordinate_owners)
            or state.manifest_path != _AGGREGATE_MANIFEST_PATH
            or state.manifest_bytes != expected_bytes
            or readback != expected_bytes
        ):
            raise TypeError("Profile-characterization completion readback changed.")
        _COMPLETION_STATES.require(value, state)
        return state


def run_profile_characterization(
    plan_owner: SealedProfileCharacterizationPlan,
    source_config: ResolvedAuditConfig,
) -> ProfileCharacterizationRunCompletion:
    """Run exactly six plan coordinates serially and publish completion last."""

    authority = _derive_run_authority(plan_owner, source_config)
    publication = _publication_for(plan_owner, source_config)
    with publication.lock:
        existing = None if publication.completion_ref is None else publication.completion_ref()
        if publication.status == "COMPLETE":
            if existing is None:
                raise TypeError("The profile-characterization completion capability was consumed.")
            _read_profile_characterization_run_completion(existing)
            return existing
        if publication.status != "FRESH":
            raise TypeError("The profile-characterization run cannot retry an incomplete root.")
        publication.status = "RUNNING"

        coordinate_owners: list[_CoordinateOwners] = []
        try:
            staging = _create_private_staging(source_config)
            aggregate_store = staging.store
            for coordinate_ordinal, coordinate in enumerate(authority.coordinates):
                owners = _run_coordinate(
                    plan_owner=plan_owner,
                    source_config=source_config,
                    coordinate=coordinate,
                    coordinate_ordinal=coordinate_ordinal,
                    staging=staging,
                )
                coordinate_owners.append(owners)

            if len(coordinate_owners) != _COORDINATE_COUNT:
                raise TypeError("The profile-characterization run is incomplete.")
            retained_owners = cast(
                tuple[
                    _CoordinateOwners,
                    _CoordinateOwners,
                    _CoordinateOwners,
                    _CoordinateOwners,
                    _CoordinateOwners,
                    _CoordinateOwners,
                ],
                tuple(coordinate_owners),
            )
            receipts = cast(
                _SixCoordinateReceipts,
                tuple(owner.sealed_receipt for owner in retained_owners),
            )
            manifest = _aggregate_manifest(authority, receipts, aggregate_store)
            _require_profile_characterization_plan_provenance_current(plan_owner)
            manifest_bytes = _write_aggregate_manifest(aggregate_store, manifest)
            completion = object.__new__(ProfileCharacterizationRunCompletion)
            state = _ProfileCharacterizationRunCompletionState(
                publication=publication,
                publication_token=publication.token,
                plan_owner=plan_owner,
                source_config=source_config,
                authority=authority,
                coordinate_owners=retained_owners,
                aggregate_store=aggregate_store,
                manifest_path=_AGGREGATE_MANIFEST_PATH,
                manifest_bytes=manifest_bytes,
            )
            _COMPLETION_STATE_ISSUER.bind_once(completion, state)
            publication.completion_ref = ref(completion)
            publication.status = "COMPLETE"
            _read_profile_characterization_run_completion(completion)
            return completion
        except BaseException:
            publication.completion_ref = None
            publication.status = "FAILED"
            raise


__all__ = [
    "ProfileCharacterizationRunCompletion",
    "run_profile_characterization",
]
