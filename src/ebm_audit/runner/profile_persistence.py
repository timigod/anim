"""Manifest-last persistence for one exact finalized PROFILE result group."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, RLock
from typing import Any, SupportsIndex, cast, final
from weakref import ReferenceType, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.artifacts import PrivateArtifactStore
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
)
from ebm_audit.schema import validate_instance

from .profile_finalization import (
    ProfileFinalizedResultGroup,
    _ProfileFinalizedResultGroupSnapshot,
    _read_profile_finalized_result_group,
    _snapshot_profile_finalized_result_group,
)

_MANIFEST_SCHEMA_VERSION = "ebm-audit-profile-result-group-manifest/1.0"


class _ProfileResultGroupPublication:
    __slots__ = ("lock", "sealed_ref", "status", "token")

    def __init__(self) -> None:
        self.lock = RLock()
        self.sealed_ref: ReferenceType[SealedProfileResultGroup] | None = None
        self.status = "FRESH"
        self.token = object()


class _ProfileResultGroupStorePublications:
    __slots__ = ("entries", "lock")

    def __init__(self) -> None:
        self.entries: dict[str, tuple[PrivateArtifactStore, _ProfileResultGroupPublication]] = {}
        self.lock = RLock()


@dataclass(frozen=True, repr=False)
class _SealedProfileResultGroupState:
    publication: _ProfileResultGroupPublication
    publication_token: object
    group: ProfileFinalizedResultGroup
    store: PrivateArtifactStore
    run_root_id: str
    coordinate_ordinal: int
    profile_execution_identity_sha256: str
    ordered_analysis_spec_ids: tuple[str, str, str]
    result_paths: tuple[str, str, str]
    result_ids: tuple[str, str, str]
    result_digests: tuple[str, str, str]
    result_byte_lengths: tuple[int, int, int]
    manifest_path: str
    manifest_bytes: bytes


@dataclass(frozen=True, repr=False, slots=True)
class _SealedProfileResultGroupSnapshot:
    run_root_id: str
    coordinate_ordinal: int
    profile_execution_identity_sha256: str
    manifest_relative_path: str
    manifest_sha256: str
    result_count: int = field(default=3, init=False)


_GROUP_PUBLICATIONS: OneShotWeakRegistry[object, _ProfileResultGroupStorePublications]
_GROUP_PUBLICATION_ISSUER: OneShotRegistryIssuer[object, _ProfileResultGroupStorePublications]
(_GROUP_PUBLICATIONS, _GROUP_PUBLICATION_ISSUER) = create_one_shot_registry()
_GROUP_PUBLICATIONS_LOCK = Lock()

_SEALED_STATES: OneShotWeakRegistry[object, _SealedProfileResultGroupState]
_SEALED_STATE_ISSUER: OneShotRegistryIssuer[object, _SealedProfileResultGroupState]
(_SEALED_STATES, _SEALED_STATE_ISSUER) = create_one_shot_registry()


@final
class SealedProfileResultGroup:
    """Opaque proof that one PROFILE result group is sealed manifest-last."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> SealedProfileResultGroup:
        raise TypeError("Sealed profile result groups are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Sealed profile result groups cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Sealed profile result groups are immutable.")

    def __copy__(self) -> SealedProfileResultGroup:
        raise TypeError("Sealed profile result groups cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> SealedProfileResultGroup:
        raise TypeError("Sealed profile result groups cannot be copied or serialized.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Sealed profile result groups cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Sealed profile result groups cannot be copied or serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Sealed profile result groups cannot be copied or serialized.")

    def __repr__(self) -> str:
        return "SealedProfileResultGroup(<sealed>)"


def _publication_for(
    group: ProfileFinalizedResultGroup,
    store: PrivateArtifactStore,
) -> _ProfileResultGroupPublication:
    _read_profile_finalized_result_group(group)
    if type(store) is not PrivateArtifactStore:
        raise TypeError("A genuine private artifact store is required.")
    with _GROUP_PUBLICATIONS_LOCK:
        publications = _GROUP_PUBLICATIONS.get(group)
        if publications is None:
            publications = _ProfileResultGroupStorePublications()
            _GROUP_PUBLICATION_ISSUER.bind_once(group, publications)
    with publications.lock:
        store_identity = store.run_root_id
        entry = publications.entries.get(store_identity)
        if entry is not None:
            if entry[0].run_root_id != store_identity:
                raise TypeError(
                    "Profile result persistence detected a run-root identity collision."
                )
            return entry[1]
        publication = _ProfileResultGroupPublication()
        publications.entries[store_identity] = (store, publication)
        return publication


def _result_paths(coordinate_ordinal: int) -> tuple[str, str, str]:
    directory = f"profile-results/coordinate-{coordinate_ordinal:08d}"
    return cast(
        tuple[str, str, str],
        tuple(f"{directory}/candidate-{ordinal:08d}.json" for ordinal in range(3)),
    )


def _manifest_path(coordinate_ordinal: int) -> str:
    return f"profile-results/coordinate-{coordinate_ordinal:08d}/profile-result-group-manifest.json"


def _commit_exact(store: PrivateArtifactStore, path: str, content: bytes) -> bytes:
    try:
        store.write_bytes(path, content)
    except InvalidInputError as exc:
        if exc.code != "SPEC.OUTPUT_ALREADY_EXISTS":
            raise
    readback = store.read_bytes(path, maximum_bytes=len(content))
    if readback != content:
        raise InvalidInputError(
            "PROFILE.RESULT_GROUP_BYTES_MISMATCH",
            "A profile result-group artifact does not match its exact authority.",
        )
    return readback


def _manifest(
    snapshot: _ProfileFinalizedResultGroupSnapshot,
    store: PrivateArtifactStore,
) -> tuple[dict[str, Any], tuple[str, str, str]]:
    paths = _result_paths(snapshot.coordinate_ordinal)
    manifest = {
        "profile_result_group_manifest_schema_version": _MANIFEST_SCHEMA_VERSION,
        "manifest_kind": "PROFILE_RESULT_GROUP",
        "run_root_id": store.run_root_id,
        "profile_execution_identity_sha256": (snapshot.profile_execution_identity_sha256),
        "coordinate_ordinal": snapshot.coordinate_ordinal,
        "ordered_analysis_spec_ids": list(snapshot.ordered_analysis_spec_ids),
        "ordered_results": [
            {
                "candidate_ordinal": result.candidate_ordinal,
                "result_id": result.result_id,
                "relative_path": paths[result.candidate_ordinal],
                "byte_length": len(result.canonical_bytes),
                "sha256": exact_file_sha256(result.canonical_bytes),
            }
            for result in snapshot.results
        ],
    }
    validate_instance(
        manifest,
        "run-artifacts.schema.json",
        definition="ProfileResultGroupManifest",
    )
    return manifest, paths


def _read_sealed_profile_result_group(
    value: object,
) -> _SealedProfileResultGroupState:
    if type(value) is not SealedProfileResultGroup:
        raise TypeError("A genuine sealed profile result group is required.")
    try:
        state = _SEALED_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine sealed profile result group is required.") from None
    with state.publication.lock:
        sealed = None if state.publication.sealed_ref is None else state.publication.sealed_ref()
        if (
            state.publication_token is not state.publication.token
            or state.publication.status != "SEALED"
            or sealed is not value
            or type(state.store) is not PrivateArtifactStore
            or state.store.run_root_id != state.run_root_id
        ):
            raise TypeError("Sealed profile result-group authority changed.")
        snapshot = _snapshot_profile_finalized_result_group(state.group)
        manifest, paths = _manifest(snapshot, state.store)
        manifest_bytes = canonical_json_bytes(manifest)
        result_ids = cast(tuple[str, str, str], tuple(r.result_id for r in snapshot.results))
        result_digests = cast(
            tuple[str, str, str],
            tuple(exact_file_sha256(r.canonical_bytes) for r in snapshot.results),
        )
        result_lengths = cast(
            tuple[int, int, int], tuple(len(r.canonical_bytes) for r in snapshot.results)
        )
        if (
            snapshot.coordinate_ordinal != state.coordinate_ordinal
            or snapshot.profile_execution_identity_sha256 != state.profile_execution_identity_sha256
            or snapshot.ordered_analysis_spec_ids != state.ordered_analysis_spec_ids
            or paths != state.result_paths
            or result_ids != state.result_ids
            or result_digests != state.result_digests
            or result_lengths != state.result_byte_lengths
            or manifest_bytes != state.manifest_bytes
            or _manifest_path(snapshot.coordinate_ordinal) != state.manifest_path
        ):
            raise InvalidInputError(
                "PROFILE.RESULT_GROUP_AUTHORITY_MISMATCH",
                "The sealed profile result group no longer matches its authority.",
            )
        for result, path in zip(snapshot.results, paths, strict=True):
            readback = state.store.read_bytes(path, maximum_bytes=len(result.canonical_bytes))
            if (
                readback != result.canonical_bytes
                or exact_file_sha256(readback) != result_digests[result.candidate_ordinal]
            ):
                raise InvalidInputError(
                    "PROFILE.RESULT_GROUP_BYTES_MISMATCH",
                    "A sealed profile result artifact no longer matches its authority.",
                )
        manifest_readback = state.store.read_bytes(
            state.manifest_path, maximum_bytes=len(manifest_bytes)
        )
        decoded = strict_json_loads(manifest_readback)
        if (
            manifest_readback != manifest_bytes
            or type(decoded) is not dict
            or canonical_json_bytes(decoded) != manifest_readback
        ):
            raise InvalidInputError(
                "PROFILE.RESULT_GROUP_MANIFEST_MISMATCH",
                "The profile result-group manifest no longer matches its authority.",
            )
        validate_instance(
            decoded,
            "run-artifacts.schema.json",
            definition="ProfileResultGroupManifest",
        )
        _SEALED_STATES.require(value, state)
        return state


def _snapshot_sealed_profile_result_group(
    value: object,
) -> _SealedProfileResultGroupSnapshot:
    """Return only the fully revalidated receipt fields needed by coordination."""

    state = _read_sealed_profile_result_group(value)
    return _SealedProfileResultGroupSnapshot(
        run_root_id=state.run_root_id,
        coordinate_ordinal=state.coordinate_ordinal,
        profile_execution_identity_sha256=(state.profile_execution_identity_sha256),
        manifest_relative_path=state.manifest_path,
        manifest_sha256=exact_file_sha256(state.manifest_bytes),
    )


def seal_profile_result_group(
    group: ProfileFinalizedResultGroup,
    store: PrivateArtifactStore,
) -> SealedProfileResultGroup:
    """Persist three exact PROFILE results and publish their manifest last."""

    publication = _publication_for(group, store)
    with publication.lock:
        existing = None if publication.sealed_ref is None else publication.sealed_ref()
        if publication.status == "SEALED":
            if existing is None:
                raise TypeError("The sealed profile result-group capability was consumed.")
            _read_sealed_profile_result_group(existing)
            return existing
        if publication.status == "FRESH":
            publication.status = "ACTIVATING"
        if publication.status not in {"ACTIVATING", "RESULTS_DURABLE"}:
            raise TypeError("Profile result-group persistence state is invalid.")

        snapshot = _snapshot_profile_finalized_result_group(group)
        manifest, paths = _manifest(snapshot, store)
        for result, path in zip(snapshot.results, paths, strict=True):
            _commit_exact(store, path, result.canonical_bytes)
        for result, path in zip(snapshot.results, paths, strict=True):
            readback = store.read_bytes(path, maximum_bytes=len(result.canonical_bytes))
            if readback != result.canonical_bytes or exact_file_sha256(
                readback
            ) != exact_file_sha256(result.canonical_bytes):
                raise InvalidInputError(
                    "PROFILE.RESULT_GROUP_BYTES_MISMATCH",
                    "A profile result artifact is not durable with exact bytes.",
                )
        publication.status = "RESULTS_DURABLE"

        manifest_bytes = canonical_json_bytes(manifest)
        path = _manifest_path(snapshot.coordinate_ordinal)
        _commit_exact(store, path, manifest_bytes)
        sealed = object.__new__(SealedProfileResultGroup)
        state = _SealedProfileResultGroupState(
            publication=publication,
            publication_token=publication.token,
            group=group,
            store=store,
            run_root_id=store.run_root_id,
            coordinate_ordinal=snapshot.coordinate_ordinal,
            profile_execution_identity_sha256=(snapshot.profile_execution_identity_sha256),
            ordered_analysis_spec_ids=snapshot.ordered_analysis_spec_ids,
            result_paths=paths,
            result_ids=cast(tuple[str, str, str], tuple(r.result_id for r in snapshot.results)),
            result_digests=cast(
                tuple[str, str, str],
                tuple(exact_file_sha256(r.canonical_bytes) for r in snapshot.results),
            ),
            result_byte_lengths=cast(
                tuple[int, int, int],
                tuple(len(r.canonical_bytes) for r in snapshot.results),
            ),
            manifest_path=path,
            manifest_bytes=manifest_bytes,
        )
        _SEALED_STATE_ISSUER.bind_once(sealed, state)
        publication.sealed_ref = ref(sealed)
        publication.status = "SEALED"
        try:
            _read_sealed_profile_result_group(sealed)
        except BaseException:
            publication.sealed_ref = None
            publication.status = "RESULTS_DURABLE"
            raise
        return sealed


__all__ = ["SealedProfileResultGroup", "seal_profile_result_group"]
