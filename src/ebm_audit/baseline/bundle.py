"""Fail-closed import of one canonical three-file baseline reference bundle."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.workers.arrays import _load_catalogued_npz_arrays_handle

from .reproduction import (
    BaselineReproductionError,
    VerifiedReferenceAlignmentOwner,
    VerifiedReferenceResult,
    _reverify_imported_reference_owner,
    _verify_private_alignment_artifact,
    issue_verified_reference_alignment_owner,
    issue_verified_reference_result,
)

if TYPE_CHECKING:
    from ebm_audit.results.finalization import FinalizedResult

BASELINE_REFERENCE_BUNDLE_SCHEMA_VERSION = "ebm-audit-baseline-reference-bundle/1.0"
BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME = "arrays.npz"
BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME = "private-alignment.json"
BASELINE_REFERENCE_BUNDLE_MAX_ARRAYS_BYTES = 513 * 1024 * 1024
_STREAM_CHUNK_BYTES = 1024 * 1024

type ReferenceBundleFileIdentity = tuple[int, int, int, int, int]
type ReferenceBundleComponentIdentity = tuple[
    str,
    str,
    ReferenceBundleFileIdentity,
]


class ReferenceBundleError(ValueError):
    """Raised without echoing private bundle values or local paths."""


@dataclass(frozen=True, repr=False)
class _VerifiedReferenceBundleState:
    manifest_bytes: bytes
    private_alignment_bytes: bytes
    component_identities: tuple[ReferenceBundleComponentIdentity, ...]
    reference_owner: VerifiedReferenceResult
    alignment_binding_eligible: bool


_BUNDLE_STATES: OneShotWeakRegistry[object, _VerifiedReferenceBundleState]
_BUNDLE_STATE_ISSUER: OneShotRegistryIssuer[object, _VerifiedReferenceBundleState]
_BUNDLE_STATES, _BUNDLE_STATE_ISSUER = create_one_shot_registry()


def _build_bundle_register(
    issuer: OneShotRegistryIssuer[object, _VerifiedReferenceBundleState],
    registry: OneShotWeakRegistry[object, _VerifiedReferenceBundleState],
) -> Callable[[object, _VerifiedReferenceBundleState], None]:
    def register(owner: object, state: _VerifiedReferenceBundleState) -> None:
        try:
            issuer.bind_once(owner, state)
            registry.require(owner, state)
        except OneShotRegistryError:
            raise ReferenceBundleError(
                "Verified reference bundle authority is unavailable."
            ) from None

    return register


_register_reference_bundle = _build_bundle_register(
    _BUNDLE_STATE_ISSUER,
    _BUNDLE_STATES,
)
del _BUNDLE_STATE_ISSUER
del _build_bundle_register


def _reject_capability_copy() -> Never:
    raise TypeError("Verified reference bundles cannot be copied or serialized.")


def _validated_reference_bundle_manifest(manifest_bytes: bytes) -> dict[str, Any]:
    """Parse one exact canonical manifest without admitting any component."""

    try:
        value = strict_json_loads(manifest_bytes)
        if type(value) is not dict or canonical_json_bytes(value) != manifest_bytes:
            raise ReferenceBundleError("The reference bundle manifest is not canonical JSON.")
        validate_instance(value, "baseline-reference-bundle.schema.json")
        return cast(dict[str, Any], value)
    except ReferenceBundleError:
        raise
    except (CanonicalizationError, SchemaValidationError, TypeError, ValueError):
        raise ReferenceBundleError(
            "The reference bundle manifest does not satisfy its closed contract."
        ) from None


def _validated_private_alignment(
    private_alignment_bytes: bytes,
    reference: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        value = strict_json_loads(private_alignment_bytes)
        if type(value) is not dict or canonical_json_bytes(value) != private_alignment_bytes:
            raise ReferenceBundleError(
                "The private reference alignment is not canonical JSON."
            )
        return _verify_private_alignment_artifact(
            cast(Mapping[str, Any], value),
            reference,
        )
    except ReferenceBundleError:
        raise
    except (BaselineReproductionError, CanonicalizationError, TypeError, ValueError):
        raise ReferenceBundleError(
            "The private reference alignment does not satisfy its closed contract."
        ) from None


def _require_exact_component_record(
    record: object,
    *,
    observed_digest: str,
    observed_identity: ReferenceBundleFileIdentity,
) -> None:
    if (
        type(record) is not dict
        or record.get("sha256") != observed_digest
        or record.get("byte_length") != observed_identity[2]
    ):
        raise ReferenceBundleError(
            "A reference bundle component is detached from its manifest descriptor."
        )


def _snapshot_exact_array_archive(
    arrays_handle: BinaryIO,
    *,
    expected_digest: str,
    expected_identity: ReferenceBundleFileIdentity,
) -> BytesIO:
    """Hash and bound one archive snapshot, then parse only those immutable bytes."""

    digest = hashlib.sha256()
    snapshot = BytesIO()
    total = 0
    try:
        arrays_handle.seek(0)
        while True:
            chunk = arrays_handle.read(_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > BASELINE_REFERENCE_BUNDLE_MAX_ARRAYS_BYTES:
                raise ReferenceBundleError(
                    "The reference array archive exceeds its closed byte limit."
                )
            digest.update(chunk)
            snapshot.write(chunk)
    except ReferenceBundleError:
        snapshot.close()
        raise
    except (OSError, TypeError, ValueError):
        snapshot.close()
        raise ReferenceBundleError(
            "The reference array archive could not be snapshotted exactly."
        ) from None
    observed_digest = f"sha256:{digest.hexdigest()}"
    if total != expected_identity[2] or observed_digest != expected_digest:
        snapshot.close()
        raise ReferenceBundleError(
            "The reference array archive changed after exact-file verification."
        )
    snapshot.seek(0)
    return snapshot


def _issue_verified_reference_bundle(
    *,
    manifest_bytes: bytes,
    manifest_digest: str,
    manifest_identity: ReferenceBundleFileIdentity,
    arrays_handle: BinaryIO,
    arrays_digest: str,
    arrays_identity: ReferenceBundleFileIdentity,
    private_alignment_bytes: bytes,
    private_alignment_digest: str,
    private_alignment_identity: ReferenceBundleFileIdentity,
    alignment_binding_eligible: bool,
) -> VerifiedReferenceBundle:
    """Issue the opaque bundle owner from already-retained private file identities."""

    manifest = _validated_reference_bundle_manifest(manifest_bytes)
    if (
        exact_file_sha256(manifest_bytes) != manifest_digest
        or manifest_identity[2] != len(manifest_bytes)
        or exact_file_sha256(private_alignment_bytes) != private_alignment_digest
        or private_alignment_identity[2] != len(private_alignment_bytes)
    ):
        raise ReferenceBundleError(
            "A reference bundle component changed after exact-file verification."
        )
    files = cast(Mapping[str, object], manifest["files"])
    if type(alignment_binding_eligible) is not bool:
        raise ReferenceBundleError(
            "The reference bundle verification status is invalid."
        )
    _require_exact_component_record(
        files[BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME],
        observed_digest=arrays_digest,
        observed_identity=arrays_identity,
    )
    _require_exact_component_record(
        files[BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME],
        observed_digest=private_alignment_digest,
        observed_identity=private_alignment_identity,
    )

    reference = cast(Mapping[str, Any], manifest["reference_result"])
    private_alignment = _validated_private_alignment(private_alignment_bytes, reference)
    arrays_snapshot = _snapshot_exact_array_archive(
        arrays_handle,
        expected_digest=arrays_digest,
        expected_identity=arrays_identity,
    )
    try:
        catalog = cast(Mapping[str, Any], reference["outputs"]["arrays"])
        arrays = _load_catalogued_npz_arrays_handle(
            arrays_snapshot,
            catalog=catalog,
        )
        reference_owner = issue_verified_reference_result(
            reference,
            reference_arrays=arrays,
        )
    except (BaselineReproductionError, KeyError, TypeError, ValueError):
        raise ReferenceBundleError(
            "The reference array archive does not match the closed reference catalog."
        ) from None
    finally:
        arrays_snapshot.close()
    del arrays
    del private_alignment

    owner = object.__new__(VerifiedReferenceBundle)
    state = _VerifiedReferenceBundleState(
        manifest_bytes=bytes(manifest_bytes),
        private_alignment_bytes=bytes(private_alignment_bytes),
        component_identities=(
            ("manifest.json", manifest_digest, manifest_identity),
            (BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME, arrays_digest, arrays_identity),
            (
                BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME,
                private_alignment_digest,
                private_alignment_identity,
            ),
        ),
        reference_owner=reference_owner,
        alignment_binding_eligible=alignment_binding_eligible,
    )
    _register_reference_bundle(owner, state)
    _reverify_reference_bundle(owner)
    return owner


def _read_reference_bundle(value: object) -> _VerifiedReferenceBundleState:
    if type(value) is not VerifiedReferenceBundle:
        raise ReferenceBundleError("A genuine verified reference bundle is required.")
    try:
        state = _BUNDLE_STATES.read(value)
    except OneShotRegistryError:
        raise ReferenceBundleError("Verified reference bundle authority is unavailable.") from None
    if type(state) is not _VerifiedReferenceBundleState:
        raise ReferenceBundleError("Verified reference bundle authority is unavailable.")
    return state


def _reverify_reference_bundle(value: object) -> _VerifiedReferenceBundleState:
    state = _read_reference_bundle(value)
    manifest = _validated_reference_bundle_manifest(state.manifest_bytes)
    try:
        _imported_state, reference, _arrays = _reverify_imported_reference_owner(
            state.reference_owner
        )
        if manifest["reference_result"] != reference:
            raise ReferenceBundleError(
                "The verified reference owner is detached from its bundle manifest."
            )
        _validated_private_alignment(state.private_alignment_bytes, reference)
        identities = dict(
            (name, (digest, identity))
            for name, digest, identity in state.component_identities
        )
        manifest_digest, manifest_identity = identities["manifest.json"]
        arrays_digest, arrays_identity = identities[BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME]
        alignment_digest, alignment_identity = identities[
            BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME
        ]
        if (
            exact_file_sha256(state.manifest_bytes) != manifest_digest
            or manifest_identity[2] != len(state.manifest_bytes)
            or exact_file_sha256(state.private_alignment_bytes) != alignment_digest
            or alignment_identity[2] != len(state.private_alignment_bytes)
        ):
            raise ReferenceBundleError("The verified reference bundle is detached.")
        files = cast(Mapping[str, object], manifest["files"])
        _require_exact_component_record(
            files[BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME],
            observed_digest=arrays_digest,
            observed_identity=arrays_identity,
        )
        _require_exact_component_record(
            files[BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME],
            observed_digest=alignment_digest,
            observed_identity=alignment_identity,
        )
    except ReferenceBundleError:
        raise
    except (BaselineReproductionError, KeyError, TypeError, ValueError):
        raise ReferenceBundleError("The verified reference bundle is detached.") from None
    return state


@final
class VerifiedReferenceBundle:
    """Opaque owner of one exact canonical manifest, arrays, and private alignment."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedReferenceBundle:
        raise ReferenceBundleError(
            "Reference bundles must come from retained exact-file verification."
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Verified reference bundles cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Verified reference bundles are immutable.")

    def __copy__(self) -> VerifiedReferenceBundle:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> VerifiedReferenceBundle:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()

    @property
    def manifest_digest(self) -> str:
        state = _reverify_reference_bundle(self)
        return dict(
            (name, digest) for name, digest, _identity in state.component_identities
        )["manifest.json"]

    @property
    def reference_id(self) -> str:
        return _reverify_reference_bundle(self).reference_owner.reference_id

    def __repr__(self) -> str:
        _reverify_reference_bundle(self)
        return "VerifiedReferenceBundle(<opaque exact-file reference owner>)"


def issue_verified_reference_alignment_owner_from_bundle(
    source_result: FinalizedResult,
    bundle: VerifiedReferenceBundle,
) -> VerifiedReferenceAlignmentOwner:
    """Bind a verified bundle to a finalized run without exposing its private mapping."""

    state = _reverify_reference_bundle(bundle)
    if not state.alignment_binding_eligible:
        raise ReferenceBundleError(
            "The reference bundle is not independently verified for run binding."
        )
    try:
        value = strict_json_loads(state.private_alignment_bytes)
        if type(value) is not dict:
            raise ReferenceBundleError(
                "The verified reference bundle alignment is unavailable."
            )
        return issue_verified_reference_alignment_owner(
            source_result,
            state.reference_owner,
            private_alignment_artifact=cast(Mapping[str, Any], value),
        )
    except (BaselineReproductionError, CanonicalizationError, TypeError, ValueError):
        raise ReferenceBundleError(
            "The verified reference bundle could not be bound to this finalized result."
        ) from None


__all__ = [
    "BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME",
    "BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME",
    "BASELINE_REFERENCE_BUNDLE_MAX_ARRAYS_BYTES",
    "BASELINE_REFERENCE_BUNDLE_SCHEMA_VERSION",
    "ReferenceBundleError",
    "VerifiedReferenceBundle",
    "issue_verified_reference_alignment_owner_from_bundle",
]
