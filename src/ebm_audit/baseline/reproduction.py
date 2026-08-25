"""Fail-closed baseline reproduction against a canonical supplied reference."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    NamedTuple,
    Never,
    Protocol,
    SupportsIndex,
    cast,
    final,
)

import numpy as np

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.metrics.convergence import is_canonical_non_sampling_convergence_record
from ebm_audit.protocol import (
    canonical_json_bytes,
    execution_input_projection_digest,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.workers.arrays import array_catalog_entry, canonical_array

if TYPE_CHECKING:
    from ebm_audit.data.identity import IdentityMap
    from ebm_audit.results.finalization import (
        FinalizedResult,
        _FinalizedBaselineSource,
        _FinalizedResultState,
    )

BASELINE_COMPARISON_IDS = (
    "dataset-binding",
    "implementation-identity",
    "scientific-contract",
    "participant-event-accounting",
    "central-order",
    "order-distribution",
    "participant-stage-output",
    "statistical-diagnostics",
    "all-supplied-fields",
)
_ORDER_DISTRIBUTION_ARRAYS = frozenset(
    {
        "postburn_order_state_chain",
        "order_state_chain",
        "position_probabilities",
        "pairwise_precedence",
    }
)
_STAGE_ARRAYS = frozenset(
    {
        "training_stage_posterior",
        "training_map_stage",
        "training_map_tie_mask",
        "training_expected_stage",
        "evaluation_stage_posterior",
        "evaluation_map_stage",
        "evaluation_map_tie_mask",
        "evaluation_expected_stage",
    }
)

BaselineStatus = Literal[
    "BASELINE_REPRODUCED",
    "BASELINE_PARTIALLY_REPRODUCED",
    "BASELINE_NOT_REPRODUCED",
    "BASELINE_REFERENCE_NOT_SUPPLIED",
]
BaselineAssessmentStatus = Literal[
    "BASELINE_REPRODUCED",
    "BASELINE_PARTIALLY_REPRODUCED",
    "BASELINE_NOT_REPRODUCED",
    "BASELINE_REFERENCE_NOT_SUPPLIED",
    "BASELINE_NOT_ASSESSABLE",
]
ReferenceAlignmentStatus = Literal["ALIGNED", "SCIENTIFIC_MISMATCH"]


class BaselineReproductionError(ValueError):
    """Raised when a baseline owner or derived record is invalid."""


def _finalized_baseline_source(
    value: object,
    validated_state: _FinalizedResultState | None = None,
) -> _FinalizedBaselineSource:
    from ebm_audit.results.finalization import (
        _baseline_source_from_finalized_result,
        _baseline_source_from_validated_finalized_result,
    )

    if validated_state is None:
        return _baseline_source_from_finalized_result(value)
    return _baseline_source_from_validated_finalized_result(value, validated_state)


def _reject_capability_copy() -> Never:
    raise TypeError("Baseline owner capabilities cannot be copied or serialized.")


@dataclass(frozen=True, repr=False)
class _PrivateArray:
    name: str
    dtype: str
    shape: tuple[int, ...]
    material: bytes

    def array(self) -> Any:
        dtype = np.dtype(self.dtype)
        return np.frombuffer(self.material, dtype=dtype).reshape(self.shape)


class _ImportedReferenceState(NamedTuple):
    reference_bytes: bytes
    reference_arrays: tuple[_PrivateArray, ...]


class _ReferenceOwnerState(NamedTuple):
    owner_id: str
    source_result: FinalizedResult
    reference_owner: VerifiedReferenceResult
    alignment_bytes: bytes
    alignment_status: ReferenceAlignmentStatus
    reference_to_current: tuple[int, ...] | None
    current_identity_row_digest: str


class _ConnectedOwnerState(NamedTuple):
    canonical_bytes: bytes
    source_result: FinalizedResult
    reference_owner: VerifiedReferenceAlignmentOwner | None


def _build_opaque_owner_registries() -> tuple[
    OneShotWeakRegistry[object, _ImportedReferenceState],
    OneShotWeakRegistry[object, _ReferenceOwnerState],
    OneShotWeakRegistry[object, _ConnectedOwnerState],
    Callable[[object, _ImportedReferenceState], None],
    Callable[[object], _ImportedReferenceState],
    Callable[[object, _ReferenceOwnerState], None],
    Callable[[object], _ReferenceOwnerState],
    Callable[[object, _ConnectedOwnerState], None],
    Callable[[object], _ConnectedOwnerState],
]:
    imported_reference_registry: OneShotWeakRegistry[object, _ImportedReferenceState]
    imported_reference_issuer: OneShotRegistryIssuer[object, _ImportedReferenceState]
    imported_reference_registry, imported_reference_issuer = create_one_shot_registry()
    reference_registry: OneShotWeakRegistry[object, _ReferenceOwnerState]
    reference_issuer: OneShotRegistryIssuer[object, _ReferenceOwnerState]
    reference_registry, reference_issuer = create_one_shot_registry()
    connected_registry: OneShotWeakRegistry[object, _ConnectedOwnerState]
    connected_issuer: OneShotRegistryIssuer[object, _ConnectedOwnerState]
    connected_registry, connected_issuer = create_one_shot_registry()

    def bind_imported_reference(
        owner: object,
        state: _ImportedReferenceState,
    ) -> None:
        if type(owner) is not VerifiedReferenceResult or type(state) is not _ImportedReferenceState:
            raise BaselineReproductionError("Imported reference authority is unavailable.")
        binding_failed = False
        try:
            imported_reference_issuer.bind_once(owner, state)
            imported_reference_registry.require(owner, state)
        except OneShotRegistryError:
            binding_failed = True
        if binding_failed:
            raise BaselineReproductionError(
                "Imported reference authority is unavailable."
            )

    def read_imported_reference(owner: object) -> _ImportedReferenceState:
        state: _ImportedReferenceState | None = None
        if type(owner) is VerifiedReferenceResult:
            with suppress(OneShotRegistryError):
                state = imported_reference_registry.read(owner)
        if type(state) is not _ImportedReferenceState:
            raise BaselineReproductionError(
                "A genuine separately imported reference owner is required."
            )
        return state

    def bind_reference(owner: object, state: _ReferenceOwnerState) -> None:
        if (
            type(owner) is not VerifiedReferenceAlignmentOwner
            or type(state) is not _ReferenceOwnerState
        ):
            raise BaselineReproductionError("Reference authority is unavailable.")
        binding_failed = False
        try:
            reference_issuer.bind_once(owner, state)
            reference_registry.require(owner, state)
        except OneShotRegistryError:
            binding_failed = True
        if binding_failed:
            raise BaselineReproductionError("Reference authority is unavailable.")

    def read_reference(owner: object) -> _ReferenceOwnerState:
        state: _ReferenceOwnerState | None = None
        if type(owner) is VerifiedReferenceAlignmentOwner:
            with suppress(OneShotRegistryError):
                state = reference_registry.read(owner)
        if type(state) is not _ReferenceOwnerState:
            raise BaselineReproductionError(
                "A genuine verified reference and alignment owner is required."
            )
        return state

    def bind_connected(owner: object, state: _ConnectedOwnerState) -> None:
        if type(owner) is not ConnectedBaselineResult or type(state) is not _ConnectedOwnerState:
            raise BaselineReproductionError("Connected baseline authority is unavailable.")
        binding_failed = False
        try:
            connected_issuer.bind_once(owner, state)
            connected_registry.require(owner, state)
        except OneShotRegistryError:
            binding_failed = True
        if binding_failed:
            raise BaselineReproductionError(
                "Connected baseline authority is unavailable."
            )

    def read_connected(owner: object) -> _ConnectedOwnerState:
        state: _ConnectedOwnerState | None = None
        if type(owner) is ConnectedBaselineResult:
            with suppress(OneShotRegistryError):
                state = connected_registry.read(owner)
        if type(state) is not _ConnectedOwnerState:
            raise BaselineReproductionError(
                "A genuine connected baseline result authority is required."
            )
        return state

    return (
        imported_reference_registry,
        reference_registry,
        connected_registry,
        bind_imported_reference,
        read_imported_reference,
        bind_reference,
        read_reference,
        bind_connected,
        read_connected,
    )


@final
class VerifiedReferenceResult:
    """Opaque owner of one separately imported canonical reference bundle."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedReferenceResult:
        raise BaselineReproductionError(
            "Reference results must come from the independent import verifier."
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Reference results cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Reference results are immutable.")

    def __copy__(self) -> VerifiedReferenceResult:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> VerifiedReferenceResult:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()

    @property
    def reference_id(self) -> str:
        return cast(str, _imported_reference_mapping(self)["reference_id"])

    @property
    def canonical_reference_bytes(self) -> bytes:
        return bytes(_read_imported_reference_owner(self).reference_bytes)

    def __repr__(self) -> str:
        _read_imported_reference_owner(self)
        return "VerifiedReferenceResult(<opaque imported-reference owner>)"


@final
class VerifiedReferenceAlignmentOwner:
    """Opaque owner of one user reference and its separately checked alignment."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedReferenceAlignmentOwner:
        raise BaselineReproductionError(
            "Reference owners must come from complete private verification."
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Reference owners cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Reference owners are immutable.")

    def __copy__(self) -> VerifiedReferenceAlignmentOwner:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> VerifiedReferenceAlignmentOwner:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()

    @property
    def owner_id(self) -> str:
        return _read_reference_owner(self).owner_id

    @property
    def reference_id(self) -> str:
        return _read_reference_owner(self).reference_owner.reference_id

    @property
    def canonical_reference_bytes(self) -> bytes:
        return _read_reference_owner(self).reference_owner.canonical_reference_bytes

    @property
    def alignment_status(self) -> ReferenceAlignmentStatus:
        return _read_reference_owner(self).alignment_status

    def __repr__(self) -> str:
        _read_reference_owner(self)
        return "VerifiedReferenceAlignmentOwner(<opaque user-reference owner>)"


@final
class ConnectedBaselineResult:
    """Opaque current-run projection issued only from one exact finalized result."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ConnectedBaselineResult:
        raise BaselineReproductionError(
            "Connected baseline results must come from the core projection authority."
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Connected baseline results cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Connected baseline results are immutable.")

    def __copy__(self) -> ConnectedBaselineResult:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> ConnectedBaselineResult:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()

    @property
    def result_id(self) -> str:
        return cast(str, _connected_mapping(self)["result_id"])

    @property
    def source_result_id(self) -> str:
        binding = cast(Mapping[str, Any], _connected_mapping(self)["source_binding"])
        return cast(str, binding["source_result_id"])

    @property
    def canonical_bytes(self) -> bytes:
        return bytes(_read_connected_owner(self).canonical_bytes)

    def __repr__(self) -> str:
        _read_connected_owner(self)
        return "ConnectedBaselineResult(<opaque finalized-result projection>)"


(
    _IMPORTED_REFERENCE_STATES,
    _REFERENCE_OWNER_STATES,
    _CONNECTED_OWNER_STATES,
    _register_imported_reference_owner,
    _read_imported_reference_owner,
    _register_reference_owner,
    _read_reference_owner,
    _register_connected_owner,
    _read_connected_owner,
) = _build_opaque_owner_registries()
del _build_opaque_owner_registries


class _VerifiedBaselineSnapshot(NamedTuple):
    """Immutable authoritative facts retained only for a genuine capability."""

    baseline_reproduction_id: str
    connected_result_id: str
    reference_id: str | None
    status: BaselineStatus
    validated_language_eligibility: bool
    reason_codes: tuple[str, ...]
    record_bytes: bytes
    connected_result: ConnectedBaselineResult
    reference_owner: VerifiedReferenceAlignmentOwner | None


def _build_verified_baseline_registry() -> tuple[
    OneShotWeakRegistry[object, _VerifiedBaselineSnapshot],
    Callable[[type[object]], None],
    Callable[[object, _VerifiedBaselineSnapshot], None],
    Callable[[object], _VerifiedBaselineSnapshot],
]:
    registry: OneShotWeakRegistry[object, _VerifiedBaselineSnapshot]
    issuer: OneShotRegistryIssuer[object, _VerifiedBaselineSnapshot]
    registry, issuer = create_one_shot_registry()
    verified_type: type[object] | None = None

    def bind_type(capability_type: type[object]) -> None:
        nonlocal verified_type
        if verified_type is not None or type(capability_type) is not type:
            raise BaselineReproductionError(
                "Verified baseline capability authority is unavailable."
            )
        verified_type = capability_type

    def register(
        capability: object,
        snapshot: _VerifiedBaselineSnapshot,
    ) -> None:
        if (
            verified_type is None
            or type(capability) is not verified_type
            or type(snapshot) is not _VerifiedBaselineSnapshot
        ):
            raise BaselineReproductionError(
                "Verified baseline capability authority is unavailable."
            )
        binding_failed = False
        try:
            issuer.bind_once(capability, snapshot)
            registry.require(capability, snapshot)
        except OneShotRegistryError:
            binding_failed = True
        if binding_failed:
            raise BaselineReproductionError(
                "Verified baseline capability authority is unavailable."
            )

    def read_snapshot(capability: object) -> _VerifiedBaselineSnapshot:
        snapshot: _VerifiedBaselineSnapshot | None = None
        if verified_type is not None and type(capability) is verified_type:
            with suppress(OneShotRegistryError):
                snapshot = registry.read(capability)
        if type(snapshot) is not _VerifiedBaselineSnapshot:
            raise BaselineReproductionError(
                "A genuine verified baseline reproduction capability is required."
            )
        _reverify_verified_baseline_snapshot(snapshot)
        return snapshot

    return registry, bind_type, register, read_snapshot


(
    _VERIFIED_BASELINE_STATES,
    _bind_verified_baseline_type,
    _register_verified_baseline_snapshot,
    _read_verified_baseline_snapshot,
) = _build_verified_baseline_registry()


class VerifiedBaselineReproduction:
    """Privacy-safe capability produced only by complete owner re-verification."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedBaselineReproduction:
        raise BaselineReproductionError(
            "Verified baseline capabilities must come from complete verification."
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Verified baseline capabilities cannot be subclassed.")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Verified baseline capabilities are immutable.")

    def __copy__(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> VerifiedBaselineReproduction:
        """Return this immutable verified capability unchanged."""

        _read_snapshot(self)
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> VerifiedBaselineReproduction:
        """Keep deep-copying aggregate inputs from weakening the capability."""

        _read_snapshot(self)
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Verified baseline capabilities cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Verified baseline capabilities cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Verified baseline capabilities cannot be serialized.")

    @property
    def baseline_reproduction_id(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> str:
        return _read_snapshot(self).baseline_reproduction_id

    @property
    def connected_result_id(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> str:
        return _read_snapshot(self).connected_result_id

    @property
    def reference_id(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> str | None:
        return _read_snapshot(self).reference_id

    @property
    def status(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> BaselineStatus:
        return _read_snapshot(self).status

    @property
    def validated_language_eligibility(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> bool:
        return _read_snapshot(self).validated_language_eligibility

    @property
    def reason_codes(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> tuple[str, ...]:
        return _read_snapshot(self).reason_codes

    def __repr__(
        self,
        _read_snapshot: Callable[
            [object], _VerifiedBaselineSnapshot
        ] = _read_verified_baseline_snapshot,
    ) -> str:
        _read_snapshot(self)
        return "VerifiedBaselineReproduction(<verified-digests-only>)"


_bind_verified_baseline_type(VerifiedBaselineReproduction)
_verified_baseline_snapshot = _read_verified_baseline_snapshot
del _bind_verified_baseline_type
del _read_verified_baseline_snapshot
del _build_verified_baseline_registry


def _copy(value: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(value))


def _validate(value: object, definition: str) -> None:
    try:
        validate_instance(
            value,
            "canonical-records.schema.json",
            definition=definition,
        )
    except SchemaValidationError as exc:
        raise BaselineReproductionError(
            "A baseline object does not satisfy its closed contract."
        ) from exc


def baseline_tolerance_contract() -> dict[str, Any]:
    """Return the sole admitted exact-comparison contract for version 0.1."""

    value = {
        "tolerance_schema_version": "ebm-audit-baseline-tolerance/1.0",
        "categorical_rule": "EXACT_RFC8785_VALUE",
        "integer_rule": "EXACT_INTEGER",
        "array_shape_rule": "EXACT_SHAPE",
        "array_value_rule": "EXACT_CANONICAL_ARRAY_DIGEST",
        "absolute_float_tolerance": 0,
        "relative_float_tolerance": 0,
        "missing_required_comparison_rule": "BASELINE_NOT_REPRODUCED",
        "missing_optional_comparison_rule": "BASELINE_PARTIALLY_REPRODUCED",
    }
    _validate(value, "BaselineToleranceContract")
    return value


_DIAGNOSTIC_CHAIN_ID_FIELDS = frozenset(
    {
        "chain_execution_id",
        "left_chain_execution_id",
        "right_chain_execution_id",
    }
)


def _statistical_diagnostics_digest(
    convergence: Mapping[str, Any],
    ordered_chain_execution_ids: Sequence[str],
) -> str:
    """Hash validated diagnostics after replacing private execution identities."""

    _validate(convergence, "ConvergenceRecord")
    if (
        isinstance(ordered_chain_execution_ids, (str, bytes))
        or not isinstance(ordered_chain_execution_ids, Sequence)
        or not ordered_chain_execution_ids
        or any(type(value) is not str for value in ordered_chain_execution_ids)
        or len(set(ordered_chain_execution_ids)) != len(ordered_chain_execution_ids)
    ):
        raise BaselineReproductionError(
            "The ordered diagnostic chain identities are invalid."
        )
    surrogates = {
        chain_execution_id: structured_sha256(
            "ebm-audit/baseline-statistical-diagnostics-chain/1",
            {"chain_plan_position": position},
        )
        for position, chain_execution_id in enumerate(ordered_chain_execution_ids)
    }

    def reject_repeated_ids(value: object) -> None:
        if isinstance(value, list):
            direct_ids = [
                item["chain_execution_id"]
                for item in value
                if isinstance(item, Mapping) and "chain_execution_id" in item
            ]
            if direct_ids and (
                len(direct_ids) != len(value)
                or len(set(direct_ids)) != len(direct_ids)
            ):
                raise BaselineReproductionError(
                    "The statistical diagnostics repeat a chain identity."
                )
            pairs = [
                (
                    item["left_chain_execution_id"],
                    item["right_chain_execution_id"],
                )
                for item in value
                if isinstance(item, Mapping)
                and "left_chain_execution_id" in item
                and "right_chain_execution_id" in item
            ]
            unordered_pairs = [frozenset(pair) for pair in pairs]
            if pairs and (
                len(pairs) != len(value)
                or any(len(pair) != 2 for pair in unordered_pairs)
                or len(set(unordered_pairs)) != len(unordered_pairs)
            ):
                raise BaselineReproductionError(
                    "The statistical diagnostics repeat a chain identity pair."
                )
            for item in value:
                reject_repeated_ids(item)
        elif isinstance(value, Mapping):
            for item in value.values():
                reject_repeated_ids(item)

    reject_repeated_ids(convergence)
    seen: set[str] = set()

    def normalize(value: object) -> object:
        if isinstance(value, Mapping):
            normalized: dict[str, object] = {}
            for key, item in value.items():
                if key in _DIAGNOSTIC_CHAIN_ID_FIELDS:
                    if type(item) is not str or item not in surrogates:
                        raise BaselineReproductionError(
                            "The statistical diagnostics contain an unknown chain identity."
                        )
                    seen.add(item)
                    normalized[str(key)] = surrogates[item]
                else:
                    normalized[str(key)] = normalize(item)
            return normalized
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, tuple):
            return [normalize(item) for item in value]
        return copy.deepcopy(value)

    normalized = normalize(convergence)
    expected_seen = (
        set()
        if is_canonical_non_sampling_convergence_record(convergence)
        else set(ordered_chain_execution_ids)
    )
    if seen != expected_seen:
        raise BaselineReproductionError(
            "The statistical diagnostics do not cover the ordered chain plan."
        )
    _validate(normalized, "ConvergenceRecord")
    preimage = {
        "diagnostics_schema_version": (
            "ebm-audit-baseline-statistical-diagnostics/1.0"
        ),
        "convergence": normalized,
    }
    _validate(preimage, "BaselineStatisticalDiagnosticsDigestPreimage")
    return structured_sha256(
        "ebm-audit/baseline-statistical-diagnostics/1",
        preimage,
    )


def build_reference_result(body: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and self-identify one complete canonical reference body."""

    preimage = _copy(body)
    if "reference_id" in preimage:
        raise BaselineReproductionError("A reference body cannot supply its own identity.")
    preimage["reference_id"] = None
    _validate(preimage, "CanonicalReferenceResultDigestPreimage")
    _validate_projection_cross_fields(preimage, require_field_origins=True)
    result = copy.deepcopy(preimage)
    result["reference_id"] = structured_sha256(
        "ebm-audit/canonical-reference/2",
        preimage,
    )
    _validate(result, "CanonicalReferenceResult")
    return result


def build_connected_result(body: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and self-identify the connected baseline projection."""

    preimage = _copy(body)
    if "result_id" in preimage:
        raise BaselineReproductionError("A connected-result body cannot supply its own identity.")
    preimage["result_id"] = None
    _validate(preimage, "BaselineConnectedResultDigestPreimage")
    _validate_projection_cross_fields(preimage, require_field_origins=False)
    result = copy.deepcopy(preimage)
    result["result_id"] = structured_sha256(
        "ebm-audit/baseline-connected-result/2",
        preimage,
    )
    _validate(result, "BaselineConnectedResultProjection")
    return result


def _verify_self_identity(
    value: Mapping[str, Any],
    *,
    identity_field: str,
    preimage_definition: str,
    result_definition: str,
    domain: str,
) -> dict[str, Any]:
    result = _copy(value)
    _validate(result, result_definition)
    preimage = copy.deepcopy(result)
    preimage[identity_field] = None
    _validate(preimage, preimage_definition)
    if result[identity_field] != structured_sha256(domain, preimage):
        raise BaselineReproductionError("A baseline object has a detached identity.")
    return result


def _validate_projection_cross_fields(
    value: Mapping[str, Any],
    *,
    require_field_origins: bool,
) -> None:
    """Enforce reference/result relations that JSON Schema cannot express."""

    try:
        dataset = value["dataset"]
        contract = value["scientific_contract"]
        outputs = value["outputs"]
        manifest = outputs["participant_event_manifest"]
        arrays = outputs["arrays"]
        participant_count = dataset["participant_count"]
        event_count = dataset["event_count"]
        event_ids = contract["event_ids"]
        event_labels = contract["event_labels"]
        directions = contract["event_directions"]
        if (
            len(event_ids) != event_count
            or len(event_labels) != event_count
            or len(set(event_labels)) != event_count
            or len(directions) != event_count
            or any(direction not in {"higher", "lower"} for direction in directions)
            or manifest["participant_count"] != participant_count
            or manifest["event_count"] != event_count
            or manifest["event_ids"] != event_ids
            or manifest["reference_row_order_digest"] != dataset["reference_row_order_digest"]
        ):
            raise BaselineReproductionError(
                "Baseline dataset, event, direction, or row-order bindings disagree."
            )
        order = outputs["central_order_permutation"]
        if len(order) != event_count or sorted(order) != list(range(event_count)):
            raise BaselineReproductionError(
                "The baseline central order is not one complete event permutation."
            )

        dtype_bytes = {"bool": 1, "int32": 4, "int64": 8, "float64": 8}
        fixed_specs: dict[str, tuple[set[str], list[int]]] = {
            "position_probabilities": ({"float64"}, [event_count, event_count]),
            "pairwise_precedence": ({"float64"}, [event_count, event_count]),
            "training_row_indexes": ({"int64"}, [participant_count]),
            "training_stage_posterior": (
                {"float64"},
                [participant_count, event_count + 1],
            ),
            "training_map_stage": ({"int32", "int64"}, [participant_count]),
            "training_map_tie_mask": (
                {"bool"},
                [participant_count, event_count + 1],
            ),
            "training_expected_stage": ({"float64"}, [participant_count]),
        }
        evaluation_count: int | None = None
        if "evaluation_row_indexes" in arrays:
            evaluation_shape = arrays["evaluation_row_indexes"]["shape"]
            if len(evaluation_shape) != 1 or evaluation_shape[0] < 1:
                raise BaselineReproductionError("The baseline evaluation row axis is invalid.")
            evaluation_count = evaluation_shape[0]
            fixed_specs.update(
                {
                    "evaluation_row_indexes": ({"int64"}, [evaluation_count]),
                    "evaluation_stage_posterior": (
                        {"float64"},
                        [evaluation_count, event_count + 1],
                    ),
                    "evaluation_map_stage": ({"int32", "int64"}, [evaluation_count]),
                    "evaluation_map_tie_mask": (
                        {"bool"},
                        [evaluation_count, event_count + 1],
                    ),
                    "evaluation_expected_stage": ({"float64"}, [evaluation_count]),
                }
            )
        elif any(name.startswith("evaluation_") for name in arrays):
            raise BaselineReproductionError(
                "Baseline evaluation-stage output lacks its row-index owner."
            )
        if (
            any(name.startswith("training_") and name != "training_row_indexes" for name in arrays)
            and "training_row_indexes" not in arrays
        ):
            raise BaselineReproductionError(
                "Baseline training-stage output lacks its row-index owner."
            )
        if (
            any(name in _STAGE_ARRAYS for name in arrays)
            and contract["stage_semantics_digest"] is None
        ):
            raise BaselineReproductionError("Baseline stage arrays lack declared stage semantics.")

        for name, entry in arrays.items():
            shape = entry["shape"]
            if entry["member_name"] != name:
                raise BaselineReproductionError(
                    "A baseline array catalog member is detached from its key."
                )
            element_count = 1
            for axis in shape:
                element_count *= axis
            if entry["byte_length"] != element_count * dtype_bytes[entry["dtype"]]:
                raise BaselineReproductionError(
                    "A baseline array byte length disagrees with its dtype and shape."
                )
            if name in {"postburn_order_state_chain", "order_state_chain"}:
                if (
                    entry["dtype"] not in {"int32", "int64"}
                    or len(shape) != 2
                    or shape[0] < 1
                    or shape[1] != event_count
                ):
                    raise BaselineReproductionError(
                        "A baseline order-state array has the wrong shape or dtype."
                    )
            elif name in fixed_specs:
                allowed_dtypes, expected_shape = fixed_specs[name]
                if entry["dtype"] not in allowed_dtypes or shape != expected_shape:
                    raise BaselineReproductionError(
                        "A baseline array has the wrong shape or dtype."
                    )

        if require_field_origins:
            export_receipt = value["export_receipt"]
            if (
                export_receipt["private_alignment_artifact_digest"]
                != dataset["private_alignment_artifact_digest"]
            ):
                raise BaselineReproductionError(
                    "The reference export receipt is detached from its private alignment artifact."
                )
            required_origin_keys = {
                "implementation",
                "dataset",
                "scientific_contract",
                "outputs.central_order_permutation",
                "outputs.participant_event_manifest",
                "outputs.statistical_diagnostics_digest",
                *(f"outputs.arrays.{name}" for name in arrays),
            }
            if set(value["field_origins"]) != required_origin_keys:
                raise BaselineReproductionError(
                    "Reference field provenance is missing, extra, or detached."
                )
    except BaselineReproductionError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise BaselineReproductionError("Baseline cross-field bindings are invalid.") from exc


def _verify_private_alignment_artifact(
    value: Mapping[str, Any],
    reference: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute the private alignment identities without exposing row values."""

    artifact = _copy(value)
    _validate(artifact, "PrivateReferenceAlignmentArtifact")
    try:
        dataset = reference["dataset"]
        manifest = reference["outputs"]["participant_event_manifest"]
        receipt = reference["export_receipt"]
        rows = artifact["rows"]
        participant_count = artifact["participant_count"]
        if len(rows) != participant_count or [row["reference_row_index"] for row in rows] != list(
            range(participant_count)
        ):
            raise BaselineReproductionError(
                "The private alignment rows are not one exact contiguous reference axis."
            )
        if artifact["alignment_method"] == "private-source-id-to-run-token/1":
            identities = [canonical_json_bytes(row["participant_private_id"]) for row in rows]
        else:
            identities = [str(row["participant_private_token"]).encode("ascii") for row in rows]
        if len(set(identities)) != participant_count:
            raise BaselineReproductionError(
                "The private alignment rows contain a duplicate participant binding."
            )

        row_order_preimage = {
            "alignment_method": artifact["alignment_method"],
            "participant_count": participant_count,
            "ordered_reference_row_bindings": rows,
        }
        _validate(row_order_preimage, "ReferenceRowOrderDigestPreimage")
        row_order_digest = structured_sha256("ebm-audit/reference-row-order/1", row_order_preimage)
        artifact_digest = structured_sha256("ebm-audit/reference-private-alignment/1", artifact)
        if (
            artifact["reference_row_order_digest"] != row_order_digest
            or dataset["reference_row_order_digest"] != row_order_digest
            or manifest["reference_row_order_digest"] != row_order_digest
            or dataset["private_alignment_artifact_digest"] != artifact_digest
            or receipt["private_alignment_artifact_digest"] != artifact_digest
            or artifact["scientific_data_digest"] != dataset["scientific_data_digest"]
            or artifact["participant_count"] != dataset["participant_count"]
            or artifact["alignment_method"] != dataset["participant_alignment_method"]
            or artifact["token_parameters"] != dataset["token_parameters"]
        ):
            raise BaselineReproductionError(
                "The private alignment artifact is detached from the reference owners."
            )
    except BaselineReproductionError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise BaselineReproductionError(
            "The private alignment artifact bindings are invalid."
        ) from exc
    return artifact


def _imported_reference_mapping(owner: object) -> dict[str, Any]:
    state = _read_imported_reference_owner(owner)
    value = strict_json_loads(state.reference_bytes)
    if type(value) is not dict or canonical_json_bytes(value) != state.reference_bytes:
        raise BaselineReproductionError("The imported reference owner is invalid.")
    reference = _verify_self_identity(
        cast(Mapping[str, Any], value),
        identity_field="reference_id",
        preimage_definition="CanonicalReferenceResultDigestPreimage",
        result_definition="CanonicalReferenceResult",
        domain="ebm-audit/canonical-reference/2",
    )
    _validate_projection_cross_fields(reference, require_field_origins=True)
    return reference


def _connected_mapping(owner: object) -> dict[str, Any]:
    state = _read_connected_owner(owner)
    value = strict_json_loads(state.canonical_bytes)
    if type(value) is not dict or canonical_json_bytes(value) != state.canonical_bytes:
        raise BaselineReproductionError("The connected baseline owner is invalid.")
    connected = _verify_self_identity(
        cast(Mapping[str, Any], value),
        identity_field="result_id",
        preimage_definition="BaselineConnectedResultDigestPreimage",
        result_definition="BaselineConnectedResultProjection",
        domain="ebm-audit/baseline-connected-result/2",
    )
    _validate_projection_cross_fields(connected, require_field_origins=False)
    return connected


def _private_array(name: str, value: object) -> _PrivateArray:
    try:
        array = canonical_array(value)
        material = bytes(array.tobytes(order="C"))
        return _PrivateArray(
            name=name,
            dtype=str(array.dtype.name),
            shape=tuple(int(axis) for axis in array.shape),
            material=material,
        )
    except Exception:
        raise BaselineReproductionError("A supplied reference array is invalid.") from None


def _private_arrays_mapping(
    arrays: tuple[_PrivateArray, ...],
) -> dict[str, Any]:
    if len({item.name for item in arrays}) != len(arrays):
        raise BaselineReproductionError("The private reference array owner is invalid.")
    return {item.name: item.array() for item in arrays}


def _verify_reference_array_material(
    reference: Mapping[str, Any],
    supplied_arrays: Mapping[str, Any],
) -> tuple[_PrivateArray, ...]:
    try:
        catalog = cast(Mapping[str, Mapping[str, Any]], reference["outputs"]["arrays"])
        if set(supplied_arrays) != set(catalog) or any(
            type(name) is not str for name in supplied_arrays
        ):
            raise BaselineReproductionError(
                "The supplied reference arrays do not match the closed catalog."
            )
        private_arrays = tuple(
            _private_array(name, supplied_arrays[name]) for name in sorted(supplied_arrays)
        )
        arrays = _private_arrays_mapping(private_arrays)
        for name, expected in catalog.items():
            observed = array_catalog_entry(
                name,
                arrays[name],
                semantic_version=cast(str, expected["semantic_version"]),
            )
            if canonical_json_bytes(observed) != canonical_json_bytes(expected):
                raise BaselineReproductionError(
                    "A supplied reference array is detached from its catalog."
                )
        if any(name.startswith("evaluation_") for name in arrays):
            raise BaselineReproductionError(
                "Evaluation reference arrays require a separate private cohort owner."
            )
        training_indexes = arrays.get("training_row_indexes")
        if training_indexes is not None:
            participant_count = cast(int, reference["dataset"]["participant_count"])
            if (
                training_indexes.dtype.name != "int64"
                or training_indexes.shape != (participant_count,)
                or training_indexes.tolist() != list(range(participant_count))
            ):
                raise BaselineReproductionError(
                    "Reference training rows are not the exact declared reference axis."
                )
        return private_arrays
    except BaselineReproductionError:
        raise
    except (KeyError, TypeError, ValueError):
        raise BaselineReproductionError("The supplied reference array owner is invalid.") from None


def _typed_private_id_key(value: Mapping[str, Any]) -> tuple[str, str | int]:
    scalar_type = value.get("type")
    scalar = value.get("value")
    if scalar_type == "string" and type(scalar) is str:
        return "string", scalar
    if scalar_type == "integer" and type(scalar) is int:
        return "integer", scalar
    raise BaselineReproductionError("A private participant alignment is invalid.")


def _identity_private_id_key(value: object) -> tuple[str, str | int]:
    if type(value) is str:
        return "string", value
    if type(value) is int:
        return "integer", value
    raise BaselineReproductionError("The current participant identity owner is invalid.")


def _current_identity_row_digest(identity_map: IdentityMap) -> str:
    rows = sorted(
        identity_map.rows,
        key=lambda row: row.participant_internal_index,
    )
    if [row.participant_internal_index for row in rows] != list(range(len(rows))):
        raise BaselineReproductionError("The current participant identity owner is invalid.")
    preimage = {
        "identity_schema_version": "ebm-audit-current-identity-row-digest/1.0",
        "dataset_variant_id": identity_map.dataset_variant_id,
        "key_id_digest": identity_map.token_parameters["key_id_digest"],
        "ordered_internal_token_rows": [
            {
                "participant_internal_index": row.participant_internal_index,
                "participant_private_token": row.participant_private_token,
            }
            for row in rows
        ],
    }
    _validate(preimage, "CurrentIdentityRowDigestPreimage")
    return structured_sha256("ebm-audit/current-identity-rows/1", preimage)


def _reference_to_current_rows(
    artifact: Mapping[str, Any],
    identity_map: IdentityMap,
) -> tuple[int, ...]:
    rows = cast(list[Mapping[str, Any]], artifact["rows"])
    current_rows = identity_map.rows
    if artifact["participant_count"] != len(current_rows) or cast(
        Mapping[str, Any], artifact["token_parameters"]
    ) != dict(identity_map.token_parameters):
        raise BaselineReproductionError(
            "The reference alignment is not bound to the current identity namespace."
        )
    if artifact["alignment_method"] == "private-source-id-to-run-token/1":
        current_by_identity = {
            _identity_private_id_key(row.participant_private_id): row.participant_internal_index
            for row in current_rows
        }
        try:
            ordered = tuple(
                current_by_identity[_typed_private_id_key(row["participant_private_id"])]
                for row in rows
            )
        except KeyError:
            raise BaselineReproductionError(
                "The reference alignment is not bound to the current identity namespace."
            ) from None
    else:
        current_by_token = {
            row.participant_private_token: row.participant_internal_index for row in current_rows
        }
        try:
            ordered = tuple(
                current_by_token[cast(str, row["participant_private_token"])] for row in rows
            )
        except KeyError:
            raise BaselineReproductionError(
                "The reference alignment is not bound to the current identity namespace."
            ) from None
    if sorted(ordered) != list(range(len(current_rows))):
        raise BaselineReproductionError(
            "The reference alignment does not own the complete current participant set."
        )
    return ordered


def _reference_alignment_for_source(
    source: _FinalizedBaselineSource,
    artifact: Mapping[str, Any],
) -> tuple[ReferenceAlignmentStatus, tuple[int, ...] | None]:
    """Separate a valid foreign dataset from an invalid same-dataset alignment."""

    dataset = source.canonical_dataset
    if (
        artifact["scientific_data_digest"] != dataset.scientific_data_digest
        or artifact["participant_count"] != dataset.view.participant_count
    ):
        return "SCIENTIFIC_MISMATCH", None
    return "ALIGNED", _reference_to_current_rows(
        artifact,
        dataset.private.identity_map,
    )


def _reference_owner_preimage(
    source: _FinalizedBaselineSource,
    reference: Mapping[str, Any],
    artifact: Mapping[str, Any],
    current_identity_row_digest: str,
) -> dict[str, Any]:
    body = cast(Mapping[str, Any], source.source_record["body"])
    identity_map = source.canonical_dataset.private.identity_map
    preimage = {
        "owner_schema_version": "ebm-audit-verified-reference-alignment-owner/1.0",
        "source_result_id": source.source_record["result_id"],
        "source_plan_digest": body["plan_digest"],
        "source_candidate_id": body["candidate_id"],
        "source_config_digest": body["config_digest"],
        "source_scientific_data_digest": body["input_digest"],
        "reference_id": reference["reference_id"],
        "private_alignment_artifact_digest": structured_sha256(
            "ebm-audit/reference-private-alignment/1",
            artifact,
        ),
        "reference_row_order_digest": artifact["reference_row_order_digest"],
        "current_identity_key_id_digest": identity_map.token_parameters[
            "key_id_digest"
        ],
        "current_identity_row_digest": current_identity_row_digest,
    }
    _validate(preimage, "VerifiedReferenceAlignmentOwnerDigestPreimage")
    return preimage


def _validated_imported_reference_state(
    reference_result: Mapping[str, Any],
    reference_arrays: Mapping[str, Any],
) -> _ImportedReferenceState:
    reference = _verify_self_identity(
        reference_result,
        identity_field="reference_id",
        preimage_definition="CanonicalReferenceResultDigestPreimage",
        result_definition="CanonicalReferenceResult",
        domain="ebm-audit/canonical-reference/2",
    )
    _validate_projection_cross_fields(reference, require_field_origins=True)
    private_arrays = _verify_reference_array_material(reference, reference_arrays)
    return _ImportedReferenceState(
        reference_bytes=canonical_json_bytes(reference),
        reference_arrays=private_arrays,
    )


def _reverify_imported_reference_owner(
    owner: object,
) -> tuple[_ImportedReferenceState, dict[str, Any], dict[str, Any]]:
    state = _read_imported_reference_owner(owner)
    reference_value = strict_json_loads(state.reference_bytes)
    if type(reference_value) is not dict:
        raise BaselineReproductionError("The imported reference owner is invalid.")
    arrays = _private_arrays_mapping(state.reference_arrays)
    expected = _validated_imported_reference_state(
        cast(Mapping[str, Any], reference_value),
        arrays,
    )
    if expected != state:
        raise BaselineReproductionError("The imported reference owner is detached.")
    return state, cast(dict[str, Any], reference_value), arrays


class _IssueVerifiedReferenceResult(Protocol):
    def __call__(
        self,
        reference_result: Mapping[str, Any],
        *,
        reference_arrays: Mapping[str, Any],
    ) -> VerifiedReferenceResult: ...


def _build_reference_result_issuer(
    register: Callable[[object, _ImportedReferenceState], None],
) -> _IssueVerifiedReferenceResult:
    def issue_verified_reference_result(
        reference_result: Mapping[str, Any],
        *,
        reference_arrays: Mapping[str, Any],
    ) -> VerifiedReferenceResult:
        """Issue an opaque owner only at the independent reference-import boundary."""

        owner = object.__new__(VerifiedReferenceResult)
        state = _validated_imported_reference_state(
            reference_result,
            reference_arrays,
        )
        register(owner, state)
        _reverify_imported_reference_owner(owner)
        return owner

    return issue_verified_reference_result


issue_verified_reference_result: _IssueVerifiedReferenceResult = _build_reference_result_issuer(
    _register_imported_reference_owner
)
del _register_imported_reference_owner
del _build_reference_result_issuer


def _reference_owner_state_from_validated_inputs(
    source: _FinalizedBaselineSource,
    reference_owner: object,
    reference: Mapping[str, Any],
    private_alignment_artifact: Mapping[str, Any],
) -> _ReferenceOwnerState:
    """Derive one alignment state from owners validated by this public call."""

    artifact = _verify_private_alignment_artifact(
        private_alignment_artifact,
        reference,
    )
    identity_map = source.canonical_dataset.private.identity_map
    alignment_status, reference_to_current = _reference_alignment_for_source(
        source,
        artifact,
    )
    current_row_digest = _current_identity_row_digest(identity_map)
    preimage = _reference_owner_preimage(
        source,
        reference,
        artifact,
        current_row_digest,
    )
    return _ReferenceOwnerState(
        owner_id=structured_sha256(
            "ebm-audit/verified-reference-alignment-owner/1",
            preimage,
        ),
        source_result=source.source_result,
        reference_owner=cast(VerifiedReferenceResult, reference_owner),
        alignment_bytes=canonical_json_bytes(artifact),
        alignment_status=alignment_status,
        reference_to_current=reference_to_current,
        current_identity_row_digest=current_row_digest,
    )


class _IssueVerifiedReferenceAlignmentOwner(Protocol):
    def __call__(
        self,
        source_result: FinalizedResult,
        reference_owner: VerifiedReferenceResult,
        *,
        private_alignment_artifact: Mapping[str, Any],
    ) -> VerifiedReferenceAlignmentOwner: ...


def _build_reference_alignment_issuer(
    register: Callable[[object, _ReferenceOwnerState], None],
) -> _IssueVerifiedReferenceAlignmentOwner:
    def issue_verified_reference_alignment_owner(
        source_result: FinalizedResult,
        reference_owner: VerifiedReferenceResult,
        *,
        private_alignment_artifact: Mapping[str, Any],
    ) -> VerifiedReferenceAlignmentOwner:
        """Bind one independently imported reference to the current identity owner."""

        owner = object.__new__(VerifiedReferenceAlignmentOwner)
        try:
            source = _finalized_baseline_source(source_result)
        except TypeError:
            raise BaselineReproductionError(
                "A successful finalized result with private baseline owners is required."
            ) from None
        _imported_state, reference, _reference_arrays = _reverify_imported_reference_owner(
            reference_owner,
        )
        state = _reference_owner_state_from_validated_inputs(
            source,
            reference_owner,
            reference,
            private_alignment_artifact,
        )
        register(owner, state)
        if _read_reference_owner(owner) is not state:
            raise BaselineReproductionError(
                "Verified reference authority is unavailable."
            )
        return owner

    return issue_verified_reference_alignment_owner


issue_verified_reference_alignment_owner: _IssueVerifiedReferenceAlignmentOwner = (
    _build_reference_alignment_issuer(_register_reference_owner)
)
del _register_reference_owner
del _build_reference_alignment_issuer


def _reverify_reference_owner(
    owner: object,
    *,
    validated_source_result: FinalizedResult | None = None,
    validated_source_state: _FinalizedResultState | None = None,
) -> tuple[_ReferenceOwnerState, _FinalizedBaselineSource, dict[str, Any], dict[str, Any]]:
    state = _read_reference_owner(owner)
    artifact_value = strict_json_loads(state.alignment_bytes)
    if type(artifact_value) is not dict:
        raise BaselineReproductionError("The verified reference owner is invalid.")
    _imported_state, reference_value, _arrays = _reverify_imported_reference_owner(
        state.reference_owner
    )
    if (validated_source_result is None) is not (validated_source_state is None):
        raise BaselineReproductionError("The verified reference owner is detached.")
    if (
        validated_source_result is not None
        and state.source_result is not validated_source_result
    ):
        raise BaselineReproductionError("The verified reference owner is detached.")
    try:
        source = _finalized_baseline_source(
            state.source_result,
            validated_source_state,
        )
    except TypeError:
        raise BaselineReproductionError("The verified reference owner is detached.") from None
    expected = _reference_owner_state_from_validated_inputs(
        source,
        state.reference_owner,
        reference_value,
        cast(Mapping[str, Any], artifact_value),
    )
    if expected != state:
        raise BaselineReproductionError("The verified reference owner is detached.")
    return state, source, reference_value, cast(dict[str, Any], artifact_value)


def _baseline_inclusion_owner(source: _FinalizedBaselineSource) -> tuple[dict[str, Any], str]:
    dataset = source.canonical_dataset
    view = dataset.view
    data_accounting = view.data_accounting.to_record()
    preimage = {
        "inclusion_schema_version": "ebm-audit-baseline-inclusion/1.0",
        "dataset_variant_id": view.variant_id,
        "scientific_data_digest": dataset.scientific_data_digest,
        "participant_count": view.participant_count,
        "event_count": view.event_count,
        "event_ids": list(view.event_ids),
        "selected_row_manifest_digest": view.source_row_manifest_digest,
        "data_accounting_digest": structured_sha256(
            "ebm-audit/data-accounting/1",
            data_accounting,
        ),
        "universe_decision_id": dataset.private.universe_decision_id,
    }
    _validate(preimage, "BaselineInclusionDigestPreimage")
    return preimage, structured_sha256("ebm-audit/baseline-inclusion/1", preimage)


def _current_alignment_artifact(source: _FinalizedBaselineSource) -> dict[str, Any]:
    identity_map = source.canonical_dataset.private.identity_map
    ordered_rows = sorted(
        identity_map.rows,
        key=lambda row: row.participant_internal_index,
    )
    rows = [
        {
            "reference_row_index": index,
            "participant_private_token": row.participant_private_token,
        }
        for index, row in enumerate(ordered_rows)
    ]
    row_preimage = {
        "alignment_method": "shared-private-namespace/1",
        "participant_count": len(rows),
        "ordered_reference_row_bindings": rows,
    }
    _validate(row_preimage, "ReferenceRowOrderDigestPreimage")
    artifact = {
        "alignment_schema_version": "ebm-audit-private-reference-alignment/1.0",
        "alignment_method": "shared-private-namespace/1",
        "scientific_data_digest": source.canonical_dataset.scientific_data_digest,
        "participant_count": len(rows),
        "reference_row_order_digest": structured_sha256(
            "ebm-audit/reference-row-order/1",
            row_preimage,
        ),
        "token_parameters": dict(identity_map.token_parameters),
        "rows": rows,
    }
    _validate(artifact, "PrivateReferenceAlignmentArtifact")
    return artifact


def _source_binding(
    source: _FinalizedBaselineSource,
    reference_owner: VerifiedReferenceAlignmentOwner | None,
) -> dict[str, Any]:
    body = cast(Mapping[str, Any], source.source_record["body"])
    binding = {
        "binding_schema_version": "ebm-audit-baseline-source-binding/1.0",
        "source_result_id": source.source_record["result_id"],
        "source_plan_digest": body["plan_digest"],
        "source_candidate_id": body["candidate_id"],
        "source_analysis_spec_id": body["analysis_spec_id"],
        "source_universe_id": body["universe_id"],
        "source_config_digest": body["config_digest"],
        "source_scientific_data_digest": body["input_digest"],
        "source_execution_input_projection_digest": execution_input_projection_digest(
            source.scientific_owner
        ),
        "reference_alignment_owner_id": (
            None if reference_owner is None else reference_owner.owner_id
        ),
    }
    _validate(binding, "BaselineSourceBinding")
    return binding


def _implementation_projection(source: _FinalizedBaselineSource) -> dict[str, Any]:
    body = cast(Mapping[str, Any], source.source_record["body"])
    identity = cast(Mapping[str, Any], source.scientific_owner["selected_backend_identity"])
    chain_results = cast(list[Mapping[str, Any]], body["chain_results"])
    seed_policy = {
        "policy_schema_version": "ebm-audit-baseline-seed-chain-policy/1.0",
        "ordered_chains": [
            {
                "chain_plan_position": row["chain_plan_position"],
                "chain_id": row["chain_id"],
                "seed": row["seed"],
            }
            for row in chain_results
        ],
        "reference_chain_rule_id": body["reference_chain"]["rule_id"],
    }
    _validate(seed_policy, "BaselineSeedChainPolicyDigestPreimage")
    source_version = (
        identity.get("backend_source_commit")
        or identity.get("backend_version")
        or identity.get("adapter_version")
    )
    evidence = [
        {
            "kind": "worker-code",
            "digest": identity["worker_code_digest"],
            "note": "Exact worker code identity reported by the selected backend.",
        }
    ]
    if identity.get("backend_source_digest") is not None:
        evidence.append(
            {
                "kind": "backend-source",
                "digest": identity["backend_source_digest"],
                "note": "Exact selected backend source identity.",
            }
        )
    implementation = {
        "implementation_id": identity["adapter_id"],
        "implementation_version": identity["adapter_version"],
        "implementation_code_or_artifact_digest": (
            identity.get("backend_source_digest") or identity["worker_code_digest"]
        ),
        "algorithm_id": source.scientific_owner["algorithm_id"],
        "settings_digest": source.scientific_owner["settings_digest"],
        "environment_digest": identity["environment_digest"],
        "seed_chain_policy_digest": structured_sha256(
            "ebm-audit/baseline-seed-chain-policy/1",
            seed_policy,
        ),
        "source_commit_or_version": source_version,
        "evidence": evidence,
    }
    _validate(implementation, "ReferenceImplementationProvenance")
    return implementation


def _effective_event_labels(source: _FinalizedBaselineSource) -> list[str]:
    """Project ordered effective labels from the retained private descriptor."""

    try:
        binding = source.canonical_dataset.private.canonical_ingestion_binding
        descriptor = cast(Mapping[str, Any], binding["audit_dataset"])
        event_specs = cast(Sequence[Mapping[str, Any]], descriptor["event_specs"])
        event_ids = source.canonical_dataset.view.event_ids
        if len(event_specs) != len(event_ids):
            raise BaselineReproductionError(
                "The private event-label owner is detached from the canonical event axis."
            )
        labels: list[str] = []
        for position, event in enumerate(event_specs):
            override = event["privacy_sensitive_display_override"]
            display_name = event["display_name"]
            label = override if override is not None else display_name
            if (
                event["event_id"] != event_ids[position]
                or type(label) is not str
                or not label
            ):
                raise BaselineReproductionError(
                    "The private event-label owner is detached from the canonical event axis."
                )
            labels.append(label)
        if len(set(labels)) != len(labels):
            raise BaselineReproductionError(
                "The private effective event labels are not unique."
            )
        return labels
    except BaselineReproductionError:
        raise
    except (KeyError, TypeError, ValueError):
        raise BaselineReproductionError(
            "The private event-label owner is invalid."
        ) from None


_REFERENCE_ARRAY_NAMES = frozenset(
    _ORDER_DISTRIBUTION_ARRAYS
    | _STAGE_ARRAYS
    | {
        "training_row_indexes",
        "evaluation_row_indexes",
    }
)
_CONNECTED_REFERENCE_ARRAY_NAMES = frozenset(
    name for name in _REFERENCE_ARRAY_NAMES if not name.startswith("evaluation_")
)
_TRAINING_PARTICIPANT_ARRAYS = frozenset(
    name for name in _REFERENCE_ARRAY_NAMES if name.startswith("training_")
)


def _connected_array_catalog(
    source: _FinalizedBaselineSource,
    reference_to_current: tuple[int, ...],
) -> tuple[dict[str, Any], str]:
    source_catalog = cast(
        Mapping[str, Mapping[str, Any]],
        source.reference_chain_payload["arrays"],
    )
    source_arrays = source.reference_chain_arrays
    catalog: dict[str, Any] = {}
    for name in sorted(set(source_catalog) & _CONNECTED_REFERENCE_ARRAY_NAMES):
        try:
            array = canonical_array(source_arrays[name])
            expected = source_catalog[name]
            observed = array_catalog_entry(
                name,
                array,
                semantic_version=cast(str, expected["semantic_version"]),
            )
            if observed != expected:
                raise BaselineReproductionError(
                    "The sealed worker array is detached from its catalog."
                )
            if name == "training_row_indexes":
                array = np.arange(len(reference_to_current), dtype=np.int64)
            elif name in _TRAINING_PARTICIPANT_ARRAYS:
                array = array[np.asarray(reference_to_current, dtype=np.int64)]
            catalog[name] = array_catalog_entry(
                name,
                array,
                semantic_version=cast(str, expected["semantic_version"]),
            )
        except BaselineReproductionError:
            raise
        except (KeyError, TypeError, ValueError, IndexError):
            raise BaselineReproductionError(
                "The sealed worker array projection is invalid."
            ) from None
    row_indexes = np.arange(len(reference_to_current), dtype=np.int64)
    row_entry = array_catalog_entry(
        "training_row_indexes",
        row_indexes,
        semantic_version="contiguous-internal-row-index/1",
    )
    return catalog, cast(str, row_entry["array_digest"])


def _derive_connected_mapping(
    source: _FinalizedBaselineSource,
    reference_owner: VerifiedReferenceAlignmentOwner | None,
    *,
    validated_reference: tuple[
        _ReferenceOwnerState,
        _FinalizedBaselineSource,
        dict[str, Any],
        dict[str, Any],
    ]
    | None = None,
) -> dict[str, Any]:
    if reference_owner is None:
        if validated_reference is not None:
            raise BaselineReproductionError(
                "A reference validation was supplied without a reference owner."
            )
        artifact = _current_alignment_artifact(source)
        reference_to_current = tuple(range(source.canonical_dataset.view.participant_count))
    else:
        reference_validation = (
            _reverify_reference_owner(reference_owner)
            if validated_reference is None
            else validated_reference
        )
        reference_state, reference_source, _reference, artifact = reference_validation
        if reference_source.source_result is not source.source_result:
            raise BaselineReproductionError(
                "The reference owner belongs to a different finalized result."
            )
        if _read_reference_owner(reference_owner) is not reference_state:
            raise BaselineReproductionError(
                "The verified reference owner is detached."
            )
        if reference_state.alignment_status == "SCIENTIFIC_MISMATCH":
            artifact = _current_alignment_artifact(source)
            reference_to_current = tuple(
                range(source.canonical_dataset.view.participant_count)
            )
        else:
            aligned_rows = reference_state.reference_to_current
            if aligned_rows is None:
                raise BaselineReproductionError(
                    "The verified reference owner is detached."
                )
            reference_to_current = aligned_rows
    inclusion_preimage, inclusion_digest = _baseline_inclusion_owner(source)
    del inclusion_preimage
    binding = _source_binding(source, reference_owner)
    artifact_digest = structured_sha256(
        "ebm-audit/reference-private-alignment/1",
        artifact,
    )
    array_catalog, row_indexes_digest = _connected_array_catalog(
        source,
        reference_to_current,
    )
    view = source.canonical_dataset.view
    components = source.canonical_dataset.private.component_digests
    stage_output_present = bool(set(array_catalog) & _STAGE_ARRAYS)
    body = cast(Mapping[str, Any], source.source_record["body"])
    chain_results = sorted(
        cast(Sequence[Mapping[str, Any]], body["chain_results"]),
        key=lambda row: cast(int, row["chain_plan_position"]),
    )
    if [row["chain_plan_position"] for row in chain_results] != list(
        range(len(chain_results))
    ):
        raise BaselineReproductionError(
            "The finalized diagnostic chain plan is invalid."
        )
    diagnostics_digest = _statistical_diagnostics_digest(
        cast(Mapping[str, Any], body["convergence"]),
        [cast(str, row["chain_execution_id"]) for row in chain_results],
    )
    scientific_contract = {
        "event_ids": list(view.event_ids),
        "event_labels": _effective_event_labels(source),
        "event_directions": list(view.event_directions),
        "preprocessing_digest": components.preprocessing_digest,
        "missingness_digest": components.missingness_digest,
        "inclusion_digest": inclusion_digest,
        "stage_semantics_digest": (
            source.reference_chain_payload["stage_semantics_digest"]
            if stage_output_present
            else None
        ),
    }
    manifest = {
        "manifest_schema_version": "ebm-audit-reference-participant-event-manifest/1.0",
        "participant_count": view.participant_count,
        "event_count": view.event_count,
        "event_ids": list(view.event_ids),
        "reference_row_indexes_digest": row_indexes_digest,
        "reference_row_order_digest": artifact["reference_row_order_digest"],
        "core_data_accounting_digest": structured_sha256(
            "ebm-audit/data-accounting/1",
            view.data_accounting.to_record(),
        ),
    }
    preimage = {
        "projection_schema_version": "ebm-audit-baseline-connected-result/3.0",
        "benchmark_subject_digest": structured_sha256(
            "ebm-audit/baseline-subject/1",
            binding,
        ),
        "source_binding": binding,
        "implementation": _implementation_projection(source),
        "dataset": {
            "scientific_data_digest": source.canonical_dataset.scientific_data_digest,
            "participant_count": view.participant_count,
            "event_count": view.event_count,
            "participant_alignment_method": artifact["alignment_method"],
            "private_alignment_artifact_digest": artifact_digest,
            "reference_row_order_digest": artifact["reference_row_order_digest"],
            "token_parameters": copy.deepcopy(artifact["token_parameters"]),
        },
        "scientific_contract": scientific_contract,
        "outputs": {
            "central_order_permutation": copy.deepcopy(
                source.reference_chain_payload["central_order_permutation"]
            ),
            "arrays": array_catalog,
            "participant_event_manifest": manifest,
            "statistical_diagnostics_digest": diagnostics_digest,
        },
        "result_id": None,
    }
    _validate(preimage, "BaselineConnectedResultDigestPreimage")
    _validate_projection_cross_fields(preimage, require_field_origins=False)
    result = copy.deepcopy(preimage)
    result["result_id"] = structured_sha256(
        "ebm-audit/baseline-connected-result/2",
        preimage,
    )
    _validate(result, "BaselineConnectedResultProjection")
    return result


class _ProjectConnectedBaselineResult(Protocol):
    def __call__(
        self,
        source_result: FinalizedResult,
        *,
        reference_owner: VerifiedReferenceAlignmentOwner | None = None,
    ) -> ConnectedBaselineResult: ...


def _build_connected_result_projector(
    register: Callable[[object, _ConnectedOwnerState], None],
) -> _ProjectConnectedBaselineResult:
    def project_connected_baseline_result(
        source_result: FinalizedResult,
        *,
        reference_owner: VerifiedReferenceAlignmentOwner | None = None,
    ) -> ConnectedBaselineResult:
        """Project exact sealed output from one successful finalized core result."""

        owner = object.__new__(ConnectedBaselineResult)
        reference_validation = None
        if reference_owner is not None:
            reference_validation = _reverify_reference_owner(
                reference_owner
            )
            state, source, _reference, _artifact = reference_validation
            if (
                state.source_result is not source_result
                or source.source_result is not source_result
            ):
                raise BaselineReproductionError(
                    "The reference owner belongs to a different finalized result."
                )
        else:
            try:
                source = _finalized_baseline_source(source_result)
            except TypeError:
                raise BaselineReproductionError(
                    "A successful finalized result with private baseline owners is required."
                ) from None
        connected = _derive_connected_mapping(
            source,
            reference_owner,
            validated_reference=reference_validation,
        )
        owner_state = _ConnectedOwnerState(
            canonical_bytes=canonical_json_bytes(connected),
            source_result=source_result,
            reference_owner=reference_owner,
        )
        register(
            owner,
            owner_state,
        )
        if _read_connected_owner(owner) is not owner_state:
            raise BaselineReproductionError(
                "Connected baseline authority is unavailable."
            )
        return owner

    return project_connected_baseline_result


project_connected_baseline_result: _ProjectConnectedBaselineResult = (
    _build_connected_result_projector(_register_connected_owner)
)
del _register_connected_owner
del _build_connected_result_projector


@dataclass(frozen=True, repr=False)
class _ValidatedConnectedOwner:
    state: _ConnectedOwnerState
    source: _FinalizedBaselineSource
    connected: dict[str, Any]
    reference: dict[str, Any] | None


def _reverify_connected_owner_context(
    owner: object,
    reference_owner: VerifiedReferenceAlignmentOwner | None,
    *,
    validated_source_result: FinalizedResult | None = None,
    validated_source_state: _FinalizedResultState | None = None,
) -> _ValidatedConnectedOwner:
    state = _read_connected_owner(owner)
    if state.reference_owner is not reference_owner:
        raise BaselineReproductionError(
            "The connected result is bound to a different reference owner."
        )
    reference_validation = None
    reference = None
    if (validated_source_result is None) is not (validated_source_state is None):
        raise BaselineReproductionError("The connected baseline owner is detached.")
    if (
        validated_source_result is not None
        and state.source_result is not validated_source_result
    ):
        raise BaselineReproductionError("The connected baseline owner is detached.")
    if reference_owner is not None:
        reference_validation = _reverify_reference_owner(
            reference_owner,
            validated_source_result=validated_source_result,
            validated_source_state=validated_source_state,
        )
        reference_state, source, reference, _artifact = reference_validation
        if reference_state.source_result is not state.source_result:
            raise BaselineReproductionError(
                "The connected baseline owner is detached."
            )
    else:
        try:
            source = _finalized_baseline_source(
                state.source_result,
                validated_source_state,
            )
        except TypeError:
            raise BaselineReproductionError(
                "The connected baseline owner is detached."
            ) from None
    expected = _derive_connected_mapping(
        source,
        reference_owner,
        validated_reference=reference_validation,
    )
    if canonical_json_bytes(expected) != state.canonical_bytes:
        raise BaselineReproductionError("The connected baseline owner is detached.")
    connected = _connected_mapping(owner)
    return _ValidatedConnectedOwner(
        state=state,
        source=source,
        connected=connected,
        reference=reference,
    )


def _comparison_value_digest(value: object) -> str:
    return structured_sha256("ebm-audit/baseline-comparison-value/1", value)


def _comparison_row(
    comparison_id: str,
    reference_value: object | None,
    connected_value: object | None,
    tolerance: Mapping[str, Any],
    *,
    rule: Literal["EXACT_RFC8785_VALUE", "EXACT_CANONICAL_ARRAY_DIGEST"] = ("EXACT_RFC8785_VALUE"),
    availability: Literal["SUPPLIED", "NOT_SUPPLIED", "NOT_REQUIRED"] = "SUPPLIED",
    not_comparable_reason: str | None = None,
) -> dict[str, Any]:
    if not_comparable_reason is not None:
        return {
            "comparison_id": comparison_id,
            "availability": availability,
            "comparison_rule": rule,
            "reference_value_digest": None,
            "connected_value_digest": None,
            "absolute_tolerance": tolerance["absolute_float_tolerance"],
            "relative_tolerance": tolerance["relative_float_tolerance"],
            "outcome": "NOT_COMPARABLE",
            "reason_code": not_comparable_reason,
        }
    if availability != "SUPPLIED":
        outcome = "NOT_REQUIRED" if availability == "NOT_REQUIRED" else "NOT_SUPPLIED"
        reason = (
            "BASELINE.NOT_REQUIRED" if availability == "NOT_REQUIRED" else ("BASELINE.NOT_SUPPLIED")
        )
        return {
            "comparison_id": comparison_id,
            "availability": availability,
            "comparison_rule": rule,
            "reference_value_digest": None,
            "connected_value_digest": None,
            "absolute_tolerance": tolerance["absolute_float_tolerance"],
            "relative_tolerance": tolerance["relative_float_tolerance"],
            "outcome": outcome,
            "reason_code": reason,
        }

    reference_digest = _comparison_value_digest(reference_value)
    connected_digest = _comparison_value_digest(connected_value)
    matches = canonical_json_bytes(reference_value) == canonical_json_bytes(connected_value)
    return {
        "comparison_id": comparison_id,
        "availability": "SUPPLIED",
        "comparison_rule": rule,
        "reference_value_digest": reference_digest,
        "connected_value_digest": connected_digest,
        "absolute_tolerance": tolerance["absolute_float_tolerance"],
        "relative_tolerance": tolerance["relative_float_tolerance"],
        "outcome": "MATCH" if matches else "MISMATCH",
        "reason_code": None if matches else "BASELINE.VALUE_MISMATCH",
    }


def _derive_comparisons(
    connected: Mapping[str, Any],
    reference: Mapping[str, Any] | None,
    tolerance: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], BaselineStatus, list[str]]:
    if reference is None:
        rows = [
            _comparison_row(
                comparison_id,
                None,
                None,
                tolerance,
                availability="NOT_SUPPLIED",
            )
            for comparison_id in BASELINE_COMPARISON_IDS
        ]
        return (
            rows,
            "BASELINE_REFERENCE_NOT_SUPPLIED",
            ["BASELINE.REFERENCE_NOT_SUPPLIED"],
        )

    required_origin_keys = {
        "implementation",
        "dataset",
        "scientific_contract",
        "outputs.central_order_permutation",
        "outputs.participant_event_manifest",
        "outputs.statistical_diagnostics_digest",
        *(f"outputs.arrays.{name}" for name in reference["outputs"]["arrays"]),
    }
    if set(reference["field_origins"]) != required_origin_keys:
        raise BaselineReproductionError(
            "Reference field provenance is missing, extra, or detached."
        )

    reference_arrays = reference["outputs"]["arrays"]
    connected_arrays = connected["outputs"]["arrays"]
    order_names = sorted(set(reference_arrays) & _ORDER_DISTRIBUTION_ARRAYS)
    stage_names = sorted(set(reference_arrays) & _STAGE_ARRAYS)
    datasets_are_comparable = (
        reference["dataset"]["scientific_data_digest"]
        == connected["dataset"]["scientific_data_digest"]
        and reference["dataset"]["participant_count"]
        == connected["dataset"]["participant_count"]
    )
    data_comparability_reason = (
        None if datasets_are_comparable else "BASELINE.DATASET_NOT_COMPARABLE"
    )
    rows = [
        _comparison_row(
            "dataset-binding",
            reference["dataset"],
            connected["dataset"],
            tolerance,
        ),
        _comparison_row(
            "implementation-identity",
            reference["implementation"],
            connected["implementation"],
            tolerance,
        ),
        _comparison_row(
            "scientific-contract",
            reference["scientific_contract"],
            connected["scientific_contract"],
            tolerance,
            not_comparable_reason=data_comparability_reason,
        ),
        _comparison_row(
            "participant-event-accounting",
            {
                "dataset_counts": [
                    reference["dataset"]["participant_count"],
                    reference["dataset"]["event_count"],
                ],
                "manifest": reference["outputs"]["participant_event_manifest"],
            },
            {
                "dataset_counts": [
                    connected["dataset"]["participant_count"],
                    connected["dataset"]["event_count"],
                ],
                "manifest": connected["outputs"]["participant_event_manifest"],
            },
            tolerance,
            not_comparable_reason=data_comparability_reason,
        ),
        _comparison_row(
            "central-order",
            reference["outputs"]["central_order_permutation"],
            connected["outputs"]["central_order_permutation"],
            tolerance,
            not_comparable_reason=data_comparability_reason,
        ),
        _comparison_row(
            "order-distribution",
            {name: reference_arrays[name] for name in order_names} if order_names else None,
            {name: connected_arrays.get(name) for name in order_names} if order_names else None,
            tolerance,
            rule="EXACT_CANONICAL_ARRAY_DIGEST",
            availability="SUPPLIED" if order_names else "NOT_SUPPLIED",
            not_comparable_reason=data_comparability_reason,
        ),
        _comparison_row(
            "participant-stage-output",
            {name: reference_arrays[name] for name in stage_names} if stage_names else None,
            {name: connected_arrays.get(name) for name in stage_names} if stage_names else None,
            tolerance,
            rule="EXACT_CANONICAL_ARRAY_DIGEST",
            availability=(
                "SUPPLIED"
                if stage_names
                else (
                    "NOT_SUPPLIED"
                    if reference["scientific_contract"]["stage_semantics_digest"] is not None
                    else "NOT_REQUIRED"
                )
            ),
            not_comparable_reason=data_comparability_reason,
        ),
        _comparison_row(
            "statistical-diagnostics",
            reference["outputs"]["statistical_diagnostics_digest"],
            connected["outputs"]["statistical_diagnostics_digest"],
            tolerance,
            availability=(
                "SUPPLIED"
                if reference["outputs"]["statistical_diagnostics_digest"] is not None
                else "NOT_SUPPLIED"
            ),
            not_comparable_reason=data_comparability_reason,
        ),
        _comparison_row(
            "all-supplied-fields",
            reference_arrays,
            {name: connected_arrays.get(name) for name in reference_arrays},
            tolerance,
            rule="EXACT_CANONICAL_ARRAY_DIGEST",
            not_comparable_reason=data_comparability_reason,
        ),
    ]
    if any(row["outcome"] in {"MISMATCH", "NOT_COMPARABLE"} for row in rows):
        reason = (
            "BASELINE.DATASET_NOT_COMPARABLE"
            if not datasets_are_comparable
            else "BASELINE.COMPARISON_MISMATCH"
        )
        return rows, "BASELINE_NOT_REPRODUCED", [reason]
    if any(row["outcome"] == "NOT_SUPPLIED" for row in rows):
        return (
            rows,
            "BASELINE_PARTIALLY_REPRODUCED",
            ["BASELINE.REQUIRED_RICH_OUTPUT_NOT_SUPPLIED"],
        )
    return rows, "BASELINE_REPRODUCED", []


def derive_baseline_reproduction(
    connected_result: ConnectedBaselineResult,
    reference_owner: VerifiedReferenceAlignmentOwner | None,
    *,
    tolerance_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive a record only from exact opaque finalized-result/reference owners."""

    return _derive_baseline_reproduction_with_source_state(
        connected_result,
        reference_owner,
        tolerance_contract=tolerance_contract,
    )


def _derive_baseline_reproduction_with_source_state(
    connected_result: ConnectedBaselineResult,
    reference_owner: VerifiedReferenceAlignmentOwner | None,
    *,
    tolerance_contract: Mapping[str, Any] | None,
    validated_source_result: FinalizedResult | None = None,
    validated_source_state: _FinalizedResultState | None = None,
) -> dict[str, Any]:
    """Derive after retaining a source state validated by this outer call."""

    context = _reverify_connected_owner_context(
        connected_result,
        reference_owner,
        validated_source_result=validated_source_result,
        validated_source_state=validated_source_state,
    )
    connected = context.connected
    tolerance = (
        baseline_tolerance_contract() if tolerance_contract is None else _copy(tolerance_contract)
    )
    _validate(tolerance, "BaselineToleranceContract")
    reference = context.reference

    rows, status, reasons = _derive_comparisons(connected, reference, tolerance)
    record: dict[str, Any] = {
        "record_schema_version": "ebm-audit-baseline-reproduction/2.0",
        "benchmark_subject_digest": connected["benchmark_subject_digest"],
        "reference_presence": "SUPPLIED" if reference is not None else "NOT_SUPPLIED",
        "reference_id": reference["reference_id"] if reference is not None else None,
        "connected_result_id": connected["result_id"],
        "tolerance_contract": tolerance,
        "ordered_comparisons": rows,
        "status": status,
        "validated_language_eligibility": status == "BASELINE_REPRODUCED",
        "reason_codes": reasons,
        "baseline_reproduction_id": None,
    }
    _validate(record, "BaselineReproductionRecordDigestPreimage")
    record["baseline_reproduction_id"] = structured_sha256(
        "ebm-audit/baseline-reproduction/2",
        record,
    )
    _validate(record, "BaselineReproductionRecord")
    return record


def _reverify_verified_baseline_snapshot(
    snapshot: _VerifiedBaselineSnapshot,
    *,
    validated_source_result: FinalizedResult | None = None,
    validated_source_state: _FinalizedResultState | None = None,
) -> None:
    value = strict_json_loads(snapshot.record_bytes)
    if type(value) is not dict or canonical_json_bytes(value) != snapshot.record_bytes:
        raise BaselineReproductionError("Verified baseline reproduction storage is invalid.")
    expected = _derive_baseline_reproduction_with_source_state(
        snapshot.connected_result,
        snapshot.reference_owner,
        tolerance_contract=cast(Mapping[str, Any], value)["tolerance_contract"],
        validated_source_result=validated_source_result,
        validated_source_state=validated_source_state,
    )
    if (
        canonical_json_bytes(expected) != snapshot.record_bytes
        or expected["baseline_reproduction_id"] != snapshot.baseline_reproduction_id
        or expected["connected_result_id"] != snapshot.connected_result_id
        or expected["reference_id"] != snapshot.reference_id
        or expected["status"] != snapshot.status
        or expected["validated_language_eligibility"]
        is not snapshot.validated_language_eligibility
        or tuple(cast(list[str], expected["reason_codes"])) != snapshot.reason_codes
    ):
        raise BaselineReproductionError("Verified baseline reproduction storage is invalid.")


def _verified_baseline_snapshot_with_source_state(
    value: object,
    source_result: FinalizedResult,
    source_state: _FinalizedResultState,
) -> _VerifiedBaselineSnapshot:
    """Read one reproduction using a source validated by this outer call."""

    snapshot = _capture_verified_baseline_snapshot_identity(value)
    try:
        _reverify_verified_baseline_snapshot(
            snapshot,
            validated_source_result=source_result,
            validated_source_state=source_state,
        )
        _VERIFIED_BASELINE_STATES.require(value, snapshot)
    except OneShotRegistryError:
        raise BaselineReproductionError(
            "A genuine verified baseline reproduction capability is required."
        ) from None
    return snapshot


def _capture_verified_baseline_snapshot_identity(
    value: object,
) -> _VerifiedBaselineSnapshot:
    """Capture one exact registry snapshot without replaying its owner graph."""

    if type(value) is not VerifiedBaselineReproduction:
        raise BaselineReproductionError(
            "A genuine verified baseline reproduction capability is required."
        )
    try:
        snapshot = _VERIFIED_BASELINE_STATES[value]
    except (KeyError, TypeError):
        raise BaselineReproductionError(
            "A genuine verified baseline reproduction capability is required."
        ) from None
    try:
        _VERIFIED_BASELINE_STATES.require(value, snapshot)
    except OneShotRegistryError:
        raise BaselineReproductionError(
            "A genuine verified baseline reproduction capability is required."
        ) from None
    return snapshot


def _verified_baseline_source_result_from_snapshot(
    snapshot: _VerifiedBaselineSnapshot,
) -> FinalizedResult:
    """Project source identity from a reproduction validated by this boundary."""

    state = _read_connected_owner(snapshot.connected_result)
    if state.reference_owner is not snapshot.reference_owner:
        raise BaselineReproductionError(
            "Verified baseline reproduction storage is invalid."
        )
    return state.source_result


class _VerifyBaselineReproduction(Protocol):
    def __call__(
        self,
        record: Mapping[str, Any],
        connected_result: ConnectedBaselineResult,
        reference_owner: VerifiedReferenceAlignmentOwner | None,
    ) -> VerifiedBaselineReproduction: ...


def _build_baseline_verifier(
    register: Callable[
        [object, _VerifiedBaselineSnapshot],
        None,
    ],
) -> _VerifyBaselineReproduction:
    def verify_baseline_reproduction(
        record: Mapping[str, Any],
        connected_result: ConnectedBaselineResult,
        reference_owner: VerifiedReferenceAlignmentOwner | None,
    ) -> VerifiedBaselineReproduction:
        """Reject a record that differs from the fixed derivation in any field."""

        capability = object.__new__(VerifiedBaselineReproduction)
        supplied = _copy(record)
        _validate(supplied, "BaselineReproductionRecord")
        expected = derive_baseline_reproduction(
            connected_result,
            reference_owner,
            tolerance_contract=supplied["tolerance_contract"],
        )
        if canonical_json_bytes(supplied) != canonical_json_bytes(expected):
            raise BaselineReproductionError(
                "The baseline reproduction record differs from the fixed derivation."
            )
        snapshot = _VerifiedBaselineSnapshot(
            baseline_reproduction_id=cast(str, expected["baseline_reproduction_id"]),
            connected_result_id=cast(str, expected["connected_result_id"]),
            reference_id=cast(str | None, expected["reference_id"]),
            status=cast(BaselineStatus, expected["status"]),
            validated_language_eligibility=cast(bool, expected["validated_language_eligibility"]),
            reason_codes=tuple(cast(list[str], expected["reason_codes"])),
            record_bytes=canonical_json_bytes(expected),
            connected_result=connected_result,
            reference_owner=reference_owner,
        )
        register(capability, snapshot)
        return capability

    return verify_baseline_reproduction


verify_baseline_reproduction: _VerifyBaselineReproduction = _build_baseline_verifier(
    _register_verified_baseline_snapshot
)
del _register_verified_baseline_snapshot
del _build_baseline_verifier


class _VerifiedBaselineAssessmentSnapshot(NamedTuple):
    baseline_assessment_id: str
    plan_digest: str
    baseline_candidate_ordinal: int
    baseline_candidate_id: str
    baseline_result_id: str
    baseline_result_digest: str
    candidate_terminal_index_digest: str
    terminal_status: str
    baseline_reproduction_id: str | None
    status: BaselineAssessmentStatus
    validated_language_eligibility: bool
    reason_codes: tuple[str, ...]
    record_bytes: bytes
    sealed_result_evidence_set: object
    verified_baseline_reproduction: VerifiedBaselineReproduction | None


def _build_verified_baseline_assessment_registry() -> tuple[
    OneShotWeakRegistry[object, _VerifiedBaselineAssessmentSnapshot],
    Callable[[object, _VerifiedBaselineAssessmentSnapshot], None],
    Callable[[object], _VerifiedBaselineAssessmentSnapshot],
]:
    registry: OneShotWeakRegistry[object, _VerifiedBaselineAssessmentSnapshot]
    issuer: OneShotRegistryIssuer[object, _VerifiedBaselineAssessmentSnapshot]
    registry, issuer = create_one_shot_registry()

    def register(
        capability: object,
        snapshot: _VerifiedBaselineAssessmentSnapshot,
    ) -> None:
        if (
            type(capability) is not VerifiedBaselineAssessment
            or type(snapshot) is not _VerifiedBaselineAssessmentSnapshot
        ):
            raise BaselineReproductionError("Baseline assessment authority is unavailable.")
        binding_failed = False
        try:
            issuer.bind_once(capability, snapshot)
            registry.require(capability, snapshot)
        except OneShotRegistryError:
            binding_failed = True
        if binding_failed:
            raise BaselineReproductionError(
                "Baseline assessment authority is unavailable."
            )

    def read(capability: object) -> _VerifiedBaselineAssessmentSnapshot:
        snapshot: _VerifiedBaselineAssessmentSnapshot | None = None
        if type(capability) is VerifiedBaselineAssessment:
            with suppress(OneShotRegistryError):
                snapshot = registry.read(capability)
        if type(snapshot) is not _VerifiedBaselineAssessmentSnapshot:
            raise BaselineReproductionError(
                "A genuine verified baseline assessment capability is required."
            )
        expected = _derive_baseline_assessment(
            snapshot.sealed_result_evidence_set,
            snapshot.verified_baseline_reproduction,
        )
        if (
            canonical_json_bytes(expected) != snapshot.record_bytes
            or expected["baseline_assessment_id"] != snapshot.baseline_assessment_id
            or expected["plan_digest"] != snapshot.plan_digest
            or expected["baseline_candidate"]["candidate_ordinal"]
            != snapshot.baseline_candidate_ordinal
            or expected["baseline_candidate"]["candidate_id"] != snapshot.baseline_candidate_id
            or expected["baseline_terminal"]["result_id"] != snapshot.baseline_result_id
            or expected["baseline_terminal"]["result_digest"] != snapshot.baseline_result_digest
            or expected["candidate_terminal_index_digest"]
            != snapshot.candidate_terminal_index_digest
            or expected["baseline_terminal"]["final_status"] != snapshot.terminal_status
            or expected["baseline_reproduction_id"] != snapshot.baseline_reproduction_id
            or expected["status"] != snapshot.status
            or expected["validated_language_eligibility"]
            is not snapshot.validated_language_eligibility
            or tuple(cast(list[str], expected["reason_codes"])) != snapshot.reason_codes
        ):
            raise BaselineReproductionError("Verified baseline assessment storage is invalid.")
        return snapshot

    return registry, register, read


@final
class VerifiedBaselineAssessment:
    """Total opaque owner of one exact Plan/3 baseline outcome."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedBaselineAssessment:
        raise BaselineReproductionError(
            "Verified baseline assessments come from exact sealed result evidence."
        )

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Verified baseline assessments cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Verified baseline assessments are immutable.")

    @property
    def baseline_assessment_id(self) -> str:
        return _verified_baseline_assessment_snapshot(self).baseline_assessment_id

    @property
    def status(self) -> BaselineAssessmentStatus:
        return _verified_baseline_assessment_snapshot(self).status

    @property
    def validated_language_eligibility(self) -> bool:
        return _verified_baseline_assessment_snapshot(self).validated_language_eligibility

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return _verified_baseline_assessment_snapshot(self).reason_codes

    def __repr__(self) -> str:
        _verified_baseline_assessment_snapshot(self)
        return "VerifiedBaselineAssessment(<opaque total baseline outcome>)"

    def __copy__(self) -> VerifiedBaselineAssessment:
        _reject_capability_copy()

    def __deepcopy__(self, _memo: object) -> VerifiedBaselineAssessment:
        _reject_capability_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_capability_copy()

    def __getstate__(self) -> object:
        _reject_capability_copy()


(
    _VERIFIED_BASELINE_ASSESSMENT_STATES,
    _register_verified_baseline_assessment_snapshot,
    _verified_baseline_assessment_snapshot,
) = _build_verified_baseline_assessment_registry()
del _build_verified_baseline_assessment_registry


def _derive_baseline_assessment(
    sealed_result_evidence_set: object,
    verified_baseline_reproduction: VerifiedBaselineReproduction | None,
) -> dict[str, Any]:
    from ebm_audit.results.persistence import _sealed_result_evidence_baseline

    try:
        binding = _sealed_result_evidence_baseline(sealed_result_evidence_set)
    except (TypeError, ValueError, InvalidInputError):
        raise BaselineReproductionError(
            "Baseline assessment requires one exact sealed result-evidence set."
        ) from None
    terminal = binding.baseline_terminal
    terminal_status = cast(str, terminal["final_status"])
    if terminal_status == "SUCCESS":
        if type(verified_baseline_reproduction) is not VerifiedBaselineReproduction:
            raise BaselineReproductionError(
                "A successful baseline requires exact verified reproduction."
            )
        retained_reproduction = _capture_verified_baseline_snapshot_identity(
            verified_baseline_reproduction
        )
        if (
            _verified_baseline_source_result_from_snapshot(retained_reproduction)
            is not binding.baseline_finalized_result
        ):
            raise BaselineReproductionError(
                "Verified reproduction belongs to a different baseline result."
            )
        reproduction = _verified_baseline_snapshot_with_source_state(
            verified_baseline_reproduction,
            binding.baseline_finalized_result,
            binding.baseline_finalized_state,
        )
        status: BaselineAssessmentStatus = reproduction.status
        reproduction_id: str | None = reproduction.baseline_reproduction_id
        reason_codes = list(reproduction.reason_codes)
        eligibility = reproduction.validated_language_eligibility
    else:
        if verified_baseline_reproduction is not None:
            raise BaselineReproductionError(
                "A non-success baseline cannot carry reproduction authority."
            )
        status = "BASELINE_NOT_ASSESSABLE"
        reproduction_id = None
        reason_codes = ["BASELINE.CANDIDATE_NOT_SUCCESSFUL"]
        eligibility = False

    preimage: dict[str, Any] = {
        "assessment_schema_version": "ebm-audit-baseline-assessment/1.0",
        "plan_digest": binding.plan_candidate_authorization.plan_digest,
        "baseline_candidate": copy.deepcopy(binding.baseline_candidate),
        "candidate_terminal_index_digest": binding.terminal_index_digest,
        "baseline_terminal": copy.deepcopy(terminal),
        "baseline_reproduction_id": reproduction_id,
        "status": status,
        "validated_language_eligibility": eligibility,
        "reason_codes": reason_codes,
        "baseline_assessment_id": None,
    }
    _validate(preimage, "BaselineAssessmentRecordDigestPreimage")
    record = copy.deepcopy(preimage)
    record["baseline_assessment_id"] = structured_sha256(
        "ebm-audit/baseline-assessment/1",
        preimage,
    )
    _validate(record, "BaselineAssessmentRecord")
    return record


class _AssessBaseline(Protocol):
    def __call__(
        self,
        sealed_result_evidence_set: object,
        verified_baseline_reproduction: VerifiedBaselineReproduction | None = None,
    ) -> VerifiedBaselineAssessment: ...


def _build_baseline_assessor(
    register: Callable[[object, _VerifiedBaselineAssessmentSnapshot], None],
) -> _AssessBaseline:
    def assess_baseline(
        sealed_result_evidence_set: object,
        verified_baseline_reproduction: VerifiedBaselineReproduction | None = None,
    ) -> VerifiedBaselineAssessment:
        """Issue the sole total outcome from exact sealed Plan/3 result owners."""

        capability = object.__new__(VerifiedBaselineAssessment)
        record = _derive_baseline_assessment(
            sealed_result_evidence_set,
            verified_baseline_reproduction,
        )
        candidate = cast(Mapping[str, Any], record["baseline_candidate"])
        terminal = cast(Mapping[str, Any], record["baseline_terminal"])
        register(
            capability,
            _VerifiedBaselineAssessmentSnapshot(
                baseline_assessment_id=cast(str, record["baseline_assessment_id"]),
                plan_digest=cast(str, record["plan_digest"]),
                baseline_candidate_ordinal=cast(int, candidate["candidate_ordinal"]),
                baseline_candidate_id=cast(str, candidate["candidate_id"]),
                baseline_result_id=cast(str, terminal["result_id"]),
                baseline_result_digest=cast(str, terminal["result_digest"]),
                candidate_terminal_index_digest=cast(
                    str,
                    record["candidate_terminal_index_digest"],
                ),
                terminal_status=cast(str, terminal["final_status"]),
                baseline_reproduction_id=cast(
                    str | None,
                    record["baseline_reproduction_id"],
                ),
                status=cast(BaselineAssessmentStatus, record["status"]),
                validated_language_eligibility=cast(
                    bool,
                    record["validated_language_eligibility"],
                ),
                reason_codes=tuple(cast(list[str], record["reason_codes"])),
                record_bytes=canonical_json_bytes(record),
                sealed_result_evidence_set=sealed_result_evidence_set,
                verified_baseline_reproduction=verified_baseline_reproduction,
            ),
        )
        return capability

    return assess_baseline


assess_baseline: _AssessBaseline = _build_baseline_assessor(
    _register_verified_baseline_assessment_snapshot
)
del _register_verified_baseline_assessment_snapshot
del _build_baseline_assessor


def baseline_assessment_record(value: object) -> dict[str, Any]:
    """Project one canonical aggregate record without transferring authority."""

    snapshot = _verified_baseline_assessment_snapshot(value)
    record = strict_json_loads(snapshot.record_bytes)
    if type(record) is not dict:
        raise BaselineReproductionError("Verified baseline assessment storage is invalid.")
    return copy.deepcopy(record)
