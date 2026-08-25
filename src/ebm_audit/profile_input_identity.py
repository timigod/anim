"""Opaque identity binding for one profile plan's generated synthetic input."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Any, Never, SupportsIndex, cast, final
from weakref import ReferenceType, WeakKeyDictionary, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.config import PlanEligibleAuditConfig, RunEligibleAuditConfig
from ebm_audit.data import PreparedAuditDataset
from ebm_audit.data.preparation import _private_prepared_dataset
from ebm_audit.data.source_admission import ValidatedSourceAdmission
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads

_PROFILE_GENERATED_INPUT_BINDING_SCHEMA_VERSION = "ebm-audit-profile-generated-input-binding/3.0"


@dataclass(frozen=True, slots=True, repr=False)
class _DerivedProfileGeneratedInputBinding:
    run_config: RunEligibleAuditConfig
    prepared_dataset: PreparedAuditDataset
    coordinate_bytes: bytes
    coordinate_ordinal: int
    ordered_analysis_spec_bytes: tuple[bytes, bytes, bytes]
    ordered_analysis_spec_ids: tuple[str, str, str]
    selected_synthetic_event_binding_bytes: bytes
    profile_execution_identity_sha256: str
    input_owner_digest: str
    raw_generated_scientific_digest: str
    audit_dataset_digest: str
    prepared_dataset_id: str
    reserved_profile_seed_placeholder: str
    profile_seed_derivation_version: str
    profile_seed_authority_state: str
    profile_seed_matrix_requirement: str
    binding_bytes: bytes


@dataclass(frozen=True, slots=True, repr=False)
class _ProfileGeneratedInputBindingState:
    plan_owner: object
    input_owner: object
    run_config: RunEligibleAuditConfig
    prepared_dataset: PreparedAuditDataset
    coordinate_bytes: bytes
    coordinate_ordinal: int
    ordered_analysis_spec_bytes: tuple[bytes, bytes, bytes]
    ordered_analysis_spec_ids: tuple[str, str, str]
    selected_synthetic_event_binding_bytes: bytes
    profile_execution_identity_sha256: str
    input_owner_digest: str
    raw_generated_scientific_digest: str
    audit_dataset_digest: str
    prepared_dataset_id: str
    reserved_profile_seed_placeholder: str
    profile_seed_derivation_version: str
    profile_seed_authority_state: str
    profile_seed_matrix_requirement: str
    binding_bytes: bytes
    revalidate: Callable[[], _DerivedProfileGeneratedInputBinding]


@final
class ProfileGeneratedInputBinding:
    """Opaque retained identity of one generated profile input."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Profile generated-input bindings are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Profile generated-input bindings cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Profile generated-input bindings are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Profile generated-input bindings cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Profile generated-input bindings cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Profile generated-input bindings cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Profile generated-input bindings cannot be serialized.")


_BINDING_STATES: OneShotWeakRegistry[
    ProfileGeneratedInputBinding, _ProfileGeneratedInputBindingState
]
_BINDING_STATE_ISSUER: OneShotRegistryIssuer[
    ProfileGeneratedInputBinding, _ProfileGeneratedInputBindingState
]
_BINDING_STATES, _BINDING_STATE_ISSUER = create_one_shot_registry()
# Values must not retain the weak key through the binding's owner graph.
_ISSUED_INPUT_OWNERS: WeakKeyDictionary[object, None] = WeakKeyDictionary()
_BINDING_ISSUANCE_LOCK = RLock()


@dataclass(frozen=True, slots=True, repr=False)
class _ProfilePreparationRouteMarker:
    input_owner_ref: ReferenceType[object]
    source_admission_ref: ReferenceType[ValidatedSourceAdmission]


# Source keys and marker references are weak; string-index entries are removed
# when the registered source dies, so no index retains the private data graph.
_PROFILE_PREPARATION_ROUTES_BY_SOURCE: WeakKeyDictionary[
    ValidatedSourceAdmission, dict[str, _ProfilePreparationRouteMarker]
] = WeakKeyDictionary()
_PROFILE_PREPARATION_ROUTES_BY_AUTHORIZATION: dict[
    str, dict[int, _ProfilePreparationRouteMarker]
] = {}
_PROFILE_PREPARATION_ROUTES_BY_ADMISSION: dict[str, dict[int, _ProfilePreparationRouteMarker]] = {}


def _register_profile_preparation_route(
    input_owner: object,
    run_config: RunEligibleAuditConfig,
) -> None:
    """Bind one profile route to its authorization and exact admitted source."""

    if type(run_config) is not RunEligibleAuditConfig:
        raise TypeError("A genuine profile run configuration is required.")
    authorization_id = run_config.authorization_id
    source_admission = run_config.source_admission
    source_admission_id = source_admission.admission_id
    owner_reference = ref(input_owner)
    source_key = id(source_admission)

    def discard_source(reference: ReferenceType[ValidatedSourceAdmission]) -> None:
        with _BINDING_ISSUANCE_LOCK:
            routes = _PROFILE_PREPARATION_ROUTES_BY_AUTHORIZATION.get(authorization_id)
            marker = None if routes is None else routes.get(source_key)
            if (
                routes is not None
                and marker is not None
                and marker.source_admission_ref is reference
            ):
                del routes[source_key]
                if not routes:
                    del _PROFILE_PREPARATION_ROUTES_BY_AUTHORIZATION[authorization_id]
            admission_routes = _PROFILE_PREPARATION_ROUTES_BY_ADMISSION.get(source_admission_id)
            admission_marker = (
                None if admission_routes is None else admission_routes.get(source_key)
            )
            if (
                admission_routes is not None
                and admission_marker is not None
                and admission_marker.source_admission_ref is reference
            ):
                del admission_routes[source_key]
                if not admission_routes:
                    del _PROFILE_PREPARATION_ROUTES_BY_ADMISSION[source_admission_id]

    source_reference = ref(source_admission, discard_source)
    marker = _ProfilePreparationRouteMarker(
        input_owner_ref=owner_reference,
        source_admission_ref=source_reference,
    )
    with _BINDING_ISSUANCE_LOCK:
        source_routes = _PROFILE_PREPARATION_ROUTES_BY_SOURCE.setdefault(source_admission, {})
        authorization_routes = _PROFILE_PREPARATION_ROUTES_BY_AUTHORIZATION.setdefault(
            authorization_id, {}
        )
        admission_routes = _PROFILE_PREPARATION_ROUTES_BY_ADMISSION.setdefault(
            source_admission_id, {}
        )
        if (
            authorization_id in source_routes
            or source_key in authorization_routes
            or source_key in admission_routes
        ):
            raise TypeError("The profile preparation route is already registered.")
        source_routes[authorization_id] = marker
        authorization_routes[source_key] = marker
        admission_routes[source_key] = marker


def _is_profile_owned_preparation_route(value: object) -> bool:
    """Identify any eligible config for a registered profile-owned source route."""

    if type(value) not in {PlanEligibleAuditConfig, RunEligibleAuditConfig}:
        return False
    config = cast(PlanEligibleAuditConfig | RunEligibleAuditConfig, value)
    authorization_id = config.authorization_id
    source_admission = config.source_admission
    with _BINDING_ISSUANCE_LOCK:
        source_routes = _PROFILE_PREPARATION_ROUTES_BY_SOURCE.get(source_admission)
        if source_routes:
            return True
        authorization_routes = _PROFILE_PREPARATION_ROUTES_BY_AUTHORIZATION.get(authorization_id)
        if authorization_routes is not None and any(
            marker.source_admission_ref() is not None for marker in authorization_routes.values()
        ):
            return True
        admission_routes = _PROFILE_PREPARATION_ROUTES_BY_ADMISSION.get(
            source_admission.admission_id
        )
        return admission_routes is not None and any(
            marker.source_admission_ref() is not None for marker in admission_routes.values()
        )


@dataclass(frozen=True, slots=True, repr=False)
class _ProfilePreparedDatasetMarker:
    prepared_dataset_ref: ReferenceType[PreparedAuditDataset]
    binding_ref: ReferenceType[ProfileGeneratedInputBinding]


# This exact-identity weak registry is only an enforcement seam. The downstream
# preparation repair must reject ordinary preparation when the marker is present.
_PROFILE_PREPARED_DATASET_MARKERS: dict[int, _ProfilePreparedDatasetMarker] = {}


def _profile_prepared_dataset_marker(
    value: object,
) -> _ProfilePreparedDatasetMarker | None:
    if type(value) is not PreparedAuditDataset:
        return None
    marker = _PROFILE_PREPARED_DATASET_MARKERS.get(id(value))
    if marker is None or marker.prepared_dataset_ref() is not value:
        return None
    return marker


def _register_profile_prepared_dataset(
    binding: ProfileGeneratedInputBinding,
    prepared_dataset: PreparedAuditDataset,
) -> None:
    key = id(prepared_dataset)
    if _profile_prepared_dataset_marker(prepared_dataset) is not None:
        raise TypeError("A prepared dataset already belongs to the profile path.")

    def discard(reference: ReferenceType[PreparedAuditDataset]) -> None:
        with _BINDING_ISSUANCE_LOCK:
            marker = _PROFILE_PREPARED_DATASET_MARKERS.get(key)
            if marker is not None and marker.prepared_dataset_ref is reference:
                del _PROFILE_PREPARED_DATASET_MARKERS[key]

    prepared_reference = ref(prepared_dataset, discard)
    _PROFILE_PREPARED_DATASET_MARKERS[key] = _ProfilePreparedDatasetMarker(
        prepared_dataset_ref=prepared_reference,
        binding_ref=ref(binding),
    )


def _is_profile_generated_prepared_dataset(value: object) -> bool:
    """Identify the exact profile-owned dataset, even after its binding dies.

    Ordinary ``PlanningAuthority.prepare()`` rejects datasets identified here.
    """

    with _BINDING_ISSUANCE_LOCK:
        return _profile_prepared_dataset_marker(value) is not None


def _resolve_live_profile_generated_input_binding(
    run_config: object,
    prepared_dataset: object,
) -> ProfileGeneratedInputBinding:
    """Resolve only the live binding for the identical retained preparation owners."""

    with _BINDING_ISSUANCE_LOCK:
        marker = _profile_prepared_dataset_marker(prepared_dataset)
        binding = None if marker is None else marker.binding_ref()
    if binding is None:
        raise TypeError("A live profile generated-input binding is required.")
    state = _read_profile_generated_input_binding(binding)
    if state.run_config is not run_config or state.prepared_dataset is not prepared_dataset:
        raise TypeError("The exact profile run config and prepared dataset are required.")
    return binding


def _closed_mapping(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        decoded = strict_json_loads(value)
    except (TypeError, ValueError):
        raise TypeError(f"{label} is not canonical closed JSON.") from None
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise TypeError(f"{label} is not canonical closed JSON.")
    return cast(dict[str, Any], decoded)


def _sha256_digest(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise TypeError(f"{label} is not an exact SHA-256 digest.")
    return value


def _raw_sha256_hex(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TypeError(f"{label} is not exact raw SHA-256 hex.")
    return value


def _derive_binding_bytes(
    plan_owner: object,
    input_owner: object,
) -> _DerivedProfileGeneratedInputBinding:
    """Reconstruct every retained binding field from the two sealed owners."""

    from ebm_audit.adapters import WorkerConfig
    from ebm_audit.synthetic.audit_input import (
        _PROFILE_SEED_AUTHORITY_STATE,
        _PROFILE_SEED_DERIVATION_VERSION,
        _PROFILE_SEED_MATRIX_REQUIREMENT,
        _authorization_state,
        _resolve_public_synthetic_audit_input,
        _validated_profile_plan_projection,
    )

    input_state = _resolve_public_synthetic_audit_input(input_owner)
    authorization = _authorization_state(input_state.authorization)
    if (
        authorization.origin != "DEVELOPMENT_PROFILE"
        or authorization.execution_owner is not plan_owner
    ):
        raise TypeError("The generated input is not owned by this sealed profile plan.")
    projected = _validated_profile_plan_projection(
        plan_owner,
        WorkerConfig.from_yaml_bytes(authorization.worker_bytes),
    )
    ordinal = authorization.coordinate_ordinal
    if (
        projected.plan_receipt_sha256 != authorization.execution_receipt_sha256
        or projected.profile_execution_identity_sha256
        != authorization.execution_identity_sha256
        or not 0 <= ordinal < len(projected.coordinate_bytes)
    ):
        raise TypeError("The projected profile plan has incomplete binding authority.")
    coordinate_bytes = projected.coordinate_bytes[ordinal]
    if coordinate_bytes != authorization.coordinate_bytes:
        raise TypeError("The generated input coordinate is detached from its projected plan.")
    ordered_spec_bytes = projected.ordered_analysis_spec_bytes
    ordered_spec_ids = projected.ordered_analysis_spec_ids
    if (
        ordered_spec_bytes != authorization.analysis_spec_bytes
        or ordered_spec_ids != authorization.analysis_spec_ids
    ):
        raise TypeError("The generated input AnalysisSpec bundle is detached from its plan.")
    selected_synthetic_event_binding_bytes = projected.ordered_synthetic_event_binding_bytes[
        ordinal
    ]
    if (
        authorization.profile_synthetic_event_binding_bytes is None
        or selected_synthetic_event_binding_bytes
        != authorization.profile_synthetic_event_binding_bytes
    ):
        raise TypeError("The retained synthetic Plan binding changed.")
    prepared_state = _private_prepared_dataset(input_state.prepared)
    input_projection = _closed_mapping(
        input_state.projection_bytes,
        label="Input owner projection",
    )
    input_owner_digest = _sha256_digest(
        input_projection.get("input_owner_digest"),
        label="Input owner digest",
    )
    generated_digest = _raw_sha256_hex(
        input_state.generated_artifacts.scientific_data.get("generated_scientific_data_sha256"),
        label="Raw generated scientific digest",
    )
    audit_dataset_digest = _sha256_digest(
        prepared_state.audit_dataset_digest,
        label="Audit dataset digest",
    )
    prepared_dataset_id = _sha256_digest(
        input_state.prepared.prepared_dataset_id,
        label="Prepared dataset ID",
    )
    randomness = input_state.authorized.private_config.get("randomness")
    reserved_profile_seed_placeholder = authorization.execution_seed_placeholder
    if (
        type(reserved_profile_seed_placeholder) is not str
        or len(reserved_profile_seed_placeholder) != 16
        or any(
            character not in "0123456789abcdef" for character in reserved_profile_seed_placeholder
        )
        or randomness
        != {
            "master_seed": reserved_profile_seed_placeholder,
            "seed_derivation_version": _PROFILE_SEED_DERIVATION_VERSION,
        }
        or input_projection.get("reserved_profile_seed_placeholder")
        != reserved_profile_seed_placeholder
        or input_projection.get("profile_seed_derivation_version")
        != _PROFILE_SEED_DERIVATION_VERSION
        or input_projection.get("profile_seed_authority_state") != _PROFILE_SEED_AUTHORITY_STATE
        or input_projection.get("profile_seed_matrix_requirement")
        != _PROFILE_SEED_MATRIX_REQUIREMENT
        or authorization.profile_seed_authority_state != _PROFILE_SEED_AUTHORITY_STATE
        or authorization.profile_seed_matrix_requirement != _PROFILE_SEED_MATRIX_REQUIREMENT
    ):
        raise TypeError("The reserved profile seed state is invalid.")
    selected_binding = _closed_mapping(
        selected_synthetic_event_binding_bytes,
        label="Profile synthetic event binding",
    )
    selected_binding_digest = _raw_sha256_hex(
        selected_binding.get("profile_synthetic_event_binding_sha256"),
        label="Profile synthetic event binding digest",
    )
    binding = {
        "binding_schema_version": _PROFILE_GENERATED_INPUT_BINDING_SCHEMA_VERSION,
        "coordinate": strict_json_loads(coordinate_bytes),
        "coordinate_ordinal": ordinal,
        "ordered_analysis_spec_ids": list(ordered_spec_ids),
        "profile_execution_identity_sha256": (projected.profile_execution_identity_sha256),
        "profile_synthetic_event_binding_sha256": selected_binding_digest,
        "raw_generated_scientific_digest": generated_digest,
        "input_owner_digest": input_owner_digest,
        "audit_dataset_digest": audit_dataset_digest,
        "prepared_dataset_id": prepared_dataset_id,
        "reserved_profile_seed": {
            "placeholder": reserved_profile_seed_placeholder,
            "seed_derivation_version": _PROFILE_SEED_DERIVATION_VERSION,
            "authority_state": _PROFILE_SEED_AUTHORITY_STATE,
            "profile_seed_matrix_requirement": _PROFILE_SEED_MATRIX_REQUIREMENT,
        },
    }
    binding_bytes = canonical_json_bytes(binding)
    return _DerivedProfileGeneratedInputBinding(
        run_config=input_state.authorized,
        prepared_dataset=input_state.prepared,
        coordinate_bytes=coordinate_bytes,
        coordinate_ordinal=ordinal,
        ordered_analysis_spec_bytes=ordered_spec_bytes,
        ordered_analysis_spec_ids=ordered_spec_ids,
        selected_synthetic_event_binding_bytes=(selected_synthetic_event_binding_bytes),
        profile_execution_identity_sha256=(projected.profile_execution_identity_sha256),
        input_owner_digest=input_owner_digest,
        raw_generated_scientific_digest=generated_digest,
        audit_dataset_digest=audit_dataset_digest,
        prepared_dataset_id=prepared_dataset_id,
        reserved_profile_seed_placeholder=reserved_profile_seed_placeholder,
        profile_seed_derivation_version=_PROFILE_SEED_DERIVATION_VERSION,
        profile_seed_authority_state=_PROFILE_SEED_AUTHORITY_STATE,
        profile_seed_matrix_requirement=_PROFILE_SEED_MATRIX_REQUIREMENT,
        binding_bytes=binding_bytes,
    )


def _read_profile_generated_input_binding(
    value: object,
) -> _ProfileGeneratedInputBindingState:
    """Revalidate the retained plan/input graph before returning private state."""

    if type(value) is not ProfileGeneratedInputBinding:
        raise TypeError("A genuine profile generated-input binding is required.")
    try:
        state = _BINDING_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine profile generated-input binding is required.") from None

    rebuilt = state.revalidate()
    with _BINDING_ISSUANCE_LOCK:
        marker = _profile_prepared_dataset_marker(state.prepared_dataset)
    if (
        rebuilt.run_config is not state.run_config
        or rebuilt.prepared_dataset is not state.prepared_dataset
        or rebuilt.coordinate_bytes != state.coordinate_bytes
        or rebuilt.coordinate_ordinal != state.coordinate_ordinal
        or rebuilt.ordered_analysis_spec_bytes != state.ordered_analysis_spec_bytes
        or rebuilt.ordered_analysis_spec_ids != state.ordered_analysis_spec_ids
        or rebuilt.selected_synthetic_event_binding_bytes
        != state.selected_synthetic_event_binding_bytes
        or rebuilt.profile_execution_identity_sha256 != state.profile_execution_identity_sha256
        or rebuilt.input_owner_digest != state.input_owner_digest
        or rebuilt.raw_generated_scientific_digest != state.raw_generated_scientific_digest
        or rebuilt.audit_dataset_digest != state.audit_dataset_digest
        or rebuilt.prepared_dataset_id != state.prepared_dataset_id
        or rebuilt.reserved_profile_seed_placeholder != state.reserved_profile_seed_placeholder
        or rebuilt.profile_seed_derivation_version != state.profile_seed_derivation_version
        or rebuilt.profile_seed_authority_state != state.profile_seed_authority_state
        or rebuilt.profile_seed_matrix_requirement != state.profile_seed_matrix_requirement
        or rebuilt.binding_bytes != state.binding_bytes
        or marker is None
        or marker.binding_ref() is not value
    ):
        raise TypeError("Profile generated-input binding ownership changed.")
    _BINDING_STATES.require(value, state)
    return state


def _issue_profile_generated_input_binding(
    plan_owner: object,
    input_owner: object,
) -> ProfileGeneratedInputBinding:
    """Seal one admitted input using only its exact plan and input owners."""

    with _BINDING_ISSUANCE_LOCK:
        if input_owner in _ISSUED_INPUT_OWNERS:
            raise TypeError("A profile generated-input binding is one-use per input owner.")
        derived = _derive_binding_bytes(plan_owner, input_owner)

        def revalidate() -> _DerivedProfileGeneratedInputBinding:
            return _derive_binding_bytes(plan_owner, input_owner)

        binding = object.__new__(ProfileGeneratedInputBinding)
        _BINDING_STATE_ISSUER.bind_once(
            binding,
            _ProfileGeneratedInputBindingState(
                plan_owner=plan_owner,
                input_owner=input_owner,
                run_config=derived.run_config,
                prepared_dataset=derived.prepared_dataset,
                coordinate_bytes=derived.coordinate_bytes,
                coordinate_ordinal=derived.coordinate_ordinal,
                ordered_analysis_spec_bytes=derived.ordered_analysis_spec_bytes,
                ordered_analysis_spec_ids=derived.ordered_analysis_spec_ids,
                selected_synthetic_event_binding_bytes=(
                    derived.selected_synthetic_event_binding_bytes
                ),
                profile_execution_identity_sha256=(derived.profile_execution_identity_sha256),
                input_owner_digest=derived.input_owner_digest,
                raw_generated_scientific_digest=(derived.raw_generated_scientific_digest),
                audit_dataset_digest=derived.audit_dataset_digest,
                prepared_dataset_id=derived.prepared_dataset_id,
                reserved_profile_seed_placeholder=(derived.reserved_profile_seed_placeholder),
                profile_seed_derivation_version=(derived.profile_seed_derivation_version),
                profile_seed_authority_state=derived.profile_seed_authority_state,
                profile_seed_matrix_requirement=(derived.profile_seed_matrix_requirement),
                binding_bytes=derived.binding_bytes,
                revalidate=revalidate,
            ),
        )
        _register_profile_prepared_dataset(binding, derived.prepared_dataset)
        _ISSUED_INPUT_OWNERS[input_owner] = None
    _read_profile_generated_input_binding(binding)
    return binding


__all__ = ["ProfileGeneratedInputBinding"]
