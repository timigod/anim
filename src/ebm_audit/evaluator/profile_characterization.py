"""Authenticated public profile-characterization plan authority.

This module resolves the exact six public synthetic cases and the currently
selected local pysaebm Describe owner.  It issues fixed pre-execution intent
only.  It never starts a fit and never issues result or selection evidence.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from threading import RLock
from typing import Any, Final, NamedTuple, Never, cast, final
from weakref import ReferenceType, ref

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.adapters import (
    WorkerCommand,
    WorkerInvoker,
    describe_worker,
    normalize_worker_timeout_seconds,
)
from ebm_audit.adapters.config import _validated_worker_command_snapshot
from ebm_audit.protocol import (
    adapter_semantics_digest,
    backend_identity_digest,
    canonical_json_bytes,
    capabilities_digest,
    expected_identity_pin_digest,
    requested_output_registry_digest,
    requested_outputs_digest,
    settings_digest,
    settings_schema_digest,
    stage_semantics_digest,
    structured_sha256_hex,
)
from ebm_audit.schema import (
    SchemaValidationError,
    load_protocol_registry,
    validate_instance,
    validate_settings,
)
from ebm_audit.synthetic import (
    CaseCoordinate,
    load_scenario_authority,
    resolve_development_case,
    verify_exact_resolution,
)
from ebm_audit.synthetic.authority import FIELD_IDS, GENERATION_STAGE_IDS
from ebm_audit.universe import analysis_spec_content_id

from .freeze_sequence import (
    _audit_profile_characterization_plan_authority_bound,
    _AuthenticatedWorkerBinding,
)
from .profile_plan_provenance import (
    ProfilePlanProvenance,
    _consume_profile_plan_provenance,
    _ConsumedProfilePlanProvenance,
    _require_profile_plan_provenance_current,
)

_PUBLIC_AUTHORITY_SHA256: Final = "6a6f0165f57ab44f88e62e70dfc2284ddcc909d1d1e7f191f741a681b3e0d629"
_SELECTED_ALGORITHM_ID: Final = "conjugate_priors"
_PROFILE_PLAN_DOMAIN: Final = "ebm-audit/profile-characterization-plan-receipt/3"
_PROFILE_PLAN_ISSUANCE_IDENTITY_DOMAIN: Final = (
    "ebm-audit/profile-characterization-plan-issuance-identity/1"
)
_SYNTHETIC_EVENT_BINDING_DOMAIN: Final = "ebm-audit/profile-synthetic-event-binding/1"
_BLOCKED_DIAGNOSTIC_DOMAIN: Final = "ebm-audit/blocked-profile-diagnostic/2"
_PROFILE_EXECUTION_SOURCE_MANIFEST_DOMAIN: Final = "ebm-audit/profile-execution-source-manifest/1"
_PROFILE_EXECUTION_IDENTITY_DOMAIN: Final = "ebm-audit/profile-execution-identity/1"
_PROFILE_WORKER_INVOCATION_SEMANTICS_DOMAIN: Final = (
    "ebm-audit/profile-worker-invocation-semantics/1"
)
_PROFILE_PUBLIC_SEED_DOMAIN: Final = "ebm-audit/profile-public-seed/2"
_PROFILE_PUBLIC_SEED_DERIVATION_ID: Final = (
    "public-sha256-profile-execution-identity-event-binding-chain-u64be/2"
)
_PROFILE_PROVENANCE_SOURCE_ROLES: Final = (
    "generator_sha256",
    "metrics_rules_sha256",
    "report_language_rules_sha256",
    "evaluator_source_sha256",
    "normative_authority_sha256",
)
_PROFILE_FIT_SOURCE_ROLES: Final = (
    "generation",
    "preparation",
    "seed",
    "request-execution",
    "capture",
    "metric-calculation",
)
_REQUESTED_OUTPUTS: Final = (
    "central_order",
    "order_samples",
    "accepted_transition_diagnostics",
    "position_probabilities",
    "pairwise_precedence",
    "fitted_event_distributions",
    "evaluation_stage_posterior",
    "evaluation_hard_stages",
    "evaluation_expected_stage",
)
_PROFILE_BUDGETS: Final = (
    ("characterization_2000", 2000, 400),
    ("characterization_5000", 5000, 1000),
    ("characterization_10000", 10000, 2000),
)
_COORDINATE_FAMILIES: Final = (
    ("easy_known_truth", "profile-pilot"),
    ("moderate_mina_shape", "profile-pilot-57x9"),
)
_ROOTS: Final = (
    "c9adc6fee9c00b79",
    "86b6740157a8ec3e",
    "725fb844ce462a7e",
)
_DERIVATION_REGISTRY: Final = {
    "event_ids": {
        "derivation_id": "event-ids-from-count/1",
        "ordered_input_field_ids": ["events"],
    },
    "event_directions": {
        "derivation_id": "alternating-event-directions/1",
        "ordered_input_field_ids": ["events", "event_ids"],
    },
    "event_centers": {
        "derivation_id": "even-event-centers/1",
        "ordered_input_field_ids": ["events", "event_ids", "event_center_range"],
    },
}


class ProfileCharacterizationAuthorityError(ValueError):
    """Reject drift in the public case or selected-worker plan authority."""


def _reject() -> Never:
    raise ProfileCharacterizationAuthorityError(
        "The profile-characterization authority does not match its closed contract."
    )


def _expected_variant(
    *,
    variant_id: str,
    participants: int,
    width: float,
    amplitude: float,
    noise: float,
    correlation: float,
    participant_sd: float,
    participant_loading: float,
    reference_window: tuple[float, float],
    at_risk_window: tuple[float, float],
    reference_fraction: float,
) -> dict[str, Any]:
    return {
        "id": variant_id,
        "participants": participants,
        "events": 9,
        "baseline": [0.0] * 9,
        "event_center_range": [-2, 2.0],
        "transition_width": [width] * 9,
        "amplitude": [amplitude] * 9,
        "participant_random_effect_sd": participant_sd,
        "participant_random_effect_loading": [participant_loading] * 9,
        "measurement_noise_family": "multivariate_normal",
        "measurement_noise_sd": [noise] * 9,
        "equicorrelation": correlation,
        "reference_sampling_window": list(reference_window),
        "at_risk_sampling_window": list(at_risk_window),
        "reference_fraction": reference_fraction,
        "missingness": "none",
        "outliers": "none",
        "covariates": "none",
        "event_covariate_effect": [0.0] * 9,
        "group_event_effect": [0.0] * 9,
    }


_EXPECTED_VARIANTS: Final = {
    "easy_known_truth": _expected_variant(
        variant_id="profile-pilot",
        participants=120,
        width=0.2,
        amplitude=3.0,
        noise=0.5,
        correlation=0.0,
        participant_sd=0.0,
        participant_loading=0.0,
        reference_window=(-4, -2.75),
        at_risk_window=(-2.75, 4.0),
        reference_fraction=0.25,
    ),
    "moderate_mina_shape": _expected_variant(
        variant_id="profile-pilot-57x9",
        participants=57,
        width=1.0,
        amplitude=2.0,
        noise=1.0,
        correlation=0.25,
        participant_sd=0.25,
        participant_loading=0.2,
        reference_window=(-3, -0.5),
        at_risk_window=(-0.5, 3.0),
        reference_fraction=0.5,
    ),
}


@dataclass(frozen=True, slots=True)
class _ResolvedPublicSemantics:
    event_ids: tuple[str, ...]
    truth_directions: tuple[str, ...]
    analysis_directions: tuple[str, ...]
    event_centers: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class _ResolvedPublicAuthority:
    semantics: _ResolvedPublicSemantics
    bindings: tuple[dict[str, Any], ...]


class _AuthorityIdentity(NamedTuple):
    exact_authority_bytes: bytes
    worker_argv: tuple[str, ...]
    timeout_seconds: float
    expected_identity_bytes: bytes
    backend_identity_bytes: bytes
    description_result_bytes: bytes


class _AuthorityState(NamedTuple):
    authority_identity: _AuthorityIdentity
    exact_authority_bytes: bytes
    definitions_sha256: str
    worker: WorkerCommand
    timeout_seconds: float
    expected_identity: dict[str, Any]
    backend_identity_bytes: bytes
    description_result_bytes: bytes
    public_authority: _ResolvedPublicAuthority


@final
class ProfileCharacterizationAuthority:
    """Opaque authority for one exact public plan and live worker identity."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("ProfileCharacterizationAuthority cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ProfileCharacterizationAuthority has no public constructor.")

    @property
    def scenario_definitions_sha256(self) -> str:
        return _read_authority(self).definitions_sha256

    @property
    def selected_backend_identity_digest(self) -> str:
        state = _read_authority(self)
        identity, _ = _authenticated_worker_description(state)
        return backend_identity_digest(identity)

    def __copy__(self) -> Never:
        _reject()

    def __deepcopy__(self, _memo: object) -> Never:
        _reject()

    def __reduce__(self) -> Never:
        _reject()

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject()


@final
class SealedProfileCharacterizationPlan:
    """Opaque in-memory owner of one exact authenticated plan graph."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Sealed profile-characterization plans cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Sealed profile-characterization plans have no public constructor.")

    def __copy__(self) -> Never:
        raise TypeError("Sealed profile-characterization plans cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Sealed profile-characterization plans cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Sealed profile-characterization plans cannot be serialized.")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("Sealed profile-characterization plans cannot be serialized.")


def _reject_receipt_copy() -> Never:
    raise TypeError("Profile-characterization receipt owners cannot be copied or serialized.")


@final
class _ProfileCharacterizationPlanReceipt:
    """Opaque owner of the authenticated canonical plan-receipt bytes."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile-characterization plan receipts cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Profile-characterization plan receipts have no public constructor.")

    def __copy__(self) -> Never:
        _reject_receipt_copy()

    def __deepcopy__(self, _memo: object) -> Never:
        _reject_receipt_copy()

    def __reduce__(self) -> Never:
        _reject_receipt_copy()

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject_receipt_copy()


@final
class _BlockedProfileDiagnosticReceipt:
    """Opaque owner of the authenticated canonical blocked-diagnostic bytes."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Blocked profile diagnostic receipts cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Blocked profile diagnostic receipts have no public constructor.")

    def __copy__(self) -> Never:
        _reject_receipt_copy()

    def __deepcopy__(self, _memo: object) -> Never:
        _reject_receipt_copy()

    def __reduce__(self) -> Never:
        _reject_receipt_copy()

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject_receipt_copy()


class _PlanContentIdentity(NamedTuple):
    authority_identity: _AuthorityIdentity
    timestamp_free_graph_bytes: bytes


type _PlanIssuanceIdentity = str


def _plan_issuance_identity(plan_identity: _PlanContentIdentity) -> _PlanIssuanceIdentity:
    """Compact the full live identity into one permanent domain-separated digest."""

    authority_identity = plan_identity.authority_identity
    parts = (
        authority_identity.exact_authority_bytes,
        canonical_json_bytes(list(authority_identity.worker_argv)),
        canonical_json_bytes(authority_identity.timeout_seconds),
        authority_identity.expected_identity_bytes,
        authority_identity.backend_identity_bytes,
        authority_identity.description_result_bytes,
        plan_identity.timestamp_free_graph_bytes,
    )
    digest = hashlib.sha256(_PROFILE_PLAN_ISSUANCE_IDENTITY_DOMAIN.encode("ascii") + b"\x00")
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


class _ReceiptOwnerState(NamedTuple):
    role: str
    plan_identity: _PlanContentIdentity
    canonical_bytes: bytes


class _SealedProfileCharacterizationPlanState(NamedTuple):
    authority: ProfileCharacterizationAuthority
    plan_identity: _PlanContentIdentity
    plan_receipt: _ProfileCharacterizationPlanReceipt
    blocked_diagnostic: _BlockedProfileDiagnosticReceipt
    provenance_owner: ProfilePlanProvenance | None
    provenance_state: _ConsumedProfilePlanProvenance | None


class _PlanIssuanceRecord(NamedTuple):
    plan_owner: ReferenceType[SealedProfileCharacterizationPlan]
    plan_receipt: ReferenceType[_ProfileCharacterizationPlanReceipt]
    blocked_diagnostic: ReferenceType[_BlockedProfileDiagnosticReceipt]


@final
class _ProfileCharacterizationOwnership:
    """Atomic canonical-owner publication and permanent one-shot tombstones."""

    __slots__ = (
        "__authority_issuer",
        "__authority_states",
        "__blocked_diagnostic_issuer",
        "__blocked_diagnostic_states",
        "__canonical_authorities",
        "__lock",
        "__plan_issuance_records",
        "__plan_issuer",
        "__plan_receipt_issuer",
        "__plan_receipt_states",
        "__plan_states",
    )

    __authority_states: OneShotWeakRegistry[object, _AuthorityState]
    __authority_issuer: OneShotRegistryIssuer[object, _AuthorityState]
    __plan_states: OneShotWeakRegistry[object, _SealedProfileCharacterizationPlanState]
    __plan_issuer: OneShotRegistryIssuer[object, _SealedProfileCharacterizationPlanState]
    __plan_receipt_states: OneShotWeakRegistry[object, _ReceiptOwnerState]
    __plan_receipt_issuer: OneShotRegistryIssuer[object, _ReceiptOwnerState]
    __blocked_diagnostic_states: OneShotWeakRegistry[object, _ReceiptOwnerState]
    __blocked_diagnostic_issuer: OneShotRegistryIssuer[object, _ReceiptOwnerState]
    __canonical_authorities: dict[
        _AuthorityIdentity,
        ReferenceType[ProfileCharacterizationAuthority],
    ]
    __plan_issuance_records: dict[_PlanIssuanceIdentity, _PlanIssuanceRecord]
    __lock: RLock

    def __init__(self) -> None:
        authority_states: OneShotWeakRegistry[object, _AuthorityState]
        authority_issuer: OneShotRegistryIssuer[object, _AuthorityState]
        authority_states, authority_issuer = create_one_shot_registry()
        plan_states: OneShotWeakRegistry[
            object,
            _SealedProfileCharacterizationPlanState,
        ]
        plan_issuer: OneShotRegistryIssuer[
            object,
            _SealedProfileCharacterizationPlanState,
        ]
        plan_states, plan_issuer = create_one_shot_registry()
        plan_receipt_states: OneShotWeakRegistry[object, _ReceiptOwnerState]
        plan_receipt_issuer: OneShotRegistryIssuer[object, _ReceiptOwnerState]
        plan_receipt_states, plan_receipt_issuer = create_one_shot_registry()
        blocked_diagnostic_states: OneShotWeakRegistry[object, _ReceiptOwnerState]
        blocked_diagnostic_issuer: OneShotRegistryIssuer[object, _ReceiptOwnerState]
        blocked_diagnostic_states, blocked_diagnostic_issuer = create_one_shot_registry()
        object.__setattr__(self, "_ProfileCharacterizationOwnership__lock", RLock())
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__canonical_authorities",
            {},
        )
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__plan_issuance_records",
            {},
        )
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__authority_states",
            authority_states,
        )
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__authority_issuer",
            authority_issuer,
        )
        object.__setattr__(self, "_ProfileCharacterizationOwnership__plan_states", plan_states)
        object.__setattr__(self, "_ProfileCharacterizationOwnership__plan_issuer", plan_issuer)
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__plan_receipt_states",
            plan_receipt_states,
        )
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__plan_receipt_issuer",
            plan_receipt_issuer,
        )
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__blocked_diagnostic_states",
            blocked_diagnostic_states,
        )
        object.__setattr__(
            self,
            "_ProfileCharacterizationOwnership__blocked_diagnostic_issuer",
            blocked_diagnostic_issuer,
        )

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise TypeError("Profile-characterization ownership is immutable.")

    def _authority_state_locked(self, value: object) -> _AuthorityState:
        if type(value) is not ProfileCharacterizationAuthority:
            raise TypeError("A genuine profile-characterization authority is required.")
        try:
            state = self.__authority_states[value]
        except (KeyError, TypeError):
            raise TypeError("A genuine profile-characterization authority is required.") from None
        if (
            type(state) is not _AuthorityState
            or (canonical_ref := self.__canonical_authorities.get(state.authority_identity)) is None
            or canonical_ref() is not value
        ):
            raise TypeError("A genuine profile-characterization authority is required.")
        return state

    def publish_authority(
        self,
        *,
        exact_authority_bytes: bytes,
        definitions_sha256: str,
        worker: WorkerCommand,
        timeout_seconds: float,
        expected_identity: Mapping[str, Any],
        backend_identity_bytes: bytes,
        description_result_bytes: bytes,
        public_authority: _ResolvedPublicAuthority,
    ) -> ProfileCharacterizationAuthority:
        worker_snapshot = _validated_worker_command_snapshot(worker)
        identity = _AuthorityIdentity(
            exact_authority_bytes=bytes(exact_authority_bytes),
            worker_argv=worker_snapshot.argv,
            timeout_seconds=timeout_seconds,
            expected_identity_bytes=canonical_json_bytes(dict(expected_identity)),
            backend_identity_bytes=bytes(backend_identity_bytes),
            description_result_bytes=bytes(description_result_bytes),
        )
        with self.__lock:
            existing_ref = self.__canonical_authorities.get(identity)
            existing = None if existing_ref is None else existing_ref()
            if existing is not None:
                self._authority_state_locked(existing)
                return existing
            if existing_ref is not None:
                self.__canonical_authorities.pop(identity, None)
            authority = object.__new__(ProfileCharacterizationAuthority)
            state = _AuthorityState(
                authority_identity=identity,
                exact_authority_bytes=identity.exact_authority_bytes,
                definitions_sha256=definitions_sha256,
                worker=worker_snapshot,
                timeout_seconds=timeout_seconds,
                expected_identity=copy.deepcopy(dict(expected_identity)),
                backend_identity_bytes=identity.backend_identity_bytes,
                description_result_bytes=identity.description_result_bytes,
                public_authority=public_authority,
            )
            self.__authority_issuer.bind_once(authority, state)
            authority_ref: ReferenceType[ProfileCharacterizationAuthority]

            def discard_collected(
                collected: ReferenceType[ProfileCharacterizationAuthority],
            ) -> None:
                with self.__lock:
                    if self.__canonical_authorities.get(identity) is collected:
                        self.__canonical_authorities.pop(identity, None)

            authority_ref = ref(authority, discard_collected)
            self.__canonical_authorities[identity] = authority_ref
            return authority

    def read_authority(self, value: object) -> _AuthorityState:
        with self.__lock:
            return self._authority_state_locked(value)

    def require_authority(
        self,
        value: object,
        expected_state: _AuthorityState,
    ) -> _AuthorityState:
        with self.__lock:
            state = self._authority_state_locked(value)
            if state is not expected_state:
                raise TypeError("Profile-characterization authority state is detached.")
            return state

    def _issuance_record_locked(
        self,
        plan_identity: _PlanContentIdentity,
    ) -> _PlanIssuanceRecord:
        record = self.__plan_issuance_records.get(_plan_issuance_identity(plan_identity))
        if type(record) is not _PlanIssuanceRecord:
            raise TypeError("Sealed profile-characterization plan identity is invalid.")
        return record

    def _receipt_state_locked(
        self,
        owner: object,
        *,
        plan_identity: _PlanContentIdentity,
        role: str,
    ) -> _ReceiptOwnerState:
        record = self._issuance_record_locked(plan_identity)
        expected_type: (
            type[_ProfileCharacterizationPlanReceipt] | type[_BlockedProfileDiagnosticReceipt]
        )
        registry: OneShotWeakRegistry[object, _ReceiptOwnerState]
        canonical_owner: object | None
        if role == "plan_receipt":
            expected_type = _ProfileCharacterizationPlanReceipt
            registry = self.__plan_receipt_states
            canonical_owner = record.plan_receipt()
        elif role == "blocked_diagnostic":
            expected_type = _BlockedProfileDiagnosticReceipt
            registry = self.__blocked_diagnostic_states
            canonical_owner = record.blocked_diagnostic()
        else:
            raise TypeError("Profile-characterization receipt role is invalid.")
        if type(owner) is not expected_type or canonical_owner is not owner:
            raise TypeError("A genuine profile-characterization receipt owner is required.")
        try:
            state = registry[owner]
        except (KeyError, TypeError):
            raise TypeError(
                "A genuine profile-characterization receipt owner is required."
            ) from None
        if (
            type(state) is not _ReceiptOwnerState
            or state.role != role
            or state.plan_identity != plan_identity
        ):
            raise TypeError("Profile-characterization receipt owner state is invalid.")
        return state

    def _plan_state_locked(self, owner: object) -> _SealedProfileCharacterizationPlanState:
        if type(owner) is not SealedProfileCharacterizationPlan:
            raise TypeError("A genuine sealed profile-characterization plan is required.")
        try:
            state = self.__plan_states[owner]
        except (KeyError, TypeError):
            raise TypeError("A genuine sealed profile-characterization plan is required.") from None
        if type(state) is not _SealedProfileCharacterizationPlanState:
            raise TypeError("Sealed profile-characterization plan storage is invalid.")
        record = self._issuance_record_locked(state.plan_identity)
        if (
            record.plan_owner() is not owner
            or record.plan_receipt() is not state.plan_receipt
            or record.blocked_diagnostic() is not state.blocked_diagnostic
        ):
            raise TypeError("A genuine sealed profile-characterization plan is required.")
        authority_state = self._authority_state_locked(state.authority)
        if authority_state.authority_identity != state.plan_identity.authority_identity:
            raise TypeError("Sealed profile-characterization plan authority is detached.")
        self._receipt_state_locked(
            state.plan_receipt,
            plan_identity=state.plan_identity,
            role="plan_receipt",
        )
        self._receipt_state_locked(
            state.blocked_diagnostic,
            plan_identity=state.plan_identity,
            role="blocked_diagnostic",
        )
        return state

    def publish_plan(
        self,
        *,
        authority: ProfileCharacterizationAuthority,
        plan_identity: _PlanContentIdentity,
        plan_receipt_bytes: bytes,
        blocked_diagnostic_bytes: bytes,
        provenance_owner: ProfilePlanProvenance | None,
        provenance_state: _ConsumedProfilePlanProvenance | None,
    ) -> SealedProfileCharacterizationPlan:
        with self.__lock:
            authority_state = self._authority_state_locked(authority)
            if authority_state.authority_identity != plan_identity.authority_identity:
                _reject()
            if (provenance_owner is None) != (provenance_state is None):
                _reject()
            issuance_identity = _plan_issuance_identity(plan_identity)
            if issuance_identity in self.__plan_issuance_records:
                _reject()

            plan_receipt = object.__new__(_ProfileCharacterizationPlanReceipt)
            blocked_diagnostic = object.__new__(_BlockedProfileDiagnosticReceipt)
            owner = object.__new__(SealedProfileCharacterizationPlan)
            plan_receipt_state = _ReceiptOwnerState(
                role="plan_receipt",
                plan_identity=plan_identity,
                canonical_bytes=bytes(plan_receipt_bytes),
            )
            blocked_diagnostic_state = _ReceiptOwnerState(
                role="blocked_diagnostic",
                plan_identity=plan_identity,
                canonical_bytes=bytes(blocked_diagnostic_bytes),
            )
            plan_state = _SealedProfileCharacterizationPlanState(
                authority=authority,
                plan_identity=plan_identity,
                plan_receipt=plan_receipt,
                blocked_diagnostic=blocked_diagnostic,
                provenance_owner=provenance_owner,
                provenance_state=provenance_state,
            )
            self.__plan_receipt_issuer.bind_once(plan_receipt, plan_receipt_state)
            self.__blocked_diagnostic_issuer.bind_once(
                blocked_diagnostic,
                blocked_diagnostic_state,
            )
            self.__plan_issuer.bind_once(owner, plan_state)
            self.__plan_issuance_records[issuance_identity] = _PlanIssuanceRecord(
                plan_owner=ref(owner),
                plan_receipt=ref(plan_receipt),
                blocked_diagnostic=ref(blocked_diagnostic),
            )
            return owner

    def read_plan(self, owner: object) -> _SealedProfileCharacterizationPlanState:
        with self.__lock:
            return self._plan_state_locked(owner)

    def require_plan(
        self,
        owner: object,
        expected_state: _SealedProfileCharacterizationPlanState,
    ) -> _SealedProfileCharacterizationPlanState:
        with self.__lock:
            state = self._plan_state_locked(owner)
            if state is not expected_state:
                raise TypeError("Sealed profile-characterization plan storage is invalid.")
            return state

    def read_receipt(
        self,
        owner: object,
        *,
        plan_identity: _PlanContentIdentity,
        role: str,
    ) -> _ReceiptOwnerState:
        with self.__lock:
            return self._receipt_state_locked(
                owner,
                plan_identity=plan_identity,
                role=role,
            )

    def require_receipt(
        self,
        owner: object,
        expected_state: _ReceiptOwnerState,
    ) -> _ReceiptOwnerState:
        with self.__lock:
            state = self._receipt_state_locked(
                owner,
                plan_identity=expected_state.plan_identity,
                role=expected_state.role,
            )
            if state is not expected_state:
                raise TypeError("Profile-characterization receipt owner state is invalid.")
            return state


_OWNERSHIP: Final = _ProfileCharacterizationOwnership()


def _read_authority(value: object) -> _AuthorityState:
    return _OWNERSHIP.read_authority(value)


def _require_authority(
    value: object,
    expected_state: _AuthorityState,
) -> _AuthorityState:
    return _OWNERSHIP.require_authority(value, expected_state)


def _decode_exact_mapping(content: bytes) -> dict[str, Any]:
    decoded = _json_from_bytes(content)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != content:
        raise TypeError("Profile-characterization retained mapping is invalid.")
    return cast(dict[str, Any], decoded)


def _read_sealed_profile_characterization_plan(
    owner: object,
) -> _SealedProfileCharacterizationPlanState:
    """Return exact retained state only after revalidating its complete plan graph."""

    state = _OWNERSHIP.read_plan(owner)
    authority_state = _read_authority(state.authority)
    plan_receipt_state = _OWNERSHIP.read_receipt(
        state.plan_receipt,
        plan_identity=state.plan_identity,
        role="plan_receipt",
    )
    blocked_diagnostic_state = _OWNERSHIP.read_receipt(
        state.blocked_diagnostic,
        plan_identity=state.plan_identity,
        role="blocked_diagnostic",
    )
    plan_receipt = _decode_exact_mapping(plan_receipt_state.canonical_bytes)
    blocked_diagnostic = _decode_exact_mapping(blocked_diagnostic_state.canonical_bytes)
    _audit_profile_characterization_plan_authority_bound(
        plan_receipt=plan_receipt,
        blocked_diagnostic=blocked_diagnostic,
        authenticated_worker_binding=_authenticated_worker_binding(authority_state),
    )
    _require_authority(state.authority, authority_state)
    _OWNERSHIP.require_receipt(state.plan_receipt, plan_receipt_state)
    _OWNERSHIP.require_receipt(state.blocked_diagnostic, blocked_diagnostic_state)
    _OWNERSHIP.require_plan(owner, state)
    return state


def audit_profile_characterization_plan(
    owner: SealedProfileCharacterizationPlan,
) -> None:
    """Audit one genuine sealed Plan against its retained authenticated worker owner."""

    _read_sealed_profile_characterization_plan(owner)


def project_profile_characterization_plan(
    owner: SealedProfileCharacterizationPlan,
) -> dict[str, dict[str, Any]]:
    """Return a fresh detached projection of one exact authenticated plan graph."""

    state = _read_sealed_profile_characterization_plan(owner)
    plan_receipt_state = _OWNERSHIP.read_receipt(
        state.plan_receipt,
        plan_identity=state.plan_identity,
        role="plan_receipt",
    )
    blocked_diagnostic_state = _OWNERSHIP.read_receipt(
        state.blocked_diagnostic,
        plan_identity=state.plan_identity,
        role="blocked_diagnostic",
    )
    authority_state = _read_authority(state.authority)
    plan_receipt = _decode_exact_mapping(plan_receipt_state.canonical_bytes)
    execution_identity = cast(dict[str, Any], plan_receipt["profile_execution_identity"])
    source_manifest = cast(dict[str, Any], plan_receipt["execution_source_manifest"])
    timeout_seconds = normalize_worker_timeout_seconds(authority_state.timeout_seconds)
    backend_identity, _ = _authenticated_worker_description(authority_state)
    execution_contract = {
        "timeout_seconds": timeout_seconds,
        "worker_invocation_semantics_sha256": profile_worker_invocation_semantics_digest(
            authority_state.worker,
            timeout_seconds=timeout_seconds,
        ),
        "expected_identity_pin_digest": expected_identity_pin_digest(
            authority_state.expected_identity
        ),
        "backend_identity_digest": backend_identity_digest(backend_identity),
        "profile_execution_source_manifest_sha256": source_manifest[
            "profile_execution_source_manifest_sha256"
        ],
    }
    if (
        timeout_seconds != authority_state.timeout_seconds
        or execution_contract["worker_invocation_semantics_sha256"]
        != execution_identity["worker_invocation_semantics_sha256"]
        or execution_contract["backend_identity_digest"] != plan_receipt["backend_identity_digest"]
        or execution_contract["backend_identity_digest"]
        != authority_state.expected_identity["selected_backend_identity_digest"]
        or execution_contract["profile_execution_source_manifest_sha256"]
        != execution_identity["profile_execution_source_manifest_sha256"]
    ):
        _reject()
    _require_authority(state.authority, authority_state)
    return {
        "plan_receipt": plan_receipt,
        "blocked_diagnostic": _decode_exact_mapping(blocked_diagnostic_state.canonical_bytes),
        "execution_contract": execution_contract,
    }


def _json_from_bytes(value: bytes) -> object:
    from ebm_audit.protocol import strict_json_loads

    return strict_json_loads(value)


def _family_map(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    families = document.get("scenario_families")
    if not isinstance(families, list) or any(not isinstance(row, Mapping) for row in families):
        _reject()
    mapped = {str(row["id"]): row for row in families}
    if list(mapped) != [family_id for family_id, _ in _COORDINATE_FAMILIES]:
        _reject()
    return mapped


def _analysis_event_id(synthetic_event_id: str) -> str:
    if (
        len(synthetic_event_id) != 3
        or synthetic_event_id[0] != "E"
        or not synthetic_event_id[1:].isascii()
        or not synthetic_event_id[1:].isdigit()
    ):
        _reject()
    return f"e{synthetic_event_id[1:]}"


def _authenticate_public_cases(exact_authority_bytes: bytes) -> _ResolvedPublicAuthority:
    if hashlib.sha256(exact_authority_bytes).hexdigest() != _PUBLIC_AUTHORITY_SHA256:
        _reject()
    authority = load_scenario_authority(exact_authority_bytes)
    document = authority.data
    registry = document.get("generator_field_registry")
    stage_registry = document.get("generation_stage_hash_registry")
    dependency_registry = document.get("dependency_stage_registry")
    source_contract = document.get("generator_parameter_source_contract")
    if (
        not isinstance(registry, Mapping)
        or registry.get("ordered_field_ids") != list(FIELD_IDS)
        or list(cast(Mapping[str, Any], registry.get("fields", {}))) != list(FIELD_IDS)
        or not isinstance(stage_registry, Mapping)
        or [
            row.get("stage_id")
            for row in cast(list[Mapping[str, Any]], stage_registry.get("ordered_stages", []))
        ]
        != list(GENERATION_STAGE_IDS)
        or not isinstance(dependency_registry, Mapping)
        or len(cast(list[Any], dependency_registry.get("ordered_stages", []))) != 7
        or not isinstance(source_contract, Mapping)
        or source_contract.get("derivation_registry") != _DERIVATION_REGISTRY
        or cast(Mapping[str, Any], document.get("seed_policy", {})).get("development_root_seeds")
        != list(_ROOTS)
        or document.get("family_mechanism_closure")
        != {
            "easy_known_truth": "STRICT_TOTAL_ORDER",
            "moderate_mina_shape": "STRICT_TOTAL_ORDER",
        }
    ):
        _reject()
    families = _family_map(document)
    for family_id, expected in _EXPECTED_VARIANTS.items():
        family = families[family_id]
        if (
            family.get("development_replicates") != 3
            or family.get("truth_type") != "strict_total_order"
            or family.get("development_variants") != [expected]
            or "latent_sampling_window" in expected
        ):
            _reject()

    common: _ResolvedPublicSemantics | None = None
    case_ids: list[str] = []
    case_seeds: set[str] = set()
    bindings: list[dict[str, Any]] = []
    for family_id, variant_id in _COORDINATE_FAMILIES:
        for replicate_index in range(3):
            resolved = resolve_development_case(
                authority,
                CaseCoordinate(family_id, variant_id, replicate_index),
            )
            verify_exact_resolution(authority, resolved)
            resolutions = {row.field_id: row for row in resolved.field_resolutions}
            semantics = _ResolvedPublicSemantics(
                event_ids=tuple(resolved.resolved_configuration["event_ids"]),
                truth_directions=tuple(resolved.resolved_configuration["event_directions"]),
                analysis_directions=tuple(
                    resolved.resolved_configuration["analysis_configuration"][
                        "event_spec_directions"
                    ]
                ),
                event_centers=tuple(
                    float(value)
                    for value in resolved.resolved_configuration["event_parameters"][
                        "event_centers"
                    ]
                ),
            )
            if any(
                resolutions[field_id].source_kind != "EVALUATOR_DERIVATION"
                for field_id in ("event_ids", "event_directions", "event_centers")
            ):
                _reject()
            if common is None:
                common = semantics
            elif semantics != common:
                _reject()
            event_mappings = [
                {
                    "event_ordinal": event_ordinal,
                    "synthetic_event_id": synthetic_event_id,
                    "analysis_event_id": _analysis_event_id(synthetic_event_id),
                }
                for event_ordinal, synthetic_event_id in enumerate(semantics.event_ids)
            ]
            binding: dict[str, Any] = {
                "binding_schema_version": ("ebm-audit-profile-synthetic-event-binding/1.0"),
                "coordinate": {
                    "family_id": family_id,
                    "scenario_id": variant_id,
                    "replicate_index": replicate_index,
                },
                "scenario_definitions_sha256": authority.definitions_sha256,
                "source_contract_sha256": resolved.source_contract_sha256,
                "resolved_parameter_manifest_sha256": resolved.resolved_parameter_manifest[
                    "resolved_parameter_manifest_sha256"
                ],
                "resolved_generator_configuration_sha256": (
                    resolved.resolved_configuration["resolved_generator_configuration_sha256"]
                ),
                "mapping_method_id": "synthetic-e-id-lowercase-machine-id/1",
                "resolver_method_ids": {
                    "event_ids": "event-ids-from-count/1",
                    "event_directions": "alternating-event-directions/1",
                    "event_centers": "even-event-centers/1",
                },
                "ordered_event_mappings": event_mappings,
                "ordered_truth_directions": list(semantics.truth_directions),
                "ordered_analysis_directions": list(semantics.analysis_directions),
                "ordered_event_centers": [
                    {"type": "float64", "value": center} for center in semantics.event_centers
                ],
                "profile_synthetic_event_binding_sha256": None,
            }
            binding["profile_synthetic_event_binding_sha256"] = structured_sha256_hex(
                _SYNTHETIC_EVENT_BINDING_DOMAIN,
                binding,
            )
            validate_instance(
                binding,
                "evaluator-receipts.schema.json",
                definition="ProfileSyntheticEventBinding",
            )
            bindings.append(binding)
            case_ids.append(resolved.case_id)
            case_seeds.add(resolved.case_seed)
    if (
        common is None
        or len(case_ids) != 6
        or len(set(case_ids)) != 6
        or len(case_seeds) != 6
        or len(common.event_ids) != 9
        or len(common.truth_directions) != 9
        or len(common.analysis_directions) != 9
        or len(common.event_centers) != 9
    ):
        _reject()
    analysis_ids = tuple(_analysis_event_id(event_id) for event_id in common.event_ids)
    return _ResolvedPublicAuthority(
        semantics=_ResolvedPublicSemantics(
            event_ids=analysis_ids,
            truth_directions=common.truth_directions,
            analysis_directions=common.analysis_directions,
            event_centers=common.event_centers,
        ),
        bindings=tuple(bindings),
    )


def _selected_algorithm(description_result: Mapping[str, Any]) -> dict[str, Any]:
    algorithms = description_result.get("supported_algorithms")
    if not isinstance(algorithms, Sequence):
        _reject()
    selected = [
        dict(row)
        for row in algorithms
        if isinstance(row, Mapping) and row.get("algorithm_id") == _SELECTED_ALGORITHM_ID
    ]
    if len(selected) != 1:
        _reject()
    return selected[0]


def _validate_requested_outputs(
    description_result: Mapping[str, Any],
    algorithm: Mapping[str, Any],
) -> None:
    registry_digest = requested_output_registry_digest()
    profile_requested_outputs_digest = requested_outputs_digest("fit", _REQUESTED_OUTPUTS)
    capabilities = algorithm["capabilities"]
    registry_rows = load_protocol_registry()["requested_outputs"]
    row_by_id = {row["output_id"]: row for row in registry_rows}
    if (
        description_result.get("requested_output_registry_digest") != registry_digest
        or algorithm["adapter_semantics"].get("requested_output_registry_digest") != registry_digest
        or not profile_requested_outputs_digest.startswith("sha256:")
        or len(profile_requested_outputs_digest) != 71
    ):
        _reject()
    for output_id in _REQUESTED_OUTPUTS:
        row = row_by_id.get(output_id)
        if (
            not isinstance(row, Mapping)
            or "fit" not in row["commands"]
            or any(
                capabilities.get(capability) is not True
                for capability in row["required_capabilities"]
            )
        ):
            _reject()


def _validate_worker_description(
    *,
    backend_identity: Mapping[str, Any],
    description_result: Mapping[str, Any],
    expected_identity: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    algorithm = _selected_algorithm(description_result)
    capabilities = algorithm["capabilities"]
    settings_schema = algorithm["settings_schema"]
    stage_semantics = algorithm["stage_semantics_definition"]
    semantics = algorithm["adapter_semantics"]
    selected_backend_identity = copy.deepcopy(dict(backend_identity))
    selected_backend_identity["algorithm_id"] = algorithm["algorithm_id"]
    if (
        backend_identity_digest(backend_identity)
        != expected_identity.get("base_backend_identity_digest")
        or backend_identity_digest(selected_backend_identity)
        != expected_identity.get("selected_backend_identity_digest")
        or expected_identity.get("selected_algorithm_id") != _SELECTED_ALGORITHM_ID
        or expected_identity.get("capabilities_digest") != algorithm.get("capabilities_digest")
        or backend_identity.get("algorithm_id") is not None
        or algorithm.get("capabilities_digest") != capabilities_digest(capabilities)
        or algorithm.get("settings_schema_digest") != settings_schema_digest(settings_schema)
        or algorithm.get("stage_semantics_digest") != stage_semantics_digest(stage_semantics)
        or algorithm.get("adapter_semantics_digest") != adapter_semantics_digest(semantics)
        or semantics.get("algorithm_id") != _SELECTED_ALGORITHM_ID
        or semantics.get("adapter_id") != backend_identity.get("adapter_id")
        or semantics.get("capabilities_digest") != algorithm.get("capabilities_digest")
        or semantics.get("settings_schema_digest") != algorithm.get("settings_schema_digest")
        or semantics.get("stage_semantics_digest") != algorithm.get("stage_semantics_digest")
        or capabilities.get("fixed_evaluation_cohort_staging") is not True
        or capabilities.get("offline_execution") is not True
        or capabilities.get("multiple_chains") is not True
        or "fit" not in algorithm.get("supported_commands", [])
    ):
        _reject()
    _validate_requested_outputs(description_result, algorithm)
    for _, raw_iterations, burn_in in _PROFILE_BUDGETS:
        validate_settings(
            {
                "raw_iterations": raw_iterations,
                "burn_in": burn_in,
                "thinning": 10,
                "n_shuffle": 2,
                "prior_n": 1.0,
                "prior_v": 1.0,
            },
            settings_schema,
        )
    return selected_backend_identity, algorithm


def profile_worker_invocation_semantics_digest(
    worker: WorkerCommand,
    *,
    timeout_seconds: float,
) -> str:
    """Hash the exact command tokens and normalized timeout without disclosing them."""

    worker_snapshot = _validated_worker_command_snapshot(worker)
    normalized_timeout = normalize_worker_timeout_seconds(timeout_seconds)
    preimage = {
        "invocation_schema_version": ("ebm-audit-profile-worker-invocation-semantics/1.0"),
        "argv": list(worker_snapshot.argv),
        "timeout_seconds": normalized_timeout,
    }
    try:
        validate_instance(
            preimage,
            "evaluator-receipts.schema.json",
            definition="ProfileWorkerInvocationSemanticsDigestPreimage",
        )
    except SchemaValidationError:
        _reject()
    return structured_sha256_hex(
        _PROFILE_WORKER_INVOCATION_SEMANTICS_DOMAIN,
        preimage,
    )


def derive_profile_public_seed(
    *,
    profile_execution_identity_sha256: str,
    profile_synthetic_event_binding_sha256: str,
    chain_id: str,
) -> str:
    """Derive one public UInt64 seed shared by all budgets for a case-chain slot."""

    preimage = {
        "seed_preimage_schema_version": "ebm-audit-profile-public-seed-preimage/2.0",
        "derivation_id": _PROFILE_PUBLIC_SEED_DERIVATION_ID,
        "profile_execution_identity_sha256": profile_execution_identity_sha256,
        "profile_synthetic_event_binding_sha256": (profile_synthetic_event_binding_sha256),
        "chain_id": chain_id,
    }
    try:
        validate_instance(
            preimage,
            "evaluator-receipts.schema.json",
            definition="ProfilePublicSeedPreimage",
        )
    except SchemaValidationError:
        _reject()
    return bytes.fromhex(structured_sha256_hex(_PROFILE_PUBLIC_SEED_DOMAIN, preimage))[:8].hex()


def _profile_source_provenance(value: Mapping[str, Any]) -> dict[str, Any]:
    provenance = copy.deepcopy(dict(value))
    try:
        validate_instance(
            provenance,
            "evaluator-receipts.schema.json",
            definition="ProfilePlanSourceProvenance",
        )
    except SchemaValidationError:
        _reject()
    if [row["source_role"] for row in provenance["ordered_source_set_identities"]] != list(
        _PROFILE_PROVENANCE_SOURCE_ROLES
    ):
        _reject()
    return provenance


def _profile_execution_source_manifest(
    preimage: Mapping[str, Any],
) -> dict[str, Any]:
    manifest = copy.deepcopy(dict(preimage))
    try:
        validate_instance(
            manifest,
            "evaluator-receipts.schema.json",
            definition="ProfileExecutionSourceManifestDigestPreimage",
        )
    except SchemaValidationError:
        _reject()
    entries = manifest["ordered_entries"]
    if [row["fit_role"] for row in entries] != list(_PROFILE_FIT_SOURCE_ROLES) or any(
        (paths := [entry["path"] for entry in row["ordered_files"]]) != sorted(set(paths))
        for row in entries
    ):
        _reject()
    manifest["profile_execution_source_manifest_sha256"] = structured_sha256_hex(
        _PROFILE_EXECUTION_SOURCE_MANIFEST_DOMAIN,
        manifest,
    )
    validate_instance(
        manifest,
        "evaluator-receipts.schema.json",
        definition="ProfileExecutionSourceManifest",
    )
    return manifest


def authenticate_profile_characterization_authority(
    *,
    exact_authority_bytes: bytes,
    worker: WorkerCommand,
    timeout_seconds: float = 60.0,
) -> ProfileCharacterizationAuthority:
    """Authenticate exact public cases and the current selected worker Describe."""

    worker_snapshot = _validated_worker_command_snapshot(worker)
    normalized_timeout = normalize_worker_timeout_seconds(timeout_seconds)
    public_authority = _authenticate_public_cases(exact_authority_bytes)
    discovery = describe_worker(
        worker_snapshot,
        timeout_seconds=normalized_timeout,
        selected_algorithm_id=_SELECTED_ALGORITHM_ID,
    )
    expected_identity = discovery.get("selected_expected_identity")
    if not isinstance(expected_identity, Mapping):
        _reject()
    authenticated = WorkerInvoker(
        worker_snapshot,
        timeout_seconds=normalized_timeout,
        expected_identity=expected_identity,
    ).describe_authenticated()
    backend_identity = authenticated.backend_identity
    description_result = authenticated.description_result
    _validate_worker_description(
        backend_identity=backend_identity,
        description_result=description_result,
        expected_identity=expected_identity,
    )
    authority = _OWNERSHIP.publish_authority(
        exact_authority_bytes=bytes(exact_authority_bytes),
        definitions_sha256=hashlib.sha256(exact_authority_bytes).hexdigest(),
        worker=worker_snapshot,
        timeout_seconds=normalized_timeout,
        expected_identity=copy.deepcopy(dict(expected_identity)),
        backend_identity_bytes=canonical_json_bytes(backend_identity),
        description_result_bytes=canonical_json_bytes(description_result),
        public_authority=public_authority,
    )
    _read_authority(authority)
    return authority


def _proposal_schema(algorithm: Mapping[str, Any]) -> dict[str, Any]:
    projection = algorithm["adapter_semantics"]["mcmc_projection"]
    bindings = projection["proposal_setting_bindings"]
    backend_properties = algorithm["settings_schema"]["properties"]
    if (
        projection.get("availability") != "AVAILABLE"
        or projection.get("plan_owned_fields") != ["chain_count", "seed_derivation_version"]
        or [row.get("plan_field") for row in projection.get("schedule_bindings", [])]
        != ["raw_iteration_count", "burn_in_count", "thinning_interval"]
    ):
        _reject()
    names = [row["proposal_setting_id"] for row in bindings]
    backend_names = [row["backend_setting_id"] for row in bindings]
    if (
        names != sorted(names)
        or len(set(names)) != len(names)
        or len(set(backend_names)) != len(backend_names)
        or any(name not in backend_properties for name in backend_names)
    ):
        _reject()
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (f"urn:ebm-audit:worker-settings-schema:{projection['proposal_method_id']}:1"),
        "type": "object",
        "additionalProperties": False,
        "properties": {
            row["proposal_setting_id"]: copy.deepcopy(backend_properties[row["backend_setting_id"]])
            for row in bindings
        },
        "required": sorted(names),
    }
    validate_instance(schema, "worker-protocol.schema.json", definition="ClosedSettingsSchema")
    return schema


def _authenticated_worker_description(
    state: _AuthorityState,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Revalidate the exact base identity and Describe result retained by the authority."""

    return _validate_worker_description(
        backend_identity=_decode_exact_mapping(state.backend_identity_bytes),
        description_result=_decode_exact_mapping(state.description_result_bytes),
        expected_identity=state.expected_identity,
    )


def _authenticated_worker_binding(state: _AuthorityState) -> _AuthenticatedWorkerBinding:
    selected_backend_identity, algorithm = _authenticated_worker_description(state)
    return (
        algorithm["adapter_semantics_digest"],
        selected_backend_identity["backend_source_digest"],
        algorithm["capabilities_digest"],
        algorithm["settings_schema_digest"],
        algorithm["stage_semantics_digest"],
        settings_schema_digest(_proposal_schema(algorithm)),
    )


def _analysis_spec(
    *,
    semantics: _ResolvedPublicSemantics,
    backend_identity: Mapping[str, Any],
    algorithm: Mapping[str, Any],
    raw_iterations: int,
    burn_in: int,
) -> dict[str, Any]:
    settings = {
        "raw_iterations": raw_iterations,
        "burn_in": burn_in,
        "thinning": 10,
        "n_shuffle": 2,
        "prior_n": 1.0,
        "prior_v": 1.0,
    }
    proposal_schema = _proposal_schema(algorithm)
    projection = algorithm["adapter_semantics"]["mcmc_projection"]
    proposal_settings = [
        {
            "name": row["proposal_setting_id"],
            "value": settings[row["backend_setting_id"]],
        }
        for row in projection["proposal_setting_bindings"]
    ]
    spec = {
        "spec_schema_version": "ebm-audit-analysis-spec/3.0",
        "dataset_variant_intent": {
            "source_variant_id": "baseline-input",
            "variant_kind": "baseline-input",
            "source_variant_id_ref": None,
            "method_id": "exact-input-bytes/1",
        },
        "cohort_rule": {
            "group_spec_id": "profile-groups",
            "source_kind": "label-alias",
            "public_field_ids": ["analysis-group"],
            "label_roles": [
                {"public_label_id": "at-risk", "role": "at_risk"},
                {"public_label_id": "reference", "role": "reference"},
            ],
            "role_rules": [],
            "required_roles": ["reference", "at_risk"],
        },
        "event_set": [{"event_id": event_id} for event_id in semantics.event_ids],
        "event_directions": dict(
            zip(semantics.event_ids, semantics.analysis_directions, strict=True)
        ),
        "preprocessing": [],
        "outlier_policy": {
            "policy_kind": "none",
            "threshold": None,
            "scope": "none",
            "action": "none",
            "reference_population": "none",
            "value_transformation": None,
        },
        "missingness_policy": {
            "policy": "error",
            "event_ids": list(semantics.event_ids),
        },
        "covariate_adjustment": {
            "method": "none",
            "ordered_terms": [],
            "intercept": None,
            "categorical_encoding": "none",
            "minimum_reference_rows": None,
            "require_full_rank": False,
        },
        "backend": {
            "backend_schema_version": "ebm-audit-backend-spec/3.0",
            "adapter_id": backend_identity["adapter_id"],
            "adapter_semantics_digest": algorithm["adapter_semantics_digest"],
            "expected_backend_name": backend_identity["backend_name"],
            "expected_backend_source_digest": backend_identity["backend_source_digest"],
            "algorithm_id": algorithm["algorithm_id"],
            "settings_classification": "public-scientific-settings/1",
            "capabilities_digest": algorithm["capabilities_digest"],
            "settings_schema_digest": algorithm["settings_schema_digest"],
            "stage_semantics_digest": algorithm["stage_semantics_digest"],
            "settings": settings,
            "settings_digest": settings_digest(settings),
            "requested_outputs": list(_REQUESTED_OUTPUTS),
            "requested_outputs_digest": requested_outputs_digest("fit", _REQUESTED_OUTPUTS),
        },
        "mcmc": {
            "raw_iteration_count": raw_iterations,
            "burn_in_count": burn_in,
            "thinning_interval": 10,
            "indexing_rule": projection["indexing_rule"],
            "proposal_method_id": projection["proposal_method_id"],
            "proposal_settings": proposal_settings,
            "proposal_settings_schema_digest": settings_schema_digest(proposal_schema),
            "proposal_settings_classification": "public-scientific-settings/1",
            "chain_count": 3,
            "seed_derivation_version": "hmac-sha256-u64be-v2",
            "initialization_rule": projection["initialization_rule"],
        },
        "operation_intent": {"kind": "ordinary"},
    }
    validate_instance(
        spec,
        "evaluator-receipts.schema.json",
        definition="ProfileCharacterizationAnalysisSpec",
    )
    return spec


def _subject(
    *,
    profile_id: str,
    candidate: Mapping[str, Any],
    contract_sha256: str,
    backend_identity: Mapping[str, Any],
    algorithm: Mapping[str, Any],
    profile_settings_digest: str,
) -> dict[str, Any]:
    return {
        "subject_schema_version": "ebm-audit-benchmark-subject/1.0",
        "subject_kind": "genuine-real-backend",
        "backend_identity_digest": backend_identity_digest(backend_identity),
        "adapter_id": backend_identity["adapter_id"],
        "adapter_version": backend_identity["adapter_version"],
        "backend_name": backend_identity["backend_name"],
        "backend_version": backend_identity["backend_version"],
        "algorithm_id": backend_identity["algorithm_id"],
        "worker_executable_digest": backend_identity["worker_executable_digest"],
        "worker_code_digest": backend_identity["worker_code_digest"],
        "backend_source_commit": backend_identity["backend_source_commit"],
        "backend_source_digest": backend_identity["backend_source_digest"],
        "environment_digest": backend_identity["environment_digest"],
        "capabilities_digest": algorithm["capabilities_digest"],
        "settings_digest": profile_settings_digest,
        "protocol_version": "ebm-audit-worker/v2",
        "request_schema_version": "ebm-audit-worker-request/2.0",
        "response_schema_version": "ebm-audit-worker-response/2.0",
        "worker_payload_schema_version": "ebm-audit-worker-fit-payload/2.0",
        "requested_outputs_digest": requested_outputs_digest("fit", _REQUESTED_OUTPUTS),
        "benchmark_profile_id": profile_id,
        "convergence_rule_id": "convergence-v1",
        "null_calibration_rule_id": "null-calibration-v1",
        "candidate_git_object_format": candidate["git_object_format"],
        "candidate_git_commit": candidate["git_commit"],
        "candidate_sha256": candidate["candidate_sha256"],
        "contract_sha256": contract_sha256,
    }


def _coordinates() -> list[dict[str, Any]]:
    return [
        {
            "family_id": family_id,
            "scenario_id": scenario_id,
            "replicate_index": replicate_index,
        }
        for family_id, scenario_id in _COORDINATE_FAMILIES
        for replicate_index in range(3)
    ]


def _evidence_registry() -> dict[str, Any]:
    return {
        "registry_schema_version": "ebm-audit-profile-evidence-metric-registry/1.0",
        "ordered_evidence_category_ids": [
            "profile-terminal-core-observed-runtime-row/1",
            "profile-chain-transition-diagnostics-row/1",
            "profile-universe-convergence-classification/1",
            "profile-within-budget-cross-chain-distance-observation/1",
            "profile-same-chain-cross-budget-distance-observation/1",
            "profile-paired-runtime-ratio/1",
        ],
        "ordered_transition_observation_ids": [
            "unthinned-transition-rate/1",
            "unique-state-fraction/1",
            "maximum-repeated-state-fraction/1",
            "endpoint-zero-transition-evidence/1",
        ],
        "ordered_distance_family_ids": [
            "central-order-kendall/1",
            "position-matrix/1",
            "pairwise-precedence-matrix/1",
        ],
        "ordered_easy_metric_ids": [
            "easy-central-order-kendall-agreement/1",
            "easy-normalized-stage-mae/1",
        ],
        "ordered_moderate_descriptive_metric_ids": [
            "moderate-fixed-reference-alignment-descriptive/1",
            "moderate-normalized-stage-mae/1",
        ],
    }


def _cardinalities() -> dict[str, int]:
    return {
        "signal_dataset_count": 6,
        "easy_signal_dataset_count": 3,
        "moderate_signal_dataset_count": 3,
        "logical_coordinate_count": 6,
        "budget_profile_count": 3,
        "profile_universe_count": 18,
        "chain_count_per_universe": 3,
        "chain_execution_count": 54,
        "budget_relation_count": 3,
        "same_chain_comparison_count_per_relation": 18,
        "paired_chain_comparison_count": 54,
        "logical_case_chain_slot_count": 18,
        "terminal_core_runtime_row_count": 54,
        "chain_transition_row_count": 54,
        "universe_convergence_classification_count": 18,
        "within_budget_cross_chain_observation_count_per_distance_family": 54,
        "within_budget_cross_chain_observation_count_all_distance_families": 162,
        "same_chain_cross_budget_observation_count_per_distance_family": 54,
        "same_chain_cross_budget_observation_count_all_distance_families": 162,
        "paired_runtime_ratio_count": 54,
        "easy_observation_count_per_metric": 9,
        "moderate_descriptive_observation_count_per_metric": 9,
    }


def _selection_policy() -> dict[str, Any]:
    return {
        "policy_schema_version": "ebm-audit-profile-budget-selection-policy/2.0",
        "selection_rule_id": "quick-full-release-budget-selection/3",
        "resolver_authority": "FUTURE_PRODUCT_OWNED_PROFILE_EVIDENCE_RESOLVER",
        "release_target_profile_id": "characterization_10000",
        "release_required_components": [
            "COMPLETE_REQUIRED_CONVERGENCE_PASS_EVIDENCE",
            "REVIEWED_TRANSITION_QUALITY_PASS",
        ],
        "release_failure_outcome": "NO_SELECTION",
        "full_candidate_profile_id": "characterization_5000",
        "full_required_relation_id": "characterization-5000-to-10000/1",
        "quick_candidate_profile_id": "characterization_2000",
        "quick_prerequisite": "FULL_5000_QUALIFIED",
        "quick_required_relation_ids": [
            "characterization-2000-to-10000/1",
            "characterization-2000-to-5000/1",
        ],
        "transitive_inference_allowed": False,
        "relation_pass_required_components": [
            "COMPLETE_CANDIDATE_AND_REFERENCE_CONVERGENCE_PASS",
            "REVIEWED_TRANSITION_QUALITY_PASS",
            "ALL_DISTANCE_FAMILY_THRESHOLDS_PASS",
            "MEDIAN_OF_18_PAIRED_CANDIDATE_OVER_REFERENCE_RUNTIME_RATIOS_LT_ONE",
            "NONINFERENTIAL_PAIRED_DEVELOPMENT_SAFEGUARDS_PASS",
        ],
        "distance_aggregation_rule": ("EACH_DISTANCE_FAMILY_SEPARATELY_PER_RELATION_NEVER_POOLED"),
        "relation_distance_pass_rule": (
            "ALL_THREE_FAMILIES_EACH_REQUIRE_MEDIAN_LTE_0_10_AND_MAX_LTE_0_20"
        ),
        "median_distance_maximum": 0.1,
        "maximum_distance_maximum": 0.2,
        "transition_quality_policy": {
            "policy_schema_version": "ebm-audit-profile-transition-quality-policy/1.0",
            "review_state": "PENDING_INDEPENDENT_TRANSITION_RULE_REVIEW",
            "pre_review_selection_outcome": "NO_SELECTION",
            "future_decision_owner_type": (
                "VERSIONED_MACHINE_EXECUTABLE_INDEPENDENT_TRANSITION_QUALITY_DECISION_OWNER"
            ),
            "ordered_transition_observation_ids": [
                "unthinned-transition-rate/1",
                "unique-state-fraction/1",
                "maximum-repeated-state-fraction/1",
                "endpoint-zero-transition-evidence/1",
            ],
            "ordered_required_decision_content_ids": [
                "transition-metric-directions/1",
                "transition-per-metric-aggregation/1",
                "transition-per-metric-tolerances/1",
                "transition-endpoint-zero-rule/1",
                "transition-complete-denominators/1",
                "transition-plan-evidence-subject-binding/1",
                "transition-no-preferred-central-order-targeting/1",
            ],
            "preferred_central_order_targeting_allowed": False,
        },
        "runtime_comparison_policy": {
            "policy_schema_version": "ebm-audit-profile-runtime-comparison-policy/1.0",
            "ordered_pairing_key_fields": [
                "family_id",
                "scenario_id",
                "replicate_index",
                "chain_id",
            ],
            "expected_ratio_count_per_relation": 18,
            "ratio_numerator": "CANDIDATE_TERMINAL_CORE_OBSERVED_RUNTIME",
            "ratio_denominator": "REFERENCE_TERMINAL_CORE_OBSERVED_RUNTIME",
            "observation_validity_rule": (
                "COMPLETE_FINITE_TERMINAL_CORE_OBSERVED_NUMERATOR_AND_COMPLETE_"
                "FINITE_STRICTLY_POSITIVE_TERMINAL_CORE_OBSERVED_DENOMINATOR"
            ),
            "quantile_rule_id": "inverse-empirical-cdf/1",
            "quantile_probability": 0.5,
            "one_based_ordered_value_ordinal": 9,
            "interpolation_allowed": False,
            "pass_rule_id": ("MEDIAN_OF_18_PAIRED_CANDIDATE_OVER_REFERENCE_RUNTIME_RATIOS_LT_ONE"),
            "comparison_operator": "LT",
            "comparison_threshold": 1.0,
            "comparison_tolerance": 0.0,
            "invalid_or_equal_outcome": "RELATION_FAIL_AND_DEFAULT_UPWARD",
        },
        "easy_truth_kendall_safeguard": ("MEDIAN_PAIRED_CANDIDATE_MINUS_REFERENCE_GTE_ZERO"),
        "easy_stage_mae_safeguard": ("MEDIAN_PAIRED_CANDIDATE_MINUS_REFERENCE_LTE_ZERO"),
        "moderate_stage_mae_safeguard": ("MEDIAN_PAIRED_CANDIDATE_MINUS_REFERENCE_LTE_ZERO"),
        "moderate_alignment_use": "DESCRIPTIVE_ONLY_NOT_A_SELECTION_GATE",
        "stage_mae_population": "EXACT_GENERATED_FIXED_EVALUATION_COHORT_ROWS",
        "stage_truth_binding": "THRESHOLD_STAGE",
        "stage_axis_incompatibility_outcome": "NOT_ASSESSABLE_AND_NO_SELECTION",
        "p_values_allowed": False,
        "adaptive_extra_replicates_allowed": False,
        "ineligible_or_incomplete_behavior": (
            "MISSING_PENDING_WARN_FAIL_NOT_ASSESSABLE_BORDERLINE_INCOMPLETE_OR_"
            "UNREVIEWED_DEFAULTS_UPWARD_EXCEPT_FAILED_OR_UNREVIEWED_10000_NO_SELECTION"
        ),
    }


def _profile_execution_identity(
    *,
    scenario_definitions_sha256: str,
    execution_source_manifest_sha256: str,
    worker_invocation_semantics_sha256: str,
    coordinates: Sequence[Mapping[str, Any]],
    synthetic_event_bindings: Sequence[Mapping[str, Any]],
    budgets: Sequence[Mapping[str, Any]],
    backend_identity: Mapping[str, Any],
    canonicalization: Mapping[str, Any],
    execution_policy: Mapping[str, Any],
    logical_slots: Sequence[Mapping[str, Any]],
    budget_relations: Sequence[Mapping[str, Any]],
    evidence_metric_registry: Mapping[str, Any],
    expected_cardinalities: Mapping[str, Any],
) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "identity_schema_version": "ebm-audit-profile-execution-identity/1.0",
        "scenario_definitions_sha256": scenario_definitions_sha256,
        "profile_execution_source_manifest_sha256": (execution_source_manifest_sha256),
        "worker_invocation_semantics_sha256": worker_invocation_semantics_sha256,
        "ordered_coordinates": [copy.deepcopy(dict(row)) for row in coordinates],
        "ordered_synthetic_event_binding_sha256s": [
            row["profile_synthetic_event_binding_sha256"] for row in synthetic_event_bindings
        ],
        "ordered_analysis_spec_identities": [
            {
                "profile_id": row["profile_id"],
                "analysis_spec_id": row["analysis_spec_id"],
            }
            for row in budgets
        ],
        "backend_identity_digest": backend_identity_digest(backend_identity),
        "environment_digest": backend_identity["environment_digest"],
        "requested_outputs_digest": budgets[0]["analysis_spec"]["backend"][
            "requested_outputs_digest"
        ],
        "canonicalization": copy.deepcopy(dict(canonicalization)),
        "chain_count": 3,
        "public_seed_derivation_id": _PROFILE_PUBLIC_SEED_DERIVATION_ID,
        "execution_policy": copy.deepcopy(dict(execution_policy)),
        "ordered_logical_case_chain_slots": [copy.deepcopy(dict(row)) for row in logical_slots],
        "ordered_budget_relations": [copy.deepcopy(dict(row)) for row in budget_relations],
        "evidence_metric_registry": copy.deepcopy(dict(evidence_metric_registry)),
        "expected_cardinalities": copy.deepcopy(dict(expected_cardinalities)),
        "profile_execution_identity_sha256": None,
    }
    validate_instance(
        identity,
        "evaluator-receipts.schema.json",
        definition="ProfileExecutionIdentityDigestPreimage",
    )
    identity["profile_execution_identity_sha256"] = structured_sha256_hex(
        _PROFILE_EXECUTION_IDENTITY_DOMAIN,
        identity,
    )
    validate_instance(
        identity,
        "evaluator-receipts.schema.json",
        definition="ProfileExecutionIdentity",
    )
    return identity


def _plan_content_identity(
    authority_state: _AuthorityState,
    graph: Mapping[str, Mapping[str, Any]],
) -> _PlanContentIdentity:
    """Bind one issuance identity to all substantive content, excluding timestamps."""

    plan = copy.deepcopy(dict(graph["plan_receipt"]))
    diagnostic = copy.deepcopy(dict(graph["blocked_diagnostic"]))
    plan["completed_at_utc"] = None
    plan["profile_characterization_plan_receipt_sha256"] = None
    diagnostic["completed_at_utc"] = None
    diagnostic["profile_characterization_plan_receipt_sha256"] = None
    diagnostic["blocked_profile_diagnostic_sha256"] = None
    return _PlanContentIdentity(
        authority_identity=authority_state.authority_identity,
        timestamp_free_graph_bytes=canonical_json_bytes(
            {
                "plan_receipt": plan,
                "blocked_diagnostic": diagnostic,
            }
        ),
    )


def _issue_profile_characterization_plan_from_material(
    authority: ProfileCharacterizationAuthority,
    *,
    candidate: Mapping[str, Any],
    contract_sha256: str,
    source_provenance: Mapping[str, Any],
    execution_source_manifest_preimage: Mapping[str, Any],
    canonicalization: Mapping[str, Any],
    plan_completed_at_utc: str,
    diagnostic_completed_at_utc: str,
    provenance_owner: ProfilePlanProvenance | None,
    provenance_state: _ConsumedProfilePlanProvenance | None,
) -> SealedProfileCharacterizationPlan:
    """Build one plan from already-owned material.

    Only the public wrapper may supply a provenance owner. The mapping-based
    path exists solely for structural tests and cannot authorize execution.
    """

    state = _read_authority(authority)
    if _authenticate_public_cases(state.exact_authority_bytes) != state.public_authority:
        _reject()
    _require_authority(authority, state)
    authenticated = WorkerInvoker(
        state.worker,
        timeout_seconds=state.timeout_seconds,
        expected_identity=state.expected_identity,
    ).describe_authenticated()
    base_backend_identity = dict(authenticated.backend_identity)
    description_result = dict(authenticated.description_result)
    backend_identity, algorithm = _validate_worker_description(
        backend_identity=base_backend_identity,
        description_result=description_result,
        expected_identity=state.expected_identity,
    )
    if (
        canonical_json_bytes(base_backend_identity) != state.backend_identity_bytes
        or canonical_json_bytes(description_result) != state.description_result_bytes
    ):
        _reject()
    _require_authority(authority, state)
    candidate_copy = copy.deepcopy(dict(candidate))
    canonicalization_copy = copy.deepcopy(dict(canonicalization))
    try:
        validate_instance(
            candidate_copy,
            "evaluator-receipts.schema.json",
            definition="CandidateIdentity",
        )
    except SchemaValidationError:
        _reject()
    source_provenance_copy = _profile_source_provenance(source_provenance)
    execution_source_manifest = _profile_execution_source_manifest(
        execution_source_manifest_preimage
    )

    coordinates = _coordinates()
    profile_ids = [profile_id for profile_id, _, _ in _PROFILE_BUDGETS]
    budgets: list[dict[str, Any]] = []
    for profile_id, raw_iterations, burn_in in _PROFILE_BUDGETS:
        spec = _analysis_spec(
            semantics=state.public_authority.semantics,
            backend_identity=backend_identity,
            algorithm=algorithm,
            raw_iterations=raw_iterations,
            burn_in=burn_in,
        )
        budgets.append(
            {
                "profile_id": profile_id,
                "raw_iteration_count": raw_iterations,
                "burn_in_count": burn_in,
                "thinning_interval": 10,
                "chain_count": 3,
                "analysis_spec_id": analysis_spec_content_id(spec),
                "analysis_spec": spec,
                "experimental_subject": _subject(
                    profile_id=profile_id,
                    candidate=candidate_copy,
                    contract_sha256=contract_sha256,
                    backend_identity=backend_identity,
                    algorithm=algorithm,
                    profile_settings_digest=spec["backend"]["settings_digest"],
                ),
                "subject_acceptance_state": "EXPERIMENTAL",
            }
        )
    synthetic_event_bindings = [
        copy.deepcopy(binding) for binding in state.public_authority.bindings
    ]
    execution_policy = {
        "policy_schema_version": "ebm-audit-profile-execution-policy/1.0",
        "fit_execution_mode": "FRESH_INDEPENDENT_SERIAL_PROCESSES",
        "cache_policy": "NO_READ_NO_WRITE",
        "checkpoint_policy": "NO_READ_NO_WRITE",
        "retry_policy": "DISALLOWED",
        "caller_supplied_seeds_allowed": False,
        "ordered_budget_rotations": [
            {
                **coordinate,
                "ordered_profile_ids": [
                    profile_ids[(int(coordinate["replicate_index"]) + offset) % len(profile_ids)]
                    for offset in range(len(profile_ids))
                ],
            }
            for coordinate in coordinates
        ],
    }
    logical_slots = [
        {
            **coordinate,
            "chain_ordinal": chain_ordinal,
            "chain_id": f"chain-{chain_ordinal:04d}",
        }
        for coordinate in coordinates
        for chain_ordinal in range(3)
    ]
    budget_relations = [
        {
            "relation_id": "characterization-5000-to-10000/1",
            "candidate_profile_id": "characterization_5000",
            "reference_profile_id": "characterization_10000",
            "comparison_direction": "CANDIDATE_TO_REFERENCE",
            "expected_same_chain_comparison_count": 18,
        },
        {
            "relation_id": "characterization-2000-to-10000/1",
            "candidate_profile_id": "characterization_2000",
            "reference_profile_id": "characterization_10000",
            "comparison_direction": "CANDIDATE_TO_REFERENCE",
            "expected_same_chain_comparison_count": 18,
        },
        {
            "relation_id": "characterization-2000-to-5000/1",
            "candidate_profile_id": "characterization_2000",
            "reference_profile_id": "characterization_5000",
            "comparison_direction": "CANDIDATE_TO_REFERENCE",
            "expected_same_chain_comparison_count": 18,
        },
    ]
    evidence_metric_registry = _evidence_registry()
    expected_cardinalities = _cardinalities()
    execution_identity = _profile_execution_identity(
        scenario_definitions_sha256=state.definitions_sha256,
        execution_source_manifest_sha256=execution_source_manifest[
            "profile_execution_source_manifest_sha256"
        ],
        worker_invocation_semantics_sha256=(
            profile_worker_invocation_semantics_digest(
                state.worker,
                timeout_seconds=state.timeout_seconds,
            )
        ),
        coordinates=coordinates,
        synthetic_event_bindings=synthetic_event_bindings,
        budgets=budgets,
        backend_identity=backend_identity,
        canonicalization=canonicalization_copy,
        execution_policy=execution_policy,
        logical_slots=logical_slots,
        budget_relations=budget_relations,
        evidence_metric_registry=evidence_metric_registry,
        expected_cardinalities=expected_cardinalities,
    )
    plan: dict[str, Any] = {
        "receipt_schema_version": "ebm-audit-profile-characterization-plan-receipt/3.0",
        "plan_state": "FIXED_PRE_EXECUTION_INTENT",
        "experiment_purpose": "COMPUTE_BUDGET_SELECTION_ONLY",
        "candidate": candidate_copy,
        "contract_sha256": contract_sha256,
        "source_provenance": source_provenance_copy,
        "execution_source_manifest": execution_source_manifest,
        "profile_execution_identity": execution_identity,
        "backend_identity": backend_identity,
        "backend_identity_digest": backend_identity_digest(backend_identity),
        "environment_digest": backend_identity["environment_digest"],
        "ordered_coordinates": coordinates,
        "ordered_synthetic_event_bindings": synthetic_event_bindings,
        "ordered_budgets": budgets,
        "execution_policy": execution_policy,
        "public_seed_policy": {
            "policy_schema_version": "ebm-audit-profile-public-seed-policy/2.0",
            "derivation_id": _PROFILE_PUBLIC_SEED_DERIVATION_ID,
            "domain": _PROFILE_PUBLIC_SEED_DOMAIN,
            "digest_algorithm": "SHA-256",
            "output_encoding": "FIRST_8_BYTES_BIG_ENDIAN_UINT64_HEX",
            "derivation_phase": "LIVE_EXECUTOR_AFTER_CASE_AUTHORITY",
            "caller_supplied_seed_material_allowed": False,
            "profile_execution_identity_sha256": execution_identity[
                "profile_execution_identity_sha256"
            ],
            "logical_slot_count": 18,
        },
        "ordered_logical_case_chain_slots": logical_slots,
        "ordered_budget_relations": budget_relations,
        "evidence_metric_registry": evidence_metric_registry,
        "expected_cardinalities": expected_cardinalities,
        "selection_policy": _selection_policy(),
        "canonicalization": canonicalization_copy,
        "command": ["ebm-audit", "plan", "profile-characterization"],
        "completed_at_utc": plan_completed_at_utc,
        "profile_characterization_plan_receipt_sha256": None,
    }
    plan["profile_characterization_plan_receipt_sha256"] = structured_sha256_hex(
        _PROFILE_PLAN_DOMAIN,
        plan,
    )
    diagnostic: dict[str, Any] = {
        "diagnostic_schema_version": "ebm-audit-blocked-profile-diagnostic/2.0",
        "profile_characterization_plan_receipt_sha256": plan[
            "profile_characterization_plan_receipt_sha256"
        ],
        "phase": "PRE_EXECUTION",
        "execution_state": "NOT_STARTED",
        "assessment_state": "NOT_AVAILABLE",
        "ordered_blocker_codes": [
            "MISSING_LIVE_PROFILE_EXECUTOR",
            "MISSING_AUTHORITATIVE_PROFILE_EVIDENCE_RESOLVER",
        ],
        "required_next_capabilities": [
            "LIVE_PROFILE_EXECUTOR",
            "AUTHORITATIVE_PROFILE_EVIDENCE_RESOLVER",
        ],
        "terminal_status": "BLOCKED",
        "completed_at_utc": diagnostic_completed_at_utc,
        "blocked_profile_diagnostic_sha256": None,
    }
    diagnostic["blocked_profile_diagnostic_sha256"] = structured_sha256_hex(
        _BLOCKED_DIAGNOSTIC_DOMAIN,
        diagnostic,
    )
    graph = {
        "plan_receipt": plan,
        "blocked_diagnostic": diagnostic,
    }
    _audit_profile_characterization_plan_authority_bound(
        plan_receipt=graph["plan_receipt"],
        blocked_diagnostic=graph["blocked_diagnostic"],
        authenticated_worker_binding=_authenticated_worker_binding(state),
    )
    if provenance_owner is not None:
        if provenance_state is None:
            _reject()
        _require_profile_plan_provenance_current(
            provenance_owner,
            provenance_state,
        )
    _require_authority(authority, state)
    owner = _OWNERSHIP.publish_plan(
        authority=authority,
        plan_identity=_plan_content_identity(state, graph),
        plan_receipt_bytes=canonical_json_bytes(graph["plan_receipt"]),
        blocked_diagnostic_bytes=canonical_json_bytes(graph["blocked_diagnostic"]),
        provenance_owner=provenance_owner,
        provenance_state=provenance_state,
    )
    _read_sealed_profile_characterization_plan(owner)
    return owner


def issue_profile_characterization_plan(
    authority: ProfileCharacterizationAuthority,
    *,
    provenance_owner: ProfilePlanProvenance,
    canonicalization: Mapping[str, Any],
    plan_completed_at_utc: str,
    diagnostic_completed_at_utc: str,
) -> SealedProfileCharacterizationPlan:
    """Issue one material Plan from exact locally derived provenance."""

    provenance_state = _consume_profile_plan_provenance(provenance_owner)
    return _issue_profile_characterization_plan_from_material(
        authority,
        candidate=provenance_state.candidate,
        contract_sha256=provenance_state.contract_sha256,
        source_provenance=provenance_state.source_provenance,
        execution_source_manifest_preimage=(provenance_state.execution_source_manifest_preimage),
        canonicalization=canonicalization,
        plan_completed_at_utc=plan_completed_at_utc,
        diagnostic_completed_at_utc=diagnostic_completed_at_utc,
        provenance_owner=provenance_owner,
        provenance_state=provenance_state,
    )


def _issue_profile_characterization_plan_for_test(
    authority: ProfileCharacterizationAuthority,
    *,
    candidate: Mapping[str, Any],
    contract_sha256: str,
    source_provenance: Mapping[str, Any],
    execution_source_manifest_preimage: Mapping[str, Any],
    canonicalization: Mapping[str, Any],
    plan_completed_at_utc: str,
    diagnostic_completed_at_utc: str,
) -> SealedProfileCharacterizationPlan:
    """Issue a non-material structural fixture that the real runner rejects."""

    return _issue_profile_characterization_plan_from_material(
        authority,
        candidate=candidate,
        contract_sha256=contract_sha256,
        source_provenance=source_provenance,
        execution_source_manifest_preimage=execution_source_manifest_preimage,
        canonicalization=canonicalization,
        plan_completed_at_utc=plan_completed_at_utc,
        diagnostic_completed_at_utc=diagnostic_completed_at_utc,
        provenance_owner=None,
        provenance_state=None,
    )


def _require_profile_characterization_plan_provenance_current(
    owner: SealedProfileCharacterizationPlan,
) -> _ConsumedProfilePlanProvenance:
    """Reattest the exact clean candidate retained by one material Plan."""

    state = _read_sealed_profile_characterization_plan(owner)
    if state.provenance_owner is None or state.provenance_state is None:
        raise TypeError(
            "A material profile-characterization plan with exact provenance is required."
        )
    current = _require_profile_plan_provenance_current(
        state.provenance_owner,
        state.provenance_state,
    )
    _OWNERSHIP.require_plan(owner, state)
    return current


__all__ = [
    "ProfileCharacterizationAuthority",
    "ProfileCharacterizationAuthorityError",
    "ProfilePlanProvenance",
    "SealedProfileCharacterizationPlan",
    "audit_profile_characterization_plan",
    "authenticate_profile_characterization_authority",
    "derive_profile_public_seed",
    "issue_profile_characterization_plan",
    "profile_worker_invocation_semantics_digest",
    "project_profile_characterization_plan",
]
