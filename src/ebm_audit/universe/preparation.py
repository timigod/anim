"""Authority-owned PreparationReceipt/2 and UniverseSpec/3 transaction.

The only public input to this module is a genuine :class:`PlanningAuthority`.
Rows, arrays, seeds, outcomes, reasons, registries, digests, replay evidence,
and universe identities are all rebuilt behind that authority boundary.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import stat
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Lock, RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, SupportsIndex, cast, final
from weakref import ReferenceType, WeakKeyDictionary, ref

import numpy as np
from numpy.typing import NDArray

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.data import (
    CanonicalDataset,
    ComponentDigests,
    build_identity_map,
    compute_source_table_content_digest,
    ingest_exact_file_audit_dataset,
    validate_canonical_dataset,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import (
    canonical_json_bytes,
    settings_schema_digest,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.schema import SchemaValidationError, load_protocol_registry, validate_instance
from ebm_audit.workers.arrays import array_catalog_entry

from ._influence_receipt import (
    _InfluencePreparationInputReceipt,
    _issue_influence_preparation_input_receipt,
    _read_influence_preparation_input_receipt,
)
from .identities import (
    UniverseIdentityError,
    _canonical_reason_rows,
    _expected_chain_seed,
    _expected_operation_seed,
    _expected_subsample_retained_count,
    _plan_preimage,
    _private_evaluation_membership_digest,
    _PrivateMembership,
    _PrivateOperationInstance,
    _PrivatePreparationReplayState,
    _receipt_preimage,
    _role_counts_from_instances,
    _role_counts_from_membership,
    _universe_preimage,
    _verify_plan_seed_collisions,
    _verify_preparation_aggregate_counts,
    _verify_preparation_record_rules,
    analysis_plan_digest,
    chain_execution_id,
    preparation_receipt_digest,
    preparation_rule_registry_digest,
    universe_id,
)
from .planning import (
    _FIXED_EVENT_RESCALE_SETTINGS_SCHEMA,
    PlanningAuthority,
    _assert_planning_description_states_current,
    _PlanningAuthorityState,
    _PreparationPublication,
    _rebuild_plan_from_state,
    _scan_private_tokens,
    _worker_owner_for_state,
)

if TYPE_CHECKING:
    from ebm_audit.adapters.invocation import AuthenticatedWorkerDescription
    from ebm_audit.config import RunEligibleAuditConfig
    from ebm_audit.data import PreparedAuditDataset
    from ebm_audit.data.preparation import _PreparedPrivateState
    from ebm_audit.evaluator.profile_characterization import SealedProfileCharacterizationPlan
    from ebm_audit.profile_input_identity import (
        ProfileGeneratedInputBinding,
        _ProfileGeneratedInputBindingState,
    )

type _ProtocolArray = (
    NDArray[np.bool_] | NDArray[np.int32] | NDArray[np.int64] | NDArray[np.float64]
)

_ALL_OPERATION_KINDS = ["ordinary", "bootstrap", "subsample", "influence", "null"]
_INVALID_REASON = "PREPARATION.CANONICAL_DATA_INVALID"
_SUBSAMPLE_ALLOCATION_INVALID_REASON = "PREPARATION.STRATIFIED_SUBSAMPLE_ALLOCATION_INFEASIBLE"
_SUBSAMPLE_ALLOCATION_RULE_ID = "global-floor-minimum-constrained-hamilton/1"
_UNSUPPORTED_REASONS = frozenset(
    {
        "PREPARATION.COMPLETE_CASE_ROW_LOSS_UNSUPPORTED",
        "PREPARATION.COVARIATE_ADJUSTMENT_UNSUPPORTED",
        "PREPARATION.EXTERNAL_VARIANT_UNSUPPORTED",
        "PREPARATION.INFLUENCE_REMOVAL_UNSUPPORTED",
        "PREPARATION.NAMED_GROUP_REMOVAL_UNSUPPORTED",
        "PREPARATION.NULL_TRANSFORMATION_UNSUPPORTED",
        "PREPARATION.OPERATION_UNSUPPORTED",
        "PREPARATION.OUTLIER_POLICY_UNSUPPORTED",
        "PREPARATION.PREPROCESSING_UNSUPPORTED",
    }
)
_PREPARATION_RULE_REGISTRY: dict[str, Any] = {
    "registry_schema_version": "ebm-audit-preparation-rule-registry/1.0",
    "ordered_rules": [
        {
            "rule_id": "preparation.capability/1",
            "operation_kinds": _ALL_OPERATION_KINDS,
            "states": ["PREPARATION_INVALID", "PREPARATION_UNSUPPORTED"],
            "allowed_reason_codes": sorted(_UNSUPPORTED_REASONS),
            "required_when_applicable": False,
        },
        {
            "rule_id": "preparation.complete/1",
            "operation_kinds": _ALL_OPERATION_KINDS,
            "states": ["PREPARED"],
            "allowed_reason_codes": [],
            "required_when_applicable": True,
        },
        {
            "rule_id": "preparation.stratified-subsample-allocation/1",
            "operation_kinds": ["subsample"],
            "states": ["PREPARATION_INVALID"],
            "allowed_reason_codes": [_SUBSAMPLE_ALLOCATION_INVALID_REASON],
            "required_when_applicable": False,
        },
        {
            "rule_id": "preparation.validity/1",
            "operation_kinds": _ALL_OPERATION_KINDS,
            "states": ["PREPARATION_INVALID"],
            "allowed_reason_codes": [_INVALID_REASON],
            "required_when_applicable": False,
        },
    ],
}
_PREPARATION_RULE_REGISTRY_DIGEST = preparation_rule_registry_digest(_PREPARATION_RULE_REGISTRY)
_STAGE_TRANSITION_RULE_ID = "declared-stage-transition-private-replay/2"
_PLAN_INVALID_REASON_CODES = frozenset(
    {"PLAN.EVENT_COUNT_BELOW_TWO", "PLAN.EVENT_DIRECTIONS_UNRESOLVED"}
)
_PLAN_UNSUPPORTED_REASON_CODE = "PLAN.MCMC_UNAVAILABLE_FOR_MVP"
_FIXED_EVENT_RESCALE_METHOD_ID = "fixed-event-rescale-v1"
_FIXED_EVENT_RESCALE_FACTOR = 2.0


@dataclass(frozen=True, repr=False)
class _PreparedExecutionOrigin:
    route: str
    owner: object | None
    profile_candidate_ordinal: int | None
    profile_execution_identity_sha256: str | None
    profile_chain_seeds: tuple[str, ...] | None


_ORDINARY_EXECUTION_ORIGIN = _PreparedExecutionOrigin(
    route="ORDINARY",
    owner=None,
    profile_candidate_ordinal=None,
    profile_execution_identity_sha256=None,
    profile_chain_seeds=None,
)


def _resolve_public_synthetic_execution_origin(
    authorized_config: RunEligibleAuditConfig,
    prepared_dataset: PreparedAuditDataset,
) -> _PreparedExecutionOrigin:
    from ebm_audit.synthetic.audit_input import (
        _resolve_public_synthetic_preparation_owner,
    )

    owner = _resolve_public_synthetic_preparation_owner(
        authorized_config,
        prepared_dataset,
    )
    if owner is None:
        return _ORDINARY_EXECUTION_ORIGIN
    return _PreparedExecutionOrigin(
        route="PUBLIC_SYNTHETIC",
        owner=owner,
        profile_candidate_ordinal=None,
        profile_execution_identity_sha256=None,
        profile_chain_seeds=None,
    )


@dataclass(frozen=True, repr=False)
class _ConformanceDemoProvenance:
    """Validated D08 provenance available only to the built-in demo route."""

    record_bytes: bytes


def _conformance_demo_provenance(value: Mapping[str, Any]) -> _ConformanceDemoProvenance:
    record = _canonical_copy(value)
    try:
        validate_instance(
            record,
            "worker-protocol.schema.json",
            definition="SyntheticProvenance",
        )
    except SchemaValidationError:
        raise UniverseIdentityError("The conformance demo provenance is invalid.") from None
    return _ConformanceDemoProvenance(canonical_json_bytes(record))


class _CandidatePreparationInvalid(Exception):
    """Internal typed branch for a data-valid but unrealizable candidate operation."""


_TRANSFORMED_NULL_METHOD_IDS = frozenset(
    {
        "label-permutation/1",
        "featurewise-within-group-participant-permutation/1",
        "pure-no-signal-synthetic/1",
    }
)
_TRANSFORMED_NULL_MAX_ATTEMPTS = 256


@dataclass(frozen=True, repr=False)
class _TransformedNullPlan:
    """One exact private transformed-null map and its derived memberships."""

    attempt_ordinal: int
    method_id: str
    source_membership: tuple[_PrivateMembership, ...]
    transformed_membership: tuple[_PrivateMembership, ...]
    transformed_instances: tuple[_PrivateOperationInstance, ...]
    label_source_positions: tuple[int, ...] | None
    event_source_positions: tuple[tuple[int, ...], ...] | None
    generated_values: NDArray[np.float64] | None
    moved_label_count: int
    moved_cell_count: int
    changed_value_cell_count: int
    changed_participant_count: int
    changed_event_ordinals: tuple[int, ...]
    participant_event_alignment_changed: bool


@dataclass(frozen=True, repr=False)
class _StratifiedSubsamplePlan:
    """One replayable constrained-Hamilton allocation and no-replacement draw."""

    retained_total: int
    reference_minimum: int
    at_risk_minimum: int
    reference_lower: int
    reference_upper: int
    reference_hamilton_quota: int
    at_risk_hamilton_quota: int
    reference_quota: int
    at_risk_quota: int
    instances: tuple[_PrivateOperationInstance, ...]
    retained_membership: tuple[_PrivateMembership, ...]


def _resolve_private_prepared_dataset(value: object) -> _PreparedPrivateState:
    """Cross the data authority boundary only after package initialization."""

    from ebm_audit.data.preparation import _private_prepared_dataset

    return _private_prepared_dataset(value)


def _closed_object(value: bytes) -> dict[str, Any]:
    loaded = strict_json_loads(value)
    if type(loaded) is not dict:
        raise TypeError("Sealed preparation storage is invalid.")
    return cast(dict[str, Any], loaded)


def _canonical_copy(value: object) -> Any:
    """Copy closed JSON material without invoking object copy hooks."""

    def thaw(item: object) -> object:
        if isinstance(item, Mapping):
            return {key: thaw(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [thaw(child) for child in item]
        return item

    return strict_json_loads(canonical_json_bytes(thaw(value)))


def _validate_schema(value: object, definition: str) -> None:
    try:
        validate_instance(value, "analysis-universe.schema.json", definition=definition)
    except SchemaValidationError:
        raise UniverseIdentityError(
            "Preparation authority produced an invalid closed record."
        ) from None


def _freeze_array(value: object, *, dtype: np.dtype[Any]) -> _ProtocolArray:
    """Copy one array into immutable little-endian, C-contiguous byte storage."""

    array = np.asarray(value, dtype=dtype)
    canonical_dtype = np.dtype(array.dtype.name)
    if canonical_dtype.byteorder not in ("|", "<"):
        canonical_dtype = canonical_dtype.newbyteorder("<")
    canonical = np.ascontiguousarray(array, dtype=canonical_dtype)
    raw = bytes(canonical.tobytes(order="C"))
    frozen = np.frombuffer(raw, dtype=canonical_dtype).reshape(canonical.shape)
    frozen.flags.writeable = False
    return cast(_ProtocolArray, frozen)


def _arrays_are_exactly_frozen(arrays: Mapping[str, _ProtocolArray]) -> bool:
    expected = {
        "evaluation_group_codes": "int32",
        "evaluation_row_indexes": "int64",
        "evaluation_values": "float64",
        "train_group_codes": "int32",
        "train_values": "float64",
        "training_row_indexes": "int64",
    }
    return (
        type(arrays) is MappingProxyType
        and set(arrays) == set(expected)
        and all(
            type(array) is np.ndarray
            and array.dtype.name == expected[name]
            and array.flags.c_contiguous
            and not array.flags.writeable
            for name, array in arrays.items()
        )
    )


@dataclass(frozen=True, repr=False)
class _PreparedExecutionAuthorizationState:
    plan_bytes: bytes
    planning_summary_binding_bytes: bytes
    receipt_bytes: bytes
    record_bytes: bytes
    universe_bytes: bytes
    analysis_spec_bytes: bytes
    dataset_projection_bytes: bytes
    config_digest: str
    prepared_dataset_id: str
    prepared_dataset: object
    data_identity_digest: str
    protocol_identity_digest: str
    worker_identity_digest: str
    selected_algorithm_binding_bytes: bytes
    master_seed: str
    authenticated_description: AuthenticatedWorkerDescription
    authenticated_description_state: object
    authenticated_description_readback: object
    arrays: Mapping[str, _ProtocolArray]
    canonical_dataset: CanonicalDataset
    private_replay: _PrivatePreparationReplayState
    private_replay_identity_digest: str
    execution_origin: _PreparedExecutionOrigin


_PREPARED_AUTHORIZATION_STATES: OneShotWeakRegistry[object, _PreparedExecutionAuthorizationState]
_PREPARED_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _PreparedExecutionAuthorizationState
]
(
    _PREPARED_AUTHORIZATION_STATES,
    _PREPARED_AUTHORIZATION_STATE_ISSUER,
) = create_one_shot_registry()


@final
class PreparedExecutionAuthorization:
    """Opaque authority for one exact PREPARED Plan/3 candidate."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PreparedExecutionAuthorization:
        raise TypeError("Prepared execution authorizations come from PlanningAuthority.prepare().")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Prepared execution authorizations cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Prepared execution authorizations are immutable.")

    @property
    def plan_digest(self) -> str:
        state = _resolve_prepared_execution_authorization(self)
        return str(_closed_object(state.plan_bytes)["plan_digest"])

    @property
    def receipt_digest(self) -> str:
        return str(
            _closed_object(_resolve_prepared_execution_authorization(self).receipt_bytes)[
                "receipt_digest"
            ]
        )

    @property
    def candidate_ordinal(self) -> int:
        return int(
            _closed_object(_resolve_prepared_execution_authorization(self).record_bytes)[
                "candidate_ordinal"
            ]
        )

    @property
    def candidate_id(self) -> str:
        return str(
            _closed_object(_resolve_prepared_execution_authorization(self).record_bytes)[
                "candidate_id"
            ]
        )

    @property
    def analysis_spec_id(self) -> str:
        return str(
            _closed_object(_resolve_prepared_execution_authorization(self).record_bytes)[
                "analysis_spec_id"
            ]
        )

    @property
    def universe_id(self) -> str:
        return str(
            _closed_object(_resolve_prepared_execution_authorization(self).universe_bytes)[
                "universe_id"
            ]
        )

    @property
    def universe_spec(self) -> dict[str, Any]:
        return _closed_object(_resolve_prepared_execution_authorization(self).universe_bytes)

    @property
    def config_digest(self) -> str:
        return _resolve_prepared_execution_authorization(self).config_digest

    @property
    def prepared_dataset_id(self) -> str:
        return _resolve_prepared_execution_authorization(self).prepared_dataset_id

    @property
    def data_identity_digest(self) -> str:
        return _resolve_prepared_execution_authorization(self).data_identity_digest

    @property
    def protocol_identity_digest(self) -> str:
        return _resolve_prepared_execution_authorization(self).protocol_identity_digest

    @property
    def worker_identity_digest(self) -> str:
        return _resolve_prepared_execution_authorization(self).worker_identity_digest

    def __copy__(self) -> PreparedExecutionAuthorization:
        raise TypeError("Prepared execution authorizations cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> PreparedExecutionAuthorization:
        raise TypeError("Prepared execution authorizations cannot be copied.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Prepared execution authorizations cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Prepared execution authorizations cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Prepared execution authorizations cannot be serialized.")

    def __repr__(self) -> str:
        _resolve_prepared_execution_authorization(self)
        return "PreparedExecutionAuthorization(<sealed-prepared-candidate>)"


def _resolve_prepared_execution_authorization(
    value: object,
) -> _PreparedExecutionAuthorizationState:
    """Resolve exact private state for trusted sibling core modules only."""

    state: _PreparedExecutionAuthorizationState | None = None
    if type(value) is PreparedExecutionAuthorization:
        try:
            state = _PREPARED_AUTHORIZATION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _PreparedExecutionAuthorizationState:
        raise TypeError("A genuine prepared execution authorization is required.")
    _revalidate_prepared_authorization_state(state)
    return state


def _resolve_ordinary_prepared_execution_authorization(
    value: object,
) -> _PreparedExecutionAuthorizationState:
    """Resolve only an ordinary candidate for the ordinary invocation path."""

    state: _PreparedExecutionAuthorizationState | None = None
    if type(value) is PreparedExecutionAuthorization:
        try:
            state = _PREPARED_AUTHORIZATION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _PreparedExecutionAuthorizationState:
        raise TypeError("A genuine prepared execution authorization is required.")
    if state.execution_origin.route == "PROFILE":
        raise TypeError("Profile prepared candidates cannot enter ordinary worker invocation.")
    _revalidate_prepared_authorization_state(state)
    return state


@dataclass(frozen=True, repr=False)
class _UnpreparedResultAuthorizationState:
    plan_bytes: bytes
    planning_summary_binding_bytes: bytes
    dataset_summary_bytes: bytes
    receipt_bytes: bytes
    record_bytes: bytes
    master_seed: str
    config_digest: str
    scientific_data_preimage_bytes: bytes | None
    input_digest: str | None
    source_byte_digest: str
    prepared_dataset_id: str
    prepared_dataset: object
    preparation_namespace_key: object


_UNPREPARED_RESULT_AUTHORIZATION_STATES: OneShotWeakRegistry[
    object, _UnpreparedResultAuthorizationState
]
_UNPREPARED_RESULT_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _UnpreparedResultAuthorizationState
]
(
    _UNPREPARED_RESULT_AUTHORIZATION_STATES,
    _UNPREPARED_RESULT_AUTHORIZATION_STATE_ISSUER,
) = create_one_shot_registry()


@final
class UnpreparedResultAuthorization:
    """Opaque authority for one exact non-PREPARED candidate result."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> UnpreparedResultAuthorization:
        raise TypeError("Unprepared result authorizations come from PlanningAuthority.prepare().")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Unprepared result authorizations cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Unprepared result authorizations are immutable.")

    @property
    def plan_digest(self) -> str:
        state = _resolve_unprepared_result_authorization(self)
        return cast(str, _closed_object(state.plan_bytes)["plan_digest"])

    @property
    def receipt_digest(self) -> str:
        state = _resolve_unprepared_result_authorization(self)
        return cast(str, _closed_object(state.receipt_bytes)["receipt_digest"])

    @property
    def candidate_ordinal(self) -> int:
        state = _resolve_unprepared_result_authorization(self)
        return cast(int, _closed_object(state.record_bytes)["candidate_ordinal"])

    @property
    def candidate_id(self) -> str:
        state = _resolve_unprepared_result_authorization(self)
        return cast(str, _closed_object(state.record_bytes)["candidate_id"])

    @property
    def analysis_spec_id(self) -> str:
        state = _resolve_unprepared_result_authorization(self)
        return cast(str, _closed_object(state.record_bytes)["analysis_spec_id"])

    @property
    def preparation_state(self) -> str:
        state = _resolve_unprepared_result_authorization(self)
        return cast(str, _closed_object(state.record_bytes)["state"])

    @property
    def operation_seed(self) -> str | None:
        state = _resolve_unprepared_result_authorization(self)
        return cast(str | None, _closed_object(state.record_bytes)["operation_seed"])

    @property
    def preparation_reasons(self) -> tuple[dict[str, str], ...]:
        state = _resolve_unprepared_result_authorization(self)
        record = _closed_object(state.record_bytes)
        return tuple(copy.deepcopy(cast(list[dict[str, str]], record["reasons"])))

    @property
    def terminal_status(self) -> str:
        state = _resolve_unprepared_result_authorization(self)
        return _unprepared_terminal_status(_closed_object(state.record_bytes))

    @property
    def config_digest(self) -> str:
        return _resolve_unprepared_result_authorization(self).config_digest

    @property
    def input_digest(self) -> str | None:
        return _resolve_unprepared_result_authorization(self).input_digest

    def __copy__(self) -> UnpreparedResultAuthorization:
        raise TypeError("Unprepared result authorizations cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> UnpreparedResultAuthorization:
        raise TypeError("Unprepared result authorizations cannot be copied.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Unprepared result authorizations cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Unprepared result authorizations cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Unprepared result authorizations cannot be serialized.")

    def __repr__(self) -> str:
        _resolve_unprepared_result_authorization(self)
        return "UnpreparedResultAuthorization(<sealed-unprepared-candidate>)"


def _resolve_unprepared_result_authorization(
    value: object,
) -> _UnpreparedResultAuthorizationState:
    """Resolve exact non-execution state for trusted sibling core modules."""

    state: _UnpreparedResultAuthorizationState | None = None
    if type(value) is UnpreparedResultAuthorization:
        try:
            state = _UNPREPARED_RESULT_AUTHORIZATION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _UnpreparedResultAuthorizationState:
        raise TypeError("A genuine unprepared result authorization is required.")
    _revalidate_unprepared_result_authorization_state(state)
    return state


type CandidateResultAuthorization = PreparedExecutionAuthorization | UnpreparedResultAuthorization


@dataclass(frozen=True, repr=False)
class _PreparationTransactionState:
    plan_bytes: bytes
    receipt_bytes: bytes
    influence_input_receipt: _InfluencePreparationInputReceipt
    master_seed: str
    publication_token: object
    authorizations: tuple[PreparedExecutionAuthorization, ...]
    unprepared_authorizations: tuple[UnpreparedResultAuthorization, ...]
    candidate_authorizations: tuple[CandidateResultAuthorization, ...]


_PREPARATION_TRANSACTION_STATES: OneShotWeakRegistry[object, _PreparationTransactionState]
_PREPARATION_TRANSACTION_STATE_ISSUER: OneShotRegistryIssuer[object, _PreparationTransactionState]
(
    _PREPARATION_TRANSACTION_STATES,
    _PREPARATION_TRANSACTION_STATE_ISSUER,
) = create_one_shot_registry()


type _CandidateAuthorizationState = (
    _PreparedExecutionAuthorizationState | _UnpreparedResultAuthorizationState
)


def _resolve_live_candidate_authorization(
    authorization: CandidateResultAuthorization,
) -> _CandidateAuthorizationState:
    if type(authorization) is PreparedExecutionAuthorization:
        return _resolve_prepared_execution_authorization(authorization)
    if type(authorization) is UnpreparedResultAuthorization:
        return _resolve_unprepared_result_authorization(authorization)
    raise TypeError("Preparation transaction contains an invalid candidate capability.")


def _capture_preparation_transaction_candidate_states(
    state: _PreparationTransactionState,
) -> tuple[_CandidateAuthorizationState, ...]:
    """Capture the exact ordered candidate registry states for one transaction state."""

    if type(state) is not _PreparationTransactionState:
        raise TypeError("A genuine preparation transaction state is required.")
    captured = tuple(
        _resolve_live_candidate_authorization(authorization)
        for authorization in state.candidate_authorizations
    )
    _assert_preparation_transaction_candidate_states_current(state, captured)
    return captured


def _capture_public_synthetic_preparation_binding(
    value: object,
) -> dict[str, str] | None:
    """Derive one public-synthetic case binding from a live full transaction."""

    if type(value) is not PreparationTransaction:
        raise TypeError("A genuine preparation transaction is required.")
    transaction_state = value._state()
    candidate_states = _capture_preparation_transaction_candidate_states(transaction_state)
    owners = {
        candidate_state.execution_origin.owner
        for candidate_state in candidate_states
        if type(candidate_state) is _PreparedExecutionAuthorizationState
        and candidate_state.execution_origin.route == "PUBLIC_SYNTHETIC"
    }
    prepared_states = tuple(
        candidate_state
        for candidate_state in candidate_states
        if type(candidate_state) is _PreparedExecutionAuthorizationState
    )
    if not prepared_states or all(
        candidate_state.execution_origin == _ORDINARY_EXECUTION_ORIGIN
        for candidate_state in prepared_states
    ):
        return None
    if (
        len(owners) != 1
        or any(
            candidate_state.execution_origin.route != "PUBLIC_SYNTHETIC"
            for candidate_state in prepared_states
        )
    ):
        raise TypeError("Preparation transaction has no exact public-synthetic owner.")
    owner = owners.pop()
    from ebm_audit.synthetic.audit_input import (
        _resolve_public_synthetic_preparation_binding,
    )

    retained_binding_bytes: bytes | None = None
    for candidate_state in prepared_states:
        if candidate_state.execution_origin.owner is not owner:
            raise TypeError("Public-synthetic preparation ownership changed.")
        binding_bytes = _resolve_public_synthetic_preparation_binding(
            owner,
            cast("PreparedAuditDataset", candidate_state.prepared_dataset),
            candidate_state.config_digest,
        )
        if binding_bytes is None:
            raise TypeError("Public-synthetic preparation ownership changed.")
        if retained_binding_bytes is None:
            retained_binding_bytes = binding_bytes
        elif retained_binding_bytes != binding_bytes:
            raise TypeError("Public-synthetic preparation ownership changed.")
    binding = strict_json_loads(retained_binding_bytes or b"")
    if (
        type(binding) is not dict
        or canonical_json_bytes(binding) != retained_binding_bytes
        or set(binding)
        != {
            "case_id",
            "source_contract_sha256",
            "scenario_definitions_sha256",
        }
        or any(type(item) is not str for item in binding.values())
    ):
        raise TypeError("Public-synthetic preparation binding is invalid.")
    return cast(dict[str, str], binding)


def _capture_preparation_transaction_state_identity(
    value: object,
) -> _PreparationTransactionState:
    """Capture a transaction's one-shot state without replaying validated semantics."""

    if type(value) is not PreparationTransaction:
        raise TypeError("A genuine preparation transaction is required.")
    try:
        state = _PREPARATION_TRANSACTION_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine preparation transaction is required.") from None
    if type(state) is not _PreparationTransactionState:
        raise TypeError("A genuine preparation transaction is required.")
    _PREPARATION_TRANSACTION_STATES.require(value, state)
    return state


def _capture_preparation_transaction_candidate_state_identities(
    state: _PreparationTransactionState,
) -> tuple[_CandidateAuthorizationState, ...]:
    """Capture candidate registry identities after the transaction boundary validated them."""

    if type(state) is not _PreparationTransactionState:
        raise TypeError("A genuine preparation transaction state is required.")
    captured: list[_CandidateAuthorizationState] = []
    for authorization in state.candidate_authorizations:
        candidate_state: _CandidateAuthorizationState
        if type(authorization) is PreparedExecutionAuthorization:
            try:
                candidate_state = _PREPARED_AUTHORIZATION_STATES[authorization]
            except (KeyError, TypeError):
                raise TypeError("Preparation transaction candidate state changed.") from None
            if type(candidate_state) is not _PreparedExecutionAuthorizationState:
                raise TypeError("Preparation transaction candidate state changed.")
            _PREPARED_AUTHORIZATION_STATES.require(authorization, candidate_state)
        elif type(authorization) is UnpreparedResultAuthorization:
            try:
                candidate_state = _UNPREPARED_RESULT_AUTHORIZATION_STATES[authorization]
            except (KeyError, TypeError):
                raise TypeError("Preparation transaction candidate state changed.") from None
            if type(candidate_state) is not _UnpreparedResultAuthorizationState:
                raise TypeError("Preparation transaction candidate state changed.")
            _UNPREPARED_RESULT_AUTHORIZATION_STATES.require(
                authorization,
                candidate_state,
            )
        else:
            raise TypeError("Preparation transaction contains an invalid candidate capability.")
        captured.append(candidate_state)
    retained = tuple(captured)
    _require_preparation_transaction_candidate_state_identities_current(
        state,
        retained,
    )
    return retained


def _require_preparation_transaction_candidate_state_identities_current(
    state: _PreparationTransactionState,
    candidate_states: tuple[_CandidateAuthorizationState, ...],
) -> None:
    """Require exact one-shot candidate bindings without replaying their semantics."""

    if (
        type(state) is not _PreparationTransactionState
        or type(candidate_states) is not tuple
        or len(candidate_states) != len(state.candidate_authorizations)
    ):
        raise TypeError("Preparation transaction candidate-state coverage is invalid.")
    for authorization, candidate_state in zip(
        state.candidate_authorizations,
        candidate_states,
        strict=True,
    ):
        if (
            type(authorization) is PreparedExecutionAuthorization
            and type(candidate_state) is _PreparedExecutionAuthorizationState
        ):
            try:
                _PREPARED_AUTHORIZATION_STATES.require(
                    authorization,
                    candidate_state,
                )
            except (KeyError, TypeError):
                raise TypeError("Preparation transaction candidate state changed.") from None
        elif (
            type(authorization) is UnpreparedResultAuthorization
            and type(candidate_state) is _UnpreparedResultAuthorizationState
        ):
            try:
                _UNPREPARED_RESULT_AUTHORIZATION_STATES.require(
                    authorization,
                    candidate_state,
                )
            except (KeyError, TypeError):
                raise TypeError("Preparation transaction candidate state changed.") from None
        else:
            raise TypeError("Preparation transaction candidate state changed.")


def _assert_preparation_transaction_candidate_states_current(
    state: _PreparationTransactionState,
    candidate_states: tuple[_CandidateAuthorizationState, ...],
) -> None:
    """Use retained states for semantics and live registries only as identity guards."""

    if (
        type(state) is not _PreparationTransactionState
        or type(candidate_states) is not tuple
        or len(candidate_states) != len(state.candidate_authorizations)
    ):
        raise TypeError("Preparation transaction candidate-state coverage is invalid.")
    retained = {
        authorization: candidate_state
        for authorization, candidate_state in zip(
            state.candidate_authorizations,
            candidate_states,
            strict=True,
        )
    }

    def resolve_retained(
        authorization: CandidateResultAuthorization,
    ) -> _CandidateAuthorizationState:
        try:
            candidate_state = retained[authorization]
        except KeyError:
            raise TypeError(
                "Preparation transaction candidate-state coverage is invalid."
            ) from None
        if _resolve_live_candidate_authorization(authorization) is not candidate_state:
            raise TypeError("Preparation transaction candidate state changed.")
        return candidate_state

    _validate_preparation_transaction_state(state, resolve_retained)


def _validate_preparation_transaction_state(
    state: _PreparationTransactionState,
    resolve_authorization: Callable[
        [CandidateResultAuthorization],
        _CandidateAuthorizationState,
    ],
) -> None:
    """Validate complete transaction coverage against live or provisional states."""

    if type(state) is not _PreparationTransactionState or state.publication_token is None:
        raise TypeError("A genuine preparation transaction is required.")
    plan = _closed_object(state.plan_bytes)
    receipt = _closed_object(state.receipt_bytes)
    influence_input = _read_influence_preparation_input_receipt(state.influence_input_receipt)
    _verify_receipt(receipt, plan, state.master_seed)
    records = tuple(cast(Sequence[Mapping[str, Any]], receipt["records"]))
    if (
        influence_input.plan_bytes != state.plan_bytes
        or influence_input.preparation_receipt_bytes != state.receipt_bytes
        or influence_input.plan_digest != plan["plan_digest"]
        or influence_input.preparation_receipt_digest != receipt["receipt_digest"]
        or influence_input.baseline_analysis_spec_id != plan["baseline_analysis_spec_id"]
        or influence_input.baseline_candidate_bytes
        != canonical_json_bytes(
            next(
                candidate
                for candidate in cast(
                    Sequence[Mapping[str, Any]],
                    plan["candidates"],
                )
                if candidate["analysis_spec_id"] == plan["baseline_analysis_spec_id"]
            )
        )
        or influence_input.plan_candidates_bytes != canonical_json_bytes(plan["candidates"])
        or influence_input.origin_comparison_edges_bytes
        != canonical_json_bytes(plan["origin_comparison_edges"])
        or len(records) != len(state.candidate_authorizations)
    ):
        raise TypeError("Preparation transaction capability coverage is incomplete.")
    seen_ordinals: set[int] = set()
    expected_prepared: list[PreparedExecutionAuthorization] = []
    expected_unprepared: list[UnpreparedResultAuthorization] = []
    for expected_record, authorization in zip(records, state.candidate_authorizations, strict=True):
        ordinal = cast(int, expected_record["candidate_ordinal"])
        authorization_state = resolve_authorization(authorization)
        if expected_record["state"] == "PREPARED":
            if (
                type(authorization) is not PreparedExecutionAuthorization
                or type(authorization_state) is not _PreparedExecutionAuthorizationState
            ):
                raise TypeError("A PREPARED record lacks its exact candidate capability.")
            expected_prepared.append(authorization)
        else:
            if (
                type(authorization) is not UnpreparedResultAuthorization
                or type(authorization_state) is not _UnpreparedResultAuthorizationState
            ):
                raise TypeError("An unprepared record lacks its exact candidate capability.")
            expected_unprepared.append(authorization)
        if (
            ordinal in seen_ordinals
            or authorization_state.plan_bytes != state.plan_bytes
            or authorization_state.receipt_bytes != state.receipt_bytes
            or _closed_object(authorization_state.record_bytes) != expected_record
        ):
            raise TypeError("Preparation transaction capability coverage is detached.")
        seen_ordinals.add(ordinal)
    if (
        len(expected_prepared) != len(state.authorizations)
        or any(
            observed is not expected
            for observed, expected in zip(
                expected_prepared,
                state.authorizations,
                strict=True,
            )
        )
        or len(expected_unprepared) != len(state.unprepared_authorizations)
        or any(
            observed is not expected
            for observed, expected in zip(
                expected_unprepared,
                state.unprepared_authorizations,
                strict=True,
            )
        )
    ):
        raise TypeError("Preparation transaction capability partitions are detached.")


@final
class PreparationTransaction:
    """Immutable public projection of one complete authority-owned transaction."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PreparationTransaction:
        raise TypeError("Preparation transactions come from PlanningAuthority.prepare().")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Preparation transactions cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Preparation transactions are immutable.")

    def _state(self) -> _PreparationTransactionState:
        try:
            state = _PREPARATION_TRANSACTION_STATES[self]
        except (KeyError, TypeError):
            raise TypeError("A genuine preparation transaction is required.") from None
        if type(state) is not _PreparationTransactionState:
            raise TypeError("A genuine preparation transaction is required.")
        _validate_preparation_transaction_state(
            state,
            _resolve_live_candidate_authorization,
        )
        return state

    @property
    def receipt(self) -> dict[str, Any]:
        return _closed_object(self._state().receipt_bytes)

    @property
    def receipt_digest(self) -> str:
        return str(self.receipt["receipt_digest"])

    @property
    def authorizations(self) -> tuple[PreparedExecutionAuthorization, ...]:
        return tuple(self._state().authorizations)

    @property
    def unprepared_authorizations(self) -> tuple[UnpreparedResultAuthorization, ...]:
        return tuple(self._state().unprepared_authorizations)

    @property
    def candidate_authorizations(self) -> tuple[CandidateResultAuthorization, ...]:
        """Return exactly one ordered opaque authority per Plan/3 candidate."""

        return tuple(self._state().candidate_authorizations)

    def authorization_for_candidate(self, candidate_ordinal: int) -> PreparedExecutionAuthorization:
        if type(candidate_ordinal) is not int:
            raise TypeError("Candidate ordinals are exact integers.")
        matches = [
            authorization
            for authorization in self._state().authorizations
            if authorization.candidate_ordinal == candidate_ordinal
        ]
        if len(matches) != 1:
            raise KeyError("That candidate has no prepared execution authorization.")
        return matches[0]

    def result_authorization_for_candidate(
        self, candidate_ordinal: int
    ) -> CandidateResultAuthorization:
        if type(candidate_ordinal) is not int:
            raise TypeError("Candidate ordinals are exact integers.")
        matches = [
            authorization
            for authorization in self._state().candidate_authorizations
            if authorization.candidate_ordinal == candidate_ordinal
        ]
        if len(matches) != 1:
            raise KeyError("That candidate has no exact result authorization.")
        return matches[0]

    def __copy__(self) -> PreparationTransaction:
        raise TypeError("Preparation transactions cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> PreparationTransaction:
        raise TypeError("Preparation transactions cannot be copied.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Preparation transactions cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Preparation transactions cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Preparation transactions cannot be serialized.")

    def __repr__(self) -> str:
        self._state()
        return "PreparationTransaction(<sealed-complete-receipt>)"


def _preparation_transaction_publication_token(value: object) -> object:
    """Return the exact planning-publication owner of a genuine transaction."""

    if type(value) is not PreparationTransaction:
        raise TypeError("A genuine preparation transaction is required.")
    return value._state().publication_token


def _derive_influence_preparation_binding_bytes(
    plan: Mapping[str, Any],
    candidate_states: tuple[_CandidateAuthorizationState, ...],
) -> tuple[bytes, ...]:
    """Seal privacy-safe influence bindings before transaction publication."""

    candidates = cast(Sequence[Mapping[str, Any]], plan["candidates"])
    if type(candidate_states) is not tuple or len(candidates) != len(candidate_states):
        raise TypeError("Influence preparation evidence coverage is invalid.")
    rows: list[bytes] = []
    for candidate, authorization_state in zip(
        candidates,
        candidate_states,
        strict=True,
    ):
        spec = cast(Mapping[str, Any], candidate["analysis_spec"])
        operation = cast(Mapping[str, Any], spec["operation_intent"])
        if operation["kind"] != "influence":
            continue
        record = _closed_object(authorization_state.record_bytes)
        removal_kind = cast(str, operation["removal_kind"])
        removal_slot = cast(int, operation["removal_slot_ordinal"])
        removed_aliases: tuple[str, ...] = ()
        fixed_evaluation_cohort_digest: str | None = None
        fixed_evaluation_cohort_count: int | None = None
        if type(authorization_state) is _PreparedExecutionAuthorizationState:
            replay = authorization_state.private_replay
            aliases = authorization_state.canonical_dataset.view.participant_aliases
            if (
                removal_kind != "leave-one-participant-out"
                or len(replay.removed_membership) != 1
                or replay.removed_membership[0].internal_row_index != removal_slot
                or removal_slot < 0
                or removal_slot >= len(aliases)
            ):
                raise TypeError("Prepared influence alias ownership is invalid.")
            removed_aliases = (aliases[removal_slot],)
            universe = _closed_object(authorization_state.universe_bytes)
            fixed_evaluation_cohort_digest = cast(
                str,
                universe["evaluation_membership_digest"],
            )
            fixed_evaluation_cohort_count = cast(
                int,
                universe["aggregate_counts"]["evaluation_participant_count"],
            )
        elif (
            type(authorization_state) is _UnpreparedResultAuthorizationState
            and removal_kind == "leave-one-participant-out"
        ):
            if authorization_state.input_digest is None:
                aliases = _source_participant_aliases(
                    authorization_state.prepared_dataset,
                    authorization_state.preparation_namespace_key,
                )
                identity_rows: Sequence[object] = ()
            else:
                try:
                    canonical, _prepared = _canonicalize_candidate_input(
                        authorization_state.prepared_dataset,
                        authorization_state.preparation_namespace_key,
                        candidate,
                        spec,
                    )
                except InvalidInputError:
                    raise TypeError(
                        "Unprepared influence alias ownership cannot be rebuilt."
                    ) from None
                aliases = canonical.view.participant_aliases
                identity_rows = canonical.private.identity_map.rows
            if (
                removal_slot < 0
                or removal_slot >= len(aliases)
                or (
                    identity_rows
                    and (
                        len(identity_rows) != len(aliases)
                        or getattr(
                            identity_rows[removal_slot],
                            "participant_internal_index",
                            None,
                        )
                        != removal_slot
                        or getattr(
                            identity_rows[removal_slot],
                            "participant_alias",
                            None,
                        )
                        != aliases[removal_slot]
                    )
                )
            ):
                raise TypeError("Unprepared influence alias ownership is invalid.")
            removed_aliases = (aliases[removal_slot],)
        elif type(authorization_state) is not _UnpreparedResultAuthorizationState:
            raise TypeError("Influence preparation evidence state is invalid.")
        preimage: dict[str, object] = {
            "binding_schema_version": ("ebm-audit-influence-preparation-evidence-input/1.0"),
            "candidate_ordinal": candidate["candidate_ordinal"],
            "analysis_spec_id": candidate["analysis_spec_id"],
            "source_analysis_spec_id": operation["source_analysis_spec_id"],
            "removal_method_id": operation["removal_method_id"],
            "removal_kind": removal_kind,
            "removal_slot_ordinal": removal_slot,
            "named_group_spec_id": operation.get("named_group_spec_id"),
            "removed_aliases": list(removed_aliases),
            "preparation_state": record["state"],
            "preparation_reason_rows": copy.deepcopy(record["reasons"]),
            "fixed_evaluation_cohort_digest": fixed_evaluation_cohort_digest,
            "fixed_evaluation_cohort_count": fixed_evaluation_cohort_count,
        }
        rows.append(
            canonical_json_bytes(
                {
                    **preimage,
                    "binding_digest": structured_sha256(
                        "ebm-audit/influence-preparation-evidence-input/1",
                        preimage,
                    ),
                }
            )
        )
    return tuple(rows)


def _derive_stage_preparation_binding_bytes(
    plan: Mapping[str, Any],
    candidate_states: tuple[_CandidateAuthorizationState, ...],
) -> tuple[bytes, ...]:
    """Seal private fixed-cohort row identities for later stage comparison."""

    candidates = cast(Sequence[Mapping[str, Any]], plan["candidates"])
    if type(candidate_states) is not tuple or len(candidates) != len(candidate_states):
        raise TypeError("Stage preparation evidence coverage is invalid.")
    rows: list[bytes] = []
    for candidate, authorization_state in zip(
        candidates,
        candidate_states,
        strict=True,
    ):
        record = _closed_object(authorization_state.record_bytes)
        evaluation_membership_digest: str | None = None
        evaluation_participant_count: int | None = None
        evaluation_units: list[dict[str, object]] = []
        if type(authorization_state) is _PreparedExecutionAuthorizationState:
            universe = _closed_object(authorization_state.universe_bytes)
            evaluation_membership = authorization_state.private_replay.evaluation_membership
            evaluation_row_indexes = authorization_state.arrays["evaluation_row_indexes"]
            evaluation_membership_digest = cast(
                str,
                universe["evaluation_membership_digest"],
            )
            evaluation_participant_count = cast(
                int,
                universe["aggregate_counts"]["evaluation_participant_count"],
            )
            if (
                evaluation_row_indexes.ndim != 1
                or len(evaluation_membership) != evaluation_participant_count
                or int(evaluation_row_indexes.shape[0]) != evaluation_participant_count
            ):
                raise TypeError("Prepared stage evaluation membership is invalid.")
            evaluation_units = [
                {
                    "evaluation_row_index": int(row_index),
                    "evaluation_unit_binding": membership.participant_token,
                    "role": membership.role,
                }
                for row_index, membership in zip(
                    evaluation_row_indexes.tolist(),
                    evaluation_membership,
                    strict=True,
                )
            ]
            if len({unit["evaluation_row_index"] for unit in evaluation_units}) != len(
                evaluation_units
            ) or len({unit["evaluation_unit_binding"] for unit in evaluation_units}) != len(
                evaluation_units
            ):
                raise TypeError("Prepared stage evaluation membership is invalid.")
        elif type(authorization_state) is not _UnpreparedResultAuthorizationState:
            raise TypeError("Stage preparation evidence state is invalid.")
        preimage: dict[str, object] = {
            "binding_schema_version": ("ebm-audit-stage-preparation-evidence-input/1.0"),
            "candidate_ordinal": candidate["candidate_ordinal"],
            "candidate_id": candidate["candidate_id"],
            "analysis_spec_id": candidate["analysis_spec_id"],
            "preparation_state": record["state"],
            "preparation_reason_rows": copy.deepcopy(record["reasons"]),
            "evaluation_membership_digest": evaluation_membership_digest,
            "evaluation_participant_count": evaluation_participant_count,
            "evaluation_units": evaluation_units,
        }
        rows.append(
            canonical_json_bytes(
                {
                    **preimage,
                    "binding_digest": structured_sha256(
                        "ebm-audit/stage-preparation-evidence-input/1",
                        preimage,
                    ),
                }
            )
        )
    return tuple(rows)


def _source_participant_aliases(
    prepared_dataset: object,
    preparation_namespace_key: object,
) -> tuple[str, ...]:
    """Derive safe aliases from the admitted source before analysis validity."""

    prepared = _resolve_private_prepared_dataset(prepared_dataset)
    catalog = prepared.catalog
    participant_column = catalog.get("participant_private_id_column")
    variant = catalog.get("variant")
    if (
        type(participant_column) is not str
        or not isinstance(variant, Mapping)
        or type(variant.get("variant_id")) is not str
        or participant_column not in prepared.private_table
    ):
        raise TypeError("Prepared source identity ownership is invalid.")
    private_ids = cast(
        Sequence[str | int],
        prepared.private_table[participant_column],
    )
    try:
        identity_map = build_identity_map(
            private_ids,
            dataset_variant_id=cast(str, variant["variant_id"]),
            namespace_key=cast(Any, preparation_namespace_key),
        )
    except ValueError:
        raise TypeError("Prepared source identity ownership is invalid.") from None
    aliases = tuple(row.participant_alias for row in identity_map.rows)
    if len(aliases) != prepared.summary.participant_count or len(set(aliases)) != len(aliases):
        raise TypeError("Prepared source alias coverage is invalid.")
    return aliases


def _preparation_transaction_influence_input_receipt(
    value: object,
) -> _InfluencePreparationInputReceipt:
    """Return the exact already-published receipt capability."""

    if type(value) is not PreparationTransaction:
        raise TypeError("A genuine preparation transaction is required.")
    state = value._state()
    _read_influence_preparation_input_receipt(state.influence_input_receipt)
    return state.influence_input_receipt


@dataclass(frozen=True, repr=False)
class _PendingPreparedCandidate:
    candidate: Mapping[str, Any]
    universe: Mapping[str, Any]
    record: Mapping[str, Any]
    dataset_projection: Mapping[str, Any]
    arrays: Mapping[str, _ProtocolArray]
    private_replay: _PrivatePreparationReplayState
    authenticated_description: AuthenticatedWorkerDescription
    authenticated_description_state: object
    authenticated_description_readback: object
    canonical_dataset: CanonicalDataset
    selected_algorithm_binding: Mapping[str, Any]
    planning_summary_binding: Mapping[str, Any]
    config_digest: str
    prepared_dataset_id: str
    prepared_dataset: object
    data_identity_digest: str
    protocol_identity_digest: str
    worker_identity_digest: str
    execution_origin: _PreparedExecutionOrigin
    candidate_provenance_issuance: object | None


@dataclass(frozen=True, repr=False)
class _UnpreparedScientificInput:
    preimage_bytes: bytes
    digest: str


@final
class _PreparationAttempt:
    """Opaque one-use activation state for a provisional transaction."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _PreparationAttempt:
        raise TypeError("Preparation attempts are authority-owned.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Preparation attempts cannot be subclassed.")


_PREPARATION_ATTEMPT_STATES: WeakKeyDictionary[_PreparationAttempt, str] = WeakKeyDictionary()


@dataclass(frozen=True, repr=False)
class _PendingPreparationTransaction:
    attempt: _PreparationAttempt
    transaction: PreparationTransaction
    state: _PreparationTransactionState
    prepared_states: tuple[
        tuple[PreparedExecutionAuthorization, _PreparedExecutionAuthorizationState],
        ...,
    ]
    unprepared_states: tuple[
        tuple[UnpreparedResultAuthorization, _UnpreparedResultAuthorizationState],
        ...,
    ]
    candidate_provenance_issuances: tuple[object, ...]


class _ProfilePreparedCandidateGroupPublication:
    """Private one-use publication cell for one generated profile input."""

    __slots__ = ("group_ref", "lock", "status", "token")

    group_ref: ReferenceType[ProfilePreparedCandidateGroup] | None
    lock: Any
    status: str
    token: object

    def __init__(self) -> None:
        self.group_ref = None
        self.lock = RLock()
        self.status = "FRESH"
        self.token = object()


@dataclass(frozen=True, repr=False)
class _ProfilePreparationContext:
    run_config: object
    prepared_dataset: object
    publication: _ProfilePreparedCandidateGroupPublication
    publication_token: object
    profile_execution_identity_sha256: str
    ordered_analysis_spec_bytes: tuple[bytes, bytes, bytes]
    ordered_analysis_spec_ids: tuple[str, str, str]
    profile_chain_seeds: tuple[str, str, str]


@dataclass(frozen=True, repr=False)
class _ProfilePreparedCandidateGroupState:
    plan_owner: object
    input_binding: object
    input_binding_state: _ProfileGeneratedInputBindingState
    planning_authority: PlanningAuthority
    planning_authority_state: _PlanningAuthorityState
    publication: _ProfilePreparedCandidateGroupPublication
    publication_token: object
    profile_execution_identity_sha256: str
    coordinate_ordinal: int
    ordered_analysis_spec_ids: tuple[str, str, str]
    profile_chain_seeds: tuple[str, str, str]
    transaction: PreparationTransaction
    transaction_state: _PreparationTransactionState
    candidate_authorizations: tuple[
        PreparedExecutionAuthorization,
        PreparedExecutionAuthorization,
        PreparedExecutionAuthorization,
    ]
    candidate_states: tuple[
        _PreparedExecutionAuthorizationState,
        _PreparedExecutionAuthorizationState,
        _PreparedExecutionAuthorizationState,
    ]


_PROFILE_PREPARED_CANDIDATE_GROUP_STATES: OneShotWeakRegistry[
    object, _ProfilePreparedCandidateGroupState
]
_PROFILE_PREPARED_CANDIDATE_GROUP_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfilePreparedCandidateGroupState
]
(
    _PROFILE_PREPARED_CANDIDATE_GROUP_STATES,
    _PROFILE_PREPARED_CANDIDATE_GROUP_STATE_ISSUER,
) = create_one_shot_registry()
_PROFILE_GROUP_PUBLICATIONS: OneShotWeakRegistry[object, _ProfilePreparedCandidateGroupPublication]
_PROFILE_GROUP_PUBLICATION_ISSUER: OneShotRegistryIssuer[
    object, _ProfilePreparedCandidateGroupPublication
]
(
    _PROFILE_GROUP_PUBLICATIONS,
    _PROFILE_GROUP_PUBLICATION_ISSUER,
) = create_one_shot_registry()
_PROFILE_GROUP_PUBLICATIONS_LOCK = Lock()


@final
class ProfilePreparedCandidateGroup:
    """Opaque atomic owner of one profile input's three prepared candidates."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProfilePreparedCandidateGroup:
        raise TypeError("Profile prepared-candidate groups are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile prepared-candidate groups cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile prepared-candidate groups are immutable.")

    @property
    def profile_execution_identity_sha256(self) -> str:
        return _read_profile_prepared_candidate_group(self).profile_execution_identity_sha256

    @property
    def coordinate_ordinal(self) -> int:
        return _read_profile_prepared_candidate_group(self).coordinate_ordinal

    @property
    def ordered_analysis_spec_ids(self) -> tuple[str, str, str]:
        return _read_profile_prepared_candidate_group(self).ordered_analysis_spec_ids

    def __copy__(self) -> ProfilePreparedCandidateGroup:
        raise TypeError("Profile prepared-candidate groups cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> ProfilePreparedCandidateGroup:
        raise TypeError("Profile prepared-candidate groups cannot be copied.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Profile prepared-candidate groups cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Profile prepared-candidate groups cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Profile prepared-candidate groups cannot be serialized.")

    def __repr__(self) -> str:
        _read_profile_prepared_candidate_group(self)
        return "ProfilePreparedCandidateGroup(<sealed-profile-candidates>)"


def _profile_group_publication(
    input_binding: object,
) -> _ProfilePreparedCandidateGroupPublication:
    from ebm_audit.profile_input_identity import (
        ProfileGeneratedInputBinding,
        _read_profile_generated_input_binding,
    )

    if type(input_binding) is not ProfileGeneratedInputBinding:
        raise TypeError("A genuine profile generated-input binding is required.")
    _read_profile_generated_input_binding(input_binding)

    with _PROFILE_GROUP_PUBLICATIONS_LOCK:
        publication = _PROFILE_GROUP_PUBLICATIONS.get(input_binding)
        if publication is None:
            publication = _ProfilePreparedCandidateGroupPublication()
            _PROFILE_GROUP_PUBLICATION_ISSUER.bind_once(input_binding, publication)
    if type(publication) is not _ProfilePreparedCandidateGroupPublication:
        raise TypeError("Profile prepared-candidate publication state is invalid.")
    return publication


def _component_digests(spec: Mapping[str, Any]) -> ComponentDigests:
    return ComponentDigests(
        preprocessing_digest=structured_sha256(
            "ebm-audit/preprocessing-spec/1", {"ordered_operations": spec["preprocessing"]}
        ),
        missingness_digest=structured_sha256(
            "ebm-audit/missingness-spec/1", spec["missingness_policy"]
        ),
        outlier_digest=structured_sha256("ebm-audit/outlier-spec/1", spec["outlier_policy"]),
        cohort_digest=structured_sha256("ebm-audit/cohort-spec/1", spec["cohort_rule"]),
        covariate_adjustment_digest=structured_sha256(
            "ebm-audit/covariate-adjustment-spec/1", spec["covariate_adjustment"]
        ),
    )


def _prepared_protocol_identity_digest() -> str:
    return structured_sha256(
        "ebm-audit/prepared-execution-protocol/1",
        {
            "protocol_registry_version": load_protocol_registry()["registry_schema_version"],
            "worker_protocol_version": "ebm-audit-worker/v2",
            "request_schema_version": "ebm-audit-worker-request/2.0",
            "response_schema_version": "ebm-audit-worker-response/2.0",
            "fit_payload_schema_version": "ebm-audit-worker-fit-payload/2.0",
            "preparation_receipt_schema_version": ("ebm-audit-preparation-receipt/2.0"),
            "universe_schema_version": "ebm-audit-analysis-universe/3.0",
        },
    )


def _prepared_data_identity_digest(
    *,
    prepared_dataset_id: str,
    universe: Mapping[str, Any],
    dataset: Mapping[str, Any],
) -> str:
    return structured_sha256(
        "ebm-audit/prepared-execution-data/1",
        {
            "prepared_dataset_id": prepared_dataset_id,
            "source_prepared_data_digest": universe["source_prepared_data_digest"],
            "training_prepared_data_digest": universe["training_prepared_data_digest"],
            "evaluation_prepared_data_digest": universe["evaluation_prepared_data_digest"],
            "array_catalog": dataset["array_catalog"],
        },
    )


def _private_replay_identity_digest(
    replay: _PrivatePreparationReplayState,
) -> str:
    def membership(rows: Sequence[_PrivateMembership]) -> list[dict[str, Any]]:
        return [row._asdict() for row in rows]

    def instances(rows: Sequence[_PrivateOperationInstance]) -> list[dict[str, Any]]:
        return [row._asdict() for row in rows]

    return structured_sha256(
        "ebm-audit/private-preparation-replay/2",
        {
            "plan_digest": replay.plan_digest,
            "candidate_ordinal": replay.candidate_ordinal,
            "candidate_id": replay.candidate_id,
            "analysis_spec_id": replay.analysis_spec_id,
            "source_analysis_spec_id": replay.source_analysis_spec_id,
            "operation_seed": replay.operation_seed,
            "preparation_rule_registry_digest": (replay.preparation_rule_registry_digest),
            "source_membership": membership(replay.source_membership),
            "cohort_membership": membership(replay.cohort_membership),
            "pre_operation_membership": membership(replay.pre_operation_membership),
            "operation_instances": instances(replay.operation_instances),
            "operation_unique_membership": membership(replay.operation_unique_membership),
            "training_instances": instances(replay.training_instances),
            "training_unique_membership": membership(replay.training_unique_membership),
            "evaluation_membership": membership(replay.evaluation_membership),
            "removed_membership": membership(replay.removed_membership),
            "public_universe_fields_sha256": (
                "sha256:" + hashlib.sha256(replay.public_universe_fields_bytes).hexdigest()
            ),
            "private_transition_chain_sha256": (
                "sha256:" + hashlib.sha256(replay.private_transition_chain_bytes).hexdigest()
            ),
        },
    )


def _source_descriptor(
    catalog: Mapping[str, Any],
    table: Mapping[str, Sequence[object]],
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    event_by_id = {
        row["event_id"]: row for row in cast(Sequence[Mapping[str, Any]], catalog["event_specs"])
    }
    try:
        events = [event_by_id[row["event_id"]] for row in spec["event_set"]]
    except KeyError:
        raise UniverseIdentityError("A planned event has no exact prepared-data owner.") from None
    groups = [
        row
        for row in cast(Sequence[Mapping[str, Any]], catalog["group_specs"])
        if row["group_spec_id"] == spec["cohort_rule"]["group_spec_id"]
    ]
    if len(groups) != 1:
        raise UniverseIdentityError("A planned cohort has no exact prepared-data owner.")
    descriptor: dict[str, Any] = {
        "schema_version": "ebm-audit-dataset/1.0",
        "variant": _canonical_copy(catalog["variant"]),
        "participant_private_id_column": catalog["participant_private_id_column"],
        "event_specs": _canonical_copy(events),
        "group_spec": _canonical_copy(groups[0]),
        "covariate_specs": _canonical_copy(catalog["covariate_specs"]),
        "metadata_specs": _canonical_copy(catalog["metadata_specs"]),
        "ignored_columns": _canonical_copy(catalog["ignored_columns"]),
        "missingness_policy": spec["missingness_policy"]["policy"],
        "source_table_content_digest": "sha256:" + "0" * 64,
        "source_table_row_count": catalog["source_table_row_count"],
        "source_column_names": [row["source_column"] for row in catalog["physical_columns"]],
    }
    descriptor["source_table_content_digest"] = compute_source_table_content_digest(
        descriptor,
        table,
        source_row_indexes=tuple(range(cast(int, catalog["source_table_row_count"]))),
    )
    return descriptor


def _canonicalize_candidate_input(
    prepared_dataset: object,
    preparation_namespace_key: object,
    candidate: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> tuple[Any, _PreparedPrivateState]:
    """Rebuild the exact canonical input from its opaque source owners."""

    prepared = _resolve_private_prepared_dataset(prepared_dataset)
    descriptor = _source_descriptor(
        cast(Mapping[str, Any], prepared.catalog),
        cast(Mapping[str, Sequence[object]], prepared.private_table),
        spec,
    )
    canonical = ingest_exact_file_audit_dataset(
        descriptor,
        prepared.source_admission,
        component_digests=_component_digests(spec),
        universe_decision_id=cast(str, candidate["candidate_id"]),
        namespace_key=preparation_namespace_key,
    )
    return canonical, prepared


def _unprepared_scientific_input(canonical: Any) -> _UnpreparedScientificInput:
    """Seal and independently hash one canonical, privacy-safe digest preimage."""

    preimage = _canonical_copy(canonical.private.scientific_data_preimage)
    try:
        validate_instance(
            preimage,
            "canonical-records.schema.json",
            definition="ScientificDataDigestPreimage",
        )
    except SchemaValidationError:
        raise UniverseIdentityError(
            "The unprepared canonical scientific-data owner is invalid."
        ) from None
    digest = structured_sha256("ebm-audit/scientific-data/1", preimage)
    if not hmac.compare_digest(digest, cast(str, canonical.scientific_data_digest)):
        raise UniverseIdentityError("The unprepared canonical scientific-data digest is detached.")
    return _UnpreparedScientificInput(
        preimage_bytes=canonical_json_bytes(preimage),
        digest=digest,
    )


def _supports_leave_one_out_influence(spec: Mapping[str, Any]) -> bool:
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    return (
        operation["kind"] == "influence"
        and operation["removal_method_id"] == "exact-participant-or-named-group-removal/1"
        and operation["removal_kind"] == "leave-one-participant-out"
        and operation["refit_preprocessing"] is True
        and operation["fixed_non_removed_cohort_policy"]
        == "fixed-non-removed-baseline-cohort-or-unsupported/1"
    )


def _supports_transformed_null(spec: Mapping[str, Any]) -> bool:
    """Return whether the declared null is one supported source-derived transformation."""

    operation = cast(Mapping[str, Any], spec["operation_intent"])
    method_id = operation.get("null_method_id")
    if (
        operation["kind"] != "null"
        or method_id not in _TRANSFORMED_NULL_METHOD_IDS
        or operation.get("refit_preprocessing") is not True
    ):
        return False
    if method_id == "label-permutation/1":
        return (
            operation.get("transformation") == "label-permutation"
            and operation.get("within_group_spec_id") is None
            and operation.get("preserves_group_conditional_event_marginals") is False
        )
    if method_id == "pure-no-signal-synthetic/1":
        return (
            operation.get("transformation") == "pure-no-signal-synthetic"
            and operation.get("within_group_spec_id") is None
            and operation.get("preserves_group_conditional_event_marginals") is False
        )
    return (
        operation.get("transformation") == "featurewise-participant-permutation"
        and operation.get("within_group_spec_id") == spec["cohort_rule"]["group_spec_id"]
        and operation.get("preserves_group_conditional_event_marginals") is True
    )


def _supports_stratified_subsample(spec: Mapping[str, Any]) -> bool:
    """Return whether one subsample uses the sole executable v1 design."""

    operation = cast(Mapping[str, Any], spec["operation_intent"])
    return (
        operation["kind"] == "subsample"
        and operation.get("sampling_method_id") == "participant-subsample-without-replacement/1"
        and operation.get("sampling_design") == "stratified"
        and operation.get("strata_group_spec_ids") == [spec["cohort_rule"]["group_spec_id"]]
        and operation.get("retained_count_rounding_rule")
        == "floor-pre-operation-count-times-fraction/1"
        and operation.get("refit_preprocessing") is True
        and operation.get("fixed_evaluation_cohort_policy")
        == "fixed-subsample-cohort-or-unsupported/1"
    )


def _unsupported_reasons(spec: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    kind = operation["kind"]
    supported_bootstrap = (
        kind == "bootstrap"
        and operation["sampling_design"] == "stratified"
        and operation["strata_group_spec_ids"] == [spec["cohort_rule"]["group_spec_id"]]
    )
    supported_subsample = _supports_stratified_subsample(spec)
    supported_influence = _supports_leave_one_out_influence(spec)
    supported_transformed_null = _supports_transformed_null(spec)
    supported_fixed_rescale = _supports_fixed_event_rescale(spec)
    if kind == "influence" and operation["removal_kind"] == "named-group-removal":
        result.append("PREPARATION.NAMED_GROUP_REMOVAL_UNSUPPORTED")
    elif (
        kind != "ordinary"
        and not supported_bootstrap
        and not supported_subsample
        and not supported_influence
        and not supported_transformed_null
    ):
        result.append("PREPARATION.OPERATION_UNSUPPORTED")
    if spec["preprocessing"] and not supported_fixed_rescale:
        result.append("PREPARATION.PREPROCESSING_UNSUPPORTED")
    if spec["outlier_policy"]["policy_kind"] != "none":
        result.append("PREPARATION.OUTLIER_POLICY_UNSUPPORTED")
    if spec["covariate_adjustment"]["method"] != "none":
        result.append("PREPARATION.COVARIATE_ADJUSTMENT_UNSUPPORTED")
    if spec["missingness_policy"]["policy"] == "external-variant":
        result.append("PREPARATION.EXTERNAL_VARIANT_UNSUPPORTED")
    return sorted(set(result))


def _reason_rows(
    invalid_reasons: Sequence[str], unsupported_reasons: Sequence[str]
) -> list[dict[str, str]]:
    rows = [
        {
            "reason_code": reason,
            "rule_id": (
                "preparation.stratified-subsample-allocation/1"
                if reason == _SUBSAMPLE_ALLOCATION_INVALID_REASON
                else "preparation.validity/1"
            ),
        }
        for reason in invalid_reasons
    ]
    rows.extend(
        {"reason_code": reason, "rule_id": "preparation.capability/1"}
        for reason in unsupported_reasons
    )
    rows.sort(key=lambda row: (row["reason_code"].encode(), row["rule_id"].encode()))
    return rows


def _unprepared_record(
    candidate: Mapping[str, Any],
    *,
    state: str,
    operation_seed: str | None,
    invalid_reasons: Sequence[str] = (),
    unsupported_reasons: Sequence[str] = (),
) -> dict[str, Any]:
    if state == "PLAN_INELIGIBLE":
        reasons = copy.deepcopy(list(candidate["planning_reasons"]))
        applied: list[str] = []
    else:
        reasons = _reason_rows(invalid_reasons, unsupported_reasons)
        applied = sorted({row["rule_id"] for row in reasons})
    record = {
        "record_schema_version": "ebm-audit-preparation-record/2.0",
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "state": state,
        "operation_seed": operation_seed,
        "applied_preparation_rule_ids": applied,
        "reasons": reasons,
        "universe_spec": None,
    }
    _validate_schema(record, "PreparationRecord")
    _verify_preparation_record_rules(
        candidate,
        record,
        _PREPARATION_RULE_REGISTRY["ordered_rules"],
        {row["rule_id"]: row for row in _PREPARATION_RULE_REGISTRY["ordered_rules"]},
    )
    return record


def _private_membership_and_arrays(
    canonical: Any,
) -> tuple[
    tuple[_PrivateMembership, ...],
    tuple[_PrivateOperationInstance, ...],
    Mapping[str, _ProtocolArray],
]:
    identity_rows = canonical.private.identity_map.rows
    group_codes = canonical.private.arrays["group_role_codes"]
    memberships = tuple(
        _PrivateMembership(
            row.participant_private_token,
            row.participant_internal_index,
            "reference" if int(group_codes[index]) == 0 else "at_risk",
        )
        for index, row in enumerate(identity_rows)
    )
    instances = tuple(
        _PrivateOperationInstance(
            row.participant_token,
            row.internal_row_index,
            row.role,
            ordinal,
            0,
        )
        for ordinal, row in enumerate(memberships)
    )
    values = canonical.private.arrays["event_values"]
    indexes = canonical.private.arrays["participant_internal_indexes"]
    arrays: dict[str, _ProtocolArray] = {
        "train_values": _freeze_array(values, dtype=np.dtype("float64")),
        "training_row_indexes": _freeze_array(indexes, dtype=np.dtype("int64")),
        "train_group_codes": _freeze_array(group_codes, dtype=np.dtype("int32")),
        "evaluation_values": _freeze_array(values, dtype=np.dtype("float64")),
        "evaluation_row_indexes": _freeze_array(indexes, dtype=np.dtype("int64")),
        "evaluation_group_codes": _freeze_array(group_codes, dtype=np.dtype("int32")),
    }
    frozen_arrays = MappingProxyType(arrays)
    if not _arrays_are_exactly_frozen(frozen_arrays):
        raise UniverseIdentityError("Prepared execution arrays are not exact immutable copies.")
    return memberships, instances, frozen_arrays


def _supports_fixed_event_rescale(spec: Mapping[str, Any]) -> bool:
    """Return whether one spec uses the exact core-owned preprocessing method."""

    transforms = spec.get("preprocessing")
    if not isinstance(transforms, list) or len(transforms) != 1:
        return False
    transform = transforms[0]
    if not isinstance(transform, Mapping):
        return False
    event_ids = [row["event_id"] for row in spec["event_set"]]
    parameters = transform.get("parameters")
    expected_schema_digest = settings_schema_digest(
        _FIXED_EVENT_RESCALE_SETTINGS_SCHEMA
    )
    return not (
        spec["operation_intent"] != {"kind": "ordinary"}
        or transform.get("method_id") != _FIXED_EVENT_RESCALE_METHOD_ID
        or transform.get("event_ids") != event_ids
        or transform.get("parameters_schema_digest") != expected_schema_digest
        or transform.get("parameters_classification")
        != "public-scientific-settings/1"
        or not isinstance(parameters, list)
        or len(parameters) != 1
        or parameters[0]
        != {"name": "scale_factor", "value": _FIXED_EVENT_RESCALE_FACTOR}
    )


def _source_candidate_for_fixed_event_rescale(
    plan: Mapping[str, Any], candidate: Mapping[str, Any]
) -> Mapping[str, Any]:
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    source_id = plan["baseline_analysis_spec_id"]
    expected_source = copy.deepcopy(dict(spec))
    expected_source["preprocessing"] = []
    matches = [
        row
        for row in cast(Sequence[Mapping[str, Any]], plan["candidates"])
        if row["analysis_spec_id"] == source_id
        and row["analysis_spec"]["operation_intent"] == {"kind": "ordinary"}
        and row["analysis_spec"] == expected_source
    ]
    if len(matches) != 1:
        raise UniverseIdentityError(
            "Fixed rescale preprocessing lacks one exact ordinary baseline source."
        )
    return matches[0]


def _fixed_event_rescale_membership_and_arrays(
    canonical: Any,
) -> tuple[
    tuple[_PrivateMembership, ...],
    tuple[_PrivateOperationInstance, ...],
    Mapping[str, _ProtocolArray],
    int,
]:
    """Apply one fixed public rescale without fitting on participant values."""

    memberships, instances, ordinary = _private_membership_and_arrays(canonical)
    source_values = cast(NDArray[np.float64], ordinary["train_values"])
    transformed_values = np.multiply(
        source_values,
        _FIXED_EVENT_RESCALE_FACTOR,
        dtype=np.float64,
    )
    changed_cell_count = int(np.count_nonzero(transformed_values != source_values))
    if changed_cell_count < 1 or not bool(np.isfinite(transformed_values).all()):
        raise UniverseIdentityError("Fixed rescale preprocessing was not an effective transform.")
    arrays: dict[str, _ProtocolArray] = {
        "train_values": _freeze_array(transformed_values, dtype=np.dtype("float64")),
        "training_row_indexes": ordinary["training_row_indexes"],
        "train_group_codes": ordinary["train_group_codes"],
        "evaluation_values": _freeze_array(
            transformed_values,
            dtype=np.dtype("float64"),
        ),
        "evaluation_row_indexes": ordinary["evaluation_row_indexes"],
        "evaluation_group_codes": ordinary["evaluation_group_codes"],
    }
    frozen_arrays = MappingProxyType(arrays)
    if not _arrays_are_exactly_frozen(frozen_arrays):
        raise UniverseIdentityError("Prepared execution arrays are not exact immutable copies.")
    return memberships, instances, frozen_arrays, changed_cell_count


def _bootstrap_draw_index(
    operation_seed: str,
    *,
    stratum_group_spec_id: str,
    role: str,
    draw_ordinal: int,
    population_size: int,
) -> int:
    """Return one unbiased bounded draw derived only from the exact operation seed."""

    if population_size < 1:
        raise _CandidatePreparationInvalid
    key = bytes.fromhex(operation_seed)
    modulus = 1 << 256
    rejection_limit = modulus - (modulus % population_size)
    counter = 0
    while True:
        message = canonical_json_bytes(
            {
                "draw_schema_version": "ebm-audit-stratified-bootstrap-draw/1.0",
                "stratum_group_spec_id": stratum_group_spec_id,
                "role": role,
                "draw_ordinal": draw_ordinal,
                "rejection_counter": counter,
            }
        )
        value = int.from_bytes(hmac.new(key, message, hashlib.sha256).digest(), "big")
        if value < rejection_limit:
            return value % population_size
        counter += 1


def _subsample_tie_score(
    operation_seed: str,
    *,
    stratum_group_spec_id: str,
    role: str,
) -> bytes:
    """Return one role-specific deterministic Hamilton tie score."""

    return hmac.new(
        bytes.fromhex(operation_seed),
        canonical_json_bytes(
            {
                "tie_schema_version": "ebm-audit-subsample-hamilton-tie/1.0",
                "allocation_rule_id": _SUBSAMPLE_ALLOCATION_RULE_ID,
                "stratum_group_spec_id": stratum_group_spec_id,
                "role": role,
            }
        ),
        hashlib.sha256,
    ).digest()


def _subsample_draw_index(
    operation_seed: str,
    *,
    stratum_group_spec_id: str,
    role: str,
    role_draw_ordinal: int,
    population_size: int,
) -> int:
    """Return one unbiased role-specific draw from a shrinking private pool."""

    if population_size < 1 or role_draw_ordinal < 0:
        raise _CandidatePreparationInvalid
    key = bytes.fromhex(operation_seed)
    modulus = 1 << 256
    rejection_limit = modulus - (modulus % population_size)
    rejection_counter = 0
    while True:
        message = canonical_json_bytes(
            {
                "draw_schema_version": "ebm-audit-stratified-subsample-draw/1.0",
                "allocation_rule_id": _SUBSAMPLE_ALLOCATION_RULE_ID,
                "stratum_group_spec_id": stratum_group_spec_id,
                "role": role,
                "role_draw_ordinal": role_draw_ordinal,
                "remaining_population_size": population_size,
                "rejection_counter": rejection_counter,
            }
        )
        value = int.from_bytes(hmac.new(key, message, hashlib.sha256).digest(), "big")
        if value < rejection_limit:
            return value % population_size
        rejection_counter += 1


def _stratified_subsample_plan(
    memberships: tuple[_PrivateMembership, ...],
    operation: Mapping[str, Any],
    operation_seed: str,
    *,
    minimum_reference_rows: int | None,
) -> _StratifiedSubsamplePlan:
    """Allocate one global floor total, then draw each role without replacement."""

    strata_group_spec_ids = cast(Sequence[str], operation["strata_group_spec_ids"])
    if len(strata_group_spec_ids) != 1:
        raise _CandidatePreparationInvalid
    stratum_group_spec_id = strata_group_spec_ids[0]
    ordered_roles = ("reference", "at_risk")
    pools = {role: tuple(row for row in memberships if row.role == role) for role in ordered_roles}
    reference_count = len(pools["reference"])
    at_risk_count = len(pools["at_risk"])
    participant_count = reference_count + at_risk_count
    retained_total = _expected_subsample_retained_count(
        participant_count,
        cast(float, operation["retained_fraction"]),
    )
    reference_minimum = max(1, minimum_reference_rows or 0)
    at_risk_minimum = 1
    reference_lower = max(reference_minimum, retained_total - at_risk_count)
    reference_upper = min(reference_count, retained_total - at_risk_minimum)
    if (
        participant_count != len(memberships)
        or reference_lower > reference_upper
        or retained_total >= participant_count
    ):
        raise _CandidatePreparationInvalid

    reference_numerator = retained_total * reference_count
    at_risk_numerator = retained_total * at_risk_count
    reference_hamilton_quota = reference_numerator // participant_count
    at_risk_hamilton_quota = at_risk_numerator // participant_count
    residual = retained_total - reference_hamilton_quota - at_risk_hamilton_quota
    if residual not in {0, 1}:
        raise UniverseIdentityError("Two-role Hamilton allocation has an invalid residual.")
    if residual:
        remainders = {
            "reference": reference_numerator % participant_count,
            "at_risk": at_risk_numerator % participant_count,
        }
        largest_remainder = max(remainders.values())
        recipients = [role for role in ordered_roles if remainders[role] == largest_remainder]
        if len(recipients) == 1:
            recipient = recipients[0]
        else:
            recipient = max(
                recipients,
                key=lambda role: (
                    _subsample_tie_score(
                        operation_seed,
                        stratum_group_spec_id=stratum_group_spec_id,
                        role=role,
                    ),
                    role.encode("utf-8"),
                ),
            )
        if recipient == "reference":
            reference_hamilton_quota += 1
        else:
            at_risk_hamilton_quota += 1

    reference_quota = min(
        max(reference_hamilton_quota, reference_lower),
        reference_upper,
    )
    at_risk_quota = retained_total - reference_quota
    if not (
        reference_minimum <= reference_quota <= reference_count
        and at_risk_minimum <= at_risk_quota <= at_risk_count
    ):
        raise _CandidatePreparationInvalid

    quotas = {
        "reference": reference_quota,
        "at_risk": at_risk_quota,
    }
    selected: list[_PrivateOperationInstance] = []
    selected_keys: set[tuple[str, int]] = set()
    draw_ordinal = 0
    for role in ordered_roles:
        remaining = list(pools[role])
        for role_draw_ordinal in range(quotas[role]):
            selected_index = _subsample_draw_index(
                operation_seed,
                stratum_group_spec_id=stratum_group_spec_id,
                role=role,
                role_draw_ordinal=role_draw_ordinal,
                population_size=len(remaining),
            )
            source = remaining.pop(selected_index)
            key = (source.participant_token, source.internal_row_index)
            if key in selected_keys:
                raise UniverseIdentityError("Subsample draw repeated a private participant.")
            selected_keys.add(key)
            selected.append(
                _PrivateOperationInstance(
                    source.participant_token,
                    source.internal_row_index,
                    source.role,
                    draw_ordinal,
                    0,
                )
            )
            draw_ordinal += 1
    retained_membership = tuple(
        row
        for row in memberships
        if (row.participant_token, row.internal_row_index) in selected_keys
    )
    if len(selected) != retained_total or len(retained_membership) != retained_total:
        raise UniverseIdentityError("Subsample draw does not retain its exact global total.")
    return _StratifiedSubsamplePlan(
        retained_total=retained_total,
        reference_minimum=reference_minimum,
        at_risk_minimum=at_risk_minimum,
        reference_lower=reference_lower,
        reference_upper=reference_upper,
        reference_hamilton_quota=reference_hamilton_quota,
        at_risk_hamilton_quota=at_risk_hamilton_quota,
        reference_quota=reference_quota,
        at_risk_quota=at_risk_quota,
        instances=tuple(selected),
        retained_membership=retained_membership,
    )


def _null_permutation_draw_index(
    operation_seed: str,
    *,
    method_id: str,
    attempt_ordinal: int,
    scope: Mapping[str, Any],
    shuffle_position: int,
    population_size: int,
) -> int:
    """Return one unbiased bounded draw for a domain-separated null permutation."""

    if (
        method_id not in _TRANSFORMED_NULL_METHOD_IDS
        or attempt_ordinal < 0
        or shuffle_position < 0
        or population_size < 1
    ):
        raise _CandidatePreparationInvalid
    key = bytes.fromhex(operation_seed)
    modulus = 1 << 256
    rejection_limit = modulus - (modulus % population_size)
    rejection_counter = 0
    while True:
        message = canonical_json_bytes(
            {
                "draw_schema_version": "ebm-audit-transformed-null-draw/1.0",
                "method_id": method_id,
                "attempt_ordinal": attempt_ordinal,
                "scope": copy.deepcopy(dict(scope)),
                "shuffle_position": shuffle_position,
                "population_size": population_size,
                "rejection_counter": rejection_counter,
            }
        )
        value = int.from_bytes(hmac.new(key, message, hashlib.sha256).digest(), "big")
        if value < rejection_limit:
            return value % population_size
        rejection_counter += 1


def _null_permutation_source_positions(
    operation_seed: str,
    *,
    method_id: str,
    attempt_ordinal: int,
    scope: Mapping[str, Any],
    population_size: int,
) -> tuple[int, ...]:
    """Return a deterministic Fisher-Yates source-position map."""

    positions = list(range(population_size))
    for upper in range(population_size - 1, 0, -1):
        selected = _null_permutation_draw_index(
            operation_seed,
            method_id=method_id,
            attempt_ordinal=attempt_ordinal,
            scope=scope,
            shuffle_position=upper,
            population_size=upper + 1,
        )
        positions[upper], positions[selected] = positions[selected], positions[upper]
    if sorted(positions) != list(range(population_size)):
        raise UniverseIdentityError("A transformed-null draw is not a permutation.")
    return tuple(positions)


def _semantic_float_row(values: NDArray[np.float64]) -> tuple[float | None, ...]:
    """Return an exact row key that treats missing values and signed zero semantically."""

    return tuple(None if np.isnan(value) else float(value) for value in values)


def _joint_event_multiset_changed(
    source_values: NDArray[np.float64],
    transformed_values: NDArray[np.float64],
    group_positions: Mapping[int, tuple[int, ...]],
) -> bool:
    """Return whether a transform changed joint event structure within any group."""

    for positions in group_positions.values():
        source_rows = Counter(
            _semantic_float_row(source_values[position]) for position in positions
        )
        transformed_rows = Counter(
            _semantic_float_row(transformed_values[position]) for position in positions
        )
        if source_rows != transformed_rows:
            return True
    return False


def _transformed_null_plan(
    memberships: tuple[_PrivateMembership, ...],
    *,
    event_count: int,
    operation: Mapping[str, Any],
    operation_seed: str,
    source_values: NDArray[np.float64] | None = None,
) -> _TransformedNullPlan:
    """Derive one effective null map or fail closed after bounded deterministic draws."""

    method_id = cast(str, operation["null_method_id"])
    if (
        method_id not in _TRANSFORMED_NULL_METHOD_IDS
        or event_count < 2
        or len(memberships) < 2
        or {row.role for row in memberships} != {"reference", "at_risk"}
    ):
        raise _CandidatePreparationInvalid
    original_codes = tuple(0 if row.role == "reference" else 1 for row in memberships)
    participant_count = len(memberships)
    if method_id == "label-permutation/1":
        for attempt_ordinal in range(_TRANSFORMED_NULL_MAX_ATTEMPTS):
            source_positions = _null_permutation_source_positions(
                operation_seed,
                method_id=method_id,
                attempt_ordinal=attempt_ordinal,
                scope={"permutation_scope": "global-group-labels"},
                population_size=participant_count,
            )
            transformed_codes = tuple(original_codes[position] for position in source_positions)
            moved_label_count = sum(
                source_code != transformed_code
                for source_code, transformed_code in zip(
                    original_codes,
                    transformed_codes,
                    strict=True,
                )
            )
            if moved_label_count == 0:
                continue
            if sorted(transformed_codes) != sorted(original_codes):
                raise UniverseIdentityError(
                    "A label permutation changed the declared group counts."
                )
            transformed_membership = tuple(
                _PrivateMembership(
                    row.participant_token,
                    row.internal_row_index,
                    "reference" if transformed_codes[position] == 0 else "at_risk",
                )
                for position, row in enumerate(memberships)
            )
            transformed_instances = tuple(
                _PrivateOperationInstance(
                    row.participant_token,
                    row.internal_row_index,
                    row.role,
                    draw_ordinal,
                    0,
                )
                for draw_ordinal, row in enumerate(transformed_membership)
            )
            return _TransformedNullPlan(
                attempt_ordinal=attempt_ordinal,
                method_id=method_id,
                source_membership=memberships,
                transformed_membership=transformed_membership,
                transformed_instances=transformed_instances,
                label_source_positions=source_positions,
                event_source_positions=None,
                generated_values=None,
                moved_label_count=moved_label_count,
                moved_cell_count=0,
                changed_value_cell_count=0,
                changed_participant_count=moved_label_count,
                changed_event_ordinals=(),
                participant_event_alignment_changed=False,
            )
        raise _CandidatePreparationInvalid

    if (
        type(source_values) is not np.ndarray
        or source_values.dtype.name != "float64"
        or source_values.shape != (participant_count, event_count)
        or bool(np.isinf(source_values).any())
    ):
        raise _CandidatePreparationInvalid
    if method_id == "pure-no-signal-synthetic/1":
        if (
            operation.get("transformation") != "pure-no-signal-synthetic"
            or operation.get("within_group_spec_id") is not None
            or operation.get("preserves_group_conditional_event_marginals") is not False
            or not np.all(np.isfinite(source_values))
        ):
            raise _CandidatePreparationInvalid
        seed_preimage = canonical_json_bytes(
            {
                "schema_version": "ebm-audit-pure-no-signal-seed/1.0",
                "method_id": method_id,
                "operation_seed": operation_seed,
                "participant_count": participant_count,
                "event_count": event_count,
            }
        )
        seed = int.from_bytes(hashlib.sha256(seed_preimage).digest(), "big")
        generator = np.random.Generator(np.random.PCG64DXSM(seed))
        generated_values = np.asarray(
            generator.standard_normal((participant_count, event_count), dtype=np.float64),
            dtype=np.float64,
        )
        generated_values.setflags(write=False)
        changed = ~np.equal(source_values, generated_values)
        changed_positions = np.argwhere(changed)
        changed_event_ordinals = tuple(
            int(value) for value in np.unique(changed_positions[:, 1])
        )
        transformed_instances = tuple(
            _PrivateOperationInstance(
                row.participant_token,
                row.internal_row_index,
                row.role,
                draw_ordinal,
                0,
            )
            for draw_ordinal, row in enumerate(memberships)
        )
        return _TransformedNullPlan(
            attempt_ordinal=0,
            method_id=method_id,
            source_membership=memberships,
            transformed_membership=memberships,
            transformed_instances=transformed_instances,
            label_source_positions=None,
            event_source_positions=None,
            generated_values=generated_values,
            moved_label_count=0,
            moved_cell_count=int(changed_positions.shape[0]),
            changed_value_cell_count=int(changed_positions.shape[0]),
            changed_participant_count=len(set(int(value) for value in changed_positions[:, 0])),
            changed_event_ordinals=changed_event_ordinals,
            participant_event_alignment_changed=True,
        )
    group_positions = {
        role_code: tuple(
            position for position, code in enumerate(original_codes) if code == role_code
        )
        for role_code in (0, 1)
    }
    if any(not positions for positions in group_positions.values()):
        raise _CandidatePreparationInvalid
    for attempt_ordinal in range(_TRANSFORMED_NULL_MAX_ATTEMPTS):
        event_maps: list[tuple[int, ...]] = []
        for event_ordinal in range(event_count):
            source_map = list(range(participant_count))
            for role_code in (0, 1):
                positions = group_positions[role_code]
                relative_sources = _null_permutation_source_positions(
                    operation_seed,
                    method_id=method_id,
                    attempt_ordinal=attempt_ordinal,
                    scope={
                        "permutation_scope": "within-group-event",
                        "role_code": role_code,
                        "event_ordinal": event_ordinal,
                    },
                    population_size=len(positions),
                )
                for destination_relative, source_relative in enumerate(relative_sources):
                    source_map[positions[destination_relative]] = positions[source_relative]
            event_map = tuple(source_map)
            for role_code in (0, 1):
                positions = group_positions[role_code]
                if sorted(event_map[position] for position in positions) != list(positions):
                    raise UniverseIdentityError(
                        "A within-group feature permutation crossed group membership."
                    )
            event_maps.append(event_map)
        event_source_positions = tuple(event_maps)
        positional_event_maps_differ = len(set(event_source_positions)) > 1
        moved_cell_count = sum(
            source_position != destination_position
            for event_map in event_source_positions
            for destination_position, source_position in enumerate(event_map)
        )
        if not positional_event_maps_differ or moved_cell_count == 0:
            continue
        transformed_values = np.empty_like(source_values)
        changed_value_cell_count = 0
        changed_participant_positions: set[int] = set()
        changed_event_ordinals: list[int] = []
        for event_ordinal, event_map in enumerate(event_source_positions):
            destination_values = source_values[:, event_ordinal]
            permuted_values = source_values[
                np.asarray(event_map, dtype=np.int64),
                event_ordinal,
            ]
            transformed_values[:, event_ordinal] = permuted_values
            unchanged = np.equal(destination_values, permuted_values) | (
                np.isnan(destination_values) & np.isnan(permuted_values)
            )
            changed_positions = np.flatnonzero(~unchanged)
            if changed_positions.size:
                changed_event_ordinals.append(event_ordinal)
                changed_value_cell_count += int(changed_positions.size)
                changed_participant_positions.update(
                    int(destination_position) for destination_position in changed_positions
                )
        if changed_value_cell_count == 0:
            continue
        if not _joint_event_multiset_changed(
            source_values,
            transformed_values,
            group_positions,
        ):
            continue
        transformed_instances = tuple(
            _PrivateOperationInstance(
                row.participant_token,
                row.internal_row_index,
                row.role,
                draw_ordinal,
                0,
            )
            for draw_ordinal, row in enumerate(memberships)
        )
        return _TransformedNullPlan(
            attempt_ordinal=attempt_ordinal,
            method_id=method_id,
            source_membership=memberships,
            transformed_membership=memberships,
            transformed_instances=transformed_instances,
            label_source_positions=None,
            event_source_positions=event_source_positions,
            generated_values=None,
            moved_label_count=0,
            moved_cell_count=moved_cell_count,
            changed_value_cell_count=changed_value_cell_count,
            changed_participant_count=len(changed_participant_positions),
            changed_event_ordinals=tuple(changed_event_ordinals),
            participant_event_alignment_changed=True,
        )
    raise _CandidatePreparationInvalid


def _transformed_null_membership_and_arrays(
    canonical: Any,
    operation: Mapping[str, Any],
    operation_seed: str,
) -> tuple[_TransformedNullPlan, Mapping[str, _ProtocolArray]]:
    """Realize one source-derived null against immutable canonical arrays."""

    memberships, _ordinary_instances, _ordinary_arrays = _private_membership_and_arrays(canonical)
    plan = _transformed_null_plan(
        memberships,
        event_count=canonical.view.event_count,
        operation=operation,
        operation_seed=operation_seed,
        source_values=canonical.private.arrays["event_values"],
    )
    source_values = canonical.private.arrays["event_values"]
    source_group_codes = canonical.private.arrays["group_role_codes"]
    source_indexes = canonical.private.arrays["participant_internal_indexes"]
    if plan.method_id == "label-permutation/1":
        transformed_values = source_values
        transformed_group_codes = np.asarray(
            [0 if row.role == "reference" else 1 for row in plan.transformed_membership],
            dtype=np.int32,
        )
    elif plan.method_id == "pure-no-signal-synthetic/1":
        if plan.generated_values is None:
            raise UniverseIdentityError("A pure no-signal transform lacks generated values.")
        transformed_values = plan.generated_values
        transformed_group_codes = source_group_codes
    else:
        if plan.event_source_positions is None:
            raise UniverseIdentityError("A feature permutation lacks its private source map.")
        transformed_values = np.empty_like(source_values)
        for event_ordinal, event_map in enumerate(plan.event_source_positions):
            transformed_values[:, event_ordinal] = source_values[
                np.asarray(event_map, dtype=np.int64),
                event_ordinal,
            ]
        transformed_group_codes = source_group_codes
    arrays: dict[str, _ProtocolArray] = {
        "train_values": _freeze_array(transformed_values, dtype=np.dtype("float64")),
        "training_row_indexes": _freeze_array(source_indexes, dtype=np.dtype("int64")),
        "train_group_codes": _freeze_array(
            transformed_group_codes,
            dtype=np.dtype("int32"),
        ),
        "evaluation_values": _freeze_array(
            transformed_values,
            dtype=np.dtype("float64"),
        ),
        "evaluation_row_indexes": _freeze_array(source_indexes, dtype=np.dtype("int64")),
        "evaluation_group_codes": _freeze_array(
            transformed_group_codes,
            dtype=np.dtype("int32"),
        ),
    }
    frozen_arrays = MappingProxyType(arrays)
    if not _arrays_are_exactly_frozen(frozen_arrays):
        raise UniverseIdentityError("Prepared execution arrays are not exact immutable copies.")
    return plan, frozen_arrays


def _stratified_bootstrap_instances(
    memberships: tuple[_PrivateMembership, ...],
    operation: Mapping[str, Any],
    operation_seed: str,
) -> tuple[
    tuple[_PrivateOperationInstance, ...],
    tuple[_PrivateMembership, ...],
]:
    """Replay the one supported role-stratified participant bootstrap."""

    strata_group_spec_ids = cast(Sequence[str], operation["strata_group_spec_ids"])
    if len(strata_group_spec_ids) != 1:
        raise _CandidatePreparationInvalid
    stratum_group_spec_id = strata_group_spec_ids[0]
    ordered_roles = ("reference", "at_risk")
    pools = {role: tuple(row for row in memberships if row.role == role) for role in ordered_roles}
    if any(not pools[role] for role in ordered_roles):
        raise _CandidatePreparationInvalid
    occurrence_counts: dict[tuple[str, int], int] = {}
    selected: list[_PrivateOperationInstance] = []
    draw_ordinal = 0
    for role in ordered_roles:
        pool = pools[role]
        for role_draw_ordinal in range(len(pool)):
            source = pool[
                _bootstrap_draw_index(
                    operation_seed,
                    stratum_group_spec_id=stratum_group_spec_id,
                    role=role,
                    draw_ordinal=role_draw_ordinal,
                    population_size=len(pool),
                )
            ]
            key = (source.participant_token, source.internal_row_index)
            occurrence_ordinal = occurrence_counts.get(key, 0)
            occurrence_counts[key] = occurrence_ordinal + 1
            selected.append(
                _PrivateOperationInstance(
                    source.participant_token,
                    source.internal_row_index,
                    source.role,
                    draw_ordinal,
                    occurrence_ordinal,
                )
            )
            draw_ordinal += 1
    selected_keys = {(row.participant_token, row.internal_row_index) for row in selected}
    unique_membership = tuple(
        row
        for row in memberships
        if (row.participant_token, row.internal_row_index) in selected_keys
    )
    return tuple(selected), unique_membership


def _stratified_bootstrap_membership_and_arrays(
    canonical: Any,
    operation: Mapping[str, Any],
    operation_seed: str,
) -> tuple[
    tuple[_PrivateMembership, ...],
    tuple[_PrivateMembership, ...],
    tuple[_PrivateOperationInstance, ...],
    tuple[_PrivateMembership, ...],
    Mapping[str, _ProtocolArray],
]:
    memberships, _ordinary_instances, _ordinary_arrays = _private_membership_and_arrays(canonical)
    source_rows_by_internal = cast(
        Sequence[int],
        canonical.private.source_row_manifest["source_row_index_by_internal_index"],
    )
    pre_operation_memberships = tuple(
        memberships[internal_index]
        for internal_index in sorted(
            range(len(memberships)),
            key=lambda internal_index: source_rows_by_internal[internal_index],
        )
    )
    instances, unique_membership = _stratified_bootstrap_instances(
        pre_operation_memberships, operation, operation_seed
    )
    source_values = canonical.private.arrays["event_values"]
    source_group_codes = canonical.private.arrays["group_role_codes"]
    source_indexes = np.asarray([row.internal_row_index for row in instances], dtype=np.int64)
    arrays: dict[str, _ProtocolArray] = {
        "train_values": _freeze_array(source_values[source_indexes], dtype=np.dtype("float64")),
        "training_row_indexes": _freeze_array(
            np.arange(len(instances), dtype=np.int64), dtype=np.dtype("int64")
        ),
        "train_group_codes": _freeze_array(
            source_group_codes[source_indexes], dtype=np.dtype("int32")
        ),
        "evaluation_values": _freeze_array(source_values, dtype=np.dtype("float64")),
        "evaluation_row_indexes": _freeze_array(
            canonical.private.arrays["participant_internal_indexes"],
            dtype=np.dtype("int64"),
        ),
        "evaluation_group_codes": _freeze_array(source_group_codes, dtype=np.dtype("int32")),
    }
    frozen_arrays = MappingProxyType(arrays)
    if not _arrays_are_exactly_frozen(frozen_arrays):
        raise UniverseIdentityError("Prepared execution arrays are not exact immutable copies.")
    return (
        memberships,
        pre_operation_memberships,
        instances,
        unique_membership,
        frozen_arrays,
    )


def _stratified_subsample_membership_and_arrays(
    canonical: Any,
    operation: Mapping[str, Any],
    operation_seed: str,
    *,
    minimum_reference_rows: int | None,
) -> tuple[
    tuple[_PrivateMembership, ...],
    tuple[_PrivateMembership, ...],
    _StratifiedSubsamplePlan,
    Mapping[str, _ProtocolArray],
]:
    """Realize retained training rows while keeping the full source evaluation cohort."""

    memberships, _ordinary_instances, _ordinary_arrays = _private_membership_and_arrays(canonical)
    source_rows_by_internal = cast(
        Sequence[int],
        canonical.private.source_row_manifest["source_row_index_by_internal_index"],
    )
    pre_operation_memberships = tuple(
        memberships[internal_index]
        for internal_index in sorted(
            range(len(memberships)),
            key=lambda internal_index: source_rows_by_internal[internal_index],
        )
    )
    plan = _stratified_subsample_plan(
        pre_operation_memberships,
        operation,
        operation_seed,
        minimum_reference_rows=minimum_reference_rows,
    )
    source_indexes = np.asarray(
        [row.internal_row_index for row in plan.instances],
        dtype=np.int64,
    )
    source_values = canonical.private.arrays["event_values"]
    source_group_codes = canonical.private.arrays["group_role_codes"]
    arrays: dict[str, _ProtocolArray] = {
        "train_values": _freeze_array(
            source_values[source_indexes],
            dtype=np.dtype("float64"),
        ),
        "training_row_indexes": _freeze_array(
            np.arange(plan.retained_total, dtype=np.int64),
            dtype=np.dtype("int64"),
        ),
        "train_group_codes": _freeze_array(
            source_group_codes[source_indexes],
            dtype=np.dtype("int32"),
        ),
        "evaluation_values": _freeze_array(
            source_values,
            dtype=np.dtype("float64"),
        ),
        "evaluation_row_indexes": _freeze_array(
            canonical.private.arrays["participant_internal_indexes"],
            dtype=np.dtype("int64"),
        ),
        "evaluation_group_codes": _freeze_array(
            source_group_codes,
            dtype=np.dtype("int32"),
        ),
    }
    frozen_arrays = MappingProxyType(arrays)
    if not _arrays_are_exactly_frozen(frozen_arrays):
        raise UniverseIdentityError("Prepared execution arrays are not exact immutable copies.")
    return memberships, pre_operation_memberships, plan, frozen_arrays


def _leave_one_out_membership_and_arrays(
    canonical: Any,
    operation: Mapping[str, Any],
) -> tuple[
    tuple[_PrivateMembership, ...],
    tuple[_PrivateMembership, ...],
    tuple[_PrivateOperationInstance, ...],
    tuple[_PrivateMembership, ...],
    tuple[_PrivateMembership, ...],
    Mapping[str, _ProtocolArray],
]:
    """Realize one exact private removal while retaining a fixed non-removed cohort."""

    memberships, _ordinary_instances, _ordinary_arrays = _private_membership_and_arrays(canonical)
    pre_operation_memberships = tuple(sorted(memberships, key=lambda row: row.internal_row_index))
    removal_slot = operation["removal_slot_ordinal"]
    if (
        type(removal_slot) is not int
        or removal_slot < 0
        or removal_slot >= len(pre_operation_memberships)
    ):
        raise UniverseIdentityError("An influence removal slot is outside private membership.")
    removed_membership = (pre_operation_memberships[removal_slot],)
    retained_membership = tuple(
        row for ordinal, row in enumerate(pre_operation_memberships) if ordinal != removal_slot
    )
    if not retained_membership or {row.role for row in retained_membership} != {
        "reference",
        "at_risk",
    }:
        raise _CandidatePreparationInvalid
    instances = tuple(
        _PrivateOperationInstance(
            row.participant_token,
            row.internal_row_index,
            row.role,
            draw_ordinal,
            0,
        )
        for draw_ordinal, row in enumerate(retained_membership)
    )
    source_indexes = np.asarray(
        [row.internal_row_index for row in retained_membership],
        dtype=np.int64,
    )
    source_values = canonical.private.arrays["event_values"]
    source_group_codes = canonical.private.arrays["group_role_codes"]
    contiguous_indexes = np.arange(len(retained_membership), dtype=np.int64)
    arrays: dict[str, _ProtocolArray] = {
        "train_values": _freeze_array(
            source_values[source_indexes],
            dtype=np.dtype("float64"),
        ),
        "training_row_indexes": _freeze_array(
            contiguous_indexes,
            dtype=np.dtype("int64"),
        ),
        "train_group_codes": _freeze_array(
            source_group_codes[source_indexes],
            dtype=np.dtype("int32"),
        ),
        "evaluation_values": _freeze_array(
            source_values[source_indexes],
            dtype=np.dtype("float64"),
        ),
        "evaluation_row_indexes": _freeze_array(
            contiguous_indexes,
            dtype=np.dtype("int64"),
        ),
        "evaluation_group_codes": _freeze_array(
            source_group_codes[source_indexes],
            dtype=np.dtype("int32"),
        ),
    }
    frozen_arrays = MappingProxyType(arrays)
    if not _arrays_are_exactly_frozen(frozen_arrays):
        raise UniverseIdentityError("Prepared execution arrays are not exact immutable copies.")
    return (
        memberships,
        pre_operation_memberships,
        instances,
        retained_membership,
        removed_membership,
        frozen_arrays,
    )


def _dataset_projection(
    spec: Mapping[str, Any],
    canonical: Any,
    arrays: Mapping[str, _ProtocolArray],
    *,
    training_prepared_data_digest: str | None = None,
    conformance_demo_provenance: _ConformanceDemoProvenance | None = None,
) -> dict[str, Any]:
    semantics = {
        "evaluation_group_codes": "canonical-group-code/1",
        "evaluation_row_indexes": "contiguous-internal-row-index/1",
        "evaluation_values": "event-value-matrix/1",
        "train_group_codes": "canonical-group-code/1",
        "training_row_indexes": "contiguous-internal-row-index/1",
        "train_values": "event-value-matrix/1",
    }
    selected_arrays = arrays
    if conformance_demo_provenance is not None:
        selected_arrays = {
            name: arrays[name]
            for name in ("train_values", "training_row_indexes", "train_group_codes")
        }
    catalog = {
        name: array_catalog_entry(name, array, semantic_version=semantics[name])
        for name, array in selected_arrays.items()
    }
    preprocessing_manifest_digest = structured_sha256(
        "ebm-audit/preprocessing-manifest/1",
        {
            "preprocessing": spec["preprocessing"],
            "missingness_policy": spec["missingness_policy"],
            "outlier_policy": spec["outlier_policy"],
            "covariate_adjustment": spec["covariate_adjustment"],
        },
    )
    if training_prepared_data_digest is None:
        variant_id = canonical.view.variant_id
        participant_count = canonical.view.participant_count
        evaluation_participant_count = canonical.view.participant_count
        scientific_data_digest = canonical.scientific_data_digest
    else:
        variant_id = spec["dataset_variant_intent"]["source_variant_id"]
        participant_count = int(arrays["train_values"].shape[0])
        evaluation_participant_count = int(arrays["evaluation_values"].shape[0])
        scientific_data_digest = training_prepared_data_digest
    provenance: dict[str, Any] | None = None
    if conformance_demo_provenance is not None:
        provenance = _closed_object(conformance_demo_provenance.record_bytes)
        event_ids = [row["event_id"] for row in spec["event_set"]]
        if (
            provenance["participant_count"] != participant_count
            or provenance["event_count"] != canonical.view.event_count
            or provenance["event_ids"] != event_ids
        ):
            raise UniverseIdentityError("The conformance demo provenance is detached.")
        evaluation_participant_count = 0
    projection = {
        "variant_id": variant_id,
        "participant_count": participant_count,
        "evaluation_participant_count": evaluation_participant_count,
        "event_count": canonical.view.event_count,
        "event_ids": [row["event_id"] for row in spec["event_set"]],
        "event_directions": [
            spec["event_directions"][row["event_id"]] for row in spec["event_set"]
        ],
        "group_codebook": {"0": "reference", "1": "at_risk"},
        "training_row_index_array": "training_row_indexes",
        "evaluation_row_index_array": (
            None if conformance_demo_provenance is not None else "evaluation_row_indexes"
        ),
        "array_catalog": catalog,
        "stage_semantics": "strict-prefix-count/1",
        "stage_semantics_digest": spec["backend"]["stage_semantics_digest"],
        "preprocessing_manifest_digest": preprocessing_manifest_digest,
        "scientific_data_digest": scientific_data_digest,
    }
    if provenance is not None:
        projection["synthetic_provenance"] = provenance
    try:
        validate_instance(projection, "worker-protocol.schema.json", definition="DatasetDescriptor")
    except SchemaValidationError:
        raise UniverseIdentityError("The prepared worker dataset projection is invalid.") from None
    return projection


def _public_universe_fields(
    *,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    prepared_dataset_id: str,
    audit_dataset_digest: str,
    canonical: Any,
    memberships: tuple[_PrivateMembership, ...],
    instances: tuple[_PrivateOperationInstance, ...],
) -> tuple[dict[str, Any], bytes]:
    accounting = canonical.view.data_accounting.to_record()
    private_membership = [row._asdict() for row in memberships]
    private_instances = [row._asdict() for row in instances]
    source_accounting = {
        "stage": "source",
        "prepared_dataset_id": prepared_dataset_id,
        "audit_dataset_digest": audit_dataset_digest,
        "ordered_membership": private_membership,
    }
    training_accounting = {
        "stage": "training",
        "scientific_data_digest": canonical.scientific_data_digest,
        "ordered_instances": private_instances,
        "data_accounting": accounting,
    }
    evaluation_accounting = {
        "stage": "evaluation",
        "scientific_data_digest": canonical.scientific_data_digest,
        "ordered_membership": private_membership,
    }
    role_counts = _role_counts_from_membership(memberships)
    instance_role_counts = _role_counts_from_instances(instances)
    participant_count = len(memberships)
    counts = {
        "source_participant_count": participant_count,
        "cohort_eligible_participant_count": participant_count,
        "pre_operation_eligible_participant_count": participant_count,
        "operation_output_participant_instance_count": participant_count,
        "operation_output_unique_participant_count": participant_count,
        "training_participant_instance_count": participant_count,
        "training_unique_participant_count": participant_count,
        "evaluation_participant_count": participant_count,
        "cohort_role_counts": role_counts,
        "pre_operation_role_counts": role_counts,
        "operation_output_role_counts": instance_role_counts,
        "training_role_counts": instance_role_counts,
        "evaluation_role_counts": role_counts,
        "event_count": canonical.view.event_count,
        "operation_transformed_cell_count": 0,
        "operation_transformed_label_count": 0,
        "preprocessing_transformed_cell_count": 0,
        "preprocessing_flagged_cell_count": 0,
        "preprocessing_masked_cell_count": 0,
        "fit_ready_missing_cell_count": 0,
    }
    fields = {
        "source_prepared_data_digest": audit_dataset_digest,
        "training_prepared_data_digest": canonical.scientific_data_digest,
        "evaluation_prepared_data_digest": canonical.scientific_data_digest,
        "evaluation_membership_digest": _private_evaluation_membership_digest(
            cast(str, plan["plan_digest"]), memberships
        ),
        "source_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", source_accounting
        ),
        "training_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", training_accounting
        ),
        "evaluation_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", evaluation_accounting
        ),
        "aggregate_counts": counts,
    }
    transition = {
        "transition_schema_version": "ebm-audit-private-preparation-transition/2.0",
        "plan_digest": plan["plan_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "source_accounting": source_accounting,
        "training_accounting": training_accounting,
        "evaluation_accounting": evaluation_accounting,
        "affected_cells": [],
        "fitted_parameters": [],
        "stratum_allocations": [],
        "removed_membership": [],
        "public_fields": fields,
    }
    return fields, canonical_json_bytes(transition)


def _fixed_event_rescale_public_universe_fields(
    *,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    prepared_dataset_id: str,
    audit_dataset_digest: str,
    canonical: Any,
    memberships: tuple[_PrivateMembership, ...],
    instances: tuple[_PrivateOperationInstance, ...],
    arrays: Mapping[str, _ProtocolArray],
    changed_cell_count: int,
    source_analysis_spec_id: str,
) -> tuple[dict[str, Any], bytes]:
    """Bind the exact fixed preprocessing transform and its aggregate accounting."""

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    transform = cast(Sequence[Mapping[str, Any]], spec["preprocessing"])[0]
    train_catalog = array_catalog_entry(
        "train_values",
        arrays["train_values"],
        semantic_version="event-value-matrix/1",
    )
    training_digest = structured_sha256(
        "ebm-audit/fixed-event-rescale-prepared-data/1",
        {
            "prepared_data_schema_version": (
                "ebm-audit-fixed-event-rescale-prepared-data/1.0"
            ),
            "source_scientific_data_digest": canonical.scientific_data_digest,
            "source_analysis_spec_id": source_analysis_spec_id,
            "analysis_spec_id": candidate["analysis_spec_id"],
            "transformation": transform,
            "transformed_train_values_array_digest": train_catalog["array_digest"],
        },
    )
    private_membership = [row._asdict() for row in memberships]
    private_instances = [row._asdict() for row in instances]
    source_accounting = {
        "stage": "source",
        "prepared_dataset_id": prepared_dataset_id,
        "audit_dataset_digest": audit_dataset_digest,
        "ordered_membership": private_membership,
    }
    parameter_digest = structured_sha256(
        "ebm-audit/fixed-event-rescale-operation/1",
        transform,
    )
    accounting_operation = {
        "operation_id": "fixed-event-rescale",
        "method_id": _FIXED_EVENT_RESCALE_METHOD_ID,
        "universe_decision_id": candidate["candidate_id"],
        "reason_code": "PREPARATION.FIXED_EVENT_RESCALE",
        "rationale": "Declared fixed public event rescale with no fitted parameters.",
        "participant_count": len(memberships),
        "event_count": canonical.view.event_count,
        "cell_count": changed_cell_count,
        "affected_event_ids": list(canonical.view.event_ids),
        "affected_auxiliary_array_names": [],
        "parameter_digest": parameter_digest,
        "input_digest": canonical.scientific_data_digest,
        "output_digest": training_digest,
    }
    data_accounting = {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": len(memberships),
        "output_participants": len(memberships),
        "input_events": canonical.view.event_count,
        "output_events": canonical.view.event_count,
        "input_missing_cells": 0,
        "output_missing_cells": 0,
        "flagged_cells": 0,
        "masked_cells": 0,
        "transformed_cells": changed_cell_count,
        "added_participant_instances": 0,
        "removed_participants": 0,
        "removed_events": 0,
        "operations": [accounting_operation],
    }
    try:
        validate_instance(
            data_accounting,
            "canonical-records.schema.json",
            definition="DataAccounting",
        )
    except SchemaValidationError:
        raise UniverseIdentityError(
            "Fixed rescale preprocessing produced invalid exact data accounting."
        ) from None
    training_accounting = {
        "stage": "training",
        "scientific_data_digest": training_digest,
        "ordered_instances": private_instances,
        "data_accounting": data_accounting,
    }
    evaluation_accounting = {
        "stage": "evaluation",
        "scientific_data_digest": training_digest,
        "ordered_membership": private_membership,
    }
    role_counts = _role_counts_from_membership(memberships)
    instance_role_counts = _role_counts_from_instances(instances)
    participant_count = len(memberships)
    counts = {
        "source_participant_count": participant_count,
        "cohort_eligible_participant_count": participant_count,
        "pre_operation_eligible_participant_count": participant_count,
        "operation_output_participant_instance_count": participant_count,
        "operation_output_unique_participant_count": participant_count,
        "training_participant_instance_count": participant_count,
        "training_unique_participant_count": participant_count,
        "evaluation_participant_count": participant_count,
        "cohort_role_counts": role_counts,
        "pre_operation_role_counts": role_counts,
        "operation_output_role_counts": instance_role_counts,
        "training_role_counts": instance_role_counts,
        "evaluation_role_counts": role_counts,
        "event_count": canonical.view.event_count,
        "operation_transformed_cell_count": 0,
        "operation_transformed_label_count": 0,
        "preprocessing_transformed_cell_count": changed_cell_count,
        "preprocessing_flagged_cell_count": 0,
        "preprocessing_masked_cell_count": 0,
        "fit_ready_missing_cell_count": 0,
    }
    fields = {
        "source_prepared_data_digest": audit_dataset_digest,
        "training_prepared_data_digest": training_digest,
        "evaluation_prepared_data_digest": training_digest,
        "evaluation_membership_digest": _private_evaluation_membership_digest(
            cast(str, plan["plan_digest"]), memberships
        ),
        "source_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", source_accounting
        ),
        "training_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", training_accounting
        ),
        "evaluation_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", evaluation_accounting
        ),
        "aggregate_counts": counts,
    }
    transition = {
        "transition_schema_version": "ebm-audit-private-preparation-transition/2.0",
        "plan_digest": plan["plan_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "source_analysis_spec_id": source_analysis_spec_id,
        "source_accounting": source_accounting,
        "training_accounting": training_accounting,
        "evaluation_accounting": evaluation_accounting,
        "affected_cells": [
            {"event_id": event_id, "participant_count": participant_count}
            for event_id in canonical.view.event_ids
        ],
        "fitted_parameters": [],
        "stratum_allocations": [],
        "removed_membership": [],
        "public_fields": fields,
    }
    return fields, canonical_json_bytes(transition)


def _bootstrap_training_prepared_data_digest(
    *,
    source_scientific_data_digest: str,
    analysis_spec_id: str,
    operation_seed: str,
    pre_operation_memberships: Sequence[_PrivateMembership],
    instances: Sequence[_PrivateOperationInstance],
) -> str:
    """Commit the exact ordered bootstrap instances without publishing their map."""

    membership_positions = {
        (row.participant_token, row.internal_row_index): position
        for position, row in enumerate(pre_operation_memberships)
    }
    if len(membership_positions) != len(pre_operation_memberships):
        raise UniverseIdentityError(
            "Bootstrap pre-operation membership contains duplicate private identities."
        )
    try:
        ordered_instances = [
            {
                "pre_operation_membership_position": membership_positions[
                    (row.participant_token, row.internal_row_index)
                ],
                "role": row.role,
                "draw_ordinal": row.draw_ordinal,
                "occurrence_ordinal": row.occurrence_ordinal,
            }
            for row in instances
        ]
    except KeyError:
        raise UniverseIdentityError(
            "Bootstrap draw contains an identity outside pre-operation membership."
        ) from None
    return structured_sha256(
        "ebm-audit/stratified-bootstrap-prepared-data/1",
        {
            "prepared_data_schema_version": ("ebm-audit-stratified-bootstrap-prepared-data/1.0"),
            "source_scientific_data_digest": source_scientific_data_digest,
            "analysis_spec_id": analysis_spec_id,
            "operation_seed": operation_seed,
            "ordered_pre_operation_membership_instances": ordered_instances,
        },
    )


def _bootstrap_public_universe_fields(
    *,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    prepared_dataset_id: str,
    audit_dataset_digest: str,
    source_scientific_data_digest: str,
    event_count: int,
    memberships: tuple[_PrivateMembership, ...],
    pre_operation_memberships: tuple[_PrivateMembership, ...],
    instances: tuple[_PrivateOperationInstance, ...],
    unique_membership: tuple[_PrivateMembership, ...],
    operation_seed: str,
) -> tuple[dict[str, Any], bytes]:
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    private_membership = [row._asdict() for row in memberships]
    private_instances = [row._asdict() for row in instances]
    private_unique_membership = [row._asdict() for row in unique_membership]
    training_prepared_data_digest = _bootstrap_training_prepared_data_digest(
        source_scientific_data_digest=source_scientific_data_digest,
        analysis_spec_id=cast(str, candidate["analysis_spec_id"]),
        operation_seed=operation_seed,
        pre_operation_memberships=pre_operation_memberships,
        instances=instances,
    )
    operation_parameters_digest = structured_sha256(
        "ebm-audit/stratified-bootstrap-operation/1", operation
    )
    operation_identity = {
        "kind": "bootstrap",
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "source_variant_id": operation["source_variant_id"],
        "derived_source_variant_id": operation["derived_source_variant_id"],
        "replicate_ordinal": operation["replicate_ordinal"],
        "sampling_method_id": operation["sampling_method_id"],
        "sampling_design": operation["sampling_design"],
        "strata_group_spec_ids": copy.deepcopy(operation["strata_group_spec_ids"]),
        "refit_preprocessing": operation["refit_preprocessing"],
        "fixed_evaluation_cohort_policy": operation["fixed_evaluation_cohort_policy"],
        "operation_seed": operation_seed,
        "operation_parameters_digest": operation_parameters_digest,
    }
    source_accounting = {
        "stage": "source",
        "prepared_dataset_id": prepared_dataset_id,
        "audit_dataset_digest": audit_dataset_digest,
        "ordered_membership": private_membership,
    }
    cohort_accounting = {
        "stage": "cohort",
        "ordered_membership": private_membership,
    }
    pre_operation_accounting = {
        "stage": "pre-operation",
        "ordered_membership": [row._asdict() for row in pre_operation_memberships],
    }
    operation_accounting = {
        "stage": "operation",
        "operation_identity": operation_identity,
        "ordered_instances": private_instances,
        "ordered_unique_membership": private_unique_membership,
    }
    accounting_operation = {
        "operation_id": "stratified-participant-bootstrap",
        "method_id": "participant-bootstrap-with-replacement-v1",
        "universe_decision_id": candidate["candidate_id"],
        "reason_code": "PREPARATION.STRATIFIED_BOOTSTRAP",
        "rationale": "Declared participant bootstrap with replacement inside each required role.",
        "participant_count": len(instances),
        "event_count": event_count,
        "cell_count": 0,
        "affected_event_ids": [],
        "affected_auxiliary_array_names": [],
        "parameter_digest": operation_parameters_digest,
        "input_digest": source_scientific_data_digest,
        "output_digest": training_prepared_data_digest,
    }
    data_accounting = {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": len(memberships),
        "output_participants": len(unique_membership),
        "input_events": event_count,
        "output_events": event_count,
        "input_missing_cells": 0,
        "output_missing_cells": 0,
        "flagged_cells": 0,
        "masked_cells": 0,
        "transformed_cells": 0,
        "added_participant_instances": len(instances) - len(unique_membership),
        "removed_participants": len(memberships) - len(unique_membership),
        "removed_events": 0,
        "operations": [accounting_operation],
    }
    try:
        validate_instance(
            data_accounting, "canonical-records.schema.json", definition="DataAccounting"
        )
    except SchemaValidationError:
        raise UniverseIdentityError(
            "Bootstrap preparation produced invalid exact data accounting."
        ) from None
    training_accounting = {
        "stage": "training",
        "scientific_data_digest": training_prepared_data_digest,
        "ordered_instances": private_instances,
        "data_accounting": data_accounting,
    }
    evaluation_accounting = {
        "stage": "evaluation",
        "scientific_data_digest": source_scientific_data_digest,
        "ordered_membership": private_membership,
    }
    stratum_allocations: list[dict[str, Any]] = []
    for group_spec_id in cast(Sequence[str], operation["strata_group_spec_ids"]):
        for role in ("reference", "at_risk"):
            source_rows = [row._asdict() for row in pre_operation_memberships if row.role == role]
            drawn_rows = [row._asdict() for row in instances if row.role == role]
            allocation_preimage = {
                "allocation_schema_version": ("ebm-audit-private-stratum-allocation/1.0"),
                "strata_group_spec_id": group_spec_id,
                "role": role,
                "source_membership": source_rows,
                "source_unique_participant_count": len(source_rows),
                "ordered_draw_instances": drawn_rows,
                "draw_participant_instance_count": len(drawn_rows),
                "draw_unique_participant_count": len(
                    {(row["participant_token"], row["internal_row_index"]) for row in drawn_rows}
                ),
            }
            stratum_allocations.append(
                {
                    **allocation_preimage,
                    "allocation_digest": structured_sha256(
                        "ebm-audit/private-stratum-allocation/1",
                        allocation_preimage,
                    ),
                }
            )
    role_counts = _role_counts_from_membership(memberships)
    instance_role_counts = _role_counts_from_instances(instances)
    unique_count = len(unique_membership)
    counts = {
        "source_participant_count": len(memberships),
        "cohort_eligible_participant_count": len(memberships),
        "pre_operation_eligible_participant_count": len(memberships),
        "operation_output_participant_instance_count": len(instances),
        "operation_output_unique_participant_count": unique_count,
        "training_participant_instance_count": len(instances),
        "training_unique_participant_count": unique_count,
        "evaluation_participant_count": len(memberships),
        "cohort_role_counts": role_counts,
        "pre_operation_role_counts": role_counts,
        "operation_output_role_counts": instance_role_counts,
        "training_role_counts": instance_role_counts,
        "evaluation_role_counts": role_counts,
        "event_count": event_count,
        "operation_transformed_cell_count": 0,
        "operation_transformed_label_count": 0,
        "preprocessing_transformed_cell_count": 0,
        "preprocessing_flagged_cell_count": 0,
        "preprocessing_masked_cell_count": 0,
        "fit_ready_missing_cell_count": 0,
    }
    fields = {
        "source_prepared_data_digest": audit_dataset_digest,
        "training_prepared_data_digest": training_prepared_data_digest,
        "evaluation_prepared_data_digest": source_scientific_data_digest,
        "evaluation_membership_digest": _private_evaluation_membership_digest(
            cast(str, plan["plan_digest"]), memberships
        ),
        "source_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", source_accounting
        ),
        "training_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", training_accounting
        ),
        "evaluation_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1", evaluation_accounting
        ),
        "aggregate_counts": counts,
    }
    transition = {
        "transition_schema_version": "ebm-audit-private-preparation-transition/2.0",
        "plan_digest": plan["plan_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "operation_identity": operation_identity,
        "source_accounting": source_accounting,
        "cohort_accounting": cohort_accounting,
        "pre_operation_accounting": pre_operation_accounting,
        "operation_accounting": operation_accounting,
        "training_accounting": training_accounting,
        "evaluation_accounting": evaluation_accounting,
        "aggregate_counts": counts,
        "affected_cells": [],
        "fitted_parameters": [],
        "stratum_allocations": stratum_allocations,
        "removed_membership": [],
        "public_fields": fields,
    }
    return fields, canonical_json_bytes(transition)


def _subsample_training_prepared_data_digest(
    *,
    source_scientific_data_digest: str,
    analysis_spec_id: str,
    operation_seed: str,
    pre_operation_memberships: Sequence[_PrivateMembership],
    plan: _StratifiedSubsamplePlan,
) -> str:
    """Commit the selected private training rows without publishing identities."""

    membership_positions = {
        (row.participant_token, row.internal_row_index): position
        for position, row in enumerate(pre_operation_memberships)
    }
    if len(membership_positions) != len(pre_operation_memberships):
        raise UniverseIdentityError(
            "Subsample pre-operation membership contains duplicate private identities."
        )
    try:
        ordered_instances = [
            {
                "pre_operation_membership_position": membership_positions[
                    (row.participant_token, row.internal_row_index)
                ],
                "role": row.role,
                "draw_ordinal": row.draw_ordinal,
                "occurrence_ordinal": row.occurrence_ordinal,
            }
            for row in plan.instances
        ]
    except KeyError:
        raise UniverseIdentityError(
            "Subsample draw contains an identity outside pre-operation membership."
        ) from None
    return structured_sha256(
        "ebm-audit/stratified-subsample-prepared-data/1",
        {
            "prepared_data_schema_version": ("ebm-audit-stratified-subsample-prepared-data/1.0"),
            "allocation_rule_id": _SUBSAMPLE_ALLOCATION_RULE_ID,
            "source_scientific_data_digest": source_scientific_data_digest,
            "analysis_spec_id": analysis_spec_id,
            "operation_seed": operation_seed,
            "retained_total": plan.retained_total,
            "ordered_pre_operation_membership_instances": ordered_instances,
        },
    )


def _subsample_public_universe_fields(
    *,
    plan_owner: Mapping[str, Any],
    candidate: Mapping[str, Any],
    prepared_dataset_id: str,
    audit_dataset_digest: str,
    source_scientific_data_digest: str,
    event_count: int,
    memberships: tuple[_PrivateMembership, ...],
    pre_operation_memberships: tuple[_PrivateMembership, ...],
    subsample_plan: _StratifiedSubsamplePlan,
    operation_seed: str,
) -> tuple[dict[str, Any], bytes]:
    """Build public commitments and the complete private subsample replay."""

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    private_membership = [row._asdict() for row in memberships]
    private_pre_operation_membership = [row._asdict() for row in pre_operation_memberships]
    private_instances = [row._asdict() for row in subsample_plan.instances]
    private_retained_membership = [row._asdict() for row in subsample_plan.retained_membership]
    training_prepared_data_digest = _subsample_training_prepared_data_digest(
        source_scientific_data_digest=source_scientific_data_digest,
        analysis_spec_id=cast(str, candidate["analysis_spec_id"]),
        operation_seed=operation_seed,
        pre_operation_memberships=pre_operation_memberships,
        plan=subsample_plan,
    )
    operation_parameters_digest = structured_sha256(
        "ebm-audit/stratified-subsample-operation/1",
        {
            "allocation_rule_id": _SUBSAMPLE_ALLOCATION_RULE_ID,
            "operation": copy.deepcopy(dict(operation)),
        },
    )
    operation_identity = {
        "kind": "subsample",
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "source_variant_id": operation["source_variant_id"],
        "derived_source_variant_id": operation["derived_source_variant_id"],
        "replicate_ordinal": operation["replicate_ordinal"],
        "sampling_method_id": operation["sampling_method_id"],
        "sampling_design": operation["sampling_design"],
        "retained_fraction": operation["retained_fraction"],
        "retained_count_rounding_rule": operation["retained_count_rounding_rule"],
        "allocation_rule_id": _SUBSAMPLE_ALLOCATION_RULE_ID,
        "retained_total": subsample_plan.retained_total,
        "strata_group_spec_ids": copy.deepcopy(operation["strata_group_spec_ids"]),
        "refit_preprocessing": operation["refit_preprocessing"],
        "fixed_evaluation_cohort_policy": operation["fixed_evaluation_cohort_policy"],
        "operation_seed": operation_seed,
        "operation_parameters_digest": operation_parameters_digest,
    }
    source_accounting = {
        "stage": "source",
        "prepared_dataset_id": prepared_dataset_id,
        "audit_dataset_digest": audit_dataset_digest,
        "ordered_membership": private_membership,
    }
    cohort_accounting = {
        "stage": "cohort",
        "ordered_membership": private_membership,
    }
    pre_operation_accounting = {
        "stage": "pre-operation",
        "ordered_membership": private_pre_operation_membership,
    }
    operation_accounting = {
        "stage": "operation",
        "operation_identity": operation_identity,
        "ordered_instances": private_instances,
        "ordered_unique_membership": private_retained_membership,
    }
    accounting_operation = {
        "operation_id": "stratified-participant-subsample",
        "method_id": "participant-subsample-without-replacement-v1",
        "universe_decision_id": candidate["candidate_id"],
        "reason_code": "PREPARATION.STRATIFIED_SUBSAMPLE",
        "rationale": (
            "Declared global-total participant subsample without replacement "
            "inside each required role."
        ),
        "participant_count": subsample_plan.retained_total,
        "event_count": event_count,
        "cell_count": 0,
        "affected_event_ids": [],
        "affected_auxiliary_array_names": [],
        "parameter_digest": operation_parameters_digest,
        "input_digest": source_scientific_data_digest,
        "output_digest": training_prepared_data_digest,
    }
    data_accounting = {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": len(memberships),
        "output_participants": subsample_plan.retained_total,
        "input_events": event_count,
        "output_events": event_count,
        "input_missing_cells": 0,
        "output_missing_cells": 0,
        "flagged_cells": 0,
        "masked_cells": 0,
        "transformed_cells": 0,
        "added_participant_instances": 0,
        "removed_participants": len(memberships) - subsample_plan.retained_total,
        "removed_events": 0,
        "operations": [accounting_operation],
    }
    try:
        validate_instance(
            data_accounting,
            "canonical-records.schema.json",
            definition="DataAccounting",
        )
    except SchemaValidationError:
        raise UniverseIdentityError(
            "Subsample preparation produced invalid exact data accounting."
        ) from None
    training_accounting = {
        "stage": "training",
        "scientific_data_digest": training_prepared_data_digest,
        "ordered_instances": private_instances,
        "data_accounting": data_accounting,
    }
    evaluation_accounting = {
        "stage": "evaluation",
        "scientific_data_digest": source_scientific_data_digest,
        "ordered_membership": private_membership,
    }
    quotas = {
        "reference": subsample_plan.reference_quota,
        "at_risk": subsample_plan.at_risk_quota,
    }
    hamilton_quotas = {
        "reference": subsample_plan.reference_hamilton_quota,
        "at_risk": subsample_plan.at_risk_hamilton_quota,
    }
    minimums = {
        "reference": subsample_plan.reference_minimum,
        "at_risk": subsample_plan.at_risk_minimum,
    }
    stratum_allocations: list[dict[str, Any]] = []
    [stratum_group_spec_id] = cast(
        Sequence[str],
        operation["strata_group_spec_ids"],
    )
    for role in ("reference", "at_risk"):
        source_rows = [row._asdict() for row in pre_operation_memberships if row.role == role]
        selected_rows = [row._asdict() for row in subsample_plan.instances if row.role == role]
        selected_membership = [
            row._asdict() for row in subsample_plan.retained_membership if row.role == role
        ]
        allocation_preimage = {
            "allocation_schema_version": ("ebm-audit-private-subsample-stratum-allocation/1.0"),
            "allocation_rule_id": _SUBSAMPLE_ALLOCATION_RULE_ID,
            "strata_group_spec_id": stratum_group_spec_id,
            "role": role,
            "global_retained_total": subsample_plan.retained_total,
            "source_membership": source_rows,
            "source_unique_participant_count": len(source_rows),
            "minimum_retained_count": minimums[role],
            "unconstrained_hamilton_quota": hamilton_quotas[role],
            "retained_quota": quotas[role],
            "ordered_draw_instances": selected_rows,
            "ordered_retained_membership": selected_membership,
        }
        stratum_allocations.append(
            {
                **allocation_preimage,
                "allocation_digest": structured_sha256(
                    "ebm-audit/private-subsample-stratum-allocation/1",
                    allocation_preimage,
                ),
            }
        )
    source_role_counts = _role_counts_from_membership(memberships)
    retained_role_counts = _role_counts_from_instances(subsample_plan.instances)
    counts = {
        "source_participant_count": len(memberships),
        "cohort_eligible_participant_count": len(memberships),
        "pre_operation_eligible_participant_count": len(memberships),
        "operation_output_participant_instance_count": subsample_plan.retained_total,
        "operation_output_unique_participant_count": subsample_plan.retained_total,
        "training_participant_instance_count": subsample_plan.retained_total,
        "training_unique_participant_count": subsample_plan.retained_total,
        "evaluation_participant_count": len(memberships),
        "cohort_role_counts": source_role_counts,
        "pre_operation_role_counts": source_role_counts,
        "operation_output_role_counts": retained_role_counts,
        "training_role_counts": retained_role_counts,
        "evaluation_role_counts": source_role_counts,
        "event_count": event_count,
        "operation_transformed_cell_count": 0,
        "operation_transformed_label_count": 0,
        "preprocessing_transformed_cell_count": 0,
        "preprocessing_flagged_cell_count": 0,
        "preprocessing_masked_cell_count": 0,
        "fit_ready_missing_cell_count": 0,
    }
    fields = {
        "source_prepared_data_digest": audit_dataset_digest,
        "training_prepared_data_digest": training_prepared_data_digest,
        "evaluation_prepared_data_digest": source_scientific_data_digest,
        "evaluation_membership_digest": _private_evaluation_membership_digest(
            cast(str, plan_owner["plan_digest"]),
            memberships,
        ),
        "source_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            source_accounting,
        ),
        "training_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            training_accounting,
        ),
        "evaluation_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            evaluation_accounting,
        ),
        "aggregate_counts": counts,
    }
    transition = {
        "transition_schema_version": "ebm-audit-private-preparation-transition/3.0",
        "plan_digest": plan_owner["plan_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "operation_identity": operation_identity,
        "source_accounting": source_accounting,
        "cohort_accounting": cohort_accounting,
        "pre_operation_accounting": pre_operation_accounting,
        "operation_accounting": operation_accounting,
        "training_accounting": training_accounting,
        "evaluation_accounting": evaluation_accounting,
        "aggregate_counts": counts,
        "affected_cells": [],
        "fitted_parameters": [],
        "stratum_allocations": stratum_allocations,
        "removed_membership": [],
        "public_fields": fields,
    }
    return fields, canonical_json_bytes(transition)


def _transformed_null_mapping_record(
    plan: _TransformedNullPlan,
) -> dict[str, Any]:
    """Return the exact private, non-public transformation map."""

    return {
        "mapping_schema_version": "ebm-audit-private-transformed-null-map/1.0",
        "attempt_ordinal": plan.attempt_ordinal,
        "method_id": plan.method_id,
        "label_source_positions": (
            None if plan.label_source_positions is None else list(plan.label_source_positions)
        ),
        "event_source_positions": (
            None
            if plan.event_source_positions is None
            else [list(row) for row in plan.event_source_positions]
        ),
        "generated_values_sha256": (
            None
            if plan.generated_values is None
            else hashlib.sha256(plan.generated_values.tobytes(order="C")).hexdigest()
        ),
        "moved_label_count": plan.moved_label_count,
        "moved_cell_count": plan.moved_cell_count,
        "changed_value_cell_count": plan.changed_value_cell_count,
        "changed_participant_count": plan.changed_participant_count,
        "changed_event_ordinals": list(plan.changed_event_ordinals),
        "participant_event_alignment_changed": (plan.participant_event_alignment_changed),
    }


def _transformed_null_prepared_data_digest(
    *,
    source_scientific_data_digest: str,
    analysis_spec_id: str,
    operation_seed: str,
    mapping_record: Mapping[str, Any],
) -> str:
    """Commit the private transform without serializing it in public artifacts."""

    return structured_sha256(
        "ebm-audit/transformed-null-prepared-data/1",
        {
            "prepared_data_schema_version": ("ebm-audit-transformed-null-prepared-data/1.0"),
            "source_scientific_data_digest": source_scientific_data_digest,
            "analysis_spec_id": analysis_spec_id,
            "operation_seed": operation_seed,
            "private_mapping": copy.deepcopy(dict(mapping_record)),
        },
    )


def _transformed_null_public_universe_fields(
    *,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    prepared_dataset_id: str,
    audit_dataset_digest: str,
    source_scientific_data_digest: str,
    event_ids: Sequence[str],
    null_plan: _TransformedNullPlan,
    operation_seed: str,
) -> tuple[dict[str, Any], bytes]:
    """Bind one effective transformed null to public aggregate commitments."""

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    mapping_record = _transformed_null_mapping_record(null_plan)
    training_prepared_data_digest = _transformed_null_prepared_data_digest(
        source_scientific_data_digest=source_scientific_data_digest,
        analysis_spec_id=cast(str, candidate["analysis_spec_id"]),
        operation_seed=operation_seed,
        mapping_record=mapping_record,
    )
    operation_parameters_digest = structured_sha256(
        "ebm-audit/transformed-null-operation/1",
        operation,
    )
    operation_identity = {
        "kind": "null",
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "source_variant_id": operation["source_variant_id"],
        "derived_source_variant_id": operation["derived_source_variant_id"],
        "replicate_ordinal": operation["replicate_ordinal"],
        "null_family_id": operation["null_family_id"],
        "null_method_id": operation["null_method_id"],
        "transformation": operation["transformation"],
        "within_group_spec_id": operation["within_group_spec_id"],
        "refit_preprocessing": operation["refit_preprocessing"],
        "preserves_group_conditional_event_marginals": operation[
            "preserves_group_conditional_event_marginals"
        ],
        "operation_seed": operation_seed,
        "operation_parameters_digest": operation_parameters_digest,
    }
    source_membership = [row._asdict() for row in null_plan.source_membership]
    transformed_membership = [row._asdict() for row in null_plan.transformed_membership]
    transformed_instances = [row._asdict() for row in null_plan.transformed_instances]
    source_accounting = {
        "stage": "source",
        "prepared_dataset_id": prepared_dataset_id,
        "audit_dataset_digest": audit_dataset_digest,
        "ordered_membership": source_membership,
    }
    cohort_accounting = {
        "stage": "cohort",
        "ordered_membership": source_membership,
    }
    pre_operation_accounting = {
        "stage": "pre-operation",
        "ordered_membership": source_membership,
    }
    operation_accounting = {
        "stage": "operation",
        "operation_identity": operation_identity,
        "ordered_instances": transformed_instances,
        "ordered_unique_membership": transformed_membership,
    }
    if null_plan.method_id == "pure-no-signal-synthetic/1":
        affected_event_ids = list(event_ids)
        affected_participant_count = null_plan.changed_participant_count
        accounting_operation_id = "pure-no-signal-synthetic"
        accounting_method_id = "pure-no-signal-synthetic-v1"
        accounting_reason_code = "PREPARATION.PURE_NO_SIGNAL_SYNTHETIC"
        accounting_rationale = (
            "Declared independently generated synthetic no-signal values with exact refit."
        )
    elif null_plan.event_source_positions is None:
        affected_event_ids: list[str] = []
        affected_participant_count = null_plan.moved_label_count
        accounting_operation_id = "group-label-permutation"
        accounting_method_id = "label-permutation-v1"
        accounting_reason_code = "PREPARATION.LABEL_PERMUTATION"
        accounting_rationale = (
            "Declared effective global group-label permutation with exact count preservation."
        )
    else:
        affected_event_ids = [event_ids[ordinal] for ordinal in null_plan.changed_event_ordinals]
        affected_participant_count = null_plan.changed_participant_count
        accounting_operation_id = "within-group-feature-permutation"
        accounting_method_id = "featurewise-within-group-permutation-v1"
        accounting_reason_code = "PREPARATION.WITHIN_GROUP_FEATURE_PERMUTATION"
        accounting_rationale = "Declared independent event permutation within each analysis group."
    accounting_operation = {
        "operation_id": accounting_operation_id,
        "method_id": accounting_method_id,
        "universe_decision_id": candidate["candidate_id"],
        "reason_code": accounting_reason_code,
        "rationale": accounting_rationale,
        "participant_count": affected_participant_count,
        "event_count": len(affected_event_ids),
        "cell_count": null_plan.changed_value_cell_count,
        "affected_event_ids": affected_event_ids,
        "affected_auxiliary_array_names": [],
        "parameter_digest": operation_parameters_digest,
        "input_digest": source_scientific_data_digest,
        "output_digest": training_prepared_data_digest,
    }
    data_accounting = {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": len(null_plan.source_membership),
        "output_participants": len(null_plan.transformed_membership),
        "input_events": len(event_ids),
        "output_events": len(event_ids),
        "input_missing_cells": 0,
        "output_missing_cells": 0,
        "flagged_cells": 0,
        "masked_cells": 0,
        "transformed_cells": null_plan.changed_value_cell_count,
        "added_participant_instances": 0,
        "removed_participants": 0,
        "removed_events": 0,
        "operations": [accounting_operation],
    }
    try:
        validate_instance(
            data_accounting,
            "canonical-records.schema.json",
            definition="DataAccounting",
        )
    except SchemaValidationError:
        raise UniverseIdentityError(
            "Transformed-null preparation produced invalid exact data accounting."
        ) from None
    training_accounting = {
        "stage": "training",
        "scientific_data_digest": training_prepared_data_digest,
        "ordered_instances": transformed_instances,
        "data_accounting": data_accounting,
    }
    evaluation_accounting = {
        "stage": "evaluation",
        "scientific_data_digest": training_prepared_data_digest,
        "ordered_membership": transformed_membership,
    }
    source_role_counts = _role_counts_from_membership(null_plan.source_membership)
    transformed_role_counts = _role_counts_from_membership(null_plan.transformed_membership)
    transformed_instance_role_counts = _role_counts_from_instances(null_plan.transformed_instances)
    participant_count = len(null_plan.source_membership)
    counts = {
        "source_participant_count": participant_count,
        "cohort_eligible_participant_count": participant_count,
        "pre_operation_eligible_participant_count": participant_count,
        "operation_output_participant_instance_count": participant_count,
        "operation_output_unique_participant_count": participant_count,
        "training_participant_instance_count": participant_count,
        "training_unique_participant_count": participant_count,
        "evaluation_participant_count": participant_count,
        "cohort_role_counts": source_role_counts,
        "pre_operation_role_counts": source_role_counts,
        "operation_output_role_counts": transformed_instance_role_counts,
        "training_role_counts": transformed_instance_role_counts,
        "evaluation_role_counts": transformed_role_counts,
        "event_count": len(event_ids),
        "operation_transformed_cell_count": null_plan.changed_value_cell_count,
        "operation_transformed_label_count": null_plan.moved_label_count,
        "preprocessing_transformed_cell_count": 0,
        "preprocessing_flagged_cell_count": 0,
        "preprocessing_masked_cell_count": 0,
        "fit_ready_missing_cell_count": 0,
    }
    fields = {
        "source_prepared_data_digest": audit_dataset_digest,
        "training_prepared_data_digest": training_prepared_data_digest,
        "evaluation_prepared_data_digest": training_prepared_data_digest,
        "evaluation_membership_digest": _private_evaluation_membership_digest(
            cast(str, plan["plan_digest"]),
            null_plan.transformed_membership,
        ),
        "source_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            source_accounting,
        ),
        "training_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            training_accounting,
        ),
        "evaluation_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            evaluation_accounting,
        ),
        "aggregate_counts": counts,
    }
    transition = {
        "transition_schema_version": "ebm-audit-private-preparation-transition/2.0",
        "plan_digest": plan["plan_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "operation_identity": operation_identity,
        "source_accounting": source_accounting,
        "cohort_accounting": cohort_accounting,
        "pre_operation_accounting": pre_operation_accounting,
        "operation_accounting": operation_accounting,
        "training_accounting": training_accounting,
        "evaluation_accounting": evaluation_accounting,
        "aggregate_counts": counts,
        "null_transformation": mapping_record,
        "affected_cells": [],
        "fitted_parameters": [],
        "stratum_allocations": [],
        "removed_membership": [],
        "public_fields": fields,
    }
    return fields, canonical_json_bytes(transition)


def _influence_prepared_data_digest(
    *,
    source_scientific_data_digest: str,
    analysis_spec_id: str,
    removal_slot_ordinal: int,
    pre_operation_memberships: Sequence[_PrivateMembership],
    retained_membership: Sequence[_PrivateMembership],
) -> str:
    """Commit one exact removal without publishing the private identity map."""

    membership_positions = {
        (row.participant_token, row.internal_row_index): position
        for position, row in enumerate(pre_operation_memberships)
    }
    if len(membership_positions) != len(pre_operation_memberships):
        raise UniverseIdentityError(
            "Influence pre-operation membership contains duplicate private identities."
        )
    try:
        retained_positions = [
            membership_positions[(row.participant_token, row.internal_row_index)]
            for row in retained_membership
        ]
    except KeyError:
        raise UniverseIdentityError(
            "Influence retention contains an identity outside pre-operation membership."
        ) from None
    expected_positions = [
        position
        for position in range(len(pre_operation_memberships))
        if position != removal_slot_ordinal
    ]
    if retained_positions != expected_positions:
        raise UniverseIdentityError("Influence retention does not match its exact removal slot.")
    return structured_sha256(
        "ebm-audit/leave-one-out-prepared-data/1",
        {
            "prepared_data_schema_version": "ebm-audit-leave-one-out-prepared-data/1.0",
            "source_scientific_data_digest": source_scientific_data_digest,
            "analysis_spec_id": analysis_spec_id,
            "removal_slot_ordinal": removal_slot_ordinal,
            "ordered_retained_pre_operation_membership_positions": retained_positions,
        },
    )


def _influence_public_universe_fields(
    *,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    prepared_dataset_id: str,
    audit_dataset_digest: str,
    source_scientific_data_digest: str,
    event_count: int,
    memberships: tuple[_PrivateMembership, ...],
    pre_operation_memberships: tuple[_PrivateMembership, ...],
    instances: tuple[_PrivateOperationInstance, ...],
    retained_membership: tuple[_PrivateMembership, ...],
    removed_membership: tuple[_PrivateMembership, ...],
) -> tuple[dict[str, Any], bytes]:
    """Bind one private leave-one-out realization to public aggregate commitments."""

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    removal_slot = cast(int, operation["removal_slot_ordinal"])
    training_prepared_data_digest = _influence_prepared_data_digest(
        source_scientific_data_digest=source_scientific_data_digest,
        analysis_spec_id=cast(str, candidate["analysis_spec_id"]),
        removal_slot_ordinal=removal_slot,
        pre_operation_memberships=pre_operation_memberships,
        retained_membership=retained_membership,
    )
    operation_parameters_digest = structured_sha256(
        "ebm-audit/leave-one-out-operation/1",
        operation,
    )
    operation_identity = {
        "kind": "influence",
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "source_variant_id": operation["source_variant_id"],
        "derived_source_variant_id": operation["derived_source_variant_id"],
        "removal_slot_ordinal": removal_slot,
        "removal_method_id": operation["removal_method_id"],
        "removal_kind": operation["removal_kind"],
        "refit_preprocessing": operation["refit_preprocessing"],
        "fixed_non_removed_cohort_policy": operation["fixed_non_removed_cohort_policy"],
        "operation_seed": None,
        "operation_parameters_digest": operation_parameters_digest,
    }
    private_membership = [row._asdict() for row in memberships]
    private_pre_operation_membership = [row._asdict() for row in pre_operation_memberships]
    private_instances = [row._asdict() for row in instances]
    private_retained_membership = [row._asdict() for row in retained_membership]
    private_removed_membership = [row._asdict() for row in removed_membership]
    source_accounting = {
        "stage": "source",
        "prepared_dataset_id": prepared_dataset_id,
        "audit_dataset_digest": audit_dataset_digest,
        "ordered_membership": private_membership,
    }
    cohort_accounting = {
        "stage": "cohort",
        "ordered_membership": private_membership,
    }
    pre_operation_accounting = {
        "stage": "pre-operation",
        "ordered_membership": private_pre_operation_membership,
    }
    operation_accounting = {
        "stage": "operation",
        "operation_identity": operation_identity,
        "ordered_instances": private_instances,
        "ordered_unique_membership": private_retained_membership,
    }
    accounting_operation = {
        "operation_id": "leave-one-participant-out",
        "method_id": "exact-participant-removal-v1",
        "universe_decision_id": candidate["candidate_id"],
        "reason_code": "PREPARATION.LEAVE_ONE_OUT",
        "rationale": "Declared exact leave-one-participant-out refit.",
        "participant_count": 1,
        "event_count": event_count,
        "cell_count": 0,
        "affected_event_ids": [],
        "affected_auxiliary_array_names": [],
        "parameter_digest": operation_parameters_digest,
        "input_digest": source_scientific_data_digest,
        "output_digest": training_prepared_data_digest,
    }
    data_accounting = {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": len(memberships),
        "output_participants": len(retained_membership),
        "input_events": event_count,
        "output_events": event_count,
        "input_missing_cells": 0,
        "output_missing_cells": 0,
        "flagged_cells": 0,
        "masked_cells": 0,
        "transformed_cells": 0,
        "added_participant_instances": 0,
        "removed_participants": len(removed_membership),
        "removed_events": 0,
        "operations": [accounting_operation],
    }
    try:
        validate_instance(
            data_accounting,
            "canonical-records.schema.json",
            definition="DataAccounting",
        )
    except SchemaValidationError:
        raise UniverseIdentityError(
            "Influence preparation produced invalid exact data accounting."
        ) from None
    training_accounting = {
        "stage": "training",
        "scientific_data_digest": training_prepared_data_digest,
        "ordered_instances": private_instances,
        "data_accounting": data_accounting,
    }
    evaluation_accounting = {
        "stage": "evaluation",
        "scientific_data_digest": training_prepared_data_digest,
        "ordered_membership": private_retained_membership,
    }
    source_role_counts = _role_counts_from_membership(memberships)
    retained_role_counts = _role_counts_from_membership(retained_membership)
    retained_instance_role_counts = _role_counts_from_instances(instances)
    retained_count = len(retained_membership)
    counts = {
        "source_participant_count": len(memberships),
        "cohort_eligible_participant_count": len(memberships),
        "pre_operation_eligible_participant_count": len(pre_operation_memberships),
        "operation_output_participant_instance_count": len(instances),
        "operation_output_unique_participant_count": retained_count,
        "training_participant_instance_count": len(instances),
        "training_unique_participant_count": retained_count,
        "evaluation_participant_count": retained_count,
        "cohort_role_counts": source_role_counts,
        "pre_operation_role_counts": source_role_counts,
        "operation_output_role_counts": retained_instance_role_counts,
        "training_role_counts": retained_instance_role_counts,
        "evaluation_role_counts": retained_role_counts,
        "event_count": event_count,
        "operation_transformed_cell_count": 0,
        "operation_transformed_label_count": 0,
        "preprocessing_transformed_cell_count": 0,
        "preprocessing_flagged_cell_count": 0,
        "preprocessing_masked_cell_count": 0,
        "fit_ready_missing_cell_count": 0,
    }
    fields = {
        "source_prepared_data_digest": audit_dataset_digest,
        "training_prepared_data_digest": training_prepared_data_digest,
        "evaluation_prepared_data_digest": training_prepared_data_digest,
        "evaluation_membership_digest": _private_evaluation_membership_digest(
            cast(str, plan["plan_digest"]),
            retained_membership,
        ),
        "source_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            source_accounting,
        ),
        "training_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            training_accounting,
        ),
        "evaluation_accounting_digest": structured_sha256(
            "ebm-audit/preparation-accounting/1",
            evaluation_accounting,
        ),
        "aggregate_counts": counts,
    }
    transition = {
        "transition_schema_version": "ebm-audit-private-preparation-transition/2.0",
        "plan_digest": plan["plan_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "source_analysis_spec_id": operation["source_analysis_spec_id"],
        "operation_identity": operation_identity,
        "source_accounting": source_accounting,
        "cohort_accounting": cohort_accounting,
        "pre_operation_accounting": pre_operation_accounting,
        "operation_accounting": operation_accounting,
        "training_accounting": training_accounting,
        "evaluation_accounting": evaluation_accounting,
        "aggregate_counts": counts,
        "affected_cells": [],
        "fitted_parameters": [],
        "stratum_allocations": [],
        "removed_membership": private_removed_membership,
        "public_fields": fields,
    }
    return fields, canonical_json_bytes(transition)


def _build_universe(
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    fields: Mapping[str, Any],
    master_seed: str,
    operation_seed: str | None,
    *,
    profile_chain_seeds: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    chain_slots = cast(Sequence[Mapping[str, Any]], candidate["chain_slots"])
    if profile_chain_seeds is not None and len(profile_chain_seeds) != len(chain_slots):
        raise UniverseIdentityError("Profile chain-seed coverage is incomplete.")
    ordered_chain_plan = [
        {
            "chain_ordinal": slot["chain_ordinal"],
            "chain_id": slot["chain_id"],
            "seed": (
                profile_chain_seeds[position]
                if profile_chain_seeds is not None
                else _expected_chain_seed(
                    spec,
                    cast(str, candidate["analysis_spec_id"]),
                    cast(int, slot["chain_ordinal"]),
                    master_seed,
                )
            ),
        }
        for position, slot in enumerate(chain_slots)
    ]
    preimage = {
        "universe_schema_version": "ebm-audit-analysis-universe/3.0",
        "plan_schema_version": "ebm-audit-analysis-plan/3.0",
        "plan_digest": plan["plan_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "preparation_rule_registry_digest": _PREPARATION_RULE_REGISTRY_DIGEST,
        "stage_transition_rule_id": _STAGE_TRANSITION_RULE_ID,
        "operation_seed": operation_seed,
        **copy.deepcopy(dict(fields)),
        "ordered_chain_plan": ordered_chain_plan,
    }
    identity = universe_id(preimage)
    universe = {
        **{key: value for key, value in preimage.items() if key != "ordered_chain_plan"},
        "chain_plan": [
            {
                **row,
                "chain_execution_id": chain_execution_id(
                    identity, cast(str, row["chain_id"]), cast(str, row["seed"])
                ),
            }
            for row in ordered_chain_plan
        ],
        "universe_id": identity,
    }
    _validate_schema(universe, "UniverseSpec")
    return universe


def _source_candidate_for_derived_operation(
    plan: Mapping[str, Any], candidate: Mapping[str, Any]
) -> Mapping[str, Any]:
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    source_id = operation["source_analysis_spec_id"]
    matches = [
        row
        for row in cast(Sequence[Mapping[str, Any]], plan["candidates"])
        if row["analysis_spec_id"] == source_id
        and row["analysis_spec"]["operation_intent"]["kind"] == "ordinary"
    ]
    if len(matches) != 1:
        raise UniverseIdentityError(
            "A derived candidate lacks one exact ordinary source candidate."
        )
    return matches[0]


def _verify_bootstrap_private_replay(
    replay: _PrivatePreparationReplayState,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    universe: Mapping[str, Any],
    prepared_dataset_id: str,
) -> None:
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    operation_seed = cast(str, replay.operation_seed)
    if (
        operation["sampling_design"] != "stratified"
        or operation["strata_group_spec_ids"] != [spec["cohort_rule"]["group_spec_id"]]
        or not (
            replay.source_membership == replay.cohort_membership == replay.evaluation_membership
        )
        or len(replay.pre_operation_membership) != len(replay.source_membership)
        or set(replay.pre_operation_membership) != set(replay.source_membership)
        or replay.operation_instances != replay.training_instances
        or replay.operation_unique_membership != replay.training_unique_membership
        or replay.removed_membership
    ):
        raise UniverseIdentityError("Stratified bootstrap private membership stages are invalid.")
    try:
        expected_instances, expected_unique = _stratified_bootstrap_instances(
            replay.pre_operation_membership, operation, operation_seed
        )
    except _CandidatePreparationInvalid:
        raise UniverseIdentityError(
            "Stratified bootstrap private replay has an impossible required stratum."
        ) from None
    if (
        replay.operation_instances != expected_instances
        or replay.operation_unique_membership != expected_unique
        or len(replay.operation_instances) != len(replay.pre_operation_membership)
    ):
        raise UniverseIdentityError(
            "Stratified bootstrap private replay changed its deterministic draw."
        )
    expected_fields, expected_transition = _bootstrap_public_universe_fields(
        plan=plan,
        candidate=candidate,
        prepared_dataset_id=prepared_dataset_id,
        audit_dataset_digest=cast(str, universe["source_prepared_data_digest"]),
        source_scientific_data_digest=cast(str, universe["evaluation_prepared_data_digest"]),
        event_count=cast(int, universe["aggregate_counts"]["event_count"]),
        memberships=replay.source_membership,
        pre_operation_memberships=replay.pre_operation_membership,
        instances=replay.operation_instances,
        unique_membership=replay.operation_unique_membership,
        operation_seed=operation_seed,
    )
    if (
        replay.public_universe_fields_bytes != canonical_json_bytes(expected_fields)
        or replay.private_transition_chain_bytes != expected_transition
        or any(universe[field] != value for field, value in expected_fields.items())
    ):
        raise UniverseIdentityError("Stratified bootstrap private replay is not exact.")


def _verify_subsample_private_replay(
    replay: _PrivatePreparationReplayState,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    universe: Mapping[str, Any],
    prepared_dataset_id: str,
) -> None:
    """Regenerate one constrained allocation and its exact no-replacement draw."""

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    operation_seed = cast(str, replay.operation_seed)
    minimum_reference_rows = cast(
        int | None,
        spec["covariate_adjustment"]["minimum_reference_rows"],
    )
    if (
        not _supports_stratified_subsample(spec)
        or replay.source_membership != replay.cohort_membership
        or replay.evaluation_membership != replay.source_membership
        or len(replay.pre_operation_membership) != len(replay.source_membership)
        or set(replay.pre_operation_membership) != set(replay.source_membership)
        or replay.operation_instances != replay.training_instances
        or replay.operation_unique_membership != replay.training_unique_membership
        or replay.removed_membership
    ):
        raise UniverseIdentityError("Stratified subsample private membership stages are invalid.")
    try:
        expected_plan = _stratified_subsample_plan(
            replay.pre_operation_membership,
            operation,
            operation_seed,
            minimum_reference_rows=minimum_reference_rows,
        )
    except _CandidatePreparationInvalid:
        raise UniverseIdentityError(
            "Stratified subsample private replay has an impossible allocation."
        ) from None
    if (
        replay.operation_instances != expected_plan.instances
        or replay.operation_unique_membership != expected_plan.retained_membership
    ):
        raise UniverseIdentityError(
            "Stratified subsample private replay changed its deterministic draw."
        )
    expected_fields, expected_transition = _subsample_public_universe_fields(
        plan_owner=plan,
        candidate=candidate,
        prepared_dataset_id=prepared_dataset_id,
        audit_dataset_digest=cast(str, universe["source_prepared_data_digest"]),
        source_scientific_data_digest=cast(
            str,
            universe["evaluation_prepared_data_digest"],
        ),
        event_count=cast(int, universe["aggregate_counts"]["event_count"]),
        memberships=replay.source_membership,
        pre_operation_memberships=replay.pre_operation_membership,
        subsample_plan=expected_plan,
        operation_seed=operation_seed,
    )
    if (
        replay.public_universe_fields_bytes != canonical_json_bytes(expected_fields)
        or replay.private_transition_chain_bytes != expected_transition
        or any(universe[field] != value for field, value in expected_fields.items())
    ):
        raise UniverseIdentityError("Stratified subsample private replay is not exact.")


def _verify_influence_private_replay(
    replay: _PrivatePreparationReplayState,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    universe: Mapping[str, Any],
    prepared_dataset_id: str,
    source_scientific_data_digest: str,
) -> None:
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    removal_slot = cast(int, operation["removal_slot_ordinal"])
    expected_pre_operation = tuple(
        sorted(replay.source_membership, key=lambda row: row.internal_row_index)
    )
    if removal_slot < 0 or removal_slot >= len(expected_pre_operation):
        raise UniverseIdentityError("Influence private replay has an impossible removal slot.")
    expected_removed = (expected_pre_operation[removal_slot],)
    expected_retained = tuple(
        row for ordinal, row in enumerate(expected_pre_operation) if ordinal != removal_slot
    )
    expected_instances = tuple(
        _PrivateOperationInstance(
            row.participant_token,
            row.internal_row_index,
            row.role,
            draw_ordinal,
            0,
        )
        for draw_ordinal, row in enumerate(expected_retained)
    )
    if (
        not _supports_leave_one_out_influence(spec)
        or replay.operation_seed is not None
        or replay.source_membership != replay.cohort_membership
        or replay.pre_operation_membership != expected_pre_operation
        or replay.removed_membership != expected_removed
        or replay.operation_instances != expected_instances
        or replay.training_instances != expected_instances
        or replay.operation_unique_membership != expected_retained
        or replay.training_unique_membership != expected_retained
        or replay.evaluation_membership != expected_retained
    ):
        raise UniverseIdentityError("Leave-one-out private membership stages are invalid.")
    transition = _closed_object(replay.private_transition_chain_bytes)
    source_accounting = cast(Mapping[str, Any], transition["source_accounting"])
    expected_fields, expected_transition = _influence_public_universe_fields(
        plan=plan,
        candidate=candidate,
        prepared_dataset_id=prepared_dataset_id,
        audit_dataset_digest=cast(str, source_accounting["audit_dataset_digest"]),
        source_scientific_data_digest=source_scientific_data_digest,
        event_count=cast(int, universe["aggregate_counts"]["event_count"]),
        memberships=replay.source_membership,
        pre_operation_memberships=replay.pre_operation_membership,
        instances=replay.operation_instances,
        retained_membership=replay.operation_unique_membership,
        removed_membership=replay.removed_membership,
    )
    if (
        replay.public_universe_fields_bytes != canonical_json_bytes(expected_fields)
        or replay.private_transition_chain_bytes != expected_transition
        or any(universe[field] != value for field, value in expected_fields.items())
    ):
        raise UniverseIdentityError("Leave-one-out private replay is not exact.")


def _verify_transformed_null_private_replay(
    replay: _PrivatePreparationReplayState,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    universe: Mapping[str, Any],
    prepared_dataset_id: str,
    source_scientific_data_digest: str,
    source_values: NDArray[np.float64],
) -> None:
    """Regenerate and jointly verify the effective null map and all stage commitments."""

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    operation_seed = cast(str, replay.operation_seed)
    try:
        expected_plan = _transformed_null_plan(
            replay.source_membership,
            event_count=cast(int, universe["aggregate_counts"]["event_count"]),
            operation=operation,
            operation_seed=operation_seed,
            source_values=source_values,
        )
    except _CandidatePreparationInvalid:
        raise UniverseIdentityError(
            "Transformed-null private replay no longer produces an effective draw."
        ) from None
    if (
        not _supports_transformed_null(spec)
        or replay.source_membership != replay.cohort_membership
        or replay.source_membership != replay.pre_operation_membership
        or replay.operation_instances != expected_plan.transformed_instances
        or replay.training_instances != expected_plan.transformed_instances
        or replay.operation_unique_membership != expected_plan.transformed_membership
        or replay.training_unique_membership != expected_plan.transformed_membership
        or replay.evaluation_membership != expected_plan.transformed_membership
        or replay.removed_membership
    ):
        raise UniverseIdentityError("Transformed-null private membership stages are invalid.")
    transition = _closed_object(replay.private_transition_chain_bytes)
    source_accounting = transition.get("source_accounting")
    if not isinstance(source_accounting, Mapping):
        raise UniverseIdentityError("Transformed-null private source accounting is invalid.")
    event_ids = tuple(
        cast(str, row["event_id"]) for row in cast(Sequence[Mapping[str, Any]], spec["event_set"])
    )
    expected_fields, expected_transition = _transformed_null_public_universe_fields(
        plan=plan,
        candidate=candidate,
        prepared_dataset_id=prepared_dataset_id,
        audit_dataset_digest=cast(str, source_accounting["audit_dataset_digest"]),
        source_scientific_data_digest=source_scientific_data_digest,
        event_ids=event_ids,
        null_plan=expected_plan,
        operation_seed=operation_seed,
    )
    if (
        replay.public_universe_fields_bytes != canonical_json_bytes(expected_fields)
        or replay.private_transition_chain_bytes != expected_transition
        or any(universe[field] != value for field, value in expected_fields.items())
    ):
        raise UniverseIdentityError("Transformed-null private replay is not exact.")


def _verify_fixed_event_rescale_private_replay(
    replay: _PrivatePreparationReplayState,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    universe: Mapping[str, Any],
    source_scientific_data_digest: str,
    source_values: NDArray[np.float64],
) -> None:
    """Verify the fixed preprocessing source, transformed bytes, and accounting."""

    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    if not _supports_fixed_event_rescale(spec):
        raise UniverseIdentityError("Fixed rescale preprocessing declaration is invalid.")
    source_id = cast(str, plan["baseline_analysis_spec_id"])
    transformed = np.multiply(
        source_values,
        _FIXED_EVENT_RESCALE_FACTOR,
        dtype=np.float64,
    )
    changed_cell_count = int(np.count_nonzero(transformed != source_values))
    transformed_digest = structured_sha256(
        "ebm-audit/fixed-event-rescale-prepared-data/1",
        {
            "prepared_data_schema_version": (
                "ebm-audit-fixed-event-rescale-prepared-data/1.0"
            ),
            "source_scientific_data_digest": source_scientific_data_digest,
            "source_analysis_spec_id": source_id,
            "analysis_spec_id": candidate["analysis_spec_id"],
            "transformation": spec["preprocessing"][0],
            "transformed_train_values_array_digest": array_catalog_entry(
                "train_values",
                transformed,
                semantic_version="event-value-matrix/1",
            )["array_digest"],
        },
    )
    memberships = replay.source_membership
    expected_instances = tuple(
        _PrivateOperationInstance(
            row.participant_token,
            row.internal_row_index,
            row.role,
            ordinal,
            0,
        )
        for ordinal, row in enumerate(memberships)
    )
    counts = cast(Mapping[str, Any], universe["aggregate_counts"])
    transition = _closed_object(replay.private_transition_chain_bytes)
    training = transition.get("training_accounting")
    evaluation = transition.get("evaluation_accounting")
    if (
        replay.source_analysis_spec_id != source_id
        or replay.source_membership != replay.cohort_membership
        or replay.source_membership != replay.pre_operation_membership
        or replay.source_membership != replay.operation_unique_membership
        or replay.source_membership != replay.training_unique_membership
        or replay.source_membership != replay.evaluation_membership
        or replay.operation_instances != expected_instances
        or replay.training_instances != expected_instances
        or replay.removed_membership
        or changed_cell_count < 1
        or universe["training_prepared_data_digest"] != transformed_digest
        or universe["evaluation_prepared_data_digest"] != transformed_digest
        or counts.get("preprocessing_transformed_cell_count") != changed_cell_count
        or counts.get("operation_transformed_cell_count") != 0
        or transition.get("source_analysis_spec_id") != source_id
        or transition.get("public_fields")
        != {
            key: universe[key]
            for key in (
                "source_prepared_data_digest",
                "training_prepared_data_digest",
                "evaluation_prepared_data_digest",
                "evaluation_membership_digest",
                "source_accounting_digest",
                "training_accounting_digest",
                "evaluation_accounting_digest",
                "aggregate_counts",
            )
        }
        or not isinstance(training, Mapping)
        or training.get("scientific_data_digest") != transformed_digest
        or not isinstance(training.get("data_accounting"), Mapping)
        or training["data_accounting"].get("transformed_cells") != changed_cell_count
        or not isinstance(evaluation, Mapping)
        or evaluation.get("scientific_data_digest") != transformed_digest
        or canonical_json_bytes(transition) != replay.private_transition_chain_bytes
    ):
        raise UniverseIdentityError("Fixed rescale preprocessing private replay is not exact.")


def _verify_private_replay(
    replay: _PrivatePreparationReplayState,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    universe: Mapping[str, Any],
    prepared_dataset_id: str,
    source_scientific_data_digest: str,
    source_values: NDArray[np.float64],
) -> None:
    if type(replay) is not _PrivatePreparationReplayState:
        raise UniverseIdentityError("Prepared private replay has the wrong exact type.")
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    operation_kind = operation["kind"]
    fixed_rescale_source_id = (
        cast(str, plan["baseline_analysis_spec_id"])
        if _supports_fixed_event_rescale(spec)
        else None
    )
    expected_source_analysis_spec_id = (
        fixed_rescale_source_id
        if fixed_rescale_source_id is not None
        else operation["source_analysis_spec_id"]
        if operation_kind in {"bootstrap", "subsample", "influence", "null"}
        else None
    )
    if (
        replay.plan_digest != plan["plan_digest"]
        or replay.candidate_ordinal != candidate["candidate_ordinal"]
        or replay.candidate_id != candidate["candidate_id"]
        or replay.analysis_spec_id != candidate["analysis_spec_id"]
        or replay.operation_seed != universe["operation_seed"]
        or replay.preparation_rule_registry_digest != _PREPARATION_RULE_REGISTRY_DIGEST
        or replay.source_analysis_spec_id != expected_source_analysis_spec_id
        or not replay.private_transition_chain_bytes
    ):
        raise UniverseIdentityError("Prepared private replay is detached from its candidate.")
    if fixed_rescale_source_id is not None:
        _verify_fixed_event_rescale_private_replay(
            replay,
            plan,
            candidate,
            universe,
            source_scientific_data_digest,
            source_values,
        )
        return
    if operation_kind == "bootstrap":
        _verify_bootstrap_private_replay(replay, plan, candidate, universe, prepared_dataset_id)
        return
    if operation_kind == "subsample":
        _verify_subsample_private_replay(replay, plan, candidate, universe, prepared_dataset_id)
        return
    if operation_kind == "influence":
        _verify_influence_private_replay(
            replay,
            plan,
            candidate,
            universe,
            prepared_dataset_id,
            source_scientific_data_digest,
        )
        return
    if operation_kind == "null":
        _verify_transformed_null_private_replay(
            replay,
            plan,
            candidate,
            universe,
            prepared_dataset_id,
            source_scientific_data_digest,
            source_values,
        )
        return
    if operation_kind != "ordinary":
        raise UniverseIdentityError("Prepared private replay has an unsupported operation kind.")
    if (
        not (
            replay.source_membership
            == replay.cohort_membership
            == replay.pre_operation_membership
            == replay.operation_unique_membership
            == replay.training_unique_membership
            == replay.evaluation_membership
        )
        or replay.removed_membership
    ):
        raise UniverseIdentityError("Ordinary preparation changed exact private membership.")
    if replay.operation_instances != replay.training_instances:
        raise UniverseIdentityError("Ordinary preparation changed exact private instances.")
    public = _closed_object(replay.public_universe_fields_bytes)
    for field, expected in public.items():
        if universe[field] != expected:
            raise UniverseIdentityError("Universe commitments differ from private replay.")
    transition = _closed_object(replay.private_transition_chain_bytes)
    if canonical_json_bytes(transition) != replay.private_transition_chain_bytes:
        raise UniverseIdentityError("Private preparation replay is not canonical.")
    expected_membership = [row._asdict() for row in replay.source_membership]
    expected_instances = [row._asdict() for row in replay.training_instances]
    source_accounting = transition.get("source_accounting")
    training_accounting = transition.get("training_accounting")
    evaluation_accounting = transition.get("evaluation_accounting")
    if not all(
        isinstance(value, Mapping)
        for value in (source_accounting, training_accounting, evaluation_accounting)
    ):
        raise UniverseIdentityError("Private preparation replay accounting is invalid.")
    source_accounting = cast(Mapping[str, Any], source_accounting)
    training_accounting = cast(Mapping[str, Any], training_accounting)
    evaluation_accounting = cast(Mapping[str, Any], evaluation_accounting)
    data_accounting = training_accounting.get("data_accounting")
    counts = cast(Mapping[str, Any], universe["aggregate_counts"])
    expected_data_accounting = {
        "accounting_schema_version": "ebm-audit-data-accounting/2.0",
        "input_participants": counts["source_participant_count"],
        "output_participants": counts["training_unique_participant_count"],
        "input_events": counts["event_count"],
        "output_events": counts["event_count"],
        "input_missing_cells": 0,
        "output_missing_cells": counts["fit_ready_missing_cell_count"],
        "flagged_cells": counts["preprocessing_flagged_cell_count"],
        "masked_cells": counts["preprocessing_masked_cell_count"],
        "transformed_cells": counts["preprocessing_transformed_cell_count"],
        "added_participant_instances": 0,
        "removed_participants": 0,
        "removed_events": 0,
        "operations": [],
    }
    if (
        set(transition)
        != {
            "transition_schema_version",
            "plan_digest",
            "candidate_ordinal",
            "candidate_id",
            "analysis_spec_id",
            "source_accounting",
            "training_accounting",
            "evaluation_accounting",
            "affected_cells",
            "fitted_parameters",
            "stratum_allocations",
            "removed_membership",
            "public_fields",
        }
        or transition["transition_schema_version"] != "ebm-audit-private-preparation-transition/2.0"
        or transition["plan_digest"] != replay.plan_digest
        or transition["candidate_ordinal"] != replay.candidate_ordinal
        or transition["candidate_id"] != replay.candidate_id
        or transition["analysis_spec_id"] != replay.analysis_spec_id
        or transition["affected_cells"]
        or transition["fitted_parameters"]
        or transition["stratum_allocations"]
        or transition["removed_membership"] != [row._asdict() for row in replay.removed_membership]
        or transition["public_fields"] != public
        or source_accounting
        != {
            "stage": "source",
            "prepared_dataset_id": prepared_dataset_id,
            "audit_dataset_digest": universe["source_prepared_data_digest"],
            "ordered_membership": expected_membership,
        }
        or training_accounting
        != {
            "stage": "training",
            "scientific_data_digest": universe["training_prepared_data_digest"],
            "ordered_instances": expected_instances,
            "data_accounting": expected_data_accounting,
        }
        or evaluation_accounting
        != {
            "stage": "evaluation",
            "scientific_data_digest": universe["evaluation_prepared_data_digest"],
            "ordered_membership": expected_membership,
        }
        or universe["source_accounting_digest"]
        != structured_sha256("ebm-audit/preparation-accounting/1", source_accounting)
        or universe["training_accounting_digest"]
        != structured_sha256("ebm-audit/preparation-accounting/1", training_accounting)
        or universe["evaluation_accounting_digest"]
        != structured_sha256("ebm-audit/preparation-accounting/1", evaluation_accounting)
        or data_accounting != expected_data_accounting
    ):
        raise UniverseIdentityError("Private preparation replay is not exact.")


def _verify_universe(
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    universe: Mapping[str, Any],
    replay: _PrivatePreparationReplayState,
    master_seed: str,
    prepared_dataset_id: str,
    source_scientific_data_digest: str,
    source_values: NDArray[np.float64],
    *,
    profile_chain_seeds: tuple[str, ...] | None = None,
) -> None:
    _validate_schema(universe, "UniverseSpec")
    if (
        universe["plan_schema_version"] != plan["plan_schema_version"]
        or universe["plan_digest"] != plan["plan_digest"]
        or universe["candidate_ordinal"] != candidate["candidate_ordinal"]
        or universe["candidate_id"] != candidate["candidate_id"]
        or universe["analysis_spec_id"] != candidate["analysis_spec_id"]
        or candidate["candidate_id"] != candidate["analysis_spec_id"]
    ):
        raise UniverseIdentityError("Universe/3 is detached from its exact Plan/3 position.")
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    expected_operation_seed = _expected_operation_seed(spec, master_seed)
    if universe["operation_seed"] != expected_operation_seed:
        raise UniverseIdentityError("Universe/3 changed its post-plan operation draw.")
    _verify_private_replay(
        replay,
        plan,
        candidate,
        universe,
        prepared_dataset_id,
        source_scientific_data_digest,
        source_values,
    )
    _verify_preparation_aggregate_counts(
        spec,
        cast(Mapping[str, Any], universe["aggregate_counts"]),
        cast(int, plan["planning_dataset_summary"]["participant_count"]),
        has_exact_stratum_allocation_replay=(
            spec["operation_intent"]["kind"] in {"bootstrap", "subsample"}
            and spec["operation_intent"]["sampling_design"] == "stratified"
        ),
    )
    chain_plan = cast(Sequence[Mapping[str, Any]], universe["chain_plan"])
    slots = cast(Sequence[Mapping[str, Any]], candidate["chain_slots"])
    if len(chain_plan) != len(slots):
        raise UniverseIdentityError("Universe/3 does not cover every seedless chain slot.")
    if profile_chain_seeds is not None and len(profile_chain_seeds) != len(slots):
        raise UniverseIdentityError("Profile chain-seed coverage is incomplete.")
    for position, (row, slot) in enumerate(zip(chain_plan, slots, strict=True)):
        expected_seed = (
            profile_chain_seeds[position]
            if profile_chain_seeds is not None
            else _expected_chain_seed(
                spec,
                cast(str, candidate["analysis_spec_id"]),
                cast(int, slot["chain_ordinal"]),
                master_seed,
            )
        )
        if (
            row["chain_ordinal"] != slot["chain_ordinal"]
            or row["chain_id"] != slot["chain_id"]
            or row["seed"] != expected_seed
        ):
            raise UniverseIdentityError("A Universe/3 chain row differs from its exact plan slot.")
    if len({row["seed"] for row in chain_plan}) != len(chain_plan):
        raise UniverseIdentityError("Universe/3 chain seeds are not unique.")
    expected_universe_id = universe_id(_universe_preimage(universe))
    if not hmac.compare_digest(cast(str, universe["universe_id"]), expected_universe_id):
        raise UniverseIdentityError("Universe/3 identity is detached from its exact preimage.")
    for row in chain_plan:
        expected_chain_id = chain_execution_id(
            expected_universe_id, cast(str, row["chain_id"]), cast(str, row["seed"])
        )
        if not hmac.compare_digest(cast(str, row["chain_execution_id"]), expected_chain_id):
            raise UniverseIdentityError("A chain-execution/3 identity is detached.")


def _prepare_candidate(
    state: _PlanningAuthorityState,
    plan: Mapping[str, Any],
    candidate: Mapping[str, Any],
    master_seed: str,
    execution_origin: _PreparedExecutionOrigin,
    conformance_demo_provenance: _ConformanceDemoProvenance | None = None,
) -> tuple[
    dict[str, Any],
    _PendingPreparedCandidate | None,
    _UnpreparedScientificInput | None,
]:
    if type(state) is not _PlanningAuthorityState:
        raise UniverseIdentityError("A genuine planning-authority state is required.")
    if state.preparation_namespace_key is None:
        raise UniverseIdentityError("Planning authority lacks private preparation authority.")
    if candidate["planning_outcome"] == "PLAN_INELIGIBLE":
        record = _unprepared_record(
            candidate,
            state="PLAN_INELIGIBLE",
            operation_seed=None,
        )
        if not _unprepared_requires_input_digest(record):
            return record, None, None
        try:
            canonical_input, _prepared = _canonicalize_candidate_input(
                state.prepared_dataset,
                state.preparation_namespace_key,
                candidate,
                cast(Mapping[str, Any], candidate["analysis_spec"]),
            )
        except InvalidInputError:
            raise UniverseIdentityError(
                "An MCMC-only ineligible candidate lacks a canonical scientific-data owner."
            ) from None
        return record, None, _unprepared_scientific_input(canonical_input)
    spec = cast(Mapping[str, Any], candidate["analysis_spec"])
    operation_seed = _expected_operation_seed(spec, master_seed)
    unsupported = _unsupported_reasons(spec)
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    supported_bootstrap = (
        operation["kind"] == "bootstrap"
        and operation["sampling_design"] == "stratified"
        and operation["strata_group_spec_ids"] == [spec["cohort_rule"]["group_spec_id"]]
    )
    supported_subsample = _supports_stratified_subsample(spec)
    supported_influence = _supports_leave_one_out_influence(spec)
    supported_transformed_null = _supports_transformed_null(spec)
    supported_fixed_rescale = _supports_fixed_event_rescale(spec)
    canonical_candidate = (
        (
            _source_candidate_for_fixed_event_rescale(plan, candidate)
            if supported_fixed_rescale
            else _source_candidate_for_derived_operation(plan, candidate)
        )
        if (
            supported_bootstrap
            or supported_subsample
            or supported_influence
            or supported_transformed_null
            or supported_fixed_rescale
        )
        and not unsupported
        else candidate
    )
    canonical_spec = cast(Mapping[str, Any], canonical_candidate["analysis_spec"])
    invalid: list[str] = []
    canonical: Any | None = None
    prepared: _PreparedPrivateState | None = None
    try:
        canonical, prepared = _canonicalize_candidate_input(
            state.prepared_dataset,
            state.preparation_namespace_key,
            canonical_candidate,
            canonical_spec,
        )
        if canonical.view.participant_count != prepared.summary.participant_count:
            unsupported.append("PREPARATION.COMPLETE_CASE_ROW_LOSS_UNSUPPORTED")
    except InvalidInputError:
        invalid.append(_INVALID_REASON)
    if invalid or unsupported:
        record_state = "PREPARATION_INVALID" if invalid else "PREPARATION_UNSUPPORTED"
        return (
            _unprepared_record(
                candidate,
                state=record_state,
                operation_seed=operation_seed,
                invalid_reasons=invalid,
                unsupported_reasons=unsupported,
            ),
            None,
            None if invalid else _unprepared_scientific_input(canonical),
        )
    if canonical is None or prepared is None:
        raise UniverseIdentityError("Prepared candidate realization is incomplete.")
    if supported_fixed_rescale:
        source_analysis_spec_id = cast(str, canonical_candidate["analysis_spec_id"])
        (
            memberships,
            instances,
            arrays,
            changed_cell_count,
        ) = _fixed_event_rescale_membership_and_arrays(canonical)
        pre_operation_memberships = memberships
        unique_membership = memberships
        evaluation_membership = memberships
        removed_membership = ()
        fields, transition_bytes = _fixed_event_rescale_public_universe_fields(
            plan=plan,
            candidate=candidate,
            prepared_dataset_id=prepared.prepared_dataset_id,
            audit_dataset_digest=prepared.audit_dataset_digest,
            canonical=canonical,
            memberships=memberships,
            instances=instances,
            arrays=arrays,
            changed_cell_count=changed_cell_count,
            source_analysis_spec_id=source_analysis_spec_id,
        )
    elif operation["kind"] == "ordinary":
        memberships, instances, arrays = _private_membership_and_arrays(canonical)
        pre_operation_memberships = memberships
        unique_membership = memberships
        fields, transition_bytes = _public_universe_fields(
            plan=plan,
            candidate=candidate,
            prepared_dataset_id=prepared.prepared_dataset_id,
            audit_dataset_digest=prepared.audit_dataset_digest,
            canonical=canonical,
            memberships=memberships,
            instances=instances,
        )
        source_analysis_spec_id = None
        evaluation_membership = memberships
        removed_membership: tuple[_PrivateMembership, ...] = ()
    elif supported_bootstrap:
        try:
            (
                memberships,
                pre_operation_memberships,
                instances,
                unique_membership,
                arrays,
            ) = _stratified_bootstrap_membership_and_arrays(
                canonical, operation, cast(str, operation_seed)
            )
        except _CandidatePreparationInvalid:
            raise UniverseIdentityError(
                "A canonical bootstrap source lacks a required declared stratum."
            ) from None
        fields, transition_bytes = _bootstrap_public_universe_fields(
            plan=plan,
            candidate=candidate,
            prepared_dataset_id=prepared.prepared_dataset_id,
            audit_dataset_digest=prepared.audit_dataset_digest,
            source_scientific_data_digest=canonical.scientific_data_digest,
            event_count=canonical.view.event_count,
            memberships=memberships,
            pre_operation_memberships=pre_operation_memberships,
            instances=instances,
            unique_membership=unique_membership,
            operation_seed=cast(str, operation_seed),
        )
        source_analysis_spec_id = cast(str, operation["source_analysis_spec_id"])
        evaluation_membership = memberships
        removed_membership = ()
    elif supported_subsample:
        try:
            (
                memberships,
                pre_operation_memberships,
                subsample_plan,
                arrays,
            ) = _stratified_subsample_membership_and_arrays(
                canonical,
                operation,
                cast(str, operation_seed),
                minimum_reference_rows=cast(
                    int | None,
                    spec["covariate_adjustment"]["minimum_reference_rows"],
                ),
            )
        except _CandidatePreparationInvalid:
            return (
                _unprepared_record(
                    candidate,
                    state="PREPARATION_INVALID",
                    operation_seed=operation_seed,
                    invalid_reasons=[_SUBSAMPLE_ALLOCATION_INVALID_REASON],
                ),
                None,
                None,
            )
        instances = subsample_plan.instances
        unique_membership = subsample_plan.retained_membership
        evaluation_membership = memberships
        removed_membership = ()
        fields, transition_bytes = _subsample_public_universe_fields(
            plan_owner=plan,
            candidate=candidate,
            prepared_dataset_id=prepared.prepared_dataset_id,
            audit_dataset_digest=prepared.audit_dataset_digest,
            source_scientific_data_digest=canonical.scientific_data_digest,
            event_count=canonical.view.event_count,
            memberships=memberships,
            pre_operation_memberships=pre_operation_memberships,
            subsample_plan=subsample_plan,
            operation_seed=cast(str, operation_seed),
        )
        source_analysis_spec_id = cast(str, operation["source_analysis_spec_id"])
    elif supported_influence:
        try:
            (
                memberships,
                pre_operation_memberships,
                instances,
                unique_membership,
                removed_membership,
                arrays,
            ) = _leave_one_out_membership_and_arrays(canonical, operation)
        except _CandidatePreparationInvalid:
            return (
                _unprepared_record(
                    candidate,
                    state="PREPARATION_UNSUPPORTED",
                    operation_seed=operation_seed,
                    unsupported_reasons=["PREPARATION.INFLUENCE_REMOVAL_UNSUPPORTED"],
                ),
                None,
                _unprepared_scientific_input(canonical),
            )
        evaluation_membership = unique_membership
        fields, transition_bytes = _influence_public_universe_fields(
            plan=plan,
            candidate=candidate,
            prepared_dataset_id=prepared.prepared_dataset_id,
            audit_dataset_digest=prepared.audit_dataset_digest,
            source_scientific_data_digest=canonical.scientific_data_digest,
            event_count=canonical.view.event_count,
            memberships=memberships,
            pre_operation_memberships=pre_operation_memberships,
            instances=instances,
            retained_membership=unique_membership,
            removed_membership=removed_membership,
        )
        source_analysis_spec_id = cast(str, operation["source_analysis_spec_id"])
    elif supported_transformed_null:
        try:
            null_plan, arrays = _transformed_null_membership_and_arrays(
                canonical,
                operation,
                cast(str, operation_seed),
            )
        except _CandidatePreparationInvalid:
            return (
                _unprepared_record(
                    candidate,
                    state="PREPARATION_UNSUPPORTED",
                    operation_seed=operation_seed,
                    unsupported_reasons=["PREPARATION.NULL_TRANSFORMATION_UNSUPPORTED"],
                ),
                None,
                _unprepared_scientific_input(canonical),
            )
        memberships = null_plan.source_membership
        pre_operation_memberships = memberships
        instances = null_plan.transformed_instances
        unique_membership = null_plan.transformed_membership
        evaluation_membership = null_plan.transformed_membership
        removed_membership = ()
        fields, transition_bytes = _transformed_null_public_universe_fields(
            plan=plan,
            candidate=candidate,
            prepared_dataset_id=prepared.prepared_dataset_id,
            audit_dataset_digest=prepared.audit_dataset_digest,
            source_scientific_data_digest=canonical.scientific_data_digest,
            event_ids=canonical.view.event_ids,
            null_plan=null_plan,
            operation_seed=cast(str, operation_seed),
        )
        source_analysis_spec_id = cast(str, operation["source_analysis_spec_id"])
    else:
        raise UniverseIdentityError("Prepared candidate operation support is inconsistent.")
    universe = _build_universe(
        plan,
        candidate,
        fields,
        master_seed,
        operation_seed,
        profile_chain_seeds=execution_origin.profile_chain_seeds,
    )
    replay = _PrivatePreparationReplayState(
        plan_digest=cast(str, plan["plan_digest"]),
        candidate_ordinal=cast(int, candidate["candidate_ordinal"]),
        candidate_id=cast(str, candidate["candidate_id"]),
        analysis_spec_id=cast(str, candidate["analysis_spec_id"]),
        source_analysis_spec_id=source_analysis_spec_id,
        operation_seed=operation_seed,
        preparation_rule_registry_digest=_PREPARATION_RULE_REGISTRY_DIGEST,
        source_membership=memberships,
        cohort_membership=memberships,
        pre_operation_membership=pre_operation_memberships,
        operation_instances=instances,
        operation_unique_membership=unique_membership,
        training_instances=instances,
        training_unique_membership=unique_membership,
        evaluation_membership=evaluation_membership,
        removed_membership=removed_membership,
        public_universe_fields_bytes=canonical_json_bytes(fields),
        private_transition_chain_bytes=transition_bytes,
    )
    _verify_universe(
        plan,
        candidate,
        universe,
        replay,
        master_seed,
        prepared.prepared_dataset_id,
        canonical.scientific_data_digest,
        cast(NDArray[np.float64], canonical.private.arrays["event_values"]),
        profile_chain_seeds=execution_origin.profile_chain_seeds,
    )
    dataset_projection = _dataset_projection(
        spec,
        canonical,
        arrays,
        training_prepared_data_digest=(
            cast(str, fields["training_prepared_data_digest"])
            if (
                supported_bootstrap
                or supported_subsample
                or supported_influence
                or supported_transformed_null
                or supported_fixed_rescale
            )
            else None
        ),
        conformance_demo_provenance=conformance_demo_provenance,
    )
    candidate_provenance_issuance: object | None = None
    if execution_origin.route == "PUBLIC_SYNTHETIC":
        from ebm_audit.synthetic.audit_input import (
            SealedPublicSyntheticAuditInput,
            _issue_public_synthetic_candidate_provenance,
        )

        if type(execution_origin.owner) is not SealedPublicSyntheticAuditInput:
            raise UniverseIdentityError("Public-synthetic preparation owner is invalid.")
        provenance, candidate_provenance_issuance = (
            _issue_public_synthetic_candidate_provenance(
                execution_origin.owner,
                prepared_dataset=state.prepared_dataset,
                config_digest=state.run_config.resolved_public_digest,
                candidate_id=cast(str, candidate["candidate_id"]),
                analysis_spec_id=cast(str, candidate["analysis_spec_id"]),
                operation_intent=operation,
                operation_seed=operation_seed,
                dataset_projection=dataset_projection,
                arrays=arrays,
            )
        )
        dataset_projection["synthetic_provenance"] = provenance
        try:
            validate_instance(
                dataset_projection,
                "worker-protocol.schema.json",
                definition="DatasetDescriptor",
            )
        except SchemaValidationError:
            raise UniverseIdentityError(
                "The public-synthetic worker dataset projection is invalid."
            ) from None
    backend = cast(Mapping[str, Any], spec["backend"])
    worker_owner = _worker_owner_for_state(
        state, cast(str, backend["adapter_id"]), cast(str, backend["algorithm_id"])
    )
    description = worker_owner.description
    description_readback = worker_owner.description_readback
    selected_binding = dict(worker_owner.selected_algorithm_binding)
    worker_identity_digest = cast(
        str,
        description_readback.expected_identity["selected_backend_identity_digest"],
    )
    data_identity_digest = _prepared_data_identity_digest(
        prepared_dataset_id=prepared.prepared_dataset_id,
        universe=universe,
        dataset=dataset_projection,
    )
    record = {
        "record_schema_version": "ebm-audit-preparation-record/2.0",
        "candidate_ordinal": candidate["candidate_ordinal"],
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "state": "PREPARED",
        "operation_seed": operation_seed,
        "applied_preparation_rule_ids": ["preparation.complete/1"],
        "reasons": [],
        "universe_spec": universe,
    }
    _validate_schema(record, "PreparationRecord")
    _verify_preparation_record_rules(
        candidate,
        record,
        _PREPARATION_RULE_REGISTRY["ordered_rules"],
        {row["rule_id"]: row for row in _PREPARATION_RULE_REGISTRY["ordered_rules"]},
    )
    pending = _PendingPreparedCandidate(
        candidate=copy.deepcopy(dict(candidate)),
        universe=copy.deepcopy(universe),
        record=copy.deepcopy(record),
        dataset_projection=copy.deepcopy(dataset_projection),
        arrays=arrays,
        private_replay=replay,
        authenticated_description=description,
        authenticated_description_state=worker_owner.description_state,
        authenticated_description_readback=description_readback,
        canonical_dataset=canonical,
        selected_algorithm_binding=copy.deepcopy(selected_binding),
        planning_summary_binding=state.planning_summary.binding,
        config_digest=state.run_config.resolved_public_digest,
        prepared_dataset_id=prepared.prepared_dataset_id,
        prepared_dataset=state.prepared_dataset,
        data_identity_digest=data_identity_digest,
        protocol_identity_digest=_prepared_protocol_identity_digest(),
        worker_identity_digest=worker_identity_digest,
        execution_origin=execution_origin,
        candidate_provenance_issuance=candidate_provenance_issuance,
    )
    return record, pending, None


def _verify_receipt(receipt: Mapping[str, Any], plan: Mapping[str, Any], master_seed: str) -> None:
    _validate_schema(plan, "AnalysisPlan")
    _validate_schema(receipt, "PreparationReceipt")
    expected_plan_digest = analysis_plan_digest(_plan_preimage(plan))
    if (
        not hmac.compare_digest(cast(str, plan["plan_digest"]), expected_plan_digest)
        or receipt["plan_schema_version"] != plan["plan_schema_version"]
        or receipt["plan_digest"] != plan["plan_digest"]
        or receipt["preparation_rule_registry_digest"] != _PREPARATION_RULE_REGISTRY_DIGEST
    ):
        raise UniverseIdentityError("PreparationReceipt/2 is detached from Plan/3.")
    expected_digest = preparation_receipt_digest(_receipt_preimage(receipt))
    if not hmac.compare_digest(cast(str, receipt["receipt_digest"]), expected_digest):
        raise UniverseIdentityError("PreparationReceipt/2 digest is detached.")
    candidates = cast(Sequence[Mapping[str, Any]], plan["candidates"])
    records = cast(Sequence[Mapping[str, Any]], receipt["records"])
    if len(records) != len(candidates):
        raise UniverseIdentityError("PreparationReceipt/2 candidate coverage is incomplete.")
    for candidate, record in zip(candidates, records, strict=True):
        if (
            record["candidate_ordinal"] != candidate["candidate_ordinal"]
            or record["candidate_id"] != candidate["candidate_id"]
            or record["analysis_spec_id"] != candidate["analysis_spec_id"]
        ):
            raise UniverseIdentityError("A preparation record was reordered or substituted.")
        _canonical_reason_rows(record["reasons"], label="Preparation reasons")
        _verify_preparation_record_rules(
            candidate,
            record,
            _PREPARATION_RULE_REGISTRY["ordered_rules"],
            {row["rule_id"]: row for row in _PREPARATION_RULE_REGISTRY["ordered_rules"]},
        )
        if candidate["planning_outcome"] == "PLANNED":
            expected_seed = _expected_operation_seed(
                cast(Mapping[str, Any], candidate["analysis_spec"]), master_seed
            )
            if record["operation_seed"] != expected_seed:
                raise UniverseIdentityError("A preparation record changed its operation draw.")
    prepared_count = sum(record["state"] == "PREPARED" for record in records)
    actual_fit_count = sum(
        len(record["universe_spec"]["chain_plan"])
        for record in records
        if record["state"] == "PREPARED"
    )
    ceiling = cast(int, plan["counts"]["planned_fit_ceiling"])
    expected = {
        "prepared_candidate_count": prepared_count,
        "unprepared_candidate_count": len(records) - prepared_count,
        "actual_fit_count": actual_fit_count,
        "unprepared_fit_count": ceiling - actual_fit_count,
        "planned_fit_ceiling": ceiling,
    }
    if actual_fit_count > ceiling or any(receipt[key] != value for key, value in expected.items()):
        raise UniverseIdentityError("PreparationReceipt/2 fit accounting is inconsistent.")


def _build_prepared_authorization(
    plan: Mapping[str, Any],
    receipt: Mapping[str, Any],
    pending: _PendingPreparedCandidate,
    master_seed: str,
) -> tuple[PreparedExecutionAuthorization, _PreparedExecutionAuthorizationState]:
    state = _PreparedExecutionAuthorizationState(
        plan_bytes=canonical_json_bytes(plan),
        planning_summary_binding_bytes=canonical_json_bytes(pending.planning_summary_binding),
        receipt_bytes=canonical_json_bytes(receipt),
        record_bytes=canonical_json_bytes(pending.record),
        universe_bytes=canonical_json_bytes(pending.universe),
        analysis_spec_bytes=canonical_json_bytes(pending.candidate["analysis_spec"]),
        dataset_projection_bytes=canonical_json_bytes(pending.dataset_projection),
        config_digest=pending.config_digest,
        prepared_dataset_id=pending.prepared_dataset_id,
        prepared_dataset=pending.prepared_dataset,
        data_identity_digest=pending.data_identity_digest,
        protocol_identity_digest=pending.protocol_identity_digest,
        worker_identity_digest=pending.worker_identity_digest,
        selected_algorithm_binding_bytes=canonical_json_bytes(pending.selected_algorithm_binding),
        master_seed=master_seed,
        authenticated_description=pending.authenticated_description,
        authenticated_description_state=pending.authenticated_description_state,
        authenticated_description_readback=pending.authenticated_description_readback,
        arrays=pending.arrays,
        canonical_dataset=pending.canonical_dataset,
        private_replay=pending.private_replay,
        private_replay_identity_digest=_private_replay_identity_digest(pending.private_replay),
        execution_origin=pending.execution_origin,
    )
    capability = object.__new__(PreparedExecutionAuthorization)
    _revalidate_prepared_authorization_state(
        state,
        provisional_profile_owner=(
            state.execution_origin.owner if state.execution_origin.route == "PROFILE" else None
        ),
    )
    return capability, state


def _revalidate_prepared_authorization_state(
    state: _PreparedExecutionAuthorizationState,
    *,
    provisional_profile_owner: object | None = None,
    retained_profile_group_state: _ProfilePreparedCandidateGroupState | None = None,
) -> None:
    if (
        type(state) is not _PreparedExecutionAuthorizationState
        or type(state.canonical_dataset) is not CanonicalDataset
        or not _arrays_are_exactly_frozen(state.arrays)
    ):
        raise TypeError("Prepared execution authorization state is invalid.")
    origin = state.execution_origin
    if type(origin) is not _PreparedExecutionOrigin:
        raise TypeError("Prepared execution origin is invalid.")
    if origin.route == "ORDINARY":
        if (
            origin != _ORDINARY_EXECUTION_ORIGIN
            or provisional_profile_owner is not None
            or retained_profile_group_state is not None
        ):
            raise TypeError("Ordinary prepared execution origin is invalid.")
    elif origin.route == "PUBLIC_SYNTHETIC":
        if (
            provisional_profile_owner is not None
            or retained_profile_group_state is not None
            or origin.profile_candidate_ordinal is not None
            or origin.profile_execution_identity_sha256 is not None
            or origin.profile_chain_seeds is not None
        ):
            raise TypeError("Public-synthetic prepared execution origin is invalid.")
        from ebm_audit.synthetic.audit_input import (
            _resolve_public_synthetic_preparation_binding,
        )

        if (
            _resolve_public_synthetic_preparation_binding(
                origin.owner,
                cast("PreparedAuditDataset", state.prepared_dataset),
                state.config_digest,
            )
            is None
        ):
            raise TypeError("Public-synthetic prepared execution origin changed.")
    elif origin.route == "PROFILE":
        if (
            type(origin.owner) is not _ProfilePreparedCandidateGroupPublication
            or type(origin.profile_candidate_ordinal) is not int
            or origin.profile_candidate_ordinal not in {0, 1, 2}
            or type(origin.profile_execution_identity_sha256) is not str
            or len(origin.profile_execution_identity_sha256) != 64
            or origin.profile_chain_seeds is None
            or len(origin.profile_chain_seeds) != 3
            or len(set(origin.profile_chain_seeds)) != 3
            or any(
                len(seed) != 16 or any(character not in "0123456789abcdef" for character in seed)
                for seed in origin.profile_chain_seeds
            )
        ):
            raise TypeError("Profile prepared execution origin is invalid.")
        publication = origin.owner
        with publication.lock:
            if provisional_profile_owner is publication:
                if (
                    retained_profile_group_state is not None
                    or publication.status != "FRESH"
                    or publication.token is None
                ):
                    raise TypeError("Provisional profile execution origin is invalid.")
            elif retained_profile_group_state is not None:
                group_state = retained_profile_group_state
                candidate_position = origin.profile_candidate_ordinal
                if (
                    provisional_profile_owner is not None
                    or type(group_state) is not _ProfilePreparedCandidateGroupState
                    or group_state.publication is not publication
                    or group_state.publication_token is not publication.token
                    or group_state.profile_execution_identity_sha256
                    != origin.profile_execution_identity_sha256
                    or group_state.candidate_states[candidate_position] is not state
                ):
                    raise TypeError("Profile prepared execution origin changed.")
                _PREPARED_AUTHORIZATION_STATES.require(
                    group_state.candidate_authorizations[candidate_position],
                    state,
                )
            else:
                raise TypeError(
                    "Profile prepared candidates require their exact live parent group."
                )
    else:
        raise TypeError("Prepared execution origin route is invalid.")
    try:
        validate_canonical_dataset(state.canonical_dataset)
    except InvalidInputError:
        raise TypeError("Prepared execution canonical data owner is invalid.") from None
    try:
        prepared_owner = _resolve_private_prepared_dataset(state.prepared_dataset)
    except TypeError:
        raise TypeError("Prepared execution audit-dataset owner is invalid.") from None
    if state.private_replay_identity_digest != _private_replay_identity_digest(
        state.private_replay
    ):
        raise TypeError("Prepared private replay is detached from its sealed identity.")
    plan = _closed_object(state.plan_bytes)
    planning_summary = _closed_object(state.planning_summary_binding_bytes)
    receipt = _closed_object(state.receipt_bytes)
    record = _closed_object(state.record_bytes)
    universe = _closed_object(state.universe_bytes)
    spec = _closed_object(state.analysis_spec_bytes)
    dataset = _closed_object(state.dataset_projection_bytes)
    _validate_schema(planning_summary, "ValidatedPlanningSummaryBindingPreimage")
    _verify_receipt(receipt, plan, state.master_seed)
    _validate_schema(record, "PreparationRecord")
    _validate_schema(universe, "UniverseSpec")
    ordinal = record["candidate_ordinal"]
    if type(ordinal) is not int or ordinal < 0 or ordinal >= len(plan["candidates"]):
        raise TypeError("Prepared execution authorization has no exact plan position.")
    candidate = cast(Mapping[str, Any], plan["candidates"][ordinal])
    if (
        record["state"] != "PREPARED"
        or record["universe_spec"] != universe
        or receipt["records"][ordinal] != record
        or candidate["analysis_spec"] != spec
        or plan["plan_digest"] != universe["plan_digest"]
        or receipt["plan_digest"] != plan["plan_digest"]
        or planning_summary["resolved_public_config_digest"] != state.config_digest
        or planning_summary["prepared_audit_dataset_id"] != state.prepared_dataset_id
        or prepared_owner.prepared_dataset_id != state.prepared_dataset_id
        or prepared_owner.audit_dataset_digest != universe["source_prepared_data_digest"]
        or planning_summary["public_intent_manifest_digest"]
        != plan["public_intent_manifest_digest"]
        or planning_summary["planning_dataset_summary"] != plan["planning_dataset_summary"]
    ):
        raise TypeError("Prepared execution authorization owners are detached.")
    _verify_universe(
        plan,
        candidate,
        universe,
        state.private_replay,
        state.master_seed,
        state.prepared_dataset_id,
        state.canonical_dataset.scientific_data_digest,
        cast(
            NDArray[np.float64],
            state.canonical_dataset.private.arrays["event_values"],
        ),
        profile_chain_seeds=origin.profile_chain_seeds,
    )
    catalog = {
        name: array_catalog_entry(
            name,
            array,
            semantic_version=dataset["array_catalog"][name]["semantic_version"],
        )
        for name, array in state.arrays.items()
        if name in dataset["array_catalog"]
    }
    if catalog != dataset["array_catalog"]:
        raise TypeError("Prepared execution arrays differ from their immutable catalogue.")
    operation = cast(Mapping[str, Any], spec["operation_intent"])
    conformance_provenance = dataset.get("synthetic_provenance")
    project_candidate_provenance = (
        conformance_provenance.get("project_candidate")
        if isinstance(conformance_provenance, Mapping)
        else None
    )
    source_candidate: Mapping[str, Any]
    source_spec: Mapping[str, Any]
    fixed_rescale_source_id = (
        cast(str, plan["baseline_analysis_spec_id"])
        if _supports_fixed_event_rescale(spec)
        else None
    )
    if fixed_rescale_source_id is not None:
        source_candidate = _source_candidate_for_fixed_event_rescale(plan, candidate)
        source_spec = cast(Mapping[str, Any], source_candidate["analysis_spec"])
        (
            _memberships,
            _instances,
            canonical_arrays,
            _changed_cell_count,
        ) = _fixed_event_rescale_membership_and_arrays(state.canonical_dataset)
        _pre_operation_memberships = _memberships
        _unique_membership = _memberships
        _evaluation_membership = _memberships
        _removed_membership = ()
        expected_variant_id = state.canonical_dataset.view.variant_id
        expected_participant_count = state.canonical_dataset.view.participant_count
        expected_evaluation_participant_count = expected_participant_count
        expected_evaluation_prepared_data_digest = cast(
            str,
            universe["training_prepared_data_digest"],
        )
    elif operation["kind"] == "ordinary":
        source_candidate = candidate
        source_spec = spec
        _memberships, _instances, canonical_arrays = _private_membership_and_arrays(
            state.canonical_dataset
        )
        _pre_operation_memberships = _memberships
        _unique_membership = _memberships
        _evaluation_membership = _memberships
        _removed_membership: tuple[_PrivateMembership, ...] = ()
        expected_variant_id = state.canonical_dataset.view.variant_id
        expected_participant_count = state.canonical_dataset.view.participant_count
        expected_evaluation_participant_count = (
            0
            if conformance_provenance is not None and project_candidate_provenance is None
            else expected_participant_count
        )
        expected_evaluation_prepared_data_digest = state.canonical_dataset.scientific_data_digest
    elif operation["kind"] == "bootstrap":
        source_candidate = _source_candidate_for_derived_operation(plan, candidate)
        source_spec = cast(Mapping[str, Any], source_candidate["analysis_spec"])
        try:
            (
                _memberships,
                _pre_operation_memberships,
                _instances,
                _unique_membership,
                canonical_arrays,
            ) = _stratified_bootstrap_membership_and_arrays(
                state.canonical_dataset,
                operation,
                cast(str, state.private_replay.operation_seed),
            )
        except _CandidatePreparationInvalid:
            raise TypeError(
                "Prepared bootstrap arrays no longer have valid required strata."
            ) from None
        expected_variant_id = cast(str, spec["dataset_variant_intent"]["source_variant_id"])
        expected_participant_count = len(_instances)
        expected_evaluation_participant_count = state.canonical_dataset.view.participant_count
        expected_evaluation_prepared_data_digest = state.canonical_dataset.scientific_data_digest
        _evaluation_membership = _memberships
        _removed_membership = ()
    elif operation["kind"] == "subsample":
        source_candidate = _source_candidate_for_derived_operation(plan, candidate)
        source_spec = cast(Mapping[str, Any], source_candidate["analysis_spec"])
        try:
            (
                _memberships,
                _pre_operation_memberships,
                subsample_plan,
                canonical_arrays,
            ) = _stratified_subsample_membership_and_arrays(
                state.canonical_dataset,
                operation,
                cast(str, state.private_replay.operation_seed),
                minimum_reference_rows=cast(
                    int | None,
                    spec["covariate_adjustment"]["minimum_reference_rows"],
                ),
            )
        except _CandidatePreparationInvalid:
            raise TypeError(
                "Prepared subsample arrays no longer have a feasible allocation."
            ) from None
        _instances = subsample_plan.instances
        _unique_membership = subsample_plan.retained_membership
        _evaluation_membership = _memberships
        _removed_membership = ()
        expected_variant_id = cast(str, spec["dataset_variant_intent"]["source_variant_id"])
        expected_participant_count = len(_instances)
        expected_evaluation_participant_count = state.canonical_dataset.view.participant_count
        expected_evaluation_prepared_data_digest = state.canonical_dataset.scientific_data_digest
    elif operation["kind"] == "influence":
        source_candidate = _source_candidate_for_derived_operation(plan, candidate)
        source_spec = cast(Mapping[str, Any], source_candidate["analysis_spec"])
        try:
            (
                _memberships,
                _pre_operation_memberships,
                _instances,
                _unique_membership,
                _removed_membership,
                canonical_arrays,
            ) = _leave_one_out_membership_and_arrays(
                state.canonical_dataset,
                operation,
            )
        except _CandidatePreparationInvalid:
            raise TypeError(
                "Prepared influence arrays no longer retain both required roles."
            ) from None
        _evaluation_membership = _unique_membership
        expected_variant_id = cast(str, spec["dataset_variant_intent"]["source_variant_id"])
        expected_participant_count = len(_instances)
        expected_evaluation_participant_count = len(_evaluation_membership)
        expected_evaluation_prepared_data_digest = cast(
            str,
            universe["training_prepared_data_digest"],
        )
    elif operation["kind"] == "null" and _supports_transformed_null(spec):
        source_candidate = _source_candidate_for_derived_operation(plan, candidate)
        source_spec = cast(Mapping[str, Any], source_candidate["analysis_spec"])
        try:
            null_plan, canonical_arrays = _transformed_null_membership_and_arrays(
                state.canonical_dataset,
                operation,
                cast(str, state.private_replay.operation_seed),
            )
        except _CandidatePreparationInvalid:
            raise TypeError(
                "Prepared transformed-null arrays no longer produce an effective draw."
            ) from None
        _memberships = null_plan.source_membership
        _pre_operation_memberships = null_plan.source_membership
        _instances = null_plan.transformed_instances
        _unique_membership = null_plan.transformed_membership
        _evaluation_membership = null_plan.transformed_membership
        _removed_membership = ()
        expected_variant_id = cast(
            str,
            spec["dataset_variant_intent"]["source_variant_id"],
        )
        expected_participant_count = len(_instances)
        expected_evaluation_participant_count = len(_evaluation_membership)
        expected_evaluation_prepared_data_digest = cast(
            str,
            universe["training_prepared_data_digest"],
        )
    else:
        raise TypeError("Prepared execution operation kind is unsupported.")
    if (
        _memberships != state.private_replay.source_membership
        or _pre_operation_memberships != state.private_replay.pre_operation_membership
        or _instances != state.private_replay.training_instances
        or _unique_membership != state.private_replay.training_unique_membership
        or _evaluation_membership != state.private_replay.evaluation_membership
        or _removed_membership != state.private_replay.removed_membership
        or set(canonical_arrays) != set(state.arrays)
        or any(
            not np.array_equal(canonical_arrays[name], state.arrays[name])
            for name in canonical_arrays
        )
    ):
        raise TypeError("Prepared execution arrays differ from their canonical data owner.")
    canonical_view = state.canonical_dataset.view
    if (
        state.canonical_dataset.private.universe_decision_id != source_candidate["candidate_id"]
        or state.canonical_dataset.private.component_digests != _component_digests(source_spec)
        or dataset["variant_id"] != expected_variant_id
        or canonical_view.variant_id != source_spec["dataset_variant_intent"]["source_variant_id"]
        or dataset["participant_count"] != expected_participant_count
        or dataset["evaluation_participant_count"] != expected_evaluation_participant_count
        or dataset["event_count"] != canonical_view.event_count
        or dataset["event_ids"] != list(canonical_view.event_ids)
        or dataset["event_directions"] != list(canonical_view.event_directions)
        or universe["evaluation_prepared_data_digest"] != expected_evaluation_prepared_data_digest
    ):
        raise TypeError("Prepared execution data projection is detached from its owner.")
    if conformance_provenance is not None:
        if not isinstance(conformance_provenance, Mapping):
            raise TypeError("Prepared conformance provenance is invalid.")
        if project_candidate_provenance is None:
            if operation["kind"] != "ordinary":
                raise TypeError("Prepared conformance provenance is invalid.")
        elif (
            not isinstance(project_candidate_provenance, Mapping)
            or origin.route != "PUBLIC_SYNTHETIC"
            or project_candidate_provenance.get("candidate_id") != candidate["candidate_id"]
            or project_candidate_provenance.get("analysis_spec_id")
            != candidate["analysis_spec_id"]
            or project_candidate_provenance.get("candidate_derivation_kind")
            != operation["kind"]
            or project_candidate_provenance.get("candidate_operation_seed")
            != state.private_replay.operation_seed
        ):
            raise TypeError("Prepared project-synthetic provenance is invalid.")
    if dataset["scientific_data_digest"] != universe[
        "training_prepared_data_digest"
    ] or state.private_replay.public_universe_fields_bytes != canonical_json_bytes(
        {
            key: universe[key]
            for key in (
                "source_prepared_data_digest",
                "training_prepared_data_digest",
                "evaluation_prepared_data_digest",
                "evaluation_membership_digest",
                "source_accounting_digest",
                "training_accounting_digest",
                "evaluation_accounting_digest",
                "aggregate_counts",
            )
        }
    ):
        raise TypeError("Prepared execution data identity is detached.")
    selected_binding = _closed_object(state.selected_algorithm_binding_bytes)
    from ebm_audit.adapters.invocation import (
        _AUTHENTICATED_DESCRIPTION_STATES,
        _AuthenticatedDescriptionReadback,
    )

    description_readback = state.authenticated_description_readback
    if (
        type(description_readback) is not _AuthenticatedDescriptionReadback
        or description_readback.description is not state.authenticated_description
        or _AUTHENTICATED_DESCRIPTION_STATES.get(state.authenticated_description)
        is not state.authenticated_description_state
        or description_readback.selected_algorithm_binding != selected_binding
        or sum(row == selected_binding for row in planning_summary["selected_algorithm_bindings"])
        != 1
        or state.worker_identity_digest
        != description_readback.expected_identity["selected_backend_identity_digest"]
        or state.data_identity_digest
        != _prepared_data_identity_digest(
            prepared_dataset_id=state.prepared_dataset_id,
            universe=universe,
            dataset=dataset,
        )
        or state.protocol_identity_digest != _prepared_protocol_identity_digest()
    ):
        raise TypeError("Prepared execution worker identity is detached.")


def _build_unprepared_result_authorization(
    *,
    plan: Mapping[str, Any],
    receipt: Mapping[str, Any],
    record: Mapping[str, Any],
    master_seed: str,
    planning_summary_binding: Mapping[str, Any],
    dataset_summary: Mapping[str, Any],
    config_digest: str,
    scientific_data_preimage_bytes: bytes | None,
    input_digest: str | None,
    source_byte_digest: str,
    prepared_dataset_id: str,
    prepared_dataset: object,
    preparation_namespace_key: object,
) -> tuple[UnpreparedResultAuthorization, _UnpreparedResultAuthorizationState]:
    state = _UnpreparedResultAuthorizationState(
        plan_bytes=canonical_json_bytes(plan),
        planning_summary_binding_bytes=canonical_json_bytes(planning_summary_binding),
        dataset_summary_bytes=canonical_json_bytes(dataset_summary),
        receipt_bytes=canonical_json_bytes(receipt),
        record_bytes=canonical_json_bytes(record),
        master_seed=master_seed,
        config_digest=config_digest,
        scientific_data_preimage_bytes=scientific_data_preimage_bytes,
        input_digest=input_digest,
        source_byte_digest=source_byte_digest,
        prepared_dataset_id=prepared_dataset_id,
        prepared_dataset=prepared_dataset,
        preparation_namespace_key=preparation_namespace_key,
    )
    capability = object.__new__(UnpreparedResultAuthorization)
    _revalidate_unprepared_result_authorization_state(state)
    return capability, state


def _revalidate_unprepared_result_authorization_state(
    state: _UnpreparedResultAuthorizationState,
) -> None:
    if type(state) is not _UnpreparedResultAuthorizationState:
        raise TypeError("Unprepared result authorization state is invalid.")
    plan = _closed_object(state.plan_bytes)
    planning_summary = _closed_object(state.planning_summary_binding_bytes)
    dataset_summary = _closed_object(state.dataset_summary_bytes)
    receipt = _closed_object(state.receipt_bytes)
    record = _closed_object(state.record_bytes)
    prepared = _resolve_private_prepared_dataset(state.prepared_dataset)
    _validate_schema(planning_summary, "ValidatedPlanningSummaryBindingPreimage")
    try:
        validate_instance(
            dataset_summary,
            "audit-config.schema.json",
            definition="ValidatedDatasetSummaryPreimage",
        )
    except SchemaValidationError:
        raise TypeError("Unprepared result data owner is invalid.") from None
    _verify_receipt(receipt, plan, state.master_seed)
    _validate_schema(record, "PreparationRecord")
    ordinal = record["candidate_ordinal"]
    if type(ordinal) is not int or ordinal < 0 or ordinal >= len(plan["candidates"]):
        raise TypeError("Unprepared result authorization has no exact plan position.")
    candidate = cast(Mapping[str, Any], plan["candidates"][ordinal])
    if (
        record["state"] == "PREPARED"
        or record["universe_spec"] is not None
        or receipt["records"][ordinal] != record
        or candidate["candidate_ordinal"] != ordinal
        or candidate["candidate_id"] != record["candidate_id"]
        or candidate["analysis_spec_id"] != record["analysis_spec_id"]
        or planning_summary["resolved_public_config_digest"] != state.config_digest
        or dataset_summary["resolved_config_digest"] != state.config_digest
        or dataset_summary["input_byte_digest"] != state.source_byte_digest
        or planning_summary["prepared_audit_dataset_id"] != state.prepared_dataset_id
        or prepared.prepared_dataset_id != state.prepared_dataset_id
        or prepared.source_admission.byte_digest != state.source_byte_digest
        or prepared.summary.preimage != dataset_summary
        or planning_summary["validated_dataset_summary_digest"]
        != structured_sha256("ebm-audit/validated-dataset-summary/1", dataset_summary)
        or planning_summary["public_intent_manifest_digest"]
        != plan["public_intent_manifest_digest"]
        or planning_summary["planning_dataset_summary"] != plan["planning_dataset_summary"]
    ):
        raise TypeError("Unprepared result authorization owners are detached.")
    requires_input = _unprepared_requires_input_digest(record)
    if requires_input:
        if state.scientific_data_preimage_bytes is None or state.input_digest is None:
            raise TypeError("A valid unprepared result lacks canonical scientific data.")
        try:
            canonical, rebuilt_prepared = _canonicalize_candidate_input(
                state.prepared_dataset,
                state.preparation_namespace_key,
                candidate,
                cast(Mapping[str, Any], candidate["analysis_spec"]),
            )
        except InvalidInputError:
            raise TypeError(
                "A valid unprepared result cannot rebuild canonical scientific data."
            ) from None
        commitment = _unprepared_scientific_input(canonical)
        if (
            rebuilt_prepared.prepared_dataset_id != state.prepared_dataset_id
            or commitment.preimage_bytes != state.scientific_data_preimage_bytes
            or not hmac.compare_digest(commitment.digest, state.input_digest)
        ):
            raise TypeError("Unprepared canonical scientific-data identity is detached.")
    else:
        if state.scientific_data_preimage_bytes is not None or state.input_digest is not None:
            raise TypeError("An invalid pre-canonical result cannot own input_digest.")
        if record["state"] == "PREPARATION_INVALID":
            reason_codes = {
                cast(str, row["reason_code"])
                for row in cast(Sequence[Mapping[str, Any]], record["reasons"])
            }
            if _SUBSAMPLE_ALLOCATION_INVALID_REASON in reason_codes:
                if reason_codes != {_SUBSAMPLE_ALLOCATION_INVALID_REASON}:
                    raise TypeError("Subsample allocation invalidity has conflicting reasons.")
                source_candidate = _source_candidate_for_derived_operation(plan, candidate)
                source_spec = cast(Mapping[str, Any], source_candidate["analysis_spec"])
                try:
                    canonical, rebuilt_prepared = _canonicalize_candidate_input(
                        state.prepared_dataset,
                        state.preparation_namespace_key,
                        source_candidate,
                        source_spec,
                    )
                except InvalidInputError:
                    raise TypeError(
                        "Subsample allocation invalidity cannot replace canonical invalidity."
                    ) from None
                operation = cast(
                    Mapping[str, Any],
                    cast(Mapping[str, Any], candidate["analysis_spec"])["operation_intent"],
                )
                try:
                    _stratified_subsample_membership_and_arrays(
                        canonical,
                        operation,
                        cast(str, record["operation_seed"]),
                        minimum_reference_rows=cast(
                            int | None,
                            cast(Mapping[str, Any], candidate["analysis_spec"])[
                                "covariate_adjustment"
                            ]["minimum_reference_rows"],
                        ),
                    )
                except _CandidatePreparationInvalid:
                    if rebuilt_prepared.prepared_dataset_id != state.prepared_dataset_id:
                        raise TypeError("Subsample invalidity changed its data owner.") from None
                else:
                    raise TypeError(
                        "PREPARATION_INVALID does not reproduce its subsample allocation failure."
                    )
            else:
                try:
                    _canonicalize_candidate_input(
                        state.prepared_dataset,
                        state.preparation_namespace_key,
                        candidate,
                        cast(Mapping[str, Any], candidate["analysis_spec"]),
                    )
                except InvalidInputError:
                    pass
                else:
                    raise TypeError(
                        "PREPARATION_INVALID does not reproduce its canonicalization failure."
                    )


def _unprepared_terminal_status(record: Mapping[str, Any]) -> str:
    """Return the only permitted finalization status for one unprepared record."""

    state = record.get("state")
    if state == "PREPARATION_INVALID":
        return "INVALID_SPECIFICATION"
    if state == "PREPARATION_UNSUPPORTED":
        return "UNSUPPORTED_CAPABILITY"
    if state != "PLAN_INELIGIBLE":
        raise UniverseIdentityError("Only an unprepared record has an unprepared status.")
    reasons = cast(Sequence[Mapping[str, Any]], record.get("reasons"))
    codes = {row.get("reason_code") for row in reasons}
    if codes & _PLAN_INVALID_REASON_CODES:
        return "INVALID_SPECIFICATION"
    if codes == {_PLAN_UNSUPPORTED_REASON_CODE}:
        return "UNSUPPORTED_CAPABILITY"
    raise UniverseIdentityError("Planning reasons have no exact unprepared status mapping.")


def _unprepared_requires_input_digest(record: Mapping[str, Any]) -> bool:
    """Derive the sole nullable-input boundary from the exact terminal branch."""

    status = _unprepared_terminal_status(record)
    state = record.get("state")
    if status == "UNSUPPORTED_CAPABILITY":
        if state not in {"PLAN_INELIGIBLE", "PREPARATION_UNSUPPORTED"}:
            raise UniverseIdentityError("Unsupported unprepared input ownership is invalid.")
        return True
    if status == "INVALID_SPECIFICATION":
        if state not in {"PLAN_INELIGIBLE", "PREPARATION_INVALID"}:
            raise UniverseIdentityError("Invalid unprepared input ownership is invalid.")
        return False
    raise UniverseIdentityError("Unprepared input ownership has no exact status.")


def _attest_profile_execution_source_file(
    repository_root: Path,
    declared_file: Mapping[str, Any],
) -> None:
    """Match one declared source file without following lexical symlinks."""

    declared_path = declared_file.get("path")
    if type(declared_path) is not str:
        raise TypeError("A profile execution source file is invalid.")
    relative_path = Path(declared_path)
    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or any(component in {"", ".", ".."} for component in relative_path.parts)
    ):
        raise TypeError("A profile execution source path escapes the candidate tree.")
    try:
        root_metadata = repository_root.lstat()
    except OSError:
        raise TypeError("The profile candidate tree is unavailable.") from None
    if repository_root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise TypeError("The profile candidate tree is not an exact directory.")

    lexical_path = repository_root
    for position, component in enumerate(relative_path.parts):
        lexical_path /= component
        try:
            component_metadata = lexical_path.lstat()
        except OSError:
            raise TypeError("A profile execution source component is unavailable.") from None
        if stat.S_ISLNK(component_metadata.st_mode):
            raise TypeError("A profile execution source path contains a symlink.")
        is_final = position == len(relative_path.parts) - 1
        if (is_final and not stat.S_ISREG(component_metadata.st_mode)) or (
            not is_final and not stat.S_ISDIR(component_metadata.st_mode)
        ):
            raise TypeError("A profile execution source component has the wrong file kind.")

    resolved_root = repository_root.resolve()
    resolved_path = lexical_path.resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError:
        raise TypeError("A profile execution source path escapes the candidate tree.") from None
    try:
        content = lexical_path.read_bytes()
        final_metadata = lexical_path.lstat()
    except OSError:
        raise TypeError("A profile execution source file is unavailable.") from None
    if (
        stat.S_ISLNK(final_metadata.st_mode)
        or not stat.S_ISREG(final_metadata.st_mode)
        or final_metadata.st_dev != component_metadata.st_dev
        or final_metadata.st_ino != component_metadata.st_ino
        or final_metadata.st_mode != component_metadata.st_mode
        or final_metadata.st_size != component_metadata.st_size
    ):
        raise TypeError("A profile execution source file changed during attestation.")
    executable_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    observed = {
        "path": relative_path.as_posix(),
        "git_mode": "100755" if final_metadata.st_mode & executable_bits else "100644",
        "kind": "file",
        "byte_length": len(content),
        "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
    }
    if dict(declared_file) != observed:
        raise TypeError("The live profile execution source manifest changed.")


def _live_profile_execution_plan(plan_owner: object) -> dict[str, Any]:
    """Revalidate the sealed profile plan and its exact live source files."""

    from ebm_audit.evaluator import profile_characterization as profile_module

    profile_module._read_sealed_profile_characterization_plan(plan_owner)
    projection = profile_module.project_profile_characterization_plan(
        cast(profile_module.SealedProfileCharacterizationPlan, plan_owner)
    )
    plan_receipt = projection.get("plan_receipt")
    if type(plan_receipt) is not dict:
        raise TypeError("The sealed profile plan has no exact execution receipt.")
    manifest = plan_receipt.get("execution_source_manifest")
    if type(manifest) is not dict:
        raise TypeError("The sealed profile plan has no execution source manifest.")
    expected_roles = tuple(profile_module._PROFILE_FIT_SOURCE_ROLES)
    entries = manifest.get("ordered_entries")
    if (
        type(entries) is not list
        or tuple(row.get("fit_role") for row in entries if type(row) is dict) != expected_roles
        or len(entries) != len(expected_roles)
    ):
        raise TypeError("The profile execution source-manifest roles changed.")
    repository_root = Path(__file__).resolve().parents[3]
    for entry in entries:
        if type(entry) is not dict or type(entry.get("ordered_files")) is not list:
            raise TypeError("A profile execution source-manifest entry is invalid.")
        ordered_files = cast(list[object], entry["ordered_files"])
        if any(type(row) is not dict or type(row.get("path")) is not str for row in ordered_files):
            raise TypeError("A profile execution source file is invalid.")
        paths = [cast(dict[str, Any], row)["path"] for row in ordered_files]
        if paths != sorted(set(paths)):
            raise TypeError("Profile execution source files are not canonically ordered.")
        for row in ordered_files:
            _attest_profile_execution_source_file(
                repository_root,
                cast(dict[str, Any], row),
            )
    return projection


def _validate_profile_preparation_context(
    context: _ProfilePreparationContext,
    state: _PlanningAuthorityState,
    plan: Mapping[str, Any],
) -> None:
    if (
        type(context) is not _ProfilePreparationContext
        or context.run_config is not state.run_config
        or context.prepared_dataset is not state.prepared_dataset
        or type(context.publication) is not _ProfilePreparedCandidateGroupPublication
        or context.publication_token is not context.publication.token
        or len(context.ordered_analysis_spec_bytes) != 3
        or len(context.ordered_analysis_spec_ids) != 3
        or len(set(context.ordered_analysis_spec_ids)) != 3
        or len(context.profile_chain_seeds) != 3
        or len(set(context.profile_chain_seeds)) != 3
    ):
        raise UniverseIdentityError("Profile preparation ownership is invalid.")
    candidates = cast(Sequence[Mapping[str, Any]], plan["candidates"])
    if (
        len(candidates) != 3
        or plan["counts"]["candidate_count"] != 3
        or plan["counts"]["planned_candidate_count"] != 3
        or plan["counts"]["planned_fit_ceiling"] != 9
        or {candidate["analysis_spec_id"] for candidate in candidates}
        != set(context.ordered_analysis_spec_ids)
    ):
        raise UniverseIdentityError("Profile preparation requires the canonical three candidates.")
    expected_chain_rows = [
        {"chain_ordinal": ordinal, "chain_id": f"chain-{ordinal:04d}"} for ordinal in range(3)
    ]
    candidates_by_spec_id = {candidate["analysis_spec_id"]: candidate for candidate in candidates}
    for spec_bytes, spec_id in zip(
        context.ordered_analysis_spec_bytes,
        context.ordered_analysis_spec_ids,
        strict=True,
    ):
        candidate = candidates_by_spec_id[spec_id]
        if (
            candidate["planning_outcome"] != "PLANNED"
            or candidate["analysis_spec_id"] != candidate["candidate_id"]
            or canonical_json_bytes(candidate["analysis_spec"]) != spec_bytes
            or candidate["chain_slots"] != expected_chain_rows
            or candidate["planned_fit_ceiling"] != 3
            or candidate["analysis_spec"]["operation_intent"]["kind"] != "ordinary"
        ):
            raise UniverseIdentityError("A profile candidate differs from its sealed Plan/3 owner.")


def _profile_execution_origin(
    context: _ProfilePreparationContext,
    candidate: Mapping[str, Any],
) -> _PreparedExecutionOrigin:
    try:
        profile_ordinal = context.ordered_analysis_spec_ids.index(
            cast(str, candidate["analysis_spec_id"])
        )
    except ValueError:
        raise UniverseIdentityError("A profile candidate has no sealed budget owner.") from None
    return _PreparedExecutionOrigin(
        route="PROFILE",
        owner=context.publication,
        profile_candidate_ordinal=profile_ordinal,
        profile_execution_identity_sha256=context.profile_execution_identity_sha256,
        profile_chain_seeds=context.profile_chain_seeds,
    )


def _derive_profile_chain_seeds(
    input_binding_state: _ProfileGeneratedInputBindingState,
) -> tuple[str, str, str]:
    from ebm_audit.evaluator.profile_characterization import derive_profile_public_seed

    selected_binding = strict_json_loads(input_binding_state.selected_synthetic_event_binding_bytes)
    if type(selected_binding) is not dict:
        raise TypeError("The profile synthetic-event binding is invalid.")
    synthetic_event_digest = selected_binding.get("profile_synthetic_event_binding_sha256")
    if (
        type(synthetic_event_digest) is not str
        or len(synthetic_event_digest) != 64
        or any(character not in "0123456789abcdef" for character in synthetic_event_digest)
    ):
        raise TypeError("The profile synthetic-event binding digest is invalid.")
    seeds = tuple(
        derive_profile_public_seed(
            profile_execution_identity_sha256=(
                input_binding_state.profile_execution_identity_sha256
            ),
            profile_synthetic_event_binding_sha256=synthetic_event_digest,
            chain_id=f"chain-{ordinal:04d}",
        )
        for ordinal in range(3)
    )
    if len(seeds) != 3 or len(set(seeds)) != 3:
        raise TypeError("Profile chain-seed derivation is invalid.")
    return seeds


def _resolve_profile_group_candidate_state(
    group_state: _ProfilePreparedCandidateGroupState,
    authorization: CandidateResultAuthorization,
) -> _PreparedExecutionAuthorizationState:
    """Resolve one candidate only through its fully retained parent-group state."""

    for expected, candidate_state in zip(
        group_state.candidate_authorizations,
        group_state.candidate_states,
        strict=True,
    ):
        if authorization is expected:
            _PREPARED_AUTHORIZATION_STATES.require(expected, candidate_state)
            _revalidate_prepared_authorization_state(
                candidate_state,
                retained_profile_group_state=group_state,
            )
            return candidate_state
    raise TypeError("That candidate does not belong to the exact profile group.")


def _validate_profile_prepared_candidate_group_state(
    value: ProfilePreparedCandidateGroup,
    state: _ProfilePreparedCandidateGroupState,
    *,
    publication_status: str,
) -> Mapping[str, Any]:
    """Validate the complete retained graph without recursively reading candidates."""

    if type(state) is not _ProfilePreparedCandidateGroupState:
        raise TypeError("Profile prepared-candidate group storage is invalid.")
    publication = state.publication
    with publication.lock:
        published = None if publication.group_ref is None else publication.group_ref()
        if (
            publication.status != publication_status
            or published is not value
            or state.publication_token is not publication.token
        ):
            raise TypeError("Profile prepared-candidate group publication changed.")

    from ebm_audit.profile_input_identity import _read_profile_generated_input_binding

    input_binding_state = _read_profile_generated_input_binding(state.input_binding)
    projection = _live_profile_execution_plan(state.plan_owner)
    plan_receipt = projection.get("plan_receipt")
    if type(plan_receipt) is not dict:
        raise TypeError("The profile candidate group lost its sealed plan receipt.")
    execution_identity = plan_receipt.get("profile_execution_identity")
    if type(execution_identity) is not dict:
        raise TypeError("The profile candidate group lost its execution identity.")
    try:
        planning_state = state.planning_authority._state()
        transaction_state = _PREPARATION_TRANSACTION_STATES.require(
            state.transaction,
            state.transaction_state,
        )
        _validate_preparation_transaction_state(
            transaction_state,
            lambda authorization: _resolve_profile_group_candidate_state(
                state,
                authorization,
            ),
        )
    except TypeError:
        raise TypeError("The profile candidate group lost a retained owner.") from None
    candidate_ids = tuple(
        cast(str, _closed_object(candidate_state.record_bytes)["analysis_spec_id"])
        for candidate_state in state.candidate_states
    )
    if (
        input_binding_state is not state.input_binding_state
        or input_binding_state.plan_owner is not state.plan_owner
        or input_binding_state.run_config is not planning_state.run_config
        or input_binding_state.prepared_dataset is not planning_state.prepared_dataset
        or planning_state is not state.planning_authority_state
        or planning_state.preparation_publication is None
        or planning_state.preparation_publication.transaction is not None
        or transaction_state is not state.transaction_state
        or transaction_state.unprepared_authorizations
        or len(transaction_state.authorizations) != 3
        or len(transaction_state.candidate_authorizations) != 3
        or any(
            observed is not expected
            for observed, expected in zip(
                transaction_state.candidate_authorizations,
                state.candidate_authorizations,
                strict=True,
            )
        )
        or candidate_ids != state.ordered_analysis_spec_ids
        or state.ordered_analysis_spec_ids != input_binding_state.ordered_analysis_spec_ids
        or state.coordinate_ordinal != input_binding_state.coordinate_ordinal
        or state.profile_execution_identity_sha256
        != input_binding_state.profile_execution_identity_sha256
        or execution_identity.get("profile_execution_identity_sha256")
        != state.profile_execution_identity_sha256
        or _derive_profile_chain_seeds(input_binding_state) != state.profile_chain_seeds
    ):
        raise TypeError("Profile prepared-candidate group ownership changed.")
    for position, (candidate, candidate_state) in enumerate(
        zip(state.candidate_authorizations, state.candidate_states, strict=True)
    ):
        if _resolve_profile_group_candidate_state(state, candidate) is not candidate_state:
            raise TypeError("A profile candidate lost its exact retained state.")
        origin = candidate_state.execution_origin
        if (
            origin.owner is not publication
            or origin.profile_candidate_ordinal != position
            or origin.profile_execution_identity_sha256 != state.profile_execution_identity_sha256
            or origin.profile_chain_seeds != state.profile_chain_seeds
        ):
            raise TypeError("A profile candidate lost its exact parent-group position.")
    _PROFILE_PREPARED_CANDIDATE_GROUP_STATES.require(value, state)
    return projection


def _read_profile_prepared_candidate_group_boundary(
    value: object,
) -> tuple[_ProfilePreparedCandidateGroupState, Mapping[str, Any]]:
    """Revalidate once and return the exact plan projection used by that boundary."""

    if type(value) is not ProfilePreparedCandidateGroup:
        raise TypeError("A genuine profile prepared-candidate group is required.")
    try:
        state = _PROFILE_PREPARED_CANDIDATE_GROUP_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine profile prepared-candidate group is required.") from None
    projection = _validate_profile_prepared_candidate_group_state(
        value,
        state,
        publication_status="PUBLISHED",
    )
    return state, projection


def _read_profile_prepared_candidate_group(
    value: object,
) -> _ProfilePreparedCandidateGroupState:
    """Revalidate one published group and all exact retained owners."""

    state, _projection = _read_profile_prepared_candidate_group_boundary(value)
    return state


def _read_profile_prepared_candidate(
    group: object,
    candidate_ordinal: object,
) -> tuple[PreparedExecutionAuthorization, _PreparedExecutionAuthorizationState]:
    """Resolve one exact profile candidate only through its live parent group."""

    group_state = _read_profile_prepared_candidate_group(group)
    if type(candidate_ordinal) is not int or candidate_ordinal not in {0, 1, 2}:
        raise TypeError("A profile candidate ordinal must be exactly 0, 1, or 2.")
    authorization = group_state.candidate_authorizations[candidate_ordinal]
    state = _resolve_profile_group_candidate_state(group_state, authorization)
    return authorization, state


def prepare_profile_candidate_group(
    plan_owner: SealedProfileCharacterizationPlan,
    input_binding: ProfileGeneratedInputBinding,
) -> ProfilePreparedCandidateGroup:
    """Atomically prepare the exact three candidates for one generated profile input."""

    from ebm_audit.adapters import WorkerConfig, WorkerInvoker
    from ebm_audit.profile_input_identity import _read_profile_generated_input_binding

    publication = _profile_group_publication(input_binding)
    with publication.lock:
        existing = None if publication.group_ref is None else publication.group_ref()
        if existing is not None:
            existing_state = _read_profile_prepared_candidate_group(existing)
            if (
                existing_state.plan_owner is not plan_owner
                or existing_state.input_binding is not input_binding
            ):
                raise TypeError("The profile input was prepared by another sealed plan.")
            return existing
        if publication.status != "FRESH":
            raise TypeError("The profile prepared-candidate publication was already consumed.")

        try:
            input_binding_state = _read_profile_generated_input_binding(input_binding)
            if input_binding_state.plan_owner is not plan_owner:
                raise TypeError("The generated profile input belongs to another sealed plan.")
            projection = _live_profile_execution_plan(plan_owner)
            plan_receipt = projection.get("plan_receipt")
            execution_contract = projection.get("execution_contract")
            if type(plan_receipt) is not dict or type(execution_contract) is not dict:
                raise TypeError("The sealed profile plan has no exact execution contract.")
            execution_identity = plan_receipt.get("profile_execution_identity")
            if (
                type(execution_identity) is not dict
                or execution_identity.get("profile_execution_identity_sha256")
                != input_binding_state.profile_execution_identity_sha256
            ):
                raise TypeError("The generated input has another profile execution identity.")
            timeout_seconds = execution_contract.get("timeout_seconds")
            if type(timeout_seconds) not in {int, float}:
                raise TypeError("The profile execution timeout is invalid.")
            worker_config = input_binding_state.run_config.consume_worker_config(
                lambda handle: WorkerConfig.from_yaml_bytes(handle.read())
            )
            description = WorkerInvoker(
                worker_config.worker,
                timeout_seconds=cast(float, timeout_seconds),
                expected_identity=worker_config.expected_identity,
            ).describe_authenticated()
            from .planning import issue_planning_authority, issue_public_intent_manifest

            public_intent = issue_public_intent_manifest(
                input_binding_state.run_config,
                (description,),
            )
            planning_authority = issue_planning_authority(
                input_binding_state.run_config,
                input_binding_state.prepared_dataset,
                (description,),
                public_intent_manifest=public_intent,
                profile_id="quick",
            )
            planning_state = planning_authority._state()
            profile_chain_seeds = _derive_profile_chain_seeds(input_binding_state)
            context = _ProfilePreparationContext(
                run_config=input_binding_state.run_config,
                prepared_dataset=input_binding_state.prepared_dataset,
                publication=publication,
                publication_token=publication.token,
                profile_execution_identity_sha256=(
                    input_binding_state.profile_execution_identity_sha256
                ),
                ordered_analysis_spec_bytes=input_binding_state.ordered_analysis_spec_bytes,
                ordered_analysis_spec_ids=input_binding_state.ordered_analysis_spec_ids,
                profile_chain_seeds=profile_chain_seeds,
            )
            pending = _build_preparation_transaction(
                planning_authority,
                captured_state=planning_state,
                profile_context=context,
            )
            if pending.unprepared_states or len(pending.prepared_states) != 3:
                raise TypeError("Profile preparation did not produce exactly three candidates.")
            candidates_by_id: dict[
                str,
                tuple[PreparedExecutionAuthorization, _PreparedExecutionAuthorizationState],
            ] = {}
            for candidate, candidate_state in pending.prepared_states:
                candidate_id = cast(
                    str,
                    _closed_object(candidate_state.record_bytes)["analysis_spec_id"],
                )
                if candidate_id in candidates_by_id:
                    raise TypeError("Profile candidate preparation produced a duplicate identity.")
                candidates_by_id[candidate_id] = (candidate, candidate_state)
            ordered_pairs = tuple(
                candidates_by_id[candidate_id]
                for candidate_id in input_binding_state.ordered_analysis_spec_ids
            )
            if len(ordered_pairs) != 3:
                raise TypeError("Profile candidate preparation has incomplete budget coverage.")
            candidate_authorizations = cast(
                tuple[
                    PreparedExecutionAuthorization,
                    PreparedExecutionAuthorization,
                    PreparedExecutionAuthorization,
                ],
                tuple(pair[0] for pair in ordered_pairs),
            )
            candidate_states = cast(
                tuple[
                    _PreparedExecutionAuthorizationState,
                    _PreparedExecutionAuthorizationState,
                    _PreparedExecutionAuthorizationState,
                ],
                tuple(pair[1] for pair in ordered_pairs),
            )
            group = object.__new__(ProfilePreparedCandidateGroup)
            group_state = _ProfilePreparedCandidateGroupState(
                plan_owner=plan_owner,
                input_binding=input_binding,
                input_binding_state=input_binding_state,
                planning_authority=planning_authority,
                planning_authority_state=planning_state,
                publication=publication,
                publication_token=publication.token,
                profile_execution_identity_sha256=(
                    input_binding_state.profile_execution_identity_sha256
                ),
                coordinate_ordinal=input_binding_state.coordinate_ordinal,
                ordered_analysis_spec_ids=input_binding_state.ordered_analysis_spec_ids,
                profile_chain_seeds=profile_chain_seeds,
                transaction=pending.transaction,
                transaction_state=pending.state,
                candidate_authorizations=candidate_authorizations,
                candidate_states=candidate_states,
            )
            group_reference = ref(group)
            publication.status = "ACTIVATING"
            publication.group_ref = group_reference
            _PROFILE_PREPARED_CANDIDATE_GROUP_STATE_ISSUER.bind_once(group, group_state)
            _activate_preparation_transaction(
                pending,
                planning_authority,
                captured_state=planning_state,
                publish_to_planning_authority=False,
            )
            _PROFILE_PREPARED_CANDIDATE_GROUP_STATES.require(group, group_state)
            _PREPARATION_TRANSACTION_STATES.require(pending.transaction, pending.state)
            for candidate, candidate_state in pending.prepared_states:
                _PREPARED_AUTHORIZATION_STATES.require(candidate, candidate_state)
            if planning_state.preparation_publication is None or (
                planning_state.preparation_publication.transaction is not None
            ):
                raise TypeError("Profile preparation entered ordinary publication.")
            _validate_profile_prepared_candidate_group_state(
                group,
                group_state,
                publication_status="ACTIVATING",
            )
            publication.group_ref = group_reference
            publication.status = "PUBLISHED"
        except BaseException:
            publication.group_ref = None
            publication.status = "FRESH"
            raise

        return group


def _build_preparation_transaction(
    authority: PlanningAuthority,
    *,
    captured_state: _PlanningAuthorityState | None = None,
    profile_context: _ProfilePreparationContext | None = None,
    conformance_demo_provenance: _ConformanceDemoProvenance | None = None,
) -> _PendingPreparationTransaction:
    """Build and validate one complete transaction without activating capabilities."""

    if type(authority) is not PlanningAuthority:
        raise UniverseIdentityError("A genuine planning authority is required.")
    try:
        state = authority._state() if captured_state is None else captured_state
        if type(state) is not _PlanningAuthorityState:
            raise TypeError("A genuine planning-authority state is required.")
        from ebm_audit.profile_input_identity import (
            _is_profile_generated_prepared_dataset,
            _is_profile_owned_preparation_route,
        )

        owns_profile_route = _is_profile_owned_preparation_route(state.run_config)
        owns_profile_dataset = _is_profile_generated_prepared_dataset(state.prepared_dataset)
        public_synthetic_origin = _resolve_public_synthetic_execution_origin(
            cast("RunEligibleAuditConfig", state.run_config),
            state.prepared_dataset,
        )
        if profile_context is None:
            if public_synthetic_origin.route == "ORDINARY" and (
                owns_profile_route or owns_profile_dataset
            ):
                raise UniverseIdentityError(
                    "Profile-generated prepared datasets cannot enter ordinary preparation."
                )
        elif not owns_profile_route or not owns_profile_dataset:
            raise UniverseIdentityError(
                "Profile preparation requires its exact generated-input owners."
            )
        state.run_config.assert_ready()
        plan = _rebuild_plan_from_state(state)
        _scan_private_tokens(plan, state)
    except TypeError:
        raise UniverseIdentityError("A genuine planning authority is required.") from None
    if plan["budget_decision"]["decision"] != "WITHIN_BUDGET":
        raise UniverseIdentityError("A budget-exceeded Plan/3 cannot enter preparation.")
    if conformance_demo_provenance is not None and (
        profile_context is not None or len(plan["candidates"]) != 1
    ):
        raise UniverseIdentityError("Conformance demo provenance requires one ordinary candidate.")
    publication = state.preparation_publication
    publication_token = state.preparation_publication_token
    if publication is None or publication_token is None:
        raise UniverseIdentityError("Planning authority lacks preparation publication state.")
    config = _closed_object(state.private_config_bytes)
    master_seed = cast(str, config["randomness"]["master_seed"])
    if profile_context is None:
        _verify_plan_seed_collisions(plan, master_seed)
    else:
        _validate_profile_preparation_context(profile_context, state, plan)
    records: list[dict[str, Any]] = []
    pending: list[_PendingPreparedCandidate] = []
    unprepared_inputs: dict[int, _UnpreparedScientificInput] = {}
    for candidate in cast(Sequence[Mapping[str, Any]], plan["candidates"]):
        execution_origin = (
            public_synthetic_origin
            if profile_context is None
            else _profile_execution_origin(profile_context, candidate)
        )
        record, prepared_candidate, unprepared_input = _prepare_candidate(
            state,
            plan,
            candidate,
            master_seed,
            execution_origin,
            conformance_demo_provenance,
        )
        records.append(record)
        if prepared_candidate is not None:
            pending.append(prepared_candidate)
        else:
            requires_input = _unprepared_requires_input_digest(record)
            if requires_input != (unprepared_input is not None):
                raise UniverseIdentityError(
                    "Unprepared canonical scientific-data coverage is inconsistent."
                )
            if unprepared_input is not None:
                ordinal = cast(int, record["candidate_ordinal"])
                if ordinal in unprepared_inputs:
                    raise UniverseIdentityError(
                        "Unprepared canonical scientific-data ownership is duplicated."
                    )
                unprepared_inputs[ordinal] = unprepared_input
    if profile_context is not None and (len(pending) != 3 or unprepared_inputs):
        raise UniverseIdentityError("All three profile candidates must prepare successfully.")
    prepared_count = len(pending)
    actual_fit_count = sum(
        len(cast(Mapping[str, Any], row["universe_spec"])["chain_plan"])
        for row in records
        if row["state"] == "PREPARED"
    )
    ceiling = cast(int, plan["counts"]["planned_fit_ceiling"])
    receipt_preimage = {
        "receipt_schema_version": "ebm-audit-preparation-receipt/2.0",
        "plan_schema_version": "ebm-audit-analysis-plan/3.0",
        "plan_digest": plan["plan_digest"],
        "preparation_rule_registry_digest": _PREPARATION_RULE_REGISTRY_DIGEST,
        "prepared_candidate_count": prepared_count,
        "unprepared_candidate_count": len(records) - prepared_count,
        "actual_fit_count": actual_fit_count,
        "unprepared_fit_count": ceiling - actual_fit_count,
        "planned_fit_ceiling": ceiling,
        "records": records,
    }
    receipt = {
        **receipt_preimage,
        "receipt_digest": preparation_receipt_digest(receipt_preimage),
    }
    _verify_receipt(receipt, plan, master_seed)
    pending_by_ordinal = {cast(int, row.record["candidate_ordinal"]): row for row in pending}
    if len(pending_by_ordinal) != len(pending):
        raise UniverseIdentityError("Prepared candidate capability ownership is duplicated.")
    prepared_state = _resolve_private_prepared_dataset(state.prepared_dataset)
    candidate_authorizations: list[CandidateResultAuthorization] = []
    candidate_authorization_states: list[_CandidateAuthorizationState] = []
    prepared_authorizations: list[PreparedExecutionAuthorization] = []
    unprepared_authorizations: list[UnpreparedResultAuthorization] = []
    prepared_authorization_states: list[
        tuple[PreparedExecutionAuthorization, _PreparedExecutionAuthorizationState]
    ] = []
    unprepared_authorization_states: list[
        tuple[UnpreparedResultAuthorization, _UnpreparedResultAuthorizationState]
    ] = []
    for record in records:
        ordinal = cast(int, record["candidate_ordinal"])
        if record["state"] == "PREPARED":
            pending_candidate = pending_by_ordinal.get(ordinal)
            if pending_candidate is None:
                raise UniverseIdentityError(
                    "A PREPARED record lacks its exact private candidate owner."
                )
            prepared_capability, prepared_capability_state = _build_prepared_authorization(
                plan, receipt, pending_candidate, master_seed
            )
            capability: CandidateResultAuthorization = prepared_capability
            capability_state: _CandidateAuthorizationState = prepared_capability_state
            prepared_authorizations.append(prepared_capability)
            prepared_authorization_states.append((prepared_capability, prepared_capability_state))
        else:
            unprepared_input = unprepared_inputs.get(ordinal)
            (
                unprepared_capability,
                unprepared_capability_state,
            ) = _build_unprepared_result_authorization(
                plan=plan,
                receipt=receipt,
                record=record,
                master_seed=master_seed,
                planning_summary_binding=state.planning_summary.binding,
                dataset_summary=prepared_state.summary.preimage,
                config_digest=state.run_config.resolved_public_digest,
                scientific_data_preimage_bytes=(
                    None if unprepared_input is None else unprepared_input.preimage_bytes
                ),
                input_digest=None if unprepared_input is None else unprepared_input.digest,
                source_byte_digest=prepared_state.source_admission.byte_digest,
                prepared_dataset_id=prepared_state.prepared_dataset_id,
                prepared_dataset=state.prepared_dataset,
                preparation_namespace_key=state.preparation_namespace_key,
            )
            capability = unprepared_capability
            capability_state = unprepared_capability_state
            unprepared_authorizations.append(unprepared_capability)
            unprepared_authorization_states.append(
                (unprepared_capability, unprepared_capability_state)
            )
        candidate_authorizations.append(capability)
        candidate_authorization_states.append(capability_state)
    authorizations = tuple(prepared_authorizations)
    provisional_states: dict[object, _CandidateAuthorizationState] = {}
    for prepared_capability, prepared_capability_state in prepared_authorization_states:
        provisional_states[prepared_capability] = prepared_capability_state
    for unprepared_capability, unprepared_capability_state in unprepared_authorization_states:
        provisional_states[unprepared_capability] = unprepared_capability_state

    def resolve_provisional(
        authorization: CandidateResultAuthorization,
    ) -> _CandidateAuthorizationState:
        try:
            authorization_state = provisional_states[authorization]
        except KeyError:
            raise TypeError(
                "Preparation transaction lacks a provisional candidate state."
            ) from None
        if type(authorization_state) is _PreparedExecutionAuthorizationState:
            _revalidate_prepared_authorization_state(
                authorization_state,
                provisional_profile_owner=(
                    authorization_state.execution_origin.owner
                    if authorization_state.execution_origin.route == "PROFILE"
                    else None
                ),
            )
        elif type(authorization_state) is _UnpreparedResultAuthorizationState:
            _revalidate_unprepared_result_authorization_state(authorization_state)
        else:
            raise TypeError("A provisional candidate state is invalid.")
        return authorization_state

    ordered_candidate_states = tuple(
        resolve_provisional(authorization) for authorization in candidate_authorizations
    )
    influence_binding_bytes = _derive_influence_preparation_binding_bytes(
        plan,
        ordered_candidate_states,
    )
    stage_binding_bytes = _derive_stage_preparation_binding_bytes(
        plan,
        ordered_candidate_states,
    )
    influence_input_receipt = _issue_influence_preparation_input_receipt(
        plan_bytes=canonical_json_bytes(plan),
        preparation_receipt_bytes=canonical_json_bytes(receipt),
        binding_bytes=influence_binding_bytes,
        stage_binding_bytes=stage_binding_bytes,
    )
    transaction = object.__new__(PreparationTransaction)
    transaction_state = _PreparationTransactionState(
        plan_bytes=canonical_json_bytes(plan),
        receipt_bytes=canonical_json_bytes(receipt),
        influence_input_receipt=influence_input_receipt,
        master_seed=master_seed,
        publication_token=publication_token,
        authorizations=authorizations,
        unprepared_authorizations=tuple(unprepared_authorizations),
        candidate_authorizations=tuple(candidate_authorizations),
    )
    _validate_preparation_transaction_state(
        transaction_state,
        resolve_provisional,
    )
    attempt = object.__new__(_PreparationAttempt)
    _PREPARATION_ATTEMPT_STATES[attempt] = "FRESH"
    return _PendingPreparationTransaction(
        attempt=attempt,
        transaction=transaction,
        state=transaction_state,
        prepared_states=tuple(prepared_authorization_states),
        unprepared_states=tuple(unprepared_authorization_states),
        candidate_provenance_issuances=tuple(
            row.candidate_provenance_issuance
            for row in pending
            if row.candidate_provenance_issuance is not None
        ),
    )


def _publish_preparation_transaction(
    publication: _PreparationPublication,
    transaction: PreparationTransaction,
) -> PreparationTransaction:
    """Perform the sole final, non-raising parent publication step."""

    publication.transaction = transaction
    return transaction


def _activate_preparation_transaction(
    pending: _PendingPreparationTransaction,
    authority: PlanningAuthority,
    *,
    captured_state: _PlanningAuthorityState | None = None,
    publish_to_planning_authority: bool = True,
) -> PreparationTransaction:
    """Bind a complete private graph, then publish its one reachable parent."""

    if type(authority) is not PlanningAuthority:
        raise UniverseIdentityError("A genuine planning authority is required.")
    try:
        authority_state = authority._state() if captured_state is None else captured_state
        if type(authority_state) is not _PlanningAuthorityState:
            raise TypeError("A genuine planning-authority state is required.")
    except TypeError:
        raise UniverseIdentityError("A genuine planning authority is required.") from None
    publication = authority_state.preparation_publication
    publication_token = authority_state.preparation_publication_token

    def assert_current_authority_state() -> None:
        try:
            current_state = authority._state()
        except TypeError:
            raise UniverseIdentityError(
                "Planning authority changed during preparation activation."
            ) from None
        if (
            current_state is not authority_state
            or current_state.preparation_publication is not publication
            or current_state.preparation_publication_token is not publication_token
        ):
            raise UniverseIdentityError("Planning authority changed during preparation activation.")
        try:
            _assert_planning_description_states_current(authority_state)
        except TypeError:
            raise UniverseIdentityError(
                "Planning authority Describe state changed during preparation activation."
            ) from None

    if (
        type(pending) is not _PendingPreparationTransaction
        or publication is None
        or publication_token is None
        or pending.state.publication_token is not publication_token
        or publication.transaction is not None
    ):
        raise UniverseIdentityError("Preparation publication ownership is invalid.")
    try:
        attempt_state = _PREPARATION_ATTEMPT_STATES[pending.attempt]
    except (KeyError, TypeError):
        raise UniverseIdentityError("Preparation activation attempt is invalid.") from None
    if attempt_state != "FRESH":
        raise UniverseIdentityError("Preparation activation attempt was already consumed.")
    assert_current_authority_state()
    _PREPARATION_ATTEMPT_STATES[pending.attempt] = "ACTIVATING"
    transaction = pending.transaction
    try:
        if transaction in _PREPARATION_TRANSACTION_STATES:
            raise UniverseIdentityError("Preparation transaction was already activated.")
        if any(
            capability in _PREPARED_AUTHORIZATION_STATES
            for capability, _state in pending.prepared_states
        ) or any(
            capability in _UNPREPARED_RESULT_AUTHORIZATION_STATES
            for capability, _state in pending.unprepared_states
        ):
            raise UniverseIdentityError("A candidate capability was already activated.")
        for prepared_capability, prepared_capability_state in pending.prepared_states:
            _PREPARED_AUTHORIZATION_STATE_ISSUER.bind_once(
                prepared_capability,
                prepared_capability_state,
            )
        for unprepared_capability, unprepared_capability_state in pending.unprepared_states:
            _UNPREPARED_RESULT_AUTHORIZATION_STATE_ISSUER.bind_once(
                unprepared_capability,
                unprepared_capability_state,
            )
        _PREPARATION_TRANSACTION_STATE_ISSUER.bind_once(transaction, pending.state)
        if publish_to_planning_authority:
            transaction._state()
        else:
            _PREPARATION_TRANSACTION_STATES.require(transaction, pending.state)
        if publication.transaction is not None:
            raise UniverseIdentityError("Preparation publication changed during activation.")
        assert_current_authority_state()
        if pending.candidate_provenance_issuances:
            from ebm_audit.synthetic.audit_input import (
                _commit_public_synthetic_candidate_provenances,
            )

            _commit_public_synthetic_candidate_provenances(
                pending.candidate_provenance_issuances
            )
        _PREPARATION_ATTEMPT_STATES[pending.attempt] = "PUBLISHED"
        if publish_to_planning_authority:
            return _publish_preparation_transaction(publication, transaction)
        return transaction
    except BaseException:
        if publication.transaction is not transaction:
            _PREPARATION_ATTEMPT_STATES[pending.attempt] = "FAILED"
        raise


def _prepare_analysis_plan(
    authority: PlanningAuthority,
    *,
    conformance_demo_provenance: _ConformanceDemoProvenance | None = None,
) -> PreparationTransaction:
    """Publish exactly one fully validated successful transaction per authority."""

    if type(authority) is not PlanningAuthority:
        raise UniverseIdentityError("A genuine planning authority is required.")
    try:
        authority_state = authority._state()
    except TypeError:
        raise UniverseIdentityError("A genuine planning authority is required.") from None
    publication = authority_state.preparation_publication
    publication_token = authority_state.preparation_publication_token
    if publication is None or publication_token is None:
        raise UniverseIdentityError("Planning authority lacks preparation publication state.")
    with publication.lock:

        def assert_current_authority_state() -> None:
            try:
                current_state = authority._state()
            except TypeError:
                raise UniverseIdentityError(
                    "Planning authority changed during preparation."
                ) from None
            if (
                current_state is not authority_state
                or current_state.preparation_publication is not publication
                or current_state.preparation_publication_token is not publication_token
            ):
                raise UniverseIdentityError("Planning authority changed during preparation.")
            try:
                _assert_planning_description_states_current(authority_state)
            except TypeError:
                raise UniverseIdentityError(
                    "Planning authority Describe state changed during preparation."
                ) from None

        existing = publication.transaction
        if existing is not None:
            if type(existing) is not PreparationTransaction:
                raise UniverseIdentityError("Preparation publication state is invalid.")
            existing_state = existing._state()
            if existing_state.publication_token is not publication_token:
                raise UniverseIdentityError(
                    "Preparation transaction belongs to another planning authority."
                )
            assert_current_authority_state()
            return existing
        pending = _build_preparation_transaction(
            authority,
            captured_state=authority_state,
            conformance_demo_provenance=conformance_demo_provenance,
        )
        assert_current_authority_state()
        return _activate_preparation_transaction(
            pending,
            authority,
            captured_state=authority_state,
        )


__all__ = [
    "PreparationTransaction",
    "PreparedExecutionAuthorization",
    "ProfilePreparedCandidateGroup",
    "UnpreparedResultAuthorization",
    "prepare_profile_candidate_group",
]
