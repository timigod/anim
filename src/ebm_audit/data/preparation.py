"""Lossless pre-plan preparation of one verified exact-file audit dataset.

Preparation validates the complete physical-column and role catalog while
retaining every admitted row and cell.  It deliberately performs no cohort
selection, missingness handling, preprocessing, identity-token generation, or
model work.  Private names and parsed values remain in an identity-keyed
registry; the public capability exposes aggregate counts and content digests.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NamedTuple, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.config.models import ConfigContractError
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256
from ebm_audit.schema import SchemaValidationError, validate_instance

from .identity import ParticipantIdentityError, validate_participant_private_id
from .source_admission import ValidatedSourceAdmission, _private_source_table

if TYPE_CHECKING:
    from ebm_audit.config.verification import (
        PlanEligibleAuditConfig,
        RunEligibleAuditConfig,
    )

_LOSSLESS_TABLE_DOMAIN = "ebm-audit/lossless-audit-table/1"
_AUDIT_DATASET_DOMAIN = "ebm-audit/audit-dataset/1"
_SUMMARY_DOMAIN = "ebm-audit/validated-dataset-summary/1"
_PREPARED_DOMAIN = "ebm-audit/prepared-audit-dataset/1"
_SAFE_FAILURE = "Audit dataset preparation failed."
_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))


class _PreparationRejected(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__()


@dataclass(frozen=True, slots=True)
class _PreparationFailure:
    code: str


@dataclass(frozen=True, slots=True)
class _PreparationControlFlow:
    kind: str
    exit_code: int | None = None


class _ValidatedSummaryState(NamedTuple):
    record_bytes: bytes


class _PreparedPrivateState(NamedTuple):
    prepared_dataset_id: str
    authorization_id: str
    source_admission_id: str
    audit_dataset_digest: str
    summary_digest: str
    summary: ValidatedDatasetSummary
    source_admission: ValidatedSourceAdmission
    catalog: Mapping[str, object]
    private_table: Mapping[str, tuple[object, ...]]


def _reject(code: str) -> _PreparationRejected:
    return _PreparationRejected(code)


def _build_summary_registry() -> tuple[
    Callable[[type[object]], None],
    Callable[[object, _ValidatedSummaryState], None],
    Callable[[object], _ValidatedSummaryState],
]:
    registry: OneShotWeakRegistry[object, _ValidatedSummaryState]
    issuer: OneShotRegistryIssuer[object, _ValidatedSummaryState]
    registry, issuer = create_one_shot_registry()
    summary_type: type[object] | None = None

    def bind_type(capability_type: type[object]) -> None:
        nonlocal summary_type
        if summary_type is not None or type(capability_type) is not type:
            raise RuntimeError("Validated dataset summary authority is unavailable.")
        summary_type = capability_type

    def register(capability: object, state: _ValidatedSummaryState) -> None:
        if (
            summary_type is None
            or type(capability) is not summary_type
            or type(state) is not _ValidatedSummaryState
            or type(state.record_bytes) is not bytes
        ):
            raise RuntimeError("Validated dataset summary authority is unavailable.")
        issuer.bind_once(capability, state)

    def read(capability: object) -> _ValidatedSummaryState:
        state: _ValidatedSummaryState | None = None
        if summary_type is not None and type(capability) is summary_type:
            try:
                state = registry.get(capability)
            except BaseException:
                state = None
        if type(state) is not _ValidatedSummaryState:
            raise TypeError("A genuine validated dataset summary is required.")
        return state

    return bind_type, register, read


(
    _bind_summary_type,
    _register_summary_state,
    _read_summary_state,
) = _build_summary_registry()


@final
class ValidatedDatasetSummary:
    """Validated, persistable public aggregate with no private source fields."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ValidatedDatasetSummary:
        raise TypeError("Validated dataset summaries come from dataset preparation.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Validated dataset summaries cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Validated dataset summaries are immutable.")

    @property
    def record(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> dict[str, object]:
        value = strict_json_loads(_read(self).record_bytes)
        if type(value) is not dict:
            raise TypeError("Validated dataset summary storage is invalid.")
        return cast(dict[str, object], value)

    @property
    def preimage(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> dict[str, object]:
        record = strict_json_loads(_read(self).record_bytes)
        if type(record) is not dict:
            raise TypeError("Validated dataset summary storage is invalid.")
        value = record.get("summary")
        if type(value) is not dict:
            raise TypeError("Validated dataset summary storage is invalid.")
        return cast(dict[str, object], value)

    @property
    def summary_digest(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str:
        record = strict_json_loads(_read(self).record_bytes)
        if type(record) is not dict:
            raise TypeError("Validated dataset summary storage is invalid.")
        value = record.get("summary_digest")
        if type(value) is not str:
            raise TypeError("Validated dataset summary storage is invalid.")
        return value

    @property
    def resolved_config_digest(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str:
        _read(self)
        return cast(str, self.preimage["resolved_config_digest"])

    @property
    def input_byte_digest(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str:
        _read(self)
        return cast(str, self.preimage["input_byte_digest"])

    @property
    def input_format_digest(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str:
        _read(self)
        return cast(str, self.preimage["input_format_digest"])

    @property
    def column_roles_digest(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str:
        _read(self)
        return cast(str, self.preimage["column_roles_digest"])

    @property
    def canonical_dataset_digest(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str:
        _read(self)
        return cast(str, self.preimage["canonical_dataset_digest"])

    @property
    def row_count(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> int:
        _read(self)
        return cast(int, self.preimage["row_count"])

    @property
    def participant_count(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> int:
        _read(self)
        return cast(int, self.preimage["participant_count"])

    @property
    def event_count(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> int:
        _read(self)
        return cast(int, self.preimage["event_count"])

    @property
    def group_spec_count(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> int:
        _read(self)
        return cast(int, self.preimage["group_spec_count"])

    @property
    def covariate_count(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> int:
        _read(self)
        return cast(int, self.preimage["covariate_count"])

    @property
    def metadata_count(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> int:
        _read(self)
        return cast(int, self.preimage["metadata_count"])

    @property
    def dropped_row_count(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> int:
        _read(self)
        return cast(int, self.preimage["dropped_row_count"])

    def __copy__(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> ValidatedDatasetSummary:
        _read(self)
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
        _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state,
    ) -> ValidatedDatasetSummary:
        _read(self)
        memo[id(self)] = self
        return self

    def __reduce__(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str | tuple[object, ...]:
        _read(self)
        raise TypeError("Validated dataset summaries use their validated record form.")

    def __reduce_ex__(
        self,
        _protocol: SupportsIndex,
        _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state,
    ) -> str | tuple[object, ...]:
        _read(self)
        raise TypeError("Validated dataset summaries use their validated record form.")

    def __getstate__(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> object:
        _read(self)
        raise TypeError("Validated dataset summaries use their validated record form.")

    def __repr__(
        self, _read: Callable[[object], _ValidatedSummaryState] = _read_summary_state
    ) -> str:
        _read(self)
        return (
            "ValidatedDatasetSummary("
            f"rows={self.row_count}, events={self.event_count}, "
            f"groups={self.group_spec_count}, dropped_rows={self.dropped_row_count})"
        )


_bind_summary_type(ValidatedDatasetSummary)


def _build_summary_issuer(
    register: Callable[[object, _ValidatedSummaryState], None],
) -> Callable[[dict[str, object]], ValidatedDatasetSummary]:
    def issue(preimage: dict[str, object]) -> ValidatedDatasetSummary:
        if type(preimage) is not dict:
            raise TypeError("Validated dataset summary authority is unavailable.")
        validated_preimage = copy.deepcopy(preimage)
        validate_instance(
            validated_preimage,
            "audit-config.schema.json",
            definition="ValidatedDatasetSummaryPreimage",
        )
        summary_digest = structured_sha256(_SUMMARY_DOMAIN, validated_preimage)
        record: dict[str, object] = {
            "summary": validated_preimage,
            "summary_digest": summary_digest,
        }
        validate_instance(
            record,
            "audit-config.schema.json",
            definition="ValidatedDatasetSummary",
        )
        record_bytes = canonical_json_bytes(record)

        reloaded = strict_json_loads(record_bytes)
        if type(reloaded) is not dict:
            raise TypeError("Validated dataset summary authority is unavailable.")
        validate_instance(
            reloaded,
            "audit-config.schema.json",
            definition="ValidatedDatasetSummary",
        )
        reloaded_preimage = reloaded.get("summary")
        if type(reloaded_preimage) is not dict or reloaded.get("summary_digest") != (
            structured_sha256(_SUMMARY_DOMAIN, reloaded_preimage)
        ):
            raise TypeError("Validated dataset summary authority is unavailable.")

        capability = object.__new__(ValidatedDatasetSummary)
        register(capability, _ValidatedSummaryState(record_bytes))
        return capability

    return issue


_issue_summary = _build_summary_issuer(_register_summary_state)


def _build_prepared_registry() -> tuple[
    Callable[[type[object]], None],
    Callable[[object, _PreparedPrivateState], None],
    Callable[[object], _PreparedPrivateState],
]:
    registry: OneShotWeakRegistry[object, _PreparedPrivateState]
    issuer: OneShotRegistryIssuer[object, _PreparedPrivateState]
    registry, issuer = create_one_shot_registry()
    prepared_type: type[object] | None = None

    def bind_type(capability_type: type[object]) -> None:
        nonlocal prepared_type
        if prepared_type is not None or type(capability_type) is not type:
            raise RuntimeError("Prepared dataset authority is unavailable.")
        prepared_type = capability_type

    def register(capability: object, state: _PreparedPrivateState) -> None:
        if (
            prepared_type is None
            or type(capability) is not prepared_type
            or type(state) is not _PreparedPrivateState
        ):
            raise RuntimeError("Prepared dataset authority is unavailable.")
        issuer.bind_once(capability, state)

    def read(capability: object) -> _PreparedPrivateState:
        state: _PreparedPrivateState | None = None
        if prepared_type is not None and type(capability) is prepared_type:
            try:
                state = registry.get(capability)
            except BaseException:
                state = None
        if type(state) is not _PreparedPrivateState:
            raise TypeError("A genuine prepared audit dataset capability is required.")
        return state

    return bind_type, register, read


(
    _bind_prepared_type,
    _register_prepared_state,
    _read_prepared_state,
) = _build_prepared_registry()


@final
class PreparedAuditDataset:
    """Sealed authority over one lossless private pre-plan dataset."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PreparedAuditDataset:
        raise TypeError("Prepared audit datasets come from verified configuration.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Prepared audit datasets cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Prepared audit datasets are immutable.")

    @property
    def prepared_dataset_id(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> str:
        return _read(self).prepared_dataset_id

    @property
    def authorization_id(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> str:
        return _read(self).authorization_id

    @property
    def source_admission_id(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> str:
        return _read(self).source_admission_id

    @property
    def audit_dataset_digest(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> str:
        return _read(self).audit_dataset_digest

    @property
    def summary_digest(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> str:
        return _read(self).summary_digest

    @property
    def summary(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> ValidatedDatasetSummary:
        return _read(self).summary

    def __copy__(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> PreparedAuditDataset:
        _read(self)
        return self

    def __deepcopy__(
        self,
        memo: dict[int, object],
        _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state,
    ) -> PreparedAuditDataset:
        _read(self)
        memo[id(self)] = self
        return self

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Prepared audit datasets cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Prepared audit datasets cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Prepared audit datasets cannot be serialized.")

    def __repr__(
        self, _read: Callable[[object], _PreparedPrivateState] = _read_prepared_state
    ) -> str:
        _read(self)
        return "PreparedAuditDataset(<sealed-private-dataset>)"


_bind_prepared_type(PreparedAuditDataset)
_private_prepared_dataset = _read_prepared_state


def _build_prepared_issuer(
    register: Callable[[object, _PreparedPrivateState], None],
    read_summary: Callable[[object], _ValidatedSummaryState],
) -> Callable[[_PreparedPrivateState], PreparedAuditDataset]:
    def deeply_frozen(value: object) -> bool:
        if type(value) is _MAPPING_PROXY_TYPE:
            mapping = cast(Mapping[object, object], value)
            return all(type(key) is str and deeply_frozen(child) for key, child in mapping.items())
        if type(value) is tuple:
            return all(deeply_frozen(child) for child in cast(tuple[object, ...], value))
        return type(value) in {str, int, float, bool, type(None)}

    def issue(state: _PreparedPrivateState) -> PreparedAuditDataset:
        summary_state: _ValidatedSummaryState | None = None
        if type(state) is _PreparedPrivateState:
            try:
                summary_state = read_summary(state.summary)
            except TypeError:
                summary_state = None
        if (
            type(state) is not _PreparedPrivateState
            or type(state.summary) is not ValidatedDatasetSummary
            or type(summary_state) is not _ValidatedSummaryState
            or state.summary.summary_digest != state.summary_digest
            or type(state.source_admission) is not ValidatedSourceAdmission
            or type(state.catalog) is not _MAPPING_PROXY_TYPE
            or not deeply_frozen(state.catalog)
            or type(state.private_table) is not _MAPPING_PROXY_TYPE
            or any(type(row) is not tuple for row in state.private_table.values())
            or any(
                type(value) not in {str, int, float, bool}
                for row in state.private_table.values()
                for value in row
            )
        ):
            raise TypeError("Prepared dataset authority is unavailable.")
        capability = object.__new__(PreparedAuditDataset)
        register(capability, state)
        return capability

    return issue


_issue_prepared = _build_prepared_issuer(_register_prepared_state, _read_summary_state)
del _bind_prepared_type
del _read_prepared_state
del _register_prepared_state
del _build_prepared_registry
del _build_prepared_issuer


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise _reject("DATA.PREPARATION_CATALOG_INVALID")
    return cast(Mapping[str, object], value)


def _records(value: object) -> tuple[Mapping[str, object], ...]:
    if type(value) is not list:
        raise _reject("DATA.PREPARATION_CATALOG_INVALID")
    return tuple(_mapping(item) for item in cast(list[object], value))


def _strings(value: object) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in cast(list[object], value)):
        raise _reject("DATA.PREPARATION_CATALOG_INVALID")
    return tuple(cast(list[str], value))


def _deep_freeze(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType(
            {str(key): _deep_freeze(child) for key, child in cast(dict[str, object], value).items()}
        )
    if type(value) is list:
        return tuple(_deep_freeze(child) for child in cast(list[object], value))
    if type(value) is tuple:
        return tuple(_deep_freeze(child) for child in cast(tuple[object, ...], value))
    return value


def _group_source_columns(group: Mapping[str, object]) -> tuple[str, ...]:
    source = _mapping(group.get("source_column_or_rule"))
    if group.get("source") == "column":
        column = source.get("source_column")
        if type(column) is not str:
            raise _reject("DATA.PREPARATION_CATALOG_INVALID")
        return (column,)
    return _strings(source.get("source_columns"))


def _role_catalog(
    private_config: Mapping[str, Any],
) -> tuple[tuple[dict[str, object], ...], Mapping[str, object]]:
    source = _mapping(private_config.get("input"))
    csv_format = _mapping(source.get("format"))
    raw_columns = _records(csv_format.get("columns"))
    roles = _mapping(private_config.get("column_roles"))
    events = _records(roles.get("events"))
    groups = _records(roles.get("groups"))
    covariates = _records(roles.get("covariates"))
    metadata = _records(roles.get("metadata"))
    ignored = _records(roles.get("ignored_columns"))

    role_by_column: dict[str, str] = {}

    def assign(column: object, role: str, *, repeat_same: bool = False) -> None:
        if type(column) is not str:
            raise _reject("DATA.PREPARATION_CATALOG_INVALID")
        prior = role_by_column.get(column)
        if prior is not None and not (repeat_same and prior == role):
            raise _reject("DATA.PREPARATION_ROLE_CLOSURE")
        role_by_column[column] = role

    assign(roles.get("participant_id_column"), "participant-private-id")
    for event in events:
        assign(event.get("source_column"), "event")
    for group in groups:
        for column in _group_source_columns(group):
            assign(column, "group", repeat_same=True)
    for covariate in covariates:
        assign(covariate.get("source_column"), "covariate")
    for item in metadata:
        assign(item.get("source_column"), "metadata")
    for item in ignored:
        assign(item.get("source_column"), "ignored")

    physical: list[dict[str, object]] = []
    physical_names: list[str] = []
    for index, physical_column in enumerate(raw_columns):
        name = physical_column.get("source_column")
        physical_type = physical_column.get("physical_type")
        if type(name) is not str or type(physical_type) is not str:
            raise _reject("DATA.PREPARATION_CATALOG_INVALID")
        role = role_by_column.get(name)
        if role is None:
            raise _reject("DATA.PREPARATION_ROLE_CLOSURE")
        physical_names.append(name)
        physical.append(
            {
                "column_index": index,
                "source_column": name,
                "physical_type": physical_type,
                "declared_role": role,
            }
        )
    if len(set(physical_names)) != len(physical_names) or set(physical_names) != set(
        role_by_column
    ):
        raise _reject("DATA.PREPARATION_ROLE_CLOSURE")
    return tuple(physical), roles


def _validate_private_table(
    table: Mapping[str, tuple[object, ...]],
    physical_columns: Sequence[Mapping[str, object]],
    *,
    row_count: int,
    participant_id_column: str,
) -> None:
    names = tuple(cast(str, item["source_column"]) for item in physical_columns)
    if tuple(table) != names or len(table) != len(physical_columns):
        raise _reject("DATA.PREPARATION_PHYSICAL_COLUMNS")
    if any(type(values) is not tuple or len(values) != row_count for values in table.values()):
        raise _reject("DATA.PREPARATION_SOURCE_SHAPE")
    participant_values = table.get(participant_id_column)
    if participant_values is None or len(participant_values) != row_count:
        raise _reject("DATA.PREPARATION_PARTICIPANT_IDS")
    typed: set[tuple[str, str | int]] = set()
    for value in participant_values:
        try:
            identifier = validate_participant_private_id(value)
        except ParticipantIdentityError:
            raise _reject("DATA.PREPARATION_PARTICIPANT_IDS") from None
        key = ("string" if type(identifier) is str else "integer", identifier)
        if key in typed:
            raise _reject("DATA.PREPARATION_PARTICIPANT_IDS")
        typed.add(key)


def _build_catalog_and_summary(
    config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
    _summary_issue: Callable[[dict[str, object]], ValidatedDatasetSummary] = _issue_summary,
) -> tuple[
    str,
    ValidatedDatasetSummary,
    Mapping[str, object],
    Mapping[str, tuple[object, ...]],
    ValidatedSourceAdmission,
]:
    from ebm_audit.config.verification import (
        PlanEligibleAuditConfig,
        RunEligibleAuditConfig,
        _verified_files_for_planning_config,
    )

    if type(config) not in {PlanEligibleAuditConfig, RunEligibleAuditConfig}:
        raise _reject("DATA.PREPARATION_CONFIG_CAPABILITY")
    from ebm_audit.profile_input_identity import _is_profile_owned_preparation_route

    if _is_profile_owned_preparation_route(config):
        raise _reject("DATA.PREPARATION_PROFILE_ROUTE")
    try:
        _verified_files_for_planning_config(config)
    except ConfigContractError as exc:
        if exc.code in {
            "CONFIG.PLAN_ELIGIBLE_TYPE",
            "CONFIG.PLAN_ELIGIBLE_AUTHORITY",
            "CONFIG.PLANNING_CAPABILITY",
        }:
            raise _reject("DATA.PREPARATION_CONFIG_CAPABILITY") from None
        raise
    config.assert_ready()
    source_admission = config.source_admission
    private_config = config.private_config
    source = _mapping(private_config.get("input"))
    csv_format = _mapping(source.get("format"))
    roles_value = _mapping(private_config.get("column_roles"))
    variant = _mapping(source.get("variant"))

    input_format_digest = structured_sha256("ebm-audit/input-format/1", csv_format)
    column_roles_digest = structured_sha256("ebm-audit/column-roles/1", roles_value)
    expected_byte_digest = source.get("expected_byte_digest")
    if (
        expected_byte_digest != source_admission.byte_digest
        or source_admission.byte_digest != config.source_admission.byte_digest
        or source_admission.input_format_digest != input_format_digest
        or source.get("byte_digest_method") != "sha256-exact-file-bytes/1"
        or variant.get("source_digest_method") != "exact-file/1"
        or variant.get("source_digest") != source_admission.byte_digest
    ):
        raise _reject("DATA.PREPARATION_SOURCE_BINDING")

    physical_columns, roles = _role_catalog(private_config)
    if source_admission.column_count != len(physical_columns):
        raise _reject("DATA.PREPARATION_SOURCE_SHAPE")
    private_table = _private_source_table(source_admission)
    participant_id_column = roles.get("participant_id_column")
    if type(participant_id_column) is not str:
        raise _reject("DATA.PREPARATION_CATALOG_INVALID")
    _validate_private_table(
        private_table,
        physical_columns,
        row_count=source_admission.row_count,
        participant_id_column=participant_id_column,
    )

    lossless_preimage: dict[str, object] = {
        "preimage_schema_version": "ebm-audit-lossless-audit-table/1.0",
        "source_admission_id": source_admission.admission_id,
        "exact_byte_digest": source_admission.byte_digest,
        "input_format_digest": input_format_digest,
        "column_roles_digest": column_roles_digest,
        "row_count": source_admission.row_count,
        "column_count": source_admission.column_count,
        "ordered_physical_columns": copy.deepcopy(list(physical_columns)),
    }
    validate_instance(
        lossless_preimage,
        "canonical-records.schema.json",
        definition="LosslessAuditTableDigestPreimage",
    )
    lossless_table_digest = structured_sha256(_LOSSLESS_TABLE_DOMAIN, lossless_preimage)

    events = _records(roles.get("events"))
    groups = _records(roles.get("groups"))
    covariates = _records(roles.get("covariates"))
    metadata = _records(roles.get("metadata"))
    ignored = _records(roles.get("ignored_columns"))
    catalog: dict[str, object] = {
        "catalog_schema_version": "ebm-audit-dataset-catalog/1.0",
        "variant": copy.deepcopy(dict(variant)),
        "participant_private_id_column": participant_id_column,
        "event_specs": copy.deepcopy(list(events)),
        "group_specs": copy.deepcopy(list(groups)),
        "covariate_specs": copy.deepcopy(list(covariates)),
        "metadata_specs": copy.deepcopy(list(metadata)),
        "ignored_columns": copy.deepcopy(list(ignored)),
        "physical_columns": copy.deepcopy(list(physical_columns)),
        "source_table_row_count": source_admission.row_count,
        "lossless_table_digest": lossless_table_digest,
    }
    validate_instance(
        catalog,
        "canonical-records.schema.json",
        definition="AuditDatasetCatalog",
    )
    if canonical_json_bytes(catalog["variant"]) != canonical_json_bytes(variant):
        raise _reject("DATA.PREPARATION_VARIANT_COPY")
    audit_dataset_digest = structured_sha256(_AUDIT_DATASET_DOMAIN, catalog)

    summary_preimage: dict[str, object] = {
        "summary_schema_version": "ebm-audit-validated-dataset-summary/1.0",
        "resolved_config_digest": config.resolved_public_digest,
        "input_byte_digest": source_admission.byte_digest,
        "input_format_digest": input_format_digest,
        "column_roles_digest": column_roles_digest,
        "canonical_dataset_digest": audit_dataset_digest,
        "admission_rule_id": "lossless-row-admission/1",
        "row_count": source_admission.row_count,
        "participant_count": source_admission.row_count,
        "event_count": len(events),
        "group_spec_count": len(groups),
        "covariate_count": len(covariates),
        "metadata_count": len(metadata),
        "dropped_row_count": 0,
    }
    summary = _summary_issue(summary_preimage)
    config.assert_ready()
    if config.source_admission is not source_admission:
        raise _reject("DATA.PREPARATION_SOURCE_CHANGED")
    frozen_catalog = _deep_freeze(catalog)
    if not isinstance(frozen_catalog, Mapping):
        raise _reject("DATA.PREPARATION_INTERNAL_CONTRACT")
    return (
        audit_dataset_digest,
        summary,
        cast(Mapping[str, object], frozen_catalog),
        private_table,
        source_admission,
    )


del _bind_summary_type
del _read_summary_state
del _register_summary_state
del _build_summary_registry
del _build_summary_issuer
del _issue_summary


def _prepare(
    config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
    _issue: Callable[[_PreparedPrivateState], PreparedAuditDataset] = _issue_prepared,
) -> PreparedAuditDataset:
    audit_dataset_digest, summary, catalog, private_table, source_admission = (
        _build_catalog_and_summary(config)
    )
    binding: dict[str, object] = {
        "binding_schema_version": "ebm-audit-prepared-audit-dataset-binding/1.0",
        "authorization_id": config.authorization_id,
        "source_admission_id": source_admission.admission_id,
        "audit_dataset_digest": audit_dataset_digest,
        "summary_digest": summary.summary_digest,
    }
    validate_instance(
        binding,
        "audit-config.schema.json",
        definition="PreparedAuditDatasetBindingPreimage",
    )
    prepared_dataset_id = structured_sha256(_PREPARED_DOMAIN, binding)
    state = _PreparedPrivateState(
        prepared_dataset_id=prepared_dataset_id,
        authorization_id=config.authorization_id,
        source_admission_id=source_admission.admission_id,
        audit_dataset_digest=audit_dataset_digest,
        summary_digest=summary.summary_digest,
        summary=summary,
        source_admission=source_admission,
        catalog=catalog,
        private_table=private_table,
    )
    return _issue(state)


del _issue_prepared


def _capture_preparation(
    operation: Callable[[], PreparedAuditDataset],
) -> PreparedAuditDataset | _PreparationFailure | _PreparationControlFlow:
    try:
        return operation()
    except BaseException as stopped:
        if type(stopped) is KeyboardInterrupt:
            return _PreparationControlFlow("keyboard_interrupt")
        if type(stopped) is SystemExit:
            stopped_code = stopped.code
            safe_exit_code = (
                stopped_code if stopped_code is None or type(stopped_code) is int else 1
            )
            return _PreparationControlFlow("system_exit", safe_exit_code)
        if type(stopped) is GeneratorExit:
            return _PreparationControlFlow("generator_exit")
        if type(stopped) is _PreparationRejected:
            return _PreparationFailure(stopped.code)
        if type(stopped) is ConfigContractError:
            return _PreparationFailure("DATA.PREPARATION_SOURCE_CHANGED")
        if type(stopped) is SchemaValidationError:
            return _PreparationFailure("DATA.PREPARATION_CATALOG_INVALID")
        return _PreparationFailure("DATA.PREPARATION_INTERNAL_CONTRACT")


def prepare_audit_dataset(
    config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
) -> PreparedAuditDataset:
    """Prepare the complete admitted table without making analysis choices."""

    def operation(
        candidate: PlanEligibleAuditConfig | RunEligibleAuditConfig = config,
    ) -> PreparedAuditDataset:
        return _prepare(candidate)

    outcome = _capture_preparation(operation)
    del operation
    del config
    if type(outcome) is _PreparationControlFlow:
        if outcome.kind == "keyboard_interrupt":
            raise KeyboardInterrupt
        if outcome.kind == "system_exit":
            raise SystemExit(outcome.exit_code)
        raise GeneratorExit
    if type(outcome) is _PreparationFailure:
        raise InvalidInputError(outcome.code, _SAFE_FAILURE)
    if type(outcome) is PreparedAuditDataset:
        return outcome
    raise InvalidInputError("DATA.PREPARATION_INTERNAL_CONTRACT", _SAFE_FAILURE)


__all__ = [
    "PreparedAuditDataset",
    "ValidatedDatasetSummary",
    "prepare_audit_dataset",
]
