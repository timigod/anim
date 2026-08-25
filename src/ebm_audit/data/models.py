"""Immutable types for the canonical data-ingestion boundary."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast

import numpy as np
from numpy.typing import NDArray

from ebm_audit.errors import InvalidInputError
from ebm_audit.schema import SchemaValidationError, validate_instance

from .identity import IdentityMap

type CanonicalArray = (
    NDArray[np.bool_]
    | NDArray[np.int32]
    | NDArray[np.int64]
    | NDArray[np.float64]
)
type PrivateCodebook = tuple[Mapping[str, object], ...]


def _deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("Private canonical records require string object keys.")
        return MappingProxyType(
            {cast(str, key): _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value


class _PrivateCanonicalIngestionBinding(Mapping[str, object]):
    """Immutable private replay record whose representation never renders values."""

    __slots__ = ("_record",)

    def __init__(self, record: Mapping[str, object]) -> None:
        self._record = cast(Mapping[str, object], _deep_freeze(record))

    def __getitem__(self, key: str) -> object:
        return self._record[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._record)

    def __len__(self) -> int:
        return len(self._record)

    def __repr__(self) -> str:
        return "PrivateCanonicalIngestionBinding(<redacted>)"


def _validated_digest(value: str) -> str:
    try:
        validate_instance(value, "canonical-records.schema.json", definition="Sha256Digest")
    except SchemaValidationError:
        raise InvalidInputError(
            "DATA.COMPONENT_DIGEST_INVALID",
            "A required scientific component digest is invalid.",
        ) from None
    return value


@dataclass(frozen=True, slots=True)
class ComponentDigests:
    """Five identities computed by their owning compiler/preprocessing modules."""

    preprocessing_digest: str
    missingness_digest: str
    outlier_digest: str
    cohort_digest: str
    covariate_adjustment_digest: str

    def __post_init__(self) -> None:
        for name in (
            "preprocessing_digest",
            "missingness_digest",
            "outlier_digest",
            "cohort_digest",
            "covariate_adjustment_digest",
        ):
            object.__setattr__(self, name, _validated_digest(cast(str, getattr(self, name))))


@dataclass(frozen=True, slots=True)
class ArrayCatalogEntry:
    """Path-free identity of one canonical in-memory array."""

    member_name: str
    dtype: str
    shape: tuple[int, ...]
    semantic_version: str
    byte_length: int
    array_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "shape", tuple(self.shape))

    def to_record(self) -> dict[str, object]:
        return {
            "member_name": self.member_name,
            "dtype": self.dtype,
            "shape": list(self.shape),
            "semantic_version": self.semantic_version,
            "byte_length": self.byte_length,
            "array_digest": self.array_digest,
        }


@dataclass(frozen=True, slots=True)
class AuxiliaryColumnBinding:
    """Scientific meaning bound to one canonical covariate or metadata array."""

    array_name: str
    role: str
    kind: str
    missingness: str
    codebook_digest: str | None

    def to_record(self) -> dict[str, object]:
        return {
            "array_name": self.array_name,
            "role": self.role,
            "kind": self.kind,
            "missingness": self.missingness,
            "codebook_digest": self.codebook_digest,
        }


@dataclass(frozen=True, slots=True)
class AccountingOperation:
    """One aggregate, privacy-safe input-to-view change."""

    operation_id: str
    method_id: str
    universe_decision_id: str
    reason_code: str
    rationale: str
    participant_count: int
    event_count: int
    cell_count: int
    affected_event_ids: tuple[str, ...]
    affected_auxiliary_array_names: tuple[str, ...]
    parameter_digest: str
    input_digest: str
    output_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "affected_event_ids", tuple(self.affected_event_ids))
        object.__setattr__(
            self,
            "affected_auxiliary_array_names",
            tuple(self.affected_auxiliary_array_names),
        )

    def to_record(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "method_id": self.method_id,
            "universe_decision_id": self.universe_decision_id,
            "reason_code": self.reason_code,
            "rationale": self.rationale,
            "participant_count": self.participant_count,
            "event_count": self.event_count,
            "cell_count": self.cell_count,
            "affected_event_ids": list(self.affected_event_ids),
            "affected_auxiliary_array_names": list(
                self.affected_auxiliary_array_names
            ),
            "parameter_digest": self.parameter_digest,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
        }


@dataclass(frozen=True, slots=True)
class DataAccounting:
    """Exact aggregate accounting for canonical row and cell selection."""

    input_participants: int
    output_participants: int
    input_events: int
    output_events: int
    input_missing_cells: int
    output_missing_cells: int
    flagged_cells: int = 0
    masked_cells: int = 0
    transformed_cells: int = 0
    added_participant_instances: int = 0
    removed_participants: int = 0
    removed_events: int = 0
    operations: tuple[AccountingOperation, ...] = ()
    accounting_schema_version: str = "ebm-audit-data-accounting/2.0"

    def __post_init__(self) -> None:
        object.__setattr__(self, "operations", tuple(self.operations))

    def to_record(self) -> dict[str, object]:
        return {
            "accounting_schema_version": self.accounting_schema_version,
            "input_participants": self.input_participants,
            "output_participants": self.output_participants,
            "input_events": self.input_events,
            "output_events": self.output_events,
            "input_missing_cells": self.input_missing_cells,
            "output_missing_cells": self.output_missing_cells,
            "flagged_cells": self.flagged_cells,
            "masked_cells": self.masked_cells,
            "transformed_cells": self.transformed_cells,
            "added_participant_instances": self.added_participant_instances,
            "removed_participants": self.removed_participants,
            "removed_events": self.removed_events,
            "operations": [operation.to_record() for operation in self.operations],
        }


@dataclass(frozen=True, slots=True)
class CanonicalDatasetView:
    """Privacy-safe, array-digest-only projection of the canonical dataset."""

    variant_id: str
    participant_count: int
    event_count: int
    participant_internal_indexes: tuple[int, ...]
    participant_aliases: tuple[str, ...]
    event_ids: tuple[str, ...]
    event_directions: tuple[str, ...]
    required_covariate_array_names: tuple[str, ...]
    required_metadata_array_names: tuple[str, ...]
    auxiliary_columns: tuple[AuxiliaryColumnBinding, ...]
    array_catalog: Mapping[str, ArrayCatalogEntry]
    source_row_manifest_digest: str
    data_accounting: DataAccounting
    view_schema_version: str = "ebm-audit-canonical-dataset-view/1.0"

    def __post_init__(self) -> None:
        for name in (
            "participant_internal_indexes",
            "participant_aliases",
            "event_ids",
            "event_directions",
            "required_covariate_array_names",
            "required_metadata_array_names",
            "auxiliary_columns",
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(
            self,
            "array_catalog",
            MappingProxyType(dict(self.array_catalog)),
        )

    def to_record(self) -> dict[str, object]:
        return {
            "view_schema_version": self.view_schema_version,
            "variant_id": self.variant_id,
            "participant_count": self.participant_count,
            "event_count": self.event_count,
            "participant_internal_indexes": list(self.participant_internal_indexes),
            "participant_aliases": list(self.participant_aliases),
            "event_ids": list(self.event_ids),
            "event_directions": list(self.event_directions),
            "required_covariate_array_names": list(self.required_covariate_array_names),
            "required_metadata_array_names": list(self.required_metadata_array_names),
            "auxiliary_columns": [binding.to_record() for binding in self.auxiliary_columns],
            "array_catalog": {
                name: entry.to_record() for name, entry in self.array_catalog.items()
            },
            "source_row_manifest_digest": self.source_row_manifest_digest,
            "data_accounting": self.data_accounting.to_record(),
        }


@dataclass(frozen=True, slots=True)
class PrivateCanonicalDatasetState:
    """Sensitive canonical state retained only by the local core."""

    identity_map: IdentityMap = field(repr=False)
    namespace_key: object = field(repr=False)
    component_digests: ComponentDigests = field(repr=False)
    universe_decision_id: str = field(repr=False)
    arrays: Mapping[str, CanonicalArray] = field(repr=False)
    categorical_covariate_codebooks: Mapping[str, PrivateCodebook] = field(repr=False)
    source_row_manifest: Mapping[str, object] = field(repr=False)
    scientific_data_preimage: Mapping[str, object] = field(repr=False)
    canonical_ingestion_binding: Mapping[str, object] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arrays", MappingProxyType(dict(self.arrays)))
        object.__setattr__(
            self,
            "categorical_covariate_codebooks",
            MappingProxyType(
                {
                    name: tuple(
                        cast(Mapping[str, object], _deep_freeze(level)) for level in levels
                    )
                    for name, levels in self.categorical_covariate_codebooks.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "source_row_manifest",
            cast(Mapping[str, object], _deep_freeze(self.source_row_manifest)),
        )
        object.__setattr__(
            self,
            "scientific_data_preimage",
            cast(Mapping[str, object], _deep_freeze(self.scientific_data_preimage)),
        )
        object.__setattr__(
            self,
            "canonical_ingestion_binding",
            _PrivateCanonicalIngestionBinding(self.canonical_ingestion_binding),
        )

    def __repr__(self) -> str:
        return (
            "PrivateCanonicalDatasetState(<redacted>, "
            f"participant_count={len(self.identity_map.rows)}, array_count={len(self.arrays)})"
        )


@dataclass(frozen=True, slots=True)
class CanonicalDataset:
    """Immutable canonical ingestion result with explicit public/private halves."""

    view: CanonicalDatasetView
    scientific_data_digest: str
    source_table_content_digest: str
    private: PrivateCanonicalDatasetState = field(repr=False)

    def __repr__(self) -> str:
        return (
            "CanonicalDataset(variant_id="
            f"{self.view.variant_id!r}, participant_count={self.view.participant_count}, "
            f"event_count={self.view.event_count}, "
            f"scientific_data_digest={self.scientific_data_digest!r})"
        )
