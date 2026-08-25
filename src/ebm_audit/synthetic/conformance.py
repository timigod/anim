"""Model-free deterministic input and provenance for the conformance EBM."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import numpy as np
from numpy.typing import NDArray

from ebm_audit.protocol import structured_sha256
from ebm_audit.schema import validate_instance

CONFORMANCE_GENERATOR_ID = "conformance-generator"
CONFORMANCE_GENERATOR_VERSION = "1.0.0"
CONFORMANCE_SCENARIO_ID = "strict-sequence"
CONFORMANCE_REPLICATE = 0
CONFORMANCE_GENERATION_SEED = "000000000000002a"
CONFORMANCE_MIN_EVENT_COUNT = 2
CONFORMANCE_MAX_EVENT_COUNT = 9
CONFORMANCE_ARRAY_NAMES = frozenset(
    {"train_values", "training_row_indexes", "train_group_codes"}
)

_CLASSIFICATION = "SYNTHETIC-ONLY"
_SOURCE_KIND = "PROJECT_OWNED_DETERMINISTIC_GENERATOR"


@dataclass(frozen=True, slots=True)
class ConformanceGeneratedInput:
    """One tiny deterministic synthetic input generated without external data."""

    event_directions: tuple[str, ...]
    group_codebook: Mapping[str, str]
    arrays: Mapping[str, NDArray[Any]]
    generated_input_sha256: str


def conformance_generator_record() -> dict[str, object]:
    """Return the complete static record for the tiny conformance generator."""

    return {
        "record_schema_version": "ebm-audit-conformance-generator/1.0",
        "classification": _CLASSIFICATION,
        "generator_id": CONFORMANCE_GENERATOR_ID,
        "generator_version": CONFORMANCE_GENERATOR_VERSION,
        "scenario_id": CONFORMANCE_SCENARIO_ID,
        "replicate": CONFORMANCE_REPLICATE,
        "generation_seed": CONFORMANCE_GENERATION_SEED,
        "source_kind": _SOURCE_KIND,
        "participant_data_present": False,
        "external_source_present": False,
        "algorithm": "domain-separated-cell-digest-to-binary-exact-float/1",
    }


def conformance_generator_record_sha256() -> str:
    """Recompute the canonical static generator-record digest."""

    return structured_sha256(
        "ebm-audit/conformance-generator-record/1",
        conformance_generator_record(),
    )


def _cell_value(participant_index: int, event_id: str) -> float:
    digest = structured_sha256(
        "ebm-audit/conformance-generated-cell/1",
        {
            "scenario_id": CONFORMANCE_SCENARIO_ID,
            "replicate": CONFORMANCE_REPLICATE,
            "generation_seed": CONFORMANCE_GENERATION_SEED,
            "participant_index": participant_index,
            "event_id": event_id,
        },
    )
    integer = int(digest.removeprefix("sha256:")[:8], 16) % 2049 - 1024
    return integer / 256.0


def generate_conformance_input(
    *,
    participant_count: int,
    event_count: int,
    event_ids: tuple[str, ...],
) -> ConformanceGeneratedInput:
    """Regenerate the only input form admitted by the conformance worker."""

    if (
        participant_count < 2
        or event_count < CONFORMANCE_MIN_EVENT_COUNT
        or event_count > CONFORMANCE_MAX_EVENT_COUNT
        or event_count != len(event_ids)
        or len(set(event_ids)) != event_count
    ):
        raise ValueError("The conformance dimensions are invalid.")

    values = np.asarray(
        [
            [_cell_value(participant_index, event_id) for event_id in event_ids]
            for participant_index in range(participant_count)
        ],
        dtype=np.float64,
    )
    row_indexes = np.arange(participant_count, dtype=np.int64)
    group_offset = int(CONFORMANCE_GENERATION_SEED[-1], 16) + CONFORMANCE_REPLICATE
    group_codes = np.asarray(
        [(participant_index + group_offset) % 2 for participant_index in range(participant_count)],
        dtype=np.int32,
    )
    event_directions = tuple(
        "higher"
        if int(
            structured_sha256(
                "ebm-audit/conformance-event-direction/1",
                {
                    "scenario_id": CONFORMANCE_SCENARIO_ID,
                    "generation_seed": CONFORMANCE_GENERATION_SEED,
                    "event_id": event_id,
                },
            ).removeprefix("sha256:")[:2],
            16,
        )
        % 2
        == 0
        else "lower"
        for event_id in event_ids
    )
    group_codebook = {"0": "reference", "1": "at_risk"}
    arrays: dict[str, NDArray[Any]] = {
        "train_values": values,
        "training_row_indexes": row_indexes,
        "train_group_codes": group_codes,
    }
    digest_record = {
        "record_schema_version": "ebm-audit-conformance-generated-input/1.0",
        "classification": _CLASSIFICATION,
        "scenario_id": CONFORMANCE_SCENARIO_ID,
        "replicate": CONFORMANCE_REPLICATE,
        "generation_seed": CONFORMANCE_GENERATION_SEED,
        "dimensions": {
            "participant_count": participant_count,
            "event_count": event_count,
        },
        "event_ids": list(event_ids),
        "event_directions": list(event_directions),
        "group_codebook": group_codebook,
        "arrays": {
            "train_values": values.tolist(),
            "training_row_indexes": row_indexes.tolist(),
            "train_group_codes": group_codes.tolist(),
        },
    }
    return ConformanceGeneratedInput(
        event_directions=event_directions,
        group_codebook=group_codebook,
        arrays=arrays,
        generated_input_sha256=structured_sha256(
            "ebm-audit/conformance-generated-input/1",
            digest_record,
        ),
    )


def conformance_complete_truth_record(
    *,
    participant_count: int,
    event_count: int,
    event_ids: tuple[str, ...],
) -> dict[str, object]:
    """Return only deterministic generator-owned truth bound into provenance."""

    generated = generate_conformance_input(
        participant_count=participant_count,
        event_count=event_count,
        event_ids=event_ids,
    )
    identity_material = {
        "classification": _CLASSIFICATION,
        "scenario_id": CONFORMANCE_SCENARIO_ID,
        "replicate": CONFORMANCE_REPLICATE,
        "generation_seed": CONFORMANCE_GENERATION_SEED,
        "generator_record": conformance_generator_record(),
        "generator_record_sha256": conformance_generator_record_sha256(),
        "dimensions": {
            "participant_count": participant_count,
            "event_count": event_count,
        },
        "event_ids": list(event_ids),
        "event_directions": list(generated.event_directions),
        "group_codebook": dict(generated.group_codebook),
        "generated_input_sha256": generated.generated_input_sha256,
        "generated_arrays": {
            name: array.tolist() for name, array in generated.arrays.items()
        },
        "source_facts": {
            "source_kind": _SOURCE_KIND,
            "participant_data_present": False,
            "external_source_present": False,
        },
        "recoverable_order_signal": {
            "claimed": False,
            "fact": "NO_CLAIMED_RECOVERABLE_ORDER_SIGNAL",
        },
    }
    identity_digest = structured_sha256(
        "ebm-audit/conformance-complete-truth-identity/3",
        identity_material,
    )
    return {
        "record_schema_version": "ebm-audit-conformance-complete-truth/3.0",
        "complete_truth_record_id": (
            "conformance-truth-" + identity_digest.removeprefix("sha256:")[:46]
        ),
        **identity_material,
    }


def _complete_truth_identity(
    *,
    participant_count: int,
    event_count: int,
    event_ids: tuple[str, ...],
) -> tuple[str, str]:
    record = conformance_complete_truth_record(
        participant_count=participant_count,
        event_count=event_count,
        event_ids=event_ids,
    )
    return str(record["complete_truth_record_id"]), structured_sha256(
        "ebm-audit/conformance-complete-truth/3",
        record,
    )


def build_conformance_provenance(
    *,
    participant_count: int,
    event_count: int,
    event_ids: tuple[str, ...],
) -> dict[str, object]:
    """Build the exact provenance expected for one regenerated input."""

    generated = generate_conformance_input(
        participant_count=participant_count,
        event_count=event_count,
        event_ids=event_ids,
    )
    truth_record_id, truth_sha256 = _complete_truth_identity(
        participant_count=participant_count,
        event_count=event_count,
        event_ids=event_ids,
    )
    provenance: dict[str, object] = {
        "schema_version": "ebm-audit-synthetic-provenance/1.0",
        "classification": _CLASSIFICATION,
        "generator_id": CONFORMANCE_GENERATOR_ID,
        "generator_version": CONFORMANCE_GENERATOR_VERSION,
        "generator_record_sha256": conformance_generator_record_sha256(),
        "generated_input_sha256": generated.generated_input_sha256,
        "complete_truth_sha256": truth_sha256,
        "complete_truth_record_id": truth_record_id,
        "scenario_id": CONFORMANCE_SCENARIO_ID,
        "replicate": CONFORMANCE_REPLICATE,
        "seed": CONFORMANCE_GENERATION_SEED,
        "source_kind": _SOURCE_KIND,
        "participant_data_present": False,
        "external_source_present": False,
        "participant_count": participant_count,
        "event_count": event_count,
        "event_ids": list(event_ids),
    }
    validate_instance(
        provenance,
        "worker-protocol.schema.json",
        definition="SyntheticProvenance",
    )
    return provenance


__all__ = [
    "CONFORMANCE_ARRAY_NAMES",
    "CONFORMANCE_GENERATION_SEED",
    "CONFORMANCE_GENERATOR_ID",
    "CONFORMANCE_GENERATOR_VERSION",
    "CONFORMANCE_MAX_EVENT_COUNT",
    "CONFORMANCE_MIN_EVENT_COUNT",
    "CONFORMANCE_REPLICATE",
    "CONFORMANCE_SCENARIO_ID",
    "ConformanceGeneratedInput",
    "build_conformance_provenance",
    "conformance_complete_truth_record",
    "conformance_generator_record",
    "conformance_generator_record_sha256",
    "generate_conformance_input",
]
