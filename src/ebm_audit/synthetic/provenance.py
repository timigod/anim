"""Deterministic identities for project-generated candidate provenance.

The live synthetic-input owner authenticates the provenance before issue.  A
worker subprocess has no credential or signature and therefore verifies only
the closed record's deterministic code, dataset, array-catalog, and internal
hash bindings.  This is the supported-path trust boundary required by the
SYNTHETIC-ONLY conformance worker; it is not an attestation system.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ebm_audit.protocol import structured_sha256

from .generator import _generator_code_sha256

PROJECT_SYNTHETIC_GENERATOR_ID = "ebm-audit-scenario-generator"
PROJECT_SYNTHETIC_GENERATOR_VERSION = "1.0.0"
PROJECT_SYNTHETIC_ARRAY_NAMES = frozenset(
    {
        "train_values",
        "training_row_indexes",
        "train_group_codes",
        "evaluation_values",
        "evaluation_row_indexes",
        "evaluation_group_codes",
    }
)


def project_synthetic_generator_code_sha256() -> str:
    """Return the exact source identity already owned by the generator."""

    return "sha256:" + _generator_code_sha256()


def project_synthetic_generator_record_sha256() -> str:
    """Bind the fixed generator name and version to its exact code identity."""

    return structured_sha256(
        "ebm-audit/project-synthetic-generator-record/1",
        {
            "generator_id": PROJECT_SYNTHETIC_GENERATOR_ID,
            "generator_version": PROJECT_SYNTHETIC_GENERATOR_VERSION,
            "generator_code_sha256": project_synthetic_generator_code_sha256(),
        },
    )


def project_candidate_array_catalog_sha256(catalog: Mapping[str, Any]) -> str:
    """Bind every actual candidate array through its canonical catalog entry."""

    return structured_sha256(
        "ebm-audit/project-synthetic-candidate-array-catalog/1",
        dict(catalog),
    )


def project_candidate_dataset_sha256(dataset: Mapping[str, Any]) -> str:
    """Bind the closed dataset descriptor before provenance is attached."""

    if "synthetic_provenance" in dataset:
        raise ValueError("Candidate dataset identity excludes its recursive provenance field.")
    return structured_sha256(
        "ebm-audit/project-synthetic-candidate-dataset/1",
        dict(dataset),
    )


def project_candidate_derivation_selector(operation: Mapping[str, Any]) -> str:
    """Return the exact public selector role for one closed operation intent."""

    kind = operation.get("kind")
    if kind == "ordinary" and set(operation) == {"kind"}:
        return "ordinary"
    if kind in {"bootstrap", "subsample", "null"}:
        ordinal = operation.get("replicate_ordinal")
        if type(ordinal) is int and ordinal >= 0:
            return f"replicate:{ordinal}"
    if kind == "influence":
        ordinal = operation.get("removal_slot_ordinal")
        if type(ordinal) is int and ordinal >= 0:
            return f"removal:{ordinal}"
    raise ValueError("Candidate operation has no closed derivation selector.")


def project_candidate_operation_intent_sha256(operation: Mapping[str, Any]) -> str:
    """Bind the complete operation intent, not only its short selector."""

    return structured_sha256(
        "ebm-audit/project-synthetic-candidate-operation-intent/1",
        dict(operation),
    )


def project_candidate_provenance_binding_sha256(
    provenance: Mapping[str, Any],
) -> str:
    """Bind one complete project provenance record with a null digest slot."""

    return structured_sha256(
        "ebm-audit/project-synthetic-candidate-provenance/1",
        dict(provenance),
    )


__all__ = [
    "PROJECT_SYNTHETIC_ARRAY_NAMES",
    "PROJECT_SYNTHETIC_GENERATOR_ID",
    "PROJECT_SYNTHETIC_GENERATOR_VERSION",
    "project_candidate_array_catalog_sha256",
    "project_candidate_dataset_sha256",
    "project_candidate_derivation_selector",
    "project_candidate_operation_intent_sha256",
    "project_candidate_provenance_binding_sha256",
    "project_synthetic_generator_code_sha256",
    "project_synthetic_generator_record_sha256",
]
