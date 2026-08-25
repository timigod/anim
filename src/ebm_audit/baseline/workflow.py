"""High-level baseline derivation from one exact sealed result-evidence set."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, cast

from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import canonical_json_bytes, strict_json_loads
from ebm_audit.results import SealedResultEvidenceSet
from ebm_audit.results.persistence import _sealed_result_evidence_baseline
from ebm_audit.schema import SchemaValidationError, validate_instance

from .bundle import (
    VerifiedReferenceBundle,
    issue_verified_reference_alignment_owner_from_bundle,
)
from .reproduction import (
    BaselineReproductionError,
    VerifiedBaselineAssessment,
    VerifiedBaselineReproduction,
    _verified_baseline_assessment_snapshot,
    _verified_baseline_snapshot,
    assess_baseline,
    baseline_assessment_record,
    derive_baseline_reproduction,
    project_connected_baseline_result,
    verify_baseline_reproduction,
)

BASELINE_ASSESSMENT_ARTIFACT_PATH = "evidence/baseline-assessment.json"
BASELINE_REPRODUCTION_ARTIFACT_PATH = "evidence/baseline-reproduction.json"


@dataclass(frozen=True, slots=True)
class VerifiedBaselineOutcome:
    """The exact total assessment and optional successful-terminal reproduction."""

    assessment: VerifiedBaselineAssessment
    reproduction: VerifiedBaselineReproduction | None


def derive_verified_baseline_outcome(
    evidence: SealedResultEvidenceSet,
    reference_bundle: VerifiedReferenceBundle | None,
) -> VerifiedBaselineOutcome:
    """Derive the one total baseline outcome owned by ``evidence``."""

    if type(evidence) is not SealedResultEvidenceSet:
        raise TypeError("Baseline workflow requires exact sealed result evidence.")
    binding = _sealed_result_evidence_baseline(evidence)
    if binding.baseline_terminal["final_status"] != "SUCCESS":
        return VerifiedBaselineOutcome(
            assessment=assess_baseline(evidence),
            reproduction=None,
        )

    reference_owner = (
        None
        if reference_bundle is None
        else issue_verified_reference_alignment_owner_from_bundle(
            binding.baseline_finalized_result,
            reference_bundle,
        )
    )
    connected = project_connected_baseline_result(
        binding.baseline_finalized_result,
        reference_owner=reference_owner,
    )
    reproduction_record = derive_baseline_reproduction(
        connected,
        reference_owner,
    )
    reproduction = verify_baseline_reproduction(
        reproduction_record,
        connected,
        reference_owner,
    )
    return VerifiedBaselineOutcome(
        assessment=assess_baseline(evidence, reproduction),
        reproduction=reproduction,
    )


def project_verified_baseline_reproduction(
    reproduction: VerifiedBaselineReproduction,
) -> dict[str, Any]:
    """Return the canonical digest-only reproduction record after live re-verification."""

    snapshot = _verified_baseline_snapshot(reproduction)
    try:
        value = strict_json_loads(snapshot.record_bytes)
        if (
            type(value) is not dict
            or canonical_json_bytes(value) != snapshot.record_bytes
        ):
            raise BaselineReproductionError(
                "Verified baseline reproduction storage is invalid."
            )
        validate_instance(
            value,
            "canonical-records.schema.json",
            definition="BaselineReproductionRecord",
        )
        assert_no_direct_identifier_fields(value)
    except (SchemaValidationError, TypeError, ValueError):
        raise BaselineReproductionError(
            "Verified baseline reproduction storage is invalid."
        ) from None
    return copy.deepcopy(cast(dict[str, Any], value))


def verified_baseline_records(
    evidence: SealedResultEvidenceSet,
    assessment: VerifiedBaselineAssessment,
    reproduction: VerifiedBaselineReproduction | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Project one exact capability pair without accepting detached siblings."""

    if type(evidence) is not SealedResultEvidenceSet:
        raise TypeError("Baseline records require exact sealed result evidence.")
    assessment_snapshot = _verified_baseline_assessment_snapshot(assessment)
    if assessment_snapshot.sealed_result_evidence_set is not evidence:
        raise BaselineReproductionError(
            "The baseline assessment belongs to a different result-evidence set."
        )
    if assessment_snapshot.verified_baseline_reproduction is not reproduction:
        raise BaselineReproductionError(
            "The baseline assessment and reproduction authorities are detached."
        )
    assessment_record = baseline_assessment_record(assessment)
    reproduction_record = (
        None
        if reproduction is None
        else project_verified_baseline_reproduction(reproduction)
    )
    if (assessment_record["baseline_terminal"]["final_status"] == "SUCCESS") != (
        reproduction_record is not None
    ):
        raise BaselineReproductionError(
            "The baseline evidence pair is inconsistent with its terminal status."
        )
    if reproduction_record is None:
        if assessment_record["baseline_reproduction_id"] is not None:
            raise BaselineReproductionError(
                "The baseline assessment retained an unavailable reproduction."
            )
    elif (
        assessment_record["baseline_reproduction_id"]
        != reproduction_record["baseline_reproduction_id"]
    ):
        raise BaselineReproductionError(
            "The baseline assessment and reproduction records are detached."
        )
    assert_no_direct_identifier_fields(assessment_record)
    return assessment_record, reproduction_record


__all__ = [
    "BASELINE_ASSESSMENT_ARTIFACT_PATH",
    "BASELINE_REPRODUCTION_ARTIFACT_PATH",
    "VerifiedBaselineOutcome",
    "derive_verified_baseline_outcome",
    "project_verified_baseline_reproduction",
    "verified_baseline_records",
]
