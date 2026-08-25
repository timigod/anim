"""Exact baseline-reference identity and reproduction gate."""

from __future__ import annotations

from .bundle import (
    BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME,
    BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME,
    BASELINE_REFERENCE_BUNDLE_SCHEMA_VERSION,
    ReferenceBundleError,
    VerifiedReferenceBundle,
    issue_verified_reference_alignment_owner_from_bundle,
)
from .reproduction import (
    BASELINE_COMPARISON_IDS,
    BaselineAssessmentStatus,
    BaselineReproductionError,
    ConnectedBaselineResult,
    VerifiedBaselineAssessment,
    VerifiedBaselineReproduction,
    VerifiedReferenceAlignmentOwner,
    VerifiedReferenceResult,
    assess_baseline,
    baseline_assessment_record,
    baseline_tolerance_contract,
    build_connected_result,
    build_reference_result,
    derive_baseline_reproduction,
    issue_verified_reference_alignment_owner,
    issue_verified_reference_result,
    project_connected_baseline_result,
    verify_baseline_reproduction,
)
from .reproduction import (
    _verified_baseline_assessment_snapshot as _verified_baseline_assessment_snapshot,
)
from .reproduction import (
    _verified_baseline_snapshot as _verified_baseline_snapshot,
)

__all__ = [
    "BASELINE_COMPARISON_IDS",
    "BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME",
    "BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME",
    "BASELINE_REFERENCE_BUNDLE_SCHEMA_VERSION",
    "BaselineAssessmentStatus",
    "BaselineReproductionError",
    "ConnectedBaselineResult",
    "ReferenceBundleError",
    "VerifiedBaselineAssessment",
    "VerifiedBaselineReproduction",
    "VerifiedReferenceAlignmentOwner",
    "VerifiedReferenceBundle",
    "VerifiedReferenceResult",
    "assess_baseline",
    "baseline_assessment_record",
    "baseline_tolerance_contract",
    "build_connected_result",
    "build_reference_result",
    "derive_baseline_reproduction",
    "issue_verified_reference_alignment_owner",
    "issue_verified_reference_alignment_owner_from_bundle",
    "issue_verified_reference_result",
    "project_connected_baseline_result",
    "verify_baseline_reproduction",
]
