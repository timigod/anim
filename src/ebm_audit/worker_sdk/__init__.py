"""Public worker-side SDK for trusted local Python integrations.

This module is imported by a researcher-owned worker subprocess. It does not
load that research model into the auditor core process.
"""

from ebm_audit.workers import WorkerApplication
from ebm_audit.workers.arrays import (
    array_catalog_entry,
    canonical_array,
    load_catalogued_npz_arrays,
    load_npz_arrays,
    write_deterministic_npz,
)
from ebm_audit.workers.types import (
    WorkerBackend,
    WorkerFailure,
    WorkerSuccess,
)

from .fit_context import FitContext, FitOutputs
from .mapping import map_fit_result
from .records import (
    ArrayReference,
    ArtifactReference,
    CapabilityDeclaration,
    CapabilityLimits,
    CapabilityName,
    ChainResult,
    DescribeSuccess,
    EvidenceReference,
    FitSuccess,
    SafeDetails,
    SDKValidationError,
    StageReference,
    SyntheticProvenance,
    UnavailableOutput,
    ValidateSuccess,
    WarningRecord,
    WorkerIdentity,
)
from .synthetic import (
    SyntheticProtocolExampleBackend,
    build_synthetic_protocol_identity,
)

__all__ = [
    "ArrayReference",
    "ArtifactReference",
    "CapabilityDeclaration",
    "CapabilityLimits",
    "CapabilityName",
    "ChainResult",
    "DescribeSuccess",
    "EvidenceReference",
    "FitContext",
    "FitOutputs",
    "FitSuccess",
    "SDKValidationError",
    "SafeDetails",
    "StageReference",
    "SyntheticProtocolExampleBackend",
    "SyntheticProvenance",
    "UnavailableOutput",
    "ValidateSuccess",
    "WarningRecord",
    "WorkerApplication",
    "WorkerBackend",
    "WorkerFailure",
    "WorkerIdentity",
    "WorkerSuccess",
    "array_catalog_entry",
    "build_synthetic_protocol_identity",
    "canonical_array",
    "load_catalogued_npz_arrays",
    "load_npz_arrays",
    "map_fit_result",
    "write_deterministic_npz",
]
