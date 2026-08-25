"""Private canonical-data boundary."""

from __future__ import annotations

from .canonical import (
    AccountingOperation,
    ArrayCatalogEntry,
    AuxiliaryColumnBinding,
    CanonicalDataset,
    CanonicalDatasetView,
    ComponentDigests,
    DataAccounting,
    PrivateCanonicalDatasetState,
    compute_source_table_content_digest,
    ingest_canonical_table_audit_dataset,
    ingest_exact_file_audit_dataset,
    validate_canonical_dataset,
)
from .identity import (
    IdentityMap,
    IdentityRow,
    build_identity_map,
    generate_namespace_key,
    participant_token_parameters,
)
from .preparation import (
    PreparedAuditDataset,
    ValidatedDatasetSummary,
    prepare_audit_dataset,
)
from .source_admission import ValidatedSourceAdmission

__all__ = [
    "AccountingOperation",
    "ArrayCatalogEntry",
    "AuxiliaryColumnBinding",
    "CanonicalDataset",
    "CanonicalDatasetView",
    "ComponentDigests",
    "DataAccounting",
    "IdentityMap",
    "IdentityRow",
    "PreparedAuditDataset",
    "PrivateCanonicalDatasetState",
    "ValidatedDatasetSummary",
    "ValidatedSourceAdmission",
    "build_identity_map",
    "compute_source_table_content_digest",
    "generate_namespace_key",
    "ingest_canonical_table_audit_dataset",
    "ingest_exact_file_audit_dataset",
    "participant_token_parameters",
    "prepare_audit_dataset",
    "validate_canonical_dataset",
]
