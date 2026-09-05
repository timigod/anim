"""Live-evidence reporting plus fail-closed persisted rehydration."""

from .claims import (
    BASELINE_WORDING_GATE,
    MANDATORY_OPENING,
    NULL_SAFE_FALLBACK,
    claim_is_allowed,
    prohibited_claim_codes,
)
from .inspection import ReportInspectionError, compare_reports, inspect_report
from .render import (
    CURRENT_REPORT_STATUS,
    REPORT_SCHEMA_VERSION,
    REPORT_V1_UNAVAILABLE_REASON,
    ReportUnavailableError,
    render_report_from_run_dir,
    write_report_from_live_evidence,
)

__all__ = [
    "BASELINE_WORDING_GATE",
    "CURRENT_REPORT_STATUS",
    "MANDATORY_OPENING",
    "NULL_SAFE_FALLBACK",
    "REPORT_SCHEMA_VERSION",
    "REPORT_V1_UNAVAILABLE_REASON",
    "ReportInspectionError",
    "ReportUnavailableError",
    "claim_is_allowed",
    "compare_reports",
    "inspect_report",
    "prohibited_claim_codes",
    "render_report_from_run_dir",
    "write_report_from_live_evidence",
]
