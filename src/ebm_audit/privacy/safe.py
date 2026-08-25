"""Small fail-closed privacy primitives.

These helpers are intentionally conservative. They do not claim that arbitrary
third-party code is contained. Their job is to keep default protocol metadata,
operator messages, and retained subprocess evidence free of obvious direct
identifiers and caller-supplied raw text.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from ebm_audit.errors import PrivacyViolationError

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9._-])(?:/[^\s:/]+){2,}")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

# Exact normalized keys. Substring rules would wrongly reject safe protocol
# fields such as participant_count and internal row indexes.
_DIRECT_IDENTIFIER_KEYS = frozenset(
    {
        "direct_identifier",
        "direct_identifiers",
        "medical_record_number",
        "nhs_number",
        "patient_id",
        "patient_identifier",
        "participant_id",
        "participant_identifier",
        "participant_alias",
        "participant_aliases",
        "private_id",
        "private_ids",
        "raw_biomarker_value",
        "raw_biomarker_values",
        "raw_values",
        "reversible_mapping",
        "source_column",
        "source_columns",
        "source_file",
        "source_filename",
    }
)

_NEGATIVE_RESPONSE_MESSAGES = {
    "INVALID_INPUT": "The worker rejected the supplied input.",
    "UNSUPPORTED_CAPABILITY": "The worker does not support the requested capability.",
    "INVALID_SPECIFICATION": "The worker rejected the supplied specification.",
    "BACKEND_ERROR": "The worker backend could not complete the request.",
    "TIMEOUT": "The worker did not complete within its execution deadline.",
    "PRIVACY_VIOLATION": "The worker reported a privacy-boundary violation.",
    "PROTOCOL_ERROR": "The worker reported a protocol-contract violation.",
    "CONVERGENCE_FAILED": "The worker reported that convergence failed.",
    "CONVERGENCE_NOT_ASSESSABLE": "The worker could not assess convergence.",
}
_VALIDATION_ISSUE_MESSAGE = "The worker reported a structured validation issue."
_WARNING_MESSAGE = "The worker reported a structured warning."
_SELF_TEST_PASS_MESSAGE = "The worker reported that this synthetic self-test check passed."
_SELF_TEST_FAIL_MESSAGE = (
    "UNVERIFIED: the worker reported that this synthetic self-test check did not pass."
)


@dataclass(frozen=True)
class DiagnosticDigest:
    """Retained evidence for a stream without retaining its content."""

    byte_length: int
    sha256: str
    truncated: bool


def sanitize_safe_text(value: str, *, maximum_length: int = 1000) -> str:
    """Return bounded diagnostic text with common path/contact leaks removed."""

    cleaned = _CONTROL_CHARACTERS.sub("?", value)
    cleaned = _EMAIL.sub("[redacted-email]", cleaned)
    cleaned = _ABSOLUTE_PATH.sub("[redacted-path]", cleaned)
    cleaned = " ".join(cleaned.split())
    return cleaned[:maximum_length]


def diagnostic_digest(data: bytes, *, retained_limit: int) -> DiagnosticDigest:
    """Summarize captured bytes; caller should discard the bytes afterwards."""

    return DiagnosticDigest(
        byte_length=len(data),
        sha256=f"sha256:{hashlib.sha256(data).hexdigest()}",
        truncated=len(data) > retained_limit,
    )


def _normalized_key(key: object) -> str:
    return str(key).strip().lower().replace("-", "_")


def assert_no_direct_identifier_fields(value: Any) -> None:
    """Reject forbidden private-ID/raw-value keys in protocol JSON metadata."""

    def visit(node: Any) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                if _normalized_key(key) in _DIRECT_IDENTIFIER_KEYS:
                    raise PrivacyViolationError(
                        "PRIVACY.DIRECT_IDENTIFIER_FIELD",
                        "Protocol metadata contains a forbidden private identifier field.",
                    )
                visit(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                visit(child)

    visit(value)


def assert_tokens_absent(data: bytes | str, forbidden_tokens: Iterable[bytes | str]) -> None:
    """Fail if any explicitly supplied canary token appears in retained content."""

    haystack = data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")
    for token in forbidden_tokens:
        needle = token if isinstance(token, bytes) else token.encode("utf-8")
        if needle and needle in haystack:
            raise PrivacyViolationError(
                "PRIVACY.CANARY_TOKEN_PRESENT",
                "A forbidden private-data canary appeared in a retained artifact.",
            )


def core_owned_negative_response_message(category: str) -> str:
    """Return the fixed public message for one closed negative category."""

    try:
        return _NEGATIVE_RESPONSE_MESSAGES[category]
    except KeyError:
        raise PrivacyViolationError(
            "PRIVACY.WORKER_DIAGNOSTIC_CATEGORY",
            "A worker diagnostic used an unknown public category.",
        ) from None


def normalize_worker_validation_issue(issue: Mapping[str, Any]) -> dict[str, Any]:
    """Replace backend-controlled issue prose with a core-owned template."""

    normalized = copy.deepcopy(dict(issue))
    normalized["safe_message"] = _VALIDATION_ISSUE_MESSAGE
    return normalized


def normalize_worker_warning(warning: Mapping[str, Any]) -> dict[str, Any]:
    """Replace backend-controlled warning prose with a core-owned template."""

    normalized = copy.deepcopy(dict(warning))
    normalized["safe_message"] = _WARNING_MESSAGE
    return normalized


def normalize_worker_success_payload(
    command: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Remove arbitrary backend prose from every admitted success diagnostic."""

    normalized = copy.deepcopy(dict(payload))
    if command == "validate":
        issues = normalized.get("validation_issues")
        if not isinstance(issues, list) or any(not isinstance(row, Mapping) for row in issues):
            raise PrivacyViolationError(
                "PRIVACY.WORKER_DIAGNOSTIC_SHAPE",
                "A worker validation diagnostic has an invalid closed shape.",
            )
        normalized["validation_issues"] = [
            normalize_worker_validation_issue(row) for row in issues
        ]
    elif command == "stage":
        result = normalized.get("result")
        if not isinstance(result, Mapping):
            raise PrivacyViolationError(
                "PRIVACY.WORKER_DIAGNOSTIC_SHAPE",
                "A worker stage diagnostic has an invalid closed shape.",
            )
        normalized_result = copy.deepcopy(dict(result))
        warnings = normalized_result.get("warnings")
        if not isinstance(warnings, list) or any(
            not isinstance(row, Mapping) for row in warnings
        ):
            raise PrivacyViolationError(
                "PRIVACY.WORKER_DIAGNOSTIC_SHAPE",
                "A worker stage warning has an invalid closed shape.",
            )
        normalized_result["warnings"] = [normalize_worker_warning(row) for row in warnings]
        normalized["result"] = normalized_result
    elif command == "self-test":
        receipt = normalized.get("receipt")
        if not isinstance(receipt, Mapping):
            raise PrivacyViolationError(
                "PRIVACY.WORKER_DIAGNOSTIC_SHAPE",
                "A worker self-test diagnostic has an invalid closed shape.",
            )
        normalized_receipt = copy.deepcopy(dict(receipt))
        checks = normalized_receipt.get("checks")
        if not isinstance(checks, list) or any(not isinstance(row, Mapping) for row in checks):
            raise PrivacyViolationError(
                "PRIVACY.WORKER_DIAGNOSTIC_SHAPE",
                "A worker self-test diagnostic has an invalid closed shape.",
            )
        normalized_checks = []
        for row in checks:
            normalized_row = copy.deepcopy(dict(row))
            normalized_row["safe_message"] = (
                _SELF_TEST_PASS_MESSAGE
                if normalized_row.get("outcome") == "PASS"
                else _SELF_TEST_FAIL_MESSAGE
            )
            normalized_checks.append(normalized_row)
        normalized_receipt["checks"] = normalized_checks
        normalized["receipt"] = normalized_receipt
    return normalized
