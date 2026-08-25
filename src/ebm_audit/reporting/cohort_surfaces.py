"""Atomic report surfaces for one sealed proportional scenario cohort."""

from __future__ import annotations

import base64
import copy
import csv
import html
import io
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Final, Never, cast
from weakref import WeakKeyDictionary

from ebm_audit._capability_registry import OneShotRegistryError
from ebm_audit.evaluator import meaning_evidence_bundle as bundle_module
from ebm_audit.evaluator import report_claim_projection as claim_module
from ebm_audit.evaluator.meaning_evidence_bundle import (
    AuthenticatedMeaningEvidenceExtension,
    MeaningEvidenceBundle,
)
from ebm_audit.evaluator.report_claim_projection import (
    AuthenticatedReportClaimProjection,
)
from ebm_audit.evaluator.scenario_cohort_evidence import SealedScenarioCohortEvidence
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
    structured_sha256_hex,
)
from ebm_audit.schema import SchemaValidationError, validate_instance

from . import _report_model_artifact_binding as binding_module
from . import render
from ._report_model_artifact_binding import AuthenticatedReportModelArtifactBinding
from .claims import MANDATORY_OPENING, NULL_SAFE_FALLBACK, REPORT_LANGUAGE_RULE_ID

_REPORT_JSON_PATH: Final = "report/report.json"
_APPLICABLE_CSV_PATH: Final = "report/meaning-evidence.csv"
_SELF_CONTAINED_HTML_PATH: Final = "report/report.html"
_SURFACE_RECEIPT_PATH: Final = "report/report-surface-verification-receipt.json"
_SURFACE_PATHS: Final = (
    _REPORT_JSON_PATH,
    _APPLICABLE_CSV_PATH,
    _SELF_CONTAINED_HTML_PATH,
)
_SURFACE_NAMES: Final = (
    "REPORT_JSON",
    "APPLICABLE_CSV",
    "SELF_CONTAINED_HTML",
)
_SURFACE_RECEIPT_DOMAIN: Final = "ebm-audit/report-surface-verification-receipt/1"
_CASE_BINDING_DOMAIN: Final = "ebm-audit/cohort-report-case-binding/1"
_ORDERED_MEANING_DOMAIN: Final = (
    "ebm-audit/report-surface-ordered-meaning-identity-state-value/1"
)
_ORDERED_WARNING_DOMAIN: Final = "ebm-audit/report-surface-ordered-warning-record/1"
_ORDERED_TERMINAL_DOMAIN: Final = "ebm-audit/report-surface-ordered-terminal-record/1"
_ORDERED_CLAIM_DOMAIN: Final = "ebm-audit/report-surface-ordered-claim-ids/1"
_SCIENCE_GATE_REASON: Final = "REPORT.COHORT_READINESS_NOT_FROZEN"
_HTML_PAYLOAD_START: Final = (
    b'<script id="ebm-audit-cohort-surface-data" type="application/octet-stream">'
)
_HTML_PAYLOAD_END: Final = b"</script>"
_CSV_FIELDS: Final = (
    "row_kind",
    "ordinal",
    "meaning_id",
    "operation_group_id",
    "state",
    "value_json",
    "reason_codes_json",
    "failure_code",
    "operation_ids_json",
    "output_schema_ref",
    "derivation_id",
    "source_record_digests_json",
    "report_claim_projection_sha256",
    "final_meaning_bundle_sha256",
    "ordered_warning_record_sha256_json",
    "ordered_terminal_record_sha256_json",
    "ordered_claim_ids_json",
)


class CohortReportSurfaceError(TypeError):
    """Raised when cohort authority or a rendered surface fails closed."""


def _reject() -> Never:
    raise CohortReportSurfaceError(
        "The cohort report surface transaction failed closed validation."
    )


@dataclass(frozen=True, slots=True)
class _CohortAuthoritySnapshot:
    cohort_sha256: str
    benchmark_subject_digest: str
    proportional_operation_plan_sha256: str
    evidence_graph_identity: dict[str, object]
    ordered_warning_record_sha256: tuple[str, ...]
    ordered_terminal_record_sha256: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _SurfaceObservation:
    final_meaning_bundle_sha256: str
    report_claim_projection_sha256: str
    ordered_meaning_identity_state_value_sha256: str
    ordered_warning_record_sha256: str
    ordered_terminal_record_sha256: str
    ordered_claim_ids_sha256: str


@dataclass(frozen=True, slots=True)
class CohortReportSurfaceTransactionResult:
    """The exact extension and terminal receipt for one promoted surface set."""

    output_directory: Path
    authenticated_meaning_evidence_extension: AuthenticatedMeaningEvidenceExtension
    report_model_artifact_binding: AuthenticatedReportModelArtifactBinding
    receipt: Mapping[str, object]


_ISSUED_EXTENSION_BY_CLAIM: WeakKeyDictionary[
    AuthenticatedReportClaimProjection, MeaningEvidenceBundle
] = WeakKeyDictionary()
_ISSUED_EXTENSION_LOCK = RLock()


def _is_bare_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _bare_sha256(value: object) -> str:
    if type(value) is not str:
        _reject()
    bare = value.removeprefix("sha256:")
    if not _is_bare_sha256(bare):
        _reject()
    return bare


def _prefixed_sha256(value: object) -> str:
    bare = _bare_sha256(value)
    return f"sha256:{bare}"


def _ordered_unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _same_owners(left: Sequence[object], right: Sequence[object]) -> bool:
    return len(left) == len(right) and all(
        left_owner is right_owner for left_owner, right_owner in zip(left, right, strict=True)
    )


def _read_cohort_authority(
    sealed_cohort: SealedScenarioCohortEvidence,
    claim_projection: AuthenticatedReportClaimProjection,
    meaning_bundle: MeaningEvidenceBundle,
) -> _CohortAuthoritySnapshot:
    """Revalidate and join the sealed cohort, final claim, and final 104 bundle."""

    if (
        type(sealed_cohort) is not SealedScenarioCohortEvidence
        or type(claim_projection) is not AuthenticatedReportClaimProjection
        or type(meaning_bundle) is not MeaningEvidenceBundle
    ):
        _reject()
    try:
        authority = claim_module._cohort_report_authority(sealed_cohort)
        retained = claim_module._read_cohort_report_claim_authority(claim_projection)
        claim_value = claim_module.read_authenticated_report_claim_projection(
            claim_projection
        )
        claim_graph_digest = claim_module._read_cohort_report_evidence_graph_digest(
            claim_projection
        )
        meaning_value = bundle_module.read_meaning_evidence_bundle(meaning_bundle)
    except (TypeError, ValueError):
        _reject()
    if (
        retained[0] is not authority.batch_owner
        or retained[1] != authority.ordered_case_contexts
        or tuple(case_id for case_id, _owner in retained[2])
        != tuple(case_id for case_id, _owner in authority.ordered_warning_records)
        or not _same_owners(
            tuple(owner for _case_id, owner in retained[2]),
            tuple(owner for _case_id, owner in authority.ordered_warning_records),
        )
        or not _same_owners(retained[3], authority.ordered_terminal_records)
    ):
        _reject()
    cohort_projection = authority.cohort_projection
    cohort_sha256 = _prefixed_sha256(cohort_projection.get("cohort_sha256"))
    cohort_bare = cohort_sha256.removeprefix("sha256:")
    plan_sha256 = _bare_sha256(
        cohort_projection.get("proportional_operation_plan_sha256")
    )
    if (
        claim_graph_digest != cohort_bare
        or claim_value.get("report_claim_projection_sha256") != claim_projection.digest
        or meaning_value.get("bundle_sha256") != meaning_bundle.digest
        or meaning_value.get("evidence_graph_digest") != cohort_bare
        or type(meaning_value.get("records")) is not list
        or len(cast(list[object], meaning_value["records"])) != 104
    ):
        _reject()

    raw_cases = authority.ordered_case_contexts
    ledger = cohort_projection.get("terminal_state_ledger")
    raw_source_sets = cohort_projection.get("ordered_source_record_digest_sets")
    if (
        len(raw_cases) != 57
        or type(ledger) is not list
        or len(ledger) != 104
        or type(raw_source_sets) is not list
        or len(raw_source_sets) != 104
    ):
        _reject()
    case_ids: list[str] = []
    case_rows: list[dict[str, str]] = []
    for value in raw_cases:
        family_id = getattr(value, "family_id", None)
        case_id = getattr(value, "case_id", None)
        source_contract_sha256 = _bare_sha256(
            getattr(value, "source_contract_sha256", None)
        )
        scenario_source_sha256 = _bare_sha256(
            getattr(value, "scenario_source_sha256", None)
        )
        if type(family_id) is not str or not family_id or type(case_id) is not str or not case_id:
            _reject()
        case_ids.append(case_id)
        case_rows.append(
            {
                "family_id": family_id,
                "case_id": case_id,
                "source_contract_sha256": source_contract_sha256,
                "scenario_source_sha256": scenario_source_sha256,
            }
        )
    if len(set(case_ids)) != 57:
        _reject()

    ledger_case_ids: list[str] = []
    source_digests_by_case: dict[str, list[str]] = {case_id: [] for case_id in case_ids}
    ordered_all_source_digests: list[str] = []
    for ledger_row, source_set in zip(ledger, raw_source_sets, strict=True):
        if type(ledger_row) is not dict or type(ledger_row.get("case_id")) is not str:
            _reject()
        case_id = cast(str, ledger_row["case_id"])
        if case_id not in source_digests_by_case or type(source_set) is not list:
            _reject()
        ledger_case_ids.append(case_id)
        for digest_value in source_set:
            digest = _bare_sha256(digest_value)
            source_digests_by_case[case_id].append(digest)
            ordered_all_source_digests.append(digest)
    if _ordered_unique(ledger_case_ids) != tuple(case_ids):
        _reject()
    ordered_source_digests = _ordered_unique(ordered_all_source_digests)
    if not ordered_source_digests or set(ordered_source_digests) != set(
        authority.source_record_digests
    ):
        _reject()

    bindings: list[dict[str, str]] = []
    for case_row in case_rows:
        case_source_digests = _ordered_unique(
            source_digests_by_case[case_row["case_id"]]
        )
        if not case_source_digests:
            _reject()
        case_graph_digest = structured_sha256_hex(
            _CASE_BINDING_DOMAIN,
            {
                "benchmark_subject_digest": authority.benchmark_subject_digest,
                "proportional_operation_plan_sha256": plan_sha256,
                **case_row,
                "ordered_source_record_digests": list(case_source_digests),
            },
        )
        bindings.append({**case_row, "evidence_graph_digest": case_graph_digest})
    identity = bundle_module._normalized_evidence_graph_identity(
        {
            "scope": "SCENARIO_COHORT",
            "benchmark_subject_digest": _prefixed_sha256(
                authority.benchmark_subject_digest
            ),
            "operation_plan_sha256": plan_sha256,
            "case_bindings": bindings,
            "source_record_digests": list(ordered_source_digests),
        }
    )
    try:
        validate_instance(
            identity,
            "report.schema.json",
            definition="EvidenceGraphIdentity",
        )
    except SchemaValidationError:
        _reject()

    warning_digests = claim_value.get("ordered_warning_record_sha256")
    terminal_digests = claim_value.get("ordered_public_terminal_result_sha256")
    if (
        type(warning_digests) is not list
        or type(terminal_digests) is not list
        or len(terminal_digests) != 104
    ):
        _reject()
    ordered_warning = tuple(_bare_sha256(value) for value in warning_digests)
    ordered_terminal = tuple(_bare_sha256(value) for value in terminal_digests)
    if (
        len(set(ordered_warning)) != len(ordered_warning)
        or len(set(ordered_terminal)) != len(ordered_terminal)
    ):
        _reject()
    return _CohortAuthoritySnapshot(
        cohort_sha256=cohort_sha256,
        benchmark_subject_digest=_prefixed_sha256(authority.benchmark_subject_digest),
        proportional_operation_plan_sha256=plan_sha256,
        evidence_graph_identity=identity,
        ordered_warning_record_sha256=ordered_warning,
        ordered_terminal_record_sha256=ordered_terminal,
    )


def _read_authenticated_cohort_authority_snapshot(
    sealed_cohort: SealedScenarioCohortEvidence,
    extension: AuthenticatedMeaningEvidenceExtension,
) -> _CohortAuthoritySnapshot:
    """Rebuild the report authority from one extension's retained owners."""

    if (
        type(sealed_cohort) is not SealedScenarioCohortEvidence
        or type(extension) is not AuthenticatedMeaningEvidenceExtension
    ):
        _reject()
    try:
        bundle_module.read_authenticated_meaning_evidence_extension(extension)
        state = bundle_module._EXTENSION_STATES.read(extension)
        return _read_cohort_authority(
            sealed_cohort,
            state.claim_projection,
            state.meaning_bundle,
        )
    except (OneShotRegistryError, TypeError, ValueError):
        _reject()


def _issue_one_cohort_extension(
    claim_projection: AuthenticatedReportClaimProjection,
    meaning_bundle: MeaningEvidenceBundle,
    authority: _CohortAuthoritySnapshot,
) -> AuthenticatedMeaningEvidenceExtension:
    with _ISSUED_EXTENSION_LOCK:
        try:
            existing = _ISSUED_EXTENSION_BY_CLAIM.get(claim_projection)
        except TypeError:
            _reject()
        if existing is not None:
            _reject()
        _ISSUED_EXTENSION_BY_CLAIM[claim_projection] = meaning_bundle
    try:
        owner = bundle_module._issue_authenticated_meaning_evidence_extension(
            claim_projection,
            meaning_bundle,
            scientific_evidence_digest=authority.cohort_sha256.removeprefix("sha256:"),
            evidence_graph_identity=authority.evidence_graph_identity,
        )
        extension = bundle_module.read_authenticated_meaning_evidence_extension(owner)
    except (TypeError, ValueError):
        _reject()
    if (
        extension.get("scientific_evidence_digest")
        != authority.cohort_sha256.removeprefix("sha256:")
        or extension.get("evidence_graph_identity") != authority.evidence_graph_identity
        or extension.get("report_claim_projection_sha256") != claim_projection.digest
        or extension.get("meaning_evidence_bundle_sha256") != meaning_bundle.digest
    ):
        _reject()
    return owner


def _meaning_identity_state_value(
    records: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, object], ...]:
    validated = render._validated_meaning_evidence_records(records)
    return tuple(
        {
            "meaning_id": record["meaning_id"],
            "state": record["state"],
            "value": copy.deepcopy(record["value"]),
        }
        for record in validated
    )


def _surface_observation(
    *,
    report_claim_projection_sha256: str,
    final_meaning_bundle_sha256: str,
    meaning_records: Sequence[Mapping[str, Any]],
    ordered_warning_record_sha256: Sequence[str],
    ordered_terminal_record_sha256: Sequence[str],
    ordered_claim_ids: Sequence[str],
) -> _SurfaceObservation:
    return _SurfaceObservation(
        final_meaning_bundle_sha256=_bare_sha256(final_meaning_bundle_sha256),
        report_claim_projection_sha256=_bare_sha256(
            report_claim_projection_sha256
        ),
        ordered_meaning_identity_state_value_sha256=structured_sha256_hex(
            _ORDERED_MEANING_DOMAIN,
            list(_meaning_identity_state_value(meaning_records)),
        ),
        ordered_warning_record_sha256=structured_sha256_hex(
            _ORDERED_WARNING_DOMAIN,
            [_bare_sha256(value) for value in ordered_warning_record_sha256],
        ),
        ordered_terminal_record_sha256=structured_sha256_hex(
            _ORDERED_TERMINAL_DOMAIN,
            [_bare_sha256(value) for value in ordered_terminal_record_sha256],
        ),
        ordered_claim_ids_sha256=structured_sha256_hex(
            _ORDERED_CLAIM_DOMAIN,
            list(ordered_claim_ids),
        ),
    )


def _report_model(
    extension: AuthenticatedMeaningEvidenceExtension,
    authority: _CohortAuthoritySnapshot,
    claim_projection: AuthenticatedReportClaimProjection,
) -> tuple[dict[str, object], bytes]:
    extension_value = bundle_module.read_authenticated_meaning_evidence_extension(extension)
    claim_value = cast(
        Mapping[str, object], extension_value.get("report_claim_projection")
    )
    meaning_value = cast(
        Mapping[str, object], extension_value.get("meaning_evidence_bundle")
    )
    try:
        claim_records = claim_module._read_authenticated_report_claim_records(
            claim_projection
        )
    except (TypeError, ValueError):
        _reject()
    meaning_records_value = meaning_value.get("records")
    if type(meaning_records_value) is not list:
        _reject()
    meaning_records = render._validated_meaning_evidence_records(
        cast(list[Mapping[str, Any]], meaning_records_value)
    )
    claims = render._validated_report_claim_records(claim_records)
    required_statements = render._required_claim_statements(claims)
    raw_claim_ids = claim_value.get("ordered_proposed_claim_ids")
    expected_claim_ids = tuple(
        cast(str, record["predicate_id"]).replace("/", ":")
        for record in claims
        if record["state"] == "AVAILABLE" and record["value"] is True
    )
    if type(raw_claim_ids) is not list or tuple(raw_claim_ids) != expected_claim_ids:
        _reject()
    claim_ids = expected_claim_ids
    state_counts = {
        state: sum(record["state"] == state for record in meaning_records)
        for state in (
            "AVAILABLE",
            "UNAVAILABLE",
            "NOT_APPLICABLE",
            "INVALID",
            "FAILED",
        )
    }
    applicable_csv_bytes = _applicable_csv_bytes(
        report_claim_projection_sha256=cast(
            str, extension_value["report_claim_projection_sha256"]
        ),
        final_meaning_bundle_sha256=cast(
            str, extension_value["meaning_evidence_bundle_sha256"]
        ),
        meaning_records=meaning_records,
        ordered_warning_record_sha256=authority.ordered_warning_record_sha256,
        ordered_terminal_record_sha256=authority.ordered_terminal_record_sha256,
        ordered_claim_ids=claim_ids,
    )
    model: dict[str, object] = {
        "report_schema_version": "ebm-audit-cohort-report/1.0",
        "report_status": render.CURRENT_REPORT_STATUS,
        "input_declaration": "DECLARED_SYNTHETIC",
        "report_language_rule_id": REPORT_LANGUAGE_RULE_ID,
        "opening": MANDATORY_OPENING,
        "null_caveat": NULL_SAFE_FALLBACK,
        "science_completion_gate": {
            "status": "BLOCKED",
            "reason_codes": [_SCIENCE_GATE_REASON],
        },
        "cohort_sha256": authority.cohort_sha256,
        "benchmark_subject_digest": authority.benchmark_subject_digest,
        "proportional_operation_plan_sha256": (
            authority.proportional_operation_plan_sha256
        ),
        "meaning_evidence_graph_identity": copy.deepcopy(
            authority.evidence_graph_identity
        ),
        "report_claim_projection_sha256": extension_value[
            "report_claim_projection_sha256"
        ],
        "meaning_evidence_bundle_sha256": extension_value[
            "meaning_evidence_bundle_sha256"
        ],
        "meaning_evidence_extension_sha256": extension_value["extension_sha256"],
        "ordered_warning_record_sha256": list(
            authority.ordered_warning_record_sha256
        ),
        "ordered_public_terminal_result_sha256": list(
            authority.ordered_terminal_record_sha256
        ),
        "ordered_claim_ids": list(claim_ids),
        "report_predicates": list(claims),
        "required_claim_statements": list(required_statements),
        "meaning_evidence": list(meaning_records),
        "meaning_evidence_state_counts": state_counts,
        "artifact_contract": {
            "report_json_path": _REPORT_JSON_PATH,
            "applicable_csv_path": _APPLICABLE_CSV_PATH,
            "applicable_csv_sha256": exact_file_sha256(applicable_csv_bytes),
            "self_contained_html_path": _SELF_CONTAINED_HTML_PATH,
            "surface_verification_receipt_path": _SURFACE_RECEIPT_PATH,
            "manifest_emitted": False,
        },
    }
    if (
        claim_value.get("report_claim_projection_sha256")
        != model["report_claim_projection_sha256"]
        or meaning_value.get("bundle_sha256")
        != model["meaning_evidence_bundle_sha256"]
        or extension_value.get("evidence_graph_digest")
        != authority.cohort_sha256.removeprefix("sha256:")
    ):
        _reject()
    assert_no_direct_identifier_fields(model)
    try:
        validate_instance(
            model,
            "report.schema.json",
            definition="CohortReportSurface",
        )
    except SchemaValidationError:
        _reject()
    return model, applicable_csv_bytes


def _applicable_csv_bytes(
    *,
    report_claim_projection_sha256: str,
    final_meaning_bundle_sha256: str,
    meaning_records: Sequence[Mapping[str, Any]],
    ordered_warning_record_sha256: Sequence[str],
    ordered_terminal_record_sha256: Sequence[str],
    ordered_claim_ids: Sequence[str],
) -> bytes:
    records = render._validated_meaning_evidence_records(meaning_records)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    control = dict.fromkeys(_CSV_FIELDS, "")
    control.update(
        row_kind="CONTROL",
        report_claim_projection_sha256=_bare_sha256(
            report_claim_projection_sha256
        ),
        final_meaning_bundle_sha256=_bare_sha256(final_meaning_bundle_sha256),
        ordered_warning_record_sha256_json=canonical_json_bytes(
            [_bare_sha256(value) for value in ordered_warning_record_sha256]
        ).decode("utf-8"),
        ordered_terminal_record_sha256_json=canonical_json_bytes(
            [_bare_sha256(value) for value in ordered_terminal_record_sha256]
        ).decode("utf-8"),
        ordered_claim_ids_json=canonical_json_bytes(list(ordered_claim_ids)).decode(
            "utf-8"
        ),
    )
    writer.writerow(control)
    for record in records:
        row = dict.fromkeys(_CSV_FIELDS, "")
        row.update(
            row_kind="MEANING",
            ordinal=str(record["ordinal"]),
            meaning_id=cast(str, record["meaning_id"]),
            operation_group_id=cast(str, record["operation_group_id"]),
            state=cast(str, record["state"]),
            value_json=(
                canonical_json_bytes(record["value"]).decode("utf-8")
                if record["value"] is not None
                else ""
            ),
            reason_codes_json=canonical_json_bytes(record["reason_codes"]).decode(
                "utf-8"
            ),
            failure_code=cast(str, record["failure_code"] or ""),
            operation_ids_json=canonical_json_bytes(record["operation_ids"]).decode(
                "utf-8"
            ),
            output_schema_ref=cast(str, record["output_schema_ref"] or ""),
            derivation_id=cast(str, record["derivation_id"]),
            source_record_digests_json=canonical_json_bytes(
                record["source_record_digests"]
            ).decode("utf-8"),
        )
        writer.writerow(row)
    return stream.getvalue().encode("utf-8")


def _cohort_html_bytes(model: Mapping[str, object]) -> bytes:
    meaning_records = render._validated_meaning_evidence_records(
        cast(Sequence[Mapping[str, Any]], model["meaning_evidence"])
    )
    claims = render._validated_report_claim_records(
        cast(Sequence[Mapping[str, Any]], model["report_predicates"])
    )
    required_statements = cast(Sequence[str], model["required_claim_statements"])
    embedded = base64.b64encode(canonical_json_bytes(dict(model))).decode("ascii")
    meaning_rows = [
        (
            record["ordinal"],
            record["meaning_id"],
            record["state"],
            (
                canonical_json_bytes(record["value"]).decode("utf-8")
                if record["value"] is not None
                else ""
            ),
            " | ".join(cast(Sequence[str], record["reason_codes"])),
            record["failure_code"] or "",
        )
        for record in meaning_records
    ]
    claim_rows = [
        (
            record["predicate_id"],
            record["state"],
            "" if record["value"] is None else str(record["value"]),
        )
        for record in claims
    ]
    warning_rows = [
        (ordinal, digest)
        for ordinal, digest in enumerate(
            cast(Sequence[str], model["ordered_warning_record_sha256"])
        )
    ]
    terminal_rows = [
        (ordinal, digest)
        for ordinal, digest in enumerate(
            cast(Sequence[str], model["ordered_public_terminal_result_sha256"])
        )
    ]
    statements = "".join(
        f"<li>{html.escape(statement)}</li>" for statement in required_statements
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EBM Robustness Auditor cohort report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4;color:#171717}}
table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem}}
th,td{{border:1px solid #bbb;padding:.35rem;text-align:left;vertical-align:top}}
th{{background:#eee}}code{{overflow-wrap:anywhere}}.status{{font-weight:700}}
</style>
</head>
<body>
<h1>EBM Robustness Auditor cohort report</h1>
<p class="status">REPORT STATUS: {html.escape(cast(str, model['report_status']))}</p>
<p class="status">SCIENCE COMPLETION GATE: BLOCKED</p>
<p>{html.escape(cast(str, model['opening']))}</p>
<p>{html.escape(cast(str, model['null_caveat']))}</p>
<h2>Required claim statements</h2><ul>{statements}</ul>
<h2>Report predicates</h2>
{render._table(('Predicate', 'State', 'Value'), claim_rows)}
<h2>Ordered warning record digests</h2>
{render._table(('Ordinal', 'SHA-256'), warning_rows)}
<h2>Ordered public terminal result digests</h2>
{render._table(('Ordinal', 'SHA-256'), terminal_rows)}
<h2>Ordered meaning evidence</h2>
{render._table(('Ordinal', 'Meaning', 'State', 'Value', 'Reasons', 'Failure'), meaning_rows)}
{_HTML_PAYLOAD_START.decode('ascii')}{embedded}{_HTML_PAYLOAD_END.decode('ascii')}
</body>
</html>
"""
    encoded = document.encode("utf-8")
    render._validate_claim_directive_output(
        cast(Mapping[str, Any], model),
        encoded,
    )
    if b"https://" in encoded or b"http://" in encoded:
        _reject()
    return encoded


def _payload_observation(payload: Mapping[str, object]) -> _SurfaceObservation:
    meanings = payload.get("meaning_evidence")
    claims = payload.get("report_predicates")
    warnings = payload.get("ordered_warning_record_sha256")
    terminals = payload.get("ordered_public_terminal_result_sha256")
    claim_ids = payload.get("ordered_claim_ids")
    if (
        type(meanings) is not list
        or type(claims) is not list
        or type(warnings) is not list
        or type(terminals) is not list
        or type(claim_ids) is not list
    ):
        _reject()
    validated_claims = render._validated_report_claim_records(
        cast(list[Mapping[str, Any]], claims)
    )
    expected_claim_ids = [
        cast(str, record["predicate_id"]).replace("/", ":")
        for record in validated_claims
        if record["state"] == "AVAILABLE" and record["value"] is True
    ]
    if claim_ids != expected_claim_ids:
        _reject()
    return _surface_observation(
        report_claim_projection_sha256=cast(
            str, payload.get("report_claim_projection_sha256")
        ),
        final_meaning_bundle_sha256=cast(
            str, payload.get("meaning_evidence_bundle_sha256")
        ),
        meaning_records=cast(list[Mapping[str, Any]], meanings),
        ordered_warning_record_sha256=cast(list[str], warnings),
        ordered_terminal_record_sha256=cast(list[str], terminals),
        ordered_claim_ids=cast(list[str], claim_ids),
    )


def _json_observation(data: bytes) -> _SurfaceObservation:
    try:
        value = strict_json_loads(data)
    except (TypeError, ValueError):
        _reject()
    if type(value) is not dict or canonical_json_bytes(value) != data:
        _reject()
    try:
        validate_instance(
            value,
            "report.schema.json",
            definition="CohortReportSurface",
        )
    except SchemaValidationError:
        _reject()
    assert_no_direct_identifier_fields(value)
    return _payload_observation(cast(dict[str, object], value))


def _csv_observation(data: bytes) -> _SurfaceObservation:
    try:
        rows = list(csv.DictReader(io.StringIO(data.decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error):
        _reject()
    if len(rows) != 105 or tuple(rows[0]) != _CSV_FIELDS or rows[0]["row_kind"] != "CONTROL":
        _reject()
    control = rows[0]
    meanings: list[dict[str, object]] = []
    for expected_ordinal, row in enumerate(rows[1:], start=1):
        if (
            row["row_kind"] != "MEANING"
            or row["ordinal"] != str(expected_ordinal)
            or not row["meaning_id"]
            or not row["state"]
        ):
            _reject()
        try:
            value = (
                strict_json_loads(row["value_json"].encode("utf-8"))
                if row["value_json"]
                else None
            )
        except (TypeError, ValueError):
            _reject()
        meanings.append(
            {
                "meaning_id": row["meaning_id"],
                "state": row["state"],
                "value": value,
            }
        )
    try:
        warnings = strict_json_loads(
            control["ordered_warning_record_sha256_json"].encode("utf-8")
        )
        terminals = strict_json_loads(
            control["ordered_terminal_record_sha256_json"].encode("utf-8")
        )
        claim_ids = strict_json_loads(
            control["ordered_claim_ids_json"].encode("utf-8")
        )
    except (TypeError, ValueError):
        _reject()
    if type(warnings) is not list or type(terminals) is not list or type(claim_ids) is not list:
        _reject()
    return _SurfaceObservation(
        final_meaning_bundle_sha256=_bare_sha256(
            control["final_meaning_bundle_sha256"]
        ),
        report_claim_projection_sha256=_bare_sha256(
            control["report_claim_projection_sha256"]
        ),
        ordered_meaning_identity_state_value_sha256=structured_sha256_hex(
            _ORDERED_MEANING_DOMAIN,
            meanings,
        ),
        ordered_warning_record_sha256=structured_sha256_hex(
            _ORDERED_WARNING_DOMAIN,
            [_bare_sha256(value) for value in warnings],
        ),
        ordered_terminal_record_sha256=structured_sha256_hex(
            _ORDERED_TERMINAL_DOMAIN,
            [_bare_sha256(value) for value in terminals],
        ),
        ordered_claim_ids_sha256=structured_sha256_hex(
            _ORDERED_CLAIM_DOMAIN,
            cast(list[str], claim_ids),
        ),
    )


def _html_observation(data: bytes) -> _SurfaceObservation:
    if data.count(_HTML_PAYLOAD_START) != 1:
        _reject()
    start = data.index(_HTML_PAYLOAD_START) + len(_HTML_PAYLOAD_START)
    if data[start:].count(_HTML_PAYLOAD_END) != 1:
        _reject()
    end = data.index(_HTML_PAYLOAD_END, start)
    try:
        payload_bytes = base64.b64decode(data[start:end], validate=True)
        payload = strict_json_loads(payload_bytes)
    except (TypeError, ValueError):
        _reject()
    if type(payload) is not dict or canonical_json_bytes(payload) != payload_bytes:
        _reject()
    return _payload_observation(cast(dict[str, object], payload))


def _read_exact(path: Path, expected: bytes | None = None) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            _reject()
        data = path.read_bytes()
    except OSError:
        _reject()
    if expected is not None and data != expected:
        _reject()
    return data


def _write_exact(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        _reject()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            _reject()
        os.fsync(descriptor)
    except OSError:
        _reject()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _receipt_preimage(receipt: Mapping[str, object]) -> dict[str, object]:
    preimage = copy.deepcopy(dict(receipt))
    preimage["digest_state"] = "DIGEST_PREIMAGE"
    preimage["report_surface_verification_receipt_sha256"] = None
    return preimage


def _receipt(
    *,
    benchmark_subject_digest: str,
    observation: _SurfaceObservation,
    artifact_bytes: Sequence[bytes],
) -> dict[str, object]:
    if len(artifact_bytes) != 3:
        _reject()
    readbacks: list[dict[str, object]] = []
    for surface, path, data in zip(
        _SURFACE_NAMES,
        _SURFACE_PATHS,
        artifact_bytes,
        strict=True,
    ):
        readbacks.append(
            {
                "surface": surface,
                "artifact_relative_path": path,
                "artifact_byte_length": len(data),
                "artifact_sha256": exact_file_sha256(data).removeprefix("sha256:"),
                "observed_final_meaning_bundle_sha256": (
                    observation.final_meaning_bundle_sha256
                ),
                "observed_report_claim_projection_sha256": (
                    observation.report_claim_projection_sha256
                ),
                "observed_ordered_meaning_identity_state_value_sha256": (
                    observation.ordered_meaning_identity_state_value_sha256
                ),
                "observed_ordered_warning_record_sha256": (
                    observation.ordered_warning_record_sha256
                ),
                "observed_ordered_terminal_record_sha256": (
                    observation.ordered_terminal_record_sha256
                ),
                "observed_ordered_claim_ids_sha256": (
                    observation.ordered_claim_ids_sha256
                ),
            }
        )
    receipt: dict[str, object] = {
        "schema_version": "ebm-audit-report-surface-verification-receipt/1.0",
        "digest_state": "PERSISTED",
        "benchmark_subject_digest": _prefixed_sha256(benchmark_subject_digest),
        "report_claim_projection_sha256": (
            observation.report_claim_projection_sha256
        ),
        "final_meaning_bundle_sha256": observation.final_meaning_bundle_sha256,
        "ordered_meaning_identity_state_value_sha256": (
            observation.ordered_meaning_identity_state_value_sha256
        ),
        "ordered_warning_record_sha256": observation.ordered_warning_record_sha256,
        "ordered_terminal_record_sha256": observation.ordered_terminal_record_sha256,
        "ordered_claim_ids_sha256": observation.ordered_claim_ids_sha256,
        "ordered_artifact_readbacks": readbacks,
        "verified_meaning_count": 104,
        "meaning_identity_state_value_equal": True,
        "warnings_equal": True,
        "terminals_equal": True,
        "claims_equal": True,
        "render_pass_count": 1,
        "verification_state": "VERIFIED",
        "report_surface_verification_receipt_sha256": None,
    }
    receipt["report_surface_verification_receipt_sha256"] = structured_sha256_hex(
        _SURFACE_RECEIPT_DOMAIN,
        _receipt_preimage(receipt),
    )
    try:
        validate_instance(
            receipt,
            "evaluator-receipts.schema.json",
            definition="ReportSurfaceVerificationReceipt",
        )
    except SchemaValidationError:
        _reject()
    assert_no_direct_identifier_fields(receipt)
    return receipt


def _observe_surface(path: str, data: bytes) -> _SurfaceObservation:
    if path == _REPORT_JSON_PATH:
        return _json_observation(data)
    if path == _APPLICABLE_CSV_PATH:
        return _csv_observation(data)
    if path == _SELF_CONTAINED_HTML_PATH:
        return _html_observation(data)
    _reject()


def _verify_surface_set(
    root: Path,
    receipt: Mapping[str, object],
    *,
    expected_artifact_bytes: Sequence[bytes] | None = None,
) -> None:
    try:
        validate_instance(
            dict(receipt),
            "evaluator-receipts.schema.json",
            definition="ReportSurfaceVerificationReceipt",
        )
    except SchemaValidationError:
        _reject()
    digest = receipt.get("report_surface_verification_receipt_sha256")
    if (
        not _is_bare_sha256(digest)
        or structured_sha256_hex(
            _SURFACE_RECEIPT_DOMAIN,
            _receipt_preimage(receipt),
        )
        != digest
    ):
        _reject()
    rows = receipt.get("ordered_artifact_readbacks")
    if type(rows) is not list or len(rows) != 3:
        _reject()
    observations: list[_SurfaceObservation] = []
    for index, (path, surface, row) in enumerate(
        zip(_SURFACE_PATHS, _SURFACE_NAMES, rows, strict=True)
    ):
        if (
            type(row) is not dict
            or row.get("surface") != surface
            or row.get("artifact_relative_path") != path
        ):
            _reject()
        expected = None if expected_artifact_bytes is None else expected_artifact_bytes[index]
        data = _read_exact(root / path, expected)
        if (
            row.get("artifact_byte_length") != len(data)
            or row.get("artifact_sha256")
            != exact_file_sha256(data).removeprefix("sha256:")
        ):
            _reject()
        observation = _observe_surface(path, data)
        observations.append(observation)
        if any(
            row.get(field) != getattr(observation, field.removeprefix("observed_"))
            for field in (
                "observed_final_meaning_bundle_sha256",
                "observed_report_claim_projection_sha256",
                "observed_ordered_meaning_identity_state_value_sha256",
                "observed_ordered_warning_record_sha256",
                "observed_ordered_terminal_record_sha256",
                "observed_ordered_claim_ids_sha256",
            )
        ):
            _reject()
    if (
        len(set(observations)) != 1
        or observations[0].report_claim_projection_sha256
        != receipt.get("report_claim_projection_sha256")
        or observations[0].final_meaning_bundle_sha256
        != receipt.get("final_meaning_bundle_sha256")
        or observations[0].ordered_meaning_identity_state_value_sha256
        != receipt.get("ordered_meaning_identity_state_value_sha256")
        or observations[0].ordered_warning_record_sha256
        != receipt.get("ordered_warning_record_sha256")
        or observations[0].ordered_terminal_record_sha256
        != receipt.get("ordered_terminal_record_sha256")
        or observations[0].ordered_claim_ids_sha256
        != receipt.get("ordered_claim_ids_sha256")
    ):
        _reject()


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _validate_cohort_report_artifact_binding(
    owner: AuthenticatedReportModelArtifactBinding,
    *,
    extension: AuthenticatedMeaningEvidenceExtension,
    authority: _CohortAuthoritySnapshot,
    report_model: Mapping[str, object],
    report_json_bytes: bytes,
    report_html_bytes: bytes,
    receipt: Mapping[str, object],
) -> None:
    """Join one genuine artifact binding to the exact cohort report authority."""

    try:
        bound_model = binding_module._read_authenticated_report_model(owner)
        binding = binding_module._validated_binding_projection(owner)
        extension_value = bundle_module.read_authenticated_meaning_evidence_extension(
            extension
        )
    except (TypeError, ValueError):
        _reject()
    artifact_contract = report_model.get("artifact_contract")
    readbacks = receipt.get("ordered_artifact_readbacks")
    if type(artifact_contract) is not dict or type(readbacks) is not list:
        _reject()
    rows_by_path = {
        row.get("artifact_relative_path"): row
        for row in readbacks
        if type(row) is dict
    }
    report_row = rows_by_path.get(_REPORT_JSON_PATH)
    html_row = rows_by_path.get(_SELF_CONTAINED_HTML_PATH)
    expected_contract = {
        "report_json_path": _REPORT_JSON_PATH,
        "applicable_csv_path": _APPLICABLE_CSV_PATH,
        "self_contained_html_path": _SELF_CONTAINED_HTML_PATH,
        "surface_verification_receipt_path": _SURFACE_RECEIPT_PATH,
    }
    if (
        type(owner) is not AuthenticatedReportModelArtifactBinding
        or bound_model != dict(report_model)
        or canonical_json_bytes(bound_model) != report_json_bytes
        or binding.get("report_schema_version")
        != report_model.get("report_schema_version")
        or binding.get("report_artifact_sha256")
        != exact_file_sha256(report_json_bytes)
        or binding.get("report_html_artifact_sha256")
        != exact_file_sha256(report_html_bytes)
        or report_model.get("cohort_sha256") != authority.cohort_sha256
        or report_model.get("benchmark_subject_digest")
        != authority.benchmark_subject_digest
        or report_model.get("proportional_operation_plan_sha256")
        != authority.proportional_operation_plan_sha256
        or report_model.get("meaning_evidence_graph_identity")
        != authority.evidence_graph_identity
        or report_model.get("report_claim_projection_sha256")
        != extension_value.get("report_claim_projection_sha256")
        or report_model.get("meaning_evidence_bundle_sha256")
        != extension_value.get("meaning_evidence_bundle_sha256")
        or report_model.get("meaning_evidence_extension_sha256")
        != extension_value.get("extension_sha256")
        or extension_value.get("scientific_evidence_digest")
        != authority.cohort_sha256.removeprefix("sha256:")
        or extension_value.get("evidence_graph_identity")
        != authority.evidence_graph_identity
        or any(artifact_contract.get(key) != value for key, value in expected_contract.items())
        or len(rows_by_path) != len(_SURFACE_PATHS)
        or type(report_row) is not dict
        or type(html_row) is not dict
        or report_row.get("artifact_sha256")
        != exact_file_sha256(report_json_bytes).removeprefix("sha256:")
        or html_row.get("artifact_sha256")
        != exact_file_sha256(report_html_bytes).removeprefix("sha256:")
        or receipt.get("benchmark_subject_digest")
        != authority.benchmark_subject_digest
        or receipt.get("report_claim_projection_sha256")
        != extension_value.get("report_claim_projection_sha256")
        or receipt.get("final_meaning_bundle_sha256")
        != extension_value.get("meaning_evidence_bundle_sha256")
    ):
        _reject()


def write_cohort_report_surfaces(
    output_directory: Path,
    ephemeral_transaction_directory: Path,
    sealed_cohort: SealedScenarioCohortEvidence,
    claim_projection: AuthenticatedReportClaimProjection,
    meaning_bundle: MeaningEvidenceBundle,
    /,
) -> CohortReportSurfaceTransactionResult:
    """Render, read back, and atomically promote one cohort-native report set."""

    if not isinstance(output_directory, Path) or not isinstance(
        ephemeral_transaction_directory, Path
    ):
        _reject()
    output = output_directory.resolve(strict=False)
    ephemeral = ephemeral_transaction_directory.resolve(strict=False)
    if (
        output == output.parent
        or output.exists()
        or not ephemeral.is_dir()
        or _is_within(output, ephemeral)
        or _is_within(output.parent, ephemeral)
    ):
        _reject()
    authority = _read_cohort_authority(sealed_cohort, claim_projection, meaning_bundle)
    extension = _issue_one_cohort_extension(
        claim_projection,
        meaning_bundle,
        authority,
    )
    model, applicable_csv_bytes = _report_model(
        extension,
        authority,
        claim_projection,
    )
    report_json_bytes = canonical_json_bytes(model)
    self_contained_html_bytes = _cohort_html_bytes(model)
    artifact_bytes = (
        report_json_bytes,
        applicable_csv_bytes,
        self_contained_html_bytes,
    )
    expected_observation = _payload_observation(model)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.cohort-report-stage-", dir=output.parent)
    )
    if _is_within(staging, ephemeral):
        shutil.rmtree(staging)
        _reject()
    promoted = False
    try:
        for relative_path, data in zip(_SURFACE_PATHS, artifact_bytes, strict=True):
            _write_exact(staging / relative_path, data)
        staged_observations = tuple(
            _observe_surface(relative_path, _read_exact(staging / relative_path, data))
            for relative_path, data in zip(_SURFACE_PATHS, artifact_bytes, strict=True)
        )
        if any(observation != expected_observation for observation in staged_observations):
            _reject()
        receipt = _receipt(
            benchmark_subject_digest=authority.benchmark_subject_digest,
            observation=expected_observation,
            artifact_bytes=artifact_bytes,
        )
        receipt_bytes = canonical_json_bytes(receipt)
        _write_exact(staging / _SURFACE_RECEIPT_PATH, receipt_bytes)
        receipt_readback = _read_exact(staging / _SURFACE_RECEIPT_PATH, receipt_bytes)
        if strict_json_loads(receipt_readback) != receipt:
            _reject()
        _verify_surface_set(
            staging,
            receipt,
            expected_artifact_bytes=artifact_bytes,
        )
        _fsync_directory(staging / "report")
        _fsync_directory(staging)
        _fsync_directory(staging.parent)
        os.replace(staging, output)
        promoted = True
        _fsync_directory(output.parent)
        promoted_artifact_bytes = tuple(
            _read_exact(output / relative_path, expected)
            for relative_path, expected in zip(
                _SURFACE_PATHS,
                artifact_bytes,
                strict=True,
            )
        )
        promoted_receipt_bytes = _read_exact(
            output / _SURFACE_RECEIPT_PATH,
            receipt_bytes,
        )
        promoted_receipt = strict_json_loads(promoted_receipt_bytes)
        if type(promoted_receipt) is not dict:
            _reject()
        _verify_surface_set(
            output,
            cast(dict[str, object], promoted_receipt),
            expected_artifact_bytes=promoted_artifact_bytes,
        )
        report_binding = binding_module._issue_report_model_artifact_binding(
            cast(dict[str, Any], model),
            promoted_artifact_bytes[0],
            promoted_artifact_bytes[2],
        )
        _validate_cohort_report_artifact_binding(
            report_binding,
            extension=extension,
            authority=authority,
            report_model=model,
            report_json_bytes=promoted_artifact_bytes[0],
            report_html_bytes=promoted_artifact_bytes[2],
            receipt=cast(dict[str, object], promoted_receipt),
        )
    except BaseException:
        cleanup = output if promoted else staging
        shutil.rmtree(cleanup, ignore_errors=True)
        if output.parent.is_dir():
            _fsync_directory(output.parent)
        raise
    return CohortReportSurfaceTransactionResult(
        output_directory=output,
        authenticated_meaning_evidence_extension=extension,
        report_model_artifact_binding=report_binding,
        receipt=cast(
            Mapping[str, object],
            strict_json_loads(canonical_json_bytes(promoted_receipt)),
        ),
    )


def verify_cohort_report_surfaces(output_directory: Path, /) -> Mapping[str, object]:
    """Re-read an already promoted surface set and reject any byte or fact drift."""

    if not isinstance(output_directory, Path):
        _reject()
    root = output_directory.resolve(strict=False)
    try:
        receipt_bytes = _read_exact(root / _SURFACE_RECEIPT_PATH)
        receipt = strict_json_loads(receipt_bytes)
    except (TypeError, ValueError):
        _reject()
    if type(receipt) is not dict or canonical_json_bytes(receipt) != receipt_bytes:
        _reject()
    _verify_surface_set(root, cast(dict[str, object], receipt))
    return cast(
        Mapping[str, object],
        strict_json_loads(canonical_json_bytes(receipt)),
    )


def rerender_and_verify_cohort_report_surfaces(
    output_directory: Path,
    /,
) -> Mapping[str, object]:
    """Independently render and read back all three persisted report surfaces."""

    if not isinstance(output_directory, Path):
        _reject()
    root = output_directory.resolve(strict=False)
    verify_cohort_report_surfaces(root)
    report_json_bytes = _read_exact(root / _REPORT_JSON_PATH)
    try:
        model = strict_json_loads(report_json_bytes)
    except (TypeError, ValueError):
        _reject()
    if type(model) is not dict or canonical_json_bytes(model) != report_json_bytes:
        _reject()
    payload = cast(dict[str, object], model)
    meanings = payload.get("meaning_evidence")
    warnings = payload.get("ordered_warning_record_sha256")
    terminals = payload.get("ordered_public_terminal_result_sha256")
    claim_ids = payload.get("ordered_claim_ids")
    if (
        type(meanings) is not list
        or type(warnings) is not list
        or type(terminals) is not list
        or type(claim_ids) is not list
    ):
        _reject()
    rerendered = (
        report_json_bytes,
        _applicable_csv_bytes(
            report_claim_projection_sha256=cast(
                str,
                payload.get("report_claim_projection_sha256"),
            ),
            final_meaning_bundle_sha256=cast(
                str,
                payload.get("meaning_evidence_bundle_sha256"),
            ),
            meaning_records=cast(list[Mapping[str, Any]], meanings),
            ordered_warning_record_sha256=cast(list[str], warnings),
            ordered_terminal_record_sha256=cast(list[str], terminals),
            ordered_claim_ids=cast(list[str], claim_ids),
        ),
        _cohort_html_bytes(payload),
    )
    staging = Path(
        tempfile.mkdtemp(prefix=f".{root.name}.determinism-readback-", dir=root.parent)
    )
    try:
        observations: list[_SurfaceObservation] = []
        for relative_path, data in zip(_SURFACE_PATHS, rerendered, strict=True):
            _write_exact(staging / relative_path, data)
            observations.append(
                _observe_surface(
                    relative_path,
                    _read_exact(staging / relative_path, data),
                )
            )
        if len(set(observations)) != 1:
            _reject()
        original = tuple(_read_exact(root / path) for path in _SURFACE_PATHS)
        if original != rerendered:
            _reject()
        artifact_hashes = {
            path: exact_file_sha256(data).removeprefix("sha256:")
            for path, data in zip(_SURFACE_PATHS, rerendered, strict=True)
        }
        result: dict[str, object] = {
            "schema_version": "ebm-audit-cohort-report-determinism-readback/1.0",
            "render_pass_count": 2,
            "artifact_hashes": artifact_hashes,
            "determinism_readback_sha256": None,
        }
        result["determinism_readback_sha256"] = structured_sha256_hex(
            "ebm-audit/cohort-report-determinism-readback/1",
            {**result, "determinism_readback_sha256": None},
        )
        return result
    finally:
        shutil.rmtree(staging, ignore_errors=True)


__all__ = [
    "CohortReportSurfaceError",
    "CohortReportSurfaceTransactionResult",
    "rerender_and_verify_cohort_report_surfaces",
    "verify_cohort_report_surfaces",
    "write_cohort_report_surfaces",
]
