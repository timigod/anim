"""Source-scoped terminal evidence for declared null refits.

This layer records which null transformations reached which terminal states.
It deliberately does not calculate p-values, false-positive rates, calibration,
or a pooled null-relative classification.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Final, cast

from ebm_audit.protocol import canonical_json_bytes, strict_json_loads, structured_sha256

from ._evidence_records import _integrity, _ScientificRecordIntegrityError
from ._frozen_derivation import build_frozen_derivation_graph

NULL_EVIDENCE_RULE_ID: Final = "source-scoped-null-terminal-roster/1"
NULL_ATTEMPT_SCHEMA_VERSION: Final = "ebm-audit-null-terminal-attempt/1.0"
NULL_AGGREGATE_SCHEMA_VERSION: Final = "ebm-audit-null-family-aggregate/1.0"
NULL_LAYER_SCHEMA_VERSION: Final = "ebm-audit-null-layer-evidence/1.0"

_ATTEMPT_DOMAIN: Final = "ebm-audit/scientific-null-terminal-attempt/1"
_AGGREGATE_DOMAIN: Final = "ebm-audit/scientific-null-family-aggregate/1"
_LAYER_DOMAIN: Final = "ebm-audit/scientific-null-layer-evidence/1"

_TERMINAL_STATUSES: Final = (
    "SUCCESS",
    "CONVERGENCE_WARN",
    "INVALID_INPUT",
    "UNSUPPORTED_CAPABILITY",
    "INVALID_SPECIFICATION",
    "BACKEND_ERROR",
    "TIMEOUT",
    "CONVERGENCE_FAILED",
    "CONVERGENCE_NOT_ASSESSABLE",
    "PRIVACY_VIOLATION",
    "PROTOCOL_ERROR",
)
_NULL_METHODS: Final = (
    (
        "pure-no-signal-synthetic/1",
        "pure-no-signal-synthetic",
        False,
    ),
    (
        "label-permutation/1",
        "label-permutation",
        False,
    ),
    (
        "featurewise-within-group-participant-permutation/1",
        "featurewise-participant-permutation",
        True,
    ),
)


@dataclass(frozen=True, repr=False, slots=True)
class _CanonicalNullLayerEvidence:
    preimage_bytes: bytes
    canonical_bytes: bytes
    layer_digest: str


@dataclass(frozen=True, repr=False, slots=True)
class _NullCandidateInput:
    candidate_record_bytes: bytes
    universe_id: str | None
    operation_bytes: bytes


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _closed_record(value: bytes, *, code: str) -> dict[str, object]:
    if type(value) is not bytes:
        raise _integrity(code)
    decoded = strict_json_loads(value)
    if type(decoded) is not dict or canonical_json_bytes(decoded) != value:
        raise _integrity(code)
    return cast(dict[str, object], decoded)


def _candidate_identity(
    record: dict[str, object],
) -> tuple[int, str, str, str, str, str]:
    ordinal = record.get("candidate_ordinal")
    candidate_id = record.get("candidate_id")
    analysis_spec_id = record.get("analysis_spec_id")
    result_id = record.get("result_id")
    final_status = record.get("final_status")
    record_digest = record.get("record_digest")
    if (
        type(ordinal) is not int
        or ordinal < 0
        or type(candidate_id) is not str
        or type(analysis_spec_id) is not str
        or candidate_id != analysis_spec_id
        or type(result_id) is not str
        or final_status not in _TERMINAL_STATUSES
        or type(record_digest) is not str
    ):
        raise _integrity("SCIENCE.NULL_CANDIDATE_IDENTITY")
    return ordinal, candidate_id, analysis_spec_id, result_id, final_status, record_digest


def _status_counts(statuses: tuple[str, ...]) -> list[dict[str, object]]:
    counts = Counter(statuses)
    return [
        {"status": status, "count": counts[status]}
        for status in _TERMINAL_STATUSES
        if counts[status]
    ]


def _method_semantics(method_id: object) -> tuple[str, bool] | None:
    for current_method_id, transformation, preserves_marginals in _NULL_METHODS:
        if method_id == current_method_id:
            return transformation, preserves_marginals
    return None


def _attempt_sort_key(record: dict[str, object]) -> tuple[object, ...]:
    return (
        _utf8(cast(str, record["source_analysis_spec_id"])),
        _utf8(cast(str, record["source_variant_id"])),
        _utf8(cast(str, record["derived_source_variant_id"])),
        _utf8(cast(str, record["null_family_id"])),
        _utf8(cast(str, record["null_method_id"])),
        cast(int, record["replicate_ordinal"]),
        _utf8(cast(str, record["candidate_id"])),
    )


def _derive_attempt(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    subject: dict[str, object],
    source: dict[str, object],
    operation: dict[str, object],
    universe_id: str | None,
) -> dict[str, object]:
    (
        candidate_ordinal,
        candidate_id,
        analysis_spec_id,
        result_id,
        final_status,
        candidate_record_digest,
    ) = _candidate_identity(subject)
    (
        _source_ordinal,
        source_candidate_id,
        source_analysis_spec_id,
        source_result_id,
        source_final_status,
        source_candidate_record_digest,
    ) = _candidate_identity(source)
    method_id = operation.get("null_method_id")
    expected_method = _method_semantics(method_id)
    within_group_spec_id = operation.get("within_group_spec_id")
    if (
        operation.get("kind") != "null"
        or expected_method is None
        or operation.get("source_analysis_spec_id") != source_analysis_spec_id
        or operation.get("transformation") != expected_method[0]
        or operation.get("preserves_group_conditional_event_marginals") is not expected_method[1]
        or operation.get("refit_preprocessing") is not True
        or type(operation.get("source_variant_id")) is not str
        or type(operation.get("derived_source_variant_id")) is not str
        or type(operation.get("null_family_id")) is not str
        or type(operation.get("replicate_ordinal")) is not int
        or cast(int, operation["replicate_ordinal"]) < 0
        or (
            method_id == "featurewise-within-group-participant-permutation/1"
            and type(within_group_spec_id) is not str
        )
        or (
            method_id != "featurewise-within-group-participant-permutation/1"
            and within_group_spec_id is not None
        )
        or (universe_id is not None and type(universe_id) is not str)
        or (final_status in {"SUCCESS", "CONVERGENCE_WARN"} and type(universe_id) is not str)
    ):
        raise _integrity("SCIENCE.NULL_OPERATION_SEMANTICS")
    preimage: dict[str, object] = {
        "record_schema_version": NULL_ATTEMPT_SCHEMA_VERSION,
        "evidence_rule_id": NULL_EVIDENCE_RULE_ID,
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "candidate_ordinal": candidate_ordinal,
        "candidate_id": candidate_id,
        "analysis_spec_id": analysis_spec_id,
        "candidate_record_digest": candidate_record_digest,
        "result_id": result_id,
        "universe_id": universe_id,
        "final_status": final_status,
        "source_analysis_spec_id": source_analysis_spec_id,
        "source_candidate_id": source_candidate_id,
        "source_candidate_record_digest": source_candidate_record_digest,
        "source_result_id": source_result_id,
        "source_final_status": source_final_status,
        "source_variant_id": operation["source_variant_id"],
        "derived_source_variant_id": operation["derived_source_variant_id"],
        "null_family_id": operation["null_family_id"],
        "null_method_id": method_id,
        "transformation": operation["transformation"],
        "within_group_spec_id": within_group_spec_id,
        "replicate_ordinal": operation["replicate_ordinal"],
        "refit_preprocessing": True,
        "preserves_group_conditional_event_marginals": expected_method[1],
        "terminal_evidence_state": "TERMINAL_RETAINED",
        "calibration_eligible": False,
        "held_out_false_positive_rate_eligible": False,
        "strong_null_relative_language_eligible": False,
    }
    return {
        **preimage,
        "attempt_digest": structured_sha256(_ATTEMPT_DOMAIN, preimage),
    }


def _derive_aggregate(
    key: tuple[str, str, str, str, str],
    rows: tuple[dict[str, object], ...],
) -> dict[str, object]:
    statuses = tuple(cast(str, row["final_status"]) for row in rows)
    preimage: dict[str, object] = {
        "record_schema_version": NULL_AGGREGATE_SCHEMA_VERSION,
        "evidence_rule_id": NULL_EVIDENCE_RULE_ID,
        "source_analysis_spec_id": key[0],
        "source_variant_id": key[1],
        "derived_source_variant_id": key[2],
        "null_family_id": key[3],
        "null_method_id": key[4],
        "attempt_count": len(rows),
        "terminal_status_counts": _status_counts(statuses),
        "candidate_ids": [row["candidate_id"] for row in rows],
        "calibration_state": "UNCALIBRATED",
    }
    return {
        **preimage,
        "aggregate_digest": structured_sha256(_AGGREGATE_DOMAIN, preimage),
    }


def _component_coverage() -> list[dict[str, object]]:
    return [
        {
            "component": "LABEL_PERMUTATION_REFIT",
            "implementation_status": "IMPLEMENTED",
            "reason_code": None,
        },
        {
            "component": "WITHIN_GROUP_FEATURE_PERMUTATION_REFIT",
            "implementation_status": "IMPLEMENTED",
            "reason_code": None,
        },
        {
            "component": "PURE_NO_SIGNAL_SYNTHETIC",
            "implementation_status": "DEVELOPMENT_ONLY_SEPARATE_EVIDENCE",
            "reason_code": "NULL.PURE_NO_SIGNAL_DEVELOPMENT_ONLY",
        },
        {
            "component": "NULL_CALIBRATION_AND_HELD_OUT_FPR",
            "implementation_status": "PENDING_IMPLEMENTATION",
            "reason_code": "NULL_CALIBRATION_NOT_VALIDATED",
        },
    ]


def _validate_status_counts(value: object, statuses: tuple[str, ...], *, code: str) -> None:
    if value != _status_counts(statuses):
        raise _integrity(code)


def _validate_null_semantics(layer: dict[str, object]) -> None:
    try:
        preimage = dict(layer)
        supplied_layer_digest = preimage.pop("layer_digest", None)
        attempts = layer.get("attempts")
        aggregates = layer.get("aggregates")
        if (
            set(layer)
            != {
                "layer_schema_version",
                "evidence_rule_id",
                "uncertainty_layer",
                "pooling_policy",
                "plan_digest",
                "terminal_index_digest",
                "component_coverage",
                "attempt_count",
                "family_count",
                "terminal_status_counts",
                "attempts",
                "aggregates",
                "calibration_state",
                "null_relative_label",
                "held_out_false_positive_rate_eligible",
                "strong_null_relative_language_eligible",
                "classification_status",
                "layer_digest",
            }
            or layer.get("layer_schema_version") != NULL_LAYER_SCHEMA_VERSION
            or layer.get("evidence_rule_id") != NULL_EVIDENCE_RULE_ID
            or layer.get("uncertainty_layer") != "NULL"
            or layer.get("pooling_policy") != "NON_POOLABLE"
            or type(layer.get("plan_digest")) is not str
            or type(layer.get("terminal_index_digest")) is not str
            or layer.get("component_coverage") != _component_coverage()
            or type(attempts) is not list
            or type(aggregates) is not list
            or layer.get("attempt_count") != len(attempts)
            or layer.get("family_count") != len(aggregates)
            or layer.get("calibration_state") != "UNCALIBRATED"
            or layer.get("null_relative_label") != "NULL_CALIBRATION_NOT_VALIDATED"
            or layer.get("held_out_false_positive_rate_eligible") is not False
            or layer.get("strong_null_relative_language_eligible") is not False
            or layer.get("classification_status") != "NO_FROZEN_NULL_CLASSIFICATION"
            or supplied_layer_digest != structured_sha256(_LAYER_DOMAIN, preimage)
        ):
            raise _integrity("SCIENCE.NULL_LAYER_SEMANTICS")
        exact_attempts = cast(list[dict[str, object]], attempts)
        if any(type(row) is not dict for row in exact_attempts) or exact_attempts != sorted(
            exact_attempts,
            key=_attempt_sort_key,
        ):
            raise _integrity("SCIENCE.NULL_ATTEMPT_ORDER")
        identities: set[tuple[object, ...]] = set()
        aggregate_sources: dict[
            tuple[str, str, str, str, str],
            list[dict[str, object]],
        ] = {}
        for row in exact_attempts:
            attempt_preimage = dict(row)
            supplied = attempt_preimage.pop("attempt_digest", None)
            identity = (
                row.get("source_analysis_spec_id"),
                row.get("source_variant_id"),
                row.get("derived_source_variant_id"),
                row.get("null_family_id"),
                row.get("null_method_id"),
                row.get("replicate_ordinal"),
                row.get("candidate_id"),
            )
            if (
                row.get("record_schema_version") != NULL_ATTEMPT_SCHEMA_VERSION
                or row.get("evidence_rule_id") != NULL_EVIDENCE_RULE_ID
                or row.get("plan_digest") != layer["plan_digest"]
                or row.get("terminal_index_digest") != layer["terminal_index_digest"]
                or row.get("final_status") not in _TERMINAL_STATUSES
                or row.get("source_final_status") not in _TERMINAL_STATUSES
                or row.get("terminal_evidence_state") != "TERMINAL_RETAINED"
                or row.get("calibration_eligible") is not False
                or row.get("held_out_false_positive_rate_eligible") is not False
                or row.get("strong_null_relative_language_eligible") is not False
                or any(value is None for value in identity)
                or identity in identities
                or supplied != structured_sha256(_ATTEMPT_DOMAIN, attempt_preimage)
            ):
                raise _integrity("SCIENCE.NULL_ATTEMPT_SEMANTICS")
            identities.add(identity)
            aggregate_key = cast(
                tuple[str, str, str, str, str],
                identity[:5],
            )
            aggregate_sources.setdefault(aggregate_key, []).append(row)
        expected_aggregates = [
            _derive_aggregate(
                key,
                tuple(sorted(rows, key=_attempt_sort_key)),
            )
            for key, rows in sorted(
                aggregate_sources.items(),
                key=lambda item: tuple(_utf8(value) for value in item[0]),
            )
        ]
        if aggregates != expected_aggregates:
            raise _integrity("SCIENCE.NULL_AGGREGATE_SEMANTICS")
        _validate_status_counts(
            layer.get("terminal_status_counts"),
            tuple(cast(str, row["final_status"]) for row in exact_attempts),
            code="SCIENCE.NULL_STATUS_COUNTS",
        )
    except _ScientificRecordIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError):
        raise _integrity("SCIENCE.NULL_LAYER_SEMANTICS") from None


def _derive_null_evidence(
    *,
    plan_digest: str,
    terminal_index_digest: str,
    candidates: tuple[_NullCandidateInput, ...],
) -> _CanonicalNullLayerEvidence:
    """Derive a source-scoped roster from exact sealed candidate terminals."""

    if type(plan_digest) is not str or type(terminal_index_digest) is not str or not candidates:
        raise _integrity("SCIENCE.NULL_RUN_IDENTITY")
    decoded: list[tuple[_NullCandidateInput, dict[str, object], dict[str, object]]] = []
    for expected_ordinal, candidate in enumerate(candidates):
        if type(candidate) is not _NullCandidateInput:
            raise _integrity("SCIENCE.NULL_CANDIDATE_INPUT")
        record = _closed_record(
            candidate.candidate_record_bytes,
            code="SCIENCE.NULL_CANDIDATE_BYTES",
        )
        operation = _closed_record(
            candidate.operation_bytes,
            code="SCIENCE.NULL_OPERATION_BYTES",
        )
        if _candidate_identity(record)[0] != expected_ordinal:
            raise _integrity("SCIENCE.NULL_CANDIDATE_INPUT")
        decoded.append((candidate, record, operation))
    by_analysis = {
        cast(str, record["analysis_spec_id"]): (candidate, record, operation)
        for candidate, record, operation in decoded
    }
    if len(by_analysis) != len(decoded):
        raise _integrity("SCIENCE.NULL_CANDIDATE_IDENTITY")

    attempts: list[dict[str, object]] = []
    for subject_input, subject, operation in decoded:
        if operation.get("kind") != "null":
            continue
        source_id = operation.get("source_analysis_spec_id")
        source_entry = by_analysis.get(cast(str, source_id))
        if source_entry is None or source_entry[2].get("kind") != "ordinary":
            raise _integrity("SCIENCE.NULL_SOURCE_NOT_ORDINARY")
        attempts.append(
            _derive_attempt(
                plan_digest=plan_digest,
                terminal_index_digest=terminal_index_digest,
                subject=subject,
                source=source_entry[1],
                operation=operation,
                universe_id=subject_input.universe_id,
            )
        )
    attempts.sort(key=_attempt_sort_key)
    aggregate_sources: dict[
        tuple[str, str, str, str, str],
        list[dict[str, object]],
    ] = {}
    for attempt in attempts:
        key = (
            cast(str, attempt["source_analysis_spec_id"]),
            cast(str, attempt["source_variant_id"]),
            cast(str, attempt["derived_source_variant_id"]),
            cast(str, attempt["null_family_id"]),
            cast(str, attempt["null_method_id"]),
        )
        aggregate_sources.setdefault(key, []).append(attempt)
    aggregates = [
        _derive_aggregate(key, tuple(rows))
        for key, rows in sorted(
            aggregate_sources.items(),
            key=lambda item: tuple(_utf8(value) for value in item[0]),
        )
    ]
    preimage: dict[str, object] = {
        "layer_schema_version": NULL_LAYER_SCHEMA_VERSION,
        "evidence_rule_id": NULL_EVIDENCE_RULE_ID,
        "uncertainty_layer": "NULL",
        "pooling_policy": "NON_POOLABLE",
        "plan_digest": plan_digest,
        "terminal_index_digest": terminal_index_digest,
        "component_coverage": _component_coverage(),
        "attempt_count": len(attempts),
        "family_count": len(aggregates),
        "terminal_status_counts": _status_counts(
            tuple(cast(str, row["final_status"]) for row in attempts)
        ),
        "attempts": attempts,
        "aggregates": aggregates,
        "calibration_state": "UNCALIBRATED",
        "null_relative_label": "NULL_CALIBRATION_NOT_VALIDATED",
        "held_out_false_positive_rate_eligible": False,
        "strong_null_relative_language_eligible": False,
        "classification_status": "NO_FROZEN_NULL_CLASSIFICATION",
    }
    layer_digest = structured_sha256(_LAYER_DOMAIN, preimage)
    layer = _CanonicalNullLayerEvidence(
        preimage_bytes=canonical_json_bytes(preimage),
        canonical_bytes=canonical_json_bytes({**preimage, "layer_digest": layer_digest}),
        layer_digest=layer_digest,
    )
    decoded_layer = strict_json_loads(layer.canonical_bytes)
    if type(decoded_layer) is not dict:
        raise _integrity("SCIENCE.NULL_LAYER_SHAPE")
    _validate_null_semantics(cast(dict[str, object], decoded_layer))
    return layer


_NULL_DERIVATION = build_frozen_derivation_graph(
    globals(),
    module_name=__name__,
    root_names=(
        "_derive_null_evidence",
        "_validate_null_semantics",
    ),
    record_type_names=(
        "_CanonicalNullLayerEvidence",
        "_NullCandidateInput",
    ),
)
for _function_name, _frozen_function in _NULL_DERIVATION.functions.items():
    globals()[_function_name] = _frozen_function
for _record_type_name, _frozen_record_type in _NULL_DERIVATION.record_types.items():
    globals()[_record_type_name] = _frozen_record_type
del _function_name
del _frozen_function
del _record_type_name
del _frozen_record_type
del build_frozen_derivation_graph


__all__: list[str] = []
