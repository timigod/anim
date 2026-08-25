"""Authenticate the complete development candidate-source graph.

The receipt in this module is deliberately not evaluator evidence.  It keeps
one observed run and fifty-nine independently generated pure-no-signal runs
alive in-process, revalidates every retained result/science owner on every
projection, and emits only deterministic privacy-safe development metadata.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.results import SealedResultEvidenceSet, project_terminal_ledgers
from ebm_audit.results.finalization import (
    _capture_finalized_result_state,
    _PreparedFinalizationOwner,
    _resolve_attempt,
    _resolve_fit_groups,
)
from ebm_audit.results.persistence import _sealed_result_evidence_run
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science import SealedScientificEvidence, project_scientific_evidence
from ebm_audit.universe.identities import analysis_spec_content_id

from .development_null import (
    SealedDevelopmentNullScienceReceipt,
    _read_development_null_science_receipt_state,
    project_development_null_science_receipt,
)

_REPLICATE_COUNT: Final = 59
_OBSERVED_CANDIDATE_COUNT: Final = 1 + (2 * _REPLICATE_COUNT)
_TOTAL_CANDIDATE_COUNT: Final = _OBSERVED_CANDIDATE_COUNT + _REPLICATE_COUNT
_CHAIN_COUNT: Final = 3
_TOTAL_CHAIN_COUNT: Final = _TOTAL_CANDIDATE_COUNT * _CHAIN_COUNT
_PIPELINE_DOMAIN: Final = "ebm-audit/development-candidate-pipeline-spec/1"
_RECORD_DOMAIN: Final = "ebm-audit/development-candidate-fit-source-record/1"
_CHILD_DOMAIN: Final = "ebm-audit/development-candidate-child-owner-binding/1"
_RECEIPT_DOMAIN: Final = "ebm-audit/development-candidate-source-receipt/1"
_SCHEMA_NAME: Final = "development-candidate-source-receipt.schema.json"
_PIPELINE_KEYS: Final = (
    "spec_schema_version",
    "cohort_rule",
    "event_set",
    "event_directions",
    "preprocessing",
    "outlier_policy",
    "missingness_policy",
    "covariate_adjustment",
    "backend",
    "mcmc",
)
_ANALYSIS_SPEC_KEYS: Final = frozenset(
    (*_PIPELINE_KEYS, "dataset_variant_intent", "operation_intent")
)
_CONVERGENCE_BY_STATUS: Final = {
    "SUCCESS": "CONVERGENCE_PASS",
    "CONVERGENCE_WARN": "CONVERGENCE_WARN",
    "CONVERGENCE_FAILED": "CONVERGENCE_FAIL",
    "CONVERGENCE_NOT_ASSESSABLE": "CONVERGENCE_NOT_ASSESSABLE",
}
_FIT_SUCCESS_STATUSES: Final = frozenset(_CONVERGENCE_BY_STATUS)
_EXPECTED_NULL_SLOTS: Final = tuple(
    (family, replicate_index)
    for family in (
        "pure_no_signal",
        "label_permutation_null",
        "within_group_feature_permutation_null",
    )
    for replicate_index in range(_REPLICATE_COUNT)
)


def _invalid() -> TypeError:
    return TypeError("Development candidate-source evidence failed exact owner validation.")


def _clone_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _invalid()
    try:
        cloned = strict_json_loads(canonical_json_bytes(dict(value)))
    except (TypeError, ValueError):
        raise _invalid() from None
    if type(cloned) is not dict:
        raise _invalid()
    return cast(dict[str, Any], cloned)


def _digest(value: object) -> str:
    if (
        type(value) is not str
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise _invalid()
    return value


@dataclass(frozen=True, slots=True, repr=False)
class _CandidateSourceView:
    candidate: dict[str, Any]
    terminal: dict[str, Any]
    result_record: dict[str, Any]
    scientific_record: dict[str, Any]
    refit_execution_digest: str
    retained_validation_evidence_count: int
    retained_fit_attempt_count: int
    retained_chain_count: int


@dataclass(frozen=True, slots=True, repr=False)
class _ChildOwnerView:
    owner_identity: object
    result_evidence_identity: object
    owner_kind: str
    child_owner_ordinal: int
    pure_replicate_index: int | None
    plan_digest: str
    preparation_receipt_digest: str
    terminal_index_digest: str
    scientific_evidence_digest: str
    pure_source_receipt_digest: str | None
    candidates: tuple[_CandidateSourceView, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _CandidateMaterial:
    child: _ChildOwnerView
    source: _CandidateSourceView
    semantic_slot: dict[str, Any]
    pipeline_spec: dict[str, Any]
    pipeline_spec_digest: str


def _pipeline_spec(analysis_spec: object) -> tuple[dict[str, Any], str]:
    if not isinstance(analysis_spec, Mapping) or set(analysis_spec) != _ANALYSIS_SPEC_KEYS:
        raise _invalid()
    exact = _clone_mapping(analysis_spec)
    try:
        validate_instance(
            exact,
            "analysis-universe.schema.json",
            definition="AnalysisSpec",
        )
    except SchemaValidationError:
        raise _invalid() from None
    pipeline = {key: copy.deepcopy(exact[key]) for key in _PIPELINE_KEYS}
    try:
        validate_instance(
            pipeline,
            _SCHEMA_NAME,
            definition="DevelopmentCandidatePipelineSpec",
        )
    except SchemaValidationError:
        raise _invalid() from None
    return pipeline, structured_sha256(_PIPELINE_DOMAIN, pipeline)


def _semantic_slot(
    child: _ChildOwnerView,
    analysis_spec: Mapping[str, Any],
) -> dict[str, Any]:
    operation = analysis_spec.get("operation_intent")
    variant = analysis_spec.get("dataset_variant_intent")
    if not isinstance(operation, Mapping) or not isinstance(variant, Mapping):
        raise _invalid()
    kind = operation.get("kind")
    exact_baseline_variant = (
        set(variant)
        == {
            "source_variant_id",
            "variant_kind",
            "source_variant_id_ref",
            "method_id",
        }
        and type(variant.get("source_variant_id")) is str
        and variant.get("variant_kind") == "baseline-input"
        and variant.get("source_variant_id_ref") is None
        and variant.get("method_id") == "exact-input-bytes/1"
    )
    if child.owner_kind == "OBSERVED_SOURCE":
        if dict(operation) == {"kind": "ordinary"}:
            if not exact_baseline_variant:
                raise _invalid()
            return {
                "slot_kind": "OBSERVED",
                "null_family_id": None,
                "replicate_index": None,
            }
        if kind != "null":
            raise _invalid()
        method = operation.get("null_method_id")
        if type(method) is not str:
            raise _invalid()
        if method == "label-permutation/1":
            family = "label_permutation_null"
            exact_method_semantics = (
                operation.get("null_family_id") == "label-permutation"
                and operation.get("transformation") == "label-permutation"
                and operation.get("within_group_spec_id") is None
                and operation.get("refit_preprocessing") is True
                and operation.get("preserves_group_conditional_event_marginals") is False
            )
        elif method == "featurewise-within-group-participant-permutation/1":
            family = "within_group_feature_permutation_null"
            exact_method_semantics = (
                operation.get("null_family_id") == "featurewise-within-group-permutation"
                and operation.get("transformation") == "featurewise-participant-permutation"
                and type(operation.get("within_group_spec_id")) is str
                and operation.get("refit_preprocessing") is True
                and operation.get("preserves_group_conditional_event_marginals") is True
            )
        else:
            family = None
            exact_method_semantics = False
        replicate_index = operation.get("replicate_ordinal")
        if (
            family is None
            or not exact_method_semantics
            or type(replicate_index) is not int
            or replicate_index < 0
            or replicate_index >= _REPLICATE_COUNT
        ):
            raise _invalid()
        return {
            "slot_kind": "NULL",
            "null_family_id": family,
            "replicate_index": replicate_index,
        }
    if child.owner_kind != "PURE_NO_SIGNAL_SOURCE":
        raise _invalid()
    if (
        dict(operation) != {"kind": "ordinary"}
        or not exact_baseline_variant
        or child.pure_replicate_index is None
    ):
        raise _invalid()
    return {
        "slot_kind": "NULL",
        "null_family_id": "pure_no_signal",
        "replicate_index": child.pure_replicate_index,
    }


def _attempt_rows(
    result_body: Mapping[str, Any],
    source: _CandidateSourceView,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    validation = result_body.get("validation_evidence")
    fit_attempts = result_body.get("fit_attempt_evidence")
    if (
        not isinstance(validation, Mapping)
        or type(fit_attempts) is not list
        or source.retained_validation_evidence_count != 1
        or source.retained_fit_attempt_count != len(fit_attempts)
    ):
        raise _invalid()
    exact_validation = _clone_mapping(validation)
    exact_fit = [_clone_mapping(row) for row in fit_attempts]
    if (
        exact_validation.get("command") != "validate"
        or exact_validation.get("chain_plan_position") is not None
        or exact_validation.get("attempt_id") is not None
        or exact_validation.get("attempt_ordinal") is not None
        or source.retained_chain_count != _CHAIN_COUNT
    ):
        raise _invalid()
    if exact_validation.get("status") != "SUCCESS":
        if exact_fit:
            raise _invalid()
        return exact_validation, exact_fit
    cursor = 0
    chain_execution_ids: list[str] = []
    for chain_position in range(_CHAIN_COUNT):
        if cursor >= len(exact_fit):
            raise _invalid()
        initial = exact_fit[cursor]
        if (
            initial.get("command") != "fit"
            or initial.get("chain_plan_position") != chain_position
            or initial.get("attempt_ordinal") != 0
            or type(initial.get("attempt_id")) is not str
            or type(initial.get("chain_execution_id")) is not str
        ):
            raise _invalid()
        chain_execution_id = cast(str, initial["chain_execution_id"])
        chain_execution_ids.append(chain_execution_id)
        cursor += 1
        if (
            cursor < len(exact_fit)
            and exact_fit[cursor].get("chain_plan_position") == chain_position
        ):
            retry = exact_fit[cursor]
            if (
                retry.get("command") != "fit"
                or retry.get("attempt_ordinal") != 1
                or retry.get("chain_execution_id") != chain_execution_id
                or type(retry.get("attempt_id")) is not str
                or retry.get("attempt_id") == initial["attempt_id"]
            ):
                raise _invalid()
            cursor += 1
    if cursor != len(exact_fit) or len(set(chain_execution_ids)) != _CHAIN_COUNT:
        raise _invalid()
    return exact_validation, exact_fit


def _convergence_and_metrics(
    scientific_record: Mapping[str, Any],
    *,
    terminal_status: str,
) -> tuple[str, str, bool, float | None, float | None]:
    convergence_binding = scientific_record.get("convergence_record_binding")
    within_fit = scientific_record.get("within_fit")
    if not isinstance(convergence_binding, Mapping) or not isinstance(within_fit, Mapping):
        raise _invalid()
    observed_assessment = convergence_binding.get("assessment")
    expected_assessment = _CONVERGENCE_BY_STATUS.get(terminal_status)
    if expected_assessment is None:
        if observed_assessment is not None:
            raise _invalid()
        convergence_state = "CONVERGENCE_NOT_ASSESSABLE"
    else:
        if observed_assessment != expected_assessment:
            raise _invalid()
        convergence_state = expected_assessment
    fit_state = "SUCCESS" if terminal_status in _FIT_SUCCESS_STATUSES else "FAILURE"
    hard_failure = fit_state == "FAILURE"

    def scalar(field: str) -> float | None:
        value = within_fit.get(field)
        if not isinstance(value, Mapping):
            raise _invalid()
        status = value.get("status")
        numeric = value.get("value")
        if status != "ASSESSABLE":
            if numeric is not None:
                raise _invalid()
            return None
        if type(numeric) not in {int, float}:
            raise _invalid()
        result = float(cast(int | float, numeric))
        if not math.isfinite(result):
            raise _invalid()
        return result

    position = scalar("position_concentration")
    pairwise = scalar("pairwise_concentration")
    if hard_failure and (position is not None or pairwise is not None):
        raise _invalid()
    return convergence_state, fit_state, hard_failure, position, pairwise


def _candidate_material(child: _ChildOwnerView, source: _CandidateSourceView) -> _CandidateMaterial:
    candidate = source.candidate
    terminal = source.terminal
    result_record = source.result_record
    scientific = source.scientific_record
    analysis_spec = candidate.get("analysis_spec")
    pipeline, pipeline_digest = _pipeline_spec(analysis_spec)
    if not isinstance(analysis_spec, Mapping):
        raise _invalid()
    mcmc = pipeline.get("mcmc")
    if not isinstance(mcmc, Mapping) or mcmc.get("chain_count") != _CHAIN_COUNT:
        raise _invalid()
    slot = _semantic_slot(child, analysis_spec)

    body = result_record.get("body")
    result_id = result_record.get("result_id")
    if not isinstance(body, Mapping):
        raise _invalid()
    if set(result_record) != {"result_schema_version", "body", "result_id"}:
        raise _invalid()
    candidate_ordinal = candidate.get("candidate_ordinal")
    candidate_id = candidate.get("candidate_id")
    analysis_spec_id = candidate.get("analysis_spec_id")
    identity = (
        candidate_ordinal,
        candidate_id,
        analysis_spec_id,
    )
    if (
        type(candidate_ordinal) is not int
        or candidate_ordinal < 0
        or _digest(candidate_id) != _digest(analysis_spec_id)
        or analysis_spec_content_id(analysis_spec) != analysis_spec_id
        or identity
        != (
            terminal.get("candidate_ordinal"),
            terminal.get("candidate_id"),
            terminal.get("analysis_spec_id"),
        )
        or identity
        != (
            body.get("candidate_ordinal"),
            body.get("candidate_id"),
            body.get("analysis_spec_id"),
        )
        or identity
        != (
            scientific.get("candidate_ordinal"),
            scientific.get("candidate_id"),
            scientific.get("analysis_spec_id"),
        )
        or body.get("plan_digest") != child.plan_digest
        or terminal.get("result_id") != result_id
        or scientific.get("result_id") != result_id
        or result_id is None
        or terminal.get("final_status") != body.get("status")
        or scientific.get("final_status") != body.get("status")
        or terminal.get("universe_id") != body.get("universe_id")
        or body.get("universe_id") is None
        or scientific.get("planned_chain_count") != _CHAIN_COUNT
        or source.retained_chain_count != _CHAIN_COUNT
    ):
        raise _invalid()
    _digest(result_id)
    if result_id != structured_sha256(
        "ebm-audit/result-record/2",
        {
            "result_schema_version": result_record["result_schema_version"],
            "body": dict(body),
        },
    ):
        raise _invalid()
    _digest(body["universe_id"])
    expected_result_digest = exact_file_sha256(canonical_json_bytes(result_record))
    if terminal.get("result_digest") != expected_result_digest:
        raise _invalid()
    scientific_preimage = _clone_mapping(scientific)
    scientific_digest = scientific_preimage.pop("record_digest", None)
    if scientific_digest != structured_sha256(
        "ebm-audit/scientific-candidate-evidence/1",
        scientific_preimage,
    ):
        raise _invalid()
    _digest(source.refit_execution_digest)
    return _CandidateMaterial(
        child=child,
        source=source,
        semantic_slot=slot,
        pipeline_spec=pipeline,
        pipeline_spec_digest=pipeline_digest,
    )


def _source_record(
    material: _CandidateMaterial,
    *,
    canonical_candidate_ordinal: int,
    common_pipeline_digest: str,
) -> dict[str, Any]:
    source = material.source
    child = material.child
    candidate = source.candidate
    terminal = source.terminal
    result = source.result_record
    science = source.scientific_record
    body = cast(Mapping[str, Any], result["body"])
    validation, fit_attempts = _attempt_rows(body, source)
    terminal_status = body.get("status")
    if type(terminal_status) is not str:
        raise _invalid()
    convergence, fit_state, hard_failure, position, pairwise = _convergence_and_metrics(
        science,
        terminal_status=terminal_status,
    )
    if material.pipeline_spec_digest != common_pipeline_digest:
        raise _invalid()
    preimage: dict[str, Any] = {
        "record_schema_version": "ebm-audit-development-candidate-fit-source-record/1.0",
        "canonical_candidate_ordinal": canonical_candidate_ordinal,
        "semantic_slot": copy.deepcopy(material.semantic_slot),
        "child_owner_ordinal": child.child_owner_ordinal,
        "source_candidate_ordinal": candidate["candidate_ordinal"],
        "plan_digest": child.plan_digest,
        "preparation_receipt_digest": child.preparation_receipt_digest,
        "terminal_index_digest": child.terminal_index_digest,
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "universe_id": body["universe_id"],
        "result_id": result["result_id"],
        "result_digest": terminal["result_digest"],
        "scientific_candidate_record_digest": science["record_digest"],
        "planned_chain_count": _CHAIN_COUNT,
        "pipeline_spec_digest": common_pipeline_digest,
        "refit_execution_digest": source.refit_execution_digest,
        "validation_evidence": validation,
        "fit_attempt_evidence": fit_attempts,
        "terminal_status": terminal_status,
        "convergence_state": convergence,
        "fit_state": fit_state,
        "hard_failure": hard_failure,
        "position_concentration": position,
        "pairwise_concentration": pairwise,
    }
    record = {
        **preimage,
        "record_digest": structured_sha256(_RECORD_DOMAIN, preimage),
    }
    try:
        validate_instance(
            record,
            _SCHEMA_NAME,
            definition="DevelopmentCandidateFitSourceRecord",
        )
    except SchemaValidationError:
        raise _invalid() from None
    return record


def _child_binding(
    child: _ChildOwnerView,
    records: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    preimage: dict[str, Any] = {
        "binding_schema_version": ("ebm-audit-development-candidate-child-owner-binding/1.0"),
        "owner_kind": child.owner_kind,
        "child_owner_ordinal": child.child_owner_ordinal,
        "pure_replicate_index": child.pure_replicate_index,
        "plan_digest": child.plan_digest,
        "preparation_receipt_digest": child.preparation_receipt_digest,
        "terminal_index_digest": child.terminal_index_digest,
        "scientific_evidence_digest": child.scientific_evidence_digest,
        "pure_source_receipt_digest": child.pure_source_receipt_digest,
        "ordered_candidate_record_digests": [record["record_digest"] for record in records],
        "candidate_count": len(records),
        "planned_chain_count": sum(record["planned_chain_count"] for record in records),
    }
    return {
        **preimage,
        "binding_digest": structured_sha256(_CHILD_DOMAIN, preimage),
    }


def _derive_projection_from_owner_views(
    observed: _ChildOwnerView,
    pure: tuple[_ChildOwnerView, ...],
) -> dict[str, Any]:
    """Internal deterministic seam; public issuance never accepts these views."""

    if (
        type(observed) is not _ChildOwnerView
        or type(pure) is not tuple
        or len(pure) != _REPLICATE_COUNT
        or any(type(child) is not _ChildOwnerView for child in pure)
        or observed.owner_kind != "OBSERVED_SOURCE"
        or observed.child_owner_ordinal != 0
        or observed.pure_replicate_index is not None
        or observed.pure_source_receipt_digest is not None
        or len(observed.candidates) != _OBSERVED_CANDIDATE_COUNT
    ):
        raise _invalid()
    children = (observed, *pure)
    if len({id(child.owner_identity) for child in children}) != len(children) or len(
        {id(child.result_evidence_identity) for child in children}
    ) != len(children):
        raise _invalid()
    for replicate_index, child in enumerate(pure):
        if (
            child.owner_kind != "PURE_NO_SIGNAL_SOURCE"
            or child.child_owner_ordinal != replicate_index + 1
            or child.pure_replicate_index != replicate_index
            or child.pure_source_receipt_digest is None
            or len(child.candidates) != 1
        ):
            raise _invalid()

    observed_materials = tuple(
        _candidate_material(observed, source) for source in observed.candidates
    )
    pure_materials = tuple(_candidate_material(child, child.candidates[0]) for child in pure)
    observed_by_slot: dict[tuple[str, int | None], _CandidateMaterial] = {}
    for material in observed_materials:
        slot = material.semantic_slot
        key = (
            cast(str, slot["null_family_id"] or slot["slot_kind"]),
            cast(int | None, slot["replicate_index"]),
        )
        if key in observed_by_slot:
            raise _invalid()
        observed_by_slot[key] = material
    observed_candidate = observed_by_slot.get(("OBSERVED", None))
    if observed_candidate is None:
        raise _invalid()
    observed_null_keys = tuple(
        (family, replicate)
        for family, replicate in _EXPECTED_NULL_SLOTS
        if family != "pure_no_signal"
    )
    if set(observed_by_slot) != {("OBSERVED", None), *observed_null_keys}:
        raise _invalid()
    observed_spec = cast(
        Mapping[str, Any],
        observed_candidate.source.candidate["analysis_spec"],
    )
    observed_variant = observed_spec.get("dataset_variant_intent")
    if not isinstance(observed_variant, Mapping):
        raise _invalid()
    observed_source_variant_id = observed_variant.get("source_variant_id")
    observed_analysis_spec_id = observed_candidate.source.candidate["analysis_spec_id"]
    for key in observed_null_keys:
        null_spec = observed_by_slot[key].source.candidate.get("analysis_spec")
        if not isinstance(null_spec, Mapping):
            raise _invalid()
        operation = null_spec.get("operation_intent")
        variant = null_spec.get("dataset_variant_intent")
        if (
            not isinstance(operation, Mapping)
            or not isinstance(variant, Mapping)
            or operation.get("source_analysis_spec_id") != observed_analysis_spec_id
            or operation.get("source_variant_id") != observed_source_variant_id
            or operation.get("derived_source_variant_id") != variant.get("source_variant_id")
            or variant.get("variant_kind") != "null-transformation"
            or variant.get("source_variant_id_ref") != observed_source_variant_id
            or variant.get("method_id") != operation.get("null_method_id")
        ):
            raise _invalid()
    pure_keys = tuple(
        (
            cast(str, material.semantic_slot["null_family_id"]),
            cast(int, material.semantic_slot["replicate_index"]),
        )
        for material in pure_materials
    )
    if pure_keys != tuple(
        ("pure_no_signal", replicate_index) for replicate_index in range(_REPLICATE_COUNT)
    ):
        raise _invalid()

    ordered_materials = (
        observed_candidate,
        *pure_materials,
        *(observed_by_slot[key] for key in observed_null_keys),
    )
    if len(ordered_materials) != _TOTAL_CANDIDATE_COUNT:
        raise _invalid()
    if (
        {source.candidate["candidate_ordinal"] for source in observed.candidates}
        != set(range(_OBSERVED_CANDIDATE_COUNT))
        or len({source.candidate["candidate_id"] for source in observed.candidates})
        != _OBSERVED_CANDIDATE_COUNT
        or any(child.candidates[0].candidate["candidate_ordinal"] != 0 for child in pure)
    ):
        raise _invalid()
    common_pipeline = observed_candidate.pipeline_spec
    common_pipeline_digest = observed_candidate.pipeline_spec_digest
    if any(
        material.pipeline_spec != common_pipeline
        or material.pipeline_spec_digest != common_pipeline_digest
        for material in ordered_materials
    ):
        raise _invalid()
    sources = tuple(material.source for material in ordered_materials)
    if (
        len({source.result_record["result_id"] for source in sources}) != _TOTAL_CANDIDATE_COUNT
        or len({source.refit_execution_digest for source in sources}) != _TOTAL_CANDIDATE_COUNT
        or sum(source.retained_chain_count for source in sources) != _TOTAL_CHAIN_COUNT
    ):
        raise _invalid()

    records = tuple(
        _source_record(
            material,
            canonical_candidate_ordinal=ordinal,
            common_pipeline_digest=common_pipeline_digest,
        )
        for ordinal, material in enumerate(ordered_materials)
    )
    observed_record = records[0]
    null_records = records[1:]
    if (
        tuple(
            (
                record["semantic_slot"]["null_family_id"],
                record["semantic_slot"]["replicate_index"],
            )
            for record in null_records
        )
        != _EXPECTED_NULL_SLOTS
    ):
        raise _invalid()

    observed_child_records = (
        observed_record,
        *null_records[_REPLICATE_COUNT:],
    )
    pure_child_records = tuple((record,) for record in null_records[:_REPLICATE_COUNT])
    observed_binding = _child_binding(observed, tuple(observed_child_records))
    pure_bindings = tuple(
        _child_binding(child, child_records)
        for child, child_records in zip(pure, pure_child_records, strict=True)
    )
    fit_attempt_count = sum(len(record["fit_attempt_evidence"]) for record in records)
    preimage: dict[str, Any] = {
        "development_candidate_source_receipt_schema_version": (
            "ebm-audit-development-candidate-source-receipt/1.0"
        ),
        "evidence_scope": "DEVELOPMENT_ONLY",
        "scientific_acceptance_eligible": False,
        "heldout_score_eligible": False,
        "report_language_authorizing": False,
        "benchmark_subject_state": "NOT_BOUND_BY_SOURCE_RECEIPT",
        "candidate_decision_state": "NOT_DERIVED",
        "canonical_candidate_order_rule": (
            "observed/1,pure_no_signal/0..58,label_permutation_null/0..58,"
            "within_group_feature_permutation_null/0..58"
        ),
        "pipeline_spec": copy.deepcopy(common_pipeline),
        "pipeline_spec_digest": common_pipeline_digest,
        "graph_summary": {
            "child_owner_count": 60,
            "observed_owner_count": 1,
            "pure_owner_count": 59,
            "candidate_record_count": _TOTAL_CANDIDATE_COUNT,
            "observed_candidate_count": 1,
            "null_candidate_count": len(null_records),
            "planned_chain_count": _TOTAL_CHAIN_COUNT,
            "validation_attempt_count": _TOTAL_CANDIDATE_COUNT,
            "fit_attempt_count": fit_attempt_count,
        },
        "observed_child": observed_binding,
        "pure_children": list(pure_bindings),
        "observed_candidate": observed_record,
        "ordered_null_candidates": list(null_records),
    }
    projection = {
        **preimage,
        "receipt_digest": structured_sha256(_RECEIPT_DOMAIN, preimage),
    }
    assert_no_direct_identifier_fields(projection)
    try:
        validate_instance(
            projection,
            _SCHEMA_NAME,
            definition="DevelopmentCandidateSourceReceipt",
        )
    except SchemaValidationError:
        raise _invalid() from None
    return projection


def _live_child_view(
    evidence: SealedResultEvidenceSet,
    scientific_evidence: SealedScientificEvidence,
    *,
    owner_identity: object,
    owner_kind: str,
    child_owner_ordinal: int,
    pure_replicate_index: int | None,
    pure_source_receipt_digest: str | None,
) -> _ChildOwnerView:
    project_terminal_ledgers(
        evidence,
        sealed_scientific_evidence=scientific_evidence,
    )
    run = _sealed_result_evidence_run(evidence)
    scientific = project_scientific_evidence(scientific_evidence)
    scientific_records = scientific.get("candidate_records")
    plan_digest = scientific.get("plan_digest")
    scientific_digest = scientific.get("scientific_evidence_digest")
    if (
        type(scientific_records) is not list
        or type(plan_digest) is not str
        or type(scientific_digest) is not str
        or len(run.plan_candidates)
        != len(run.candidate_terminals)
        != len(run.finalized_results)
        != len(scientific_records)
    ):
        raise _invalid()
    sources: list[_CandidateSourceView] = []
    for candidate, terminal, finalized, scientific_record in zip(
        run.plan_candidates,
        run.candidate_terminals,
        run.finalized_results,
        scientific_records,
        strict=True,
    ):
        finalized_state = _capture_finalized_result_state(finalized)
        prepared_owner = finalized_state.prepared_finalization_owner
        if (
            type(prepared_owner) is not _PreparedFinalizationOwner
            or finalized_state.candidate_result_authorization is None
        ):
            raise _invalid()
        prepared_state = prepared_owner._state()
        validation_attempt = _resolve_attempt(
            prepared_state.validation_evidence,
            expected_command="validate",
            chain_plan_position=None,
            expected_planning_summary_id=prepared_state.planning_summary_id,
        )
        fit_groups = _resolve_fit_groups(
            tuple(prepared_state.fit_attempt_evidence),
            state=prepared_state,
        )
        result_record = strict_json_loads(finalized_state.canonical_bytes)
        if type(result_record) is not dict:
            raise _invalid()
        result_body = result_record.get("body")
        retained_validation = _clone_mapping(validation_attempt.reference)
        retained_fit_attempts = [
            _clone_mapping(attempt.reference) for group in fit_groups for attempt in group
        ]
        retained_chain_execution_ids = tuple(
            cast(str, attempt_group[0].chain_execution_id) for attempt_group in fit_groups
        )
        ordered_chain_execution_ids = prepared_state.ordered_chain_execution_ids
        exact_attempt_ownership = (
            validation_attempt.status == "SUCCESS"
            and retained_chain_execution_ids == ordered_chain_execution_ids
        ) or (validation_attempt.status != "SUCCESS" and not fit_groups)
        if (
            not isinstance(result_body, Mapping)
            or result_body.get("preparation_state") != "PREPARED"
            or result_body.get("validation_evidence") != retained_validation
            or result_body.get("fit_attempt_evidence") != retained_fit_attempts
            or len(ordered_chain_execution_ids) != _CHAIN_COUNT
            or len(set(ordered_chain_execution_ids)) != _CHAIN_COUNT
            or not exact_attempt_ownership
        ):
            raise _invalid()
        sources.append(
            _CandidateSourceView(
                candidate=_clone_mapping(candidate),
                terminal=_clone_mapping(terminal),
                result_record=cast(dict[str, Any], result_record),
                scientific_record=_clone_mapping(scientific_record),
                refit_execution_digest=_digest(prepared_state.execution_input_projection_digest),
                retained_validation_evidence_count=1,
                retained_fit_attempt_count=len(prepared_state.fit_attempt_evidence),
                retained_chain_count=len(prepared_state.ordered_chain_execution_ids),
            )
        )
    view = _ChildOwnerView(
        owner_identity=owner_identity,
        result_evidence_identity=evidence,
        owner_kind=owner_kind,
        child_owner_ordinal=child_owner_ordinal,
        pure_replicate_index=pure_replicate_index,
        plan_digest=_digest(plan_digest),
        preparation_receipt_digest=_digest(run.preparation_receipt_digest),
        terminal_index_digest=_digest(run.terminal_index_digest),
        scientific_evidence_digest=_digest(scientific_digest),
        pure_source_receipt_digest=(
            None if pure_source_receipt_digest is None else _digest(pure_source_receipt_digest)
        ),
        candidates=tuple(sources),
    )
    final_run = _sealed_result_evidence_run(evidence)
    final_scientific = project_scientific_evidence(scientific_evidence)
    if (
        final_run.finalized_results != run.finalized_results
        or final_run.plan_candidates != run.plan_candidates
        or final_run.candidate_terminals != run.candidate_terminals
        or final_scientific != scientific
    ):
        raise _invalid()
    return view


def _derive_live_projection(
    observed_evidence: SealedResultEvidenceSet,
    observed_scientific_evidence: SealedScientificEvidence,
    pure_receipts: tuple[SealedDevelopmentNullScienceReceipt, ...],
) -> dict[str, Any]:
    observed = _live_child_view(
        observed_evidence,
        observed_scientific_evidence,
        owner_identity=observed_evidence,
        owner_kind="OBSERVED_SOURCE",
        child_owner_ordinal=0,
        pure_replicate_index=None,
        pure_source_receipt_digest=None,
    )
    pure_views: list[_ChildOwnerView] = []
    for child_owner_ordinal, receipt in enumerate(pure_receipts, start=1):
        state = _read_development_null_science_receipt_state(receipt)
        source_projection = project_development_null_science_receipt(receipt)
        development_null = source_projection.get("development_null")
        if (
            not isinstance(development_null, Mapping)
            or development_null.get("family_id") != "pure_no_signal"
            or development_null.get("null_method_id") != "pure-no-signal-synthetic/1"
            or development_null.get("candidate_count") != 1
            or development_null.get("replicate_index") != child_owner_ordinal - 1
            or type(source_projection.get("receipt_digest")) is not str
        ):
            raise _invalid()
        pure_views.append(
            _live_child_view(
                state.result_evidence,
                state.scientific_evidence,
                owner_identity=receipt,
                owner_kind="PURE_NO_SIGNAL_SOURCE",
                child_owner_ordinal=child_owner_ordinal,
                pure_replicate_index=child_owner_ordinal - 1,
                pure_source_receipt_digest=cast(str, source_projection["receipt_digest"]),
            )
        )
    return _derive_projection_from_owner_views(observed, tuple(pure_views))


@dataclass(frozen=True, slots=True, repr=False)
class _DevelopmentCandidateSourceReceiptState:
    observed_evidence: SealedResultEvidenceSet
    observed_scientific_evidence: SealedScientificEvidence
    pure_receipts: tuple[SealedDevelopmentNullScienceReceipt, ...]
    canonical_bytes: bytes


def _reject_copy() -> Never:
    raise TypeError("Development candidate-source receipts cannot be copied or serialized.")


@final
class SealedDevelopmentCandidateSourceReceipt:
    """Opaque non-transferable owner of the exact development candidate graph."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("SealedDevelopmentCandidateSourceReceipt cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "Development candidate-source receipts are issued from exact live owners only."
        )

    def __repr__(self) -> str:
        projection = project_development_candidate_source_receipt(self)
        return (
            "SealedDevelopmentCandidateSourceReceipt("
            f"receipt_digest={projection['receipt_digest']!r})"
        )

    def __copy__(self) -> SealedDevelopmentCandidateSourceReceipt:
        _reject_copy()

    def __deepcopy__(self, _memo: object) -> SealedDevelopmentCandidateSourceReceipt:
        _reject_copy()

    def __reduce__(self) -> str | tuple[object, ...]:
        _reject_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        _reject_copy()

    def __getstate__(self) -> object:
        _reject_copy()


_RECEIPT_STATES: OneShotWeakRegistry[
    SealedDevelopmentCandidateSourceReceipt,
    _DevelopmentCandidateSourceReceiptState,
]
_RECEIPT_STATE_ISSUER: OneShotRegistryIssuer[
    SealedDevelopmentCandidateSourceReceipt,
    _DevelopmentCandidateSourceReceiptState,
]
(_RECEIPT_STATES, _RECEIPT_STATE_ISSUER) = create_one_shot_registry()


def seal_development_candidate_source_receipt(
    observed_evidence: SealedResultEvidenceSet,
    observed_scientific_evidence: SealedScientificEvidence,
    pure_receipts: tuple[SealedDevelopmentNullScienceReceipt, ...],
) -> SealedDevelopmentCandidateSourceReceipt:
    """Seal only one exact live 1+59-owner development candidate graph."""

    if (
        type(observed_evidence) is not SealedResultEvidenceSet
        or type(observed_scientific_evidence) is not SealedScientificEvidence
        or type(pure_receipts) is not tuple
        or len(pure_receipts) != _REPLICATE_COUNT
        or any(
            type(receipt) is not SealedDevelopmentNullScienceReceipt for receipt in pure_receipts
        )
        or len({id(receipt) for receipt in pure_receipts}) != _REPLICATE_COUNT
    ):
        raise TypeError("Exact live development candidate-source owners are required.")
    projection = _derive_live_projection(
        observed_evidence,
        observed_scientific_evidence,
        pure_receipts,
    )
    receipt = object.__new__(SealedDevelopmentCandidateSourceReceipt)
    state = _DevelopmentCandidateSourceReceiptState(
        observed_evidence=observed_evidence,
        observed_scientific_evidence=observed_scientific_evidence,
        pure_receipts=pure_receipts,
        canonical_bytes=canonical_json_bytes(projection),
    )
    _RECEIPT_STATE_ISSUER.bind_once(receipt, state)
    return receipt


def project_development_candidate_source_receipt(
    value: object,
) -> dict[str, Any]:
    """Revalidate all sixty live owners before returning a fresh safe projection."""

    if type(value) is not SealedDevelopmentCandidateSourceReceipt:
        raise TypeError("A genuine development candidate-source receipt is required.")
    try:
        state = _RECEIPT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine development candidate-source receipt is required.") from None
    if type(state) is not _DevelopmentCandidateSourceReceiptState:
        raise TypeError("Development candidate-source receipt storage is invalid.")
    projection = _derive_live_projection(
        state.observed_evidence,
        state.observed_scientific_evidence,
        state.pure_receipts,
    )
    if canonical_json_bytes(projection) != state.canonical_bytes:
        raise TypeError("Development candidate-source receipt storage is invalid.")
    try:
        _RECEIPT_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("Development candidate-source receipt storage is invalid.") from None
    return projection


__all__ = [
    "SealedDevelopmentCandidateSourceReceipt",
    "project_development_candidate_source_receipt",
    "seal_development_candidate_source_receipt",
]
