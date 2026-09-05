"""Bounded inspection of saved software artifacts, never scientific rehydration.

Local hashes detect accidental changes, not a party rewriting the entire bundle.
Only packaged enum tokens, numbers and hashed identities leave this module.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

from ebm_audit.protocol import exact_file_sha256, strict_json_loads, structured_sha256
from ebm_audit.schema import load_schema, validate_instance

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_NODES = 200_000
MAX_DEPTH = 48
_HASH = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_REPORT = "report/report.json"
_SCIENCE = "evidence/scientific-evidence-projection.json"
_SECTIONS = (
    "candidate_records",
    "uncertainty_layers",
    "capability_evidence",
    "sampling_evidence",
    "analyst_decision_evidence",
    "participant_stage_comparisons",
    "participant_influence",
    "null_evidence",
)
_PROVENANCE = {"plan_digest", "terminal_index_digest", "scientific_evidence_digest"}
_OMIT = {
    "record_schema_version",
    "layer_schema_version",
    "plan_digest",
    "terminal_index_digest",
    "layer_digest",
    "numeric_comparison_digest",
    "attempt_digest",
    "aggregate_digest",
    "record_digest",
    "description",
    "label",
    "display_name",
    "notes",
    "provenance_note",
    "scientific_evidence_digest",
}
_SCIENCE_KEYS = frozenset(
    {
        "authenticated_available_chain_count",
        "authenticated_available_pair_count",
        "available_descriptive_chain_count",
        "chain_accounting_rule_id",
        "contributing_chain_count",
        "contributing_pair_count",
        "convergence_record_digest",
        "convergence_relationship",
        "convergence_rule_binding",
        "expected_pair_count",
        "finalized_terminal_chain_count",
        "finalized_terminal_pair_count",
        "headline_order_method",
        "independent_chain_count",
        "mean_normalized_position_entropy",
        "metric_available_pair_count",
        "observed_pair_count",
        "pair_denominator_rule_id",
        "pairwise_concentration",
        "pairwise_majorities",
        "per_event_normalized_position_entropy",
        "planned_chain_count",
        "planned_independent_chain_count",
        "planned_pair_count",
        "position_concentration",
        "position_summaries",
        "reference_chain_plan_position",
        "relation_rule_id",
        "relationship",
        "retained_state_count",
        "retained_state_count_rule_id",
        "retained_state_modal_order_method_id",
        "rule_digest",
        "source_chains",
        "summary_rule_id",
        "values",
        "within_fit_contributing_chain_count",
    }
)


class ReportInspectionError(ValueError):
    """A fixed diagnostic that cannot contain saved paths, labels or values."""

    def __init__(self, code: str = "REPORT.INSPECTION_INVALID") -> None:
        self.code = code
        super().__init__("Saved report inspection failed closed validation.")


def _identity(value: str) -> str:
    return "sha256:" + hashlib.sha256(b"anim-report-identity/1\0" + value.encode()).hexdigest()


@contextmanager
def _directory(path: Path) -> Iterator[int]:
    """Open every directory component without following links, including ancestors."""
    absolute = Path(os.path.abspath(path))
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _read(root: int, relative: str, budget: list[int]) -> bytes:
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts) or relative.startswith("/"):
        raise ReportInspectionError()
    fd = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
                raise ReportInspectionError()
            limit = min(MAX_FILE_BYTES, budget[0])
            chunks = []
            size = 0
            while True:
                chunk = os.read(file_fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    raise ReportInspectionError()
            after = os.fstat(file_fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or size != before.st_size:
                raise ReportInspectionError()
            budget[0] -= size
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def _json(raw: bytes) -> dict[str, Any]:
    value = strict_json_loads(raw)
    remaining = MAX_NODES
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > MAX_DEPTH:
            raise ReportInspectionError()
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    if type(value) is not dict:
        raise ReportInspectionError()
    return value


@lru_cache(maxsize=1)
def _vocabulary() -> tuple[frozenset[str], frozenset[str]]:
    """Keys and enum tokens come from installed contracts, never report strings."""
    keys: set[str] = set()
    tokens: set[str] = set()
    pending = ["report.schema.json", "canonical-records.schema.json"]
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        nodes = [load_schema(name)]
        while nodes:
            node = nodes.pop()
            if isinstance(node, dict):
                keys.update(node.get("properties", {}))
                tokens.update(x for x in node.get("enum", []) if type(x) is str)
                if type(node.get("const")) is str:
                    tokens.add(node["const"])
                ref = node.get("$ref", "").split("#")[0]
                if ref and "/" not in ref and ref.endswith(".schema.json"):
                    pending.append(ref)
                nodes.extend(node.values())
            elif isinstance(node, list):
                nodes.extend(node)
    keys.update(
        {
            "event_semantics",
            "ordered_event_ids",
            "ordered_event_directions",
            "within_fit",
            "chain",
            "headline_order_event_ids",
            "retained_state_modal_order_event_ids",
            "metric_summaries",
            "maximum_distance",
            "median_distance",
            "within_fit_classifier_status",
        }
    )
    keys.update(_SCIENCE_KEYS)
    tokens.update(
        {
            "higher",
            "lower",
            "CONFIRMED",
            "NOT_ASSESSABLE",
            "ASSESSABLE",
            "WITHIN_FIT_NOT_ASSESSABLE",
            "IMPLEMENTED",
            "PENDING_IMPLEMENTATION",
        }
    )
    from .summary import STAGE_METRICS

    tokens.update(STAGE_METRICS)
    return frozenset(keys), frozenset(tokens)


def safe_projection(value: Any, *, key: str = "", identities: bool = False) -> Any:
    """Project public evidence without copying arbitrary labels or dictionary keys."""
    keys, tokens = _vocabulary()
    if isinstance(value, dict):
        return {
            field: safe_projection(child, key=field, identities=identities)
            for field, child in value.items()
            if field in keys
            and field not in _OMIT
            and not (
                isinstance(child, dict)
                and child.get("report_exposure") == "INTERNAL_CLASSIFIER_INPUT_ONLY"
            )
        }
    if isinstance(value, list):
        return [safe_projection(child, key=key, identities=identities) for child in value]
    if type(value) is str:
        # Event/choice identities are always hashed, including enum-like labels.
        if identities or key.endswith(("event_id", "event_ids", "axis_id", "choice_id")):
            return _identity(value)
        if _HASH.fullmatch(value):
            return value
        return value if value in tokens else _identity(value)
    if type(value) is float and not math.isfinite(value):
        raise ReportInspectionError()
    if value is None or type(value) in {int, float, bool}:
        return value
    raise ReportInspectionError()


def _validate_join(report: dict[str, Any], status: dict[str, Any]) -> None:
    validate_instance(report, "report.schema.json")
    validate_instance(status, "run-status.schema.json")
    for key in _PROVENANCE:
        if report["provenance"][key] != status[key]:
            raise ReportInspectionError()
    execution = report["candidate_execution"]
    pairs = {
        "state": "candidate_execution_status",
        "exit_code": "candidate_execution_exit_code",
        "primary_failure_class": "candidate_execution_primary_failure_class",
    }
    for key in execution:
        target = pairs.get(key, key)
        if target in status and execution[key] != status[target]:
            raise ReportInspectionError()
    if (
        report["report_status"] != status["audit_report_status"]
        or (
            report["input_declaration"] != status["input_declaration"]
            and not (
                report["input_declaration"] == "PRIVATE_LOCAL_INPUT"
                and status["input_declaration"] == "DECLARED_SYNTHETIC"
            )
        )
        or report["science_completion_gate"]["status"] != status["science_completion_gate_status"]
        or report["science_completion_gate"]["reason_codes"]
        != status["science_completion_reason_codes"]
    ):
        raise ReportInspectionError()
    rows = report["candidate_records"]
    if (
        len(rows) > 10_000
        or [row["candidate_ordinal"] for row in rows] != list(range(len(rows)))
        or len({row["candidate_id"] for row in rows}) != len(rows)
        or len(rows) != status["requested_candidate_count"]
        or len(rows) != status["terminal_record_count"]
    ):
        raise ReportInspectionError()
    counts = Counter(row["final_status"] for row in rows)
    if (
        counts["SUCCESS"] != status["success_count"]
        or len(rows) - counts["SUCCESS"] != status["non_success_terminal_count"]
        or counts["PRIVACY_VIOLATION"] != status["privacy_failure_count"]
    ) or any(counts[key] != count for key, count in status["terminal_status_counts"].items()):
        raise ReportInspectionError()


def inspect_report(run_dir: Path) -> dict[str, Any]:
    """Inspect a bound run directory; arbitrary report JSON is not accepted."""
    try:
        return _inspect_report(Path(run_dir))
    except Exception:
        # Schema errors, parser errors and filesystem errors can carry private values.
        raise ReportInspectionError() from None


def _inspect_report(run_dir: Path) -> dict[str, Any]:
    with _directory(run_dir) as root:
        budget = [MAX_TOTAL_BYTES]
        status_raw = _read(root, "run-status.json", budget)
        status = _json(status_raw)
        validate_instance(status, "run-status.schema.json")
        rows = status["report_artifacts"]
        inventory = status["publication"]["inventory"]
        if (
            len({row["path"] for row in inventory}) != len(inventory)
            or structured_sha256("ebm-audit/run-publication-inventory/1", inventory)
            != status["publication"]["inventory_digest"]
        ):
            raise ReportInspectionError()
        by_path = {row["path"]: row for row in inventory}
        if (
            len({row["path"] for row in rows}) != len(rows)
            or len(rows) != status["report_artifact_count"]
        ):
            raise ReportInspectionError()
        payloads = {}
        for row in rows:
            raw = _read(root, row["path"], budget)
            published = by_path.get(row["path"], {})
            if (
                exact_file_sha256(raw) != row["sha256"]
                or published.get("sha256") != row["sha256"]
                or published.get("byte_length") != len(raw)
            ):
                raise ReportInspectionError()
            if row["path"] in {_REPORT, _SCIENCE}:
                payloads[row["path"]] = raw
        report = _json(payloads[_REPORT])
        _validate_join(report, status)
        science = _json(payloads[_SCIENCE])
        for key in _PROVENANCE:
            if science.get(key) != status[key]:
                raise ReportInspectionError()
        if (
            science.get("scientific_evidence_schema_version")
            != report["provenance"]["scientific_evidence_schema_version"]
        ):
            raise ReportInspectionError()
        candidates = science.get("candidate_records")
        if type(candidates) is not list or len(candidates) != len(report["candidate_records"]):
            raise ReportInspectionError()
        orders = []
        candidate_metrics = []
        objective_orders = []
        from .objective_orders import objective_order_projection

        for candidate, row in zip(candidates, report["candidate_records"], strict=True):
            for key in (
                "candidate_ordinal",
                "candidate_id",
                "analysis_spec_id",
                "final_status",
                "eligibility",
            ):
                if candidate.get(key) != row[key]:
                    raise ReportInspectionError()
            within = candidate["within_fit"]
            if (
                within["status"] != row["within_fit_status"]
                or candidate["chain"]["status"] != row["chain_status"]
            ):
                raise ReportInspectionError()
            events = candidate["event_semantics"]["ordered_event_ids"]
            if (
                type(events) is not list
                or not events
                or len(events) > 4096
                or any(type(event) is not str for event in events)
                or len(set(events)) != len(events)
            ):
                raise ReportInspectionError()
            order_row = {
                "candidate_id": row["candidate_id"],
                "status": within["status"],
                "event_semantics": safe_projection(candidate["event_semantics"]),
            }
            for key in ("headline_order_event_ids", "retained_state_modal_order_event_ids"):
                order = within[key]
                if order is not None and (
                    type(order) is not list
                    or len(order) != len(events)
                    or set(order) != set(events)
                ):
                    raise ReportInspectionError()
                order_row[key] = safe_projection(order, key=key)
            orders.append(order_row)
            result_path = f"results/candidate-{row['candidate_ordinal']:08d}.json"
            published = by_path.get(result_path, {})
            raw = _read(root, result_path, budget)
            if exact_file_sha256(raw) != published.get("sha256") or len(raw) != published.get(
                "byte_length"
            ):
                raise ReportInspectionError()
            result = _json(raw)
            if result.get("result_id") != candidate.get("result_id"):
                raise ReportInspectionError()
            body_events = result.get("body", {}).get("event_ids")
            if body_events is not None and body_events != events:
                raise ReportInspectionError()
            objective_orders.append(
                objective_order_projection(
                    result, row, status["plan_digest"], candidate["event_semantics"]
                )
            )
            candidate_metrics.append(
                {
                    "candidate_id": row["candidate_id"],
                    "within_fit": safe_projection(within),
                    "chain": safe_projection(candidate["chain"]),
                }
            )
        replay = {"state": "MISSING", "bindings": None}
        # Operational recipes sit outside the frozen scientific publication inventory.
        # Their loader validates bounded non-symlink bytes and the complete self-hash.
        from ebm_audit.replay import load_replay_manifest, replay_directory

        replay_path = replay_directory(run_dir) / "replay.json"
        if os.path.lexists(replay_directory(run_dir)):
            saved = load_replay_manifest(replay_path)
            if (
                saved["plan_digest"] != status["plan_digest"]
                or saved["source_run_root_id"] != status["publication"]["staging_run_root_id"]
                or saved["bindings"]["profile_id"] != status["profile_id"]
            ):
                raise ReportInspectionError()
            replay = {"state": "AVAILABLE", "bindings": saved["bindings"]}
        if _read(root, "run-status.json", budget) != status_raw:
            raise ReportInspectionError()
    from .objective_orders import objective_choice_summary
    from .summary import decision_summary

    return {
        "schema_version": "anim-report-inspection/1",
        "inspection_state": "BOUND_ARTIFACT_INSPECTION",
        "scientific_rehydration": False,
        "run_completion_status": status["run_completion_status"],
        "input_declaration": report["input_declaration"],
        "declared_input_classification": status["input_declaration"],
        "report_status": report["report_status"],
        "science_completion_gate_status": report["science_completion_gate"]["status"],
        "baseline_status": report["baseline"]["assessment_status"],
        "candidate_execution": safe_projection(report["candidate_execution"]),
        "sections": {key: safe_projection(report[key]) for key in _SECTIONS},
        "event_orders": orders,
        "candidate_metrics": candidate_metrics,
        "objective_orders": objective_orders,
        "provenance": {key: status[key] for key in sorted(_PROVENANCE)},
        "replay": replay,
        "summary": decision_summary(report),
        "objective_summary": objective_choice_summary(report, objective_orders),
    }


def _changes(left: Any, right: Any, path: str = "") -> list[dict[str, Any]]:
    if left == right:
        return []
    if isinstance(left, dict) and isinstance(right, dict):
        result = []
        for key in sorted(set(left) | set(right)):
            location = f"{path}/{key}"
            if key not in left or key not in right:
                result.append({"path": location, "state": "ADDED" if key in right else "REMOVED"})
            else:
                result.extend(_changes(left[key], right[key], location))
        return result
    if isinstance(left, list) and isinstance(right, list) and len(left) == len(right):
        return [
            change
            for i, (a, b) in enumerate(zip(left, right, strict=True))
            for change in _changes(a, b, f"{path}/{i}")
        ]
    change = {"path": path, "state": "CHANGED", "before": left, "after": right}
    if type(left) in {int, float} and type(right) in {int, float}:
        delta = right - left
        change["delta"] = delta if math.isfinite(delta) else None
    return [change]


def _provenance_change(change: dict[str, Any]) -> bool:
    field = change["path"].rsplit("/", 1)[-1]
    return (
        field.endswith(("_digest", "_sha256", "_result_id", "_universe_id"))
        and not field.endswith("_semantics_digest")
    ) or field in {"result_id", "universe_id"}


def compare_reports(left_dir: Path, right_dir: Path) -> dict[str, Any]:
    """Compare persisted projections, preserving absence and unassessable states."""
    left, right = inspect_report(left_dir), inspect_report(right_dir)
    before = {row["candidate_id"]: row for row in left["sections"]["candidate_records"]}
    after = {row["candidate_id"]: row for row in right["sections"]["candidate_records"]}
    members = {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "changes": [
            change
            for key in sorted(before.keys() & after.keys())
            for change in _changes(before[key], after[key], f"/candidates/{key}")
        ],
    }
    members["provenance_changes"] = [row for row in members["changes"] if _provenance_change(row)]
    members["changes"] = [row for row in members["changes"] if not _provenance_change(row)]
    sections = {}
    for key in (*_SECTIONS[1:], "event_orders", "candidate_metrics", "objective_orders"):
        standalone = {"event_orders", "candidate_metrics", "objective_orders"}
        a = left[key] if key in standalone else left["sections"][key]
        b = right[key] if key in standalone else right["sections"][key]
        changes = _changes(a, b)
        science_changes = [row for row in changes if not _provenance_change(row)]
        sections[key] = {
            "state": "CHANGED" if science_changes else "UNCHANGED",
            "changes": science_changes,
            "provenance_changes": [row for row in changes if _provenance_change(row)],
        }
    state_fields = (
        "run_completion_status",
        "report_status",
        "science_completion_gate_status",
        "baseline_status",
    )
    state_changes = _changes(
        {key: left[key] for key in state_fields}, {key: right[key] for key in state_fields}
    )
    sections["run_states"] = {
        "state": "CHANGED" if state_changes else "UNCHANGED",
        "changes": state_changes,
        "provenance_changes": [],
    }
    bindings_available = left["replay"]["state"] == right["replay"]["state"] == "AVAILABLE"
    binding_changes = _changes(left["replay"]["bindings"], right["replay"]["bindings"])
    provenance = _changes(left["provenance"], right["provenance"])
    changed = bool(
        members["added"]
        or members["removed"]
        or members["changes"]
        or any(row["changes"] for row in sections.values())
    )
    semantics_equal = [row["event_semantics"] for row in left["event_orders"]] == [
        row["event_semantics"] for row in right["event_orders"]
    ]
    from .objective_orders import objective_order_distances

    return {
        "schema_version": "anim-report-comparison/1",
        "scientific_rehydration": False,
        "state": "CHANGED" if changed else "UNCHANGED",
        "comparison_scope": "SAVED_ARTIFACT_PROJECTIONS_ONLY",
        "metric_comparability": "NOT_COMPARABLE"
        if (members["added"] or members["removed"] or not semantics_equal)
        else "MATCHED_CANDIDATES_AND_SEMANTICS",
        "replay_comparability": (
            "SAME_BINDINGS" if not binding_changes else "DECLARED_BINDINGS_CHANGED"
        )
        if bindings_available
        else "MISSING_REPLAY_BINDINGS",
        "candidate_membership": members,
        "sections": sections,
        "objective_order_distances": objective_order_distances(
            left["objective_orders"], right["objective_orders"]
        ),
        "provenance_changes": provenance,
        "provenance_state": "CHANGED"
        if (
            provenance
            or members["provenance_changes"]
            or any(row["provenance_changes"] for row in sections.values())
        )
        else "UNCHANGED",
        "binding_changes": binding_changes,
        "left_summary": left["summary"],
        "right_summary": right["summary"],
    }
