"""Descriptive native central orders, distinct from retained-state uncertainty."""

from __future__ import annotations

import html
from typing import Any

from ebm_audit.metrics import strict_order_comparison
from ebm_audit.protocol import structured_sha256
from ebm_audit.schema import validate_instance


def objective_order_projection(
    record: dict[str, Any],
    candidate: dict[str, Any],
    plan_digest: str,
    event_semantics: dict[str, Any],
) -> dict[str, Any]:
    """Select only orders from a bound canonical record; never materialize arrays."""
    from .inspection import ReportInspectionError, safe_projection

    validate_instance(record, "canonical-records.schema.json", definition="ResultRecord")
    validate_instance(
        event_semantics["event_semantics_digest"],
        "canonical-records.schema.json",
        definition="Sha256Digest",
    )
    body = record["body"]
    preimage = {key: record[key] for key in ("result_schema_version", "body")}
    if (
        structured_sha256("ebm-audit/result-record/2", preimage) != record["result_id"]
        or body["plan_digest"] != plan_digest
        or any(
            body[key] != candidate[key]
            for key in ("candidate_id", "candidate_ordinal", "analysis_spec_id")
        )
        or body["status"] != candidate["final_status"]
    ):
        raise ReportInspectionError()
    event_ids = body.get("event_ids", [])
    orders = []
    positions = set()
    for chain in body.get("chain_results", []):
        order = chain["central_order_event_ids"]
        permutation = chain["central_order_permutation"]
        position = chain["chain_plan_position"]
        if (
            chain["event_ids"] != event_ids
            or len(event_ids) > 4096
            or len(order) != len(event_ids)
            or set(order) != set(event_ids)
            or sorted(permutation) != list(range(len(event_ids)))
            or order != [event_ids[i] for i in permutation]
            or position in positions
        ):
            raise ReportInspectionError()
        positions.add(position)
        orders.append(
            {
                "chain_plan_position": position,
                "central_order_event_ids": safe_projection(order, key="central_order_event_ids"),
                "central_order_method": safe_projection(chain["central_order_method"]),
                "stage_semantics_digest": chain["stage_semantics_digest"],
            }
        )
    return {
        "candidate_id": candidate["candidate_id"],
        "analysis_spec_id": candidate["analysis_spec_id"],
        "event_semantics_digest": event_semantics["event_semantics_digest"],
        "candidate_ordinal": candidate["candidate_ordinal"],
        "final_status": candidate["final_status"],
        "state": "AVAILABLE" if orders else "UNAVAILABLE",
        "kind": "NATIVE_CENTRAL_ORDER_ONLY",
        "sampled_order_uncertainty": False,
        "orders": sorted(orders, key=lambda row: row["chain_plan_position"]),
    }


def objective_order_distances(
    left: list[dict[str, Any]], right: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Use the existing strict-order metrics only on matched candidates/chains."""
    before = {row["candidate_id"]: row for row in left}
    after = {row["candidate_id"]: row for row in right}
    comparisons = []
    for candidate in sorted(before.keys() & after.keys()):
        a = {row["chain_plan_position"]: row for row in before[candidate]["orders"]}
        b = {row["chain_plan_position"]: row for row in after[candidate]["orders"]}
        for position in sorted(a.keys() & b.keys()):
            first, second = a[position], b[position]
            same_semantics = (
                before[candidate]["event_semantics_digest"]
                == after[candidate]["event_semantics_digest"]
                and first["central_order_method"] == second["central_order_method"]
                and first["stage_semantics_digest"] == second["stage_semantics_digest"]
                and set(first["central_order_event_ids"]) == set(second["central_order_event_ids"])
            )
            # Metrics accept canonical event IDs, while inspection publishes hashes.
            # A shared bijection preserves order distances without disclosing labels.
            identities = sorted(
                set(first["central_order_event_ids"] + second["central_order_event_ids"])
            )
            event_aliases = {value: f"event-{index}" for index, value in enumerate(identities)}
            result = strict_order_comparison(
                [event_aliases[value] for value in first["central_order_event_ids"]],
                [event_aliases[value] for value in second["central_order_event_ids"]],
            )
            comparisons.append(
                {
                    "candidate_id": candidate,
                    "chain_plan_position": position,
                    "kind": "NATIVE_CENTRAL_ORDER_ONLY",
                    "sampled_order_uncertainty": False,
                    "state": "COMPARABLE" if same_semantics else "NOT_COMPARABLE",
                    "kendall_distance": result.kendall_distance.value if same_semantics else None,
                    "footrule_distance": result.footrule_distance.value if same_semantics else None,
                    "metric_status": result.kendall_distance.status
                    if same_semantics
                    else "NOT_ASSESSABLE",
                }
            )
    return comparisons


def objective_choice_summary(
    report: dict[str, Any],
    orders: list[dict[str, Any]],
) -> dict[str, Any]:
    """Descriptive declared-choice edges using exactly one native order per side."""
    from .inspection import safe_projection

    by_spec = {row["analysis_spec_id"]: row for row in orders}
    comparisons = []
    for attempt in report["analyst_decision_evidence"]["attempts"]:
        if not attempt["axis_choices"]:
            continue
        subject = by_spec.get(attempt["subject_analysis_spec_id"])
        comparator = by_spec.get(attempt["comparator_analysis_spec_id"])
        row = {
            "choices": safe_projection(attempt["axis_choices"]),
            "subject_analysis_spec_id": attempt["subject_analysis_spec_id"],
            "comparator_analysis_spec_id": attempt["comparator_analysis_spec_id"],
            "subject_status": attempt["subject_terminal_status"],
            "comparator_status": attempt["comparator_terminal_status"],
            "state": "NOT_ASSESSABLE",
            "kendall_distance": None,
            "footrule_distance": None,
        }
        if (
            subject
            and comparator
            and len(subject["orders"]) == len(comparator["orders"]) == 1
            and subject["final_status"] in {"SUCCESS", "CONVERGENCE_WARN"}
            and comparator["final_status"] in {"SUCCESS", "CONVERGENCE_WARN"}
        ):
            # Reuse strict order comparison with a common temporary candidate identity;
            # these are explicitly declared cross-candidate edges, not matched reruns.
            a = {**comparator, "candidate_id": subject["candidate_id"]}
            result = objective_order_distances([a], [subject])
            if result:
                row.update(
                    {
                        key: result[0][key]
                        for key in ("state", "kendall_distance", "footrule_distance")
                    }
                )
        comparisons.append(row)
    values = [
        row["kendall_distance"]
        for row in comparisons
        if row["state"] == "COMPARABLE" and row["kendall_distance"] is not None
    ]
    return {
        "kind": "NATIVE_CENTRAL_ORDER_ONLY",
        "sampled_order_uncertainty": False,
        "association": "DESCRIPTIVE_ASSOCIATION",
        "comparisons": comparisons,
        "unchanged_count": sum(value == 0 for value in values),
        "moved_count": sum(value > 0 for value in values),
        "unavailable_count": len(comparisons) - len(values),
        "minimum_kendall_distance": min(values) if values else None,
        "maximum_kendall_distance": max(values) if values else None,
    }


def objective_choice_html(summary: dict[str, Any]) -> str:
    """Fixed readable native-order panel, outside the frozen scientific model."""

    def cell(value: Any) -> str:
        return html.escape("not available" if value is None else str(value))

    rows = []
    for ordinal, row in enumerate(summary["comparisons"], 1):
        hashes = "; ".join(
            f"{choice['axis_id']} / {choice['choice_id']}" for choice in row["choices"]
        )
        rows.append(
            f"<tr><td>Declared comparison {ordinal}</td><td>{cell(row['state'])}</td>"
            f"<td>{cell(row['kendall_distance'])}</td><td>{cell(row['footrule_distance'])}</td>"
            "<td><details><summary>Choice identities and terminal states</summary>"
            f"<code>{cell(hashes)}</code><p>{cell(row['subject_status'])} / "
            f"{cell(row['comparator_status'])}</p></details></td></tr>"
        )
    table = (
        "<div class=table-scroll><table><thead><tr><th>Declared choice comparison</th>"
        "<th>Comparability</th><th>Kendall distance</th><th>Footrule distance</th>"
        "<th>Details</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )
    return f"""<section id="native-objective-summary">
<h3>Native central orders across declared choices</h3>
<p><strong>{summary["unchanged_count"]} native order comparisons had zero difference;
{summary["moved_count"]} differed; {summary["unavailable_count"]} were unavailable.</strong>
Kendall distances range from {cell(summary["minimum_kendall_distance"])}
to {cell(summary["maximum_kendall_distance"])}.</p>
<p>These descriptive distances use each successful fit's single native central order,
its declared objective method and the same event set. They are separate from retained-state
modal orders, sampled-order uncertainty and scientific stability. Multiple-chain fits are
not reduced to a selected chain here. Zero distance does not establish a no-signal advantage.
Declared choices are associated with comparisons. Associations are descriptive only.</p>
{table if rows else "<p>No eligible declared native-order comparisons are available.</p>"}
</section>"""
