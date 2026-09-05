"""Deterministic decision aids from existing public metrics, with no new gates."""

from __future__ import annotations

import html
from collections import defaultdict
from collections.abc import Iterator, Mapping
from typing import Any

from .claims import NULL_SAFE_FALLBACK

STAGE_METRICS = (
    "fixed-cohort-stage-wasserstein-median/1",
    "fixed-cohort-stage-wasserstein-maximum/1",
    "mean-left-expected-stage/1",
    "mean-right-expected-stage/1",
    "mean-signed-expected-stage-change/1",
    "mean-absolute-expected-stage-change/1",
    "mean-normalized-absolute-expected-stage-change/1",
    "map-stage-agreement-fraction/1",
    "mean-normalized-stage-wasserstein/1",
    "cohort-normalized-stage-wasserstein/1",
    "mean-normalized-stage-jensen-shannon/1",
)
_DISTANCES = {
    "central-order-kendall-distance/1",
    "central-order-footrule-distance/1",
    "position-matrix-distance/1",
    "pairwise-matrix-distance/1",
    "strict-pairwise-majority-flip-count/1",
    "strict-pairwise-majority-flip-fraction/1",
    *STAGE_METRICS[:2],
    *STAGE_METRICS[5:7],
    *STAGE_METRICS[8:],
}
_LAYER_NAMES = {
    "WITHIN_FIT": "Within fit",
    "CHAIN": "Independent chains",
    "SAMPLING": "Sampling",
    "ANALYST_DECISION": "Analysis choices",
    "PARTICIPANT_INFLUENCE": "Participant influence",
    "NULL": "No-signal checks",
}
_METRIC_NAMES = {
    "central-order-kendall-distance/1": "Order distance (Kendall)",
    "central-order-footrule-distance/1": "Order distance (footrule)",
    "position-matrix-distance/1": "Position probability distance",
    "pairwise-matrix-distance/1": "Pairwise precedence distance",
    "strict-pairwise-majority-flip-count/1": "Reversed event pairs (count)",
    "strict-pairwise-majority-flip-fraction/1": "Reversed event pairs (fraction)",
    **dict(
        zip(
            STAGE_METRICS,
            (
                "Stage distribution distance (median)",
                "Stage distribution distance (maximum)",
                "Expected stage (left mean)",
                "Expected stage (right mean)",
                "Expected stage change (signed mean)",
                "Expected stage change (absolute mean)",
                "Expected stage change (normalized absolute mean)",
                "Most likely stage agreement",
                "Stage Wasserstein distance (normalized mean)",
                "Cohort stage Wasserstein distance (normalized)",
                "Stage Jensen-Shannon distance (normalized mean)",
            ),
            strict=True,
        )
    ),
}


def _metric_rows(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if "metric_id" in value and "status" in value and "value" in value:
            if value["value"] is None or type(value["value"]) in {int, float}:
                yield value
        else:
            for child in value.values():
                yield from _metric_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from _metric_rows(child)


def decision_summary(model: Mapping[str, Any]) -> dict[str, Any]:
    """Called on live validated models or schema/hash-bound saved report models.

    Zero means exactly zero in an existing difference metric. It is not a
    scientific stability threshold. Uncertainty layers are never pooled.
    """
    from .inspection import safe_projection

    magnitudes = []
    for layer, name in (
        ("ANALYST_DECISION", "analyst_decision_evidence"),
        ("SAMPLING", "sampling_evidence"),
        ("PARTICIPANT_INFLUENCE", "participant_influence"),
    ):
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for metric in _metric_rows(model[name].get("numeric_records", [])):
            groups[metric["metric_id"]].append(metric)
        for metric_id, rows in sorted(groups.items()):
            values = [
                row["value"]
                for row in rows
                if row["status"] == "ASSESSABLE" and type(row["value"]) in {int, float}
            ]
            distances = metric_id in _DISTANCES
            magnitudes.append(
                {
                    "layer": layer,
                    "metric_id": safe_projection(metric_id, key="metric_id"),
                    "comparison_count": len(rows),
                    "assessable_count": len(values),
                    "unavailable_count": len(rows) - len(values),
                    "minimum": min(values) if values else None,
                    "maximum": max(values) if values else None,
                    "unchanged_count": sum(value == 0 for value in values) if distances else None,
                    "moved_count": sum(value > 0 for value in values) if distances else None,
                    "state": "AVAILABLE" if values else "NOT_ASSESSABLE",
                    "movement_rule": "EXACT_ZERO_DIFFERENCE"
                    if distances
                    else "DESCRIPTIVE_MAGNITUDE_ONLY",
                    "metric_states": [safe_projection(row["status"]) for row in rows],
                }
            )
    # Join declared choices to their exact numeric record; no causal attribution.
    evidence = model["analyst_decision_evidence"]
    numeric = {row["numeric_comparison_digest"]: row for row in evidence["numeric_records"]}
    associations = []
    for attempt in evidence["attempts"]:
        if not attempt["axis_choices"]:
            continue
        record = numeric.get(attempt["numeric_comparison_digest"])
        metrics = (
            []
            if record is None
            else [
                {
                    "metric_id": safe_projection(row["metric_id"], key="metric_id"),
                    "status": safe_projection(row["status"]),
                    "value": row["value"],
                }
                for row in _metric_rows(record)
            ]
        )
        associations.append(
            {
                "choices": safe_projection(attempt["axis_choices"]),
                "subject_analysis_spec_id": safe_projection(attempt["subject_analysis_spec_id"]),
                "contribution_state": safe_projection(attempt["contribution_state"]),
                "association": "DESCRIPTIVE_ASSOCIATION",
                "metrics": metrics,
            }
        )
    return {
        "schema_version": "anim-decision-summary/1",
        "report_status": safe_projection(model["report_status"]),
        "science_completion_gate_status": safe_projection(
            model["science_completion_gate"]["status"]
        ),
        "candidate_execution_status": safe_projection(model["candidate_execution"]["state"]),
        "baseline_status": safe_projection(model["baseline"]["assessment_status"]),
        "uncertainty_layers": safe_projection(model["uncertainty_layers"]),
        "worker_capabilities": safe_projection(model["capability_evidence"]),
        "magnitudes": magnitudes,
        "declared_choice_associations": associations,
        "null_calibration_state": safe_projection(model["null_evidence"]["calibration_state"]),
        "null_relative_label": safe_projection(model["null_evidence"]["null_relative_label"]),
        "strong_null_relative_language_eligible": model["null_evidence"][
            "strong_null_relative_language_eligible"
        ],
        "held_out_false_positive_rate_eligible": model["null_evidence"][
            "held_out_false_positive_rate_eligible"
        ],
        "scientific_truth_assessed": False,
        "causal_attribution": False,
        "scientific_rehydration": False,
    }


def decision_summary_html(model: Mapping[str, Any]) -> str:
    """Return a fixed-language opening panel; arbitrary prose is never rendered."""
    summary = decision_summary(model)

    def cell(value: Any) -> str:
        return html.escape("not available" if value is None else str(value))

    lead = []
    for row in summary["magnitudes"]:
        if row["metric_id"] not in {
            "central-order-kendall-distance/1",
            "mean-absolute-expected-stage-change/1",
        }:
            continue
        label = "order" if row["metric_id"] == "central-order-kendall-distance/1" else "stage"
        lead.append(
            f"<p><strong>{cell(_LAYER_NAMES[row['layer']])}:</strong> "
            f"{row['unchanged_count']} {label} comparisons had zero difference; "
            f"{row['moved_count']} differed; {row['unavailable_count']} were unavailable. "
            + (
                f"Reported magnitudes ranged from {cell(row['minimum'])} to {cell(row['maximum'])}."
                if row["assessable_count"]
                else "Movement cannot be assessed from these comparisons."
            )
            + "</p>"
        )
    lead_html = "".join(lead)
    rows = "".join(
        f"<tr><td>{cell(_LAYER_NAMES[row['layer']])}</td>"
        f"<td>{cell(_METRIC_NAMES.get(row['metric_id'], 'Additional numeric metric'))}</td>"
        + "".join(
            f"<td>{cell(row[key])}</td>"
            for key in (
                "assessable_count",
                "unavailable_count",
                "unchanged_count",
                "moved_count",
                "minimum",
                "maximum",
            )
        )
        + "</tr>"
        for row in summary["magnitudes"]
    )
    magnitudes = (
        "<div class=summary-scroll><table><thead><tr><th>Uncertainty layer</th><th>Metric</th>"
        "<th>Assessable</th><th>Unavailable</th><th>Unchanged</th><th>Moved</th>"
        "<th>Smallest magnitude</th><th>Largest magnitude</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
        if rows
        else "<p><strong>No assessable comparison magnitudes are available "
        "in this report.</strong> "
        "Successful candidate execution alone does not establish stability.</p>"
    )
    layers = "".join(
        f"<tr><td>{cell(_LAYER_NAMES[row['layer']])}</td>"
        f"<td>{cell(row['implementation_status'])}</td>"
        f"<td>{cell(row['assessable_record_count'])}</td>"
        f"<td>{cell(row['not_assessable_record_count'])}</td>"
        f"<td>{cell(row['not_applicable_record_count'])}</td></tr>"
        for row in summary["uncertainty_layers"]
    )
    axes: dict[str, set[str]] = defaultdict(set)
    for association in summary["declared_choice_associations"]:
        for choice in association["choices"]:
            axes[choice["axis_id"]].add(choice["choice_id"])
    axis_numbers = {axis: i + 1 for i, axis in enumerate(sorted(axes))}
    option_numbers = {
        (axis, option): i + 1
        for axis, options in axes.items()
        for i, option in enumerate(sorted(options))
    }
    choices = []
    for association in summary["declared_choice_associations"]:
        labels = "; ".join(
            f"Decision {axis_numbers[row['axis_id']]} / "
            f"Option {option_numbers[row['axis_id'], row['choice_id']]}"
            for row in association["choices"]
        )
        hashes = "; ".join(
            f"{row['axis_id']} / {row['choice_id']}" for row in association["choices"]
        )
        metrics = (
            "; ".join(
                f"{_METRIC_NAMES.get(row['metric_id'], 'Additional numeric metric')}: "
                + (str(row["value"]) if row["status"] == "ASSESSABLE" else "not assessable")
                for row in association["metrics"]
            )
            or "No numeric comparison available"
        )
        choices.append(
            f"<li><strong>{cell(labels)}</strong>: {cell(metrics)}. "
            "<details><summary>Comparison identities and state</summary>"
            f"<code>{cell(hashes)}</code>"
            f"<p>{cell(association['contribution_state'])}</p></details></li>"
        )
    choice_html = (
        "<ul>" + "".join(choices) + "</ul>"
        if choices
        else "<p>No declared-choice numeric associations are available.</p>"
    )
    return f"""<section id="decision-summary" aria-labelledby="decision-summary-title">
<h2 id="decision-summary-title">Decision summary</h2>
<p><strong>Software execution: {cell(summary["candidate_execution_status"])}.
Scientific report: {cell(summary["report_status"])}.
Science completion: {cell(summary["science_completion_gate_status"])}.</strong></p>
<p>Baseline: <code>{cell(summary["baseline_status"])}</code>. Worker capability, software execution,
robustness evidence and scientific interpretation are separate assessments.</p>
<h3>What stayed unchanged, what moved, and by how much</h3>
{lead_html}
<p>Unchanged means exactly zero in an existing difference metric; moved means a positive
difference. These are descriptive comparisons, not new scientific stability thresholds.
Magnitudes retain their original metric units. Unavailable and incomparable results are
not counted as unchanged. Uncertainty layers are kept separate.</p>
{magnitudes}
<h3>Declared choices associated with movement</h3>
<p>Decision and option numbers are local aliases for the hashed identities in the details.
Associations describe the declared comparisons;
they do not attribute causes. Detailed JSON and CSV retain the comparison records.</p>
{choice_html}
<h3>Evidence coverage and interpretation limits</h3>
<div class="summary-scroll"><table><thead><tr><th>Layer</th><th>Implementation</th>
<th>Assessable</th><th>Not assessable</th><th>Not applicable</th></tr></thead>
<tbody>{layers}</tbody></table></div>
<p>Null calibration: <code>{cell(summary["null_calibration_state"])}</code>.
Null-relative status: <code>{cell(summary["null_relative_label"])}</code>.</p>
<p class="gate">{html.escape(NULL_SAFE_FALLBACK)}</p>
<p>Stable or concentrated orders can occur on no-signal data. This summary does not
establish biological truth, and persisted inspection does not rehydrate scientific evidence.</p>
</section>"""
