"""Shared semantic validation for privacy-safe participant-stage comparisons.

The validator is deliberately one self-contained module-level function.  Both
scientific derivation graphs retain this exact function as an immutable leaf,
so analyst-decision and sampling evidence cannot drift onto separate semantic
interpretations of the shared public record.
"""

from __future__ import annotations


def validate_participant_stage_comparison_semantics(
    value: object,
    *,
    common_event_ids: tuple[str, ...],
    left_only_event_ids: tuple[str, ...],
    right_only_event_ids: tuple[str, ...],
    expected_left_ordered_event_ids: tuple[str, ...] | None = None,
    expected_right_ordered_event_ids: tuple[str, ...] | None = None,
    _metric_ids: tuple[str, ...] = (
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
    ),
    _absolute_tolerance: float = 1e-12,
) -> None:
    """Validate one canonical public stage record against its source events."""

    def string_sequence(item: object) -> tuple[str, ...]:
        if type(item) is not list or any(type(child) is not str for child in item):
            raise ValueError("STAGE.EVENT_ACCOUNTING")
        return tuple(item)

    if type(value) is not dict:
        raise ValueError("STAGE.SHAPE")
    record = value
    left_events = string_sequence(record.get("left_ordered_event_ids"))
    right_events = string_sequence(record.get("right_ordered_event_ids"))
    stage_common = string_sequence(record.get("common_event_ids"))
    stage_left_only = string_sequence(record.get("left_only_event_ids"))
    stage_right_only = string_sequence(record.get("right_only_event_ids"))
    same_event_set = not left_only_event_ids and not right_only_event_ids
    same_ordered_events = left_events == right_events
    if (
        set(left_events) != set((*common_event_ids, *left_only_event_ids))
        or set(right_events) != set((*common_event_ids, *right_only_event_ids))
        or (
            expected_left_ordered_event_ids is not None
            and left_events != expected_left_ordered_event_ids
        )
        or (
            expected_right_ordered_event_ids is not None
            and right_events != expected_right_ordered_event_ids
        )
        or stage_common != common_event_ids
        or stage_left_only != left_only_event_ids
        or stage_right_only != right_only_event_ids
        or record.get("common_event_count") != len(common_event_ids)
        or record.get("same_event_set") is not same_event_set
        or record.get("same_ordered_event_ids") is not same_ordered_events
    ):
        raise ValueError("STAGE.EVENT_ACCOUNTING")
    for prefix, events in (("left", left_events), ("right", right_events)):
        side_availability = record.get(f"{prefix}_availability")
        reference_digest = record.get(f"{prefix}_stage_model_reference_digest")
        reference_order_value = record.get(f"{prefix}_stage_reference_order_event_ids")
        headline_order_value = record.get(f"{prefix}_headline_central_order_event_ids")
        matches = record.get(f"{prefix}_stage_reference_order_matches_headline")
        if side_availability == "AVAILABLE":
            reference_order = string_sequence(reference_order_value)
            headline_order = string_sequence(headline_order_value)
            if (
                type(reference_digest) is not str
                or set(reference_order) != set(events)
                or len(reference_order) != len(events)
                or set(headline_order) != set(events)
                or len(headline_order) != len(events)
                or type(matches) is not bool
                or matches is not (reference_order == headline_order)
            ):
                raise ValueError("STAGE.PROVENANCE")
        elif any(
            item is not None
            for item in (
                reference_digest,
                reference_order_value,
                headline_order_value,
                matches,
            )
        ):
            raise ValueError("STAGE.PROVENANCE")
    quantiles = record.get("normalized_stage_wasserstein_quantiles")
    if (
        type(record.get("private_evidence_digest")) is not str
        or record.get("participant_selection_source") != "FIXED_EVALUATION_COHORT"
        or record.get("quantile_rule_id") != "inverse-empirical-cdf/1"
        or type(quantiles) is not dict
        or set(quantiles) != {"q10", "q25", "q50", "q75", "q90"}
    ):
        raise ValueError("STAGE.SUMMARY")
    metric_status = record.get("metric_status")
    availability = record.get("availability")
    comparability = record.get("semantic_comparability")
    metrics = record.get("metrics")
    if (
        type(metrics) is not list
        or len(metrics) != len(_metric_ids)
        or any(type(metric) is not dict for metric in metrics)
        or [metric.get("metric_id") for metric in metrics] != list(_metric_ids)
        or any(metric.get("status") != metric_status for metric in metrics)
    ):
        raise ValueError("STAGE.METRICS")
    if metric_status == "ASSESSABLE":
        if (
            availability != "AVAILABLE"
            or comparability != "COMPARABLE"
            or record.get("availability_reason_code") is not None
            or record.get("semantic_comparability_reason_code") is not None
            or record.get("metric_reason_code") is not None
            or record.get("same_event_set") is not True
            or record.get("same_ordered_event_ids") is not True
            or record.get("same_event_direction_bindings") is not True
            or record.get("same_stage_semantics") is not True
            or record.get("same_evaluation_cohort") is not True
            or record.get("same_evaluation_row_indexes") is not True
            or record.get("same_evaluation_unit_bindings") is not True
            or type(record.get("evaluation_cohort_digest")) is not str
            or type(record.get("evaluation_cohort_count")) is not int
            or record["evaluation_cohort_count"] < 1
            or record.get("cohort_denominator_count")
            != record.get("evaluation_cohort_count")
            or record.get("valid_participant_count")
            != record.get("cohort_denominator_count")
            or record.get("missing_participant_count") != 0
            or any(
                type(quantiles.get(name)) not in {int, float}
                or isinstance(quantiles[name], bool)
                or not (-float("inf") < float(quantiles[name]) < float("inf"))
                for name in ("q10", "q25", "q50", "q75", "q90")
            )
            or not (
                float(quantiles["q10"])
                <= float(quantiles["q25"])
                <= float(quantiles["q50"])
                <= float(quantiles["q75"])
                <= float(quantiles["q90"])
            )
            or type(record.get("normalized_stage_wasserstein_iqr")) not in {int, float}
            or isinstance(record.get("normalized_stage_wasserstein_iqr"), bool)
            or not (
                -float("inf")
                < float(record["normalized_stage_wasserstein_iqr"])
                < float("inf")
            )
            or abs(
                float(record["normalized_stage_wasserstein_iqr"])
                - (float(quantiles["q75"]) - float(quantiles["q25"]))
            )
            > _absolute_tolerance
            or any(
                type(metric.get("value")) not in {int, float}
                or isinstance(metric.get("value"), bool)
                or not (-float("inf") < float(metric["value"]) < float("inf"))
                or metric.get("reason_code") is not None
                for metric in metrics
            )
        ):
            raise ValueError("STAGE.METRICS")
        if metrics[0].get("value") != quantiles["q50"] or float(
            metrics[1]["value"]
        ) < float(quantiles["q90"]):
            raise ValueError("STAGE.METRICS")
        return
    if metric_status == "NOT_APPLICABLE_BY_CAPABILITY":
        if (
            availability != "NOT_APPLICABLE_BY_CAPABILITY"
            or record.get("availability_reason_code")
            != "STAGING.FIXED_COHORT_UNAVAILABLE"
            or record.get("metric_reason_code") != "STAGING.FIXED_COHORT_UNAVAILABLE"
        ):
            raise ValueError("STAGE.METRICS")
    elif metric_status != "NOT_ASSESSABLE":
        raise ValueError("STAGE.METRICS")
    incomplete_fixed_cohort = (
        metric_status == "NOT_ASSESSABLE"
        and availability == "AVAILABLE"
        and record.get("metric_reason_code")
        == "STAGE.INCOMPLETE_FIXED_COHORT_DERIVATION"
    )
    if (
        (
            incomplete_fixed_cohort
            and (
                type(record.get("evaluation_cohort_digest")) is not str
                or type(record.get("evaluation_cohort_count")) is not int
                or record.get("cohort_denominator_count")
                != record.get("evaluation_cohort_count")
                or type(record.get("valid_participant_count")) is not int
                or type(record.get("missing_participant_count")) is not int
                or record["valid_participant_count"] + record["missing_participant_count"]
                != record["cohort_denominator_count"]
                or record["missing_participant_count"] < 1
            )
        )
        or (
            not incomplete_fixed_cohort
            and any(
                record.get(field) is not None
                for field in (
                    "evaluation_cohort_digest",
                    "evaluation_cohort_count",
                    "cohort_denominator_count",
                    "valid_participant_count",
                    "missing_participant_count",
                )
            )
        )
        or any(item is not None for item in quantiles.values())
        or record.get("normalized_stage_wasserstein_iqr") is not None
        or type(record.get("metric_reason_code")) is not str
        or any(
            metric.get("value") is not None
            or type(metric.get("reason_code")) is not str
            for metric in metrics
        )
    ):
        raise ValueError("STAGE.METRICS")


__all__: list[str] = []
