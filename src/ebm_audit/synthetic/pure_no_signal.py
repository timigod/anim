"""Closed semantic gate for truth-guaranteed pure-no-signal configurations."""

from __future__ import annotations

import math
from collections.abc import Mapping

from ebm_audit.errors import InvalidInputError

_ERROR_CODE = "GENERATOR.PURE_NO_SIGNAL_SEMANTICS_INVALID"
_SAFE_MESSAGE = "The pure-no-signal configuration violates its closed semantic contract."
_ZERO_EVENT_PARAMETER_IDS = (
    "amplitude",
    "covariate_effect",
    "group_effect",
    "participant_effect_loading",
)


def _invalid() -> InvalidInputError:
    return InvalidInputError(_ERROR_CODE, _SAFE_MESSAGE)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _invalid()
    return value


def _finite_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def verify_pure_no_signal_semantics(configuration: Mapping[str, object]) -> None:
    """Require the exact numerical semantics that justify no-signal truth.

    The predicate is intentionally evaluated only for ``pure_no_signal``. Its
    one global measurement-noise object remains valid and may retain
    participant-independent cross-event correlation; signal is excluded by
    zeroing every event-level signal path and using one group-independent
    latent window. The no-recoverable truth type is reserved to that family.
    """

    family_id = configuration.get("scenario_family_id")
    untrusted_parameters = configuration.get("scenario_parameters")
    if family_id != "pure_no_signal":
        if (
            isinstance(untrusted_parameters, Mapping)
            and untrusted_parameters.get("truth_type")
            == "no_recoverable_order_or_stage"
        ):
            raise _invalid()
        return

    dimensions = _mapping(configuration.get("dimensions"))
    event_count = dimensions.get("event_count")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count < 1
    ):
        raise _invalid()

    parameters = _mapping(untrusted_parameters)
    if parameters.get("truth_type") != "no_recoverable_order_or_stage":
        raise _invalid()

    event_parameters = _mapping(configuration.get("event_parameters"))
    for parameter_id in _ZERO_EVENT_PARAMETER_IDS:
        values = event_parameters.get(parameter_id)
        if (
            not isinstance(values, list)
            or len(values) != event_count
            or any(not _finite_number(value) or value != 0 for value in values)
        ):
            raise _invalid()

    latent = _mapping(configuration.get("latent_sampling"))
    window = latent.get("group_independent_window")
    if (
        latent.get("mode") != "GROUP_INDEPENDENT_WINDOW"
        or latent.get("reference_window") is not None
        or latent.get("at_risk_window") is not None
        or not isinstance(window, list)
        or len(window) != 2
        or any(not _finite_number(value) for value in window)
        or window[0] >= window[1]
    ):
        raise _invalid()
