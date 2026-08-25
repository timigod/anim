"""Exact public-synthetic input for the one pySuStaIn conformance transaction."""

from __future__ import annotations

import hashlib

CONFORMANCE_CASE_ID = "pysustain-full-reference-worker-v1-conformance-0"
SYNTHETIC_DATA_SEED = "38d55c207c5f9631"
PARTICIPANT_COUNT = 24
EVENT_IDS = ("event-01", "event-02", "event-03", "event-04")
EVENT_SOURCE_COLUMNS = ("event_01", "event_02", "event_03", "event_04")
_REFERENCE_COUNT = 12
_AT_RISK_STAGES = (1, 1, 2, 2, 3, 3, 4, 4, 4, 3, 2, 1)
_ABNORMAL_MILLI = 3500
_NOISE_LIMIT_MILLI = 200


def _noise_milli(participant_ordinal: int, event_ordinal: int) -> int:
    preimage = (
        "ebm-audit/pysustain-conformance-noise/1\0"
        f"{SYNTHETIC_DATA_SEED}\0{participant_ordinal}\0{event_ordinal}"
    ).encode("ascii")
    draw = int.from_bytes(hashlib.sha256(preimage).digest()[:8], "big")
    return (draw % (2 * _NOISE_LIMIT_MILLI + 1)) - _NOISE_LIMIT_MILLI


def _measurement_milli(
    participant_ordinal: int,
    event_ordinal: int,
    stage: int,
) -> int:
    direction = 1 if event_ordinal % 2 == 1 else -1
    abnormal = _ABNORMAL_MILLI if stage >= event_ordinal else 0
    return direction * abnormal + _noise_milli(participant_ordinal, event_ordinal)


def generate_conformance_csv_bytes() -> bytes:
    """Return the fixed 24-by-4 table; no filesystem, network, or backend access."""

    lines = ["participant_code,group," + ",".join(EVENT_SOURCE_COLUMNS)]
    for participant_ordinal in range(1, PARTICIPANT_COUNT + 1):
        if participant_ordinal <= _REFERENCE_COUNT:
            group = "reference"
            stage = 0
        else:
            group = "at-risk"
            stage = _AT_RISK_STAGES[participant_ordinal - _REFERENCE_COUNT - 1]
        values = [
            f"{_measurement_milli(participant_ordinal, event_ordinal, stage) / 1000:.3f}"
            for event_ordinal in range(1, len(EVENT_IDS) + 1)
        ]
        lines.append(f"synthetic-conformance-{participant_ordinal:03d},{group}," + ",".join(values))
    return ("\n".join(lines) + "\n").encode("ascii")


def conformance_csv_sha256() -> str:
    return "sha256:" + hashlib.sha256(generate_conformance_csv_bytes()).hexdigest()
