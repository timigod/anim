"""Partial-capability surface for the SYNTHETIC-ONLY conformance EBM."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from numpy.typing import NDArray

from ebm_audit.protocol import adapter_semantics_digest, structured_sha256
from ebm_audit.worker_sdk import WorkerFailure
from ebm_audit.workers.identity import WorkerIdentityMaterial

_FULL_WORKER_ROOT = Path(__file__).resolve().parents[1] / "conformance_ebm"
if str(_FULL_WORKER_ROOT) not in sys.path:
    sys.path.insert(0, str(_FULL_WORKER_ROOT))

from model import ExactConformanceBackend, SyntheticOnlyConformanceBackend  # noqa: E402

PARTIAL_CONFORMANCE_OUTPUTS = frozenset(
    {
        "central_order",
        "position_probabilities",
        "pairwise_precedence",
        "training_stage_posterior",
        "training_expected_stage",
    }
)


class PartialExactConformanceBackend(ExactConformanceBackend):
    """Exact conformance EBM with hard-stage output deliberately unavailable."""

    def __init__(self, identity: WorkerIdentityMaterial) -> None:
        super().__init__(identity)
        capabilities = dict(self._capabilities)
        capabilities["hard_stages"] = False
        self._capabilities = capabilities
        self._capabilities_digest = structured_sha256("ebm-audit/capabilities/1", capabilities)
        self._adapter_semantics = {
            **self._adapter_semantics,
            "semantic_version": "fixed-directional-gaussian-partial/1.0",
            "capabilities_digest": self._capabilities_digest,
        }
        self._adapter_semantics_digest = adapter_semantics_digest(self._adapter_semantics)
        self._allowed_requested_outputs = set(PARTIAL_CONFORMANCE_OUTPUTS)

    @property
    def describe_result(self) -> Mapping[str, Any]:
        result = dict(super().describe_result)
        algorithm = dict(cast(list[Mapping[str, Any]], result["supported_algorithms"])[0])
        algorithm.update(
            {
                "capabilities": self._capabilities,
                "capabilities_digest": self._capabilities_digest,
                "adapter_semantics": self._adapter_semantics,
                "adapter_semantics_digest": self._adapter_semantics_digest,
            }
        )
        result["supported_algorithms"] = [algorithm]
        result["worker_limitations"] = [
            "SYNTHETIC-ONLY: accepts only this worker's regenerated deterministic fixture.",
            "Produces order outputs, training-stage posterior, and expected stage.",
            "Training hard-stage evidence is unavailable by capability.",
            "Does not implement sampling, evaluation-cohort staging, or model artifacts.",
        ]
        return result

    def _framed_data(
        self,
        request: Mapping[str, Any],
        request_dir: Path,
    ) -> tuple[dict[str, Any], dict[str, NDArray[Any]]]:
        requested_outputs = request["payload"]["execution_input_projection"][
            "requested_outputs"
        ]
        unsupported = [
            output_id
            for output_id in requested_outputs
            if output_id not in PARTIAL_CONFORMANCE_OUTPUTS
        ]
        if unsupported:
            raise WorkerFailure(
                status="UNSUPPORTED_CAPABILITY",
                code="CAPABILITY.OUTPUT_UNSUPPORTED",
                safe_message="The partial conformance worker cannot produce a requested output.",
                phase="capability-validation",
                counts={"unsupported_output_count": len(unsupported)},
            )
        return super()._framed_data(request, request_dir)


class PartialSyntheticOnlyConformanceBackend(SyntheticOnlyConformanceBackend):
    """Synthetic admission wrapper retaining the partial capability description."""

    @property
    def describe_result(self) -> Mapping[str, Any]:
        return self._delegate.describe_result


__all__ = [
    "PARTIAL_CONFORMANCE_OUTPUTS",
    "PartialExactConformanceBackend",
    "PartialSyntheticOnlyConformanceBackend",
]
