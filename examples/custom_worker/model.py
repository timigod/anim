"""Runnable synthetic custom-worker example.

This toy delegates to the project's deterministic structural callback so every
mandatory transport command can be exercised without a scientific backend. It
is not an EBM, is not backend-acceptance evidence, and must never be used for a
scientific analysis.

This file is a transport demonstration, not a three-method scientific adapter
template. A real integration must replace the complete backend declaration as
well as its callbacks: identity, algorithm ID, capabilities, constraints,
settings schema, staging-semantics definition, limitations, validation, fit,
and self-test. The ``WorkerApplication`` subprocess boundary and closed response
framing may stay the same; private model code is never imported by the auditor
core.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ebm_audit.protocol import structured_sha256
from ebm_audit.worker_sdk import FitContext, FitOutputs, WorkerFailure
from ebm_audit.workers.identity import WorkerIdentityMaterial
from ebm_audit.workers.structural import DeterministicMcmcFixtureBackend
from ebm_audit.workers.types import WorkerSuccess


@dataclass(frozen=True, slots=True)
class _SyntheticNativeFitResult:
    central_order: Any
    outputs: FitOutputs
    central_order_method: Mapping[str, Any]
    field_origins: Mapping[str, Mapping[str, Any]]
    raw_iteration_count: int
    burn_in_count: int
    thinning_interval: int
    postburn_unthinned_state_count: int
    retained_state_count: int
    likelihood_indexing: str | None
    actual_transition_count: int | None
    actual_transition_fraction: float | None
    backend_artifacts: tuple[Mapping[str, Any], ...]
    warnings: tuple[Mapping[str, Any], ...]


def _synthetic_native_fit(context: FitContext) -> _SyntheticNativeFitResult:
    """Produce toy native model output without constructing a worker payload."""

    np = __import__("numpy")
    payload = context.payload
    projection = context.execution_input_projection
    event_ids = list(projection["dataset"]["event_ids"])
    requested_outputs = frozenset(projection["requested_outputs"])
    event_count = len(event_ids)
    offset = int(payload["seed"], 16) % event_count
    central = np.roll(np.arange(event_count, dtype=np.int32), -offset)
    alternate = central.copy()
    if event_count > 1:
        alternate[0], alternate[1] = central[1], central[0]
    postburn = np.tile(central, (500, 1))
    postburn[::5] = alternate
    retained = postburn.copy()
    changes = np.any(postburn[1:] != postburn[:-1], axis=1)
    likelihood = np.linspace(-250.0, -249.0, postburn.shape[0], dtype=np.float64)
    position = np.zeros((event_count, event_count), dtype=np.float64)
    precedence = np.zeros((event_count, event_count), dtype=np.float64)
    for state in retained:
        for position_index, event_index in enumerate(state.tolist()):
            position[event_index, position_index] += 1.0
        inverse = np.empty(event_count, dtype=np.int64)
        inverse[state] = np.arange(event_count, dtype=np.int64)
        precedence += inverse[:, None] < inverse[None, :]
    position /= float(retained.shape[0])
    precedence /= float(retained.shape[0])
    np.fill_diagonal(precedence, 0.5)

    source_digest = structured_sha256(
        "ebm-audit/custom-worker-synthetic-native-fit/1",
        {"seed": payload["seed"], "event_ids": event_ids},
    )
    origins: dict[str, Mapping[str, Any]] = {
        "central_order_permutation": {
            "origin": "WORKER_DERIVED",
            "method_id": "custom-worker-synthetic-native-order-v1",
            "source_fields": ["seed", "event_ids"],
            "source_hashes": [source_digest],
        }
    }
    if "order_samples" in requested_outputs:
        trace_origin = {
            "origin": "WORKER_DERIVED",
            "method_id": "custom-worker-synthetic-native-order-trace-v1",
            "source_fields": ["seed", "event_ids"],
            "source_hashes": [source_digest],
        }
        origins["postburn_order_state_chain"] = trace_origin
        origins["order_state_chain"] = trace_origin
    if "accepted_transition_diagnostics" in requested_outputs:
        transition_origin = {
            "origin": "WORKER_DERIVED",
            "method_id": "adjacent-unthinned-postburn-state-change-v1",
            "source_fields": ["seed", "event_ids"],
            "source_hashes": [source_digest],
        }
        for name in (
            "postburn_state_change_mask",
            "actual_transition_count",
            "actual_transition_fraction",
        ):
            origins[name] = transition_origin
    for output_id, member_name, method_id in (
        (
            "position_probabilities",
            "position_probabilities",
            "retained-chain-position-probability-v1",
        ),
        (
            "pairwise_precedence",
            "pairwise_precedence",
            "retained-chain-pairwise-precedence-v1",
        ),
    ):
        if output_id in requested_outputs:
            origins[member_name] = {
                "origin": "WORKER_DERIVED",
                "method_id": method_id,
                "source_fields": ["seed", "event_ids"],
                "source_hashes": [source_digest],
            }
    if "likelihood_trace" in requested_outputs:
        likelihood_origin = {
            "origin": "WORKER_DERIVED",
            "method_id": "custom-worker-synthetic-native-likelihood-trace-v1",
            "source_fields": ["seed", "event_ids"],
            "source_hashes": [source_digest],
        }
        origins["postburn_likelihood_trace"] = likelihood_origin
        origins["likelihood_trace"] = likelihood_origin

    transition_requested = "accepted_transition_diagnostics" in requested_outputs
    return _SyntheticNativeFitResult(
        central_order=central,
        outputs=FitOutputs(
            postburn_order_state_chain=(postburn if "order_samples" in requested_outputs else None),
            order_state_chain=retained if "order_samples" in requested_outputs else None,
            postburn_likelihood_trace=(
                likelihood if "likelihood_trace" in requested_outputs else None
            ),
            likelihood_trace=(
                likelihood.copy() if "likelihood_trace" in requested_outputs else None
            ),
            postburn_state_change_mask=changes if transition_requested else None,
            position_probabilities=(
                position if "position_probabilities" in requested_outputs else None
            ),
            pairwise_precedence=(
                precedence if "pairwise_precedence" in requested_outputs else None
            ),
        ),
        central_order_method={
            "method_id": "backend-objective-maximum/1",
            "candidate_source": "backend_explored_order_set",
            "objective_id": "custom-worker-synthetic-native-objective-v1",
            "tie_break_rule": "lexicographically-smallest-event-id-sequence/1",
        },
        field_origins=origins,
        raw_iteration_count=501,
        burn_in_count=1,
        thinning_interval=1,
        postburn_unthinned_state_count=500,
        retained_state_count=500,
        likelihood_indexing=(
            "post-proposal-state/1" if "likelihood_trace" in requested_outputs else None
        ),
        actual_transition_count=int(changes.sum()) if transition_requested else None,
        actual_transition_fraction=float(changes.mean()) if transition_requested else None,
        backend_artifacts=(),
        warnings=(),
    )


class CustomWorkerExampleBackend(DeterministicMcmcFixtureBackend):
    """Transport-only toy; never a base class for an accepted scientific worker."""

    def __init__(self, identity: WorkerIdentityMaterial) -> None:
        super().__init__(identity)

    @property
    def describe_result(self) -> Mapping[str, Any]:
        result = dict(super().describe_result)
        result["worker_limitations"] = [
            "Runnable synthetic deterministic-chain custom-worker example only.",
            "It is not an EBM and is never eligible for scientific backend acceptance.",
            (
                "Its deterministic chain exists only to exercise the complete "
                "audit transport and report path."
            ),
            (
                "A real worker must replace the complete fixture-owned backend "
                "declaration and callbacks."
            ),
        ]
        return result

    def validate(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        # TRANSPORT DEMO ONLY: a real backend owns its complete declaration too.
        return super().validate(request, request_dir)

    def fit(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        context = FitContext.from_request(request, request_dir)
        native = _synthetic_native_fit(context)
        authored = context.fit_success(
            central_order=native.central_order,
            outputs=native.outputs,
            central_order_method=native.central_order_method,
            field_origins=native.field_origins,
            raw_iteration_count=native.raw_iteration_count,
            burn_in_count=native.burn_in_count,
            thinning_interval=native.thinning_interval,
            postburn_unthinned_state_count=native.postburn_unthinned_state_count,
            retained_state_count=native.retained_state_count,
            likelihood_indexing=native.likelihood_indexing,
            actual_transition_count=native.actual_transition_count,
            actual_transition_fraction=native.actual_transition_fraction,
            backend_artifacts=native.backend_artifacts,
            warnings=native.warnings,
        )
        if isinstance(authored, WorkerFailure):
            raise authored
        return authored

    def self_test(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        # TRANSPORT DEMO ONLY: replace the full backend, not only this method.
        return super().self_test(request, request_dir)
