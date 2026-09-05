"""Real pysaebm hard-kmeans inference behind the existing worker-v2 protocol.

Upstream code runs unchanged. The wrapper canonicalizes input traversal and
rescoring/tie selection, and deliberately exposes central order only.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import numpy as np

from ebm_audit.protocol import (
    adapter_semantics_digest,
    capabilities_digest,
    expected_identity_pin,
    requested_output_registry_digest,
    self_test_check_registry_digest,
    settings_schema_digest,
    stage_semantics_digest,
    structured_sha256,
)
from ebm_audit.schema import load_protocol_registry, validate_instance
from ebm_audit.worker_sdk import (
    CapabilityDeclaration,
    CapabilityLimits,
    FitContext,
    WorkerFailure,
    WorkerIdentity,
    WorkerSuccess,
    load_catalogued_npz_arrays,
)

ALGORITHM_ID = "pysaebm-hard-kmeans-central-order"
STAGE_SEMANTICS = {
    "stage_semantics_schema_version": "ebm-audit-stage-semantics/1.0",
    "stage_model_availability": "UNAVAILABLE",
    "stage_axis_id": "strict-prefix-count-v1",
    "unavailable_reason_code": "STAGING.MODEL_UNAVAILABLE",
}
SETTINGS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:ebm-audit:worker-settings-schema:pysaebm-hard-kmeans:1",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "iterations": {"type": "integer", "minimum": 8, "maximum": 20000},
        "prior_n": {"type": "number", "exclusiveMinimum": 0, "maximum": 100},
        "prior_v": {"type": "number", "exclusiveMinimum": 0, "maximum": 100},
    },
    "required": ["iterations", "prior_n", "prior_v"],
}
DEFAULT_SETTINGS = {"iterations": 64, "prior_n": 1.0, "prior_v": 1.0}


def _failure(status: str, code: str, phase: str = "data-validation") -> WorkerFailure:
    return WorkerFailure(
        status=status, code=code, safe_message="The request was rejected.", phase=phase
    )


def load_upstream(source_dir: Path) -> tuple[Any, Any]:
    """Load only authenticated algorithm modules, never package data loaders."""
    from provision import verify_source

    verify_source(source_dir)
    os.environ["NUMBA_DISABLE_JIT"] = "1"
    sys.dont_write_bytecode = True
    package = types.ModuleType("pysaebm")
    package.__path__ = [str(source_dir / "pysaebm")]
    sys.modules["pysaebm"] = package
    modules = []
    for name in ("utils", "mh"):
        specification = importlib.util.spec_from_file_location(
            "pysaebm." + name, source_dir / "pysaebm" / (name + ".py")
        )
        if specification is None or specification.loader is None:
            raise ValueError("EXAMPLE.SOURCE_MODULE_UNAVAILABLE")
        module = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = module
        setattr(package, name, module)
        specification.loader.exec_module(module)
        modules.append(module)
    return modules[1], modules[0]


def fit_central_order(
    mh: Any,
    utils: Any,
    values: np.ndarray,
    groups: np.ndarray,
    event_ids: list[str],
    directions: list[str],
    settings: Mapping[str, Any],
    seed: str,
) -> np.ndarray:
    """Run native EBM, rescore explored orders at fixed returned nuisance values.

    Upstream orders store one-based stage-at-event. Anim stores zero-based
    event-at-position. No native sampler history is presented as an uncertainty
    estimate. The declared tie rule is applied to canonical event IDs.
    """
    columns = sorted(range(len(event_ids)), key=lambda i: event_ids[i].encode("utf-8"))
    canonical_ids = [event_ids[i] for i in columns]
    signs = np.array([1.0 if directions[i] == "higher" else -1.0 for i in columns])
    canonical_values = np.asarray(values[:, columns] * signs, dtype=np.float64)
    rows = sorted(range(len(groups)), key=lambda i: (int(groups[i]), *canonical_values[i].tolist()))
    x = np.ascontiguousarray(canonical_values[rows])
    y = np.ascontiguousarray(groups[rows], dtype=np.int32)
    try:
        history, _shifted_trace, _native_best, theta_phi, stage_prior = mh.metropolis_hastings(
            algorithm="hard_kmeans",
            data_matrix=x,
            diseased_arr=y,
            iterations=int(settings["iterations"]),
            n_shuffle=2,
            prior_n=float(settings["prior_n"]),
            prior_v=float(settings["prior_v"]),
            burn_in=0,
            rng=np.random.default_rng(int(seed, 16)),
        )
        theta_phi = np.asarray(theta_phi, dtype=np.float64)
        stage_prior = np.asarray(stage_prior, dtype=np.float64)
        if (
            len(history) != settings["iterations"]
            or theta_phi.shape != (len(event_ids), 4)
            or stage_prior.shape != (len(event_ids),)
            or not np.isfinite(theta_phi).all()
            or not np.isfinite(stage_prior).all()
            or (theta_phi[:, [1, 3]] <= 0).any()
            or (stage_prior <= 0).any()
            or not np.isclose(stage_prior.sum(), 1.0)
        ):
            raise ValueError
        candidates = sorted({tuple(int(i) for i in order) for order in history})
        best_score = -np.inf
        best_permutation = None
        best_labels = None
        for candidate in candidates:
            if sorted(candidate) != list(range(1, len(event_ids) + 1)):
                raise ValueError
            score, _ = utils.compute_total_ln_likelihood_and_stage_likelihoods(
                len(y),
                x,
                np.asarray(candidate, dtype=np.int64),
                np.flatnonzero(y == 0),
                theta_phi,
                stage_prior,
                np.arange(1, len(event_ids) + 1),
            )
            if not np.isfinite(score):
                raise ValueError
            permutation = np.argsort(candidate)
            labels = tuple(canonical_ids[i] for i in permutation)
            if score > best_score or (
                score == best_score and (best_labels is None or labels < best_labels)
            ):
                best_score, best_labels = score, labels
                best_permutation = np.asarray([columns[i] for i in permutation], dtype=np.int32)
        if best_permutation is None:
            raise ValueError
        return best_permutation
    except Exception:
        raise _failure("BACKEND_ERROR", "BACKEND.PYSAEBM_NUMERICAL_FAILURE", "model-fit") from None


class PysaebmBackend:
    def __init__(self, identity: WorkerIdentity, source_dir: Path) -> None:
        self.identity = identity
        self.mh, self.utils = load_upstream(source_dir)
        self.capability = CapabilityDeclaration.limited(
            limits=CapabilityLimits(
                minimum_participants=8,
                maximum_participants=2048,
                minimum_events=2,
                maximum_events=32,
                maximum_threads=1,
                required_group_roles=("reference", "at_risk"),
            ),
            enabled=("strict_single_sequence", "deterministic_seed"),
        )
        self.capabilities = self.capability.to_mapping()
        self.algorithm = {
            "algorithm_id": ALGORITHM_ID,
            "supported_commands": ["validate", "fit"],
            "capabilities": self.capabilities,
            "capabilities_digest": capabilities_digest(self.capabilities),
            "settings_schema": SETTINGS_SCHEMA,
            "settings_schema_digest": settings_schema_digest(SETTINGS_SCHEMA),
            "stage_semantics_definition": STAGE_SEMANTICS,
            "stage_semantics_digest": stage_semantics_digest(STAGE_SEMANTICS),
            "settings_schema_validation_rules": [
                {
                    "rule_id": "settings-schema-required-subset-of-properties/1",
                    "enforcement_phase": "describe-validation",
                    "failure_status": "PROTOCOL_ERROR",
                    "failure_code": "PROTOCOL.SETTINGS_SCHEMA_REQUIRED_PROPERTY_UNDECLARED",
                }
            ],
        }
        semantics = {
            "adapter_semantics_schema_version": "ebm-audit-adapter-semantics/2.0",
            "adapter_id": identity.adapter_id,
            "algorithm_id": ALGORITHM_ID,
            "semantic_version": "pysaebm-hard-kmeans-fixed-nuisance-rescore/1",
            "supported_commands": ["validate", "fit"],
            "capabilities_digest": self.algorithm["capabilities_digest"],
            "settings_schema_digest": self.algorithm["settings_schema_digest"],
            "stage_semantics_digest": self.algorithm["stage_semantics_digest"],
            "requested_output_registry_digest": requested_output_registry_digest(),
            "mcmc_projection": {
                "projection_schema_version": "ebm-audit-adapter-mcmc-projection/1.0",
                "availability": "UNAVAILABLE",
                "reason_code": "NON_CHAIN_ALGORITHM",
            },
        }
        self.algorithm["adapter_semantics"] = semantics
        self.algorithm["adapter_semantics_digest"] = adapter_semantics_digest(semantics)

    @property
    def describe_result(self) -> Mapping[str, Any]:
        return {
            "supported_commands": ["describe", "validate", "fit", "self-test"],
            "supported_algorithms": [self.algorithm],
            "requested_output_registry_digest": requested_output_registry_digest(),
            "self_test_check_registry_digest": self_test_check_registry_digest(),
            "worker_limitations": [
                "Real pysaebm 7.7.9 MIT integration; checked with synthetic input only.",
                "Central order is the best rescored visited order at fixed returned parameters "
                "and prior, with lexicographic event-ID ties; it is not an exhaustive optimum.",
                "The native trace is shifted and its stage prior changes during fitting; "
                "convergence, order uncertainty, and staging are not exposed or established.",
                "No-chain projection describes the exposed central-order surface, not the upstream "
                "search algorithm. Search budget is the explicit iterations setting.",
                "Missing cells and undeclared roles are rejected. No imputation is performed.",
                "Clinical validity, backend acceptance and robustness evidence are absent.",
            ],
        }

    def backend_identity(self, algorithm_id: str | None) -> Mapping[str, Any]:
        return self.identity.for_algorithm(algorithm_id)

    def capabilities_for(self, algorithm_id: str) -> Mapping[str, Any]:
        if algorithm_id != ALGORITHM_ID:
            raise _failure(
                "UNSUPPORTED_CAPABILITY", "CAPABILITY.ALGORITHM_UNSUPPORTED", "request-validation"
            )
        return self.capabilities

    def capabilities_digest_for(self, algorithm_id: str) -> str:
        return capabilities_digest(self.capabilities_for(algorithm_id))

    def describe(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        expected = request["payload"]["expected_identity"]
        if expected is not None and expected != expected_identity_pin(
            self.backend_identity(None),
            algorithm_id=ALGORITHM_ID,
            algorithm_capabilities_digest=self.capabilities_digest_for(ALGORITHM_ID),
        ):
            raise _failure(
                "PROTOCOL_ERROR", "PROTOCOL.EXPECTED_IDENTITY_MISMATCH", "identity-validation"
            )
        return WorkerSuccess(payload={"result": dict(self.describe_result)})

    def _validate(self, request: Mapping[str, Any], request_dir: Path) -> tuple[dict, dict, list]:
        wire = request["payload"]
        projection = wire["execution_input_projection"]
        self.capabilities_for(projection["algorithm_id"])
        if list(
            jsonschema.Draft202012Validator(SETTINGS_SCHEMA).iter_errors(projection["settings"])
        ):
            raise _failure("INVALID_SPECIFICATION", "SPEC.PYSAEBM_SETTINGS", "settings-validation")
        absent = self.capability.assess_requested_outputs(projection["requested_outputs"])
        if "central_order" not in projection["requested_outputs"]:
            raise _failure(
                "INVALID_SPECIFICATION", "SPEC.CENTRAL_ORDER_REQUIRED", "request-validation"
            )
        dataset = projection["dataset"]
        if dataset["stage_semantics_digest"] != self.algorithm["stage_semantics_digest"]:
            raise _failure("PROTOCOL_ERROR", "PROTOCOL.STAGE_SEMANTICS_MISMATCH")
        arrays = load_catalogued_npz_arrays(
            request_dir / "values.npz", catalog=dataset["array_catalog"]
        )
        x, groups = arrays["train_values"], arrays["train_group_codes"]
        n, m = dataset["participant_count"], dataset["event_count"]
        if not 8 <= n <= 2048 or not 2 <= m <= 32:
            raise _failure("UNSUPPORTED_CAPABILITY", "CAPABILITY.PYSAEBM_SIZE_LIMIT")
        if x.shape != (n, m) or groups.shape != (n,):
            raise _failure("INVALID_INPUT", "DATA.EVENT_MATRIX_SHAPE")
        if not np.array_equal(arrays["training_row_indexes"], np.arange(n, dtype=np.int64)):
            raise _failure("PROTOCOL_ERROR", "PROTOCOL.ROW_INDEX_ALIGNMENT")
        if any(
            not np.isfinite(value).all()
            for name, value in arrays.items()
            if name.endswith("values")
        ):
            raise _failure("UNSUPPORTED_CAPABILITY", "CAPABILITY.MISSING_VALUES")
        codebook = dataset["group_codebook"]
        if set(codebook.values()) != {"reference", "at_risk"} or len(codebook) != 2:
            raise _failure("INVALID_INPUT", "DATA.PYSAEBM_GROUP_ROLES")
        if not set(int(i) for i in groups) <= {int(i) for i in codebook}:
            raise _failure("INVALID_INPUT", "DATA.GROUP_CODE_UNDECLARED")
        y = np.asarray([int(codebook[str(int(i))] == "at_risk") for i in groups], dtype=np.int32)
        if min(np.count_nonzero(y == 0), np.count_nonzero(y == 1)) < 2:
            raise _failure("INVALID_INPUT", "DATA.PYSAEBM_GROUP_SIZE")
        if np.any(np.ptp(x, axis=0) == 0):
            raise _failure("INVALID_INPUT", "DATA.PYSAEBM_CONSTANT_EVENT")
        arrays = dict(arrays)
        arrays["model_groups"] = y
        return projection, arrays, [item.to_mapping() for item in absent]

    def validate(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        projection, _arrays, absent = self._validate(request, request_dir)
        return WorkerSuccess(
            payload={
                "algorithm_id": ALGORITHM_ID,
                "settings_digest": projection["settings_digest"],
                "config_digest": projection["config_digest"],
                "requested_outputs_digest": projection["requested_outputs_digest"],
                "execution_input_projection_digest": request["payload"][
                    "execution_input_projection_digest"
                ],
                "validation_issues": [],
                "predicted_accounting": projection["data_accounting"],
                "component_applicability": absent,
                "fit_permitted": True,
            }
        )

    def fit(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess | WorkerFailure:
        projection, arrays, _absent = self._validate(request, request_dir)
        context = FitContext.from_request(request, request_dir)
        dataset = projection["dataset"]
        order = fit_central_order(
            self.mh,
            self.utils,
            arrays["train_values"],
            arrays["model_groups"],
            dataset["event_ids"],
            dataset["event_directions"],
            projection["settings"],
            request["payload"]["seed"],
        )
        return context.fit_success(
            central_order=order,
            central_order_method={
                "method_id": "backend-objective-maximum/1",
                "candidate_source": "backend_explored_order_set",
                "objective_id": "pysaebm-fixed-nuisance-native-log-likelihood-v1",
                "tie_break_rule": "lexicographically-smallest-event-id-sequence/1",
            },
            field_origins={
                "central_order_permutation": {
                    "origin": "WORKER_DERIVED",
                    "method_id": "pysaebm-native-visited-order-rescoring-v1",
                    "source_fields": ["train_values", "train_group_codes", "seed", "settings"],
                    "source_hashes": [
                        dataset["scientific_data_digest"],
                        self.identity.backend_source_digest,
                    ],
                }
            },
            raw_iteration_count=None,
            burn_in_count=None,
            thinning_interval=None,
            postburn_unthinned_state_count=None,
            retained_state_count=None,
            likelihood_indexing=None,
            actual_transition_count=None,
            actual_transition_fraction=None,
            warnings=(),
        )

    def self_test(self, request: Mapping[str, Any], request_dir: Path) -> WorkerSuccess:
        checks = request["payload"]["requested_checks"]
        registered = {row["check_id"] for row in load_protocol_registry()["self_test_checks"]}
        if not set(checks) <= registered:
            raise _failure("INVALID_SPECIFICATION", "SPEC.SELF_TEST_CHECK_UNKNOWN")
        started = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        x = np.asarray([[i / 4, (i % 3) - 1.0] for i in range(12)], dtype=np.float64)
        y = np.asarray([0] * 4 + [1] * 8, dtype=np.int32)
        fixture_digest = structured_sha256(
            "anim/pysaebm-self-test/1", {"x": x.tolist(), "y": y.tolist()}
        )
        results = []
        for check in checks:
            outcome, message = "PASS", "The synthetic worker check passed."
            try:
                if check == "schema-roundtrip":
                    validate_instance(
                        dict(self.describe_result),
                        "worker-protocol.schema.json",
                        definition="DescribeResult",
                    )
                elif check == "identity-stability":
                    assert self.backend_identity(None) == self.backend_identity(None)
                elif check in {"seed-repeatability", "array-invariants"}:
                    first = fit_central_order(
                        self.mh,
                        self.utils,
                        x,
                        y,
                        ["event-a", "event-b"],
                        ["higher", "higher"],
                        DEFAULT_SETTINGS,
                        request["payload"]["seed"],
                    )
                    assert sorted(first.tolist()) == [0, 1]
                    if check == "seed-repeatability":
                        second = fit_central_order(
                            self.mh,
                            self.utils,
                            x,
                            y,
                            ["event-a", "event-b"],
                            ["higher", "higher"],
                            DEFAULT_SETTINGS,
                            request["payload"]["seed"],
                        )
                        assert np.array_equal(first, second)
                else:
                    outcome, message = "FAIL", "UNVERIFIED: containment is measured by the auditor."
            except Exception:
                outcome, message = "FAIL", "The synthetic worker check failed."
            results.append(
                {
                    "check_id": check,
                    "outcome": outcome,
                    "safe_message": message,
                    "evidence_digests": {"fixture": fixture_digest},
                    "evidence_counts": {"participant_count": 12, "event_count": 2},
                }
            )
        return WorkerSuccess(
            payload={
                "seed": request["payload"]["seed"],
                "receipt": {
                    "profile": "tiny-synthetic/1",
                    "fixture_id": "pysaebm-synthetic-only",
                    "fixture_digest": fixture_digest,
                    "worker_executable_digest": self.identity.worker_executable_digest,
                    "worker_code_digest": self.identity.worker_code_digest,
                    "backend_source_digest": self.identity.backend_source_digest,
                    "environment_digest": self.identity.environment_digest,
                    "started_at_utc": started,
                    "ended_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "checks": results,
                },
            }
        )
