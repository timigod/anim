"""Small immutable records for authoring a local worker adapter.

The records in this module produce mappings owned by the existing worker
protocol. They deliberately delegate schema truth, digests, and array
canonicalization to the auditor's established implementations.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Self, cast

from ebm_audit.protocol import canonical_json_bytes, strict_json_loads
from ebm_audit.schema import load_protocol_registry, validate_instance
from ebm_audit.workers.arrays import array_catalog_entry, canonical_array
from ebm_audit.workers.types import WorkerFailure, WorkerSuccess

type CapabilityName = Literal[
    "strict_single_sequence",
    "grouped_or_simultaneous_events",
    "subtypes",
    "temporal_events",
    "order_samples",
    "position_probabilities",
    "pairwise_precedence",
    "exact_fixed_order_target",
    "likelihood_trace",
    "accepted_transition_diagnostics",
    "fitted_event_distributions",
    "participant_stage_posterior",
    "hard_stages",
    "fixed_evaluation_cohort_staging",
    "portable_fitted_model_artifact",
    "multiple_chains",
    "bootstrap",
    "cross_validation",
    "deterministic_seed",
]

_CAPABILITY_NAMES: frozenset[str] = frozenset(
    {
        "strict_single_sequence",
        "grouped_or_simultaneous_events",
        "subtypes",
        "temporal_events",
        "order_samples",
        "position_probabilities",
        "pairwise_precedence",
        "exact_fixed_order_target",
        "likelihood_trace",
        "accepted_transition_diagnostics",
        "fitted_event_distributions",
        "participant_stage_posterior",
        "hard_stages",
        "fixed_evaluation_cohort_staging",
        "portable_fitted_model_artifact",
        "multiple_chains",
        "bootstrap",
        "cross_validation",
        "deterministic_seed",
    }
)


class SDKValidationError(ValueError):
    """A privacy-safe SDK construction failure with a stable phase and field."""

    def __init__(self, *, phase: str, field: str) -> None:
        self.phase = phase
        self.field = field
        super().__init__(f"SDK validation failed during {phase} at {field}.")


@dataclass(frozen=True, slots=True)
class SyntheticProvenance:
    """Closed public provenance for project-owned deterministic synthetic data."""

    generator_id: str
    generator_version: str
    generator_record_sha256: str
    generated_input_sha256: str
    complete_truth_sha256: str
    complete_truth_record_id: str
    scenario_id: str
    replicate: int
    seed: str
    participant_count: int
    event_count: int
    event_ids: tuple[str, ...]
    schema_version: Literal["ebm-audit-synthetic-provenance/1.0"] = field(
        default="ebm-audit-synthetic-provenance/1.0",
        init=False,
    )
    classification: Literal["SYNTHETIC-ONLY"] = field(
        default="SYNTHETIC-ONLY",
        init=False,
    )
    source_kind: Literal["PROJECT_OWNED_DETERMINISTIC_GENERATOR"] = field(
        default="PROJECT_OWNED_DETERMINISTIC_GENERATOR",
        init=False,
    )
    participant_data_present: Literal[False] = field(default=False, init=False)
    external_source_present: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_ids", tuple(self.event_ids))
        _validated_bytes(
            self.to_mapping(),
            schema_name="worker-protocol.schema.json",
            definition="SyntheticProvenance",
            phase="synthetic-provenance-validation",
            field="synthetic_provenance",
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Self:
        """Build from one exact canonical provenance mapping."""

        encoded = _validated_bytes(
            value,
            schema_name="worker-protocol.schema.json",
            definition="SyntheticProvenance",
            phase="synthetic-provenance-validation",
            field="synthetic_provenance",
        )
        copied = _mapping_from_bytes(encoded)
        return cls(
            generator_id=cast(str, copied["generator_id"]),
            generator_version=cast(str, copied["generator_version"]),
            generator_record_sha256=cast(str, copied["generator_record_sha256"]),
            generated_input_sha256=cast(str, copied["generated_input_sha256"]),
            complete_truth_sha256=cast(str, copied["complete_truth_sha256"]),
            complete_truth_record_id=cast(str, copied["complete_truth_record_id"]),
            scenario_id=cast(str, copied["scenario_id"]),
            replicate=cast(int, copied["replicate"]),
            seed=cast(str, copied["seed"]),
            participant_count=cast(int, copied["participant_count"]),
            event_count=cast(int, copied["event_count"]),
            event_ids=tuple(cast(list[str], copied["event_ids"])),
        )

    def to_mapping(self) -> dict[str, object]:
        """Return a fresh mapping for a dataset descriptor or Fit result."""

        return {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "generator_id": self.generator_id,
            "generator_version": self.generator_version,
            "generator_record_sha256": self.generator_record_sha256,
            "generated_input_sha256": self.generated_input_sha256,
            "complete_truth_sha256": self.complete_truth_sha256,
            "complete_truth_record_id": self.complete_truth_record_id,
            "scenario_id": self.scenario_id,
            "replicate": self.replicate,
            "seed": self.seed,
            "source_kind": self.source_kind,
            "participant_data_present": self.participant_data_present,
            "external_source_present": self.external_source_present,
            "participant_count": self.participant_count,
            "event_count": self.event_count,
            "event_ids": list(self.event_ids),
        }


def _validated_bytes(
    value: object,
    *,
    schema_name: str,
    definition: str,
    phase: str,
    field: str,
) -> bytes:
    try:
        encoded = canonical_json_bytes(value)
        copied = strict_json_loads(encoded)
        validate_instance(copied, schema_name, definition=definition)
        return encoded
    except Exception:
        raise SDKValidationError(phase=phase, field=field) from None


def _mapping_from_bytes(value: bytes) -> dict[str, Any]:
    decoded = strict_json_loads(value)
    if not isinstance(decoded, dict):  # protected by construction-time validation
        raise RuntimeError("The validated SDK record is not a mapping.")
    return decoded


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """One public digest reference used to support worker identity."""

    kind: str
    digest: str
    note: str = ""

    def to_mapping(self) -> dict[str, object]:
        value: dict[str, object] = {
            "kind": self.kind,
            "digest": self.digest,
            "note": self.note,
        }
        _validated_bytes(
            value,
            schema_name="canonical-records.schema.json",
            definition="EvidenceReference",
            phase="identity-validation",
            field="identity_evidence",
        )
        return value


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    """Complete immutable identity material for one local adapter process."""

    adapter_id: str
    adapter_version: str
    worker_executable_digest: str
    worker_code_digest: str
    backend_name: str
    backend_version: str | None
    backend_source_commit: str | None
    backend_source_digest: str | None
    environment_digest: str
    identity_evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        self.for_algorithm(None)

    def for_algorithm(self, algorithm_id: str | None) -> dict[str, object]:
        """Return the exact canonical identity mapping for a worker callback."""

        value: dict[str, object] = {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "worker_executable_digest": self.worker_executable_digest,
            "worker_code_digest": self.worker_code_digest,
            "backend_name": self.backend_name,
            "backend_version": self.backend_version,
            "backend_source_commit": self.backend_source_commit,
            "backend_source_digest": self.backend_source_digest,
            "environment_digest": self.environment_digest,
            "algorithm_id": algorithm_id,
            "identity_evidence": [item.to_mapping() for item in self.identity_evidence],
        }
        _validated_bytes(
            value,
            schema_name="canonical-records.schema.json",
            definition="BackendIdentity",
            phase="identity-validation",
            field="backend_identity",
        )
        return value


@dataclass(frozen=True, slots=True)
class CapabilityLimits:
    """Closed participant, event, thread, and iteration limits for an adapter."""

    minimum_participants: int
    minimum_events: int
    maximum_threads: int
    maximum_participants: int | None = None
    maximum_events: int | None = None
    required_group_roles: tuple[Literal["reference", "at_risk"], ...] = ()
    maximum_raw_iterations: int | None = None

    def to_mapping(self) -> dict[str, object]:
        return {
            "minimum_participants": self.minimum_participants,
            "maximum_participants": self.maximum_participants,
            "minimum_events": self.minimum_events,
            "maximum_events": self.maximum_events,
            "required_group_roles": list(self.required_group_roles),
            "maximum_threads": self.maximum_threads,
            "maximum_raw_iterations": self.maximum_raw_iterations,
        }


@dataclass(frozen=True, slots=True)
class UnavailableOutput:
    """An output that is explicitly not applicable because capability is absent."""

    output_id: Literal[
        "evaluation_stage_posterior",
        "evaluation_hard_stages",
        "evaluation_expected_stage",
    ]

    def to_mapping(self) -> dict[str, object]:
        return {
            "output_id": self.output_id,
            "status": "NOT_APPLICABLE_BY_CAPABILITY",
            "value": None,
            "reason_code": "STAGING.FIXED_COHORT_UNAVAILABLE",
        }


@dataclass(frozen=True, slots=True)
class CapabilityDeclaration:
    """Schema-validated capabilities with fail-closed requested-output checks."""

    _canonical_bytes: bytes = field(repr=False)

    @classmethod
    def limited(
        cls,
        *,
        limits: CapabilityLimits,
        enabled: Iterable[CapabilityName] = (),
    ) -> Self:
        """Build a declaration where every capability not named is false.

        Missing values are never inferred from output data. The protocol-fixed
        policies remain ``missing_values=REJECT``, no per-feature missingness,
        and local offline execution.
        """

        enabled_set = frozenset(enabled)
        if not enabled_set <= _CAPABILITY_NAMES:
            raise SDKValidationError(
                phase="capability-validation",
                field="capabilities.enabled",
            )
        value: dict[str, object] = {
            "capabilities_schema_version": "ebm-audit-worker-capabilities/1.0",
            **{name: name in enabled_set for name in sorted(_CAPABILITY_NAMES)},
            "missing_values": "REJECT",
            "per_feature_missingness": False,
            "offline_execution": True,
            "constraints": limits.to_mapping(),
        }
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Self:
        """Admit an exact existing capabilities mapping without changing it."""

        return cls(
            _validated_bytes(
                value,
                schema_name="worker-protocol.schema.json",
                definition="AdapterCapabilities",
                phase="capability-validation",
                field="capabilities",
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        """Return a fresh mutable copy for the existing worker protocol."""

        return _mapping_from_bytes(self._canonical_bytes)

    def assess_requested_outputs(
        self,
        requested_outputs: Iterable[str],
    ) -> tuple[UnavailableOutput, ...]:
        """Reject unsupported outputs or return explicit fixed-stage absences.

        The three fixed-evaluation staging outputs are the protocol's only
        capability-absence-as-not-applicable cases. Every other missing
        capability is a typed failure, never an invented result.
        """

        requested = tuple(requested_outputs)
        if len(requested) != len(set(requested)):
            raise SDKValidationError(
                phase="capability-validation",
                field="requested_outputs",
            )
        registry = load_protocol_registry().get("requested_outputs")
        if not isinstance(registry, list):
            raise SDKValidationError(
                phase="capability-validation",
                field="requested_output_registry",
            )
        rows = {
            row.get("output_id"): row
            for row in registry
            if isinstance(row, Mapping) and isinstance(row.get("output_id"), str)
        }
        capabilities = self.to_mapping()
        not_applicable: list[UnavailableOutput] = []
        unsupported_count = 0
        for output_id in requested:
            row = rows.get(output_id)
            if not isinstance(row, Mapping):
                raise SDKValidationError(
                    phase="capability-validation",
                    field="requested_outputs",
                )
            required = row.get("required_capabilities")
            if not isinstance(required, list) or any(
                not isinstance(name, str) for name in required
            ):
                raise SDKValidationError(
                    phase="capability-validation",
                    field="requested_output_registry",
                )
            missing = [name for name in required if capabilities.get(name) is not True]
            if not missing:
                continue
            if (
                missing == ["fixed_evaluation_cohort_staging"]
                and row.get("capability_absence_behavior")
                == "FIXED_COHORT_STAGE_COMPONENT_NOT_APPLICABLE"
            ):
                not_applicable.append(
                    UnavailableOutput(
                        cast(
                            Literal[
                                "evaluation_stage_posterior",
                                "evaluation_hard_stages",
                                "evaluation_expected_stage",
                            ],
                            output_id,
                        )
                    )
                )
            else:
                unsupported_count += 1
        if unsupported_count:
            raise WorkerFailure(
                status="UNSUPPORTED_CAPABILITY",
                code="CAPABILITY.OUTPUT_UNSUPPORTED",
                safe_message="One or more requested outputs are unavailable.",
                phase="capability-validation",
                counts={"unsupported_output_count": unsupported_count},
            )
        return tuple(not_applicable)


@dataclass(frozen=True, slots=True)
class SafeDetails:
    """Privacy-safe counts, internal indexes, approved IDs, and digests."""

    counts: tuple[tuple[str, int], ...] = ()
    internal_indexes: tuple[int, ...] = ()
    approved_event_ids: tuple[str, ...] = ()
    digests: tuple[tuple[str, str], ...] = ()

    def to_mapping(self) -> dict[str, object]:
        return {
            "counts": dict(self.counts),
            "internal_indexes": list(self.internal_indexes),
            "approved_event_ids": list(self.approved_event_ids),
            "digests": dict(self.digests),
        }


@dataclass(frozen=True, slots=True)
class WarningRecord:
    """One typed warning passed through the existing privacy normalizer."""

    code: str
    severity: Literal["INFO", "WARNING", "SEVERE"]
    safe_message: str
    details: SafeDetails = SafeDetails()

    def to_mapping(self) -> dict[str, Any]:
        value = {
            "code": self.code,
            "severity": self.severity,
            "safe_message": self.safe_message,
            "details": self.details.to_mapping(),
        }
        encoded = _validated_bytes(
            value,
            schema_name="canonical-records.schema.json",
            definition="WarningRecord",
            phase="warning-validation",
            field="warning",
        )
        return _mapping_from_bytes(encoded)


@dataclass(frozen=True, slots=True)
class ArrayReference:
    """One canonical in-memory array and its protocol catalog declaration."""

    member_name: str
    value: Any = field(repr=False, compare=False)
    semantic_version: str

    def __post_init__(self) -> None:
        try:
            array = canonical_array(self.value).copy(order="C")
            array.flags.writeable = False
            catalog = array_catalog_entry(
                self.member_name,
                array,
                semantic_version=self.semantic_version,
            )
            validate_instance(
                catalog,
                "canonical-records.schema.json",
                definition="ArrayCatalogEntry",
            )
        except Exception:
            raise SDKValidationError(
                phase="array-validation",
                field="array_reference",
            ) from None
        object.__setattr__(self, "value", array)

    def catalog_entry(self) -> dict[str, Any]:
        """Return the canonical array-catalog entry."""

        return array_catalog_entry(
            self.member_name,
            self.value,
            semantic_version=self.semantic_version,
        )


@dataclass(frozen=True, slots=True)
class StageReference:
    """A thin, schema-validated canonical stage-model reference."""

    _canonical_bytes: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, reference: Mapping[str, Any]) -> Self:
        return cls(
            _validated_bytes(
                reference,
                schema_name="canonical-records.schema.json",
                definition="StageModelReference",
                phase="stage-reference-validation",
                field="stage_reference",
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return _mapping_from_bytes(self._canonical_bytes)


@dataclass(frozen=True, slots=True)
class ChainResult:
    """A thin, schema-validated canonical per-chain Fit result."""

    _canonical_bytes: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, result: Mapping[str, Any]) -> Self:
        return cls(
            _validated_bytes(
                result,
                schema_name="worker-protocol.schema.json",
                definition="WorkerFitPayload",
                phase="chain-result-validation",
                field="chain_result",
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return _mapping_from_bytes(self._canonical_bytes)


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    """A thin, schema-validated canonical fitted-artifact reference."""

    _canonical_bytes: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, reference: Mapping[str, Any]) -> Self:
        return cls(
            _validated_bytes(
                reference,
                schema_name="canonical-records.schema.json",
                definition="ArtifactReference",
                phase="artifact-reference-validation",
                field="artifact_reference",
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return _mapping_from_bytes(self._canonical_bytes)


@dataclass(frozen=True, slots=True)
class FitSuccess:
    """A thin, schema-validated complete Fit-success payload."""

    _canonical_bytes: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            _validated_bytes(
                payload,
                schema_name="worker-protocol.schema.json",
                definition="FitSuccessPayload",
                phase="fit-result-validation",
                field="fit_result",
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return _mapping_from_bytes(self._canonical_bytes)

    def as_worker_result(
        self,
        *,
        arrays: Mapping[str, Any] | None = None,
        array_archive: Path | None = None,
        warnings: Iterable[WarningRecord | Mapping[str, Any]] | None = None,
    ) -> WorkerSuccess | WorkerFailure:
        """Return the existing callback result after channel validation."""

        from .mapping import map_fit_result

        return map_fit_result(
            self.to_mapping(),
            arrays=arrays,
            array_archive=array_archive,
            warnings=warnings,
        )


@dataclass(frozen=True, slots=True)
class DescribeSuccess:
    """An immutable, schema-valid Describe result builder."""

    _canonical_bytes: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, result: Mapping[str, Any]) -> Self:
        return cls(
            _validated_bytes(
                result,
                schema_name="worker-protocol.schema.json",
                definition="DescribeResult",
                phase="describe-validation",
                field="result",
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return _mapping_from_bytes(self._canonical_bytes)

    def as_worker_success(self) -> WorkerSuccess:
        """Return the established callback success type."""

        return WorkerSuccess(payload={"result": self.to_mapping()})


@dataclass(frozen=True, slots=True)
class ValidateSuccess:
    """An immutable, schema-valid Validate payload builder."""

    _canonical_bytes: bytes = field(repr=False)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> Self:
        return cls(
            _validated_bytes(
                payload,
                schema_name="worker-protocol.schema.json",
                definition="ValidateSuccessPayload",
                phase="validate-validation",
                field="payload",
            )
        )

    def to_mapping(self) -> dict[str, Any]:
        return _mapping_from_bytes(self._canonical_bytes)

    def as_worker_success(
        self,
        *,
        warnings: Iterable[WarningRecord] = (),
    ) -> WorkerSuccess:
        """Return the established callback success type."""

        return WorkerSuccess(
            payload=self.to_mapping(),
            warnings=tuple(warning.to_mapping() for warning in warnings),
        )
