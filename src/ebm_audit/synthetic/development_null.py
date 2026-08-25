"""One exact development-only generated-input transaction.

This module does not add a second source-admission path.  It converts the one
accepted registered pure-no-signal development case into deterministic CSV
bytes and an ordinary AuditConfig, then requires the existing exact-file
verification and preparation owners before exposing anything to execution.
Generator truth can be projected only after the exact result-evidence set is
terminal and sealed.
"""

from __future__ import annotations

import os
import stat
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock
from typing import Any, Final, Never, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.artifacts import StagedOutputTransaction
from ebm_audit.artifacts.store import (
    _DIRECTORY_OPEN_FLAGS,
    _validate_private_directory_descriptor,
)
from ebm_audit.config import (
    RunEligibleAuditConfig,
    VerifiedAuditConfigFiles,
    authorize_audit_config_run,
    load_audit_config,
    verify_audit_config_files,
)
from ebm_audit.config.models import ResolvedAuditConfig
from ebm_audit.data import PreparedAuditDataset, prepare_audit_dataset
from ebm_audit.errors import InvalidInputError, UnexpectedCoreError
from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
    structured_sha256,
)
from ebm_audit.results import SealedResultEvidenceSet, project_terminal_ledgers
from ebm_audit.results.persistence import _sealed_result_evidence_run
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.science import SealedScientificEvidence, project_scientific_evidence
from ebm_audit.universe.preparation import _resolve_prepared_execution_authorization

from .audit_input import (
    _assert_exact_generated_prepared_semantics as _assert_generic_prepared_semantics,
)
from .audit_input import _compile_input_analysis_spec, _read_exact_source_inputs
from .audit_input import _derived_config as _derive_generic_config
from .audit_input import _serialize_generated_csv as _serialize_generic_csv
from .authority import ScenarioAuthority, load_scenario_authority
from .generator import generate_synthetic_case
from .models import (
    CaseCoordinate,
    ReplayReceipt,
    ResolvedSyntheticCase,
    SyntheticCaseArtifacts,
)
from .replay import replay_synthetic_case
from .resolver import resolve_development_case, verify_exact_resolution

_FAMILY_ID: Final = "pure_no_signal"
_VARIANT_ID: Final = "null_correlated"
_DEVELOPMENT_REPLICATE_COUNT: Final = 59
_PRIVATE_DIRECTORY = "_development-null-input"
_PRIVATE_CONFIG = "audit.json"
_PRIVATE_CSV = "source.csv"
_PRIVATE_WORKER = "worker.json"
_PRIVATE_NAMES = frozenset({_PRIVATE_CONFIG, _PRIVATE_CSV, _PRIVATE_WORKER})
_REPLAY_RECEIPT_DOMAIN = "ebm-audit/synthetic-replay-receipt/1"
_MAPPING_DOMAIN = "ebm-audit/development-null-csv-mapping/1"
_TERMINAL_BINDING_DOMAIN = "ebm-audit/development-null-terminal-binding/1"
_RECEIPT_DOMAIN = "ebm-audit/development-null-receipt/1"
_SCIENCE_RECEIPT_DOMAIN = "ebm-audit/development-null-science-receipt/1"
_GROUP_BINDINGS: Final = (
    ("reference", "development-label-0001", "reference"),
    ("at_risk", "development-label-0002", "at_risk"),
)
_TERMINAL_STATUSES = (
    "SUCCESS",
    "CONVERGENCE_WARN",
    "INVALID_INPUT",
    "UNSUPPORTED_CAPABILITY",
    "INVALID_SPECIFICATION",
    "BACKEND_ERROR",
    "TIMEOUT",
    "CONVERGENCE_FAILED",
    "CONVERGENCE_NOT_ASSESSABLE",
    "PRIVACY_VIOLATION",
    "PROTOCOL_ERROR",
)


def _invalid(code: str) -> InvalidInputError:
    return InvalidInputError(
        code,
        "The development-only null input request is invalid.",
    )


def _development_coordinate(replicate_index: object) -> CaseCoordinate:
    if type(replicate_index) is not int or not 0 <= replicate_index < _DEVELOPMENT_REPLICATE_COUNT:
        raise _invalid("DEVELOPMENT.NULL_REPLICATE_INDEX_INVALID")
    return CaseCoordinate(
        _FAMILY_ID,
        _VARIANT_ID,
        replicate_index,
        "DEVELOPMENT_VARIANT",
    )


def _public_digest_from_generator_hex(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _invalid("DEVELOPMENT.NULL_GENERATOR_DIGEST_INVALID")
    return "sha256:" + value


@dataclass(frozen=True, slots=True)
class ClosedSyntheticReplayReceipt:
    """Closed MATCH-only replay evidence retained by the transaction."""

    compared_stage_count: int
    stage_ledger_digest: str
    receipt_digest: str
    replay_receipt_schema_version: str = "ebm-audit-synthetic-replay-receipt/1.0"
    status: str = "MATCH"
    data_match: bool = True
    truth_match: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "replay_receipt_schema_version": self.replay_receipt_schema_version,
            "status": self.status,
            "compared_stage_count": self.compared_stage_count,
            "data_match": self.data_match,
            "truth_match": self.truth_match,
            "stage_ledger_digest": self.stage_ledger_digest,
            "receipt_digest": self.receipt_digest,
        }


def _close_replay_receipt(
    receipt: ReplayReceipt,
    artifacts: SyntheticCaseArtifacts,
) -> ClosedSyntheticReplayReceipt:
    if (
        type(receipt) is not ReplayReceipt
        or receipt.status != "MATCH"
        or receipt.first_mismatch_stage is not None
        or receipt.expected_stage_sha256 is not None
        or receipt.candidate_stage_sha256 is not None
        or receipt.data_match is not True
        or receipt.truth_match is not True
        or receipt.compared_stage_count != len(artifacts.stage_snapshots)
        or receipt.compared_stage_count < 1
    ):
        raise _invalid("DEVELOPMENT.NULL_REPLAY_FAILED")
    ledger = [
        {
            "stage_index": row.stage_index,
            "stage_id": row.stage_id,
            "output_sha256": row.output_sha256,
        }
        for row in artifacts.stage_snapshots
    ]
    stage_ledger_digest = structured_sha256(
        "ebm-audit/synthetic-replay-stage-ledger/1",
        ledger,
    )
    preimage = {
        "replay_receipt_schema_version": "ebm-audit-synthetic-replay-receipt/1.0",
        "status": "MATCH",
        "compared_stage_count": receipt.compared_stage_count,
        "data_match": True,
        "truth_match": True,
        "stage_ledger_digest": stage_ledger_digest,
    }
    closed = ClosedSyntheticReplayReceipt(
        compared_stage_count=receipt.compared_stage_count,
        stage_ledger_digest=stage_ledger_digest,
        receipt_digest=structured_sha256(_REPLAY_RECEIPT_DOMAIN, preimage),
    )
    try:
        validate_instance(
            closed.as_dict(),
            "development-null-receipt.schema.json",
            definition="ClosedSyntheticReplayReceipt",
        )
    except SchemaValidationError:
        raise _invalid("DEVELOPMENT.NULL_REPLAY_RECEIPT_INVALID") from None
    return closed


def _exact_enabled_null_declaration(
    config: Mapping[str, Any],
    *,
    profile_id: str,
) -> Mapping[str, Any]:
    descriptor = config.get("development_scenario_authority")
    experiments = config.get("experiments")
    profiles = config.get("profiles")
    baseline = config.get("baseline_analysis")
    if (
        type(descriptor) is not dict
        or set(descriptor) != {"path", "expected_byte_digest"}
        or type(experiments) is not dict
        or type(profiles) is not dict
        or type(baseline) is not dict
        or profile_id not in {"quick", "full", "release"}
    ):
        raise _invalid("DEVELOPMENT.NULL_INTENT_INVALID")
    selected_profile = profiles.get(profile_id)
    sets = experiments.get("sets")
    if type(selected_profile) is not dict or type(sets) is not list:
        raise _invalid("DEVELOPMENT.NULL_INTENT_INVALID")
    enabled = [row for row in sets if type(row) is dict and row.get("enabled") is True]
    baseline_sets = [row for row in enabled if row.get("mode") == "baseline"]
    null_sets = [row for row in enabled if row.get("mode") == "null"]
    if (
        len(enabled) != 2
        or len(baseline_sets) != 1
        or len(null_sets) != 1
        or baseline.get("operation_intent") != {"kind": "ordinary"}
        or baseline.get("preprocessing") != []
        or cast(Mapping[str, Any], baseline.get("covariate_adjustment", {})).get("method") != "none"
        or cast(Mapping[str, Any], baseline.get("outlier_policy", {})).get("policy_kind") != "none"
        or selected_profile.get("null_replicates_per_family") != 1
        or selected_profile.get("bootstrap_replicates") != 0
        or selected_profile.get("subsample_replicates") != 0
        or selected_profile.get("influence_max_removals") != 0
    ):
        raise _invalid("DEVELOPMENT.NULL_INTENT_OUT_OF_SCOPE")
    families = null_sets[0].get("null_families")
    if type(families) is not list or len(families) != 1 or type(families[0]) is not dict:
        raise _invalid("DEVELOPMENT.NULL_INTENT_OUT_OF_SCOPE")
    family = cast(Mapping[str, Any], families[0])
    if (
        family.get("null_family_id") != "pure-no-signal"
        or family.get("null_method_id") != "pure-no-signal-synthetic/1"
        or family.get("transformation") != "pure-no-signal-synthetic"
        or family.get("within_group_spec_id") is not None
        or family.get("refit_preprocessing") is not True
        or family.get("preserves_group_conditional_event_marginals") is not False
    ):
        raise _invalid("DEVELOPMENT.NULL_INTENT_OUT_OF_SCOPE")
    return family


def is_development_null_run(config: ResolvedAuditConfig) -> bool:
    """Return whether the config asks the closed development transaction to run."""

    if type(config) is not ResolvedAuditConfig:
        return False
    return config.private_paths.development_scenario_authority is not None


def _read_exact_inputs(
    resolved: ResolvedAuditConfig,
) -> tuple[bytes, bytes, bytes]:
    try:
        return _read_exact_source_inputs(resolved)
    except InvalidInputError:
        raise _invalid("DEVELOPMENT.NULL_DECLARED_FILE_MISMATCH") from None


def _serialize_generated_csv(
    artifacts: SyntheticCaseArtifacts,
) -> tuple[bytes, dict[str, Any]]:
    try:
        return _serialize_generic_csv(artifacts, participant_namespace=None)
    except InvalidInputError:
        raise _invalid("DEVELOPMENT.NULL_DATA_INVALID") from None


def _derived_config(
    source: Mapping[str, Any],
    artifacts: SyntheticCaseArtifacts,
    csv_bytes: bytes,
    mapping: Mapping[str, Any],
) -> dict[str, Any]:
    baseline = _compile_input_analysis_spec(
        cast(Mapping[str, Any], source["baseline_analysis"]),
        mapping,
    )
    return _derive_generic_config(
        source,
        artifacts,
        csv_bytes,
        mapping,
        baseline,
        cast(str, cast(Mapping[str, Any], source["worker"])["worker_config_digest"]),
        cast(str, cast(Mapping[str, Any], source["randomness"])["master_seed"]),
    )


@dataclass(slots=True, repr=False)
class _TransactionState:
    source_config: ResolvedAuditConfig
    staging: StagedOutputTransaction
    authority_bytes: bytes
    authority: ScenarioAuthority | None
    resolved_case: ResolvedSyntheticCase | None
    generated_artifacts: SyntheticCaseArtifacts | None
    replay_receipt: ClosedSyntheticReplayReceipt
    csv_bytes: bytes
    mapping: dict[str, Any]
    mapping_digest: str
    verified: VerifiedAuditConfigFiles
    authorized: RunEligibleAuditConfig
    prepared: PreparedAuditDataset
    lock: RLock
    receipt_issued: bool = False
    private_inputs_removed: bool = False


@final
class SealedGeneratedAuditInputTransaction:
    """Opaque one-shot owner of the generated input and its ordinary admission."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "Generated audit-input transactions are issued by the development null boundary."
        )

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Generated audit-input transactions cannot be subclassed.")

    def __repr__(self) -> str:
        _transaction_state(self)
        return "SealedGeneratedAuditInputTransaction(<opaque one-shot development owner>)"

    @property
    def authorized_config(self) -> RunEligibleAuditConfig:
        state = _transaction_state(self)
        with state.lock:
            if state.private_inputs_removed:
                raise TypeError("Generated input transaction files are closed.")
            state.authorized.assert_ready()
            return state.authorized

    @property
    def verified_config_files(self) -> VerifiedAuditConfigFiles:
        state = _transaction_state(self)
        with state.lock:
            if state.private_inputs_removed:
                raise TypeError("Generated input transaction files are closed.")
            state.verified.assert_unchanged()
            return state.verified

    @property
    def prepared_dataset(self) -> PreparedAuditDataset:
        state = _transaction_state(self)
        with state.lock:
            return state.prepared

    def __copy__(self) -> Never:
        raise TypeError("Generated audit-input transactions cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Generated audit-input transactions cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Generated audit-input transactions cannot be serialized.")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("Generated audit-input transactions cannot be serialized.")


_TRANSACTION_STATES: OneShotWeakRegistry[
    SealedGeneratedAuditInputTransaction,
    _TransactionState,
]
_TRANSACTION_STATE_ISSUER: OneShotRegistryIssuer[
    SealedGeneratedAuditInputTransaction,
    _TransactionState,
]
(_TRANSACTION_STATES, _TRANSACTION_STATE_ISSUER) = create_one_shot_registry()


def _transaction_state(value: object) -> _TransactionState:
    if type(value) is not SealedGeneratedAuditInputTransaction:
        raise TypeError("A genuine generated audit-input transaction is required.")
    try:
        state = _TRANSACTION_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine generated audit-input transaction is required.") from None
    if type(state) is not _TransactionState:
        raise TypeError("A genuine generated audit-input transaction is required.")
    return state


@final
class DevelopmentNullReceipt:
    """Opaque digest/count/status projection issued only after terminal sealing."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Development-null receipts are issued by an exact transaction.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Development-null receipts cannot be subclassed.")

    def __repr__(self) -> str:
        projection = project_development_null_receipt(self)
        return (
            "DevelopmentNullReceipt("
            f"calibration_state={projection['calibration_state']!r}, "
            f"receipt_digest={projection['receipt_digest']!r})"
        )

    def __copy__(self) -> Never:
        raise TypeError("Development-null receipts cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Development-null receipts cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Development-null receipts cannot be serialized.")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("Development-null receipts cannot be serialized.")


@dataclass(slots=True)
class _DevelopmentNullReceiptState:
    result_evidence: SealedResultEvidenceSet
    canonical_bytes: bytes
    lock: RLock
    science_receipt_issued: bool = False


_RECEIPT_STATES: OneShotWeakRegistry[
    DevelopmentNullReceipt,
    _DevelopmentNullReceiptState,
]
_RECEIPT_STATE_ISSUER: OneShotRegistryIssuer[
    DevelopmentNullReceipt,
    _DevelopmentNullReceiptState,
]
(_RECEIPT_STATES, _RECEIPT_STATE_ISSUER) = create_one_shot_registry()


def _development_null_receipt_state(value: object) -> _DevelopmentNullReceiptState:
    if type(value) is not DevelopmentNullReceipt:
        raise TypeError("A genuine development-null receipt is required.")
    try:
        state = _RECEIPT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine development-null receipt is required.") from None
    if type(state) is not _DevelopmentNullReceiptState:
        raise TypeError("A genuine development-null receipt is required.")
    return state


def project_development_null_receipt(value: object) -> dict[str, Any]:
    state = _development_null_receipt_state(value)
    content = state.canonical_bytes
    projection = strict_json_loads(content)
    if type(projection) is not dict or canonical_json_bytes(projection) != content:
        raise TypeError("Development-null receipt storage is invalid.")
    preimage = dict(projection)
    receipt_digest = preimage.pop("receipt_digest", None)
    if receipt_digest != structured_sha256(_RECEIPT_DOMAIN, preimage):
        raise TypeError("Development-null receipt storage is invalid.")
    try:
        validate_instance(
            projection,
            "development-null-receipt.schema.json",
            definition="DevelopmentNullReceipt",
        )
    except SchemaValidationError:
        raise TypeError("Development-null receipt storage is invalid.") from None
    assert_no_direct_identifier_fields(projection)
    return cast(dict[str, Any], projection)


@final
class SealedDevelopmentNullScienceReceipt:
    """Opaque canonical science projection retaining both genuine sealed owners."""

    __slots__ = ("__weakref__",)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Development-null science receipts are issued from exact sealed owners.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Development-null science receipts cannot be subclassed.")

    def __repr__(self) -> str:
        projection = project_development_null_science_receipt(self)
        return (
            f"SealedDevelopmentNullScienceReceipt(receipt_digest={projection['receipt_digest']!r})"
        )

    def __copy__(self) -> Never:
        raise TypeError("Development-null science receipts cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Development-null science receipts cannot be copied.")

    def __reduce__(self) -> Never:
        raise TypeError("Development-null science receipts cannot be serialized.")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("Development-null science receipts cannot be serialized.")


@dataclass(frozen=True, slots=True)
class _DevelopmentNullScienceReceiptState:
    result_evidence: SealedResultEvidenceSet
    scientific_evidence: SealedScientificEvidence
    development_null_receipt: DevelopmentNullReceipt
    canonical_bytes: bytes


_SCIENCE_RECEIPT_STATES: OneShotWeakRegistry[
    SealedDevelopmentNullScienceReceipt,
    _DevelopmentNullScienceReceiptState,
]
_SCIENCE_RECEIPT_STATE_ISSUER: OneShotRegistryIssuer[
    SealedDevelopmentNullScienceReceipt,
    _DevelopmentNullScienceReceiptState,
]
(_SCIENCE_RECEIPT_STATES, _SCIENCE_RECEIPT_STATE_ISSUER) = create_one_shot_registry()


def _science_receipt_projection(
    scientific_evidence: SealedScientificEvidence,
    development_null_receipt: DevelopmentNullReceipt,
) -> dict[str, Any]:
    scientific = project_scientific_evidence(scientific_evidence)
    development_null = project_development_null_receipt(development_null_receipt)
    if (
        scientific.get("plan_digest") != development_null["plan_digest"]
        or scientific.get("terminal_index_digest") != development_null["terminal_index_digest"]
        or len(cast(list[object], scientific.get("candidate_records")))
        != development_null["candidate_count"]
    ):
        raise UnexpectedCoreError(
            "DEVELOPMENT.NULL_SCIENCE_BINDING",
            "Development-null evidence is detached from its sealed science owner.",
        )
    preimage: dict[str, Any] = {
        "development_null_science_receipt_schema_version": (
            "ebm-audit-development-null-science-receipt/1.0"
        ),
        "scientific_evidence": scientific,
        "development_null": development_null,
    }
    projection = {
        **preimage,
        "receipt_digest": structured_sha256(_SCIENCE_RECEIPT_DOMAIN, preimage),
    }
    assert_no_direct_identifier_fields(projection)
    try:
        validate_instance(
            projection,
            "development-null-receipt.schema.json",
            definition="DevelopmentNullScienceReceipt",
        )
    except SchemaValidationError:
        raise UnexpectedCoreError(
            "DEVELOPMENT.NULL_SCIENCE_RECEIPT_INVALID",
            "Development-null science evidence failed its closed public contract.",
        ) from None
    return projection


def seal_development_null_science_receipt(
    evidence: SealedResultEvidenceSet,
    scientific_evidence: SealedScientificEvidence,
    development_null_receipt: DevelopmentNullReceipt,
) -> SealedDevelopmentNullScienceReceipt:
    """Retain one exact result/science/null authority graph behind one owner."""

    if (
        type(evidence) is not SealedResultEvidenceSet
        or type(scientific_evidence) is not SealedScientificEvidence
        or type(development_null_receipt) is not DevelopmentNullReceipt
    ):
        raise TypeError("Exact sealed development-null science owners are required.")
    receipt_state = _development_null_receipt_state(development_null_receipt)
    if receipt_state.result_evidence is not evidence:
        raise TypeError("Development-null science owners do not share one result run.")
    # This public result projection performs the result subsystem's exact
    # identity check against the science seal's ledger receipt.  Its bytes are
    # not retained here; the wrapper owns the one canonical science projection.
    project_terminal_ledgers(
        evidence,
        sealed_scientific_evidence=scientific_evidence,
    )
    projection = _science_receipt_projection(
        scientific_evidence,
        development_null_receipt,
    )
    with receipt_state.lock:
        if receipt_state.science_receipt_issued:
            raise TypeError("Development-null receipt has already issued its science owner.")
        receipt = object.__new__(SealedDevelopmentNullScienceReceipt)
        state = _DevelopmentNullScienceReceiptState(
            result_evidence=evidence,
            scientific_evidence=scientific_evidence,
            development_null_receipt=development_null_receipt,
            canonical_bytes=canonical_json_bytes(projection),
        )
        _SCIENCE_RECEIPT_STATE_ISSUER.bind_once(receipt, state)
        receipt_state.science_receipt_issued = True
        return receipt


def project_development_null_science_receipt(
    value: object,
    *,
    evidence: SealedResultEvidenceSet | None = None,
) -> dict[str, Any]:
    """Project only after revalidating both exact retained owner identities."""

    state = _read_development_null_science_receipt_state(value)
    if evidence is not None and state.result_evidence is not evidence:
        raise TypeError("Development-null science receipt storage is invalid.")
    projection = strict_json_loads(state.canonical_bytes)
    if type(projection) is not dict:
        raise TypeError("Development-null science receipt storage is invalid.")
    return cast(dict[str, Any], projection)


def _read_development_null_science_receipt_state(
    value: object,
) -> _DevelopmentNullScienceReceiptState:
    """Return both retained live owners after complete receipt revalidation."""

    if type(value) is not SealedDevelopmentNullScienceReceipt:
        raise TypeError("A genuine development-null science receipt is required.")
    try:
        state = _SCIENCE_RECEIPT_STATES[value]
    except (KeyError, TypeError):
        raise TypeError("A genuine development-null science receipt is required.") from None
    if type(state) is not _DevelopmentNullScienceReceiptState:
        raise TypeError("Development-null science receipt storage is invalid.")
    project_terminal_ledgers(
        state.result_evidence,
        sealed_scientific_evidence=state.scientific_evidence,
    )
    projection = _science_receipt_projection(
        state.scientific_evidence,
        state.development_null_receipt,
    )
    if canonical_json_bytes(projection) != state.canonical_bytes:
        raise TypeError("Development-null science receipt storage is invalid.")
    try:
        _SCIENCE_RECEIPT_STATES.require(value, state)
    except (KeyError, TypeError):
        raise TypeError("Development-null science receipt storage is invalid.") from None
    return state


def _read_development_null_scientific_evidence(
    value: object,
    *,
    evidence: SealedResultEvidenceSet,
) -> SealedScientificEvidence:
    """Return the exact retained science owner after full receipt revalidation."""

    state = _read_development_null_science_receipt_state(value)
    if (
        type(state) is not _DevelopmentNullScienceReceiptState
        or state.result_evidence is not evidence
        or type(state.scientific_evidence) is not SealedScientificEvidence
    ):
        raise TypeError("Development-null science receipt storage is invalid.")
    return state.scientific_evidence


def _assert_exact_generated_prepared_semantics(
    prepared: PreparedAuditDataset,
    artifacts: SyntheticCaseArtifacts,
    mapping: Mapping[str, Any],
) -> None:
    try:
        _assert_generic_prepared_semantics(prepared, artifacts, mapping)
    except InvalidInputError:
        raise _invalid("DEVELOPMENT.NULL_PREPARED_SEMANTICS_MISMATCH") from None


def open_development_null_transaction(
    resolved: ResolvedAuditConfig,
    staging: StagedOutputTransaction,
    *,
    profile_id: str,
    replicate_index: int = 0,
) -> SealedGeneratedAuditInputTransaction:
    """Resolve, replay, serialize, admit, and prepare one fixed development slot."""

    if type(resolved) is not ResolvedAuditConfig or type(staging) is not StagedOutputTransaction:
        raise _invalid("DEVELOPMENT.NULL_TRANSACTION_INPUT")
    coordinate = _development_coordinate(replicate_index)
    if staging.final_output_path != resolved.private_paths.output_root:
        raise _invalid("DEVELOPMENT.NULL_STAGING_OUTPUT_MISMATCH")
    source = resolved.private_config
    _exact_enabled_null_declaration(source, profile_id=profile_id)
    _config_bytes, authority_bytes, worker_bytes = _read_exact_inputs(resolved)
    authority = load_scenario_authority(authority_bytes)
    case = resolve_development_case(authority, coordinate)
    verify_exact_resolution(authority, case)
    if (
        case.coordinate != coordinate
        or case.shared_draw_seed is not None
        or case.operation_seed is not None
    ):
        raise _invalid("DEVELOPMENT.NULL_RESOLUTION_OUT_OF_SCOPE")
    artifacts = generate_synthetic_case(authority, case)
    replay = _close_replay_receipt(
        replay_synthetic_case(case, artifacts, authority=authority),
        artifacts,
    )
    csv_bytes, mapping = _serialize_generated_csv(artifacts)
    mapping_digest = structured_sha256(_MAPPING_DOMAIN, mapping)
    derived = _derived_config(source, artifacts, csv_bytes, mapping)
    try:
        validate_instance(derived, "audit-config.schema.json", definition="AuditConfig")
    except SchemaValidationError:
        raise _invalid("DEVELOPMENT.NULL_DERIVED_CONFIG_INVALID") from None
    store = staging.store
    store.ensure_directory(_PRIVATE_DIRECTORY)
    store.write_bytes(f"{_PRIVATE_DIRECTORY}/{_PRIVATE_CSV}", csv_bytes)
    store.write_bytes(f"{_PRIVATE_DIRECTORY}/{_PRIVATE_WORKER}", worker_bytes)
    config_bytes = canonical_json_bytes(derived)
    store.write_bytes(f"{_PRIVATE_DIRECTORY}/{_PRIVATE_CONFIG}", config_bytes)
    config_path = store.resolve(f"{_PRIVATE_DIRECTORY}/{_PRIVATE_CONFIG}")
    verified: VerifiedAuditConfigFiles | None = None
    try:
        verified = verify_audit_config_files(load_audit_config(config_path))
        authorized = authorize_audit_config_run(verified)
        prepared = prepare_audit_dataset(authorized)
        _assert_exact_generated_prepared_semantics(
            prepared,
            artifacts,
            mapping,
        )
    except BaseException:
        if verified is not None:
            verified.close()
        raise
    if (
        verified.input_byte_digest != exact_file_sha256(csv_bytes)
        or prepared.source_admission_id != verified.source_admission_id
        or prepared.summary.input_byte_digest != exact_file_sha256(csv_bytes)
        or prepared.summary.participant_count != mapping["participant_count"]
        or prepared.summary.event_count != mapping["event_count"]
        or prepared.summary.covariate_count != mapping["covariate_count"]
        or prepared.summary.dropped_row_count != 0
    ):
        verified.close()
        raise _invalid("DEVELOPMENT.NULL_ORDINARY_ADMISSION_MISMATCH")
    transaction = object.__new__(SealedGeneratedAuditInputTransaction)
    _TRANSACTION_STATE_ISSUER.bind_once(
        transaction,
        _TransactionState(
            source_config=resolved,
            staging=staging,
            authority_bytes=authority_bytes,
            authority=authority,
            resolved_case=case,
            generated_artifacts=artifacts,
            replay_receipt=replay,
            csv_bytes=csv_bytes,
            mapping=mapping,
            mapping_digest=mapping_digest,
            verified=verified,
            authorized=authorized,
            prepared=prepared,
            lock=RLock(),
        ),
    )
    return transaction


def _validated_terminal_result_body(
    result_record: object,
    terminal: Mapping[str, Any],
    *,
    expected_input_digest: str,
) -> tuple[Mapping[str, Any], str]:
    """Return the exact nested result body bound to one terminal projection."""

    body = result_record.get("body") if type(result_record) is dict else None
    if not isinstance(body, Mapping):
        raise UnexpectedCoreError(
            "DEVELOPMENT.NULL_TERMINAL_BINDING",
            "Development-null terminal evidence is detached from its exact input.",
        )
    status = body.get("status")
    if (
        type(status) is not str
        or body.get("input_digest") != expected_input_digest
        or terminal.get("candidate_ordinal") != body.get("candidate_ordinal")
        or terminal.get("candidate_id") != body.get("candidate_id")
        or terminal.get("analysis_spec_id") != body.get("analysis_spec_id")
        or terminal.get("universe_id") != body.get("universe_id")
        or terminal.get("final_status") != status
        or terminal.get("result_id") != cast(Mapping[str, Any], result_record).get("result_id")
    ):
        raise UnexpectedCoreError(
            "DEVELOPMENT.NULL_TERMINAL_BINDING",
            "Development-null terminal evidence is detached from its exact input.",
        )
    return cast(Mapping[str, Any], body), status


def bind_development_null_terminal_evidence(
    transaction: SealedGeneratedAuditInputTransaction,
    evidence: SealedResultEvidenceSet,
) -> DevelopmentNullReceipt:
    """Bind exact terminal/result input identities, then issue the safe receipt."""

    state = _transaction_state(transaction)
    if type(evidence) is not SealedResultEvidenceSet:
        raise TypeError("Exact sealed result evidence is required.")
    with state.lock:
        if state.receipt_issued:
            raise TypeError("Development-null receipt is one-use.")
        run = _sealed_result_evidence_run(evidence)
        if (
            run.preparation_transaction is None
            or len(run.candidate_result_authorizations) != 1
            or len(run.finalized_results) != 1
            or len(run.candidate_terminals) != 1
            or len(run.plan_candidates) != 1
        ):
            raise UnexpectedCoreError(
                "DEVELOPMENT.NULL_TERMINAL_BINDING",
                "Development-null terminal evidence is detached from its exact transaction.",
            )
        authorization_state = _resolve_prepared_execution_authorization(
            run.candidate_result_authorizations[0]
        )
        expected_input_digest = authorization_state.canonical_dataset.scientific_data_digest
        result = strict_json_loads(run.finalized_results[0].canonical_bytes)
        terminal = run.candidate_terminals[0]
        if (
            authorization_state.prepared_dataset is not state.prepared
            or authorization_state.prepared_dataset_id != state.prepared.prepared_dataset_id
            or authorization_state.config_digest != state.authorized.resolved_public_digest
        ):
            raise UnexpectedCoreError(
                "DEVELOPMENT.NULL_TERMINAL_BINDING",
                "Development-null terminal evidence is detached from its exact input.",
            )
        _body, status = _validated_terminal_result_body(
            result,
            terminal,
            expected_input_digest=expected_input_digest,
        )
        terminal_binding = {
            "plan_digest": evidence.plan_digest,
            "terminal_index_digest": evidence.terminal_index_digest,
            "candidate_ordinal": terminal["candidate_ordinal"],
            "candidate_id": terminal["candidate_id"],
            "analysis_spec_id": terminal["analysis_spec_id"],
            "status": terminal["final_status"],
            "result_digest": terminal["result_digest"],
        }
        counts = Counter({name: 0 for name in _TERMINAL_STATUSES})
        if status not in counts:
            raise UnexpectedCoreError(
                "DEVELOPMENT.NULL_TERMINAL_BINDING",
                "Development-null terminal evidence has an unknown outcome.",
            )
        counts[status] += 1
        success_count = counts["SUCCESS"]
        case = state.resolved_case
        artifacts = state.generated_artifacts
        if case is None or artifacts is None:
            raise UnexpectedCoreError(
                "DEVELOPMENT.NULL_TERMINAL_BINDING",
                "Development-null generated evidence is unavailable.",
            )
        preimage: dict[str, Any] = {
            "development_null_receipt_schema_version": ("ebm-audit-development-null-receipt/1.0"),
            "development_scope": "DEVELOPMENT_ONLY",
            "calibration_state": "DEVELOPMENT_UNCALIBRATED",
            "null_relative_label": "NULL_CALIBRATION_NOT_VALIDATED",
            "strong_null_relative_language_eligible": False,
            "held_out_false_positive_rate_eligible": False,
            "family_id": case.coordinate.family_id,
            "variant_id": case.coordinate.variant_id,
            "replicate_index": case.coordinate.replicate_index,
            "resolution_mode": case.coordinate.resolution_mode,
            "null_method_id": "pure-no-signal-synthetic/1",
            "transformation": "pure-no-signal-synthetic",
            "refit_preprocessing": True,
            "preserves_group_conditional_event_marginals": False,
            "case_id": case.case_id,
            "intent_config_digest": state.source_config.public_digest,
            "authority_byte_digest": exact_file_sha256(state.authority_bytes),
            "source_contract_digest": _public_digest_from_generator_hex(
                case.source_contract_sha256
            ),
            "scenario_definitions_digest": _public_digest_from_generator_hex(
                case.scenario_definitions_sha256
            ),
            "resolved_configuration_digest": _public_digest_from_generator_hex(
                case.resolved_configuration["resolved_generator_configuration_sha256"]
            ),
            "resolved_mechanism_digest": _public_digest_from_generator_hex(
                case.resolved_mechanism["resolved_generator_mechanism_sha256"]
            ),
            "generated_data_digest": _public_digest_from_generator_hex(
                artifacts.scientific_data["generated_scientific_data_sha256"]
            ),
            "truth_digest": _public_digest_from_generator_hex(
                artifacts.truth["truth_object_sha256"]
            ),
            "replay_receipt_digest": state.replay_receipt.receipt_digest,
            "mapping_digest": state.mapping_digest,
            "serialized_input_byte_digest": exact_file_sha256(state.csv_bytes),
            "source_admission_digest": state.prepared.source_admission_id,
            "prepared_dataset_digest": state.prepared.prepared_dataset_id,
            "plan_digest": evidence.plan_digest,
            "terminal_index_digest": evidence.terminal_index_digest,
            "terminal_binding_digest": structured_sha256(
                _TERMINAL_BINDING_DOMAIN,
                terminal_binding,
            ),
            "participant_count": state.mapping["participant_count"],
            "event_count": state.mapping["event_count"],
            "covariate_count": state.mapping["covariate_count"],
            "missing_cell_count": state.mapping["missing_cell_count"],
            "generation_stage_count": state.replay_receipt.compared_stage_count,
            "candidate_count": 1,
            "terminal_record_count": 1,
            "success_count": success_count,
            "non_success_terminal_count": 1 - success_count,
            "terminal_status_counts": {name: counts[name] for name in _TERMINAL_STATUSES},
        }
        projection = {
            **preimage,
            "receipt_digest": structured_sha256(_RECEIPT_DOMAIN, preimage),
        }
        assert "input_digest" not in projection
        assert_no_direct_identifier_fields(projection)
        try:
            validate_instance(
                projection,
                "development-null-receipt.schema.json",
                definition="DevelopmentNullReceipt",
            )
        except SchemaValidationError:
            raise UnexpectedCoreError(
                "DEVELOPMENT.NULL_RECEIPT_INVALID",
                "Development-null evidence failed its closed public contract.",
            ) from None
        receipt = object.__new__(DevelopmentNullReceipt)
        _RECEIPT_STATE_ISSUER.bind_once(
            receipt,
            _DevelopmentNullReceiptState(
                result_evidence=evidence,
                canonical_bytes=canonical_json_bytes(projection),
                lock=RLock(),
            ),
        )
        state.receipt_issued = True
        return receipt


def remove_development_null_private_inputs(
    transaction: SealedGeneratedAuditInputTransaction,
) -> None:
    """Close retained input descriptors and remove only the exact private files."""

    state = _transaction_state(transaction)
    with state.lock:
        if not state.receipt_issued:
            raise TypeError("Terminal evidence must be sealed before private input cleanup.")
        if state.private_inputs_removed:
            return
        state.verified.close()
        store = state.staging.store
        root_fd = store._open_owned_root()
        directory_fd: int | None = None
        try:
            directory_fd = os.open(
                _PRIVATE_DIRECTORY,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=root_fd,
            )
            _validate_private_directory_descriptor(directory_fd)
            if frozenset(os.listdir(directory_fd)) != _PRIVATE_NAMES:
                raise UnexpectedCoreError(
                    "DEVELOPMENT.NULL_PRIVATE_CLEANUP",
                    "Development-null private staging contents changed.",
                )
            for name in sorted(_PRIVATE_NAMES):
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or stat.S_IMODE(observed.st_mode) != 0o600
                    or observed.st_nlink != 1
                    or (hasattr(os, "geteuid") and observed.st_uid != os.geteuid())
                ):
                    raise UnexpectedCoreError(
                        "DEVELOPMENT.NULL_PRIVATE_CLEANUP",
                        "Development-null private staging contents changed.",
                    )
                os.unlink(name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            os.rmdir(_PRIVATE_DIRECTORY, dir_fd=root_fd)
            os.fsync(root_fd)
            state.private_inputs_removed = True
            state.authority_bytes = b""
            state.authority = None
            state.resolved_case = None
            state.generated_artifacts = None
            state.csv_bytes = b""
            state.mapping.clear()
            state.mapping_digest = ""
        except OSError:
            raise UnexpectedCoreError(
                "DEVELOPMENT.NULL_PRIVATE_CLEANUP",
                "Development-null private staging cleanup failed.",
            ) from None
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
            os.close(root_fd)


__all__ = [
    "ClosedSyntheticReplayReceipt",
    "DevelopmentNullReceipt",
    "SealedDevelopmentNullScienceReceipt",
    "SealedGeneratedAuditInputTransaction",
    "bind_development_null_terminal_evidence",
    "is_development_null_run",
    "open_development_null_transaction",
    "project_development_null_receipt",
    "project_development_null_science_receipt",
    "remove_development_null_private_inputs",
    "seal_development_null_science_receipt",
]
