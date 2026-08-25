"""Contained, shell-free local worker invocation."""

from __future__ import annotations

import hashlib
import math
import os
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import IO, Any, NamedTuple, Never, SupportsIndex, cast, final

import numpy as np

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import (
    AuditError,
    PrivacyViolationError,
    UnexpectedCoreError,
    WorkerProtocolError,
)
from ebm_audit.privacy import DiagnosticDigest, assert_no_direct_identifier_fields
from ebm_audit.protocol import (
    BundleSnapshot,
    actual_fit_worker_subject_digest,
    actual_stage_worker_subject_digest,
    actual_validate_worker_subject_digest,
    adapter_semantics_digest,
    authenticated_execution_evidence_digest,
    authenticated_request_evidence_digest,
    backend_identity_digest,
    bind_request_digests,
    canonical_json_bytes,
    capabilities_digest,
    capture_bundle_snapshot,
    core_observed_failure_digest,
    exact_file_sha256,
    exact_file_sha256_path,
    execution_input_projection_digest,
    expected_identity_pin,
    expected_identity_pin_digest,
    load_worker_response,
    read_regular_file_exact,
    request_metadata_digest,
    requested_output_registry_digest,
    requested_outputs_digest,
    response_metadata_digest,
    scientific_request_digest,
    selected_algorithm_binding_digest,
    self_test_check_registry_digest,
    settings_digest,
    settings_schema_digest,
    strict_json_loads,
    structured_sha256,
    validate_execution_input_projection,
    validate_expected_identity_pin,
    validate_request_execution_input_binding,
    verify_snapshot_unchanged,
    worker_command_evidence_digest,
    worker_fit_payload_digest,
    worker_stage_result_digest,
    worker_validation_payload_digest,
    write_worker_request,
)
from ebm_audit.protocol.framing import MAX_SIDE_EFFECTS_JSON_BYTES
from ebm_audit.schema import (
    RESOURCE_FILENAMES,
    resource_bytes,
    validate_instance,
    validate_settings,
    validate_settings_schema,
)
from ebm_audit.workers.arrays import (
    array_catalog_entry,
    load_catalogued_npz_array_bytes,
    load_catalogued_npz_arrays,
    write_deterministic_npz,
)

from .config import WorkerCommand, _validated_worker_command_snapshot
from .containment import build_containment_plan
from .requests import (
    base_request,
    build_execution_input_projection,
    build_wire_scientific_payload,
)
from .semantics import validate_success_response_semantics

_STREAM_RETAINED_LIMIT = 64 * 1024
_DIAGNOSTIC_STREAM_HARD_LIMIT_BYTES = 1024 * 1024
_MAX_INVOCATION_TREE_BYTES = 512 * 1024 * 1024
_MAX_INVOCATION_TREE_FILES = 256
_MAX_INVOCATION_TREE_DIRECTORIES = 64
_PROCESS_WAIT_POLL_SECONDS = 0.05
_PROCESS_TERM_GRACE_SECONDS = 0.25
_PROCESS_KILL_GRACE_SECONDS = 0.5
_MAX_SAFE_INTEGER = (1 << 53) - 1
_SIDE_EFFECT_INVENTORY_EXCLUSIONS = (
    "response/.side-effects.json.tmp",
    "response/side-effects.json",
    "response/.response.json.tmp",
    "response/response.json",
)
_UNOBSERVED_ACTIVITY_CLASSES = (
    "file-reads",
    "transient-file-creations",
    "transient-file-modifications",
    "transient-file-deletions",
    "denied-network-attempts",
    "denied-outside-path-attempts",
    "denied-or-transient-subprocess-activity",
)
# Wheel-only worker demonstrations/templates are not imported by the core. If
# invoked, their bytes belong to the separate worker-code identity.
_CORE_PYTHON_EXCLUDED_PREFIXES = ("examples", "templates")


def normalize_worker_timeout_seconds(timeout_seconds: object) -> float:
    """Return the one timeout value accepted by every worker-facing surface."""

    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("Worker timeout must be finite and positive.")
    try:
        normalized_timeout = float(timeout_seconds)
    except (OverflowError, ValueError):
        raise ValueError("Worker timeout must be finite and positive.") from None
    if (
        not math.isfinite(normalized_timeout)
        or normalized_timeout <= 0
        or normalized_timeout > _MAX_SAFE_INTEGER / 1000
        or round(normalized_timeout * 1000) < 1
    ):
        raise ValueError("Worker timeout must be finite and positive.")
    return normalized_timeout


@dataclass(frozen=True, repr=False)
class WorkerExecution:
    """Opaque transport result container; not product authority.

    ``authenticated_request`` is non-null for every result issued by
    :class:`WorkerInvoker`.  The nullable default exists only for hand-built,
    untrusted projection DTOs in unit tests; it is not product authority and
    must never be accepted as an invocation receipt.
    """

    response: Mapping[str, Any]
    arrays: Mapping[str, Any]
    stdout: DiagnosticDigest
    stderr: DiagnosticDigest
    core_runtime_seconds: float
    containment_provider: str
    containment_launcher_sha256: str
    attempt_observability_verified: bool
    command_evidence: Mapping[str, Any] | None = None
    authenticated_description: AuthenticatedWorkerDescription | None = None
    authenticated_request: AuthenticatedWorkerRequestEvidence | None = None
    authenticated_execution: AuthenticatedWorkerExecutionEvidence | None = None

    def __repr__(self) -> str:
        return "WorkerExecution(<opaque transport result; authority not implied>)"


@dataclass(frozen=True, repr=False)
class _RetainedFile:
    relative_path: str
    byte_length: int
    sha256: str
    private_bytes: bytes


@dataclass(frozen=True, repr=False)
class _RetainedBundle:
    snapshot: BundleSnapshot
    files: tuple[_RetainedFile, ...]
    bundle_digest: str

    def private_bytes_for(self, relative_path: str) -> bytes:
        matches = [
            entry.private_bytes for entry in self.files if entry.relative_path == relative_path
        ]
        if len(matches) != 1:
            raise TypeError("Retained evidence has no exact private bundle member.")
        return bytes(matches[0])


def _retained_snapshot_digest(snapshot: BundleSnapshot) -> str:
    return structured_sha256(
        "ebm-audit/retained-worker-bundle/1",
        {
            "entries": [
                {
                    "relative_path": relative_path,
                    "byte_length": record.byte_length,
                    "sha256": record.sha256,
                }
                for relative_path, record in snapshot.entries
            ]
        },
    )


def _retain_bundle(root: Path, snapshot: BundleSnapshot) -> _RetainedBundle:
    """Retain one already-verified private bundle and recheck every exact byte."""

    verify_snapshot_unchanged(root, snapshot)
    files: list[_RetainedFile] = []
    for relative_path, record in snapshot.entries:
        private_bytes = read_regular_file_exact(
            root / PurePosixPath(relative_path),
            max_bytes=record.byte_length,
        )
        if (
            len(private_bytes) != record.byte_length
            or exact_file_sha256(private_bytes) != record.sha256
        ):
            raise TypeError("Retained evidence does not match its exact bundle snapshot.")
        files.append(
            _RetainedFile(
                relative_path=relative_path,
                byte_length=record.byte_length,
                sha256=record.sha256,
                private_bytes=bytes(private_bytes),
            )
        )
    verify_snapshot_unchanged(root, snapshot)
    retained = _RetainedBundle(
        snapshot=snapshot,
        files=tuple(files),
        bundle_digest=_retained_snapshot_digest(snapshot),
    )
    if tuple(entry.relative_path for entry in retained.files) != tuple(
        relative_path for relative_path, _record in snapshot.entries
    ):
        raise TypeError("Retained evidence changed canonical bundle order.")
    return retained


def _reject_opaque_evidence_copy() -> Never:
    raise TypeError("Opaque worker evidence cannot be copied or serialized.")


class _AuthenticatedWorkerRequestState(NamedTuple):
    canonical_request_bytes: bytes
    retained_request_bundle: _RetainedBundle
    command: str
    request_metadata_digest: str
    scientific_request_digest: str | None
    execution_input_projection_digest: str | None
    prepared_candidate_execution_context: object | None
    prepared_candidate_execution_context_state: object | None
    authenticated_description: AuthenticatedWorkerDescription | None
    authenticated_description_state: object | None
    authenticated_description_readback: object | None
    planning_summary_id: str | None
    selected_algorithm_binding: Mapping[str, Any] | None
    selected_algorithm_binding_digest: str | None
    profile_fit_receipt_row: object | None
    identity_projection: Mapping[str, Any]
    evidence_digest: str


_AUTHENTICATED_REQUEST_STATES: OneShotWeakRegistry[object, _AuthenticatedWorkerRequestState]
_AUTHENTICATED_REQUEST_STATE_ISSUER: OneShotRegistryIssuer[object, _AuthenticatedWorkerRequestState]
(
    _AUTHENTICATED_REQUEST_STATES,
    _AUTHENTICATED_REQUEST_STATE_ISSUER,
) = create_one_shot_registry()
_AUTHENTICATED_REQUEST_ISSUER = object()


@final
class AuthenticatedWorkerRequestEvidence:
    """Opaque evidence for the exact request frame; never product execution authority."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("AuthenticatedWorkerRequestEvidence cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("AuthenticatedWorkerRequestEvidence is issued by WorkerInvoker only.")

    @classmethod
    def _issue(
        cls,
        issuer: object,
        *,
        request: Mapping[str, Any],
        canonical_request_bytes: bytes,
        retained_request_bundle: _RetainedBundle,
        authenticated_description: AuthenticatedWorkerDescription | None,
        selected_algorithm_binding: Mapping[str, Any] | None,
        planning_summary_id: str | None = None,
        prepared_candidate_execution_context: object | None = None,
        authenticated_description_state: object | None = None,
        authenticated_description_readback: object | None = None,
        profile_fit_receipt_row: object | None = None,
    ) -> AuthenticatedWorkerRequestEvidence:
        if issuer is not _AUTHENTICATED_REQUEST_ISSUER:
            raise TypeError("AuthenticatedWorkerRequestEvidence has no public constructor.")
        invalid = False
        try:
            parsed = strict_json_loads(canonical_request_bytes)
            if not isinstance(parsed, dict) or parsed != request:
                raise ValueError
            if canonical_json_bytes(request) != canonical_request_bytes:
                raise ValueError
            if (
                retained_request_bundle.private_bytes_for("request.json") != canonical_request_bytes
                or retained_request_bundle.snapshot.as_mapping().get("request.json") is None
                or retained_request_bundle.bundle_digest
                != _retained_snapshot_digest(retained_request_bundle.snapshot)
            ):
                raise ValueError
            validate_instance(request, "worker-protocol.schema.json", definition="WorkerRequest")
            validate_request_execution_input_binding(request)
            if request["request_metadata_digest"] != request_metadata_digest(request):
                raise ValueError
            if request["scientific_request_digest"] != scientific_request_digest(request):
                raise ValueError
            projection_digest: str | None = None
            payload = request.get("payload")
            if isinstance(payload, Mapping):
                candidate = payload.get("execution_input_projection_digest")
                if isinstance(candidate, str):
                    projection = payload.get("execution_input_projection")
                    if not isinstance(
                        projection, Mapping
                    ) or candidate != execution_input_projection_digest(projection):
                        raise ValueError
                    projection_digest = candidate
            description_digest: str | None = None
            selected_binding_digest: str | None = None
            profile_fit_owner: Any | None = None
            if profile_fit_receipt_row is not None:
                from ebm_audit.runner.profile_validation import (
                    _profile_fit_request_owner_from_row,
                )

                profile_fit_owner = _profile_fit_request_owner_from_row(profile_fit_receipt_row)
                owner_context = profile_fit_owner.invocation_context
                if (
                    request["command"] != "fit"
                    or prepared_candidate_execution_context
                    is not profile_fit_owner.candidate_execution_context
                    or planning_summary_id != owner_context.planning_summary_id
                    or authenticated_description is not owner_context.authenticated_description
                    or authenticated_description_state
                    is not owner_context.authenticated_description_state
                    or authenticated_description_readback != owner_context.description
                    or selected_algorithm_binding is None
                    or dict(selected_algorithm_binding)
                    != dict(owner_context.selected_algorithm_binding)
                ):
                    raise ValueError
            if authenticated_description is None:
                if (
                    selected_algorithm_binding is not None
                    or authenticated_description_state is not None
                    or authenticated_description_readback is not None
                ):
                    raise ValueError
                if request["command"] in {"validate", "fit", "stage", "self-test"}:
                    raise ValueError
            else:
                if type(authenticated_description) is not AuthenticatedWorkerDescription:
                    raise ValueError
                if profile_fit_owner is not None:
                    owner_context = profile_fit_owner.invocation_context
                    _AUTHENTICATED_DESCRIPTION_STATES.require(
                        authenticated_description,
                        owner_context.authenticated_description_state,
                    )
                    authenticated_description_state = owner_context.authenticated_description_state
                    description_readback = owner_context.description
                    authenticated_description_readback = description_readback
                elif (
                    authenticated_description_state is None
                    or authenticated_description_readback is None
                ):
                    (
                        authenticated_description_state,
                        description_readback,
                    ) = _capture_authenticated_description(authenticated_description)
                    authenticated_description_readback = description_readback
                else:
                    description_readback = cast(
                        _AuthenticatedDescriptionReadback,
                        authenticated_description_readback,
                    )
                    if (
                        type(description_readback) is not _AuthenticatedDescriptionReadback
                        or description_readback.description is not authenticated_description
                        or _AUTHENTICATED_DESCRIPTION_STATES.get(authenticated_description)
                        is not authenticated_description_state
                    ):
                        raise ValueError
                expected_binding = description_readback.selected_algorithm_binding
                if selected_algorithm_binding is None or dict(selected_algorithm_binding) != (
                    dict(expected_binding)
                ):
                    raise ValueError
                description_digest = description_readback.response_metadata_digest
                selected_binding_digest = description_readback.selected_algorithm_binding_digest
                if request["command"] in {"validate", "fit", "stage"}:
                    execution_input = request["payload"]["execution_input_projection"]
                    described_owner = _described_owner_from_description_readback(
                        description_readback,
                        command=str(request["command"]),
                        payload=execution_input,
                    )
                    _verify_execution_input_description_binding(
                        execution_input,
                        description=description_readback,
                        described_owner=described_owner,
                    )
            if planning_summary_id is not None and not _is_sha256_digest(planning_summary_id):
                raise ValueError
            if request["command"] not in {"validate", "fit"} and planning_summary_id is not None:
                raise ValueError
            if prepared_candidate_execution_context is None:
                if planning_summary_id is not None:
                    raise ValueError
                prepared_candidate_execution_context_state = None
            else:
                if profile_fit_owner is None:
                    context_state = _read_prepared_candidate_execution_context(
                        prepared_candidate_execution_context
                    )
                    invocation_context = context_state.invocation_context
                else:
                    context_state = _require_prepared_candidate_execution_context_state_identity(
                        prepared_candidate_execution_context,
                        profile_fit_owner.candidate_execution_context_state,
                    )
                    invocation_context = profile_fit_owner.invocation_context
                prepared_candidate_execution_context_state = context_state
                if (
                    request["command"] not in {"validate", "fit"}
                    or planning_summary_id != invocation_context.planning_summary_id
                    or authenticated_description is not invocation_context.authenticated_description
                    or selected_algorithm_binding is None
                    or dict(selected_algorithm_binding)
                    != dict(invocation_context.selected_algorithm_binding)
                ):
                    raise ValueError
        except Exception:
            invalid = True
        if invalid:
            raise TypeError(
                "Authenticated request evidence requires one exact valid request frame."
            )
        projection = {
            "request_evidence_schema_version": (
                "ebm-audit-authenticated-worker-request-evidence/2.0"
            ),
            "protocol_version": request["protocol_version"],
            "request_schema_version": request["request_schema_version"],
            "payload_schema_version": request["payload_schema_version"],
            "command": request["command"],
            "request_metadata_digest": request["request_metadata_digest"],
            "scientific_request_digest": request["scientific_request_digest"],
            "execution_input_projection_digest": projection_digest,
            "request_bundle_digest": retained_request_bundle.bundle_digest,
            "authenticated_description_response_metadata_digest": description_digest,
            "planning_summary_id": planning_summary_id,
            "selected_algorithm_binding_digest": selected_binding_digest,
        }
        state = _AuthenticatedWorkerRequestState(
            canonical_request_bytes=bytes(canonical_request_bytes),
            retained_request_bundle=retained_request_bundle,
            command=str(request["command"]),
            request_metadata_digest=str(request["request_metadata_digest"]),
            scientific_request_digest=(
                None
                if request["scientific_request_digest"] is None
                else str(request["scientific_request_digest"])
            ),
            execution_input_projection_digest=projection_digest,
            prepared_candidate_execution_context=(prepared_candidate_execution_context),
            prepared_candidate_execution_context_state=(prepared_candidate_execution_context_state),
            authenticated_description=authenticated_description,
            authenticated_description_state=authenticated_description_state,
            authenticated_description_readback=authenticated_description_readback,
            planning_summary_id=planning_summary_id,
            selected_algorithm_binding=(
                None if selected_algorithm_binding is None else deepcopy(selected_algorithm_binding)
            ),
            selected_algorithm_binding_digest=selected_binding_digest,
            profile_fit_receipt_row=profile_fit_receipt_row,
            identity_projection=deepcopy(projection),
            evidence_digest=authenticated_request_evidence_digest(projection),
        )
        self = object.__new__(cls)
        _AUTHENTICATED_REQUEST_STATE_ISSUER.bind_once(self, state)
        _readback_authenticated_request(self)
        return self

    def _state(self) -> _AuthenticatedWorkerRequestState:
        try:
            return _AUTHENTICATED_REQUEST_STATES[self]
        except KeyError:
            raise TypeError(
                "The authenticated request capability was not issued by WorkerInvoker."
            ) from None

    def _request(self) -> Mapping[str, Any]:
        return deepcopy(dict(_readback_authenticated_request(self).request))

    def __repr__(self) -> str:
        _readback_authenticated_request(self)
        return "AuthenticatedWorkerRequestEvidence(<opaque exact request evidence>)"

    def __copy__(self) -> AuthenticatedWorkerRequestEvidence:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> AuthenticatedWorkerRequestEvidence:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    @property
    def command(self) -> str:
        return _readback_authenticated_request(self).command

    @property
    def request_metadata_digest(self) -> str:
        return _readback_authenticated_request(self).request_metadata_digest

    @property
    def scientific_request_digest(self) -> str | None:
        return _readback_authenticated_request(self).scientific_request_digest

    @property
    def execution_input_projection_digest(self) -> str | None:
        return _readback_authenticated_request(self).execution_input_projection_digest

    @property
    def request_bundle_digest(self) -> str:
        return _readback_authenticated_request(self).retained_request_bundle.bundle_digest

    @property
    def authenticated_description(self) -> AuthenticatedWorkerDescription | None:
        return _readback_authenticated_request(self).authenticated_description

    @property
    def planning_summary_id(self) -> str | None:
        return _readback_authenticated_request(self).planning_summary_id

    @property
    def selected_algorithm_binding_digest(self) -> str | None:
        return _readback_authenticated_request(self).selected_algorithm_binding_digest

    def binds_authenticated_description(self, description: AuthenticatedWorkerDescription) -> bool:
        return _readback_authenticated_request(self).authenticated_description is description

    def binds_selected_algorithm(self, binding: Mapping[str, Any]) -> bool:
        selected = _readback_authenticated_request(self).selected_algorithm_binding
        return selected is not None and dict(selected) == dict(binding)

    @property
    def identity_projection(self) -> Mapping[str, Any]:
        return deepcopy(dict(_readback_authenticated_request(self).identity_projection))

    @property
    def evidence_digest(self) -> str:
        return _readback_authenticated_request(self).evidence_digest


class InvocationFailureClass(StrEnum):
    """Closed core-observed failure classes; never worker-returned statuses."""

    TIMEOUT = "TIMEOUT"
    PRIVACY_VIOLATION = "PRIVACY_VIOLATION"
    PROCESS_FAILURE = "PROCESS_FAILURE"
    RESPONSE_MISSING = "RESPONSE_MISSING"
    RESPONSE_INVALID = "RESPONSE_INVALID"
    PROTOCOL_FAILURE = "PROTOCOL_FAILURE"
    UNEXPECTED_CORE_ERROR = "UNEXPECTED_CORE_ERROR"


@dataclass(frozen=True, repr=False)
class _WorkerInvocationObservationState:
    failure_class: InvocationFailureClass
    failure_code: str
    authenticated_request: AuthenticatedWorkerRequestEvidence
    authenticated_description: AuthenticatedWorkerDescription | None
    selected_algorithm_id: str | None
    framed_response_metadata_digest: str | None
    safe_evidence: Mapping[str, int | str | bool]
    canonical_identity_projection_bytes: bytes
    identity_projection: Mapping[str, Any]
    observation_digest: str


_INVOCATION_OBSERVATION_STATES: OneShotWeakRegistry[object, _WorkerInvocationObservationState]
_INVOCATION_OBSERVATION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _WorkerInvocationObservationState
]
(
    _INVOCATION_OBSERVATION_STATES,
    _INVOCATION_OBSERVATION_STATE_ISSUER,
) = create_one_shot_registry()
_INVOCATION_OBSERVATION_ISSUANCE_PROJECTIONS: OneShotWeakRegistry[object, bytes]
_INVOCATION_OBSERVATION_ISSUANCE_PROJECTION_ISSUER: OneShotRegistryIssuer[object, bytes]
(
    _INVOCATION_OBSERVATION_ISSUANCE_PROJECTIONS,
    _INVOCATION_OBSERVATION_ISSUANCE_PROJECTION_ISSUER,
) = create_one_shot_registry()
_INVOCATION_OBSERVATION_ISSUER = object()
_OBSERVATION_EVIDENCE_KEYS = frozenset(
    {
        "completed_response_status",
        "maximum_directory_count",
        "maximum_file_count",
        "maximum_total_bytes",
        "observation_digest",
        "observed_directory_count",
        "observed_file_count",
        "observed_total_bytes",
        "partial_file_count",
        "partial_inventory_complete",
        "partial_workspace_digest",
        "response_marker_present",
        "return_code",
        "runtime_milliseconds",
        "stderr_byte_length",
        "stderr_sha256",
        "stdout_byte_length",
        "stdout_sha256",
        "stream_hard_limit_bytes",
        "timeout_milliseconds",
    }
)


@final
class WorkerInvocationObservation:
    """Opaque privacy-safe record of a core-observed invocation failure."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("WorkerInvocationObservation cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("WorkerInvocationObservation is issued by WorkerInvoker only.")

    @classmethod
    def _issue(
        cls,
        issuer: object,
        *,
        failure_class: InvocationFailureClass,
        failure_code: str,
        authenticated_request: AuthenticatedWorkerRequestEvidence,
        authenticated_description: AuthenticatedWorkerDescription | None,
        selected_algorithm_id: str | None,
        framed_response_metadata_digest: str | None,
        safe_evidence: Mapping[str, int | str | bool],
    ) -> WorkerInvocationObservation:
        if issuer is not _INVOCATION_OBSERVATION_ISSUER:
            raise TypeError("WorkerInvocationObservation has no public constructor.")
        if type(authenticated_request) is not AuthenticatedWorkerRequestEvidence:
            raise TypeError("Invocation observation requires exact request evidence.")
        request_readback = _readback_authenticated_request(authenticated_request)
        if authenticated_description is not request_readback.authenticated_description:
            raise TypeError("Invocation observation description is detached from its request.")
        if not isinstance(failure_class, InvocationFailureClass):
            raise TypeError("Invocation failure class is not registered.")
        if set(safe_evidence) - _OBSERVATION_EVIDENCE_KEYS:
            raise TypeError("Invocation observation contains an unregistered evidence field.")
        if any(not isinstance(value, (int, str, bool)) for value in safe_evidence.values()):
            raise TypeError("Invocation observation evidence is not a closed scalar mapping.")
        if (
            framed_response_metadata_digest is not None
            and not framed_response_metadata_digest.startswith("sha256:")
        ):
            raise TypeError("Framed response metadata identity is not a digest.")
        description_digest: str | None = None
        selected_binding_digest: str | None = None
        if authenticated_description is not None:
            description_readback = request_readback.description
            if (
                type(authenticated_description) is not AuthenticatedWorkerDescription
                or description_readback is None
            ):
                raise TypeError("Invocation observation requires an exact description.")
            description_digest = description_readback.response_metadata_digest
            expected_identity = description_readback.expected_identity
            if selected_algorithm_id != expected_identity["selected_algorithm_id"]:
                raise TypeError(
                    "Invocation observation selected owner does not match its authenticated "
                    "description."
                )
            selected_binding_digest = description_readback.selected_algorithm_binding_digest
        elif selected_algorithm_id is not None:
            raise TypeError(
                "Invocation observation cannot select an owner without an authenticated "
                "description."
            )
        if selected_binding_digest != request_readback.selected_algorithm_binding_digest:
            raise TypeError("Invocation observation selected binding is detached from its request.")
        projection = {
            "observation_schema_version": "ebm-audit-core-observed-failure/2.0",
            "failure_class": failure_class.value,
            "failure_code": failure_code,
            "authenticated_request_evidence_digest": request_readback.evidence_digest,
            "authenticated_description_response_metadata_digest": description_digest,
            "selected_algorithm_binding_digest": selected_binding_digest,
            "framed_response_metadata_digest": framed_response_metadata_digest,
            "safe_evidence": dict(safe_evidence),
        }
        observation_digest = core_observed_failure_digest(projection)
        self = object.__new__(cls)
        state = _WorkerInvocationObservationState(
            failure_class=failure_class,
            failure_code=failure_code,
            authenticated_request=authenticated_request,
            authenticated_description=authenticated_description,
            selected_algorithm_id=selected_algorithm_id,
            framed_response_metadata_digest=framed_response_metadata_digest,
            safe_evidence=deepcopy(dict(safe_evidence)),
            canonical_identity_projection_bytes=canonical_json_bytes(projection),
            identity_projection=deepcopy(projection),
            observation_digest=observation_digest,
        )
        projection_bytes = canonical_json_bytes(projection)
        _INVOCATION_OBSERVATION_STATE_ISSUER.bind_once(self, state)
        _INVOCATION_OBSERVATION_ISSUANCE_PROJECTION_ISSUER.bind_once(
            self,
            projection_bytes,
        )
        _readback_worker_invocation_observation(self)
        return self

    def _state(self) -> _WorkerInvocationObservationState:
        try:
            return _INVOCATION_OBSERVATION_STATES[self]
        except KeyError:
            raise TypeError("The invocation observation was not issued by WorkerInvoker.") from None

    def __repr__(self) -> str:
        _readback_worker_invocation_observation(self)
        return "WorkerInvocationObservation(<opaque safe failure evidence>)"

    def __copy__(self) -> WorkerInvocationObservation:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> WorkerInvocationObservation:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    @property
    def failure_class(self) -> InvocationFailureClass:
        return _readback_worker_invocation_observation(self).failure_class

    @property
    def failure_code(self) -> str:
        return _readback_worker_invocation_observation(self).failure_code

    @property
    def authenticated_request(self) -> AuthenticatedWorkerRequestEvidence:
        return _readback_worker_invocation_observation(self).authenticated_request

    @property
    def authenticated_description(self) -> AuthenticatedWorkerDescription | None:
        return _readback_worker_invocation_observation(self).authenticated_description

    @property
    def selected_algorithm_binding_digest(self) -> str | None:
        return _readback_worker_invocation_observation(self).selected_algorithm_binding_digest

    @property
    def framed_response_metadata_digest(self) -> str | None:
        return _readback_worker_invocation_observation(self).framed_response_metadata_digest

    @property
    def safe_evidence(self) -> Mapping[str, int | str | bool]:
        return deepcopy(dict(_readback_worker_invocation_observation(self).safe_evidence))

    @property
    def identity_projection(self) -> Mapping[str, Any]:
        return deepcopy(dict(_readback_worker_invocation_observation(self).identity_projection))

    @property
    def observation_digest(self) -> str:
        return _readback_worker_invocation_observation(self).observation_digest


_AUTHENTICATED_DESCRIPTION_ISSUER = object()


class _AuthenticatedWorkerDescriptionState(NamedTuple):
    backend_identity: Mapping[str, Any]
    backend_identity_digest: str
    canonical_response_bytes: bytes
    description_result: Mapping[str, Any]
    expected_identity: Mapping[str, Any]
    expected_identity_digest: str
    requested_output_registry_digest: str
    response_metadata_digest: str
    supported_algorithms: tuple[Mapping[str, Any], ...]


class _AuthenticatedDescriptionReadback(NamedTuple):
    """One closed snapshot of an authenticated Describe capability."""

    description: AuthenticatedWorkerDescription
    canonical_response_bytes: bytes
    backend_identity: Mapping[str, Any]
    backend_identity_digest: str
    description_result: Mapping[str, Any]
    expected_identity: Mapping[str, Any]
    expected_identity_digest: str
    requested_output_registry_digest: str
    response_metadata_digest: str
    supported_algorithms: tuple[Mapping[str, Any], ...]
    selected_algorithm_binding: Mapping[str, Any]
    selected_algorithm_binding_digest: str


_AUTHENTICATED_DESCRIPTION_STATES: OneShotWeakRegistry[object, _AuthenticatedWorkerDescriptionState]
_AUTHENTICATED_DESCRIPTION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _AuthenticatedWorkerDescriptionState
]
(
    _AUTHENTICATED_DESCRIPTION_STATES,
    _AUTHENTICATED_DESCRIPTION_STATE_ISSUER,
) = create_one_shot_registry()


@final
class AuthenticatedWorkerDescription:
    """Opaque, immutable-by-copy evidence from one authenticated Describe."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("AuthenticatedWorkerDescription cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("AuthenticatedWorkerDescription is issued by WorkerInvoker only.")

    @classmethod
    def _issue(
        cls,
        issuer: object,
        *,
        response: Mapping[str, Any],
        expected_identity: Mapping[str, Any],
    ) -> AuthenticatedWorkerDescription:
        if issuer is not _AUTHENTICATED_DESCRIPTION_ISSUER:
            raise TypeError("AuthenticatedWorkerDescription has no public constructor.")
        result = response["payload"]["result"]
        self = object.__new__(cls)
        state = _AuthenticatedWorkerDescriptionState(
            backend_identity=deepcopy(response["backend_identity"]),
            backend_identity_digest=str(response["backend_identity_digest"]),
            canonical_response_bytes=canonical_json_bytes(response),
            description_result=deepcopy(result),
            expected_identity=deepcopy(expected_identity),
            expected_identity_digest=expected_identity_pin_digest(expected_identity),
            requested_output_registry_digest=str(result["requested_output_registry_digest"]),
            response_metadata_digest=str(response["response_metadata_digest"]),
            supported_algorithms=tuple(deepcopy(result["supported_algorithms"])),
        )
        try:
            _description_readback_from_state(self, state)
        except Exception:
            raise TypeError(
                "Authenticated description requires one exact valid Describe response."
            ) from None
        _AUTHENTICATED_DESCRIPTION_STATE_ISSUER.bind_once(self, state)
        _readback_authenticated_description(self)
        return self

    def _state(self) -> _AuthenticatedWorkerDescriptionState:
        try:
            return _AUTHENTICATED_DESCRIPTION_STATES[self]
        except KeyError:
            raise TypeError(
                "The authenticated description capability was not issued by WorkerInvoker."
            ) from None

    def _readback(self) -> _AuthenticatedDescriptionReadback:
        return _readback_authenticated_description(self)

    def __repr__(self) -> str:
        self._readback()
        return "AuthenticatedWorkerDescription(<opaque authenticated description>)"

    def __copy__(self) -> AuthenticatedWorkerDescription:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> AuthenticatedWorkerDescription:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    @property
    def backend_identity(self) -> Mapping[str, Any]:
        return deepcopy(dict(self._readback().backend_identity))

    @property
    def backend_identity_digest(self) -> str:
        return self._readback().backend_identity_digest

    @property
    def canonical_response_bytes(self) -> bytes:
        return bytes(self._readback().canonical_response_bytes)

    @property
    def description_result(self) -> Mapping[str, Any]:
        return deepcopy(dict(self._readback().description_result))

    @property
    def supported_commands(self) -> tuple[str, ...]:
        return tuple(self._readback().description_result["supported_commands"])

    @property
    def worker_limitations(self) -> tuple[str, ...]:
        return tuple(self._readback().description_result["worker_limitations"])

    @property
    def self_test_check_registry_digest(self) -> str:
        return str(self._readback().description_result["self_test_check_registry_digest"])

    @property
    def supported_algorithms(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(deepcopy(self._readback().supported_algorithms))

    @property
    def requested_output_registry_digest(self) -> str:
        return self._readback().requested_output_registry_digest

    @property
    def response_metadata_digest(self) -> str:
        return self._readback().response_metadata_digest

    @property
    def expected_identity(self) -> Mapping[str, Any]:
        return deepcopy(dict(self._readback().expected_identity))

    @property
    def expected_identity_digest(self) -> str:
        return self._readback().expected_identity_digest

    @property
    def selected_algorithm_binding(self) -> Mapping[str, Any]:
        """Return the one closed invocation binding owned by this Describe."""

        return deepcopy(dict(self._readback().selected_algorithm_binding))

    @property
    def selected_algorithm_binding_digest(self) -> str:
        """Return the identity of the exact selected-algorithm binding."""

        return self._readback().selected_algorithm_binding_digest


def _is_sha256_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _selected_algorithm_binding_from_description_state(
    state: _AuthenticatedWorkerDescriptionState,
) -> dict[str, Any]:
    expected_identity = state.expected_identity
    algorithm_id = expected_identity["selected_algorithm_id"]
    matching = [
        algorithm
        for algorithm in state.supported_algorithms
        if algorithm["algorithm_id"] == algorithm_id
    ]
    if len(matching) != 1:
        raise TypeError("Authenticated description has no exact selected algorithm binding.")
    algorithm = matching[0]
    base = state.backend_identity
    binding = {
        "adapter_id": base["adapter_id"],
        "adapter_semantics_digest": algorithm["adapter_semantics_digest"],
        "expected_backend_name": base["backend_name"],
        "expected_backend_source_digest": base["backend_source_digest"],
        "algorithm_id": algorithm["algorithm_id"],
        "capabilities_digest": algorithm["capabilities_digest"],
        "settings_schema_digest": algorithm["settings_schema_digest"],
        "stage_semantics_digest": algorithm["stage_semantics_digest"],
        "description_response_metadata_digest": state.response_metadata_digest,
        "expected_identity_pin_digest": state.expected_identity_digest,
    }
    validate_instance(
        binding,
        "analysis-universe.schema.json",
        definition="SelectedAlgorithmBinding",
    )
    return binding


def _revalidate_authenticated_description(
    description: AuthenticatedWorkerDescription,
) -> _AuthenticatedWorkerDescriptionState:
    try:
        if type(description) is not AuthenticatedWorkerDescription:
            raise TypeError
        state = description._state()
        response = strict_json_loads(state.canonical_response_bytes)
        if (
            not isinstance(response, dict)
            or canonical_json_bytes(response) != state.canonical_response_bytes
        ):
            raise TypeError
        validate_instance(response, "worker-protocol.schema.json", definition="WorkerResponse")
        if response["command"] != "describe" or response["status"] != "SUCCESS":
            raise ValueError
        _verify_pinned_response(
            command="describe",
            response=response,
            expected_identity=state.expected_identity,
        )
        _verify_response_owner_digests(response, {"command": "describe"}, None)
        result = response["payload"]["result"]
        if (
            response["backend_identity"] != state.backend_identity
            or response["backend_identity_digest"] != state.backend_identity_digest
            or response["response_metadata_digest"] != state.response_metadata_digest
            or result != state.description_result
            or tuple(result["supported_algorithms"]) != state.supported_algorithms
            or result["requested_output_registry_digest"] != state.requested_output_registry_digest
            or expected_identity_pin_digest(state.expected_identity)
            != state.expected_identity_digest
        ):
            raise ValueError
        _selected_algorithm_binding_from_description_state(state)
        return state
    except Exception:
        raise TypeError(
            "Authenticated description does not revalidate against its exact identity owner."
        ) from None


def _description_readback_from_state(
    description: AuthenticatedWorkerDescription,
    state: _AuthenticatedWorkerDescriptionState,
) -> _AuthenticatedDescriptionReadback:
    selected_binding = _selected_algorithm_binding_from_description_state(state)
    return _AuthenticatedDescriptionReadback(
        description=description,
        canonical_response_bytes=bytes(state.canonical_response_bytes),
        backend_identity=MappingProxyType(deepcopy(dict(state.backend_identity))),
        backend_identity_digest=state.backend_identity_digest,
        description_result=MappingProxyType(deepcopy(dict(state.description_result))),
        expected_identity=MappingProxyType(deepcopy(dict(state.expected_identity))),
        expected_identity_digest=state.expected_identity_digest,
        requested_output_registry_digest=state.requested_output_registry_digest,
        response_metadata_digest=state.response_metadata_digest,
        supported_algorithms=tuple(deepcopy(state.supported_algorithms)),
        selected_algorithm_binding=MappingProxyType(deepcopy(selected_binding)),
        selected_algorithm_binding_digest=selected_algorithm_binding_digest(selected_binding),
    )


def _capture_authenticated_description(
    value: object,
) -> tuple[
    _AuthenticatedWorkerDescriptionState,
    _AuthenticatedDescriptionReadback,
]:
    """Capture one exact Describe registry state and its closed readback."""

    try:
        if type(value) is not AuthenticatedWorkerDescription:
            raise TypeError
        description = value
        state = _revalidate_authenticated_description(description)
        return state, _description_readback_from_state(description, state)
    except Exception:
        raise TypeError(
            "Authenticated description does not revalidate against its exact identity owner."
        ) from None


def _readback_authenticated_description(
    value: object,
) -> _AuthenticatedDescriptionReadback:
    """Capture all Describe-owned authority from one validated registry state."""

    return _capture_authenticated_description(value)[1]


@dataclass(eq=False)
class _ContractHarnessDescriptionCapabilityState:
    """One call-scoped owner for a contract harness Describe snapshot."""

    invoker: WorkerInvoker
    authenticated_description: AuthenticatedWorkerDescription
    authenticated_description_state: _AuthenticatedWorkerDescriptionState
    description: _AuthenticatedDescriptionReadback
    active: bool = True


_CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_STATES: OneShotWeakRegistry[
    object, _ContractHarnessDescriptionCapabilityState
]
_CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ContractHarnessDescriptionCapabilityState
]
(
    _CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_STATES,
    _CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_STATE_ISSUER,
) = create_one_shot_registry()
_CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_ISSUER = object()


@final
class _ContractHarnessDescriptionCapability:
    """Private non-serializable authority for one contract receipt lifetime."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Contract harness description capability cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("Contract harness description capability has no public constructor.")

    @classmethod
    def _issue(
        cls,
        issuer: object,
        *,
        invoker: WorkerInvoker,
        authenticated_description: AuthenticatedWorkerDescription,
    ) -> _ContractHarnessDescriptionCapability:
        if issuer is not _CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_ISSUER:
            raise TypeError("Contract harness description capability has no public issuer.")
        description_state, description = _capture_authenticated_description(
            authenticated_description
        )
        self = object.__new__(cls)
        _CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_STATE_ISSUER.bind_once(
            self,
            _ContractHarnessDescriptionCapabilityState(
                invoker=invoker,
                authenticated_description=authenticated_description,
                authenticated_description_state=description_state,
                description=description,
            ),
        )
        _read_contract_harness_description_capability(self, invoker)
        return self

    def __repr__(self) -> str:
        return "_ContractHarnessDescriptionCapability(<opaque call-scoped description>)"

    def __copy__(self) -> _ContractHarnessDescriptionCapability:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> _ContractHarnessDescriptionCapability:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()


def _read_contract_harness_description_capability(
    value: object,
    invoker: WorkerInvoker,
) -> _ContractHarnessDescriptionCapabilityState:
    """Revalidate one exact call-scoped description without refreshing it."""

    try:
        if type(value) is not _ContractHarnessDescriptionCapability:
            raise TypeError
        state = _CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_STATES[value]
        description_state, description = _capture_authenticated_description(
            state.authenticated_description
        )
        if (
            not state.active
            or state.invoker is not invoker
            or description_state is not state.authenticated_description_state
            or description.description is not state.authenticated_description
            or description.response_metadata_digest
            != state.description.response_metadata_digest
            or description.selected_algorithm_binding_digest
            != state.description.selected_algorithm_binding_digest
            or invoker._expected_identity is None
            or dict(description.expected_identity) != dict(invoker._expected_identity)
        ):
            raise TypeError
        return state
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.DESCRIBE_COMMAND_OWNER",
            "The contract command has no active authenticated description owner.",
        ) from None


@dataclass(frozen=True, repr=False)
class _AuthenticatedWorkerExecutionState:
    canonical_response_bytes: bytes
    retained_response_bundle: _RetainedBundle
    response_snapshot: BundleSnapshot
    invocation_snapshot: BundleSnapshot
    authenticated_request: AuthenticatedWorkerRequestEvidence
    command_evidence: Mapping[str, Any] | None
    identity_projection: Mapping[str, Any]
    evidence_digest: str
    stdout_byte_length: int
    stdout_sha256: str
    stderr_byte_length: int
    stderr_sha256: str
    runtime_milliseconds: int
    containment_provider: str
    containment_launcher_sha256: str
    attempt_observability_verified: bool


_AUTHENTICATED_EXECUTION_STATES: OneShotWeakRegistry[object, _AuthenticatedWorkerExecutionState]
_AUTHENTICATED_EXECUTION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _AuthenticatedWorkerExecutionState
]
(
    _AUTHENTICATED_EXECUTION_STATES,
    _AUTHENTICATED_EXECUTION_STATE_ISSUER,
) = create_one_shot_registry()
_AUTHENTICATED_EXECUTION_ISSUER = object()


@final
class AuthenticatedWorkerExecutionEvidence:
    """Opaque checked-response evidence; never product execution or result authority."""

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("AuthenticatedWorkerExecutionEvidence cannot be subclassed.")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("AuthenticatedWorkerExecutionEvidence is issued by WorkerInvoker only.")

    @classmethod
    def _issue(
        cls,
        issuer: object,
        *,
        authenticated_request: AuthenticatedWorkerRequestEvidence,
        response: Mapping[str, Any],
        canonical_response_bytes: bytes,
        retained_response_bundle: _RetainedBundle,
        response_snapshot: BundleSnapshot,
        invocation_snapshot: BundleSnapshot,
        command_evidence: Mapping[str, Any] | None,
        stdout: DiagnosticDigest,
        stderr: DiagnosticDigest,
        runtime_milliseconds: int,
        containment_provider: str,
        containment_launcher_sha256: str,
        attempt_observability_verified: bool,
    ) -> AuthenticatedWorkerExecutionEvidence:
        if issuer is not _AUTHENTICATED_EXECUTION_ISSUER:
            raise TypeError("AuthenticatedWorkerExecutionEvidence has no public constructor.")
        try:
            if type(authenticated_request) is not AuthenticatedWorkerRequestEvidence:
                raise ValueError
            request_readback = _readback_authenticated_request(authenticated_request)
            request = request_readback.request
            parsed_response = strict_json_loads(canonical_response_bytes)
            if (
                not isinstance(parsed_response, dict)
                or parsed_response != response
                or canonical_json_bytes(response) != canonical_response_bytes
                or retained_response_bundle.snapshot != response_snapshot
                or retained_response_bundle.private_bytes_for("response.json")
                != canonical_response_bytes
                or retained_response_bundle.bundle_digest
                != _retained_snapshot_digest(response_snapshot)
            ):
                raise ValueError
            validate_instance(response, "worker-protocol.schema.json", definition="WorkerResponse")
            if response["response_metadata_digest"] != response_metadata_digest(response):
                raise ValueError
            for field in (
                "request_id",
                "request_metadata_digest",
                "scientific_request_digest",
                "command",
                "core_code_digest",
            ):
                if response[field] != request[field]:
                    raise ValueError
            described_owner = request_readback.described_owner
            description = request_readback.description
            expected_identity = request["payload"].get("expected_identity")
            if isinstance(expected_identity, Mapping):
                _verify_pinned_response(
                    command=str(request["command"]),
                    response=response,
                    expected_identity=expected_identity,
                )
            elif description is not None:
                _verify_pinned_response(
                    command=str(request["command"]),
                    response=response,
                    expected_identity=description.expected_identity,
                )
            _verify_response_owner_digests(response, request, described_owner)
            expected_command_evidence = _command_evidence(request, response)
            if expected_command_evidence != command_evidence:
                raise ValueError

            request_arrays: Mapping[str, Any] = {}
            request_archive = request_readback.retained_request_bundle.snapshot.as_mapping().get(
                "values.npz"
            )
            if request_archive is not None:
                request_catalog = request["payload"]["execution_input_projection"]["dataset"][
                    "array_catalog"
                ]
                request_arrays = load_catalogued_npz_array_bytes(
                    request_readback.retained_request_bundle.private_bytes_for("values.npz"),
                    catalog=request_catalog,
                    max_aggregate_uncompressed_bytes=_MAX_INVOCATION_TREE_BYTES,
                )
            response_arrays: Mapping[str, Any] = {}
            catalog = _response_array_catalog(response)
            response_archive = response_snapshot.as_mapping().get("arrays.npz")
            if bool(catalog) != (response_archive is not None):
                raise ValueError
            if response_archive is not None:
                response_arrays = load_catalogued_npz_array_bytes(
                    retained_response_bundle.private_bytes_for("arrays.npz"),
                    catalog=catalog,
                    max_aggregate_uncompressed_bytes=_MAX_INVOCATION_TREE_BYTES,
                )
            validate_success_response_semantics(
                response=response,
                request=request,
                arrays=response_arrays,
                request_arrays=request_arrays,
                described_algorithm=(
                    None if described_owner is None else described_owner.algorithm
                ),
            )

            invocation_entries = invocation_snapshot.as_mapping()
            for relative_path, record in request_readback.retained_request_bundle.snapshot.entries:
                if invocation_entries.get(f"request/{relative_path}") != record:
                    raise ValueError
            for relative_path, record in response_snapshot.entries:
                invocation_path = f"response/{relative_path}"
                if invocation_path in _SIDE_EFFECT_INVENTORY_EXCLUSIONS:
                    continue
                if invocation_entries.get(invocation_path) != record:
                    raise ValueError
            if not isinstance(runtime_milliseconds, int) or runtime_milliseconds < 0:
                raise ValueError
            if not isinstance(attempt_observability_verified, bool):
                raise ValueError
            if not _is_sha256_digest(containment_launcher_sha256):
                raise ValueError
            command_evidence_reference = (
                None
                if command_evidence is None
                else {
                    "kind": _command_evidence_reference_kind(command_evidence),
                    "schema_version": command_evidence["command_evidence_schema_version"],
                    "digest": worker_command_evidence_digest(command_evidence),
                }
            )
            projection = {
                "execution_evidence_schema_version": (
                    "ebm-audit-authenticated-worker-execution-evidence/2.0"
                ),
                "protocol_version": response["protocol_version"],
                "response_schema_version": response["response_schema_version"],
                "payload_schema_version": response["payload_schema_version"],
                "command": response["command"],
                "status": response["status"],
                "authenticated_request_evidence_digest": request_readback.evidence_digest,
                "authenticated_description_response_metadata_digest": (
                    None if description is None else description.response_metadata_digest
                ),
                "planning_summary_id": request_readback.planning_summary_id,
                "selected_algorithm_binding_digest": (
                    request_readback.selected_algorithm_binding_digest
                ),
                "response_metadata_digest": response["response_metadata_digest"],
                "request_bundle_digest": (request_readback.retained_request_bundle.bundle_digest),
                "response_bundle_digest": retained_response_bundle.bundle_digest,
                "invocation_bundle_digest": _retained_snapshot_digest(invocation_snapshot),
                "command_evidence_reference": command_evidence_reference,
                "stdout_byte_length": stdout.byte_length,
                "stdout_sha256": stdout.sha256,
                "stderr_byte_length": stderr.byte_length,
                "stderr_sha256": stderr.sha256,
                "runtime_milliseconds": runtime_milliseconds,
                "containment_provider": containment_provider,
                "containment_launcher_sha256": containment_launcher_sha256,
                "attempt_observability_verified": attempt_observability_verified,
            }
            evidence_digest = authenticated_execution_evidence_digest(projection)
        except Exception:
            raise TypeError(
                "Authenticated execution evidence requires one exact fully verified response."
            ) from None
        self = object.__new__(cls)
        state = _AuthenticatedWorkerExecutionState(
            canonical_response_bytes=bytes(canonical_response_bytes),
            retained_response_bundle=retained_response_bundle,
            response_snapshot=response_snapshot,
            invocation_snapshot=invocation_snapshot,
            authenticated_request=authenticated_request,
            command_evidence=(None if command_evidence is None else deepcopy(command_evidence)),
            identity_projection=deepcopy(projection),
            evidence_digest=evidence_digest,
            stdout_byte_length=stdout.byte_length,
            stdout_sha256=stdout.sha256,
            stderr_byte_length=stderr.byte_length,
            stderr_sha256=stderr.sha256,
            runtime_milliseconds=runtime_milliseconds,
            containment_provider=containment_provider,
            containment_launcher_sha256=containment_launcher_sha256,
            attempt_observability_verified=attempt_observability_verified,
        )
        _AUTHENTICATED_EXECUTION_STATE_ISSUER.bind_once(self, state)
        _readback_authenticated_execution(self)
        return self

    def _state(self) -> _AuthenticatedWorkerExecutionState:
        try:
            return _AUTHENTICATED_EXECUTION_STATES[self]
        except KeyError:
            raise TypeError(
                "The authenticated execution capability was not issued by WorkerInvoker."
            ) from None

    def _response(self) -> Mapping[str, Any]:
        return deepcopy(_readback_authenticated_execution(self).response)

    def _arrays(self) -> Mapping[str, Any]:
        return _readback_authenticated_execution(self).response_arrays

    def _command_evidence(self) -> Mapping[str, Any] | None:
        evidence = _readback_authenticated_execution(self).command_evidence
        return None if evidence is None else deepcopy(evidence)

    def __repr__(self) -> str:
        _readback_authenticated_execution(self)
        return "AuthenticatedWorkerExecutionEvidence(<opaque complete response evidence>)"

    def __copy__(self) -> AuthenticatedWorkerExecutionEvidence:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> AuthenticatedWorkerExecutionEvidence:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    @property
    def authenticated_request(self) -> AuthenticatedWorkerRequestEvidence:
        return _readback_authenticated_execution(self).authenticated_request

    @property
    def command(self) -> str:
        return str(self._response()["command"])

    @property
    def status(self) -> str:
        return str(self._response()["status"])

    @property
    def response_metadata_digest(self) -> str:
        return str(self._response()["response_metadata_digest"])

    @property
    def identity_projection(self) -> Mapping[str, Any]:
        readback = _readback_authenticated_execution(self)
        return deepcopy(dict(readback.execution_identity_projection))

    @property
    def evidence_digest(self) -> str:
        return _readback_authenticated_execution(self).execution_evidence_digest

    def binds_authenticated_description(self, description: AuthenticatedWorkerDescription) -> bool:
        return (
            _readback_authenticated_execution(self).request_authenticated_description is description
        )

    def binds_selected_algorithm(self, binding: Mapping[str, Any]) -> bool:
        selected = _readback_authenticated_execution(self).request_selected_algorithm_binding
        return selected is not None and dict(selected) == dict(binding)


@dataclass(frozen=True, repr=False)
class _DescribedAlgorithmOwner:
    backend_identity: Mapping[str, Any]
    algorithm: Mapping[str, Any]


def _invocation_failure_class(
    error: WorkerProtocolError | PrivacyViolationError | UnexpectedCoreError,
) -> InvocationFailureClass:
    if isinstance(error, UnexpectedCoreError):
        return InvocationFailureClass.UNEXPECTED_CORE_ERROR
    if isinstance(error, PrivacyViolationError):
        return InvocationFailureClass.PRIVACY_VIOLATION
    if error.code == "TIMEOUT.WORKER_DEADLINE":
        return InvocationFailureClass.TIMEOUT
    if error.code in {"BACKEND.WORKER_START_FAILED", "BACKEND.WORKER_PROCESS_FAILED"}:
        return InvocationFailureClass.PROCESS_FAILURE
    if error.code == "PROTOCOL.RESPONSE_MISSING":
        return InvocationFailureClass.RESPONSE_MISSING
    if error.code == "PROTOCOL.RESPONSE_SCHEMA":
        return InvocationFailureClass.RESPONSE_INVALID
    return InvocationFailureClass.PROTOCOL_FAILURE


@dataclass(repr=False)
class _InvocationAttemptState:
    frame_written: bool = False
    authenticated_request: AuthenticatedWorkerRequestEvidence | None = None
    authenticated_description: AuthenticatedWorkerDescription | None = None
    selected_algorithm_id: str | None = None
    framed_response_metadata_digest: str | None = None
    safe_evidence: dict[str, int | str | bool] | None = None

    def mark_frame_written(self) -> None:
        self.frame_written = True

    def activate(
        self,
        *,
        authenticated_request: AuthenticatedWorkerRequestEvidence,
        authenticated_description: AuthenticatedWorkerDescription | None,
        selected_algorithm_id: str | None,
    ) -> None:
        self.authenticated_request = authenticated_request
        self.authenticated_description = authenticated_description
        self.selected_algorithm_id = selected_algorithm_id
        self.safe_evidence = {}

    def record(self, **evidence: int | str | bool) -> None:
        if self.safe_evidence is None:
            return
        if set(evidence) - _OBSERVATION_EVIDENCE_KEYS:
            raise TypeError("Invocation attempt recorded an unregistered evidence field.")
        self.safe_evidence.update(evidence)

    def issue(
        self,
        error: WorkerProtocolError | PrivacyViolationError | UnexpectedCoreError,
    ) -> WorkerInvocationObservation | None:
        if self.authenticated_request is None or self.safe_evidence is None:
            return None
        evidence = dict(self.safe_evidence)
        for key, value in error.details.items():
            if key in _OBSERVATION_EVIDENCE_KEYS:
                evidence[key] = value
        return WorkerInvocationObservation._issue(
            _INVOCATION_OBSERVATION_ISSUER,
            failure_class=_invocation_failure_class(error),
            failure_code=error.code,
            authenticated_request=self.authenticated_request,
            authenticated_description=self.authenticated_description,
            selected_algorithm_id=self.selected_algorithm_id,
            framed_response_metadata_digest=self.framed_response_metadata_digest,
            safe_evidence=evidence,
        )


@dataclass(frozen=True)
class _InvocationTreeObservation:
    file_count: int
    directory_count: int
    total_bytes: int
    observation_digest: str
    complete: bool


class _InvocationTreeLimitExceeded(Exception):
    def __init__(self, observation: _InvocationTreeObservation) -> None:
        super().__init__("The invocation tree exceeded a resource limit.")
        self.observation = observation


class _StreamDigestCollector:
    """Drain a process stream without retaining its potentially private bytes."""

    def __init__(
        self,
        stream: IO[bytes],
        *,
        hard_limit_bytes: int,
        on_overflow: Callable[[], None],
    ) -> None:
        self._stream = stream
        self._hard_limit_bytes = hard_limit_bytes
        self._on_overflow = on_overflow
        self._digest = hashlib.sha256()
        self._byte_length = 0
        self._error = False
        self._overflowed = False
        self._thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _drain(self) -> None:
        try:
            while True:
                block = self._stream.read(64 * 1024)
                if not block:
                    break
                self._byte_length += len(block)
                self._digest.update(block)
                if self._byte_length > self._hard_limit_bytes and not self._overflowed:
                    self._overflowed = True
                    self._on_overflow()
        except (OSError, ValueError):
            self._error = True
        finally:
            try:
                self._stream.close()
            except OSError:
                self._error = True

    def finish(self, *, timeout_seconds: float = 2.0) -> DiagnosticDigest:
        self._thread.join(timeout=timeout_seconds)
        if self._thread.is_alive() or self._error:
            raise WorkerProtocolError(
                "PROTOCOL.DIAGNOSTIC_STREAM",
                "A bounded worker diagnostic stream did not close cleanly.",
            )
        return DiagnosticDigest(
            byte_length=self._byte_length,
            sha256=f"sha256:{self._digest.hexdigest()}",
            truncated=self._byte_length > _STREAM_RETAINED_LIMIT,
        )

    @property
    def overflowed(self) -> bool:
        return self._overflowed


def _core_manifest_entry(relative_path: str, data: bytes) -> dict[str, str | int]:
    return {
        "relative_path": relative_path,
        "byte_length": len(data),
        "sha256": exact_file_sha256(data),
    }


def _core_code_manifest(
    *,
    package_root: Path | None = None,
    sitecustomize_path: Path | None = None,
    resource_reader: Callable[[str], bytes] = resource_bytes,
) -> dict[str, object]:
    """Build the path-stable closed inventory of operation-affecting core bytes."""

    resolved_package_root = (
        Path(__file__).resolve().parents[1] if package_root is None else package_root.resolve()
    )
    resolved_sitecustomize = (
        resolved_package_root.parent / "sitecustomize.py"
        if sitecustomize_path is None
        else sitecustomize_path.resolve()
    )
    entries: list[dict[str, str | int]] = []
    for path in sorted(resolved_package_root.rglob("*.py")):
        relative = path.relative_to(resolved_package_root)
        if relative.parts and relative.parts[0] in _CORE_PYTHON_EXCLUDED_PREFIXES:
            continue
        if not path.is_file() or path.is_symlink():
            raise WorkerProtocolError(
                "PROTOCOL.CORE_CODE_INVENTORY",
                "The auditor core code inventory is not a closed regular-file set.",
            )
        logical_path = PurePosixPath("ebm_audit") / relative
        entries.append(_core_manifest_entry(logical_path.as_posix(), path.read_bytes()))
    if not entries:
        raise WorkerProtocolError(
            "PROTOCOL.CORE_CODE_INVENTORY",
            "The auditor core code inventory is empty.",
        )
    if not resolved_sitecustomize.is_file() or resolved_sitecustomize.is_symlink():
        raise WorkerProtocolError(
            "PROTOCOL.CORE_CODE_INVENTORY",
            "The auditor offline guard is unavailable from the core code inventory.",
        )
    entries.append(_core_manifest_entry("sitecustomize.py", resolved_sitecustomize.read_bytes()))
    for name in RESOURCE_FILENAMES:
        entries.append(_core_manifest_entry(f"schemas/{name}", resource_reader(name)))
    entries.sort(key=lambda entry: str(entry["relative_path"]).encode("utf-8"))
    relative_paths = [entry["relative_path"] for entry in entries]
    if len(relative_paths) != len(set(relative_paths)):
        raise WorkerProtocolError(
            "PROTOCOL.CORE_CODE_INVENTORY",
            "The auditor core code inventory contains a duplicate logical path.",
        )
    return {
        "manifest_schema_version": "ebm-audit-core-code-manifest/1.1",
        "entries": entries,
    }


def _core_code_digest() -> str:
    return structured_sha256(
        "ebm-audit/core-code/1",
        _core_code_manifest(),
    )


def _prepare_worker_sdk_view(
    sdk_root: Path,
    *,
    package_root: Path | None = None,
    sitecustomize_path: Path | None = None,
) -> Path:
    """Expose audited worker SDK code without installation metadata."""

    resolved_package_root = (
        Path(__file__).resolve().parents[1] if package_root is None else package_root.resolve()
    )
    resolved_sitecustomize = (
        resolved_package_root.parent / "sitecustomize.py"
        if sitecustomize_path is None
        else sitecustomize_path.resolve()
    )
    resolved_sdk_root = sdk_root.resolve()
    if (
        sdk_root.is_symlink()
        or not resolved_sdk_root.is_dir()
        or not resolved_package_root.is_dir()
        or not resolved_sitecustomize.is_file()
    ):
        raise ValueError("The worker SDK view inputs are invalid.")

    package_link = resolved_sdk_root / "ebm_audit"
    sitecustomize_link = resolved_sdk_root / "sitecustomize.py"
    package_link.symlink_to(resolved_package_root, target_is_directory=True)
    sitecustomize_link.symlink_to(resolved_sitecustomize)
    if (
        not package_link.is_symlink()
        or package_link.resolve() != resolved_package_root
        or not sitecustomize_link.is_symlink()
        or sitecustomize_link.resolve() != resolved_sitecustomize
    ):
        raise ValueError("The worker SDK view could not be verified.")
    return resolved_sdk_root


def _offline_environment(
    *,
    invocation_root: Path,
    request_dir: Path,
    work_dir: Path,
    network_attempt_path: Path,
    outside_attempt_path: Path,
    guard_active_path: Path,
    worker_sdk_root: Path,
) -> dict[str, str]:
    environment = {
        "ALL_PROXY": "",
        "EBM_AUDIT_OFFLINE": "1",
        "EBM_AUDIT_INVOCATION_ROOT": str(invocation_root),
        "EBM_AUDIT_GUARD_ACTIVE_FILE": str(guard_active_path),
        "EBM_AUDIT_NETWORK_ATTEMPT_FILE": str(network_attempt_path),
        "EBM_AUDIT_OUTSIDE_ATTEMPT_FILE": str(outside_attempt_path),
        "EBM_AUDIT_REQUEST_DIR": str(request_dir),
        "EBM_AUDIT_WORK_DIR": str(work_dir),
        "HOME": str(work_dir),
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_PROXY": "*",
        "PATH": "/usr/bin:/bin",
        "PIP_NO_INDEX": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        # Supply only the audited SDK package and offline guard. In an installed
        # wheel, exposing the whole site-packages parent would also expose its
        # dist-info and corrupt exact worker-environment identity discovery.
        "PYTHONPATH": str(worker_sdk_root),
        "TMPDIR": str(work_dir),
        "UV_NO_INDEX": "1",
        "UV_OFFLINE": "1",
        "BLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }
    return environment


def _attempt_recorded(path: Path) -> bool:
    """Treat any worker-created sentinel state as a forbidden attempt."""

    try:
        return path.exists() or path.is_symlink()
    except OSError:
        return True


def _guard_activation_verified(path: Path) -> bool:
    try:
        return read_regular_file_exact(path) == b"offline-guard-active\n"
    except Exception:
        return False


def _terminate_process_group(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return
    except PermissionError:
        raise PrivacyViolationError(
            "PRIVACY.SUBPROCESS_OWNERSHIP_UNVERIFIED",
            "The worker process-group ownership could not be verified for safe cleanup.",
        ) from None


def _process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        raise PrivacyViolationError(
            "PRIVACY.SUBPROCESS_OWNERSHIP_UNVERIFIED",
            "The worker process-group ownership could not be verified for safe cleanup.",
        ) from None
    return True


def _wait_for_process_group_exit(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _process_group_exists(process):
            return True
        time.sleep(0.01)
    return not _process_group_exists(process)


def _terminate_residual_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Terminate descendants that retained the worker's fresh process group."""

    if not _process_group_exists(process):
        return False
    _terminate_process_group(process, signal.SIGTERM)
    if not _wait_for_process_group_exit(process, timeout_seconds=0.25):
        _terminate_process_group(process, signal.SIGKILL)
        if not _wait_for_process_group_exit(process, timeout_seconds=0.5):
            raise PrivacyViolationError(
                "PRIVACY.SUBPROCESS_CLEANUP_FAILED",
                "A worker subprocess could not be terminated inside its process boundary.",
            )
    return True


def _terminate_and_reap_process(process: subprocess.Popen[bytes]) -> int:
    """Stop the fresh worker process group and reap its leader deterministically."""

    return_code = process.poll()
    if return_code is not None:
        return return_code
    _terminate_process_group(process, signal.SIGTERM)
    try:
        return process.wait(timeout=_PROCESS_TERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process, signal.SIGKILL)
        try:
            return process.wait(timeout=_PROCESS_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            raise PrivacyViolationError(
                "PRIVACY.SUBPROCESS_CLEANUP_FAILED",
                "A worker subprocess could not be terminated inside its process boundary.",
            ) from None


def _wait_for_worker_exit(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    diagnostic_overflow: threading.Event,
) -> tuple[int, bool]:
    """Wait with a short poll so diagnostic overflow triggers prompt termination."""

    deadline = time.monotonic() + timeout_seconds
    while True:
        if diagnostic_overflow.is_set():
            return _terminate_and_reap_process(process), False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _terminate_and_reap_process(process), True
        try:
            return (
                process.wait(timeout=min(_PROCESS_WAIT_POLL_SECONDS, remaining)),
                False,
            )
        except subprocess.TimeoutExpired:
            continue


def _tree_observation_digest(entry_digests: list[bytes], *, complete: bool) -> str:
    digest = hashlib.sha256()
    digest.update(b"ebm-audit/invocation-tree-observation/1\x00")
    digest.update(b"complete\x00" if complete else b"partial\x00")
    for entry_digest in sorted(entry_digests):
        digest.update(entry_digest)
    return f"sha256:{digest.hexdigest()}"


def _tree_entry_digest(*, kind: bytes, relative_path: str, byte_length: int) -> bytes:
    encoded_path = os.fsencode(relative_path)
    digest = hashlib.sha256()
    digest.update(b"ebm-audit/invocation-tree-entry/1\x00")
    digest.update(kind)
    digest.update(len(encoded_path).to_bytes(8, byteorder="big", signed=False))
    digest.update(encoded_path)
    digest.update(byte_length.to_bytes(8, byteorder="big", signed=False))
    return digest.digest()


def _observe_invocation_tree(invocation_root: Path) -> _InvocationTreeObservation:
    """Bound a retained tree using metadata only, before any content hashing."""

    file_count = 0
    directory_count = 0
    total_bytes = 0
    entry_digests: list[bytes] = []
    pending: list[tuple[Path, tuple[str, ...]]] = [(invocation_root, ())]

    def observation(*, complete: bool) -> _InvocationTreeObservation:
        return _InvocationTreeObservation(
            file_count=file_count,
            directory_count=directory_count,
            total_bytes=total_bytes,
            observation_digest=_tree_observation_digest(
                entry_digests,
                complete=complete,
            ),
            complete=complete,
        )

    while pending:
        directory, prefix = pending.pop()
        try:
            iterator = os.scandir(directory)
        except OSError:
            raise WorkerProtocolError(
                "PROTOCOL.INVOCATION_TREE_INVENTORY",
                "The retained worker invocation tree could not be inspected safely.",
            ) from None
        with iterator:
            for entry in iterator:
                relative_parts = (*prefix, entry.name)
                relative_path = "/".join(relative_parts)
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError:
                    raise WorkerProtocolError(
                        "PROTOCOL.INVOCATION_TREE_INVENTORY",
                        "The retained worker invocation tree could not be inspected safely.",
                    ) from None
                if stat.S_ISDIR(entry_stat.st_mode):
                    directory_count += 1
                    entry_digests.append(
                        _tree_entry_digest(
                            kind=b"directory\x00",
                            relative_path=relative_path,
                            byte_length=0,
                        )
                    )
                    if directory_count > _MAX_INVOCATION_TREE_DIRECTORIES:
                        raise _InvocationTreeLimitExceeded(observation(complete=False))
                    pending.append((Path(entry.path), relative_parts))
                    continue
                if not stat.S_ISREG(entry_stat.st_mode):
                    raise WorkerProtocolError(
                        "PROTOCOL.INVOCATION_TREE_INVENTORY",
                        "The retained worker invocation tree contains an unsafe entry type.",
                    )
                file_count += 1
                total_bytes += entry_stat.st_size
                entry_digests.append(
                    _tree_entry_digest(
                        kind=b"file\x00",
                        relative_path=relative_path,
                        byte_length=entry_stat.st_size,
                    )
                )
                if (
                    file_count > _MAX_INVOCATION_TREE_FILES
                    or total_bytes > _MAX_INVOCATION_TREE_BYTES
                ):
                    raise _InvocationTreeLimitExceeded(observation(complete=False))
    return observation(complete=True)


def _enforce_invocation_tree_limits(invocation_root: Path) -> _InvocationTreeObservation:
    try:
        return _observe_invocation_tree(invocation_root)
    except _InvocationTreeLimitExceeded as error:
        observed = error.observation
        raise WorkerProtocolError(
            "PROTOCOL.INVOCATION_TREE_LIMIT_EXCEEDED",
            "The retained worker invocation tree exceeded its local resource limit.",
            details={
                "observed_file_count": observed.file_count,
                "observed_directory_count": observed.directory_count,
                "observed_total_bytes": observed.total_bytes,
                "observation_digest": observed.observation_digest,
                "maximum_file_count": _MAX_INVOCATION_TREE_FILES,
                "maximum_directory_count": _MAX_INVOCATION_TREE_DIRECTORIES,
                "maximum_total_bytes": _MAX_INVOCATION_TREE_BYTES,
            },
        ) from None


def _remaining_archive_expansion_budget(
    invocation_root: Path,
    archive_path: Path,
) -> int:
    """Replace one archive's physical bytes with its admitted logical bytes."""

    observed = _enforce_invocation_tree_limits(invocation_root)
    try:
        archive_stat = archive_path.stat(follow_symlinks=False)
    except OSError:
        raise WorkerProtocolError(
            "PROTOCOL.INVOCATION_TREE_INVENTORY",
            "The retained worker invocation tree could not be inspected safely.",
        ) from None
    if not stat.S_ISREG(archive_stat.st_mode) or archive_stat.st_size > observed.total_bytes:
        raise WorkerProtocolError(
            "PROTOCOL.INVOCATION_TREE_INVENTORY",
            "The retained worker invocation tree could not be inspected safely.",
        )
    physical_bytes_outside_archive = observed.total_bytes - archive_stat.st_size
    return _MAX_INVOCATION_TREE_BYTES - physical_bytes_outside_archive


def _response_array_catalog(response: Mapping[str, Any]) -> Mapping[str, Any]:
    if response.get("status") != "SUCCESS" or response.get("command") not in {
        "fit",
        "stage",
    }:
        return {}
    payload = response.get("payload")
    result = payload.get("result") if isinstance(payload, Mapping) else None
    catalog = result.get("array_catalog") if isinstance(result, Mapping) else None
    if not isinstance(catalog, Mapping):
        raise WorkerProtocolError(
            "PROTOCOL.RESPONSE_ARRAY_CATALOG",
            "The successful array-bearing response has no closed array catalog.",
        )
    return catalog


def _verify_request_owner_digests(command: str, payload: Mapping[str, Any]) -> None:
    if command not in {"validate", "fit", "stage"}:
        return
    try:
        owner = payload["execution_input_projection"]
        if not isinstance(owner, Mapping):
            raise TypeError
        validate_execution_input_projection(owner)
        if payload["execution_input_projection_digest"] != (
            execution_input_projection_digest(owner)
        ):
            raise ValueError
        settings = owner["settings"]
        requested_outputs = owner["requested_outputs"]
        if not isinstance(settings, Mapping) or not isinstance(requested_outputs, list):
            raise TypeError
        if owner["settings_digest"] != settings_digest(settings):
            raise ValueError
        if owner["requested_outputs_digest"] != requested_outputs_digest(
            command, requested_outputs
        ):
            raise ValueError
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.REQUEST_OWNER_DIGEST",
            "A request identity does not match its complete local owner.",
        ) from None


def _verify_raw_scientific_input(command: str, payload: Mapping[str, Any]) -> None:
    """Reject a detached caller-side owner before constructing the sole wire projection."""

    if command not in {"validate", "fit", "stage"}:
        return
    try:
        settings = payload["settings"]
        outputs = payload["requested_outputs"]
        if not isinstance(settings, Mapping) or not isinstance(outputs, list):
            raise TypeError
        if payload["settings_digest"] != settings_digest(settings):
            raise ValueError
        if payload["requested_outputs_digest"] != requested_outputs_digest(command, outputs):
            raise ValueError
        if command == "fit":
            attempt_id = payload["attempt_id"]
            attempt_ordinal = payload["attempt_ordinal"]
            if (
                not isinstance(attempt_id, str)
                or not attempt_id.startswith("sha256:")
                or len(attempt_id) != 71
                or attempt_ordinal not in {0, 1}
                or isinstance(attempt_ordinal, bool)
            ):
                raise ValueError
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.REQUEST_OWNER_DIGEST",
            "A caller-side request owner does not match its digest.",
        ) from None


def _materialize_stage_artifact(
    *,
    request_dir: Path,
    artifact: Mapping[str, Any],
    stage_artifact_path: Path | None,
    stage_artifact_bytes: bytes | None,
) -> tuple[str, dict[str, Any]]:
    """Copy one exact fitted artifact into the contained request bundle."""

    try:
        relative_path = str(artifact["relative_path"])
        relative = PurePosixPath(relative_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative_path in {"request.json", "values.npz"}
        ):
            raise ValueError
        declared_length = artifact["byte_length"]
        if isinstance(declared_length, bool) or not isinstance(declared_length, int):
            raise TypeError
        if stage_artifact_path is not None:
            material = read_regular_file_exact(stage_artifact_path, max_bytes=declared_length)
        else:
            if not isinstance(stage_artifact_bytes, bytes):
                raise TypeError
            material = stage_artifact_bytes
        digest = exact_file_sha256(material)
        if len(material) != declared_length or digest != artifact["sha256"]:
            raise ValueError
        destination = request_dir.joinpath(*relative.parts)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes(material)
        destination.chmod(0o600)
        return relative_path, {"byte_length": len(material), "sha256": digest}
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.STAGE_ARTIFACT_BINDING",
            "The explicit stage artifact does not match its contained binding.",
        ) from None


def _verify_success_result_owner_bindings(
    response: Mapping[str, Any],
    request: Mapping[str, Any],
) -> None:
    """Bind every repeated successful result field to its authoritative owner."""

    command = str(request["command"])
    if response["status"] != "SUCCESS" or command not in {"fit", "stage"}:
        return
    request_payload = request["payload"]
    execution_input = request_payload["execution_input_projection"]
    response_payload = response["payload"]
    result = response_payload["result"]
    backend_identity = response["backend_identity"]
    common_expected: dict[str, Any] = {
        "algorithm_id": execution_input["algorithm_id"],
        "settings_digest": execution_input["settings_digest"],
        "config_digest": execution_input["config_digest"],
        "requested_outputs_digest": requested_outputs_digest(
            command, execution_input["requested_outputs"]
        ),
    }
    if command in {"fit", "stage"}:
        common_expected["execution_input_projection_digest"] = request_payload[
            "execution_input_projection_digest"
        ]
    if any(response_payload[field] != value for field, value in common_expected.items()):
        raise ValueError

    dataset = execution_input["dataset"]
    backend_expected = {
        "core_code_digest": response["core_code_digest"],
        "worker_executable_digest": backend_identity["worker_executable_digest"],
        "worker_code_digest": backend_identity["worker_code_digest"],
        "backend_source_digest": backend_identity["backend_source_digest"],
        "environment_digest": backend_identity["environment_digest"],
        "capabilities_digest": response["capabilities_digest"],
        "input_digest": dataset["scientific_data_digest"],
        "event_ids": dataset["event_ids"],
        "stage_semantics_digest": dataset["stage_semantics_digest"],
    }
    if command == "fit":
        _verify_synthetic_provenance_binding(dataset, result)
        fit_expected = {
            **common_expected,
            "universe_id": request_payload["universe_id"],
            "chain_execution_id": request_payload["chain_execution_id"],
            "attempt_id": request_payload["attempt_id"],
            "attempt_ordinal": request_payload["attempt_ordinal"],
            "seed": request_payload["seed"],
            "chain_id": request_payload["chain_id"],
            **backend_expected,
            "preprocessing_manifest_digest": dataset["preprocessing_manifest_digest"],
        }
        if any(
            response_payload[field] != value
            for field, value in fit_expected.items()
            if field in response_payload
        ):
            raise ValueError
        if any(result[field] != value for field, value in fit_expected.items()):
            raise ValueError
        supplied_fit_digest = result["worker_fit_payload_digest"]
        fit_preimage = dict(result)
        fit_preimage.pop("worker_fit_payload_digest")
        if supplied_fit_digest != worker_fit_payload_digest(fit_preimage):
            raise ValueError
        return

    stage_expected = {
        **common_expected,
        "protocol_version": request["protocol_version"],
        "request_id": request["request_id"],
        "stage_call_id": request_payload["stage_call_id"],
        "seed": request_payload["seed"],
        "fitted_artifact": request_payload["fitted_artifact"],
        "stage_model_reference_digest": request_payload["fitted_artifact"][
            "stage_model_reference_digest"
        ],
        **backend_expected,
        "runtime_seconds": response["runtime_seconds"],
        "resource_summary": response["resource_summary"],
    }
    response_stage_expected = {
        **common_expected,
        "stage_call_id": request_payload["stage_call_id"],
        "seed": request_payload["seed"],
    }
    if any(
        response_payload[field] != value for field, value in response_stage_expected.items()
    ) or any(result[field] != value for field, value in stage_expected.items()):
        raise ValueError
    supplied_stage_digest = result["worker_stage_result_digest"]
    stage_preimage = dict(result)
    stage_preimage.pop("worker_stage_result_digest")
    if supplied_stage_digest != worker_stage_result_digest(stage_preimage):
        raise ValueError
    if len(result["warnings"]) != response["warnings_record_count"]:
        raise ValueError
    manifest = result["participant_event_manifest"]
    expected_stage_row_digest = dataset["array_catalog"]["stage_row_indexes"]["array_digest"]
    if not (
        manifest["request_training_participants"] == dataset["participant_count"]
        and manifest["returned_training_participants"] == dataset["participant_count"]
        and manifest["training_row_indexes_digest"] == expected_stage_row_digest
        and manifest["request_evaluation_participants"] == 0
        and manifest["returned_evaluation_participants"] == 0
        and manifest["evaluation_row_indexes_digest"] is None
        and manifest["request_events"] == dataset["event_ids"]
        and manifest["returned_events"] == dataset["event_ids"]
        and manifest["worker_removed_participants"] == []
        and manifest["worker_removed_events"] == []
        and manifest["worker_modified_cells"] == []
    ):
        raise ValueError


def _verify_synthetic_provenance_binding(
    dataset: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    """Require exact optional synthetic provenance propagation without disclosure."""

    if result.get("synthetic_provenance") != dataset.get("synthetic_provenance"):
        raise ValueError


def _verify_response_owner_digests(
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    described_owner: _DescribedAlgorithmOwner | None,
) -> None:
    try:
        if response["backend_identity_digest"] != backend_identity_digest(
            response["backend_identity"]
        ):
            raise ValueError
        response_capabilities = response["capabilities"]
        if response_capabilities is None:
            if response["capabilities_digest"] is not None:
                raise ValueError
        elif response["capabilities_digest"] != capabilities_digest(response_capabilities):
            raise ValueError

        command = request["command"]
        if command == "describe" and response["status"] == "SUCCESS":
            result = response["payload"]["result"]
            if result["requested_output_registry_digest"] != requested_output_registry_digest():
                raise ValueError
            if result["self_test_check_registry_digest"] != self_test_check_registry_digest():
                raise ValueError
            algorithms = result["supported_algorithms"]
            algorithm_ids = [algorithm["algorithm_id"] for algorithm in algorithms]
            if len(algorithm_ids) != len(set(algorithm_ids)):
                raise ValueError
            for algorithm in algorithms:
                if algorithm["capabilities_digest"] != capabilities_digest(
                    algorithm["capabilities"]
                ):
                    raise ValueError
                if algorithm["settings_schema_digest"] != settings_schema_digest(
                    algorithm["settings_schema"]
                ):
                    raise ValueError
                semantics = algorithm["adapter_semantics"]
                if (
                    algorithm["adapter_semantics_digest"] != adapter_semantics_digest(semantics)
                    or semantics["algorithm_id"] != algorithm["algorithm_id"]
                    or semantics["adapter_id"] != response["backend_identity"]["adapter_id"]
                    or semantics["supported_commands"] != algorithm["supported_commands"]
                    or semantics["capabilities_digest"] != algorithm["capabilities_digest"]
                    or semantics["settings_schema_digest"] != algorithm["settings_schema_digest"]
                    or semantics["stage_semantics_digest"] != algorithm["stage_semantics_digest"]
                    or semantics["requested_output_registry_digest"]
                    != result["requested_output_registry_digest"]
                ):
                    raise ValueError
                validate_settings_schema(algorithm["settings_schema"])
                mcmc_projection = semantics["mcmc_projection"]
                if mcmc_projection["availability"] == "AVAILABLE":
                    declared_settings = set(algorithm["settings_schema"]["properties"])
                    schedule_setting_ids = [
                        row["backend_setting_id"]
                        for row in mcmc_projection["schedule_bindings"]
                        if row["source_kind"] == "backend-setting"
                    ]
                    proposal_setting_ids = [
                        row["backend_setting_id"]
                        for row in mcmc_projection["proposal_setting_bindings"]
                    ]
                    if (
                        len(schedule_setting_ids) != len(set(schedule_setting_ids))
                        or not set(schedule_setting_ids).issubset(declared_settings)
                        or not set(proposal_setting_ids).issubset(declared_settings)
                    ):
                        raise ValueError
        if command in {"validate", "fit", "stage"}:
            request_payload = request["payload"]
            execution_input = (
                request_payload["execution_input_projection"]
                if command in {"validate", "fit", "stage"}
                else request_payload
            )
            if response["backend_identity"]["algorithm_id"] != execution_input["algorithm_id"]:
                raise ValueError
            if response["settings_digest"] != execution_input["settings_digest"] or response[
                "requested_outputs_digest"
            ] != requested_outputs_digest(command, execution_input["requested_outputs"]):
                raise ValueError
            if (
                command in {"validate", "fit", "stage"}
                and response["execution_input_projection_digest"]
                != request_payload["execution_input_projection_digest"]
            ):
                raise ValueError
            if response["status"] == "SUCCESS":
                response_payload = response["payload"]
                common_fields = (
                    "algorithm_id",
                    "settings_digest",
                    "config_digest",
                    "requested_outputs_digest",
                )
                for field in common_fields:
                    expected = (
                        requested_outputs_digest(command, execution_input["requested_outputs"])
                        if field == "requested_outputs_digest"
                        else execution_input[field]
                    )
                    if response_payload[field] != expected:
                        raise ValueError
                if (
                    command in {"validate", "fit", "stage"}
                    and response_payload["execution_input_projection_digest"]
                    != request_payload["execution_input_projection_digest"]
                ):
                    raise ValueError
                _verify_success_result_owner_bindings(response, request)
            if described_owner is None:
                raise ValueError
            expected_identity = dict(described_owner.backend_identity)
            expected_identity["algorithm_id"] = execution_input["algorithm_id"]
            if response["backend_identity"] != expected_identity:
                raise ValueError
            if response["capabilities"] != described_owner.algorithm["capabilities"]:
                raise ValueError
            if response["capabilities_digest"] != described_owner.algorithm["capabilities_digest"]:
                raise ValueError
        if command == "self-test" and response["status"] == "SUCCESS":
            request_payload = request["payload"]
            response_payload = response["payload"]
            receipt = response_payload["receipt"]
            backend_identity = response["backend_identity"]
            if response_payload["seed"] != request_payload["seed"]:
                raise ValueError
            if [check["check_id"] for check in receipt["checks"]] != request_payload[
                "requested_checks"
            ]:
                raise ValueError
            receipt_identity_pairs = {
                "worker_executable_digest": backend_identity["worker_executable_digest"],
                "worker_code_digest": backend_identity["worker_code_digest"],
                "backend_source_digest": backend_identity["backend_source_digest"],
                "environment_digest": backend_identity["environment_digest"],
            }
            if any(
                receipt[field] != expected for field, expected in receipt_identity_pairs.items()
            ):
                raise ValueError
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.RESPONSE_OWNER_DIGEST",
            "A response identity does not match its complete local owner.",
        ) from None


def _verify_invocation_inventory(
    invocation_root: Path,
    response: Mapping[str, Any],
) -> BundleSnapshot:
    bounded_before = _enforce_invocation_tree_limits(invocation_root)
    try:
        with os.scandir(invocation_root) as root_entries:
            root_layout = {
                entry.name for entry in root_entries if entry.is_dir(follow_symlinks=False)
            }
        if (
            root_layout != {"request", "response", "work"}
            or len(tuple(invocation_root.iterdir())) != 3
        ):
            raise ValueError
        side_effects = strict_json_loads(
            read_regular_file_exact(
                invocation_root / "response" / "side-effects.json",
                max_bytes=MAX_SIDE_EFFECTS_JSON_BYTES,
            )
        )
        if not isinstance(side_effects, Mapping):
            raise TypeError
        if tuple(side_effects["inventory_exclusions"]) != _SIDE_EFFECT_INVENTORY_EXCLUSIONS:
            raise ValueError
        if tuple(side_effects["unobserved_activity_classes"]) != _UNOBSERVED_ACTIVITY_CLASSES:
            raise ValueError
        snapshot = capture_bundle_snapshot(
            invocation_root,
            excluded_paths=frozenset(_SIDE_EFFECT_INVENTORY_EXCLUSIONS),
        )
        observed: list[dict[str, Any]] = [
            {
                "relative_path": path,
                "byte_length": record.byte_length,
                "sha256": record.sha256,
            }
            for path, record in snapshot.entries
        ]
        if any(
            not entry["relative_path"].startswith(("request/", "response/", "work/"))
            for entry in observed
        ):
            raise ValueError
        expected_partitions = {
            "retained_request_files": [
                entry for entry in observed if entry["relative_path"].startswith("request/")
            ],
            "retained_output_files": [
                entry for entry in observed if entry["relative_path"].startswith("response/")
            ],
            "retained_workspace_files": [
                entry for entry in observed if entry["relative_path"].startswith("work/")
            ],
        }
        if any(
            side_effects[collection_name] != expected
            for collection_name, expected in expected_partitions.items()
        ):
            raise ValueError
        if response["side_effects_file_digest"] != response["files"]["side-effects.json"]["sha256"]:
            raise ValueError
        if _enforce_invocation_tree_limits(invocation_root) != bounded_before:
            raise ValueError
    except (PrivacyViolationError, WorkerProtocolError):
        raise
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.SIDE_EFFECT_INVENTORY",
            "The worker side-effect inventory does not match the complete invocation tree.",
        ) from None
    return snapshot


def _partial_workspace_evidence(invocation_root: Path) -> dict[str, int | str | bool]:
    """Return privacy-safe evidence for a stopped partial invocation tree."""

    bounded_before = _enforce_invocation_tree_limits(invocation_root)
    try:
        snapshot = capture_bundle_snapshot(invocation_root)
        if _enforce_invocation_tree_limits(invocation_root) != bounded_before:
            raise ValueError
        digest = structured_sha256(
            "ebm-audit/partial-workspace/1",
            {
                "entries": [
                    {
                        "relative_path": relative_path,
                        "byte_length": record.byte_length,
                        "sha256": record.sha256,
                    }
                    for relative_path, record in snapshot.entries
                ]
            },
        )
    except (PrivacyViolationError, WorkerProtocolError):
        raise
    except Exception:
        return {
            "partial_inventory_complete": False,
            "partial_file_count": 0,
        }
    return {
        "partial_inventory_complete": True,
        "partial_file_count": len(snapshot.entries),
        "partial_workspace_digest": digest,
    }


def _resolve_described_algorithm_owner(
    execution: WorkerExecution,
    *,
    command: str,
    payload: Mapping[str, Any],
) -> _DescribedAlgorithmOwner:
    """Resolve one command to the exact validated description that owns it."""

    try:
        response = execution.response
        if response["status"] != "SUCCESS" or response["command"] != "describe":
            raise ValueError
        result = response["payload"]["result"]
        if command not in result["supported_commands"]:
            raise ValueError
        algorithm_id = payload["algorithm_id"]
        matching = [
            algorithm
            for algorithm in result["supported_algorithms"]
            if algorithm["algorithm_id"] == algorithm_id
        ]
        if len(matching) != 1:
            raise ValueError
        algorithm = matching[0]
        if command not in algorithm["supported_commands"]:
            if command == "stage":
                raise WorkerProtocolError(
                    "CAPABILITY.STAGE_UNSUPPORTED",
                    "The authenticated algorithm description does not support stage.",
                )
            raise ValueError
        validate_settings(payload["settings"], algorithm["settings_schema"])
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.DESCRIBE_COMMAND_OWNER",
            "The requested worker command does not match one exact described algorithm owner.",
        ) from None
    return _DescribedAlgorithmOwner(
        backend_identity=dict(response["backend_identity"]),
        algorithm=dict(algorithm),
    )


def _described_owner_from_description_readback(
    description: _AuthenticatedDescriptionReadback,
    *,
    command: str,
    payload: Mapping[str, Any],
) -> _DescribedAlgorithmOwner:
    """Resolve an owner without reopening the planning-time description registry."""

    try:
        result = description.description_result
        if command not in result["supported_commands"]:
            raise ValueError
        matching = [
            algorithm
            for algorithm in description.supported_algorithms
            if algorithm["algorithm_id"] == payload["algorithm_id"]
        ]
        if len(matching) != 1:
            raise ValueError
        algorithm = matching[0]
        if command not in algorithm["supported_commands"]:
            raise ValueError
        validate_settings(payload["settings"], algorithm["settings_schema"])
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.DESCRIBE_COMMAND_OWNER",
            "The requested worker command does not match one exact described algorithm owner.",
        ) from None
    return _DescribedAlgorithmOwner(
        backend_identity=deepcopy(dict(description.backend_identity)),
        algorithm=deepcopy(algorithm),
    )


def _verify_pinned_response(
    *,
    command: str,
    response: Mapping[str, Any],
    expected_identity: Mapping[str, Any],
) -> None:
    """Bind every configured command to the complete core-owned identity pin."""

    try:
        if command in {"describe", "self-test"}:
            if (
                response["backend_identity"] != expected_identity["base_backend_identity"]
                or response["backend_identity_digest"]
                != expected_identity["base_backend_identity_digest"]
            ):
                raise ValueError
            if command == "describe":
                if response["status"] != "SUCCESS":
                    raise ValueError
                result = response["payload"]["result"]
                matching = [
                    algorithm
                    for algorithm in result["supported_algorithms"]
                    if algorithm["algorithm_id"] == expected_identity["selected_algorithm_id"]
                ]
                if len(matching) != 1:
                    raise ValueError
                observed_pin = expected_identity_pin(
                    response["backend_identity"],
                    algorithm_id=str(expected_identity["selected_algorithm_id"]),
                    algorithm_capabilities_digest=str(matching[0]["capabilities_digest"]),
                )
                if observed_pin != expected_identity:
                    raise ValueError
            return
        if command in {"validate", "fit", "stage"} and (
            response["backend_identity_digest"]
            != expected_identity["selected_backend_identity_digest"]
            or response["backend_identity"]["algorithm_id"]
            != expected_identity["selected_algorithm_id"]
            or response["capabilities_digest"] != expected_identity["capabilities_digest"]
        ):
            raise ValueError
    except Exception:
        raise WorkerProtocolError(
            "PROTOCOL.EXPECTED_IDENTITY_MISMATCH",
            "The worker identity does not match the configured expectation.",
        ) from None


def _actual_worker_subject(
    request: Mapping[str, Any], response: Mapping[str, Any]
) -> dict[str, Any]:
    """Reconstruct the command-specific actual subject from verified owners."""

    command = str(request["command"])
    wire = request["payload"]
    projection = wire["execution_input_projection"]
    identity = response["backend_identity"]
    common = {
        "backend_identity_digest": response["backend_identity_digest"],
        "adapter_id": identity["adapter_id"],
        "adapter_version": identity["adapter_version"],
        "backend_name": identity["backend_name"],
        "backend_version": identity["backend_version"],
        "algorithm_id": identity["algorithm_id"],
        "worker_executable_digest": identity["worker_executable_digest"],
        "worker_code_digest": identity["worker_code_digest"],
        "backend_source_commit": identity["backend_source_commit"],
        "backend_source_digest": identity["backend_source_digest"],
        "environment_digest": identity["environment_digest"],
        "capabilities_digest": response["capabilities_digest"],
        "settings_digest": projection["settings_digest"],
        "execution_input_projection_digest": wire["execution_input_projection_digest"],
        "protocol_version": request["protocol_version"],
        "request_schema_version": request["request_schema_version"],
        "response_schema_version": response["response_schema_version"],
    }
    if command == "validate":
        return {
            "actual_subject_schema_version": "ebm-audit-actual-validate-worker-subject/2.0",
            "command": command,
            **common,
            "validation_payload_schema_version": request["payload_schema_version"],
            "validate_requested_outputs_digest": projection["requested_outputs_digest"],
        }
    if command == "fit":
        return {
            "actual_subject_schema_version": "ebm-audit-actual-fit-worker-subject/2.0",
            "command": command,
            "attempt_id": wire["attempt_id"],
            "attempt_ordinal": wire["attempt_ordinal"],
            **common,
            "worker_payload_schema_version": response["payload_schema_version"],
            "fit_requested_outputs_digest": projection["requested_outputs_digest"],
        }
    artifact = wire["fitted_artifact"]
    return {
        "actual_subject_schema_version": "ebm-audit-actual-stage-worker-subject/2.0",
        "command": command,
        "stage_call_id": wire["stage_call_id"],
        "fitted_artifact_sha256": artifact["sha256"],
        "stage_model_reference_digest": artifact["stage_model_reference_digest"],
        **common,
        "stage_scientific_input_schema_version": request["payload_schema_version"],
        "stage_result_schema_version": "ebm-audit-stage-result/2.0",
        "stage_requested_outputs_digest": projection["requested_outputs_digest"],
    }


def _command_evidence(
    request: Mapping[str, Any], response: Mapping[str, Any]
) -> dict[str, Any] | None:
    command = str(request["command"])
    if command not in {"validate", "fit", "stage"}:
        return None
    wire = request["payload"]
    subject = _actual_worker_subject(request, response)
    subject_digesters = {
        "validate": actual_validate_worker_subject_digest,
        "fit": actual_fit_worker_subject_digest,
        "stage": actual_stage_worker_subject_digest,
    }
    subject_digest = subject_digesters[command](subject)
    common: dict[str, Any] = {
        "command": command,
        "status": response["status"],
        "request_metadata_digest": request["request_metadata_digest"],
        "scientific_request_digest": request["scientific_request_digest"],
        "response_metadata_digest": response["response_metadata_digest"],
        "payload_schema_version": response["payload_schema_version"],
        "requested_outputs_digest": response["requested_outputs_digest"],
        "execution_input_projection_digest": response["execution_input_projection_digest"],
        "backend_identity_digest": response["backend_identity_digest"],
    }
    if response["status"] != "SUCCESS":
        evidence = {
            "command_evidence_schema_version": "ebm-audit-negative-command-evidence/2.0",
            **common,
            "payload_digest_kind": "NONE",
            "payload_digest": None,
            "capabilities_digest": response["capabilities_digest"],
            "settings_digest": response["settings_digest"],
            f"actual_{command}_worker_subject_preimage": subject,
            f"actual_{command}_worker_subject_digest": subject_digest,
            "error": response["error"],
        }
        if command == "fit":
            evidence["attempt_id"] = wire["attempt_id"]
            evidence["attempt_ordinal"] = wire["attempt_ordinal"]
        validate_instance(
            evidence,
            "worker-protocol.schema.json",
            definition="NegativeCommandEvidenceProjection",
        )
        return evidence
    if command == "validate":
        evidence = {
            "command_evidence_schema_version": "ebm-audit-validate-success-command-evidence/2.0",
            **common,
            "payload_digest_kind": "WORKER_VALIDATION_PAYLOAD",
            "payload_digest": worker_validation_payload_digest(response["payload"]),
            "actual_validate_worker_subject_digest": subject_digest,
        }
        definition = "ValidateSuccessCommandEvidenceProjection"
    elif command == "fit":
        result = response["payload"]["result"]
        evidence = {
            "command_evidence_schema_version": "ebm-audit-fit-success-command-evidence/2.0",
            **common,
            "attempt_id": wire["attempt_id"],
            "attempt_ordinal": wire["attempt_ordinal"],
            "payload_digest_kind": "WORKER_FIT_PAYLOAD",
            "payload_digest": result["worker_fit_payload_digest"],
            "actual_fit_worker_subject_digest": subject_digest,
        }
        definition = "FitSuccessCommandEvidenceProjection"
    else:
        result = response["payload"]["result"]
        evidence = {
            "command_evidence_schema_version": "ebm-audit-stage-success-command-evidence/2.0",
            **common,
            "stage_call_id": wire["stage_call_id"],
            "result_schema_version": result["stage_result_schema_version"],
            "payload_digest_kind": "WORKER_STAGE_RESULT",
            "payload_digest": result["worker_stage_result_digest"],
            "actual_stage_worker_subject_digest": subject_digest,
        }
        definition = "StageSuccessCommandEvidenceProjection"
    validate_instance(
        evidence,
        "worker-protocol.schema.json",
        definition=definition,
    )
    return evidence


def _command_evidence_reference_kind(evidence: Mapping[str, Any]) -> str:
    """Return the closed execution-reference kind for active command evidence."""

    command = evidence.get("command")
    status = evidence.get("status")
    if command not in {"validate", "fit"}:
        raise TypeError("Only validate and fit command evidence are active.")
    suffix = "SUCCESS" if status == "SUCCESS" else "NEGATIVE"
    return f"{str(command).upper()}_{suffix}"


@dataclass(frozen=True, repr=False)
class _AuthenticatedExecutionReadback:
    """Fresh private readback rebuilt only from exact retained bundle owners."""

    execution: AuthenticatedWorkerExecutionEvidence
    request_readback: _AuthenticatedRequestReadback
    authenticated_request: AuthenticatedWorkerRequestEvidence
    request_planning_summary_id: str | None
    request_authenticated_description: AuthenticatedWorkerDescription | None
    request_selected_algorithm_binding: Mapping[str, Any] | None
    request_execution_input_projection_digest: str | None
    request: Mapping[str, Any]
    response: Mapping[str, Any]
    command_evidence: Mapping[str, Any] | None
    execution_identity_projection: Mapping[str, Any]
    execution_evidence_digest: str
    retained_response_bundle: _RetainedBundle
    request_arrays: Mapping[str, Any]
    response_arrays: Mapping[str, Any]

    def response_file_bytes(self, relative_path: str) -> bytes:
        """Return one member from the exact bundle proved by this readback."""

        return self.retained_response_bundle.private_bytes_for(relative_path)


def _revalidate_retained_bundle(value: object) -> _RetainedBundle:
    """Reprove one retained bundle's closed snapshot from every private byte."""

    if type(value) is not _RetainedBundle:
        raise TypeError("Authenticated evidence has no exact retained bundle.")
    bundle = value
    snapshot = bundle.snapshot
    if (
        type(snapshot) is not BundleSnapshot
        or type(bundle.files) is not tuple
        or bundle.bundle_digest != _retained_snapshot_digest(snapshot)
        or len(bundle.files) != len(snapshot.entries)
    ):
        raise TypeError("Authenticated evidence retained bundle is invalid.")
    for retained, (relative_path, record) in zip(
        bundle.files,
        snapshot.entries,
        strict=True,
    ):
        if (
            type(retained) is not _RetainedFile
            or retained.relative_path != relative_path
            or type(retained.private_bytes) is not bytes
            or retained.byte_length != record.byte_length
            or retained.sha256 != record.sha256
            or len(retained.private_bytes) != record.byte_length
            or exact_file_sha256(retained.private_bytes) != record.sha256
        ):
            raise TypeError("Authenticated evidence retained bundle is invalid.")
    return bundle


def _declared_files_match_snapshot(
    value: object,
    snapshot: BundleSnapshot,
    *,
    metadata_name: str,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    observed = {
        relative_path: record.to_mapping()
        for relative_path, record in snapshot.entries
        if relative_path != metadata_name
    }
    return metadata_name in snapshot.as_mapping() and dict(value) == observed


def _verify_execution_input_description_binding(
    projection: Mapping[str, Any],
    *,
    description: _AuthenticatedDescriptionReadback,
    described_owner: _DescribedAlgorithmOwner,
) -> None:
    """Bind every repeated execution-input owner field to one Describe snapshot."""

    try:
        binding = description.selected_algorithm_binding
        expected_identity = description.expected_identity
        algorithm = described_owner.algorithm
        selected_backend_identity = deepcopy(dict(described_owner.backend_identity))
        selected_backend_identity["algorithm_id"] = binding["algorithm_id"]
        if (
            projection["selected_backend_identity"] != selected_backend_identity
            or projection["selected_backend_identity_digest"]
            != expected_identity["selected_backend_identity_digest"]
            or projection["algorithm_id"] != binding["algorithm_id"]
            or projection["capabilities"] != algorithm["capabilities"]
            or projection["capabilities_digest"] != binding["capabilities_digest"]
            or projection["adapter_semantics"] != algorithm["adapter_semantics"]
            or projection["adapter_semantics_digest"] != binding["adapter_semantics_digest"]
            or projection["stage_semantics_definition"] != algorithm["stage_semantics_definition"]
            or projection["stage_semantics_digest"] != binding["stage_semantics_digest"]
            or algorithm["settings_schema_digest"] != binding["settings_schema_digest"]
            or selected_backend_identity["adapter_id"] != binding["adapter_id"]
            or selected_backend_identity["backend_name"] != binding["expected_backend_name"]
            or selected_backend_identity["backend_source_digest"]
            != binding["expected_backend_source_digest"]
            or binding["description_response_metadata_digest"]
            != description.response_metadata_digest
            or binding["expected_identity_pin_digest"] != description.expected_identity_digest
            or expected_identity["capabilities_digest"] != binding["capabilities_digest"]
        ):
            raise ValueError
        validate_settings(projection["settings"], algorithm["settings_schema"])
        if (
            settings_schema_digest(algorithm["settings_schema"])
            != binding["settings_schema_digest"]
        ):
            raise ValueError
    except Exception:
        raise TypeError(
            "Execution input is detached from its exact authenticated description."
        ) from None


class _AuthenticatedRequestReadback(NamedTuple):
    """One exact request snapshot including its complete Describe-owned authority."""

    request_evidence: AuthenticatedWorkerRequestEvidence
    canonical_request_bytes: bytes
    retained_request_bundle: _RetainedBundle
    request: Mapping[str, Any]
    command: str
    request_metadata_digest: str
    scientific_request_digest: str | None
    execution_input_projection_digest: str | None
    prepared_candidate_execution_context: object | None
    prepared_candidate_execution_context_state: object | None
    authenticated_description: AuthenticatedWorkerDescription | None
    description: _AuthenticatedDescriptionReadback | None
    described_owner: _DescribedAlgorithmOwner | None
    planning_summary_id: str | None
    selected_algorithm_binding: Mapping[str, Any] | None
    selected_algorithm_binding_digest: str | None
    profile_fit_receipt_row: object | None
    identity_projection: Mapping[str, Any]
    evidence_digest: str


def _readback_authenticated_request_unchecked(
    value: object,
) -> _AuthenticatedRequestReadback:
    if type(value) is not AuthenticatedWorkerRequestEvidence:
        raise TypeError("Authenticated execution has no exact request evidence.")
    request_evidence = value
    state = request_evidence._state()
    if type(state) is not _AuthenticatedWorkerRequestState:
        raise TypeError("Authenticated execution has no exact request evidence.")
    bundle = _revalidate_retained_bundle(state.retained_request_bundle)
    request = strict_json_loads(state.canonical_request_bytes)
    if (
        not isinstance(request, dict)
        or canonical_json_bytes(request) != state.canonical_request_bytes
        or bundle.private_bytes_for("request.json") != state.canonical_request_bytes
        or not _declared_files_match_snapshot(
            request.get("files"),
            bundle.snapshot,
            metadata_name="request.json",
        )
    ):
        raise TypeError("Authenticated request failed exact bundle readback.")

    validate_instance(request, "worker-protocol.schema.json", definition="WorkerRequest")
    validate_request_execution_input_binding(request)
    _verify_request_owner_digests(str(request["command"]), request["payload"])
    if request["request_metadata_digest"] != request_metadata_digest(request) or request[
        "scientific_request_digest"
    ] != scientific_request_digest(request):
        raise TypeError("Authenticated request failed exact bundle readback.")

    projection_digest: str | None = None
    payload = request.get("payload")
    if isinstance(payload, Mapping):
        candidate = payload.get("execution_input_projection_digest")
        if isinstance(candidate, str):
            projection = payload.get("execution_input_projection")
            if not isinstance(
                projection, Mapping
            ) or candidate != execution_input_projection_digest(projection):
                raise TypeError("Authenticated request failed exact bundle readback.")
            projection_digest = candidate

    profile_fit_owner: Any | None = None
    if state.profile_fit_receipt_row is not None:
        from ebm_audit.runner.profile_validation import (
            _profile_fit_request_owner_from_row,
        )

        profile_fit_owner = _profile_fit_request_owner_from_row(state.profile_fit_receipt_row)
    description = state.authenticated_description
    description_readback: _AuthenticatedDescriptionReadback | None = None
    described_owner: _DescribedAlgorithmOwner | None = None
    description_digest: str | None = None
    selected_binding_digest: str | None = None
    if description is None:
        if (
            state.selected_algorithm_binding is not None
            or state.authenticated_description_state is not None
            or state.authenticated_description_readback is not None
            or request["command"] in {"validate", "fit", "stage", "self-test"}
        ):
            raise TypeError("Authenticated request failed exact owner readback.")
    else:
        if type(description) is not AuthenticatedWorkerDescription:
            raise TypeError("Authenticated request failed exact owner readback.")
        if profile_fit_owner is None:
            description_readback = cast(
                _AuthenticatedDescriptionReadback,
                state.authenticated_description_readback,
            )
            if (
                type(description_readback) is not _AuthenticatedDescriptionReadback
                or description_readback.description is not description
                or _AUTHENTICATED_DESCRIPTION_STATES.get(description)
                is not state.authenticated_description_state
            ):
                raise TypeError("Authenticated request failed exact owner readback.")
        else:
            owner_context = profile_fit_owner.invocation_context
            description_readback = owner_context.description
            _AUTHENTICATED_DESCRIPTION_STATES.require(
                description,
                owner_context.authenticated_description_state,
            )
            if (
                description is not owner_context.authenticated_description
                or state.authenticated_description_state
                is not owner_context.authenticated_description_state
                or state.authenticated_description_readback != description_readback
            ):
                raise TypeError("Authenticated request failed exact owner readback.")
        description_readback = cast(
            _AuthenticatedDescriptionReadback,
            description_readback,
        )
        expected_binding = description_readback.selected_algorithm_binding
        if state.selected_algorithm_binding is None or dict(
            state.selected_algorithm_binding
        ) != dict(expected_binding):
            raise TypeError("Authenticated request failed exact owner readback.")
        description_digest = description_readback.response_metadata_digest
        selected_binding_digest = description_readback.selected_algorithm_binding_digest
        if request["command"] in {"validate", "fit", "stage"}:
            execution_input = request["payload"]["execution_input_projection"]
            described_owner = _described_owner_from_description_readback(
                description_readback,
                command=str(request["command"]),
                payload=execution_input,
            )
            _verify_execution_input_description_binding(
                execution_input,
                description=description_readback,
                described_owner=described_owner,
            )

    if (
        state.planning_summary_id is not None and not _is_sha256_digest(state.planning_summary_id)
    ) or (request["command"] not in {"validate", "fit"} and state.planning_summary_id is not None):
        raise TypeError("Authenticated request failed exact owner readback.")
    if state.prepared_candidate_execution_context is None:
        if (
            state.planning_summary_id is not None
            or state.prepared_candidate_execution_context_state is not None
            or state.profile_fit_receipt_row is not None
        ):
            raise TypeError("Authenticated request failed exact owner readback.")
    else:
        if profile_fit_owner is None:
            context_state = _read_prepared_candidate_execution_context(
                state.prepared_candidate_execution_context
            )
            invocation_context = context_state.invocation_context
        else:
            context_state = _require_prepared_candidate_execution_context_state_identity(
                state.prepared_candidate_execution_context,
                profile_fit_owner.candidate_execution_context_state,
            )
            invocation_context = profile_fit_owner.invocation_context
        if (
            request["command"] not in {"validate", "fit"}
            or context_state is not state.prepared_candidate_execution_context_state
            or state.planning_summary_id != invocation_context.planning_summary_id
            or description is not invocation_context.authenticated_description
            or state.selected_algorithm_binding is None
            or dict(state.selected_algorithm_binding)
            != dict(invocation_context.selected_algorithm_binding)
        ):
            raise TypeError("Authenticated request failed exact owner readback.")

    identity_projection = {
        "request_evidence_schema_version": ("ebm-audit-authenticated-worker-request-evidence/2.0"),
        "protocol_version": request["protocol_version"],
        "request_schema_version": request["request_schema_version"],
        "payload_schema_version": request["payload_schema_version"],
        "command": request["command"],
        "request_metadata_digest": request["request_metadata_digest"],
        "scientific_request_digest": request["scientific_request_digest"],
        "execution_input_projection_digest": projection_digest,
        "request_bundle_digest": bundle.bundle_digest,
        "authenticated_description_response_metadata_digest": description_digest,
        "planning_summary_id": state.planning_summary_id,
        "selected_algorithm_binding_digest": selected_binding_digest,
    }
    if (
        dict(state.identity_projection) != identity_projection
        or state.evidence_digest != authenticated_request_evidence_digest(identity_projection)
        or state.command != request["command"]
        or state.request_metadata_digest != request["request_metadata_digest"]
        or state.scientific_request_digest != request["scientific_request_digest"]
        or state.execution_input_projection_digest != projection_digest
        or state.selected_algorithm_binding_digest != selected_binding_digest
    ):
        raise TypeError("Authenticated request failed exact owner readback.")
    return _AuthenticatedRequestReadback(
        request_evidence=request_evidence,
        canonical_request_bytes=bytes(state.canonical_request_bytes),
        retained_request_bundle=bundle,
        request=MappingProxyType(deepcopy(request)),
        command=str(request["command"]),
        request_metadata_digest=str(request["request_metadata_digest"]),
        scientific_request_digest=(
            None
            if request["scientific_request_digest"] is None
            else str(request["scientific_request_digest"])
        ),
        execution_input_projection_digest=projection_digest,
        prepared_candidate_execution_context=(state.prepared_candidate_execution_context),
        prepared_candidate_execution_context_state=(
            state.prepared_candidate_execution_context_state
        ),
        authenticated_description=description,
        description=description_readback,
        described_owner=described_owner,
        planning_summary_id=state.planning_summary_id,
        selected_algorithm_binding=(
            None
            if state.selected_algorithm_binding is None
            else MappingProxyType(deepcopy(dict(state.selected_algorithm_binding)))
        ),
        selected_algorithm_binding_digest=selected_binding_digest,
        profile_fit_receipt_row=state.profile_fit_receipt_row,
        identity_projection=MappingProxyType(deepcopy(identity_projection)),
        evidence_digest=state.evidence_digest,
    )


def _readback_authenticated_request(
    value: object,
) -> _AuthenticatedRequestReadback:
    """Totalize every exact request-bundle or owner failure at one safe boundary."""

    try:
        return _readback_authenticated_request_unchecked(value)
    except Exception:
        raise TypeError("Authenticated request evidence failed exact bundle readback.") from None


@dataclass(frozen=True, repr=False)
class _WorkerInvocationObservationReadback:
    """Fresh closed readback of one core-observed invocation failure."""

    observation: WorkerInvocationObservation
    request_readback: _AuthenticatedRequestReadback
    failure_class: InvocationFailureClass
    failure_code: str
    authenticated_request: AuthenticatedWorkerRequestEvidence
    request: Mapping[str, Any]
    request_planning_summary_id: str | None
    authenticated_description: AuthenticatedWorkerDescription | None
    selected_algorithm_binding_digest: str | None
    framed_response_metadata_digest: str | None
    safe_evidence: Mapping[str, int | str | bool]
    identity_projection: Mapping[str, Any]
    observation_digest: str


def _readback_worker_invocation_observation(
    value: object,
) -> _WorkerInvocationObservationReadback:
    """Reprove exact request, owner, and closed failure identity on every read."""

    try:
        if type(value) is not WorkerInvocationObservation:
            raise TypeError
        observation = value
        state = observation._state()
        if type(state) is not _WorkerInvocationObservationState:
            raise TypeError
        issuance_projection_bytes = _INVOCATION_OBSERVATION_ISSUANCE_PROJECTIONS[observation]
        if type(issuance_projection_bytes) is not bytes:
            raise TypeError
        request_readback = _readback_authenticated_request(state.authenticated_request)
        request_evidence = request_readback.request_evidence
        request = request_readback.request
        if (
            type(state.failure_class) is not InvocationFailureClass
            or type(state.failure_code) is not str
            or not state.failure_code
            or not isinstance(state.safe_evidence, Mapping)
            or set(state.safe_evidence) - _OBSERVATION_EVIDENCE_KEYS
            or any(not isinstance(item, (int, str, bool)) for item in state.safe_evidence.values())
            or (
                state.framed_response_metadata_digest is not None
                and not _is_sha256_digest(state.framed_response_metadata_digest)
            )
        ):
            raise TypeError

        description = state.authenticated_description
        description_digest: str | None = None
        selected_binding_digest: str | None = None
        if description is not request_readback.authenticated_description:
            raise TypeError
        if description is None:
            if state.selected_algorithm_id is not None:
                raise TypeError
        else:
            description_readback = request_readback.description
            if (
                type(description) is not AuthenticatedWorkerDescription
                or description_readback is None
            ):
                raise TypeError
            if (
                state.selected_algorithm_id
                != description_readback.expected_identity["selected_algorithm_id"]
            ):
                raise TypeError
            description_digest = description_readback.response_metadata_digest
            selected_binding_digest = description_readback.selected_algorithm_binding_digest
        if selected_binding_digest != request_readback.selected_algorithm_binding_digest:
            raise TypeError

        expected_identity_projection = {
            "observation_schema_version": "ebm-audit-core-observed-failure/2.0",
            "failure_class": state.failure_class.value,
            "failure_code": state.failure_code,
            "authenticated_request_evidence_digest": request_readback.evidence_digest,
            "authenticated_description_response_metadata_digest": (description_digest),
            "selected_algorithm_binding_digest": selected_binding_digest,
            "framed_response_metadata_digest": (state.framed_response_metadata_digest),
            "safe_evidence": dict(state.safe_evidence),
        }
        canonical_identity_projection = strict_json_loads(state.canonical_identity_projection_bytes)
        if (
            not isinstance(canonical_identity_projection, dict)
            or canonical_json_bytes(canonical_identity_projection)
            != state.canonical_identity_projection_bytes
            or canonical_identity_projection != expected_identity_projection
            or state.canonical_identity_projection_bytes != issuance_projection_bytes
            or dict(state.identity_projection) != expected_identity_projection
            or state.observation_digest
            != core_observed_failure_digest(expected_identity_projection)
        ):
            raise TypeError
        return _WorkerInvocationObservationReadback(
            observation=observation,
            request_readback=request_readback,
            failure_class=state.failure_class,
            failure_code=state.failure_code,
            authenticated_request=request_evidence,
            request=deepcopy(dict(request)),
            request_planning_summary_id=request_readback.planning_summary_id,
            authenticated_description=description,
            selected_algorithm_binding_digest=selected_binding_digest,
            framed_response_metadata_digest=state.framed_response_metadata_digest,
            safe_evidence=MappingProxyType(deepcopy(dict(state.safe_evidence))),
            identity_projection=MappingProxyType(deepcopy(expected_identity_projection)),
            observation_digest=state.observation_digest,
        )
    except Exception:
        raise TypeError("Invocation observation failed exact authenticated readback.") from None


def _revalidate_invocation_snapshot(
    snapshot: object,
    *,
    request_bundle: _RetainedBundle,
    response_bundle: _RetainedBundle,
    response: Mapping[str, Any],
) -> BundleSnapshot:
    """Reprove the exact retained invocation inventory and its three partitions."""

    if type(snapshot) is not BundleSnapshot:
        raise TypeError("Authenticated execution has no exact invocation snapshot.")
    side_effects = strict_json_loads(response_bundle.private_bytes_for("side-effects.json"))
    if (
        not isinstance(side_effects, Mapping)
        or tuple(side_effects["inventory_exclusions"]) != _SIDE_EFFECT_INVENTORY_EXCLUSIONS
        or tuple(side_effects["unobserved_activity_classes"]) != _UNOBSERVED_ACTIVITY_CLASSES
    ):
        raise TypeError("Authenticated execution inventory failed exact readback.")

    observed_with_paths: list[tuple[str, dict[str, str | int]]] = [
        (
            relative_path,
            {
                "relative_path": relative_path,
                "byte_length": record.byte_length,
                "sha256": record.sha256,
            },
        )
        for relative_path, record in snapshot.entries
    ]
    if any(
        not relative_path.startswith(("request/", "response/", "work/"))
        for relative_path, _entry in observed_with_paths
    ):
        raise TypeError("Authenticated execution inventory failed exact readback.")
    expected_partitions = {
        "retained_request_files": [
            entry
            for relative_path, entry in observed_with_paths
            if relative_path.startswith("request/")
        ],
        "retained_output_files": [
            entry
            for relative_path, entry in observed_with_paths
            if relative_path.startswith("response/")
        ],
        "retained_workspace_files": [
            entry
            for relative_path, entry in observed_with_paths
            if relative_path.startswith("work/")
        ],
    }
    expected_request_files = [
        {
            "relative_path": f"request/{relative_path}",
            "byte_length": record.byte_length,
            "sha256": record.sha256,
        }
        for relative_path, record in request_bundle.snapshot.entries
    ]
    expected_output_files = [
        {
            "relative_path": f"response/{relative_path}",
            "byte_length": record.byte_length,
            "sha256": record.sha256,
        }
        for relative_path, record in response_bundle.snapshot.entries
        if f"response/{relative_path}" not in _SIDE_EFFECT_INVENTORY_EXCLUSIONS
    ]
    if (
        any(
            side_effects[collection_name] != expected
            for collection_name, expected in expected_partitions.items()
        )
        or expected_partitions["retained_request_files"] != expected_request_files
        or expected_partitions["retained_output_files"] != expected_output_files
        or response["side_effects_file_digest"] != response["files"]["side-effects.json"]["sha256"]
    ):
        raise TypeError("Authenticated execution inventory failed exact readback.")
    return snapshot


def _readback_authenticated_execution(
    value: object,
) -> _AuthenticatedExecutionReadback:
    """Reprove exact request/response bytes and semantics before returning arrays."""

    try:
        if type(value) is not AuthenticatedWorkerExecutionEvidence:
            raise TypeError
        execution = value
        state = execution._state()
        if type(state) is not _AuthenticatedWorkerExecutionState:
            raise TypeError
        request_readback = _readback_authenticated_request(state.authenticated_request)
        request_evidence = request_readback.request_evidence
        request = request_readback.request
        response_bundle = _revalidate_retained_bundle(state.retained_response_bundle)
        response = strict_json_loads(state.canonical_response_bytes)
        if (
            not isinstance(response, dict)
            or canonical_json_bytes(response) != state.canonical_response_bytes
            or state.response_snapshot != response_bundle.snapshot
            or response_bundle.private_bytes_for("response.json") != state.canonical_response_bytes
            or not _declared_files_match_snapshot(
                response.get("files"),
                response_bundle.snapshot,
                metadata_name="response.json",
            )
        ):
            raise TypeError
        validate_instance(
            response,
            "worker-protocol.schema.json",
            definition="WorkerResponse",
        )
        if response["response_metadata_digest"] != response_metadata_digest(response):
            raise TypeError
        for field in (
            "request_id",
            "request_metadata_digest",
            "scientific_request_digest",
            "command",
            "core_code_digest",
        ):
            if response[field] != request[field]:
                raise TypeError

        description = request_readback.description
        described_owner = request_readback.described_owner
        expected_identity = request["payload"].get("expected_identity")
        if isinstance(expected_identity, Mapping):
            _verify_pinned_response(
                command=str(request["command"]),
                response=response,
                expected_identity=expected_identity,
            )
        elif description is not None:
            _verify_pinned_response(
                command=str(request["command"]),
                response=response,
                expected_identity=description.expected_identity,
            )
        _verify_response_owner_digests(response, request, described_owner)

        request_arrays: Mapping[str, Any] = {}
        request_archive = request_readback.retained_request_bundle.snapshot.as_mapping().get(
            "values.npz"
        )
        request_catalog: Mapping[str, Any] = {}
        if request["command"] in {"validate", "fit", "stage"}:
            candidate_catalog = request["payload"]["execution_input_projection"]["dataset"][
                "array_catalog"
            ]
            if not isinstance(candidate_catalog, Mapping):
                raise TypeError
            request_catalog = candidate_catalog
        if bool(request_catalog) != (request_archive is not None):
            raise TypeError
        if request_archive is not None:
            request_arrays = load_catalogued_npz_array_bytes(
                request_readback.retained_request_bundle.private_bytes_for("values.npz"),
                catalog=request_catalog,
                max_aggregate_uncompressed_bytes=_MAX_INVOCATION_TREE_BYTES,
            )

        immutable_request_arrays: dict[str, Any] = {}
        for name, array in request_arrays.items():
            snapshot = np.frombuffer(
                array.tobytes(order="C"),
                dtype=array.dtype,
            ).reshape(array.shape)
            snapshot.setflags(write=False)
            immutable_request_arrays[name] = snapshot
        readonly_request_arrays = MappingProxyType(immutable_request_arrays)

        response_catalog = _response_array_catalog(response)
        response_archive = response_bundle.snapshot.as_mapping().get("arrays.npz")
        if bool(response_catalog) != (response_archive is not None):
            raise TypeError
        response_arrays: Mapping[str, Any] = {}
        if response_archive is not None:
            response_arrays = load_catalogued_npz_array_bytes(
                response_bundle.private_bytes_for("arrays.npz"),
                catalog=response_catalog,
                max_aggregate_uncompressed_bytes=_MAX_INVOCATION_TREE_BYTES,
            )
        immutable_response_arrays: dict[str, Any] = {}
        for name, array in response_arrays.items():
            snapshot = np.frombuffer(
                array.tobytes(order="C"),
                dtype=array.dtype,
            ).reshape(array.shape)
            immutable_response_arrays[name] = snapshot
        readonly_response_arrays = MappingProxyType(immutable_response_arrays)

        validate_success_response_semantics(
            response=response,
            request=request,
            arrays=readonly_response_arrays,
            request_arrays=request_arrays,
            described_algorithm=(None if described_owner is None else described_owner.algorithm),
        )

        command_evidence = _command_evidence(request, response)
        if command_evidence != state.command_evidence:
            raise TypeError
        command_evidence_reference = (
            None
            if command_evidence is None
            else {
                "kind": _command_evidence_reference_kind(command_evidence),
                "schema_version": command_evidence["command_evidence_schema_version"],
                "digest": worker_command_evidence_digest(command_evidence),
            }
        )
        invocation_snapshot = _revalidate_invocation_snapshot(
            state.invocation_snapshot,
            request_bundle=request_readback.retained_request_bundle,
            response_bundle=response_bundle,
            response=response,
        )
        if (
            type(state.stdout_byte_length) is not int
            or state.stdout_byte_length < 0
            or not _is_sha256_digest(state.stdout_sha256)
            or type(state.stderr_byte_length) is not int
            or state.stderr_byte_length < 0
            or not _is_sha256_digest(state.stderr_sha256)
            or type(state.runtime_milliseconds) is not int
            or state.runtime_milliseconds < 0
            or type(state.containment_provider) is not str
            or not state.containment_provider
            or not _is_sha256_digest(state.containment_launcher_sha256)
            or type(state.attempt_observability_verified) is not bool
        ):
            raise TypeError
        expected_identity_projection = {
            "execution_evidence_schema_version": (
                "ebm-audit-authenticated-worker-execution-evidence/2.0"
            ),
            "protocol_version": response["protocol_version"],
            "response_schema_version": response["response_schema_version"],
            "payload_schema_version": response["payload_schema_version"],
            "command": response["command"],
            "status": response["status"],
            "authenticated_request_evidence_digest": request_readback.evidence_digest,
            "authenticated_description_response_metadata_digest": (
                None if description is None else description.response_metadata_digest
            ),
            "planning_summary_id": request_readback.planning_summary_id,
            "selected_algorithm_binding_digest": (
                request_readback.selected_algorithm_binding_digest
            ),
            "response_metadata_digest": response["response_metadata_digest"],
            "request_bundle_digest": (request_readback.retained_request_bundle.bundle_digest),
            "response_bundle_digest": response_bundle.bundle_digest,
            "invocation_bundle_digest": _retained_snapshot_digest(invocation_snapshot),
            "command_evidence_reference": command_evidence_reference,
            "stdout_byte_length": state.stdout_byte_length,
            "stdout_sha256": state.stdout_sha256,
            "stderr_byte_length": state.stderr_byte_length,
            "stderr_sha256": state.stderr_sha256,
            "runtime_milliseconds": state.runtime_milliseconds,
            "containment_provider": state.containment_provider,
            "containment_launcher_sha256": state.containment_launcher_sha256,
            "attempt_observability_verified": (state.attempt_observability_verified),
        }
        if (
            dict(state.identity_projection) != expected_identity_projection
            or state.evidence_digest
            != authenticated_execution_evidence_digest(expected_identity_projection)
        ):
            raise TypeError
        return _AuthenticatedExecutionReadback(
            execution=execution,
            request_readback=request_readback,
            authenticated_request=request_evidence,
            request_planning_summary_id=request_readback.planning_summary_id,
            request_authenticated_description=(request_readback.authenticated_description),
            request_selected_algorithm_binding=(
                None
                if request_readback.selected_algorithm_binding is None
                else MappingProxyType(deepcopy(dict(request_readback.selected_algorithm_binding)))
            ),
            request_execution_input_projection_digest=(
                request_readback.execution_input_projection_digest
            ),
            request=deepcopy(dict(request)),
            response=deepcopy(response),
            command_evidence=(None if command_evidence is None else deepcopy(command_evidence)),
            execution_identity_projection=MappingProxyType(deepcopy(expected_identity_projection)),
            execution_evidence_digest=state.evidence_digest,
            retained_response_bundle=response_bundle,
            request_arrays=readonly_request_arrays,
            response_arrays=readonly_response_arrays,
        )
    except Exception:
        raise TypeError("Authenticated execution evidence failed exact bundle readback.") from None


class _PreparedInvocationContext(NamedTuple):
    authorization: object
    prepared_state: Any
    authenticated_description: AuthenticatedWorkerDescription
    authenticated_description_state: object
    description: _AuthenticatedDescriptionReadback
    selected_algorithm_binding: Mapping[str, Any]
    planning_summary_id: str
    required_execution_input_projection_digest: str | None


def _prepared_candidate_provenance_binding(state: object) -> dict[str, Any]:
    """Project one candidate binding from sealed core-owned preparation state."""

    from ebm_audit.synthetic.provenance import (
        project_candidate_derivation_selector,
        project_candidate_operation_intent_sha256,
    )
    from ebm_audit.universe.preparation import _PreparedExecutionAuthorizationState

    if type(state) is not _PreparedExecutionAuthorizationState:
        raise TypeError("A genuine prepared execution authorization state is required.")
    spec = strict_json_loads(state.analysis_spec_bytes)
    record = strict_json_loads(state.record_bytes)
    if type(spec) is not dict or type(record) is not dict:
        raise TypeError("Prepared candidate provenance storage is invalid.")
    operation = spec.get("operation_intent")
    if not isinstance(operation, Mapping):
        raise TypeError("Prepared candidate provenance has no exact operation owner.")
    return {
        "binding_schema_version": "ebm-audit-candidate-provenance-binding/1.0",
        "candidate_id": record["candidate_id"],
        "analysis_specification_id": record["analysis_spec_id"],
        "operation_intent_digest": project_candidate_operation_intent_sha256(operation),
        "selector": project_candidate_derivation_selector(operation),
        "operation_seed": record["operation_seed"],
    }


class _PreparedCandidateExecutionContextState(NamedTuple):
    invoker: WorkerInvoker
    invocation_context: _PreparedInvocationContext
    profile_validation_schedule_basis: object | None = None
    profile_validation_schedule_basis_token: object | None = None


_PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATES: OneShotWeakRegistry[
    object, _PreparedCandidateExecutionContextState
]
_PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATE_ISSUER: OneShotRegistryIssuer[
    object, _PreparedCandidateExecutionContextState
]
(
    _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATES,
    _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATE_ISSUER,
) = create_one_shot_registry()


@final
class _PreparedCandidateExecutionContext:
    """Opaque one-snapshot owner for one validate-to-terminal candidate decision."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _PreparedCandidateExecutionContext:
        raise TypeError("Prepared candidate execution contexts are issued by core orchestration.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Prepared candidate execution contexts cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Prepared candidate execution contexts are immutable.")

    def __copy__(self) -> _PreparedCandidateExecutionContext:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> _PreparedCandidateExecutionContext:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __getstate__(self) -> object:
        _reject_opaque_evidence_copy()


def _profile_fit_array_catalog(
    payload: object,
    arrays: object,
) -> dict[str, dict[str, Any]]:
    if type(payload) is not dict or not isinstance(arrays, Mapping):
        raise TypeError("Profile fit dispatch snapshot is invalid.")
    dataset = payload.get("dataset")
    expected_catalog = None if not isinstance(dataset, Mapping) else dataset.get("array_catalog")
    if (
        type(expected_catalog) is not dict
        or set(expected_catalog) != set(arrays)
        or any(type(name) is not str for name in arrays)
    ):
        raise TypeError("Profile fit dispatch arrays changed their closed catalogue.")
    actual_catalog: dict[str, dict[str, Any]] = {}
    for name, array in arrays.items():
        expected = expected_catalog.get(name)
        if type(expected) is not dict or type(expected.get("semantic_version")) is not str:
            raise TypeError("Profile fit dispatch array semantics changed.")
        actual_catalog[name] = array_catalog_entry(
            name,
            array,
            semantic_version=cast(str, expected["semantic_version"]),
        )
    if actual_catalog != expected_catalog:
        raise TypeError("Profile fit dispatch arrays changed after validation.")
    return actual_catalog


def _read_prepared_candidate_execution_context(
    value: object,
) -> _PreparedCandidateExecutionContextState:
    state: _PreparedCandidateExecutionContextState | None = None
    if type(value) is _PreparedCandidateExecutionContext:
        try:
            state = _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _PreparedCandidateExecutionContextState:
        raise TypeError("A genuine prepared candidate execution context is required.")
    if (
        type(state.invoker) is not WorkerInvoker
        or type(state.invocation_context) is not _PreparedInvocationContext
        or (state.profile_validation_schedule_basis is None)
        != (state.profile_validation_schedule_basis_token is None)
    ):
        raise TypeError("Prepared candidate execution context state is invalid.")
    return state


def _require_prepared_candidate_execution_context_state_identity(
    value: object,
    expected_state: object,
) -> _PreparedCandidateExecutionContextState:
    """Require only the exact immutable registry binding, without replaying fields."""

    state = (
        _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATES.get(value)
        if type(value) is _PreparedCandidateExecutionContext
        else None
    )
    if (
        type(expected_state) is not _PreparedCandidateExecutionContextState
        or state is not expected_state
    ):
        raise TypeError("A genuine prepared candidate execution context is required.")
    _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATES.require(value, expected_state)
    return expected_state


@dataclass(frozen=True, repr=False)
class _FitExecutionAuthorizationState:
    invoker: WorkerInvoker
    candidate_execution_context: _PreparedCandidateExecutionContext
    candidate_execution_context_state: _PreparedCandidateExecutionContextState
    validation_evidence: AuthenticatedWorkerExecutionEvidence
    execution_input_projection_digest: str


_FIT_EXECUTION_AUTHORIZATION_STATES: OneShotWeakRegistry[object, _FitExecutionAuthorizationState]
_FIT_EXECUTION_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _FitExecutionAuthorizationState
]
(
    _FIT_EXECUTION_AUTHORIZATION_STATES,
    _FIT_EXECUTION_AUTHORIZATION_STATE_ISSUER,
) = create_one_shot_registry()


@final
class _FitExecutionAuthorization:
    """Opaque authority issued only by exact fit-permitted product validation."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> _FitExecutionAuthorization:
        raise TypeError("Fit execution authority comes from prepared validation.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Fit execution authority cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Fit execution authority is immutable.")

    def __copy__(self) -> _FitExecutionAuthorization:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> _FitExecutionAuthorization:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __getstate__(self) -> object:
        _reject_opaque_evidence_copy()

    def __repr__(self) -> str:
        _read_fit_execution_authorization(self)
        return "_FitExecutionAuthorization(<sealed-fit-permitted-validation>)"


def _read_fit_execution_authorization(value: object) -> _FitExecutionAuthorizationState:
    state: _FitExecutionAuthorizationState | None = None
    if type(value) is _FitExecutionAuthorization:
        try:
            state = _FIT_EXECUTION_AUTHORIZATION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _FitExecutionAuthorizationState:
        raise TypeError("A genuine fit execution authorization is required.")
    return state


class _ProfileValidationInvocationUse:
    """One atomic consumption cell shared only by its exact authorization."""

    __slots__ = ("consumed", "lock")

    def __init__(self) -> None:
        self.consumed = False
        self.lock = threading.Lock()


@dataclass(frozen=True, repr=False)
class _ProfileValidationInvocationAuthorizationState:
    group: object
    ordinal: int
    invoker: WorkerInvoker
    candidate_authorization: object
    candidate_state: object
    schedule_basis: object
    schedule_basis_token: object
    one_use: _ProfileValidationInvocationUse


_PROFILE_VALIDATION_INVOCATION_AUTHORIZATION_STATES: OneShotWeakRegistry[
    object, _ProfileValidationInvocationAuthorizationState
]
_PROFILE_VALIDATION_INVOCATION_AUTHORIZATION_STATE_ISSUER: OneShotRegistryIssuer[
    object, _ProfileValidationInvocationAuthorizationState
]
(
    _PROFILE_VALIDATION_INVOCATION_AUTHORIZATION_STATES,
    _PROFILE_VALIDATION_INVOCATION_AUTHORIZATION_STATE_ISSUER,
) = create_one_shot_registry()


@final
class _ProfileValidationInvocationAuthorization:
    """Opaque one-use authority for one exact profile candidate validation."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> _ProfileValidationInvocationAuthorization:
        raise TypeError("Profile validation invocation authority is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Profile validation invocation authority cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Profile validation invocation authority is immutable.")

    def __copy__(self) -> _ProfileValidationInvocationAuthorization:
        _reject_opaque_evidence_copy()

    def __deepcopy__(self, _memo: object) -> _ProfileValidationInvocationAuthorization:
        _reject_opaque_evidence_copy()

    def __reduce__(self) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        _reject_opaque_evidence_copy()

    def __getstate__(self) -> object:
        _reject_opaque_evidence_copy()


def _read_profile_validation_invocation_authorization(
    value: object,
) -> _ProfileValidationInvocationAuthorizationState:
    state: _ProfileValidationInvocationAuthorizationState | None = None
    if type(value) is _ProfileValidationInvocationAuthorization:
        try:
            state = _PROFILE_VALIDATION_INVOCATION_AUTHORIZATION_STATES.get(value)
        except BaseException:
            state = None
    if type(state) is not _ProfileValidationInvocationAuthorizationState:
        raise TypeError("A genuine profile validation invocation authorization is required.")
    if (
        type(state.invoker) is not WorkerInvoker
        or type(state.ordinal) is not int
        or state.ordinal not in {0, 1, 2}
        or state.candidate_authorization is None
        or state.candidate_state is None
        or state.schedule_basis is None
        or state.schedule_basis_token is None
        or type(state.one_use) is not _ProfileValidationInvocationUse
    ):
        raise TypeError("Profile validation invocation authorization state is invalid.")
    from ebm_audit.runner.profile_validation import (
        _bound_profile_validation_schedule_basis,
    )

    basis_state = _bound_profile_validation_schedule_basis(state.schedule_basis)
    if (
        basis_state.group is not state.group
        or basis_state.invoker is not state.invoker
        or state.schedule_basis_token is not basis_state.token
        or state.candidate_authorization
        is not basis_state.candidates[state.ordinal].candidate_authorization
        or state.candidate_state is not basis_state.candidates[state.ordinal].candidate_state
    ):
        raise TypeError("Profile validation invocation schedule basis changed.")
    return state


def _issue_profile_validation_invocation_authorizations(
    group: object,
    invoker: object,
    *,
    schedule_basis: object,
    schedule_basis_token: object,
    expected_candidates: tuple[tuple[object, object], ...],
) -> tuple[
    _ProfileValidationInvocationAuthorization,
    _ProfileValidationInvocationAuthorization,
    _ProfileValidationInvocationAuthorization,
]:
    """Atomically preissue one validation authority for each profile candidate."""

    from ebm_audit.runner.profile_validation import (
        _bound_profile_validation_schedule_basis,
        _require_profile_validation_schedule_basis,
    )
    from ebm_audit.universe.preparation import (
        ProfilePreparedCandidateGroup,
    )

    if type(group) is not ProfilePreparedCandidateGroup:
        raise TypeError("A genuine profile prepared-candidate group is required.")
    if type(invoker) is not WorkerInvoker:
        raise TypeError("Profile validation requires one exact configured invoker.")
    if (
        schedule_basis is None
        or schedule_basis_token is None
        or type(expected_candidates) is not tuple
        or len(expected_candidates) != 3
    ):
        raise TypeError("Profile validation requires one exact schedule basis.")
    basis = _require_profile_validation_schedule_basis(
        schedule_basis,
        group=group,
        invoker=invoker,
    )
    basis_state = _bound_profile_validation_schedule_basis(basis)
    if schedule_basis_token is not basis_state.token:
        raise TypeError("Profile validation schedule basis token changed.")
    if any(
        expected[0] is not captured.candidate_authorization
        or expected[1] is not captured.candidate_state
        for expected, captured in zip(
            expected_candidates,
            basis_state.candidates,
            strict=True,
        )
    ):
        raise TypeError("Profile validation candidates changed after schedule capture.")

    authorizations = tuple(
        object.__new__(_ProfileValidationInvocationAuthorization) for _ordinal in range(3)
    )
    states = tuple(
        _ProfileValidationInvocationAuthorizationState(
            group=group,
            ordinal=ordinal,
            invoker=invoker,
            candidate_authorization=expected_candidates[ordinal][0],
            candidate_state=expected_candidates[ordinal][1],
            schedule_basis=schedule_basis,
            schedule_basis_token=schedule_basis_token,
            one_use=_ProfileValidationInvocationUse(),
        )
        for ordinal in range(3)
    )
    for authorization, state in zip(authorizations, states, strict=True):
        _PROFILE_VALIDATION_INVOCATION_AUTHORIZATION_STATE_ISSUER.bind_once(
            authorization,
            state,
        )
        if _read_profile_validation_invocation_authorization(authorization) is not state:
            raise TypeError("Profile validation invocation authority issuance failed.")
    return cast(
        tuple[
            _ProfileValidationInvocationAuthorization,
            _ProfileValidationInvocationAuthorization,
            _ProfileValidationInvocationAuthorization,
        ],
        authorizations,
    )


class WorkerInvoker:
    def __init__(
        self,
        worker: WorkerCommand,
        *,
        timeout_seconds: float = 30.0,
        expected_identity: Mapping[str, Any] | None = None,
    ) -> None:
        normalized_timeout = normalize_worker_timeout_seconds(timeout_seconds)
        self._worker = _validated_worker_command_snapshot(worker)
        self._timeout_seconds = normalized_timeout
        self._timeout_milliseconds = round(normalized_timeout * 1000)
        self._expected_identity = (
            None if expected_identity is None else validate_expected_identity_pin(expected_identity)
        )

    def describe_authenticated(self) -> AuthenticatedWorkerDescription:
        """Return opaque evidence only after the full authenticated Describe gate."""

        if self._expected_identity is None:
            raise WorkerProtocolError(
                "PROTOCOL.EXPECTED_IDENTITY_REQUIRED",
                "An authenticated description requires one configured identity pin.",
            )
        execution = self.invoke(
            command="describe",
            payload_schema_version=None,
            payload={"expected_identity": dict(self._expected_identity)},
        )
        if execution.response["status"] != "SUCCESS":
            raise WorkerProtocolError(
                "BACKEND.DESCRIBE_FAILED",
                "The authenticated worker description did not succeed.",
            )
        return AuthenticatedWorkerDescription._issue(
            _AUTHENTICATED_DESCRIPTION_ISSUER,
            response=execution.response,
            expected_identity=self._expected_identity,
        )

    def _open_contract_harness_description(
        self,
        expected_identity: Mapping[str, Any] | None,
    ) -> tuple[WorkerExecution, object | None]:
        """Run one normal Describe and pin it for one contract receipt call."""

        supplied = None if expected_identity is None else dict(expected_identity)
        execution = self._invoke_contract_harness(
            command="describe",
            payload_schema_version=None,
            payload={"expected_identity": supplied},
        )
        if execution.response["status"] != "SUCCESS" or self._expected_identity is None:
            return execution, None
        authenticated_description = AuthenticatedWorkerDescription._issue(
            _AUTHENTICATED_DESCRIPTION_ISSUER,
            response=execution.response,
            expected_identity=self._expected_identity,
        )
        capability = _ContractHarnessDescriptionCapability._issue(
            _CONTRACT_HARNESS_DESCRIPTION_CAPABILITY_ISSUER,
            invoker=self,
            authenticated_description=authenticated_description,
        )
        return execution, capability

    def _close_contract_harness_description(self, capability: object) -> None:
        """End one contract receipt lifetime without retaining a reusable cache."""

        state = _read_contract_harness_description_capability(capability, self)
        state.active = False

    def _prepared_invocation_context(
        self,
        authorization: object,
        *,
        required_execution_input_projection_digest: str | None = None,
        captured_state: object | None = None,
    ) -> _PreparedInvocationContext:
        """Resolve one exact preparation capability without accepting caller mappings."""

        from ebm_audit.universe.preparation import (
            _PreparedExecutionAuthorizationState,
            _resolve_ordinary_prepared_execution_authorization,
        )

        state = (
            _resolve_ordinary_prepared_execution_authorization(authorization)
            if captured_state is None
            else captured_state
        )
        if type(state) is not _PreparedExecutionAuthorizationState:
            raise TypeError("A genuine prepared execution authorization is required.")
        if state.execution_origin.route == "PROFILE":
            raise TypeError("Profile prepared candidates cannot enter ordinary worker invocation.")
        return self._prepared_invocation_context_from_state(
            authorization,
            state,
            required_execution_input_projection_digest=(required_execution_input_projection_digest),
        )

    def _prepared_invocation_context_from_state(
        self,
        authorization: object,
        state: object,
        *,
        required_execution_input_projection_digest: str | None = None,
    ) -> _PreparedInvocationContext:
        """Build context only from an already revalidated exact prepared state."""

        from ebm_audit.universe.identities import validated_planning_summary_id
        from ebm_audit.universe.preparation import _PreparedExecutionAuthorizationState

        if type(state) is not _PreparedExecutionAuthorizationState:
            raise TypeError("A genuine prepared execution authorization is required.")
        description = state.authenticated_description
        description_readback = state.authenticated_description_readback
        selected_binding = strict_json_loads(state.selected_algorithm_binding_bytes)
        planning_summary = strict_json_loads(state.planning_summary_binding_bytes)
        if (
            self._expected_identity is None
            or type(selected_binding) is not dict
            or type(planning_summary) is not dict
            or type(description_readback) is not _AuthenticatedDescriptionReadback
            or description_readback.description is not description
            or _AUTHENTICATED_DESCRIPTION_STATES.get(description)
            is not state.authenticated_description_state
            or description_readback.expected_identity != self._expected_identity
            or description_readback.selected_algorithm_binding != selected_binding
            or state.worker_identity_digest
            != self._expected_identity["selected_backend_identity_digest"]
        ):
            raise TypeError(
                "The configured invoker is detached from the prepared worker authority."
            )
        planning_summary_id = validated_planning_summary_id(planning_summary)
        if required_execution_input_projection_digest is not None and not _is_sha256_digest(
            required_execution_input_projection_digest
        ):
            raise TypeError("Prepared fit authority has an invalid execution-input identity.")
        return _PreparedInvocationContext(
            authorization=authorization,
            prepared_state=state,
            authenticated_description=description,
            authenticated_description_state=state.authenticated_description_state,
            description=description_readback,
            selected_algorithm_binding=deepcopy(selected_binding),
            planning_summary_id=planning_summary_id,
            required_execution_input_projection_digest=(required_execution_input_projection_digest),
        )

    def _begin_prepared_candidate_execution(
        self,
        authorization: object,
    ) -> _PreparedCandidateExecutionContext:
        """Capture the sole prepared state used through one candidate terminal decision."""

        invocation_context = self._prepared_invocation_context(authorization)
        context = object.__new__(_PreparedCandidateExecutionContext)
        _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATE_ISSUER.bind_once(
            context,
            _PreparedCandidateExecutionContextState(
                invoker=self, invocation_context=invocation_context
            ),
        )
        _read_prepared_candidate_execution_context(context)
        return context

    def _begin_prepared_candidate_execution_from_state(
        self,
        authorization: object,
        prepared_state: object,
    ) -> _PreparedCandidateExecutionContext:
        """Issue one candidate context from an already retained exact state."""

        from ebm_audit.universe.preparation import (
            _resolve_ordinary_prepared_execution_authorization,
        )

        if _resolve_ordinary_prepared_execution_authorization(authorization) is not prepared_state:
            raise TypeError("Prepared execution authorization changed before execution.")
        invocation_context = self._prepared_invocation_context(
            authorization,
            captured_state=prepared_state,
        )
        context = object.__new__(_PreparedCandidateExecutionContext)
        _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATE_ISSUER.bind_once(
            context,
            _PreparedCandidateExecutionContextState(
                invoker=self, invocation_context=invocation_context
            ),
        )
        _read_prepared_candidate_execution_context(context)
        return context

    def _candidate_execution_context(
        self,
        value: object,
    ) -> tuple[
        _PreparedCandidateExecutionContext,
        _PreparedCandidateExecutionContextState,
    ]:
        if type(value) is _PreparedCandidateExecutionContext:
            context = value
        else:
            context = self._begin_prepared_candidate_execution(value)
        state = _read_prepared_candidate_execution_context(context)
        if state.invoker is not self:
            raise TypeError(
                "Prepared candidate execution context belongs to another configured invoker."
            )
        return context, state

    def _assert_prepared_candidate_execution_context_current(
        self,
        value: object,
    ) -> None:
        """Fail closed if the live authorization registry changed before terminal commit."""

        from ebm_audit.universe.preparation import (
            _resolve_ordinary_prepared_execution_authorization,
        )

        if type(value) is not _PreparedCandidateExecutionContext:
            raise TypeError(
                "Terminal commit requires the exact prepared candidate execution context."
            )
        state = _read_prepared_candidate_execution_context(value)
        if state.invoker is not self:
            raise TypeError(
                "Prepared candidate execution context belongs to another configured invoker."
            )
        invocation_context = state.invocation_context
        current = _resolve_ordinary_prepared_execution_authorization(
            invocation_context.authorization
        )
        if current is not invocation_context.prepared_state:
            raise TypeError("Prepared execution authorization changed before terminal commit.")

    def _prepared_scientific_payload(
        self,
        context: _PreparedInvocationContext,
        *,
        command: str,
        chain_plan_position: int | None = None,
        attempt_ordinal: int | None = None,
    ) -> tuple[dict[str, Any], Mapping[str, Any]]:
        """Rebuild one scientific request solely from sealed preparation state."""

        from ebm_audit.universe.identities import attempt_id

        state = context.prepared_state
        spec = strict_json_loads(state.analysis_spec_bytes)
        dataset = strict_json_loads(state.dataset_projection_bytes)
        universe = strict_json_loads(state.universe_bytes)
        if (
            type(spec) is not dict
            or type(dataset) is not dict
            or type(universe) is not dict
        ):
            raise TypeError("Prepared scientific request storage is invalid.")
        backend = spec.get("backend")
        if not isinstance(backend, Mapping):
            raise TypeError("Prepared scientific request has no exact backend owner.")
        requested = backend.get("requested_outputs")
        settings = backend.get("settings")
        array_catalog = dataset.get("array_catalog")
        if (
            not isinstance(requested, list)
            or not isinstance(settings, Mapping)
            or not isinstance(array_catalog, Mapping)
        ):
            raise TypeError("Prepared scientific request has no exact settings owner.")
        arrays = {name: state.arrays[name] for name in array_catalog}
        candidate_provenance_binding = _prepared_candidate_provenance_binding(state)
        payload: dict[str, Any] = {
            "algorithm_id": backend["algorithm_id"],
            "settings": deepcopy(dict(settings)),
            "settings_digest": backend["settings_digest"],
            "config_digest": state.config_digest,
            "requested_outputs": list(requested),
            "requested_outputs_digest": requested_outputs_digest(command, requested),
            "dataset": deepcopy(dataset),
            "candidate_provenance_binding": candidate_provenance_binding,
        }
        if command == "validate":
            if chain_plan_position is not None or attempt_ordinal is not None:
                raise TypeError("Prepared validation cannot own a chain attempt.")
            return payload, arrays
        if (
            command != "fit"
            or type(chain_plan_position) is not int
            or type(attempt_ordinal) is not int
            or attempt_ordinal not in {0, 1}
        ):
            raise TypeError("Prepared fit requires one exact chain attempt.")
        chain_plan = universe.get("chain_plan")
        if (
            not isinstance(chain_plan, list)
            or chain_plan_position < 0
            or chain_plan_position >= len(chain_plan)
        ):
            raise TypeError("Prepared fit chain position is outside the sealed plan.")
        chain = chain_plan[chain_plan_position]
        if not isinstance(chain, Mapping):
            raise TypeError("Prepared fit chain owner is invalid.")
        chain_execution = str(chain["chain_execution_id"])
        payload.update(
            {
                "universe_id": universe["universe_id"],
                "chain_execution_id": chain_execution,
                "attempt_id": attempt_id(chain_execution, attempt_ordinal),
                "attempt_ordinal": attempt_ordinal,
                "seed": chain["seed"],
                "chain_id": chain["chain_id"],
            }
        )
        return payload, arrays

    def _invoke_prepared_validate(self, authorization: object) -> WorkerExecution:
        """Validate one exact prepared candidate; raw payloads are not accepted."""

        _candidate_context, candidate_state = self._candidate_execution_context(authorization)
        context = candidate_state.invocation_context
        if context.prepared_state.execution_origin.route == "PROFILE":
            raise TypeError("Profile prepared candidates cannot enter ordinary worker invocation.")
        payload, arrays = self._prepared_scientific_payload(
            context,
            command="validate",
        )
        return self._invoke_guarded(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=payload,
            arrays=arrays,
            stage_artifact_path=None,
            stage_artifact_bytes=None,
            prepared_context=context,
            prepared_candidate_execution_context=_candidate_context,
        )

    def _invoke_profile_prepared_validate(self, authority: object) -> WorkerExecution:
        """Consume one exact profile-owned authorization to validate its candidate."""

        from ebm_audit.runner.profile_validation import (
            _bound_profile_validation_schedule_basis,
        )

        authority_state = _read_profile_validation_invocation_authorization(authority)
        if authority_state.invoker is not self:
            raise TypeError("Profile validation invocation authority belongs to another invoker.")
        basis_state = _bound_profile_validation_schedule_basis(authority_state.schedule_basis)
        candidate_basis = basis_state.candidates[authority_state.ordinal]
        candidate = candidate_basis.candidate_authorization
        prepared_state = candidate_basis.candidate_state
        if (
            candidate is not authority_state.candidate_authorization
            or prepared_state is not authority_state.candidate_state
        ):
            raise TypeError("Profile validation candidate changed after schedule capture.")
        context = candidate_basis.invocation_context
        candidate_context = object.__new__(_PreparedCandidateExecutionContext)
        candidate_context_state = _PreparedCandidateExecutionContextState(
            invoker=self,
            invocation_context=context,
            profile_validation_schedule_basis=authority_state.schedule_basis,
            profile_validation_schedule_basis_token=(authority_state.schedule_basis_token),
        )
        _PREPARED_CANDIDATE_EXECUTION_CONTEXT_STATE_ISSUER.bind_once(
            candidate_context,
            candidate_context_state,
        )
        if _read_prepared_candidate_execution_context(candidate_context) is not (
            candidate_context_state
        ):
            raise TypeError("Profile candidate execution context issuance failed.")
        payload = strict_json_loads(candidate_basis.validation_payload_bytes)
        if type(payload) is not dict:
            raise TypeError("Profile validation schedule payload changed.")
        arrays = candidate_basis.arrays

        with authority_state.one_use.lock:
            if authority_state.one_use.consumed:
                raise TypeError("Profile validation invocation authority was already consumed.")
            authority_state.one_use.consumed = True
        return self._invoke_guarded(
            command="validate",
            payload_schema_version="ebm-audit-worker-validation/2.0",
            payload=payload,
            arrays=arrays,
            stage_artifact_path=None,
            stage_artifact_bytes=None,
            prepared_context=context,
            prepared_candidate_execution_context=candidate_context,
        )

    def _authorize_prepared_fit(
        self,
        authorization: object,
        validation_evidence: object,
    ) -> _FitExecutionAuthorization:
        """Issue fit authority only from exact SUCCESS and ``fit_permitted`` evidence."""

        if type(validation_evidence) is not AuthenticatedWorkerExecutionEvidence:
            raise TypeError("Fit authority requires exact authenticated validation evidence.")
        execution = validation_evidence
        readback = _readback_authenticated_execution(execution)
        if type(authorization) is _PreparedCandidateExecutionContext:
            candidate_context, candidate_state = self._candidate_execution_context(authorization)
        else:
            if (
                type(readback.request_readback.prepared_candidate_execution_context)
                is not _PreparedCandidateExecutionContext
            ):
                raise TypeError(
                    "Fit authority requires the exact fit-permitted prepared validation."
                )
            candidate_context = readback.request_readback.prepared_candidate_execution_context
            candidate_state = _read_prepared_candidate_execution_context(candidate_context)
            if (
                candidate_state.invoker is not self
                or candidate_state.invocation_context.authorization is not authorization
            ):
                raise TypeError(
                    "Fit authority requires the exact fit-permitted prepared validation."
                )
        context = candidate_state.invocation_context
        if context.prepared_state.execution_origin.route == "PROFILE":
            raise TypeError("Profile prepared candidates cannot enter ordinary worker invocation.")
        request = readback.request
        response = readback.response
        if (
            request["command"] != "validate"
            or readback.request_planning_summary_id != context.planning_summary_id
            or readback.request_authenticated_description is not context.authenticated_description
            or readback.request_selected_algorithm_binding != context.selected_algorithm_binding
            or readback.request_readback.prepared_candidate_execution_context
            is not candidate_context
            or readback.request_readback.prepared_candidate_execution_context_state
            is not candidate_state
            or response["command"] != "validate"
            or response["status"] != "SUCCESS"
            or response["payload"].get("fit_permitted") is not True
            or readback.request_execution_input_projection_digest is None
        ):
            raise TypeError("Fit authority requires the exact fit-permitted prepared validation.")
        fit_authorization = object.__new__(_FitExecutionAuthorization)
        _FIT_EXECUTION_AUTHORIZATION_STATE_ISSUER.bind_once(
            fit_authorization,
            _FitExecutionAuthorizationState(
                invoker=self,
                candidate_execution_context=candidate_context,
                candidate_execution_context_state=candidate_state,
                validation_evidence=execution,
                execution_input_projection_digest=(
                    readback.request_execution_input_projection_digest
                ),
            ),
        )
        _read_fit_execution_authorization(fit_authorization)
        return fit_authorization

    def _invoke_prepared_fit(
        self,
        fit_authorization: object,
        *,
        chain_plan_position: int,
        attempt_ordinal: int,
    ) -> WorkerExecution:
        """Fit one exact planned chain/seed from successful-validation authority."""

        state = _read_fit_execution_authorization(fit_authorization)
        if state.invoker is not self:
            raise TypeError("Fit execution authority belongs to another configured invoker.")
        candidate_state = _read_prepared_candidate_execution_context(
            state.candidate_execution_context
        )
        if candidate_state.invoker is not self:
            raise TypeError("Fit execution authority belongs to another configured invoker.")
        if candidate_state is not state.candidate_execution_context_state:
            raise TypeError("Prepared candidate execution context changed before fit.")
        base_context = candidate_state.invocation_context
        if base_context.prepared_state.execution_origin.route == "PROFILE":
            raise TypeError("Profile prepared candidates cannot enter ordinary worker invocation.")
        context = _PreparedInvocationContext(
            authorization=base_context.authorization,
            prepared_state=base_context.prepared_state,
            authenticated_description=base_context.authenticated_description,
            authenticated_description_state=(base_context.authenticated_description_state),
            description=base_context.description,
            selected_algorithm_binding=base_context.selected_algorithm_binding,
            planning_summary_id=base_context.planning_summary_id,
            required_execution_input_projection_digest=(state.execution_input_projection_digest),
        )
        payload, arrays = self._prepared_scientific_payload(
            context,
            command="fit",
            chain_plan_position=chain_plan_position,
            attempt_ordinal=attempt_ordinal,
        )
        return self._invoke_guarded(
            command="fit",
            payload_schema_version="ebm-audit-worker-fit-payload/2.0",
            payload=payload,
            arrays=arrays,
            stage_artifact_path=None,
            stage_artifact_bytes=None,
            prepared_context=context,
            prepared_candidate_execution_context=(state.candidate_execution_context),
        )

    def _invoke_profile_prepared_fit(self, authority: object) -> WorkerExecution:
        """Consume and terminalize one exact profile-owned serial fit slot."""

        from ebm_audit.runner.profile_fit_slots import (
            _complete_profile_fit_slot_authorization,
            _complete_profile_fit_slot_without_observation,
            _consume_profile_fit_slot_authorization,
            _read_profile_fit_slot_authorization,
        )
        from ebm_audit.runner.profile_validation import (
            _bound_profile_fit_schedule_receipt,
            _profile_fit_request_owner_from_receipt,
        )

        state = _read_profile_fit_slot_authorization(authority)
        if state.invoker is not self:
            raise TypeError("Profile fit-slot authority belongs to another invoker.")
        receipt_state = _bound_profile_fit_schedule_receipt(state.receipt)
        receipt_row = receipt_state.rows[state.row_index]
        request_owner = _profile_fit_request_owner_from_receipt(
            state.receipt,
            state.row_index,
            invoker=self,
        )
        candidate = state.candidate_authorization
        prepared_state = state.candidate_state
        candidate_basis = receipt_state.basis.candidates[state.candidate_ordinal]
        if (
            receipt_state.invoker is not self
            or candidate is not candidate_basis.candidate_authorization
            or prepared_state is not candidate_basis.candidate_state
            or receipt_row.candidate_execution_context is not state.candidate_execution_context
            or receipt_row.candidate_execution_context_state
            is not state.candidate_execution_context_state
        ):
            raise TypeError("Profile fit-slot authority changed its candidate owner.")
        captured_execution_input_projection_digest = state.execution_input_projection_digest
        context = request_owner.invocation_context
        payload_readback = strict_json_loads(
            receipt_state.basis.fit_payload_bytes[state.runtime_position]
        )
        if (
            type(payload_readback) is not dict
            or payload_readback.get("universe_id") != state.universe_id
            or payload_readback.get("chain_execution_id") != state.chain_execution_id
            or payload_readback.get("attempt_id") != state.attempt_id
            or payload_readback.get("attempt_ordinal") != state.attempt_ordinal
            or payload_readback.get("seed") != state.seed
            or payload_readback.get("chain_id") != state.chain_id
        ):
            raise TypeError("Profile fit-slot payload changed its exact plan position.")

        _consume_profile_fit_slot_authorization(
            authority,
            invoker=self,
            candidate_execution_context=state.candidate_execution_context,
            execution_input_projection_digest=(captured_execution_input_projection_digest),
        )
        try:
            execution = self._invoke_guarded(
                command="fit",
                payload_schema_version="ebm-audit-worker-fit-payload/2.0",
                payload=payload_readback,
                arrays=candidate_basis.arrays,
                stage_artifact_path=None,
                stage_artifact_bytes=None,
                prepared_context=context,
                prepared_candidate_execution_context=(state.candidate_execution_context),
                profile_fit_receipt_row=receipt_row,
            )
        except AuditError as error:
            observation = error.invocation_observation
            if type(observation) is WorkerInvocationObservation:
                _complete_profile_fit_slot_authorization(authority, observation)
            else:
                _complete_profile_fit_slot_without_observation(authority)
            raise
        except Exception:
            _complete_profile_fit_slot_without_observation(authority)
            pending = UnexpectedCoreError(
                "UNEXPECTED.PROFILE_FIT_INVOCATION_FAILURE",
                "The core could not safely complete the profile fit invocation.",
            )
            pending.__traceback__ = None
            pending.__context__ = None
            pending.__cause__ = None
            raise pending from None
        authenticated = execution.authenticated_execution
        if type(authenticated) is not AuthenticatedWorkerExecutionEvidence:
            _complete_profile_fit_slot_without_observation(authority)
            pending = UnexpectedCoreError(
                "UNEXPECTED.PROFILE_FIT_EVIDENCE_FAILURE",
                "The core could not retain exact profile fit evidence.",
            )
            pending.__traceback__ = None
            pending.__context__ = None
            pending.__cause__ = None
            raise pending from None
        _complete_profile_fit_slot_authorization(authority, authenticated)
        return execution

    def invoke(
        self,
        *,
        command: str,
        payload_schema_version: str | None,
        payload: Mapping[str, Any],
        arrays: Mapping[str, Any] | None = None,
        stage_artifact_path: Path | None = None,
        stage_artifact_bytes: bytes | None = None,
    ) -> WorkerExecution:
        """Invoke only the public non-scientific worker surface.

        Production scientific execution is available only through the private
        sealed ``PreparedExecutionAuthorization`` path and its exact
        successful-validation-owned fit authorization.  A PlanningAuthority,
        digest, mapping, contract-harness receipt, or caller-created object is
        never sufficient authority here.
        """

        if command in {"validate", "fit"}:
            raise WorkerProtocolError(
                "CAPABILITY.PREPARED_EXECUTION_AUTHORITY_REQUIRED",
                "Scientific worker execution requires a sealed per-candidate authority.",
            )
        if command == "stage":
            raise WorkerProtocolError(
                "CAPABILITY.STAGE_COMMAND_UNAVAILABLE",
                "Separate stage execution is not an active worker command.",
            )
        return self._invoke_guarded(
            command=command,
            payload_schema_version=payload_schema_version,
            payload=payload,
            arrays=arrays,
            stage_artifact_path=stage_artifact_path,
            stage_artifact_bytes=stage_artifact_bytes,
            prepared_context=None,
            prepared_candidate_execution_context=None,
        )

    def _invoke_contract_harness(
        self,
        *,
        command: str,
        payload_schema_version: str | None,
        payload: Mapping[str, Any],
        arrays: Mapping[str, Any] | None = None,
        _authenticated_description_capability: object | None = None,
    ) -> WorkerExecution:
        """Characterize synthetic workers without issuing product authority.

        This package-private path exists only for ``adapters.contract`` and its
        synthetic protocol tests.  Its request evidence deliberately has no
        planning-summary owner and cannot authorize a product run or result.
        """

        if command == "stage":
            raise WorkerProtocolError(
                "CAPABILITY.STAGE_COMMAND_UNAVAILABLE",
                "Separate stage execution is not an active worker command.",
            )
        return self._invoke_guarded(
            command=command,
            payload_schema_version=payload_schema_version,
            payload=payload,
            arrays=arrays,
            stage_artifact_path=None,
            stage_artifact_bytes=None,
            prepared_context=None,
            prepared_candidate_execution_context=None,
            contract_description_capability=(
                _authenticated_description_capability
            ),
        )

    def _invoke_guarded(
        self,
        *,
        command: str,
        payload_schema_version: str | None,
        payload: Mapping[str, Any],
        arrays: Mapping[str, Any] | None,
        stage_artifact_path: Path | None,
        stage_artifact_bytes: bytes | None,
        prepared_context: _PreparedInvocationContext | None,
        prepared_candidate_execution_context: (_PreparedCandidateExecutionContext | None),
        profile_fit_receipt_row: object | None = None,
        contract_description_capability: object | None = None,
    ) -> WorkerExecution:
        attempt = _InvocationAttemptState()
        pending: WorkerProtocolError | PrivacyViolationError | UnexpectedCoreError | None = None
        try:
            return self._invoke(
                command=command,
                payload_schema_version=payload_schema_version,
                payload=payload,
                arrays=arrays,
                stage_artifact_path=stage_artifact_path,
                stage_artifact_bytes=stage_artifact_bytes,
                attempt=attempt,
                prepared_context=prepared_context,
                prepared_candidate_execution_context=(prepared_candidate_execution_context),
                profile_fit_receipt_row=profile_fit_receipt_row,
                contract_description_capability=contract_description_capability,
            )
        except (WorkerProtocolError, PrivacyViolationError, UnexpectedCoreError) as caught:
            observation = caught.invocation_observation
            if observation is None:
                observation = attempt.issue(caught)
            if isinstance(caught, PrivacyViolationError):
                pending = PrivacyViolationError(caught.code, caught.safe_message)
            elif isinstance(caught, UnexpectedCoreError):
                pending = UnexpectedCoreError(caught.code, caught.safe_message)
            else:
                pending = WorkerProtocolError(
                    caught.code,
                    caught.safe_message,
                    details=caught.details,
                )
            pending.invocation_observation = observation
        except Exception:
            pending = UnexpectedCoreError(
                "UNEXPECTED.CORE_INVOCATION_FAILURE",
                "The core could not safely complete the worker invocation.",
            )
            if attempt.frame_written:
                pending.invocation_observation = attempt.issue(pending)
        assert pending is not None
        pending.__traceback__ = None
        pending.__context__ = None
        pending.__cause__ = None
        del (
            payload,
            arrays,
            stage_artifact_path,
            stage_artifact_bytes,
        )
        raise pending

    def _invoke(
        self,
        *,
        command: str,
        payload_schema_version: str | None,
        payload: Mapping[str, Any],
        arrays: Mapping[str, Any] | None = None,
        stage_artifact_path: Path | None = None,
        stage_artifact_bytes: bytes | None = None,
        attempt: _InvocationAttemptState,
        prepared_context: _PreparedInvocationContext | None,
        prepared_candidate_execution_context: (_PreparedCandidateExecutionContext | None),
        profile_fit_receipt_row: object | None = None,
        contract_description_capability: object | None = None,
    ) -> WorkerExecution:
        expected_payload_version = {
            "describe": None,
            "validate": "ebm-audit-worker-validation/2.0",
            "fit": "ebm-audit-worker-fit-payload/2.0",
            "self-test": None,
        }.get(command)
        if command not in {"describe", "validate", "fit", "self-test"} or (
            payload_schema_version != expected_payload_version
        ):
            raise WorkerProtocolError(
                "PROTOCOL.V2_PAYLOAD_VERSION",
                "The invocation does not use the exact v2 command payload version.",
            )
        if (prepared_context is None) != (prepared_candidate_execution_context is None):
            raise WorkerProtocolError(
                "CAPABILITY.PREPARED_EXECUTION_AUTHORITY_REQUIRED",
                "Prepared execution requires one exact candidate context.",
            )
        if profile_fit_receipt_row is not None:
            from ebm_audit.runner.profile_validation import (
                _profile_fit_request_owner_from_row,
            )

            profile_fit_owner = _profile_fit_request_owner_from_row(profile_fit_receipt_row)
            if (
                command != "fit"
                or prepared_candidate_execution_context
                is not profile_fit_owner.candidate_execution_context
                or prepared_context is None
                or prepared_context != profile_fit_owner.invocation_context
            ):
                raise WorkerProtocolError(
                    "CAPABILITY.PREPARED_EXECUTION_AUTHORITY_REQUIRED",
                    "Prepared execution context ownership is invalid.",
                )
            _require_prepared_candidate_execution_context_state_identity(
                prepared_candidate_execution_context,
                profile_fit_owner.candidate_execution_context_state,
            )
            prepared_context = profile_fit_owner.invocation_context
        elif prepared_candidate_execution_context is not None:
            candidate_context_state = _read_prepared_candidate_execution_context(
                prepared_candidate_execution_context
            )
            if (
                candidate_context_state.invoker is not self
                or prepared_context is None
                or candidate_context_state.invocation_context.authorization
                is not prepared_context.authorization
                or candidate_context_state.invocation_context.prepared_state
                is not prepared_context.prepared_state
            ):
                raise WorkerProtocolError(
                    "CAPABILITY.PREPARED_EXECUTION_AUTHORITY_REQUIRED",
                    "Prepared execution context ownership is invalid.",
                )
        effective_payload = dict(payload)
        if command == "describe":
            supplied = effective_payload.get("expected_identity")
            if self._expected_identity is None:
                if supplied is not None:
                    raise WorkerProtocolError(
                        "PROTOCOL.EXPECTED_IDENTITY_REQUIRED",
                        "A configured worker identity must be bound to the invoker.",
                    )
            else:
                if supplied is not None and supplied != self._expected_identity:
                    raise WorkerProtocolError(
                        "PROTOCOL.EXPECTED_IDENTITY_MISMATCH",
                        "The worker identity does not match the configured expectation.",
                    )
                effective_payload["expected_identity"] = dict(self._expected_identity)
        payload = effective_payload
        assert_no_direct_identifier_fields(payload)
        _verify_raw_scientific_input(command, payload)
        if stage_artifact_path is not None or stage_artifact_bytes is not None:
            raise WorkerProtocolError(
                "PROTOCOL.STAGE_ARTIFACT_INPUT",
                "A fitted-artifact input is valid for the stage command only.",
            )
        validated_projection_digest: str | None = None
        if command == "fit" and prepared_context is None:
            validate_payload = {
                field: payload[field]
                for field in (
                    "algorithm_id",
                    "settings",
                    "settings_digest",
                    "config_digest",
                    "requested_outputs",
                    "dataset",
                )
            }
            validate_payload["requested_outputs_digest"] = requested_outputs_digest(
                "validate", validate_payload["requested_outputs"]
            )
            validation = self._invoke_contract_harness(
                command="validate",
                payload_schema_version="ebm-audit-worker-validation/2.0",
                payload=validate_payload,
                arrays=arrays,
                _authenticated_description_capability=(
                    contract_description_capability
                ),
            )
            if (
                validation.response["status"] != "SUCCESS"
                or validation.response["payload"]["fit_permitted"] is not True
            ):
                raise WorkerProtocolError(
                    "PROTOCOL.VALIDATE_BEFORE_FIT",
                    "The exact execution input was not validated as fit-permitted.",
                )
            validated_projection_digest = validation.response["execution_input_projection_digest"]
        described_owner: _DescribedAlgorithmOwner | None = None
        authenticated_description: AuthenticatedWorkerDescription | None = None
        description_readback: _AuthenticatedDescriptionReadback | None = None
        authenticated_description_state: object | None = None
        selected_algorithm_binding: dict[str, Any] | None = None
        if command in {"validate", "fit", "self-test"}:
            if self._expected_identity is None:
                raise WorkerProtocolError(
                    "PROTOCOL.EXPECTED_IDENTITY_REQUIRED",
                    "A complete reviewed worker identity is required for this command.",
                )
            if prepared_context is None:
                if contract_description_capability is None:
                    description = self.invoke(
                        command="describe",
                        payload_schema_version=None,
                        payload={"expected_identity": dict(self._expected_identity)},
                    )
                    authenticated_description = AuthenticatedWorkerDescription._issue(
                        _AUTHENTICATED_DESCRIPTION_ISSUER,
                        response=description.response,
                        expected_identity=self._expected_identity,
                    )
                    (
                        authenticated_description_state,
                        description_readback,
                    ) = _capture_authenticated_description(authenticated_description)
                else:
                    contract_state = _read_contract_harness_description_capability(
                        contract_description_capability,
                        self,
                    )
                    authenticated_description = contract_state.authenticated_description
                    authenticated_description_state = (
                        contract_state.authenticated_description_state
                    )
                    description_readback = contract_state.description
            else:
                if command not in {"validate", "fit"}:
                    raise WorkerProtocolError(
                        "CAPABILITY.PREPARED_EXECUTION_AUTHORITY_REQUIRED",
                        "Prepared scientific authority cannot invoke this worker command.",
                    )
                authenticated_description = prepared_context.authenticated_description
                authenticated_description_state = (
                    prepared_context.authenticated_description_state
                )
                description_readback = prepared_context.description
            if description_readback is None:
                raise WorkerProtocolError(
                    "PROTOCOL.DESCRIBE_COMMAND_OWNER",
                    "The requested worker command has no authenticated description.",
                )
            selected_algorithm_binding = deepcopy(
                dict(description_readback.selected_algorithm_binding)
            )
            if command in {"validate", "fit"}:
                described_owner = _described_owner_from_description_readback(
                    description_readback,
                    command=command,
                    payload=payload,
                )
            if (
                command in {"validate", "fit"}
                and payload.get("algorithm_id") != self._expected_identity["selected_algorithm_id"]
            ):
                raise WorkerProtocolError(
                    "PROTOCOL.EXPECTED_IDENTITY_MISMATCH",
                    "The worker identity does not match the configured expectation.",
                )
        with (
            tempfile.TemporaryDirectory(prefix="ebm-audit-worker-sdk-") as sdk_name,
            tempfile.TemporaryDirectory(prefix="ebm-audit-worker-") as temporary_name,
        ):
            invocation_root = Path(temporary_name)
            os.chmod(invocation_root, 0o700)
            request_dir = invocation_root / "request"
            response_dir = invocation_root / "response"
            work_dir = invocation_root / "work"
            for directory in (request_dir, response_dir, work_dir):
                directory.mkdir(mode=0o700)

            files: dict[str, dict[str, Any]] = {}
            request_arrays: Mapping[str, Any] = {}
            request_array_catalog: Mapping[str, Any] | None = None
            values_path: Path | None = None
            if arrays:
                values_path = request_dir / "values.npz"
                write_deterministic_npz(values_path, arrays)
                files["values.npz"] = {
                    "byte_length": values_path.stat().st_size,
                    "sha256": exact_file_sha256_path(values_path),
                }
                try:
                    dataset = payload["dataset"]
                    if not isinstance(dataset, Mapping):
                        raise TypeError
                    catalog = dataset["array_catalog"]
                    if not isinstance(catalog, Mapping):
                        raise TypeError
                    request_array_catalog = catalog
                except Exception:
                    raise WorkerProtocolError(
                        "PROTOCOL.REQUEST_ARRAY_CATALOG",
                        "The request arrays do not match their closed catalog.",
                    ) from None
            core_code_digest = _core_code_digest()
            if command in {"validate", "fit"}:
                if described_owner is None:
                    raise WorkerProtocolError(
                        "PROTOCOL.DESCRIBE_COMMAND_OWNER",
                        "The scientific request has no described algorithm owner.",
                    )
                selected_backend_identity = dict(described_owner.backend_identity)
                selected_backend_identity["algorithm_id"] = payload["algorithm_id"]
                projection, projection_digest = build_execution_input_projection(
                    payload,
                    arrays={} if arrays is None else arrays,
                    files=files,
                    core_code_digest=core_code_digest,
                    selected_backend_identity=selected_backend_identity,
                    capabilities=described_owner.algorithm["capabilities"],
                    stage_semantics_definition=described_owner.algorithm[
                        "stage_semantics_definition"
                    ],
                    adapter_semantics=described_owner.algorithm["adapter_semantics"],
                )
                if (
                    validated_projection_digest is not None
                    and projection_digest != validated_projection_digest
                ):
                    raise WorkerProtocolError(
                        "PROTOCOL.VALIDATE_FIT_PROJECTION_MISMATCH",
                        "Validate and fit do not bind the same execution input.",
                    )
                if (
                    prepared_context is not None
                    and prepared_context.required_execution_input_projection_digest is not None
                    and projection_digest
                    != prepared_context.required_execution_input_projection_digest
                ):
                    raise WorkerProtocolError(
                        "PROTOCOL.VALIDATE_FIT_PROJECTION_MISMATCH",
                        "Validate and fit do not bind the same execution input.",
                    )
                payload = build_wire_scientific_payload(
                    command,
                    payload,
                    execution_input_projection=projection,
                    execution_input_projection_digest_value=projection_digest,
                )
            _verify_request_owner_digests(command, payload)
            request = base_request(
                command=command,
                payload_schema_version=payload_schema_version,
                payload=payload,
                core_code_digest=core_code_digest,
                files=files,
            )
            request = bind_request_digests(request)
            request_frame = write_worker_request(request_dir, request)
            request = request_frame.request
            attempt.mark_frame_written()
            retained_request_bundle = _retain_bundle(request_dir, request_frame.snapshot)
            authenticated_request = AuthenticatedWorkerRequestEvidence._issue(
                _AUTHENTICATED_REQUEST_ISSUER,
                request=request,
                canonical_request_bytes=request_frame.metadata_bytes,
                retained_request_bundle=retained_request_bundle,
                authenticated_description=authenticated_description,
                selected_algorithm_binding=selected_algorithm_binding,
                planning_summary_id=(
                    None if prepared_context is None else prepared_context.planning_summary_id
                ),
                prepared_candidate_execution_context=(prepared_candidate_execution_context),
                authenticated_description_state=(
                    authenticated_description_state
                ),
                authenticated_description_readback=(
                    description_readback
                ),
                profile_fit_receipt_row=profile_fit_receipt_row,
            )
            attempt.activate(
                authenticated_request=authenticated_request,
                authenticated_description=authenticated_description,
                selected_algorithm_id=(
                    None
                    if description_readback is None
                    else str(description_readback.expected_identity["selected_algorithm_id"])
                ),
            )
            _enforce_invocation_tree_limits(invocation_root)
            if values_path is not None and request_array_catalog is not None:
                try:
                    request_arrays = load_catalogued_npz_arrays(
                        values_path,
                        catalog=request_array_catalog,
                        max_aggregate_uncompressed_bytes=(
                            _remaining_archive_expansion_budget(
                                invocation_root,
                                values_path,
                            )
                        ),
                    )
                except Exception:
                    raise WorkerProtocolError(
                        "PROTOCOL.REQUEST_ARRAY_CATALOG",
                        "The request arrays do not match their closed catalog.",
                    ) from None

            argv = self._worker.protocol_argv(
                command=command,
                request_dir=request_dir,
                response_dir=response_dir,
            )
            try:
                containment = build_containment_plan(
                    argv,
                    invocation_root=invocation_root,
                    request_dir=request_dir,
                    work_dir=work_dir,
                )
            except OSError:
                raise PrivacyViolationError(
                    "PRIVACY.CONTAINMENT_START_FAILED",
                    "The local worker containment boundary could not be prepared.",
                ) from None
            if containment is None:
                raise PrivacyViolationError(
                    "PRIVACY.CONTAINMENT_UNAVAILABLE",
                    "No reviewed local worker containment provider is available on this host.",
                )
            try:
                worker_sdk_root = _prepare_worker_sdk_view(Path(sdk_name))
            except (OSError, ValueError):
                raise WorkerProtocolError(
                    "PROTOCOL.CORE_CODE_INVENTORY",
                    "The auditor worker SDK view could not be prepared.",
                ) from None
            network_attempt_path = work_dir / ".network-attempt"
            outside_attempt_path = work_dir / ".outside-write-attempt"
            guard_active_path = work_dir / ".offline-guard-active"
            started = time.monotonic()
            try:
                process = subprocess.Popen(
                    containment.argv,
                    cwd=work_dir,
                    env=_offline_environment(
                        invocation_root=invocation_root,
                        request_dir=request_dir,
                        work_dir=work_dir,
                        network_attempt_path=network_attempt_path,
                        outside_attempt_path=outside_attempt_path,
                        guard_active_path=guard_active_path,
                        worker_sdk_root=worker_sdk_root,
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    shell=False,
                    close_fds=True,
                )
            except OSError:
                raise WorkerProtocolError(
                    "BACKEND.WORKER_START_FAILED",
                    "The local worker process could not be started.",
                ) from None
            process_boundary_clean = False
            started_collectors: list[_StreamDigestCollector] = []
            try:
                if process.stdout is None or process.stderr is None:
                    raise WorkerProtocolError(
                        "PROTOCOL.DIAGNOSTIC_STREAM_SETUP",
                        "The worker diagnostic stream boundary could not be established.",
                    )
                try:
                    diagnostic_overflow = threading.Event()

                    def stop_on_diagnostic_overflow() -> None:
                        diagnostic_overflow.set()

                    stdout_collector = _StreamDigestCollector(
                        process.stdout,
                        hard_limit_bytes=_DIAGNOSTIC_STREAM_HARD_LIMIT_BYTES,
                        on_overflow=stop_on_diagnostic_overflow,
                    )
                    stderr_collector = _StreamDigestCollector(
                        process.stderr,
                        hard_limit_bytes=_DIAGNOSTIC_STREAM_HARD_LIMIT_BYTES,
                        on_overflow=stop_on_diagnostic_overflow,
                    )
                    stdout_collector.start()
                    started_collectors.append(stdout_collector)
                    stderr_collector.start()
                    started_collectors.append(stderr_collector)
                except (OSError, RuntimeError):
                    raise WorkerProtocolError(
                        "PROTOCOL.DIAGNOSTIC_STREAM_SETUP",
                        "The worker diagnostic stream boundary could not be established.",
                    ) from None
                return_code, timed_out = _wait_for_worker_exit(
                    process,
                    timeout_seconds=self._timeout_seconds,
                    diagnostic_overflow=diagnostic_overflow,
                )
                residual_process_group = _terminate_residual_process_group(process)
                process_boundary_clean = True
            finally:
                if not process_boundary_clean:
                    _terminate_and_reap_process(process)
                    _terminate_residual_process_group(process)
                    for collector in started_collectors:
                        collector.finish()
            runtime = max(0.0, time.monotonic() - started)
            stdout_digest = stdout_collector.finish()
            stderr_digest = stderr_collector.finish()
            attempt.record(
                runtime_milliseconds=round(runtime * 1000),
                timeout_milliseconds=self._timeout_milliseconds,
                stdout_byte_length=stdout_digest.byte_length,
                stdout_sha256=stdout_digest.sha256,
                stderr_byte_length=stderr_digest.byte_length,
                stderr_sha256=stderr_digest.sha256,
            )

            if stdout_collector.overflowed or stderr_collector.overflowed:
                raise WorkerProtocolError(
                    "PROTOCOL.DIAGNOSTIC_STREAM_LIMIT_EXCEEDED",
                    "A worker diagnostic stream exceeded its local byte limit.",
                    details={
                        "stream_hard_limit_bytes": _DIAGNOSTIC_STREAM_HARD_LIMIT_BYTES,
                        "stdout_byte_length": stdout_digest.byte_length,
                        "stdout_sha256": stdout_digest.sha256,
                        "stderr_byte_length": stderr_digest.byte_length,
                        "stderr_sha256": stderr_digest.sha256,
                    },
                )
            _enforce_invocation_tree_limits(invocation_root)
            if _attempt_recorded(network_attempt_path):
                raise PrivacyViolationError(
                    "PRIVACY.NETWORK_ATTEMPT",
                    "The offline worker attempted a forbidden network operation.",
                )
            if _attempt_recorded(outside_attempt_path):
                raise PrivacyViolationError(
                    "PRIVACY.OUTSIDE_WRITE_ATTEMPT",
                    "The worker attempted a forbidden filesystem write.",
                )
            if residual_process_group:
                raise PrivacyViolationError(
                    "PRIVACY.RESIDUAL_SUBPROCESS",
                    "A worker subprocess remained after the command completed.",
                )
            try:
                verify_snapshot_unchanged(request_dir, request_frame.snapshot)
            except Exception:
                raise WorkerProtocolError(
                    "PROTOCOL.REQUEST_MUTATED",
                    "The immutable worker request changed during execution.",
                ) from None

            terminal_details = _partial_workspace_evidence(invocation_root)
            response_path = response_dir / "response.json"
            attempt.record(
                response_marker_present=(response_path.exists() or response_path.is_symlink())
            )
            terminal_response_frame = None
            terminal_response: Mapping[str, Any] | None = None
            if (timed_out or return_code != 0) and (
                response_path.exists() or response_path.is_symlink()
            ):
                try:
                    terminal_response_frame = load_worker_response(
                        response_dir,
                        request=request,
                        expected_command=command,
                    )
                    terminal_response = terminal_response_frame.response
                except Exception:
                    raise WorkerProtocolError(
                        "PROTOCOL.RESPONSE_SCHEMA",
                        "A stopped worker left an invalid response completion marker.",
                    ) from None
                attempt.framed_response_metadata_digest = (
                    terminal_response_frame.response_metadata_digest
                )
                if self._expected_identity is not None:
                    _verify_pinned_response(
                        command=command,
                        response=terminal_response,
                        expected_identity=self._expected_identity,
                    )
                _verify_response_owner_digests(
                    terminal_response,
                    request,
                    described_owner,
                )
                _verify_invocation_inventory(invocation_root, terminal_response)
                terminal_details.update(
                    {
                        "completed_response_valid": True,
                        "completed_response_status": str(terminal_response["status"]),
                        "completed_response_digest": (
                            terminal_response_frame.response_metadata_digest
                        ),
                    }
                )
            if timed_out:
                raise WorkerProtocolError(
                    "TIMEOUT.WORKER_DEADLINE",
                    "The worker exceeded its local execution deadline.",
                    details={
                        "timeout_seconds": int(self._timeout_seconds),
                        **terminal_details,
                    },
                )
            if return_code != 0:
                raise WorkerProtocolError(
                    "BACKEND.WORKER_PROCESS_FAILED",
                    "The worker process did not complete its response transport.",
                    details={
                        "return_code": return_code,
                        "stdout_byte_length": stdout_digest.byte_length,
                        "stderr_byte_length": stderr_digest.byte_length,
                        **terminal_details,
                    },
                )
            if not response_path.is_file() or response_path.is_symlink():
                raise WorkerProtocolError(
                    "PROTOCOL.RESPONSE_MISSING",
                    "The worker exited without an atomic response completion marker.",
                )
            try:
                response_frame = load_worker_response(
                    response_dir,
                    request=request,
                    expected_command=command,
                )
                response = response_frame.response
            except Exception:
                raise WorkerProtocolError(
                    "PROTOCOL.RESPONSE_SCHEMA",
                    "The worker response does not satisfy the complete closed protocol.",
                ) from None
            attempt.framed_response_metadata_digest = response_frame.response_metadata_digest

            if self._expected_identity is not None:
                _verify_pinned_response(
                    command=command,
                    response=response,
                    expected_identity=self._expected_identity,
                )
            _verify_response_owner_digests(response, request, described_owner)
            invocation_snapshot = _verify_invocation_inventory(invocation_root, response)
            catalog = _response_array_catalog(response)
            has_arrays = "arrays.npz" in response["files"]
            if bool(catalog) != has_arrays:
                raise WorkerProtocolError(
                    "PROTOCOL.RESPONSE_ARRAY_FILE_SET",
                    "The response array archive does not match its closed array catalog.",
                )
            response_arrays: Mapping[str, Any] = {}
            if has_arrays:
                try:
                    response_arrays = load_catalogued_npz_arrays(
                        response_dir / "arrays.npz",
                        catalog=catalog,
                        max_aggregate_uncompressed_bytes=(
                            _remaining_archive_expansion_budget(
                                invocation_root,
                                response_dir / "arrays.npz",
                            )
                        ),
                    )
                except Exception:
                    raise WorkerProtocolError(
                        "PROTOCOL.RESPONSE_ARRAY_CATALOG",
                        "A returned array does not match its closed catalog entry.",
                    ) from None
            validate_success_response_semantics(
                response=response,
                request=request,
                arrays=response_arrays,
                request_arrays=request_arrays,
                described_algorithm=(
                    None if described_owner is None else described_owner.algorithm
                ),
            )
            try:
                verify_snapshot_unchanged(request_dir, request_frame.snapshot)
                verify_snapshot_unchanged(response_dir, response_frame.snapshot)
                if (
                    capture_bundle_snapshot(
                        invocation_root,
                        excluded_paths=frozenset(_SIDE_EFFECT_INVENTORY_EXCLUSIONS),
                    )
                    != invocation_snapshot
                ):
                    raise ValueError
            except Exception:
                raise WorkerProtocolError(
                    "PROTOCOL.BUNDLE_MUTATED",
                    "The worker bundle changed while its response was being verified.",
                ) from None
            retained_response_bundle = _retain_bundle(response_dir, response_frame.snapshot)
            command_evidence = _command_evidence(request, response)
            guard_verified = _guard_activation_verified(guard_active_path)
            authenticated_execution = AuthenticatedWorkerExecutionEvidence._issue(
                _AUTHENTICATED_EXECUTION_ISSUER,
                authenticated_request=authenticated_request,
                response=response,
                canonical_response_bytes=response_frame.metadata_bytes,
                retained_response_bundle=retained_response_bundle,
                response_snapshot=response_frame.snapshot,
                invocation_snapshot=invocation_snapshot,
                command_evidence=command_evidence,
                stdout=stdout_digest,
                stderr=stderr_digest,
                runtime_milliseconds=round(runtime * 1000),
                containment_provider=containment.provider,
                containment_launcher_sha256=containment.launcher_sha256,
                attempt_observability_verified=guard_verified,
            )
            execution_readback = _readback_authenticated_execution(authenticated_execution)
            return WorkerExecution(
                response=deepcopy(execution_readback.response),
                arrays={
                    name: array.copy(order="C")
                    for name, array in execution_readback.response_arrays.items()
                },
                stdout=stdout_digest,
                stderr=stderr_digest,
                core_runtime_seconds=runtime,
                containment_provider=containment.provider,
                containment_launcher_sha256=containment.launcher_sha256,
                attempt_observability_verified=guard_verified,
                command_evidence=(
                    None
                    if execution_readback.command_evidence is None
                    else deepcopy(execution_readback.command_evidence)
                ),
                authenticated_description=authenticated_description,
                authenticated_request=authenticated_request,
                authenticated_execution=authenticated_execution,
            )
