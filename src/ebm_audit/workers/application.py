"""Worker-side execution shell for the exact ``ebm-audit-worker/v2`` framing."""

from __future__ import annotations

import argparse
import os
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ebm_audit.privacy import assert_no_direct_identifier_fields
from ebm_audit.privacy.safe import (
    normalize_worker_success_payload,
    normalize_worker_warning,
)
from ebm_audit.protocol import (
    canonical_json_bytes,
    capture_bundle_snapshot,
    exact_file_sha256_path,
    load_worker_request,
    structured_sha256,
    write_worker_response,
)
from ebm_audit.protocol.identities import FitPayloadFinalizationError

from .arrays import write_deterministic_npz
from .types import WorkerBackend, WorkerFailure, WorkerSuccess

_THREAD_LIMITS = {
    "blas": 1,
    "openblas": 1,
    "mkl": 1,
    "omp": 1,
    "numexpr": 1,
    "veclib": 1,
}
_SIDE_EFFECT_INVENTORY_EXCLUSIONS = frozenset(
    {
        "response/.side-effects.json.tmp",
        "response/side-effects.json",
        "response/.response.json.tmp",
        "response/response.json",
    }
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
_CALLBACK_EXCEPTION_CLASS_IDS = {
    AssertionError: "BUILTINS_ASSERTION_ERROR",
    KeyError: "BUILTINS_KEY_ERROR",
    MemoryError: "BUILTINS_MEMORY_ERROR",
    OSError: "BUILTINS_OS_ERROR",
    RuntimeError: "BUILTINS_RUNTIME_ERROR",
    TypeError: "BUILTINS_TYPE_ERROR",
    ValueError: "BUILTINS_VALUE_ERROR",
}
_CALLBACK_SOURCE_IDS = {
    "ebm_audit.workers.structural": "EBM_AUDIT_WORKERS_STRUCTURAL",
    "model": "KDE_EBM_MODEL",
}
_UNLISTED_CALLBACK_LINE = 0
_MAX_CALLBACK_LINE = 1_000_000


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _request_mapping(frame: Any) -> dict[str, Any]:
    """Accept the public frame object or its plain-mapping compatibility form."""

    for attribute in ("request", "value", "metadata"):
        candidate = getattr(frame, attribute, None)
        if isinstance(candidate, Mapping):
            return dict(candidate)
    if isinstance(frame, Mapping):
        return dict(frame)
    raise TypeError("The protocol request loader returned an unsupported frame type.")


def _callback_failure_diagnostic(caught: Exception) -> dict[str, Any]:
    source_id = "UNLISTED_CALLBACK_SOURCE"
    callback_line = _UNLISTED_CALLBACK_LINE
    traceback = caught.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        module_name = frame.f_globals.get("__name__")
        frame_source_id = (
            _CALLBACK_SOURCE_IDS.get(module_name) if isinstance(module_name, str) else None
        )
        if frame_source_id is not None:
            source_id = frame_source_id
            callback_line = min(max(traceback.tb_lineno, 1), _MAX_CALLBACK_LINE)
            break
        traceback = traceback.tb_next
    return {
        "exception_class_id": _CALLBACK_EXCEPTION_CLASS_IDS.get(type(caught), "UNLISTED_EXCEPTION"),
        "callback_source_id": source_id,
        "callback_line": callback_line,
    }


def _write_atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(canonical_json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


class WorkerApplication:
    """Run trusted local Python callbacks inside the worker subprocess only."""

    def __init__(self, backend: WorkerBackend) -> None:
        self._backend = backend

    @staticmethod
    def _parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="ebm-audit-worker")
        parser.add_argument("--protocol", required=True)
        parser.add_argument(
            "--command",
            required=True,
            choices=("describe", "validate", "fit", "self-test"),
        )
        parser.add_argument("--request-dir", required=True, type=Path)
        parser.add_argument("--response-dir", required=True, type=Path)
        return parser

    def run(self, argv: Sequence[str] | None = None) -> int:
        arguments = self._parser().parse_args(argv)
        if arguments.protocol != "ebm-audit-worker/v2":
            return 2
        request_dir = arguments.request_dir
        response_dir = arguments.response_dir
        if not request_dir.is_absolute() or not response_dir.is_absolute():
            return 2
        if (
            request_dir.is_symlink()
            or response_dir.is_symlink()
            or request_dir.parent.resolve() != response_dir.parent.resolve()
        ):
            return 2
        if not request_dir.is_dir() or not response_dir.is_dir():
            return 2

        try:
            request = _request_mapping(load_worker_request(request_dir))
        except Exception:
            # The core will retain this as transport/protocol failure. Do not
            # expose a schema library message that may quote private input.
            return 2
        if request.get("protocol_version") != arguments.protocol:
            return 2
        if request.get("command") != arguments.command:
            return 2
        try:
            assert_no_direct_identifier_fields(request)
        except Exception:
            return 2

        started_wall = _utc_now()
        started_monotonic = time.monotonic()
        try:
            success = self._dispatch(arguments.command, request, request_dir)
            failure: WorkerFailure | None = None
        except WorkerFailure as caught:
            success = None
            failure = caught
        except FitPayloadFinalizationError as caught:
            success = None
            failure = WorkerFailure(
                status="BACKEND_ERROR",
                code="BACKEND.FIT_PAYLOAD_FINALIZATION_FAILED",
                safe_message="The worker fit payload could not be finalized.",
                phase="payload-finalization",
                retryable_identical_request=False,
                payload_finalization_failure=caught.failure,
            )
        except Exception as caught:
            success = None
            failure = WorkerFailure(
                status="BACKEND_ERROR",
                code="BACKEND.CALLBACK_FAILED",
                safe_message="The worker callback failed without a safe typed result.",
                phase="backend-execution",
                callback_failure=_callback_failure_diagnostic(caught),
            )

        try:
            response = self._frame_response(
                command=arguments.command,
                request=request,
                response_dir=response_dir,
                started_at=started_wall,
                runtime_seconds=max(0.0, time.monotonic() - started_monotonic),
                success=success,
                failure=failure,
            )
            write_worker_response(response_dir, response)
        except Exception:
            # A response that does not satisfy the closed protocol must not be
            # left looking complete. write_worker_response is atomic and writes
            # the completion marker last.
            return 2
        return 0

    def _dispatch(
        self,
        command: str,
        request: Mapping[str, Any],
        request_dir: Path,
    ) -> WorkerSuccess:
        if command == "describe":
            return self._backend.describe(request, request_dir)
        if command == "validate":
            return self._backend.validate(request, request_dir)
        if command == "fit":
            return self._backend.fit(request, request_dir)
        if command == "self-test":
            return self._backend.self_test(request, request_dir)
        raise WorkerFailure(
            status="UNSUPPORTED_CAPABILITY",
            code="CAPABILITY.WORKER_COMMAND_UNAVAILABLE",
            safe_message="This worker command is not active.",
            phase="capability-validation",
        )

    def _frame_response(
        self,
        *,
        command: str,
        request: Mapping[str, Any],
        response_dir: Path,
        started_at: str,
        runtime_seconds: float,
        success: WorkerSuccess | None,
        failure: WorkerFailure | None,
    ) -> dict[str, Any]:
        if (success is None) == (failure is None):
            raise RuntimeError("Exactly one callback outcome is required.")
        if success is None:
            assert failure is not None
            response_status = failure.status
            response_payload: dict[str, Any] | None = None
            response_error: dict[str, Any] | None = failure.as_error()
        else:
            response_status = "SUCCESS"
            response_payload = normalize_worker_success_payload(command, success.payload)
            response_error = None

        response_dir = response_dir.resolve()
        warnings = (
            tuple(normalize_worker_warning(warning) for warning in success.warnings)
            if success is not None
            else ()
        )
        warnings_path = response_dir / "warnings.jsonl"
        with warnings_path.open("xb") as handle:
            os.chmod(warnings_path, 0o600)
            for warning in warnings:
                assert_no_direct_identifier_fields(warning)
                handle.write(canonical_json_bytes(warning) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

        created_paths = [warnings_path]
        if success is not None and success.arrays:
            arrays_path = response_dir / "arrays.npz"
            write_deterministic_npz(arrays_path, success.arrays)
            created_paths.append(arrays_path)

        invocation_root = response_dir.parent.resolve()
        inventory_snapshot = capture_bundle_snapshot(
            invocation_root,
            excluded_paths=_SIDE_EFFECT_INVENTORY_EXCLUSIONS,
        )
        retained_files: list[dict[str, Any]] = [
            {
                "relative_path": relative_path,
                "byte_length": record.byte_length,
                "sha256": record.sha256,
            }
            for relative_path, record in inventory_snapshot.entries
        ]
        side_effects = {
            "schema_version": "ebm-audit-side-effects/1.1",
            "observation_scope": "FINAL_RETAINED_TREE_ONLY",
            "inventory_root": "invocation",
            "inventory_exclusions": [
                "response/.side-effects.json.tmp",
                "response/side-effects.json",
                "response/.response.json.tmp",
                "response/response.json",
            ],
            "retained_request_files": [
                entry for entry in retained_files if entry["relative_path"].startswith("request/")
            ],
            "retained_output_files": [
                entry for entry in retained_files if entry["relative_path"].startswith("response/")
            ],
            "retained_workspace_files": [
                entry for entry in retained_files if entry["relative_path"].startswith("work/")
            ],
            "unobserved_activity_classes": list(_UNOBSERVED_ACTIVITY_CLASSES),
        }
        side_effects_path = response_dir / "side-effects.json"
        _write_atomic_json(side_effects_path, side_effects)

        file_paths = sorted(
            [*created_paths, side_effects_path],
            key=lambda path: path.relative_to(response_dir).as_posix(),
        )
        files = {
            path.relative_to(response_dir).as_posix(): {
                "byte_length": path.stat().st_size,
                "sha256": exact_file_sha256_path(path),
            }
            for path in file_paths
        }
        payload = dict(request["payload"])
        execution_input = (
            dict(payload["execution_input_projection"]) if command in {"validate", "fit"} else None
        )
        algorithm_id = execution_input.get("algorithm_id") if execution_input is not None else None
        backend_identity = dict(self._backend.backend_identity(algorithm_id))
        backend_identity_digest = structured_sha256(
            "ebm-audit/backend-identity/1", backend_identity
        )

        command_has_algorithm = command in {"validate", "fit"}
        capabilities = (
            dict(self._backend.capabilities_for(str(algorithm_id)))
            if command_has_algorithm
            else None
        )
        capabilities_digest = (
            self._backend.capabilities_digest_for(str(algorithm_id))
            if command_has_algorithm
            else None
        )
        response: dict[str, Any] = {
            "protocol_version": "ebm-audit-worker/v2",
            "response_schema_version": "ebm-audit-worker-response/2.0",
            "payload_schema_version": request["payload_schema_version"],
            "request_id": request["request_id"],
            "request_metadata_digest": request["request_metadata_digest"],
            "scientific_request_digest": request["scientific_request_digest"],
            "response_metadata_digest": None,
            "command": command,
            "status": response_status,
            "backend_identity": backend_identity,
            "backend_identity_digest": backend_identity_digest,
            "capabilities": capabilities,
            "capabilities_digest": capabilities_digest,
            "settings_digest": (
                execution_input.get("settings_digest") if execution_input is not None else None
            ),
            "requested_outputs_digest": (
                execution_input.get("requested_outputs_digest")
                if execution_input is not None
                else None
            ),
            "execution_input_projection_digest": (
                payload.get("execution_input_projection_digest")
                if execution_input is not None
                else None
            ),
            "core_code_digest": request["core_code_digest"],
            "started_at_utc": started_at,
            "ended_at_utc": _utc_now(),
            "runtime_seconds": runtime_seconds,
            "resource_summary": {
                "peak_resident_bytes": None,
                "cpu_seconds": None,
                "worker_process_count": 1,
                "effective_thread_limits": dict(_THREAD_LIMITS),
            },
            "warnings_record_count": len(warnings),
            "warnings_file_digest": files["warnings.jsonl"]["sha256"],
            "side_effects_file_digest": files["side-effects.json"]["sha256"],
            "payload": response_payload,
            "error": response_error,
            "files": files,
        }
        assert_no_direct_identifier_fields(response)
        return response
