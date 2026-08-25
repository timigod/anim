"""Strict request/response metadata framing around closed bundles."""

from __future__ import annotations

import copy
import os
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from ebm_audit.schema import SchemaValidationError, validate_instance

from .bundle import (
    build_files_map,
    read_regular_file_exact,
    verify_files_map,
)
from .canonical import canonical_json_bytes, exact_file_sha256, strict_json_loads
from .errors import BundleValidationError, CanonicalizationError, FramingError, PathBoundaryError
from .identities import (
    bind_request_digests,
    bind_response_metadata_digest,
    request_metadata_digest,
    response_metadata_digest,
    scientific_request_digest,
    validate_request_execution_input_binding,
)
from .models import (
    WorkerCommand,
    WorkerRequestFrame,
    WorkerResponseFrame,
    WorkerStatus,
)
from .paths import PathLike, ensure_private_directory, resolve_contained_path

MAX_PROTOCOL_METADATA_BYTES = 16 * 1024 * 1024
MAX_WARNINGS_JSONL_BYTES = 8 * 1024 * 1024
MAX_SIDE_EFFECTS_JSON_BYTES = 8 * 1024 * 1024
_PROTOCOL_VERSION = "ebm-audit-worker/v2"
_REQUEST_SCHEMA_VERSION = "ebm-audit-worker-request/2.0"
_RESPONSE_SCHEMA_VERSION = "ebm-audit-worker-response/2.0"


def _require_request_v2_envelope(request: Mapping[str, Any]) -> None:
    if (
        request.get("protocol_version") != _PROTOCOL_VERSION
        or request.get("request_schema_version") != _REQUEST_SCHEMA_VERSION
    ):
        raise FramingError("Worker request is not the exact v2 envelope.")


def _require_response_v2_envelope(response: Mapping[str, Any]) -> None:
    if (
        response.get("protocol_version") != _PROTOCOL_VERSION
        or response.get("response_schema_version") != _RESPONSE_SCHEMA_VERSION
    ):
        raise FramingError("Worker response is not the exact v2 envelope.")


def _load_metadata(root: Path, name: str) -> tuple[dict[str, Any], bytes]:
    path = resolve_contained_path(root, name)
    data = read_regular_file_exact(path, max_bytes=MAX_PROTOCOL_METADATA_BYTES)
    value = strict_json_loads(data)
    if not isinstance(value, dict):
        raise FramingError("Protocol metadata root must be an object.")
    return value, data


def _require_request_file_shape(command: WorkerCommand, files: Mapping[str, object]) -> None:
    has_values = "values.npz" in files
    if command in {WorkerCommand.DESCRIBE, WorkerCommand.SELF_TEST} and has_values:
        raise FramingError("Data-free worker command must not include values.npz.")
    data_commands = {WorkerCommand.VALIDATE, WorkerCommand.FIT, WorkerCommand.STAGE}
    if command in data_commands and not has_values:
        raise FramingError("Data-bearing worker command requires values.npz.")


def _verify_response_diagnostics(root: Path, response: Mapping[str, Any]) -> None:
    files = response["files"]
    assert isinstance(files, Mapping)
    warnings_record = files["warnings.jsonl"]
    side_effects_record = files["side-effects.json"]
    if not isinstance(warnings_record, Mapping) or not isinstance(side_effects_record, Mapping):
        raise FramingError("Response diagnostic file records are invalid.")
    if response["warnings_file_digest"] != warnings_record.get("sha256"):
        raise FramingError("Warnings digest does not match the closed files map.")
    if response["side_effects_file_digest"] != side_effects_record.get("sha256"):
        raise FramingError("Side-effects digest does not match the closed files map.")

    warnings_bytes = read_regular_file_exact(
        resolve_contained_path(root, "warnings.jsonl"),
        max_bytes=MAX_WARNINGS_JSONL_BYTES,
    )
    if exact_file_sha256(warnings_bytes) != response["warnings_file_digest"]:
        raise FramingError("Warnings digest does not match exact file bytes.")
    warning_lines = warnings_bytes.splitlines()
    if len(warning_lines) != response["warnings_record_count"]:
        raise FramingError("Warnings record count does not match warnings.jsonl.")
    for line in warning_lines:
        if not line:
            raise FramingError("Warnings JSONL contains an empty record.")
        warning = strict_json_loads(line)
        validate_instance(
            warning,
            "canonical-records.schema.json",
            definition="WarningRecord",
        )

    side_effects_bytes = read_regular_file_exact(
        resolve_contained_path(root, "side-effects.json"),
        max_bytes=MAX_SIDE_EFFECTS_JSON_BYTES,
    )
    if exact_file_sha256(side_effects_bytes) != response["side_effects_file_digest"]:
        raise FramingError("Side-effects digest does not match exact file bytes.")
    side_effects = strict_json_loads(side_effects_bytes)
    validate_instance(
        side_effects,
        "worker-protocol.schema.json",
        definition="SideEffectsRecord",
    )


def load_worker_request(
    request_dir: PathLike,
    *,
    expected_command: WorkerCommand | str | None = None,
) -> WorkerRequestFrame:
    """Load, schema-check, hash-check, and snapshot a request bundle."""

    root = ensure_private_directory(request_dir)
    try:
        request, metadata_bytes = _load_metadata(root, "request.json")
        _require_request_v2_envelope(request)
        validate_instance(request, "worker-protocol.schema.json", definition="WorkerRequest")
        validate_request_execution_input_binding(request)
        command = WorkerCommand(request["command"])
        if expected_command is not None and command != WorkerCommand(expected_command):
            raise FramingError("Request command does not match the invocation command.")
        supplied_metadata = request["request_metadata_digest"]
        if supplied_metadata != request_metadata_digest(request):
            raise FramingError("Request metadata digest does not match its exact owner.")
        supplied_scientific = request["scientific_request_digest"]
        if supplied_scientific != scientific_request_digest(request):
            raise FramingError("Scientific request digest does not match its exact owner.")
        files = request["files"]
        assert isinstance(files, Mapping)
        _require_request_file_shape(command, files)
        snapshot = verify_files_map(root, files, metadata_name="request.json")
    except (SchemaValidationError, BundleValidationError, CanonicalizationError, PathBoundaryError):
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise FramingError("Request metadata has an invalid closed shape.") from exc
    if dict(snapshot.entries)["request.json"].byte_length != len(metadata_bytes):
        raise FramingError("Request metadata changed during validation.")
    return WorkerRequestFrame(
        command=command,
        request_id=request["request_id"],
        request_metadata_digest=supplied_metadata,
        scientific_request_digest=supplied_scientific,
        metadata_bytes=metadata_bytes,
        snapshot=snapshot,
    )


def load_worker_response(
    response_dir: PathLike,
    *,
    request: Mapping[str, Any] | None = None,
    expected_command: WorkerCommand | str | None = None,
) -> WorkerResponseFrame:
    """Load and verify a complete response whose marker was written last."""

    root = ensure_private_directory(response_dir)
    response, metadata_bytes = _load_metadata(root, "response.json")
    _require_response_v2_envelope(response)
    validate_instance(response, "worker-protocol.schema.json", definition="WorkerResponse")
    try:
        command = WorkerCommand(response["command"])
        status = WorkerStatus(response["status"])
        if expected_command is not None and command != WorkerCommand(expected_command):
            raise FramingError("Response command does not match the invocation command.")
        if response["response_metadata_digest"] != response_metadata_digest(response):
            raise FramingError("Response metadata digest does not match its exact owner.")
        if request is not None:
            for field in (
                "request_id",
                "request_metadata_digest",
                "scientific_request_digest",
                "command",
                "core_code_digest",
            ):
                if response[field] != request[field]:
                    raise FramingError("Response does not match its request owner.")
            if response["command"] in {"validate", "fit", "stage"} and response[
                "execution_input_projection_digest"
            ] != request["payload"]["execution_input_projection_digest"]:
                raise FramingError("Response execution input does not match its request owner.")
        files = response["files"]
        if not isinstance(files, Mapping):
            raise FramingError("Response files map is not an object.")
        if "warnings.jsonl" not in files or "side-effects.json" not in files:
            raise FramingError("Complete response is missing a mandatory diagnostic file.")
        snapshot = verify_files_map(root, files, metadata_name="response.json")
        _verify_response_diagnostics(root, response)
    except (BundleValidationError, PathBoundaryError):
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise FramingError("Response metadata has an invalid closed shape.") from exc
    return WorkerResponseFrame(
        command=command,
        status=status,
        request_id=response["request_id"],
        response_metadata_digest=response["response_metadata_digest"],
        metadata_bytes=metadata_bytes,
        snapshot=snapshot,
    )


def _write_metadata_atomic(
    root: Path,
    *,
    name: str,
    temporary_name: str,
    data: bytes,
    overwrite: bool,
) -> None:
    destination = root / name
    temporary = root / temporary_name
    if temporary.exists() or temporary.is_symlink():
        raise FramingError("Atomic metadata temporary path already exists.")
    if not overwrite and (destination.exists() or destination.is_symlink()):
        raise FramingError("Protocol metadata completion marker already exists.")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        directory_descriptor = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise


def write_worker_request(
    request_dir: PathLike,
    request: Mapping[str, Any],
    *,
    overwrite: bool = False,
) -> WorkerRequestFrame:
    """Bind, validate, and atomically write ``request.json`` last."""

    root = ensure_private_directory(request_dir)
    document = copy.deepcopy(dict(request))
    document["files"] = build_files_map(root, metadata_name="request.json")
    _require_request_v2_envelope(document)
    bound = bind_request_digests(document)
    _require_request_file_shape(WorkerCommand(bound["command"]), bound["files"])
    data = canonical_json_bytes(bound)
    if len(data) > MAX_PROTOCOL_METADATA_BYTES:
        raise FramingError("Request metadata exceeds the allowed byte limit.")
    _write_metadata_atomic(
        root,
        name="request.json",
        temporary_name=".request.json.tmp",
        data=data,
        overwrite=overwrite,
    )
    return load_worker_request(root)


def write_worker_response(
    response_dir: PathLike,
    response: Mapping[str, Any],
    *,
    overwrite: bool = False,
) -> WorkerResponseFrame:
    """Bind, validate, and atomically write ``response.json`` last."""

    root = ensure_private_directory(response_dir)
    document = copy.deepcopy(dict(response))
    _require_response_v2_envelope(document)
    document["files"] = build_files_map(root, metadata_name="response.json")
    bound = bind_response_metadata_digest(document)
    files = bound["files"]
    if "warnings.jsonl" not in files or "side-effects.json" not in files:
        raise FramingError("Complete response requires warnings and side-effects files.")
    _verify_response_diagnostics(root, bound)
    data = canonical_json_bytes(bound)
    if len(data) > MAX_PROTOCOL_METADATA_BYTES:
        raise FramingError("Response metadata exceeds the allowed byte limit.")
    _write_metadata_atomic(
        root,
        name="response.json",
        temporary_name=".response.json.tmp",
        data=data,
        overwrite=overwrite,
    )
    return load_worker_response(root)
