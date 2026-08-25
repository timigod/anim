"""Private researcher-facing export and validation of baseline references."""

from __future__ import annotations

import json
import os
import unicodedata
import zipfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from io import BytesIO
from pathlib import Path
from typing import Any, cast

import numpy as np

from ebm_audit.artifacts import ensure_private_directory, write_private_new
from ebm_audit.config.models import ConfigContractError
from ebm_audit.config.verification import (
    _MAX_PRIVATE_ALIGNMENT_BYTES,
    _MAX_REFERENCE_ARRAYS_BYTES,
    _MAX_REFERENCE_MANIFEST_BYTES,
    _open_private_root,
    _read_private_file,
    _reference_bundle_component_paths,
    _reference_bundle_component_records,
    _retain_verified_file,
    _verify_retained_descriptor,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
)
from ebm_audit.schema import SchemaValidationError, validate_instance
from ebm_audit.workers.arrays import canonical_array

from .bundle import (
    BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME,
    BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME,
    BASELINE_REFERENCE_BUNDLE_SCHEMA_VERSION,
    ReferenceBundleError,
    _issue_verified_reference_bundle,
    _validated_reference_bundle_manifest,
)
from .reproduction import (
    BaselineReproductionError,
    _statistical_diagnostics_digest,
    _verify_private_alignment_artifact,
    issue_verified_reference_result,
)

BASELINE_REFERENCE_MANIFEST_NAME = "reference-bundle.json"
BASELINE_REFERENCE_VALIDATION_RECEIPT_SCHEMA_VERSION = (
    "ebm-audit-baseline-reference-validation-receipt/1.0"
)
BASELINE_REFERENCE_DRAFT_NAME = "reference-bundle-draft.json"
BASELINE_REFERENCE_NOTEBOOK_EXAMPLE_NAME = "reference-bundle-notebook-example.py"
_VALIDATION_RECEIPT_SCHEMA_NAME = "baseline-reference-validation-receipt.schema.json"
_DRAFT_SCHEMA_VERSION = "ebm-audit-baseline-reference-draft/1.0"
_INIT_SCHEMA_VERSION = "ebm-audit-baseline-reference-init/1.0"


def statistical_diagnostics_digest(
    convergence: Mapping[str, Any],
    ordered_chain_execution_ids: Sequence[str],
) -> str:
    """Return the identity-normalized digest for notebook-supplied diagnostics."""

    return _statistical_diagnostics_digest(
        convergence,
        ordered_chain_execution_ids,
    )


def _reference_error(message: str) -> ReferenceBundleError:
    return ReferenceBundleError(message)


def _safe_absolute_manifest_path(value: str | os.PathLike[str]) -> Path:
    try:
        path = Path(value).absolute()
    except (OSError, TypeError, ValueError):
        raise _reference_error("The canonical reference manifest path is invalid.") from None
    if (
        path.name != BASELINE_REFERENCE_MANIFEST_NAME
        or not path.is_absolute()
        or not path.parts
        or path.parts[0] != os.sep
        or any(
            part in {"", ".", ".."} or "\x00" in part or not unicodedata.is_normalized("NFC", part)
            for part in path.parts[1:]
        )
    ):
        raise _reference_error("The canonical reference manifest path is invalid.")
    return path


def _snapshot_arrays(arrays: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if not isinstance(arrays, Mapping):
            raise TypeError
        names = tuple(arrays)
        if any(type(name) is not str for name in names) or len(set(names)) != len(names):
            raise TypeError
        return {
            name: np.array(canonical_array(arrays[name]), copy=True, order="C")
            for name in sorted(names)
        }
    except (KeyError, RuntimeError, TypeError, ValueError):
        raise _reference_error(
            "The supplied reference arrays do not match the closed reference catalog."
        ) from None


def _deterministic_npz_bytes(arrays: Mapping[str, Any]) -> bytes:
    """Serialize the already-validated array snapshot using the canonical NPZ layout."""

    archive_buffer = BytesIO()
    try:
        with zipfile.ZipFile(
            archive_buffer,
            mode="w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            for name in sorted(arrays):
                member_buffer = BytesIO()
                write_array = cast(Any, np.lib.format.write_array)
                write_array(
                    member_buffer,
                    canonical_array(arrays[name]),
                    allow_pickle=False,
                )
                info = zipfile.ZipInfo(
                    f"{name}.npy",
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o600 << 16
                archive.writestr(info, member_buffer.getvalue())
        return archive_buffer.getvalue()
    except (OSError, RuntimeError, TypeError, ValueError, zipfile.BadZipFile):
        raise _reference_error(
            "The supplied reference arrays could not be serialized canonically."
        ) from None


def _validated_export_components(
    *,
    reference: Mapping[str, Any],
    arrays: Mapping[str, Any],
    private_alignment: Mapping[str, Any],
) -> tuple[bytes, bytes, bytes]:
    array_snapshot = _snapshot_arrays(arrays)
    try:
        reference_owner = issue_verified_reference_result(
            reference,
            reference_arrays=array_snapshot,
        )
        reference_bytes = reference_owner.canonical_reference_bytes
        reference_value = strict_json_loads(reference_bytes)
        if type(reference_value) is not dict:
            raise BaselineReproductionError("The canonical reference is invalid.")
        alignment = _verify_private_alignment_artifact(
            private_alignment,
            cast(Mapping[str, Any], reference_value),
        )
        alignment_bytes = canonical_json_bytes(alignment)
        if len(alignment_bytes) > _MAX_PRIVATE_ALIGNMENT_BYTES:
            raise ReferenceBundleError(
                "The private reference alignment exceeds its closed byte limit."
            )
        arrays_bytes = _deterministic_npz_bytes(array_snapshot)
        if len(arrays_bytes) > _MAX_REFERENCE_ARRAYS_BYTES:
            raise ReferenceBundleError("The reference array archive exceeds its closed byte limit.")
        manifest_bytes = canonical_json_bytes(
            {
                "bundle_schema_version": BASELINE_REFERENCE_BUNDLE_SCHEMA_VERSION,
                "reference_result": reference_value,
                "files": {
                    BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME: {
                        "byte_length": len(arrays_bytes),
                        "sha256": exact_file_sha256(arrays_bytes),
                    },
                    BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME: {
                        "byte_length": len(alignment_bytes),
                        "sha256": exact_file_sha256(alignment_bytes),
                    },
                },
            }
        )
        if len(manifest_bytes) > _MAX_REFERENCE_MANIFEST_BYTES:
            raise ReferenceBundleError(
                "The reference bundle manifest exceeds its closed byte limit."
            )
        with BytesIO(arrays_bytes) as arrays_handle:
            _issue_verified_reference_bundle(
                manifest_bytes=manifest_bytes,
                manifest_digest=exact_file_sha256(manifest_bytes),
                manifest_identity=(0, 0, len(manifest_bytes), 0, 0),
                arrays_handle=arrays_handle,
                arrays_digest=exact_file_sha256(arrays_bytes),
                arrays_identity=(0, 0, len(arrays_bytes), 0, 0),
                private_alignment_bytes=alignment_bytes,
                private_alignment_digest=exact_file_sha256(alignment_bytes),
                private_alignment_identity=(0, 0, len(alignment_bytes), 0, 0),
                alignment_binding_eligible=False,
            )
        return manifest_bytes, arrays_bytes, alignment_bytes
    except ReferenceBundleError:
        raise
    except (
        BaselineReproductionError,
        CanonicalizationError,
        KeyError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise _reference_error(
            "The supplied reference material does not satisfy the closed export contract."
        ) from None
    finally:
        del array_snapshot


def _validation_receipt(
    *,
    manifest: Mapping[str, Any],
    reference_id: str,
    manifest_digest: str,
    manifest_length: int,
    arrays_digest: str,
    arrays_length: int,
    alignment_digest: str,
    alignment_length: int,
) -> dict[str, Any]:
    try:
        reference = cast(Mapping[str, Any], manifest["reference_result"])
        dataset = cast(Mapping[str, Any], reference["dataset"])
        outputs = cast(Mapping[str, Any], reference["outputs"])
        arrays = cast(Mapping[str, Any], outputs["arrays"])
        receipt: dict[str, Any] = {
            "receipt_schema_version": (BASELINE_REFERENCE_VALIDATION_RECEIPT_SCHEMA_VERSION),
            "status": "VALID",
            "reference_id": reference_id,
            "components": [
                {
                    "name": BASELINE_REFERENCE_MANIFEST_NAME,
                    "sha256": manifest_digest,
                    "byte_length": manifest_length,
                },
                {
                    "name": BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME,
                    "sha256": arrays_digest,
                    "byte_length": arrays_length,
                },
                {
                    "name": BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME,
                    "sha256": alignment_digest,
                    "byte_length": alignment_length,
                },
            ],
            "aggregate_counts": {
                "participant_count": dataset["participant_count"],
                "event_count": dataset["event_count"],
                "array_count": len(arrays),
            },
        }
        validate_instance(receipt, _VALIDATION_RECEIPT_SCHEMA_NAME)
        return receipt
    except ReferenceBundleError:
        raise
    except (KeyError, SchemaValidationError, TypeError, ValueError):
        raise _reference_error(
            "The reference validation receipt could not satisfy its closed contract."
        ) from None


def validate_reference_bundle(
    manifest_file: str | os.PathLike[str],
) -> dict[str, Any]:
    """Validate one canonical bundle with the config importer's exact file semantics."""

    manifest_path = _safe_absolute_manifest_path(manifest_file)
    root_descriptor: int | None = None
    retained: list[int] = []
    try:
        root_descriptor = _open_private_root(manifest_path.parent)
        manifest_digest, manifest_identity, manifest_bytes = _read_private_file(
            root_descriptor,
            manifest_path.name,
            maximum_bytes=_MAX_REFERENCE_MANIFEST_BYTES,
            retain_bytes=True,
        )
        if manifest_bytes is None:  # pragma: no cover - closed helper contract
            raise _reference_error("The canonical reference manifest is unavailable.")
        arrays_record, alignment_record = _reference_bundle_component_records(manifest_bytes)
        arrays_path, alignment_path = _reference_bundle_component_paths(manifest_path.name)
        arrays_digest, arrays_identity, _unused_arrays = _read_private_file(
            root_descriptor,
            arrays_path,
            maximum_bytes=_MAX_REFERENCE_ARRAYS_BYTES,
        )
        alignment_digest, alignment_identity, _unused_alignment = _read_private_file(
            root_descriptor,
            alignment_path,
            maximum_bytes=_MAX_PRIVATE_ALIGNMENT_BYTES,
        )
        if (
            arrays_digest != arrays_record["sha256"]
            or alignment_digest != alignment_record["sha256"]
        ):
            raise _reference_error("A canonical reference component is detached from its manifest.")

        roles = (
            (
                manifest_path.name,
                manifest_digest,
                manifest_identity,
                _MAX_REFERENCE_MANIFEST_BYTES,
            ),
            (
                arrays_path,
                arrays_digest,
                arrays_identity,
                _MAX_REFERENCE_ARRAYS_BYTES,
            ),
            (
                alignment_path,
                alignment_digest,
                alignment_identity,
                _MAX_PRIVATE_ALIGNMENT_BYTES,
            ),
        )
        for relative_path, digest, identity, maximum_bytes in roles:
            retained.append(
                _retain_verified_file(
                    root_descriptor,
                    relative_path,
                    expected_digest=digest,
                    expected_identity=identity,
                    maximum_bytes=maximum_bytes,
                )
            )
        manifest_readback = _verify_retained_descriptor(
            retained[0],
            expected_digest=manifest_digest,
            expected_identity=manifest_identity,
            retain_bytes=True,
            maximum_bytes=_MAX_REFERENCE_MANIFEST_BYTES,
        )
        alignment_readback = _verify_retained_descriptor(
            retained[2],
            expected_digest=alignment_digest,
            expected_identity=alignment_identity,
            retain_bytes=True,
            maximum_bytes=_MAX_PRIVATE_ALIGNMENT_BYTES,
        )
        if manifest_readback is None or alignment_readback is None:
            raise _reference_error("The canonical reference components are unavailable.")
        with os.fdopen(os.dup(retained[1]), "rb", closefd=True) as arrays_handle:
            bundle = _issue_verified_reference_bundle(
                manifest_bytes=manifest_readback,
                manifest_digest=manifest_digest,
                manifest_identity=manifest_identity,
                arrays_handle=arrays_handle,
                arrays_digest=arrays_digest,
                arrays_identity=arrays_identity,
                private_alignment_bytes=alignment_readback,
                private_alignment_digest=alignment_digest,
                private_alignment_identity=alignment_identity,
                alignment_binding_eligible=False,
            )
        manifest = _validated_reference_bundle_manifest(manifest_readback)
        return _validation_receipt(
            manifest=manifest,
            reference_id=bundle.reference_id,
            manifest_digest=manifest_digest,
            manifest_length=manifest_identity[2],
            arrays_digest=arrays_digest,
            arrays_length=arrays_identity[2],
            alignment_digest=alignment_digest,
            alignment_length=alignment_identity[2],
        )
    except ReferenceBundleError:
        raise
    except (ConfigContractError, KeyError, OSError, TypeError, ValueError):
        raise _reference_error(
            "The canonical reference bundle is invalid or unavailable."
        ) from None
    finally:
        for descriptor in retained:
            with suppress(OSError):
                os.close(descriptor)
        if root_descriptor is not None:
            with suppress(OSError):
                os.close(root_descriptor)


def write_reference_bundle(
    *,
    output_dir: str | os.PathLike[str],
    reference: Mapping[str, Any],
    arrays: Mapping[str, Any],
    private_alignment: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and write one canonical private bundle, publishing its manifest last."""

    manifest_bytes, arrays_bytes, alignment_bytes = _validated_export_components(
        reference=reference,
        arrays=arrays,
        private_alignment=private_alignment,
    )
    directory = Path(output_dir)
    manifest_path = directory / BASELINE_REFERENCE_MANIFEST_NAME
    arrays_path = directory / BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME
    alignment_path = directory / BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME
    try:
        ensure_private_directory(directory)
        if any(
            path.exists() or path.is_symlink()
            for path in (manifest_path, arrays_path, alignment_path)
        ):
            raise _reference_error(
                "A canonical reference output already exists; export never overwrites."
            )
        write_private_new(arrays_path, arrays_bytes)
        write_private_new(alignment_path, alignment_bytes)
        write_private_new(manifest_path, manifest_bytes)
    except ReferenceBundleError:
        raise
    except (InvalidInputError, OSError, TypeError, ValueError):
        raise _reference_error(
            "The canonical reference bundle could not be written without overwriting."
        ) from None
    return validate_reference_bundle(manifest_path)


def initialize_reference_bundle(
    output_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Create a deliberately non-importable draft and notebook helper example."""

    directory = Path(output_dir)
    draft_path = directory / BASELINE_REFERENCE_DRAFT_NAME
    example_path = directory / BASELINE_REFERENCE_NOTEBOOK_EXAMPLE_NAME
    draft = {
        "draft_schema_version": _DRAFT_SCHEMA_VERSION,
        "state": "DRAFT_NOT_IMPORTABLE",
        "purpose": (
            "Complete the canonical reference objects inside the researcher's "
            "private local notebook before export."
        ),
        "canonical_output_files": [
            BASELINE_REFERENCE_MANIFEST_NAME,
            BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME,
            BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME,
        ],
        "required_notebook_objects": [
            "reference_body",
            "arrays",
            "private_alignment",
        ],
        "notebook_helper": "ebm_audit.baseline.export.write_reference_bundle",
        "diagnostics_helper": (
            "ebm_audit.baseline.export.statistical_diagnostics_digest"
        ),
        "schema_contracts": {
            "reference_body": (
                "canonical-records.schema.json"
                "#/$defs/CanonicalReferenceResultBody"
            ),
            "reference": (
                "canonical-records.schema.json"
                "#/$defs/CanonicalReferenceResult"
            ),
            "scientific_contract": (
                "canonical-records.schema.json"
                "#/$defs/ReferenceScientificContract"
            ),
            "outputs": (
                "canonical-records.schema.json"
                "#/$defs/ReferenceOutputs"
            ),
            "array_catalog": (
                "canonical-records.schema.json"
                "#/$defs/ReferenceArrayCatalog"
            ),
            "private_alignment": (
                "canonical-records.schema.json"
                "#/$defs/PrivateReferenceAlignmentArtifact"
            ),
            "convergence": (
                "canonical-records.schema.json"
                "#/$defs/ConvergenceRecord"
            ),
        },
        "rules": [
            "Do not reconstruct unavailable evidence.",
            "Do not put participant material on a command line.",
            "Keep the bundle outside repositories and report output.",
        ],
    }
    draft_bytes = (
        json.dumps(
            draft,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    example_bytes = (
        b"from pathlib import Path\n"
        b"\n"
        b"from ebm_audit.baseline import build_reference_result\n"
        b"from ebm_audit.baseline.export import (\n"
        b"    statistical_diagnostics_digest,\n"
        b"    write_reference_bundle,\n"
        b")\n"
        b"\n"
        b"# Build reference_body, arrays, and private_alignment from exact\n"
        b"# private notebook output.\n"
        b"# Use the schema_contracts in reference-bundle-draft.json; never reconstruct evidence.\n"
        b"# If exact comparable diagnostics are available before self-identification:\n"
        b"# reference_body[\"outputs\"][\"statistical_diagnostics_digest\"] = (\n"
        b"#     statistical_diagnostics_digest(\n"
        b"#         convergence,\n"
        b"#         ordered_chain_execution_ids=ordered_chain_execution_ids,\n"
        b"#     )\n"
        b"# )\n"
        b"# Otherwise set that field to None; the outcome cannot be fully reproduced.\n"
        b"reference = build_reference_result(reference_body)\n"
        b"receipt = write_reference_bundle(\n"
        b'    output_dir=Path("private-reference-output"),\n'
        b"    reference=reference,\n"
        b"    arrays=arrays,\n"
        b"    private_alignment=private_alignment,\n"
        b")\n"
        b"receipt\n"
    )
    try:
        ensure_private_directory(directory)
        if any(path.exists() or path.is_symlink() for path in (draft_path, example_path)):
            raise InvalidInputError(
                "SPEC.OUTPUT_ALREADY_EXISTS",
                "The output path already exists; this command does not overwrite artifacts.",
            )
        write_private_new(draft_path, draft_bytes)
        write_private_new(example_path, example_bytes)
    except InvalidInputError:
        raise
    except (OSError, TypeError, ValueError):
        raise InvalidInputError(
            "SPEC.BASELINE_REFERENCE_INIT",
            "The private baseline-reference draft could not be created.",
        ) from None
    return {
        "init_schema_version": _INIT_SCHEMA_VERSION,
        "status": "DRAFT_CREATED",
        "files": [
            BASELINE_REFERENCE_DRAFT_NAME,
            BASELINE_REFERENCE_NOTEBOOK_EXAMPLE_NAME,
        ],
        "canonical_bundle_status": "NOT_CREATED",
    }


__all__ = [
    "BASELINE_REFERENCE_DRAFT_NAME",
    "BASELINE_REFERENCE_MANIFEST_NAME",
    "BASELINE_REFERENCE_NOTEBOOK_EXAMPLE_NAME",
    "BASELINE_REFERENCE_VALIDATION_RECEIPT_SCHEMA_VERSION",
    "initialize_reference_bundle",
    "statistical_diagnostics_digest",
    "validate_reference_bundle",
    "write_reference_bundle",
]
