"""Deterministic, pickle-free NPZ helpers for protocol arrays."""

from __future__ import annotations

import os
import re
import struct
import tempfile
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from io import BytesIO
from math import prod
from pathlib import Path
from typing import Any, BinaryIO

from ebm_audit.protocol import exact_file_sha256, structured_sha256

_ALLOWED_DTYPES = frozenset({"bool", "int32", "int64", "float64"})
_MAX_NPY_HEADER_BYTES = 64 * 1024
_DEFAULT_MAX_AGGREGATE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_MAX_ZIP_MEMBERS = 64
_MAX_CENTRAL_DIRECTORY_BYTES = 256 * 1024
_EOCD = struct.Struct("<4s4H2LH")
_CENTRAL_DIRECTORY_ENTRY = struct.Struct("<4s6H3L5H2L")
_LOCAL_FILE_HEADER = struct.Struct("<4s5H3L2H")
_EOCD_SIGNATURE = b"PK\x05\x06"
_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_LOCAL_FILE_SIGNATURE = b"PK\x03\x04"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP32_UINT16_SENTINEL = (1 << 16) - 1
_ZIP32_UINT32_SENTINEL = (1 << 32) - 1
_SAFE_MEMBER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.npy\Z")


@dataclass(frozen=True)
class _AdmittedMember:
    filename: str
    logical_name: str
    compressed_size: int
    uncompressed_size: int
    local_header_offset: int
    local_record_end: int


@dataclass(frozen=True)
class _ArchiveAdmission:
    members: tuple[_AdmittedMember, ...]
    aggregate_uncompressed_bytes: int


def _read_exact_at(handle: BinaryIO, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0:
        raise ValueError("The NPZ archive contains an invalid byte range.")
    handle.seek(offset)
    value = handle.read(length)
    if len(value) != length:
        raise ValueError("The NPZ archive is truncated.")
    return value


def _validated_uncompressed_budget(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("The NPZ aggregate-uncompressed-byte limit is invalid.")
    return value


def _safe_member_name(filename_bytes: bytes) -> tuple[str, str]:
    try:
        filename = filename_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("The NPZ archive contains a non-ASCII member name.") from exc
    if _SAFE_MEMBER_NAME.fullmatch(filename) is None:
        raise ValueError("The NPZ archive contains a forbidden member path.")
    logical_name = filename.removesuffix(".npy")
    if not logical_name:
        raise ValueError("The NPZ archive contains an empty array name.")
    return filename, logical_name


def _expected_filenames(expected_names: set[str]) -> frozenset[str]:
    filenames: set[str] = set()
    for logical_name in expected_names:
        if not isinstance(logical_name, str):
            raise ValueError("The expected NPZ member set contains an invalid array name.")
        filename, observed_logical_name = _safe_member_name(
            f"{logical_name}.npy".encode("ascii", errors="strict")
        )
        if observed_logical_name != logical_name:
            raise ValueError("The expected NPZ member set contains an invalid array name.")
        filenames.add(filename)
    if len(filenames) != len(expected_names):
        raise ValueError("The expected NPZ member set contains duplicate array names.")
    return frozenset(filenames)


def _admit_npz_archive(
    handle: BinaryIO,
    *,
    expected_names: set[str],
    max_aggregate_uncompressed_bytes: int,
) -> _ArchiveAdmission:
    """Raw-bound a closed, stored-only NPZ before zipfile or NumPy sees it."""

    budget = _validated_uncompressed_budget(max_aggregate_uncompressed_bytes)
    expected_filenames = _expected_filenames(expected_names)
    handle.seek(0, os.SEEK_END)
    archive_size = handle.tell()
    if archive_size < _EOCD.size:
        raise ValueError("The NPZ archive is not a complete ZIP file.")

    eocd_offset = archive_size - _EOCD.size
    eocd_raw = _read_exact_at(handle, eocd_offset, _EOCD.size)
    (
        signature,
        disk_number,
        central_directory_disk,
        disk_member_count,
        member_count,
        central_directory_size,
        central_directory_offset,
        archive_comment_length,
    ) = _EOCD.unpack(eocd_raw)
    if signature != _EOCD_SIGNATURE:
        raise ValueError("The NPZ archive has no exact end-of-central-directory record.")
    if archive_comment_length != 0:
        raise ValueError("The NPZ archive comment is forbidden.")
    if disk_number != 0 or central_directory_disk != 0 or disk_member_count != member_count:
        raise ValueError("Multi-disk NPZ archives are forbidden.")
    if (
        member_count == _ZIP32_UINT16_SENTINEL
        or central_directory_size == _ZIP32_UINT32_SENTINEL
        or central_directory_offset == _ZIP32_UINT32_SENTINEL
    ):
        raise ValueError("ZIP64 NPZ archives are forbidden.")
    if member_count > _MAX_ZIP_MEMBERS:
        raise ValueError("The NPZ archive exceeds the member-count limit.")
    if central_directory_size > _MAX_CENTRAL_DIRECTORY_BYTES:
        raise ValueError("The NPZ central directory exceeds its byte limit.")
    if central_directory_offset + central_directory_size != eocd_offset:
        raise ValueError("The NPZ central-directory byte range is not exact.")
    if (
        eocd_offset >= 20
        and _read_exact_at(handle, eocd_offset - 20, 4) == _ZIP64_LOCATOR_SIGNATURE
    ):
        raise ValueError("ZIP64 NPZ archives are forbidden.")

    central_directory = _read_exact_at(
        handle,
        central_directory_offset,
        central_directory_size,
    )
    cursor = 0
    aggregate_uncompressed_bytes = 0
    members: list[_AdmittedMember] = []
    observed_filenames: set[str] = set()
    observed_logical_names: set[str] = set()
    for _ in range(member_count):
        fixed_end = cursor + _CENTRAL_DIRECTORY_ENTRY.size
        if fixed_end > len(central_directory):
            raise ValueError("The NPZ central directory is truncated.")
        (
            member_signature,
            _version_made_by,
            version_needed,
            flags,
            compression_method,
            modified_time,
            modified_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename_length,
            extra_length,
            member_comment_length,
            member_disk_number,
            _internal_attributes,
            _external_attributes,
            local_header_offset,
        ) = _CENTRAL_DIRECTORY_ENTRY.unpack_from(central_directory, cursor)
        if member_signature != _CENTRAL_DIRECTORY_SIGNATURE:
            raise ValueError("The NPZ central directory contains an invalid member record.")
        record_end = fixed_end + filename_length + extra_length + member_comment_length
        if record_end > len(central_directory):
            raise ValueError("The NPZ central-directory member record is truncated.")
        filename_bytes = central_directory[fixed_end : fixed_end + filename_length]
        if extra_length != 0:
            raise ValueError("NPZ member extra fields are forbidden.")
        if member_comment_length != 0:
            raise ValueError("NPZ member comments are forbidden.")
        if member_disk_number != 0:
            raise ValueError("Multi-disk NPZ archives are forbidden.")
        if (
            compressed_size == _ZIP32_UINT32_SENTINEL
            or uncompressed_size == _ZIP32_UINT32_SENTINEL
            or local_header_offset == _ZIP32_UINT32_SENTINEL
            or version_needed >= 45
        ):
            raise ValueError("ZIP64 NPZ members are forbidden.")
        if flags & 0x0001:
            raise ValueError("Encrypted NPZ members are forbidden.")
        if flags & 0x0008:
            raise ValueError("Data-descriptor NPZ members are forbidden.")
        if flags != 0:
            raise ValueError("The NPZ member uses unsupported general-purpose flags.")
        if compression_method != zipfile.ZIP_STORED:
            raise ValueError("NPZ members must use ZIP_STORED.")
        if compressed_size != uncompressed_size:
            raise ValueError("An NPZ member's compressed and uncompressed sizes differ.")

        filename, logical_name = _safe_member_name(filename_bytes)
        if filename in observed_filenames or logical_name in observed_logical_names:
            raise ValueError("The NPZ archive contains duplicate members.")
        observed_filenames.add(filename)
        observed_logical_names.add(logical_name)

        aggregate_uncompressed_bytes += uncompressed_size
        if aggregate_uncompressed_bytes > budget:
            raise ValueError("The NPZ archive exceeds its aggregate uncompressed-byte limit.")

        local_fixed = _read_exact_at(
            handle,
            local_header_offset,
            _LOCAL_FILE_HEADER.size,
        )
        (
            local_signature,
            local_version_needed,
            local_flags,
            local_compression_method,
            local_modified_time,
            local_modified_date,
            local_crc32,
            local_compressed_size,
            local_uncompressed_size,
            local_filename_length,
            local_extra_length,
        ) = _LOCAL_FILE_HEADER.unpack(local_fixed)
        if local_signature != _LOCAL_FILE_SIGNATURE:
            raise ValueError("The NPZ archive contains an invalid local member header.")
        if local_extra_length != 0:
            raise ValueError("NPZ local member extra fields are forbidden.")
        local_filename = _read_exact_at(
            handle,
            local_header_offset + _LOCAL_FILE_HEADER.size,
            local_filename_length,
        )
        if (
            local_version_needed != version_needed
            or local_flags != flags
            or local_compression_method != compression_method
            or local_modified_time != modified_time
            or local_modified_date != modified_date
            or local_crc32 != crc32
            or local_compressed_size != compressed_size
            or local_uncompressed_size != uncompressed_size
            or local_filename_length != filename_length
            or local_filename != filename_bytes
        ):
            raise ValueError("The NPZ local and central member records do not match.")
        local_record_end = (
            local_header_offset
            + _LOCAL_FILE_HEADER.size
            + local_filename_length
            + local_extra_length
            + compressed_size
        )
        if local_record_end > central_directory_offset:
            raise ValueError("An NPZ local member record exceeds its bounded byte range.")
        members.append(
            _AdmittedMember(
                filename=filename,
                logical_name=logical_name,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                local_header_offset=local_header_offset,
                local_record_end=local_record_end,
            )
        )
        cursor = record_end

    if cursor != len(central_directory):
        raise ValueError("The NPZ central-directory byte count is not exact.")
    if observed_filenames != expected_filenames:
        raise ValueError("The NPZ member set does not match its closed catalog.")

    local_cursor = 0
    for member in sorted(members, key=lambda value: value.local_header_offset):
        if member.local_header_offset != local_cursor:
            raise ValueError("The NPZ local-member byte ranges are not exact.")
        local_cursor = member.local_record_end
    if local_cursor != central_directory_offset:
        raise ValueError("The NPZ local-member byte count is not exact.")

    return _ArchiveAdmission(
        members=tuple(members),
        aggregate_uncompressed_bytes=aggregate_uncompressed_bytes,
    )


def _numpy() -> Any:
    try:
        import numpy as np
    except ImportError as exc:  # pragma: no cover - packaging gate owns this path
        raise RuntimeError("The worker array runtime is unavailable.") from exc
    return np


def canonical_array(value: Any) -> Any:
    """Return a finite, little-endian, C-contiguous protocol array."""

    np = _numpy()
    array = np.asarray(value)
    dtype_name = array.dtype.name
    if dtype_name not in _ALLOWED_DTYPES:
        raise ValueError("Array dtype is not permitted by the worker protocol.")
    if dtype_name == "float64" and not bool(np.isfinite(array).all()):
        raise ValueError("Protocol output arrays must be finite.")
    dtype = np.dtype(dtype_name)
    if dtype.byteorder not in ("|", "<"):
        dtype = dtype.newbyteorder("<")
    return np.ascontiguousarray(array, dtype=dtype)


def array_catalog_entry(
    member_name: str,
    value: Any,
    *,
    semantic_version: str,
) -> dict[str, Any]:
    array = canonical_array(value)
    raw = array.tobytes(order="C")
    preimage = {
        "member_name": member_name,
        "dtype": array.dtype.name,
        "shape": list(array.shape),
        "semantic_version": semantic_version,
        "byte_length": len(raw),
        "array_bytes_sha256": exact_file_sha256(raw),
    }
    return {
        "member_name": member_name,
        "dtype": array.dtype.name,
        "shape": list(array.shape),
        "semantic_version": semantic_version,
        "byte_length": len(raw),
        "array_digest": structured_sha256("ebm-audit/array/1", preimage),
    }


def write_deterministic_npz(path: Path, arrays: Mapping[str, Any]) -> None:
    """Write a byte-stable ZIP_STORED NPZ using fixed member metadata."""

    np = _numpy()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as raw_file:
            with zipfile.ZipFile(raw_file, mode="w", compression=zipfile.ZIP_STORED) as archive:
                for name in sorted(arrays):
                    array = canonical_array(arrays[name])
                    buffer = BytesIO()
                    np.lib.format.write_array(buffer, array, allow_pickle=False)
                    info = zipfile.ZipInfo(f"{name}.npy", date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_STORED
                    info.create_system = 3
                    info.external_attr = 0o600 << 16
                    archive.writestr(info, buffer.getvalue())
            raw_file.flush()
            os.fsync(raw_file.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _load_admitted_npz_arrays(
    handle: BinaryIO,
    *,
    admission: _ArchiveAdmission,
) -> dict[str, Any]:
    np = _numpy()
    logical_names = [member.logical_name for member in admission.members]
    handle.seek(0)
    try:
        with np.load(handle, allow_pickle=False) as loaded:
            if loaded.files != logical_names:
                raise ValueError("The NPZ logical member list is not exact.")
            return {name: canonical_array(loaded[name]) for name in loaded.files}
    except ValueError:
        raise
    except (EOFError, OSError, zipfile.BadZipFile) as exc:
        raise ValueError("The admitted NPZ archive could not be loaded safely.") from exc


def load_npz_arrays(
    path: Path,
    *,
    expected_names: set[str],
    max_aggregate_uncompressed_bytes: int = _DEFAULT_MAX_AGGREGATE_UNCOMPRESSED_BYTES,
) -> dict[str, Any]:
    """Load a raw-admitted NPZ with pickle disabled and a closed member set."""

    try:
        with path.open("rb") as handle:
            admission = _admit_npz_archive(
                handle,
                expected_names=expected_names,
                max_aggregate_uncompressed_bytes=max_aggregate_uncompressed_bytes,
            )
            return _load_admitted_npz_arrays(handle, admission=admission)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("The NPZ archive is not a readable ZIP file.") from exc


def _load_catalogued_npz_arrays_handle(
    raw_handle: BinaryIO,
    *,
    catalog: Mapping[str, Any],
    max_aggregate_uncompressed_bytes: int = _DEFAULT_MAX_AGGREGATE_UNCOMPRESSED_BYTES,
) -> dict[str, Any]:
    if any(
        not isinstance(name, str) or not isinstance(entry, Mapping)
        for name, entry in catalog.items()
    ):
        raise ValueError("The array catalog is not a string-keyed object catalog.")
    try:
        admission = _admit_npz_archive(
            raw_handle,
            expected_names=set(catalog),
            max_aggregate_uncompressed_bytes=max_aggregate_uncompressed_bytes,
        )
        np = _numpy()
        raw_handle.seek(0)
        with zipfile.ZipFile(raw_handle, mode="r") as archive:
            members = {
                member.filename.removesuffix(".npy"): member for member in archive.infolist()
            }
            if list(members) != [member.logical_name for member in admission.members]:
                raise ValueError("The NPZ logical member list is not exact.")
            for name, declared in catalog.items():
                member = members.get(name)
                byte_length = declared.get("byte_length")
                shape = declared.get("shape")
                dtype_name = declared.get("dtype")
                if (
                    member is None
                    or isinstance(byte_length, bool)
                    or not isinstance(byte_length, int)
                    or byte_length < 0
                    or not isinstance(shape, list)
                    or any(
                        isinstance(size, bool) or not isinstance(size, int) or size < 0
                        for size in shape
                    )
                    or not isinstance(dtype_name, str)
                ):
                    raise ValueError("An array catalog entry has invalid bounds.")
                if member.file_size > byte_length + _MAX_NPY_HEADER_BYTES:
                    raise ValueError("An NPZ member exceeds its declared expansion bound.")
                with archive.open(member, mode="r") as member_handle:
                    version = np.lib.format.read_magic(member_handle)
                    if version == (1, 0):
                        observed_shape, fortran_order, observed_dtype = (
                            np.lib.format.read_array_header_1_0(
                                member_handle,
                                max_header_size=_MAX_NPY_HEADER_BYTES,
                            )
                        )
                    elif version == (2, 0):
                        observed_shape, fortran_order, observed_dtype = (
                            np.lib.format.read_array_header_2_0(
                                member_handle,
                                max_header_size=_MAX_NPY_HEADER_BYTES,
                            )
                        )
                    else:
                        raise ValueError("The NPZ member uses an unsupported NPY version.")
                    header_length = member_handle.tell()
                observed_raw_length = prod(observed_shape) * observed_dtype.itemsize
                if (
                    fortran_order
                    or list(observed_shape) != shape
                    or observed_dtype.name != dtype_name
                    or observed_raw_length != byte_length
                    or member.file_size != header_length + byte_length
                ):
                    raise ValueError("An NPZ member exceeds or contradicts its declared bounds.")
        arrays = _load_admitted_npz_arrays(raw_handle, admission=admission)
    except ValueError:
        raise
    except (EOFError, OSError, zipfile.BadZipFile) as exc:
        raise ValueError("The NPZ member header could not be validated safely.") from exc
    for name, declared in catalog.items():
        semantic_version = declared.get("semantic_version")
        if not isinstance(semantic_version, str):
            raise ValueError("An array catalog entry has no semantic version.")
        observed = array_catalog_entry(
            name,
            arrays[name],
            semantic_version=semantic_version,
        )
        if observed != dict(declared):
            raise ValueError("An array does not match its closed catalog entry.")
    return arrays


def load_catalogued_npz_arrays(
    path: Path,
    *,
    catalog: Mapping[str, Any],
    max_aggregate_uncompressed_bytes: int = _DEFAULT_MAX_AGGREGATE_UNCOMPRESSED_BYTES,
) -> dict[str, Any]:
    """Load an NPZ and recompute every closed catalog entry from exact arrays."""

    try:
        with path.open("rb") as raw_handle:
            return _load_catalogued_npz_arrays_handle(
                raw_handle,
                catalog=catalog,
                max_aggregate_uncompressed_bytes=max_aggregate_uncompressed_bytes,
            )
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("The NPZ archive is not a readable ZIP file.") from exc


def load_catalogued_npz_array_bytes(
    data: bytes,
    *,
    catalog: Mapping[str, Any],
    max_aggregate_uncompressed_bytes: int = _DEFAULT_MAX_AGGREGATE_UNCOMPRESSED_BYTES,
) -> dict[str, Any]:
    """Load catalogued arrays from one already-retained immutable archive."""

    if not isinstance(data, bytes):
        raise TypeError("Retained NPZ input must be exact bytes.")
    return _load_catalogued_npz_arrays_handle(
        BytesIO(data),
        catalog=catalog,
        max_aggregate_uncompressed_bytes=max_aggregate_uncompressed_bytes,
    )
