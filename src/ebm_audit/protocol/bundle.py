"""Closed bundle inventories and immutable exact-byte snapshots."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO

from .errors import BundleValidationError
from .models import BundleSnapshot, FileRecord
from .paths import PathLike, ensure_private_directory, validate_relative_posix_path

_STREAM_CHUNK_BYTES = 1024 * 1024


def _utf8_path_key(value: str) -> bytes:
    return value.encode("utf-8", errors="strict")


def _validate_private_file_mode(mode: int) -> None:
    permissions = stat.S_IMODE(mode)
    if permissions & ~0o600 or not permissions & 0o400:
        raise BundleValidationError("Bundle files must use readable mode 0600 or stricter.")


def _validate_max_bytes(max_bytes: int | None) -> None:
    if max_bytes is None:
        return
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a nonnegative integer or None")


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


@contextmanager
def _open_regular_file_exact(
    path: PathLike,
    *,
    max_bytes: int | None,
) -> Iterator[tuple[BinaryIO, int]]:
    """Open a stable private regular file and recheck it after consumption."""

    _validate_max_bytes(max_bytes)
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as exc:
        raise BundleValidationError("Bundle file is unavailable.") from exc
    if not stat.S_ISREG(before.st_mode):
        raise BundleValidationError("Bundle entry must be a regular file.")
    _validate_private_file_mode(before.st_mode)
    if max_bytes is not None and before.st_size > max_bytes:
        raise BundleValidationError("Bundle file exceeds the allowed byte limit.")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise BundleValidationError("Bundle file could not be opened safely.") from exc
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise BundleValidationError("Bundle entry must be a regular file.")
            _validate_private_file_mode(opened.st_mode)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise BundleValidationError("Bundle file identity changed during open.")
            if _file_identity(opened) != _file_identity(before):
                raise BundleValidationError("Bundle file changed while being opened.")
            if max_bytes is not None and opened.st_size > max_bytes:
                raise BundleValidationError("Bundle file exceeds the allowed byte limit.")
            yield handle, before.st_size
            after_read = os.fstat(handle.fileno())
            _validate_private_file_mode(after_read.st_mode)
    except Exception:
        # fdopen owns the descriptor after successful construction. If it failed
        # before ownership, close defensively without exposing the path.
        with suppress(OSError):
            os.close(descriptor)
        raise

    try:
        after = candidate.lstat()
    except OSError as exc:
        raise BundleValidationError("Bundle file changed after reading.") from exc
    if not stat.S_ISREG(after.st_mode):
        raise BundleValidationError("Bundle entry must remain a regular file.")
    _validate_private_file_mode(after.st_mode)
    identity_before = _file_identity(before)
    if identity_before != _file_identity(after_read) or identity_before != _file_identity(after):
        raise BundleValidationError("Bundle file changed while being read.")


def _consume_regular_file_exact(
    path: PathLike,
    *,
    max_bytes: int | None,
    consume: Callable[[bytes], None],
) -> int:
    total = 0
    with _open_regular_file_exact(path, max_bytes=max_bytes) as (handle, expected_size):
        while True:
            chunk = handle.read(_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise BundleValidationError("Bundle file exceeds the allowed byte limit.")
            consume(chunk)
        if total != expected_size:
            raise BundleValidationError("Bundle file byte length changed while being read.")
    return total


def read_regular_file_exact(path: PathLike, *, max_bytes: int | None = None) -> bytes:
    """Read one regular file exactly, optionally enforcing a pre-allocation cap."""

    chunks: list[bytes] = []
    _consume_regular_file_exact(path, max_bytes=max_bytes, consume=chunks.append)
    return b"".join(chunks)


def exact_file_sha256_path(path: PathLike) -> str:
    """Stream-hash one safely opened exact regular file."""

    digest = sha256()
    _consume_regular_file_exact(path, max_bytes=None, consume=digest.update)
    return f"sha256:{digest.hexdigest()}"


def _file_record_exact(path: PathLike) -> FileRecord:
    digest = sha256()
    byte_length = _consume_regular_file_exact(path, max_bytes=None, consume=digest.update)
    return FileRecord(byte_length=byte_length, sha256=f"sha256:{digest.hexdigest()}")


def _walk_regular_files(root: Path) -> tuple[tuple[str, Path], ...]:
    entries: list[tuple[str, Path]] = []

    def visit(directory: Path, prefix: tuple[str, ...]) -> None:
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name.encode("utf-8"))
        except (OSError, UnicodeEncodeError) as exc:
            raise BundleValidationError("Bundle directory cannot be inventoried safely.") from exc
        for child in children:
            relative = "/".join((*prefix, child.name))
            validate_relative_posix_path(relative)
            try:
                child_stat = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise BundleValidationError("Bundle entry cannot be inspected.") from exc
            if stat.S_ISLNK(child_stat.st_mode):
                raise BundleValidationError("Bundle symlinks are forbidden.")
            if stat.S_ISDIR(child_stat.st_mode):
                if stat.S_IMODE(child_stat.st_mode) != 0o700:
                    raise BundleValidationError("Bundle directories must use mode 0700.")
                visit(Path(child.path), (*prefix, child.name))
            elif stat.S_ISREG(child_stat.st_mode):
                _validate_private_file_mode(child_stat.st_mode)
                entries.append((relative, Path(child.path)))
            else:
                raise BundleValidationError("Bundle contains a non-regular entry.")

    visit(root, ())
    entries.sort(key=lambda item: _utf8_path_key(item[0]))
    return tuple(entries)


def capture_bundle_snapshot(
    root: PathLike,
    *,
    excluded_paths: frozenset[str] = frozenset(),
) -> BundleSnapshot:
    """Capture an exact closed file snapshot and recheck its physical set."""

    base = ensure_private_directory(root)
    for excluded in excluded_paths:
        validate_relative_posix_path(excluded)
    first_listing = _walk_regular_files(base)
    records: list[tuple[str, FileRecord]] = []
    for relative, path in first_listing:
        if relative in excluded_paths:
            continue
        records.append((relative, _file_record_exact(path)))
    second_listing = _walk_regular_files(base)
    if tuple(relative for relative, _path in first_listing) != tuple(
        relative for relative, _path in second_listing
    ):
        raise BundleValidationError("Bundle file set changed during inventory.")
    return BundleSnapshot(tuple(records))


def build_files_map(root: PathLike, *, metadata_name: str) -> dict[str, dict[str, object]]:
    """Build the closed files map, excluding exactly its metadata file."""

    validate_relative_posix_path(metadata_name)
    snapshot = capture_bundle_snapshot(root, excluded_paths=frozenset({metadata_name}))
    return {path: record.to_mapping() for path, record in snapshot.entries}


def _expected_file_records(files: object, metadata_name: str) -> BundleSnapshot:
    if not isinstance(files, Mapping):
        raise BundleValidationError("Bundle files map must be an object.")
    records: list[tuple[str, FileRecord]] = []
    for raw_path, raw_record in files.items():
        if not isinstance(raw_path, str):
            raise BundleValidationError("Bundle files map keys must be strings.")
        path = validate_relative_posix_path(raw_path)
        if path == metadata_name:
            raise BundleValidationError("Metadata file must not list itself.")
        try:
            record = FileRecord.from_mapping(raw_record)
        except (TypeError, ValueError) as exc:
            raise BundleValidationError("Bundle file record is invalid.") from exc
        records.append((path, record))
    records.sort(key=lambda item: _utf8_path_key(item[0]))
    return BundleSnapshot(tuple(records))


def verify_files_map(
    root: PathLike,
    files: object,
    *,
    metadata_name: str,
) -> BundleSnapshot:
    """Require exact equality between the declared and physical regular files."""

    expected = _expected_file_records(files, metadata_name)
    observed = capture_bundle_snapshot(root, excluded_paths=frozenset({metadata_name}))
    if observed != expected:
        raise BundleValidationError("Bundle file set, byte length, or digest does not match.")
    return capture_bundle_snapshot(root)


def verify_snapshot_unchanged(root: PathLike, snapshot: BundleSnapshot) -> None:
    """Fail if any snapshotted byte or physical entry has changed."""

    observed = capture_bundle_snapshot(root)
    if observed != snapshot:
        raise BundleValidationError("Immutable bundle bytes changed after validation.")
