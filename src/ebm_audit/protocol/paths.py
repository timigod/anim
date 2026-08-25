"""Normalized relative paths and symlink-safe containment checks."""

from __future__ import annotations

import os
import stat
import unicodedata
from pathlib import Path

from .errors import PathBoundaryError

type PathLike = str | os.PathLike[str]


def validate_relative_posix_path(value: str) -> str:
    """Validate and return one already-normalized relative POSIX path."""

    if not isinstance(value, str) or not value:
        raise PathBoundaryError("Bundle path must be a non-empty string.")
    if not unicodedata.is_normalized("NFC", value):
        raise PathBoundaryError("Bundle path must already be Unicode NFC.")
    if "\x00" in value or "\\" in value or value.startswith("/"):
        raise PathBoundaryError("Bundle path is not a relative POSIX path.")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise PathBoundaryError("Bundle path is not normalized.")
    return value


def _validate_root(root: PathLike) -> Path:
    path = Path(root)
    if not path.is_absolute():
        raise PathBoundaryError("Assigned bundle root must be absolute.")
    try:
        root_stat = path.lstat()
    except OSError as exc:
        raise PathBoundaryError("Assigned bundle root is unavailable.") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise PathBoundaryError("Assigned bundle root must be a real directory.")
    if stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise PathBoundaryError("Assigned bundle directory must use mode 0700.")
    return path


def resolve_contained_path(
    root: PathLike,
    relative_path: str,
    *,
    require_exists: bool = True,
) -> Path:
    """Resolve a normalized path while rejecting every symlink component."""

    base = _validate_root(root)
    normalized = validate_relative_posix_path(relative_path)
    candidate = base
    components = normalized.split("/")
    for index, component in enumerate(components):
        candidate = candidate / component
        is_last = index == len(components) - 1
        try:
            component_stat = candidate.lstat()
        except FileNotFoundError:
            if require_exists or not is_last:
                raise PathBoundaryError("Contained path does not exist.") from None
            continue
        except OSError as exc:
            raise PathBoundaryError("Contained path cannot be inspected.") from exc
        if stat.S_ISLNK(component_stat.st_mode):
            raise PathBoundaryError("Symlinks are forbidden in bundle paths.")
        if not is_last and not stat.S_ISDIR(component_stat.st_mode):
            raise PathBoundaryError("Intermediate bundle path is not a directory.")
    return candidate


def ensure_private_directory(root: PathLike) -> Path:
    """Validate an existing absolute mode-0700 directory."""

    return _validate_root(root)
