"""Create the installed package's deterministic local adapter starter."""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from contextlib import suppress
from importlib import resources
from pathlib import Path

from ebm_audit.artifacts.store import (
    _create_child_directory,
    _open_directory_chain,
    _verify_current_directory_path,
)
from ebm_audit.artifacts.transaction import _atomic_rename_noreplace
from ebm_audit.errors import InvalidInputError

_SCAFFOLD_SCHEMA_VERSION = "ebm-audit-adapter-scaffold/1.0"
_TEMPLATE_FILES = (
    "README.md",
    "pyproject.toml",
    "synthetic_example.py",
    "tests/test_worker.py",
    "worker.py",
    "worker.yaml",
)
_EXECUTABLE_FILES = frozenset({"worker.py"})
_DIRECTORY_FLAGS = os.O_RDONLY
if hasattr(os, "O_DIRECTORY"):
    _DIRECTORY_FLAGS |= os.O_DIRECTORY
if hasattr(os, "O_NOFOLLOW"):
    _DIRECTORY_FLAGS |= os.O_NOFOLLOW


def _unsafe_path() -> InvalidInputError:
    return InvalidInputError(
        "SPEC.ADAPTER_SCAFFOLD_UNSAFE_PATH",
        "The adapter project path is not a safe writable directory.",
    )


def _occupied_path() -> InvalidInputError:
    return InvalidInputError(
        "SPEC.ADAPTER_SCAFFOLD_NOT_EMPTY",
        "The adapter project directory contains files that this command will not overwrite.",
    )


def _absolute_path(path: Path) -> Path:
    try:
        return Path(os.path.abspath(path))
    except (OSError, ValueError):
        raise _unsafe_path() from None


def _rendered_files(destination: Path) -> dict[str, bytes]:
    template_root = resources.files("ebm_audit.adapter_scaffold").joinpath("templates")
    replacements = {
        b"{{PYTHON_EXECUTABLE}}": json.dumps(str(Path(sys.executable).absolute())).encode(),
        b"{{WORKER_PATH}}": json.dumps(str(destination / "worker.py")).encode(),
    }
    rendered: dict[str, bytes] = {}
    for relative_name in _TEMPLATE_FILES:
        content = template_root.joinpath(*relative_name.split("/")).read_bytes()
        for marker, value in replacements.items():
            content = content.replace(marker, value)
        if b"{{" in content or b"}}" in content:
            raise RuntimeError("An adapter scaffold template contains an unknown marker.")
        rendered[relative_name] = content
    return rendered


def _expected_directories() -> set[str]:
    directories: set[str] = set()
    for relative_name in _TEMPLATE_FILES:
        parent = Path(relative_name).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _open_child_directory(parent_fd: int, name: str) -> int:
    try:
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError:
        raise _unsafe_path() from None


def _directory_entries(directory_fd: int) -> dict[str, os.DirEntry[str]]:
    try:
        return {entry.name: entry for entry in os.scandir(directory_fd)}
    except OSError:
        raise _unsafe_path() from None


def _read_exact_file(directory_fd: int, name: str, expected: bytes) -> bool:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        raise _unsafe_path() from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != len(expected):
            return False
        content = b""
        while len(content) <= len(expected):
            chunk = os.read(descriptor, len(expected) + 1 - len(content))
            if not chunk:
                break
            content += chunk
        after = os.fstat(descriptor)
        identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
            raise _unsafe_path()
        return content == expected
    except OSError:
        raise _unsafe_path() from None
    finally:
        os.close(descriptor)


def _is_exact_scaffold(destination_fd: int, rendered: dict[str, bytes]) -> bool:
    expected_root_files = {name for name in _TEMPLATE_FILES if "/" not in name}
    expected_root_directories = {name for name in _expected_directories() if "/" not in name}
    root_entries = _directory_entries(destination_fd)
    if set(root_entries) != expected_root_files | expected_root_directories:
        return False
    if any(
        entry.is_symlink()
        or (name in expected_root_files and not entry.is_file(follow_symlinks=False))
        or (name in expected_root_directories and not entry.is_dir(follow_symlinks=False))
        for name, entry in root_entries.items()
    ):
        raise _unsafe_path()
    if any(
        not _read_exact_file(destination_fd, name, rendered[name]) for name in expected_root_files
    ):
        return False

    for directory_name in sorted(expected_root_directories):
        directory_fd = _open_child_directory(destination_fd, directory_name)
        try:
            expected_files = {
                name.removeprefix(f"{directory_name}/")
                for name in _TEMPLATE_FILES
                if name.startswith(f"{directory_name}/") and name.count("/") == 1
            }
            entries = _directory_entries(directory_fd)
            if set(entries) != expected_files:
                return False
            if any(
                entry.is_symlink() or not entry.is_file(follow_symlinks=False)
                for entry in entries.values()
            ):
                raise _unsafe_path()
            if any(
                not _read_exact_file(
                    directory_fd,
                    name,
                    rendered[f"{directory_name}/{name}"],
                )
                for name in expected_files
            ):
                return False
        finally:
            os.close(directory_fd)
    return True


def _write_staged_file(root_fd: int, relative_name: str, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(relative_name, flags, 0o600, dir_fd=root_fd)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if relative_name in _EXECUTABLE_FILES:
            os.chmod(relative_name, 0o700, dir_fd=root_fd, follow_symlinks=False)
    except OSError:
        raise _unsafe_path() from None


def _remove_staging(parent_fd: int, staging_name: str, staging_fd: int) -> None:
    for relative_name in reversed(_TEMPLATE_FILES):
        with suppress(OSError):
            os.unlink(relative_name, dir_fd=staging_fd)
    for relative_directory in sorted(_expected_directories(), reverse=True):
        with suppress(OSError):
            os.rmdir(relative_directory, dir_fd=staging_fd)
    with suppress(OSError):
        os.rmdir(staging_name, dir_fd=parent_fd)


def _create_staging(parent_fd: int, destination_name: str) -> tuple[str, int]:
    for _attempt in range(8):
        staging_name = f".{destination_name}.ebm-audit-{secrets.token_hex(8)}"
        try:
            staging_fd, _identity = _create_child_directory(parent_fd, staging_name)
            return staging_name, staging_fd
        except FileExistsError:
            continue
        except InvalidInputError:
            raise _unsafe_path() from None
        except OSError:
            raise _unsafe_path() from None
    raise _unsafe_path()


def _existing_destination(parent_fd: int, destination_name: str) -> int | None:
    try:
        observed = os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise _unsafe_path() from None
    if not stat.S_ISDIR(observed.st_mode):
        raise _unsafe_path()
    return _open_child_directory(parent_fd, destination_name)


def _validate_parent_directory(parent_fd: int) -> None:
    try:
        observed = os.fstat(parent_fd)
    except OSError:
        raise _unsafe_path() from None
    owner_matches = not hasattr(os, "geteuid") or observed.st_uid == os.geteuid()
    if not stat.S_ISDIR(observed.st_mode) or not owner_matches or observed.st_mode & 0o022:
        raise _unsafe_path()


def initialize_adapter_scaffold(destination: Path) -> dict[str, object]:
    """Atomically create or recognize one exact scaffold without replacing entries."""

    absolute_destination = _absolute_path(destination)
    if absolute_destination == Path(absolute_destination.anchor) or not absolute_destination.name:
        raise _unsafe_path()
    rendered = _rendered_files(absolute_destination)
    parent = absolute_destination.parent
    try:
        parent_fd = _open_directory_chain(parent, create=True)
        _validate_parent_directory(parent_fd)
        _verify_current_directory_path(parent, parent_fd)
    except InvalidInputError:
        raise _unsafe_path() from None

    try:
        destination_fd = _existing_destination(parent_fd, absolute_destination.name)
        if destination_fd is not None:
            try:
                if not _is_exact_scaffold(destination_fd, rendered):
                    raise _occupied_path()
                try:
                    _verify_current_directory_path(absolute_destination, destination_fd)
                except InvalidInputError:
                    raise _unsafe_path() from None
            finally:
                os.close(destination_fd)
            return {
                "adapter_scaffold_schema_version": _SCAFFOLD_SCHEMA_VERSION,
                "files": list(_TEMPLATE_FILES),
                "status": "UNCHANGED",
            }

        staging_name, staging_fd = _create_staging(parent_fd, absolute_destination.name)
        installed = False
        try:
            for relative_directory in sorted(_expected_directories()):
                os.mkdir(relative_directory, 0o700, dir_fd=staging_fd)
            for relative_name in _TEMPLATE_FILES:
                _write_staged_file(staging_fd, relative_name, rendered[relative_name])
            os.fsync(staging_fd)
            _verify_current_directory_path(parent, parent_fd)
            raced_destination_fd = _existing_destination(parent_fd, absolute_destination.name)
            if raced_destination_fd is not None:
                os.close(raced_destination_fd)
                raise _occupied_path()
            try:
                _atomic_rename_noreplace(
                    parent_fd,
                    staging_name,
                    absolute_destination.name,
                )
            except InvalidInputError as exc:
                if exc.code == "SPEC.OUTPUT_PUBLICATION_CONFLICT":
                    raise _occupied_path() from None
                raise _unsafe_path() from None
            installed = True
            os.fsync(parent_fd)
            _verify_current_directory_path(parent, parent_fd)
        except InvalidInputError:
            raise
        except OSError:
            raise _unsafe_path() from None
        finally:
            if not installed:
                _remove_staging(parent_fd, staging_name, staging_fd)
            os.close(staging_fd)
    finally:
        os.close(parent_fd)
    return {
        "adapter_scaffold_schema_version": _SCAFFOLD_SCHEMA_VERSION,
        "files": list(_TEMPLATE_FILES),
        "status": "CREATED",
    }
