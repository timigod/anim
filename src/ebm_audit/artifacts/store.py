"""Directory-fd-anchored private artifact creation with closed relative paths."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import re
import stat
import unicodedata
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ebm_audit._profile_storage_boundary import _observe_profile_storage_operation
from ebm_audit.errors import InvalidInputError

_DIRECTORY_OPEN_FLAGS = os.O_RDONLY
_STORE_CONSTRUCTION_TOKEN = object()
_RUN_ROOT_KEY_NAME = ".ebm-audit-run-root.key"
_RUN_ROOT_MARKER_NAME = ".ebm-audit-run-root.json"
_RUN_ROOT_DOMAIN = b"ebm-audit/private-run-root/1\x00"
_RUN_ROOT_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ROOT_AUTH_PATTERN = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_DEFAULT_MAXIMUM_ARTIFACT_BYTES = 64 * 1024 * 1024
_STORE_ATTACHMENT_MODES = frozenset({"CREATED_FRESH", "ATTACHED_EXISTING"})
_INVENTORY_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
if hasattr(os, "O_DIRECTORY"):
    _DIRECTORY_OPEN_FLAGS |= os.O_DIRECTORY
if hasattr(os, "O_NOFOLLOW"):
    _DIRECTORY_OPEN_FLAGS |= os.O_NOFOLLOW


def _profile_storage_resource(relative: PurePosixPath) -> str | None:
    if not relative.parts:
        return None
    namespace = relative.parts[0]
    if namespace == "cache":
        return "CACHE"
    if namespace in {"checkpoint", "checkpoints"}:
        return "CHECKPOINT"
    return None


def _observe_profile_store_path(relative: PurePosixPath, *, operation: str) -> None:
    resource = _profile_storage_resource(relative)
    if resource is not None:
        _observe_profile_storage_operation(
            resource=resource,
            operation=operation,
        )


def _directory_error(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _absolute_parts(path: Path) -> tuple[str, ...]:
    absolute = path.absolute()
    if not absolute.is_absolute() or not absolute.parts or absolute.parts[0] != os.sep:
        raise _directory_error(
            "SPEC.OUTPUT_DIRECTORY",
            "The private output directory path is invalid.",
        )
    if any(
        part in {"", ".", ".."} or "\x00" in part or not unicodedata.is_normalized("NFC", part)
        for part in absolute.parts[1:]
    ):
        raise _directory_error(
            "SPEC.OUTPUT_DIRECTORY",
            "The private output directory path is invalid.",
        )
    return tuple(absolute.parts[1:])


def _remove_directory_if_identity(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
) -> bool:
    """Remove one empty directory only while its exact entry identity remains."""

    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (observed.st_dev, observed.st_ino) != identity or not stat.S_ISDIR(observed.st_mode):
            return False
        os.rmdir(name, dir_fd=parent_fd)
        return True
    except OSError:
        return False


def _create_child_directory(parent_fd: int, name: str) -> tuple[int, tuple[int, int]]:
    """Create/open one child and roll it back on every post-mkdir failure."""

    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    created = False
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created = True
        try:
            descriptor = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino)
        except OSError:
            with suppress(OSError):
                observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                identity = (observed.st_dev, observed.st_ino)
            raise
        os.fchmod(descriptor, 0o700)
        _validate_private_directory_descriptor(descriptor)
        os.fsync(parent_fd)
        return descriptor, identity
    except BaseException:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if created and identity is not None:
            changed = _remove_directory_if_identity(parent_fd, name, identity)
            if changed:
                with suppress(OSError):
                    os.fsync(parent_fd)
        raise


def _open_directory_chain(path: Path, *, create: bool) -> int:
    """Open one absolute directory without following any component symlink."""

    try:
        current_fd = os.open(os.sep, _DIRECTORY_OPEN_FLAGS)
    except OSError:
        raise _directory_error(
            "SPEC.OUTPUT_DIRECTORY",
            "The private output directory could not be opened.",
        ) from None
    created_entries: list[tuple[int, str, tuple[int, int]]] = []
    try:
        for part in _absolute_parts(path):
            try:
                next_fd = os.open(part, _DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                rollback_parent_fd: int | None = None
                try:
                    rollback_parent_fd = os.dup(current_fd)
                    next_fd, identity = _create_child_directory(current_fd, part)
                    created_entries.append((rollback_parent_fd, part, identity))
                    rollback_parent_fd = None
                except OSError:
                    raise _directory_error(
                        "SPEC.OUTPUT_DIRECTORY",
                        "The private output directory could not be created.",
                    ) from None
                finally:
                    if rollback_parent_fd is not None:
                        os.close(rollback_parent_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise _directory_error(
                        "SPEC.OUTPUT_SYMLINK",
                        "Output paths must not contain symbolic links.",
                    ) from None
                raise _directory_error(
                    "SPEC.OUTPUT_DIRECTORY",
                    "The private output directory could not be opened.",
                ) from None
            os.close(current_fd)
            current_fd = next_fd
        for parent_fd, _name, _identity in created_entries:
            os.close(parent_fd)
        return current_fd
    except BaseException:
        with suppress(OSError):
            os.close(current_fd)
        for parent_fd, name, identity in reversed(created_entries):
            changed = _remove_directory_if_identity(parent_fd, name, identity)
            if changed:
                with suppress(OSError):
                    os.fsync(parent_fd)
            os.close(parent_fd)
        raise


def _same_directory(first_fd: int, second_fd: int) -> bool:
    first = os.fstat(first_fd)
    second = os.fstat(second_fd)
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _validate_private_directory_descriptor(descriptor: int) -> None:
    observed = os.fstat(descriptor)
    if not stat.S_ISDIR(observed.st_mode):
        raise _directory_error(
            "SPEC.OUTPUT_DIRECTORY",
            "The private output path is not a directory.",
        )
    if stat.S_IMODE(observed.st_mode) != 0o700:
        raise _directory_error(
            "SPEC.OUTPUT_DIRECTORY_MODE",
            "The output directory must have exact mode 0700 with no special bits.",
        )
    if hasattr(os, "geteuid") and observed.st_uid != os.geteuid():
        raise _directory_error(
            "SPEC.OUTPUT_DIRECTORY_OWNER",
            "The output directory must be owned by the current user.",
        )


def _marker_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _read_private_regular_file_at(
    directory_fd: int,
    name: str,
    *,
    maximum_bytes: int,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        raise _directory_error(
            "SPEC.RUN_ROOT_AUTHENTICATION",
            "The private run-root authentication files are unavailable.",
        ) from None
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_nlink != 1
            or observed.st_size < 1
            or observed.st_size > maximum_bytes
            or (hasattr(os, "geteuid") and observed.st_uid != os.geteuid())
        ):
            raise _directory_error(
                "SPEC.RUN_ROOT_AUTHENTICATION",
                "The private run-root authentication files are invalid.",
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != observed.st_size or len(content) > maximum_bytes:
            raise _directory_error(
                "SPEC.RUN_ROOT_AUTHENTICATION",
                "The private run-root authentication files are invalid.",
            )
        return content
    finally:
        os.close(descriptor)


def _run_root_marker(
    *,
    key: bytes,
    device: int,
    inode: int,
    owner_uid: int,
) -> tuple[dict[str, object], bytes]:
    run_root_id = "sha256:" + hashlib.sha256(_RUN_ROOT_DOMAIN + key).hexdigest()
    body: dict[str, object] = {
        "marker_schema_version": "ebm-audit-private-run-root/1.0",
        "run_root_id": run_root_id,
        "device": device,
        "inode": inode,
        "owner_uid": owner_uid,
    }
    authentication = (
        "hmac-sha256:"
        + hmac.new(
            key,
            _RUN_ROOT_DOMAIN + _marker_bytes(body),
            hashlib.sha256,
        ).hexdigest()
    )
    marker = {**body, "authentication": authentication}
    return marker, _marker_bytes(marker)


def _parse_marker_bytes(content: bytes) -> dict[str, object]:
    if content.startswith(b"\xef\xbb\xbf"):
        raise _directory_error(
            "SPEC.RUN_ROOT_AUTHENTICATION",
            "The private run-root authentication marker is invalid.",
        )

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _directory_error(
            "SPEC.RUN_ROOT_AUTHENTICATION",
            "The private run-root authentication marker is invalid.",
        ) from None
    if not isinstance(value, dict):
        raise _directory_error(
            "SPEC.RUN_ROOT_AUTHENTICATION",
            "The private run-root authentication marker is invalid.",
        )
    return value


def _verify_run_root_authentication(
    root_fd: int,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> str:
    observed = os.fstat(root_fd)
    identity = (observed.st_dev, observed.st_ino)
    if expected_identity is not None and identity != expected_identity:
        raise _directory_error(
            "SPEC.OUTPUT_PATH_CHANGED",
            "The private run root changed after it was created.",
        )
    key = _read_private_regular_file_at(
        root_fd,
        _RUN_ROOT_KEY_NAME,
        maximum_bytes=32,
    )
    if len(key) != 32:
        raise _directory_error(
            "SPEC.RUN_ROOT_AUTHENTICATION",
            "The private run-root authentication key is invalid.",
        )
    marker_content = _read_private_regular_file_at(
        root_fd,
        _RUN_ROOT_MARKER_NAME,
        maximum_bytes=4096,
    )
    marker = _parse_marker_bytes(marker_content)
    expected_keys = {
        "marker_schema_version",
        "run_root_id",
        "device",
        "inode",
        "owner_uid",
        "authentication",
    }
    run_root_id = marker.get("run_root_id")
    authentication = marker.get("authentication")
    owner_uid = os.geteuid() if hasattr(os, "geteuid") else observed.st_uid
    if (
        set(marker) != expected_keys
        or marker.get("marker_schema_version") != "ebm-audit-private-run-root/1.0"
        or not isinstance(run_root_id, str)
        or _RUN_ROOT_ID_PATTERN.fullmatch(run_root_id) is None
        or not isinstance(authentication, str)
        or _RUN_ROOT_AUTH_PATTERN.fullmatch(authentication) is None
        or isinstance(marker.get("device"), bool)
        or not isinstance(marker.get("device"), int)
        or isinstance(marker.get("inode"), bool)
        or not isinstance(marker.get("inode"), int)
        or isinstance(marker.get("owner_uid"), bool)
        or not isinstance(marker.get("owner_uid"), int)
        or marker["device"] != observed.st_dev
        or marker["inode"] != observed.st_ino
        or marker["owner_uid"] != owner_uid
    ):
        raise _directory_error(
            "SPEC.RUN_ROOT_AUTHENTICATION",
            "The private run-root authentication marker is invalid.",
        )
    body = {key_name: marker[key_name] for key_name in expected_keys - {"authentication"}}
    expected_marker, expected_content = _run_root_marker(
        key=key,
        device=observed.st_dev,
        inode=observed.st_ino,
        owner_uid=owner_uid,
    )
    if (
        body != {key_name: expected_marker[key_name] for key_name in body}
        or not hmac.compare_digest(authentication, str(expected_marker["authentication"]))
        or marker_content != expected_content
    ):
        raise _directory_error(
            "SPEC.RUN_ROOT_AUTHENTICATION",
            "The private run-root authentication marker is invalid.",
        )
    return run_root_id


def _verify_current_directory_path(path: Path, expected_fd: int) -> None:
    try:
        observed_fd = _open_directory_chain(path, create=False)
    except FileNotFoundError:
        raise _directory_error(
            "SPEC.OUTPUT_PATH_CHANGED",
            "The private output path changed during artifact creation.",
        ) from None
    try:
        if not _same_directory(observed_fd, expected_fd):
            raise _directory_error(
                "SPEC.OUTPUT_PATH_CHANGED",
                "The private output path changed during artifact creation.",
            )
    finally:
        os.close(observed_fd)


def ensure_private_directory(path: Path) -> None:
    """Create or validate one local directory with exact mode ``0700``."""

    descriptor = _open_directory_chain(path, create=True)
    try:
        _validate_private_directory_descriptor(descriptor)
        _verify_current_directory_path(path, descriptor)
    finally:
        os.close(descriptor)


def _create_private_directory_exclusive(path: Path) -> tuple[int, int]:
    """Create one fresh private directory without accepting a stale run root."""

    absolute = path.absolute()
    name = _validate_file_name(absolute)
    parent = absolute.parent
    try:
        parent_fd = _open_directory_chain(parent, create=False)
    except FileNotFoundError:
        raise _directory_error(
            "SPEC.OUTPUT_DIRECTORY",
            "The parent of the private run directory does not exist.",
        ) from None
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    complete = False
    try:
        try:
            descriptor, created_identity = _create_child_directory(parent_fd, name)
            _verify_current_directory_path(absolute, descriptor)
            complete = True
        except FileExistsError:
            raise _directory_error(
                "SPEC.OUTPUT_ALREADY_EXISTS",
                "The private run directory already exists; a fresh root is required.",
            ) from None
        except InvalidInputError:
            raise
        except OSError:
            raise _directory_error(
                "SPEC.OUTPUT_DIRECTORY",
                "The fresh private run directory could not be created.",
            ) from None
    finally:
        if not complete and created_identity is not None:
            changed = _remove_directory_if_identity(parent_fd, name, created_identity)
            if changed:
                with suppress(OSError):
                    os.fsync(parent_fd)
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
    assert created_identity is not None
    return created_identity


def _validate_file_name(path: Path) -> str:
    name = path.name
    if (
        not name
        or name in {".", ".."}
        or "\x00" in name
        or not unicodedata.is_normalized("NFC", name)
        or os.sep in name
        or (os.altsep and os.altsep in name)
    ):
        raise InvalidInputError(
            "SPEC.OUTPUT_RELATIVE_PATH",
            "The private output artifact name is invalid.",
        )
    return name


def _path_exists_at(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        raise InvalidInputError(
            "SPEC.OUTPUT_CREATE_FAILED",
            "The private output artifact could not be inspected.",
        ) from None
    return True


def _write_private_new_at(
    parent_fd: int,
    name: str,
    content: bytes,
    *,
    verify_directory: Callable[[], None],
) -> None:
    """Write exact bytes once relative to one already-open directory."""

    temporary_name = f".{name}.tmp"
    descriptor: int | None = None
    temporary_created = False
    destination_linked = False
    committed = False
    try:
        if _path_exists_at(parent_fd, name):
            raise InvalidInputError(
                "SPEC.OUTPUT_ALREADY_EXISTS",
                "The output path already exists; this command does not overwrite artifacts.",
            )
        if _path_exists_at(parent_fd, temporary_name):
            raise InvalidInputError(
                "SPEC.OUTPUT_TEMPORARY_EXISTS",
                "The private output directory contains a conflicting temporary artifact.",
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
            temporary_created = True
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "wb", closefd=True)
            descriptor = None
            with handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(
                temporary_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            destination_linked = True
            os.fsync(parent_fd)
            verify_directory()
            os.unlink(temporary_name, dir_fd=parent_fd)
            temporary_created = False
            os.fsync(parent_fd)
            verify_directory()
            committed = True
        except InvalidInputError:
            raise
        except OSError:
            raise InvalidInputError(
                "SPEC.OUTPUT_CREATE_FAILED",
                "The private output artifact could not be created without overwriting.",
            ) from None
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        cleanup_changed_directory = False
        if destination_linked and not committed:
            with suppress(OSError):
                os.unlink(name, dir_fd=parent_fd)
                cleanup_changed_directory = True
        if temporary_created:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=parent_fd)
                cleanup_changed_directory = True
        if cleanup_changed_directory:
            with suppress(OSError):
                os.fsync(parent_fd)


def _read_private_existing_at(
    parent_fd: int,
    name: str,
    *,
    maximum_bytes: int,
    verify_directory: Callable[[], None],
) -> bytes:
    """Read one exact private regular file relative to an owned directory fd."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise InvalidInputError(
            "SPEC.OUTPUT_MISSING",
            "The private output artifact does not exist.",
        ) from None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise InvalidInputError(
                "SPEC.OUTPUT_SYMLINK",
                "Output paths must not contain symbolic links.",
            ) from None
        raise InvalidInputError(
            "SPEC.OUTPUT_READ_FAILED",
            "The private output artifact could not be read.",
        ) from None
    try:
        before = os.fstat(descriptor)

        def verify_live_leaf(observed: os.stat_result) -> None:
            try:
                live = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                raise InvalidInputError(
                    "SPEC.OUTPUT_PATH_CHANGED",
                    "The private output artifact changed while it was read.",
                ) from None
            stability_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_uid",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if not stat.S_ISREG(live.st_mode) or any(
                getattr(live, field) != getattr(observed, field) for field in stability_fields
            ):
                raise InvalidInputError(
                    "SPEC.OUTPUT_PATH_CHANGED",
                    "The private output artifact changed while it was read.",
                )

        owner_matches = not hasattr(os, "geteuid") or before.st_uid == os.geteuid()
        if before.st_size > maximum_bytes:
            raise InvalidInputError(
                "SPEC.OUTPUT_READ_LIMIT",
                "The private output artifact exceeds the allowed read limit.",
            )
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not owner_matches
            or before.st_size < 0
        ):
            raise InvalidInputError(
                "SPEC.OUTPUT_FILE_MODE",
                "The private output artifact is not an exact private regular file.",
            )
        verify_directory()
        verify_live_leaf(before)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise InvalidInputError(
                    "SPEC.OUTPUT_READ_FAILED",
                    "The private output artifact changed while it was read.",
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InvalidInputError(
                "SPEC.OUTPUT_READ_FAILED",
                "The private output artifact changed while it was read.",
            )
        after = os.fstat(descriptor)
        verify_directory()
        verify_live_leaf(after)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
            raise InvalidInputError(
                "SPEC.OUTPUT_PATH_CHANGED",
                "The private output artifact changed while it was read.",
            )
        content = b"".join(chunks)
        if len(content) != before.st_size:
            raise InvalidInputError(
                "SPEC.OUTPUT_READ_FAILED",
                "The private output artifact changed while it was read.",
            )
        return content
    finally:
        os.close(descriptor)


def _initialize_run_root_authentication(
    path: Path,
    identity: tuple[int, int],
) -> str:
    root_fd = _open_directory_chain(path, create=False)
    try:
        return _initialize_run_root_authentication_at(
            root_fd,
            identity,
            verify_root=lambda: _verify_current_directory_path(path, root_fd),
        )
    finally:
        os.close(root_fd)


def _initialize_run_root_authentication_at(
    root_fd: int,
    identity: tuple[int, int],
    *,
    verify_root: Callable[[], None],
) -> str:
    """Initialize authentication through one already-open exact root."""

    _validate_private_directory_descriptor(root_fd)
    observed = os.fstat(root_fd)
    if (observed.st_dev, observed.st_ino) != identity:
        raise _directory_error(
            "SPEC.OUTPUT_PATH_CHANGED",
            "The private run root changed while it was initialized.",
        )
    key = os.urandom(32)
    owner_uid = os.geteuid() if hasattr(os, "geteuid") else observed.st_uid
    marker, marker_content = _run_root_marker(
        key=key,
        device=observed.st_dev,
        inode=observed.st_ino,
        owner_uid=owner_uid,
    )
    _write_private_new_at(
        root_fd,
        _RUN_ROOT_KEY_NAME,
        key,
        verify_directory=verify_root,
    )
    _write_private_new_at(
        root_fd,
        _RUN_ROOT_MARKER_NAME,
        marker_content,
        verify_directory=verify_root,
    )
    os.fsync(root_fd)
    verified_id = _verify_run_root_authentication(
        root_fd,
        expected_identity=identity,
    )
    assert verified_id == marker["run_root_id"]
    return verified_id


def _remove_run_root_authentication_at(root_fd: int) -> None:
    for name in (
        _RUN_ROOT_MARKER_NAME,
        f".{_RUN_ROOT_MARKER_NAME}.tmp",
        _RUN_ROOT_KEY_NAME,
        f".{_RUN_ROOT_KEY_NAME}.tmp",
    ):
        with suppress(OSError):
            os.unlink(name, dir_fd=root_fd)
    with suppress(OSError):
        os.fsync(root_fd)


def _rollback_fresh_run_root(path: Path, identity: tuple[int, int]) -> None:
    root_fd: int | None = None
    try:
        root_fd = _open_directory_chain(path, create=False)
        observed = os.fstat(root_fd)
        if (observed.st_dev, observed.st_ino) != identity:
            return
        _remove_run_root_authentication_at(root_fd)
    except (OSError, InvalidInputError):
        return
    finally:
        if root_fd is not None:
            os.close(root_fd)
    absolute = path.absolute()
    try:
        parent_fd = _open_directory_chain(absolute.parent, create=False)
    except (FileNotFoundError, InvalidInputError):
        return
    try:
        removed = _remove_directory_if_identity(parent_fd, absolute.name, identity)
        if removed:
            with suppress(OSError):
                os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def write_private_new(path: Path, content: bytes) -> None:
    """Write exact bytes once using one already-open, no-symlink parent fd."""

    name = _validate_file_name(path)
    parent = path.absolute().parent
    ensure_private_directory(parent)
    parent_fd = _open_directory_chain(parent, create=False)
    try:
        _write_private_new_at(
            parent_fd,
            name,
            content,
            verify_directory=lambda: _verify_current_directory_path(parent, parent_fd),
        )
    finally:
        os.close(parent_fd)


def _closed_relative_path(relative_path: str) -> PurePosixPath:
    raw_parts = relative_path.split("/")
    if (
        not relative_path
        or "\\" in relative_path
        or "\x00" in relative_path
        or not unicodedata.is_normalized("NFC", relative_path)
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise InvalidInputError(
            "SPEC.OUTPUT_RELATIVE_PATH",
            "Artifact paths must be non-empty relative POSIX paths.",
        )
    relative = PurePosixPath(relative_path)
    if (
        not relative.parts
        or relative == PurePosixPath(".")
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise InvalidInputError(
            "SPEC.OUTPUT_RELATIVE_PATH",
            "Artifact paths must stay inside the private run directory.",
        )
    return relative


@dataclass(frozen=True, slots=True)
class ArtifactInventoryEntry:
    """One closed, content-addressed private artifact inventory row."""

    path: str
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        relative = _closed_relative_path(self.path)
        if (
            relative.as_posix() != self.path
            or _INVENTORY_DIGEST_PATTERN.fullmatch(self.sha256) is None
            or type(self.byte_length) is not int
            or self.byte_length < 0
        ):
            raise InvalidInputError(
                "SPEC.OUTPUT_INVENTORY",
                "The private artifact inventory is invalid.",
            )

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
        }


@dataclass(frozen=True, slots=True)
class _ArtifactTreeScan:
    inventory: tuple[ArtifactInventoryEntry, ...]
    identities: tuple[tuple[str, str, tuple[int, ...]], ...]


def _inventory_error() -> InvalidInputError:
    return InvalidInputError(
        "SPEC.OUTPUT_INVENTORY",
        "The private artifact inventory could not be verified.",
    )


def _validate_inventory_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or not unicodedata.is_normalized("NFC", name)
    ):
        raise _inventory_error()
    if name.startswith(".") and name.endswith(".tmp"):
        raise InvalidInputError(
            "SPEC.OUTPUT_INVENTORY_TEMPORARY",
            "The private artifact tree contains an unfinished temporary entry.",
        )


def _inventory_identity_fields(observed: os.stat_result) -> tuple[int, ...]:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_nlink,
        observed.st_uid,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def _verify_inventory_entry_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
) -> None:
    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise _inventory_error() from None
    if _inventory_identity_fields(observed) != _inventory_identity_fields(expected):
        raise _inventory_error()


def _hash_inventory_file_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
) -> ArtifactInventoryEntry:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError:
        raise _inventory_error() from None
    try:
        before = os.fstat(descriptor)
        owner_matches = not hasattr(os, "geteuid") or before.st_uid == os.geteuid()
        if (
            _inventory_identity_fields(before) != _inventory_identity_fields(expected)
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not owner_matches
            or before.st_size < 0
        ):
            raise _inventory_error()
        _verify_inventory_entry_at(parent_fd, name, before)
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            try:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
            except OSError:
                raise _inventory_error() from None
            if not chunk:
                raise _inventory_error()
            digest.update(chunk)
            remaining -= len(chunk)
        try:
            if os.read(descriptor, 1):
                raise _inventory_error()
        except OSError:
            raise _inventory_error() from None
        after = os.fstat(descriptor)
        _verify_inventory_entry_at(parent_fd, name, after)
        if _inventory_identity_fields(before) != _inventory_identity_fields(after):
            raise _inventory_error()
        return ArtifactInventoryEntry(
            path=name,
            sha256="sha256:" + digest.hexdigest(),
            byte_length=before.st_size,
        )
    finally:
        os.close(descriptor)


def _private_artifact_inventory_single_scan_at(
    root_fd: int,
    *,
    exclude_run_status: bool,
) -> _ArtifactTreeScan:
    """Perform one complete descriptor-relative inventory scan."""

    _validate_private_directory_descriptor(root_fd)
    root_before = os.fstat(root_fd)
    _verify_run_root_authentication(
        root_fd,
        expected_identity=(root_before.st_dev, root_before.st_ino),
    )
    rows: list[ArtifactInventoryEntry] = []
    identities: list[tuple[str, str, tuple[int, ...]]] = []

    def walk(directory_fd: int, prefix: tuple[str, ...], *, is_root: bool) -> int:
        _validate_private_directory_descriptor(directory_fd)
        directory_before = os.fstat(directory_fd)
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError:
            raise _inventory_error() from None
        if len(names) != len(set(names)):
            raise _inventory_error()
        artifact_count = 0
        for name in names:
            _validate_inventory_name(name)
            relative_parts = (*prefix, name)
            relative_path = PurePosixPath(*relative_parts).as_posix()
            _observe_profile_store_path(
                PurePosixPath(*relative_parts),
                operation="READ",
            )
            try:
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                raise _inventory_error() from None
            if stat.S_ISDIR(observed.st_mode):
                flags = _DIRECTORY_OPEN_FLAGS
                try:
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                except OSError:
                    raise _inventory_error() from None
                try:
                    opened = os.fstat(child_fd)
                    if _inventory_identity_fields(opened) != _inventory_identity_fields(observed):
                        raise _inventory_error()
                    _validate_private_directory_descriptor(child_fd)
                    child_count = walk(child_fd, relative_parts, is_root=False)
                    if child_count == 0:
                        raise InvalidInputError(
                            "SPEC.OUTPUT_INVENTORY_EMPTY_DIRECTORY",
                            "The private artifact tree contains an unexpected empty directory.",
                        )
                    artifact_count += child_count
                    _verify_inventory_entry_at(directory_fd, name, opened)
                    identities.append(
                        (
                            relative_path,
                            "DIRECTORY",
                            _inventory_identity_fields(opened),
                        )
                    )
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(observed.st_mode):
                raise _inventory_error()
            row = _hash_inventory_file_at(directory_fd, name, observed)
            row = ArtifactInventoryEntry(
                path=relative_path,
                sha256=row.sha256,
                byte_length=row.byte_length,
            )
            identities.append(
                (
                    relative_path,
                    "FILE",
                    _inventory_identity_fields(observed),
                )
            )
            excluded_authentication = is_root and name in {
                _RUN_ROOT_KEY_NAME,
                _RUN_ROOT_MARKER_NAME,
            }
            excluded_status = is_root and exclude_run_status and name == "run-status.json"
            if not excluded_authentication and not excluded_status:
                rows.append(row)
                artifact_count += 1
        try:
            names_after = sorted(os.listdir(directory_fd))
        except OSError:
            raise _inventory_error() from None
        directory_after = os.fstat(directory_fd)
        if (
            names_after != names
            or _inventory_identity_fields(directory_before)
            != _inventory_identity_fields(directory_after)
        ):
            raise _inventory_error()
        return artifact_count

    walk(root_fd, (), is_root=True)
    root_after = os.fstat(root_fd)
    if _inventory_identity_fields(root_before) != _inventory_identity_fields(root_after):
        raise _inventory_error()
    _verify_run_root_authentication(
        root_fd,
        expected_identity=(root_before.st_dev, root_before.st_ino),
    )
    ordered = tuple(sorted(rows, key=lambda row: row.path))
    if len({row.path for row in ordered}) != len(ordered):
        raise _inventory_error()
    identities.append((".", "DIRECTORY", _inventory_identity_fields(root_after)))
    return _ArtifactTreeScan(
        inventory=ordered,
        identities=tuple(sorted(identities)),
    )


def _private_artifact_inventory_at(
    root_fd: int,
    *,
    exclude_run_status: bool,
) -> tuple[ArtifactInventoryEntry, ...]:
    """Return one self-consistent observation, not a tree immutability proof."""

    observation = _private_artifact_inventory_single_scan_at(
        root_fd,
        exclude_run_status=exclude_run_status,
    )
    return observation.inventory


def _fsync_private_artifact_tree_at(
    root_fd: int,
    *,
    expected_inventory: tuple[ArtifactInventoryEntry, ...],
    exclude_run_status: bool,
) -> None:
    """Synchronize every accepted file and directory through exact descriptors."""

    before = _private_artifact_inventory_at(
        root_fd,
        exclude_run_status=exclude_run_status,
    )
    if before != expected_inventory:
        raise _inventory_error()

    def fsync_walk(directory_fd: int, *, is_root: bool) -> int:
        _validate_private_directory_descriptor(directory_fd)
        directory_before = os.fstat(directory_fd)
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError:
            raise _inventory_error() from None
        if len(names) != len(set(names)):
            raise _inventory_error()
        artifact_count = 0
        for name in names:
            _validate_inventory_name(name)
            try:
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                raise _inventory_error() from None
            if stat.S_ISDIR(observed.st_mode):
                try:
                    child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
                except OSError:
                    raise _inventory_error() from None
                try:
                    opened = os.fstat(child_fd)
                    if _inventory_identity_fields(opened) != _inventory_identity_fields(observed):
                        raise _inventory_error()
                    _validate_private_directory_descriptor(child_fd)
                    child_count = fsync_walk(child_fd, is_root=False)
                    if child_count == 0:
                        raise InvalidInputError(
                            "SPEC.OUTPUT_INVENTORY_EMPTY_DIRECTORY",
                            "The private artifact tree contains an unexpected empty directory.",
                        )
                    artifact_count += child_count
                    _verify_inventory_entry_at(directory_fd, name, opened)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(observed.st_mode):
                raise _inventory_error()
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                file_fd = os.open(name, flags, dir_fd=directory_fd)
            except OSError:
                raise _inventory_error() from None
            try:
                opened = os.fstat(file_fd)
                owner_matches = not hasattr(os, "geteuid") or opened.st_uid == os.geteuid()
                if (
                    _inventory_identity_fields(opened) != _inventory_identity_fields(observed)
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or opened.st_nlink != 1
                    or not owner_matches
                    or opened.st_size < 0
                ):
                    raise _inventory_error()
                _verify_inventory_entry_at(directory_fd, name, opened)
                try:
                    os.fsync(file_fd)
                except OSError:
                    raise InvalidInputError(
                        "SPEC.OUTPUT_DURABILITY",
                        "A private artifact could not be synchronized for publication.",
                    ) from None
                after = os.fstat(file_fd)
                _verify_inventory_entry_at(directory_fd, name, after)
                if _inventory_identity_fields(opened) != _inventory_identity_fields(after):
                    raise _inventory_error()
            finally:
                os.close(file_fd)
            excluded_authentication = is_root and name in {
                _RUN_ROOT_KEY_NAME,
                _RUN_ROOT_MARKER_NAME,
            }
            excluded_status = is_root and exclude_run_status and name == "run-status.json"
            if not excluded_authentication and not excluded_status:
                artifact_count += 1
        try:
            names_after = sorted(os.listdir(directory_fd))
        except OSError:
            raise _inventory_error() from None
        directory_after = os.fstat(directory_fd)
        if (
            names_after != names
            or _inventory_identity_fields(directory_before)
            != _inventory_identity_fields(directory_after)
        ):
            raise _inventory_error()
        try:
            os.fsync(directory_fd)
        except OSError:
            raise InvalidInputError(
                "SPEC.OUTPUT_DURABILITY",
                "A private artifact directory could not be synchronized for publication.",
            ) from None
        synchronized = os.fstat(directory_fd)
        if _inventory_identity_fields(directory_after) != _inventory_identity_fields(
            synchronized
        ):
            raise _inventory_error()
        return artifact_count

    fsync_walk(root_fd, is_root=True)
    after = _private_artifact_inventory_at(
        root_fd,
        exclude_run_status=exclude_run_status,
    )
    if after != expected_inventory:
        raise _inventory_error()


class PrivateArtifactStore:
    """One private run root that creates artifacts without overwriting them."""

    __slots__ = (
        "_attachment_mode",
        "_root",
        "_root_device",
        "_root_inode",
        "_run_root_id",
    )
    _attachment_mode: str
    _root: Path
    _root_device: int
    _root_inode: int
    _run_root_id: str

    def __init__(
        self,
        root: Path,
        root_device: int,
        root_inode: int,
        run_root_id: str | None = None,
        attachment_mode: str | None = None,
        *,
        construction_token: object | None = None,
    ) -> None:
        if construction_token is not _STORE_CONSTRUCTION_TOKEN:
            raise _directory_error(
                "SPEC.OUTPUT_STORE_CONSTRUCTION",
                "Private artifact stores must be created with PrivateArtifactStore.open().",
            )
        object.__setattr__(self, "_root", root)
        object.__setattr__(self, "_root_device", root_device)
        object.__setattr__(self, "_root_inode", root_inode)
        if run_root_id is None or _RUN_ROOT_ID_PATTERN.fullmatch(run_root_id) is None:
            raise _directory_error(
                "SPEC.RUN_ROOT_AUTHENTICATION",
                "The private run-root identity is invalid.",
            )
        object.__setattr__(self, "_run_root_id", run_root_id)
        if attachment_mode not in _STORE_ATTACHMENT_MODES:
            raise _directory_error(
                "SPEC.OUTPUT_STORE_CONSTRUCTION",
                "The private artifact-store attachment mode is invalid.",
            )
        object.__setattr__(self, "_attachment_mode", attachment_mode)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Private artifact stores are immutable.")

    @property
    def root(self) -> Path:
        return self._root

    @property
    def run_root_id(self) -> str:
        """Return the privacy-safe random identity of this exact run root."""

        return self._run_root_id

    @property
    def attachment_mode(self) -> str:
        """Distinguish a fresh root from a cross-process existing-root attach."""

        return self._attachment_mode

    def __repr__(self) -> str:
        return "PrivateArtifactStore(<private-root>)"

    @classmethod
    def open(cls, root: Path) -> PrivateArtifactStore:
        absolute = root.absolute()
        identity = _create_private_directory_exclusive(absolute)
        try:
            run_root_id = _initialize_run_root_authentication(absolute, identity)
            return cls(
                absolute,
                identity[0],
                identity[1],
                run_root_id,
                "CREATED_FRESH",
                construction_token=_STORE_CONSTRUCTION_TOKEN,
            )
        except BaseException:
            _rollback_fresh_run_root(absolute, identity)
            raise

    @classmethod
    def _open_fresh_at(
        cls,
        parent_fd: int,
        parent_path: Path,
        name: str,
    ) -> PrivateArtifactStore:
        """Create a fresh store under one caller-retained exact parent."""

        absolute_parent = parent_path.absolute()
        absolute = absolute_parent / name
        if _validate_file_name(absolute) != name:
            raise _directory_error(
                "SPEC.OUTPUT_RELATIVE_PATH",
                "The private run-root name is invalid.",
            )
        descriptor: int | None = None
        identity: tuple[int, int] | None = None
        authenticated = False
        try:
            try:
                descriptor, identity = _create_child_directory(parent_fd, name)
            except FileExistsError:
                raise _directory_error(
                    "SPEC.OUTPUT_ALREADY_EXISTS",
                    "The private run directory already exists; a fresh root is required.",
                ) from None

            def verify_root() -> None:
                assert descriptor is not None
                observed_parent = _open_directory_chain(absolute_parent, create=False)
                try:
                    if not _same_directory(parent_fd, observed_parent):
                        raise _directory_error(
                            "SPEC.OUTPUT_PATH_CHANGED",
                            "The private run root changed while it was initialized.",
                        )
                finally:
                    os.close(observed_parent)
                _verify_current_directory_path(absolute, descriptor)
                assert identity is not None
                _verify_inventory_entry_at(parent_fd, name, os.fstat(descriptor))

            assert identity is not None
            run_root_id = _initialize_run_root_authentication_at(
                descriptor,
                identity,
                verify_root=verify_root,
            )
            verify_root()
            authenticated = True
            return cls(
                absolute,
                identity[0],
                identity[1],
                run_root_id,
                "CREATED_FRESH",
                construction_token=_STORE_CONSTRUCTION_TOKEN,
            )
        except InvalidInputError:
            raise
        except OSError:
            raise _directory_error(
                "SPEC.OUTPUT_DIRECTORY",
                "The fresh private run directory could not be created.",
            ) from None
        finally:
            if descriptor is not None:
                if not authenticated:
                    _remove_run_root_authentication_at(descriptor)
                os.close(descriptor)
            if not authenticated and identity is not None:
                changed = _remove_directory_if_identity(parent_fd, name, identity)
                if changed:
                    with suppress(OSError):
                        os.fsync(parent_fd)

    @classmethod
    def attach_existing(
        cls,
        root: Path,
        *,
        expected_run_root_id: str,
    ) -> PrivateArtifactStore:
        """Attach only when the caller-held identity matches the existing root."""

        absolute = root.absolute()
        if _RUN_ROOT_ID_PATTERN.fullmatch(expected_run_root_id) is None:
            raise _directory_error(
                "SPEC.RUN_ROOT_AUTHENTICATION",
                "The expected private run-root identity is invalid.",
            )
        try:
            descriptor = _open_directory_chain(absolute, create=False)
        except FileNotFoundError:
            raise _directory_error(
                "SPEC.OUTPUT_DIRECTORY",
                "The private run directory does not exist.",
            ) from None
        try:
            _validate_private_directory_descriptor(descriptor)
            observed = os.fstat(descriptor)
            identity = (observed.st_dev, observed.st_ino)
            run_root_id = _verify_run_root_authentication(
                descriptor,
                expected_identity=identity,
            )
            if not hmac.compare_digest(run_root_id, expected_run_root_id):
                raise _directory_error(
                    "SPEC.RUN_ROOT_AUTHENTICATION",
                    "The private run root does not match the expected identity.",
                )
            _verify_current_directory_path(absolute, descriptor)
            return cls(
                absolute,
                identity[0],
                identity[1],
                run_root_id,
                "ATTACHED_EXISTING",
                construction_token=_STORE_CONSTRUCTION_TOKEN,
            )
        finally:
            os.close(descriptor)

    def _open_owned_root(self) -> int:
        try:
            descriptor = _open_directory_chain(self.root, create=False)
        except FileNotFoundError:
            raise _directory_error(
                "SPEC.OUTPUT_PATH_CHANGED",
                "The private run root changed after it was created.",
            ) from None
        try:
            _validate_private_directory_descriptor(descriptor)
            observed = os.fstat(descriptor)
            if (observed.st_dev, observed.st_ino) != (self._root_device, self._root_inode):
                raise _directory_error(
                    "SPEC.OUTPUT_PATH_CHANGED",
                    "The private run root changed after it was created.",
                )
            authenticated_id = _verify_run_root_authentication(
                descriptor,
                expected_identity=(self._root_device, self._root_inode),
            )
            if authenticated_id != self._run_root_id:
                raise _directory_error(
                    "SPEC.RUN_ROOT_AUTHENTICATION",
                    "The private run-root identity changed.",
                )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _close_created_entries(
        entries: list[tuple[int, str, tuple[int, int]]], *, rollback: bool
    ) -> None:
        for parent_fd, name, identity in reversed(entries):
            if rollback:
                changed = _remove_directory_if_identity(parent_fd, name, identity)
                if changed:
                    with suppress(OSError):
                        os.fsync(parent_fd)
            os.close(parent_fd)

    @staticmethod
    def _open_relative_directories(
        root_fd: int,
        parts: tuple[str, ...],
        *,
        create: bool,
    ) -> tuple[int, list[tuple[int, str, tuple[int, int]]]]:
        current_fd = os.dup(root_fd)
        created_entries: list[tuple[int, str, tuple[int, int]]] = []
        try:
            for part in parts:
                try:
                    next_fd = os.open(part, _DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    rollback_parent_fd = os.dup(current_fd)
                    try:
                        next_fd, identity = _create_child_directory(current_fd, part)
                    except BaseException:
                        os.close(rollback_parent_fd)
                        raise
                    created_entries.append((rollback_parent_fd, part, identity))
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise _directory_error(
                            "SPEC.OUTPUT_SYMLINK",
                            "Output paths must not contain symbolic links.",
                        ) from None
                    raise
                try:
                    _validate_private_directory_descriptor(next_fd)
                except BaseException:
                    os.close(next_fd)
                    raise
                os.close(current_fd)
                current_fd = next_fd
            return current_fd, created_entries
        except BaseException:
            with suppress(OSError):
                os.close(current_fd)
            PrivateArtifactStore._close_created_entries(created_entries, rollback=True)
            raise

    def resolve(self, relative_path: str) -> Path:
        relative = _closed_relative_path(relative_path)
        return self.root.joinpath(*relative.parts)

    def ensure_directory(self, relative_path: str) -> Path:
        relative = _closed_relative_path(relative_path)
        _observe_profile_store_path(relative, operation="WRITE")
        root_fd = self._open_owned_root()
        directory_fd: int | None = None
        created_entries: list[tuple[int, str, tuple[int, int]]] = []
        complete = False
        candidate = self.root.joinpath(*relative.parts)
        try:
            directory_fd, created_entries = self._open_relative_directories(
                root_fd,
                relative.parts,
                create=True,
            )
            _verify_current_directory_path(self.root, root_fd)
            _verify_current_directory_path(candidate, directory_fd)
            complete = True
            return candidate
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
            self._close_created_entries(created_entries, rollback=not complete)
            os.close(root_fd)

    def write_bytes(self, relative_path: str, content: bytes) -> Path:
        relative = _closed_relative_path(relative_path)
        _observe_profile_store_path(relative, operation="WRITE")
        candidate = self.root.joinpath(*relative.parts)
        parent = candidate.parent
        root_fd = self._open_owned_root()
        parent_fd: int | None = None
        created_entries: list[tuple[int, str, tuple[int, int]]] = []
        complete = False
        try:
            parent_fd, created_entries = self._open_relative_directories(
                root_fd,
                relative.parts[:-1],
                create=True,
            )
            assert parent_fd is not None

            def verify_owned_parent() -> None:
                _verify_current_directory_path(self.root, root_fd)
                _verify_current_directory_path(parent, parent_fd)

            _write_private_new_at(
                parent_fd,
                relative.parts[-1],
                content,
                verify_directory=verify_owned_parent,
            )
            complete = True
            return candidate
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            self._close_created_entries(created_entries, rollback=not complete)
            os.close(root_fd)

    def read_bytes(
        self,
        relative_path: str,
        *,
        maximum_bytes: int = _DEFAULT_MAXIMUM_ARTIFACT_BYTES,
    ) -> bytes:
        """Read one exact private artifact without following path symlinks."""

        if (
            type(maximum_bytes) is not int
            or maximum_bytes < 0
            or maximum_bytes > _DEFAULT_MAXIMUM_ARTIFACT_BYTES
        ):
            raise InvalidInputError(
                "SPEC.OUTPUT_READ_LIMIT",
                "The private output read limit is invalid.",
            )
        relative = _closed_relative_path(relative_path)
        _observe_profile_store_path(relative, operation="READ")
        parent = self.root.joinpath(*relative.parts[:-1])
        root_fd = self._open_owned_root()
        parent_fd: int | None = None
        try:
            try:
                parent_fd, created_entries = self._open_relative_directories(
                    root_fd,
                    relative.parts[:-1],
                    create=False,
                )
            except FileNotFoundError:
                raise InvalidInputError(
                    "SPEC.OUTPUT_MISSING",
                    "The private output artifact does not exist.",
                ) from None
            assert parent_fd is not None
            assert created_entries == []

            def verify_owned_parent() -> None:
                _verify_current_directory_path(self.root, root_fd)
                _verify_current_directory_path(parent, parent_fd)

            return _read_private_existing_at(
                parent_fd,
                relative.parts[-1],
                maximum_bytes=maximum_bytes,
                verify_directory=verify_owned_parent,
            )
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            os.close(root_fd)

    def inventory(
        self,
        *,
        exclude_run_status: bool = False,
    ) -> tuple[ArtifactInventoryEntry, ...]:
        """Return the exact descriptor-walked private artifact inventory."""

        if type(exclude_run_status) is not bool:
            raise InvalidInputError(
                "SPEC.OUTPUT_INVENTORY",
                "The private artifact inventory request is invalid.",
            )
        root_fd = self._open_owned_root()
        try:
            return _private_artifact_inventory_at(
                root_fd,
                exclude_run_status=exclude_run_status,
            )
        finally:
            os.close(root_fd)
