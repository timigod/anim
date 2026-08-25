"""Fail-closed Python worker network-attempt sentinel.

Python imports ``sitecustomize`` during interpreter startup. This module is
inert outside an EBM Audit offline worker. Inside one, it records only that a
network operation was attempted (never an endpoint) and raises before the
operation. The OS containment provider remains the enforcement boundary.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _safe_sentinel(name: str, work_dir: Path) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    candidate = Path(value)
    try:
        if candidate.is_absolute() and candidate.parent.resolve() == work_dir.resolve():
            return candidate
    except OSError:
        pass
    return None


def _create_sentinel(path: Path, record: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return
    try:
        os.write(descriptor, record)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _install_offline_guard() -> None:
    if os.environ.get("EBM_AUDIT_OFFLINE") != "1":
        return
    work_name = os.environ.get("EBM_AUDIT_WORK_DIR")
    root_name = os.environ.get("EBM_AUDIT_INVOCATION_ROOT")
    request_name = os.environ.get("EBM_AUDIT_REQUEST_DIR")
    if not work_name or not root_name or not request_name:
        return
    work_dir = Path(work_name)
    invocation_root = Path(root_name)
    request_dir = Path(request_name)
    try:
        if (
            not work_dir.is_absolute()
            or not invocation_root.is_absolute()
            or not request_dir.is_absolute()
            or work_dir.resolve().parent != invocation_root.resolve()
            or request_dir.resolve().parent != invocation_root.resolve()
        ):
            return
    except OSError:
        return
    network_attempt_path = _safe_sentinel("EBM_AUDIT_NETWORK_ATTEMPT_FILE", work_dir)
    outside_attempt_path = _safe_sentinel("EBM_AUDIT_OUTSIDE_ATTEMPT_FILE", work_dir)
    guard_active_path = _safe_sentinel("EBM_AUDIT_GUARD_ACTIVE_FILE", work_dir)
    if network_attempt_path is None or outside_attempt_path is None or guard_active_path is None:
        return
    _create_sentinel(guard_active_path, b"offline-guard-active\n")

    import socket as socket_module

    def record_attempt() -> None:
        _create_sentinel(network_attempt_path, b"network-attempt\n")

    def blocked(*_args: object, **_kwargs: object) -> object:
        record_attempt()
        raise PermissionError("Offline worker network access is denied.")

    original_socket = socket_module.socket

    class OfflineSocket(original_socket):  # type: ignore[misc, valid-type]
        def __init__(
            self,
            family: int = socket_module.AF_INET,
            type: int = socket_module.SOCK_STREAM,
            proto: int = 0,
            fileno: int | None = None,
        ) -> None:
            if family in {socket_module.AF_INET, socket_module.AF_INET6}:
                blocked()
            super().__init__(family, type, proto, fileno)

    socket_module.socket = OfflineSocket
    socket_module.create_connection = blocked  # type: ignore[assignment]
    socket_module.getaddrinfo = blocked  # type: ignore[assignment]
    socket_module.gethostbyaddr = blocked  # type: ignore[assignment]
    socket_module.gethostbyname = blocked  # type: ignore[assignment]
    socket_module.gethostbyname_ex = blocked  # type: ignore[assignment]
    socket_module.getfqdn = blocked  # type: ignore[assignment]

    root = invocation_root.resolve()
    request = request_dir.resolve()
    reentrant = False

    def contained(path_value: object) -> tuple[bool, bool]:
        if not isinstance(path_value, (str, bytes, os.PathLike)):
            return True, False
        try:
            path = Path(path_value)
            resolved = (Path.cwd() / path).resolve() if not path.is_absolute() else path.resolve()
            resolved.relative_to(root)
            in_root = True
        except (OSError, TypeError, ValueError):
            return False, False
        try:
            resolved.relative_to(request)
            in_request = True
        except ValueError:
            in_request = False
        return in_root, in_request

    def null_sink(path_value: object) -> bool:
        """Permit only the OS null device as a non-persistent write sink."""

        if not isinstance(path_value, (str, bytes, os.PathLike)):
            return False
        try:
            return Path(path_value).resolve() == Path(os.devnull).resolve()
        except (OSError, TypeError, ValueError):
            return False

    def record_file_attempt() -> None:
        nonlocal reentrant
        if reentrant:
            return
        reentrant = True
        try:
            _create_sentinel(outside_attempt_path, b"file-write-attempt\n")
        finally:
            reentrant = False

    def audit(event: str, args: tuple[object, ...]) -> None:
        if reentrant:
            return
        if event == "open" and args:
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else 0
            writes = (isinstance(mode, str) and any(character in mode for character in "wax+")) or (
                isinstance(flags, int)
                and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC))
            )
            if writes:
                in_root, in_request = contained(args[0])
                if (not in_root or in_request) and not null_sink(args[0]):
                    record_file_attempt()
            return
        path_events = {
            "os.chdir": (0,),
            "os.chmod": (0,),
            "os.chown": (0,),
            "os.link": (0, 1),
            "os.mkdir": (0,),
            "os.remove": (0,),
            "os.rename": (0, 1),
            "os.rmdir": (0,),
            "os.symlink": (0, 1),
            "os.truncate": (0,),
        }
        indexes = path_events.get(event)
        if indexes is not None:
            for index in indexes:
                if index >= len(args):
                    continue
                in_root, in_request = contained(args[index])
                if not in_root or in_request:
                    record_file_attempt()
                    return

    sys.addaudithook(audit)


_install_offline_guard()
