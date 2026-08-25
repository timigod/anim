"""One-use staged publication of an authenticated private artifact tree."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import unicodedata
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from threading import RLock
from types import TracebackType
from typing import NoReturn, SupportsIndex

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import CanonicalizationError, canonical_json_bytes

from .store import (
    _DIRECTORY_OPEN_FLAGS,
    _RUN_ROOT_KEY_NAME,
    _RUN_ROOT_MARKER_NAME,
    ArtifactInventoryEntry,
    PrivateArtifactStore,
    _closed_relative_path,
    _fsync_private_artifact_tree_at,
    _inventory_identity_fields,
    _open_directory_chain,
    _private_artifact_inventory_at,
    _read_private_existing_at,
    _same_directory,
    _validate_file_name,
    _validate_inventory_name,
    _validate_private_directory_descriptor,
    _verify_run_root_authentication,
)

_TRANSACTION_CONSTRUCTION_TOKEN = object()
_PUBLICATION_SCHEMA_VERSION = "ebm-audit-run-publication/1.0"
_PUBLICATION_STATE = "STAGED_READY_FOR_PUBLICATION"
_FINAL_PRECONDITION = "ABSENT"
_PUBLICATION_SCOPE = "NON_AUTHENTICATION_ARTIFACTS_EXCLUDING_RUN_STATUS"
_RUN_STATUS_NAME = "run-status.json"
_INVENTORY_DOMAIN = b"ebm-audit/run-publication-inventory/1\x00"
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAXIMUM_RUN_STATUS_BYTES = 8 * 1024 * 1024
_DARWIN_RENAME_EXCL = 0x4
_LINUX_RENAME_NOREPLACE = 1
_STAGED_PUBLISH_OPERATION_TOKEN = object()
_TERMINAL_VALIDATOR_CONSTRUCTION_TOKEN = object()
_VERIFIED_READ_OPERATION_TOKEN = object()
_VERIFIED_RUN_CONSTRUCTION_TOKEN = object()
_VERIFIED_VALUE_CONSTRUCTION_TOKEN = object()
_UNSUPPORTED_RENAME_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, "ENOSYS", None),
        getattr(errno, "EINVAL", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
)


def _publication_error(code: str, message: str) -> InvalidInputError:
    return InvalidInputError(code, message)


def _verified_read_error() -> InvalidInputError:
    return _publication_error(
        "SPEC.OUTPUT_VERIFIED_READ",
        "The published output could not be returned as one verified snapshot.",
    )


@dataclass(slots=True)
class _TerminalValidatorState:
    expected_status_bytes: bytes = field(repr=False)
    expected_status_digest: str
    lock: RLock = field(default_factory=RLock, repr=False)
    consumed: bool = False


class TerminalRunStatusValidator:
    """One-use authority for exact parent-approved terminal run-status bytes."""

    __slots__ = ("__weakref__",)

    def __init__(
        self,
        validated_status_bytes: bytes,
        *,
        construction_token: object | None = None,
    ) -> None:
        if (
            type(self) is not TerminalRunStatusValidator
            or construction_token is not _TERMINAL_VALIDATOR_CONSTRUCTION_TOKEN
            or type(validated_status_bytes) is not bytes
        ):
            raise _publication_error(
                "SPEC.OUTPUT_TERMINAL_AUTHORITY",
                "A parent-issued terminal run-status authority is required.",
            )
        expected_status_digest = (
            "sha256:" + hashlib.sha256(validated_status_bytes).hexdigest()
        )
        _TERMINAL_VALIDATOR_STATE_ISSUER.bind_once(
            self,
            _TerminalValidatorState(
                expected_status_bytes=validated_status_bytes,
                expected_status_digest=expected_status_digest,
            ),
        )

    def __repr__(self) -> str:
        if self not in _TERMINAL_VALIDATOR_STATES:
            return "TerminalRunStatusValidator(state='UNISSUED')"
        return "TerminalRunStatusValidator(expected_status_bytes=<redacted>)"

    def __copy__(self) -> NoReturn:
        raise TypeError("Terminal run-status validators cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("Terminal run-status validators cannot be copied.")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Terminal run-status validators cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Terminal run-status validators cannot be serialized.")

    def __init_subclass__(cls, **_kwargs: object) -> NoReturn:
        raise TypeError("Terminal run-status validators cannot be subclassed.")


_TERMINAL_VALIDATOR_STATES: OneShotWeakRegistry[
    TerminalRunStatusValidator,
    _TerminalValidatorState,
]
_TERMINAL_VALIDATOR_STATE_ISSUER: OneShotRegistryIssuer[
    TerminalRunStatusValidator,
    _TerminalValidatorState,
]
(
    _TERMINAL_VALIDATOR_STATES,
    _TERMINAL_VALIDATOR_STATE_ISSUER,
) = create_one_shot_registry()


def _issue_terminal_run_status_validator(
    validated_status_bytes: bytes,
) -> TerminalRunStatusValidator:
    """Issue one-use authority for canonical bytes already approved by the parent."""

    if type(validated_status_bytes) is not bytes:
        raise _publication_error(
            "SPEC.OUTPUT_TERMINAL_AUTHORITY",
            "A parent-issued terminal run-status authority is required.",
        )
    _strict_json_object(validated_status_bytes)
    return TerminalRunStatusValidator(
        validated_status_bytes,
        construction_token=_TERMINAL_VALIDATOR_CONSTRUCTION_TOKEN,
    )


def _terminal_validator_state(
    validator: TerminalRunStatusValidator,
) -> _TerminalValidatorState:
    if type(validator) is not TerminalRunStatusValidator:
        raise _publication_error(
            "SPEC.OUTPUT_TERMINAL_AUTHORITY",
            "A parent-issued terminal run-status authority is required.",
        )
    try:
        return _TERMINAL_VALIDATOR_STATES[validator]
    except (OneShotRegistryError, TypeError):
        raise _publication_error(
            "SPEC.OUTPUT_TERMINAL_AUTHORITY",
            "A parent-issued terminal run-status authority is required.",
        ) from None


def _closed_final_output_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.parts:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_PATH",
            "The configured final output path is invalid.",
        )
    if any(
        part in {"", ".", ".."} or "\x00" in part or not unicodedata.is_normalized("NFC", part)
        for part in path.parts
        if part != os.sep
    ):
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_PATH",
            "The configured final output path is invalid.",
        )
    absolute = path.absolute()
    try:
        _validate_file_name(absolute)
    except InvalidInputError:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_PATH",
            "The configured final output path is invalid.",
        ) from None
    return absolute


def _inventory_json_bytes(inventory: tuple[ArtifactInventoryEntry, ...]) -> bytes:
    return json.dumps(
        [row.as_dict() for row in inventory],
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _inventory_digest(inventory: tuple[ArtifactInventoryEntry, ...]) -> str:
    return "sha256:" + hashlib.sha256(
        _INVENTORY_DOMAIN + _inventory_json_bytes(inventory)
    ).hexdigest()


def _publication_receipt(
    *,
    run_root_id: str,
    inventory: tuple[ArtifactInventoryEntry, ...],
) -> dict[str, object]:
    return {
        "schema_version": _PUBLICATION_SCHEMA_VERSION,
        "state": _PUBLICATION_STATE,
        "staging_run_root_id": run_root_id,
        "final_precondition": _FINAL_PRECONDITION,
        "scope": _PUBLICATION_SCOPE,
        "inventory": [row.as_dict() for row in inventory],
        "inventory_digest": _inventory_digest(inventory),
    }


def _strict_json_object(content: bytes) -> dict[str, object]:
    if content.startswith(b"\xef\xbb\xbf"):
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        )

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        decoded = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        ) from None
    if type(decoded) is not dict:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        )
    try:
        canonical = canonical_json_bytes(decoded)
    except CanonicalizationError:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        ) from None
    if canonical != content:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt must use exact canonical JSON bytes.",
        )
    return decoded


def _validate_terminal_authority(
    validator: TerminalRunStatusValidator,
    status_bytes: bytes,
) -> None:
    state = _terminal_validator_state(validator)
    with state.lock:
        if state.consumed:
            raise _publication_error(
                "SPEC.OUTPUT_TERMINAL_AUTHORITY",
                "The terminal run-status validation authority was already consumed.",
            )
        state.consumed = True
        observed_status_digest = "sha256:" + hashlib.sha256(status_bytes).hexdigest()
        if not hmac.compare_digest(
            status_bytes,
            state.expected_status_bytes,
        ) or not hmac.compare_digest(
            observed_status_digest,
            state.expected_status_digest,
        ):
            raise _publication_error(
                "SPEC.OUTPUT_TERMINAL_AUTHORITY",
                "The staged run-status bytes do not match the parent-approved bytes.",
            )


def _parse_receipt_inventory(value: object) -> tuple[ArtifactInventoryEntry, ...]:
    if type(value) is not list:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        )
    rows: list[ArtifactInventoryEntry] = []
    for raw_row in value:
        if type(raw_row) is not dict or set(raw_row) != {"path", "sha256", "byte_length"}:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_RECEIPT",
                "The terminal run-status publication receipt is invalid.",
            )
        path = raw_row["path"]
        digest = raw_row["sha256"]
        byte_length = raw_row["byte_length"]
        if (
            type(path) is not str
            or type(digest) is not str
            or _DIGEST_PATTERN.fullmatch(digest) is None
            or type(byte_length) is not int
            or byte_length < 0
        ):
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_RECEIPT",
                "The terminal run-status publication receipt is invalid.",
            )
        relative = _closed_relative_path(path)
        if (
            relative.as_posix() != path
            or path in {_RUN_ROOT_KEY_NAME, _RUN_ROOT_MARKER_NAME, _RUN_STATUS_NAME}
        ):
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_RECEIPT",
                "The terminal run-status publication receipt is invalid.",
            )
        rows.append(
            ArtifactInventoryEntry(
                path=path,
                sha256=digest,
                byte_length=byte_length,
            )
        )
    inventory = tuple(rows)
    if (
        tuple(sorted(inventory, key=lambda row: row.path)) != inventory
        or len({row.path for row in inventory}) != len(inventory)
    ):
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        )
    return inventory


def _validate_publication_receipt(
    value: object,
    *,
    expected_run_root_id: str,
    actual_inventory: tuple[ArtifactInventoryEntry, ...],
) -> dict[str, object]:
    expected_keys = {
        "schema_version",
        "state",
        "staging_run_root_id",
        "final_precondition",
        "scope",
        "inventory",
        "inventory_digest",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        )
    run_root_id = value["staging_run_root_id"]
    inventory_digest = value["inventory_digest"]
    if (
        value["schema_version"] != _PUBLICATION_SCHEMA_VERSION
        or value["state"] != _PUBLICATION_STATE
        or type(run_root_id) is not str
        or not hmac.compare_digest(run_root_id, expected_run_root_id)
        or value["final_precondition"] != _FINAL_PRECONDITION
        or value["scope"] != _PUBLICATION_SCOPE
        or type(inventory_digest) is not str
        or _DIGEST_PATTERN.fullmatch(inventory_digest) is None
    ):
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_RECEIPT",
            "The terminal run-status publication receipt is invalid.",
        )
    recorded_inventory = _parse_receipt_inventory(value["inventory"])
    if (
        recorded_inventory != actual_inventory
        or not hmac.compare_digest(inventory_digest, _inventory_digest(actual_inventory))
    ):
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_INVENTORY_MISMATCH",
            "The staged artifact inventory does not match its terminal publication receipt.",
        )
    return value


def _rename_failure(error_number: int) -> InvalidInputError:
    if error_number == errno.EEXIST:
        return _publication_error(
            "SPEC.OUTPUT_PUBLICATION_CONFLICT",
            "The final output destination appeared before publication.",
        )
    if error_number in _UNSUPPORTED_RENAME_ERRNOS:
        return _publication_error(
            "SPEC.OUTPUT_PUBLICATION_UNSUPPORTED",
            "Atomic no-replace output publication is unavailable on this platform.",
        )
    return _publication_error(
        "SPEC.OUTPUT_PUBLICATION_FAILED",
        "The staged output could not be published atomically.",
    )


def _atomic_rename_noreplace(parent_fd: int, source_name: str, destination_name: str) -> None:
    """Rename one sibling entry without replacement or a weaker fallback."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except (OSError, TypeError):
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_UNSUPPORTED",
            "Atomic no-replace output publication is unavailable on this platform.",
        ) from None
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    function: object
    arguments: tuple[object, ...]
    if sys.platform == "darwin":
        try:
            function = libc.renameatx_np
        except AttributeError:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_UNSUPPORTED",
                "Atomic no-replace output publication is unavailable on this platform.",
            ) from None
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        arguments = (
            parent_fd,
            source,
            parent_fd,
            destination,
            _DARWIN_RENAME_EXCL,
        )
    elif sys.platform.startswith("linux"):
        try:
            function = libc.renameat2
        except AttributeError:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_UNSUPPORTED",
                "Atomic no-replace output publication is unavailable on this platform.",
            ) from None
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        arguments = (
            parent_fd,
            source,
            parent_fd,
            destination,
            _LINUX_RENAME_NOREPLACE,
        )
    else:
        raise _publication_error(
            "SPEC.OUTPUT_PUBLICATION_UNSUPPORTED",
            "Atomic no-replace output publication is unavailable on this platform.",
        )
    ctypes.set_errno(0)
    result = function(*arguments)
    if result != 0:
        raise _rename_failure(ctypes.get_errno())


class VerifiedArtifact:
    """One receipt-matching artifact returned as immutable in-memory bytes."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *,
        path: str,
        content: bytes,
        sha256: str,
        byte_length: int,
        construction_token: object | None = None,
    ) -> VerifiedArtifact:
        if (
            cls is not VerifiedArtifact
            or construction_token is not _VERIFIED_VALUE_CONSTRUCTION_TOKEN
        ):
            raise _verified_read_error()
        return super().__new__(cls)

    def __init__(
        self,
        *,
        path: str,
        content: bytes,
        sha256: str,
        byte_length: int,
        construction_token: object | None = None,
    ) -> None:
        if (
            type(self) is not VerifiedArtifact
            or construction_token is not _VERIFIED_VALUE_CONSTRUCTION_TOKEN
        ):
            raise _verified_read_error()
        if not isinstance(content, bytes):
            raise _verified_read_error()
        relative = _closed_relative_path(path)
        observed_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        if (
            relative.as_posix() != path
            or not hmac.compare_digest(sha256, observed_digest)
            or byte_length != len(content)
        ):
            raise _verified_read_error()
        _VERIFIED_ARTIFACT_STATE_ISSUER.bind_once(
            self,
            (
                path,
                content,
                sha256,
                byte_length,
            ),
        )

    def __repr__(self) -> str:
        if self not in _VERIFIED_ARTIFACT_STATES:
            return "VerifiedArtifact(state='UNISSUED')"
        return (
            "VerifiedArtifact("
            "path=<redacted>, content=<redacted>, "
            "sha256=<redacted>, byte_length=<redacted>)"
        )

    @property
    def path(self) -> str:
        return _verified_artifact_state(self)[0]

    @property
    def content(self) -> bytes:
        return _verified_artifact_state(self)[1]

    @property
    def sha256(self) -> str:
        return _verified_artifact_state(self)[2]

    @property
    def byte_length(self) -> int:
        return _verified_artifact_state(self)[3]

    def __copy__(self) -> NoReturn:
        raise TypeError("Verified artifacts cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("Verified artifacts cannot be copied.")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Verified artifacts cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Verified artifacts cannot be serialized.")

    def __init_subclass__(cls, **_kwargs: object) -> NoReturn:
        raise TypeError("Verified artifacts cannot be subclassed.")


type _VerifiedArtifactState = tuple[str, bytes, str, int]
_VERIFIED_ARTIFACT_STATES: OneShotWeakRegistry[
    VerifiedArtifact,
    _VerifiedArtifactState,
]
_VERIFIED_ARTIFACT_STATE_ISSUER: OneShotRegistryIssuer[
    VerifiedArtifact,
    _VerifiedArtifactState,
]
(
    _VERIFIED_ARTIFACT_STATES,
    _VERIFIED_ARTIFACT_STATE_ISSUER,
) = create_one_shot_registry()


def _verified_artifact_state(artifact: VerifiedArtifact) -> _VerifiedArtifactState:
    if type(artifact) is not VerifiedArtifact:
        raise _verified_read_error()
    try:
        return _VERIFIED_ARTIFACT_STATES[artifact]
    except (OneShotRegistryError, TypeError):
        raise _verified_read_error() from None


class VerifiedPublishedSnapshot:
    """One complete verified read; no filesystem path is part of its trust claim."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *,
        run_status_bytes: bytes,
        artifacts: tuple[VerifiedArtifact, ...],
        construction_token: object | None = None,
    ) -> VerifiedPublishedSnapshot:
        if (
            cls is not VerifiedPublishedSnapshot
            or construction_token is not _VERIFIED_VALUE_CONSTRUCTION_TOKEN
        ):
            raise _verified_read_error()
        return super().__new__(cls)

    def __init__(
        self,
        *,
        run_status_bytes: bytes,
        artifacts: tuple[VerifiedArtifact, ...],
        construction_token: object | None = None,
    ) -> None:
        if (
            type(self) is not VerifiedPublishedSnapshot
            or construction_token is not _VERIFIED_VALUE_CONSTRUCTION_TOKEN
        ):
            raise _verified_read_error()
        if not isinstance(run_status_bytes, bytes) or not isinstance(artifacts, tuple):
            raise _verified_read_error()
        for artifact in artifacts:
            if not isinstance(artifact, VerifiedArtifact):
                raise _verified_read_error()
            _verified_artifact_state(artifact)
        _VERIFIED_SNAPSHOT_STATE_ISSUER.bind_once(
            self,
            (run_status_bytes, artifacts),
        )

    def __repr__(self) -> str:
        if self not in _VERIFIED_SNAPSHOT_STATES:
            return "VerifiedPublishedSnapshot(state='UNISSUED')"
        return (
            "VerifiedPublishedSnapshot("
            "run_status_bytes=<redacted>, artifacts=<redacted>)"
        )

    @property
    def run_status_bytes(self) -> bytes:
        return _verified_snapshot_state(self)[0]

    @property
    def artifacts(self) -> tuple[VerifiedArtifact, ...]:
        return _verified_snapshot_state(self)[1]

    def read_bytes(self, relative_path: str) -> bytes:
        """Return verified bytes for one exact receipt path."""

        relative = _closed_relative_path(relative_path)
        closed_path = relative.as_posix()
        for artifact in self.artifacts:
            if artifact.path == closed_path:
                return artifact.content
        raise KeyError(relative_path)

    def __copy__(self) -> NoReturn:
        raise TypeError("Verified snapshots cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("Verified snapshots cannot be copied.")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Verified snapshots cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Verified snapshots cannot be serialized.")

    def __init_subclass__(cls, **_kwargs: object) -> NoReturn:
        raise TypeError("Verified snapshots cannot be subclassed.")


type _VerifiedSnapshotState = tuple[bytes, tuple[VerifiedArtifact, ...]]
_VERIFIED_SNAPSHOT_STATES: OneShotWeakRegistry[
    VerifiedPublishedSnapshot,
    _VerifiedSnapshotState,
]
_VERIFIED_SNAPSHOT_STATE_ISSUER: OneShotRegistryIssuer[
    VerifiedPublishedSnapshot,
    _VerifiedSnapshotState,
]
(
    _VERIFIED_SNAPSHOT_STATES,
    _VERIFIED_SNAPSHOT_STATE_ISSUER,
) = create_one_shot_registry()


def _verified_snapshot_state(
    snapshot: VerifiedPublishedSnapshot,
) -> _VerifiedSnapshotState:
    if type(snapshot) is not VerifiedPublishedSnapshot:
        raise _verified_read_error()
    try:
        return _VERIFIED_SNAPSHOT_STATES[snapshot]
    except (OneShotRegistryError, TypeError):
        raise _verified_read_error() from None


def _read_verified_open_file(descriptor: int, expected_size: int) -> bytes:
    if expected_size < 0:
        raise _verified_read_error()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        raise _verified_read_error() from None
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        try:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
        except OSError:
            raise _verified_read_error() from None
        if not chunk:
            raise _verified_read_error()
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        if os.read(descriptor, 1):
            raise _verified_read_error()
    except OSError:
        raise _verified_read_error() from None
    return b"".join(chunks)


@dataclass(slots=True)
class _VerifiedPublishedRunState:
    parent_fd: int
    parent_path: Path
    final_name: str
    final_identity: tuple[int, int]
    root_fd: int
    run_root_id: str
    expected_status_bytes: bytes
    inventory: tuple[ArtifactInventoryEntry, ...]
    untrusted_path: Path
    lock: RLock = field(default_factory=RLock, repr=False)
    consumed: bool = False
    closed: bool = False


class VerifiedPublishedRun:
    """One-use reader for a descriptor-anchored published run."""

    __slots__ = ("__weakref__",)

    def __init__(
        self,
        *,
        parent_fd: int,
        parent_path: Path,
        final_name: str,
        final_identity: tuple[int, int],
        root_fd: int,
        run_root_id: str,
        expected_status_bytes: bytes,
        inventory: tuple[ArtifactInventoryEntry, ...],
        construction_token: object | None = None,
    ) -> None:
        if (
            type(self) is not VerifiedPublishedRun
            or construction_token is not _VERIFIED_RUN_CONSTRUCTION_TOKEN
        ):
            raise _verified_read_error()
        _VERIFIED_RUN_STATE_ISSUER.bind_once(
            self,
            _VerifiedPublishedRunState(
                parent_fd=parent_fd,
                parent_path=parent_path,
                final_name=final_name,
                final_identity=final_identity,
                root_fd=root_fd,
                run_root_id=run_root_id,
                expected_status_bytes=expected_status_bytes,
                inventory=inventory,
                untrusted_path=parent_path / final_name,
            ),
        )

    def __repr__(self) -> str:
        state = _VERIFIED_RUN_STATES.get(self)
        if state is None:
            return "VerifiedPublishedRun(state='UNISSUED')"
        with state.lock:
            label = "CLOSED" if state.closed else "REQUIRES_VERIFIED_READ"
        return f"VerifiedPublishedRun(state={label!r})"

    def __copy__(self) -> NoReturn:
        raise TypeError("Verified published runs cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("Verified published runs cannot be copied.")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Verified published runs cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Verified published runs cannot be serialized.")

    def __init_subclass__(cls, **_kwargs: object) -> NoReturn:
        raise TypeError("Verified published runs cannot be subclassed.")

    @property
    def untrusted_path(self) -> Path:
        """Return the convenience path, which is never a verified read result."""

        state = _verified_run_state(self)
        with state.lock:
            return state.untrusted_path

    @property
    def closed(self) -> bool:
        state = _verified_run_state(self)
        with state.lock:
            return state.closed

    def _verify_configured_parent_identity(self) -> None:
        state = _verified_run_state(self)
        with state.lock:
            try:
                configured_parent_fd = _open_directory_chain(
                    state.parent_path,
                    create=False,
                )
            except (FileNotFoundError, InvalidInputError):
                raise _verified_read_error() from None
            try:
                if not _same_directory(configured_parent_fd, state.parent_fd):
                    raise _verified_read_error()
            finally:
                os.close(configured_parent_fd)

    def _verify_linked_root(self) -> None:
        state = _verified_run_state(self)
        with state.lock:
            _validate_private_directory_descriptor(state.root_fd)
            observed = os.fstat(state.root_fd)
            if (observed.st_dev, observed.st_ino) != state.final_identity:
                raise _verified_read_error()
            try:
                linked = os.stat(
                    state.final_name,
                    dir_fd=state.parent_fd,
                    follow_symlinks=False,
                )
            except OSError:
                raise _verified_read_error() from None
            if (
                not stat.S_ISDIR(linked.st_mode)
                or _inventory_identity_fields(linked)
                != _inventory_identity_fields(observed)
            ):
                raise _verified_read_error()
            authenticated = _verify_run_root_authentication(
                state.root_fd,
                expected_identity=state.final_identity,
            )
            if not hmac.compare_digest(authenticated, state.run_root_id):
                raise _verified_read_error()

    def _expected_tree(
        self,
    ) -> dict[tuple[str, ...], dict[str, str]]:
        state = _verified_run_state(self)
        with state.lock:
            inventory = state.inventory
        expected: dict[tuple[str, ...], dict[str, str]] = {
            (): {
                _RUN_ROOT_KEY_NAME: "FILE",
                _RUN_ROOT_MARKER_NAME: "FILE",
                _RUN_STATUS_NAME: "FILE",
            }
        }

        def add_child(parent: tuple[str, ...], name: str, kind: str) -> None:
            children = expected.setdefault(parent, {})
            existing = children.get(name)
            if existing is not None and existing != kind:
                raise _verified_read_error()
            children[name] = kind

        for row in inventory:
            parts = tuple(PurePosixPath(row.path).parts)
            for index in range(1, len(parts)):
                directory = parts[:index]
                expected.setdefault(directory, {})
                add_child(parts[: index - 1], parts[index - 1], "DIRECTORY")
            add_child(parts[:-1], parts[-1], "FILE")
        return expected

    def _read_verified_snapshot(
        self,
        *,
        operation_token: object,
    ) -> VerifiedPublishedSnapshot:
        if operation_token is not _VERIFIED_READ_OPERATION_TOKEN:
            raise _verified_read_error()
        state = _verified_run_state(self)
        expected_tree = self._expected_tree()
        opened_files: dict[
            tuple[str, ...],
            tuple[int, os.stat_result, int, str],
        ] = {}
        opened_directories: dict[
            tuple[str, ...],
            tuple[int, os.stat_result, int | None, str | None, tuple[str, ...]],
        ] = {}
        nested_directory_fds: list[int] = []

        def walk(
            path: tuple[str, ...],
            directory_fd: int,
            parent_fd: int | None,
            name: str | None,
        ) -> None:
            _validate_private_directory_descriptor(directory_fd)
            directory_before = os.fstat(directory_fd)
            try:
                names = tuple(sorted(os.listdir(directory_fd)))
            except OSError:
                raise _verified_read_error() from None
            for observed_name in names:
                _validate_inventory_name(observed_name)
            expected_children = expected_tree.get(path)
            if expected_children is None or set(names) != set(expected_children):
                raise _verified_read_error()
            opened_directories[path] = (
                directory_fd,
                directory_before,
                parent_fd,
                name,
                names,
            )
            for child_name in names:
                try:
                    linked = os.stat(
                        child_name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except OSError:
                    raise _verified_read_error() from None
                child_path = (*path, child_name)
                if expected_children[child_name] == "DIRECTORY":
                    if not stat.S_ISDIR(linked.st_mode):
                        raise _verified_read_error()
                    try:
                        child_fd = os.open(
                            child_name,
                            _DIRECTORY_OPEN_FLAGS,
                            dir_fd=directory_fd,
                        )
                    except OSError:
                        raise _verified_read_error() from None
                    nested_directory_fds.append(child_fd)
                    opened = os.fstat(child_fd)
                    if _inventory_identity_fields(opened) != _inventory_identity_fields(
                        linked
                    ):
                        raise _verified_read_error()
                    walk(child_path, child_fd, directory_fd, child_name)
                    continue
                if not stat.S_ISREG(linked.st_mode):
                    raise _verified_read_error()
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    file_fd = os.open(child_name, flags, dir_fd=directory_fd)
                except OSError:
                    raise _verified_read_error() from None
                try:
                    opened = os.fstat(file_fd)
                    owner_matches = (
                        not hasattr(os, "geteuid") or opened.st_uid == os.geteuid()
                    )
                    if (
                        _inventory_identity_fields(opened)
                        != _inventory_identity_fields(linked)
                        or not stat.S_ISREG(opened.st_mode)
                        or stat.S_IMODE(opened.st_mode) != 0o600
                        or opened.st_nlink != 1
                        or not owner_matches
                        or opened.st_size < 0
                    ):
                        raise _verified_read_error()
                    opened_files[child_path] = (
                        file_fd,
                        opened,
                        directory_fd,
                        child_name,
                    )
                except BaseException:
                    os.close(file_fd)
                    raise

        try:
            self._verify_configured_parent_identity()
            self._verify_linked_root()
            walk((), state.root_fd, state.parent_fd, state.final_name)
            self._verify_linked_root()

            status_entry = opened_files.get((_RUN_STATUS_NAME,))
            if status_entry is None:
                raise _verified_read_error()
            status_fd, status_before, _, _ = status_entry
            if status_before.st_size > _MAXIMUM_RUN_STATUS_BYTES:
                raise _verified_read_error()
            status_bytes = _read_verified_open_file(status_fd, status_before.st_size)
            if not hmac.compare_digest(status_bytes, state.expected_status_bytes):
                raise _verified_read_error()
            status = _strict_json_object(status_bytes)
            _validate_publication_receipt(
                status.get("publication"),
                expected_run_root_id=state.run_root_id,
                actual_inventory=state.inventory,
            )

            verified_artifacts: list[VerifiedArtifact] = []
            for row in state.inventory:
                parts = tuple(PurePosixPath(row.path).parts)
                opened_entry = opened_files.get(parts)
                if opened_entry is None:
                    raise _verified_read_error()
                file_fd, before, _, _ = opened_entry
                if before.st_size != row.byte_length:
                    raise _verified_read_error()
                content = _read_verified_open_file(file_fd, row.byte_length)
                digest = "sha256:" + hashlib.sha256(content).hexdigest()
                if not hmac.compare_digest(digest, row.sha256):
                    raise _verified_read_error()
                verified_artifacts.append(
                    VerifiedArtifact(
                        path=row.path,
                        content=content,
                        sha256=digest,
                        byte_length=len(content),
                        construction_token=_VERIFIED_VALUE_CONSTRUCTION_TOKEN,
                    )
                )

            for _, (file_fd, before, parent_fd, name) in opened_files.items():
                after = os.fstat(file_fd)
                try:
                    linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError:
                    raise _verified_read_error() from None
                if (
                    _inventory_identity_fields(after)
                    != _inventory_identity_fields(before)
                    or _inventory_identity_fields(linked)
                    != _inventory_identity_fields(before)
                ):
                    raise _verified_read_error()

            for _, (
                directory_fd,
                before,
                directory_parent_fd,
                directory_name,
                initial_names,
            ) in opened_directories.items():
                after = os.fstat(directory_fd)
                try:
                    final_names = tuple(sorted(os.listdir(directory_fd)))
                except OSError:
                    raise _verified_read_error() from None
                if (
                    final_names != initial_names
                    or _inventory_identity_fields(after)
                    != _inventory_identity_fields(before)
                ):
                    raise _verified_read_error()
                if directory_parent_fd is not None and directory_name is not None:
                    try:
                        linked = os.stat(
                            directory_name,
                            dir_fd=directory_parent_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        raise _verified_read_error() from None
                    if _inventory_identity_fields(linked) != _inventory_identity_fields(
                        before
                    ):
                        raise _verified_read_error()

            self._verify_linked_root()
            self._verify_configured_parent_identity()
            return VerifiedPublishedSnapshot(
                run_status_bytes=status_bytes,
                artifacts=tuple(verified_artifacts),
                construction_token=_VERIFIED_VALUE_CONSTRUCTION_TOKEN,
            )
        finally:
            for file_fd, _, _, _ in opened_files.values():
                with suppress(OSError):
                    os.close(file_fd)
            for directory_fd in reversed(nested_directory_fds):
                with suppress(OSError):
                    os.close(directory_fd)

    def read_verified(self) -> VerifiedPublishedSnapshot:
        """Consume this handle and return bytes only after complete verification."""

        state = _verified_run_state(self)
        with state.lock:
            if state.closed or state.consumed:
                raise _verified_read_error()
            state.consumed = True
            try:
                return self._read_verified_snapshot(
                    operation_token=_VERIFIED_READ_OPERATION_TOKEN,
                )
            except (InvalidInputError, OSError):
                raise _verified_read_error() from None
            finally:
                self.close()

    def close(self) -> None:
        """Close retained descriptors; no unverified bytes are returned."""

        state = _verified_run_state(self)
        with state.lock:
            if state.closed:
                return
            state.closed = True
            parent_fd = state.parent_fd
            root_fd = state.root_fd
            state.parent_fd = -1
            state.root_fd = -1
            with suppress(OSError):
                os.close(root_fd)
            with suppress(OSError):
                os.close(parent_fd)

    def __enter__(self) -> VerifiedPublishedRun:
        state = _verified_run_state(self)
        with state.lock:
            if state.closed:
                raise _verified_read_error()
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()


_VERIFIED_RUN_STATES: OneShotWeakRegistry[
    VerifiedPublishedRun,
    _VerifiedPublishedRunState,
]
_VERIFIED_RUN_STATE_ISSUER: OneShotRegistryIssuer[
    VerifiedPublishedRun,
    _VerifiedPublishedRunState,
]
(
    _VERIFIED_RUN_STATES,
    _VERIFIED_RUN_STATE_ISSUER,
) = create_one_shot_registry()


def _verified_run_state(
    published_run: VerifiedPublishedRun,
) -> _VerifiedPublishedRunState:
    if type(published_run) is not VerifiedPublishedRun:
        raise _verified_read_error()
    try:
        return _VERIFIED_RUN_STATES[published_run]
    except (OneShotRegistryError, TypeError):
        raise _verified_read_error() from None


@dataclass(slots=True)
class _StagedOutputTransactionState:
    parent_fd: int
    parent_path: Path
    final_path: Path
    final_name: str
    staging_name: str
    staging_path: Path
    staging_identity: tuple[int, int]
    staging_run_root_id: str
    store: PrivateArtifactStore | None
    lock: RLock = field(default_factory=RLock, repr=False)
    publish_attempted: bool = False
    publishing: bool = False
    close_requested: bool = False
    renamed: bool = False
    published_requires_verified_read: bool = False
    durability_unknown: bool = False
    closed: bool = False


def _staged_state_label(state: _StagedOutputTransactionState) -> str:
    if state.closed:
        return "CLOSED"
    if state.durability_unknown:
        return "DURABILITY_UNKNOWN"
    if state.published_requires_verified_read:
        return "PUBLISHED_REQUIRES_VERIFIED_READ"
    if state.renamed:
        return "PUBLISHED_REVALIDATION_FAILED"
    if state.publish_attempted:
        return "STAGED_PUBLICATION_FAILED"
    return "STAGED"


def _close_staged_state_locked(state: _StagedOutputTransactionState) -> None:
    if state.closed:
        return
    state.closed = True
    state.close_requested = False
    parent_fd = state.parent_fd
    state.parent_fd = -1
    with suppress(OSError):
        os.close(parent_fd)


class StagedOutputTransaction:
    """Own one unique staging root and publish it exactly once."""

    __slots__ = ("__weakref__",)

    def __init__(
        self,
        *,
        parent_fd: int,
        parent_path: Path,
        final_path: Path,
        staging_name: str,
        staging_identity: tuple[int, int],
        staging_run_root_id: str,
        store: PrivateArtifactStore,
        construction_token: object | None = None,
    ) -> None:
        if (
            type(self) is not StagedOutputTransaction
            or construction_token is not _TRANSACTION_CONSTRUCTION_TOKEN
        ):
            raise _publication_error(
                "SPEC.OUTPUT_TRANSACTION_STATE",
                "Staged output transactions must be created with create().",
            )
        _STAGED_TRANSACTION_STATE_ISSUER.bind_once(
            self,
            _StagedOutputTransactionState(
                parent_fd=parent_fd,
                parent_path=parent_path,
                final_path=final_path,
                final_name=final_path.name,
                staging_name=staging_name,
                staging_path=parent_path / staging_name,
                staging_identity=staging_identity,
                staging_run_root_id=staging_run_root_id,
                store=store,
            ),
        )

    def __repr__(self) -> str:
        state = _STAGED_TRANSACTION_STATES.get(self)
        if state is None:
            return "StagedOutputTransaction(state='UNISSUED')"
        with state.lock:
            label = _staged_state_label(state)
        return f"StagedOutputTransaction(state={label!r})"

    def __copy__(self) -> NoReturn:
        raise TypeError("Staged output transactions cannot be copied.")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("Staged output transactions cannot be copied.")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Staged output transactions cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("Staged output transactions cannot be serialized.")

    def __init_subclass__(cls, **_kwargs: object) -> NoReturn:
        raise TypeError("Staged output transactions cannot be subclassed.")

    @classmethod
    def create(cls, final_output_path: Path) -> StagedOutputTransaction:
        if cls is not StagedOutputTransaction:
            raise _publication_error(
                "SPEC.OUTPUT_TRANSACTION_STATE",
                "Staged output transactions must be created with create().",
            )
        final_path = _closed_final_output_path(final_output_path)
        parent_path = final_path.parent
        try:
            parent_fd = _open_directory_chain(parent_path, create=False)
        except FileNotFoundError:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_PATH",
                "The configured final output parent does not exist.",
            ) from None
        try:
            try:
                os.stat(final_path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_PATH",
                    "The configured final output destination could not be inspected.",
                ) from None
            else:
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_CONFLICT",
                    "The final output destination already exists.",
                )
            try:
                staging_name = ".ebm-audit-stage-" + os.urandom(16).hex()
            except OSError:
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_FAILED",
                    "A unique private staging root could not be created.",
                ) from None
            store = PrivateArtifactStore._open_fresh_at(
                parent_fd,
                parent_path,
                staging_name,
            )
            try:
                observed = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_FAILED",
                    "The authenticated private staging root could not be retained.",
                ) from None
            if (
                not stat.S_ISDIR(observed.st_mode)
                or stat.S_IMODE(observed.st_mode) != 0o700
                or (hasattr(os, "geteuid") and observed.st_uid != os.geteuid())
            ):
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_FAILED",
                    "The authenticated private staging root could not be retained.",
                )
            return cls(
                parent_fd=parent_fd,
                parent_path=parent_path,
                final_path=final_path,
                staging_name=staging_name,
                staging_identity=(observed.st_dev, observed.st_ino),
                staging_run_root_id=store.run_root_id,
                store=store,
                construction_token=_TRANSACTION_CONSTRUCTION_TOKEN,
            )
        except BaseException:
            os.close(parent_fd)
            raise

    @property
    def store(self) -> PrivateArtifactStore:
        state = _staged_transaction_state(self)
        with state.lock:
            if state.closed or state.store is None:
                raise _publication_error(
                    "SPEC.OUTPUT_TRANSACTION_STATE",
                    "The staged artifact store is no longer available.",
                )
            return state.store

    @property
    def staging_root(self) -> Path:
        state = _staged_transaction_state(self)
        with state.lock:
            return state.staging_path

    @property
    def final_output_path(self) -> Path:
        """Return the final convenience path, which is not a verified read."""

        state = _staged_transaction_state(self)
        with state.lock:
            return state.final_path

    @property
    def run_root_id(self) -> str:
        state = _staged_transaction_state(self)
        with state.lock:
            return state.staging_run_root_id

    @property
    def closed(self) -> bool:
        state = _staged_transaction_state(self)
        with state.lock:
            return state.closed

    @property
    def state(self) -> str:
        state = _staged_transaction_state(self)
        with state.lock:
            return _staged_state_label(state)

    def publication_receipt(self) -> dict[str, object]:
        state = _staged_transaction_state(self)
        with state.lock:
            if state.closed or state.renamed or state.publish_attempted:
                raise _publication_error(
                    "SPEC.OUTPUT_TRANSACTION_STATE",
                    "The staged publication receipt cannot be created in this transaction state.",
                )
            if state.store is None:
                raise _publication_error(
                    "SPEC.OUTPUT_TRANSACTION_STATE",
                    "The staged artifact store is no longer available.",
                )
            inventory = state.store.inventory(exclude_run_status=True)
            return _publication_receipt(
                run_root_id=state.staging_run_root_id,
                inventory=inventory,
            )

    def _verify_configured_parent_identity(self) -> None:
        state = _staged_transaction_state(self)
        try:
            configured_parent_fd = _open_directory_chain(state.parent_path, create=False)
        except (FileNotFoundError, InvalidInputError):
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_PARENT_CHANGED",
                "The configured final output parent changed before publication completed.",
            ) from None
        try:
            if not _same_directory(configured_parent_fd, state.parent_fd):
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_PARENT_CHANGED",
                    "The configured final output parent changed before publication completed.",
                )
        finally:
            os.close(configured_parent_fd)

    def _linked_entry_state(self, name: str) -> str:
        state = _staged_transaction_state(self)
        try:
            observed = os.stat(name, dir_fd=state.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "ABSENT"
        except OSError:
            return "UNKNOWN"
        if (
            stat.S_ISDIR(observed.st_mode)
            and (observed.st_dev, observed.st_ino) == state.staging_identity
            and stat.S_IMODE(observed.st_mode) == 0o700
            and (not hasattr(os, "geteuid") or observed.st_uid == os.geteuid())
        ):
            return "OWNED"
        return "OTHER"

    def _mark_renamed_durability_unknown(self) -> None:
        state = _staged_transaction_state(self)
        with state.lock:
            state.store = None
            state.renamed = True
            state.durability_unknown = True

    def _reconcile_after_rename_attempt(self) -> bool:
        state = _staged_transaction_state(self)
        with state.lock:
            source_state = self._linked_entry_state(state.staging_name)
            destination_state = self._linked_entry_state(state.final_name)
            if source_state == "OWNED" and destination_state != "OWNED":
                return False
            if source_state == "ABSENT" and destination_state == "OWNED":
                self._mark_renamed_durability_unknown()
                return True
            if source_state != "OWNED":
                state.store = None
            state.durability_unknown = True
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_IDENTITY",
                "The staged publication link state could not be reconciled safely.",
            )

    def _verify_linked_root(self, root_fd: int, name: str) -> None:
        state = _staged_transaction_state(self)
        _validate_private_directory_descriptor(root_fd)
        observed = os.fstat(root_fd)
        if (observed.st_dev, observed.st_ino) != state.staging_identity:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_IDENTITY",
                "The authenticated publication root identity changed.",
            )
        try:
            linked = os.stat(name, dir_fd=state.parent_fd, follow_symlinks=False)
        except OSError:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_IDENTITY",
                "The authenticated publication root identity changed.",
            ) from None
        if (
            not stat.S_ISDIR(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != state.staging_identity
            or stat.S_IMODE(linked.st_mode) != 0o700
            or (hasattr(os, "geteuid") and linked.st_uid != os.geteuid())
        ):
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_IDENTITY",
                "The authenticated publication root identity changed.",
            )
        authenticated = _verify_run_root_authentication(
            root_fd,
            expected_identity=state.staging_identity,
        )
        if not hmac.compare_digest(authenticated, state.staging_run_root_id):
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_IDENTITY",
                "The authenticated publication root identity changed.",
            )

    def _open_linked_root(self, name: str) -> int:
        state = _staged_transaction_state(self)
        try:
            descriptor = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=state.parent_fd)
        except OSError:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_IDENTITY",
                "The authenticated publication root identity changed.",
            ) from None
        try:
            self._verify_linked_root(descriptor, name)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _terminal_snapshot(
        self,
        root_fd: int,
        linked_name: str,
        validate_terminal_run_status: TerminalRunStatusValidator | None = None,
    ) -> tuple[bytes, dict[str, object], tuple[ArtifactInventoryEntry, ...]]:
        state = _staged_transaction_state(self)
        self._verify_linked_root(root_fd, linked_name)
        status_bytes = _read_private_existing_at(
            root_fd,
            _RUN_STATUS_NAME,
            maximum_bytes=_MAXIMUM_RUN_STATUS_BYTES,
            verify_directory=lambda: self._verify_linked_root(root_fd, linked_name),
        )
        status = _strict_json_object(status_bytes)
        if validate_terminal_run_status is not None:
            _validate_terminal_authority(validate_terminal_run_status, status_bytes)
        inventory = _private_artifact_inventory_at(root_fd, exclude_run_status=True)
        publication = _validate_publication_receipt(
            status.get("publication"),
            expected_run_root_id=state.staging_run_root_id,
            actual_inventory=inventory,
        )
        self._verify_linked_root(root_fd, linked_name)
        return status_bytes, publication, inventory

    def publish_terminal_receipt(
        self,
        *,
        validate_terminal_run_status: TerminalRunStatusValidator,
    ) -> VerifiedPublishedRun:
        """Publish a named tree and return its only trusted read boundary."""

        state = _staged_transaction_state(self)
        with state.lock:
            if state.publishing:
                raise _publication_error(
                    "SPEC.OUTPUT_TRANSACTION_STATE",
                    "This staged output transaction is already publishing.",
                )
            state.publishing = True
            try:
                return self._publish_terminal_receipt_locked(
                    validate_terminal_run_status=validate_terminal_run_status,
                    operation_token=_STAGED_PUBLISH_OPERATION_TOKEN,
                )
            finally:
                state.publishing = False
                if state.close_requested:
                    _close_staged_state_locked(state)

    def _publish_terminal_receipt_locked(
        self,
        *,
        validate_terminal_run_status: TerminalRunStatusValidator,
        operation_token: object,
    ) -> VerifiedPublishedRun:
        if operation_token is not _STAGED_PUBLISH_OPERATION_TOKEN:
            raise _publication_error(
                "SPEC.OUTPUT_TRANSACTION_STATE",
                "The staged publication operation is not authority-issued.",
            )
        state = _staged_transaction_state(self)
        if state.closed or state.publish_attempted:
            raise _publication_error(
                "SPEC.OUTPUT_TRANSACTION_STATE",
                "This staged output transaction cannot publish more than once.",
            )
        state.publish_attempted = True
        _terminal_validator_state(validate_terminal_run_status)
        staging_fd: int | None = None
        try:
            self._verify_configured_parent_identity()
            staging_fd = self._open_linked_root(state.staging_name)
            before_status, before_publication, before_inventory = self._terminal_snapshot(
                staging_fd,
                state.staging_name,
                validate_terminal_run_status,
            )
            _fsync_private_artifact_tree_at(
                staging_fd,
                expected_inventory=before_inventory,
                exclude_run_status=True,
            )
            synced_status, synced_publication, synced_inventory = self._terminal_snapshot(
                staging_fd,
                state.staging_name,
            )
            if (
                synced_status != before_status
                or synced_publication != before_publication
                or synced_inventory != before_inventory
            ):
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_INVENTORY_MISMATCH",
                    "The staged output changed while it was synchronized for publication.",
                )
            self._verify_linked_root(staging_fd, state.staging_name)
            self._verify_configured_parent_identity()
            try:
                _atomic_rename_noreplace(
                    state.parent_fd,
                    state.staging_name,
                    state.final_name,
                )
            except BaseException:
                try:
                    self._reconcile_after_rename_attempt()
                except BaseException:
                    state.store = None
                    state.durability_unknown = True
                raise
            self._mark_renamed_durability_unknown()
            if not self._reconcile_after_rename_attempt():
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_FAILED",
                    "The staged output did not reach the final publication entry.",
                )
        finally:
            if staging_fd is not None:
                os.close(staging_fd)

        try:
            os.fsync(state.parent_fd)
            state.durability_unknown = False
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            state.durability_unknown = True
            raise
        except OSError:
            state.durability_unknown = True
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_DURABILITY_UNKNOWN",
                "The final output was renamed, but publication durability is unknown.",
            ) from None

        self._verify_configured_parent_identity()
        final_fd: int | None = None
        verified_run: VerifiedPublishedRun | None = None
        try:
            final_fd = self._open_linked_root(state.final_name)
            after_status, after_publication, after_inventory = self._terminal_snapshot(
                final_fd,
                state.final_name,
            )
            if (
                after_status != before_status
                or after_publication != before_publication
                or after_inventory != before_inventory
            ):
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_REVALIDATION",
                    "The published output did not match the verified staged output.",
                )
            self._verify_configured_parent_identity()
            try:
                retained_parent_fd = os.dup(state.parent_fd)
            except OSError:
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_REVALIDATION",
                    "The published output could not retain its verified-read authority.",
                ) from None
            try:
                retained_root_fd = os.dup(final_fd)
            except OSError:
                os.close(retained_parent_fd)
                raise _publication_error(
                    "SPEC.OUTPUT_PUBLICATION_REVALIDATION",
                    "The published output could not retain its verified-read authority.",
                ) from None
            try:
                verified_run = VerifiedPublishedRun(
                    parent_fd=retained_parent_fd,
                    parent_path=state.parent_path,
                    final_name=state.final_name,
                    final_identity=state.staging_identity,
                    root_fd=retained_root_fd,
                    run_root_id=state.staging_run_root_id,
                    expected_status_bytes=before_status,
                    inventory=before_inventory,
                    construction_token=_VERIFIED_RUN_CONSTRUCTION_TOKEN,
                )
            except BaseException:
                os.close(retained_root_fd)
                os.close(retained_parent_fd)
                raise
        except (InvalidInputError, OSError):
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_REVALIDATION",
                "The published output could not be revalidated.",
            ) from None
        finally:
            if final_fd is not None:
                os.close(final_fd)
        if verified_run is None:
            raise _publication_error(
                "SPEC.OUTPUT_PUBLICATION_REVALIDATION",
                "The published output could not retain its verified-read authority.",
            )
        state.published_requires_verified_read = True
        return verified_run

    def close(self) -> None:
        """Close retained descriptors without deleting staged or final output."""

        state = _staged_transaction_state(self)
        with state.lock:
            if state.publishing:
                state.close_requested = True
                return
            _close_staged_state_locked(state)

    def __enter__(self) -> StagedOutputTransaction:
        state = _staged_transaction_state(self)
        with state.lock:
            if state.closed:
                raise _publication_error(
                    "SPEC.OUTPUT_TRANSACTION_STATE",
                    "The staged output transaction is already closed.",
                )
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()


_STAGED_TRANSACTION_STATES: OneShotWeakRegistry[
    StagedOutputTransaction,
    _StagedOutputTransactionState,
]
_STAGED_TRANSACTION_STATE_ISSUER: OneShotRegistryIssuer[
    StagedOutputTransaction,
    _StagedOutputTransactionState,
]
(
    _STAGED_TRANSACTION_STATES,
    _STAGED_TRANSACTION_STATE_ISSUER,
) = create_one_shot_registry()


def _staged_transaction_state(
    transaction: StagedOutputTransaction,
) -> _StagedOutputTransactionState:
    if type(transaction) is not StagedOutputTransaction:
        raise _publication_error(
            "SPEC.OUTPUT_TRANSACTION_STATE",
            "The staged output transaction is not authority-issued.",
        )
    try:
        return _STAGED_TRANSACTION_STATES[transaction]
    except (OneShotRegistryError, TypeError):
        raise _publication_error(
            "SPEC.OUTPUT_TRANSACTION_STATE",
            "The staged output transaction is not authority-issued.",
        ) from None
