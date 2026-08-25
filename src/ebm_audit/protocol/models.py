"""Small immutable protocol records used at the filesystem boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class WorkerCommand(StrEnum):
    DESCRIBE = "describe"
    VALIDATE = "validate"
    FIT = "fit"
    STAGE = "stage"
    SELF_TEST = "self-test"


class WorkerStatus(StrEnum):
    SUCCESS = "SUCCESS"
    INVALID_INPUT = "INVALID_INPUT"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    INVALID_SPECIFICATION = "INVALID_SPECIFICATION"
    BACKEND_ERROR = "BACKEND_ERROR"
    TIMEOUT = "TIMEOUT"
    PRIVACY_VIOLATION = "PRIVACY_VIOLATION"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"


@dataclass(frozen=True, slots=True, order=True)
class FileRecord:
    byte_length: int
    sha256: str

    def __post_init__(self) -> None:
        if isinstance(self.byte_length, bool) or not isinstance(self.byte_length, int):
            raise TypeError("byte_length must be an integer")
        if not 0 <= self.byte_length <= (1 << 53) - 1:
            raise ValueError("byte_length is outside the safe nonnegative range")
        if not isinstance(self.sha256, str) or _SHA256_DIGEST.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must be a prefixed lowercase SHA-256 digest")

    def to_mapping(self) -> dict[str, object]:
        return {"byte_length": self.byte_length, "sha256": self.sha256}

    @classmethod
    def from_mapping(cls, value: object) -> FileRecord:
        if not isinstance(value, Mapping) or set(value) != {"byte_length", "sha256"}:
            raise ValueError("file record has an invalid closed shape")
        return cls(byte_length=value["byte_length"], sha256=value["sha256"])


@dataclass(frozen=True, slots=True)
class BundleSnapshot:
    entries: tuple[tuple[str, FileRecord], ...]

    def __post_init__(self) -> None:
        paths = tuple(path for path, _record in self.entries)
        if paths != tuple(sorted(paths, key=lambda value: value.encode("utf-8"))):
            raise ValueError("bundle snapshot entries must use UTF-8 path order")
        if len(set(paths)) != len(paths):
            raise ValueError("bundle snapshot contains duplicate paths")

    def as_mapping(self) -> Mapping[str, FileRecord]:
        return MappingProxyType(dict(self.entries))


@dataclass(frozen=True, slots=True)
class WorkerRequestFrame:
    command: WorkerCommand
    request_id: str
    request_metadata_digest: str
    scientific_request_digest: str | None
    metadata_bytes: bytes
    snapshot: BundleSnapshot

    @property
    def request(self) -> dict[str, Any]:
        """Return a fresh mutable copy parsed from the verified metadata bytes."""

        from .canonical import strict_json_loads

        value = strict_json_loads(self.metadata_bytes)
        if not isinstance(value, dict):  # guaranteed by the framing constructor
            raise TypeError("Verified request metadata is not an object.")
        return value


@dataclass(frozen=True, slots=True)
class WorkerResponseFrame:
    command: WorkerCommand
    status: WorkerStatus
    request_id: str
    response_metadata_digest: str
    metadata_bytes: bytes
    snapshot: BundleSnapshot

    @property
    def response(self) -> dict[str, Any]:
        """Return a fresh mutable copy parsed from the verified metadata bytes."""

        from .canonical import strict_json_loads

        value = strict_json_loads(self.metadata_bytes)
        if not isinstance(value, dict):  # guaranteed by the framing constructor
            raise TypeError("Verified response metadata is not an object.")
        return value


JsonMapping = Mapping[str, Any]
