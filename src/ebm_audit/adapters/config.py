"""Configuration for shell-free local worker invocation."""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast, final

from ebm_audit.config.strict_yaml import StrictYamlError, load_strict_yaml_bytes
from ebm_audit.errors import InvalidInputError, WorkerUnavailableError
from ebm_audit.protocol import (
    canonical_json_bytes,
    validate_expected_identity_pin,
)

_CONFIG_FIELDS = frozenset({"worker", "algorithm_id", "settings", "expected_identity"})
_WORKER_FIELDS = frozenset({"argv"})
_MAX_CONFIG_BYTES = 256 * 1024


@final
@dataclass(frozen=True)
class WorkerCommand:
    """An already-tokenized command; it is never interpreted by a shell."""

    argv: tuple[str, ...]

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("WorkerCommand cannot be subclassed.")

    def __post_init__(self) -> None:
        argv = tuple(self.argv)
        if not argv:
            raise InvalidInputError(
                "SPEC.WORKER_COMMAND_EMPTY",
                "A worker command is required.",
            )
        if any(not isinstance(token, str) or not token or "\x00" in token for token in argv):
            raise InvalidInputError(
                "SPEC.WORKER_COMMAND_TOKEN_INVALID",
                "Every worker command token must be non-empty and contain no NUL byte.",
            )
        object.__setattr__(self, "argv", argv)

    @classmethod
    def from_tokens(cls, tokens: Iterable[str]) -> WorkerCommand:
        argv = cls(tuple(tokens)).argv

        executable = argv[0]
        resolved: str | None
        if Path(executable).is_absolute():
            resolved = executable if Path(executable).is_file() else None
        else:
            resolved = shutil.which(executable)
        if resolved is None:
            raise WorkerUnavailableError()
        # Preserve a virtual-environment launcher path. Resolving its symlink to
        # the base interpreter would silently discard that environment's locked
        # site-packages. Every non-executable token is retained byte-for-byte:
        # guessing that an existing token is a path made the command depend on
        # the caller's current working directory. Path arguments must therefore
        # already be absolute when the worker needs them from its isolated cwd.
        return cls((str(Path(resolved).absolute()), *argv[1:]))

    def protocol_argv(
        self,
        *,
        command: str,
        request_dir: Path,
        response_dir: Path,
    ) -> list[str]:
        return [
            *self.argv,
            "--protocol",
            "ebm-audit-worker/v2",
            "--command",
            command,
            "--request-dir",
            str(request_dir.resolve()),
            "--response-dir",
            str(response_dir.resolve()),
        ]


def _validated_worker_command_snapshot(value: object) -> WorkerCommand:
    """Return a fresh exact command after rerunning its token validation."""

    if type(value) is not WorkerCommand:
        raise TypeError("An exact WorkerCommand is required.")
    try:
        argv = value.argv
    except AttributeError:
        raise TypeError("A valid WorkerCommand is required.") from None
    return WorkerCommand(argv)


@dataclass(frozen=True)
class WorkerConfig:
    """Closed local YAML configuration for one external worker algorithm."""

    worker: WorkerCommand
    algorithm_id: str
    settings: Mapping[str, Any]
    expected_identity: Mapping[str, Any] | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker", _validated_worker_command_snapshot(self.worker))

    @classmethod
    def from_yaml(cls, path: Path) -> WorkerConfig:
        try:
            raw = path.read_bytes()
        except OSError:
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_UNREADABLE",
                "The worker configuration could not be read.",
            ) from None
        return cls.from_yaml_bytes(raw)

    @classmethod
    def from_yaml_bytes(
        cls,
        raw: bytes | bytearray | memoryview,
    ) -> WorkerConfig:
        """Parse already-authenticated exact worker-config bytes."""

        try:
            decoded = load_strict_yaml_bytes(raw, maximum_bytes=_MAX_CONFIG_BYTES)
        except StrictYamlError:
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_YAML",
                "The worker configuration is not valid strict JSON-model YAML.",
            ) from None
        if not isinstance(decoded, Mapping) or set(decoded) != _CONFIG_FIELDS:
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_SHAPE",
                "The worker configuration must contain exactly the documented fields.",
            )
        worker_value = decoded.get("worker")
        if not isinstance(worker_value, Mapping) or set(worker_value) != _WORKER_FIELDS:
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_COMMAND",
                "The worker configuration must contain one exact argv array.",
            )
        argv_value = worker_value.get("argv")
        if not isinstance(argv_value, list) or any(
            not isinstance(token, str) for token in argv_value
        ):
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_COMMAND",
                "The worker argv must be an array of string tokens.",
            )
        if not argv_value or not Path(argv_value[0]).is_absolute():
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_COMMAND",
                "The configured worker executable must be an absolute argv token.",
            )
        algorithm_id = decoded.get("algorithm_id")
        if not isinstance(algorithm_id, str) or not algorithm_id or "\x00" in algorithm_id:
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_ALGORITHM",
                "The worker configuration must name one algorithm.",
            )
        settings = decoded.get("settings")
        if not isinstance(settings, Mapping):
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_SETTINGS",
                "Worker settings must be a JSON object.",
            )
        expected_identity = decoded.get("expected_identity")
        if expected_identity is not None and not isinstance(expected_identity, Mapping):
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_IDENTITY",
                "The expected worker identity must be an object or null.",
            )
        try:
            canonical_json_bytes(settings)
            if expected_identity is not None:
                canonical_json_bytes(expected_identity)
                validated_identity = validate_expected_identity_pin(expected_identity)
                if validated_identity["selected_algorithm_id"] != algorithm_id:
                    raise ValueError
        except Exception:
            raise InvalidInputError(
                "SPEC.WORKER_CONFIG_VALUE",
                "The worker configuration contains a value outside its closed contract.",
            ) from None
        return cls(
            worker=WorkerCommand.from_tokens(cast(list[str], argv_value)),
            algorithm_id=algorithm_id,
            settings=dict(cast(Mapping[str, Any], settings)),
            expected_identity=(
                None
                if expected_identity is None
                else dict(cast(Mapping[str, Any], expected_identity))
            ),
        )
