"""Local reproducibility recipes, never persisted scientific authorities.

A recipe contains hashes, not runnable configuration or participant evidence.
Replaying requires the original private config and fresh ordinary verification.
"""

from __future__ import annotations

import os
import platform
import re
import stat
import sys
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ebm_audit import __version__
from ebm_audit.artifacts import PrivateArtifactStore, ensure_private_directory, write_private_new
from ebm_audit.artifacts.store import _open_directory_chain
from ebm_audit.config import VerifiedAuditConfigFiles, parse_audit_config
from ebm_audit.config.verification import _read_verified_source_config_binding
from ebm_audit.errors import AuditError, InvalidInputError
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
)

if TYPE_CHECKING:
    from ebm_audit.errors import ExitCode
    from ebm_audit.runner import ExecutionControl

REPLAY_PATH = "replay.json"
ATTEMPT_PATH = "attempt-status.json"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BINDING_DIGESTS = frozenset(
    {
        "configuration_digest",
        "input_digest",
        "worker_config_digest",
        "worker_identity_digest",
        "file_roles_digest",
        "randomness_digest",
        "environment_digest",
    }
)


def replay_directory(run_dir: Path) -> Path:
    """Operational sidecars live beside the closed scientific publication."""

    return run_dir.with_name(run_dir.name + ".operations")


def _invalid() -> InvalidInputError:
    return InvalidInputError("REPLAY.INVALID", "The local replay record is invalid or unavailable.")


def read_private_bytes(path: Path, *, maximum_bytes: int = 65536) -> bytes:
    """Read one bounded regular private file without following any symlink."""

    directory: int | None = None
    descriptor: int | None = None
    try:
        directory = _open_directory_chain(path.absolute().parent, create=False)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise _invalid()
        chunks = bytearray()
        while len(chunks) <= maximum_bytes:
            chunk = os.read(descriptor, min(65536, maximum_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        at_path = os.stat(path.name, dir_fd=directory, follow_symlinks=False)

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_uid,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if (
            identity(before) != identity(after)
            or identity(before) != identity(at_path)
            or len(chunks) != before.st_size
        ):
            raise _invalid()
        return bytes(chunks)
    except (OSError, ValueError, TypeError, RecursionError, AuditError):
        raise _invalid() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def read_private_json(path: Path, *, maximum_bytes: int = 65536) -> Any:
    try:
        return strict_json_loads(read_private_bytes(path, maximum_bytes=maximum_bytes))
    except (CanonicalizationError, ValueError, TypeError, RecursionError):
        raise _invalid() from None


def load_replay_manifest(path: Path) -> dict[str, Any]:
    record = read_private_json(path)
    keys = {
        "schema_version",
        "bindings",
        "plan_digest",
        "source_run_root_id",
        "parent_manifest_digest",
        "manifest_digest",
    }
    if (
        type(record) is not dict
        or set(record) != keys
        or record["schema_version"] != "anim-replay/1"
    ):
        raise _invalid()
    bindings = record["bindings"]
    if type(bindings) is not dict or set(bindings) != _BINDING_DIGESTS | {"profile_id"}:
        raise _invalid()
    if bindings["profile_id"] not in ("quick", "full", "release"):
        raise _invalid()
    digests = [bindings[key] for key in _BINDING_DIGESTS]
    digests.extend((record["plan_digest"], record["source_run_root_id"], record["manifest_digest"]))
    if record["parent_manifest_digest"] is not None:
        digests.append(record["parent_manifest_digest"])
    if any(type(value) is not str or _DIGEST.fullmatch(value) is None for value in digests):
        raise _invalid()
    preimage = {key: value for key, value in record.items() if key != "manifest_digest"}
    if structured_sha256("anim/replay/1", preimage) != record["manifest_digest"]:
        raise _invalid()
    return record


def environment_digest() -> str:
    """Fingerprint runtime, declared dependencies, code and normative resources.

    Deliberately never enumerate environment variables or unrelated installed
    applications. Numerical thread settings enter only this opaque digest.
    """

    dependency_names = (
        "attrs",
        "jsonschema",
        "jsonschema-specifications",
        "numpy",
        "PyYAML",
        "referencing",
        "rfc8785",
        "rpds-py",
        "typing-extensions",
    )
    from ebm_audit.adapters.invocation import _core_code_digest

    numerical_environment = {
        name: os.environ.get(name)
        for name in (
            "OMP_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
            "MKL_NUM_THREADS",
            "VECLIB_MAXIMUM_THREADS",
            "NUMEXPR_NUM_THREADS",
            "PYTHONHASHSEED",
        )
    }
    return structured_sha256(
        "anim/replay-environment/1",
        {
            "version": __version__,
            "python": sys.version,
            "system": platform.system(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "dependencies": {name: metadata.version(name) for name in dependency_names},
            "core_code_digest": _core_code_digest(),
            "numerical_environment": numerical_environment,
        },
    )


def replay_bindings(verified: VerifiedAuditConfigFiles, *, profile_id: str) -> dict[str, str]:
    source = _read_verified_source_config_binding(verified)
    config = parse_audit_config(source.exact_bytes)
    del config["output"]["root"]
    identity = verified.worker_identity_digest
    if identity is None:
        raise _invalid()
    return {
        "configuration_digest": structured_sha256("anim/replay-config/1", config),
        "input_digest": verified.input_byte_digest,
        "worker_config_digest": verified.worker_config_digest,
        "worker_identity_digest": identity,
        "file_roles_digest": verified.replay_file_bindings_digest,
        "randomness_digest": structured_sha256("anim/replay-randomness/1", config["randomness"]),
        "environment_digest": environment_digest(),
        "profile_id": profile_id,
    }


def write_replay_manifest(
    store: PrivateArtifactStore,
    verified: VerifiedAuditConfigFiles,
    *,
    profile_id: str,
    plan_digest: str,
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    bindings = replay_bindings(verified, profile_id=profile_id)
    if expected is not None and (
        bindings != expected["bindings"] or plan_digest != expected["plan_digest"]
    ):
        raise InvalidInputError(
            "REPLAY.DRIFT",
            "Replay refused: configuration, inputs, worker, plan or runtime changed.",
        )
    record: dict[str, Any] = {
        "schema_version": "anim-replay/1",
        "bindings": bindings,
        "plan_digest": plan_digest,
        "source_run_root_id": store.run_root_id,
        "parent_manifest_digest": None if expected is None else expected["manifest_digest"],
    }
    record["manifest_digest"] = structured_sha256("anim/replay/1", record)
    directory = replay_directory(store.root)
    # Never attach to a prior operational attempt, including an empty directory.
    descriptor = _open_directory_chain(directory.parent, create=False)
    try:
        os.mkdir(directory.name, 0o700, dir_fd=descriptor)
    except OSError:
        raise InvalidInputError(
            "REPLAY.OUTPUT_EXISTS", "Replay requires a fresh operations directory."
        ) from None
    finally:
        os.close(descriptor)
    ensure_private_directory(directory)
    write_private_new(directory / REPLAY_PATH, canonical_json_bytes(record))
    return record


class AttemptRecord:
    """Write one terminal operational disposition; never scientific status."""

    def __init__(self, store: PrivateArtifactStore, manifest: Mapping[str, Any]) -> None:
        self.store = store
        self.manifest_digest = manifest["manifest_digest"]
        self.finished = False

    def finish(self, state: str) -> None:
        if state not in {"FINISHED", "CANCELLED", "FAILED"}:
            raise _invalid()
        if not self.finished:
            write_private_new(
                replay_directory(self.store.root) / ATTEMPT_PATH,
                canonical_json_bytes(
                    {
                        "schema_version": "anim-attempt/1",
                        "state": state,
                        "manifest_digest": self.manifest_digest,
                        "scientific_completion_claim": False,
                    }
                ),
            )
            self.finished = True

    def __enter__(self) -> AttemptRecord:
        return self

    def __exit__(self, kind: Any, error: Any, traceback: Any) -> None:
        if self.finished:
            return
        cancelled = isinstance(error, AuditError) and error.code == "EXECUTION.CANCELLED"
        try:
            self.finish("CANCELLED" if cancelled or kind is KeyboardInterrupt else "FAILED")
        except (AuditError, OSError):
            # Failure to record an operational sidecar cannot replace the
            # primary failure. Missing terminal sidecar means INTERRUPTED/UNKNOWN.
            if error is None:
                raise


@contextmanager
def replay_config(config_path: Path, *, run_root: str) -> Iterator[Path]:
    """Create a private sibling so all relative input bindings stay unchanged."""

    # The ordinary workflow reopens, validates and pins every byte of this
    # derivative. Its normalized config digest must match the original recipe.
    from ebm_audit.config import resolve_audit_config

    config = parse_audit_config(read_private_bytes(config_path, maximum_bytes=2 * 1024 * 1024))
    config["output"]["root"] = run_root
    resolve_audit_config(config, source_path=config_path)
    path = config_path.absolute().with_name(f".anim-replay-{uuid.uuid4().hex}.json")
    write_private_new(path, canonical_json_bytes(config))
    created = path.stat(follow_symlinks=False)
    try:
        yield path
    finally:
        try:
            current = path.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                path.unlink()
        except FileNotFoundError:
            pass


def rerun_audit(
    manifest_path: Path,
    config_path: Path,
    *,
    run_root: str,
    timeout_seconds: float,
    control: ExecutionControl | None = None,
) -> tuple[Mapping[str, Any], ExitCode]:
    from ebm_audit.cli_workflows import run_audit

    manifest = load_replay_manifest(manifest_path)
    with replay_config(config_path, run_root=run_root) as source:
        return run_audit(
            source,
            profile_id=manifest["bindings"]["profile_id"],
            timeout_seconds=timeout_seconds,
            execution_control=control,
            _expected_replay=manifest,
        )
