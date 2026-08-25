"""Private exact-file verification for a resolved audit configuration.

Parsing a configuration is intentionally non-mutating and permits starter
templates whose local files do not exist yet.  This module is the separate
execution gate: it reopens the source configuration and every declared input
without following symlinks, requires private ownership and permissions, and
binds the observed exact bytes back to the resolved public identity.
"""

from __future__ import annotations

import copy
import hashlib
import os
import stat
from _thread import LockType
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any, BinaryIO, SupportsIndex, TypeVar, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.data.source_admission import (
    _MAX_SOURCE_BYTES,
    ValidatedSourceAdmission,
    _admit_exact_source_bytes,
    _private_source_table,
)
from ebm_audit.errors import InvalidInputError
from ebm_audit.protocol import canonical_json_bytes, settings_digest, structured_sha256
from ebm_audit.protocol.paths import validate_relative_posix_path

from .loader import parse_audit_config, resolve_audit_config
from .models import ConfigContractError, ResolvedAuditConfig

if TYPE_CHECKING:
    from ebm_audit.adapters.config import WorkerConfig
    from ebm_audit.adapters.invocation import AuthenticatedWorkerDescription
    from ebm_audit.artifacts import PrivateArtifactStore
    from ebm_audit.baseline.bundle import VerifiedReferenceBundle

_DIRECTORY_FLAGS = os.O_RDONLY
_FILE_FLAGS = os.O_RDONLY
_MAX_SOURCE_CONFIG_BYTES = 2 * 1024 * 1024
_MAX_WORKER_CONFIG_BYTES = 256 * 1024
_MAX_REFERENCE_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_REFERENCE_ARRAYS_BYTES = 513 * 1024 * 1024
_MAX_PRIVATE_ALIGNMENT_BYTES = 64 * 1024 * 1024
_VERIFIED_FILES_TOKEN = object()
_RUN_ELIGIBLE_TOKEN = object()
_STREAM_CHUNK_BYTES = 1024 * 1024
if hasattr(os, "O_CLOEXEC"):
    _DIRECTORY_FLAGS |= os.O_CLOEXEC
    _FILE_FLAGS |= os.O_CLOEXEC
if hasattr(os, "O_DIRECTORY"):
    _DIRECTORY_FLAGS |= os.O_DIRECTORY
if hasattr(os, "O_NOFOLLOW"):
    _DIRECTORY_FLAGS |= os.O_NOFOLLOW
    _FILE_FLAGS |= os.O_NOFOLLOW

type _FileIdentity = tuple[int, int, int, int, int]
type _ObservedFile = tuple[str, _FileIdentity, bytes | None]
_T = TypeVar("_T")


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw_json(child) for child in value]
    return copy.deepcopy(value)


def _file_identity(observed: os.stat_result) -> _FileIdentity:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )


def _require_owned_directory(descriptor: int, *, root: bool) -> None:
    observed = os.fstat(descriptor)
    if not stat.S_ISDIR(observed.st_mode):
        raise ConfigContractError("CONFIG.PRIVATE_DIRECTORY_TYPE")
    if stat.S_IMODE(observed.st_mode) != 0o700:
        code = "CONFIG.PRIVATE_ROOT_MODE" if root else "CONFIG.PRIVATE_DIRECTORY_MODE"
        raise ConfigContractError(code)
    if hasattr(os, "geteuid") and observed.st_uid != os.geteuid():
        code = "CONFIG.PRIVATE_ROOT_OWNER" if root else "CONFIG.PRIVATE_DIRECTORY_OWNER"
        raise ConfigContractError(code)


def _open_private_root(path: Path) -> int:
    absolute = path.absolute()
    if not absolute.is_absolute() or not absolute.parts or absolute.parts[0] != os.sep:
        raise ConfigContractError("CONFIG.PRIVATE_ROOT")
    try:
        current = os.open(os.sep, _DIRECTORY_FLAGS)
    except OSError:
        raise ConfigContractError("CONFIG.PRIVATE_ROOT") from None
    try:
        for component in absolute.parts[1:]:
            try:
                next_descriptor = os.open(
                    component,
                    _DIRECTORY_FLAGS,
                    dir_fd=current,
                )
            except OSError:
                raise ConfigContractError("CONFIG.PRIVATE_ROOT") from None
            os.close(current)
            current = next_descriptor
        _require_owned_directory(current, root=True)
        return current
    except BaseException:
        with suppress(OSError):
            os.close(current)
        raise


def _relative_components(value: str) -> tuple[str, ...]:
    try:
        normalized = validate_relative_posix_path(value)
    except Exception:
        raise ConfigContractError("CONFIG.UNSAFE_PATH") from None
    return tuple(normalized.split("/"))


def _open_private_parent(root_descriptor: int, relative_path: str) -> tuple[int, str]:
    components = _relative_components(relative_path)
    try:
        current = os.dup(root_descriptor)
    except OSError:
        raise ConfigContractError("CONFIG.FILE_UNAVAILABLE") from None
    try:
        for component in components[:-1]:
            try:
                next_descriptor = os.open(
                    component,
                    _DIRECTORY_FLAGS,
                    dir_fd=current,
                )
            except OSError:
                raise ConfigContractError("CONFIG.FILE_UNAVAILABLE") from None
            os.close(current)
            current = next_descriptor
            _require_owned_directory(current, root=False)
        return current, components[-1]
    except BaseException:
        with suppress(OSError):
            os.close(current)
        raise


def _require_private_regular_file(observed: os.stat_result) -> None:
    if not stat.S_ISREG(observed.st_mode):
        raise ConfigContractError("CONFIG.FILE_TYPE")
    if stat.S_IMODE(observed.st_mode) not in {0o400, 0o600}:
        raise ConfigContractError("CONFIG.FILE_MODE")
    if hasattr(os, "geteuid") and observed.st_uid != os.geteuid():
        raise ConfigContractError("CONFIG.FILE_OWNER")
    if observed.st_nlink != 1:
        raise ConfigContractError("CONFIG.FILE_HARDLINK")


def _require_private_retained_file(observed: os.stat_result) -> None:
    """Recheck a retained FD while permitting its verified path to be replaced."""

    if not stat.S_ISREG(observed.st_mode):
        raise ConfigContractError("CONFIG.FILE_TYPE")
    if stat.S_IMODE(observed.st_mode) not in {0o400, 0o600}:
        raise ConfigContractError("CONFIG.FILE_MODE")
    if hasattr(os, "geteuid") and observed.st_uid != os.geteuid():
        raise ConfigContractError("CONFIG.FILE_OWNER")


def _consume_file(
    handle: BinaryIO,
    *,
    maximum_bytes: int | None,
    retain_bytes: bool,
) -> tuple[str, bytes | None]:
    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if retain_bytes else None
    total = 0
    while True:
        chunk = handle.read(_STREAM_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if maximum_bytes is not None and total > maximum_bytes:
            raise ConfigContractError("CONFIG.FILE_SIZE")
        digest.update(chunk)
        if chunks is not None:
            chunks.append(chunk)
    return f"sha256:{digest.hexdigest()}", None if chunks is None else b"".join(chunks)


def _read_private_file(
    root_descriptor: int,
    relative_path: str,
    *,
    maximum_bytes: int | None = None,
    retain_bytes: bool = False,
) -> _ObservedFile:
    parent_descriptor, name = _open_private_parent(root_descriptor, relative_path)
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_descriptor)
        except OSError:
            raise ConfigContractError("CONFIG.FILE_UNAVAILABLE") from None
        before = os.fstat(descriptor)
        _require_private_regular_file(before)
        if maximum_bytes is not None and before.st_size > maximum_bytes:
            raise ConfigContractError("CONFIG.FILE_SIZE")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            digest, retained = _consume_file(
                handle,
                maximum_bytes=maximum_bytes,
                retain_bytes=retain_bytes,
            )
            after_read = os.fstat(handle.fileno())
        _require_private_regular_file(after_read)
        try:
            after_entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError:
            raise ConfigContractError("CONFIG.FILE_CHANGED") from None
        _require_private_regular_file(after_entry)
        identity = _file_identity(before)
        if identity != _file_identity(after_read) or identity != _file_identity(after_entry):
            raise ConfigContractError("CONFIG.FILE_CHANGED")
        return digest, identity, retained
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        os.close(parent_descriptor)


def _retain_verified_file(
    root_descriptor: int,
    relative_path: str,
    *,
    expected_digest: str,
    expected_identity: _FileIdentity,
    maximum_bytes: int | None = None,
) -> int:
    """Open a second descriptor pinned to the exact file just verified."""

    parent_descriptor, name = _open_private_parent(root_descriptor, relative_path)
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_descriptor)
        except OSError:
            raise ConfigContractError("CONFIG.FILE_CHANGED") from None
        before = os.fstat(descriptor)
        _require_private_regular_file(before)
        if maximum_bytes is not None and before.st_size > maximum_bytes:
            raise ConfigContractError("CONFIG.FILE_SIZE")
        try:
            entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError:
            raise ConfigContractError("CONFIG.FILE_CHANGED") from None
        _require_private_regular_file(entry)
        if (
            _file_identity(before) != expected_identity
            or _file_identity(entry) != expected_identity
        ):
            raise ConfigContractError("CONFIG.FILE_CHANGED")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
            digest, _retained = _consume_file(
                handle,
                maximum_bytes=maximum_bytes,
                retain_bytes=False,
            )
        after = os.fstat(descriptor)
        if _file_identity(after) != expected_identity or digest != expected_digest:
            raise ConfigContractError("CONFIG.FILE_CHANGED")
        os.lseek(descriptor, 0, os.SEEK_SET)
        retained = descriptor
        descriptor = None
        return retained
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        os.close(parent_descriptor)


def _verify_retained_descriptor(
    descriptor: int,
    *,
    expected_digest: str,
    expected_identity: _FileIdentity,
    retain_bytes: bool,
    maximum_bytes: int | None = None,
) -> bytes | None:
    try:
        before = os.fstat(descriptor)
        _require_private_retained_file(before)
        if _file_identity(before)[:4] != expected_identity[:4]:
            raise ConfigContractError("CONFIG.FILE_CHANGED")
    except (OSError, ConfigContractError):
        raise ConfigContractError("CONFIG.FILE_CHANGED") from None
    if maximum_bytes is not None and before.st_size > maximum_bytes:
        raise ConfigContractError("CONFIG.INPUT_SOURCE_INVALID")
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
            digest, value = _consume_file(
                handle,
                maximum_bytes=maximum_bytes,
                retain_bytes=retain_bytes,
            )
        after = os.fstat(descriptor)
    except ConfigContractError as exc:
        if exc.code == "CONFIG.FILE_SIZE":
            raise ConfigContractError("CONFIG.INPUT_SOURCE_INVALID") from None
        raise ConfigContractError("CONFIG.FILE_CHANGED") from None
    except OSError:
        raise ConfigContractError("CONFIG.FILE_CHANGED") from None
    if digest != expected_digest or _file_identity(after)[:4] != expected_identity[:4]:
        raise ConfigContractError("CONFIG.FILE_CHANGED")
    return value


def _require_output_absent(root_descriptor: int, relative_path: str) -> None:
    components = _relative_components(relative_path)
    try:
        current = os.dup(root_descriptor)
    except OSError:
        raise ConfigContractError("CONFIG.OUTPUT_PATH") from None
    try:
        for index, component in enumerate(components):
            is_last = index == len(components) - 1
            try:
                observed = os.stat(component, dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                return
            except OSError:
                raise ConfigContractError("CONFIG.OUTPUT_PATH") from None
            if is_last:
                raise ConfigContractError("CONFIG.OUTPUT_EXISTS")
            if not stat.S_ISDIR(observed.st_mode):
                raise ConfigContractError("CONFIG.OUTPUT_PATH")
            try:
                next_descriptor = os.open(
                    component,
                    _DIRECTORY_FLAGS,
                    dir_fd=current,
                )
            except OSError:
                raise ConfigContractError("CONFIG.OUTPUT_PATH") from None
            os.close(current)
            current = next_descriptor
            _require_owned_directory(current, root=False)
    finally:
        os.close(current)


def _verify_worker_identity_binding(
    private_config: Mapping[str, Any],
    worker_config: WorkerConfig,
) -> tuple[bool, str | None]:
    declaration = cast(Mapping[str, Any], private_config["worker"])
    baseline = cast(Mapping[str, Any], private_config["baseline_analysis"])
    backend = cast(Mapping[str, Any], baseline["backend"])
    expected = worker_config.expected_identity
    if expected is None:
        if declaration["worker_identity_digest"] != "sha256:" + "0" * 64:
            raise ConfigContractError("CONFIG.WORKER_IDENTITY_MISMATCH")
        return False, None

    base = cast(Mapping[str, Any], expected["base_backend_identity"])
    selected_digest = cast(str, expected["selected_backend_identity_digest"])
    if (
        declaration["worker_identity_digest"] != selected_digest
        or worker_config.algorithm_id != expected["selected_algorithm_id"]
        or backend["adapter_id"] != base["adapter_id"]
        or backend["expected_backend_name"] != base["backend_name"]
        or backend["expected_backend_source_digest"] != base["backend_source_digest"]
        or backend["algorithm_id"] != worker_config.algorithm_id
        or backend["capabilities_digest"] != expected["capabilities_digest"]
        or canonical_json_bytes(backend["settings"]) != canonical_json_bytes(worker_config.settings)
        or backend["settings_digest"] != settings_digest(worker_config.settings)
    ):
        raise ConfigContractError("CONFIG.WORKER_IDENTITY_MISMATCH")
    return True, selected_digest


def _parse_worker_config_bytes(data: bytes) -> WorkerConfig:
    """Import lazily so adapter config can reuse strict YAML without a cycle."""

    from ebm_audit.adapters.config import WorkerConfig

    return WorkerConfig.from_yaml_bytes(data)


def _reference_bundle_component_paths(manifest_path: str) -> tuple[str, str]:
    from ebm_audit.baseline.bundle import (
        BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME,
        BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME,
    )

    components = _relative_components(manifest_path)
    parent = components[:-1]
    return (
        "/".join((*parent, BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME)),
        "/".join((*parent, BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME)),
    )


def _reference_bundle_component_records(
    manifest_bytes: bytes,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    from ebm_audit.baseline.bundle import (
        BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME,
        BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME,
        ReferenceBundleError,
        _validated_reference_bundle_manifest,
    )

    try:
        manifest = _validated_reference_bundle_manifest(manifest_bytes)
        files = cast(Mapping[str, Mapping[str, Any]], manifest["files"])
        arrays_record = files[BASELINE_REFERENCE_BUNDLE_ARRAYS_NAME]
        alignment_record = files[BASELINE_REFERENCE_BUNDLE_ALIGNMENT_NAME]
        if (
            arrays_record["byte_length"] > _MAX_REFERENCE_ARRAYS_BYTES
            or alignment_record["byte_length"] > _MAX_PRIVATE_ALIGNMENT_BYTES
        ):
            raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID")
        return arrays_record, alignment_record
    except (KeyError, ReferenceBundleError, TypeError):
        raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID") from None


class VerifiedAuditConfigFiles:
    """Capability owning descriptors for the exact private files verified."""

    __slots__ = (
        "_access_lock",
        "_baseline_reference_bundle",
        "_closed",
        "_confirmation_issue_codes",
        "_file_digests",
        "_file_identities",
        "_input_byte_digest",
        "_resolved",
        "_resolved_public_digest",
        "_retained_descriptors",
        "_source_admission",
        "_source_config_byte_digest",
        "_verification_id",
        "_worker_config_digest",
        "_worker_identity_digest",
        "_worker_identity_verified",
    )
    _access_lock: LockType
    _baseline_reference_bundle: VerifiedReferenceBundle | None
    _closed: bool
    _confirmation_issue_codes: tuple[object, ...]
    _file_identities: tuple[tuple[str, _FileIdentity], ...]
    _file_digests: tuple[tuple[str, str], ...]
    _input_byte_digest: object
    _retained_descriptors: tuple[tuple[str, int], ...]
    _resolved: ResolvedAuditConfig
    _resolved_public_digest: object
    _source_config_byte_digest: object
    _source_admission: ValidatedSourceAdmission
    _verification_id: object
    _worker_config_digest: object
    _worker_identity_digest: object
    _worker_identity_verified: bool

    def __init__(
        self,
        *,
        resolved: ResolvedAuditConfig,
        source_config_byte_digest: str,
        source_admission: ValidatedSourceAdmission,
        input_byte_digest: str,
        worker_config_digest: str,
        file_identities: tuple[tuple[str, _FileIdentity], ...],
        file_digests: tuple[tuple[str, str], ...],
        retained_descriptors: tuple[tuple[str, int], ...],
        baseline_reference_bundle: VerifiedReferenceBundle | None,
        worker_identity_verified: bool,
        worker_identity_digest: str | None,
        verification_id: str,
        construction_token: object | None = None,
    ) -> None:
        if construction_token is not _VERIFIED_FILES_TOKEN:
            raise ConfigContractError("CONFIG.VERIFIED_FILES_CONSTRUCTION")
        object.__setattr__(self, "_access_lock", Lock())
        object.__setattr__(self, "_resolved", resolved)
        object.__setattr__(self, "_resolved_public_digest", resolved.public_digest)
        object.__setattr__(self, "_source_config_byte_digest", source_config_byte_digest)
        object.__setattr__(self, "_source_admission", source_admission)
        object.__setattr__(self, "_input_byte_digest", input_byte_digest)
        object.__setattr__(self, "_worker_config_digest", worker_config_digest)
        object.__setattr__(self, "_file_identities", file_identities)
        object.__setattr__(self, "_file_digests", file_digests)
        object.__setattr__(self, "_retained_descriptors", retained_descriptors)
        object.__setattr__(self, "_baseline_reference_bundle", baseline_reference_bundle)
        object.__setattr__(self, "_worker_identity_verified", worker_identity_verified)
        object.__setattr__(self, "_worker_identity_digest", worker_identity_digest)
        object.__setattr__(self, "_verification_id", verification_id)
        object.__setattr__(self, "_closed", False)
        object.__setattr__(
            self,
            "_confirmation_issue_codes",
            resolved.confirmation_issue_codes,
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Verified audit-config file capabilities are immutable.")

    def __copy__(self) -> VerifiedAuditConfigFiles:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> VerifiedAuditConfigFiles:
        memo[id(self)] = self
        return self

    @property
    def verification_id(self) -> str:
        return str(self._verification_id)

    @property
    def resolved_public_digest(self) -> str:
        return str(self._resolved_public_digest)

    @property
    def source_config_byte_digest(self) -> str:
        return str(self._source_config_byte_digest)

    @property
    def input_byte_digest(self) -> str:
        return str(self._input_byte_digest)

    @property
    def source_admission_id(self) -> str:
        return self._source_admission.admission_id

    @property
    def source_admission(self) -> ValidatedSourceAdmission:
        """Return the sole admitted source-table capability after FD revalidation."""

        self.assert_unchanged()
        try:
            _private_source_table(self._source_admission)
        except TypeError:
            raise ConfigContractError("CONFIG.INPUT_SOURCE_INVALID") from None
        return self._source_admission

    @property
    def worker_config_digest(self) -> str:
        return str(self._worker_config_digest)

    @property
    def verified_file_role_count(self) -> int:
        """Revalidate and count sealed file roles without materializing their bytes."""

        self.assert_unchanged()
        return len(self._retained_descriptors)

    @property
    def confirmation_issue_codes(self) -> tuple[str, ...]:
        return tuple(str(code) for code in self._confirmation_issue_codes)

    @property
    def configuration_run_eligible(self) -> bool:
        """Whether configuration confirmation alone permits backend execution.

        Worker capability, canonical-data, and execution-plan gates remain
        separate requirements.
        """

        reference = cast(
            Mapping[str, Any],
            self._resolved.private_config["baseline_reference"],
        )
        status = reference["status"]
        reference_ready = status == "NOT_SUPPLIED" or (
            status == "SUPPLIED_INDEPENDENTLY_VERIFIED"
            and self._baseline_reference_bundle is not None
        )
        return (
            not self.confirmation_issue_codes
            and self._worker_identity_verified
            and reference_ready
        )

    @property
    def worker_identity_digest(self) -> str | None:
        value = self._worker_identity_digest
        return None if value is None else str(value)

    @property
    def baseline_reference_bundle(self) -> VerifiedReferenceBundle | None:
        """Return the opaque imported bundle only after all retained FDs revalidate."""

        self.assert_unchanged()
        bundle = self._baseline_reference_bundle
        if bundle is not None:
            # The property revalidates the opaque owner without exposing its contents.
            _ = bundle.reference_id
        return bundle

    def _role_binding(self, role: str) -> tuple[int, str, _FileIdentity]:
        if self._closed:
            raise ConfigContractError("CONFIG.VERIFIED_FILES_CLOSED")
        descriptor_by_role = dict(self._retained_descriptors)
        identity_by_role = dict(self._file_identities)
        digest_by_role = dict(self._file_digests)
        if role not in descriptor_by_role:
            raise ConfigContractError("CONFIG.FILE_ROLE_UNAVAILABLE")
        return (
            descriptor_by_role[role],
            digest_by_role[role],
            identity_by_role[role],
        )

    def _read_role(self, role: str) -> bytes:
        with self._access_lock:
            descriptor, digest, identity = self._role_binding(role)
            value = _verify_retained_descriptor(
                descriptor,
                expected_digest=digest,
                expected_identity=identity,
                retain_bytes=True,
            )
            if value is None:
                raise ConfigContractError("CONFIG.FILE_CHANGED")
            return value

    def _consume_role(self, role: str, consumer: Callable[[BinaryIO], _T]) -> _T:
        """Run a consumer on a pinned stream and reverify before returning."""

        if not callable(consumer):
            raise ConfigContractError("CONFIG.FILE_CONSUMER")
        with self._access_lock:
            descriptor, digest, identity = self._role_binding(role)
            _verify_retained_descriptor(
                descriptor,
                expected_digest=digest,
                expected_identity=identity,
                retain_bytes=False,
            )
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
                    result = consumer(handle)
            except OSError:
                raise ConfigContractError("CONFIG.FILE_CHANGED") from None
            _verify_retained_descriptor(
                descriptor,
                expected_digest=digest,
                expected_identity=identity,
                retain_bytes=False,
            )
            return result

    def read_worker_config_bytes(self) -> bytes:
        return self._read_role("worker-config")

    def consume_worker_config(self, consumer: Callable[[BinaryIO], _T]) -> _T:
        return self._consume_role("worker-config", consumer)

    def read_baseline_reference_bytes(self) -> bytes | None:
        if "baseline-reference" not in dict(self._retained_descriptors):
            return None
        return self._read_role("baseline-reference")

    def consume_baseline_reference(self, consumer: Callable[[BinaryIO], _T]) -> _T:
        return self._consume_role("baseline-reference", consumer)

    def assert_unchanged(self) -> None:
        """Rehash every retained descriptor before consuming any file."""

        with self._access_lock:
            for role, _descriptor in self._retained_descriptors:
                descriptor, digest, identity = self._role_binding(role)
                _verify_retained_descriptor(
                    descriptor,
                    expected_digest=digest,
                    expected_identity=identity,
                    retain_bytes=False,
                )

    def close(self) -> None:
        with self._access_lock:
            if self._closed:
                return
            for _role, descriptor in self._retained_descriptors:
                with suppress(OSError):
                    os.close(descriptor)
            object.__setattr__(self, "_closed", True)

    def __enter__(self) -> VerifiedAuditConfigFiles:
        if self._closed:
            raise ConfigContractError("CONFIG.VERIFIED_FILES_CLOSED")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:  # noqa: SIM105 - contextlib globals may be cleared at shutdown.
            self.close()
        except BaseException:
            # Module globals may already be cleared during interpreter
            # shutdown. The process owns and will close any remaining file
            # descriptors; finalization must never emit a secondary exception.
            pass

    def __repr__(self) -> str:
        return (
            "VerifiedAuditConfigFiles("
            f"verification_id={self.verification_id!r}, private_paths=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class _VerifiedSourceConfigBinding:
    resolved: ResolvedAuditConfig
    exact_bytes: bytes
    byte_digest: str


def _read_verified_source_config_binding(
    owner: VerifiedAuditConfigFiles,
) -> _VerifiedSourceConfigBinding:
    """Read the exact retained source bytes with their resolved owner."""

    if type(owner) is not VerifiedAuditConfigFiles:
        raise ConfigContractError("CONFIG.VERIFIED_FILES_OWNER")
    exact_bytes = owner._read_role("source-config")
    observed_digest = f"sha256:{hashlib.sha256(exact_bytes).hexdigest()}"
    if observed_digest != owner.source_config_byte_digest:
        raise ConfigContractError("CONFIG.FILE_CHANGED")
    return _VerifiedSourceConfigBinding(
        resolved=owner._resolved,
        exact_bytes=bytes(exact_bytes),
        byte_digest=observed_digest,
    )


@dataclass(frozen=True, repr=False)
class _PlanEligibleAuditConfigState:
    verified_files: VerifiedAuditConfigFiles
    authorization_id: str
    authenticated_description: object
    authenticated_description_state: object
    expected_identity_bytes: bytes


_PLAN_ELIGIBLE_STATES: OneShotWeakRegistry[object, _PlanEligibleAuditConfigState]
_PLAN_ELIGIBLE_STATE_ISSUER: OneShotRegistryIssuer[object, _PlanEligibleAuditConfigState]
(
    _PLAN_ELIGIBLE_STATES,
    _PLAN_ELIGIBLE_STATE_ISSUER,
) = create_one_shot_registry()


def _read_plan_eligible_state(value: object) -> _PlanEligibleAuditConfigState:
    if type(value) is not PlanEligibleAuditConfig:
        raise ConfigContractError("CONFIG.PLAN_ELIGIBLE_TYPE")
    try:
        state = _PLAN_ELIGIBLE_STATES[value]
    except (KeyError, TypeError):
        raise ConfigContractError("CONFIG.PLAN_ELIGIBLE_AUTHORITY") from None
    if type(state) is not _PlanEligibleAuditConfigState:
        raise ConfigContractError("CONFIG.PLAN_ELIGIBLE_AUTHORITY")
    state.verified_files.assert_unchanged()
    try:
        from ebm_audit.adapters.invocation import _capture_authenticated_description

        description_state, readback = _capture_authenticated_description(
            state.authenticated_description
        )
    except TypeError:
        raise ConfigContractError("CONFIG.PLAN_ELIGIBLE_AUTHORITY") from None
    if (
        description_state is not state.authenticated_description_state
        or canonical_json_bytes(dict(readback.expected_identity)) != state.expected_identity_bytes
    ):
        raise ConfigContractError("CONFIG.PLAN_ELIGIBLE_AUTHORITY")
    return state


@final
class PlanEligibleAuditConfig:
    """Opaque authority for exact-file inspection and Plan/3 compilation only."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PlanEligibleAuditConfig:
        raise TypeError("Plan-eligible configurations come from authenticated verification.")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Plan-eligible audit configurations cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Plan-eligible audit configurations are immutable.")

    def _state(self) -> _PlanEligibleAuditConfigState:
        return _read_plan_eligible_state(self)

    @property
    def authorization_id(self) -> str:
        return self._state().authorization_id

    @property
    def resolved_public_digest(self) -> str:
        return self._state().verified_files.resolved_public_digest

    @property
    def verification_id(self) -> str:
        return self._state().verified_files.verification_id

    @property
    def source_admission_id(self) -> str:
        return self._state().verified_files.source_admission_id

    @property
    def source_admission(self) -> ValidatedSourceAdmission:
        return self._state().verified_files.source_admission

    @property
    def confirmation_issue_codes(self) -> tuple[str, ...]:
        return self._state().verified_files.confirmation_issue_codes

    @property
    def private_config(self) -> dict[str, Any]:
        return self._state().verified_files._resolved.private_config

    @property
    def resolved_public_config(self) -> dict[str, Any]:
        return self._state().verified_files._resolved.public_projection

    def assert_ready(self) -> None:
        self._state()

    def close(self) -> None:
        try:
            state = _PLAN_ELIGIBLE_STATES[self]
        except (KeyError, TypeError):
            raise ConfigContractError("CONFIG.PLAN_ELIGIBLE_AUTHORITY") from None
        if type(state) is not _PlanEligibleAuditConfigState:
            raise ConfigContractError("CONFIG.PLAN_ELIGIBLE_AUTHORITY")
        state.verified_files.close()

    def __enter__(self) -> PlanEligibleAuditConfig:
        self.assert_ready()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __copy__(self) -> PlanEligibleAuditConfig:
        self._state()
        raise TypeError("Plan-eligible audit configurations cannot be copied.")

    def __deepcopy__(self, _memo: object) -> PlanEligibleAuditConfig:
        self._state()
        raise TypeError("Plan-eligible audit configurations cannot be copied.")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Plan-eligible audit configurations cannot be serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Plan-eligible audit configurations cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Plan-eligible audit configurations cannot be serialized.")

    def __repr__(self) -> str:
        self._state()
        return "PlanEligibleAuditConfig(<sealed-exact-planning-owners>)"


class RunEligibleAuditConfig:
    """Sealed execution capability issued from verified bytes and a pinned worker."""

    __slots__ = ("_authorization_id", "_verified_files")
    _authorization_id: object
    _verified_files: VerifiedAuditConfigFiles

    def __init__(
        self,
        verified_files: VerifiedAuditConfigFiles,
        *,
        authorization_id: str,
        construction_token: object | None = None,
    ) -> None:
        if construction_token is not _RUN_ELIGIBLE_TOKEN:
            raise ConfigContractError("CONFIG.RUN_ELIGIBLE_CONSTRUCTION")
        object.__setattr__(self, "_verified_files", verified_files)
        object.__setattr__(self, "_authorization_id", authorization_id)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Run-eligible audit-config capabilities are immutable.")

    @property
    def authorization_id(self) -> str:
        return str(self._authorization_id)

    @property
    def resolved_public_digest(self) -> str:
        return self._verified_files.resolved_public_digest

    @property
    def verification_id(self) -> str:
        return self._verified_files.verification_id

    @property
    def source_admission_id(self) -> str:
        return self._verified_files.source_admission_id

    @property
    def source_admission(self) -> ValidatedSourceAdmission:
        """Return the exact-file table capability bound into this authorization."""

        return self._verified_files.source_admission

    def assert_ready(self) -> None:
        self._verified_files.assert_unchanged()

    @property
    def private_config(self) -> dict[str, Any]:
        """Return a defensive execution copy of the resolved private mapping."""

        self.assert_ready()
        return self._verified_files._resolved.private_config

    @property
    def resolved_public_config(self) -> dict[str, Any]:
        """Return the exact privacy-safe resolved configuration projection."""

        self.assert_ready()
        return self._verified_files._resolved.public_projection

    def open_output_store(self) -> PrivateArtifactStore:
        """Create the configured private run root without exposing its path."""

        from ebm_audit.artifacts import PrivateArtifactStore, ensure_private_directory

        self.assert_ready()
        output_root = self._verified_files._resolved.private_paths.output_root
        ensure_private_directory(output_root.parent)
        return PrivateArtifactStore.open(output_root)

    def read_worker_config_bytes(self) -> bytes:
        self.assert_ready()
        return self._verified_files.read_worker_config_bytes()

    def consume_worker_config(self, consumer: Callable[[BinaryIO], _T]) -> _T:
        self.assert_ready()
        return self._verified_files.consume_worker_config(consumer)

    def read_baseline_reference_bytes(self) -> bytes | None:
        self.assert_ready()
        return self._verified_files.read_baseline_reference_bytes()

    def consume_baseline_reference(self, consumer: Callable[[BinaryIO], _T]) -> _T:
        self.assert_ready()
        return self._verified_files.consume_baseline_reference(consumer)

    @property
    def baseline_reference_bundle(self) -> VerifiedReferenceBundle | None:
        self.assert_ready()
        return self._verified_files.baseline_reference_bundle

    def close(self) -> None:
        self._verified_files.close()

    def __enter__(self) -> RunEligibleAuditConfig:
        self.assert_ready()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "RunEligibleAuditConfig("
            f"authorization_id={self.authorization_id!r}, private_paths=<redacted>)"
        )


def authorize_audit_config_run(
    verified_files: VerifiedAuditConfigFiles,
) -> RunEligibleAuditConfig:
    """Issue the only configuration capability accepted by real execution."""

    if type(verified_files) is not VerifiedAuditConfigFiles:
        raise ConfigContractError("CONFIG.VERIFIED_FILES_TYPE")
    source_admission = verified_files.source_admission
    reference = cast(
        Mapping[str, Any],
        verified_files._resolved.private_config["baseline_reference"],
    )
    if reference["status"] == "SUPPLIED_STRUCTURAL_ONLY":
        raise ConfigContractError("CONFIG.BASELINE_REFERENCE_STRUCTURAL_ONLY")
    if not verified_files.configuration_run_eligible:
        raise ConfigContractError("CONFIG.REQUIRES_CONFIRMATION")
    authorization_id = structured_sha256(
        "ebm-audit/run-eligible-audit-config/2",
        {
            "verification_id": verified_files.verification_id,
            "resolved_public_digest": verified_files.resolved_public_digest,
            "source_admission_id": source_admission.admission_id,
            "worker_identity_digest": verified_files.worker_identity_digest,
        },
    )
    return RunEligibleAuditConfig(
        verified_files,
        authorization_id=authorization_id,
        construction_token=_RUN_ELIGIBLE_TOKEN,
    )


def authorize_audit_config_plan(
    verified_files: VerifiedAuditConfigFiles,
    authenticated_description: AuthenticatedWorkerDescription,
) -> PlanEligibleAuditConfig:
    """Issue exact-file planning authority after one authenticated Describe."""

    if type(verified_files) is not VerifiedAuditConfigFiles:
        raise ConfigContractError("CONFIG.VERIFIED_FILES_TYPE")
    verified_files.assert_unchanged()
    if verified_files.worker_identity_digest is None:
        raise ConfigContractError("CONFIG.WORKER_IDENTITY_MISMATCH")
    worker_config = verified_files.consume_worker_config(
        lambda handle: _parse_worker_config_bytes(handle.read())
    )
    if worker_config.expected_identity is None:
        raise ConfigContractError("CONFIG.WORKER_IDENTITY_MISMATCH")
    try:
        from ebm_audit.adapters.invocation import _capture_authenticated_description

        description_state, readback = _capture_authenticated_description(authenticated_description)
    except TypeError:
        raise ConfigContractError("CONFIG.AUTHENTICATED_WORKER_REQUIRED") from None
    expected_identity_bytes = canonical_json_bytes(worker_config.expected_identity)
    if (
        canonical_json_bytes(dict(readback.expected_identity)) != expected_identity_bytes
        or readback.expected_identity["selected_backend_identity_digest"]
        != verified_files.worker_identity_digest
    ):
        raise ConfigContractError("CONFIG.WORKER_IDENTITY_MISMATCH")
    authorization_id = structured_sha256(
        "ebm-audit/plan-eligible-audit-config/1",
        {
            "verification_id": verified_files.verification_id,
            "resolved_public_digest": verified_files.resolved_public_digest,
            "source_admission_id": verified_files.source_admission_id,
            "worker_identity_digest": verified_files.worker_identity_digest,
        },
    )
    capability = object.__new__(PlanEligibleAuditConfig)
    _PLAN_ELIGIBLE_STATE_ISSUER.bind_once(
        capability,
        _PlanEligibleAuditConfigState(
            verified_files=verified_files,
            authorization_id=authorization_id,
            authenticated_description=authenticated_description,
            authenticated_description_state=description_state,
            expected_identity_bytes=expected_identity_bytes,
        ),
    )
    _read_plan_eligible_state(capability)
    return capability


def _verified_files_for_planning_config(
    config: PlanEligibleAuditConfig | RunEligibleAuditConfig,
) -> VerifiedAuditConfigFiles:
    if type(config) is PlanEligibleAuditConfig:
        return _read_plan_eligible_state(config).verified_files
    if type(config) is RunEligibleAuditConfig:
        config.assert_ready()
        return config._verified_files
    raise ConfigContractError("CONFIG.PLANNING_CAPABILITY")


def _plan_eligible_owns_descriptions(
    config: PlanEligibleAuditConfig,
    descriptions: tuple[AuthenticatedWorkerDescription, ...],
) -> bool:
    try:
        state = _read_plan_eligible_state(config)
        if len(descriptions) != 1 or descriptions[0] is not state.authenticated_description:
            return False
        from ebm_audit.adapters.invocation import _capture_authenticated_description

        description_state, _readback = _capture_authenticated_description(descriptions[0])
        return description_state is state.authenticated_description_state
    except (ConfigContractError, TypeError):
        return False


def _expect_digest(observed: str, expected: object, code: str) -> None:
    if observed != expected:
        raise ConfigContractError(code)


def _verify_audit_config_files(
    resolved: ResolvedAuditConfig,
) -> VerifiedAuditConfigFiles:
    """Verify every declared local byte source and issue an immutable capability."""

    if not isinstance(resolved, ResolvedAuditConfig):
        raise ConfigContractError("CONFIG.RESOLVED_TYPE")
    if (
        resolved.private_paths.development_scenario_authority is not None
        or resolved.private_config.get("development_scenario_authority") is not None
        or resolved.public_projection.get("development_scenario_authority_digest") is not None
    ):
        raise ConfigContractError("CONFIG.DEVELOPMENT_TRANSACTION_REQUIRED")
    source_path = resolved.private_paths.source_config
    root_descriptor = _open_private_root(source_path.parent)
    try:
        source_digest, source_identity, source_bytes = _read_private_file(
            root_descriptor,
            source_path.name,
            maximum_bytes=_MAX_SOURCE_CONFIG_BYTES,
            retain_bytes=True,
        )
        assert source_bytes is not None
        parsed = parse_audit_config(source_bytes)
        reloaded = resolve_audit_config(parsed, source_path=source_path)
        if (
            canonical_json_bytes(parsed)
            != canonical_json_bytes(_thaw_json(resolved.private_config))
            or reloaded.public_digest != resolved.public_digest
            or reloaded.private_paths != resolved.private_paths
        ):
            raise ConfigContractError("CONFIG.SOURCE_CONFIG_CHANGED")
        private = reloaded.private_config
        source = cast(Mapping[str, Any], private["input"])
        worker = cast(Mapping[str, Any], private["worker"])
        reference = cast(Mapping[str, Any], private["baseline_reference"])
        output = cast(Mapping[str, Any], private["output"])

        try:
            input_digest, input_identity, _ = _read_private_file(
                root_descriptor,
                cast(str, source["path"]),
                maximum_bytes=_MAX_SOURCE_BYTES,
            )
        except ConfigContractError as exc:
            if exc.code == "CONFIG.FILE_SIZE":
                raise ConfigContractError("CONFIG.INPUT_SOURCE_INVALID") from None
            raise
        _expect_digest(
            input_digest,
            source["expected_byte_digest"],
            "CONFIG.INPUT_DIGEST_MISMATCH",
        )
        physical_variant = cast(Mapping[str, Any], source["variant"])
        _expect_digest(
            input_digest,
            physical_variant["source_digest"],
            "CONFIG.INPUT_VARIANT_DIGEST_MISMATCH",
        )
        worker_digest, worker_identity, worker_bytes = _read_private_file(
            root_descriptor,
            cast(str, worker["config_path"]),
            maximum_bytes=_MAX_WORKER_CONFIG_BYTES,
            retain_bytes=True,
        )
        _expect_digest(
            worker_digest,
            worker["worker_config_digest"],
            "CONFIG.WORKER_CONFIG_DIGEST_MISMATCH",
        )
        assert worker_bytes is not None
        try:
            parsed_worker_config = _parse_worker_config_bytes(worker_bytes)
        except InvalidInputError:
            raise ConfigContractError("CONFIG.WORKER_CONFIG_INVALID") from None
        worker_identity_verified, worker_identity_digest = _verify_worker_identity_binding(
            private, parsed_worker_config
        )

        identities: list[tuple[str, _FileIdentity]] = [
            ("source-config", source_identity),
            ("input", input_identity),
            ("worker-config", worker_identity),
        ]
        file_digests: list[tuple[str, str]] = [
            ("source-config", source_digest),
            ("input", input_digest),
            ("worker-config", worker_digest),
        ]
        role_paths: list[tuple[str, str]] = [
            ("source-config", source_path.name),
            ("input", cast(str, source["path"])),
            ("worker-config", cast(str, worker["config_path"])),
        ]
        optional_digests: dict[str, str | None] = {
            "baseline_reference_digest": None,
            "external_missingness_byte_digest": None,
        }
        reference_manifest_digest: str | None = None
        reference_manifest_identity: _FileIdentity | None = None
        reference_arrays_digest: str | None = None
        reference_arrays_identity: _FileIdentity | None = None
        reference_alignment_digest: str | None = None
        reference_alignment_identity: _FileIdentity | None = None
        if reference["status"] != "NOT_SUPPLIED":
            manifest_path = cast(str, reference["path"])
            try:
                (
                    reference_manifest_digest,
                    reference_manifest_identity,
                    reference_manifest_bytes,
                ) = _read_private_file(
                    root_descriptor,
                    manifest_path,
                    maximum_bytes=_MAX_REFERENCE_MANIFEST_BYTES,
                    retain_bytes=True,
                )
            except ConfigContractError as exc:
                if exc.code == "CONFIG.FILE_SIZE":
                    raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID") from None
                raise
            _expect_digest(
                reference_manifest_digest,
                reference["byte_digest"],
                "CONFIG.BASELINE_REFERENCE_DIGEST_MISMATCH",
            )
            if reference_manifest_bytes is None:  # pragma: no cover - closed helper contract
                raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID")
            arrays_record, alignment_record = _reference_bundle_component_records(
                reference_manifest_bytes
            )
            arrays_path, alignment_path = _reference_bundle_component_paths(manifest_path)
            try:
                reference_arrays_digest, reference_arrays_identity, _ = (
                    _read_private_file(
                        root_descriptor,
                        arrays_path,
                        maximum_bytes=_MAX_REFERENCE_ARRAYS_BYTES,
                    )
                )
            except ConfigContractError as exc:
                if exc.code == "CONFIG.FILE_SIZE":
                    raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID") from None
                raise
            _expect_digest(
                reference_arrays_digest,
                arrays_record["sha256"],
                "CONFIG.BASELINE_REFERENCE_ARRAYS_DIGEST_MISMATCH",
            )
            try:
                reference_alignment_digest, reference_alignment_identity, _ = (
                    _read_private_file(
                        root_descriptor,
                        alignment_path,
                        maximum_bytes=_MAX_PRIVATE_ALIGNMENT_BYTES,
                    )
                )
            except ConfigContractError as exc:
                if exc.code == "CONFIG.FILE_SIZE":
                    raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID") from None
                raise
            _expect_digest(
                reference_alignment_digest,
                alignment_record["sha256"],
                "CONFIG.BASELINE_REFERENCE_ALIGNMENT_DIGEST_MISMATCH",
            )
            identities.extend(
                (
                    ("baseline-reference", reference_manifest_identity),
                    ("baseline-reference-arrays", reference_arrays_identity),
                    ("baseline-reference-alignment", reference_alignment_identity),
                )
            )
            file_digests.extend(
                (
                    ("baseline-reference", reference_manifest_digest),
                    ("baseline-reference-arrays", reference_arrays_digest),
                    ("baseline-reference-alignment", reference_alignment_digest),
                )
            )
            role_paths.extend(
                (
                    ("baseline-reference", manifest_path),
                    ("baseline-reference-arrays", arrays_path),
                    ("baseline-reference-alignment", alignment_path),
                )
            )
            optional_digests.update(
                {
                    "baseline_reference_digest": reference_manifest_digest,
                    "baseline_reference_arrays_digest": reference_arrays_digest,
                    "baseline_reference_alignment_digest": reference_alignment_digest,
                }
            )
        _require_output_absent(root_descriptor, cast(str, output["root"]))
        identity_by_role = dict(identities)
        digest_by_role = dict(file_digests)
        retained: list[tuple[str, int]] = []
        try:
            for role, relative_path in role_paths:
                try:
                    retained_descriptor = _retain_verified_file(
                        root_descriptor,
                        relative_path,
                        expected_digest=digest_by_role[role],
                        expected_identity=identity_by_role[role],
                        maximum_bytes=(
                            _MAX_SOURCE_BYTES
                            if role == "input"
                            else (
                                _MAX_REFERENCE_MANIFEST_BYTES
                                if role == "baseline-reference"
                                else (
                                    _MAX_REFERENCE_ARRAYS_BYTES
                                    if role == "baseline-reference-arrays"
                                    else (
                                        _MAX_PRIVATE_ALIGNMENT_BYTES
                                        if role == "baseline-reference-alignment"
                                        else None
                                    )
                                )
                            )
                        ),
                    )
                except ConfigContractError as exc:
                    if role == "input" and exc.code == "CONFIG.FILE_SIZE":
                        raise ConfigContractError("CONFIG.INPUT_SOURCE_INVALID") from None
                    if role.startswith("baseline-reference") and exc.code == "CONFIG.FILE_SIZE":
                        raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID") from None
                    raise
                retained.append((role, retained_descriptor))
            input_descriptor = dict(retained)["input"]
            admitted_bytes = _verify_retained_descriptor(
                input_descriptor,
                expected_digest=input_digest,
                expected_identity=input_identity,
                retain_bytes=True,
                maximum_bytes=_MAX_SOURCE_BYTES,
            )
            if admitted_bytes is None:  # pragma: no cover - closed helper contract
                raise ConfigContractError("CONFIG.FILE_CHANGED")
            admission_failed = False
            source_admission: ValidatedSourceAdmission | None = None
            try:
                try:
                    source_admission = _admit_exact_source_bytes(
                        admitted_bytes,
                        expected_byte_digest=input_digest,
                        csv_format=cast(Mapping[str, object], source["format"]),
                    )
                except InvalidInputError:
                    admission_failed = True
            finally:
                del admitted_bytes
            if admission_failed or source_admission is None:
                raise ConfigContractError("CONFIG.INPUT_SOURCE_INVALID")
            reference_bundle: VerifiedReferenceBundle | None = None
            if reference_manifest_digest is not None:
                from ebm_audit.baseline.bundle import (
                    ReferenceBundleError,
                    _issue_verified_reference_bundle,
                )

                if (
                    reference_manifest_identity is None
                    or reference_arrays_digest is None
                    or reference_arrays_identity is None
                    or reference_alignment_digest is None
                    or reference_alignment_identity is None
                ):  # pragma: no cover - closed local state construction
                    raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID")
                retained_by_role = dict(retained)
                manifest_readback = _verify_retained_descriptor(
                    retained_by_role["baseline-reference"],
                    expected_digest=reference_manifest_digest,
                    expected_identity=reference_manifest_identity,
                    retain_bytes=True,
                )
                alignment_readback = _verify_retained_descriptor(
                    retained_by_role["baseline-reference-alignment"],
                    expected_digest=reference_alignment_digest,
                    expected_identity=reference_alignment_identity,
                    retain_bytes=True,
                )
                if manifest_readback is None or alignment_readback is None:
                    raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID")
                try:
                    with os.fdopen(
                        os.dup(retained_by_role["baseline-reference-arrays"]),
                        "rb",
                        closefd=True,
                    ) as arrays_handle:
                        reference_bundle = _issue_verified_reference_bundle(
                            manifest_bytes=manifest_readback,
                            manifest_digest=reference_manifest_digest,
                            manifest_identity=reference_manifest_identity,
                            arrays_handle=arrays_handle,
                            arrays_digest=reference_arrays_digest,
                            arrays_identity=reference_arrays_identity,
                            private_alignment_bytes=alignment_readback,
                            private_alignment_digest=reference_alignment_digest,
                            private_alignment_identity=reference_alignment_identity,
                            alignment_binding_eligible=(
                                reference["status"]
                                == "SUPPLIED_INDEPENDENTLY_VERIFIED"
                            ),
                        )
                except (OSError, ReferenceBundleError):
                    raise ConfigContractError("CONFIG.BASELINE_REFERENCE_INVALID") from None
            verification_id = structured_sha256(
                "ebm-audit/verified-audit-config-files/2",
                {
                    "resolved_public_digest": reloaded.public_digest,
                    "source_config_byte_digest": source_digest,
                    "input_byte_digest": input_digest,
                    "source_admission_id": source_admission.admission_id,
                    "worker_config_digest": worker_digest,
                    "worker_identity_digest": worker_identity_digest,
                    **optional_digests,
                },
            )
            return VerifiedAuditConfigFiles(
                resolved=reloaded,
                source_config_byte_digest=source_digest,
                source_admission=source_admission,
                input_byte_digest=input_digest,
                worker_config_digest=worker_digest,
                file_identities=tuple(identities),
                file_digests=tuple(file_digests),
                retained_descriptors=tuple(retained),
                baseline_reference_bundle=reference_bundle,
                worker_identity_verified=worker_identity_verified,
                worker_identity_digest=worker_identity_digest,
                verification_id=verification_id,
                construction_token=_VERIFIED_FILES_TOKEN,
            )
        except BaseException:
            for _role, descriptor in retained:
                with suppress(OSError):
                    os.close(descriptor)
            raise
    finally:
        os.close(root_descriptor)


def verify_audit_config_files(
    resolved: ResolvedAuditConfig,
) -> VerifiedAuditConfigFiles:
    """Verify private sources without retaining raw exception chains."""

    failure_code: str | None = None
    try:
        return _verify_audit_config_files(resolved)
    except ConfigContractError as exc:
        failure_code = exc.code
    if failure_code is None:  # pragma: no cover - defensive type narrowing
        raise RuntimeError("Configuration verification ended without a result.")
    raise ConfigContractError(failure_code)


__all__ = [
    "PlanEligibleAuditConfig",
    "RunEligibleAuditConfig",
    "VerifiedAuditConfigFiles",
    "authorize_audit_config_plan",
    "authorize_audit_config_run",
    "verify_audit_config_files",
]
