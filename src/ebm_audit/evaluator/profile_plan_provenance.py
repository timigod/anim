"""Sealed local provenance for material profile-characterization plans.

The public derivation has no caller-selected repository surface.  It resolves
the package source root, observes one exact clean committed Git tree, and
returns an opaque one-shot owner.  Protected manifests remain registry state;
the public projection contains digests and counts only.
"""

from __future__ import annotations

import copy
import hashlib
import os
import shutil
import stat
import subprocess
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Final, Never, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.config import StrictYamlError, load_strict_yaml_bytes
from ebm_audit.protocol import structured_sha256_hex
from ebm_audit.schema import SchemaValidationError, validate_instance

_GIT_TIMEOUT_SECONDS: Final = 15.0
_MAXIMUM_CONTRACT_BYTES: Final = 16 * 1024 * 1024
_CANDIDATE_DOMAIN: Final = "ebm-audit/candidate-tree/1"
_SOURCE_SET_DOMAIN: Final = "ebm-audit/source-set/1"
_CONTRACT_DOMAIN: Final = "ebm-audit/proportional-benchmark-contract/1"
_EXECUTION_SOURCE_DOMAIN: Final = "ebm-audit/profile-execution-source-manifest/1"
_ATTESTATION_DOMAIN: Final = "ebm-audit/profile-plan-provenance-attestation/1"
_CONTRACT_PATHS: Final = (
    "evaluator/proportional_benchmark_contract-0.3.0-candidate.yaml",
)

_SOURCE_SET_DEFINITIONS: Final = (
    (
        "generator_sha256",
        "generator_sha256",
        "generator_sha256",
        (
            "docs/spec/synthetic-and-null-validation.md",
            "src/ebm_audit/synthetic",
            "uv.lock",
        ),
    ),
    (
        "metrics_rules_sha256",
        "metrics_rules_sha256",
        "metrics_rules_sha256",
        ("docs/spec/metrics-and-uncertainty.md",),
    ),
    (
        "report_language_rules_sha256",
        "report_language_rules_sha256",
        "report_language_rules_sha256",
        ("docs/spec/report-language-rules.md",),
    ),
    (
        "evaluator_source_sha256",
        "evaluator_source_sha256",
        "evaluator_source_sha256",
        (
            "evaluator/scenario_derivation_registry.json",
            "evaluator/scenario_predicate_registry.yaml",
            "schemas/cli-lifecycle-registry.json",
            "schemas/evaluator-receipts.schema.json",
            "schemas/protocol-registry.json",
            "schemas/scenario-derivation-registry.schema.json",
            "schemas/scenario-evidence.schema.json",
            "schemas/scenario-family-payload.schema.json",
            "schemas/scenario-fixture-evidence.schema.json",
            "schemas/scenario-fixture-contract.schema.json",
            "schemas/scenario-fixture-predicate.schema.json",
            "schemas/scenario-predicate.schema.json",
            "schemas/scientific-invariant-counterexample.schema.json",
            "schemas/scientific-invariant.schema.json",
            "src/ebm_audit/evaluator",
        ),
    ),
    (
        "normative_authority_sha256",
        "normative_authority",
        "normative_authority_sha256",
        ("docs/spec/ebm-integration-readiness-1.2.0-candidate.md",),
    ),
)

_EXECUTION_SOURCE_DEFINITIONS: Final = (
    ("generation", "src/ebm_audit/synthetic/generator.py"),
    ("preparation", "src/ebm_audit/universe/preparation.py"),
    ("seed", "src/ebm_audit/config/seeds.py"),
    ("request-execution", "src/ebm_audit/adapters/invocation.py"),
    ("capture", "schemas/worker-protocol.schema.json"),
    ("metric-calculation", "src/ebm_audit/metrics/core.py"),
)


class ProfilePlanProvenanceError(ValueError):
    """Fail closed without disclosing rejected repository content."""


def _reject() -> Never:
    raise ProfilePlanProvenanceError("Profile-plan provenance could not be derived or reattested.")


@final
class ProfilePlanProvenance:
    """Opaque, noncopyable, nonserializable owner of one Git-tree attestation."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ProfilePlanProvenance:
        raise TypeError("Profile-plan provenance is privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Profile-plan provenance cannot be subclassed.")

    def __copy__(self) -> Never:
        _reject()

    def __deepcopy__(self, _memo: object) -> Never:
        _reject()

    def __reduce__(self) -> Never:
        _reject()

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject()

    def __getstate__(self) -> Never:
        _reject()

    def __repr__(self) -> str:
        _read_state(self)
        return "ProfilePlanProvenance(<sealed-local-attestation>)"


@dataclass(frozen=True, slots=True, repr=False)
class _ConsumedProfilePlanProvenance:
    """Protected Plan/3 issuance material; never part of a public projection."""

    candidate: dict[str, Any]
    contract_sha256: str
    source_provenance: dict[str, Any]
    execution_source_manifest_preimage: dict[str, Any]
    attestation_receipt_sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class _DerivedProfilePlanProvenance:
    consumed: _ConsumedProfilePlanProvenance
    candidate_manifest: dict[str, Any]
    ordered_source_set_preimages: tuple[dict[str, Any], ...]
    execution_source_manifest: dict[str, Any]
    safe_attestation: dict[str, Any]


@dataclass(frozen=True, slots=True, repr=False)
class _ObservedTree:
    repository_root: Path
    git_object_format: str
    git_commit: str
    entries: tuple[dict[str, Any], ...]
    committed_bytes: dict[str, bytes]


class _ProfilePlanProvenanceState:
    __slots__ = ("derived", "lock", "material_eligible", "repository_root", "status")

    def __init__(
        self,
        *,
        repository_root: Path,
        derived: _DerivedProfilePlanProvenance,
        material_eligible: bool,
    ) -> None:
        self.repository_root = repository_root
        self.derived = derived
        self.material_eligible = material_eligible
        self.lock = RLock()
        self.status = "FRESH"


_STATES: OneShotWeakRegistry[object, _ProfilePlanProvenanceState]
_STATE_ISSUER: OneShotRegistryIssuer[object, _ProfilePlanProvenanceState]
(_STATES, _STATE_ISSUER) = create_one_shot_registry()


def _read_state(owner: object) -> _ProfilePlanProvenanceState:
    if type(owner) is not ProfilePlanProvenance:
        _reject()
    try:
        state = _STATES[owner]
    except (KeyError, TypeError):
        _reject()
    if type(state) is not _ProfilePlanProvenanceState:
        _reject()
    return state


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None:
        _reject()
    try:
        resolved = Path(executable).resolve(strict=True)
    except OSError:
        _reject()
    if not resolved.is_file():
        _reject()
    return os.fspath(resolved)


def _git_environment(executable: str) -> dict[str, str]:
    executable_directory = os.fspath(Path(executable).parent)
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join((executable_directory, os.defpath)),
    }
    for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"):
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    return environment


def _run_git(
    repository_root: Path,
    arguments: Sequence[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    executable = _git_executable()
    try:
        completed = subprocess.run(
            (
                executable,
                "--no-replace-objects",
                "-C",
                os.fspath(repository_root),
                *arguments,
            ),
            check=False,
            input=input_bytes,
            stdin=subprocess.DEVNULL if input_bytes is None else None,
            capture_output=True,
            env=_git_environment(executable),
            close_fds=True,
            shell=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        _reject()
    if completed.returncode != 0:
        _reject()
    return bytes(completed.stdout)


def _decode_git_atom(value: bytes) -> str:
    try:
        decoded = value.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        _reject()
    if decoded != decoded.strip() or "\n" in decoded or "\r" in decoded:
        _reject()
    return decoded


def _safe_repository_path(raw: bytes) -> str:
    try:
        path = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _reject()
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or unicodedata.normalize("NFC", path) != path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        _reject()
    return path


def _tree_rows(repository_root: Path) -> tuple[tuple[str, str, str, bytes], ...]:
    raw = _run_git(repository_root, ("ls-tree", "-r", "-z", "--full-tree", "HEAD"))
    rows: list[tuple[str, str, str, bytes]] = []
    previous_path: bytes | None = None
    for record in raw.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            mode_bytes, object_type_bytes, object_id_bytes = metadata.split(b" ", 2)
        except ValueError:
            _reject()
        mode = _decode_git_atom(mode_bytes)
        object_type = _decode_git_atom(object_type_bytes)
        object_id = _decode_git_atom(object_id_bytes)
        _safe_repository_path(path_bytes)
        if previous_path is not None and path_bytes <= previous_path:
            _reject()
        previous_path = path_bytes
        if (
            mode not in {"100644", "100755", "120000"}
            or object_type != "blob"
            or len(object_id) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in object_id)
        ):
            _reject()
        rows.append((mode, object_type, object_id, path_bytes))
    if not rows:
        _reject()
    return tuple(rows)


def _committed_blobs(
    repository_root: Path,
    rows: Sequence[tuple[str, str, str, bytes]],
) -> tuple[bytes, ...]:
    requested_ids = [row[2] for row in rows]
    output = _run_git(
        repository_root,
        ("cat-file", "--batch"),
        input_bytes=("".join(object_id + "\n" for object_id in requested_ids)).encode("ascii"),
    )
    blobs: list[bytes] = []
    cursor = 0
    for expected_id in requested_ids:
        header_end = output.find(b"\n", cursor)
        if header_end < 0:
            _reject()
        try:
            returned_id_bytes, object_type, size_bytes = output[cursor:header_end].split(b" ", 2)
            returned_id = returned_id_bytes.decode("ascii", errors="strict")
            size_text = size_bytes.decode("ascii", errors="strict")
            size = int(size_text)
        except (UnicodeDecodeError, ValueError):
            _reject()
        if (
            returned_id != expected_id
            or object_type != b"blob"
            or size < 0
            or str(size) != size_text
        ):
            _reject()
        content_start = header_end + 1
        content_end = content_start + size
        if content_end >= len(output) or output[content_end : content_end + 1] != b"\n":
            _reject()
        blobs.append(output[content_start:content_end])
        cursor = content_end + 1
    if cursor != len(output):
        _reject()
    return tuple(blobs)


def _assert_parent_directories(repository_root: Path, path: str) -> None:
    current = repository_root
    for component in path.split("/")[:-1]:
        current = current / component
        try:
            observed = os.lstat(current)
        except OSError:
            _reject()
        if not stat.S_ISDIR(observed.st_mode):
            _reject()


def _read_regular_file_without_symlinks(path: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _reject()
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            _reject()
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev != observed.st_dev
            or after.st_ino != observed.st_ino
            or after.st_mode != observed.st_mode
            or after.st_size != observed.st_size
            or after.st_mtime_ns != observed.st_mtime_ns
            or after.st_ctime_ns != observed.st_ctime_ns
        ):
            _reject()
        return b"".join(chunks), observed
    except OSError:
        _reject()
    finally:
        os.close(descriptor)


def _physical_bytes(
    repository_root: Path,
    *,
    path: str,
    git_mode: str,
) -> bytes:
    _assert_parent_directories(repository_root, path)
    physical_path = repository_root.joinpath(*path.split("/"))
    try:
        observed = os.lstat(physical_path)
    except OSError:
        _reject()
    if git_mode == "120000":
        if not stat.S_ISLNK(observed.st_mode):
            _reject()
        try:
            return os.fsencode(os.readlink(physical_path))
        except OSError:
            _reject()
    if not stat.S_ISREG(observed.st_mode):
        _reject()
    content, opened = _read_regular_file_without_symlinks(physical_path)
    if (
        observed.st_dev != opened.st_dev
        or observed.st_ino != opened.st_ino
        or observed.st_size != opened.st_size
        or (os.name != "nt" and bool(opened.st_mode & 0o111) != (git_mode == "100755"))
    ):
        _reject()
    return content


def _observe_tree(repository_root: Path) -> _ObservedTree:
    try:
        resolved = repository_root.resolve(strict=True)
    except OSError:
        _reject()
    top_level_raw = _run_git(resolved, ("rev-parse", "--show-toplevel"))
    try:
        top_level = Path(top_level_raw.decode("utf-8", errors="strict").rstrip("\n")).resolve(
            strict=True
        )
    except (OSError, UnicodeDecodeError):
        _reject()
    if top_level != resolved or _run_git(resolved, ("replace", "--list")):
        _reject()
    object_format = _decode_git_atom(
        _run_git(resolved, ("rev-parse", "--show-object-format")).rstrip(b"\n")
    )
    commit = _decode_git_atom(
        _run_git(resolved, ("rev-parse", "--verify", "HEAD^{commit}")).rstrip(b"\n")
    )
    expected_oid_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    if (
        len(commit) != expected_oid_length
        or any(character not in "0123456789abcdef" for character in commit)
        or _run_git(
            resolved,
            (
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ),
        )
    ):
        _reject()
    rows = _tree_rows(resolved)
    blobs = _committed_blobs(resolved, rows)
    entries: list[dict[str, Any]] = []
    committed_bytes: dict[str, bytes] = {}
    for (mode, _object_type, object_id, raw_path), blob in zip(rows, blobs, strict=True):
        if len(object_id) != expected_oid_length:
            _reject()
        path = _safe_repository_path(raw_path)
        physical = _physical_bytes(resolved, path=path, git_mode=mode)
        if physical != blob:
            _reject()
        if path in committed_bytes:
            _reject()
        committed_bytes[path] = blob
        entries.append(
            {
                "path": path,
                "git_mode": mode,
                "kind": "symlink" if mode == "120000" else "file",
                "byte_length": len(blob),
                "sha256": "sha256:" + hashlib.sha256(blob).hexdigest(),
            }
        )
    try:
        ending_top_level = Path(
            _run_git(resolved, ("rev-parse", "--show-toplevel"))
            .decode("utf-8", errors="strict")
            .rstrip("\n")
        ).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        _reject()
    if (
        ending_top_level != resolved
        or _run_git(resolved, ("replace", "--list"))
        or _decode_git_atom(_run_git(resolved, ("rev-parse", "--show-object-format")).rstrip(b"\n"))
        != object_format
        or _decode_git_atom(
            _run_git(resolved, ("rev-parse", "--verify", "HEAD^{commit}")).rstrip(b"\n")
        )
        != commit
        or _run_git(
            resolved,
            (
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ),
        )
        or _tree_rows(resolved) != rows
    ):
        _reject()
    return _ObservedTree(
        repository_root=resolved,
        git_object_format=object_format,
        git_commit=commit,
        entries=tuple(entries),
        committed_bytes=committed_bytes,
    )


def _matches_root(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _candidate_manifest(observed: _ObservedTree) -> tuple[dict[str, Any], str]:
    manifest = {
        "schema_version": "ebm-audit-candidate-tree/1.0",
        "git_object_format": observed.git_object_format,
        "git_commit": observed.git_commit,
        "entries": copy.deepcopy(list(observed.entries)),
    }
    validate_instance(
        manifest,
        "source-set-manifest.schema.json",
        definition="CandidateTreeManifest",
    )
    return manifest, structured_sha256_hex(_CANDIDATE_DOMAIN, manifest)


def _source_set_material(
    observed: _ObservedTree,
) -> tuple[tuple[dict[str, Any], ...], list[dict[str, Any]]]:
    preimages: list[dict[str, Any]] = []
    identities: list[dict[str, Any]] = []
    for source_role, component_kind, destination_field, roots in _SOURCE_SET_DEFINITIONS:
        selected = [
            copy.deepcopy(entry)
            for entry in observed.entries
            if any(_matches_root(cast(str, entry["path"]), root) for root in roots)
        ]
        if (
            not selected
            or any(
                not any(_matches_root(cast(str, entry["path"]), root) for entry in selected)
                for root in roots
            )
            or any(
                sum(_matches_root(cast(str, entry["path"]), root) for root in roots) != 1
                for entry in selected
            )
        ):
            _reject()
        preimage = {
            "component_kind": component_kind,
            "destination_field": destination_field,
            "manifest": {
                "schema_version": "ebm-audit-source-set/1.0",
                "declared_roots": list(roots),
                "entries": selected,
            },
        }
        validate_instance(
            preimage,
            "source-set-manifest.schema.json",
            definition="SourceSetDigestPreimage",
        )
        preimages.append(preimage)
        identities.append(
            {
                "source_role": source_role,
                "source_set_sha256": structured_sha256_hex(_SOURCE_SET_DOMAIN, preimage),
            }
        )
    return tuple(preimages), identities


def _execution_source_material(
    observed: _ObservedTree,
) -> tuple[dict[str, Any], dict[str, Any]]:
    by_path = {cast(str, entry["path"]): entry for entry in observed.entries}
    ordered_entries: list[dict[str, Any]] = []
    for fit_role, path in _EXECUTION_SOURCE_DEFINITIONS:
        entry = by_path.get(path)
        if entry is None or entry["kind"] != "file":
            _reject()
        ordered_entries.append(
            {
                "fit_role": fit_role,
                "ordered_files": [copy.deepcopy(entry)],
            }
        )
    preimage = {
        "manifest_schema_version": "ebm-audit-profile-execution-source-manifest/1.0",
        "attestation_state": "DECLARED_PRE_EXECUTION_NOT_ATTESTED",
        "executor_attestation_requirement": (
            "DERIVE_AND_MATCH_EACH_ENTRY_AGAINST_EXACT_CANDIDATE_TREE_BEFORE_FIT"
        ),
        "ordered_entries": ordered_entries,
        "profile_execution_source_manifest_sha256": None,
    }
    validate_instance(
        preimage,
        "evaluator-receipts.schema.json",
        definition="ProfileExecutionSourceManifestDigestPreimage",
    )
    manifest = copy.deepcopy(preimage)
    manifest["profile_execution_source_manifest_sha256"] = structured_sha256_hex(
        _EXECUTION_SOURCE_DOMAIN,
        preimage,
    )
    validate_instance(
        manifest,
        "evaluator-receipts.schema.json",
        definition="ProfileExecutionSourceManifest",
    )
    return preimage, manifest


def _contract_sha256(observed: _ObservedTree) -> str:
    contract_candidates = [
        observed.committed_bytes[path]
        for path in _CONTRACT_PATHS
        if path in observed.committed_bytes
    ]
    if len(contract_candidates) != 1:
        _reject()
    raw = contract_candidates[0]
    try:
        parsed = load_strict_yaml_bytes(raw, maximum_bytes=_MAXIMUM_CONTRACT_BYTES)
    except StrictYamlError:
        _reject()
    if type(parsed) is not dict:
        _reject()
    projection = copy.deepcopy(cast(dict[str, Any], parsed))
    digest_owners: list[dict[str, Any]] = []

    def find_digest_owner(value: object) -> None:
        if type(value) is dict:
            mapping = cast(dict[str, Any], value)
            claimed = mapping.get("contract_sha256", object())
            if claimed is None or (
                type(claimed) is str
                and len(claimed) == 64
                and all(character in "0123456789abcdef" for character in claimed)
            ):
                digest_owners.append(mapping)
            for child in mapping.values():
                find_digest_owner(child)
        elif type(value) is list:
            for child in cast(list[object], value):
                find_digest_owner(child)

    find_digest_owner(projection)
    if len(digest_owners) != 1:
        _reject()
    claimed = digest_owners[0]["contract_sha256"]
    digest_owners[0]["contract_sha256"] = None
    derived = structured_sha256_hex(_CONTRACT_DOMAIN, projection)
    if claimed is not None and claimed != derived:
        _reject()
    return derived


def _derive_once(repository_root: Path) -> _DerivedProfilePlanProvenance:
    observed = _observe_tree(repository_root)
    candidate_manifest, candidate_sha256 = _candidate_manifest(observed)
    source_preimages, source_identities = _source_set_material(observed)
    execution_preimage, execution_manifest = _execution_source_material(observed)
    contract_sha256 = _contract_sha256(observed)
    source_provenance = {
        "provenance_schema_version": "ebm-audit-profile-plan-source-provenance/1.0",
        "attestation_state": "DECLARED_PRE_EXECUTION_NOT_ATTESTED",
        "ordered_source_set_identities": copy.deepcopy(source_identities),
    }
    validate_instance(
        source_provenance,
        "evaluator-receipts.schema.json",
        definition="ProfilePlanSourceProvenance",
    )
    candidate = {
        "git_object_format": observed.git_object_format,
        "git_commit": observed.git_commit,
        "candidate_sha256": candidate_sha256,
    }
    validate_instance(
        candidate,
        "evaluator-receipts.schema.json",
        definition="CandidateIdentity",
    )
    source_digest_rows = [
        {
            **copy.deepcopy(identity),
            "entry_count": len(cast(dict[str, Any], preimage["manifest"])["entries"]),
        }
        for identity, preimage in zip(source_identities, source_preimages, strict=True)
    ]
    attestation = {
        "attestation_schema_version": ("ebm-audit-profile-plan-provenance-attestation/1.0"),
        "attestation_state": "CLEAN_COMMITTED_TREE_ATTESTED",
        "git_object_format": observed.git_object_format,
        "git_commit": observed.git_commit,
        "candidate_sha256": candidate_sha256,
        "contract_sha256": contract_sha256,
        "ordered_source_set_digests": source_digest_rows,
        "profile_execution_source_manifest_sha256": execution_manifest[
            "profile_execution_source_manifest_sha256"
        ],
        "candidate_entry_count": len(observed.entries),
        "source_set_entry_count": sum(row["entry_count"] for row in source_digest_rows),
        "execution_source_entry_count": len(_EXECUTION_SOURCE_DEFINITIONS),
        "attestation_receipt_sha256": None,
    }
    validate_instance(
        attestation,
        "profile-plan-provenance.schema.json",
        definition="ProfilePlanProvenanceAttestationDigestPreimage",
    )
    attestation["attestation_receipt_sha256"] = structured_sha256_hex(
        _ATTESTATION_DOMAIN,
        attestation,
    )
    validate_instance(
        attestation,
        "profile-plan-provenance.schema.json",
        definition="ProfilePlanProvenanceAttestation",
    )
    return _DerivedProfilePlanProvenance(
        consumed=_ConsumedProfilePlanProvenance(
            candidate=candidate,
            contract_sha256=contract_sha256,
            source_provenance=source_provenance,
            execution_source_manifest_preimage=execution_preimage,
            attestation_receipt_sha256=cast(
                str,
                attestation["attestation_receipt_sha256"],
            ),
        ),
        candidate_manifest=candidate_manifest,
        ordered_source_set_preimages=source_preimages,
        execution_source_manifest=execution_manifest,
        safe_attestation={
            "projection_schema_version": ("ebm-audit-profile-plan-provenance-projection/1.0"),
            "attestation": attestation,
        },
    )


def _derive_at_root(repository_root: Path) -> _DerivedProfilePlanProvenance:
    """Derive protected and safe state from one internally bracketed observation."""

    try:
        return _derive_once(repository_root)
    except ProfilePlanProvenanceError:
        raise
    except (OSError, TypeError, ValueError, SchemaValidationError, RecursionError):
        _reject()


def _issue(
    repository_root: Path,
    derived: _DerivedProfilePlanProvenance,
    *,
    material_eligible: bool,
) -> ProfilePlanProvenance:
    owner = object.__new__(ProfilePlanProvenance)
    _STATE_ISSUER.bind_once(
        owner,
        _ProfilePlanProvenanceState(
            repository_root=repository_root,
            derived=derived,
            material_eligible=material_eligible,
        ),
    )
    return owner


def derive_profile_plan_provenance() -> ProfilePlanProvenance:
    """Derive one material provenance owner from the package repository root."""

    try:
        repository_root = Path(__file__).resolve(strict=True).parents[3]
    except (OSError, IndexError):
        _reject()
    return _issue(
        repository_root,
        _derive_at_root(repository_root),
        material_eligible=True,
    )


def _derive_profile_plan_provenance_for_test(
    repository_root: Path,
) -> ProfilePlanProvenance:
    """Test-only seam for synthetic temporary Git repositories."""

    if not isinstance(repository_root, Path):
        _reject()
    try:
        resolved = repository_root.resolve(strict=True)
    except OSError:
        _reject()
    return _issue(
        resolved,
        _derive_at_root(resolved),
        material_eligible=False,
    )


def project_profile_plan_provenance(
    owner: ProfilePlanProvenance,
) -> dict[str, Any]:
    """Return a detached digest-and-count-only projection."""

    state = _read_state(owner)
    with state.lock:
        projection = copy.deepcopy(state.derived.safe_attestation)
        projection["owner_state"] = state.status
        try:
            validate_instance(
                projection,
                "profile-plan-provenance.schema.json",
                definition="ProfilePlanProvenanceProjection",
            )
        except SchemaValidationError:
            _reject()
        return projection


def _consume_profile_plan_provenance(
    owner: ProfilePlanProvenance,
) -> _ConsumedProfilePlanProvenance:
    """Reattest and consume one owner for material Plan/3 issuance."""

    return _consume_profile_plan_provenance_state(owner, material_required=True)


def _consume_profile_plan_provenance_for_test(
    owner: ProfilePlanProvenance,
) -> _ConsumedProfilePlanProvenance:
    """Consume one explicitly non-material synthetic-repository owner."""

    return _consume_profile_plan_provenance_state(owner, material_required=False)


def _consume_profile_plan_provenance_state(
    owner: ProfilePlanProvenance,
    *,
    material_required: bool,
) -> _ConsumedProfilePlanProvenance:
    state = _read_state(owner)
    with state.lock:
        try:
            package_root = Path(__file__).resolve(strict=True).parents[3]
        except (OSError, IndexError):
            _reject()
        if (
            state.status != "FRESH"
            or state.material_eligible is not material_required
            or (material_required and state.repository_root != package_root)
        ):
            _reject()
        observed = _derive_at_root(state.repository_root)
        if observed != state.derived:
            _reject()
        state.status = "CONSUMED"
        return copy.deepcopy(state.derived.consumed)


def _require_profile_plan_provenance_current(
    owner: ProfilePlanProvenance,
    expected_state: _ConsumedProfilePlanProvenance,
) -> _ConsumedProfilePlanProvenance:
    """Require one consumed owner and reattest its exact tree now."""

    return _require_profile_plan_provenance_state_current(
        owner,
        expected_state,
        material_required=True,
    )


def _require_profile_plan_provenance_for_test_current(
    owner: ProfilePlanProvenance,
    expected_state: _ConsumedProfilePlanProvenance,
) -> _ConsumedProfilePlanProvenance:
    """Reattest one consumed non-material synthetic-repository owner."""

    return _require_profile_plan_provenance_state_current(
        owner,
        expected_state,
        material_required=False,
    )


def _require_profile_plan_provenance_state_current(
    owner: ProfilePlanProvenance,
    expected_state: _ConsumedProfilePlanProvenance,
    *,
    material_required: bool,
) -> _ConsumedProfilePlanProvenance:
    state = _read_state(owner)
    with state.lock:
        try:
            package_root = Path(__file__).resolve(strict=True).parents[3]
        except (OSError, IndexError):
            _reject()
        if (
            state.status != "CONSUMED"
            or state.material_eligible is not material_required
            or (material_required and state.repository_root != package_root)
            or expected_state != state.derived.consumed
        ):
            _reject()
        observed = _derive_at_root(state.repository_root)
        if observed != state.derived:
            _reject()
        return state.derived.consumed


__all__ = [
    "ProfilePlanProvenance",
    "ProfilePlanProvenanceError",
    "derive_profile_plan_provenance",
    "project_profile_plan_provenance",
]
