"""Exact source and dependency code identity; never reads sample datasets."""

from __future__ import annotations

import importlib.metadata
import platform
import sys
from pathlib import Path

from ebm_audit.protocol import exact_file_sha256, structured_sha256
from ebm_audit.worker_sdk import EvidenceReference, WorkerIdentity

ROOT = Path(__file__).resolve().parent


def build_identity(manifest: dict) -> WorkerIdentity:
    executable_digest = exact_file_sha256(Path(sys.executable).resolve().read_bytes())
    requirements = [
        line
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if line and not line.startswith("#")
    ]
    # The SDK's installed dependencies also affect validation/canonicalization.
    # Anim currently declares exact pins with no extras/markers; fail closed if
    # that contract changes instead of silently ignoring a dependency.
    for requirement in importlib.metadata.requires("anim") or ():
        if "==" not in requirement or ";" in requirement or "[" in requirement:
            raise ValueError("EXAMPLE.CORE_REQUIREMENTS_UNSUPPORTED")
        if requirement not in requirements:
            requirements.append(requirement)
    dependencies = []
    for requirement in requirements:
        name, version = requirement.split("==")
        distribution = importlib.metadata.distribution(name)
        if distribution.version != version:
            raise ValueError("EXAMPLE.ENVIRONMENT_DRIFT: install the exact worker requirements.")
        entries = []
        for relative in sorted(distribution.files or (), key=str):
            # Dataset/sample/test files are not opened, even to hash them. The
            # executable dependency code and native library surface is inventoried.
            if any(
                part in {"tests", "test", "datasets", "data", "__pycache__"}
                for part in relative.parts
            ):
                continue
            if str(relative).startswith(".."):
                continue
            if not str(relative).endswith((".py", ".dylib", ".dll", "/METADATA")) and (
                ".so" not in relative.name
            ):
                continue
            path = Path(distribution.locate_file(relative))
            if path.is_file():
                entries.append(
                    {"path": str(relative), "sha256": exact_file_sha256(path.read_bytes())}
                )
        dependencies.append({"name": name, "version": version, "code_files": entries})
    import ebm_audit

    sdk_root = Path(ebm_audit.__file__).resolve().parent
    # Inventory the worker SDK/transport closure, not unrelated auditor CLI,
    # reporting or evaluator code, which has its own execution identity.
    sdk_paths = {
        sdk_root / name for name in ("__init__.py", "errors.py", "_capability_registry.py")
    }
    for directory in ("worker_sdk", "protocol", "schema", "privacy", "artifacts", "workers"):
        sdk_paths.update((sdk_root / directory).glob("*.py"))
    sdk_files = [
        {
            "path": path.relative_to(sdk_root).as_posix(),
            "sha256": exact_file_sha256(path.read_bytes()),
        }
        for path in sorted(sdk_paths)
    ]
    code = [
        {"path": name, "sha256": exact_file_sha256((ROOT / name).read_bytes())}
        for name in (
            "worker.py",
            "model.py",
            "identity.py",
            "provision.py",
            "source-manifest.json",
            "requirements.txt",
        )
    ]
    code_digest = structured_sha256("anim/pysaebm-example-code/1", code)
    source_digest = structured_sha256("anim/pysaebm-example-source/1", manifest)
    environment_digest = structured_sha256(
        "anim/pysaebm-example-environment/1",
        {
            "python": platform.python_version(),
            "executable": executable_digest,
            "os": platform.system(),
            "architecture": platform.machine(),
            "abi": sys.implementation.cache_tag,
            "dependencies": dependencies,
            "anim_version": ebm_audit.__version__,
            "sdk_code": sdk_files,
            "numba_disable_jit": True,
            "threads": 1,
            "requirements_sha256": exact_file_sha256((ROOT / "requirements.txt").read_bytes()),
        },
    )
    return WorkerIdentity(
        adapter_id="anim-pysaebm-example",
        adapter_version="0.2.0.dev0",
        worker_executable_digest=executable_digest,
        worker_code_digest=code_digest,
        backend_name="pysaebm",
        backend_version=manifest["version"],
        backend_source_commit=manifest["commit"],
        backend_source_digest=source_digest,
        environment_digest=environment_digest,
        identity_evidence=(
            EvidenceReference(
                "exact-public-source-manifest",
                source_digest,
                "Four exact source and MIT license files; no upstream datasets.",
            ),
            EvidenceReference(
                "dependency-code-inventory",
                environment_digest,
                "Pinned dependency code and native libraries; dataset files excluded.",
            ),
        ),
    )
