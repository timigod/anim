"""Validate source and distribution identities without importing auditor internals."""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
import csv
import hashlib
import io
import json
import re
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

PUBLIC_HASHES = {
    "anim-0.1.1-py3-none-any.whl": "b44da7bd75cf6816fea502d043631481a21ae7e26cd153d4a23f19b6aa96da34",  # noqa: E501
    "anim-0.1.1.tar.gz": "6ee1ff6e2428a5639255d13a65757289112410e49e835163c36b22f96cb7470d",
}
REPOSITORY = "https://github.com/timigod/anim"
# Keep the historical public-inventory exclusions without embedding excluded prose.
FORBIDDEN_NAMES = (
    "heldout" + "_manifest",
    "/workers/" + "pysaebm/",
    "contract-" + "acceptance",
    "acquisition-" + "receipt",
    "environment-" + "receipt",
    "robustness-auditor-" + "build-prompt",
    "/research/",
    "/.venv/",
    "/__pycache__/",
    "/.git/",
    "/tmp/",
    ".pyc",
)
FORBIDDEN_CONTENT = (
    b"robustness-auditor-" + b"build-prompt",
    b"build_" + b"prompt",
    b"heldout_" + b"manifest.json",
    b"/use" + b"rs/",
    b"/private/" + b"tmp/",
)
FORBIDDEN_IDENTITY_HASHES = {
    "2307040750d61ff6c7d5cd57959d6632d8ee77cbe87330e9d584fea73850f39d",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def module_version(payload: bytes) -> str:
    tree = ast.parse(payload)
    values = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
    ]
    require(len(values) == 1 and isinstance(values[0], str), "missing/ambiguous package version")
    return values[0]


def check_source(root: Path, tag: str | None = None) -> dict:
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    version = project["version"]
    require(project["name"] == "anim", "project name drift")
    require(str(Version(version)) == version, "version is not normalized PEP 440")
    require(
        module_version((root / "src/ebm_audit/__init__.py").read_bytes()) == version,
        "package/source version drift",
    )
    lock = tomllib.loads((root / "uv.lock").read_text())
    local = [p for p in lock["package"] if p["name"] == "anim"]
    require(len(local) == 1 and local[0]["version"] == version, "lock/project version drift")
    require(
        SpecifierSet(project["requires-python"]) == SpecifierSet(">=3.12,<3.13"),
        "supported Python range changed without compatibility evidence",
    )
    require(
        SpecifierSet(lock["requires-python"]) == SpecifierSet("==3.12.*"), "lock Python range drift"
    )
    readme = (root / "README.md").read_text()
    require(f"Development version: **{version}**" in readme, "README development version drift")
    headings = re.findall(r"^## (\d[^\n]*)", (root / "CHANGELOG.md").read_text(), re.M)
    require(bool(headings) and headings[0].split(" - ")[0] == version, "changelog version drift")
    if Version(version).is_devrelease:
        require(headings[0].endswith(" - Unreleased"), "development changelog claims a release")
    require(
        project["urls"]
        == {
            "Repository": REPOSITORY,
            "Issues": f"{REPOSITORY}/issues",
            "Documentation": f"{REPOSITORY}/tree/main/docs",
            "Changelog": f"{REPOSITORY}/blob/main/CHANGELOG.md",
        },
        "project URL drift",
    )
    # Resolve local and canonical source links; no network or account access is needed.
    for target in re.findall(r"\]\(([^)]+)\)", readme):
        relative = None
        for kind in ("blob", "tree"):
            prefix = f"{REPOSITORY}/{kind}/main/"
            if target.startswith(prefix):
                relative = target.removeprefix(prefix)
        if "://" not in target and not target.startswith("#"):
            relative = target
        if relative:
            require((root / relative.split("#")[0]).exists(), "README source link is missing")
    manifest = (root / "release/anim-0.1.1-sha256.txt").read_text()
    expected = "".join(f"{digest}  {name}\n" for name, digest in PUBLIC_HASHES.items())
    require(manifest == expected, "immutable 0.1.1 hash manifest changed")
    if tag is not None:
        require(tag == f"v{version}", "tag/project version drift")
    return project


def safe_name(name: str) -> None:
    path = PurePosixPath(name)
    require(
        not path.is_absolute() and ".." not in path.parts and "\\" not in name,
        "unsafe archive member",
    )
    require(
        not any(part in f"/{name.lower()}" for part in FORBIDDEN_NAMES),
        f"excluded inventory member: {name}",
    )


def check_inventory(payloads: dict[str, bytes]) -> None:
    for name, payload in payloads.items():
        safe_name(name)
        lower = payload.lower()
        require(
            not any(fragment in lower for fragment in FORBIDDEN_CONTENT),
            f"excluded content in member: {name}",
        )
        tokens = re.findall(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", lower)
        require(
            not any(hashlib.sha256(t).hexdigest() in FORBIDDEN_IDENTITY_HASHES for t in tokens),
            f"excluded identity in member: {name}",
        )


def check_metadata(payload: bytes, project: dict) -> None:
    metadata = BytesParser().parsebytes(payload)
    for field, key in (("Name", "name"), ("Version", "version"), ("Summary", "description")):
        require(metadata[field] == project[key], f"distribution {field} drift")
    require(
        SpecifierSet(metadata["Requires-Python"]) == SpecifierSet(project["requires-python"]),
        "distribution Python requirement drift",
    )
    require(metadata["License-Expression"] == project["license"], "distribution license drift")
    require(
        set(metadata.get_all("Project-URL", []))
        == {f"{key}, {value}" for key, value in project["urls"].items()},
        "distribution URL drift",
    )
    actual = [Requirement(value) for value in metadata.get_all("Requires-Dist", [])]
    expected = [Requirement(value) for value in project["dependencies"]]
    require(
        set(actual) == set(expected) and len(actual) == len(expected),
        "distribution runtime requirement drift",
    )
    require(metadata["Description-Content-Type"] == "text/markdown", "missing Markdown metadata")
    require(bool(metadata.get_payload()), "empty package description")


def check_record(payloads: dict[str, bytes], record_name: str) -> None:
    rows = list(csv.reader(io.StringIO(payloads[record_name].decode())))
    names = [row[0] for row in rows]
    require(
        len(names) == len(set(names)) and set(names) == set(payloads),
        "wheel RECORD inventory drift",
    )
    for name, digest, size in rows:
        if name == record_name:
            require(digest == size == "", "wheel RECORD cannot hash itself")
            continue
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(payloads[name]).digest()).rstrip(b"=").decode()
        )
        require(
            digest == f"sha256={expected}" and size == str(len(payloads[name])),
            f"wheel RECORD integrity mismatch: {name}",
        )


def source_files(root: Path, relative: str) -> list[Path]:
    path = root / relative.lstrip("/")
    require(path.exists(), f"declared package resource missing: {relative}")
    require(not path.is_symlink(), "declared resource is a symlink")
    candidates = list(path.rglob("*")) if path.is_dir() else [path]
    require(not any(p.is_symlink() for p in candidates), "package resource contains a symlink")
    return [
        p
        for p in candidates
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.suffix != ".pyc"
        and not any(part.startswith(".") for part in p.relative_to(root).parts)
    ]


def check_distributions(root: Path, directory: Path, project: dict) -> dict[str, str]:
    version = project["version"]
    wheel_name = f"anim-{version}-py3-none-any.whl"
    sdist_name = f"anim-{version}.tar.gz"
    actual = {p.name for p in directory.iterdir() if not p.name.startswith(".")}
    require(actual == {wheel_name, sdist_name}, "distribution filenames or count drift")
    with zipfile.ZipFile(directory / wheel_name) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), "duplicate wheel members")
        require(archive.testzip() is None, "wheel CRC failure")
        wheel = {n: archive.read(n) for n in archive.namelist() if not n.endswith("/")}
    prefix = f"anim-{version}.dist-info"
    check_metadata(wheel[f"{prefix}/METADATA"], project)
    wheel_metadata = BytesParser().parsebytes(wheel[f"{prefix}/WHEEL"])
    require(
        wheel_metadata["Wheel-Version"] == "1.0"
        and wheel_metadata["Root-Is-Purelib"] == "true"
        and wheel_metadata.get_all("Tag") == ["py3-none-any"],
        "wheel compatibility tag drift",
    )
    check_record(wheel, f"{prefix}/RECORD")
    entrypoints = configparser.ConfigParser()
    entrypoints.read_string(wheel[f"{prefix}/entry_points.txt"].decode())
    require(dict(entrypoints["console_scripts"]) == project["scripts"], "CLI entry point drift")
    require(module_version(wheel["ebm_audit/__init__.py"]) == version, "wheel import version drift")
    source = {}
    with tarfile.open(directory / sdist_name, "r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            safe_name(member.name)
            require(path.parts[0] == f"anim-{version}", "source archive root drift")
            require(member.isdir() or member.isfile(), "source archive contains special member")
            if member.isfile():
                name = path.relative_to(f"anim-{version}").as_posix()
                require(name not in source, "duplicate source members")
                handle = archive.extractfile(member)
                require(handle is not None, "source member cannot be read")
                source[name] = handle.read()
    check_metadata(source["PKG-INFO"], project)
    for payload in (wheel[f"{prefix}/METADATA"], source["PKG-INFO"]):
        description = BytesParser().parsebytes(payload).get_payload()
        require(
            description.rstrip() == (root / "README.md").read_text().rstrip(),
            "distribution README description drift",
        )
    require(
        wheel[f"{prefix}/licenses/LICENSE"] == (root / "LICENSE").read_bytes(),
        "distribution license text drift",
    )
    build = tomllib.loads((root / "pyproject.toml").read_text())["tool"]["hatch"]["build"][
        "targets"
    ]
    expected_source = {"PKG-INFO", ".gitignore"}
    require(
        source.get(".gitignore") == (root / ".gitignore").read_bytes(), "sdist ignore rules drift"
    )
    for relative in build["sdist"]["include"]:
        for path in source_files(root, relative):
            name = path.relative_to(root).as_posix()
            expected_source.add(name)
            require(source.get(name) == path.read_bytes(), f"source resource missing/stale: {name}")
    require(set(source) == expected_source, "source archive has undeclared resources")
    expected_wheel = {
        f"{prefix}/{name}"
        for name in ("METADATA", "WHEEL", "entry_points.txt", "RECORD", "licenses/LICENSE")
    }
    mappings = {"src/ebm_audit": "ebm_audit", **build["wheel"]["force-include"]}
    for relative, destination in mappings.items():
        base = root / relative
        for path in source_files(root, relative):
            name = (
                (PurePosixPath(destination) / path.relative_to(base)).as_posix()
                if base.is_dir()
                else destination
            )
            expected_wheel.add(name)
            require(wheel.get(name) == path.read_bytes(), f"wheel resource missing/stale: {name}")
    require(set(wheel) == expected_wheel, "wheel has undeclared resources")
    check_inventory(wheel)
    check_inventory(source)
    return {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in sorted(actual)
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--tag")
    args = parser.parse_args()
    try:
        project = check_source(args.root, args.tag)
        hashes = check_distributions(args.root, args.dist, project) if args.dist else None
    except (ValueError, KeyError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit(f"packaging validation failed: {error}") from None
    print(
        json.dumps(
            {"status": "PASS", "version": project["version"], "sha256": hashes}, sort_keys=True
        )
    )


if __name__ == "__main__":
    main()
