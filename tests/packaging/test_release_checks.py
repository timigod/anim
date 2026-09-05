"""Focused packaging regressions; no private evaluators or scientific fixtures."""

from __future__ import annotations

import base64
import csv
import importlib.util
import io
import tomllib
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/packaging/check_release.py"
spec = importlib.util.spec_from_file_location("release_check", SCRIPT)
assert spec is not None and spec.loader is not None
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


@pytest.fixture
def source(tmp_path):
    root = SCRIPT.parents[2]
    current_version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    for relative in (
        "pyproject.toml",
        "uv.lock",
        "src/ebm_audit/__init__.py",
        "CHANGELOG.md",
        "release/anim-0.1.1-sha256.txt",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (root / relative).read_text()
        if relative != "release/anim-0.1.1-sha256.txt":
            content = content.replace(current_version, "0.2.0.dev0")
        if relative == "CHANGELOG.md":
            lines = content.splitlines()
            index = next(i for i, line in enumerate(lines) if line.startswith("## "))
            lines[index] = "## 0.2.0.dev0 - Unreleased"
            content = "\n".join(lines) + "\n"
        path.write_text(content)
    (tmp_path / "README.md").write_text("Development version: **0.2.0.dev0** (unreleased).\n")
    return tmp_path


def test_coherent_development_version_and_tag(source):
    assert check.check_source(source, "v0.2.0.dev0")["version"] == "0.2.0.dev0"


def test_next_development_version_does_not_need_checker_edits(source):
    for relative in (
        "pyproject.toml",
        "uv.lock",
        "src/ebm_audit/__init__.py",
        "CHANGELOG.md",
        "README.md",
    ):
        path = source / relative
        path.write_text(path.read_text().replace("0.2.0.dev0", "0.2.0.dev1"))
    assert check.check_source(source)["version"] == "0.2.0.dev1"


@pytest.mark.parametrize(
    "relative", ["uv.lock", "src/ebm_audit/__init__.py", "README.md", "CHANGELOG.md"]
)
def test_single_surface_version_drift_is_rejected(source, relative):
    path = source / relative
    path.write_text(path.read_text().replace("0.2.0.dev0", "0.1.1"))
    with pytest.raises(ValueError, match="drift"):
        check.check_source(source)


def test_wrong_tag_is_rejected(source):
    with pytest.raises(ValueError, match="tag/project"):
        check.check_source(source, "v0.1.1")


def test_development_version_cannot_claim_release(source):
    path = source / "CHANGELOG.md"
    path.write_text(path.read_text().replace("Unreleased", "2026-09-05"))
    with pytest.raises(ValueError, match="claims a release"):
        check.check_source(source)


@pytest.mark.parametrize("changelog_date", ["2026-09-05", "Unreleased", "2026-02-30"])
def test_stable_release_requires_matching_version_tag_and_valid_date(source, changelog_date):
    for relative in (
        "pyproject.toml", "uv.lock", "src/ebm_audit/__init__.py", "CHANGELOG.md", "README.md"
    ):
        path = source / relative
        content = path.read_text().replace("0.2.0.dev0", "0.2.0")
        content = content.replace("Development version:", "Version:")
        if relative == "CHANGELOG.md":
            content = content.replace("Unreleased", changelog_date)
        path.write_text(content)
    if changelog_date == "2026-09-05":
        assert check.check_source(source, "v0.2.0")["version"] == "0.2.0"
        with pytest.raises(ValueError, match="tag/project"):
            check.check_source(source, "v0.2.1")
    else:
        with pytest.raises(ValueError):
            check.check_source(source, "v0.2.0")


def test_immutable_public_hashes_cannot_be_rewritten(source):
    path = source / "release/anim-0.1.1-sha256.txt"
    path.write_text(path.read_text().replace("b44da7bd", "00000000"))
    with pytest.raises(ValueError, match="immutable"):
        check.check_source(source)


def test_unverified_python_widening_is_rejected(source):
    path = source / "pyproject.toml"
    path.write_text(path.read_text().replace(">=3.12,<3.13", ">=3.12,<3.14"))
    with pytest.raises(ValueError, match="compatibility evidence"):
        check.check_source(source)


def test_broken_readme_link_is_rejected(source):
    with (source / "README.md").open("a") as handle:
        handle.write("[guide](docs/missing.md)\n")
    with pytest.raises(ValueError, match="source link"):
        check.check_source(source)


@pytest.mark.parametrize(
    "name",
    [
        "../escape.py",
        "/absolute.py",
        "a/../../escape.py",
        "a\\escape.py",
        "a/__pycache__/x.pyc",
        "a/.venv/x.py",
    ],
)
def test_unsafe_archive_inventory_is_rejected(name):
    with pytest.raises(ValueError):
        check.check_inventory({name: b"synthetic fixture"})


def test_machine_path_leak_is_rejected_without_printing_payload():
    payload = b"/use" + b"rs/example/local-artifact"
    with pytest.raises(ValueError, match="excluded content") as caught:
        check.check_inventory({"README.md": payload})
    assert payload.decode() not in str(caught.value)


def recorded_wheel():
    payload = b"synthetic resource"
    digest = base64.urlsafe_b64encode(check.hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    out = io.StringIO()
    csv.writer(out).writerows(
        [["resource.txt", f"sha256={digest}", len(payload)], ["anim.dist-info/RECORD", "", ""]]
    )
    return {"resource.txt": payload, "anim.dist-info/RECORD": out.getvalue().encode()}


def test_valid_wheel_record():
    check.check_record(recorded_wheel(), "anim.dist-info/RECORD")


def test_tampered_wheel_payload_fails_integrity():
    payloads = recorded_wheel()
    payloads["resource.txt"] = b"altered resource"
    with pytest.raises(ValueError, match="integrity mismatch"):
        check.check_record(payloads, "anim.dist-info/RECORD")


def test_unrecorded_wheel_member_fails_inventory():
    payloads = recorded_wheel()
    payloads["extra.py"] = b""
    with pytest.raises(ValueError, match="RECORD inventory"):
        check.check_record(payloads, "anim.dist-info/RECORD")


def test_wrong_distribution_filename_is_rejected(source, tmp_path):
    directory = tmp_path / "wrong-dist"
    directory.mkdir()
    (directory / "anim-0.1.1-py3-none-any.whl").write_bytes(b"")
    with pytest.raises(ValueError, match="filenames"):
        check.check_distributions(source, directory, check.check_source(source))


def test_source_symlink_cannot_pull_files_into_distribution(source):
    path = source / "linked-resource"
    path.symlink_to(source / "README.md")
    with pytest.raises(ValueError, match="symlink"):
        check.source_files(source, "linked-resource")


def metadata_bytes(project, **overrides):
    from email.message import EmailMessage

    message = EmailMessage()
    fields = {
        "Name": project["name"],
        "Version": project["version"],
        "Summary": project["description"],
        "Requires-Python": project["requires-python"],
        "License-Expression": project["license"],
        "Description-Content-Type": "text/markdown",
        **overrides,
    }
    for key, value in fields.items():
        message[key] = value
    for key, value in project["urls"].items():
        message["Project-URL"] = f"{key}, {value}"
    for requirement in project["dependencies"]:
        message["Requires-Dist"] = requirement
    message.set_payload("Synthetic package description\n")
    return message.as_bytes()


def test_coherent_distribution_metadata(source):
    project = check.check_source(source)
    check.check_metadata(metadata_bytes(project), project)


@pytest.mark.parametrize(
    "field,value",
    [
        ("Version", "0.1.1"),
        ("Name", "other-package"),
        ("Requires-Python", ">=3.11"),
        ("License-Expression", "MIT"),
    ],
)
def test_distribution_metadata_drift_is_rejected(source, field, value):
    project = check.check_source(source)
    with pytest.raises(ValueError, match="drift"):
        check.check_metadata(metadata_bytes(project, **{field: value}), project)
