"""Explicit setup-time fetch of four exact public files; never used by the worker.

No upstream package archive or dataset is fetched. Pass --verify to check an
existing source directory entirely offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.request import urlopen

MANIFEST_PATH = Path(__file__).with_name("source-manifest.json")


def verify_source(root: Path) -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text())
    if root.is_symlink() or not root.is_dir():
        raise ValueError("EXAMPLE.SOURCE_MISSING: provision the exact source directory first.")
    expected = {row["path"] for row in manifest["files"]}
    observed = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("EXAMPLE.SOURCE_SYMLINK: use regular local source files.")
        if path.is_file():
            observed.add(path.relative_to(root).as_posix())
    if observed != expected:
        raise ValueError("EXAMPLE.SOURCE_INVENTORY: use only the four allowlisted source files.")
    for row in manifest["files"]:
        content = (root / row["path"]).read_bytes()
        if (
            len(content) != row["byte_length"]
            or hashlib.sha256(content).hexdigest() != row["sha256"]
        ):
            raise ValueError("EXAMPLE.SOURCE_DRIFT: restore exact pinned source files.")
    return manifest


def provision(root: Path) -> dict:
    if root.exists() or root.is_symlink():
        return verify_source(root)
    manifest = json.loads(MANIFEST_PATH.read_text())
    # Fetch and authenticate everything before creating an output directory.
    payloads = {}
    base = "https://raw.githubusercontent.com/jpcca/pysaebm/" + manifest["commit"] + "/"
    for row in manifest["files"]:
        with urlopen(base + row["path"], timeout=30) as response:
            content = response.read(row["byte_length"] + 1)
        if (
            len(content) != row["byte_length"]
            or hashlib.sha256(content).hexdigest() != row["sha256"]
        ):
            raise ValueError("EXAMPLE.SOURCE_DOWNLOAD_MISMATCH: no source was installed.")
        payloads[row["path"]] = content
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for relative, content in payloads.items():
        path = root / relative
        path.parent.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
    return verify_source(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("--verify", action="store_true", help="Offline verification only.")
    arguments = parser.parse_args()
    try:
        manifest = (verify_source if arguments.verify else provision)(arguments.source_dir)
    except Exception:
        print(
            "EXAMPLE.SOURCE_UNAVAILABLE: source verification failed; use a fresh empty destination."
        )
        return 1
    print(
        json.dumps(
            {
                "status": "PASS",
                "commit": manifest["commit"],
                "version": manifest["version"],
                "license": manifest["license"],
                "source_file_count": len(manifest["files"]),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
