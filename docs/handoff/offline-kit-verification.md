# Offline Kit Verification

This runbook describes an explicitly prepared **unreleased 0.2.0.dev0** kit.
For build and installed-worker proof, see [packaging validation](packaging-validation.md).
The public 0.1.1 artifacts and recorded hashes remain unchanged.

This route is for a researcher with local CPython 3.12 and an immutable,
platform-compatible kit transferred outside this repository. It is not needed
for the source-checkout quick start in the repository README.

The kit must be prepared and verified before transfer and contain exactly:

```text
README.md
KIT-IDENTITY.txt
SHA256SUMS
wheels/
  anim-0.2.0.dev0-py3-none-any.whl
  <all locked CPython 3.12 destination-platform runtime dependency wheels>
```

`wheels/` contains the candidate wheel plus exactly one compatible wheel for
each locked runtime dependency. Each wheel must match CPython 3.12 and the destination platform. The directory contains no
source distribution or build, development, or test dependency.

`KIT-IDENTITY.txt` records these five fields and the exact values used to
prepare the kit:

```text
candidate_commit=<40-hex Git commit>
candidate_tree=<40-hex Git tree>
python=<CPython 3.12 patch version>
platform=<destination platform and wheel tag>
preparation_command=<literal local kit preparation and verification command>
```

Authenticate the transferred kit and its provenance through the approved local
process. `SHA256SUMS` lists `README.md`, `KIT-IDENTITY.txt`, and every wheel under
`wheels/`, with two spaces between digest and relative path. It does not list itself. A checksum verifies integrity and
transfer corruption, not provenance, authenticity, or trust on its own.

Set absolute paths to the read-only transferred kit and a new neutral directory
outside any repository, then verify the kit's exact file set and hashes:

```sh
KIT_ROOT=/absolute/path/to/transferred-kit
PROOF_ROOT=/absolute/path/to/neutral-proof-root
export KIT_ROOT PROOF_ROOT

(
  cd "$KIT_ROOT" || exit 1
  python3.12 -I - <<'PY'
from hashlib import sha256
from pathlib import Path

root = Path(".")
wheels = root / "wheels"
assert {entry.name for entry in root.iterdir()} == {"README.md", "KIT-IDENTITY.txt", "SHA256SUMS", "wheels"}
top_level_files = ("README.md", "KIT-IDENTITY.txt", "SHA256SUMS")
assert all((root / name).is_file() and not (root / name).is_symlink() for name in top_level_files)
assert wheels.is_dir() and not wheels.is_symlink()
wheel_paths = sorted(
    path for path in wheels.iterdir()
    if path.is_file() and not path.is_symlink() and path.suffix == ".whl"
)
assert wheel_paths and set(wheels.iterdir()) == set(wheel_paths)
required = {"README.md", "KIT-IDENTITY.txt", *(path.as_posix() for path in wheel_paths)}
recorded = {}
for line in Path("SHA256SUMS").read_text(encoding="ascii").splitlines():
    digest, separator, relative = line.partition("  ")
    assert separator and len(digest) == 64 and relative not in recorded
    assert all(character in "0123456789abcdef" for character in digest)
    recorded[relative] = digest
assert set(recorded) == required
for relative, expected in recorded.items():
    assert sha256(Path(relative).read_bytes()).hexdigest() == expected
print(f"verified {len(recorded)} kit files")
PY
)
```

From that neutral directory, create a private virtual environment and install
only the transferred binary wheels. No package index, URL, source build, or pip
cache is allowed during installation.

```sh
umask 077
mkdir -p "$PROOF_ROOT"
cd "$PROOF_ROOT" || exit 1
python3.12 -m venv auditor-venv
VENV_ROOT=$PROOF_ROOT/auditor-venv

(
  cd "$KIT_ROOT/wheels" || exit 1
  "$VENV_ROOT/bin/python" -m pip install \
    --disable-pip-version-check \
    --no-index \
    --no-cache-dir \
    --only-binary :all: \
    --find-links . \
    --quiet \
    'anim==0.2.0.dev0'
)
```

Verify the installed distribution version and that its origin is inside the
selected virtual environment without printing either private absolute path:

```sh
"$VENV_ROOT/bin/python" -I - "$VENV_ROOT" <<'PY'
from importlib import metadata
from pathlib import Path
import sys

distribution = metadata.distribution("anim")
environment = Path(sys.argv[1]).resolve()
origin = Path(distribution.locate_file("")).resolve()
assert distribution.version == "0.2.0.dev0"
assert origin.is_relative_to(environment)
print("distribution=anim")
print(f"version={distribution.version}")
print("origin=selected-virtual-environment")
PY

"$VENV_ROOT/bin/ebm-audit" doctor
```

Initialize, but do not execute, a custom worker and verify its exact six-file
scaffold:

```sh
"$VENV_ROOT/bin/ebm-audit" adapter init "$PROOF_ROOT/my-ebm-worker"

"$VENV_ROOT/bin/python" -I - "$PROOF_ROOT/my-ebm-worker" <<'PY'
from pathlib import Path
import sys

expected = [
    "README.md",
    "pyproject.toml",
    "synthetic_example.py",
    "tests/test_worker.py",
    "worker.py",
    "worker.yaml",
]
root = Path(sys.argv[1])
actual = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
assert actual == expected
print("\n".join(actual))
PY
```

This route ends after initialization. It does not execute the worker, run
conformance or a scientific audit, obtain or use participant data, qualify a
named backend, release or publish anything, or establish trust merely from the
bundled SHA files.
