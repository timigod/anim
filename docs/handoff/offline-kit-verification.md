# Verify and install an offline kit

Use this guide to install **Anim 0.2.0** from a prepared kit on a computer with
no package-index access. It verifies the transferred files, installs Anim,
checks the installation and creates a custom-worker starter directory. It stops
before worker execution.

You need local CPython 3.12 and an unchanged kit prepared for the destination
platform and transferred outside this repository. The source-checkout quick
start in the repository README does not need a kit. For build and installed
worker checks, see [packaging validation](packaging-validation.md). The public
0.1.1 artifacts and recorded hashes remain unchanged.

## Check the kit before installation

The kit must be prepared and verified before transfer. It must contain exactly:

```text
README.md
KIT-IDENTITY.txt
SHA256SUMS
wheels/
  anim-0.2.0-py3-none-any.whl
  <all locked CPython 3.12 destination-platform runtime dependency wheels>
```

A wheel is a prebuilt Python package file. `wheels/` must contain the Anim wheel
and exactly one compatible wheel for each locked runtime dependency. Every
wheel must match CPython 3.12 and the destination platform. Do not include source
archives or build, development or test dependencies.

`KIT-IDENTITY.txt` records these five fields with the exact values used to
prepare the kit:

```text
candidate_commit=<40-hex Git commit>
candidate_tree=<40-hex Git tree>
python=<CPython 3.12 patch version>
platform=<destination platform and wheel tag>
preparation_command=<literal local kit preparation and verification command>
```

Use the approved local process to authenticate who prepared the transferred kit
and which source it came from. `SHA256SUMS` lists `README.md`, `KIT-IDENTITY.txt`
and every wheel under `wheels/`, with two spaces between digest and relative
path. It does not list itself. Checksums can detect changed files or transfer
corruption; by themselves, they do not establish origin, authenticity or trust.

Set absolute paths to the read-only transferred kit and a new directory outside
any repository. The following command checks the kit's exact file set and hashes:

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

## Install from the transferred wheels

In the new directory, create a private virtual environment and install only the
transferred binary wheels. Do not use a package index, URL, source build or pip
cache during installation.

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
    'anim==0.2.0'
)
```

## Check the installed version and package location

Verify that the installed version is 0.2.0 and the package is inside the selected
virtual environment. The check avoids printing private absolute paths. Then
run `doctor`:

```sh
"$VENV_ROOT/bin/python" -I - "$VENV_ROOT" <<'PY'
from importlib import metadata
from pathlib import Path
import sys

distribution = metadata.distribution("anim")
environment = Path(sys.argv[1]).resolve()
origin = Path(distribution.locate_file("")).resolve()
assert distribution.version == "0.2.0"
assert origin.is_relative_to(environment)
print("distribution=anim")
print(f"version={distribution.version}")
print("origin=selected-virtual-environment")
PY

"$VENV_ROOT/bin/ebm-audit" doctor
```

## Create the custom-worker starter files

Initialize, but do not execute, a custom worker. Verify the exact six-file
scaffold (the generated starter directory):

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

## What this procedure verifies

This procedure verifies the transferred file checksums, local installation and
starter files. It does not execute a worker, run conformance checks or a
scientific audit, obtain or use participant data, qualify a named backend, or
release or publish anything. Bundled checksum files alone do not establish
trust in the kit.
