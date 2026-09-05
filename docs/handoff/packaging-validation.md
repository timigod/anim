# Packaging and compatibility validation

The current source is **0.2.0.dev0**, an unpublished development version. The
public **0.1.1** wheel and source archive remain immutable. Their exact identities
are recorded in `release/anim-0.1.1-sha256.txt`; never regenerate that manifest
from changed source. Development builds produce their own versioned filenames
and validation output. None of the commands below publishes a release.

## Supported surfaces

| Surface | Contract and verification |
| --- | --- |
| CPython 3.12, macOS | Fresh wheel install; installed CLI, scaffold, full and partial synthetic worker demos with native worker Seatbelt denial and a CLI Python socket guard. |
| CPython 3.12, Linux | Fresh wheel install and the same demos with working `/usr/bin/bwrap` and OS namespace support. CI uses Ubuntu 22.04. |
| Linux without `/usr/bin/bwrap` | Installed `doctor` and scaffold work; worker execution exits 14 with `PRIVACY.CONTAINMENT_UNAVAILABLE` and produces no scientific report. CI exercises this separately. |
| Linux with unusable namespaces | Worker execution is unsupported on that host until containment is operational. An installed executable alone does not establish containment support; failures must remain visible. |
| Windows; Python 3.11 or 3.13+ | Execution is unsupported. Package metadata retains `>=3.12,<3.13`; no widening has been established. |

The CI matrix is automated evidence when it runs, not a claim of a locally
verified Linux installation. `doctor` alone does not exercise worker containment.
These synthetic checks establish software integration behavior, not backend
acceptance, scientific validity, or a recoverable disease-order signal.

## Build and check identities

Use CPython 3.12 and the pinned uv 0.9.15. Run from the checkout. In a shared
checkout use a dedicated environment, and build only after source writers have
finished. Use a fresh output directory so old artifacts cannot be mistaken for
the new build.

```sh
export UV_PROJECT_ENVIRONMENT=tmp/packaging-tools
uv sync --locked --group build --no-install-project --python 3.12
"$UV_PROJECT_ENVIRONMENT/bin/python" scripts/packaging/check_release.py
"$UV_PROJECT_ENVIRONMENT/bin/python" -m pytest tests/packaging -q
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
uv build --no-build-isolation --out-dir tmp/packaging-dist
"$UV_PROJECT_ENVIRONMENT/bin/python" scripts/packaging/check_release.py --dist tmp/packaging-dist
```

The checker verifies package/import/lock/README/changelog versions, Python
constraints, metadata and source links, immutable public hashes, distribution
filenames, runtime requirements, console entry points, packaged source/resource
bytes, wheel RECORD integrity, safe archive paths and the existing public
inventory exclusions. It prints new artifact SHA-256 values without changing
release manifests. The sdist includes the packaging harness and the maintained public regression
tests referenced by the runbooks.
No historical private tests or evaluator inputs are used.

Python widening requires successful installed-wheel and containment evidence on
the proposed Python/OS combinations, compatible locked dependency wheels, and
a deliberate update of the supported range and checker. Merely removing the
upper bound is not compatibility evidence.

## Prepare runtime wheels, then disconnect

This step may use a public package index to obtain **software only**. No dataset
is downloaded. It exports exact locked requirements with hashes, and accepts
only destination-compatible binary wheels. Keep this step separate from the
offline installation/runtime proof.

```sh
python3.12 -m venv tmp/packaging-download
uv export --locked --no-dev --no-emit-project --format requirements-txt \
  --output-file tmp/runtime-requirements.txt
tmp/packaging-download/bin/python -m pip download \
  --only-binary=:all: --require-hashes --dest tmp/runtime-wheels \
  -r tmp/runtime-requirements.txt
```

On macOS:

```sh
python3.12 -I scripts/packaging/installed_smoke.py \
  --wheel tmp/packaging-dist/anim-0.2.0.dev0-py3-none-any.whl \
  --wheelhouse tmp/runtime-wheels --proof-root tmp/installed-proof-macos \
  --version 0.2.0.dev0 --containment available
```

The proof root must not exist. The harness creates a fresh virtual environment,
installs with `--no-index --no-cache-dir --only-binary=:all:`, runs `pip check`,
checks the installed package origin and version, exercises `summary` for each
synthetic report and `diff` for identical/changed-capability reports, and invokes the installed
console entry point with isolated Python. The source tree is not on its import
path. On macOS, pip installation uses a Seatbelt profile denying network access.
The CLI parent runs with an audit hook denying and recording Python socket
operations; native workers keep their own Seatbelt boundary. Nested Seatbelt
launchers fail with `sandbox_apply: Operation not permitted`, so the harness
does not wrap the CLI parent in a second OS sandbox or weaken worker containment.
The parent guard is a Python socket boundary, not a claim to sandbox arbitrary
native networking in the parent. Any CLI socket attempt fails the smoke even
if application code catches the denial. IPv4/IPv6 denial probes must receive
a permission or no-route error, not a timeout. The resulting `smoke-receipt.json` binds the wheel hash, Python, OS,
architecture, containment case, and observed synthetic result states. Logs and
reports remain beside it for local inspection. An existing proof is never
reused or overwritten.

On Linux, create a network namespace, then drop privilege back to the current
ordinary user before invoking the same harness:

```sh
sudo unshare --net -- setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups -- \
  "$(command -v python3.12)" -I scripts/packaging/installed_smoke.py \
  --wheel tmp/packaging-dist/anim-0.2.0.dev0-py3-none-any.whl \
  --wheelhouse tmp/runtime-wheels --proof-root tmp/installed-proof-linux \
  --version 0.2.0.dev0 --containment available
```

Linux checks require an isolated route table and kernel network-denial probes;
the harness refuses a normal network-enabled session. The supported worker case
requires working Bubblewrap. Use `--containment unavailable` only in a separate
disposable host without `/usr/bin/bwrap`; it must return the exact typed error.
The CI workflow installs/removes Bubblewrap only on its disposable runners.
Neither case relaxes the product's containment boundary.

`.github/workflows/checks.yml` runs these checks on pushes and pull requests.
Its separate macOS/Linux CPython 3.12 regression job runs only the maintained
public `tests/packaging`, `tests/runner`, `tests/replay`, `tests/reporting`, and
`tests/adapters` directories, with Linux Bubblewrap enabled. Optional real-upstream
source tests explicitly skip unless the exact public files and optional software
dependencies were provisioned and `ANIM_PYSAEBM_SOURCE_DIR` is set; the default CI
job does not fetch those sources or any dataset. See the adapter runbook for
explicit software-only provisioning and opt-in tests.
It has read-only repository permissions and retains distributions and synthetic
receipts as CI artifacts. The historical release workflow only matches
`v0.1.1`; it is not a development publication path. Any later publication needs
its own explicitly authorized, reviewed release procedure and artifact hashes.

## Optional local Linux-container proof

A Docker proof is additional Linux evidence, not native-host verification or a
claim that GitHub Actions ran. Resolve `python:3.12-slim-bookworm` to its immutable
repository digest and record that digest, Docker server version, Python version,
architecture, and required container permissions in the proof receipt. Use the
digest for subsequent runs. Use an empty task-local Docker client config with
the existing Docker endpoint; never mount host authentication state.

Prepare Linux runtime wheels inside that Python image using the same exported
hash-locked requirements. Provision Bubblewrap from the image's operating-system
repository in a separate task image if testing the supported case. These are
software preparation steps with network access; do not acquire datasets.

Run the installed smoke in a fresh container with `--network none`. Mount only
the development wheel, Linux runtime wheelhouse, smoke harness, and a fresh
output directory. The base Python image without `/usr/bin/bwrap` must pass
`--containment unavailable`. Test `--containment available` in the Bubblewrap
image only if its namespace setup works. If additional capabilities or security
options are necessary, apply the minimum to that disposable task container,
record them, and retain any initial failure. Do not use `--privileged`, change
host-global security configuration, or interpret a container limitation as
successful containment. An available-case proof that needed container root or
additional capabilities does not establish unprivileged native Linux support.
