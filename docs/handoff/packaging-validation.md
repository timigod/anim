# Build and check an Anim package

Use this guide to build a wheel (an installable Python package) and source
archive, then check a fresh installation on macOS or Linux. The current stable
release, **0.2.0**, is already published. Local build and check commands do not
publish anything; the release procedure below is for a new, unpublished version.

Published files must never be replaced. This also applies to the public
**0.1.1** wheel, source archive and hashes in `release/anim-0.1.1-sha256.txt`.
Never regenerate that manifest from changed source. A local rebuild of a
changed checkout is for validation, even if its filename has the same version
as a published file.

## Build and check the distributions

Use CPython 3.12 and the pinned uv 0.9.15. Run from the checkout. In a shared
checkout, use a dedicated environment and wait until source writers have
finished before building. Use a fresh output directory so old files cannot be
mistaken for the new build.

```sh
export UV_PROJECT_ENVIRONMENT=tmp/packaging-tools
uv sync --locked --group build --no-install-project --python 3.12
"$UV_PROJECT_ENVIRONMENT/bin/python" scripts/packaging/check_release.py
"$UV_PROJECT_ENVIRONMENT/bin/python" -m pytest tests/packaging -q
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
uv build --python "$UV_PROJECT_ENVIRONMENT/bin/python" --no-build-isolation --out-dir tmp/packaging-dist
"$UV_PROJECT_ENVIRONMENT/bin/python" scripts/packaging/check_release.py --dist tmp/packaging-dist
```

The checker verifies versions, package contents, hashes and metadata; see the
reference section below for the full list. It prints SHA-256 hashes of new
artifacts without changing release manifests. These checks use no historical
private tests or evaluator inputs.

## Prepare dependency wheels, then disconnect

This preparation step may use a public package index to obtain **software
only**. It does not download a dataset. It exports the exact locked requirements
with hashes and accepts only binary wheels compatible with the destination
platform. Keep this online preparation separate from the offline installation
and runtime checks.

```sh
python3.12 -m venv tmp/packaging-download
uv export --locked --no-dev --no-emit-project --format requirements-txt \
  --output-file tmp/runtime-requirements.txt
tmp/packaging-download/bin/python -m pip download \
  --only-binary=:all: --require-hashes --dest tmp/runtime-wheels \
  -r tmp/runtime-requirements.txt
```

## Check a fresh macOS installation

```sh
python3.12 -I scripts/packaging/installed_smoke.py \
  --wheel tmp/packaging-dist/anim-0.2.0-py3-none-any.whl \
  --wheelhouse tmp/runtime-wheels --proof-root tmp/installed-proof-macos \
  --version 0.2.0 --containment available
```

The proof root (the directory holding test results) must not exist. The harness
creates a fresh virtual environment, installs with
`--no-index --no-cache-dir --only-binary=:all:`, runs `pip check`, and checks the
installed package origin and version. It invokes the installed command with
isolated Python, so the source tree is not on its import path. It exercises
`summary` for each synthetic report and `diff` for reports with identical or
changed capabilities.

On macOS, pip installation uses Seatbelt, the macOS sandbox, to deny network
access. The CLI process has a Python audit hook that denies and records socket
operations; native workers run inside their own Seatbelt sandbox. Any CLI
socket attempt fails the smoke test (the installation and basic execution
check), even if application code catches the denial. IPv4/IPv6 denial probes
must receive a permission or no-route error, not a timeout. See the reference
section for the limit of the CLI's Python socket guard.

The resulting `smoke-receipt.json` records the wheel hash, Python, OS,
architecture, containment case (whether the host can isolate worker processes)
and observed synthetic result states. Logs and reports remain beside it for
local inspection. Never reuse or overwrite an existing proof directory.

## Check a fresh Linux installation

Create a network namespace, which gives the process an isolated network
configuration. Then return to the current ordinary user's privileges before
invoking the same harness:

```sh
sudo unshare --net -- setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups -- \
  "$(command -v python3.12)" -I scripts/packaging/installed_smoke.py \
  --wheel tmp/packaging-dist/anim-0.2.0-py3-none-any.whl \
  --wheelhouse tmp/runtime-wheels --proof-root tmp/installed-proof-linux \
  --version 0.2.0 --containment available
```

Linux checks require an isolated route table and kernel network-denial probes.
The harness refuses a normal network-enabled session. Worker execution requires
working Bubblewrap at `/usr/bin/bwrap`, with usable operating-system namespaces.
Use `--containment unavailable` only on a separate disposable host without
`/usr/bin/bwrap`. That case must return `PRIVACY.CONTAINMENT_UNAVAILABLE`
(exit 14) and produce no scientific report. Neither case relaxes worker
isolation requirements.

## Publish a new release

For the next release, update the package, import, lock, README, changelog and
versioned examples together. Use a dated changelog entry and a stable version,
run the checks above, and land the release preparation on `main`. Before
creating the public tag, confirm that the intended version is absent from PyPI
and GitHub and the exact commit has passed CI (the automated repository
checks). Existing versions and artifact hashes must never be replaced.

After release authorization, create and push the matching annotated tag.
The published 0.2.0 release uses `v0.2.0`; retain that tag and use a new tag for
a new version. `.github/workflows/release.yml` rejects mismatched tags and
development versions, requires the tagged commit to be on `main`, then calls
the complete validation workflow.

Only successful validation permits the `pypi` environment job to publish the
exact validated distributions through GitHub OIDC, the workflow's trusted
identity mechanism. No API token is needed locally. A following job creates
the matching GitHub Release with those same files, SHA-256 checksums and the
version's changelog entry.

Wait for the workflow to finish. Verify the public PyPI version and both file
hashes against the validated distributions, and check the GitHub tag, notes and
assets. Record publication separately from a successful source push. If PyPI
publishes but GitHub Release creation fails, retain the published files and
retry only the failed job; never alter or republish the version's artifacts.

## Optional: check installation in a local Linux container

A Docker test supplies additional Linux evidence. It does not verify a native
Linux host or show that GitHub Actions ran. Resolve `python:3.12-slim-bookworm`
to its immutable repository digest (the hash identifying the exact image).
Record that digest, Docker server version, Python version, architecture and
required container permissions in the test record. Use the digest for subsequent
runs. Use an empty task-local Docker client configuration with the existing
Docker endpoint; never mount host authentication state.

Prepare Linux runtime wheels inside that Python image using the same exported
hash-locked requirements. To test the supported case, install Bubblewrap from
the image's operating-system repository in a separate task image. These are
software preparation steps with network access; do not acquire datasets.

Run the installed smoke test in a fresh container with `--network none`. Mount
only the wheel under test, Linux runtime wheel directory, smoke-test harness
and a fresh output directory. The base Python image without `/usr/bin/bwrap`
must pass `--containment unavailable`. Test `--containment available` in the
Bubblewrap image only if its namespace setup works.

If additional capabilities or security options are necessary, apply the minimum
to that disposable task container, record them and retain any initial failure.
Do not use `--privileged`, change host-global security configuration or interpret
a container limitation as successful containment. A successful available-case
test that needed container root or additional capabilities does not establish
unprivileged native Linux support.

## Reference: supported platforms and limits

| Platform | Required behavior and verification |
| --- | --- |
| CPython 3.12, macOS | Fresh wheel install; installed CLI, scaffold, full and partial synthetic worker demos with native worker Seatbelt network denial and a CLI Python socket guard. |
| CPython 3.12, Linux | Fresh wheel install and the same demos with working `/usr/bin/bwrap` and operating-system namespace support. CI uses Ubuntu 22.04. |
| Linux without `/usr/bin/bwrap` | Installed `doctor` and scaffold work; worker execution exits 14 with `PRIVACY.CONTAINMENT_UNAVAILABLE` and produces no scientific report. CI exercises this separately. |
| Linux with unusable namespaces | Worker execution is unsupported until containment works. An installed executable alone does not establish support; failures must remain visible. |
| Windows; Python 3.11 or 3.13+ | Execution is unsupported. Package metadata retains `>=3.12,<3.13`; support for other versions has not been established. |

The CI matrix supplies automated evidence when it runs. It does not establish
that a Linux installation was checked locally. `doctor` alone does not test
worker containment. Synthetic checks establish software integration behavior,
not backend acceptance, scientific validity or recovery of a true disease order.

To support more Python versions, first obtain successful installed-wheel and
containment results on the proposed Python/OS combinations and compatible
locked dependency wheels. Then deliberately update the supported range and
checker. Removing the upper bound alone is not compatibility evidence.

On macOS, nested Seatbelt launchers fail with
`sandbox_apply: Operation not permitted`. The harness therefore does not wrap
the CLI process in a second OS sandbox or weaken worker containment. The
parent's guard covers Python socket operations; it does not sandbox arbitrary
native networking in that parent process.

## Reference: package checks and CI

The release checker verifies:

- Package/import/lock/README/changelog versions and Python constraints.
- Metadata, source links, immutable public hashes and distribution filenames.
- Runtime requirements, console entry points and packaged source/resource bytes.
- Wheel `RECORD` integrity, safe archive paths and the existing public file
  exclusions.

The source distribution (sdist) includes the packaging harness and maintained
public regression tests referenced by the runbooks.

`.github/workflows/checks.yml` runs the checks on pushes and pull requests. Its
separate macOS/Linux CPython 3.12 regression job runs only the maintained public
`tests/packaging`, `tests/runner`, `tests/replay`, `tests/reporting` and
`tests/adapters` directories, with Linux Bubblewrap enabled. The workflow
installs or removes Bubblewrap only on its disposable runners.

Optional tests using real upstream source skip unless the exact public files
and optional software dependencies have been installed and
`ANIM_PYSAEBM_SOURCE_DIR` is set. Default CI does not fetch those sources or any
dataset. See the [adapter runbook](adapter-runbook.md) for software-only setup
and opt-in tests.

The checks workflow has read-only repository permissions and retains
distributions and synthetic test records as CI artifacts. The release workflow
calls this same workflow, so publication requires the same build, public
regression and installed-wheel checks.
