"""Install a fresh wheel without an index and run only synthetic CLI examples.

On Linux invoke this inside a fresh network namespace as an ordinary user (see
packaging-validation.md). On macOS installation uses OS network denial; CLI
Python sockets are denied and recorded while workers retain native Seatbelt.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import runpy
import socket
import subprocess
import sys
import venv
from importlib import metadata
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def environment() -> dict[str, str]:
    # Do not inherit package overrides, user configuration, or application credentials.
    values = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")
        if key in os.environ
    }
    values.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "UV_OFFLINE": "1",
        }
    )
    return values


def isolated_linux_routes() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return False
    return not any(row.split()[0] != "lo" for row in routes if row.strip())


def network_wrapper() -> list[str]:
    if platform.system() == "Darwin":
        return ["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)"]
    require(platform.system() == "Linux", "unsupported OS: smoke supports macOS and Linux")
    # Requiring an empty non-loopback route table makes isolation an explicit precondition.
    require(
        isolated_linux_routes(),
        "Linux smoke requires a fresh network namespace; see the packaging runbook",
    )
    return []


def install_socket_guard(marker: Path | None = None) -> None:
    def audit(event: str, _args: tuple) -> None:
        if event.startswith("socket."):
            if marker is not None:
                marker.write_text("network-attempt-denied\n")
            raise PermissionError(errno.EPERM, "Offline smoke denies Python socket operations")

    sys.addaudithook(audit)


def prove_network_denied() -> None:
    # Documentation-only addresses: no DNS, external account, service, or participant input.
    for family, endpoint in (
        (socket.AF_INET, ("192.0.2.1", 9)),
        (socket.AF_INET6, ("2001:db8::1", 9)),
    ):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as stream:
                stream.settimeout(1)
                stream.connect(endpoint)
        except OSError as error:
            # Linux IPv6 may have no source address in a fresh network namespace.
            # Recheck the same route precondition; errno alone cannot prove isolation.
            isolated_missing_source = (
                error.errno == errno.EADDRNOTAVAIL
                and family == socket.AF_INET6
                and isolated_linux_routes()
            )
            require(
                error.errno
                in {
                    errno.EPERM,
                    errno.EACCES,
                    errno.ENETUNREACH,
                    errno.EAFNOSUPPORT,
                    errno.EPROTONOSUPPORT,
                }
                or isolated_missing_source,
                "network denial probe was inconclusive",
            )
        else:
            raise RuntimeError("network-denial probe unexpectedly connected")


def command(args: list[str], cwd: Path, log: str, expected: int) -> dict:
    result = subprocess.run(
        args, cwd=cwd, env=environment(), capture_output=True, text=True, timeout=180, check=False
    )
    (cwd / f"{log}.stdout").write_text(result.stdout)
    (cwd / f"{log}.stderr").write_text(result.stderr)
    require(
        result.returncode == expected,
        f"{log}: expected exit {expected}, received {result.returncode}; inspect local logs",
    )
    return json.loads(result.stdout or "{}") if expected != 14 else json.loads(result.stderr)


def installed_runtime(root: Path, version: str, containment: str) -> None:
    if platform.system() == "Darwin":
        install_socket_guard()
    import ebm_audit

    require(sys.version_info[:2] == (3, 12), "unsupported Python minor")
    origin = Path(ebm_audit.__file__).resolve()
    require(
        origin.is_relative_to(Path(sys.prefix).resolve()), "package imported outside fresh venv"
    )
    require(
        metadata.version("anim") == ebm_audit.__version__ == version,
        "installed metadata/import version mismatch",
    )
    require(not any(Path(p).name == "src" for p in sys.path), "checkout source leaked into imports")
    prove_network_denied()
    cli = [sys.executable, "-I", str(Path(sys.executable).parent / "ebm-audit")]
    network_marker = root / "network-attempt.txt"
    if platform.system() == "Darwin":
        cli = [
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--guarded-cli",
            str(network_marker),
            str(Path(sys.executable).parent / "ebm-audit"),
        ]
    doctor = command([*cli, "doctor"], root, "doctor", 0)
    require(
        doctor["status"] == "READY" and doctor["offline"] is True and doctor["network_calls"] == 0,
        "doctor not ready/offline",
    )
    command([*cli, "adapter", "init", str(root / "starter")], root, "adapter-init", 0)
    require(
        (root / "starter/worker.py").is_file()
        and (root / "starter/tests/test_worker.py").is_file(),
        "starter resources missing",
    )
    profiles = ("full", "partial") if containment == "available" else ("full",)
    reports = {}
    for profile in profiles:
        work = root / profile
        work.mkdir(mode=0o700)
        args = [*cli, "demo", "--conformance-ebm", "--capability-profile", profile]
        if containment == "unavailable":
            require(
                platform.system() == "Linux" and not Path("/usr/bin/bwrap").exists(),
                "unavailable case requires Linux without the configured Bubblewrap launcher",
            )
            status = command(args, work, "demo", 14)
            require(
                status["error"]["code"] == "PRIVACY.CONTAINMENT_UNAVAILABLE",
                "missing containment did not fail closed with its typed error",
            )
            require(
                not (work / "ebm-audit-demo/report/report.json").exists(),
                "containment failure unexpectedly emitted a scientific report",
            )
            reports[profile] = {"error": status["error"]["code"], "exit": 14}
            continue
        status = command(args, work, "demo", 12)
        report_dir = work / "ebm-audit-demo/report"
        report = json.loads((report_dir / "report.json").read_bytes())
        require(
            status["run_completion_status"] == "PARTIAL"
            and status["candidate_execution_status"] == "COMPLETE"
            and status["success_count"] == status["requested_candidate_count"] == 1,
            "unexpected synthetic candidate/completion state",
        )
        require(
            report["report_status"] == "INCOMPLETE"
            and report["input_declaration"] == "DECLARED_SYNTHETIC",
            "synthetic report lost its incomplete/synthetic declaration",
        )
        for name in ("report.html", "universes.csv"):
            require((report_dir / name).stat().st_size > 0, f"missing or empty {name}")
        require((report_dir.parent / "warnings.jsonl").is_file(), "warning stream missing")
        require(len(report["candidate_records"]) == 1, "candidate disappeared from report")
        summary = command(
            [*cli, "summary", "--run-dir", str(report_dir.parent)], work, "summary", 0
        )
        require(
            summary["schema_version"] == "anim-report-inspection/1"
            and summary["scientific_rehydration"] is False
            and summary["report_status"] == "INCOMPLETE",
            "installed summary lost report identity or scientific limits",
        )
        # Preserve typed absence; the partial worker must not become full scientific evidence.
        stage = report["capability_evidence"]["training_stage"]
        states = {key: value["status"] for key, value in stage.items()}
        if profile == "partial":
            require(
                "UNAVAILABLE" in states.values() or "NOT_APPLICABLE" in states.values(),
                "partial worker did not retain typed absence",
            )
        reports[profile] = {
            "run": "PARTIAL",
            "report": "INCOMPLETE",
            "stage": states,
            "candidate_status": report["candidate_records"][0]["final_status"],
        }
    report_commands = {"summary": "NOT_RUN", "diff": "NOT_RUN"}
    if containment == "available":
        full_run = root / "full/ebm-audit-demo"
        partial_run = root / "partial/ebm-audit-demo"
        same = command(
            [*cli, "diff", "--left", str(full_run), "--right", str(full_run)], root, "diff-same", 0
        )
        require(
            same["schema_version"] == "anim-report-comparison/1"
            and same["state"] == "UNCHANGED"
            and same["scientific_rehydration"] is False
            and same["replay_comparability"] == "MISSING_REPLAY_BINDINGS",
            "installed diff confused unchanged evidence and missing replay bindings",
        )
        changed = command(
            [*cli, "diff", "--left", str(full_run), "--right", str(partial_run)],
            root,
            "diff-capability",
            0,
        )
        require(
            changed["state"] == "CHANGED"
            and changed["sections"]["capability_evidence"]["state"] == "CHANGED",
            "installed diff lost changed worker capability",
        )
        report_commands = {
            "summary": "PASS_BOTH_PROFILES",
            "diff": "PASS_SAME_AND_CAPABILITY_CHANGE",
        }
    require(not network_marker.exists(), "CLI attempted a Python network operation")
    receipt = {
        "status": "PASS",
        "version": version,
        "python": platform.python_version(),
        "os": platform.system(),
        "machine": platform.machine(),
        "installed_origin": "fresh-venv",
        "network_denial_probe": "PASS",
        "runtime_network_boundary": (
            "CLI Python socket audit hook; workers native Seatbelt"
            if platform.system() == "Darwin"
            else "isolated Linux network namespace; workers Bubblewrap when available"
        ),
        "containment_case": containment,
        "synthetic_reports": reports,
        "installed_report_commands": report_commands,
    }
    (root / "runtime-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


def main() -> None:
    if sys.argv[1:2] == ["--guarded-cli"]:
        install_socket_guard(Path(sys.argv[2]))
        sys.argv = sys.argv[3:]
        runpy.run_path(sys.argv[0], run_name="__main__")
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--proof-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--containment", choices=("available", "unavailable"), required=True)
    parser.add_argument("--installed-runtime", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.proof_root.resolve()
    require(sys.version_info[:2] == (3, 12), "smoke requires CPython 3.12")
    if args.installed_runtime:
        installed_runtime(root, args.version, args.containment)
        return
    require(args.wheel is not None and args.wheelhouse is not None, "wheel and wheelhouse required")
    wheel = args.wheel.resolve()
    wheelhouse = args.wheelhouse.resolve()
    require(wheel.name == f"anim-{args.version}-py3-none-any.whl", "wheel/version mismatch")
    require(not root.exists(), "proof root must be fresh; existing evidence is never overwritten")
    wrapper = network_wrapper()
    root.mkdir(mode=0o700, parents=True)
    venv.EnvBuilder(with_pip=True).create(root / "venv")
    python = root / "venv/bin/python"
    install = subprocess.run(
        [
            *wrapper,
            str(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--find-links",
            str(wheelhouse),
            str(wheel),
        ],
        env=environment(),
        cwd=root,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    (root / "install.stdout").write_text(install.stdout)
    (root / "install.stderr").write_text(install.stderr)
    require(
        install.returncode == 0, "offline fresh wheel installation failed; inspect install logs"
    )
    subprocess.run(
        [*wrapper, str(python), "-I", "-m", "pip", "check"],
        env=environment(),
        cwd=root,
        check=True,
        timeout=30,
        capture_output=True,
    )
    # Copy the harness only; no product source or local test suite enters this directory.
    harness = root / "installed_smoke.py"
    harness.write_bytes(Path(__file__).read_bytes())
    result = command(
        [
            str(python),
            "-I",
            str(harness),
            "--installed-runtime",
            "--proof-root",
            str(root),
            "--version",
            args.version,
            "--containment",
            args.containment,
        ],
        root,
        "runtime",
        0,
    )
    result["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
    result["offline_install"] = "PASS"
    (root / "smoke-receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
