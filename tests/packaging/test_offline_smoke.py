"""The smoke's Python parent guard fails closed even if a denial is caught."""

from __future__ import annotations

import errno
import importlib.util
import json
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/packaging/installed_smoke.py"


def test_socket_attempt_is_denied_and_recorded_without_endpoint(tmp_path):
    marker = tmp_path / "attempt.txt"
    code = """
import errno, importlib.util, json, socket, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("smoke", sys.argv[1])
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
smoke.install_socket_guard(Path(sys.argv[2]))
try:
    socket.create_connection(("192.0.2.1", 9), timeout=1)
except OSError as error:
    print(json.dumps({"denied": error.errno == errno.EPERM}))
else:
    raise RuntimeError("guard allowed a connection")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(SCRIPT), str(marker)],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert json.loads(result.stdout) == {"denied": True}
    assert marker.read_text() == "network-attempt-denied\n"
    assert "192.0.2.1" not in marker.read_text()


def test_existing_proof_is_not_overwritten(tmp_path):
    sentinel = tmp_path / "evidence.txt"
    sentinel.write_text("keep this evidence")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            "--wheel",
            "anim-0.2.0.dev0-py3-none-any.whl",
            "--wheelhouse",
            str(tmp_path),
            "--proof-root",
            str(tmp_path),
            "--version",
            "0.2.0.dev0",
            "--containment",
            "available",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "proof root must be fresh" in result.stderr
    assert sentinel.read_text() == "keep this evidence"
    assert list(tmp_path.iterdir()) == [sentinel]


@pytest.fixture
def denial_probe(monkeypatch):
    """Drive actual probe branching with synthetic kernel outcomes; no socket is opened."""
    spec = importlib.util.spec_from_file_location("probe_smoke", SCRIPT)
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)

    def configure(*, system="Linux", routes="Iface\tDestination\n", failure=errno.EADDRNOTAVAIL):
        route_reads = []
        attempts = []

        class RouteFile:
            def read_text(self):
                route_reads.append(True)
                if routes is None:
                    raise FileNotFoundError("synthetic unavailable route table")
                return routes

        def route_path(name):
            assert name == "/proc/net/route"
            return RouteFile()

        class SocketProbe:
            def __init__(self, family, kind):
                self.family = family
                assert kind == socket.SOCK_STREAM

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, timeout):
                assert timeout == 1

            def connect(self, _endpoint):
                attempts.append(self.family)
                if self.family == socket.AF_INET:
                    raise OSError(errno.ENETUNREACH, "synthetic no route")
                if failure is None:
                    raise TimeoutError("synthetic timeout")
                raise OSError(failure, "synthetic kernel outcome")

        monkeypatch.setattr(smoke, "platform", SimpleNamespace(system=lambda: system))
        monkeypatch.setattr(smoke, "Path", route_path)
        monkeypatch.setattr(
            smoke,
            "socket",
            SimpleNamespace(
                AF_INET=socket.AF_INET,
                AF_INET6=socket.AF_INET6,
                SOCK_STREAM=socket.SOCK_STREAM,
                socket=SocketProbe,
            ),
        )
        return smoke, route_reads, attempts

    return configure


def test_linux_ipv6_without_source_address_requires_rechecked_isolated_routes(denial_probe):
    smoke, reads, attempts = denial_probe()
    assert smoke.network_wrapper() == []
    smoke.prove_network_denied()
    assert len(reads) == 2  # Check again at the error, not only before creating the venv.
    assert attempts == [socket.AF_INET, socket.AF_INET6]


@pytest.mark.parametrize(
    "system,routes",
    [
        ("Darwin", "Iface\tDestination\n"),
        ("Linux", "Iface\tDestination\neth0\t00000000\n"),
        ("Linux", None),
    ],
)
def test_address_unavailable_is_inconclusive_without_linux_isolation(denial_probe, system, routes):
    smoke, _reads, _attempts = denial_probe(system=system, routes=routes)
    with pytest.raises(RuntimeError, match="inconclusive"):
        smoke.prove_network_denied()


@pytest.mark.parametrize("failure", [None, errno.ETIMEDOUT, errno.ECONNREFUSED])
def test_timeout_and_connection_refused_stay_inconclusive_even_when_isolated(denial_probe, failure):
    smoke, _reads, _attempts = denial_probe(failure=failure)
    assert smoke.network_wrapper() == []
    with pytest.raises(RuntimeError, match="inconclusive"):
        smoke.prove_network_denied()
