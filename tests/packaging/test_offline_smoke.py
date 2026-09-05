"""The smoke's Python parent guard fails closed even if a denial is caught."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

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
