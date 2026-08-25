"""Project-owned synthetic adversary used only by the public core contract suite.

These modes exercise the auditor's rejection boundary. They never represent
behavior observed from the configured external worker.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from pathlib import Path

from ebm_audit.protocol import canonical_json_bytes, strict_json_loads
from ebm_audit.workers import WorkerApplication
from ebm_audit.workers.identity import build_fixture_identity
from ebm_audit.workers.structural import DeterministicFixtureBackend


def _argument_path(arguments: list[str], name: str) -> Path:
    index = arguments.index(name)
    return Path(arguments[index + 1])


def _append(path: Path, content: bytes) -> None:
    with path.open("ab") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    mode = sys.argv[1]
    protocol_arguments = sys.argv[2:]
    sdk_root = Path(__import__("ebm_audit.workers").workers.__file__).resolve().parent
    identity = build_fixture_identity(
        adapter_id="public-contract-core-adversary",
        backend_name="synthetic-core-boundary-adversary",
        code_paths=[Path(__file__), *sdk_root.glob("*.py")],
    )
    result = WorkerApplication(DeterministicFixtureBackend(identity)).run(protocol_arguments)
    if result != 0:
        return result

    request_dir = _argument_path(protocol_arguments, "--request-dir")
    response_dir = _argument_path(protocol_arguments, "--response-dir")
    response_path = response_dir / "response.json"
    if mode == "malformed-json":
        response_path.write_bytes(b"{")
    elif mode == "wrong-version":
        response = strict_json_loads(response_path.read_bytes())
        if not isinstance(response, dict):
            return 20
        response["protocol_version"] = "ebm-audit-worker/adversarial-version"
        response_path.write_bytes(canonical_json_bytes(response))
    elif mode == "extra-work-file":
        path = response_dir.parent / "work" / "undeclared.bin"
        path.write_bytes(b"project-owned-synthetic-transport-sentinel")
        path.chmod(0o600)
    elif mode == "nested-response-marker":
        nested = response_dir / "nested"
        nested.mkdir(mode=0o700)
        marker = nested / "response.json"
        marker.write_bytes(b"{}")
        marker.chmod(0o600)
    elif mode == "caught-network-attempt":
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except PermissionError:
            pass
        else:
            return 21
    elif mode == "caught-outside-write-attempt":
        path = Path("/tmp") / f"{response_dir.parent.name}-contract-adversary.bin"
        try:
            path.write_bytes(b"must-not-exist")
        except OSError:
            pass
        else:
            path.unlink(missing_ok=True)
            return 22
    elif mode == "mutate-request":
        _append(request_dir / "request.json", b"\n")
    elif mode == "tamper-warnings":
        _append(response_dir / "warnings.jsonl", b"{}\n")
    elif mode == "timeout-after-response":
        time.sleep(5)
    elif mode == "nonzero-after-response":
        return 23
    elif mode == "partial-response":
        response_path.unlink()
        temporary = response_dir / ".response.json.tmp"
        temporary.write_bytes(b"{")
        temporary.chmod(0o600)
        return 24
    else:
        return 25
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
