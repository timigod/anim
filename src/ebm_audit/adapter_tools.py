"""Operator pinning, capability negotiation, and safe synthetic worker checks.

These helpers are CLI-independent. They never import a research backend, infer
capabilities from outputs, or turn absent/failed evidence into a pass.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]

from ebm_audit.adapter_scaffold.conformance import build_conformance_receipt
from ebm_audit.adapters.config import WorkerConfig
from ebm_audit.adapters.contract import run_contract_test
from ebm_audit.adapters.service import describe_worker
from ebm_audit.artifacts.store import _open_directory_chain, write_private_new
from ebm_audit.errors import AuditError, ExitCode, InvalidInputError, PrivacyViolationError
from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256, structured_sha256
from ebm_audit.schema import load_protocol_registry


def _pin_error() -> InvalidInputError:
    return InvalidInputError(
        "SPEC.ADAPTER_PIN_CHANGED",
        "The configuration changed or is not a regular private file. "
        "Keep the original configuration and pin a fresh copy with --output.",
    )


def _replace_config(path: Path, before: bytes, after: bytes) -> None:
    """Publish a complete pin without following links or truncating a live file."""
    directory_fd = _open_directory_chain(path.absolute().parent, create=False)
    temporary = f".adapter-pin-{secrets.token_hex(12)}.tmp"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=directory_fd)
        try:
            original = os.fstat(descriptor)
            if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
                raise _pin_error()
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                if handle.read(len(before) + 1) != before:
                    raise _pin_error()
            staged = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd
            )
            with os.fdopen(staged, "wb") as handle:
                handle.write(after)
                handle.flush()
                os.fsync(handle.fileno())
            current = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
            if any(getattr(current, field) != getattr(original, field) for field in fields):
                raise _pin_error()
            os.replace(temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            os.close(descriptor)
    except OSError:
        raise _pin_error() from None
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory_fd)
        os.close(directory_fd)


def pin_adapter(
    worker_config: Path, *, output: Path | None = None, timeout_seconds: float = 30.0
) -> dict[str, Any]:
    """Pin a null identity, or verify an existing pin; never silently re-pin drift.

    ``output`` is a new configuration file, not a receipt path. Without it the
    original is replaced atomically. Existing matching pins are left untouched.
    """
    if worker_config.is_symlink() or not worker_config.is_file():
        raise _pin_error()
    try:
        original = worker_config.read_bytes()
    except OSError:
        raise _pin_error() from None
    config = WorkerConfig.from_yaml_bytes(original)
    description = describe_worker(
        config.worker,
        selected_algorithm_id=config.algorithm_id,
        expected_identity=config.expected_identity,
        timeout_seconds=timeout_seconds,
    )
    pin = description["selected_expected_identity"]
    if config.expected_identity is not None and config.expected_identity != pin:
        raise _pin_error()
    document = {
        "worker": {"argv": list(config.worker.argv)},
        "algorithm_id": config.algorithm_id,
        "settings": dict(config.settings),
        "expected_identity": pin,
    }
    content = canonical_json_bytes(document) + b"\n"  # JSON is strict YAML, too.
    WorkerConfig.from_yaml_bytes(content)
    if output is not None and output.absolute() != worker_config.absolute():
        write_private_new(output, content)
        disposition = "CREATED"
    elif config.expected_identity is None:
        _replace_config(worker_config, original, content)
        disposition = "PINNED"
    else:
        content = original
        disposition = "ALREADY_PINNED"
    return {
        "adapter_pin_schema_version": "ebm-audit-adapter-pin/1.0",
        "status": "PASS",
        "disposition": disposition,
        "configuration_sha256": exact_file_sha256(content),
        "expected_identity": pin,
        "limitations": [
            "Pinning binds the observed worker; it does not establish trust or validity.",
            "Existing identities are verified, never silently replaced after drift.",
        ],
    }


def negotiate_capabilities(
    algorithm: Mapping[str, Any],
    *,
    requested_outputs: Sequence[str] = (),
    required_capabilities: Sequence[str] = (),
) -> dict[str, Any]:
    """Assess explicit requirements using the frozen requested-output registry."""
    capabilities = algorithm["capabilities"]
    outputs = tuple(requested_outputs) or ("central_order",)
    registry = {row["output_id"]: row for row in load_protocol_registry()["requested_outputs"]}
    known_capabilities = {name for name, value in capabilities.items() if type(value) is bool}
    if (
        len(outputs) != len(set(outputs))
        or len(required_capabilities) != len(set(required_capabilities))
        or not set(outputs) <= set(registry)
        or not set(required_capabilities) <= known_capabilities
    ):
        raise InvalidInputError(
            "SPEC.ADAPTER_REQUIREMENT_UNKNOWN",
            "Use unique output IDs from the protocol registry and boolean capability IDs "
            "from adapter describe. Unknown requirement text is not echoed.",
        )
    rows: list[dict[str, Any]] = []
    for output_id in outputs:
        rule = registry[output_id]
        missing = [
            name for name in rule["required_capabilities"] if capabilities.get(name) is not True
        ]
        status = "AVAILABLE"
        reason = None
        if missing:
            if (
                missing == ["fixed_evaluation_cohort_staging"]
                and rule.get("capability_absence_behavior")
                == "FIXED_COHORT_STAGE_COMPONENT_NOT_APPLICABLE"
            ):
                status = "NOT_APPLICABLE_BY_CAPABILITY"
                reason = "STAGING.FIXED_COHORT_UNAVAILABLE"
            else:
                status = "UNSUPPORTED"
                reason = "CAPABILITY.OUTPUT_UNSUPPORTED"
        rows.append(
            {
                "output_id": output_id,
                "status": status,
                "missing_capabilities": missing,
                "reason_code": reason,
                "value": None,
            }
        )
    requirements = [
        {"capability_id": name, "status": "AVAILABLE" if capabilities[name] else "UNSUPPORTED"}
        for name in required_capabilities
    ]
    available = all(row["status"] == "AVAILABLE" for row in [*rows, *requirements])
    return {
        "status": "PASS" if available else "UNSUPPORTED",
        "requested_outputs": rows,
        "required_capabilities": requirements,
        "constraints": dict(capabilities["constraints"]),
        "missing_values": capabilities["missing_values"],
        "supported_commands": list(algorithm["supported_commands"]),
        "remediation": []
        if available
        else [
            "Choose a worker that declares the missing capabilities, or explicitly reduce "
            "the requested outputs. Absent values must remain typed absence."
        ],
    }


def _diagnostic(code: str, action: str) -> dict[str, Any]:
    return {"code": code, "remediation": [action]}


def check_adapter(
    worker_config: Path,
    *,
    requested_outputs: Sequence[str] = (),
    required_capabilities: Sequence[str] = (),
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Return actionable diagnostics plus real synthetic conformance evidence."""
    receipt: dict[str, Any] = {
        "adapter_check_schema_version": "ebm-audit-adapter-check/1.0",
        "status": "UNAVAILABLE",
        "exit_code": int(ExitCode.PARTIAL),
        "negotiation": None,
        "conformance": None,
        "diagnostics": [],
        "scientific_acceptance": "NOT_ASSESSED",
    }
    try:
        config = WorkerConfig.from_yaml(worker_config)
        description = describe_worker(
            config.worker,
            selected_algorithm_id=config.algorithm_id,
            expected_identity=config.expected_identity,
            timeout_seconds=timeout_seconds,
        )
        algorithm = next(
            row
            for row in description["description"]["supported_algorithms"]
            if row["algorithm_id"] == config.algorithm_id
        )
        negotiation = negotiate_capabilities(
            algorithm,
            requested_outputs=requested_outputs,
            required_capabilities=required_capabilities,
        )
        receipt["negotiation"] = negotiation
        if list(
            jsonschema.Draft202012Validator(algorithm["settings_schema"]).iter_errors(
                config.settings
            )
        ):
            receipt.update(status="INVALID", exit_code=int(ExitCode.INVALID_INPUT_OR_SPECIFICATION))
            receipt["diagnostics"].append(
                _diagnostic(
                    "SPEC.ADAPTER_SETTINGS_INVALID",
                    "Match settings to settings_schema in adapter describe; check required keys, "
                    "types, ranges, and additionalProperties. Values are not echoed.",
                )
            )
            return receipt
        if config.expected_identity is None:
            receipt["diagnostics"].append(
                _diagnostic(
                    "SPEC.ADAPTER_IDENTITY_UNPINNED",
                    "Run adapter pin --worker-config on this config, then run adapter check.",
                )
            )
            return receipt
        command_digest = structured_sha256(
            "ebm-audit/adapter-conformance-worker-command/1", list(config.worker.argv)
        )
        config_digest = structured_sha256(
            "ebm-audit/adapter-conformance-config/1",
            {
                "algorithm_id": config.algorithm_id,
                "settings": dict(config.settings),
                "expected_identity": dict(config.expected_identity),
                "worker_command_digest": command_digest,
            },
        )
        contract = run_contract_test(config, timeout_seconds=timeout_seconds)
        conformance = build_conformance_receipt(
            description, contract, config_digest=config_digest, worker_command_digest=command_digest
        )
        receipt["conformance"] = conformance
        overall = conformance["overall_protocol_result"]
        if overall.get("result") == "FAIL":
            receipt.update(status="FAIL", exit_code=int(ExitCode.BACKEND_OR_PROTOCOL_FAILURE))
        elif overall.get("result") != "PASS":
            receipt.update(status="UNAVAILABLE", exit_code=int(ExitCode.PARTIAL))
        elif negotiation["status"] != "PASS":
            receipt.update(
                status="UNSUPPORTED", exit_code=int(ExitCode.WORKER_OR_CAPABILITY_UNAVAILABLE)
            )
        else:
            receipt.update(status="PASS", exit_code=int(ExitCode.SUCCESS))
        if conformance["first_actionable_failure"] is not None:
            receipt["diagnostics"].append(conformance["first_actionable_failure"])
        if negotiation["status"] != "PASS":
            receipt["diagnostics"].append(
                _diagnostic("CAPABILITY.REQUIREMENT_UNSATISFIED", negotiation["remediation"][0])
            )
    except PrivacyViolationError:
        raise
    except AuditError as error:
        receipt["exit_code"] = int(error.exit_code)
        receipt["status"] = (
            "INVALID"
            if error.exit_code == ExitCode.INVALID_INPUT_OR_SPECIFICATION
            else "UNAVAILABLE"
            if error.exit_code == ExitCode.WORKER_OR_CAPABILITY_UNAVAILABLE
            else "FAIL"
        )
        receipt["diagnostics"].append(
            _diagnostic(
                error.code,
                "Check the local executable and environment, algorithm ID, and immutable identity. "
                "Restore pins after drift; use a new configuration for an intentional upgrade. "
                "For an unavailable host sandbox, use a supported offline execution host.",
            )
        )
    return receipt


__all__ = ["check_adapter", "negotiate_capabilities", "pin_adapter"]
