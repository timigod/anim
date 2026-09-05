"""Scriptable local command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn, cast

from ebm_audit.adapter_scaffold import (
    build_conformance_receipt,
    initialize_adapter_scaffold,
)
from ebm_audit.adapters import (
    WorkerCommand,
    WorkerConfig,
    describe_worker,
    normalize_worker_timeout_seconds,
    run_contract_test,
)
from ebm_audit.artifacts import ensure_private_directory, write_private_new
from ebm_audit.baseline.bundle import ReferenceBundleError
from ebm_audit.config import ConfigContractError
from ebm_audit.errors import AuditError, ExitCode, InvalidInputError
from ebm_audit.protocol import structured_sha256
from ebm_audit.reporting import (
    ReportUnavailableError,
    render_report_from_run_dir,
)
from ebm_audit.reporting.inspection import ReportInspectionError
from ebm_audit.universe.identities import UniverseIdentityError


class _SafeUsageError(Exception):
    """Argument parsing failed without retaining argparse's raw message."""


class _HelpComplete(Exception):
    """Normal help output was printed and needs a zero return code."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argparse surface that never writes caller-controlled error prose."""

    def error(self, message: str) -> NoReturn:
        del message
        raise _SafeUsageError from None

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        # Help has already printed the parser-owned, caller-independent text.
        # No other argparse exit is allowed to print its constructed message.
        if status == 0 and message is None:
            raise _HelpComplete from None
        del message
        raise _SafeUsageError from None


def _worker_timeout(value: str) -> float:
    try:
        timeout = float(value)
        return normalize_worker_timeout_seconds(timeout)
    except (OverflowError, ValueError):
        raise argparse.ArgumentTypeError("timeout must be a positive number") from None


def _memory_megabytes(value: str) -> int:
    try:
        parsed = int(value)
        if not 1 <= parsed <= 1048576:
            raise ValueError
        return parsed * 1024 * 1024
    except ValueError:
        raise argparse.ArgumentTypeError("memory must be a positive integer in MiB") from None


def _execution_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--progress", action="store_true", help="Write progress JSON to stderr.")
    parser.add_argument(
        "--memory-budget-mb",
        type=_memory_megabytes,
        help="Worker admission budget in MiB; requires --worker-memory-mb.",
    )
    parser.add_argument(
        "--worker-memory-mb",
        type=_memory_megabytes,
        help="Declared per-worker reservation in MiB; this is not an RSS limit.",
    )


def _parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(prog="ebm-audit")
    command = parser.add_subparsers(dest="command", required=True)

    doctor_parser = command.add_parser(
        "doctor", help="Check local, offline pre-execution readiness."
    )
    doctor_parser.add_argument("--root", type=Path)
    doctor_parser.add_argument("--worker-config", type=Path)
    doctor_parser.add_argument("--require-pysaebm", action="store_true")
    doctor_parser.add_argument("--timeout", type=_worker_timeout, default=30.0)
    doctor_parser.add_argument("--output", type=Path)

    init_parser = command.add_parser(
        "init", help="Create a strict AuditConfig/0.3 starter without overwriting."
    )
    init_parser.add_argument(
        "--template",
        choices=("synthetic", "idris-2025-public"),
        default="synthetic",
    )
    init_parser.add_argument("--output", type=Path, required=True)
    init_parser.add_argument("--input-path", required=True)
    init_parser.add_argument("--worker-config-path", required=True)
    init_parser.add_argument("--run-root", required=True)

    validate_parser = command.add_parser(
        "validate", help="Verify local inputs and authenticated worker identity without fitting."
    )
    validate_parser.add_argument("--config", type=Path, required=True)
    validate_parser.add_argument(
        "--offline",
        action="store_true",
        required=True,
        help="Required acknowledgement of the enforced local no-network mode.",
    )
    validate_parser.add_argument("--timeout", type=_worker_timeout, default=30.0)
    validate_parser.add_argument("--output", type=Path)

    plan_parser = command.add_parser(
        "plan", help="Compile and verify a safe Plan/3 summary without fitting."
    )
    plan_parser.add_argument("--config", type=Path, required=True)
    plan_parser.add_argument(
        "--offline",
        action="store_true",
        required=True,
        help="Required acknowledgement of the enforced local no-network mode.",
    )
    plan_parser.add_argument("--profile", choices=("quick", "full", "release"), default="quick")
    plan_parser.add_argument("--timeout", type=_worker_timeout, default=30.0)
    plan_parser.add_argument("--output", type=Path)

    run_parser = command.add_parser(
        "run",
        help="Execute the exact local candidate set and write an incomplete offline report.",
        description=(
            "Execute the configured local audit candidate set. The current report "
            "is explicitly incomplete until every scientific and run gate is implemented."
        ),
    )
    run_parser.add_argument("--config", type=Path, required=True)
    run_parser.add_argument(
        "--offline",
        action="store_true",
        required=True,
        help="Required acknowledgement of the enforced local no-network mode.",
    )
    run_parser.add_argument("--profile", choices=("quick", "full", "release"), default="quick")
    run_parser.add_argument("--timeout", type=_worker_timeout, default=30.0)
    _execution_options(run_parser)

    rerun_parser = command.add_parser(
        "rerun",
        help="Verify a replay recipe and create a fresh attempt with unchanged inputs.",
    )
    rerun_parser.add_argument("--manifest", type=Path, required=True)
    rerun_parser.add_argument("--config", type=Path, required=True)
    rerun_parser.add_argument(
        "--run-root",
        required=True,
        help="Fresh output path relative to the original config directory.",
    )
    rerun_parser.add_argument("--offline", action="store_true", required=True)
    rerun_parser.add_argument("--timeout", type=_worker_timeout, default=30.0)
    _execution_options(rerun_parser)

    summary_parser = command.add_parser("summary", help="Inspect saved report evidence and limits.")
    summary_parser.add_argument("--run-dir", type=Path, required=True)
    summary_parser.add_argument("--output", type=Path)
    diff_parser = command.add_parser(
        "diff", help="Compare saved scientific evidence and provenance."
    )
    diff_parser.add_argument("--left", type=Path, required=True)
    diff_parser.add_argument("--right", type=Path, required=True)
    diff_parser.add_argument("--output", type=Path)

    demo_parser = command.add_parser(
        "demo",
        help="Run the project-owned SYNTHETIC-ONLY conformance EBM locally.",
    )
    demo_parser.add_argument("--conformance-ebm", action="store_true", required=True)
    demo_parser.add_argument(
        "--capability-profile",
        choices=("full", "partial"),
        default="full",
    )

    report_parser = command.add_parser(
        "report",
        help="Refuse standalone reporting until persisted science-v2 authority exists.",
        description=(
            "Standalone report rehydration is currently unavailable. This command "
            "returns REPORT.V1_DISABLED without reading the run path or writing artifacts."
        ),
    )
    report_parser.add_argument("--run-dir", type=Path, required=True)
    report_parser.add_argument("--output-dir", type=Path, required=True)

    baseline_reference = command.add_parser(
        "baseline-reference",
        help="Create or validate a private canonical baseline reference bundle.",
    )
    baseline_reference_command = baseline_reference.add_subparsers(
        dest="baseline_reference_command",
        required=True,
    )
    baseline_reference_init = baseline_reference_command.add_parser(
        "init",
        help="Create a deliberately non-importable local draft and notebook example.",
    )
    baseline_reference_init.add_argument("--output-dir", type=Path, required=True)
    baseline_reference_validate = baseline_reference_command.add_parser(
        "validate",
        help="Validate one canonical private reference bundle without fitting.",
    )
    baseline_reference_validate.add_argument("--manifest", type=Path, required=True)
    baseline_reference_validate.add_argument(
        "--offline",
        action="store_true",
        required=True,
        help="Required acknowledgement of the enforced local no-network mode.",
    )
    baseline_reference_validate.add_argument("--output", type=Path, required=True)

    adapter = command.add_parser("adapter", help="Create and inspect a local external worker.")
    adapter_command = adapter.add_subparsers(dest="adapter_command", required=True)
    adapter_init = adapter_command.add_parser(
        "init", help="Create a deterministic offline local worker project."
    )
    adapter_init.add_argument("path", type=Path)
    pin = adapter_command.add_parser("pin", help="Pin the exact local worker identity.")
    pin.add_argument("--worker-config", type=Path, required=True)
    pin.add_argument("--output", type=Path)
    pin.add_argument("--timeout", type=_worker_timeout, default=30.0)
    check = adapter_command.add_parser("check", help="Qualify a worker and negotiate capabilities.")
    check.add_argument("--worker-config", type=Path, required=True)
    check.add_argument("--require-output", action="append", default=[])
    check.add_argument("--require-capability", action="append", default=[])
    check.add_argument("--output", type=Path)
    check.add_argument("--timeout", type=_worker_timeout, default=30.0)
    describe = adapter_command.add_parser("describe", help="Read worker identity and capabilities.")
    describe.add_argument("--offline", action="store_true", default=True)
    describe.add_argument("--timeout", type=_worker_timeout, default=30.0)
    describe.add_argument("--output", type=Path)
    describe_source = describe.add_mutually_exclusive_group(required=True)
    describe_source.add_argument("--worker-config", type=Path)
    describe_source.add_argument(
        "--worker",
        nargs=argparse.REMAINDER,
        help="Tokenized local command. Place this option last.",
    )
    contract_test = adapter_command.add_parser(
        "contract-test",
        help="Run the implemented synthetic public worker contract cases.",
    )
    contract_test.add_argument("--worker-config", type=Path, required=True)
    contract_test.add_argument("--offline", action="store_true", default=True)
    contract_test.add_argument("--timeout", type=_worker_timeout, default=30.0)
    contract_test.add_argument("--output-dir", type=Path, required=True)
    conformance = adapter_command.add_parser(
        "conformance",
        help="Run the one protocol and declared-capability conformance check.",
    )
    conformance.add_argument("--worker-config", type=Path, required=True)
    conformance.add_argument("--offline", action="store_true", default=True)
    conformance.add_argument("--timeout", type=_worker_timeout, default=30.0)
    conformance.add_argument("--output-dir", type=Path, required=True)
    return parser


def _emit_error(error: AuditError) -> None:
    body = {"error": {"code": error.code, "safe_message": error.safe_message}}
    print(json.dumps(body, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def _emit_result(result: Mapping[str, Any], output: Path | None) -> None:
    content = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if output is None:
        sys.stdout.buffer.write(content)
    else:
        write_private_new(output, content)


def _describe_configured_worker(
    config: WorkerConfig,
    *,
    timeout_seconds: float,
) -> Mapping[str, Any]:
    receipt = describe_worker(
        config.worker,
        timeout_seconds=timeout_seconds,
        selected_algorithm_id=config.algorithm_id,
        expected_identity=config.expected_identity,
    )
    return dict(receipt)


def _conformance_identity_digests(config: WorkerConfig) -> tuple[str, str]:
    command_digest = structured_sha256(
        "ebm-audit/adapter-conformance-worker-command/1",
        list(config.worker.argv),
    )
    config_digest = structured_sha256(
        "ebm-audit/adapter-conformance-config/1",
        {
            "algorithm_id": config.algorithm_id,
            "expected_identity": config.expected_identity,
            "settings": config.settings,
            "worker_command_digest": command_digest,
        },
    )
    return config_digest, command_digest


def _emit_conformance_summary(result: Mapping[str, Any], receipt_name: str) -> None:
    overall = cast(Mapping[str, Any], result["overall_protocol_result"])
    overall_label = overall.get("result", overall["availability"])
    print(f"Conformance receipt: {receipt_name}")
    print(f"Overall protocol result: {overall_label}")
    failure = result["first_actionable_failure"]
    if isinstance(failure, Mapping):
        print(f"First actionable failure: {failure['check_id']}: {failure['safe_message']}")
        remediation = failure["remediation"]
        if isinstance(remediation, Sequence) and remediation:
            print(f"Remediation: {remediation[0]}")


def main(argv: Sequence[str] | None = None) -> int:
    # This process and every worker child receive the product's explicit local,
    # no-network posture. No command offers a flag that can turn it off.
    os.environ["EBM_AUDIT_OFFLINE"] = "1"
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "doctor":
            from ebm_audit.cli_workflows import doctor

            result, exit_code = doctor(
                root=arguments.root,
                worker_config=arguments.worker_config,
                require_pysaebm=arguments.require_pysaebm,
                timeout_seconds=arguments.timeout,
            )
            _emit_result(result, arguments.output)
            return int(exit_code)
        if arguments.command == "init":
            from ebm_audit.cli_workflows import initialize_config

            result = initialize_config(
                destination=arguments.output,
                input_path=arguments.input_path,
                worker_config_path=arguments.worker_config_path,
                run_root=arguments.run_root,
                template_kind=arguments.template,
            )
            _emit_result(result, None)
            return int(ExitCode.SUCCESS)
        if arguments.command == "validate":
            from ebm_audit.cli_workflows import validate_preexecution

            result = validate_preexecution(
                arguments.config,
                timeout_seconds=arguments.timeout,
            )
            _emit_result(result, arguments.output)
            return int(ExitCode.SUCCESS)
        if arguments.command == "plan":
            from ebm_audit.cli_workflows import plan_preexecution

            result = plan_preexecution(
                arguments.config,
                profile_id=arguments.profile,
                timeout_seconds=arguments.timeout,
            )
            _emit_result(result, arguments.output)
            return int(ExitCode.SUCCESS)
        if arguments.command in {"run", "rerun"}:
            from ebm_audit.cli_workflows import run_audit
            from ebm_audit.runner import ExecutionControl, ExecutionProgress

            def progress(event: ExecutionProgress) -> None:
                print(
                    json.dumps(
                        {"progress": {"phase": str(event.phase), **event.counts()}}, sort_keys=True
                    ),
                    file=sys.stderr,
                    flush=True,
                )

            control = ExecutionControl(
                progress_callback=progress if arguments.progress else None,
                memory_budget_bytes=arguments.memory_budget_mb,
                per_worker_memory_bytes=arguments.worker_memory_mb,
            )
            with control.signal_handlers():
                if arguments.command == "rerun":
                    from ebm_audit.replay import rerun_audit

                    result, exit_code = rerun_audit(
                        arguments.manifest,
                        arguments.config,
                        run_root=arguments.run_root,
                        timeout_seconds=arguments.timeout,
                        control=control,
                    )
                else:
                    result, exit_code = run_audit(
                        arguments.config,
                        profile_id=arguments.profile,
                        timeout_seconds=arguments.timeout,
                        execution_control=control,
                    )
            _emit_result(result, None)
            return int(exit_code)
        if arguments.command in {"summary", "diff"}:
            from ebm_audit.reporting.inspection import compare_reports, inspect_report

            result = (
                inspect_report(arguments.run_dir)
                if arguments.command == "summary"
                else compare_reports(arguments.left, arguments.right)
            )
            _emit_result(result, arguments.output)
            return int(ExitCode.SUCCESS)
        if arguments.command == "adapter" and arguments.adapter_command == "pin":
            from ebm_audit.adapter_tools import pin_adapter

            result = pin_adapter(
                arguments.worker_config, output=arguments.output, timeout_seconds=arguments.timeout
            )
            _emit_result(result, None)
            return int(ExitCode.SUCCESS)
        if arguments.command == "adapter" and arguments.adapter_command == "check":
            from ebm_audit.adapter_tools import check_adapter

            result = check_adapter(
                arguments.worker_config,
                requested_outputs=arguments.require_output,
                required_capabilities=arguments.require_capability,
                timeout_seconds=arguments.timeout,
            )
            _emit_result(result, arguments.output)
            return int(result["exit_code"])
        if arguments.command == "demo":
            from ebm_audit.cli_workflows import run_conformance_demo

            result, exit_code = run_conformance_demo(
                timeout_seconds=30.0,
                capability_profile=arguments.capability_profile,
            )
            _emit_result(result, None)
            return int(exit_code)
        if arguments.command == "report":
            result = render_report_from_run_dir(
                arguments.run_dir,
                arguments.output_dir,
            )
            _emit_result(result, None)
            return int(ExitCode.SUCCESS)
        if (
            arguments.command == "baseline-reference"
            and arguments.baseline_reference_command == "init"
        ):
            from ebm_audit.baseline.export import initialize_reference_bundle

            result = initialize_reference_bundle(arguments.output_dir)
            _emit_result(result, None)
            return int(ExitCode.SUCCESS)
        if (
            arguments.command == "baseline-reference"
            and arguments.baseline_reference_command == "validate"
        ):
            from ebm_audit.baseline.export import validate_reference_bundle

            result = validate_reference_bundle(arguments.manifest)
            _emit_result(result, arguments.output)
            return int(ExitCode.SUCCESS)
        if arguments.command == "adapter" and arguments.adapter_command == "describe":
            if arguments.worker_config is not None:
                config = WorkerConfig.from_yaml(arguments.worker_config)
                result = _describe_configured_worker(
                    config,
                    timeout_seconds=arguments.timeout,
                )
            else:
                if not arguments.worker:
                    raise InvalidInputError(
                        "SPEC.WORKER_COMMAND_EMPTY", "A worker command is required."
                    )
                worker = WorkerCommand.from_tokens(arguments.worker)
                result = describe_worker(worker, timeout_seconds=arguments.timeout)
            content = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
            if arguments.output is None:
                sys.stdout.buffer.write(content)
            else:
                write_private_new(arguments.output, content)
            return int(ExitCode.SUCCESS)
        if arguments.command == "adapter" and arguments.adapter_command == "init":
            result = initialize_adapter_scaffold(arguments.path)
            _emit_result(result, None)
            return int(ExitCode.SUCCESS)
        if arguments.command == "adapter" and arguments.adapter_command == "contract-test":
            config = WorkerConfig.from_yaml(arguments.worker_config)
            output_dir = arguments.output_dir
            ensure_private_directory(output_dir)
            receipt_path = output_dir / "contract-test-receipt.json"
            if receipt_path.exists() or receipt_path.is_symlink():
                raise InvalidInputError(
                    "SPEC.OUTPUT_ALREADY_EXISTS",
                    "The output path already exists; this command does not overwrite artifacts.",
                )
            result = run_contract_test(config, timeout_seconds=arguments.timeout)
            content = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
            write_private_new(receipt_path, content)
            aggregate = result["aggregate_status"]
            if aggregate == "PASS":
                return int(ExitCode.SUCCESS)
            if aggregate == "FAIL":
                return int(ExitCode.BACKEND_OR_PROTOCOL_FAILURE)
            return int(ExitCode.PARTIAL)
        if arguments.command == "adapter" and arguments.adapter_command == "conformance":
            config = WorkerConfig.from_yaml(arguments.worker_config)
            output_dir = arguments.output_dir
            ensure_private_directory(output_dir)
            receipt_path = output_dir / "adapter-conformance-receipt.json"
            if receipt_path.exists() or receipt_path.is_symlink():
                raise InvalidInputError(
                    "SPEC.OUTPUT_ALREADY_EXISTS",
                    "The output path already exists; this command does not overwrite artifacts.",
                )
            config_digest, command_digest = _conformance_identity_digests(config)
            description = _describe_configured_worker(
                config,
                timeout_seconds=arguments.timeout,
            )
            contract = run_contract_test(config, timeout_seconds=arguments.timeout)
            result = build_conformance_receipt(
                description,
                contract,
                config_digest=config_digest,
                worker_command_digest=command_digest,
            )
            content = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
            write_private_new(receipt_path, content)
            _emit_conformance_summary(result, receipt_path.name)
            overall = cast(Mapping[str, Any], result["overall_protocol_result"])
            if overall.get("result") == "PASS":
                return int(ExitCode.SUCCESS)
            if overall.get("result") == "FAIL":
                return int(ExitCode.BACKEND_OR_PROTOCOL_FAILURE)
            return int(ExitCode.PARTIAL)
    except _HelpComplete:
        return int(ExitCode.SUCCESS)
    except _SafeUsageError:
        _emit_error(
            InvalidInputError(
                "SPEC.CLI_USAGE",
                "The command usage is invalid.",
            )
        )
        return int(ExitCode.INVALID_INPUT_OR_SPECIFICATION)
    except ReferenceBundleError:
        _emit_error(
            InvalidInputError(
                "SPEC.BASELINE_REFERENCE_INVALID",
                "The private baseline reference bundle is invalid or unavailable.",
            )
        )
        return int(ExitCode.INVALID_INPUT_OR_SPECIFICATION)
    except AuditError as error:
        _emit_error(error)
        return int(error.exit_code)
    except ConfigContractError as error:
        _emit_error(InvalidInputError(error.code, "The audit configuration is invalid."))
        return int(ExitCode.INVALID_INPUT_OR_SPECIFICATION)
    except UniverseIdentityError:
        _emit_error(
            InvalidInputError(
                "PLAN.INVALID",
                "The exact local inputs do not produce a valid analysis plan.",
            )
        )
        return int(ExitCode.INVALID_INPUT_OR_SPECIFICATION)
    except ReportUnavailableError as error:
        _emit_error(InvalidInputError(error.code, error.safe_message))
        return int(ExitCode.INVALID_INPUT_OR_SPECIFICATION)
    except ReportInspectionError as error:
        _emit_error(InvalidInputError(error.code, str(error)))
        return int(ExitCode.INVALID_INPUT_OR_SPECIFICATION)
    except Exception:
        body = {
            "error": {
                "code": "UNEXPECTED.CORE_FAILURE",
                "safe_message": "The auditor stopped at an unexpected local core boundary.",
            }
        }
        print(json.dumps(body, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return int(ExitCode.UNEXPECTED_CORE_ERROR)
    return int(ExitCode.UNEXPECTED_CORE_ERROR)
