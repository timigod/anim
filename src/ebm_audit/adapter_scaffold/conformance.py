"""Stable operator receipt composed from existing adapter checks."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from ebm_audit import __version__
from ebm_audit.protocol import canonical_json_bytes, exact_file_sha256

_UNAVAILABLE_REASON = "The source receipt did not provide this identity."


def _available(**fields: object) -> dict[str, object]:
    return {"availability": "AVAILABLE", **fields}


def _unavailable(reason: str = _UNAVAILABLE_REASON) -> dict[str, object]:
    return {"availability": "UNAVAILABLE", "reason": reason}


def _selected_algorithm(description_receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    selected_id = description_receipt["selected_algorithm_id"]
    description = description_receipt["description"]
    algorithms = description["supported_algorithms"]
    selected = [row for row in algorithms if row["algorithm_id"] == selected_id]
    if len(selected) != 1:
        raise ValueError("The selected algorithm is absent from the description receipt.")
    return cast(Mapping[str, Any], selected[0])


def _remediation(check_id: str) -> list[str]:
    actions = {
        "expected-immutable-identity": "Run adapter pin on an unpinned configuration. "
        "For drift restore pinned source/environment, or create a new configuration.",
        "describe-schema-and-algorithm": "Check the executable, installed worker dependencies, "
        "configured algorithm ID, closed describe schema, and declaration digests.",
        "worker-self-test": "Run generated tests and repair the synthetic self-test callbacks.",
        "finite-synthetic-validate": "Check settings, group roles, finite array shapes, "
        "and the selected algorithm's minimum participant and event counts.",
        "fit-same-seed-repeatability": "Bind every random generator to the full request seed and "
        "use deterministic ordering before reductions or model fitting.",
        "fit-different-seed-no-cache": "Bind seed and scientific request identity to every fit; "
        "do not reuse a cached result under another request.",
        "full-range-canonical-seeds": "Accept the entire UInt64 seed, including both boundaries; "
        "avoid truncation to a 32-bit legacy random seed.",
        "unknown-setting-rejected": "Reject undeclared settings using the closed settings schema.",
        "unavailable-output-rejected": "Reject unsupported outputs with UNSUPPORTED_CAPABILITY; "
        "preserve the protocol's explicit fixed-evaluation absence exception.",
        "declared-fit-output-surface": "Return every declared requested output with its canonical "
        "array metadata, or withdraw the unsupported capability from the declaration.",
        "row-permutation-and-index-roundtrip": "Keep internal row indexes aligned and canonicalize "
        "model fitting order so input row permutation cannot change scientific results.",
        "feature-column-permutation-and-label-remap": "Map backend positions to event IDs and "
        "canonicalize event ordering before any seeded operation or floating-point reduction.",
        "sampler-off-by-one-and-convergence-finalisation": "Return postproposal states and "
        "aligned likelihoods; compute burn/thin counts from the canonical indexing equations.",
        "private-identifier-and-raw-value-canary-scan": "Remove identifiers and raw input values "
        "from metadata, returned arrays, logs, and retained diagnostics.",
        "explicit-network-attempt-case": "Use a supported offline sandbox. Runtime workers must "
        "not attempt network access; provision dependencies before running checks.",
        "complete-result-invariant-matrix": "Build results using FitContext.fit_success and retain "
        "request identities, provenance, typed absence, canonical arrays, and field origins.",
        "participant-event-cell-accounting": "Preserve all requested rows, event IDs, and cells; "
        "bind returned row indexes and counts to the unchanged execution projection.",
    }
    return [
        actions.get(
            check_id, "Repair the named synthetic contract boundary and rerun adapter check."
        )
    ]


def _failure(check: Mapping[str, Any], *, unavailable: bool) -> dict[str, Any]:
    return {
        "code": (
            "CONFORMANCE.REQUIRED_CHECK_UNAVAILABLE"
            if unavailable
            else "CONFORMANCE.REQUIRED_CHECK_FAILED"
        ),
        "check_id": check["check_id"],
        "remediation": _remediation(str(check["check_id"])),
        "safe_message": check["safe_message"],
    }


def _check_rows(contract_receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_cases = contract_receipt["cases"]
    if not isinstance(raw_cases, Sequence):
        raise TypeError("The contract receipt cases are invalid.")
    checks: list[dict[str, Any]] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, Mapping):
            raise TypeError("A contract receipt case is invalid.")
        source_status = raw_case["status"]
        applicability = raw_case["applicability"]
        check: dict[str, Any] = {
            "applicability": applicability,
            "check_id": raw_case["case_id"],
            "required": raw_case["required"],
            "safe_message": raw_case["safe_message"],
        }
        if applicability == "NOT_APPLICABLE":
            check["availability"] = "NOT_APPLICABLE"
        elif source_status in {"PASS", "FAIL"}:
            check["availability"] = "AVAILABLE"
            check["result"] = source_status
        elif source_status in {"UNVERIFIED", "UNSUPPORTED"}:
            check["availability"] = "UNAVAILABLE"
            check["unavailable_reason"] = "The contract check did not run to a pass/fail result."
        else:
            raise TypeError("A contract receipt case status is invalid.")
        if "evidence_subject" in raw_case:
            check["evidence_subject"] = raw_case["evidence_subject"]
        checks.append(check)
    return checks


def _first_actionable_failure(checks: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    for check in checks:
        if check["required"] is not True:
            continue
        if check["availability"] == "AVAILABLE" and check.get("result") == "PASS":
            continue
        return _failure(check, unavailable=check["availability"] != "AVAILABLE")
    return None


def _counts(checks: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        "availability": {
            status: sum(check["availability"] == status for check in checks)
            for status in ("AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE")
        },
        "results": {
            result: sum(check.get("result") == result for check in checks)
            for result in ("PASS", "FAIL")
        },
    }


def _identity_value(identity: Mapping[str, Any] | None, field: str) -> dict[str, object]:
    if identity is None or identity.get(field) is None:
        return _unavailable()
    return _available(value=identity[field])


def _declared_limitations(description: Mapping[str, Any]) -> dict[str, object]:
    limitations = description.get("worker_limitations")
    if not isinstance(limitations, Sequence) or isinstance(limitations, (str, bytes)):
        return _unavailable("The worker description did not provide declared limitations.")
    return _available(limitations=list(limitations))


def _evidence_inventory(
    description_receipt: Mapping[str, Any],
    contract_receipt: Mapping[str, Any],
) -> dict[str, object]:
    entries = []
    for name, receipt in (
        ("adapter-description-receipt.json", description_receipt),
        ("public-contract-test-receipt.json", contract_receipt),
    ):
        content = canonical_json_bytes(receipt)
        entries.append(
            {
                "byte_length": len(content),
                "name": name,
                "sha256": exact_file_sha256(content),
            }
        )
    return _available(entries=entries)


def _named_check_result(
    checks: Sequence[Mapping[str, Any]],
    check_id: str,
) -> dict[str, object]:
    selected = [check for check in checks if check["check_id"] == check_id]
    if len(selected) != 1:
        return _unavailable("The required conformance check is absent.")
    check = selected[0]
    if check["availability"] == "NOT_APPLICABLE":
        return {"availability": "NOT_APPLICABLE", "check_id": check_id}
    if check["availability"] == "UNAVAILABLE":
        return _unavailable("The required conformance check did not run.") | {"check_id": check_id}
    return _available(check_id=check_id, result=check["result"])


def _overall_result(
    contract_receipt: Mapping[str, Any],
    first_failure: Mapping[str, Any] | None,
) -> dict[str, object]:
    aggregate = contract_receipt["aggregate_status"]
    if aggregate in {"PASS", "FAIL"}:
        result = _available(result=aggregate)
    elif aggregate in {"UNVERIFIED", "UNSUPPORTED"}:
        result = _unavailable("One or more required checks did not run to a pass/fail result.")
    else:
        raise TypeError("The contract aggregate status is invalid.")
    if first_failure is not None:
        result["failure"] = dict(first_failure)
    return result


def build_conformance_receipt(
    description_receipt: Mapping[str, Any],
    contract_receipt: Mapping[str, Any],
    *,
    config_digest: str | None = None,
    worker_command_digest: str | None = None,
) -> dict[str, Any]:
    """Compose stable, path-free protocol and capability conformance state."""

    algorithm = _selected_algorithm(description_receipt)
    checks = _check_rows(contract_receipt)
    first_failure = _first_actionable_failure(checks)
    worker_identity = cast(Mapping[str, Any] | None, contract_receipt["worker_identity"])
    capabilities = algorithm.get("capabilities")
    description = cast(Mapping[str, Any], description_receipt["description"])
    classification = description.get("worker_classification")
    return {
        "adapter_conformance_schema_version": "ebm-audit-adapter-conformance/2.0",
        "artifact_inventory": _evidence_inventory(description_receipt, contract_receipt),
        "check_counts": _counts(checks),
        "checks": checks,
        "command_identity": _available(
            command_id="ebm-audit.adapter.conformance",
            contract_receipt_schema_version=contract_receipt["receipt_schema_version"],
            test_profile_id="ebm-audit-adapter-conformance-profile/1.0",
            worker_command=(
                _unavailable("The caller did not provide a path-free worker command digest.")
                if worker_command_digest is None
                else _available(digest=worker_command_digest)
            ),
        ),
        "config_identity": (
            _unavailable("The caller did not provide a configuration digest.")
            if config_digest is None
            else _available(digest=config_digest)
        ),
        "declared_capabilities": (
            _unavailable("The selected algorithm did not declare capabilities.")
            if not isinstance(capabilities, Mapping)
            else _available(
                algorithm_id=contract_receipt["algorithm_id"],
                capabilities=dict(capabilities),
                capability_applicability=list(contract_receipt["capability_applicability"]),
                capabilities_digest=algorithm["capabilities_digest"],
                supported_commands=list(algorithm["supported_commands"]),
            )
        ),
        "declared_limitations": _declared_limitations(description),
        "environment_identity": {
            "auditor_environment": _unavailable(
                "This focused protocol receipt does not inventory the auditor environment."
            ),
            "worker_environment": _identity_value(worker_identity, "environment_digest"),
        },
        "first_actionable_failure": first_failure,
        "offline_network_denial": _named_check_result(checks, "explicit-network-attempt-case"),
        "overall_protocol_result": _overall_result(contract_receipt, first_failure),
        "package_identity": _available(
            distribution="anim",
            version=__version__,
        ),
        "privacy_scan": _named_check_result(checks, "private-identifier-and-raw-value-canary-scan"),
        "protocol_identity": _available(
            contract_receipt_schema_version=contract_receipt["receipt_schema_version"],
            protocol_version=contract_receipt["protocol_version"],
            synthetic_fixture_digest=_identity_value(contract_receipt, "fixture_digest"),
            synthetic_fixture_label=contract_receipt["fixture_label"],
        ),
        "scientific_acceptance": {
            "availability": "NOT_APPLICABLE",
            "statement": "Protocol conformance is not scientific acceptance.",
        },
        "source_identity": {
            "auditor_source": _unavailable(
                "The installed package does not declare a source revision in this receipt."
            ),
            "backend_source": _identity_value(worker_identity, "backend_source_digest"),
            "worker_code": _identity_value(worker_identity, "worker_code_digest"),
        },
        "tool_identity": _available(tool_id="ebm-audit", version=__version__),
        "worker_classification": (
            _unavailable("The worker description did not declare a classification.")
            if classification is None
            else _available(value=classification)
        ),
        "worker_identity": (
            _unavailable("The worker identity was not available.")
            if worker_identity is None
            else _available(identity=dict(worker_identity))
        ),
    }
