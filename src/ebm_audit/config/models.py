"""Typed, privacy-safe audit configuration values."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ebm_audit.protocol import (
    canonical_json_bytes,
    strict_json_loads,
    structured_sha256,
)

_RESOLVED_CONFIG_CONSTRUCTION_TOKEN = object()


@dataclass(frozen=True, slots=True, repr=False)
class PrivatePathBindings:
    """Resolved local paths kept outside the public resolved configuration."""

    source_config: Path
    input_table: Path
    worker_config: Path
    output_root: Path
    baseline_reference: Path | None
    external_missingness_variant: Path | None
    development_scenario_authority: Path | None

    def __repr__(self) -> str:
        return "PrivatePathBindings(<redacted-local-paths>)"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ResolvedAuditConfig:
    """One validated configuration with defensive JSON-compatible projections.

    Construction is private to the validating loader.  The canonical owner is
    retained internally, while callers receive a deep copy on every access so
    no mutation can detach either projection from ``public_digest``.
    """

    _private_config_bytes: bytes = field(repr=False)
    private_paths: PrivatePathBindings
    _public_projection_bytes: bytes = field(repr=False)
    _confirmation_issue_codes: tuple[str, ...] = field(repr=False)
    public_digest: str

    def __init__(
        self,
        *,
        private_config: Mapping[str, Any],
        private_paths: PrivatePathBindings,
        public_projection: Mapping[str, Any],
        public_digest: str,
        construction_token: object | None = None,
    ) -> None:
        if construction_token is not _RESOLVED_CONFIG_CONSTRUCTION_TOKEN:
            raise ConfigContractError("CONFIG.RESOLVED_CONFIG_CONSTRUCTION")
        private_owner = dict(private_config)
        public_owner = dict(public_projection)
        private_bytes = canonical_json_bytes(private_owner)
        public_bytes = canonical_json_bytes(public_owner)
        expected_digest = structured_sha256("ebm-audit/resolved-audit-config/3", public_owner)
        if public_digest != expected_digest:
            raise ConfigContractError("CONFIG.RESOLVED_CONFIG_DIGEST")
        issues = public_owner.get("confirmation_issue_codes")
        if not isinstance(issues, list) or any(not isinstance(item, str) for item in issues):
            raise ConfigContractError("CONFIG.RESOLVED_CONFIRMATION_ISSUES")
        object.__setattr__(self, "_private_config_bytes", private_bytes)
        object.__setattr__(self, "private_paths", private_paths)
        object.__setattr__(self, "_public_projection_bytes", public_bytes)
        object.__setattr__(self, "_confirmation_issue_codes", tuple(issues))
        object.__setattr__(self, "public_digest", public_digest)

    @property
    def private_config(self) -> dict[str, Any]:
        """Return a mutable execution copy without exposing the canonical owner."""

        value = strict_json_loads(self._private_config_bytes)
        if not isinstance(value, dict):
            raise TypeError("Resolved private configuration is not an object.")
        return value

    @property
    def public_projection(self) -> dict[str, Any]:
        """Return a JSON-compatible copy bound to ``public_digest``."""

        value = strict_json_loads(self._public_projection_bytes)
        if not isinstance(value, dict):
            raise TypeError("Resolved public configuration is not an object.")
        return value

    @property
    def confirmation_issue_codes(self) -> tuple[str, ...]:
        return self._confirmation_issue_codes

    @property
    def requires_confirmation(self) -> bool:
        return bool(self.confirmation_issue_codes)

    def __copy__(self) -> ResolvedAuditConfig:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> ResolvedAuditConfig:
        memo[id(self)] = self
        return self

    def __repr__(self) -> str:
        return (
            f"ResolvedAuditConfig(public_digest={self.public_digest!r}, private_paths=<redacted>)"
        )


def _construct_resolved_audit_config(
    *,
    private_config: Mapping[str, Any],
    private_paths: PrivatePathBindings,
    public_projection: Mapping[str, Any],
    public_digest: str,
) -> ResolvedAuditConfig:
    """Issue a resolved capability after loader-owned validation."""

    return ResolvedAuditConfig(
        private_config=private_config,
        private_paths=private_paths,
        public_projection=public_projection,
        public_digest=public_digest,
        construction_token=_RESOLVED_CONFIG_CONSTRUCTION_TOKEN,
    )


class ConfigContractError(ValueError):
    """A fixed-message configuration failure that never echoes private input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("Audit configuration is invalid.")

    def __repr__(self) -> str:
        return f"ConfigContractError(code={self.code!r})"
