"""Opaque binding of one validated report model to its exact JSON and HTML bytes.

This is deliberately not a ``REPORT_PREDICATE_OUTCOME``. The evaluator joins
this owner to its authenticated complete scenario case batch at the separate
package-private outcome issuance boundary.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Never, SupportsIndex, cast, final

from ebm_audit._capability_registry import (
    OneShotRegistryError,
    OneShotRegistryIssuer,
    OneShotWeakRegistry,
    create_one_shot_registry,
)
from ebm_audit.protocol import (
    CanonicalizationError,
    canonical_json_bytes,
    exact_file_sha256,
    strict_json_loads,
    structured_sha256,
)

_MODEL_DOMAIN = "ebm-audit/report-predicate-model/1"
_BINDING_DOMAIN = "ebm-audit/report-model-artifact-binding/2"
_BINDING_SCHEMA_VERSION = "ebm-audit-report-model-artifact-binding/2.0"


class ReportModelArtifactBindingError(TypeError):
    """Raised when the exact report-model/artifact authority is absent or detached."""


@dataclass(frozen=True, slots=True)
class _BindingState:
    model_bytes: bytes
    report_artifact_bytes: bytes
    report_html_artifact_bytes: bytes
    projection_bytes: bytes


_BINDING_STATES: OneShotWeakRegistry[object, _BindingState]


@final
class AuthenticatedReportModelArtifactBinding:
    """Unforgeable owner of exact, mutually authenticated report representations."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> AuthenticatedReportModelArtifactBinding:
        raise TypeError("Report model/artifact bindings are privately issued.")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        raise TypeError("Report model/artifact bindings cannot be subclassed.")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("Report model/artifact bindings are immutable.")

    def __copy__(self) -> Never:
        raise TypeError("Report model/artifact bindings cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Report model/artifact bindings cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("Report model/artifact bindings cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("Report model/artifact bindings cannot be copied or serialized.")

    def __getstate__(self) -> Never:
        raise TypeError("Report model/artifact bindings cannot be copied or serialized.")

    def __repr__(self) -> str:
        return "AuthenticatedReportModelArtifactBinding(<opaque>)"

    @property
    def digest(self) -> str:
        return cast(str, _validated_binding_projection(self)["binding_sha256"])


def _binding_error() -> ReportModelArtifactBindingError:
    return ReportModelArtifactBindingError(
        "Authenticated report model/artifact evidence failed closed validation."
    )


def _validated_binding(
    owner: AuthenticatedReportModelArtifactBinding,
) -> tuple[dict[str, Any], dict[str, object]]:
    if type(owner) is not AuthenticatedReportModelArtifactBinding:
        raise _binding_error()
    try:
        state = _BINDING_STATES.read(owner)
        if type(state) is not _BindingState:
            raise _binding_error()
        if (
            type(state.model_bytes) is not bytes
            or type(state.report_artifact_bytes) is not bytes
            or type(state.report_html_artifact_bytes) is not bytes
            or type(state.projection_bytes) is not bytes
        ):
            raise _binding_error()
        model = strict_json_loads(state.model_bytes)
        artifact_model = strict_json_loads(state.report_artifact_bytes)
        projection_value = strict_json_loads(state.projection_bytes)
    except (CanonicalizationError, OneShotRegistryError):
        raise _binding_error() from None
    if (
        type(model) is not dict
        or type(artifact_model) is not dict
        or type(projection_value) is not dict
    ):
        raise _binding_error()
    projection = cast(dict[str, object], projection_value)
    required = {
        "binding_schema_version",
        "report_schema_version",
        "report_model_sha256",
        "report_artifact_sha256",
        "report_html_artifact_sha256",
        "binding_sha256",
    }
    digest = projection.get("binding_sha256")
    preimage = copy.deepcopy(projection)
    preimage["binding_sha256"] = None
    if (
        set(projection) != required
        or canonical_json_bytes(model) != state.model_bytes
        or canonical_json_bytes(artifact_model) != state.report_artifact_bytes
        or state.model_bytes != state.report_artifact_bytes
        or model != artifact_model
        or type(model.get("report_schema_version")) is not str
        or not model["report_schema_version"]
        or projection.get("binding_schema_version") != _BINDING_SCHEMA_VERSION
        or projection.get("report_schema_version") != model["report_schema_version"]
        or projection.get("report_model_sha256") != structured_sha256(_MODEL_DOMAIN, model)
        or projection.get("report_artifact_sha256")
        != exact_file_sha256(state.report_artifact_bytes)
        or projection.get("report_html_artifact_sha256")
        != exact_file_sha256(state.report_html_artifact_bytes)
        or type(digest) is not str
        or structured_sha256(_BINDING_DOMAIN, preimage) != digest
        or canonical_json_bytes(projection) != state.projection_bytes
    ):
        raise _binding_error()
    return cast(dict[str, Any], model), projection


def _validated_binding_projection(
    owner: AuthenticatedReportModelArtifactBinding,
) -> dict[str, object]:
    _model, projection = _validated_binding(owner)
    return projection


def _read_authenticated_report_model(
    owner: AuthenticatedReportModelArtifactBinding,
) -> dict[str, Any]:
    """Return a fresh exact model only after complete owner revalidation."""

    model, _projection = _validated_binding(owner)
    return model


def _build_binding_issuer() -> tuple[
    OneShotWeakRegistry[object, _BindingState],
    Callable[[dict[str, Any], bytes, bytes], AuthenticatedReportModelArtifactBinding],
]:
    states: OneShotWeakRegistry[object, _BindingState]
    issuer: OneShotRegistryIssuer[object, _BindingState]
    states, issuer = create_one_shot_registry()

    def issue(
        report_model: dict[str, Any],
        report_artifact_bytes: bytes,
        report_html_artifact_bytes: bytes,
        /,
    ) -> AuthenticatedReportModelArtifactBinding:
        if (
            type(report_model) is not dict
            or type(report_artifact_bytes) is not bytes
            or type(report_html_artifact_bytes) is not bytes
        ):
            raise _binding_error()
        model_bytes = canonical_json_bytes(report_model)
        if model_bytes != report_artifact_bytes:
            raise _binding_error()
        projection: dict[str, object] = {
            "binding_schema_version": _BINDING_SCHEMA_VERSION,
            "report_schema_version": report_model.get("report_schema_version"),
            "report_model_sha256": structured_sha256(_MODEL_DOMAIN, report_model),
            "report_artifact_sha256": exact_file_sha256(report_artifact_bytes),
            "report_html_artifact_sha256": exact_file_sha256(report_html_artifact_bytes),
            "binding_sha256": None,
        }
        projection["binding_sha256"] = structured_sha256(_BINDING_DOMAIN, projection)
        owner = object.__new__(AuthenticatedReportModelArtifactBinding)
        issuer.bind_once(
            owner,
            _BindingState(
                model_bytes=model_bytes,
                report_artifact_bytes=report_artifact_bytes,
                report_html_artifact_bytes=report_html_artifact_bytes,
                projection_bytes=canonical_json_bytes(projection),
            ),
        )
        _validated_binding_projection(owner)
        return owner

    return states, issue


(_BINDING_STATES, _issue_report_model_artifact_binding) = _build_binding_issuer()
del _build_binding_issuer
