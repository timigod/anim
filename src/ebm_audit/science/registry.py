"""Structural ownership registry for the non-poolable science-v2 evidence lanes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal


class UncertaintyLayer(StrEnum):
    """Six scientifically distinct replication/variation owners."""

    WITHIN_FIT = "WITHIN_FIT"
    CHAIN = "CHAIN"
    SAMPLING = "SAMPLING"
    ANALYST_DECISION = "ANALYST_DECISION"
    PARTICIPANT_INFLUENCE = "PARTICIPANT_INFLUENCE"
    NULL = "NULL"


class ReportEvidenceDomain(StrEnum):
    """Seven display domains; participant stage is not an uncertainty layer."""

    WITHIN_FIT = "WITHIN_FIT"
    CHAIN = "CHAIN"
    SAMPLING = "SAMPLING"
    ANALYST_DECISION = "ANALYST_DECISION"
    PARTICIPANT_INFLUENCE = "PARTICIPANT_INFLUENCE"
    NULL = "NULL"
    PARTICIPANT_STAGE = "PARTICIPANT_STAGE"


@dataclass(frozen=True, slots=True)
class UncertaintyLayerContract:
    """Ownership-only contract; quantitative rules remain deliberately absent."""

    layer: UncertaintyLayer
    pooling_policy: Literal["NON_POOLABLE"] = "NON_POOLABLE"


@dataclass(frozen=True, slots=True)
class ReportEvidenceDomainContract:
    """Bind a report domain to its originating uncertainty-layer rule."""

    domain: ReportEvidenceDomain
    fixed_originating_layer: UncertaintyLayer | None
    requires_originating_layer: bool
    allowed_originating_layers: frozenset[UncertaintyLayer]


_UNCERTAINTY_LAYER_ORDER: Final = tuple(UncertaintyLayer)
_REPORT_EVIDENCE_DOMAIN_ORDER: Final = tuple(ReportEvidenceDomain)

UNCERTAINTY_LAYER_REGISTRY: Final = MappingProxyType(
    {
        layer: UncertaintyLayerContract(layer=layer)
        for layer in _UNCERTAINTY_LAYER_ORDER
    }
)

REPORT_EVIDENCE_DOMAIN_REGISTRY: Final = MappingProxyType(
    {
        **{
            ReportEvidenceDomain(layer.value): ReportEvidenceDomainContract(
                domain=ReportEvidenceDomain(layer.value),
                fixed_originating_layer=layer,
                requires_originating_layer=False,
                allowed_originating_layers=frozenset((layer,)),
            )
            for layer in _UNCERTAINTY_LAYER_ORDER
        },
        ReportEvidenceDomain.PARTICIPANT_STAGE: ReportEvidenceDomainContract(
            domain=ReportEvidenceDomain.PARTICIPANT_STAGE,
            fixed_originating_layer=None,
            requires_originating_layer=True,
            allowed_originating_layers=frozenset(_UNCERTAINTY_LAYER_ORDER),
        ),
    }
)


__all__ = [
    "REPORT_EVIDENCE_DOMAIN_REGISTRY",
    "UNCERTAINTY_LAYER_REGISTRY",
    "ReportEvidenceDomain",
    "ReportEvidenceDomainContract",
    "UncertaintyLayer",
    "UncertaintyLayerContract",
]
