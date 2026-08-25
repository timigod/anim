"""Lazy development-only exports; backend modules must not load each other."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_KDE_EXPORTS = frozenset(
    {
        "preflight_kde_profile_development",
        "run_kde_profile_development",
        "run_kde_profile_development_qualification",
        "verify_kde_profile_development_evidence",
    }
)
_PYSAEBM_EXPORTS = frozenset(
    {
        "accept_pysaebm_observable_profile",
        "preflight_pysaebm_observable_profile",
        "run_pysaebm_observable_profile",
    }
)


def __getattr__(name: str) -> Any:
    if name in _KDE_EXPORTS:
        return getattr(import_module(".kde_profile", __name__), name)
    if name in _PYSAEBM_EXPORTS:
        return getattr(import_module(".pysaebm_observable_profile", __name__), name)
    raise AttributeError(name)


__all__ = sorted(_KDE_EXPORTS | _PYSAEBM_EXPORTS)
