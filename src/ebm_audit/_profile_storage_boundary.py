"""Runtime enforcement boundary for profile cache and checkpoint operations."""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Protocol


class _ProfileStorageOperationObserver(Protocol):
    def _observe(self, *, resource: str, operation: str) -> None: ...


_ACTIVE_PROFILE_STORAGE_OBSERVER: ContextVar[
    _ProfileStorageOperationObserver | None
] = ContextVar(
    "ebm_audit_active_profile_storage_observer",
    default=None,
)


def _activate_profile_storage_observer(
    observer: _ProfileStorageOperationObserver,
) -> Token[_ProfileStorageOperationObserver | None]:
    if _ACTIVE_PROFILE_STORAGE_OBSERVER.get() is not None:
        raise TypeError("A profile storage runtime boundary is already active.")
    return _ACTIVE_PROFILE_STORAGE_OBSERVER.set(observer)


def _deactivate_profile_storage_observer(
    token: Token[_ProfileStorageOperationObserver | None],
) -> None:
    _ACTIVE_PROFILE_STORAGE_OBSERVER.reset(token)


def _observe_profile_storage_operation(*, resource: str, operation: str) -> None:
    """Route a real cache/checkpoint operation through the active profile guard."""

    observer = _ACTIVE_PROFILE_STORAGE_OBSERVER.get()
    if observer is not None:
        observer._observe(resource=resource, operation=operation)


__all__: list[str] = []
