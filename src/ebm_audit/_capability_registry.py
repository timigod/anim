"""One-shot identity bindings for fresh, unpublished capabilities.

Each capability may be bound to exactly one state for its lifetime.  Keys are
compared by object identity, not by ``__eq__``.  Issuance must follow one
monotonic sequence: create fresh private capabilities, bind each once, validate
the complete bound graph, and only then publish the single externally reachable
parent.  Nothing rolls back after publication.

Weak key references do not expose cleanup callbacks.  Instead, every registry
operation sweeps dead keys while holding the registry lock.  An idle registry
may retain state whose keys died since its last interaction, but the next
completed operation removes it, so abandoned attempts cannot accumulate without
bound.  Cleanup still requires that no strong state-to-capability cycle exists
anywhere in the complete graph, including transitive, cross-key, and
cross-registry paths.  Callers must prove that invariant for every migrated
graph; Python does not provide ephemeron semantics that could collect such a
cycle.
"""

from __future__ import annotations

from threading import RLock
from typing import Never, final
from weakref import ReferenceType, ref

_MISSING = object()


class OneShotRegistryError(TypeError):
    """Raised when an opaque capability binding is absent or already consumed."""


@final
class CallbackFreeWeakIdentityMap[K, V]:
    """Retain one live weak value per live identity key without callbacks.

    Unlike ``WeakValueDictionary``, neither weak reference has a callback that
    untrusted holders can retrieve and invoke.  Dead pairs are removed lazily
    under the supplied reentrant lock.  Once a value dies, the same still-live
    key may bind one new value; while a value is live, replacement is rejected.
    """

    __slots__ = ("__entries", "__lock")

    def __init__(self, lock: RLock | None = None) -> None:
        self.__entries: dict[int, tuple[ReferenceType[K], ReferenceType[V]]] = {}
        self.__lock = RLock() if lock is None else lock

    def _sweep_dead_locked(self) -> None:
        for key_id, entry in tuple(self.__entries.items()):
            if (entry[0]() is None or entry[1]() is None) and self.__entries.get(
                key_id
            ) is entry:
                self.__entries.pop(key_id, None)

    def _entry_locked(self, key: object) -> tuple[ReferenceType[K], ReferenceType[V]] | None:
        entry = self.__entries.get(id(key))
        if entry is None:
            return None
        bound_key = entry[0]()
        if bound_key is key:
            return entry
        if bound_key is None:
            if self.__entries.get(id(key)) is entry:
                self.__entries.pop(id(key), None)
            return None
        raise TypeError("Weak identity map detected an id collision.")

    def get(self, key: object) -> V | None:
        with self.__lock:
            self._sweep_dead_locked()
            entry = self._entry_locked(key)
            if entry is None:
                return None
            value = entry[1]()
            if value is None:
                if self.__entries.get(id(key)) is entry:
                    self.__entries.pop(id(key), None)
                return None
            return value

    def bind_once(self, key: K, value: V) -> None:
        with self.__lock:
            self._sweep_dead_locked()
            if self._entry_locked(key) is not None:
                raise TypeError("A live value is already bound to this identity key.")
            try:
                key_reference = ref(key)
                value_reference = ref(value)
            except TypeError:
                raise TypeError("Weak identity map entries must be weak-referenceable.") from None
            self.__entries[id(key)] = (key_reference, value_reference)

    def active_count(self) -> int:
        with self.__lock:
            self._sweep_dead_locked()
            return len(self.__entries)

    def __len__(self) -> int:
        return self.active_count()


class _OneShotRegistryCore[K, S]:
    """Closure-private mutable core shared by one reader and one issuer."""

    __slots__ = ("_issuer_token", "_lock", "_states")

    def __init__(self) -> None:
        self._states: dict[int, tuple[ReferenceType[K], S]] = {}
        self._lock = RLock()
        self._issuer_token = object()

    def _require_issuer(self, token: object) -> None:
        if token is not self._issuer_token:
            raise OneShotRegistryError("Capability state has no valid one-shot issuer.")

    def _entry_locked(self, capability: object) -> tuple[ReferenceType[K], S] | None:
        key_id = id(capability)
        entry = self._states.get(key_id)
        if entry is None:
            return None
        bound_capability = entry[0]()
        if bound_capability is capability:
            return entry
        if bound_capability is None:
            if self._states.get(key_id) is entry:
                self._states.pop(key_id, None)
            return None
        raise OneShotRegistryError("Capability identity registry detected an id collision.")

    def _sweep_dead_locked(self) -> None:
        for key_id, entry in tuple(self._states.items()):
            if entry[0]() is None and self._states.get(key_id) is entry:
                self._states.pop(key_id, None)

    def bind_once(self, capability: K, state: S, token: object) -> None:
        with self._lock:
            self._require_issuer(token)
            self._sweep_dead_locked()
            if self._entry_locked(capability) is not None:
                raise OneShotRegistryError("Capability state is already bound.")

            try:
                key_reference = ref(capability)
            except TypeError:
                raise OneShotRegistryError("Capability keys must be weak-referenceable.") from None
            self._states[id(capability)] = (key_reference, state)

    def read(self, capability: object) -> S:
        with self._lock:
            self._sweep_dead_locked()
            entry = self._entry_locked(capability)
            if entry is None:
                raise OneShotRegistryError("No state is bound to this capability.")
            return entry[1]

    def get[T](self, capability: object, default: T | None = None) -> S | T | None:
        with self._lock:
            self._sweep_dead_locked()
            entry = self._entry_locked(capability)
            if entry is None:
                return default
            return entry[1]

    def require(self, capability: object, expected_state: object) -> S:
        state = self.read(capability)
        if state is not expected_state:
            raise OneShotRegistryError("Capability state does not match its exact binding.")
        return state

    def active_count(self) -> int:
        with self._lock:
            self._sweep_dead_locked()
            return len(self._states)


@final
class OneShotWeakRegistry[K, S]:
    """Read-only view of one weak, immutable capability-state registry."""

    __slots__ = ("__core",)
    __core: _OneShotRegistryCore[K, S]

    def __init__(self, core: _OneShotRegistryCore[K, S]) -> None:
        object.__setattr__(self, "_OneShotWeakRegistry__core", core)

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise TypeError("One-shot registry views are immutable.")

    def read(self, capability: object) -> S:
        return self.__core.read(capability)

    def get[T](self, capability: object, default: T | None = None) -> S | T | None:
        return self.__core.get(capability, default)

    def require(self, capability: object, expected_state: object) -> S:
        return self.__core.require(capability, expected_state)

    def __getitem__(self, capability: object) -> S:
        return self.read(capability)

    def __contains__(self, capability: object) -> bool:
        return self.get(capability, _MISSING) is not _MISSING

    def __len__(self) -> int:
        return self.__core.active_count()

    def __copy__(self) -> Never:
        raise TypeError("One-shot registry views cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("One-shot registry views cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("One-shot registry views cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("One-shot registry views cannot be copied or serialized.")


@final
class OneShotRegistryIssuer[K, S]:
    """Private one-shot issuer paired with one read-only registry view."""

    __slots__ = ("__core", "__token")
    __core: _OneShotRegistryCore[K, S]
    __token: object

    def __init__(self, core: _OneShotRegistryCore[K, S]) -> None:
        object.__setattr__(self, "_OneShotRegistryIssuer__core", core)
        object.__setattr__(self, "_OneShotRegistryIssuer__token", core._issuer_token)

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise TypeError("One-shot registry issuers are immutable.")

    def bind_once(self, capability: K, state: S) -> None:
        self.__core.bind_once(capability, state, self.__token)

    def __copy__(self) -> Never:
        raise TypeError("One-shot registry issuers cannot be copied or serialized.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("One-shot registry issuers cannot be copied or serialized.")

    def __reduce__(self) -> Never:
        raise TypeError("One-shot registry issuers cannot be copied or serialized.")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("One-shot registry issuers cannot be copied or serialized.")


def create_one_shot_registry[K, S]() -> tuple[
    OneShotWeakRegistry[K, S], OneShotRegistryIssuer[K, S]
]:
    """Create one read-only registry view and its sole private issuer."""

    core: _OneShotRegistryCore[K, S] = _OneShotRegistryCore()
    return OneShotWeakRegistry(core), OneShotRegistryIssuer(core)


__all__ = [
    "CallbackFreeWeakIdentityMap",
    "OneShotRegistryError",
    "OneShotRegistryIssuer",
    "OneShotWeakRegistry",
    "create_one_shot_registry",
]
