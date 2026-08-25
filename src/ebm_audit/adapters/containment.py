"""OS-backed worker containment plans.

The environment's offline flags are advisory. A participant-data worker is
launched only through a provider that denies network access and limits writes
to its invocation root. Python workers additionally use the attempt sentinel
installed by the worker bootstrap so a caught network denial is still visible.
"""

from __future__ import annotations

import hashlib
import platform
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ContainmentProvider = Literal["macos-seatbelt", "linux-bubblewrap"]


@dataclass(frozen=True, slots=True)
class ContainmentPlan:
    argv: tuple[str, ...]
    provider: ContainmentProvider
    launcher_sha256: str
    network_denied: bool = True
    writes_scoped_to_invocation: bool = True
    child_processes_contained: bool = True


@dataclass(frozen=True, slots=True)
class _InheritedOuterContainmentCapability:
    """Attempt-bound proof that the current process already owns containment."""

    attempt_id: str
    launcher_sha256: str
    profile_sha256: str
    command_sha256: str
    active_denial_probe_sha256: str


_ACTIVE_OUTER_CONTAINMENT: ContextVar[
    _InheritedOuterContainmentCapability | None
] = ContextVar("ebm_audit_active_outer_containment", default=None)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _issue_inherited_outer_containment_capability(
    *,
    attempt_id: str,
    launcher_sha256: str,
    profile_sha256: str,
    command_sha256: str,
    active_denial_probe_sha256: str,
) -> _InheritedOuterContainmentCapability:
    if (
        not attempt_id
        or any(
            not _is_sha256(value)
            for value in (
                launcher_sha256,
                profile_sha256,
                command_sha256,
                active_denial_probe_sha256,
            )
        )
    ):
        raise ValueError("The inherited outer-containment capability is invalid.")
    return _InheritedOuterContainmentCapability(
        attempt_id=attempt_id,
        launcher_sha256=launcher_sha256,
        profile_sha256=profile_sha256,
        command_sha256=command_sha256,
        active_denial_probe_sha256=active_denial_probe_sha256,
    )


@contextmanager
def _use_inherited_outer_containment(
    capability: _InheritedOuterContainmentCapability,
) -> Iterator[None]:
    if type(capability) is not _InheritedOuterContainmentCapability:
        raise TypeError("An authenticated outer-containment capability is required.")
    if _ACTIVE_OUTER_CONTAINMENT.get() is not None:
        raise RuntimeError("Outer containment is already active.")
    token: Token[_InheritedOuterContainmentCapability | None] = (
        _ACTIVE_OUTER_CONTAINMENT.set(capability)
    )
    try:
        yield
    finally:
        _ACTIVE_OUTER_CONTAINMENT.reset(token)


def _inherited_outer_containment_projection() -> dict[str, str] | None:
    capability = _ACTIVE_OUTER_CONTAINMENT.get()
    if capability is None:
        return None
    return {
        "attempt_id": capability.attempt_id,
        "provider": "macos-seatbelt",
        "launcher_sha256": capability.launcher_sha256,
        "profile_sha256": capability.profile_sha256,
        "command_sha256": capability.command_sha256,
        "active_denial_probe_sha256": capability.active_denial_probe_sha256,
        "child_process_inheritance": "REQUIRED",
    }


def _launcher_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _seatbelt_literal(path: Path) -> str:
    value = str(path.resolve())
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("Containment path contains a forbidden character.")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _macos_plan(
    argv: tuple[str, ...],
    *,
    invocation_root: Path,
    request_dir: Path,
) -> ContainmentPlan | None:
    executable = Path("/usr/bin/sandbox-exec")
    if not executable.is_file():
        return None
    root = _seatbelt_literal(invocation_root)
    request = _seatbelt_literal(request_dir)
    profile = " ".join(
        (
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            "(deny process-fork)",
            f'(deny file-write* (require-not (subpath "{root}")))',
            f'(deny file-write* (subpath "{request}"))',
        )
    )
    return ContainmentPlan(
        argv=(str(executable), "-p", profile, *argv),
        provider="macos-seatbelt",
        launcher_sha256=_launcher_sha256(executable),
    )


def _linux_plan(
    argv: tuple[str, ...],
    *,
    invocation_root: Path,
    request_dir: Path,
    work_dir: Path,
) -> ContainmentPlan | None:
    executable = Path("/usr/bin/bwrap")
    if not executable.is_file():
        return None
    root = str(invocation_root.resolve())
    request = str(request_dir.resolve())
    work = str(work_dir.resolve())
    return ContainmentPlan(
        argv=(
            str(executable),
            "--die-with-parent",
            "--new-session",
            "--unshare-net",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            root,
            root,
            "--ro-bind",
            request,
            request,
            "--chdir",
            work,
            "--",
            *argv,
        ),
        provider="linux-bubblewrap",
        launcher_sha256=_launcher_sha256(executable),
    )


def build_containment_plan(
    argv: tuple[str, ...] | list[str],
    *,
    invocation_root: Path,
    request_dir: Path,
    work_dir: Path,
) -> ContainmentPlan | None:
    """Return the supported fail-closed OS plan, or ``None`` when unavailable."""

    command = tuple(argv)
    if not command:
        raise ValueError("Containment requires a non-empty command.")
    inherited = _ACTIVE_OUTER_CONTAINMENT.get()
    if inherited is not None:
        if platform.system() != "Darwin":
            raise ValueError("Inherited outer containment is supported only on macOS.")
        return ContainmentPlan(
            argv=command,
            provider="macos-seatbelt",
            launcher_sha256=inherited.launcher_sha256,
        )
    system = platform.system()
    if system == "Darwin":
        return _macos_plan(
            command,
            invocation_root=invocation_root,
            request_dir=request_dir,
        )
    if system == "Linux":
        return _linux_plan(
            command,
            invocation_root=invocation_root,
            request_dir=request_dir,
            work_dir=work_dir,
        )
    return None


__all__ = ["ContainmentPlan", "build_containment_plan"]
