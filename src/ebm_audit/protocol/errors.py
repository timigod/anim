"""Privacy-safe protocol exceptions."""

from __future__ import annotations


class ProtocolError(RuntimeError):
    """Base class carrying only a stable code and safe message."""

    code = "PROTOCOL.ERROR"

    def __init__(self, safe_message: str) -> None:
        self.safe_message = safe_message
        super().__init__(f"{self.code}: {safe_message}")


class CanonicalizationError(ProtocolError):
    code = "PROTOCOL.CANONICALIZATION_INVALID"


class PathBoundaryError(ProtocolError):
    code = "PROTOCOL.PATH_BOUNDARY_INVALID"


class BundleValidationError(ProtocolError):
    code = "PROTOCOL.BUNDLE_INVALID"


class FramingError(ProtocolError):
    code = "PROTOCOL.FRAMING_INVALID"

