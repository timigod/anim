"""Offline adapter project scaffolding and conformance receipts."""

from .conformance import build_conformance_receipt
from .scaffold import initialize_adapter_scaffold

__all__ = ["build_conformance_receipt", "initialize_adapter_scaffold"]
