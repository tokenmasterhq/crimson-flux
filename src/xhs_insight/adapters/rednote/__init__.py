"""Independent pure-HTTP adapter."""

from xhs_insight.platform import EXPECTED_SIGNER_VERSION, runtime_doctor

from .live import RednoteAdapter

__all__ = ["EXPECTED_SIGNER_VERSION", "RednoteAdapter", "runtime_doctor"]
