"""Stable adapter boundary for CrimsonFlux's independent protocol client."""

from .auth import AuthManager, VerifiedLogin, normalize_cookie_header
from .base import AuthState, Cursor, XHSAdapter
from .errors import AdapterError, classify_upstream_error
from .rednote import RednoteAdapter

__all__ = [
    "AdapterError",
    "AuthManager",
    "AuthState",
    "Cursor",
    "RednoteAdapter",
    "VerifiedLogin",
    "XHSAdapter",
    "classify_upstream_error",
    "normalize_cookie_header",
]
