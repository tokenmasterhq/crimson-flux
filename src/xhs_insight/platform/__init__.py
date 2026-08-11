"""Independent, fixed-surface platform protocol."""

from .client import (
    API_ORIGIN,
    EXPECTED_SIGNER_VERSION,
    SEARCH_ORIGIN,
    WEB_ORIGIN,
    CookieView,
    FailureKind,
    HttpxJsonTransport,
    JsonTransport,
    RedNoteClient,
    RedNoteProtocolError,
    RequestSigner,
    TransportResponse,
    XhshowSigner,
)
from .doctor import RuntimeDoctorReport, runtime_doctor

__all__ = [
    "API_ORIGIN",
    "EXPECTED_SIGNER_VERSION",
    "WEB_ORIGIN",
    "CookieView",
    "FailureKind",
    "HttpxJsonTransport",
    "JsonTransport",
    "RedNoteClient",
    "RedNoteProtocolError",
    "RequestSigner",
    "SEARCH_ORIGIN",
    "RuntimeDoctorReport",
    "TransportResponse",
    "XhshowSigner",
    "runtime_doctor",
]
