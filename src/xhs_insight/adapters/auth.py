"""Encrypted single-account state committed only after verified Cookie import."""

from __future__ import annotations

import copy
import hashlib
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from xhs_insight.domain import AdapterErrorCode
from xhs_insight.security import CredentialCipher
from xhs_insight.storage import Repository

from .errors import AdapterError

_AUTH_AAD = "xhs-insight:auth-session:v1"
_MAX_COOKIE_BYTES = 16 * 1024
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True, slots=True)
class VerifiedLogin:
    """Validated credential material; secret fields are excluded from repr."""

    cookie: str = field(repr=False)
    account_id: str
    host_cookies: Mapping[str, Any] = field(default_factory=dict, repr=False)
    host_cookie_state: Mapping[str, Any] = field(default_factory=dict, repr=False)
    cookie_source_url: str = "https://edith.xiaohongshu.com"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _cookie_names(cookie: str) -> set[str]:
    names: set[str] = set()
    for part in cookie.split(";"):
        name, separator, _ = part.strip().partition("=")
        if separator and name:
            names.add(name)
    return names


def normalize_cookie_header(value: str) -> str:
    """Return one unambiguous Cookie header without reflecting its values.

    The public import boundary accepts a Cookie *value*, not arbitrary HTTP
    headers.  A single leading ``Cookie:`` label copied from DevTools is
    tolerated, but control characters, duplicate names and malformed pairs are
    rejected before any upstream request is attempted.
    """

    raw = str(value or "").strip()
    if not raw or len(raw.encode("utf-8")) > _MAX_COOKIE_BYTES:
        raise ValueError("Cookie 为空或超过 16 KiB 限制")
    if any(character in raw for character in ("\r", "\n", "\0")):
        raise ValueError("Cookie 包含不允许的控制字符")
    if raw[:7].casefold() == "cookie:":
        raw = raw[7:].strip()
    if not raw:
        raise ValueError("Cookie 为空")

    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for part in raw.split(";"):
        item = part.strip()
        if not item:
            continue
        name, separator, content = item.partition("=")
        name = name.strip()
        if not separator or not _COOKIE_NAME_RE.fullmatch(name):
            raise ValueError("Cookie 格式无效")
        if name in seen:
            raise ValueError("Cookie 含重复字段")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in content):
            raise ValueError("Cookie 包含不允许的控制字符")
        seen.add(name)
        pairs.append((name, content.strip()))
    if not pairs:
        raise ValueError("Cookie 为空")
    missing = {"a1", "web_session"} - seen
    if missing:
        raise ValueError("Cookie 缺少登录所需字段")
    return "; ".join(f"{name}={content}" for name, content in pairs)


class AuthManager:
    """Own the only decrypted Cookie copy and persist an AES-GCM envelope.

    There is deliberately no generic ``set_cookie`` API. Production callers
    may persist credentials only after the independent protocol adapter has verified
    ``user/me`` for the submitted Cookie.
    """

    def __init__(self, repository: Repository, cipher: CredentialCipher):
        self.repository = repository
        self.cipher = cipher
        self._payload: dict[str, Any] | None = None
        self._account_fingerprint: str | None = None
        self._load_error: str | None = None
        self._session_generation = 0
        self._lock = threading.RLock()
        self.reload()

    def reload(self) -> None:
        row = self.repository.load_auth()
        with self._lock:
            self._session_generation += 1
            self._payload = None
            self._account_fingerprint = None
            self._load_error = None
            if row is None:
                return
            try:
                payload = self.cipher.decrypt_json(row["payload_cipher"], aad=_AUTH_AAD)
                self._validate_payload(payload)
            except Exception as error:
                self._load_error = type(error).__name__
                return
            self._payload = dict(payload)
            self._account_fingerprint = str(row["account_fingerprint"])

    @staticmethod
    def _validate_payload(payload: Any) -> None:
        if not isinstance(payload, Mapping):
            raise ValueError("auth payload must be an object")
        cookie = str(payload.get("cookie") or "")
        missing = {"a1", "web_session"} - _cookie_names(cookie)
        if missing:
            raise ValueError("authenticated Cookie is incomplete")
        if not str(payload.get("account_id") or ""):
            raise ValueError("account id is missing")

    @property
    def authenticated(self) -> bool:
        with self._lock:
            return self._payload is not None

    @property
    def account_fingerprint(self) -> str | None:
        with self._lock:
            return self._account_fingerprint

    @property
    def session_generation(self) -> int:
        """Process-local cache key; changes even when the same account reconnects."""

        with self._lock:
            return self._session_generation

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "authenticated": self._payload is not None,
                "account_fingerprint": self._account_fingerprint,
                "connected_at": self._payload.get("connected_at") if self._payload else None,
                "credential_error": self._load_error,
            }

    def persist_verified_login(
        self,
        *,
        cookie: str,
        account_id: str,
        host_cookies: Mapping[str, Any] | None = None,
        host_cookie_state: Mapping[str, Any] | None = None,
        cookie_source_url: str = "https://edith.xiaohongshu.com",
    ) -> dict[str, Any]:
        account = str(account_id or "").strip()
        payload = {
            "cookie": normalize_cookie_header(cookie),
            "account_id": account,
            "host_cookies": copy.deepcopy(dict(host_cookies or {})),
            "host_cookie_state": copy.deepcopy(dict(host_cookie_state or {})),
            "cookie_source_url": str(cookie_source_url or "https://edith.xiaohongshu.com"),
            "connected_at": _utc_now(),
        }
        self._validate_payload(payload)
        fingerprint = hashlib.sha256(f"xhs-account:{account}".encode()).hexdigest()
        envelope = self.cipher.encrypt_json(payload, aad=_AUTH_AAD)
        self.repository.save_auth(envelope, fingerprint)
        with self._lock:
            self._payload = payload
            self._account_fingerprint = fingerprint
            self._load_error = None
            self._session_generation += 1
        return self.status()

    def require_payload(self) -> dict[str, Any]:
        with self._lock:
            if self._payload is None:
                raise AdapterError(AdapterErrorCode.AUTH_EXPIRED)
            return copy.deepcopy(self._payload)

    def clear(self) -> None:
        self.repository.delete_auth()
        with self._lock:
            self._payload = None
            self._account_fingerprint = None
            self._load_error = None
            self._session_generation += 1

    def logout(self) -> None:
        """Web/CLI vocabulary for clearing the encrypted local session."""

        self.clear()


__all__ = [
    "AuthManager",
    "VerifiedLogin",
    "normalize_cookie_header",
]
