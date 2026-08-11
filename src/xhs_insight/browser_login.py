"""In-memory, pure-HTTP QR login orchestration for CrimsonFlux.

The protocol transport and request signing live in :mod:`xhs_insight.platform`.
This module owns only the user-facing login state machine and local QR image.
It never starts a browser, executes remote code, or persists an unverified
credential.
"""

from __future__ import annotations

import hashlib
import io
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

COOKIE_SOURCE_URL = "https://edith.xiaohongshu.com/api/sns/web/v2/user/me"
DEFAULT_LOGIN_TIMEOUT_SECONDS = 180
DEFAULT_POLL_SECONDS = 2.0
_ACTIVE_STATUSES = frozenset({"starting", "awaiting_scan", "verifying"})
_QR_WAITING = 0
_QR_SCANNED = 1
_QR_CONFIRMED = 2
_QR_EXPIRED = 3


class BrowserLoginError(RuntimeError):
    """Credential-free failure safe to expose through the local API."""

    def __init__(self, code: str, public_message: str):
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


class _Cancelled(Exception):
    pass


class _Expired(Exception):
    pass


def _iso_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat(timespec="seconds")


def _validate_qr_value(value: Any) -> str:
    text = value if isinstance(value, str) else ""
    if not 1 <= len(text) <= 4096 or any(ord(character) < 32 for character in text):
        raise BrowserLoginError("QR_RESPONSE_INVALID", "平台返回的二维码内容无效。")
    try:
        parsed = urlsplit(text)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == "www.xiaohongshu.com"
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        valid = False
    if not valid:
        raise BrowserLoginError("QR_RESPONSE_INVALID", "平台返回的二维码内容无效。")
    return text


def _opaque(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise BrowserLoginError("QR_RESPONSE_INVALID", f"平台返回的{label}格式无效。")
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        raise BrowserLoginError("QR_RESPONSE_INVALID", f"平台返回的{label}格式无效。")
    return value


def _render_qr_png(value: str) -> bytes:
    """Render the server-issued value locally without exposing the value."""

    try:
        import qrcode  # type: ignore[import-untyped]

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        qr.add_data(_validate_qr_value(value))
        qr.make(fit=True)
        output = io.BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(output, format="PNG")
        image = output.getvalue()
    except BrowserLoginError:
        raise
    except Exception as error:
        raise BrowserLoginError(
            "QR_RENDER_UNAVAILABLE", "本地二维码生成组件不可用。"
        ) from error
    if not image.startswith(b"\x89PNG\r\n\x1a\n") or len(image) > 1_000_000:
        raise BrowserLoginError("QR_IMAGE_INVALID", "本地生成的二维码图片无效。")
    return image


def _mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BrowserLoginError("UPSTREAM_SCHEMA_CHANGED", f"{label}返回结构已变化。")
    return value


def _first(data: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return None


def _status_code(data: Mapping[str, Any]) -> int:
    value = _first(data, "codeStatus", "code_status")
    if type(value) is not int or value not in {_QR_WAITING, _QR_SCANNED, _QR_CONFIRMED, _QR_EXPIRED}:
        raise BrowserLoginError("UPSTREAM_SCHEMA_CHANGED", "扫码状态返回结构已变化。")
    return value


class DirectQrClient:
    """Compatibility facade over CrimsonFlux's independent protocol client."""

    def __init__(self) -> None:
        from xhs_insight.platform.client import RedNoteClient

        self._client = RedNoteClient.visitor()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def close(self) -> None:
        self._client.close()


@dataclass(slots=True)
class _LoginSession:
    internal_id: str = field(repr=False)
    created_at: float
    deadline: float
    expires_at: str
    status: str = "starting"
    message: str = "正在生成官方登录二维码…"
    error_code: str | None = None
    qr_png: bytes | None = field(default=None, repr=False)
    qr_revision: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    thread: threading.Thread | None = field(default=None, repr=False)
    client: Any | None = field(default=None, repr=False)


class DirectQrLoginManager:
    """Run at most one QR login and expose only its public progress."""

    def __init__(
        self,
        state_dir: Path,
        import_cookie: Callable[[str, Callable[[], bool]], dict[str, Any]],
        active_jobs: Callable[[], bool],
        *,
        timeout_seconds: int = DEFAULT_LOGIN_TIMEOUT_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        del state_dir
        self._import_cookie = import_cookie
        self._active_jobs = active_jobs
        self._timeout_seconds = max(30, min(int(timeout_seconds), 300))
        self._poll_seconds = max(0.1, min(float(poll_seconds), 5.0))
        self._client_factory = client_factory or DirectQrClient
        self._lock = threading.RLock()
        self._session: _LoginSession | None = None

    def capability(self) -> dict[str, Any]:
        return {
            "browser_login_supported": True,
            "browser_login_mode": "official_direct_qr",
            "browser_login_embedded_qr": True,
            "browser_name": None,
            "browser_major_version": None,
            "browser_login_timeout_seconds": self._timeout_seconds,
            "browser_login_reason": None,
        }

    def _public(self, session: _LoginSession | None = None) -> dict[str, Any]:
        current = session or self._session
        capability = self.capability()
        if current is None:
            return {
                **capability,
                "status": "idle",
                "message": "尚未启动扫码登录。",
                "qr_ready": False,
                "qr_revision": None,
                "qr_url": None,
            }
        ready = current.status == "awaiting_scan" and current.qr_png is not None
        return {
            **capability,
            "status": current.status,
            "message": current.message,
            "expires_at": current.expires_at,
            "error_code": current.error_code,
            "authenticated": current.status == "succeeded",
            "qr_ready": ready,
            "qr_revision": current.qr_revision if ready else None,
            "qr_url": "/api/v1/auth/browser/qr" if ready else None,
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self._public()

    def qr_image(self) -> tuple[bytes, str]:
        with self._lock:
            current = self._session
            if (
                current is None
                or current.status != "awaiting_scan"
                or current.qr_png is None
                or current.qr_revision is None
            ):
                raise BrowserLoginError(
                    "QR_NOT_READY", "二维码尚未生成、已过期或登录已结束，请重新开始。"
                )
            return bytes(current.qr_png), current.qr_revision

    def _set_status(
        self,
        session: _LoginSession,
        status: str,
        message: str,
        error_code: str | None = None,
    ) -> None:
        with self._lock:
            if self._session is session:
                session.status = status
                session.message = message
                session.error_code = error_code

    def _publish_qr(self, session: _LoginSession, image: bytes) -> None:
        with self._lock:
            if self._session is not session or session.cancel_event.is_set():
                raise _Cancelled
            session.qr_png = bytes(image)
            session.qr_revision = hashlib.sha256(image).hexdigest()[:16]

    def _clear_qr(self, session: _LoginSession) -> None:
        with self._lock:
            session.qr_png = None
            session.qr_revision = None

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._active_jobs():
                raise PermissionError("请先取消或暂停正在运行、排队的任务，再更换登录态")
            if self._session is not None and self._session.status in _ACTIVE_STATUSES:
                raise PermissionError("已有扫码登录正在等待，请先完成或取消")
            now = time.time()
            session = _LoginSession(
                internal_id=secrets.token_urlsafe(24),
                created_at=now,
                deadline=time.monotonic() + self._timeout_seconds,
                expires_at=_iso_timestamp(now + self._timeout_seconds),
            )
            session.thread = threading.Thread(
                target=self._run,
                args=(session,),
                name="crimsonflux-qr-login",
                daemon=True,
            )
            self._session = session
            session.thread.start()
            return self._public(session)

    def cancel(self) -> dict[str, Any]:
        with self._lock:
            current = self._session
            if current is None:
                return self._public()
            if current.status in _ACTIVE_STATUSES:
                current.cancel_event.set()
                self._clear_qr(current)
                current.message = "正在取消扫码登录…"
                return self._public(current)
            self._session = None
            return self._public()

    def close(self) -> None:
        with self._lock:
            current = self._session
            if current is None:
                return
            current.cancel_event.set()
            thread = current.thread
            client = current.client
        if thread is not None and thread.is_alive():
            thread.join(timeout=35)
        if thread is not None and thread.is_alive() and client is not None:
            with suppress(Exception):
                client.close()

    def _run(self, session: _LoginSession) -> None:
        terminal: tuple[str, str, str | None] | None = None
        client: Any | None = None
        cookie_text = ""
        qr_id = ""
        qr_code = ""
        try:
            if session.cancel_event.is_set():
                raise _Cancelled
            client = self._client_factory()
            session.client = client
            _mapping(client.login_activate(), label="访客会话")
            created = _mapping(client.create_qr(), label="二维码")
            qr_id = _opaque(_first(created, "qr_id", "qrId"), "二维码 ID")
            qr_code = _opaque(created.get("code"), "二维码校验码")
            qr_value = _validate_qr_value(_first(created, "url", "qr_url"))
            image = _render_qr_png(qr_value)
            qr_value = ""
            self._publish_qr(session, image)
            image = b""
            self._set_status(
                session,
                "awaiting_scan",
                "请使用小红书 App 扫描二维码，并在手机上确认登录。",
            )

            while True:
                if time.monotonic() >= session.deadline:
                    raise _Expired
                if session.cancel_event.wait(self._poll_seconds):
                    raise _Cancelled
                poll = _mapping(client.poll_qr(qr_id, qr_code), label="扫码状态")
                status = _status_code(poll)
                if status == _QR_WAITING:
                    self._set_status(session, "awaiting_scan", "等待扫描二维码…")
                    continue
                if status == _QR_SCANNED:
                    self._set_status(session, "awaiting_scan", "已扫码，请在手机上确认登录。")
                    continue
                if status == _QR_EXPIRED:
                    raise _Expired
                break

            self._clear_qr(session)
            self._set_status(session, "verifying", "扫码已确认，正在验证正式登录状态…")
            _mapping(client.complete_qr(qr_id, qr_code), label="正式登录")
            identity = _mapping(client.get_user_me(), label="账号验证")
            if identity.get("guest") is not False or not str(identity.get("user_id") or "").strip():
                raise BrowserLoginError("AUTH_VERIFY_FAILED", "扫码登录态未通过账号验证。")
            cookie_text = str(client.cookie_header())
            client.close()
            session.client = None
            client = None
            qr_id = ""
            qr_code = ""
            if session.cancel_event.is_set():
                raise _Cancelled
            result = self._import_cookie(cookie_text, session.cancel_event.is_set)
            if not isinstance(result, Mapping) or result.get("authenticated") is not True:
                raise BrowserLoginError("AUTH_VERIFY_FAILED", "扫码登录态未通过账号验证。")
            terminal = ("succeeded", "扫码登录成功，登录态已加密保存在本机。", None)
        except _Cancelled:
            terminal = ("cancelled", "已取消扫码登录。", None)
        except _Expired:
            terminal = ("expired", "二维码登录已超时或过期，请重新开始。", "LOGIN_EXPIRED")
        except PermissionError:
            terminal = (
                "failed",
                "验证期间已有任务开始运行，扫码登录态未保存。",
                "CREDENTIAL_CHANGE_CONFLICT",
            )
        except BrowserLoginError as error:
            terminal = ("failed", error.public_message, error.code)
        except Exception as error:
            protocol_kind = str(getattr(getattr(error, "kind", None), "value", ""))
            raw_code = getattr(getattr(error, "code", None), "value", None) or getattr(
                error, "code", None
            )
            kind_codes = {
                "auth": "AUTH_EXPIRED",
                "rate_limit": "RATE_LIMITED",
                "risk_control": "RISK_CONTROLLED",
                "network": "NETWORK_ERROR",
                "schema": "UPSTREAM_SCHEMA_CHANGED",
                "signer": "SIGNER_FAILED",
                "unsupported": "UPSTREAM_UNSUPPORTED",
            }
            code = str(raw_code or kind_codes.get(protocol_kind) or "DIRECT_QR_FAILED")
            messages = {
                "AUTH_EXPIRED": "扫码登录态未通过账号验证，请重新扫码。",
                "RATE_LIMITED": "平台暂时限制了登录请求，请稍后重试。",
                "RISK_CONTROLLED": "平台拒绝了登录请求，请稍后重试。",
                "NETWORK_ERROR": "登录网络请求失败，请检查连接后重试。",
                "SIGNER_FAILED": "本地签名组件不可用。",
                "UPSTREAM_SCHEMA_CHANGED": "登录接口返回结构已变化。",
            }
            terminal = ("failed", messages.get(code, "二维码登录失败，请稍后重试。"), code)
        finally:
            cookie_text = ""
            qr_id = ""
            qr_code = ""
            self._clear_qr(session)
            if client is not None:
                with suppress(Exception):
                    client.close()
            session.client = None
            if terminal is None:
                terminal = ("failed", "二维码登录未完成。", "DIRECT_QR_FAILED")
            self._set_status(session, terminal[0], terminal[1], terminal[2])


BrowserLoginManager = DirectQrLoginManager

__all__ = [
    "BrowserLoginError",
    "BrowserLoginManager",
    "COOKIE_SOURCE_URL",
    "DirectQrClient",
    "DirectQrLoginManager",
]
