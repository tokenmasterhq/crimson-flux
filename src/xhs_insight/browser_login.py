"""Visible, isolated official-browser login with verified Cookie import.

Only a fixed official page is opened.  The browser uses a disposable profile
and a loopback-only DevTools endpoint; it never attaches to the user's normal
browser profile.  Cookie material is read only for the fixed ``user/me`` URL,
passed directly to the existing account-verification boundary, and never
returned by the local API or written to logs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from xhs_insight.domain import AdapterErrorCode

OFFICIAL_LOGIN_URL = "https://www.xiaohongshu.com/explore"
COOKIE_SOURCE_URL = "https://edith.xiaohongshu.com/api/sns/web/v2/user/me"
DEFAULT_LOGIN_TIMEOUT_SECONDS = 300
DEFAULT_POLL_SECONDS = 1.5
_VERIFY_RETRY_SECONDS = 5.0
_ACTIVE_STATUSES = frozenset({"starting", "awaiting_login", "verifying"})
_PUBLIC_ERROR_CODES = frozenset(
    {
        "AUTH_EXPIRED",
        "AUTH_VERIFY_FAILED",
        "BROWSER_CLOSED",
        "BROWSER_CONTROL_FAILED",
        "BROWSER_LAUNCH_FAILED",
        "BROWSER_NOT_FOUND",
        "BROWSER_PROFILE_CLEANUP_FAILED",
        "CREDENTIAL_CHANGE_CONFLICT",
        "LOGIN_EXPIRED",
        "NETWORK_ERROR",
        "QR_NOT_READY",
        "RATE_LIMITED",
        "RISK_CONTROLLED",
        "SIGNER_FAILED",
        "UPSTREAM_SCHEMA_CHANGED",
        "UPSTREAM_UNSUPPORTED",
    }
)
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_DEVTOOLS_PATH_RE = re.compile(r"^/devtools/browser/[0-9A-Za-z._-]{8,128}$")
_MAX_CDP_MESSAGE_BYTES = 2 * 1024 * 1024
_MAX_CDP_CALL_BYTES = 8 * 1024 * 1024
_MAX_CDP_MESSAGES_PER_CALL = 256
_MAX_COOKIE_BYTES = 16 * 1024
_MAX_COOKIE_COUNT = 64

# These are the account/session and request-context cookies used by the fixed
# local collector.  Analytics, preference and unrelated site cookies are not
# copied out of the disposable browser profile.
_COOKIE_ALLOWLIST = frozenset(
    {
        "a1",
        "abRequestId",
        "acw_tc",
        "gid",
        "sec_poison_id",
        "webBuild",
        "webId",
        "web_session",
        "websectiga",
        "xsecappid",
    }
)


class BrowserLoginError(RuntimeError):
    """Credential-free failure safe to expose through the local API."""

    def __init__(self, code: str, public_message: str):
        super().__init__(public_message)
        self.code = code if code in _PUBLIC_ERROR_CODES else "BROWSER_CONTROL_FAILED"
        self.public_message = public_message


class _Cancelled(Exception):
    pass


class _Expired(Exception):
    pass


def _iso_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat(timespec="seconds")


def _official_host(value: Any) -> bool:
    try:
        parsed = urlsplit(str(value or ""))
        host = (parsed.hostname or "").lower().rstrip(".")
        return (
            parsed.scheme == "https"
            and (host == "xiaohongshu.com" or host.endswith(".xiaohongshu.com"))
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class BrowserExecutable:
    path: Path
    name: str


def _browser_candidates() -> tuple[BrowserExecutable, ...]:
    """Return only fixed vendor locations; no environment override is accepted."""

    system = platform.system()
    if system == "Darwin":
        return (
            BrowserExecutable(
                Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                "Google Chrome",
            ),
            BrowserExecutable(
                Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
                "Microsoft Edge",
            ),
            BrowserExecutable(
                Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
                "Chromium",
            ),
        )
    if system == "Windows":
        roots = tuple(
            Path(value)
            for key in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")
            if (value := os.environ.get(key))
        )
        relative = (
            (Path("Google/Chrome/Application/chrome.exe"), "Google Chrome"),
            (Path("Microsoft/Edge/Application/msedge.exe"), "Microsoft Edge"),
            (Path("Chromium/Application/chrome.exe"), "Chromium"),
        )
        return tuple(
            BrowserExecutable(root / path, name)
            for root in roots
            for path, name in relative
        )
    return (
        BrowserExecutable(Path("/usr/bin/google-chrome"), "Google Chrome"),
        BrowserExecutable(Path("/usr/bin/google-chrome-stable"), "Google Chrome"),
        BrowserExecutable(Path("/usr/bin/microsoft-edge"), "Microsoft Edge"),
        BrowserExecutable(Path("/usr/bin/microsoft-edge-stable"), "Microsoft Edge"),
        BrowserExecutable(Path("/usr/bin/chromium"), "Chromium"),
        BrowserExecutable(Path("/usr/bin/chromium-browser"), "Chromium"),
    )


def find_supported_browser() -> BrowserExecutable | None:
    for candidate in _browser_candidates():
        try:
            if candidate.path.is_file() and os.access(candidate.path, os.X_OK):
                return candidate
        except OSError:
            continue
    return None


def _browser_argv(executable: BrowserExecutable, profile_dir: Path) -> list[str]:
    """Build the fixed, secret-free launch command for the isolated profile."""

    return [
        str(executable.path),
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-extensions",
        "--new-window",
        OFFICIAL_LOGIN_URL,
    ]


def _read_exact(sock: socket.socket, size: int, buffer: bytearray) -> bytes:
    while len(buffer) < size:
        chunk = sock.recv(min(65536, size - len(buffer)))
        if not chunk:
            raise ConnectionError("browser control channel closed")
        buffer.extend(chunk)
        if len(buffer) > _MAX_CDP_MESSAGE_BYTES:
            raise ValueError("browser control message exceeded limit")
    result = bytes(buffer[:size])
    del buffer[:size]
    return result


def _bounded_json(value: Any, *, depth: int = 0) -> bool:
    if depth > 16:
        return False
    if value is None or isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, str):
        return len(value) <= _MAX_CDP_MESSAGE_BYTES
    if isinstance(value, Mapping):
        return len(value) <= 512 and all(
            isinstance(key, str)
            and len(key) <= 256
            and _bounded_json(item, depth=depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return len(value) <= 4096 and all(
            _bounded_json(item, depth=depth + 1) for item in value
        )
    return False


def _validate_cdp_request(
    method: str,
    params: Mapping[str, Any],
    session_id: str | None,
) -> None:
    """Reject every CDP capability outside the audited login subset."""

    if method == "Target.getTargets":
        valid = not params and session_id is None
    elif method == "Target.attachToTarget":
        target_id = params.get("targetId")
        valid = (
            set(params) == {"targetId", "flatten"}
            and isinstance(target_id, str)
            and 1 <= len(target_id) <= 256
            and params.get("flatten") is True
            and session_id is None
        )
    elif method == "Network.enable":
        valid = not params and isinstance(session_id, str) and 1 <= len(session_id) <= 256
    elif method == "Network.getCookies":
        valid = (
            params == {"urls": [COOKIE_SOURCE_URL]}
            and isinstance(session_id, str)
            and 1 <= len(session_id) <= 256
        )
    else:
        valid = False
    if not valid:
        raise BrowserLoginError(
            "BROWSER_CONTROL_FAILED", "浏览器登录请求超出本地安全范围。"
        )


class _CdpConnection:
    """Minimal RFC 6455 client for the loopback Chrome DevTools endpoint."""

    def __init__(self, port: int, path: str, *, timeout: float = 3.0) -> None:
        if not 1 <= port <= 65535 or not _DEVTOOLS_PATH_RE.fullmatch(path):
            raise ValueError("invalid browser control endpoint")
        self._socket = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self._socket.settimeout(timeout)
        self._buffer = bytearray()
        self._next_id = 0
        self._closed = False
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        self._socket.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionError("browser control handshake closed")
            response.extend(chunk)
            if len(response) > 65536:
                raise ValueError("browser control handshake exceeded limit")
        header, leftover = bytes(response).split(b"\r\n\r\n", 1)
        lines = header.split(b"\r\n")
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"),
                usedforsecurity=False,
            ).digest()
        )
        if (
            not lines
            or b" 101 " not in lines[0]
            or headers.get(b"upgrade", b"").lower() != b"websocket"
            or headers.get(b"sec-websocket-accept") != expected
        ):
            self.close()
            raise ConnectionError("browser control handshake rejected")
        self._buffer.extend(leftover)

    def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
        if self._closed:
            raise ConnectionError("browser control channel is closed")
        if len(payload) > _MAX_CDP_MESSAGE_BYTES:
            raise ValueError("browser control request exceeded limit")
        first = 0x80 | opcode
        length = len(payload)
        if length < 126:
            header = bytes((first, 0x80 | length))
        elif length <= 0xFFFF:
            header = bytes((first, 0x80 | 126)) + struct.pack("!H", length)
        else:
            header = bytes((first, 0x80 | 127)) + struct.pack("!Q", length)
        mask = secrets.token_bytes(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self._socket.sendall(header + mask + masked)

    def _read_message(self) -> bytes:
        fragments = bytearray()
        message_opcode: int | None = None
        while True:
            first, second = _read_exact(self._socket, 2, self._buffer)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if masked:
                raise ValueError("server browser-control frame must not be masked")
            if length == 126:
                length = struct.unpack("!H", _read_exact(self._socket, 2, self._buffer))[0]
            elif length == 127:
                length = struct.unpack("!Q", _read_exact(self._socket, 8, self._buffer))[0]
            if length > _MAX_CDP_MESSAGE_BYTES:
                raise ValueError("browser control response exceeded limit")
            payload = _read_exact(self._socket, length, self._buffer)
            if opcode == 0x8:
                raise ConnectionError("browser control channel closed")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in {0x1, 0x2}:
                message_opcode = opcode
                fragments.clear()
            elif opcode != 0x0 or message_opcode is None:
                raise ValueError("invalid browser control frame")
            fragments.extend(payload)
            if len(fragments) > _MAX_CDP_MESSAGE_BYTES:
                raise ValueError("browser control response exceeded limit")
            if final:
                if message_opcode != 0x1:
                    raise ValueError("browser control response was not text")
                return bytes(fragments)

    def call(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        session_id: str | None = None,
    ) -> Mapping[str, Any]:
        safe_params = dict(params or {})
        _validate_cdp_request(method, safe_params, session_id)
        self._next_id += 1
        request_id = self._next_id
        request: dict[str, Any] = {
            "id": request_id,
            "method": method,
            "params": safe_params,
        }
        if session_id:
            request["sessionId"] = session_id
        payload = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self._send_frame(0x1, payload)
        message_count = 0
        cumulative_bytes = 0
        while message_count < _MAX_CDP_MESSAGES_PER_CALL:
            message = self._read_message()
            message_count += 1
            cumulative_bytes += len(message)
            if cumulative_bytes > _MAX_CDP_CALL_BYTES:
                break
            decoded = json.loads(message)
            if not _bounded_json(decoded):
                raise BrowserLoginError(
                    "BROWSER_CONTROL_FAILED", "官方浏览器返回了无效的登录状态。"
                )
            if not isinstance(decoded, Mapping) or decoded.get("id") != request_id:
                continue
            if "error" in decoded:
                raise BrowserLoginError(
                    "BROWSER_CONTROL_FAILED", "无法安全读取官方网页登录状态。"
                )
            result = decoded.get("result")
            if not isinstance(result, Mapping):
                raise BrowserLoginError(
                    "BROWSER_CONTROL_FAILED", "官方浏览器返回了无效的登录状态。"
                )
            return result
        raise BrowserLoginError(
            "BROWSER_CONTROL_FAILED", "官方浏览器登录状态响应超过本地安全限制。"
        )

    def close(self) -> None:
        if self._closed:
            return
        with suppress(Exception):
            self._send_frame(0x8)
        self._closed = True
        with suppress(Exception):
            self._socket.shutdown(socket.SHUT_RDWR)
        with suppress(Exception):
            self._socket.close()


def _read_devtools_endpoint(
    profile_dir: Path,
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> tuple[int, str]:
    marker = profile_dir / "DevToolsActivePort"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise BrowserLoginError("BROWSER_CLOSED", "官方浏览器已关闭，登录未完成。")
        try:
            payload = marker.read_text(encoding="ascii")
        except (FileNotFoundError, OSError, UnicodeError):
            time.sleep(0.05)
            continue
        lines = payload.splitlines()
        if len(lines) < 2:
            time.sleep(0.05)
            continue
        try:
            port = int(lines[0])
        except ValueError:
            port = 0
        path = lines[1].strip()
        if 1 <= port <= 65535 and _DEVTOOLS_PATH_RE.fullmatch(path):
            return port, path
        raise BrowserLoginError(
            "BROWSER_CONTROL_FAILED", "官方浏览器未提供安全的本机控制通道。"
        )
    raise BrowserLoginError("BROWSER_LAUNCH_FAILED", "官方浏览器启动超时。")


def _cookie_header_from_cdp(payload: Any) -> str | None:
    """Select bounded, URL-scoped allowlisted cookies without exposing values."""

    if not isinstance(payload, Sequence) or isinstance(payload, (str, bytes, bytearray)):
        raise BrowserLoginError(
            "BROWSER_CONTROL_FAILED", "官方浏览器返回了无效的登录状态。"
        )
    selected: dict[str, tuple[tuple[int, int], str]] = {}
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "")
        value = str(item.get("value") or "")
        domain = str(item.get("domain") or "").lower().lstrip(".").rstrip(".")
        path = str(item.get("path") or "/")
        if (
            name not in _COOKIE_ALLOWLIST
            or not _COOKIE_NAME_RE.fullmatch(name)
            or not value
            or len(value) > 4096
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
            or ";" in value
            or not (domain == "xiaohongshu.com" or domain.endswith(".xiaohongshu.com"))
            or not path.startswith("/")
        ):
            continue
        # Prefer the most specific domain, then the longest path.  This makes
        # duplicate-name selection deterministic without serializing metadata.
        priority = (domain.count("."), len(path))
        previous = selected.get(name)
        if previous is None or priority > previous[0]:
            selected[name] = (priority, value)
    if not {"a1", "web_session"}.issubset(selected):
        return None
    pairs = [f"{name}={selected[name][1]}" for name in sorted(selected)]
    header = "; ".join(pairs)
    if len(pairs) > _MAX_COOKIE_COUNT or len(header.encode("utf-8")) > _MAX_COOKIE_BYTES:
        raise BrowserLoginError(
            "BROWSER_CONTROL_FAILED", "官方浏览器登录状态超过本地安全限制。"
        )
    return header


def _remove_profile(profile_dir: Path | None) -> bool:
    if profile_dir is None:
        return True
    for _attempt in range(5):
        with suppress(OSError):
            shutil.rmtree(profile_dir)
        if not profile_dir.exists():
            return True
        time.sleep(0.1)
    # Best effort hardening if Windows still has a transient lock.  No path is
    # logged or returned; a future startup may remove the empty/locked shell.
    with suppress(OSError):
        os.chmod(profile_dir, 0o700)
    return not profile_dir.exists()


class _IsolatedBrowserSession:
    def __init__(
        self,
        executable: BrowserExecutable,
        state_dir: Path,
        *,
        launch_timeout: float = 20.0,
    ) -> None:
        self._profile_dir: Path | None = Path(
            tempfile.mkdtemp(prefix=".browser-login-", dir=state_dir)
        )
        with suppress(OSError):
            os.chmod(self._profile_dir, 0o700)
        self._process: subprocess.Popen[bytes] | None = None
        self._connection: _CdpConnection | None = None
        self._session_id: str | None = None
        self._close_lock = threading.RLock()
        try:
            self._process = subprocess.Popen(
                _browser_argv(executable, self._profile_dir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
            )
            endpoint_deadline = time.monotonic() + max(3.0, min(launch_timeout, 30.0))
            port, path = _read_devtools_endpoint(
                self._profile_dir,
                self._process,
                deadline=endpoint_deadline,
            )
            self._connection = _CdpConnection(port, path)
            self._session_id = self._attach_official_page(endpoint_deadline)
            self._connection.call("Network.enable", session_id=self._session_id)
        except BrowserLoginError:
            self.close()
            raise
        except Exception:
            self.close()
            raise BrowserLoginError(
                "BROWSER_LAUNCH_FAILED", "无法启动隔离的官方浏览器登录窗口。"
            ) from None

    def _attach_official_page(self, deadline: float) -> str:
        assert self._connection is not None
        while time.monotonic() < deadline:
            result = self._connection.call("Target.getTargets")
            targets = result.get("targetInfos")
            if isinstance(targets, Sequence):
                for target in targets:
                    if (
                        isinstance(target, Mapping)
                        and target.get("type") == "page"
                        and _official_host(target.get("url"))
                    ):
                        target_id = str(target.get("targetId") or "")
                        if not target_id or len(target_id) > 256:
                            continue
                        attached = self._connection.call(
                            "Target.attachToTarget",
                            {"targetId": target_id, "flatten": True},
                        )
                        session_id = str(attached.get("sessionId") or "")
                        if 1 <= len(session_id) <= 256:
                            return session_id
            if not self.is_running():
                raise BrowserLoginError("BROWSER_CLOSED", "官方浏览器已关闭，登录未完成。")
            time.sleep(0.1)
        raise BrowserLoginError(
            "BROWSER_CONTROL_FAILED", "无法连接到固定的官方登录页面。"
        )

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def cookie_header(self) -> str | None:
        if not self.is_running():
            raise BrowserLoginError("BROWSER_CLOSED", "官方浏览器已关闭，登录未完成。")
        if self._connection is None or not self._session_id:
            raise BrowserLoginError(
                "BROWSER_CONTROL_FAILED", "官方浏览器登录通道不可用。"
            )
        result = self._connection.call(
            "Network.getCookies",
            {"urls": [COOKIE_SOURCE_URL]},
            session_id=self._session_id,
        )
        return _cookie_header_from_cdp(result.get("cookies"))

    def close(self) -> None:
        with self._close_lock:
            connection, self._connection = self._connection, None
            if connection is not None:
                connection.close()
            process, self._process = self._process, None
            if process is not None and process.poll() is None:
                with suppress(Exception):
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    with suppress(Exception):
                        process.kill()
                    with suppress(Exception):
                        process.wait(timeout=3)
            profile = self._profile_dir
            if not _remove_profile(profile):
                raise BrowserLoginError(
                    "BROWSER_PROFILE_CLEANUP_FAILED",
                    "临时浏览器资料未能安全清理，请关闭官方窗口后重试。",
                )
            self._profile_dir = None


@dataclass(slots=True)
class _LoginSession:
    internal_id: str = field(repr=False)
    created_at: float
    deadline: float
    expires_at: str
    status: str = "starting"
    message: str = "正在打开隔离的官方登录窗口…"
    error_code: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    thread: threading.Thread | None = field(default=None, repr=False)
    browser: Any | None = field(default=None, repr=False)


class IsolatedBrowserLoginManager:
    """Run at most one visible isolated-browser login."""

    def __init__(
        self,
        state_dir: Path,
        import_cookie: Callable[
            [str, Callable[[], bool], Callable[[], None]], dict[str, Any]
        ],
        active_jobs: Callable[[], bool],
        *,
        timeout_seconds: int = DEFAULT_LOGIN_TIMEOUT_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
    ) -> None:
        self._state_dir = state_dir
        self._import_cookie = import_cookie
        self._active_jobs = active_jobs
        self._timeout_seconds = max(30, min(int(timeout_seconds), 600))
        self._poll_seconds = max(0.1, min(float(poll_seconds), 5.0))
        self._executable = find_supported_browser()
        self._browser_factory: Callable[[BrowserExecutable, Path], Any] = (
            _IsolatedBrowserSession
        )
        self._lock = threading.RLock()
        self._session: _LoginSession | None = None

    def capability(self) -> dict[str, Any]:
        supported = self._executable is not None
        return {
            "browser_login_supported": supported,
            "browser_login_mode": "official_isolated_browser",
            "browser_login_embedded_qr": False,
            "browser_name": self._executable.name if self._executable else None,
            "browser_major_version": None,
            "browser_login_timeout_seconds": self._timeout_seconds,
            "browser_login_reason": (
                None
                if supported
                else "未找到受支持的 Chrome、Edge 或 Chromium；可使用手动 Cookie 导入。"
            ),
        }

    def _public(self, session: _LoginSession | None = None) -> dict[str, Any]:
        current = session or self._session
        capability = self.capability()
        if current is None:
            return {
                **capability,
                "status": "idle",
                "message": "尚未启动网页登录。",
                "failure_stage": None,
                "qr_ready": False,
                "qr_revision": None,
                "qr_url": None,
            }
        return {
            **capability,
            "status": current.status,
            "message": current.message,
            "expires_at": current.expires_at,
            "error_code": current.error_code,
            "failure_stage": "browser_login" if current.status == "failed" else None,
            "authenticated": current.status == "succeeded",
            "qr_ready": False,
            "qr_revision": None,
            "qr_url": None,
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self._public()

    def qr_image(self) -> tuple[bytes, str]:
        raise BrowserLoginError(
            "BROWSER_CONTROL_FAILED", "二维码显示在隔离的官方浏览器窗口中。"
        )

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
                session.error_code = (
                    error_code if error_code in _PUBLIC_ERROR_CODES else None
                )

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._active_jobs():
                raise PermissionError("请先取消或暂停正在运行、排队的任务，再更换登录态")
            if self._executable is None:
                raise BrowserLoginError(
                    "BROWSER_NOT_FOUND",
                    "未找到受支持的 Chrome、Edge 或 Chromium，请使用手动 Cookie 导入。",
                )
            if self._session is not None and self._session.status in _ACTIVE_STATUSES:
                raise PermissionError("已有网页登录正在等待，请先完成或取消")
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
                name="crimsonflux-browser-login",
                daemon=True,
            )
            self._session = session
            session.thread.start()
            return self._public(session)

    def cancel(self) -> dict[str, Any]:
        browser: Any | None = None
        with self._lock:
            current = self._session
            if current is None:
                return self._public()
            if current.status in _ACTIVE_STATUSES:
                current.cancel_event.set()
                current.message = "正在取消网页登录…"
                browser = current.browser
                result = self._public(current)
            else:
                self._session = None
                return self._public()
        if browser is not None:
            with suppress(Exception):
                browser.close()
        return result

    def close(self) -> None:
        with self._lock:
            current = self._session
            if current is None:
                return
            current.cancel_event.set()
            browser = current.browser
            thread = current.thread
        if browser is not None:
            with suppress(Exception):
                browser.close()
        if thread is not None and thread.is_alive():
            thread.join(timeout=10)

    def _run(self, session: _LoginSession) -> None:
        browser: Any | None = None
        candidate = ""
        last_candidate_hash: bytes | None = None
        last_verify_at = 0.0
        terminal: tuple[str, str, str | None] | None = None
        try:
            if session.cancel_event.is_set():
                raise _Cancelled
            assert self._executable is not None
            browser = self._browser_factory(self._executable, self._state_dir)
            session.browser = browser
            self._set_status(
                session,
                "awaiting_login",
                "请在弹出的官方网页扫码，并按手机提示完成确认；成功后会自动连接。",
            )
            while True:
                if session.cancel_event.is_set():
                    raise _Cancelled
                if time.monotonic() >= session.deadline:
                    raise _Expired
                if not browser.is_running():
                    raise BrowserLoginError(
                        "BROWSER_CLOSED", "官方浏览器已关闭，登录未完成。"
                    )
                candidate = browser.cookie_header() or ""
                if candidate:
                    digest = hashlib.sha256(candidate.encode("utf-8")).digest()
                    now = time.monotonic()
                    if (
                        digest != last_candidate_hash
                        or now - last_verify_at >= _VERIFY_RETRY_SECONDS
                    ):
                        last_candidate_hash = digest
                        last_verify_at = now
                        self._set_status(
                            session,
                            "verifying",
                            "检测到网页登录状态，正在验证账号…",
                        )
                        try:
                            result = self._import_cookie(
                                candidate,
                                session.cancel_event.is_set,
                                browser.close,
                            )
                        except Exception as error:
                            code = getattr(getattr(error, "code", None), "value", None) or getattr(
                                error, "code", None
                            )
                            if str(code) in {
                                AdapterErrorCode.AUTH_EXPIRED.value,
                                AdapterErrorCode.RISK_CONTROLLED.value,
                            }:
                                self._set_status(
                                    session,
                                    "awaiting_login",
                                    "网页登录尚未确认，请继续在官方页面完成扫码或验证。",
                                )
                            else:
                                raise
                        else:
                            if isinstance(result, Mapping) and result.get("authenticated") is True:
                                terminal = (
                                    "succeeded",
                                    "网页登录成功，登录态已验证并加密保存在本机。",
                                    None,
                                )
                                break
                            raise BrowserLoginError(
                                "AUTH_VERIFY_FAILED", "网页登录态未通过账号验证。"
                            )
                if session.cancel_event.wait(self._poll_seconds):
                    raise _Cancelled
        except _Cancelled:
            terminal = ("cancelled", "已取消网页登录。", None)
        except _Expired:
            terminal = (
                "expired",
                "网页登录已超时，请重新开始。",
                "LOGIN_EXPIRED",
            )
        except PermissionError:
            terminal = (
                "failed",
                "验证期间已有任务开始运行，登录态未保存。",
                "CREDENTIAL_CHANGE_CONFLICT",
            )
        except BrowserLoginError as error:
            terminal = (
                ("cancelled", "已取消网页登录。", None)
                if session.cancel_event.is_set()
                else ("failed", error.public_message, error.code)
            )
        except Exception as error:
            if session.cancel_event.is_set():
                terminal = ("cancelled", "已取消网页登录。", None)
            else:
                raw_code = getattr(getattr(error, "code", None), "value", None) or getattr(
                    error, "code", None
                )
                code = str(raw_code or "BROWSER_CONTROL_FAILED")
                messages = {
                    AdapterErrorCode.RATE_LIMITED.value: "平台暂时限制了账号验证请求，请稍后重试。",
                    AdapterErrorCode.RISK_CONTROLLED.value: "平台要求额外验证，请在官方网页完成后重试。",
                    AdapterErrorCode.NETWORK_ERROR.value: "账号验证网络请求失败，请检查连接后重试。",
                    AdapterErrorCode.SIGNER_FAILED.value: "本地签名运行时不可用。",
                    AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED.value: "账号验证接口返回结构已变化。",
                    AdapterErrorCode.UPSTREAM_UNSUPPORTED.value: "固定登录运行时未达到安全启用条件。",
                }
                if code not in _PUBLIC_ERROR_CODES:
                    code = "BROWSER_CONTROL_FAILED"
                terminal = (
                    "failed",
                    messages.get(code, "网页登录失败，请关闭窗口后重试。"),
                    code,
                )
        finally:
            candidate = ""
            last_candidate_hash = None
            last_verify_at = 0.0
            session.browser = None
            if browser is not None:
                try:
                    browser.close()
                except BrowserLoginError as cleanup_error:
                    terminal = (
                        "failed",
                        cleanup_error.public_message,
                        cleanup_error.code,
                    )
            if terminal is None:
                terminal = (
                    "failed",
                    "网页登录未完成。",
                    "BROWSER_CONTROL_FAILED",
                )
            self._set_status(session, terminal[0], terminal[1], terminal[2])


# Product code uses the explicit name.  This singular alias keeps compatibility
# for callers that imported the generic manager name.
BrowserLoginManager = IsolatedBrowserLoginManager

__all__ = [
    "BrowserExecutable",
    "BrowserLoginError",
    "BrowserLoginManager",
    "COOKIE_SOURCE_URL",
    "IsolatedBrowserLoginManager",
    "OFFICIAL_LOGIN_URL",
    "find_supported_browser",
]
