"""Visible, isolated official-browser login with verified Cookie import.

Only a fixed official page is opened.  The browser uses a disposable profile
and a loopback-only DevTools endpoint; it never attaches to the user's normal
browser profile.  Cookie material is read only for the fixed ``user/me`` URL,
passed directly to the existing account-verification boundary, and never
returned by the local API or written to logs.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

from xhs_insight.domain import AdapterErrorCode
from xhs_insight.security import write_private_file

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
_WINDOWS_TREE_KILL_TIMEOUT_SECONDS = 12.0
_WINDOWS_PROFILE_CLEANUP_DELAYS = (0.1, 0.2, 0.4, 0.8, 1.0, 1.5, 2.0, 2.0, 2.0, 2.0)
_DEFAULT_PROFILE_CLEANUP_DELAYS = (0.05, 0.1, 0.2, 0.4)
_PROFILE_ROOT_PREFIX = "crimsonflux-browser-login-"
_PROFILE_SESSION_PREFIX = "profile-"
_PROFILE_OWNER_MARKER = ".crimsonflux-owner"
_PROFILE_SESSION_MARKER_SUFFIX = ".owner"
_PROFILE_ROOT_NAME_RE = re.compile(r"^crimsonflux-browser-login-[0-9A-Za-z_-]{8,64}$")
_PROFILE_SESSION_NAME_RE = re.compile(r"^profile-[0-9A-Za-z_-]{8,64}$")
_PROFILE_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_MARKER_MAX_BYTES = 256
_FILE_ATTRIBUTE_REPARSE_POINT = int(
    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
)

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


class _WindowsGuid(ctypes.Structure):
    _fields_ = (
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    )


_WINDOWS_KNOWN_FOLDER_IDS = (
    "905e63b6-c1bf-494e-b29c-65b732d3d21a",
    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e",
    "f1b32785-6fba-4fcf-9d55-7b8e7f157091",
)
_WINDOWS_BROWSER_SUFFIXES = (
    (PureWindowsPath("Google/Chrome/Application/chrome.exe"), "Google Chrome"),
    (PureWindowsPath("Microsoft/Edge/Application/msedge.exe"), "Microsoft Edge"),
    (PureWindowsPath("Chromium/Application/chrome.exe"), "Chromium"),
)
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


def _windows_guid(value: str) -> _WindowsGuid:
    compact = value.replace("-", "")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", compact):
        raise ValueError("invalid Windows known-folder identifier")
    data4 = bytes.fromhex(compact[16:])
    return _WindowsGuid(
        int(compact[0:8], 16),
        int(compact[8:12], 16),
        int(compact[12:16], 16),
        (ctypes.c_ubyte * 8)(*data4),
    )


def _windows_known_folder_path(folder_id: str) -> Path | None:
    """Resolve one trusted Known Folder and always release its OS allocation."""

    try:
        loader = getattr(ctypes, "WinDLL", None)
        if not callable(loader):
            return None
        shell32 = loader(
            "shell32.dll",
            use_last_error=True,
            winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        ole32 = loader(
            "ole32.dll",
            use_last_error=True,
            winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        get_known_folder = shell32.SHGetKnownFolderPath
        free_memory = ole32.CoTaskMemFree
        get_known_folder.argtypes = (
            ctypes.POINTER(_WindowsGuid),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        get_known_folder.restype = ctypes.c_long
        free_memory.argtypes = (ctypes.c_void_p,)
        free_memory.restype = None
        identifier = _windows_guid(folder_id)
        allocated = ctypes.c_void_p()
        try:
            result = int(
                get_known_folder(
                    ctypes.byref(identifier),
                    0,
                    None,
                    ctypes.byref(allocated),
                )
            )
            if result != 0 or not allocated.value:
                return None
            raw = ctypes.wstring_at(allocated.value)
        finally:
            if allocated.value:
                free_memory(allocated)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if not raw or len(raw) > 32767 or any(ord(character) < 32 for character in raw):
        return None
    candidate = PureWindowsPath(raw)
    if (
        not candidate.is_absolute()
        or not re.fullmatch(r"[A-Za-z]:", candidate.drive)
        or candidate.root != "\\"
        or any(part in {".", ".."} for part in candidate.parts)
    ):
        return None
    return Path(candidate)


def _windows_known_folder_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    observed: set[str] = set()
    for folder_id in _WINDOWS_KNOWN_FOLDER_IDS:
        root = _windows_known_folder_path(folder_id)
        if root is None:
            continue
        normalized = str(root).replace("/", "\\").casefold().rstrip("\\")
        if normalized not in observed:
            observed.add(normalized)
            roots.append(root)
    return tuple(roots)


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
        return tuple(
            BrowserExecutable(root / Path(suffix), name)
            for root in _windows_known_folder_roots()
            for suffix, name in _WINDOWS_BROWSER_SUFFIXES
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


def _browser_creation_flags() -> int:
    """Keep the disposable Windows browser in a distinct process group."""

    if platform.system() != "Windows":
        return 0
    value = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return value if type(value) is int and value >= 0 else 0


def _windows_taskkill_path() -> Path:
    """Resolve only the operating-system taskkill binary, never PATH input."""

    # Environment variables and PATH are attacker-controlled inputs here. Ask
    # the Windows loader for its trusted system directory instead.  The fixed
    # fallback is used only if that OS API is unavailable or returns malformed
    # data (for example while unit tests execute on another platform).
    try:
        loader = getattr(ctypes, "windll", None)
        kernel32 = getattr(loader, "kernel32", None)
        get_system_directory = getattr(kernel32, "GetSystemDirectoryW", None)
        if not callable(get_system_directory):
            raise AttributeError("Windows system directory API unavailable")
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(get_system_directory(buffer, len(buffer)))
        system_directory = buffer.value.rstrip("\\/")
        if (
            0 < length < len(buffer)
            and re.fullmatch(
                r"[A-Za-z]:\\[^:\r\n]+\\System32",
                system_directory,
                flags=re.IGNORECASE,
            )
        ):
            return Path(system_directory + "\\taskkill.exe")
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    return Path("C:\\Windows\\System32\\taskkill.exe")


def _terminate_browser_process(process: subprocess.Popen[bytes]) -> None:
    """Bound termination and, on Windows, close the whole Chrome process tree."""

    if process.poll() is not None:
        return
    if platform.system() == "Windows":
        pid = getattr(process, "pid", None)
        if (
            type(pid) is int
            and 1 <= pid <= 2_147_483_647
            and process.poll() is None
        ):
            with suppress(OSError, subprocess.TimeoutExpired):
                subprocess.run(
                    [
                        str(_windows_taskkill_path()),
                        "/PID",
                        str(pid),
                        "/T",
                        "/F",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    shell=False,
                    timeout=_WINDOWS_TREE_KILL_TIMEOUT_SECONDS,
                )
        # taskkill can be blocked by endpoint security.  Retain a bounded
        # direct-process fallback so close() always progresses to cleanup.
        if process.poll() is None:
            with suppress(Exception):
                process.kill()
            with suppress(Exception):
                process.wait(timeout=3)
        return
    with suppress(Exception):
        process.terminate()
    try:
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        with suppress(Exception):
            process.kill()
        with suppress(Exception):
            process.wait(timeout=3)


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
            "BROWSER_CONTROL_FAILED",
            "登录页面返回的信息过多，本次读取已安全停止。请关闭登录窗口后重试。",
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


def _has_reparse_attribute(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _directory_lstat(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        raise RuntimeError("临时浏览器目录所有权校验失败")
    return metadata


def _owned_directory_lstat(path: Path) -> os.stat_result:
    metadata = _directory_lstat(path)
    if os.name != "nt":
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise RuntimeError("临时浏览器目录不属于当前用户")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("临时浏览器目录权限过宽")
    return metadata


def _regular_lstat(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or _has_reparse_attribute(metadata)
    ):
        raise RuntimeError("临时浏览器标记所有权校验失败")
    return metadata


def _path_absent(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return os.path.samestat(left, right) and (
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _read_owned_marker(path: Path, expected: os.stat_result) -> bytes:
    """Read an already-hardened ownership marker without reapplying its ACL."""

    before = _regular_lstat(path)
    if not _same_file_state(before, expected):
        raise RuntimeError("临时浏览器标记已被替换或修改")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _has_reparse_attribute(opened)
            or not _same_file_state(opened, expected)
        ):
            raise RuntimeError("临时浏览器标记读取校验失败")
        payload = bytearray()
        while len(payload) <= _PROFILE_MARKER_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(256, _PROFILE_MARKER_MAX_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > _PROFILE_MARKER_MAX_BYTES:
            raise RuntimeError("临时浏览器标记超过安全大小限制")
        if not _same_file_state(_regular_lstat(path), expected):
            raise RuntimeError("临时浏览器标记读取时已变化")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _root_marker_payload(nonce: str) -> bytes:
    return f"crimsonflux-browser-login-root-v1\n{nonce}\n".encode("ascii")


def _profile_marker_payload(root_nonce: str, profile_nonce: str) -> bytes:
    return (
        f"crimsonflux-browser-login-profile-v1\n{root_nonce}\n{profile_nonce}\n"
    ).encode("ascii")


@dataclass(slots=True)
class _OwnedProfileRoot:
    path: Path
    nonce: str = field(repr=False)
    identity: os.stat_result = field(repr=False)
    marker_identity: os.stat_result = field(repr=False)
    temp_parent: Path
    temp_parent_identity: os.stat_result = field(repr=False)
    profiles: dict[str, _OwnedProfile] = field(default_factory=dict, repr=False)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)


@dataclass(slots=True)
class _OwnedProfile:
    root: _OwnedProfileRoot = field(repr=False)
    path: Path
    nonce: str = field(repr=False)
    identity: os.stat_result = field(repr=False)
    marker_path: Path
    marker_identity: os.stat_result = field(repr=False)


def _validate_root(root: _OwnedProfileRoot) -> None:
    if (
        not _PROFILE_NONCE_RE.fullmatch(root.nonce)
        or not _PROFILE_ROOT_NAME_RE.fullmatch(root.path.name)
        or root.path.parent != root.temp_parent
        or not os.path.samestat(
            _directory_lstat(root.temp_parent), root.temp_parent_identity
        )
        or not os.path.samestat(_owned_directory_lstat(root.path), root.identity)
    ):
        raise RuntimeError("临时浏览器根目录所有权校验失败")
    marker = root.path / _PROFILE_OWNER_MARKER
    if not os.path.samestat(_regular_lstat(marker), root.marker_identity):
        raise RuntimeError("临时浏览器根目录标记已被替换")
    if _read_owned_marker(marker, root.marker_identity) != _root_marker_payload(
        root.nonce
    ):
        raise RuntimeError("临时浏览器根目录标记无效")
    if not os.path.samestat(_regular_lstat(marker), root.marker_identity):
        raise RuntimeError("临时浏览器根目录标记读取时已变化")


def _validate_profile(profile: _OwnedProfile, *, require_directory: bool = True) -> None:
    root = profile.root
    _validate_root(root)
    if (
        not _PROFILE_NONCE_RE.fullmatch(profile.nonce)
        or not _PROFILE_SESSION_NAME_RE.fullmatch(profile.path.name)
        or profile.path.parent != root.path
        or root.profiles.get(profile.path.name) is not profile
        or profile.marker_path
        != root.path / f".{profile.path.name}{_PROFILE_SESSION_MARKER_SUFFIX}"
    ):
        raise RuntimeError("临时浏览器会话目录所有权校验失败")
    if require_directory and not os.path.samestat(
        _owned_directory_lstat(profile.path), profile.identity
    ):
        raise RuntimeError("临时浏览器会话目录已被替换")
    if not os.path.samestat(
        _regular_lstat(profile.marker_path), profile.marker_identity
    ):
        raise RuntimeError("临时浏览器会话标记已被替换")
    if _read_owned_marker(
        profile.marker_path, profile.marker_identity
    ) != _profile_marker_payload(root.nonce, profile.nonce):
        raise RuntimeError("临时浏览器会话标记无效")
    if not os.path.samestat(
        _regular_lstat(profile.marker_path), profile.marker_identity
    ):
        raise RuntimeError("临时浏览器会话标记读取时已变化")


def _create_owned_profile_root_at(temp_parent: Path) -> _OwnedProfileRoot:
    parent = Path(os.path.abspath(temp_parent))
    parent_identity = _directory_lstat(parent)
    path = Path(tempfile.mkdtemp(prefix=_PROFILE_ROOT_PREFIX, dir=parent))
    try:
        os.chmod(path, 0o700)
        identity = _owned_directory_lstat(path)
        nonce = secrets.token_hex(32)
        marker_identity = write_private_file(
            path / _PROFILE_OWNER_MARKER, _root_marker_payload(nonce)
        )
        root = _OwnedProfileRoot(
            path=path,
            nonce=nonce,
            identity=identity,
            marker_identity=marker_identity,
            temp_parent=parent,
            temp_parent_identity=parent_identity,
        )
        _validate_root(root)
        return root
    except BaseException:
        # The directory was just created by this call and contains at most our
        # private marker.  Never recurse over a root whose ownership is unknown.
        marker = path / _PROFILE_OWNER_MARKER
        with suppress(OSError):
            marker.unlink()
        with suppress(OSError):
            path.rmdir()
        raise


def _create_owned_profile_root() -> _OwnedProfileRoot:
    """Create one application-owned root under Python's system temp directory."""

    return _create_owned_profile_root_at(Path(tempfile.gettempdir()))


def _create_owned_profile(root: _OwnedProfileRoot) -> _OwnedProfile:
    with root.lock:
        _validate_root(root)
        path = Path(tempfile.mkdtemp(prefix=_PROFILE_SESSION_PREFIX, dir=root.path))
        try:
            os.chmod(path, 0o700)
            identity = _owned_directory_lstat(path)
            nonce = secrets.token_hex(32)
            marker_path = root.path / (
                f".{path.name}{_PROFILE_SESSION_MARKER_SUFFIX}"
            )
            marker_identity = write_private_file(
                marker_path, _profile_marker_payload(root.nonce, nonce)
            )
            profile = _OwnedProfile(
                root=root,
                path=path,
                nonce=nonce,
                identity=identity,
                marker_path=marker_path,
                marker_identity=marker_identity,
            )
            root.profiles[path.name] = profile
            _validate_profile(profile)
            return profile
        except BaseException:
            marker_path = root.path / f".{path.name}{_PROFILE_SESSION_MARKER_SUFFIX}"
            with suppress(OSError):
                marker_path.unlink()
            with suppress(OSError):
                path.rmdir()
            raise


def _remove_profile(profile: _OwnedProfile | None) -> bool:
    if profile is None:
        return True
    delays = (
        _WINDOWS_PROFILE_CLEANUP_DELAYS
        if platform.system() == "Windows"
        else _DEFAULT_PROFILE_CLEANUP_DELAYS
    )
    with profile.root.lock:
        for delay in (*delays, None):
            try:
                directory_absent = _path_absent(profile.path)
                _validate_profile(profile, require_directory=not directory_absent)
                if not directory_absent:
                    # Exact, registered path only.  No glob, shell or root-wide
                    # recursive deletion is permitted at this boundary.
                    shutil.rmtree(profile.path)
                if _path_absent(profile.path):
                    profile.marker_path.unlink(missing_ok=True)
                    if _path_absent(profile.marker_path):
                        profile.root.profiles.pop(profile.path.name, None)
                        return True
            except Exception:
                pass
            if delay is not None:
                time.sleep(delay)
        return False


def _remove_profile_root(root: _OwnedProfileRoot | None) -> bool:
    if root is None:
        return True
    with root.lock:
        for profile in tuple(root.profiles.values()):
            if not _remove_profile(profile):
                return False
        try:
            _validate_root(root)
            marker = root.path / _PROFILE_OWNER_MARKER
            entries = tuple(root.path.iterdir())
            if entries != (marker,):
                return False
            marker.unlink()
            if not _path_absent(marker):
                return False
            if not os.path.samestat(_owned_directory_lstat(root.path), root.identity):
                return False
            if any(root.path.iterdir()):
                return False
            root.path.rmdir()
            if _path_absent(root.path):
                return True
            # A delete shim may silently no-op.  Restore the marker so the same
            # owned root can be validated and retried later.
            root.marker_identity = write_private_file(
                marker, _root_marker_payload(root.nonce)
            )
        except Exception:
            marker = root.path / _PROFILE_OWNER_MARKER
            if not _path_absent(root.path) and _path_absent(marker):
                with suppress(Exception):
                    root.marker_identity = write_private_file(
                        marker, _root_marker_payload(root.nonce)
                    )
        return False


class _IsolatedBrowserSession:
    def __init__(
        self,
        executable: BrowserExecutable,
        profile_root: _OwnedProfileRoot,
        *,
        launch_timeout: float = 20.0,
    ) -> None:
        self._profile: _OwnedProfile | None = _create_owned_profile(profile_root)
        self._process: subprocess.Popen[bytes] | None = None
        self._connection: _CdpConnection | None = None
        self._session_id: str | None = None
        self._close_lock = threading.RLock()
        try:
            self._process = subprocess.Popen(
                _browser_argv(executable, self._profile.path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                creationflags=_browser_creation_flags(),
            )
            endpoint_deadline = time.monotonic() + max(3.0, min(launch_timeout, 30.0))
            port, path = _read_devtools_endpoint(
                self._profile.path,
                self._process,
                deadline=endpoint_deadline,
            )
            self._connection = _CdpConnection(port, path)
            self._session_id = self._attach_official_page(endpoint_deadline)
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
            connection = self._connection
            if connection is not None:
                connection.close()
                self._connection = None
                self._session_id = None
            process = self._process
            if process is not None:
                _terminate_browser_process(process)
                if process.poll() is None:
                    raise BrowserLoginError(
                        "BROWSER_PROFILE_CLEANUP_FAILED",
                        "临时浏览器进程未能安全关闭，请关闭官方窗口后重试。",
                    )
            profile = self._profile
            if not _remove_profile(profile):
                raise BrowserLoginError(
                    "BROWSER_PROFILE_CLEANUP_FAILED",
                    "临时浏览器资料未能安全清理，请关闭官方窗口后重试。",
                )
            self._profile = None
            self._process = None


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
    commit_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    committed: bool = field(default=False, repr=False)
    thread: threading.Thread | None = field(default=None, repr=False)
    browser: Any | None = field(default=None, repr=False)


class _SessionCommitGuard:
    """Linearize stop/deadline against the final credential commit."""

    def __init__(self, session: _LoginSession) -> None:
        self._session = session
        self._entered = False

    def __enter__(self) -> _SessionCommitGuard:
        session = self._session
        session.commit_lock.acquire()
        if (
            session.committed
            or session.cancel_event.is_set()
            or time.monotonic() >= session.deadline
        ):
            session.commit_lock.release()
            raise PermissionError("网页登录已停止，登录态未保存")
        self._entered = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if not self._entered:
            return
        try:
            if exc_type is None:
                self._session.committed = True
        finally:
            self._entered = False
            self._session.commit_lock.release()


class IsolatedBrowserLoginManager:
    """Run at most one visible isolated-browser login."""

    def __init__(
        self,
        state_dir: Path,
        import_cookie: Callable[
            [str, Callable[[], bool], Callable[[], Any]], dict[str, Any]
        ],
        active_jobs: Callable[[], bool],
        *,
        timeout_seconds: int = DEFAULT_LOGIN_TIMEOUT_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
    ) -> None:
        # Kept in the public constructor for compatibility with callers, but
        # persistent state must never select the disposable browser location.
        del state_dir
        self._import_cookie = import_cookie
        self._active_jobs = active_jobs
        self._timeout_seconds = max(30, min(int(timeout_seconds), 600))
        self._poll_seconds = max(0.1, min(float(poll_seconds), 5.0))
        self._executable = find_supported_browser()
        self._browser_factory: Callable[[BrowserExecutable, _OwnedProfileRoot], Any] = (
            _IsolatedBrowserSession
        )
        self._lock = threading.RLock()
        self._session: _LoginSession | None = None
        self._profile_root: _OwnedProfileRoot | None = None

    def _ensure_profile_root(self) -> _OwnedProfileRoot:
        root = self._profile_root
        if root is not None:
            try:
                _validate_root(root)
            except Exception:
                raise BrowserLoginError(
                    "BROWSER_PROFILE_CLEANUP_FAILED",
                    "临时浏览器目录所有权校验失败，请重启服务后重试。",
                ) from None
            return root
        try:
            root = _create_owned_profile_root()
        except Exception:
            raise BrowserLoginError(
                "BROWSER_LAUNCH_FAILED",
                "无法在系统临时目录创建受保护的浏览器资料。",
            ) from None
        self._profile_root = root
        return root

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

    def _close_session_browser(self, session: _LoginSession, browser: Any) -> None:
        try:
            browser.close()
        except BrowserLoginError as error:
            with session.commit_lock:
                committed = session.committed
            if not committed:
                self._set_status(session, "failed", error.public_message, error.code)
        except Exception:
            with session.commit_lock:
                committed = session.committed
            if not committed:
                self._set_status(
                    session,
                    "failed",
                    "临时浏览器资料未能安全清理，请关闭官方窗口后重试。",
                    "BROWSER_PROFILE_CLEANUP_FAILED",
                )
        else:
            with self._lock:
                if session.browser is browser:
                    session.browser = None

    def status(self) -> dict[str, Any]:
        cleanup: tuple[_LoginSession, Any] | None = None
        with self._lock:
            current = self._session
            if current is not None:
                with current.commit_lock:
                    if current.committed:
                        current.status = "succeeded"
                        current.message = "网页登录成功，登录态已验证并加密保存在本机。"
                        current.error_code = None
                    elif current.status in _ACTIVE_STATUSES:
                        thread = current.thread
                        if current.cancel_event.is_set():
                            current.status = "cancelled"
                            current.message = "已取消网页登录。"
                            current.error_code = None
                        elif time.monotonic() >= current.deadline:
                            current.cancel_event.set()
                            current.status = "expired"
                            current.message = "网页登录已超时，请重新开始。"
                            current.error_code = "LOGIN_EXPIRED"
                            if current.browser is not None:
                                cleanup = (current, current.browser)
                        elif thread is not None and not thread.is_alive():
                            current.cancel_event.set()
                            current.status = "failed"
                            current.message = "网页登录进程意外结束，请重新开始。"
                            current.error_code = "BROWSER_CONTROL_FAILED"
                            if current.browser is not None:
                                cleanup = (current, current.browser)
        if cleanup is not None:
            session, browser = cleanup
            self._close_session_browser(session, browser)
        with self._lock:
            return self._public(current)

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
        # Reconcile an expired/dead prior worker before deciding whether a new
        # login may start.  This also prevents an abandoned active state from
        # blocking the API forever.
        self.status()
        with self._lock:
            if self._active_jobs():
                raise PermissionError("请先取消或暂停正在运行、排队的任务，再更换登录态")
            if self._executable is None:
                raise BrowserLoginError(
                    "BROWSER_NOT_FOUND",
                    "未找到受支持的 Chrome、Edge 或 Chromium，请使用手动 Cookie 导入。",
                )
            previous = self._session
            if previous is not None:
                if previous.status in _ACTIVE_STATUSES:
                    raise PermissionError("已有网页登录正在等待，请先完成或取消")
                if previous.thread is not None and previous.thread.is_alive():
                    raise PermissionError("上一次网页登录正在安全结束，请稍后重试")
                if previous.browser is not None:
                    try:
                        previous.browser.close()
                    except BrowserLoginError:
                        raise
                    except Exception:
                        raise BrowserLoginError(
                            "BROWSER_PROFILE_CLEANUP_FAILED",
                            "临时浏览器资料未能安全清理，请关闭官方窗口后重试。",
                        ) from None
                    previous.browser = None
            self._ensure_profile_root()
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
        with self._lock:
            current = self._session
            if current is None:
                return self._public()
            with current.commit_lock:
                committed = current.committed
                was_active = current.status in _ACTIVE_STATUSES
                if committed:
                    current.status = "succeeded"
                    current.message = "网页登录成功，登录态已验证并加密保存在本机。"
                    current.error_code = None
                elif was_active:
                    current.cancel_event.set()
                    current.status = "cancelled"
                    current.message = "已取消网页登录。"
                    current.error_code = None
                browser = current.browser
                thread = current.thread
        if browser is not None:
            self._close_session_browser(current, browser)
        with self._lock:
            worker_alive = thread is not None and thread.is_alive()
            cleanup_pending = current.browser is not None
            if (
                self._session is current
                and not was_active
                and not committed
                and not worker_alive
                and not cleanup_pending
            ):
                self._session = None
                return self._public()
            return self._public(current)

    def close(self) -> None:
        with self._lock:
            current = self._session
            browser = None
            thread = None
            if current is not None:
                with current.commit_lock:
                    if current.committed:
                        current.status = "succeeded"
                        current.message = "网页登录成功，登录态已验证并加密保存在本机。"
                        current.error_code = None
                    else:
                        current.cancel_event.set()
                        if current.status in _ACTIVE_STATUSES:
                            current.status = "cancelled"
                            current.message = "已取消网页登录。"
                            current.error_code = None
                    browser = current.browser
                    thread = current.thread
        if current is not None and browser is not None:
            self._close_session_browser(current, browser)
        if thread is not None and thread.is_alive():
            thread.join(timeout=10)
        with self._lock:
            cleanup_pending = (
                current is not None
                and (
                    current.browser is not None
                    or (current.thread is not None and current.thread.is_alive())
                )
            )
            root = None if cleanup_pending else self._profile_root
        if root is not None and _remove_profile_root(root):
            with self._lock:
                if self._profile_root is root:
                    self._profile_root = None

    def _run(self, session: _LoginSession) -> None:
        browser: Any | None = None
        candidate = ""
        last_candidate_hash: bytes | None = None
        last_verify_at = 0.0
        terminal: tuple[str, str, str | None] | None = None

        def stopped() -> bool:
            with session.commit_lock:
                return not session.committed and (
                    session.cancel_event.is_set()
                    or time.monotonic() >= session.deadline
                )

        def cleanup_before_persist() -> _SessionCommitGuard:
            if stopped():
                raise PermissionError("网页登录已停止，登录态未保存")
            assert browser is not None
            self._set_status(
                session,
                "verifying",
                "账号验证通过，正在安全关闭临时浏览器并保存登录状态…",
            )
            browser.close()
            with self._lock:
                if session.browser is browser:
                    session.browser = None
            if stopped():
                raise PermissionError("网页登录已停止，登录态未保存")
            return _SessionCommitGuard(session)

        try:
            if session.cancel_event.is_set():
                raise _Cancelled
            assert self._executable is not None
            root = self._profile_root
            if root is None:
                raise BrowserLoginError(
                    "BROWSER_LAUNCH_FAILED",
                    "临时浏览器目录尚未准备完成。",
                )
            browser = self._browser_factory(self._executable, root)
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
                                stopped,
                                cleanup_before_persist,
                            )
                        except Exception as error:
                            with session.commit_lock:
                                committed = session.committed
                            if committed:
                                terminal = (
                                    "succeeded",
                                    "网页登录成功，登录态已验证并加密保存在本机。",
                                    None,
                                )
                                break
                            if session.cancel_event.is_set():
                                raise _Cancelled from None
                            if time.monotonic() >= session.deadline:
                                raise _Expired from None
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
                            with session.commit_lock:
                                committed = session.committed
                            if (
                                committed
                                and isinstance(result, Mapping)
                                and result.get("authenticated") is True
                            ):
                                terminal = (
                                    "succeeded",
                                    "网页登录成功，登录态已验证并加密保存在本机。",
                                    None,
                                )
                                break
                            if session.cancel_event.is_set():
                                raise _Cancelled
                            if time.monotonic() >= session.deadline:
                                raise _Expired
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
            if session.cancel_event.is_set():
                terminal = ("cancelled", "已取消网页登录。", None)
            elif time.monotonic() >= session.deadline:
                terminal = (
                    "expired",
                    "网页登录已超时，请重新开始。",
                    "LOGIN_EXPIRED",
                )
            else:
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
            if browser is not None:
                try:
                    browser.close()
                except BrowserLoginError as cleanup_error:
                    session.browser = browser
                    terminal = (
                        "failed",
                        cleanup_error.public_message,
                        cleanup_error.code,
                    )
                except Exception:
                    session.browser = browser
                    terminal = (
                        "failed",
                        "临时浏览器资料未能安全清理，请关闭官方窗口后重试。",
                        "BROWSER_PROFILE_CLEANUP_FAILED",
                    )
                else:
                    session.browser = None
            with session.commit_lock:
                committed = session.committed
                if committed:
                    terminal = (
                        "succeeded",
                        "网页登录成功，登录态已验证并加密保存在本机。",
                        None,
                    )
                elif terminal is None:
                    terminal = (
                        "failed",
                        "网页登录未完成。",
                        "BROWSER_CONTROL_FAILED",
                    )
                elif session.cancel_event.is_set() and terminal[0] == "succeeded":
                    terminal = ("cancelled", "已取消网页登录。", None)
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
