"""Credential encryption, URL scrubbing and log-safe helpers."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SECRET_QUERY_NAMES = frozenset(
    {
        "auth",
        "auth_key",
        "authorization",
        "credential",
        "expires",
        "id_token",
        "key_pair_id",
        "login_token",
        "mobile_token",
        "ossaccesskeyid",
        "policy",
        "secure_session",
        "session_key",
        "session_token",
        "sig",
        "sign",
        "signature",
        "token",
        "web_session",
        "wssecret",
        "wstime",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
        "x_rap_param",
        "x_s",
        "x_s_common",
        "x_t",
        "xsec_token",
        "xsec_source",
        "access_token",
    }
)
_SECRET_NAME = (
    r"a1|access[_-]?token|auth(?:orization)?|auth[_-]?key|cookie|credential|id[_-]?token|"
    r"login[_-]?token|mobile[_-]?token|secure[_-]?session|session[_-]?(?:key|token)|sig|"
    r"sign(?:ature)?|token|web[_-]?session|wssecret|x[_-]?amz[_-]?(?:credential|security[_-]?token|"
    r"signature)|x[_-]?rap[_-]?param|x[_-]?s(?:[_-]?common)?|x[_-]?t|xsec[_-]?token"
)
_JSON_SECRET_RE = re.compile(
    rf'''(?i)(["'](?:{_SECRET_NAME})["']\s*:\s*)(["'])(?:\\.|[^\\])*?\2'''
)
_HEADER_SECRET_RE = re.compile(
    r"(?im)\b(cookie|set-cookie|authorization)\s*:\s*[^\r\n]*"
)
_COOKIE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(cookie|set-cookie|authorization)\s*=\s*[^\r\n,}\]]*"
)
_QUERY_VALUE_RE = re.compile(r"([?&])([^=&\s]+)=([^&#\s\"']*)")
_ASSIGNMENT_RE = re.compile(
    rf"(?i)\b({_SECRET_NAME})\s*=\s*(?!\[REDACTED\])[^\s,;&\"'\]\}}]+"
)
_URL_USERINFO_RE = re.compile(r"(?i)(https?://)[^/@\s]+@")


def _normalize_secret_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _is_secret_query_name(value: str) -> bool:
    name = _normalize_secret_name(unquote_plus(value))
    return name in _SECRET_QUERY_NAMES or name.endswith(
        ("_credential", "_secret", "_signature", "_token")
    )


def _is_windows() -> bool:
    return os.name == "nt"


def _absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(Path(path).expanduser()))


def _regular_lstat(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("本地凭证文件不能是符号链接")
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("本地凭证路径不是普通文件")
    return metadata


def _optional_regular_lstat(path: Path) -> os.stat_result | None:
    try:
        return _regular_lstat(path)
    except FileNotFoundError:
        return None


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return os.path.samestat(left, right)


def _unlink_if_same(path: Path, expected: os.stat_result | None) -> None:
    if expected is None:
        return
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(current.st_mode) and _same_file(expected, current):
        path.unlink(missing_ok=True)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("写入本地凭证文件失败")
        remaining = remaining[written:]


def secure_private_file(path: str | Path) -> None:
    """Restrict a credential-bearing file to the current OS user."""

    target = _absolute_path(path)
    _regular_lstat(target)
    if not _is_windows():
        os.chmod(target, 0o600)
        return
    username = os.getenv("USERNAME", "").strip()
    domain = os.getenv("USERDOMAIN", "").strip()
    if not username:
        raise RuntimeError("无法确定当前 Windows 用户，拒绝保存本地凭证")
    principal = f"{domain}\\{username}" if domain else username
    result = subprocess.run(
        [
            "icacls",
            str(target),
            "/inheritance:r",
            "/grant:r",
            f"{principal}:(F)",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("无法限制本地凭证文件的 Windows ACL，已停止启动")


def write_private_file(path: str | Path, payload: bytes) -> os.stat_result:
    """Create a private file, harden its empty inode, then durably write bytes.

    The descriptor remains open while the path ACL is changed.  Any ACL,
    symlink, replacement or write failure removes the file when it is still the
    inode created by this call, so a secret is never written before hardening.
    """

    target = _absolute_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    created: os.stat_result | None = None
    try:
        created = os.fstat(descriptor)
        if not stat.S_ISREG(created.st_mode):
            raise RuntimeError("本地凭证路径不是普通文件")
        # On Windows the newly created file may inherit a broad DACL.  Keep it
        # empty until icacls succeeds and the directory entry is revalidated.
        secure_private_file(target)
        if not _same_file(created, _regular_lstat(target)):
            raise RuntimeError("本地凭证文件在写入前已被替换")
        _write_all(descriptor, bytes(payload))
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        if not _same_file(written, _regular_lstat(target)):
            raise RuntimeError("本地凭证文件在写入时已被替换")
        return written
    except BaseException:
        os.close(descriptor)
        descriptor = -1
        _unlink_if_same(target, created)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def replace_private_file(path: str | Path, payload: bytes) -> os.stat_result:
    """Atomically replace a private regular file with an ACL-first temp file."""

    target = _absolute_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    original = _optional_regular_lstat(target)
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    created = write_private_file(temporary, payload)
    try:
        current = _optional_regular_lstat(target)
        if (original is None) != (current is None) or (
            original is not None and current is not None and not _same_file(original, current)
        ):
            raise RuntimeError("本地凭证目标在替换前已变化")
        os.replace(temporary, target)
        installed = _regular_lstat(target)
        if not _same_file(created, installed):
            raise RuntimeError("本地凭证文件原子替换校验失败")
        return installed
    except BaseException:
        _unlink_if_same(temporary, created)
        raise


def read_private_file(path: str | Path, *, max_bytes: int) -> bytes:
    """Harden and read a bounded private regular file through one descriptor."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    target = _absolute_path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("本地凭证路径不是普通文件")
        secure_private_file(target)
        if not _same_file(opened, _regular_lstat(target)):
            raise RuntimeError("本地凭证文件在读取前已被替换")
        result = bytearray()
        while len(result) <= max_bytes:
            chunk = os.read(descriptor, min(8192, max_bytes + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if not _same_file(opened, _regular_lstat(target)):
            raise RuntimeError("本地凭证文件在读取时已被替换")
        return bytes(result)
    finally:
        os.close(descriptor)


class CredentialCipher:
    """AES-256-GCM envelope using a local, versioned master key."""

    VERSION = b"XHS1"

    def __init__(self, key_path: str | Path):
        self.key_path = _absolute_path(key_path)
        if self.key_path.is_symlink():
            raise RuntimeError("本地登录密钥不能是符号链接")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._load_or_create()

    def _load_or_create(self) -> bytes:
        if _optional_regular_lstat(self.key_path) is not None:
            key = read_private_file(self.key_path, max_bytes=33)
            if len(key) != 32:
                raise RuntimeError("本地登录密钥长度无效；请清除本地登录数据后重试")
            return key
        key = os.urandom(32)
        write_private_file(self.key_path, key)
        return key

    def encrypt_json(self, value: Any, *, aad: str) -> bytes:
        nonce = os.urandom(12)
        plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, aad.encode("utf-8"))
        return self.VERSION + nonce + ciphertext

    def decrypt_json(self, envelope: bytes | memoryview, *, aad: str) -> Any:
        payload = bytes(envelope)
        if not payload.startswith(self.VERSION) or len(payload) < len(self.VERSION) + 29:
            raise ValueError("加密数据格式无效")
        nonce_start = len(self.VERSION)
        nonce = payload[nonce_start : nonce_start + 12]
        ciphertext = payload[nonce_start + 12 :]
        plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, aad.encode("utf-8"))
        return json.loads(plaintext.decode("utf-8"))

    def rotate(self) -> None:
        """Replace the persisted key after all encrypted records are deleted."""

        key = os.urandom(32)
        replace_private_file(self.key_path, key)
        self._key = key


def sanitize_url(value: Any, *, allow_hosts: set[str] | None = None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parts = urlsplit(text)
        username = parts.username
        password = parts.password
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not hostname or username is not None or password is not None:
        return None
    host = hostname.lower().rstrip(".")
    normalized_allow_hosts = (
        {item.casefold().rstrip(".") for item in allow_hosts} if allow_hosts is not None else None
    )
    if normalized_allow_hosts is not None and host not in normalized_allow_hosts:
        return None
    query = [
        (key, item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
        if not _is_secret_query_name(key)
    ]
    rendered_host = f"[{host}]" if ":" in host else host
    netloc = f"{rendered_host}:{port}" if port is not None else rendered_host
    return urlunsplit(("https", netloc, parts.path, urlencode(query), ""))


def redact_text(value: Any, *, limit: int = 500) -> str:
    text = str(value or "").replace("\x00", "")
    text = _JSON_SECRET_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]{match.group(2)}", text
    )
    text = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", text)
    text = _HEADER_SECRET_RE.sub(lambda match: f"{match.group(1)}: [REDACTED]", text)
    text = _COOKIE_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)

    def redact_query(match: re.Match[str]) -> str:
        if not _is_secret_query_name(match.group(2)):
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}=[REDACTED]"

    text = _QUERY_VALUE_RE.sub(redact_query, text)
    text = _ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    return text[:limit]


def safe_slug(value: str, *, limit: int = 40) -> str:
    result = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff._-]+", "-", value.strip()).strip("-._")
    return (result or "export")[:limit]
