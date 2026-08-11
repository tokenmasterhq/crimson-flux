"""Small, local-only HTTP client shared by CLI commands."""

from __future__ import annotations

import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from xhs_insight.config import default_state_dir

LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
DEFAULT_API_URL = "http://127.0.0.1:8765/api/v1"
INSTANCE_FILENAME = "instance.json"


class ClientConfigurationError(RuntimeError):
    """The local instance metadata is missing or unsafe."""


class ApiError(RuntimeError):
    """A structured local API failure with a safe public message."""

    def __init__(self, message: str, *, code: str | None = None, status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status


def instance_file() -> Path:
    return default_state_dir() / INSTANCE_FILENAME


def _read_instance(path: Path, expected: os.stat_result | None) -> dict[str, Any]:
    if expected is None:
        return {}
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode):
            raise ClientConfigurationError(f"拒绝读取非普通实例文件：{path}")
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise ClientConfigurationError(f"实例文件在读取期间已被替换，已拒绝读取：{path}")
        if os.name != "nt" and stat.S_IMODE(current.st_mode) & 0o077:
            raise ClientConfigurationError(
                f"拒绝读取权限不安全的实例文件：{path}（应为普通 0600 文件）"
            )
        handle = os.fdopen(descriptor, "r", encoding="utf-8")
        descriptor = -1
        with handle:
            raw_payload = handle.read()
    except FileNotFoundError:
        return {}
    except ClientConfigurationError:
        raise
    except OSError as exc:
        raise ClientConfigurationError(f"无法读取本地实例信息：{path}（{exc}）") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise ClientConfigurationError(f"本地实例信息不是有效 JSON：{path}（{exc}）") from exc
    if not isinstance(payload, dict):
        raise ClientConfigurationError(f"本地实例信息格式不正确：{path}")
    return payload


def _validate_instance_file(path: Path) -> os.stat_result | None:
    """Reject unsafe instance metadata before following or reading the path."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ClientConfigurationError(f"无法检查本地实例信息：{path}（{exc}）") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ClientConfigurationError(f"拒绝读取符号链接实例文件：{path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ClientConfigurationError(f"拒绝读取非普通实例文件：{path}")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ClientConfigurationError(
            f"拒绝读取权限不安全的实例文件：{path}（应为普通 0600 文件）"
        )
    return metadata


def normalize_api_url(value: str) -> str:
    raw = value.strip().rstrip("/")
    if not raw:
        raise ClientConfigurationError("本地 API 地址不能为空")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or host not in LOCAL_HOSTS:
        raise ClientConfigurationError("为防止本地令牌泄露，CLI 只允许连接 localhost/127.0.0.1/::1")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ClientConfigurationError("本地 API 地址不能包含账号、查询参数或片段")
    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v1"):
        path = f"{path}/api/v1" if path else "/api/v1"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


@dataclass(frozen=True, slots=True)
class ClientConfig:
    api_url: str
    local_token: str | None
    instance_path: Path

    @classmethod
    def load(cls, *, require_token: bool = True) -> ClientConfig:
        path = instance_file()
        expected = _validate_instance_file(path)
        instance = _read_instance(path, expected)
        api_url = normalize_api_url(
            os.getenv("CRIMSONFLUX_API_URL")
            or os.getenv("XHS_INSIGHT_API_URL")
            or str(instance.get("api_url") or DEFAULT_API_URL)
        )
        local_token_value = (
            os.getenv("CRIMSONFLUX_LOCAL_TOKEN")
            or os.getenv("XHS_INSIGHT_LOCAL_TOKEN")
            or instance.get("local_token")
        )
        local_token = str(local_token_value).strip() if local_token_value else None
        if require_token and not local_token:
            raise ClientConfigurationError(
                f"未找到本地服务令牌。请先运行 `crimsonflux serve`；实例信息应位于 {path}"
            )
        return cls(api_url=api_url, local_token=local_token, instance_path=path)


def _error_from_response(response: httpx.Response) -> ApiError:
    payload: Any = None
    try:
        payload = response.json()
    except ValueError:
        payload = response.text.strip()
    detail = payload.get("detail") if isinstance(payload, dict) else None
    error = payload.get("error") if isinstance(payload, dict) else None
    candidate = error or detail or payload
    if isinstance(candidate, dict):
        message = str(candidate.get("message") or candidate.get("msg") or "").strip()
        code_value = candidate.get("code")
    else:
        message = str(candidate or "").strip()
        code_value = payload.get("code") if isinstance(payload, dict) else None
    if not message:
        message = f"本地服务返回错误（HTTP {response.status_code}）"
    return ApiError(message, code=str(code_value) if code_value else None, status=response.status_code)


def _safe_filename(value: str) -> str | None:
    # Content-Disposition is advisory only. Never allow it to escape the chosen directory.
    match = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';]+)', value, flags=re.IGNORECASE)
    if not match:
        return None
    filename = Path(match.group(1).strip()).name
    return filename if filename not in {"", ".", ".."} else None


class ApiClient:
    def __init__(self, config: ClientConfig, *, timeout: float = 30.0):
        headers = {"Accept": "application/json"}
        if config.local_token:
            headers["X-XHS-Local-Token"] = config.local_token
        self.config = config
        self._client = httpx.Client(
            base_url=config.api_url.rstrip("/") + "/",
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
            follow_redirects=False,
            trust_env=False,
        )

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, path: str, *, json_body: Any = None) -> Any:
        try:
            response = self._client.request(method, path.lstrip("/"), json=json_body)
        except httpx.ConnectError as exc:
            raise ApiError(
                f"无法连接 {self.config.api_url}。请确认 `crimsonflux serve` 正在运行。",
                code="OFFLINE",
            ) from exc
        except httpx.TimeoutException as exc:
            raise ApiError("本地服务响应超时。任务可能仍在后台运行。", code="TIMEOUT") from exc
        except httpx.HTTPError as exc:
            raise ApiError(f"本地请求失败：{exc}", code="HTTP_ERROR") from exc
        if not response.is_success:
            raise _error_from_response(response)
        if response.status_code == 204 or not response.content:
            return None
        try:
            payload = response.json()
        except ValueError as exc:
            raise ApiError("本地服务返回了无法解析的响应。", code="INVALID_RESPONSE") from exc
        return payload.get("data") if isinstance(payload, dict) and "data" in payload else payload

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, body: Any | None = None) -> Any:
        return self.request("POST", path, json_body={} if body is None else body)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)

    def download(self, path: str, target: Path) -> tuple[Path, str | None]:
        target = target.expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.part")
        try:
            with self._client.stream("GET", path.lstrip("/")) as response:
                if not response.is_success:
                    response.read()
                    raise _error_from_response(response)
                disposition = response.headers.get("content-disposition", "")
                suggested = _safe_filename(disposition)
                with temporary.open("wb") as handle:
                    for chunk in response.iter_bytes():
                        handle.write(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            os.replace(temporary, target)
            return target, suggested
        except httpx.ConnectError as exc:
            raise ApiError(
                f"无法连接 {self.config.api_url}。请确认本地服务正在运行。", code="OFFLINE"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ApiError("下载超时，请稍后重试。", code="TIMEOUT") from exc
        except httpx.HTTPError as exc:
            raise ApiError(f"下载过程中连接中断：{exc}", code="HTTP_ERROR") from exc
        finally:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
