"""Application assembly, lifecycle, and local-API security boundary."""

from __future__ import annotations

import hmac
import json
import os
import secrets
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from xhs_insight import __version__
from xhs_insight.adapters import AuthManager, RednoteAdapter
from xhs_insight.browser_login import DirectQrLoginManager
from xhs_insight.config import Settings
from xhs_insight.exporting import Exporter
from xhs_insight.jobs import JobService
from xhs_insight.platform import runtime_doctor
from xhs_insight.security import CredentialCipher, replace_private_file
from xhs_insight.storage import Repository
from xhs_insight.web import mount_web

from .router import create_router

SAFE_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(slots=True)
class Backend:
    settings: Settings
    repository: Repository
    cipher: CredentialCipher
    auth: Any
    adapter: Any
    exporter: Exporter
    jobs: JobService
    browser_login: Any | None = dataclass_field(default=None, repr=False)
    _credential_lock: threading.RLock = dataclass_field(
        default_factory=threading.RLock,
        repr=False,
    )

    def collector_doctor(self) -> dict[str, Any]:
        result = {"mode": "live", **runtime_doctor().as_dict()}
        if self.browser_login is not None:
            result.update(self.browser_login.capability())
        return result

    def start(self) -> None:
        self.jobs.start()

    def stop(self) -> None:
        if self.browser_login is not None:
            self.browser_login.close()
        self.jobs.stop()
        self.adapter.close()

    def logout(self) -> None:
        if self.browser_login is not None:
            self.browser_login.cancel()
        with self._credential_lock:
            self.adapter.close()
            self.auth.logout()

    def import_cookie(
        self,
        cookie: str,
        cancelled: Any | None = None,
    ) -> dict[str, Any]:
        """Verify a Cookie against XHS before committing its encrypted state."""

        with self._credential_lock:
            if callable(cancelled) and cancelled():
                raise PermissionError("扫码登录已取消，登录态未保存")
            if self.repository.has_running_or_queued_jobs():
                raise PermissionError("请先取消或暂停正在运行、排队的任务，再更换登录态")
            verified = self.adapter.verify_cookie(cookie)
            # Verification is a network operation. Re-check after it returns so
            # a task queued concurrently cannot have its credential replaced.
            if self.repository.has_running_or_queued_jobs():
                raise PermissionError("验证期间已有任务开始运行，登录态未保存")
            if callable(cancelled) and cancelled():
                raise PermissionError("扫码登录已取消，登录态未保存")
            self.adapter.close()
            return self.auth.persist_verified_login(
                cookie=verified.cookie,
                account_id=verified.account_id,
                host_cookies=verified.host_cookies,
                host_cookie_state=verified.host_cookie_state,
                cookie_source_url=verified.cookie_source_url,
            )

    def clear_all(self) -> None:
        # JobService refuses this operation while work is queued/running.
        # Rotate the master key only after every encrypted record is gone so
        # deleted database pages cannot be recovered with the current key.
        self.jobs.clear_all()
        self.logout()
        self.cipher.rotate()


def create_backend(settings: Settings) -> Backend:
    settings.prepare()
    repository = Repository(settings.state_dir / "xhs-insight.sqlite3")
    cipher = CredentialCipher(settings.state_dir / "master.key")

    auth = AuthManager(repository, cipher)
    adapter = RednoteAdapter(auth)

    exporter = Exporter(
        repository,
        settings.export_dir,
        collector_version=adapter.version,
    )
    jobs = JobService(
        repository,
        cipher,
        adapter,
        exporter,
        settings,
        authenticated=lambda: bool(auth.authenticated),
        account_fingerprint=lambda: auth.account_fingerprint,
    )
    backend = Backend(settings, repository, cipher, auth, adapter, exporter, jobs)
    backend.browser_login = DirectQrLoginManager(
        settings.state_dir,
        backend.import_cookie,
        repository.has_running_or_queued_jobs,
    )
    return backend


def _request_host(request: Request) -> tuple[str | None, int | None]:
    raw = request.headers.get("host", "")
    if not raw or any(character in raw for character in "@/\\\r\n\t"):
        return None, None
    try:
        parsed = urlsplit(f"http://{raw}")
        return (parsed.hostname or "").lower().rstrip("."), parsed.port
    except ValueError:
        return None, None


def _origin_is_local(value: str, expected_port: int) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return (
        parsed.scheme == "http"
        and (parsed.hostname or "").lower().rstrip(".") in SAFE_HOSTS
        and port == expected_port
        and not parsed.username
        and not parsed.password
        and not parsed.path.rstrip("/")
        and not parsed.query
        and not parsed.fragment
    )


class LocalSecurityMiddleware(BaseHTTPMiddleware):
    """Require an in-process Web session or the per-instance CLI token."""

    def __init__(
        self,
        app: Any,
        *,
        port: int,
        web_session: str,
        csrf_token: str,
        local_token: str,
    ) -> None:
        super().__init__(app)
        self.port = int(port)
        self.web_session = web_session
        self.csrf_token = csrf_token
        self.local_token = local_token

    @staticmethod
    def _same(left: str | None, right: str) -> bool:
        return bool(left) and hmac.compare_digest(str(left), right)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        host, port = _request_host(request)
        request_port = port or 80
        if host not in SAFE_HOSTS or not 1 <= request_port <= 65535:
            return JSONResponse(status_code=400, content={"detail": "invalid local Host"})

        origin = request.headers.get("origin")
        if origin and not _origin_is_local(origin, request_port):
            return JSONResponse(status_code=403, content={"detail": "invalid local Origin"})

        is_api = request.url.path.startswith("/api/")
        is_health = request.url.path == "/api/v1/health" and request.method in SAFE_METHODS
        cli_ok = self._same(request.headers.get("x-xhs-local-token"), self.local_token)
        web_ok = self._same(request.cookies.get("xhs_session"), self.web_session)

        if is_api and not is_health and not (cli_ok or web_ok):
            return JSONResponse(
                status_code=401,
                content={
                    "detail": {
                        "code": "LOCAL_AUTH_REQUIRED",
                        "message": "本地会话无效，请刷新页面或重新启动 CLI。",
                    }
                },
            )
        if is_api and request.method not in SAFE_METHODS and not cli_ok:
            cookie_ok = self._same(request.cookies.get("xhs_csrf"), self.csrf_token)
            header_ok = self._same(request.headers.get("x-xhs-csrf"), self.csrf_token)
            if not (web_ok and cookie_ok and header_ok):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": {
                            "code": "CSRF_REJECTED",
                            "message": "本地请求校验失败，请刷新页面后重试。",
                        }
                    },
                )

        response = await call_next(request)
        if request.url.path == "/":
            response.set_cookie(
                "xhs_session",
                self.web_session,
                httponly=True,
                samesite="strict",
                secure=False,
                path="/",
            )
            response.set_cookie(
                "xhs_csrf",
                self.csrf_token,
                httponly=False,
                samesite="strict",
                secure=False,
                path="/",
            )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'; img-src 'self' data: blob:; "
            "script-src 'self'; style-src 'self'; connect-src 'self'",
        )
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if is_api:
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def _write_instance_file(path: Path, *, port: int, local_token: str) -> None:
    payload = {
        "api_url": f"http://127.0.0.1:{port}/api/v1",
        "local_token": local_token,
        "pid": os.getpid(),
        "version": __version__,
    }
    encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    replace_private_file(path, encoded)


def create_app(
    settings: Settings | None = None,
    *,
    backend: Backend | None = None,
) -> FastAPI:
    effective_settings = settings or Settings.from_env()
    effective_backend = backend or create_backend(effective_settings)
    web_session = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    local_token = secrets.token_urlsafe(48)
    instance_path = effective_settings.state_dir / "instance.json"

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        _write_instance_file(instance_path, port=effective_settings.port, local_token=local_token)
        effective_backend.start()
        try:
            yield
        finally:
            effective_backend.stop()
            try:
                current = json.loads(instance_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                current = {}
            if current.get("local_token") == local_token:
                instance_path.unlink(missing_ok=True)

    app = FastAPI(
        title="CrimsonFlux local API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.backend = effective_backend
    app.state.local_token = local_token

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, error: RequestValidationError
    ) -> JSONResponse:
        messages = [str(item.get("msg") or "输入无效") for item in error.errors()[:5]]
        return JSONResponse(
            status_code=422,
            content={
                "detail": {
                    "code": "VALIDATION_ERROR",
                    "message": "；".join(messages),
                    "retryable": False,
                }
            },
        )

    app.add_middleware(
        LocalSecurityMiddleware,
        port=effective_settings.port,
        web_session=web_session,
        csrf_token=csrf_token,
        local_token=local_token,
    )
    app.include_router(create_router(effective_backend))
    mount_web(app)
    return app


__all__ = ["Backend", "LocalSecurityMiddleware", "create_app", "create_backend"]
