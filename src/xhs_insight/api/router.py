"""Collection, authentication and export routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, SecretStr, field_validator

from xhs_insight import __version__
from xhs_insight.domain import AdapterErrorCode, ConfirmDetailsRequest, CreateJobRequest, FieldGroup


def _http_error(error: BaseException, *, default_status: int = 422) -> HTTPException:
    if isinstance(error, PermissionError):
        status = 409
    elif isinstance(error, KeyError):
        status = 404
    elif isinstance(error, FileNotFoundError):
        status = 409
    else:
        status = default_status
    code = getattr(getattr(error, "code", None), "value", None) or getattr(error, "code", None)
    return HTTPException(
        status_code=status,
        detail={
            "code": str(code or type(error).__name__).upper(),
            "message": str(getattr(error, "public_message", str(error))),
            "retryable": bool(getattr(error, "retryable", False)),
        },
    )


def _auth_import_error(error: BaseException) -> HTTPException:
    raw_code = getattr(getattr(error, "code", None), "value", None) or getattr(
        error, "code", None
    )
    code = str(raw_code or "AUTH_IMPORT_FAILED")
    statuses = {
        AdapterErrorCode.AUTH_EXPIRED.value: 401,
        AdapterErrorCode.RATE_LIMITED.value: 429,
        AdapterErrorCode.RISK_CONTROLLED.value: 429,
        AdapterErrorCode.NETWORK_ERROR.value: 503,
        AdapterErrorCode.SIGNER_FAILED.value: 503,
        AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED.value: 502,
        AdapterErrorCode.UPSTREAM_UNSUPPORTED.value: 503,
    }
    public_messages = {
        AdapterErrorCode.AUTH_EXPIRED.value: "Cookie 已失效或无法通过账号验证，请重新复制。",
        AdapterErrorCode.RATE_LIMITED.value: "平台暂时限制了账号验证请求，请稍后重试。",
        AdapterErrorCode.RISK_CONTROLLED.value: "平台拒绝了账号验证请求，请稍后重试。",
        AdapterErrorCode.NETWORK_ERROR.value: "账号验证网络请求失败，请检查连接后重试。",
        AdapterErrorCode.SIGNER_FAILED.value: "本地签名运行时不可用。",
        AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED.value: "账号验证接口返回结构已变化。",
        AdapterErrorCode.UPSTREAM_UNSUPPORTED.value: "固定登录运行时未达到安全启用条件。",
    }
    return HTTPException(
        status_code=statuses.get(code, 503),
        detail={
            "code": code,
            "message": public_messages.get(code, "登录态验证失败。"),
            "retryable": bool(getattr(error, "retryable", False)),
        },
    )


def _browser_login_error(error: BaseException) -> HTTPException:
    if isinstance(error, PermissionError):
        status = 409
        code = "BROWSER_LOGIN_CONFLICT"
        message = str(error)
    else:
        code = str(getattr(error, "code", None) or "BROWSER_LOGIN_UNAVAILABLE")
        status = 409 if code in {"QR_NOT_READY", "LOGIN_EXPIRED"} else 503
        message = str(
            getattr(
                error,
                "public_message",
                "当前环境无法安全启动官方浏览器扫码登录。",
            )
        )
    return HTTPException(
        status_code=status,
        detail={"code": code, "message": message, "retryable": status == 503},
    )


class CookieImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cookie: SecretStr

    @field_validator("cookie")
    @classmethod
    def validate_cookie(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not 1 <= len(raw) <= 16_384:
            raise ValueError("Cookie 长度必须在 1–16384 个字符之间")
        if any(character in raw for character in ("\r", "\n", "\0")):
            raise ValueError("Cookie 不能包含换行或空字节")
        return value


def _require_collector_capability(backend: Any, capability: str, message: str) -> None:
    doctor = backend.collector_doctor()
    if bool(doctor.get(capability)):
        return
    raise HTTPException(
        status_code=503,
        detail={
            "code": "COLLECTOR_NOT_READY",
            "message": message,
            "retryable": False,
        },
    )


def create_router(backend: Any) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.get("/health")
    async def health() -> dict[str, Any]:
        doctor = (
            backend.collector_doctor()
            if hasattr(backend, "collector_doctor")
            else backend.adapter.doctor()
            if hasattr(backend.adapter, "doctor")
            else {}
        )
        ready = bool(
            doctor.get("collection_runtime_ok") and doctor.get("cookie_import_supported")
        )
        return {
            "status": "ok" if ready else "degraded",
            "service": "crimsonflux",
            "version": __version__,
            "collector": doctor,
            "limits": {
                "keyword": backend.settings.max_keyword_items,
                "user": backend.settings.max_user_items,
                "pause_min_seconds": backend.settings.pause_min_seconds,
                "pause_max_seconds": backend.settings.pause_max_seconds,
            },
        }

    @router.get("/field-presets")
    async def field_presets() -> dict[str, Any]:
        return {
            "presets": {
                "basic": ["author"],
                "full": [field.value for field in FieldGroup],
                "custom": [field.value for field in FieldGroup],
            },
            "detail_fields": ["body", "tags", "metrics", "media"],
        }

    @router.get("/auth/status")
    async def auth_status() -> dict[str, Any]:
        return backend.auth.status()

    @router.post("/auth/import")
    async def import_cookie(payload: CookieImportRequest) -> dict[str, Any]:
        _require_collector_capability(
            backend,
            "cookie_import_supported",
            "Cookie 导入安全运行时未就绪，请先修复健康检查中的阻断项。",
        )
        try:
            return backend.import_cookie(payload.cookie.get_secret_value())
        except Exception as error:
            raise _auth_import_error(error) from error

    @router.post("/auth/browser", status_code=202)
    async def start_browser_login() -> dict[str, Any]:
        _require_collector_capability(
            backend,
            "cookie_import_supported",
            "账号验证安全运行时未就绪，请先修复健康检查中的阻断项。",
        )
        manager = getattr(backend, "browser_login", None)
        if manager is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "BROWSER_LOGIN_UNAVAILABLE",
                    "message": "当前环境不支持官方浏览器扫码登录，请使用手动 Cookie 导入。",
                    "retryable": False,
                },
            )
        try:
            return manager.start()
        except Exception as error:
            raise _browser_login_error(error) from error

    @router.get("/auth/browser/status")
    async def browser_login_status() -> dict[str, Any]:
        manager = getattr(backend, "browser_login", None)
        if manager is None:
            return {
                "browser_login_supported": False,
                "status": "idle",
                "message": "当前环境不支持自动打开官方网页登录窗口。",
            }
        return manager.status()

    @router.get("/auth/browser/qr")
    async def browser_login_qr() -> Response:
        manager = getattr(backend, "browser_login", None)
        if manager is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "BROWSER_LOGIN_UNAVAILABLE",
                    "message": "当前环境不支持页面内扫码登录。",
                    "retryable": False,
                },
            )
        capability = manager.capability() if hasattr(manager, "capability") else {}
        if capability.get("browser_login_embedded_qr") is not True:
            raise HTTPException(
                status_code=410,
                detail={
                    "code": "EMBEDDED_QR_DISABLED",
                    "message": "页面内二维码已停用；请使用隔离的官方网页登录窗口。",
                    "retryable": False,
                },
            )
        try:
            image, revision = manager.qr_image()
        except Exception as error:
            raise _browser_login_error(error) from error
        return Response(
            content=image,
            media_type="image/png",
            headers={
                "Cache-Control": "private, no-store, max-age=0, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
                "ETag": f'"qr-{revision}"',
                "X-Content-Type-Options": "nosniff",
                "X-XHS-QR-Revision": revision,
            },
        )

    @router.delete("/auth/browser")
    async def cancel_browser_login() -> dict[str, Any]:
        manager = getattr(backend, "browser_login", None)
        if manager is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "BROWSER_LOGIN_UNAVAILABLE",
                    "message": "当前环境不支持官方浏览器扫码登录。",
                    "retryable": False,
                },
            )
        return manager.cancel()

    @router.delete("/auth/session", status_code=204)
    async def logout() -> Response:
        backend.logout()
        return Response(status_code=204)

    @router.post("/jobs", status_code=202)
    async def create_job(payload: CreateJobRequest) -> dict[str, Any]:
        _require_collector_capability(
            backend,
            "collection_runtime_ok",
            "采集运行时未就绪，请先修复健康检查中的阻断项。",
        )
        try:
            return backend.jobs.create(payload)
        except Exception as error:
            raise _http_error(error) from error

    @router.get("/jobs")
    async def list_jobs(limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
        return {"items": backend.jobs.list(limit=limit)}

    @router.get("/jobs/{job_id}")
    async def get_job(job_id: str) -> dict[str, Any]:
        try:
            return backend.jobs.get(job_id)
        except Exception as error:
            raise _http_error(error) from error

    @router.post("/jobs/{job_id}/confirm-details")
    async def confirm_details(job_id: str, payload: ConfirmDetailsRequest) -> dict[str, Any]:
        try:
            return backend.jobs.confirm_details(job_id, payload)
        except Exception as error:
            raise _http_error(error) from error

    @router.post("/jobs/{job_id}/resume")
    async def resume_job(job_id: str) -> dict[str, Any]:
        try:
            return backend.jobs.resume(job_id)
        except Exception as error:
            raise _http_error(error) from error

    @router.post("/jobs/{job_id}/cancel")
    async def cancel_job(job_id: str) -> dict[str, Any]:
        try:
            return backend.jobs.cancel(job_id)
        except Exception as error:
            raise _http_error(error) from error

    @router.post("/jobs/{job_id}/retry-details")
    async def retry_details(job_id: str) -> dict[str, Any]:
        try:
            return backend.jobs.retry_details(job_id)
        except Exception as error:
            raise _http_error(error) from error

    @router.get("/jobs/{job_id}/exports/{artifact}")
    async def export(job_id: str, artifact: str) -> FileResponse:
        media_types = {
            "csv": "text/csv; charset=utf-8",
            "jsonl": "application/x-ndjson",
            "manifest": "application/json",
        }
        if artifact not in media_types:
            raise HTTPException(status_code=404, detail="导出类型不存在")
        try:
            path = backend.jobs.export_path(job_id, artifact)
        except Exception as error:
            raise _http_error(error) from error
        return FileResponse(path, filename=path.name, media_type=media_types[artifact])

    @router.delete("/data", status_code=204)
    async def clear_data() -> Response:
        try:
            backend.clear_all()
        except Exception as error:
            raise _http_error(error) from error
        return Response(status_code=204)

    return router
