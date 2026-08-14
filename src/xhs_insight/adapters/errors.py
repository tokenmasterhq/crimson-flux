"""Stable adapter failures for volatile upstream behaviour."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from xhs_insight.domain import AdapterErrorCode, PublicError
from xhs_insight.security import redact_text

_DEFAULTS: dict[AdapterErrorCode, tuple[str, bool]] = {
    AdapterErrorCode.AUTH_EXPIRED: ("登录状态已失效，请重新导入 Cookie 后继续。", True),
    AdapterErrorCode.RATE_LIMITED: ("请求过于频繁，任务已暂停，请稍后继续。", True),
    AdapterErrorCode.RISK_CONTROLLED: ("平台触发了访问限制，已有数据已保留。", True),
    AdapterErrorCode.NETWORK_ERROR: ("网络请求失败，请检查连接后继续。", True),
    AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED: ("上游返回结构发生变化，请更新适配器。", False),
    AdapterErrorCode.UPSTREAM_UNSUPPORTED: ("当前上游能力未达到安全启用条件。", False),
    AdapterErrorCode.SIGNER_FAILED: ("本地签名运行时不可用。", True),
    AdapterErrorCode.CANCELLED: ("任务已取消。", True),
    AdapterErrorCode.INVALID_PROFILE_URL: ("小红书用户主页地址无效。", False),
    AdapterErrorCode.RESUME_INCOMPATIBLE: ("当前版本无法继续旧游标，请创建新任务。", False),
    AdapterErrorCode.ACCOUNT_CHANGED: ("登录账号已变化，不能继续旧任务。", False),
    AdapterErrorCode.DISK_FULL: ("磁盘空间不足。", True),
    AdapterErrorCode.INTERNAL_ERROR: ("采集遇到未预期错误。", True),
    AdapterErrorCode.REQUEST_BUDGET_EXHAUSTED: (
        "任务已达到本地安全请求预算，已停止继续请求。",
        False,
    ),
}


@dataclass(eq=False)
class AdapterError(Exception):
    code: AdapterErrorCode
    message: str | None = None
    retryable: bool | None = None
    detail: str = ""
    retry_after: int | None = None

    def __post_init__(self) -> None:
        default_message, default_retryable = _DEFAULTS[self.code]
        self.message = self.message or default_message
        if self.retryable is None:
            self.retryable = default_retryable
        if type(self.retry_after) is not int or self.retry_after < 0:
            self.retry_after = None
        self.detail = redact_text(self.detail, limit=500)
        super().__init__(self.message)

    def public(self, *, request_id: str | None = None) -> PublicError:
        return PublicError(
            code=self.code,
            message=str(self.message),
            retryable=bool(self.retryable),
            request_id=request_id,
        )

    def as_dict(self, *, request_id: str | None = None) -> dict[str, Any]:
        return self.public(request_id=request_id).model_dump(mode="json")


def classify_upstream_error(
    error: BaseException | str,
    *,
    default: AdapterErrorCode = AdapterErrorCode.INTERNAL_ERROR,
) -> AdapterError:
    if isinstance(error, AdapterError):
        return error
    detail = redact_text(error, limit=500)
    normalized = detail.casefold()
    if isinstance(error, OSError) and getattr(error, "errno", None) == 28:
        code = AdapterErrorCode.DISK_FULL
    elif any(token in normalized for token in ("remote jsvmp", "runinthiscontext", "unsafe signer")):
        code = AdapterErrorCode.UPSTREAM_UNSUPPORTED
    elif any(token in normalized for token in ("429", "too many", "rate limit", "请求频繁", "频繁")):
        code = AdapterErrorCode.RATE_LIMITED
    elif any(token in normalized for token in ("risk", "风控", "captcha", "verify challenge", "406")):
        code = AdapterErrorCode.RISK_CONTROLLED
    elif any(
        token in normalized
        for token in ("invalid cursor", "cursor expired", "cursor invalid", "游标失效")
    ):
        code = AdapterErrorCode.RESUME_INCOMPATIBLE
    elif any(
        token in normalized
        for token in ("unauthorized", "auth expired", "web_session", "登录已失效", "not logged")
    ):
        code = AdapterErrorCode.AUTH_EXPIRED
    elif re.search(r"\b(?:http\s*)?5(?:00|02|03|04)\b", normalized) or any(
        token in normalized
        for token in ("timeout", "timed out", "connection", "network", "dns", "网络")
    ):
        code = AdapterErrorCode.NETWORK_ERROR
    elif isinstance(error, (KeyError, TypeError, IndexError)) or any(
        token in normalized for token in ("schema", "missing field", "数据结构")
    ):
        code = AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED
    else:
        code = default
    return AdapterError(code=code, detail=detail)


__all__ = ["AdapterError", "classify_upstream_error"]
