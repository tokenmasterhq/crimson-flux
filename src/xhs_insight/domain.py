"""Stable domain contracts shared by Web, CLI, jobs and exports."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StringEnum(StrEnum):
    pass


class SourceType(StringEnum):
    KEYWORD = "keyword"
    USER = "user"


class ContentPreset(StringEnum):
    BASIC = "basic"
    FULL = "full"
    CUSTOM = "custom"


class FieldGroup(StringEnum):
    AUTHOR = "author"
    BODY = "body"
    TAGS = "tags"
    METRICS = "metrics"
    MEDIA = "media"


DETAIL_FIELD_GROUPS = frozenset(
    {FieldGroup.BODY, FieldGroup.TAGS, FieldGroup.METRICS, FieldGroup.MEDIA}
)
FULL_FIELD_GROUPS = frozenset(FieldGroup)
BASIC_FIELD_GROUPS = frozenset({FieldGroup.AUTHOR})


class JobStatus(StringEnum):
    QUEUED = "queued"
    ENUMERATING = "enumerating"
    AWAITING_DETAIL_CONFIRMATION = "awaiting_detail_confirmation"
    FETCHING_DETAILS = "fetching_details"
    EXPORTING = "exporting"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    PAUSED_AUTH = "paused_auth"
    PAUSED_RATE_LIMIT = "paused_rate_limit"
    PAUSED_INTERRUPTED = "paused_interrupted"
    PAUSED_CURSOR_INVALID = "paused_cursor_invalid"
    CANCELLED = "cancelled"
    FAILED = "failed"


ACTIVE_STATUSES = frozenset(
    {JobStatus.ENUMERATING, JobStatus.FETCHING_DETAILS, JobStatus.EXPORTING}
)
TERMINAL_STATUSES = frozenset(
    {JobStatus.COMPLETED, JobStatus.COMPLETED_WITH_WARNINGS, JobStatus.CANCELLED, JobStatus.FAILED}
)
RESUMABLE_STATUSES = frozenset(
    {
        JobStatus.PAUSED_AUTH,
        JobStatus.PAUSED_RATE_LIMIT,
        JobStatus.PAUSED_INTERRUPTED,
        JobStatus.CANCELLED,
    }
)


class KeywordSource(BaseModel):
    type: Literal[SourceType.KEYWORD] = SourceType.KEYWORD
    keyword: Annotated[str, Field(min_length=1, max_length=100)]
    limit: Annotated[int, Field(ge=1)] = 50

    @field_validator("keyword")
    @classmethod
    def normalize_keyword(cls, value: str) -> str:
        result = " ".join(value.split())
        if not result:
            raise ValueError("关键词不能为空")
        return result


class UserSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal[SourceType.USER] = SourceType.USER
    profile_url: Annotated[str, Field(min_length=20, max_length=2048)]
    all: Literal[True] = True
    profile_access: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)

    @model_validator(mode="before")
    @classmethod
    def extract_profile_access(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        if "profile_access" in payload:
            raise ValueError("profile_access 不能作为独立字段提交")
        raw_url = str(payload.get("profile_url") or "").strip()
        parsed = urlparse(raw_url)
        query = parse_qs(parsed.query, keep_blank_values=False)
        payload["profile_access"] = {
            key: str(query[key][-1])[:2048]
            for key in ("xsec_token", "xsec_source")
            if query.get(key) and str(query[key][-1]).strip()
        }
        payload["profile_url"] = parsed._replace(query="", fragment="").geturl()
        return payload

    @field_validator("profile_url")
    @classmethod
    def validate_profile_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        host = (parsed.hostname or "").lower().rstrip(".")
        if (
            parsed.scheme != "https"
            or host not in {"www.xiaohongshu.com", "xiaohongshu.com"}
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("请输入 https://www.xiaohongshu.com/user/profile/... 完整主页地址")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 3 or parts[:2] != ["user", "profile"] or not parts[2]:
            raise ValueError("小红书用户主页地址格式不正确")
        return f"https://www.xiaohongshu.com/user/profile/{parts[2]}"


class ContentSelection(BaseModel):
    preset: ContentPreset = ContentPreset.BASIC
    fields: set[FieldGroup] = Field(default_factory=set)

    @model_validator(mode="after")
    def resolve_fields(self) -> ContentSelection:
        if self.preset == ContentPreset.BASIC:
            self.fields = set(BASIC_FIELD_GROUPS)
        elif self.preset == ContentPreset.FULL:
            self.fields = set(FULL_FIELD_GROUPS)
        elif not self.fields:
            raise ValueError("custom 模式至少选择一个字段组")
        return self

    @property
    def needs_details(self) -> bool:
        return bool(DETAIL_FIELD_GROUPS.intersection(self.fields))


class CreateJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: KeywordSource | UserSource = Field(discriminator="type")
    content: ContentSelection = Field(default_factory=ContentSelection)
    preapprove_details: bool = False


class ConfirmDetailsRequest(BaseModel):
    content: ContentSelection


class JobEstimate(BaseModel):
    list_requests: int | None
    detail_requests: int
    minimum_seconds: int
    maximum_seconds: int
    approximate: bool = True


class AdapterErrorCode(StringEnum):
    AUTH_EXPIRED = "AUTH_EXPIRED"
    RATE_LIMITED = "RATE_LIMITED"
    RISK_CONTROLLED = "RISK_CONTROLLED"
    NETWORK_ERROR = "NETWORK_ERROR"
    UPSTREAM_SCHEMA_CHANGED = "UPSTREAM_SCHEMA_CHANGED"
    UPSTREAM_UNSUPPORTED = "UPSTREAM_UNSUPPORTED"
    SIGNER_FAILED = "SIGNER_FAILED"
    CANCELLED = "CANCELLED"
    INVALID_PROFILE_URL = "INVALID_PROFILE_URL"
    RESUME_INCOMPATIBLE = "RESUME_INCOMPATIBLE"
    ACCOUNT_CHANGED = "ACCOUNT_CHANGED"
    DISK_FULL = "DISK_FULL"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class PublicError(BaseModel):
    code: AdapterErrorCode
    message: str
    retryable: bool = False
    request_id: str | None = None


class PageResult(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: dict[str, Any] | None
    has_more: bool
    raw_item_count: int = 0
    skipped_item_count: int = 0


class DetailResult(BaseModel):
    note_id: str
    fields: dict[str, Any]
