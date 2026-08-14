"""Typer commands for running and operating the local CrimsonFlux service."""

from __future__ import annotations

import json
import math
import os
import stat
import sys
import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import typer
from pydantic import ValidationError

from xhs_insight import __version__
from xhs_insight.cli.client import (
    ApiClient,
    ApiError,
    ClientConfig,
    ClientConfigurationError,
)
from xhs_insight.domain import (
    ContentPreset,
    ContentSelection,
    CreateJobRequest,
    FieldGroup,
    KeywordSource,
    UserSource,
)

DEFAULT_LIMIT = 50
DEFAULT_MAX_KEYWORD_ITEMS = 1000
DEFAULT_PAUSE_MIN_SECONDS = 2.0
DEFAULT_PAUSE_MAX_SECONDS = 4.0
MAX_SAFE_DEADLINE = datetime(9998, 12, 31, 23, 59, 59, tzinfo=UTC)
SENSITIVE_QUERY_EXACT = frozenset(
    {
        "a1",
        "auth",
        "cookie",
        "session",
        "sign",
        "signature",
        "token",
        "web_session",
        "x-s",
        "x-t",
        "xsec_source",
        "xsec_token",
    }
)
SENSITIVE_QUERY_PARTS = (
    "auth",
    "cookie",
    "credential",
    "secret",
    "session",
    "sign",
    "token",
    "xsec",
)
DETAIL_FIELDS = frozenset(
    {FieldGroup.BODY, FieldGroup.TAGS, FieldGroup.METRICS, FieldGroup.MEDIA}
)
STATUS_LABELS = {
    "queued": "等待运行",
    "enumerating": "列出笔记",
    "awaiting_detail_confirmation": "等你确认更多信息",
    "fetching_details": "正在读取更多信息",
    "exporting": "生成文件",
    "completed": "已完成",
    "completed_with_warnings": "完成（有缺失）",
    "paused_auth": "登录失效，已暂停",
    "paused_rate_limit": "平台要求等待，已暂停",
    "paused_interrupted": "服务中断，已暂停",
    "paused_cursor_invalid": "翻页位置失效，请新建任务",
    "cancelled": "已取消",
    "failed": "失败",
}
WATCH_STOP_STATUSES = frozenset(
    {
        "paused_auth",
        "paused_rate_limit",
        "paused_interrupted",
        "paused_cursor_invalid",
        "completed",
        "completed_with_warnings",
        "cancelled",
        "failed",
    }
)


def _bounded_deadline(base: datetime, seconds: float) -> datetime:
    try:
        deadline = base + timedelta(seconds=seconds)
    except OverflowError:
        return MAX_SAFE_DEADLINE
    normalized = deadline.replace(tzinfo=UTC) if deadline.tzinfo is None else deadline.astimezone(UTC)
    return min(normalized, MAX_SAFE_DEADLINE)

app = typer.Typer(
    name="crimsonflux",
    no_args_is_help=True,
    add_completion=False,
    help="本地小红书公开笔记采集与 CSV/JSONL 导出工具。",
)
collect_app = typer.Typer(no_args_is_help=True, help="创建关键词或指定用户采集任务。")
jobs_app = typer.Typer(
    no_args_is_help=False,
    invoke_without_command=True,
    help="查看与控制本地采集任务。",
)
app.add_typer(collect_app, name="collect")
app.add_typer(jobs_app, name="jobs")


class ExportFormat(StrEnum):
    CSV = "csv"
    JSONL = "jsonl"
    MANIFEST = "manifest"
    ALL = "all"


def _fail(error: Exception | str, *, code: int = 1) -> NoReturn:
    message = str(error)
    if isinstance(error, ApiError):
        if error.code == "UPSTREAM_UNSUPPORTED":
            message = (
                "当前采集运行时不可用，请运行 `crimsonflux doctor` 检查阻断项。"
            )
        elif error.code == "AUTH_EXPIRED":
            message = "登录已失效，请运行 `crimsonflux login` 后恢复任务。"
        elif error.code in {"RATE_LIMITED", "RISK_CONTROLLED", "NETWORK_ERROR"}:
            retry_at: datetime | None = None
            if error.retry_after_at:
                try:
                    retry_at = datetime.fromisoformat(
                        error.retry_after_at.replace("Z", "+00:00")
                    )
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=UTC)
                except ValueError:
                    retry_at = None
            if retry_at is None and error.retry_after is not None:
                retry_at = _bounded_deadline(datetime.now(UTC), error.retry_after)
            if retry_at and retry_at > datetime.now(UTC):
                remaining = max(
                    1, math.ceil((retry_at - datetime.now(UTC)).total_seconds())
                )
                local_now = datetime.now().astimezone()
                try:
                    local_retry = retry_at.astimezone()
                except (OSError, OverflowError):
                    # Windows' CRT rejects timestamps near datetime.max.
                    # A fixed local offset preserves a useful bounded display
                    # without asking the operating system to convert that date.
                    local_retry = retry_at.astimezone(local_now.tzinfo)
                label = local_retry.strftime(
                    "%H:%M:%S"
                    if local_retry.date() == local_now.date()
                    else "%Y-%m-%d %H:%M:%S"
                )
                reason = (
                    "服务或网络暂时不可用"
                    if error.code == "NETWORK_ERROR"
                    else "平台要求暂时等待"
                )
                message = f"{reason}；请在本地时间 {label} 后重试（约 {remaining} 秒）。"
            else:
                message = message or (
                    "服务或网络暂时不可用，请稍后重试。"
                    if error.code == "NETWORK_ERROR"
                    else "平台暂时限制请求，任务已安全暂停，请稍后恢复。"
                )
        elif error.code == "REQUEST_BUDGET_EXHAUSTED":
            message = "已达到本地安全请求上限。请下载已有结果，并缩小范围后创建新任务。"
        prefix = f"[{error.code}] " if error.code else ""
        message = prefix + message
    typer.secho(f"错误：{message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)


def _client(*, timeout: float = 30.0, require_token: bool = True) -> ApiClient:
    try:
        config = ClientConfig.load(require_token=require_token)
        return ApiClient(config, timeout=timeout)
    except ClientConfigurationError as exc:
        _fail(exc, code=2)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _as_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _health(client: ApiClient) -> dict[str, Any]:
    payload = client.get("/health")
    if not isinstance(payload, dict):
        raise ApiError("本地服务未返回有效运行配置。", code="INVALID_RESPONSE")
    return _as_dict(payload)


def _health_limits(health: dict[str, Any]) -> tuple[int, int, float, float]:
    limits = _as_dict(health.get("limits"))
    try:
        keyword = max(1, int(limits.get("keyword") or DEFAULT_MAX_KEYWORD_ITEMS))
        user = max(0, int(limits.get("user") or 0))
        pause_min_raw = limits.get("pause_min_seconds")
        pause_max_raw = limits.get("pause_max_seconds")
        pause_min = max(
            0.0,
            float(DEFAULT_PAUSE_MIN_SECONDS if pause_min_raw is None else pause_min_raw),
        )
        pause_max = max(
            pause_min,
            float(DEFAULT_PAUSE_MAX_SECONDS if pause_max_raw is None else pause_max_raw),
        )
    except (TypeError, ValueError) as exc:
        raise ApiError("本地服务返回的采集限制无效。", code="INVALID_RESPONSE") from exc
    return keyword, user, pause_min, pause_max


def _announce_runtime(health: dict[str, Any]) -> None:
    keyword, user, pause_min, pause_max = _health_limits(health)
    typer.echo(
        f"服务配置：关键词上限 {keyword} 条；"
        f"用户任务安全上限 {user or '不限'} 条；请求间隔 {pause_min:g}–{pause_max:g} 秒。"
    )


def _keyword_estimate(limit: int, content: ContentSelection, health: dict[str, Any]) -> str:
    _keyword, _user, pause_min, pause_max = _health_limits(health)
    list_requests = max(1, math.ceil(limit / 20))
    detail_requests = limit if _needs_details(content) else 0
    total_requests = list_requests + detail_requests
    minimum = math.ceil(total_requests * pause_min)
    maximum = math.ceil(total_requests * pause_max)
    return (
        f"大约需要查看 {list_requests} 页结果；最多逐条读取 {detail_requests} 项内容；"
        f"预计约需 {minimum}–{maximum} 秒（网络较慢或平台限制时会更久）"
    )


def _unwrap_job(payload: Any) -> dict[str, Any]:
    nested = payload.get("job") if isinstance(payload, dict) else None
    if isinstance(nested, dict):
        return _as_dict(nested)
    if isinstance(payload, dict):
        return _as_dict(payload)
    raise ApiError("本地服务未返回有效任务。", code="INVALID_RESPONSE")


def _jobs(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [_as_dict(item) for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        values = payload.get("items") or payload.get("jobs") or []
        if isinstance(values, list):
            return [_as_dict(item) for item in values if isinstance(item, dict)]
    return []


def _truncate(value: Any, width: int) -> str:
    text = str(value or "")
    return text if len(text) <= width else text[: max(1, width - 1)] + "…"


def _source_label(job: dict[str, Any]) -> str:
    source = _as_dict(job.get("source"))
    if job.get("source_type") == "keyword" or source.get("type") == "keyword":
        return f"# {source.get('keyword') or '未知关键词'}"
    profile = str(source.get("profile_url") or "")
    profile_path = urlsplit(profile).path
    profile_id = next((part for part in reversed(profile_path.split("/")) if part), "公开主页")
    return f"@ {profile_id}"


def _print_jobs(items: list[dict[str, Any]]) -> None:
    if not items:
        typer.echo("暂无任务。")
        return
    typer.echo(f"{'任务 ID':<10}  {'状态':<18}  {'条数':>6}  {'更多信息':>11}  来源")
    typer.echo("-" * 82)
    for job in items:
        job_id = _truncate(job.get("id"), 10)
        status_value = str(job.get("status") or "unknown")
        status_label = _truncate(STATUS_LABELS.get(status_value, status_value), 18)
        unique = int(job.get("unique_notes") or 0)
        succeeded = int(job.get("detail_succeeded") or 0)
        failed = int(job.get("detail_failed") or 0)
        details = f"{succeeded}/{failed}失败" if succeeded or failed else "-"
        source = _truncate(_source_label(job), 30)
        typer.echo(f"{job_id:<10}  {status_label:<18}  {unique:>6}  {details:>11}  {source}")


def _job_resume_at(job: dict[str, Any]) -> datetime | None:
    deadlines: list[datetime] = []
    for raw in (
        job.get("resume_not_before"),
        job.get("retry_after_at"),
        job.get("account_cooldown_until"),
    ):
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
            deadlines.append(min(parsed, MAX_SAFE_DEADLINE))
        except ValueError:
            pass
    retry_after_raw = job.get("retry_after")
    try:
        seconds = float(str(retry_after_raw)) if retry_after_raw is not None else 0.0
        updated = datetime.fromisoformat(str(job.get("updated_at") or "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        pass
    else:
        if seconds > 0:
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=UTC)
            deadlines.append(_bounded_deadline(updated, seconds))
    return max(deadlines) if deadlines else None


def _job_next_step(job: dict[str, Any]) -> str | None:
    status = str(job.get("status") or "")
    job_id = str(job.get("id") or "JOB_ID")
    if job.get("error_code") == "REQUEST_BUDGET_EXHAUSTED":
        return "已达到本地安全请求上限。请下载已有结果，并缩小范围后创建新任务。"
    if status == "paused_auth":
        if job.get("error_code") == "ACCOUNT_CHANGED":
            return f"切换回创建任务时的账号，再运行 `crimsonflux jobs resume {job_id}`。"
        return f"运行 `crimsonflux login` 重新登录，再运行 `crimsonflux jobs resume {job_id}`。"
    if status == "paused_rate_limit":
        resume_at = _job_resume_at(job)
        now = datetime.now(UTC)
        if resume_at and resume_at > now:
            seconds = max(1, math.ceil((resume_at - now).total_seconds()))
            minutes, remainder = divmod(seconds, 60)
            remaining = f"{minutes} 分 {remainder} 秒" if minutes else f"{remainder} 秒"
            local_resume = resume_at.astimezone()
            local_now = now.astimezone()
            local_time = local_resume.strftime(
                "%H:%M:%S"
                if local_resume.date() == local_now.date()
                else "%Y-%m-%d %H:%M:%S"
            )
            return f"请等待到本地时间 {local_time}（还需约 {remaining}），再运行 `crimsonflux jobs resume {job_id}`。"
        return f"现在可以运行 `crimsonflux jobs resume {job_id}` 尝试继续；若仍受限，请停止重试并继续等待。"
    if status == "paused_interrupted":
        resume_at = _job_resume_at(job)
        now = datetime.now(UTC)
        if resume_at and resume_at > now:
            seconds = max(1, math.ceil((resume_at - now).total_seconds()))
            minutes, remainder = divmod(seconds, 60)
            remaining = f"{minutes} 分 {remainder} 秒" if minutes else f"{remainder} 秒"
            local_resume = resume_at.astimezone()
            local_now = now.astimezone()
            local_time = local_resume.strftime(
                "%H:%M:%S"
                if local_resume.date() == local_now.date()
                else "%Y-%m-%d %H:%M:%S"
            )
            return f"请等待到本地时间 {local_time}（还需约 {remaining}），再运行 `crimsonflux jobs resume {job_id}`。"
        return f"进度已保存。确认服务和网络正常后，运行 `crimsonflux jobs resume {job_id}`。"
    if status == "paused_cursor_invalid":
        return "下一页位置已经失效，旧任务不能安全继续。请下载已有结果，并按原设置创建新任务。"
    return None


def _print_job(job: dict[str, Any]) -> None:
    source = _as_dict(job.get("source"))
    content = _as_dict(job.get("content"))
    raw_fields = content.get("fields")
    fields = [str(item) for item in raw_fields] if isinstance(raw_fields, list) else []
    typer.echo(f"任务：{job.get('id', '-')}")
    typer.echo(f"状态：{STATUS_LABELS.get(str(job.get('status')), job.get('status', '-'))}")
    typer.echo(f"来源：{_source_label(job)}")
    preset_labels = {"basic": "快速版", "full": "完整版", "custom": "自己选择"}
    field_labels = {
        "author": "作者信息",
        "body": "正文和时间",
        "tags": "内容标签",
        "metrics": "点赞收藏评论数",
        "media": "图片视频链接",
    }
    selected = "、".join(field_labels.get(item, item) for item in fields) or "默认信息"
    typer.echo(
        f"保存内容：{preset_labels.get(str(content.get('preset')), '快速版')}（{selected}）"
    )
    typer.echo(
        "进度："
        f"{int(job.get('unique_notes') or 0)} 条；"
        f"更多信息已读 {int(job.get('detail_succeeded') or 0)}；"
        f"未读到 {int(job.get('detail_failed') or 0)}"
    )
    if source.get("type") == "keyword":
        typer.echo(f"目标：{source.get('limit', '-')} 条（实际结果可能少于目标）")
    else:
        typer.echo("范围：运行时登录账号当前可见的全部公开笔记，不含私密/删除/未返回内容")
    if job.get("termination_reason"):
        typer.echo(f"结束原因：{job['termination_reason']}")
    next_step = _job_next_step(job)
    if next_step:
        typer.secho(f"下一步：{next_step}", fg=typer.colors.YELLOW)
    elif job.get("error_code") or job.get("error_message"):
        typer.secho(
            f"错误：{job.get('error_code') or '-'} {job.get('error_message') or ''}".rstrip(),
            fg=typer.colors.RED,
        )


def _content_selection(preset: ContentPreset, fields: list[FieldGroup]) -> ContentSelection:
    if preset != ContentPreset.CUSTOM and fields:
        raise typer.BadParameter("--field 只能与 --preset custom 一起使用")
    try:
        return ContentSelection(preset=preset, fields=set(fields))
    except ValidationError as exc:
        raise typer.BadParameter(exc.errors()[0].get("msg", str(exc))) from exc


def _field_options(
    repeated: list[FieldGroup] | None,
    comma_separated: str | None,
) -> list[FieldGroup]:
    result = list(repeated or [])
    if comma_separated:
        for raw in comma_separated.split(","):
            value = raw.strip().lower()
            if not value:
                continue
            try:
                field = FieldGroup(value)
            except ValueError as exc:
                choices = ", ".join(item.value for item in FieldGroup)
                raise typer.BadParameter(f"未知字段组 {value!r}；可选：{choices}") from exc
            if field not in result:
                result.append(field)
    return result


def _sensitive_query_names(value: str) -> list[str]:
    try:
        pairs = parse_qsl(urlsplit(value.strip()).query, keep_blank_values=True)
    except ValueError:
        return []
    result: set[str] = set()
    for name, _secret_value in pairs:
        normalized = name.strip().casefold()
        if normalized in SENSITIVE_QUERY_EXACT or any(
            part in normalized for part in SENSITIVE_QUERY_PARTS
        ):
            result.add(name)
    return sorted(result)


def _resolve_profile_url(url: str | None, url_arg: str | None) -> str:
    if url and url_arg and url != url_arg:
        raise typer.BadParameter("位置 URL 与 --url 不能取不同值")
    from_argv = url or url_arg
    if from_argv:
        sensitive_names = _sensitive_query_names(from_argv)
        if sensitive_names:
            raise typer.BadParameter(
                "主页 URL 含敏感访问参数，不得放入命令行历史。"
                "请省略 URL 参数，随后在隐藏输入提示中粘贴。"
            )
        return from_argv
    return typer.prompt("请粘贴用户主页完整地址（输入将隐藏）", hide_input=True).strip()


def _needs_details(content: ContentSelection) -> bool:
    return bool(DETAIL_FIELDS.intersection(content.fields))


def _create_job(client: ApiClient, request: CreateJobRequest) -> dict[str, Any]:
    payload = request.model_dump(mode="json")
    if isinstance(request.source, UserSource) and request.source.profile_access:
        # UserSource intentionally excludes profile_access from normal serialization so
        # it can never enter job JSON, logs, manifests or CLI output.  Reattach it only
        # as the validated URL query accepted by the loopback API; the server extracts
        # and encrypts it before persistence.
        source = _as_dict(payload.get("source"))
        parsed = urlsplit(str(source.get("profile_url") or request.source.profile_url))
        source["profile_url"] = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(request.source.profile_access), "")
        )
        payload["source"] = source
    return _unwrap_job(client.post("/jobs", payload))


def _print_created(job: dict[str, Any]) -> None:
    typer.secho("任务已创建。", fg=typer.colors.GREEN)
    _print_job(job)
    typer.echo(f"查看进度：crimsonflux jobs show {job.get('id', '')}")


@app.command()
def serve(
    host: Annotated[
        str | None,
        typer.Option("--host", help="绑定地址；默认读取 CRIMSONFLUX_HOST。"),
    ] = None,
    port: Annotated[
        int | None,
        typer.Option("--port", min=1, max=65535, help="监听端口；默认读取 CRIMSONFLUX_PORT。"),
    ] = None,
    no_browser: Annotated[
        bool,
        typer.Option("--no-browser", help="启动后不自动打开浏览器。"),
    ] = False,
) -> None:
    """启动本地 Web 与 REST 服务。"""

    if host is not None and host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("CLI 只允许绑定 127.0.0.1、localhost 或 ::1")
    from xhs_insight.app import serve as run_server

    run_server(host=host, port=port, open_browser=False if no_browser else None)


@app.command()
def login(
    stdin: Annotated[
        bool,
        typer.Option("--stdin", help="从标准输入读取 Cookie；不会从参数或环境变量读取。"),
    ] = False,
    manual: Annotated[
        bool,
        typer.Option("--manual", help="使用隐藏输入手动导入 Cookie，不启动扫码登录。"),
    ] = False,
) -> None:
    """在本地 Web 页面扫码登录；也可手动导入 Cookie。"""

    if not stdin and not manual:
        try:
            with _client(timeout=15.0) as client:
                health = _health(client)
                collector = _as_dict(health.get("collector"))
                if not collector.get("browser_login_supported"):
                    raise ApiError(
                        "当前环境不支持页面扫码。请使用 `crimsonflux login --manual`，"
                        "Docker 请使用 `crimsonflux login --stdin`。",
                        code="BROWSER_LOGIN_UNAVAILABLE",
                    )
                result = _as_dict(client.post("/auth/browser", {}))
                typer.secho("已打开隔离的官方网页登录窗口。", fg=typer.colors.CYAN)
                typer.echo("请在该窗口按官方提示完成扫码、确认或短信验证。")
                typer.echo("完成后会自动连接，并关闭窗口、删除临时浏览器资料。")
                last_status = ""
                try:
                    while str(result.get("status") or "") in {
                        "starting",
                        "awaiting_login",
                        "verifying",
                    }:
                        status = str(result.get("status") or "")
                        if status != last_status:
                            typer.echo(str(result.get("message") or "正在等待网页登录…"))
                            last_status = status
                        time.sleep(1)
                        result = _as_dict(client.get("/auth/browser/status"))
                except KeyboardInterrupt:
                    client.delete("/auth/browser")
                    raise typer.Abort() from None
                if result.get("status") != "succeeded" or result.get("authenticated") is not True:
                    raise ApiError(
                        str(result.get("message") or "网页登录未完成。"),
                        code=str(result.get("error_code") or "BROWSER_LOGIN_FAILED"),
                    )
            typer.secho("网页登录成功，登录态已加密保存在本机。", fg=typer.colors.GREEN)
            return
        except (ApiError, ClientConfigurationError) as exc:
            _fail(exc)

    cookie = ""
    try:
        if stdin:
            cookie = sys.stdin.read(16_385).rstrip("\r\n")
        else:
            cookie = typer.prompt(
                "请粘贴官方网页当前请求的完整 Cookie header",
                hide_input=True,
            )
        if not 1 <= len(cookie) <= 16_384 or any(
            character in cookie for character in ("\r", "\n", "\0")
        ):
            _fail("Cookie 为空、过长或包含非法控制字符。", code=2)
        with _client(timeout=45.0) as client:
            health = _health(client)
            collector = _as_dict(health.get("collector"))
            if not collector.get("cookie_import_supported"):
                raise ApiError(
                    "Cookie 导入安全运行时未就绪，请先运行 doctor。",
                    code="COLLECTOR_NOT_READY",
                )
            result = client.post("/auth/import", {"cookie": cookie})
        if not isinstance(result, dict) or result.get("authenticated") is not True:
            raise ApiError("本地服务未确认登录态。", code="INVALID_RESPONSE")
        typer.secho("登录态验证成功并已加密保存。", fg=typer.colors.GREEN)
    except (ApiError, ClientConfigurationError) as exc:
        _fail(exc)
    finally:
        cookie = ""


@app.command()
def logout(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过确认。")] = False,
) -> None:
    """退出账号并清除本地加密登录态。"""

    try:
        with _client() as client:
            _health(client)
            if not yes and not typer.confirm("退出可能让正在运行的任务暂停。确定继续？"):
                raise typer.Abort()
            client.delete("/auth/session")
        typer.secho("本地登录态已清除。", fg=typer.colors.GREEN)
    except (ApiError, ClientConfigurationError) as exc:
        _fail(exc)


@app.command("clear-data")
def clear_data(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过确认。")] = False,
) -> None:
    """删除全部任务、导出、登录态并轮换本地主密钥。"""

    if not yes and not typer.confirm(
        "这会永久删除全部任务、导出和登录态，且无法撤销。确定继续？"
    ):
        raise typer.Abort()
    try:
        with _client() as client:
            client.delete("/data")
        typer.secho("全部本地数据已清除，本地主密钥已轮换。", fg=typer.colors.GREEN)
    except (ApiError, ClientConfigurationError) as exc:
        _fail(exc)


@collect_app.command("keyword")
def collect_keyword(
    keyword_arg: Annotated[
        str | None,
        typer.Argument(help="兼容入口：要采集的关键词。"),
    ] = None,
    keyword: Annotated[
        str | None,
        typer.Option("--keyword", "-k", help="要采集的关键词。"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", min=1, help="目标笔记数量；上限由本地服务配置决定。"),
    ] = DEFAULT_LIMIT,
    preset: Annotated[
        ContentPreset,
        typer.Option("--preset", case_sensitive=False, help="basic、full 或 custom。"),
    ] = ContentPreset.BASIC,
    field: Annotated[
        list[FieldGroup] | None,
        typer.Option("--field", help="custom 字段组，可重复：author/body/tags/metrics/media。"),
    ] = None,
    fields: Annotated[
        str | None,
        typer.Option("--fields", help="custom 字段组，使用逗号分隔。"),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="跳过大任务耗时确认。"),
    ] = False,
) -> None:
    """按关键词创建有明确目标数量的采集任务。"""

    if keyword and keyword_arg and keyword != keyword_arg:
        raise typer.BadParameter("位置关键词与 --keyword 不能取不同值")
    resolved_keyword = keyword or keyword_arg
    if not resolved_keyword:
        raise typer.BadParameter("请通过 --keyword 提供关键词")
    content = _content_selection(preset, _field_options(field, fields))
    try:
        request = CreateJobRequest(
            source=KeywordSource(keyword=resolved_keyword, limit=limit),
            content=content,
            preapprove_details=True,
        )
        with _client() as client:
            health = _health(client)
            max_keyword, _max_user, _pause_min, _pause_max = _health_limits(health)
            if limit > max_keyword:
                raise typer.BadParameter(f"当前本地服务最多允许 {max_keyword} 条关键词结果")
            _announce_runtime(health)
            typer.echo(_keyword_estimate(limit, content, health))
            if (limit > 200 or (_needs_details(content) and limit > 100)) and not yes:
                warning = (
                    f"将采集目标 {limit} 条"
                    + ("并逐条请求详情" if _needs_details(content) else "")
                    + "，可能运行较长时间。继续？"
                )
                if not typer.confirm(warning):
                    raise typer.Abort()
            job = _create_job(client, request)
        _print_created(job)
    except ValidationError as exc:
        _fail(exc.errors()[0].get("msg", str(exc)), code=2)
    except (ApiError, ClientConfigurationError) as exc:
        _fail(exc)


@collect_app.command("user")
def collect_user(
    url_arg: Annotated[
        str | None,
        typer.Argument(help="兼容入口：小红书用户主页完整 https 地址。"),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option("--url", help="小红书用户主页完整 https 地址。"),
    ] = None,
    all_public: Annotated[
        bool,
        typer.Option("--all", help="明确确认遍历当前可见的全部公开笔记。"),
    ] = False,
    preset: Annotated[
        ContentPreset,
        typer.Option("--preset", case_sensitive=False, help="basic、full 或 custom。"),
    ] = ContentPreset.BASIC,
    field: Annotated[
        list[FieldGroup] | None,
        typer.Option("--field", help="custom 字段组，可重复：author/body/tags/metrics/media。"),
    ] = None,
    fields: Annotated[
        str | None,
        typer.Option("--fields", help="custom 字段组，使用逗号分隔。"),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="确认整理全部可见内容；若选择更多信息，也直接确认逐条读取。",
        ),
    ] = False,
) -> None:
    """遍历指定用户当前可见的全部公开笔记。"""

    resolved_url = _resolve_profile_url(url, url_arg)
    content = _content_selection(preset, _field_options(field, fields))
    if not all_public and yes:
        raise typer.BadParameter("非交互模式必须同时提供 --all 与 --yes")
    try:
        request = CreateJobRequest(
            source=UserSource(profile_url=resolved_url, all=True),
            content=content,
            # --yes is the explicit non-interactive second consent. Without it,
            # detail jobs pause after enumeration so the discovered count is visible.
            preapprove_details=bool(yes and _needs_details(content)),
        )
        with _client() as client:
            health = _health(client)
            _announce_runtime(health)
            typer.echo("用户公开笔记总量需完成列表遍历后才能确定。")
            if not all_public:
                typer.secho(
                    "范围说明：会持续翻页到平台返回无更多结果；"
                    "私密、删除、不可见或未返回内容不在结果内。",
                    fg=typer.colors.YELLOW,
                )
                if not typer.confirm("确认遍历该用户当前可见的全部公开笔记？"):
                    raise typer.Abort()
            job = _create_job(client, request)
        _print_created(job)
        if _needs_details(content) and not yes:
            typer.secho(
                "列出全部笔记后，任务会暂停等待二次确认。"
                f"届时运行：crimsonflux jobs confirm-details {job.get('id', '')}",
                fg=typer.colors.YELLOW,
            )
    except ValidationError as exc:
        _fail(exc.errors()[0].get("msg", str(exc)), code=2)
    except (ApiError, ClientConfigurationError) as exc:
        _fail(exc)


def _legacy_jobs(
    job_id: Annotated[
        str | None,
        typer.Argument(help="可选任务 ID；省略则列出最近任务。"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=500, help="列表最大条数。"),
    ] = 50,
    watch: Annotated[
        bool,
        typer.Option("--watch", "-w", help="持续刷新；按 Ctrl-C 退出，不会取消任务。"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出机器可读 JSON。"),
    ] = False,
    resume: Annotated[bool, typer.Option("--resume", help="恢复暂停/已取消的任务。")] = False,
    cancel: Annotated[bool, typer.Option("--cancel", help="请求安全取消任务。")] = False,
    retry: Annotated[bool, typer.Option("--retry", help="重试失败任务或详情项。")] = False,
    confirm_details: Annotated[
        bool,
        typer.Option("--confirm-details", help="在已知条数后确认指定用户的详情采集。"),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过任务操作确认。")] = False,
    confirm_content: ContentSelection | None = None,
) -> None:
    """查看任务，或对指定任务执行恢复、取消、重试和详情确认。"""

    if watch and json_output:
        raise typer.BadParameter("--watch 与 --json 不能同时使用；请定时调用 jobs list/show --json")
    actions = [name for name, enabled in {
        "resume": resume,
        "cancel": cancel,
        "retry": retry,
        "confirm-details": confirm_details,
    }.items() if enabled]
    if len(actions) > 1:
        raise typer.BadParameter("一次只能执行一个任务操作")
    if actions and not job_id:
        raise typer.BadParameter("任务操作需要提供 JOB_ID")
    if watch and actions:
        raise typer.BadParameter("--watch 不能与任务操作同时使用")

    try:
        with _client() as client:
            if actions:
                job = _unwrap_job(client.get(f"/jobs/{job_id}"))
                action = actions[0]
                if (
                    job.get("error_code") == "REQUEST_BUDGET_EXHAUSTED"
                    and action in {"resume", "retry"}
                ):
                    _fail("已达到本地安全请求上限，不能继续或重试。请下载已有结果，并缩小范围后创建新任务。")
                question = ""
                if action == "confirm-details":
                    count = int(job.get("unique_notes") or 0)
                    content_payload = (
                        confirm_content.model_dump(mode="json")
                        if confirm_content is not None
                        else _as_dict(job.get("content"))
                    )
                    selection = ContentSelection.model_validate(content_payload)
                    if selection.needs_details:
                        health = _health(client)
                        _keyword, _user, pause_min, pause_max = _health_limits(health)
                        minimum = math.ceil(count * pause_min)
                        maximum = math.ceil(count * pause_max)
                        typer.echo(
                            f"已发现 {count} 条内容；接下来最多逐条读取 {count} 项；"
                            f"按当前 {pause_min:g}–{pause_max:g} 秒间隔，"
                            f"预计还需 {minimum}–{maximum} 秒。"
                        )
                        question = "确认逐条读取你选择的更多信息？"
                    else:
                        typer.echo(f"已发现 {count} 条内容；不会逐条打开。")
                        question = "确认直接导出当前结果？"
                if not yes:
                    if action == "cancel":
                        question = "确定取消任务？已采集的数据不会被删除。"
                    elif action == "resume":
                        question = "确定继续这个任务？"
                    elif action == "retry":
                        question = "确定重试没有读取成功的内容？"
                    if not typer.confirm(question):
                        raise typer.Abort()
                if action == "confirm-details":
                    body = {
                        "content": confirm_content.model_dump(mode="json")
                        if confirm_content is not None
                        else _as_dict(job.get("content"))
                    }
                    result = client.post(f"/jobs/{job_id}/confirm-details", body)
                else:
                    endpoint_action = "retry-details" if action == "retry" else action
                    result = client.post(f"/jobs/{job_id}/{endpoint_action}", {})
                updated = _unwrap_job(result)
                typer.secho("任务已更新。", fg=typer.colors.GREEN)
                _print_job(updated)
                return

            while True:
                payload = client.get(f"/jobs/{job_id}" if job_id else f"/jobs?limit={limit}")
                shown_job: dict[str, Any] | None = None
                if json_output:
                    typer.echo(_json(payload))
                elif job_id:
                    shown_job = _unwrap_job(payload)
                    _print_job(shown_job)
                else:
                    _print_jobs(_jobs(payload))
                if not watch:
                    return
                if shown_job and str(shown_job.get("status")) in WATCH_STOP_STATUSES:
                    typer.echo("\n任务当前不再自动变化，已停止刷新。")
                    return
                typer.echo(f"\n刷新时间：{time.strftime('%H:%M:%S')}（Ctrl-C 退出）\n")
                time.sleep(2.5)
    except KeyboardInterrupt:
        typer.echo("\n已停止刷新；后台任务未受影响。")
    except (ApiError, ClientConfigurationError) as exc:
        _fail(exc)


@jobs_app.callback()
def jobs_default(ctx: typer.Context) -> None:
    """省略子命令时列出最近任务。"""

    if ctx.invoked_subcommand is None:
        _legacy_jobs()


@jobs_app.command("list")
def jobs_list(
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=500, help="列表最大条数。"),
    ] = 50,
    watch: Annotated[
        bool,
        typer.Option("--watch", "-w", help="持续刷新；按 Ctrl-C 退出，不会取消任务。"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出机器可读 JSON。"),
    ] = False,
) -> None:
    """列出最近任务。"""

    _legacy_jobs(limit=limit, watch=watch, json_output=json_output)


@jobs_app.command("show")
def jobs_show(
    job_id: Annotated[str, typer.Argument(help="任务 ID。")],
    watch: Annotated[
        bool,
        typer.Option("--watch", "-w", help="持续刷新；按 Ctrl-C 退出，不会取消任务。"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出机器可读 JSON。"),
    ] = False,
) -> None:
    """显示单个任务的范围、进度与错误。"""

    _legacy_jobs(job_id=job_id, watch=watch, json_output=json_output)


@jobs_app.command("resume")
def jobs_resume(
    job_id: Annotated[str, typer.Argument(help="任务 ID。")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过确认。")] = False,
) -> None:
    """恢复暂停或已取消的任务。"""

    _legacy_jobs(job_id=job_id, resume=True, yes=yes)


@jobs_app.command("cancel")
def jobs_cancel(
    job_id: Annotated[str, typer.Argument(help="任务 ID。")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过确认。")] = False,
) -> None:
    """安全取消任务并保留已采集内容。"""

    _legacy_jobs(job_id=job_id, cancel=True, yes=yes)


@jobs_app.command("retry-details")
def jobs_retry_details(
    job_id: Annotated[str, typer.Argument(help="任务 ID。")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过确认。")] = False,
) -> None:
    """只重试已失败的详情项。"""

    _legacy_jobs(job_id=job_id, retry=True, yes=yes)


@jobs_app.command("confirm-details")
def jobs_confirm_details(
    job_id: Annotated[str, typer.Argument(help="等待二次确认的任务 ID。")],
    preset: Annotated[
        ContentPreset | None,
        typer.Option("--preset", case_sensitive=False, help="可改为 basic、full 或 custom。"),
    ] = None,
    field: Annotated[
        list[FieldGroup] | None,
        typer.Option("--field", help="custom 字段组，可重复。"),
    ] = None,
    fields: Annotated[
        str | None,
        typer.Option("--fields", help="custom 字段组，使用逗号分隔。"),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过确认。")] = False,
) -> None:
    """查看条数后继续详情，或改为仅导出基础/自定义字段。"""

    chosen_fields = _field_options(field, fields)
    if preset is None and chosen_fields:
        raise typer.BadParameter("调整字段时必须同时提供 --preset custom")
    content = _content_selection(preset, chosen_fields) if preset is not None else None
    _legacy_jobs(
        job_id=job_id,
        confirm_details=True,
        yes=yes,
        confirm_content=content,
    )


def _export_filename(file_format: ExportFormat) -> str:
    return "manifest.json" if file_format == ExportFormat.MANIFEST else f"notes.{file_format.value}"


@app.command("export")
def export_job(
    job_id: Annotated[str, typer.Argument(help="要导出的任务 ID。")],
    file_format: Annotated[
        ExportFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="csv、jsonl、manifest 或 all。"),
    ] = ExportFormat.ALL,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="目标文件（单格式）或目录（all）。"),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="导出目录；文件名固定为 notes.* / manifest.json。"),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="覆盖已存在文件且不再确认。"),
    ] = False,
) -> None:
    """从本地服务下载 CSV、JSONL 和 manifest。"""

    if output is not None and output_dir is not None:
        raise typer.BadParameter("--output 与 --output-dir 不能同时使用")
    formats = (
        [ExportFormat.CSV, ExportFormat.JSONL, ExportFormat.MANIFEST]
        if file_format == ExportFormat.ALL
        else [file_format]
    )
    if output_dir is not None:
        target_dir = output_dir.expanduser().resolve()
        targets = {item: target_dir / _export_filename(item) for item in formats}
    elif file_format == ExportFormat.ALL:
        target_dir = (output or (Path.cwd() / job_id)).expanduser().resolve()
        targets = {item: target_dir / _export_filename(item) for item in formats}
    else:
        default = Path.cwd() / job_id / _export_filename(file_format)
        chosen = (output or default).expanduser()
        if chosen.exists() and chosen.is_dir():
            chosen = chosen / _export_filename(file_format)
        targets = {file_format: chosen.resolve()}

    existing = [path for path in targets.values() if path.exists()]
    if existing and not yes:
        typer.echo("以下文件已存在：")
        for path in existing:
            typer.echo(f"  {path}")
        if not typer.confirm("确认覆盖？"):
            raise typer.Abort()

    try:
        with _client(timeout=120.0) as client:
            for item, target in targets.items():
                path, _suggested = client.download(
                    f"/jobs/{job_id}/exports/{item.value}", target
                )
                typer.secho(f"已保存：{path}", fg=typer.colors.GREEN)
    except (ApiError, ClientConfigurationError, OSError) as exc:
        _fail(exc)


@app.command()
def doctor(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="输出机器可读 JSON。"),
    ] = False,
) -> None:
    """检查本地实例、令牌权限、API 健康状态和登录状态。"""

    checks: dict[str, Any] = {
        "ok": True,
        "version": __version__,
        "python": sys.version.split()[0],
    }
    try:
        config = ClientConfig.load(require_token=False)
        checks["api_url"] = config.api_url
        checks["instance_file"] = str(config.instance_path)
        checks["instance_exists"] = config.instance_path.is_file()
        checks["local_token_present"] = bool(config.local_token)
        if config.instance_path.is_file() and os.name != "nt":
            mode = stat.S_IMODE(config.instance_path.stat().st_mode)
            checks["instance_mode"] = f"{mode:04o}"
            checks["instance_permissions_secure"] = mode & 0o077 == 0
            if not checks["instance_permissions_secure"]:
                checks["ok"] = False
        else:
            checks["instance_permissions_secure"] = None
        if not config.local_token:
            checks["ok"] = False
            checks["api"] = {"reachable": False, "reason": "local_token_missing"}
        else:
            with ApiClient(config, timeout=5.0) as client:
                health = client.get("/health")
                checks["api"] = {"reachable": True, "health": health}
                try:
                    auth = client.get("/auth/status")
                    checks["auth"] = auth
                except ApiError as exc:
                    checks["auth"] = {"error": str(exc), "code": exc.code}
                    checks["ok"] = False
    except (ClientConfigurationError, ApiError, OSError) as exc:
        checks["ok"] = False
        checks["api"] = {"reachable": False, "reason": str(exc)}

    if json_output:
        typer.echo(_json(checks))
    else:
        mark = "✓" if checks["ok"] else "!"
        typer.echo(f"{mark} CrimsonFlux {checks['version']} / Python {checks['python']}")
        typer.echo(f"  API：{checks.get('api_url', '配置无效')}")
        typer.echo(f"  实例：{checks.get('instance_file', '未知')}")
        typer.echo(f"  本地令牌：{'已找到（未显示）' if checks.get('local_token_present') else '未找到'}")
        permission = checks.get("instance_permissions_secure")
        if permission is True:
            typer.echo(f"  文件权限：{checks.get('instance_mode')}（安全）")
        elif permission is False:
            typer.secho(
                f"  文件权限：{checks.get('instance_mode')}（应为 0600）",
                fg=typer.colors.RED,
            )
        api_check = _as_dict(checks.get("api"))
        typer.echo(f"  本地服务：{'可连接' if api_check.get('reachable') else '不可连接'}")
        health = _as_dict(api_check.get("health"))
        if health:
            max_keyword, max_user, pause_min, pause_max = _health_limits(health)
            typer.echo(
                f"  采集配置：关键词上限 {max_keyword}；用户上限 {max_user or '不限'}；"
                f"请求间隔 {pause_min:g}–{pause_max:g} 秒"
            )
        auth = _as_dict(checks.get("auth"))
        if "error" not in auth:
            connected = bool(
                auth.get("authenticated")
                or auth.get("logged_in")
                or auth.get("status") in {"authenticated", "connected"}
            )
            typer.echo(f"  小红书登录：{'已连接' if connected else '未连接'}")
        if not checks["ok"]:
            typer.echo("建议：先运行 `crimsonflux serve`，再重新执行 doctor。")
    if not checks["ok"]:
        raise typer.Exit(code=1)


@app.callback()
def version_option(
    version: Annotated[
        bool,
        typer.Option("--version", help="显示版本并退出。", is_eager=True),
    ] = False,
) -> None:
    """CrimsonFlux CLI。"""

    if version:
        typer.echo(__version__)
        raise typer.Exit()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
