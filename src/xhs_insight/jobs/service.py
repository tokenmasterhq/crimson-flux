"""Resumable, one-at-a-time collection orchestration."""

from __future__ import annotations

import math
import random
import shutil
import threading
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from xhs_insight.config import Settings
from xhs_insight.domain import (
    AdapterErrorCode,
    ConfirmDetailsRequest,
    ContentSelection,
    CreateJobRequest,
    DetailResult,
    JobEstimate,
    JobStatus,
    PageResult,
    SourceType,
)
from xhs_insight.exporting import Exporter
from xhs_insight.security import CredentialCipher, redact_text
from xhs_insight.storage import Repository


class _Cancelled(Exception):
    pass


class _Interrupted(Exception):
    pass


_ENUMERATION_TERMINATION_REASONS = frozenset(
    {"natural_end", "pagination_stalled", "reached_limit", "safety_cap", "source_exhausted"}
)


def _code(error: BaseException) -> str:
    value = getattr(error, "code", AdapterErrorCode.INTERNAL_ERROR)
    return str(getattr(value, "value", value))


def _retryable(error: BaseException) -> bool:
    return bool(getattr(error, "retryable", False))


class JobService:
    def __init__(
        self,
        repository: Repository,
        cipher: CredentialCipher,
        adapter: Any,
        exporter: Exporter,
        settings: Settings,
        *,
        authenticated: Callable[[], bool],
        account_fingerprint: Callable[[], str | None],
    ):
        self.repository = repository
        self.cipher = cipher
        self.adapter = adapter
        self.exporter = exporter
        self.settings = settings
        self.authenticated = authenticated
        self.account_fingerprint = account_fingerprint
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def adapter_version(self) -> str:
        return str(getattr(self.adapter, "version", "unknown"))

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.repository.mark_interrupted()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="crimsonflux-job-worker",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def create(self, payload: CreateJobRequest) -> dict[str, Any]:
        if payload.source.type == SourceType.KEYWORD and payload.source.limit > self.settings.max_keyword_items:
            raise ValueError(f"最多采集 {self.settings.max_keyword_items} 条关键词结果")
        if not self.authenticated():
            raise PermissionError("请先导入并验证登录 Cookie")
        job_id = uuid.uuid4().hex
        source = payload.source.model_dump(mode="json")
        source_private_cipher: bytes | None = None
        if payload.source.type == SourceType.USER:
            private = dict(payload.source.profile_access)
            if private:
                source_private_cipher = self.cipher.encrypt_json(
                    private,
                    aad=f"job-source:{job_id}",
                )
        job = self.repository.create_job(
            job_id=job_id,
            source=source,
            content=payload.content.model_dump(mode="json"),
            adapter_version=self.adapter_version,
            account_fingerprint=self.account_fingerprint(),
            preapprove_details=payload.preapprove_details,
            source_private_cipher=source_private_cipher,
        )
        self._wake.set()
        return self.public_job(job)

    def list(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return [self.public_job(job) for job in self.repository.list_jobs(limit=limit)]

    def get(self, job_id: str) -> dict[str, Any]:
        return self.public_job(self.repository.require_job(job_id))

    def public_job(self, job: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(job)
        result["estimate"] = self.estimate(dict(job)).model_dump(mode="json")
        directory = self.settings.export_dir / str(job["id"])
        result["artifacts"] = {
            name: path.is_file()
            for name, path in {
                "csv": directory / "notes.csv",
                "jsonl": directory / "notes.jsonl",
                "manifest": directory / "manifest.json",
            }.items()
        }
        result.pop("cursor", None)
        result.pop("account_fingerprint", None)
        result.pop("source_private_cipher", None)
        result.pop("cancel_requested", None)
        return result

    def estimate(self, job: Mapping[str, Any]) -> JobEstimate:
        source = job["source"]
        content = ContentSelection.model_validate(job["content"])
        unique = int(job.get("unique_notes") or 0)
        list_requests: int | None
        if source["type"] == SourceType.KEYWORD.value:
            page_size = max(1, int(getattr(self.adapter, "keyword_page_size", 20)))
            list_requests = math.ceil(int(source["limit"]) / page_size)
            detail_requests = int(source["limit"]) if content.needs_details else 0
        else:
            list_requests = int(job.get("pages_requested") or 0) if job.get("enumeration_complete") else None
            detail_requests = unique if content.needs_details else 0
        requests = detail_requests + (list_requests or 0)
        return JobEstimate(
            list_requests=list_requests,
            detail_requests=detail_requests,
            minimum_seconds=math.ceil(requests * self.settings.pause_min_seconds),
            maximum_seconds=math.ceil(requests * self.settings.pause_max_seconds),
        )

    def confirm_details(self, job_id: str, payload: ConfirmDetailsRequest) -> dict[str, Any]:
        job = self.repository.set_content_and_queue_details(
            job_id, payload.content.model_dump(mode="json")
        )
        self._wake.set()
        return self.public_job(job)

    def resume(self, job_id: str) -> dict[str, Any]:
        job = self.repository.require_job(job_id)
        retry_after_at = job.get("retry_after_at")
        if retry_after_at:
            try:
                resume_at = datetime.fromisoformat(str(retry_after_at))
            except ValueError:
                resume_at = datetime.max.replace(tzinfo=UTC)
            if resume_at.tzinfo is None:
                resume_at = resume_at.replace(tzinfo=UTC)
            if resume_at > datetime.now(UTC):
                raise ValueError(
                    f"平台要求等待至 {resume_at.isoformat(timespec='seconds')} 后再继续"
                )
        if (
            job["status"] == JobStatus.PAUSED_CURSOR_INVALID.value
            or job["error_code"] == AdapterErrorCode.RESUME_INCOMPATIBLE.value
        ):
            raise ValueError("任务游标已失效，不能恢复；请创建新任务")
        if job["adapter_version"] != self.adapter_version:
            raise ValueError(
                "任务由不同版本的采集适配器创建，旧游标不能安全续跑；请创建新任务"
            )
        if job["account_fingerprint"] and job["account_fingerprint"] != self.account_fingerprint():
            raise PermissionError("当前登录账号与任务创建账号不一致")
        if not self.authenticated():
            raise PermissionError("登录已过期，请重新导入 Cookie")
        queued = self.repository.queue_job(job_id)
        self._wake.set()
        return self.public_job(queued)

    def cancel(self, job_id: str) -> dict[str, Any]:
        job = self.repository.require_job(job_id)
        status = JobStatus(job["status"])
        if status in {JobStatus.COMPLETED, JobStatus.COMPLETED_WITH_WARNINGS, JobStatus.FAILED}:
            raise ValueError(f"任务已结束，不能取消: {status.value}")
        if status == JobStatus.CANCELLED:
            return self.public_job(job)
        if status in {
            JobStatus.ENUMERATING,
            JobStatus.FETCHING_DETAILS,
            JobStatus.EXPORTING,
        }:
            return self.public_job(self.repository.request_cancel(job_id))
        cancelled = self.repository.update_job(
            job_id,
            status=JobStatus.CANCELLED,
            stage=JobStatus.CANCELLED,
            cancel_requested=False,
            termination_reason="user_cancelled",
        )
        self._safe_export(job_id)
        return self.public_job(cancelled)

    def retry_details(self, job_id: str) -> dict[str, Any]:
        job = self.repository.require_job(job_id)
        if JobStatus(job["status"]) not in {
            JobStatus.COMPLETED,
            JobStatus.COMPLETED_WITH_WARNINGS,
            JobStatus.CANCELLED,
            JobStatus.FAILED,
        }:
            raise ValueError("任务仍在运行或等待操作，当前不能重试详情")
        if not job["enumeration_complete"]:
            raise ValueError("列表尚未完成，不能单独重试详情")
        count = self.repository.retry_failed_details(job_id)
        if count == 0:
            raise ValueError("没有可重试的详情")
        self.repository.update_job(
            job_id,
            status=JobStatus.QUEUED,
            stage=JobStatus.QUEUED,
            preapprove_details=True,
            cancel_requested=False,
            error_code=None,
            error_message=None,
        )
        self._wake.set()
        return self.get(job_id)

    def export_path(self, job_id: str, artifact: str) -> Path:
        filenames = {"csv": "notes.csv", "jsonl": "notes.jsonl", "manifest": "manifest.json"}
        if artifact not in filenames:
            raise KeyError(artifact)
        self.repository.require_job(job_id)
        directory = (self.settings.export_dir / job_id).resolve()
        try:
            directory.relative_to(self.settings.export_dir.resolve())
        except ValueError as error:
            raise KeyError(job_id) from error
        path = directory / filenames[artifact]
        if not path.is_file():
            raise FileNotFoundError(path)
        return path

    def clear_all(self) -> None:
        if self.repository.has_running_or_queued_jobs():
            raise ValueError("请先取消正在运行或排队的任务，再清除全部本地数据")
        export_root = self.settings.export_dir.resolve()
        targets: list[Path] = []
        for job_id in self.repository.list_job_ids():
            candidate = export_root / job_id
            if (
                not job_id
                or candidate.parent != export_root
                or candidate.name != job_id
                or candidate.is_symlink()
            ):
                raise ValueError("任务导出目录不安全，已拒绝清除本地数据")
            if not candidate.exists():
                continue
            if not candidate.is_dir() or candidate.resolve().parent != export_root:
                raise ValueError("任务导出目录越界，已拒绝清除本地数据")
            targets.append(candidate)
        for target in targets:
            shutil.rmtree(target)
        # Keep the ownership records until all filesystem deletions succeed.  A
        # later failure therefore leaves enough metadata for a safe retry.
        self.repository.clear_all()

    def _loop(self) -> None:
        while not self._stop.is_set():
            job = self.repository.next_runnable_job()
            if job is None:
                self._wake.clear()
                self._wake.wait(0.5)
                continue
            self._execute(job["id"])

    def _check_cancel(self, job_id: str) -> None:
        if self._stop.is_set():
            raise _Interrupted()
        if self.repository.require_job(job_id)["cancel_requested"]:
            raise _Cancelled()

    def _request_pause(self, job_id: str) -> None:
        seconds = random.uniform(
            self.settings.pause_min_seconds, self.settings.pause_max_seconds
        )
        if self._stop.wait(seconds):
            raise _Interrupted()
        self._check_cancel(job_id)

    def _upstream_call(
        self,
        job_id: str,
        operation: Callable[[], Any],
        *,
        detail: bool,
    ) -> Any:
        max_retries = 3
        for attempt in range(max_retries + 1):
            self._check_cancel(job_id)
            self.repository.increment_request(job_id, detail=detail)
            try:
                return operation()
            except Exception as error:
                code = _code(error)
                may_retry = code == AdapterErrorCode.NETWORK_ERROR.value
                if not may_retry or attempt >= max_retries:
                    raise
                self._request_pause(job_id)
        raise AssertionError("unreachable")

    def _execute(self, job_id: str) -> None:
        try:
            job = self.repository.require_job(job_id)
            # The worker atomically claims queued work as ``enumerating`` before
            # dispatch.  A stale dispatch after cancellation must be a no-op.
            if job["status"] != JobStatus.ENUMERATING.value:
                return
            self._check_cancel(job_id)
            if job["adapter_version"] != self.adapter_version:
                self._pause_job(
                    job_id,
                    JobStatus.PAUSED_CURSOR_INVALID,
                    AdapterErrorCode.RESUME_INCOMPATIBLE.value,
                    "任务由不同版本的采集适配器创建，不能安全继续",
                )
                return
            if not self.authenticated():
                self._pause_job(
                    job_id,
                    JobStatus.PAUSED_AUTH,
                    AdapterErrorCode.AUTH_EXPIRED.value,
                    "登录已过期，请重新导入 Cookie",
                )
                return
            fingerprint = self.account_fingerprint()
            if job["account_fingerprint"] and fingerprint != job["account_fingerprint"]:
                self._pause_job(job_id, JobStatus.PAUSED_AUTH, AdapterErrorCode.ACCOUNT_CHANGED.value, "当前登录账号与任务账号不一致")
                return
            enumeration_stopped = bool(job["enumeration_complete"]) or job[
                "termination_reason"
            ] in {"pagination_stalled", "safety_cap"}
            if not enumeration_stopped:
                self._enumerate(job_id)
            job = self.repository.require_job(job_id)
            if job["enumeration_complete"] or job["termination_reason"] in {
                "pagination_stalled",
                "safety_cap",
            }:
                self.repository.clear_source_private(job_id)
            self._check_cancel(job_id)
            content = ContentSelection.model_validate(job["content"])
            if (
                job["source_type"] == SourceType.USER.value
                and content.needs_details
                and not job["preapprove_details"]
            ):
                self.repository.update_job(
                    job_id,
                    status=JobStatus.AWAITING_DETAIL_CONFIRMATION,
                    stage=JobStatus.AWAITING_DETAIL_CONFIRMATION,
                )
                return
            if content.needs_details:
                self._details(job_id)
            else:
                self.repository.clear_note_private(job_id)
                self.repository.update_job(job_id, details_complete=True)
            self._check_cancel(job_id)
            self._finish(job_id)
        except _Interrupted:
            current = self.repository.require_job(job_id)
            changes: dict[str, Any] = {
                "status": JobStatus.PAUSED_INTERRUPTED,
                "stage": JobStatus.PAUSED_INTERRUPTED,
                "error_code": None,
                "error_message": None,
            }
            if current["termination_reason"] not in _ENUMERATION_TERMINATION_REASONS:
                changes["termination_reason"] = "process_interrupted"
            self.repository.update_job(job_id, **changes)
            if self.repository.require_job(job_id)["unique_notes"]:
                self._safe_export(job_id)
        except _Cancelled:
            self.repository.update_job(
                job_id,
                status=JobStatus.CANCELLED,
                stage=JobStatus.CANCELLED,
                termination_reason="user_cancelled",
            )
            self._safe_export(job_id)
        except Exception as error:
            self._handle_error(job_id, error)

    def _enumerate(self, job_id: str) -> None:
        self.repository.update_job(
            job_id, status=JobStatus.ENUMERATING, stage=JobStatus.ENUMERATING
        )
        while True:
            self._check_cancel(job_id)
            job = self.repository.require_job(job_id)
            source = job["source"]
            cursor = job["cursor"] or ({"page": 1} if job["source_type"] == "keyword" else {"cursor": ""})
            if self.repository.has_page_cursor(job_id, cursor):
                self.repository.update_job(
                    job_id,
                    enumeration_complete=False,
                    termination_reason="pagination_stalled",
                    error_code="PAGINATION_STALLED",
                    error_message="分页游标重复，任务已停止以避免无限请求",
                )
                return
            limit: int | None
            if job["source_type"] == SourceType.KEYWORD.value:
                keyword = str(source["keyword"])
                page_cursor: dict[str, Any] = dict(cursor)

                def fetch_keyword_page(
                    keyword_value: str = keyword,
                    cursor_value: dict[str, Any] = page_cursor,
                ) -> Any:
                    return self.adapter.keyword_page(keyword_value, cursor_value)

                raw_page = self._upstream_call(
                    job_id,
                    fetch_keyword_page,
                    detail=False,
                )
                limit = int(source["limit"])
            else:
                profile_url = str(source["profile_url"])
                if job.get("source_private_cipher"):
                    private_source = self.cipher.decrypt_json(
                        job["source_private_cipher"],
                        aad=f"job-source:{job_id}",
                    )
                    allowed_query = {
                        key: str(private_source[key])
                        for key in ("xsec_token", "xsec_source")
                        if private_source.get(key)
                    }
                    if allowed_query:
                        profile_url = f"{profile_url}?{urlencode(allowed_query)}"

                user_page_cursor: dict[str, Any] = dict(cursor)

                def fetch_user_page(
                    url_value: str = profile_url,
                    cursor_value: dict[str, Any] = user_page_cursor,
                ) -> Any:
                    return self.adapter.user_page(url_value, cursor_value)

                raw_page = self._upstream_call(
                    job_id,
                    fetch_user_page,
                    detail=False,
                )
                limit = self.settings.max_user_items or None
            page = PageResult.model_validate(raw_page)
            items: list[dict[str, Any]] = []
            for raw_item in page.items:
                item = dict(raw_item)
                note_id = str(item.get("note_id") or "")
                private = item.pop("_private", None)
                if private and note_id:
                    item["_private_cipher"] = self.cipher.encrypt_json(
                        private, aad=f"note:{job_id}:{note_id}"
                    )
                items.append(item)
            self.repository.save_page(
                job_id,
                cursor=cursor,
                next_cursor=page.next_cursor,
                has_more=page.has_more,
                items=items,
                raw_count=page.raw_item_count or len(page.items),
                skipped_count=page.skipped_item_count,
                limit=limit,
            )
            job = self.repository.require_job(job_id)
            if job["enumeration_complete"] or job["termination_reason"] in {
                "pagination_stalled",
                "safety_cap",
            }:
                return
            self._request_pause(job_id)

    def _details(self, job_id: str) -> None:
        self.repository.update_job(
            job_id, status=JobStatus.FETCHING_DETAILS, stage=JobStatus.FETCHING_DETAILS
        )
        self.repository.prepare_details(job_id)
        while note := self.repository.next_detail(job_id):
            self._check_cancel(job_id)
            private: dict[str, Any] = {}
            if note.get("private_cipher"):
                private = self.cipher.decrypt_json(
                    note["private_cipher"], aad=f"note:{job_id}:{note['note_id']}"
                )
            try:
                note_id = str(note["note_id"])

                def fetch_note_detail(
                    note_id_value: str = note_id,
                    access_value: dict[str, Any] = private,
                ) -> Any:
                    return self.adapter.note_detail(note_id_value, access_value)

                raw_detail = self._upstream_call(
                    job_id,
                    fetch_note_detail,
                    detail=True,
                )
                detail = DetailResult.model_validate(raw_detail)
                self.repository.save_detail(job_id, note_id, detail=detail.fields)
            except Exception as error:
                code = _code(error)
                if code in {
                    AdapterErrorCode.AUTH_EXPIRED.value,
                    AdapterErrorCode.RATE_LIMITED.value,
                    AdapterErrorCode.RISK_CONTROLLED.value,
                    AdapterErrorCode.NETWORK_ERROR.value,
                    AdapterErrorCode.SIGNER_FAILED.value,
                    AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED.value,
                    AdapterErrorCode.UPSTREAM_UNSUPPORTED.value,
                }:
                    raise
                self.repository.save_detail(job_id, note["note_id"], detail=None, error_code=code)
            self._request_pause(job_id)
        current = self.repository.require_job(job_id)
        self.repository.update_job(
            job_id,
            details_complete=int(current["detail_failed"]) == 0,
        )

    def _finish(self, job_id: str) -> None:
        job = self.repository.require_job(job_id)
        has_warnings = (
            not job["enumeration_complete"]
            or not job["details_complete"]
            or job["limit_satisfied"] is False
            or bool(job["error_code"])
        )
        if not job["unique_notes"]:
            status = JobStatus.FAILED
            reason = job["termination_reason"] or "no_records"
        else:
            status = JobStatus.COMPLETED_WITH_WARNINGS if has_warnings else JobStatus.COMPLETED
            reason = job["termination_reason"]
        self.repository.update_job(
            job_id,
            status=JobStatus.EXPORTING,
            stage=JobStatus.EXPORTING,
            termination_reason=reason,
        )
        if self._safe_export(job_id, status_override=status.value):
            self.repository.update_job(job_id, status=status, stage=status)

    def _safe_export(self, job_id: str, *, status_override: str | None = None) -> bool:
        try:
            self.exporter.export(job_id, status_override=status_override)
        except Exception as error:
            self.repository.update_job(
                job_id,
                status=JobStatus.FAILED,
                stage=JobStatus.FAILED,
                error_code=(
                    AdapterErrorCode.DISK_FULL.value
                    if isinstance(error, OSError)
                    else AdapterErrorCode.INTERNAL_ERROR.value
                ),
                error_message=redact_text(error),
            )
            return False
        return True

    def _pause_job(
        self,
        job_id: str,
        status: JobStatus,
        code: str,
        message: str,
        *,
        retry_after: int | None = None,
    ) -> None:
        current = self.repository.require_job(job_id)
        bounded_retry_after = (
            min(retry_after, 3600)
            if type(retry_after) is int and retry_after >= 0
            else None
        )
        retry_after_at = (
            (datetime.now(UTC) + timedelta(seconds=bounded_retry_after)).isoformat(
                timespec="seconds"
            )
            if bounded_retry_after is not None
            else None
        )
        public_message = message
        if bounded_retry_after:
            public_message = f"{message}请至少等待 {bounded_retry_after} 秒后继续。"
        changes: dict[str, Any] = {
            "status": status,
            "stage": status,
            "error_code": code,
            "error_message": redact_text(public_message),
            "retry_after_at": retry_after_at,
        }
        if current["termination_reason"] not in _ENUMERATION_TERMINATION_REASONS:
            changes["termination_reason"] = code.lower()
        self.repository.update_job(job_id, **changes)
        if self.repository.require_job(job_id)["unique_notes"]:
            self._safe_export(job_id)

    def _handle_error(self, job_id: str, error: BaseException) -> None:
        code = _code(error)
        message = redact_text(getattr(error, "public_message", str(error) or type(error).__name__))
        if code in {AdapterErrorCode.AUTH_EXPIRED.value, AdapterErrorCode.ACCOUNT_CHANGED.value}:
            self._pause_job(job_id, JobStatus.PAUSED_AUTH, code, message)
            return
        if code in {
            AdapterErrorCode.RATE_LIMITED.value,
            AdapterErrorCode.RISK_CONTROLLED.value,
        }:
            self._pause_job(
                job_id,
                JobStatus.PAUSED_RATE_LIMIT,
                code,
                message,
                retry_after=getattr(error, "retry_after", None),
            )
            return
        if code == AdapterErrorCode.RESUME_INCOMPATIBLE.value:
            self._pause_job(job_id, JobStatus.PAUSED_CURSOR_INVALID, code, message)
            return
        if code == AdapterErrorCode.NETWORK_ERROR.value or _retryable(error):
            self._pause_job(job_id, JobStatus.PAUSED_INTERRUPTED, code, message)
            return
        job = self.repository.require_job(job_id)
        status = JobStatus.COMPLETED_WITH_WARNINGS if job["unique_notes"] else JobStatus.FAILED
        self.repository.update_job(
            job_id,
            status=status,
            stage=status,
            termination_reason=code.lower(),
            error_code=code,
            error_message=message,
        )
        self._safe_export(job_id)
