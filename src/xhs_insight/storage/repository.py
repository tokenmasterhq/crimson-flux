"""Explicit SQLite repository for one local worker and resumable pagination."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from xhs_insight.domain import (
    ACTIVE_STATUSES,
    RESUMABLE_STATUSES,
    TERMINAL_STATUSES,
    AdapterErrorCode,
    JobStatus,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _load(value: str | None, default: Any = None) -> Any:
    return default if not value else json.loads(value)


class Repository:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._schema_lock = threading.Lock()
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def initialize(self) -> None:
        with self._schema_lock, self.connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS app_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_session (
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    payload_cipher BLOB NOT NULL,
                    account_fingerprint TEXT NOT NULL,
                    connected_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL CHECK(source_type IN ('keyword','user')),
                    source_json TEXT NOT NULL,
                    source_private_cipher BLOB,
                    content_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    cursor_json TEXT,
                    account_fingerprint TEXT,
                    adapter_version TEXT NOT NULL,
                    enumeration_complete INTEGER NOT NULL DEFAULT 0,
                    details_complete INTEGER NOT NULL DEFAULT 0,
                    limit_satisfied INTEGER,
                    termination_reason TEXT,
                    list_requests INTEGER NOT NULL DEFAULT 0,
                    detail_requests INTEGER NOT NULL DEFAULT 0,
                    pages_requested INTEGER NOT NULL DEFAULT 0,
                    raw_items_received INTEGER NOT NULL DEFAULT 0,
                    skipped_items INTEGER NOT NULL DEFAULT 0,
                    duplicates_dropped INTEGER NOT NULL DEFAULT 0,
                    detail_succeeded INTEGER NOT NULL DEFAULT 0,
                    detail_failed INTEGER NOT NULL DEFAULT 0,
                    consecutive_empty_pages INTEGER NOT NULL DEFAULT 0,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    preapprove_details INTEGER NOT NULL DEFAULT 0,
                    error_code TEXT,
                    error_message TEXT,
                    retry_after_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_jobs_status_created
                    ON jobs(status, created_at);

                CREATE TABLE IF NOT EXISTS job_pages (
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    cursor_hash TEXT NOT NULL,
                    cursor_json TEXT NOT NULL,
                    next_cursor_json TEXT,
                    has_more INTEGER NOT NULL,
                    raw_count INTEGER NOT NULL,
                    added_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(job_id, cursor_hash)
                );

                CREATE TABLE IF NOT EXISTS notes (
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    note_id TEXT NOT NULL,
                    source_page INTEGER NOT NULL,
                    source_rank INTEGER NOT NULL,
                    list_json TEXT NOT NULL,
                    private_cipher BLOB,
                    detail_json TEXT,
                    detail_status TEXT NOT NULL DEFAULT 'not_requested',
                    detail_error_code TEXT,
                    detail_attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(job_id, note_id)
                );

                CREATE INDEX IF NOT EXISTS idx_notes_job_rank
                    ON notes(job_id, source_rank);
                CREATE INDEX IF NOT EXISTS idx_notes_job_detail
                    ON notes(job_id, detail_status, source_rank);

                """
            )
            columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }
            if "source_private_cipher" not in columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN source_private_cipher BLOB")
            if "list_requests" not in columns:
                connection.execute(
                    "ALTER TABLE jobs ADD COLUMN list_requests INTEGER NOT NULL DEFAULT 0"
                )
            if "detail_requests" not in columns:
                connection.execute(
                    "ALTER TABLE jobs ADD COLUMN detail_requests INTEGER NOT NULL DEFAULT 0"
                )
            if "retry_after_at" not in columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN retry_after_at TEXT")
            connection.execute("PRAGMA user_version=4")

    def set_meta(self, key: str, value: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO app_meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_meta(self, key: str) -> str | None:
        with self.connection() as connection:
            row = connection.execute("SELECT value FROM app_meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else None

    def save_auth(self, payload_cipher: bytes, account_fingerprint: str) -> None:
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO auth_session(id,payload_cipher,account_fingerprint,connected_at,updated_at)
                   VALUES(1,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET payload_cipher=excluded.payload_cipher,
                     account_fingerprint=excluded.account_fingerprint,
                     connected_at=excluded.connected_at,updated_at=excluded.updated_at""",
                (payload_cipher, account_fingerprint, now, now),
            )

    def load_auth(self) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM auth_session WHERE id=1").fetchone()
        return dict(row) if row else None

    def delete_auth(self) -> None:
        with self.transaction() as connection:
            connection.execute("DELETE FROM auth_session")
        with self.connection() as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    @staticmethod
    def _job(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["source"] = _load(result.pop("source_json"), {})
        result["content"] = _load(result.pop("content_json"), {})
        result["cursor"] = _load(result.pop("cursor_json"), None)
        for key in (
            "enumeration_complete",
            "details_complete",
            "cancel_requested",
            "preapprove_details",
        ):
            result[key] = bool(result[key])
        if result["limit_satisfied"] is not None:
            result["limit_satisfied"] = bool(result["limit_satisfied"])
        result["unique_notes"] = result.get("unique_notes", 0)
        return result

    def create_job(
        self,
        *,
        source: Mapping[str, Any],
        content: Mapping[str, Any],
        adapter_version: str,
        account_fingerprint: str | None,
        preapprove_details: bool = False,
        source_private_cipher: bytes | None = None,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        job_id = job_id or uuid.uuid4().hex
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO jobs(
                     id,source_type,source_json,source_private_cipher,content_json,status,stage,cursor_json,
                     account_fingerprint,adapter_version,preapprove_details,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id,
                    source["type"],
                    _dump(dict(source)),
                    source_private_cipher,
                    _dump(dict(content)),
                    JobStatus.QUEUED.value,
                    JobStatus.QUEUED.value,
                    _dump({"page": 1}) if source["type"] == "keyword" else _dump({"cursor": ""}),
                    account_fingerprint,
                    adapter_version,
                    int(preapprove_details),
                    now,
                    now,
                ),
            )
        return self.require_job(job_id)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                """SELECT jobs.*,
                     (SELECT COUNT(*) FROM notes WHERE notes.job_id=jobs.id) AS unique_notes
                   FROM jobs WHERE id=?""",
                (job_id,),
            ).fetchone()
        return self._job(row)

    def require_job(self, job_id: str) -> dict[str, Any]:
        result = self.get_job(job_id)
        if result is None:
            raise KeyError(job_id)
        return result

    def list_jobs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT jobs.*,
                     (SELECT COUNT(*) FROM notes WHERE notes.job_id=jobs.id) AS unique_notes
                   FROM jobs ORDER BY created_at DESC LIMIT ?""",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        return [item for row in rows if (item := self._job(row)) is not None]

    def list_job_ids(self) -> list[str]:
        """Return the exact export-directory names owned by persisted jobs."""

        with self.connection() as connection:
            rows = connection.execute("SELECT id FROM jobs ORDER BY created_at ASC").fetchall()
        return [str(row[0]) for row in rows]

    def next_runnable_job(self) -> dict[str, Any] | None:
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT id FROM jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            job_id = str(row[0])
            claimed = connection.execute(
                """UPDATE jobs SET status=?,stage=?,started_at=COALESCE(started_at,?),
                     finished_at=NULL,updated_at=? WHERE id=? AND status=?""",
                (
                    JobStatus.ENUMERATING.value,
                    JobStatus.ENUMERATING.value,
                    now,
                    now,
                    job_id,
                    JobStatus.QUEUED.value,
                ),
            )
            if not claimed.rowcount:
                return None
            claimed_row = connection.execute(
                """SELECT jobs.*,
                     (SELECT COUNT(*) FROM notes WHERE notes.job_id=jobs.id) AS unique_notes
                   FROM jobs WHERE id=?""",
                (job_id,),
            ).fetchone()
        return self._job(claimed_row)

    def has_running_or_queued_jobs(self) -> bool:
        statuses = (JobStatus.QUEUED.value, *(item.value for item in ACTIVE_STATUSES))
        placeholders = ",".join("?" for _ in statuses)
        with self.connection() as connection:
            row = connection.execute(
                f"SELECT 1 FROM jobs WHERE status IN ({placeholders}) LIMIT 1",
                statuses,
            ).fetchone()
        return row is not None

    def update_job(self, job_id: str, **changes: Any) -> dict[str, Any]:
        if not changes:
            return self.require_job(job_id)
        allowed = {
            "status",
            "stage",
            "cursor",
            "content",
            "account_fingerprint",
            "enumeration_complete",
            "details_complete",
            "limit_satisfied",
            "termination_reason",
            "pages_requested",
            "raw_items_received",
            "skipped_items",
            "duplicates_dropped",
            "detail_succeeded",
            "detail_failed",
            "consecutive_empty_pages",
            "cancel_requested",
            "preapprove_details",
            "error_code",
            "error_message",
            "retry_after_at",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"unsupported job fields: {sorted(unknown)}")
        now = utc_now()
        clauses: list[str] = []
        values: list[Any] = []
        status = changes.get("status")
        for key, value in changes.items():
            column = {"cursor": "cursor_json", "content": "content_json"}.get(key, key)
            if key in {"cursor", "content"}:
                value = _dump(value) if value is not None else None
            elif key in {
                "enumeration_complete",
                "details_complete",
                "limit_satisfied",
                "cancel_requested",
                "preapprove_details",
            }:
                value = None if value is None else int(bool(value))
            elif isinstance(value, Enum):
                value = value.value
            clauses.append(f"{column}=?")
            values.append(value)
        if status in {item.value for item in ACTIVE_STATUSES}:
            clauses.append("started_at=COALESCE(started_at,?)")
            values.append(now)
            clauses.append("finished_at=NULL")
        if status in {item.value for item in TERMINAL_STATUSES}:
            clauses.append("finished_at=?")
            values.append(now)
        clauses.append("updated_at=?")
        values.append(now)
        values.append(job_id)
        with self.transaction() as connection:
            cursor = connection.execute(
                f"UPDATE jobs SET {', '.join(clauses)} WHERE id=?", values
            )
            if not cursor.rowcount:
                raise KeyError(job_id)
        return self.require_job(job_id)

    def request_cancel(self, job_id: str) -> dict[str, Any]:
        return self.update_job(job_id, cancel_requested=True)

    def increment_request(self, job_id: str, *, detail: bool) -> None:
        column = "detail_requests" if detail else "list_requests"
        with self.transaction() as connection:
            cursor = connection.execute(
                f"UPDATE jobs SET {column}={column}+1,updated_at=? WHERE id=?",
                (utc_now(), job_id),
            )
            if not cursor.rowcount:
                raise KeyError(job_id)

    def queue_job(self, job_id: str) -> dict[str, Any]:
        current = self.require_job(job_id)
        if (
            current["status"] == JobStatus.PAUSED_CURSOR_INVALID.value
            or current["error_code"] == AdapterErrorCode.RESUME_INCOMPATIBLE.value
        ):
            raise ValueError("任务游标已失效，不能恢复；请创建新任务")
        if JobStatus(current["status"]) not in RESUMABLE_STATUSES:
            raise ValueError(f"任务当前状态不可继续: {current['status']}")
        changes: dict[str, Any] = {
            "status": JobStatus.QUEUED,
            "stage": JobStatus.QUEUED,
            "cancel_requested": False,
            "error_code": None,
            "error_message": None,
            "retry_after_at": None,
        }
        enumeration_reasons = {
            "natural_end",
            "pagination_stalled",
            "reached_limit",
            "safety_cap",
            "source_exhausted",
        }
        if current["termination_reason"] not in enumeration_reasons:
            changes["termination_reason"] = None
        return self.update_job(job_id, **changes)

    def mark_interrupted(self) -> list[str]:
        statuses = tuple(item.value for item in ACTIVE_STATUSES)
        placeholders = ",".join("?" for _ in statuses)
        with self.transaction() as connection:
            rows = connection.execute(
                f"SELECT id FROM jobs WHERE status IN ({placeholders})", statuses
            ).fetchall()
            now = utc_now()
            connection.execute(
                f"""UPDATE jobs SET status=?,stage=?,
                    termination_reason=CASE WHEN enumeration_complete=1
                        OR termination_reason IN ('pagination_stalled','safety_cap')
                        THEN termination_reason ELSE 'process_interrupted' END,
                    updated_at=?
                    WHERE status IN ({placeholders})""",
                (JobStatus.PAUSED_INTERRUPTED.value, JobStatus.PAUSED_INTERRUPTED.value, now, *statuses),
            )
        return [str(row[0]) for row in rows]

    def set_content_and_queue_details(
        self, job_id: str, content: Mapping[str, Any]
    ) -> dict[str, Any]:
        current = self.require_job(job_id)
        if current["status"] != JobStatus.AWAITING_DETAIL_CONFIRMATION.value:
            raise ValueError("任务不在等待详情确认状态")
        return self.update_job(
            job_id,
            content=dict(content),
            preapprove_details=True,
            status=JobStatus.QUEUED,
            stage=JobStatus.QUEUED,
        )

    @staticmethod
    def _cursor_identity(source_type: str, cursor: Mapping[str, Any]) -> dict[str, Any]:
        if source_type == "user":
            # ``page`` is a local display/progress counter.  Only the opaque
            # upstream token identifies a user-note page and detects A -> B -> A
            # cycles correctly. Synthetic repository tests call the same
            # concept ``offset``; keeping that fallback avoids giving a local
            # page counter identity semantics.
            token = cursor.get("cursor") if "cursor" in cursor else cursor.get("offset")
            return {"cursor": str(token or "")}
        return dict(cursor)

    @classmethod
    def _cursor_hash(cls, source_type: str, cursor: Mapping[str, Any]) -> str:
        identity = cls._cursor_identity(source_type, cursor)
        return hashlib.sha256(_dump(identity).encode("utf-8")).hexdigest()

    @classmethod
    def _page_cursor_exists(
        cls,
        connection: sqlite3.Connection,
        job_id: str,
        source_type: str,
        cursor: Mapping[str, Any],
    ) -> bool:
        digest = cls._cursor_hash(source_type, cursor)
        row = connection.execute(
            "SELECT 1 FROM job_pages WHERE job_id=? AND cursor_hash=?", (job_id, digest)
        ).fetchone()
        if row is not None or source_type != "user":
            return row is not None

        # Compatibility with pre-v0.1 preview databases whose user cursor hash
        # included the synthetic page number.
        expected = cls._cursor_identity(source_type, cursor)
        rows = connection.execute(
            "SELECT cursor_json FROM job_pages WHERE job_id=?", (job_id,)
        ).fetchall()
        return any(
            cls._cursor_identity(source_type, _load(str(item[0]), {})) == expected
            for item in rows
        )

    def has_page_cursor(self, job_id: str, cursor: Mapping[str, Any]) -> bool:
        with self.connection() as connection:
            job = connection.execute(
                "SELECT source_type FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if job is None:
                raise KeyError(job_id)
            return self._page_cursor_exists(
                connection, job_id, str(job[0]), cursor
            )

    def save_page(
        self,
        job_id: str,
        *,
        cursor: Mapping[str, Any],
        next_cursor: Mapping[str, Any] | None,
        has_more: bool,
        items: Iterable[Mapping[str, Any]],
        raw_count: int,
        skipped_count: int,
        limit: int | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        prepared = [dict(item) for item in items]
        with self.transaction() as connection:
            job = connection.execute(
                """SELECT source_type,consecutive_empty_pages,enumeration_complete,
                     limit_satisfied FROM jobs WHERE id=?""",
                (job_id,),
            ).fetchone()
            if job is None:
                raise KeyError(job_id)
            source_type = str(job["source_type"])
            cursor_hash = self._cursor_hash(source_type, cursor)
            if self._page_cursor_exists(connection, job_id, source_type, cursor):
                connection.execute(
                    """UPDATE jobs SET enumeration_complete=0,
                         termination_reason='pagination_stalled',error_code='PAGINATION_STALLED',
                         error_message='分页游标重复，任务已停止以避免无限请求',updated_at=?
                       WHERE id=?""",
                    (now, job_id),
                )
                return {"added": 0, "duplicates": len(prepared), "already_saved": True}
            current_count = int(
                connection.execute("SELECT COUNT(*) FROM notes WHERE job_id=?", (job_id,)).fetchone()[0]
            )
            empty_pages = int(job["consecutive_empty_pages"])
            added = 0
            duplicates = 0
            truncated_by_limit = False
            for item in prepared:
                note_id = str(item.pop("note_id", "")).strip()
                if not note_id:
                    continue
                if limit is not None and current_count + added >= limit:
                    existing_note = connection.execute(
                        "SELECT 1 FROM notes WHERE job_id=? AND note_id=?",
                        (job_id, note_id),
                    ).fetchone()
                    if existing_note is None:
                        truncated_by_limit = True
                    continue
                private_cipher = item.pop("_private_cipher", None)
                source_page = int(item.get("source_page") or 1)
                source_rank = current_count + added + 1
                cursor_result = connection.execute(
                    """INSERT OR IGNORE INTO notes(
                         job_id,note_id,source_page,source_rank,list_json,private_cipher,
                         detail_status,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,'not_requested',?,?)""",
                    (
                        job_id,
                        note_id,
                        source_page,
                        source_rank,
                        _dump(item),
                        private_cipher,
                        now,
                        now,
                    ),
                )
                if cursor_result.rowcount:
                    added += 1
                else:
                    duplicates += 1
            connection.execute(
                """INSERT INTO job_pages(
                     job_id,cursor_hash,cursor_json,next_cursor_json,has_more,raw_count,
                     added_count,created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    job_id,
                    cursor_hash,
                    _dump(dict(cursor)),
                    _dump(dict(next_cursor)) if next_cursor is not None else None,
                    int(has_more),
                    int(raw_count),
                    added,
                    now,
                ),
            )
            result_count = current_count + added
            consecutive_empty = 0 if added else empty_pages + 1
            enumeration_complete: bool | None = None
            limit_satisfied: bool | None = None
            termination_reason: str | None = None
            error_code: str | None = None
            error_message: str | None = None

            # An explicit upstream ``has_more=false`` is authoritative.  In
            # particular, a user with exactly the configured safety-cap count is
            # complete rather than artificially truncated.
            if source_type == "user" and truncated_by_limit:
                enumeration_complete = False
                termination_reason = "safety_cap"
                error_code = "SAFETY_CAP"
                error_message = f"已达到 {limit} 条安全上限"
            elif not has_more:
                enumeration_complete = True
                if source_type == "keyword":
                    limit_satisfied = limit is not None and result_count >= limit
                    termination_reason = (
                        "reached_limit" if limit_satisfied else "source_exhausted"
                    )
                else:
                    termination_reason = "natural_end"
            elif source_type == "keyword" and limit is not None and result_count >= limit:
                enumeration_complete = True
                limit_satisfied = True
                termination_reason = "reached_limit"
            elif source_type == "user" and limit is not None and result_count >= limit:
                enumeration_complete = False
                termination_reason = "safety_cap"
                error_code = "SAFETY_CAP"
                error_message = f"已达到 {limit} 条安全上限"
            elif next_cursor is None:
                enumeration_complete = False
                termination_reason = "pagination_stalled"
                error_code = "PAGINATION_STALLED"
                error_message = "上游表示仍有结果，但没有提供下一页游标"
            elif self._page_cursor_exists(
                connection, job_id, source_type, next_cursor
            ):
                enumeration_complete = False
                termination_reason = "pagination_stalled"
                error_code = "PAGINATION_STALLED"
                error_message = "分页游标重复，任务已停止以避免无限请求"
            elif consecutive_empty >= 2:
                enumeration_complete = False
                termination_reason = "pagination_stalled"
                error_code = "PAGINATION_STALLED"
                error_message = "连续两页没有新增笔记，任务已停止"

            clauses = [
                "cursor_json=?",
                "pages_requested=pages_requested+1",
                "raw_items_received=raw_items_received+?",
                "skipped_items=skipped_items+?",
                "duplicates_dropped=duplicates_dropped+?",
                "consecutive_empty_pages=?",
            ]
            values: list[Any] = [
                _dump(dict(next_cursor)) if next_cursor is not None else None,
                int(raw_count),
                int(skipped_count),
                duplicates,
                consecutive_empty,
            ]
            if enumeration_complete is not None:
                clauses.extend(
                    [
                        "enumeration_complete=?",
                        "termination_reason=?",
                        "error_code=?",
                        "error_message=?",
                    ]
                )
                values.extend(
                    [
                        int(enumeration_complete),
                        termination_reason,
                        error_code,
                        error_message,
                    ]
                )
                if source_type == "keyword":
                    clauses.append("limit_satisfied=?")
                    values.append(None if limit_satisfied is None else int(limit_satisfied))
            clauses.append("updated_at=?")
            values.extend([now, job_id])
            connection.execute(
                f"UPDATE jobs SET {', '.join(clauses)} WHERE id=?",
                values,
            )
        return {"added": added, "duplicates": duplicates, "already_saved": False}

    def prepare_details(self, job_id: str) -> int:
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """UPDATE notes SET detail_status='pending',updated_at=?
                   WHERE job_id=? AND detail_status='not_requested'""",
                (now, job_id),
            )
            count = connection.execute(
                "SELECT COUNT(*) FROM notes WHERE job_id=? AND detail_status IN ('pending','failed')",
                (job_id,),
            ).fetchone()[0]
        return int(count)

    @staticmethod
    def _note(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["list_data"] = _load(result.pop("list_json"), {})
        result["detail_data"] = _load(result.pop("detail_json"), None)
        return result

    def next_detail(self, job_id: str, *, include_failed: bool = False) -> dict[str, Any] | None:
        statuses = ("pending", "failed") if include_failed else ("pending",)
        placeholders = ",".join("?" for _ in statuses)
        with self.connection() as connection:
            row = connection.execute(
                f"""SELECT * FROM notes WHERE job_id=? AND detail_status IN ({placeholders})
                    ORDER BY source_rank ASC LIMIT 1""",
                (job_id, *statuses),
            ).fetchone()
        return self._note(row) if row else None

    def save_detail(
        self,
        job_id: str,
        note_id: str,
        *,
        detail: Mapping[str, Any] | None,
        error_code: str | None = None,
    ) -> None:
        success = detail is not None
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """UPDATE notes SET detail_json=?,detail_status=?,detail_error_code=?,
                     private_cipher=CASE WHEN ? THEN NULL ELSE private_cipher END,
                     detail_attempts=detail_attempts+1,updated_at=?
                   WHERE job_id=? AND note_id=?""",
                (
                    _dump(dict(detail)) if detail is not None else None,
                    "succeeded" if success else "failed",
                    None if success else (error_code or "DETAIL_FAILED"),
                    int(success),
                    now,
                    job_id,
                    note_id,
                ),
            )
            column = "detail_succeeded" if success else "detail_failed"
            connection.execute(
                f"UPDATE jobs SET {column}={column}+1,updated_at=? WHERE id=?", (now, job_id)
            )

    def clear_source_private(self, job_id: str) -> None:
        """Discard a profile access token after enumeration can no longer use it."""

        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET source_private_cipher=NULL,updated_at=? WHERE id=?",
                (utc_now(), job_id),
            )
            if not cursor.rowcount:
                raise KeyError(job_id)

    def clear_note_private(self, job_id: str) -> None:
        """Discard every note access token when the task will not request details."""

        with self.transaction() as connection:
            connection.execute(
                "UPDATE notes SET private_cipher=NULL,updated_at=? WHERE job_id=?",
                (utc_now(), job_id),
            )

    def retry_failed_details(self, job_id: str) -> int:
        now = utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """UPDATE notes SET detail_status='pending',detail_error_code=NULL,updated_at=?
                   WHERE job_id=? AND detail_status='failed'""",
                (now, job_id),
            )
            connection.execute(
                "UPDATE jobs SET detail_failed=0,details_complete=0,updated_at=? WHERE id=?",
                (now, job_id),
            )
        return int(cursor.rowcount)

    def list_notes(self, job_id: str, *, limit: int | None = None, offset: int = 0) -> list[dict[str, Any]]:
        parameters: list[Any] = [job_id]
        sql = "SELECT * FROM notes WHERE job_id=? ORDER BY source_rank ASC"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            parameters.extend([max(1, min(int(limit), 1000)), max(0, int(offset))])
        with self.connection() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._note(row) for row in rows]

    def clear_all(self) -> None:
        with self.transaction() as connection:
            connection.execute("DELETE FROM auth_session")
            connection.execute("DELETE FROM jobs")

    def delete_job(self, job_id: str) -> bool:
        with self.transaction() as connection:
            cursor = connection.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        return bool(cursor.rowcount)
