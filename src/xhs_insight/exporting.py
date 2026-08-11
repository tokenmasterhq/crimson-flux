"""Deterministic CSV, JSONL and manifest exports from SQLite records."""

from __future__ import annotations

import csv
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xhs_insight import __version__
from xhs_insight.domain import ContentSelection, FieldGroup
from xhs_insight.security import redact_text, sanitize_url
from xhs_insight.storage import Repository

SCHEMA_VERSION = "1.0"

CORE_COLUMNS = [
    "schema_version",
    "job_id",
    "source_type",
    "source_query",
    "source_page",
    "source_rank",
    "note_id",
    "note_url",
    "note_type",
    "title",
    "collected_at",
    "detail_status",
    "detail_error_code",
]
GROUP_COLUMNS: dict[FieldGroup, list[str]] = {
    FieldGroup.AUTHOR: ["author_id", "author_name", "author_profile_url"],
    FieldGroup.BODY: ["description", "published_at", "updated_at"],
    FieldGroup.TAGS: ["tag_names"],
    FieldGroup.METRICS: [
        "liked_count",
        "collected_count",
        "comment_count",
        "share_count",
    ],
    FieldGroup.MEDIA: ["image_count", "image_urls", "has_video", "video_url"],
}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _iso_time(value: Any) -> str | None:
    """Return a UTC ISO-8601 timestamp, or ``None`` for untrusted input."""

    if value is None or isinstance(value, bool):
        return None
    candidate: datetime
    try:
        if isinstance(value, (int, float)):
            seconds = float(value)
            if abs(seconds) >= 100_000_000_000:
                seconds /= 1000
            candidate = datetime.fromtimestamp(seconds, UTC)
        else:
            text = str(value).strip()
            if not text:
                return None
            try:
                seconds = float(text)
            except ValueError:
                candidate = datetime.fromisoformat(text.replace("Z", "+00:00"))
            else:
                if abs(seconds) >= 100_000_000_000:
                    seconds /= 1000
                candidate = datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    if candidate.tzinfo is None:
        candidate = candidate.replace(tzinfo=UTC)
    return candidate.astimezone(UTC).isoformat(timespec="seconds")


def _int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().replace(",", "")
    multiplier = 1
    if text.endswith("万"):
        text, multiplier = text[:-1], 10_000
    elif text.endswith("千"):
        text, multiplier = text[:-1], 1_000
    try:
        return max(0, int(float(text) * multiplier))
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).replace("\x00", "")


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value is None or value == "":
        return []
    return [str(value)]


def _normalize_record(job: dict[str, Any], note: dict[str, Any]) -> dict[str, Any]:
    listed = dict(note.get("list_data") or {})
    detail = dict(note.get("detail_data") or {})
    merged = {**listed, **detail}
    source = job["source"]
    source_query = source.get("keyword") if job["source_type"] == "keyword" else source.get("profile_url")
    image_urls = [url for item in _list(merged.get("image_urls")) if (url := sanitize_url(item))]
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "job_id": job["id"],
        "source_type": job["source_type"],
        "source_query": source_query,
        "source_page": note["source_page"],
        "source_rank": note["source_rank"],
        "note_id": note["note_id"],
        "note_url": sanitize_url(merged.get("note_url")),
        "note_type": merged.get("note_type") if merged.get("note_type") in {"image", "video"} else "unknown",
        "title": _text(merged.get("title")) or "",
        "collected_at": _iso_time(merged.get("collected_at"))
        or _iso_time(note["created_at"])
        or _now(),
        "detail_status": note["detail_status"],
        "detail_error_code": note.get("detail_error_code"),
        "author_id": _text(merged.get("author_id")),
        "author_name": _text(merged.get("author_name")),
        "author_profile_url": sanitize_url(merged.get("author_profile_url")),
        "description": _text(merged.get("description")),
        "published_at": _iso_time(merged.get("published_at")),
        "updated_at": _iso_time(merged.get("updated_at")),
        "tag_names": _list(merged.get("tag_names")),
        "liked_count": _int_or_none(merged.get("liked_count")),
        "collected_count": _int_or_none(merged.get("collected_count")),
        "comment_count": _int_or_none(merged.get("comment_count")),
        "share_count": _int_or_none(merged.get("share_count")),
        "image_count": _int_or_none(merged.get("image_count")) or len(image_urls),
        "image_urls": image_urls,
        "has_video": bool(merged.get("has_video") or merged.get("video_url")),
        "video_url": sanitize_url(merged.get("video_url")),
    }
    return record


def selected_columns(content: ContentSelection) -> list[str]:
    columns = list(CORE_COLUMNS)
    for group in FieldGroup:
        if group in content.fields:
            columns.extend(GROUP_COLUMNS[group])
    return columns


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + value
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Exporter:
    def __init__(self, repository: Repository, export_root: str | Path, *, collector_version: str):
        self.repository = repository
        self.export_root = Path(export_root).expanduser().resolve()
        self.collector_version = collector_version

    def export(self, job_id: str, *, status_override: str | None = None) -> dict[str, str]:
        job = self.repository.require_job(job_id)
        content = ContentSelection.model_validate(job["content"])
        columns = selected_columns(content)
        notes = self.repository.list_notes(job_id)
        records = [_normalize_record(job, note) for note in notes]
        target = self.export_root / job_id
        target.mkdir(parents=True, exist_ok=True)
        csv_path = target / "notes.csv"
        jsonl_path = target / "notes.jsonl"
        manifest_path = target / "manifest.json"
        csv_temp = target / ".notes.csv.tmp"
        jsonl_temp = target / ".notes.jsonl.tmp"
        manifest_temp = target / ".manifest.json.tmp"

        with csv_temp.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for record in records:
                writer.writerow({key: _csv_value(record.get(key)) for key in columns})
            handle.flush()
            os.fsync(handle.fileno())

        with jsonl_temp.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                projected = {key: record.get(key) for key in columns}
                handle.write(json.dumps(projected, ensure_ascii=False, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(csv_temp, csv_path)
        os.replace(jsonl_temp, jsonl_path)

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "job_id": job_id,
            "app_version": __version__,
            "collector_version": self.collector_version,
            "created_at": job["created_at"],
            "exported_at": _now(),
            "status": status_override or job["status"],
            "source": job["source"],
            "content": {
                "preset": content.preset.value,
                "fields": sorted(field.value for field in content.fields),
                "columns": columns,
            },
            "scope": {
                "enumeration_complete": job["enumeration_complete"],
                "details_complete": job["details_complete"],
                "limit_satisfied": job["limit_satisfied"],
                "termination_reason": job["termination_reason"],
            },
            "counts": {
                "list_requests": job["list_requests"],
                "detail_requests": job["detail_requests"],
                "total_requests": job["list_requests"] + job["detail_requests"],
                "pages_requested": job["pages_requested"],
                "raw_items_received": job["raw_items_received"],
                "skipped_items": job["skipped_items"],
                "duplicates_dropped": job["duplicates_dropped"],
                "unique_notes": len(records),
                "detail_succeeded": job["detail_succeeded"],
                "detail_failed": job["detail_failed"],
                "exported_rows": len(records),
            },
            "error": {
                "code": job["error_code"],
                "message": redact_text(job["error_message"]),
            }
            if job["error_code"]
            else None,
            "outputs": [
                {
                    "filename": csv_path.name,
                    "rows": len(records),
                    "bytes": csv_path.stat().st_size,
                    "sha256": _sha256(csv_path),
                },
                {
                    "filename": jsonl_path.name,
                    "rows": len(records),
                    "bytes": jsonl_path.stat().st_size,
                    "sha256": _sha256(jsonl_path),
                },
            ],
            "privacy": {
                "credentials_written": False,
                "auth_query_params_removed": True,
                "csv_formula_escaped": True,
            },
        }
        with manifest_temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(manifest_temp, manifest_path)
        return {
            "csv": str(csv_path),
            "jsonl": str(jsonl_path),
            "manifest": str(manifest_path),
        }
