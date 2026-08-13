import json
import time
from pathlib import Path

import pytest

from xhs_insight.adapters import AdapterError
from xhs_insight.config import Settings
from xhs_insight.domain import (
    AdapterErrorCode,
    ConfirmDetailsRequest,
    CreateJobRequest,
    DetailResult,
    JobStatus,
    PageResult,
)
from xhs_insight.exporting import Exporter
from xhs_insight.jobs import JobService
from xhs_insight.security import CredentialCipher
from xhs_insight.storage import Repository


class FakeAdapter:
    version = "fixture-v1"
    keyword_page_size = 2

    def keyword_page(self, keyword, cursor):
        page = cursor["page"]
        if page == 1:
            return PageResult(
                items=[
                    {"note_id": "n1", "source_page": 1, "title": keyword + " 1", "_private": {"token": "a"}},
                    {"note_id": "n1", "source_page": 1, "title": "duplicate"},
                ],
                next_cursor={"page": 2},
                has_more=True,
                raw_item_count=2,
            )
        return PageResult(
            items=[{"note_id": "n2", "source_page": 2, "title": keyword + " 2"}],
            next_cursor={"page": 3},
            has_more=True,
            raw_item_count=1,
        )

    def user_page(self, profile_url, cursor):
        self.last_profile_url = profile_url
        return PageResult(
            items=[
                {"note_id": "u1", "source_page": 1, "title": "user 1"},
                {"note_id": "u2", "source_page": 1, "title": "user 2"},
            ],
            next_cursor=None,
            has_more=False,
            raw_item_count=2,
        )

    def note_detail(self, note_id, private):
        return DetailResult(note_id=note_id, fields={"description": "detail " + note_id, "liked_count": 3})


def _service(tmp_path: Path, adapter=None) -> JobService:
    settings = Settings(
        host="127.0.0.1",
        port=8765,
        state_dir=tmp_path / "state",
        export_dir=tmp_path / "exports",
        max_keyword_items=1000,
        max_user_items=10000,
        pause_min_seconds=0,
        pause_max_seconds=0,
        open_browser=False,
    )
    settings.prepare()
    repository = Repository(settings.state_dir / "xhs-insight.sqlite3")
    cipher = CredentialCipher(settings.state_dir / ".session.key")
    adapter = adapter or FakeAdapter()
    return JobService(
        repository,
        cipher,
        adapter,
        Exporter(repository, settings.export_dir, collector_version=adapter.version),
        settings,
        authenticated=lambda: True,
        account_fingerprint=lambda: "account-1",
    )


def _wait(service: JobService, job_id: str, statuses: set[str], timeout: float = 10) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = service.get(job_id)
        if job["status"] in statuses:
            return job
        time.sleep(0.02)
    job = service.get(job_id)
    if job["status"] in statuses:
        return job
    raise AssertionError(job)


def test_keyword_exact_limit_and_details(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {"type": "keyword", "keyword": "露营", "limit": 2},
                    "content": {"preset": "full"},
                }
            )
        )
        done = _wait(service, job["id"], {"completed", "completed_with_warnings"})
        assert done["status"] == "completed"
        assert done["unique_notes"] == 2
        assert done["detail_succeeded"] == 2
        assert done["artifacts"] == {"csv": True, "jsonl": True, "manifest": True}
        assert all(
            note["private_cipher"] is None
            for note in service.repository.list_notes(job["id"])
        )
    finally:
        service.stop()


def test_user_details_require_second_confirmation(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {
                        "type": "user",
                        "profile_url": "https://www.xiaohongshu.com/user/profile/test-user",
                        "all": True,
                    },
                    "content": {"preset": "full"},
                }
            )
        )
        waiting = _wait(service, job["id"], {"awaiting_detail_confirmation"})
        assert waiting["unique_notes"] == 2
        service.confirm_details(
            job["id"], ConfirmDetailsRequest.model_validate({"content": {"preset": "full"}})
        )
        done = _wait(service, job["id"], {"completed", "completed_with_warnings"})
        assert done["status"] == "completed"
        assert done["detail_succeeded"] == 2
    finally:
        service.stop()


def test_user_access_query_is_encrypted_and_never_exported(tmp_path: Path) -> None:
    service = _service(tmp_path)
    secret = "sensitive-xsec-value"
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {
                        "type": "user",
                        "profile_url": (
                            "https://www.xiaohongshu.com/user/profile/test-user"
                            f"?xsec_token={secret}&xsec_source=pc_user&tracking=discarded"
                        ),
                        "all": True,
                    },
                    "content": {"preset": "basic"},
                }
            )
        )
        assert "xsec" not in job["source"]["profile_url"]
        done = _wait(service, job["id"], {"completed", "completed_with_warnings"})
        assert done["status"] == "completed"
        assert secret in service.adapter.last_profile_url
        assert service.repository.require_job(job["id"])["source_private_cipher"] is None
    finally:
        service.stop()

    persisted = (tmp_path / "state" / "xhs-insight.sqlite3").read_bytes()
    exported = b"".join(
        path.read_bytes() for path in (tmp_path / "exports").rglob("*") if path.is_file()
    )
    assert secret.encode() not in persisted
    assert secret.encode() not in exported


def test_network_retries_three_times_but_rate_limit_pauses_immediately(tmp_path: Path) -> None:
    class FlakyAdapter(FakeAdapter):
        attempts = 0

        def keyword_page(self, keyword, cursor):
            self.attempts += 1
            if self.attempts <= 3:
                raise AdapterError(AdapterErrorCode.NETWORK_ERROR)
            return super().keyword_page(keyword, cursor)

    flaky = FlakyAdapter()
    service = _service(tmp_path / "retry", flaky)
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {"type": "keyword", "keyword": "露营", "limit": 2},
                    "content": {"preset": "basic"},
                }
            )
        )
        done = _wait(service, job["id"], {"completed", "completed_with_warnings"})
        assert done["status"] == "completed"
        assert done["list_requests"] == 5
    finally:
        service.stop()

    class LimitedAdapter(FakeAdapter):
        def keyword_page(self, keyword, cursor):
            raise AdapterError(AdapterErrorCode.RATE_LIMITED, retry_after=30)

    service = _service(tmp_path / "limited", LimitedAdapter())
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                    "content": {"preset": "basic"},
                }
            )
        )
        paused = _wait(service, job["id"], {"paused_rate_limit"})
        assert paused["list_requests"] == 1
        assert paused["retry_after_at"]
        assert "30 秒" in paused["error_message"]
        with pytest.raises(ValueError, match="平台要求等待"):
            service.resume(job["id"])
    finally:
        service.stop()


def test_claimed_job_honours_cancel_before_any_upstream_request(tmp_path: Path) -> None:
    class CountingAdapter(FakeAdapter):
        calls = 0

        def keyword_page(self, keyword, cursor):
            self.calls += 1
            return super().keyword_page(keyword, cursor)

    adapter = CountingAdapter()
    service = _service(tmp_path, adapter)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                "content": {"preset": "basic"},
            }
        )
    )

    claimed = service.repository.next_runnable_job()
    assert claimed is not None
    assert claimed["status"] == "enumerating"
    service.cancel(job["id"])
    service._execute(job["id"])

    cancelled = service.get(job["id"])
    assert adapter.calls == 0
    assert cancelled["status"] == "cancelled"


def test_cursor_invalid_cannot_resume_through_cancelled_state(tmp_path: Path) -> None:
    service = _service(tmp_path)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                "content": {"preset": "basic"},
            }
        )
    )
    service.repository.update_job(
        job["id"],
        status=JobStatus.PAUSED_CURSOR_INVALID,
        stage=JobStatus.PAUSED_CURSOR_INVALID,
        error_code=AdapterErrorCode.RESUME_INCOMPATIBLE.value,
        termination_reason="resume_incompatible",
    )

    assert service.cancel(job["id"])["status"] == "cancelled"
    with pytest.raises(ValueError, match="游标已失效"):
        service.resume(job["id"])


def test_execute_rejects_job_from_different_adapter_version(tmp_path: Path) -> None:
    class CountingAdapter(FakeAdapter):
        calls = 0

        def keyword_page(self, keyword, cursor):
            self.calls += 1
            return super().keyword_page(keyword, cursor)

    adapter = CountingAdapter()
    service = _service(tmp_path, adapter)
    job = service.repository.create_job(
        source={"type": "keyword", "keyword": "露营", "limit": 1},
        content={"preset": "basic", "fields": ["author"]},
        adapter_version="older-adapter",
        account_fingerprint="account-1",
    )
    assert service.repository.next_runnable_job() is not None

    service._execute(job["id"])

    paused = service.get(job["id"])
    assert adapter.calls == 0
    assert paused["status"] == "paused_cursor_invalid"
    assert paused["error_code"] == AdapterErrorCode.RESUME_INCOMPATIBLE.value


def test_clear_all_removes_only_known_job_directories(tmp_path: Path) -> None:
    service = _service(tmp_path)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                "content": {"preset": "basic"},
            }
        )
    )
    service.cancel(job["id"])
    owned = service.settings.export_dir / job["id"]
    assert owned.is_dir()
    unrelated_file = service.settings.export_dir / "keep-me.txt"
    unrelated_file.write_text("sentinel", encoding="utf-8")
    unrelated_dir = service.settings.export_dir / "unrelated"
    unrelated_dir.mkdir()
    (unrelated_dir / "keep.txt").write_text("sentinel", encoding="utf-8")

    service.clear_all()

    assert not owned.exists()
    assert unrelated_file.read_text(encoding="utf-8") == "sentinel"
    assert (unrelated_dir / "keep.txt").read_text(encoding="utf-8") == "sentinel"
    assert service.repository.list_job_ids() == []


def test_clear_all_refuses_known_job_symlink(tmp_path: Path) -> None:
    service = _service(tmp_path)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                "content": {"preset": "basic"},
            }
        )
    )
    service.repository.update_job(
        job["id"],
        status=JobStatus.CANCELLED,
        stage=JobStatus.CANCELLED,
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("sentinel", encoding="utf-8")
    link = service.settings.export_dir / job["id"]
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(ValueError, match="不安全"):
        service.clear_all()

    assert sentinel.read_text(encoding="utf-8") == "sentinel"
    assert service.repository.require_job(job["id"])["status"] == "cancelled"


def test_clear_all_keeps_job_ownership_if_export_removal_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                "content": {"preset": "basic"},
            }
        )
    )
    service.cancel(job["id"])
    owned = service.settings.export_dir / job["id"]

    def fail_remove(_path: Path) -> None:
        raise OSError("synthetic removal failure")

    monkeypatch.setattr("xhs_insight.jobs.service.shutil.rmtree", fail_remove)
    with pytest.raises(OSError, match="synthetic removal failure"):
        service.clear_all()

    assert owned.is_dir()
    assert service.repository.require_job(job["id"])["status"] == "cancelled"


def test_pause_and_resume_preserve_completed_enumeration_reason(tmp_path: Path) -> None:
    service = _service(tmp_path)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                "content": {"preset": "basic"},
            }
        )
    )
    service.repository.save_page(
        job["id"],
        cursor={"page": 1},
        next_cursor=None,
        has_more=False,
        raw_count=1,
        skipped_count=0,
        items=[{"note_id": "n1", "source_page": 1}],
        limit=1,
    )
    service._pause_job(
        job["id"],
        JobStatus.PAUSED_RATE_LIMIT,
        AdapterErrorCode.RATE_LIMITED.value,
        "paused",
    )
    assert service.get(job["id"])["termination_reason"] == "reached_limit"

    resumed = service.resume(job["id"])
    assert resumed["status"] == "queued"
    assert resumed["termination_reason"] == "reached_limit"

    service.repository.update_job(
        job["id"], status=JobStatus.FETCHING_DETAILS, stage=JobStatus.FETCHING_DETAILS
    )
    service.repository.mark_interrupted()
    interrupted = service.get(job["id"])
    assert interrupted["status"] == "paused_interrupted"
    assert interrupted["termination_reason"] == "reached_limit"


def test_partial_nonretryable_error_uses_consistent_terminal_stage(tmp_path: Path) -> None:
    service = _service(tmp_path)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 2},
                "content": {"preset": "basic"},
            }
        )
    )
    assert service.repository.next_runnable_job() is not None
    service.repository.save_page(
        job["id"],
        cursor={"page": 1},
        next_cursor={"page": 2},
        has_more=True,
        raw_count=1,
        skipped_count=0,
        items=[{"note_id": "n1", "source_page": 1}],
        limit=2,
    )

    service._handle_error(
        job["id"], AdapterError(AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED)
    )

    warning = service.get(job["id"])
    assert warning["status"] == "completed_with_warnings"
    assert warning["stage"] == "completed_with_warnings"


def test_user_three_pages_exports_all_65_unique_notes(tmp_path: Path) -> None:
    class PagedUserAdapter(FakeAdapter):
        def user_page(self, profile_url, cursor):
            del profile_url
            offset = int(cursor.get("cursor") or 0)
            page_sizes = {0: 30, 30: 30, 60: 5}
            count = page_sizes[offset]
            next_offset = offset + count
            return PageResult(
                items=[
                    {
                        "note_id": f"u{index:03d}",
                        "source_page": offset // 30 + 1,
                        "title": f"user {index}",
                    }
                    for index in range(offset, next_offset)
                ],
                next_cursor={"cursor": str(next_offset)} if next_offset < 65 else None,
                has_more=next_offset < 65,
                raw_item_count=count,
            )

    service = _service(tmp_path, PagedUserAdapter())
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {
                        "type": "user",
                        "profile_url": "https://www.xiaohongshu.com/user/profile/test-user",
                        "all": True,
                    },
                    "content": {"preset": "basic"},
                }
            )
        )
        done = _wait(service, job["id"], {"completed", "completed_with_warnings"})
        assert done["status"] == "completed"
        assert done["unique_notes"] == 65
        assert done["pages_requested"] == 3
        assert done["list_requests"] == 3
        assert done["detail_requests"] == 0
        assert done["enumeration_complete"] is True
        assert done["termination_reason"] == "natural_end"
        manifest = json.loads(
            (tmp_path / "exports" / job["id"] / "manifest.json").read_text(encoding="utf-8")
        )
        assert manifest["counts"]["exported_rows"] == 65
    finally:
        service.stop()


def test_repeated_cursor_stops_with_partial_warning_instead_of_looping(tmp_path: Path) -> None:
    class RepeatingCursorAdapter(FakeAdapter):
        calls = 0

        def user_page(self, profile_url, cursor):
            del profile_url
            self.calls += 1
            return PageResult(
                items=[{"note_id": "u1", "source_page": 1, "title": "one"}],
                next_cursor=dict(cursor),
                has_more=True,
                raw_item_count=1,
            )

    adapter = RepeatingCursorAdapter()
    service = _service(tmp_path, adapter)
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {
                        "type": "user",
                        "profile_url": "https://www.xiaohongshu.com/user/profile/test-user",
                        "all": True,
                    },
                    "content": {"preset": "basic"},
                }
            )
        )
        done = _wait(service, job["id"], {"completed_with_warnings", "failed"})
        assert done["status"] == "completed_with_warnings"
        assert done["enumeration_complete"] is False
        assert done["termination_reason"] == "pagination_stalled"
        assert done["error_code"] == "PAGINATION_STALLED"
        assert done["unique_notes"] == 1
        assert adapter.calls == 1
    finally:
        service.stop()


def test_interrupted_page_checkpoint_resumes_without_duplicates(tmp_path: Path) -> None:
    service = _service(tmp_path)
    job = service.create(
        CreateJobRequest.model_validate(
            {
                "source": {"type": "keyword", "keyword": "露营", "limit": 2},
                "content": {"preset": "basic"},
            }
        )
    )
    service.repository.save_page(
        job["id"],
        cursor={"page": 1},
        next_cursor={"page": 2},
        has_more=True,
        raw_count=2,
        skipped_count=0,
        items=[
            {"note_id": "n1", "source_page": 1, "title": "first"},
            {"note_id": "n1", "source_page": 1, "title": "duplicate"},
        ],
        limit=2,
    )
    service.repository.update_job(
        job["id"], status="enumerating", stage="enumerating"
    )

    service.start()
    try:
        paused = _wait(service, job["id"], {"paused_interrupted"})
        assert paused["unique_notes"] == 1
        service.resume(job["id"])
        done = _wait(service, job["id"], {"completed", "completed_with_warnings"})
        assert done["status"] == "completed"
        assert done["unique_notes"] == 2
        assert [
            note["note_id"] for note in service.repository.list_notes(job["id"])
        ] == ["n1", "n2"]
    finally:
        service.stop()


def test_failed_detail_can_be_retried_without_reenumeration(tmp_path: Path) -> None:
    class RecoveringDetailAdapter(FakeAdapter):
        fail_details = True
        keyword_calls = 0

        def keyword_page(self, keyword, cursor):
            self.keyword_calls += 1
            return PageResult(
                items=[{"note_id": "n1", "source_page": 1, "title": keyword}],
                next_cursor=None,
                has_more=False,
                raw_item_count=1,
            )

        def note_detail(self, note_id, private):
            if self.fail_details:
                raise RuntimeError("synthetic detail failure")
            return super().note_detail(note_id, private)

    adapter = RecoveringDetailAdapter()
    service = _service(tmp_path, adapter)
    service.start()
    try:
        job = service.create(
            CreateJobRequest.model_validate(
                {
                    "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                    "content": {"preset": "full"},
                }
            )
        )
        warning = _wait(service, job["id"], {"completed_with_warnings"})
        assert warning["detail_failed"] == 1
        assert adapter.keyword_calls == 1

        adapter.fail_details = False
        service.retry_details(job["id"])
        done = _wait(service, job["id"], {"completed", "completed_with_warnings"})
        assert done["status"] == "completed"
        assert done["detail_succeeded"] == 1
        assert done["detail_failed"] == 0
        assert adapter.keyword_calls == 1
    finally:
        service.stop()
