import csv
import hashlib
import json
from pathlib import Path

from xhs_insight.domain import ContentSelection
from xhs_insight.exporting import Exporter
from xhs_insight.storage import Repository


def _create_job(repository: Repository) -> dict:
    return repository.create_job(
        source={"type": "keyword", "keyword": "测试", "limit": 2},
        content=ContentSelection.model_validate({"preset": "full"}).model_dump(mode="json"),
        adapter_version="fixture-v1",
        account_fingerprint="account-1",
    )


def test_page_checkpoint_deduplicates_and_resumes(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "state.db")
    job = _create_job(repository)
    first = repository.save_page(
        job["id"],
        cursor={"page": 1},
        next_cursor={"page": 2},
        has_more=True,
        raw_count=2,
        skipped_count=0,
        items=[
            {"note_id": "n1", "source_page": 1, "title": "one"},
            {"note_id": "n1", "source_page": 1, "title": "duplicate"},
        ],
        limit=2,
    )
    assert first == {"added": 1, "duplicates": 1, "already_saved": False}
    second = repository.save_page(
        job["id"],
        cursor={"page": 2},
        next_cursor=None,
        has_more=False,
        raw_count=1,
        skipped_count=0,
        items=[{"note_id": "n2", "source_page": 2, "title": "two"}],
        limit=2,
    )
    assert second["added"] == 1
    assert [note["note_id"] for note in repository.list_notes(job["id"])] == ["n1", "n2"]


def test_page_checkpoint_commits_terminal_scope_with_records(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "state.db")
    job = _create_job(repository)

    repository.save_page(
        job["id"],
        cursor={"page": 1},
        next_cursor=None,
        has_more=False,
        raw_count=1,
        skipped_count=0,
        items=[{"note_id": "n1", "source_page": 1}],
        limit=1,
    )

    persisted = repository.require_job(job["id"])
    assert persisted["unique_notes"] == 1
    assert persisted["cursor"] is None
    assert persisted["enumeration_complete"] is True
    assert persisted["limit_satisfied"] is True
    assert persisted["termination_reason"] == "reached_limit"


def test_user_cursor_identity_ignores_page_and_no_more_beats_safety_cap(
    tmp_path: Path,
) -> None:
    repository = Repository(tmp_path / "state.db")
    source = {
        "type": "user",
        "profile_url": "https://www.xiaohongshu.com/user/profile/test-user",
        "all": True,
    }
    content = ContentSelection.model_validate({"preset": "basic"}).model_dump(mode="json")

    repeated_job = repository.create_job(
        source=source,
        content=content,
        adapter_version="fixture-v1",
        account_fingerprint="account-1",
    )
    repository.save_page(
        repeated_job["id"],
        cursor={"cursor": ""},
        next_cursor={"cursor": "opaque-a", "page": 2},
        has_more=True,
        raw_count=1,
        skipped_count=0,
        items=[{"note_id": "u1", "source_page": 1}],
        limit=10,
    )
    repository.save_page(
        repeated_job["id"],
        cursor={"cursor": "opaque-a", "page": 2},
        next_cursor={"cursor": "opaque-a", "page": 3},
        has_more=True,
        raw_count=1,
        skipped_count=0,
        items=[{"note_id": "u2", "source_page": 2}],
        limit=10,
    )
    repeated = repository.require_job(repeated_job["id"])
    assert repeated["termination_reason"] == "pagination_stalled"
    assert repeated["enumeration_complete"] is False
    assert repository.has_page_cursor(
        repeated_job["id"], {"cursor": "opaque-a", "page": 999}
    )

    exact_cap_job = repository.create_job(
        source=source,
        content=content,
        adapter_version="fixture-v1",
        account_fingerprint="account-1",
    )
    repository.save_page(
        exact_cap_job["id"],
        cursor={"cursor": ""},
        next_cursor=None,
        has_more=False,
        raw_count=2,
        skipped_count=0,
        items=[{"note_id": "c1"}, {"note_id": "c2"}],
        limit=2,
    )
    exact_cap = repository.require_job(exact_cap_job["id"])
    assert exact_cap["unique_notes"] == 2
    assert exact_cap["enumeration_complete"] is True
    assert exact_cap["termination_reason"] == "natural_end"

    truncated_job = repository.create_job(
        source=source,
        content=content,
        adapter_version="fixture-v1",
        account_fingerprint="account-1",
    )
    repository.save_page(
        truncated_job["id"],
        cursor={"cursor": ""},
        next_cursor=None,
        has_more=False,
        raw_count=3,
        skipped_count=0,
        items=[{"note_id": "t1"}, {"note_id": "t2"}, {"note_id": "t3"}],
        limit=2,
    )
    truncated = repository.require_job(truncated_job["id"])
    assert truncated["unique_notes"] == 2
    assert truncated["enumeration_complete"] is False
    assert truncated["termination_reason"] == "safety_cap"
    assert truncated["error_code"] == "SAFETY_CAP"
    repository.update_job(
        truncated_job["id"], status="enumerating", stage="enumerating"
    )
    repository.mark_interrupted()
    assert repository.require_job(truncated_job["id"])["termination_reason"] == "safety_cap"
    repository.queue_job(truncated_job["id"])
    assert repository.require_job(truncated_job["id"])["termination_reason"] == "safety_cap"


def test_csv_jsonl_and_manifest_share_rows(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "state.db")
    job = _create_job(repository)
    repository.save_page(
        job["id"],
        cursor={"page": 1},
        next_cursor=None,
        has_more=False,
        raw_count=2,
        skipped_count=0,
        items=[
            {
                "note_id": "n1",
                "source_page": 1,
                "title": "=SUM(1,1)",
                "note_url": "https://www.xiaohongshu.com/explore/n1?xsec_token=secret",
                "author_name": "作者",
                "collected_at": "2026-08-10T12:00:00+08:00",
                "_private_cipher": b"encrypted-note-1",
            },
            {
                "note_id": "n2",
                "source_page": 1,
                "title": "中文,引号\"与\n换行",
                "collected_at": "2026-08-10T12:00:00+08:00",
                "_private_cipher": b"encrypted-note-2",
            },
        ],
        limit=2,
    )
    repository.prepare_details(job["id"])
    repository.save_detail(
        job["id"],
        "n1",
        detail={
            "description": "正文",
            "tag_names": ["A", "B"],
            "liked_count": "1.2万",
            "published_at": 1_786_317_600_000,
            "updated_at": "not-a-time",
            "image_urls": ["https://img.example/a.jpg?token=secret"],
        },
    )
    repository.save_detail(job["id"], "n2", detail=None, error_code="DELETED")
    notes_after_detail = repository.list_notes(job["id"])
    assert notes_after_detail[0]["private_cipher"] is None
    assert notes_after_detail[1]["private_cipher"] == b"encrypted-note-2"
    repository.update_job(
        job["id"],
        status="completed_with_warnings",
        stage="completed_with_warnings",
        enumeration_complete=True,
        details_complete=False,
        limit_satisfied=True,
        termination_reason="reached_limit",
    )
    paths = Exporter(repository, tmp_path / "exports", collector_version="fixture-v1").export(job["id"])
    with Path(paths["csv"]).open(encoding="utf-8-sig", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    json_rows = [json.loads(line) for line in Path(paths["jsonl"]).read_text().splitlines()]
    assert [row["note_id"] for row in csv_rows] == [row["note_id"] for row in json_rows]
    assert csv_rows[0]["title"].startswith("'")
    assert json_rows[0]["title"] == "=SUM(1,1)"
    assert json_rows[0]["liked_count"] == 12000
    assert json_rows[0]["collected_at"] == "2026-08-10T04:00:00+00:00"
    assert json_rows[0]["published_at"].endswith("+00:00")
    assert json_rows[0]["updated_at"] is None
    combined = Path(paths["csv"]).read_bytes() + Path(paths["jsonl"]).read_bytes()
    assert b"xsec_token" not in combined
    manifest = json.loads(Path(paths["manifest"]).read_text())
    assert manifest["collector_version"] == "fixture-v1"
    assert manifest["counts"]["exported_rows"] == 2
    for output in manifest["outputs"]:
        data = (Path(paths["manifest"]).parent / output["filename"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == output["sha256"]
