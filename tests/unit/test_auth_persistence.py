from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag

from xhs_insight.adapters import AuthManager, VerifiedLogin, normalize_cookie_header
from xhs_insight.api import Backend
from xhs_insight.api.app import CredentialChangeConflict
from xhs_insight.api.router import _auth_import_error
from xhs_insight.config import Settings
from xhs_insight.domain import CreateJobRequest, PageResult
from xhs_insight.exporting import Exporter
from xhs_insight.jobs import JobService
from xhs_insight.security import CredentialCipher
from xhs_insight.storage import Repository


def test_auth_is_encrypted_reloaded_and_irrecoverable_after_logout(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    repository = Repository(database)
    cipher = CredentialCipher(tmp_path / "master.key")
    manager = AuthManager(repository, cipher)
    cookie = "a1=top-secret-a1; web_session=top-secret-session"

    saved = manager.persist_verified_login(cookie=cookie, account_id="account-1")
    assert saved["authenticated"] is True
    assert cookie.encode() not in database.read_bytes()

    restored = AuthManager(repository, CredentialCipher(tmp_path / "master.key"))
    assert restored.authenticated is True
    assert restored.require_payload()["cookie"] == cookie

    restored.logout()
    assert repository.load_auth() is None
    assert restored.authenticated is False
    assert cookie.encode() not in database.read_bytes()


@pytest.mark.parametrize(
    "cookie",
    [
        "a1=one; a1=two; web_session=session",
        "a1=one\r\nX-Injected: yes; web_session=session",
        "a1=one; missing-equals; web_session=session",
        "a1=one",
    ],
)
def test_cookie_import_rejects_ambiguous_or_incomplete_headers(cookie: str) -> None:
    with pytest.raises(ValueError) as raised:
        normalize_cookie_header(cookie)
    assert "one" not in str(raised.value)
    assert "session" not in str(raised.value)


def test_cookie_import_accepts_a_single_devtools_header_label() -> None:
    assert normalize_cookie_header(
        " Cookie: a1=one; web_session=session; webBuild=4.3.7 "
    ) == "a1=one; web_session=session; webBuild=4.3.7"


def test_verified_login_repr_never_contains_credential_material() -> None:
    verified = VerifiedLogin(
        cookie="a1=top-secret; web_session=top-secret-session",
        account_id="account-1",
        host_cookies={"edith.xiaohongshu.com": {"acw_tc": "top-secret-edge"}},
        host_cookie_state={"values": {"edith.xiaohongshu.com": {"acw_tc": "secret"}}},
    )
    rendered = repr(verified)
    assert "top-secret" not in rendered
    assert "acw_tc" not in rendered


def test_backend_persists_only_the_adapter_verified_credential() -> None:
    verified = VerifiedLogin(
        cookie="a1=verified-a1; web_session=verified-session",
        account_id="account-1",
        host_cookies={"edith.xiaohongshu.com": {"acw_tc": "edge"}},
        host_cookie_state={"values": {}},
    )
    events: list[str] = []

    class FakeRepository:
        @staticmethod
        def has_running_or_queued_jobs() -> bool:
            return False

    class FakeAdapter:
        @staticmethod
        def verify_cookie(cookie: str) -> VerifiedLogin:
            assert cookie == "unverified-input"
            events.append("verified")
            return verified

        @staticmethod
        def close() -> None:
            events.append("closed")

    class FakeAuth:
        @staticmethod
        def persist_verified_login(**kwargs: object) -> dict[str, object]:
            assert kwargs["cookie"] == verified.cookie
            assert kwargs["account_id"] == verified.account_id
            events.append("persisted")
            return {"authenticated": True}

    backend = Backend(
        settings=object(),  # type: ignore[arg-type]
        repository=FakeRepository(),  # type: ignore[arg-type]
        cipher=object(),  # type: ignore[arg-type]
        auth=FakeAuth(),
        adapter=FakeAdapter(),
        exporter=object(),  # type: ignore[arg-type]
        jobs=object(),  # type: ignore[arg-type]
    )

    assert backend.import_cookie(
        "unverified-input",
        before_persist=lambda: events.append("profile-cleaned"),
    ) == {"authenticated": True}
    assert events == ["verified", "profile-cleaned", "persisted"]


def test_backend_wraps_final_checks_and_persist_in_returned_commit_guard() -> None:
    verified = VerifiedLogin(
        cookie="a1=verified-a1; web_session=verified-session",
        account_id="account-1",
    )
    events: list[str] = []

    class FakeRepository:
        @staticmethod
        def has_running_or_queued_jobs() -> bool:
            events.append("jobs-checked")
            return False

    class FakeAdapter:
        @staticmethod
        def verify_cookie(_cookie: str) -> VerifiedLogin:
            events.append("verified")
            return verified

        @staticmethod
        def close() -> None:
            events.append("adapter-closed")

    class FakeAuth:
        @staticmethod
        def persist_verified_login(**_kwargs: object) -> dict[str, object]:
            events.append("persisted")
            return {"authenticated": True}

    class CommitGuard:
        def __enter__(self) -> None:
            events.append("commit-enter")

        def __exit__(self, *_args: object) -> None:
            events.append("commit-exit")

    backend = Backend(
        settings=object(),  # type: ignore[arg-type]
        repository=FakeRepository(),  # type: ignore[arg-type]
        cipher=object(),  # type: ignore[arg-type]
        auth=FakeAuth(),
        adapter=FakeAdapter(),
        exporter=object(),  # type: ignore[arg-type]
        jobs=object(),  # type: ignore[arg-type]
    )

    def before_persist() -> CommitGuard:
        events.append("profile-cleaned")
        return CommitGuard()

    result = backend.import_cookie(
        "candidate",
        before_persist=before_persist,
    )

    assert result == {"authenticated": True}
    assert events == [
        "jobs-checked",
        "verified",
        "jobs-checked",
        "profile-cleaned",
        "commit-enter",
        "jobs-checked",
        "persisted",
        "commit-exit",
    ]


def test_backend_never_persists_when_isolated_profile_cleanup_fails() -> None:
    verified = VerifiedLogin(
        cookie="a1=verified-a1; web_session=verified-session",
        account_id="account-1",
    )

    class IdleRepository:
        @staticmethod
        def has_running_or_queued_jobs() -> bool:
            return False

    class VerifiedAdapter:
        @staticmethod
        def verify_cookie(_cookie: str) -> VerifiedLogin:
            return verified

    class ForbiddenAuth:
        @staticmethod
        def persist_verified_login(**_kwargs: object) -> dict[str, object]:
            raise AssertionError("credential must not persist before profile cleanup")

    backend = Backend(
        settings=object(),  # type: ignore[arg-type]
        repository=IdleRepository(),  # type: ignore[arg-type]
        cipher=object(),  # type: ignore[arg-type]
        auth=ForbiddenAuth(),
        adapter=VerifiedAdapter(),
        exporter=object(),  # type: ignore[arg-type]
        jobs=object(),  # type: ignore[arg-type]
    )

    def fail_cleanup() -> None:
        raise RuntimeError("cleanup failed")

    with pytest.raises(RuntimeError, match="cleanup failed"):
        backend.import_cookie(
            "candidate",
            before_persist=fail_cleanup,
        )


def test_backend_refuses_credential_change_while_a_job_is_active() -> None:
    class ActiveRepository:
        @staticmethod
        def has_running_or_queued_jobs() -> bool:
            return True

    class ForbiddenAdapter:
        @staticmethod
        def verify_cookie(_cookie: str) -> VerifiedLogin:
            raise AssertionError("active jobs must be checked before verification")

    backend = Backend(
        settings=object(),  # type: ignore[arg-type]
        repository=ActiveRepository(),  # type: ignore[arg-type]
        cipher=object(),  # type: ignore[arg-type]
        auth=object(),
        adapter=ForbiddenAdapter(),
        exporter=object(),  # type: ignore[arg-type]
        jobs=object(),  # type: ignore[arg-type]
    )

    with pytest.raises(PermissionError, match="任务"):
        backend.import_cookie("must-not-be-read")


def test_backend_never_persists_an_unverified_cookie() -> None:
    class IdleRepository:
        @staticmethod
        def has_running_or_queued_jobs() -> bool:
            return False

    class RejectingAdapter:
        @staticmethod
        def verify_cookie(_cookie: str) -> VerifiedLogin:
            raise ValueError("credential rejected")

    class ForbiddenAuth:
        @staticmethod
        def persist_verified_login(**_kwargs: object) -> dict[str, object]:
            raise AssertionError("unverified credentials must never be persisted")

    backend = Backend(
        settings=object(),  # type: ignore[arg-type]
        repository=IdleRepository(),  # type: ignore[arg-type]
        cipher=object(),  # type: ignore[arg-type]
        auth=ForbiddenAuth(),
        adapter=RejectingAdapter(),
        exporter=object(),  # type: ignore[arg-type]
        jobs=object(),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="rejected"):
        backend.import_cookie("a1=unverified; web_session=unverified")


def test_credential_change_conflict_maps_to_stable_http_409() -> None:
    error = _auth_import_error(CredentialChangeConflict())

    assert error.status_code == 409
    assert error.detail == {
        "code": "CREDENTIAL_CHANGE_CONFLICT",
        "message": "登录状态已在验证期间发生变化，本次验证结果未保存。",
        "retryable": False,
    }


class _RaceAdapter:
    version = "credential-race-v1"
    keyword_page_size = 20

    def __init__(self, auth: AuthManager) -> None:
        self.auth = auth
        self.request_accounts: list[str] = []
        self.close_calls = 0

    @staticmethod
    def verify_cookie(cookie: str) -> VerifiedLogin:
        assert cookie == "a1=new-a1; web_session=new-session"
        return VerifiedLogin(cookie=cookie, account_id="new-account")

    def close(self) -> None:
        self.close_calls += 1

    def keyword_page(self, _keyword: str, _cursor: dict[str, Any]) -> PageResult:
        self.request_accounts.append(str(self.auth.require_payload()["account_id"]))
        return PageResult(
            items=[{"note_id": "race-note", "source_page": 1, "title": "race"}],
            next_cursor=None,
            has_more=False,
            raw_item_count=1,
        )


def _fingerprint(account_id: str) -> str:
    return hashlib.sha256(f"xhs-account:{account_id}".encode()).hexdigest()


def _race_backend(tmp_path: Path) -> tuple[Backend, _RaceAdapter]:
    settings = Settings(
        host="127.0.0.1",
        port=8765,
        state_dir=tmp_path / "state",
        export_dir=tmp_path / "exports",
        max_keyword_items=100,
        max_user_items=100,
        pause_min_seconds=0,
        pause_max_seconds=0,
        open_browser=False,
    )
    settings.prepare()
    repository = Repository(settings.state_dir / "state.sqlite3")
    cipher = CredentialCipher(settings.state_dir / "master.key")
    auth = AuthManager(repository, cipher)
    auth.persist_verified_login(
        cookie="a1=old-a1; web_session=old-session",
        account_id="old-account",
    )
    adapter = _RaceAdapter(auth)
    exporter = Exporter(repository, settings.export_dir, collector_version=adapter.version)
    jobs = JobService(
        repository,
        cipher,
        adapter,
        exporter,
        settings,
        authenticated=lambda: auth.authenticated,
        account_fingerprint=lambda: auth.account_fingerprint,
    )
    return (
        Backend(settings, repository, cipher, auth, adapter, exporter, jobs),
        adapter,
    )


def _race_job_request() -> CreateJobRequest:
    return CreateJobRequest.model_validate(
        {
            "source": {"type": "keyword", "keyword": "race", "limit": 1},
            "content": {"preset": "basic"},
        }
    )


def test_job_create_wins_atomic_boundary_and_credential_commit_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, adapter = _race_backend(tmp_path)
    original_save = backend.repository.save_auth_if_no_running_or_queued_jobs
    original_create = backend.repository.create_job
    reached_create = threading.Barrier(2)
    release_create = threading.Event()
    reached_commit = threading.Barrier(2)
    release_commit = threading.Event()
    import_errors: list[BaseException] = []
    create_errors: list[BaseException] = []
    created: list[dict[str, Any]] = []

    def delayed_create(**kwargs: Any) -> dict[str, Any]:
        reached_create.wait(timeout=5)
        assert release_create.wait(timeout=5)
        return original_create(**kwargs)

    def delayed_save(payload_cipher: bytes, account_fingerprint: str) -> None:
        reached_commit.wait(timeout=5)
        assert release_commit.wait(timeout=5)
        original_save(payload_cipher, account_fingerprint)

    monkeypatch.setattr(
        backend.repository,
        "save_auth_if_no_running_or_queued_jobs",
        delayed_save,
    )
    monkeypatch.setattr(backend.repository, "create_job", delayed_create)

    def create_old_account_job() -> None:
        try:
            created.append(backend.jobs.create(_race_job_request()))
        except BaseException as error:
            create_errors.append(error)

    def import_new_credential() -> None:
        try:
            backend.import_cookie("a1=new-a1; web_session=new-session")
        except BaseException as error:
            import_errors.append(error)

    create_thread = threading.Thread(target=create_old_account_job)
    create_thread.start()
    reached_create.wait(timeout=5)
    import_thread = threading.Thread(target=import_new_credential)
    import_thread.start()
    reached_commit.wait(timeout=5)
    release_create.set()
    create_thread.join(timeout=5)
    release_commit.set()
    import_thread.join(timeout=5)

    assert not create_thread.is_alive()
    assert not import_thread.is_alive()
    assert create_errors == []
    assert len(created) == 1
    assert len(import_errors) == 1
    assert isinstance(import_errors[0], PermissionError)
    assert "登录态未保存" in str(import_errors[0])
    assert backend.auth.require_payload()["account_id"] == "old-account"
    assert backend.repository.load_auth()["account_fingerprint"] == _fingerprint(
        "old-account"
    )
    assert backend.repository.require_job(created[0]["id"])[
        "account_fingerprint"
    ] == _fingerprint("old-account")
    assert adapter.request_accounts == []


def test_credential_commit_wins_and_stale_create_binds_new_account(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, adapter = _race_backend(tmp_path)
    original_create = backend.repository.create_job
    captured_old_fingerprint = threading.Barrier(2)
    release_create = threading.Event()
    created: list[dict[str, Any]] = []
    errors: list[BaseException] = []

    def delayed_create(**kwargs: Any) -> dict[str, Any]:
        assert kwargs["account_fingerprint"] == _fingerprint("old-account")
        captured_old_fingerprint.wait(timeout=5)
        assert release_create.wait(timeout=5)
        return original_create(**kwargs)

    monkeypatch.setattr(backend.repository, "create_job", delayed_create)

    def create_with_stale_snapshot() -> None:
        try:
            created.append(backend.jobs.create(_race_job_request()))
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=create_with_stale_snapshot)
    thread.start()
    captured_old_fingerprint.wait(timeout=5)
    try:
        result = backend.import_cookie("a1=new-a1; web_session=new-session")
    finally:
        release_create.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == []
    assert result["account_fingerprint"] == _fingerprint("new-account")
    assert len(created) == 1
    job_id = created[0]["id"]
    assert backend.repository.require_job(job_id)["account_fingerprint"] == _fingerprint(
        "new-account"
    )

    backend.jobs.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if backend.repository.require_job(job_id)["status"] == "completed":
                break
            time.sleep(0.01)
        assert backend.repository.require_job(job_id)["status"] == "completed"
    finally:
        backend.jobs.stop()

    assert adapter.request_accounts == ["new-account"]
    assert "old-account" not in adapter.request_accounts


def test_rejected_credential_commit_never_closes_an_active_old_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, adapter = _race_backend(tmp_path)
    original_job_check = backend.repository.has_running_or_queued_jobs
    final_check_reached = threading.Barrier(2)
    release_final_check = threading.Event()
    request_entered = threading.Event()
    release_request = threading.Event()
    check_count = 0
    import_errors: list[BaseException] = []

    def staged_job_check() -> bool:
        nonlocal check_count
        check_count += 1
        result = original_job_check()
        if check_count == 3:
            final_check_reached.wait(timeout=5)
            assert release_final_check.wait(timeout=5)
        return result

    def blocking_keyword_page(_keyword: str, _cursor: dict[str, Any]) -> PageResult:
        request_entered.set()
        assert release_request.wait(timeout=5)
        adapter.request_accounts.append(
            str(backend.auth.require_payload()["account_id"])
        )
        return PageResult(
            items=[{"note_id": "active-note", "source_page": 1}],
            next_cursor=None,
            has_more=False,
            raw_item_count=1,
        )

    monkeypatch.setattr(
        backend.repository,
        "has_running_or_queued_jobs",
        staged_job_check,
    )
    monkeypatch.setattr(adapter, "keyword_page", blocking_keyword_page)

    def import_new_credential() -> None:
        try:
            backend.import_cookie("a1=new-a1; web_session=new-session")
        except BaseException as error:
            import_errors.append(error)

    import_thread = threading.Thread(target=import_new_credential)
    import_thread.start()
    final_check_reached.wait(timeout=5)
    job = backend.jobs.create(_race_job_request())
    backend.jobs.start()
    try:
        assert request_entered.wait(timeout=5)
        release_final_check.set()
        import_thread.join(timeout=5)

        assert not import_thread.is_alive()
        assert len(import_errors) == 1
        assert isinstance(import_errors[0], PermissionError)
        assert backend.auth.require_payload()["account_id"] == "old-account"
        assert adapter.close_calls == 0
        assert backend.repository.require_job(job["id"])["status"] == "enumerating"
    finally:
        release_final_check.set()
        release_request.set()
        backend.jobs.stop()

    assert adapter.request_accounts == ["old-account"]


def test_logout_wins_against_slow_import_and_late_result_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, adapter = _race_backend(tmp_path)
    verification_started = threading.Barrier(2)
    release_verification = threading.Event()
    errors: list[BaseException] = []

    def slow_verify(cookie: str) -> VerifiedLogin:
        verification_started.wait(timeout=5)
        assert release_verification.wait(timeout=5)
        return VerifiedLogin(cookie=cookie, account_id="late-account")

    monkeypatch.setattr(adapter, "verify_cookie", slow_verify)

    def import_late() -> None:
        try:
            backend.import_cookie("a1=late-a1; web_session=late-session")
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=import_late)
    thread.start()
    verification_started.wait(timeout=5)
    backend.logout()
    assert backend.auth.authenticated is False
    assert backend.repository.load_auth() is None
    release_verification.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(errors) == 1
    assert getattr(errors[0], "code", None) == "CREDENTIAL_CHANGE_CONFLICT"
    assert backend.auth.authenticated is False
    assert backend.repository.load_auth() is None
    assert adapter.close_calls == 1


def test_first_concurrent_import_commit_wins_and_late_finisher_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, adapter = _race_backend(tmp_path)
    slow_verification_started = threading.Barrier(2)
    release_slow_verification = threading.Event()
    slow_errors: list[BaseException] = []

    def ordered_verify(cookie: str) -> VerifiedLogin:
        if "slow" in cookie:
            slow_verification_started.wait(timeout=5)
            assert release_slow_verification.wait(timeout=5)
            return VerifiedLogin(cookie=cookie, account_id="slow-account")
        return VerifiedLogin(cookie=cookie, account_id="fast-account")

    monkeypatch.setattr(adapter, "verify_cookie", ordered_verify)

    def import_slow() -> None:
        try:
            backend.import_cookie("a1=slow-a1; web_session=slow-session")
        except BaseException as error:
            slow_errors.append(error)

    slow_thread = threading.Thread(target=import_slow)
    slow_thread.start()
    slow_verification_started.wait(timeout=5)
    fast = backend.import_cookie("a1=fast-a1; web_session=fast-session")
    release_slow_verification.set()
    slow_thread.join(timeout=5)

    assert not slow_thread.is_alive()
    assert fast["account_fingerprint"] == _fingerprint("fast-account")
    assert len(slow_errors) == 1
    assert getattr(slow_errors[0], "code", None) == "CREDENTIAL_CHANGE_CONFLICT"
    assert backend.auth.require_payload()["account_id"] == "fast-account"
    assert backend.repository.load_auth()["account_fingerprint"] == _fingerprint(
        "fast-account"
    )
    assert adapter.close_calls == 0


def test_logout_rejects_a_creator_with_stale_fingerprint_and_no_request_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, adapter = _race_backend(tmp_path)
    original_create = backend.repository.create_job
    stale_snapshot_captured = threading.Barrier(2)
    release_create = threading.Event()
    create_errors: list[BaseException] = []

    def delayed_create(**kwargs: Any) -> dict[str, Any]:
        assert kwargs["account_fingerprint"] == _fingerprint("old-account")
        stale_snapshot_captured.wait(timeout=5)
        assert release_create.wait(timeout=5)
        return original_create(**kwargs)

    monkeypatch.setattr(backend.repository, "create_job", delayed_create)

    def create_from_stale_snapshot() -> None:
        try:
            backend.jobs.create(_race_job_request())
        except BaseException as error:
            create_errors.append(error)

    thread = threading.Thread(target=create_from_stale_snapshot)
    thread.start()
    stale_snapshot_captured.wait(timeout=5)
    backend.logout()
    release_create.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(create_errors) == 1
    assert isinstance(create_errors[0], PermissionError)
    assert backend.repository.list_jobs() == []
    assert backend.repository.load_auth() is None
    assert backend.auth.authenticated is False
    backend.jobs.start()
    try:
        time.sleep(0.1)
    finally:
        backend.jobs.stop()
    assert adapter.request_accounts == []
    assert adapter.close_calls == 1


def test_master_key_rotation_invalidates_existing_envelopes(tmp_path: Path) -> None:
    cipher = CredentialCipher(tmp_path / "master.key")
    envelope = cipher.encrypt_json({"value": "secret"}, aad="rotation-test")
    old_key = cipher.key_path.read_bytes()

    cipher.rotate()

    assert cipher.key_path.read_bytes() != old_key
    with pytest.raises(InvalidTag):
        cipher.decrypt_json(envelope, aad="rotation-test")
