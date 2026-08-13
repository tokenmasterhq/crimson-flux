from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from xhs_insight.adapters import AuthManager, VerifiedLogin, normalize_cookie_header
from xhs_insight.api import Backend
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
    assert events == ["verified", "profile-cleaned", "closed", "persisted"]


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
        "adapter-closed",
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


def test_master_key_rotation_invalidates_existing_envelopes(tmp_path: Path) -> None:
    cipher = CredentialCipher(tmp_path / "master.key")
    envelope = cipher.encrypt_json({"value": "secret"}, aad="rotation-test")
    old_key = cipher.key_path.read_bytes()

    cipher.rotate()

    assert cipher.key_path.read_bytes() != old_key
    with pytest.raises(InvalidTag):
        cipher.decrypt_json(envelope, aad="rotation-test")
