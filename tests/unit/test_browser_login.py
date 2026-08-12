from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import Any

import pytest

from xhs_insight.browser_login import (
    BrowserLoginError,
    DirectQrLoginManager,
    _render_qr_png,
    _validate_qr_value,
)
from xhs_insight.platform import FailureKind, RedNoteProtocolError

_MISSING = object()


class _FakeDirectClient:
    def __init__(
        self,
        statuses: list[int] | None = None,
        *,
        geo_zone: Any = _MISSING,
    ) -> None:
        self.statuses = list(statuses or [0, 2])
        self.geo_zone = geo_zone
        self.calls: list[str] = []
        self.closed = False
        self.cookies = {"a1": "guest-a1", "web_session": "guest-session"}

    def login_activate(self) -> dict[str, Any]:
        self.calls.append("activate")
        return {"guest": True}

    def create_qr(self) -> dict[str, str]:
        self.calls.append("create")
        return {
            "qr_id": "private-qr-id",
            "code": "private-qr-code",
            "url": "https://www.xiaohongshu.com/login/qr?private-token",
        }

    def poll_qr(self, _qr_id: str, _code: str) -> dict[str, Any]:
        self.calls.append("poll")
        status = self.statuses.pop(0) if self.statuses else 0
        result: dict[str, Any] = {"codeStatus": status}
        if self.geo_zone is not _MISSING:
            result["geoZone"] = self.geo_zone
        if status == 2 and self.geo_zone is _MISSING:
            self.cookies["web_session"] = "formal-secret-session"
        return result

    def complete_qr(self, _qr_id: str, _code: str) -> dict[str, Any]:
        self.calls.append("complete")
        self.cookies["web_session"] = "formal-secret-session"
        return {"login_info": {"session": "formal-secret-session"}}

    def get_user_me(self) -> dict[str, Any]:
        self.calls.append("user-me")
        return {"guest": False, "user_id": "verified-user"}

    def cookie_header(self) -> str:
        return "; ".join(f"{key}={value}" for key, value in self.cookies.items())

    def close(self) -> None:
        self.calls.append("close")
        self.closed = True


def _manager(
    tmp_path: Path,
    importer: Any,
    fake: _FakeDirectClient,
    *,
    active_jobs: Any = lambda: False,
) -> DirectQrLoginManager:
    return DirectQrLoginManager(
        tmp_path,
        importer,
        active_jobs,
        client_factory=lambda: fake,
        poll_seconds=0.1,
    )


def _wait_for(
    manager: DirectQrLoginManager, statuses: set[str], timeout: float = 4
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = manager.status()
        if status["status"] in statuses:
            return status
        time.sleep(0.01)
    raise AssertionError(f"direct QR login did not reach {statuses}: {manager.status()}")


@pytest.mark.parametrize(
    "value",
    [
        "https://www.xiaohongshu.com/login/qr?token",
    ],
)
def test_qr_value_is_validated_and_rendered_locally(value: str) -> None:
    assert _validate_qr_value(value) == value
    image = _render_qr_png(value)
    assert image.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(image) < 1_000_000


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "xhsdiscover://login/qr?token",
        "http://www.xiaohongshu.com/login/qr?token",
        "https://attacker.invalid/login/qr?token",
        "file:///private/token",
        "https://",
        "xhsdiscover:///missing-host",
        "https://www.xiaohongshu.com/\nsecret",
        "x" * 4097,
    ],
)
def test_qr_value_rejects_unbounded_or_non_url_input(value: str) -> None:
    with pytest.raises(BrowserLoginError, match="二维码"):
        _validate_qr_value(value)


def test_direct_qr_source_has_no_remote_execution_or_browser_transport() -> None:
    source_path = Path(__file__).resolve().parents[2] / "src/xhs_insight/browser_login.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not ({"eval", "exec", "compile"} & called_names)
    for forbidden in (
        "subprocess",
        "devtools",
        "websocket",
        "generate_websectiga",
        "runInThisContext",
    ):
        assert forbidden.casefold() not in source.casefold()


def test_manager_publishes_only_png_then_persists_verified_cookie(tmp_path: Path) -> None:
    fake = _FakeDirectClient()
    observed: dict[str, Any] = {}

    def importer(cookie: str, cancelled: Any) -> dict[str, Any]:
        assert cancelled() is False
        observed["cookie"] = cookie
        return {"authenticated": True, "account_fingerprint": "safe"}

    manager = _manager(tmp_path, importer, fake)
    started = manager.start()
    assert "private" not in repr(started)
    assert started["failure_stage"] is None

    awaiting = _wait_for(manager, {"awaiting_scan", "succeeded"})
    if awaiting["status"] == "awaiting_scan":
        image, revision = manager.qr_image()
        assert image.startswith(b"\x89PNG")
        assert len(revision) == 16
    result = _wait_for(manager, {"succeeded"})

    assert result["authenticated"] is True
    assert result["failure_stage"] is None
    assert "private" not in repr(result)
    assert "formal-secret-session" in observed["cookie"]
    assert fake.calls == [
        "activate",
        "create",
        "poll",
        "poll",
        "user-me",
        "close",
    ]
    assert fake.closed is True
    with pytest.raises(BrowserLoginError, match="二维码"):
        manager.qr_image()


def test_scanned_qr_waits_for_optional_phone_verification(tmp_path: Path) -> None:
    fake = _FakeDirectClient(statuses=[1, 1, 2])
    manager = _manager(
        tmp_path,
        lambda _cookie, _cancelled: {"authenticated": True},
        fake,
    )

    manager.start()
    waiting = _wait_for(manager, {"awaiting_phone_confirmation"})

    assert waiting["authenticated"] is False
    assert waiting["qr_ready"] is False
    assert waiting["qr_url"] is None
    assert "短信验证" in waiting["message"]
    assert "手机端完成" in waiting["message"]

    result = _wait_for(manager, {"succeeded"})
    assert result["authenticated"] is True


def test_phone_confirmation_extends_deadline_once_and_remains_bounded(
    tmp_path: Path,
) -> None:
    fake = _FakeDirectClient(statuses=[0, *([1] * 100)])
    manager = _manager(
        tmp_path,
        lambda _cookie, _cancelled: {"authenticated": True},
        fake,
    )

    manager.start()
    waiting = _wait_for(manager, {"awaiting_phone_confirmation"})
    session = manager._session
    assert session is not None
    first_deadline = session.deadline
    first_expiry = waiting["expires_at"]
    remaining = first_deadline - time.monotonic()
    assert 295 <= remaining <= 300

    time.sleep(0.35)

    assert manager._session is session
    assert session.deadline == first_deadline
    assert manager.status()["expires_at"] == first_expiry
    manager.cancel()
    _wait_for(manager, {"cancelled"})


def test_manager_cancel_clears_qr_and_never_imports(tmp_path: Path) -> None:
    fake = _FakeDirectClient(statuses=[0])
    manager = _manager(
        tmp_path,
        lambda *_args: pytest.fail("cancelled login must not persist credentials"),
        fake,
    )
    manager.start()
    _wait_for(manager, {"awaiting_scan"})
    assert manager.status()["qr_ready"] is True

    cancelled = manager.cancel()
    assert cancelled["qr_ready"] is False
    result = _wait_for(manager, {"cancelled"})

    assert result["status"] == "cancelled"
    assert fake.closed is True
    with pytest.raises(BrowserLoginError, match="二维码"):
        manager.qr_image()


class _GuestClient(_FakeDirectClient):
    def get_user_me(self) -> dict[str, Any]:
        self.calls.append("user-me")
        return {"guest": True, "user_id": "guest"}


def test_guest_session_is_never_persisted(tmp_path: Path) -> None:
    fake = _GuestClient()
    manager = _manager(
        tmp_path,
        lambda *_args: pytest.fail("guest session must not persist"),
        fake,
    )
    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["error_code"] == "AUTH_VERIFY_FAILED"
    assert result["qr_ready"] is False


def test_manager_refuses_to_start_while_jobs_are_active(tmp_path: Path) -> None:
    manager = _manager(
        tmp_path,
        lambda *_args: {},
        _FakeDirectClient(),
        active_jobs=lambda: True,
    )

    with pytest.raises(PermissionError, match="任务"):
        manager.start()

    assert manager.status()["failure_stage"] is None


@pytest.mark.parametrize(
    ("failure_stage", "method_name"),
    [
        ("login_activate", "login_activate"),
        ("qr_create", "create_qr"),
        ("qr_poll", "poll_qr"),
        ("qr_complete", "complete_qr"),
        ("user_identity", "get_user_me"),
    ],
)
def test_failure_status_exposes_only_fixed_stage_and_error_code(
    tmp_path: Path,
    failure_stage: str,
    method_name: str,
) -> None:
    class FailingClient(_FakeDirectClient):
        pass

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RedNoteProtocolError(
            FailureKind.RISK_CONTROL,
            "operation-with-private-qr-id-and-verifyuuid",
            status_code=461,
            upstream_code=300015,
        )

    fake = FailingClient(
        statuses=[2],
        geo_zone=0 if method_name == "complete_qr" else _MISSING,
    )
    setattr(fake, method_name, fail)
    if method_name == "complete_qr":
        fake.get_user_me = lambda: {"guest": True, "user_id": "guest"}  # type: ignore[method-assign]
    manager = _manager(
        tmp_path,
        lambda _cookie, _cancelled: {"authenticated": True},
        fake,
    )

    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["failure_stage"] == failure_stage
    assert result["error_code"] == "PLATFORM_RISK_REJECTED"
    public = repr(result)
    assert "private-qr-id" not in public
    assert "verifyuuid" not in public
    assert "300015" not in public
    assert "461" not in public


def test_geo_zone_null_fails_closed_without_completion(tmp_path: Path) -> None:
    fake = _FakeDirectClient(statuses=[2], geo_zone=None)
    manager = _manager(
        tmp_path,
        lambda *_args: pytest.fail("null route must not persist credentials"),
        fake,
    )

    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["error_code"] == "UPSTREAM_SCHEMA_CHANGED"
    assert "complete" not in fake.calls
    assert "user-me" not in fake.calls


def test_domestic_geo_zone_completes_before_identity_check(tmp_path: Path) -> None:
    fake = _FakeDirectClient(statuses=[2], geo_zone=0)
    manager = _manager(
        tmp_path,
        lambda cookie, _cancelled: {"authenticated": "formal-secret-session" in cookie},
        fake,
    )

    manager.start()
    result = _wait_for(manager, {"succeeded"})

    assert result["authenticated"] is True
    assert fake.calls.count("complete") == 1
    assert fake.calls.count("user-me") == 1


@pytest.mark.parametrize("geo_zone", [1, 2])
def test_cross_region_geo_zone_fails_closed_without_completion(
    tmp_path: Path, geo_zone: int
) -> None:
    fake = _FakeDirectClient(statuses=[2], geo_zone=geo_zone)
    manager = _manager(
        tmp_path,
        lambda *_args: pytest.fail("unsupported route must not persist credentials"),
        fake,
    )

    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["error_code"] == "UPSTREAM_UNSUPPORTED"
    assert result["failure_stage"] == "qr_complete"
    assert "complete" not in fake.calls
    assert "user-me" not in fake.calls


@pytest.mark.parametrize("geo_zone", [True, "0", 9])
def test_unknown_geo_zone_fails_closed_without_completion(tmp_path: Path, geo_zone: Any) -> None:
    fake = _FakeDirectClient(statuses=[2], geo_zone=geo_zone)
    manager = _manager(
        tmp_path,
        lambda *_args: pytest.fail("unknown route must not persist credentials"),
        fake,
    )

    manager.start()
    result = _wait_for(manager, {"failed"})

    expected = "UPSTREAM_SCHEMA_CHANGED" if type(geo_zone) is not int else "UPSTREAM_UNSUPPORTED"
    assert result["error_code"] == expected
    assert "complete" not in fake.calls
    assert "user-me" not in fake.calls


def test_completion_protocol_error_checks_identity_exactly_once(tmp_path: Path) -> None:
    class CompletionRejectedClient(_FakeDirectClient):
        def poll_qr(self, qr_id: str, code: str) -> dict[str, Any]:
            result = super().poll_qr(qr_id, code)
            if result["codeStatus"] == 2:
                self.cookies["web_session"] = "formal-secret-session"
            return result

        def complete_qr(self, _qr_id: str, _code: str) -> dict[str, Any]:
            self.calls.append("complete")
            raise RedNoteProtocolError(
                FailureKind.RISK_CONTROL,
                "QR complete",
                status_code=461,
            )

    fake = CompletionRejectedClient(statuses=[2], geo_zone=0)
    manager = _manager(
        tmp_path,
        lambda cookie, _cancelled: {"authenticated": "formal-secret-session" in cookie},
        fake,
    )

    manager.start()
    result = _wait_for(manager, {"succeeded"})

    assert result["authenticated"] is True
    assert fake.calls.count("complete") == 1
    assert fake.calls.count("user-me") == 1


@pytest.mark.parametrize(
    ("status_code", "upstream_code", "expected"),
    [
        (471, None, "PLATFORM_CHALLENGE_REQUIRED"),
        (461, None, "PLATFORM_RISK_REJECTED"),
        (406, None, "CLIENT_INTEGRITY_REJECTED"),
        (None, 300015, "CLIENT_INTEGRITY_REJECTED"),
        (None, 300012, "NETWORK_OR_IP_BLOCKED"),
        (None, 300013, "RATE_LIMITED"),
        (429, None, "RATE_LIMITED"),
        (None, 429, "RATE_LIMITED"),
    ],
)
def test_protocol_metadata_maps_to_fixed_public_classification(
    tmp_path: Path,
    status_code: int | None,
    upstream_code: int | None,
    expected: str,
) -> None:
    class FailingClient(_FakeDirectClient):
        poll_calls = 0

        def poll_qr(self, _qr_id: str, _code: str) -> dict[str, int]:
            self.poll_calls += 1
            raise RedNoteProtocolError(
                FailureKind.RISK_CONTROL,
                "QR poll",
                status_code=status_code,
                upstream_code=upstream_code,
            )

    fake = FailingClient(statuses=[2])
    manager = _manager(
        tmp_path,
        lambda _cookie, _cancelled: {"authenticated": True},
        fake,
    )

    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["failure_stage"] == "qr_poll"
    assert result["error_code"] == expected
    expected_phrases = {
        "CLIENT_INTEGRITY_REJECTED": "客户端完整性",
        "NETWORK_OR_IP_BLOCKED": "网络或 IP",
        "PLATFORM_CHALLENGE_REQUIRED": "额外网页验证",
        "PLATFORM_RISK_REJECTED": "当前登录请求",
        "RATE_LIMITED": "限制",
    }
    assert expected_phrases[expected] in result["message"]
    assert fake.poll_calls == 1
    public = repr(result)
    if status_code is not None:
        assert str(status_code) not in public
    if upstream_code is not None:
        assert str(upstream_code) not in public


def test_unknown_exception_code_and_message_are_not_reflected(tmp_path: Path) -> None:
    class UnsafeKind:
        value = "risk_control"

    class UnsafeError(RuntimeError):
        kind = UnsafeKind()
        code = "verifyuuid-secret-value"

    class UnsafeClient(_FakeDirectClient):
        def poll_qr(self, _qr_id: str, _code: str) -> dict[str, int]:
            raise UnsafeError("raw response with cookie-secret and QR token")

    manager = _manager(
        tmp_path,
        lambda _cookie, _cancelled: {"authenticated": True},
        UnsafeClient(statuses=[2]),
    )

    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["failure_stage"] == "qr_poll"
    assert result["error_code"] == "RISK_CONTROLLED"
    public = repr(result)
    assert "verifyuuid-secret-value" not in public
    assert "cookie-secret" not in public
    assert "QR token" not in public


def test_unknown_browser_error_is_replaced_with_generic_failure(tmp_path: Path) -> None:
    class UnsafeClient(_FakeDirectClient):
        def create_qr(self) -> dict[str, str]:
            raise BrowserLoginError(
                "verifyuuid-secret-value",
                "raw response with cookie-secret and QR token",
            )

    manager = _manager(
        tmp_path,
        lambda _cookie, _cancelled: {"authenticated": True},
        UnsafeClient(),
    )

    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["failure_stage"] == "qr_create"
    assert result["error_code"] == "DIRECT_QR_FAILED"
    public = repr(result)
    assert "verifyuuid-secret-value" not in public
    assert "cookie-secret" not in public
    assert "QR token" not in public
