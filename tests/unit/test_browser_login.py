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


class _FakeDirectClient:
    def __init__(self, statuses: list[int] | None = None) -> None:
        self.statuses = list(statuses or [0, 2])
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

    def poll_qr(self, _qr_id: str, _code: str) -> dict[str, int]:
        self.calls.append("poll")
        status = self.statuses.pop(0) if self.statuses else 0
        return {"codeStatus": status}

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

    awaiting = _wait_for(manager, {"awaiting_scan", "succeeded"})
    if awaiting["status"] == "awaiting_scan":
        image, revision = manager.qr_image()
        assert image.startswith(b"\x89PNG")
        assert len(revision) == 16
    result = _wait_for(manager, {"succeeded"})

    assert result["authenticated"] is True
    assert "private" not in repr(result)
    assert "formal-secret-session" in observed["cookie"]
    assert fake.calls == [
        "activate",
        "create",
        "poll",
        "poll",
        "complete",
        "user-me",
        "close",
    ]
    assert fake.closed is True
    with pytest.raises(BrowserLoginError, match="二维码"):
        manager.qr_image()


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
