from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from xhs_insight.adapters import AdapterError
from xhs_insight.browser_login import (
    COOKIE_SOURCE_URL,
    OFFICIAL_LOGIN_URL,
    BrowserExecutable,
    BrowserLoginError,
    IsolatedBrowserLoginManager,
    _browser_argv,
    _CdpConnection,
    _cookie_header_from_cdp,
    _remove_profile,
    _validate_cdp_request,
)
from xhs_insight.domain import AdapterErrorCode


class _FakeBrowser:
    def __init__(self, cookies: list[str | None] | None = None) -> None:
        self.cookies = list(cookies or [None, "a1=secret-a1; web_session=secret-session"])
        self.closed = False
        self.running = True
        self.cookie_calls = 0

    def is_running(self) -> bool:
        return self.running and not self.closed

    def cookie_header(self) -> str | None:
        self.cookie_calls += 1
        if self.cookies:
            return self.cookies.pop(0)
        return None

    def close(self) -> None:
        self.closed = True


def _executable(tmp_path: Path) -> BrowserExecutable:
    return BrowserExecutable(tmp_path / "fixed-browser", "Synthetic Chrome")


def _manager(
    tmp_path: Path,
    importer: Any,
    browser: _FakeBrowser,
    *,
    active_jobs: Any = lambda: False,
) -> IsolatedBrowserLoginManager:
    manager = IsolatedBrowserLoginManager(
        tmp_path,
        importer,
        active_jobs,
        poll_seconds=0.1,
    )
    manager._executable = _executable(tmp_path)
    manager._browser_factory = lambda _executable, _state_dir: browser
    return manager


def _wait_for(
    manager: IsolatedBrowserLoginManager,
    statuses: set[str],
    timeout: float = 4,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = manager.status()
        if status["status"] in statuses:
            return status
        time.sleep(0.01)
    raise AssertionError(f"browser login did not reach {statuses}: {manager.status()}")


def test_launch_command_is_fixed_visible_isolated_and_secret_free(tmp_path: Path) -> None:
    executable = _executable(tmp_path)
    profile = tmp_path / "temporary-profile"

    argv = _browser_argv(executable, profile)

    assert argv[0] == str(executable.path)
    assert argv[-1] == OFFICIAL_LOGIN_URL
    assert "--remote-debugging-address=127.0.0.1" in argv
    assert "--remote-debugging-port=0" in argv
    assert f"--user-data-dir={profile}" in argv
    assert "--new-window" in argv
    assert not any(flag in argv for flag in ("--headless", "--no-sandbox", "--disable-web-security"))
    assert not any("cookie" in value.casefold() or "web_session" in value for value in argv)
    constructor = inspect.signature(IsolatedBrowserLoginManager).parameters
    assert "executable" not in constructor
    assert "browser_factory" not in constructor


def test_source_uses_no_page_script_execution_or_default_profile() -> None:
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
        "Runtime.evaluate",
        "document.cookie",
        "localStorage",
        "Network.getResponseBody",
        "--no-sandbox",
        "--disable-web-security",
        "--remote-allow-origins",
    ):
        assert forbidden not in source
    assert '"Network.getCookies"' in source
    assert '{"urls": [COOKIE_SOURCE_URL]}' in source
    assert "tempfile.mkdtemp" in source


def test_minimal_loopback_websocket_round_trip_uses_cdp_request_ids() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
    except PermissionError:
        listener.close()
        pytest.skip("sandbox does not permit loopback listeners")
    listener.listen(1)
    port = int(listener.getsockname()[1])
    observed: dict[str, Any] = {}

    def server() -> None:
        def receive_exact(connection: socket.socket, size: int) -> bytes:
            payload = bytearray()
            while len(payload) < size:
                payload.extend(connection.recv(size - len(payload)))
            return bytes(payload)

        connection, _address = listener.accept()
        with connection:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(connection.recv(4096))
            headers: dict[str, str] = {}
            for line in bytes(request).split(b"\r\n")[1:]:
                name, separator, value = line.partition(b":")
                if separator:
                    headers[name.decode("ascii").casefold()] = value.decode("ascii").strip()
            key = headers["sec-websocket-key"]
            accept = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"),
                    usedforsecurity=False,
                ).digest()
            ).decode("ascii")
            connection.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode("ascii")
            )
            first, second = receive_exact(connection, 2)
            assert first & 0x0F == 1
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", receive_exact(connection, 2))[0]
            mask = receive_exact(connection, 4)
            payload = receive_exact(connection, length)
            decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            observed.update(json.loads(decoded))
            response = json.dumps(
                {"id": observed["id"], "result": {"cookies": []}},
                separators=(",", ":"),
            ).encode("ascii")
            connection.sendall(bytes((0x81, len(response))) + response)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    client = _CdpConnection(port, "/devtools/browser/abcdefgh")
    try:
        result = client.call(
            "Network.getCookies",
            {"urls": [COOKIE_SOURCE_URL]},
            session_id="synthetic-session",
        )
    finally:
        client.close()
        listener.close()
        thread.join(timeout=2)

    assert result == {"cookies": []}
    assert observed["method"] == "Network.getCookies"
    assert observed["params"] == {"urls": [COOKIE_SOURCE_URL]}
    assert observed["sessionId"] == "synthetic-session"


@pytest.mark.parametrize(
    ("method", "params", "session_id"),
    [
        ("Runtime.evaluate", {"expression": "document.cookie"}, "session"),
        ("Storage.getCookies", {}, "session"),
        ("Network.getCookies", {"urls": ["https://attacker.invalid"]}, "session"),
        ("Network.getCookies", {"urls": [COOKIE_SOURCE_URL]}, None),
        ("Target.getTargets", {"unexpected": True}, None),
    ],
)
def test_cdp_capability_allowlist_rejects_unscoped_requests(
    method: str,
    params: dict[str, Any],
    session_id: str | None,
) -> None:
    with pytest.raises(BrowserLoginError, match="安全范围"):
        _validate_cdp_request(method, params, session_id)


def test_cookie_selection_is_url_domain_scoped_allowlisted_and_bounded() -> None:
    header = _cookie_header_from_cdp(
        [
            {"name": "a1", "value": "private-a1", "domain": ".xiaohongshu.com", "path": "/"},
            {
                "name": "web_session",
                "value": "private-session",
                "domain": ".xiaohongshu.com",
                "path": "/",
            },
            {"name": "webId", "value": "private-web-id", "domain": "edith.xiaohongshu.com", "path": "/"},
            {"name": "analytics", "value": "must-not-copy", "domain": ".xiaohongshu.com", "path": "/"},
            {"name": "gid", "value": "attacker", "domain": ".attacker.invalid", "path": "/"},
        ]
    )

    assert header is not None
    assert "a1=private-a1" in header
    assert "web_session=private-session" in header
    assert "webId=private-web-id" in header
    assert "analytics" not in header
    assert "attacker" not in header


def test_cookie_selection_requires_login_pair_and_prefers_specific_domain() -> None:
    assert (
        _cookie_header_from_cdp(
            [{"name": "a1", "value": "only-a1", "domain": ".xiaohongshu.com", "path": "/"}]
        )
        is None
    )
    header = _cookie_header_from_cdp(
        [
            {"name": "a1", "value": "parent", "domain": ".xiaohongshu.com", "path": "/"},
            {"name": "a1", "value": "specific", "domain": "edith.xiaohongshu.com", "path": "/"},
            {"name": "web_session", "value": "session", "domain": ".xiaohongshu.com", "path": "/"},
        ]
    )
    assert header is not None
    assert "a1=specific" in header
    assert "a1=parent" not in header


def test_manager_opens_browser_then_persists_only_after_existing_verifier(
    tmp_path: Path,
) -> None:
    browser = _FakeBrowser()
    observed: dict[str, str] = {}

    def importer(
        cookie: str,
        cancelled: Any,
        before_persist: Any,
    ) -> dict[str, Any]:
        assert cancelled() is False
        observed["cookie"] = cookie
        before_persist()
        return {"authenticated": True, "account_fingerprint": "safe"}

    manager = _manager(tmp_path, importer, browser)
    started = manager.start()
    assert started["browser_login_mode"] == "official_isolated_browser"
    assert started["browser_login_embedded_qr"] is False
    assert started["qr_url"] is None
    assert "secret" not in repr(started)

    result = _wait_for(manager, {"succeeded"})

    assert result["authenticated"] is True
    assert result["qr_ready"] is False
    assert result["failure_stage"] is None
    assert "secret" not in repr(result)
    assert observed["cookie"] == "a1=secret-a1; web_session=secret-session"
    assert browser.closed is True


def test_unverified_guest_cookie_waits_for_changed_verified_cookie(tmp_path: Path) -> None:
    guest = "a1=guest-a1; web_session=guest-session"
    formal = "a1=formal-a1; web_session=formal-session"
    browser = _FakeBrowser([guest, guest, formal])
    attempted: list[str] = []

    def importer(cookie: str, _cancelled: Any, before_persist: Any) -> dict[str, Any]:
        attempted.append(cookie)
        if cookie == guest:
            raise AdapterError(AdapterErrorCode.AUTH_EXPIRED)
        before_persist()
        return {"authenticated": True}

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    result = _wait_for(manager, {"succeeded"})

    assert result["authenticated"] is True
    assert attempted == [guest, formal]
    assert browser.cookie_calls >= 3
    assert browser.closed is True


def test_manager_cancel_closes_browser_and_never_imports(tmp_path: Path) -> None:
    browser = _FakeBrowser([None] * 100)
    manager = _manager(
        tmp_path,
        lambda *_args: pytest.fail("cancelled login must not import a Cookie"),
        browser,
    )
    manager.start()
    waiting = _wait_for(manager, {"awaiting_login"})
    assert waiting["qr_ready"] is False

    manager.cancel()
    result = _wait_for(manager, {"cancelled"})

    assert result["authenticated"] is False
    assert browser.closed is True


def test_manager_reports_closed_browser_without_internal_details(tmp_path: Path) -> None:
    browser = _FakeBrowser([None])
    browser.running = False
    manager = _manager(tmp_path, lambda *_args: {}, browser)

    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["error_code"] == "BROWSER_CLOSED"
    assert result["failure_stage"] == "browser_login"
    for marker in (str(tmp_path), "DevTools", "127.0.0.1", "web_session"):
        assert marker not in repr(result)


def test_profile_cleanup_failure_blocks_success_and_stays_redacted(tmp_path: Path) -> None:
    class CleanupFailBrowser(_FakeBrowser):
        def close(self) -> None:
            self.closed = True
            raise BrowserLoginError(
                "BROWSER_PROFILE_CLEANUP_FAILED",
                "临时浏览器资料未能安全清理，请关闭官方窗口后重试。",
            )

    browser = CleanupFailBrowser(["a1=secret-a1; web_session=secret-session"])

    def importer(_cookie: str, _cancelled: Any, before_persist: Any) -> dict[str, Any]:
        before_persist()
        pytest.fail("cleanup failure must prevent persistence")

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["error_code"] == "BROWSER_PROFILE_CLEANUP_FAILED"
    assert result["authenticated"] is False
    assert "secret" not in repr(result)


def test_manager_refuses_active_jobs_and_missing_browser(tmp_path: Path) -> None:
    active = _manager(
        tmp_path,
        lambda *_args: {},
        _FakeBrowser(),
        active_jobs=lambda: True,
    )
    with pytest.raises(PermissionError, match="任务"):
        active.start()

    missing = IsolatedBrowserLoginManager(
        tmp_path,
        lambda *_args: {},
        lambda: False,
    )
    missing._executable = None
    assert missing.capability()["browser_login_supported"] is False
    with pytest.raises(BrowserLoginError) as captured:
        missing.start()
    assert captured.value.code == "BROWSER_NOT_FOUND"


def test_disabled_embedded_qr_never_returns_browser_state(tmp_path: Path) -> None:
    manager = _manager(tmp_path, lambda *_args: {}, _FakeBrowser())

    with pytest.raises(BrowserLoginError) as captured:
        manager.qr_image()

    assert captured.value.code == "BROWSER_CONTROL_FAILED"
    assert "二维码" in captured.value.public_message


def test_profile_cleanup_removes_disposable_cookie_store(tmp_path: Path) -> None:
    profile = tmp_path / ".browser-login-test"
    profile.mkdir()
    (profile / "Cookies").write_bytes(b"private-cookie-material")

    assert _remove_profile(profile) is True

    assert not profile.exists()
    assert COOKIE_SOURCE_URL.endswith("/api/sns/web/v2/user/me")


def test_profile_cleanup_reports_a_locked_residual(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / ".browser-login-locked"
    profile.mkdir()
    monkeypatch.setattr("xhs_insight.browser_login.shutil.rmtree", lambda _path: None)
    monkeypatch.setattr("xhs_insight.browser_login.time.sleep", lambda _seconds: None)

    assert _remove_profile(profile) is False
