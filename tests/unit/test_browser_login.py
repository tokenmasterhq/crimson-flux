from __future__ import annotations

import ast
import base64
import ctypes
import hashlib
import inspect
import json
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from xhs_insight.adapters import AdapterError
from xhs_insight.browser_login import (
    _WINDOWS_KNOWN_FOLDER_IDS,
    COOKIE_SOURCE_URL,
    OFFICIAL_LOGIN_URL,
    BrowserExecutable,
    BrowserLoginError,
    IsolatedBrowserLoginManager,
    _browser_argv,
    _browser_candidates,
    _CdpConnection,
    _cookie_header_from_cdp,
    _IsolatedBrowserSession,
    _LoginSession,
    _remove_profile,
    _terminate_browser_process,
    _validate_cdp_request,
    _windows_known_folder_path,
    _windows_known_folder_roots,
    _windows_taskkill_path,
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


def test_windows_known_folder_api_returns_path_and_frees_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backing = ctypes.create_unicode_buffer(r"C:\Trusted Apps")
    address = ctypes.cast(backing, ctypes.c_void_p).value
    freed: list[int | None] = []
    loaded: list[tuple[str, dict[str, Any]]] = []

    class Function:
        argtypes: Any = None
        restype: Any = None

        def __init__(self, implementation: Any) -> None:
            self.implementation = implementation

        def __call__(self, *args: Any) -> Any:
            return self.implementation(*args)

    def resolve(_folder: Any, _flags: int, _token: Any, output: Any) -> int:
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = address
        return 0

    shell32 = type("Shell32", (), {"SHGetKnownFolderPath": Function(resolve)})()
    ole32 = type(
        "Ole32",
        (),
        {
            "CoTaskMemFree": Function(
                lambda pointer: freed.append(ctypes.cast(pointer, ctypes.c_void_p).value)
            )
        },
    )()

    def load(name: str, **kwargs: Any) -> Any:
        loaded.append((name, kwargs))
        return shell32 if name == "shell32.dll" else ole32

    monkeypatch.setattr("xhs_insight.browser_login.ctypes.WinDLL", load, raising=False)

    result = _windows_known_folder_path(_WINDOWS_KNOWN_FOLDER_IDS[0])

    assert str(result).replace("\\", "/") == "C:/Trusted Apps"
    assert freed == [address]
    assert [name for name, _kwargs in loaded] == ["shell32.dll", "ole32.dll"]
    assert all(kwargs["winmode"] == 0x00000800 for _name, kwargs in loaded)


def test_windows_known_folder_failure_frees_any_returned_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backing = ctypes.create_unicode_buffer(r"C:\Must Not Execute")
    address = ctypes.cast(backing, ctypes.c_void_p).value
    freed: list[int | None] = []

    class Function:
        argtypes: Any = None
        restype: Any = None

        def __init__(self, implementation: Any) -> None:
            self.implementation = implementation

        def __call__(self, *args: Any) -> Any:
            return self.implementation(*args)

    def fail(_folder: Any, _flags: int, _token: Any, output: Any) -> int:
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = address
        return -1

    shell32 = type("Shell32", (), {"SHGetKnownFolderPath": Function(fail)})()
    ole32 = type(
        "Ole32",
        (),
        {
            "CoTaskMemFree": Function(
                lambda pointer: freed.append(ctypes.cast(pointer, ctypes.c_void_p).value)
            )
        },
    )()
    monkeypatch.setattr(
        "xhs_insight.browser_login.ctypes.WinDLL",
        lambda name, **_kwargs: shell32 if name == "shell32.dll" else ole32,
        raising=False,
    )

    assert _windows_known_folder_path(_WINDOWS_KNOWN_FOLDER_IDS[0]) is None
    assert freed == [address]


def test_windows_candidates_use_known_folder_roots_and_fixed_suffixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROGRAMFILES", r"D:\attacker")
    monkeypatch.setenv("PROGRAMFILES(X86)", r"D:\attacker-x86")
    monkeypatch.setenv("LOCALAPPDATA", r"D:\attacker-user")
    monkeypatch.setattr("xhs_insight.browser_login.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_known_folder_roots",
        lambda: (Path("C:/Trusted/SystemApps"), Path("C:/Trusted/UserApps")),
    )

    candidates = _browser_candidates()
    rendered = [str(item.path).replace("\\", "/") for item in candidates]

    assert len(rendered) == 6
    assert all(path.startswith("C:/Trusted/") for path in rendered)
    assert not any("attacker" in path.casefold() for path in rendered)
    assert all(
        path.endswith(
            (
                "/Google/Chrome/Application/chrome.exe",
                "/Microsoft/Edge/Application/msedge.exe",
                "/Chromium/Application/chrome.exe",
            )
        )
        for path in rendered
    )


def test_windows_known_folder_api_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROGRAMFILES", r"D:\attacker")
    monkeypatch.setenv("LOCALAPPDATA", r"D:\attacker-user")
    monkeypatch.setattr("xhs_insight.browser_login.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "xhs_insight.browser_login.ctypes.WinDLL",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
        raising=False,
    )

    assert _windows_known_folder_roots() == ()
    assert _browser_candidates() == ()


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
        "Network.enable",
    ):
        assert forbidden not in source
    assert '"Network.getCookies"' in source
    assert '{"urls": [COOKIE_SOURCE_URL]}' in source
    assert "tempfile.mkdtemp" in source


def test_session_initialization_does_not_enable_network_events_and_cookie_read_still_works(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any], str | None]] = []
    cookie_payload = [
        {"name": "a1", "value": "private-a1", "domain": ".xiaohongshu.com", "path": "/"},
        {
            "name": "web_session",
            "value": "private-session",
            "domain": ".xiaohongshu.com",
            "path": "/",
        },
    ]

    class FakeProcess:
        def __init__(self) -> None:
            self.running = True

        def poll(self) -> int | None:
            return None if self.running else 0

        def terminate(self) -> None:
            self.running = False

        def kill(self) -> None:
            self.running = False

        def wait(self, timeout: float) -> int:
            assert timeout > 0
            return 0

    class FakeConnection:
        def __init__(self, _port: int, _path: str) -> None:
            return None

        def call(
            self,
            method: str,
            params: dict[str, Any] | None = None,
            *,
            session_id: str | None = None,
        ) -> dict[str, Any]:
            calls.append((method, dict(params or {}), session_id))
            if method == "Target.getTargets":
                return {
                    "targetInfos": [
                        {
                            "type": "page",
                            "url": OFFICIAL_LOGIN_URL,
                            "targetId": "official-page",
                        }
                    ]
                }
            if method == "Target.attachToTarget":
                return {"sessionId": "official-session"}
            if method == "Network.getCookies":
                return {"cookies": cookie_payload}
            raise AssertionError(f"unexpected CDP method: {method}")

        def close(self) -> None:
            return None

    executable = _executable(tmp_path)
    monkeypatch.setattr(
        "xhs_insight.browser_login.subprocess.Popen",
        lambda *_args, **_kwargs: FakeProcess(),
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._read_devtools_endpoint",
        lambda *_args, **_kwargs: (49152, "/devtools/browser/abcdefgh"),
    )
    monkeypatch.setattr("xhs_insight.browser_login._CdpConnection", FakeConnection)

    session = _IsolatedBrowserSession(executable, tmp_path)
    try:
        assert [method for method, _params, _session_id in calls] == [
            "Target.getTargets",
            "Target.attachToTarget",
        ]
        assert session.cookie_header() == "a1=private-a1; web_session=private-session"
    finally:
        session.close()

    assert [method for method, _params, _session_id in calls] == [
        "Target.getTargets",
        "Target.attachToTarget",
        "Network.getCookies",
    ]
    assert calls[-1] == (
        "Network.getCookies",
        {"urls": [COOKIE_SOURCE_URL]},
        "official-session",
    )
    assert all(method != "Network.enable" for method, _params, _session_id in calls)


def test_windows_close_uses_bounded_taskkill_tree_before_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[Any] = []

    class WindowsProcess:
        pid = 4242

        def __init__(self) -> None:
            self.running = True

        def poll(self) -> int | None:
            events.append("poll")
            return None if self.running else 0

        def terminate(self) -> None:
            raise AssertionError("Windows must not terminate the root before taskkill /T")

        def kill(self) -> None:
            events.append("kill")
            self.running = False

        def wait(self, timeout: float) -> int:
            events.append(("wait", timeout))
            return 0

    def taskkill(command: list[str], **kwargs: Any) -> Any:
        events.append(("taskkill", command, kwargs))
        return type("Result", (), {"returncode": 1})()

    process = WindowsProcess()
    monkeypatch.setattr("xhs_insight.browser_login.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_taskkill_path",
        lambda: Path("C:/Windows/System32/taskkill.exe"),
    )
    monkeypatch.setattr("xhs_insight.browser_login.subprocess.run", taskkill)

    _terminate_browser_process(process)  # type: ignore[arg-type]

    taskkill_event = next(event for event in events if isinstance(event, tuple) and event[0] == "taskkill")
    assert str(taskkill_event[1][0]).replace("\\", "/") == (
        "C:/Windows/System32/taskkill.exe"
    )
    assert taskkill_event[1][1:] == ["/PID", "4242", "/T", "/F"]
    assert taskkill_event[2]["shell"] is False
    assert taskkill_event[2]["timeout"] == 12.0
    assert taskkill_event[2]["stdin"] is subprocess.DEVNULL
    assert taskkill_event[2]["stdout"] is subprocess.DEVNULL
    assert taskkill_event[2]["stderr"] is subprocess.DEVNULL
    assert "kill" in events
    assert ("wait", 3) in events


def test_windows_taskkill_timeout_has_bounded_direct_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[Any] = []

    class WindowsProcess:
        pid = 5151

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def kill() -> None:
            events.append("kill")

        @staticmethod
        def wait(timeout: float) -> int:
            events.append(("wait", timeout))
            return 0

    def timeout(*_args: Any, **_kwargs: Any) -> Any:
        events.append("taskkill-timeout")
        raise subprocess.TimeoutExpired("taskkill", 12)

    monkeypatch.setattr("xhs_insight.browser_login.platform.system", lambda: "Windows")
    monkeypatch.setattr("xhs_insight.browser_login.subprocess.run", timeout)

    _terminate_browser_process(WindowsProcess())  # type: ignore[arg-type]

    assert events == ["taskkill-timeout", "kill", ("wait", 3)]


def test_windows_taskkill_path_rejects_relative_environment_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEMROOT", "attacker-controlled-relative")
    monkeypatch.delenv("WINDIR", raising=False)

    result = str(_windows_taskkill_path()).replace("/", "\\")

    assert result.casefold() == "c:\\windows\\system32\\taskkill.exe"
    assert "attacker-controlled" not in result


def test_windows_taskkill_path_ignores_absolute_environment_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEMROOT", "D:\\attacker\\controlled")
    monkeypatch.setenv("WINDIR", "D:\\attacker\\controlled")

    result = str(_windows_taskkill_path()).replace("/", "\\")

    assert result.casefold().endswith("\\system32\\taskkill.exe")
    assert "attacker" not in result.casefold()


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
        ("Network.enable", {}, "session"),
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
    manager_holder: dict[str, IsolatedBrowserLoginManager] = {}

    def importer(
        cookie: str,
        cancelled: Any,
        before_persist: Any,
    ) -> dict[str, Any]:
        assert cancelled() is False
        observed["cookie"] = cookie
        commit_guard = before_persist()
        with commit_guard:
            observed["cleanup_message"] = manager_holder["manager"].status()["message"]
            return {"authenticated": True, "account_fingerprint": "safe"}

    manager = _manager(tmp_path, importer, browser)
    manager_holder["manager"] = manager
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
    assert observed["cleanup_message"] == (
        "账号验证通过，正在安全关闭临时浏览器并保存登录状态…"
    )
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
        commit_guard = before_persist()
        with commit_guard:
            return {"authenticated": True}

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    result = _wait_for(manager, {"succeeded"})

    assert result["authenticated"] is True
    assert attempted == [guest, formal]
    assert browser.cookie_calls >= 3
    assert browser.closed is True


def test_verification_crossing_deadline_finishes_expired_not_succeeded(
    tmp_path: Path,
) -> None:
    browser = _FakeBrowser(["a1=formal-a1; web_session=formal-session"])
    manager_holder: dict[str, IsolatedBrowserLoginManager] = {}

    def importer(
        _cookie: str,
        stopped: Any,
        _before_persist: Any,
    ) -> dict[str, Any]:
        assert stopped() is False
        active = manager_holder["manager"]._session
        assert active is not None
        active.deadline = time.monotonic() - 1
        assert stopped() is True
        raise PermissionError("stopped before persistence")

    manager = _manager(tmp_path, importer, browser)
    manager_holder["manager"] = manager
    manager.start()
    result = _wait_for(manager, {"expired"})

    assert result["status"] == "expired"
    assert result["authenticated"] is False
    assert result["error_code"] == "LOGIN_EXPIRED"
    assert browser.closed is True


def test_cancel_during_bounded_verification_cannot_publish_success(tmp_path: Path) -> None:
    browser = _FakeBrowser(["a1=formal-a1; web_session=formal-session"])
    importer_entered = threading.Event()
    importer_release = threading.Event()

    def importer(
        _cookie: str,
        stopped: Any,
        _before_persist: Any,
    ) -> dict[str, Any]:
        importer_entered.set()
        assert importer_release.wait(timeout=2)
        assert stopped() is True
        raise PermissionError("cancelled before persistence")

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    assert importer_entered.wait(timeout=2)
    manager.cancel()
    importer_release.set()
    result = _wait_for(manager, {"cancelled"})

    assert result["authenticated"] is False
    assert result["error_code"] is None
    assert browser.closed is True


def test_persist_commit_wins_and_concurrent_cancel_reports_succeeded(
    tmp_path: Path,
) -> None:
    browser = _FakeBrowser(["a1=formal-a1; web_session=formal-session"])
    persist_entered = threading.Event()
    persist_release = threading.Event()
    cancel_finished = threading.Event()
    cancel_result: dict[str, Any] = {}

    def importer(
        _cookie: str,
        _stopped: Any,
        before_persist: Any,
    ) -> dict[str, Any]:
        commit_guard = before_persist()
        with commit_guard:
            persist_entered.set()
            assert persist_release.wait(timeout=2)
            return {"authenticated": True}

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    assert persist_entered.wait(timeout=2)

    def cancel() -> None:
        cancel_result.update(manager.cancel())
        cancel_finished.set()

    cancel_thread = threading.Thread(target=cancel)
    cancel_thread.start()
    assert cancel_finished.wait(timeout=0.1) is False
    persist_release.set()
    cancel_thread.join(timeout=2)

    assert cancel_finished.is_set()
    assert cancel_result["status"] == "succeeded"
    assert cancel_result["authenticated"] is True
    assert manager.status()["status"] == "succeeded"
    assert manager._session is not None
    assert manager._session.committed is True
    assert manager._session.cancel_event.is_set() is False


def test_deadline_status_closes_browser_while_verifier_is_blocked(
    tmp_path: Path,
) -> None:
    browser = _FakeBrowser(["a1=formal-a1; web_session=formal-session"])
    verifier_entered = threading.Event()
    verifier_release = threading.Event()

    def importer(
        _cookie: str,
        stopped: Any,
        _before_persist: Any,
    ) -> dict[str, Any]:
        verifier_entered.set()
        assert verifier_release.wait(timeout=2)
        assert stopped() is True
        raise PermissionError("deadline won before commit")

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    assert verifier_entered.wait(timeout=2)
    assert manager._session is not None
    manager._session.deadline = time.monotonic() - 1

    expired = manager.status()

    assert expired["status"] == "expired"
    assert expired["authenticated"] is False
    assert browser.closed is True
    verifier_release.set()
    result = _wait_for(manager, {"expired"})
    assert result["status"] == "expired"


def test_deadline_wins_after_cleanup_and_commit_guard_rejects_late_persist(
    tmp_path: Path,
) -> None:
    browser = _FakeBrowser(["a1=formal-a1; web_session=formal-session"])
    guard_ready = threading.Event()
    commit_release = threading.Event()
    persisted = threading.Event()

    def importer(
        _cookie: str,
        _stopped: Any,
        before_persist: Any,
    ) -> dict[str, Any]:
        commit_guard = before_persist()
        guard_ready.set()
        assert commit_release.wait(timeout=2)
        with commit_guard:
            persisted.set()
            return {"authenticated": True}

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    assert guard_ready.wait(timeout=2)
    assert manager._session is not None
    manager._session.deadline = time.monotonic() - 1
    assert manager.status()["status"] == "expired"
    commit_release.set()
    result = _wait_for(manager, {"expired"})

    assert result["authenticated"] is False
    assert persisted.is_set() is False
    assert manager._session.committed is False


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


def test_non_browser_cleanup_error_is_terminal_and_retained_for_retry(
    tmp_path: Path,
) -> None:
    class RetryCleanupBrowser(_FakeBrowser):
        def __init__(self) -> None:
            super().__init__(["a1=secret-a1; web_session=secret-session"])
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls <= 2:
                raise OSError("synthetic locked profile")
            self.closed = True

    browser = RetryCleanupBrowser()

    def importer(_cookie: str, _cancelled: Any, before_persist: Any) -> dict[str, Any]:
        before_persist()
        pytest.fail("cleanup failure must prevent persistence")

    manager = _manager(tmp_path, importer, browser)
    manager.start()
    result = _wait_for(manager, {"failed"})

    assert result["error_code"] == "BROWSER_PROFILE_CLEANUP_FAILED"
    assert manager._session is not None
    assert manager._session.browser is browser

    cleared = manager.cancel()

    assert cleared["status"] == "idle"
    assert browser.closed is True
    assert browser.close_calls == 3


def test_dead_active_worker_self_heals_and_closes_retained_browser(tmp_path: Path) -> None:
    browser = _FakeBrowser([None])
    manager = _manager(tmp_path, lambda *_args: {}, browser)
    dead_worker = threading.Thread(target=lambda: None)
    dead_worker.start()
    dead_worker.join(timeout=1)
    now = time.time()
    manager._session = _LoginSession(
        internal_id="synthetic",
        created_at=now,
        deadline=time.monotonic() + 60,
        expires_at="2099-01-01T00:00:00+00:00",
        status="verifying",
        thread=dead_worker,
        browser=browser,
    )

    result = manager.status()

    assert result["status"] == "failed"
    assert result["error_code"] == "BROWSER_CONTROL_FAILED"
    assert browser.closed is True
    assert manager._session.browser is None


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


def test_windows_profile_cleanup_uses_bounded_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / ".browser-login-windows-locked"
    profile.mkdir()
    delays: list[float] = []
    monkeypatch.setattr("xhs_insight.browser_login.platform.system", lambda: "Windows")
    monkeypatch.setattr("xhs_insight.browser_login.shutil.rmtree", lambda _path: None)
    monkeypatch.setattr("xhs_insight.browser_login.time.sleep", delays.append)

    assert _remove_profile(profile) is False

    assert delays == [0.1, 0.2, 0.4, 0.8, 1.0, 1.5, 2.0, 2.0, 2.0, 2.0]
    assert sum(delays) == pytest.approx(12.0)
