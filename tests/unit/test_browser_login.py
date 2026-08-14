from __future__ import annotations

import ast
import base64
import ctypes
import hashlib
import inspect
import json
import os
import shutil
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
    _create_owned_profile,
    _create_owned_profile_root,
    _create_owned_profile_root_at,
    _IsolatedBrowserSession,
    _LoginSession,
    _remove_profile,
    _remove_profile_root,
    _terminate_browser_process,
    _validate_cdp_request,
    _windows_known_folder_path,
    _windows_known_folder_roots,
    _windows_private_directory_sddl,
    _windows_taskkill_path,
    _windows_trusted_temp_parent,
    _windows_validate_private_directory_dacl,
    _windows_validate_private_file_dacl,
    _write_owned_marker,
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
    manager._profile_root = _create_owned_profile_root_at(tmp_path)
    manager._browser_factory = lambda _executable, _profile_root: browser
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
    assert "CreateDirectoryW" in source
    assert "CreateFileW" in source
    assert "WriteFile" in source
    assert "FlushFileBuffers" in source
    assert not any(value in source for value in ("USERNAME", "USERDOMAIN", "icacls"))


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

    root = _create_owned_profile_root_at(tmp_path)
    session = _IsolatedBrowserSession(executable, root)
    try:
        assert [method for method, _params, _session_id in calls] == [
            "Target.getTargets",
            "Target.attachToTarget",
        ]
        assert session.cookie_header() == "a1=private-a1; web_session=private-session"
    finally:
        session.close()
        assert _remove_profile_root(root) is True

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
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_taskkill_path",
        lambda: Path("C:/Windows/System32/taskkill.exe"),
    )
    monkeypatch.setattr("xhs_insight.browser_login.subprocess.run", timeout)

    _terminate_browser_process(WindowsProcess())  # type: ignore[arg-type]

    assert events == ["taskkill-timeout", "kill", ("wait", 3)]


def test_windows_taskkill_path_rejects_relative_environment_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Function:
        argtypes: Any = None
        restype: Any = None

        @staticmethod
        def __call__(buffer: Any, _size: int) -> int:
            buffer.value = r"C:\Windows\System32"
            return len(buffer.value)

    monkeypatch.setenv("SYSTEMROOT", "attacker-controlled-relative")
    monkeypatch.delenv("WINDIR", raising=False)
    kernel32 = type("Kernel32", (), {"GetSystemDirectoryW": Function()})()
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_system_dll",
        lambda _name: kernel32,
    )

    result = _windows_taskkill_path()

    assert result is not None
    assert str(result).replace("/", "\\").casefold() == (
        "c:\\windows\\system32\\taskkill.exe"
    )
    assert "attacker-controlled" not in str(result)


def test_windows_taskkill_path_ignores_absolute_environment_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Function:
        argtypes: Any = None
        restype: Any = None

        @staticmethod
        def __call__(buffer: Any, _size: int) -> int:
            buffer.value = r"C:\Windows\System32"
            return len(buffer.value)

    monkeypatch.setenv("SYSTEMROOT", "D:\\attacker\\controlled")
    monkeypatch.setenv("WINDIR", "D:\\attacker\\controlled")
    kernel32 = type("Kernel32", (), {"GetSystemDirectoryW": Function()})()
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_system_dll",
        lambda _name: kernel32,
    )

    result = _windows_taskkill_path()

    assert result is not None
    assert str(result).replace("/", "\\").casefold() == (
        "c:\\windows\\system32\\taskkill.exe"
    )
    assert "attacker" not in str(result).casefold()


def test_windows_taskkill_path_uses_typed_system_directory_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Function:
        argtypes: Any = None
        restype: Any = None

        @staticmethod
        def __call__(buffer: Any, size: int) -> int:
            assert size == 32768
            buffer.value = r"C:\Windows\System32"
            return len(buffer.value)

    function = Function()
    kernel32 = type("Kernel32", (), {"GetSystemDirectoryW": function})()
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_system_dll", lambda _name: kernel32
    )

    result = _windows_taskkill_path()

    assert result is not None
    assert str(result).replace("/", "\\").casefold() == (
        "c:\\windows\\system32\\taskkill.exe"
    )
    assert function.argtypes == (ctypes.POINTER(ctypes.c_wchar), ctypes.c_uint32)
    assert function.restype is ctypes.c_uint32


def test_windows_missing_taskkill_path_skips_helper_and_kills_owned_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[Any] = []

    class WindowsProcess:
        pid = 6161

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

    monkeypatch.setattr("xhs_insight.browser_login.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_system_dll",
        lambda _name: (_ for _ in ()).throw(RuntimeError("system API unavailable")),
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("untrusted taskkill must not execute"),
    )

    assert _windows_taskkill_path() is None
    _terminate_browser_process(WindowsProcess())  # type: ignore[arg-type]

    assert events == ["kill", ("wait", 3)]


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
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    (profile.path / "Cookies").write_bytes(b"private-cookie-material")

    assert _remove_profile(profile) is True

    assert not profile.path.exists()
    assert _remove_profile_root(root) is True
    assert COOKIE_SOURCE_URL.endswith("/api/sns/web/v2/user/me")


def test_profile_cleanup_does_not_reapply_marker_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    (profile.path / "Cookies").write_bytes(b"private-cookie-material")

    def unexpected_acl_update(_path: str | Path) -> None:
        raise AssertionError("cleanup must not rerun the Windows ACL helper")

    monkeypatch.setattr(
        "xhs_insight.security.secure_private_file", unexpected_acl_update
    )

    assert _remove_profile(profile) is True
    assert _remove_profile_root(root) is True


def test_profile_root_uses_system_temp_not_state_dir_and_preserves_host_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "persistent-state"
    system_temp = tmp_path / "system-temp"
    state_dir.mkdir()
    system_temp.mkdir()
    monkeypatch.setenv("CODEBUDDY_SAFE_DELETE", "leave-host-setting-alone")
    monkeypatch.setattr(
        "xhs_insight.browser_login.tempfile.gettempdir", lambda: str(system_temp)
    )
    manager = IsolatedBrowserLoginManager(
        state_dir,
        lambda *_args: {},
        lambda: False,
    )

    root = manager._ensure_profile_root()

    assert root.path.parent == system_temp
    assert root.path.parent != state_dir
    assert os.environ["CODEBUDDY_SAFE_DELETE"] == "leave-host-setting-alone"
    manager.close()
    assert manager._profile_root is None
    assert not root.path.exists()


def test_windows_trusted_temp_uses_known_folder_not_temp_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_local = tmp_path / "trusted-local-app-data"
    trusted_temp = trusted_local / "Temp"
    trusted_temp.mkdir(parents=True)
    attacker = tmp_path / "attacker-temp"
    attacker.mkdir()
    validated: list[tuple[Path, str]] = []
    monkeypatch.setenv("TEMP", str(attacker))
    monkeypatch.setenv("TMP", str(attacker))
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_known_folder_path",
        lambda _folder_id: trusted_local,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_current_user_sid",
        lambda: "S-1-5-21-100-200-300-400",
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_temp_parent",
        lambda path, sid: validated.append((path, sid)),
    )

    result = _windows_trusted_temp_parent()

    assert result == trusted_temp
    assert result != attacker
    assert validated == [(trusted_temp, "S-1-5-21-100-200-300-400")]


def test_windows_profile_root_never_calls_tempfile_selector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_temp = tmp_path / "trusted-temp"
    trusted_temp.mkdir()
    sentinel = object()
    observed: list[Path] = []
    monkeypatch.setattr("xhs_insight.browser_login._windows_runtime", lambda: True)
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_trusted_temp_parent",
        lambda: trusted_temp,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login.tempfile.gettempdir",
        lambda: pytest.fail("Windows must not consult tempfile.gettempdir"),
    )

    def create_at(parent: Path) -> object:
        observed.append(parent)
        return sentinel

    monkeypatch.setattr(
        "xhs_insight.browser_login._create_owned_profile_root_at", create_at
    )

    assert _create_owned_profile_root() is sentinel
    assert observed == [trusted_temp]


def test_windows_private_dacl_verification_is_exact_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = "S-1-5-21-100-200-300-400"
    expected = _windows_private_directory_sddl(sid)
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_canonical_sddl",
        lambda value, _information: value,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_read_security_sddl",
        lambda _path, _information: expected,
    )

    _windows_validate_private_directory_dacl(tmp_path, sid)

    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_read_security_sddl",
        lambda _path, _information: (
            expected + "(A;OICI;FA;;;S-1-5-18)"
        ),
    )
    with pytest.raises(RuntimeError, match="DACL 不安全"):
        _windows_validate_private_directory_dacl(tmp_path, sid)

    file_expected = f"O:{sid}D:P(A;;FA;;;{sid})"
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_read_security_sddl",
        lambda _path, _information: file_expected,
    )
    _windows_validate_private_file_dacl(tmp_path, sid)
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_read_security_sddl",
        lambda _path, _information: file_expected + "(A;;FR;;;S-1-1-0)",
    )
    with pytest.raises(RuntimeError, match="标记 DACL 不安全"):
        _windows_validate_private_file_dacl(tmp_path, sid)


def test_windows_marker_dispatch_never_uses_environment_icacls_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / ".owner"
    sentinel = tmp_path.lstat()
    calls: list[tuple[Path, bytes, str]] = []

    def windows_writer(path: Path, payload: bytes, sid: str) -> os.stat_result:
        calls.append((path, payload, sid))
        return sentinel

    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_write_private_marker", windows_writer
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login.write_private_file",
        lambda *_args: pytest.fail("Windows marker must not call icacls-backed writer"),
    )

    result = _write_owned_marker(
        marker,
        b"owned-marker",
        "S-1-5-21-100-200-300-400",
    )

    assert result is sentinel
    assert calls == [
        (marker, b"owned-marker", "S-1-5-21-100-200-300-400")
    ]


def test_windows_root_dacl_failure_removes_exact_new_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = "S-1-5-21-100-200-300-400"
    created: list[Path] = []
    monkeypatch.setattr("xhs_insight.browser_login._windows_runtime", lambda: True)
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_current_user_sid", lambda: sid
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_temp_parent",
        lambda path, _sid: path.lstat(),
    )

    def create_private(parent: Path, prefix: str, _owner_sid: str) -> Path:
        path = parent / f"{prefix}{'c' * 32}"
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        created.append(path)
        return path

    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_create_private_directory",
        create_private,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_private_directory_dacl",
        lambda _path, _sid: (_ for _ in ()).throw(
            RuntimeError("synthetic root DACL failure")
        ),
    )

    with pytest.raises(RuntimeError, match="synthetic root DACL failure"):
        _create_owned_profile_root_at(tmp_path)

    assert len(created) == 1
    assert not created[0].exists()


def test_windows_root_and_each_profile_apply_and_revalidate_private_dacl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = "S-1-5-21-100-200-300-400"
    created: list[tuple[Path, str, str]] = []
    validated: list[Path] = []
    monkeypatch.setattr("xhs_insight.browser_login._windows_runtime", lambda: True)
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_current_user_sid", lambda: sid
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_temp_parent",
        lambda path, _sid: path.lstat(),
    )

    def create_private(parent: Path, prefix: str, owner_sid: str) -> Path:
        path = parent / f"{prefix}{'a' * 32}"
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        created.append((parent, prefix, owner_sid))
        return path

    def write_marker(path: Path, payload: bytes, _owner_sid: str) -> os.stat_result:
        path.write_bytes(payload)
        path.chmod(0o600)
        return path.lstat()

    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_create_private_directory",
        create_private,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_private_directory_dacl",
        lambda path, _sid: validated.append(path),
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_private_file_dacl",
        lambda _path, _sid: None,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_write_private_marker", write_marker
    )

    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)

    assert root.windows_owner_sid == sid
    assert created == [
        (tmp_path, "crimsonflux-browser-login-", sid),
        (root.path, "profile-", sid),
    ]
    assert root.path in validated
    assert profile.path in validated
    assert validated.count(root.path) >= 2
    assert validated.count(profile.path) >= 2
    assert _remove_profile_root(root) is True


def test_windows_profile_dacl_failure_leaves_no_registered_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = "S-1-5-21-100-200-300-400"
    fail_profiles = {"enabled": False}
    monkeypatch.setattr("xhs_insight.browser_login._windows_runtime", lambda: True)
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_current_user_sid", lambda: sid
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_temp_parent",
        lambda path, _sid: path.lstat(),
    )

    def create_private(parent: Path, prefix: str, _owner_sid: str) -> Path:
        path = parent / f"{prefix}{'b' * 32}"
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        return path

    def verify(path: Path, _owner_sid: str) -> None:
        if fail_profiles["enabled"] and path.name.startswith("profile-"):
            raise RuntimeError("synthetic unsafe DACL")

    def write_marker(path: Path, payload: bytes, _owner_sid: str) -> os.stat_result:
        path.write_bytes(payload)
        path.chmod(0o600)
        return path.lstat()

    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_create_private_directory",
        create_private,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_private_directory_dacl",
        verify,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_validate_private_file_dacl",
        lambda _path, _sid: None,
    )
    monkeypatch.setattr(
        "xhs_insight.browser_login._windows_write_private_marker", write_marker
    )
    root = _create_owned_profile_root_at(tmp_path)
    fail_profiles["enabled"] = True

    with pytest.raises(RuntimeError, match="synthetic unsafe DACL"):
        _create_owned_profile(root)

    assert root.profiles == {}
    assert not any(item.name.startswith("profile-") for item in root.path.iterdir())
    fail_profiles["enabled"] = False
    assert _remove_profile_root(root) is True


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows security APIs")
def test_real_windows_root_and_profile_have_exact_current_user_dacl(
    tmp_path: Path,
) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    assert root.windows_owner_sid

    _windows_validate_private_directory_dacl(root.path, root.windows_owner_sid)
    _windows_validate_private_directory_dacl(profile.path, root.windows_owner_sid)
    _windows_validate_private_file_dacl(
        root.path / ".crimsonflux-owner", root.windows_owner_sid
    )
    _windows_validate_private_file_dacl(
        profile.marker_path, root.windows_owner_sid
    )

    assert _remove_profile_root(root) is True


def test_owned_root_and_profile_have_direct_parent_markers(tmp_path: Path) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)

    assert root.path.parent == Path(os.path.abspath(tmp_path))
    assert root.path.name.startswith("crimsonflux-browser-login-")
    assert (root.path / ".crimsonflux-owner").is_file()
    assert root.nonce in (root.path / ".crimsonflux-owner").read_text("ascii")
    assert profile.path.parent == root.path
    assert profile.path.name.startswith("profile-")
    assert profile.marker_path.parent == root.path
    assert profile.marker_path.name == f".{profile.path.name}.owner"
    marker = profile.marker_path.read_text("ascii")
    assert root.nonce in marker
    assert profile.nonce in marker
    assert root.profiles[profile.path.name] is profile

    assert _remove_profile_root(root) is True
    assert not root.path.exists()


@pytest.mark.parametrize("shim_behavior", ["raise", "no_op"])
def test_safe_delete_shim_blocks_session_cleanup_and_retains_profile_for_retry(
    shim_behavior: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    (profile.path / "Cookies").write_bytes(b"private-cookie-material")
    original_rmtree = shutil.rmtree

    def intercepted(_path: Path) -> None:
        if shim_behavior == "raise":
            raise PermissionError("synthetic WorkBuddy safe-delete block")

    monkeypatch.setattr("xhs_insight.browser_login.shutil.rmtree", intercepted)
    monkeypatch.setattr("xhs_insight.browser_login.time.sleep", lambda _delay: None)
    session = object.__new__(_IsolatedBrowserSession)
    session._profile = profile
    session._process = None
    session._connection = None
    session._session_id = None
    session._close_lock = threading.RLock()

    with pytest.raises(BrowserLoginError) as captured:
        session.close()

    assert captured.value.code == "BROWSER_PROFILE_CLEANUP_FAILED"
    assert session._profile is profile
    assert profile.path.exists()
    assert root.profiles[profile.path.name] is profile

    monkeypatch.setattr("xhs_insight.browser_login.shutil.rmtree", original_rmtree)
    session.close()
    assert session._profile is None
    assert not profile.path.exists()
    assert _remove_profile_root(root) is True


@pytest.mark.parametrize("invalid_location", ["outside", "wrong_prefix"])
def test_profile_cleanup_rejects_unowned_location_without_recursive_delete(
    invalid_location: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    owned_path = profile.path
    if invalid_location == "outside":
        outside = tmp_path / "outside" / owned_path.name
        outside.mkdir(parents=True)
        profile.path = outside
    else:
        profile.path = root.path / "not-an-owned-profile"
    recursive_calls: list[Path] = []
    monkeypatch.setattr(
        "xhs_insight.browser_login.shutil.rmtree",
        lambda path: recursive_calls.append(Path(path)),
    )
    monkeypatch.setattr("xhs_insight.browser_login.time.sleep", lambda _delay: None)

    assert _remove_profile(profile) is False
    assert recursive_calls == []

    profile.path = owned_path


def test_profile_cleanup_rejects_symlink_without_recursive_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    target = tmp_path / "must-not-delete"
    target.mkdir()
    shutil.rmtree(profile.path)
    try:
        profile.path.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    recursive_calls: list[Path] = []
    monkeypatch.setattr(
        "xhs_insight.browser_login.shutil.rmtree",
        lambda path: recursive_calls.append(Path(path)),
    )
    monkeypatch.setattr("xhs_insight.browser_login.time.sleep", lambda _delay: None)

    assert _remove_profile(profile) is False
    assert recursive_calls == []
    assert target.is_dir()


def test_manager_close_removes_empty_owned_profile_root(tmp_path: Path) -> None:
    manager = _manager(tmp_path, lambda *_args: {}, _FakeBrowser([None]))
    root = manager._profile_root
    assert root is not None
    assert root.path.exists()

    manager.close()

    assert manager._profile_root is None
    assert not root.path.exists()


def test_profile_cleanup_reports_a_locked_residual(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    monkeypatch.setattr("xhs_insight.browser_login.shutil.rmtree", lambda _path: None)
    monkeypatch.setattr("xhs_insight.browser_login.time.sleep", lambda _seconds: None)

    assert _remove_profile(profile) is False
    assert profile.path.exists()
    assert root.profiles[profile.path.name] is profile


def test_windows_profile_cleanup_uses_bounded_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _create_owned_profile_root_at(tmp_path)
    profile = _create_owned_profile(root)
    delays: list[float] = []
    monkeypatch.setattr("xhs_insight.browser_login.platform.system", lambda: "Windows")
    monkeypatch.setattr("xhs_insight.browser_login.shutil.rmtree", lambda _path: None)
    monkeypatch.setattr("xhs_insight.browser_login.time.sleep", delays.append)

    assert _remove_profile(profile) is False

    assert delays == [0.1, 0.2, 0.4, 0.8, 1.0, 1.5, 2.0, 2.0, 2.0, 2.0]
    assert sum(delays) == pytest.approx(12.0)
