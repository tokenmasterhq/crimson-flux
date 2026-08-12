from __future__ import annotations

import importlib
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from typer.testing import CliRunner

cli_app = importlib.import_module("xhs_insight.cli.app")
cli_client = importlib.import_module("xhs_insight.cli.client")

runner = CliRunner()


def _health(*, keyword: int = 1000) -> dict[str, Any]:
    return {
        "status": "ok",
        "collector": {
            "mode": "live",
            "collection_runtime_ok": True,
            "cookie_import_supported": True,
            "browser_login_supported": True,
            "browser_login_mode": "official_isolated_browser",
            "browser_name": "Google Chrome",
            "browser_major_version": 151,
            "browser_login_timeout_seconds": 180,
        },
        "limits": {
            "keyword": keyword,
            "user": 10_000,
            "pause_min_seconds": 7,
            "pause_max_seconds": 9,
        },
    }


def _public_job(
    *,
    job_id: str = "job-1",
    source: dict[str, Any] | None = None,
    content: dict[str, Any] | None = None,
    status: str = "queued",
    adapter_version: str = "synthetic-test-v1",
) -> dict[str, Any]:
    return {
        "id": job_id,
        "status": status,
        "source_type": (source or {}).get("type", "keyword"),
        "source": source or {"type": "keyword", "keyword": "露营", "limit": 2},
        "content": content or {"preset": "basic", "fields": ["author"]},
        "unique_notes": 0,
        "detail_succeeded": 0,
        "detail_failed": 0,
        "adapter_version": adapter_version,
    }


class FakeClient:
    def __init__(self, *, health: dict[str, Any] | None = None) -> None:
        self.health = health or _health()
        self.posts: list[tuple[str, Any]] = []
        self.config = SimpleNamespace(api_url="http://127.0.0.1:8765/api/v1")

    def __enter__(self) -> FakeClient:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, path: str) -> Any:
        if path == "/health":
            return self.health
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path: str, body: Any = None) -> Any:
        self.posts.append((path, body))
        if path == "/jobs":
            source = dict(body["source"])
            source["profile_url"] = str(source.get("profile_url", "")).split("?", 1)[0]
            return _public_job(source=source, content=body["content"])
        raise AssertionError(f"unexpected POST {path}")


def test_http_client_disables_environment_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class StubHttpxClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(cli_client.httpx, "Client", StubHttpxClient)
    config = cli_client.ClientConfig(
        api_url="http://127.0.0.1:8765/api/v1",
        local_token="local-only",
        instance_path=Path("instance.json"),
    )
    cli_client.ApiClient(config)

    assert captured["trust_env"] is False


def test_instance_file_is_rejected_before_reading_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "actual.json"
    target.write_text('{"local_token":"must-not-be-read"}', encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "instance.json"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    read_called = False

    def forbidden_read(_path: Path, _expected: os.stat_result | None) -> dict[str, Any]:
        nonlocal read_called
        read_called = True
        raise AssertionError("unsafe path was read")

    monkeypatch.setattr(cli_client, "instance_file", lambda: link)
    monkeypatch.setattr(cli_client, "_read_instance", forbidden_read)

    with pytest.raises(cli_client.ClientConfigurationError, match="符号链接"):
        cli_client.ClientConfig.load(require_token=False)
    assert read_called is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode-bit regression")
def test_instance_permissions_are_checked_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "instance.json"
    path.write_text('{"local_token":"must-not-be-read"}', encoding="utf-8")
    path.chmod(0o644)
    read_called = False

    def forbidden_read(_path: Path, _expected: os.stat_result | None) -> dict[str, Any]:
        nonlocal read_called
        read_called = True
        raise AssertionError("unsafe path was read")

    monkeypatch.setattr(cli_client, "instance_file", lambda: path)
    monkeypatch.setattr(cli_client, "_read_instance", forbidden_read)

    with pytest.raises(cli_client.ClientConfigurationError, match="权限不安全"):
        cli_client.ClientConfig.load(require_token=False)
    assert read_called is False


def test_instance_replacement_between_validation_and_open_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "instance.json"
    path.write_text(
        '{"api_url":"http://127.0.0.1:8765/api/v1","local_token":"original"}',
        encoding="utf-8",
    )
    path.chmod(0o600)
    expected = cli_client._validate_instance_file(path)
    assert expected is not None

    replacement = tmp_path / "replacement.json"
    replacement.write_text(
        '{"api_url":"http://127.0.0.1:9999/api/v1","local_token":"replacement"}',
        encoding="utf-8",
    )
    replacement.chmod(0o600)
    os.replace(replacement, path)

    with pytest.raises(cli_client.ClientConfigurationError, match="读取期间已被替换"):
        cli_client._read_instance(path, expected)


@pytest.mark.parametrize("query_name", ["xsec_token", "sign_v2", "access_token"])
def test_collect_user_rejects_sensitive_query_in_argv_without_echoing_value(
    query_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "should-never-appear"

    def forbidden_client(**_kwargs: Any) -> FakeClient:
        raise AssertionError("the API must not be called")

    monkeypatch.setattr(cli_app, "_client", forbidden_client)
    result = runner.invoke(
        cli_app.app,
        [
            "collect",
            "user",
            "--url",
            f"https://www.xiaohongshu.com/user/profile/demo?{query_name}={secret}",
            "--all",
            "--yes",
        ],
    )

    assert result.exit_code != 0
    assert "隐藏输入" in result.output
    assert secret not in result.output


def test_collect_user_hidden_input_passes_access_only_in_loopback_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeClient()
    monkeypatch.setattr(cli_app, "_client", lambda **_kwargs: fake)
    secret = "private-access-value"
    profile_url = (
        "https://www.xiaohongshu.com/user/profile/demo-user"
        f"?xsec_token={secret}&xsec_source=pc_search"
    )

    result = runner.invoke(
        cli_app.app,
        ["collect", "user", "--all", "--yes"],
        input=f"{profile_url}\n",
    )

    assert result.exit_code == 0, result.output
    assert fake.posts[0][0] == "/jobs"
    submitted_url = fake.posts[0][1]["source"]["profile_url"]
    submitted_query = parse_qs(urlsplit(submitted_url).query)
    assert submitted_query == {"xsec_token": [secret], "xsec_source": ["pc_search"]}
    assert secret not in result.output
    assert "xsec_token" not in result.output
    assert profile_url not in result.output


def test_login_reads_cookie_from_stdin_without_echoing_or_argv_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "a1=private-cookie; web_session=private-session"
    observed: dict[str, Any] = {}

    class LoginClient(FakeClient):
        def __init__(self) -> None:
            super().__init__(health=_health())

        def post(self, path: str, body: Any = None) -> Any:
            assert path == "/auth/import"
            observed["body"] = body
            return {"authenticated": True, "account_fingerprint": "safe-fingerprint"}

    monkeypatch.setattr(cli_app, "_client", lambda **_kwargs: LoginClient())
    result = runner.invoke(cli_app.app, ["login", "--stdin"], input=f"{secret}\n")

    assert result.exit_code == 0, result.output
    assert observed["body"] == {"cookie": secret}
    assert secret not in result.output
    assert "private-cookie" not in result.output
    assert "验证成功" in result.output


def test_login_defaults_to_official_browser_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrowserLoginClient(FakeClient):
        def __init__(self) -> None:
            super().__init__(health=_health())
            self.status_reads = 0

        def post(self, path: str, body: Any = None) -> Any:
            assert path == "/auth/browser"
            assert body == {}
            return {"status": "awaiting_scan", "message": "请扫码"}

        def get(self, path: str) -> Any:
            if path == "/health":
                return self.health
            assert path == "/auth/browser/status"
            self.status_reads += 1
            if self.status_reads == 1:
                return {
                    "status": "awaiting_phone_confirmation",
                    "authenticated": False,
                    "message": (
                        "已扫码，请按手机提示完成确认；"
                        "如要求短信验证，请在手机端完成。"
                    ),
                }
            return {
                "status": "succeeded",
                "authenticated": True,
                "message": "登录成功",
            }

    fake = BrowserLoginClient()
    monkeypatch.setattr(cli_app, "_client", lambda **_kwargs: fake)
    monkeypatch.setattr(cli_app.time, "sleep", lambda _seconds: None)

    result = runner.invoke(cli_app.app, ["login"])

    assert result.exit_code == 0, result.output
    assert fake.status_reads == 2
    assert "登录二维码已生成" in result.output
    assert "http://127.0.0.1:8765" in result.output
    assert "直接扫描页面中的二维码" in result.output
    assert "如要求短信验证，请在手机端完成" in result.output
    assert "官方小红书窗口" not in result.output
    assert "扫码登录成功" in result.output


def test_login_rejects_invalid_cookie_without_calling_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_app,
        "_client",
        lambda **_kwargs: pytest.fail("invalid Cookie must not reach the API"),
    )
    result = runner.invoke(cli_app.app, ["login", "--stdin"], input="a1=one\nsecond-line\n")

    assert result.exit_code != 0
    assert "非法控制字符" in result.output
    assert "second-line" not in result.output


def test_keyword_limit_and_estimate_come_from_health(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient(health=_health(keyword=3))
    monkeypatch.setattr(cli_app, "_client", lambda **_kwargs: fake)

    rejected = runner.invoke(
        cli_app.app,
        ["collect", "keyword", "--keyword", "露营", "--limit", "4", "--yes"],
    )
    assert rejected.exit_code != 0
    assert "最多允许 3 条" in rejected.output
    assert fake.posts == []

    accepted = runner.invoke(
        cli_app.app,
        ["collect", "keyword", "--keyword", "露营", "--limit", "2", "--yes"],
    )
    assert accepted.exit_code == 0, accepted.output
    assert "请求间隔 7–9 秒" in accepted.output
    assert "预计列表请求约 1 次" in accepted.output
    assert "最多详情请求 0 次" in accepted.output
    assert "估算约 7–9 秒" in accepted.output
    assert fake.posts[0][0] == "/jobs"


@pytest.mark.parametrize(
    ("args", "expected_preset", "expected_fields"),
    [
        (["--preset", "basic"], "basic", {"author"}),
        (["--preset", "custom", "--fields", "body,tags"], "custom", {"body", "tags"}),
    ],
)
def test_confirm_details_can_change_content_selection(
    args: list[str],
    expected_preset: str,
    expected_fields: set[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ConfirmClient(FakeClient):
        def get(self, path: str) -> Any:
            if path == "/health":
                return self.health
            assert path == "/jobs/job-1"
            return _public_job(
                source={
                    "type": "user",
                    "profile_url": "https://www.xiaohongshu.com/user/profile/demo-user",
                    "all": True,
                },
                content={
                    "preset": "full",
                    "fields": ["author", "body", "tags", "metrics", "media"],
                },
                status="awaiting_detail_confirmation",
            )

        def post(self, path: str, body: Any = None) -> Any:
            self.posts.append((path, body))
            assert path == "/jobs/job-1/confirm-details"
            return _public_job(content=body["content"])

    fake = ConfirmClient()
    monkeypatch.setattr(cli_app, "_client", lambda **_kwargs: fake)
    result = runner.invoke(
        cli_app.app,
        ["jobs", "confirm-details", "job-1", *args, "--yes"],
    )

    assert result.exit_code == 0, result.output
    content = fake.posts[0][1]["content"]
    assert content["preset"] == expected_preset
    assert set(content["fields"]) == expected_fields


def test_confirm_details_prompt_states_discovered_count_and_request_maximum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ConfirmClient(FakeClient):
        def get(self, path: str) -> Any:
            if path == "/health":
                return self.health
            assert path == "/jobs/job-1"
            job = _public_job(
                source={
                    "type": "user",
                    "profile_url": "https://www.xiaohongshu.com/user/profile/demo-user",
                    "all": True,
                },
                content={
                    "preset": "full",
                    "fields": ["author", "body", "tags", "metrics", "media"],
                },
                status="awaiting_detail_confirmation",
            )
            job["unique_notes"] = 37
            return job

        def post(self, path: str, body: Any = None) -> Any:
            self.posts.append((path, body))
            return _public_job(content=body["content"])

    fake = ConfirmClient()
    monkeypatch.setattr(cli_app, "_client", lambda **_kwargs: fake)
    result = runner.invoke(
        cli_app.app,
        ["jobs", "confirm-details", "job-1"],
        input="y\n",
    )

    assert result.exit_code == 0, result.output
    assert "已发现 37 条笔记" in result.output
    assert "最多详情请求 37 次" in result.output
    assert "按当前 7–9 秒间隔" in result.output
    assert "详情阶段约需 259–333 秒" in result.output
    assert fake.posts[0][0] == "/jobs/job-1/confirm-details"


def test_web_contract_has_no_runtime_demo_mode_and_keeps_export_controls() -> None:
    root = Path(__file__).resolve().parents[2]
    template = (root / "src/xhs_insight/web/templates/index.html").read_text(encoding="utf-8")
    script = (root / "src/xhs_insight/web/static/app.js").read_text(encoding="utf-8")

    assert 'id="fixture-banner"' not in template
    assert "DEMO" not in template
    assert 'id="cookie-input"' in template
    assert 'type="password"' in template
    assert 'autocomplete="new-password"' in template
    assert 'id="browser-login"' in template
    assert "扫码连接平台账号" in template
    assert "打开一个全新的小红书官方浏览器窗口" not in template
    assert 'id="browser-login-qr"' in template
    assert 'alt="平台登录二维码，请使用平台官方 App 扫描"' in template
    assert 'id="browser-login-countdown"' in template
    assert 'aria-live="polite"' in template
    assert "二维码在本页完成，不读取日常浏览器资料" in template
    assert 'id="export-basic"' in template
    assert 'id="profile-url"' in template
    assert 'autocomplete="off" spellcheck="false"' in template
    assert 'api("/health")' in script
    assert 'elements.profileUrl.value = ""' in script
    assert 'elements.exportBasic.addEventListener("click", exportBasic)' in script
    assert '{ preset: "basic", fields: [] }' in script
    assert "预计列表请求约 ${requests.listRequests} 次" in script
    assert "最多发起 ${count} 次详情请求" in script
    assert "fixtureMode" not in script
    assert "离线演示" not in script
    assert "小红书" not in template
    assert "小红书" not in script
    assert "采集" not in template
    assert "采集" not in script
    assert "只按回车" in template
    assert '<span class="hero-product-cn">绯流</span>' in template
    assert '<span class="hero-product-en">CrimsonFlux</span>' in template
    assert "brand-just-enter.svg" in template
    assert 'api("/auth/import"' in script
    assert 'api("/auth/browser"' in script
    assert 'api("/auth/browser/status")' in script
    assert "`${API_BASE}/auth/browser/qr`" in script
    assert 'response.headers.get("x-xhs-qr-revision")' in script
    assert "state.browserQrRevision !== nextQrRevision" in script
    assert 'cache: "no-store"' in script
    assert "/auth/qr" not in script
    assert 'awaiting_phone_confirmation: "等待手机确认"' in script
    assert "已扫码，请按手机提示完成确认；如要求短信验证，请在手机端完成。" in script
    assert 'status === "awaiting_phone_confirmation"' in script
    browser_active_statuses = script[
        script.index("const BROWSER_LOGIN_ACTIVE") : script.index(
            "const BROWSER_LOGIN_LABELS"
        )
    ]
    assert '"awaiting_phone_confirmation"' in browser_active_statuses
    assert "browser-verification" not in template
    assert "/auth/browser/verification" not in script


def test_web_platform_challenge_recommends_cookie_fallback_without_retry_loop() -> None:
    root = Path(__file__).resolve().parents[2]
    template = (root / "src/xhs_insight/web/templates/index.html").read_text(
        encoding="utf-8"
    )
    script = (root / "src/xhs_insight/web/static/app.js").read_text(
        encoding="utf-8"
    )
    styles = (root / "src/xhs_insight/web/static/styles.css").read_text(
        encoding="utf-8"
    )

    assert 'id="manual-login-recommendation"' in template
    assert 'role="status" aria-live="polite" aria-atomic="true"' in template
    assert "扫码确认已完成，但还需要网页验证" in template
    assert "当前安全模式无法在本页自动完成" in template

    assert 'const PLATFORM_CHALLENGE_REQUIRED = "PLATFORM_CHALLENGE_REQUIRED"' in script
    assert "手机确认已完成，但平台要求额外网页验证" in script
    assert "当前安全模式无法在页内自动完成" in script
    fallback_branch = script[
        script.index("function renderManualLoginFallback") : script.index(
            "function releaseBrowserQrObjectUrl"
        )
    ]
    assert 'classList.toggle("is-recommended", recommended)' in fallback_branch
    assert "elements.manualLoginRecommendation.hidden = !recommended" in fallback_branch
    assert "elements.manualLogin.open = true" in fallback_branch
    assert 'state.manualLoginAutoOpened = true' in fallback_branch
    assert '"仍要尝试扫码"' in script
    assert "重新扫码可能仍会遇到相同验证" in script
    assert "browserLoginDisplayMessage(result" in script
    assert "showToast(result?.message" not in script
    assert "请在官方客户端完成后重新扫码" not in template
    assert "请在官方客户端完成后重新扫码" not in script

    assert ".manual-login-disclosure.is-recommended" in styles
    assert ".manual-login-recommendation" in styles
    assert '.browser-login-visual[data-state="challenge"]' in styles


def test_web_cookie_import_has_safe_five_step_guidance() -> None:
    root = Path(__file__).resolve().parents[2]
    template = (root / "src/xhs_insight/web/templates/index.html").read_text(
        encoding="utf-8"
    )
    script = (root / "src/xhs_insight/web/static/app.js").read_text(
        encoding="utf-8"
    )
    styles = (root / "src/xhs_insight/web/static/styles.css").read_text(
        encoding="utf-8"
    )

    assert '<details class="help-disclosure" open>' in template
    assert "5 步安全导入方法" in template
    guide = template[
        template.index('<ol class="auth-guide-steps">') : template.index(
            "</ol>", template.index('<ol class="auth-guide-steps">')
        )
    ]
    assert guide.count("<li>") == 5
    assert "打开开发者工具" in guide
    assert "<kbd>F12</kbd>" in guide
    assert "<kbd>⌥⌘I</kbd>" in guide
    assert "Network" in guide
    assert "确认录制圆点为红色" in guide
    assert "/api/sns/web/v2/user/me" in guide
    assert "user/me" in guide
    assert "Headers" in guide
    assert "Request Headers" in guide
    assert "Cookie:" in guide
    assert "复制冒号之后的完整值" in guide
    assert "document.cookie" in guide
    assert "Copy as cURL" in guide
    assert "不要复制整块 Request Headers" in guide
    assert "覆盖系统剪贴板" in guide
    assert "小红书" not in guide
    assert "采集" not in guide

    assert template.index('<div class="auth-guide">') < template.index(
        '<form id="login-form"'
    )
    auth_guide = template[
        template.index('<div class="auth-guide">') : template.index(
            '<form id="login-form"'
        )
    ]
    assert 'target="_blank" rel="noopener noreferrer"' in auth_guide
    assert "打开官方网页" in auth_guide
    assert "完成全部验证" in auth_guide
    assert '<details class="troubleshooting-disclosure">' in auth_guide

    assert "navigator.clipboard" not in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    assert "输入框已清空。请复制一段普通文字覆盖系统剪贴板" in script
    assert ".auth-guide-steps" in styles
    assert "min-height: 44px" in styles


def test_web_polish_keeps_polling_stable_accessible_and_cache_safe() -> None:
    root = Path(__file__).resolve().parents[2]
    template = (root / "src/xhs_insight/web/templates/index.html").read_text(
        encoding="utf-8"
    )
    script = (root / "src/xhs_insight/web/static/app.js").read_text(
        encoding="utf-8"
    )
    styles = (root / "src/xhs_insight/web/static/styles.css").read_text(
        encoding="utf-8"
    )
    routes = (root / "src/xhs_insight/web/routes.py").read_text(encoding="utf-8")

    assert 'id="jobs-list" class="jobs-list" aria-live=' not in template
    assert '<div id="toast" class="toast" hidden></div>' in template
    assert 'id="sr-status"' in template
    assert '<legend class="fieldset-heading">' in template
    assert '<div class="fieldset-heading">' not in template
    assert "replaceChildren" not in script
    assert "jobRenderSignatures" in script
    assert "patchJobActions" in script
    assert "transition: all" not in styles
    assert "scale: 0.96" in styles
    assert "font-variant-numeric: tabular-nums" in styles
    assert "@media (prefers-reduced-motion: reduce)" in styles
    assert "width: min(220px, 100%)" in styles
    assert "outline: 1px solid oklch(0 0 0 / 0.1)" in styles
    assert "min-height: 44px" in styles
    assert "asset_version" in template
    assert "ASSET_VERSION = _asset_version()" in routes

    invalid_cookie_branch = script[
        script.index("if (!cookie || cookie.length > 16384") : script.index(
            "elements.importLogin.disabled = true"
        )
    ]
    assert 'cookie = "";' in invalid_cookie_branch
    assert 'elements.cookieInput.value = "";' in invalid_cookie_branch
    assert invalid_cookie_branch.index('elements.cookieInput.value = "";') < (
        invalid_cookie_branch.index("showToast(")
    )
