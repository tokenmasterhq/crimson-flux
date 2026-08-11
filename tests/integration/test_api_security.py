from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from xhs_insight.adapters import AdapterError
from xhs_insight.api import Backend, create_app
from xhs_insight.browser_login import BrowserLoginError
from xhs_insight.config import Settings
from xhs_insight.domain import AdapterErrorCode, DetailResult, PageResult
from xhs_insight.exporting import Exporter
from xhs_insight.jobs import JobService
from xhs_insight.security import CredentialCipher
from xhs_insight.storage import Repository


class SyntheticAuth:
    authenticated = True
    account_fingerprint: str | None = "synthetic-account"

    def status(self) -> dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "account_fingerprint": self.account_fingerprint,
            "connected_at": None,
            "credential_error": None,
        }

    def logout(self) -> None:
        self.authenticated = False


class SyntheticAdapter:
    """Test-only upstream double; it is never selectable by product code."""

    version = "synthetic-test-v1"
    keyword_page_size = 20

    def keyword_page(self, keyword: str, cursor: dict[str, Any]) -> PageResult:
        if int(cursor.get("page") or 1) > 1:
            return PageResult(items=[], next_cursor=None, has_more=False)
        return PageResult(
            items=[
                {"note_id": "n1", "source_page": 1, "title": f"{keyword} 1"},
                {"note_id": "n2", "source_page": 1, "title": f"{keyword} 2"},
            ],
            next_cursor=None,
            has_more=False,
            raw_item_count=2,
        )

    def user_page(self, _profile_url: str, _cursor: dict[str, Any]) -> PageResult:
        return PageResult(
            items=[
                {"note_id": "u1", "source_page": 1, "title": "user 1"},
                {"note_id": "u2", "source_page": 1, "title": "user 2"},
            ],
            next_cursor=None,
            has_more=False,
            raw_item_count=2,
        )

    def note_detail(
        self, note_id: str, _private: dict[str, Any] | None
    ) -> DetailResult:
        return DetailResult(note_id=note_id, fields={"description": f"detail {note_id}"})

    def close(self) -> None:
        return None


class SyntheticBrowserLogin:
    qr_png = b"\x89PNG\r\n\x1a\nsynthetic-integration-qr"

    def __init__(self) -> None:
        self.current = {
            "browser_login_supported": True,
            "status": "idle",
            "message": "尚未启动扫码登录。",
        }

    def capability(self) -> dict[str, Any]:
        return {
            "browser_login_supported": True,
            "browser_login_mode": "official_embedded_qr",
            "browser_login_embedded_qr": True,
            "browser_name": "Synthetic Browser",
            "browser_major_version": 151,
            "browser_login_timeout_seconds": 180,
            "browser_login_reason": None,
        }

    def start(self) -> dict[str, Any]:
        self.current = {
            **self.capability(),
            "status": "awaiting_scan",
            "message": "请扫描页面二维码。",
            "qr_ready": True,
            "qr_revision": "syntheticrevision",
            "qr_url": "/api/v1/auth/browser/qr",
        }
        return dict(self.current)

    def status(self) -> dict[str, Any]:
        return dict(self.current)

    def cancel(self) -> dict[str, Any]:
        self.current = {
            **self.capability(),
            "status": "cancelled",
            "message": "已取消扫码登录。",
        }
        return dict(self.current)

    def qr_image(self) -> tuple[bytes, str]:
        if self.current.get("status") != "awaiting_scan":
            raise BrowserLoginError(
                "QR_NOT_READY", "二维码尚未生成、已过期或登录已结束，请重新开始。"
            )
        return self.qr_png, "syntheticrevision"

    def close(self) -> None:
        return None


class SyntheticBackend(Backend):
    def collector_doctor(self) -> dict[str, Any]:
        return {
            "mode": "live",
            "collection_runtime_ok": True,
            "cookie_import_supported": True,
            "browser_login_supported": True,
            "browser_login_mode": "official_embedded_qr",
            "browser_login_embedded_qr": True,
            "browser_name": "Synthetic Browser",
            "browser_major_version": 151,
            "browser_login_timeout_seconds": 180,
            "issues": [],
        }

    def import_cookie(self, cookie: str) -> dict[str, Any]:
        assert cookie.startswith("a1=")
        return {
            "authenticated": True,
            "account_fingerprint": "safe-fingerprint",
            "connected_at": None,
            "credential_error": None,
        }


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        host="127.0.0.1",
        port=8765,
        state_dir=tmp_path / "state",
        export_dir=tmp_path / "exports",
        max_keyword_items=1000,
        max_user_items=10_000,
        pause_min_seconds=0,
        pause_max_seconds=0,
        open_browser=False,
    )


def _app(settings: Settings):
    settings.prepare()
    repository = Repository(settings.state_dir / "xhs-insight.sqlite3")
    cipher = CredentialCipher(settings.state_dir / "master.key")
    auth = SyntheticAuth()
    adapter = SyntheticAdapter()
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
    backend = SyntheticBackend(
        settings=settings,
        repository=repository,
        cipher=cipher,
        auth=auth,
        adapter=adapter,
        exporter=exporter,
        jobs=jobs,
        browser_login=SyntheticBrowserLogin(),
    )
    return create_app(settings, backend=backend)


def _wait(
    client: TestClient,
    job_id: str,
    statuses: set[str],
    *,
    headers: dict[str, str] | None = None,
) -> dict:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert response.status_code == 200
        job = response.json()
        if job["status"] in statuses:
            return job
        time.sleep(0.02)
    raise AssertionError("job did not reach expected status")


@pytest.mark.parametrize(
    ("runtime_ok", "cookie_import_ok"),
    [(False, True), (True, False), (False, False)],
)
def test_health_is_degraded_when_live_runtime_is_not_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_ok: bool,
    cookie_import_ok: bool,
) -> None:
    monkeypatch.setattr(
        SyntheticBackend,
        "collector_doctor",
        lambda _self: {
            "mode": "live",
            "collection_runtime_ok": runtime_ok,
            "cookie_import_supported": cookie_import_ok,
            "issues": ["synthetic readiness failure"],
        },
    )
    app = _app(_settings(tmp_path))
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["collector"]["mode"] == "live"


def test_cookie_import_never_reflects_secret_and_rejects_control_characters(
    tmp_path: Path,
) -> None:
    app = _app(_settings(tmp_path))
    secret = "a1=private-a1-value; web_session=private-session-value"
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        headers = {"X-XHS-Local-Token": app.state.local_token}
        imported = client.post(
            "/api/v1/auth/import",
            headers=headers,
            json={"cookie": secret},
        )
        rejected = client.post(
            "/api/v1/auth/import",
            headers=headers,
            json={"cookie": f"{secret}\r\nInjected: yes"},
        )

    assert imported.status_code == 200
    assert imported.json()["authenticated"] is True
    assert secret not in imported.text
    assert rejected.status_code == 422
    assert secret not in rejected.text


def test_rejected_cookie_returns_401_without_secret_reflection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(_self: SyntheticBackend, _cookie: str) -> dict[str, Any]:
        raise AdapterError(AdapterErrorCode.AUTH_EXPIRED, detail="private-cookie-material")

    monkeypatch.setattr(SyntheticBackend, "import_cookie", reject)
    app = _app(_settings(tmp_path))
    secret = "a1=private-a1-value; web_session=private-session-value"
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/api/v1/auth/import",
            headers={"X-XHS-Local-Token": app.state.local_token},
            json={"cookie": secret},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == AdapterErrorCode.AUTH_EXPIRED.value
    assert secret not in response.text
    assert "private-cookie-material" not in response.text


def test_web_session_csrf_cli_token_and_host_boundary(tmp_path: Path) -> None:
    app = _app(_settings(tmp_path))
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in health.headers["content-security-policy"]

        fresh = TestClient(app, base_url="http://127.0.0.1:8765")
        assert fresh.get("/api/v1/auth/status").status_code == 401
        assert fresh.get("/api/v1/auth/browser/qr").status_code == 401
        assert fresh.get("/api/v1/health", headers={"Host": "attacker.invalid"}).status_code == 400

        page = client.get("/")
        assert page.status_code == 200
        assert "img-src 'self' data: blob:" in page.headers[
            "content-security-policy"
        ]
        csrf = client.cookies.get("xhs_csrf")
        assert csrf
        assert client.cookies.get("xhs_session")
        assert client.get(
            "/api/v1/auth/browser/qr", headers={"Host": "attacker.invalid"}
        ).status_code == 400
        assert client.get(
            "/api/v1/auth/browser/qr", headers={"Origin": "http://attacker.invalid"}
        ).status_code == 403

        assert client.post("/api/v1/auth/browser").status_code == 403
        browser_login = client.post(
            "/api/v1/auth/browser", headers={"X-XHS-CSRF": csrf}
        )
        assert browser_login.status_code == 202
        assert browser_login.json()["status"] == "awaiting_scan"
        assert "cookie" not in browser_login.text.casefold()
        assert client.get("/api/v1/auth/browser/status").status_code == 200
        qr = client.get("/api/v1/auth/browser/qr")
        assert qr.status_code == 200
        assert qr.content == SyntheticBrowserLogin.qr_png
        assert qr.headers["content-type"] == "image/png"
        assert qr.headers["cache-control"] == (
            "private, no-store, max-age=0, must-revalidate"
        )
        assert qr.headers["pragma"] == "no-cache"
        assert qr.headers["x-content-type-options"] == "nosniff"
        assert qr.headers["etag"] == '"qr-syntheticrevision"'
        assert not any(
            marker in qr.content.lower()
            for marker in (b"cookie", b"devtools", b"profile", b"web_session")
        )
        cancelled_login = client.delete(
            "/api/v1/auth/browser", headers={"X-XHS-CSRF": csrf}
        )
        assert cancelled_login.status_code == 200
        assert cancelled_login.json()["status"] == "cancelled"
        unavailable_qr = client.get("/api/v1/auth/browser/qr")
        assert unavailable_qr.status_code == 409
        assert unavailable_qr.json()["detail"]["code"] == "QR_NOT_READY"
        assert not any(
            marker in unavailable_qr.text.casefold()
            for marker in ("cookie", "devtools", "profile", "web_session")
        )

        payload = {
            "source": {"type": "keyword", "keyword": "露营", "limit": 2},
            "content": {"preset": "basic", "fields": []},
        }
        assert client.post("/api/v1/jobs", json=payload).status_code == 403

        # Pydantic normally includes the rejected input in validation details.
        # The local API deliberately emits messages only so access tokens in a
        # pasted profile URL cannot be reflected into logs or browser tooling.
        reflected_secret = "must-not-be-reflected"
        invalid_profile = client.post(
            "/api/v1/jobs",
            headers={"X-XHS-CSRF": csrf},
            json={
                "source": {
                    "type": "user",
                    "profile_url": (
                        "https://www.xiaohongshu.com/not-a-profile/demo"
                        f"?xsec_token={reflected_secret}"
                    ),
                    "all": True,
                },
                "content": {"preset": "basic", "fields": []},
            },
        )
        assert invalid_profile.status_code == 422
        assert reflected_secret not in invalid_profile.text

        created = client.post(
            "/api/v1/jobs",
            json=payload,
            headers={"X-XHS-CSRF": csrf},
        )
        assert created.status_code == 202
        job_id = created.json()["id"]
        done = _wait(client, job_id, {"completed", "completed_with_warnings"})
        assert done["unique_notes"] == 2
        assert done["artifacts"] == {"csv": True, "jsonl": True, "manifest": True}

        token = app.state.local_token
        cli_headers = {"X-XHS-Local-Token": token}
        assert fresh.get("/api/v1/jobs", headers=cli_headers).status_code == 200
        assert (
            fresh.post(
                "/api/v1/jobs",
                headers={**cli_headers, "Origin": "https://attacker.invalid"},
                json=payload,
            ).status_code
            == 403
        )


def test_cancel_while_waiting_for_detail_confirmation_exports_partial(tmp_path: Path) -> None:
    app = _app(_settings(tmp_path))
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        token = app.state.local_token
        headers = {"X-XHS-Local-Token": token}
        created = client.post(
            "/api/v1/jobs",
            headers=headers,
            json={
                "source": {
                    "type": "user",
                    "profile_url": "https://www.xiaohongshu.com/user/profile/demo-user",
                    "all": True,
                },
                "content": {"preset": "full", "fields": []},
            },
        )
        assert created.status_code == 202
        job_id = created.json()["id"]
        waiting = _wait(
            client,
            job_id,
            {"awaiting_detail_confirmation"},
            headers=headers,
        )
        assert waiting["unique_notes"] == 2

        cancelled = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=headers)
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        assert cancelled.json()["artifacts"] == {
            "csv": True,
            "jsonl": True,
            "manifest": True,
        }


def test_clear_data_removes_jobs_exports_and_rotates_master_key(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    app = _app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        headers = {"X-XHS-Local-Token": app.state.local_token}
        created = client.post(
            "/api/v1/jobs",
            headers=headers,
            json={
                "source": {"type": "keyword", "keyword": "露营", "limit": 1},
                "content": {"preset": "basic", "fields": []},
            },
        )
        assert created.status_code == 202
        job_id = created.json()["id"]
        _wait(
            client,
            job_id,
            {"completed", "completed_with_warnings"},
            headers=headers,
        )
        key_path = settings.state_dir / "master.key"
        old_key = key_path.read_bytes()
        assert (settings.export_dir / job_id / "manifest.json").is_file()

        cleared = client.delete("/api/v1/data", headers=headers)
        assert cleared.status_code == 204
        assert client.get("/api/v1/jobs", headers=headers).json() == {"items": []}
        assert not (settings.export_dir / job_id).exists()
        assert key_path.read_bytes() != old_key
