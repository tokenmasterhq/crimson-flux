from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from xhs_insight.api import create_app
from xhs_insight.config import Settings

_QR_PNG = b"\x89PNG\r\n\x1a\nreviewed-test-only-payload"
_REVISION = "0123456789abcdef"


class _QrManager:
    def qr_image(self) -> tuple[bytes, str]:
        return _QR_PNG, _REVISION


class _Backend:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.browser_login = _QrManager()

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(
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
    settings.prepare()
    return settings


def test_embedded_qr_requires_local_session_and_same_origin(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    app = create_app(settings, backend=_Backend(settings))  # type: ignore[arg-type]

    with TestClient(app, base_url="http://127.0.0.1:8765") as anonymous:
        response = anonymous.get("/api/v1/auth/browser/qr")
        assert response.status_code == 401

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        assert client.get("/").status_code == 200

        cross_origin = client.get(
            "/api/v1/auth/browser/qr",
            headers={"Origin": "https://attacker.invalid"},
        )
        assert cross_origin.status_code == 403

        hostile_host = client.get(
            "/api/v1/auth/browser/qr",
            headers={"Host": "attacker.invalid"},
        )
        assert hostile_host.status_code == 400

        response = client.get(
            "/api/v1/auth/browser/qr",
            headers={"Origin": "http://127.0.0.1:8765"},
        )

    assert response.status_code == 200
    assert response.content == _QR_PNG
    assert response.headers["content-type"] == "image/png"
    assert response.headers["cache-control"] == (
        "private, no-store, max-age=0, must-revalidate"
    )
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["expires"] == "0"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-xhs-qr-revision"] == _REVISION
    assert response.headers["etag"] == f'"qr-{_REVISION}"'
    assert "access-control-allow-origin" not in response.headers


def test_embedded_qr_route_does_not_serialize_manager_state(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    backend: Any = _Backend(settings)
    backend.browser_login.cookie = "must-not-leak"
    backend.browser_login.remote_program = "must-not-execute-or-leak"
    backend.browser_login.qr_value = "https://www.xiaohongshu.com/private-qr"
    app = create_app(settings, backend=backend)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        assert client.get("/").status_code == 200
        response = client.get("/api/v1/auth/browser/qr")

    assert response.status_code == 200
    assert response.content == _QR_PNG
    lowered_headers = repr(dict(response.headers)).casefold()
    for marker in (
        "must-not-leak",
        "must-not-execute-or-leak",
        "private-qr",
        "cookie",
        "secpoisonid",
    ):
        assert marker not in lowered_headers
