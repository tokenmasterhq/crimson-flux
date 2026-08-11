"""Routes and packaged assets for the local single-page Web interface."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

if TYPE_CHECKING:
    from fastapi import FastAPI

WEB_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = WEB_ROOT / "static"
TEMPLATE_ROOT = WEB_ROOT / "templates"

templates = Jinja2Templates(directory=str(TEMPLATE_ROOT))


def _asset_version() -> str:
    """Return a short content hash so browser caches follow the bundled UI."""

    digest = sha256()
    for path in sorted(STATIC_ROOT.iterdir()):
        if path.is_file():
            digest.update(path.name.encode("utf-8"))
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


ASSET_VERSION = _asset_version()


def create_web_router() -> APIRouter:
    """Return the HTML router without coupling it to application construction."""

    router = APIRouter(include_in_schema=False)

    @router.get("/", response_class=HTMLResponse, name="web_index")
    async def index(request: Request) -> HTMLResponse:
        response = templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"api_base": "/api/v1", "asset_version": ASSET_VERSION},
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'none'; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data: blob:; "
            "object-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    return router


def mount_web(app: FastAPI) -> None:
    """Mount static files and the root page on an existing FastAPI app."""

    app.mount("/static", StaticFiles(directory=str(STATIC_ROOT)), name="web_static")
    app.include_router(create_web_router())
