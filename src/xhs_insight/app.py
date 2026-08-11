"""Local server entry point and cross-platform single-instance lock."""

from __future__ import annotations

import os
import sys
import threading
import webbrowser
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO

import uvicorn

from xhs_insight.api.app import create_app
from xhs_insight.config import Settings


class SingleInstanceLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle: BinaryIO | None = None

    def __enter__(self) -> SingleInstanceLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if sys.platform == "win32":
                import msvcrt

                handle.seek(0, os.SEEK_END)
                if handle.tell() < 1:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as error:
            handle.close()
            raise RuntimeError("CrimsonFlux 已在当前用户下运行。") from error
        self.handle = handle
        return self

    def __exit__(self, *_args: object) -> None:
        if self.handle is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt

                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


def serve(
    *,
    host: str | None = None,
    port: int | None = None,
    open_browser: bool | None = None,
) -> None:
    settings = Settings.from_env()
    if host is not None:
        settings = replace(settings, host=host)
    if port is not None:
        settings = replace(settings, port=int(port))
    if open_browser is not None:
        settings = replace(settings, open_browser=bool(open_browser))
    settings.prepare()

    with SingleInstanceLock(settings.state_dir / "instance.lock"):
        app = create_app(settings)
        if settings.open_browser:
            url = f"http://127.0.0.1:{settings.port}/"
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            log_level="info",
            access_log=False,
            server_header=False,
        )


__all__ = ["SingleInstanceLock", "serve"]
