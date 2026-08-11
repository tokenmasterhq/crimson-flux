"""Jinja powered local Web interface.

The Web layer intentionally contains no authentication material.  It talks to
the local, same-origin ``/api/v1`` API from the browser.
"""

from xhs_insight.web.routes import create_web_router, mount_web

__all__ = ["create_web_router", "mount_web"]
