"""Public adapter contracts shared by the worker, Web API and CLI.

Adapters return only canonical public note fields plus an ephemeral ``_private``
mapping.  The worker must remove and encrypt that mapping before persisting a
page.  This keeps platform access tokens out of public JSON and exports.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from xhs_insight.domain import DetailResult, PageResult

Cursor = Mapping[str, Any] | None


@runtime_checkable
class AuthState(Protocol):
    @property
    def authenticated(self) -> bool: ...

    @property
    def account_fingerprint(self) -> str | None: ...


@runtime_checkable
class XHSAdapter(Protocol):
    """Minimal collection boundary used by the single-worker runner."""

    version: str
    auth: AuthState

    def keyword_page(self, keyword: str, cursor: Cursor = None) -> PageResult: ...

    def user_page(self, profile_url: str, cursor: Cursor = None) -> PageResult: ...

    def note_detail(
        self,
        note_id: str,
        private: Mapping[str, Any] | None = None,
    ) -> DetailResult: ...

    def close(self) -> None: ...


__all__ = ["AuthState", "Cursor", "XHSAdapter"]
