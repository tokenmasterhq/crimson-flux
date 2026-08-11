"""Canonical collection adapter over the independent platform client."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, urlsplit

from xhs_insight.domain import AdapterErrorCode, DetailResult, PageResult
from xhs_insight.platform import (
    EXPECTED_SIGNER_VERSION,
    FailureKind,
    RedNoteClient,
    RedNoteProtocolError,
    runtime_doctor,
)
from xhs_insight.security import sanitize_url

from ..auth import AuthManager, VerifiedLogin, normalize_cookie_header
from ..base import Cursor
from ..errors import AdapterError


class PlatformClient(Protocol):
    def cookie_header(self) -> str: ...

    def get_user_me(self) -> Mapping[str, Any]: ...

    def new_search_id(self) -> str: ...

    def search_notes(
        self, keyword: str, *, page: int, search_id: str, page_size: int = 20
    ) -> Mapping[str, Any]: ...

    def user_notes(
        self,
        user_id: str,
        *,
        cursor: str,
        xsec_token: str,
        xsec_source: str,
    ) -> Mapping[str, Any]: ...

    def note_detail(
        self, note_id: str, *, xsec_token: str, xsec_source: str
    ) -> Mapping[str, Any]: ...

    def close(self) -> None: ...


ClientFactory = Callable[[str], PlatformClient]

_FAILURE_CODES = {
    FailureKind.AUTH: AdapterErrorCode.AUTH_EXPIRED,
    FailureKind.RATE_LIMIT: AdapterErrorCode.RATE_LIMITED,
    FailureKind.RISK_CONTROL: AdapterErrorCode.RISK_CONTROLLED,
    FailureKind.NETWORK: AdapterErrorCode.NETWORK_ERROR,
    FailureKind.SCHEMA: AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
    FailureKind.SIGNER: AdapterErrorCode.SIGNER_FAILED,
    FailureKind.UNSUPPORTED: AdapterErrorCode.UPSTREAM_UNSUPPORTED,
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return {}


def _timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            value = int(text)
        else:
            return text
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        seconds = numeric / 1000 if numeric > 10_000_000_000 else numeric
        try:
            return datetime.fromtimestamp(seconds, UTC).isoformat(timespec="seconds")
        except (OSError, OverflowError, ValueError):
            return None
    return None


def _note_type(value: Any) -> str:
    normalized = str(value or "").casefold()
    if normalized in {"normal", "image", "images", "图文", "图集"}:
        return "image"
    if normalized in {"video", "视频"}:
        return "video"
    return "unknown"


def _identity(item: Mapping[str, Any]) -> tuple[str, str, Mapping[str, Any]]:
    card = _mapping(item.get("note_card")) or item
    note_id = str(item.get("id") or item.get("note_id") or card.get("id") or "").strip()
    token = str(item.get("xsec_token") or card.get("xsec_token") or "").strip()
    return note_id, token, card


def _list_item(
    raw: Mapping[str, Any],
    *,
    page: int,
    default_token: str = "",
    default_author_id: str = "",
    xsec_source: str,
) -> dict[str, Any] | None:
    note_id, token, card = _identity(raw)
    if not note_id or len(note_id) > 256:
        return None
    user = _mapping(card.get("user"))
    interactions = _mapping(card.get("interact_info"))
    author_id = str(user.get("user_id") or user.get("id") or default_author_id).strip()
    item: dict[str, Any] = {
        "note_id": note_id,
        "source_page": page,
        "note_url": f"https://www.xiaohongshu.com/explore/{quote(note_id, safe='')}",
        "note_type": _note_type(card.get("type")),
        "title": str(card.get("title") or card.get("display_title") or ""),
        "author_id": author_id or None,
        "author_name": str(user.get("nickname") or user.get("nick_name") or "") or None,
        "author_profile_url": (
            f"https://www.xiaohongshu.com/user/profile/{quote(author_id, safe='')}"
            if author_id
            else None
        ),
        "liked_count": interactions.get("liked_count"),
        "collected_count": interactions.get("collected_count"),
        "comment_count": interactions.get("comment_count"),
        "share_count": interactions.get("share_count"),
        "collected_at": _utc_now(),
    }
    private: dict[str, str] = {}
    access_token = token or default_token
    if access_token:
        private["xsec_token"] = access_token
    if xsec_source:
        private["xsec_source"] = xsec_source
    if private:
        item["_private"] = private
    return item


def _image_urls(card: Mapping[str, Any]) -> list[str]:
    images = card.get("image_list")
    if not isinstance(images, list):
        return []
    result: list[str] = []
    for image in images:
        if not isinstance(image, Mapping):
            continue
        candidates: list[Any] = [image.get("url_default"), image.get("url")]
        info_list = image.get("info_list")
        if isinstance(info_list, list):
            candidates.extend(
                info.get("url") for info in info_list if isinstance(info, Mapping)
            )
        for candidate in candidates:
            url = sanitize_url(candidate)
            if url and url not in result:
                result.append(url)
                break
    return result


def _video_url(card: Mapping[str, Any]) -> str | None:
    stream = _mapping(_mapping(_mapping(card.get("video")).get("media")).get("stream"))
    h264 = stream.get("h264")
    if isinstance(h264, list):
        for candidate in h264:
            if isinstance(candidate, Mapping):
                url = sanitize_url(candidate.get("master_url") or candidate.get("url"))
                if url:
                    return url
    origin_key = str(
        _mapping(_mapping(card.get("video")).get("consumer")).get("origin_video_key") or ""
    ).strip()
    if origin_key:
        return sanitize_url(f"https://sns-video-bd.xhscdn.com/{quote(origin_key, safe='/')}")
    return None


def _detail_fields(item: Mapping[str, Any], note_id: str) -> dict[str, Any]:
    card = _mapping(item.get("note_card")) or item
    user = _mapping(card.get("user"))
    interactions = _mapping(card.get("interact_info"))
    author_id = str(user.get("user_id") or user.get("id") or "").strip()
    raw_tags = card.get("tag_list")
    tags = (
        [
            str(tag.get("name"))
            for tag in raw_tags
            if isinstance(tag, Mapping) and str(tag.get("name") or "").strip()
        ]
        if isinstance(raw_tags, list)
        else []
    )
    images = _image_urls(card)
    video_url = _video_url(card)
    return {
        "note_url": f"https://www.xiaohongshu.com/explore/{quote(note_id, safe='')}",
        "note_type": _note_type(card.get("type")),
        "title": str(card.get("title") or card.get("display_title") or ""),
        "description": str(card.get("desc") or card.get("description") or ""),
        "author_id": author_id or None,
        "author_name": str(user.get("nickname") or user.get("nick_name") or "") or None,
        "author_profile_url": (
            f"https://www.xiaohongshu.com/user/profile/{quote(author_id, safe='')}"
            if author_id
            else None
        ),
        "published_at": _timestamp(card.get("time") or card.get("publish_time")),
        "updated_at": _timestamp(card.get("last_update_time") or card.get("update_time")),
        "tag_names": tags,
        "liked_count": interactions.get("liked_count"),
        "collected_count": interactions.get("collected_count"),
        "comment_count": interactions.get("comment_count"),
        "share_count": interactions.get("share_count"),
        "image_count": len(images),
        "image_urls": images,
        "has_video": bool(video_url or _note_type(card.get("type")) == "video"),
        "video_url": video_url,
    }


def _adapter_error(error: Exception) -> AdapterError:
    if isinstance(error, AdapterError):
        return error
    if isinstance(error, RedNoteProtocolError):
        mapped = AdapterError(
            _FAILURE_CODES[error.kind],
            detail=f"{error.operation}:{error.kind.value}",
            retry_after=error.retry_after,
        )
        return mapped
    if isinstance(error, ValueError):
        return AdapterError(
            AdapterErrorCode.AUTH_EXPIRED,
            detail="credential or local state validation failed",
        )
    return AdapterError(
        AdapterErrorCode.INTERNAL_ERROR,
        detail=f"platform client raised {type(error).__name__}",
    )


class RednoteAdapter:
    """Stable worker boundary backed only by the independent protocol client."""

    version = f"rednote-http:xhshow-{EXPECTED_SIGNER_VERSION}:adapter-v1"

    def __init__(
        self,
        auth: AuthManager | Any,
        *,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self.auth = auth
        self._client_factory = client_factory or (lambda cookie: RedNoteClient(cookie))
        self._client: PlatformClient | None = None
        self._client_fingerprint: str | None = None
        self._client_generation: int | None = None
        self._lock = threading.RLock()

    def doctor(self) -> dict[str, Any]:
        return runtime_doctor().as_dict()

    def _close_locked(self) -> None:
        if self._client is not None:
            with suppress(Exception):
                self._client.close()
        self._client = None
        self._client_fingerprint = None
        self._client_generation = None

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def _open_client(self) -> PlatformClient:
        if not bool(getattr(self.auth, "authenticated", False)):
            raise AdapterError(AdapterErrorCode.AUTH_EXPIRED)
        fingerprint = getattr(self.auth, "account_fingerprint", None)
        generation = getattr(self.auth, "session_generation", None)
        with self._lock:
            if (
                self._client is not None
                and self._client_fingerprint == fingerprint
                and self._client_generation == generation
            ):
                return self._client
            self._close_locked()
            try:
                payload = self.auth.require_payload()
                cookie = normalize_cookie_header(str(payload.get("cookie") or ""))
                client = self._client_factory(cookie)
            except (AdapterError, ValueError):
                raise
            except Exception as error:
                raise _adapter_error(error) from None
            self._client = client
            self._client_fingerprint = fingerprint
            self._client_generation = generation
            return client

    def verify_cookie(self, cookie: str) -> VerifiedLogin:
        try:
            normalized = normalize_cookie_header(cookie)
        except ValueError as error:
            raise AdapterError(
                AdapterErrorCode.AUTH_EXPIRED,
                detail=f"credential format rejected ({type(error).__name__})",
            ) from None
        candidate: PlatformClient | None = None
        try:
            candidate = self._client_factory(normalized)
            data = candidate.get_user_me()
            guest = data.get("guest")
            if type(guest) is not bool:
                raise AdapterError(
                    AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
                    detail="user identity guest flag missing",
                )
            if guest is not False:
                raise AdapterError(
                    AdapterErrorCode.AUTH_EXPIRED,
                    detail="user identity remained guest",
                )
            account_id = str(data.get("user_id") or "").strip()
            if not account_id or len(account_id) > 256:
                raise AdapterError(
                    AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
                    detail="user identity id missing",
                )
            verified_cookie = normalize_cookie_header(candidate.cookie_header())
            return VerifiedLogin(cookie=verified_cookie, account_id=account_id)
        except AdapterError:
            raise
        except Exception as error:
            raise _adapter_error(error) from None
        finally:
            if candidate is not None:
                with suppress(Exception):
                    candidate.close()

    def keyword_page(self, keyword: str, cursor: Cursor = None) -> PageResult:
        query = " ".join(str(keyword or "").split())
        if not query:
            raise ValueError("keyword cannot be empty")
        state = dict(cursor or {})
        try:
            page = max(1, int(state.get("page") or 1))
        except (TypeError, ValueError):
            raise AdapterError(
                AdapterErrorCode.RESUME_INCOMPATIBLE, detail="keyword page cursor invalid"
            ) from None
        client = self._open_client()
        try:
            search_id = str(state.get("search_id") or client.new_search_id())
            if not search_id or len(search_id) > 128:
                raise AdapterError(
                    AdapterErrorCode.RESUME_INCOMPATIBLE, detail="search id invalid"
                )
            data = client.search_notes(query, page=page, search_id=search_id)
        except Exception as error:
            raise _adapter_error(error) from None
        raw_items = data.get("items")
        has_more = data.get("has_more")
        if not isinstance(raw_items, list) or type(has_more) is not bool:
            raise AdapterError(
                AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
                detail="search items or has_more invalid",
            )
        items: list[dict[str, Any]] = []
        skipped = 0
        for raw in raw_items:
            if not isinstance(raw, Mapping) or raw.get("model_type") != "note":
                skipped += 1
                continue
            item = _list_item(raw, page=page, xsec_source="pc_search")
            if item is None:
                skipped += 1
            else:
                items.append(item)
        return PageResult(
            items=items,
            next_cursor={"page": page + 1, "search_id": search_id} if has_more else None,
            has_more=has_more,
            raw_item_count=len(raw_items),
            skipped_item_count=skipped,
        )

    @staticmethod
    def _parse_profile(profile_url: str) -> tuple[str, str, str]:
        try:
            parsed = urlsplit(str(profile_url or "").strip())
            port = parsed.port
        except ValueError:
            raise AdapterError(AdapterErrorCode.INVALID_PROFILE_URL) from None
        parts = [part for part in parsed.path.split("/") if part]
        if (
            parsed.scheme != "https"
            or (parsed.hostname or "").casefold().rstrip(".")
            not in {"xiaohongshu.com", "www.xiaohongshu.com"}
            or port is not None
            or parsed.username is not None
            or parsed.password is not None
            or len(parts) != 3
            or parts[:2] != ["user", "profile"]
            or not parts[2]
            or len(parts[2]) > 256
        ):
            raise AdapterError(AdapterErrorCode.INVALID_PROFILE_URL)
        query = parse_qs(parsed.query, keep_blank_values=False)
        token = str((query.get("xsec_token") or [""])[-1])[:2048]
        source = str((query.get("xsec_source") or ["pc_user"])[-1])[:128] or "pc_user"
        return parts[2], token, source

    def user_page(self, profile_url: str, cursor: Cursor = None) -> PageResult:
        user_id, profile_token, xsec_source = self._parse_profile(profile_url)
        state = dict(cursor or {})
        current_cursor = str(state.get("cursor") or "")
        try:
            page = max(1, int(state.get("page") or 1))
        except (TypeError, ValueError):
            raise AdapterError(
                AdapterErrorCode.RESUME_INCOMPATIBLE, detail="user page cursor invalid"
            ) from None
        if len(current_cursor) > 4096:
            raise AdapterError(
                AdapterErrorCode.RESUME_INCOMPATIBLE, detail="user cursor too long"
            )
        client = self._open_client()
        try:
            data = client.user_notes(
                user_id,
                cursor=current_cursor,
                xsec_token=profile_token,
                xsec_source=xsec_source,
            )
        except Exception as error:
            raise _adapter_error(error) from None
        raw_items = data.get("notes")
        has_more = data.get("has_more")
        if not isinstance(raw_items, list) or type(has_more) is not bool:
            raise AdapterError(
                AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
                detail="user notes or has_more invalid",
            )
        items: list[dict[str, Any]] = []
        skipped = 0
        for raw in raw_items:
            if not isinstance(raw, Mapping):
                skipped += 1
                continue
            item = _list_item(
                raw,
                page=page,
                default_token=profile_token,
                default_author_id=user_id,
                xsec_source=xsec_source,
            )
            if item is None:
                skipped += 1
            else:
                items.append(item)
        next_value = data.get("cursor")
        if has_more and (not isinstance(next_value, str) or not next_value or len(next_value) > 4096):
            raise AdapterError(
                AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
                detail="user has_more cursor invalid",
            )
        return PageResult(
            items=items,
            next_cursor={"cursor": next_value, "page": page + 1} if has_more else None,
            has_more=has_more,
            raw_item_count=len(raw_items),
            skipped_item_count=skipped,
        )

    def note_detail(
        self,
        note_id: str,
        private: Mapping[str, Any] | None = None,
    ) -> DetailResult:
        identifier = str(note_id or "").strip()
        if not identifier or len(identifier) > 256:
            raise ValueError("note_id cannot be empty or exceed 256 characters")
        access = dict(private or {})
        token = str(access.get("xsec_token") or "")
        source = str(access.get("xsec_source") or "pc_search") or "pc_search"
        if len(token) > 2048 or len(source) > 128:
            raise AdapterError(
                AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED, detail="note access context invalid"
            )
        client = self._open_client()
        try:
            data = client.note_detail(
                identifier,
                xsec_token=token,
                xsec_source=source,
            )
        except Exception as error:
            raise _adapter_error(error) from None
        raw_item = _first_mapping(data.get("items"))
        if not raw_item:
            raise AdapterError(
                AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
                detail="detail items[0] missing",
            )
        returned_id, _, _ = _identity(raw_item)
        if returned_id and returned_id != identifier:
            raise AdapterError(
                AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED,
                detail="detail note id mismatch",
            )
        return DetailResult(note_id=identifier, fields=_detail_fields(raw_item, identifier))


__all__ = ["RednoteAdapter"]
