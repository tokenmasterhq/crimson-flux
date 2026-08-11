from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from xhs_insight.adapters import AdapterError
from xhs_insight.adapters.rednote import RednoteAdapter
from xhs_insight.domain import AdapterErrorCode
from xhs_insight.platform import FailureKind, RedNoteProtocolError


class FakeAuth:
    authenticated = True
    account_fingerprint = "account-fixture"
    session_generation = 1

    @staticmethod
    def require_payload() -> dict[str, str]:
        return {"cookie": "a1=fixture-a1; web_session=fixture-session"}


class FakeClient:
    def __init__(
        self,
        *,
        me: Mapping[str, Any] | None = None,
        search: Mapping[str, Any] | None = None,
        user: Mapping[str, Any] | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        self.me = me or {}
        self.search = search or {}
        self.user = user or {}
        self.detail = detail or {}
        self.closed = False
        self.user_request: dict[str, str] | None = None

    @staticmethod
    def cookie_header() -> str:
        return "a1=fixture-a1; web_session=fixture-session"

    def get_user_me(self) -> Mapping[str, Any]:
        return self.me

    @staticmethod
    def new_search_id() -> str:
        return "search-fixture"

    def search_notes(
        self, _keyword: str, *, page: int, search_id: str, page_size: int = 20
    ) -> Mapping[str, Any]:
        assert page >= 1 and search_id and page_size == 20
        return self.search

    def user_notes(
        self,
        _user_id: str,
        *,
        cursor: str,
        xsec_token: str,
        xsec_source: str,
    ) -> Mapping[str, Any]:
        assert isinstance(cursor, str)
        self.user_request = {
            "cursor": cursor,
            "xsec_token": xsec_token,
            "xsec_source": xsec_source,
        }
        return self.user

    def note_detail(
        self, _note_id: str, *, xsec_token: str, xsec_source: str
    ) -> Mapping[str, Any]:
        assert isinstance(xsec_token, str) and xsec_source
        return self.detail

    def close(self) -> None:
        self.closed = True


def adapter_for(client: FakeClient) -> RednoteAdapter:
    return RednoteAdapter(FakeAuth(), client_factory=lambda _cookie: client)


def test_verify_cookie_requires_non_guest_identity_and_closes_candidate() -> None:
    client = FakeClient(me={"guest": False, "user_id": "user-1"})
    verified = adapter_for(client).verify_cookie(
        "Cookie: a1=secret-a1; web_session=secret-session"
    )
    assert verified.account_id == "user-1"
    assert "secret" not in repr(verified)
    assert client.closed is True


@pytest.mark.parametrize(
    ("identity", "expected"),
    [
        ({"guest": True, "user_id": "guest"}, AdapterErrorCode.AUTH_EXPIRED),
        ({"user_id": "user-1"}, AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED),
        ({"guest": False}, AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED),
    ],
)
def test_verify_cookie_fails_closed_on_identity_schema(
    identity: Mapping[str, Any], expected: AdapterErrorCode
) -> None:
    client = FakeClient(me=identity)
    with pytest.raises(AdapterError) as captured:
        adapter_for(client).verify_cookie("a1=secret-a1; web_session=secret-session")
    assert captured.value.code == expected
    assert client.closed is True


def test_retry_after_is_carried_to_adapter_error() -> None:
    class RateLimitedClient(FakeClient):
        def get_user_me(self) -> Mapping[str, Any]:
            raise RedNoteProtocolError(
                FailureKind.RATE_LIMIT,
                "user identity",
                status_code=429,
                retry_after=120,
            )

    with pytest.raises(AdapterError) as captured:
        adapter_for(RateLimitedClient()).verify_cookie(
            "a1=secret-a1; web_session=secret-session"
        )
    assert captured.value.code == AdapterErrorCode.RATE_LIMITED
    assert getattr(captured.value, "retry_after", None) == 120


def test_keyword_page_filters_non_note_cards_and_keeps_access_private() -> None:
    client = FakeClient(
        search={
            "items": [
                {"model_type": "user", "id": "skip"},
                {
                    "model_type": "note",
                    "id": "note-1",
                    "xsec_token": "private-token",
                    "note_card": {
                        "display_title": "一条笔记",
                        "type": "normal",
                        "user": {"user_id": "author-1", "nickname": "作者"},
                    },
                },
            ],
            "has_more": True,
        }
    )
    page = adapter_for(client).keyword_page("露营", {"page": 1})
    assert [item["note_id"] for item in page.items] == ["note-1"]
    assert page.items[0]["_private"] == {
        "xsec_token": "private-token",
        "xsec_source": "pc_search",
    }
    assert page.next_cursor == {"page": 2, "search_id": "search-fixture"}
    assert page.raw_item_count == 2
    assert page.skipped_item_count == 1


@pytest.mark.parametrize(
    "data",
    [
        {"items": []},
        {"items": [], "has_more": 0},
        {"items": {}, "has_more": False},
    ],
)
def test_keyword_page_rejects_schema_drift(data: Mapping[str, Any]) -> None:
    with pytest.raises(AdapterError) as captured:
        adapter_for(FakeClient(search=data)).keyword_page("露营")
    assert captured.value.code == AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED


def test_user_page_preserves_cursor_and_profile_access() -> None:
    client = FakeClient(
        user={
            "notes": [{"note_id": "note-1", "display_title": "主页笔记"}],
            "has_more": True,
            "cursor": "next-cursor",
        }
    )
    page = adapter_for(client).user_page(
        "https://www.xiaohongshu.com/user/profile/user-1"
        "?xsec_token=profile-token&xsec_source=pc_user",
        {"cursor": "", "page": 1},
    )
    assert page.items[0]["author_id"] == "user-1"
    assert page.items[0]["_private"]["xsec_token"] == "profile-token"
    assert page.next_cursor == {"cursor": "next-cursor", "page": 2}
    assert client.user_request == {
        "cursor": "",
        "xsec_token": "profile-token",
        "xsec_source": "pc_user",
    }


def test_user_page_rejects_has_more_without_cursor() -> None:
    client = FakeClient(user={"notes": [], "has_more": True, "cursor": ""})
    with pytest.raises(AdapterError) as captured:
        adapter_for(client).user_page(
            "https://www.xiaohongshu.com/user/profile/user-1"
        )
    assert captured.value.code == AdapterErrorCode.UPSTREAM_SCHEMA_CHANGED


def test_note_detail_returns_canonical_fields_and_sanitized_media() -> None:
    client = FakeClient(
        detail={
            "items": [
                {
                    "id": "note-1",
                    "note_card": {
                        "type": "video",
                        "title": "标题",
                        "desc": "正文",
                        "time": 1_700_000_000_000,
                        "tag_list": [{"name": "户外"}],
                        "image_list": [
                            {"url_default": "https://img.example/a.jpg?xsec_token=secret"}
                        ],
                        "video": {
                            "media": {
                                "stream": {
                                    "h264": [{"master_url": "https://video.example/v.mp4?sign=x"}]
                                }
                            }
                        },
                    },
                }
            ]
        }
    )
    result = adapter_for(client).note_detail(
        "note-1", {"xsec_token": "secret", "xsec_source": "pc_search"}
    )
    assert result.fields["description"] == "正文"
    assert result.fields["tag_names"] == ["户外"]
    assert result.fields["has_video"] is True
    assert "xsec_token" not in result.fields["image_urls"][0]
    assert "sign=" not in result.fields["video_url"]
