from __future__ import annotations

import gzip
import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest

from xhs_insight.platform import (
    FailureKind,
    HttpxJsonTransport,
    RedNoteClient,
    RedNoteProtocolError,
    TransportResponse,
)


class FakeSigner:
    user_agent = "fixture-agent"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, bool, str | None]] = []

    @staticmethod
    def generate_a1() -> str:
        return "a" * 52

    @staticmethod
    def generate_web_id(_a1: str) -> str:
        return "b" * 32

    @staticmethod
    def new_search_id() -> str:
        return "search-fixture"

    @staticmethod
    def new_search_request_id() -> str:
        return "request-fixture"

    @staticmethod
    def build_url(path: str, params: Mapping[str, Any]) -> str:
        return path if not params else f"{path}?{urlencode(params, doseq=True)}"

    def sign_get(
        self,
        path: str,
        _cookies: Mapping[str, str],
        _params: Mapping[str, Any],
        *,
        sign_format: str,
        user_id: str | None,
        x_rap: bool,
    ) -> Mapping[str, str]:
        self.calls.append(("GET", path, sign_format, x_rap, user_id))
        return {"x-s": "signed", "x-s-common": "common", "x-t": "1"}

    def sign_post(
        self,
        path: str,
        _cookies: Mapping[str, str],
        _payload: Mapping[str, Any],
        *,
        sign_format: str,
        user_id: str | None,
        x_rap: bool,
    ) -> Mapping[str, str]:
        self.calls.append(("POST", path, sign_format, x_rap, user_id))
        return {"x-s": "signed", "x-s-common": "common", "x-t": "1"}


class FakeTransport:
    def __init__(self, *responses: TransportResponse) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []
        self.closed = False

    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        max_response_bytes: int,
    ) -> TransportResponse:
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "max_response_bytes": max_response_bytes,
            }
        )
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


def ok(data: Mapping[str, Any], **cookies: str) -> TransportResponse:
    return TransportResponse(200, {"success": True, "data": dict(data)}, cookies)


def test_direct_qr_flow_merges_cookies_and_replaces_visitor_session() -> None:
    signer = FakeSigner()
    transport = FakeTransport(
        ok({"session": "visitor-session"}, abRequestId="edge-cookie"),
        ok(
            {
                "qr_id": "qr-id",
                "code": "qr-code",
                "url": "https://www.xiaohongshu.com/mobile/login?fixture=1",
            }
        ),
        ok({"codeStatus": 1}),
        ok(
            {
                "code_status": 2,
                "login_info": {
                    "session": "formal-session",
                    "secure_session": "secure-session",
                },
            }
        ),
        ok({"guest": False, "user_id": "user-1"}),
    )
    client = RedNoteClient.visitor(transport=transport, signer=signer)

    assert "a" * 52 not in repr(client)
    assert "a" * 52 not in repr(client.cookies)
    client.login_activate()
    challenge = client.create_qr()
    assert challenge["qr_id"] == "qr-id"
    assert client.poll_qr("qr-id", "qr-code")["codeStatus"] == 1
    client.complete_qr("qr-id", "qr-code")
    assert client.get_user_me()["guest"] is False

    cookie_header = client.cookie_header()
    assert "formal-session" in cookie_header
    assert "secure-session" in cookie_header
    assert "visitor-session" not in cookie_header
    assert [call[:4] for call in signer.calls] == [
        ("POST", "/api/sns/web/v1/login/activate", "xys", False),
        ("POST", "/api/sns/web/v1/login/qrcode/create", "xys", False),
        ("POST", "/api/qrcode/userinfo", "xys", False),
        ("GET", "/api/sns/web/v1/login/qrcode/status", "xys", False),
        ("GET", "/api/sns/web/v2/user/me", "xys", False),
    ]
    assert transport.requests[2]["headers"]["service-tag"] == "webcn"
    assert transport.requests[3]["headers"]["x-login-mode"] == ""
    assert {
        request["max_response_bytes"] for request in transport.requests
    } == {256 * 1024}


def test_collection_uses_endpoint_specific_signature_modes() -> None:
    signer = FakeSigner()
    transport = FakeTransport(
        ok({"items": [], "has_more": False}),
        ok({"notes": [], "has_more": False, "cursor": ""}),
        ok({"items": []}),
    )
    client = RedNoteClient(
        "a1=fixture-a1; webId=fixture-web; web_session=fixture-session",
        transport=transport,
        signer=signer,
    )

    client.search_notes("露营", page=1, search_id="search-1")
    client.user_notes(
        "user-1",
        cursor="",
        xsec_token="profile-token",
        xsec_source="pc_user",
    )
    client.note_detail("note-1", xsec_token="token", xsec_source="pc_search")

    assert signer.calls == [
        ("POST", "/api/sns/web/v2/search/notes", "xys", True, None),
        ("GET", "/api/sns/web/v1/user_posted", "xyw", True, "user-1"),
        ("POST", "/api/sns/web/v1/feed", "xys", True, None),
    ]
    search_payload = json.loads(transport.requests[0]["body"])
    assert search_payload["session_id"] == "request-fixture"
    assert "filters" not in search_payload
    assert transport.requests[0]["url"].startswith(
        "https://so.xiaohongshu.com/api/sns/web/v2/search/notes"
    )
    assert transport.requests[0]["max_response_bytes"] == 4 * 1024 * 1024
    assert transport.requests[0]["body"] is not None
    assert "x-rap-param" not in transport.requests[0]["headers"]  # fake signer is minimal
    assert "user_id=user-1" in transport.requests[1]["url"]
    assert "xsec_token=profile-token" in transport.requests[1]["url"]
    assert "xsec_source=pc_user" in transport.requests[1]["url"]
    assert "image_formats=" in transport.requests[1]["url"]
    assert "image_scenes=" not in transport.requests[1]["url"]
    assert transport.requests[1]["max_response_bytes"] == 4 * 1024 * 1024


@pytest.mark.parametrize("request_id", ["", "x" * 129])
def test_search_request_id_must_be_nonempty_and_bounded(request_id: str) -> None:
    class InvalidRequestIdSigner(FakeSigner):
        @staticmethod
        def new_search_request_id() -> str:
            return request_id

    transport = FakeTransport()
    client = RedNoteClient(
        "a1=fixture-a1; web_session=fixture-session",
        transport=transport,
        signer=InvalidRequestIdSigner(),
    )
    with pytest.raises(RedNoteProtocolError) as captured:
        client.search_notes("露营", page=1, search_id="search-1")
    assert captured.value.kind == FailureKind.SCHEMA
    assert transport.requests == []


def test_upstream_error_never_reflects_response_message_or_cookie() -> None:
    secret = "top-secret-session"
    transport = FakeTransport(
        TransportResponse(
            200,
            {"success": False, "code": -100, "msg": f"expired {secret}"},
        )
    )
    client = RedNoteClient(
        f"a1=fixture-a1; web_session={secret}",
        transport=transport,
        signer=FakeSigner(),
    )

    with pytest.raises(RedNoteProtocolError) as captured:
        client.get_user_me()

    assert captured.value.kind == FailureKind.AUTH
    assert secret not in str(captured.value)
    assert secret not in repr(captured.value)


def test_qr_completion_rejects_unchanged_visitor_session() -> None:
    transport = FakeTransport(
        ok(
            {
                "code_status": 2,
                "login_info": {"session": "visitor-session"},
            }
        )
    )
    client = RedNoteClient(
        "a1=fixture-a1; webId=fixture-web; web_session=visitor-session",
        transport=transport,
        signer=FakeSigner(),
    )
    with pytest.raises(RedNoteProtocolError) as captured:
        client.complete_qr("qr-id", "qr-code")
    assert captured.value.kind == FailureKind.SCHEMA


def test_close_erases_cookie_state_and_closes_transport() -> None:
    transport = FakeTransport()
    client = RedNoteClient(
        "a1=fixture-a1; web_session=fixture-session",
        transport=transport,
        signer=FakeSigner(),
    )
    client.close()
    assert transport.closed is True
    assert dict(client.cookies) == {}
    with pytest.raises(RedNoteProtocolError):
        client.cookie_header()


def test_authenticated_cookie_requires_a1_and_web_session() -> None:
    with pytest.raises(ValueError, match="a1 and web_session"):
        RedNoteClient(
            "a1=fixture-a1",
            transport=FakeTransport(),
            signer=FakeSigner(),
        )
    with pytest.raises(ValueError, match="a1 and web_session"):
        RedNoteClient(
            "web_session=fixture-session",
            transport=FakeTransport(),
            signer=FakeSigner(),
        )


def test_retry_after_is_bounded_and_carried_without_response_text() -> None:
    transport = FakeTransport(
        TransportResponse(
            429,
            {"success": False, "msg": "secret upstream message"},
            retry_after=100_000,
        )
    )
    client = RedNoteClient(
        "a1=fixture-a1; web_session=fixture-session",
        transport=transport,
        signer=FakeSigner(),
    )
    with pytest.raises(RedNoteProtocolError) as captured:
        client.get_user_me()
    assert captured.value.kind == FailureKind.RATE_LIMIT
    assert captured.value.retry_after == 60 * 60
    assert "secret upstream message" not in repr(captured.value)


def test_signer_cannot_replace_fixed_origin_or_retain_external_exception() -> None:
    class HostReplacingSigner(FakeSigner):
        @staticmethod
        def build_url(_path: str, _params: Mapping[str, Any]) -> str:
            return "https://attacker.invalid/collect"

    transport = FakeTransport()
    client = RedNoteClient(
        "a1=fixture-a1; web_session=fixture-session",
        transport=transport,
        signer=HostReplacingSigner(),
    )
    with pytest.raises(RedNoteProtocolError) as captured:
        client.get_user_me()
    assert captured.value.kind == FailureKind.SIGNER
    assert captured.value.__cause__ is None
    assert transport.requests == []

    class ExplodingSigner(FakeSigner):
        def sign_get(
            self,
            path: str,
            cookies: Mapping[str, str],
            params: Mapping[str, Any],
            *,
            sign_format: str,
            user_id: str | None,
            x_rap: bool,
        ) -> Mapping[str, str]:
            del path, cookies, params, sign_format, user_id, x_rap
            raise RuntimeError("secret request material")

    exploding = RedNoteClient(
        "a1=fixture-a1; web_session=fixture-session",
        transport=FakeTransport(),
        signer=ExplodingSigner(),
    )
    with pytest.raises(RedNoteProtocolError) as exploded:
        exploding.get_user_me()
    assert exploded.value.__cause__ is None
    assert "secret request material" not in repr(exploded.value)


def test_http_transport_bounds_decompressed_json_and_parses_retry_after() -> None:
    oversized = gzip.compress(json.dumps({"value": "x" * 512}).encode())

    def oversized_response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            content=oversized,
            headers={"content-encoding": "gzip", "retry-after": "999999"},
        )

    transport = HttpxJsonTransport()
    transport._client.close()
    transport._client = httpx.Client(
        transport=httpx.MockTransport(oversized_response), trust_env=False
    )
    with pytest.raises(RedNoteProtocolError) as captured:
        transport.request_json(
            "GET",
            "https://edith.xiaohongshu.com/api/sns/web/v2/user/me",
            headers={},
            body=None,
            max_response_bytes=256,
        )
    assert captured.value.operation == "bounded response"

    def retry_response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={"success": False},
            headers={"retry-after": "999999"},
        )

    transport._client.close()
    transport._client = httpx.Client(
        transport=httpx.MockTransport(retry_response), trust_env=False
    )
    response = transport.request_json(
        "GET",
        "https://edith.xiaohongshu.com/api/sns/web/v2/user/me",
        headers={},
        body=None,
        max_response_bytes=256 * 1024,
    )
    assert response.retry_after == 60 * 60
    transport.close()
