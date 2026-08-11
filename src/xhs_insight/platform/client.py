"""Narrow, pure-Python transport for the public-note collection surface.

Only the fixed endpoint allowlist in this module is reachable.  Request
signatures are delegated to the public ``xhshow`` API; this module neither
downloads nor executes JavaScript and never persists credentials.
"""

from __future__ import annotations

import json
import math
import re
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import httpx
import xhshow

API_ORIGIN = "https://edith.xiaohongshu.com"
SEARCH_ORIGIN = "https://so.xiaohongshu.com"
WEB_ORIGIN = "https://www.xiaohongshu.com"
EXPECTED_SIGNER_VERSION = "0.2.0"

_MAX_LOGIN_RESPONSE_BYTES = 256 * 1024
_MAX_COLLECTION_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_RETRY_AFTER_SECONDS = 60 * 60
_MAX_COOKIE_BYTES = 16 * 1024
_MAX_COOKIE_COUNT = 64
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SAFE_SIGNED_HEADERS = frozenset(
    {
        "x-s",
        "x-s-common",
        "x-t",
        "x-b3-traceid",
        "x-xray-traceid",
        "x-mns",
        "xy-direction",
        "x-rap-param",
    }
)
_ENDPOINTS = {
    ("POST", "/api/sns/web/v1/login/activate"): (
        API_ORIGIN,
        _MAX_LOGIN_RESPONSE_BYTES,
    ),
    ("POST", "/api/sns/web/v1/login/qrcode/create"): (
        API_ORIGIN,
        _MAX_LOGIN_RESPONSE_BYTES,
    ),
    ("POST", "/api/qrcode/userinfo"): (API_ORIGIN, _MAX_LOGIN_RESPONSE_BYTES),
    ("GET", "/api/sns/web/v1/login/qrcode/status"): (
        API_ORIGIN,
        _MAX_LOGIN_RESPONSE_BYTES,
    ),
    ("GET", "/api/sns/web/v2/user/me"): (API_ORIGIN, _MAX_LOGIN_RESPONSE_BYTES),
    ("POST", "/api/sns/web/v2/search/notes"): (
        SEARCH_ORIGIN,
        _MAX_COLLECTION_RESPONSE_BYTES,
    ),
    ("GET", "/api/sns/web/v1/user_posted"): (
        API_ORIGIN,
        _MAX_COLLECTION_RESPONSE_BYTES,
    ),
    ("POST", "/api/sns/web/v1/feed"): (
        API_ORIGIN,
        _MAX_COLLECTION_RESPONSE_BYTES,
    ),
}


class FailureKind(StrEnum):
    """Credential-free platform failure categories."""

    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    RISK_CONTROL = "risk_control"
    NETWORK = "network"
    SCHEMA = "schema"
    SIGNER = "signer"
    UNSUPPORTED = "unsupported"


class RedNoteProtocolError(RuntimeError):
    """An error safe to classify without retaining response or credential data."""

    def __init__(
        self,
        kind: FailureKind,
        operation: str,
        *,
        status_code: int | None = None,
        upstream_code: int | None = None,
        retry_after: int | None = None,
    ) -> None:
        self.kind = kind
        self.operation = operation
        self.status_code = status_code
        self.upstream_code = upstream_code
        self.retry_after = (
            min(retry_after, _MAX_RETRY_AFTER_SECONDS)
            if type(retry_after) is int and retry_after >= 0
            else None
        )
        super().__init__(f"{operation} failed ({kind.value})")

    def __repr__(self) -> str:
        return (
            f"RedNoteProtocolError(kind={self.kind.value!r}, "
            f"operation={self.operation!r})"
        )


class CookieView(Mapping[str, str]):
    """Read-only cookie snapshot whose repr never reveals values."""

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: str) -> str:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return f"CookieView(<redacted>, count={len(self._values)})"


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status_code: int
    body: Any = field(repr=False)
    cookies: Mapping[str, str] = field(default_factory=dict, repr=False)
    retry_after: int | None = None


class JsonTransport(Protocol):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        max_response_bytes: int,
    ) -> TransportResponse: ...

    def close(self) -> None: ...


class RequestSigner(Protocol):
    user_agent: str

    def generate_a1(self) -> str: ...

    def generate_web_id(self, a1: str) -> str: ...

    def new_search_id(self) -> str: ...

    def new_search_request_id(self) -> str: ...

    def build_url(self, path: str, params: Mapping[str, Any]) -> str: ...

    def sign_get(
        self,
        path: str,
        cookies: Mapping[str, str],
        params: Mapping[str, Any],
        *,
        sign_format: Literal["xys", "xyw"],
        user_id: str | None,
        x_rap: bool,
    ) -> Mapping[str, str]: ...

    def sign_post(
        self,
        path: str,
        cookies: Mapping[str, str],
        payload: Mapping[str, Any],
        *,
        sign_format: Literal["xys", "xyw"],
        user_id: str | None,
        x_rap: bool,
    ) -> Mapping[str, str]: ...


class XhshowSigner:
    """Small adapter over public APIs exported by ``xhshow==0.2.0``."""

    def __init__(self) -> None:
        try:
            config = xhshow.CryptoConfig()
            self._client = xhshow.Xhshow(config)
            self._session = xhshow.SessionManager(config)
            self.user_agent = str(config.PUBLIC_USERAGENT)
        except Exception:
            raise RedNoteProtocolError(
                FailureKind.SIGNER, "signer initialization"
            ) from None

    def generate_a1(self) -> str:
        try:
            return str(self._client.generate_a1())
        except Exception:
            raise RedNoteProtocolError(FailureKind.SIGNER, "visitor a1") from None

    def generate_web_id(self, a1: str) -> str:
        try:
            return str(self._client.generate_web_id(a1))
        except Exception:
            raise RedNoteProtocolError(FailureKind.SIGNER, "visitor webId") from None

    def new_search_id(self) -> str:
        try:
            return str(self._client.get_search_id())
        except Exception:
            raise RedNoteProtocolError(FailureKind.SIGNER, "search id") from None

    def new_search_request_id(self) -> str:
        try:
            return str(self._client.get_search_request_id())
        except Exception:
            raise RedNoteProtocolError(
                FailureKind.SIGNER, "search request id"
            ) from None

    def build_url(self, path: str, params: Mapping[str, Any]) -> str:
        try:
            return str(self._client.build_url(path, dict(params)))
        except Exception:
            raise RedNoteProtocolError(FailureKind.SIGNER, "request path") from None

    def sign_get(
        self,
        path: str,
        cookies: Mapping[str, str],
        params: Mapping[str, Any],
        *,
        sign_format: Literal["xys", "xyw"],
        user_id: str | None,
        x_rap: bool,
    ) -> Mapping[str, str]:
        try:
            return self._client.sign_headers_get(
                path,
                dict(cookies),
                params=dict(params),
                session=self._session,
                sign_format=sign_format,
                user_id=user_id,
                x_rap=x_rap,
            )
        except Exception:
            raise RedNoteProtocolError(FailureKind.SIGNER, "GET signing") from None

    def sign_post(
        self,
        path: str,
        cookies: Mapping[str, str],
        payload: Mapping[str, Any],
        *,
        sign_format: Literal["xys", "xyw"],
        user_id: str | None,
        x_rap: bool,
    ) -> Mapping[str, str]:
        try:
            return self._client.sign_headers_post(
                path,
                dict(cookies),
                payload=dict(payload),
                session=self._session,
                sign_format=sign_format,
                user_id=user_id,
                x_rap=x_rap,
            )
        except Exception:
            raise RedNoteProtocolError(FailureKind.SIGNER, "POST signing") from None


class HttpxJsonTransport:
    """Bounded JSON transport with no redirects or implicit cookie replay."""

    def __init__(self, *, timeout: float = 30.0) -> None:
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            verify=True,
            trust_env=False,
        )

    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        max_response_bytes: int,
    ) -> TransportResponse:
        if (
            type(max_response_bytes) is not int
            or max_response_bytes < 1
            or max_response_bytes > _MAX_COLLECTION_RESPONSE_BYTES
        ):
            raise RedNoteProtocolError(FailureKind.UNSUPPORTED, "response bound")
        retained = bytearray()
        response_cookies: dict[str, str] = {}
        try:
            with self._client.stream(
                method,
                url,
                headers=dict(headers),
                content=body,
            ) as response:
                for chunk in response.iter_bytes():
                    retained.extend(chunk)
                    if len(retained) > max_response_bytes:
                        raise RedNoteProtocolError(
                            FailureKind.SCHEMA, "bounded response"
                        )
                for cookie in response.cookies.jar:
                    cookie_name = cookie.name
                    cookie_value = cookie.value
                    if (
                        isinstance(cookie_name, str)
                        and isinstance(cookie_value, str)
                        and _valid_cookie_pair(cookie_name, cookie_value)
                    ):
                        response_cookies[cookie_name] = cookie_value
                status_code = response.status_code
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
        except RedNoteProtocolError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError):
            raise RedNoteProtocolError(FailureKind.NETWORK, "HTTP request") from None
        except httpx.HTTPError:
            raise RedNoteProtocolError(FailureKind.NETWORK, "HTTP transport") from None
        finally:
            # This client uses the explicitly constructed Cookie header only.
            self._client.cookies.clear()

        try:
            decoded = json.loads(retained)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RedNoteProtocolError(FailureKind.SCHEMA, "JSON response") from None
        return TransportResponse(
            status_code=status_code,
            body=decoded,
            cookies=response_cookies,
            retry_after=retry_after,
        )

    def close(self) -> None:
        self._client.cookies.clear()
        self._client.close()


def _parse_retry_after(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 128 or "\r" in text or "\n" in text:
        return None
    if text.isascii() and text.isdecimal():
        seconds = int(text)
    else:
        try:
            parsed = parsedate_to_datetime(text)
            if parsed.tzinfo is None:
                return None
            seconds = max(
                0,
                math.ceil(
                    (parsed.astimezone(UTC) - datetime.now(UTC)).total_seconds()
                ),
            )
        except (OverflowError, TypeError, ValueError):
            return None
    return min(seconds, _MAX_RETRY_AFTER_SECONDS)


def _valid_cookie_pair(name: Any, value: Any) -> bool:
    if not isinstance(name, str) or not isinstance(value, str):
        return False
    return bool(
        _COOKIE_NAME_RE.fullmatch(name)
        and 0 < len(name) <= 256
        and len(value.encode("utf-8")) <= 4096
        and ";" not in value
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _parse_cookie_input(value: str | Mapping[str, Any] | None) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        pairs = [(str(name), str(content)) for name, content in value.items()]
    else:
        raw = str(value).strip()
        if raw[:7].casefold() == "cookie:":
            raw = raw[7:].strip()
        pairs = []
        for part in raw.split(";"):
            item = part.strip()
            if not item:
                continue
            name, separator, content = item.partition("=")
            if not separator:
                raise ValueError("Cookie format is invalid")
            pairs.append((name.strip(), content.strip()))
    if len(pairs) > _MAX_COOKIE_COUNT:
        raise ValueError("Cookie count exceeds the local limit")
    result: dict[str, str] = {}
    for name, content in pairs:
        if name in result or not _valid_cookie_pair(name, content):
            raise ValueError("Cookie format is invalid")
        result[name] = content
    if len(_cookie_header(result).encode("utf-8")) > _MAX_COOKIE_BYTES:
        raise ValueError("Cookie size exceeds the local limit")
    return result


def _cookie_header(cookies: Mapping[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def _validate_token(value: Any, label: str, *, minimum: int = 1, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise RedNoteProtocolError(FailureKind.SCHEMA, label)
    if any(ord(character) < 0x21 or ord(character) == 0x7F for character in value):
        raise RedNoteProtocolError(FailureKind.SCHEMA, label)
    return value


def _validate_qr_url(value: Any) -> str:
    text = _validate_token(value, "QR URL", maximum=4096)
    try:
        parsed = urlsplit(text)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == "www.xiaohongshu.com"
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        valid = False
    if not valid:
        raise RedNoteProtocolError(FailureKind.SCHEMA, "QR URL")
    return text


def _validate_query_component(
    value: Any,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not value and not allow_empty):
        raise RedNoteProtocolError(FailureKind.SCHEMA, label)
    if any(
        character in "&#?" or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    ):
        raise RedNoteProtocolError(FailureKind.SCHEMA, label)
    return value


def _validate_request_target(origin: str, request_path: Any, path: str) -> str:
    if (
        not isinstance(request_path, str)
        or len(request_path) > 8192
        or "\r" in request_path
        or "\n" in request_path
    ):
        raise RedNoteProtocolError(FailureKind.SIGNER, "signed request path")
    try:
        relative = urlsplit(request_path)
        expected_origin = urlsplit(origin)
        absolute = urlsplit(origin + request_path)
        valid = (
            not relative.scheme
            and not relative.netloc
            and not relative.fragment
            and relative.path == path
            and expected_origin.scheme == "https"
            and expected_origin.hostname is not None
            and expected_origin.port is None
            and absolute.scheme == expected_origin.scheme
            and absolute.netloc == expected_origin.netloc
            and absolute.hostname == expected_origin.hostname
            and absolute.port is None
            and absolute.username is None
            and absolute.password is None
            and absolute.path == path
            and absolute.query == relative.query
            and not absolute.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        raise RedNoteProtocolError(FailureKind.SIGNER, "signed request path") from None
    return origin + request_path


class RedNoteClient:
    """Stateful client for one visitor or authenticated local session."""

    def __init__(
        self,
        cookie: str | Mapping[str, Any] | None = None,
        *,
        transport: JsonTransport | None = None,
        signer: RequestSigner | None = None,
    ) -> None:
        self._signer = signer or XhshowSigner()
        self._transport = transport or HttpxJsonTransport()
        self._cookies = _parse_cookie_input(cookie)
        if cookie is None:
            try:
                a1 = _validate_token(
                    self._signer.generate_a1(),
                    "visitor a1",
                    minimum=52,
                    maximum=52,
                )
                web_id = _validate_token(
                    self._signer.generate_web_id(a1),
                    "visitor webId",
                    minimum=32,
                    maximum=32,
                )
            except RedNoteProtocolError:
                raise
            except Exception:
                raise RedNoteProtocolError(
                    FailureKind.SIGNER, "visitor identity"
                ) from None
            self._cookies.update({"a1": a1, "webId": web_id})
        if not self._cookies.get("a1") or (
            cookie is not None and not self._cookies.get("web_session")
        ):
            raise ValueError("Cookie must include non-empty a1 and web_session")
        self._closed = False
        self._lock = threading.RLock()

    @classmethod
    def visitor(
        cls,
        *,
        transport: JsonTransport | None = None,
        signer: RequestSigner | None = None,
    ) -> RedNoteClient:
        return cls(None, transport=transport, signer=signer)

    @property
    def cookies(self) -> Mapping[str, str]:
        with self._lock:
            return CookieView(self._cookies)

    def cookie_header(self) -> str:
        with self._lock:
            self._require_open()
            return _cookie_header(self._cookies)

    def __repr__(self) -> str:
        return f"RedNoteClient(closed={self._closed}, cookies=<redacted>)"

    def _require_open(self) -> None:
        if self._closed:
            raise RedNoteProtocolError(FailureKind.UNSUPPORTED, "closed client")

    def _merge_cookies(self, values: Mapping[str, str]) -> None:
        previous = dict(self._cookies)
        for name, value in values.items():
            if _valid_cookie_pair(name, value):
                self._cookies[name] = value
        if len(self._cookies) > _MAX_COOKIE_COUNT or len(
            _cookie_header(self._cookies).encode("utf-8")
        ) > _MAX_COOKIE_BYTES:
            self._cookies.clear()
            self._cookies.update(previous)
            raise RedNoteProtocolError(FailureKind.SCHEMA, "response cookies")

    @staticmethod
    def _classify_response(response: TransportResponse, operation: str) -> None:
        status = response.status_code
        if status == 429:
            raise RedNoteProtocolError(
                FailureKind.RATE_LIMIT,
                operation,
                status_code=status,
                retry_after=response.retry_after,
            )
        if status in {401, 403}:
            raise RedNoteProtocolError(
                FailureKind.AUTH,
                operation,
                status_code=status,
                retry_after=response.retry_after,
            )
        if status in {406, 461, 471}:
            raise RedNoteProtocolError(
                FailureKind.RISK_CONTROL,
                operation,
                status_code=status,
                retry_after=response.retry_after,
            )
        if status >= 500:
            raise RedNoteProtocolError(
                FailureKind.NETWORK,
                operation,
                status_code=status,
                retry_after=response.retry_after,
            )
        if status < 200 or status >= 300:
            raise RedNoteProtocolError(
                FailureKind.SCHEMA,
                operation,
                status_code=status,
                retry_after=response.retry_after,
            )

    @staticmethod
    def _upstream_failure(
        body: Mapping[str, Any], operation: str, retry_after: int | None
    ) -> RedNoteProtocolError:
        code = body.get("code")
        if code == -100:
            kind = FailureKind.AUTH
        elif code in {300012, 300015}:
            kind = FailureKind.RISK_CONTROL
        elif code == 429:
            kind = FailureKind.RATE_LIMIT
        else:
            kind = FailureKind.SCHEMA
        safe_code = code if type(code) is int else None
        return RedNoteProtocolError(
            kind,
            operation,
            upstream_code=safe_code,
            retry_after=retry_after,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
        sign_format: Literal["xys", "xyw"] = "xys",
        user_id: str | None = None,
        x_rap: bool = False,
        extra_headers: Mapping[str, str] | None = None,
        operation: str,
    ) -> Mapping[str, Any]:
        method = method.upper()
        endpoint = _ENDPOINTS.get((method, path))
        if endpoint is None:
            raise RedNoteProtocolError(FailureKind.UNSUPPORTED, "endpoint allowlist")
        origin, max_response_bytes = endpoint
        if method == "GET" and payload is not None:
            raise RedNoteProtocolError(FailureKind.UNSUPPORTED, "GET payload")
        if method == "POST" and params is not None:
            raise RedNoteProtocolError(FailureKind.UNSUPPORTED, "POST params")
        with self._lock:
            self._require_open()
            request_params = dict(params or {})
            request_payload = dict(payload or {})
            try:
                if method == "GET":
                    signed = self._signer.sign_get(
                        path,
                        self._cookies,
                        request_params,
                        sign_format=sign_format,
                        user_id=user_id,
                        x_rap=x_rap,
                    )
                    request_path = self._signer.build_url(path, request_params)
                    request_body = None
                else:
                    signed = self._signer.sign_post(
                        path,
                        self._cookies,
                        request_payload,
                        sign_format=sign_format,
                        user_id=user_id,
                        x_rap=x_rap,
                    )
                    request_path = path
                    request_body = json.dumps(
                        request_payload,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
            except RedNoteProtocolError:
                raise
            except Exception:
                raise RedNoteProtocolError(FailureKind.SIGNER, operation) from None

            if not isinstance(signed, Mapping):
                raise RedNoteProtocolError(FailureKind.SIGNER, "signed headers")
            target_url = _validate_request_target(origin, request_path, path)

            signed_headers: dict[str, str] = {}
            for raw_name, raw_value in signed.items():
                if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                    raise RedNoteProtocolError(FailureKind.SIGNER, "signed headers")
                name = raw_name.casefold()
                value = raw_value
                if (
                    name not in _SAFE_SIGNED_HEADERS
                    or not value
                    or len(value) > 32 * 1024
                    or "\r" in value
                    or "\n" in value
                ):
                    raise RedNoteProtocolError(FailureKind.SIGNER, "signed headers")
                signed_headers[name] = value
            user_agent = self._signer.user_agent
            if (
                not isinstance(user_agent, str)
                or not user_agent
                or len(user_agent) > 1024
                or "\r" in user_agent
                or "\n" in user_agent
            ):
                raise RedNoteProtocolError(FailureKind.SIGNER, "signer user agent")
            headers = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                "content-type": "application/json;charset=UTF-8",
                "origin": WEB_ORIGIN,
                "referer": WEB_ORIGIN + "/explore",
                "user-agent": user_agent,
                "cookie": _cookie_header(self._cookies),
                "xsecappid": "xhs-pc-web",
                **signed_headers,
            }
            for name, value in (extra_headers or {}).items():
                normalized = name.casefold()
                if normalized not in {"service-tag", "x-login-mode"}:
                    raise RedNoteProtocolError(FailureKind.UNSUPPORTED, "extra header")
                if "\r" in value or "\n" in value or len(value) > 256:
                    raise RedNoteProtocolError(FailureKind.SCHEMA, "extra header")
                headers[normalized] = value
            try:
                response = self._transport.request_json(
                    method,
                    target_url,
                    headers=headers,
                    body=request_body,
                    max_response_bytes=max_response_bytes,
                )
            except RedNoteProtocolError:
                raise
            except Exception:
                raise RedNoteProtocolError(FailureKind.NETWORK, operation) from None
            self._classify_response(response, operation)
            if not isinstance(response.body, Mapping):
                raise RedNoteProtocolError(FailureKind.SCHEMA, operation)
            success = response.body.get("success")
            if success is not True:
                raise self._upstream_failure(
                    response.body, operation, response.retry_after
                )
            data = response.body.get("data")
            if not isinstance(data, Mapping):
                raise RedNoteProtocolError(FailureKind.SCHEMA, operation)
            self._merge_cookies(response.cookies)
            return dict(data)

    def login_activate(self) -> Mapping[str, Any]:
        data = self._request(
            "POST",
            "/api/sns/web/v1/login/activate",
            payload={},
            operation="login activate",
        )
        session = data.get("session")
        if session:
            self._cookies["web_session"] = _validate_token(
                session, "visitor session", minimum=8
            )
        if not self._cookies.get("web_session"):
            raise RedNoteProtocolError(FailureKind.SCHEMA, "visitor session")
        return data

    def create_qr(self) -> Mapping[str, Any]:
        data = self._request(
            "POST",
            "/api/sns/web/v1/login/qrcode/create",
            payload={"qr_type": 1},
            operation="QR create",
        )
        return {
            "qr_id": _validate_token(data.get("qr_id"), "QR id", maximum=512),
            "code": _validate_token(data.get("code"), "QR code", maximum=512),
            "url": _validate_qr_url(data.get("url")),
        }

    def poll_qr(self, qr_id: str, code: str) -> Mapping[str, Any]:
        identifier = _validate_token(qr_id, "QR id", maximum=512)
        check_code = _validate_token(code, "QR code", maximum=512)
        data = self._request(
            "POST",
            "/api/qrcode/userinfo",
            payload={"qrId": identifier, "code": check_code},
            extra_headers={"service-tag": "webcn"},
            operation="QR poll",
        )
        status = data.get("codeStatus")
        if type(status) is not int or status not in {0, 1, 2, 3}:
            raise RedNoteProtocolError(FailureKind.SCHEMA, "QR poll status")
        return data

    def complete_qr(self, qr_id: str, code: str) -> Mapping[str, Any]:
        identifier = _validate_token(qr_id, "QR id", maximum=512)
        check_code = _validate_token(code, "QR code", maximum=512)
        visitor_session = str(self._cookies.get("web_session") or "")
        data = self._request(
            "GET",
            "/api/sns/web/v1/login/qrcode/status",
            params={"qr_id": identifier, "code": check_code},
            extra_headers={"x-login-mode": ""},
            operation="QR complete",
        )
        status = data.get("code_status")
        login_info = data.get("login_info")
        if type(status) is not int or status != 2 or not isinstance(login_info, Mapping):
            raise RedNoteProtocolError(FailureKind.SCHEMA, "QR completion status")
        formal_session = _validate_token(
            login_info.get("session"), "authenticated session", minimum=8
        )
        if formal_session == visitor_session:
            raise RedNoteProtocolError(FailureKind.SCHEMA, "authenticated session")
        self._cookies["web_session"] = formal_session
        secure_session = login_info.get("secure_session")
        if secure_session:
            self._cookies["web_session_sec"] = _validate_token(
                secure_session, "secure session", minimum=8
            )
        return data

    def get_user_me(self) -> Mapping[str, Any]:
        return self._request(
            "GET",
            "/api/sns/web/v2/user/me",
            params={},
            operation="user identity",
        )

    def new_search_id(self) -> str:
        try:
            return _validate_token(
                self._signer.new_search_id(), "search id", maximum=128
            )
        except RedNoteProtocolError:
            raise
        except Exception:
            raise RedNoteProtocolError(FailureKind.SIGNER, "search id") from None

    def search_notes(
        self, keyword: str, *, page: int, search_id: str, page_size: int = 20
    ) -> Mapping[str, Any]:
        if not self._cookies.get("web_session"):
            raise RedNoteProtocolError(FailureKind.AUTH, "note search")
        if not isinstance(keyword, str) or not keyword.strip() or len(keyword) > 256:
            raise RedNoteProtocolError(FailureKind.SCHEMA, "search keyword")
        if type(page) is not int or page < 1 or page > 10_000:
            raise RedNoteProtocolError(FailureKind.SCHEMA, "search page")
        if type(page_size) is not int or page_size < 1 or page_size > 100:
            raise RedNoteProtocolError(FailureKind.SCHEMA, "search page size")
        identifier = _validate_token(search_id, "search id", maximum=128)
        try:
            session_id = _validate_token(
                self._signer.new_search_request_id(),
                "search request id",
                maximum=128,
            )
        except RedNoteProtocolError:
            raise
        except Exception:
            raise RedNoteProtocolError(
                FailureKind.SIGNER, "search request id"
            ) from None
        payload = {
            "keyword": keyword,
            "page": page,
            "page_size": page_size,
            "search_id": identifier,
            "session_id": session_id,
            "sort": "general",
            "note_type": 0,
            "ext_flags": [],
            "geo": "",
            "image_formats": ["jpg", "webp", "avif"],
        }
        return self._request(
            "POST",
            "/api/sns/web/v2/search/notes",
            payload=payload,
            x_rap=True,
            operation="note search",
        )

    def user_notes(
        self,
        user_id: str,
        *,
        cursor: str,
        xsec_token: str,
        xsec_source: str,
    ) -> Mapping[str, Any]:
        if not self._cookies.get("web_session"):
            raise RedNoteProtocolError(FailureKind.AUTH, "user notes")
        identifier = _validate_query_component(user_id, "user id", maximum=256)
        page_cursor = _validate_query_component(
            cursor, "user cursor", maximum=4096, allow_empty=True
        )
        validated_xsec = _validate_query_component(
            xsec_token, "user access token", maximum=2048, allow_empty=True
        )
        access_source = _validate_query_component(
            xsec_source, "user access source", maximum=128
        )
        return self._request(
            "GET",
            "/api/sns/web/v1/user_posted",
            params={
                "num": 30,
                "cursor": page_cursor,
                "user_id": identifier,
                "image_formats": ["jpg", "webp", "avif"],
                "xsec_token": validated_xsec,
                "xsec_source": access_source,
            },
            sign_format="xyw",
            user_id=identifier,
            x_rap=True,
            operation="user notes",
        )

    def note_detail(
        self, note_id: str, *, xsec_token: str, xsec_source: str
    ) -> Mapping[str, Any]:
        if not self._cookies.get("web_session"):
            raise RedNoteProtocolError(FailureKind.AUTH, "note detail")
        return self._request(
            "POST",
            "/api/sns/web/v1/feed",
            payload={
                "source_note_id": note_id,
                "image_formats": ["jpg", "webp", "avif"],
                "extra": {"need_body_topic": "1"},
                "xsec_source": xsec_source,
                "xsec_token": xsec_token,
            },
            x_rap=True,
            operation="note detail",
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for name in tuple(self._cookies):
                self._cookies[name] = ""
            self._cookies.clear()
            try:
                self._transport.close()
            except Exception:
                raise RedNoteProtocolError(FailureKind.NETWORK, "client close") from None


__all__ = [
    "API_ORIGIN",
    "EXPECTED_SIGNER_VERSION",
    "CookieView",
    "FailureKind",
    "HttpxJsonTransport",
    "JsonTransport",
    "RedNoteClient",
    "RedNoteProtocolError",
    "RequestSigner",
    "SEARCH_ORIGIN",
    "TransportResponse",
    "WEB_ORIGIN",
    "XhshowSigner",
]
