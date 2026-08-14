from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from xhs_insight.config import Settings
from xhs_insight.platform import doctor


class _Signer:
    def generate_a1(self) -> str:
        return "a" * 52

    def generate_web_id(self, _a1: str) -> str:
        return "b" * 32

    def sign_get(self, *_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {"x-s": "signed", "x-s-common": "common"}


def test_runtime_doctor_accepts_only_the_exact_audited_signer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor.metadata, "version", lambda _name: "0.2.0")
    monkeypatch.setattr(doctor, "XhshowSigner", _Signer)

    report = doctor.runtime_doctor()

    assert report.signer_package == "xhshow"
    assert report.signer_version_ok is True
    assert report.collection_runtime_ok is True
    assert report.qr_login_supported is True
    assert report.browser_required is False
    assert report.node_required is False


def test_runtime_doctor_fails_closed_on_signer_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor.metadata, "version", lambda _name: "0.2.1")

    report = doctor.runtime_doctor()

    assert report.signer_version_ok is False
    assert report.collection_runtime_ok is False
    assert report.qr_login_supported is False
    assert report.issues


def test_cli_host_override_cannot_bypass_native_loopback_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XHS_INSIGHT_ALLOW_CONTAINER_BIND", raising=False)
    monkeypatch.setenv("XHS_INSIGHT_HOST", "127.0.0.1")
    settings = Settings.from_env()

    with pytest.raises(ValueError, match="hardened container"):
        replace(settings, host="0.0.0.0")

    with pytest.raises(ValueError, match="local bind address"):
        replace(settings, host="192.0.2.10")


def test_environment_cannot_reduce_request_pause_below_two_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRIMSONFLUX_REQUEST_PAUSE_MIN", "1.99")
    monkeypatch.setenv("CRIMSONFLUX_REQUEST_PAUSE_MAX", "4")

    with pytest.raises(ValueError, match="at least 2 seconds"):
        Settings.from_env()

    # Direct construction remains available for deterministic offline fixtures.
    direct = Settings(
        host="127.0.0.1",
        port=8765,
        state_dir=Path("state"),
        export_dir=Path("exports"),
        max_keyword_items=10,
        max_user_items=10,
        pause_min_seconds=0,
        pause_max_seconds=0,
        open_browser=False,
    )
    assert direct.pause_min_seconds == 0


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_environment_rejects_non_finite_request_pause(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRIMSONFLUX_REQUEST_PAUSE_MIN", value)
    monkeypatch.setenv("CRIMSONFLUX_REQUEST_PAUSE_MAX", "4")

    with pytest.raises(ValueError, match="at least 2 seconds"):
        Settings.from_env()


def test_environment_caps_lifecycle_retry_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CRIMSONFLUX_MAX_JOB_RETRIES", "21")

    with pytest.raises(ValueError, match="must be <= 20"):
        Settings.from_env()
