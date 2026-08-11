"""Non-network runtime checks for the independent protocol client."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

from .client import EXPECTED_SIGNER_VERSION, XhshowSigner


@dataclass(frozen=True, slots=True)
class RuntimeDoctorReport:
    signer_package: str = "xhshow"
    signer_version: str | None = None
    signer_version_ok: bool = False
    signer_usable: bool = False
    pure_python: bool = True
    remote_js_detected: bool = False
    browser_required: bool = False
    node_required: bool = False
    qr_login_supported: bool = False
    issues: tuple[str, ...] = field(default_factory=tuple)

    @property
    def collection_runtime_ok(self) -> bool:
        return (
            self.signer_version_ok
            and self.signer_usable
            and self.pure_python
            and not self.remote_js_detected
            and not self.browser_required
            and not self.node_required
        )

    @property
    def cookie_import_supported(self) -> bool:
        return self.collection_runtime_ok

    def as_dict(self) -> dict[str, Any]:
        return {
            "signer_package": self.signer_package,
            "signer_version": self.signer_version,
            "expected_signer_version": EXPECTED_SIGNER_VERSION,
            "signer_version_ok": self.signer_version_ok,
            "signer_usable": self.signer_usable,
            "pure_python": self.pure_python,
            "remote_js_detected": self.remote_js_detected,
            "browser_required": self.browser_required,
            "node_required": self.node_required,
            "qr_login_supported": self.qr_login_supported,
            "collection_runtime_ok": self.collection_runtime_ok,
            "cookie_import_supported": self.cookie_import_supported,
            "issues": list(self.issues),
        }


def runtime_doctor() -> RuntimeDoctorReport:
    issues: list[str] = []
    try:
        signer_version = metadata.version("xhshow")
    except metadata.PackageNotFoundError:
        signer_version = None
        issues.append(f"缺少固定签名依赖 xhshow=={EXPECTED_SIGNER_VERSION}。")
    signer_version_ok = signer_version == EXPECTED_SIGNER_VERSION
    if signer_version is not None and not signer_version_ok:
        issues.append(
            f"签名依赖必须为 xhshow=={EXPECTED_SIGNER_VERSION}，当前为 {signer_version}。"
        )

    signer_usable = False
    if signer_version_ok:
        try:
            signer = XhshowSigner()
            a1 = signer.generate_a1()
            web_id = signer.generate_web_id(a1)
            headers = signer.sign_get(
                "/api/sns/web/v2/user/me",
                {"a1": a1, "webId": web_id},
                {},
                sign_format="xys",
                user_id=None,
                x_rap=False,
            )
            signer_usable = bool(headers.get("x-s") and headers.get("x-s-common"))
        except Exception:
            issues.append("固定签名依赖无法完成本地自检。")
    if signer_version_ok and not signer_usable and not issues:
        issues.append("固定签名依赖未返回完整签名头。")

    return RuntimeDoctorReport(
        signer_version=signer_version,
        signer_version_ok=signer_version_ok,
        signer_usable=signer_usable,
        qr_login_supported=bool(signer_version_ok and signer_usable),
        issues=tuple(issues),
    )


__all__ = ["RuntimeDoctorReport", "runtime_doctor"]
