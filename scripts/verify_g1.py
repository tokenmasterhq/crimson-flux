#!/usr/bin/env python3
"""Produce or verify Python-only G1 and source-provenance evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scan_release import scan_g1_tree, scan_git_history, scan_source, source_file_paths

ROOT = Path(__file__).resolve().parents[1]
POLICY_VERSION = "crimsonflux-g1-v6-independent-http"
EVIDENCE_SCHEMA = "https://crimsonflux.local/schemas/g1-evidence-v6.json"


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _run(command: list[str], *, cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _git_sha(root: Path) -> str | None:
    try:
        result = _run(["git", "rev-parse", "HEAD"], cwd=root, timeout=10)
    except OSError:
        return None
    value = result.stdout.strip().casefold()
    if result.returncode == 0 and len(value) == 40 and all(char in "0123456789abcdef" for char in value):
        return value
    return None


def _file_manifest(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in source_file_paths(root):
        payload = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": _digest(payload),
                "size": len(payload),
            }
        )
    return entries


def _tree_digest(files: list[dict[str, Any]]) -> str:
    identity = [
        {"path": item["path"], "sha256": item["sha256"], "size": item["size"]}
        for item in files
    ]
    return _digest(_canonical(identity))


def _python_only_check(root: Path) -> dict[str, Any]:
    retired_root = root / ("third" + "_party")
    inspected = (
        root / "Dockerfile",
        root / "docker-compose.yml",
        root / "scripts" / "start.py",
        root / ".github" / "workflows" / "ci.yml",
        root / ".github" / "workflows" / "release.yml",
    )
    forbidden = {
        "node_image": "FROM " + "node:",
        "package_manager": "n" + "pm ",
        "runtime_override": "CRIMSONFLUX_" + "UPSTREAM_DIR",
        "retired_path": "third" + "_party/",
    }
    observed: dict[str, list[str]] = {name: [] for name in forbidden}
    for path in inspected:
        if not path.is_file():
            observed.setdefault("missing", []).append(path.relative_to(root).as_posix())
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, marker in forbidden.items():
            if marker.casefold() in text.casefold():
                observed[name].append(path.relative_to(root).as_posix())
    observed = {name: paths for name, paths in observed.items() if paths}
    passed = not retired_root.exists() and not observed
    return {
        "name": "python_only_runtime",
        "passed": passed,
        "detail": {
            "retired_vendor_root_present": retired_root.exists(),
            "forbidden_build_markers": observed,
        },
    }


def _direct_qr_check(root: Path) -> dict[str, Any]:
    browser_path = root / "src" / "xhs_insight" / "browser_login.py"
    client_path = root / "src" / "xhs_insight" / "platform" / "client.py"
    if not browser_path.is_file() or not client_path.is_file():
        return {
            "name": "direct_http_qr_contract",
            "passed": False,
            "detail": "login or platform module missing",
        }
    browser = browser_path.read_bytes()
    client = client_path.read_bytes()
    combined = browser + b"\n" + client
    request_start = client.find(b"    def _request(")
    request_end = client.find(b"    def login_activate(", request_start)
    request_body = (
        client[request_start:request_end]
        if request_start >= 0 and request_end > request_start
        else b""
    )
    merge_index = request_body.find(b"self._merge_cookies(response.cookies)")
    classify_index = request_body.find(b"self._classify_response(response, operation)")
    run_start = browser.find(b"    def _run(")
    run_end = browser.find(b"\n\nBrowserLoginManager =", run_start)
    run_body = (
        browser[run_start:run_end]
        if run_start >= 0 and run_end > run_start
        else b""
    )
    identity_gate_index = run_body.find(b"if not _is_verified_identity(identity):")
    import_index = run_body.find(b"result = self._import_cookie(")
    required = {
        "direct_client": b"class DirectQrClient" in browser,
        "manager": b"class DirectQrLoginManager" in browser,
        "bounded_login_json": b"_MAX_LOGIN_RESPONSE_BYTES = 256 * 1024" in client,
        "bounded_collection_json": (
            b"_MAX_COLLECTION_RESPONSE_BYTES = 4 * 1024 * 1024" in client
        ),
        "response_cookies_before_classification": (
            merge_index >= 0 and classify_index > merge_index
        ),
        "verified_nonguest_identity": (
            b'return value.get("guest") is False '
            b'and bool(str(value.get("user_id") or "").strip())' in browser
        ),
        "identity_verified_before_import": (
            identity_gate_index >= 0 and import_index > identity_gate_index
        ),
        "local_png": b"qrcode.QRCode(" in browser,
        "fixed_signer_import": b"import xhshow" in client,
        "fixed_search_origin": b'SEARCH_ORIGIN = "https://so.xiaohongshu.com"' in client,
        "no_remote_program_surface": not any(
            marker in combined.lower()
            for marker in (b"scripting_code", b"websectiga", b"security_program")
        ),
        "no_browser_process": b"subprocess" not in combined,
        "no_dynamic_import": (
            b"importlib.import_module" not in combined and b"__import__(" not in combined
        ),
    }
    return {
        "name": "direct_http_qr_contract",
        "passed": all(required.values()),
        "detail": required,
    }


def _qr_api_check(root: Path) -> dict[str, Any]:
    router = (root / "src" / "xhs_insight" / "api" / "router.py").read_bytes()
    app = (root / "src" / "xhs_insight" / "api" / "app.py").read_bytes()
    markers = {
        "fixed_route": b'@router.get("/auth/browser/qr")' in router,
        "png_only": b'media_type="image/png"' in router,
        "private_no_store": b'"private, no-store, max-age=0, must-revalidate"' in router,
        "nosniff": b'"X-Content-Type-Options": "nosniff"' in router,
        "manager_bytes_only": b"image, revision = manager.qr_image()" in router,
        "local_session_or_cli_auth": (
            b'request.cookies.get("xhs_session")' in app
            and b'request.headers.get("x-xhs-local-token")' in app
        ),
        "host_and_origin_guard": (
            b"host not in SAFE_HOSTS" in app and b"_origin_is_local(origin, request_port)" in app
        ),
    }
    return {"name": "embedded_qr_local_api_contract", "passed": all(markers.values()), "detail": markers}


def _container_policy_check(root: Path) -> dict[str, Any]:
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    markers = {
        "python312": "FROM python:3.12-" in dockerfile,
        "non_root": "USER app:app" in dockerfile,
        "read_only": "read_only: true" in compose,
        "no_new_privileges": "no-new-privileges:true" in compose,
        "cap_drop_all": "cap_drop:\n      - ALL" in compose,
        "tmp_noexec": "/tmp:rw,noexec,nosuid,nodev" in compose,
        "pid_limit": "pids_limit:" in compose,
    }
    return {"name": "container_runtime_restrictions", "passed": all(markers.values()), "detail": markers}


def _static_checks(root: Path) -> list[dict[str, Any]]:
    tree_findings = scan_g1_tree(root)
    source_findings = scan_source(root)
    history_findings = scan_git_history(root)
    return [
        {
            "name": "source_provenance",
            "passed": not tree_findings and not history_findings,
            "detail": {
                "tree": [f"{item.path}: {item.reason}" for item in tree_findings],
                "history": [f"{item.path}: {item.reason}" for item in history_findings],
            },
        },
        {
            "name": "release_projection_scan",
            "passed": not source_findings,
            "detail": [f"{item.path}: {item.reason}" for item in source_findings],
        },
        _python_only_check(root),
        _direct_qr_check(root),
        _qr_api_check(root),
        _container_policy_check(root),
    ]


def _security_tests(root: Path) -> dict[str, Any]:
    command = [sys.executable, "-m", "pytest", "-q", "tests/security"]
    try:
        result = _run(command, cwd=root, timeout=180)
    except subprocess.TimeoutExpired:
        return {"name": "adversarial_security_tests", "passed": False, "detail": "timeout"}
    return {
        "name": "adversarial_security_tests",
        "passed": result.returncode == 0,
        "detail": (result.stdout or result.stderr)[-2000:],
    }


def _container_check(root: Path, image: str) -> dict[str, Any]:
    docker = shutil.which("docker")
    if not docker:
        return {"name": "built_container_parity", "passed": False, "detail": "docker not found"}
    inspect = _run(
        [docker, "image", "inspect", "--format", "{{.Id}}", image],
        cwd=root,
        timeout=30,
    )
    image_id = inspect.stdout.strip() if inspect.returncode == 0 else None
    retired = "third" + "_party"
    probe = (
        "import json,pathlib,shutil,xhs_insight;"
        f"r=pathlib.Path('/app/{retired}');"
        "print(json.dumps({'version':xhs_insight.__version__,'retired':r.exists(),"
        "'node':shutil.which('node')}))"
    )
    result = _run(
        [docker, "run", "--rm", "--entrypoint", "python", image, "-c", probe],
        cwd=root,
        timeout=120,
    )
    if result.returncode:
        return {
            "name": "built_container_parity",
            "passed": False,
            "detail": f"container probe exited {result.returncode}",
        }
    try:
        observed = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {
            "name": "built_container_parity",
            "passed": False,
            "detail": "container probe returned invalid JSON",
        }
    passed = bool(image_id) and observed.get("retired") is False and observed.get("node") is None
    return {
        "name": "built_container_parity",
        "passed": passed,
        "detail": {"image_id": image_id, **observed},
    }


def build_evidence(root: Path, *, container_image: str | None = None) -> dict[str, Any]:
    root = root.resolve()
    files = _file_manifest(root)
    checks = _static_checks(root)
    checks.append(
        {
            "name": "native_python312",
            "passed": platform.python_version_tuple()[:2] == ("3", "12"),
            "detail": platform.python_version(),
        }
    )
    checks.append(_security_tests(root))
    if container_image:
        checks.append(_container_check(root, container_image))
    evidence: dict[str, Any] = {
        "$schema": EVIDENCE_SCHEMA,
        "policy_version": POLICY_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "source": {
            "git_sha": _git_sha(root),
            "tree_sha256": _tree_digest(files),
            "files": files,
        },
        "environment": {
            "os": platform.system(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "container_image": container_image,
            "runtime": "python-only",
        },
        "limits": {
            "direct_qr_json_response_bytes": 256 * 1024,
            "collection_json_response_bytes": 4 * 1024 * 1024,
            "direct_qr_poll_seconds": 2,
            "direct_qr_timeout_seconds": 180,
            "direct_qr_transport": "authenticated-same-origin-image-png-no-store",
        },
        "checks": checks,
        "result": "passed" if all(item["passed"] for item in checks) else "failed",
        "human_approval_still_required": [
            "independent source-provenance and data-flow review",
            "real low-frequency direct QR scan -> formal session -> /user/me nonguest -> collection smoke",
            "manual confirmation that remote program text is never executed, saved, or logged",
            "manual confirmation that QR bytes are removed on every terminal path",
            "release-owner review of this evidence and private G1 approval record",
        ],
    }
    evidence["evidence_sha256"] = _digest(_canonical(evidence))
    return evidence


def _validate_evidence(root: Path, evidence: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    digest = evidence.get("evidence_sha256")
    unsigned = dict(evidence)
    unsigned.pop("evidence_sha256", None)
    if digest != _digest(_canonical(unsigned)):
        errors.append("evidence digest mismatch")
    if evidence.get("policy_version") != POLICY_VERSION:
        errors.append("policy version mismatch")
    if evidence.get("result") != "passed":
        errors.append("evidence result is not passed")
    files = _file_manifest(root.resolve())
    if evidence.get("source", {}).get("tree_sha256") != _tree_digest(files):
        errors.append("source tree digest mismatch")
    if evidence.get("source", {}).get("files") != files:
        errors.append("source file manifest mismatch")
    expected_sha = _git_sha(root)
    evidence_sha = evidence.get("source", {}).get("git_sha")
    if expected_sha and evidence_sha != expected_sha:
        errors.append("Git commit mismatch")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--container-image")
    args = parser.parse_args()
    root = args.source.expanduser().resolve()
    if args.verify:
        try:
            evidence = json.loads(args.verify.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"[FAIL] cannot read G1 evidence: {type(error).__name__}", file=sys.stderr)
            return 1
        errors = _validate_evidence(root, evidence)
        if errors:
            for error in errors:
                print(f"[FAIL] {error}", file=sys.stderr)
            return 1
        print(f"[OK] G1 evidence verified: {args.verify}")
        return 0
    evidence = build_evidence(root, container_image=args.container_image)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    for check in evidence["checks"]:
        label = "OK" if check["passed"] else "FAIL"
        print(f"[{label}] {check['name']}")
    print(f"tree_sha256={evidence['source']['tree_sha256']}")
    if evidence["result"] != "passed":
        return 1
    print(f"[OK] G1 machine evidence: {evidence['evidence_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
