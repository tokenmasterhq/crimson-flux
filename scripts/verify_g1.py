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
POLICY_VERSION = "crimsonflux-g1-v7-isolated-visible-browser"
EVIDENCE_SCHEMA = "https://crimsonflux.local/schemas/g1-evidence-v7.json"


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


def _browser_login_check(root: Path) -> dict[str, Any]:
    browser_path = root / "src" / "xhs_insight" / "browser_login.py"
    adapter_path = root / "src" / "xhs_insight" / "adapters" / "rednote" / "live.py"
    if not browser_path.is_file() or not adapter_path.is_file():
        return {
            "name": "isolated_visible_browser_login_contract",
            "passed": False,
            "detail": "browser login or adapter module missing",
        }
    browser = browser_path.read_bytes()
    adapter = adapter_path.read_bytes()
    lowered = browser.lower()
    login_url = b'https://www.xiaohongshu.com/explore'
    cookie_source = b'https://edith.xiaohongshu.com/api/sns/web/v2/user/me'
    required = {
        "canonical_manager": b"class IsolatedBrowserLoginManager" in browser,
        "official_login_url": login_url in browser,
        "fixed_cookie_scope": cookie_source in browser,
        "executable_allowlist": (
            b"def _browser_candidates(" in browser
            and b"def find_supported_browser(" in browser
        ),
        "isolated_profile": b"tempfile.mkdtemp(" in browser and b"--user-data-dir=" in browser,
        "profile_mode_0700": b"0o700" in browser and b"chmod(" in browser,
        "loopback_random_cdp": (
            b"--remote-debugging-address=127.0.0.1" in browser
            and b"--remote-debugging-port=0" in browser
            and b"DevToolsActivePort" in browser
        ),
        "fixed_launch_flags": all(
            flag in browser
            for flag in (
                b"--no-first-run",
                b"--no-default-browser-check",
                b"--disable-sync",
                b"--disable-extensions",
                b"--new-window",
            )
        ),
        "no_shell": b"shell=True" not in browser and b"os.system(" not in browser,
        "no_unsafe_flags": (
            b"--no-sandbox" not in browser
            and b"--disable-web-security" not in browser
            and b"--remote-allow-origins=*" not in browser
        ),
        "minimal_cdp": (
            b"Target.getTargets" in browser
            and b"Target.attachToTarget" in browser
            and b"Network.getCookies" in browser
        ),
        "network_domain_not_enabled": b"Network.enable" not in browser,
        "no_page_execution_or_content": not any(
            marker in lowered
            for marker in (
                b"runtime.evaluate",
                b"runtime.callfunctionon",
                b"getresponsebody",
                b"localstorage",
                b"sessionstorage",
                b"storage.getcookies",
                b"network.getallcookies",
            )
        ),
        "url_scoped_cookie_query": b'"urls": [COOKIE_SOURCE_URL]' in browser,
        "required_cookie_pair": b'"a1"' in browser and b'"web_session"' in browser,
        "verified_before_persist": (
            b"data = candidate.get_user_me()" in adapter
            and b"if guest is not False:" in adapter
            and b"account_id = str(data.get(" in adapter
        ),
        "terminal_cleanup": (
            b"terminate(" in browser
            and b"kill(" in browser
            and b"shutil.rmtree(" in browser
            and b"finally:" in browser
        ),
        "no_dynamic_import": (
            b"importlib.import_module" not in browser and b"__import__(" not in browser
        ),
    }
    return {
        "name": "isolated_visible_browser_login_contract",
        "passed": all(required.values()),
        "detail": required,
    }


def _browser_api_check(root: Path) -> dict[str, Any]:
    router = (root / "src" / "xhs_insight" / "api" / "router.py").read_bytes()
    app = (root / "src" / "xhs_insight" / "api" / "app.py").read_bytes()
    status_start = router.find(b'    @router.get("/auth/browser/status")')
    status_end = router.find(b"\n    @router.", status_start + 1)
    status_body = (
        router[status_start:status_end]
        if status_start >= 0 and status_end > status_start
        else b""
    )
    markers = {
        "start_route": b'@router.post("/auth/browser"' in router,
        "status_route": b'@router.get("/auth/browser/status")' in router,
        "cancel_route": b'@router.delete("/auth/browser")' in router,
        "embedded_qr_fixed_disabled": (
            b'@router.get("/auth/browser/qr")' in router
            and b'"EMBEDDED_QR_DISABLED"' in router
            and b"status_code=410" in router
        ),
        "status_delegates_public_state": (
            b"return manager.status()" in status_body and b'"cookie"' not in status_body
        ),
        "local_session_or_cli_auth": (
            b'request.cookies.get("xhs_session")' in app
            and b'request.headers.get("x-xhs-local-token")' in app
        ),
        "host_and_origin_guard": (
            b"host not in SAFE_HOSTS" in app and b"_origin_is_local(origin, request_port)" in app
        ),
    }
    return {"name": "isolated_browser_local_api_contract", "passed": all(markers.values()), "detail": markers}


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
        _browser_login_check(root),
        _browser_api_check(root),
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
            "browser_login_control": "fixed-argv-loopback-random-cdp",
            "collection_json_response_bytes": 4 * 1024 * 1024,
            "browser_login_cookie_scope": "https://edith.xiaohongshu.com/api/sns/web/v2/user/me",
            "browser_login_profile": "temporary-isolated-delete-on-terminal-state",
        },
        "checks": checks,
        "result": "passed" if all(item["passed"] for item in checks) else "failed",
        "human_approval_still_required": [
            "independent source-provenance and data-flow review",
            "real low-frequency isolated browser login -> /user/me nonguest -> collection smoke",
            "manual confirmation that remote program text is never executed, saved, or logged",
            "manual confirmation that browser/CDP/profile resources are removed on every terminal path",
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
