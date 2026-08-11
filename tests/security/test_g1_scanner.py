from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from scan_release import _scan_payload, scan_g1_tree, scan_git_history  # noqa: E402

_RETIRED_ROOT = "third" + "_party"
_RETIRED_PROJECT = "Spider" + "_XHS"
_RETIRED_IMPORT = "xhs_" + "utils.xhs_pc"
_RETIRED_PATH = _RETIRED_ROOT + "/spider_" + "xhs"
_RETIRED_COMMIT = "2030f5d4454e556ad7a9" + "caa83b3ec532d4df20c7"


@pytest.mark.parametrize(
    "program",
    [
        b"ev" + b"al(remoteProgram)",
        b"new " + b"Function(remoteProgram)()",
        b"globalThis['ev" + b"al'](remoteProgram)",
        b"vm.runInNewContext(remoteProgram)",
        b"module._compile(remoteProgram, 'remote.js')",
        b"value.constructor.constructor(remoteProgram)()",
    ],
)
def test_dynamic_javascript_variants_are_rejected(program: bytes) -> None:
    findings = _scan_payload(PurePosixPath("src/probe.js"), program)

    assert any(finding.reason == "dynamic JavaScript execution primitive" for finding in findings)


@pytest.mark.parametrize("call", ["ev" + "al", "ex" + "ec", "com" + "pile"])
def test_dynamic_python_variants_are_rejected(call: str) -> None:
    program = f"def run(value):\n    return {call}(value)\n".encode()

    findings = _scan_payload(PurePosixPath("src/xhs_insight/probe.py"), program)

    assert any("dynamic Python execution primitive" in finding.reason for finding in findings)


@pytest.mark.parametrize(
    "module",
    ["exec" + "js", "play" + "wright", "sele" + "nium", "py" + "ppeteer"],
)
def test_dynamic_bridge_imports_are_rejected(module: str) -> None:
    findings = _scan_payload(
        PurePosixPath("src/xhs_insight/probe.py"), f"import {module}\n".encode()
    )

    assert any("dynamic code bridge import" in finding.reason for finding in findings)


def test_browser_automation_transport_is_rejected() -> None:
    marker = "--remote-" + "debugging-port=0"
    source = f"FLAG = {marker!r}\n".encode()

    findings = _scan_payload(PurePosixPath("src/xhs_insight/probe.py"), source)

    assert any("browser automation or debugging transport marker" in finding.reason for finding in findings)


def test_direct_qr_module_cannot_spawn_processes() -> None:
    source = b"import sub" + b"process\n"

    findings = _scan_payload(PurePosixPath("src/xhs_insight/browser_login.py"), source)

    assert any("direct QR module may not spawn processes" in finding.reason for finding in findings)


def test_full_tree_scan_rejects_non_release_dynamic_js(tmp_path: Path) -> None:
    hidden = tmp_path / "internal" / "legacy.js"
    hidden.parent.mkdir(parents=True)
    hidden.write_bytes(b"ev" + b"al(serverResponse);\n")

    findings = scan_g1_tree(tmp_path)

    assert any(finding.path == "internal/legacy.js" for finding in findings)


def test_full_tree_scan_rejects_retired_vendor_directory(tmp_path: Path) -> None:
    retired = tmp_path / _RETIRED_PATH / "module.py"
    retired.parent.mkdir(parents=True)
    retired.write_text("VALUE = 1\n", encoding="utf-8")

    findings = scan_g1_tree(tmp_path)

    assert any(finding.reason == "retired vendor directory is present" for finding in findings)


def test_retired_source_markers_are_rejected() -> None:
    for marker in (_RETIRED_PROJECT, _RETIRED_IMPORT, _RETIRED_PATH, _RETIRED_COMMIT):
        findings = _scan_payload(
            PurePosixPath("src/xhs_insight/probe.py"), f"# {marker}\n".encode()
        )
        assert findings, marker


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _new_repository(path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is unavailable")
    _git(path, "init")
    _git(path, "config", "user.email", "security-test@example.invalid")
    _git(path, "config", "user.name", "Security Test")


def _commit_all(path: Path, message: str) -> None:
    _git(path, "add", "--all")
    _git(path, "commit", "-m", message)


def test_git_history_accepts_independent_source_and_allowed_disclosure(tmp_path: Path) -> None:
    _new_repository(tmp_path)
    (tmp_path / "README.md").write_text(
        f"Independent source; does not contain or depend on {_RETIRED_PROJECT}.\n",
        encoding="utf-8",
    )
    _commit_all(tmp_path, "independent source")

    assert scan_git_history(tmp_path) == []


def test_git_history_rejects_reachable_retired_vendor_path(tmp_path: Path) -> None:
    _new_repository(tmp_path)
    (tmp_path / "README.md").write_text("safe\n", encoding="utf-8")
    _commit_all(tmp_path, "initial")
    retired = tmp_path / _RETIRED_PATH / "module.py"
    retired.parent.mkdir(parents=True)
    retired.write_text("VALUE = 1\n", encoding="utf-8")
    _commit_all(tmp_path, "add old source")

    reasons = {finding.reason for finding in scan_git_history(tmp_path)}

    assert "reachable history contains a retired vendor path" in reasons


@pytest.mark.parametrize("marker", [_RETIRED_IMPORT, _RETIRED_COMMIT])
def test_git_history_rejects_reachable_retired_blob_content(
    tmp_path: Path, marker: str
) -> None:
    _new_repository(tmp_path)
    source = tmp_path / "src" / "xhs_insight" / "probe.py"
    source.parent.mkdir(parents=True)
    source.write_text(f"# {marker}\n", encoding="utf-8")
    _commit_all(tmp_path, "independent source")

    findings = scan_git_history(tmp_path)

    assert findings


def test_repository_full_tree_g1_scan_is_clean() -> None:
    assert scan_g1_tree(ROOT) == []
