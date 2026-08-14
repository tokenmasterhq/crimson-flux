from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from scan_release import _scan_payload, scan_g1_tree, scan_git_history  # noqa: E402
from verify_g1 import _browser_login_check  # noqa: E402

_RETIRED_ROOT = "third" + "_party"
_RETIRED_PROJECT = "Spider" + "_XHS"
_RETIRED_IMPORT = "xhs_" + "utils.xhs_pc"
_RETIRED_PATH = _RETIRED_ROOT + "/spider_" + "xhs"
_RETIRED_COMMIT = "2030f5d4454e556ad7a9" + "caa83b3ec532d4df20c7"
_HOST_SAFE_DELETE_KEY = "CODE" + "BUDDY_SAFE_DELETE_ROOT"


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


def test_canonical_browser_module_may_contain_reviewed_cdp_transport() -> None:
    marker = "--remote-" + "debugging-port=0"
    source = f"FLAG = {marker!r}\n".encode()

    findings = _scan_payload(PurePosixPath("src/xhs_insight/browser_login.py"), source)

    assert not any("browser automation or debugging transport marker" in finding.reason for finding in findings)


def test_canonical_browser_module_rejects_environment_selected_profile_root() -> None:
    source = (
        b"from pathlib import Path\nimport tempfile\n"
        b"root = _create_owned_profile_root_at(Path(tempfile.gettempdir()))\n"
    )

    findings = _scan_payload(
        PurePosixPath("src/xhs_insight/browser_login.py"), source
    )

    assert any("environment-selected tempfile path" in item.reason for item in findings)


@pytest.mark.parametrize(
    "marker",
    [
        "Runtime." + "evaluate",
        "Network." + "enable",
        "Network." + "getResponseBody",
        "Fetch." + "getResponseBody",
        "Storage." + "getCookies",
        "Network." + "getAllCookies",
        "local" + "Storage",
        "session" + "Storage",
        "--no-" + "sandbox",
        "--disable-" + "web-security",
        "--remote-allow-origins=" + "*",
        '"/IM"',
    ],
)
def test_canonical_browser_module_rejects_expanded_capabilities(marker: str) -> None:
    findings = _scan_payload(
        PurePosixPath("src/xhs_insight/browser_login.py"),
        f"MARKER = {marker!r}\n".encode(),
    )

    assert any(
        finding.reason == "unsafe browser or CDP capability in canonical login module"
        for finding in findings
    )


def test_canonical_browser_module_rejects_shell_launch() -> None:
    source = b"import subprocess\nsubprocess.Popen(['browser'], shell=True)\n"

    findings = _scan_payload(PurePosixPath("src/xhs_insight/browser_login.py"), source)

    assert any("subprocess shell" in finding.reason for finding in findings)


@pytest.mark.parametrize(
    "source, reason",
    [
        (
            b"import tempfile\ntempfile.tempdir = '/chosen/root'\n",
            "canonical browser login overrides the system temp root",
        ),
        (
            b"import tempfile\ntempfile.mkdtemp(prefix='profile-', dir=state_dir)\n",
            "browser profile is allocated under persistent state",
        ),
        (
            b"from pathlib import Path\nlist(Path('/tmp').glob('profile-*'))\n",
            "canonical browser cleanup uses broad path enumeration",
        ),
        (
            b"import glob\nglob.glob('/tmp/profile-*')\n",
            "canonical browser cleanup uses broad path enumeration",
        ),
        (
            b"import subprocess\nsubprocess.run(['rm', '-rf', target], shell=False, "
            b"stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            b"stderr=subprocess.DEVNULL, timeout=12)\n",
            "canonical browser cleanup invokes an external delete helper",
        ),
    ],
)
def test_canonical_browser_module_rejects_unsafe_profile_cleanup_patterns(
    source: bytes,
    reason: str,
) -> None:
    findings = _scan_payload(PurePosixPath("src/xhs_insight/browser_login.py"), source)

    assert any(item.reason == reason for item in findings)


@pytest.mark.parametrize(
    "statement",
    [
        "os.environ.pop({key!r}, None)",
        "os.unsetenv({key!r})",
        "del os.environ[{key!r}]",
        "child_env.pop({key!r}, None)",
        "os.getenv({key!r})",
        "os.environ[{key!r}]",
        "probe = {key!r}",
    ],
)
def test_product_code_cannot_reference_host_safe_delete_controls(statement: str) -> None:
    source = ("import os\n" + statement.format(key=_HOST_SAFE_DELETE_KEY) + "\n").encode()

    findings = _scan_payload(PurePosixPath("src/xhs_insight/probe.py"), source)

    assert any(
        item.reason == "product code references or mutates host safe-delete controls"
        for item in findings
    )


def test_non_python_product_code_cannot_bypass_host_safe_delete_controls() -> None:
    source = f"delete process.env.{_HOST_SAFE_DELETE_KEY};\n".encode()

    findings = _scan_payload(
        PurePosixPath("src/xhs_insight/web/static/probe.js"), source
    )

    assert any(
        item.reason == "product code references or mutates host safe-delete controls"
        for item in findings
    )


@pytest.mark.parametrize(
    "source",
    [
        b"import os\nroot = os.environ.get('PROGRAMFILES')\n",
        b"import os\nroot = os.getenv('LOCALAPPDATA')\n",
        b"import os\nroot = os.environ['PROGRAMFILES(X86)']\n",
        b"import shutil\nexecutable = shutil.which('chrome')\n",
        b"import os\npaths = os.get_exec_path()\n",
        b"import os\npath = os.path.expandvars(r'%PROGRAMFILES%\\Chrome')\n",
    ],
)
def test_canonical_browser_module_rejects_environment_executable_roots(
    source: bytes,
) -> None:
    findings = _scan_payload(PurePosixPath("src/xhs_insight/browser_login.py"), source)

    assert any(
        item.reason
        == "canonical browser executable discovery uses environment or PATH input"
        for item in findings
    )


def test_canonical_browser_module_requires_explicit_shell_false_and_bounded_helper_io() -> None:
    missing_shell = b"import subprocess\nsubprocess.Popen(['browser'])\n"
    unbounded_helper = (
        b"import subprocess\n"
        b"subprocess.run(['helper'], shell=False, stdin=None, stdout=None, "
        b"stderr=None, timeout=12)\n"
    )

    findings = _scan_payload(PurePosixPath("src/xhs_insight/browser_login.py"), missing_shell)
    assert any("explicitly disable subprocess shell" in item.reason for item in findings)

    findings = _scan_payload(PurePosixPath("src/xhs_insight/browser_login.py"), unbounded_helper)
    assert any("bounded redacted I/O" in item.reason for item in findings)


def test_browser_login_g1_contract_requires_isolation_scope_verification_and_cleanup(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "xhs_insight"
    adapter_dir = package / "adapters" / "rednote"
    adapter_dir.mkdir(parents=True)
    api_dir = package / "api"
    api_dir.mkdir(parents=True)
    browser = package / "browser_login.py"
    adapter = adapter_dir / "live.py"
    app = api_dir / "app.py"
    shutil.copyfile(ROOT / "src" / "xhs_insight" / "browser_login.py", browser)
    shutil.copyfile(ROOT / "src" / "xhs_insight" / "adapters" / "rednote" / "live.py", adapter)
    shutil.copyfile(ROOT / "src" / "xhs_insight" / "api" / "app.py", app)

    detail = _browser_login_check(tmp_path)["detail"]
    assert all(detail.values()), detail

    for path in (browser, adapter, app):
        normalized = path.read_bytes().replace(b"\r\n", b"\n")
        path.write_bytes(normalized.replace(b"\n", b"\r\n"))
    crlf_detail = _browser_login_check(tmp_path)["detail"]
    assert all(crlf_detail.values()), crlf_detail

    browser_source = browser.read_text(encoding="utf-8")
    app_source = app.read_text(encoding="utf-8")

    def changed(source: str, needle: str, replacement: str) -> str:
        assert needle in source
        return source.replace(needle, replacement, 1)

    browser.write_text(
        changed(
            browser_source,
            '{"urls": [COOKIE_SOURCE_URL]}', '{"urls": [user_input]}'
        ),
        encoding="utf-8",
    )
    assert _browser_login_check(tmp_path)["detail"]["url_scoped_cookie_query"] is False
    browser.write_text(browser_source, encoding="utf-8")

    app.write_text(
        changed(
            app_source,
            "candidate_guard = before_persist()",
            "candidate_guard = None",
        ),
        encoding="utf-8",
    )
    assert _browser_login_check(tmp_path)["detail"]["cleanup_barrier_before_persist"] is False
    app.write_text(app_source, encoding="utf-8")

    browser.write_text(
        changed(
            browser_source,
            "get_known_folder = shell32.SHGetKnownFolderPath",
            "get_known_folder = os.environ.get('PROGRAMFILES')",
        ),
        encoding="utf-8",
    )
    assert _browser_login_check(tmp_path)["detail"]["windows_known_folder_roots"] is False
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(browser_source, "            self._session.committed = True\n", ""),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["cancel_and_deadline_guard_persist"]
        is False
    )
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(
            browser_source,
            "_create_owned_profile_root_at(_trusted_profile_temp_parent())",
            "_create_owned_profile_root_at(state_dir)",
        ),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["system_temp_dedicated_profile_root"]
        is False
    )
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(
            browser_source,
            "return _windows_trusted_temp_parent()",
            "return Path(tempfile.gettempdir())",
        ),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["system_temp_dedicated_profile_root"]
        is False
    )
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(
            browser_source,
            "create_directory = kernel32.CreateDirectoryW",
            "create_directory = kernel32.CreateDirectoryA",
        ),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["windows_private_profile_dacl"]
        is False
    )
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(
            browser_source,
            "create_file = kernel32.CreateFileW",
            "create_file = lambda *_args: write_private_file(*_args)",
        ),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["windows_private_profile_dacl"]
        is False
    )
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(
            browser_source,
            "    return None\n\n\ndef _terminate_browser_process",
            '    return Path("C:/Windows/System32/taskkill.exe")\n\n\ndef _terminate_browser_process',
        ),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["windows_owned_process_tree_only"]
        is False
    )
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(browser_source, "def _validate_profile(", "def unsafe_profile_check("),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["profile_owner_and_link_validation"]
        is False
    )
    browser.write_text(browser_source, encoding="utf-8")

    browser.write_text(
        changed(
            browser_source,
            "shutil.rmtree(profile.path)",
            "shutil.rmtree(profile.root.path)",
        ),
        encoding="utf-8",
    )
    assert (
        _browser_login_check(tmp_path)["detail"]["exact_fail_closed_profile_cleanup"]
        is False
    )


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
