#!/usr/bin/env python3
"""Scan source trees, reachable Git history, and ZIPs for release blockers."""

from __future__ import annotations

import argparse
import ast
import re
import stat
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]

ROOT_RELEASE_FILES = frozenset(
    {
        ".dockerignore",
        ".env.example",
        ".gitignore",
        ".python-version",
        "Dockerfile",
        "LICENSE",
        "README.md",
        "THIRD_PARTY_NOTICES.md",
        "docker-compose.yml",
        "pyproject.toml",
        "requirements.lock",
        "uv.lock",
    }
)
_DIRECTORY_SUFFIXES = {
    ".github": frozenset({".md", ".yml", ".yaml"}),
    "docs": frozenset({".md"}),
    "scripts": frozenset({".py"}),
    "src": frozenset({".css", ".html", ".js", ".json", ".py"}),
    "tests": frozenset({".json", ".py"}),
}
_EXACT_RELEASE_PATHS = frozenset(
    {"src/xhs_insight/web/static/brand-just-enter.svg"}
)
_RETIRED_ROOT = "third" + "_party"
_FORBIDDEN_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "data",
        "dist",
        "htmlcov",
        "log",
        "logs",
        "node_modules",
        "state",
        "work",
    }
)
_FORBIDDEN_SUFFIXES = frozenset(
    {".db", ".key", ".log", ".p12", ".pem", ".pfx", ".pyc", ".pyo", ".sqlite", ".sqlite3"}
)
_MAX_ENTRY_SIZE = 20 * 1024 * 1024
_MAX_TOTAL_SIZE = 160 * 1024 * 1024
_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:DSA |EC |ENCRYPTED |OPENSSH |RSA )?PRIVATE KEY-----"
)
_XSEC_RE = re.compile(
    rb'''(?i)["']?xsec[_-]?token["']?\s*(?:=|:)\s*["']?([A-Za-z0-9_-]{24,})'''
)
_CREDENTIAL_RE = re.compile(
    rb'''(?i)["']?(?:a1|access[_-]?token|id[_-]?token|web[_-]?session)["']?'''
    rb'''\s*(?:=|:)\s*["']?([A-Za-z0-9_-]{24,})'''
)
_GITHUB_TOKEN_RE = re.compile(rb"(?:github_pat_[A-Za-z0-9_]{50,}|gh[pousr]_[A-Za-z0-9]{30,})")
_LEGACY_PROJECT_RE = re.compile(
    rb"(?:spider"
    + rb"[_ -]?xhs|cv-cat/"
    + rb"spider"
    + rb"[_ -]?xhs|spider"
    + rb"-xhs@)",
    re.IGNORECASE,
)
_LEGACY_IMPORT_RE = re.compile(
    rb"(?:xhs_"
    + rb"utils\.xhs_(?:core|pc)|apis\.xhs_pc|third_"
    + rb"party/spider_"
    + rb"xhs)",
    re.IGNORECASE,
)
_RETIRED_COMMIT = ("2030f5d4454e556ad7a9" + "caa83b3ec532d4df20c7").encode("ascii")
_DYNAMIC_JS_RE = re.compile(
    rb"(?:"
    rb"\b(?:ev" + rb"al|Function|AsyncFunction|GeneratorFunction)\s*\("
    rb"|\bnew\s+(?:Function|AsyncFunction|GeneratorFunction)\s*\("
    rb"|\bvm\s*\.\s*(?:runInThisContext|runInNewContext|runInContext|compileFunction|Script)\s*\("
    rb"|\bmodule\s*\.\s*_compile\s*\("
    rb"|\.\s*constructor\s*\.\s*constructor\s*\("
    rb"|\b(?:globalThis|global|window)\s*(?:\.\s*ev" + rb"al|\[\s*['\"]ev" + rb"al['\"]\s*\])\s*\("
    rb")"
)
_BROWSER_AUTOMATION_RE = re.compile(
    rb"(?:"
    rb"--remote-debugging-(?:address|port)|--user-data-dir|DevToolsActivePort"
    rb"|/devtools/(?:browser|page)/|/json/(?:list|version)\b"
    rb"|\b(?:Target\.(?:getTargets|attachToTarget)|Network\.getCookies)\b"
    rb"|(?:google-chrome(?:-stable)?|chromium(?:-browser)?|msedge(?:\.exe)?|chrome\.exe)"
    rb")",
    re.IGNORECASE,
)
_FORBIDDEN_CANONICAL_BROWSER_RE = re.compile(
    rb"(?:"
    rb"\bRuntime\s*\.\s*(?:evaluate|callFunctionOn)\b"
    rb"|\b(?:Network|Fetch)\s*\.\s*getResponseBody\b"
    rb"|\b(?:Storage\s*\.\s*getCookies|Network\s*\.\s*getAllCookies)\b"
    rb"|\b(?:localStorage|sessionStorage)\b"
    rb"|--no-sandbox\b"
    rb"|--disable-web-security\b"
    rb"|--remote-allow-origins\s*=\s*\*"
    rb")",
    re.IGNORECASE,
)
_DYNAMIC_BRIDGES = frozenset(
    {"execjs", "js2py", "playwright", "py_mini_racer", "pyppeteer", "selenium"}
)
_CANONICAL_BROWSER_LOGIN = PurePosixPath("src/xhs_insight/browser_login.py")
_HISTORICAL_DISCLOSURE_PATHS = frozenset(
    {
        "README.md",
        "THIRD_PARTY_NOTICES.md",
        "docs/RELEASE_GATES.md",
        "docs/SECURITY.md",
    }
)


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    reason: str


class ReleasePolicyError(RuntimeError):
    """The source tree cannot be projected into a safe release archive."""


def _pure_path(value: str | Path | PurePosixPath) -> PurePosixPath:
    if isinstance(value, PurePosixPath):
        return value
    return PurePosixPath(str(value).replace("\\", "/"))


def is_sensitive_path(relative: str | Path | PurePosixPath) -> bool:
    path = _pure_path(relative)
    lowered_parts = {part.casefold() for part in path.parts}
    name = path.name.casefold()
    if lowered_parts & _FORBIDDEN_PARTS or _RETIRED_ROOT in lowered_parts:
        return True
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    if name in {"instance.json", "master.key"} or name.startswith(".instance.json."):
        return True
    return path.suffix.casefold() in _FORBIDDEN_SUFFIXES or name == ".ds_store"


def release_path_allowed(relative: str | Path | PurePosixPath) -> bool:
    path = _pure_path(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        return False
    if is_sensitive_path(path):
        return False
    if path.as_posix() in _EXACT_RELEASE_PATHS:
        return True
    if len(path.parts) == 1:
        return path.as_posix() in ROOT_RELEASE_FILES
    if path.parts[0] == "exports":
        return path.as_posix() == "exports/.gitkeep"
    allowed_suffixes = _DIRECTORY_SUFFIXES.get(path.parts[0])
    return allowed_suffixes is not None and path.suffix.casefold() in allowed_suffixes


def _under_release_namespace(relative: PurePosixPath) -> bool:
    if not relative.parts:
        return False
    return (
        relative.parts[0] in _DIRECTORY_SUFFIXES
        or relative.parts[0] == "exports"
        or relative.as_posix() in ROOT_RELEASE_FILES
    )


def source_file_paths(root: Path) -> list[Path]:
    """Return the explicit release projection, rejecting eligible symlinks."""

    selected: list[Path] = []
    for path in root.rglob("*"):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if path.is_symlink():
            if _under_release_namespace(relative) and not is_sensitive_path(relative):
                raise ReleasePolicyError(f"release path is a symlink: {relative}")
            continue
        if path.is_file() and release_path_allowed(relative):
            selected.append(path)
    return sorted(selected, key=lambda item: item.relative_to(root).as_posix())


def required_release_paths() -> frozenset[str]:
    required = set(ROOT_RELEASE_FILES)
    required.update(
        {
            ".github/workflows/ci.yml",
            ".github/workflows/release.yml",
            "docs/G1_SECURITY.md",
            "docs/RELEASE_GATES.md",
            "docs/SECURITY.md",
            "exports/.gitkeep",
            "scripts/archive_source.py",
            "scripts/doctor.py",
            "scripts/scan_release.py",
            "scripts/verify_g1.py",
            _CANONICAL_BROWSER_LOGIN.as_posix(),
        }
    )
    return frozenset(required)


def _legacy_payload_findings(path: str, payload: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if _LEGACY_PROJECT_RE.search(payload) and path not in _HISTORICAL_DISCLOSURE_PATHS:
        findings.append(Finding(path, "retired vendor project reference"))
    if _LEGACY_IMPORT_RE.search(payload):
        findings.append(Finding(path, "retired vendor path or import reference"))
    if _RETIRED_COMMIT in payload.lower():
        findings.append(Finding(path, "retired vendor commit reference"))
    return findings


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _python_security_findings(relative: PurePosixPath, payload: bytes) -> list[Finding]:
    path = relative.as_posix()
    try:
        tree = ast.parse(payload, filename=path)
    except SyntaxError:
        return [Finding(path, "Python source is invalid")]
    findings: list[Finding] = []
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported_roots.add((node.module or "").partition(".")[0])
    if imported_roots & _DYNAMIC_BRIDGES:
        findings.append(Finding(path, "browser automation or dynamic code bridge import"))

    if relative.parts[:2] == ("src", "xhs_insight"):
        forbidden_calls = {"ev" + "al", "ex" + "ec", "com" + "pile", "importlib.import_module"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _qualified_name(node.func) or ""
            if name in forbidden_calls:
                findings.append(Finding(path, f"dynamic Python execution primitive: {name}"))
                break

    if relative == _CANONICAL_BROWSER_LOGIN:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = _qualified_name(node.func) or ""
            if call_name in {"os.system", "os.popen"}:
                findings.append(Finding(path, "canonical browser login uses a shell launcher"))
                break
            if call_name in {"subprocess.Popen", "subprocess.run", "subprocess.call"}:
                shell_keywords = [
                    keyword
                    for keyword in node.keywords
                    if keyword.arg == "shell"
                    and not (
                        isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                    )
                ]
                if shell_keywords:
                    findings.append(
                        Finding(path, "canonical browser login may not enable subprocess shell")
                    )
                    break
    return findings


def _scan_payload(relative: PurePosixPath, payload: bytes) -> list[Finding]:
    path = relative.as_posix()
    findings = _legacy_payload_findings(path, payload)
    if _PRIVATE_KEY_RE.search(payload):
        findings.append(Finding(path, "private-key PEM material"))
    if _XSEC_RE.search(payload):
        findings.append(Finding(path, "high-confidence xsec_token value"))
    if _CREDENTIAL_RE.search(payload):
        findings.append(Finding(path, "high-confidence Cookie/token value"))
    if _GITHUB_TOKEN_RE.search(payload):
        findings.append(Finding(path, "GitHub access token value"))
    suffix = relative.suffix.casefold()
    if suffix in {".cjs", ".js", ".mjs"} and _DYNAMIC_JS_RE.search(payload):
        findings.append(Finding(path, "dynamic JavaScript execution primitive"))
    if (
        relative.parts[:2] == ("src", "xhs_insight")
        and relative != _CANONICAL_BROWSER_LOGIN
        and _BROWSER_AUTOMATION_RE.search(payload)
    ):
        findings.append(Finding(path, "browser automation or debugging transport marker"))
    if relative == _CANONICAL_BROWSER_LOGIN and _FORBIDDEN_CANONICAL_BROWSER_RE.search(payload):
        findings.append(Finding(path, "unsafe browser or CDP capability in canonical login module"))
    if suffix == ".py":
        findings.extend(_python_security_findings(relative, payload))
    return findings


def _checkout_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in root.rglob("*"):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        lowered = {part.casefold() for part in relative.parts}
        if lowered & _FORBIDDEN_PARTS:
            continue
        if path.is_symlink() or path.is_file():
            paths.append(path)
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def scan_g1_tree(root: Path) -> list[Finding]:
    """Scan the full checkout, including files outside the release projection."""

    findings: list[Finding] = []
    for path in _checkout_paths(root):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if _RETIRED_ROOT in {part.casefold() for part in relative.parts}:
            findings.append(Finding(relative.as_posix(), "retired vendor directory is present"))
            continue
        if path.is_symlink():
            findings.append(Finding(relative.as_posix(), "source path is a symlink"))
            continue
        try:
            payload = path.read_bytes()
        except OSError as error:
            findings.append(Finding(relative.as_posix(), f"cannot read: {type(error).__name__}"))
            continue
        if len(payload) > _MAX_ENTRY_SIZE:
            continue
        findings.extend(_legacy_payload_findings(relative.as_posix(), payload))
        if relative.suffix.casefold() in {".cjs", ".js", ".mjs", ".py"}:
            findings.extend(_scan_payload(relative, payload))
    return _deduplicate(findings)


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    return list(dict.fromkeys(findings))


def scan_source(root: Path, *, require_complete: bool = True) -> list[Finding]:
    findings = scan_g1_tree(root)
    try:
        paths = source_file_paths(root)
    except ReleasePolicyError as error:
        return [Finding(".", str(error))]
    relative_names: set[str] = set()
    for path in paths:
        relative = PurePosixPath(path.relative_to(root).as_posix())
        relative_names.add(relative.as_posix())
        try:
            payload = path.read_bytes()
        except OSError as error:
            findings.append(Finding(relative.as_posix(), f"cannot read: {type(error).__name__}"))
            continue
        if len(payload) > _MAX_ENTRY_SIZE:
            findings.append(Finding(relative.as_posix(), "file exceeds release scanner size limit"))
            continue
        findings.extend(_scan_payload(relative, payload))
    if require_complete:
        for missing in sorted(required_release_paths() - relative_names):
            findings.append(Finding(missing, "required release file is missing"))
    return _deduplicate(findings)


def scan_git_history(root: Path) -> list[Finding]:
    """Reject retired vendor paths, names, and commit markers in reachable history."""

    try:
        inside = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [Finding(".git", "cannot inspect Git history")]
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return []
    findings: list[Finding] = []
    try:
        objects = subprocess.run(
            ["git", "rev-list", "--objects", "--all"],
            cwd=root,
            check=False,
            capture_output=True,
            timeout=30,
        )
        commits = subprocess.run(
            ["git", "rev-list", "--all"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        messages = subprocess.run(
            ["git", "log", "--format=%H%n%B", "--all"],
            cwd=root,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [Finding(".git", "cannot inspect reachable Git objects")]
    if objects.returncode or commits.returncode or messages.returncode:
        return [Finding(".git", "Git history inspection failed")]

    findings.extend(_legacy_payload_findings(".git", messages.stdout))
    retired_root = _RETIRED_ROOT.encode("ascii")
    for object_line in objects.stdout.splitlines():
        _, separator, object_path = object_line.partition(b" ")
        if not separator:
            continue
        parts = object_path.replace(b"\\", b"/").lower().split(b"/")
        if retired_root in parts:
            findings.append(Finding(".git", "reachable history contains a retired vendor path"))
            break
    findings.extend(_legacy_payload_findings(".git", objects.stdout))

    grep_pattern = (
        "spider"
        + "[_ -]?xhs|cv-cat/"
        + "spider[_ -]?xhs|spider"
        + "-xhs@|xhs_utils\\.xhs_(core|pc)"
        + "|apis\\.xhs_pc|third_"
        + "party/spider_"
        + "xhs|"
        + _RETIRED_COMMIT.decode("ascii")
    )
    for revision in commits.stdout.splitlines():
        if not revision:
            continue
        try:
            grep = subprocess.run(
                ["git", "grep", "-I", "-n", "-E", grep_pattern, revision, "--", "."],
                cwd=root,
                check=False,
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            findings.append(Finding(".git", "cannot inspect reachable Git blob content"))
            continue
        if grep.returncode not in {0, 1}:
            findings.append(Finding(".git", "Git blob content inspection failed"))
            continue
        for line in grep.stdout.splitlines():
            _, separator, remainder = line.partition(b":")
            path_bytes, separator, content = remainder.partition(b":")
            if not separator:
                findings.append(Finding(".git", "unparseable Git blob match"))
                continue
            path = path_bytes.decode("utf-8", errors="replace")
            findings.extend(_legacy_payload_findings(path, content))
    return _deduplicate(findings)


def _zip_relative(name: str, prefix: str | None) -> tuple[PurePosixPath | None, str | None]:
    if "\\" in name or name.startswith("/"):
        return None, "invalid archive path"
    raw = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in raw.parts) or not raw.parts:
        return None, "invalid archive path"
    if prefix is not None and raw.parts[0] != prefix:
        return None, "multiple archive roots"
    if len(raw.parts) == 1:
        return None, None
    return PurePosixPath(*raw.parts[1:]), None


def scan_zip(archive: Path, *, require_complete: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    names: set[str] = set()
    casefolded_names: set[str] = set()
    prefix: str | None = None
    total_size = 0
    try:
        bundle = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as error:
        return [Finding(str(archive), f"invalid ZIP: {type(error).__name__}")]
    with bundle:
        for info in bundle.infolist():
            raw = PurePosixPath(info.filename)
            if raw.parts and prefix is None:
                prefix = raw.parts[0]
            relative, path_error = _zip_relative(info.filename, prefix)
            if path_error:
                findings.append(Finding(info.filename, path_error))
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                findings.append(Finding(info.filename, "symlink archive member"))
                continue
            file_type = stat.S_IFMT(mode)
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                findings.append(Finding(info.filename, "special archive member"))
                continue
            if info.is_dir() or relative is None:
                continue
            path = relative.as_posix()
            if path in names or path.casefold() in casefolded_names:
                findings.append(Finding(path, "duplicate or case-colliding archive member"))
                continue
            names.add(path)
            casefolded_names.add(path.casefold())
            if not release_path_allowed(relative):
                findings.append(Finding(path, "path is outside the release whitelist"))
                continue
            if info.file_size > _MAX_ENTRY_SIZE:
                findings.append(Finding(path, "file exceeds release scanner size limit"))
                continue
            total_size += info.file_size
            if total_size > _MAX_TOTAL_SIZE:
                findings.append(Finding(path, "archive exceeds release scanner total size limit"))
                break
            try:
                payload = bundle.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                findings.append(Finding(path, f"cannot read ZIP member: {type(error).__name__}"))
                continue
            findings.extend(_scan_payload(relative, payload))
    if prefix is None or "-v" not in prefix:
        findings.append(Finding(str(archive), "unexpected archive root prefix"))
    if require_complete:
        for missing in sorted(required_release_paths() - names):
            findings.append(Finding(missing, "required release file is missing"))
    return _deduplicate(findings)


def _resolve_archive(value: Path) -> Path:
    if value.is_file():
        return value
    candidates = sorted(value.glob("*-source-v*.zip")) if value.is_dir() else []
    if len(candidates) != 1:
        raise ReleasePolicyError("--archive must name one ZIP, or a directory containing exactly one source ZIP")
    return candidates[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--source", type=Path, help="scan the release projection of a source tree")
    target.add_argument("--archive", type=Path, help="scan a source ZIP or its containing directory")
    parser.add_argument(
        "--git-history",
        action="store_true",
        help="also reject retired vendor provenance in reachable Git history",
    )
    args = parser.parse_args()
    try:
        if args.archive:
            path = _resolve_archive(args.archive.expanduser().resolve())
            findings = scan_zip(path)
            label = str(path)
        else:
            path = (args.source or ROOT).expanduser().resolve()
            findings = scan_source(path)
            if args.git_history:
                findings.extend(scan_git_history(path))
            label = str(path)
    except ReleasePolicyError as error:
        print(f"[FAIL] release-scan: {error}", file=sys.stderr)
        return 1
    findings = _deduplicate(findings)
    if findings:
        for finding in findings:
            print(f"[FAIL] {finding.path}: {finding.reason}", file=sys.stderr)
        print(f"release scan failed: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print(f"[OK] release-scan: {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
