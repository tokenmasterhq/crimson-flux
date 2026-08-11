from __future__ import annotations

import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from scan_release import (  # noqa: E402
    ReleasePolicyError,
    _scan_payload,
    release_path_allowed,
    scan_source,
    scan_zip,
    source_file_paths,
)

_RETIRED_ROOT = "third" + "_party"
_RETIRED_PROJECT = "Spider" + "_XHS"
_RETIRED_IMPORT = "xhs_" + "utils.xhs_core"
_RETIRED_PATH = _RETIRED_ROOT + "/spider_" + "xhs"
_RETIRED_COMMIT = "2030f5d4454e556ad7a9" + "caa83b3ec532d4df20c7"


def _write_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as bundle:
        for name, payload in entries:
            bundle.writestr(name, payload)


def test_repository_release_projection_is_independent_and_clean() -> None:
    selected = [path.relative_to(ROOT).as_posix() for path in source_file_paths(ROOT)]

    assert selected
    assert "src/xhs_insight/web/static/brand-just-enter.svg" in selected
    assert all(_RETIRED_ROOT not in PurePosixPath(path).parts for path in selected)
    assert all("node_modules" not in PurePosixPath(path).parts for path in selected)
    assert scan_source(ROOT) == []


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "Dockerfile",
        "src/xhs_insight/app.py",
        "src/xhs_insight/web/static/brand-just-enter.svg",
        "scripts/start.py",
        "tests/unit/test_example.py",
        "exports/.gitkeep",
    ],
)
def test_release_path_allowlist_accepts_reviewable_source(path: str) -> None:
    assert release_path_allowed(path)


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "state/app.sqlite3",
        "exports/private.jsonl",
        "src/xhs_insight/master.key",
        "dist/release.zip",
        "node_modules/package/index.js",
        "../README.md",
    ],
)
def test_release_path_allowlist_rejects_secrets_state_and_build_output(path: str) -> None:
    assert not release_path_allowed(path)


def test_release_path_allowlist_rejects_retired_vendor_root() -> None:
    assert not release_path_allowed(f"{_RETIRED_PATH}/module.py")


def test_release_projection_rejects_eligible_symlinks(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    target = tmp_path / "outside.py"
    target.write_text("print('outside')\n", encoding="utf-8")
    link = scripts / "linked.py"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(ReleasePolicyError, match="symlink"):
        source_file_paths(tmp_path)


def test_payload_scanner_detects_high_confidence_secrets() -> None:
    xsec = "Ab7_" * 8
    session = "Session7_" * 4
    pat = "github_" + "pat_" + "A" * 64
    payload = (
        f'{{"xsec_token":"{xsec}","web_session":"{session}","pat":"{pat}"}}'
    ).encode()
    payload += b"\n-----BEGIN " + b"PRIVATE KEY-----\n"

    reasons = {
        finding.reason for finding in _scan_payload(PurePosixPath("docs/probe.md"), payload)
    }

    assert "high-confidence xsec_token value" in reasons
    assert "high-confidence Cookie/token value" in reasons
    assert "GitHub access token value" in reasons
    assert "private-key PEM material" in reasons


def test_historical_name_disclosure_is_limited_to_documentation() -> None:
    payload = _RETIRED_PROJECT.encode()

    assert _scan_payload(PurePosixPath("README.md"), payload) == []
    findings = _scan_payload(PurePosixPath("src/xhs_insight/probe.py"), b"# " + payload)

    assert any(finding.reason == "retired vendor project reference" for finding in findings)


@pytest.mark.parametrize("marker", [_RETIRED_IMPORT, _RETIRED_PATH, _RETIRED_COMMIT])
def test_historical_disclosure_never_allows_import_path_or_commit(marker: str) -> None:
    findings = _scan_payload(PurePosixPath("README.md"), marker.encode())

    assert findings


def test_minimal_legal_source_tree_passes(tmp_path: Path) -> None:
    source = tmp_path / "src" / "xhs_insight" / "safe.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("Independent collector\n", encoding="utf-8")

    assert scan_source(tmp_path, require_complete=False) == []


def test_minimal_legal_zip_passes(tmp_path: Path) -> None:
    archive = tmp_path / "safe.zip"
    _write_zip(
        archive,
        [
            ("crimsonflux-v0.1.0/README.md", b"Independent collector\n"),
            ("crimsonflux-v0.1.0/src/xhs_insight/safe.py", b"VALUE = 1\n"),
        ],
    )

    assert scan_zip(archive, require_complete=False) == []


def test_zip_scan_rejects_retired_path_and_secrets(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    xsec = b"Ab7_" * 8
    _write_zip(
        archive,
        [
            (f"crimsonflux-v0.1.0/{_RETIRED_PATH}/module.py", b"VALUE = 1\n"),
            (
                "crimsonflux-v0.1.0/docs/credential.md",
                b'{"xsec_token":"' + xsec + b'"}',
            ),
        ],
    )

    reasons = {finding.reason for finding in scan_zip(archive, require_complete=False)}

    assert "path is outside the release whitelist" in reasons
    assert "high-confidence xsec_token value" in reasons


def test_zip_scan_rejects_traversal_symlink_and_case_collision(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("crimsonflux-v0.1.0/../README.md", b"escape\n")
        bundle.writestr("crimsonflux-v0.1.0/docs/Guide.md", b"one\n")
        bundle.writestr("crimsonflux-v0.1.0/docs/guide.md", b"two\n")
        link = zipfile.ZipInfo("crimsonflux-v0.1.0/scripts/link.py")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        bundle.writestr(link, b"../../outside.py")

    reasons = {finding.reason for finding in scan_zip(archive, require_complete=False)}

    assert "invalid archive path" in reasons
    assert "duplicate or case-colliding archive member" in reasons
    assert "symlink archive member" in reasons


def test_zip_scan_requires_one_versioned_root(tmp_path: Path) -> None:
    archive = tmp_path / "roots.zip"
    _write_zip(
        archive,
        [
            ("crimsonflux-v0.1.0/README.md", b"one\n"),
            ("other-v0.1.0/README.md", b"two\n"),
        ],
    )

    reasons = {finding.reason for finding in scan_zip(archive, require_complete=False)}

    assert "multiple archive roots" in reasons
