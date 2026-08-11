#!/usr/bin/env python3
"""Check Python-only source-deployment prerequisites without network access."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from scan_release import scan_git_history, scan_source

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


def _python_check() -> Check:
    current = sys.version_info
    version = f"{current.major}.{current.minor}.{current.micro}"
    if current < (3, 12) or current >= (3, 13):
        return Check("python", "fail", f"Python 3.12.x required; found {version}")
    return Check("python", "ok", version)


def _file_check(name: str, path: Path) -> Check:
    if not path.is_file():
        return Check(name, "fail", f"missing: {path.relative_to(ROOT)}")
    return Check(name, "ok", str(path.relative_to(ROOT)))


def _source_check() -> Check:
    findings = scan_source(ROOT)
    if findings:
        summary = ", ".join(f"{item.path}: {item.reason}" for item in findings[:10])
        return Check("release-source", "fail", summary)
    return Check("release-source", "ok", "source tree matches the Python-only release policy")


def _history_check() -> Check:
    findings = scan_git_history(ROOT)
    if findings:
        summary = ", ".join(f"{item.path}: {item.reason}" for item in findings[:10])
        return Check("git-history", "fail", summary)
    return Check("git-history", "ok", "reachable history contains no retired vendor provenance")


def collect_checks(*, release: bool = False) -> list[Check]:
    checks = [
        _python_check(),
        _file_check("python-lock", ROOT / "uv.lock"),
        _file_check("native-python-lock", ROOT / "requirements.lock"),
        _source_check(),
    ]
    if release:
        g1_reference = os.getenv("CRIMSONFLUX_RELEASE_G1_APPROVAL_REF", "").strip()
        checks.extend(
            [
                Check("g1-approval", "ok", g1_reference)
                if g1_reference
                else Check(
                    "g1-approval",
                    "fail",
                    "CRIMSONFLUX_RELEASE_G1_APPROVAL_REF is required",
                ),
                _history_check(),
                _file_check("release-gates", ROOT / "docs" / "RELEASE_GATES.md"),
            ]
        )
    return checks


def print_checks(checks: list[Check], *, json_output: bool = False) -> None:
    if json_output:
        print(json.dumps([asdict(item) for item in checks], ensure_ascii=False, indent=2))
        return
    labels = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}
    for item in checks:
        print(f"[{labels[item.status]:4}] {item.name}: {item.detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="also require G1 approval and clean history")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args()
    checks = collect_checks(release=args.release)
    print_checks(checks, json_output=args.json)
    return 1 if any(item.status == "fail" for item in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
