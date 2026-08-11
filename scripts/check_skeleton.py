#!/usr/bin/env python3
"""Static checks for the Python-only source-deployment skeleton."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(path: str, *needles: str) -> list[str]:
    target = ROOT / path
    if not target.is_file():
        return [f"missing {path}"]
    text = target.read_text(encoding="utf-8")
    return [f"{path} does not contain {needle!r}" for needle in needles if needle not in text]


def main() -> int:
    errors: list[str] = []
    errors.extend(
        require(
            "Dockerfile",
            "python:3.12",
            "uv sync --frozen",
            "USER app:app",
        )
    )
    errors.extend(
        require(
            "docker-compose.yml",
            "127.0.0.1:${CRIMSONFLUX_PORT:-8765}:8765",
            "crimsonflux_state",
            "./exports:/app/exports",
            "no-new-privileges:true",
            'CRIMSONFLUX_ALLOW_CONTAINER_BIND: "1"',
        )
    )
    errors.extend(
        require(
            "scripts/start.py",
            '"--require-hashes"',
            '"--no-build-isolation"',
            "CRIMSONFLUX_HOST",
        )
    )
    errors.extend(require("requirements.lock", "hatchling==1.27.0", "--hash=sha256:"))
    errors.extend(require("docs/RELEASE_GATES.md", "G1", "scripts/verify_g1.py"))
    errors.extend(require("docs/G1_SECURITY.md", "scripts/verify_g1.py", "Cookie"))
    errors.extend(require("scripts/verify_g1.py", "python_only_runtime", "source_provenance"))
    errors.extend(require("README.md", "docker compose up -d --build", "python scripts/start.py"))

    inspected = (
        "Dockerfile",
        "docker-compose.yml",
        "scripts/start.py",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    )
    forbidden = (
        "FROM " + "node:",
        "n" + "pm ",
        "CRIMSONFLUX_" + "UPSTREAM_DIR",
        "XHS_INSIGHT_",
        "third" + "_party/",
    )
    for path in inspected:
        target = ROOT / path
        if not target.is_file():
            continue
        text = target.read_text(encoding="utf-8")
        for marker in forbidden:
            if marker.casefold() in text.casefold():
                errors.append(f"{path} contains retired runtime marker: {marker}")

    for path in (".env.example", "docker-compose.yml", "scripts/start.py"):
        text = (ROOT / path).read_text(encoding="utf-8")
        if "XHS_USE_FIXTURE_ADAPTER" in text or "--fixture" in text:
            errors.append(f"{path} exposes an unsupported runtime fixture switch")
    docker_text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for forbidden_path in ("PyInstaller", "npm run build --prefix web", "openai"):
        if forbidden_path.casefold() in docker_text.casefold():
            errors.append(f"Dockerfile contains forbidden build path: {forbidden_path}")
    for script in sorted((ROOT / "scripts").glob("*.py")):
        try:
            ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
        except SyntaxError as error:
            errors.append(f"{script.name}: {error}")
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("source deployment skeleton: Python-only static checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
