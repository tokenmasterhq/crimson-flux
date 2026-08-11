#!/usr/bin/env python3
"""Prepare the locked Python environment and start the local Web service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from doctor import collect_checks, print_checks

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
STAMP = VENV / ".crimsonflux-bootstrap.json"


def _venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _venv_command() -> Path:
    return VENV / ("Scripts/crimsonflux.exe" if os.name == "nt" else "bin/crimsonflux")


def _digest(paths: tuple[Path, ...]) -> str:
    value = hashlib.sha256()
    for path in paths:
        value.update(str(path.relative_to(ROOT)).encode("utf-8"))
        value.update(b"\0")
        value.update(path.read_bytes())
        value.update(b"\0")
    return value.hexdigest()


def _run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def prepare() -> None:
    checks = collect_checks()
    print_checks(checks)
    failures = [item for item in checks if item.status == "fail"]
    if failures:
        raise SystemExit("environment check failed; fix the FAIL items above")

    project_files = tuple(sorted(path for path in (ROOT / "src").rglob("*") if path.is_file()))
    lock_inputs = (
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
        ROOT / "requirements.lock",
        *project_files,
    )
    fingerprint = _digest(lock_inputs)
    if STAMP.is_file() and _venv_command().is_file():
        try:
            previous = json.loads(STAMP.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}
        if previous.get("fingerprint") == fingerprint:
            print("Locked Python dependencies are already prepared.")
            return

    if not VENV.exists():
        _run([sys.executable, "-m", "venv", str(VENV)])

    _run(
        [
            str(_venv_python()),
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--requirement",
            str(ROOT / "requirements.lock"),
        ]
    )
    _run(
        [
            str(_venv_python()),
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-build-isolation",
            str(ROOT),
        ]
    )
    STAMP.write_text(
        json.dumps({"fingerprint": fingerprint}, indent=2) + "\n",
        encoding="utf-8",
    )


def launch(*, port: int, no_browser: bool) -> int:
    executable = _venv_command()
    if not executable.is_file():
        raise SystemExit(f"console entry point is missing after sync: {executable}")
    environment = dict(os.environ)
    environment["CRIMSONFLUX_HOST"] = "127.0.0.1"
    environment["CRIMSONFLUX_PORT"] = str(port)
    environment.setdefault("CRIMSONFLUX_EXPORT_DIR", str(ROOT / "exports"))
    if no_browser:
        environment["CRIMSONFLUX_NO_BROWSER"] = "1"
    command = [str(executable), "serve"]
    print("+", " ".join(command), flush=True)
    if os.name != "nt":
        os.execve(str(executable), command, environment)
        return 0
    return subprocess.call(command, cwd=ROOT, env=environment)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    prepare()
    if args.prepare_only:
        return 0
    return launch(port=args.port, no_browser=args.no_browser)


if __name__ == "__main__":
    raise SystemExit(main())
