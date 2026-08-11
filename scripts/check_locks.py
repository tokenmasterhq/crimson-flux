#!/usr/bin/env python3
"""Verify that the native pip lock is an exact export of uv.lock."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xhs-lock-check-") as directory:
        generated = Path(directory) / "requirements.lock"
        command = [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--extra",
            "bootstrap",
            "--no-emit-project",
            "--no-header",
            "--output-file",
            str(generated),
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            if result.stdout:
                print(result.stdout, file=sys.stderr, end="")
            if result.stderr:
                print(result.stderr, file=sys.stderr, end="")
            return result.returncode
        expected = ROOT / "requirements.lock"
        generated_bytes = generated.read_bytes().replace(b"\r\n", b"\n")
        expected_bytes = expected.read_bytes().replace(b"\r\n", b"\n")
        if generated_bytes != expected_bytes:
            print(
                "requirements.lock is stale; regenerate it with: " + " ".join(command[:-1]) + " requirements.lock",
                file=sys.stderr,
            )
            return 1
    print("uv.lock and requirements.lock are synchronized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
