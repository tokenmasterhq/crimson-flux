#!/usr/bin/env python3
"""Create a deterministic source ZIP after release-gate verification."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import time
import tomllib
import zipfile
from pathlib import Path

from doctor import collect_checks, print_checks
from scan_release import ReleasePolicyError, source_file_paths

ROOT = Path(__file__).resolve().parents[1]


def _version() -> str:
    payload = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(payload["project"]["version"])


def _paths() -> list[Path]:
    return source_file_paths(ROOT)


def _read_regular_file(path: Path) -> bytes:
    """Read one selected file without following a final-component symlink."""

    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ReleasePolicyError(f"release path is not a regular file: {path.relative_to(ROOT)}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise ReleasePolicyError(
                f"release path changed while archiving: {path.relative_to(ROOT)}"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release",
        action="store_true",
        help="require protected G1 approval and a clean, independently implemented source history",
    )
    args = parser.parse_args()
    checks = collect_checks(release=args.release)
    print_checks(checks)
    if any(item.status == "fail" for item in checks):
        return 1

    version = _version()
    output_dir = ROOT / "dist" / "source"
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"crimsonflux-source-v{version}.zip"
    prefix = f"crimsonflux-v{version}"
    epoch = max(int(os.getenv("SOURCE_DATE_EPOCH", "315532800")), 315532800)
    timestamp = time.gmtime(epoch)[:6]

    try:
        paths = _paths()
        with zipfile.ZipFile(
            archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as bundle:
            for path in paths:
                relative = path.relative_to(ROOT).as_posix()
                mode = path.lstat().st_mode
                info = zipfile.ZipInfo(f"{prefix}/{relative}", date_time=timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                permissions = 0o755 if mode & 0o111 else 0o644
                info.external_attr = (stat.S_IFREG | permissions) << 16
                bundle.writestr(info, _read_regular_file(path))
    except (OSError, ReleasePolicyError) as error:
        print(f"[FAIL] source archive policy: {error}")
        return 1

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sidecar = archive.with_suffix(archive.suffix + ".sha256")
    sidecar.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    print(archive)
    print(sidecar)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
