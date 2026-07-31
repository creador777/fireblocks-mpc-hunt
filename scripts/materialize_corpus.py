#!/usr/bin/env python3
"""Copy only flat SHA-1-addressed regular corpus units into a fresh directory."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys


def validated_units(root: Path) -> list[Path]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid corpus root")
    result: list[Path] = []
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise ValueError("symlink rejected")
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("nested or non-regular corpus entry rejected")
            name = entry.name
            if len(name) != 40 or any(char not in "0123456789abcdef" for char in name):
                raise ValueError("invalid corpus name")
            path = Path(entry.path)
            if info.st_size > 4 * 1024 * 1024:
                raise ValueError("corpus unit too large")
            if hashlib.sha1(path.read_bytes()).hexdigest() != name:
                raise ValueError("corpus hash mismatch")
            result.append(path)
    return result


def materialize(destination: Path, sources: list[Path]) -> None:
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ValueError("destination must be an empty regular directory")
    count = 0
    total = 0
    for source in sources:
        for path in validated_units(source):
            target = destination / path.name
            if target.exists():
                if target.is_symlink() or target.read_bytes() != path.read_bytes():
                    raise ValueError("corpus collision")
                continue
            size = path.stat().st_size
            count += 1
            total += size
            if count > 100_000 or total > 512 * 1024 * 1024:
                raise ValueError("corpus materialization limit exceeded")
            shutil.copyfile(path, target, follow_symlinks=False)
            target.chmod(0o600)


def main() -> int:
    if len(sys.argv) < 3:
        return 64
    try:
        materialize(Path(sys.argv[1]), [Path(value) for value in sys.argv[2:]])
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
