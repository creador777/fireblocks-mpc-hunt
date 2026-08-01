#!/usr/bin/env python3
"""Fail-closed validation of a flat SHA-1-addressed corpus directory.

Same contract as materialize_corpus.validated_units: only regular files at
depth one, each named by the lowercase SHA-1 of its content. Any anomaly
exits 1. Nothing is modified or deleted.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    root = Path(sys.argv[1])
    try:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("invalid corpus root")
        count = 0
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
                if info.st_size > 4 * 1024 * 1024:
                    raise ValueError("corpus unit too large")
                if hashlib.sha1(Path(entry.path).read_bytes()).hexdigest() != name:
                    raise ValueError("corpus hash mismatch")
                count += 1
        if count == 0:
            raise ValueError("empty corpus")
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
