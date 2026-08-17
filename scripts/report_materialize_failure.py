#!/usr/bin/env python3
"""Reduce a private materializer sidecar to one public allowlisted status."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from materialize_window import FAILURE_CODES


FALLBACK = "status=fail_closed code=materializer_internal"
MAX_INPUT_BYTES = 4096


def sanitized_status(path: Path) -> str:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return FALLBACK
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            raw = os.read(descriptor, MAX_INPUT_BYTES + 1)
            if os.read(descriptor, 1):
                return FALLBACK
        finally:
            os.close(descriptor)
        if len(raw) > MAX_INPUT_BYTES or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            return FALLBACK
        line = raw[:-1].decode("ascii", errors="strict")
    except BaseException:
        return FALLBACK

    prefix = "status=fail_closed code="
    if not line.startswith(prefix):
        return FALLBACK
    code = line[len(prefix) :]
    if code not in FAILURE_CODES:
        return FALLBACK
    return line


def main() -> int:
    if len(sys.argv) != 2:
        print(FALLBACK)
        return 0
    print(sanitized_status(Path(sys.argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
