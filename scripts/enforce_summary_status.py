#!/usr/bin/env python3
"""Return the fuzzer exit status only after the safe summary was emitted."""
from __future__ import annotations

from pathlib import Path
import sys

from emit_summary import validate


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    try:
        text = validate(Path(sys.argv[1]))
        values = dict(line.split("=", 1) for line in text.splitlines())
        code = int(values["exit_code"])
    except (OSError, UnicodeError, ValueError, KeyError):
        return 1
    return 0 if code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
