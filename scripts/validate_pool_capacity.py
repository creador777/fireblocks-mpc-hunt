#!/usr/bin/env python3
"""Validate flat private corpus capacity without exposing private details."""

from __future__ import annotations

import sys
from pathlib import Path

from materialize_window import FailClosed, scan_private_inventory


def validate(directories: list[Path]) -> None:
    # Limits are per harness because each hunt shard consumes one harness.
    for directory in directories:
        scan_private_inventory([directory])


def main() -> int:
    try:
        validate([Path(value) for value in sys.argv[1:]])
    except FailClosed as error:
        print(f"status=fail_closed code={error.code}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("status=fail_closed code=interrupted", file=sys.stderr)
        return 2
    except BaseException:
        print("status=fail_closed code=materializer_internal", file=sys.stderr)
        return 2
    print("status=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
