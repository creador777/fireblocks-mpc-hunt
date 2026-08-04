#!/usr/bin/env python3
"""Validate and emit only the immutable seven-field public contract."""
from __future__ import annotations

from pathlib import Path
import re
import sys


RULES = {
    # Identica a HARNESSES de public_summary.py. Actualizar SIEMPRE las
    # dos en el mismo commit: tests/test_harness_contract.py falla si no.
    "harness": re.compile(
        r"(?:cmp_ecdsa_online|cmp_ecdsa_online_r4_tn)\Z"),
    "shard": re.compile(r"(?:[0-9]|1[0-9]|2[0-4])\Z"),
    "exit_code": re.compile(r"(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])\Z"),
    "sanitizer": re.compile(r"(?:none|asan|ubsan|msan|oracle|libfuzzer|multiple|tool)\Z"),
    "summary": re.compile(
        r"(?:no_finding|memory_safety|undefined_behavior|uninitialized_memory|"
        r"oracle_violation|timeout|oom|slow_unit|crash_signal|multiple_signals|"
        r"execution_failed|budget_exhausted|container_oom)\Z"
    ),
    "stack_normalized": re.compile(
        r"(?:none|[A-Za-z_~][A-Za-z0-9_:~<>]{0,127}"
        r"(?:>[A-Za-z_~][A-Za-z0-9_:~<>]{0,127}){0,7})\Z"
    ),
    "sha256": re.compile(r"[0-9a-f]{64}\Z"),
}
ORDER = tuple(RULES)
FORBIDDEN = re.compile(
    r"Base64:|MS:|ASCII|artifact_prefix|Test unit written|"
    r"0x[0-9a-fA-F]+|(?:/home/|/Users/|C:\\Users\\)|input bytes",
    re.IGNORECASE,
)


def validate(path: Path) -> str:
    raw = path.read_bytes()
    if len(raw) > 2048 or b"\x00" in raw:
        raise ValueError("invalid summary bytes")
    text = raw.decode("ascii", errors="strict")
    if FORBIDDEN.search(text):
        raise ValueError("forbidden marker")
    lines = text.splitlines()
    if len(lines) != 7:
        raise ValueError("summary must contain seven lines")
    parsed: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator != "=" or key in parsed or key not in RULES:
            raise ValueError("invalid summary field")
        if not RULES[key].fullmatch(value):
            raise ValueError("invalid summary value")
        parsed[key] = value
    if tuple(parsed) != ORDER:
        raise ValueError("summary order changed")
    return text


def main() -> int:
    if len(sys.argv) != 2:
        return 64
    try:
        text = validate(Path(sys.argv[1]))
    except (OSError, UnicodeError, ValueError):
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
