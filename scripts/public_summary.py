#!/usr/bin/env python3
"""Build a seven-field public summary without echoing fuzzer-controlled text."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import sys


ARTIFACT = re.compile(r"(crash|timeout|oom|slow-unit)-[0-9a-f]{40}\Z")
FRAME = re.compile(rb"#[0-9]+ +0x[0-9a-fA-F]+ +in +([A-Za-z_~][A-Za-z0-9_:~<>]{0,127})")
# Frame allowlist fixed OUTSIDE the log: extracted from the fuzzer binary at
# build time and versioned next to this script. A frame whose symbol is not
# listed is published as "unknown". The alternative — trusting the token's
# shape — bounds nothing: a symbol name is free text chosen by whoever wrote
# the log, and it would be printed to the public stdout of a public repo.
ALLOWED_FRAMES = frozenset(
    (Path(__file__).with_name("frame-allowlist.txt")
     .read_text(encoding="ascii").split()))
FIELDS = (
    "harness",
    "shard",
    "exit_code",
    "sanitizer",
    "summary",
    "stack_normalized",
    "sha256",
)


class SummaryError(RuntimeError):
    pass


def regular_depth_one(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise SummaryError("invalid private directory")
    result: list[Path] = []
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise SummaryError("symlink rejected")
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise SummaryError("non-regular entry rejected")
            result.append(Path(entry.path))
    return result


def classify(log: bytes, artifact_kind: str | None) -> tuple[str, str]:
    signals: set[str] = set()
    if b"AddressSanitizer" in log or b"ERROR: ASan" in log:
        signals.add("asan")
    if b"UndefinedBehaviorSanitizer" in log or b"runtime error:" in log:
        signals.add("ubsan")
    if b"MemorySanitizer" in log:
        signals.add("msan")
    if b"FIREBLOCKS_HIGH_SIGNAL" in log:
        signals.add("oracle")

    if len(signals) > 1:
        return "multiple", "multiple_signals"
    if signals:
        sanitizer = next(iter(signals))
        summary = {
            "asan": "memory_safety",
            "ubsan": "undefined_behavior",
            "msan": "uninitialized_memory",
            "oracle": "oracle_violation",
        }[sanitizer]
        return sanitizer, summary
    if artifact_kind == "timeout":
        return "libfuzzer", "timeout"
    if artifact_kind == "oom":
        return "libfuzzer", "oom"
    if artifact_kind == "slow-unit":
        return "libfuzzer", "slow_unit"
    if artifact_kind == "crash":
        return "libfuzzer", "crash_signal"
    return "none", "no_finding"


def normalized_stack(log: bytes) -> str:
    frames: list[str] = []
    for line in log.splitlines():
        if len(line) > 65_536:
            continue
        match = FRAME.search(line)
        if not match:
            continue
        frame = match.group(1).decode("ascii", errors="strict")
        if frame not in ALLOWED_FRAMES:
            frame = "unknown"
        if frame not in frames:
            frames.append(frame)
        if len(frames) == 8:
            break
    value = ">".join(frames) if frames else "none"
    if len(value) > 512 or "/" in value or "\\" in value or "0x" in value.lower():
        raise SummaryError("unsafe normalized stack")
    return value


def build(private_root: Path, harness: str, shard_text: str) -> dict[str, str]:
    if harness != "cmp_ecdsa_online":
        raise SummaryError("unexpected harness")
    if not shard_text.isdecimal() or not 0 <= int(shard_text) < 25:
        raise SummaryError("invalid shard")

    entries = regular_depth_one(private_root)
    by_name = {entry.name: entry for entry in entries}
    if set(by_name).issuperset({"fuzzer.raw.log", "exit_code"}) is False:
        raise SummaryError("missing private execution evidence")
    if by_name["fuzzer.raw.log"].stat().st_size > 64 * 1024 * 1024:
        raise SummaryError("raw log exceeds limit")
    log = by_name["fuzzer.raw.log"].read_bytes()
    exit_text = by_name["exit_code"].read_text(encoding="ascii").strip()
    if not exit_text.isdecimal() or not 0 <= int(exit_text) <= 255:
        raise SummaryError("invalid exit code")

    artifacts: list[tuple[Path, str]] = []
    for name, path in by_name.items():
        if name in {"fuzzer.raw.log", "exit_code", "oom_killed"}:
            continue
        match = ARTIFACT.fullmatch(name)
        if not match or path.stat().st_size > 32 * 1024 * 1024:
            raise SummaryError("unexpected artifact")
        artifacts.append((path, match.group(1)))
    if len(artifacts) > 1:
        raise SummaryError("ambiguous artifact set")

    artifact_kind = artifacts[0][1] if artifacts else None
    sanitizer, summary = classify(log, artifact_kind)
    if not artifacts and int(exit_text) != 0:
        if int(exit_text) == 72:
            sanitizer, summary = "tool", "budget_exhausted"
        elif int(exit_text) == 73:
            sanitizer, summary = "tool", "container_oom"
        else:
            sanitizer, summary = "tool", "execution_failed"
    digest = (
        hashlib.sha256(artifacts[0][0].read_bytes()).hexdigest()
        if artifacts
        else "0" * 64
    )
    values = {
        "harness": harness,
        "shard": shard_text,
        "exit_code": exit_text,
        "sanitizer": sanitizer,
        "summary": summary,
        "stack_normalized": normalized_stack(log),
        "sha256": digest,
    }
    if tuple(values) != FIELDS:
        raise SummaryError("field contract changed")
    return values


def main() -> int:
    if len(sys.argv) != 5:
        return 64
    private_root, harness, shard, destination = sys.argv[1:]
    try:
        values = build(Path(private_root), harness, shard)
        output = Path(destination)
        if output.exists() or output.is_symlink() or not output.parent.is_dir():
            raise SummaryError("invalid summary destination")
        data = "".join(f"{key}={values[key]}\n" for key in FIELDS)
        output.write_text(data, encoding="ascii", newline="\n")
        output.chmod(0o600)
    except (OSError, UnicodeError, SummaryError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
