#!/usr/bin/env python3
"""Fail-closed validator for R4 per-job libFuzzer telemetry.

The validator never includes source paths, JSON values, exception messages, or
filenames in its result.  Its public result is an allowlisted aggregate only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


DOCUMENT_SCHEMA = "rt4.telemetry/2"
RESULT_SCHEMA = "rt4.validation/1"
MAX_DOCUMENT_BYTES = 1 << 20
MAX_COUNTER = (1 << 63) - 1

# Espejo exacto de CELLS en harness/cmp_ecdsa_online/src/telemetry_v2.cpp.
# tests/test_harness_contract.py exige que coincidan: el harness emite una
# clave por celda y este validador rechaza el documento entero si le sobra o
# le falta una, asi que una copia desactualizada invalida telemetria correcta.
CELL_KEYS = (
    "r1.mta_proofs[victim]|flip_bit",
    "r1.mta_proofs[victim]|zero",
    "r1.mta_proofs[victim]|truncate",
    "r4.si|extra_map_key",
    "dual.schedule|sequential",
    "dual.schedule|blocked",
    "dual.schedule|alternating",
)
VERDICT_KEYS = (
    "CLEAN-SIGN",
    "CLEAN-REJECT",
    "INVALID-SIGNATURE",
    "STATE-CORRUPTION",
    "CRASH",
    "TIMEOUT",
    "HARNESS-FAULT",
)

_TELEMETRY_NAME = re.compile(r"telemetry-job(0|[1-9][0-9]*)\.json\Z")
_CLAIM_NAME = re.compile(r"job-(0|[1-9][0-9]*)\Z")


class _ValidationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _blocked(*codes: str) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "telemetry_valid": False,
        "decision": "SHADOW_BLOCKED",
        "reason_codes": sorted(set(codes)) or ["INTERNAL_ERROR"],
        "jobs": None,
        "parallelism": None,
        "max_overlap": None,
        "totals": None,
    }


def _ready(
    jobs: int, parallelism: int, max_overlap: int, totals: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "telemetry_valid": True,
        "decision": "SHADOW_READY",
        "reason_codes": [],
        "jobs": jobs,
        "parallelism": parallelism,
        "max_overlap": max_overlap,
        "totals": totals,
    }


def _expect_exact_keys(value: Any, keys: Iterable[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise _ValidationError(code)
    return value


def _expect_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise _ValidationError(code)
    return value


def _expect_int(value: Any, code: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _ValidationError(code)
    lower = 1 if positive else 0
    if value < lower or value > MAX_COUNTER:
        raise _ValidationError(code)
    return value


def _expect_counter_map(value: Any, keys: tuple[str, ...], code: str) -> dict[str, int]:
    obj = _expect_exact_keys(value, keys, code)
    return {key: _expect_int(obj[key], code) for key in keys}


def _checked_add(left: int, right: int) -> int:
    result = left + right
    if result > MAX_COUNTER:
        raise _ValidationError("COUNTER_OVERFLOW")
    return result


def _strict_regular_files(
    directory: Path, pattern: re.Pattern[str], directory_code: str
) -> dict[int, Path]:
    try:
        if directory.is_symlink():
            raise _ValidationError("SYMLINK_ENTRY")
        directory_stat = directory.stat(follow_symlinks=False)
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise _ValidationError(directory_code)
        entries = list(os.scandir(directory))
    except _ValidationError:
        raise
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
        raise _ValidationError(directory_code) from None

    result: dict[int, Path] = {}
    for entry in entries:
        try:
            if entry.is_symlink():
                raise _ValidationError("SYMLINK_ENTRY")
            entry_stat = entry.stat(follow_symlinks=False)
        except _ValidationError:
            raise
        except OSError:
            raise _ValidationError("UNREADABLE_ENTRY") from None
        if not stat.S_ISREG(entry_stat.st_mode):
            raise _ValidationError("NON_REGULAR_ENTRY")
        match = pattern.fullmatch(entry.name)
        if match is None:
            raise _ValidationError("UNEXPECTED_ENTRY")
        index = int(match.group(1), 10)
        if index in result:
            raise _ValidationError("DUPLICATE_JOB_INDEX")
        result[index] = Path(entry.path)
    return result


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ValidationError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise _ValidationError("INVALID_JSON_NUMBER")


def _read_json(path: Path) -> Any:
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_DOCUMENT_BYTES:
            raise _ValidationError("INVALID_DOCUMENT_FILE")
        raw = path.read_bytes()
        after = path.stat(follow_symlinks=False)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise _ValidationError("DOCUMENT_CHANGED")
        if len(raw) != before.st_size:
            raise _ValidationError("DOCUMENT_CHANGED")
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_constant,
        )
    except _ValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _ValidationError("INVALID_JSON") from None
    except (FileNotFoundError, PermissionError, OSError):
        raise _ValidationError("UNREADABLE_DOCUMENT") from None


def _parse_document(document: Any, filename_job: int) -> dict[str, Any]:
    root = _expect_exact_keys(
        document,
        ("schema", "identity", "build", "process", "counters"),
        "DOCUMENT_SHAPE",
    )
    if root["schema"] != DOCUMENT_SCHEMA:
        raise _ValidationError("SCHEMA_MISMATCH")

    identity = _expect_exact_keys(
        root["identity"], ("campaign", "fuzzer"), "IDENTITY_SHAPE"
    )
    identity = {
        "campaign": _expect_string(identity["campaign"], "IDENTITY_VALUE"),
        "fuzzer": _expect_string(identity["fuzzer"], "IDENTITY_VALUE"),
    }
    build = _expect_exact_keys(
        root["build"], ("id", "compiler", "sanitizers"), "BUILD_SHAPE"
    )
    build = {
        "id": _expect_string(build["id"], "BUILD_VALUE"),
        "compiler": _expect_string(build["compiler"], "BUILD_VALUE"),
        "sanitizers": _expect_string(build["sanitizers"], "BUILD_VALUE"),
    }
    process = _expect_exact_keys(
        root["process"],
        (
            "job_index",
            "parallelism",
            "started_monotonic_ns",
            "updated_monotonic_ns",
        ),
        "PROCESS_SHAPE",
    )
    job_index = _expect_int(process["job_index"], "JOB_INDEX")
    if job_index != filename_job:
        raise _ValidationError("JOB_INDEX_MISMATCH")
    parallelism = _expect_int(process["parallelism"], "PARALLELISM", positive=True)
    started = _expect_int(process["started_monotonic_ns"], "TIMESTAMP")
    updated = _expect_int(process["updated_monotonic_ns"], "TIMESTAMP")
    if started >= updated:
        raise _ValidationError("INVALID_INTERVAL")

    counters = _expect_exact_keys(
        root["counters"],
        (
            "execs",
            "door_rejects",
            "decoded",
            "selected",
            "applied",
            "not_applied",
            "verdicts",
        ),
        "COUNTERS_SHAPE",
    )
    execs = _expect_int(counters["execs"], "COUNTER_VALUE")
    door_rejects = _expect_int(counters["door_rejects"], "COUNTER_VALUE")
    decoded = _expect_int(counters["decoded"], "COUNTER_VALUE")
    selected = _expect_counter_map(counters["selected"], CELL_KEYS, "SELECTED_MAP")
    applied = _expect_counter_map(counters["applied"], CELL_KEYS, "APPLIED_MAP")
    not_applied = _expect_counter_map(
        counters["not_applied"], CELL_KEYS, "NOT_APPLIED_MAP"
    )
    verdicts = _expect_counter_map(counters["verdicts"], VERDICT_KEYS, "VERDICT_MAP")

    if _checked_add(door_rejects, decoded) != execs:
        raise _ValidationError("EXECS_EQUATION")
    if sum(selected.values()) != decoded:
        raise _ValidationError("SELECTED_EQUATION")
    for key in CELL_KEYS:
        if _checked_add(applied[key], not_applied[key]) != selected[key]:
            raise _ValidationError("APPLICATION_EQUATION")
    if sum(verdicts.values()) != sum(applied.values()):
        raise _ValidationError("VERDICT_EQUATION")

    return {
        "identity": identity,
        "build": build,
        "job_index": job_index,
        "parallelism": parallelism,
        "started": started,
        "updated": updated,
        "counters": {
            "execs": execs,
            "door_rejects": door_rejects,
            "decoded": decoded,
            "selected": selected,
            "applied": applied,
            "not_applied": not_applied,
            "verdicts": verdicts,
        },
    }


def _aggregate(documents: list[dict[str, Any]]) -> dict[str, Any]:
    totals: dict[str, Any] = {
        "execs": 0,
        "door_rejects": 0,
        "decoded": 0,
        "selected": {key: 0 for key in CELL_KEYS},
        "applied": {key: 0 for key in CELL_KEYS},
        "not_applied": {key: 0 for key in CELL_KEYS},
        "verdicts": {key: 0 for key in VERDICT_KEYS},
    }
    for document in documents:
        counters = document["counters"]
        for scalar in ("execs", "door_rejects", "decoded"):
            totals[scalar] = _checked_add(totals[scalar], counters[scalar])
        for map_name, keys in (
            ("selected", CELL_KEYS),
            ("applied", CELL_KEYS),
            ("not_applied", CELL_KEYS),
            ("verdicts", VERDICT_KEYS),
        ):
            for key in keys:
                totals[map_name][key] = _checked_add(
                    totals[map_name][key], counters[map_name][key]
                )
    return totals


def _max_overlap(documents: list[dict[str, Any]]) -> int:
    # Half-open intervals: a job ending exactly when another starts does not
    # overlap it.  Strictly positive intervals are required during parsing.
    events: list[tuple[int, int]] = []
    for document in documents:
        events.append((document["started"], 1))
        events.append((document["updated"], -1))
    active = 0
    maximum = 0
    for _timestamp, delta in sorted(events, key=lambda item: (item[0], item[1])):
        active += delta
        if active < 0:
            raise _ValidationError("INVALID_INTERVAL_SET")
        maximum = max(maximum, active)
    if active != 0:
        raise _ValidationError("INVALID_INTERVAL_SET")
    return maximum


def validate(telemetry_dir: os.PathLike[str] | str, claims_dir: os.PathLike[str] | str) -> dict[str, Any]:
    """Validate one completed R4 run and return only allowlisted metadata."""
    try:
        telemetry = _strict_regular_files(
            Path(telemetry_dir), _TELEMETRY_NAME, "TELEMETRY_DIRECTORY"
        )
        claims = _strict_regular_files(Path(claims_dir), _CLAIM_NAME, "CLAIMS_DIRECTORY")
        if set(telemetry) != set(claims):
            raise _ValidationError("CLAIM_DOCUMENT_MISMATCH")
        if not telemetry:
            raise _ValidationError("NO_JOBS")

        documents = [_parse_document(_read_json(telemetry[index]), index) for index in sorted(telemetry)]
        if len({document["job_index"] for document in documents}) != len(documents):
            raise _ValidationError("DUPLICATE_JOB_INDEX")
        parallelisms = {document["parallelism"] for document in documents}
        if len(parallelisms) != 1:
            raise _ValidationError("PARALLELISM_MISMATCH")
        identities = {json.dumps(document["identity"], sort_keys=True) for document in documents}
        builds = {json.dumps(document["build"], sort_keys=True) for document in documents}
        if len(identities) != 1:
            raise _ValidationError("IDENTITY_MISMATCH")
        if len(builds) != 1:
            raise _ValidationError("BUILD_MISMATCH")

        parallelism = next(iter(parallelisms))
        max_overlap = _max_overlap(documents)
        if max_overlap > parallelism:
            raise _ValidationError("OVERLAP_EXCEEDS_PARALLELISM")
        totals = _aggregate(documents)
        for cell in CELL_KEYS:
            if totals["selected"][cell] == 0:
                raise _ValidationError("CELL_UNREACHED")
            if totals["applied"][cell] == 0:
                raise _ValidationError("VACUOUS_CELL")
        return _ready(len(documents), parallelism, max_overlap, totals)
    except _ValidationError as error:
        return _blocked(error.code)
    except Exception:
        # No exception text is returned: it can contain private paths or values.
        return _blocked("INTERNAL_ERROR")


def _write_atomic(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate R4 telemetry fail-closed")
    parser.add_argument("--telemetry-dir", required=True)
    parser.add_argument("--claims-dir", required=True)
    parser.add_argument("--output")
    arguments = parser.parse_args(argv)

    result = validate(arguments.telemetry_dir, arguments.claims_dir)
    if arguments.output:
        _write_atomic(Path(arguments.output), result)
    else:
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["telemetry_valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
