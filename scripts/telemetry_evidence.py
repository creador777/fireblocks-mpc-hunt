#!/usr/bin/env python3
"""Turn a shard's telemetry directory into one canonical, allowlisted document.

WHY THIS EXISTS. The reachability harness counts which wire cells it selected
and applied, but those counters were written to the runner's output directory
and never captured: package_incident.py only packages private_plain, so in the
cloud they died with the machine. A wave could report "no findings" with no way
to tell whether it had exercised anything at all.

WHAT IT GUARANTEES. Nothing from the harness reaches the bundle verbatim. The
input is parsed, every field is checked against a closed allowlist, and the
output is re-serialised from validated integers and vocabulary-checked short
strings. A key the harness invents, a cell name it makes up, or a byte of
corpus that somehow lands in the document cannot survive: they are rejected,
not filtered. That is the difference between a sanitiser and a redactor, and
only the first one is safe to point at attacker-influenced data.

WHAT IT DELIBERATELY DOES NOT DO. It does not decide whether a campaign is
ready to promote. scripts/validate_rt4.py does that, and it requires every
known cell to have been reached -- correct for a promotion gate, wrong here: a
short shard legitimately reaches only some cells, and refusing to package its
evidence would throw away the very measurement we are trying to keep.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


#: Espejo de CELLS en harness/cmp_ecdsa_online/src/telemetry_v2.cpp.
#: tests/test_harness_contract.py exige que coincidan.
CELL_KEYS = (
    "r1.mta_proofs[victim]|flip_bit",
    "r1.mta_proofs[victim]|zero",
    "r1.mta_proofs[victim]|truncate",
    "r4.si|extra_map_key",
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

DOCUMENT_SCHEMA = "rt4.telemetry/2"
EVIDENCE_SCHEMA = "rt4.evidence/1"

#: Un fichero por job. La paralelizacion maxima del runner es 8, asi que mas
#: de ocho documentos significa que alguien escribio en el directorio.
TELEMETRY_NAME = re.compile(r"telemetry-job(0|[1-9][0-9]*)\.json\Z")
MAX_JOBS = 8
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024

#: Vocabulario de las cadenas cortas que si se conservan (id de build,
#: compilador, sanitizers). Sin espacios, sin rutas, sin separadores: una ruta
#: privada o un fragmento de corpus no puede pasar por aqui.
VOCABULARY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")

#: Cota superior de cualquier contador. Un entero fuera de rango es corrupcion,
#: no un valor grande: el harness no puede ejecutar 2^40 casos en una ronda.
MAX_COUNTER = 1 << 40

#: Las marcas monotonas NO son contadores: cuentan nanosegundos desde el
#: arranque de la maquina, asi que en un runner con dias de uptime valen
#: ~1e15 y la cota de contador las rechazaria. 2^60 ns son 36 años, muy por
#: encima de cualquier valor legitimo y aun exacto en coma flotante.
MAX_NANOS = 1 << 60


class TelemetryError(RuntimeError):
    pass


def _expect_bounded(value: Any, field: str, ceiling: int) -> int:
    # bool es subclase de int en Python y no es un contador.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TelemetryError(f"non-integer value: {field}")
    if value < 0 or value > ceiling:
        raise TelemetryError(f"value out of range: {field}")
    return value


def _expect_int(value: Any, field: str) -> int:
    return _expect_bounded(value, field, MAX_COUNTER)


def _expect_nanos(value: Any, field: str) -> int:
    return _expect_bounded(value, field, MAX_NANOS)


def _expect_vocabulary(value: Any, field: str) -> str:
    if not isinstance(value, str) or not VOCABULARY.fullmatch(value):
        raise TelemetryError(f"value outside vocabulary: {field}")
    return value


def _expect_counter_map(value: Any, keys: tuple[str, ...], field: str) -> dict[str, int]:
    """Exact key set: not a subset, not a superset.

    An unknown key means the harness emitted a cell this build does not know
    about, and a missing one means the document was truncated. Both are
    rejected: quietly accepting either would publish counters that do not add
    up to what the equations below check.
    """
    if not isinstance(value, dict):
        raise TelemetryError(f"counter map expected: {field}")
    if set(value) != set(keys):
        raise TelemetryError(f"unexpected counter keys: {field}")
    return {key: _expect_int(value[key], f"{field}.{key}") for key in keys}


def _expect_exact_keys(document: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise TelemetryError(f"object expected: {field}")
    if set(document) != keys:
        raise TelemetryError(f"unexpected keys: {field}")
    return document


def parse_document(raw: Any, expected_job: int) -> dict[str, Any]:
    """Validate one telemetry document and return a canonical copy."""
    document = _expect_exact_keys(
        raw, {"schema", "identity", "build", "process", "counters"}, "document"
    )
    if document["schema"] != DOCUMENT_SCHEMA:
        raise TelemetryError("unknown document schema")

    identity = _expect_exact_keys(document["identity"], {"campaign", "fuzzer"}, "identity")
    build = _expect_exact_keys(document["build"], {"id", "compiler", "sanitizers"}, "build")
    process = _expect_exact_keys(
        document["process"],
        {"job_index", "parallelism", "started_monotonic_ns", "updated_monotonic_ns"},
        "process",
    )
    counters = _expect_exact_keys(
        document["counters"],
        {"execs", "door_rejects", "decoded", "selected", "applied",
         "not_applied", "verdicts"},
        "counters",
    )

    job_index = _expect_int(process["job_index"], "process.job_index")
    if job_index != expected_job:
        raise TelemetryError("job index does not match the file name")
    parallelism = _expect_int(process["parallelism"], "process.parallelism")
    if parallelism < 1 or parallelism > MAX_JOBS:
        raise TelemetryError("parallelism out of range")
    started = _expect_nanos(process["started_monotonic_ns"], "process.started")
    updated = _expect_nanos(process["updated_monotonic_ns"], "process.updated")
    if updated < started:
        raise TelemetryError("negative duration")

    execs = _expect_int(counters["execs"], "counters.execs")
    door_rejects = _expect_int(counters["door_rejects"], "counters.door_rejects")
    decoded = _expect_int(counters["decoded"], "counters.decoded")
    selected = _expect_counter_map(counters["selected"], CELL_KEYS, "selected")
    applied = _expect_counter_map(counters["applied"], CELL_KEYS, "applied")
    not_applied = _expect_counter_map(counters["not_applied"], CELL_KEYS, "not_applied")
    verdicts = _expect_counter_map(counters["verdicts"], VERDICT_KEYS, "verdicts")

    # Identidades aritmeticas: un documento que no cierra es corrupcion, y
    # publicar contadores que no suman es peor que no publicar ninguno.
    if door_rejects + decoded != execs:
        raise TelemetryError("execs equation does not close")
    if sum(selected.values()) != decoded:
        raise TelemetryError("selected equation does not close")
    for cell in CELL_KEYS:
        if applied[cell] + not_applied[cell] != selected[cell]:
            raise TelemetryError("applied equation does not close")
    if sum(verdicts.values()) != sum(applied.values()):
        raise TelemetryError("verdict equation does not close")

    return {
        "job_index": job_index,
        "parallelism": parallelism,
        "duration_ns": updated - started,
        "campaign": _expect_vocabulary(identity["campaign"], "identity.campaign"),
        "fuzzer": _expect_vocabulary(identity["fuzzer"], "identity.fuzzer"),
        "build": {
            "id": _expect_vocabulary(build["id"], "build.id"),
            "compiler": _expect_vocabulary(build["compiler"], "build.compiler"),
            "sanitizers": _expect_vocabulary(build["sanitizers"], "build.sanitizers"),
        },
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


def read_directory(root: Path) -> list[tuple[int, Path]]:
    """Enumerate telemetry files, rejecting anything that is not one."""
    if root.is_symlink() or not root.is_dir():
        raise TelemetryError("invalid telemetry directory")
    found: list[tuple[int, Path]] = []
    total = 0
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise TelemetryError("symlink rejected")
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise TelemetryError("nested or non-regular telemetry rejected")
            match = TELEMETRY_NAME.fullmatch(entry.name)
            if match is None:
                raise TelemetryError("unexpected telemetry name")
            if info.st_size == 0:
                raise TelemetryError("empty telemetry file")
            total += info.st_size
            if info.st_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                raise TelemetryError("telemetry size limit exceeded")
            found.append((int(match.group(1)), Path(entry.path)))
    if not found:
        raise TelemetryError("telemetry absent")
    if len(found) > MAX_JOBS:
        raise TelemetryError("too many telemetry documents")
    found.sort()
    if [index for index, _ in found] != list(range(len(found))):
        raise TelemetryError("job indices are not contiguous from zero")
    return found


def sanitize(root: Path, run_id: int, attempt: int, shard: int, harness: str) -> dict[str, Any]:
    """Validate a telemetry directory and return the canonical evidence."""
    jobs = []
    for index, path in read_directory(root):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TelemetryError("telemetry is not readable JSON") from error
        jobs.append(parse_document(raw, index))

    builds = {json.dumps(job["build"], sort_keys=True) for job in jobs}
    if len(builds) != 1:
        raise TelemetryError("documents disagree about the build")

    totals = {
        "execs": sum(job["counters"]["execs"] for job in jobs),
        "door_rejects": sum(job["counters"]["door_rejects"] for job in jobs),
        "decoded": sum(job["counters"]["decoded"] for job in jobs),
        "selected": {c: sum(j["counters"]["selected"][c] for j in jobs) for c in CELL_KEYS},
        "applied": {c: sum(j["counters"]["applied"][c] for j in jobs) for c in CELL_KEYS},
        "not_applied": {c: sum(j["counters"]["not_applied"][c] for j in jobs) for c in CELL_KEYS},
        "verdicts": {v: sum(j["counters"]["verdicts"][v] for j in jobs) for v in VERDICT_KEYS},
    }
    return {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id,
        "attempt": attempt,
        "shard": shard,
        "harness": harness,
        "build": jobs[0]["build"],
        "jobs": jobs,
        "totals": totals,
    }


def _check_job(raw: Any) -> dict[str, Any]:
    job = _expect_exact_keys(
        raw,
        {"job_index", "parallelism", "duration_ns", "campaign", "fuzzer",
         "build", "counters"},
        "job",
    )
    counters = _expect_exact_keys(
        job["counters"],
        {"execs", "door_rejects", "decoded", "selected", "applied",
         "not_applied", "verdicts"},
        "job.counters",
    )
    selected = _expect_counter_map(counters["selected"], CELL_KEYS, "selected")
    applied = _expect_counter_map(counters["applied"], CELL_KEYS, "applied")
    not_applied = _expect_counter_map(counters["not_applied"], CELL_KEYS, "not_applied")
    verdicts = _expect_counter_map(counters["verdicts"], VERDICT_KEYS, "verdicts")
    execs = _expect_int(counters["execs"], "execs")
    door_rejects = _expect_int(counters["door_rejects"], "door_rejects")
    decoded = _expect_int(counters["decoded"], "decoded")
    if door_rejects + decoded != execs or sum(selected.values()) != decoded:
        raise TelemetryError("job equations do not close")
    for cell in CELL_KEYS:
        if applied[cell] + not_applied[cell] != selected[cell]:
            raise TelemetryError("job equations do not close")
    if sum(verdicts.values()) != sum(applied.values()):
        raise TelemetryError("job equations do not close")
    build = _expect_exact_keys(job["build"], {"id", "compiler", "sanitizers"}, "job.build")
    return {
        "job_index": _expect_int(job["job_index"], "job_index"),
        "parallelism": _expect_bounded(job["parallelism"], "parallelism", MAX_JOBS),
        "duration_ns": _expect_nanos(job["duration_ns"], "duration_ns"),
        "campaign": _expect_vocabulary(job["campaign"], "campaign"),
        "fuzzer": _expect_vocabulary(job["fuzzer"], "fuzzer"),
        "build": {key: _expect_vocabulary(build[key], f"build.{key}")
                  for key in ("id", "compiler", "sanitizers")},
        "counters": {
            "execs": execs, "door_rejects": door_rejects, "decoded": decoded,
            "selected": selected, "applied": applied,
            "not_applied": not_applied, "verdicts": verdicts,
        },
    }


def check(path: Path, run_id: int, attempt: int, shard: int, harness: str) -> dict[str, Any]:
    """Re-validate a canonical document and prove it is byte-for-byte canonical.

    publish_ingest.sh calls this before pushing. Revalidating what this same
    module produced looks redundant until you notice the file crosses a
    workflow step boundary in between: whatever reaches the brain has to be
    provably the document the sanitiser would emit, not merely a file that was
    once produced by it.
    """
    try:
        raw = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TelemetryError("evidence is not readable JSON") from error
    evidence = _expect_exact_keys(
        raw,
        {"schema", "run_id", "attempt", "shard", "harness", "build", "jobs", "totals"},
        "evidence",
    )
    if evidence["schema"] != EVIDENCE_SCHEMA:
        raise TelemetryError("unknown evidence schema")
    if (evidence["run_id"], evidence["attempt"], evidence["shard"]) != (run_id, attempt, shard):
        raise TelemetryError("evidence identifies another shard")
    if evidence["harness"] != harness:
        raise TelemetryError("evidence identifies another surface")
    if not isinstance(evidence["jobs"], list) or not evidence["jobs"]:
        raise TelemetryError("evidence carries no jobs")
    if len(evidence["jobs"]) > MAX_JOBS:
        raise TelemetryError("too many jobs")

    jobs = [_check_job(job) for job in evidence["jobs"]]
    if [job["job_index"] for job in jobs] != list(range(len(jobs))):
        raise TelemetryError("job indices are not contiguous from zero")
    rebuilt = {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id,
        "attempt": attempt,
        "shard": shard,
        "harness": harness,
        "build": jobs[0]["build"],
        "jobs": jobs,
        "totals": {
            "execs": sum(j["counters"]["execs"] for j in jobs),
            "door_rejects": sum(j["counters"]["door_rejects"] for j in jobs),
            "decoded": sum(j["counters"]["decoded"] for j in jobs),
            "selected": {c: sum(j["counters"]["selected"][c] for j in jobs) for c in CELL_KEYS},
            "applied": {c: sum(j["counters"]["applied"][c] for j in jobs) for c in CELL_KEYS},
            "not_applied": {c: sum(j["counters"]["not_applied"][c] for j in jobs) for c in CELL_KEYS},
            "verdicts": {v: sum(j["counters"]["verdicts"][v] for j in jobs) for v in VERDICT_KEYS},
        },
    }
    # Comparacion por BYTES: detecta ademas reordenaciones, espacios y
    # duplicados que un compare de diccionarios dejaria pasar.
    if serialize(rebuilt) != path.read_bytes():
        raise TelemetryError("evidence is not byte-canonical")
    return rebuilt


def serialize(evidence: dict[str, Any]) -> bytes:
    """Deterministic bytes: same counters always produce the same blob."""
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii") + b"\n"


def main() -> int:
    checking = len(sys.argv) > 1 and sys.argv[1] == "--check"
    argv = sys.argv[2:] if checking else sys.argv[1:]
    if len(argv) != (5 if checking else 6):
        sys.stderr.write(
            "usage: telemetry_evidence.py DIR OUT RUN_ID ATTEMPT SHARD HARNESS\n"
            "       telemetry_evidence.py --check FILE RUN_ID ATTEMPT SHARD HARNESS\n")
        return 64
    try:
        numbers = argv[1:4] if checking else argv[2:5]
        run_id, attempt, shard = (int(value) for value in numbers)
    except ValueError:
        return 64
    harness = argv[-1]
    if not VOCABULARY.fullmatch(harness):
        return 64
    try:
        if checking:
            check(Path(argv[0]), run_id, attempt, shard, harness)
            return 0
        directory, out = Path(argv[0]), Path(argv[1])
        evidence = sanitize(directory, run_id, attempt, shard, harness)
        if out.exists() or out.is_symlink():
            raise TelemetryError("destination already exists")
        out.write_bytes(serialize(evidence))
    except TelemetryError as error:
        # El motivo es una cadena fija del propio codigo, nunca contenido del
        # documento: un mensaje que cite el input seria un canal de fuga.
        sys.stderr.write(f"TELEMETRY_FAIL_CLOSED reason={error}\n")
        return 65
    except OSError:
        sys.stderr.write("TELEMETRY_FAIL_CLOSED reason=io error\n")
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
