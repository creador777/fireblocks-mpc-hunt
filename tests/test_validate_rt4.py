from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_rt4.py"
SPEC = importlib.util.spec_from_file_location("validate_rt4", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load validate_rt4")
validate_rt4 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_rt4)


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
RESULT_KEYS = {
    "schema",
    "telemetry_valid",
    "decision",
    "reason_codes",
    "jobs",
    "parallelism",
    "max_overlap",
    "totals",
}


def zero_map(keys: tuple[str, ...]) -> dict[str, int]:
    return {key: 0 for key in keys}


def make_doc(job: int, parallelism: int, start: int, end: int) -> dict[str, object]:
    selected = zero_map(CELL_KEYS)
    applied = zero_map(CELL_KEYS)
    not_applied = zero_map(CELL_KEYS)
    verdicts = zero_map(VERDICT_KEYS)
    cell = CELL_KEYS[job % len(CELL_KEYS)]
    selected[cell] = 1
    applied[cell] = 1
    verdicts["CLEAN-REJECT"] = 1
    return {
        "schema": "rt4.telemetry/2",
        "identity": {"campaign": "synthetic-r4", "fuzzer": "cmp-ecdsa-online"},
        "build": {
            "id": "synthetic-build",
            "compiler": "clang-synthetic",
            "sanitizers": "address,undefined",
        },
        "process": {
            "job_index": job,
            "parallelism": parallelism,
            "started_monotonic_ns": start,
            "updated_monotonic_ns": end,
        },
        "counters": {
            "execs": 1,
            "door_rejects": 0,
            "decoded": 1,
            "selected": selected,
            "applied": applied,
            "not_applied": not_applied,
            "verdicts": verdicts,
        },
    }


def make_complete_doc(job: int, parallelism: int, start: int, end: int) -> dict[str, object]:
    doc = make_doc(job, parallelism, start, end)
    counters = doc["counters"]
    assert isinstance(counters, dict)
    counters["execs"] = len(CELL_KEYS)
    counters["decoded"] = len(CELL_KEYS)
    counters["selected"] = {key: 1 for key in CELL_KEYS}
    counters["applied"] = {key: 1 for key in CELL_KEYS}
    counters["not_applied"] = {key: 0 for key in CELL_KEYS}
    counters["verdicts"] = zero_map(VERDICT_KEYS)
    counters["verdicts"]["CLEAN-REJECT"] = len(CELL_KEYS)
    return doc


class CollectorCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rt4-validator-test-")
        self.root = Path(self.temp.name)
        self.telemetry = self.root / "telemetry"
        self.claims = self.root / "claims"
        self.telemetry.mkdir()
        self.claims.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_job(self, doc: dict[str, object]) -> None:
        process = doc["process"]
        assert isinstance(process, dict)
        job = process["job_index"]
        (self.telemetry / f"telemetry-job{job}.json").write_text(
            json.dumps(doc, sort_keys=True), encoding="utf-8"
        )
        (self.claims / f"job-{job}").write_bytes(b"")

    def validate(self) -> dict[str, object]:
        return validate_rt4.validate(self.telemetry, self.claims)

    def assert_blocked(self, result: dict[str, object], reason: str) -> None:
        self.assertEqual(set(result), RESULT_KEYS)
        self.assertEqual(result["schema"], "rt4.validation/1")
        self.assertIs(result["telemetry_valid"], False)
        self.assertEqual(result["decision"], "SHADOW_BLOCKED")
        self.assertIn(reason, result["reason_codes"])
        for key in ("jobs", "parallelism", "max_overlap", "totals"):
            self.assertIsNone(result[key])

    def validate_separate(self, name: str, doc: dict[str, object]) -> dict[str, object]:
        telemetry = self.root / f"telemetry-{name}"
        claims = self.root / f"claims-{name}"
        telemetry.mkdir()
        claims.mkdir()
        (telemetry / "telemetry-job0.json").write_text(json.dumps(doc), encoding="utf-8")
        (claims / "job-0").write_bytes(b"")
        return validate_rt4.validate(telemetry, claims)

    def test_accepts_generations_and_measures_half_open_overlap(self) -> None:
        # Un job por celda: el validador exige que TODAS se alcancen, asi que
        # una cuenta fija de jobs empieza a dar CELL_UNREACHED en cuanto se
        # añade una celda -- que es como se rompio al llegar
        # r4.si|extra_map_key. Las ventanas se generan solapando cada job con
        # el siguiente y solo con el siguiente, asi que max_overlap vale 2
        # sea cual sea el numero de celdas.
        jobs = len(CELL_KEYS)
        self.assertGreaterEqual(jobs, 2, "hacen falta dos jobs para solapar")
        for job in range(jobs):
            self.write_job(make_doc(job, 2, 100 * job, 100 * job + 150))
        result = self.validate()
        self.assertEqual(set(result), RESULT_KEYS)
        self.assertIs(result["telemetry_valid"], True)
        self.assertEqual(result["decision"], "SHADOW_READY")
        self.assertEqual((result["jobs"], result["parallelism"], result["max_overlap"]),
                         (jobs, 2, 2))
        totals = result["totals"]
        assert isinstance(totals, dict)
        self.assertEqual((totals["execs"], totals["decoded"]), (jobs, jobs))
        self.assertEqual(sum(totals["selected"].values()), jobs)
        self.assertEqual(sum(totals["applied"].values()), jobs)
        self.assertEqual(totals["verdicts"]["CLEAN-REJECT"], jobs)

    def test_accepts_one_job_when_parallelism_is_eight(self) -> None:
        self.write_job(make_complete_doc(7, 8, 100, 200))
        result = self.validate()
        self.assertIs(result["telemetry_valid"], True)
        self.assertEqual((result["jobs"], result["parallelism"], result["max_overlap"]), (1, 8, 1))

    def test_blocks_unreached_and_vacuous_cells(self) -> None:
        self.assert_blocked(
            self.validate_separate("unreached", make_doc(0, 1, 100, 200)),
            "CELL_UNREACHED",
        )
        vacuous = make_complete_doc(0, 1, 100, 200)
        counters = vacuous["counters"]
        assert isinstance(counters, dict)
        counters["applied"][CELL_KEYS[0]] = 0
        counters["not_applied"][CELL_KEYS[0]] = 1
        counters["verdicts"]["CLEAN-REJECT"] -= 1
        self.assert_blocked(self.validate_separate("vacuous", vacuous), "VACUOUS_CELL")

    def test_blocks_empty_run(self) -> None:
        self.assert_blocked(self.validate(), "NO_JOBS")

    def test_blocks_missing_claim_and_missing_document(self) -> None:
        self.write_job(make_doc(0, 1, 100, 200))
        (self.claims / "job-0").unlink()
        self.assert_blocked(self.validate(), "CLAIM_DOCUMENT_MISMATCH")
        (self.telemetry / "telemetry-job0.json").unlink()
        (self.claims / "job-0").write_bytes(b"")
        self.assert_blocked(self.validate(), "CLAIM_DOCUMENT_MISMATCH")

    def test_blocks_duplicate_semantic_job_index(self) -> None:
        self.write_job(make_doc(0, 2, 100, 200))
        duplicate = make_doc(1, 2, 200, 300)
        process = duplicate["process"]
        assert isinstance(process, dict)
        process["job_index"] = 0
        (self.telemetry / "telemetry-job1.json").write_text(json.dumps(duplicate), encoding="utf-8")
        (self.claims / "job-1").write_bytes(b"")
        self.assert_blocked(self.validate(), "JOB_INDEX_MISMATCH")

    def test_blocks_duplicate_json_key(self) -> None:
        self.write_job(make_doc(0, 1, 100, 200))
        path = self.telemetry / "telemetry-job0.json"
        raw = path.read_text(encoding="utf-8")
        path.write_text(raw[:-1] + ',"schema":"rt4.telemetry/2"}', encoding="utf-8")
        self.assert_blocked(self.validate(), "DUPLICATE_JSON_KEY")

    def test_blocks_truncated_document(self) -> None:
        (self.telemetry / "telemetry-job0.json").write_bytes(b'{"schema":')
        (self.claims / "job-0").write_bytes(b"")
        self.assert_blocked(self.validate(), "INVALID_JSON")

    def test_blocks_temporary_extra_and_nested_entries(self) -> None:
        for label, entry in (("tmp", ".telemetry-job0.json.tmp"), ("extra", "notes.log")):
            with self.subTest(label=label):
                telemetry = self.root / label
                claims = self.root / f"{label}-claims"
                telemetry.mkdir()
                claims.mkdir()
                (telemetry / entry).write_bytes(b"synthetic")
                self.assert_blocked(validate_rt4.validate(telemetry, claims), "UNEXPECTED_ENTRY")
        self.write_job(make_doc(0, 1, 100, 200))
        (self.telemetry / "nested").mkdir()
        self.assert_blocked(self.validate(), "NON_REGULAR_ENTRY")

    def test_blocks_symlink(self) -> None:
        self.write_job(make_doc(0, 2, 100, 200))
        try:
            os.symlink(self.telemetry / "telemetry-job0.json", self.telemetry / "telemetry-job1.json")
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink unavailable: {error}")
        (self.claims / "job-1").write_bytes(b"")
        self.assert_blocked(self.validate(), "SYMLINK_ENTRY")

    def test_blocks_non_exact_maps(self) -> None:
        cases = []
        missing = make_doc(0, 1, 100, 200)
        del missing["counters"]["selected"][CELL_KEYS[-1]]
        cases.append(("missing-cell", missing, "SELECTED_MAP"))
        extra = make_doc(0, 1, 100, 200)
        extra["counters"]["applied"]["private.extra|forbidden"] = 0
        cases.append(("extra-cell", extra, "APPLIED_MAP"))
        verdict = make_doc(0, 1, 100, 200)
        del verdict["counters"]["verdicts"]["HARNESS-FAULT"]
        cases.append(("missing-verdict", verdict, "VERDICT_MAP"))
        for name, doc, reason in cases:
            with self.subTest(name=name):
                self.assert_blocked(self.validate_separate(name, doc), reason)

    def test_blocks_broken_equations(self) -> None:
        cases = []
        for name, reason in (
            ("execs", "EXECS_EQUATION"),
            ("selected", "SELECTED_EQUATION"),
            ("application", "APPLICATION_EQUATION"),
            ("verdict", "VERDICT_EQUATION"),
        ):
            doc = make_doc(0, 1, 100, 200)
            counters = doc["counters"]
            if name == "execs":
                counters["execs"] = 2
            elif name == "selected":
                counters["selected"][CELL_KEYS[0]] = 2
            elif name == "application":
                counters["not_applied"][CELL_KEYS[0]] = 1
            else:
                counters["verdicts"]["CLEAN-REJECT"] = 0
            cases.append((name, doc, reason))
        for name, doc, reason in cases:
            with self.subTest(name=name):
                self.assert_blocked(self.validate_separate(name, doc), reason)

    def test_blocks_heterogeneous_parallelism(self) -> None:
        self.write_job(make_doc(0, 2, 100, 200))
        self.write_job(make_doc(1, 3, 200, 300))
        self.assert_blocked(self.validate(), "PARALLELISM_MISMATCH")

    def test_blocks_overlap_above_parallelism(self) -> None:
        self.write_job(make_doc(0, 1, 100, 300))
        self.write_job(make_doc(1, 1, 200, 400))
        self.assert_blocked(self.validate(), "OVERLAP_EXCEEDS_PARALLELISM")

    def test_blocks_boolean_counter(self) -> None:
        doc = make_doc(0, 1, 100, 200)
        doc["counters"]["execs"] = True
        self.write_job(doc)
        self.assert_blocked(self.validate(), "COUNTER_VALUE")


if __name__ == "__main__":
    unittest.main()
