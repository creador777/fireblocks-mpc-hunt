#!/usr/bin/env python3
"""El saneador de telemetria: documento canonico y fallo cerrado.

Todo es sintetico. No hay red, ni corpus, ni GPG: eso lo prueba
tests/test_telemetry_pipeline.sh, que recorre cifrado, publicacion y
agregacion de punta a punta.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "telemetry_evidence", ROOT / "scripts" / "telemetry_evidence.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load telemetry_evidence")
telemetry_evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(telemetry_evidence)

CELL_KEYS = telemetry_evidence.CELL_KEYS
VERDICT_KEYS = telemetry_evidence.VERDICT_KEYS


def make_document(job: int = 0, *, applied: int = 3) -> dict:
    """Un documento que cierra todas las identidades aritmeticas."""
    selected = {cell: 0 for cell in CELL_KEYS}
    not_applied = {cell: 0 for cell in CELL_KEYS}
    selected[CELL_KEYS[job % len(CELL_KEYS)]] = applied
    verdicts = {verdict: 0 for verdict in VERDICT_KEYS}
    verdicts["CLEAN-REJECT"] = applied
    return {
        "schema": "rt4.telemetry/2",
        "identity": {"campaign": "sintetico", "fuzzer": "cmp-ecdsa-online"},
        "build": {"id": "v2-r4-extrakey", "compiler": "clang",
                  "sanitizers": "asan+ubsan"},
        "process": {"job_index": job, "parallelism": 1,
                    "started_monotonic_ns": 10 ** 15,
                    "updated_monotonic_ns": 10 ** 15 + 5},
        "counters": {
            "execs": applied + 2,
            "door_rejects": 2,
            "decoded": applied,
            "selected": selected,
            "applied": dict(selected),
            "not_applied": not_applied,
            "verdicts": verdicts,
        },
    }


class TelemetryEvidenceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "telemetry"
        self.dir.mkdir()

    def write(self, document: dict) -> None:
        job = document["process"]["job_index"]
        (self.dir / f"telemetry-job{job}.json").write_text(
            json.dumps(document), encoding="utf-8")

    def sanitize(self) -> dict:
        return telemetry_evidence.sanitize(self.dir, 7, 1, 3, "cmp_ecdsa_online_r4_tn")

    # --- camino feliz -----------------------------------------------------
    def test_counters_survive_and_totals_add_up(self) -> None:
        self.write(make_document(0, applied=3))
        evidence = self.sanitize()
        self.assertEqual(evidence["schema"], "rt4.evidence/1")
        self.assertEqual((evidence["run_id"], evidence["attempt"], evidence["shard"]),
                         (7, 1, 3))
        self.assertEqual(evidence["harness"], "cmp_ecdsa_online_r4_tn")
        self.assertEqual(sum(evidence["totals"]["applied"].values()), 3)
        self.assertEqual(evidence["totals"]["verdicts"]["CLEAN-REJECT"], 3)

    def test_serialization_is_deterministic(self) -> None:
        self.write(make_document(0))
        first = telemetry_evidence.serialize(self.sanitize())
        second = telemetry_evidence.serialize(self.sanitize())
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))

    def test_several_jobs_are_summed(self) -> None:
        for job in range(3):
            self.write(make_document(job, applied=2))
        evidence = self.sanitize()
        self.assertEqual(len(evidence["jobs"]), 3)
        self.assertEqual(sum(evidence["totals"]["selected"].values()), 6)

    # --- nada del harness pasa verbatim -----------------------------------
    def test_an_invented_key_is_rejected_not_filtered(self) -> None:
        document = make_document(0)
        document["counters"]["private_path"] = "/home/victor/secreto"
        self.write(document)
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_an_unknown_cell_is_rejected(self) -> None:
        document = make_document(0)
        document["counters"]["selected"]["r9.inventada|flip"] = 0
        self.write(document)
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_a_missing_cell_is_rejected(self) -> None:
        document = make_document(0)
        del document["counters"]["selected"][CELL_KEYS[-1]]
        self.write(document)
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_a_path_shaped_string_cannot_ride_in_a_vocabulary_field(self) -> None:
        for value in ("/home/victor/corpus", "a b", "x" * 65, "", "../etc"):
            with self.subTest(value=value):
                document = make_document(0)
                document["build"]["id"] = value
                self.write(document)
                with self.assertRaises(telemetry_evidence.TelemetryError):
                    self.sanitize()

    def test_only_allowlisted_fields_reach_the_output(self) -> None:
        self.write(make_document(0))
        evidence = self.sanitize()
        blob = telemetry_evidence.serialize(evidence).decode("ascii")
        self.assertNotIn("identity", blob)      # se aplana a campaign/fuzzer
        self.assertNotIn("monotonic", blob)     # solo sobrevive la duracion
        self.assertNotIn("schema\":\"rt4.telemetry", blob)

    # --- fallo cerrado ----------------------------------------------------
    def test_absent_telemetry_fails_closed(self) -> None:
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_missing_directory_fails_closed(self) -> None:
        telemetry_evidence_dir = Path(self.tmp.name) / "ausente"
        with self.assertRaises(telemetry_evidence.TelemetryError):
            telemetry_evidence.sanitize(telemetry_evidence_dir, 7, 1, 3,
                                        "cmp_ecdsa_online_r4_tn")

    def test_corrupt_json_fails_closed(self) -> None:
        (self.dir / "telemetry-job0.json").write_text("{no es json",
                                                      encoding="utf-8")
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_excess_documents_fail_closed(self) -> None:
        for job in range(telemetry_evidence.MAX_JOBS + 1):
            self.write(make_document(job, applied=1))
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_an_oversized_document_fails_closed(self) -> None:
        document = make_document(0)
        document["identity"]["campaign"] = "x"
        self.write(document)
        with (self.dir / "telemetry-job0.json").open("ab") as handle:
            handle.write(b" " * (telemetry_evidence.MAX_FILE_BYTES + 1))
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_a_gap_in_the_job_indices_fails_closed(self) -> None:
        self.write(make_document(0))
        self.write(make_document(2))
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_a_foreign_file_fails_closed(self) -> None:
        self.write(make_document(0))
        (self.dir / "fuzzer.raw.log").write_text("crudo", encoding="utf-8")
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    @unittest.skipIf(os.name == "nt", "Windows no crea symlinks sin privilegio")
    def test_a_symlink_fails_closed(self) -> None:
        self.write(make_document(0))
        (self.dir / "telemetry-job1.json").symlink_to(self.dir / "telemetry-job0.json")
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_equations_that_do_not_close_fail(self) -> None:
        cases = {
            "execs": lambda d: d["counters"].__setitem__("execs", 99),
            "selected": lambda d: d["counters"]["selected"].__setitem__(CELL_KEYS[0], 99),
            "applied": lambda d: d["counters"]["applied"].__setitem__(CELL_KEYS[0], 99),
            "verdicts": lambda d: d["counters"]["verdicts"].__setitem__("CRASH", 99),
        }
        for name, mutate in cases.items():
            with self.subTest(equation=name):
                document = make_document(0)
                mutate(document)
                self.write(document)
                with self.assertRaises(telemetry_evidence.TelemetryError):
                    self.sanitize()
                (self.dir / "telemetry-job0.json").unlink()

    def test_a_boolean_is_not_a_counter(self) -> None:
        document = make_document(0)
        document["counters"]["door_rejects"] = True
        self.write(document)
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    def test_documents_disagreeing_about_the_build_fail_closed(self) -> None:
        self.write(make_document(0, applied=1))
        second = make_document(1, applied=1)
        second["build"]["id"] = "otro-build"
        self.write(second)
        with self.assertRaises(telemetry_evidence.TelemetryError):
            self.sanitize()

    # --- check: lo que se publica es exactamente lo que se saneo ----------
    def test_check_accepts_the_canonical_document(self) -> None:
        self.write(make_document(0))
        out = Path(self.tmp.name) / "evidence.json"
        out.write_bytes(telemetry_evidence.serialize(self.sanitize()))
        telemetry_evidence.check(out, 7, 1, 3, "cmp_ecdsa_online_r4_tn")

    def test_check_rejects_a_tampered_counter(self) -> None:
        self.write(make_document(0))
        out = Path(self.tmp.name) / "evidence.json"
        evidence = self.sanitize()
        out.write_bytes(telemetry_evidence.serialize(evidence))
        tampered = copy.deepcopy(evidence)
        tampered["totals"]["execs"] += 1
        out.write_bytes(telemetry_evidence.serialize(tampered))
        with self.assertRaises(telemetry_evidence.TelemetryError):
            telemetry_evidence.check(out, 7, 1, 3, "cmp_ecdsa_online_r4_tn")

    def test_check_rejects_a_document_from_another_shard(self) -> None:
        self.write(make_document(0))
        out = Path(self.tmp.name) / "evidence.json"
        out.write_bytes(telemetry_evidence.serialize(self.sanitize()))
        for run, attempt, shard, harness in (
            (8, 1, 3, "cmp_ecdsa_online_r4_tn"),
            (7, 2, 3, "cmp_ecdsa_online_r4_tn"),
            (7, 1, 4, "cmp_ecdsa_online_r4_tn"),
            (7, 1, 3, "cmp_ecdsa_online"),
        ):
            with self.subTest(shard=(run, attempt, shard, harness)):
                with self.assertRaises(telemetry_evidence.TelemetryError):
                    telemetry_evidence.check(out, run, attempt, shard, harness)

    def test_check_rejects_a_reordered_but_equivalent_document(self) -> None:
        """Mismos datos, otros bytes: se rechaza igual.

        La comparacion es por bytes justamente para que 'equivalente' no sea
        una puerta trasera: lo que llega al brain tiene que ser el documento
        que el saneador emite, no uno que se le parece.
        """
        self.write(make_document(0))
        out = Path(self.tmp.name) / "evidence.json"
        evidence = self.sanitize()
        out.write_bytes(json.dumps(evidence, indent=2).encode("ascii"))
        with self.assertRaises(telemetry_evidence.TelemetryError):
            telemetry_evidence.check(out, 7, 1, 3, "cmp_ecdsa_online_r4_tn")


if __name__ == "__main__":
    unittest.main(verbosity=2)
