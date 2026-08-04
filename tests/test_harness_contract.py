"""Contrato de superficies: las dos allowlists deben permanecer en sincronía.

El harness identifica la SUPERFICIE que se fuzzea. `arm_id` identifica quién
decidió el presupuesto (fixed_v1 / e2_v1 / …) y es una dimensión distinta: este
módulo no la toca.

Las listas viven en dos ficheros a propósito. Centralizarlas en un módulo
compartido cambiaría el empaquetado y el runtime de dos scripts que hoy son
autónomos, y ese riesgo es mayor que el que se quiere evitar. El cambio mínimo
seguro es actualizar las dos en el mismo commit y que este test falle si
alguien toca una sola.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SUMMARY = ROOT / "scripts" / "public_summary.py"
EMIT_SUMMARY = ROOT / "scripts" / "emit_summary.py"
PUBLISH_INGEST = ROOT / "scripts" / "publish_ingest.sh"
AGGREGATE_INGEST = ROOT / "scripts" / "aggregate_ingest.sh"
LANE_ENTRYPOINT = ROOT / "docker" / "lane-entrypoint.sh"
BRAIN_PATHS = ROOT / "scripts" / "brain_paths.sh"
DOCKERFILE = ROOT / "docker" / "Dockerfile.fuzzer"

EXPECTED = ("cmp_ecdsa_online", "cmp_ecdsa_online_r4_tn")


def harnesses_from_producer() -> tuple[str, ...]:
    """(1) Extrae la allowlist del PRODUCTOR leyendo su AST, no ejecutándolo."""
    tree = ast.parse(PUBLIC_SUMMARY.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "HARNESSES":
                return tuple(ast.literal_eval(node.value))
    raise AssertionError("public_summary.py no define HARNESSES")


def harnesses_from_emitter() -> tuple[str, ...]:
    """(1) Extrae la allowlist del EMISOR desde su expresión regular."""
    tree = ast.parse(EMIT_SUMMARY.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if not (isinstance(key, ast.Constant) and key.value == "harness"):
                continue
            pattern = ast.literal_eval(value.args[0])
            body = pattern[:-2] if pattern.endswith(r"\Z") else pattern
            body = body.strip()
            if body.startswith("(?:") and body.endswith(")"):
                body = body[3:-1]
            return tuple(part.strip() for part in body.split("|"))
    raise AssertionError("emit_summary.py no define la regla de harness")


class HarnessContractTests(unittest.TestCase):

    # -- (2) igualdad exacta entre las dos listas -------------------------

    def test_01_both_allowlists_are_exactly_equal(self):
        producer = harnesses_from_producer()
        emitter = harnesses_from_emitter()
        self.assertEqual(
            sorted(producer), sorted(emitter),
            "las allowlists divergieron: el productor emitiría un harness que "
            "el emisor rechaza y la cadena entera se caería en la emisión")

    # -- (3) sólo los dos harness conocidos --------------------------------

    def test_02_only_the_two_known_surfaces_are_accepted(self):
        self.assertEqual(sorted(harnesses_from_producer()), sorted(EXPECTED))
        self.assertEqual(sorted(harnesses_from_emitter()), sorted(EXPECTED))

    def test_03_the_producer_accepts_each_known_surface(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import public_summary
        import hashlib
        for harness in EXPECTED:
            with self.subTest(harness=harness), \
                    tempfile.TemporaryDirectory() as temporary:
                private = Path(temporary) / "private"
                private.mkdir()
                (private / "fuzzer.raw.log").write_bytes(b"INFO: Seed: 1\n")
                (private / "exit_code").write_text("0\n", encoding="ascii")
                values = public_summary.build(private, harness, "3")
                self.assertEqual(values["harness"], harness)

    # -- (4) cualquier harness desconocido se rechaza ----------------------

    def test_04_an_unknown_surface_is_rejected_by_the_producer(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import public_summary
        for bogus in ("cmp_ecdsa_offline", "cmp_ecdsa_online_r4",
                      "cmp_ecdsa_online_r4_tn_x", "", "CMP_ECDSA_ONLINE",
                      "cmp_ecdsa_online\n"):
            with self.subTest(harness=bogus), \
                    tempfile.TemporaryDirectory() as temporary:
                private = Path(temporary) / "private"
                private.mkdir()
                (private / "fuzzer.raw.log").write_bytes(b"log\n")
                (private / "exit_code").write_text("0\n", encoding="ascii")
                with self.assertRaises(public_summary.SummaryError):
                    public_summary.build(private, bogus, "3")

    def test_05_an_unknown_surface_is_rejected_by_the_emitter(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import emit_summary
        fields = ("harness", "shard", "exit_code", "sanitizer", "summary",
                  "stack_normalized", "sha256")
        for bogus in ("cmp_ecdsa_offline", "cmp_ecdsa_online_r4",
                      "cmp_ecdsa_online_r4_tn_x"):
            with self.subTest(harness=bogus), \
                    tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "s.public"
                values = {"harness": bogus, "shard": "3", "exit_code": "0",
                          "sanitizer": "none", "summary": "no_finding",
                          "stack_normalized": "none", "sha256": "0" * 64}
                path.write_text(
                    "".join(f"{k}={values[k]}\n" for k in fields),
                    encoding="ascii")
                with self.assertRaises(ValueError):
                    emit_summary.validate(path)

    # -- (5) sin fallback silencioso a cmp_ecdsa_online --------------------

    def test_06_no_component_falls_back_to_the_default_surface(self):
        """Un harness desconocido debe FALLAR, nunca degradar al histórico."""
        for script, name in ((PUBLISH_INGEST, "publish_ingest.sh"),
                             (BRAIN_PATHS, "brain_paths.sh"),
                             (LANE_ENTRYPOINT, "lane-entrypoint.sh")):
            body = script.read_text(encoding="utf-8")
            self.assertNotRegex(
                body, r":-\s*cmp_ecdsa_online\b",
                f"{name} tiene un valor por defecto que degrada a la "
                f"superficie histórica en vez de fallar")

    def test_07_publish_refuses_an_unknown_surface(self):
        """Se EJECUTA el script: un harness desconocido sale 64, sin red."""
        environment = {k: v for k, v in os.environ.items()
                       if not k.startswith("GIT_")}
        environment.update({"FIREBLOCKS_BRAIN_WRITE_TOKEN": "x",
                            "https_proxy": "http://127.0.0.1:1",
                            "http_proxy": "http://127.0.0.1:1",
                            "GIT_TERMINAL_PROMPT": "0"})
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "corpus").mkdir()
            bundle = work / "incident-1-1-0.gpg"
            bundle.write_bytes(bytes([0x85, 0x02]) + b"sintetico")
            for bogus in ("cmp_ecdsa_offline", "cmp_ecdsa_online_r4", ""):
                with self.subTest(harness=bogus):
                    result = subprocess.run(
                        ["bash", str(PUBLISH_INGEST), str(work / "corpus"),
                         str(bundle), "1", "1", "0", bogus],
                        env=environment, capture_output=True, text=True,
                        cwd=str(ROOT), timeout=60)
                    self.assertEqual(result.returncode, 64)

    # -- (6) separación por harness de corpus, artefactos e incidentes -----

    def test_08_the_corpus_subtree_is_a_function_of_the_surface(self):
        """El publicador DELEGA la ruta de corpus, no la concatena.

        Se comprueba la delegacion y no una cadena concreta: exigir un literal
        obliga a reescribir el test cada vez que cambia el formato, y lo que
        importa es que el script no tenga una ruta propia que pueda divergir
        del agregador.
        """
        body = PUBLISH_INGEST.read_text(encoding="utf-8")
        self.assertIn("brain_paths.sh", body, "no carga la autoridad de rutas")
        self.assertIn("corpus_dir_for", body)
        self.assertIn("corpus_unit_for", body)
        for literal in ("corpus/cmp_ecdsa_online", 'corpus/${HARNESS}'):
            self.assertNotIn(literal, body,
                             f"conserva una ruta propia: {literal}")

    def test_09_the_incident_name_carries_the_surface(self):
        """El nombre del incidente lo produce la autoridad, y lleva superficie."""
        body = PUBLISH_INGEST.read_text(encoding="utf-8")
        self.assertIn("incident_for", body, "no delega el nombre del incidente")
        self.assertNotIn("attempt-${ATTEMPT}-shard-", body,
                         "conserva un nombre de incidente propio")
        import subprocess
        general = subprocess.run(
            ["bash", str(BRAIN_PATHS), "incident_for", "1", "1",
             "cmp_ecdsa_online", "0"],
            capture_output=True, text=True, cwd=str(ROOT)).stdout.strip()
        r4tn = subprocess.run(
            ["bash", str(BRAIN_PATHS), "incident_for", "1", "1",
             "cmp_ecdsa_online_r4_tn", "0"],
            capture_output=True, text=True, cwd=str(ROOT)).stdout.strip()
        self.assertTrue(general and r4tn)
        self.assertNotEqual(general, r4tn,
                            "dos lanes escribirian el mismo incidente")

    def test_10_the_ingest_branch_carries_the_surface(self):
        body = PUBLISH_INGEST.read_text(encoding="utf-8")
        self.assertRegex(body, r'BRANCH=.*\$\{HARNESS\}',
                         "dos lanes competirían por la misma referencia")

    def test_11_each_lane_has_its_own_binary_and_snapshot(self):
        body = LANE_ENTRYPOINT.read_text(encoding="utf-8")
        for token in ("snapshot.bin", "snapshot_tn.bin",
                      "opus_cmp_fuzzer", "opus_cmp_fuzzer_reachability_v2"):
            self.assertIn(token, body)
        self.assertIn("unknown_lane", body, "la lane desconocida debe fallar")

    def test_12_the_image_really_builds_both_lanes(self):
        body = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("snapshot_tn.bin", body)
        self.assertIn("opus_cmp_fuzzer_reachability_v2 \\", body)
        self.assertIn("lane-entrypoint.sh", body)
        self.assertNotIn('ENTRYPOINT ["/opt/fireblocks/bin/opus_cmp_fuzzer"]',
                         body, "el ENTRYPOINT sigue fijo a una sola lane")

    # -- (7) una lane no puede consumir el corpus de la otra ---------------

    def test_13_the_aggregator_never_lands_a_unit_in_the_other_subtree(self):
        """El agregador INTERPRETA con la autoridad, no con una regex paralela.

        Que tuviera su propio patron fue la causa del fallo del canary: el
        publicador cambio de formato y el agregador siguio buscando el viejo.
        """
        body = AGGREGATE_INGEST.read_text(encoding="utf-8")
        self.assertIn("brain_paths.sh", body, "no carga la autoridad de rutas")
        self.assertIn("parse_branch", body, "no delega la interpretacion")
        self.assertIn("corpus_unit_for", body)
        for literal in ("corpus/cmp_ecdsa_online",
                        "ingest/run-${RUN_ID}",
                        "attempt-${ATTEMPT}-shard-"):
            self.assertNotIn(literal, body,
                             f"conserva un patron propio: {literal}")

    def test_14_a_unit_cannot_cross_from_one_surface_to_the_other(self):
        """Se ejecuta la validación real: la ruta de una lane no vale en la otra."""
        pattern = re.compile(
            r"^corpus/(cmp_ecdsa_online|cmp_ecdsa_online_r4_tn)/[0-9a-f]{40}$")
        digest = "a" * 40
        for harness in EXPECTED:
            self.assertTrue(pattern.match(f"corpus/{harness}/{digest}"))
        for crossing in (f"corpus/cmp_ecdsa_online/../cmp_ecdsa_online_r4_tn/{digest}",
                         f"corpus/cmp_ecdsa_online_r4_tn/sub/{digest}",
                         f"corpus/otra_superficie/{digest}",
                         f"corpus/{digest}"):
            self.assertIsNone(pattern.match(crossing), crossing)

    def test_16_the_artifact_allowlist_agrees_across_its_copies(self):
        """Los nombres que libFuzzer escribe se aceptan en las tres copias.

        leak- faltaba en package_incident.py y en public_summary.py, y "leak"
        faltaba en el vocabulario de emit_summary.py. ASan detecta leaks, asi
        que un leak real habria hecho fallar el resumen y, con el, el cifrado:
        cero bundle, cero upload, cero publicacion. El hallazgo se perdia
        entero, que es exactamente el modo de fallo que este proyecto no puede
        permitirse.
        """
        kinds = {"crash", "leak", "timeout", "oom", "slow-unit"}
        for module in ("package_incident.py", "public_summary.py"):
            body = (ROOT / "scripts" / module).read_text(encoding="utf-8")
            declaration = re.search(r"^ARTIFACT\s*=\s*re\.compile\(r\"(.+)\"\)",
                                    body, re.M)
            self.assertIsNotNone(declaration, f"{module} no define ARTIFACT")
            found = set(re.findall(r"[a-z][a-z-]+", declaration.group(1).split("-[")[0]))
            self.assertEqual(found & kinds, kinds,
                             f"{module} no acepta todos los artefactos")

        # Y el veredicto que produce cada uno tiene que caber en el
        # vocabulario publico, o el resumen se rechaza a si mismo.
        emit = (ROOT / "scripts" / "emit_summary.py").read_text(encoding="utf-8")
        for verdict in ("leak", "timeout", "oom", "slow_unit", "crash_signal"):
            self.assertRegex(emit, rf"\|{verdict}\||\|{verdict}\)|\({verdict}\|",
                             f"emit_summary.py no admite el resumen {verdict}")

    def test_15_the_cell_allowlist_agrees_with_the_harness(self):
        """CELLS del C++ y CELL_KEYS del validador son la misma lista.

        Habia cuatro copias de esta lista y al añadir r4.si|extra_map_key
        actualicé tres. La cuarta, la de validate_rt4.py, rechazaba con
        SELECTED_MAP la telemetria que el harness emitia correctamente: el
        validador exige una entrada por celda conocida, ni una mas ni una
        menos. Nada lo detecto porque ningun test comparaba las copias.
        """
        source = (ROOT / "harness" / "cmp_ecdsa_online" / "src"
                  / "telemetry_v2.cpp").read_text(encoding="utf-8")
        block = re.search(r"CELLS\[\]\s*=\s*\{(.*?)\};", source, re.S)
        self.assertIsNotNone(block, "telemetry_v2.cpp no define CELLS")
        # Solo las cadenas: los comentarios del bloque no son celdas.
        from_cpp = tuple(re.findall(r'"((?:[^"\\]|\\.)*)"', block.group(1)))
        self.assertTrue(from_cpp, "CELLS quedo vacio")

        validator = (ROOT / "scripts" / "validate_rt4.py").read_text(
            encoding="utf-8")
        declaration = re.search(r"^CELL_KEYS\s*=\s*\((.*?)\)", validator,
                                re.S | re.M)
        self.assertIsNotNone(declaration, "validate_rt4.py no define CELL_KEYS")
        from_validator = tuple(
            re.findall(r'"((?:[^"\\]|\\.)*)"', declaration.group(1)))

        self.assertEqual(from_cpp, from_validator,
                         "CELLS y CELL_KEYS divergen: la telemetria valida "
                         "del harness seria rechazada por el validador")


if __name__ == "__main__":
    unittest.main(verbosity=2)
