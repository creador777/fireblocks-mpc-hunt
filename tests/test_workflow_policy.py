from __future__ import annotations

from pathlib import Path
import re
import os
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
HUNT = (ROOT / ".github" / "workflows" / "hunt.yml").read_text(encoding="utf-8")
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
RUNNER = (ROOT / "scripts" / "run_fuzzer_shard.sh").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "docker" / "Dockerfile.fuzzer").read_text(encoding="utf-8")
FUZZER = (ROOT / "harness" / "cmp_ecdsa_online" / "src" / "fuzzer.cpp").read_text(
    encoding="utf-8"
)
PLANNER = ROOT / "scripts" / "plan_wave.sh"


class WorkflowPolicyTests(unittest.TestCase):
    def test_01_actions_are_full_sha_pinned(self) -> None:
        for workflow in (HUNT, CI):
            actions = re.findall(r"uses:\s+([^@\s]+)@([^\s]+)", workflow)
            self.assertTrue(actions)
            for _, reference in actions:
                self.assertRegex(reference, r"^[0-9a-f]{40}$")

    def test_02_no_dangerous_workflow_triggers_or_secret_inheritance(self) -> None:
        combined = HUNT + CI
        self.assertNotIn("pull_request_target", combined)
        self.assertNotIn("secrets: inherit", combined)
        self.assertNotIn("permissions: write-all", combined)
        self.assertNotIn("git add -A", combined)

    def test_03_schedule_is_disabled_unless_explicit_variable_is_true(self) -> None:
        self.assertIn("vars.FIREBLOCKS_HUNT_ENABLED == 'true'", HUNT)
        self.assertIn("workflow_dispatch", HUNT)
        self.assertIn('default: "1"', HUNT)
        self.assertIn('default: "300"', HUNT)

    def test_04_tokens_are_separate_and_credentials_are_not_persisted(self) -> None:
        self.assertIn("FIREBLOCKS_BRAIN_READ_TOKEN", HUNT)
        self.assertIn("FIREBLOCKS_BRAIN_WRITE_TOKEN", HUNT)
        self.assertIn('test "${READ_TOKEN}" != "${WRITE_TOKEN}"', HUNT)
        self.assertGreaterEqual(HUNT.count("persist-credentials: false"), 3)
        self.assertNotIn("secrets.GITHUB_TOKEN", HUNT)

    def test_05_raw_material_is_never_an_upload_path(self) -> None:
        upload_block = HUNT[HUNT.index("Upload encrypted bundle only") :]
        upload_block = upload_block[: upload_block.index("Publish corpus")]
        self.assertIn(".gpg", upload_block)
        self.assertNotIn("private_plain", upload_block)
        self.assertNotIn("fuzzer.raw.log", upload_block)
        self.assertNotIn("crash-*", upload_block)

    def test_06_encryption_and_cleanup_precede_upload_and_summary(self) -> None:
        encryption = HUNT.index("Encrypt evidence and verify plaintext cleanup")
        upload = HUNT.index("Upload encrypted bundle only")
        emit = HUNT.index("Emit only the seven-field public summary")
        self.assertLess(encryption, upload)
        self.assertLess(upload, emit)
        self.assertIn("test ! -e", HUNT[encryption:upload])

    def test_07_workflow_never_prints_raw_fuzzer_log(self) -> None:
        combined = HUNT + CI
        for forbidden in (
            "tail ",
            "cat fuzzer",
            "cat ${",
            "Base64:",
            "artifact_prefix=",
            "Test unit written",
        ):
            self.assertNotIn(forbidden, combined)

    def test_08_runner_propagates_container_status(self) -> None:
        self.assertIn('exit "${RC}"', RUNNER)
        self.assertIn("-error_exitcode=77", RUNNER)
        self.assertIn("-timeout_exitcode=70", RUNNER)
        self.assertIn("-oom_exitcode=71", RUNNER)

    def test_09_clean_sign_and_harness_fault_do_not_create_crash_artifacts(self) -> None:
        clean_block = FUZZER[FUZZER.index("case opus::verdict::CLEAN_REJECT") :]
        self.assertRegex(
            clean_block,
            r"case opus::verdict::CLEAN_REJECT:\s*"
            r"case opus::verdict::CLEAN_SIGN:\s*return 0;",
        )
        self.assertRegex(
            clean_block,
            r"case opus::verdict::HARNESS_FAULT:\s*"
            r'fail_closed\("harness_fault"\);',
        )

    def test_10_no_personal_paths_or_token_shapes(self) -> None:
        excluded_suffixes = {".next", ".v2", ".v3", ".pyc"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or any(path.name.endswith(value) for value in excluded_suffixes):
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            data = path.read_bytes().lower()
            self.assertNotIn(b"/c/users/", data, str(path))
            self.assertNotIn(b"c:\\users\\victor", data, str(path))
            self.assertNotIn(b"github_pat_", data, str(path))
            self.assertNotIn(b"ghp_", data, str(path))

    def test_11_linkage_check_never_prints_load_addresses(self) -> None:
        linkage_lines = [
            line
            for line in DOCKERFILE.splitlines()
            if "ldd /opt/fireblocks/bin/opus_cmp_fuzzer" in line
        ]
        # Una linea por binario enlazado. No se fija el numero: lo que importa
        # es que NINGUNA vuelque su salida a stdout, porque `ldd` imprime
        # direcciones de carga. Cada una debe redirigir a un fichero propio,
        # que despues se comprueba con grep y se borra.
        self.assertGreaterEqual(len(linkage_lines), 1)
        redirects = []
        for line in linkage_lines:
            self.assertIn(">", line, line.strip())
            target = line.split(">", 1)[1].split()[0]
            self.assertTrue(target.startswith("/tmp/"), target)
            self.assertTrue(target.endswith(".ldd"), target)
            redirects.append(target)
        self.assertEqual(len(set(redirects)), len(redirects),
                         "dos binarios comparten fichero de enlazado")
        for target in redirects:
            self.assertIn(f"grep -q 'not found' {target}", DOCKERFILE)
            self.assertIn(target, DOCKERFILE[DOCKERFILE.index("rm -f"):])

    def test_12_two_hour_100_core_tuple_is_exact_and_fail_closed(self) -> None:
        def plan(count: str, workers: str, seconds: str, approved: str, until: str):
            with tempfile.TemporaryDirectory() as tempdir:
                output_path = Path(tempdir) / "github-output"
                env = os.environ.copy()
                env["GITHUB_OUTPUT"] = str(output_path)
                result = subprocess.run(
                    ["bash", str(PLANNER), count, workers, seconds, approved, until],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                output = output_path.read_text() if output_path.exists() else ""
                return result, output

        now = int(time.time())
        valid_until = str(now + 600)
        result, output = plan("25", "4", "7200", "25x4x7200", valid_until)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("count=25\n", output)
        self.assertIn("seconds=7200\n", output)
        self.assertIn("workers=4\n", output)
        self.assertIn("profile=cloud\n", output)

        for approved, until in (
            ("", ""),
            ("25x4x900", valid_until),
            ("25x4x7200", str(now - 1)),
            ("25x4x7200", str(now + 1200)),
            ("25x4x7200", "not-an-epoch"),
        ):
            result, _ = plan("25", "4", "7200", approved, until)
            self.assertEqual(result.returncode, 64)

        for count, workers in (("15", "4"), ("25", "1")):
            result, _ = plan(count, workers, "7200", "25x4x7200", valid_until)
            self.assertEqual(result.returncode, 64)

        result, _ = plan(
            "25", "4", "20700", "25x4x20700", valid_until
        )
        self.assertEqual(result.returncode, 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
