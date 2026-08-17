from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "report_materialize_failure.py"
FALLBACK = "status=fail_closed code=materializer_internal\n"


class ReportMaterializeFailureTests(unittest.TestCase):
    def report(self, payload: bytes) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            sidecar = Path(temporary) / "materialize.err"
            sidecar.write_bytes(payload)
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(sidecar)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_known_closed_code_is_forwarded_exactly(self) -> None:
        result = self.report(b"status=fail_closed code=bucket_cap\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "status=fail_closed code=bucket_cap\n")
        self.assertEqual(result.stderr, "")

    def test_untrusted_payloads_collapse_to_one_generic_line(self) -> None:
        payloads = (
            b"status=fail_closed code=bucket_cap\nsecond line\n",
            b"status=fail_closed code=bucket_cap",
            b"private path /brain/corpus/0123456789abcdef\n",
            b"\xff\n",
            b"x" * 4097,
        )
        for payload in payloads:
            with self.subTest(payload=payload[:40]):
                result = self.report(payload)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, FALLBACK)
                self.assertEqual(result.stderr, "")
                self.assertNotIn("brain", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
