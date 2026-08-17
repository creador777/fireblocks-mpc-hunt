from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_pool_capacity.py"
AGGREGATE = (ROOT / "scripts" / "aggregate_ingest.sh").read_text(encoding="utf-8")


def add_unit(directory: Path, label: str) -> str:
    data = ("synthetic-pool-unit:" + label).encode("ascii")
    name = hashlib.sha1(data).hexdigest()
    (directory / name).write_bytes(data)
    return name


class PoolCapacityTests(unittest.TestCase):
    def run_validator(self, *directories: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *(str(path) for path in directories)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_valid_multi_prefix_inventory_passes_without_public_details(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            corpus.mkdir()
            for index in range(30):
                add_unit(corpus, str(index))
            result = self.run_validator(corpus)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "status=ok\n")
            self.assertEqual(result.stderr, "")

    def test_malformed_name_is_rejected_with_closed_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            corpus.mkdir()
            (corpus / "private-secret.txt").write_text("secret", encoding="ascii")
            result = self.run_validator(corpus)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "status=fail_closed code=source_name\n")
            self.assertNotIn("private-secret", result.stderr)

    def test_nested_entry_is_rejected_as_nonregular(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            corpus.mkdir()
            (corpus / ("0" * 40)).mkdir()
            result = self.run_validator(corpus)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, "status=fail_closed code=source_nonregular\n")

    def test_scanner_limits_are_reused_for_inventory_and_bucket_caps(self) -> None:
        from scripts import materialize_window

        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            corpus.mkdir()
            for index in range(3):
                add_unit(corpus, str(index))
            with mock.patch.object(materialize_window, "MAX_TOTAL_FILES", 2):
                with self.assertRaises(materialize_window.FailClosed) as caught:
                    materialize_window.scan_private_inventory([corpus])
            self.assertEqual(caught.exception.code, "file_count_cap")

            names = sorted(path.name for path in corpus.iterdir())
            chosen = names[0][:2]
            for index in range(100_000):
                if sum(path.name.startswith(chosen) for path in corpus.iterdir()) >= 2:
                    break
                add_unit(corpus, f"same-prefix-{index}")
            with mock.patch.object(materialize_window, "MAX_BUCKET_FILES", 1):
                with self.assertRaises(materialize_window.FailClosed) as caught:
                    materialize_window.scan_private_inventory([corpus])
            self.assertEqual(caught.exception.code, "bucket_cap")

    def test_declared_byte_overflow_has_its_own_closed_code(self) -> None:
        from scripts import materialize_window

        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            corpus.mkdir()
            add_unit(corpus, "larger-than-test-cap")
            with mock.patch.object(materialize_window, "MAX_TOTAL_BYTES", 1):
                with self.assertRaises(materialize_window.FailClosed) as caught:
                    materialize_window.scan_private_inventory([corpus])
            self.assertEqual(caught.exception.code, "total_size_cap")

    def test_bucket_byte_overflow_has_a_distinct_closed_code(self) -> None:
        from scripts import materialize_window

        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            corpus.mkdir()
            add_unit(corpus, "larger-than-bucket-test-cap")
            with mock.patch.object(materialize_window, "MAX_TOTAL_BYTES", 1024 * 1024), mock.patch.object(
                materialize_window, "MAX_BUCKET_BYTES", 1
            ):
                with self.assertRaises(materialize_window.FailClosed) as caught:
                    materialize_window.scan_private_inventory([corpus])
            self.assertEqual(caught.exception.code, "bucket_size_cap")

    def test_aggregate_validates_capacity_before_commit_and_push(self) -> None:
        gate = AGGREGATE.index("validate_pool_capacity.py")
        commit = AGGREGATE.index(" commit -q -m")
        push = AGGREGATE.index(" push -q origin")
        self.assertLess(gate, commit)
        self.assertLess(gate, push)
        self.assertIn("for harness in ${BRAIN_HARNESSES}", AGGREGATE)
        self.assertIn('[[ -e "${STAGE}/${corpus_rel}" || -L "${STAGE}/${corpus_rel}" ]]', AGGREGATE)
        self.assertNotIn("cat ", AGGREGATE[gate:commit])


if __name__ == "__main__":
    unittest.main(verbosity=2)
