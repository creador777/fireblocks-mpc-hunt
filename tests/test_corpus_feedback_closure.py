from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HUNT = (ROOT / ".github" / "workflows" / "hunt.yml").read_text(encoding="utf-8")


def lane_to_harness(lane: str) -> str:
    r = subprocess.run(
        ["bash", str(ROOT / "scripts/brain_paths.sh"), "lane_to_harness", lane],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def corpus_dir_for(harness: str) -> str:
    r = subprocess.run(
        ["bash", str(ROOT / "scripts/brain_paths.sh"), "corpus_dir_for", harness],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


class CorpusFeedbackClosureTests(unittest.TestCase):
    def test_lane_to_harness_to_corpus_dir_round_trip(self) -> None:
        cases = {
            "cmp_general": "cmp_ecdsa_online",
            "cmp_r4_tn": "cmp_ecdsa_online_r4_tn",
            "cmp_dual": "cmp_ecdsa_online_dual",
        }
        for lane, expected_harness in cases.items():
            with self.subTest(lane=lane):
                harness = lane_to_harness(lane)
                self.assertEqual(harness, expected_harness)
                corpus_dir = corpus_dir_for(harness)
                self.assertEqual(corpus_dir, f"corpus/{expected_harness}")
                self.assertNotEqual(
                    corpus_dir_for("cmp_ecdsa_online"),
                    corpus_dir_for("cmp_ecdsa_online_dual"),
                )

    def test_workflow_materializes_lane_specific_private_corpus(self) -> None:
        hunt = HUNT
        block_start = hunt.index("Materialize deterministic 24-unit corpus window privately")
        block = hunt[block_start : hunt.index("Execute isolated shard", block_start)]
        self.assertIn("lane_to_harness", block)
        self.assertIn("FIREBLOCKS_LANE", block)
        self.assertIn("corpus_dir_for", block)
        self.assertIn("brain/${corpus_rel}", block)
        self.assertIn("GITHUB_WORKSPACE}/hunt/scripts/brain_paths.sh", block)

    def test_publish_and_aggregate_conserve_harness(self) -> None:
        for script in ("scripts/publish_ingest.sh", "scripts/aggregate_ingest.sh"):
            body = (ROOT / script).read_text(encoding="utf-8")
            self.assertIn("brain_paths.sh", body)
            self.assertNotIn("corpus/cmp_ecdsa_online\"", body)
            self.assertNotIn("corpus/${HARNESS}", body)

    def test_synthetic_dual_unit_reappears_next_wave(self) -> None:
        from scripts import materialize_window

        def add_unit(directory: Path, label: str) -> str:
            data = f"synthetic-{label}".encode()
            name = hashlib.sha1(data).hexdigest()
            (directory / name).write_bytes(data)
            return name

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            common = base / "common"
            priv_general = base / "priv_general"
            priv_dual = base / "priv_dual"
            common.mkdir()
            priv_general.mkdir()
            priv_dual.mkdir()
            add_unit(common, "common-0")
            dual_name = add_unit(priv_dual, "dual-unique")
            add_unit(priv_general, "general-unique")
            dest_bug = base / "dest_bug"
            dest_bug.mkdir()
            materialize_window.materialize(
                [str(dest_bug), "3", "15", "7", str(common), str(priv_general)]
            )
            bug_contains = dual_name in {p.name for p in dest_bug.iterdir()}
            self.assertFalse(bug_contains)
            dest_fix = base / "dest_fix"
            dest_fix.mkdir()
            materialize_window.materialize(
                [str(dest_fix), "3", "15", "7", str(common), str(priv_dual)]
            )
            fix_contains = dual_name in {p.name for p in dest_fix.iterdir()}
            self.assertTrue(fix_contains)

    def test_three_lanes_are_disjoint(self) -> None:
        dirs = {lane_to_harness(l) for l in ("cmp_general", "cmp_r4_tn", "cmp_dual")}
        self.assertEqual(len(dirs), 3)
        for h in dirs:
            self.assertRegex(corpus_dir_for(h), r"^corpus/cmp_ecdsa_online")


if __name__ == "__main__":
    unittest.main(verbosity=2)
