from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import materialize_window


def add_unit(directory: Path, label: str) -> str:
    data = ("synthetic-window-unit:" + label).encode("ascii")
    name = hashlib.sha1(data).hexdigest()
    (directory / name).write_bytes(data)
    return name


def add_unit_with_prefix(directory: Path, prefix: str, label: str) -> str:
    for nonce in range(100_000):
        data = f"synthetic-window-unit:{label}:{nonce}".encode("ascii")
        name = hashlib.sha1(data).hexdigest()
        if name.startswith(prefix):
            (directory / name).write_bytes(data)
            return name
    raise AssertionError(f"unable to synthesize prefix {prefix}")


class MaterializeWindowTests(unittest.TestCase):
    def make_sources(
        self, base: Path, common_count: int, private_count: int
    ) -> tuple[Path, Path, list[str], list[str]]:
        common = base / "common"
        private = base / "private"
        common.mkdir()
        private.mkdir()
        common_names = [add_unit(common, f"common-{i:03d}") for i in range(common_count)]
        private_names = [add_unit(private, f"private-{i:03d}") for i in range(private_count)]
        return common, private, sorted(common_names), sorted(private_names)

    def call(
        self,
        destination: Path,
        shard: int,
        count: int,
        wave: int,
        common: Path,
        private: Path,
    ) -> tuple[int, int, int, int | None, int, int, int, str, str | None, int]:
        return materialize_window.materialize(
            [str(destination), str(shard), str(count), str(wave), str(common), str(private)]
        )

    def test_one_common_never_materializes_more_than_24_total(self) -> None:
        # Catches using WINDOW_SIZE as private capacity before adding common units.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, common_names, _ = self.make_sources(base, 1, 0)
            for index in range(40):
                add_unit_with_prefix(private, "00", f"capacity-{index}")
            destination = base / "destination"
            destination.mkdir()
            result = self.call(destination, 0, 1, 0, common, private)
            selected = sorted(path.name for path in destination.iterdir())
            self.assertEqual(len(selected), 24)
            self.assertEqual(result[5:7], (1, 23))
            self.assertIn(common_names[0], selected)

    def test_23_common_leaves_capacity_for_exactly_one_private_unit(self) -> None:
        # Catches forgetting that common units consume the same total 24-file budget.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, common_names, _ = self.make_sources(base, 23, 10)
            destination = base / "destination"
            destination.mkdir()
            result = self.call(destination, 0, 1, 0, common, private)
            selected = {path.name for path in destination.iterdir()}
            self.assertEqual(len(selected), 24)
            self.assertEqual(result[5:7], (23, 1))
            self.assertTrue(set(common_names).issubset(selected))

    def test_common_must_contain_between_1_and_23_units(self) -> None:
        # Catches accepting an empty common set or a set that exhausts capacity.
        for common_count in (0, 24):
            with self.subTest(common_count=common_count), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                common, private, _, _ = self.make_sources(base, common_count, 3)
                destination = base / "destination"
                destination.mkdir()
                with self.assertRaises(materialize_window.FailClosed) as caught:
                    self.call(destination, 0, 1, 0, common, private)
                self.assertEqual(caught.exception.code, "common_capacity")
                self.assertEqual(list(destination.iterdir()), [])

    def test_every_source_is_validated_before_any_window_is_selected(self) -> None:
        # Catches validating only the units that happen to land in this shard.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, _, _ = self.make_sources(base, 1, 60)
            (private / "unexpected-report.txt").write_text("synthetic", encoding="ascii")
            destination = base / "destination"
            destination.mkdir()
            with self.assertRaises(materialize_window.FailClosed) as caught:
                self.call(destination, 0, 1, 0, common, private)
            self.assertEqual(caught.exception.code, "source_name")
            self.assertEqual(list(destination.iterdir()), [])

    def test_valid_common_private_overlap_is_validated_then_deduplicated(self) -> None:
        # Catches rejecting a public seed that the additive private master already learned.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, common_names, _ = self.make_sources(base, 1, 0)
            overlap = common_names[0]
            (private / overlap).write_bytes((common / overlap).read_bytes())
            for index in range(40):
                add_unit_with_prefix(private, overlap[:2], f"overlap-{index}")
            destination = base / "destination"
            destination.mkdir()
            result = self.call(destination, 0, 1, 0, common, private)
            selected = [path.name for path in destination.iterdir()]
            self.assertEqual(len(selected), 24)
            self.assertEqual(selected.count(overlap), 1)
            self.assertEqual(result[5:7], (1, 23))

    def test_invalid_overlapping_name_is_rejected_before_deduplication(self) -> None:
        # Catches dropping common-name entries before validating private bytes.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, common_names, _ = self.make_sources(base, 1, 0)
            overlap = common_names[0]
            (private / overlap).write_bytes(b"wrong-private-overlap-content")
            destination = base / "destination"
            destination.mkdir()
            with self.assertRaises(materialize_window.FailClosed) as caught:
                self.call(destination, 0, 1, 0, common, private)
            self.assertEqual(caught.exception.code, "content_hash")
            self.assertEqual(list(destination.iterdir()), [])

    def test_retry_of_same_wave_and_shard_is_bit_for_bit_deterministic(self) -> None:
        # Catches incorporating run-attempt, time, filesystem order, or randomness.
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, _, _ = self.make_sources(base, 2, 70)
            first = base / "first"
            second = base / "second"
            first.mkdir()
            second.mkdir()
            result_first = self.call(first, 3, 5, 7, common, private)
            result_second = self.call(second, 3, 5, 7, common, private)
            names_first = sorted(path.name for path in first.iterdir())
            names_second = sorted(path.name for path in second.iterdir())
            self.assertEqual(result_first, result_second)
            self.assertEqual(names_first, names_second)
            self.assertEqual(len(result_first), 10)
            self.assertRegex(result_first[8] or "", r"^[0-9a-f]{2}$")
            self.assertLessEqual(len(names_first), materialize_window.WINDOW_SIZE)

    def test_inventory_can_exceed_bucket_cap_when_each_prefix_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, _, _ = self.make_sources(base, 1, 0)
            for prefix in ("00", "01", "02"):
                for index in range(2):
                    add_unit_with_prefix(private, prefix, f"{prefix}-{index}")
            destination = base / "destination"
            destination.mkdir()
            with mock.patch.object(materialize_window, "MAX_TOTAL_FILES", 8), mock.patch.object(
                materialize_window, "MAX_BUCKET_FILES", 2
            ):
                result = self.call(destination, 0, 1, 0, common, private)
            self.assertEqual(result[8], "00")
            self.assertEqual(result[6], 2)

    def test_separate_shards_choose_separate_sorted_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, _, _ = self.make_sources(base, 1, 0)
            for prefix in ("20", "a0", "f0"):
                add_unit_with_prefix(private, prefix, prefix)
            prefixes = []
            for shard in range(3):
                destination = base / f"destination-{shard}"
                destination.mkdir()
                prefixes.append(self.call(destination, shard, 3, 0, common, private)[8])
            self.assertEqual(prefixes, ["20", "a0", "f0"])

    def test_hash_mismatch_in_unselected_prefix_is_deferred_until_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, _, _ = self.make_sources(base, 1, 0)
            add_unit_with_prefix(private, "00", "valid")
            corrupt_name = add_unit_with_prefix(private, "ff", "corrupt-name")
            (private / corrupt_name).write_bytes(b"content-does-not-match-name")

            first = base / "first"
            first.mkdir()
            self.assertEqual(self.call(first, 0, 2, 0, common, private)[8], "00")

            second = base / "second"
            second.mkdir()
            with self.assertRaises(materialize_window.FailClosed) as caught:
                self.call(second, 1, 2, 0, common, private)
            self.assertEqual(caught.exception.code, "content_hash")
            self.assertEqual(list(second.iterdir()), [])

    def test_inventory_and_selected_bucket_caps_have_distinct_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, _, _ = self.make_sources(base, 1, 0)
            for index in range(3):
                add_unit_with_prefix(private, "ab", f"ab-{index}")

            destination = base / "inventory-cap"
            destination.mkdir()
            with mock.patch.object(materialize_window, "MAX_TOTAL_FILES", 2):
                with self.assertRaises(materialize_window.FailClosed) as caught:
                    self.call(destination, 0, 1, 0, common, private)
            self.assertEqual(caught.exception.code, "file_count_cap")

            destination = base / "bucket-cap"
            destination.mkdir()
            with mock.patch.object(materialize_window, "MAX_TOTAL_FILES", 10), mock.patch.object(
                materialize_window, "MAX_BUCKET_FILES", 2
            ):
                with self.assertRaises(materialize_window.FailClosed) as caught:
                    self.call(destination, 0, 1, 0, common, private)
            self.assertEqual(caught.exception.code, "bucket_cap")

    def test_large_bucket_visit_wraps_by_its_local_window_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, _, _ = self.make_sources(base, 1, 0)
            for index in range(5):
                add_unit_with_prefix(private, "7e", f"7e-{index}")
            destination = base / "destination"
            destination.mkdir()
            with mock.patch.object(materialize_window, "WINDOW_SIZE", 3):
                result = self.call(destination, 0, 1, 4, common, private)
            self.assertEqual(result[8:], ("7e", 4))
            self.assertEqual(result[4], 3)
            self.assertEqual(result[3], 1)

    def test_nonzero_wave_selects_exact_prefix_visit_and_local_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common, private, common_names, _ = self.make_sources(base, 1, 0)
            prefix_10 = sorted(
                add_unit_with_prefix(private, "10", f"ten-{index}") for index in range(5)
            )
            for index in range(5):
                add_unit_with_prefix(private, "20", f"twenty-{index}")
            destination = base / "destination"
            destination.mkdir()
            with mock.patch.object(materialize_window, "WINDOW_SIZE", 3):
                result = self.call(destination, 1, 3, 1, common, private)
            self.assertEqual(result[8:], ("10", 2))
            self.assertEqual((result[3], result[4]), (2, 3))
            self.assertEqual(
                sorted(path.name for path in destination.iterdir()),
                sorted(common_names + prefix_10[4:5]),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
