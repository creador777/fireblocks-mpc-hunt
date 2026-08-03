from __future__ import annotations

import contextlib
import hashlib
import io
import os
from pathlib import Path
import re
import tempfile
import unittest

from scripts import emit_summary, materialize_corpus, package_incident, public_summary


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY = ROOT / "keys" / "artifact-recipient.asc"
FINGERPRINT_FILE = ROOT / "keys" / "artifact-recipient.fingerprint"
FORBIDDEN = (
    "Base64:",
    "MS:",
    "ASCII",
    "artifact_prefix",
    "Test unit written",
    "0x1234abcd",
    "/home/runner/",
    r"C:\Users\private-user",
    "input bytes",
)
ALLOWLIST_FILE = ROOT / "scripts" / "frame-allowlist.txt"
#: Canario garantizadamente AUSENTE de la allowlist: si algún día entrara en
#: ella, el control negativo dejaría de probar algo y este test falla aquí.
CANARY = "ZZCANARIO_no_es_un_simbolo_del_binarioZZ"
FRAME_SYMBOL = re.compile(r"[A-Za-z][A-Za-z0-9_:~<>]{0,127}\Z")


def write_private(root: Path, log: bytes, exit_code: int = 0) -> None:
    root.mkdir()
    (root / "fuzzer.raw.log").write_bytes(log)
    (root / "exit_code").write_text(f"{exit_code}\n", encoding="ascii")


class SecurityBoundaryTests(unittest.TestCase):
    def test_01_summary_strips_all_forbidden_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            private = base / "private"
            artifact_data = b"synthetic-input-bytes"
            artifact = "crash-" + hashlib.sha1(artifact_data).hexdigest()
            # Control positivo: un símbolo REAL de la allowlist (extraída del
            # binario). Control negativo: el canario, ausente por contrato.
            allowed = ALLOWLIST_FILE.read_text(encoding="ascii").split()
            self.assertNotIn(CANARY, allowed)
            positive = next(
                symbol for symbol in allowed if FRAME_SYMBOL.fullmatch(symbol))
            log = (
                b"ERROR: AddressSanitizer: heap-buffer-overflow\n"
                + f"#0 0x1234abcd in {positive} /home/runner/private.cc:9\n".encode()
                + f"#1 0xdeadbeef in {CANARY} /home/runner/private.cc:10\n".encode()
                + b"Base64:QUJDREVGRw==\nMS: 1 ASCII unit\n"
                + b"artifact_prefix=/tmp/private Test unit written to /tmp/private\n"
                + b"C:\\Users\\private-user\\secret input bytes 41424344\n"
                + b"X" * 100_000
                + b"\xff\xfe\n"
            )
            write_private(private, log, 77)
            (private / artifact).write_bytes(artifact_data)
            summary = base / "summary.public"
            values = public_summary.build(private, "cmp_ecdsa_online", "3")
            summary.write_text(
                "".join(f"{key}={values[key]}\n" for key in public_summary.FIELDS),
                encoding="ascii",
            )
            emitted = emit_summary.validate(summary)
            self.assertEqual(len(emitted.splitlines()), 7)
            self.assertIn("sanitizer=asan", emitted)
            # El símbolo legítimo se publica; el canario queda como "unknown"
            # y nunca sale al canal público.
            self.assertIn(f"stack_normalized={positive}>unknown", emitted)
            self.assertNotIn(CANARY, emitted)
            self.assertIn(hashlib.sha256(artifact_data).hexdigest(), emitted)
            for marker in FORBIDDEN:
                self.assertNotIn(marker, emitted)

    def test_02_multiple_sanitizers_are_fixed_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary) / "private"
            data = b"synthetic"
            write_private(
                private,
                b"AddressSanitizer\nUndefinedBehaviorSanitizer\nMemorySanitizer\n",
                1,
            )
            (private / ("crash-" + hashlib.sha1(data).hexdigest())).write_bytes(data)
            values = public_summary.build(private, "cmp_ecdsa_online", "0")
            self.assertEqual(values["sanitizer"], "multiple")
            self.assertEqual(values["summary"], "multiple_signals")

    def test_03_no_finding_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary) / "private"
            write_private(private, b"DONE\n", 0)
            values = public_summary.build(private, "cmp_ecdsa_online", "24")
            self.assertEqual(values["summary"], "no_finding")
            self.assertEqual(values["sha256"], "0" * 64)

    def test_04_invalid_artifact_and_nested_directory_fail_closed(self) -> None:
        for name in ("poc.txt", "crash-ABC", ".gitkeep"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                private = Path(temporary) / "private"
                write_private(private, b"DONE\n", 1)
                (private / name).write_bytes(b"x")
                with self.assertRaises(public_summary.SummaryError):
                    public_summary.build(private, "cmp_ecdsa_online", "0")
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary) / "private"
            write_private(private, b"DONE\n", 1)
            (private / "nested").mkdir()
            with self.assertRaises(public_summary.SummaryError):
                public_summary.build(private, "cmp_ecdsa_online", "0")

    def test_05_symlink_fails_closed_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary) / "private"
            write_private(private, b"DONE\n", 0)
            try:
                (private / "link").symlink_to(private / "exit_code")
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaises(public_summary.SummaryError):
                public_summary.build(private, "cmp_ecdsa_online", "0")

    def test_06_emitter_rejects_extra_or_tainted_fields_without_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.summary"
            path.write_text(
                "harness=cmp_ecdsa_online\n"
                "shard=0\nexit_code=0\nsanitizer=none\nsummary=no_finding\n"
                "stack_normalized=none\nsha256=" + "0" * 64 + "\n"
                "Base64:=forbidden\n",
                encoding="ascii",
            )
            with self.assertRaises(ValueError):
                emit_summary.validate(path)

    def test_07_gpg_bundle_is_nonempty_and_plaintext_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            private = base / "private"
            upload = base / "upload"
            upload.mkdir()
            marker = b"Base64:SYNTHETIC-SECRET-MARKER"
            write_private(private, marker, 0)
            destination = upload / "incident.gpg"
            package_incident.package(
                private,
                PUBLIC_KEY,
                FINGERPRINT_FILE.read_text(encoding="ascii").strip(),
                destination,
            )
            self.assertTrue(destination.is_file())
            self.assertGreater(destination.stat().st_size, 0)
            self.assertFalse(private.exists())
            self.assertNotIn(marker, destination.read_bytes())

    def test_08_gpg_failure_preserves_private_evidence_and_publishes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            private = base / "private"
            upload = base / "upload"
            upload.mkdir()
            write_private(private, b"synthetic", 0)
            bad_key = base / "bad.asc"
            bad_key.write_text("not a key", encoding="ascii")
            destination = upload / "incident.gpg"
            with self.assertRaises(package_incident.PackageError):
                package_incident.package(
                    private,
                    bad_key,
                    "A" * 40,
                    destination,
                )
            self.assertTrue(private.is_dir())
            self.assertFalse(destination.exists())

    def test_09_materialize_accepts_only_matching_sha1_depth_one_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            destination = base / "destination"
            source.mkdir()
            destination.mkdir()
            content = b"synthetic-corpus"
            name = hashlib.sha1(content).hexdigest()
            (source / name).write_bytes(content)
            materialize_corpus.materialize(destination, [source])
            self.assertEqual((destination / name).read_bytes(), content)

    def test_10_materialize_rejects_wrong_hash_uppercase_and_nested(self) -> None:
        cases = ("wrong_hash", "uppercase", "nested")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "source"
                source.mkdir()
                if case == "wrong_hash":
                    (source / ("a" * 40)).write_bytes(b"x")
                elif case == "uppercase":
                    data = b"x"
                    (source / hashlib.sha1(data).hexdigest().upper()).write_bytes(data)
                else:
                    (source / "nested").mkdir()
                with self.assertRaises((OSError, ValueError)):
                    materialize_corpus.validated_units(source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
