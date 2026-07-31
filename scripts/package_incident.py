#!/usr/bin/env python3
"""Stream private evidence directly into a public-key encrypted GPG bundle."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


ARTIFACT = re.compile(r"(?:crash|timeout|oom|slow-unit)-[0-9a-f]{40}\Z")
FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")


class PackageError(RuntimeError):
    pass


def run_gpg(args: list[str], *, data: bytes | None = None) -> bytes:
    result = subprocess.run(
        args,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise PackageError("gpg failed closed")
    return result.stdout


def validate_files(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise PackageError("invalid private directory")
    result: list[Path] = []
    total = 0
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise PackageError("symlink rejected")
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise PackageError("nested or non-regular evidence rejected")
            if entry.name not in {"fuzzer.raw.log", "exit_code"} and not ARTIFACT.fullmatch(entry.name):
                raise PackageError("unexpected evidence name")
            total += info.st_size
            if info.st_size > 64 * 1024 * 1024 or total > 128 * 1024 * 1024:
                raise PackageError("evidence size limit exceeded")
            result.append(Path(entry.path))
    if {"fuzzer.raw.log", "exit_code"} - {path.name for path in result}:
        raise PackageError("incomplete evidence")
    return sorted(result, key=lambda path: path.name)


def add_file(archive: tarfile.TarFile, path: Path) -> None:
    info = tarfile.TarInfo(name=f"private/{path.name}")
    info.size = path.stat().st_size
    info.mtime = 0
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with path.open("rb") as source:
        archive.addfile(info, source)


def package(
    private_root: Path,
    public_key: Path,
    fingerprint: str,
    destination: Path,
) -> None:
    files = validate_files(private_root)
    fingerprint = fingerprint.upper()
    if not FINGERPRINT.fullmatch(fingerprint):
        raise PackageError("invalid fingerprint")
    key_data = public_key.read_bytes()
    if (
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----" not in key_data
        or b"PRIVATE KEY" in key_data
        or b"SECRET KEY" in key_data
    ):
        raise PackageError("public key contract rejected")
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise PackageError("invalid destination")

    with tempfile.TemporaryDirectory(prefix=".gpg-home-", dir=destination.parent) as home_text:
        home = Path(home_text)
        home.chmod(0o700)
        base = ["gpg", "--homedir", str(home), "--batch", "--no-tty"]
        run_gpg(base + ["--import-options", "import-minimal", "--import"], data=key_data)
        listing = run_gpg(base + ["--with-colons", "--fingerprint", fingerprint])
        imported = {
            line.split(b":")[9].decode("ascii").upper()
            for line in listing.splitlines()
            if line.startswith(b"fpr:") and len(line.split(b":")) > 9
        }
        if fingerprint not in imported:
            raise PackageError("fingerprint mismatch")

        partial = destination.with_name(destination.name + ".part")
        if partial.exists() or partial.is_symlink():
            raise PackageError("partial output exists")
        process = subprocess.Popen(
            base
            + [
                "--trust-model",
                "always",
                "--recipient",
                fingerprint,
                "--output",
                str(partial),
                "--encrypt",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            if process.stdin is None:
                raise PackageError("gpg stdin unavailable")
            with tarfile.open(fileobj=process.stdin, mode="w|", format=tarfile.GNU_FORMAT) as archive:
                for path in files:
                    add_file(archive, path)
            process.stdin.close()
            stderr = process.stderr.read() if process.stderr is not None else b""
            if process.stderr is not None:
                process.stderr.close()
            return_code = process.wait()
            if return_code != 0:
                raise PackageError(f"gpg encryption failed ({len(stderr)} bytes suppressed)")
            if not partial.is_file() or partial.stat().st_size == 0:
                raise PackageError("empty ciphertext")
            run_gpg(base + ["--list-only", "--decrypt", str(partial)])
            os.replace(partial, destination)
        except Exception:
            if partial.exists() and not partial.is_symlink():
                partial.unlink()
            raise

    shutil.rmtree(private_root)
    if private_root.exists() or private_root.is_symlink():
        if destination.exists() and not destination.is_symlink():
            destination.unlink()
        raise PackageError("plaintext cleanup could not be verified")


def main() -> int:
    if len(sys.argv) != 5:
        return 64
    private_root, public_key, fingerprint_file, destination = map(Path, sys.argv[1:])
    try:
        fingerprint = fingerprint_file.read_text(encoding="ascii").strip()
        package(private_root, public_key, fingerprint, destination)
    except (OSError, UnicodeError, PackageError, tarfile.TarError, subprocess.SubprocessError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
