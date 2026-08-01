#!/usr/bin/env python3
"""Deterministically materialize one validated, flat corpus shard.

Public output is deliberately restricted to aggregate metadata.  Input names,
paths, and bytes are never written to stdout or stderr.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


NAME_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_SHARDS = 4096
MAX_SHARDED_SOURCES = 64
MAX_UNIT_BYTES = 1024 * 1024
MAX_UNIQUE_FILES = 100_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
READ_SIZE = 1024 * 1024
WINDOW_SIZE = 24


class FailClosed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Unit:
    name: str
    source: Path
    size: int


def reject(code: str) -> None:
    raise FailClosed(code)


def parse_uint(value: str, code: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        reject(code)
    return int(value, 10)


def lstat_directory(path: Path, code: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError:
        reject(code)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        reject(code)
    return metadata


def hash_regular_file(path: Path, expected: os.stat_result) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        reject("source_open")

    digest = hashlib.sha1()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            reject("source_nonregular")
        # Windows reports different inode values for DirEntry.stat() and
        # fstat() on the same file. Content is still rehashed before and
        # during copying; POSIX can additionally enforce object identity.
        if os.name != "nt" and (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            reject("source_changed")
        while True:
            chunk = os.read(descriptor, READ_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UNIT_BYTES:
                reject("unit_size_cap")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or size != opened.st_size
        ):
            reject("source_changed")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def validate_source(directory: Path) -> dict[str, Unit]:
    lstat_directory(directory, "source_directory")
    units: dict[str, Unit] = {}
    try:
        entries = list(os.scandir(directory))
    except OSError:
        reject("source_scan")
    if len(entries) > MAX_UNIQUE_FILES:
        reject("file_count_cap")

    for entry in entries:
        if not NAME_RE.fullmatch(entry.name):
            reject("source_name")
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError:
            reject("source_stat")
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            reject("source_nonregular")
        if metadata.st_size > MAX_UNIT_BYTES:
            reject("unit_size_cap")
        path = directory / entry.name
        actual_hash, actual_size = hash_regular_file(path, metadata)
        if actual_hash != entry.name:
            reject("content_hash")
        units[entry.name] = Unit(entry.name, path, actual_size)
    return units


def validate_destination(destination: Path) -> None:
    lstat_directory(destination, "destination_directory")
    try:
        if next(os.scandir(destination), None) is not None:
            reject("destination_dirty")
    except FailClosed:
        raise
    except OSError:
        reject("destination_scan")


def merge_private(sources: Iterable[Path]) -> dict[str, Unit]:
    merged: dict[str, Unit] = {}
    for source in sources:
        for name, unit in validate_source(source).items():
            merged.setdefault(name, unit)
    return merged


def enforce_global_caps(common: dict[str, Unit], private: dict[str, Unit]) -> None:
    total_files = len(common) + len(private)
    if total_files > MAX_UNIQUE_FILES:
        reject("file_count_cap")
    total_bytes = sum(unit.size for unit in common.values()) + sum(unit.size for unit in private.values())
    if total_bytes > MAX_TOTAL_BYTES:
        reject("total_size_cap")


def copy_verified(unit: Unit, destination: Path) -> None:
    try:
        metadata = unit.source.lstat()
    except OSError:
        reject("source_changed")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        reject("source_changed")
    digest, size = hash_regular_file(unit.source, metadata)
    if digest != unit.name or size != unit.size:
        reject("source_changed")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    target = destination / unit.name
    try:
        output = os.open(target, flags, 0o600)
    except OSError:
        reject("destination_write")
    try:
        source_fd = os.open(unit.source, os.O_RDONLY | (getattr(os, "O_BINARY", 0)))
        try:
            copied = 0
            copied_hash = hashlib.sha1()
            while True:
                chunk = os.read(source_fd, READ_SIZE)
                if not chunk:
                    break
                copied += len(chunk)
                copied_hash.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        reject("destination_write")
                    view = view[written:]
            if copied != unit.size or copied_hash.hexdigest() != unit.name:
                reject("source_changed")
            os.fsync(output)
        finally:
            os.close(source_fd)
    finally:
        os.close(output)
    try:
        os.chmod(target, 0o644)
    except OSError:
        reject("destination_mode")


def manifest_hash(
    shard_index: int,
    wave_shard_count: int,
    wave_number: int,
    window_index: int | None,
    window_count: int,
    common_names: list[str],
    private_names: list[str],
) -> str:
    digest = hashlib.sha256()
    printable_window = "none" if window_index is None else str(window_index)
    digest.update(
        (
            f"shard_index={shard_index}\nwave_shard_count={wave_shard_count}\n"
            f"wave_number={wave_number}\nwindow_index={printable_window}\nwindow_count={window_count}\n"
        ).encode("ascii")
    )
    for name in common_names:
        digest.update(f"common {name}\n".encode("ascii"))
    for name in private_names:
        digest.update(f"private {name}\n".encode("ascii"))
    return digest.hexdigest()


def materialize(arguments: list[str]) -> tuple[int, int, int, int | None, int, int, int, str]:
    if len(arguments) < 6:
        reject("arguments")
    destination = Path(arguments[0])
    shard_index = parse_uint(arguments[1], "shard_index")
    wave_shard_count = parse_uint(arguments[2], "wave_shard_count")
    wave_number = parse_uint(arguments[3], "wave_number")
    common_source = Path(arguments[4])
    sharded_sources = [Path(value) for value in arguments[5:]]
    if wave_shard_count < 1 or wave_shard_count > MAX_SHARDS or shard_index >= wave_shard_count:
        reject("shard_range")
    if len(sharded_sources) > MAX_SHARDED_SOURCES:
        reject("source_count_cap")

    validate_destination(destination)
    common = validate_source(common_source)
    if not 1 <= len(common) < WINDOW_SIZE:
        reject("common_capacity")
    private_capacity = WINDOW_SIZE - len(common)
    private = merge_private(sharded_sources)
    # Both roles were fully validated above; a learned public seed already
    # present in the private master is one unit and must not consume capacity twice.
    private = {name: unit for name, unit in private.items() if name not in common}
    enforce_global_caps(common, private)

    common_names = sorted(common)
    all_private_names = sorted(private)
    window_count = (len(all_private_names) + private_capacity - 1) // private_capacity
    if window_count:
        window_index: int | None = (wave_number * wave_shard_count + shard_index) % window_count
        start = window_index * private_capacity
        assigned_names = all_private_names[start : start + private_capacity]
    else:
        window_index = None
        assigned_names = []
    selected = [common[name] for name in common_names] + [private[name] for name in assigned_names]

    try:
        staging = Path(tempfile.mkdtemp(prefix=".corpus-shard-", dir=destination.parent))
    except OSError:
        reject("staging_create")
    try:
        for unit in selected:
            copy_verified(unit, staging)
        validate_destination(destination)
        created: list[Path] = []
        try:
            for unit in selected:
                source = staging / unit.name
                target = destination / unit.name
                try:
                    os.link(source, target)
                except OSError:
                    copy_verified(Unit(unit.name, source, unit.size), destination)
                created.append(target)
        except BaseException:
            for target in reversed(created):
                try:
                    target.unlink()
                except OSError:
                    pass
            raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    return (
        shard_index,
        wave_shard_count,
        wave_number,
        window_index,
        window_count,
        len(common_names),
        len(assigned_names),
        manifest_hash(
            shard_index, wave_shard_count, wave_number, window_index, window_count, common_names, assigned_names
        ),
    )


def main() -> int:
    try:
        (
            shard_index, wave_shard_count, wave_number, window_index, window_count,
            common_files, private_files, manifest,
        ) = materialize(sys.argv[1:])
    except FailClosed as error:
        print(f"status=fail_closed code={error.code}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("status=fail_closed code=interrupted", file=sys.stderr)
        return 2
    except BaseException:
        print("status=fail_closed code=internal", file=sys.stderr)
        return 2

    print("status=ok")
    print(f"shard_index={shard_index}")
    print(f"wave_shard_count={wave_shard_count}")
    print(f"wave_number={wave_number}")
    print(f"window_index={'none' if window_index is None else window_index}")
    print(f"window_count={window_count}")
    print(f"common_files={common_files}")
    print(f"private_files={private_files}")
    print(f"total_files={common_files + private_files}")
    print(f"manifest_sha256={manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
