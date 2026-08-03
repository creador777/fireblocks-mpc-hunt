#!/usr/bin/env python3
"""Set aside invalid corpus units and keep the valid ones. Never relaxes.

A libFuzzer write interrupted by the host watchdog leaves a file whose
content does not hash to its name. validate_corpus.py is all-or-nothing by
design, so one such unit used to forfeit every valid unit of the shard.
Setting the broken unit aside conserves what was learned WITHOUT relaxing
the allowlist: whatever survives still satisfies name == sha1(content) and
the size limit, and validate_corpus.py still runs afterwards, unchanged,
over the survivors.

Structural anomalies are NOT a broken unit; they are something that should
not exist at all, and they keep failing closed:

- symlink entry                     -> exit 1
- non-regular or nested entry       -> exit 1
- name not exactly 40 lowercase hex -> exit 1

Content-level rejections with a structurally valid name are set aside:

- sha1(content) != name (interrupted write) -> moved to the quarantine dir
- size over the 4 MiB unit limit            -> moved to the quarantine dir

Exit 0 when at least one valid unit remains; 1 when none remains or on any
anomaly. Nothing is printed: the exit code is the whole contract.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys

MAX_UNIT_BYTES = 4 * 1024 * 1024


class QuarantineError(RuntimeError):
    pass


def main() -> int:
    if len(sys.argv) not in (2, 3):
        return 64
    root = Path(sys.argv[1])
    quarantine = (Path(sys.argv[2]) if len(sys.argv) == 3
                  else root.with_name(root.name + ".quarantine"))
    try:
        if root.is_symlink() or not root.is_dir():
            raise QuarantineError("invalid corpus root")
        prepared = False
        remaining = 0
        with os.scandir(root) as iterator:
            entries = list(iterator)
        for entry in entries:
            if entry.is_symlink():
                raise QuarantineError("symlink rejected")
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise QuarantineError(
                    "nested or non-regular corpus entry rejected")
            name = entry.name
            if len(name) != 40 or any(
                    char not in "0123456789abcdef" for char in name):
                raise QuarantineError("invalid corpus name")
            valid = (
                info.st_size <= MAX_UNIT_BYTES
                and hashlib.sha1(Path(entry.path).read_bytes()).hexdigest()
                == name
            )
            if valid:
                remaining += 1
                continue
            if not prepared:
                if quarantine.is_symlink() or (
                        quarantine.exists() and not quarantine.is_dir()):
                    raise QuarantineError("invalid quarantine directory")
                quarantine.mkdir(mode=0o700, parents=True, exist_ok=True)
                prepared = True
            os.replace(entry.path, quarantine / name)
        if remaining == 0:
            raise QuarantineError("no valid unit survives")
    except (OSError, QuarantineError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
