#!/usr/bin/env python3
"""Fail on UTF-8 BOM in JSON/YAML/shell and CRLF in Unix shell scripts."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git",
    "target",
    "node_modules",
    ".tomorrowci",
    "dist",
    "examples",  # may contain large generated HTML
}

BOM = b"\xef\xbb\xbf"
SHELL_SUFFIXES = {".sh"}
BOM_SUFFIXES = {".json", ".yml", ".yaml", ".sh", ".toml", ".md"}


def should_skip(path: Path) -> bool:
    parts = set(path.parts)
    return bool(parts & SKIP_DIRS)


def main() -> int:
    errors: list[str] = []
    walk_errors: list[OSError] = []
    for directory, dirnames, filenames in os.walk(
        ROOT, topdown=True, onerror=walk_errors.append, followlinks=False
    ):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            path = Path(directory, filename)
            if should_skip(path):
                continue
            try:
                data = path.read_bytes()
            except OSError as e:
                errors.append(f"{path}: read error {e}")
                continue
            rel = path.relative_to(ROOT).as_posix()
            if path.suffix.lower() in BOM_SUFFIXES and data.startswith(BOM):
                errors.append(f"{rel}: UTF-8 BOM forbidden")
            if path.suffix.lower() in SHELL_SUFFIXES:
                if b"\r\n" in data or data.endswith(b"\r"):
                    errors.append(f"{rel}: CRLF forbidden in Unix shell scripts")
    errors.extend(f"{error.filename or ROOT}: walk error {error}" for error in walk_errors)
    if errors:
        print("check-text-encoding: FAIL")
        for e in errors:
            print(f"  {e}")
        return 1
    print("check-text-encoding: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
