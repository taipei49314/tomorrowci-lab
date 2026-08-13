#!/usr/bin/env python3
"""Fail closed unless a Windows candidate has a parseable, static VCRUNTIME closure."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path


DLL_LINE = re.compile(r"^\s*([A-Za-z0-9_.-]+\.dll)\s*$", re.IGNORECASE)
FORBIDDEN_VCRUNTIME = re.compile(r"VCRUNTIME[A-Za-z0-9_.-]*\.dll", re.IGNORECASE)


class RuntimeGateError(ValueError):
    """The PE dependency inspection could not establish the required closure."""


def validate_dumpbin_output(output: str) -> tuple[str, ...]:
    dependencies = tuple(
        dict.fromkeys(
            match.group(1).upper()
            for line in output.splitlines()
            if (match := DLL_LINE.fullmatch(line)) is not None
        )
    )
    if not dependencies:
        raise RuntimeGateError("dumpbin output contained no parseable DLL dependencies")
    forbidden = tuple(
        dependency
        for dependency in dependencies
        if FORBIDDEN_VCRUNTIME.fullmatch(dependency) is not None
    )
    if forbidden:
        raise RuntimeGateError(
            "Windows candidate retains an app-local-resolvable MSVC runtime import: "
            + ", ".join(forbidden)
        )
    return dependencies


def inspect_pe_imports(*, dumpbin: Path, binary: Path) -> tuple[str, ...]:
    dumpbin = dumpbin.resolve(strict=True)
    binary = binary.resolve(strict=True)
    if not dumpbin.is_file() or dumpbin.name.lower() != "dumpbin.exe":
        raise RuntimeGateError("dumpbin must resolve to an exact dumpbin.exe file")
    if not binary.is_file() or binary.suffix.lower() != ".exe":
        raise RuntimeGateError("candidate must resolve to an exact PE executable file")

    completed = subprocess.run(
        [str(dumpbin), "/dependents", str(binary)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = completed.stdout.decode("utf-8", errors="replace")
    sys.stdout.write(output)
    if completed.returncode != 0:
        raise RuntimeGateError(
            f"dumpbin dependency inspection failed with exit {completed.returncode}"
        )
    return validate_dumpbin_output(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dumpbin", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        dumpbin_digest = hashlib.sha256(args.dumpbin.read_bytes()).hexdigest()
        binary_digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        dependencies = inspect_pe_imports(dumpbin=args.dumpbin, binary=args.binary)
    except (OSError, RuntimeGateError) as error:
        print(f"windows-runtime-gate: {error}", file=sys.stderr)
        return 1

    print(f"dumpbin_sha256: {dumpbin_digest}")
    print(f"candidate_sha256: {binary_digest}")
    print("pe_dependencies: " + ", ".join(dependencies))
    print("windows_runtime_gate: accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
