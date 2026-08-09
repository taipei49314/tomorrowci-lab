#!/usr/bin/env python3
"""Require immutable commit SHAs for every external GitHub Action reference."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")


def main() -> int:
    errors: list[str] = []
    paths = sorted(
        {
            *list((ROOT / ".github").rglob("*.yml")),
            *list((ROOT / ".github").rglob("*.yaml")),
            *list((ROOT / "action").rglob("*.yml")),
            *list((ROOT / "action").rglob("*.yaml")),
        }
    )
    for path in paths:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = USES.match(line)
            if not match:
                continue
            value = match.group(1).strip('"\'')
            if value.startswith("./") or value.startswith("docker://"):
                continue
            if "@" not in value:
                errors.append(f"{path.relative_to(ROOT)}:{line_number}: missing @ref")
                continue
            pin = value.rsplit("@", 1)[1]
            if not PIN.fullmatch(pin):
                errors.append(
                    f"{path.relative_to(ROOT)}:{line_number}: mutable action ref {value}"
                )
    if errors:
        print("check-actions-pinned: FAIL")
        for error in errors:
            print(f"  {error}")
        return 1
    print("check-actions-pinned: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
