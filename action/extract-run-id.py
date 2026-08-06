#!/usr/bin/env python3
"""Extract structured run_id from tomorrowci scan output."""
from __future__ import annotations

import json
import sys


def main() -> int:
    lines = sys.stdin.read().splitlines()
    rid = ""
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("{") and "run_id" in line:
            try:
                rid = json.loads(line).get("run_id") or ""
                if rid:
                    break
            except Exception:
                pass
        if line.startswith("run_id:"):
            rid = line.split(":", 1)[1].strip()
            break
    print(rid)
    return 0 if rid else 1


if __name__ == "__main__":
    raise SystemExit(main())
