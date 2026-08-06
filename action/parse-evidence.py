#!/usr/bin/env python3
"""Parse run evidence into shell assignments for the composite Action."""
from __future__ import annotations

import json
import os
import sys


def main() -> int:
    run_dir = os.environ.get("RUN_DIR") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not run_dir:
        print("missing RUN_DIR", file=sys.stderr)
        return 2
    fr = json.load(open(f"{run_dir}/frontier.json", encoding="utf-8"))
    run = json.load(open(f"{run_dir}/run.json", encoding="utf-8"))
    fo = bool(fr.get("observed"))
    blocked = any(r.get("verdict") == "BLOCKED" for r in run.get("results", []))
    baseline_pass = any(r.get("verdict") == "BASELINE_PASS" for r in run.get("results", []))
    future_fail = any(r.get("verdict") == "FUTURE_FAIL" for r in run.get("results", []))
    sig = bool((fr.get("failure_signature") or {}).get("normalized_hash"))
    print(f"TCI_BLOCKED={'1' if blocked else '0'}")
    print(f"TCI_BASELINE_PASS={'1' if baseline_pass else '0'}")
    print(f"TCI_FUTURE_FAIL={'1' if future_fail else '0'}")
    print(f"TCI_SIG={'1' if sig else '0'}")
    print(f"TCI_FO={'1' if fo else '0'}")
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as o:
            o.write(f"frontier_observed={'true' if fo else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
