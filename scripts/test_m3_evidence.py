#!/usr/bin/env python3
"""Fail-closed assertions for retained M3 Node/Rust live evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys


EXCLUDED_TREE_PARTS = {".git", ".tomorrowci", "node_modules", "target"}
DIGEST = re.compile(r"^(?:[a-z0-9._-]+(?:/[a-z0-9._-]+)*@)?sha256:[0-9a-f]{64}$")


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object: {path}")
    return value


def source_tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    files = []
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        retained_directories = []
        for name in directory_names:
            candidate = current_path / name
            relative = candidate.relative_to(root)
            if name in EXCLUDED_TREE_PARTS:
                continue
            if candidate.is_symlink():
                raise AssertionError(
                    f"source inventory refuses symlink: {relative.as_posix()}"
                )
            retained_directories.append(name)
        directory_names[:] = retained_directories

        for name in file_names:
            candidate = current_path / name
            relative = candidate.relative_to(root)
            if candidate.is_symlink():
                raise AssertionError(
                    f"source inventory refuses symlink: {relative.as_posix()}"
                )
            if candidate.is_file():
                files.append((relative.as_posix(), candidate))
    for relative, candidate in sorted(files):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(candidate.read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def file_hash(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def run_root(fixture: Path, run_id: str) -> Path:
    root = fixture / ".tomorrowci" / "runs" / run_id
    assert root.is_dir(), f"missing run directory: {root}"
    return root


def assert_live(args: argparse.Namespace) -> None:
    fixture = args.fixture.resolve()
    root = run_root(fixture, args.run_id)
    manifest = load_json(root / "run.json")
    frontier = load_json(root / "frontier.json")

    assert manifest["run_id"] == args.run_id
    assert manifest["detection"]["ecosystem"] == args.ecosystem
    assert manifest["detection"]["package_manager"] == args.manager
    assert manifest["baseline"]["runtime"] == args.baseline
    assert manifest["identity"]["adapter_name"] == args.ecosystem
    assert manifest["identity"]["container_engine"] == "docker"
    assert manifest["identity"]["container_engine_version"]
    if args.source_sha:
        assert manifest["repository"]["commit_sha"] == args.source_sha
        assert manifest["identity"]["source_commit"] == args.source_sha
    if args.require_clean:
        assert manifest["identity"]["dirty_tree"] is False

    lock_path = fixture / args.lockfile
    lock_hash = file_hash(lock_path)
    assert args.lockfile in manifest["detection"]["manifests"]
    assert manifest["identity"]["manifest_hashes"][args.lockfile] == lock_hash

    assert frontier["observed"] is True, frontier
    assert frontier["horizon_label"] == args.candidate, frontier
    assert frontier["first_failing_scenario"], frontier
    signature = frontier["failure_signature"]
    assert signature["kind"] == args.failure_kind, signature
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", signature["normalized_hash"])

    results = {result["scenario_id"]: result for result in manifest["results"]}
    scenarios = {scenario["id"]: scenario for scenario in manifest["plan"]["scenarios"]}
    baseline = results["baseline"]
    failing_id = frontier["first_failing_scenario"]
    failing = results[failing_id]
    assert baseline["verdict"] == "BASELINE_PASS", baseline
    assert failing["verdict"] == "FUTURE_FAIL", failing
    assert failing["attempt"] >= 3, failing

    seen_digests = set()
    state_roots = set()
    for scenario_id in ("baseline", failing_id):
        result = results[scenario_id]
        environment = result["environment"]
        assert environment["engine"] == "docker"
        assert environment["engine_version"] == manifest["identity"]["container_engine_version"]
        assert environment["image_tag"] == environment["image"]
        assert "sha256:" not in environment["image_tag"]
        assert DIGEST.fullmatch(environment["image_digest"]), environment
        seen_digests.add(environment["image_digest"])

        commands = json.loads(
            (root / "scenarios" / scenario_id / "test-commands.json").read_text(
                encoding="utf-8"
            )
        )
        argv = [command["argv"] for command in commands]
        assert all(command["phase"] == "test" and command["network"] is False for command in commands)
        assert any(command[:2] == args.runtime_version_command for command in argv), argv
        assert any(command[:2] == args.manager_version_command for command in argv), argv
        assert any(args.lockfile in " ".join(command) for command in argv), argv

        stdout = (root / "scenarios" / scenario_id / "stdout.log").read_text(
            encoding="utf-8", errors="replace"
        )
        assert lock_hash.removeprefix("sha256:") in stdout, stdout
        runtime = scenarios[scenario_id]["runtime"]
        if args.ecosystem == "node":
            assert f"v{runtime}." in stdout, stdout
            assert re.search(r"(?m)^\d+\.\d+\.\d+$", stdout), stdout
        else:
            assert f"rustc {runtime}" in stdout, stdout
            assert re.search(r"(?m)^cargo \d+\.\d+\.\d+", stdout), stdout

        environment_vars = environment["env"]
        if args.ecosystem == "node":
            state = environment_vars["NODE_PATH"]
        else:
            state = environment_vars["CARGO_TARGET_DIR"]
        assert scenario_id in state, (scenario_id, state)
        state_roots.add(state)

    assert len(seen_digests) == 2, seen_digests
    assert len(state_roots) == 2, state_roots

    if args.replays:
        replay_root = root / "scenarios" / failing_id / "replays"
        for number in range(1, args.replays + 1):
            report = load_json(replay_root / f"attempt-{number}" / "result.json")
            assert report["ok"] is True, report
            assert report["exit_match"] is True, report
            assert report["signature_match"] is True, report

    print(
        json.dumps(
            {
                "status": "PASS",
                "ecosystem": args.ecosystem,
                "run_id": args.run_id,
                "horizon": args.candidate,
                "failure_kind": args.failure_kind,
                "source_commit": manifest["identity"]["source_commit"],
                "image_digests": sorted(seen_digests),
                "replays": args.replays,
            },
            sort_keys=True,
        )
    )


def assert_negative(args: argparse.Namespace) -> None:
    root = run_root(args.fixture.resolve(), args.run_id)
    manifest = load_json(root / "run.json")
    frontier = load_json(root / "frontier.json")
    expected = {
        "baseline-invalid": "BASELINE_INVALID",
        "flaky": "FLAKY",
        "blocked": "BLOCKED",
    }[args.expected]

    verdicts = [result["verdict"] for result in manifest["results"]]
    assert expected in verdicts, (expected, verdicts)
    assert "FUTURE_FAIL" not in verdicts, verdicts
    assert frontier["observed"] is False, frontier
    assert frontier["horizon_label"] is None, frontier
    assert frontier["first_failing_scenario"] is None, frontier
    assert frontier["replay_command"] is None, frontier
    print(
        json.dumps(
            {
                "status": "PASS",
                "negative_control": args.expected,
                "run_id": args.run_id,
                "verdicts": verdicts,
            },
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    tree = commands.add_parser("tree-hash")
    tree.add_argument("fixture", type=Path)

    live = commands.add_parser("assert-live")
    live.add_argument("--fixture", required=True, type=Path)
    live.add_argument("--run-id", required=True)
    live.add_argument("--ecosystem", required=True, choices=("node", "rust"))
    live.add_argument("--baseline", required=True)
    live.add_argument("--candidate", required=True)
    live.add_argument("--manager", required=True)
    live.add_argument("--lockfile", required=True)
    live.add_argument("--failure-kind", required=True)
    live.add_argument("--source-sha", default=os.environ.get("GITHUB_SHA"))
    live.add_argument("--require-clean", action="store_true")
    live.add_argument("--replays", type=int, default=0)

    negative = commands.add_parser("assert-negative")
    negative.add_argument("--fixture", required=True, type=Path)
    negative.add_argument("--run-id", required=True)
    negative.add_argument(
        "--expected", required=True, choices=("baseline-invalid", "flaky", "blocked")
    )
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "tree-hash":
        print(source_tree_hash(args.fixture.resolve()))
        return 0
    if hasattr(args, "ecosystem"):
        if args.ecosystem == "node":
            args.runtime_version_command = ["node", "--version"]
            args.manager_version_command = ["npm", "--version"]
        else:
            args.runtime_version_command = ["rustc", "--version"]
            args.manager_version_command = ["cargo", "--version"]

    if args.command == "assert-live":
        assert_live(args)
    else:
        assert_negative(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, ValueError) as error:
        print(f"M3 evidence assertion failed: {error}", file=sys.stderr)
        raise SystemExit(1)
