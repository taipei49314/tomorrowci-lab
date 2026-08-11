#!/usr/bin/env python3
"""Create and summarize non-authoritative raw qualification-step observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

KIND = "tomorrowci.repository-external-target-raw-observation.v1"
SUMMARY_KIND = "tomorrowci.repository-external-target-raw-summary.v1"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[0-9a-f]{12}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RAW_ARTIFACT = re.compile(
    r"^raw-external-observation-"
    r"(?P<target>python-azure-flask|node-helmet|rust-human-panic)-"
    r"(?P<engine>docker|podman)-attempt-(?P<attempt>[1-9][0-9]*)-"
    r"source-(?P<source>[0-9a-f]{40})$"
)
PREREGISTRATION_SHA256 = (
    "sha256:1f9dee08d03f5f07b8c7f4396d6a0d3ee3aeb2b3071914e26d0a32f6e8b79ace"
)
PREREGISTRATION = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "qualification"
    / "external-targets"
    / "preregistration-v1.json"
)
PHASES = {
    "complete",
    "create-record",
    "engine-probe",
    "final-verify",
    "input-verification",
    "preflight",
    "raw-evidence-copy",
    "replay-1",
    "replay-2",
    "repository-clean-check",
    "scan",
    "select-replay",
    "verify-artifact",
    "verify-run",
}
EXPECTED = {
    ("python-azure-flask", "docker"): (
        "Azure-Samples/msdocs-python-flask-webapp-quickstart",
        "5bfb67bffda1a5083e33fec45861de6b55f74e57",
        "docs/qualification/external-targets/configs/python-azure-flask.docker.tomorrowci.json",
    ),
    ("python-azure-flask", "podman"): (
        "Azure-Samples/msdocs-python-flask-webapp-quickstart",
        "5bfb67bffda1a5083e33fec45861de6b55f74e57",
        "docs/qualification/external-targets/configs/python-azure-flask.podman.tomorrowci.json",
    ),
    ("node-helmet", "docker"): (
        "helmetjs/helmet",
        "9315aac37eb69d8dd3fe81c67febcebe60d7e97e",
        "docs/qualification/external-targets/configs/node-helmet.docker.tomorrowci.json",
    ),
    ("node-helmet", "podman"): (
        "helmetjs/helmet",
        "9315aac37eb69d8dd3fe81c67febcebe60d7e97e",
        "docs/qualification/external-targets/configs/node-helmet.podman.tomorrowci.json",
    ),
    ("rust-human-panic", "docker"): (
        "rust-cli/human-panic",
        "b8915ed30fcfca3300e3796fa35ddd0a9a0a5db7",
        "docs/qualification/external-targets/configs/rust-human-panic.docker.tomorrowci.json",
    ),
    ("rust-human-panic", "podman"): (
        "rust-cli/human-panic",
        "b8915ed30fcfca3300e3796fa35ddd0a9a0a5db7",
        "docs/qualification/external-targets/configs/rust-human-panic.podman.tomorrowci.json",
    ),
}


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def read_log(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("scan transcript exceeds 16 MiB")
    data.decode("utf-8", errors="strict")
    return data


def create_record(args: argparse.Namespace) -> dict[str, object]:
    pair = (args.target_id, args.engine)
    if pair not in EXPECTED:
        raise ValueError("target/engine pair is not frozen")
    repository, commit, config = EXPECTED[pair]
    if (args.remote_repository, args.remote_commit, args.config_path) != (
        repository,
        commit,
        config,
    ):
        raise ValueError("raw observation differs from frozen target identity")
    if not COMMIT.fullmatch(args.project_source_sha):
        raise ValueError("project source SHA is not exact")
    if args.candidate_source_sha != args.project_source_sha:
        raise ValueError("candidate and project source SHAs disagree")
    if not REPOSITORY.fullmatch(args.project_repository):
        raise ValueError("project repository is not canonical")
    if (
        args.workflow_run_id <= 0
        or args.workflow_run_attempt <= 0
        or args.candidate_run_id <= 0
        or args.candidate_run_attempt <= 0
    ):
        raise ValueError("workflow run identity must be positive")
    if not SHA256.fullmatch(args.candidate_manifest_sha256):
        raise ValueError("candidate manifest digest is not exact")
    if not SHA256.fullmatch(args.oci_manifest_digest):
        raise ValueError("OCI manifest digest is not exact")
    if digest(PREREGISTRATION.read_bytes()) != PREREGISTRATION_SHA256:
        raise ValueError("frozen preregistration bytes changed")
    if not 0 <= args.step_exit <= 255:
        raise ValueError("qualification step exit must be in 0..255")
    if args.phase not in PHASES:
        raise ValueError("qualification step phase is not recognized")
    if args.scan_attempted and args.scan_exit is None:
        raise ValueError("attempted scan must record an exit code")
    if not args.scan_attempted and args.scan_exit is not None:
        raise ValueError("unattempted scan must not record an exit code")
    if args.scan_exit is not None and not 0 <= args.scan_exit <= 255:
        raise ValueError("scan exit must be in 0..255")
    transcript = read_log(args.scan_log)
    text = transcript.decode("utf-8")
    run_ids = re.findall(r"^run_id: ([0-9a-f]{12})$", text, flags=re.MULTILINE)
    if len(set(run_ids)) != len(run_ids) or any(not RUN_ID.fullmatch(value) for value in run_ids):
        raise ValueError("scan transcript has duplicate or malformed run IDs")
    if not args.scan_attempted and (transcript or run_ids):
        raise ValueError("unattempted scan transcript must be empty")
    return {
        "candidate": {
            "manifest_sha256": args.candidate_manifest_sha256,
            "oci_manifest_digest": args.oci_manifest_digest,
            "run_attempt": args.candidate_run_attempt,
            "run_id": args.candidate_run_id,
            "source_sha": args.candidate_source_sha,
        },
        "kind": KIND,
        "preregistration_sha256": PREREGISTRATION_SHA256,
        "qualification_authority": False,
        "qualification": {
            "config_path": config,
            "engine": args.engine,
            "remote_commit": commit,
            "remote_repository": repository,
            "target_id": args.target_id,
        },
        "scan": {
            "attempted": args.scan_attempted,
            "exit_code": args.scan_exit,
            "run_ids": run_ids,
            "transcript_sha256": digest(transcript),
            "transcript_size": len(transcript),
        },
        "schema_version": 1,
        "status": (
            "QUALIFICATION_STEP_EXIT_ZERO"
            if args.step_exit == 0
            else "QUALIFICATION_STEP_NONZERO"
        ),
        "step": {"exit_code": args.step_exit, "phase": args.phase},
        "workflow": {
            "repository": args.project_repository,
            "run_attempt": args.workflow_run_attempt,
            "run_id": args.workflow_run_id,
            "source_sha": args.project_source_sha,
        },
    }


def expect_keys(value: dict[str, object], expected: set[str], label: str, path: Path) -> None:
    if set(value) != expected:
        raise ValueError(f"raw observation {label} keys are invalid: {path}")


def load_record(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"raw observation is not a regular file: {path}")
    data = path.read_bytes()
    if len(data) > 1024 * 1024:
        raise ValueError(f"raw observation exceeds 1 MiB: {path}")
    value = json.loads(data)
    if type(value) is not dict or data != canonical_bytes(value):
        raise ValueError(f"raw observation is not canonical: {path}")
    expect_keys(
        value,
        {
            "candidate",
            "kind",
            "preregistration_sha256",
            "qualification",
            "qualification_authority",
            "scan",
            "schema_version",
            "status",
            "step",
            "workflow",
        },
        "top-level",
        path,
    )
    if value.get("kind") != KIND or value.get("schema_version") != 1:
        raise ValueError(f"raw observation identity mismatch: {path}")
    if value.get("qualification_authority") is not False:
        raise ValueError(f"raw observation claims qualification authority: {path}")
    if value.get("preregistration_sha256") != PREREGISTRATION_SHA256:
        raise ValueError(f"raw observation preregistration digest mismatch: {path}")
    candidate = value.get("candidate")
    qualification = value.get("qualification")
    scan = value.get("scan")
    step = value.get("step")
    workflow = value.get("workflow")
    if (
        type(candidate) is not dict
        or type(qualification) is not dict
        or type(scan) is not dict
        or type(step) is not dict
        or type(workflow) is not dict
    ):
        raise ValueError(f"raw observation objects are missing: {path}")
    expect_keys(
        candidate,
        {"manifest_sha256", "oci_manifest_digest", "run_attempt", "run_id", "source_sha"},
        "candidate",
        path,
    )
    expect_keys(
        qualification,
        {"config_path", "engine", "remote_commit", "remote_repository", "target_id"},
        "qualification",
        path,
    )
    expect_keys(
        scan,
        {"attempted", "exit_code", "run_ids", "transcript_sha256", "transcript_size"},
        "scan",
        path,
    )
    expect_keys(step, {"exit_code", "phase"}, "step", path)
    expect_keys(workflow, {"repository", "run_attempt", "run_id", "source_sha"}, "workflow", path)
    pair = (qualification.get("target_id"), qualification.get("engine"))
    if pair not in EXPECTED:
        raise ValueError(f"raw observation pair is not frozen: {path}")
    repository, commit, config = EXPECTED[pair]
    if (
        qualification.get("remote_repository") != repository
        or qualification.get("remote_commit") != commit
        or qualification.get("config_path") != config
    ):
        raise ValueError(f"raw observation target identity mismatch: {path}")
    if (
        not SHA256.fullmatch(str(candidate.get("manifest_sha256", "")))
        or not SHA256.fullmatch(str(candidate.get("oci_manifest_digest", "")))
        or type(candidate.get("run_id")) is not int
        or candidate["run_id"] <= 0
        or type(candidate.get("run_attempt")) is not int
        or candidate["run_attempt"] <= 0
        or not COMMIT.fullmatch(str(candidate.get("source_sha", "")))
    ):
        raise ValueError(f"raw observation candidate identity is invalid: {path}")
    attempted = scan.get("attempted")
    scan_exit = scan.get("exit_code")
    if type(attempted) is not bool:
        raise ValueError(f"raw observation attempted flag is invalid: {path}")
    if attempted and (type(scan_exit) is not int or not 0 <= scan_exit <= 255):
        raise ValueError(f"raw observation exit is invalid: {path}")
    if not attempted and scan_exit is not None:
        raise ValueError(f"raw observation unattempted scan has an exit: {path}")
    run_ids = scan.get("run_ids")
    transcript_sha256 = scan.get("transcript_sha256")
    transcript_size = scan.get("transcript_size")
    if (
        type(run_ids) is not list
        or any(type(run_id) is not str or not RUN_ID.fullmatch(run_id) for run_id in run_ids)
        or len(run_ids) != len(set(run_ids))
        or not SHA256.fullmatch(str(transcript_sha256 or ""))
        or type(transcript_size) is not int
        or not 0 <= transcript_size <= 16 * 1024 * 1024
    ):
        raise ValueError(f"raw observation transcript identity is invalid: {path}")
    transcript_path = path.parent / "scan.txt"
    if transcript_path.is_symlink() or not transcript_path.is_file():
        raise ValueError(f"raw observation transcript is not a regular file: {transcript_path}")
    transcript = read_log(transcript_path)
    actual_run_ids = re.findall(
        r"^run_id: ([0-9a-f]{12})$", transcript.decode("utf-8"), flags=re.MULTILINE
    )
    if (
        digest(transcript) != transcript_sha256
        or len(transcript) != transcript_size
        or actual_run_ids != run_ids
    ):
        raise ValueError(f"raw observation transcript read-back mismatch: {path}")
    if not attempted and (transcript or run_ids):
        raise ValueError(f"raw observation unattempted transcript is not empty: {path}")
    step_exit = step.get("exit_code")
    phase = step.get("phase")
    if type(step_exit) is not int or not 0 <= step_exit <= 255 or phase not in PHASES:
        raise ValueError(f"raw observation qualification step status is invalid: {path}")
    if (step_exit == 0) != (phase == "complete"):
        raise ValueError(f"raw observation completion phase disagrees with exit: {path}")
    if step_exit == 0 and (not attempted or scan_exit != 0):
        raise ValueError(f"raw observation successful step lacks a successful scan: {path}")
    if attempted and scan_exit != 0 and step_exit == 0:
        raise ValueError(f"raw observation scan failure became step success: {path}")
    expected_status = (
        "QUALIFICATION_STEP_EXIT_ZERO" if step_exit == 0 else "QUALIFICATION_STEP_NONZERO"
    )
    if value.get("status") != expected_status:
        raise ValueError(f"raw observation status disagrees with exit: {path}")
    if (
        not REPOSITORY.fullmatch(str(workflow.get("repository", "")))
        or type(workflow.get("run_id")) is not int
        or workflow["run_id"] <= 0
        or type(workflow.get("run_attempt")) is not int
        or workflow["run_attempt"] <= 0
        or not COMMIT.fullmatch(str(workflow.get("source_sha", "")))
        or workflow["source_sha"] != candidate["source_sha"]
    ):
        raise ValueError(f"raw observation source SHA is invalid: {path}")
    return value


def build_summary(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("raw read-back root is not a regular directory")
    artifact_roots = sorted(root.iterdir())
    if len(artifact_roots) != len(EXPECTED):
        raise ValueError(
            f"raw read-back requires six downloaded artifact roots, got {len(artifact_roots)}"
        )
    records = []
    for artifact_root in artifact_roots:
        if artifact_root.is_symlink() or not artifact_root.is_dir():
            raise ValueError(f"raw downloaded artifact root is invalid: {artifact_root}")
        match = RAW_ARTIFACT.fullmatch(artifact_root.name)
        if match is None:
            raise ValueError(f"raw downloaded artifact name is invalid: {artifact_root.name}")
        path = artifact_root / "observation.json"
        record = load_record(path)
        if (
            record["qualification"]["target_id"] != match.group("target")
            or record["qualification"]["engine"] != match.group("engine")
            or record["workflow"]["run_attempt"] != int(match.group("attempt"))
            or record["workflow"]["source_sha"] != match.group("source")
        ):
            raise ValueError(f"raw observation disagrees with artifact name: {artifact_root.name}")
        records.append(record)
    if len(records) != len(EXPECTED):
        raise ValueError(f"raw read-back requires six observation records, got {len(records)}")
    pairs: dict[tuple[str, str], dict[str, object]] = {}
    workflow_identity: tuple[object, ...] | None = None
    candidate_identity: tuple[object, ...] | None = None
    for record in records:
        qualification = record["qualification"]
        pair = (qualification["target_id"], qualification["engine"])
        if pair in pairs:
            raise ValueError(f"duplicate raw observation pair: {pair!r}")
        workflow = record["workflow"]
        identity = (
            workflow["repository"],
            workflow["run_id"],
            workflow["run_attempt"],
            workflow["source_sha"],
        )
        if workflow_identity is None:
            workflow_identity = identity
        elif workflow_identity != identity:
            raise ValueError("raw observations disagree on workflow identity")
        candidate = record["candidate"]
        identity = (
            candidate["run_id"],
            candidate["run_attempt"],
            candidate["source_sha"],
            candidate["manifest_sha256"],
            candidate["oci_manifest_digest"],
        )
        if candidate_identity is None:
            candidate_identity = identity
        elif candidate_identity != identity:
            raise ValueError("raw observations disagree on candidate identity")
        pairs[pair] = record
    if set(pairs) != set(EXPECTED):
        raise ValueError("raw observations do not cover the frozen six-pair matrix")
    results = []
    for pair in sorted(pairs):
        record = pairs[pair]
        scan = record["scan"]
        results.append(
            {
                "engine": pair[1],
                "failure_phase": record["step"]["phase"],
                "qualification_step_exit_code": record["step"]["exit_code"],
                "scan_attempted": scan["attempted"],
                "scan_exit_code": scan["exit_code"],
                "scan_run_ids": scan["run_ids"],
                "target_id": pair[0],
                "transcript_sha256": scan["transcript_sha256"],
                "transcript_size": scan["transcript_size"],
            }
        )
    return {
        "artifact_count": len(records),
        "candidate": {
            "manifest_sha256": candidate_identity[3],
            "oci_manifest_digest": candidate_identity[4],
            "run_attempt": candidate_identity[1],
            "run_id": candidate_identity[0],
            "source_sha": candidate_identity[2],
        },
        "kind": SUMMARY_KIND,
        "preregistration_sha256": PREREGISTRATION_SHA256,
        "qualification_authority": False,
        "results": results,
        "schema_version": 1,
        "status": (
            "ALL_QUALIFICATION_STEPS_EXITED_ZERO"
            if all(result["qualification_step_exit_code"] == 0 for result in results)
            else "ONE_OR_MORE_QUALIFICATION_STEPS_NONZERO"
        ),
        "workflow": {
            "repository": workflow_identity[0],
            "run_id": workflow_identity[1],
            "run_attempt": workflow_identity[2],
            "source_sha": workflow_identity[3],
        },
    }


def write_new(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(canonical_bytes(value))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--target-id", required=True)
    create.add_argument("--engine", required=True)
    create.add_argument("--remote-repository", required=True)
    create.add_argument("--remote-commit", required=True)
    create.add_argument("--config-path", required=True)
    create.add_argument("--project-repository", required=True)
    create.add_argument("--project-source-sha", required=True)
    create.add_argument("--candidate-run-id", type=int, required=True)
    create.add_argument("--candidate-run-attempt", type=int, required=True)
    create.add_argument("--candidate-manifest-sha256", required=True)
    create.add_argument("--candidate-source-sha", required=True)
    create.add_argument("--oci-manifest-digest", required=True)
    create.add_argument("--workflow-run-id", type=int, required=True)
    create.add_argument("--workflow-run-attempt", type=int, required=True)
    create.add_argument("--scan-attempted", action="store_true")
    create.add_argument("--scan-exit", type=int)
    create.add_argument("--step-exit", type=int, required=True)
    create.add_argument("--phase", required=True)
    create.add_argument("--scan-log", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    summary = commands.add_parser("summarize")
    summary.add_argument("--observations-root", type=Path, required=True)
    summary.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        value = create_record(args) if args.command == "create" else build_summary(args.observations_root)
        write_new(args.output, value)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"raw external observation: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"raw external observation: PASS: {value['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
