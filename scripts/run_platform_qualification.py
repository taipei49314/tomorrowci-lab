#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import candidate_manifest
import oci_candidate
import package_release
import platform_qualification as contract

QUALIFICATION_ERRORS = (
    OSError,
    ValueError,
    KeyError,
    subprocess.SubprocessError,
    shutil.Error,
)


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
    log: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=os.environ.copy(),
    )
    if log is not None:
        payload = completed.stdout
        if completed.stderr:
            payload += "\n--- stderr ---\n" + completed.stderr
        if not payload.endswith("\n"):
            payload += "\n"
        log.write_text(payload, encoding="utf-8", newline="\n")
    if completed.returncode != 0:
        command = " ".join(argv)
        raise ValueError(
            f"command failed with exit {completed.returncode}: {command}: "
            f"{completed.stderr.strip()}"
        )
    return completed


def _line(argv: list[str], *, cwd: Path | None = None, timeout: int = 120) -> str:
    completed = _run(argv, cwd=cwd, timeout=timeout)
    value = completed.stdout.strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"command did not produce exactly one identity line: {argv!r}")
    return value


def _engine_state() -> dict[str, list[str]]:
    containers = [
        line
        for line in _run(["docker", "ps", "-aq", "--no-trunc"]).stdout.splitlines()
        if line
    ]
    volumes = [
        line
        for line in _run(["docker", "volume", "ls", "-q"]).stdout.splitlines()
        if line
    ]
    return {"containers": sorted(containers), "volumes": sorted(volumes)}


def _write_json(path: Path, value: object) -> None:
    contract._write_new(path, value, path.name)


def _json_command(argv: list[str]) -> object:
    completed = _run(argv, timeout=30)
    if completed.stderr:
        raise ValueError(
            "platform provider identity command emitted stderr: "
            f"{completed.stderr.strip()}"
        )
    try:
        return json.loads(
            completed.stdout, object_pairs_hook=contract._reject_duplicates
        )
    except json.JSONDecodeError as error:
        raise ValueError(
            f"platform provider identity is not strict JSON: {error}"
        ) from error


def _provider_status(platform_id: str) -> dict[str, object]:
    spec = contract.PLATFORMS[platform_id]
    value = {
        "docker_context": _json_command(
            ["docker", "context", "inspect", spec.engine_context]
        )
    }
    if spec.provider == "colima":
        value["colima"] = _json_command(["colima", "status", "--json"])
    return value


def _engine_identity(platform_id: str) -> dict[str, object]:
    context = _line(["docker", "context", "show"], timeout=30)
    version = _line(
        ["docker", "version", "--format", "{{.Server.Version}}"], timeout=30
    )
    info = _json_command(["docker", "info", "--format", "{{json .}}"])
    if type(info) is not dict:
        raise ValueError("Docker engine identity is not a JSON object")
    if info.get("ServerVersion") != version:
        raise ValueError("Docker version and info ServerVersion contradict each other")
    return {
        "context": context,
        "info": info,
        "provider": _provider_status(platform_id),
        "version": version,
    }


def _assert_engine_identity(
    expected: dict[str, object], actual: dict[str, object], phase: str
) -> None:
    if actual["context"] != expected["context"]:
        raise ValueError(f"Docker context changed {phase}")
    if actual["version"] != expected["version"]:
        raise ValueError(f"Docker server version changed {phase}")
    expected_info = expected["info"]
    actual_info = actual["info"]
    if type(expected_info) is not dict or type(actual_info) is not dict:
        raise ValueError(f"Docker engine identity is malformed {phase}")
    if any(
        actual_info.get(key) != expected_info.get(key)
        for key in ("Architecture", "OSType", "OperatingSystem", "ServerVersion")
    ):
        raise ValueError(f"Docker engine identity changed {phase}")
    if actual["provider"] != expected["provider"]:
        raise ValueError(f"platform provider identity changed {phase}")


def _write_engine_identity(metadata: Path, identity: dict[str, object]) -> None:
    (metadata / "engine-context.txt").write_text(
        str(identity["context"]) + "\n", encoding="utf-8", newline="\n"
    )
    (metadata / "engine-version.txt").write_text(
        str(identity["version"]) + "\n", encoding="utf-8", newline="\n"
    )
    (metadata / "engine-info.json").write_bytes(
        contract.canonical_json_bytes(identity["info"])
    )
    _write_json(metadata / "provider-status.json", identity["provider"])


def _copy_evidence(
    source: Path,
    artifact_root: Path,
    run_id: str,
    verified_before: dict[str, object],
) -> Path:
    source_after_verify = contract.tree_snapshot(source, exclude_internal=False)
    if verified_before != source_after_verify:
        raise ValueError("platform evidence changed while it was verified")
    runs = artifact_root / ".tomorrowci" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    destination = runs / run_id
    if destination.exists():
        raise ValueError("platform evidence destination already exists")
    shutil.copytree(source, destination, symlinks=False)
    source_after_copy = contract.tree_snapshot(source, exclude_internal=False)
    copied = contract.tree_snapshot(destination, exclude_internal=False)
    if verified_before != source_after_copy or verified_before != copied:
        raise ValueError("platform evidence changed while it was retained")
    return destination


def _workflow_preflight_bytes(args: argparse.Namespace) -> bytes:
    return (
        "kind: tomorrowci.platform-workflow-preflight/v1\n"
        "status: FAIL_ONLY\n"
        f"platform_id: {args.platform_id}\n"
        f"repository: {args.project_repository}\n"
        f"source_sha: {args.project_source_sha}\n"
        f"source_ref: {args.project_source_ref}\n"
        f"workflow_run_id: {args.workflow_run_id}\n"
        f"workflow_run_attempt: {args.workflow_run_attempt}\n"
        f"candidate_run_id: {args.candidate_run_id}\n"
        f"candidate_run_attempt: {args.candidate_run_attempt}\n"
        f"candidate_source_sha: {args.candidate_source_sha}\n"
        f"candidate_manifest_sha256: {args.candidate_manifest_sha256}\n"
        f"oci_manifest_digest: {args.oci_manifest_digest}\n"
    ).encode()


def _consume_workflow_preflight(artifact: Path, args: argparse.Namespace) -> None:
    root = contract._plain_directory(artifact, "platform workflow artifact root")
    actual = sorted(entry.name for entry in os.scandir(root))
    if actual != ["workflow-preflight.txt"]:
        raise ValueError(
            "platform workflow artifact root is not a fresh preflight root"
        )
    path = root / "workflow-preflight.txt"
    expected = _workflow_preflight_bytes(args)
    if (
        contract._snapshot_file(path, "platform workflow preflight", len(expected))
        != expected
    ):
        raise ValueError("platform workflow preflight identity mismatch")
    path.unlink()
    if path.exists():
        raise ValueError("platform workflow preflight could not be consumed")


def _failure_document(
    args: argparse.Namespace, error: Exception, run_id: str | None
) -> dict[str, object]:
    return {
        "candidate_manifest_sha256": args.candidate_manifest_sha256,
        "candidate_run_attempt": args.candidate_run_attempt,
        "candidate_run_id": args.candidate_run_id,
        "candidate_source_sha": args.candidate_source_sha,
        "error": str(error),
        "kind": "tomorrowci.platform-qualification-failure/v1",
        "oci_manifest_digest": args.oci_manifest_digest,
        "platform_id": args.platform_id,
        "project_repository": args.project_repository,
        "project_source_ref": args.project_source_ref,
        "project_source_sha": args.project_source_sha,
        "run_id": run_id,
        "status": "FAIL",
        "workflow_run_attempt": args.workflow_run_attempt,
        "workflow_run_id": args.workflow_run_id,
    }


def _record_context(
    args: argparse.Namespace,
    metadata: Path,
    binary: Path,
    run_root: Path,
) -> argparse.Namespace:
    return argparse.Namespace(
        metadata_root=metadata,
        platform_id=args.platform_id,
        runner_name=os.environ.get("RUNNER_NAME", ""),
        runner_os=os.environ.get("RUNNER_OS", ""),
        runner_arch=os.environ.get("RUNNER_ARCH", ""),
        project_repository=args.project_repository,
        project_source_sha=args.project_source_sha,
        project_source_ref=args.project_source_ref,
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
        candidate_dist=args.candidate_dist,
        candidate_binary=binary,
        candidate_run_id=args.candidate_run_id,
        candidate_run_attempt=args.candidate_run_attempt,
        candidate_manifest_sha256=args.candidate_manifest_sha256,
        candidate_source_sha=args.candidate_source_sha,
        oci_manifest_digest=args.oci_manifest_digest,
        fixture_source=args.fixture,
        run_root=run_root,
    )


def qualify(args: argparse.Namespace) -> None:
    spec = contract.PLATFORMS[args.platform_id]
    repository_root = contract._plain_directory(args.repository_root, "repository root")
    fixture = contract._plain_directory(args.fixture, "platform fixture")
    if fixture.parent.parent != repository_root:
        raise ValueError(
            "platform fixture must be the checked-in fixtures/python-runtime-break"
        )
    if fixture.name != "python-runtime-break" or fixture.parent.name != "fixtures":
        raise ValueError("unexpected platform fixture path")
    if args.config.resolve(strict=True) != (
        fixture / ".tomorrowci-platform.yml"
    ).resolve(strict=True):
        raise ValueError("platform qualification must use the checked-in Docker config")
    if args.project_source_ref != "refs/heads/master":
        raise ValueError("platform qualification must run from master")
    if args.project_source_sha != args.candidate_source_sha:
        raise ValueError("candidate source and platform workflow source differ")
    contract._sha(args.project_source_sha, "project source SHA")
    contract._integer_string(args.candidate_run_id, "candidate run ID")
    contract._integer_string(args.candidate_run_attempt, "candidate run attempt")
    contract._integer_string(args.workflow_run_id, "workflow run ID")
    contract._integer_string(args.workflow_run_attempt, "workflow run attempt")
    contract._digest(args.candidate_manifest_sha256, "candidate manifest digest")
    contract._digest(args.oci_manifest_digest, "OCI manifest digest")
    if (
        _line(["git", "rev-parse", "HEAD"], cwd=repository_root)
        != args.project_source_sha
    ):
        raise ValueError("checked-out repository HEAD differs from requested source")
    if _run(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=repository_root
    ).stdout:
        raise ValueError("platform checkout is not clean")
    if (fixture / ".tomorrowci").exists():
        raise ValueError(
            "platform fixture contains stale internal evidence before scan"
        )
    artifact = args.artifact_root.absolute()
    if artifact.exists():
        _consume_workflow_preflight(artifact, args)
    else:
        contract._plain_directory(artifact.parent, "platform artifact parent")
        artifact.mkdir(exist_ok=False)
    metadata = artifact / "metadata"
    metadata.mkdir()
    failure: Exception | None = None
    run_id: str | None = None
    binary: Path | None = None
    run_root: Path | None = None
    candidate_temp: tempfile.TemporaryDirectory[str] | None = None

    try:
        source_snapshot = contract.tree_snapshot(fixture, exclude_internal=True)
        _write_json(metadata / "source-before.json", source_snapshot)
        initial_engine = _engine_identity(args.platform_id)
        _write_json(metadata / "pre-state.json", _engine_state())

        manifest = candidate_manifest.verify_candidate(
            dist=args.candidate_dist,
            expected_source_sha=args.candidate_source_sha,
            expected_repository=args.project_repository,
            expected_run_id=args.candidate_run_id,
            expected_run_attempt=int(args.candidate_run_attempt),
        )
        manifest_bytes = contract._snapshot_file(
            args.candidate_dist / candidate_manifest.MANIFEST_NAME,
            "candidate manifest",
        )
        if contract._sha256(manifest_bytes) != args.candidate_manifest_sha256:
            raise ValueError("candidate manifest digest mismatch")
        provenance = oci_candidate.verify_candidate(
            archive=args.candidate_dist / "tomorrowci-oci-linux-amd64.tar",
            metadata=args.candidate_dist / "build-metadata.json",
            containerfile=args.candidate_dist / "Containerfile",
            provenance=args.candidate_dist / "image-provenance.json",
            expected_source_sha=args.candidate_source_sha,
            expected_repository=args.project_repository,
            expected_run_id=args.candidate_run_id,
            expected_run_attempt=int(args.candidate_run_attempt),
        )
        if provenance["oci"]["manifest"]["digest"] != args.oci_manifest_digest:
            raise ValueError("OCI manifest digest differs from detached provenance")
        version_number = manifest["version"]
        archive = (
            args.candidate_dist
            / f"tomorrowci-v{version_number}-{spec.target}.{spec.archive_extension}"
        )
        candidate_temp = contract._temporary_directory(
            prefix="tomorrowci-platform-candidate-",
            parent=artifact.parent,
            label="platform candidate extraction",
        )
        extract = Path(candidate_temp.name) / "extract"
        package_root = package_release.extract_archive(
            archive=archive,
            output_dir=extract,
            version=version_number,
            target=spec.target,
        )
        binary = package_root / spec.binary_name
        _run([str(binary), "trust"], cwd=repository_root, log=metadata / "trust.txt")
        _run([str(binary), "doctor"], cwd=repository_root, log=metadata / "doctor.txt")

        scan = _run(
            [
                str(binary),
                "scan",
                str(fixture),
                "--config",
                str(args.config),
            ],
            cwd=repository_root,
            timeout=1800,
            log=metadata / "scan.txt",
        )
        run_ids = re.findall(r"(?m)^run_id: ([0-9a-f]{12})\r?$", scan.stdout)
        if len(run_ids) != 1:
            raise ValueError(
                f"platform scan must emit exactly one run ID, got {run_ids!r}"
            )
        run_id = run_ids[0]
        original_run = fixture / ".tomorrowci" / "runs" / run_id
        contract._plain_directory(original_run, "platform scan run root")
        scan_engine = _engine_identity(args.platform_id)
        _assert_engine_identity(initial_engine, scan_engine, "during platform scan")
        _write_engine_identity(metadata, scan_engine)
        scan_manifest, _ = contract._load_json(
            original_run / "run.json", "post-scan platform run manifest"
        )
        if type(scan_manifest) is not dict:
            raise ValueError("post-scan platform run manifest is not an object")
        contract._result_engine_versions(
            scan_manifest.get("results"), str(scan_engine["version"])
        )
        _run([str(binary), "verify", run_id], cwd=fixture, timeout=120)
        frontier, _ = contract._load_json(original_run / "frontier.json", "frontier")
        if (
            type(frontier) is not dict
            or type(frontier.get("first_failing_scenario")) is not str
        ):
            raise ValueError("platform scan did not emit an observed replay scenario")
        scenario = frontier["first_failing_scenario"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", scenario):
            raise ValueError("platform replay scenario ID is unsafe")
        _run(
            [str(binary), "replay", run_id, "--scenario", scenario],
            cwd=fixture,
            timeout=1800,
            log=metadata / "replay-1.txt",
        )
        _run(
            [str(binary), "replay", run_id, "--scenario", scenario],
            cwd=fixture,
            timeout=1800,
            log=metadata / "replay-2.txt",
        )
        _run([str(binary), "verify", run_id], cwd=fixture, timeout=120)
        verified_before = contract.tree_snapshot(original_run, exclude_internal=False)
        final_engine = _engine_identity(args.platform_id)
        _assert_engine_identity(
            scan_engine, final_engine, "after platform verify and replay"
        )
        _write_json(
            metadata / "source-after.json",
            contract.tree_snapshot(fixture, exclude_internal=True),
        )
        _write_json(metadata / "post-state.json", _engine_state())
        run_root = _copy_evidence(original_run, artifact, run_id, verified_before)
        capture_args = _record_context(args, metadata, binary, run_root)
        capture = contract.create_capture(
            metadata_root=metadata,
            platform_id=capture_args.platform_id,
            runner_name=capture_args.runner_name,
            runner_os=capture_args.runner_os,
            runner_arch=capture_args.runner_arch,
            project_repository=capture_args.project_repository,
            project_source_sha=capture_args.project_source_sha,
            project_source_ref=capture_args.project_source_ref,
            workflow_run_id=capture_args.workflow_run_id,
            workflow_run_attempt=capture_args.workflow_run_attempt,
        )
        contract._write_new(
            metadata / contract.CAPTURE_NAME, capture, "platform capture"
        )
        record = contract.build_record(capture_args)
        contract._write_new(artifact / contract.RECORD_NAME, record, "platform record")
        if _run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=repository_root,
        ).stdout:
            raise ValueError(
                "tracked source checkout changed during platform qualification"
            )
        print(f"platform qualification: PASS: {args.platform_id}: {run_id}")
    except QUALIFICATION_ERRORS as error:
        failure = error
        retention_errors: list[str] = []
        try:
            _write_json(
                artifact / "failure.json",
                _failure_document(args, error, run_id),
            )
        except QUALIFICATION_ERRORS as retention_error:
            retention_errors.append(f"failure record: {retention_error}")
        try:
            if not (metadata / "source-after.json").exists():
                _write_json(
                    metadata / "source-after.json",
                    contract.tree_snapshot(fixture, exclude_internal=True),
                )
        except QUALIFICATION_ERRORS as retention_error:
            retention_errors.append(f"source-after snapshot: {retention_error}")
        try:
            if not (metadata / "post-state.json").exists():
                _write_json(metadata / "post-state.json", _engine_state())
        except QUALIFICATION_ERRORS as retention_error:
            retention_errors.append(f"post-state snapshot: {retention_error}")
        try:
            if run_id is not None and run_root is None:
                candidate_run = fixture / ".tomorrowci" / "runs" / run_id
                if candidate_run.is_dir():
                    failure_before = contract.tree_snapshot(
                        candidate_run, exclude_internal=False
                    )
                    _copy_evidence(candidate_run, artifact, run_id, failure_before)
        except QUALIFICATION_ERRORS as retention_error:
            retention_errors.append(f"run evidence copy: {retention_error}")
        for retention_error in retention_errors:
            print(
                f"platform qualification evidence retention also failed: {retention_error}",
                file=sys.stderr,
            )
    if candidate_temp is not None:
        try:
            candidate_temp.cleanup()
        except OSError as cleanup_error:
            if failure is None:
                raise ValueError(
                    f"candidate extraction cleanup failed: {cleanup_error}"
                ) from cleanup_error
            print(
                f"candidate extraction cleanup failed: {cleanup_error}", file=sys.stderr
            )
    if failure is not None:
        raise failure


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Execute one dedicated clean-machine platform qualification"
    )
    result.add_argument("--repository-root", type=Path, required=True)
    result.add_argument("--fixture", type=Path, required=True)
    result.add_argument("--config", type=Path, required=True)
    result.add_argument("--artifact-root", type=Path, required=True)
    result.add_argument("--candidate-dist", type=Path, required=True)
    result.add_argument("--candidate-run-id", required=True)
    result.add_argument("--candidate-run-attempt", required=True)
    result.add_argument("--candidate-manifest-sha256", required=True)
    result.add_argument("--candidate-source-sha", required=True)
    result.add_argument("--oci-manifest-digest", required=True)
    result.add_argument(
        "--platform-id", choices=sorted(contract.PLATFORMS), required=True
    )
    result.add_argument("--project-repository", required=True)
    result.add_argument("--project-source-sha", required=True)
    result.add_argument("--project-source-ref", required=True)
    result.add_argument("--workflow-run-id", required=True)
    result.add_argument("--workflow-run-attempt", required=True)
    return result


def _retain_uncaught_failure(args: argparse.Namespace, error: Exception) -> None:
    artifact = args.artifact_root.absolute()
    try:
        if artifact.exists():
            contract._plain_directory(artifact, "platform failure artifact root")
        else:
            contract._plain_directory(
                artifact.parent, "platform failure artifact parent"
            )
            artifact.mkdir(exist_ok=False)
        failure_path = artifact / "failure.json"
        if failure_path.exists():
            contract._snapshot_file(failure_path, "existing platform failure record")
            return
        _write_json(
            failure_path,
            _failure_document(args, error, None),
        )
    except QUALIFICATION_ERRORS as retention_error:
        print(
            "platform qualification top-level failure retention also failed: "
            f"{retention_error}",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        qualify(args)
    except QUALIFICATION_ERRORS as error:
        _retain_uncaught_failure(args, error)
        print(f"platform qualification: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
