#!/usr/bin/env python3
"""Freeze and verify a fail-closed TomorrowCI release candidate inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from version_contract import is_semver


MANIFEST_NAME = "candidate-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"
KIND = "tomorrowci.release-candidate.v1"
STATUS = "CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED"
SHA = re.compile(r"^[0-9a-f]{40}$")
SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")
TOOLCHAIN = "1.97.1"
TARGETS = (
    ("x86_64-unknown-linux-gnu", "tar.gz"),
    ("x86_64-apple-darwin", "tar.gz"),
    ("aarch64-apple-darwin", "tar.gz"),
    ("x86_64-pc-windows-msvc", "zip"),
)
OCI_PAYLOAD = (
    "Containerfile",
    "build-metadata.json",
    "image-provenance.json",
    "image-sbom.cdx.json",
    "image-vulnerabilities.json",
    "tomorrowci-oci-linux-amd64.tar",
)
STATIC_PAYLOAD = (
    "claim-to-evidence.md",
    "qualification-backlog.json",
    "sbom.cdx.json",
    "support.md",
    *OCI_PAYLOAD,
)


def payload_names(version: str) -> tuple[str, ...]:
    if not is_semver(version):
        raise ValueError(f"candidate version is not SemVer: {version!r}")
    archives = tuple(
        f"tomorrowci-v{version}-{target}.{extension}"
        for target, extension in TARGETS
    )
    return tuple(sorted((*archives, *STATIC_PAYLOAD)))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_files(directory: Path) -> set[str]:
    result: set[str] = set()
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ValueError(f"candidate directory contains non-regular entry: {entry.name}")
        result.add(entry.name)
    return result


def _validate_identity(
    *,
    source_sha: str,
    repository: str,
    source_ref: str,
    run_id: str,
    run_attempt: int,
    workflow_ref: str,
) -> None:
    if type(source_sha) is not str or not SHA.fullmatch(source_sha):
        raise ValueError("source SHA must be exactly 40 lowercase hex characters")
    if type(repository) is not str or not SLUG.fullmatch(repository):
        raise ValueError(f"invalid GitHub repository slug: {repository!r}")
    if type(source_ref) is not str or source_ref != "refs/heads/master":
        raise ValueError(f"candidate source ref must be refs/heads/master: {source_ref!r}")
    if (
        not RUN_ID.fullmatch(run_id)
        or type(run_attempt) is not int
        or run_attempt < 1
    ):
        raise ValueError("workflow run identity must use positive integers")
    expected_workflow_ref = f"{repository}/.github/workflows/candidate.yml@{source_ref}"
    if type(workflow_ref) is not str or workflow_ref != expected_workflow_ref:
        raise ValueError(
            f"workflow ref mismatch: expected {expected_workflow_ref!r}, got {workflow_ref!r}"
        )


def create_candidate(
    *,
    dist: Path,
    version: str,
    source_sha: str,
    repository: str,
    source_ref: str,
    run_id: str,
    run_attempt: int,
    workflow_ref: str,
    server_url: str = "https://github.com",
) -> dict:
    dist = dist.resolve()
    names = payload_names(version)
    _validate_identity(
        source_sha=source_sha,
        repository=repository,
        source_ref=source_ref,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_ref=workflow_ref,
    )
    if server_url != "https://github.com":
        raise ValueError(f"unsupported candidate server URL: {server_url!r}")
    actual = _regular_files(dist)
    if actual != set(names):
        raise ValueError(
            f"candidate payload inventory mismatch: expected {list(names)!r}, got {sorted(actual)!r}"
        )
    payload = []
    for name in names:
        path = dist / name
        size = path.stat().st_size
        if size <= 0:
            raise ValueError(f"candidate payload is empty: {name}")
        payload.append(
            {"name": name, "sha256": f"sha256:{sha256_file(path)}", "size": size}
        )
    run_url = f"{server_url}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    manifest = {
        "schema_version": 1,
        "kind": KIND,
        "status": STATUS,
        "version": version,
        "source": {
            "repository": repository,
            "commit": source_sha,
            "ref": source_ref,
            "dirty": False,
        },
        "workflow": {
            "name": "release-candidate",
            "workflow_ref": workflow_ref,
            "run_id": int(run_id),
            "run_attempt": run_attempt,
            "run_url": run_url,
        },
        "build": {"rust_toolchain": TOOLCHAIN, "reproducible_builds": 2},
        "payload": payload,
        "promotion": {
            "authorized": False,
            "authorization_source": None,
            "instruction": "Bind detached external authorization to this manifest's SHA-256 digest.",
        },
    }
    manifest_path = dist / MANIFEST_NAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    checksum_names = sorted((*names, MANIFEST_NAME))
    sums = "".join(f"{sha256_file(dist / name)}  {name}\n" for name in checksum_names)
    (dist / CHECKSUMS_NAME).write_text(sums, encoding="ascii", newline="\n")
    verify_candidate(
        dist=dist,
        expected_source_sha=source_sha,
        expected_repository=repository,
        expected_run_id=run_id,
    )
    return manifest


def _load_manifest(path: Path) -> dict:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate manifest key: {key}")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate)
    if not isinstance(value, dict):
        raise ValueError("candidate manifest root must be an object")
    return value


def verify_candidate(
    *,
    dist: Path,
    expected_source_sha: str | None = None,
    expected_repository: str | None = None,
    expected_run_id: str | None = None,
    expected_run_attempt: int | None = None,
) -> dict:
    dist = dist.resolve()
    manifest = _load_manifest(dist / MANIFEST_NAME)
    if set(manifest) != {
        "schema_version",
        "kind",
        "status",
        "version",
        "source",
        "workflow",
        "build",
        "payload",
        "promotion",
    }:
        raise ValueError("candidate manifest has an unexpected top-level schema")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or type(manifest["kind"]) is not str
        or manifest["kind"] != KIND
    ):
        raise ValueError("candidate manifest schema identity mismatch")
    promotion = manifest["promotion"]
    if (
        type(manifest["status"]) is not str
        or manifest["status"] != STATUS
        or type(promotion) is not dict
        or set(promotion) != {"authorized", "authorization_source", "instruction"}
        or promotion["authorized"] is not False
        or promotion["authorization_source"] is not None
        or type(promotion["instruction"]) is not str
        or promotion["instruction"]
        != "Bind detached external authorization to this manifest's SHA-256 digest."
    ):
        raise ValueError("candidate manifest must remain explicitly unauthorized")
    version = manifest["version"]
    names = payload_names(version)
    source = manifest["source"]
    workflow = manifest["workflow"]
    build = manifest["build"]
    if (
        type(source) is not dict
        or set(source) != {"repository", "commit", "ref", "dirty"}
        or source["dirty"] is not False
    ):
        raise ValueError("candidate source identity is malformed")
    if (
        type(workflow) is not dict
        or set(workflow) != {"name", "workflow_ref", "run_id", "run_attempt", "run_url"}
    ):
        raise ValueError("candidate workflow identity is malformed")
    if type(workflow["name"]) is not str or workflow["name"] != "release-candidate":
        raise ValueError("candidate workflow name mismatch")
    if (
        type(build) is not dict
        or set(build) != {"rust_toolchain", "reproducible_builds"}
        or type(build["rust_toolchain"]) is not str
        or build["rust_toolchain"] != TOOLCHAIN
        or type(build["reproducible_builds"]) is not int
        or build["reproducible_builds"] != 2
    ):
        raise ValueError("candidate build contract mismatch")
    if (
        type(workflow["run_id"]) is not int
        or type(workflow["run_attempt"]) is not int
    ):
        raise ValueError("candidate workflow run identity must use strict integers")
    run_id = str(workflow["run_id"])
    _validate_identity(
        source_sha=source["commit"],
        repository=source["repository"],
        source_ref=source["ref"],
        run_id=run_id,
        run_attempt=workflow["run_attempt"],
        workflow_ref=workflow["workflow_ref"],
    )
    expected_url = (
        f"https://github.com/{source['repository']}/actions/runs/{run_id}"
        f"/attempts/{workflow['run_attempt']}"
    )
    if type(workflow["run_url"]) is not str or workflow["run_url"] != expected_url:
        raise ValueError("candidate run URL does not match repository and run ID")
    if expected_source_sha is not None and source["commit"] != expected_source_sha:
        raise ValueError("candidate source SHA does not match the requested exact commit")
    if expected_repository is not None and source["repository"] != expected_repository:
        raise ValueError("candidate repository does not match the requested repository")
    if expected_run_id is not None and run_id != expected_run_id:
        raise ValueError("candidate run ID does not match the requested workflow run")
    if (
        expected_run_attempt is not None
        and workflow["run_attempt"] != expected_run_attempt
    ):
        raise ValueError("candidate run attempt does not match the requested workflow attempt")
    payload = manifest["payload"]
    if type(payload) is not list or any(
        type(entry) is not dict or set(entry) != {"name", "sha256", "size"}
        for entry in payload
    ):
        raise ValueError("candidate payload entry schema mismatch")
    if [entry["name"] for entry in payload] != list(names):
        raise ValueError("candidate payload names/order do not match the exact inventory")
    for entry in payload:
        name = entry["name"]
        path = dist / name
        digest = entry["sha256"]
        if not isinstance(digest, str) or not digest.startswith("sha256:") or not SHA256.fullmatch(digest[7:]):
            raise ValueError(f"malformed candidate digest: {name}")
        if (
            type(entry["name"]) is not str
            or type(entry["size"]) is not int
            or entry["size"] <= 0
            or entry["size"] != path.stat().st_size
            or digest[7:] != sha256_file(path)
        ):
            raise ValueError(f"candidate payload mismatch: {name}")
    expected_files = set((*names, MANIFEST_NAME, CHECKSUMS_NAME))
    actual_files = _regular_files(dist)
    if actual_files != expected_files:
        raise ValueError(
            f"candidate final inventory mismatch: expected {sorted(expected_files)!r}, got {sorted(actual_files)!r}"
        )
    expected_checksum_names = sorted((*names, MANIFEST_NAME))
    expected_checksum_bytes = "".join(
        f"{sha256_file(dist / name)}  {name}\n" for name in expected_checksum_names
    ).encode("ascii")
    if (dist / CHECKSUMS_NAME).read_bytes() != expected_checksum_bytes:
        raise ValueError("candidate checksums have mismatched bytes or non-canonical encoding")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--dist", type=Path, required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--source-ref", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--run-attempt", type=int, required=True)
    create.add_argument("--workflow-ref", required=True)
    create.add_argument("--server-url", default="https://github.com")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--dist", type=Path, required=True)
    verify.add_argument("--expected-source-sha")
    verify.add_argument("--expected-repository")
    verify.add_argument("--expected-run-id")
    verify.add_argument("--expected-run-attempt", type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            create_candidate(
                dist=args.dist,
                version=args.version,
                source_sha=args.source_sha,
                repository=args.repository,
                source_ref=args.source_ref,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                workflow_ref=args.workflow_ref,
                server_url=args.server_url,
            )
        else:
            verify_candidate(
                dist=args.dist,
                expected_source_sha=args.expected_source_sha,
                expected_repository=args.expected_repository,
                expected_run_id=args.expected_run_id,
                expected_run_attempt=args.expected_run_attempt,
            )
        manifest_digest = sha256_file(args.dist.resolve() / MANIFEST_NAME)
        print(f"candidate-manifest: PASS: sha256:{manifest_digest}")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"candidate-manifest: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
