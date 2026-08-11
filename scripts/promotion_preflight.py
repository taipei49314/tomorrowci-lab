#!/usr/bin/env python3
"""Fail-closed preflight helpers for exact-byte release promotion.

This module deliberately has no publication primitive.  It validates immutable
GitHub observations and the two-ref authorization-consumption state machine;
the final command always refuses publication until a separately reviewed
publisher and public read-back contract exist.
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
import zipfile
from pathlib import Path

import tag_promotion_attestation


SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REF = re.compile(r"^refs/tags/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")
AUTHORIZATION_ID = re.compile(r"^[0-9a-f]{64}$")
KIND = "tomorrowci.protected-promotion-remote-state.v1"
DISABLED_STATUS = "PREPARED_ONLY_PUBLICATION_PERMANENTLY_DISABLED"
AUTHORIZATION_FILES = {
    "external-authorization.json",
    "external-authorization.json.sig",
    "external-qualification-evidence.json",
    "preregistered-policy.json",
    "tag-promotion-attestation.json",
}


def _load_json(path: Path, label: str) -> dict:
    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate,
        parse_constant=lambda item: (_ for _ in ()).throw(
            ValueError(f"{label} contains non-finite JSON value {item}")
        ),
    )
    if type(value) is not dict:
        raise ValueError(f"{label} root must be an object")
    return value


def _positive(value: str, label: str) -> int:
    if type(value) is not str or not POSITIVE.fullmatch(value):
        raise ValueError(f"{label} must be a positive decimal integer")
    return int(value)


def inspect_ci_run(
    metadata: dict,
    *,
    repository: str,
    source_sha: str,
    run_id: str,
    run_attempt: str,
) -> dict:
    if not SLUG.fullmatch(repository) or not SHA.fullmatch(source_sha):
        raise ValueError("expected CI repository or source SHA is malformed")
    expected_id = _positive(run_id, "CI run ID")
    expected_attempt = _positive(run_attempt, "CI run attempt")
    repo = metadata.get("repository")
    head_repo = metadata.get("head_repository")
    expected = {
        "id": expected_id,
        "run_attempt": expected_attempt,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "master",
        "head_sha": source_sha,
        "path": ".github/workflows/ci.yml",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"CI run {key} mismatch")
    if (
        type(repo) is not dict
        or type(head_repo) is not dict
        or repo.get("full_name") != repository
        or head_repo.get("full_name") != repository
    ):
        raise ValueError("CI run repository identity mismatch")
    return expected


def inspect_artifact(
    metadata: dict,
    *,
    artifact_id: str,
    artifact_sha256: str,
) -> dict:
    expected_id = _positive(artifact_id, "authorization artifact ID")
    if not SHA256.fullmatch(artifact_sha256):
        raise ValueError("authorization artifact digest is malformed")
    if metadata.get("id") != expected_id:
        raise ValueError("authorization artifact ID mismatch")
    if metadata.get("digest") != artifact_sha256:
        raise ValueError("authorization artifact API digest mismatch")
    if metadata.get("expired") is not False:
        raise ValueError("authorization artifact is expired")
    size = metadata.get("size_in_bytes")
    if type(size) is not int or size <= 0:
        raise ValueError("authorization artifact size is invalid")
    return {"artifact_id": expected_id, "digest": artifact_sha256, "size": size}


def inspect_oci_manifest_digest(provenance: Path, expected_digest: str) -> str:
    """Read strict JSON and bind only the authoritative OCI manifest field."""

    if not SHA256.fullmatch(expected_digest):
        raise ValueError("expected OCI manifest digest is malformed")
    document = _load_json(provenance, "OCI detached provenance")
    oci = document.get("oci")
    manifest = oci.get("manifest") if type(oci) is dict else None
    actual = manifest.get("digest") if type(manifest) is dict else None
    if type(actual) is not str or not SHA256.fullmatch(actual):
        raise ValueError("OCI detached provenance manifest digest is malformed")
    if actual != expected_digest:
        raise ValueError("OCI detached provenance manifest digest mismatch")
    return actual


def safe_extract_authorization(archive: Path, destination: Path) -> None:
    destination = destination.absolute()
    if destination.exists():
        raise ValueError("authorization extraction destination already exists")
    destination.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(archive) as package:
            entries = package.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)) or set(names) != AUTHORIZATION_FILES:
                raise ValueError("authorization bundle inventory mismatch")
            if sum(entry.file_size for entry in entries) > 64 * 1024 * 1024:
                raise ValueError("authorization bundle exceeds size limit")
            for entry in entries:
                name = entry.filename
                mode = entry.external_attr >> 16
                if (
                    entry.is_dir()
                    or entry.flag_bits & 0x1
                    or Path(name).name != name
                    or name in {".", ".."}
                    or entry.file_size <= 0
                    or (mode and not stat.S_ISREG(mode))
                ):
                    raise ValueError(f"unsafe authorization bundle entry: {name!r}")
                data = package.read(entry)
                if len(data) != entry.file_size:
                    raise ValueError(f"authorization entry size drift: {name}")
                with (destination / name).open("xb") as handle:
                    handle.write(data)
    except Exception:
        # The workflow uses a fresh runner temp path.  Leaving a partial,
        # inaccessible directory is safer than reusing it after an error.
        raise


def remote_state(
    text: str,
    *,
    version_ref: str,
    version_oid: str,
    marker_ref: str,
    marker_oid: str,
) -> dict:
    expected = {version_ref: version_oid, marker_ref: marker_oid}
    if (
        not REF.fullmatch(version_ref)
        or not REF.fullmatch(marker_ref)
        or version_ref == marker_ref
        or not SHA.fullmatch(version_oid)
        or not SHA.fullmatch(marker_oid)
    ):
        raise ValueError("expected promotion ref identity is malformed")
    observed: dict[str, str] = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not SHA.fullmatch(fields[0]) or fields[1] not in expected:
            raise ValueError("remote ref observation contains an unexpected entry")
        if fields[1] in observed:
            raise ValueError("remote ref observation contains a duplicate ref")
        observed[fields[1]] = fields[0]
    if not observed:
        state = "READY_FOR_ATOMIC_CREATE_ONLY"
    elif observed == expected:
        state = "IDEMPOTENT_EXACT_PAIR"
    else:
        raise ValueError("remote tag/authorization marker is partial or mismatched")
    return {
        "kind": KIND,
        "refs": {key: expected[key] for key in sorted(expected)},
        "schema_version": 1,
        "state": state,
        "status": DISABLED_STATUS,
    }


def inspect_authorization_marker(
    *,
    git_repo: Path,
    marker_ref: str,
    candidate_source_sha: str,
    authorization_id: str,
) -> dict:
    """Require a direct annotated marker binding one authorization to one commit."""

    if not SHA.fullmatch(candidate_source_sha):
        raise ValueError("candidate source SHA is malformed")
    if not AUTHORIZATION_ID.fullmatch(authorization_id):
        raise ValueError("authorization ID is malformed")
    marker_name = f"tomorrowci-authorization/{authorization_id}"
    expected_ref = f"refs/tags/{marker_name}"
    if marker_ref != expected_ref:
        raise ValueError("authorization marker ref does not match its exact ID")
    identity = tag_promotion_attestation._annotated_tag_ref_identity(
        git_repo, marker_name
    )
    if (
        identity.get("target_type") != "commit"
        or identity.get("target_sha") != candidate_source_sha
        or identity.get("peeled_commit") != candidate_source_sha
        or identity.get("internal_name") != marker_name
        or identity.get("name") != marker_name
    ):
        raise ValueError(
            "authorization marker annotated tag does not bind the exact candidate commit"
        )
    return identity


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def refuse_publication() -> None:
    raise ValueError(
        "publication is permanently disabled: atomic GitHub Release/GHCR "
        "promotion and public exact-byte read-back are not implemented"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    ci = commands.add_parser("inspect-ci-api")
    ci.add_argument("--metadata", type=Path, required=True)
    ci.add_argument("--repository", required=True)
    ci.add_argument("--source-sha", required=True)
    ci.add_argument("--run-id", required=True)
    ci.add_argument("--run-attempt", required=True)
    artifact = commands.add_parser("inspect-authorization-artifact")
    artifact.add_argument("--metadata", type=Path, required=True)
    artifact.add_argument("--artifact-id", required=True)
    artifact.add_argument("--artifact-sha256", required=True)
    extract = commands.add_parser("extract-authorization")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    refs = commands.add_parser("inspect-remote-refs")
    refs.add_argument("--observation", type=Path, required=True)
    refs.add_argument("--version-ref", required=True)
    refs.add_argument("--version-oid", required=True)
    refs.add_argument("--marker-ref", required=True)
    refs.add_argument("--marker-oid", required=True)
    refs.add_argument("--output", type=Path, required=True)
    marker = commands.add_parser("inspect-authorization-marker")
    marker.add_argument("--git-repo", type=Path, required=True)
    marker.add_argument("--marker-ref", required=True)
    marker.add_argument("--candidate-source-sha", required=True)
    marker.add_argument("--authorization-id", required=True)
    oci = commands.add_parser("inspect-oci-manifest")
    oci.add_argument("--provenance", type=Path, required=True)
    oci.add_argument("--expected-digest", required=True)
    commands.add_parser("assert-publication-disabled")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect-ci-api":
            value = inspect_ci_run(
                _load_json(args.metadata, "CI run metadata"),
                repository=args.repository,
                source_sha=args.source_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "inspect-authorization-artifact":
            value = inspect_artifact(
                _load_json(args.metadata, "authorization artifact metadata"),
                artifact_id=args.artifact_id,
                artifact_sha256=args.artifact_sha256,
            )
            print(json.dumps(value, sort_keys=True))
        elif args.command == "extract-authorization":
            safe_extract_authorization(args.archive, args.destination)
            print("authorization bundle: PASS")
        elif args.command == "inspect-remote-refs":
            value = remote_state(
                args.observation.read_text(encoding="utf-8"),
                version_ref=args.version_ref,
                version_oid=args.version_oid,
                marker_ref=args.marker_ref,
                marker_oid=args.marker_oid,
            )
            with args.output.open("xb") as handle:
                handle.write(canonical_bytes(value))
            print(f"promotion remote state: PASS: {value['state']}")
        elif args.command == "inspect-authorization-marker":
            value = inspect_authorization_marker(
                git_repo=args.git_repo,
                marker_ref=args.marker_ref,
                candidate_source_sha=args.candidate_source_sha,
                authorization_id=args.authorization_id,
            )
            sys.stdout.buffer.write(canonical_bytes(value))
        elif args.command == "inspect-oci-manifest":
            digest = inspect_oci_manifest_digest(
                args.provenance, args.expected_digest
            )
            print(f"OCI authoritative manifest digest: PASS: {digest}")
        else:
            refuse_publication()
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"promotion-preflight: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
